use super::{HysteriaClient, HysteriaConfig, HysteriaServer, HysteriaIncoming, QuicVarint, TcpRequest, TcpResponse, UDPMessage, Defragger, frag_udp_message};
use super::config::HysteriaUser;
use crate::{common::{net::Destination, protocol::SessionContext}, features::outbound::OutboundHandler, transport::internet::hysteria::auth};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn vectors() -> Vec<Value> {
    // Compile-time inclusion makes the checked-in Go oracle mandatory.
    let frozen = include_bytes!("testdata/go-vectors.jsonl");
    assert_eq!(hex::encode(Sha256::digest(frozen)), "6f5147a6034af06cbe7b2aa14873eaee96d893af63f554c761152f76879ad2f2");
    let source = match std::env::var_os("XRAY_HYSTERIA_REFERENCE_FILE") {
        Some(path) => std::fs::read_to_string(path).expect("required external Hysteria reference fixture"),
        None => String::from_utf8(frozen.to_vec()).expect("UTF-8 Go fixture"),
    };
    let records: Vec<Value> = source.lines().map(|line| serde_json::from_str(line).expect("Go JSON record")).collect();
    assert_eq!(records.len(), 2, "protocol and authentication records are required");
    records
}

#[tokio::test]
async fn required_go_protocol_vectors() {
    let records = vectors();
    let protocol = records.iter().find(|record| record["kind"] == "protocol").expect("Go protocol vectors");
    assert_eq!(protocol["reference"], "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7");
    for request in protocol["requests"].as_array().unwrap() {
        let request_value = TcpRequest::new(request["address"].as_str().unwrap(), 0);
        let encoded = hex::decode(request["hex"].as_str().unwrap()).unwrap();
        assert_eq!(request_value.encode(), encoded);
        assert_eq!(TcpRequest::decode(&mut Cursor::new(encoded)).await.unwrap(), request_value);
    }
    for response in protocol["responses"].as_array().unwrap() {
        let response_value = TcpResponse::new(response["ok"].as_bool().unwrap(), response["message"].as_str().unwrap(), 0);
        let encoded = hex::decode(response["hex"].as_str().unwrap()).unwrap();
        assert_eq!(response_value.encode().unwrap(), encoded);
        assert_eq!(TcpResponse::decode(&mut Cursor::new(encoded)).await.unwrap(), response_value);
    }
    let message = UDPMessage::new(0x01020304, 0x0506, "dns.example:53".into(), (0..10).collect());
    assert_eq!(hex::encode(message.encode().unwrap()), protocol["udp"].as_str().unwrap());
    assert_eq!(UDPMessage::decode(&message.encode().unwrap()).unwrap(), message);
    let fragments = frag_udp_message(&message, message.header_size() + 3);
    assert_eq!(fragments.len(), 4);
    for (fragment, expected) in fragments.iter().zip(protocol["fragments"].as_array().unwrap()) {
        assert_eq!(hex::encode(fragment.encode().unwrap()), expected.as_str().unwrap());
    }
    for invalid in protocol["invalid_udp"].as_array().unwrap() {
        assert!(UDPMessage::decode(&hex::decode(invalid.as_str().unwrap()).unwrap()).is_err());
    }
}

#[test]
fn required_go_authentication_vectors() {
    let records = vectors();
    let authentication = records.iter().find(|record| record["kind"] == "authentication").unwrap();
    let config = HysteriaConfig::new("secret", 0, 0);
    for vector in authentication["vectors"].as_array().unwrap() {
        let request = http::Request::builder().method(vector["method"].as_str().unwrap())
            .uri(vector["url"].as_str().unwrap()).header(auth::HEADER_AUTH, vector["auth"].as_str().unwrap()).body(()).unwrap();
        let accepted = auth::authenticate(&request, &config, false).is_some();
        assert_eq!(accepted, vector["accepted"].as_bool().unwrap());
        let response = if accepted { auth::auth_response_values(123456, false).unwrap() } else { auth::masquerade(&config).unwrap().0 };
        assert_eq!(u64::from(response.status().as_u16()), vector["status"].as_u64().unwrap());
        for (header, field) in [(auth::HEADER_UDP, "udp"), (auth::HEADER_CC_RX, "rx")] {
            assert_eq!(response.headers().get(header).map_or("", |value| value.to_str().unwrap()), vector[field].as_str().unwrap());
        }
    }
}

#[tokio::test]
async fn varint_boundaries_and_truncation() {
    for value in [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1 << 62) - 1] {
        let mut bytes = Vec::new(); QuicVarint::write(value, &mut bytes);
        assert_eq!(QuicVarint::parse(&bytes).unwrap(), (value, bytes.len()));
        assert_eq!(QuicVarint::read(&mut Cursor::new(bytes.clone())).await.unwrap(), value);
        for length in 0..bytes.len() { assert!(QuicVarint::parse(&bytes[..length]).is_err()); }
    }
}
#[tokio::test]
async fn fragmented_tcp_frames_and_invalid_lengths() {
    let request = TcpRequest::new("example.com:443", 17);
    let encoded = request.encode_stream().unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let writing = tokio::spawn(async move { for byte in encoded { writer.write_all(&[byte]).await.unwrap(); } });
    assert_eq!(TcpRequest::decode_stream(&mut reader).await.unwrap(), request);
    writing.await.unwrap();
    let request = request.encode_stream().unwrap();
    for length in 0..request.len() { assert!(TcpRequest::decode_stream(&mut Cursor::new(&request[..length])).await.is_err()); }
    for bytes in [vec![0], vec![0x48, 0x01], vec![1, b'a', 0x50, 1]] {
        assert!(TcpRequest::decode(&mut Cursor::new(bytes)).await.is_err());
    }
    let response = TcpResponse::new(false, "rejected", 7).encode().unwrap();
    for length in 0..response.len() { assert!(TcpResponse::decode(&mut Cursor::new(&response[..length])).await.is_err()); }
    assert!(!TcpResponse::decode(&mut Cursor::new([255, 0, 0])).await.unwrap().ok);
}
#[test]
fn udp_reassembly_out_of_order_duplicates_and_packet_replacement() {
    let message = UDPMessage::new(7, 9, "dns.example:53".into(), (0..200).map(|value| value as u8).collect());
    let fragments = frag_udp_message(&message, message.header_size() + 80);
    let mut defragger = Defragger::new();
    assert!(defragger.feed(fragments[2].clone()).is_none());
    assert!(defragger.feed(fragments[2].clone()).is_none());
    assert!(defragger.feed(fragments[0].clone()).is_none());
    assert_eq!(defragger.feed(fragments[1].clone()).unwrap().data, message.data);
    let mut defragger = Defragger::new();
    assert!(defragger.feed(fragments[0].clone()).is_none());
    let mut next = fragments.clone();
    for fragment in &mut next { fragment.packet_id += 1; }
    assert!(defragger.feed(next[0].clone()).is_none());
    assert!(defragger.feed(next[2].clone()).is_none());
    assert_eq!(defragger.feed(next[1].clone()).unwrap().packet_id, 10);
    let mut invalid = fragments[0].clone(); invalid.frag_id = invalid.frag_count;
    assert!(defragger.feed(invalid).is_none());
    assert!(frag_udp_message(&message, message.header_size()).is_empty());
    assert!(frag_udp_message(&message, message.header_size() + 1).len() <= 255);
}
#[test]
fn config_validation_is_explicit() {
    let mut config = HysteriaConfig::default();
    assert!(config.validate(false).is_err());
    config.auth = "secret".into(); assert!(config.validate(false).is_ok());
    assert!(serde_json::from_str::<HysteriaConfig>(r#"{"auth":"secret","obfs":"salamander"}"#).is_err());
    config.up_mbps = 1; assert!(config.validate(false).is_err()); config.up_mbps = 0;
    config.transport.congestion = "force-brutal".into(); assert!(config.validate(false).is_err());
    config.transport.congestion = "bbr".into(); config.transport.bbr_profile = "aggressive".into(); assert!(config.validate(false).is_err());
    config.transport.bbr_profile = "standard".into(); config.transport.masq_type = "proxy".into(); assert!(config.validate(false).is_err());
    config.transport.masq_type.clear(); config.transport.recv_window_conn = 0; assert!(config.validate(false).is_err());
    let user = HysteriaUser { auth: "secret".into(), email: "alice@example.test".into(), level: 2 };
    let config = HysteriaConfig { users: vec![user.clone(), user], ..HysteriaConfig::default() };
    assert!(config.validate(true).is_err());
}

pub(super) fn tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
    let der = cert.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_no_client_auth().with_single_cert(vec![der.clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into())).unwrap();
    let mut roots = rustls::RootCertStore::empty(); roots.add(der.clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
    (Arc::new(server), Arc::new(client), der.to_vec())
}
pub(super) fn server_config() -> HysteriaConfig {
    HysteriaConfig { users: vec![HysteriaUser { auth: "secret".into(), email: "alice@example.test".into(), level: 2 }], ..HysteriaConfig::default() }
}
pub(super) fn client_config() -> HysteriaConfig {
    HysteriaConfig { server_name: Some("localhost".into()), ..HysteriaConfig::new("secret", 0, 0) }
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future).await.expect("Hysteria QUIC loopback timed out")
}
#[tokio::test]
async fn real_quic_http3_auth_tcp_success_and_rejection() {
    bounded(async {
        let (server_tls, client_tls, _) = tls_configs();
        let mut listener = HysteriaServer::new("hy-in", server_config()).bind("127.0.0.1:0".parse().unwrap(), server_tls).unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let HysteriaIncoming::Tcp(request) = listener.accept().await.unwrap() else { panic!("expected TCP request"); };
            assert_eq!(request.session.destination.to_string(), "example.com:443");
            assert_eq!(request.session.user.as_ref().unwrap().email, "alice@example.test");
            let mut incoming = request.accept().await.unwrap();
            let mut data = [0; 4]; incoming.stream.read_exact(&mut data).await.unwrap();
            incoming.stream.write_all(&data).await.unwrap();
            let HysteriaIncoming::Tcp(request) = listener.accept().await.unwrap() else { panic!("expected TCP request"); };
            request.reject("destination blocked").await.unwrap();
            // The client signals completion before the listener is dropped.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let client = HysteriaClient::with_tls("hy-out", Destination::from(address), client_config(), client_tls);
        let context = SessionContext::new("test", "example.com:443".parse().unwrap());
        let mut stream = client.connect(&context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut data = [0; 4]; stream.read_exact(&mut data).await.unwrap(); assert_eq!(&data, b"ping");
        let error = client.connect(&context).await.err().expect("TCP rejection must reach caller");
        assert!(error.to_string().contains("destination blocked"));
        server.await.unwrap();
    }).await;
}
#[tokio::test]
async fn real_quic_rejects_bad_auth_and_untrusted_certificate() {
    bounded(async {
        let (server_tls, client_tls, _) = tls_configs();
        let listener = HysteriaServer::new("hy-in", server_config()).bind("127.0.0.1:0".parse().unwrap(), server_tls).unwrap();
        let mut config = client_config(); config.auth = "wrong".into();
        let client = HysteriaClient::with_tls("bad-auth", Destination::from(listener.local_addr().unwrap()), config, client_tls);
        assert!(matches!(client.authenticated_connection().await, Err(crate::common::errors::Error::AuthFailed(_))));
        let client = HysteriaClient::new("untrusted", Destination::from(listener.local_addr().unwrap()), client_config());
        assert!(client.authenticated_connection().await.is_err());
    }).await;
}
#[tokio::test]
async fn real_quic_rejects_unauthenticated_proxy_stream() {
    bounded(async {
        let (server_tls, client_tls, _) = tls_configs();
        let listener = HysteriaServer::new("hy-in", server_config()).bind("127.0.0.1:0".parse().unwrap(), server_tls).unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = crate::transport::internet::hysteria::endpoint::client(addr, &client_tls, &client_config().transport).unwrap();
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let frame = TcpRequest::new("example.com:443", 0).encode_stream().unwrap();
        send.write_all(&frame[..1]).await.unwrap(); tokio::task::yield_now().await;
        send.write_all(&frame[1..]).await.unwrap(); send.finish().unwrap();
        assert!(recv.read_to_end(1024).await.is_err());
    }).await;
}
#[tokio::test]
async fn real_quic_udp_fragmentation_and_session_isolation() {
    bounded(async {
        let (server_tls, client_tls, _) = tls_configs();
        let mut listener = HysteriaServer::new("hy-in", server_config()).bind("127.0.0.1:0".parse().unwrap(), server_tls).unwrap();
        let address = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let HysteriaIncoming::Udp { session, user, .. } = listener.accept().await.unwrap() else { panic!("expected UDP session"); };
                assert_eq!(user.unwrap().level, 2);
                let packet = session.recv().await.unwrap();
                session.send(&packet.address, &packet.data).await.unwrap();
            }
            let _ = done_rx.await;
        });
        let client = HysteriaClient::with_tls("hy-out", Destination::from(address), client_config(), client_tls);
        let first = client.open_udp().await.unwrap(); let second = client.open_udp().await.unwrap();
        assert_ne!(first.id(), second.id());
        for (session, value) in [(&first, 41u8), (&second, 99u8)] {
            let data = vec![value; 6000]; session.send("dns.example:53", &data).await.unwrap();
            let response = session.recv().await.unwrap(); assert_eq!(response.address, "dns.example:53"); assert_eq!(response.data, data);
        }
        let _ = done_tx.send(()); server.await.unwrap();
    }).await;
}
