//! Independent Go vectors are a mandatory gate, not an optional local fixture.
use super::certificate::{certified_key, verify_certificate};
use super::hello::{parse_client_hello, read_client_hello};
use super::kx::{Exchange, provider, shared};
use super::reality::{RealityAuthSession, RealityClient, RealityServer, derive_auth_key, open_session_id, seal_session_id};
use super::RealityConfig;
use crate::common::net::BoxStream;
use rustls::crypto::ActiveKeyExchange;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

fn fixture() -> serde_json::Value {
    // Missing fixture is a compile error, including on an otherwise clean clone.
    let text = include_str!("fixtures/go-vectors.json");
    assert_eq!(hex::encode(ring::digest::digest(&ring::digest::SHA256, text.as_bytes())),
        "4643f0ca070c22783dc22dfebc20a8d353fcbc2579895ed02cd7195c2e5687b5");
    serde_json::from_str(text).unwrap()
}
fn bytes(value: &serde_json::Value, key: &str) -> Vec<u8> { hex::decode(value[key].as_str().unwrap()).unwrap() }
fn array<const N: usize>(value: &serde_json::Value, key: &str) -> [u8; N] { bytes(value, key).try_into().unwrap() }
fn server(config: RealityConfig) -> RealityServer {
    RealityServer::new(&RealityConfig { private_key: Some(hex::encode([7; 32])), short_ids: vec!["01020304".into()], ..config }).unwrap()
}

#[test]
fn independent_go_clienthello_ecdh_hkdf_aead_and_certificate_vectors() {
    let vector = fixture();
    assert_eq!(vector["go_reference"], "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7");
    let record = bytes(&vector, "client_hello_record");
    let hello = parse_client_hello(&record[5..]).unwrap();
    assert_eq!(hello.server_name, vector["server_name"].as_str().unwrap());
    assert_eq!(hello.aad, bytes(&vector, "aad"));
    assert_eq!(hello.public, array::<32>(&vector, "client_public_key"));
    let private = StaticSecret::from(array::<32>(&vector, "server_private_key"));
    let secret = shared(&private, &hello.public).unwrap();
    assert_eq!(secret, array::<32>(&vector, "shared_secret"));
    let auth = derive_auth_key(&secret, &hello.random[..20]);
    assert_eq!(auth, array::<32>(&vector, "auth_key"));
    let session = open_session_id(&auth, &hello.random[20..], &hello.session, &hello.aad).unwrap();
    assert_eq!(session.version, (26, 11, 9));
    assert_eq!(session.timestamp as u64, vector["timestamp"].as_u64().unwrap());
    assert_eq!(session.short_id, [1, 2, 3, 4, 0, 0, 0, 0]);
    assert_eq!(seal_session_id(&auth, &hello.random[20..], session.version, session.timestamp, &[1, 2, 3, 4], &hello.aad).unwrap(), hello.session);
    assert_eq!(verify_certificate(&bytes(&vector, "certificate"), &auth).unwrap(), array::<32>(&vector, "ed25519_public_key"));
}

#[test]
fn go_vectors_reject_wrong_key_tampered_random_aad_session_and_certificate() {
    let vector = fixture();
    let record = bytes(&vector, "client_hello_record");
    let hello = parse_client_hello(&record[5..]).unwrap();
    let auth = array::<32>(&vector, "auth_key");
    let mut altered = auth; altered[0] ^= 1;
    assert!(open_session_id(&altered, &hello.random[20..], &hello.session, &hello.aad).is_err());
    let mut nonce = hello.random[20..].to_vec(); nonce[0] ^= 1;
    assert!(open_session_id(&auth, &nonce, &hello.session, &hello.aad).is_err());
    let mut aad = hello.aad.clone(); aad[5] ^= 1;
    assert!(open_session_id(&auth, &hello.random[20..], &hello.session, &aad).is_err());
    let mut session = hello.session; session[31] ^= 1;
    assert!(open_session_id(&auth, &hello.random[20..], &session, &hello.aad).is_err());
    let mut cert = bytes(&vector, "certificate");
    assert!(verify_certificate(&cert, &altered).is_err());
    *cert.last_mut().unwrap() ^= 1;
    assert!(verify_certificate(&cert, &auth).is_err());
    assert!(verify_certificate(b"not a certificate", &auth).is_err());
    cert = bytes(&vector, "certificate"); cert.push(0);
    assert!(verify_certificate(&cert, &auth).is_err());
    assert!(shared(&StaticSecret::from([7; 32]), &[0; 32]).is_err());
    assert!(seal_session_id(&auth, &[0; 11], (26, 11, 9), 0, &[], &[]).is_err());
    assert!(seal_session_id(&auth, &[0; 12], (26, 11, 9), 0, &[0; 9], &[]).is_err());
}

#[test]
fn short_ids_are_exact_zero_padded_not_prefixes_and_time_is_milliseconds() {
    let server = server(RealityConfig { min_client_ver: Some("26.1.0".into()), max_client_ver: Some("26.12.0".into()), ..Default::default() });
    assert!(server.validate_short_id(&[1, 2, 3, 4]));
    assert!(!server.validate_short_id(&[1, 2, 3, 4, 1, 0, 0, 0]));
    assert!(!server.validate_short_id(&[]));
    let empty_id = RealityServer::new(&RealityConfig { private_key: Some(hex::encode([7; 32])), short_ids: vec![String::new()], ..Default::default() }).unwrap();
    assert!(empty_id.validate_short_id(&[]));
    assert!(!empty_id.validate_short_id(&[1]));
    let private = StaticSecret::from([3; 32]);
    let public = PublicKey::from(&private);
    let random = [5; 32];
    let auth = derive_auth_key(&shared(&private, PublicKey::from(&StaticSecret::from([7; 32])).as_bytes()).unwrap(), &random[..20]);
    let old = seal_session_id(&auth, &random[20..], (26, 11, 9), 1, &[1, 2, 3, 4], b"hello").unwrap();
    // Zero deliberately disables the time restriction, matching Go.
    assert!(server.verify_client_hello(public.as_bytes(), &random, &old, b"hello", 0).is_ok());
    assert!(server.verify_client_hello(public.as_bytes(), &random, &old, b"hello", 1).is_err());
    for version in [(25, 0, 0), (27, 0, 0)] {
        let sid = seal_session_id(&auth, &random[20..], version, 1, &[1, 2, 3, 4], b"hello").unwrap();
        assert!(server.verify_client_hello(public.as_bytes(), &random, &sid, b"hello", 0).is_err());
    }
    for id in ["0", "xx", "000000000000000000"] { assert!(RealityClient::new("www.example.com", &hex::encode([7; 32]), id).is_err()); }
    let session = RealityAuthSession { version: (26, 11, 9), timestamp: 1_700_000_000, short_id: vec![1, 2, 3, 4, 0, 0, 0, 0] };
    let exact = UNIX_EPOCH + Duration::from_secs(session.timestamp as u64);
    assert!(server.validate_session_at(&session, 500, exact + Duration::from_millis(500)).is_ok());
    assert!(server.validate_session_at(&session, 499, exact + Duration::from_millis(500)).is_err());
    assert!(server.validate_session_at(&session, 500, exact - Duration::from_millis(500)).is_ok());
    assert!(server.validate_session_at(&session, 499, exact - Duration::from_millis(500)).is_err());
    assert!(server.validate_session_at(&session, 0, exact + Duration::from_secs(100_000)).is_ok());
}

#[test]
fn hybrid_key_exchange_works_with_both_target_groups_and_rejects_bad_lengths() {
    let client = Exchange::new(rustls::NamedGroup::X25519MLKEM768).unwrap();
    let provider = provider();
    let server = provider.kx_groups[0].start_and_complete(client.pub_key()).unwrap();
    let expected = server.secret.secret_bytes().to_vec();
    let actual = Box::new(client).complete(&server.pub_key).unwrap();
    assert_eq!(actual.secret_bytes(), expected);
    let client = Exchange::new(rustls::NamedGroup::X25519MLKEM768).unwrap();
    let (_, public) = client.hybrid_component().unwrap();
    let server = provider.kx_groups[1].start_and_complete(public).unwrap();
    let actual = Box::new(client).complete_hybrid_component(&server.pub_key).unwrap();
    assert_eq!(actual.secret_bytes(), server.secret.secret_bytes());
    let client = Exchange::new(rustls::NamedGroup::X25519MLKEM768).unwrap();
    assert!(Box::new(client).complete(&[0; 31]).is_err());
    assert!(provider.kx_groups[0].start_and_complete(&[0; 1215]).is_err());
}

#[test]
fn ordinary_self_signed_certificate_is_never_a_reality_credential() {
    let key = certified_key(&[7; 32]).unwrap();
    verify_certificate(&key.cert[0], &[7; 32]).unwrap();
    assert!(verify_certificate(&key.cert[0], &[8; 32]).is_err());
    let ordinary = rcgen::generate_simple_self_signed(vec!["www.example.com".into()]).unwrap();
    assert!(verify_certificate(ordinary.cert.der(), &[7; 32]).is_err());
}

// Force sub-record socket writes and reads, independently of TLS fragmentation.
struct Fragmented<S>(S);
impl<S: AsyncRead + Unpin> AsyncRead for Fragmented<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut bytes = [0; 7];
        let mut small = ReadBuf::new(&mut bytes[..buf.remaining().min(7)]);
        match Pin::new(&mut self.0).poll_read(cx, &mut small) {
            Poll::Ready(Ok(())) => { buf.put_slice(small.filled()); Poll::Ready(Ok(())) }
            result => result,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmented<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> { Pin::new(&mut self.0).poll_write(cx, &bytes[..bytes.len().min(3)]) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.0).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.0).poll_shutdown(cx) }
}

#[tokio::test]
async fn hello_reassembly_preserves_original_fragmented_wire_and_target_mirror() {
    let vector = fixture();
    let original = bytes(&vector, "client_hello_record");
    let mut fragmented = Vec::new();
    for chunk in original[5..].chunks(17) {
        fragmented.extend_from_slice(&[22, 3, 1, 0, chunk.len() as u8]);
        fragmented.extend_from_slice(chunk);
    }
    let (mut writer, mut reader) = tokio::io::duplex(37);
    let expected = fragmented.clone();
    let task = tokio::spawn(async move { for chunk in fragmented.chunks(3) { writer.write_all(chunk).await.unwrap(); } });
    let mut mirror = Vec::new();
    let (wire, hello) = read_client_hello(&mut reader, &mut mirror).await.unwrap();
    task.await.unwrap();
    assert_eq!(wire, expected);
    assert_eq!(mirror, wire);
    assert_eq!(hello.unwrap().session, array::<32>(&vector, "session_id"));
}

async fn cover_target() -> (String, tokio::task::JoinHandle<()>, Vec<u8>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut names = vec!["www.example.com".into()];
    names.extend((0..32).map(|n| format!("cover-{n}.example.com")));
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    let der = cert.cert.der().to_vec();
    let tls = crate::transport::internet::tls::TlsServer::from_pem(cert.cert.pem().as_bytes(), cert.signing_key.serialize_pem().as_bytes(), vec![]).unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        if let Ok(mut stream) = tls.accept(Box::pin(socket)).await {
            let mut data = [0; 32];
            if let Ok(n) = stream.read(&mut data).await { let _ = stream.write_all(&data[..n]).await; let _ = stream.flush().await; }
        }
    });
    (address, task, der)
}

#[tokio::test]
async fn live_authenticated_client_server_exchange_over_fragmented_io() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (dest, cover, _) = cover_target().await;
        let private = StaticSecret::from([7; 32]);
        let public = PublicKey::from(&private);
        let server = server(RealityConfig { dest: Some(dest), server_names: vec!["www.example.com".into()], max_time_diff: Some(60_000), ..Default::default() });
        let client = RealityClient::new("www.example.com", &hex::encode(public.as_bytes()), "01020304").unwrap();
        let (left, right) = tokio::io::duplex(97);
        let task = tokio::spawn(async move {
            let raw: BoxStream = Box::pin(Fragmented(right));
            let mut authenticated = server.accept(raw).await.unwrap().expect("actual REALITY authentication");
            let mut bytes = [0; 19];
            authenticated.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"authenticated-vless");
            authenticated.write_all(b"reality-auth-ok").await.unwrap();
            authenticated.flush().await.unwrap();
        });
        let mut stream = client.connect(Box::pin(Fragmented(left))).await.unwrap();
        stream.write_all(b"authenticated-vless").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 15];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reality-auth-ok");
        drop(stream);
        task.await.unwrap();
        cover.await.unwrap();
    }).await.expect("REALITY handshake must make progress with fragmented IO");
}

#[tokio::test]
async fn authentication_failure_forwards_target_bytes_and_never_exposes_proxy_stream() {
    let (dest, target, certificate) = cover_target().await;
    let server = server(RealityConfig { dest: Some(dest), server_names: vec!["www.example.com".into()], ..Default::default() });
    let (left, right) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { assert!(server.accept(Box::pin(right)).await.unwrap().is_none()); });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(certificate)).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("www.example.com").unwrap();
    let mut stream = connector.connect(name, left).await.unwrap();
    stream.write_all(b"cover-echo").await.unwrap(); stream.flush().await.unwrap();
    let mut reply = [0; 10]; stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"cover-echo");
    drop(stream); target.await.unwrap(); task.await.unwrap();
}

#[tokio::test]
async fn wrong_short_id_and_wrong_server_key_cannot_authenticate_live() {
    for wrong_key in [false, true] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (dest, target, _) = cover_target().await;
            let server = server(RealityConfig { dest: Some(dest), server_names: vec!["www.example.com".into()], ..Default::default() });
            let private = StaticSecret::from(if wrong_key { [8; 32] } else { [7; 32] });
            let client = RealityClient::new("www.example.com", &hex::encode(PublicKey::from(&private).as_bytes()), if wrong_key { "01020304" } else { "01020305" }).unwrap();
            let (left, right) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move { assert!(server.accept(Box::pin(right)).await.unwrap().is_none()); });
            assert!(client.connect(Box::pin(left)).await.is_err());
            task.await.unwrap(); target.await.unwrap();
        }).await.unwrap();
    }
}

#[test]
fn required_go_fixture_is_valid_under_the_server_authentication_policy() {
    let vector = fixture();
    let record = bytes(&vector, "client_hello_record");
    let hello = parse_client_hello(&record[5..]).unwrap();
    let server = RealityServer::new(&RealityConfig { private_key: Some(vector["server_private_key"].as_str().unwrap().into()), short_ids: vec!["01020304".into()], server_names: vec![hello.server_name], ..Default::default() }).unwrap();
    assert!(server.verify_client_hello(&hello.public, &hello.random, &hello.session, &hello.aad, 0).is_ok());
    // A one-second window rejects the independently frozen historical hello.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if now.abs_diff(vector["timestamp"].as_u64().unwrap()) > 1 { assert!(server.verify_client_hello(&hello.public, &hello.random, &hello.session, &hello.aad, 1).is_err()); }
}


async fn stream_pair() -> (BoxStream, BoxStream, tokio::task::JoinHandle<()>) {
    let (dest, cover, _) = cover_target().await;
    let public = PublicKey::from(&StaticSecret::from([7; 32]));
    let server = server(RealityConfig { dest: Some(dest), server_names: vec!["www.example.com".into()], ..Default::default() });
    let client = RealityClient::new("www.example.com", &hex::encode(public.as_bytes()), "01020304").unwrap();
    let (left, right) = tokio::io::duplex(65536);
    let (client, server) = tokio::join!(client.connect(Box::pin(left)), server.accept(Box::pin(right)));
    // Report the server's concrete staging error before the client's secondary
    // transport EOF (for example, an unsupported record-padding provider).
    let server = server.expect("REALITY server handshake").expect("authenticated REALITY stream");
    (client.expect("REALITY client handshake"), server, cover)
}

#[tokio::test]
async fn large_coalesced_records_and_clean_close_preserve_every_plaintext_byte() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut client, mut server, cover) = stream_pair().await;
        let expected: Vec<u8> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
        let bytes = expected.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
        writer.await.unwrap();
        cover.await.unwrap();
    }).await.expect("large TLS transfer stalled");
}

#[tokio::test]
async fn transport_eof_without_tls_close_notify_is_not_clean_eof() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut client, mut server, cover) = stream_pair().await;
        client.write_all(b"before-truncation").await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let mut received = Vec::new();
        let error = server.read_to_end(&mut received).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(received, b"before-truncation");
        cover.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn valid_authkey_hmac_does_not_bypass_ed25519_certificate_verify() {
    use std::sync::Arc;
    tokio::time::timeout(Duration::from_secs(15), async {
        let public = PublicKey::from(&StaticSecret::from([7; 32]));
        let client = RealityClient::new("www.example.com", &hex::encode(public.as_bytes()), "01020304").unwrap();
        let (left, mut right) = tokio::io::duplex(65536);
        let malicious = tokio::spawn(async move {
            let mut mirror = Vec::new();
            let (wire, hello) = read_client_hello(&mut right, &mut mirror).await.unwrap();
            let hello = hello.unwrap();
            let secret = shared(&StaticSecret::from([7; 32]), &hello.public).unwrap();
            let auth = derive_auth_key(&secret, &hello.random[..20]);
            let mut credential = certified_key(&auth).unwrap();
            // The leaf is genuinely authenticated, but this signer cannot prove
            // possession of its Ed25519 private key in TLS CertificateVerify.
            credential.key = certified_key(&[9; 32]).unwrap().key;
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
                .with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(credential)));
            let mut tls = rustls::Connection::Server(rustls::ServerConnection::new(Arc::new(config)).unwrap());
            let mut cursor = std::io::Cursor::new(wire.as_slice());
            while cursor.position() as usize != wire.len() {
                assert_ne!(tls.read_tls(&mut cursor).unwrap(), 0);
                tls.process_new_packets().unwrap();
            }
            let result = super::stream::RealityStream::new(Box::pin(right), tls).handshake().await;
            assert!(result.is_err());
        });
        assert!(client.connect(Box::pin(left)).await.is_err());
        malicious.await.unwrap();
    }).await.expect("certificate proof rejection stalled");
}

fn replace_key_shares(handshake: &[u8], shares: &[u8]) -> Vec<u8> {
    let read_u16 = |offset| u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    let mut offset = 71;
    offset += 2 + read_u16(offset);
    offset += 1 + handshake[offset] as usize;
    let extension_length_offset = offset;
    offset += 2;
    while offset < handshake.len() {
        let kind = read_u16(offset);
        let length = read_u16(offset + 2);
        if kind == 51 {
            let mut result = handshake[..offset + 2].to_vec();
            result.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
            result.extend_from_slice(&(shares.len() as u16).to_be_bytes());
            result.extend_from_slice(shares);
            result.extend_from_slice(&handshake[offset + 4 + length..]);
            let extensions = result.len() - extension_length_offset - 2;
            result[extension_length_offset..extension_length_offset + 2].copy_from_slice(&(extensions as u16).to_be_bytes());
            let total = result.len() - 4;
            result[1..4].copy_from_slice(&(total as u32).to_be_bytes()[1..]);
            return result;
        }
        offset += 4 + length;
    }
    panic!("required Go fixture has no key_share extension");
}

#[test]
fn hello_parser_rejects_truncation_classical_only_and_wrong_hybrid_order() {
    let vector = fixture();
    let record = bytes(&vector, "client_hello_record");
    let handshake = &record[5..];
    for end in 0..handshake.len() { assert!(parse_client_hello(&handshake[..end]).is_err()); }
    let public = bytes(&vector, "client_public_key");
    let mut classical = vec![0, 29, 0, 32]; classical.extend_from_slice(&public);
    assert!(parse_client_hello(&replace_key_shares(handshake, &classical)).is_err());
    // A valid encoded hybrid value is enough to test ordering/framing; the
    // authenticated path separately validates the ML-KEM encapsulation key.
    let mut hybrid = vec![0x11, 0xec, 0x04, 0xc0]; hybrid.resize(1220, 0);
    hybrid[1188..1220].copy_from_slice(&public);
    let mut correct = hybrid.clone(); correct.extend_from_slice(&classical);
    assert!(parse_client_hello(&replace_key_shares(handshake, &correct)).is_ok());
    let mut reverse = classical.clone(); reverse.extend_from_slice(&hybrid);
    assert!(parse_client_hello(&replace_key_shares(handshake, &reverse)).is_err());
    let mut duplicate = hybrid.clone(); duplicate.extend_from_slice(&hybrid);
    assert!(parse_client_hello(&replace_key_shares(handshake, &duplicate)).is_err());
    correct.push(0); // Malformed tail must be checked even after choosing X25519.
    assert!(parse_client_hello(&replace_key_shares(handshake, &correct)).is_err());
}
