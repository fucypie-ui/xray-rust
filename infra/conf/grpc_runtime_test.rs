use super::*;
use crate::{
    common::{net::{Address, datagram::{BoxDatagram, Datagram}}, protocol::SessionContext},
    infra::conf::{Config, BuiltConfig},
};
use serde_json::{Value, json};
use std::{sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::mpsc};

const LIMIT: Duration = Duration::from_secs(20);
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn stream(multi: bool) -> Value {
    json!({"network":"grpc","grpcSettings":{"serviceName":"config/service!","multiMode":multi,"user_agent":"golang"}})
}
fn build(value: Value) -> Result<BuiltConfig> { serde_json::from_value::<Config>(value).unwrap().build() }
fn inbound_settings(role: &str) -> Value {
    match role {
        "vless" | "vmess" => json!({"decryption":"none","clients":[{"id":ID,"email":"gun@example.test","level":3}]}),
        "trojan" => json!({"clients":[{"password":"gun-secret"}]}),
        _ => json!({}),
    }
}
fn outbound_settings(role: &str, port: u16) -> Value {
    match role {
        "vless" | "vmess" => json!({"vnext":[{"address":"127.0.0.1","port":port,"users":[{"id":ID,"encryption":"none","security":"aes-128-gcm"}]}]}),
        "trojan" => json!({"servers":[{"address":"127.0.0.1","port":port,"password":"gun-secret"}]}),
        _ => json!({"servers":[{"address":"127.0.0.1","port":port}]}),
    }
}
fn inbound_config(role: &str, stream: Value) -> Result<BuiltConfig> {
    build(json!({"inbounds":[{"tag":"gun-in","protocol":role,"listen":"127.0.0.1","port":12345,
        "settings":inbound_settings(role),"streamSettings":stream,"sniffing":{"enabled":true,"destOverride":["http","tls"]}}]}))
}
fn outbound_config(role: &str, port: u16, stream: Value) -> Result<BuiltConfig> {
    build(json!({"outbounds":[{"tag":"gun-out","protocol":role,"settings":outbound_settings(role,port),"streamSettings":stream}]}))
}
fn close_features(config: &BuiltConfig) {
    for feature in &config.features { if feature.feature_type() == "grpcTransport" { feature.close().unwrap(); } }
}
fn tls_streams(multi: bool) -> (Value, Value) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut inbound = stream(multi);
    inbound["security"] = json!("tls");
    inbound["tlsSettings"] = json!({"alpn":["h2"],"certificates":[{
        "certificate":cert.cert.pem().lines().collect::<Vec<_>>(),
        "key":cert.signing_key.serialize_pem().lines().collect::<Vec<_>>()
    }]});
    let mut outbound = stream(multi);
    outbound["security"] = json!("tls");
    outbound["tlsSettings"] = json!({"serverName":"localhost","allowInsecure":true,"alpn":["h2"]});
    (inbound, outbound)
}
async fn echo(mut stream: BoxStream) -> Result<()> {
    let mut buffer = [0;8192];
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 { stream.shutdown().await?; return Ok(()); }
        stream.write_all(&buffer[..n]).await?;
        stream.flush().await?;
    }
}
struct Echo(mpsc::UnboundedSender<SessionContext>);
#[async_trait]
impl InboundDispatcher for Echo {
    async fn dispatch_stream(&self, stream: BoxStream, session: SessionContext) -> Result<()> {
        self.0.send(session).map_err(|_| Error::Closed)?;
        echo(stream).await
    }
    async fn connect_stream(&self, session: &SessionContext) -> Result<BoxStream> {
        self.0.send(session.clone()).map_err(|_| Error::Closed)?;
        let (stream, peer) = tokio::io::duplex(65536);
        tokio::spawn(async move { let _ = echo(Box::pin(peer)).await; });
        Ok(Box::pin(stream))
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        self.0.send(session).map_err(|_| Error::Closed)?;
        while let Some(packet) = packets.recv().await? {
            let Some(source) = packet.source else { return Err(Error::Protocol("packet source missing".into())); };
            packets.send(Datagram { payload: packet.payload, source: Some(packet.destination), destination: source }).await?;
        }
        Ok(())
    }
}
async fn roundtrip(role: &str, secure: bool, multi: bool) {
    let (in_stream, out_stream) = if secure { tls_streams(multi) } else { (stream(multi), stream(multi)) };
    let inbound = inbound_config(role, in_stream).unwrap();
    let handler = inbound.inbounds[0].1.clone();
    let mut listener = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
    let address = listener.local_addr().unwrap();
    let outbound = outbound_config(role, address.port(), out_stream).unwrap();
    assert_eq!(outbound.features.iter().filter(|feature| feature.feature_type() == "grpcTransport").count(), 1);
    let (seen, mut sessions) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let task = listener.accept(Arc::new(Echo(seen))).await.unwrap();
        (task.await, listener)
    });
    let destination = Destination::tcp(crate::common::net::parse_address("target.example"), 443);
    let stream = outbound.outbounds["gun-out"].connect(&SessionContext::new("test", destination.clone())).await.unwrap();
    let payload: Vec<_> = (0..131137).map(|i| (i * 37 % 251) as u8).collect();
    let expected = payload.clone();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sending = async { writer.write_all(&payload).await.unwrap(); writer.flush().await.unwrap(); };
    let receiving = async { let mut received = vec![0; expected.len()]; reader.read_exact(&mut received).await.unwrap(); received };
    let ((), received) = tokio::join!(sending, receiving);
    assert_eq!(received, expected, "{} secure={} multi={}", role, secure, multi);
    let session = sessions.recv().await.unwrap();
    assert_eq!(session.destination, destination);
    assert_eq!(session.inbound_tag, "gun-in");
    assert!(session.source.unwrap().ip().is_loopback());
    assert!(session.sniffing_request.is_some());
    if matches!(role, "vless" | "vmess") {
        let user = session.user.unwrap();
        assert_eq!(user.email, "gun@example.test");
        assert_eq!(user.level, 3);
    }
    handler.close().await.unwrap();
    close_features(&outbound);
    let (result, native) = server.await.unwrap();
    assert!(matches!(result, Ok(()) | Err(Error::Closed)));
    drop(native);
    close_features(&inbound);
}

#[test]
fn grpc_go_json_aliases_defaults_and_signed_clamping() {
    let default = super::super::grpc::GrpcConfig::default();
    assert_eq!(default.service_name, "");
    assert_eq!(default.user_agent, "");
    assert!(matches!(default.build(), Err(Error::Unsupported(_))));
    assert!(default.build_server().is_ok());
    let json = json!({"serviceName":"svc","multiMode":true,"authority":"example.test:443",
        "idle_timeout":-1,"health_check_timeout":-5,"initial_windows_size":-9,"user_agent":"golang"});
    let config: super::super::grpc::GrpcConfig = serde_json::from_value(json).unwrap();
    let built = config.build().unwrap();
    assert_eq!(built.service_name, "svc"); assert!(built.multi_mode);
    assert_eq!(built.authority, "example.test:443");
    assert_eq!(built.idle_timeout, 0); assert_eq!(built.health_check_timeout, 0); assert_eq!(built.initial_windows_size, 0);
    let aliases: super::super::grpc::GrpcConfig = serde_json::from_value(json!({"service_name":"svc","multi_mode":true,
        "idleTimeout":-1,"healthCheckTimeout":-5,"initialWindowsSize":-9,"permitWithoutStream":false,"userAgent":"golang"})).unwrap();
    let normalized = aliases.build().unwrap();
    assert_eq!(normalized.service_name, built.service_name);
    assert_eq!(normalized.initial_windows_size, built.initial_windows_size);
    let mut omitted = stream(false);
    omitted["grpcSettings"].as_object_mut().unwrap().remove("user_agent");
    assert!(matches!(outbound_config("http", 1, omitted.clone()), Err(Error::Unsupported(_))));
    assert!(inbound_config("http", omitted).is_ok());
    let mut literal = stream(false);
    literal["grpcSettings"]["user_agent"] = json!("gun-config-ci/1.0");
    assert!(outbound_config("http", 1, literal).is_ok());
}

#[test]
fn grpc_unavailable_options_and_roles_fail_during_root_build() {
    for setting in [json!({"idle_timeout":1}), json!({"health_check_timeout":1}),json!({"permit_without_stream":true}),
        json!({"initial_windows_size":16777217}),json!({"user_agent":"chrome"}),json!({"user_agent":""}),json!({"compression":"gzip"})]
    {
        let mut value = stream(false);
        for (key, setting) in setting.as_object().unwrap() { value["grpcSettings"][key] = setting.clone(); }
        assert!(outbound_config("http", 1, value).is_err());
    }
    for role in ["freedom","blackhole","shadowsocks","wireguard","hysteria","tun"] {
        assert!(matches!(outbound_config(role, 1, stream(false)), Err(Error::Unsupported(_))));
        assert!(matches!(inbound_config(role, stream(false)), Err(Error::Unsupported(_))));
    }
    for role in ["vless","vmess","trojan","socks","http"] {
        assert!(outbound_config(role,1,stream(false)).is_ok());
        assert!(inbound_config(role,stream(false)).is_ok());
    }
}

#[test]
fn grpc_compositions_and_unconsumed_tls_options_are_explicit_errors() {
    let options = [json!({"security":"reality"}),json!({"security":"tls","tlsSettings":{"fingerprint":"chrome"}}),
        json!({"security":"tls","tlsSettings":{"alpn":["http/1.1"]}}),json!({"wsSettings":{}}),json!({"xhttpSettings":{}}),
        json!({"httpupgradeSettings":{}}),json!({"kcpSettings":{}}),json!({"finalmask":{}}),json!({"sockopt":{"mark":1}}),
        json!({"security":"tls","tlsSettings":{"minVersion":"1.3"}}),json!({"security":"none","tlsSettings":{}})];
    for option in options {
        let mut value = stream(false);
        for (key, setting) in option.as_object().unwrap() { value[key] = setting.clone(); }
        assert!(matches!(outbound_config("http",1,value.clone()), Err(Error::Unsupported(_))));
        assert!(matches!(inbound_config("http",value), Err(Error::Unsupported(_))));
    }
    let mut value = stream(false); value["security"] = json!("tls");
    assert!(inbound_config("http",value).is_err());
    let mut value = stream(false); value["grpcSettings"]["serviceName"] = json!("/same");
    assert!(inbound_config("http",value).is_err());
    let mut outbound = json!({"outbounds":[{"protocol":"vless","settings":outbound_settings("vless",1),"streamSettings":stream(false)}]});
    outbound["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = json!("xtls-rprx-vision");
    assert!(matches!(build(outbound), Err(Error::Unsupported(_))));
    let mut inbound = json!({"inbounds":[{"protocol":"vless","port":12345,"settings":inbound_settings("vless"),"streamSettings":stream(false)}]});
    inbound["inbounds"][0]["settings"]["clients"][0]["flow"] = json!("xtls-rprx-vision");
    assert!(matches!(build(inbound), Err(Error::Unsupported(_))));
    assert!(matches!(build(json!({"outbounds":[{"protocol":"http","settings":outbound_settings("http",1),
        "mux":{"enabled":true},"streamSettings":stream(false)}]})), Err(Error::Unsupported(_))));
}

#[tokio::test]
async fn grpc_plain_root_built_five_protocols_hunk_and_multi_preserve_sessions() {
    tokio::time::timeout(LIMIT, async { for role in ["vless","vmess","trojan","socks","http"] { for multi in [false,true] { roundtrip(role,false,multi).await; } } }).await.unwrap();
}

#[tokio::test]
async fn grpc_tls_root_built_five_protocols_hunk_and_multi_compose_once() {
    tokio::time::timeout(LIMIT, async { for role in ["vless","vmess","trojan","socks","http"] { for multi in [false,true] { roundtrip(role,true,multi).await; } } }).await.unwrap();
}

#[tokio::test]
async fn grpc_root_close_cancels_pending_tls_connect_and_drops_socket() {
    tokio::time::timeout(LIMIT, async {
        for explicit_close in [false,true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut value = stream(false); value["security"] = json!("tls");
            value["tlsSettings"] = json!({"serverName":"localhost","allowInsecure":true});
            let mut built = Some(outbound_config("http", listener.local_addr().unwrap().port(), value).unwrap());
            let handler = built.as_ref().unwrap().outbounds["gun-out"].clone();
            let connect = tokio::spawn(async move { handler.connect(&SessionContext::new("test", Destination::tcp(Address::Domain("target.example".into()),443))).await });
            let (mut peer,_) = listener.accept().await.unwrap();
            if explicit_close { close_features(built.as_ref().unwrap()); } else { drop(built.take()); }
            assert!(connect.await.unwrap().is_err());
            let mut bytes = Vec::new();
            // A handshake prefix may already have been written; eventual EOF
            // or reset proves cancellation closed the actual retained socket.
            let _ = peer.read_to_end(&mut bytes).await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_root_close_releases_retained_outbound_and_rejects_redial() {
    tokio::time::timeout(LIMIT, async {
        let engine = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), crate::transport::internet::grpc::GrpcConfig::new("config/service!")).await.unwrap();
        let built = outbound_config("vmess",engine.local_addr().unwrap().port(),stream(false)).unwrap();
        let handler = built.outbounds["gun-out"].clone();
        let retained = handler.connect(&SessionContext::new("test",Destination::tcp(Address::Domain("target.example".into()),443))).await.unwrap();
        let (mut remote,_) = engine.accept().await.unwrap();
        close_features(&built);
        let mut bytes = Vec::new(); let _ = remote.read_to_end(&mut bytes).await;
        assert!(matches!(handler.connect(&SessionContext::new("test",Destination::tcp(Address::Domain("target.example".into()),443))).await, Err(Error::Closed)));
        drop(retained);
        engine.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_inbound_close_releases_port_and_children_with_native_retained() {
    tokio::time::timeout(LIMIT, async {
        let built = inbound_config("socks",stream(false)).unwrap();
        let handler = built.inbounds[0].1.clone();
        let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = native.local_addr().unwrap();
        let retained = GrpcDialer::new(crate::transport::internet::grpc::GrpcConfig::new("config/service!"))
            .dial(&Destination::tcp(address.ip().into(),address.port())).await.unwrap();
        let (seen,_) = mpsc::unbounded_channel();
        let child = native.accept(Arc::new(Echo(seen))).await.unwrap();
        let child = tokio::spawn(child);
        tokio::task::yield_now().await;
        handler.close().await.unwrap();
        let rebound = TcpListener::bind(address).await.unwrap();
        let (seen,_) = mpsc::unbounded_channel();
        assert!(native.accept(Arc::new(Echo(seen))).await.is_err());
        assert!(child.await.unwrap().is_err());
        drop((retained,rebound,native));
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_native_drop_and_root_feature_close_release_retained_handler_socket() {
    tokio::time::timeout(LIMIT, async {
        for root_close in [false,true] {
            let built = inbound_config("http",stream(false)).unwrap();
            let handler = built.inbounds[0].1.clone();
            let native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            let address = native.local_addr().unwrap();
            let mut retained = Some(native);
            if root_close { close_features(&built); } else { drop(retained.take()); }
            loop {
                match TcpListener::bind(address).await {
                    Ok(rebound) => { drop(rebound); break; },
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => tokio::task::yield_now().await,
                    Err(error) => panic!("{}",error),
                }
            }
            assert!(handler.tag() == "gun-in");
            drop(retained);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_vmess_packet_dispatch_preserves_addresses_and_boundaries() {
    tokio::time::timeout(LIMIT, async {
        let inbound = inbound_config("vmess",stream(true)).unwrap();
        let handler = inbound.inbounds[0].1.clone();
        let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let outbound = outbound_config("vmess",native.local_addr().unwrap().port(),stream(true)).unwrap();
        let (seen,mut sessions) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move { native.accept(Arc::new(Echo(seen))).await.unwrap().await });
        let destination = Destination::udp(Address::Domain("dns.example".into()),53);
        let source = Destination::udp(Address::from("127.0.0.2".parse::<std::net::IpAddr>().unwrap()),12345);
        let packets = outbound.outbounds["gun-out"].connect_datagram(&SessionContext::new("test",destination.clone())).await.unwrap();
        for size in [1,127,2048] {
            let payload = bytes::Bytes::from(vec![size as u8;size]);
            packets.send(Datagram {payload:payload.clone(),source:Some(source.clone()),destination:destination.clone()}).await.unwrap();
            let received = packets.recv().await.unwrap().unwrap();
            assert_eq!(received.payload,payload); assert_eq!(received.source,Some(destination.clone())); assert_eq!(received.destination,source);
        }
        let session = sessions.recv().await.unwrap();
        assert_eq!(session.destination,destination); assert!(session.source.unwrap().ip().is_loopback());
        assert!(session.sniffing_request.is_some()); assert_eq!(session.user.unwrap().level,3);
        packets.close().await.unwrap();
        handler.close().await.unwrap();
        let _ = server.await.unwrap();
        close_features(&outbound);
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_raw_tcp_protocol_is_never_an_inbound_fallback() {
    tokio::time::timeout(LIMIT, async {
        let built = inbound_config("socks",stream(false)).unwrap();
        let handler = built.inbounds[0].1.clone();
        let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let mut raw = tokio::net::TcpStream::connect(native.local_addr().unwrap()).await.unwrap();
        raw.write_all(&[5,1,0]).await.unwrap();
        let (seen,_) = mpsc::unbounded_channel();
        assert!(tokio::time::timeout(Duration::from_millis(100),native.accept(Arc::new(Echo(seen)))).await.is_err());
        handler.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_tls_does_not_downgrade_or_accept_untrusted_certificate() {
    tokio::time::timeout(LIMIT, async {
        for insecure in [false,true] {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let alpn = if insecure { vec![b"http/1.1".to_vec()] } else { vec![b"h2".to_vec()] };
            let tls = crate::transport::internet::TlsServer::from_pem(cert.cert.pem().as_bytes(),cert.signing_key.serialize_pem().as_bytes(),alpn).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut value = stream(false); value["security"] = json!("tls");
            value["tlsSettings"] = json!({"serverName":"localhost","allowInsecure":insecure});
            let built = outbound_config("http",listener.local_addr().unwrap().port(),value).unwrap();
            let server = tokio::spawn(async move { let (socket,_) = listener.accept().await.unwrap(); let _ = tls.accept(Box::pin(socket)).await; });
            assert!(built.outbounds["gun-out"].connect(&SessionContext::new("test",Destination::tcp(Address::Domain("target.example".into()),443))).await.is_err());
            close_features(&built);
            server.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_native_dispatch_preserves_exact_tcp_peer() {
    tokio::time::timeout(LIMIT, async {
        let built = inbound_config("socks", stream(false)).unwrap();
        let handler = built.inbounds[0].1.clone();
        let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = native.local_addr().unwrap();
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let peer = socket.local_addr().unwrap();
        let (seen, mut sessions) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let task = native.accept(Arc::new(Echo(seen))).await.unwrap();
            (task.await, native)
        });
        let endpoint = Destination::tcp(address.ip().into(), address.port());
        let mut gun = GrpcDialer::new(crate::transport::internet::grpc::GrpcConfig::new("config/service!"))
            .dial_over(Box::pin(socket), &endpoint, false).await.unwrap();
        let target = Destination::tcp(Address::Domain("peer-target.example".into()), 8443);
        crate::proxy::socks::protocol::SocksProtocol::client_handshake(&mut gun, &target).await.unwrap();
        gun.write_all(b"exact-peer").await.unwrap();
        gun.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        gun.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"exact-peer");
        let session = sessions.recv().await.unwrap();
        assert_eq!(session.source, Some(peer));
        assert_eq!(session.destination, target);
        assert_eq!(session.inbound_tag, "gun-in");
        assert!(session.sniffing_request.is_some());
        let (result, native) = server.await.unwrap();
        result.unwrap();
        handler.close().await.unwrap();
        drop(native);
        close_features(&built);
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_inbound_tls_requires_negotiated_h2_before_gun() {
    tokio::time::timeout(LIMIT, async {
        let (value, _) = tls_streams(false);
        let built = inbound_config("socks", value).unwrap();
        let handler = built.inbounds[0].1.clone();
        let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = native.local_addr().unwrap();
        for alpn in [Vec::new(), vec![b"http/1.1".to_vec()]] {
            let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions().unwrap().dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::transport::internet::tls::NoCertificateVerification))
                .with_no_client_auth();
            client.alpn_protocols = alpn;
            let client = TlsConnector::from(Arc::new(client));
            let name = rustls_pki_types::ServerName::try_from("localhost".to_owned()).unwrap();
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            if let Ok(mut secured) = client.connect(name, socket).await {
                assert_ne!(secured.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                let mut bytes = Vec::new();
                let _ = secured.read_to_end(&mut bytes).await;
            }
            let (seen, _) = mpsc::unbounded_channel();
            assert!(tokio::time::timeout(Duration::from_millis(100), native.accept(Arc::new(Echo(seen)))).await.is_err());
        }
        handler.close().await.unwrap();
        close_features(&built);
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_built_outbound_sends_real_h2_authority_service_and_user_agent() {
    tokio::time::timeout(LIMIT, async {
        for (secure, ipv6) in [(false, false), (true, false), (true, true)] {
            for custom in [false, true] {
                let (inbound, mut outbound) = if secure { tls_streams(false) } else { (stream(false), stream(false)) };
                if ipv6 { outbound["tlsSettings"].as_object_mut().unwrap().remove("serverName"); }
                if custom {
                    outbound["grpcSettings"]["authority"] = json!("metadata.example:8443");
                    outbound["grpcSettings"]["user_agent"] = json!("gun-config-ci/1.0");
                }
                let inbound: StreamSettingsConfig = serde_json::from_value(inbound).unwrap();
                let tls = server_security(tls_settings(&inbound).unwrap()).unwrap();
                let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).await
                    .expect("loopback is required for the configured Gun authority regression");
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let lower: BoxStream = if let Some(tls) = tls {
                        let secured = tls.accept(socket).await.unwrap();
                        assert_eq!(secured.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                        Box::pin(secured)
                    } else { Box::pin(socket) };
                    let mut connection = h2::server::handshake(lower).await.unwrap();
                    let (request, response) = connection.accept().await.unwrap().unwrap();
                    (request, response, connection)
                });
                let mut settings = outbound_settings("vmess", address.port());
                if ipv6 { settings["vnext"][0]["address"] = json!("::1"); }
                let built = build(json!({"outbounds":[{"tag":"gun-out","protocol":"vmess","settings":settings,"streamSettings":outbound}]})).unwrap();
                let retained = built.outbounds["gun-out"].connect(&SessionContext::new("test",
                    Destination::tcp(Address::Domain("target.example".into()), 443))).await.unwrap();
                let (request, response, connection) = server.await.unwrap();
                let expected_authority = if custom { "metadata.example:8443".to_owned() }
                    else if secure && !ipv6 { "localhost".to_owned() } else { address.to_string() };
                assert_eq!(request.uri().authority().unwrap().as_str(), expected_authority);
                assert_eq!(request.uri().scheme_str(), Some(if secure { "https" } else { "http" }));
                assert_eq!(request.uri().path(), "/config%2Fservice%21/Tun");
                assert_eq!(request.headers()["content-type"], "application/grpc");
                assert_eq!(request.headers()["te"], "trailers");
                if custom { assert_eq!(request.headers()["user-agent"], "gun-config-ci/1.0"); }
                else { assert!(!request.headers().contains_key("user-agent")); }
                close_features(&built);
                drop((retained, request, response, connection));
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_configured_ipv6_tls_without_server_name_preserves_stream_and_peer() {
    tokio::time::timeout(LIMIT, async {
        for multi in [false, true] {
            let (in_stream, mut out_stream) = tls_streams(multi);
            out_stream["tlsSettings"].as_object_mut().unwrap().remove("serverName");
            let inbound = build(json!({"inbounds":[{"tag":"gun-in","protocol":"http","listen":"[::1]","port":12345,
                "settings":inbound_settings("http"),"streamSettings":in_stream}]})).unwrap();
            let handler = inbound.inbounds[0].1.clone();
            let mut native = handler.bind_native("[::1]:0".parse().unwrap()).await
                .expect("IPv6 loopback is required for the configured Gun TLS regression").unwrap();
            let address = native.local_addr().unwrap();
            assert_eq!(address.ip(), std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
            let mut settings = outbound_settings("http", address.port());
            settings["servers"][0]["address"] = json!("::1");
            let outbound = build(json!({"outbounds":[{"tag":"gun-out","protocol":"http","settings":settings,"streamSettings":out_stream}]})).unwrap();
            let (seen, mut sessions) = mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let task = native.accept(Arc::new(Echo(seen))).await.unwrap();
                (task.await, native)
            });
            let target = Destination::tcp(Address::Domain("ipv6-target.example".into()), 8443);
            let mut application = outbound.outbounds["gun-out"].connect(&SessionContext::new("test", target.clone())).await.unwrap();
            application.write_all(b"IPv6 TLS without serverName").await.unwrap();
            application.flush().await.unwrap();
            let mut received = vec![0; b"IPv6 TLS without serverName".len()];
            application.read_exact(&mut received).await.unwrap();
            assert_eq!(received, b"IPv6 TLS without serverName");
            let session = sessions.recv().await.unwrap();
            assert_eq!(session.destination, target);
            assert_eq!(session.source.unwrap().ip(), address.ip());
            handler.close().await.unwrap();
            close_features(&outbound);
            let (result, native) = server.await.unwrap();
            assert!(matches!(result, Ok(()) | Err(Error::Closed)));
            drop((application, native));
            close_features(&inbound);
        }
    }).await.unwrap();
}

struct FaultingLower;
impl AsyncRead for FaultingLower {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "injected lower read reset")))
    }
}
impl AsyncWrite for FaultingLower {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buffer: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected lower write denial")))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "injected lower flush timeout")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "injected lower shutdown failure")))
    }
}

#[tokio::test]
async fn grpc_managed_lower_preserves_read_write_flush_and_shutdown_errors() {
    tokio::time::timeout(LIMIT, async {
        let root = CancellationToken::new();
        let mut stream = managed_stream(Box::pin(FaultingLower), &root);
        let error = stream.read(&mut [0; 1]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "injected lower read reset");
        let error = stream.write(b"write").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "injected lower write denial");
        let error = stream.flush().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "injected lower flush timeout");
        let error = stream.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(error.to_string(), "injected lower shutdown failure");
    }).await.unwrap();
}

#[derive(Default)]
struct PendingProbe { read_polled: AtomicBool, write_polled: AtomicBool, dropped: AtomicBool }
struct NeverReadyLower(Arc<PendingProbe>);
impl Drop for NeverReadyLower { fn drop(&mut self) { self.0.dropped.store(true, Ordering::Release); } }
impl AsyncRead for NeverReadyLower {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.read_polled.store(true, Ordering::Release);
        // Intentionally register no lower waker: revocation must wake the
        // retained upper future even if the lower I/O never wakes it again.
        Poll::Pending
    }
}
impl AsyncWrite for NeverReadyLower {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.0.write_polled.store(true, Ordering::Release);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.write_polled.store(true, Ordering::Release);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.write_polled.store(true, Ordering::Release);
        Poll::Pending
    }
}

#[tokio::test]
async fn grpc_managed_lower_revocation_wakes_pending_read_write_flush_and_shutdown() {
    tokio::time::timeout(LIMIT, async {
        for operation in ["write", "flush", "shutdown"] {
            let root = CancellationToken::new();
            let probe = Arc::new(PendingProbe::default());
            let stream = managed_stream(Box::pin(NeverReadyLower(probe.clone())), &root);
            let (mut reader, mut writer) = tokio::io::split(stream);
            let reading = tokio::spawn(async move {
                let result = reader.read(&mut [0; 1]).await;
                (result, reader)
            });
            let writing = tokio::spawn(async move {
                let result = match operation {
                    "write" => writer.write(b"pending").await.map(|_| ()),
                    "flush" => writer.flush().await,
                    _ => writer.shutdown().await,
                };
                (result, writer)
            });
            while !probe.read_polled.load(Ordering::Acquire) || !probe.write_polled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            root.cancel();
            let (read_result, retained_reader) = reading.await.unwrap();
            let (write_result, retained_writer) = writing.await.unwrap();
            for error in [read_result.unwrap_err(), write_result.unwrap_err()] {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert_eq!(error.to_string(), "gRPC lower stream cancelled");
            }
            assert!(probe.dropped.load(Ordering::Acquire));
            drop((retained_reader, retained_writer));
        }
        let root = CancellationToken::new();
        let probe = Arc::new(PendingProbe::default());
        let retained = managed_stream(Box::pin(NeverReadyLower(probe.clone())), &root);
        root.cancel();
        while !probe.dropped.load(Ordering::Acquire) { tokio::task::yield_now().await; }
        assert!(!probe.read_polled.load(Ordering::Acquire));
        assert!(!probe.write_polled.load(Ordering::Acquire));
        drop(retained);
        let root = CancellationToken::new();
        let probe = Arc::new(PendingProbe::default());
        let unpolled = managed_stream(Box::pin(NeverReadyLower(probe.clone())), &root);
        drop(unpolled);
        assert!(probe.dropped.load(Ordering::Acquire), "drop must synchronously revoke the actual lower stream");
        assert!(!root.is_cancelled());
    }).await.unwrap();
}

struct ShutdownGate {
    output_pending: AtomicBool,
    shutdown_polled: AtomicBool,
    allow_shutdown: AtomicBool,
    shutdown_done: AtomicBool,
    waker: AtomicWaker,
}
struct DelayedShutdownLower { stream: tokio::io::DuplexStream, gate: Arc<ShutdownGate> }
impl AsyncRead for DelayedShutdownLower {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for DelayedShutdownLower {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buffer);
        if result.is_pending() { self.gate.output_pending.store(true, Ordering::Release); }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gate.waker.register(cx.waker());
        self.gate.shutdown_polled.store(true, Ordering::Release);
        if !self.gate.allow_shutdown.load(Ordering::Acquire) { return Poll::Pending; }
        let result = Pin::new(&mut self.stream).poll_shutdown(cx);
        if matches!(&result, Poll::Ready(Ok(()))) { self.gate.shutdown_done.store(true, Ordering::Release); }
        result
    }
}

#[tokio::test]
async fn grpc_managed_lower_half_close_waits_for_pending_output_and_actual_shutdown() {
    tokio::time::timeout(LIMIT, async {
        let root = CancellationToken::new();
        let gate = Arc::new(ShutdownGate { output_pending: AtomicBool::new(false), shutdown_polled: AtomicBool::new(false),
            allow_shutdown: AtomicBool::new(false), shutdown_done: AtomicBool::new(false), waker: AtomicWaker::new() });
        let (lower, mut peer) = tokio::io::duplex(4096);
        let mut managed = managed_stream(Box::pin(DelayedShutdownLower { stream: lower, gate: gate.clone() }), &root);
        let payload: Vec<_> = (0..131137).map(|i| (i * 37 % 251) as u8).collect();
        let expected = payload.clone();
        let sending = tokio::spawn(async move {
            managed.write_all(&payload).await.unwrap();
            managed.shutdown().await.unwrap();
            managed
        });
        while !gate.output_pending.load(Ordering::Acquire) { tokio::task::yield_now().await; }
        assert!(!gate.shutdown_polled.load(Ordering::Acquire));
        let mut received = vec![0; expected.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        while !gate.shutdown_polled.load(Ordering::Acquire) { tokio::task::yield_now().await; }
        assert!(!gate.shutdown_done.load(Ordering::Acquire));
        assert!(!sending.is_finished(), "upper shutdown completed before the lower shutdown");
        assert!(tokio::time::timeout(Duration::from_millis(25), peer.read(&mut [0; 1])).await.is_err());
        gate.allow_shutdown.store(true, Ordering::Release);
        gate.waker.wake();
        let mut retained = sending.await.unwrap();
        assert!(gate.shutdown_done.load(Ordering::Acquire));
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        peer.write_all(b"read after half-close").await.unwrap();
        let mut reply = vec![0; b"read after half-close".len()];
        retained.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, b"read after half-close");
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_configured_plain_and_tls_half_close_drain_exact_payload() {
    tokio::time::timeout(LIMIT, async {
        for (secure, multi) in [(false, false), (false, true), (true, false), (true, true)] {
            let (in_stream, out_stream) = if secure { tls_streams(multi) } else { (stream(multi), stream(multi)) };
            let inbound = inbound_config("http", in_stream).unwrap();
            let handler = inbound.inbounds[0].1.clone();
            let mut native = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            let outbound = outbound_config("http", native.local_addr().unwrap().port(), out_stream).unwrap();
            let (seen, mut sessions) = mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let task = native.accept(Arc::new(Echo(seen))).await.unwrap();
                (task.await, native)
            });
            let target = Destination::tcp(Address::Domain("half-close.example".into()), 443);
            let application = outbound.outbounds["gun-out"].connect(&SessionContext::new("test", target.clone())).await.unwrap();
            let payload: Vec<_> = (0..131137).map(|i| (i * 37 % 251) as u8).collect();
            let expected = payload.clone();
            let (mut reader, mut writer) = tokio::io::split(application);
            let sending = async { writer.write_all(&payload).await.unwrap(); writer.shutdown().await.unwrap(); };
            let receiving = async { let mut received = Vec::new(); reader.read_to_end(&mut received).await.unwrap(); received };
            let ((), received) = tokio::join!(sending, receiving);
            assert_eq!(received, expected);
            assert_eq!(sessions.recv().await.unwrap().destination, target);
            let (result, native) = server.await.unwrap();
            result.unwrap();
            handler.close().await.unwrap();
            close_features(&outbound);
            drop(native);
            close_features(&inbound);
        }
    }).await.unwrap();
}
