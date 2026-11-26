use super::*;
use super::super::{WireGuardPeer, WireGuardServer};
use base64::Engine as _;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyVectors { alice_secret: String, alice_public: String, bob_secret: String, bob_public: String }
fn vectors() -> KeyVectors {
    serde_json::from_str(include_str!("../../testing/wireguard-reference/generated/wireguard-key-vectors.json"))
        .expect("independent Go fixture")
}
fn config(alice: bool, endpoint: &str) -> WireGuardConfig {
    let keys = vectors();
    WireGuardConfig {
        secret_key: if alice { keys.alice_secret } else { keys.bob_secret },
        address: if alice { vec!["10.77.0.2/32".into(), "fd77::2/128".into()] }
            else { vec!["10.77.0.1/32".into(), "fd77::1/128".into()] },
        peers: vec![WireGuardPeer {
            public_key: if alice { keys.bob_public } else { keys.alice_public },
            endpoint: endpoint.into(), keepalive: 1,
            allowed_ips: if alice { vec!["0.0.0.0/0".into(), "::/0".into()] }
                else { vec!["10.77.0.2/32".into(), "fd77::2/128".into()] },
            ..WireGuardPeer::default()
        }], mtu: Some(1280), ..WireGuardConfig::default()
    }
}

#[test]
fn independent_go_key_vectors_match_boringtun() {
    use sha2::Digest as _;
    assert_eq!(hex::encode(sha2::Sha256::digest(include_bytes!("../../testing/wireguard-reference/generated/wireguard-key-vectors.json"))),
        "711505b1551b672f0cbb84c7135ef1a12f33a21a618e67ee52b72050881ffed0");
    let keys = vectors();
    for (secret, expected) in [(keys.alice_secret, keys.alice_public), (keys.bob_secret, keys.bob_public)] {
        let bytes = super::super::parse_key(&secret).unwrap();
        assert_eq!(hex::encode(PublicKey::from(&StaticSecret::from(bytes)).as_bytes()), expected);
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert_eq!(super::super::parse_key(&b64).unwrap(), bytes);
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(super::super::parse_key(&b64url).unwrap(), bytes);
    }
}

#[test]
fn config_camel_case_defaults_and_validation() {
    let keys = vectors();
    let json = serde_json::json!({"secretKey":keys.alice_secret, "peers":[{
        "publicKey":keys.bob_public, "preSharedKey":hex::encode([42;32]),
        "endpoint":"localhost:51820", "keepAlive":25, "allowedIPs":["10.77.0.0/24"], "email":"peer@example.com", "level":7
    }], "reserved":[1,2,3], "remoteDNS":["10.77.0.1"]});
    let config: WireGuardConfig = serde_json::from_value(json).unwrap();
    config.validate().unwrap();
    assert_eq!(config.peers[0].keepalive, 25);
    assert_eq!(config.peers[0].allowed_ips, ["10.77.0.0/24"]);
    assert_eq!(config.peers[0].email, "peer@example.com"); assert_eq!(config.peers[0].level, 7);
    assert_eq!(serde_json::to_value(&config).unwrap()["peers"][0]["keepAlive"], 25);
    assert!(!format!("{config:?}").contains(&config.secret_key));
    let mut invalid = config.clone(); invalid.secret_key = "AA==".into(); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.secret_key = format!("{}===", base64::engine::general_purpose::STANDARD_NO_PAD.encode([7;32])); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.secret_key = hex::encode([0;32]); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.reserved = Some(vec![0,1]); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.mtu = Some(1279); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.mtu = Some(65535); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.peers[0].endpoint = "host:0".into(); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.peers[0].allowed_ips = vec!["10.0.0.0/33".into()]; assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.peers.push(invalid.peers[0].clone()); assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.peers[0].public_key = vectors().alice_public; assert!(invalid.validate().is_err());
    let mut invalid = config.clone(); invalid.peers[0].public_key = hex::encode([0;32]); assert!(invalid.validate().is_err());
    let mut empty_routes = config; empty_routes.peers[0].allowed_ips.clear();
    assert!(route_peer(&empty_routes.validated().unwrap(), "10.77.0.1".parse().unwrap()).is_none());
    let keys = vectors();
    let defaults: WireGuardConfig = serde_json::from_value(serde_json::json!({"secretKey":keys.alice_secret,
        "peers":[{"publicKey":keys.bob_public}]})).unwrap();
    assert_eq!(defaults.peers[0].allowed_ips.len(), 2);
    assert_eq!(defaults.address.len(), 2);
}

#[test]
fn longest_prefix_and_exact_prefix_last_owner() {
    let mut config = config(true, "127.0.0.1:51820");
    let key = PublicKey::from(&StaticSecret::from([9;32]));
    config.peers.push(WireGuardPeer { public_key: hex::encode(key.as_bytes()),
        allowed_ips: vec!["10.77.0.0/24".into()], ..WireGuardPeer::default() });
    let key = PublicKey::from(&StaticSecret::from([8;32]));
    config.peers.push(WireGuardPeer { public_key: hex::encode(key.as_bytes()),
        allowed_ips: vec!["10.77.0.0/24".into(), "fd77::/64".into()], ..WireGuardPeer::default() });
    let config = config.validated().unwrap();
    assert_eq!(route_peer(&config, "1.1.1.1".parse().unwrap()), Some(0));
    assert_eq!(route_peer(&config, "10.77.0.7".parse().unwrap()), Some(2));
    assert_eq!(route_peer(&config, "fd77::7".parse().unwrap()), Some(2));
}

fn udp4(source: [u8;4], destination: [u8;4], payload: &[u8]) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ipv4(source, destination, 64).udp(12345, 9001);
    let mut packet = Vec::new(); builder.write(&mut packet, payload).unwrap(); packet
}

#[test]
fn inbound_ipv6_fragments_reassemble_before_socket_provisioning_and_validate_udp_checksum() {
    let source = "fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let destination = "fd77::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let payload = (0..8192).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let mut packet = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64).udp(12345, 9001)
        .write(&mut packet, &payload).unwrap();
    // Encode the RFC 8200 wire layout independently of the product fragmenter.
    let fragments = packet[40..].chunks(1232).enumerate().map(|(index, chunk)| {
        let mut fragment = packet[..40].to_vec();
        fragment[4..6].copy_from_slice(&((chunk.len() + 8) as u16).to_be_bytes());
        fragment[6] = 44;
        fragment.extend_from_slice(&[17, 0]);
        let offset = index * 1232;
        let flags = offset as u16 | u16::from(offset + chunk.len() < packet.len() - 40);
        fragment.extend_from_slice(&flags.to_be_bytes());
        fragment.extend_from_slice(&0x12345678u32.to_be_bytes());
        fragment.extend_from_slice(chunk);
        fragment
    }).collect::<Vec<_>>();
    assert_eq!(fragments.len(), 7);
    for valid_checksum in [true, false] {
        let mut stack = Stack::new(&config(false, "").validated().unwrap(), true, 1).unwrap();
        for (index, fragment) in fragments.iter().enumerate().rev() {
            let mut fragment = fragment.clone();
            if !valid_checksum && index == 0 { fragment[56] ^= 1; }
            stack.ingest(fragment);
            stack.poll(smoltcp::time::Instant::from_millis(0));
            if index != 0 { assert!(stack.take_udp().is_empty()); }
        }
        let received = stack.take_udp();
        if valid_checksum {
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, payload);
            assert_eq!(received[0].source, "[fd77::2]:12345".parse().unwrap());
            assert_eq!(received[0].destination, "[fd77::1]:9001".parse().unwrap());
        } else { assert!(received.is_empty(), "reassembly must preserve UDP checksum validation"); }
    }
}
fn peers() -> (NoisePeers, NoisePeers, SocketAddr, SocketAddr) {
    let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    (NoisePeers::new(Arc::new(config(true, &b.to_string()).validated().unwrap()), vec![Some(b)]),
        NoisePeers::new(Arc::new(config(false, &a.to_string()).validated().unwrap()), vec![Some(a)]), a, b)
}
fn handshake(a: &mut NoisePeers, b: &mut NoisePeers, source_a: SocketAddr, source_b: SocketAddr, packet: Vec<u8>) -> Vec<u8> {
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    let (_, mut initiation) = a.encapsulate(packet, &mut buffer).unwrap();
    assert_eq!(initiation.len(), 148);
    let received = b.receive(source_a, &mut initiation, &mut buffer);
    assert!(received.authenticated);
    let mut response = received.network.into_iter().find(|(_, packet)| packet[0] == 2).unwrap().1;
    assert_eq!(response.len(), 92);
    let received = a.receive(source_b, &mut response, &mut buffer);
    assert!(received.authenticated);
    let mut encrypted = None;
    for (_, mut data) in received.network {
        if data.len() == 32 { assert!(b.receive(source_a, &mut data, &mut buffer).authenticated); }
        else { encrypted = Some(data); }
    }
    encrypted.expect("handshake must flush the queued IP packet")
}

#[test]
fn encrypted_noise_rejects_tampering_replay_and_spoofed_allowed_ip() {
    let (mut a, mut b, source_a, source_b) = peers();
    let payload = b"distinct private application payload never sent as raw UDP";
    let packet = udp4([10,77,0,2], [10,77,0,1], payload);
    let encrypted = handshake(&mut a, &mut b, source_a, source_b, packet.clone());
    assert!(!encrypted.windows(payload.len()).any(|window| window == payload));
    assert_eq!(encrypted[0], 4);
    assert_eq!((encrypted.len() - 32) % 16, 0);
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    let attacker: SocketAddr = "127.0.0.1:30003".parse().unwrap();
    let mut modified = encrypted.clone(); let last = modified.len() - 1; modified[last] ^= 0x80;
    let rejected = b.receive(attacker, &mut modified, &mut buffer);
    assert!(!rejected.authenticated); assert!(rejected.packets.is_empty());
    assert_eq!(b.peers[0].endpoint, Some(source_a));
    let mut valid = encrypted.clone();
    let accepted = b.receive(source_a, &mut valid, &mut buffer);
    assert_eq!(accepted.packets, [packet]); assert!(accepted.authenticated);
    let mut replay = encrypted;
    let rejected = b.receive(attacker, &mut replay, &mut buffer);
    assert!(!rejected.authenticated); assert!(rejected.packets.is_empty());
    let spoof = udp4([10,99,99,99], [10,77,0,1], b"spoofed-source");
    let (_, mut encrypted) = a.encapsulate(spoof, &mut buffer).unwrap();
    assert!(b.receive(source_a, &mut encrypted, &mut buffer).packets.is_empty());
    let (_, mut encrypted) = a.encapsulate(udp4([10,77,0,2], [10,77,0,1], b"roaming"), &mut buffer).unwrap();
    assert!(b.receive(attacker, &mut encrypted, &mut buffer).authenticated);
    assert_eq!(b.peers[0].endpoint, Some(attacker));
}

#[test]
fn wrong_preshared_key_cannot_complete_noise_handshake() {
    let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    let mut config_a = config(true, &b.to_string()); config_a.peers[0].pre_shared_key = Some(hex::encode([1;32]));
    let mut config_b = config(false, &a.to_string()); config_b.peers[0].pre_shared_key = Some(hex::encode([2;32]));
    let mut a_peer = NoisePeers::new(Arc::new(config_a.validated().unwrap()), vec![Some(b)]);
    let mut b_peer = NoisePeers::new(Arc::new(config_b.validated().unwrap()), vec![Some(a)]);
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    let (_, mut initiation) = a_peer.encapsulate(udp4([10,77,0,2], [10,77,0,1], b"secret"), &mut buffer).unwrap();
    let mut response = b_peer.receive(a, &mut initiation, &mut buffer).network.pop().unwrap().1;
    let received = a_peer.receive(b, &mut response, &mut buffer);
    assert!(!received.authenticated); assert!(received.packets.is_empty()); assert!(received.network.is_empty());
}

#[test]
fn unknown_peer_and_plaintext_never_enter_ip_stack() {
    let (_, mut b, source_a, _) = peers();
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    let mut raw = udp4([10,77,0,2], [10,77,0,1], b"plaintext");
    assert!(b.receive(source_a, &mut raw, &mut buffer).packets.is_empty());
    let mut unknown = config(true, "127.0.0.1:10002"); unknown.secret_key = hex::encode([19;32]);
    let mut a = NoisePeers::new(Arc::new(unknown.validated().unwrap()), vec![Some("127.0.0.1:10002".parse().unwrap())]);
    let (_, mut initiation) = a.encapsulate(udp4([10,77,0,2], [10,77,0,1], b"unknown"), &mut buffer).unwrap();
    let received = b.receive(source_a, &mut initiation, &mut buffer);
    assert!(!received.authenticated); assert!(received.network.is_empty()); assert!(received.packets.is_empty());
}

#[tokio::test]
async fn persistent_keepalive_and_handshake_retransmission_timers() {
    let (mut a, mut b, source_a, source_b) = peers();
    let mut encrypted = handshake(&mut a, &mut b, source_a, source_b,
        udp4([10,77,0,2], [10,77,0,1], b"establish"));
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    assert!(b.receive(source_a, &mut encrypted, &mut buffer).authenticated);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(a.timers(&mut buffer).iter().any(|(_, packet)| packet[0] == 4 && packet.len() == 32));
    let (mut waiting, _, _, _) = peers();
    let first = waiting.encapsulate(udp4([10,77,0,2], [10,77,0,1], b"dropped initiation"), &mut buffer).unwrap().1;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let retry = waiting.timers(&mut buffer).into_iter().find(|(_, packet)| packet[0] == 1).expect("retransmit handshake").1;
    assert_ne!(first, retry);
}

#[tokio::test]
async fn real_encrypted_loopback_tcp_udp_dual_stack_mtu_fragmentation_and_empty_datagrams() {
    let server = Arc::new(WireGuardServer::bind("wg-in", config(false, ""), "127.0.0.1:0".parse().unwrap()).await.unwrap());
    let client = WireGuardDevice::bind(config(true, &server.local_addr().to_string()), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let echo = {
        let server = server.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let mut accepted = server.accept().await.unwrap();
                assert!(accepted.session.destination.port == 9000);
                let mut payload = vec![0; 48 * 1024];
                accepted.stream.read_exact(&mut payload).await.unwrap();
                accepted.stream.write_all(&payload).await.unwrap();
            }
        })
    };
    for destination in ["10.77.0.1:9000", "[fd77::1]:9000"] {
        let mut stream = tokio::time::timeout(Duration::from_secs(10), client.connect_tcp(destination.parse().unwrap())).await.unwrap().unwrap();
        let payload = vec![0x5a; 48 * 1024];
        stream.write_all(&payload).await.unwrap();
        let mut response = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut response)).await.unwrap().unwrap();
        assert_eq!(response, payload);
    }
    echo.await.unwrap();
    for destination in ["10.77.0.1:9001", "[fd77::1]:9001"] {
        let socket = client.connect_udp(destination.parse().unwrap()).unwrap();
        for length in [0, 1, 8192] {
            let payload = (0..length).map(|index| (index % 251) as u8).collect::<Vec<_>>();
            socket.send(&payload).await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(10), server.recv_datagram()).await
                .unwrap_or_else(|_| panic!("UDP ingress timeout: destination={destination} payload_length={length}")).unwrap();
            assert_eq!(received.data, payload); assert_eq!(received.destination.port(), 9001);
            received.reply(&received.data).unwrap();
            let mut response = vec![0; 65535];
            let len = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut response)).await
                .unwrap_or_else(|_| panic!("UDP reply timeout: destination={destination} payload_length={length}")).unwrap();
            assert_eq!(&response[..len], payload);
        }
    }
    assert!(client.stats().encrypted_sent > 0); assert!(server.device().stats().authenticated_packets > 0);
    client.close().await.unwrap(); server.close().await.unwrap();
}

#[tokio::test]
async fn device_close_wakes_pending_socket_read_and_joins_worker() {
    let device = WireGuardDevice::bind(config(true, "127.0.0.1:9"), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let socket = device.connect_udp("10.77.0.1:9001".parse().unwrap()).unwrap();
    let read = tokio::spawn(async move { let mut buffer = [0;32]; socket.recv(&mut buffer).await });
    tokio::task::yield_now().await; device.close().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), read).await.unwrap().unwrap().is_err());
    device.close().await.unwrap();
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoReady { endpoint: String, public_key: String }
struct GoPeer { child: tokio::process::Child, ready: GoReady }
impl Drop for GoPeer { fn drop(&mut self) { let _ = self.child.start_kill(); } }
impl GoPeer {
    async fn start() -> Self {
        let executable = std::env::var_os("XRAY_WIREGUARD_REFERENCE")
            .expect("live Go interoperability requires XRAY_WIREGUARD_REFERENCE; never silently skip this gate");
        let mut child = tokio::process::Command::new(executable).args(["-mode", "serve", "-mtu", "1280"])
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()).kill_on_drop(true).spawn().expect("start independent Go peer on Ubuntu");
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout); let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line)).await.unwrap().unwrap();
        let ready: GoReady = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("Go readiness JSON: {error}; stdout line: {line:?}"));
        assert_eq!(ready.public_key, vectors().bob_public);
        Self { child, ready }
    }
}
async fn go_tcp(destination: &str) {
    let go = GoPeer::start().await;
    let client = super::super::Client::try_new("wg-out", config(true, &go.ready.endpoint)).unwrap();
    let destination: crate::common::net::Destination = destination.parse().unwrap();
    let session = crate::common::protocol::SessionContext::new("test", destination);
    let mut stream = crate::features::outbound::OutboundHandler::connect(&client, &session).await.unwrap();
    let payload = (0..48000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    stream.write_all(&payload).await.unwrap();
    let mut response = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut response)).await.unwrap().unwrap();
    assert_eq!(response, payload); assert!(client.device().await.unwrap().stats().authenticated_packets > 0);
    crate::features::outbound::OutboundHandler::close(&client).await.unwrap();
}
async fn go_udp(destination: &str) {
    let go = GoPeer::start().await;
    use crate::common::net::datagram::Datagram;
    use crate::features::outbound::OutboundHandler;
    let client = super::super::Client::try_new("wg-out", config(true, &go.ready.endpoint)).unwrap();
    let remote = super::super::datagram::udp_destination(destination.parse().unwrap());
    let local = super::super::datagram::udp_destination("198.51.100.7:34567".parse().unwrap());
    let session = crate::common::protocol::SessionContext::new("test", remote.clone());
    let socket = client.connect_datagram(&session).await.unwrap();
    for length in [0, 7, 8192] {
        let payload = (0..length).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        socket.send(Datagram { payload: payload.clone().into(), source: Some(local.clone()), destination: remote.clone() }).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(20), socket.recv()).await.unwrap().unwrap().unwrap();
        assert_eq!(response.payload.as_ref(), payload); assert_eq!(response.source, Some(remote.clone()));
        assert_eq!(response.destination, local);
    }
    assert!(client.device().await.unwrap().stats().authenticated_packets > 0);
    socket.close().await.unwrap(); client.close().await.unwrap();
}

// These tests are explicitly ignored in the ordinary test suite, never reported
// as successful live interop when no independent executable was supplied. CI
// must require the env var and run --include-ignored (or --ignored).
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_tcp_ipv4() { go_tcp("10.77.0.1:9000").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_tcp_ipv6() { go_tcp("[fd77::1]:9000").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_udp_ipv4_fragmentation() { go_udp("10.77.0.1:9001").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_udp_ipv6_fragmentation() { go_udp("[fd77::1]:9001").await; }


struct EchoDispatcher { payload_length: usize }
#[async_trait::async_trait]
impl crate::features::inbound::InboundDispatcher for EchoDispatcher {
    async fn dispatch_stream(&self, mut stream: crate::common::net::BoxStream,
        _session: crate::common::protocol::SessionContext) -> Result<()> {
        let mut payload = vec![0; self.payload_length];
        stream.read_exact(&mut payload).await?; stream.write_all(&payload).await?;
        stream.shutdown().await?; Ok(())
    }
    async fn dispatch_datagrams(&self, transport: crate::common::net::datagram::BoxDatagram,
        session: crate::common::protocol::SessionContext) -> Result<()> {
        use crate::common::net::datagram::Datagram;
        let packet = transport.recv().await?.ok_or(Error::Closed)?;
        assert_eq!(packet.destination, session.destination);
        assert_eq!(packet.source.as_ref().and_then(|source| source.to_socket_addr()), session.source);
        let reply = Datagram { payload: packet.payload, source: Some(packet.destination),
            destination: packet.source.ok_or(Error::Closed)? };
        transport.send(reply).await?;
        transport.close().await
    }
}

async fn go_probe_rust_server(tcp: bool, destination: &str) {
    use crate::features::inbound::InboundHandler;
    let executable = std::env::var_os("XRAY_WIREGUARD_REFERENCE")
        .expect("live Go interoperability requires XRAY_WIREGUARD_REFERENCE; never silently skip this gate");
    let handler = super::super::WireGuardInbound::try_new("wg-native", config(true, "")).unwrap();
    let mut listener = handler.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
    let payload = (0..8192).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let child = tokio::process::Command::new(executable).args([
        "-mode", if tcp { "probe-tcp" } else { "probe-udp" }, "-peer-endpoint", &listener.local_addr().unwrap().to_string(),
        "-target", destination, "-payload", &hex::encode(&payload), "-mtu", "1280",
    ]).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit())
        .kill_on_drop(true).spawn().expect("start independent Go probe on Ubuntu");
    let operation = async {
        let dispatcher = Arc::new(EchoDispatcher { payload_length: payload.len() });
        let task = listener.accept(dispatcher).await.unwrap();
        let (accepted, output) = tokio::join!(task, child.wait_with_output());
        accepted.unwrap(); let output = output.unwrap();
        assert!(output.status.success(), "independent Go probe failed: {}", output.status);
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["reply"], hex::encode(&payload));
        assert_eq!(response["publicKey"], vectors().bob_public);
    };
    tokio::time::timeout(Duration::from_secs(30), operation).await.unwrap();
    handler.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_to_rust_server_tcp_ipv4() { go_probe_rust_server(true, "10.77.0.2:9000").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_to_rust_server_tcp_ipv6() { go_probe_rust_server(true, "[fd77::2]:9000").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_to_rust_server_udp_ipv4_fragmentation() { go_probe_rust_server(false, "10.77.0.2:9001").await; }
#[tokio::test]
#[ignore = "requires frozen Go reference executable on Ubuntu"]
async fn live_go_to_rust_server_udp_ipv6_fragmentation() { go_probe_rust_server(false, "[fd77::2]:9001").await; }

#[tokio::test]
async fn native_datagrams_keep_boundaries_original_source_and_multiple_destinations() {
    use crate::common::net::datagram::Datagram;
    use crate::features::{inbound::InboundHandler, outbound::OutboundHandler};
    let server = super::super::WireGuardInbound::try_new("wg-native", config(false, "")).unwrap();
    let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
    let client = super::super::Client::try_new("wg-out", config(true, &listener.local_addr().unwrap().to_string())).unwrap();
    let session = crate::common::protocol::SessionContext::new("test", "10.77.0.1:9001".parse().unwrap());
    let packets = client.connect_datagram(&session).await.unwrap();
    let source = super::super::datagram::udp_destination("198.51.100.7:12345".parse().unwrap());
    let echo = tokio::spawn(async move {
        for _ in 0..6 {
            let task = listener.accept(Arc::new(EchoDispatcher { payload_length: 0 })).await.unwrap();
            task.await.unwrap();
        }
        // The caller closes the client only after consuming the final response.
        listener
    });
    for (index, target) in ["10.77.0.1:9001", "[fd77::1]:9001", "10.77.0.1:9002", "[fd77::1]:9002", "203.0.113.8:9003", "[fd88::8]:9003"].iter().enumerate() {
        let destination = super::super::datagram::udp_destination(target.parse().unwrap());
        let payload = vec![index as u8; if index == 0 { 0 } else { index * 2000 }];
        packets.send(Datagram { payload: payload.clone().into(), source: Some(source.clone()), destination: destination.clone() }).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), packets.recv()).await
            .unwrap_or_else(|_| panic!("native UDP reply timeout: destination={target} payload_length={}", payload.len())).unwrap().unwrap();
        assert_eq!(response.payload.as_ref(), payload); assert_eq!(response.source, Some(destination));
        assert_eq!(response.destination, source);
    }
    let listener = echo.await.unwrap();
    let waiting = { let packets = packets.clone(); tokio::spawn(async move { packets.recv().await }) };
    tokio::task::yield_now().await; packets.close().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), waiting).await.unwrap().unwrap().unwrap().is_none());
    client.close().await.unwrap(); server.close().await.unwrap(); drop(listener);
}


#[test]
fn preshared_key_authenticates_real_noise_transport() {
    let source_a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let source_b: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    let mut config_a = config(true, &source_b.to_string());
    let mut config_b = config(false, &source_a.to_string());
    for config in [&mut config_a, &mut config_b] { config.peers[0].pre_shared_key = Some(hex::encode([23;32])); }
    let mut a = NoisePeers::new(Arc::new(config_a.validated().unwrap()), vec![Some(source_b)]);
    let mut b = NoisePeers::new(Arc::new(config_b.validated().unwrap()), vec![Some(source_a)]);
    let packet = udp4([10,77,0,2], [10,77,0,1], b"psk-authenticated payload");
    let mut encrypted = handshake(&mut a, &mut b, source_a, source_b, packet.clone());
    let received = b.receive(source_a, &mut encrypted, &mut vec![0; MAX_DATAGRAM + 64]);
    assert!(received.authenticated); assert_eq!(received.packets, [packet]);
}

#[tokio::test]
async fn tcp_half_close_keeps_response_readable_and_peer_metadata() {
    let mut config_b = config(false, "");
    config_b.peers[0].email = "alice@example.com".into(); config_b.peers[0].level = 7;
    let server = Arc::new(WireGuardServer::bind("wg-in", config_b, "127.0.0.1:0".parse().unwrap()).await.unwrap());
    let client = WireGuardDevice::bind(config(true, &server.local_addr().to_string()), "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let echo = {
        let server = server.clone(); tokio::spawn(async move {
            let mut accepted = server.accept().await.unwrap();
            let user = accepted.session.user.unwrap(); assert_eq!(user.email, "alice@example.com"); assert_eq!(user.level, 7);
            let mut payload = Vec::new(); accepted.stream.read_to_end(&mut payload).await.unwrap();
            accepted.stream.write_all(&payload).await.unwrap(); accepted.stream.shutdown().await.unwrap();
        })
    };
    let mut stream = client.connect_tcp("10.77.0.1:9000".parse().unwrap()).await.unwrap();
    let payload = vec![42; 16000]; stream.write_all(&payload).await.unwrap(); stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await.unwrap().unwrap();
    assert_eq!(response, payload); echo.await.unwrap(); client.close().await.unwrap(); server.close().await.unwrap();
}
