//! Runtime boundary tests. Rust loopback is lifecycle evidence, not live Go parity.
use std::{net::SocketAddr, sync::Arc, time::Duration};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use sha2::Digest;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::mpsc, task::{JoinHandle, JoinSet}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram}}, protocol::{SessionContext, User}}, features::{inbound::{InboundDispatcher, InboundHandler, NativeInboundListener}, outbound::OutboundHandler}};
use super::{Client, Server, Shadowsocks2022Config, cipher::CipherMethod, multi_server::{MultiUserServer, UserAccount}, relay_server::{RelayServer, RelayTarget}, udp_session::ClientUdpSession};

const WAIT: Duration = Duration::from_secs(10);
const METHODS: [CipherMethod; 3] = [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm, CipherMethod::ChaCha20Poly1305];
fn name(method: CipherMethod) -> &'static str {
    match method {
        CipherMethod::Aes128Gcm => "2022-blake3-aes-128-gcm",
        CipherMethod::Aes256Gcm => "2022-blake3-aes-256-gcm",
        CipherMethod::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
    }
}
fn config(method: CipherMethod, keys: &[Vec<u8>], network: &str) -> Shadowsocks2022Config {
    Shadowsocks2022Config { method: name(method).into(), key: keys.iter().map(|key| base64::engine::general_purpose::STANDARD.encode(key)).collect::<Vec<_>>().join(":"), network: Some(network.into()) }
}
fn udp(address: &str) -> Destination { Destination::parse_str(address, Network::Udp).unwrap() }
fn target() -> Destination { udp("target.example:443") }
fn user() -> User { User::with_email(uuid::Uuid::nil(), "native@example", 9) }

struct Echo { events: mpsc::UnboundedSender<(Datagram, SessionContext)> }
#[async_trait]
impl InboundDispatcher for Echo {
    async fn dispatch_stream(&self, mut stream: BoxStream, session: SessionContext) -> Result<()> {
        assert_eq!(session.destination.network, Network::Tcp);
        let mut buffer = [0; 1024];
        loop {
            let length = stream.read(&mut buffer).await?;
            if length == 0 { stream.shutdown().await?; return Ok(()); }
            stream.write_all(&buffer[..length]).await?;
            stream.flush().await?;
        }
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        while let Some(packet) = packets.recv().await? {
            let _ = self.events.send((packet.clone(), session.clone()));
            packets.send(Datagram { payload: packet.payload, source: Some(packet.destination), destination: packet.source.ok_or_else(|| Error::Protocol("missing request source".into()))? }).await?;
        }
        Ok(())
    }
}
fn echo() -> (Arc<dyn InboundDispatcher>, mpsc::UnboundedReceiver<(Datagram, SessionContext)>) {
    let (events, receiver) = mpsc::unbounded_channel();
    (Arc::new(Echo { events }), receiver)
}

struct Running { address: SocketAddr, task: JoinHandle<()> }
impl Drop for Running { fn drop(&mut self) { self.task.abort(); } }
fn run(mut listener: Box<dyn NativeInboundListener>, dispatcher: Arc<dyn InboundDispatcher>) -> Running {
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                task = listener.accept(dispatcher.clone()) => {
                    match task {
                        Ok(task) => { children.spawn(task); }
                        Err(Error::Closed) => return,
                        Err(error) => panic!("native accept: {error}"),
                    }
                }
                completed = children.join_next(), if !children.is_empty() => {
                    completed.unwrap().unwrap().unwrap();
                }
            }
        }
    });
    Running { address, task }
}

#[tokio::test]
async fn ss2022_native_udp_real_traits_single_multi_and_packet_sources() {
    tokio::time::timeout(WAIT, async {
        for method in METHODS {
            for multi in [false, true] {
                if multi && method.is_chacha() { continue; }
                let key = vec![3; method.key_length()];
                let master = vec![5; method.key_length()];
                let keys = if multi { vec![master.clone(), key.clone()] } else { vec![key.clone()] };
                let inbound: Arc<dyn InboundHandler> = if multi {
                    let server = MultiUserServer::new("native", method, master).unwrap().with_network(Some("udp")).unwrap();
                    server.add_account(UserAccount { key, user: user() }).unwrap();
                    Arc::new(server)
                } else { Arc::new(Server::try_new("native", config(method, &keys, "udp")).unwrap().with_user(user())) };
                let listener = inbound.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
                let (dispatcher, mut events) = echo();
                let running = run(listener, dispatcher);
                // UDP-only must leave the TCP port free.
                let tcp_probe = TcpListener::bind(running.address).await.unwrap();
                drop(tcp_probe);
                let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("out", Destination::from(running.address), config(method, &keys, "tcp")).unwrap());
                let mut context = SessionContext::new("local", target());
                context.source = Some("192.0.2.1:42000".parse().unwrap());
                let packets = client.connect_datagram(&context).await.unwrap();
                assert!(tokio::time::timeout(Duration::from_millis(10), packets.recv()).await.is_err());
                let logical = udp("198.51.100.10:53000");
                for (index, payload) in [Vec::new(), vec![0x5a; 7900], b"after-large".to_vec()].into_iter().enumerate() {
                    let destination = if index == 1 { udp("[2001:db8::53]:5353") } else { target() };
                    let source = if index == 0 { Some(logical.clone()) } else { None };
                    packets.send(Datagram { payload: Bytes::from(payload.clone()), source, destination: destination.clone() }).await.unwrap();
                    let response = packets.recv().await.unwrap().unwrap();
                    assert_eq!(response.payload.as_ref(), payload.as_slice());
                    assert_eq!(response.destination, logical);
                    assert_eq!(response.source, Some(destination.clone()));
                    let (request, session) = events.recv().await.unwrap();
                    assert_eq!(request.destination, destination);
                    assert_eq!(request.payload.as_ref(), payload.as_slice());
                    assert_eq!(request.source.unwrap().to_socket_addr(), session.source);
                    assert_eq!(session.inbound_tag, "native");
                    assert_eq!(session.user.as_ref().unwrap().email, "native@example");
                    assert_eq!(session.user.unwrap().level, 9);
                }
                assert!(packets.send(Datagram { payload: Bytes::new(), source: Some(udp("198.51.100.11:53000")), destination: target() }).await.is_err());
                // Oversize wire packets must fail whole, with no truncation or
                // loss of subsequent legal packets in this association.
                for size in [8192, 8193, 65_507] {
                    assert!(packets.send(Datagram { payload: Bytes::from(vec![0; size]), source: None, destination: target() }).await.is_err());
                }
                packets.send(Datagram { payload: Bytes::new(), source: None, destination: target() }).await.unwrap();
                assert!(packets.recv().await.unwrap().unwrap().payload.is_empty());
                let pending = { let packets = packets.clone(); tokio::spawn(async move { packets.recv().await }) };
                client.close().await.unwrap();
                assert!(pending.await.unwrap().unwrap().is_none());
                packets.close().await.unwrap();
                packets.close().await.unwrap();
                assert!(matches!(packets.send(Datagram::new(Bytes::new(), target()).unwrap()).await, Err(Error::Closed)));
                assert!(matches!(client.connect_datagram(&context).await, Err(Error::Closed)));
                inbound.close().await.unwrap();
                drop(running);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_native_dual_network_same_port_and_udp_reply_fallback() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::ChaCha20Poly1305;
        let keys = vec![vec![7; 32]];
        let server = Server::try_new("dual", config(method, &keys, "tcp,udp")).unwrap();
        let listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let (dispatcher, mut events) = echo();
        let running = run(listener, dispatcher);
        let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("out", Destination::from(running.address), config(method, &keys, "tcp")).unwrap());
        let context = SessionContext::new("tcp", Destination::from_domain_port("tcp.example", 80));
        assert!(matches!(client.connect_datagram(&context).await, Err(Error::Unsupported(_))));
        let mut stream = client.connect(&context).await.unwrap();
        stream.write_all(b"same port TCP").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 13];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"same port TCP");
        stream.shutdown().await.unwrap();
        for source in [Some("192.0.2.10:42000".parse().unwrap()), None] {
            let mut context = SessionContext::new("udp", target()); context.source = source;
            let packets = client.connect_datagram(&context).await.unwrap();
            packets.send(Datagram::new(Bytes::from_static(b"same port UDP"), target()).unwrap()).await.unwrap();
            let response = packets.recv().await.unwrap().unwrap();
            let (packet, _) = events.recv().await.unwrap();
            assert_eq!(response.destination, source.map(super::native::udp_destination).unwrap_or(packet.source.unwrap()));
            assert_eq!(response.source, Some(target()));
            packets.close().await.unwrap();
        }
        server.close().await.unwrap();
        drop(running);
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_native_outbound_close_also_closes_concrete_association_api() {
    tokio::time::timeout(WAIT, async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Client::try_new("out", Destination::from(peer.local_addr().unwrap()), config(CipherMethod::Aes128Gcm, &[vec![1; 16]], "tcp")).unwrap();
        let association = Arc::new(client.connect_datagram().await.unwrap());
        let address = association.local_addr().unwrap();
        let pending = { let association = association.clone(); tokio::spawn(async move { association.recv().await }) };
        client.close().await.unwrap();
        assert_eq!(pending.await.unwrap().unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert!(association.is_closed());
        assert!(association.send(target(), b"closed").await.is_err());
        association.close();
        let rebound = UdpSocket::bind(address).await.unwrap(); drop(rebound);
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_native_bind_atomicity_and_explicit_network_role_errors() {
    let method = CipherMethod::Aes128Gcm;
    let keys = vec![vec![1; 16]];
    let tcp_only = Server::try_new("tcp", config(method, &keys, "tcp")).unwrap();
    assert!(tcp_only.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().is_none());
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let dual = Server::try_new("dual", config(method, &keys, "tcp,udp")).unwrap();
    assert!(dual.bind_native(address).await.is_err());
    // UDP bind failed after TCP bind; rollback must have released TCP.
    let tcp = TcpListener::bind(address).await.unwrap(); drop(tcp); drop(occupied);
    let listener = dual.bind_native(address).await.unwrap().unwrap();
    dual.close().await.unwrap();
    // Retaining the listener object must not retain its bound sockets.
    let udp = UdpSocket::bind(address).await.unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    drop(listener); drop(udp); drop(tcp);
    assert!(matches!(dual.bind_native(address).await, Err(Error::Closed)));
    for network in ["", "tcp,", "udp,,tcp", "quic", " tcp", "udp ", "tcp, udp", " TCP , UDP "] {
        assert!(Server::try_new("bad", config(method, &keys, network)).is_err());
    }
    assert!(MultiUserServer::new("bad", CipherMethod::ChaCha20Poly1305, vec![1; 32]).is_err());
    assert!(RelayServer::new("bad", CipherMethod::ChaCha20Poly1305, vec![1; 32], Vec::new()).is_err());
    for network in [None, Some("udp"), Some("tcp,udp")] {
        let relay = RelayServer::new("relay", method, vec![1; 16], Vec::new()).unwrap().with_network(network).unwrap();
        let listener = relay.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().expect("relay must retain native UDP selection");
        let address = listener.local_addr().unwrap();
        assert!(UdpSocket::bind(address).await.is_err());
        let tcp = TcpListener::bind(address).await;
        assert_eq!(tcp.is_err(), network != Some("udp"));
        drop(tcp);
        relay.close().await.unwrap();
        // Close must release both sockets even while the listener is retained.
        drop((UdpSocket::bind(address).await.unwrap(), TcpListener::bind(address).await.unwrap()));
        assert!(matches!(relay.bind_native(address).await, Err(Error::Closed)));
        drop(listener);
    }
    let relay = RelayServer::new("relay", method, vec![1; 16], Vec::new()).unwrap().with_network(Some("tcp")).unwrap();
    assert!(relay.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().is_none());
}

#[tokio::test]
async fn ss2022_native_listener_drop_closes_tcp_child_in_unpolled_task() {
    tokio::time::timeout(WAIT, async {
        let server = Server::try_new("dual", config(CipherMethod::Aes128Gcm, &[vec![1; 16]], "tcp,udp")).unwrap();
        let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (dispatcher, _) = echo();
        let task = listener.accept(dispatcher).await.unwrap();
        drop(listener);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        drop(task);
    }).await.unwrap();
}

struct Capture { accepted: mpsc::UnboundedSender<BoxDatagram> }
#[async_trait]
impl InboundDispatcher for Capture {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("test streams".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, _session: SessionContext) -> Result<()> {
        self.accepted.send(packets).map_err(|_| Error::Closed)?;
        std::future::pending().await
    }
}

#[tokio::test]
async fn ss2022_native_replay_rebinding_task_drop_listener_drop_and_cancelled_accept() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes256Gcm;
        let keys = vec![vec![4; 32]];
        let server = Server::try_new("native", config(method, &keys, "udp")).unwrap();
        let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (accepted, mut captures) = mpsc::unbounded_channel();
        let dispatcher: Arc<dyn InboundDispatcher> = Arc::new(Capture { accepted });
        assert!(tokio::time::timeout(Duration::from_millis(10), listener.accept(dispatcher.clone())).await.is_err());
        let mut client = ClientUdpSession::with_session_id(method, keys, 123).unwrap();
        let first_wire = client.encode(target(), b"one").unwrap();
        first.send_to(&first_wire, address).await.unwrap();
        let task = listener.accept(dispatcher.clone()).await.unwrap();
        // Drop without polling the dispatch task, then send a fresh packet.
        drop(task);
        let second_wire = client.encode(target(), b"two").unwrap();
        first.send_to(&second_wire, address).await.unwrap();
        let task = tokio::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let packets = captures.recv().await.unwrap();
        let request = packets.recv().await.unwrap().unwrap();
        assert_eq!(request.payload.as_ref(), b"two");
        // Replay from another socket must neither dispatch nor redirect replies.
        second.send_to(&second_wire, address).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept(dispatcher.clone())).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(10), packets.recv()).await.is_err());
        assert!(packets.send(Datagram { payload: Bytes::new(), source: Some(target()), destination: udp("192.0.2.99:9999") }).await.is_err());
        assert!(packets.send(Datagram { payload: Bytes::new(), source: None, destination: request.source.clone().unwrap() }).await.is_err());
        assert!(packets.send(Datagram { payload: Bytes::new(), source: Some(Destination::from_domain_port("wrong-network", 80)), destination: request.source.clone().unwrap() }).await.is_err());
        assert!(packets.send(Datagram { payload: Bytes::from(vec![0; 8193]), source: Some(target()), destination: request.source.clone().unwrap() }).await.is_err());
        packets.send(Datagram { payload: Bytes::from_static(b"original peer"), source: Some(target()), destination: request.source.clone().unwrap() }).await.unwrap();
        let mut wire = vec![0; 8193];
        let (length, _) = first.recv_from(&mut wire).await.unwrap();
        assert_eq!(client.decode(&wire[..length]).unwrap().payload, b"original peer");
        assert!(tokio::time::timeout(Duration::from_millis(10), second.recv_from(&mut wire)).await.is_err());
        // Only an authenticated, fresh packet may migrate the session. The
        // current dispatcher/ReplyToken remains in use for the new socket.
        let migrated = client.encode(target(), b"migrate").unwrap();
        let mut invalid = migrated.clone(); *invalid.last_mut().unwrap() ^= 1;
        second.send_to(&invalid, address).await.unwrap();
        let mut oversized = migrated.clone(); oversized.resize(9000, 0);
        second.send_to(&oversized, address).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept(dispatcher.clone())).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(10), packets.recv()).await.is_err());
        second.send_to(&migrated, address).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept(dispatcher.clone())).await.is_err());
        let migrated = packets.recv().await.unwrap().unwrap();
        assert_eq!(migrated.source.as_ref().unwrap().to_socket_addr(), Some(second.local_addr().unwrap()));
        packets.send(Datagram { payload: Bytes::new(), source: Some(target()), destination: request.source.unwrap() }).await.unwrap();
        let (length, _) = second.recv_from(&mut wire).await.unwrap();
        assert!(client.decode(&wire[..length]).unwrap().payload.is_empty());
        assert!(captures.try_recv().is_err());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(packets.recv().await.unwrap().is_none());
        first.send_to(&client.encode(target(), b"after abort").unwrap(), address).await.unwrap();
        let task = tokio::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let packets = captures.recv().await.unwrap();
        assert_eq!(packets.recv().await.unwrap().unwrap().payload.as_ref(), b"after abort");
        let pending = { let packets = packets.clone(); tokio::spawn(async move { packets.recv().await }) };
        drop(listener);
        assert!(pending.await.unwrap().unwrap().is_none());
        task.await.unwrap().unwrap();
        assert!(matches!(packets.send(Datagram::new(Bytes::new(), target()).unwrap()).await, Err(Error::Closed)));
        // A retained packet transport must not keep the listener's UDP socket.
        let rebound = UdpSocket::bind(address).await.unwrap(); drop(rebound);
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_native_udp_bounded_queue_does_not_stall_other_sessions() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes128Gcm;
        let master = vec![1; 16]; let key = vec![2; 16];
        let server = MultiUserServer::new("multi", method, master.clone()).unwrap().with_network(Some("udp")).unwrap();
        let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        // The listener clone must retain the live account indices, not a
        // snapshot taken at bind time.
        server.add_account(UserAccount { key: key.clone(), user: user() }).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (accepted, mut captures) = mpsc::unbounded_channel();
        let dispatcher: Arc<dyn InboundDispatcher> = Arc::new(Capture { accepted });
        let keys = vec![master, key];
        let mut slow = ClientUdpSession::with_session_id(method, keys.clone(), 300).unwrap();
        socket.send_to(&slow.encode(target(), b"first").unwrap(), address).await.unwrap();
        let first_task = tokio::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let first = captures.recv().await.unwrap();
        assert_eq!(first.recv().await.unwrap().unwrap().payload.as_ref(), b"first");
        for sequence in 0..35u8 {
            socket.send_to(&slow.encode(target(), &[sequence]).unwrap(), address).await.unwrap();
            assert!(tokio::time::timeout(Duration::from_millis(2), listener.accept(dispatcher.clone())).await.is_err());
        }
        let mut fast = ClientUdpSession::with_session_id(method, keys, 301).unwrap();
        socket.send_to(&fast.encode(target(), b"independent").unwrap(), address).await.unwrap();
        let second_task = tokio::spawn(listener.accept(dispatcher).await.unwrap());
        let second = captures.recv().await.unwrap();
        assert_eq!(second.recv().await.unwrap().unwrap().payload.as_ref(), b"independent");
        for sequence in 0..32u8 { assert_eq!(first.recv().await.unwrap().unwrap().payload.as_ref(), &[sequence]); }
        assert!(tokio::time::timeout(Duration::from_millis(10), first.recv()).await.is_err());
        // Closing one flow wakes it without closing another peer or the socket.
        first.close().await.unwrap();
        first_task.await.unwrap().unwrap();
        second.send(Datagram { payload: Bytes::new(), source: Some(target()), destination: super::native::udp_destination(socket.local_addr().unwrap()) }).await.unwrap();
        let mut wire = vec![0; 8193];
        let (length, _) = socket.recv_from(&mut wire).await.unwrap();
        assert!(fast.decode(&wire[..length]).unwrap().payload.is_empty());
        drop(listener);
        second_task.await.unwrap().unwrap();
    }).await.unwrap();
}

#[derive(Deserialize)]
struct Frozen { method: String, keys: Vec<String>, timestamp: u64, destination: String, udp_request: String, udp_request_payload: String }
#[test]
fn ss2022_native_handler_entry_points_accept_independent_frozen_go_packets() {
    let fixture = include_bytes!("testdata/go-extended-vectors.jsonl");
    assert_eq!(hex::encode(sha2::Sha256::digest(fixture)), "349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0");
    let remote = "127.0.0.1:43000".parse().unwrap();
    for line in std::str::from_utf8(fixture).unwrap().lines() {
        let frozen: Frozen = serde_json::from_str(line).unwrap();
        let method = CipherMethod::parse(&frozen.method).unwrap();
        let keys: Vec<Vec<u8>> = frozen.keys.iter().map(|key| hex::decode(key).unwrap()).collect();
        let wire = hex::decode(frozen.udp_request).unwrap();
        // Fixed-time entry points are the same handler decoders used by the
        // live boundary, with the fixture's recorded Go timestamp supplied.
        let incoming = if method.is_chacha() {
            let server = Server::try_new("fixture", config(method, &keys, "udp")).unwrap();
            let incoming = server.decode_datagram_at(&wire, remote, frozen.timestamp).unwrap();
            assert!(server.decode_datagram_at(&wire, "127.0.0.1:43001".parse().unwrap(), frozen.timestamp).is_err());
            incoming
        } else {
            let relay = RelayServer::new("fixture-relay", method, keys[0].clone(), vec![RelayTarget { key: keys[1].clone(), destination: Destination::from_domain_port("next.example", 8388), user: user() }]).unwrap();
            let forwarded = relay.relay_datagram(&wire).unwrap();
            let server = MultiUserServer::new("fixture-multi", method, keys[1].clone()).unwrap().with_network(Some("udp")).unwrap();
            server.add_account(UserAccount { key: keys[2].clone(), user: user() }).unwrap();
            let incoming = server.decode_datagram_at(&forwarded.wire, remote, frozen.timestamp).unwrap();
            assert_eq!(incoming.user.as_ref().unwrap().email, "native@example");
            assert!(server.decode_datagram_at(&forwarded.wire, remote, frozen.timestamp).is_err());
            incoming
        };
        assert_eq!(incoming.remote, remote);
        assert_eq!(incoming.packet.destination, udp(&frozen.destination));
        assert_eq!(incoming.packet.payload, hex::decode(frozen.udp_request_payload).unwrap());
    }
}
