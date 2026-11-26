//! Native relay lifecycle evidence; Linux execution and live Go relay parity
//! are separate gates. Independent bytes come only from the frozen Go JSONL.
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use sha2::Digest;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::mpsc, task::{JoinHandle, JoinSet}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram}}, protocol::{SessionContext, User}}, features::{inbound::{InboundDispatcher, InboundHandler, InboundTask, NativeInboundListener}, outbound::OutboundHandler}};
use super::{Client, Server, Shadowsocks2022Config, cipher::CipherMethod, multi_server::{MultiUserServer, UserAccount}, native::RelayLimits, relay_server::{RelayServer, RelayTarget}, udp_session::ClientUdpSession};

const WAIT: Duration = Duration::from_secs(10);
const AES: [CipherMethod; 2] = [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm];
const RELAY_EMAIL: &str = "relay-target@example.invalid";
const FINAL_EMAIL: &str = "final-user@example.invalid";
fn udp(address: &str) -> Destination { Destination::parse_str(address, Network::Udp).unwrap() }
fn source(address: SocketAddr) -> Destination { Destination::udp(address.ip().into(), address.port()) }
fn user(email: &str) -> User { User::with_email(uuid::Uuid::nil(), email, 9) }
fn method_name(method: CipherMethod) -> &'static str {
    match method {
        CipherMethod::Aes128Gcm => "2022-blake3-aes-128-gcm",
        CipherMethod::Aes256Gcm => "2022-blake3-aes-256-gcm",
        CipherMethod::ChaCha20Poly1305 => panic!("relay is AES only"),
    }
}
fn config(method: CipherMethod, keys: &[Vec<u8>]) -> Shadowsocks2022Config {
    Shadowsocks2022Config { method: method_name(method).into(), key: keys.iter().map(|key| base64::engine::general_purpose::STANDARD.encode(key)).collect::<Vec<_>>().join(":"), network: Some("udp".into()) }
}
fn relay(method: CipherMethod, keys: &[Vec<u8>], target: Destination, network: Option<&str>) -> RelayServer {
    RelayServer::new("relay-native", method, keys[0].clone(), vec![RelayTarget { key: keys[1].clone(), destination: target, user: user(RELAY_EMAIL) }]).unwrap().with_network(network).unwrap()
}
fn local() -> SocketAddr { "127.0.0.1:0".parse().unwrap() }
fn target() -> Destination { Destination::from_domain_port("next.example.invalid", 8388) }
fn destination() -> Destination { udp("final.example.invalid:443") }
fn keys(method: CipherMethod) -> Vec<Vec<u8>> { vec![vec![1; method.key_length()], vec![2; method.key_length()], vec![3; method.key_length()]] }

struct Flow { packets: BoxDatagram, session: SessionContext }
struct Capture { started: mpsc::UnboundedSender<Flow>, next: Option<Arc<dyn InboundDispatcher>> }
#[async_trait]
impl InboundDispatcher for Capture {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("test captures UDP routes".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        self.started.send(Flow { packets: packets.clone(), session: session.clone() }).map_err(|_| Error::Closed)?;
        match &self.next {
            Some(next) => next.dispatch_datagrams(packets, session).await,
            None => std::future::pending().await,
        }
    }
}
fn capture(next: Option<Arc<dyn InboundDispatcher>>) -> (Arc<dyn InboundDispatcher>, mpsc::UnboundedReceiver<Flow>) {
    let (started, receiver) = mpsc::unbounded_channel();
    (Arc::new(Capture { started, next }), receiver)
}

// Retain abort ownership while awaiting, including when the test times out.
struct Task(Option<JoinHandle<Result<()>>>);
impl Drop for Task { fn drop(&mut self) { if let Some(task) = &self.0 { task.abort(); } } }
impl Task {
    fn spawn(task: InboundTask) -> Self { Self(Some(tokio::spawn(task))) }
    async fn finish(mut self) {
        self.0.as_mut().unwrap().await.unwrap().unwrap();
        let _ = self.0.take();
    }
}
fn run(mut listener: Box<dyn NativeInboundListener>, dispatcher: Arc<dyn InboundDispatcher>) -> Task {
    Task::spawn(Box::pin(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept(dispatcher.clone()) => match accepted {
                    Ok(task) => { children.spawn(task); }
                    Err(Error::Closed) => break,
                    Err(error) => return Err(error),
                },
                completed = children.join_next(), if !children.is_empty() => { completed.unwrap().unwrap()?; }
            }
        }
        while let Some(completed) = children.join_next().await { completed.unwrap()?; }
        Ok(())
    }))
}
async fn next_packet(listener: &mut Box<dyn NativeInboundListener>, dispatcher: &Arc<dyn InboundDispatcher>, flow: &Flow) -> Datagram {
    tokio::select! {
        _ = listener.accept(dispatcher.clone()) => panic!("an existing relay association must reuse its cached dispatch task"),
        packet = flow.packets.recv() => packet.unwrap().expect("relay route unexpectedly closed"),
    }
}
async fn pump(listener: &mut Box<dyn NativeInboundListener>, dispatcher: &Arc<dyn InboundDispatcher>) {
    assert!(tokio::time::timeout(Duration::from_millis(10), listener.accept(dispatcher.clone())).await.is_err());
}
fn packet_id(method: CipherMethod, key: &[u8], packet: &Datagram) -> u64 {
    let header = super::packet::decrypt_header(method, key, &packet.payload[..16]).unwrap();
    u64::from_be_bytes(header[8..].try_into().unwrap())
}
async fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut wire = vec![0; super::packet::MAX_DATAGRAM_SIZE + 1];
    let (size, remote) = socket.recv_from(&mut wire).await.unwrap();
    wire.truncate(size);
    (wire, remote)
}
fn response(flow: &Flow, bytes: impl Into<Bytes>) -> Datagram {
    Datagram { payload: bytes.into(), source: Some(flow.session.destination.clone()), destination: source(flow.session.source.unwrap()) }
}

#[derive(Deserialize)]
struct Frozen {
    method: String, keys: Vec<String>, timestamp: u64, client_session_id: u64, destination: String,
    request: String, udp_request: String, udp_response: String, udp_request_payload: String, udp_response_payload: String,
}
fn fixtures() -> Vec<Frozen> {
    let file = include_bytes!("testdata/go-extended-vectors.jsonl");
    assert_eq!(hex::encode(sha2::Sha256::digest(file)), "349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0");
    std::str::from_utf8(file).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

#[tokio::test]
async fn ss2022_relay_native_frozen_go_bytes_eih_cache_and_reply_passthrough() {
    tokio::time::timeout(WAIT, async {
        let mut checked = 0;
        for frozen in fixtures() {
            let method = CipherMethod::parse(&frozen.method).unwrap();
            if method.is_chacha() { continue; }
            let keys: Vec<Vec<u8>> = frozen.keys.iter().map(|key| hex::decode(key).unwrap()).collect();
            let inbound: Arc<dyn InboundHandler> = Arc::new(relay(method, &keys, target(), Some("udp")));
            let mut listener = inbound.bind_native(local()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let a = UdpSocket::bind(local()).await.unwrap();
            let b = UdpSocket::bind(local()).await.unwrap();
            let (dispatcher, mut captures) = capture(None);
            let wire = hex::decode(&frozen.udp_request).unwrap();
            a.send_to(&wire, address).await.unwrap();
            let task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
            let flow = captures.recv().await.unwrap();
            assert_eq!(flow.session.source, Some(a.local_addr().unwrap()));
            assert_eq!(flow.session.inbound_tag, "relay-native");
            assert_eq!(flow.session.destination, udp(&target().to_string()));
            assert_eq!(flow.session.user.as_ref().unwrap().email, RELAY_EMAIL);
            assert_eq!(flow.session.user.as_ref().unwrap().level, 9);
            let forwarded = flow.packets.recv().await.unwrap().unwrap();
            assert_eq!(forwarded.source, Some(source(a.local_addr().unwrap())));
            assert_eq!(forwarded.destination, flow.session.destination);
            assert_eq!(forwarded.payload.len() + 16, wire.len());
            // These expected bytes are the committed independent Go input:
            // all lower EIHs and the sealed body survive byte-for-byte.
            assert_eq!(&forwarded.payload[16..], &wire[32..]);
            let header = super::packet::decrypt_header(method, &keys[1], &forwarded.payload[..16]).unwrap();
            assert_eq!(&header[..8], &frozen.client_session_id.to_be_bytes());
            assert_eq!(&header[8..], &0u64.to_be_bytes());
            let downstream = MultiUserServer::new("final", method, keys[1].clone()).unwrap();
            downstream.add_account(UserAccount { key: keys[2].clone(), user: user(FINAL_EMAIL) }).unwrap();
            let incoming = downstream.decode_datagram_at(&forwarded.payload, address, frozen.timestamp).unwrap();
            assert_eq!(incoming.packet.payload, hex::decode(&frozen.udp_request_payload).unwrap());
            assert_eq!(incoming.packet.destination, udp(&frozen.destination));
            assert_eq!(incoming.user.unwrap().email, FINAL_EMAIL);
            // Peel the remaining EIH through a second native relay. Capture
            // supplies an explicit packet bridge here; the next test exercises
            // the production dispatcher/direct outbound path end-to-end.
            let next_relay = relay(method, &keys[1..], target(), Some("udp"));
            let mut next_listener = next_relay.bind_native(local()).await.unwrap().unwrap();
            let next_address = next_listener.local_addr().unwrap();
            let bridge = UdpSocket::bind(local()).await.unwrap();
            let (next_dispatcher, mut next_captures) = capture(None);
            bridge.send_to(&forwarded.payload, next_address).await.unwrap();
            let next_task = Task::spawn(next_listener.accept(next_dispatcher).await.unwrap());
            let next_flow = next_captures.recv().await.unwrap();
            let final_packet = next_flow.packets.recv().await.unwrap().unwrap();
            assert_eq!(final_packet.payload.len() + 32, wire.len());
            assert_eq!(&final_packet.payload[16..], &wire[48..]);
            let final_server = Server::try_new("final-single", config(method, &keys[2..])).unwrap();
            let final_incoming = final_server.decode_datagram_at(&final_packet.payload, next_address, frozen.timestamp).unwrap();
            assert_eq!(final_incoming.packet.payload, hex::decode(&frozen.udp_request_payload).unwrap());
            assert_eq!(final_incoming.packet.destination, udp(&frozen.destination));
            // Go does not apply endpoint replay/timestamp checks at a relay.
            // The exact same old Go packet rebinds without another dispatch.
            b.send_to(&wire, address).await.unwrap();
            assert_eq!(next_packet(&mut listener, &dispatcher, &flow).await, forwarded);
            assert!(captures.try_recv().is_err());
            let reply = hex::decode(&frozen.udp_response).unwrap();
            next_flow.packets.send(response(&next_flow, reply.clone())).await.unwrap();
            let (bridged_reply, remote) = receive(&bridge).await;
            assert_eq!(remote, next_address);
            assert_eq!(bridged_reply, reply);
            flow.packets.send(response(&flow, bridged_reply)).await.unwrap();
            let (received, remote) = receive(&b).await;
            assert_eq!(remote, address);
            assert_eq!(received, reply);
            let mut client = ClientUdpSession::with_session_id(method, keys, frozen.client_session_id).unwrap();
            let decoded = client.decode_at(&received, frozen.timestamp).unwrap();
            assert_eq!(decoded.payload, hex::decode(frozen.udp_response_payload).unwrap());
            assert_eq!(decoded.destination, udp(&frozen.destination));
            assert!(tokio::time::timeout(Duration::from_millis(10), receive(&a)).await.is_err());
            inbound.close().await.unwrap();
            task.finish().await;
            next_relay.close().await.unwrap();
            next_task.finish().await;
            assert!(flow.packets.recv().await.unwrap().is_none());
            assert!(matches!(flow.packets.send(response(&flow, Bytes::new())).await, Err(Error::Closed)));
            let rebound = UdpSocket::bind(address).await.unwrap();
            drop(rebound); drop(listener); drop(flow);
            checked += 1;
        }
        assert_eq!(checked, 2);
    }).await.unwrap();
}

struct Direct { calls: Arc<AtomicUsize>, inner: crate::proxy::freedom::Handler }
#[async_trait]
impl OutboundHandler for Direct {
    fn tag(&self) -> &str { "direct" }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> { self.inner.connect(session).await }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.connect_datagram(session).await
    }
}
struct Echo { seen: mpsc::UnboundedSender<(Datagram, SessionContext)> }
fn reply_payload(bytes: &[u8]) -> Vec<u8> { bytes.iter().enumerate().map(|(i, byte)| byte.wrapping_add((i as u8).wrapping_mul(17)) ^ 0xa5).collect() }
fn reply_source() -> Destination { udp("reply.example.invalid:9443") }
#[async_trait]
impl InboundDispatcher for Echo {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("UDP echo".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        while let Some(packet) = packets.recv().await? {
            self.seen.send((packet.clone(), session.clone())).map_err(|_| Error::Closed)?;
            packets.send(Datagram { payload: reply_payload(&packet.payload).into(), source: Some(reply_source()), destination: packet.source.ok_or(Error::Closed)? }).await?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn ss2022_relay_native_real_traits_direct_routes_single_multi_and_rebind() {
    tokio::time::timeout(WAIT, async {
        for method in AES {
            for multi in [false, true] {
                let mut keys = keys(method);
                if !multi { keys.pop(); }
                let downstream: Arc<dyn InboundHandler> = if multi {
                    let server = MultiUserServer::new("final", method, keys[1].clone()).unwrap().with_network(Some("udp")).unwrap();
                    server.add_account(UserAccount { key: keys[2].clone(), user: user(FINAL_EMAIL) }).unwrap();
                    Arc::new(server)
                } else { Arc::new(Server::try_new("final", config(method, &keys[1..])).unwrap().with_user(user(FINAL_EMAIL))) };
                let next = downstream.bind_native(local()).await.unwrap().unwrap();
                let next_address = next.local_addr().unwrap();
                let (seen, mut observed) = mpsc::unbounded_channel();
                let next_task = run(next, Arc::new(Echo { seen }));
                let relay: Arc<dyn InboundHandler> = Arc::new(relay(method, &keys, Destination::from(next_address), Some("udp")));
                let listener = relay.bind_native(local()).await.unwrap().unwrap();
                let address = listener.local_addr().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let mut outbounds: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
                outbounds.insert("direct".into(), Arc::new(Direct { calls: calls.clone(), inner: crate::proxy::freedom::Handler::new("direct") }));
                let routing = crate::app::dispatcher::default::DefaultDispatcher::new(outbounds, Arc::new(crate::features::routing::DefaultRouter)).with_default_outbound("direct");
                let (dispatcher, mut captures) = capture(Some(Arc::new(routing)));
                let relay_task = run(listener, dispatcher);
                let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("client", Destination::from(address), config(method, &keys)).unwrap());
                let context = SessionContext::new("local", destination());
                let packets = client.connect_datagram(&context).await.unwrap();
                for (destination, payload) in [(destination(), Vec::new()), (udp("[2001:db8::7]:5353"), vec![0x53; 7900]), (udp("198.51.100.7:9001"), vec![0, 255, 0, 128, 9])] {
                    packets.send(Datagram::new(payload.clone(), destination.clone()).unwrap()).await.unwrap();
                    let reply = packets.recv().await.unwrap().unwrap();
                    assert_eq!(reply.payload.as_ref(), reply_payload(&payload).as_slice());
                    assert_eq!(reply.source, Some(reply_source()));
                    let (seen, session) = observed.recv().await.unwrap();
                    assert_eq!(seen.payload.as_ref(), payload.as_slice());
                    assert_eq!(seen.destination, destination);
                    assert_eq!(seen.source.as_ref().unwrap().to_socket_addr(), session.source);
                    assert_eq!(session.inbound_tag, "final");
                    assert_eq!(session.user.unwrap().email, FINAL_EMAIL);
                }
                let routed = captures.recv().await.unwrap();
                assert_eq!(routed.session.user.as_ref().unwrap().email, RELAY_EMAIL);
                assert_eq!(routed.session.destination, source(next_address));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                // A second association physically rebinds. DefaultDispatcher
                // must keep exactly one direct socket/route for its session.
                let mut raw = ClientUdpSession::with_session_id(method, keys, 7000).unwrap();
                let a = UdpSocket::bind(local()).await.unwrap();
                let b = UdpSocket::bind(local()).await.unwrap();
                let mut next_peer = None;
                for (index, socket) in [&a, &b].into_iter().enumerate() {
                    let payload = [index as u8, 0, 255];
                    socket.send_to(&raw.encode(destination(), &payload).unwrap(), address).await.unwrap();
                    let (wire, remote) = receive(socket).await;
                    assert_eq!(remote, address);
                    let reply = raw.decode(&wire).unwrap();
                    assert_eq!(reply.payload, reply_payload(&payload));
                    assert_eq!(reply.destination, reply_source());
                    let (seen, session) = observed.recv().await.unwrap();
                    assert_eq!(seen.payload.as_ref(), &payload);
                    if let Some(peer) = next_peer { assert_eq!(session.source, Some(peer)); } else { next_peer = session.source; }
                    assert_eq!(calls.load(Ordering::SeqCst), 2);
                }
                let rebound_flow = captures.recv().await.unwrap();
                assert_eq!(rebound_flow.session.source, Some(a.local_addr().unwrap()));
                assert!(captures.try_recv().is_err());
                assert!(tokio::time::timeout(Duration::from_millis(10), receive(&a)).await.is_err());
                client.close().await.unwrap();
                assert!(packets.recv().await.unwrap().is_none());
                relay.close().await.unwrap();
                relay_task.finish().await;
                for flow in [&routed, &rebound_flow] { assert!(flow.packets.recv().await.unwrap().is_none()); }
                downstream.close().await.unwrap();
                next_task.finish().await;
                let rebound = UdpSocket::bind(address).await.unwrap();
                drop(rebound);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_relay_native_bounds_queue_peers_and_independent_sessions() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes128Gcm;
        let keys = keys(method);
        let relay = relay(method, &keys, target(), Some("udp"));
        let limits = RelayLimits { flows: 2, queue: 2, peers: 2, ..RelayLimits::default() };
        let mut listener = relay.bind_with_limits(local(), limits).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let a = UdpSocket::bind(local()).await.unwrap();
        let b = UdpSocket::bind(local()).await.unwrap();
        let c = UdpSocket::bind(local()).await.unwrap();
        let (dispatcher, mut captures) = capture(None);
        let mut slow = ClientUdpSession::with_session_id(method, keys.clone(), 1).unwrap();
        a.send_to(&slow.encode(destination(), &[0]).unwrap(), address).await.unwrap();
        let slow_task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let first = captures.recv().await.unwrap();
        for sequence in 1..5 {
            a.send_to(&slow.encode(destination(), &[sequence]).unwrap(), address).await.unwrap();
            pump(&mut listener, &dispatcher).await;
        }
        // A full association cannot block another session. Queue overflow
        // drops whole packets and preserves the first two boundaries/order.
        let mut fast = ClientUdpSession::with_session_id(method, keys.clone(), 2).unwrap();
        a.send_to(&fast.encode(destination(), b"independent").unwrap(), address).await.unwrap();
        let fast_task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let second = captures.recv().await.unwrap();
        assert_eq!(packet_id(method, &keys[1], &second.packets.recv().await.unwrap().unwrap()), 0);
        for expected in 0..2 {
            assert_eq!(packet_id(method, &keys[1], &first.packets.recv().await.unwrap().unwrap()), expected);
        }
        assert!(tokio::time::timeout(Duration::from_millis(10), first.packets.recv()).await.is_err());
        let mut excess = ClientUdpSession::with_session_id(method, keys.clone(), 3).unwrap();
        a.send_to(&excess.encode(destination(), b"capacity").unwrap(), address).await.unwrap();
        pump(&mut listener, &dispatcher).await;
        assert!(captures.try_recv().is_err());
        b.send_to(&slow.encode(destination(), b"rebind").unwrap(), address).await.unwrap();
        let rebound = next_packet(&mut listener, &dispatcher, &first).await;
        assert_eq!(rebound.source, Some(source(a.local_addr().unwrap())));
        assert_eq!(packet_id(method, &keys[1], &rebound), 5);
        c.send_to(&slow.encode(destination(), b"peer-cap").unwrap(), address).await.unwrap();
        pump(&mut listener, &dispatcher).await;
        assert!(tokio::time::timeout(Duration::from_millis(10), first.packets.recv()).await.is_err());
        first.packets.send(response(&first, Bytes::from_static(b"latest-peer"))).await.unwrap();
        assert_eq!(receive(&b).await.0, b"latest-peer");
        assert!(tokio::time::timeout(Duration::from_millis(10), receive(&c)).await.is_err());
        // Reply address validation is per association, with unchanged bounds
        // even if a custom dispatcher keeps the transport indefinitely.
        let mut wrong = response(&first, Bytes::new());
        wrong.destination = source(c.local_addr().unwrap());
        assert!(matches!(first.packets.send(wrong).await, Err(Error::Protocol(_))));
        let mut wrong = response(&first, Bytes::new());
        wrong.source = Some(target());
        assert!(matches!(first.packets.send(wrong).await, Err(Error::Protocol(_))));
        assert!(matches!(first.packets.send(response(&first, vec![0; super::packet::MAX_DATAGRAM_SIZE + 1])).await, Err(Error::BufferOverflow)));
        first.packets.send(response(&first, vec![7; super::packet::MAX_DATAGRAM_SIZE])).await.unwrap();
        assert_eq!(receive(&b).await.0, vec![7; super::packet::MAX_DATAGRAM_SIZE]);
        // Cancelling a pending recv must not consume the next complete packet.
        assert!(tokio::time::timeout(Duration::from_millis(10), first.packets.recv()).await.is_err());
        a.send_to(&slow.encode(destination(), b"after-cancel").unwrap(), address).await.unwrap();
        assert_eq!(packet_id(method, &keys[1], &next_packet(&mut listener, &dispatcher, &first).await), 7);
        first.packets.close().await.unwrap();
        slow_task.finish().await;
        assert!(first.packets.recv().await.unwrap().is_none());
        a.send_to(&excess.encode(destination(), b"released-slot").unwrap(), address).await.unwrap();
        let third_task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let third = captures.recv().await.unwrap();
        assert_eq!(packet_id(method, &keys[1], &third.packets.recv().await.unwrap().unwrap()), 1);
        // Other associations still send empty packets as actual UDP records.
        second.packets.send(response(&second, Bytes::new())).await.unwrap();
        assert!(receive(&a).await.0.is_empty());
        relay.close().await.unwrap();
        fast_task.finish().await;
        third_task.finish().await;
        assert!(second.packets.recv().await.unwrap().is_none());
        assert!(third.packets.recv().await.unwrap().is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_relay_native_expiry_reply_activity_and_retained_transports() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes256Gcm;
        let keys = keys(method);
        let relay = relay(method, &keys, target(), Some("udp"));
        let limits = RelayLimits { flows: 1, idle: Duration::from_millis(300), sweep: Duration::from_millis(10), ..RelayLimits::default() };
        let listener = relay.bind_with_limits(local(), limits).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let a = UdpSocket::bind(local()).await.unwrap();
        let (dispatcher, mut captures) = capture(None);
        let runner = run(listener, dispatcher);
        let mut client = ClientUdpSession::with_session_id(method, keys, 99).unwrap();
        a.send_to(&client.encode(destination(), b"start").unwrap(), address).await.unwrap();
        let first = captures.recv().await.unwrap();
        first.packets.recv().await.unwrap().unwrap();
        // Stay alive beyond the request-only deadline using downlink activity.
        let started = tokio::time::Instant::now();
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            first.packets.send(response(&first, Bytes::from_static(b"activity"))).await.unwrap();
            assert_eq!(receive(&a).await.0, b"activity");
        }
        assert!(started.elapsed() > limits.idle);
        // With no further traffic, the sweep closes even retained transports
        // and the captured dispatch future, freeing the single route slot.
        assert!(first.packets.recv().await.unwrap().is_none());
        assert!(matches!(first.packets.send(response(&first, Bytes::new())).await, Err(Error::Closed)));
        a.send_to(&client.encode(destination(), b"after-expiry").unwrap(), address).await.unwrap();
        let second = captures.recv().await.unwrap();
        assert!(second.packets.recv().await.unwrap().is_some());
        relay.close().await.unwrap();
        runner.finish().await;
        assert!(second.packets.recv().await.unwrap().is_none());
        let rebound = UdpSocket::bind(address).await.unwrap();
        drop(rebound);
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_relay_native_unpolled_dropped_aborted_and_closed_tasks() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes128Gcm;
        let keys = keys(method);
        let relay = relay(method, &keys, target(), Some("udp"));
        let mut listener = relay.bind_with_limits(local(), RelayLimits { flows: 1, ..RelayLimits::default() }).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let a = UdpSocket::bind(local()).await.unwrap();
        let (dispatcher, mut captures) = capture(None);
        let mut client = ClientUdpSession::with_session_id(method, keys, 123).unwrap();
        let wire = client.encode(destination(), b"retry").unwrap();
        // Dropping an unpolled task must cancel before its first poll. The
        // listener can immediately recreate the same session and route slot.
        a.send_to(&wire, address).await.unwrap();
        drop(listener.accept(dispatcher.clone()).await.unwrap());
        assert!(captures.try_recv().is_err());
        a.send_to(&wire, address).await.unwrap();
        let mut task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let first = captures.recv().await.unwrap();
        first.packets.recv().await.unwrap().unwrap();
        let handle = task.0.take().unwrap();
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
        assert!(first.packets.recv().await.unwrap().is_none());
        assert!(matches!(first.packets.send(response(&first, Bytes::new())).await, Err(Error::Closed)));
        a.send_to(&wire, address).await.unwrap();
        let running = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
        let second = captures.recv().await.unwrap();
        second.packets.recv().await.unwrap().unwrap();
        second.packets.close().await.unwrap();
        running.finish().await;
        a.send_to(&wire, address).await.unwrap();
        let unpolled = listener.accept(dispatcher.clone()).await.unwrap();
        // Close releases its socket while listener and task remain retained.
        relay.close().await.unwrap();
        relay.close().await.unwrap();
        let rebound = UdpSocket::bind(address).await.unwrap();
        assert!(matches!(listener.accept(dispatcher).await, Err(Error::Closed)));
        assert!(matches!(relay.bind_native(local()).await, Err(Error::Closed)));
        unpolled.await.unwrap();
        drop(rebound);
        let relay = super::relay_server::RelayServer::new("drop", method, vec![1; 16], Vec::new()).unwrap().with_network(Some("udp")).unwrap();
        let listener = relay.bind_native(local()).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let rebound = UdpSocket::bind(address).await.unwrap();
        drop(rebound);
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_relay_native_network_roles_bind_rollback_and_tcp_children() {
    tokio::time::timeout(WAIT, async {
        for frozen in fixtures() {
            let method = CipherMethod::parse(&frozen.method).unwrap();
            if method.is_chacha() { continue; }
            let keys: Vec<Vec<u8>> = frozen.keys.iter().map(|key| hex::decode(key).unwrap()).collect();
            let base = relay(method, &keys, target(), Some("tcp"));
            assert!(base.bind_native(local()).await.unwrap().is_none());
            for invalid in ["", "tcp,", "udp,,tcp", "quic", " tcp", "udp ", "tcp, udp", "unix"] {
                assert!(matches!(base.clone().with_network(Some(invalid)), Err(Error::Config(_))));
            }
            let udp_only = relay(method, &keys, target(), Some("UDP,udp"));
            let listener = udp_only.bind_native(local()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let probe = TcpListener::bind(address).await.unwrap();
            drop(probe); drop(listener);
            let (_, stream) = tokio::io::duplex(64);
            assert!(matches!(udp_only.handle_connection(Box::pin(stream), local()).await, Err(Error::Unsupported(_))));
            // None and mixed/case/duplicate accepted tokens retain both
            // sockets on one port. UDP failure must roll back the TCP bind.
            for network in [None, Some("UDP,TCP,udp"), Some("tcp,udp")] {
                let dual: Arc<dyn InboundHandler> = Arc::new(relay(method, &keys, target(), network));
                let occupied = UdpSocket::bind(local()).await.unwrap();
                let address = occupied.local_addr().unwrap();
                assert!(dual.bind_native(address).await.is_err());
                let probe = TcpListener::bind(address).await.unwrap();
                drop(probe); drop(occupied);
                let mut listener = dual.bind_native(address).await.unwrap().unwrap();
                assert_eq!(listener.local_addr().unwrap(), address);
                let (dispatcher, _captures) = capture(None);
                // Unpolled accepted TCP children close when the listener drops.
                let mut peer = TcpStream::connect(address).await.unwrap();
                let child = listener.accept(dispatcher.clone()).await.unwrap();
                drop(listener);
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                child.await.unwrap();
                let mut listener = dual.bind_native(address).await.unwrap().unwrap();
                let mut peer = TcpStream::connect(address).await.unwrap();
                let child = listener.accept(dispatcher).await.unwrap();
                dual.close().await.unwrap();
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                // Retained listener and unpolled task cannot retain either bind.
                let udp_probe = UdpSocket::bind(address).await.unwrap();
                let tcp_probe = TcpListener::bind(address).await.unwrap();
                child.await.unwrap();
                drop(udp_probe); drop(tcp_probe); drop(listener);
            }
            // The original TCP relay path must still forward the independent
            // Go handshake with exactly one EIH removed and no other edits.
            let (mut peer, stream) = tokio::io::duplex(2048);
            let wire = hex::decode(&frozen.request).unwrap();
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
            let remote = "127.0.0.1:43210".parse().unwrap();
            let mut incoming = base.handle_connection(Box::pin(stream), remote).await.unwrap();
            assert_eq!(incoming.session.source, Some(remote));
            assert_eq!(incoming.session.destination, target());
            assert_eq!(incoming.session.user.unwrap().email, RELAY_EMAIL);
            let mut actual = Vec::new();
            incoming.stream.read_to_end(&mut actual).await.unwrap();
            let salt_length = method.key_length();
            assert_eq!(&actual[..salt_length], &wire[..salt_length]);
            assert_eq!(&actual[salt_length..], &wire[salt_length + 16..]);
        }
        assert!(RelayServer::new("bad", CipherMethod::ChaCha20Poly1305, vec![1; 32], Vec::new()).is_err());
        assert!(RelayServer::new("bad", CipherMethod::Aes128Gcm, vec![1; 15], Vec::new()).is_err());
        for destination in [udp("next.example:8388"), Destination::from_domain_port("next.example", 0)] {
            assert!(RelayServer::new("bad", CipherMethod::Aes128Gcm, vec![1; 16], vec![RelayTarget { key: vec![2; 16], destination, user: user(RELAY_EMAIL) }]).is_err());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_relay_native_invalid_headers_and_cached_identity_destination() {
    tokio::time::timeout(WAIT, async {
        for method in AES {
            let keys = keys(method);
            let other_key = vec![4; method.key_length()];
            let relay = RelayServer::new("relay-native", method, keys[0].clone(), vec![
                RelayTarget { key: keys[1].clone(), destination: target(), user: user(RELAY_EMAIL) },
                RelayTarget { key: other_key.clone(), destination: Destination::from_domain_port("other.example", 8488), user: user("other@example.invalid") },
            ]).unwrap().with_network(Some("udp")).unwrap();
            let mut listener = relay.bind_native(local()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let a = UdpSocket::bind(local()).await.unwrap();
            let b = UdpSocket::bind(local()).await.unwrap();
            let (dispatcher, mut captures) = capture(None);
            let mut client = ClientUdpSession::with_session_id(method, keys.clone(), 10).unwrap();
            let wire = client.encode(destination(), b"initial").unwrap();
            let mut unknown = ClientUdpSession::with_session_id(method, vec![keys[0].clone(), vec![9; method.key_length()]], 11).unwrap();
            let mut corrupt = wire.clone();
            corrupt[16] ^= 1;
            for invalid in [Vec::new(), vec![0; 31], vec![0; super::packet::MAX_DATAGRAM_SIZE + 1], corrupt, unknown.encode(destination(), b"unknown").unwrap()] {
                b.send_to(&invalid, address).await.unwrap();
                pump(&mut listener, &dispatcher).await;
            }
            assert!(captures.try_recv().is_err());
            a.send_to(&wire, address).await.unwrap();
            let task = Task::spawn(listener.accept(dispatcher.clone()).await.unwrap());
            let flow = captures.recv().await.unwrap();
            flow.packets.recv().await.unwrap().unwrap();
            // Like Go, a valid EIH selecting another identity with the same
            // session ID reuses the first link, destination and recorded user.
            let mut collision = ClientUdpSession::with_session_id(method, vec![keys[0].clone(), other_key.clone()], 10).unwrap();
            let wire = collision.encode(destination(), b"same-session").unwrap();
            b.send_to(&wire, address).await.unwrap();
            let packet = next_packet(&mut listener, &dispatcher, &flow).await;
            assert_eq!(packet.destination, udp(&target().to_string()));
            assert_eq!(packet.source, Some(source(a.local_addr().unwrap())));
            assert_eq!(flow.session.user.as_ref().unwrap().email, RELAY_EMAIL);
            assert_eq!(&packet.payload[16..], &wire[32..]);
            assert_eq!(packet_id(method, &other_key, &packet), 0);
            assert!(captures.try_recv().is_err());
            flow.packets.send(response(&flow, Bytes::from_static(b"cached"))).await.unwrap();
            assert_eq!(receive(&b).await.0, b"cached");
            // A valid outer header is sufficient, including a body-less packet.
            // Replays and AEAD failures belong to the final server, as in Go.
            a.send_to(&wire[..32], address).await.unwrap();
            let bare = next_packet(&mut listener, &dispatcher, &flow).await;
            assert_eq!(bare.payload.len(), 16);
            assert_eq!(&bare.payload[..], &packet.payload[..16]);
            relay.close().await.unwrap();
            task.finish().await;
        }
    }).await.unwrap();
}

struct Finished { fail: bool }
#[async_trait]
impl InboundDispatcher for Finished {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("UDP completion test".into())) }
    async fn dispatch_datagrams(&self, _packets: BoxDatagram, _session: SessionContext) -> Result<()> {
        if self.fail { Err(Error::Other("test route failed".into())) } else { Ok(()) }
    }
}

#[tokio::test]
async fn ss2022_relay_native_unpolled_expiry_listener_drop_and_dispatch_completion() {
    tokio::time::timeout(WAIT, async {
        let method = CipherMethod::Aes128Gcm;
        let keys = keys(method);
        let server = relay(method, &keys, target(), Some("udp"));
        let limits = RelayLimits { flows: 1, idle: Duration::from_millis(150), sweep: Duration::from_millis(10), ..RelayLimits::default() };
        let mut listener = server.bind_with_limits(local(), limits).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let a = UdpSocket::bind(local()).await.unwrap();
        let (dispatcher, mut captures) = capture(None);
        let mut client = ClientUdpSession::with_session_id(method, keys.clone(), 567).unwrap();
        let wire = client.encode(destination(), b"unpolled-expiry").unwrap();
        a.send_to(&wire, address).await.unwrap();
        let unpolled = listener.accept(dispatcher.clone()).await.unwrap();
        tokio::select! {
            _ = listener.accept(dispatcher.clone()) => panic!("idle expiry must not dispatch a task"),
            _ = tokio::time::sleep(limits.idle + limits.sweep * 3) => {}
        }
        a.send_to(&wire, address).await.unwrap();
        let replacement = listener.accept(dispatcher.clone()).await.unwrap();
        unpolled.await.unwrap();
        assert!(captures.try_recv().is_err());
        let task = Task::spawn(replacement);
        let flow = captures.recv().await.unwrap();
        flow.packets.recv().await.unwrap().unwrap();
        drop(listener);
        task.finish().await;
        assert!(flow.packets.recv().await.unwrap().is_none());
        assert!(matches!(flow.packets.send(response(&flow, Bytes::new())).await, Err(Error::Closed)));
        let rebound = UdpSocket::bind(address).await.unwrap();
        drop(rebound);
        // Completion, failure and transport closure release a slot even when
        // callers retain every previously captured transport.
        for fail in [false, true] {
            let server = relay(method, &keys, target(), Some("udp"));
            let mut listener = server.bind_with_limits(local(), RelayLimits { flows: 1, ..RelayLimits::default() }).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let (dispatcher, mut captures) = capture(Some(Arc::new(Finished { fail })));
            let mut retained = Vec::new();
            for _ in 0..3 {
                a.send_to(&wire, address).await.unwrap();
                let result = listener.accept(dispatcher.clone()).await.unwrap().await;
                assert_eq!(result.is_err(), fail);
                let flow = captures.recv().await.unwrap();
                assert!(flow.packets.recv().await.unwrap().is_none());
                retained.push(flow);
            }
            server.close().await.unwrap();
            let rebound = UdpSocket::bind(address).await.unwrap();
            drop(rebound); drop(retained);
        }
    }).await.unwrap();
}
