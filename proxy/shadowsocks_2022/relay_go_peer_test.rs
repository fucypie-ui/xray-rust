//! Selected Linux live relay gate: two ignored tests, four AES/endpoint cases
//! per direction, two production relay hops, 48 exact request/reply pairs.
//! Build testing/ss2022-relay-reference/build-peer.sh GO_REFERENCE_ROOT BINARY
//! and set XRAY_SS2022_RELAY_GO_PEER. Missing/empty/unusable helpers are fatal.
//! Parent owns module/workflow registration. Run this module with --ignored.
//! Go nonempty traffic uses Process; empty/rebinding traffic uses its exported
//! UDPWriter/UDPReader session APIs because pinned Process buf.Copy drops empties.
//! Rust nonempty traffic uses OutboundHandler; empties/rebinding use the existing
//! ClientUdpSession API. No test implements an independent wire codec.
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, process::Stdio, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::UdpSocket, process::{Child, Command}, sync::mpsc, task::{JoinHandle, JoinSet}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram, DatagramTransport}}, protocol::{SessionContext, User}}, features::{inbound::{InboundDispatcher, InboundHandler, NativeInboundListener}, outbound::OutboundHandler}};
use super::{Client, Server, Shadowsocks2022Config, cipher::CipherMethod, multi_server::{MultiUserServer, UserAccount}, relay_server::{RelayServer, RelayTarget}, udp_session::ClientUdpSession};

const REFERENCE: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const LIMIT: Duration = Duration::from_secs(40);
const IO_LIMIT: Duration = Duration::from_secs(10);
const PACKETS: usize = 6;
const SESSIONS: usize = 2;
const EMAIL: &str = "relay-final@example.invalid";
const CASES: [usize; PACKETS] = [1, 2, 3, 4, 0, 5];
const MAX_LINE: usize = 16_384;
const MAX_LINES: usize = 64;
const MAX_STDOUT: usize = 192 * 1024;

#[derive(Clone, Copy, Debug)]
struct Scenario { method: &'static str, role: &'static str }
const SCENARIOS: [Scenario; 4] = [
    Scenario { method: "2022-blake3-aes-128-gcm", role: "single" },
    Scenario { method: "2022-blake3-aes-256-gcm", role: "single" },
    Scenario { method: "2022-blake3-aes-128-gcm", role: "multi" },
    Scenario { method: "2022-blake3-aes-256-gcm", role: "multi" },
];
impl Scenario {
    fn method(self) -> CipherMethod { CipherMethod::parse(self.method).unwrap() }
    fn keys(self) -> Vec<Vec<u8>> {
        let size = self.method().key_length();
        let mut keys = vec![key(size, 0x81), key(size, 0xa1)];
        if self.role == "multi" { keys.push(key(size, 0xc1)); }
        keys.push(key(size, 0x11));
        keys
    }
    fn config(self, keys: &[Vec<u8>]) -> Shadowsocks2022Config {
        Shadowsocks2022Config { method: self.method.into(), key: keys.iter().map(|key| base64::engine::general_purpose::STANDARD.encode(key)).collect::<Vec<_>>().join(":"), network: Some("udp".into()) }
    }
    fn inbound(self) -> Arc<dyn InboundHandler> {
        let keys = self.keys();
        let user = User::with_email(uuid::Uuid::nil(), EMAIL, 7);
        if self.role == "multi" {
            let server = MultiUserServer::new("rust-relay-final", self.method(), keys[2].clone()).unwrap().with_network(Some("udp")).unwrap();
            server.add_account(UserAccount { key: key(self.method().key_length(), 0x51), user: User::with_email(uuid::Uuid::nil(), "decoy@example.invalid", 7) }).unwrap();
            server.add_account(UserAccount { key: keys[3].clone(), user }).unwrap();
            Arc::new(server)
        } else { Arc::new(Server::try_new("rust-relay-final", self.config(&keys[2..])).unwrap().with_user(user)) }
    }
    fn relay(self, layer: usize, next: SocketAddr) -> Arc<dyn InboundHandler> {
        let keys = self.keys();
        let targets = vec![
            RelayTarget { key: key(self.method().key_length(), 0x51), destination: Destination::from(next), user: User::with_email(uuid::Uuid::nil(), "decoy@example.invalid", 10 + layer as u32) },
            RelayTarget { key: keys[layer + 1].clone(), destination: Destination::from(next), user: User::with_email(uuid::Uuid::nil(), hop_email(layer), 10 + layer as u32) },
        ];
        Arc::new(RelayServer::new(format!("rust-relay-{layer}"), self.method(), keys[layer].clone(), targets).unwrap().with_network(Some("udp")).unwrap())
    }
}
fn key(size: usize, first: u8) -> Vec<u8> { (0..size).map(|i| first.wrapping_add(i as u8)).collect() }
fn hop_email(layer: usize) -> String { format!("relay-hop-{layer}@example.invalid") }
fn local() -> SocketAddr { "127.0.0.1:0".parse().unwrap() }
fn udp(address: &str) -> Destination { Destination::parse_str(address, Network::Udp).unwrap() }
fn source(address: SocketAddr) -> Destination { Destination::udp(address.ip().into(), address.port()) }
fn loopback(address: SocketAddr) { assert!(address.ip().is_loopback()); assert_ne!(address.port(), 0); }
fn destination(index: usize, reply: bool) -> Destination {
    let addresses = if reply {
        ["[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002", "[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354"]
    } else {
        ["empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000", "large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353"]
    };
    udp(addresses[index])
}
fn payload(index: usize, reply: bool) -> Vec<u8> {
    let (sizes, salt) = if reply { ([0, 19, 513, 7800, 1, 0], 0xa7) } else { ([0, 1, 257, 7900, 19, 0], 0x31) };
    (0..sizes[index]).map(|i| (i * 73 + i / 251 + salt + index * 17) as u8).collect()
}
fn helper() -> PathBuf {
    assert_eq!(std::env::consts::OS, "linux", "selected relay gate requires Linux, not Android or another target");
    assert!(std::env::var_os("TERMUX_VERSION").is_none_or(|value| value.is_empty()) && std::env::var_os("ANDROID_ROOT").is_none_or(|value| value.is_empty()), "selected relay gate rejects Android/Termux");
    assert!(!std::env::var("PREFIX").unwrap_or_default().starts_with("/data/data/com.termux/"), "selected relay gate rejects Android/Termux");
    let binary = std::env::var_os("XRAY_SS2022_RELAY_GO_PEER").expect("selected relay gate requires XRAY_SS2022_RELAY_GO_PEER built from pinned Go sources on Linux");
    assert!(!binary.is_empty(), "XRAY_SS2022_RELAY_GO_PEER must not be empty");
    let binary = PathBuf::from(binary);
    assert!(binary.is_file(), "relay helper must be an existing executable: {}", binary.display());
    binary
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    event: String, source: String, mode: String, method: String, role: String, layer: usize,
    path: String, address: SocketAddr, peer: String, next: String, email: String, level: u32,
    packets: usize, sessions: usize, wire: String,
}
impl Event {
    fn is_wire(&self) -> bool { matches!(self.event.as_str(), "request" | "forward" | "reply" | "response") }
    fn bytes(&self) -> Vec<u8> {
        assert!(self.is_wire());
        let bytes = base64::engine::general_purpose::STANDARD.decode(&self.wire).unwrap();
        assert!(!bytes.is_empty() && bytes.len() <= super::packet::MAX_DATAGRAM_SIZE);
        bytes
    }
    fn remote(&self) -> SocketAddr { let remote = self.peer.parse().unwrap(); loopback(remote); remote }
}
struct Peer {
    child: Child, pump: Option<JoinHandle<()>>, events: mpsc::Receiver<Event>, history: Vec<Event>,
    mode: &'static str, layer: usize, scenario: Scenario,
}
impl Drop for Peer { fn drop(&mut self) { if let Some(pump) = &self.pump { pump.abort(); } } }
impl Peer {
    fn spawn(mode: &'static str, layer: usize, address: SocketAddr, next: Option<SocketAddr>, scenario: Scenario) -> Self {
        let mut command = Command::new(helper());
        command.args(["--mode", mode, "--method", scenario.method, "--role", scenario.role, "--layer", &layer.to_string(), "--address", &address.to_string()]);
        if let Some(next) = next { command.args(["--next", &next.to_string()]); }
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().expect("start mandatory pinned Go relay helper");
        let stdout = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel(MAX_LINES);
        // Drain concurrently: byte records must never deadlock a helper on its
        // stdout pipe. take() bounds allocation before UTF-8/JSON parsing.
        let pump = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut lines = 0;
            let mut total = 0;
            loop {
                let mut line = Vec::new();
                let n = (&mut reader).take((MAX_LINE + 1) as u64).read_until(b'\n', &mut line).await.unwrap();
                if n == 0 { break; }
                lines += 1; total += n;
                assert!(n <= MAX_LINE && line.last() == Some(&b'\n'), "unterminated/oversize helper stdout line");
                assert!(lines <= MAX_LINES && total <= MAX_STDOUT, "helper stdout exceeded fixed bounds");
                let event = serde_json::from_slice(&line).expect("relay helper stdout must contain only strict JSON events");
                if sender.send(event).await.is_err() { break; }
            }
        });
        Self { child, pump: Some(pump), events, history: Vec::new(), mode, layer, scenario }
    }
    async fn until(&mut self, kind: &str) -> Event {
        loop {
            let event = tokio::time::timeout(IO_LIMIT, self.events.recv()).await.expect("relay helper event timed out").expect("mandatory Go relay helper exited or emitted invalid stdout");
            assert_eq!(event.source, REFERENCE);
            assert_eq!(event.mode, self.mode); assert_eq!(event.layer, self.layer);
            assert_eq!(event.method, self.scenario.method); assert_eq!(event.role, self.scenario.role);
            loopback(event.address);
            let allowed = match self.mode {
                "client" => matches!(event.event.as_str(), "ready" | "request" | "reply" | "handler_complete" | "handler_closed" | "empty_ready" | "empty_rebind" | "complete" | "closed"),
                "endpoint" => matches!(event.event.as_str(), "ready" | "request" | "dispatch" | "response" | "complete" | "closed"),
                "relay" => matches!(event.event.as_str(), "ready" | "request" | "dispatch" | "forward" | "reply" | "response" | "complete" | "closed"),
                _ => false,
            };
            assert!(allowed, "unexpected event for helper mode: {event:?}");
            if self.mode != "client" { assert_eq!(event.path, "handler"); }
            if event.is_wire() {
                let _ = event.bytes(); let _ = event.remote();
                assert!(event.email.is_empty() && event.next.is_empty());
                assert_eq!((event.level, event.packets, event.sessions), (0, 0, 0));
            } else { assert!(event.wire.is_empty()); }
            self.history.push(event.clone());
            if event.event == kind { return event; }
            assert!(event.is_wire() || event.event == "dispatch", "unexpected helper control while waiting for {kind}: {event:?}");
        }
    }
    async fn control(&mut self, kind: &str, path: &str, packets: usize, sessions: usize) -> Event {
        let event = self.until(kind).await;
        assert_eq!(event.path, path); assert_eq!(event.packets, packets); assert_eq!(event.sessions, sessions);
        assert!(event.wire.is_empty() && event.email.is_empty()); assert_eq!(event.level, 0);
        event
    }
    async fn finish(mut self, path: &str, address: SocketAddr) -> Vec<Event> {
        self.child.stdin.take().unwrap().write_all(b"exit\n").await.unwrap();
        let closed = self.control("closed", path, PACKETS, SESSIONS).await;
        assert_eq!(closed.address, address);
        assert!(tokio::time::timeout(IO_LIMIT, self.child.wait()).await.unwrap().unwrap().success(), "mandatory Go relay helper failed");
        assert!(self.events.recv().await.is_none(), "unexpected trailing helper events");
        self.pump.as_mut().unwrap().await.unwrap();
        let _ = self.pump.take();
        std::mem::take(&mut self.history)
    }
}
fn events<'a>(history: &'a [Event], kind: &str) -> Vec<&'a Event> { history.iter().filter(|event| event.event == kind).collect() }
fn wires(history: &[Event], kind: &str) -> Vec<Vec<u8>> {
    let selected = events(history, kind);
    assert_eq!(selected.len(), PACKETS, "exact wire packet count for {kind}");
    selected.iter().map(|event| event.bytes()).collect()
}
fn headers(scenario: Scenario, input: &[Vec<u8>]) {
    assert_eq!(input.len(), PACKETS);
    let keys = scenario.keys();
    let raw: Vec<_> = input.iter().map(|wire| super::packet::decrypt_header(scenario.method(), &keys[0], &wire[..16]).unwrap()).collect();
    assert_ne!(&raw[0][..8], &raw[4][..8], "two independent client sessions must execute");
    for (position, header) in raw.iter().enumerate() {
        let start = if position < 4 { 0 } else { 4 };
        assert_eq!(&header[..8], &raw[start][..8]);
        assert_eq!(&header[8..], &((position - start) as u64).to_be_bytes());
    }
}
fn peel(scenario: Scenario, layer: usize, before: &[Vec<u8>], after: &[Vec<u8>]) {
    let keys = scenario.keys();
    assert_eq!(before.len(), PACKETS); assert_eq!(after.len(), PACKETS);
    for (before, after) in before.iter().zip(after) {
        assert!(before.len() >= 32 && after.len() >= 16);
        assert_eq!(after.len() + 16, before.len(), "exactly one EIH must be removed");
        // Independent Go wire records provide the input and all retained
        // EIH/body bytes; only the existing header engine is used to compare
        // the session/counter under the required successive hop keys.
        assert_eq!(&after[16..], &before[32..], "lower EIHs and AEAD body must pass through byte-for-byte");
        assert_eq!(super::packet::decrypt_header(scenario.method(), &keys[layer], &before[..16]).unwrap(), super::packet::decrypt_header(scenario.method(), &keys[layer + 1], &after[..16]).unwrap());
    }
}
fn dispatches(history: &[Event], address: SocketAddr, next: Option<SocketAddr>, layer: usize, first_peers: [SocketAddr; SESSIONS]) {
    let selected = events(history, "dispatch");
    assert_eq!(selected.len(), SESSIONS, "rebinding must reuse the production session link");
    for (index, event) in selected.into_iter().enumerate() {
        assert_eq!(event.address, address); assert_eq!(event.remote(), first_peers[index]);
        assert_eq!(event.sessions, index + 1); assert_eq!(event.packets, 0); assert_eq!(event.path, "handler");
        if let Some(next) = next {
            assert_eq!(event.next, next.to_string()); assert_eq!(event.email, hop_email(layer)); assert_eq!(event.level, 10 + layer as u32);
        } else {
            assert_eq!(event.next, destination(CASES[index * 4], false).to_string()); assert_eq!(event.email, EMAIL); assert_eq!(event.level, 7);
        }
    }
}

struct Flow { packets: BoxDatagram, session: SessionContext }
struct Trace { reply: bool, packet: Datagram, remote: SocketAddr }
struct Tap { packets: BoxDatagram, traces: mpsc::Sender<Trace>, remote: SocketAddr }
#[async_trait]
impl DatagramTransport for Tap {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let packet = self.packets.recv().await?;
        if let Some(packet) = &packet { self.traces.try_send(Trace { reply: false, packet: packet.clone(), remote: self.remote }).map_err(|_| Error::BufferOverflow)?; }
        Ok(packet)
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        self.traces.try_send(Trace { reply: true, packet: packet.clone(), remote: self.remote }).map_err(|_| Error::BufferOverflow)?;
        self.packets.send(packet).await
    }
    async fn close(&self) -> Result<()> { self.packets.close().await }
}
struct Direct { calls: Arc<AtomicUsize>, inner: crate::proxy::freedom::Handler }
#[async_trait]
impl OutboundHandler for Direct {
    fn tag(&self) -> &str { "direct" }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> { self.inner.connect(session).await }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> { self.calls.fetch_add(1, Ordering::SeqCst); self.inner.connect_datagram(session).await }
}
struct Route { layer: usize, next: SocketAddr, started: mpsc::Sender<Flow>, traces: mpsc::Sender<Trace>, inner: Arc<dyn InboundDispatcher> }
#[async_trait]
impl InboundDispatcher for Route {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("live relay gate selects UDP".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        let remote = session.source.unwrap(); loopback(remote);
        assert_eq!(session.inbound_tag, format!("rust-relay-{}", self.layer));
        assert_eq!(session.destination, source(self.next));
        assert_eq!(session.user.as_ref().unwrap().email, hop_email(self.layer));
        assert_eq!(session.user.as_ref().unwrap().level, 10 + self.layer as u32);
        self.started.send(Flow { packets: packets.clone(), session: session.clone() }).await.map_err(|_| Error::Closed)?;
        self.inner.dispatch_datagrams(Arc::new(Tap { packets, traces: self.traces.clone(), remote }), session).await
    }
}
struct RelayCapture { flows: mpsc::Receiver<Flow>, traces: mpsc::Receiver<Trace>, calls: Arc<AtomicUsize> }
fn routing(layer: usize, next: SocketAddr) -> (Arc<dyn InboundDispatcher>, RelayCapture) {
    let (started, flows) = mpsc::channel(4); let (traces, captured) = mpsc::channel(32);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut outbounds: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
    outbounds.insert("direct".into(), Arc::new(Direct { calls: calls.clone(), inner: crate::proxy::freedom::Handler::new("direct") }));
    let inner = crate::app::dispatcher::DefaultDispatcher::new(outbounds, Arc::new(crate::features::routing::DefaultRouter)).with_default_outbound("direct");
    (Arc::new(Route { layer, next, started, traces, inner: Arc::new(inner) }), RelayCapture { flows, traces: captured, calls })
}
impl RelayCapture {
    async fn collect(&mut self, next: SocketAddr) -> (Vec<Flow>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut flows = Vec::new();
        for _ in 0..SESSIONS { flows.push(self.flows.recv().await.unwrap()); }
        let mut requests = Vec::new(); let mut replies = Vec::new();
        for _ in 0..PACKETS * 2 {
            let trace = self.traces.recv().await.unwrap();
            let position = if trace.reply { replies.len() } else { requests.len() };
            let flow = &flows[usize::from(position >= 4)];
            assert_eq!(trace.remote, flow.session.source.unwrap());
            if trace.reply {
                assert_eq!(trace.packet.source, Some(source(next))); assert_eq!(trace.packet.destination, source(trace.remote));
                replies.push(trace.packet.payload.to_vec());
            } else {
                assert_eq!(trace.packet.source, Some(source(trace.remote))); assert_eq!(trace.packet.destination, source(next));
                requests.push(trace.packet.payload.to_vec());
            }
        }
        assert_eq!(self.calls.load(Ordering::SeqCst), SESSIONS, "production dispatcher must cache one direct association per session, including rebinding");
        assert!(self.flows.try_recv().is_err() && self.traces.try_recv().is_err());
        (flows, requests, replies)
    }
}
struct Observed { index: usize, remote: SocketAddr }
struct Respond { started: mpsc::Sender<Flow>, seen: mpsc::Sender<Observed> }
#[async_trait]
impl InboundDispatcher for Respond {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("live relay endpoint selects UDP".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        let remote = session.source.unwrap(); loopback(remote);
        assert_eq!(session.inbound_tag, "rust-relay-final");
        assert_eq!(session.user.as_ref().unwrap().email, EMAIL); assert_eq!(session.user.as_ref().unwrap().level, 7);
        self.started.send(Flow { packets: packets.clone(), session: session.clone() }).await.map_err(|_| Error::Closed)?;
        let mut cases: &[usize] = &[]; let mut position = 0;
        while let Some(packet) = packets.recv().await? {
            if position == 0 {
                cases = if packet.destination == destination(1, false) { &CASES[..4] } else { &CASES[4..] };
                assert_eq!(session.destination, packet.destination);
            }
            assert!(position < cases.len(), "unexpected plaintext packet");
            let index = cases[position];
            assert_eq!(packet.source, Some(source(remote))); assert_eq!(packet.destination, destination(index, false));
            assert_eq!(packet.payload.as_ref(), payload(index, false).as_slice());
            packets.send(Datagram { payload: payload(index, true).into(), source: Some(destination(index, true)), destination: source(remote) }).await?;
            self.seen.send(Observed { index, remote }).await.map_err(|_| Error::Closed)?;
            position += 1;
        }
        Ok(())
    }
}

// Timeout/assertion paths retain abort ownership of listener and all dispatch
// children. Helpers are separately kill_on_drop and their stdout tasks abort.
struct Running(Option<JoinHandle<Result<()>>>);
impl Drop for Running { fn drop(&mut self) { if let Some(task) = &self.0 { task.abort(); } } }
impl Running {
    fn start(mut listener: Box<dyn NativeInboundListener>, dispatcher: Arc<dyn InboundDispatcher>) -> Self {
        Self(Some(tokio::spawn(async move {
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
        })))
    }
    async fn finish(mut self) { self.0.as_mut().unwrap().await.unwrap().unwrap(); let _ = self.0.take(); }
}
async fn released(address: SocketAddr) { let socket = UdpSocket::bind(address).await.expect("closed transport must release UDP socket"); drop(socket); }
async fn retained_closed(flow: &Flow) {
    assert!(flow.packets.recv().await.unwrap().is_none());
    assert!(matches!(flow.packets.send(Datagram { payload: Bytes::new(), source: Some(flow.session.destination.clone()), destination: source(flow.session.source.unwrap()) }).await, Err(Error::Closed)));
    flow.packets.close().await.unwrap(); flow.packets.close().await.unwrap();
}
async fn receive(socket: &UdpSocket, expected: SocketAddr) -> Vec<u8> {
    let mut wire = vec![0; super::packet::MAX_DATAGRAM_SIZE + 1];
    let (n, remote) = socket.recv_from(&mut wire).await.unwrap();
    assert_eq!(remote, expected); assert!(n != 0 && n <= super::packet::MAX_DATAGRAM_SIZE); wire.truncate(n); wire
}

#[tokio::test]
#[ignore = "selected Linux relay gate requires XRAY_SS2022_RELAY_GO_PEER; run with --ignored and require both tests to execute"]
async fn pinned_go_client_through_two_rust_relays_to_pinned_go_udp_endpoints() {
    let _ = helper();
    let mut completed = 0;
    for scenario in SCENARIOS {
        tokio::time::timeout(LIMIT, async {
            let mut endpoint = Peer::spawn("endpoint", 2, local(), None, scenario);
            let final_ready = endpoint.control("ready", "handler", 0, 0).await;
            assert!(final_ready.peer.is_empty() && final_ready.next.is_empty());
            let lower = scenario.relay(1, final_ready.address);
            let listener = lower.bind_native(local()).await.unwrap().unwrap();
            let lower_address = listener.local_addr().unwrap();
            let (dispatcher, mut lower_capture) = routing(1, final_ready.address);
            let lower_task = Running::start(listener, dispatcher);
            let outer = scenario.relay(0, lower_address);
            let listener = outer.bind_native(local()).await.unwrap().unwrap();
            let outer_address = listener.local_addr().unwrap();
            let (dispatcher, mut outer_capture) = routing(0, lower_address);
            let outer_task = Running::start(listener, dispatcher);
            let mut client = Peer::spawn("client", 0, outer_address, None, scenario);
            let ready = client.control("ready", "handler", 0, 1).await;
            assert_eq!(ready.remote(), outer_address);
            assert_eq!(client.control("handler_complete", "handler", 4, 1).await.address, ready.address);
            assert_eq!(client.control("handler_closed", "handler", 4, 1).await.address, ready.address);
            let empty = client.control("empty_ready", "session", 0, 1).await;
            let rebound = client.control("empty_rebind", "session", 1, 1).await;
            assert_ne!(empty.address, rebound.address); assert_eq!(empty.remote(), outer_address); assert_eq!(rebound.remote(), outer_address);
            assert_eq!(client.control("complete", "handler+session", PACKETS, SESSIONS).await.address, rebound.address);
            assert_eq!(endpoint.control("complete", "handler", PACKETS, SESSIONS).await.address, final_ready.address);
            let (outer_flows, first, first_replies) = outer_capture.collect(lower_address).await;
            let (lower_flows, second, second_replies) = lower_capture.collect(final_ready.address).await;
            assert_eq!(outer_flows[0].session.source, Some(ready.address)); assert_eq!(outer_flows[1].session.source, Some(empty.address));
            let client_history = client.finish("handler+session", rebound.address).await;
            let endpoint_history = endpoint.finish("handler", final_ready.address).await;
            let original = wires(&client_history, "request");
            headers(scenario, &original); peel(scenario, 0, &original, &first); peel(scenario, 1, &first, &second);
            assert_eq!(wires(&endpoint_history, "request"), second);
            let replies = wires(&endpoint_history, "response");
            assert_eq!(first_replies, replies); assert_eq!(second_replies, replies); assert_eq!(wires(&client_history, "reply"), replies);
            let requests = events(&endpoint_history, "request");
            let peers = [requests[0].remote(), requests[4].remote()];
            dispatches(&endpoint_history, final_ready.address, None, 2, peers);
            for (position, request) in requests.iter().enumerate() {
                assert_eq!(request.address, final_ready.address); assert_eq!(request.remote(), peers[usize::from(position >= 4)]);
                assert_eq!(events(&endpoint_history, "response")[position].remote(), request.remote());
                assert_eq!(events(&client_history, "request")[position].address, if position < 4 { ready.address } else if position == 4 { empty.address } else { rebound.address });
            }
            assert_eq!(events(&client_history, "request").iter().map(|event| event.path.as_str()).collect::<Vec<_>>(), ["handler", "handler", "handler", "handler", "session", "session"]);
            outer.close().await.unwrap(); lower.close().await.unwrap();
            // Keep the accept owners and captured transports alive here:
            // close itself must revoke both native listener sockets.
            released(outer_address).await; released(lower_address).await;
            outer_task.finish().await; lower_task.finish().await;
            for flow in outer_flows.iter().chain(&lower_flows) { retained_closed(flow).await; }
            released(outer_address).await; released(lower_address).await; released(final_ready.address).await;
        }).await.unwrap_or_else(|_| panic!("Go client -> two Rust relays -> Go endpoint timed out: {scenario:?}"));
        completed += 1;
    }
    assert_eq!(completed, 4, "both AES methods and both final endpoint roles must execute");
}

#[tokio::test]
#[ignore = "selected Linux relay gate requires XRAY_SS2022_RELAY_GO_PEER; run with --ignored and require both tests to execute"]
async fn rust_client_through_two_pinned_go_relays_to_rust_native_udp_endpoints() {
    let _ = helper();
    let mut completed = 0;
    for scenario in SCENARIOS {
        tokio::time::timeout(LIMIT, async {
            let inbound = scenario.inbound();
            let listener = inbound.bind_native(local()).await.unwrap().unwrap();
            let final_address = listener.local_addr().unwrap();
            let (started, mut flows) = mpsc::channel(4); let (seen, mut observations) = mpsc::channel(8);
            let running = Running::start(listener, Arc::new(Respond { started, seen }));
            let mut lower = Peer::spawn("relay", 1, local(), Some(final_address), scenario);
            let lower_ready = lower.control("ready", "handler", 0, 0).await;
            assert_eq!(lower_ready.next, final_address.to_string());
            let mut outer = Peer::spawn("relay", 0, local(), Some(lower_ready.address), scenario);
            let outer_ready = outer.control("ready", "handler", 0, 0).await;
            assert_eq!(outer_ready.next, lower_ready.address.to_string());
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("rust-relay-client", Destination::from(outer_ready.address), scenario.config(&scenario.keys())).unwrap());
            let mut context = SessionContext::new("local", destination(1, false));
            context.source = Some("198.51.100.90:41000".parse().unwrap());
            let logical = udp("192.0.2.90:42000");
            let packets = client.connect_datagram(&context).await.unwrap();
            for &index in &CASES[..4] {
                packets.send(Datagram { payload: payload(index, false).into(), source: (index == 1).then(|| logical.clone()), destination: destination(index, false) }).await.unwrap();
                let reply = packets.recv().await.unwrap().expect("binary reply must retain its boundary");
                assert_eq!(reply.payload.as_ref(), payload(index, true).as_slice()); assert_eq!(reply.source, Some(destination(index, true))); assert_eq!(reply.destination, logical);
            }
            let first = outer.until("request").await;
            let client_address = first.remote(); assert_ne!(source(client_address), logical);
            let pending = packets.recv(); tokio::pin!(pending);
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut pending).await.is_err());
            client.close().await.unwrap();
            assert!(pending.await.unwrap().is_none());
            assert!(matches!(packets.send(Datagram::new(Bytes::new(), destination(1, false)).unwrap()).await, Err(Error::Closed)));
            assert!(matches!(client.connect_datagram(&context).await, Err(Error::Closed)));
            packets.close().await.unwrap(); packets.close().await.unwrap();
            released(client_address).await; // retained trait transport cannot hold its socket
            let a = UdpSocket::bind(local()).await.unwrap(); let b = UdpSocket::bind(local()).await.unwrap();
            let mut raw = ClientUdpSession::new(scenario.method(), scenario.keys()).unwrap();
            let mut raw_requests = Vec::new(); let mut raw_replies = Vec::new();
            for (&index, socket) in CASES[4..].iter().zip([&a, &b]) {
                let wire = raw.encode(destination(index, false), &payload(index, false)).unwrap();
                assert_eq!(socket.send_to(&wire, outer_ready.address).await.unwrap(), wire.len());
                raw_requests.push(wire);
                let wire = receive(socket, outer_ready.address).await;
                let decoded = raw.decode(&wire).unwrap();
                assert_eq!(decoded.client_session_id, Some(raw.session_id())); assert_eq!(decoded.destination, destination(index, true)); assert_eq!(decoded.payload, payload(index, true));
                raw_replies.push(wire);
            }
            assert_ne!(a.local_addr().unwrap(), b.local_addr().unwrap());
            assert!(tokio::time::timeout(Duration::from_millis(10), receive(&a, outer_ready.address)).await.is_err(), "Go production relay reply must follow the rebound socket");
            assert_eq!(outer.control("complete", "handler", PACKETS, SESSIONS).await.address, outer_ready.address);
            assert_eq!(lower.control("complete", "handler", PACKETS, SESSIONS).await.address, lower_ready.address);
            let outer_history = outer.finish("handler", outer_ready.address).await;
            let lower_history = lower.finish("handler", lower_ready.address).await;
            let original = wires(&outer_history, "request"); let first_forward = wires(&outer_history, "forward"); let second_forward = wires(&lower_history, "forward");
            headers(scenario, &original); peel(scenario, 0, &original, &first_forward); peel(scenario, 1, &first_forward, &second_forward);
            assert_eq!(wires(&lower_history, "request"), first_forward); assert_eq!(&original[4..], raw_requests.as_slice());
            let replies = wires(&lower_history, "reply");
            assert_eq!(wires(&lower_history, "response"), replies); assert_eq!(wires(&outer_history, "reply"), replies); assert_eq!(wires(&outer_history, "response"), replies); assert_eq!(&replies[4..], raw_replies.as_slice());
            let outer_requests = events(&outer_history, "request"); let lower_requests = events(&lower_history, "request");
            dispatches(&outer_history, outer_ready.address, Some(lower_ready.address), 0, [client_address, a.local_addr().unwrap()]);
            dispatches(&lower_history, lower_ready.address, Some(final_address), 1, [lower_requests[0].remote(), lower_requests[4].remote()]);
            let handler = flows.recv().await.unwrap(); let empty = flows.recv().await.unwrap();
            assert_eq!(handler.session.destination, destination(1, false)); assert_eq!(empty.session.destination, destination(0, false));
            assert!(!Arc::ptr_eq(&handler.packets, &empty.packets));
            for (position, &index) in CASES.iter().enumerate() {
                let observed = observations.recv().await.unwrap(); assert_eq!(observed.index, index);
                let flow = if position < 4 { &handler } else { &empty }; assert_eq!(Some(observed.remote), flow.session.source);
                let outer_forward = events(&outer_history, "forward")[position]; let lower_forward = events(&lower_history, "forward")[position];
                assert_eq!(outer_requests[position].address, outer_ready.address);
                assert_eq!(outer_requests[position].remote(), if position < 4 { client_address } else if position == 4 { a.local_addr().unwrap() } else { b.local_addr().unwrap() });
                assert_eq!(outer_forward.remote(), lower_ready.address); assert_eq!(lower_requests[position].remote(), outer_forward.address);
                assert_eq!(lower_forward.remote(), final_address); assert_eq!(lower_forward.address, observed.remote);
                assert_eq!(events(&outer_history, "response")[position].remote(), outer_requests[position].remote());
                assert_eq!(events(&lower_history, "response")[position].remote(), lower_requests[position].remote());
            }
            assert!(flows.try_recv().is_err() && observations.try_recv().is_err());
            inbound.close().await.unwrap();
            released(final_address).await; // accept owner and transports are still retained
            running.finish().await;
            retained_closed(&handler).await; retained_closed(&empty).await;
            released(final_address).await; released(outer_ready.address).await; released(lower_ready.address).await;
        }).await.unwrap_or_else(|_| panic!("Rust client -> two Go relays -> Rust endpoint timed out: {scenario:?}"));
        completed += 1;
    }
    assert_eq!(completed, 4, "both AES methods and both final endpoint roles must execute");
}
