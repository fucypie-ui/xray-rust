//! Selected Linux live gate: two tests, five configurations per direction.
//! Build testing/ss2022-reference/build-peer.sh GO_REFERENCE_ROOT OUTPUT_BINARY
//! and set XRAY_SS2022_GO_PEER to that binary. Missing/empty/unusable is fatal.
//! Run this module with --ignored; the parent owns module/workflow registration.
//! Ten configurations exchange 60 exact request/reply pairs over real UDP.
//! Go client Process handles four nonempty pairs; its exported UDP session APIs
//! handle two empty pairs because the pinned Process buf.Copy drops empties.
use std::{net::SocketAddr, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines}, net::UdpSocket, process::{Child, ChildStdout, Command}, sync::mpsc, task::{JoinHandle, JoinSet}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram}}, protocol::{SessionContext, User}}, features::{inbound::{InboundDispatcher, InboundHandler, NativeInboundListener}, outbound::OutboundHandler}};
use super::{Client, Server, Shadowsocks2022Config, cipher::CipherMethod, multi_server::{MultiUserServer, UserAccount}};

const REFERENCE: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const SESSION_LIMIT: Duration = Duration::from_secs(30);
const EMAIL: &str = "live-user@example.invalid";
const PACKETS: usize = 6;
const HANDLER_CASES: &[usize] = &[1, 2, 3, 4];
const EMPTY_CASES: &[usize] = &[0, 5];

#[derive(Clone, Copy, Debug)]
struct Scenario { method: &'static str, role: &'static str }
const SCENARIOS: [Scenario; 5] = [
    Scenario { method: "2022-blake3-aes-128-gcm", role: "single" },
    Scenario { method: "2022-blake3-aes-256-gcm", role: "single" },
    Scenario { method: "2022-blake3-chacha20-poly1305", role: "single" },
    Scenario { method: "2022-blake3-aes-128-gcm", role: "multi" },
    Scenario { method: "2022-blake3-aes-256-gcm", role: "multi" },
];

impl Scenario {
    fn method(self) -> CipherMethod { CipherMethod::parse(self.method).unwrap() }
    fn keys(self) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        if self.role == "multi" { keys.push(key(self.method().key_length(), 0xa1)); }
        keys.push(key(self.method().key_length(), 0x11));
        keys
    }
    fn config(self, network: &str) -> Shadowsocks2022Config {
        Shadowsocks2022Config {
            method: self.method.into(),
            key: self.keys().iter().map(|key| base64::engine::general_purpose::STANDARD.encode(key)).collect::<Vec<_>>().join(":"),
            network: Some(network.into()),
        }
    }
    fn inbound(self) -> Arc<dyn InboundHandler> {
        let user = User::with_email(uuid::Uuid::nil(), EMAIL, 7);
        if self.role == "multi" {
            let keys = self.keys();
            let server = MultiUserServer::new("rust-live", self.method(), keys[0].clone()).unwrap().with_network(Some("udp")).unwrap();
            server.add_account(UserAccount { key: key(self.method().key_length(), 0x51), user: User::with_email(uuid::Uuid::nil(), "decoy@example.invalid", 7) }).unwrap();
            server.add_account(UserAccount { key: keys[1].clone(), user }).unwrap();
            Arc::new(server)
        } else { Arc::new(Server::try_new("rust-live", self.config("udp")).unwrap().with_user(user)) }
    }
}

fn key(size: usize, first: u8) -> Vec<u8> { (0..size).map(|i| first.wrapping_add(i as u8)).collect() }
fn udp(address: &str) -> Destination { Destination::parse_str(address, Network::Udp).unwrap() }
fn source(address: SocketAddr) -> Destination { Destination::udp(address.ip().into(), address.port()) }
fn destination(index: usize, reply: bool) -> Destination {
    let addresses = if reply {
        ["[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002",
         "[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354"]
    } else {
        ["empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000",
         "large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353"]
    };
    udp(addresses[index])
}
fn payload(index: usize, reply: bool) -> Vec<u8> {
    let (sizes, salt) = if reply { ([0, 19, 513, 7800, 1, 0], 0xa7) } else { ([0, 1, 257, 7900, 19, 0], 0x31) };
    (0..sizes[index]).map(|i| (i * 73 + i / 251 + salt + index * 17) as u8).collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    event: String, source: String, mode: String, method: String, role: String,
    path: String, address: SocketAddr, peer: String, packets: usize, sessions: usize,
}
struct Peer { child: Child, lines: Lines<BufReader<ChildStdout>>, mode: &'static str, scenario: Scenario, endpoint: SocketAddr }
impl Peer {
    fn spawn(mode: &'static str, endpoint: SocketAddr, scenario: Scenario) -> Self {
        let executable = std::env::var_os("XRAY_SS2022_GO_PEER").expect("selected live SS2022 tests require XRAY_SS2022_GO_PEER built from the pinned Go module on Linux");
        assert!(!executable.is_empty(), "XRAY_SS2022_GO_PEER must not be empty");
        let executable = PathBuf::from(executable);
        assert!(executable.is_file(), "XRAY_SS2022_GO_PEER must name an existing helper binary: {}", executable.display());
        let address = endpoint.to_string();
        let mut child = Command::new(executable)
            .args(["--mode", mode, "--address", &address, "--method", scenario.method, "--role", scenario.role])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true)
            .spawn().expect("start pinned Go SS2022 peer");
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self { child, lines, mode, scenario, endpoint }
    }
    async fn event(&mut self, kind: &str, path: &str, packets: usize, sessions: usize) -> Event {
        let line = self.lines.next_line().await.unwrap().expect("Go SS2022 peer exited before the required JSON event");
        let event: Event = serde_json::from_str(&line).expect("Go SS2022 stdout must contain only strict JSON events");
        assert_eq!(event.event, kind);
        assert_eq!(event.source, REFERENCE);
        assert_eq!(event.mode, self.mode);
        assert_eq!(event.method, self.scenario.method);
        assert_eq!(event.role, self.scenario.role);
        assert_eq!(event.path, path);
        assert_eq!(event.packets, packets);
        assert_eq!(event.sessions, sessions);
        assert!(event.address.ip().is_loopback());
        assert_ne!(event.address.port(), 0);
        if self.mode == "client" { assert_eq!(event.peer.parse::<SocketAddr>().unwrap(), self.endpoint); }
        event
    }
    async fn finish(mut self, path: &str, sessions: usize, address: SocketAddr) {
        self.child.stdin.take().unwrap().write_all(b"exit\n").await.unwrap();
        let closed = self.event("closed", path, PACKETS, sessions).await;
        assert_eq!(closed.address, address);
        assert!(self.child.wait().await.unwrap().success(), "Go SS2022 peer failed");
        assert!(self.lines.next_line().await.unwrap().is_none(), "unexpected trailing Go stdout");
    }
}

struct Flow { packets: BoxDatagram, session: SessionContext }
struct Observation { index: usize, remote: SocketAddr }
struct Respond { started: mpsc::UnboundedSender<Flow>, seen: mpsc::UnboundedSender<Observation> }
#[async_trait]
impl InboundDispatcher for Respond {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> { Err(Error::Unsupported("live UDP test does not dispatch streams".into())) }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        let remote = session.source.expect("native dispatcher requires the actual Go source socket");
        assert!(remote.ip().is_loopback());
        assert_ne!(remote.port(), 0);
        assert_eq!(session.inbound_tag, "rust-live");
        assert_eq!(session.user.as_ref().unwrap().email, EMAIL);
        assert_eq!(session.user.as_ref().unwrap().level, 7);
        self.started.send(Flow { packets: packets.clone(), session: session.clone() }).map_err(|_| Error::Closed)?;
        let mut cases: &[usize] = &[];
        let mut position = 0;
        while let Some(packet) = packets.recv().await? {
            if position == 0 {
                cases = if packet.destination == destination(1, false) { HANDLER_CASES } else { EMPTY_CASES };
                assert_eq!(session.destination, packet.destination);
            }
            assert!(position < cases.len(), "unexpected additional packet in native flow");
            let index = cases[position];
            assert_eq!(packet.destination, destination(index, false));
            assert_eq!(packet.source, Some(source(remote)));
            assert_eq!(packet.payload.as_ref(), payload(index, false).as_slice());
            packets.send(Datagram { payload: Bytes::from(payload(index, true)), source: Some(destination(index, true)), destination: source(remote) }).await?;
            self.seen.send(Observation { index, remote }).map_err(|_| Error::Closed)?;
            position += 1;
        }
        Ok(())
    }
}

// Own both accept and dispatch tasks; cancellation or a failed assertion drops
// the listener/JoinSet and cannot leave a detached UDP bridge running.
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
    async fn finish(mut self) {
        self.0.as_mut().unwrap().await.unwrap().unwrap();
        let _ = self.0.take();
    }
}

#[tokio::test]
#[ignore = "selected Linux live gate requires XRAY_SS2022_GO_PEER; run with --ignored and require both tests to execute"]
async fn rust_outbound_trait_to_pinned_go_udp_handlers_single_and_eih() {
    let mut completed = 0;
    for scenario in SCENARIOS {
        tokio::time::timeout(SESSION_LIMIT, async {
            let mut peer = Peer::spawn("server", "127.0.0.1:0".parse().unwrap(), scenario);
            let ready = peer.event("ready", "handler", 0, 0).await;
            assert!(ready.peer.is_empty());
            // Endpoint metadata stays TCP; the actual trait selects UDP.
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("rust-live", Destination::from(ready.address), scenario.config("tcp")).unwrap());
            let mut context = SessionContext::new("live", destination(0, false));
            context.source = Some("198.51.100.90:41000".parse().unwrap());
            let logical = udp("192.0.2.90:42000");
            let packets = client.connect_datagram(&context).await.unwrap();
            for index in 0..PACKETS {
                packets.send(Datagram { payload: Bytes::from(payload(index, false)), source: (index == 0).then(|| logical.clone()), destination: destination(index, false) }).await.unwrap();
                let response = packets.recv().await.unwrap().expect("empty packet must not be treated as closure");
                assert_eq!(response.payload.as_ref(), payload(index, true).as_slice());
                assert_eq!(response.source, Some(destination(index, true)));
                assert_eq!(response.destination, logical);
            }
            let complete = peer.event("complete", "handler", PACKETS, 1).await;
            assert_eq!(complete.address, ready.address);
            let physical = complete.peer.parse::<SocketAddr>().unwrap();
            assert!(physical.ip().is_loopback());
            assert_ne!(physical.port(), 0);
            assert_ne!(source(physical), logical);
            let pending = packets.recv();
            tokio::pin!(pending);
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut pending).await.is_err());
            client.close().await.unwrap();
            assert!(pending.await.unwrap().is_none());
            assert!(matches!(packets.send(Datagram::new(Bytes::new(), destination(0, false)).unwrap()).await, Err(Error::Closed)));
            assert!(matches!(client.connect_datagram(&context).await, Err(Error::Closed)));
            packets.close().await.unwrap();
            packets.close().await.unwrap();
            peer.finish("handler", 1, ready.address).await;
            let rebound = UdpSocket::bind(ready.address).await.unwrap();
            drop(rebound);
        }).await.unwrap_or_else(|_| panic!("Rust trait -> pinned Go handler timed out: {scenario:?}"));
        completed += 1;
    }
    assert_eq!(completed, 5, "all three single-user and both AES EIH configurations must run");
}

#[tokio::test]
#[ignore = "selected Linux live gate requires XRAY_SS2022_GO_PEER; run with --ignored and require both tests to execute"]
async fn pinned_go_udp_client_and_empty_sessions_to_rust_native_traits() {
    let mut completed = 0;
    for scenario in SCENARIOS {
        tokio::time::timeout(SESSION_LIMIT, async {
            let inbound = scenario.inbound();
            let listener = inbound.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().expect("UDP configuration must select the native boundary");
            let address = listener.local_addr().unwrap();
            let (started, mut flows) = mpsc::unbounded_channel();
            let (seen, mut observations) = mpsc::unbounded_channel();
            let running = Running::start(listener, Arc::new(Respond { started, seen }));
            let mut peer = Peer::spawn("client", address, scenario);
            let ready = peer.event("ready", "handler", 0, 1).await;
            let handler = flows.recv().await.unwrap();
            assert_eq!(handler.session.source, Some(ready.address));
            assert_eq!(handler.session.destination, destination(1, false));
            for &index in HANDLER_CASES {
                let observed = observations.recv().await.unwrap();
                assert_eq!(observed.index, index);
                assert_eq!(observed.remote, ready.address);
            }
            let done = peer.event("handler_complete", "handler", 4, 1).await;
            assert_eq!(done.address, ready.address);
            let closed = peer.event("handler_closed", "handler", 4, 1).await;
            assert_eq!(closed.address, ready.address);
            let empty = peer.event("empty_ready", "session", 0, 1).await;
            let session = flows.recv().await.unwrap();
            assert_eq!(session.session.source, Some(empty.address));
            assert_eq!(session.session.destination, destination(0, false));
            assert!(!Arc::ptr_eq(&handler.packets, &session.packets));
            for &index in EMPTY_CASES {
                let observed = observations.recv().await.unwrap();
                assert_eq!(observed.index, index);
                assert_eq!(observed.remote, empty.address);
            }
            let done = peer.event("complete", "handler+session", PACKETS, 2).await;
            assert_eq!(done.address, empty.address);
            peer.finish("handler+session", 2, empty.address).await;
            assert!(observations.try_recv().is_err());
            assert!(flows.try_recv().is_err());
            inbound.close().await.unwrap();
            running.finish().await;
            let retained = [handler, session];
            for flow in &retained {
                assert!(flow.packets.recv().await.unwrap().is_none());
                assert!(matches!(flow.packets.send(Datagram { payload: Bytes::new(), source: Some(destination(0, true)), destination: source(flow.session.source.unwrap()) }).await, Err(Error::Closed)));
                flow.packets.close().await.unwrap();
            }
            // Retained native transports above must not retain the bound socket.
            let rebound = UdpSocket::bind(address).await.unwrap();
            drop(rebound);
            drop(retained);
        }).await.unwrap_or_else(|_| panic!("Pinned Go -> Rust native traits timed out: {scenario:?}"));
        completed += 1;
    }
    assert_eq!(completed, 5, "all three single-user and both AES EIH configurations must run");
}
