//! Linux G3 live gate; the parent owns module/workflow registration.
//! Build: bash testing/shadowsocks-reference/build-peer.sh GO_REFERENCE_ROOT BINARY
//! Set XRAY_SS_CLASSIC_GO_PEER=BINARY and select this module with --ignored.
//! All five grouped tests must execute. Missing/empty/unusable helpers fail hard.
//! Go uses core constructors and Client/Server.Process for TCP and nonempty UDP.
//! Only two Go-client empty UDP pairs use exported UDPWriter/UDPReader directly:
//! the pinned Client.Process generic buf.Copy drops zero-length MultiBuffers.
//! Four methods: 12 TCP pairs per direction, 48 Rust->Go UDP pairs (two source
//! fallbacks), 24 Go->Rust UDP pairs, plus eight wrong-password TCP attempts.
use std::{
    net::SocketAddr, path::PathBuf, process::Stdio,
    sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration,
};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UdpSocket}, process::{Child, ChildStdout, Command},
    sync::mpsc, task::{JoinHandle, JoinSet},
};
use crate::{
    common::{
        errors::{Error, Result},
        net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram}},
        protocol::{SessionContext, User},
    },
    features::{inbound::{InboundDispatcher, InboundHandler, NativeInboundListener}, outbound::OutboundHandler},
};
use super::{Client, Server};

const REFERENCE: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const PASSWORD: &str = "classic-live-password";
const WRONG_PASSWORD: &str = "wrong-classic-live-password";
const EMAIL: &str = "classic-live@example.invalid";
const LIMIT: Duration = Duration::from_secs(30);
const MAX_EVENT_BYTES: usize = 4096;
const METHODS: [&str; 4] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"];
const TCP_COUNT: usize = 3;
const UDP_COUNT: usize = 6;
const GREETING: usize = 16;
const HANDLER_CASES: &[usize] = &[1, 2, 3, 4];
const EMPTY_CASES: &[usize] = &[0, 5];

fn destination(index: usize, reply: bool, network: Network) -> Destination {
    let addresses = if reply {
        ["[2001:db8::50]:9443", "198.51.100.70:5354", "response.example.invalid:9002",
         "[2001:db8::51]:8444", "last.example.invalid:9003", "empty-reply.example.invalid:5354"]
    } else {
        ["empty.example.invalid:443", "203.0.113.7:5353", "[2001:db8::7]:9000",
         "large.example.invalid:8443", "198.51.100.8:9001", "[2001:db8::8]:5353"]
    };
    Destination::parse_str(addresses[index], network).unwrap()
}
fn source(address: SocketAddr) -> Destination { Destination::udp(address.ip().into(), address.port()) }
fn payload(index: usize, reply: bool, network: Network) -> Vec<u8> {
    let (sizes, salt): (&[usize], usize) = match (network, reply) {
        (Network::Tcp, false) => (&[1, 16641, 50000], 0x31),
        (Network::Tcp, true) => (&[257, 17000, 49000], 0xa7),
        (Network::Udp, false) => (&[0, 1, 257, 7900, 19, 0], 0x31),
        (Network::Udp, true) => (&[0, 19, 513, 7800, 1, 0], 0xa7),
    };
    (0..sizes[index]).map(|i| (i * 73 + i / 251 + salt + index * 17) as u8).collect()
}
fn inbound(method: &str, password: &str, tcp: bool) -> Arc<dyn InboundHandler> {
    // TCP uses the co-bound native listener; its companion UDP socket is idle.
    Arc::new(Server::try_new("rust-live", method, password).unwrap()
        .with_networks(tcp, true).unwrap()
        .with_user(User::with_email(uuid::Uuid::nil(), EMAIL, 7)))
}
fn check_session(session: &SessionContext) -> SocketAddr {
    assert_eq!(session.inbound_tag, "rust-live");
    assert_eq!(session.user.as_ref().unwrap().email, EMAIL);
    assert_eq!(session.user.as_ref().unwrap().level, 7);
    let remote = session.source.expect("native dispatch must preserve the physical Go source socket");
    assert!(remote.ip().is_loopback());
    assert_ne!(remote.port(), 0);
    remote
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    event: String, source: String, mode: String, network: String, method: String,
    path: String, address: SocketAddr, peer: String, exchanges: usize, sessions: usize,
}
struct Peer {
    child: Child, output: BufReader<ChildStdout>, mode: &'static str,
    network: Network, method: &'static str, endpoint: SocketAddr,
}
impl Peer {
    fn spawn(mode: &'static str, network: Network, method: &'static str, endpoint: SocketAddr, reject: bool) -> Self {
        assert_eq!(std::env::consts::OS, "linux", "selected classic Go live tests must run on Linux");
        let executable = std::env::var_os("XRAY_SS_CLASSIC_GO_PEER")
            .expect("selected classic live tests require XRAY_SS_CLASSIC_GO_PEER built from the pinned Go module on Linux");
        assert!(!executable.is_empty(), "XRAY_SS_CLASSIC_GO_PEER must not be empty");
        let executable = PathBuf::from(executable);
        assert!(executable.is_file(), "XRAY_SS_CLASSIC_GO_PEER must name an existing binary: {}", executable.display());
        let executable = executable.canonicalize().expect("resolve the classic Go peer binary path");
        let address = endpoint.to_string();
        let mut command = Command::new(executable);
        command.args(["--mode", mode, "--network", network.as_str(), "--method", method, "--address", &address])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
        if reject { command.arg("--expect-rejected"); }
        let mut child = command.spawn().expect("start pinned classic Go peer");
        let output = BufReader::new(child.stdout.take().unwrap());
        Self { child, output, mode, network, method, endpoint }
    }
    async fn event(&mut self, kind: &str, path: &str, exchanges: usize, sessions: usize) -> Event {
        // Bound a line before allocating it, including an unterminated line.
        let mut line = Vec::new();
        loop {
            let available = self.output.fill_buf().await.unwrap();
            assert!(!available.is_empty(), "Go peer exited before {kind}: {} {} {}", self.mode, self.network, self.method);
            let length = available.iter().position(|byte| *byte == b'\n').map_or(available.len(), |position| position + 1);
            assert!(line.len() + length <= MAX_EVENT_BYTES, "Go stdout JSON line exceeded its bound");
            line.extend_from_slice(&available[..length]);
            self.output.consume(length);
            if line.last() == Some(&b'\n') { break; }
        }
        let event: Event = serde_json::from_slice(&line).expect("Go stdout must contain only strict JSON event lines");
        assert_eq!(event.event, kind);
        assert_eq!(event.source, REFERENCE);
        assert_eq!(event.mode, self.mode);
        assert_eq!(event.network, self.network.as_str());
        assert_eq!(event.method, self.method);
        assert_eq!(event.path, path);
        assert_eq!(event.exchanges, exchanges);
        assert_eq!(event.sessions, sessions);
        assert!(event.address.ip().is_loopback());
        assert_ne!(event.address.port(), 0);
        if self.mode == "client" {
            assert_eq!(event.peer.parse::<SocketAddr>().unwrap(), self.endpoint);
        } else if kind == "ready" {
            assert!(event.peer.is_empty());
            self.endpoint = event.address;
        } else {
            assert_eq!(event.address, self.endpoint);
            let remote = event.peer.parse::<SocketAddr>().unwrap();
            assert!(remote.ip().is_loopback());
            assert_ne!(remote.port(), 0);
        }
        event
    }
    async fn finish(mut self, path: &str, exchanges: usize, sessions: usize, address: SocketAddr) {
        self.child.stdin.take().unwrap().write_all(b"exit\n").await.unwrap();
        assert_eq!(self.event("closed", path, exchanges, sessions).await.address, address);
        assert!(self.child.wait().await.unwrap().success(), "pinned classic Go peer failed");
        let mut trailing = [0];
        assert_eq!(self.output.read(&mut trailing).await.unwrap(), 0, "unexpected trailing Go stdout");
    }
}

struct Observation { index: usize, remote: SocketAddr }
struct Flow { packets: BoxDatagram, session: SessionContext }
struct TcpRespond { seen: mpsc::Sender<Observation> }
#[async_trait]
impl InboundDispatcher for TcpRespond {
    async fn dispatch_stream(&self, mut stream: BoxStream, session: SessionContext) -> Result<()> {
        let remote = check_session(&session);
        let index = (0..TCP_COUNT).find(|&i| session.destination == destination(i, false, Network::Tcp))
            .expect("unexpected native TCP target");
        let expected = payload(index, false, Network::Tcp);
        let response = payload(index, true, Network::Tcp);
        stream.write_all(&response[..GREETING]).await?;
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await?;
        assert_eq!(received, expected);
        for chunk in response[GREETING..].chunks(997) { stream.write_all(chunk).await?; }
        stream.shutdown().await?;
        let mut extra = [0];
        assert_eq!(stream.read(&mut extra).await?, 0, "extra TCP request bytes");
        self.seen.send(Observation { index, remote }).await.map_err(|_| Error::Closed)?;
        Ok(())
    }
}
struct UdpRespond { started: mpsc::Sender<Flow>, seen: mpsc::Sender<Observation> }
#[async_trait]
impl InboundDispatcher for UdpRespond {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> {
        Err(Error::Unsupported("UDP live scenario received a stream".into()))
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        let remote = check_session(&session);
        self.started.send(Flow { packets: packets.clone(), session: session.clone() }).await.map_err(|_| Error::Closed)?;
        let mut cases: &[usize] = &[];
        let mut position = 0;
        while let Some(packet) = packets.recv().await? {
            if position == 0 {
                cases = if packet.destination == destination(1, false, Network::Udp) { HANDLER_CASES } else { EMPTY_CASES };
                assert_eq!(session.destination, packet.destination);
            }
            assert!(position < cases.len(), "extra packet in native Go-client flow");
            let index = cases[position];
            assert_eq!(packet.destination, destination(index, false, Network::Udp));
            assert_eq!(packet.source, Some(source(remote)));
            assert_eq!(packet.payload.as_ref(), payload(index, false, Network::Udp).as_slice());
            packets.send(Datagram {
                payload: Bytes::from(payload(index, true, Network::Udp)),
                source: Some(destination(index, true, Network::Udp)), destination: source(remote),
            }).await?;
            self.seen.send(Observation { index, remote }).await.map_err(|_| Error::Closed)?;
            position += 1;
        }
        Ok(())
    }
}

// Own the accept loop and every returned task; failure/timeout aborts children.
struct Running(Option<JoinHandle<Result<()>>>);
impl Drop for Running { fn drop(&mut self) { if let Some(task) = &self.0 { task.abort(); } } }
impl Running {
    fn start(mut listener: Box<dyn NativeInboundListener>, dispatcher: Arc<dyn InboundDispatcher>) -> Self {
        Self(Some(tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept(dispatcher.clone()) => match accepted {
                        Ok(task) => {
                            assert!(children.len() < 8, "unexpected excess native live tasks");
                            let _ = children.spawn(task);
                        }
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
async fn rebind_native(address: SocketAddr, tcp: bool) {
    let udp = UdpSocket::bind(address).await.expect("native UDP socket must be released");
    let listener = if tcp { Some(TcpListener::bind(address).await.expect("native TCP listener must be released")) } else { None };
    drop(listener);
    drop(udp);
}

#[tokio::test]
#[ignore = "Linux G3 requires XRAY_SS_CLASSIC_GO_PEER; select --ignored and execute all five groups"]
async fn rust_outbound_traits_to_pinned_go_tcp_server_process_all_methods() {
    let mut completed = 0;
    for method in METHODS {
        tokio::time::timeout(LIMIT, async {
            let mut peer = Peer::spawn("server", Network::Tcp, method, "127.0.0.1:0".parse().unwrap(), false);
            let ready = peer.event("ready", "handler", 0, 0).await;
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("rust-live", ready.address.into(), method, PASSWORD).unwrap());
            for index in 0..TCP_COUNT {
                let session = SessionContext::new("live", destination(index, false, Network::Tcp));
                let mut stream = client.connect(&session).await.unwrap();
                let expected = payload(index, true, Network::Tcp);
                let mut greeting = [0; GREETING];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting.as_slice(), &expected[..GREETING], "Go must respond before Rust application payload");
                for chunk in payload(index, false, Network::Tcp).chunks(997) { stream.write_all(chunk).await.unwrap(); }
                // Receive the rest of the response after the request half-close.
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.take((expected.len() - GREETING + 1) as u64).read_to_end(&mut response).await.unwrap();
                assert_eq!(response.as_slice(), &expected[GREETING..]);
                let event = peer.event("session_complete", "handler", index + 1, index + 1).await;
                assert_eq!(event.address, ready.address);
            }
            let done = peer.event("complete", "handler", TCP_COUNT, TCP_COUNT).await;
            assert_eq!(done.address, ready.address);
            client.close().await.unwrap();
            assert!(matches!(client.connect(&SessionContext::new("live", destination(0, false, Network::Tcp))).await, Err(Error::Closed)));
            peer.finish("handler", TCP_COUNT, TCP_COUNT, ready.address).await;
            drop(TcpListener::bind(ready.address).await.expect("Go TCP listener must be released"));
        }).await.unwrap_or_else(|_| panic!("Rust outbound -> Go TCP Server.Process timed out: {method}"));
        completed += 1;
    }
    assert_eq!(completed, METHODS.len());
}

#[tokio::test]
#[ignore = "Linux G3 requires XRAY_SS_CLASSIC_GO_PEER; select --ignored and execute all five groups"]
async fn pinned_go_tcp_client_process_to_rust_native_traits_all_methods() {
    let mut completed = 0;
    for method in METHODS {
        tokio::time::timeout(LIMIT, async {
            let server = inbound(method, PASSWORD, true);
            let listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().expect("native co-binding is required");
            let address = listener.local_addr().unwrap();
            let (seen, mut observations) = mpsc::channel(8);
            let running = Running::start(listener, Arc::new(TcpRespond { seen }));
            let mut peer = Peer::spawn("client", Network::Tcp, method, address, false);
            let ready = peer.event("ready", "handler", 0, 1).await;
            let mut sources = Vec::new();
            for index in 0..TCP_COUNT {
                let event = peer.event("session_complete", "handler", index + 1, index + 1).await;
                if index == 0 { assert_eq!(event.address, ready.address); }
                sources.push(event.address);
            }
            let done = peer.event("complete", "handler", TCP_COUNT, TCP_COUNT).await;
            assert_eq!(done.address, sources[TCP_COUNT - 1]);
            let mut observed = Vec::new();
            for _ in 0..TCP_COUNT { observed.push(observations.recv().await.unwrap()); }
            observed.sort_by_key(|observation| observation.index);
            for (index, observation) in observed.iter().enumerate() {
                assert_eq!(observation.index, index);
                assert_eq!(observation.remote, sources[index]);
            }
            assert!(observations.try_recv().is_err());
            peer.finish("handler", TCP_COUNT, TCP_COUNT, done.address).await;
            server.close().await.unwrap();
            running.finish().await;
            rebind_native(address, true).await;
        }).await.unwrap_or_else(|_| panic!("Go TCP Client.Process -> Rust native timed out: {method}"));
        completed += 1;
    }
    assert_eq!(completed, METHODS.len());
}

#[tokio::test]
#[ignore = "Linux G3 requires XRAY_SS_CLASSIC_GO_PEER; select --ignored and execute all five groups"]
async fn rust_outbound_traits_to_pinned_go_udp_server_process_all_methods() {
    let mut completed = 0;
    for method in METHODS {
        for session_source in [None, Some("198.51.100.90:41000".parse::<SocketAddr>().unwrap())] {
            tokio::time::timeout(LIMIT, async {
                let mut peer = Peer::spawn("server", Network::Udp, method, "127.0.0.1:0".parse().unwrap(), false);
                let ready = peer.event("ready", "handler", 0, 0).await;
                let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("rust-live", ready.address.into(), method, PASSWORD).unwrap());
                let mut session = SessionContext::new("live", destination(0, false, Network::Udp));
                session.source = session_source;
                let logical = source("192.0.2.90:42000".parse().unwrap());
                let packets = client.connect_datagram(&session).await.unwrap();
                let mut fallback_destinations = Vec::new();
                for index in 0..UDP_COUNT {
                    packets.send(Datagram {
                        payload: Bytes::from(payload(index, false, Network::Udp)),
                        source: (index == 3).then(|| logical.clone()), destination: destination(index, false, Network::Udp),
                    }).await.unwrap();
                    let response = packets.recv().await.unwrap().expect("an empty authenticated UDP packet is not EOF");
                    assert_eq!(response.payload.as_ref(), payload(index, true, Network::Udp).as_slice());
                    assert_eq!(response.source, Some(destination(index, true, Network::Udp)));
                    if index < 3 { fallback_destinations.push(response.destination); } else { assert_eq!(response.destination, logical); }
                    if index == 3 {
                        assert!(matches!(packets.send(Datagram {
                            payload: Bytes::from_static(b"mixed local source"),
                            source: Some(source("192.0.2.90:42001".parse().unwrap())), destination: destination(index, false, Network::Udp),
                        }).await, Err(Error::Protocol(_))));
                    }
                }
                let done = peer.event("complete", "handler", UDP_COUNT, 1).await;
                let physical = done.peer.parse::<SocketAddr>().unwrap();
                assert_ne!(source(physical), logical);
                for destination in fallback_destinations { assert_eq!(destination, source(session_source.unwrap_or(physical))); }
                let pending = packets.recv();
                tokio::pin!(pending);
                assert!(tokio::time::timeout(Duration::from_millis(10), &mut pending).await.is_err());
                client.close().await.unwrap();
                assert!(pending.await.unwrap().is_none());
                assert!(matches!(packets.send(Datagram { payload: Bytes::new(), source: None, destination: destination(0, false, Network::Udp) }).await, Err(Error::Closed)));
                assert!(matches!(client.connect_datagram(&session).await, Err(Error::Closed)));
                packets.close().await.unwrap();
                packets.close().await.unwrap();
                drop(UdpSocket::bind(physical).await.expect("retained outbound transport must release its socket"));
                peer.finish("handler", UDP_COUNT, 1, ready.address).await;
                drop(UdpSocket::bind(ready.address).await.expect("Go UDP listener must be released"));
            }).await.unwrap_or_else(|_| panic!("Rust outbound -> Go UDP Server.Process timed out: {method}, source={session_source:?}"));
            completed += 1;
        }
    }
    assert_eq!(completed, METHODS.len() * 2);
}

#[tokio::test]
#[ignore = "Linux G3 requires XRAY_SS_CLASSIC_GO_PEER; select --ignored and execute all five groups"]
async fn pinned_go_udp_client_process_and_empty_sessions_to_rust_native_traits_all_methods() {
    let mut completed = 0;
    for method in METHODS {
        tokio::time::timeout(LIMIT, async {
            let server = inbound(method, PASSWORD, false);
            let listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().expect("native UDP is required");
            let address = listener.local_addr().unwrap();
            let (started, mut flows) = mpsc::channel(4);
            let (seen, mut observations) = mpsc::channel(8);
            let running = Running::start(listener, Arc::new(UdpRespond { started, seen }));
            let mut peer = Peer::spawn("client", Network::Udp, method, address, false);
            let ready = peer.event("ready", "handler", 0, 1).await;
            let handler = flows.recv().await.unwrap();
            assert_eq!(handler.session.source, Some(ready.address));
            assert_eq!(handler.session.destination, destination(1, false, Network::Udp));
            for &index in HANDLER_CASES {
                let observed = observations.recv().await.unwrap();
                assert_eq!(observed.index, index);
                assert_eq!(observed.remote, ready.address);
            }
            assert_eq!(peer.event("handler_complete", "handler", HANDLER_CASES.len(), 1).await.address, ready.address);
            assert_eq!(peer.event("handler_closed", "handler", HANDLER_CASES.len(), 1).await.address, ready.address);
            let empty = peer.event("empty_ready", "session", 0, 1).await;
            assert_ne!(empty.address, ready.address, "handler and direct empty-session flows must be distinct");
            let session = flows.recv().await.unwrap();
            assert_eq!(session.session.source, Some(empty.address));
            assert_eq!(session.session.destination, destination(0, false, Network::Udp));
            assert!(!Arc::ptr_eq(&handler.packets, &session.packets));
            for &index in EMPTY_CASES {
                let observed = observations.recv().await.unwrap();
                assert_eq!(observed.index, index);
                assert_eq!(observed.remote, empty.address);
            }
            let done = peer.event("complete", "handler+session", UDP_COUNT, 2).await;
            assert_eq!(done.address, empty.address);
            peer.finish("handler+session", UDP_COUNT, 2, empty.address).await;
            assert!(observations.try_recv().is_err());
            assert!(flows.try_recv().is_err());
            server.close().await.unwrap();
            running.finish().await;
            let retained = [handler, session];
            for flow in &retained {
                assert!(flow.packets.recv().await.unwrap().is_none());
                assert!(matches!(flow.packets.send(Datagram {
                    payload: Bytes::new(), source: Some(destination(0, true, Network::Udp)), destination: source(flow.session.source.unwrap()),
                }).await, Err(Error::Closed)));
                flow.packets.close().await.unwrap();
            }
            rebind_native(address, false).await;
            drop(retained);
        }).await.unwrap_or_else(|_| panic!("Go UDP Client.Process and empty APIs -> Rust native timed out: {method}"));
        completed += 1;
    }
    assert_eq!(completed, METHODS.len());
}

struct RejectDispatch(AtomicUsize);
#[async_trait]
impl InboundDispatcher for RejectDispatch {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(Error::Protocol("wrong-password TCP reached native dispatch".into()))
    }
    async fn dispatch_datagrams(&self, _packets: BoxDatagram, _session: SessionContext) -> Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(Error::Protocol("wrong-password test unexpectedly dispatched UDP".into()))
    }
}

#[tokio::test]
#[ignore = "Linux G3 requires XRAY_SS_CLASSIC_GO_PEER; select --ignored and execute all five groups"]
async fn pinned_go_tcp_wrong_password_is_rejected_both_directions_all_methods() {
    let mut completed = 0;
    for method in METHODS {
        tokio::time::timeout(LIMIT, async {
            let mut peer = Peer::spawn("server", Network::Tcp, method, "127.0.0.1:0".parse().unwrap(), true);
            let ready = peer.event("ready", "handler", 0, 0).await;
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("rust-live", ready.address.into(), method, WRONG_PASSWORD).unwrap());
            match client.connect(&SessionContext::new("live", destination(0, false, Network::Tcp))).await {
                Ok(mut stream) => {
                    // Satisfy the pinned Go probing drain without implementing it.
                    // A write/reset error is permitted only in this rejection case.
                    let _ = stream.write_all(&[0x99; 4096]).await;
                    let _ = stream.shutdown().await;
                    let mut plaintext = [0];
                    match stream.read(&mut plaintext).await {
                        Ok(0) | Err(_) => {}
                        Ok(_) => panic!("wrong-password Go server returned application plaintext"),
                    }
                }
                Err(error) => assert!(matches!(error, Error::Io(_)), "unexpected local failure: {error}"),
            }
            let rejected = peer.event("rejected", "handler", 0, 1).await;
            assert_eq!(rejected.address, ready.address);
            client.close().await.unwrap();
            peer.finish("handler", 0, 1, ready.address).await;
            drop(TcpListener::bind(ready.address).await.expect("negative Go TCP listener must be released"));
        }).await.unwrap_or_else(|_| panic!("Rust wrong password -> Go production handler timed out: {method}"));
        completed += 1;
        tokio::time::timeout(LIMIT, async {
            let server = inbound(method, WRONG_PASSWORD, true);
            let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let dispatch = Arc::new(RejectDispatch(AtomicUsize::new(0)));
            let mut peer = Peer::spawn("client", Network::Tcp, method, address, true);
            let ready = peer.event("ready", "handler", 0, 1).await;
            let task = listener.accept(dispatch.clone()).await.unwrap();
            let rejection = task.await;
            assert!(matches!(rejection, Err(Error::Io(_))), "expected native authentication IO error, got {rejection:?}");
            assert_eq!(dispatch.0.load(Ordering::Relaxed), 0);
            assert_eq!(peer.event("rejected", "handler", 0, 1).await.address, ready.address);
            peer.finish("handler", 0, 1, ready.address).await;
            server.close().await.unwrap();
            drop(listener);
            rebind_native(address, true).await;
        }).await.unwrap_or_else(|_| panic!("Go wrong password -> Rust native handler timed out: {method}"));
        completed += 1;
    }
    assert_eq!(completed, METHODS.len() * 2);
}
