//! Native, packet-preserving UDP boundary around the reviewed session engine.
use std::{collections::{HashMap, HashSet}, io, net::SocketAddr, pin::Pin, sync::{Arc, Mutex, Weak}, task::{Context, Poll}, time::Duration};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, net::{TcpListener, TcpStream, UdpSocket}, sync::{mpsc, Mutex as AsyncMutex}, time::Instant};
use tokio_util::sync::CancellationToken;
use crate::{common::{errors::{Error, Result}, net::{Destination, Network, datagram::{Datagram, DatagramTransport}}, protocol::SessionContext}, features::inbound::{InboundDispatcher, InboundHandler, InboundTask, NativeInboundListener}};
use super::{config::Networks, packet::MAX_DATAGRAM_SIZE, udp_session::{InboundDatagram, ReplyToken}};

const MAX_FLOWS: usize = 256;
const FLOW_QUEUE: usize = 32;
const MAX_PEER_ADDRESSES: usize = 64;
const SESSION_IDLE: Duration = Duration::from_secs(500);

pub(super) trait PacketServer: InboundHandler {
    fn decode(&self, wire: &[u8], remote: SocketAddr) -> Result<InboundDatagram>;
    fn reply(&self, token: &ReplyToken, source: Destination, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>)>;
}

#[derive(Default)]
pub(super) struct NativeState {
    cancelled: CancellationToken,
    listeners: Mutex<Vec<Weak<Bindings>>>,
}
impl NativeState {
    pub fn close(&self) {
        self.cancelled.cancel();
        let mut listeners = self.listeners.lock().unwrap_or_else(|error| error.into_inner());
        for bindings in listeners.drain(..).filter_map(|weak| weak.upgrade()) { bindings.stop(); }
    }
}

struct Bindings {
    udp: Mutex<Option<Arc<UdpSocket>>>,
    tcp: Mutex<Option<Arc<TcpListener>>>,
    cancelled: CancellationToken,
    connections: Mutex<Vec<Weak<TcpChild>>>,
}
impl Bindings {
    fn stop(&self) {
        self.cancelled.cancel();
        self.udp.lock().unwrap_or_else(|error| error.into_inner()).take();
        self.tcp.lock().unwrap_or_else(|error| error.into_inner()).take();
        for connection in self.connections.lock().unwrap_or_else(|error| error.into_inner()).drain(..).filter_map(|weak| weak.upgrade()) {
            connection.0.lock().unwrap_or_else(|error| error.into_inner()).take();
        }
    }
    fn udp(&self) -> Result<Arc<UdpSocket>> {
        self.udp.lock().map_err(|_| Error::Other("SS2022 UDP socket lock poisoned".into()))?.clone().ok_or(Error::Closed)
    }
}

// Accepted streams can sit in an unpolled InboundTask. Keep a weak registry so
// closing the listener also closes those child sockets immediately.
struct TcpChild(Mutex<Option<TcpStream>>);
struct ChildStream(Arc<TcpChild>);
impl AsyncRead for ChildStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
        match socket.as_mut() { Some(socket) => Pin::new(socket).poll_read(cx, buffer), None => Poll::Ready(Ok(())) }
    }
}
impl AsyncWrite for ChildStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let mut socket = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
        match socket.as_mut() { Some(socket) => Pin::new(socket).poll_write(cx, buffer), None => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "SS2022 listener closed"))) }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
        match socket.as_mut() { Some(socket) => Pin::new(socket).poll_flush(cx), None => Poll::Ready(Ok(())) }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut socket = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
        match socket.as_mut() { Some(socket) => Pin::new(socket).poll_shutdown(cx), None => Poll::Ready(Ok(())) }
    }
}

pub(super) async fn bind<S: PacketServer + 'static>(server: S, networks: Networks, state: &NativeState, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
    let Some((bindings, address)) = bind_sockets(networks, state, address).await? else { return Ok(None); };
    Ok(Some(Box::new(Listener { server: Arc::new(server), bindings, address, flows: HashMap::new(), sweep: tokio::time::interval(Duration::from_secs(30)) })))
}

async fn bind_sockets(networks: Networks, state: &NativeState, address: SocketAddr) -> Result<Option<(Arc<Bindings>, SocketAddr)>> {
    if state.cancelled.is_cancelled() { return Err(Error::Closed); }
    if !networks.udp { return Ok(None); }
    // Bind both sockets before returning. Failure to bind UDP drops the TCP
    // listener too; port zero must choose one shared port, not two random ports.
    let tcp = if networks.tcp { Some(Arc::new(TcpListener::bind(address).await?)) } else { None };
    let address = match &tcp { Some(listener) => listener.local_addr()?, None => address };
    let udp = UdpSocket::bind(address).await?;
    let address = udp.local_addr()?;
    let bindings = Arc::new(Bindings { udp: Mutex::new(Some(Arc::new(udp))), tcp: Mutex::new(tcp), cancelled: state.cancelled.child_token(), connections: Mutex::new(Vec::new()) });
    {
        let mut listeners = state.listeners.lock().map_err(|_| Error::Other("SS2022 listener lock poisoned".into()))?;
        if state.cancelled.is_cancelled() { bindings.stop(); return Err(Error::Closed); }
        listeners.retain(|listener| listener.strong_count() != 0);
        listeners.push(Arc::downgrade(&bindings));
    }
    Ok(Some((bindings, address)))
}

struct Flow {
    token: ReplyToken,
    sender: mpsc::Sender<Datagram>,
    peers: Arc<Mutex<HashSet<Destination>>>,
    cancelled: CancellationToken,
    active: Instant,
}
impl Drop for Flow { fn drop(&mut self) { self.cancelled.cancel(); } }

struct Listener {
    server: Arc<dyn PacketServer>,
    bindings: Arc<Bindings>,
    address: SocketAddr,
    flows: HashMap<u64, Flow>,
    sweep: tokio::time::Interval,
}
impl Drop for Listener { fn drop(&mut self) { self.bindings.stop(); } }
impl Listener {
    fn expire(&mut self) {
        self.flows.retain(|_, flow| !flow.cancelled.is_cancelled() && !flow.sender.is_closed() && flow.active.elapsed() < SESSION_IDLE);
    }
    fn incoming(&mut self, incoming: InboundDatagram, dispatcher: Arc<dyn InboundDispatcher>) -> Result<Option<InboundTask>> {
        self.expire();
        let id = incoming.packet.session_id;
        if self.flows.get(&id).is_some_and(|flow| !flow.token.same_session(&incoming.reply)) { self.flows.remove(&id); }
        let peer = udp_destination(incoming.remote);
        let packet = Datagram { payload: Bytes::from(incoming.packet.payload), source: Some(peer.clone()), destination: incoming.packet.destination };
        if let Some(flow) = self.flows.get_mut(&id) {
            {
                let mut peers = flow.peers.lock().map_err(|_| Error::Other("SS2022 peer lock poisoned".into()))?;
                if peers.len() >= MAX_PEER_ADDRESSES && !peers.contains(&peer) { return Ok(None); }
                peers.insert(peer);
            }
            flow.active = Instant::now();
            // A congested client may lose whole UDP packets, but cannot block
            // acceptance of another client's session or a TCP handshake.
            let _ = flow.sender.try_send(packet);
            return Ok(None);
        }
        if self.flows.len() >= MAX_FLOWS { return Ok(None); }
        let mut session = SessionContext::new(self.server.tag(), packet.destination.clone());
        session.source = Some(incoming.remote);
        session.user = incoming.user;
        let (sender, receiver) = mpsc::channel(FLOW_QUEUE);
        sender.try_send(packet).map_err(|_| Error::Closed)?;
        let cancelled = self.bindings.cancelled.child_token();
        let peers = Arc::new(Mutex::new(HashSet::from([peer])));
        let transport = Arc::new(IncomingPackets { server: self.server.clone(), bindings: self.bindings.clone(), token: incoming.reply.clone(), peers: peers.clone(), receiver: AsyncMutex::new(receiver), cancelled: cancelled.clone() });
        self.flows.insert(id, Flow { token: incoming.reply, sender, peers, cancelled: cancelled.clone(), active: Instant::now() });
        // Construct the guard outside the async block: dropping an unpolled
        // task must cancel the route just as dropping a running task does.
        let guard = CancelOnDrop(cancelled.clone());
        Ok(Some(Box::pin(async move {
            let _guard = guard;
            tokio::select! {
                biased;
                _ = cancelled.cancelled() => Ok(()),
                result = dispatcher.dispatch_datagrams(transport, session) => result,
            }
        })))
    }
}
#[async_trait]
impl NativeInboundListener for Listener {
    fn local_addr(&self) -> Result<SocketAddr> { Ok(self.address) }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let udp = self.bindings.udp()?;
        let tcp = self.bindings.tcp.lock().map_err(|_| Error::Other("SS2022 TCP socket lock poisoned".into()))?.clone();
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
        loop {
            if self.bindings.cancelled.is_cancelled() { return Err(Error::Closed); }
            tokio::select! {
                _ = self.bindings.cancelled.cancelled() => return Err(Error::Closed),
                _ = self.sweep.tick() => self.expire(),
                accepted = async {
                    match &tcp { Some(listener) => listener.accept().await, None => std::future::pending().await }
                } => {
                    let (stream, remote) = accepted?;
                    let stream = Arc::new(TcpChild(Mutex::new(Some(stream))));
                    {
                        let mut connections = self.bindings.connections.lock().map_err(|_| Error::Other("SS2022 TCP child lock poisoned".into()))?;
                        if self.bindings.cancelled.is_cancelled() { return Err(Error::Closed); }
                        connections.retain(|connection| connection.strong_count() != 0);
                        connections.push(Arc::downgrade(&stream));
                    }
                    let stream = ChildStream(stream);
                    let server = self.server.clone();
                    let cancelled = self.bindings.cancelled.clone();
                    return Ok(Box::pin(async move {
                        tokio::select! {
                            biased; _ = cancelled.cancelled() => Ok(()),
                            result = server.dispatch_connection(Box::pin(stream), remote, dispatcher) => result,
                        }
                    }));
                }
                received = udp.recv_from(&mut buffer) => {
                    let (length, remote) = received?;
                    if length > MAX_DATAGRAM_SIZE { continue; }
                    // Malformed, unauthenticated and replayed packets are not
                    // listener errors and cannot create or rebind a flow.
                    let incoming = match self.server.decode(&buffer[..length], remote) {
                        Ok(packet) => packet,
                        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                        Err(error) => return Err(error),
                    };
                    if let Some(task) = self.incoming(incoming, dispatcher.clone())? { return Ok(task); }
                }
            }
        }
    }
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop { fn drop(&mut self) { self.0.cancel(); } }

struct IncomingPackets {
    server: Arc<dyn PacketServer>,
    bindings: Arc<Bindings>,
    token: ReplyToken,
    peers: Arc<Mutex<HashSet<Destination>>>,
    receiver: AsyncMutex<mpsc::Receiver<Datagram>>,
    cancelled: CancellationToken,
}
impl Drop for IncomingPackets { fn drop(&mut self) { self.cancelled.cancel(); } }
#[async_trait]
impl DatagramTransport for IncomingPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Ok(None),
            packet = async { self.receiver.lock().await.recv().await } => Ok(packet),
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.cancelled.is_cancelled() { return Err(Error::Closed); }
        if packet.payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        if !self.peers.lock().map_err(|_| Error::Other("SS2022 peer lock poisoned".into()))?.contains(&packet.destination) {
            return Err(Error::Protocol("SS2022 reply is addressed to another client association".into()));
        }
        let source = packet.source.ok_or_else(|| Error::Protocol("SS2022 UDP reply requires its remote source".into()))?;
        if source.network != Network::Udp { return Err(Error::Protocol("SS2022 UDP reply source must use UDP".into())); }
        let (remote, wire) = self.server.reply(&self.token, source, &packet.payload)?;
        let socket = self.bindings.udp()?;
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(Error::Closed),
            written = socket.send_to(&wire, remote) => {
                if written? != wire.len() { return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short SS2022 UDP response").into()); }
                Ok(())
            }
        }
    }
    async fn close(&self) -> Result<()> { self.cancelled.cancel(); self.receiver.lock().await.close(); Ok(()) }
}

pub(super) fn udp_destination(address: SocketAddr) -> Destination { Destination::udp(address.ip().into(), address.port()) }

// Pinned Go inbound_relay.go caches one link by the original client session ID,
// before rewriting its header. It never decrypts the body or encrypts a reply.
// Keep this separate from PacketServer: endpoint authentication/replay rules
// must not accidentally turn a relay into a terminating SS2022 server.
#[derive(Clone, Copy)]
pub(super) struct RelayLimits {
    pub flows: usize,
    pub queue: usize,
    pub peers: usize,
    pub idle: Duration,
    pub sweep: Duration,
}
impl Default for RelayLimits {
    fn default() -> Self {
        Self { flows: MAX_FLOWS, queue: FLOW_QUEUE, peers: MAX_PEER_ADDRESSES, idle: SESSION_IDLE, sweep: Duration::from_secs(30) }
    }
}

pub(super) async fn bind_relay(server: super::relay_server::RelayServer, networks: Networks, state: &NativeState, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
    bind_relay_with_limits(server, networks, state, address, RelayLimits::default()).await
}

// Internal limits make the same bounded production path testable without
// waiting 500 seconds. They are not new configuration or environment options.
pub(super) async fn bind_relay_with_limits(server: super::relay_server::RelayServer, networks: Networks, state: &NativeState, address: SocketAddr, limits: RelayLimits) -> Result<Option<Box<dyn NativeInboundListener>>> {
    if limits.flows == 0 || limits.queue == 0 || limits.peers == 0 || limits.idle.is_zero() || limits.sweep.is_zero() {
        return Err(Error::Config("SS2022 relay limits must be positive".into()));
    }
    let Some((bindings, address)) = bind_sockets(networks, state, address).await? else { return Ok(None); };
    Ok(Some(Box::new(RelayListener { server: Arc::new(server), bindings, address, flows: HashMap::new(), limits, sweep: tokio::time::interval(limits.sweep) })))
}

struct RelayPeer {
    remote: SocketAddr,
    peers: HashSet<Destination>,
    active: Instant,
}
struct RelayFlow {
    sender: mpsc::Sender<Datagram>,
    source: Destination,
    destination: Destination,
    peer: Arc<Mutex<RelayPeer>>,
    cancelled: CancellationToken,
}
impl Drop for RelayFlow { fn drop(&mut self) { self.cancelled.cancel(); } }

struct RelayListener {
    server: Arc<super::relay_server::RelayServer>,
    bindings: Arc<Bindings>,
    address: SocketAddr,
    flows: HashMap<u64, RelayFlow>,
    limits: RelayLimits,
    sweep: tokio::time::Interval,
}
impl Drop for RelayListener { fn drop(&mut self) { self.bindings.stop(); } }
impl RelayListener {
    fn expire(&mut self) {
        let idle = self.limits.idle;
        self.flows.retain(|_, flow| !flow.cancelled.is_cancelled() && !flow.sender.is_closed() && flow.peer.lock().is_ok_and(|peer| peer.active.elapsed() < idle));
    }
    fn incoming(&mut self, incoming: super::relay_server::RelayDatagram, remote: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<Option<InboundTask>> {
        self.expire();
        let id = incoming.session_id;
        let source = udp_destination(remote);
        if let Some(flow) = self.flows.get_mut(&id) {
            {
                let mut peer = flow.peer.lock().map_err(|_| Error::Other("SS2022 relay peer lock poisoned".into()))?;
                if peer.peers.len() >= self.limits.peers && !peer.peers.contains(&source) { return Ok(None); }
                peer.peers.insert(source);
                peer.remote = remote;
                peer.active = Instant::now();
            }
            // Both metadata values stay at their first-dispatch values. The
            // shared dispatcher keys outbound routes by source+destination;
            // exposing the rebinding address here would open a new route. Go
            // also retains the first link/destination/user on an ID collision.
            let _ = flow.sender.try_send(Datagram { payload: Bytes::from(incoming.wire), source: Some(flow.source.clone()), destination: flow.destination.clone() });
            return Ok(None);
        }
        if self.flows.len() >= self.limits.flows { return Ok(None); }
        let mut session = SessionContext::new(self.server.tag(), incoming.destination.clone());
        session.source = Some(remote);
        session.user = Some(incoming.user);
        let (sender, receiver) = mpsc::channel(self.limits.queue);
        sender.try_send(Datagram { payload: Bytes::from(incoming.wire), source: Some(source.clone()), destination: incoming.destination.clone() }).map_err(|_| Error::Closed)?;
        let cancelled = self.bindings.cancelled.child_token();
        let peer = Arc::new(Mutex::new(RelayPeer { remote, peers: HashSet::from([source.clone()]), active: Instant::now() }));
        let transport = Arc::new(RelayPackets { bindings: self.bindings.clone(), peer: peer.clone(), receiver: AsyncMutex::new(receiver), cancelled: cancelled.clone() });
        self.flows.insert(id, RelayFlow { sender, source, destination: incoming.destination, peer, cancelled: cancelled.clone() });
        let guard = CancelOnDrop(cancelled.clone());
        Ok(Some(Box::pin(async move {
            let _guard = guard;
            tokio::select! {
                biased;
                _ = cancelled.cancelled() => Ok(()),
                result = dispatcher.dispatch_datagrams(transport, session) => result,
            }
        })))
    }
}

#[async_trait]
impl NativeInboundListener for RelayListener {
    fn local_addr(&self) -> Result<SocketAddr> { Ok(self.address) }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let udp = self.bindings.udp()?;
        let tcp = self.bindings.tcp.lock().map_err(|_| Error::Other("SS2022 relay TCP socket lock poisoned".into()))?.clone();
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
        loop {
            if self.bindings.cancelled.is_cancelled() { return Err(Error::Closed); }
            tokio::select! {
                _ = self.bindings.cancelled.cancelled() => return Err(Error::Closed),
                _ = self.sweep.tick() => self.expire(),
                accepted = async {
                    match &tcp { Some(listener) => listener.accept().await, None => std::future::pending().await }
                } => {
                    let (stream, remote) = accepted?;
                    let stream = Arc::new(TcpChild(Mutex::new(Some(stream))));
                    {
                        let mut connections = self.bindings.connections.lock().map_err(|_| Error::Other("SS2022 relay TCP child lock poisoned".into()))?;
                        if self.bindings.cancelled.is_cancelled() { return Err(Error::Closed); }
                        connections.retain(|connection| connection.strong_count() != 0);
                        connections.push(Arc::downgrade(&stream));
                    }
                    let stream = ChildStream(stream);
                    let server = self.server.clone();
                    let cancelled = self.bindings.cancelled.clone();
                    return Ok(Box::pin(async move {
                        tokio::select! {
                            biased; _ = cancelled.cancelled() => Ok(()),
                            result = server.dispatch_connection(Box::pin(stream), remote, dispatcher) => result,
                        }
                    }));
                }
                received = udp.recv_from(&mut buffer) => {
                    let (length, remote) = received?;
                    if length > MAX_DATAGRAM_SIZE { continue; }
                    let incoming = match self.server.relay_datagram(&buffer[..length]) {
                        Ok(packet) => packet,
                        Err(Error::Protocol(_)) => continue,
                        Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData => continue,
                        Err(error) => return Err(error),
                    };
                    if let Some(task) = self.incoming(incoming, remote, dispatcher.clone())? { return Ok(task); }
                }
            }
        }
    }
}

struct RelayPackets {
    bindings: Arc<Bindings>,
    peer: Arc<Mutex<RelayPeer>>,
    receiver: AsyncMutex<mpsc::Receiver<Datagram>>,
    cancelled: CancellationToken,
}
impl Drop for RelayPackets { fn drop(&mut self) { self.cancelled.cancel(); } }
#[async_trait]
impl DatagramTransport for RelayPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Ok(None),
            packet = async { self.receiver.lock().await.recv().await } => Ok(packet),
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.cancelled.is_cancelled() { return Err(Error::Closed); }
        if packet.payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        if packet.source.as_ref().is_some_and(|source| source.network != Network::Udp) { return Err(Error::Protocol("SS2022 relay reply source must use UDP".into())); }
        let remote = {
            let peer = self.peer.lock().map_err(|_| Error::Other("SS2022 relay peer lock poisoned".into()))?;
            if !peer.peers.contains(&packet.destination) { return Err(Error::Protocol("SS2022 relay reply is addressed to another association".into())); }
            peer.remote
        };
        let socket = self.bindings.udp()?;
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(Error::Closed),
            written = socket.send_to(&packet.payload, remote) => {
                if written? != packet.payload.len() { return Err(io::Error::new(io::ErrorKind::WriteZero, "short SS2022 relay UDP response").into()); }
                self.peer.lock().map_err(|_| Error::Other("SS2022 relay peer lock poisoned".into()))?.active = Instant::now();
                Ok(())
            }
        }
    }
    async fn close(&self) -> Result<()> { self.cancelled.cancel(); self.receiver.lock().await.close(); Ok(()) }
}
