//! Bounded classic Shadowsocks UDP associations and optional TCP co-binding.
use super::{Server, datagram::{Closed, Codec, check_send, udp_destination}};
use crate::{
    common::{errors::{Error, Result}, net::{datagram::{Datagram, DatagramTransport, MAX_DATAGRAM_SIZE}, Destination}, protocol::{SessionContext, User}},
    features::inbound::{InboundDispatcher, InboundHandler, InboundTask, NativeInboundListener},
};
use async_trait::async_trait;
use std::{collections::HashMap, future::poll_fn, net::SocketAddr, sync::{Arc, Mutex, Weak}, task::Poll, time::Duration};
use tokio::{io::ReadBuf, net::{TcpListener, TcpStream, UdpSocket}, sync::{mpsc, Mutex as AsyncMutex}, time::Instant};

const MAX_FLOWS: usize = 256;
const FLOW_QUEUE: usize = 32;
const FLOW_IDLE: Duration = Duration::from_secs(300);

#[derive(Default)]
pub(super) struct State {
    closed: Closed,
    bindings: Mutex<Vec<Weak<Bindings>>>,
}
impl State {
    pub fn is_closed(&self) -> bool { self.closed.is_cancelled() }
    pub fn close(&self) {
        self.closed.cancel();
        let mut bindings = self.bindings.lock().unwrap_or_else(|error| error.into_inner());
        for binding in bindings.drain(..).filter_map(|weak| weak.upgrade()) { binding.stop(); }
    }
}

struct Bindings {
    tcp: Mutex<Option<TcpListener>>,
    udp: Mutex<Option<UdpSocket>>,
    udp_send: AsyncMutex<()>,
    closed: Closed,
    pending_tcp: Mutex<Vec<Weak<PendingTcp>>>,
}
impl Bindings {
    fn stop(&self) {
        self.closed.cancel();
        self.tcp.lock().unwrap_or_else(|error| error.into_inner()).take();
        self.udp.lock().unwrap_or_else(|error| error.into_inner()).take();
        let mut pending = self.pending_tcp.lock().unwrap_or_else(|error| error.into_inner());
        for stream in pending.drain(..).filter_map(|weak| weak.upgrade()) { drop(stream.take()); }
    }
    // Socket ownership stays in revocable storage. Pending listener and send
    // futures borrow a socket for one poll and cannot retain its port on close.
    async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        poll_fn(|cx| {
            let listener = self.tcp.lock().map_err(|_| Error::Other("Shadowsocks TCP listener lock poisoned".into()))?;
            match listener.as_ref() {
                Some(listener) => listener.poll_accept(cx).map_err(Error::from),
                None if self.closed.is_cancelled() => Poll::Ready(Err(Error::Closed)),
                None => Poll::Pending,
            }
        }).await
    }
    async fn recv_from(&self, bytes: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut buffer = ReadBuf::new(bytes);
        let remote = poll_fn(|cx| {
            let socket = self.udp.lock().map_err(|_| Error::Other("Shadowsocks UDP socket lock poisoned".into()))?;
            let socket = socket.as_ref().ok_or(Error::Closed)?;
            socket.poll_recv_from(cx, &mut buffer).map_err(Error::from)
        }).await?;
        Ok((buffer.filled().len(), remote))
    }
    async fn send_to(&self, bytes: &[u8], remote: SocketAddr) -> Result<usize> {
        // Tokio stores one send waker per socket. Keep concurrent association
        // replies serialized while holding no socket across a pending poll.
        let _sending = self.udp_send.lock().await;
        poll_fn(|cx| {
            let socket = self.udp.lock().map_err(|_| Error::Other("Shadowsocks UDP socket lock poisoned".into()))?;
            let socket = socket.as_ref().ok_or(Error::Closed)?;
            socket.poll_send_to(cx, bytes, remote).map_err(Error::from)
        }).await
    }
    fn register_tcp(&self, stream: TcpStream) -> Result<Arc<PendingTcp>> {
        let mut pending = self.pending_tcp.lock().map_err(|_| Error::Other("Shadowsocks TCP child lock poisoned".into()))?;
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        let stream = Arc::new(PendingTcp { stream: Mutex::new(Some(stream)) });
        pending.retain(|stream| stream.strong_count() != 0);
        pending.push(Arc::downgrade(&stream));
        Ok(stream)
    }
}

// Until its returned task is polled, the accepted socket remains accessible
// to listener drop and handler close. A cancellation flag alone cannot drop a
// socket captured by a future that the caller keeps without ever polling.
struct PendingTcp { stream: Mutex<Option<TcpStream>> }
impl PendingTcp {
    fn take(&self) -> Option<TcpStream> {
        self.stream.lock().unwrap_or_else(|error| error.into_inner()).take()
    }
}

pub(super) async fn bind(
    server: Server, tcp: bool, codec: Codec, state: &State, address: SocketAddr, user: Option<User>,
) -> Result<Box<dyn NativeInboundListener>> {
    if state.is_closed() { return Err(Error::Closed); }
    // Finish both binds before returning. Port zero must pick a shared port.
    let tcp = if tcp { Some(TcpListener::bind(address).await?) } else { None };
    let address = match &tcp { Some(listener) => listener.local_addr()?, None => address };
    let udp = UdpSocket::bind(address).await?;
    let address = udp.local_addr()?;
    let bindings = Arc::new(Bindings {
        tcp: Mutex::new(tcp), udp: Mutex::new(Some(udp)), udp_send: AsyncMutex::new(()),
        closed: Closed::default(), pending_tcp: Mutex::new(Vec::new()),
    });
    {
        let mut listeners = state.bindings.lock().map_err(|_| Error::Other("Shadowsocks listener lock poisoned".into()))?;
        if state.is_closed() { bindings.stop(); return Err(Error::Closed); }
        listeners.retain(|binding| binding.strong_count() != 0);
        listeners.push(Arc::downgrade(&bindings));
    }
    Ok(Box::new(Listener {
        server: Arc::new(server), codec, bindings, address, user, flows: HashMap::new(),
        sweep: tokio::time::interval(Duration::from_secs(30)),
    }))
}

struct Flow {
    sender: mpsc::Sender<Datagram>,
    closed: Closed,
    active: Instant,
}
impl Drop for Flow { fn drop(&mut self) { self.closed.cancel(); } }

struct Listener {
    server: Arc<Server>,
    codec: Codec,
    bindings: Arc<Bindings>,
    address: SocketAddr,
    user: Option<User>,
    flows: HashMap<SocketAddr, Flow>,
    sweep: tokio::time::Interval,
}
impl Drop for Listener { fn drop(&mut self) { self.bindings.stop(); } }
impl Listener {
    fn expire(&mut self) {
        self.flows.retain(|_, flow| !flow.closed.is_cancelled() && !flow.sender.is_closed() && flow.active.elapsed() < FLOW_IDLE);
    }
    fn incoming(&mut self, remote: SocketAddr, packet: Datagram, dispatcher: Arc<dyn InboundDispatcher>) -> Result<Option<InboundTask>> {
        self.expire();
        if let Some(flow) = self.flows.get_mut(&remote) {
            flow.active = Instant::now();
            // Full queues drop a whole UDP packet without blocking TCP or other
            // peers. Neither packets nor associations may grow without bound.
            let _ = flow.sender.try_send(packet);
            return Ok(None);
        }
        if self.flows.len() >= MAX_FLOWS { return Ok(None); }
        let mut session = SessionContext::new(self.server.tag(), packet.destination.clone());
        session.source = Some(remote);
        session.user = self.user.clone();
        let (sender, receiver) = mpsc::channel(FLOW_QUEUE);
        sender.try_send(packet).map_err(|_| Error::Closed)?;
        let closed = Closed::default();
        let transport = Arc::new(Incoming {
            codec: self.codec.clone(), bindings: self.bindings.clone(), remote,
            receiver: AsyncMutex::new(receiver), closed: closed.clone(),
        });
        self.flows.insert(remote, Flow { sender, closed: closed.clone(), active: Instant::now() });
        // Capture before constructing the future, so dropping an unpolled task
        // also invalidates the corresponding association.
        let guard = CancelOnDrop(closed.clone());
        let listener_closed = self.bindings.closed.clone();
        Ok(Some(Box::pin(async move {
            let _guard = guard;
            tokio::select! {
                biased;
                _ = listener_closed.cancelled() => Ok(()),
                _ = closed.cancelled() => Ok(()),
                result = dispatcher.dispatch_datagrams(transport, session) => result,
            }
        })))
    }
}

#[async_trait]
impl NativeInboundListener for Listener {
    fn local_addr(&self) -> Result<SocketAddr> { Ok(self.address) }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
        loop {
            tokio::select! {
                biased;
                _ = self.bindings.closed.cancelled() => return Err(Error::Closed),
                _ = self.sweep.tick() => self.expire(),
                accepted = self.bindings.accept() => {
                    let (stream, remote) = accepted?;
                    let stream = self.bindings.register_tcp(stream)?;
                    let server = self.server.clone();
                    let closed = self.bindings.closed.clone();
                    return Ok(Box::pin(async move {
                        let Some(stream) = stream.take() else { return Ok(()); };
                        tokio::select! {
                            biased;
                            _ = closed.cancelled() => Ok(()),
                            result = server.dispatch_connection(Box::pin(stream), remote, dispatcher) => result,
                        }
                    }));
                }
                received = self.bindings.recv_from(&mut buffer) => {
                    let (length, remote) = received?;
                    let (destination, payload) = match self.codec.decode(&buffer[..length]) {
                        Ok(packet) => packet, Err(_) => continue,
                    };
                    let packet = Datagram { payload, source: Some(udp_destination(remote)), destination };
                    if let Some(task) = self.incoming(remote, packet, dispatcher.clone())? { return Ok(task); }
                }
            }
        }
    }
}

struct CancelOnDrop(Closed);
impl Drop for CancelOnDrop { fn drop(&mut self) { self.0.cancel(); } }

struct Incoming {
    codec: Codec,
    bindings: Arc<Bindings>,
    remote: SocketAddr,
    receiver: AsyncMutex<mpsc::Receiver<Datagram>>,
    closed: Closed,
}
impl Drop for Incoming { fn drop(&mut self) { self.closed.cancel(); } }
#[async_trait]
impl DatagramTransport for Incoming {
    async fn recv(&self) -> Result<Option<Datagram>> {
        tokio::select! {
            biased;
            _ = self.bindings.closed.cancelled() => Ok(None),
            _ = self.closed.cancelled() => Ok(None),
            packet = async { self.receiver.lock().await.recv().await } => Ok(packet),
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.closed.is_cancelled() || self.bindings.closed.is_cancelled() { return Err(Error::Closed); }
        if packet.destination != udp_destination(self.remote) {
            return Err(Error::Protocol("Shadowsocks UDP reply is addressed to another association".into()));
        }
        let source: Destination = packet.source.ok_or_else(|| Error::Protocol("Shadowsocks UDP reply requires a source".into()))?;
        let wire = self.codec.encode(&source, &packet.payload)?;
        tokio::select! {
            biased;
            _ = self.bindings.closed.cancelled() => Err(Error::Closed),
            _ = self.closed.cancelled() => Err(Error::Closed),
            written = self.bindings.send_to(&wire, self.remote) => check_send(written?, wire.len()),
        }
    }
    async fn close(&self) -> Result<()> {
        self.closed.cancel();
        self.receiver.lock().await.close();
        Ok(())
    }
}
