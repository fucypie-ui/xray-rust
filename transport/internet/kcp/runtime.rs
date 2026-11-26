//! Tokio driver and native asynchronous stream for Xray's mKCP wire protocol.
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::config::KcpConfig;
use super::connection::KcpConnection;
use super::engine::{Engine, State, WriteBlocked};
use super::wire::read_segments;
use crate::common::errors::Result;
use crate::common::net::BoxStream;
use crate::transport::internet::finalmask::mkcp::aes128gcm::conn::Aes128GcmPacketConn;
use crate::transport::internet::finalmask::mkcp::original::conn::OriginalPacketConn;

/// A finalmask boundary around one complete mKCP datagram. Implementations
/// must preserve datagram boundaries and may reject unauthenticated packets.
/// The MTU in KcpConfig describes the unwrapped mKCP segment, as in Go.
pub trait DatagramCodec: Send + Sync + 'static {
    fn encode(&self, packet: &[u8]) -> Result<Vec<u8>>;
    fn decode(&self, packet: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct PlainPacketCodec;
impl DatagramCodec for PlainPacketCodec {
    fn encode(&self, packet: &[u8]) -> Result<Vec<u8>> { Ok(packet.to_vec()) }
    fn decode(&self, packet: &[u8]) -> Result<Vec<u8>> { Ok(packet.to_vec()) }
}

/// Existing legacy packet masks, reused rather than reimplementing crypto.
/// Current Go defaults to raw segments; Original must be selected explicitly.
pub enum LegacyPacketCodec {
    Original(OriginalPacketConn),
    Aes128Gcm(Box<Aes128GcmPacketConn>),
}
impl LegacyPacketCodec {
    pub fn original() -> Self { Self::Original(OriginalPacketConn::default()) }
    pub fn with_seed(seed: &str) -> Self {
        Self::Aes128Gcm(Box::new(Aes128GcmPacketConn::new(seed)))
    }
}
impl DatagramCodec for LegacyPacketCodec {
    fn encode(&self, packet: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Original(codec) => Ok(codec.wrap(packet)),
            Self::Aes128Gcm(codec) => codec.wrap(packet),
        }
    }
    fn decode(&self, packet: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Original(codec) => codec.unwrap(packet),
            Self::Aes128Gcm(codec) => codec.unwrap(packet),
        }
    }
}
pub(super) fn config_codec(_config: &KcpConfig) -> Arc<dyn DatagramCodec> {
    // At the authoritative Go revision, kcpSettings.seed/header are retained
    // JSON fields but Build does not apply them. Packet transforms belong to
    // streamSettings.finalmask. Select a codec explicitly for those masks.
    Arc::new(PlainPacketCodec)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    pub state: State,
    pub pending_segments: usize,
    pub receiving_next: u32,
    pub congestion_window: u32,
    pub retransmission_timeout_ms: u32,
}

pub(super) struct Core {
    pub engine: Engine,
    failure: Option<(io::ErrorKind, String)>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    flusher: Option<Waker>,
    closer: Option<Waker>,
}
impl Core {
    fn error(&self) -> Option<io::Error> {
        self.failure.as_ref().map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
    fn wake(&mut self) {
        for slot in [&mut self.reader, &mut self.writer, &mut self.flusher, &mut self.closer] {
            if let Some(waker) = slot.take() { waker.wake(); }
        }
    }
}

pub(super) struct Shared {
    pub core: Mutex<Core>,
    pub notify: Notify,
    pub cancellation: CancellationToken,
    pub created: Instant,
    task: Mutex<Option<JoinHandle<()>>>,
}
impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn elapsed(&self) -> u32 { self.created.elapsed().as_millis() as u32 }
    pub fn request_close(&self) {
        let mut core = self.lock();
        core.engine.close(self.elapsed());
        core.wake();
        drop(core);
        self.notify.notify_one();
    }
    pub fn fail(&self, error: io::Error) {
        let mut core = self.lock();
        if core.failure.is_none() { core.failure = Some((error.kind(), error.to_string())); }
        core.engine.abort(self.elapsed());
        core.wake();
        drop(core);
        self.notify.notify_one();
    }
    pub async fn join(&self) {
        let task = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(task) = task { let _ = task.await; }
    }
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        let mut core = self.lock();
        if let Some(error) = core.error() { return Poll::Ready(Err(error)); }
        match core.engine.read(buf) {
            None => Poll::Ready(Ok(0)),
            Some(0) => {
                core.reader = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(count) => {
                drop(core);
                self.notify.notify_one();
                Poll::Ready(Ok(count))
            }
        }
    }
    pub fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        let mut core = self.lock();
        if let Some(error) = core.error() { return Poll::Ready(Err(error)); }
        match core.engine.write(buf) {
            Ok(count) => {
                drop(core);
                self.notify.notify_one();
                Poll::Ready(Ok(count))
            }
            Err(WriteBlocked::Full) => {
                core.writer = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(WriteBlocked::Closed) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "mKCP write side closed"))),
        }
    }
    pub fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut core = self.lock();
        if let Some(error) = core.error() { return Poll::Ready(Err(error)); }
        if !core.engine.awaits_acknowledgement() { return Poll::Ready(Ok(())); }
        core.flusher = Some(cx.waker().clone());
        Poll::Pending
    }
    pub fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut core = self.lock();
        if core.engine.state() == State::Terminated { return Poll::Ready(()); }
        core.closer = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            task.abort();
        }
    }
}

/// Application ownership is separate from the driver, so dropping the last
/// client handle requests a graceful close without retaining an active task.
pub(super) struct Lease(pub Arc<Shared>);
impl Drop for Lease {
    fn drop(&mut self) { self.0.request_close(); }
}

pub(super) enum Incoming {
    Socket,
    Demux(mpsc::Receiver<Vec<u8>>),
}

pub(super) fn start(
    conv: u16,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    config: &KcpConfig,
    cancellation: CancellationToken,
    codec: Arc<dyn DatagramCodec>,
    incoming: Incoming,
) -> Result<Arc<Lease>> {
    let engine_config = config.engine_config()?;
    if cancellation.is_cancelled() { return Err(crate::common::errors::Error::Closed); }
    tokio::runtime::Handle::try_current().map_err(|error| {
        crate::common::errors::Error::Config(format!("mKCP requires a Tokio runtime: {error}"))
    })?;
    let shared = Arc::new(Shared {
        core: Mutex::new(Core {
            engine: Engine::new(conv, engine_config), failure: None,
            reader: None, writer: None, flusher: None, closer: None,
        }),
        notify: Notify::new(), cancellation: cancellation.child_token(), created: Instant::now(),
        task: Mutex::new(None),
    });
    let task = tokio::spawn(drive(shared.clone(), socket, peer, conv, codec, incoming));
    *shared.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    Ok(Arc::new(Lease(shared)))
}

async fn receive(incoming: &mut Incoming, socket: &UdpSocket, peer: SocketAddr, raw: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
    match incoming {
        Incoming::Demux(receiver) => Ok(receiver.recv().await),
        Incoming::Socket => {
            let (count, source) = socket.recv_from(raw).await?;
            if source != peer { return Ok(Some(Vec::new())); }
            Ok(Some(raw[..count].to_vec()))
        }
    }
}

async fn send(
    shared: &Shared, socket: &UdpSocket, peer: SocketAddr, packet: &[u8],
) -> io::Result<()> {
    let mut attempts = 0;
    loop {
        let result = tokio::select! {
            biased;
            _ = shared.cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "mKCP cancelled")),
            result = socket.send_to(packet, peer) => result,
        };
        match result {
            Ok(count) if count == packet.len() => return Ok(()),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial mKCP datagram")),
            Err(error) => {
                attempts += 1;
                if attempts == 5 { return Err(error); }
                tokio::select! {
                    biased;
                    _ = shared.cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "mKCP cancelled")),
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
}

enum Event { Wake, Tick, Packet(io::Result<Option<Vec<u8>>>), Cancel }
async fn drive(
    shared: Arc<Shared>, socket: Arc<UdpSocket>, peer: SocketAddr, conv: u16,
    codec: Arc<dyn DatagramCodec>, mut incoming: Incoming,
) {
    let mut raw = vec![0u8; 65_535];
    let demultiplexed = matches!(&incoming, Incoming::Demux(_));
    let mut next_update = Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::select! {
            biased;
            _ = shared.cancellation.cancelled() => Event::Cancel,
            _ = tokio::time::sleep_until(next_update) => Event::Tick,
            _ = shared.notify.notified() => Event::Wake,
            packet = receive(&mut incoming, &socket, peer, &mut raw) => Event::Packet(packet),
        };
        let segments = match event {
            Event::Cancel => {
                shared.fail(io::Error::new(io::ErrorKind::Interrupted, "mKCP cancelled"));
                break;
            }
            Event::Packet(Err(error)) => { shared.fail(error); break; }
            Event::Packet(Ok(None)) => {
                shared.fail(io::Error::new(io::ErrorKind::ConnectionAborted, "mKCP packet source closed"));
                break;
            }
            Event::Packet(Ok(Some(packet))) => {
                // Authentication failures and malformed/foreign packets never
                // create activity or extend the connection's idle lifetime.
                let plain = if demultiplexed { packet } else {
                    let Ok(plain) = codec.decode(&packet) else { continue; };
                    plain
                };
                let segments = read_segments(&plain);
                if segments.first().is_none_or(|segment| segment.conv() != conv) { continue; }
                Some(segments)
            }
            Event::Wake | Event::Tick => None,
        };
        let (out, terminated, interval) = {
            let mut core = shared.lock();
            let current = shared.elapsed();
            if let Some(segments) = segments { core.engine.input(segments, current); }
            core.engine.flush(current);
            let terminated = core.engine.state() == State::Terminated;
            let interval = if core.engine.data_update_necessary() {
                Duration::from_millis(u64::from(core.engine.tti()))
            } else if core.engine.data_update_terminated() || core.engine.state() == State::PeerTerminating {
                Duration::from_secs(1)
            } else { Duration::from_secs(5) };
            let out = std::mem::take(&mut core.engine.out);
            // This driver wakes every registered operation after a turn;
            // consume the sans-I/O engine's edge-triggered hints together.
            let _signals = (
                std::mem::take(&mut core.engine.input_ready),
                std::mem::take(&mut core.engine.output_ready),
                std::mem::take(&mut core.engine.wake_data),
                std::mem::take(&mut core.engine.peer_heard),
            );
            core.wake();
            (out, terminated, interval)
        };
        for packet in out {
            let packet = match codec.encode(&packet) {
                Ok(packet) => packet,
                Err(error) => { shared.fail(io::Error::other(error.to_string())); return; }
            };
            if let Err(error) = send(&shared, &socket, peer, &packet).await {
                shared.fail(error);
                return;
            }
        }
        if terminated { break; }
        next_update = Instant::now() + interval;
    }
}

/// A native AsyncRead/AsyncWrite adapter. Reads wait for in-order data;
/// writes apply the Go sending-buffer limit; flush waits for acknowledgments.
/// Shutdown drains accepted data and starts Go's terminate handshake.
pub struct KcpStream { connection: KcpConnection }
impl KcpStream {
    pub(super) fn new(connection: KcpConnection) -> Self { Self { connection } }
    pub fn connection(&self) -> &KcpConnection { &self.connection }
    pub fn into_boxed(self) -> BoxStream { Box::pin(self) }
}
impl AsyncRead for KcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let out = buf.initialize_unfilled();
        match self.connection.shared().poll_read(cx, out) {
            Poll::Ready(Ok(count)) => { buf.advance(count); Poll::Ready(Ok(())) }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for KcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.connection.shared().poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.connection.shared().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.connection.shared().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.connection.shared().request_close();
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl Drop for KcpStream {
    fn drop(&mut self) { self.connection.shared().request_close(); }
}
