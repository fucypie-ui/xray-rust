use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, Weak};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::config::KcpConfig;
use super::runtime::{self, ConnectionStats, DatagramCodec, Incoming, KcpStream, Lease, Shared};
use super::wire::read_segments;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

pub use super::engine::State;

/// Monotonic time for callers using the public low-level window helpers.
/// Session wire timestamps use milliseconds since that session was created.
pub fn now_millis() -> u32 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}

/// Public diagnostic RTT helper retained for existing low-level callers.
/// Arithmetic is the same as Go RoundTripInfo, including peer-RTO aging.
pub struct RoundTripInfo {
    pub variation: u32,
    pub srtt: u32,
    pub rto: u32,
    pub min_rtt: u32,
    pub updated_timestamp: u32,
}
impl RoundTripInfo {
    pub fn new() -> Self {
        Self { variation: 0, srtt: 0, rto: 100, min_rtt: 50, updated_timestamp: 0 }
    }
    pub fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp) < 3000 { return; }
        self.updated_timestamp = current;
        self.rto = rto;
    }
    pub fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7fff_ffff { return; }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            self.variation = self.variation.wrapping_mul(3).wrapping_add(rtt.abs_diff(self.srtt)) / 4;
            self.srtt = (self.srtt.wrapping_mul(7).wrapping_add(rtt) / 8).max(self.min_rtt);
        }
        let four = self.variation.wrapping_mul(4);
        let variation = if self.min_rtt < four { four } else { self.variation };
        self.rto = self.srtt.wrapping_add(variation).min(10_000) * 5 / 4;
        self.updated_timestamp = current;
    }
}
impl Default for RoundTripInfo { fn default() -> Self { Self::new() } }

/// A live session. Every constructor starts packet input and timed output;
/// applications never need to call input_packet or flush to run the ARQ.
#[derive(Clone)]
pub struct KcpConnection {
    pub conv: u16,
    pub remote_addr: Option<SocketAddr>,
    pub mss: usize,
    local_addr: SocketAddr,
    lease: Arc<Lease>,
}
impl KcpConnection {
    pub fn new(conv: u16, socket: Arc<UdpSocket>) -> Self {
        let remote = socket.peer_addr().expect("KcpConnection::new requires a connected UDP socket");
        Self::with_remote_addr(conv, socket, Some(remote))
    }
    pub fn with_remote_addr(conv: u16, socket: Arc<UdpSocket>, remote_addr: Option<SocketAddr>) -> Self {
        let remote = remote_addr.or_else(|| socket.peer_addr().ok())
            .expect("mKCP requires a remote socket address");
        Self::from_socket_with_config(conv, socket, remote, KcpConfig::default(), CancellationToken::new())
            .expect("default mKCP configuration requires a running Tokio runtime")
    }
    pub fn from_socket_with_config(
        conv: u16, socket: Arc<UdpSocket>, remote: SocketAddr,
        config: KcpConfig, cancellation: CancellationToken,
    ) -> Result<Self> {
        let codec = runtime::config_codec(&config);
        Self::from_socket_with_codec(conv, socket, remote, config, cancellation, codec)
    }
    pub fn from_socket_with_codec(
        conv: u16, socket: Arc<UdpSocket>, remote: SocketAddr,
        config: KcpConfig, cancellation: CancellationToken, codec: Arc<dyn DatagramCodec>,
    ) -> Result<Self> {
        Self::start(conv, socket, remote, config, cancellation, codec, Incoming::Socket)
    }
    pub(super) fn accepted(
        conv: u16, socket: Arc<UdpSocket>, remote: SocketAddr,
        config: KcpConfig, cancellation: CancellationToken, codec: Arc<dyn DatagramCodec>,
        incoming: mpsc::Receiver<Vec<u8>>,
    ) -> Result<Self> {
        Self::start(conv, socket, remote, config, cancellation, codec, Incoming::Demux(incoming))
    }
    #[allow(clippy::too_many_arguments)]
    fn start(
        conv: u16, socket: Arc<UdpSocket>, remote: SocketAddr,
        config: KcpConfig, cancellation: CancellationToken, codec: Arc<dyn DatagramCodec>,
        incoming: Incoming,
    ) -> Result<Self> {
        let local_addr = socket.local_addr()?;
        let lease = runtime::start(conv, socket, remote, &config, cancellation, codec, incoming)?;
        Ok(Self { conv, local_addr, remote_addr: Some(remote), mss: (config.mtu - 18) as usize, lease })
    }
    pub(super) fn shared(&self) -> &Arc<Shared> { &self.lease.0 }
    pub(super) fn weak_lease(&self) -> Weak<Lease> { Arc::downgrade(&self.lease) }
    pub(super) fn from_lease(lease: Arc<Lease>, conv: u16, local_addr: SocketAddr, peer: SocketAddr, mss: usize) -> Self {
        Self { conv, local_addr, remote_addr: Some(peer), mss, lease }
    }
    pub fn conv(&self) -> u16 { self.conv }
    pub fn local_addr(&self) -> Result<SocketAddr> { Ok(self.local_addr) }
    pub fn peer_addr(&self) -> Result<SocketAddr> { self.remote_addr.ok_or(Error::Closed) }
    pub fn stats(&self) -> ConnectionStats { self.shared().lock().engine.statistics() }
    pub async fn is_closed(&self) -> bool {
        matches!(self.stats().state, State::Terminating | State::Terminated)
    }
    pub fn is_terminated(&self) -> bool { self.stats().state == State::Terminated }
    pub async fn handle_incoming_segment(&self, packet: &[u8]) -> Result<()> { self.input_packet(packet).await }
    /// Optional injection hook for an already-unwrapped Go mKCP datagram.
    pub async fn input_packet(&self, packet: &[u8]) -> Result<()> {
        let segments = read_segments(packet);
        if segments.first().is_none_or(|segment| segment.conv() != self.conv) {
            return Err(Error::Protocol("invalid or foreign mKCP packet".into()));
        }
        let mut core = self.shared().lock();
        core.engine.input(segments, self.shared().elapsed());
        drop(core);
        self.shared().notify.notify_one();
        Ok(())
    }
    pub async fn send_data(&self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let count = poll_fn(|cx| self.shared().poll_write(cx, data)).await?;
            data = &data[count..];
        }
        Ok(())
    }
    /// Waits until queued data has been acknowledged. Background timers
    /// continue retransmissions even when this method is never called.
    pub async fn flush(&self) -> Result<()> {
        poll_fn(|cx| self.shared().poll_flush(cx)).await?;
        Ok(())
    }
    pub async fn flush_acks(&self) -> Result<()> {
        self.shared().notify.notify_one();
        Ok(())
    }
    /// Waits for ordered bytes, a peer close, or cancellation. Zero is EOF.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(poll_fn(|cx| self.shared().poll_read(cx, buf)).await?)
    }
    pub async fn close(&self) -> Result<()> {
        self.shared().request_close();
        Ok(())
    }
    /// Immediate local cancellation wakes blocked I/O and joins the driver.
    pub async fn cancel(&self) {
        self.shared().cancellation.cancel();
        self.shared().join().await;
    }
    pub async fn wait_closed(&self) {
        poll_fn(|cx| self.shared().poll_closed(cx)).await;
        self.shared().join().await;
    }
    pub fn into_stream(self) -> KcpStream { KcpStream::new(self) }
    pub fn into_box_stream(self) -> BoxStream { self.into_stream().into_boxed() }
}
