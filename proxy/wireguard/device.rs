//! Authenticated WireGuard device backed by Cloudflare's BoringTun Noise engine.
use boringtun::{
    noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    collections::HashMap, future::pending, io, net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, Weak, atomic::{AtomicU64, Ordering}},
    time::{Duration, Instant},
};
use tokio::{net::{UdpSocket, lookup_host}, sync::{Notify, mpsc}, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use crate::common::errors::{Error, Result};
use super::{
    config::{ValidatedConfig, WireGuardConfig},
    stack::{AcceptedTcp, IncomingUdp, Stack, WireGuardTcpStream, WireGuardUdpSocket, io_error},
};

const MAX_DATAGRAM: usize = 65535;

#[derive(Debug, Clone, Copy, Default)]
pub struct WireGuardStats {
    pub encrypted_sent: u64,
    pub encrypted_received: u64,
    pub authenticated_packets: u64,
    pub rejected_packets: u64,
}
#[derive(Default)]
struct Counters { sent: AtomicU64, received: AtomicU64, authenticated: AtomicU64, rejected: AtomicU64 }

pub(crate) struct DeviceInner {
    state: Mutex<Stack>,
    pub notify: Arc<Notify>,
    cancellation: CancellationToken,
    worker: Mutex<Option<JoinHandle<()>>>,
    config: Arc<ValidatedConfig>,
    local_addr: SocketAddr,
    counters: Arc<Counters>,
}
impl DeviceInner {
    pub fn stack(&self) -> MutexGuard<'_, Stack> { self.state.lock().unwrap_or_else(|error| error.into_inner()) }
}
impl Drop for DeviceInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(worker) = self.worker.get_mut().unwrap_or_else(|error| error.into_inner()).take() { worker.abort(); }
    }
}

#[derive(Clone)]
pub struct WireGuardDevice { inner: Arc<DeviceInner> }

pub(crate) struct ServerReceivers {
    pub tcp: mpsc::Receiver<(WireGuardTcpStream, SocketAddr, SocketAddr)>,
    pub udp: mpsc::Receiver<IncomingUdp>,
}

impl WireGuardDevice {
    /// Open a real userspace WireGuard device; no TUN privileges are required.
    pub async fn bind(config: WireGuardConfig, listen: SocketAddr) -> Result<Self> {
        Self::open(config, listen, false).await.map(|(device, _)| device)
    }

    pub(crate) async fn open(config: WireGuardConfig, listen: SocketAddr, server: bool) -> Result<(Self, ServerReceivers)> {
        let config = Arc::new(config.validated()?);
        let sockets = UdpSockets::bind(listen).await?;
        let local_addr = sockets.local_addr()?;
        let mut endpoints = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            if peer.endpoint.is_empty() { endpoints.push(None); continue; }
            let addresses = tokio::time::timeout(Duration::from_secs(10), lookup_host(&peer.endpoint)).await
                .map_err(|_| Error::Config("WireGuard endpoint DNS lookup timed out".into()))??;
            let endpoint = addresses.into_iter().find(|address| sockets.supports(*address))
                .ok_or_else(|| Error::Config(format!("WireGuard endpoint has no usable address: {}", peer.endpoint)))?;
            endpoints.push(Some(endpoint));
        }
        let stack = Stack::new(&config, server, rand::random())?;
        let inner = Arc::new(DeviceInner {
            state: Mutex::new(stack), notify: Arc::new(Notify::new()), cancellation: CancellationToken::new(),
            worker: Mutex::new(None), config: config.clone(), local_addr, counters: Arc::new(Counters::default()),
        });
        let noise = NoisePeers::new(config, endpoints);
        let (tcp_tx, tcp_rx) = mpsc::channel(64);
        let (udp_tx, udp_rx) = mpsc::channel(256);
        let worker = tokio::spawn(run_device(Arc::downgrade(&inner), sockets, noise, inner.notify.clone(),
            inner.cancellation.clone(), inner.counters.clone(), tcp_tx, udp_tx));
        *inner.worker.lock().unwrap_or_else(|error| error.into_inner()) = Some(worker);
        Ok((Self { inner }, ServerReceivers { tcp: tcp_rx, udp: udp_rx }))
    }

    pub fn local_addr(&self) -> SocketAddr { self.inner.local_addr }
    pub fn mtu(&self) -> usize { self.inner.config.mtu }
    pub fn stats(&self) -> WireGuardStats {
        let counters = &self.inner.counters;
        WireGuardStats { encrypted_sent: counters.sent.load(Ordering::Relaxed),
            encrypted_received: counters.received.load(Ordering::Relaxed),
            authenticated_packets: counters.authenticated.load(Ordering::Relaxed),
            rejected_packets: counters.rejected.load(Ordering::Relaxed) }
    }

    pub fn can_route(&self, address: IpAddr) -> bool {
        route_peer(&self.inner.config, address).is_some()
            && self.inner.config.addresses.iter().any(|local| local.is_ipv4() == address.is_ipv4())
    }

    pub async fn connect_tcp(&self, destination: SocketAddr) -> Result<WireGuardTcpStream> {
        if !self.can_route(destination.ip()) { return Err(Error::Config("no WireGuard allowedIPs route for TCP destination".into())); }
        let handle = self.inner.stack().connect_tcp(destination)?;
        let stream = WireGuardTcpStream::new(self.inner.clone(), handle);
        self.inner.notify.notify_one();
        tokio::time::timeout(Duration::from_secs(20), stream.established()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WireGuard TCP handshake timed out"))??;
        Ok(stream)
    }

    pub fn connect_udp(&self, destination: SocketAddr) -> Result<WireGuardUdpSocket> {
        if !self.can_route(destination.ip()) { return Err(Error::Config("no WireGuard allowedIPs route for UDP destination".into())); }
        let handle = self.inner.stack().connect_udp(destination)?;
        self.inner.notify.notify_one();
        Ok(WireGuardUdpSocket::new(self.inner.clone(), handle, destination))
    }

    pub(crate) fn dns_servers(&self) -> &[IpAddr] { &self.inner.config.dns }

    pub(crate) fn user_for_ip(&self, source: IpAddr) -> Option<crate::common::protocol::User> {
        let peer = &self.inner.config.peers[route_peer(&self.inner.config, source)?];
        // The runtime User requires a UUID whereas WireGuard authenticates a
        // public key. Use a stable custom UUID derived from its public bytes;
        // authentication has already happened in Noise and cryptokey routing.
        let mut identity = [0; 16]; identity.copy_from_slice(&peer.public_key[..16]);
        identity[6] = (identity[6] & 0x0f) | 0x80; identity[8] = (identity[8] & 0x3f) | 0x80;
        Some(crate::common::protocol::User::with_email(uuid::Uuid::from_bytes(identity), &peer.email, peer.level))
    }

    pub(crate) fn reply_udp(&self, source: SocketAddr, destination: SocketAddr, data: &[u8]) -> Result<()> {
        self.inner.stack().reply_udp(source, destination, data)?;
        self.inner.notify.notify_one(); Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.stop();
        let worker = self.inner.worker.lock().unwrap_or_else(|error| error.into_inner()).take();
        if let Some(worker) = worker { worker.await.map_err(|error| io_error(error.to_string()))?; }
        Ok(())
    }

    pub(crate) fn stop(&self) {
        self.inner.cancellation.cancel(); self.inner.stack().shutdown();
    }
    pub(crate) fn child_cancellation(&self) -> CancellationToken { self.inner.cancellation.child_token() }
}

struct UdpSockets { v4: Option<UdpSocket>, v6: Option<UdpSocket>, primary_v6: bool }
impl UdpSockets {
    async fn bind(listen: SocketAddr) -> io::Result<Self> {
        let primary = bind_socket(listen)?;
        let port = primary.local_addr()?.port();
        let primary_v6 = listen.is_ipv6();
        let secondary = if listen.ip().is_unspecified() {
            let ip = if primary_v6 { IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) };
            // An unavailable secondary family must not disable a working IPv4-only host.
            bind_socket(SocketAddr::new(ip, port)).ok()
        } else { None };
        Ok(if primary_v6 { Self { v4: secondary, v6: Some(primary), primary_v6 } }
            else { Self { v4: Some(primary), v6: secondary, primary_v6 } })
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let socket = if self.primary_v6 { &self.v6 } else { &self.v4 };
        socket.as_ref().ok_or_else(|| io_error("WireGuard socket unavailable"))?.local_addr()
    }
    fn supports(&self, endpoint: SocketAddr) -> bool { if endpoint.is_ipv4() { self.v4.is_some() } else { self.v6.is_some() } }
    async fn send(&self, data: &[u8], endpoint: SocketAddr) -> io::Result<()> {
        let socket = if endpoint.is_ipv4() { &self.v4 } else { &self.v6 };
        let n = socket.as_ref().ok_or_else(|| io_error("WireGuard endpoint family unavailable"))?.send_to(data, endpoint).await?;
        if n == data.len() { Ok(()) } else { Err(io::Error::new(io::ErrorKind::WriteZero, "short WireGuard UDP write")) }
    }
}
fn bind_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(if address.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
        socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if address.is_ipv6() { socket.set_only_v6(true)?; }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    UdpSocket::from_std(socket.into())
}
async fn receive(socket: &Option<UdpSocket>, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match socket { Some(socket) => socket.recv_from(buffer).await, None => pending().await }
}

struct Peer { tunnel: Tunn, endpoint: Option<SocketAddr> }
struct NoisePeers {
    config: Arc<ValidatedConfig>, peers: Vec<Peer>, by_public_key: HashMap<[u8; 32], usize>,
    private: StaticSecret, public: PublicKey, discovery: RateLimiter,
}
#[derive(Debug)]
enum Output { Done, Rejected, Network(Vec<u8>), Tunnel(Vec<u8>, IpAddr) }
impl From<TunnResult<'_>> for Output {
    fn from(result: TunnResult<'_>) -> Self {
        match result {
            TunnResult::Done => Self::Done, TunnResult::Err(_) => Self::Rejected,
            TunnResult::WriteToNetwork(data) => Self::Network(data.to_vec()),
            TunnResult::WriteToTunnelV4(data, ip) => Self::Tunnel(data.to_vec(), ip.into()),
            TunnResult::WriteToTunnelV6(data, ip) => Self::Tunnel(data.to_vec(), ip.into()),
        }
    }
}
struct Received { network: Vec<(SocketAddr, Vec<u8>)>, packets: Vec<Vec<u8>>, authenticated: bool }

impl NoisePeers {
    fn new(config: Arc<ValidatedConfig>, endpoints: Vec<Option<SocketAddr>>) -> Self {
        let private = StaticSecret::from(config.private_key);
        let public = PublicKey::from(&private);
        let discovery = RateLimiter::new(&public, 100);
        let by_public_key = config.peers.iter().enumerate().map(|(index, peer)| (peer.public_key, index)).collect();
        let peers = config.peers.iter().zip(endpoints).enumerate().map(|(index, (peer, endpoint))| Peer {
            tunnel: Tunn::new(StaticSecret::from(config.private_key), PublicKey::from(peer.public_key),
                peer.pre_shared_key, (peer.keepalive != 0).then_some(peer.keepalive), (index + 1) as u32, None), endpoint,
        }).collect();
        Self { config, peers, by_public_key, private, public, discovery }
    }

    fn receive(&mut self, source: SocketAddr, datagram: &mut [u8], buffer: &mut [u8]) -> Received {
        let mut received = Received { network: Vec::new(), packets: Vec::new(), authenticated: false };
        if datagram.len() < 4 { return received; }
        // Xray's reserved bytes are an outer transport convention, outside Noise's MAC input.
        datagram[1..4].fill(0);
        let packet_type = datagram[0];
        let index = match Tunn::parse_incoming_packet(datagram) {
            Ok(Packet::HandshakeInit(_)) => {
                let packet = match self.discovery.verify_packet(Some(source.ip()), datagram, buffer) {
                    Ok(Packet::HandshakeInit(packet)) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        received.network.push((source, cookie.to_vec())); return received;
                    }
                    _ => return received,
                };
                let Ok(half) = parse_handshake_anon(&self.private, &self.public, &packet) else { return received; };
                let Some(index) = self.by_public_key.get(&half.peer_static_public) else { return received; };
                *index
            }
            Ok(Packet::HandshakeResponse(packet)) => match (packet.receiver_idx >> 8).checked_sub(1) { Some(i) => i as usize, None => return received },
            Ok(Packet::PacketCookieReply(packet)) => match (packet.receiver_idx >> 8).checked_sub(1) { Some(i) => i as usize, None => return received },
            Ok(Packet::PacketData(packet)) => match (packet.receiver_idx >> 8).checked_sub(1) { Some(i) => i as usize, None => return received },
            Err(_) => return received,
        };
        let Some(peer) = self.peers.get_mut(index) else { return received; };
        let output = Output::from(peer.tunnel.decapsulate(Some(source.ip()), datagram, buffer));
        match output {
            Output::Rejected => return received,
            Output::Done => { received.authenticated = packet_type == 4; }
            Output::Network(data) => {
                // Cookie replies do not prove peer identity and cannot move its endpoint.
                received.authenticated = matches!(data.first(), Some(2 | 4));
                received.network.push((source, data));
            }
            Output::Tunnel(data, ip) => {
                // Cryptokey routing applies on receive as well as transmit. Longest
                // prefix and last owner of an exact prefix match wireguard-go's trie.
                if route_peer(&self.config, ip) != Some(index) { return received; }
                received.authenticated = true; received.packets.push(data);
            }
        }
        if received.authenticated { self.peers[index].endpoint = Some(source); }
        // Drain the engine's bounded queue after completing a handshake.
        for _ in 0..256 {
            match Output::from(self.peers[index].tunnel.decapsulate(None, &[], buffer)) {
                Output::Network(data) => {
                    if let Some(endpoint) = self.peers[index].endpoint { received.network.push((endpoint, data)); }
                }
                _ => break,
            }
        }
        received
    }

    fn encapsulate(&mut self, mut packet: Vec<u8>, buffer: &mut [u8]) -> Option<(SocketAddr, Vec<u8>)> {
        if packet.len() > self.config.mtu { return None; }
        let destination = Tunn::dst_address(&packet)?;
        let index = route_peer(&self.config, destination)?;
        let peer = &mut self.peers[index];
        let endpoint = peer.endpoint?;
        // BoringTun's engine does not add the spec's optional transport padding.
        // Pad before AEAD, bounded by MTU, as wireguard-go does.
        packet.resize(packet.len().next_multiple_of(16).min(self.config.mtu), 0);
        match Output::from(peer.tunnel.encapsulate(&packet, buffer)) {
            Output::Network(data) => Some((endpoint, data)), _ => None,
        }
    }

    fn timers(&mut self, buffer: &mut [u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        self.discovery.reset_count();
        self.peers.iter_mut().filter_map(|peer| match Output::from(peer.tunnel.update_timers(buffer)) {
            Output::Network(data) => peer.endpoint.map(|endpoint| (endpoint, data)), _ => None,
        }).collect()
    }
}

pub(crate) fn route_peer(config: &ValidatedConfig, address: IpAddr) -> Option<usize> {
    config.peers.iter().enumerate().flat_map(|(index, peer)| peer.allowed_ips.iter().filter_map(move |prefix| {
        prefix.contains(&address).then_some((prefix.prefix_len(), index))
    })).max().map(|(_, index)| index)
}

#[allow(clippy::too_many_arguments)]
async fn run_device(inner: Weak<DeviceInner>, sockets: UdpSockets, mut noise: NoisePeers,
    notify: Arc<Notify>, cancellation: CancellationToken, counters: Arc<Counters>,
    tcp_tx: mpsc::Sender<(WireGuardTcpStream, SocketAddr, SocketAddr)>, udp_tx: mpsc::Sender<IncomingUdp>) {
    let started = Instant::now();
    let mut timer = tokio::time::interval(Duration::from_millis(10));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_noise_tick = Instant::now() - Duration::from_secs(1);
    let mut buffer = vec![0; MAX_DATAGRAM + 64];
    let (mut incoming4, mut incoming6) = (vec![0; MAX_DATAGRAM], vec![0; MAX_DATAGRAM]);
    loop {
        let mut network = Vec::new();
        let Some(device) = inner.upgrade() else { break; };
        if cancellation.is_cancelled() { break; }
        let (packets, accepted, datagrams) = {
            let mut stack = device.stack();
            let packets = stack.poll(smoltcp::time::Instant::from_millis(started.elapsed().as_millis() as i64));
            (packets, stack.take_tcp(), stack.take_udp())
        };
        for AcceptedTcp { handle, source, destination } in accepted {
            let stream = WireGuardTcpStream::new(device.clone(), handle);
            let _ = tcp_tx.try_send((stream, source, destination));
        }
        for datagram in datagrams { let _ = udp_tx.try_send(datagram); }
        for packet in packets { if let Some(packet) = noise.encapsulate(packet, &mut buffer) { network.push(packet); } }
        if last_noise_tick.elapsed() >= Duration::from_millis(100) {
            network.extend(noise.timers(&mut buffer)); last_noise_tick = Instant::now();
        }
        // Do not retain the device over an await: its final owner must be able to
        // drop it and cancel all UDP/timer work without a reference cycle.
        drop(device);
        for (endpoint, mut packet) in network {
            packet[1..4].copy_from_slice(&noise.config.reserved);
            let sent = tokio::select! { biased; _ = cancellation.cancelled() => break, result = sockets.send(&packet, endpoint) => result };
            if sent.is_ok() { counters.sent.fetch_add(1, Ordering::Relaxed); }
            else { counters.rejected.fetch_add(1, Ordering::Relaxed); }
        }
        let incoming = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            result = receive(&sockets.v4, &mut incoming4) => result.map(|(n, source)| (false, n, source)),
            result = receive(&sockets.v6, &mut incoming6) => result.map(|(n, source)| (true, n, source)),
            _ = notify.notified() => continue,
            _ = timer.tick() => continue,
        };
        let Ok((v6, n, source)) = incoming else { break; };
        counters.received.fetch_add(1, Ordering::Relaxed);
        let datagram = if v6 { &mut incoming6[..n] } else { &mut incoming4[..n] };
        let received = noise.receive(source, datagram, &mut buffer);
        if received.authenticated { counters.authenticated.fetch_add(1, Ordering::Relaxed); }
        else { counters.rejected.fetch_add(1, Ordering::Relaxed); }
        if let Some(device) = inner.upgrade() {
            let mut stack = device.stack();
            for packet in received.packets { stack.ingest(packet); }
        }
        for (endpoint, mut packet) in received.network {
            packet[1..4].copy_from_slice(&noise.config.reserved);
            let sent = tokio::select! { biased; _ = cancellation.cancelled() => break, result = sockets.send(&packet, endpoint) => result };
            if sent.is_ok() { counters.sent.fetch_add(1, Ordering::Relaxed); }
        }
    }
    if let Some(device) = inner.upgrade() { device.stack().shutdown(); }
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
