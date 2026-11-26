//! WireGuard-local IP stack. This deliberately shares no state with proxy/tun.
use std::{
    collections::{HashMap, HashSet, VecDeque}, future::poll_fn, io,
    net::{IpAddr, SocketAddr}, pin::Pin, sync::Arc,
    task::{Context, Poll, Waker}, time::{Duration, Instant},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, Device, DeviceCapabilities, Medium},
    socket::{Socket, tcp, udp}, time::Instant as StackInstant,
    wire::{HardwareAddress, IpCidr, UdpPacket},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use super::{config::ValidatedConfig, device::DeviceInner};

const MAX_SOCKETS: usize = 256;
const PACKET_QUEUE: usize = 256;
const TCP_BUFFER: usize = 64 * 1024;
const UDP_BUFFER: usize = 128 * 1024;

pub(crate) fn io_error(message: impl Into<String>) -> io::Error { io::Error::other(message.into()) }
fn closed() -> io::Error { io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard device closed") }

pub(crate) struct PacketDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    mtu: usize,
}

pub(crate) struct RxToken(Vec<u8>);
pub(crate) struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R { f(&self.0) }
}
impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= PACKET_QUEUE { return None; }
        self.incoming.pop_front().map(|packet| (RxToken(packet), TxToken(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Self::TxToken<'_>> {
        (self.outgoing.len() < PACKET_QUEUE).then_some(TxToken(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(PACKET_QUEUE);
        caps
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey { source: SocketAddr, destination: SocketAddr }
pub(crate) struct AcceptedTcp {
    pub handle: SocketHandle, pub source: SocketAddr, pub destination: SocketAddr,
}
pub(crate) struct IncomingUdp {
    pub data: Vec<u8>, pub source: SocketAddr, pub destination: SocketAddr,
}

pub(crate) struct Stack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    device: PacketDevice,
    addresses: Vec<IpAddr>,
    next_port: u16,
    ports: HashMap<SocketHandle, u16>,
    released_tcp: HashSet<SocketHandle>,
    pending_tcp: HashMap<FlowKey, (SocketHandle, Instant)>,
    server_udp: HashMap<SocketAddr, (SocketHandle, Instant)>,
    next_fragment_id: u32,
    fragment_wakers: Vec<Waker>,
    server: bool,
    pub closed: bool,
}

impl Stack {
    pub fn new(config: &ValidatedConfig, server: bool, seed: u64) -> io::Result<Self> {
        if server && config.addresses.len() == 8 {
            return Err(io_error("WireGuard server supports at most seven base addresses; one slot is reserved for IPv6 forwarding"));
        }
        let mut device = PacketDevice { incoming: VecDeque::new(), outgoing: VecDeque::new(), mtu: config.mtu };
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = seed;
        let mut iface = Interface::new(iface_config, &mut device, StackInstant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            for ip in &config.addresses {
                // Configuration validation bounds address count to the requested feature capacity.
                let _ = addresses.push(IpCidr::new((*ip).into(), if ip.is_ipv4() { 32 } else { 128 }));
            }
        });
        // A layer-3 device has no ARP/NDP; these gateways select the tunnel route.
        if let Some(ip) = config.addresses.iter().find_map(|ip| if let IpAddr::V4(ip) = ip { Some(*ip) } else { None }) {
            iface.routes_mut().add_default_ipv4_route(ip).map_err(|e| io_error(e.to_string()))?;
        }
        if let Some(ip) = config.addresses.iter().find_map(|ip| if let IpAddr::V6(ip) = ip { Some(*ip) } else { None }) {
            iface.routes_mut().add_default_ipv6_route(ip).map_err(|e| io_error(e.to_string()))?;
        }
        iface.set_any_ip(server);
        Ok(Self { iface, sockets: SocketSet::new(Vec::new()), device,
            addresses: config.addresses.clone(), next_port: 49152 + (seed % 16384) as u16,
            ports: HashMap::new(), released_tcp: HashSet::new(), pending_tcp: HashMap::new(),
            server_udp: HashMap::new(), next_fragment_id: seed as u32, fragment_wakers: Vec::new(), server, closed: false })
    }

    fn ensure_capacity(&self) -> io::Result<()> {
        if self.closed { return Err(closed()); }
        if self.sockets.iter().count() >= MAX_SOCKETS {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "WireGuard socket limit reached"));
        }
        Ok(())
    }

    fn local_endpoint(&mut self, destination: SocketAddr) -> io::Result<SocketAddr> {
        let ip = *self.addresses.iter().find(|ip| ip.is_ipv4() == destination.is_ipv4())
            .ok_or_else(|| io_error("no WireGuard interface address for destination family"))?;
        for _ in 0..16384 {
            let port = self.next_port;
            self.next_port = if port == u16::MAX { 49152 } else { port + 1 };
            if !self.ports.values().any(|allocated| *allocated == port)
                && !self.server_udp.keys().any(|endpoint| endpoint.port() == port) {
                return Ok(SocketAddr::new(ip, port));
            }
        }
        Err(io_error("WireGuard ephemeral ports exhausted"))
    }

    pub fn connect_tcp(&mut self, destination: SocketAddr) -> io::Result<SocketHandle> {
        self.ensure_capacity()?;
        let local = self.local_endpoint(destination)?;
        let mut socket = tcp_socket();
        socket.connect(self.iface.context(), destination, local).map_err(|e| io_error(e.to_string()))?;
        let handle = self.sockets.add(socket);
        self.ports.insert(handle, local.port());
        Ok(handle)
    }

    pub fn connect_udp(&mut self, destination: SocketAddr) -> io::Result<SocketHandle> {
        self.ensure_capacity()?;
        let local = self.local_endpoint(destination)?;
        let mut socket = udp_socket();
        socket.bind(local).map_err(|e| io_error(e.to_string()))?;
        let handle = self.sockets.add(socket);
        self.ports.insert(handle, local.port());
        Ok(handle)
    }

    pub fn ingest(&mut self, packet: Vec<u8>) {
        if self.closed || self.device.incoming.len() >= PACKET_QUEUE { return; }
        if self.server { self.prepare_inbound(&packet); }
        self.device.incoming.push_back(packet);
    }

    fn prepare_inbound(&mut self, packet: &[u8]) {
        let Some((flow, protocol, syn)) = transport_header(packet) else { return; };
        if protocol == 6 && syn && !self.pending_tcp.contains_key(&flow) {
            // Established sockets already own this exact tuple. A retransmitted SYN
            // must not create a second listener or steal the existing connection.
            if self.sockets.iter().any(|(_, socket)| matches!(socket, Socket::Tcp(tcp)
                if tcp.local_endpoint() == Some(flow.destination.into())
                    && tcp.remote_endpoint() == Some(flow.source.into()))) { return; }
            if self.ensure_capacity().is_err() { return; }
            let mut socket = tcp_socket();
            if socket.listen(flow.destination).is_ok() {
                let handle = self.sockets.add(socket);
                self.pending_tcp.insert(flow, (handle, Instant::now()));
            }
        } else if protocol == 17 {
            if let Some((_, last_activity)) = self.server_udp.get_mut(&flow.destination) {
                *last_activity = Instant::now();
            } else if self.ensure_capacity().is_ok() {
                let mut socket = udp_socket();
                if socket.bind(flow.destination).is_ok() {
                    let handle = self.sockets.add(socket);
                    self.server_udp.insert(flow.destination, (handle, Instant::now()));
                }
            }
        }
    }

    pub fn poll(&mut self, now: StackInstant) -> Vec<Vec<u8>> {
        if !self.closed {
            self.iface.poll_maintenance(now);
            while !self.device.incoming.is_empty() && self.device.outgoing.len() < PACKET_QUEUE {
                // smoltcp 0.14 AnyIP only forwards IPv4. Install a temporary
                // IPv6 destination alias for the packet currently being polled.
                // Socket endpoints remain explicit; no address ever escapes this
                // private userspace interface or changes host networking.
                if self.server {
                    if let Some(IpAddr::V6(destination)) = self.device.incoming.front().and_then(|packet| boringtun::noise::Tunn::dst_address(packet)) {
                        if !self.addresses.contains(&IpAddr::V6(destination)) {
                            let base = &self.addresses;
                            self.iface.update_ip_addrs(|addresses| {
                                addresses.retain(|cidr| base.contains(&cidr.address().into()));
                                let _ = addresses.push(IpCidr::new(destination.into(), 128));
                            });
                        }
                    }
                }
                self.iface.poll_ingress_single(now, &mut self.device, &mut self.sockets);
            }
            // Bound the amount of work and respect the packet queue capacity.
            for _ in 0..PACKET_QUEUE {
                if self.device.outgoing.len() >= PACKET_QUEUE { break; }
                if self.iface.poll_egress(now, &mut self.device, &mut self.sockets) == smoltcp::iface::PollResult::None { break; }
            }
        }
        self.cleanup();
        let outgoing = self.device.outgoing.drain(..).collect();
        for waker in self.fragment_wakers.drain(..) { waker.wake(); }
        outgoing
    }

    pub fn take_tcp(&mut self) -> Vec<AcceptedTcp> {
        let ready = self.pending_tcp.iter().filter_map(|(flow, (handle, _))| {
            let socket = self.sockets.get::<tcp::Socket<'_>>(*handle);
            matches!(socket.state(), tcp::State::Established | tcp::State::CloseWait)
                .then_some((*flow, *handle))
        }).collect::<Vec<_>>();
        ready.into_iter().map(|(flow, handle)| {
            self.pending_tcp.remove(&flow);
            AcceptedTcp { handle, source: flow.source, destination: flow.destination }
        }).collect()
    }

    pub fn take_udp(&mut self) -> Vec<IncomingUdp> {
        let mut packets = Vec::new();
        for (destination, (handle, _)) in &self.server_udp {
            let socket = self.sockets.get_mut::<udp::Socket<'_>>(*handle);
            while socket.can_recv() && packets.len() < PACKET_QUEUE {
                if let Ok((data, meta)) = socket.recv() {
                    packets.push(IncomingUdp { data: data.to_vec(), source: meta.endpoint.into(), destination: *destination });
                }
            }
        }
        packets
    }

    pub fn reply_udp(&mut self, source: SocketAddr, destination: SocketAddr, data: &[u8]) -> io::Result<()> {
        if self.closed { return Err(closed()); }
        if source.is_ipv6() && data.len() + 48 > self.device.mtu {
            return self.fragment_udp6(source, destination, data);
        }
        let (handle, active) = self.server_udp.get_mut(&source).ok_or_else(|| io_error("WireGuard UDP association expired"))?;
        *active = Instant::now();
        self.sockets.get_mut::<udp::Socket<'_>>(*handle).send_slice(data, destination)
            .map_err(|e| io_error(e.to_string()))
    }

    // smoltcp 0.14 reassembles IPv6 but does not emit IPv6 fragments. Adapt
    // only that missing egress operation using its vetted UDP checksum codec.
    // Every resulting IP fragment still traverses allowedIPs and Noise AEAD.
    fn fragment_udp6(&mut self, source: SocketAddr, destination: SocketAddr, data: &[u8]) -> io::Result<()> {
        let (SocketAddr::V6(source), SocketAddr::V6(destination)) = (source, destination) else {
            return Err(io_error("IPv6 UDP address-family mismatch"));
        };
        if data.len() > 65507 { return Err(io_error("UDP payload too large")); }
        let fragment_size = (self.device.mtu - 48) & !7;
        let total_len = data.len() + 8;
        let count = total_len.div_ceil(fragment_size);
        if self.device.outgoing.len() + count > PACKET_QUEUE {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WireGuard packet queue full"));
        }
        let mut udp = vec![0; total_len];
        {
            let mut packet = UdpPacket::new_unchecked(&mut udp[..]);
            packet.set_src_port(source.port()); packet.set_dst_port(destination.port());
            packet.set_len(total_len as u16); packet.payload_mut().copy_from_slice(data);
            packet.fill_checksum(&(*source.ip()).into(), &(*destination.ip()).into());
        }
        let id = self.next_fragment_id;
        self.next_fragment_id = self.next_fragment_id.wrapping_add(1);
        for (index, chunk) in udp.chunks(fragment_size).enumerate() {
            let offset = index * fragment_size;
            let mut packet = vec![0; 48 + chunk.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((chunk.len() + 8) as u16).to_be_bytes());
            packet[6] = 44; packet[7] = 64;
            packet[8..24].copy_from_slice(&source.ip().octets());
            packet[24..40].copy_from_slice(&destination.ip().octets());
            packet[40] = 17;
            let flags = offset as u16 | u16::from(offset + chunk.len() < total_len);
            packet[42..44].copy_from_slice(&flags.to_be_bytes());
            packet[44..48].copy_from_slice(&id.to_be_bytes());
            packet[48..].copy_from_slice(chunk);
            self.device.outgoing.push_back(packet);
        }
        Ok(())
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let expired_tcp = self.pending_tcp.iter().filter_map(|(flow, (handle, created))| {
            (now.duration_since(*created) > Duration::from_secs(30)
                || self.sockets.get::<tcp::Socket<'_>>(*handle).state() == tcp::State::Closed)
                .then_some((*flow, *handle))
        }).collect::<Vec<_>>();
        for (flow, handle) in expired_tcp {
            self.pending_tcp.remove(&flow);
            self.sockets.remove(handle);
        }
        let released = self.released_tcp.iter().copied().filter(|handle| {
            self.sockets.get::<tcp::Socket<'_>>(*handle).state() == tcp::State::Closed
        }).collect::<Vec<_>>();
        for handle in released {
            self.released_tcp.remove(&handle);
            self.ports.remove(&handle);
            self.sockets.remove(handle);
        }
        let expired_udp = self.server_udp.iter().filter_map(|(endpoint, (handle, active))| {
            (now.duration_since(*active) > Duration::from_secs(120)).then_some((*endpoint, *handle))
        }).collect::<Vec<_>>();
        for (endpoint, handle) in expired_udp {
            self.server_udp.remove(&endpoint);
            self.sockets.remove(handle);
        }
    }

    pub fn shutdown(&mut self) {
        self.closed = true;
        for waker in self.fragment_wakers.drain(..) { waker.wake(); }
        for (_, socket) in self.sockets.iter_mut() {
            if let Socket::Tcp(socket) = socket { socket.abort(); }
            else if let Socket::Udp(socket) = socket { socket.close(); }
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0; TCP_BUFFER]));
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    socket
}
fn udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; UDP_BUFFER]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; UDP_BUFFER]))
}

/// Inspect only the first fragment to provision a socket. smoltcp validates
/// checksums, extension headers, fragmentation and transport state itself.
fn transport_header(packet: &[u8]) -> Option<(FlowKey, u8, bool)> {
    let (source, destination, mut next, mut offset) = match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let offset = usize::from(packet[0] & 15) * 4;
            if offset < 20 || u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0 { return None; }
            (IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
                IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?), packet[9], offset)
        }
        6 if packet.len() >= 40 => (
            IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
            IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?), packet[6], 40),
        _ => return None,
    };
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let header = packet.get(offset..offset + 2)?;
                next = header[0]; offset += (usize::from(header[1]) + 1) * 8;
            }
            44 => {
                let header = packet.get(offset..offset + 8)?;
                if u16::from_be_bytes([header[2], header[3]]) & 0xfff8 != 0 { return None; }
                next = header[0]; offset += 8;
            }
            6 | 17 => {
                let ports = packet.get(offset..offset + 4)?;
                let source = SocketAddr::new(source, u16::from_be_bytes([ports[0], ports[1]]));
                let destination = SocketAddr::new(destination, u16::from_be_bytes([ports[2], ports[3]]));
                let syn = next == 6 && packet.get(offset + 13).is_some_and(|flags| flags & 0x12 == 0x02);
                return Some((FlowKey { source, destination }, next, syn));
            }
            _ => return None,
        }
    }
    None
}

struct SocketLease { inner: Arc<DeviceInner>, handle: SocketHandle, udp: bool }
impl Drop for SocketLease {
    fn drop(&mut self) {
        let mut stack = self.inner.stack();
        if self.udp {
            stack.sockets.remove(self.handle);
            stack.ports.remove(&self.handle);
        } else {
            stack.sockets.get_mut::<tcp::Socket<'_>>(self.handle).close();
            stack.released_tcp.insert(self.handle);
        }
        self.inner.notify.notify_one();
    }
}

pub struct WireGuardTcpStream { lease: SocketLease }
impl WireGuardTcpStream {
    pub(crate) fn new(inner: Arc<DeviceInner>, handle: SocketHandle) -> Self {
        Self { lease: SocketLease { inner, handle, udp: false } }
    }
    pub(crate) async fn established(&self) -> io::Result<()> {
        poll_fn(|cx| {
            let mut stack = self.lease.inner.stack();
            if stack.closed { return Poll::Ready(Err(closed())); }
            let socket = stack.sockets.get_mut::<tcp::Socket<'_>>(self.lease.handle);
            match socket.state() {
                tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                tcp::State::Closed => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "WireGuard TCP connection failed"))),
                _ => { socket.register_send_waker(cx.waker()); socket.register_recv_waker(cx.waker()); Poll::Pending }
            }
        }).await
    }
}
impl AsyncRead for WireGuardTcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 { return Poll::Ready(Ok(())); }
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        let socket = stack.sockets.get_mut::<tcp::Socket<'_>>(self.lease.handle);
        if socket.can_recv() {
            let n = socket.recv_slice(buffer.initialize_unfilled()).map_err(|e| io_error(e.to_string()))?;
            buffer.advance(n); self.lease.inner.notify.notify_one();
            Poll::Ready(Ok(()))
        } else if !socket.may_recv() { Poll::Ready(Ok(())) }
        else { socket.register_recv_waker(cx.waker()); Poll::Pending }
    }
}
impl AsyncWrite for WireGuardTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        let socket = stack.sockets.get_mut::<tcp::Socket<'_>>(self.lease.handle);
        if data.is_empty() { return Poll::Ready(Ok(0)); }
        if !socket.may_send() { return Poll::Ready(Err(closed())); }
        if socket.can_send() {
            let result = socket.send_slice(data).map_err(|e| io_error(e.to_string()));
            self.lease.inner.notify.notify_one(); Poll::Ready(result)
        } else { socket.register_send_waker(cx.waker()); Poll::Pending }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        let socket = stack.sockets.get_mut::<tcp::Socket<'_>>(self.lease.handle);
        if socket.send_queue() == 0 { Poll::Ready(Ok(())) }
        else if !socket.is_open() { Poll::Ready(Err(closed())) }
        else { socket.register_send_waker(cx.waker()); Poll::Pending }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        stack.sockets.get_mut::<tcp::Socket<'_>>(self.lease.handle).close();
        self.lease.inner.notify.notify_one(); Poll::Ready(Ok(()))
    }
}

/// Connected datagram socket. send/recv preserve packet boundaries and empty UDP
/// payloads. Its AsyncRead/AsyncWrite adapter follows the runtime's UDP BoxStream
/// convention: one write/one read is one datagram; use recv for empty datagrams.
pub struct WireGuardUdpSocket { lease: SocketLease, destination: SocketAddr }
impl WireGuardUdpSocket {
    pub(crate) fn new(inner: Arc<DeviceInner>, handle: SocketHandle, destination: SocketAddr) -> Self {
        Self { lease: SocketLease { inner, handle, udp: true }, destination }
    }
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> { poll_fn(|cx| self.poll_send(cx, data)).await }
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> { poll_fn(|cx| self.poll_recv(cx, buffer)).await }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let stack = self.lease.inner.stack();
        let endpoint = stack.sockets.get::<udp::Socket<'_>>(self.lease.handle).endpoint();
        Ok(SocketAddr::new(endpoint.addr.ok_or_else(|| io_error("WireGuard UDP socket has no local IP"))?.into(), endpoint.port))
    }
    pub(crate) fn poll_send(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.len() > 65507 { return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP payload too large"))); }
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        if self.destination.is_ipv6() && data.len() + 48 > stack.device.mtu {
            let endpoint = stack.sockets.get::<udp::Socket<'_>>(self.lease.handle).endpoint();
            let Some(local_ip) = endpoint.addr else { return Poll::Ready(Err(io_error("WireGuard UDP socket has no local IP"))); };
            let local = SocketAddr::new(local_ip.into(), endpoint.port);
            let result = stack.fragment_udp6(local, self.destination, data).map(|()| data.len());
            self.lease.inner.notify.notify_one();
            if result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock) {
                if !stack.fragment_wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    stack.fragment_wakers.push(cx.waker().clone());
                }
                return Poll::Pending;
            }
            return Poll::Ready(result);
        }
        let socket = stack.sockets.get_mut::<udp::Socket<'_>>(self.lease.handle);
        if socket.can_send() {
            let result = socket.send_slice(data, self.destination).map(|()| data.len()).map_err(|e| io_error(e.to_string()));
            self.lease.inner.notify.notify_one(); Poll::Ready(result)
        } else { socket.register_send_waker(cx.waker()); Poll::Pending }
    }
    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        let socket = stack.sockets.get_mut::<udp::Socket<'_>>(self.lease.handle);
        while socket.can_recv() {
            match socket.recv() {
                Ok((data, metadata)) if metadata.endpoint == self.destination.into() => {
                    if data.len() > buffer.len() { return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "UDP receive buffer too small"))); }
                    buffer[..data.len()].copy_from_slice(data);
                    return Poll::Ready(Ok(data.len()));
                }
                _ => {}
            }
        }
        socket.register_recv_waker(cx.waker()); Poll::Pending
    }
}
impl AsyncRead for WireGuardUdpSocket {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 { return Poll::Ready(Ok(())); }
        match self.poll_recv(cx, buffer.initialize_unfilled()) {
            Poll::Ready(Ok(n)) => { buffer.advance(n); Poll::Ready(Ok(())) }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)), Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for WireGuardUdpSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> { self.poll_send(cx, data) }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stack = self.lease.inner.stack();
        if stack.closed { return Poll::Ready(Err(closed())); }
        let socket = stack.sockets.get_mut::<udp::Socket<'_>>(self.lease.handle);
        if socket.send_queue() == 0 { Poll::Ready(Ok(())) }
        else { socket.register_send_waker(cx.waker()); Poll::Pending }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
