//! Bounded UDP replay/session state. Packet authentication precedes state mutation.
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use rand::{RngExt, TryRng};
use crate::common::{net::Destination, protocol::User};
use super::{cipher::{CipherMethod, invalid_data}, packet::{DecodedPacket, PacketCodec, PACKET_NONCE_SIZE}, protocol::{HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER}, stream::{unix_time, MAX_PADDING_LENGTH}};

#[derive(Clone)]
pub struct SlidingWindow { last: u64, ring: [u64; 128] }
impl Default for SlidingWindow { fn default() -> Self { Self { last: 0, ring: [0; 128] } } }
impl SlidingWindow {
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last { return true; }
        if self.last - counter > 8128 { return false; }
        self.ring[((counter >> 6) & 127) as usize] & (1 << (counter & 63)) == 0
    }
    pub fn check_and_add(&mut self, counter: u64) -> bool {
        if !self.check(counter) { return false; }
        let block = counter >> 6;
        if counter > self.last {
            let last_block = self.last >> 6;
            for advance in 1..=(block - last_block).min(128) { self.ring[((last_block + advance) & 127) as usize] = 0; }
            self.last = counter;
        }
        self.ring[(block & 127) as usize] |= 1 << (counter & 63);
        true
    }
}

fn random_u64() -> io::Result<u64> {
    let mut bytes = [0; 8];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes).map_err(io::Error::other)?;
    Ok(u64::from_be_bytes(bytes))
}
fn random_nonce() -> io::Result<[u8; PACKET_NONCE_SIZE]> {
    let mut nonce = [0; PACKET_NONCE_SIZE];
    rand::rngs::SysRng.try_fill_bytes(&mut nonce).map_err(io::Error::other)?;
    Ok(nonce)
}

struct PeerState { session_id: u64, last_seen: u64, window: SlidingWindow }

pub struct ClientUdpSession {
    codec: PacketCodec,
    session_id: u64,
    next_packet_id: Option<u64>,
    current: Option<PeerState>,
    old: Option<PeerState>,
}
impl ClientUdpSession {
    pub fn new(method: CipherMethod, psks: Vec<Vec<u8>>) -> io::Result<Self> { Self::with_session_id(method, psks, random_u64()?) }
    pub fn with_session_id(method: CipherMethod, psks: Vec<Vec<u8>>, session_id: u64) -> io::Result<Self> {
        Ok(Self { codec: PacketCodec::new(method, psks)?, session_id, next_packet_id: Some(0), current: None, old: None })
    }
    pub fn session_id(&self) -> u64 { self.session_id }
    pub fn encode(&mut self, destination: Destination, payload: &[u8]) -> io::Result<Vec<u8>> {
        let padding_length = if destination.port == 53 && payload.len() < MAX_PADDING_LENGTH { rand::rng().random_range(1..=(MAX_PADDING_LENGTH - payload.len())) } else { 0 };
        self.encode_at(destination, payload, unix_time()?, &vec![0; padding_length], &random_nonce()?)
    }
    pub fn encode_at(&mut self, destination: Destination, payload: &[u8], now: u64, padding: &[u8], nonce: &[u8; PACKET_NONCE_SIZE]) -> io::Result<Vec<u8>> {
        if payload.len() > super::packet::MAX_DATAGRAM_SIZE { return Err(invalid_data("UDP payload too large")); }
        let packet_id = self.next_packet_id.ok_or_else(|| invalid_data("UDP packet ID exhausted"))?;
        // Reserve before returning ciphertext; cancellation must never reuse IDs.
        self.next_packet_id = packet_id.checked_add(1);
        self.codec.encode_at(&DecodedPacket { session_id: self.session_id, packet_id, header_type: HEADER_TYPE_CLIENT, timestamp: now, client_session_id: None, destination, payload: payload.to_vec() }, padding, nonce)
    }
    pub fn decode(&mut self, wire: &[u8]) -> io::Result<DecodedPacket> { self.decode_at(wire, unix_time()?) }
    pub fn decode_at(&mut self, wire: &[u8], now: u64) -> io::Result<DecodedPacket> {
        let packet = self.codec.decode_at(wire, HEADER_TYPE_SERVER, now)?;
        if packet.client_session_id != Some(self.session_id) { return Err(invalid_data("UDP client session ID mismatch")); }
        let is_current = self.current.as_ref().is_some_and(|peer| peer.session_id == packet.session_id);
        let is_old = self.old.as_ref().is_some_and(|peer| peer.session_id == packet.session_id);
        if is_old && self.old.as_ref().is_some_and(|old| now.saturating_sub(old.last_seen) > 60) {
            return Err(invalid_data("old UDP server session expired"));
        }
        let peer = if is_current {
            self.current.as_mut().ok_or_else(|| invalid_data("missing current UDP peer"))?
        } else if is_old {
            self.old.as_mut().ok_or_else(|| invalid_data("missing old UDP peer"))?
        } else {
            if self.old.as_ref().is_some_and(|old| now.saturating_sub(old.last_seen) < 60) { return Err(invalid_data("UDP server rotated sessions too quickly")); }
            self.old = self.current.take();
            self.current = Some(PeerState { session_id: packet.session_id, last_seen: now, window: SlidingWindow::default() });
            self.current.as_mut().ok_or_else(|| invalid_data("missing new UDP peer"))?
        };
        if !peer.window.check_and_add(packet.packet_id) { return Err(invalid_data("UDP packet ID not unique")); }
        peer.last_seen = now;
        Ok(packet)
    }
}

#[derive(Debug, Clone)]
// Pointer identity binds a token to one handler and one live session generation.
// Reusing a client ID after expiry cannot redirect an earlier request's replies.
pub struct ReplyToken { session_id: u64, binding: Arc<()> }
impl ReplyToken {
    pub(crate) fn same_session(&self, other: &Self) -> bool { self.session_id == other.session_id && Arc::ptr_eq(&self.binding, &other.binding) }
}

pub struct InboundDatagram {
    pub packet: DecodedPacket,
    pub remote: SocketAddr,
    pub user: Option<User>,
    pub reply: ReplyToken,
}
struct ServerState {
    key: Vec<u8>, user: Option<User>, remote: SocketAddr, last_seen: u64,
    window: SlidingWindow, server_id: u64, next_packet_id: Option<u64>, binding: Arc<()>,
}

pub(crate) struct ServerUdpSessions { method: CipherMethod, sessions: HashMap<u64, ServerState>, last_cleanup: Option<u64> }
impl ServerUdpSessions {
    pub fn new(method: CipherMethod) -> Self { Self { method, sessions: HashMap::new(), last_cleanup: None } }
    pub fn accept_at(&mut self, packet: DecodedPacket, key: Vec<u8>, user: Option<User>, remote: SocketAddr, now: u64) -> io::Result<InboundDatagram> {
        if packet.header_type != HEADER_TYPE_CLIENT || packet.client_session_id.is_some() || key.len() != self.method.key_length() { return Err(invalid_data("invalid UDP client session")); }
        if self.last_cleanup.is_none_or(|last| now.saturating_sub(last) >= 30) || self.sessions.len() >= 65_536 {
            self.sessions.retain(|_, session| now.saturating_sub(session.last_seen) <= 500);
            self.last_cleanup = Some(now);
        }
        if self.sessions.get(&packet.session_id).is_some_and(|session| now.saturating_sub(session.last_seen) > 500) {
            self.sessions.remove(&packet.session_id);
        }
        if !self.sessions.contains_key(&packet.session_id) {
            if self.sessions.len() >= 65_536 { return Err(invalid_data("UDP session capacity reached")); }
            let mut server_id = random_u64()?;
            while server_id == 0 { server_id = random_u64()?; }
            self.sessions.insert(packet.session_id, ServerState { key: key.clone(), user: user.clone(), remote, last_seen: now, window: SlidingWindow::default(), server_id, next_packet_id: Some(0), binding: Arc::new(()) });
        }
        let state = self.sessions.get_mut(&packet.session_id).ok_or_else(|| invalid_data("missing UDP session"))?;
        if state.key != key { return Err(invalid_data("UDP session belongs to another identity")); }
        if !state.window.check_and_add(packet.packet_id) { return Err(invalid_data("UDP packet ID not unique")); }
        state.remote = remote;
        state.last_seen = now;
        let reply = ReplyToken { session_id: packet.session_id, binding: Arc::clone(&state.binding) };
        Ok(InboundDatagram { packet, remote, user: state.user.clone(), reply })
    }
    pub fn reply(&mut self, token: &ReplyToken, source: Destination, payload: &[u8]) -> io::Result<(SocketAddr, Vec<u8>)> {
        self.reply_at(token, source, payload, unix_time()?, &random_nonce()?)
    }
    fn reply_at(&mut self, token: &ReplyToken, source: Destination, payload: &[u8], now: u64, nonce: &[u8; PACKET_NONCE_SIZE]) -> io::Result<(SocketAddr, Vec<u8>)> {
        if payload.len() > super::packet::MAX_DATAGRAM_SIZE { return Err(invalid_data("UDP response payload too large")); }
        let state = self.sessions.get_mut(&token.session_id).filter(|state| now.saturating_sub(state.last_seen) <= 500 && Arc::ptr_eq(&state.binding, &token.binding)).ok_or_else(|| invalid_data("UDP reply session expired or token belongs to another session"))?;
        let packet_id = state.next_packet_id.ok_or_else(|| invalid_data("UDP response packet ID exhausted"))?;
        state.next_packet_id = packet_id.checked_add(1);
        let packet = DecodedPacket { session_id: state.server_id, packet_id, header_type: HEADER_TYPE_SERVER, timestamp: now, client_session_id: Some(token.session_id), destination: source, payload: payload.to_vec() };
        let codec = PacketCodec::new(self.method, vec![state.key.clone()])?;
        Ok((state.remote, codec.encode_at(&packet, &[], nonce)?))
    }
}

/// Real connected UDP association for integration by the shared outbound runtime.
/// Each send/recv operation preserves one datagram; no bridge tasks are spawned.
pub struct UdpAssociation {
    shared: Arc<AssociationSocket>,
    session: std::sync::Mutex<ClientUdpSession>,
}
pub(super) struct AssociationSocket {
    socket: std::sync::Mutex<Option<Arc<tokio::net::UdpSocket>>>,
    closed: tokio_util::sync::CancellationToken,
}
impl AssociationSocket {
    pub(super) fn close(&self) {
        self.closed.cancel();
        self.socket.lock().unwrap_or_else(|error| error.into_inner()).take();
    }
}
impl UdpAssociation {
    pub async fn connect(server: &Destination, method: CipherMethod, psks: Vec<Vec<u8>>) -> io::Result<Self> {
        let session = ClientUdpSession::new(method, psks)?;
        let addresses = match server.to_socket_addr() {
            Some(address) => vec![address],
            None => crate::transport::internet::dialer::lookup_for_ip(&server.address.to_string(), server.port).await.map_err(io::Error::other)?,
        };
        let mut last_error = invalid_data("UDP server resolved to no addresses");
        for address in addresses {
            let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let socket = match tokio::net::UdpSocket::bind(bind).await {
                Ok(socket) => socket,
                Err(error) => { last_error = error; continue; }
            };
            match socket.connect(address).await {
                Ok(()) => return Ok(Self { shared: Arc::new(AssociationSocket { socket: std::sync::Mutex::new(Some(Arc::new(socket))), closed: tokio_util::sync::CancellationToken::new() }), session: std::sync::Mutex::new(session) }),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
    fn socket(&self) -> io::Result<Arc<tokio::net::UdpSocket>> {
        self.shared.socket.lock().map_err(|_| io::Error::other("UDP socket lock poisoned"))?.clone().ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "UDP association closed"))
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> { self.socket()?.local_addr() }
    pub fn is_closed(&self) -> bool { self.shared.closed.is_cancelled() }
    pub(super) fn downgrade(&self) -> std::sync::Weak<AssociationSocket> { Arc::downgrade(&self.shared) }
    /// Closing releases the owned socket and wakes pending receives and sends.
    /// A caller's cancelled send has already reserved its packet ID.
    pub fn close(&self) {
        self.shared.close();
    }
    pub(super) fn encode(&self, destination: Destination, payload: &[u8]) -> io::Result<Vec<u8>> {
        if self.is_closed() { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDP association closed")); }
        self.session.lock().map_err(|_| io::Error::other("UDP session lock poisoned"))?.encode(destination, payload)
    }
    pub async fn send(&self, destination: Destination, payload: &[u8]) -> io::Result<()> {
        let wire = self.encode(destination, payload)?;
        self.send_wire(&wire).await
    }
    pub(super) async fn send_wire(&self, wire: &[u8]) -> io::Result<()> {
        let socket = self.socket()?;
        let written = tokio::select! {
            biased;
            _ = self.shared.closed.cancelled() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDP association closed")),
            written = socket.send(wire) => written?,
        };
        if written != wire.len() { return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP datagram write")); }
        Ok(())
    }
    pub async fn recv(&self) -> io::Result<(Destination, Vec<u8>)> {
        let socket = self.socket()?;
        let mut wire = vec![0; super::packet::MAX_DATAGRAM_SIZE + 1];
        loop {
            let length = tokio::select! {
                biased;
                _ = self.shared.closed.cancelled() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDP association closed")),
                received = socket.recv(&mut wire) => received?,
            };
            let decoded = self.session.lock().map_err(|_| io::Error::other("UDP session lock poisoned"))?.decode(&wire[..length]);
            match decoded {
                Ok(packet) => return Ok((packet.destination, packet.payload)),
                Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::net::Network;

    fn packet(session_id: u64, packet_id: u64, now: u64) -> DecodedPacket {
        let mut destination = Destination::from_domain_port("example.com", 443);
        destination.network = Network::Udp;
        DecodedPacket {
            session_id, packet_id, header_type: HEADER_TYPE_CLIENT,
            timestamp: now, client_session_id: None, destination, payload: b"ping".to_vec(),
        }
    }

    #[test]
    fn ss2022_udp_reply_tokens_bind_handler_generation_and_authenticated_remote() {
        let method = CipherMethod::Aes128Gcm;
        let mut sessions = ServerUdpSessions::new(method);
        let first_remote = "127.0.0.1:10001".parse().unwrap();
        let next_remote = "127.0.0.1:10002".parse().unwrap();
        let first = sessions.accept_at(packet(1, 0, 1000), vec![1; 16], None, first_remote, 1000).unwrap();
        // A replay from a new address cannot rebind the existing reply route.
        assert!(sessions.accept_at(packet(1, 0, 1000), vec![1; 16], None, next_remote, 1000).is_err());
        assert_eq!(sessions.reply_at(&first.reply, first.packet.destination.clone(), b"pong", 1000, &[0; 24]).unwrap().0, first_remote);
        sessions.accept_at(packet(1, 1, 1001), vec![1; 16], None, next_remote, 1001).unwrap();
        assert_eq!(sessions.reply_at(&first.reply, first.packet.destination.clone(), b"pong", 1001, &[0; 24]).unwrap().0, next_remote);
        // Tokens from another handler are rejected even with identical IDs/key.
        let mut other = ServerUdpSessions::new(method);
        other.accept_at(packet(1, 0, 1001), vec![1; 16], None, first_remote, 1001).unwrap();
        assert!(other.reply_at(&first.reply, first.packet.destination.clone(), b"pong", 1001, &[0; 24]).is_err());
        // Reusing an expired client ID creates a distinct generation.
        assert!(sessions.reply_at(&first.reply, first.packet.destination.clone(), b"pong", 1502, &[0; 24]).is_err());
        let replacement = sessions.accept_at(packet(1, 0, 1502), vec![1; 16], None, first_remote, 1502).unwrap();
        assert!(sessions.reply_at(&first.reply, first.packet.destination.clone(), b"pong", 1502, &[0; 24]).is_err());
        assert!(sessions.reply_at(&replacement.reply, replacement.packet.destination, b"pong", 1502, &[0; 24]).is_ok());
    }

    #[test]
    fn ss2022_udp_counter_exhaustion_never_reuses_packet_ids() {
        for method in [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm, CipherMethod::ChaCha20Poly1305] {
            let key = vec![1; method.key_length()];
            let codec = PacketCodec::new(method, vec![key.clone()]).unwrap();
            let mut client = ClientUdpSession::with_session_id(method, vec![key.clone()], 10).unwrap();
            client.next_packet_id = Some(u64::MAX);
            let destination = packet(10, 0, 1000).destination;
            let wire = client.encode_at(destination.clone(), b"last", 1000, &[], &[1; 24]).unwrap();
            assert_eq!(codec.decode_at(&wire, HEADER_TYPE_CLIENT, 1000).unwrap().packet_id, u64::MAX);
            assert!(client.encode_at(destination.clone(), b"again", 1000, &[], &[2; 24]).is_err());
            let mut sessions = ServerUdpSessions::new(method);
            let incoming = sessions.accept_at(packet(10, 0, 1000), key, None, "127.0.0.1:10000".parse().unwrap(), 1000).unwrap();
            sessions.sessions.get_mut(&10).unwrap().next_packet_id = Some(u64::MAX);
            let (_, wire) = sessions.reply_at(&incoming.reply, destination.clone(), b"last", 1000, &[3; 24]).unwrap();
            assert_eq!(codec.decode_at(&wire, HEADER_TYPE_SERVER, 1000).unwrap().packet_id, u64::MAX);
            assert!(sessions.reply_at(&incoming.reply, destination, b"again", 1000, &[4; 24]).is_err());
        }
    }
}
