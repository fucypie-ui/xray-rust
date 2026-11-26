//! Packet-preserving adapters using the upstream classic AEAD implementation.
use super::runtime;
use crate::common::{
    errors::{Error, Result},
    net::{Address, Destination, Network, datagram::{BoxDatagram, Datagram, DatagramTransport, MAX_DATAGRAM_SIZE}},
    protocol::SessionContext,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use shadowsocks::{
    ServerConfig, context::SharedContext, crypto::v1::Cipher,
    relay::udprelay::{crypto_io::encrypt_client_payload, options::UdpSocketControlData},
};
use std::{net::SocketAddr, sync::{Arc, Mutex, Weak}};
use tokio::{net::UdpSocket, sync::watch};

#[derive(Clone)]
pub(super) struct Closed(watch::Sender<bool>);
impl Default for Closed {
    fn default() -> Self { Self(watch::channel(false).0) }
}
impl Closed {
    pub fn cancel(&self) { self.0.send_replace(true); }
    pub fn is_cancelled(&self) -> bool { *self.0.borrow() }
    pub async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|closed| *closed).await;
    }
}

#[derive(Default)]
pub(super) struct OutboundState {
    closed: Closed,
    associations: Mutex<Vec<Weak<Outbound>>>,
}
impl OutboundState {
    pub fn is_closed(&self) -> bool { self.closed.is_cancelled() }
    pub async fn cancelled(&self) { self.closed.cancelled().await; }
    pub fn close(&self) {
        self.closed.cancel();
        let mut associations = self.associations.lock().unwrap_or_else(|error| error.into_inner());
        for association in associations.drain(..).filter_map(|weak| weak.upgrade()) { association.stop(); }
    }
    fn register(&self, association: &Arc<Outbound>) -> Result<()> {
        let mut associations = self.associations.lock().map_err(|_| Error::Other("Shadowsocks association lock poisoned".into()))?;
        if self.is_closed() { association.stop(); return Err(Error::Closed); }
        associations.retain(|association| association.strong_count() != 0);
        associations.push(Arc::downgrade(association));
        Ok(())
    }
}
impl Drop for OutboundState { fn drop(&mut self) { self.close(); } }

#[derive(Clone)]
pub(super) struct Codec {
    config: Arc<ServerConfig>,
    context: SharedContext,
}
impl Codec {
    pub fn new(method: &str, password: &str, context: SharedContext) -> Result<Self> {
        Ok(Self { config: Arc::new(runtime::account(method, password)?), context })
    }
    pub fn encode(&self, destination: &Destination, payload: &[u8]) -> Result<BytesMut> {
        if payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        if destination.network != Network::Udp {
            return Err(Error::Protocol("Shadowsocks packet destination must use UDP".into()));
        }
        let address = runtime::address(destination)?;
        let method = self.config.method();
        let length = method.salt_len() + address.serialized_len() + payload.len() + method.tag_len();
        if length > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        let mut wire = BytesMut::with_capacity(length);
        // Classic AEAD has identical request and response packet formats.
        encrypt_client_payload(&self.context, method, self.config.key(), &address,
            &UdpSocketControlData::default(), &[], payload, &mut wire);
        Ok(wire)
    }
    pub fn decode(&self, wire: &[u8]) -> Result<(Destination, Bytes)> {
        if wire.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        let method = self.config.method();
        let salt_len = method.salt_len();
        let tag_len = method.tag_len();
        if wire.len() < salt_len + tag_len + 1 {
            return Err(Error::Protocol("truncated Shadowsocks UDP packet".into()));
        }
        let (salt, encrypted) = wire.split_at(salt_len);
        let mut plaintext = encrypted.to_vec();
        // Use the maintained engine's Cipher for authentication and subkey /
        // nonce handling. Its UDP address reader in 1.25.0 can panic on an
        // authenticated domain missing its port, so parse the address below.
        // No local AEAD, password KDF, subkey KDF or nonce counter is used.
        let mut cipher = Cipher::new(method, self.config.key(), salt);
        if !cipher.decrypt_packet(&mut plaintext) {
            return Err(Error::AuthFailed("Shadowsocks UDP authentication failed".into()));
        }
        plaintext.truncate(plaintext.len() - tag_len);
        let (destination, offset) = packet_address(&plaintext)?;
        // Upstream UDP deliberately omits replay filtering. Apply its shared
        // public replay protector only after authentication and safe parsing.
        self.context.check_nonce_replay(method, salt)?;
        Ok((destination, Bytes::copy_from_slice(&plaintext[offset..])))
    }
}

fn packet_address(packet: &[u8]) -> Result<(Destination, usize)> {
    let truncated = || Error::Protocol("truncated Shadowsocks UDP address".into());
    let atyp = *packet.first().ok_or_else(truncated)? & 0x0f;
    let (address, offset) = match atyp {
        1 => {
            let bytes = packet.get(1..5).ok_or_else(truncated)?;
            (Address::Ipv4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])), 5)
        }
        4 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(packet.get(1..17).ok_or_else(truncated)?);
            (Address::Ipv6(bytes.into()), 17)
        }
        3 => {
            let length = usize::from(*packet.get(1).ok_or_else(truncated)?);
            if length == 0 { return Err(Error::Protocol("empty Shadowsocks UDP domain".into())); }
            let domain = std::str::from_utf8(packet.get(2..2 + length).ok_or_else(truncated)?)
                .map_err(|_| Error::Protocol("invalid Shadowsocks UDP domain encoding".into()))?;
            (Address::Domain(domain.into()), 2 + length)
        }
        _ => return Err(Error::Protocol(format!("unsupported Shadowsocks UDP address type: {atyp}"))),
    };
    let port = packet.get(offset..offset + 2).ok_or_else(truncated)?;
    Ok((Destination::udp(address, u16::from_be_bytes([port[0], port[1]])), offset + 2))
}

struct ReplyAddress {
    source: Option<Destination>,
    fallback: Destination,
}
impl ReplyAddress {
    fn new(session: &SessionContext, local_addr: SocketAddr) -> Self {
        Self { source: None, fallback: udp_destination(session.source.unwrap_or(local_addr)) }
    }
    fn remember(&mut self, source: Option<Destination>) -> Result<()> {
        if let Some(source) = source {
            if source.network != Network::Udp { return Err(Error::Protocol("Shadowsocks UDP source must use UDP".into())); }
            if self.source.as_ref().is_some_and(|original| original != &source) {
                return Err(Error::Protocol("Shadowsocks UDP association cannot mix local sources".into()));
            }
            self.source = Some(source);
        }
        Ok(())
    }
    fn destination(&self) -> Destination { self.source.as_ref().unwrap_or(&self.fallback).clone() }
}

struct Outbound {
    socket: Mutex<Option<Arc<UdpSocket>>>,
    codec: Codec,
    reply: Mutex<ReplyAddress>,
    closed: Closed,
}
impl Outbound {
    fn stop(&self) {
        self.closed.cancel();
        self.socket.lock().unwrap_or_else(|error| error.into_inner()).take();
    }
    fn socket(&self) -> Result<Arc<UdpSocket>> {
        self.socket.lock().map_err(|_| Error::Other("Shadowsocks UDP socket lock poisoned".into()))?
            .clone().ok_or(Error::Closed)
    }
}
impl Drop for Outbound { fn drop(&mut self) { self.stop(); } }

pub(super) async fn connect(
    server: &Destination, method: &str, password: &str,
    context: SharedContext, session: &SessionContext, state: &OutboundState,
) -> Result<BoxDatagram> {
    if state.is_closed() { return Err(Error::Closed); }
    if session.destination.network != Network::Udp {
        return Err(Error::Protocol("Shadowsocks datagram connect requires UDP".into()));
    }
    let codec = Codec::new(method, password, context)?;
    runtime::address(server)?;
    runtime::address(&session.destination)?;
    if server.port == 0 { return Err(Error::Config("Shadowsocks server port must be nonzero".into())); }
    let remotes = match server.to_socket_addr() {
        Some(address) => vec![address],
        None => crate::transport::internet::dialer::lookup_for_ip(&server.address.to_string(), server.port).await?,
    };
    let mut error = None;
    for remote in remotes {
        let local = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(local).await?;
        match socket.connect(remote).await {
            Ok(()) => {
                let reply = ReplyAddress::new(session, socket.local_addr()?);
                let association = Arc::new(Outbound {
                    socket: Mutex::new(Some(Arc::new(socket))), codec,
                    reply: Mutex::new(reply), closed: Closed::default(),
                });
                state.register(&association)?;
                return Ok(association);
            }
            Err(failed) => error = Some(failed),
        }
    }
    Err(error.map(Error::Io).unwrap_or_else(|| Error::AddressParse("Shadowsocks UDP server resolved to no addresses".into())))
}

#[async_trait]
impl DatagramTransport for Outbound {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let socket = self.socket();
        if self.closed.is_cancelled() { return Ok(None); }
        let socket = socket?;
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
        loop {
            let length = tokio::select! {
                biased;
                _ = self.closed.cancelled() => return Ok(None),
                received = socket.recv(&mut buffer) => received?,
            };
            let (source, payload) = match self.codec.decode(&buffer[..length]) {
                Ok(packet) => packet,
                Err(_) => continue, // Invalid packets do not close a healthy association.
            };
            let destination = self.reply.lock().map_err(|_| Error::Other("Shadowsocks UDP reply lock poisoned".into()))?.destination();
            return Ok(Some(Datagram { payload, source: Some(source), destination }));
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        let wire = self.codec.encode(&packet.destination, &packet.payload)?;
        self.reply.lock().map_err(|_| Error::Other("Shadowsocks UDP reply lock poisoned".into()))?.remember(packet.source)?;
        let socket = self.socket()?;
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(Error::Closed),
            written = socket.send(&wire) => check_send(written?, wire.len()),
        }
    }
    async fn close(&self) -> Result<()> {
        self.stop();
        Ok(())
    }
}

pub(super) fn udp_destination(address: SocketAddr) -> Destination {
    Destination::udp(address.ip().into(), address.port())
}

pub(super) fn check_send(written: usize, length: usize) -> Result<()> {
    if written != length {
        return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short Shadowsocks UDP send").into());
    }
    Ok(())
}
