//! Hysteria UDP wire messages and per-session defragmentation.
use super::protocol::{MAX_ADDRESS_LENGTH, QuicVarint};
use crate::common::errors::{Error, Result};

pub const MAX_UDP_PAYLOAD: usize = 65507;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDPMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub address: String,
    pub data: Vec<u8>,
}
impl UDPMessage {
    pub fn new(session_id: u32, packet_id: u16, address: String, data: Vec<u8>) -> Self {
        Self { session_id, packet_id, frag_id: 0, frag_count: 1, address, data }
    }
    pub fn header_size(&self) -> usize { 8 + QuicVarint::size(self.address.len() as u64) + self.address.len() }
    pub fn size(&self) -> usize { self.header_size() + self.data.len() }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.address.is_empty() || self.address.len() > MAX_ADDRESS_LENGTH || self.data.is_empty() || self.data.len() > MAX_UDP_PAYLOAD {
            return Err(Error::Protocol("invalid Hysteria UDP message length".into()));
        }
        let mut bytes = Vec::with_capacity(self.size());
        // Go's transport InterConn.Write adds this field after proxy serialization.
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&self.packet_id.to_be_bytes());
        bytes.extend_from_slice(&[self.frag_id, self.frag_count]);
        QuicVarint::write(self.address.len() as u64, &mut bytes);
        bytes.extend_from_slice(self.address.as_bytes());
        bytes.extend_from_slice(&self.data);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 9 { return Err(Error::Protocol("truncated Hysteria UDP header".into())); }
        let (size, used) = QuicVarint::parse(&bytes[8..])?;
        if size == 0 || size > MAX_ADDRESS_LENGTH as u64 { return Err(Error::Protocol("invalid Hysteria UDP address length".into())); }
        let end = 8 + used + size as usize;
        if bytes.len() <= end { return Err(Error::Protocol("truncated/empty Hysteria UDP payload".into())); }
        if bytes.len() - end > MAX_UDP_PAYLOAD { return Err(Error::Protocol("oversized Hysteria UDP payload".into())); }
        let address = String::from_utf8(bytes[8 + used..end].to_vec()).map_err(|_| Error::Protocol("invalid UDP address UTF-8".into()))?;
        Ok(Self {
            session_id: u32::from_be_bytes(bytes[..4].try_into().expect("fixed header")),
            packet_id: u16::from_be_bytes(bytes[4..6].try_into().expect("fixed header")),
            frag_id: bytes[6], frag_count: bytes[7], address, data: bytes[end..].to_vec(),
        })
    }
}

/// An impossible MTU or more than 255 fragments is an error, never an oversized packet.
pub fn frag_udp_message(message: &UDPMessage, maximum: usize) -> Vec<UDPMessage> {
    if message.size() <= maximum { return vec![message.clone()]; }
    let capacity = maximum.saturating_sub(message.header_size());
    if capacity == 0 { return Vec::new(); }
    let count = message.data.len().div_ceil(capacity);
    if count > usize::from(u8::MAX) { return Vec::new(); }
    message.data.chunks(capacity).enumerate().map(|(id, chunk)| {
        let mut fragment = message.clone();
        fragment.frag_id = id as u8;
        fragment.frag_count = count as u8;
        fragment.data = chunk.to_vec();
        fragment
    }).collect()
}

/// One pending packet per session, matching Go. A new packet replaces old fragments.
#[derive(Default)]
pub struct Defragger {
    key: Option<(u32, u16, u8)>,
    fragments: Vec<Option<UDPMessage>>,
    received: usize,
    size: usize,
}
impl Defragger {
    pub fn new() -> Self { Self::default() }
    pub fn feed(&mut self, message: UDPMessage) -> Option<UDPMessage> {
        // Go accepts FragCount 0 and 1 as unfragmented.
        if message.frag_count <= 1 { return Some(message); }
        if message.frag_id >= message.frag_count { return None; }
        let key = (message.session_id, message.packet_id, message.frag_count);
        if self.key.as_ref() != Some(&key) {
            self.key = Some(key);
            self.fragments = vec![None; usize::from(message.frag_count)];
            self.received = 0;
            self.size = 0;
        }
        let index = usize::from(message.frag_id);
        if self.fragments[index].is_some() { return None; }
        self.size += message.data.len();
        if self.size > MAX_UDP_PAYLOAD { *self = Self::default(); return None; }
        let last = message.clone();
        self.fragments[index] = Some(message);
        self.received += 1;
        if self.received != self.fragments.len() { return None; }
        let mut complete = last;
        complete.data = Vec::with_capacity(self.size);
        for fragment in self.fragments.iter().flatten() { complete.data.extend_from_slice(&fragment.data); }
        complete.frag_id = 0;
        complete.frag_count = 1;
        Some(complete)
    }
}
