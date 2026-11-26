//! Go-compatible SS2022 UDP packet framing using the official Rust AEAD engine.
use std::io;
use shadowsocks_crypto::v2::udp::UdpCipher;
use crate::common::net::{Destination, Network};
use super::{cipher::{AEAD_TAG_SIZE, CipherMethod, invalid_data}, identity::{HeaderCipher, udp_identity, validate_psks}, kdf::user_psk_hash, protocol::{HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER}, stream::{decode_address, encode_address, validate_timestamp}};

pub const MAX_DATAGRAM_SIZE: usize = 8192;
pub const PACKET_NONCE_SIZE: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket {
    pub session_id: u64,
    pub packet_id: u64,
    pub header_type: u8,
    pub timestamp: u64,
    pub client_session_id: Option<u64>,
    pub destination: Destination,
    pub payload: Vec<u8>,
}

pub struct PacketCodec { method: CipherMethod, psks: Vec<Vec<u8>> }
impl PacketCodec {
    pub fn new(method: CipherMethod, psks: Vec<Vec<u8>>) -> io::Result<Self> {
        validate_psks(method, &psks)?;
        Ok(Self { method, psks })
    }
    pub fn method(&self) -> CipherMethod { self.method }
    fn key(&self) -> &[u8] { &self.psks[self.psks.len() - 1] }

    /// Deterministic codec entry point; callers supply a fresh nonce for ChaCha.
    /// Runtime sessions allocate unique packet IDs and random nonces for callers.
    pub fn encode_at(&self, packet: &DecodedPacket, padding: &[u8], nonce: &[u8; PACKET_NONCE_SIZE]) -> io::Result<Vec<u8>> {
        if !matches!(packet.header_type, HEADER_TYPE_CLIENT | HEADER_TYPE_SERVER)
            || (packet.header_type == HEADER_TYPE_SERVER) != packet.client_session_id.is_some()
            || packet.destination.network != Network::Udp
        { return Err(invalid_data("invalid SS2022 UDP packet metadata")); }
        let mut body = vec![packet.header_type];
        body.extend_from_slice(&packet.timestamp.to_be_bytes());
        if let Some(client_session_id) = packet.client_session_id { body.extend_from_slice(&client_session_id.to_be_bytes()); }
        let padding_length = u16::try_from(padding.len()).map_err(|_| invalid_data("UDP padding exceeds u16"))?;
        body.extend_from_slice(&padding_length.to_be_bytes());
        body.extend_from_slice(padding);
        let mut address = packet.destination.clone();
        address.network = Network::Tcp;
        body.extend(encode_address(&address)?);
        body.extend_from_slice(&packet.payload);
        let mut raw = [0; 16];
        raw[..8].copy_from_slice(&packet.session_id.to_be_bytes());
        raw[8..].copy_from_slice(&packet.packet_id.to_be_bytes());
        let eih_count = if packet.header_type == HEADER_TYPE_CLIENT { self.psks.len() - 1 } else { 0 };
        let overhead = if self.method.is_chacha() { 24 + 16 } else { 16 + 16 * eih_count };
        if body.len().checked_add(overhead + AEAD_TAG_SIZE).is_none_or(|size| size > MAX_DATAGRAM_SIZE) { return Err(invalid_data("SS2022 UDP packet exceeds Go buffer size")); }
        let cipher = UdpCipher::new(self.method.kind(), self.key(), packet.session_id);
        if self.method.is_chacha() {
            let mut plain = raw.to_vec();
            plain.extend(body);
            plain.resize(plain.len() + AEAD_TAG_SIZE, 0);
            cipher.encrypt_packet(nonce, &mut plain);
            let mut wire = nonce.to_vec();
            wire.extend(plain);
            return Ok(wire);
        }
        let header_key = if eih_count > 0 { &self.psks[0] } else { self.key() };
        let mut wire = HeaderCipher::new(self.method, header_key)?.encrypt(&raw).to_vec();
        for pair in self.psks.windows(2).take(eih_count) {
            let mut hash = user_psk_hash(&pair[1]);
            for (byte, header) in hash.iter_mut().zip(raw) { *byte ^= header; }
            wire.extend(HeaderCipher::new(self.method, &pair[0])?.encrypt(&hash));
        }
        body.resize(body.len() + AEAD_TAG_SIZE, 0);
        cipher.encrypt_packet(&raw[4..], &mut body);
        wire.extend(body);
        Ok(wire)
    }

    /// Stateless authenticated decode. Runtime session types additionally enforce replay.
    pub fn decode_at(&self, wire: &[u8], expected_type: u8, now: u64) -> io::Result<DecodedPacket> {
        if wire.len() > MAX_DATAGRAM_SIZE || wire.len() < 32 { return Err(invalid_data("invalid SS2022 UDP packet length")); }
        let packet = if self.method.is_chacha() {
            if wire.len() < PACKET_NONCE_SIZE + 16 + AEAD_TAG_SIZE { return Err(invalid_data("short ChaCha UDP packet")); }
            let mut plain = wire[PACKET_NONCE_SIZE..].to_vec();
            let cipher = UdpCipher::new(self.method.kind(), self.key(), 0);
            if !cipher.decrypt_packet(&wire[..PACKET_NONCE_SIZE], &mut plain) { return Err(invalid_data("SS2022 UDP authentication failed")); }
            plain.truncate(plain.len() - AEAD_TAG_SIZE);
            let raw: [u8; 16] = plain[..16].try_into().map_err(|_| invalid_data("short UDP header"))?;
            parse_body(&raw, &plain[16..], now)?
        } else {
            let identities = if expected_type == HEADER_TYPE_CLIENT { self.psks.len() - 1 } else { 0 };
            let offset = 16 + identities * 16;
            if wire.len() < offset + AEAD_TAG_SIZE { return Err(invalid_data("short EIH UDP packet")); }
            let key = if identities > 0 { &self.psks[0] } else { self.key() };
            let raw = decrypt_header(self.method, key, &wire[..16])?;
            for (index, pair) in self.psks.windows(2).take(identities).enumerate() {
                let cipher = HeaderCipher::new(self.method, &pair[0])?;
                let eih: [u8; 16] = wire[16 + 16 * index..32 + 16 * index].try_into().map_err(|_| invalid_data("short EIH"))?;
                if udp_identity(&cipher, &raw, &eih) != user_psk_hash(&pair[1]) { return Err(invalid_data("unknown UDP identity")); }
            }
            self.decode_aes_body_at(&raw, &wire[offset..], now)?
        };
        if packet.header_type != expected_type { return Err(invalid_data("unexpected SS2022 UDP header type")); }
        Ok(packet)
    }

    pub(crate) fn decode_aes_body_at(&self, raw: &[u8; 16], body: &[u8], now: u64) -> io::Result<DecodedPacket> {
        if self.method.is_chacha() || body.len() < AEAD_TAG_SIZE || body.len() > MAX_DATAGRAM_SIZE { return Err(invalid_data("invalid AES UDP body")); }
        let session_id = u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid_data("short UDP session ID"))?);
        let cipher = UdpCipher::new(self.method.kind(), self.key(), session_id);
        let mut plain = body.to_vec();
        if !cipher.decrypt_packet(&raw[4..], &mut plain) { return Err(invalid_data("SS2022 UDP authentication failed")); }
        plain.truncate(plain.len() - AEAD_TAG_SIZE);
        parse_body(raw, &plain, now)
    }
}

pub(crate) fn decrypt_header(method: CipherMethod, key: &[u8], header: &[u8]) -> io::Result<[u8; 16]> {
    let block = header.try_into().map_err(|_| invalid_data("short UDP header"))?;
    Ok(HeaderCipher::new(method, key)?.decrypt(&block))
}

fn parse_body(raw: &[u8; 16], body: &[u8], now: u64) -> io::Result<DecodedPacket> {
    if body.len() < 11 { return Err(invalid_data("short UDP body")); }
    let header_type = body[0];
    if !matches!(header_type, HEADER_TYPE_CLIENT | HEADER_TYPE_SERVER) { return Err(invalid_data("invalid UDP header type")); }
    let timestamp = u64::from_be_bytes(body[1..9].try_into().map_err(|_| invalid_data("short timestamp"))?);
    validate_timestamp(timestamp, now)?;
    let mut offset = 9;
    let client_session_id = if header_type == HEADER_TYPE_SERVER {
        let field = body.get(offset..offset + 8).ok_or_else(|| invalid_data("short client session ID"))?;
        offset += 8;
        Some(u64::from_be_bytes(field.try_into().map_err(|_| invalid_data("short client session ID"))?))
    } else { None };
    let field = body.get(offset..offset + 2).ok_or_else(|| invalid_data("short UDP padding length"))?;
    offset += 2 + usize::from(u16::from_be_bytes([field[0], field[1]]));
    let address = body.get(offset..).ok_or_else(|| invalid_data("short UDP padding"))?;
    let (mut destination, length) = decode_address(address)?;
    destination.network = Network::Udp;
    Ok(DecodedPacket {
        session_id: u64::from_be_bytes(raw[..8].try_into().map_err(|_| invalid_data("short UDP session"))?),
        packet_id: u64::from_be_bytes(raw[8..].try_into().map_err(|_| invalid_data("short UDP packet ID"))?),
        header_type, timestamp, client_session_id, destination, payload: address[length..].to_vec(),
    })
}
