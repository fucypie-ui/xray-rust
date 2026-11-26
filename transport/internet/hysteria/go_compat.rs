//! Xray's server-side AssumePeerMaxDatagramFrameSize=1200 policy.
//!
//! Source verified against apernet/quic-go 2895f039137a (connection.go,
//! peerMaxDatagramFrameSize) and quinn-proto 0.11.19 (crypto.rs and
//! transport_parameters.rs). This changes only Quinn's local interpretation of
//! the authenticated TLS transport parameters, never the TLS transcript or keys.
//! It is confined to dedicated Hysteria servers, never general QUIC endpoints.
//! Go-peer runtime validation belongs to the Ubuntu interoperability test.
use bytes::BytesMut;
use quinn_proto::{ConnectionId, Side, TransportError, crypto::{self, Session}, transport_parameters::TransportParameters};
use std::{any::Any, sync::Arc};

pub struct HysteriaServerCrypto(pub Arc<dyn crypto::ServerConfig>);
impl crypto::ServerConfig for HysteriaServerCrypto {
    fn initial_keys(&self, version: u32, cid: &ConnectionId) -> Result<crypto::Keys, crypto::UnsupportedVersion> { self.0.initial_keys(version, cid) }
    fn retry_tag(&self, version: u32, cid: &ConnectionId, packet: &[u8]) -> [u8; 16] { self.0.retry_tag(version, cid, packet) }
    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn Session> {
        Box::new(HysteriaSession(self.0.clone().start_session(version, params)))
    }
}
struct HysteriaSession(Box<dyn Session>);
impl Session for HysteriaSession {
    fn initial_keys(&self, cid: &ConnectionId, side: Side) -> crypto::Keys { self.0.initial_keys(cid, side) }
    fn handshake_data(&self) -> Option<Box<dyn Any>> { self.0.handshake_data() }
    fn peer_identity(&self) -> Option<Box<dyn Any>> { self.0.peer_identity() }
    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> { self.0.early_crypto() }
    fn early_data_accepted(&self) -> Option<bool> { self.0.early_data_accepted() }
    fn is_handshaking(&self) -> bool { self.0.is_handshaking() }
    fn read_handshake(&mut self, bytes: &[u8]) -> Result<bool, TransportError> { self.0.read_handshake(bytes) }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.0.transport_parameters()?.map(assume_go_datagrams).transpose()
    }
    fn write_handshake(&mut self, bytes: &mut Vec<u8>) -> Option<crypto::Keys> { self.0.write_handshake(bytes) }
    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> { self.0.next_1rtt_keys() }
    fn is_valid_retry(&self, cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool { self.0.is_valid_retry(cid, header, payload) }
    fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), crypto::ExportKeyingMaterialError> { self.0.export_keying_material(output, label, context) }
}

pub(super) fn assume_go_datagrams(params: TransportParameters) -> Result<TransportParameters, TransportError> {
    let mut encoded = Vec::new();
    params.write(&mut encoded);
    let encoded = add_missing_datagram_parameter(&encoded)?;
    TransportParameters::read(Side::Server, &mut encoded.as_slice()).map_err(Into::into)
}

/// Preserve explicitly advertised values, including zero. Only omission uses
/// Xray's out-of-band Hysteria capability policy. No duplicate TLV is appended.
pub(super) fn add_missing_datagram_parameter(bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut remaining = bytes;
    let mut present = false;
    while !remaining.is_empty() {
        let (kind, used) = read_varint(remaining)?;
        remaining = &remaining[used..];
        let (length, used) = read_varint(remaining)?;
        remaining = &remaining[used..];
        if length > remaining.len() as u64 { return Err(quinn_proto::transport_parameters::Error::Malformed.into()); }
        present |= kind == 0x20;
        remaining = &remaining[length as usize..];
    }
    let mut encoded = bytes.to_vec();
    if !present {
        // TP ID 0x20, value length 2, QUIC varint 1200 = 0x44b0.
        encoded.extend_from_slice(&[0x20, 0x02, 0x44, 0xb0]);
    }
    Ok(encoded)
}
fn read_varint(bytes: &[u8]) -> Result<(u64, usize), TransportError> {
    use bytes::Buf;
    let mut bytes = BytesMut::from(bytes);
    let initial = bytes.first().copied().ok_or(quinn_proto::transport_parameters::Error::Malformed)?;
    let length = 1usize << (initial >> 6);
    if bytes.len() < length { return Err(quinn_proto::transport_parameters::Error::Malformed.into()); }
    let mut value = u64::from(bytes.get_u8() & 0x3f);
    for _ in 1..length { value = value << 8 | u64::from(bytes.get_u8()); }
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn omitted_datagram_parameter_and_existing_values() {
        let missing = [0x0c, 0x00]; // disable_active_migration
        assert_eq!(add_missing_datagram_parameter(&missing).unwrap(), [0x0c, 0, 0x20, 2, 0x44, 0xb0]);
        for encoded in [&[0x20, 1, 0][..], &[0x20, 2, 0x44, 0xb0][..], &[0x20, 2, 0x45, 0xdc][..]] {
            assert_eq!(add_missing_datagram_parameter(encoded).unwrap(), encoded);
        }
        for malformed in [&[0x40][..], &[0x20][..], &[0x20, 2, 1][..]] { assert!(add_missing_datagram_parameter(malformed).is_err()); }
        let original = TransportParameters::read(Side::Server, &mut missing.as_slice()).unwrap();
        let patched = assume_go_datagrams(original).unwrap();
        let mut encoded = Vec::new(); patched.write(&mut encoded);
        assert!(encoded.windows(4).any(|window| window == [0x20, 2, 0x44, 0xb0]));
    }
}
