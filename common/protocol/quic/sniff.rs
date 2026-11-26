use crate::common::errors::{Error, Result};
use crate::common::protocol::protocol::err_proto_need_more_data;
use crate::common::protocol::tls::sniff::read_client_hello;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::{Block, BlockCipherEncrypt};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSniffHeader {
    pub domain: String,
}

impl QuicSniffHeader {
    pub fn protocol(&self) -> &'static str { "quic" }
    pub fn domain(&self) -> &str { &self.domain }
}

pub fn sniff_quic(b: &[u8]) -> Result<QuicSniffHeader> {
    if b.is_empty() {
        return Err(invalid("empty quic packet"));
    }
    let mut packets = b;
    let mut crypto = CryptoStream::default();
    while !packets.is_empty() {
        let mut reader = PacketReader::new(packets);
        let first = reader.byte()?;
        if first & 0xc0 != 0xc0 {
            return Err(invalid("not quic long header"));
        }
        let version = reader.take(4)?;
        let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
        let (salt, label, initial_type) = version_spec(version)?;
        let dcid_len = usize::from(reader.byte()?);
        let dcid = reader.take(dcid_len)?;
        let scid_len = usize::from(reader.byte()?);
        reader.take(scid_len)?;
        let is_initial = (first & 0x30) >> 4 == initial_type;
        if is_initial {
            let token_len = reader.varint()?;
            reader.take(token_len)?;
        }
        let packet_len = reader.varint()?;
        if packet_len < 4 {
            return Err(invalid("quic packet length too short"));
        }
        let pn_offset = reader.pos;
        reader.take(packet_len)?;
        let packet_end = reader.pos;
        let packet = &packets[..packet_end];
        let rest = &packets[packet_end..];
        // The dispatcher may concatenate datagrams with zero padding between
        // them. Padding outside a packet is not authenticated frame data.
        let padding = rest.iter().take_while(|byte| **byte == 0).count();
        packets = &rest[padding..];
        if !is_initial {
            continue;
        }

        let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
        let secret = expand_label::<32>(&initial, "client in")?;
        let client = Hkdf::<Sha256>::from_prk(&secret)
            .map_err(|_| invalid("invalid quic initial secret"))?;
        let hp_key = expand_label::<16>(&client, &format!("{label} hp"))?;
        let sample: [u8; 16] = packet.get(pn_offset + 4..pn_offset + 20)
            .ok_or_else(|| invalid("truncated quic header protection sample"))?
            .try_into().map_err(|_| invalid("invalid quic header protection sample"))?;
        let mut mask = Block::<Aes128>::from(sample);
        let hp = Aes128::new_from_slice(&hp_key)
            .map_err(|_| invalid("invalid quic header protection key"))?;
        hp.encrypt_block(&mut mask);
        let unprotected_first = first ^ (mask[0] & 0x0f);
        let pn_len = usize::from(unprotected_first & 3) + 1;
        let header_len = pn_offset + pn_len;
        let mut header = packet.get(..header_len)
            .ok_or_else(|| invalid("truncated quic packet number"))?.to_vec();
        header[0] = unprotected_first;
        let mut nonce = expand_label::<12>(&client, &format!("{label} iv"))?;
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[i + 1];
            nonce[12 - pn_len + i] ^= header[pn_offset + i];
        }
        let key = expand_label::<16>(&client, &format!("{label} key"))?;
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|_| invalid("invalid quic initial key"))?;
        let plaintext = cipher.decrypt(&nonce.into(), Payload {
            msg: &packet[header_len..],
            aad: &header,
        }).map_err(|_| invalid("quic initial authentication failed"))?;
        crypto.read_frames(&plaintext)?;
        if crypto.received.iter().all(|received| *received)
            && let Ok(domain) = read_client_hello(&crypto.data)
        {
            return Ok(QuicSniffHeader { domain });
        }
    }
    Err(err_proto_need_more_data())
}

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}

// These salts and TLS label prefixes match the local Go implementation.
fn version_spec(version: u32) -> Result<(&'static [u8], &'static str, u8)> {
    match version {
        0xff00_001d => Ok((&[
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
            0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
        ], "quic", 0)),
        1 => Ok((&[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ], "quic", 0)),
        0x6b33_43cf => Ok((&[
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ], "quicv2", 1)),
        _ => Err(invalid("unsupported quic version")),
    }
}

fn expand_label<const N: usize>(hkdf: &Hkdf<Sha256>, label: &str) -> Result<[u8; N]> {
    let mut info = Vec::with_capacity(10 + label.len());
    let len = u16::try_from(N).map_err(|_| invalid("quic key too long"))?;
    info.extend_from_slice(&len.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).map_err(|_| invalid("quic label too long"))?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut output = [0; N];
    hkdf.expand(&info, &mut output).map_err(|_| invalid("quic key expansion failed"))?;
    Ok(output)
}

struct PacketReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PacketReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or_else(|| invalid("quic length overflow"))?;
        let value = self.bytes.get(self.pos..end).ok_or_else(|| invalid("truncated quic data"))?;
        self.pos = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    // Like readShortQUICVarint in Go, accept all four encodings but bound
    // values used for Initial packet lengths and offsets to 65535.
    fn varint(&mut self) -> Result<usize> {
        let first = self.byte()?;
        let width = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(width - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        if value > 65535 {
            return Err(invalid("quic initial varint exceeds 65535"));
        }
        Ok(value as usize)
    }
}

#[derive(Default)]
struct CryptoStream {
    data: Vec<u8>,
    received: Vec<bool>,
}

impl CryptoStream {
    fn read_frames(&mut self, bytes: &[u8]) -> Result<()> {
        let mut reader = PacketReader::new(bytes);
        while reader.pos < bytes.len() {
            match reader.byte()? {
                0x00 | 0x01 => {} // PADDING, PING
                frame @ (0x02 | 0x03) => {
                    reader.varint()?; // Largest Acknowledged
                    reader.varint()?; // ACK Delay
                    let ranges = reader.varint()?;
                    reader.varint()?; // First ACK Range
                    for _ in 0..ranges {
                        reader.varint()?; // Gap
                        reader.varint()?; // ACK Range Length
                    }
                    if frame == 0x03 {
                        for _ in 0..3 {
                            reader.varint()?; // ECN counts
                        }
                    }
                }
                0x06 => {
                    let offset = reader.varint()?;
                    let length = reader.varint()?;
                    let end = offset.checked_add(length)
                        .filter(|end| *end <= 32767)
                        .ok_or_else(|| invalid("quic crypto stream exceeds 32767 bytes"))?;
                    let fragment = reader.take(length)?;
                    if self.data.len() < end {
                        self.data.resize(end, 0);
                        self.received.resize(end, false);
                    }
                    self.data[offset..end].copy_from_slice(fragment);
                    self.received[offset..end].fill(true);
                }
                0x1c => {
                    reader.varint()?; // Error Code
                    reader.varint()?; // Frame Type
                    let length = reader.varint()?;
                    reader.take(length)?; // Reason Phrase
                }
                _ => return Err(invalid("frame not permitted in quic initial")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wire_test.rs"]
mod wire_test;
