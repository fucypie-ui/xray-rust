//! Xray's Hysteria 2 framing (Go reference 67756b3).
use crate::common::errors::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_VARINT: u64 = (1 << 62) - 1;

pub struct QuicVarint;
impl QuicVarint {
    pub fn size(value: u64) -> usize {
        match value { 0..=63 => 1, 64..=16383 => 2, 16384..=1073741823 => 4, _ => 8 }
    }
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64> {
        let first = reader.read_u8().await?;
        let length = 1 << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..length { value = (value << 8) | u64::from(reader.read_u8().await?); }
        Ok(value)
    }
    /// A complete datagram parser; truncated encodings never consume bytes.
    pub fn parse(bytes: &[u8]) -> Result<(u64, usize)> {
        let first = *bytes.first().ok_or_else(|| Error::Protocol("truncated QUIC varint".into()))?;
        let length = 1usize << (first >> 6);
        if bytes.len() < length { return Err(Error::Protocol("truncated QUIC varint".into())); }
        let mut value = u64::from(first & 0x3f);
        for byte in &bytes[1..length] { value = (value << 8) | u64::from(*byte); }
        Ok((value, length))
    }
    pub fn write(value: u64, buffer: &mut Vec<u8>) {
        assert!(value <= MAX_VARINT, "QUIC integers have at most 62 bits");
        match Self::size(value) {
            1 => buffer.push(value as u8),
            2 => buffer.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
            4 => buffer.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes()),
            _ => buffer.extend_from_slice(&(0xc000_0000_0000_0000 | value).to_be_bytes()),
        }
    }
}

async fn read_text<R: AsyncRead + Unpin>(reader: &mut R, maximum: usize, allow_empty: bool) -> Result<String> {
    let size = QuicVarint::read(reader).await?;
    if size > maximum as u64 || (!allow_empty && size == 0) {
        return Err(Error::Protocol("invalid Hysteria text length".into()));
    }
    let mut bytes = vec![0; size as usize];
    reader.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| Error::Protocol("invalid UTF-8 in Hysteria address/message".into()))
}
async fn read_padding<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize> {
    let size = QuicVarint::read(reader).await?;
    if size > MAX_PADDING_LENGTH as u64 { return Err(Error::Protocol("invalid Hysteria padding length".into())); }
    let mut padding = vec![0; size as usize];
    reader.read_exact(&mut padding).await?;
    Ok(size as usize)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest { pub address: String, pub padding_len: usize }
impl TcpRequest {
    pub fn new(address: impl Into<String>, padding_len: usize) -> Self { Self { address: address.into(), padding_len } }
    /// Body only, matching Go WriteTCPRequest. The transport adds 0x401 once.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        QuicVarint::write(self.address.len() as u64, &mut bytes);
        bytes.extend_from_slice(self.address.as_bytes());
        QuicVarint::write(self.padding_len as u64, &mut bytes);
        bytes.resize(bytes.len() + self.padding_len, 0);
        bytes
    }
    pub fn encode_stream(&self) -> Result<Vec<u8>> {
        if self.address.is_empty() || self.address.len() > MAX_ADDRESS_LENGTH || self.padding_len > MAX_PADDING_LENGTH {
            return Err(Error::Protocol("invalid Hysteria TCP request".into()));
        }
        let mut bytes = Vec::new();
        QuicVarint::write(FRAME_TYPE_TCP_REQUEST, &mut bytes);
        bytes.extend_from_slice(&self.encode());
        Ok(bytes)
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let address = read_text(reader, MAX_ADDRESS_LENGTH, false).await?;
        let padding_len = read_padding(reader).await?;
        Ok(Self { address, padding_len })
    }
    pub async fn decode_stream<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        if QuicVarint::read(reader).await? != FRAME_TYPE_TCP_REQUEST {
            return Err(Error::Protocol("unexpected Hysteria stream type".into()));
        }
        Self::decode(reader).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse { pub ok: bool, pub message: String, pub padding_len: usize }
impl TcpResponse {
    pub fn new(ok: bool, message: impl Into<String>, padding_len: usize) -> Self { Self { ok, message: message.into(), padding_len } }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.message.len() > MAX_MESSAGE_LENGTH || self.padding_len > MAX_PADDING_LENGTH {
            return Err(Error::Protocol("invalid Hysteria TCP response".into()));
        }
        let mut bytes = vec![u8::from(!self.ok)];
        QuicVarint::write(self.message.len() as u64, &mut bytes);
        bytes.extend_from_slice(self.message.as_bytes());
        QuicVarint::write(self.padding_len as u64, &mut bytes);
        bytes.resize(bytes.len() + self.padding_len, 0);
        Ok(bytes)
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        // Like Go, every nonzero status is a failure (not just 1).
        let ok = reader.read_u8().await? == 0;
        let message = read_text(reader, MAX_MESSAGE_LENGTH, true).await?;
        let padding_len = read_padding(reader).await?;
        Ok(Self { ok, message, padding_len })
    }
}
