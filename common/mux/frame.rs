//! Mux.Cool framing, verified against the pinned Go proxy/vless/multiplex codec.
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination, Network};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_METADATA_SIZE: usize = 512;
pub const MAX_UDP_PAYLOAD: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus { New = 1, Keep = 2, End = 3, KeepAlive = 4 }
impl SessionStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value { 1 => Some(Self::New), 2 => Some(Self::Keep), 3 => Some(Self::End), 4 => Some(Self::KeepAlive), _ => None }
    }
}
pub const OPTION_DATA: u8 = 1;
pub const OPTION_ERROR: u8 = 2;
pub const TARGET_NETWORK_TCP: u8 = 1;
pub const TARGET_NETWORK_UDP: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameMetadata {
    pub target: Option<Destination>,
    pub session_id: u16,
    pub option: u8,
    pub session_status: SessionStatus,
    pub global_id: [u8; 8],
}
impl FrameMetadata {
    pub fn new(session_id: u16, session_status: SessionStatus) -> Self {
        Self { target: None, session_id, option: 0, session_status, global_id: [0; 8] }
    }
    pub fn write_to(&self, output: &mut Vec<u8>) -> Result<()> {
        let mut metadata = Vec::with_capacity(64);
        metadata.extend_from_slice(&self.session_id.to_be_bytes());
        metadata.extend_from_slice(&[self.session_status as u8, self.option]);
        if self.session_status == SessionStatus::New {
            let target = self.target.as_ref().ok_or_else(|| Error::Protocol("mux New missing destination".into()))?;
            put_destination(&mut metadata, target)?;
            if target.network == Network::Udp && self.option & OPTION_DATA != 0 {
                metadata.extend_from_slice(&self.global_id);
            }
        } else if self.session_status == SessionStatus::Keep && let Some(target) = &self.target {
            if target.network != Network::Udp { return Err(Error::Protocol("mux Keep target must be UDP".into())); }
            put_destination(&mut metadata, target)?;
        }
        if metadata.len() > MAX_METADATA_SIZE { return Err(Error::BufferOverflow); }
        output.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        output.extend_from_slice(&metadata);
        Ok(())
    }
    pub fn unmarshal(&mut self, bytes: &[u8]) -> Result<usize> {
        if bytes.len() < 2 { return Err(Error::Protocol("truncated mux metadata length".into())); }
        let length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if !(4..=MAX_METADATA_SIZE).contains(&length) { return Err(Error::Protocol("invalid mux metadata length".into())); }
        let block = bytes.get(2..2 + length).ok_or_else(|| Error::Protocol("truncated mux metadata".into()))?;
        self.session_id = u16::from_be_bytes([block[0], block[1]]);
        self.session_status = SessionStatus::from_u8(block[2]).ok_or_else(|| Error::Protocol("unknown mux status".into()))?;
        self.option = block[3];
        self.target = None;
        self.global_id = [0; 8];
        if self.session_status == SessionStatus::New || (self.session_status == SessionStatus::Keep && block.get(4) == Some(&TARGET_NETWORK_UDP)) {
            let (target, consumed) = get_destination(&block[4..])?;
            if self.session_status == SessionStatus::New && target.network == Network::Udp && self.option & OPTION_DATA != 0
                && let Some(id) = block.get(4 + consumed..4 + consumed + 8)
            { self.global_id.copy_from_slice(id); }
            self.target = Some(target);
        }
        Ok(2 + length)
    }
}

fn put_destination(output: &mut Vec<u8>, target: &Destination) -> Result<()> {
    output.push(if target.network == Network::Udp { TARGET_NETWORK_UDP } else { TARGET_NETWORK_TCP });
    output.extend_from_slice(&target.port.to_be_bytes());
    match &target.address {
        Address::Ipv4(address) => { output.push(1); output.extend_from_slice(&address.octets()); }
        Address::Domain(address) => {
            if address.is_empty() || address.len() > 255 { return Err(Error::Protocol("mux domain length outside 1..255".into())); }
            output.extend_from_slice(&[2, address.len() as u8]); output.extend_from_slice(address.as_bytes());
        }
        Address::Ipv6(address) => { output.push(3); output.extend_from_slice(&address.octets()); }
    }
    Ok(())
}
fn get_destination(bytes: &[u8]) -> Result<(Destination, usize)> {
    let short = || Error::Protocol("truncated mux destination".into());
    let header = bytes.get(..4).ok_or_else(short)?;
    let network = match header[0] { 1 => Network::Tcp, 2 => Network::Udp, _ => return Err(Error::Protocol("unknown mux network".into())) };
    let port = u16::from_be_bytes([header[1], header[2]]);
    let (address, consumed) = match header[3] {
        1 => { let raw: [u8; 4] = bytes.get(4..8).ok_or_else(short)?.try_into().map_err(|_| short())?; (Address::Ipv4(raw.into()), 8) }
        2 => {
            let length = *bytes.get(4).ok_or_else(short)? as usize;
            if length == 0 { return Err(Error::Protocol("empty mux domain".into())); }
            let raw = bytes.get(5..5 + length).ok_or_else(short)?;
            let domain = std::str::from_utf8(raw).map_err(|_| Error::Protocol("mux domain is not UTF-8".into()))?;
            (Address::Domain(domain.to_owned()), 5 + length)
        }
        3 => { let raw: [u8; 16] = bytes.get(4..20).ok_or_else(short)?.try_into().map_err(|_| short())?; (Address::Ipv6(raw.into()), 20) }
        _ => return Err(Error::Protocol("unknown mux address type".into())),
    };
    Ok((Destination { network, address, port }, consumed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: u8,
    pub target: Option<Destination>,
    pub global_id: [u8; 8],
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn new(session_id: u16, status: SessionStatus, payload: Vec<u8>) -> Self {
        Self { session_id, status, option: if payload.is_empty() { 0 } else { OPTION_DATA }, target: None, global_id: [0; 8], payload }
    }
    pub fn new_session(session_id: u16, target: Destination, payload: Vec<u8>) -> Self {
        let mut frame = Self::new(session_id, SessionStatus::New, payload);
        frame.target = Some(target); frame
    }
    pub fn data(session_id: u16, payload: Vec<u8>) -> Self {
        let mut frame = Self::new(session_id, SessionStatus::Keep, payload);
        frame.option = OPTION_DATA; frame
    }
    pub fn end(session_id: u16) -> Self { Self::new(session_id, SessionStatus::End, Vec::new()) }
    pub fn error(session_id: u16) -> Self { let mut frame = Self::end(session_id); frame.option = OPTION_ERROR; frame }
    pub fn keepalive() -> Self { Self::new(0, SessionStatus::KeepAlive, Vec::new()) }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        if self.payload.len() > u16::MAX as usize { return Err(Error::BufferOverflow); }
        if self.option & OPTION_DATA == 0 && !self.payload.is_empty() { return Err(Error::Protocol("mux payload without Data option".into())); }
        let meta = FrameMetadata { target: self.target.clone(), session_id: self.session_id, option: self.option, session_status: self.status, global_id: self.global_id };
        let mut output = Vec::with_capacity(64 + self.payload.len());
        meta.write_to(&mut output)?;
        if self.option & OPTION_DATA != 0 {
            output.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            output.extend_from_slice(&self.payload);
        }
        writer.write_all(&output).await?;
        writer.flush().await?;
        Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut prefix = [0; 2];
        if reader.read(&mut prefix[..1]).await? == 0 { return Err(Error::Eof); }
        reader.read_exact(&mut prefix[1..]).await?;
        let length = u16::from_be_bytes(prefix) as usize;
        if !(4..=MAX_METADATA_SIZE).contains(&length) { return Err(Error::Protocol("invalid mux metadata length".into())); }
        let mut bytes = vec![0; length + 2];
        bytes[..2].copy_from_slice(&prefix);
        reader.read_exact(&mut bytes[2..]).await?;
        let mut meta = FrameMetadata::new(0, SessionStatus::KeepAlive);
        meta.unmarshal(&bytes)?;
        let mut payload = Vec::new();
        if meta.option & OPTION_DATA != 0 {
            let length = reader.read_u16().await? as usize;
            payload.resize(length, 0);
            reader.read_exact(&mut payload).await?;
        }
        Ok(Self { session_id: meta.session_id, status: meta.session_status, option: meta.option, target: meta.target, global_id: meta.global_id, payload })
    }
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> { self.encode(writer).await }
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> { Self::decode(reader).await }
}
pub type FrameType = SessionStatus;
