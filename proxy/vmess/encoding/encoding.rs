use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use crate::common::protocol::RequestCommand;
use crate::proxy::vmess::{aead::{AuthIdGenerator, VmessAeadEncryptor, consts::*, kdf::{kdf, kdf16}}, validator::MemoryValidator};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const VMESS_VERSION: u8 = 1;
pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CHUNK_MASKING: u8 = 4;
pub const OPTION_GLOBAL_PADDING: u8 = 8;
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BodySecurity { Aes128Gcm = 3, ChaCha20Poly1305 = 4 }
impl BodySecurity {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            3 => Ok(Self::Aes128Gcm), 4 => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::Protocol(format!("unsupported VMess body security: {value}"))),
        }
    }
    pub fn from_name(value: &str) -> Result<Self> {
        match value {
            "auto" | "" => Ok(Self::auto()),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::Config(format!("unsupported VMess body security: {value}"))),
        }
    }
    pub fn auto() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") && std::is_x86_feature_detected!("sse4.1") && std::is_x86_feature_detected!("ssse3") {
            return Self::Aes128Gcm;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull") {
            return Self::Aes128Gcm;
        }
        Self::ChaCha20Poly1305
    }
}

pub fn unix_seconds() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs())
        .map_err(|_| Error::AuthFailed("system time precedes Unix epoch".into()))
}
pub fn command_key(id: &Uuid) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(id.as_bytes());
    hash.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hash.finalize().into()
}
pub fn fnv1a_32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5u32, |hash, byte| (hash ^ u32::from(*byte)).wrapping_mul(0x01000193))
}
pub fn generate_chacha20_key(seed: &[u8; 16]) -> [u8; 32] {
    super::auth::generate_chacha20poly1305_key(seed)
}
pub fn response_key_iv(request: &RequestHeader) -> ([u8; 16], [u8; 16]) {
    let mut key = [0u8; 16]; let mut iv = [0u8; 16];
    key.copy_from_slice(&Sha256::digest(request.request_body_key)[..16]);
    iv.copy_from_slice(&Sha256::digest(request.request_body_iv)[..16]);
    (key, iv)
}
fn nonce12(bytes: &[u8; 32]) -> [u8; 12] {
    let mut nonce = [0u8; 12]; nonce.copy_from_slice(&bytes[..12]); nonce
}
fn address_from_ip(ip: std::net::IpAddr) -> Address {
    match ip {
        std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(Address::Ipv6(ip), Address::Ipv4),
    }
}
fn header_cipher(key: &[u8], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> VmessAeadEncryptor {
    VmessAeadEncryptor::new(&kdf16(key, &[label, auth_id, nonce]))
}

/// Seal a deterministic envelope when randomness/time are supplied explicitly.
/// Production callers use RequestHeader::encode, which supplies fresh values.
pub fn seal_request_payload(key: &[u8; 16], payload: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| Error::Protocol("VMess header too large".into()))?;
    let encrypted_length = header_cipher(key, HEADER_LENGTH_KEY, auth_id, nonce).seal_with_aad(
        &nonce12(&kdf(key, &[HEADER_LENGTH_NONCE, auth_id, nonce])), &length.to_be_bytes(), auth_id)?;
    let encrypted_payload = header_cipher(key, HEADER_KEY, auth_id, nonce).seal_with_aad(
        &nonce12(&kdf(key, &[HEADER_NONCE, auth_id, nonce])), payload, auth_id)?;
    let mut output = Vec::with_capacity(42 + encrypted_payload.len());
    output.extend_from_slice(auth_id); output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(nonce); output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub version: u8,
    pub user_id: Uuid,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header_byte: u8,
    pub options: u8,
    pub security: BodySecurity,
    pub command: RequestCommand,
    pub destination: Destination,
}
impl RequestHeader {
    pub fn new(user_id: Uuid, command: RequestCommand, destination: Destination) -> Self {
        Self { version: VMESS_VERSION, user_id, request_body_iv: rand::random(),
            request_body_key: rand::random(), response_header_byte: rand::random(),
            options: OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            security: BodySecurity::auto(), command, destination }
    }
    pub fn validate(&self) -> Result<()> {
        if self.options & OPTION_GLOBAL_PADDING != 0 && self.options & OPTION_CHUNK_MASKING == 0 {
            return Err(Error::Protocol("VMess global padding requires chunk masking".into()));
        }
        if !matches!(self.command, RequestCommand::Tcp | RequestCommand::Udp | RequestCommand::Mux) {
            return Err(Error::Protocol("unsupported VMess command".into()));
        }
        Ok(())
    }
    pub fn encode_payload(&self, padding: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        if padding.len() > 15 { return Err(Error::Protocol("VMess header padding exceeds 15 bytes".into())); }
        let mut bytes = Vec::with_capacity(320);
        bytes.push(VMESS_VERSION); bytes.extend_from_slice(&self.request_body_iv);
        bytes.extend_from_slice(&self.request_body_key);
        bytes.extend_from_slice(&[self.response_header_byte, self.options,
            ((padding.len() as u8) << 4) | self.security as u8, 0, self.command.to_u8()]);
        if self.command != RequestCommand::Mux {
            bytes.extend_from_slice(&self.destination.port.to_be_bytes());
            match &self.destination.address {
                Address::Ipv4(ip) => { bytes.push(1); bytes.extend_from_slice(&ip.octets()); }
                Address::Ipv6(ip) => { bytes.push(3); bytes.extend_from_slice(&ip.octets()); }
                Address::Domain(domain) => {
                    let length = u8::try_from(domain.len()).map_err(|_| Error::Protocol("VMess domain exceeds 255 bytes".into()))?;
                    if length == 0 { return Err(Error::Protocol("empty VMess domain".into())); }
                    bytes.extend_from_slice(&[2, length]); bytes.extend_from_slice(domain.as_bytes());
                }
            }
        }
        bytes.extend_from_slice(padding);
        let checksum = fnv1a_32(&bytes);
        bytes.extend_from_slice(&checksum.to_be_bytes());
        Ok(bytes)
    }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let padding_length = usize::from(rand::random::<u8>() & 15);
        let random: [u8; 16] = rand::random();
        let payload = self.encode_payload(&random[..padding_length])?;
        let key = command_key(&self.user_id);
        let auth_id = AuthIdGenerator::new(&key).create_auth_id(unix_seconds()?);
        let bytes = seal_request_payload(&key, &payload, &auth_id, &rand::random())?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R, validator: &MemoryValidator) -> Result<Self> {
        Self::decode_at(reader, validator, unix_seconds()?).await
    }
    pub async fn decode_at<R: AsyncRead + Unpin>(reader: &mut R, validator: &MemoryValidator, now: u64) -> Result<Self> {
        let mut auth_id = [0u8; 16]; reader.read_exact(&mut auth_id).await?;
        let user = validator.authenticate(&auth_id, now)?;
        let key = command_key(&user.id);
        let mut encrypted_length = [0u8; 18]; reader.read_exact(&mut encrypted_length).await?;
        let mut nonce = [0u8; 8]; reader.read_exact(&mut nonce).await?;
        let length = header_cipher(&key, HEADER_LENGTH_KEY, &auth_id, &nonce).open_with_aad(
            &nonce12(&kdf(&key, &[HEADER_LENGTH_NONCE, &auth_id, &nonce])), &encrypted_length, &auth_id)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let mut ciphertext = vec![0u8; length + 16]; reader.read_exact(&mut ciphertext).await?;
        let payload = header_cipher(&key, HEADER_KEY, &auth_id, &nonce).open_with_aad(
            &nonce12(&kdf(&key, &[HEADER_NONCE, &auth_id, &nonce])), &ciphertext, &auth_id)?;
        // Go reserves a body-key/IV session immediately after the fixed
        // 38-byte prefix, before checksum/address/security validation.
        if payload.len() >= 38 {
            let mut iv = [0u8;16]; iv.copy_from_slice(&payload[1..17]);
            let mut body_key = [0u8;16]; body_key.copy_from_slice(&payload[17..33]);
            validator.register_session_parts(&user.id, body_key, iv, now)?;
        }
        Self::decode_payload(user.id, &payload)
    }
    pub fn decode_payload(user_id: Uuid, payload: &[u8]) -> Result<Self> {
        let mut cursor = HeaderCursor { bytes: payload, offset: 0 };
        let version = cursor.byte()?;
        let request_body_iv = cursor.take(16)?.try_into().map_err(|_| Error::Protocol("invalid VMess IV".into()))?;
        let request_body_key = cursor.take(16)?.try_into().map_err(|_| Error::Protocol("invalid VMess key".into()))?;
        let response_header_byte = cursor.byte()?; let options = cursor.byte()?;
        let padding_security = cursor.byte()?;
        let security = BodySecurity::from_byte(padding_security & 15)?;
        let _reserved = cursor.byte()?;
        let command = RequestCommand::from_u8(cursor.byte()?).ok_or_else(|| Error::Protocol("invalid VMess command".into()))?;
        let destination = if command == RequestCommand::Mux {
            Destination::tcp(Address::Domain("v1.mux.cool".into()), 0)
        } else {
            let port = cursor.take(2)?; let port = u16::from_be_bytes([port[0],port[1]]);
            let address = match cursor.byte()? {
                1 => Address::Ipv4(std::net::Ipv4Addr::from(<[u8;4]>::try_from(cursor.take(4)?).map_err(|_| Error::Protocol("invalid IPv4".into()))?)),
                3 => address_from_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8;16]>::try_from(cursor.take(16)?).map_err(|_| Error::Protocol("invalid IPv6".into()))?))),
                2 => {
                    let length = usize::from(cursor.byte()?);
                    let domain = std::str::from_utf8(cursor.take(length)?).map_err(|_| Error::Protocol("invalid VMess domain".into()))?;
                    if domain.is_empty() { return Err(Error::Protocol("empty VMess domain".into())); }
                    let maybe_ip = domain.as_bytes()[0].is_ascii_digit() || domain.starts_with('[');
                    let candidate = domain.strip_prefix('[').and_then(|value| value.strip_suffix(']')).unwrap_or(domain).trim();
                    let parsed_ip = maybe_ip.then(|| candidate.parse::<std::net::IpAddr>().ok()).flatten();
                    if let Some(ip) = parsed_ip {
                        address_from_ip(ip)
                    } else {
                        if !domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')) {
                            return Err(Error::Protocol("invalid VMess domain characters".into()));
                        }
                        Address::Domain(domain.into())
                    }
                }
                _ => return Err(Error::Protocol("invalid VMess address type".into())),
            };
            if command == RequestCommand::Udp { Destination::udp(address,port) } else { Destination::tcp(address,port) }
        };
        cursor.take(usize::from(padding_security >> 4))?;
        let checksum_offset = cursor.offset;
        let expected = cursor.take(4)?;
        if fnv1a_32(&payload[..checksum_offset]).to_be_bytes().as_slice() != expected {
            return Err(Error::AuthFailed("invalid VMess request checksum".into()));
        }
        let header = Self { version, user_id, request_body_iv, request_body_key, response_header_byte, options, security, command, destination };
        header.validate()?;
        Ok(header)
    }
}
struct HeaderCursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> HeaderCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| Error::Protocol("VMess header overflow".into()))?;
        let output = self.bytes.get(self.offset..end).ok_or_else(|| Error::Protocol("truncated VMess header".into()))?;
        self.offset = end; Ok(output)
    }
    fn byte(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
}

#[derive(Debug, Clone, Default)]
pub struct ResponseHeader {
    pub response_header_byte: u8,
    pub option: u8,
    pub command: Option<RequestCommand>,
}
impl ResponseHeader {
    pub fn new(response_header_byte: u8) -> Self { Self { response_header_byte, option: 0, command: None } }
    pub fn encode_bytes(&self, request: &RequestHeader) -> Result<Vec<u8>> {
        if self.command.is_some() { return Err(Error::Protocol("pinned Go VMess supports no response commands".into())); }
        let (key, iv) = response_key_iv(request);
        let length = VmessAeadEncryptor::new(&kdf16(&key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY])).seal(
            &nonce12(&kdf(&iv, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV])), &4u16.to_be_bytes())?;
        let payload = VmessAeadEncryptor::new(&kdf16(&key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY])).seal(
            &nonce12(&kdf(&iv, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV])), &[self.response_header_byte, self.option, 0, 0])?;
        let mut output = length; output.extend(payload); Ok(output)
    }
    pub fn decode_length(request: &RequestHeader, bytes: &[u8]) -> Result<usize> {
        if bytes.len() != 18 { return Err(Error::Protocol("invalid VMess response length field size".into())); }
        let (key, iv) = response_key_iv(request);
        let length = VmessAeadEncryptor::new(&kdf16(&key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY])).open(
            &nonce12(&kdf(&iv, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV])), bytes)?;
        Ok(usize::from(u16::from_be_bytes([length[0], length[1]])))
    }
    pub fn decode_payload(request: &RequestHeader, bytes: &[u8]) -> Result<Self> {
        let (key, iv) = response_key_iv(request);
        let payload = VmessAeadEncryptor::new(&kdf16(&key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY])).open(
            &nonce12(&kdf(&iv, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV])), bytes)?;
        if payload.len() < 4 || payload[0] != request.response_header_byte {
            return Err(Error::AuthFailed("unexpected VMess response header byte".into()));
        }
        if payload[2] != 0 && payload.len() < 4 + usize::from(payload[3]) {
            return Err(Error::Protocol("truncated VMess response command".into()));
        }
        // Go ignores commands it cannot unmarshal; this revision has no factories.
        Ok(Self { response_header_byte: payload[0], option: payload[1], command: None })
    }
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W, request: &RequestHeader) -> Result<()> {
        writer.write_all(&self.encode_bytes(request)?).await?; writer.flush().await?; Ok(())
    }
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R, request: &RequestHeader) -> Result<Self> {
        let mut length = [0u8; 18]; reader.read_exact(&mut length).await?;
        let mut payload = vec![0u8; Self::decode_length(request, &length)? + 16];
        reader.read_exact(&mut payload).await?;
        Self::decode_payload(request, &payload)
    }
}
