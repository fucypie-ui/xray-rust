//! Authenticated VMess body chunks. Lengths include tag and clear padding.
use super::{auth::ShakeSizeParser, encoding::{BodySecurity, RequestHeader, OPTION_AUTHENTICATED_LENGTH, OPTION_CHUNK_MASKING, OPTION_GLOBAL_PADDING, generate_chacha20_key, response_key_iv}};
use crate::common::{errors::{Error, Result}, protocol::RequestCommand};
use crate::proxy::vmess::aead::kdf::kdf16;
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit}};
use chacha20poly1305::ChaCha20Poly1305;

const TAG: usize = 16;
// common/buf/buffer.go at the pinned commit defines Size = 8192.
const GO_BUFFER_SIZE: usize = 8192;

enum Cipher { Aes(Box<Aes128Gcm>), ChaCha(Box<ChaCha20Poly1305>) }
impl Cipher {
    fn new(security: BodySecurity, key: &[u8; 16]) -> Self {
        match security {
            BodySecurity::Aes128Gcm => Self::Aes(Box::new(Aes128Gcm::new(&(*key).into()))),
            BodySecurity::ChaCha20Poly1305 => Self::ChaCha(Box::new(ChaCha20Poly1305::new(&generate_chacha20_key(key).into()))),
        }
    }
    fn seal(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher) => cipher.encrypt(&(*nonce).into(), data),
            Self::ChaCha(cipher) => cipher.encrypt(&(*nonce).into(), data),
        }.map_err(|_| Error::Crypto("VMess body encryption failed".into()))
    }
    fn open(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher) => cipher.decrypt(&(*nonce).into(), data),
            Self::ChaCha(cipher) => cipher.decrypt(&(*nonce).into(), data),
        }.map_err(|_| Error::AuthFailed("VMess body authentication failed".into()))
    }
}

struct ChunkNonce { iv: [u8; 12], count: u16 }
impl ChunkNonce {
    fn new(iv: &[u8; 16]) -> Self {
        let mut nonce = [0u8; 12]; nonce.copy_from_slice(&iv[..12]); Self { iv: nonce, count: 0 }
    }
    fn next(&mut self) -> [u8; 12] {
        self.iv[..2].copy_from_slice(&self.count.to_be_bytes());
        // This is the pinned Go uint16 counter, including its wrap behavior.
        self.count = self.count.wrapping_add(1);
        self.iv
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction { Request, Response }
struct BodyState {
    cipher: Cipher,
    nonce: ChunkNonce,
    length_cipher: Option<Cipher>,
    length_nonce: ChunkNonce,
    shake: Option<ShakeSizeParser>,
    global_padding: bool,
}
impl BodyState {
    fn new(request: &RequestHeader, direction: Direction) -> Result<Self> {
        request.validate()?;
        let (key,iv) = match direction {
            Direction::Request => (request.request_body_key, request.request_body_iv),
            Direction::Response => response_key_iv(request),
        };
        // Go intentionally derives *both directions* of authenticated lengths
        // from the request key/IV, independently of the response body cipher.
        let length_cipher = (request.options & OPTION_AUTHENTICATED_LENGTH != 0).then(|| {
            Cipher::new(request.security, &kdf16(&request.request_body_key, &[b"auth_len"]))
        });
        Ok(Self {
            cipher: Cipher::new(request.security, &key), nonce: ChunkNonce::new(&iv),
            length_cipher, length_nonce: ChunkNonce::new(&request.request_body_iv),
            shake: (request.options & OPTION_CHUNK_MASKING != 0).then(|| ShakeSizeParser::new(&iv)),
            global_padding: request.options & OPTION_GLOBAL_PADDING != 0,
        })
    }
    fn length_bytes(&self) -> usize { if self.length_cipher.is_some() {18} else {2} }
    fn padding(&mut self) -> usize {
        if self.global_padding {
            self.shake.as_mut().map_or(0, |shake| usize::from(shake.next_padding_len()))
        } else {0}
    }
}

pub struct BodyEncoder { state: BodyState, packet: bool, finished: bool }
impl BodyEncoder {
    pub fn new(request: &RequestHeader, direction: Direction) -> Result<Self> {
        Ok(Self { state: BodyState::new(request,direction)?, packet: request.command == RequestCommand::Udp, finished: false })
    }
    pub fn max_stream_payload(&self) -> usize {
        GO_BUFFER_SIZE - TAG - self.state.length_bytes() - if self.state.global_padding {64} else {0}
    }
    pub fn is_packet(&self) -> bool { self.packet }
    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.encode_frame_with_padding(data, rand::fill)
    }
    /// Injectable padding is only for deterministic independent-vector tests.
    pub fn encode_frame_with_padding<F: FnMut(&mut [u8])>(&mut self, data: &[u8], mut fill: F) -> Result<Vec<u8>> {
        if self.finished { return Err(Error::Protocol("write after VMess termination".into())); }
        let padding = self.state.padding();
        let size = data.len().checked_add(TAG + padding).ok_or(Error::BufferOverflow)?;
        if self.state.length_bytes() + size > GO_BUFFER_SIZE {
            return Err(Error::Protocol("VMess packet exceeds Go's 8192-byte frame limit".into()));
        }
        let size = u16::try_from(size).map_err(|_| Error::BufferOverflow)?;
        let mut frame = if let Some(cipher) = &self.state.length_cipher {
            // AEADChunkSizeParser subtracts its own tag overhead before sealing.
            cipher.seal(&self.state.length_nonce.next(), &(size - TAG as u16).to_be_bytes())?
        } else if let Some(shake) = &mut self.state.shake {
            shake.encode(size).to_vec()
        } else { size.to_be_bytes().to_vec() };
        frame.extend(self.state.cipher.seal(&self.state.nonce.next(), data)?);
        let end = frame.len(); frame.resize(end + padding,0); fill(&mut frame[end..]);
        if data.is_empty() { self.finished = true; }
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameLength { pub size: usize, pub padding: usize }
impl FrameLength {
    /// Go recognizes EOF from this length before reading its tag or padding.
    pub fn is_terminal(self) -> bool { self.size == TAG + self.padding }
}
pub struct BodyDecoder { state: BodyState }
impl BodyDecoder {
    pub fn new(request: &RequestHeader, direction: Direction) -> Result<Self> {
        Ok(Self {state: BodyState::new(request,direction)?})
    }
    pub fn length_bytes(&self) -> usize {self.state.length_bytes()}
    pub fn decode_length(&mut self, bytes: &[u8]) -> Result<FrameLength> {
        if bytes.len() != self.length_bytes() { return Err(Error::Protocol("invalid VMess length field size".into())); }
        let padding = self.state.padding();
        let size = if let Some(cipher) = &self.state.length_cipher {
            let plain = cipher.open(&self.state.length_nonce.next(),bytes)?;
            let size = u16::from_be_bytes([plain[0],plain[1]]);
            // Match Go's uint16 addition without debug-mode overflow panics.
            usize::from(size.wrapping_add(TAG as u16))
        } else {
            let raw = [bytes[0],bytes[1]];
            usize::from(if let Some(shake) = &mut self.state.shake {shake.decode(&raw)?} else {u16::from_be_bytes(raw)})
        };
        if size < TAG + padding {return Err(Error::Protocol("VMess chunk shorter than padding and tag".into()));}
        Ok(FrameLength {size,padding})
    }
    pub fn decode_frame(&mut self, length: FrameLength, bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() != length.size || length.padding > length.size || length.size - length.padding < TAG {
            return Err(Error::Protocol("invalid VMess body frame length".into()));
        }
        self.state.cipher.open(&self.state.nonce.next(), &bytes[..length.size-length.padding])
    }
    pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut bytes = vec![0u8;self.length_bytes()]; reader.read_exact(&mut bytes).await?;
        let length = self.decode_length(&bytes)?;
        if length.is_terminal() { return Ok(Vec::new()); }
        bytes.resize(length.size,0); reader.read_exact(&mut bytes).await?;
        self.decode_frame(length,&bytes)
    }
}
