use crate::common::errors::Result;
use md5::{Digest, Md5};
use shake::{Shake128, Shake128Reader, digest::{ExtendableOutput, Update, XofReader}};

pub const AUTH_TIME_TOLERANCE: u64 = 120;
pub fn authenticate(bytes: &[u8]) -> u32 { super::encoding::fnv1a_32(bytes) }
pub fn generate_chacha20poly1305_key(seed: &[u8]) -> [u8; 32] {
    let first = Md5::digest(seed);
    let second = Md5::digest(first);
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

pub struct ShakeSizeParser { reader: Shake128Reader }
impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        let mut shake = Shake128::default();
        Update::update(&mut shake, nonce);
        Self { reader: shake.finalize_xof() }
    }
    pub fn next_mask(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
    pub fn size_bytes(&self) -> usize { 2 }
    pub fn encode(&mut self, size: u16) -> [u8; 2] { (size ^ self.next_mask()).to_be_bytes() }
    pub fn decode(&mut self, bytes: &[u8; 2]) -> Result<u16> {
        Ok(u16::from_be_bytes(*bytes) ^ self.next_mask())
    }
    pub fn next_padding_len(&mut self) -> u16 { self.next_mask() % 64 }
    pub fn max_padding_len(&self) -> u16 { 64 }
}

pub struct NoOpAuthenticator;
impl NoOpAuthenticator {
    pub fn seal<'a>(&self, plaintext: &'a [u8]) -> &'a [u8] { plaintext }
    pub fn open<'a>(&self, ciphertext: &'a [u8]) -> Result<&'a [u8]> { Ok(ciphertext) }
}
