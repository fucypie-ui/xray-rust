use shadowsocks_crypto::{CipherKind, v2::tcp::TcpCipher};
use crate::common::errors::{Error, Result};
use std::io;

use super::config::{CIPHER_2022_BLAKE3_AES_128_GCM, CIPHER_2022_BLAKE3_AES_256_GCM, CIPHER_2022_BLAKE3_CHACHA20_POLY1305};

pub const AEAD_TAG_SIZE: usize = 16;
pub const STREAM_NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherMethod {
    pub fn parse(method: &str) -> Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            CIPHER_2022_BLAKE3_AES_128_GCM => Ok(Self::Aes128Gcm),
            CIPHER_2022_BLAKE3_AES_256_GCM => Ok(Self::Aes256Gcm),
            CIPHER_2022_BLAKE3_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::Unsupported(format!("Shadowsocks 2022 method: {method}"))),
        }
    }

    pub fn key_length(self) -> usize {
        match self { Self::Aes128Gcm => 16, Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32 }
    }
}

impl CipherMethod {
    pub(crate) fn kind(self) -> CipherKind {
        match self {
            Self::Aes128Gcm => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            Self::Aes256Gcm => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            Self::ChaCha20Poly1305 => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }

    pub fn is_chacha(self) -> bool { self == Self::ChaCha20Poly1305 }
}

// Reuse the official MIT-licensed engine for KDF, AEAD and nonce progression.
// Keep the Go record codec and a terminal-failure/exhaustion guard outside it.
pub(crate) struct CipherState {
    cipher: TcpCipher,
    nonce: [u8; STREAM_NONCE_SIZE],
    exhausted: bool,
}

impl CipherState {
    pub(crate) fn new(method: CipherMethod, psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        if psk.len() != method.key_length() || salt.len() != method.key_length() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SS2022 key or salt length"));
        }
        Ok(Self { cipher: TcpCipher::new(method.kind(), psk, salt), nonce: [0; STREAM_NONCE_SIZE], exhausted: false })
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        self.check_nonce()?;
        let mut result = vec![0; plaintext.len() + AEAD_TAG_SIZE];
        result[..plaintext.len()].copy_from_slice(plaintext);
        self.cipher.encrypt_packet(&mut result);
        self.exhausted = !increase_nonce(&mut self.nonce);
        Ok(result)
    }

    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        self.check_nonce()?;
        if ciphertext.len() < AEAD_TAG_SIZE {
            self.exhausted = true;
            return Err(invalid_data("short SS2022 AEAD chunk"));
        }
        let mut result = ciphertext.to_vec();
        if !self.cipher.decrypt_packet(&mut result) {
            self.exhausted = true;
            return Err(invalid_data("SS2022 authentication failed"));
        }
        result.truncate(result.len() - AEAD_TAG_SIZE);
        self.exhausted = !increase_nonce(&mut self.nonce);
        Ok(result)
    }

    fn check_nonce(&self) -> io::Result<()> {
        if self.exhausted { return Err(invalid_data("SS2022 cipher failed or nonce exhausted")); }
        Ok(())
    }
}

// Go IncreaseNonce treats the nonce as a little-endian 96-bit counter.
// Return false on wrap so callers cannot reuse nonce zero with the same key.
pub fn increase_nonce(nonce: &mut [u8; STREAM_NONCE_SIZE]) -> bool {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 { return true; }
    }
    false
}

pub(crate) fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss2022_nonce_exhaustion_never_reuses_zero() {
        let mut writer = CipherState::new(CipherMethod::Aes128Gcm, &[1; 16], &[2; 16]).unwrap();
        let mut reader = CipherState::new(CipherMethod::Aes128Gcm, &[1; 16], &[2; 16]).unwrap();
        writer.nonce = [255; STREAM_NONCE_SIZE];
        reader.nonce = [255; STREAM_NONCE_SIZE];
        let encrypted = writer.seal(b"last nonce").unwrap();
        assert_eq!(reader.open(&encrypted).unwrap(), b"last nonce");
        assert!(writer.seal(b"must fail").is_err());
        assert!(reader.open(&encrypted).is_err());
    }
}
