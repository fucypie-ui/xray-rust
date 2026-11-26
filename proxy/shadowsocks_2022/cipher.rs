use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use crate::common::errors::{Error, Result};
use std::io;

use super::config::{CIPHER_2022_BLAKE3_AES_128_GCM, CIPHER_2022_BLAKE3_AES_256_GCM};
use super::kdf::derive_session_subkey;

pub const AEAD_TAG_SIZE: usize = 16;
pub const STREAM_NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    Aes128Gcm,
    Aes256Gcm,
}

impl CipherMethod {
    pub fn parse(method: &str) -> Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            CIPHER_2022_BLAKE3_AES_128_GCM => Ok(Self::Aes128Gcm),
            CIPHER_2022_BLAKE3_AES_256_GCM => Ok(Self::Aes256Gcm),
            _ => Err(Error::Unsupported(format!("Shadowsocks 2022 single-user TCP method: {method}"))),
        }
    }

    pub fn key_length(self) -> usize {
        match self { Self::Aes128Gcm => 16, Self::Aes256Gcm => 32 }
    }
}

enum AesCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

pub(crate) struct CipherState {
    cipher: AesCipher,
    nonce: [u8; STREAM_NONCE_SIZE],
    exhausted: bool,
}

impl CipherState {
    pub(crate) fn new(method: CipherMethod, psk: &[u8], salt: &[u8]) -> io::Result<Self> {
        if psk.len() != method.key_length() || salt.len() != method.key_length() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SS2022 key or salt length"));
        }
        let key = derive_session_subkey(psk, salt, method.key_length());
        let cipher = match method {
            CipherMethod::Aes128Gcm => AesCipher::Aes128(Box::new(Aes128Gcm::new_from_slice(&key).map_err(|_| invalid_data("invalid AES key"))?)),
            CipherMethod::Aes256Gcm => AesCipher::Aes256(Box::new(Aes256Gcm::new_from_slice(&key).map_err(|_| invalid_data("invalid AES key"))?)),
        };
        Ok(Self { cipher, nonce: [0; STREAM_NONCE_SIZE], exhausted: false })
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        self.check_nonce()?;
        let nonce = Nonce::from_slice(&self.nonce);
        let result = match &self.cipher {
            AesCipher::Aes128(cipher) => cipher.encrypt(nonce, plaintext),
            AesCipher::Aes256(cipher) => cipher.encrypt(nonce, plaintext),
        }.map_err(|_| invalid_data("SS2022 encryption failed"))?;
        self.exhausted = !increase_nonce(&mut self.nonce);
        Ok(result)
    }

    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        self.check_nonce()?;
        let nonce = Nonce::from_slice(&self.nonce);
        let result = match &self.cipher {
            AesCipher::Aes128(cipher) => cipher.decrypt(nonce, ciphertext),
            AesCipher::Aes256(cipher) => cipher.decrypt(nonce, ciphertext),
        }.map_err(|_| invalid_data("SS2022 authentication failed"))?;
        self.exhausted = !increase_nonce(&mut self.nonce);
        Ok(result)
    }

    fn check_nonce(&self) -> io::Result<()> {
        if self.exhausted { return Err(invalid_data("SS2022 nonce exhausted")); }
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
