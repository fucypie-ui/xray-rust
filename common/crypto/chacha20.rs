use crate::common::errors::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use super::internal::chacha::ChaChaCore;

/// Construct the raw ChaCha20 stream used by Xray-core (without a Poly1305 tag).
pub fn new_chacha20_stream(key: &[u8], nonce: &[u8]) -> Result<ChaChaCore> {
    let key: &[u8; 32] = key.try_into()
        .map_err(|_| Error::Crypto("ChaCha20 key must be 32 bytes".into()))?;
    ChaChaCore::from_nonce(key, nonce)
}

pub struct ChaCha20Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let key_ref: &Key = key.into();
        let cipher = ChaCha20Poly1305::new(key_ref);
        Self { cipher }
    }
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let n: &Nonce = nonce.into();
        self.cipher.encrypt(n, plaintext).map_err(|e| Error::Crypto(e.to_string()))
    }
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let n: &Nonce = nonce.into();
        self.cipher.decrypt(n, ciphertext).map_err(|e| Error::Crypto(e.to_string()))
    }
}
