use crate::common::errors::{Error, Result};
use aes_gcm::{Aes128Gcm, aead::{Aead, KeyInit, Payload}};

pub struct VmessAeadEncryptor { cipher: Aes128Gcm }
impl VmessAeadEncryptor {
    pub fn new(key: &[u8; 16]) -> Self { Self { cipher: Aes128Gcm::new(&(*key).into()) } }
    pub fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_aad(nonce, plaintext, &[])
    }
    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.open_with_aad(nonce, ciphertext, &[])
    }
    pub fn seal_with_aad(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(&(*nonce).into(), Payload { msg: plaintext, aad })
            .map_err(|_| Error::Crypto("VMess AEAD encryption failed".into()))
    }
    pub fn open_with_aad(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(&(*nonce).into(), Payload { msg: ciphertext, aad })
            .map_err(|_| Error::AuthFailed("VMess AEAD authentication failed".into()))
    }
}
