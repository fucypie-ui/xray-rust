//! SIP022 extensible identity headers, using RustCrypto AES block operations.
use aes_gcm::aes::{Aes128, Aes256, cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit}};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::common::net::BoxStream;
use super::{cipher::{CipherMethod, invalid_data}, kdf::{derive_identity_subkey, user_psk_hash}};

pub(crate) enum HeaderCipher { Aes128(Box<Aes128>), Aes256(Box<Aes256>) }

impl HeaderCipher {
    pub(crate) fn new(method: CipherMethod, key: &[u8]) -> io::Result<Self> {
        match method {
            CipherMethod::Aes128Gcm => Ok(Self::Aes128(Box::new(Aes128::new_from_slice(key).map_err(|_| invalid_data("invalid AES128 identity key"))?))),
            CipherMethod::Aes256Gcm => Ok(Self::Aes256(Box::new(Aes256::new_from_slice(key).map_err(|_| invalid_data("invalid AES256 identity key"))?))),
            CipherMethod::ChaCha20Poly1305 => Err(invalid_data("ChaCha20 does not support EIH")),
        }
    }
    pub(crate) fn encrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut block = Block::<Aes128>::from(*input);
        match self { Self::Aes128(c) => c.encrypt_block(&mut block), Self::Aes256(c) => c.encrypt_block(&mut block) }
        block.into()
    }
    pub(crate) fn decrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut block = Block::<Aes128>::from(*input);
        match self { Self::Aes128(c) => c.decrypt_block(&mut block), Self::Aes256(c) => c.decrypt_block(&mut block) }
        block.into()
    }
}

pub(crate) fn validate_psks(method: CipherMethod, psks: &[Vec<u8>]) -> io::Result<()> {
    if psks.is_empty() || psks.iter().any(|key| key.len() != method.key_length()) || (method.is_chacha() && psks.len() != 1) {
        return Err(invalid_data("invalid SS2022 key chain"));
    }
    Ok(())
}

pub(crate) fn tcp_headers(method: CipherMethod, psks: &[Vec<u8>], salt: &[u8]) -> io::Result<Vec<u8>> {
    validate_psks(method, psks)?;
    if salt.len() != method.key_length() { return Err(invalid_data("invalid identity salt")); }
    let mut output = Vec::new();
    for pair in psks.windows(2) {
        let key = derive_identity_subkey(&pair[0], salt, method.key_length());
        output.extend_from_slice(&HeaderCipher::new(method, &key)?.encrypt(&user_psk_hash(&pair[1])));
    }
    Ok(output)
}

pub(crate) fn tcp_identity(method: CipherMethod, key: &[u8], salt: &[u8], eih: &[u8; 16]) -> io::Result<[u8; 16]> {
    if key.len() != method.key_length() || salt.len() != method.key_length() { return Err(invalid_data("invalid identity key/salt")); }
    let subkey = derive_identity_subkey(key, salt, method.key_length());
    Ok(HeaderCipher::new(method, &subkey)?.decrypt(eih))
}

pub(crate) fn udp_identity(cipher: &HeaderCipher, raw: &[u8; 16], eih: &[u8; 16]) -> [u8; 16] {
    let mut hash = cipher.decrypt(eih);
    for (byte, header) in hash.iter_mut().zip(raw) { *byte ^= *header; }
    hash
}

// A relay removes one EIH and forwards the salt with the remaining raw stream.
// This wrapper preserves duplex operation; the relay buffers at most 75 bytes.
pub(crate) struct PrefixedStream { pub(crate) prefix: Vec<u8>, pub(crate) offset: usize, pub(crate) inner: BoxStream }
impl AsyncRead for PrefixedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 { return Poll::Ready(Ok(())); }
        if this.offset < this.prefix.len() {
            let count = output.remaining().min(this.prefix.len() - this.offset);
            output.put_slice(&this.prefix[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        this.inner.as_mut().poll_read(cx, output)
    }
}
impl AsyncWrite for PrefixedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> { self.get_mut().inner.as_mut().poll_write(cx, input) }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { self.get_mut().inner.as_mut().poll_flush(cx) }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { self.get_mut().inner.as_mut().poll_shutdown(cx) }
}
