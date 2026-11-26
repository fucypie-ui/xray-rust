use base64::Engine as _;
use base64::alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use crate::common::errors::{Error, Result};

pub const CONTEXT_SESSION_SUBKEY: &str = "shadowsocks 2022 session subkey";

// Match Go ParseKey: standard padded base64, falling back to literal bytes only
// if decoding fails. Go's decoder ignores CR/LF and accepts nonzero trailing bits.
pub fn parse_key(key: &str, key_length: usize) -> Result<Vec<u8>> {
    let engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true));
    let normalized: String = key.chars().filter(|&c| c != '\r' && c != '\n').collect();
    let raw = engine.decode(normalized.as_bytes()).unwrap_or_else(|_| key.as_bytes().to_vec());
    if raw.len() != key_length {
        return Err(Error::Config(format!("SS2022 key must decode to exactly {key_length} bytes")));
    }
    Ok(raw)
}

pub fn derive_session_subkey(psk: &[u8], salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_SESSION_SUBKEY);
    hasher.update(&material);
    let mut key = vec![0; key_length];
    hasher.finalize_xof().fill(&mut key);
    key
}

/// Parse a Go PSK chain; the last key encrypts the stream, earlier keys are EIHs.
pub fn parse_psk_list(password: &str, method: super::cipher::CipherMethod) -> Result<Vec<Vec<u8>>> {
    let keys = password.split(':').map(|part| parse_key(part, method.key_length())).collect::<Result<Vec<_>>>()?;
    if method.is_chacha() && keys.len() != 1 {
        return Err(Error::Config("SS2022 ChaCha20 does not support EIH chains".into()));
    }
    Ok(keys)
}

pub fn derive_identity_subkey(psk: &[u8], salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
    hasher.update(psk);
    hasher.update(salt);
    let mut key = vec![0; key_length];
    hasher.finalize_xof().fill(&mut key);
    key
}

pub fn user_psk_hash(psk: &[u8]) -> [u8; 16] {
    let mut hash = [0; 16];
    hash.copy_from_slice(&blake3::hash(psk).as_bytes()[..16]);
    hash
}
