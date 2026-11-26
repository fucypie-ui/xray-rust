//! VMess's nested HMAC construction, which is deliberately not HKDF.
use sha2::{Digest, Sha256};

fn nested_hash(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
    let Some((key, previous)) = keys.split_last() else {
        return Sha256::digest(message).into();
    };
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        normalized[..32].copy_from_slice(&nested_hash(previous, key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend(normalized.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let digest = nested_hash(previous, &inner);
    let mut outer = [0u8; 96];
    for (out, key) in outer[..64].iter_mut().zip(normalized) { *out = key ^ 0x5c; }
    outer[64..].copy_from_slice(&digest);
    nested_hash(previous, &outer)
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(super::consts::KDF_SALT_CONST_VMESS_AEAD_KDF);
    keys.extend_from_slice(path);
    nested_hash(&keys, key)
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut output = [0u8; 16];
    output.copy_from_slice(&kdf(key, path)[..16]);
    output
}

pub fn vmess_kdf_1(key: &[u8], path1: &[u8]) -> [u8; 16] { kdf16(key, &[path1]) }
pub fn vmess_kdf_2(key: &[u8], path1: &[u8], path2: &[u8]) -> [u8; 16] {
    kdf16(key, &[path1, path2])
}
