use aes_gcm::aes::{Aes128, cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit}};
use super::{consts::KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY, kdf::kdf16};

pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1)); }
    }
    !crc
}

pub struct AuthIdGenerator { cipher: Aes128 }
impl AuthIdGenerator {
    /// The key is the account command key (MD5 of UUID and VMess's fixed salt).
    pub fn new(command_key: &[u8]) -> Self {
        Self { cipher: Aes128::new(&kdf16(command_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY]).into()) }
    }
    pub fn create_auth_id(&self, timestamp: u64) -> [u8; 16] {
        self.create_with_random(timestamp, rand::random())
    }
    pub fn create_with_random(&self, timestamp: u64, random: [u8; 4]) -> [u8; 16] {
        let mut plain = [0u8; 16];
        plain[..8].copy_from_slice(&timestamp.to_be_bytes());
        plain[8..12].copy_from_slice(&random);
        let checksum = crc32_ieee(&plain[..12]);
        plain[12..].copy_from_slice(&checksum.to_be_bytes());
        let mut block: Block<Aes128> = plain.into();
        self.cipher.encrypt_block(&mut block);
        block.into()
    }
    pub fn timestamp(&self, auth_id: &[u8; 16]) -> Option<u64> {
        let mut block: Block<Aes128> = (*auth_id).into();
        self.cipher.decrypt_block(&mut block);
        let time = u64::from_be_bytes(block[..8].try_into().ok()?);
        let checksum = u32::from_be_bytes(block[12..].try_into().ok()?);
        (time <= i64::MAX as u64 && checksum == crc32_ieee(&block[..12])).then_some(time)
    }
    pub fn matches(&self, auth_id: &[u8], current_ts: u64, window: u64) -> bool {
        let Ok(id) = <&[u8; 16]>::try_from(auth_id) else { return false; };
        self.timestamp(id).is_some_and(|time| time.abs_diff(current_ts) <= window)
    }
}
