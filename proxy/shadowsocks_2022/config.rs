use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shadowsocks2022Config {
    pub method: String,
    pub key: String,
    #[serde(default)]
    pub network: Option<String>,
}

pub const CIPHER_2022_BLAKE3_AES_128_GCM: &str = "2022-blake3-aes-128-gcm";
pub const CIPHER_2022_BLAKE3_AES_256_GCM: &str = "2022-blake3-aes-256-gcm";
pub const CIPHER_2022_BLAKE3_CHACHA20_POLY1305: &str = "2022-blake3-chacha20-poly1305";

impl Shadowsocks2022Config {
    pub fn validate_tcp(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<u8>)> {
        use crate::common::errors::Error;
        let method = super::cipher::CipherMethod::parse(&self.method)?;
        if let Some(network) = &self.network
            && !network.eq_ignore_ascii_case("tcp")
        {
            return Err(Error::Unsupported("SS2022 supports only single-user TCP; UDP is not implemented".into()));
        }
        if self.key.contains(':') {
            return Err(Error::Unsupported("SS2022 EIH/PSK chains and relay are not implemented".into()));
        }
        let key = super::kdf::parse_key(&self.key, method.key_length())?;
        Ok((method, key))
    }
}
