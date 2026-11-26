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
    pub fn validate_outbound_tcp(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<Vec<u8>>)> {
        let method = super::cipher::CipherMethod::parse(&self.method)?;
        self.validate_network()?;
        Ok((method, super::kdf::parse_psk_list(&self.key, method)?))
    }

    fn validate_network(&self) -> crate::common::errors::Result<()> {
        if let Some(network) = &self.network
            && !network.eq_ignore_ascii_case("tcp")
        {
            return Err(crate::common::errors::Error::Unsupported("SS2022 native UDP requires shared datagram runtime integration".into()));
        }
        Ok(())
    }

    pub fn validate_tcp(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<u8>)> {
        use crate::common::errors::Error;
        let method = super::cipher::CipherMethod::parse(&self.method)?;
        self.validate_network()?;
        if self.key.contains(':') {
            return Err(Error::Unsupported("SS2022 single-user inbound requires one PSK; use a multi-user or relay inbound for EIH".into()));
        }
        let key = super::kdf::parse_key(&self.key, method.key_length())?;
        Ok((method, key))
    }
}
