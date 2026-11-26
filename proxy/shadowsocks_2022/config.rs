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

#[derive(Clone, Copy)]
pub(super) struct Networks { pub tcp: bool, pub udp: bool }
impl Networks {
    pub const BOTH: Self = Self { tcp: true, udp: true };
    pub fn parse(network: Option<&str>) -> crate::common::errors::Result<Self> {
        let Some(network) = network else { return Ok(Self::BOTH); };
        let mut result = Self { tcp: false, udp: false };
        for name in network.split(',') {
            if name.eq_ignore_ascii_case("tcp") { result.tcp = true; }
            else if name.eq_ignore_ascii_case("udp") { result.udp = true; }
            else { return Err(crate::common::errors::Error::Config(format!("invalid SS2022 network: {network}"))); }
        }
        Ok(result)
    }
}

impl Shadowsocks2022Config {
    pub fn validate_outbound_tcp(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<Vec<u8>>)> {
        let method = super::cipher::CipherMethod::parse(&self.method)?;
        Networks::parse(self.network.as_deref())?;
        Ok((method, super::kdf::parse_psk_list(&self.key, method)?))
    }

    pub fn validate_tcp(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<u8>)> {
        if !Networks::parse(self.network.as_deref())?.tcp {
            return Err(crate::common::errors::Error::Unsupported("SS2022 inbound TCP is disabled".into()));
        }
        self.validate_inbound()
    }

    pub(super) fn validate_inbound(&self) -> crate::common::errors::Result<(super::cipher::CipherMethod, Vec<u8>)> {
        use crate::common::errors::Error;
        let method = super::cipher::CipherMethod::parse(&self.method)?;
        Networks::parse(self.network.as_deref())?;
        if self.key.contains(':') {
            return Err(Error::Unsupported("SS2022 single-user inbound requires one PSK; use a multi-user or relay inbound for EIH".into()));
        }
        let key = super::kdf::parse_key(&self.key, method.key_length())?;
        Ok((method, key))
    }
}
