use crate::common::errors::{Error, Result};
use crate::transport::internet::hysteria::HysteriaTransportConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HysteriaUser {
    pub auth: String,
    #[serde(default)] pub email: String,
    #[serde(default)] pub level: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HysteriaConfig {
    pub auth: String,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub users: Vec<HysteriaUser>,
    pub server_name: Option<String>,
    pub transport: HysteriaTransportConfig,
}
impl HysteriaConfig {
    pub fn new(auth: impl Into<String>, up_mbps: u64, down_mbps: u64) -> Self {
        Self { auth: auth.into(), up_mbps, down_mbps, ..Self::default() }
    }
    pub fn validate(&self, server: bool) -> Result<()> {
        self.transport.validate()?;
        if !self.auth.is_empty() && !self.transport.auth.is_empty() && self.auth != self.transport.auth {
            return Err(Error::Config("conflicting Hysteria proxy/transport authentication".into()));
        }
        if self.up_mbps > 0 {
            return Err(Error::Unsupported("Hysteria Brutal transmit rate requires a rate-pacing engine; Quinn BBR is available with up_mbps=0".into()));
        }
        http::HeaderValue::from_str(self.auth_value()).map_err(|_| Error::Config("invalid Hysteria authentication header".into()))?;
        if self.auth_value().is_empty() && (!server || self.users.is_empty()) {
            return Err(Error::Config("Hysteria authentication must not be empty".into()));
        }
        if self.up_mbps.checked_mul(125_000).is_none() || self.down_mbps.checked_mul(125_000).is_none() {
            return Err(Error::Config("Hysteria bandwidth overflows bytes per second".into()));
        }
        if self.users.iter().any(|user| user.auth.is_empty()) {
            return Err(Error::Config("Hysteria user authentication must not be empty".into()));
        }
        let mut keys = std::collections::HashSet::new();
        if self.users.iter().any(|user| !keys.insert(&user.auth)) {
            return Err(Error::Config("duplicate Hysteria user authentication".into()));
        }
        Ok(())
    }
    pub fn auth_value(&self) -> &str { if self.auth.is_empty() { &self.transport.auth } else { &self.auth } }
    pub fn tx_bytes(&self) -> u64 { self.up_mbps.saturating_mul(125_000) }
    pub fn rx_bytes(&self) -> u64 { self.down_mbps.saturating_mul(125_000) }
}
