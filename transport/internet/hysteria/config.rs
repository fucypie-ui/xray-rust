use crate::common::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HysteriaTransportConfig {
    pub auth: String,
    pub recv_window_conn: u64,
    pub recv_window_client: u64,
    pub max_conn_client: usize,
    pub max_idle_timeout: u64,
    pub keep_alive_period: u64,
    pub handshake_timeout: u64,
    pub udp_idle_timeout: u64,
    pub congestion: String,
    pub bbr_profile: String,
    pub brutal_disable_loss_compensation: bool,
    pub disable_path_mtu_discovery: bool,
    pub disable_gso: bool,
    pub masq_type: String,
    pub masq_string: String,
    pub masq_string_headers: BTreeMap<String, String>,
    pub masq_string_status_code: u16,
}
impl Default for HysteriaTransportConfig {
    fn default() -> Self {
        Self {
            auth: String::new(), recv_window_conn: 20 * 1024 * 1024,
            recv_window_client: 8 * 1024 * 1024, max_conn_client: 1024,
            max_idle_timeout: 30, keep_alive_period: 0, handshake_timeout: 10,
            udp_idle_timeout: 60, congestion: String::new(), bbr_profile: "standard".into(),
            brutal_disable_loss_compensation: false, disable_path_mtu_discovery: false,
            disable_gso: false, masq_type: String::new(), masq_string: String::new(),
            masq_string_headers: BTreeMap::new(), masq_string_status_code: 0,
        }
    }
}
impl HysteriaTransportConfig {
    pub fn validate(&self) -> Result<()> {
        if self.recv_window_client == 0 || self.recv_window_conn < self.recv_window_client
            || self.recv_window_conn >= 1 << 62 || self.max_conn_client == 0
            || self.max_conn_client as u64 >= 1 << 60 {
            return Err(Error::Config("invalid Hysteria QUIC receive windows/stream limit".into()));
        }
        if self.max_idle_timeout == 0 || self.max_idle_timeout > 86400
            || self.handshake_timeout == 0 || self.handshake_timeout > 3600
            || self.udp_idle_timeout == 0 || self.udp_idle_timeout > 86400
            || self.keep_alive_period >= self.max_idle_timeout {
            return Err(Error::Config("invalid Hysteria timeout/keepalive".into()));
        }
        if !matches!(self.congestion.as_str(), "" | "reno" | "bbr" | "brutal" | "force-brutal") {
            return Err(Error::Config("unknown Hysteria congestion controller".into()));
        }
        if matches!(self.congestion.as_str(), "brutal" | "force-brutal") || self.brutal_disable_loss_compensation {
            return Err(Error::Unsupported("Hysteria Brutal pacing is not implemented by the Quinn adapter".into()));
        }
        if !matches!(self.bbr_profile.as_str(), "" | "standard") {
            return Err(Error::Unsupported("Quinn does not expose Xray's conservative/aggressive BBR profiles".into()));
        }
        if !matches!(self.masq_type.to_ascii_lowercase().as_str(), "" | "404" | "string") {
            return Err(Error::Unsupported("Hysteria file/proxy masquerade requires an HTTP handler supplied by the caller".into()));
        }
        if self.masq_string_status_code != 0 && !(200..=599).contains(&self.masq_string_status_code) {
            return Err(Error::Config("invalid Hysteria masquerade status".into()));
        }
        for (name, value) in &self.masq_string_headers {
            http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::Config("invalid masquerade header name".into()))?;
            http::HeaderValue::from_str(value).map_err(|_| Error::Config("invalid masquerade header value".into()))?;
        }
        Ok(())
    }
}
