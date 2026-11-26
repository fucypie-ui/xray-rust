use base64::{Engine as _, engine::general_purpose};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, net::IpAddr};

use crate::common::errors::{Error, Result};
use super::wireguard::{DEFAULT_MTU, parse_endpoints};

fn default_addresses() -> Vec<String> {
    vec!["10.0.0.1".into(), "fd59:7153:2388:b5fd::1".into()]
}
fn default_allowed_ips() -> Vec<String> { vec!["0.0.0.0/0".into(), "::/0".into()] }

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPeer {
    #[serde(rename = "publicKey", alias = "public_key")]
    pub public_key: String,
    #[serde(default, rename = "preSharedKey", alias = "pre_shared_key", alias = "preshared_key")]
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, rename = "keepAlive", alias = "keepalive", alias = "keep_alive")]
    pub keepalive: u16,
    #[serde(default = "default_allowed_ips", rename = "allowedIPs", alias = "allowed_ips")]
    pub allowed_ips: Vec<String>,
}

impl Default for WireGuardPeer {
    fn default() -> Self {
        Self { public_key: String::new(), pre_shared_key: None, endpoint: String::new(),
            keepalive: 0, allowed_ips: default_allowed_ips() }
    }
}

impl fmt::Debug for WireGuardPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardPeer").field("public_key", &self.public_key)
            .field("pre_shared_key", &self.pre_shared_key.as_ref().map(|_| "[redacted]"))
            .field("endpoint", &self.endpoint).field("keepalive", &self.keepalive)
            .field("allowed_ips", &self.allowed_ips).finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardConfig {
    #[serde(rename = "secretKey", alias = "secret_key")]
    pub secret_key: String,
    #[serde(default = "default_addresses")]
    pub address: Vec<String>,
    #[serde(default)]
    pub peers: Vec<WireGuardPeer>,
    #[serde(default, alias = "MTU")]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
    #[serde(default, rename = "remoteDNS", alias = "remote_dns")]
    pub remote_dns: Vec<String>,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self { secret_key: String::new(), address: default_addresses(), peers: Vec::new(),
            mtu: None, reserved: None, remote_dns: Vec::new() }
    }
}

impl fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardConfig").field("secret_key", &"[redacted]")
            .field("address", &self.address).field("peers", &self.peers)
            .field("mtu", &self.mtu).field("reserved", &self.reserved)
            .field("remote_dns", &self.remote_dns).finish()
    }
}

/// WireGuard accepts a 32-byte hexadecimal, standard-base64, or URL-base64 key.
/// Unlike the Go JSON parser, reject base64 decoding to a non-key length here.
pub fn parse_key(value: &str) -> Result<[u8; 32]> {
    let decoded = if value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(value).map_err(|_| Error::Config("invalid WireGuard hexadecimal key".into()))?
    } else {
        let value = value.trim_end_matches('=');
        general_purpose::STANDARD_NO_PAD.decode(value)
            .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
            .map_err(|_| Error::Config("invalid WireGuard base64 key".into()))?
    };
    decoded.try_into().map_err(|_| Error::Config("WireGuard keys must decode to exactly 32 bytes".into()))
}

pub(crate) struct ValidatedPeer {
    pub public_key: [u8; 32],
    pub pre_shared_key: Option<[u8; 32]>,
    pub endpoint: String,
    pub keepalive: u16,
    pub allowed_ips: Vec<IpNet>,
}

pub(crate) struct ValidatedConfig {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpAddr>,
    pub peers: Vec<ValidatedPeer>,
    pub mtu: usize,
    pub reserved: [u8; 3],
    pub dns: Vec<IpAddr>,
}

impl WireGuardConfig {
    pub fn validate(&self) -> Result<()> { self.validated().map(|_| ()) }

    pub(crate) fn validated(&self) -> Result<ValidatedConfig> {
        let private_key = parse_key(&self.secret_key)?;
        if private_key == [0; 32] { return Err(Error::Config("WireGuard private key must not be zero".into())); }
        let secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&secret).to_bytes();
        let (addresses, _, has_v6) = parse_endpoints(&self.address)?;
        if addresses.is_empty() || addresses.len() > 8 {
            return Err(Error::Config("WireGuard needs between one and eight interface addresses".into()));
        }
        if addresses.iter().any(|ip| ip.is_unspecified() || ip.is_multicast()) {
            return Err(Error::Config("WireGuard interface addresses must be unicast".into()));
        }
        let mtu = self.mtu.filter(|mtu| *mtu != 0).unwrap_or(DEFAULT_MTU) as usize;
        let minimum_mtu = if has_v6 { 1280 } else { 576 };
        if !(minimum_mtu..=65_475).contains(&mtu) {
            return Err(Error::Config("WireGuard MTU must be 576..=65475 (at least 1280 with IPv6)".into()));
        }
        let mut reserved = [0; 3];
        if let Some(bytes) = &self.reserved {
            if !bytes.is_empty() && bytes.len() != 3 {
                return Err(Error::Config("WireGuard reserved must be empty or exactly three bytes".into()));
            }
            if bytes.len() == 3 { reserved.copy_from_slice(bytes); }
        }
        if self.peers.is_empty() || self.peers.len() > 65_535 {
            return Err(Error::Config("WireGuard needs between one and 65535 peers".into()));
        }
        let mut seen = HashSet::new();
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let key = parse_key(&peer.public_key)?;
            if key == public_key || secret.diffie_hellman(&PublicKey::from(key)).to_bytes() == [0; 32] {
                return Err(Error::Config("invalid WireGuard peer public key (self or low order)".into()));
            }
            if !seen.insert(key) { return Err(Error::Config("duplicate WireGuard peer public key".into())); }
            if !peer.endpoint.is_empty() { validate_endpoint(&peer.endpoint)?; }
            let allowed_ips = peer.allowed_ips.iter().map(|text| text.parse::<IpNet>()
                .map(|prefix| prefix.trunc())
                .map_err(|_| Error::Config(format!("invalid WireGuard allowed IP prefix: {text}"))))
                .collect::<Result<Vec<_>>>()?;
            let pre_shared_key = peer.pre_shared_key.as_deref().filter(|key| !key.is_empty())
                .map(parse_key).transpose()?.filter(|key| *key != [0; 32]);
            peers.push(ValidatedPeer { public_key: key, pre_shared_key, endpoint: peer.endpoint.clone(),
                keepalive: peer.keepalive, allowed_ips });
        }
        let dns_text = if self.remote_dns.is_empty() {
            vec!["1.1.1.1".into(), "1.0.0.1".into(), "2606:4700:4700::1111".into(), "2606:4700:4700::1001".into()]
        } else { self.remote_dns.clone() };
        let dns = dns_text.iter().map(|text| text.parse::<IpAddr>()
            .map_err(|_| Error::Config(format!("WireGuard remoteDNS must contain IP addresses: {text}"))))
            .collect::<Result<Vec<_>>>()?;
        Ok(ValidatedConfig { private_key, addresses, peers, mtu, reserved, dns })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let invalid = || Error::Config(format!("invalid WireGuard endpoint: {endpoint}"));
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(invalid)?;
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if port == 0 || host.is_empty() || host.chars().any(char::is_whitespace)
        || (host.contains(':') && endpoint.parse::<std::net::SocketAddr>().is_err()) {
        return Err(invalid());
    }
    Ok(())
}
