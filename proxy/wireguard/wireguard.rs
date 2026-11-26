use super::config::WireGuardConfig;
use crate::common::errors::{Error, Result};
use std::{fmt::Write, net::IpAddr, str::FromStr};

pub const PROTOCOL_NAME: &str = "wireguard";
pub const DEFAULT_MTU: u32 = 1420;

/// Go accepts either an IP literal or a CIDR and retains the host address.
pub fn parse_endpoints(endpoints: &[String]) -> Result<(Vec<IpAddr>, bool, bool)> {
    let (mut addrs, mut has_v4, mut has_v6) = (Vec::with_capacity(endpoints.len()), false, false);
    for text in endpoints {
        let (ip, prefix) = text.split_once('/').map_or((text.as_str(), None), |(ip, prefix)| (ip, Some(prefix)));
        let address = IpAddr::from_str(ip).map_err(|_| Error::Config(format!("invalid WireGuard interface IP: {text}")))?;
        if let Some(prefix) = prefix {
            let prefix = prefix.parse::<u8>().map_err(|_| Error::Config("invalid WireGuard address prefix".into()))?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                return Err(Error::Config("invalid WireGuard address prefix".into()));
            }
        }
        has_v4 |= address.is_ipv4(); has_v6 |= address.is_ipv6(); addrs.push(address);
    }
    Ok((addrs, has_v4, has_v6))
}

/// Checked diagnostic/export helper. Runtime encryption uses BoringTun directly.
pub fn create_ipc_request(conf: &WireGuardConfig, is_client: bool, listen_port: Option<u16>) -> Result<String> {
    let config = conf.validated()?;
    let mut request = format!("private_key={}\n", hex::encode(config.private_key));
    if !is_client { let _ = writeln!(request, "listen_port={}", listen_port.unwrap_or(1337)); }
    for peer in &config.peers {
        let _ = writeln!(request, "public_key={}", hex::encode(peer.public_key));
        if let Some(key) = peer.pre_shared_key { let _ = writeln!(request, "preshared_key={}", hex::encode(key)); }
        if !peer.endpoint.is_empty() { let _ = writeln!(request, "endpoint={}", peer.endpoint); }
        let _ = writeln!(request, "replace_allowed_ips=true");
        for prefix in &peer.allowed_ips { let _ = writeln!(request, "allowed_ip={prefix}"); }
        if peer.keepalive != 0 { let _ = writeln!(request, "persistent_keepalive_interval={}", peer.keepalive); }
    }
    Ok(request)
}
