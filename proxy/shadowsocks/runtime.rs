//! Thin adapters to the maintained shadowsocks-rust protocol engine.
//! Cipher selection and password derivation are delegated to that engine.
//! Reviewed: shadowsocks 1.25.0 / shadowsocks-crypto 0.8.0, tagged sources:
//! https://github.com/shadowsocks/shadowsocks-rust/tree/v1.25.0/crates/shadowsocks
//! https://github.com/shadowsocks/shadowsocks-crypto/tree/v0.8.0
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use shadowsocks::{
    config::{ReplayAttackPolicy, ServerConfig, ServerType},
    context::{Context, SharedContext},
    crypto::CipherKind,
    relay::socks5::Address as EngineAddress,
};
use std::{net::SocketAddr, sync::Arc};

pub(super) fn method(name: &str) -> Result<CipherKind> {
    match name.to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "aead_aes_128_gcm" => Ok(CipherKind::AES_128_GCM),
        "aes-256-gcm" | "aead_aes_256_gcm" => Ok(CipherKind::AES_256_GCM),
        "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => {
            Ok(CipherKind::CHACHA20_POLY1305)
        }
        "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => {
            Ok(CipherKind::XCHACHA20_POLY1305)
        }
        _ => Err(Error::Unsupported(format!("unsupported classic Shadowsocks method: {name}"))),
    }
}

pub(super) fn account(name: &str, password: &str) -> Result<ServerConfig> {
    let method = method(name)?;
    if password.is_empty() {
        return Err(Error::Config("Shadowsocks password is not specified".into()));
    }
    // Only the upstream key derivation and method are needed here: dialing uses
    // Xray's dialer, not the placeholder address in this upstream configuration.
    let placeholder = SocketAddr::from(([127, 0, 0, 1], 1));
    ServerConfig::new(placeholder, password, method)
        .map_err(|error| Error::Config(format!("invalid Shadowsocks account: {error}")))
}

pub(super) fn context(server_type: ServerType) -> SharedContext {
    let mut context = Context::new(server_type);
    // Default upstream policy accepts replay. Both the Reject policy and the
    // security-replay-attack-detect dependency feature are necessary.
    context.set_replay_attack_policy(ReplayAttackPolicy::Reject);
    Arc::new(context)
}

pub(super) fn address(destination: &Destination) -> Result<EngineAddress> {
    match &destination.address {
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(Error::Protocol("Shadowsocks domain must contain 1..255 bytes".into()));
            }
            Ok(EngineAddress::DomainNameAddress(domain.clone(), destination.port))
        }
        Address::Ipv4(ip) => Ok(EngineAddress::SocketAddress(SocketAddr::new((*ip).into(), destination.port))),
        Address::Ipv6(ip) => Ok(EngineAddress::SocketAddress(SocketAddr::new((*ip).into(), destination.port))),
    }
}

pub(super) fn destination(address: EngineAddress) -> Result<Destination> {
    match address {
        EngineAddress::SocketAddress(address) => Ok(address.into()),
        EngineAddress::DomainNameAddress(domain, port) => {
            let destination = Destination::from_domain_port(domain, port);
            self::address(&destination)?;
            Ok(destination)
        }
    }
}
