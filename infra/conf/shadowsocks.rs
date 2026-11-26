use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksServerConfig {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub iv_check: Option<bool>,
}

pub type ShadowsocksInboundConfig = ShadowsocksServerConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksServerTarget {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub uot: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksOutboundConfig {
    #[serde(default)]
    pub servers: Vec<ShadowsocksServerTarget>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uot: Option<bool>,
}

use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination};
use crate::features::inbound::InboundHandler;
use crate::features::outbound::OutboundHandler;
use crate::proxy::shadowsocks_2022::{Client, Server, Shadowsocks2022Config};
use serde_json::Value;
use std::sync::Arc;

fn is_2022(method: &str) -> bool { method.to_ascii_lowercase().starts_with("2022-") }

// Inspect the original JSON before generic settings normalization can discard
// users, PSK chains or UDP options. Unsupported SS2022 must never reach legacy SS.
fn contains_2022(value: &Value) -> bool {
    if value.get("method").and_then(Value::as_str).is_some_and(is_2022) { return true; }
    ["servers", "users", "clients"].iter().any(|field| {
        value.get(*field).and_then(Value::as_array).is_some_and(|items| items.iter().any(contains_2022))
    })
}

fn reject_users(value: &Value) -> Result<()> {
    for field in ["users", "clients"] {
        if let Some(items) = value.get(field).filter(|items| !items.is_null()) {
            let items = items.as_array().ok_or_else(|| Error::Config(format!("SS2022 {field} must be an array")))?;
            if !items.is_empty() {
                return Err(Error::Unsupported("SS2022 EIH, multi-user and relay configurations are not implemented".into()));
            }
        }
    }
    if value.get("uot").is_some_and(|uot| !uot.is_null() && uot != &Value::Bool(false)) {
        return Err(Error::Unsupported("SS2022 UDP-over-TCP is not implemented".into()));
    }
    if let Some(network) = value.get("network").filter(|network| !network.is_null())
        && !network.as_str().is_some_and(|network| network.eq_ignore_ascii_case("tcp"))
    {
        return Err(Error::Unsupported("SS2022 supports only single-user TCP; UDP is not implemented".into()));
    }
    Ok(())
}

fn validate_2022_transport(stream: Option<&super::conf::StreamSettingsConfig>) -> Result<()> {
    if let Some(stream) = stream {
        let network = stream.network.as_deref().unwrap_or("tcp");
        let security = stream.security.as_deref().unwrap_or("none");
        if !(network.eq_ignore_ascii_case("tcp") || network.eq_ignore_ascii_case("raw"))
            || !security.eq_ignore_ascii_case("none") || stream.finalmask.is_some()
        {
            return Err(Error::Unsupported("SS2022 currently requires plain TCP streamSettings".into()));
        }
    }
    Ok(())
}

pub(crate) fn build_2022_inbound(
    tag: &str, raw: Option<&Value>, stream: Option<&super::conf::StreamSettingsConfig>,
) -> Result<Option<Arc<dyn InboundHandler>>> {
    let Some(raw) = raw.filter(|raw| contains_2022(raw)) else { return Ok(None); };
    reject_users(raw)?;
    validate_2022_transport(stream)?;
    let settings: ShadowsocksServerConfig = serde_json::from_value(raw.clone())
        .map_err(|error| Error::Config(format!("Invalid SS2022 inbound settings: {error}")))?;
    if !is_2022(&settings.method) || raw.get("servers").is_some_and(|servers| !servers.is_null()) {
        return Err(Error::Unsupported("SS2022 inbound requires one settings.method/password pair".into()));
    }
    let config = Shadowsocks2022Config { method: settings.method, key: settings.password, network: settings.network };
    Ok(Some(Arc::new(Server::try_new(tag, config)?)))
}

pub(crate) fn build_2022_outbound(
    tag: &str, raw: Option<&Value>, stream: Option<&super::conf::StreamSettingsConfig>, mux: Option<&Value>,
) -> Result<Option<Arc<dyn OutboundHandler>>> {
    let Some(raw) = raw.filter(|raw| contains_2022(raw)) else { return Ok(None); };
    reject_users(raw)?;
    validate_2022_transport(stream)?;
    if let Some(mux) = mux.filter(|mux| !mux.is_null())
        && (!mux.is_object() || mux.get("enabled").is_some_and(|enabled| enabled != &Value::Bool(false)))
    {
        return Err(Error::Unsupported("SS2022 multiplexing is not implemented".into()));
    }
    let settings: ShadowsocksOutboundConfig = serde_json::from_value(raw.clone())
        .map_err(|error| Error::Config(format!("Invalid SS2022 outbound settings: {error}")))?;
    let endpoint = if settings.address.is_some() {
        if !settings.servers.is_empty() {
            return Err(Error::Config("SS2022 settings must use either address or servers, not both".into()));
        }
        ShadowsocksServerTarget {
            address: settings.address, port: settings.port, method: settings.method,
            password: settings.password, uot: settings.uot, level: None, email: None,
        }
    } else {
        if settings.servers.len() != 1 {
            return Err(Error::Unsupported("SS2022 outbound requires exactly one server".into()));
        }
        if let Some(server) = raw.get("servers").and_then(Value::as_array).and_then(|servers| servers.first()) { reject_users(server)?; }
        settings.servers.into_iter().next().ok_or_else(|| Error::Config("SS2022 server missing".into()))?
    };
    if endpoint.uot == Some(true) { return Err(Error::Unsupported("SS2022 UDP-over-TCP is not implemented".into())); }
    let address = endpoint.address.filter(|address| !address.is_empty()).ok_or_else(|| Error::Config("SS2022 server address missing".into()))?;
    let port = endpoint.port.filter(|port| *port != 0).ok_or_else(|| Error::Config("SS2022 server port must be nonzero".into()))?;
    let method = endpoint.method.filter(|method| is_2022(method)).ok_or_else(|| Error::Config("SS2022 server method missing or mixed with legacy SS".into()))?;
    let config = Shadowsocks2022Config { method, key: endpoint.password.unwrap_or_default(), network: Some("tcp".into()) };
    let address = address.parse::<Address>()?;
    Ok(Some(Arc::new(Client::try_new(tag, Destination::tcp(address, port), config)?)))
}

#[cfg(test)]
mod ss2022_tests {
    use super::*;
    use crate::common::protocol::SessionContext;
    use super::super::conf::Config;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;

    const METHOD: &str = "2022-blake3-aes-128-gcm";
    const KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";

    #[test]
    fn ss2022_runtime_rejects_unsupported_combinations() {
        let inbound = json!({"method": METHOD, "password": KEY});
        assert!(build_2022_inbound("ss", Some(&inbound), None).unwrap().is_some());
        for extra in [
            json!({"network": "udp"}), json!({"network": "tcp,udp"}),
            json!({"users": [{"password": KEY}]}),
            json!({"clients": [{"password": KEY}]}),
            json!({"users": [{"password": KEY, "address": "127.0.0.1", "port": 80}]}),
            json!({"method": "2022-blake3-chacha20-poly1305"}),
            json!({"method": "2022-unknown"}), json!({"password": "short"}),
            json!({"password": format!("{KEY}:{KEY}")}), json!({"uot": true}),
        ] {
            let mut raw = inbound.clone();
            raw.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            assert!(build_2022_inbound("ss", Some(&raw), None).is_err(), "accepted {raw}");
            let config: Config = serde_json::from_value(json!({"inbounds": [{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388, "settings": raw}]})).unwrap();
            assert!(config.build().is_err());
        }
        let outbound = json!({"address": "127.0.0.1", "port": 8388, "method": METHOD, "password": KEY});
        assert!(build_2022_outbound("ss", Some(&outbound), None, None).unwrap().is_some());
        for extra in [
            json!({"uot": true}), json!({"network": "udp"}),
            json!({"password": format!("{KEY}:{KEY}")}), json!({"password": "invalid"}),
            json!({"method": "2022-blake3-chacha20-poly1305"}),
            json!({"clients": [{"password": KEY}]}),
            json!({"port": 0}), json!({"address": ""}),
        ] {
            let mut raw = outbound.clone();
            raw.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            assert!(build_2022_outbound("ss", Some(&raw), None, None).is_err(), "accepted {raw}");
        }
        let two = json!({"servers": [outbound.clone(), outbound.clone()]});
        assert!(build_2022_outbound("ss", Some(&two), None, None).is_err());
        let mixed = json!({"servers": [outbound.clone(), {"method": "aes-256-gcm", "password": "legacy"}]});
        assert!(build_2022_outbound("ss", Some(&mixed), None, None).is_err());
        let nested_uot = json!({"servers": [{"address": "127.0.0.1", "port": 8388, "method": METHOD, "password": KEY, "uot": true}]});
        assert!(build_2022_outbound("ss", Some(&nested_uot), None, None).is_err());
        for stream in [json!({"network": "ws"}), json!({"security": "tls"}), json!({"finalmask": {"tcp": []}})] {
            let stream = serde_json::from_value(stream).unwrap();
            assert!(build_2022_outbound("ss", Some(&outbound), Some(&stream), None).is_err());
        }
        assert!(build_2022_outbound("ss", Some(&outbound), None, Some(&json!({"enabled": true}))).is_err());
    }

    #[test]
    fn ss2022_legacy_settings_keep_original_dispatch() {
        let inbound = json!({"method": "aes-256-gcm", "password": "legacy", "network": "tcp,udp"});
        assert!(build_2022_inbound("legacy", Some(&inbound), None).unwrap().is_none());
        let outbound = json!({"servers": [{"address": "127.0.0.1", "port": 8388, "method": "chacha20-ietf-poly1305", "password": "legacy", "uot": true}]});
        assert!(build_2022_outbound("legacy", Some(&outbound), None, None).unwrap().is_none());
        let config: Config = serde_json::from_value(json!({"inbounds": [{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388, "settings": inbound}], "outbounds": [{"protocol": "shadowsocks", "settings": outbound}]})).unwrap();
        assert!(config.build().is_ok());
    }

    #[test]
    fn ss2022_runtime_inbound_rejects_unsupported_stream_settings() {
        for stream in [
            json!({"security": "tls"}), json!({"security": "reality"}),
            json!({"security": "unknown"}), json!({"network": "ws"}),
            json!({"network": "websocket"}), json!({"network": "grpc"}),
            json!({"network": "xhttp"}), json!({"network": "httpupgrade"}),
            json!({"network": "unknown"}), json!({"finalmask": {"tcp": []}}),
        ] {
            let config: Config = serde_json::from_value(json!({"inbounds": [{
                "protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388,
                "settings": {"method": METHOD, "password": KEY}, "streamSettings": stream,
            }]})).unwrap();
            let error = config.build().err().expect("unsupported SS2022 stream must fail at build");
            assert!(matches!(error, Error::Unsupported(message) if message.contains("plain TCP")), "wrong rejection for {stream}");
        }
        for network in ["tcp", "raw"] {
            let config: Config = serde_json::from_value(json!({"inbounds": [{
                "protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388,
                "settings": {"method": METHOD, "password": KEY},
                "streamSettings": {"network": network, "security": "none"},
            }]})).unwrap();
            assert!(config.build().is_ok());
        }
        // Legacy SS still reaches the existing generic inbound wrapper.
        let config: Config = serde_json::from_value(json!({"inbounds": [{
            "protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388,
            "settings": {"method": "aes-256-gcm", "password": "legacy"},
            "streamSettings": {"network": "ws"},
        }]})).unwrap();
        assert!(config.build().is_ok());
    }

    #[tokio::test]
    async fn ss2022_runtime_config_selects_authenticated_handlers() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (method, key, nested) in [
                (METHOD, KEY, false),
                ("2022-BLAKE3-AES-256-GCM", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", true),
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let endpoint = json!({"address": "127.0.0.1", "port": address.port(), "method": method, "password": key});
                let settings = if nested { json!({"servers": [endpoint]}) } else { endpoint };
                let config: Config = serde_json::from_value(json!({
                    "inbounds": [{"tag": "ss-in", "protocol": "shadowsocks", "listen": "127.0.0.1", "port": 8388, "settings": {"method": method, "password": key, "network": "tcp"}}],
                    "outbounds": [{"tag": "ss-out", "protocol": "shadowsocks", "settings": settings}],
                })).unwrap();
                let mut built = config.build().unwrap();
                let server = built.inbounds.remove(0).1;
                let client = built.outbounds.remove("ss-out").unwrap();
                let worker = tokio::spawn(async move {
                    let (stream, remote) = listener.accept().await.unwrap();
                    let mut inbound = server.handle_connection(Box::pin(stream), remote).await.unwrap();
                    assert_eq!(inbound.session.destination, Destination::from_domain_port("example.com", 443));
                    let mut payload = [0; 4];
                    inbound.stream.read_exact(&mut payload).await.unwrap();
                    assert_eq!(&payload, b"ping");
                    inbound.stream.write_all(b"pong").await.unwrap();
                    inbound.stream.shutdown().await.unwrap();
                });
                let mut stream = client.connect(&SessionContext::new("test", Destination::from_domain_port("example.com", 443))).await.unwrap();
                stream.write_all(b"ping").await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"pong");
                worker.await.unwrap();
            }
        }).await.unwrap();
    }
}
