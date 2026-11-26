//! Translate root Go JSON and TLS settings into the Hysteria engine contract.
use std::sync::Arc;
use serde_json::Value;
use crate::{common::{errors::{Error, Result}, net::{Destination, parse_address}}, features::{inbound::InboundHandler, outbound::OutboundHandler}, proxy::hysteria::{HysteriaConfig, HysteriaClient, HysteriaServer}};
use super::{StreamSettingsConfig, TlsSettingsConfig};

fn settings(raw: Option<Value>, stream: Option<&StreamSettingsConfig>, server: bool) -> Result<(Value, HysteriaConfig)> {
    let raw = raw.unwrap_or_else(|| serde_json::json!({}));
    if raw["version"].as_i64() != Some(2) { return Err(Error::Config("version != 2".into())); }
    let mut config = HysteriaConfig::default();
    if let Some(auth) = raw["auth"].as_str() { config.auth = auth.into(); }
    if server {
        let users = raw.get("clients").or_else(|| raw.get("users"));
        if let Some(users) = users { config.users = serde_json::from_value(users.clone()).map_err(|error| Error::Config(format!("invalid Hysteria users: {}", error)))?; }
    }
    if let Some(settings) = stream.and_then(|stream| stream.hysteria_settings.as_ref()) {
        if settings["version"].as_i64() != Some(2) { return Err(Error::Config("version != 2".into())); }
        config.transport.auth = settings["auth"].as_str().unwrap_or_default().into();
        let idle = settings["udpIdleTimeout"].as_u64().unwrap_or(0);
        if idle != 0 && !(2..=600).contains(&idle) { return Err(Error::Config("UdpIdleTimeout must be between 2 and 600".into())); }
        if idle != 0 { config.transport.udp_idle_timeout = idle; }
        if let Some(masquerade) = settings.get("masquerade") {
            config.transport.masq_type = masquerade["type"].as_str().unwrap_or_default().into();
            config.transport.masq_string = masquerade["content"].as_str().unwrap_or_default().into();
            if let Some(headers) = masquerade.get("headers") {
                config.transport.masq_string_headers = serde_json::from_value(headers.clone()).map_err(|error| Error::Config(error.to_string()))?;
            }
            config.transport.masq_string_status_code = masquerade["statusCode"].as_u64().unwrap_or(0).try_into().map_err(|_| Error::Config("invalid masquerade status".into()))?;
        }
    }
    if let Some(quic) = stream.and_then(|stream| stream.finalmask.as_ref()).and_then(|mask| mask.quic.as_ref()) {
        // These options need runtime support beyond the engine's public contract.
        for key in ["brutalUp", "brutalDown", "initStreamReceiveWindow", "initConnectionReceiveWindow", "disableChromeParrot", "disableStatelessReset", "debug"] {
            if quic.get(key).is_some_and(|value| !value.is_null() && value != &Value::Bool(false) && value != &serde_json::json!(0) && value != &serde_json::json!("")) {
                return Err(Error::Unsupported(format!("Hysteria QUIC option is not implemented: {}", key)));
            }
        }
        config.transport.congestion = quic["congestion"].as_str().unwrap_or_default().to_ascii_lowercase();
        if let Some(profile) = quic["bbrProfile"].as_str().filter(|profile| !profile.is_empty()) { config.transport.bbr_profile = profile.to_ascii_lowercase(); }
        config.transport.brutal_disable_loss_compensation = quic["brutalDisableLossCompensation"].as_bool().unwrap_or(false);
        if let Some(window) = quic["maxStreamReceiveWindow"].as_u64().filter(|window| *window != 0) { config.transport.recv_window_client = window; }
        if let Some(window) = quic["maxConnectionReceiveWindow"].as_u64().filter(|window| *window != 0) { config.transport.recv_window_conn = window; }
        if let Some(timeout) = quic["maxIdleTimeout"].as_u64().filter(|value| *value != 0) { config.transport.max_idle_timeout = timeout; }
        if let Some(interval) = quic["keepAlivePeriod"].as_u64() { config.transport.keep_alive_period = interval; }
        if let Some(streams) = quic["maxIncomingStreams"].as_u64().filter(|value| *value != 0) { config.transport.max_conn_client = streams.try_into().map_err(|_| Error::Config("Hysteria stream count overflow".into()))?; }
        config.transport.disable_path_mtu_discovery = quic["disablePathMTUDiscovery"].as_bool().unwrap_or(false);
        config.transport.disable_gso = quic["disableGSO"].as_bool().unwrap_or(false);
    }
    config.validate(server)?;
    Ok((raw, config))
}
fn tls_settings(stream: Option<&StreamSettingsConfig>) -> Result<TlsSettingsConfig> {
    let stream = stream.ok_or_else(|| Error::Config("Hysteria requires streamSettings with TLS".into()))?;
    if stream.security.as_deref() != Some("tls") { return Err(Error::Config("Hysteria requires security=tls".into())); }
    if stream.network.as_deref().is_some_and(|network| network != "hysteria") { return Err(Error::Config("Hysteria requires network=hysteria".into())); }
    let settings = stream.tls_settings.clone().unwrap_or_default();
    if settings.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty() && alpn != &["h3".to_string()]) {
        return Err(Error::Unsupported("Hysteria requires the h3 ALPN".into()));
    }
    Ok(settings)
}
pub(crate) fn client(tag: &str, raw: Option<Value>, stream: Option<&StreamSettingsConfig>) -> Result<Arc<dyn OutboundHandler>> {
    let tls = tls_settings(stream)?;
    let (raw, mut config) = settings(raw, stream, false)?;
    let address = raw["address"].as_str().filter(|address| !address.is_empty()).ok_or_else(|| Error::Config("Hysteria server address is required".into()))?;
    let port: u16 = raw["port"].as_u64().unwrap_or(0).try_into().map_err(|_| Error::Config("invalid Hysteria port".into()))?;
    if port == 0 { return Err(Error::Config("Hysteria server port is required".into())); }
    config.server_name = tls.server_name.filter(|name| !name.is_empty()).or_else(|| Some(address.into()));
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(fingerprint) = tls.fingerprint { crate::transport::internet::tls::tls::apply_fingerprint(&mut provider, &fingerprint); }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(&[&rustls::version::TLS13]).map_err(|error| Error::Config(error.to_string()))?;
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut tls_config = if tls.allow_insecure.unwrap_or(false) {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(crate::transport::internet::tls::NoCertificateVerification)).with_no_client_auth()
    } else { builder.with_root_certificates(roots).with_no_client_auth() };
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let destination = Destination::tcp(parse_address(address), port);
    Ok(Arc::new(HysteriaClient::with_tls(tag, destination, config, Arc::new(tls_config))))
}
pub(crate) fn server(tag: &str, raw: Option<Value>, stream: Option<&StreamSettingsConfig>) -> Result<Arc<dyn InboundHandler>> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let tls = tls_settings(stream)?;
    let (_, config) = settings(raw, stream, true)?;
    let certificates = tls.certificates.unwrap_or_default();
    if certificates.len() != 1 { return Err(Error::Unsupported("Hysteria requires exactly one TLS certificate/key pair".into())); }
    let certificate = &certificates[0];
    let (cert, key) = match (&certificate.certificate_file, &certificate.key_file, &certificate.certificate, &certificate.key) {
        (Some(cert), Some(key), _, _) => (std::fs::read(cert)?, std::fs::read(key)?),
        (_, _, Some(cert), Some(key)) => (cert.join("
").into_bytes(), key.join("
").into_bytes()),
        _ => return Err(Error::Config("Hysteria TLS requires certificateFile/keyFile or certificate/key".into())),
    };
    let certs = CertificateDer::pem_slice_iter(&cert).collect::<std::result::Result<Vec<_>, _>>().map_err(|error| Error::Config(error.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|error| Error::Config(error.to_string()))?;
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(&[&rustls::version::TLS13]).map_err(|error| Error::Config(error.to_string()))?
        .with_no_client_auth().with_single_cert(certs, key).map_err(|error| Error::Config(error.to_string()))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(HysteriaServer::with_tls(tag, config, Arc::new(tls_config))))
}
