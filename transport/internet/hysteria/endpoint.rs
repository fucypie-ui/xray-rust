//! TLS-verified QUIC endpoints. Only H3 ALPN and TLS 1.3 are used.
use super::HysteriaTransportConfig;
use crate::common::errors::{Error, Result};
use std::{net::SocketAddr, sync::Arc, time::Duration};

pub fn transport(config: &HysteriaTransportConfig) -> Result<quinn::TransportConfig> {
    config.validate()?;
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(quinn::VarInt::from_u64(config.recv_window_conn).map_err(|error| Error::Config(error.to_string()))?);
    transport.stream_receive_window(quinn::VarInt::from_u64(config.recv_window_client).map_err(|error| Error::Config(error.to_string()))?);
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u64(config.max_conn_client as u64).map_err(|error| Error::Config(error.to_string()))?);
    transport.max_concurrent_uni_streams(16u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(config.max_idle_timeout).try_into().map_err(|error: quinn::VarIntBoundsExceeded| Error::Config(error.to_string()))?));
    transport.keep_alive_interval((config.keep_alive_period > 0).then(|| Duration::from_secs(config.keep_alive_period)));
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.enable_segmentation_offload(!config.disable_gso);
    if config.disable_path_mtu_discovery { transport.mtu_discovery_config(None); }
    match config.congestion.as_str() {
        "reno" => { transport.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())); }
        _ => { transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())); }
    }
    Ok(transport)
}

pub fn client_tls() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).expect("TLS 1.3 provider")
        .with_root_certificates(roots).with_no_client_auth()
}

pub fn client(addr: SocketAddr, tls: &rustls::ClientConfig, config: &HysteriaTransportConfig) -> Result<quinn::Endpoint> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|error| Error::Config(error.to_string()))?;
    let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
    quic.transport_config(Arc::new(transport(config)?));
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let mut endpoint = quinn::Endpoint::client(bind.parse().expect("literal bind address"))?;
    endpoint.set_default_client_config(quic);
    Ok(endpoint)
}

pub fn server(addr: SocketAddr, tls: &rustls::ServerConfig, config: &HysteriaTransportConfig) -> Result<quinn::Endpoint> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|error| Error::Config(error.to_string()))?;
    let crypto = super::go_compat::HysteriaServerCrypto(Arc::new(crypto));
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    quic.transport_config(Arc::new(transport(config)?));
    Ok(quinn::Endpoint::server(quic, addr)?)
}
