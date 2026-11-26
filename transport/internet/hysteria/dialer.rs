use super::{HysteriaTransportConfig, HysteriaConn, endpoint};
use crate::{common::errors::Result, proxy::hysteria::config::HysteriaConfig};
use std::{net::SocketAddr, sync::Arc};

pub struct HysteriaDialer {
    pub config: HysteriaTransportConfig,
    tls: Arc<rustls::ClientConfig>,
    server_name: Option<String>,
}
impl HysteriaDialer {
    pub fn new(config: HysteriaTransportConfig) -> Self { Self { config, tls: Arc::new(endpoint::client_tls()), server_name: None } }
    pub fn with_tls(config: HysteriaTransportConfig, tls: Arc<rustls::ClientConfig>, server_name: String) -> Self { Self { config, tls, server_name: Some(server_name) } }
    pub async fn dial(&self, addr: SocketAddr) -> Result<HysteriaConn> {
        let config = HysteriaConfig { transport: self.config.clone(), ..HysteriaConfig::default() };
        let name = self.server_name.clone().unwrap_or_else(|| addr.ip().to_string());
        HysteriaConn::connect(addr, &name, &self.tls, &config).await
    }
}
