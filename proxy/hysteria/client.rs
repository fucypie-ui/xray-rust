use super::{config::HysteriaConfig, protocol::{TcpRequest, TcpResponse}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network}, protocol::SessionContext},
    features::outbound::OutboundHandler,
    transport::internet::hysteria::{HysteriaConn, endpoint, padding::padding::Padding, udp::UdpSession}};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

pub struct HysteriaClient {
    pub tag: String,
    pub server: Destination,
    pub config: HysteriaConfig,
    tls: Arc<rustls::ClientConfig>,
    connection: tokio::sync::Mutex<Option<HysteriaConn>>,
}
impl HysteriaClient {
    pub fn new(tag: impl Into<String>, server: Destination, config: HysteriaConfig) -> Self {
        Self::with_tls(tag, server, config, Arc::new(endpoint::client_tls()))
    }
    pub fn with_tls(tag: impl Into<String>, server: Destination, config: HysteriaConfig, tls: Arc<rustls::ClientConfig>) -> Self {
        Self { tag: tag.into(), server, config, tls, connection: tokio::sync::Mutex::new(None) }
    }
    pub async fn authenticated_connection(&self) -> Result<HysteriaConn> {
        self.config.validate(false)?;
        let mut guard = self.connection.lock().await;
        if let Some(connection) = guard.as_ref().filter(|connection| !connection.is_closed()) { return Ok(connection.clone()); }
        let name = self.config.server_name.clone().unwrap_or_else(|| self.server.address.to_string());
        let address = if let Some(address) = self.server.to_socket_addr() { address } else {
            tokio::time::timeout(Duration::from_secs(self.config.transport.handshake_timeout), tokio::net::lookup_host(self.server.net_addr())).await
                .map_err(|_| Error::Protocol("Hysteria server DNS lookup timed out".into()))??
                .next().ok_or_else(|| Error::Config("Hysteria server DNS lookup returned no addresses".into()))?
        };
        let connection = HysteriaConn::connect(address, &name, &self.tls, &self.config).await?;
        *guard = Some(connection.clone());
        Ok(connection)
    }
    pub async fn open_udp(&self) -> Result<UdpSession> { self.authenticated_connection().await?.open_udp() }
}
#[async_trait]
impl OutboundHandler for HysteriaClient {
    fn tag(&self) -> &str { &self.tag }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<crate::common::net::datagram::BoxDatagram> {
        Ok(super::native::OutboundPackets::boxed(self.open_udp().await?, session))
    }
    async fn close(&self) -> Result<()> {
        if let Some(connection) = self.connection.lock().await.take() { connection.close(); }
        Ok(())
    }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        if session.destination.network != Network::Tcp {
            return Err(Error::Unsupported("Hysteria UDP requires open_udp() and whole datagrams".into()));
        }
        let connection = self.authenticated_connection().await?;
        let exchange = async {
            let mut stream = connection.open_bi().await?;
            let padding = Padding::new(64, 512).generate_string();
            let request = TcpRequest::new(session.destination.to_string(), padding.len());
            let mut encoded = request.encode_stream()?;
            let start = encoded.len() - padding.len();
            encoded[start..].copy_from_slice(padding.as_bytes());
            stream.write_all(&encoded).await?;
            stream.flush().await?;
            let response = TcpResponse::decode(&mut stream).await?;
            if !response.ok { return Err(Error::Protocol(format!("Hysteria destination rejected: {}", response.message))); }
            Ok(Box::pin(stream) as BoxStream)
        };
        tokio::time::timeout(Duration::from_secs(self.config.transport.handshake_timeout), exchange).await
            .map_err(|_| Error::Protocol("Hysteria TCP request timed out".into()))?
    }
}
