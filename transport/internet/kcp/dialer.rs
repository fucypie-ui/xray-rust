use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::config::KcpConfig;
use super::connection::KcpConnection;
use super::runtime::DatagramCodec;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::transport::internet::dialer::{Dialer, lookup_for_ip};

pub struct KcpDialer;
impl KcpDialer {
    pub fn next_conversation() -> u16 {
        static NEXT: OnceLock<AtomicU32> = OnceLock::new();
        NEXT.get_or_init(|| AtomicU32::new(u32::from(rand::random::<u16>())))
            .fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16
    }
    pub async fn dial(addr: SocketAddr, conv: u16) -> Result<KcpConnection> {
        Self::dial_with_config(addr, conv, KcpConfig::default(), CancellationToken::new()).await
    }
    pub async fn dial_with_config(
        addr: SocketAddr, conv: u16, config: KcpConfig, cancellation: CancellationToken,
    ) -> Result<KcpConnection> {
        config.validate()?;
        if cancellation.is_cancelled() { return Err(Error::Closed); }
        let socket = Self::socket(addr).await?;
        KcpConnection::from_socket_with_config(conv, socket, addr, config, cancellation)
    }
    pub async fn dial_with_codec(
        addr: SocketAddr, conv: u16, config: KcpConfig, cancellation: CancellationToken,
        codec: Arc<dyn DatagramCodec>,
    ) -> Result<KcpConnection> {
        config.validate()?;
        if cancellation.is_cancelled() { return Err(Error::Closed); }
        let socket = Self::socket(addr).await?;
        KcpConnection::from_socket_with_codec(conv, socket, addr, config, cancellation, codec)
    }
    pub async fn dial_stream(
        addr: SocketAddr, config: KcpConfig, cancellation: CancellationToken,
    ) -> Result<BoxStream> {
        Ok(Self::dial_with_config(addr, Self::next_conversation(), config, cancellation).await?.into_box_stream())
    }
    async fn socket(addr: SocketAddr) -> Result<Arc<UdpSocket>> {
        let bind = if addr.is_ipv4() { SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)) }
            else { SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)) };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(addr).await?;
        Ok(Arc::new(socket))
    }
}

/// Configured adapter for the existing global Dialer trait. Resolution uses
/// the core DNS path; cancellation covers resolution and every UDP session.
pub struct ConfiguredKcpDialer {
    config: KcpConfig,
    cancellation: CancellationToken,
    codec: Arc<dyn DatagramCodec>,
}
impl ConfiguredKcpDialer {
    pub fn new(config: KcpConfig, cancellation: CancellationToken) -> Result<Self> {
        let codec = super::runtime::config_codec(&config);
        Self::with_codec(config, cancellation, codec)
    }
    pub fn with_codec(config: KcpConfig, cancellation: CancellationToken, codec: Arc<dyn DatagramCodec>) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, cancellation, codec })
    }
}
#[async_trait::async_trait]
impl Dialer for ConfiguredKcpDialer {
    async fn dial(&self, destination: &Destination) -> Result<BoxStream> {
        let addresses = if let Some(address) = destination.to_socket_addr() { vec![address] } else {
            let Address::Domain(domain) = &destination.address else {
                return Err(Error::AddressParse("missing mKCP destination".into()));
            };
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(Error::Closed),
                result = lookup_for_ip(domain, destination.port) => result?,
            }
        };
        let mut last_error = Error::AddressParse("no mKCP destination address".into());
        for address in addresses {
            let result = tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(Error::Closed),
                result = KcpDialer::dial_with_codec(
                    address, KcpDialer::next_conversation(), self.config.clone(),
                    self.cancellation.clone(), self.codec.clone(),
                ) => result,
            };
            match result {
                Ok(connection) => return Ok(connection.into_box_stream()),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}
