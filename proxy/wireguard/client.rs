use async_trait::async_trait;
use std::{net::SocketAddr, sync::atomic::{AtomicBool, Ordering}};
use tokio::sync::Mutex;
use super::{config::WireGuardConfig, device::WireGuardDevice, stack::WireGuardUdpSocket};
use crate::common::{errors::{Error, Result}, net::{BoxStream, Destination, Network}, protocol::SessionContext};
use crate::features::outbound::OutboundHandler;

/// One authenticated device and one userspace IP stack are shared by all flows.
/// Application bytes enter TCP/UDP sockets; only Noise ciphertext reaches UDP.
pub struct Client {
    tag: String,
    config: WireGuardConfig,
    device: Mutex<Option<WireGuardDevice>>,
    closed: AtomicBool,
}
impl Client {
    /// Kept infallible for the runtime's existing handler factory. start/connect
    /// validate before opening a socket; new factories should use try_new.
    pub fn new(tag: impl Into<String>, config: WireGuardConfig) -> Self {
        Self { tag: tag.into(), config, device: Mutex::new(None), closed: AtomicBool::new(false) }
    }
    pub fn try_new(tag: impl Into<String>, config: WireGuardConfig) -> Result<Self> {
        config.validate()?; Ok(Self::new(tag, config))
    }
    pub fn config(&self) -> &WireGuardConfig { &self.config }

    pub async fn device(&self) -> Result<WireGuardDevice> {
        if self.closed.load(Ordering::Acquire) { return Err(Error::Closed); }
        let mut slot = self.device.lock().await;
        if self.closed.load(Ordering::Acquire) { return Err(Error::Closed); }
        if let Some(device) = slot.as_ref() { return Ok(device.clone()); }
        let device = WireGuardDevice::bind(self.config.clone(), SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        *slot = Some(device.clone()); Ok(device)
    }

    async fn destination(&self, device: &WireGuardDevice, destination: &Destination) -> Result<SocketAddr> {
        resolve_destination(device, destination).await
    }

    /// Native packet-preserving UDP path, including zero-length datagrams.
    pub async fn connect_udp(&self, destination: &Destination) -> Result<WireGuardUdpSocket> {
        let device = self.device().await?;
        device.connect_udp(self.destination(&device, destination).await?)
    }
}
#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn start(&self) -> Result<()> { self.device().await.map(|_| ()) }
    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let device = self.device.lock().await.take();
        if let Some(device) = device { device.close().await?; }
        Ok(())
    }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let device = self.device().await?;
        let destination = self.destination(&device, &session.destination).await?;
        match session.destination.network {
            Network::Tcp => Ok(Box::pin(device.connect_tcp(destination).await?)),
            Network::Udp => Ok(Box::pin(device.connect_udp(destination)?)),
        }
    }
    async fn connect_datagram(&self, _session: &SessionContext) -> Result<crate::common::net::datagram::BoxDatagram> {
        Ok(std::sync::Arc::new(super::datagram::WireGuardDatagrams::new(self.device().await?)))
    }
}

pub(super) async fn resolve_destination(device: &WireGuardDevice, destination: &Destination) -> Result<SocketAddr> {
    if destination.port == 0 { return Err(Error::Config("WireGuard destination port must be nonzero".into())); }
    if let Some(address) = destination.to_socket_addr() { return Ok(address); }
    let domain = destination.address.domain_name().ok_or_else(|| Error::Config("invalid WireGuard destination".into()))?;
    super::dns::resolve(device, domain).await?.into_iter()
        .find(|address| device.can_route(*address))
        .map(|address| SocketAddr::new(address, destination.port))
        .ok_or_else(|| Error::Config("no WireGuard allowedIPs route for resolved destination".into()))
}
