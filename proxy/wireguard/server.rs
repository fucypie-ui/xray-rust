use std::net::SocketAddr;
use tokio::sync::Mutex;
use super::{WireGuardConfig, device::WireGuardDevice, stack::{IncomingUdp, WireGuardTcpStream}};
use crate::common::{errors::{Error, Result}, net::{Destination, Network}, protocol::SessionContext};
use crate::features::inbound::InboundResult;

/// An authenticated UDP listener with a userspace TCP acceptor and UDP packet
/// receiver. The runtime owns dispatching these flows to its routing manager.
pub struct WireGuardServer {
    tag: String,
    device: WireGuardDevice,
    tcp: Mutex<tokio::sync::mpsc::Receiver<(WireGuardTcpStream, SocketAddr, SocketAddr)>>,
    udp: Mutex<tokio::sync::mpsc::Receiver<IncomingUdp>>,
}
impl WireGuardServer {
    pub async fn bind(tag: impl Into<String>, config: WireGuardConfig, listen: SocketAddr) -> Result<Self> {
        let (device, receivers) = WireGuardDevice::open(config, listen, true).await?;
        Ok(Self { tag: tag.into(), device, tcp: Mutex::new(receivers.tcp), udp: Mutex::new(receivers.udp) })
    }
    pub fn local_addr(&self) -> SocketAddr { self.device.local_addr() }
    pub fn device(&self) -> &WireGuardDevice { &self.device }
    pub async fn close(&self) -> Result<()> { self.device.close().await }
    pub async fn accept(&self) -> Result<InboundResult> {
        let (stream, source, destination) = self.tcp.lock().await.recv().await.ok_or(Error::Closed)?;
        let mut session = SessionContext::new(&self.tag, Destination::from(destination));
        session.source = Some(source);
        Ok(InboundResult { stream: Box::pin(stream), session })
    }
    pub async fn recv_datagram(&self) -> Result<WireGuardInboundDatagram> {
        let packet = self.udp.lock().await.recv().await.ok_or(Error::Closed)?;
        let mut session = SessionContext::new(&self.tag, Destination::from(packet.destination));
        session.destination.network = Network::Udp; session.source = Some(packet.source);
        Ok(WireGuardInboundDatagram { data: packet.data, session, source: packet.source,
            destination: packet.destination, device: self.device.clone() })
    }
}

pub struct WireGuardInboundDatagram {
    pub data: Vec<u8>,
    pub session: SessionContext,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    device: WireGuardDevice,
}
impl WireGuardInboundDatagram {
    /// Reply preserves the original IP/port tuple, including transparent targets.
    pub fn reply(&self, payload: &[u8]) -> Result<()> { self.device.reply_udp(self.destination, self.source, payload) }
}
