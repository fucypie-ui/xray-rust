//! Native UDP-listener integration for the runtime's inbound dispatcher.
use async_trait::async_trait;
use bytes::Bytes;
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}, time::Duration};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio_util::sync::CancellationToken;
use crate::common::{errors::{Error, Result}, net::{BoxStream, datagram::{Datagram, DatagramTransport}}};
use crate::features::inbound::{InboundDispatcher, InboundHandler, InboundResult, InboundTask, NativeInboundListener};
use super::{WireGuardConfig, WireGuardDevice, WireGuardServer, datagram::udp_destination};

pub struct WireGuardInbound {
    tag: String,
    config: WireGuardConfig,
    devices: Mutex<Vec<WireGuardDevice>>,
}
impl WireGuardInbound {
    pub fn try_new(tag: impl Into<String>, config: WireGuardConfig) -> Result<Self> {
        config.validate()?; Ok(Self { tag: tag.into(), config, devices: Mutex::new(Vec::new()) })
    }
}
#[async_trait]
impl InboundHandler for WireGuardInbound {
    fn tag(&self) -> &str { &self.tag }
    async fn close(&self) -> Result<()> {
        let devices = std::mem::take(&mut *self.devices.lock().unwrap_or_else(|error| error.into_inner()));
        for device in devices { device.close().await?; }
        Ok(())
    }
    async fn handle_connection(&self, _stream: BoxStream, _remote: SocketAddr) -> Result<InboundResult> {
        Err(Error::Unsupported("WireGuard requires its native authenticated UDP listener".into()))
    }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        let server = Arc::new(WireGuardServer::bind(&self.tag, self.config.clone(), address).await?);
        self.devices.lock().unwrap_or_else(|error| error.into_inner()).push(server.device().clone());
        Ok(Some(Box::new(Listener { server, flows: HashMap::new(), cancellation: CancellationToken::new() })))
    }
}

struct Listener {
    server: Arc<WireGuardServer>,
    flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Datagram>>,
    cancellation: CancellationToken,
}
impl Drop for Listener {
    fn drop(&mut self) { self.cancellation.cancel(); self.server.device().stop(); }
}
#[async_trait]
impl NativeInboundListener for Listener {
    fn local_addr(&self) -> Result<SocketAddr> { Ok(self.server.local_addr()) }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        loop {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(Error::Closed),
                accepted = self.server.accept() => {
                    let accepted = accepted?;
                    let cancel = self.cancellation.clone();
                    return Ok(Box::pin(async move {
                        tokio::select! {
                            biased; _ = cancel.cancelled() => Ok(()),
                            result = dispatcher.dispatch_stream(accepted.stream, accepted.session) => result,
                        }
                    }));
                }
                received = self.server.recv_datagram() => {
                    let packet = received?;
                    self.flows.retain(|_, sender| !sender.is_closed());
                    let key = (packet.source, packet.destination);
                    let datagram = Datagram { payload: Bytes::from(packet.data),
                        source: Some(udp_destination(packet.source)), destination: udp_destination(packet.destination) };
                    if let Some(sender) = self.flows.get(&key) {
                        // A slow association cannot stall every peer on the device.
                        let _ = sender.try_send(datagram); continue;
                    }
                    if self.flows.len() >= 256 { continue; }
                    let (sender, receiver) = mpsc::channel(32);
                    sender.try_send(datagram).map_err(|_| Error::Closed)?;
                    self.flows.insert(key, sender);
                    let transport = Arc::new(IncomingFlow { server: self.server.clone(),
                        source: packet.source, destination: packet.destination,
                        receiver: AsyncMutex::new(receiver), cancellation: self.cancellation.child_token() });
                    let cancel = transport.cancellation.clone();
                    return Ok(Box::pin(async move {
                        tokio::select! {
                            biased; _ = cancel.cancelled() => Ok(()),
                            result = dispatcher.dispatch_datagrams(transport, packet.session) => result,
                        }
                    }));
                }
            }
        }
    }
}

struct IncomingFlow {
    server: Arc<WireGuardServer>,
    source: SocketAddr,
    destination: SocketAddr,
    receiver: AsyncMutex<mpsc::Receiver<Datagram>>,
    cancellation: CancellationToken,
}
#[async_trait]
impl DatagramTransport for IncomingFlow {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let mut receiver = self.receiver.lock().await;
        tokio::select! {
            biased; _ = self.cancellation.cancelled() => Ok(None),
            packet = tokio::time::timeout(Duration::from_secs(120), receiver.recv()) => Ok(packet.unwrap_or(None)),
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.cancellation.is_cancelled() { return Err(Error::Closed); }
        if packet.payload.len() > 65507 { return Err(Error::BufferOverflow); }
        if packet.destination.to_socket_addr() != Some(self.source)
            || packet.source.as_ref().and_then(|source| source.to_socket_addr()) != Some(self.destination) {
            return Err(Error::Protocol("WireGuard UDP response tuple does not match association".into()));
        }
        self.server.device().reply_udp(self.destination, self.source, &packet.payload)
    }
    async fn close(&self) -> Result<()> {
        self.cancellation.cancel(); self.receiver.lock().await.close(); Ok(())
    }
}
