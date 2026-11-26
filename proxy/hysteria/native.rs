//! Adapters for the shared native-listener and whole-datagram contracts.
use super::{HysteriaIncoming, HysteriaListener};
use crate::{common::{errors::{Error, Result}, net::{Destination, Network, datagram::{BoxDatagram, Datagram, DatagramTransport}}, protocol::SessionContext},
    features::inbound::{InboundDispatcher, InboundTask, NativeInboundListener},
    transport::internet::hysteria::udp::{DatagramPacket, UdpSession}};
use async_trait::async_trait;
use bytes::Bytes;
use std::{net::SocketAddr, str::FromStr, sync::{Arc, Mutex}};

pub(super) struct NativeListener { pub listener: HysteriaListener, pub tag: String }
#[async_trait]
impl NativeInboundListener for NativeListener {
    fn local_addr(&self) -> Result<SocketAddr> { self.listener.local_addr() }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let incoming = self.listener.accept().await?;
        let tag = self.tag.clone();
        Ok(Box::pin(async move {
            match incoming {
                HysteriaIncoming::Tcp(pending) => {
                    let mut target = match dispatcher.connect_stream(&pending.session).await {
                        Ok(target) => target,
                        Err(error) => { let _ = pending.reject("destination connection failed").await; return Err(error); }
                    };
                    let mut accepted = pending.accept().await?;
                    tokio::io::copy_bidirectional(&mut accepted.stream, &mut target).await?;
                    Ok(())
                }
                HysteriaIncoming::Udp { session, source, user } => {
                    // SessionContext needs an initial route; retain the first
                    // whole packet for the dispatcher rather than consuming it.
                    let first = session.recv().await?;
                    let destination = udp_destination(&first.address)?;
                    let mut context = SessionContext::new(tag, destination);
                    context.source = Some(source); context.user = user;
                    let peer = Destination::udp(source.ip().into(), source.port());
                    let packets: BoxDatagram = Arc::new(InboundPackets { session, peer, first: tokio::sync::Mutex::new(Some(first)) });
                    dispatcher.dispatch_datagrams(packets, context).await
                }
            }
        }))
    }
}
fn udp_destination(address: &str) -> Result<Destination> {
    let mut destination = Destination::from_str(address)?;
    destination.network = Network::Udp;
    Ok(destination)
}
struct InboundPackets { session: UdpSession, peer: Destination, first: tokio::sync::Mutex<Option<DatagramPacket>> }
#[async_trait]
impl DatagramTransport for InboundPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let first = self.first.lock().await.take();
        let packet = match first { Some(packet) => packet, None => match self.session.recv().await {
            Ok(packet) => packet, Err(Error::Closed) => return Ok(None), Err(error) => return Err(error),
        }};
        Ok(Some(Datagram { payload: Bytes::from(packet.data), source: Some(self.peer.clone()), destination: udp_destination(&packet.address)? }))
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.destination != self.peer { return Err(Error::Protocol("Hysteria reply is addressed to a different client association".into())); }
        let source = packet.source.ok_or_else(|| Error::Protocol("Hysteria reply requires the remote UDP origin".into()))?;
        self.session.send(&source.to_string(), &packet.payload).await
    }
    async fn close(&self) -> Result<()> { self.session.close(); Ok(()) }
}

pub(super) struct OutboundPackets { session: UdpSession, local: Mutex<Option<Destination>> }
impl OutboundPackets {
    pub fn boxed(session: UdpSession, context: &SessionContext) -> BoxDatagram {
        let local = context.source.map(|source| Destination::udp(source.ip().into(), source.port()));
        Arc::new(Self { session, local: Mutex::new(local) })
    }
}
#[async_trait]
impl DatagramTransport for OutboundPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let packet = match self.session.recv().await { Ok(packet) => packet, Err(Error::Closed) => return Ok(None), Err(error) => return Err(error) };
        let local = self.local.lock().expect("Hysteria UDP local source mutex").clone().ok_or_else(|| Error::Protocol("Hysteria UDP response has no original local source".into()))?;
        Ok(Some(Datagram { payload: Bytes::from(packet.data), source: Some(udp_destination(&packet.address)?), destination: local }))
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.destination.network != Network::Udp { return Err(Error::Protocol("Hysteria datagram destination must use UDP".into())); }
        {
            let mut local = self.local.lock().expect("Hysteria UDP local source mutex");
            if let Some(source) = packet.source {
                if local.as_ref().is_some_and(|local| *local != source) {
                    return Err(Error::Protocol("Hysteria UDP association cannot mix original local sources".into()));
                }
                *local = Some(source);
            }
            if local.is_none() { return Err(Error::Protocol("Hysteria UDP send requires the original local source".into())); }
        }
        self.session.send(&packet.destination.to_string(), &packet.payload).await
    }
    async fn close(&self) -> Result<()> { self.session.close(); Ok(()) }
}
