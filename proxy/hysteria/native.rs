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
        let source = packet.source.as_ref().unwrap_or(&packet.destination);
        self.session.send(&source.to_string(), &packet.payload).await
    }
    async fn close(&self) -> Result<()> { self.session.close(); Ok(()) }
}

/// An explicit packet source takes precedence over the session's socket source.
/// The original destination is used only when neither local source is known.
struct ReplyAddress {
    packet_source: Option<Destination>,
    session_source: Option<Destination>,
    fallback: Destination,
}
impl ReplyAddress {
    fn new(context: &SessionContext) -> Self {
        let session_source = context.source.map(|source| Destination::udp(source.ip().into(), source.port()));
        let mut fallback = context.destination.clone();
        fallback.network = Network::Udp;
        Self { packet_source: None, session_source, fallback }
    }
    fn remember(&mut self, source: Option<Destination>) -> Result<()> {
        if let Some(source) = source {
            if self.packet_source.as_ref().is_some_and(|local| *local != source) {
                return Err(Error::Protocol("Hysteria UDP association cannot mix original local sources".into()));
            }
            self.packet_source = Some(source);
        }
        Ok(())
    }
    fn destination(&self) -> Destination {
        self.packet_source.as_ref().or(self.session_source.as_ref()).unwrap_or(&self.fallback).clone()
    }
}

pub(super) struct OutboundPackets { session: UdpSession, reply_address: Mutex<ReplyAddress> }
impl OutboundPackets {
    pub fn boxed(session: UdpSession, context: &SessionContext) -> BoxDatagram {
        Arc::new(Self { session, reply_address: Mutex::new(ReplyAddress::new(context)) })
    }
}
#[async_trait]
impl DatagramTransport for OutboundPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let packet = match self.session.recv().await { Ok(packet) => packet, Err(Error::Closed) => return Ok(None), Err(error) => return Err(error) };
        let local = self.reply_address.lock().expect("Hysteria UDP reply address mutex").destination();
        Ok(Some(Datagram { payload: Bytes::from(packet.data), source: Some(udp_destination(&packet.address)?), destination: local }))
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.destination.network != Network::Udp { return Err(Error::Protocol("Hysteria datagram destination must use UDP".into())); }
        self.reply_address.lock().expect("Hysteria UDP reply address mutex").remember(packet.source)?;
        self.session.send(&packet.destination.to_string(), &packet.payload).await
    }
    async fn close(&self) -> Result<()> { self.session.close(); Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn destination(address: &str) -> Destination { udp_destination(address).unwrap() }
    #[test]
    fn reply_uses_packet_source_then_session_source_then_original_destination() {
        let mut context = SessionContext::new("test", destination("dns.example:53"));
        let unknown = ReplyAddress::new(&context);
        assert_eq!(unknown.destination(), destination("dns.example:53"));
        context.source = Some("127.0.0.1:53000".parse().unwrap());
        let mut addresses = ReplyAddress::new(&context);
        assert_eq!(addresses.destination(), destination("127.0.0.1:53000"));
        // A proxy's logical packet source can differ from its socket source.
        addresses.remember(Some(destination("192.0.2.10:42000"))).unwrap();
        assert_eq!(addresses.destination(), destination("192.0.2.10:42000"));
        addresses.remember(None).unwrap();
        assert_eq!(addresses.destination(), destination("192.0.2.10:42000"));
        assert!(addresses.remember(Some(destination("192.0.2.11:42000"))).is_err());
        assert_eq!(addresses.destination(), destination("192.0.2.10:42000"));
    }
}
