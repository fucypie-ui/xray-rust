use async_trait::async_trait;
use bytes::Bytes;
use std::sync::{Arc, Mutex, Weak};
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::net::datagram::{BoxDatagram, Datagram, DatagramTransport};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::stream::connect_tcp_chain;
use crate::transport::internet::TcpDialer;

pub struct Client {
    pub tag: String,
    pub server_addr: Destination,
    pub config: Shadowsocks2022Config,
    datagrams: Mutex<Vec<Weak<super::udp_session::AssociationSocket>>>,
    closed: tokio_util::sync::CancellationToken,
}

impl Client {
    pub fn new(tag: impl Into<String>, server_addr: Destination, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            server_addr,
            config,
            datagrams: Mutex::new(Vec::new()),
            closed: tokio_util::sync::CancellationToken::new(),
        }
    }

    pub fn try_new(tag: impl Into<String>, server_addr: Destination, config: Shadowsocks2022Config) -> Result<Self> {
        config.validate_outbound_tcp()?;
        if server_addr.network != Network::Tcp {
            return Err(Error::Unsupported("SS2022 server transport must be TCP".into()));
        }
        Ok(Self::new(tag, server_addr, config))
    }
    fn register(&self, association: &super::udp_session::UdpAssociation) -> Result<()> {
        let mut datagrams = self.datagrams.lock().map_err(|_| Error::Other("SS2022 association lock poisoned".into()))?;
        if self.closed.is_cancelled() { association.close(); return Err(Error::Closed); }
        datagrams.retain(|association| association.strong_count() != 0);
        datagrams.push(association.downgrade());
        Ok(())
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn close(&self) -> Result<()> {
        self.closed.cancel();
        let mut datagrams = self.datagrams.lock().map_err(|_| Error::Other("SS2022 association lock poisoned".into()))?;
        for association in datagrams.drain(..).filter_map(|association| association.upgrade()) { association.close(); }
        Ok(())
    }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        let (method, key) = self.config.validate_outbound_tcp()?;
        if session.destination.network != Network::Tcp || self.server_addr.network != Network::Tcp {
            return Err(Error::Unsupported("SS2022 stream connect requires a TCP destination; use connect_datagram for UDP".into()));
        }
        // Validate before dialing, including domain length.
        super::stream::encode_address(&session.destination)?;
        let stream = TcpDialer::dial(&self.server_addr).await?;
        Ok(Box::pin(connect_tcp_chain(stream, method, key, &session.destination).await?))
    }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> {
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        if session.destination.network != Network::Udp { return Err(Error::Unsupported("SS2022 packet connect requires a UDP destination".into())); }
        // The server endpoint's TCP metadata is not a transport restriction:
        // Go selects the remote transport dynamically from the target network.
        let (method, psks) = self.config.validate_outbound_tcp()?;
        let mut address = session.destination.clone(); address.network = Network::Tcp;
        super::stream::encode_address(&address)?;
        let association = Arc::new(super::udp_session::UdpAssociation::connect(&self.server_addr, method, psks).await?);
        let fallback = session.source.map(super::native::udp_destination).unwrap_or(super::native::udp_destination(association.local_addr()?));
        self.register(&association)?;
        Ok(Arc::new(OutboundPackets { association, reply_to: Mutex::new(None), fallback }))
    }
}

impl Client {
    pub async fn connect_datagram(&self) -> Result<super::udp_session::UdpAssociation> {
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        let (method, psks) = self.config.validate_outbound_tcp()?;
        let association = super::udp_session::UdpAssociation::connect(&self.server_addr, method, psks).await?;
        self.register(&association)?;
        Ok(association)
    }
}

struct OutboundPackets {
    association: Arc<super::udp_session::UdpAssociation>,
    reply_to: Mutex<Option<Destination>>,
    fallback: Destination,
}
impl Drop for OutboundPackets { fn drop(&mut self) { self.association.close(); } }
#[async_trait]
impl DatagramTransport for OutboundPackets {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let (source, payload) = match self.association.recv().await {
            Ok(packet) => packet,
            Err(_) if self.association.is_closed() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let destination = self.reply_to.lock().map_err(|_| Error::Other("SS2022 reply address lock poisoned".into()))?.clone().unwrap_or_else(|| self.fallback.clone());
        Ok(Some(Datagram { payload: Bytes::from(payload), source: Some(source), destination }))
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if self.association.is_closed() { return Err(Error::Closed); }
        if packet.payload.len() > super::packet::MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        if packet.destination.network != Network::Udp { return Err(Error::Protocol("SS2022 datagram destination must use UDP".into())); }
        if packet.source.as_ref().is_some_and(|source| source.network != Network::Udp) { return Err(Error::Protocol("SS2022 datagram source must use UDP".into())); }
        let wire = self.association.encode(packet.destination, &packet.payload).map_err(|error| if self.association.is_closed() { Error::Closed } else { error.into() })?;
        {
            let mut reply_to = self.reply_to.lock().map_err(|_| Error::Other("SS2022 reply address lock poisoned".into()))?;
            // One SS2022 client session represents one original local source.
            // Reject mixed sources rather than redirecting prior replies.
            let source = packet.source.unwrap_or_else(|| reply_to.clone().unwrap_or_else(|| self.fallback.clone()));
            if reply_to.as_ref().is_some_and(|existing| *existing != source) { return Err(Error::Protocol("SS2022 UDP association cannot mix original local sources".into())); }
            *reply_to = Some(source);
        }
        self.association.send_wire(&wire).await.map_err(|error| if self.association.is_closed() { Error::Closed } else { error.into() })
    }
    async fn close(&self) -> Result<()> { self.association.close(); Ok(()) }
}
