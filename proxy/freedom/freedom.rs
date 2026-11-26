use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::net::datagram::{BoxDatagram, Datagram, DatagramTransport, MAX_DATAGRAM_SIZE};
use crate::common::net::Network;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::transport::internet::TcpDialer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    UseIP,
    UseIPv4,
    UseIPv6,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "useip" | "use_ip" => DomainStrategy::UseIP,
            "useipv4" | "use_ipv4" | "useip4" => DomainStrategy::UseIPv4,
            "useipv6" | "use_ipv6" | "useip6" => DomainStrategy::UseIPv6,
            _ => DomainStrategy::AsIs,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FreedomConfig {
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub timeout: u32,
    pub destination_override: Option<Destination>,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default)]
    pub fragment: Option<crate::transport::internet::finalmask::fragment::Config>,
}

pub struct Handler {
    tag: String,
    pub config: FreedomConfig,
}

impl Handler {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            config: FreedomConfig::default(),
        }
    }
    pub fn with_config(tag: impl Into<String>, config: FreedomConfig) -> Self {
        Self {
            tag: tag.into(),
            config,
        }
    }
    pub fn with_strategy(mut self, strategy: DomainStrategy) -> Self {
        self.config.domain_strategy = strategy;
        self
    }
    pub fn with_destination_override(mut self, dest: Destination) -> Self {
        self.config.destination_override = Some(dest);
        self
    }
    pub fn with_fragment(mut self, fragment: crate::transport::internet::finalmask::fragment::Config) -> Self {
        self.config.fragment = Some(fragment);
        self
    }
    async fn resolve_destination(&self, dest: &Destination) -> Result<Destination> {
        let Address::Domain(ref domain) = dest.address else { return Ok(dest.clone()) };
        if self.config.domain_strategy == DomainStrategy::AsIs { return Ok(dest.clone()); }
        if let Ok(addrs) = lookup_host(format!("{}:{}", domain, dest.port)).await
            && let Some(sa) = addrs.into_iter().find(|sa| match self.config.domain_strategy {
                DomainStrategy::UseIPv4 => sa.is_ipv4(),
                DomainStrategy::UseIPv6 => sa.is_ipv6(),
                _ => true,
            })
        { return Ok(Destination::new(Address::from(sa.ip()), dest.port)); }
        Ok(dest.clone())
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn tag(&self) -> &str { &self.tag }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> {
        let target = self.config.destination_override.as_ref().unwrap_or(&session.destination);
        let address = resolve_udp(target, self.config.domain_strategy).await?;
        let v4 = UdpSocket::bind("0.0.0.0:0").await;
        let v6 = UdpSocket::bind("[::]:0").await;
        let (v4, v6) = if address.is_ipv4() { (Some(Arc::new(v4?)), v6.ok().map(Arc::new)) }
            else { (v4.ok().map(Arc::new), Some(Arc::new(v6?))) };
        let (closed, _) = watch::channel(false);
        Ok(Arc::new(DirectDatagram {
            v4, v6, closed, routes: Mutex::new(HashMap::new()),
            strategy: self.config.domain_strategy, target_override: self.config.destination_override.clone(),
            source: session.source.map(|source| Destination::udp(source.ip().into(), source.port())),
        }))
    }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let dest = self.config.destination_override.as_ref().unwrap_or(&session.destination);
        let dial_dest = self.resolve_destination(dest).await?;
        if dial_dest.network == crate::common::net::Network::Udp {
            crate::transport::internet::dialer::dial_system(&dial_dest, None).await
        } else {
            let s = TcpDialer::dial(&dial_dest).await?;
            match &self.config.fragment {
                Some(f_cfg) => Ok(Box::pin(crate::transport::internet::finalmask::fragment::FragmentConn::new_client(f_cfg.clone(), s))),
                None => Ok(s),
            }
        }
    }
}

pub use Handler as Client;
pub use Handler as FreedomClient;

async fn resolve_udp(target: &Destination, strategy: DomainStrategy) -> Result<SocketAddr> {
    if target.network != Network::Udp { return Err(Error::Protocol("freedom packet destination must be UDP".into())); }
    if let Some(address) = target.to_socket_addr() { return Ok(address); }
    let Address::Domain(domain) = &target.address else { return Err(Error::AddressParse(target.to_string())); };
    lookup_host((domain.as_str(), target.port)).await?
        .find(|address| match strategy { DomainStrategy::UseIPv4 => address.is_ipv4(), DomainStrategy::UseIPv6 => address.is_ipv6(), _ => true })
        .ok_or_else(|| Error::NotFound(format!("no UDP address matching domain strategy for {target}")))
}

struct DirectDatagram {
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    routes: Mutex<HashMap<SocketAddr, Destination>>,
    closed: watch::Sender<bool>,
    strategy: DomainStrategy,
    target_override: Option<Destination>,
    source: Option<Destination>,
}
async fn receive_udp(socket: &Option<Arc<UdpSocket>>, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match socket { Some(socket) => socket.recv_from(buffer).await, None => std::future::pending().await }
}
#[async_trait]
impl DatagramTransport for DirectDatagram {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Ok(None); }
        let mut v4 = vec![0; MAX_DATAGRAM_SIZE + 1];
        let mut v6 = vec![0; MAX_DATAGRAM_SIZE + 1];
        loop {
            let (size, remote, buffer) = tokio::select! {
                _ = closed.changed() => return Ok(None),
                packet = receive_udp(&self.v4, &mut v4) => { let (size, remote) = packet?; (size, remote, &v4) }
                packet = receive_udp(&self.v6, &mut v6) => { let (size, remote) = packet?; (size, remote, &v6) }
            };
            if size > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
            let local = self.routes.lock().await.get(&remote).cloned();
            // Ignore unsolicited datagrams on the association's ephemeral socket.
            if let Some(destination) = local {
                return Ok(Some(Datagram { payload: buffer[..size].to_vec().into(), source: Some(Destination::udp(remote.ip().into(), remote.port())), destination }));
            }
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Err(Error::Closed); }
        let operation = async {
            let target = self.target_override.as_ref().unwrap_or(&packet.destination);
            let address = resolve_udp(target, self.strategy).await?;
            let socket = if address.is_ipv4() { self.v4.as_ref() } else { self.v6.as_ref() }
                .ok_or_else(|| Error::Unsupported("UDP address family is unavailable on this host".into()))?;
            {
                let mut routes = self.routes.lock().await;
                if !routes.contains_key(&address) && routes.len() >= 64 { return Err(Error::BufferOverflow); }
                routes.insert(address, packet.source.or_else(|| self.source.clone()).unwrap_or_else(|| packet.destination.clone()));
            }
            let size = socket.send_to(&packet.payload, address).await?;
            if size != packet.payload.len() { return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::WriteZero, "partial UDP send"))); }
            Ok(())
        };
        tokio::select! { _ = closed.changed() => Err(Error::Closed), result = operation => result }
    }
    async fn close(&self) -> Result<()> { self.closed.send_replace(true); Ok(()) }
}
