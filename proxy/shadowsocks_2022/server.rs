use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::{SessionContext, User};
use crate::features::inbound::{InboundHandler, InboundResult, NativeInboundListener};
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::replay::ReplayFilter;
use crate::proxy::shadowsocks_2022::stream::accept_tcp;

#[derive(Clone)]
pub struct Server {
    pub tag: String,
    pub config: Shadowsocks2022Config,
    replay: Arc<ReplayFilter>,
    user: User,
    datagrams: Arc<std::sync::Mutex<Option<(super::cipher::CipherMethod, Vec<u8>, super::udp_session::ServerUdpSessions)>>>,
    native: Arc<super::native::NativeState>,
}

impl Server {
    pub fn new(tag: impl Into<String>, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            replay: Arc::new(ReplayFilter::default()),
            user: User::new(uuid::Uuid::nil()),
            datagrams: Arc::new(std::sync::Mutex::new(None)),
            native: Arc::new(super::native::NativeState::default()),
        }
    }

    pub fn with_user(mut self, user: User) -> Self {
        self.user = user;
        self
    }

    pub fn try_new(tag: impl Into<String>, config: Shadowsocks2022Config) -> Result<Self> {
        config.validate_inbound()?;
        Ok(Self::new(tag, config))
    }

    pub fn with_network(mut self, network: Option<&str>) -> Result<Self> {
        super::config::Networks::parse(network)?;
        self.config.network = network.map(str::to_owned);
        Ok(self)
    }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str { &self.tag }
    async fn close(&self) -> Result<()> { self.native.close(); Ok(()) }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        self.config.validate_inbound()?;
        super::native::bind(self.clone(), super::config::Networks::parse(self.config.network.as_deref())?, &self.native, address).await
    }
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let (method, key) = self.config.validate_tcp()?;
        let (destination, stream) = tokio::time::timeout(
            Duration::from_secs(10), accept_tcp(stream, method, key, &self.replay),
        ).await.map_err(|_| Error::Timeout)??;
        let mut session = SessionContext::new(&self.tag, destination);
        session.source = Some(remote_addr);
        session.user = Some(self.user.clone());
        Ok(InboundResult { stream: Box::pin(stream), session })
    }
}

impl super::native::PacketServer for Server {
    fn decode(&self, wire: &[u8], remote: SocketAddr) -> Result<super::udp_session::InboundDatagram> { self.decode_datagram(wire, remote) }
    fn reply(&self, token: &super::udp_session::ReplyToken, source: crate::common::net::Destination, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>)> { self.reply_datagram(token, source, payload) }
}

impl Server {
    pub fn decode_datagram(&self, wire: &[u8], remote: SocketAddr) -> Result<super::udp_session::InboundDatagram> {
        self.decode_datagram_at(wire, remote, super::stream::unix_time()?)
    }
    pub(super) fn decode_datagram_at(&self, wire: &[u8], remote: SocketAddr, now: u64) -> Result<super::udp_session::InboundDatagram> {
        let method = super::cipher::CipherMethod::parse(&self.config.method)?;
        let key = super::kdf::parse_key(&self.config.key, method.key_length())?;
        let packet = super::packet::PacketCodec::new(method, vec![key.clone()])?.decode_at(wire, super::protocol::HEADER_TYPE_CLIENT, now)?;
        let mut guard = self.datagrams.lock().map_err(|_| Error::Other("SS2022 UDP lock poisoned".into()))?;
        if guard.as_ref().is_none_or(|(existing, psk, _)| *existing != method || psk != &key) {
            *guard = Some((method, key.clone(), super::udp_session::ServerUdpSessions::new(method)));
        }
        let (_, _, sessions) = guard.as_mut().ok_or_else(|| Error::Other("missing UDP state".into()))?;
        Ok(sessions.accept_at(packet, key, Some(self.user.clone()), remote, now)?)
    }
    pub fn reply_datagram(&self, token: &super::udp_session::ReplyToken, source: crate::common::net::Destination, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>)> {
        let mut guard = self.datagrams.lock().map_err(|_| Error::Other("SS2022 UDP lock poisoned".into()))?;
        let (_, _, sessions) = guard.as_mut().ok_or_else(|| Error::Other("missing UDP state".into()))?;
        Ok(sessions.reply(token, source, payload)?)
    }
}
