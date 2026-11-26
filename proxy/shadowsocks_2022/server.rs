use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Duration;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::{SessionContext, User};
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::replay::ReplayFilter;
use crate::proxy::shadowsocks_2022::stream::accept_tcp;

pub struct Server {
    pub tag: String,
    pub config: Shadowsocks2022Config,
    replay: ReplayFilter,
    user: User,
    datagrams: std::sync::Mutex<Option<(super::cipher::CipherMethod, Vec<u8>, super::udp_session::ServerUdpSessions)>>,
}

impl Server {
    pub fn new(tag: impl Into<String>, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            replay: ReplayFilter::default(),
            user: User::new(uuid::Uuid::nil()),
            datagrams: std::sync::Mutex::new(None),
        }
    }

    pub fn with_user(mut self, user: User) -> Self {
        self.user = user;
        self
    }

    pub fn try_new(tag: impl Into<String>, config: Shadowsocks2022Config) -> Result<Self> {
        config.validate_tcp()?;
        Ok(Self::new(tag, config))
    }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str { &self.tag }
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

impl Server {
    pub fn decode_datagram(&self, wire: &[u8], remote: SocketAddr) -> Result<super::udp_session::InboundDatagram> {
        let method = super::cipher::CipherMethod::parse(&self.config.method)?;
        let key = super::kdf::parse_key(&self.config.key, method.key_length())?;
        let now = super::stream::unix_time()?;
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
