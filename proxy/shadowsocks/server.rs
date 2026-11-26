use async_trait::async_trait;
use std::net::SocketAddr;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Network};
use crate::common::protocol::SessionContext;
use crate::features::inbound::{InboundHandler, InboundResult};
use shadowsocks::{config::ServerType, context::SharedContext, relay::tcprelay::ProxyServerStream};
use super::runtime;

#[derive(Clone)]
pub struct Server {
    tag: String,
    method: String,
    password: String,
    context: SharedContext,
    user: Option<crate::common::protocol::User>,
    tcp: bool,
    udp: bool,
    native: std::sync::Arc<super::native::State>,
}

impl Server {
    pub fn new(tag: impl Into<String>, method: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            method: method.into(),
            password: password.into(),
            context: runtime::context(ServerType::Server),
            user: None,
            tcp: true,
            udp: false,
            native: std::sync::Arc::new(super::native::State::default()),
        }
    }
    pub fn try_new(tag: impl Into<String>, method: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let server = Self::new(tag, method, password);
        runtime::account(&server.method, &server.password)?;
        Ok(server)
    }
    pub fn with_user(mut self, user: crate::common::protocol::User) -> Self {
        self.user = Some(user);
        self
    }
    pub fn with_networks(mut self, tcp: bool, udp: bool) -> Result<Self> {
        if !tcp && !udp { return Err(Error::Config("Shadowsocks must enable TCP or UDP".into())); }
        self.tcp = tcp;
        self.udp = udp;
        Ok(self)
    }
    pub fn method(&self) -> &str { &self.method }
    pub fn password(&self) -> &str { &self.password }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str { &self.tag }
    async fn start(&self) -> Result<()> {
        if self.native.is_closed() { return Err(Error::Closed); }
        runtime::account(&self.method, &self.password).map(|_| ())
    }
    async fn close(&self) -> Result<()> { self.native.close(); Ok(()) }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn crate::features::inbound::NativeInboundListener>>> {
        if self.native.is_closed() { return Err(Error::Closed); }
        let codec = super::datagram::Codec::new(&self.method, &self.password, self.context.clone())?;
        if !self.udp { return Ok(None); }
        super::native::bind(self.clone(), self.tcp, codec, &self.native, address, self.user.clone()).await.map(Some)
    }
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        if !self.tcp { return Err(Error::Unsupported("Shadowsocks TCP is disabled".into())); }
        if self.native.is_closed() { return Err(Error::Closed); }
        let config = runtime::account(&self.method, &self.password)?;
        let mut stream = ProxyServerStream::from_stream(self.context.clone(), stream, config.method(), config.key());
        let dest = runtime::destination(stream.handshake().await?)?;
        let mut session = SessionContext::new(&self.tag, dest);
        session.source = Some(remote_addr);
        session.destination.network = Network::Tcp;
        session.user = self.user.clone();
        Ok(InboundResult { stream: Box::pin(stream), session })
    }
}
