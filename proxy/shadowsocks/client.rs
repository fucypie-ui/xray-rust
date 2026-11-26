use async_trait::async_trait;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::transport::internet::TcpDialer;
use crate::transport::internet::dialer::Dialer as StreamDialer;
use shadowsocks::{config::ServerType, context::SharedContext, relay::tcprelay::ProxyClientStream};
use std::{pin::Pin, sync::Arc};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use super::runtime;

pub struct Client {
    tag: String,
    server_addr: Destination,
    method: String,
    password: String,
    context: SharedContext,
    dialer: Option<Arc<dyn StreamDialer>>,
    datagrams: super::datagram::OutboundState,
}

impl Client {
    pub fn new(
        tag: impl Into<String>,
        server_addr: Destination,
        method: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_addr,
            method: method.into(),
            password: password.into(),
            context: runtime::context(ServerType::Local),
            dialer: None,
            datagrams: super::datagram::OutboundState::default(),
        }
    }
    pub fn try_new(
        tag: impl Into<String>, server_addr: Destination,
        method: impl Into<String>, password: impl Into<String>,
    ) -> Result<Self> {
        let client = Self::new(tag, server_addr, method, password);
        runtime::account(&client.method, &client.password)?;
        if client.server_addr.port == 0 {
            return Err(Error::Config("Shadowsocks server port must be nonzero".into()));
        }
        runtime::address(&client.server_addr)?;
        Ok(client)
    }
    pub fn method(&self) -> &str { &self.method }
    pub fn password(&self) -> &str { &self.password }
    /// Inject the server stream transport before the classic AEAD handshake.
    /// Native UDP associations do not use this stream dialer.
    pub fn with_dialer(mut self, dialer: Arc<dyn StreamDialer>) -> Self {
        self.dialer = Some(dialer);
        self
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn start(&self) -> Result<()> {
        if self.datagrams.is_closed() { return Err(Error::Closed); }
        runtime::account(&self.method, &self.password)?;
        runtime::address(&self.server_addr)?;
        if self.server_addr.port == 0 { return Err(Error::Config("Shadowsocks server port must be nonzero".into())); }
        Ok(())
    }
    async fn close(&self) -> Result<()> { self.datagrams.close(); Ok(()) }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        if self.datagrams.is_closed() { return Err(Error::Closed); }
        if session.destination.network != Network::Tcp {
            return Err(Error::Unsupported("classic Shadowsocks stream connect requires TCP; use connect_datagram for UDP".into()));
        }
        let config = runtime::account(&self.method, &self.password)?;
        let target = runtime::address(&session.destination)?;
        if self.server_addr.port == 0 {
            return Err(Error::Config("Shadowsocks server port must be nonzero".into()));
        }
        runtime::address(&self.server_addr)?;
        tokio::select! {
            biased;
            _ = self.datagrams.cancelled() => Err(Error::Closed),
            result = async {
                let stream = match &self.dialer {
                    Some(dialer) => dialer.dial(&self.server_addr).await?,
                    None => TcpDialer::dial(&self.server_addr).await?,
                };
                let mut stream = ProxyClientStream::from_stream(self.context.clone(), stream, &config, target);
                // Upstream explicitly supports an empty poll_write to send the target.
                // write_all(&[]) would skip poll_write, and flush alone sends no header.
                // Eager handshake also supports targets that speak before their client.
                futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, &[])).await?;
                stream.flush().await?;
                Ok(Box::pin(stream) as BoxStream)
            } => result,
        }
    }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<crate::common::net::datagram::BoxDatagram> {
        if self.datagrams.is_closed() { return Err(Error::Closed); }
        tokio::select! {
            biased;
            _ = self.datagrams.cancelled() => Err(Error::Closed),
            result = super::datagram::connect(&self.server_addr, &self.method, &self.password, self.context.clone(), session, &self.datagrams) => result,
        }
    }
}
