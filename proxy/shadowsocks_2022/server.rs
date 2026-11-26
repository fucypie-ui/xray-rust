use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::Duration;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::protocol::SessionContext;
use crate::features::inbound::{InboundHandler, InboundResult};
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::replay::ReplayFilter;
use crate::proxy::shadowsocks_2022::stream::accept_tcp;

pub struct Server {
    pub tag: String,
    pub config: Shadowsocks2022Config,
    replay: ReplayFilter,
}

impl Server {
    pub fn new(tag: impl Into<String>, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            replay: ReplayFilter::default(),
        }
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
        Ok(InboundResult { stream: Box::pin(stream), session })
    }
}
