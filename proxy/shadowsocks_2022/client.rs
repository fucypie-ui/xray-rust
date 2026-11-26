use async_trait::async_trait;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::proxy::shadowsocks_2022::config::Shadowsocks2022Config;
use crate::proxy::shadowsocks_2022::stream::connect_tcp;
use crate::transport::internet::TcpDialer;

pub struct Client {
    pub tag: String,
    pub server_addr: Destination,
    pub config: Shadowsocks2022Config,
}

impl Client {
    pub fn new(tag: impl Into<String>, server_addr: Destination, config: Shadowsocks2022Config) -> Self {
        Self {
            tag: tag.into(),
            server_addr,
            config,
        }
    }

    pub fn try_new(tag: impl Into<String>, server_addr: Destination, config: Shadowsocks2022Config) -> Result<Self> {
        config.validate_tcp()?;
        if server_addr.network != Network::Tcp {
            return Err(Error::Unsupported("SS2022 server transport must be TCP".into()));
        }
        Ok(Self::new(tag, server_addr, config))
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let (method, key) = self.config.validate_tcp()?;
        if session.destination.network != Network::Tcp || self.server_addr.network != Network::Tcp {
            return Err(Error::Unsupported("SS2022 UDP is not implemented".into()));
        }
        // Validate before dialing, including domain length.
        super::stream::encode_address(&session.destination)?;
        let stream = TcpDialer::dial(&self.server_addr).await?;
        Ok(Box::pin(connect_tcp(stream, method, key, &session.destination).await?))
    }
}
