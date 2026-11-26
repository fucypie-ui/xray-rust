use crate::common::errors::Result;
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::proxy::socks::protocol::SocksProtocol;
use crate::transport::internet::dialer::Dialer;
use async_trait::async_trait;
use std::sync::Arc;

pub struct Client {
    tag: String,
    server: Destination,
    dialer: Option<Arc<dyn Dialer>>,
    account: Option<(String, String)>,
}

impl Client {
    pub fn new(tag: impl Into<String>, server: Destination) -> Self {
        Self {
            tag: tag.into(),
            server,
            dialer: None,
            account: None,
        }
    }

    /// Require username/password authentication without falling back to no-auth.
    pub fn with_auth(
        tag: impl Into<String>,
        server: Destination,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server,
            account: Some((username.into(), password.into())),
            dialer: None,
        }
    }

    pub fn with_dialer(mut self, dialer: Arc<dyn Dialer>) -> Self {
        self.dialer = Some(dialer);
        self
    }
}

#[async_trait]
impl OutboundHandler for Client {
    fn tag(&self) -> &str { &self.tag }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut stream = match &self.dialer {
            Some(dialer) => dialer.dial(&self.server).await?,
            None => crate::transport::internet::TcpDialer::dial(&self.server).await?,
        };
        let account = self.account.as_ref().map(|(user, pass)| (user.as_str(), pass.as_str()));
        SocksProtocol::client_handshake_with_auth(&mut stream, &session.destination, account).await?;
        Ok(stream)
    }
}
