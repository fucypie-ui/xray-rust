use crate::common::errors::Result;
use crate::common::net::BoxStream;
use crate::common::net::datagram::BoxDatagram;
use crate::common::protocol::SessionContext;
use crate::features::feature::TYPE_INBOUND_MANAGER;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{future::Future, pin::Pin};

#[async_trait]
pub trait InboundDispatcher: Send + Sync {
    async fn dispatch_stream(&self, stream: BoxStream, session: SessionContext) -> Result<()>;
    /// Establish the route before a protocol acknowledges a pending request.
    async fn connect_stream(&self, _session: &SessionContext) -> Result<BoxStream> {
        Err(crate::common::errors::Error::Unsupported("pre-accept stream dispatch".into()))
    }
    async fn dispatch_datagrams(&self, _packets: BoxDatagram, _session: SessionContext) -> Result<()> {
        Err(crate::common::errors::Error::Unsupported("packet dispatch".into()))
    }
}

pub type InboundTask = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

/// Binding must finish before this listener is returned. Dropping a listener or
/// a returned task must release its sockets and connection children. Accept is
/// cancellation safe: proxyman also polls completion of previous children.
#[async_trait]
pub trait NativeInboundListener: Send {
    fn local_addr(&self) -> Result<SocketAddr>;
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask>;
}

pub struct InboundResult {
    pub stream: BoxStream,
    pub session: SessionContext,
}

#[async_trait]
pub trait InboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn start(&self) -> Result<()> { Ok(()) }
    async fn close(&self) -> Result<()> { Ok(()) }
    fn receiver_settings(&self) -> Option<Vec<u8>> { None }
    fn proxy_settings(&self) -> Option<Vec<u8>> { None }
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult>;
    async fn dispatch_connection(&self, stream: BoxStream, remote_addr: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
        let result = self.handle_connection(stream, remote_addr).await?;
        dispatcher.dispatch_stream(result.stream, result.session).await
    }
    /// `None` requests the conventional TCP accept loop. An error is a startup
    /// failure and must not fall back to a different transport.
    async fn bind_native(&self, _address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> { Ok(None) }
}

#[async_trait]
pub trait InboundManager: Send + Sync {
    async fn get_handler(&self, tag: &str) -> Result<Arc<dyn InboundHandler>>;
    async fn add_handler(&self, handler: Arc<dyn InboundHandler>) -> Result<()>;
    async fn remove_handler(&self, tag: &str) -> Result<()>;
    async fn list_handlers(&self) -> Vec<Arc<dyn InboundHandler>>;
}

pub fn manager_type() -> &'static str { TYPE_INBOUND_MANAGER }
