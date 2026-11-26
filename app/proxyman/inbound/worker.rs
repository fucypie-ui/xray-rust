use crate::app::stats::Counter;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::net::datagram::BoxDatagram;
use crate::common::protocol::SessionContext;
use crate::common::session::SniffingRequest;
use crate::features::inbound::{InboundDispatcher, InboundHandler, InboundResult, InboundTask, NativeInboundListener};
use crate::transport::internet::httpupgrade::HttpUpgradeStream;
use crate::transport::internet::reality::RealityServer;
use crate::transport::internet::splithttp::SplitHttpServer;
use crate::transport::internet::{TlsServer, WebSocketStream};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct StreamInboundHandler {
    inner: Arc<dyn InboundHandler>,
    tls_server: Option<Arc<TlsServer>>,
    reality_server: Option<Arc<RealityServer>>,
    is_ws: bool,
    ws_path: Option<String>,
    ws_host: Option<String>,
    httpupgrade: Option<(Option<String>, Option<String>)>,
    splithttp_server: Option<Arc<SplitHttpServer>>,
    sniffing_request: Option<SniffingRequest>,
    pub uplink_counter: Arc<Counter>,
    pub downlink_counter: Arc<Counter>,
}

impl StreamInboundHandler {
    pub fn new(inner: Arc<dyn InboundHandler>, tls_server: Option<Arc<TlsServer>>, is_ws: bool, ws_path: Option<String>, ws_host: Option<String>) -> Self {
        Self {
            inner, tls_server, reality_server: None, is_ws, ws_path, ws_host,
            httpupgrade: None, splithttp_server: None, sniffing_request: None,
            uplink_counter: Arc::new(Counter::new()), downlink_counter: Arc::new(Counter::new()),
        }
    }
    pub fn with_reality(mut self, server: Arc<RealityServer>) -> Self {
        self.reality_server = Some(server);
        self
    }
    pub fn with_httpupgrade(mut self, path: Option<String>, host: Option<String>) -> Self {
        self.httpupgrade = Some((path, host));
        self
    }
    pub fn with_splithttp(mut self, server: Arc<SplitHttpServer>) -> Self {
        self.splithttp_server = Some(server);
        self
    }
    pub fn with_sniffing(mut self, sniffing: SniffingRequest) -> Self {
        self.sniffing_request = Some(sniffing);
        self
    }
    async fn prepare(&self, mut stream: BoxStream, remote_addr: SocketAddr) -> Result<BoxStream> {
        if let Some(ref reality) = self.reality_server {
            stream = reality.accept(stream).await?.ok_or(Error::Closed)?;
        } else if let Some(ref tls) = self.tls_server {
            stream = tls.accept(stream).await?;
        }
        if let Some(ref xhttp) = self.splithttp_server {
            stream = xhttp.accept_stream(stream, remote_addr).await?.ok_or(Error::Closed)?;
        } else if let Some((ref path, ref host)) = self.httpupgrade {
            stream = HttpUpgradeStream::server_handshake(stream, host.as_deref(), path.as_deref()).await?;
        } else if self.is_ws {
            stream = WebSocketStream::server_handshake_with_config(stream, self.ws_path.as_deref(), self.ws_host.as_deref()).await?;
        }
        Ok(stream)
    }
}

#[async_trait]
impl InboundHandler for StreamInboundHandler {
    fn tag(&self) -> &str { self.inner.tag() }
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let stream = self.prepare(stream, remote_addr).await?;
        let mut res = self.inner.handle_connection(stream, remote_addr).await?;
        if res.session.sniffing_request.is_none() { res.session.sniffing_request = self.sniffing_request.clone(); }
        Ok(res)
    }
    async fn start(&self) -> Result<()> { self.inner.start().await }
    async fn close(&self) -> Result<()> { self.inner.close().await }
    async fn dispatch_connection(&self, stream: BoxStream, remote: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
        let stream = self.prepare(stream, remote).await?;
        let dispatcher = Arc::new(SniffingDispatcher { inner: dispatcher, request: self.sniffing_request.clone() });
        self.inner.dispatch_connection(stream, remote, dispatcher).await
    }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        Ok(self.inner.bind_native(address).await?.map(|inner| Box::new(SniffingListener { inner, request: self.sniffing_request.clone() }) as Box<dyn NativeInboundListener>))
    }
}

struct SniffingDispatcher {
    inner: Arc<dyn InboundDispatcher>,
    request: Option<SniffingRequest>,
}
impl SniffingDispatcher {
    fn enrich(&self, mut session: SessionContext) -> SessionContext {
        if session.sniffing_request.is_none() { session.sniffing_request = self.request.clone(); }
        session
    }
}
#[async_trait]
impl InboundDispatcher for SniffingDispatcher {
    async fn dispatch_stream(&self, stream: BoxStream, session: SessionContext) -> Result<()> {
        self.inner.dispatch_stream(stream, self.enrich(session)).await
    }
    async fn connect_stream(&self, session: &SessionContext) -> Result<BoxStream> {
        self.inner.connect_stream(&self.enrich(session.clone())).await
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        self.inner.dispatch_datagrams(packets, self.enrich(session)).await
    }
}
struct SniffingListener {
    inner: Box<dyn NativeInboundListener>,
    request: Option<SniffingRequest>,
}
#[async_trait]
impl NativeInboundListener for SniffingListener {
    fn local_addr(&self) -> Result<SocketAddr> { self.inner.local_addr() }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        self.inner.accept(Arc::new(SniffingDispatcher { inner: dispatcher, request: self.request.clone() })).await
    }
}

/// Stream transport adapter: protocol selection stays in the wrapped handler.
pub struct KcpInboundHandler {
    inner: Arc<dyn InboundHandler>,
    config: crate::transport::internet::kcp::KcpConfig,
}
impl KcpInboundHandler {
    pub fn new(inner: Arc<dyn InboundHandler>, config: crate::transport::internet::kcp::KcpConfig) -> Self { Self { inner, config } }
}
#[async_trait]
impl InboundHandler for KcpInboundHandler {
    fn tag(&self) -> &str { self.inner.tag() }
    async fn start(&self) -> Result<()> { self.inner.start().await }
    async fn close(&self) -> Result<()> { self.inner.close().await }
    fn receiver_settings(&self) -> Option<Vec<u8>> { self.inner.receiver_settings() }
    fn proxy_settings(&self) -> Option<Vec<u8>> { self.inner.proxy_settings() }
    async fn handle_connection(&self, stream: BoxStream, remote: SocketAddr) -> Result<InboundResult> { self.inner.handle_connection(stream, remote).await }
    async fn dispatch_connection(&self, stream: BoxStream, remote: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> { self.inner.dispatch_connection(stream, remote, dispatcher).await }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        let listener = crate::transport::internet::kcp::KcpListener::bind_with_config(address, self.config.clone(), tokio_util::sync::CancellationToken::new()).await?;
        Ok(Some(Box::new(KcpNativeListener { listener, handler: self.inner.clone() })))
    }
}
struct KcpNativeListener {
    listener: crate::transport::internet::kcp::KcpListener,
    handler: Arc<dyn InboundHandler>,
}
#[async_trait]
impl NativeInboundListener for KcpNativeListener {
    fn local_addr(&self) -> Result<SocketAddr> { self.listener.local_addr() }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let (stream, remote) = self.listener.accept_box_stream().await?;
        let handler = self.handler.clone();
        Ok(Box::pin(async move { handler.dispatch_connection(stream, remote, dispatcher).await }))
    }
}

pub struct InboundWorker {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub running: AtomicBool,
    pub uplink_counter: Arc<Counter>,
    pub downlink_counter: Arc<Counter>,
}

impl InboundWorker {
    pub fn new(tag: impl Into<String>, listen: impl Into<String>, port: u16) -> Self {
        Self {
            tag: tag.into(),
            listen: listen.into(),
            port,
            running: AtomicBool::new(false),
            uplink_counter: Arc::new(Counter::new()),
            downlink_counter: Arc::new(Counter::new()),
        }
    }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }
    pub fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        Ok(())
    }
}
