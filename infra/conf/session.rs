//! Policy metadata and handshake boundaries for stream and native inbounds.
use std::{collections::HashMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};
use async_trait::async_trait;
use tokio::sync::Notify;
use uuid::Uuid;
use crate::common::{errors::{Error, Result}, net::{BoxStream, datagram::{BoxDatagram, Datagram, DatagramTransport}}, protocol::{SessionContext, User}};
use crate::features::{inbound::{InboundDispatcher, InboundHandler, InboundResult, InboundTask, NativeInboundListener}, policy::PolicyManager, stats::{Counter, DefaultStatsManager}};

pub(crate) struct PolicyInbound {
    inner: Arc<dyn InboundHandler>,
    policy: Arc<dyn PolicyManager>,
    metadata: Arc<SessionMetadata>,
    stats: Option<Arc<DefaultStatsManager>>,
}

struct SessionMetadata {
    default_level: Option<u32>,
    users: HashMap<Uuid, User>,
}
impl SessionMetadata {
    fn enrich(&self, session: &mut SessionContext) {
        if let Some(user) = &mut session.user {
            if let Some(configured) = self.users.get(&user.id) { *user = configured.clone(); }
            else if let Some(level) = self.default_level { user.level = level; }
        } else if let Some(level) = self.default_level {
            session.user = Some(User::with_email(Uuid::nil(), "", level));
        }
    }
}

impl PolicyInbound {
    pub fn new(inner: Arc<dyn InboundHandler>, policy: Arc<dyn PolicyManager>, protocol: &str, settings: Option<&serde_json::Value>, stats: Option<Arc<DefaultStatsManager>>) -> Result<Self> {
        let mut users = HashMap::new();
        let default_level = settings.and_then(|settings| settings.get("userLevel"))
            .and_then(serde_json::Value::as_u64).map(|level| level as u32);
        if matches!(protocol, "vless" | "vmess") {
            let clients = settings.and_then(|settings| settings.get("clients").or_else(|| settings.get("users"))).and_then(serde_json::Value::as_array);
            if let Some(clients) = clients {
                for client in clients {
                    let id = client["id"].as_str().unwrap_or_default();
                    let id = Uuid::parse_str(id).map_err(|error| Error::Config(format!("Invalid UUID: {}", error)))?;
                    let level = client["level"].as_u64().unwrap_or(0) as u32;
                    users.insert(id, User::with_email(id, client["email"].as_str().unwrap_or(""), level));
                }
            }
        }
        Ok(Self { inner, policy, metadata: Arc::new(SessionMetadata { default_level, users }), stats })
    }
    fn handshake_timeout(&self) -> Duration {
        self.policy.for_level(self.metadata.default_level.unwrap_or(0)).timeouts.handshake
    }
    fn counters(&self) -> (Option<Arc<Counter>>, Option<Arc<Counter>>) {
        let system = self.policy.for_system().stats;
        let Some(stats) = &self.stats else { return (None, None); };
        let up = system.inbound_uplink.then(|| stats.register_counter(&format!("inbound>>>{}>>>traffic>>>uplink", self.tag())));
        let down = system.inbound_downlink.then(|| stats.register_counter(&format!("inbound>>>{}>>>traffic>>>downlink", self.tag())));
        (up, down)
    }
    fn count_stream(&self, stream: BoxStream) -> BoxStream {
        let (up, down) = self.counters();
        count_stream(stream, up, down)
    }
    fn decorator(&self, inner: Arc<dyn InboundDispatcher>, native: bool) -> Arc<EnrichingDispatcher> {
        let (up, down) = if native { self.counters() } else { (None, None) };
        Arc::new(EnrichingDispatcher { inner, metadata: self.metadata.clone(), dispatched: Arc::new(Notify::new()), up, down })
    }
}

#[async_trait]
impl InboundHandler for PolicyInbound {
    fn tag(&self) -> &str { self.inner.tag() }
    async fn start(&self) -> Result<()> { self.inner.start().await }
    async fn close(&self) -> Result<()> { self.inner.close().await }
    fn receiver_settings(&self) -> Option<Vec<u8>> { self.inner.receiver_settings() }
    fn proxy_settings(&self) -> Option<Vec<u8>> { self.inner.proxy_settings() }
    async fn handle_connection(&self, stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let mut accepted = tokio::time::timeout(self.handshake_timeout(), self.inner.handle_connection(self.count_stream(stream), remote_addr)).await
            .map_err(|_| handshake_error())??;
        self.metadata.enrich(&mut accepted.session);
        Ok(accepted)
    }
    async fn dispatch_connection(&self, stream: BoxStream, remote_addr: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
        let decorated = self.decorator(dispatcher, false);
        let dispatched = decorated.dispatched.clone();
        finish_handshake(self.inner.dispatch_connection(self.count_stream(stream), remote_addr, decorated), dispatched, self.handshake_timeout()).await
    }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        let Some(inner) = self.inner.bind_native(address).await? else { return Ok(None); };
        // Packet/native engines expose payload streams at dispatch rather than
        // a common wire stream; account those payloads at the same boundary.
        let (up, down) = self.counters();
        Ok(Some(Box::new(PolicyListener { inner, metadata: self.metadata.clone(), timeout: self.handshake_timeout(), up, down })))
    }
}

fn handshake_error() -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "inbound handshake timeout"))
}

async fn finish_handshake(future: impl Future<Output = Result<()>>, dispatched: Arc<Notify>, timeout: Duration) -> Result<()> {
    tokio::pin!(future);
    tokio::select! {
        biased;
        result = &mut future => result,
        _ = dispatched.notified() => future.await,
        _ = tokio::time::sleep(timeout) => Err(handshake_error()),
    }
}

struct PolicyListener {
    inner: Box<dyn NativeInboundListener>,
    metadata: Arc<SessionMetadata>,
    timeout: Duration,
    up: Option<Arc<Counter>>,
    down: Option<Arc<Counter>>,
}
#[async_trait]
impl NativeInboundListener for PolicyListener {
    fn local_addr(&self) -> Result<SocketAddr> { self.inner.local_addr() }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let decorated = Arc::new(EnrichingDispatcher {
            inner: dispatcher, metadata: self.metadata.clone(), dispatched: Arc::new(Notify::new()),
            up: self.up.clone(), down: self.down.clone(),
        });
        let dispatched = decorated.dispatched.clone();
        let task = self.inner.accept(decorated).await?;
        let timeout = self.timeout;
        Ok(Box::pin(async move { finish_handshake(task, dispatched, timeout).await }))
    }
}

struct EnrichingDispatcher {
    inner: Arc<dyn InboundDispatcher>,
    metadata: Arc<SessionMetadata>,
    dispatched: Arc<Notify>,
    up: Option<Arc<Counter>>,
    down: Option<Arc<Counter>>,
}
#[async_trait]
impl InboundDispatcher for EnrichingDispatcher {
    async fn dispatch_stream(&self, stream: BoxStream, mut session: SessionContext) -> Result<()> {
        self.metadata.enrich(&mut session);
        self.dispatched.notify_one();
        self.inner.dispatch_stream(count_stream(stream, self.up.clone(), self.down.clone()), session).await
    }
    async fn connect_stream(&self, session: &SessionContext) -> Result<BoxStream> {
        let mut session = session.clone();
        self.metadata.enrich(&mut session);
        self.dispatched.notify_one();
        let stream = self.inner.connect_stream(&session).await?;
        // This stream faces the remote: reads are inbound downlink.
        Ok(count_stream(stream, self.down.clone(), self.up.clone()))
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, mut session: SessionContext) -> Result<()> {
        self.metadata.enrich(&mut session);
        self.dispatched.notify_one();
        let packets = if self.up.is_some() || self.down.is_some() {
            Arc::new(CounterDatagrams { inner: packets, up: self.up.clone(), down: self.down.clone() }) as BoxDatagram
        } else { packets };
        self.inner.dispatch_datagrams(packets, session).await
    }
}

fn count_stream(stream: BoxStream, read: Option<Arc<Counter>>, write: Option<Arc<Counter>>) -> BoxStream {
    if read.is_none() && write.is_none() { stream }
    else { Box::pin(CounterStream { inner: stream, read, write }) }
}
struct CounterStream {
    inner: BoxStream,
    read: Option<Arc<Counter>>,
    write: Option<Arc<Counter>>,
}
impl tokio::io::AsyncRead for CounterStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = self.inner.as_mut().poll_read(cx, buffer);
        if let Some(counter) = &self.read { counter.add((buffer.filled().len() - before) as i64); }
        result
    }
}
impl tokio::io::AsyncWrite for CounterStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buffer: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let result = self.inner.as_mut().poll_write(cx, buffer);
        if let std::task::Poll::Ready(Ok(n)) = result { if let Some(counter) = &self.write { counter.add(n as i64); } }
        result
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { self.inner.as_mut().poll_flush(cx) }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { self.inner.as_mut().poll_shutdown(cx) }
}
struct CounterDatagrams { inner: BoxDatagram, up: Option<Arc<Counter>>, down: Option<Arc<Counter>> }
#[async_trait]
impl DatagramTransport for CounterDatagrams {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let packet = self.inner.recv().await?;
        if let (Some(counter), Some(packet)) = (&self.up, &packet) { counter.add(packet.payload.len() as i64); }
        Ok(packet)
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        let len = packet.payload.len();
        self.inner.send(packet).await?;
        if let Some(counter) = &self.down { counter.add(len as i64); }
        Ok(())
    }
    async fn close(&self) -> Result<()> { self.inner.close().await }
}

#[cfg(test)]
#[path = "session_test.rs"]
mod tests;
