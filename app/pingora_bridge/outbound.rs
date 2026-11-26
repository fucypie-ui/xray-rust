use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::sync::watch;
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use crate::common::net::datagram::BoxDatagram;
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use super::pool::{PingoraStreamPool, PingoraUpstreamBalancer, pool_key};

pub struct PingoraPooledOutbound {
    tag: String,
    pool: Arc<PingoraStreamPool>,
    upstreams: Vec<Arc<dyn OutboundHandler>>,
    balancer: Option<Arc<PingoraUpstreamBalancer>>,
    closed: watch::Sender<bool>,
}

impl PingoraPooledOutbound {
    pub fn new(
        tag: impl Into<String>,
        upstreams: Vec<Arc<dyn OutboundHandler>>,
        balancer: Option<Arc<PingoraUpstreamBalancer>>,
        pool_capacity: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            tag: tag.into(),
            pool: Arc::new(PingoraStreamPool::new(pool_capacity, idle_timeout)),
            upstreams,
            balancer,
            closed: watch::channel(false).0,
        }
    }
    /// Close blocks wrapper reuse but cannot drain this shared pool: its public
    /// API has no drain operation. Idle entries retain their existing timeout /
    /// eviction behavior, and external pool holders can still access them.
    /// Streams already returned to callers remain owned by those callers.
    pub fn pool(&self) -> &Arc<PingoraStreamPool> { &self.pool }
    fn is_closed(&self) -> bool { *self.closed.borrow() }
    async fn cancelled(&self) {
        let mut closed = self.closed.subscribe();
        let _ = closed.wait_for(|closed| *closed).await;
    }
    async fn while_open<T: Send>(&self, future: impl Future<Output = Result<T>> + Send) -> Result<T> {
        if self.is_closed() { return Err(Error::Closed); }
        tokio::select! {
            biased;
            _ = self.cancelled() => Err(Error::Closed),
            result = future => {
                // A child may finish in the same poll that closes the wrapper.
                if self.is_closed() { Err(Error::Closed) } else { result }
            }
        }
    }
    fn pick_upstream_index(&self, key: &[u8]) -> usize {
        if self.upstreams.len() <= 1 { return 0; }
        if let Some(lb) = &self.balancer && let Some(idx) = lb.select_index_for_key(key) && idx < self.upstreams.len()
        { return idx; }
        0
    }
}

#[async_trait]
impl OutboundHandler for PingoraPooledOutbound {
    fn tag(&self) -> &str { &self.tag }
    async fn start(&self) -> Result<()> {
        self.while_open(async {
            if self.upstreams.is_empty() {
                return Err(Error::NotFound(format!("PingoraPooledOutbound '{}' has no upstreams", self.tag)));
            }
            let results = futures::future::join_all(self.upstreams.iter().map(|handler| handler.start())).await;
            for result in results { result?; }
            Ok(())
        }).await
    }
    async fn close(&self) -> Result<()> {
        // Signal before awaiting children, including when their close fails or
        // stalls. Repeated close calls still attempt every child's cleanup.
        self.closed.send_replace(true);
        let results = futures::future::join_all(self.upstreams.iter().map(|handler| handler.close())).await;
        for result in results { result?; }
        Ok(())
    }
    async fn connect_datagram(&self, session: &SessionContext) -> Result<BoxDatagram> {
        self.while_open(async {
            if self.upstreams.is_empty() {
                return Err(Error::NotFound(format!("PingoraPooledOutbound '{}' has no upstreams", self.tag)));
            }
            let target_key = session.sniffed_domain.clone().unwrap_or_else(|| session.destination.address.to_string());
            let start = self.pick_upstream_index(target_key.as_bytes());
            let mut last_err = None;
            for offset in 0..self.upstreams.len() {
                if self.is_closed() { return Err(Error::Closed); }
                match self.upstreams[(start + offset) % self.upstreams.len()].connect_datagram(session).await {
                    Ok(packets) => return Ok(packets),
                    Err(error) => last_err = Some(error),
                }
            }
            Err(last_err.unwrap_or(Error::Closed))
        }).await
    }
    async fn connect(&self, session: &SessionContext) -> Result<BoxStream> {
        self.while_open(async {
            let key = pool_key(&format!("{}:{}", self.tag, session.destination));
            if let Some(reused) = self.pool.get(key) {
                #[cfg(debug_assertions)]
                crate::debug_panel::metrics().record_pool_reuse(&session.destination.address.to_string(), &self.tag);
                return Ok(reused);
            }
            if self.upstreams.is_empty() {
                return Err(Error::NotFound(format!("PingoraPooledOutbound '{}' has no upstreams", self.tag)));
            }
            let target_key = session.sniffed_domain.clone().unwrap_or_else(|| session.destination.address.to_string());
            let start = self.pick_upstream_index(target_key.as_bytes());
            let mut last_err = None;
            for offset in 0..self.upstreams.len() {
                if self.is_closed() { return Err(Error::Closed); }
                match self.upstreams[(start + offset) % self.upstreams.len()].connect(session).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or(Error::Closed))
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::net::Destination;
    use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
    use std::task::Poll;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const LIMIT: Duration = Duration::from_secs(5);

    struct PendingCall(Arc<AtomicUsize>);
    impl PendingCall {
        fn new(active: &Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self(active.clone())
        }
    }
    impl Drop for PendingCall {
        fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
    }

    struct ChildSpy {
        tag: &'static str,
        starts: AtomicUsize,
        closes: AtomicUsize,
        tcp: AtomicUsize,
        udp: AtomicUsize,
        active: Arc<AtomicUsize>,
        start_error: bool,
        close_error: bool,
        pending_connects: bool,
        close_gate: Option<watch::Sender<bool>>,
        stream: Mutex<Option<BoxStream>>,
    }
    impl ChildSpy {
        fn new(tag: &'static str) -> Self {
            Self {
                tag, starts: AtomicUsize::new(0), closes: AtomicUsize::new(0),
                tcp: AtomicUsize::new(0), udp: AtomicUsize::new(0),
                active: Arc::new(AtomicUsize::new(0)), start_error: false, close_error: false,
                pending_connects: false, close_gate: None, stream: Mutex::new(None),
            }
        }
    }
    #[async_trait]
    impl OutboundHandler for ChildSpy {
        fn tag(&self) -> &str { self.tag }
        async fn start(&self) -> Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if self.start_error { Err(Error::Config(format!("start {}", self.tag))) } else { Ok(()) }
        }
        async fn close(&self) -> Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.close_gate {
                let mut ready = gate.subscribe();
                let _ = ready.wait_for(|ready| *ready).await;
            }
            if self.close_error { Err(Error::Other(format!("close {}", self.tag))) } else { Ok(()) }
        }
        async fn connect(&self, _: &SessionContext) -> Result<BoxStream> {
            self.tcp.fetch_add(1, Ordering::SeqCst);
            let _pending = PendingCall::new(&self.active);
            if self.pending_connects { return std::future::pending().await; }
            self.stream.lock().unwrap().take().ok_or_else(|| Error::Unsupported("spy TCP".into()))
        }
        async fn connect_datagram(&self, _: &SessionContext) -> Result<BoxDatagram> {
            self.udp.fetch_add(1, Ordering::SeqCst);
            let _pending = PendingCall::new(&self.active);
            if self.pending_connects { return std::future::pending().await; }
            Err(Error::Unsupported("spy UDP".into()))
        }
    }

    fn wrapper(children: &[Arc<ChildSpy>]) -> PingoraPooledOutbound {
        PingoraPooledOutbound::new(
            "lifecycle", children.iter().map(|child| child.clone() as Arc<dyn OutboundHandler>).collect(),
            None, 4, Duration::from_secs(60),
        )
    }
    fn session(udp: bool) -> SessionContext {
        let address = "127.0.0.1".parse().unwrap();
        SessionContext::new("test", if udp { Destination::udp(address, 53) } else { Destination::tcp(address, 443) })
    }

    #[tokio::test]
    async fn pooled_start_validates_and_starts_every_child_even_after_errors() {
        tokio::time::timeout(LIMIT, async {
            for fail in [false, true] {
                let children = [
                    Arc::new(ChildSpy { start_error: fail, ..ChildSpy::new("first") }),
                    Arc::new(ChildSpy::new("second")),
                    Arc::new(ChildSpy { start_error: fail, ..ChildSpy::new("third") }),
                ];
                let pooled = wrapper(&children);
                let result = pooled.start().await;
                if fail { assert!(matches!(result, Err(Error::Config(message)) if message == "start first")); }
                else { result.unwrap(); }
                for child in &children { assert_eq!(child.starts.load(Ordering::SeqCst), 1); }
                pooled.close().await.unwrap();
                assert!(matches!(pooled.start().await, Err(Error::Closed)));
                for child in &children { assert_eq!(child.starts.load(Ordering::SeqCst), 1); }
            }
            let empty = wrapper(&[]);
            assert!(matches!(empty.start().await, Err(Error::NotFound(_))));
            assert!(matches!(empty.connect(&session(false)).await, Err(Error::NotFound(_))));
            assert!(matches!(empty.connect_datagram(&session(true)).await, Err(Error::NotFound(_))));
            empty.close().await.unwrap();
            assert!(matches!(empty.start().await, Err(Error::Closed)));
            assert!(matches!(empty.connect(&session(false)).await, Err(Error::Closed)));
            assert!(matches!(empty.connect_datagram(&session(true)).await, Err(Error::Closed)));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn pooled_close_attempts_all_children_and_blocks_cached_tcp_and_udp_after_errors() {
        tokio::time::timeout(LIMIT, async {
            let children = [
                Arc::new(ChildSpy { close_error: true, ..ChildSpy::new("first") }),
                Arc::new(ChildSpy::new("second")),
                Arc::new(ChildSpy { close_error: true, ..ChildSpy::new("third") }),
            ];
            let pooled = wrapper(&children);
            let tcp = session(false);
            let key = pool_key(&format!("{}:{}", pooled.tag(), tcp.destination));
            let (cached, _peer) = tokio::io::duplex(32);
            pooled.pool().put(key, Box::pin(cached));
            assert!(matches!(pooled.close().await, Err(Error::Other(message)) if message == "close first"));
            for child in &children { assert_eq!(child.closes.load(Ordering::SeqCst), 1); }
            assert!(matches!(pooled.connect(&tcp).await, Err(Error::Closed)));
            assert!(matches!(pooled.connect_datagram(&session(true)).await, Err(Error::Closed)));
            assert!(matches!(pooled.start().await, Err(Error::Closed)));
            for child in &children {
                assert_eq!(child.tcp.load(Ordering::SeqCst), 0);
                assert_eq!(child.udp.load(Ordering::SeqCst), 0);
                assert_eq!(child.starts.load(Ordering::SeqCst), 0);
            }
            // The wrapper refuses reuse without draining the independently
            // shared pool. Its normal idle eviction still owns this entry.
            assert!(pooled.pool().get(key).is_some());
        }).await.unwrap();
    }

    #[tokio::test]
    async fn pooled_close_cancels_pending_tcp_and_udp_before_child_shutdown_finishes() {
        tokio::time::timeout(LIMIT, async {
            let gate = watch::channel(false).0;
            let children = [
                Arc::new(ChildSpy { pending_connects: true, close_gate: Some(gate.clone()), ..ChildSpy::new("first") }),
                Arc::new(ChildSpy { close_error: true, ..ChildSpy::new("second") }),
                Arc::new(ChildSpy::new("third")),
            ];
            let pooled = wrapper(&children);
            let tcp = session(false);
            let udp = session(true);
            let mut pending_tcp = pooled.connect(&tcp);
            let mut pending_udp = pooled.connect_datagram(&udp);
            futures::future::poll_fn(|cx| {
                assert!(pending_tcp.as_mut().poll(cx).is_pending());
                assert!(pending_udp.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            assert_eq!(children[0].active.load(Ordering::SeqCst), 2);
            let mut closing = pooled.close();
            futures::future::poll_fn(|cx| {
                assert!(closing.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            // A stalled first close must neither delay cancellation nor keep
            // later children from being asked to close.
            for child in &children { assert_eq!(child.closes.load(Ordering::SeqCst), 1); }
            assert!(matches!(pending_tcp.await, Err(Error::Closed)));
            assert!(matches!(pending_udp.await, Err(Error::Closed)));
            assert_eq!(children[0].active.load(Ordering::SeqCst), 0);
            assert_eq!(children[0].tcp.load(Ordering::SeqCst), 1);
            assert_eq!(children[0].udp.load(Ordering::SeqCst), 1);
            for child in &children[1..] {
                assert_eq!(child.tcp.load(Ordering::SeqCst), 0);
                assert_eq!(child.udp.load(Ordering::SeqCst), 0);
            }
            assert!(matches!(pooled.connect(&tcp).await, Err(Error::Closed)));
            assert!(matches!(pooled.connect_datagram(&udp).await, Err(Error::Closed)));
            gate.send_replace(true);
            assert!(matches!(closing.await, Err(Error::Other(message)) if message == "close second"));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn pooled_close_preserves_caller_owned_fresh_and_cached_streams() {
        tokio::time::timeout(LIMIT, async {
            for cached in [false, true] {
                let child = Arc::new(ChildSpy::new("ready"));
                let pooled = wrapper(std::slice::from_ref(&child));
                let tcp = session(false);
                let (stream, mut peer) = tokio::io::duplex(32);
                let stream: BoxStream = Box::pin(stream);
                if cached {
                    let key = pool_key(&format!("{}:{}", pooled.tag(), tcp.destination));
                    pooled.pool().put(key, stream);
                } else { *child.stream.lock().unwrap() = Some(stream); }
                let mut stream = pooled.connect(&tcp).await.unwrap();
                assert_eq!(child.tcp.load(Ordering::SeqCst), if cached { 0 } else { 1 });
                pooled.close().await.unwrap();
                assert_eq!(child.closes.load(Ordering::SeqCst), 1);
                stream.write_all(b"ping").await.unwrap();
                let mut payload = [0; 4];
                peer.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                peer.write_all(b"pong").await.unwrap();
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"pong");
                stream.shutdown().await.unwrap();
            }
        }).await.unwrap();
    }
}
