use super::*;
use crate::common::net::BoxStream;
use crate::features::inbound::InboundResult;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::timeout;

struct StalledHandler {
    ready: mpsc::UnboundedSender<()>,
    dropped: mpsc::UnboundedSender<()>,
}

struct ConnectionDrop(mpsc::UnboundedSender<()>);
impl Drop for ConnectionDrop {
    fn drop(&mut self) { let _ = self.0.send(()); }
}

#[async_trait::async_trait]
impl InboundHandler for StalledHandler {
    fn tag(&self) -> &str { "owned-test" }
    async fn handle_connection(&self, stream: BoxStream, _remote: SocketAddr) -> Result<InboundResult> {
        let _drop = ConnectionDrop(self.dropped.clone());
        self.ready.send(()).unwrap();
        let result = std::future::pending().await;
        drop(stream);
        result
    }
}

fn dispatcher() -> Arc<DefaultDispatcher> {
    Arc::new(DefaultDispatcher::new(
        Default::default(),
        Arc::new(crate::app::router::Router::new(Vec::new(), None)),
    ))
}

#[tokio::test]
async fn aborting_returned_listener_handle_also_aborts_all_connection_tasks() {
    let (ready_tx, mut ready) = mpsc::unbounded_channel();
    let (dropped_tx, mut dropped) = mpsc::unbounded_channel();
    let manager = InboundManager::new(vec![(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(StalledHandler { ready: ready_tx, dropped: dropped_tx }),
    )]);
    let mut tasks = manager.start(dispatcher()).await.unwrap();
    let address = manager.listen_addresses()[0];
    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(tokio::net::TcpStream::connect(address).await.unwrap());
        timeout(Duration::from_secs(5), ready.recv()).await.unwrap().unwrap();
    }
    assert!(manager.start(dispatcher()).await.unwrap().is_empty());
    let listener = tasks.pop().unwrap();
    listener.abort();
    assert!(timeout(Duration::from_secs(5), listener).await.unwrap().unwrap_err().is_cancelled());
    for mut client in clients {
        timeout(Duration::from_secs(5), dropped.recv()).await.unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(timeout(Duration::from_secs(5), client.read(&mut byte)).await.unwrap().unwrap(), 0);
    }
    assert!(tokio::net::TcpStream::connect(address).await.is_err(), "abort left the listening socket open");
    manager.close().unwrap();
    manager.close().unwrap();
    assert!(manager.listen_addresses().is_empty());
    assert!(matches!(manager.start(dispatcher()).await, Err(Error::Closed)));
}

#[tokio::test]
async fn dropping_manager_stops_listeners_even_when_callers_retain_join_handles() {
    let (ready_tx, mut ready) = mpsc::unbounded_channel();
    let (dropped_tx, mut dropped) = mpsc::unbounded_channel();
    let manager = InboundManager::new(vec![(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(StalledHandler { ready: ready_tx, dropped: dropped_tx }),
    )]);
    let tasks = manager.start(dispatcher()).await.unwrap();
    let address = manager.listen_addresses()[0];
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(5), ready.recv()).await.unwrap().unwrap();
    drop(manager);
    for task in tasks { assert!(timeout(Duration::from_secs(5), task).await.unwrap().unwrap_err().is_cancelled()); }
    timeout(Duration::from_secs(5), dropped.recv()).await.unwrap().unwrap();
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(5), client.read(&mut byte)).await.unwrap().unwrap(), 0);
}

struct RecoveringListener {
    listener: TcpListener,
    attempts: usize,
    injected: Option<oneshot::Sender<()>>,
}

#[async_trait::async_trait]
impl InboundListener for RecoveringListener {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        self.attempts += 1;
        if self.attempts == 2 {
            self.injected.take().unwrap().send(()).unwrap();
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        TcpListener::accept(&self.listener).await
    }
}

#[tokio::test]
async fn recoverable_accept_error_keeps_existing_clients_and_accepts_the_next_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (injected_tx, injected_rx) = oneshot::channel();
    let (ready_tx, mut ready) = mpsc::unbounded_channel();
    let (dropped_tx, mut dropped) = mpsc::unbounded_channel();
    let task = InboundManager::spawn_accept_loop(
        RecoveringListener { listener, attempts: 0, injected: Some(injected_tx) },
        Arc::new(StalledHandler { ready: ready_tx, dropped: dropped_tx }),
        dispatcher(),
    );
    let mut first = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(5), ready.recv()).await.unwrap().unwrap();
    timeout(Duration::from_secs(5), injected_rx).await.unwrap().unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(5), ready.recv()).await.unwrap().unwrap();
    assert!(matches!(dropped.try_recv(), Err(mpsc::error::TryRecvError::Empty)), "recoverable accept failure dropped an active client");
    task.abort();
    assert!(timeout(Duration::from_secs(5), task).await.unwrap().unwrap_err().is_cancelled());
    for _ in 0..2 { timeout(Duration::from_secs(5), dropped.recv()).await.unwrap().unwrap(); }
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(5), first.read(&mut byte)).await.unwrap().unwrap(), 0);
    assert_eq!(timeout(Duration::from_secs(5), second.read(&mut byte)).await.unwrap().unwrap(), 0);
}

#[test]
fn accept_backoff_is_bounded_and_exhaustion_uses_go_half_second_delay() {
    let recoverable = std::io::Error::from(std::io::ErrorKind::Interrupted);
    let mut backoff = ACCEPT_RETRY_MIN;
    assert_eq!(accept_retry_delay(&recoverable, &mut backoff), Some(ACCEPT_RETRY_MIN));
    for _ in 0..32 {
        let delay = accept_retry_delay(&recoverable, &mut backoff).unwrap();
        assert!((ACCEPT_RETRY_MIN..=ACCEPT_RETRY_MAX).contains(&delay));
    }
    assert_eq!(backoff, ACCEPT_RETRY_MAX);
    backoff = ACCEPT_RETRY_MIN;
    let exhausted = std::io::Error::other("too many open files");
    assert_eq!(accept_retry_delay(&exhausted, &mut backoff), Some(Duration::from_millis(500)));
    assert_eq!(backoff, ACCEPT_RETRY_MAX);
    let closed = std::io::Error::other("use of closed network connection");
    assert_eq!(accept_retry_delay(&closed, &mut backoff), None);
}
