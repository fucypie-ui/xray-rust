use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{common::net::{Destination, datagram::{datagram_pair, MAX_DATAGRAM_SIZE}}, features::{feature::{Feature, TYPE_POLICY_MANAGER}, policy::{SessionPolicy, SystemPolicy}}};

struct Policy;
impl Feature for Policy { fn feature_type(&self) -> &'static str { TYPE_POLICY_MANAGER } }
impl PolicyManager for Policy {
    fn for_level(&self, _: u32) -> SessionPolicy {
        let mut policy = SessionPolicy::default();
        policy.timeouts.handshake = Duration::from_millis(10);
        policy
    }
    fn for_system(&self) -> SystemPolicy { SystemPolicy::default() }
}
struct Capture { seen: Mutex<Vec<SessionContext>> }
impl Capture { fn new() -> Self { Self { seen: Mutex::new(Vec::new()) } } }
#[async_trait]
impl InboundDispatcher for Capture {
    async fn dispatch_stream(&self, _: BoxStream, session: SessionContext) -> Result<()> { self.seen.lock().unwrap().push(session); Ok(()) }
    async fn connect_stream(&self, session: &SessionContext) -> Result<BoxStream> {
        self.seen.lock().unwrap().push(session.clone());
        let (stream, _) = tokio::io::duplex(64); Ok(Box::pin(stream))
    }
    async fn dispatch_datagrams(&self, _: BoxDatagram, session: SessionContext) -> Result<()> { self.seen.lock().unwrap().push(session); Ok(()) }
}
fn session() -> SessionContext {
    SessionContext::new("in", Destination::from_domain_port("example.com", 443))
        .with_user(User::new(Uuid::from_u128(1)))
}
fn metadata() -> Arc<SessionMetadata> {
    Arc::new(SessionMetadata { default_level: Some(7), users: HashMap::from([(Uuid::from_u128(1), User::with_email(Uuid::from_u128(1), "alice@example.com", 3))]) })
}

#[tokio::test]
async fn all_dispatch_methods_enrich_without_mutating_borrowed_session() {
    let capture = Arc::new(Capture::new());
    let dispatcher = EnrichingDispatcher { inner: capture.clone(), metadata: metadata(), dispatched: Arc::new(Notify::new()), up: None, down: None };
    let original = session();
    let (stream, _) = tokio::io::duplex(64);
    dispatcher.dispatch_stream(Box::pin(stream), original.clone()).await.unwrap();
    let _ = dispatcher.connect_stream(&original).await.unwrap();
    let (packets, _) = datagram_pair(1);
    dispatcher.dispatch_datagrams(packets, original.clone()).await.unwrap();
    assert_eq!(original.user.unwrap().level, 0);
    let seen = capture.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    for session in seen.iter() {
        let user = session.user.as_ref().unwrap();
        assert_eq!(user.email, "alice@example.com"); assert_eq!(user.level, 3);
    }
}

#[tokio::test]
async fn handshake_deadline_ends_at_dispatch_not_connection_end() {
    let dispatched = Arc::new(Notify::new());
    let signal = dispatched.clone();
    let (release, released) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(finish_handshake(async move {
        signal.notify_one();
        released.await.map_err(|_| Error::Closed)?; Ok(())
    }, dispatched, Duration::from_millis(10)));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!task.is_finished());
    release.send(()).unwrap(); task.await.unwrap().unwrap();
    let result = finish_handshake(std::future::pending::<Result<()>>(), Arc::new(Notify::new()), Duration::ZERO).await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut));
}

struct NativeHandler;
#[async_trait]
impl InboundHandler for NativeHandler {
    fn tag(&self) -> &str { "native" }
    async fn handle_connection(&self, _: BoxStream, _: SocketAddr) -> Result<InboundResult> { Err(Error::Unsupported("must use dispatch_connection".into())) }
    async fn dispatch_connection(&self, stream: BoxStream, _: SocketAddr, dispatcher: Arc<dyn InboundDispatcher>) -> Result<()> {
        dispatcher.dispatch_stream(stream, session()).await
    }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> { Ok(Some(Box::new(Listener(address)))) }
}
struct Listener(SocketAddr);
#[async_trait]
impl NativeInboundListener for Listener {
    fn local_addr(&self) -> Result<SocketAddr> { Ok(self.0) }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        Ok(Box::pin(async move {
            let (packets, _) = datagram_pair(1);
            dispatcher.dispatch_datagrams(packets, session()).await
        }))
    }
}
#[tokio::test]
async fn policy_forwards_inner_dispatch_and_native_listener() {
    let settings = serde_json::json!({"clients":[{"id":Uuid::from_u128(1).to_string(),"email":"alice@example.com","level":3}]});
    let handler = PolicyInbound::new(Arc::new(NativeHandler), Arc::new(Policy), "vmess", Some(&settings), None).unwrap();
    let capture = Arc::new(Capture::new());
    let address = "127.0.0.1:12345".parse().unwrap();
    let (stream, _) = tokio::io::duplex(64);
    handler.dispatch_connection(Box::pin(stream), address, capture.clone()).await.unwrap();
    let mut listener = handler.bind_native(address).await.unwrap().unwrap();
    assert_eq!(listener.local_addr().unwrap(), address);
    listener.accept(capture.clone()).await.unwrap().await.unwrap();
    let seen = capture.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|session| session.user.as_ref().unwrap().level == 3));
}

#[tokio::test]
async fn packet_counter_preserves_both_addresses_and_whole_payloads() {
    let (wrapped, peer) = datagram_pair(2);
    let up = Arc::new(Counter::new()); let down = Arc::new(Counter::new());
    let packets = CounterDatagrams { inner: wrapped, up: Some(up.clone()), down: Some(down.clone()) };
    let source = Destination::udp("127.0.0.1".parse::<std::net::IpAddr>().unwrap().into(), 1234);
    let destination = Destination::udp("127.0.0.2".parse::<std::net::IpAddr>().unwrap().into(), 4321);
    let packet = Datagram { payload: bytes::Bytes::from(vec![7u8; MAX_DATAGRAM_SIZE]), source: Some(source.clone()), destination: destination.clone() };
    peer.send(packet.clone()).await.unwrap();
    assert_eq!(packets.recv().await.unwrap(), Some(packet.clone()));
    assert_eq!(up.value(), MAX_DATAGRAM_SIZE as i64);
    packets.send(packet.clone()).await.unwrap();
    assert_eq!(peer.recv().await.unwrap(), Some(packet));
    assert_eq!(down.value(), MAX_DATAGRAM_SIZE as i64);
    packets.close().await.unwrap(); assert!(peer.recv().await.unwrap().is_none());
}

#[tokio::test]
async fn stream_counter_counts_actual_bytes_in_each_direction() {
    let (stream, mut peer) = tokio::io::duplex(64);
    let read = Arc::new(Counter::new()); let write = Arc::new(Counter::new());
    let mut counted = count_stream(Box::pin(stream), Some(read.clone()), Some(write.clone()));
    peer.write_all(b"up").await.unwrap(); let mut buffer = [0u8;2];
    counted.read_exact(&mut buffer).await.unwrap(); assert_eq!(read.value(), 2);
    counted.write_all(b"down").await.unwrap(); assert_eq!(write.value(), 4);
}
