use super::*;
use crate::common::net::Address;
use crate::core::Instance;
use crate::core::functions::dial_udp;
use crate::transport::pipe::{PipeOption, new_pipe};
use std::time::Duration;
use tokio::time::timeout;

fn destination() -> Destination { Destination::udp(Address::ip([127, 0, 0, 1].into()), 53) }

fn loopback_dispatcher() -> Arc<dyn LinkDispatcher> {
    Arc::new(|_destination: Destination| -> Result<Link> {
        let (reader, writer) = new_pipe(PipeOption::new());
        Ok(Link::new(reader, writer))
    })
}

fn take_worker(conn: &DispatcherConn) -> JoinHandle<()> {
    conn.dispatcher.workers.lock().unwrap().pop().expect("UDP worker was not retained")
}

async fn establish(conn: &DispatcherConn) -> Arc<ConnEntry> {
    assert_eq!(timeout(Duration::from_secs(5), conn.write_to(b"active", destination())).await.unwrap().unwrap(), 6);
    let mut payload = [0; 16];
    let (n, source) = timeout(Duration::from_secs(5), conn.read_from(&mut payload)).await.unwrap().unwrap();
    assert_eq!(&payload[..n], b"active");
    assert_eq!(source, destination());
    conn.dispatcher.conn.read().await.as_ref().unwrap().clone()
}

async fn assert_link_interrupted(entry: &ConnEntry) {
    assert!(entry.closed.load(Ordering::SeqCst));
    assert!(matches!(entry.link.writer.write_buffer(Buffer::from_bytes(b"closed")).await, Err(Error::Closed)));
    assert!(matches!(timeout(Duration::from_secs(5), entry.link.reader.read_multi_buffer()).await.unwrap(), Err(Error::Closed)));
}

#[tokio::test]
async fn instance_close_stops_active_udp_worker_unblocks_read_and_rejects_new_dials() {
    let instance = Instance::from_config(Default::default()).unwrap();
    let conn = dial_udp(&instance).await.unwrap();
    let entry = establish(&conn).await;
    let worker = take_worker(&conn);
    assert!(!worker.is_finished());
    let mut bytes = [0; 32];
    let mut read = Box::pin(conn.read_from(&mut bytes));
    assert!(futures::poll!(read.as_mut()).is_pending());
    instance.close().unwrap();
    assert!(conn.is_closed(), "instance Close did not synchronously mark UDP closed");
    assert!(matches!(timeout(Duration::from_secs(5), read).await.unwrap(), Err(Error::Closed)));
    // Observe the actual worker without calling conn.close(): the instance's
    // cancellation alone must stop it and interrupt both sides of the link.
    timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    assert_link_interrupted(&entry).await;
    assert!(matches!(conn.write_to(b"later", destination()).await, Err(Error::Closed)));
    assert!(matches!(dial_udp(&instance).await, Err(Error::Closed)));
    conn.close().await;
    conn.close().await;
}

#[tokio::test]
async fn dropping_instance_cancels_udp_reads_before_a_worker_has_started() {
    let instance = Instance::from_config(Default::default()).unwrap();
    let conn = dial_udp(&instance).await.unwrap();
    let mut bytes = [0; 8];
    let mut read = Box::pin(conn.read_from(&mut bytes));
    assert!(futures::poll!(read.as_mut()).is_pending());
    drop(instance);
    assert!(conn.is_closed());
    assert!(matches!(timeout(Duration::from_secs(5), read).await.unwrap(), Err(Error::Closed)));
    assert!(matches!(conn.write_to(b"closed", destination()).await, Err(Error::Closed)));
}

#[tokio::test]
async fn closing_one_udp_connection_leaves_its_instance_and_siblings_usable() {
    let instance = Instance::from_config(Default::default()).unwrap();
    let first = dial_udp(&instance).await.unwrap();
    let second = dial_udp(&instance).await.unwrap();
    let entry = establish(&first).await;
    first.close().await;
    assert_link_interrupted(&entry).await;
    assert!(!second.is_closed());
    establish(&second).await;
    let third = dial_udp(&instance).await.unwrap();
    assert!(!third.is_closed(), "closing a connection cancelled its owner");
    instance.close().unwrap();
    assert!(second.is_closed());
    assert!(third.is_closed());
    second.close().await;
    third.close().await;
}

#[tokio::test]
async fn dropping_udp_connection_cancels_its_retained_worker_and_link() {
    let conn = dial_dispatcher(loopback_dispatcher()).await.unwrap();
    let entry = establish(&conn).await;
    let worker = take_worker(&conn);
    drop(conn);
    timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    assert_link_interrupted(&entry).await;
}

#[tokio::test]
async fn standalone_close_wakes_pending_read_and_natural_worker_exit_closes_connection() {
    let conn = dial_dispatcher(loopback_dispatcher()).await.unwrap();
    let mut bytes = [0; 16];
    let mut read = Box::pin(conn.read_from(&mut bytes));
    assert!(futures::poll!(read.as_mut()).is_pending());
    let mut waiting_bytes = [0; 16];
    let mut waiting_read = Box::pin(conn.read_from(&mut waiting_bytes));
    assert!(futures::poll!(waiting_read.as_mut()).is_pending());
    conn.close().await;
    assert!(matches!(timeout(Duration::from_secs(5), read).await.unwrap(), Err(Error::Closed)));
    assert!(matches!(timeout(Duration::from_secs(5), waiting_read).await.unwrap(), Err(Error::Closed)));

    let (downlink_reader, downlink_writer) = new_pipe(PipeOption::new());
    let (_uplink_reader, uplink_writer) = new_pipe(PipeOption::new());
    let dispatcher: Arc<dyn LinkDispatcher> = Arc::new(move |_destination: Destination| -> Result<Link> {
        Ok(Link::new(downlink_reader.clone(), uplink_writer.clone()))
    });
    let conn = dial_dispatcher(dispatcher).await.unwrap();
    timeout(Duration::from_secs(5), conn.write_to(b"request", destination())).await.unwrap().unwrap();
    let worker = take_worker(&conn);
    let mut read = Box::pin(conn.read_from(&mut bytes));
    assert!(futures::poll!(read.as_mut()).is_pending());
    downlink_writer.close().await.unwrap();
    assert!(matches!(timeout(Duration::from_secs(5), read).await.unwrap(), Err(Error::Closed)));
    timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    assert!(conn.is_closed());
}

#[tokio::test]
async fn read_drains_a_real_worker_response_after_eof_before_returning_closed() {
    let (downlink_reader, downlink_writer) = new_pipe(PipeOption::new());
    let (_uplink_reader, uplink_writer) = new_pipe(PipeOption::new());
    let dispatcher: Arc<dyn LinkDispatcher> = Arc::new(move |_destination: Destination| -> Result<Link> {
        Ok(Link::new(downlink_reader.clone(), uplink_writer.clone()))
    });
    let conn = dial_dispatcher(dispatcher).await.unwrap();
    timeout(Duration::from_secs(5), conn.write_to(b"request", destination())).await.unwrap().unwrap();
    let worker = take_worker(&conn);
    // Send through the actual response pipe. The real worker must queue this
    // packet through its callback, observe EOF, and finish before any read.
    timeout(Duration::from_secs(5), downlink_writer.write_buffer(Buffer::from_bytes(b"response"))).await.unwrap().unwrap();
    downlink_writer.close().await.unwrap();
    timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    assert!(conn.is_closed(), "worker EOF did not close the connection");

    let mut bytes = [0; 32];
    let (n, source) = timeout(Duration::from_secs(5), conn.read_from(&mut bytes)).await.unwrap().unwrap();
    assert_eq!(&bytes[..n], b"response");
    assert_eq!(source, destination());
    assert!(matches!(timeout(Duration::from_secs(5), conn.read_from(&mut bytes)).await.unwrap(), Err(Error::Closed)));
}

struct NotifyOnDrop(Option<oneshot::Sender<()>>);
impl Drop for NotifyOnDrop {
    fn drop(&mut self) { if let Some(sender) = self.0.take() { let _ = sender.send(()); } }
}

struct PendingDispatcher {
    ready: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    dropped: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait]
impl LinkDispatcher for PendingDispatcher {
    async fn dispatch(&self, _destination: Destination) -> Result<Link> {
        let _drop = NotifyOnDrop(self.dropped.lock().unwrap().take());
        self.ready.lock().unwrap().take().unwrap().send(()).unwrap();
        std::future::pending().await
    }
}

#[tokio::test]
async fn cancellation_drops_pending_dispatch_and_releases_its_connection_lock() {
    let cancellation = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let dispatcher = Arc::new(PendingDispatcher {
        ready: std::sync::Mutex::new(Some(ready_tx)),
        dropped: std::sync::Mutex::new(Some(dropped_tx)),
    });
    let conn = Arc::new(dial_dispatcher_with_cancellation(dispatcher, cancellation.child_token()).await.unwrap());
    let writer = conn.clone();
    let write = tokio::spawn(async move { writer.write_to(b"blocked", destination()).await });
    timeout(Duration::from_secs(5), ready_rx).await.unwrap().unwrap();
    cancellation.cancel();
    assert!(matches!(timeout(Duration::from_secs(5), write).await.unwrap().unwrap(), Err(Error::Closed)));
    timeout(Duration::from_secs(5), dropped_rx).await.unwrap().unwrap();
    timeout(Duration::from_secs(5), conn.close()).await.expect("cancelled dispatch held the connection lock");
    assert!(conn.is_closed());
}
