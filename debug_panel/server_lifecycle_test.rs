use super::*;
use crate::debug_panel::{spawn_reserved_server, spawn_reserved_server_when_closed};
use std::future::Future;
use std::sync::{Mutex, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn observe(
    future: impl Future<Output = ()> + Send + 'static,
) -> (
    impl Future<Output = ()> + Send + 'static,
    oneshot::Receiver<()>,
    oneshot::Receiver<()>,
) {
    let (start, started) = oneshot::channel();
    let (drop, dropped) = oneshot::channel();
    // Capture the guard before polling so unpolled cancellation is observable.
    let guard = DropSignal(Some(drop));
    let future = async move {
        let _guard = guard;
        let _ = start.send(());
        future.await;
    };
    (future, started, dropped)
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    timeout(Duration::from_secs(5), future)
        .await
        .expect("debug server lifecycle operation did not finish")
}

async fn stop(task: JoinHandle<()>) {
    task.abort();
    assert!(within(task).await.unwrap_err().is_cancelled());
}

async fn handle_connection(stream: TcpStream) {
    let _ = handle_conn(stream).await;
}

#[tokio::test]
async fn abort_drops_stalled_http_connections_and_resource_sampler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sampler, sampler_started, mut sampler_dropped) = observe(sample_resources());
    let (accepted, mut connections) = mpsc::unbounded_channel();
    let task = tokio::spawn(serve(listener, sampler, move |stream| {
        let (connection, started, dropped) = observe(handle_connection(stream));
        accepted.send((started, dropped)).unwrap();
        connection
    }));
    within(sampler_started).await.unwrap();

    let mut clients = Vec::new();
    for _ in 0..3 {
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /ai HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        let (started, mut dropped) = within(connections.recv()).await.unwrap();
        within(started).await.unwrap();
        assert!(matches!(
            dropped.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        clients.push((client, dropped));
    }
    assert!(matches!(
        sampler_dropped.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    stop(task).await;
    within(sampler_dropped).await.expect("sampler survived abort");
    for (mut client, dropped) in clients {
        within(dropped).await.expect("connection child survived abort");
        let mut byte = [0u8; 1];
        match within(client.read(&mut byte)).await {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            result => panic!("stalled connection remained open: {result:?}"),
        }
    }
}

#[tokio::test]
async fn sequential_servers_restart_without_releasing_a_new_owner() {
    let reservation = Mutex::new(Weak::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sampler, started, mut dropped) = observe(sample_resources());
    let mut cancellation = CancellationToken::new();
    let mut task = spawn_reserved_server_when_closed(
        &reservation,
        cancellation.clone(),
        serve(listener, sampler, handle_connection),
    )
    .await
    .unwrap();
    within(started).await.unwrap();

    for _ in 0..3 {
        let (sampler, started, next_dropped) = observe(sample_resources());
        let next_cancellation = CancellationToken::new();
        let old_abort = task.abort_handle();
        // Match Instance::close: signal cancellation and abort synchronously.
        // No await, yield, or old-handle join may precede replacement startup.
        cancellation.cancel();
        task.abort();
        assert!(!task.is_finished());
        assert!(reservation.lock().unwrap().upgrade().is_some());
        let next = within(spawn_reserved_server_when_closed(
            &reservation,
            next_cancellation.clone(),
            run_server_with_sampler(address.to_string(), sampler),
        ))
        .await
        .expect("previous server retained the singleton reservation");
        // Sampling starts only after the replacement binds the same address.
        within(started).await.unwrap();
        within(dropped).await.expect("old sampler survived restart");

        old_abort.abort();
        // A live concurrent instance must neither take over nor cancel next.
        assert!(within(spawn_reserved_server_when_closed(
            &reservation,
            CancellationToken::new(),
            async {},
        ))
        .await
        .is_none());
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /ai/help HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        within(client.read_to_end(&mut response)).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

        assert!(within(task).await.unwrap_err().is_cancelled());
        task = next;
        cancellation = next_cancellation;
        dropped = next_dropped;
    }
    cancellation.cancel();
    stop(task).await;
    within(dropped).await.unwrap();
    assert!(reservation.lock().unwrap().upgrade().is_none());
}

#[tokio::test]
async fn completed_server_releases_reservation() {
    let reservation = Mutex::new(Weak::new());
    for _ in 0..3 {
        let task = spawn_reserved_server(&reservation, async {}).unwrap();
        assert!(spawn_reserved_server(&reservation, async {}).is_none());
        within(task).await.unwrap();
        assert!(reservation.lock().unwrap().upgrade().is_none());
    }
}

#[tokio::test]
async fn abort_before_first_poll_releases_reservation() {
    let reservation = Mutex::new(Weak::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sampler, mut sampler_started, sampler_dropped) = observe(sample_resources());
    let (server, mut started, dropped) = observe(serve(listener, sampler, handle_connection));
    let cancellation = CancellationToken::new();
    let task = spawn_reserved_server_when_closed(&reservation, cancellation.clone(), server)
        .await
        .unwrap();
    // The default current-thread runtime cannot poll the task before this abort.
    cancellation.cancel();
    task.abort();
    assert!(!task.is_finished());
    let (sampler, replacement_started, replacement_dropped) = observe(sample_resources());
    let replacement = within(spawn_reserved_server_when_closed(
        &reservation,
        CancellationToken::new(),
        run_server_with_sampler(address.to_string(), sampler),
    ))
    .await
    .expect("unpolled abort blocked immediate replacement");
    within(replacement_started).await.unwrap();
    assert!(matches!(
        started.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    assert!(matches!(
        sampler_started.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    within(dropped).await.expect("unpolled server future was retained");
    within(sampler_dropped).await.expect("unpolled sampler was retained");
    assert!(within(task).await.unwrap_err().is_cancelled());
    stop(replacement).await;
    within(replacement_dropped).await.unwrap();
    assert!(reservation.lock().unwrap().upgrade().is_none());
}

#[tokio::test]
async fn cancelling_waiting_replacement_does_not_claim_or_start_a_server() {
    let reservation = Mutex::new(Weak::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sampler, started, dropped) = observe(sample_resources());
    let cancellation = CancellationToken::new();
    let task = spawn_reserved_server_when_closed(
        &reservation,
        cancellation.clone(),
        serve(listener, sampler, handle_connection),
    )
    .await
    .unwrap();
    within(started).await.unwrap();
    let original_owner = reservation.lock().unwrap().clone();
    cancellation.cancel();
    task.abort();

    let next_cancellation = CancellationToken::new();
    let (server, mut next_started, next_dropped) = observe(run_server(address.to_string()));
    let mut replacement = Box::pin(spawn_reserved_server_when_closed(
        &reservation,
        next_cancellation.clone(),
        server,
    ));
    assert!(futures::poll!(replacement.as_mut()).is_pending());
    next_cancellation.cancel();
    assert!(within(replacement).await.is_none());
    assert!(Weak::ptr_eq(&reservation.lock().unwrap(), &original_owner));
    assert!(matches!(
        next_started.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    within(next_dropped).await.expect("cancelled replacement future was retained");
    assert!(within(task).await.unwrap_err().is_cancelled());
    within(dropped).await.unwrap();
}

#[tokio::test]
async fn bind_failure_never_starts_sampler_and_releases_reservation() {
    let reservation = Mutex::new(Weak::new());
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let (sampler, mut started, dropped) = observe(sample_resources());
    let task = spawn_reserved_server_when_closed(
        &reservation,
        CancellationToken::new(),
        run_server_with_sampler(address.to_string(), sampler),
    )
    .await
    .unwrap();
    within(task).await.unwrap();
    assert!(matches!(
        started.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    within(dropped).await.expect("failed bind retained the sampler");
    assert!(reservation.lock().unwrap().upgrade().is_none());

    // Retry with a fresh ephemeral listener while the occupied port stays held.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (sampler, started, dropped) = observe(sample_resources());
    let task = spawn_reserved_server_when_closed(
        &reservation,
        CancellationToken::new(),
        serve(listener, sampler, handle_connection),
    )
    .await
    .unwrap();
    within(started).await.unwrap();
    stop(task).await;
    within(dropped).await.unwrap();

    // Preserve the public spawn_server entry point's normal bind-error exit.
    within(spawn_server(address.to_string())).await.unwrap();
}
