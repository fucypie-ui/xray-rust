use super::{CleanupGuard, spawn_supervised_flows, supervise_flows};
use crate::common::errors::Error;
use std::future::{pending, ready};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, DuplexStream, duplex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const DEADLINE: Duration = Duration::from_secs(3);

async fn assert_stalled_dispatches_stop(abort: bool) {
    let cancellation = CancellationToken::new();
    let (flows_tx, flows_rx) = mpsc::unbounded_channel::<std::io::Result<DuplexStream>>();
    let flows = futures::stream::unfold(flows_rx, |mut receiver| async move {
        receiver.recv().await.map(|flow| (flow, receiver))
    });
    let (ready_tx, mut started) = mpsc::unbounded_channel();
    let (dropped_tx, mut dropped) = mpsc::unbounded_channel();
    let (cleaned_tx, cleaned) = oneshot::channel();
    let dispatcher = Arc::new(());
    let dispatcher_weak = Arc::downgrade(&dispatcher);
    let handle = tokio::spawn(supervise_flows(
        flows,
        cancellation.clone(),
        move |stream| {
            let dispatcher = dispatcher.clone();
            let ready_tx = ready_tx.clone();
            let dropped_tx = dropped_tx.clone();
            Some(async move {
                let _child = CleanupGuard::new(move || { let _ = dropped_tx.send(()); });
                ready_tx.send(()).unwrap();
                // Model an outbound handshake which never finishes or reads its stream.
                pending::<()>().await;
                drop((stream, dispatcher));
            })
        },
        CleanupGuard::new(move || { let _ = cleaned_tx.send(()); }),
    ));
    let mut peers = Vec::new();
    for _ in 0..3 {
        let (stream, peer) = duplex(64);
        flows_tx.send(Ok(stream)).unwrap();
        peers.push(peer);
        timeout(DEADLINE, started.recv()).await.unwrap().unwrap();
    }
    if abort {
        handle.abort();
        assert!(timeout(DEADLINE, handle).await.unwrap().unwrap_err().is_cancelled());
    } else {
        cancellation.cancel();
        timeout(DEADLINE, handle).await.unwrap().unwrap();
    }
    timeout(DEADLINE, cleaned).await.unwrap().unwrap();
    for mut peer in peers {
        timeout(DEADLINE, dropped.recv()).await.unwrap().unwrap();
        assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
    }
    assert!(dispatcher_weak.upgrade().is_none(), "dispatcher retained after runner exit");
    assert!(flows_tx.is_closed(), "runner retained its flow source");
}

#[tokio::test]
async fn cancellation_releases_stalled_dispatches_and_streams() {
    assert_stalled_dispatches_stop(false).await;
}

#[tokio::test]
async fn aborting_runner_releases_stalled_dispatches_and_streams() {
    assert_stalled_dispatches_stop(true).await;
}

#[tokio::test]
async fn abort_before_first_poll_releases_source_and_runs_cleanup() {
    let (stream, mut peer) = duplex(64);
    let (flows_tx, flows_rx) = mpsc::unbounded_channel::<std::io::Result<DuplexStream>>();
    flows_tx.send(Ok(stream)).unwrap();
    let flows = futures::stream::unfold(flows_rx, |mut receiver| async move {
        receiver.recv().await.map(|flow| (flow, receiver))
    });
    let (cleaned_tx, cleaned) = oneshot::channel();
    let handle = tokio::spawn(supervise_flows(
        flows,
        CancellationToken::new(),
        |_| -> Option<std::future::Ready<()>> { panic!("aborted runner was polled") },
        CleanupGuard::new(move || { let _ = cleaned_tx.send(()); }),
    ));
    // No await has allowed this current-thread runtime to poll the runner.
    handle.abort();
    assert!(timeout(DEADLINE, handle).await.unwrap().unwrap_err().is_cancelled());
    timeout(DEADLINE, cleaned).await.unwrap().unwrap();
    assert!(flows_tx.is_closed());
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn completed_dispatches_are_reaped_while_accept_is_idle() {
    let (flows_tx, flows_rx) = mpsc::unbounded_channel::<std::io::Result<()>>();
    let flows = futures::stream::unfold(flows_rx, |mut receiver| async move {
        receiver.recv().await.map(|flow| (flow, receiver))
    });
    let cancellation = CancellationToken::new();
    let (reaped_tx, mut reaped) = mpsc::unbounded_channel();
    let handle = tokio::spawn(supervise_flows(
        flows,
        cancellation.clone(),
        move |_| {
            let reaped_tx = reaped_tx.clone();
            // This value is the task result: it drops only when JoinSet reaps it.
            Some(ready(CleanupGuard::new(move || { let _ = reaped_tx.send(()); })))
        },
        CleanupGuard::new(|| {}),
    ));
    for _ in 0..3 {
        flows_tx.send(Ok(())).unwrap();
        timeout(DEADLINE, reaped.recv()).await.unwrap().unwrap();
    }
    assert!(!handle.is_finished());
    cancellation.cancel();
    timeout(DEADLINE, handle).await.unwrap().unwrap();
}

#[tokio::test]
async fn accept_error_aborts_stalled_child_and_runs_cleanup() {
    let (flows_tx, flows_rx) = mpsc::unbounded_channel::<std::io::Result<DuplexStream>>();
    let flows = futures::stream::unfold(flows_rx, |mut receiver| async move {
        receiver.recv().await.map(|flow| (flow, receiver))
    });
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let (cleaned_tx, cleaned) = oneshot::channel();
    let handle = tokio::spawn(supervise_flows(
        flows,
        CancellationToken::new(),
        move |stream| {
            let started_tx = started_tx.clone();
            Some(async move {
                started_tx.send(()).unwrap();
                pending::<()>().await;
                drop(stream);
            })
        },
        CleanupGuard::new(move || { let _ = cleaned_tx.send(()); }),
    ));
    let (stream, mut peer) = duplex(64);
    flows_tx.send(Ok(stream)).unwrap();
    timeout(DEADLINE, started.recv()).await.unwrap().unwrap();
    flows_tx.send(Err(std::io::Error::other("injected accept failure"))).unwrap();
    timeout(DEADLINE, handle).await.unwrap().unwrap();
    timeout(DEADLINE, cleaned).await.unwrap().unwrap();
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
}

async fn assert_pending_startup_stops(cancel: bool) {
    let (device, mut peer) = duplex(64);
    let device_owner = Arc::new(());
    let device_weak = Arc::downgrade(&device_owner);
    let (cleaned_tx, cleaned) = oneshot::channel();
    let cancellation = CancellationToken::new();
    let mut startup = Box::pin(spawn_supervised_flows(
        async move {
            pending::<()>().await;
            drop((device, device_owner));
            Ok(futures::stream::empty::<std::io::Result<DuplexStream>>())
        },
        cancellation.clone(),
        |_| Some(ready(())),
        CleanupGuard::new(move || {
            assert!(device_weak.upgrade().is_some(), "device dropped before route cleanup");
            let _ = cleaned_tx.send(());
        }),
    ));
    assert!(futures::poll!(startup.as_mut()).is_pending());
    if cancel {
        cancellation.cancel();
        assert!(matches!(timeout(DEADLINE, startup.as_mut()).await.unwrap(), Err(Error::Closed)));
    }
    drop(startup);
    timeout(DEADLINE, cleaned).await.unwrap().unwrap();
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn dropping_pending_startup_releases_device_and_cleans_routes_first() {
    assert_pending_startup_stops(false).await;
}

#[tokio::test]
async fn cancelling_pending_startup_releases_device_and_cleans_routes_first() {
    assert_pending_startup_stops(true).await;
}
