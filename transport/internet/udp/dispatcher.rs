use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use crate::common::buf::Buffer;
use crate::common::errors::{Error, Result};
use crate::common::net::Destination;
use crate::common::protocol::udp::UdpPacket;
use crate::transport::link::Link;

pub type ResponseCallback = Arc<dyn Fn(&UdpPacket) + Send + Sync>;

#[async_trait]
pub trait LinkDispatcher: Send + Sync {
    async fn dispatch(&self, dest: Destination) -> Result<Link>;
}

#[async_trait]
impl<F> LinkDispatcher for F
where
    F: Fn(Destination) -> Result<Link> + Send + Sync,
{ async fn dispatch(&self, dest: Destination) -> Result<Link> { (self)(dest) } }

pub struct ConnEntry {
    pub link: Link,
    pub cancel_tx: Mutex<Option<oneshot::Sender<()>>>,
    pub closed: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl ConnEntry {
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cancellation.cancel();
        if let Ok(mut guard) = self.cancel_tx.try_lock() && let Some(tx) = guard.take()
        { let _ = tx.send(()); }
        // The retained worker interrupts both pipe ends before it exits. Do not
        // create a detached cleanup task every time an entry closes.
    }
}

pub struct Dispatcher {
    conn: Arc<RwLock<Option<Arc<ConnEntry>>>>,
    dispatcher: Arc<dyn LinkDispatcher>,
    callback: ResponseCallback,
    call_close: Option<Arc<dyn Fn() + Send + Sync>>,
    closed: Arc<AtomicBool>,
    cancellation: CancellationToken,
    workers: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

pub type UdpDispatcher = Dispatcher;

impl Dispatcher {
    pub fn new(dispatcher: Arc<dyn LinkDispatcher>, callback: ResponseCallback) -> Self {
        Self::new_with_cancellation(dispatcher, callback, CancellationToken::new())
    }
    fn new_with_cancellation(dispatcher: Arc<dyn LinkDispatcher>, callback: ResponseCallback, cancellation: CancellationToken) -> Self {
        Self {
            conn: Arc::new(RwLock::new(None)),
            dispatcher,
            callback,
            call_close: None,
            closed: Arc::new(AtomicBool::new(false)),
            cancellation,
            workers: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn with_call_close<F: Fn() + Send + Sync + 'static>(mut self, call_close: F) -> Self {
        self.call_close = Some(Arc::new(call_close));
        self
    }
    pub async fn remove_ray(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Cancel first so an in-progress dispatcher or pipe write releases its
        // connection lock rather than preventing removal indefinitely.
        self.cancellation.cancel();
        let entry = self.conn.write().await.take();
        if let Some(entry) = entry { entry.close(); }
        let workers = {
            let mut workers = self.workers.lock().unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut *workers)
        };
        for worker in workers {
            if let Err(error) = worker.await { tracing::warn!("UDP dispatcher worker failed: {}", error); }
        }
    }
    pub async fn get_inbound_ray(&self, dest: Destination) -> Result<Arc<ConnEntry>> {
        if self.closed.load(Ordering::SeqCst) || self.cancellation.is_cancelled() { return Err(Error::Closed); }
        {
            let guard = tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Err(Error::Closed),
                guard = self.conn.read() => guard,
            };
            if let Some(entry) = guard.as_ref().filter(|e| !e.closed.load(Ordering::SeqCst)) {
                return Ok(entry.clone());
            }
        }
        let mut guard = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(Error::Closed),
            guard = self.conn.write() => guard,
        };
        if self.closed.load(Ordering::SeqCst) || self.cancellation.is_cancelled() { return Err(Error::Closed); }
        if let Some(entry) = guard.as_ref().filter(|e| !e.closed.load(Ordering::SeqCst)) { return Ok(entry.clone()); }
        let link = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(Error::Closed),
            link = self.dispatcher.dispatch(dest.clone()) => link?,
        };
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let entry = Arc::new(ConnEntry {
            link: link.clone(),
            cancel_tx: Mutex::new(Some(cancel_tx)),
            closed: Arc::new(AtomicBool::new(false)),
            cancellation: self.cancellation.child_token(),
        });
        *guard = Some(entry.clone());
        let (callback, call_close, closed, cancellation) = (
            self.callback.clone(), self.call_close.clone(), entry.closed.clone(), entry.cancellation.clone(),
        );
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = &mut cancel_rx => break,
                    res = link.reader.read_multi_buffer() => match res {
                        Ok(mb) if !mb.is_empty() => {
                            for buf in mb.into_buffers() {
                                callback(&UdpPacket::new(buf, dest.clone(), Destination::default()));
                            }
                        }
                        _ => break,
                    }
                }
            }
            closed.store(true, Ordering::SeqCst);
            cancellation.cancel();
            link.reader.interrupt().await;
            link.writer.interrupt().await;
            if let Some(close_fn) = call_close { close_fn(); }
        });
        let mut workers = self.workers.lock().unwrap_or_else(|error| error.into_inner());
        workers.retain(|worker| !worker.is_finished());
        workers.push(worker);
        Ok(entry)
    }
    pub async fn dispatch(&self, destination: Destination, payload: Buffer) -> Result<()> {
        let entry = self.get_inbound_ray(destination).await?;
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(Error::Closed),
            _ = entry.cancellation.cancelled() => Err(Error::Closed),
            result = entry.link.writer.write_buffer(payload) => result,
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        // Cooperatively stop retained workers so they can still finish their
        // asynchronous pipe cleanup. Explicit remove_ray also joins them.
        self.cancellation.cancel();
    }
}

pub struct DispatcherConn {
    dispatcher: Arc<Dispatcher>,
    cache_rx: Mutex<mpsc::Receiver<UdpPacket>>,
    closed: Arc<AtomicBool>,
    cancellation: CancellationToken,
}

impl DispatcherConn {
    pub async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Destination)> {
        let mut cache = self.cache_rx.lock().await;
        let pkt = tokio::select! {
            biased;
            // Like Go's ReadFrom, drain queued packets even after closure.
            packet = cache.recv() => packet.ok_or(Error::Closed)?,
            // Recheck the cache if cancellation races a response becoming ready.
            _ = self.cancellation.cancelled() => cache.try_recv().map_err(|_| Error::Closed)?,
        };
        let bytes = pkt.payload.as_slice();
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok((n, pkt.source))
    }
    pub async fn write_to(&self, buf: &[u8], dest: Destination) -> Result<usize> {
        if self.is_closed() { return Err(Error::Closed); }
        let buffer = Buffer::from_bytes(buf);
        self.dispatcher.dispatch(dest, buffer).await?;
        Ok(buf.len())
    }
    pub fn is_closed(&self) -> bool { self.closed.load(Ordering::SeqCst) || self.cancellation.is_cancelled() }
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cancellation.cancel();
        self.dispatcher.remove_ray().await;
    }
}

impl Drop for DispatcherConn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cancellation.cancel();
    }
}

pub async fn dial_dispatcher(dispatcher: Arc<dyn LinkDispatcher>) -> Result<DispatcherConn> {
    dial_dispatcher_with_cancellation(dispatcher, CancellationToken::new()).await
}

pub(crate) async fn dial_dispatcher_with_cancellation(dispatcher: Arc<dyn LinkDispatcher>, cancellation: CancellationToken) -> Result<DispatcherConn> {
    if cancellation.is_cancelled() { return Err(Error::Closed); }
    let ((tx, rx), closed) = (mpsc::channel(16), Arc::new(AtomicBool::new(false)));
    let c = closed.clone();
    let callback_cancellation = cancellation.clone();
    let cb: ResponseCallback = Arc::new(move |pkt: &UdpPacket| {
        if !c.load(Ordering::Relaxed) && !callback_cancellation.is_cancelled() { let _ = tx.try_send(pkt.clone()); }
    });
    let close_flag = closed.clone();
    let close_cancellation = cancellation.clone();
    let dispatcher = Dispatcher::new_with_cancellation(dispatcher, cb, cancellation.clone()).with_call_close(move || {
        close_flag.store(true, Ordering::SeqCst);
        close_cancellation.cancel();
    });
    Ok(DispatcherConn { dispatcher: Arc::new(dispatcher), cache_rx: Mutex::new(rx), closed, cancellation })
}

#[cfg(test)]
#[path = "cancellation_test.rs"]
mod cancellation_test;
