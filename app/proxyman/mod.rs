pub mod command;
pub mod config;
pub mod inbound;
pub mod outbound;

use crate::app::dispatcher::DefaultDispatcher;
use crate::common::errors::{Error, Result};
use crate::features::inbound::{InboundDispatcher, InboundHandler, NativeInboundListener};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

pub use config::{InboundHandlerConfig, KnownProtocols, OutboundHandlerConfig, SniffingConfig};
pub use inbound::DefaultInboundManager;
pub use outbound::DefaultOutboundManager;

const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(5);
const ACCEPT_RETRY_MAX: Duration = Duration::from_millis(500);

#[async_trait::async_trait]
trait InboundListener: Send + 'static {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)>;
}

#[async_trait::async_trait]
impl InboundListener for TcpListener {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

fn accept_retry_delay(error: &std::io::Error, backoff: &mut Duration) -> Option<Duration> {
    let message = error.to_string().to_ascii_lowercase();
    // Match Go's terminal closed-listener check. Other accept errors must not
    // discard established clients or permanently stop this inbound.
    if message.contains("closed") { return None; }
    // ENFILE / EMFILE on Unix, WSAEMFILE on Windows. The message also covers
    // wrapped exhaustion errors, as in Go's TCP hub.
    let exhausted = matches!(error.raw_os_error(), Some(23 | 24 | 10024))
        || error.kind() == std::io::ErrorKind::OutOfMemory || message.contains("too many");
    let delay = if exhausted { ACCEPT_RETRY_MAX } else { *backoff };
    *backoff = delay.saturating_mul(2).min(ACCEPT_RETRY_MAX);
    Some(delay)
}

struct ListenerTasks {
    abort: Vec<AbortHandle>,
    addresses: Vec<SocketAddr>,
}

enum BoundInbound {
    Tcp(TcpListener, Arc<dyn InboundHandler>),
    Native(Box<dyn NativeInboundListener>),
}

pub struct InboundManager {
    inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>,
    tasks: Mutex<Option<ListenerTasks>>,
    closed: std::sync::atomic::AtomicBool,
    start_lock: tokio::sync::Mutex<()>,
}

impl InboundManager {
    pub fn new(inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>) -> Self {
        Self { inbounds, tasks: Mutex::new(None), closed: std::sync::atomic::AtomicBool::new(false), start_lock: tokio::sync::Mutex::new(()) }
    }
    pub async fn start(&self, dispatcher: Arc<DefaultDispatcher>) -> Result<Vec<JoinHandle<()>>> {
        let _starting = self.start_lock.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) { return Err(Error::Closed); }
        if self.tasks.lock().map_err(|_| Error::Other("inbound task lock".into()))?.is_some() { return Ok(Vec::new()); }
        // Bind the actual sockets before spawning anything: a later bind failure
        // drops all earlier listeners and propagates to Instance's startup rollback.
        // The old bridge performed a bind probe and suppressed startup errors.
        let mut listeners = Vec::new();
        let mut addresses = Vec::new();
        for (addr, handler) in &self.inbounds {
            if let Some(listener) = handler.bind_native(*addr).await? {
                addresses.push(listener.local_addr()?);
                listeners.push(BoundInbound::Native(listener));
                continue;
            }
            let socket = std::net::TcpListener::bind(addr).map_err(|error| {
                Error::Io(std::io::Error::new(error.kind(), format!("inbound [{}] bind {}: {}", handler.tag(), addr, error)))
            })?;
            socket.set_nonblocking(true)?;
            let listener = TcpListener::from_std(socket)?;
            addresses.push(listener.local_addr()?);
            listeners.push(BoundInbound::Tcp(listener, handler.clone()));
        }
        // No synchronous mutex is held across an asynchronous native bind.
        // close() may have raced the bind, so recheck before spawning children.
        let mut owned = self.tasks.lock().map_err(|_| Error::Other("inbound task lock".into()))?;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) { return Err(Error::Closed); }
        let mut tasks = Vec::new();
        for (listener, address) in listeners.into_iter().zip(&addresses) {
            tracing::info!("Inbound listening on {}", address);
            tasks.push(match listener {
                BoundInbound::Tcp(listener, handler) => Self::spawn_listener(listener, handler, dispatcher.clone()),
                BoundInbound::Native(listener) => Self::spawn_native_listener(listener, dispatcher.clone()),
            });
        }
        *owned = Some(ListenerTasks { abort: tasks.iter().map(JoinHandle::abort_handle).collect(), addresses });
        Ok(tasks)
    }

    fn spawn_native_listener(mut listener: Box<dyn NativeInboundListener>, dispatcher: Arc<dyn InboundDispatcher>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut backoff = ACCEPT_RETRY_MIN;
            loop {
                tokio::select! {
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed { tracing::warn!("native inbound task failed: {}", error); }
                    }
                    accepted = listener.accept(dispatcher.clone()) => {
                        match accepted {
                            Ok(task) => {
                                backoff = ACCEPT_RETRY_MIN;
                                connections.spawn(async move {
                                    if let Err(error) = task.await { tracing::warn!("native inbound dispatch: {}", error); }
                                });
                            }
                            Err(Error::Closed | Error::Eof) => break,
                            Err(Error::Io(error)) => {
                                let Some(delay) = accept_retry_delay(&error, &mut backoff) else { break; };
                                tracing::warn!("native inbound accept: {}", error);
                                tokio::time::sleep(delay).await;
                            }
                            Err(error) => {
                                tracing::warn!("native inbound accept: {}", error);
                                tokio::time::sleep(backoff).await;
                                backoff = backoff.saturating_mul(2).min(ACCEPT_RETRY_MAX);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Actual bound addresses, including OS-assigned ports for port-zero listeners.
    pub fn listen_addresses(&self) -> Vec<SocketAddr> {
        self.tasks.lock().ok().and_then(|tasks| tasks.as_ref().map(|tasks| tasks.addresses.clone())).unwrap_or_default()
    }

    fn spawn_listener(listener: TcpListener, handler: Arc<dyn InboundHandler>, dispatcher: Arc<DefaultDispatcher>) -> JoinHandle<()> {
        Self::spawn_accept_loop(listener, handler, dispatcher)
    }

    fn spawn_accept_loop<L: InboundListener>(mut listener: L, handler: Arc<dyn InboundHandler>, dispatcher: Arc<DefaultDispatcher>) -> JoinHandle<()> {
        tokio::spawn(async move {
            // The listener future owns every handshake/dispatch task. Dropping
            // or aborting it drops the JoinSet, cancelling even stalled clients.
            let mut connections = JoinSet::new();
            let mut backoff = ACCEPT_RETRY_MIN;
            loop {
                tokio::select! {
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed {
                            tracing::warn!("inbound connection task failed: {}", error);
                        }
                    }
                    accepted = listener.accept() => {
                        let (stream, remote_addr) = match accepted {
                            Ok(connection) => connection,
                            Err(error) => {
                                let Some(delay) = accept_retry_delay(&error, &mut backoff) else { break; };
                                tracing::warn!("inbound [{}] accept failed: {}", handler.tag(), error);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                        };
                        backoff = ACCEPT_RETRY_MIN;
                        let _ = stream.set_nodelay(true);
                        let (handler, dispatcher) = (handler.clone(), dispatcher.clone());
                        connections.spawn(async move {
                            match handler.dispatch_connection(Box::pin(stream), remote_addr, dispatcher).await {
                                Ok(()) => {}
                                Err(Error::Closed) => {}
                                Err(error) => tracing::warn!("[{}] handshake failed from {}: {}", handler.tag(), remote_addr, error),
                            }
                        });
                    }
                }
            }
        })
    }

    pub fn close(&self) -> Result<()> {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(tasks) = tasks.take() {
            for task in tasks.abort { task.abort(); }
        }
        Ok(())
    }
}

impl Drop for InboundManager {
    fn drop(&mut self) { let _ = self.close(); }
}
#[cfg(test)]
mod proxyman_full_test;
#[cfg(test)]
mod proxyman_manager_test;
#[cfg(test)]
mod lifecycle_test;
