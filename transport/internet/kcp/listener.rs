use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::config::KcpConfig;
use super::connection::KcpConnection;
use super::runtime::{self, DatagramCodec, KcpStream, Lease, Shared};
use super::connection::State;
use super::wire::{CMD_TERMINATE, Segment, read_segments};
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;

#[derive(Debug, Clone, Copy)]
pub struct KcpListenerOptions {
    pub max_sessions: usize,
    pub accept_backlog: usize,
    pub input_backlog: usize,
}
impl Default for KcpListenerOptions {
    fn default() -> Self {
        Self { max_sessions: 4096, accept_backlog: 1024, input_backlog: 1024 }
    }
}
struct Session {
    // The demultiplexer owns protocol state, not an application lease.
    // Dropping the last accepted handle must still start graceful close.
    lease: Weak<Lease>,
    shared: Arc<Shared>,
    mss: usize,
    input: mpsc::Sender<Vec<u8>>,
}
impl Session {
    fn is_terminated(&self) -> bool { self.shared.lock().engine.state() == State::Terminated }
    fn connection(&self, conv: u16, local: SocketAddr, peer: SocketAddr) -> Option<KcpConnection> {
        self.lease.upgrade().map(|lease| KcpConnection::from_lease(lease, conv, local, peer, self.mss))
    }
}
type Sessions = Arc<Mutex<HashMap<(SocketAddr, u16), Session>>>;

/// One UDP input loop, demultiplexed by the full Go ConnectionID. A session
/// has its own timer/output task and can never consume another peer's packet.
pub struct KcpListener {
    local_addr: SocketAddr,
    sessions: Sessions,
    accepted: tokio::sync::Mutex<mpsc::Receiver<KcpConnection>>,
    cancellation: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}
impl KcpListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        Self::bind_with_config(addr, KcpConfig::default(), CancellationToken::new()).await
    }
    pub async fn bind_with_config(
        addr: SocketAddr, config: KcpConfig, cancellation: CancellationToken,
    ) -> Result<Self> {
        let codec = runtime::config_codec(&config);
        Self::bind_with_options(addr, config, cancellation, codec, KcpListenerOptions::default()).await
    }
    pub async fn bind_with_codec(
        addr: SocketAddr, config: KcpConfig, cancellation: CancellationToken,
        codec: Arc<dyn DatagramCodec>,
    ) -> Result<Self> {
        Self::bind_with_options(addr, config, cancellation, codec, KcpListenerOptions::default()).await
    }
    pub async fn bind_with_options(
        addr: SocketAddr, config: KcpConfig, cancellation: CancellationToken,
        codec: Arc<dyn DatagramCodec>, options: KcpListenerOptions,
    ) -> Result<Self> {
        config.validate()?;
        if cancellation.is_cancelled() { return Err(Error::Closed); }
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Self::from_socket_with_options(socket, config, cancellation, codec, options)
    }
    /// Attach a socket configured by the core system listener (sockopt,
    /// interface binding, or platform routing) before starting packet input.
    pub fn from_socket_with_config(
        socket: Arc<UdpSocket>, config: KcpConfig, cancellation: CancellationToken,
    ) -> Result<Self> {
        let codec = runtime::config_codec(&config);
        Self::from_socket_with_options(socket, config, cancellation, codec, KcpListenerOptions::default())
    }
    pub fn from_socket_with_options(
        socket: Arc<UdpSocket>, config: KcpConfig, cancellation: CancellationToken,
        codec: Arc<dyn DatagramCodec>, options: KcpListenerOptions,
    ) -> Result<Self> {
        config.validate()?;
        if cancellation.is_cancelled() { return Err(Error::Closed); }
        if options.max_sessions == 0 || options.accept_backlog == 0 || options.input_backlog == 0 {
            return Err(Error::Config("mKCP listener capacities must be positive".into()));
        }
        tokio::runtime::Handle::try_current().map_err(|error| Error::Config(format!("mKCP listener requires a Tokio runtime: {error}")))?;
        if socket.peer_addr().is_ok() { return Err(Error::Config("mKCP listener requires an unconnected UDP socket".into())); }
        let local_addr = socket.local_addr()?;
        let cancellation = cancellation.child_token();
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let (accepted, receiver) = mpsc::channel(options.accept_backlog);
        let task = tokio::spawn(receive_loop(
            socket, sessions.clone(), accepted, cancellation.clone(), config, codec, options,
        ));
        Ok(Self {
            local_addr, sessions, accepted: tokio::sync::Mutex::new(receiver), cancellation,
            task: Mutex::new(Some(task)),
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> { Ok(self.local_addr) }
    pub async fn accept(&self) -> Result<(KcpConnection, SocketAddr)> {
        let mut receiver = self.accepted.lock().await;
        let connection = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(Error::Closed),
            connection = receiver.recv() => connection.ok_or(Error::Closed)?,
        };
        let peer = connection.peer_addr()?;
        Ok((connection, peer))
    }
    pub async fn accept_stream(&self) -> Result<(KcpStream, SocketAddr)> {
        let (connection, peer) = self.accept().await?;
        Ok((connection.into_stream(), peer))
    }
    pub async fn accept_box_stream(&self) -> Result<(BoxStream, SocketAddr)> {
        let (stream, peer) = self.accept_stream().await?;
        Ok((stream.into_boxed(), peer))
    }
    pub async fn get_session_for(&self, peer: SocketAddr, conv: u16) -> Option<KcpConnection> {
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(peer, conv)).filter(|session| !session.is_terminated())
            .and_then(|session| session.connection(conv, self.local_addr, peer))
    }
    /// Legacy lookup: ambiguity never returns a different peer's session.
    pub async fn get_session(&self, conv: u16) -> Option<KcpConnection> {
        let sessions = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut matches = sessions.iter().filter(|((_, id), session)| *id == conv && !session.is_terminated());
        let ((peer, _), session) = matches.next()?;
        let connection = session.connection(conv, self.local_addr, *peer)?;
        if matches.next().is_some() { None } else { Some(connection) }
    }
    pub fn active_connections(&self) -> usize {
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .values().filter(|session| !session.is_terminated()).count()
    }
    /// Cancels all accepted sessions, wakes accept/read/write, and joins
    /// the receive loop and every session driver it owns.
    pub async fn close(&self) -> Result<()> {
        self.cancellation.cancel();
        let task = self.task.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(task) = task { let _ = task.await; }
        Ok(())
    }
}
impl Drop for KcpListener {
    fn drop(&mut self) { self.cancellation.cancel(); }
}

async fn receive_loop(
    socket: Arc<UdpSocket>, sessions: Sessions, accepted: mpsc::Sender<KcpConnection>,
    cancellation: CancellationToken, config: KcpConfig, codec: Arc<dyn DatagramCodec>,
    options: KcpListenerOptions,
) {
    let mut raw = vec![0u8; 65_535];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    loop {
        let packet = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = cleanup.tick() => {
                sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|_, session| !session.is_terminated());
                continue;
            }
            result = socket.recv_from(&mut raw) => result,
        };
        let Ok((count, peer)) = packet else { break; };
        let Ok(plain) = codec.decode(&raw[..count]) else { continue; };
        let segments = read_segments(&plain);
        let Some(first) = segments.first() else { continue; };
        let conv = first.conv();
        let terminate = matches!(first, Segment::Cmd(segment) if segment.cmd == CMD_TERMINATE);
        let mut sessions = sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.get(&(peer, conv)).is_some_and(Session::is_terminated) {
            sessions.remove(&(peer, conv));
        }
        if let Some(session) = sessions.get(&(peer, conv)) {
            // Overflow is ordinary loss; ARQ will retransmit. Never stall
            // every peer because one session stopped consuming input.
            let _ = session.input.try_send(plain);
            continue;
        }
        if terminate || sessions.len() >= options.max_sessions || accepted.capacity() == 0 { continue; }
        let (input, receiver) = mpsc::channel(options.input_backlog);
        let connection = match KcpConnection::accepted(
            conv, socket.clone(), peer, config.clone(), cancellation.clone(), codec.clone(), receiver,
        ) {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        let _ = input.try_send(plain);
        // Only this loop produces accepted connections, so a checked free
        // slot cannot be taken by another producer before try_send.
        if accepted.try_send(connection.clone()).is_err() {
            connection.shared().cancellation.cancel();
            continue;
        }
        sessions.insert((peer, conv), Session {
            lease: connection.weak_lease(), shared: connection.shared().clone(),
            mss: connection.mss, input,
        });
    }
    cancellation.cancel();
    let connections: Vec<_> = sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        .drain().map(|(_, session)| session.shared).collect();
    for shared in connections {
        shared.cancellation.cancel();
        shared.join().await;
    }
}
