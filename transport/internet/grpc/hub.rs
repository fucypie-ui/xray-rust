use super::config::GrpcConfig;
use super::encoding::CustomServiceName;
use super::encoding::encoding::WRITE_CHUNK;
use super::stream::{GunStream, content_type, identity_encoding, status_trailers};
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use std::net::SocketAddr;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use http::{Request, Response};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc, watch};
use tokio::task::JoinSet;

type Accepted = (BoxStream, SocketAddr);
/// Parent-owned lower security handshake; TLS must negotiate ALPN h2.
pub type LowerStreamAcceptor = Arc<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send>> + Send + Sync>;
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: usize = 128;

pub struct GrpcListener {
    local: SocketAddr,
    incoming: Mutex<mpsc::Receiver<Accepted>>,
    shutdown: watch::Sender<bool>,
    done: watch::Receiver<bool>,
}

impl GrpcListener {
    pub async fn bind(addr: SocketAddr, config: GrpcConfig) -> Result<Self> {
        Self::bind_over(addr, config, Arc::new(|socket| Box::pin(async move {
            Ok(Box::pin(socket) as BoxStream)
        }))).await
    }

    /// Additive lower-stream hook for parent TLS/REALITY wiring. Its handshake
    /// is bounded and cancelled with listener shutdown, like the h2 handshake.
    pub async fn bind_over(addr: SocketAddr, config: GrpcConfig, acceptor: LowerStreamAcceptor) -> Result<Self> {
        config.validate()?;
        let service = CustomServiceName::new(&config.service_name);
        if service.method_path() == service.multi_method_path() {
            return Err(Error::Config("gRPC listener requires distinct Tun/TunMulti paths; use /service/Tun|TunMulti for custom paths".into()));
        }
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (incoming, receiver) = mpsc::channel(32);
        let (shutdown, mut stopped) = watch::channel(false);
        let (done, completion) = watch::channel(false);
        tokio::spawn(async move {
            let streams = Arc::new(Semaphore::new(MAX_STREAMS));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.wait_for(|closed| *closed) => break,
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                        let Ok((socket, peer)) = accepted else { break; };
                        let incoming = incoming.clone();
                        let streams = streams.clone();
                        let config = config.clone();
                        let acceptor = acceptor.clone();
                        connections.spawn(async move {
                            // A malformed/stalled connection cannot fail accept
                            // for unrelated clients. Each handshake is bounded.
                            let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), acceptor(socket)).await else { return; };
                            let _ = serve_connection(stream, peer, config, incoming, streams).await;
                        });
                    }
                }
            }
            // Dropping h2 connections wakes pending stream reads/writes with
            // errors. Shutdown is explicit and does not emit false OK trailers.
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            // Release the bound socket before acknowledging completed close.
            drop(listener);
            done.send_replace(true);
        });
        Ok(Self { local, incoming: Mutex::new(receiver), shutdown, done: completion })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> { Ok(self.local) }

    pub async fn accept(&self) -> Result<Accepted> {
        let mut stopped = self.shutdown.subscribe();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|closed| *closed) => Err(Error::Closed),
            next = async { self.incoming.lock().await.recv().await } => next.ok_or(Error::Closed),
        }
    }

    /// Cancels accept, handshakes, and every live server connection. Returned
    /// streams then observe transport errors; close never pretends they ended OK.
    pub async fn close(&self) -> Result<()> {
        self.shutdown.send_replace(true);
        let mut done = self.done.clone();
        done.wait_for(|done| *done).await.map_err(|_| Error::Closed)?;
        // Discard queued streams after the driver tasks have terminated.
        let mut incoming = self.incoming.lock().await;
        incoming.close();
        while incoming.try_recv().is_ok() {}
        Ok(())
    }
}

impl Drop for GrpcListener {
    fn drop(&mut self) { self.shutdown.send_replace(true); }
}

fn reject(mut respond: h2::server::SendResponse<Bytes>, code: u8, message: &str) -> Result<()> {
    let response = Response::builder().status(200).header("content-type", "application/grpc")
        .body(()).map_err(|e| Error::Protocol(e.to_string()))?;
    let mut send = respond.send_response(response, false).map_err(|e| Error::Protocol(e.to_string()))?;
    send.send_trailers(status_trailers(code, message)).map_err(|e| Error::Protocol(e.to_string()))
}

fn request_mode(request: &Request<h2::RecvStream>, config: &GrpcConfig) -> std::result::Result<bool, (u8, &'static str)> {
    if request.method() != http::Method::POST { return Err((12, "gRPC requires POST")); }
    if !content_type(request.headers()) { return Err((12, "gRPC requires application/grpc protobuf content-type")); }
    if request.headers().get("te").is_none_or(|value| value != "trailers") {
        return Err((13, "gRPC requires te: trailers"));
    }
    if !identity_encoding(request.headers()) { return Err((12, "gRPC compression is unavailable")); }
    if request.headers().contains_key("grpc-timeout") {
        return Err((12, "gRPC per-RPC deadline metadata is unavailable; use stream cancellation"));
    }
    let service = CustomServiceName::new(&config.service_name);
    let path = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("");
    if path == service.method_path() { Ok(false) }
    else if path == service.multi_method_path() { Ok(true) }
    else { Err((12, "unknown Gun service/method")) }
}

async fn serve_connection(socket: BoxStream, peer: SocketAddr, config: GrpcConfig,
    incoming: mpsc::Sender<Accepted>, streams: Arc<Semaphore>) -> Result<()> {
    let mut builder = h2::server::Builder::new();
    builder.initial_window_size(config.window_size()).initial_connection_window_size(1024 * 1024)
        .max_header_list_size(16 * 1024).max_concurrent_streams(32)
        .max_send_buffer_size(WRITE_CHUNK + 16);
    let mut connection = tokio::time::timeout(Duration::from_secs(10), builder.handshake::<_, Bytes>(socket))
        .await.map_err(|_| Error::Protocol("gRPC HTTP/2 handshake timed out".into()))?
        .map_err(|e| Error::Protocol(format!("gRPC HTTP/2 handshake: {e}")))?;
    while let Some(next) = connection.accept().await {
        let (request, mut respond) = match next {
            Ok(request) => request,
            Err(error) if error.is_reset() => continue,
            Err(error) => return Err(Error::Protocol(format!("gRPC HTTP/2 request: {error}"))),
        };
        if !content_type(request.headers()) {
            let response = Response::builder().status(415).body(())
                .map_err(|e| Error::Protocol(e.to_string()))?;
            // A peer reset racing this rejection affects only its stream.
            let _ = respond.send_response(response, true);
            continue;
        }
        let multi = match request_mode(&request, &config) {
            Ok(multi) => multi,
            Err((code, message)) => { let _ = reject(respond, code, message); continue; }
        };
        let permit = match streams.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => { let _ = reject(respond, 8, "Gun listener stream limit reached"); continue; }
        };
        // Reserve queue space before sending response headers. Never await a
        // full application queue on the only h2 connection driver.
        let queued = match incoming.try_reserve() {
            Ok(queued) => queued,
            Err(_) => { let _ = reject(respond, 8, "Gun listener accept queue is full/closed"); continue; }
        };
        let response = Response::builder().status(200).header("content-type", "application/grpc")
            .header("grpc-accept-encoding", "identity").body(())
            .map_err(|e| Error::Protocol(e.to_string()))?;
        let send = match respond.send_response(response, false) {
            Ok(send) => send,
            Err(_) => continue, // A cancelled RPC must not close other streams.
        };
        queued.send((Box::pin(GunStream::server(send, request.into_body(), multi, permit)), peer));
    }
    Ok(())
}
