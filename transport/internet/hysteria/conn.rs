//! An authenticated QUIC connection with a continuously driven HTTP/3 control plane.
use super::{auth, endpoint, udp::{DatagramManager, UdpSession}};
use crate::{common::errors::{Error, Result}, proxy::hysteria::config::HysteriaConfig};
use std::{io, net::SocketAddr, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Task(pub tokio::task::JoinHandle<()>);
impl Drop for Task { fn drop(&mut self) { self.0.abort(); } }
struct Inner {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    datagrams: Option<Arc<DatagramManager>>,
    _driver: Task,
    _udp_task: Option<Task>,
}
impl Drop for Inner { fn drop(&mut self) { self.connection.close(0x100u32.into(), b"Hysteria client closed"); } }
#[derive(Clone)]
pub struct HysteriaConn(Arc<Inner>);
impl HysteriaConn {
    pub async fn connect(addr: SocketAddr, server_name: &str, tls: &rustls::ClientConfig, config: &HysteriaConfig) -> Result<Self> {
        config.validate(false)?;
        let endpoint = endpoint::client(addr, tls, &config.transport)?;
        let handshake = async {
            let connection = endpoint.connect(addr, server_name).map_err(|error| Error::Config(error.to_string()))?
                .await.map_err(|error| Error::Protocol(format!("Hysteria QUIC handshake: {error}")))?;
            let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(connection.clone())).await
                .map_err(|error| Error::Protocol(format!("Hysteria HTTP/3 setup: {error}")))?;
            // Sending the last SendRequest handle to the driver task is essential:
            // its Drop closes the connection, including all raw proxy streams.
            let (keeper_tx, keeper_rx) = tokio::sync::oneshot::channel();
            let task = Task(tokio::spawn(async move {
                tokio::select! {
                    _ = driver.wait_idle() => {}
                    keeper = keeper_rx => {
                        if let Ok(keeper) = keeper { let _ = driver.wait_idle().await; drop(keeper); }
                    }
                }
            }));
            let mut request = requests.send_request(auth::auth_request(config)?).await
                .map_err(|error| Error::Protocol(format!("Hysteria auth request: {error}")))?;
            request.finish().await.map_err(|error| Error::Protocol(error.to_string()))?;
            let response = request.recv_response().await.map_err(|error| Error::Protocol(error.to_string()))?;
            let udp = auth::parse_response(&response)?;
            // Auth responses carry no application data. Drain only a bounded body.
            use bytes::Buf;
            let mut body_size = 0usize;
            while let Some(body) = request.recv_data().await.map_err(|error| Error::Protocol(error.to_string()))? {
                body_size = body_size.saturating_add(body.remaining());
                if body_size > 16384 { return Err(Error::Protocol("oversized Hysteria authentication body".into())); }
            }
            keeper_tx.send(requests).map_err(|_| Error::Protocol("HTTP/3 driver closed during authentication".into()))?;
            let datagrams = udp.then(|| DatagramManager::new(connection.clone(), endpoint.clone(), Duration::from_secs(config.transport.udp_idle_timeout), None));
            let udp_task = datagrams.as_ref().map(|manager| Task(tokio::spawn(manager.clone().run())));
            Ok(Self(Arc::new(Inner { connection, _endpoint: endpoint.clone(), datagrams, _driver: task, _udp_task: udp_task })))
        };
        tokio::time::timeout(Duration::from_secs(config.transport.handshake_timeout), handshake).await
            .map_err(|_| Error::Protocol("Hysteria handshake/authentication timed out".into()))?
    }
    pub fn connection(&self) -> &quinn::Connection { &self.0.connection }
    pub fn is_closed(&self) -> bool { self.0.connection.close_reason().is_some() }
    pub fn udp_enabled(&self) -> bool { self.0.datagrams.is_some() }
    pub fn total_sent(&self) -> u64 { self.0.connection.stats().udp_tx.bytes }
    pub fn total_recv(&self) -> u64 { self.0.connection.stats().udp_rx.bytes }
    pub fn close(&self) { self.0.connection.close(0x100u32.into(), b"Hysteria client closed"); }
    /// Opens a raw stream; the proxy layer writes exactly one 0x401 prefix.
    pub async fn open_bi(&self) -> Result<QuicStream> {
        let (send, recv) = self.0.connection.open_bi().await.map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(QuicStream { io: Mutex::new(QuicIo { send, recv }), _owner: self.clone() })
    }
    pub fn open_udp(&self) -> Result<UdpSession> {
        self.0.datagrams.as_ref().ok_or_else(|| Error::Unsupported("Hysteria server disabled UDP".into()))?.open(self.clone())
    }
}
struct QuicIo { send: quinn::SendStream, recv: quinn::RecvStream }
/// The mutex supplies Sync required by the repository's BoxStream interface;
/// polling uses exclusive get_mut and never holds a lock across an await.
pub struct QuicStream { io: Mutex<QuicIo>, _owner: HysteriaConn }
impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.io.get_mut().expect("QUIC stream mutex").recv), cx, output)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.io.get_mut().expect("QUIC stream mutex").send), cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.io.get_mut().expect("QUIC stream mutex").send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.io.get_mut().expect("QUIC stream mutex").send), cx)
    }
}
