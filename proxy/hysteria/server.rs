use super::{config::{HysteriaConfig, HysteriaUser}, protocol::{TcpRequest, TcpResponse}};
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination}, protocol::{SessionContext, User}},
    features::inbound::{InboundHandler, InboundResult}, transport::internet::hysteria::{auth, endpoint, h3_backend::{Backend, ProxyStream}, padding::padding::Padding, udp::{DatagramManager, UdpSession}}};
use async_trait::async_trait;
use bytes::Bytes;
use std::{net::SocketAddr, str::FromStr, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::AsyncWriteExt, sync::{Notify, mpsc}, task::{JoinHandle, JoinSet}};

pub struct HysteriaServer { pub tag: String, pub config: HysteriaConfig, tls: Option<Arc<rustls::ServerConfig>> }
impl HysteriaServer {
    pub fn new(tag: impl Into<String>, config: HysteriaConfig) -> Self { Self { tag: tag.into(), config, tls: None } }
    pub fn with_tls(tag: impl Into<String>, config: HysteriaConfig, tls: Arc<rustls::ServerConfig>) -> Self {
        Self { tag: tag.into(), config, tls: Some(tls) }
    }
    /// Bind a dedicated UDP/QUIC listener. TLS certificate verification is never
    /// bypassed by this module; the caller supplies the server certificate config.
    pub fn bind(&self, address: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<HysteriaListener> {
        self.config.validate(true)?;
        let endpoint = endpoint::server(address, &tls, &self.config.transport)?;
        let (tx, rx) = mpsc::channel(128);
        let serving_endpoint = endpoint.clone();
        let config = Arc::new(self.config.clone());
        let tag = self.tag.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = serving_endpoint.accept(), if connections.len() < 1024 => {
                        let Some(incoming) = incoming else { break; };
                        let config = config.clone(); let tx = tx.clone(); let tag = tag.clone(); let endpoint = serving_endpoint.clone();
                        connections.spawn(async move {
                            let handshake = tokio::time::timeout(Duration::from_secs(config.transport.handshake_timeout), incoming).await;
                            if let Ok(Ok(connection)) = handshake {
                                if let Err(error) = serve_connection(connection.clone(), endpoint, tag, config, tx).await {
                                    tracing::debug!("Hysteria connection ended: {error}");
                                }
                                connection.close(0x100u32.into(), b"Hysteria connection ended");
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(HysteriaListener { endpoint, receiver: rx, task })
    }
}
#[async_trait]
impl InboundHandler for HysteriaServer {
    fn tag(&self) -> &str { &self.tag }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn crate::features::inbound::NativeInboundListener>>> {
        let tls = self.tls.clone().ok_or_else(|| Error::Config("Hysteria native listener requires an explicit TLS server configuration".into()))?;
        let listener = self.bind(address, tls)?;
        Ok(Some(Box::new(super::native::NativeListener { listener, tag: self.tag.clone() })))
    }
    async fn handle_connection(&self, _stream: BoxStream, _remote_addr: SocketAddr) -> Result<InboundResult> {
        Err(Error::Unsupported("Hysteria requires HysteriaServer::bind and its authenticated QUIC listener".into()))
    }
}

pub struct HysteriaListener { endpoint: quinn::Endpoint, receiver: mpsc::Receiver<HysteriaIncoming>, task: JoinHandle<()> }
impl HysteriaListener {
    pub fn local_addr(&self) -> Result<SocketAddr> { Ok(self.endpoint.local_addr()?) }
    pub async fn accept(&mut self) -> Result<HysteriaIncoming> {
        self.receiver.recv().await.ok_or_else(|| Error::Protocol("Hysteria listener closed".into()))
    }
    pub fn close(&self) { self.endpoint.close(0x100u32.into(), b"Hysteria listener closed"); self.task.abort(); }
}
impl Drop for HysteriaListener { fn drop(&mut self) { self.close(); } }

pub enum HysteriaIncoming {
    Tcp(HysteriaTcpIncoming),
    Udp { session: UdpSession, source: SocketAddr, user: Option<User> },
}
/// A pending request: the router can establish the destination first, then send
/// success. Destination failures must call reject rather than fabricating success.
pub struct HysteriaTcpIncoming { pub session: SessionContext, stream: BoxStream }
impl HysteriaTcpIncoming {
    pub async fn accept(mut self) -> Result<InboundResult> {
        write_response(&mut self.stream, true, "").await?;
        Ok(InboundResult { stream: self.stream, session: self.session })
    }
    pub async fn reject(mut self, reason: &str) -> Result<()> {
        write_response(&mut self.stream, false, reason).await?;
        self.stream.shutdown().await?;
        Ok(())
    }
}
async fn write_response(stream: &mut BoxStream, ok: bool, reason: &str) -> Result<()> {
    let padding = Padding::new(128, 1024).generate_string();
    let mut encoded = TcpResponse::new(ok, reason, padding.len()).encode()?;
    let start = encoded.len() - padding.len();
    encoded[start..].copy_from_slice(padding.as_bytes());
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}
fn user_context(user: &HysteriaUser) -> User {
    // Keep auth secrets out of routing metadata. The stable identity follows
    // email/level while authorization itself uses the exact password above.
    User::with_email(uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, user.email.as_bytes()), &user.email, user.level)
}
type AuthState = Arc<Mutex<Option<Option<HysteriaUser>>>>;

async fn serve_connection(connection: quinn::Connection, endpoint: quinn::Endpoint, tag: String, config: Arc<HysteriaConfig>, output: mpsc::Sender<HysteriaIncoming>) -> Result<()> {
    let authenticated = Arc::new(AtomicBool::new(false));
    let state: AuthState = Arc::new(Mutex::new(None));
    let notify = Arc::new(Notify::new());
    let (proxy_tx, mut proxy_rx) = mpsc::channel(128);
    let backend = Backend::new(connection.clone(), authenticated.clone(), proxy_tx);
    let mut h3 = h3::server::builder().max_field_section_size(16384).build::<_, Bytes>(backend).await.map_err(|error| Error::Protocol(error.to_string()))?;
    let (udp_tx, mut udp_rx) = mpsc::channel(64);
    let udp_enabled = !config.users.is_empty();
    let udp_manager = DatagramManager::new(connection.clone(), endpoint, Duration::from_secs(config.transport.udp_idle_timeout), Some(udp_tx));
    let mut udp_task: Option<crate::transport::internet::hysteria::conn::Task> = None;
    let mut work = JoinSet::new();
    let deadline = tokio::time::sleep(Duration::from_secs(config.transport.handshake_timeout));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = connection.closed() => return Ok(()),
            _ = &mut deadline, if !authenticated.load(Ordering::Acquire) => return Err(Error::AuthFailed("Hysteria authentication timed out".into())),
            _ = notify.notified(), if udp_task.is_none() => {
                if udp_enabled && authenticated.load(Ordering::Acquire) {
                    udp_task = Some(crate::transport::internet::hysteria::conn::Task(tokio::spawn(udp_manager.clone().run())));
                }
            }
            accepted = h3.accept(), if work.len() < 128 => {
                let Some(resolver) = accepted.map_err(|error| Error::Protocol(error.to_string()))? else { return Ok(()); };
                let config = config.clone(); let state = state.clone(); let flag = authenticated.clone(); let notify = notify.clone();
                work.spawn(async move {
                    let handle = async {
                        let (request, mut stream) = resolver.resolve_request().await.map_err(|error| Error::Protocol(error.to_string()))?;
                        let decision = {
                            let mut state = state.lock().expect("Hysteria auth mutex");
                            let accepted = auth::authenticate(&request, &config, state.is_some());
                            if let Some(user) = &accepted {
                                if state.is_none() { *state = Some(user.clone()); }
                                flag.store(true, Ordering::Release);
                                notify.notify_one();
                            }
                            accepted.is_some()
                        };
                        let (response, body) = if decision { (auth::auth_response(&config, udp_enabled)?, Bytes::new()) } else { auth::masquerade(&config)? };
                        stream.send_response(response).await.map_err(|error| Error::Protocol(error.to_string()))?;
                        if !body.is_empty() { stream.send_data(body).await.map_err(|error| Error::Protocol(error.to_string()))?; }
                        stream.finish().await.map_err(|error| Error::Protocol(error.to_string()))?;
                        Ok::<_, Error>(())
                    };
                    // A client with unfinished HTTP headers cannot stall other streams.
                    let _ = tokio::time::timeout(Duration::from_secs(config.transport.handshake_timeout), handle).await;
                });
            }
            Some(stream) = proxy_rx.recv(), if work.len() < 128 => {
                let output = output.clone(); let tag = tag.clone(); let state = state.clone(); let timeout = config.transport.handshake_timeout;
                let source = connection.remote_address();
                work.spawn(async move {
                    let parse = receive_tcp(stream, source, tag, state, output);
                    let _ = tokio::time::timeout(Duration::from_secs(timeout), parse).await;
                });
            }
            Some(session) = udp_rx.recv(), if udp_enabled => {
                let user = state.lock().expect("Hysteria auth mutex").as_ref().and_then(|user| user.as_ref()).map(user_context);
                let event = HysteriaIncoming::Udp { source: connection.remote_address(), session, user };
                // Application routing must never stall H3 control traffic.
                let _ = output.try_send(event);
            }
            _ = work.join_next(), if !work.is_empty() => {}
        }
    }
}
async fn receive_tcp(mut stream: ProxyStream, source: SocketAddr, tag: String, state: AuthState, output: mpsc::Sender<HysteriaIncoming>) -> Result<()> {
    // Backend already consumed exactly the 0x401 varint, nothing else.
    let request = TcpRequest::decode(&mut stream).await?;
    let destination = match Destination::from_str(&request.address) {
        Ok(destination) => destination,
        Err(error) => {
            let mut stream: BoxStream = Box::pin(stream);
            write_response(&mut stream, false, "invalid destination address").await?;
            return Err(error);
        }
    };
    let user = state.lock().expect("Hysteria auth mutex").as_ref().and_then(|user| user.as_ref()).map(user_context);
    let mut session = SessionContext::new(tag, destination);
    session.source = Some(source); session.user = user;
    let incoming = HysteriaTcpIncoming { session, stream: Box::pin(stream) };
    if let Err(error) = output.try_send(HysteriaIncoming::Tcp(incoming)) {
        if let HysteriaIncoming::Tcp(incoming) = error.into_inner() { incoming.reject("server busy").await?; }
    }
    Ok(())
}
