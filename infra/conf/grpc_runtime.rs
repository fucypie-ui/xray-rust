//! Configured Gun transport. Security is negotiated below HTTP/2 exactly once.
use std::{io, net::SocketAddr, pin::Pin, sync::{Arc, Mutex, MutexGuard, Weak}, task::{Context, Poll}};
use async_trait::async_trait;
use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use crate::{
    common::{errors::{Error, Result}, net::{BoxStream, Destination, Network}},
    features::{feature::Feature, inbound::{InboundDispatcher, InboundHandler, InboundResult, InboundTask, NativeInboundListener}},
    transport::internet::{dialer::Dialer, grpc::{GrpcDialer, GrpcListener}, grpc::hub::LowerStreamAcceptor, system_dialer::SystemDialer},
};
use super::{StreamSettingsConfig, TlsSettingsConfig};

pub(crate) fn selected(stream: Option<&StreamSettingsConfig>) -> bool {
    stream.and_then(|stream| stream.network.as_deref()).is_some_and(|network| network.eq_ignore_ascii_case("grpc"))
}

pub(crate) fn validate_role(protocol: &str, stream: Option<&StreamSettingsConfig>, inbound: bool) -> Result<()> {
    if !selected(stream) { return Ok(()); }
    let protocol = protocol.to_ascii_lowercase();
    if !(matches!(protocol.as_str(), "vless" | "vmess" | "trojan" | "socks" | "http") || inbound && protocol == "socks5") {
        return Err(Error::Unsupported(format!("gRPC transport is not implemented for {} {}", protocol, if inbound {"inbound"} else {"outbound"})));
    }
    Ok(())
}

pub(crate) fn validate_protocol_options(protocol: &str, settings: Option<&serde_json::Value>) -> Result<()> {
    if !protocol.eq_ignore_ascii_case("vless") { return Ok(()); }
    let Some(settings) = settings else { return Ok(()); };
    fn has_flow(user: &serde_json::Value) -> bool {
        user.get("flow").and_then(serde_json::Value::as_str).is_some_and(|flow| !flow.is_empty())
    }
    let clients_have_flow = ["clients", "users"].iter().any(|key| {
        settings.get(*key).and_then(serde_json::Value::as_array).is_some_and(|users| users.iter().any(has_flow))
    });
    let servers_have_flow = settings.get("vnext").and_then(serde_json::Value::as_array).is_some_and(|servers| {
        servers.iter().any(|server| server.get("users").and_then(serde_json::Value::as_array)
            .is_some_and(|users| users.iter().any(has_flow)))
    });
    if has_flow(settings) || clients_have_flow || servers_have_flow {
        return Err(Error::Unsupported("VLESS flow over gRPC is not implemented".into()));
    }
    Ok(())
}

fn settings(stream: &StreamSettingsConfig, inbound: bool) -> Result<crate::transport::internet::grpc::GrpcConfig> {
    if !stream.extra.is_empty() || stream.ws_settings.is_some() || stream.httpupgrade_settings.is_some()
        || stream.xhttp_settings.is_some() || stream.finalmask.is_some() || stream.kcp_settings.is_some()
        || stream.hysteria_settings.is_some() || stream.reality_settings.is_some()
    {
        return Err(Error::Unsupported("gRPC does not support additional transports, REALITY, finalmask, or extra stream options".into()));
    }
    match stream.security.as_deref().unwrap_or("none") {
        "none" | "" if stream.tls_settings.is_none() => {},
        "tls" => {},
        security => return Err(Error::Unsupported(format!("gRPC security/composition is not implemented: {}", security))),
    }
    let json: super::grpc::GrpcConfig = serde_json::from_value(stream.grpc_settings.clone().unwrap_or_else(|| serde_json::json!({})))
        .map_err(|error| Error::Config(format!("invalid grpcSettings: {}", error)))?;
    if inbound { json.build_server() } else { json.build() }
}

fn tls_settings(stream: &StreamSettingsConfig) -> Result<Option<TlsSettingsConfig>> {
    if stream.security.as_deref() != Some("tls") { return Ok(None); }
    let tls = stream.tls_settings.clone().unwrap_or_default();
    if !tls.extra.is_empty() || tls.fingerprint.as_deref().is_some_and(|fingerprint| !fingerprint.is_empty()) {
        return Err(Error::Unsupported("gRPC TLS fingerprint and extra TLS options are not implemented".into()));
    }
    if tls.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty() && (alpn.len() != 1 || alpn[0] != "h2")) {
        return Err(Error::Unsupported("gRPC TLS requires the h2 ALPN exclusively".into()));
    }
    Ok(Some(tls))
}

pub(crate) fn consume_security(stream: &mut StreamSettingsConfig) {
    // The injected dialer now owns TCP -> TLS -> Gun. Protocol clients must not
    // run their own TLS/REALITY handshake over the resulting Gun byte stream.
    stream.security = Some("none".into());
    stream.tls_settings = None;
    stream.reality_settings = None;
}

struct GrpcLifecycle(CancellationToken);
impl Feature for GrpcLifecycle {
    fn feature_type(&self) -> &'static str { "grpcTransport" }
    fn close(&self) -> Result<()> { self.0.cancel(); Ok(()) }
}
impl Drop for GrpcLifecycle { fn drop(&mut self) { self.0.cancel(); } }

struct ClientSecurity { connector: TlsConnector, server_name: Option<String> }
fn client_security(tls: Option<TlsSettingsConfig>) -> Result<Option<ClientSecurity>> {
    let Some(tls) = tls else { return Ok(None); };
    if tls.certificates.as_ref().is_some_and(|certificates| !certificates.is_empty()) {
        return Err(Error::Unsupported("gRPC outbound custom TLS certificates are not implemented".into()));
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().map_err(|error| Error::Config(error.to_string()))?;
    let mut config = if tls.allow_insecure.unwrap_or(false) {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(crate::transport::internet::tls::NoCertificateVerification)).with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    let server_name = tls.server_name.filter(|name| !name.is_empty());
    if let Some(name) = &server_name {
        rustls_pki_types::ServerName::try_from(name.clone()).map_err(|error| Error::Config(format!("invalid gRPC TLS serverName: {}", error)))?;
    }
    Ok(Some(ClientSecurity { connector: TlsConnector::from(Arc::new(config)), server_name }))
}

fn server_security(tls: Option<TlsSettingsConfig>) -> Result<Option<TlsAcceptor>> {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let Some(tls) = tls else { return Ok(None); };
    if tls.allow_insecure.unwrap_or(false) || tls.server_name.as_deref().is_some_and(|name| !name.is_empty()) {
        return Err(Error::Unsupported("gRPC inbound TLS serverName/allowInsecure options are not implemented".into()));
    }
    let certificates = tls.certificates.unwrap_or_default();
    if certificates.len() != 1 { return Err(Error::Config("gRPC inbound TLS requires exactly one certificate/key pair".into())); }
    let cert = &certificates[0];
    if !cert.extra.is_empty() { return Err(Error::Unsupported("gRPC extra certificate options are not implemented".into())); }
    let (certificate, key) = match (&cert.certificate_file, &cert.key_file, &cert.certificate, &cert.key) {
        (Some(certificate), Some(key), None, None) => (std::fs::read(certificate)?, std::fs::read(key)?),
        (None, None, Some(certificate), Some(key)) => (certificate.join("\n").into_bytes(), key.join("\n").into_bytes()),
        _ => return Err(Error::Config("gRPC TLS requires certificateFile/keyFile or inline certificate/key".into())),
    };
    let certificates = CertificateDer::pem_slice_iter(&certificate).collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Config(format!("invalid gRPC TLS certificate: {}", error)))?;
    if certificates.is_empty() { return Err(Error::Config("gRPC TLS certificate chain is empty".into())); }
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|error| Error::Config(format!("invalid gRPC TLS key: {}", error)))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().map_err(|error| Error::Config(error.to_string()))?
        .with_no_client_auth().with_single_cert(certificates, key).map_err(|error| Error::Config(error.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

/// Borrow the actual lower stream only for a poll. Cancellation can revoke its
/// storage even while a Gun stream or an unpolled I/O future remains retained.
/// Direct polling preserves the lower error and half-close completion exactly.
struct ManagedLower {
    stream: Mutex<Option<BoxStream>>,
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl ManagedLower {
    fn close(&self) {
        let lower = self.stream.lock().unwrap_or_else(|error| error.into_inner()).take();
        drop(lower);
        self.reader.wake();
        self.writer.wake();
    }
}
struct ManagedStream { lower: Arc<ManagedLower>, cancel: CancellationToken }
impl ManagedStream {
    fn lower(&self, cx: &Context<'_>, waker: &AtomicWaker) -> MutexGuard<'_, Option<BoxStream>> {
        // Register before checking cancellation/storage so a concurrent close
        // either wakes this poll or is observed before touching the lower I/O.
        waker.register(cx.waker());
        if self.cancel.is_cancelled() { self.lower.close(); }
        self.lower.stream.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn closed() -> io::Error { io::Error::new(io::ErrorKind::ConnectionAborted, "gRPC lower stream cancelled") }
}
impl Drop for ManagedStream {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.lower.close();
    }
}
impl AsyncRead for ManagedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut lower = self.lower(cx, &self.lower.reader);
        match lower.as_mut() {
            Some(lower) => lower.as_mut().poll_read(cx, buffer),
            None => Poll::Ready(Err(Self::closed())),
        }
    }
}
impl AsyncWrite for ManagedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let mut lower = self.lower(cx, &self.lower.writer);
        match lower.as_mut() {
            Some(lower) => lower.as_mut().poll_write(cx, buffer),
            None => Poll::Ready(Err(Self::closed())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut lower = self.lower(cx, &self.lower.writer);
        match lower.as_mut() {
            Some(lower) => lower.as_mut().poll_flush(cx),
            None => Poll::Ready(Err(Self::closed())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut lower = self.lower(cx, &self.lower.writer);
        match lower.as_mut() {
            Some(lower) => lower.as_mut().poll_shutdown(cx),
            None => Poll::Ready(Err(Self::closed())),
        }
    }
}
fn managed_stream(lower: BoxStream, parent: &CancellationToken) -> BoxStream {
    let cancel = parent.child_token();
    let stopped = cancel.clone();
    let lower = Arc::new(ManagedLower { stream: Mutex::new(Some(lower)), reader: AtomicWaker::new(), writer: AtomicWaker::new() });
    let watched = lower.clone();
    tokio::spawn(async move {
        stopped.cancelled().await;
        watched.close();
    });
    Box::pin(ManagedStream { lower, cancel })
}

struct ConfiguredGrpcDialer {
    config: crate::transport::internet::grpc::GrpcConfig,
    tls: Option<ClientSecurity>,
    cancel: CancellationToken,
}
#[async_trait]
impl Dialer for ConfiguredGrpcDialer {
    async fn dial(&self, destination: &Destination) -> Result<BoxStream> {
        if destination.network != Network::Tcp { return Err(Error::Unsupported("gRPC lower transport requires TCP".into())); }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Closed),
            result = async {
                let socket = SystemDialer::dial_tcp(destination).await?;
                let mut stream = managed_stream(Box::pin(socket), &self.cancel);
                let mut config = self.config.clone();
                if let Some(tls) = &self.tls {
                    let name = tls.server_name.clone().unwrap_or_else(|| destination.address.to_ip()
                        .map(|ip| ip.to_string()).unwrap_or_else(|| destination.address.to_string()));
                    let name = rustls_pki_types::ServerName::try_from(name).map_err(|error| Error::Config(error.to_string()))?;
                    let secured = tls.connector.connect(name, stream).await.map_err(|error| Error::Protocol(format!("gRPC lower TLS handshake: {}", error)))?;
                    if secured.get_ref().1.alpn_protocol() != Some(b"h2") { return Err(Error::Protocol("gRPC lower TLS did not negotiate h2".into())); }
                    stream = Box::pin(secured);
                    if config.authority.is_empty() { config.authority = tls.server_name.clone().unwrap_or_default(); }
                }
                GrpcDialer::new(config).dial_over(stream, destination, self.tls.is_some()).await
            } => result,
        }
    }
}

pub(crate) fn outbound(protocol: &str, stream: &StreamSettingsConfig) -> Result<(Arc<dyn Dialer>, Arc<dyn Feature>)> {
    validate_role(protocol, Some(stream), false)?;
    let config = settings(stream, false)?;
    let tls = client_security(tls_settings(stream)?)?;
    let cancel = CancellationToken::new();
    let dialer = Arc::new(ConfiguredGrpcDialer { config, tls, cancel: cancel.clone() });
    Ok((dialer, Arc::new(GrpcLifecycle(cancel))))
}

pub(crate) fn inbound(inner: Arc<dyn InboundHandler>, protocol: &str, stream: &StreamSettingsConfig) -> Result<(Arc<dyn InboundHandler>, Arc<dyn Feature>)> {
    validate_role(protocol, Some(stream), true)?;
    let config = settings(stream, true)?;
    let tls = server_security(tls_settings(stream)?)?;
    let cancel = CancellationToken::new();
    let handler = Arc::new(GrpcInbound { inner, config, tls, cancel: cancel.clone(), listeners: Mutex::new(Vec::new()) });
    Ok((handler, Arc::new(GrpcLifecycle(cancel))))
}

struct GrpcInbound {
    inner: Arc<dyn InboundHandler>,
    config: crate::transport::internet::grpc::GrpcConfig,
    tls: Option<TlsAcceptor>,
    cancel: CancellationToken,
    listeners: Mutex<Vec<Weak<GrpcListener>>>,
}
#[async_trait]
impl InboundHandler for GrpcInbound {
    fn tag(&self) -> &str { self.inner.tag() }
    fn receiver_settings(&self) -> Option<Vec<u8>> { self.inner.receiver_settings() }
    fn proxy_settings(&self) -> Option<Vec<u8>> { self.inner.proxy_settings() }
    async fn start(&self) -> Result<()> {
        if self.cancel.is_cancelled() { return Err(Error::Closed); }
        self.inner.start().await
    }
    async fn close(&self) -> Result<()> {
        self.cancel.cancel();
        let listeners: Vec<_> = self.listeners.lock().unwrap_or_else(|error| error.into_inner()).iter().filter_map(Weak::upgrade).collect();
        let mut result = Ok(());
        for listener in listeners {
            if let Err(error) = listener.close().await && result.is_ok() { result = Err(error); }
        }
        let inner = self.inner.close().await;
        result.and(inner)
    }
    async fn handle_connection(&self, _stream: BoxStream, _remote: SocketAddr) -> Result<InboundResult> {
        Err(Error::Unsupported("gRPC inbound requires its native Gun listener".into()))
    }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        let tls = self.tls.clone();
        let cancel = self.cancel.child_token();
        let acceptor: LowerStreamAcceptor = Arc::new(move |socket| {
            let tls = tls.clone();
            Box::pin(async move {
                // The engine owns and joins inbound lower handshakes and h2
                // children. Keep their sockets there so listener.close() also
                // awaits the actual TCP socket drop.
                let stream = Box::pin(socket) as BoxStream;
                let Some(tls) = tls else { return Ok(stream); };
                let stream = tls.accept(stream).await.map_err(|error| Error::Protocol(format!("gRPC lower TLS handshake: {}", error)))?;
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") { return Err(Error::Protocol("gRPC lower TLS did not negotiate h2".into())); }
                Ok(Box::pin(stream) as BoxStream)
            })
        });
        let listener = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(Error::Closed),
            listener = GrpcListener::bind_over(address, self.config.clone(), acceptor) => Arc::new(listener?),
        };
        {
            let mut listeners = self.listeners.lock().unwrap_or_else(|error| error.into_inner());
            listeners.retain(|listener| listener.strong_count() != 0);
            listeners.push(Arc::downgrade(&listener));
        }
        let watched = listener.clone();
        let stopped = cancel.clone();
        tokio::spawn(async move { stopped.cancelled().await; let _ = watched.close().await; });
        if self.cancel.is_cancelled() { cancel.cancel(); listener.close().await?; return Err(Error::Closed); }
        Ok(Some(Box::new(GrpcNative { listener, inner: self.inner.clone(), cancel })))
    }
}
struct GrpcNative { listener: Arc<GrpcListener>, inner: Arc<dyn InboundHandler>, cancel: CancellationToken }
impl Drop for GrpcNative { fn drop(&mut self) { self.cancel.cancel(); } }
#[async_trait]
impl NativeInboundListener for GrpcNative {
    fn local_addr(&self) -> Result<SocketAddr> { self.listener.local_addr() }
    async fn accept(&mut self, dispatcher: Arc<dyn InboundDispatcher>) -> Result<InboundTask> {
        let (stream, peer) = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(Error::Closed),
            accepted = self.listener.accept() => accepted?,
        };
        let inner = self.inner.clone();
        let cancel = self.cancel.clone();
        Ok(Box::pin(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Error::Closed),
                result = inner.dispatch_connection(stream, peer, dispatcher) => result,
            }
        }))
    }
}

#[cfg(test)]
#[path = "grpc_runtime_test.rs"]
mod tests;
