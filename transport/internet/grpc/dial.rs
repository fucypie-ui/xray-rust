use super::config::GrpcConfig;
use super::encoding::CustomServiceName;
use super::encoding::encoding::WRITE_CHUNK;
use super::stream::{DriverGuard, GunStream};
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination, Network};
use crate::transport::internet::dialer::Dialer;
use crate::transport::internet::system_dialer::SystemDialer;
use async_trait::async_trait;
use bytes::Bytes;
use http::Request;
use tokio::sync::oneshot;
use std::time::Duration;

pub struct GrpcDialer {
    pub config: GrpcConfig,
}

impl GrpcDialer {
    pub fn new(config: GrpcConfig) -> Self { Self { config } }

    /// Additive hook for parent-owned TLS/REALITY/base-dialer wiring. The caller
    /// supplies the established lower stream, with h2 ALPN for TLS. No security
    /// option is downgraded or interpreted by this module.
    pub async fn dial_over(&self, stream: BoxStream, dest: &Destination, secure: bool) -> Result<BoxStream> {
        self.config.validate()?;
        if dest.network != Network::Tcp {
            return Err(Error::Unsupported("gRPC transport requires a TCP lower stream".into()));
        }
        let authority = if !self.config.authority.is_empty() { self.config.authority.clone() }
            else { match &dest.address {
                Address::Domain(domain) => domain.clone(),
                Address::Ipv6(ip) => format!("[{ip}]:{}", dest.port),
                _ => format!("{}:{}", dest.address, dest.port),
            }};
        let service = CustomServiceName::new(&self.config.service_name);
        let path = if self.config.multi_mode { service.multi_method_path() } else { service.method_path() };
        let scheme = if secure { "https" } else { "http" };
        let uri: http::Uri = format!("{scheme}://{authority}{path}").parse()
            .map_err(|e| Error::Config(format!("invalid gRPC request URI: {e}")))?;
        let mut request = Request::builder().method("POST").version(http::Version::HTTP_2)
            .uri(uri).header("content-type", "application/grpc")
            .header("te", "trailers").header("grpc-accept-encoding", "identity");
        if !self.config.user_agent.is_empty() && self.config.user_agent != "golang" {
            request = request.header("user-agent", &self.config.user_agent);
        }
        let request = request.body(()).map_err(|e| Error::Config(format!("invalid gRPC request: {e}")))?;
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(self.config.window_size())
            .initial_connection_window_size(1024 * 1024)
            .max_header_list_size(16 * 1024).max_send_buffer_size(WRITE_CHUNK + 16)
            .enable_push(false);
        let (sender, mut connection) = builder.handshake::<_, Bytes>(stream).await
            .map_err(|e| Error::Protocol(format!("gRPC HTTP/2 handshake: {e}")))?;
        let (stop, mut stopped) = oneshot::channel();
        let driver = DriverGuard { _stop: stop };
        tokio::spawn(async move {
            tokio::select! {
                _ = &mut connection => {},
                _ = &mut stopped => {
                    // Poll queued END_STREAM/RST before dropping the socket;
                    // also bound cancellation when a peer stops reading.
                    let _ = tokio::time::timeout(Duration::from_secs(1), &mut connection).await;
                }
            }
        });
        let mut sender = sender.ready().await
            .map_err(|e| Error::Protocol(format!("gRPC HTTP/2 readiness: {e}")))?;
        let (response, send) = sender.send_request(request, false)
            .map_err(|e| Error::Protocol(format!("gRPC HTTP/2 request: {e}")))?;
        // Do NOT await response headers here: grpc-go can defer them until its
        // first response write, after the caller has sent application bytes.
        Ok(Box::pin(GunStream::client(send, response, self.config.multi_mode, driver)))
    }
}

#[async_trait]
impl Dialer for GrpcDialer {
    async fn dial(&self, dest: &Destination) -> Result<BoxStream> {
        self.config.validate()?;
        if dest.network != Network::Tcp {
            return Err(Error::Unsupported("gRPC transport requires TCP".into()));
        }
        let stream = SystemDialer::dial_tcp(dest).await?;
        self.dial_over(Box::pin(stream), dest, false).await
    }
}
