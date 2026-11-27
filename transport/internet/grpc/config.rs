use crate::common::errors::{Error, Result};
use serde::{Deserialize, Serialize};

/// Gun over prior-knowledge HTTP/2. TLS/REALITY belongs below this transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[serde(default, alias = "serviceName")]
    pub service_name: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default, alias = "multiMode")]
    pub multi_mode: bool,
    #[serde(default)]
    pub idle_timeout: u32,
    #[serde(default)]
    pub health_check_timeout: u32,
    #[serde(default)]
    pub permit_without_stream: bool,
    #[serde(default)]
    pub initial_windows_size: i32,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

fn default_user_agent() -> String { "golang".into() }

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: String::new(), authority: String::new(), multi_mode: false,
            idle_timeout: 0, health_check_timeout: 0, permit_without_stream: false,
            initial_windows_size: 0, user_agent: default_user_agent(),
        }
    }
}

impl GrpcConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        // Nonzero keepalive settings are rejected, rather than silently ignored.
        Self { service_name: service_name.into(), ..Default::default() }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.idle_timeout != 0 || self.health_check_timeout != 0 || self.permit_without_stream {
            return Err(Error::Unsupported("gRPC PING keepalive options (idle_timeout, health_check_timeout, permit_without_stream) are unavailable".into()));
        }
        if self.initial_windows_size < 0 || self.initial_windows_size > 16 * 1024 * 1024 {
            return Err(Error::Unsupported("gRPC initial_windows_size must be 0..=16777216 (bounded receive window)".into()));
        }
        // The Go aliases synthesize changing browser fingerprints. Do not claim
        // to reproduce those fingerprints with a hard-coded browser UA.
        if matches!(self.user_agent.as_str(), "" | "chrome" | "firefox" | "edge") {
            return Err(Error::Unsupported("gRPC browser user_agent aliases are unavailable; use golang or a literal user agent".into()));
        }
        if !self.authority.is_empty() {
            self.authority.parse::<http::uri::Authority>()
                .map_err(|e| Error::Config(format!("invalid gRPC authority: {e}")))?;
            if self.authority.contains('@') {
                return Err(Error::Config("gRPC authority cannot contain user information".into()));
            }
        }
        http::HeaderValue::from_str(&self.user_agent)
            .map_err(|e| Error::Config(format!("invalid gRPC user_agent: {e}")))?;
        Ok(())
    }

    pub(crate) fn window_size(&self) -> u32 {
        // grpc-go ignores positive stream windows smaller than 64 KiB - 1.
        (self.initial_windows_size as u32).max(65_535)
    }
}
