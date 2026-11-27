use serde::{Deserialize, Serialize};
use crate::common::errors::{Error, Result};

/// JSON configuration follows the pinned Go GRPCConfig, including signed
/// timeout/window inputs. Runtime capabilities are validated after clamping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[serde(default, rename = "serviceName", alias = "service_name")]
    pub service_name: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default, rename = "multiMode", alias = "multi_mode")]
    pub multi_mode: bool,
    #[serde(default, alias = "idleTimeout")]
    pub idle_timeout: Option<i32>,
    #[serde(default, alias = "healthCheckTimeout")]
    pub health_check_timeout: Option<i32>,
    #[serde(default, alias = "permitWithoutStream")]
    pub permit_without_stream: Option<bool>,
    #[serde(default, alias = "initialWindowsSize")]
    pub initial_windows_size: Option<i32>,
    #[serde(default, alias = "userAgent")]
    pub user_agent: String,
}

impl GrpcConfig {
    pub fn build(&self) -> Result<crate::transport::internet::grpc::GrpcConfig> {
        let config = self.normalized();
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn build_server(&self) -> Result<crate::transport::internet::grpc::GrpcConfig> {
        let mut config = self.normalized();
        // Go never sends a user-agent from the listener. Its empty client UA
        // default therefore does not require browser fingerprint emulation here.
        config.user_agent = "golang".into();
        config.validate()?;
        let service = crate::transport::internet::grpc::encoding::CustomServiceName::new(&config.service_name);
        if service.method_path() == service.multi_method_path() {
            return Err(Error::Config("gRPC listener requires distinct Tun/TunMulti paths".into()));
        }
        Ok(config)
    }

    fn normalized(&self) -> crate::transport::internet::grpc::GrpcConfig {
        crate::transport::internet::grpc::GrpcConfig {
            service_name: self.service_name.clone(), authority: self.authority.clone(),
            multi_mode: self.multi_mode,
            idle_timeout: self.idle_timeout.unwrap_or(0).max(0) as u32,
            health_check_timeout: self.health_check_timeout.unwrap_or(0).max(0) as u32,
            permit_without_stream: self.permit_without_stream.unwrap_or(false),
            initial_windows_size: self.initial_windows_size.unwrap_or(0).max(0),
            user_agent: self.user_agent.clone(),
        }
    }
}
