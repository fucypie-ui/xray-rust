use crate::features::feature::{Feature, TYPE_POLICY_MANAGER};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeout {
    pub handshake: Duration,
    pub connection_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
}

impl Default for Timeout {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(60),
            connection_idle: Duration::from_secs(300),
            uplink_only: Duration::from_secs(1),
            downlink_only: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    pub per_connection: i32,
}

impl Default for Buffer {
    fn default() -> Self {
        let value = std::env::var("xray.ray.buffer.size").ok()
            .or_else(|| std::env::var("XRAY_RAY_BUFFER_SIZE").ok());
        Self { per_connection: buffer_size_from_env(value.as_deref()) }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemStats {
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemPolicy {
    pub stats: SystemStats,
    pub buffer: Buffer,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPolicy {
    pub timeouts: Timeout,
    pub stats: Stats,
    pub buffer: Buffer,
}

pub type Policy = SessionPolicy;

pub fn default_buffer_policy() -> Buffer { Buffer::default() }

pub fn session_default() -> SessionPolicy { SessionPolicy::default() }

pub trait PolicyManager: Feature {
    fn for_level(&self, level: u32) -> SessionPolicy;
    fn for_system(&self) -> SystemPolicy;
}

pub fn manager_type() -> &'static str { TYPE_POLICY_MANAGER }

/// Match Go's signed 32-bit MiB environment flag and architecture defaults.
pub fn buffer_size_from_env(value: Option<&str>) -> i32 {
    match value.and_then(|value| value.parse::<i32>().ok()).unwrap_or(-17) {
        0 => -1,
        -17 => {
            if cfg!(any(target_arch = "arm", target_arch = "mips")) { 0 }
            else if cfg!(any(target_arch = "aarch64", target_arch = "mips64")) { 4 * 1024 }
            else { 512 * 1024 }
        }
        size => size.wrapping_mul(1024 * 1024),
    }
}
