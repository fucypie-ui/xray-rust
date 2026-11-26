use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::app::policy::config_pb as pb;
use crate::common::errors::Result;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLevelConfig {
    #[serde(default)]
    pub handshake: Option<u32>,
    #[serde(default, rename = "connIdle", alias = "conn_idle")]
    pub conn_idle: Option<u32>,
    #[serde(default, rename = "uplinkOnly", alias = "uplink_only")]
    pub uplink_only: Option<u32>,
    #[serde(default, rename = "downlinkOnly", alias = "downlink_only")]
    pub downlink_only: Option<u32>,
    #[serde(default, rename = "statsUserUplink")]
    pub stats_user_uplink: bool,
    #[serde(default, rename = "statsUserDownlink")]
    pub stats_user_downlink: bool,
    #[serde(default, rename = "statsUserOnline")]
    pub stats_user_online: bool,
    #[serde(default, rename = "bufferSize")]
    pub buffer_size: Option<i32>,
}

impl PolicyLevelConfig {
    pub fn build(&self) -> pb::Policy {
        pb::Policy {
            timeout: Some(pb::PolicyTimeout {
                handshake: self.handshake.map(pb::Second::new),
                connection_idle: self.conn_idle.map(pb::Second::new),
                uplink_only: self.uplink_only.map(pb::Second::new),
                downlink_only: self.downlink_only.map(pb::Second::new),
            }),
            stats: Some(pb::PolicyStats {
                user_uplink: self.stats_user_uplink,
                user_downlink: self.stats_user_downlink,
                user_online: self.stats_user_online,
            }),
            // Go int32 multiplication wraps, and every negative value means
            // unlimited. JSON uses KiB; the native message uses bytes.
            buffer: self.buffer_size.map(|size| pb::PolicyBuffer {
                connection: if size < 0 { -1 } else { size.wrapping_mul(1024) },
            }),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemPolicyConfig {
    #[serde(default, rename = "statsInboundUplink")]
    pub stats_inbound_uplink: bool,
    #[serde(default, rename = "statsInboundDownlink")]
    pub stats_inbound_downlink: bool,
    #[serde(default, rename = "statsOutboundUplink")]
    pub stats_outbound_uplink: bool,
    #[serde(default, rename = "statsOutboundDownlink")]
    pub stats_outbound_downlink: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub levels: HashMap<u32, Option<PolicyLevelConfig>>,
    #[serde(default)]
    pub system: Option<SystemPolicyConfig>,
    // A native protobuf buffer is measured in bytes, including non-KiB values.
    #[serde(skip)]
    pub native: Option<pb::Config>,
}

impl PolicyConfig {
    pub fn build(&self) -> Result<pb::Config> {
        if let Some(native) = &self.native { return Ok(native.clone()); }
        Ok(pb::Config {
            level: self.levels.iter().filter_map(|(&level, policy)| policy.as_ref().map(|policy| (level, policy.build()))).collect(),
            system: self.system.as_ref().map(|policy| pb::SystemPolicy {
                stats: Some(pb::SystemPolicyStats {
                    inbound_uplink: policy.stats_inbound_uplink,
                    inbound_downlink: policy.stats_inbound_downlink,
                    outbound_uplink: policy.stats_outbound_uplink,
                    outbound_downlink: policy.stats_outbound_downlink,
                }),
            }),
        })
    }
}
