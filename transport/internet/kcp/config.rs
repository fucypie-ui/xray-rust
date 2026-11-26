use serde::{Deserialize, Serialize};
use crate::common::errors::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KcpConfig {
    pub mtu: u32,
    pub tti: u32,
    #[serde(alias = "uplinkCapacity")]
    pub uplink_capacity: u32,
    #[serde(alias = "downlinkCapacity")]
    pub downlink_capacity: u32,
    #[serde(alias = "cwndMultiplier")]
    pub cwnd_multiplier: u32,
    #[serde(alias = "maxSendingWindow")]
    pub max_sending_window: u32,
    /// Legacy fields retained for old JSON configurations. Current Go mKCP
    /// always adapts its congestion window; it has no congestion toggle.
    pub congestion: bool,
    #[serde(alias = "readBufferSize")]
    pub read_buffer_size: u32,
    #[serde(alias = "writeBufferSize")]
    pub write_buffer_size: u32,
    /// Retained JSON compatibility only. The authoritative Go Build ignores
    /// seed; choose LegacyPacketCodec::with_seed through finalmask instead.
    pub seed: Option<String>,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * 1024 * 1024,
            congestion: false,
            read_buffer_size: 2 * 1024 * 1024,
            write_buffer_size: 2 * 1024 * 1024,
            seed: None,
        }
    }
}

impl KcpConfig {
    pub fn new() -> Self { Self::default() }
    pub fn validate(&self) -> Result<()> {
        if !(21..=8192).contains(&self.mtu) {
            return Err(Error::Config("mKCP mtu must be in 21..=8192".into()));
        }
        if !(10..=1000).contains(&self.tti) {
            return Err(Error::Config("mKCP tti must be in 10..=1000 milliseconds".into()));
        }
        if self.cwnd_multiplier == 0 || self.max_sending_window < self.mtu {
            return Err(Error::Config("mKCP cwndMultiplier must be positive and maxSendingWindow >= mtu".into()));
        }
        // Go performs these operations in u32. Reject capacities whose
        // arithmetic would wrap instead of silently configuring a tiny window.
        for capacity in [self.uplink_capacity, self.downlink_capacity] {
            if capacity.checked_mul(1024 * 1024).is_none() {
                return Err(Error::Config("mKCP capacity exceeds the Go u32 range".into()));
            }
        }
        if self.sending_in_flight_size().checked_mul(self.cwnd_multiplier).is_none() {
            return Err(Error::Config("mKCP congestion window overflows u32".into()));
        }
        Ok(())
    }
    pub(super) fn engine_config(&self) -> Result<super::engine::Config> {
        self.validate()?;
        Ok(super::engine::Config {
            mtu: self.mtu, tti: self.tti,
            uplink_capacity: self.uplink_capacity, downlink_capacity: self.downlink_capacity,
            cwnd_multiplier: self.cwnd_multiplier, max_sending_window: self.max_sending_window,
        })
    }
    pub fn sending_in_flight_size(&self) -> u32 {
        self.in_flight_size(self.uplink_capacity)
    }
    pub fn receiving_in_flight_size(&self) -> u32 {
        self.in_flight_size(self.downlink_capacity)
    }
    fn in_flight_size(&self, capacity: u32) -> u32 {
        let mtu = self.mtu.max(1);
        let intervals = (1000 / self.tti.max(1)).max(1);
        (capacity.saturating_mul(1024 * 1024) / mtu / intervals).max(8)
    }
}
