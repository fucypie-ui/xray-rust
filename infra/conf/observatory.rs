use serde::{Deserialize, Serialize};
use crate::common::errors::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservatoryConfig {
    #[serde(default, rename = "subjectSelector", alias = "subject_selectors")]
    pub subject_selectors: Vec<String>,
    #[serde(default, rename = "probeURL", alias = "probe_url")]
    pub probe_url: Option<String>,
    #[serde(default, rename = "probeInterval", alias = "probe_interval")]
    pub probe_interval: Option<String>,
    #[serde(default, rename = "enableConcurrency", alias = "enable_concurrency")]
    pub enable_concurrency: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckSettings {
    #[serde(default)] pub destination: String,
    #[serde(default)] pub connectivity: String,
    #[serde(default)] pub interval: Option<String>,
    #[serde(default)] pub timeout: Option<String>,
    #[serde(default)] pub sampling: i32,
    #[serde(default, rename = "httpMethod")] pub http_method: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstObservatoryConfig {
    #[serde(default, rename = "subjectSelector")] pub subject_selectors: Vec<String>,
    #[serde(default, rename = "pingConfig")] pub ping_config: Option<HealthCheckSettings>,
}

pub fn duration_ns(value: Option<&str>) -> Result<i64> {
    match value {
        None => Ok(0),
        Some(value) => go_parse_duration::parse_duration(value)
            .map_err(|error| Error::Config(format!("invalid duration: {:?}", error))),
    }
}

impl ObservatoryConfig {
    pub fn validate(&self) -> Result<()> {
        duration_ns(self.probe_interval.as_deref())?;
        Ok(())
    }
}
impl BurstObservatoryConfig {
    pub fn validate(&self) -> Result<()> {
        let ping = self.ping_config.as_ref().ok_or_else(|| Error::Config("BurstObservatory requires a valid pingConfig".into()))?;
        duration_ns(ping.interval.as_deref())?;
        duration_ns(ping.timeout.as_deref())?;
        Ok(())
    }
}
