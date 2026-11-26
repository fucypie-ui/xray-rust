//! Root application construction. Features own their lifecycle and resources;
//! the Instance consumes this registry without manufacturing another stats store.
use std::{collections::HashMap, sync::Arc};
use crate::common::errors::{Error, Result};
use crate::features::{feature::{Feature, TYPE_FAKE_DNS}, outbound::OutboundHandler};
use super::Config;

#[path = "runtime/services.rs"] mod services;
#[path = "runtime/probes.rs"] mod probes;

pub(crate) struct RootRuntime {
    pub policy: Arc<crate::app::policy::Instance>,
    pub stats: Arc<crate::features::stats::DefaultStatsManager>,
    pub stats_enabled: bool,
    pub fake_dns: Option<Arc<crate::app::dns::fakedns::FakeDnsHolder>>,
    pub features: Vec<Arc<dyn Feature>>,
    api: Option<super::api::ApiConfig>,
    metrics: Option<super::metrics::MetricsConfig>,
    observatory: Option<super::observatory::ObservatoryConfig>,
    burst: Option<super::observatory::BurstObservatoryConfig>,
}

impl RootRuntime {
    pub fn new(config: &Config) -> Result<Self> {
        if let Some(api) = &config.api { api.validate()?; }
        if let Some(metrics) = &config.metrics { metrics.build()?; }
        if config.reverse.is_some() {
            return Err(crate::common::errors::print_removed_feature_error("\"legacy reverse\"", "\"VLESS Reverse Proxy\""));
        }
        if config.transport.as_ref().and_then(serde_json::Value::as_object).is_some_and(|transport| !transport.is_empty()) {
            return Err(crate::common::errors::print_removed_feature_error("Global transport config", "streamSettings in inbounds and outbounds"));
        }
        if let Some(observatory) = &config.observatory { observatory.validate()?; }
        if let Some(burst) = &config.burst_observatory { burst.validate()?; }
        if let Some(version) = &config.version {
            use super::buildable::Buildable;
            crate::app::version::Version::new(version.clone().build()?)?;
        }
        if let Some(geodata) = &config.geodata {
            if geodata.get("cron").is_some_and(|value| !value.is_null()) || geodata.get("assets").and_then(serde_json::Value::as_array).is_some_and(|assets| !assets.is_empty()) {
                return Err(Error::Unsupported("scheduled root geodata updates are not implemented".into()));
            }
        }
        // Applying os::set_var in a multithreaded Rust process is unsafe.
        // Resolve the supported environment flag within this instance instead.
        for key in config.env.keys() {
            if key != "xray.ray.buffer.size" && key != "XRAY_RAY_BUFFER_SIZE" {
                return Err(Error::Unsupported(format!("root environment flag is not implemented: {}", key)));
            }
        }
        let mut defaults = crate::features::policy::session_default();
        if let Some(value) = config.env.get("xray.ray.buffer.size").or_else(|| config.env.get("XRAY_RAY_BUFFER_SIZE")) {
            defaults.buffer.per_connection = crate::features::policy::policy::buffer_size_from_env(Some(value));
        }
        let policy_config = config.policy.as_ref().map(super::policy::PolicyConfig::build).transpose()?.unwrap_or_default();
        let policy = Arc::new(crate::app::policy::Instance::with_defaults(&policy_config, defaults)?);
        let stats = Arc::new(crate::features::stats::DefaultStatsManager::new());
        let stats_enabled = config.stats.is_some();
        let mut features: Vec<Arc<dyn Feature>> = vec![policy.clone()];
        if stats_enabled { features.push(stats.clone()); }
        else { features.push(Arc::new(crate::features::stats::NoopStatsManager::new())); }
        let fake_dns = build_fake_dns(config.fake_dns.as_ref())?;
        if let Some(holder) = &fake_dns { features.push(Arc::new(FakeDnsFeature(holder.clone()))); }
        Ok(Self {
            policy, stats, stats_enabled, fake_dns, features,
            api: config.api.clone(), metrics: config.metrics.clone(),
            observatory: config.observatory.clone(), burst: config.burst_observatory.clone(),
        })
    }

    pub fn outbound_dialer(&mut self, protocol: &str, stream: Option<&super::StreamSettingsConfig>) -> Result<Option<Arc<dyn crate::transport::internet::dialer::Dialer>>> {
        let Some(stream) = stream.filter(|stream| matches!(stream.network.as_deref(), Some("kcp" | "mkcp"))) else { return Ok(None); };
        if !matches!(protocol.to_ascii_lowercase().as_str(), "vless" | "vmess" | "trojan" | "socks" | "http") {
            return Err(Error::Unsupported(format!("KCP base transport is not implemented for {}", protocol)));
        }
        let cancellation = tokio_util::sync::CancellationToken::new();
        let dialer = crate::transport::internet::kcp::dialer::ConfiguredKcpDialer::new(stream.kcp_settings.clone().unwrap_or_default(), cancellation.clone())?;
        self.features.push(Arc::new(KcpLifecycle(cancellation)));
        Ok(Some(Arc::new(dialer)))
    }

    pub fn wire(&mut self, outbounds: &mut HashMap<String, Arc<dyn OutboundHandler>>) -> Result<Option<Arc<crate::app::observatory::Observatory>>> {
        let mut primary = None;
        let mut burst_state = None;
        if let Some(config) = self.observatory.take() {
            let probe = Arc::new(probes::ProbeFeature::observatory(config, outbounds.clone())?);
            primary = Some(probe.state.clone());
            self.features.push(probe);
        }
        if let Some(config) = self.burst.take() {
            let probe = Arc::new(probes::ProbeFeature::burst(config, outbounds.clone())?);
            burst_state = Some(probe.state.clone());
            self.features.push(probe);
        }
        if self.api.is_some() || self.metrics.is_some() {
            let services = Arc::new(services::RootServices::new(self.stats.clone(), self.stats_enabled, primary.clone().or(burst_state)));
            if let Some(config) = self.api.take() {
                let feature = services::ServiceFeature::api(config, services.clone());
                outbounds.insert(feature.tag().into(), feature.outbound());
                self.features.push(Arc::new(feature));
            }
            if let Some(config) = self.metrics.take() {
                let feature = services::ServiceFeature::metrics(config, services)?;
                outbounds.insert(feature.tag().into(), feature.outbound());
                self.features.push(Arc::new(feature));
            }
        }
        Ok(primary)
    }
}

struct FakeDnsFeature(#[allow(dead_code)] Arc<crate::app::dns::fakedns::FakeDnsHolder>);
impl Feature for FakeDnsFeature { fn feature_type(&self) -> &'static str { TYPE_FAKE_DNS } }

fn build_fake_dns(value: Option<&serde_json::Value>) -> Result<Option<Arc<crate::app::dns::fakedns::FakeDnsHolder>>> {
    let Some(value) = value else { return Ok(None); };
    let pool = if let Some(pools) = value.as_array() {
        if pools.len() != 1 { return Err(Error::Unsupported("root FakeDNS requires one IPv4 pool; multiple/IPv6 pools are not implemented".into())); }
        &pools[0]
    } else { value };
    let pool_size = pool["poolSize"].as_i64().unwrap_or(0);
    if pool_size > 0 { return Err(Error::Unsupported("root FakeDNS poolSize/LRU limits are not implemented".into())); }
    let cidr = pool["ipPool"].as_str().unwrap_or("");
    Ok(Some(Arc::new(crate::app::dns::fakedns::FakeDnsHolder::new(cidr)?)))
}

struct KcpLifecycle(tokio_util::sync::CancellationToken);
impl Feature for KcpLifecycle {
    fn feature_type(&self) -> &'static str { "kcpDialer" }
    fn close(&self) -> Result<()> { self.0.cancel(); Ok(()) }
}
impl Drop for KcpLifecycle { fn drop(&mut self) { self.0.cancel(); } }
