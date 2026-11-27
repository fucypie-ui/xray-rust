pub const CONF_DIR: &str = "conf";

use std::collections::HashMap;
use crate::app::router::{DomainMatcher, IpMatcher, Router, Rule};
use crate::common::errors::{Error, Result};
use crate::common::net::{Destination, Network};
use crate::features::inbound::InboundHandler;
use crate::features::outbound::OutboundHandler;
use crate::proxy as p;
use crate::transport::internet::TlsClient;
use crate::transport::internet::reality::RealityConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub dns: Option<serde_json::Value>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub policy: Option<super::policy::PolicyConfig>,
    #[serde(default)]
    pub api: Option<super::api::ApiConfig>,
    #[serde(default)]
    pub metrics: Option<super::metrics::MetricsConfig>,
    #[serde(default)]
    pub stats: Option<serde_json::Value>,
    #[serde(default)]
    pub reverse: Option<serde_json::Value>,
    #[serde(default, rename = "fakeDns", alias = "fakedns")]
    pub fake_dns: Option<serde_json::Value>,
    #[serde(default)]
    pub observatory: Option<super::observatory::ObservatoryConfig>,
    #[serde(default, rename = "burstObservatory")]
    pub burst_observatory: Option<super::observatory::BurstObservatoryConfig>,
    #[serde(default)]
    pub version: Option<super::version::VersionConfig>,
    #[serde(default)]
    pub transport: Option<serde_json::Value>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub geodata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default)]
    pub loglevel: Option<String>,
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub tag: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub listen: Option<String>,
    pub protocol: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default)]
    pub sniffing: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub protocol: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsConfig>,
    #[serde(default)]
    pub mux: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettingsConfig {
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    #[serde(default, rename = "hysteriaSettings")]
    pub hysteria_settings: Option<serde_json::Value>,
    #[serde(default, rename = "kcpSettings")]
    pub kcp_settings: Option<crate::transport::internet::kcp::KcpConfig>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default, rename = "tlsSettings")]
    pub tls_settings: Option<TlsSettingsConfig>,
    #[serde(default, rename = "realitySettings")]
    pub reality_settings: Option<RealityConfig>,
    #[serde(default, rename = "wsSettings")]
    pub ws_settings: Option<WsSettingsConfig>,
    #[serde(default, rename = "httpupgradeSettings")]
    pub httpupgrade_settings: Option<WsSettingsConfig>,
    #[serde(default, rename = "grpcSettings")]
    pub grpc_settings: Option<serde_json::Value>,
    #[serde(default, rename = "xhttpSettings", alias = "splithttpSettings")]
    pub xhttp_settings: Option<crate::transport::internet::SplitHttpConfig>,
    #[serde(default)]
    pub finalmask: Option<FinalmaskConfigJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalmaskConfigJson {
    #[serde(default)]
    pub quic: Option<serde_json::Value>,
    #[serde(default)]
    pub tcp: Option<Vec<FinalmaskLayerJson>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalmaskLayerJson {
    #[serde(rename = "type")]
    pub mask_type: String,
    #[serde(default)]
    pub settings: Option<FinalmaskSettingsJson>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinalmaskSettingsJson {
    #[serde(default)]
    pub packets: Option<String>,
    #[serde(default)]
    pub length: Option<serde_json::Value>,
    #[serde(default)]
    pub delay: Option<serde_json::Value>,
    #[serde(default)]
    pub interval: Option<serde_json::Value>,
    #[serde(default)]
    pub lengths: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub delays: Option<Vec<serde_json::Value>>,
    #[serde(default, rename = "maxSplit", alias = "max_split")]
    pub max_split: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettingsConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, rename = "heartbeatPeriod")]
    pub heartbeat_period: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsCertificateConfig {
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    #[serde(default, rename = "certificateFile")]
    pub certificate_file: Option<String>,
    #[serde(default, rename = "keyFile")]
    pub key_file: Option<String>,
    #[serde(default)]
    pub certificate: Option<Vec<String>>,
    #[serde(default)]
    pub key: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSettingsConfig {
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    #[serde(default, rename = "serverName")]
    pub server_name: Option<String>,
    #[serde(default, rename = "allowInsecure")]
    pub allow_insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub certificates: Option<Vec<TlsCertificateConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default, rename = "domainStrategy")]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub rules: Option<Vec<RuleConfig>>,
    #[serde(default)]
    pub balancers: Option<Vec<BalancerRuleConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerStrategyConfig {
    #[serde(default, rename = "type")]
    pub strategy_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerRuleConfig {
    pub tag: String,
    #[serde(default)]
    pub selector: Vec<String>,
    #[serde(default)]
    pub strategy: Option<BalancerStrategyConfig>,
    #[serde(default, rename = "fallbackTag")]
    pub fallback_tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default, rename = "type")]
    pub rule_type: Option<String>,
    #[serde(default, rename = "ruleTag")]
    pub rule_tag: Option<String>,
    #[serde(default, rename = "outboundTag")]
    pub outbound_tag: String,
    #[serde(default, rename = "balancerTag")]
    pub balancer_tag: Option<String>,
    #[serde(default, rename = "inboundTag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(default, alias = "domains")]
    pub domain: Option<Vec<String>>,
    #[serde(default)]
    pub ip: Option<Vec<String>>,
    #[serde(default, rename = "sourceIP", alias = "source")]
    pub source_ip: Option<Vec<String>>,
    #[serde(default)]
    pub port: Option<serde_json::Value>,
    #[serde(default, rename = "sourcePort")]
    pub source_port: Option<serde_json::Value>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub protocol: Option<Vec<String>>,
    #[serde(default)]
    pub user: Option<Vec<String>>,
    #[serde(default)]
    pub process: Option<Vec<String>>,
    #[serde(default, rename = "localOS")]
    pub local_os: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub experiments: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub testpre: Option<u32>,
    #[serde(default, rename = "testpreIdle")]
    pub testpre_idle: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTargetConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiServerSettings {
    #[serde(default)]
    pub vnext: Vec<ServerTargetConfig>,
    #[serde(default)]
    pub servers: Vec<ServerTargetConfig>,
    #[serde(default)]
    pub clients: Vec<UserConfig>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub experiments: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub testpre: Option<u32>,
    #[serde(default, rename = "testpreIdle")]
    pub testpre_idle: Option<u32>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Option<Vec<crate::proxy::vless::inbound::Fallback>>,
}

impl MultiServerSettings {
    fn normalize_flat_outbound(&mut self) {
        let Some(addr) = self.address.as_ref().filter(|a| !a.is_empty()) else { return; };
        let base = |users| ServerTargetConfig {
            address: Some(addr.clone()), port: self.port, users,
            password: self.password.clone(), method: self.method.clone(),
        };
        if self.vnext.is_empty() && let Some(ref id) = self.id && !id.is_empty() {
            self.vnext.push(base(vec![UserConfig {
                id: id.clone(), password: self.password.clone(), level: self.level,
                security: self.security.clone(), experiments: self.experiments.clone(), email: self.email.clone(),
                flow: self.flow.clone(), testpre: self.testpre, testpre_idle: self.testpre_idle,
            }]));
        }
        if self.servers.is_empty() { self.servers.push(base(Vec::new())); }
    }
}

fn parse_i64_range_val(val: &serde_json::Value, def_min: i64, def_max: i64) -> (i64, i64) {
    match val {
        serde_json::Value::Number(n) => {
            let v = n.as_i64().unwrap_or(def_min);
            (v, v)
        }
        serde_json::Value::String(s) => {
            if let Some((a, b)) = s.split_once('-') {
                (a.trim().parse().unwrap_or(def_min), b.trim().parse().unwrap_or(def_max))
            } else if let Ok(v) = s.trim().parse() {
                (v, v)
            } else {
                (def_min, def_max)
            }
        }
        serde_json::Value::Object(obj) => {
            let from = obj.get("from").and_then(|v| v.as_i64()).unwrap_or(def_min);
            let to = obj.get("to").and_then(|v| v.as_i64()).unwrap_or(from);
            (from, to)
        }
        _ => (def_min, def_max),
    }
}

fn build_fragment_from_settings(s: &FinalmaskSettingsJson) -> crate::transport::internet::finalmask::fragment::Config {
    let mut cfg = crate::transport::internet::finalmask::fragment::Config::default();
    match s.packets.as_deref().map(str::trim).unwrap_or("") {
        "" => { cfg.packets_from = 0; cfg.packets_to = 0; }
        p if p.eq_ignore_ascii_case("tlshello") => { cfg.packets_from = 0; cfg.packets_to = 1; }
        p => {
            if let Some((from_str, to_str)) = p.split_once('-') {
                cfg.packets_from = from_str.trim().parse().unwrap_or(1);
                cfg.packets_to = to_str.trim().parse().unwrap_or(cfg.packets_from);
            } else if let Ok(v) = p.parse() {
                cfg.packets_from = v;
                cfg.packets_to = v;
            }
        }
    }
    if let Some(ref list) = s.lengths && !list.is_empty() {
        for item in list {
            let (lo, hi) = parse_i64_range_val(item, 50, 100);
            cfg.lengths_min.push(lo);
            cfg.lengths_max.push(hi);
        }
        cfg.length_min = cfg.lengths_min[0];
        cfg.length_max = cfg.lengths_max[0];
    } else if let Some(ref l) = s.length {
        let (lo, hi) = parse_i64_range_val(l, 50, 100);
        cfg.length_min = lo;
        cfg.length_max = hi;
        cfg.lengths_min.push(lo);
        cfg.lengths_max.push(hi);
    }
    if let Some(ref list) = s.delays && !list.is_empty() {
        for item in list {
            let (lo, hi) = parse_i64_range_val(item, 0, 0);
            cfg.delays_min.push(lo);
            cfg.delays_max.push(hi);
        }
        cfg.delay_min = cfg.delays_min[0];
        cfg.delay_max = cfg.delays_max[0];
    } else if let Some(d) = s.delay.as_ref().or(s.interval.as_ref()) {
        let (lo, hi) = parse_i64_range_val(d, 0, 0);
        cfg.delay_min = lo;
        cfg.delay_max = hi;
        cfg.delays_min.push(lo);
        cfg.delays_max.push(hi);
    }
    if let Some(ref ms) = s.max_split {
        let (lo, hi) = parse_i64_range_val(ms, 0, 0);
        cfg.max_split_min = lo;
        cfg.max_split_max = hi;
    }
    cfg
}

fn parse_fragment_config(fm: &FinalmaskConfigJson) -> Option<crate::transport::internet::finalmask::fragment::Config> {
    let tcp_layers = fm.tcp.as_ref()?;
    for layer in tcp_layers {
        if layer.mask_type.eq_ignore_ascii_case("fragment") {
            let cfg = match layer.settings {
                Some(ref s) => build_fragment_from_settings(s),
                None => crate::transport::internet::finalmask::fragment::Config::default(),
            };
            return Some(cfg);
        }
    }
    None
}

fn parse_multi_settings(raw: Option<serde_json::Value>, proto: &str) -> Result<MultiServerSettings> {
    let mut s: MultiServerSettings = serde_json::from_value(raw.unwrap_or_default())
        .map_err(|e| Error::Config(format!("Invalid {} outbound settings: {}", proto, e)))?;
    s.normalize_flat_outbound();
    Ok(s)
}

fn build_socks_inbound(tag: &str, raw: Option<serde_json::Value>) -> Result<Arc<dyn InboundHandler>> {
    let settings: super::socks::SocksServerConfig = serde_json::from_value(
        raw.filter(|value| !value.is_null()).unwrap_or_else(|| serde_json::json!({})),
    ).map_err(|error| Error::Config(format!("Invalid SOCKS inbound settings: {}", error)))?;
    let server = if settings.auth.as_deref() == Some("password") {
        // An absent/empty account list must remain password-only and reject all
        // logins, rather than accidentally becoming an unauthenticated proxy.
        p::socks::Server::with_auth(tag, settings.accounts)
    } else {
        p::socks::Server::new(tag)
    };
    Ok(Arc::new(server))
}

fn build_socks_outbound(tag: &str, raw: Option<serde_json::Value>, dialer: Option<Arc<dyn crate::transport::internet::dialer::Dialer>>) -> Result<Arc<dyn OutboundHandler>> {
    let settings: super::socks::SocksClientConfig = serde_json::from_value(
        raw.filter(|value| !value.is_null()).unwrap_or_else(|| serde_json::json!({})),
    ).map_err(|error| Error::Config(format!("Invalid SOCKS outbound settings: {}", error)))?;
    let server = settings.into_server()?;
    let address = server.address.as_deref()
        .ok_or_else(|| Error::Config("SOCKS server address is required".into()))?;
    let destination = Destination::from_str(&format!("{}:{}", address, server.port))?;
    let client = match server.users.as_deref().and_then(|users| users.first()) {
        Some(account) => p::socks::Client::with_auth(tag, destination, &account.username, &account.password),
        None => p::socks::Client::new(tag, destination),
    };
    let client = if let Some(dialer) = dialer { client.with_dialer(dialer) } else { client };
    Ok(Arc::new(client))
}

fn sub_tag_for(tag: &str, len: usize, idx: usize) -> String {
    if len == 1 { tag.to_string() } else { format!("{}#{}", tag, idx) }
}

fn build_optional_tls(ss: Option<&StreamSettingsConfig>, addr: &str) -> Result<(Option<TlsClient>, Option<String>)> {
    let Some(ss) = ss else { return Ok((None, None)) };
    if ss.security.as_deref() != Some("tls") { return Ok((None, None)); }
    let cfg = ss.tls_settings.clone().unwrap_or_default();
    let sni = cfg.server_name.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| addr.to_string());
    let alpn = cfg.alpn.unwrap_or_default().into_iter().map(String::into_bytes).collect();
    let client = TlsClient::new_with_fingerprint(
        &sni,
        cfg.allow_insecure.unwrap_or(false),
        alpn,
        cfg.fingerprint.as_deref().unwrap_or(""),
    )?;
    Ok((Some(client), Some(sni)))
}

fn parse_json_str_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn parse_sniffing(
    v: Option<&serde_json::Value>,
    require_enabled: bool,
) -> Option<crate::common::session::SniffingRequest> {
    let v = v?;
    let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
    if require_enabled && !enabled { return None; }
    Some(crate::common::session::SniffingRequest {
        enabled,
        metadata_only: v.get("metadataOnly").and_then(|b| b.as_bool()).unwrap_or(false),
        route_only: v.get("routeOnly").and_then(|b| b.as_bool()).unwrap_or(false),
        override_destination_for_protocol: parse_json_str_array(v, "destOverride"),
        exclude_for_domain: parse_json_str_array(v, "domainsExcluded"),
    })
}

fn parse_client_uuids(clients: &[UserConfig]) -> Result<Vec<Uuid>> {
    clients.iter().map(|c| Uuid::from_str(&c.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))).collect()
}

fn wrap_pingora_multi_outbound(
    tag: &str,
    handlers: Vec<Arc<dyn OutboundHandler>>,
    labels: Vec<String>,
) -> Result<Arc<dyn OutboundHandler>> {
    if handlers.len() == 1 { return Ok(handlers.into_iter().next().unwrap()); }
    let lb = Arc::new(crate::app::pingora_bridge::PingoraUpstreamBalancer::from_labels_ketama(labels)?);
    Ok(Arc::new(crate::app::pingora_bridge::PingoraPooledOutbound::new(
        tag,
        handlers,
        Some(lb),
        32,
        std::time::Duration::from_secs(60),
    )))
}

pub struct BuiltConfig {
    pub inbounds: Vec<(SocketAddr, Arc<dyn InboundHandler>)>,
    pub tun_devices: Vec<Arc<p::tun::WindowsTunDevice>>,
    pub outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    pub router: Router,
    pub default_outbound_tag: Option<String>,
    pub policy_manager: Arc<crate::app::policy::Instance>,
    pub stats_manager: Arc<crate::features::stats::DefaultStatsManager>,
    pub stats_enabled: bool,
    pub fake_dns: Option<Arc<crate::app::dns::fakedns::FakeDnsHolder>>,
    pub features: Vec<Arc<dyn crate::features::feature::Feature>>,
}

impl Config {
    /// Match conf.Config.Override: root sections replace, handlers update by
    /// tag, and new outbounds prepend unless the source name contains "tail".
    pub fn override_with(&mut self, next: Self, filename: &str) {
        macro_rules! replace_some {
            ($($field:ident),* $(,)?) => { $(if next.$field.is_some() { self.$field = next.$field; })* };
        }
        replace_some!(log, dns, routing, policy, api, metrics, stats, reverse,
            fake_dns, observatory, burst_observatory, version, transport, geodata);
        self.env.extend(next.env);
        for inbound in next.inbounds {
            if let Some(existing) = self.inbounds.iter_mut().find(|item| item.tag.as_deref().unwrap_or("") == inbound.tag.as_deref().unwrap_or("")) {
                *existing = inbound;
            } else { self.inbounds.push(inbound); }
        }
        let mut prepended = Vec::new();
        for outbound in next.outbounds {
            if let Some(existing) = self.outbounds.iter_mut().find(|item| item.tag.as_deref().unwrap_or("") == outbound.tag.as_deref().unwrap_or("")) {
                *existing = outbound;
            } else if filename.to_lowercase().contains("tail") { self.outbounds.push(outbound); }
            else { prepended.push(outbound); }
        }
        prepended.append(&mut self.outbounds);
        self.outbounds = prepended;
    }

    pub fn build(self) -> Result<BuiltConfig> {
        let mut runtime = super::runtime::RootRuntime::new(&self)?;
        let policy_manager = runtime.policy.clone();
        let mut inbounds = Vec::new();
        let mut tun_devices = Vec::new();
        let mut outbounds = HashMap::new();
        let mut default_outbound_tag = None;
        let mut dns_client = build_dns_client(self.dns.as_ref());
        if let Some(holder) = &runtime.fake_dns { dns_client.set_fakedns_holder(holder.clone()); }
        let dns_client = Arc::new(dns_client);
        for (i, mut out_cfg) in self.outbounds.into_iter().enumerate() {
            let base_dialer = runtime.outbound_dialer(&out_cfg.protocol, out_cfg.stream_settings.as_ref())?;
            if super::grpc_runtime::selected(out_cfg.stream_settings.as_ref()) {
                if out_cfg.mux.as_ref().is_some_and(|mux| !mux.is_null() && mux.get("enabled").and_then(serde_json::Value::as_bool) != Some(false)) {
                    return Err(Error::Unsupported("gRPC outbound mux settings are not implemented".into()));
                }
                super::grpc_runtime::validate_protocol_options(&out_cfg.protocol, out_cfg.settings.as_ref())?;
                if let Some(stream) = out_cfg.stream_settings.as_mut() { super::grpc_runtime::consume_security(stream); }
            }
            let tag = out_cfg.tag.unwrap_or_else(|| format!("outbound-{}", i));
            if default_outbound_tag.is_none() { default_outbound_tag = Some(tag.clone()); }
            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol.to_lowercase().as_str() {
                "freedom" | "direct" => {
                    let mut h = p::freedom::Handler::new(&tag);
                    if let Some(ref st) = out_cfg.settings {
                        if let Some(ds) = st.get("targetStrategy").or_else(|| st.get("domainStrategy")).and_then(|v| v.as_str()) {
                            h = h.with_strategy(p::freedom::DomainStrategy::parse(ds));
                        }
                        if let Some(red) = st.get("redirect").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                            && let Ok(dest) = Destination::from_str(red)
                        {
                            h = h.with_destination_override(dest);
                        }
                        if let Some(frag_val) = st.get("fragment")
                            && let Ok(fs) = serde_json::from_value::<FinalmaskSettingsJson>(frag_val.clone())
                        {
                            h = h.with_fragment(build_fragment_from_settings(&fs));
                        }
                    }
                    if let Some(f_cfg) = out_cfg.stream_settings.as_ref().and_then(|ss| ss.finalmask.as_ref()).and_then(parse_fragment_config) {
                        h = h.with_fragment(f_cfg);
                    }
                    Arc::new(h)
                }
                "blackhole" | "block" => {
                    let resp_type = out_cfg
                        .settings
                        .as_ref().and_then(|s| s.get("response")).and_then(|r| r.get("type")).and_then(|t| t.as_str())
                        .map(|t| match t.to_lowercase().as_str() {
                            "http" | "http403" => p::blackhole::ResponseType::Http403,
                            "http500" => p::blackhole::ResponseType::Http500,
                            _ => p::blackhole::ResponseType::None,
                        })
                        .unwrap_or(p::blackhole::ResponseType::None);
                    Arc::new(p::blackhole::Handler::with_response(&tag, resp_type))
                }
                "vless" => build_vless_outbound(&tag, out_cfg.settings, out_cfg.stream_settings, base_dialer)?,
                "trojan" => {
                    let s = parse_multi_settings(out_cfg.settings, "Trojan")?;
                    if s.servers.is_empty() { return Err(Error::Config("Trojan servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let (tls, sni) = build_optional_tls(out_cfg.stream_settings.as_ref(), addr)?;
                        let client = p::trojan::OutboundClient::new(&sub, dest, srv.password.clone().unwrap_or_default(), tls, sni);
                        let client = if let Some(dialer) = &base_dialer { client.with_dialer(dialer.clone()) } else { client };
                        hs.push(Arc::new(client) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "shadowsocks" => {
                    if let Some(handler) = super::shadowsocks::build_2022_outbound(
                        &tag, out_cfg.settings.as_ref(), out_cfg.stream_settings.as_ref(), out_cfg.mux.as_ref(),
                    )? {
                        handler
                    } else {
                        let (hs, lbs) = super::shadowsocks::build_classic_outbound(
                            &tag, out_cfg.settings.as_ref(), out_cfg.stream_settings.as_ref(), out_cfg.mux.as_ref(), base_dialer,
                        )?;
                        wrap_pingora_multi_outbound(&tag, hs, lbs)?
                    }
                }
                "vmess" => {
                    let s = parse_multi_settings(out_cfg.settings, "VMess")?;
                    if s.vnext.len() != 1 { return Err(Error::Config("VMess settings: \"vnext\" should have one and only one member".into())); }
                    if s.vnext[0].users.len() != 1 { return Err(Error::Config("VMess vnext: \"users\" should have one and only one member".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.vnext.len()), Vec::with_capacity(s.vnext.len()));
                    for (idx, srv) in s.vnext.iter().enumerate() {
                        let user = srv.users.first().ok_or_else(|| Error::Config("VMess users is empty".into()))?;
                        let uid = Uuid::from_str(&user.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(443);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.vnext.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let (tls, sni) = build_optional_tls(out_cfg.stream_settings.as_ref(), addr)?;
                        let security = match user.security.to_ascii_lowercase().as_str() {
                            "aes-128-gcm" => "aes-128-gcm", "chacha20-poly1305" => "chacha20-poly1305", _ => "auto",
                        };
                        let options = 13 | if user.experiments.contains("AuthenticatedLength") { 16 } else { 0 };
                        let client = p::vmess::OutboundClient::new(&sub, dest, uid, tls, sni)
                            .with_security(security)?.with_options(options)
                            .with_termination_signal(!user.experiments.contains("NoTerminationSignal"));
                        let client = if let Some(dialer) = &base_dialer { client.with_dialer(dialer.clone()) } else { client };
                        hs.push(Arc::new(client) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "socks" => build_socks_outbound(&tag, out_cfg.settings, base_dialer)?,
                "http" => {
                    let s = parse_multi_settings(out_cfg.settings, "HTTP")?;
                    if s.servers.is_empty() { return Err(Error::Config("HTTP servers list is empty".into())); }
                    let (mut hs, mut lbs) = (Vec::with_capacity(s.servers.len()), Vec::with_capacity(s.servers.len()));
                    for (idx, srv) in s.servers.iter().enumerate() {
                        let addr = srv.address.as_deref().unwrap_or("127.0.0.1");
                        let port = srv.port.unwrap_or(8080);
                        let dest = Destination::from_str(&format!("{}:{}", addr, port))?;
                        let sub = sub_tag_for(&tag, s.servers.len(), idx);
                        lbs.push(format!("{}:{}", addr, port));
                        let c = match srv.users.first() {
                            Some(u) => p::http::client::HttpClient::with_auth(&sub, dest, &u.id, u.password.as_deref().unwrap_or("")),
                            None => p::http::client::HttpClient::new(&sub, dest),
                        };
                        let c = if let Some(dialer) = &base_dialer { c.with_dialer(dialer.clone()) } else { c };
                        hs.push(Arc::new(c) as Arc<dyn OutboundHandler>);
                    }
                    wrap_pingora_multi_outbound(&tag, hs, lbs)?
                }
                "wireguard" => {
                    let wg_cfg: p::wireguard::WireGuardConfig =
                        serde_json::from_value(out_cfg.settings.unwrap_or_default()).map_err(
                            |e| Error::Config(format!("Invalid WireGuard outbound settings: {}", e)),
                        )?;
                    Arc::new(p::wireguard::Client::try_new(&tag, wg_cfg)?)
                }
                "hysteria" => super::hysteria_runtime::client(&tag, out_cfg.settings, out_cfg.stream_settings.as_ref())?,
                "dns" => Arc::new(p::DnsOutbound::new(tag.clone(), dns_client.clone())),
                other => { return Err(Error::Unsupported(format!("Outbound protocol '{}' is not supported", other))); }
            };
            outbounds.insert(tag, handler);
        }
        for (i, in_cfg) in self.inbounds.into_iter().enumerate() {
            let tag = in_cfg.tag.unwrap_or_else(|| format!("inbound-{}", i));
            let proto = in_cfg.protocol.to_lowercase();
            super::grpc_runtime::validate_role(&proto, in_cfg.stream_settings.as_ref(), true)?;
            if super::grpc_runtime::selected(in_cfg.stream_settings.as_ref()) {
                super::grpc_runtime::validate_protocol_options(&proto, in_cfg.settings.as_ref())?;
            }
            let session_settings = in_cfg.settings.clone();
            if proto == "tun" {
                let st = in_cfg.settings.as_ref();
                let tun_name = st.and_then(|s| s.get("name")?.as_str()).unwrap_or("xray_tun");
                let mtu = st.and_then(|s| s.get("mtu").or_else(|| s.get("MTU"))?.as_u64()).unwrap_or(1500) as usize;
                let mut gateway_v4: ipnet::Ipv4Net = "172.18.0.1/30".parse().unwrap();
                let mut gateway_v6: Option<ipnet::Ipv6Net> = None;
                if let Some(gws) = st.and_then(|s| s.get("gateway")?.as_array()) {
                    for gw in gws.iter().filter_map(|v| v.as_str()) {
                        if let Ok(net) = gw.parse::<ipnet::Ipv4Net>() {
                            gateway_v4 = net;
                        } else if let Ok(net) = gw.parse::<ipnet::Ipv6Net>() {
                            gateway_v6 = Some(net);
                        }
                    }
                }
                let (mut route_all, mut routes) = (false, Vec::new());
                if let Some(rt) = st.and_then(|s| s.get("autoSystemRoutingTable")) {
                    if let Some(arr) = rt.as_array() {
                        for s in arr.iter().filter_map(|x| x.as_str()) {
                            if s == "0.0.0.0/0" || s == "::/0" {
                                route_all = true;
                            } else if let Ok(net) = s.parse::<ipnet::IpNet>() {
                                routes.push(net);
                            }
                        }
                    } else if rt.as_bool() == Some(true) {
                        route_all = true;
                    }
                }
                tun_devices.push(Arc::new(p::tun::TunRunner::new(p::tun::TunConfig {
                    enable: true,
                    name: tun_name.to_string(),
                    device_id: tun_name.to_string(),
                    route_all,
                    routes,
                    gateway: gateway_v4,
                    gateway_v6,
                    mtu,
                    so_mark: None,
                    dns_hijack: false,
                    sniffing: parse_sniffing(in_cfg.sniffing.as_ref(), false),
                    auto_route: route_all,
                    strict_route: true,
                })));
                continue;
            }
            let listen_ip = in_cfg.listen.as_deref().unwrap_or("0.0.0.0");
            let port_val = in_cfg.port.unwrap_or(0);
            if port_val == 0 { continue; }
            let bind_addr: SocketAddr = format!("{}:{}", listen_ip, port_val)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address '{}:{}': {}", listen_ip, port_val, e)))?;
            let handler: Arc<dyn InboundHandler> = match proto.as_str() {
                "socks" | "socks5" => build_socks_inbound(&tag, in_cfg.settings)?,
                "wireguard" => {
                    let config = serde_json::from_value(in_cfg.settings.unwrap_or_else(|| serde_json::json!({})))
                        .map_err(|error| Error::Config(format!("Invalid WireGuard inbound settings: {}", error)))?;
                    Arc::new(p::wireguard::WireGuardInbound::try_new(&tag, config)?)
                }
                "hysteria" => super::hysteria_runtime::server(&tag, in_cfg.settings, in_cfg.stream_settings.as_ref())?,
                "http" => Arc::new(p::http::Server::new(&tag)),
                "mixed" => Arc::new(p::mixed::Server::new(&tag)),
                "vless" => {
                    let s = parse_multi_settings(in_cfg.settings, "VLESS")?;
                    if let Some(ref dec) = s.decryption && !dec.is_empty() && !dec.eq_ignore_ascii_case("none")
                    {
                        return Err(Error::Config(format!(
                            "VLESS inbound '{}' unsupported decryption '{}': only 'none' is supported",
                            tag, dec
                        )));
                    }
                    let mut srv = p::vless::InboundServer::new(&tag, parse_client_uuids(&s.clients)?);
                    if let Some(fb) = s.fallbacks && !fb.is_empty() { srv = srv.with_fallbacks(fb); }
                    Arc::new(srv)
                }
                "trojan" => {
                    let s = parse_multi_settings(in_cfg.settings, "Trojan")?;
                    let pwds = s.clients.into_iter().filter_map(|c| c.password).collect();
                    Arc::new(p::trojan::InboundServer::new(&tag, pwds))
                }
                "shadowsocks" => {
                    if let Some(handler) = super::shadowsocks::build_2022_inbound(
                        &tag, in_cfg.settings.as_ref(), in_cfg.stream_settings.as_ref(),
                    )? {
                        handler
                    } else {
                        super::shadowsocks::build_classic_inbound(
                            &tag, in_cfg.settings.as_ref(), in_cfg.stream_settings.as_ref(),
                        )?
                    }
                }
                "dokodemo-door" | "dokodemo" => {
                    let s = parse_multi_settings(in_cfg.settings, "Dokodemo")?;
                    let dest = Destination::from_str(&format!(
                        "{}:{}",
                        s.address.as_deref().unwrap_or("127.0.0.1"),
                        s.port.unwrap_or(80)
                    ))?;
                    let net = if s.network.as_deref() == Some("udp") { Network::Udp } else { Network::Tcp };
                    Arc::new(p::dokodemo::Server::new(&tag, dest, net))
                }
                "vmess" => {
                    let s = parse_multi_settings(in_cfg.settings, "VMess")?;
                    Arc::new(p::vmess::InboundServer::new(&tag, parse_client_uuids(&s.clients)?))
                }
                other => return Err(Error::Unsupported(format!("Inbound protocol '{}' is not supported", other))),
            };
            let sniffing_req = parse_sniffing(in_cfg.sniffing.as_ref(), true);
            let handler: Arc<dyn InboundHandler> = if let Some(stream) = in_cfg.stream_settings.as_ref().filter(|stream| super::grpc_runtime::selected(Some(stream))) {
                let handler = if let Some(sniff) = sniffing_req {
                    Arc::new(crate::app::proxyman::inbound::StreamInboundHandler::new(handler, None, false, None, None).with_sniffing(sniff)) as Arc<dyn InboundHandler>
                } else { handler };
                runtime.grpc_inbound(handler, &proto, stream)?
            } else if matches!(proto.as_str(), "hysteria" | "wireguard") {
                if sniffing_req.is_some() { return Err(Error::Unsupported(format!("native {} inbound sniffing is not implemented", proto))); }
                handler
            } else if let Some(ref stream_cfg) = in_cfg.stream_settings
            {
                let security = stream_cfg.security.as_deref().unwrap_or("none").to_ascii_lowercase();
                let network = stream_cfg.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
                let tls_server = if security == "tls" {
                    let tls_cfg = stream_cfg.tls_settings.as_ref().ok_or_else(|| {
                        Error::Config(format!("Inbound '{}' has security='tls' but missing tlsSettings", tag))
                    })?;
                    let alpn: Vec<Vec<u8>> = tls_cfg
                        .alpn
                        .as_ref().map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect()).unwrap_or_default();
                    let cert_cfg = tls_cfg.certificates.as_ref().and_then(|c| c.first())
                        .ok_or_else(|| {
                            Error::Config(format!(
                                "Inbound '{}' has security='tls' but missing tlsSettings.certificates",
                                tag
                            ))
                        })?;
                    let srv = if let (Some(cert_file), Some(key_file)) = (
                        cert_cfg.certificate_file.as_deref(),
                        cert_cfg.key_file.as_deref(),
                    ) {
                        crate::transport::internet::TlsServer::from_pem_files(cert_file, key_file, alpn)?
                    } else if let (Some(cert_lines), Some(key_lines)) = (
                        cert_cfg.certificate.as_ref(),
                        cert_cfg.key.as_ref(),
                    ) {
                        let cert_pem = cert_lines.join("\n");
                        let key_pem = key_lines.join("\n");
                        crate::transport::internet::TlsServer::from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), alpn)?
                    } else {
                        return Err(Error::Config(format!(
                            "Inbound '{}' tlsSettings.certificates requires certificateFile/keyFile or certificate/key",
                            tag
                        )));
                    };
                    Some(Arc::new(srv))
                } else {
                    None
                };
                let reality_server = if security == "reality" {
                    let rc = stream_cfg.reality_settings.as_ref().ok_or_else(|| {
                        Error::Config(format!("Inbound '{}' has security='reality' but missing realitySettings", tag))
                    })?;
                    Some(Arc::new(crate::transport::internet::reality::RealityServer::new(rc)?))
                } else {
                    None
                };
                let is_xhttp = network == "xhttp" || network == "splithttp";
                let splithttp_server = if is_xhttp {
                    let x_cfg = stream_cfg.xhttp_settings.clone().unwrap_or_default();
                    Some(Arc::new(crate::transport::internet::splithttp::SplitHttpServer::new(x_cfg)))
                } else {
                    None
                };
                let is_httpupgrade = !is_xhttp && network == "httpupgrade";
                let httpupgrade_pair = if is_httpupgrade {
                    let hu = stream_cfg.httpupgrade_settings.as_ref();
                    let path = hu.and_then(|h| h.path.clone());
                    let host = hu.and_then(|h| h.host.clone());
                    Some((path, host))
                } else {
                    None
                };
                let is_ws = !is_xhttp && !is_httpupgrade && (network == "ws" || network == "websocket");
                let (ws_path, ws_host) = if is_ws {
                    let ws_cfg = stream_cfg.ws_settings.as_ref();
                    let path = ws_cfg.and_then(|w| w.path.clone());
                    let host = ws_cfg.and_then(|w| {
                        w.host.clone().or_else(|| {
                            w.headers.as_ref().and_then(|h| {
                                h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone())
                            })
                        })
                    });
                    (path, host)
                } else {
                    (None, None)
                };
                if tls_server.is_some()
                    || reality_server.is_some()
                    || is_ws || httpupgrade_pair.is_some() || splithttp_server.is_some() || sniffing_req.is_some()
                {
                    let mut wrapped = crate::app::proxyman::inbound::StreamInboundHandler::new(
                        handler, tls_server, is_ws, ws_path, ws_host,
                    );
                    if let Some(r_srv) = reality_server { wrapped = wrapped.with_reality(r_srv); }
                    if let Some((hu_path, hu_host)) = httpupgrade_pair {
                        wrapped = wrapped.with_httpupgrade(hu_path, hu_host);
                    }
                    if let Some(xhttp_srv) = splithttp_server { wrapped = wrapped.with_splithttp(xhttp_srv); }
                    if let Some(sniff) = sniffing_req { wrapped = wrapped.with_sniffing(sniff); }
                    Arc::new(wrapped)
                } else {
                    handler
                }
            } else if let Some(sniff) = sniffing_req {
                Arc::new(
                    crate::app::proxyman::inbound::StreamInboundHandler::new(handler, None, false, None, None)
                    .with_sniffing(sniff),
                )
            } else {
                handler
            };
            let handler: Arc<dyn InboundHandler> = if let Some(stream) = in_cfg.stream_settings.as_ref().filter(|stream| matches!(stream.network.as_deref(), Some("kcp" | "mkcp"))) {
                let config = stream.kcp_settings.clone().unwrap_or_default();
                config.validate()?;
                Arc::new(crate::app::proxyman::inbound::worker::KcpInboundHandler::new(handler, config))
            } else { handler };
            let handler = Arc::new(super::session::PolicyInbound::new(
                handler, policy_manager.clone(), &proto, session_settings.as_ref(),
                runtime.stats_enabled.then(|| runtime.stats.clone()),
            )?) as Arc<dyn InboundHandler>;
            inbounds.push((bind_addr, handler));
        }
        let observatory = runtime.wire(&mut outbounds)?;
        let outbound_tags: Vec<String> = outbounds.keys().cloned().collect();
        let router = build_router(self.routing, default_outbound_tag.clone(), &outbound_tags, dns_client.clone());
        let _ = observatory; // Strategies receive the same observation state below.
        runtime.features.push(dns_client.clone());
        runtime.features.push(Arc::new(router.clone()));
        dns_client.attach_routing(router.clone(), outbounds.clone());
        crate::transport::internet::tcp::dialer::init_system_dialer_dns(dns_client.clone());
        Ok(BuiltConfig {
            inbounds,
            tun_devices,
            outbounds,
            router,
            default_outbound_tag,
            policy_manager, stats_manager: runtime.stats, stats_enabled: runtime.stats_enabled,
            fake_dns: runtime.fake_dns, features: runtime.features,
        })
    }
}

fn build_vless_outbound(
    tag: &str,
    settings_val: Option<serde_json::Value>,
    stream_settings: Option<StreamSettingsConfig>,
    base_dialer: Option<Arc<dyn crate::transport::internet::dialer::Dialer>>,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = parse_multi_settings(settings_val, "VLESS")?;
    if settings.vnext.is_empty() { return Err(Error::Config("VLESS vnext is empty".into())); }
    let (mut handlers, mut lbs) = (Vec::with_capacity(settings.vnext.len()), Vec::with_capacity(settings.vnext.len()));
    for (v_idx, server) in settings.vnext.iter().enumerate() {
        let user = server.users.first().ok_or_else(|| Error::Config("VLESS users is empty".into()))?;
        let user_uuid = Uuid::from_str(&user.id).map_err(|e| Error::Config(format!("Invalid UUID: {}", e)))?;
        let addr_str = server.address.as_deref().unwrap_or("127.0.0.1");
        let port_val = server.port.unwrap_or(443);
        let dest = Destination::from_str(&format!("{}:{}", addr_str, port_val))?;
        let sub_tag = sub_tag_for(tag, settings.vnext.len(), v_idx);
        lbs.push(format!("{}:{}", addr_str, port_val));
        let (mut tls_client, mut tls_sni, mut reality_client) = (None, None, None);
        let (mut ws_path, mut ws_host, mut ws_headers, mut ws_heartbeat) = (None, None, HashMap::new(), 0u32);
        let (mut xhttp_cfg, mut httpupgrade_cfg, mut fragment_cfg) = (None, None, None);
        if let Some(ref ss) = stream_settings {
            fragment_cfg = ss.finalmask.as_ref().and_then(parse_fragment_config);
            let net = ss.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
            let is_xhttp = matches!(net.as_str(), "xhttp" | "splithttp") || ss.xhttp_settings.is_some();
            if is_xhttp { xhttp_cfg = Some(ss.xhttp_settings.clone().unwrap_or_default()); }
            let is_hu = !is_xhttp && (net == "httpupgrade" || ss.httpupgrade_settings.is_some());
            if is_hu {
                let hu = ss.httpupgrade_settings.as_ref();
                let path = hu.and_then(|h| h.path.as_deref()).map(str::trim).filter(|p| !p.is_empty()).unwrap_or("/").to_string();
                let host = hu.and_then(|h| h.host.clone()).filter(|h| !h.trim().is_empty());
                let headers = hu.and_then(|h| h.headers.clone()).unwrap_or_default();
                httpupgrade_cfg = Some((path, host, headers));
            }
            let is_ws = !is_xhttp && !is_hu && (matches!(net.as_str(), "ws" | "websocket") || ss.ws_settings.is_some());
            if is_ws {
                let w = ss.ws_settings.as_ref();
                ws_heartbeat = w.and_then(|x| x.heartbeat_period).unwrap_or(0);
                let p = w.and_then(|x| x.path.as_deref()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("/");
                ws_path = Some(p.to_string());
                if let Some(w) = w {
                    ws_host = w.host.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
                    if let Some(headers) = &w.headers {
                        ws_headers = headers.clone();
                        if ws_host.is_none() {
                            ws_host = headers
                                .iter()
                                .find(|(k, v)| k.eq_ignore_ascii_case("host") && !v.trim().is_empty())
                                .map(|(_, v)| v.trim().to_string());
                        }
                    }
                }
            }
            match ss.security.as_deref() {
                Some("tls") => {
                    let tls_cfg = ss.tls_settings.clone().unwrap_or_default();
                    let sni = tls_cfg
                        .server_name
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| ws_host.clone().filter(|s| !s.trim().is_empty()))
                        .unwrap_or_else(|| addr_str.to_string());
                    let alpn = tls_cfg.alpn.unwrap_or_default().into_iter().map(String::into_bytes).collect();
                    tls_client = Some(TlsClient::new_with_fingerprint(
                        &sni,
                        tls_cfg.allow_insecure.unwrap_or(false),
                        alpn,
                        tls_cfg.fingerprint.as_deref().unwrap_or(""),
                    )?);
                    tls_sni = Some(sni.clone());
                    ws_host.get_or_insert(sni);
                }
                Some("reality") if ss.reality_settings.is_some() => {
                    let rc = ss.reality_settings.as_ref().unwrap();
                    let sni = rc
                        .server_name
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| rc.server_names.first().map(String::as_str)).unwrap_or(addr_str);
                    let pub_key = rc.public_key.as_deref().ok_or_else(|| {
                        Error::Config(format!("Outbound '{}' has security='reality' but missing publicKey/password", tag))
                    })?;
                    let short_id = rc.short_id.as_deref().or_else(|| rc.short_ids.first().map(String::as_str)).unwrap_or("");
                    tls_sni = Some(sni.to_string());
                    reality_client = Some(crate::transport::internet::reality::RealityClient::new(sni, pub_key, short_id)?.with_spider_path(rc.spider_x.as_deref().unwrap_or("/"))?);
                }
                _ => {}
            }
            if is_ws && ws_host.is_none() { ws_host = tls_sni.clone().or_else(|| Some(addr_str.to_string())); }
        }
        let is_ws_tls = ws_path.is_some() && (tls_client.is_some() || reality_client.is_some());
        let mut client = p::vless::OutboundClient::new(&sub_tag, dest, user_uuid, tls_client, tls_sni, ws_path, ws_host)
            .with_ws_headers(ws_headers).with_ws_heartbeat(ws_heartbeat);
        if let Some(dialer) = &base_dialer { client = client.with_dialer(dialer.clone()); }
        if let Some(ref flow) = user.flow && !flow.is_empty()
        { client = client.with_flow(flow.clone()); }
        let testpre = user.testpre.unwrap_or_else(|| if is_ws_tls && !client.has_ws_early_data() { 3 } else { 0 });
        if testpre > 0 { client = client.with_testpre_idle(testpre, user.testpre_idle.unwrap_or(45)); }
        if let Some(rc) = reality_client { client = client.with_reality(rc); }
        if let Some(f_cfg) = fragment_cfg { client = client.with_fragment(f_cfg); }
        if let Some(x_cfg) = xhttp_cfg { client = client.with_splithttp(x_cfg); }
        if let Some((hu_path, hu_host, hu_headers)) = httpupgrade_cfg {
            client = client.with_httpupgrade(hu_path, hu_host, hu_headers);
        }
        handlers.push(Arc::new(client) as Arc<dyn OutboundHandler>);
    }
    wrap_pingora_multi_outbound(tag, handlers, lbs)
}

fn parse_port_value(port_val: serde_json::Value, ports: &mut Vec<u16>, ranges: &mut Vec<(u16, u16)>) {
    let ports_str = match port_val {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s,
        _ => String::new(),
    };
    for part in ports_str.split(',').map(str::trim) {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if s <= e { ranges.push((s, e)); } else { ranges.push((e, s)); }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
}

fn build_router(
    routing: Option<RoutingConfig>,
    default_outbound_tag: Option<String>,
    outbound_tags: &[String],
    dns_client: Arc<crate::app::dns::DnsClient>,
) -> Router {
    let domain_strategy = routing
        .as_ref()
        .and_then(|r| r.domain_strategy.as_deref())
        .map(crate::app::router::router::DomainStrategy::parse)
        .unwrap_or_default();
    let balancers_cfg = routing.as_ref().and_then(|r| r.balancers.clone()).unwrap_or_default();
    let rules = build_routing_rules(routing);
    let mut router = Router::new(rules, default_outbound_tag);
    router.set_domain_strategy(domain_strategy);
    router.set_ip_resolver(Arc::new(move |domain: &str| dns_client.lookup_cached_or_hosts(domain)));
    for b_cfg in balancers_cfg {
        if b_cfg.tag.is_empty() || b_cfg.selector.is_empty() { continue; }
        let strategy: Arc<dyn crate::app::router::balancing::BalancingStrategy> =
            match b_cfg.strategy.as_ref().and_then(|s| s.strategy_type.as_deref()).unwrap_or("random").to_ascii_lowercase().as_str() {
                "roundrobin" => Arc::new(crate::app::router::balancing::RoundRobinStrategy::new(b_cfg.fallback_tag.clone())),
                _ => Arc::new(crate::app::router::balancing::RandomStrategy::new()),
            };
        let balancer = crate::app::router::balancing::Balancer::with_candidates(
            &b_cfg.tag,
            b_cfg.selector,
            outbound_tags.to_vec(),
            strategy,
            b_cfg.fallback_tag,
        );
        router.add_balancer(b_cfg.tag, Arc::new(balancer));
    }
    router
}

fn build_routing_rules(routing: Option<RoutingConfig>) -> Vec<Rule> {
    let mut rules = Vec::new();
    let Some(rule_configs) = routing.and_then(|r| r.rules) else { return rules };
    for r_cfg in rule_configs {
        if r_cfg.outbound_tag.is_empty() && r_cfg.balancer_tag.as_deref().unwrap_or("").is_empty() {
            continue;
        }
        let mut rule = Rule::new(&r_cfg.outbound_tag);
        rule.balancer_tag = r_cfg.balancer_tag.filter(|s| !s.is_empty());
        if let Some(in_tags) = r_cfg.inbound_tag { rule.inbound_tags = in_tags; }
        if let Some(domains) = r_cfg.domain {
            rule.domain_matchers.extend(domains.iter().map(|d| DomainMatcher::parse(d)));
        }
        if let Some(ips) = r_cfg.ip {
            let had_ips = !ips.is_empty();
            for ip_str in ips {
                if let Some(m) = IpMatcher::parse(&ip_str) {
                    rule.ip_matchers.push(m);
                } else {
                    tracing::warn!("Ignoring unrecognized routing IP matcher: '{}'", ip_str);
                }
            }
            if had_ips && rule.ip_matchers.is_empty() {
                tracing::warn!("Skipping routing rule for '{}' because none of its IP matchers could be parsed", rule.tag);
                continue;
            }
        }
        if let Some(src_ips) = r_cfg.source_ip {
            let had_src_ips = !src_ips.is_empty();
            for ip_str in src_ips {
                if let Some(m) = IpMatcher::parse(&ip_str) {
                    rule.source_ip_matchers.push(m);
                }
            }
            if had_src_ips && rule.source_ip_matchers.is_empty() {
                continue;
            }
        }
        if let Some(port_val) = r_cfg.port {
            parse_port_value(port_val, &mut rule.ports, &mut rule.port_ranges);
        }
        if let Some(src_port_val) = r_cfg.source_port {
            parse_port_value(src_port_val, &mut rule.source_ports, &mut rule.source_port_ranges);
        }
        if let Some(net_str) = r_cfg.network {
            rule.network = match net_str.to_lowercase().as_str() {
                "tcp" => Some(Network::Tcp),
                "udp" => Some(Network::Udp),
                _ => None,
            };
        }
        if let Some(protos) = r_cfg.protocol { rule.protocols = protos; }
        if let Some(users) = r_cfg.user { rule.user_emails = users; }
        if let Some(proc_list) = r_cfg.process { rule.process = proc_list; }
        if let Some(os_list) = r_cfg.local_os { rule.local_os = os_list; }
        rules.push(rule);
    }
    rules
}

fn build_dns_client(dns_val: Option<&serde_json::Value>) -> crate::app::dns::DnsClient {
    let mut client = crate::app::dns::DnsClient::new();
    let Some(val) = dns_val else { return client };
    if let Some(qs) = val.get("queryStrategy").and_then(|v| v.as_str()) {
        client.set_query_strategy(crate::app::dns::config::QueryStrategy::from_str(qs));
    }
    if let Some(dc) = val.get("disableCache").and_then(|v| v.as_bool()) { client.set_disable_cache(dc); }
    if let Some(df) = val.get("disableFallback").and_then(|v| v.as_bool()) { client.set_disable_fallback(df); }
    if let Some(dfim) = val.get("disableFallbackIfMatch").and_then(|v| v.as_bool()) {
        client.set_disable_fallback_if_match(dfim);
    }
    if let Some(hosts_obj) = val.get("hosts").and_then(|h| h.as_object()) {
        for (domain, ip_val) in hosts_obj {
            let ips: Vec<std::net::IpAddr> = match ip_val {
                serde_json::Value::String(s) => s.parse().into_iter().collect(),
                serde_json::Value::Array(arr) => arr.iter().filter_map(|x| x.as_str()?.parse().ok()).collect(),
                _ => Vec::new(),
            };
            if !ips.is_empty() { client.add_host(domain, ips); }
        }
    }
    let default_dns_tag = val.get("tag").and_then(|v| v.as_str()).map(str::to_string);
    let default_client_ip = val
        .get("clientIp").and_then(|v| v.as_str()).and_then(|s| s.parse::<std::net::IpAddr>().ok());
    if let Some(servers_arr) = val.get("servers").and_then(|s| s.as_array()) {
        for s in servers_arr {
            if let Some(addr) = s.as_str() {
                client.add_server(crate::app::dns::DnsServerConfig {
                    address: addr.to_string(),
                    tag: default_dns_tag.clone(),
                    client_ip: default_client_ip,
                    ..Default::default()
                });
            } else if let Some(obj) = s.as_object()
                && let Some(raw_addr) = obj.get("address").and_then(|v| v.as_str())
            {
                let address = match (
                    obj.get("port").and_then(|v| v.as_u64()),
                    raw_addr.parse::<std::net::IpAddr>().ok(),
                ) {
                    (Some(port), Some(ip)) => std::net::SocketAddr::new(ip, port as u16).to_string(),
                    _ => raw_addr.to_string(),
                };
                client.add_server(crate::app::dns::DnsServerConfig {
                    address,
                    domains: parse_json_str_array(s, "domains"),
                    expect_ips: parse_json_str_array(s, "expectIPs"),
                    skip_fallback: obj.get("skipFallback").and_then(|v| v.as_bool()).unwrap_or(false),
                    query_strategy: obj
                        .get("queryStrategy")
                        .and_then(|v| v.as_str()).map(crate::app::dns::config::QueryStrategy::from_str),
                    tag: obj
                        .get("tag").and_then(|v| v.as_str()).map(str::to_string).or_else(|| default_dns_tag.clone()),
                    client_ip: obj
                        .get("clientIp")
                        .and_then(|v| v.as_str())
                        .and_then(|x| x.parse::<std::net::IpAddr>().ok()).or(default_client_ip),
                });
            }
        }
    }
    client
}

#[cfg(test)]
mod socks_runtime_config_tests {
    use super::{BuiltConfig, Config};
    use crate::common::errors::{Error, Result};
    use crate::common::net::{Address, Destination};
    use crate::common::protocol::SessionContext;
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    fn build_config(value: Value) -> Result<BuiltConfig> {
        serde_json::from_value::<Config>(value).unwrap().build()
    }

    fn password_request(username: &str, password: &str) -> Vec<u8> {
        let mut wire = vec![5, 1, 2, 1, username.len() as u8];
        wire.extend_from_slice(username.as_bytes());
        wire.push(password.len() as u8);
        wire.extend_from_slice(password.as_bytes());
        wire.extend_from_slice(b"\x05\x01\x00\x03\x0bexample.com\x01\xbbping");
        wire
    }

    async fn inbound_exchange(settings: Value, wire: &[u8]) -> (Result<SessionContext>, Vec<u8>, Vec<u8>) {
        timeout(Duration::from_secs(5), async {
            let mut built = build_config(json!({
                "inbounds": [{
                    "tag": "configured-socks", "protocol": "socks5",
                    "listen": "127.0.0.1", "port": 1080, "settings": settings
                }]
            })).unwrap();
            let (address, handler) = built.inbounds.pop().unwrap();
            assert_eq!(address, "127.0.0.1:1080".parse::<SocketAddr>().unwrap());
            assert_eq!(handler.tag(), "configured-socks");
            let (mut client, stream) = tokio::io::duplex(4096);
            client.write_all(wire).await.unwrap();
            client.shutdown().await.unwrap();
            let remote = "127.0.0.1:54321".parse().unwrap();
            let mut payload = Vec::new();
            let result = match handler.handle_connection(Box::pin(stream), remote).await {
                Ok(mut inbound) => {
                    inbound.stream.read_to_end(&mut payload).await.unwrap();
                    Ok(inbound.session)
                }
                Err(error) => Err(error),
            };
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            (result, reply, payload)
        }).await.unwrap()
    }

    // Exercise the outbound returned by Config::build against a scripted TCP
    // peer, so client/server implementation mistakes cannot mask each other.
    async fn outbound_wire_case(listener: TcpListener, settings: Value, account: Option<(&str, &str)>) {
        timeout(Duration::from_secs(5), async {
            let credentials = account.map(|(username, password)| {
                let mut bytes = vec![1, username.len() as u8];
                bytes.extend_from_slice(username.as_bytes());
                bytes.push(password.len() as u8);
                bytes.extend_from_slice(password.as_bytes());
                bytes
            });
            let mut built = build_config(json!({
                "outbounds": [{"tag": "configured-socks", "protocol": "socks", "settings": settings}]
            })).unwrap();
            let outbound = built.outbounds.remove("configured-socks").unwrap();
            assert_eq!(outbound.tag(), "configured-socks");
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let method = if credentials.is_some() { 2 } else { 0 };
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, method]);
                stream.write_all(&[5, method]).await.unwrap();
                if let Some(expected) = credentials {
                    let mut actual = vec![0; expected.len()];
                    stream.read_exact(&mut actual).await.unwrap();
                    assert_eq!(actual, expected);
                    stream.write_all(&[1, 0]).await.unwrap();
                }
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [5, 1, 0, 1, 1, 2, 3, 4, 1, 187]);
                stream.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00pong").await.unwrap();
                let mut payload = [0; 4];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
            });
            let target = Destination::tcp(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
            let mut tunnel = outbound.connect(&SessionContext::new("test", target)).await.unwrap();
            let mut payload = [0; 4];
            tunnel.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            tunnel.write_all(b"ping").await.unwrap();
            tunnel.flush().await.unwrap();
            peer.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn built_socks_inbound_uses_go_account_list_for_password_handshake() {
        // Xray-core/infra/conf/socks_test.go TestSocksInboundConfig credentials.
        let settings = json!({
            "auth": "password",
            "accounts": [{"user": "my-username", "pass": "my-password"}],
            "udp": false, "ip": "127.0.0.1", "userLevel": 1
        });
        let (result, reply, payload) = inbound_exchange(settings, &password_request("my-username", "my-password")).await;
        let session = result.unwrap();
        assert_eq!(session.destination, Destination::from_domain_port("example.com", 443));
        assert_eq!(session.user.unwrap().email, "my-username");
        assert_eq!(session.source, Some("127.0.0.1:54321".parse::<SocketAddr>().unwrap()));
        assert_eq!(reply, [5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(payload, b"ping");
    }

    #[tokio::test]
    async fn built_socks_inbound_rejects_bad_credentials_and_auth_downgrade() {
        let settings = json!({"auth": "password", "accounts": [{"user": "a", "pass": "bc"}]});
        for (username, password) in [("a", "wrong"), ("wrong", "bc")] {
            let (result, reply, _) = inbound_exchange(settings.clone(), &password_request(username, password)).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 2, 1, 255]);
        }
        let (result, reply, _) = inbound_exchange(settings.clone(), &[5, 1, 0]).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 255]);
        let (result, reply, _) = inbound_exchange(settings, &[4, 1]).await;
        assert!(result.is_err());
        assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn built_socks_password_mode_without_accounts_rejects_all_logins() {
        // Go's Build succeeds here; ServerConfig.HasAccount returns false.
        for settings in [
            json!({"auth": "password"}),
            json!({"auth": "password", "accounts": []}),
            json!({"auth": "password", "accounts": null}),
            json!({"auth": "password", "users": []}),
        ] {
            let (result, reply, _) = inbound_exchange(settings.clone(), &password_request("a", "bc")).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 2, 1, 255]);
            let (result, reply, _) = inbound_exchange(settings, &[5, 1, 0]).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 255]);
        }
    }

    #[tokio::test]
    async fn built_socks_accounts_override_users_including_empty_lists() {
        for accounts in [None, Some(Value::Null)] {
            let mut settings = json!({"auth": "password", "users": [{"user": "legacy", "pass": "pass"}]});
            if let Some(accounts) = accounts { settings["accounts"] = accounts; }
            let (result, reply, _) = inbound_exchange(settings, &password_request("legacy", "pass")).await;
            assert!(result.is_ok());
            assert_eq!(&reply[..4], &[5, 2, 1, 0]);
        }
        for accounts in [json!([]), json!([{"user": "primary", "pass": "pass"}])] {
            let settings = json!({
                "auth": "password", "accounts": accounts,
                "users": [{"user": "legacy", "pass": "pass"}]
            });
            let (result, reply, _) = inbound_exchange(settings, &password_request("legacy", "pass")).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 2, 1, 255]);
        }
        let settings = json!({
            "auth": "password", "accounts": [{"user": "primary", "pass": "pass"}],
            "users": [{"user": "legacy", "pass": "pass"}]
        });
        let (result, reply, _) = inbound_exchange(settings, &password_request("primary", "pass")).await;
        assert_eq!(result.unwrap().user.unwrap().email, "primary");
        assert_eq!(&reply[..4], &[5, 2, 1, 0]);
    }

    #[tokio::test]
    async fn built_socks_account_map_uses_last_duplicate_and_accepts_legacy_rust_maps() {
        for accounts in [
            json!([{"user": "a", "pass": "old"}, {"user": "a", "pass": "new"}]),
            json!({"a": "new"}),
        ] {
            let settings = json!({"auth": "password", "accounts": accounts});
            let (result, reply, _) = inbound_exchange(settings.clone(), &password_request("a", "new")).await;
            assert!(result.is_ok());
            assert_eq!(&reply[..4], &[5, 2, 1, 0]);
            let (result, reply, _) = inbound_exchange(settings, &password_request("a", "old")).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 2, 1, 255]);
        }
    }

    #[tokio::test]
    async fn built_socks_empty_configured_account_remains_password_auth() {
        let (result, reply, _) = inbound_exchange(
            json!({"auth": "password", "accounts": [{}]}), &password_request("", ""),
        ).await;
        assert!(result.is_ok());
        assert_eq!(&reply[..4], &[5, 2, 1, 0]);
    }

    #[tokio::test]
    async fn built_socks_missing_or_unknown_auth_defaults_to_noauth_like_go() {
        for settings in [
            Value::Null,
            json!({}),
            json!({"auth": "noauth"}),
            json!({"auth": "PASSWORD", "accounts": [{"user": "a", "pass": "bc"}]}),
            json!({"auth": "unknown"}),
        ] {
            let wire = b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50data";
            let (result, reply, payload) = inbound_exchange(settings.clone(), wire).await;
            assert_eq!(result.unwrap().destination, Destination::tcp(Address::Ipv4(Ipv4Addr::LOCALHOST), 80));
            assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(payload, b"data");
            let (result, reply, _) = inbound_exchange(settings, &[5, 1, 2]).await;
            assert!(result.is_err());
            assert_eq!(reply, [5, 255]);
        }
    }

    #[test]
    fn built_socks_inbound_rejects_malformed_account_settings() {
        for settings in [
            json!({"auth": "password", "accounts": "not-accounts"}),
            json!({"auth": "password", "accounts": [{"user": "a", "pass": 123}]}),
            json!({"auth": "password", "users": {"a": "bc"}}),
            json!({"auth": true}),
        ] {
            let result = build_config(json!({
                "inbounds": [{"protocol": "socks", "port": 1080, "settings": settings}]
            }));
            assert!(matches!(result, Err(Error::Config(_))));
        }
    }

    #[tokio::test]
    async fn built_socks_outbound_emits_go_user_pass_vectors_without_uuid_ids() {
        // Both shapes are Go TestSocksOutboundConfig vectors. The flat form
        // overrides servers, even if that list would otherwise fail validation.
        for flat in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let settings = if flat {
                json!({
                    "address": "127.0.0.1", "port": port,
                    "user": "test user", "pass": "test pass", "email": "test@email.com",
                    "servers": [{}, {}]
                })
            } else {
                json!({"servers": [{
                    "address": "127.0.0.1", "port": port,
                    "users": [{"user": "test user", "pass": "test pass", "email": "test@email.com", "level": 1}]
                }]})
            };
            outbound_wire_case(listener, settings, Some(("test user", "test pass"))).await;
        }
    }

    #[tokio::test]
    async fn built_socks_outbound_omitted_users_and_flat_empty_username_use_noauth() {
        for mode in 0..5 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let settings = match mode {
                0 => json!({"servers": [{"address": "127.0.0.1", "port": port}]}),
                1 => json!({"servers": [{"address": "127.0.0.1", "port": port, "users": []}]}),
                2 => json!({"servers": [{"address": "127.0.0.1", "port": port, "users": null}]}),
                3 => json!({"address": "127.0.0.1", "port": port, "pass": "ignored"}),
                _ => json!({"address": "127.0.0.1", "port": port, "user": "", "pass": "ignored"}),
            };
            outbound_wire_case(listener, settings, None).await;
        }
    }

    #[tokio::test]
    async fn built_socks_outbound_explicit_empty_account_still_uses_password_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let settings = json!({"servers": [{"address": "127.0.0.1", "port": port, "users": [{}]}]});
        outbound_wire_case(listener, settings, Some(("", ""))).await;
    }

    #[test]
    fn built_socks_outbound_enforces_go_server_and_user_cardinality() {
        for settings in [
            Value::Null,
            json!({}),
            json!({"servers": []}),
            json!({"servers": null}),
            json!({"servers": [{"address": "127.0.0.1"}, {"address": "127.0.0.2"}]}),
            json!({"servers": [{"address": "127.0.0.1", "users": [{"user": "a"}, {"user": "b"}]}]}),
            json!({"servers": [{"port": 1080}]}),
            json!({"servers": [{"address": "127.0.0.1", "port": 70000}]}),
        ] {
            let result = build_config(json!({
                "outbounds": [{"protocol": "socks", "settings": settings}]
            }));
            assert!(matches!(result, Err(Error::Config(_))));
        }
    }

    #[tokio::test]
    async fn built_socks_outbound_and_inbound_authenticate_and_exchange_payload() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut built = build_config(json!({
                "inbounds": [{
                    "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": port,
                    "settings": {"auth": "password", "accounts": [{"user": "a", "pass": "bc"}]}
                }],
                "outbounds": [{
                    "tag": "socks-out", "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.1", "port": port, "users": [{"user": "a", "pass": "bc"}]}]}
                }]
            })).unwrap();
            let (address, inbound) = built.inbounds.pop().unwrap();
            assert_eq!(address, listener.local_addr().unwrap());
            let outbound = built.outbounds.remove("socks-out").unwrap();
            let target = Destination::from_domain_port("example.com", 443);
            let expected_target = target.clone();
            let peer = tokio::spawn(async move {
                let (stream, remote) = listener.accept().await.unwrap();
                let mut result = inbound.handle_connection(Box::pin(stream), remote).await.unwrap();
                assert_eq!(result.session.destination, expected_target);
                assert_eq!(result.session.user.unwrap().email, "a");
                let mut payload = [0; 4];
                result.stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                result.stream.write_all(b"pong").await.unwrap();
            });
            let mut stream = outbound.connect(&SessionContext::new("test", target)).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            peer.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn built_socks_outbound_cannot_bypass_bad_credentials_or_missing_inbound_accounts() {
        timeout(Duration::from_secs(10), async {
            for mode in 0..3 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let settings = if mode == 1 {
                    json!({"auth": "password"})
                } else {
                    json!({"auth": "password", "accounts": [{"user": "a", "pass": "bc"}]})
                };
                let users = match mode {
                    0 => json!([{"user": "a", "pass": "wrong"}]),
                    1 => json!([{"user": "a", "pass": "bc"}]),
                    _ => json!([]),
                };
                let mut built = build_config(json!({
                    "inbounds": [{"protocol": "socks", "port": port, "settings": settings}],
                    "outbounds": [{
                        "tag": "socks-out", "protocol": "socks",
                        "settings": {"servers": [{"address": "127.0.0.1", "port": port, "users": users}]}
                    }]
                })).unwrap();
                let inbound = built.inbounds.pop().unwrap().1;
                let outbound = built.outbounds.remove("socks-out").unwrap();
                let peer = tokio::spawn(async move {
                    let (stream, remote) = listener.accept().await.unwrap();
                    assert!(inbound.handle_connection(Box::pin(stream), remote).await.is_err());
                });
                let target = Destination::from_domain_port("example.com", 443);
                assert!(outbound.connect(&SessionContext::new("test", target)).await.is_err());
                peer.await.unwrap();
            }
        }).await.unwrap();
    }
}
