use crate::app::router::geo::GeoDatabase;
use crate::common::net::{Address, Network};
use crate::common::protocol::SessionContext;
use crate::features::routing::context::RoutingContext;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

static GLOBAL_GEO_DB: LazyLock<GeoDatabase> = LazyLock::new(GeoDatabase::new);

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Plain(String),
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(Regex),
    GeoSite(String, bool),
}

impl DomainMatcher {
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some(pat) = s.strip_prefix("regexp:").or_else(|| s.strip_prefix("REGEXP:"))
            && let Ok(re) = Regex::new(pat)
        {
            return Self::Regex(re);
        }
        if let Some(substr) = s.strip_prefix("dotless:")
            && !substr.contains('.')
            && let Ok(re) = Regex::new(&format!("^[^.]*{substr}[^.]*$"))
        {
            return Self::Regex(re);
        }
        let lower = s.to_lowercase();
        let parse_geosite_tag = |raw: &str, neg_outer: bool| -> Self {
            let (neg_inner, tag) = match raw.strip_prefix('!') {
                Some(t) => (true, t),
                None => (false, raw),
            };
            Self::GeoSite(tag.to_string(), neg_outer ^ neg_inner)
        };
        if let Some(r) = lower.strip_prefix("!geosite:") { return parse_geosite_tag(r, true); }
        if let Some(r) = lower.strip_prefix("geosite:") { return parse_geosite_tag(r, false); }
        if let Some(r) = lower.strip_prefix("ext:") {
            if let Some((_, t)) = r.rsplit_once(':').filter(|(_, t)| !t.is_empty()) {
                return parse_geosite_tag(t, false);
            }
            return Self::Plain(lower);
        }
        if let Some(r) = lower.strip_prefix("full:") { Self::Exact(r.to_string()) }
        else if let Some(r) = lower.strip_prefix("domain:") { Self::Suffix(r.to_string()) }
        else if let Some(r) = lower.strip_prefix("keyword:") { Self::Keyword(r.to_string()) }
        else { Self::Plain(lower) }
    }
    pub fn matches(&self, domain: &str) -> bool {
        // The routing condition lowercases the input for every matcher, including
        // regexes. The regex pattern itself remains case-sensitive, as in Go.
        let d = domain.to_lowercase();
        match self {
            DomainMatcher::Exact(pattern) => d == *pattern,
            DomainMatcher::Suffix(pattern) => {
                d == *pattern
                    || (d.len() > pattern.len()
                        && d.ends_with(pattern.as_str())
                        && d.as_bytes()[d.len() - pattern.len() - 1] == b'.')
            }
            DomainMatcher::Keyword(pattern) | DomainMatcher::Plain(pattern) => d.contains(pattern.as_str()),
            DomainMatcher::Regex(re) => re.is_match(&d),
            DomainMatcher::GeoSite(group, invert) => GLOBAL_GEO_DB.match_geosite(group, &d) ^ invert,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    Exact(IpAddr),
    CidrV4(Ipv4Addr, u8),
    CidrV6(Ipv6Addr, u8),
    Private(bool),
    GeoIp(String, bool),
}

impl IpMatcher {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let lower = s.to_lowercase();
        let geo = |raw: &str, neg_outer: bool| -> Self {
            let (neg_inner, tag) = match raw.strip_prefix('!') {
                Some(t) => (true, t),
                None => (false, raw),
            };
            let inv = neg_outer ^ neg_inner;
            if tag == "private" { Self::Private(inv) } else { Self::GeoIp(tag.to_string(), inv) }
        };
        if let Some(rest) = lower.strip_prefix("!geoip:") { return Some(geo(rest, true)); }
        if let Some(rest) = lower.strip_prefix("geoip:") { return Some(geo(rest, false)); }
        if let Some(rest) = lower.strip_prefix("ext:") {
            return rest.rsplit_once(':').filter(|(_, t)| !t.is_empty()).map(|(_, t)| geo(t, false));
        }
        if lower == "private" { return Some(Self::Private(false)); }
        if lower == "!private" { return Some(Self::Private(true)); }
        if s.contains('/') {
            let cidr = super::condition_geoip::Cidr::parse(s)?;
            return Some(match cidr.ip {
                IpAddr::V4(v4) => Self::CidrV4(v4, cidr.prefix),
                IpAddr::V6(v6) => Self::CidrV6(v6, cidr.prefix),
            });
        }
        IpAddr::from_str(s).ok().map(|ip| Self::Exact(ip.to_canonical()))
    }
    pub fn matches(&self, ip: &IpAddr) -> bool {
        let canonical = ip.to_canonical();
        let ip = &canonical;
        match self {
            IpMatcher::Exact(target_ip) => *ip == target_ip.to_canonical(),
            IpMatcher::Private(invert) => {
                let hit = match ip {
                    IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
                    IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || (v6.segments()[0] & 0xfe00) == 0xfc00,
                };
                hit ^ invert
            }
            IpMatcher::CidrV4(net, mask) => {
                if let IpAddr::V4(v4) = ip {
                    if *mask == 0 { return true; }
                    if *mask > 32 { return false; }
                    let net_u32 = u32::from_be_bytes(net.octets());
                    let ip_u32 = u32::from_be_bytes(v4.octets());
                    let mask_u32 = !0u32 << (32 - mask);
                    (ip_u32 & mask_u32) == (net_u32 & mask_u32)
                } else {
                    false
                }
            }
            IpMatcher::CidrV6(net, mask) => {
                if let IpAddr::V6(v6) = ip {
                    if *mask == 0 { return true; }
                    if *mask > 128 { return false; }
                    let net_u128 = u128::from_be_bytes(net.octets());
                    let ip_u128 = u128::from_be_bytes(v6.octets());
                    let mask_u128 = !0u128 << (128 - mask);
                    (ip_u128 & mask_u128) == (net_u128 & mask_u128)
                } else {
                    false
                }
            }
            IpMatcher::GeoIp(group, invert) => GLOBAL_GEO_DB.match_geoip(group, ip) ^ invert,
        }
    }
}

fn current_goos() -> &'static str {
    if cfg!(target_os = "windows") { "windows" }
    else if cfg!(target_os = "android") { "android" }
    else if cfg!(target_os = "macos") { "darwin" }
    else if cfg!(target_os = "freebsd") { "freebsd" }
    else { "linux" }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub tag: String,
    pub balancer_tag: Option<String>,
    pub inbound_tags: Vec<String>,
    pub domain_matchers: Vec<DomainMatcher>,
    pub ip_matchers: Vec<IpMatcher>,
    pub source_ip_matchers: Vec<IpMatcher>,
    pub ports: Vec<u16>,
    pub port_ranges: Vec<(u16, u16)>,
    pub source_ports: Vec<u16>,
    pub source_port_ranges: Vec<(u16, u16)>,
    pub network: Option<Network>,
    pub protocols: Vec<String>,
    pub user_emails: Vec<String>,
    pub process: Vec<String>,
    pub local_os: Vec<String>,
}

impl Rule {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(), balancer_tag: None, inbound_tags: Vec::new(), domain_matchers: Vec::new(),
            ip_matchers: Vec::new(), source_ip_matchers: Vec::new(), ports: Vec::new(), port_ranges: Vec::new(),
            source_ports: Vec::new(), source_port_ranges: Vec::new(), network: None, protocols: Vec::new(),
            user_emails: Vec::new(), process: Vec::new(), local_os: Vec::new(),
        }
    }
    pub fn with_balancer(balancer_tag: impl Into<String>) -> Self {
        let mut r = Self::new("");
        r.balancer_tag = Some(balancer_tag.into());
        r
    }
    pub fn matches_destination_ip(&self, ip: &IpAddr) -> bool {
        self.ip_matchers.iter().any(|m| m.matches(ip))
    }
    pub fn matches_user(&self, email: &str) -> bool {
        if email.is_empty() { return false; }
        self.user_emails.iter().any(|pat| {
            if let Some(re_str) = pat.strip_prefix("regexp:").filter(|s| !s.is_empty()) {
                Regex::new(re_str).is_ok_and(|re| re.is_match(email))
            } else {
                pat == email
            }
        })
    }
    pub fn matches_protocol(&self, proto: &str) -> bool {
        !proto.is_empty() && self.protocols.iter().any(|rp| !rp.is_empty() && proto.starts_with(rp))
    }
    pub fn matches_local_os(&self) -> bool {
        let os = current_goos();
        self.local_os.is_empty() || self.local_os.iter().any(|n| n.eq_ignore_ascii_case(os))
    }
    pub fn matches_process_info(&self, info: Option<&crate::common::net::find_process::ProcessInfo>) -> bool {
        if self.process.is_empty() { return true; }
        let Some(info) = info else { return false };
        let cur_pid = std::process::id();
        self.process.iter().any(|p| {
            let p = if cfg!(windows) { p.replace('\\', "/") } else { p.clone() };
            if p == "self/" {
                info.pid == cur_pid
            } else if p == "xray/" {
                std::env::current_exe().is_ok_and(|path| {
                    let path = path.to_string_lossy();
                    let path = if cfg!(windows) { path.replace('\\', "/") } else { path.into_owned() };
                    path == info.path
                })
            } else if p.ends_with('/') {
                info.path.starts_with(&p)
            } else if p.contains('/') {
                info.path == p
            } else {
                info.name == p.strip_suffix(".exe").unwrap_or(&p)
            }
        })
    }
    pub fn matches_process(&self, src: Option<std::net::SocketAddr>, is_tcp: bool) -> bool {
        if self.process.is_empty() { return true; }
        let Some(src) = src else { return false };
        let Ok(info) = crate::common::net::ProcessFinder::find_process_by_socket(src, is_tcp) else {
            return false;
        };
        self.matches_process_info(info.as_ref())
    }
    pub fn matches(&self, session: &SessionContext) -> bool {
        self.matches_with_ips(session, &[])
    }
    pub fn matches_with_ips(&self, session: &SessionContext, resolved_ips: &[IpAddr]) -> bool {
        let mut proc_cache = None;
        self.matches_with_cache(session, resolved_ips, &mut proc_cache)
    }
    pub fn matches_with_cache(
        &self,
        session: &SessionContext,
        resolved_ips: &[IpAddr],
        proc_cache: &mut Option<Option<crate::common::net::find_process::ProcessInfo>>,
    ) -> bool {
        let context = SessionRoutingContext::new(session);
        self.matches_context(&context, || {
            let mut ips = context.get_target_ips();
            ips.extend_from_slice(resolved_ips);
            ips
        }, proc_cache)
    }
    // Keep condition ordering in sync with RoutingRule.BuildCondition. Target IP
    // access is lazy because it may invoke DNS; earlier conditions must be able
    // to reject a rule without performing a lookup.
    pub(crate) fn matches_context(
        &self,
        context: &dyn RoutingContext,
        mut target_ips: impl FnMut() -> Vec<IpAddr>,
        proc_cache: &mut Option<Option<crate::common::net::find_process::ProcessInfo>>,
    ) -> bool {
        if !self.matches_local_os() { return false; }
        if !self.inbound_tags.is_empty() {
            let tag = context.get_inbound_tag();
            if tag.is_empty() || !self.inbound_tags.iter().any(|t| t == tag) { return false; }
        }
        if self.network.is_some_and(|net| net != context.get_network()) { return false; }
        if !self.protocols.is_empty()
            && !context.get_protocol().is_some_and(|proto| self.matches_protocol(proto))
        { return false; }
        let target_port = context.get_target_port();
        if (!self.ports.is_empty() || !self.port_ranges.is_empty())
            && !self.ports.contains(&target_port)
            && !self.port_ranges.iter().any(|&(s, e)| (s..=e).contains(&target_port))
        { return false; }
        if !self.source_ports.is_empty() || !self.source_port_ranges.is_empty() {
            let sp = context.get_source_port();
            if !self.source_ports.contains(&sp)
                && !self.source_port_ranges.iter().any(|&(s, e)| (s..=e).contains(&sp))
            { return false; }
        }
        if !self.user_emails.is_empty()
            && !context.get_user().is_some_and(|email| self.matches_user(email))
        { return false; }
        if !self.ip_matchers.is_empty()
            && !target_ips().iter().any(|ip| self.matches_destination_ip(ip))
        { return false; }
        if !self.source_ip_matchers.is_empty()
            && !context.get_source_ips().iter().any(|ip| {
                self.source_ip_matchers.iter().any(|m| m.matches(ip))
            })
        { return false; }
        if !self.domain_matchers.is_empty()
            && !context.get_target_domain().is_some_and(|d| {
                !d.is_empty() && self.domain_matchers.iter().any(|m| m.matches(d))
            })
        { return false; }
        if !self.process.is_empty() {
            let info = proc_cache.get_or_insert_with(|| {
                let ip = *context.get_source_ips().first()?;
                let src = std::net::SocketAddr::new(ip, context.get_source_port());
                crate::common::net::ProcessFinder::find_process_by_socket(
                    src,
                    context.get_network() == Network::Tcp,
                )
                .ok()
                .flatten()
            });
            if !self.matches_process_info(info.as_ref()) { return false; }
        }
        true
    }
}

// A borrowed adapter lets both Router entry points share the same condition
// evaluation while retaining SessionContext's original-destination IP support.
pub(crate) struct SessionRoutingContext<'a> {
    session: &'a SessionContext,
}

impl<'a> SessionRoutingContext<'a> {
    pub(crate) fn new(session: &'a SessionContext) -> Self { Self { session } }
}

impl RoutingContext for SessionRoutingContext<'_> {
    fn get_inbound_tag(&self) -> &str { &self.session.inbound_tag }
    fn get_source_ips(&self) -> Vec<IpAddr> { self.session.source.map(|s| vec![s.ip()]).unwrap_or_default() }
    fn get_source_port(&self) -> u16 { self.session.source.map(|s| s.port()).unwrap_or(0) }
    fn get_target_ips(&self) -> Vec<IpAddr> {
        [
            self.session.route_target.as_ref().and_then(|d| d.address.as_ip()),
            self.session.destination.address.as_ip(),
            self.session.original_destination.as_ref().and_then(|d| d.address.as_ip()),
        ].into_iter().flatten().collect()
    }
    fn get_target_port(&self) -> u16 {
        self.session.route_target.as_ref().unwrap_or(&self.session.destination).port
    }
    fn get_target_domain(&self) -> Option<&str> {
        self.session.route_target.as_ref()
            .and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None })
            .or(self.session.sniffed_domain.as_deref())
            .or(match &self.session.destination.address { Address::Domain(s) => Some(s.as_str()), _ => None })
            .or_else(|| self.session.original_destination.as_ref()
                .and_then(|d| match &d.address { Address::Domain(s) => Some(s.as_str()), _ => None }))
    }
    fn get_network(&self) -> Network { self.session.destination.network }
    fn get_protocol(&self) -> Option<&str> { self.session.sniffed_protocol.as_deref() }
    fn get_user(&self) -> Option<&str> { self.session.user.as_ref().map(|u| u.email.as_str()) }
    fn get_attributes(&self) -> &HashMap<String, String> {
        static EMPTY: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);
        &EMPTY
    }
}
