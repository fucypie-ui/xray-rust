use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(ip: IpAddr, prefix: u8) -> Self { Self { ip, prefix } }
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('/');
        let ip_str = parts.next()?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let ip = ip.to_canonical();
        let prefix = match parts.next() {
            Some("") | None => match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
            Some(p) => p.parse::<u8>().ok()?,
        };
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if parts.next().is_some() || prefix > max_prefix { return None; }
        Some(Self { ip, prefix })
    }
    pub fn contains(&self, target: &IpAddr) -> bool {
        // net.ParseAddress/netipx.FromStdIP treat IPv4-mapped IPv6 as IPv4.
        match (self.ip, target.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(tgt)) => self.prefix == 0 || (self.prefix <= 32 && {
                let mask = !0u32 << (32 - self.prefix);
                (u32::from_be_bytes(net.octets()) & mask) == (u32::from_be_bytes(tgt.octets()) & mask)
            }),
            (IpAddr::V6(net), IpAddr::V6(tgt)) => self.prefix == 0 || (self.prefix <= 128 && {
                let mask = !0u128 << (128 - self.prefix);
                (u128::from_be_bytes(net.octets()) & mask) == (u128::from_be_bytes(tgt.octets()) & mask)
            }),
            _ => false,
        }
    }
}

pub trait GeoIpMatcher: Send + Sync {
    fn matches_ip(&self, ip: &IpAddr) -> bool;
    fn any_match(&self, ips: &[IpAddr]) -> bool { ips.iter().any(|ip| self.matches_ip(ip)) }
    fn all_match(&self, ips: &[IpAddr]) -> bool { !ips.is_empty() && ips.iter().all(|ip| self.matches_ip(ip)) }
    fn filter_ips(&self, ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let mut matched = Vec::new();
        let mut unmatched = Vec::new();
        for ip in ips {
            if self.matches_ip(ip) {
                matched.push(*ip);
            } else {
                unmatched.push(*ip);
            }
        }
        (matched, unmatched)
    }
}

pub struct HeuristicGeoIpMatcher {
    cidrs: Vec<Cidr>,
    reverse: bool,
    has_ipv4: bool,
    has_ipv6: bool,
}

impl HeuristicGeoIpMatcher {
    pub fn new(cidrs: Vec<Cidr>, reverse: bool) -> Self {
        let has_ipv4 = cidrs.iter().any(|net| net.ip.is_ipv4() && net.prefix <= 32);
        let has_ipv6 = cidrs.iter().any(|net| net.ip.is_ipv6() && net.prefix <= 128);
        Self { cidrs, reverse, has_ipv4, has_ipv6 }
    }
    pub fn toggle_reverse(&mut self) { self.reverse = !self.reverse; }
    pub fn set_reverse(&mut self, reverse: bool) { self.reverse = reverse; }
}

impl GeoIpMatcher for HeuristicGeoIpMatcher {
    fn matches_ip(&self, ip: &IpAddr) -> bool {
        // Go's heuristic matcher never reverses an absent address family. An
        // IPv4-only reverse set cannot match IPv6 (nor an empty set everything).
        let ip = ip.to_canonical();
        let has_family = if ip.is_ipv4() { self.has_ipv4 } else { self.has_ipv6 };
        if !has_family { return false; }
        let is_contained = self.cidrs.iter().any(|net| net.contains(&ip));
        if self.reverse {
            !is_contained
        } else {
            is_contained
        }
    }
}
