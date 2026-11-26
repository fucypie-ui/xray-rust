use super::{CachedNameServer, DnsClient, NameServer};
use crate::common::errors::{Error, Result};
use crate::features::dns::client::IPOption;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct CountingServer {
    calls: AtomicUsize,
    disable_cache: bool,
    ttl: u32,
    fail: bool,
}

impl CountingServer {
    fn new(ttl: u32, disable_cache: bool, fail: bool) -> Arc<Self> {
        Arc::new(Self { calls: AtomicUsize::new(0), disable_cache, ttl, fail })
    }
}

#[async_trait]
impl NameServer for CountingServer {
    fn name(&self) -> &str { "counting" }
    fn is_disable_cache(&self) -> bool { self.disable_cache }
    fn routes_via_proxy(&self) -> bool { true }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.query_ip_with_opt(domain, true, false).await.map(|(ips, _)| ips)
    }
    async fn query_ip_with_opt(&self, _domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail { return Err(Error::NotFound("test failure".into())); }
        let mut ips = Vec::new();
        if ipv4 { ips.push("8.8.8.8".parse().unwrap()); }
        if ipv6 { ips.push("2001:db8::1".parse().unwrap()); }
        Ok((ips, self.ttl))
    }
}

#[tokio::test]
async fn dns_cache_client_returns_wire_ttl_on_hit() {
    let server = CountingServer::new(7, false, false);
    let mut client = DnsClient::new();
    client.add_nameserver(server.clone());
    for domain in ["EXAMPLE.COM.", "example.com"] {
        let (ips, ttl) = client.lookup_ip_with_option(domain, IPOption {
            ipv4_enable: true, ipv6_enable: false, fake_enable: false,
        }).await.unwrap();
        assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert!((1..=7).contains(&ttl));
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dns_cache_wrapper_preserves_options_and_server_ttl() {
    let server = CountingServer::new(7, false, false);
    let cached = CachedNameServer::new(server.clone(), Duration::from_secs(300));
    assert!(cached.routes_via_proxy());
    for (v4, v6) in [(true, false), (false, true), (true, true)] {
        for _ in 0..2 {
            let (ips, ttl) = cached.query_ip_with_opt("example.com", v4, v6).await.unwrap();
            assert_eq!(ips.len(), usize::from(v4) + usize::from(v6));
            assert!(ips.iter().all(|ip| if ip.is_ipv4() { v4 } else { v6 }));
            assert!((1..=7).contains(&ttl));
        }
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn dns_cache_wrapper_obeys_cap_disable_and_failures() {
    let server = CountingServer::new(300, false, false);
    let cached = CachedNameServer::new(server.clone(), Duration::from_secs(4));
    for _ in 0..2 {
        assert!((1..=4).contains(&cached.query_ip_with_opt("example.com", true, false).await.unwrap().1));
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    for (disable, fail, cap) in [(true, false, 300), (false, true, 300), (false, false, 0)] {
        let server = CountingServer::new(10, disable, fail);
        let cached = CachedNameServer::new(server.clone(), Duration::from_secs(cap));
        assert_eq!(cached.is_disable_cache(), disable);
        for _ in 0..2 {
            assert_eq!(cached.query_ip("example.com").await.is_err(), fail);
        }
        assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    }
}
