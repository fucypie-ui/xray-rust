use crate::app::dns::cache_controller::CacheController;
use crate::app::dns::nameserver::NameServer;
use crate::common::errors::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct CachedNameServer {
    server: Arc<dyn NameServer>,
    cache: CacheController,
    ttl: Duration,
}

impl CachedNameServer {
    pub fn new(server: Arc<dyn NameServer>, ttl: Duration) -> Self {
        Self {
            cache: CacheController::new(format!("cache-{}", server.name()), false, false, Duration::ZERO),
            server,
            ttl,
        }
    }
}

#[async_trait]
impl NameServer for CachedNameServer {
    fn name(&self) -> &str { self.server.name() }
    fn is_disable_cache(&self) -> bool { self.server.is_disable_cache() }
    fn routes_via_proxy(&self) -> bool { self.server.routes_via_proxy() }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.query_ip_with_opt(domain, true, false).await.map(|(ips, _)| ips)
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        if self.server.is_disable_cache() {
            return self.server.query_ip_with_opt(domain, ipv4, ipv6).await;
        }
        let key = format!("{}|{}{}", domain.trim_end_matches('.'), u8::from(ipv4), u8::from(ipv6));
        if let Some(record) = self.cache.get_with_ttl(&key) { return Ok(record); }
        let (ips, ttl) = self.server.query_ip_with_opt(domain, ipv4, ipv6).await?;
        let ttl = ttl.min(self.ttl.as_secs().min(u32::MAX as u64) as u32);
        if ttl != 0 && !ips.is_empty() {
            self.cache.set(&key, ips.clone(), Duration::from_secs(ttl as u64));
        }
        Ok((ips, ttl))
    }
}
