use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub ips: Vec<IpAddr>,
    pub expire_at: Instant,
}

pub struct CacheController {
    pub name: String,
    pub disable_cache: bool,
    pub serve_stale: bool,
    pub serve_expired_ttl: Duration,
    records: Arc<RwLock<HashMap<String, DnsRecord>>>,
}

impl CacheController {
    pub fn new(name: String, disable_cache: bool, serve_stale: bool, serve_expired_ttl: Duration) -> Self {
        let records = Arc::new(RwLock::new(HashMap::<String, DnsRecord>::new()));
        if !disable_cache && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let cleaner = Arc::downgrade(&records);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    let Some(records) = cleaner.upgrade() else { break; };
                    let now = Instant::now();
                    if let Ok(mut guard) = records.write() {
                        let before = guard.len();
                        guard.retain(|_, r| is_usable(r, now, serve_stale, serve_expired_ttl));
                        if guard.len() < before { guard.shrink_to_fit(); }
                    }
                }
            });
        }
        Self { name, disable_cache, serve_stale, serve_expired_ttl, records }
    }
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.get_with_ttl(domain).map(|(ips, _)| ips)
    }
    pub fn get_with_ttl(&self, domain: &str) -> Option<(Vec<IpAddr>, u32)> {
        if self.disable_cache { return None; }
        let domain_lower = domain.trim_end_matches('.').to_ascii_lowercase();
        let guard = self.records.read().ok()?;
        let record = guard.get(&domain_lower)?;
        let now = Instant::now();
        if !is_usable(record, now, self.serve_stale, self.serve_expired_ttl) { return None; }
        let remaining = record.expire_at.saturating_duration_since(now);
        // Go's IPRecord.getIPs rounds up; stale answers are advertised for 1s.
        let ttl = remaining.as_secs().saturating_add(u64::from(remaining.subsec_nanos() != 0))
            .clamp(1, u32::MAX as u64) as u32;
        Some((record.ips.clone(), ttl))
    }
    pub fn set(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        if self.disable_cache { return; }
        let domain_lower = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Ok(mut guard) = self.records.write() {
            guard.insert(
                domain_lower,
                DnsRecord {
                    ips,
                    expire_at: Instant::now() + ttl,
                },
            );
        }
    }
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.records.write() {
            let len_before = guard.len();
            guard.retain(|_, r| is_usable(r, now, self.serve_stale, self.serve_expired_ttl));
            if guard.len() < len_before { guard.shrink_to_fit(); }
        }
    }
    pub fn cache_cleanup(&self) { self.cleanup_expired(); }
    pub fn len(&self) -> usize { self.records.read().map(|g| g.len()).unwrap_or(0) }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

fn is_usable(record: &DnsRecord, now: Instant, serve_stale: bool, stale_ttl: Duration) -> bool {
    now < record.expire_at || (serve_stale
        && (stale_ttl.is_zero() || now.saturating_duration_since(record.expire_at) < stale_ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(serve_stale: bool, stale_ttl: Duration) -> CacheController {
        CacheController::new("test".into(), false, serve_stale, stale_ttl)
    }

    #[test]
    fn dns_cache_remaining_ttl_rounds_up_and_normalizes_names() {
        let cache = cache(false, Duration::ZERO);
        let ips = vec!["8.8.8.8".parse().unwrap()];
        cache.set("EXAMPLE.COM.", ips.clone(), Duration::from_secs(5));
        assert_eq!(cache.get_with_ttl("example.com"), Some((ips, 5)));
        let mut records = cache.records.write().unwrap();
        records.get_mut("example.com").unwrap().expire_at = Instant::now() + Duration::from_millis(900);
        drop(records);
        assert_eq!(cache.get_with_ttl("example.com.").unwrap().1, 1);
    }

    #[test]
    fn dns_cache_expired_records_obey_stale_window() {
        for (serve_stale, stale_ttl, expected) in [
            (false, Duration::ZERO, false),
            (true, Duration::from_secs(10), true),
            (true, Duration::from_secs(1), false),
            // Go queryIP treats serveExpiredTTL == 0 as unlimited stale.
            (true, Duration::ZERO, true),
        ] {
            let cache = cache(serve_stale, stale_ttl);
            cache.set("example.com", vec!["8.8.8.8".parse().unwrap()], Duration::ZERO);
            cache.records.write().unwrap().get_mut("example.com").unwrap().expire_at =
                Instant::now() - Duration::from_secs(2);
            assert_eq!(cache.get_with_ttl("example.com").is_some(), expected);
            if expected { assert_eq!(cache.get_with_ttl("example.com").unwrap().1, 1); }
            cache.cleanup_expired();
            assert_eq!(!cache.is_empty(), expected);
        }
    }

    #[test]
    fn dns_cache_disabled_never_stores() {
        let cache = CacheController::new("disabled".into(), true, true, Duration::ZERO);
        cache.set("example.com", vec!["8.8.8.8".parse().unwrap()], Duration::from_secs(60));
        assert!(cache.get_with_ttl("example.com").is_none());
        assert!(cache.is_empty());
    }
}
