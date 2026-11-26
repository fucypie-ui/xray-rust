use crate::app::dns::fakedns::FakeDnsHolder;
use crate::common::errors::{Error, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[async_trait]
pub trait NameServer: Send + Sync {
    fn name(&self) -> &str;
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>>;
    async fn query_ip_with_opt(&self, domain: &str, _ipv4: bool, _ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        self.query_ip(domain).await.map(|ips| (ips, 300))
    }
    fn is_disable_cache(&self) -> bool { false }
    fn routes_via_proxy(&self) -> bool { false }
}

pub struct UdpNameServer {
    name: String,
    inner: super::nameserver_udp::UdpNameServer,
}

impl UdpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            name: format!("udp://{}", server_addr),
            inner: super::nameserver_udp::UdpNameServer::new(server_addr),
        }
    }
    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            name: format!("udp://{}", server_addr),
            inner: super::nameserver_udp::UdpNameServer::with_timeout(server_addr, timeout),
        }
    }
}

#[async_trait]
impl NameServer for UdpNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.inner.query_ip(domain).await
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        self.inner.query_ip_with_opt(domain, ipv4, ipv6).await
    }
}

pub struct TcpNameServer {
    name: String,
    inner: super::nameserver_tcp::TcpNameServer,
}

impl TcpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            name: format!("tcp://{}", server_addr),
            inner: super::nameserver_tcp::TcpNameServer::new(server_addr),
        }
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.inner.query_ip(domain).await
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        self.inner.query_ip_with_opt(domain, ipv4, ipv6).await
    }
}

pub struct FakeDnsNameServer {
    name: String,
    holder: Arc<FakeDnsHolder>,
}

impl FakeDnsNameServer {
    pub fn new(holder: Arc<FakeDnsHolder>) -> Self {
        Self {
            name: "fakedns".into(),
            holder,
        }
    }
}

#[async_trait]
impl NameServer for FakeDnsNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let ip = self.holder.get_fake_ip_for_domain(domain);
        Ok(vec![IpAddr::V4(ip)])
    }
}

pub struct LocalNameServer {
    name: String,
}

impl LocalNameServer {
    pub fn new() -> Self { Self { name: "local".into(), } }
}

impl Default for LocalNameServer {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl NameServer for LocalNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let addr_str = format!("{}:80", domain);
        let addrs = tokio::net::lookup_host(addr_str).await.map_err(Error::Io)?;
        let ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
        if ips.is_empty() {
            Err(Error::NotFound(format!("Local DNS could not resolve {}", domain)))
        } else {
            Ok(ips)
        }
    }
}

pub fn build_dns_query(domain: &str) -> Vec<u8> { build_dns_query_typed(domain, 1) }

pub fn build_dns_query_typed(domain: &str, qtype: u16) -> Vec<u8> { build_dns_query_with_ecs(domain, qtype, None) }

pub fn build_dns_query_with_ecs(domain: &str, qtype: u16, client_ip: Option<IpAddr>) -> Vec<u8> {
    // Preserve the existing Vec-returning helper; transports use the checked API.
    try_build_dns_query_with_ecs(domain, qtype, client_ip).unwrap_or_default()
}

pub(super) fn try_build_dns_query_with_ecs(domain: &str, qtype: u16, client_ip: Option<IpAddr>) -> Result<Vec<u8>> {
    let name = Name::from_ascii(super::dnscommon::fqdn(domain))
        .map_err(|e| Error::Protocol(format!("Invalid DNS name: {e}")))?;
    let mut message = Message::query();
    message.metadata.id = rand::random();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(qtype)));
    let mut query = message.to_vec().map_err(|e| Error::Protocol(format!("Failed to encode DNS query: {e}")))?;
    if let Some(ip) = client_ip {
        query[10..12].copy_from_slice(&1u16.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                query.extend_from_slice(&[
                    0, 0, 0x29, 0x05, 0x46, 0, 0, 0x80, 0, 0, 0x0B, 0, 8, 0, 7, 0, 1, 24, 0, o[0], o[1], o[2],
                ]);
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                query.extend_from_slice(&[
                    0, 0, 0x29, 0x05, 0x46, 0, 0, 0x80, 0, 0, 0x14, 0, 8, 0, 0x10, 0, 2, 96, 0,
                    o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11],
                ]);
            }
        }
    }
    Ok(query)
}

pub fn parse_dns_response(resp: &[u8], domain: &str) -> Result<Vec<IpAddr>> {
    parse_dns_response_with_ttl(resp, domain).map(|(ips, _)| ips)
}

pub fn parse_dns_response_with_ttl(resp: &[u8], domain: &str) -> Result<(Vec<IpAddr>, u32)> {
    let message = decode_dns_response(resp)?;
    let name = Name::from_ascii(super::dnscommon::fqdn(domain))
        .map_err(|e| Error::Protocol(format!("Invalid DNS name: {e}")))?;
    if message.queries.len() != 1 || message.queries[0].name != name
        || message.queries[0].query_class != DNSClass::IN
    {
        return Err(Error::Protocol("DNS response question does not match request".into()));
    }
    response_ips(message, None)
}

fn decode_dns_response(resp: &[u8]) -> Result<Message> {
    let message = Message::from_vec(resp)
        .map_err(|e| Error::Protocol(format!("Malformed DNS response: {e}")))?;
    if message.metadata.message_type != MessageType::Response || message.metadata.op_code != OpCode::Query {
        return Err(Error::Protocol("Invalid DNS response flags or opcode".into()));
    }
    if message.metadata.truncation {
        return Err(Error::Protocol("Truncated DNS response".into()));
    }
    Ok(message)
}

// Inspect only the header/question: TC responses may end inside an answer.
pub(super) fn response_matches_query(resp: &[u8], query: &[u8]) -> bool {
    let Ok(request) = Message::from_vec(query) else { return false; };
    let mut decoder = BinDecoder::new(resp);
    let Ok(header) = Header::read(&mut decoder) else { return false; };
    if header.metadata.id != request.metadata.id
        || header.metadata.message_type != MessageType::Response
        || header.metadata.op_code != OpCode::Query || header.counts.queries != 1
        || request.queries.len() != 1
    { return false; }
    let Ok(question) = Query::read(&mut decoder) else { return false; };
    question == request.queries[0]
}

pub(super) fn parse_dns_response_for_query(resp: &[u8], query: &[u8]) -> Result<(Vec<IpAddr>, u32)> {
    if !response_matches_query(resp, query) {
        return Err(Error::Protocol("DNS response transaction or question does not match request".into()));
    }
    let message = decode_dns_response(resp)?;
    let qtype = message.queries[0].query_type;
    response_ips(message, Some(qtype))
}

fn response_ips(message: Message, qtype: Option<RecordType>) -> Result<(Vec<IpAddr>, u32)> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(Error::NotFound(format!("DNS server returned {}", message.metadata.response_code)));
    }
    // Go's parseResponse bounds the entire record by the shortest answer TTL.
    let ttl = message.answers.iter().map(|answer| answer.ttl.max(1)).min().unwrap_or(300);
    let ips: Vec<_> = message.answers.iter()
        .filter(|answer| answer.dns_class == DNSClass::IN)
        .filter(|answer| qtype.is_none_or(|qtype| answer.record_type() == qtype))
        .filter_map(|answer| answer.data.ip_addr())
        .filter(|ip| !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()))
        .collect();
    if ips.is_empty() {
        Err(Error::NotFound("DNS response contains no matching IP addresses".into()))
    } else {
        Ok((ips, ttl))
    }
}

pub(super) fn retry_with_edns(query: &mut Vec<u8>) -> bool {
    if query.len() < 12 || query[10..12] != [0, 0] { return false; }
    let id = u16::from_be_bytes([query[0], query[1]]).wrapping_add(1);
    query[..2].copy_from_slice(&id.to_be_bytes());
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    // Root owner, OPT, payload 1350, EDNS version 0, DO, no options.
    query.extend_from_slice(&[0, 0, 41, 5, 70, 0, 0, 0x80, 0, 0, 0]);
    true
}

pub(super) async fn query_ip_families<F, Fut>(domain: &str, ipv4: bool, ipv6: bool, mut query: F) -> Result<(Vec<IpAddr>, u32)>
where
    F: FnMut(u16) -> Fut,
    Fut: Future<Output = Result<(Vec<IpAddr>, u32)>>,
{
    let a = ipv4.then(|| query(1));
    let aaaa = ipv6.then(|| query(28));
    let (a, aaaa) = tokio::join!(
        async { if let Some(future) = a { Some((future.await, Instant::now())) } else { None } },
        async { if let Some(future) = aaaa { Some((future.await, Instant::now())) } else { None } },
    );
    let (mut ips, mut ttl, mut last_error) = (Vec::new(), u32::MAX, None);
    for (result, received) in [a, aaaa].into_iter().flatten() {
        match result {
            Ok((addresses, lifetime)) => {
                ips.extend(addresses);
                ttl = ttl.min(lifetime.saturating_sub(received.elapsed().as_secs().min(u32::MAX as u64) as u32).max(1));
            }
            Err(error) => last_error = Some(error),
        }
    }
    if ips.is_empty() {
        Err(last_error.unwrap_or_else(|| Error::NotFound(format!("No IP found for {domain}"))))
    } else {
        Ok((ips, ttl))
    }
}
