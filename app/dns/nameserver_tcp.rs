use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;
use super::nameserver::{NameServer, parse_dns_response_for_query, query_ip_families, try_build_dns_query_with_ecs};
use super::nameserver_doh::DohRoutingCtx;
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::routing::RouterFeature;

pub struct TcpNameServer {
    pub server_addr: SocketAddr,
    pub timeout: Duration,
    tag: Option<String>,
    routing: Option<Arc<OnceLock<DohRoutingCtx>>>,
    client_ip: Option<IpAddr>,
}

impl TcpNameServer {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(5),
            tag: None,
            routing: None,
            client_ip: None,
        }
    }
    pub fn new_local_with_ecs(server_addr: SocketAddr, client_ip: Option<IpAddr>) -> Self {
        let mut s = Self::new(server_addr);
        s.client_ip = client_ip;
        s
    }
    pub fn new_routed(
        server_addr: SocketAddr,
        tag: Option<String>,
        routing: Arc<OnceLock<DohRoutingCtx>>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            server_addr,
            timeout: Duration::from_secs(5),
            tag,
            routing: Some(routing),
            client_ip,
        }
    }
    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            server_addr,
            timeout,
            tag: None,
            routing: None,
            client_ip: None,
        }
    }
    pub fn server_addr(&self) -> SocketAddr { self.server_addr }
}

impl TcpNameServer {
    async fn query_qtype(&self, clean: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
        tokio::time::timeout(self.timeout, self.query_qtype_inner(clean, qtype))
            .await.map_err(|_| Error::Timeout)?
    }

    async fn query_qtype_inner(&self, clean: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
        let query = try_build_dns_query_with_ecs(clean, qtype, self.client_ip)?;
        let mut routed_stream = None;
        if let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) {
            let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
            let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
            let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
            if matches!(picked, "block" | "blackhole") {
                return Err(Error::Protocol(format!("TCP DNS server '{}' blocked by routing rule", self.server_addr)));
            }
            if !matches!(picked, "direct" | "freedom" | "dns") && let Some(outbound) = ctx.outbounds.get(picked)
            {
                routed_stream = Some(outbound.connect(&session).await?);
            }
        }
        let mut stream: BoxStream = match routed_stream {
            Some(s) => s,
            None => crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(self.server_addr).await?,
        };
        let query_len = u16::try_from(query.len())
            .map_err(|_| Error::Protocol("DNS query exceeds TCP frame size".into()))?;
        stream.write_all(&query_len.to_be_bytes()).await?;
        stream.write_all(&query).await?;
        stream.flush().await?;
        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let response_len = u16::from_be_bytes(resp_len_buf) as usize;
        if response_len < 12 { return Err(Error::Protocol("DNS TCP frame is shorter than a header".into())); }
        let mut resp = vec![0u8; response_len];
        stream.read_exact(&mut resp).await?;
        parse_dns_response_for_query(&resp, &query)
    }
}

#[async_trait]
impl NameServer for TcpNameServer {
    fn name(&self) -> &str { "tcp" }
    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else { return false; };
        let dest = Destination::from_ip_port(self.server_addr.ip(), self.server_addr.port());
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), dest);
        !matches!(ctx.router.pick_outbound(&session).unwrap_or("direct"), "direct" | "freedom" | "dns" | "block" | "blackhole")
    }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.query_ip_with_opt(domain, true, false).await.map(|(ips, _)| ips)
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        query_ip_families(domain, ipv4, ipv6, |qtype| self.query_qtype(domain, qtype)).await
    }
}
