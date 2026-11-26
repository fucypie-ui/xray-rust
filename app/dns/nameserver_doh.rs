use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use crate::app::dns::hosts::StaticHosts;
use crate::app::dns::nameserver::{NameServer, parse_dns_response_for_query, query_ip_families, try_build_dns_query_with_ecs};
use crate::app::router::Router;
use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::protocol::SessionContext;
use crate::features::outbound::OutboundHandler;
use crate::features::routing::RouterFeature;
use crate::transport::internet::tls::tls::TlsClient;

const MAX_DOH_RESPONSE_LEN: usize = 65536;

pub struct DohRoutingCtx {
    pub router: Router,
    pub outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    pub hosts: Arc<StaticHosts>,
}

pub struct DohNameServer {
    name: String,
    url: String,
    timeout: Duration,
    tag: Option<String>,
    routing: Option<Arc<OnceLock<DohRoutingCtx>>>,
    client_ip: Option<IpAddr>,
    h2_client: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl DohNameServer {
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout: Duration::from_secs(8),
            tag: None,
            routing: None,
            client_ip: None,
            h2_client: Arc::new(Mutex::new(None)),
        }
    }
    pub fn new_local_with_ecs(url: impl Into<String>, client_ip: Option<IpAddr>) -> Self {
        let mut s = Self::new(url);
        s.client_ip = client_ip;
        s
    }
    pub fn new_routed(
        url: impl Into<String>,
        tag: Option<String>,
        routing: Arc<OnceLock<DohRoutingCtx>>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout: Duration::from_secs(8),
            tag,
            routing: Some(routing),
            client_ip,
            h2_client: Arc::new(Mutex::new(None)),
        }
    }
    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        let u = url.into();
        Self {
            name: format!("doh://{}", u),
            url: u,
            timeout,
            tag: None,
            routing: None,
            client_ip: None,
            h2_client: Arc::new(Mutex::new(None)),
        }
    }
    pub fn url(&self) -> &str { &self.url }
    fn parse_url(&self) -> (bool, String, u16, String) {
        let clean = self.url.trim();
        let is_https = !clean.starts_with("http://");
        let def_port = if is_https { 443 } else { 80 };
        let rest = clean.strip_prefix("https://").or_else(|| clean.strip_prefix("http://")).unwrap_or(clean);
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/dns-query"),
        };
        let (host, port) = if let Some(after_l) = host_port.strip_prefix('[')
            && let Some((h, tail)) = after_l.split_once(']')
        {
            let p = tail.strip_prefix(':').and_then(|s| s.parse().ok()).unwrap_or(def_port);
            (h, p)
        } else if let Some((h, p_str)) = host_port.split_once(':') {
            (h, p_str.parse().unwrap_or(def_port))
        } else {
            (host_port, def_port)
        };
        (is_https, host.to_string(), port, if path.is_empty() { "/dns-query" } else { path }.to_string())
    }
    async fn dial_direct(&self, host: &str, port: u16, hosts: Option<&StaticHosts>) -> Result<BoxStream> {
        let mut addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else if let Some(ips) = hosts.and_then(|h| h.lookup(host)) {
            ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()
        } else { Vec::new() };
        if addrs.is_empty() {
            addrs.extend(tokio::net::lookup_host(format!("{}:{}", host, port)).await.map_err(Error::Io)?);
        }
        let mut last_err = None;
        for addr in addrs {
            match pingora_timeout::timeout(self.timeout, crate::app::pingora_bridge::PingoraCoreConnector::dial_tcp(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => return Err(Error::Timeout),
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound, format!("Failed to connect to {}:{}", host, port),
        ))))
    }
    async fn dial_transport(&self, host: &str, port: u16) -> Result<BoxStream> {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else {
            return self.dial_direct(host, port, None).await;
        };
        let addr = host.parse::<IpAddr>().map(Address::ip).unwrap_or_else(|_| Address::Domain(host.to_string()));
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), Destination::new(addr, port));
        let picked = ctx.router.pick_outbound(&session).unwrap_or("direct");
        if matches!(picked, "block" | "blackhole") {
            return Err(Error::Protocol(format!("DoH server '{}' blocked by routing rule", self.url)));
        }
        if !matches!(picked, "direct" | "freedom" | "dns") && let Some(outbound) = ctx.outbounds.get(picked)
        {
            return pingora_timeout::timeout(self.timeout, outbound.connect(&session))
                .await.map_err(|_| Error::Protocol(format!("DoH outbound '{}' connect timeout", picked)))?;
        }
        self.dial_direct(host, port, Some(&ctx.hosts)).await
    }
    async fn get_or_connect_h2(&self, host: &str, port: u16) -> Result<h2::client::SendRequest<Bytes>> {
        let mut guard = self.h2_client.lock().await;
        if let Some(existing) = guard.as_ref() {
            if existing.clone().ready().await.is_ok() { return Ok(existing.clone()); }
            *guard = None;
        }
        let tcp_stream = self.dial_transport(host, port).await?;
        let tls_client = TlsClient::new(host, false, vec![b"h2".to_vec()])?;
        let tls_stream = pingora_timeout::timeout(self.timeout, tls_client.connect(host, tcp_stream))
            .await.map_err(|_| Error::Protocol(format!("DoH TLS handshake timeout with '{}'", host)))??;
        let (send_req, h2_conn) = pingora_timeout::timeout(
            self.timeout,
            h2::client::Builder::new()
                .initial_window_size(65536).initial_connection_window_size(262144).handshake(tls_stream),
        )
        .await
        .map_err(|_| Error::Protocol(format!("DoH H2 handshake timeout with '{}'", host)))?
        .map_err(|e| Error::Protocol(format!("DoH H2 handshake failed with '{}': {}", host, e)))?;
        let slot = self.h2_client.clone();
        tokio::spawn(async move {
            let _ = h2_conn.await;
            *slot.lock().await = None;
        });
        *guard = Some(send_req.clone());
        Ok(send_req)
    }
    async fn send_h2_query(
        &self,
        send_req: h2::client::SendRequest<Bytes>,
        host: &str,
        port: u16,
        path: &str,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        let authority = if port == 443 { host.to_string() } else { format!("{}:{}", host, port) };
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{}{}", authority, path))
            .header(http::header::ACCEPT, "application/dns-message")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::USER_AGENT, "xray/dns")
            .body(()).map_err(|e| Error::Protocol(format!("DoH H2 request build error: {}", e)))?;
        let mut ready = pingora_timeout::timeout(self.timeout, send_req.ready())
            .await
            .map_err(|_| Error::Protocol("DoH H2 ready timeout".into()))?
            .map_err(|e| Error::Protocol(format!("DoH H2 ready error: {}", e)))?;
        let (resp_fut, mut send_stream) = ready
            .send_request(req, false).map_err(|e| Error::Protocol(format!("DoH H2 send_request error: {}", e)))?;
        send_stream
            .send_data(Bytes::copy_from_slice(query), true)
            .map_err(|e| Error::Protocol(format!("DoH H2 send_data error: {}", e)))?;
        let resp = pingora_timeout::timeout(self.timeout, resp_fut)
            .await
            .map_err(|_| Error::Protocol("DoH H2 response timeout".into()))?
            .map_err(|e| Error::Protocol(format!("DoH H2 response error: {}", e)))?;
        let status = resp.status();
        let mut content_len = None;
        for value in resp.headers().get_all(http::header::CONTENT_LENGTH) {
            content_len = Some(parse_content_length(value.as_bytes(), content_len)?);
        }
        let mut body_stream = resp.into_body();
        let mut out = Vec::with_capacity(512);
        while let Some(chunk_res) = pingora_timeout::timeout(self.timeout, body_stream.data())
            .await.map_err(|_| Error::Protocol("DoH H2 body read timeout".into()))?
        {
            let chunk = chunk_res.map_err(|e| Error::Protocol(format!("DoH H2 body chunk error: {}", e)))?;
            let length = out.len().checked_add(chunk.len())
                .filter(|length| *length <= MAX_DOH_RESPONSE_LEN)
                .ok_or_else(|| Error::Protocol("DoH H2 response exceeds size limit".into()))?;
            if content_len.is_some_and(|declared| length > declared) {
                return Err(Error::Protocol("DoH H2 body exceeds Content-Length".into()));
            }
            let _ = body_stream.flow_control().release_capacity(chunk.len());
            out.extend_from_slice(&chunk);
        }
        let _ = pingora_timeout::timeout(self.timeout, body_stream.trailers()).await
            .map_err(|_| Error::Protocol("DoH H2 trailers timeout".into()))?
            .map_err(|e| Error::Protocol(format!("DoH H2 trailers error: {}", e)))?;
        if content_len.is_some_and(|declared| out.len() != declared) {
            return Err(Error::Protocol("Incomplete DoH H2 body (Content-Length mismatch)".into()));
        }
        if status != http::StatusCode::OK {
            return Err(Error::Protocol(format!("DoH server responded with HTTP {}", status.as_u16())));
        }
        if out.is_empty() { return Err(Error::Protocol("Invalid or empty DoH H2 response".into())); }
        Ok(out)
    }
    async fn execute_doh(&self, domain: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
        tokio::time::timeout(self.timeout, self.execute_doh_inner(domain, qtype))
            .await.map_err(|_| Error::Timeout)?
    }
    async fn execute_doh_inner(&self, domain: &str, qtype: u16) -> Result<(Vec<IpAddr>, u32)> {
        let (is_https, host, port, path) = self.parse_url();
        let clean = domain.trim_end_matches('.');
        if clean.eq_ignore_ascii_case(&host) {
            return Err(Error::Protocol(format!("DoH server '{}' tries to resolve itself", self.url)));
        }
        let mut query = try_build_dns_query_with_ecs(domain, qtype, self.client_ip)?;
        // Go DoHNameServer.newReqID always returns zero (RFC 8484 section 4.1).
        query[..2].copy_from_slice(&[0, 0]);
        if is_https {
            for attempt in 0..2 {
                let send_req = self.get_or_connect_h2(&host, port).await?;
                match self.send_h2_query(send_req, &host, port, &path, &query).await {
                    Ok(body) => return parse_dns_response_for_query(&body, &query),
                    Err(e) if attempt == 0 => {
                        *self.h2_client.lock().await = None;
                        tracing::debug!("DoH H2 query failed for '{}' on attempt 0 ({}), retrying on fresh H2 conn", clean, e);
                    }
                    Err(e) => return Err(e),
                }
            }
            return Err(Error::Protocol("DoH H2 retry exhausted".into()));
        }
        let mut stream = self.dial_transport(&host, port).await?;
        let host_hdr = if port == 80 { host.clone() } else { format!("{}:{}", host, port) };
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray/dns\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path, host_hdr, query.len()
        );
        pingora_timeout::timeout(self.timeout, async {
            stream.write_all(req.as_bytes()).await?;
            stream.write_all(&query).await?;
            stream.flush().await
        })
        .await.map_err(|_| Error::Timeout)?.map_err(Error::Io)?;
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let (mut header_len, mut content_len, mut is_chunked) = (0, None, false);
        loop {
            let n = pingora_timeout::timeout(self.timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Protocol(format!("DoH HTTP read timeout (buf_len={}, header_len={}, chunked={})", buf.len(), header_len, is_chunked)))?
                .map_err(Error::Io)?;
            if n == 0 {
                if header_len == 0 { return Err(Error::Protocol("Invalid DoH HTTP headers".into())); }
                if is_chunked { return Err(Error::Protocol("Incomplete DoH chunked response".into())); }
                if content_len.is_some() { return Err(Error::Protocol("Incomplete DoH HTTP body".into())); }
                return parse_dns_response_for_query(&buf[header_len..], &query);
            }
            buf.len().checked_add(n).filter(|length| *length <= MAX_DOH_RESPONSE_LEN)
                .ok_or_else(|| Error::Protocol("DoH HTTP response exceeds size limit".into()))?;
            buf.extend_from_slice(&chunk[..n]);
            if header_len == 0 {
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut resp = httparse::Response::new(&mut headers);
                if let httparse::Status::Complete(hlen) = resp.parse(&buf)
                    .map_err(|e| Error::Protocol(format!("Invalid DoH HTTP headers: {}", e)))?
                {
                    header_len = hlen;
                    if let Some(code) = resp.code && code != 200
                    { return Err(Error::Protocol(format!("DoH server responded with HTTP {}", code))); }
                    for h in resp.headers.iter() {
                        if h.name.eq_ignore_ascii_case("content-length") {
                            content_len = Some(parse_content_length(h.value, content_len)?);
                        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                            let encoding = std::str::from_utf8(h.value)
                                .map_err(|_| Error::Protocol("Invalid DoH HTTP Transfer-Encoding".into()))?;
                            if is_chunked || !encoding.trim().eq_ignore_ascii_case("chunked") {
                                return Err(Error::Protocol("Invalid DoH HTTP Transfer-Encoding".into()));
                            }
                            is_chunked = true;
                        }
                    }
                    if is_chunked && content_len.is_some() {
                        return Err(Error::Protocol("Ambiguous DoH HTTP response framing".into()));
                    }
                    if let Some(length) = content_len {
                        header_len.checked_add(length).filter(|end| *end <= MAX_DOH_RESPONSE_LEN)
                            .ok_or_else(|| Error::Protocol("DoH HTTP Content-Length exceeds size limit".into()))?;
                    }
                }
            }
            if header_len > 0 {
                if is_chunked {
                    if let Some(body) = decode_chunked_complete(&buf[header_len..])? {
                        return parse_dns_response_for_query(&body, &query);
                    }
                } else if let Some(length) = content_len {
                    let end = header_len.checked_add(length)
                        .ok_or_else(|| Error::Protocol("DoH HTTP Content-Length overflow".into()))?;
                    if buf.len() >= end { return parse_dns_response_for_query(&buf[header_len..end], &query); }
                }
            }
        }
    }
}

fn parse_content_length(value: &[u8], previous: Option<usize>) -> Result<usize> {
    let invalid = || Error::Protocol("Invalid or conflicting DoH HTTP Content-Length".into());
    let value = std::str::from_utf8(value).map_err(|_| invalid())?.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) { return Err(invalid()); }
    let length = value.parse::<usize>().map_err(|_| invalid())?;
    if length > MAX_DOH_RESPONSE_LEN {
        return Err(Error::Protocol("DoH HTTP Content-Length exceeds size limit".into()));
    }
    if previous.is_some_and(|old| old != length) { return Err(invalid()); }
    Ok(length)
}

fn decode_chunked_complete(input: &[u8]) -> Result<Option<Vec<u8>>> {
    let (mut out, mut pos) = (Vec::new(), 0usize);
    let invalid = || Error::Protocol("Invalid or oversized DoH chunk framing".into());
    loop {
        let rest = input.get(pos..).ok_or_else(invalid)?;
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else { return Ok(None); };
        let line = std::str::from_utf8(&rest[..line_end]).map_err(|_| invalid())?;
        let size = line.split(';').next().ok_or_else(invalid)?.trim();
        if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(invalid()); }
        let chunk_size = usize::from_str_radix(size, 16).map_err(|_| invalid())?;
        pos = pos.checked_add(line_end).and_then(|pos| pos.checked_add(2)).ok_or_else(invalid)?;
        if chunk_size == 0 {
            let mut trailers = [httparse::EMPTY_HEADER; 32];
            return match httparse::parse_headers(&input[pos..], &mut trailers)
                .map_err(|_| invalid())?
            {
                httparse::Status::Complete(_) => Ok(Some(out)),
                httparse::Status::Partial => Ok(None),
            };
        }
        out.len().checked_add(chunk_size).filter(|length| *length <= MAX_DOH_RESPONSE_LEN)
            .ok_or_else(invalid)?;
        let end = pos.checked_add(chunk_size).ok_or_else(invalid)?;
        let next = end.checked_add(2).filter(|end| *end <= MAX_DOH_RESPONSE_LEN).ok_or_else(invalid)?;
        if input.len() < next { return Ok(None); }
        if &input[end..next] != b"\r\n" { return Err(invalid()); }
        out.extend_from_slice(&input[pos..end]);
        pos = next;
    }
}

#[async_trait]
impl NameServer for DohNameServer {
    fn name(&self) -> &str { &self.name }
    fn routes_via_proxy(&self) -> bool {
        let Some(ctx) = self.routing.as_ref().and_then(|c| c.get()) else { return false; };
        let (_, host, port, _) = self.parse_url();
        let addr = host.parse::<IpAddr>().map_or_else(|_| Address::Domain(host), Address::ip);
        let session = SessionContext::new(self.tag.as_deref().unwrap_or("dns"), Destination::new(addr, port));
        !matches!(ctx.router.pick_outbound(&session).unwrap_or("direct"), "direct" | "freedom" | "dns" | "block" | "blackhole")
    }
    async fn query_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.query_ip_with_opt(domain, true, false).await.map(|(ips, _)| ips)
    }
    async fn query_ip_with_opt(&self, domain: &str, ipv4: bool, ipv6: bool) -> Result<(Vec<IpAddr>, u32)> {
        query_ip_families(domain, ipv4, ipv6, |qtype| self.execute_doh(domain, qtype)).await
    }
}

#[cfg(test)]
#[path = "nameserver_doh_h2_test.rs"]
mod h2_tests;
