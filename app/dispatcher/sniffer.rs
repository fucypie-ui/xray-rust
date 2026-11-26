use crate::app::dns::fakedns::FakeDnsHolder;
use crate::common::common::ERR_NO_CLUE;
use crate::common::errors::{Error, Result};
use crate::common::net::Network;
use crate::common::protocol::protocol::err_proto_need_more_data;
use crate::common::protocol::{quic, tls};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffResult {
    pub protocol: String,
    pub domain: String,
}

impl SniffResult {
    pub fn protocol(&self) -> &str { &self.protocol }
    pub fn domain(&self) -> &str { &self.domain }
    pub fn composite_result(domain_res: SniffResult, proto_res: SniffResult) -> Self {
        Self {
            protocol: proto_res.protocol,
            domain: domain_res.domain,
        }
    }
}

type ProtocolSniffer = fn(&[u8]) -> Result<SniffResult>;

pub struct Sniffer {
    fakedns: Option<Arc<FakeDnsHolder>>,
}

impl Sniffer {
    pub fn new(fakedns: Option<Arc<FakeDnsHolder>>) -> Self { Self { fakedns } }
    pub fn new_sniffer(fakedns: Option<Arc<FakeDnsHolder>>) -> Self { Self::new(fakedns) }
    pub fn sniff_metadata(&self, ip: IpAddr) -> Option<SniffResult> {
        self.sniff_ip(ip).map(|domain| SniffResult {
            protocol: "fakedns".into(),
            domain,
        })
    }
    pub fn sniff_ip(&self, ip: IpAddr) -> Option<String> {
        if let Some(fdns) = &self.fakedns {
            match ip {
                IpAddr::V4(ref v4) => fdns.get_domain_for_fake_ip(v4),
                IpAddr::V6(_) => None,
            }
        } else {
            None
        }
    }
    pub fn is_in_fake_ip_pool(&self, ip: &IpAddr) -> bool {
        if let Some(fdns) = &self.fakedns {
            fdns.is_fake_ip(ip)
        } else {
            false
        }
    }
    pub fn sniff(&self, payload: &[u8], network: Network) -> Result<SniffResult> {
        let sniffers: &[ProtocolSniffer] = match network {
            Network::Tcp => &[Self::sniff_http, Self::sniff_tls, Self::sniff_bittorrent],
            Network::Udp => &[Self::sniff_quic, Self::sniff_bittorrent],
        };
        // This Sniffer is shared by connections: candidates stay per call.
        sniff_content(payload, sniffers)
    }
    fn sniff_http(payload: &[u8]) -> Result<SniffResult> {
        if let Some(domain) = Self::sniff_http_host(payload) {
            return Ok(SniffResult { protocol: "http".into(), domain });
        }
        // Preserve existing HTTP extraction (including PATCH/TRACE), while
        // retaining Go beginWithHTTPMethod's incomplete-method/header outcome.
        for method in [b"get".as_slice(), b"post", b"head", b"put", b"delete", b"options", b"connect", b"patch", b"trace"] {
            if payload.len() < method.len() || payload[..method.len()].eq_ignore_ascii_case(method) {
                return Err(no_clue());
            }
        }
        Err(Error::Protocol("not an HTTP method".into()))
    }
    fn sniff_tls(payload: &[u8]) -> Result<SniffResult> {
        match tls::sniff::sniff_tls(payload) {
            Ok(header) => Ok(SniffResult { protocol: header.protocol().into(), domain: header.domain }),
            // Common parsers currently expose Protocol(String), not typed Go
            // sentinels. Translate only failures Go classifies as ErrNoClue.
            Err(Error::Protocol(message)) if matches!(message.as_str(),
                "TLS payload too short" | "incomplete TLS record" |
                "client hello too short" | "invalid session id len" |
                "no cipher suite len" | "no compression method len" |
                "invalid compression method len"
            ) => Err(no_clue()),
            Err(error) => Err(error),
        }
    }
    fn sniff_quic(payload: &[u8]) -> Result<SniffResult> {
        match quic::sniff::sniff_quic(payload) {
            Ok(header) => Ok(SniffResult { protocol: header.protocol().into(), domain: header.domain }),
            Err(_) if payload.is_empty() => Err(no_clue()),
            Err(Error::Protocol(message)) if message == "truncated quic data" && incomplete_quic_packet(payload) => {
                Err(no_clue())
            }
            Err(error) => Err(error),
        }
    }
    fn sniff_bittorrent(payload: &[u8]) -> Result<SniffResult> {
        if payload.len() < 20 { return Err(no_clue()); }
        // Keep the port's existing BitTorrent/uTP recognition on both networks.
        crate::common::protocol::bittorrent::BittorrentSniffer::sniff(payload)
            .map(|protocol| SniffResult { protocol, domain: String::new() })
    }
    pub fn sniff_tls_sni(payload: &[u8]) -> Option<String> {
        tls::sniff::sniff_tls(payload).ok().map(|header| header.domain)
    }
    pub fn is_incomplete_tls_client_hello(payload: &[u8]) -> bool {
        if payload.first() != Some(&0x16) || payload.get(1).is_some_and(|major| *major != 3) { return false; }
        if payload.len() < 5 { return true; }
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        payload.len() < 5 + record_len
    }
    pub fn sniff_http_host(payload: &[u8]) -> Option<String> {
        const METHODS: &[&[u8]] = &[
            b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ", b"TRACE ",
        ];
        if !METHODS.iter().any(|m| payload.starts_with(m)) { return None; }
        let header_end = payload.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(payload.len());
        let text = std::str::from_utf8(&payload[..header_end]).ok()?;
        for line in text.lines().skip(1) {
            if line.as_bytes().get(..5).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"host:")) {
                let host = line[5..].trim();
                let domain = if let Some(rest) = host.strip_prefix('[') {
                    rest.split(']').next()?.trim()
                } else {
                    host.split(':').next()?.trim()
                };
                if !domain.is_empty() { return Some(domain.to_string()); }
            }
        }
        None
    }
    pub fn sniff_quic_sni(payload: &[u8]) -> Option<String> {
        quic::sniff::sniff_quic(payload).ok().map(|header| header.domain)
    }
}

fn sniff_content(payload: &[u8], sniffers: &[ProtocolSniffer]) -> Result<SniffResult> {
    // Match Go Sniff: defer ErrNoClue until all candidates run, but a
    // protocol-matched need-more-data error wins immediately.
    let mut pending = false;
    for sniff in sniffers {
        match sniff(payload) {
            Ok(result) => return Ok(result),
            Err(Error::Protocol(message)) if message == ERR_NO_CLUE => pending = true,
            Err(error) if is_need_more_data(&error) => return Err(error),
            Err(_) => {}
        }
    }
    if pending {
        Err(no_clue())
    } else {
        Err(Error::Protocol("unknown content".into()))
    }
}

fn no_clue() -> Error {
    Error::Protocol(ERR_NO_CLUE.into())
}

fn is_need_more_data(error: &Error) -> bool {
    matches!((error, err_proto_need_more_data()),
        (Error::Protocol(message), Error::Protocol(expected)) if message == &expected)
}

// Go distinguishes a complete packet header with a truncated declared payload
// (ErrNoClue) from a malformed/truncated header (rejected). This framing-only
// probe runs only after the common decoder fails; it can never accept QUIC.
fn incomplete_quic_packet(mut payload: &[u8]) -> bool {
    fn packet_end(payload: &[u8]) -> Option<usize> {
        fn varint(payload: &[u8], pos: &mut usize) -> Option<usize> {
            let first = *payload.get(*pos)?;
            let width = 1usize << (first >> 6);
            let bytes = payload.get(*pos..*pos + width)?;
            let mut value = u64::from(first & 0x3f);
            for byte in &bytes[1..] { value = (value << 8) | u64::from(*byte); }
            *pos += width;
            (value <= 65535).then_some(value as usize)
        }
        let first = *payload.first()?;
        if first & 0xc0 != 0xc0 { return None; }
        let version = u32::from_be_bytes(payload.get(1..5)?.try_into().ok()?);
        let initial_type = match version {
            1 | 0xff00_001d => 0,
            0x6b33_43cf => 1,
            _ => return None,
        };
        let mut pos = 6 + usize::from(*payload.get(5)?);
        pos += 1 + usize::from(*payload.get(pos)?);
        payload.get(..pos)?;
        if (first & 0x30) >> 4 == initial_type {
            let length = varint(payload, &mut pos)?;
            pos += length;
            payload.get(..pos)?;
        }
        let length = varint(payload, &mut pos)?;
        if length < 4 { return None; }
        Some(pos + length)
    }
    while !payload.is_empty() {
        let Some(end) = packet_end(payload) else { return false; };
        if end > payload.len() { return true; }
        // A shared "truncated quic data" error may originate in an earlier
        // authenticated frame, not the last packet header. Do not let a later
        // incomplete packet downgrade that failure to ErrNoClue.
        match quic::sniff::sniff_quic(&payload[..end]) {
            Ok(_) => {}
            Err(error) if is_need_more_data(&error) => {}
            _ => return false,
        }
        payload = &payload[end..];
        let padding = payload.iter().take_while(|byte| **byte == 0).count();
        payload = &payload[padding..];
    }
    false
}

#[cfg(test)]
#[path = "sniffer_wire_test.rs"]
mod wire_test;
