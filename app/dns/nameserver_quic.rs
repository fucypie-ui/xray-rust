use crate::app::dns::nameserver::NameServer;
use crate::common::errors::{Error, Result};
use async_trait::async_trait;
use std::net::IpAddr;

pub const NEXT_PROTO_DOQ: &str = "doq";

pub struct QuicNameServer {
    name: String,
    url: String,
}

impl QuicNameServer {
    pub fn new(url: impl Into<String>) -> Self {
        let u = url.into();
        Self {
            name: format!("quic://{}", u),
            url: u,
        }
    }
    pub fn url(&self) -> &str { &self.url }
}

#[async_trait]
impl NameServer for QuicNameServer {
    fn name(&self) -> &str { &self.name }
    async fn query_ip(&self, _domain: &str) -> Result<Vec<IpAddr>> {
        Err(Error::Protocol(format!("DNS-over-QUIC transport is not implemented for {}", self.url)))
    }
}
