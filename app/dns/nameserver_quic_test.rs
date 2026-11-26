#[cfg(test)]
mod tests {
    use super::super::nameserver::NameServer;
    use super::super::nameserver_quic::QuicNameServer;

    #[test]
    fn test_quic_nameserver_creation() {
        let quic = QuicNameServer::new("dns.adguard.com:853");
        assert_eq!(quic.url(), "dns.adguard.com:853");
    }

    #[tokio::test]
    async fn dns_wire_quic_does_not_silently_use_system_dns() {
        let quic = QuicNameServer::new("127.0.0.1:853");
        let error = quic.query_ip("localhost").await.unwrap_err();
        assert!(error.to_string().contains("DNS-over-QUIC transport is not implemented"));
    }
}
