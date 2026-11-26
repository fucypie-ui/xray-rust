#[cfg(test)]
mod tests {
    use crate::common::net::{Address, Destination};
    use crate::common::protocol::SessionContext;
    use crate::features::outbound::OutboundHandler;
    use crate::proxy::wireguard::{Client, WireGuardConfig, WireGuardPeer};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_wireguard_rejects_invalid_keys_before_network_io() {
        let endpoint = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = WireGuardConfig {
            secret_key: "private-key-base64".into(),
            address: vec!["10.0.0.2/32".into()],
            peers: vec![WireGuardPeer {
                public_key: "peer-public-key-base64".into(),
                endpoint: endpoint.local_addr().unwrap().to_string(),
                keepalive: 25,
                ..WireGuardPeer::default()
            }],
            mtu: Some(1420),
            reserved: Some(vec![0, 0, 0]),
            ..WireGuardConfig::default()
        };
        assert!(Client::try_new("wg-out", config.clone()).is_err());
        let client = Client::new("wg-out", config);
        let session = SessionContext::new(
            "socks",
            Destination::new(Address::Domain("example.com".into()), 80),
        );
        assert!(client.start().await.is_err());
        assert!(client.connect(&session).await.is_err());
        let mut packet = [0; 2048];
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), endpoint.recv_from(&mut packet)).await.is_err());
        client.close().await.unwrap();
    }
}
