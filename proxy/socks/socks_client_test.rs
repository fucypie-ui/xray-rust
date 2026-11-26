#[cfg(test)]
mod tests {
    use crate::common::net::{Address, Destination, Network};
    use crate::common::protocol::SessionContext;
    use crate::features::inbound::InboundHandler;
    use crate::features::outbound::OutboundHandler;
    use crate::proxy::socks::{Client, Server};
    use crate::proxy::socks::protocol::SocksProtocol;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_socks5_client_and_server_handshake() {
        let server = Server::new("socks-in");
        let (client_stream, server_stream) = tokio::io::duplex(256);

        let target = Destination {
            network: Network::Tcp,
            address: Address::Domain("www.example.com".to_string()),
            port: 443,
        };

        let server_task = tokio::spawn(async move {
            let fake_remote: SocketAddr = "127.0.0.1:54321".parse().unwrap();
            let res = server
                .handle_connection(Box::pin(server_stream), fake_remote)
                .await
                .unwrap();
            assert_eq!(res.session.destination.port, 443);
            assert_eq!(
                res.session.destination.address,
                Address::Domain("www.example.com".to_string())
            );

            let mut stream = res.stream;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client = client_stream;
        SocksProtocol::client_handshake(&mut client, &target)
            .await
            .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_outbound_connects_to_inbound_over_loopback_tcp() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listen_addr = listener.local_addr().unwrap();
            let target = Destination::from_domain_port("example.com", 443);
            let expected_target = target.clone();
            let server_task = tokio::spawn(async move {
                let (stream, remote) = listener.accept().await.unwrap();
                let server = Server::with_auth("socks-in", HashMap::from([("a".into(), "bc".into())]));
                let mut inbound = server.handle_connection(Box::pin(stream), remote).await.unwrap();
                assert_eq!(inbound.session.destination, expected_target);
                assert_eq!(inbound.session.user.unwrap().email, "a");
                assert_eq!(inbound.session.source, Some(remote));
                let mut payload = [0; 4];
                inbound.stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                inbound.stream.write_all(b"pong").await.unwrap();
            });
            let client = Client::with_auth("socks-out", Destination::from(listen_addr), "a", "bc");
            assert_eq!(client.tag(), "socks-out");
            let mut tunnel = client.connect(&SessionContext::new("test", target)).await.unwrap();
            tunnel.write_all(b"ping").await.unwrap();
            tunnel.flush().await.unwrap();
            let mut payload = [0; 4];
            tunnel.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            server_task.await.unwrap();
        }).await.unwrap();
    }
}
