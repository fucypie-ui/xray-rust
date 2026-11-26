#[cfg(test)]
mod tests {
    use super::super::connection::KcpConnection;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_kcp_connection_lifecycle() {
        let socket1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr1 = socket1.local_addr().unwrap();
        let addr2 = socket2.local_addr().unwrap();
        let client = KcpConnection::with_remote_addr(1024, socket1, Some(addr2));
        let server = KcpConnection::with_remote_addr(1024, socket2, Some(addr1));
        let payload = b"Hello robust KCP ARQ transmission in Rust!";
        client.send_data(payload).await.unwrap();
        let mut output = [0u8; 1024];
        let count = tokio::time::timeout(Duration::from_secs(2), server.recv(&mut output)).await.unwrap().unwrap();
        assert_eq!(&output[..count], payload);
        tokio::time::timeout(Duration::from_secs(2), client.flush()).await.unwrap().unwrap();
        assert_eq!(client.stats().pending_segments, 0);
        client.cancel().await;
        server.cancel().await;
    }
}
