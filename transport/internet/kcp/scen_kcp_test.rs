#[cfg(test)]
mod tests {
    use crate::transport::internet::kcp::{AckSegment, DataSegment, KcpConnection};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    #[test]
    fn test_kcp_data_segment_roundtrip() {
        let payload = b"Hello mKCP Segment Payload!";
        let seg = DataSegment::new(0x1234, 42, payload.to_vec());
        let mut buf = [0u8; 128];
        let len = seg.serialize(&mut buf).unwrap();
        assert_eq!(len, 18 + payload.len());

        let decoded = DataSegment::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.conv, 0x1234);
        assert_eq!(decoded.number, 42);
        assert_eq!(decoded.sending_next, 43);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_kcp_ack_segment_roundtrip() {
        let mut ack = AckSegment::new(0x5678, 100);
        ack.put_number(100);
        let mut buf = [0u8; 64];
        let len = ack.serialize(&mut buf).unwrap();
        assert_eq!(len, 17 + 4);

        let decoded = AckSegment::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.conv, 0x5678);
        assert_eq!(decoded.number_list, vec![100]);
    }

    #[tokio::test]
    async fn test_kcp_connection_arq_ack() {
        let s1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let s2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr1 = s1.local_addr().unwrap();
        let addr2 = s2.local_addr().unwrap();
        s1.connect(addr2).await.unwrap();
        s2.connect(addr1).await.unwrap();

        let conn1 = KcpConnection::new(101, s1.clone());
        let conn2 = KcpConnection::new(101, s2.clone());

        let payload = b"Reliable packet over KCP";
        conn1.send_data(payload).await.unwrap();

        let mut buf = [0u8; 1024];
        let count = tokio::time::timeout(std::time::Duration::from_secs(2), conn2.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..count], payload);
        tokio::time::timeout(std::time::Duration::from_secs(2), conn1.flush()).await.unwrap().unwrap();
        conn1.cancel().await;
        conn2.cancel().await;
    }
}
