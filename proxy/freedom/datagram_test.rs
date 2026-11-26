use super::*;
use tokio::time::{Duration, timeout};

async fn echo_socket(address: &str, count: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind(address).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        for _ in 0..count {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(socket.send_to(&buffer[..length], peer).await.unwrap(), length);
        }
    });
    (address, task)
}
async fn check_packets(handler: Handler, destination: Destination, expected_remote: SocketAddr) {
    let mut session = SessionContext::new("test", destination.clone());
    session.source = Some("127.0.0.1:34567".parse().unwrap());
    let packets = handler.connect_datagram(&session).await.unwrap();
    let local = Destination::udp("127.0.0.1".parse().unwrap(), 34567);
    for payload in [vec![1], vec![2; 9000], Vec::new()] {
        packets.send(Datagram { payload: payload.clone().into(), source: Some(local.clone()), destination: destination.clone() }).await.unwrap();
        let received = timeout(Duration::from_secs(5), packets.recv()).await.unwrap().unwrap().unwrap();
        assert_eq!(received.payload.as_ref(), payload.as_slice());
        assert_eq!(received.source, Some(Destination::udp(expected_remote.ip().into(), expected_remote.port())));
        assert_eq!(received.destination, local);
    }
    assert!(matches!(packets.send(Datagram { payload: vec![0; MAX_DATAGRAM_SIZE + 1].into(), source: None, destination }).await, Err(Error::BufferOverflow)));
    packets.close().await.unwrap();
    assert!(packets.recv().await.unwrap().is_none());
}
#[tokio::test]
async fn direct_udp_ipv4_preserves_independent_packets_empty_packets_and_reply_endpoints() {
    let (address, echo) = echo_socket("127.0.0.1:0", 3).await;
    check_packets(Handler::new("direct"), Destination::udp(address.ip().into(), address.port()), address).await;
    echo.await.unwrap();
}
#[tokio::test]
async fn direct_udp_domain_uses_explicit_ipv4_strategy() {
    let (address, echo) = echo_socket("127.0.0.1:0", 3).await;
    check_packets(Handler::new("direct").with_strategy(DomainStrategy::UseIPv4), Destination::udp(Address::Domain("localhost".into()), address.port()), address).await;
    echo.await.unwrap();
}
#[tokio::test]
async fn direct_udp_ipv6_preserves_packet_source_and_local_destination() {
    // Linux CI is expected to provide IPv6 loopback; do not silently skip it.
    let (address, echo) = echo_socket("[::1]:0", 3).await;
    check_packets(Handler::new("direct"), Destination::udp(address.ip().into(), address.port()), address).await;
    echo.await.unwrap();
}
#[tokio::test]
async fn direct_udp_one_association_can_target_multiple_ipv4_and_ipv6_endpoints() {
    let (v4, a) = echo_socket("127.0.0.1:0", 1).await;
    let (v6, b) = echo_socket("[::1]:0", 1).await;
    let session = SessionContext::new("test", Destination::udp(v4.ip().into(), v4.port()));
    let packets = Handler::new("direct").connect_datagram(&session).await.unwrap();
    for (index, remote) in [v4, v6].into_iter().enumerate() {
        let local = Destination::udp("127.0.0.1".parse().unwrap(), 30000 + index as u16);
        packets.send(Datagram { payload: vec![index as u8; 64].into(), source: Some(local.clone()), destination: Destination::udp(remote.ip().into(), remote.port()) }).await.unwrap();
        let reply = timeout(Duration::from_secs(5), packets.recv()).await.unwrap().unwrap().unwrap();
        assert_eq!(reply.destination, local);
        assert_eq!(reply.source, Some(Destination::udp(remote.ip().into(), remote.port())));
        assert_eq!(reply.payload.as_ref(), &[index as u8; 64]);
    }
    packets.close().await.unwrap();
    a.await.unwrap(); b.await.unwrap();
}
