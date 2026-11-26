//! Native dispatch and true packet transport integration (Linux CI only).
use super::{encoding::{BodySecurity, RequestHeader, VmessDatagram, VmessStream}, inbound::Server, outbound::Client};
use crate::{
    common::{errors::{Error, Result}, net::{Address, BoxStream, Destination, datagram::{BoxDatagram, Datagram}}, protocol::{RequestCommand, SessionContext}},
    features::{inbound::{InboundDispatcher, InboundHandler}, outbound::OutboundHandler},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{net::{Ipv4Addr, SocketAddr}, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

struct EchoDispatcher { id: Uuid, target: Destination, lengths: Vec<usize> }
#[async_trait]
impl InboundDispatcher for EchoDispatcher {
    async fn dispatch_stream(&self, mut stream: BoxStream, session: SessionContext) -> Result<()> {
        assert_eq!(session.destination, self.target);
        assert_eq!(session.user.as_ref().unwrap().id, self.id);
        assert!(session.source.is_some());
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await?;
        stream.write_all(&payload).await?;
        stream.shutdown().await?;
        Ok(())
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        assert_eq!(session.destination, self.target);
        assert_eq!(session.user.as_ref().unwrap().id, self.id);
        let remote = session.source.unwrap();
        let source = Destination::udp(remote.ip().into(), remote.port());
        for length in &self.lengths {
            let packet = packets.recv().await?.ok_or(Error::Eof)?;
            assert_eq!(packet.payload.len(), *length);
            assert_eq!(packet.destination, self.target);
            assert_eq!(packet.source, Some(source.clone()));
            packets.send(Datagram {
                payload: packet.payload, source: Some(packet.destination),
                destination: packet.source.unwrap(),
            }).await?;
        }
        packets.close().await
    }
}

#[tokio::test]
async fn native_udp_dispatch_and_outbound_preserve_packets_and_addresses() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for security in ["aes-128-gcm", "chacha20-poly1305"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let id = Uuid::from_bytes([0x67;16]);
            let target = Destination::udp(Address::Domain("dns.example.org".into()), 53);
            let local = Destination::udp(Address::Ipv4(Ipv4Addr::new(127,0,0,7)), 34567);
            let lengths = vec![257, 517, 3000];
            let dispatcher = Arc::new(EchoDispatcher { id, target: target.clone(), lengths: lengths.clone() });
            let server = tokio::spawn(async move {
                let (socket, remote) = listener.accept().await.unwrap();
                Server::new("vmess-native", vec![id]).dispatch_connection(Box::pin(socket), remote, dispatcher).await.unwrap();
            });
            let client = Client::new("vmess", Destination::tcp(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port()), id, None, None)
                .with_security(security).unwrap();
            let session = SessionContext::new("test", target.clone());
            assert!(client.connect(&session).await.is_err(), "UDP was returned as a stream");
            let packets = client.connect_datagram(&session).await.unwrap();
            let wrong = Destination::udp(Address::Domain("wrong.example.org".into()), 53);
            assert!(packets.send(Datagram { payload: Bytes::from_static(b"wrong"), source: Some(local.clone()), destination: wrong }).await.is_err());
            assert!(matches!(packets.send(Datagram { payload: Bytes::new(), source: Some(local.clone()), destination: target.clone() }).await, Err(Error::Unsupported(_))));
            for length in lengths {
                let payload = Bytes::from((0..length).map(|index| (index % 251) as u8).collect::<Vec<_>>());
                packets.send(Datagram { payload: payload.clone(), source: Some(local.clone()), destination: target.clone() }).await.unwrap();
                let reply = packets.recv().await.unwrap().unwrap();
                assert_eq!(reply.payload, payload);
                assert_eq!(reply.source, Some(target.clone()));
                assert_eq!(reply.destination, local);
            }
            assert!(packets.recv().await.unwrap().is_none());
            packets.close().await.unwrap();
            server.await.unwrap();
        }
    }).await.expect("native VMess packet dispatch deadlock");
}

#[tokio::test]
async fn empty_udp_packets_are_unsupported_without_closing_the_session() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let target = Destination::udp(Address::Domain("example.org".into()), 53);
        let source = Destination::udp(Address::Ipv4(Ipv4Addr::LOCALHOST), 12345);
        for security in [BodySecurity::Aes128Gcm, BodySecurity::ChaCha20Poly1305] {
            let mut request = RequestHeader::new(Uuid::nil(), RequestCommand::Udp, target.clone());
            request.security = security;
            let (left, right) = tokio::io::duplex(16384);
            let mut client = VmessStream::client(Box::pin(left), request.clone()).unwrap();
            let mut server = VmessStream::server(Box::pin(right), request).unwrap();
            assert!(matches!(client.send_packet(&[]).await, Err(Error::Unsupported(_))));
            assert!(matches!(server.send_packet(&[]).await, Err(Error::Unsupported(_))));
            let client = VmessDatagram::outbound(client, target.clone()).unwrap();
            let server = VmessDatagram::inbound(server, target.clone(), Some(source.clone())).unwrap();
            let empty = Datagram { payload: Bytes::new(), source: Some(source.clone()), destination: target.clone() };
            assert!(matches!(client.send(empty.clone()).await, Err(Error::Unsupported(_))));
            assert!(matches!(server.send(empty).await, Err(Error::Unsupported(_))));
            // A rejected empty packet must neither emit EOF nor advance either
            // body codec. The next ordinary packet must work in both directions.
            let payload = Bytes::from_static(b"packet after rejected empty datagram");
            let packet = Datagram { payload: payload.clone(), source: Some(source.clone()), destination: target.clone() };
            let (sent, received) = tokio::join!(client.send(packet), server.recv());
            sent.unwrap();
            let received = received.unwrap().expect("empty send closed the VMess request direction");
            assert_eq!(received.payload, payload);
            assert_eq!(received.source, Some(source.clone()));
            assert_eq!(received.destination, target);
            let reply = Datagram { payload: payload.clone(), source: Some(target.clone()), destination: source.clone() };
            let (sent, received) = tokio::join!(server.send(reply), client.recv());
            sent.unwrap();
            let received = received.unwrap().expect("empty send closed the VMess response direction");
            assert_eq!(received.payload, payload);
            assert_eq!(received.source, Some(target.clone()));
            assert_eq!(received.destination, source);
            let (left, right) = tokio::join!(client.close(), server.close());
            left.unwrap(); right.unwrap();
        }
    }).await.expect("empty VMess packet rejection corrupted the session");
}

#[tokio::test]
async fn native_tcp_dispatch_carries_authenticated_user_and_context() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let id = Uuid::from_bytes([0x48;16]);
        let target = Destination::tcp(Address::Domain("example.org".into()), 443);
        let dispatcher = Arc::new(EchoDispatcher { id, target: target.clone(), lengths: Vec::new() });
        let (left, right) = tokio::io::duplex(16384);
        let remote: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let task = tokio::spawn(async move {
            Server::new("vmess-native", vec![id]).dispatch_connection(Box::pin(right), remote, dispatcher).await.unwrap();
        });
        let client = Client::new("vmess", target.clone(), id, None, None);
        let mut stream = client.open_session(Box::pin(left), target, RequestCommand::Tcp).await.unwrap();
        stream.write_all(b"native authenticated dispatch").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new(); stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"native authenticated dispatch");
        task.await.unwrap();
    }).await.expect("native VMess TCP dispatch deadlock");
}

#[tokio::test]
async fn native_packet_close_cancels_pending_receive_and_releases_transport() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let target = Destination::udp(Address::Ipv4(Ipv4Addr::LOCALHOST), 53);
        let request = RequestHeader::new(Uuid::nil(), RequestCommand::Udp, target.clone());
        let (left, mut right) = tokio::io::duplex(4096);
        let packets = VmessDatagram::outbound(VmessStream::client(Box::pin(left), request).unwrap(), target).unwrap();
        // Cancel an incomplete response-header read, then start another receive.
        assert!(tokio::time::timeout(Duration::from_millis(5), packets.recv()).await.is_err());
        let cloned = packets.clone();
        let receiver = tokio::spawn(async move { cloned.recv().await });
        tokio::task::yield_now().await;
        packets.close().await.unwrap();
        assert!(receiver.await.unwrap().unwrap().is_none());
        assert!(packets.recv().await.unwrap().is_none());
        packets.close().await.unwrap();
        let mut remaining = Vec::new(); right.read_to_end(&mut remaining).await.unwrap();
        assert!(!remaining.is_empty(), "graceful close omitted the terminal frame");
    }).await.expect("closing VMess packet association retained a pending read");
}

#[tokio::test]
async fn native_packet_adapter_keeps_large_packets_and_rejects_oversize_atomically() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let target = Destination::udp(Address::Domain("example.org".into()), 53);
        let source = Destination::udp(Address::Ipv4(Ipv4Addr::LOCALHOST), 12345);
        for security in [BodySecurity::Aes128Gcm, BodySecurity::ChaCha20Poly1305] {
            let mut request = RequestHeader::new(Uuid::nil(), RequestCommand::Udp, target.clone());
            request.security = security;
            let (left, right) = tokio::io::duplex(32);
            let client = VmessDatagram::outbound(VmessStream::client(Box::pin(left), request.clone()).unwrap(), target.clone()).unwrap();
            let server = VmessDatagram::inbound(VmessStream::server(Box::pin(right), request).unwrap(), target.clone(), Some(source.clone())).unwrap();
            let payload = Bytes::from(vec![0x72; 7000]);
            let packet = Datagram { payload: payload.clone(), source: Some(source.clone()), destination: target.clone() };
            let (sent, received) = tokio::join!(client.send(packet), server.recv());
            sent.unwrap(); let received = received.unwrap().unwrap();
            assert_eq!(received.payload, payload); assert_eq!(received.source, Some(source.clone()));
            assert!(client.send(Datagram { payload: Bytes::from(vec![0;8192]), source: Some(source.clone()), destination: target.clone() }).await.is_err());
            // The failed packet never becomes a shortened application packet.
            assert!(tokio::time::timeout(Duration::from_millis(5), server.recv()).await.is_err());
            drop(client); drop(server);
        }
    }).await.expect("VMess packet backpressure deadlock");
}
