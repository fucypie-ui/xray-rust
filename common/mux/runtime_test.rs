use super::{Frame, MuxConnection, MuxLimits, SessionStatus, serve_mux};
use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination, datagram::{BoxDatagram, Datagram}};
use crate::common::protocol::SessionContext;
use crate::features::inbound::InboundDispatcher;
use async_trait::async_trait;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

#[derive(serde::Deserialize)]
struct GoVector {
    name: String,
    session_id: u16,
    status: u8,
    option: u8,
    host: String,
    port: u16,
    network: String,
    payload_hex: String,
    global_id_hex: String,
    wire_hex: String,
}

#[tokio::test]
async fn frozen_pinned_go_vectors_match_actual_frame_encoding_and_decoding() {
    use sha2::{Digest, Sha256};
    // Mandatory independent Linux-generated fixture: absence is a compile error.
    let fixture = include_bytes!("../../testing/mux-reference/generated/mux-vectors.jsonl");
    assert_eq!(hex::encode(Sha256::digest(fixture)), "dd2496a796d24a860f55ac9f251e73664ccd8aa2de22e2cfa2614b0d670261c3", "verified Go mux fixture changed");
    let vectors: Vec<GoVector> = std::str::from_utf8(fixture).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(vectors.len(), 12);
    for vector in vectors {
        let target = match vector.network.as_str() {
            "tcp" => Some(Destination::tcp(vector.host.parse().unwrap(), vector.port)),
            "udp" => Some(Destination::udp(vector.host.parse().unwrap(), vector.port)),
            "" => None,
            other => panic!("unknown Go fixture network {other}"),
        };
        let expected = Frame {
            session_id: vector.session_id,
            status: SessionStatus::from_u8(vector.status).unwrap(),
            option: vector.option, target,
            global_id: hex::decode(&vector.global_id_hex).unwrap().try_into().unwrap(),
            payload: hex::decode(&vector.payload_hex).unwrap(),
        };
        let wire = hex::decode(&vector.wire_hex).unwrap();
        let mut encoded = Vec::new();
        expected.encode(&mut encoded).await.unwrap();
        assert_eq!(encoded, wire, "Rust encode differs from Go: {}", vector.name);
        let mut input = wire.as_slice();
        let decoded = Frame::decode(&mut input).await.unwrap();
        assert_eq!(decoded, expected, "Rust decode differs from Go: {}", vector.name);
        assert!(input.is_empty(), "unconsumed bytes in {}", vector.name);
    }
}

struct DropNotice(Arc<AtomicUsize>);
impl Drop for DropNotice { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
struct Echo {
    entered: mpsc::UnboundedSender<SessionContext>,
    dropped: Arc<AtomicUsize>,
}
#[async_trait]
impl InboundDispatcher for Echo {
    async fn dispatch_stream(&self, mut stream: BoxStream, session: SessionContext) -> Result<()> {
        let _drop = DropNotice(self.dropped.clone());
        let _ = self.entered.send(session);
        let mut buffer = vec![0; 8192];
        loop {
            let size = stream.read(&mut buffer).await?;
            if size == 0 { return Ok(()); }
            stream.write_all(&buffer[..size]).await?;
            stream.flush().await?;
        }
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        let _drop = DropNotice(self.dropped.clone());
        let _ = self.entered.send(session);
        while let Some(packet) = packets.recv().await? {
            let destination = packet.source.unwrap_or_else(|| packet.destination.clone());
            packets.send(Datagram { payload: packet.payload, source: Some(packet.destination), destination }).await?;
        }
        Ok(())
    }
}
fn target(port: u16, udp: bool) -> Destination {
    if udp { Destination::udp("127.0.0.1".parse().unwrap(), port) }
    else { Destination::tcp("127.0.0.1".parse().unwrap(), port) }
}
fn context() -> SessionContext {
    let mut session = SessionContext::new("mux-in", target(0, false));
    session.source = Some("127.0.0.1:32100".parse().unwrap());
    session.user = Some(crate::common::protocol::User::with_email(uuid::Uuid::from_u128(7), "mux@example.test", 3));
    session
}
fn echo() -> (Arc<Echo>, mpsc::UnboundedReceiver<SessionContext>) {
    let (entered, receiver) = mpsc::unbounded_channel();
    (Arc::new(Echo { entered, dropped: Arc::new(AtomicUsize::new(0)) }), receiver)
}

#[tokio::test]
async fn concurrent_tcp_and_udp_sessions_preserve_bytes_packets_and_metadata() {
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let (dispatcher, mut entered) = echo();
    let server = tokio::spawn(serve_mux(Box::pin(server_stream), context(), dispatcher.clone()));
    let client = MuxConnection::new(Box::pin(client_stream), MuxLimits::default()).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..16 {
        let client = client.clone();
        tasks.spawn(async move {
            let mut stream = client.open_stream(target(10000 + index, false)).await.unwrap();
            let payload = vec![index as u8; 11000 + usize::from(index)];
            stream.write_all(&payload).await.unwrap();
            let mut echoed = vec![0; payload.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        });
    }
    for index in 0..8 {
        let client = client.clone();
        tasks.spawn(async move {
            let packets = client.open_datagram(target(20000 + index, true)).await.unwrap();
            let source = target(32100 + index, true);
            for (payload, destination) in [(vec![index as u8], target(20000 + index, true)), (vec![9; 8192], target(21000 + index, true)), (Vec::new(), target(22000 + index, true))] {
                packets.send(Datagram { payload: payload.clone().into(), source: Some(source.clone()), destination: destination.clone() }).await.unwrap();
                let reply = packets.recv().await.unwrap().unwrap();
                assert_eq!(reply.payload.as_ref(), payload.as_slice());
                assert_eq!(reply.source, Some(destination));
                assert_eq!(reply.destination, source);
            }
            packets.close().await.unwrap();
        });
    }
    timeout(WAIT, async { while let Some(result) = tasks.join_next().await { result.unwrap(); } }).await.unwrap();
    for _ in 0..24 {
        let session = timeout(WAIT, entered.recv()).await.unwrap().unwrap();
        assert_eq!(session.inbound_tag, "mux-in");
        assert_eq!(session.user.as_ref().unwrap().email, "mux@example.test");
        assert_eq!(session.user.as_ref().unwrap().level, 3);
        assert_eq!(session.source, context().source);
        assert_eq!(session.original_destination, Some(session.destination.clone()));
    }
    client.close();
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
    assert_eq!(dispatcher.dropped.load(Ordering::SeqCst), 24);
}

#[tokio::test]
async fn aborting_carrier_owns_and_cancels_stalled_connection_children() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (dispatcher, mut entered) = echo();
    let server = tokio::spawn(serve_mux(Box::pin(server_stream), context(), dispatcher.clone()));
    let client = MuxConnection::new(Box::pin(client_stream), MuxLimits::default()).unwrap();
    let mut streams = Vec::new();
    for index in 0..4 {
        streams.push(client.open_stream(target(1000 + index, false)).await.unwrap());
        timeout(WAIT, entered.recv()).await.unwrap().unwrap();
    }
    client.close();
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
    assert_eq!(dispatcher.dropped.load(Ordering::SeqCst), 4);
    for mut stream in streams {
        let mut byte = [0];
        assert_eq!(timeout(WAIT, stream.read(&mut byte)).await.unwrap().unwrap(), 0);
    }
}

#[tokio::test]
async fn local_eof_closes_one_session_without_closing_other_sessions() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (dispatcher, mut entered) = echo();
    let server = tokio::spawn(serve_mux(Box::pin(server_stream), context(), dispatcher.clone()));
    let client = MuxConnection::new(Box::pin(client_stream), MuxLimits::default()).unwrap();
    let mut first = client.open_stream(target(1, false)).await.unwrap();
    let mut second = client.open_stream(target(2, false)).await.unwrap();
    for _ in 0..2 { timeout(WAIT, entered.recv()).await.unwrap().unwrap(); }
    first.shutdown().await.unwrap();
    let mut byte = [0];
    assert_eq!(timeout(WAIT, first.read(&mut byte)).await.unwrap().unwrap(), 0);
    second.write_all(b"still alive").await.unwrap();
    let mut output = [0; 11];
    timeout(WAIT, second.read_exact(&mut output)).await.unwrap().unwrap();
    assert_eq!(&output, b"still alive");
    client.close();
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn repeated_new_replaces_child_with_same_wire_id_and_keeps_carrier_alive() {
    let (mut client, server_stream) = tokio::io::duplex(4096);
    let (dispatcher, mut entered) = echo();
    let server = tokio::spawn(serve_mux(Box::pin(server_stream), context(), dispatcher));
    Frame::new_session(42, target(1, false), b"first".to_vec()).encode(&mut client).await.unwrap();
    timeout(WAIT, entered.recv()).await.unwrap().unwrap();
    let first = timeout(WAIT, Frame::decode(&mut client)).await.unwrap().unwrap();
    assert_eq!(first.payload, b"first");
    Frame::new_session(42, target(2, false), b"second".to_vec()).encode(&mut client).await.unwrap();
    timeout(WAIT, entered.recv()).await.unwrap().unwrap();
    let second = timeout(WAIT, Frame::decode(&mut client)).await.unwrap().unwrap();
    assert_eq!(second.status, SessionStatus::Keep);
    assert_eq!(second.payload, b"second");
    Frame::data(42, b"third".to_vec()).encode(&mut client).await.unwrap();
    let third = timeout(WAIT, Frame::decode(&mut client)).await.unwrap().unwrap();
    assert_eq!(third.payload, b"third");
    drop(client);
    timeout(WAIT, server).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn configured_session_limit_is_enforced_before_open_admission() {
    let (client_stream, _server_stream) = tokio::io::duplex(4096);
    let limits = MuxLimits { max_sessions: 1, ..MuxLimits::default() };
    let client = MuxConnection::new(Box::pin(client_stream), limits).unwrap();
    let _first = client.open_stream(target(1, false)).await.unwrap();
    assert!(matches!(client.open_stream(target(2, false)).await, Err(Error::BufferOverflow)));
    client.close();
}

#[tokio::test]
async fn framing_separates_metadata_and_payload_and_rejects_truncation() {
    let frame = Frame::new_session(1, target(443, false), b"abc".to_vec());
    let mut wire = Vec::new();
    frame.encode(&mut wire).await.unwrap();
    assert_eq!(&wire[..2], &[0, 12]);
    assert_eq!(&wire[14..16], &[0, 3]);
    assert_eq!(&wire[16..], b"abc");
    for cut in 1..wire.len() {
        assert!(Frame::decode(&mut &wire[..cut]).await.is_err(), "accepted truncation at {cut}");
    }
    assert!(matches!(Frame::decode(&mut &[][..]).await, Err(Error::Eof)));
    assert!(Frame::decode(&mut &[2, 1][..]).await.is_err());
    let mut bad_network = wire;
    bad_network[6] = 3;
    assert!(Frame::decode(&mut &bad_network[..]).await.is_err());
}
