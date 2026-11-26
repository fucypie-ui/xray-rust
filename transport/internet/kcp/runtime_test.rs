use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::engine::{Engine, State, WriteBlocked};
use super::wire::{self, Segment};
use super::{KcpConfig, KcpDialer, KcpListener, KcpListenerOptions, PlainPacketCodec};

fn small_config() -> KcpConfig {
    KcpConfig { mtu: 200, tti: 10, max_sending_window: 1024, ..KcpConfig::default() }
}

#[test]
fn deterministic_loss_reordering_duplicates_and_fragmentation() {
    let config = small_config().engine_config().unwrap();
    let mut client = Engine::new(77, config);
    let mut server = Engine::new(77, config);
    let payload: Vec<u8> = (0..150_003).map(|n| (n * 37) as u8).collect();
    let mut sent = 0;
    let mut received = Vec::new();
    let mut network: Vec<(u32, bool, Vec<u8>)> = Vec::new();
    let mut ordinal = 0;
    let mut lost = 0;
    let mut duplicated = 0;
    let mut buffer = [0u8; 997];
    for now in (0..120_000u32).step_by(10) {
        let mut later = Vec::new();
        for (due, to_server, packet) in network.drain(..) {
            if due > now { later.push((due, to_server, packet)); continue; }
            let engine = if to_server { &mut server } else { &mut client };
            engine.input(wire::read_segments(&packet), now);
        }
        network = later;
        if sent < payload.len() {
            match client.write(&payload[sent..]) {
                Ok(count) => sent += count,
                Err(WriteBlocked::Full) => {}
                Err(WriteBlocked::Closed) => panic!("session closed at {now}, wrote {sent}"),
            }
        }
        while let Some(count) = server.read(&mut buffer) {
            if count == 0 { break; }
            received.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(received, payload[..received.len()], "delivered unordered bytes at {now}");
        client.flush(now);
        server.flush(now);
        for (to_server, engine) in [(true, &mut client), (false, &mut server)] {
            for packet in std::mem::take(&mut engine.out) {
                ordinal += 1;
                if ordinal % 7 == 0 { lost += 1; continue; }
                let delay = [30, 0, 20, 10][ordinal % 4];
                if ordinal % 11 == 0 {
                    duplicated += 1;
                    network.push((now + delay + 10, to_server, packet.clone()));
                }
                network.push((now + delay, to_server, packet));
            }
        }
        if received == payload && !client.awaits_acknowledgement() {
            assert_eq!(sent, payload.len());
            assert!(lost > 10 && duplicated > 10);
            return;
        }
    }
    panic!("deterministic network timed out: {sent} accepted, {} received", received.len());
}

#[test]
fn ack_batches_cover_more_than_128_segments_and_echo_timestamps() {
    let config = KcpConfig::default().engine_config().unwrap();
    let mut sender = Engine::new(9, config);
    let mut receiver = Engine::new(9, config);
    let payload = vec![0x57; 1332 * 300];
    assert_eq!(sender.write(&payload), Ok(payload.len()));
    for _ in 0..10 {
        sender.flush(17);
        for packet in std::mem::take(&mut sender.out) {
            receiver.input(wire::read_segments(&packet), 30);
        }
    }
    let mut bytes = vec![0; payload.len()];
    assert_eq!(receiver.read(&mut bytes), Some(payload.len()));
    receiver.flush(39);
    let acks: Vec<_> = receiver.out.iter().flat_map(|packet| wire::read_segments(packet))
        .filter_map(|segment| if let Segment::Ack(ack) = segment { Some(ack) } else { None }).collect();
    assert_eq!(acks.iter().map(|ack| ack.numbers.len()).collect::<Vec<_>>(), [128, 128, 44]);
    assert!(acks.iter().all(|ack| ack.timestamp == 17 && ack.receiving_next == 300 && ack.receiving_window == 1076));
    assert_eq!(bytes, payload);
}

#[test]
fn config_rejects_invalid_arithmetic_before_starting_tasks() {
    for config in [
        KcpConfig { mtu: 0, ..KcpConfig::default() },
        KcpConfig { tti: 0, ..KcpConfig::default() },
        KcpConfig { tti: 1001, ..KcpConfig::default() },
        KcpConfig { cwnd_multiplier: 0, ..KcpConfig::default() },
        KcpConfig { max_sending_window: 1, ..KcpConfig::default() },
        KcpConfig { uplink_capacity: u32::MAX, ..KcpConfig::default() },
    ] { assert!(config.validate().is_err()); }
    let config: KcpConfig = serde_json::from_str(r#"{"mtu":1200,"tti":20,"cwndMultiplier":2,"maxSendingWindow":8192}"#).unwrap();
    assert_eq!(config.cwnd_multiplier, 2);
    assert_eq!(config.max_sending_window, 8192);
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn loopback_native_box_stream_fragments_and_returns_both_directions() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let listener = KcpListener::bind_with_config("127.0.0.1:0".parse().unwrap(), small_config(), CancellationToken::new()).await.unwrap();
        let client = KcpDialer::dial_with_config(listener.local_addr().unwrap(), 0x1234, small_config(), CancellationToken::new()).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let payload: Vec<u8> = (0..65_539).map(|n| (n * 19) as u8).collect();
        let expected = payload.clone();
        let task = tokio::spawn(async move {
            let mut stream: crate::common::net::BoxStream = client.into_box_stream();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0u8; 12];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"server-reply");
            stream.shutdown().await.unwrap();
        });
        let (mut stream, peer) = listener.accept_box_stream().await.unwrap();
        assert_eq!(peer, client_addr);
        let mut received = vec![0u8; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        stream.write_all(b"server-reply").await.unwrap();
        stream.flush().await.unwrap();
        task.await.unwrap();
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn timer_retransmits_without_manual_input_or_flush() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let connection = KcpDialer::dial_with_config(sink.local_addr().unwrap(), 61, small_config(), CancellationToken::new()).await.unwrap();
    connection.send_data(b"lost-first-packet").await.unwrap();
    let mut raw = [0u8; 1024];
    let count = tokio::time::timeout(Duration::from_secs(2), sink.recv_from(&mut raw)).await.unwrap().unwrap().0;
    let Segment::Data(first) = wire::read_segments(&raw[..count]).remove(0) else { panic!("expected data"); };
    // Deliberately never ACK the first datagram.
    let count = tokio::time::timeout(Duration::from_secs(2), sink.recv_from(&mut raw)).await.unwrap().unwrap().0;
    let Segment::Data(second) = wire::read_segments(&raw[..count]).remove(0) else { panic!("expected retransmission"); };
    assert_eq!(first.payload, second.payload);
    assert_eq!(first.number, second.number);
    assert!(second.timestamp.wrapping_sub(first.timestamp) >= 100);
    assert_eq!(second.sending_next, 0);
    connection.cancel().await;
}

#[tokio::test]
async fn live_runtime_survives_udp_loss_reordering_and_duplicates() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    tokio::time::timeout(Duration::from_secs(12), async {
        let listener = KcpListener::bind_with_config("127.0.0.1:0".parse().unwrap(), small_config(), CancellationToken::new()).await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_address = relay.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let stop_relay = cancellation.clone();
        let lost = Arc::new(AtomicUsize::new(0));
        let loss_count = lost.clone();
        let proxy = tokio::spawn(async move {
            let mut peer = None;
            let mut ordinal = 0usize;
            let mut queue: Vec<(tokio::time::Instant, std::net::SocketAddr, Vec<u8>)> = Vec::new();
            let mut clock = tokio::time::interval(Duration::from_millis(3));
            let mut raw = [0; 8192];
            loop {
                tokio::select! {
                    biased;
                    _ = stop_relay.cancelled() => break,
                    _ = clock.tick() => {},
                    packet = relay.recv_from(&mut raw) => {
                        let (count, from) = packet.unwrap();
                        let to = if from == server_address {
                            let Some(peer) = peer else { continue; };
                            peer
                        } else { peer = Some(from); server_address };
                        ordinal += 1;
                        // Lose the first DATA, then every ninth datagram.
                        if ordinal == 1 || ordinal % 9 == 0 {
                            loss_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let due = tokio::time::Instant::now() + Duration::from_millis([21, 0, 14, 7][ordinal % 4]);
                        queue.push((due, to, raw[..count].to_vec()));
                        if ordinal % 11 == 0 {
                            queue.push((due + Duration::from_millis(5), to, raw[..count].to_vec()));
                        }
                    }
                }
                let now = tokio::time::Instant::now();
                let mut index = 0;
                while index < queue.len() {
                    if queue[index].0 > now { index += 1; continue; }
                    let (_, to, packet) = queue.swap_remove(index);
                    tokio::select! {
                        biased;
                        _ = stop_relay.cancelled() => return,
                        result = relay.send_to(&packet, to) => { result.unwrap(); }
                    }
                }
            }
        });
        let client = KcpDialer::dial_with_config(relay_address, 104, small_config(), CancellationToken::new()).await.unwrap();
        let payload: Vec<u8> = (0..16_389).map(|n| (n * 13) as u8).collect();
        let expected = payload.clone();
        let exchange = tokio::spawn(async move {
            let mut stream = client.into_stream();
            stream.write_all(&payload).await.unwrap();
            let mut reply = vec![0; payload.len()];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
            stream.shutdown().await.unwrap();
        });
        let (mut server, _) = listener.accept_stream().await.unwrap();
        let mut received = vec![0; expected.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_all(&received).await.unwrap();
        server.flush().await.unwrap();
        exchange.await.unwrap();
        assert!(lost.load(Ordering::Relaxed) > 5);
        cancellation.cancel();
        proxy.await.unwrap();
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn equal_conversations_are_isolated_by_remote_address() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = KcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let a = KcpDialer::dial(address, 7).await.unwrap();
        let b = KcpDialer::dial(address, 7).await.unwrap();
        a.send_data(b"peer-a").await.unwrap();
        b.send_data(b"peer-b").await.unwrap();
        let (first, first_peer) = listener.accept().await.unwrap();
        let (second, second_peer) = listener.accept().await.unwrap();
        assert_ne!(first_peer, second_peer);
        assert_eq!(listener.active_connections(), 2);
        assert!(listener.get_session(7).await.is_none());
        let mut buffer = [0; 16];
        for (connection, peer) in [(&first, first_peer), (&second, second_peer)] {
            let count = connection.recv(&mut buffer).await.unwrap();
            let expected = if peer == a.local_addr().unwrap() { b"peer-a" } else { b"peer-b" };
            assert_eq!(&buffer[..count], expected);
            assert!(listener.get_session_for(peer, 7).await.is_some());
        }
        listener.close().await.unwrap();
        a.cancel().await;
        b.cancel().await;
    }).await.unwrap();
}

#[tokio::test]
async fn cancellation_wakes_blocked_reader_writer_flush_and_accept() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cancellation = CancellationToken::new();
        let connection = KcpDialer::dial_with_config(sink.local_addr().unwrap(), 8, small_config(), cancellation.clone()).await.unwrap();
        let read = connection.clone();
        let reader = tokio::spawn(async move { read.recv(&mut [0; 1]).await });
        let write = connection.clone();
        let writer = tokio::spawn(async move { write.send_data(&[0x42; 8192]).await });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(reader.await.unwrap().is_err());
        assert!(writer.await.unwrap().is_err());
        assert!(connection.flush().await.is_err());
        connection.wait_closed().await;
        assert_eq!(connection.stats().state, State::Terminated);
        let listener_cancel = CancellationToken::new();
        let listener = KcpListener::bind_with_config("127.0.0.1:0".parse().unwrap(), small_config(), listener_cancel.clone()).await.unwrap();
        listener_cancel.cancel();
        assert!(listener.accept().await.is_err());
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn peer_close_delivers_eof_after_accepted_data() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = KcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let client = KcpDialer::dial(listener.local_addr().unwrap(), 19).await.unwrap();
        client.send_data(b"last-bytes").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut stream = server.into_stream();
        let close = tokio::spawn(async move { client.flush().await.unwrap(); client.close().await.unwrap(); client });
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"last-bytes");
        let client = close.await.unwrap();
        client.cancel().await;
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn listener_rejects_invalid_and_unknown_terminate_and_limits_sessions() {
    let listener = KcpListener::bind_with_options(
        "127.0.0.1:0".parse().unwrap(), small_config(), CancellationToken::new(),
        Arc::new(PlainPacketCodec), KcpListenerOptions { max_sessions: 1, accept_backlog: 1, input_backlog: 1 },
    ).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    socket.send_to(&[0, 1, 1], address).await.unwrap();
    let terminate = super::segment::CmdOnlySegment::new(1, super::segment::COMMAND_TERMINATE);
    let mut raw = [0; 16];
    terminate.serialize(&mut raw).unwrap();
    socket.send_to(&raw, address).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept()).await.is_err());
    assert_eq!(listener.active_connections(), 0);
    let client = KcpDialer::dial(address, 1).await.unwrap();
    client.send_data(b"first").await.unwrap();
    let (_connection, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
    let rejected = KcpDialer::dial(address, 2).await.unwrap();
    rejected.send_data(b"second").await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept()).await.is_err());
    assert_eq!(listener.active_connections(), 1);
    listener.close().await.unwrap();
    client.cancel().await;
    rejected.cancel().await;
}

#[tokio::test]
async fn explicit_finalmask_seed_codec_is_applied_on_both_sides() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = small_config();
        let codec = Arc::new(super::LegacyPacketCodec::with_seed("independent-kcp-seed"));
        let listener = KcpListener::bind_with_codec("127.0.0.1:0".parse().unwrap(), config.clone(), CancellationToken::new(), codec.clone()).await.unwrap();
        let client = KcpDialer::dial_with_codec(listener.local_addr().unwrap(), 23, config, CancellationToken::new(), codec).await.unwrap();
        client.send_data(b"encrypted-packet").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut data = [0; 128];
        let count = server.recv(&mut data).await.unwrap();
        assert_eq!(&data[..count], b"encrypted-packet");
        listener.close().await.unwrap();
        client.cancel().await;
    }).await.unwrap();
}

#[tokio::test]
async fn dropping_last_accepted_handle_closes_session_without_map_retention() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = KcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let client = KcpDialer::dial(listener.local_addr().unwrap(), 31).await.unwrap();
        client.send_data(b"delivered").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert_eq!(server.recv(&mut [0; 128]).await.unwrap(), 9);
        drop(server);
        assert_eq!(client.recv(&mut [0; 1]).await.unwrap(), 0);
        listener.close().await.unwrap();
        client.cancel().await;
    }).await.unwrap();
}

#[tokio::test]
async fn close_and_cancel_release_udp_sockets_even_while_handles_remain() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = KcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = KcpDialer::dial(address, 32).await.unwrap();
        let client_address = client.local_addr().unwrap();
        client.send_data(b"allocate-session").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        listener.close().await.unwrap();
        assert!(server.is_terminated());
        // Keep listener and accepted handles alive across the rebind.
        let rebound_listener = UdpSocket::bind(address).await.unwrap();
        client.cancel().await;
        let rebound_client = UdpSocket::bind(client_address).await.unwrap();
        assert_eq!(rebound_listener.local_addr().unwrap(), address);
        assert_eq!(rebound_client.local_addr().unwrap(), client_address);
    }).await.unwrap();
}

#[tokio::test]
async fn configured_adapter_implements_the_global_dialer_trait() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = KcpListener::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let dialer: Arc<dyn crate::transport::internet::dialer::Dialer> = Arc::new(
            super::ConfiguredKcpDialer::new(small_config(), CancellationToken::new()).unwrap(),
        );
        let destination = crate::common::net::Destination::from_ip_port(address.ip(), address.port());
        let mut stream = dialer.dial(&destination).await.unwrap();
        stream.write_all(b"global-dialer").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut data = [0; 64];
        let count = server.recv(&mut data).await.unwrap();
        assert_eq!(&data[..count], b"global-dialer");
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Trace { at: u32, side: String, packets: Vec<String> }
#[derive(Deserialize)]
struct Vector { name: String, hex: String, parsed: usize }
#[derive(Deserialize)]
struct Reference { source: String, vectors: Vec<Vector>, trace: Vec<Trace>, payload: String, received: String, rtos: Vec<u32> }
fn trace_flush(engine: &mut Engine, side: &str, at: u32, trace: &mut Vec<Trace>) -> Vec<Vec<u8>> {
    engine.flush(at);
    let packets = std::mem::take(&mut engine.out);
    trace.push(Trace { at, side: side.to_owned(), packets: packets.iter().map(hex::encode).collect() });
    packets
}
fn trace_deliver(engine: &mut Engine, packets: &[Vec<u8>], at: u32) {
    for packet in packets { engine.input(wire::read_segments(packet), at); }
}

/// Parent Ubuntu CI generates this file with the independent Go helper.
/// No checked-in expected bytes are produced by the Rust implementation.
#[test]
fn go_reference_byte_and_session_vectors() {
    let directory = std::env::var_os("XRAY_KCP_REFERENCE_DIR").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testing/kcp-reference/generated"));
    let raw = std::fs::read(directory.join("kcp-reference.json"))
        .expect("required Go mKCP fixture is missing; run testing/kcp-reference/generate.sh on Ubuntu CI");
    let reference: Reference = serde_json::from_slice(&raw).unwrap();
    assert!(reference.source.contains("67756b3674d56b72c7a7e675e8dcd3f883e1b2f7"));
    for vector in reference.vectors {
        let raw = hex::decode(&vector.hex).unwrap();
        let parsed = wire::read_segments(&raw);
        assert_eq!(parsed.len(), vector.parsed, "{}", vector.name);
        let mut encoded = Vec::new();
        for segment in parsed { segment.encode(&mut encoded); }
        assert!(raw.starts_with(&encoded), "{}", vector.name);
        // Also verify the retained public codec against the same Go bytes.
        let mut rest = raw.as_slice();
        let mut count = 0;
        let mut public_encoded = Vec::new();
        while let Some((segment, remaining)) = super::segment::read_segment(rest) {
            count += 1;
            let mut packet = vec![0; segment.byte_size()];
            let length = segment.serialize(&mut packet).unwrap();
            public_encoded.extend_from_slice(&packet[..length]);
            rest = remaining;
        }
        assert_eq!(count, vector.parsed, "{} public parser", vector.name);
        assert_eq!(public_encoded, encoded, "{} public encoding", vector.name);
    }
    let config = KcpConfig { mtu: 80, tti: 20, uplink_capacity: 1, downlink_capacity: 1, max_sending_window: 512, ..KcpConfig::default() }.engine_config().unwrap();
    let (mut client, mut server) = (Engine::new(7, config), Engine::new(7, config));
    let payload = hex::decode(reference.payload).unwrap();
    assert_eq!(client.write(&payload), Ok(payload.len()));
    let mut trace = Vec::new();
    let packets = trace_flush(&mut client, "client", 0, &mut trace);
    trace_deliver(&mut server, &[packets[2].clone(), packets[1].clone()], 5);
    let mut received = [0; 512];
    assert_eq!(server.read(&mut received), Some(0));
    let packets = trace_flush(&mut server, "server", 10, &mut trace);
    trace_deliver(&mut client, &packets, 15);
    trace_flush(&mut client, "client", 66, &mut trace);
    let packets = trace_flush(&mut client, "client", 67, &mut trace);
    trace_deliver(&mut server, &packets, 72);
    let count = server.read(&mut received).unwrap();
    let packets = trace_flush(&mut server, "server", 75, &mut trace);
    trace_deliver(&mut client, &packets, 80);
    let packets = trace_flush(&mut client, "client", 85, &mut trace);
    trace_deliver(&mut server, &packets, 86);
    trace_flush(&mut server, "server", 90, &mut trace);
    assert_eq!(trace, reference.trace);
    assert_eq!(hex::encode(&received[..count]), reference.received);
    assert_eq!(&received[..count], payload);
    let mut rtt = super::connection::RoundTripInfo { min_rtt: 20, ..Default::default() };
    let mut rtos = Vec::new();
    for (index, sample) in [40, 80, 20, 100, u32::MAX].into_iter().enumerate() {
        rtt.update(sample, 100 + index as u32);
        rtos.push(rtt.rto);
    }
    assert_eq!(rtos, reference.rtos);
}
