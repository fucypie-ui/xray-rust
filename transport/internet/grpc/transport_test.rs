use super::*;
use super::encoding::{CustomServiceName, decode_grpc_frame, encode_grpc_frame};
use super::encoding::encoding::{MAX_HUNKS, MAX_MESSAGE, decode_hunk, encode_hunk};
use super::encoding::messages::{Hunk, MultiHunk};
use super::stream::status_trailers;
use crate::common::net::{Address, Destination};
use crate::transport::internet::dialer::Dialer;
use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use prost::Message;
use std::net::SocketAddr;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(20);
fn destination(addr: SocketAddr) -> Destination { Destination::tcp(Address::from(addr.ip()), addr.port()) }
fn payload(n: usize) -> Vec<u8> { (0..n).map(|i| (i * 73 + i / 251 + 19) as u8).collect() }
fn request(path: &str) -> Request<()> {
    Request::builder().method("POST").version(http::Version::HTTP_2)
        .uri(format!("http://gun.test{path}")).header("content-type", "application/grpc")
        .header("te", "trailers").body(()).unwrap()
}
async fn client(addr: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let (send, connection) = h2::client::handshake(TcpStream::connect(addr).await.unwrap()).await.unwrap();
    tokio::spawn(async move { let _ = connection.await; });
    send.ready().await.unwrap()
}
async fn try_send_fragments(send: &mut h2::SendStream<Bytes>, mut bytes: Bytes, fragment: usize) -> std::result::Result<(), ()> {
    while !bytes.is_empty() {
        send.reserve_capacity(fragment.min(bytes.len()));
        let available = futures::future::poll_fn(|cx| send.poll_capacity(cx)).await.ok_or(())?.map_err(|_| ())?;
        if available == 0 { continue; }
        let n = fragment.min(bytes.len()).min(available);
        send.send_data(bytes.split_to(n), false).map_err(|_| ())?;
    }
    Ok(())
}
async fn send_fragments(send: &mut h2::SendStream<Bytes>, bytes: Bytes, fragment: usize) {
    try_send_fragments(send, bytes, fragment).await.unwrap();
}
async fn drain(mut recv: h2::RecvStream) -> (Vec<u8>, Option<HeaderMap>) {
    let mut bytes = Vec::new();
    while let Some(data) = recv.data().await {
        let data = data.unwrap();
        bytes.extend_from_slice(&data);
        recv.flow_control().release_capacity(data.len()).unwrap();
    }
    (bytes, recv.trailers().await.unwrap())
}

#[test]
fn grpc_pinned_paths_and_protobuf_golden_wire() {
    for (name, tun, multi) in [
        ("", "//Tun", "//TunMulti"),
        ("a/b!", "/a%2Fb%21/Tun", "/a%2Fb%21/TunMulti"),
        ("/hello /world!/a|b", "/hello%20/world%21/a", "/hello%20/world%21/b"),
        ("/only", "//only", "//only"),
        ("/svc/é%|x y", "/svc/%C3%A9%25", "/svc/x%20y"),
        ("$&+:=@,;?", "/$&+:=@%2C%3B%3F/Tun", "/$&+:=@%2C%3B%3F/TunMulti"),
    ] {
        let service = CustomServiceName::new(name);
        assert_eq!(service.method_path(), tun);
        assert_eq!(service.multi_method_path(), multi);
    }
    assert_eq!(&encode_hunk(b"abc", false)[..], &[0, 0, 0, 0, 5, 10, 3, b'a', b'b', b'c']);
    let multi = MultiHunk { data: vec![Bytes::from_static(b"a"), Bytes::new(), Bytes::from_static(b"bc")] };
    assert_eq!(multi.encode_to_vec(), b"\x0a\x01a\x0a\x00\x0a\x02bc");
    assert_eq!(decode_hunk(Bytes::from_static(b"\x0a\x01a\x10\x07\x0a\x01b"), false).unwrap(), vec![Bytes::from_static(b"b")]);
    assert!(decode_hunk(Bytes::from_static(b"\x0a\x05x"), false).is_err());
    assert!(decode_hunk(Bytes::from([10, 0].repeat(MAX_HUNKS + 1)), true).is_err());
    for flag in [1, 2, 255] {
        assert!(decode_grpc_frame(&[flag, 0, 0, 0, 0]).is_err());
    }
    let mut oversized = vec![0]; oversized.extend_from_slice(&((MAX_MESSAGE + 1) as u32).to_be_bytes());
    assert!(decode_grpc_frame(&oversized).is_err());
    assert!(decode_grpc_frame(&[0, 0, 0, 0]).is_err());
}

#[tokio::test]
async fn grpc_unavailable_options_fail_before_network_io() {
    tokio::time::timeout(LIMIT, async {
        let mut cases = Vec::new();
        let base = GrpcConfig::new("GunService");
        for option in 0..8 {
            let mut config = base.clone();
            match option {
                0 => config.idle_timeout = 1,
                1 => config.health_check_timeout = 1,
                2 => config.permit_without_stream = true,
                3 => config.initial_windows_size = -1,
                4 => config.initial_windows_size = 16 * 1024 * 1024 + 1,
                5 => config.user_agent = "chrome".into(),
                6 => config.user_agent.clear(),
                _ => config.user_agent = "edge".into(),
            }
            cases.push(config);
        }
        let unreachable = destination("127.0.0.1:1".parse().unwrap());
        for config in cases {
            assert!(matches!(GrpcDialer::new(config.clone()).dial(&unreachable).await, Err(Error::Unsupported(_))));
            assert!(matches!(GrpcListener::bind("127.0.0.1:0".parse().unwrap(), config).await, Err(Error::Unsupported(_))));
        }
        let invalid = GrpcConfig { authority: "user@example.org".into(), ..base.clone() };
        assert!(matches!(invalid.validate(), Err(Error::Config(_))));
        assert!(serde_json::from_str::<GrpcConfig>(r#"{"compression":"gzip"}"#).is_err());
        assert!(matches!(GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("/svc/same")).await, Err(Error::Config(_))));
        let udp = Destination::udp(Address::from("127.0.0.1".parse::<std::net::IpAddr>().unwrap()), 1);
        assert!(matches!(GrpcDialer::new(base).dial(&udp).await, Err(Error::Unsupported(_))));
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_localhost_hunk_and_multi_half_close_and_large_bidirectional_bytes() {
    tokio::time::timeout(LIMIT, async {
        for service in ["", "custom/service!", "/custom/service/A|B"] {
            let config = GrpcConfig::new(service);
            let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), config.clone()).await.unwrap();
            let address = listener.local_addr().unwrap();
            for multi in [false, true] {
                let dialer = GrpcDialer::new(GrpcConfig { multi_mode: multi, ..config.clone() });
                let mut outgoing = dialer.dial(&destination(address)).await.unwrap();
                let (mut incoming, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let expected = payload(262_151);
                let received = expected.clone();
                let server = tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    incoming.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, received);
                    bytes.reverse();
                    incoming.write_all(&bytes).await.unwrap();
                    incoming.shutdown().await.unwrap();
                    // shutdown is idempotent and the read EOF is stable.
                    incoming.shutdown().await.unwrap();
                });
                outgoing.write_all(&expected).await.unwrap();
                outgoing.shutdown().await.unwrap();
                let mut reply = Vec::new();
                outgoing.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, expected.into_iter().rev().collect::<Vec<_>>());
                assert_eq!(outgoing.read(&mut [0]).await.unwrap(), 0);
                assert!(outgoing.write(b"after shutdown").await.is_err());
                server.await.unwrap();
                drop(outgoing);
            }
            listener.close().await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_fragmented_request_prefix_protobuf_and_multi_entries_over_real_tcp() {
    tokio::time::timeout(LIMIT, async {
        for multi in [false, true] {
            let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("frag")).await.unwrap();
            let mut sender = client(listener.local_addr().unwrap()).await;
            let path = if multi { "/frag/TunMulti" } else { "/frag/Tun" };
            let (response, mut send) = sender.send_request(request(path), false).unwrap();
            let mut wire = encode_grpc_frame(&[]);
            let message = if multi { MultiHunk { data: vec![Bytes::new(), Bytes::from_static(b"a"), Bytes::new(), Bytes::from_static(b"bc")] }.encode_to_vec() }
                else { Hunk { data: Bytes::from_static(b"abc") }.encode_to_vec() };
            wire.extend(encode_grpc_frame(&message));
            let writer = tokio::spawn(async move {
                send_fragments(&mut send, Bytes::from(wire), 1).await;
                send.send_data(Bytes::new(), true).unwrap();
            });
            let (mut accepted, _) = listener.accept().await.unwrap();
            let mut value = Vec::new();
            accepted.read_to_end(&mut value).await.unwrap();
            assert_eq!(value, b"abc");
            accepted.write_all(b"reply").await.unwrap();
            accepted.shutdown().await.unwrap();
            let (wire, trailers) = drain(response.await.unwrap().into_body()).await;
            let (payload, rest) = decode_grpc_frame(&wire).unwrap();
            assert!(rest.is_empty());
            let values = decode_hunk(Bytes::copy_from_slice(payload), multi).unwrap();
            assert_eq!(values.concat(), b"reply");
            assert_eq!(trailers.unwrap()["grpc-status"], "0");
            writer.await.unwrap();
            drop(accepted); drop(sender);
            listener.close().await.unwrap();
        }
    }).await.unwrap();
}

#[derive(Clone)]
struct Reply {
    http_status: u16,
    content_type: &'static str,
    encoding: Option<&'static str>,
    wire: Bytes,
    trailers: Option<HeaderMap>,
    initial: Option<HeaderMap>,
    reset: bool,
}
impl Reply {
    fn ok(wire: Bytes) -> Self {
        Self { http_status: 200, content_type: "application/grpc", encoding: None, wire,
            trailers: Some(status_trailers(0, "")), initial: None, reset: false }
    }
}
async fn raw_server(reply: Reply, path: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), path);
        assert_eq!(request.uri().authority().unwrap(), "gun.reference.invalid:8443");
        assert_eq!(request.headers()["user-agent"], "p0u27-rust");
        let worker = tokio::spawn(async move {
            // Read application bytes BEFORE sending headers. Awaiting response
            // headers in dial() would deadlock this production grpc-go pattern.
            let (body, _) = drain(request.into_body()).await;
            assert_eq!(&decode_hunk(Bytes::copy_from_slice(decode_grpc_frame(&body).unwrap().0), false).unwrap()[0][..], b"request");
            let mut headers = Response::builder().status(reply.http_status)
                .header("content-type", reply.content_type).body(()).unwrap();
            if let Some(encoding) = reply.encoding { headers.headers_mut().insert("grpc-encoding", http::HeaderValue::from_static(encoding)); }
            if let Some(initial) = &reply.initial { headers.headers_mut().extend(initial.clone()); }
            let mut send = respond.send_response(headers, reply.initial.is_some()).unwrap();
            if reply.initial.is_none() {
                if reply.reset { send.send_reset(h2::Reason::CANCEL); return; }
                // Negative responses may be reset as soon as the client has
                // enough bytes to reject them. That is expected cancellation.
                if try_send_fragments(&mut send, reply.wire, 113).await.is_err() { return; }
                if let Some(trailers) = reply.trailers { let _ = send.send_trailers(trailers); }
                else { let _ = send.send_data(Bytes::new(), true); }
            }
        });
        while let Some(next) = connection.accept().await { assert!(next.is_err(), "unexpected second request"); }
        worker.await.unwrap();
    });
    (addr, task)
}
fn raw_config(multi: bool) -> GrpcConfig {
    GrpcConfig { authority: "gun.reference.invalid:8443".into(), user_agent: "p0u27-rust".into(), multi_mode: multi, ..GrpcConfig::new("/escaped space/S|M") }
}

#[tokio::test]
async fn grpc_response_fragmentation_authority_delayed_headers_and_multi_protobuf() {
    tokio::time::timeout(LIMIT, async {
        for multi in [false, true] {
            let expected = payload(131_079);
            let proto = if multi {
                MultiHunk { data: vec![Bytes::new(), Bytes::copy_from_slice(&expected[..1]), Bytes::new(), Bytes::copy_from_slice(&expected[1..])] }.encode_to_vec()
            } else { Hunk { data: Bytes::copy_from_slice(&expected) }.encode_to_vec() };
            let mut wire = encode_grpc_frame(&[]); wire.extend(encode_grpc_frame(&proto));
            let (addr, server) = raw_server(Reply::ok(Bytes::from(wire)), if multi { "/escaped%20space/M" } else { "/escaped%20space/S" }).await;
            let mut stream = GrpcDialer::new(raw_config(multi)).dial(&destination(addr)).await.unwrap();
            stream.write_all(b"request").await.unwrap(); stream.shutdown().await.unwrap();
            let mut value = Vec::new(); stream.read_to_end(&mut value).await.unwrap();
            assert_eq!(value, expected);
            drop(stream); server.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_bad_responses_trailers_status_compression_truncation_and_reset_are_errors() {
    tokio::time::timeout(LIMIT, async {
        let mut cases = Vec::new();
        let ok = Reply::ok(Bytes::new());
        cases.push(Reply { trailers: None, ..ok.clone() });
        cases.push(Reply { trailers: Some(status_trailers(7, "denied: 100% café")), ..ok.clone() });
        cases.push(Reply { wire: encode_hunk(b"partial", false), trailers: Some(status_trailers(7, "late denial")), ..ok.clone() });
        cases.push(Reply { http_status: 503, ..ok.clone() });
        cases.push(Reply { content_type: "text/plain", ..ok.clone() });
        cases.push(Reply { encoding: Some("gzip"), ..ok.clone() });
        cases.push(Reply { wire: Bytes::from_static(&[1, 0, 0, 0, 0]), ..ok.clone() });
        cases.push(Reply { wire: Bytes::from_static(&[2, 0, 0, 0, 0]), ..ok.clone() });
        cases.push(Reply { wire: Bytes::from_static(&[0, 0, 0]), ..ok.clone() });
        cases.push(Reply { wire: Bytes::from_static(&[0, 0, 0, 0, 9, 10, 7, 1]), ..ok.clone() });
        cases.push(Reply { wire: Bytes::from(encode_grpc_frame(&[10, 3, 1])), ..ok.clone() });
        let mut oversized = vec![0]; oversized.extend_from_slice(&((MAX_MESSAGE + 1) as u32).to_be_bytes());
        cases.push(Reply { wire: Bytes::from(oversized), ..ok.clone() });
        let mut duplicate = status_trailers(0, ""); duplicate.append("grpc-status", http::HeaderValue::from_static("0"));
        cases.push(Reply { trailers: Some(duplicate), ..ok.clone() });
        let mut invalid = HeaderMap::new(); invalid.insert("grpc-status", http::HeaderValue::from_static("potato"));
        cases.push(Reply { trailers: Some(invalid), ..ok.clone() });
        for value in ["", "-1", "17", "256"] {
            let mut invalid = HeaderMap::new(); invalid.insert("grpc-status", http::HeaderValue::from_static(value));
            cases.push(Reply { trailers: Some(invalid), ..ok.clone() });
        }
        let mut escaped = status_trailers(7, ""); escaped.insert("grpc-message", http::HeaderValue::from_static("bad%GG"));
        cases.push(Reply { trailers: Some(escaped), ..ok.clone() });
        cases.push(Reply { initial: Some(status_trailers(7, "immediate denial")), ..ok.clone() });
        cases.push(Reply { reset: true, ..ok.clone() });
        for reply in cases {
            let partial = reply.wire == encode_hunk(b"partial", false);
            let (addr, server) = raw_server(reply, "/escaped%20space/S").await;
            let mut stream = GrpcDialer::new(raw_config(false)).dial(&destination(addr)).await.unwrap();
            stream.write_all(b"request").await.unwrap(); stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            assert!(stream.read_to_end(&mut bytes).await.is_err());
            if partial { assert_eq!(bytes, b"partial"); }
            drop(stream); server.await.unwrap();
        }
        // A successful trailers-only response is valid, unlike bare HTTP EOF.
        let (addr, server) = raw_server(Reply { initial: Some(status_trailers(0, "")), ..ok }, "/escaped%20space/S").await;
        let mut stream = GrpcDialer::new(raw_config(false)).dial(&destination(addr)).await.unwrap();
        stream.write_all(b"request").await.unwrap(); stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        drop(stream); server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_rejects_wrong_service_compression_deadline_and_non_grpc_media() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("correct")).await.unwrap();
        let mut sender = client(listener.local_addr().unwrap()).await;
        for case in 0..4 {
            let mut req = request(if case == 0 { "/wrong/Tun" } else { "/correct/Tun" });
            match case {
                1 => { req.headers_mut().insert("grpc-encoding", http::HeaderValue::from_static("gzip")); },
                2 => { req.headers_mut().insert("grpc-timeout", http::HeaderValue::from_static("1S")); },
                3 => { req.headers_mut().insert("content-type", http::HeaderValue::from_static("application/grpc-web")); },
                _ => {}
            }
            let (response, _send) = sender.send_request(req, true).unwrap();
            let response = response.await.unwrap();
            if case == 3 { assert_eq!(response.status(), 415); }
            else {
                assert_eq!(response.status(), 200);
                let (_, trailers) = drain(response.into_body()).await;
                assert_eq!(trailers.unwrap()["grpc-status"], "12");
            }
        }
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_multiple_h2_streams_are_independent_and_drop_cancels_only_one() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("mux")).await.unwrap();
        let mut sender = client(listener.local_addr().unwrap()).await;
        let (first, _send_first) = sender.send_request(request("/mux/Tun"), false).unwrap();
        let (second, mut send_second) = sender.send_request(request("/mux/TunMulti"), false).unwrap();
        let (cancelled, _) = listener.accept().await.unwrap();
        let (mut survivor, _) = listener.accept().await.unwrap();
        let mut reset = first.await.unwrap().into_body();
        drop(cancelled);
        assert!(reset.data().await.unwrap().is_err());
        send_fragments(&mut send_second, encode_hunk(b"still alive", true), 3).await;
        send_second.send_data(Bytes::new(), true).unwrap();
        let mut received = Vec::new(); survivor.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"still alive");
        survivor.write_all(b"ok").await.unwrap(); survivor.shutdown().await.unwrap();
        let (wire, trailers) = drain(second.await.unwrap().into_body()).await;
        assert_eq!(decode_hunk(Bytes::copy_from_slice(decode_grpc_frame(&wire).unwrap().0), true).unwrap().concat(), b"ok");
        assert_eq!(trailers.unwrap()["grpc-status"], "0");
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_client_drop_and_listener_close_wake_pending_reads_and_accept() {
    tokio::time::timeout(LIMIT, async {
        for _ in 0..8 {
            let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("cancel")).await.unwrap();
            let address = listener.local_addr().unwrap();
            let dialer = GrpcDialer::new(GrpcConfig::new("cancel"));
            let outgoing = dialer.dial(&destination(address)).await.unwrap();
            let (mut accepted, _) = listener.accept().await.unwrap();
            drop(outgoing);
            assert!(accepted.read(&mut [0]).await.is_err());
            let mut outgoing = dialer.dial(&destination(address)).await.unwrap();
            let (mut accepted, _) = listener.accept().await.unwrap();
            let (closed, accept) = tokio::join!(listener.close(), listener.accept());
            closed.unwrap();
            // Rebind synchronously before further read/await cleanup, retaining
            // the old listener wrapper and both returned streams.
            // Match Tokio's reuse policy to avoid a TIME_WAIT-only failure.
            let rebound = tokio::net::TcpSocket::new_v4().unwrap();
            rebound.set_reuseaddr(true).unwrap();
            rebound.bind(address).expect("close must release the TCP listener before returning");
            let rebound = rebound.listen(1024).unwrap();
            assert!(matches!(accept, Err(Error::Closed)));
            assert!(accepted.read(&mut [0]).await.is_err());
            assert!(outgoing.read(&mut [0]).await.is_err());
            listener.close().await.unwrap();
            drop(rebound);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_real_h2_tiny_window_blocks_then_resumes_without_application_flush() {
    tokio::time::timeout(LIMIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let expected = payload(257);
        let checked = expected.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut builder = h2::server::Builder::new(); builder.initial_window_size(1);
            let mut connection = builder.handshake::<_, Bytes>(socket).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                let mut send = respond.send_response(Response::builder().header("content-type", "application/grpc").body(()).unwrap(), false).unwrap();
                send_fragments(&mut send, encode_hunk(b"go", false), 7).await;
                let mut recv = request.into_body();
                let first = recv.data().await.unwrap().unwrap();
                seen_tx.send(()).unwrap();
                resume_rx.await.unwrap();
                let mut wire = first.to_vec(); recv.flow_control().release_capacity(first.len()).unwrap();
                let (rest, _) = drain(recv).await; wire.extend(rest);
                let mut decoded = Vec::new(); let mut tail = wire.as_slice();
                while !tail.is_empty() { let (value, rest) = decode_grpc_frame(tail).unwrap(); decoded.extend(decode_hunk(Bytes::copy_from_slice(value), false).unwrap().concat()); tail = rest; }
                assert_eq!(decoded, checked);
                send.send_trailers(status_trailers(0, "")).unwrap();
            });
            while connection.accept().await.is_some() {}
            handler.await.unwrap();
        });
        let mut outgoing = GrpcDialer::new(GrpcConfig::new("tiny")).dial(&destination(address)).await.unwrap();
        let mut greeting = [0; 2]; outgoing.read_exact(&mut greeting).await.unwrap(); assert_eq!(&greeting, b"go");
        let writer = tokio::spawn(async move {
            outgoing.write_all(&expected).await.unwrap(); outgoing.shutdown().await.unwrap();
            outgoing.read_to_end(&mut Vec::new()).await.unwrap();
        });
        seen_rx.await.unwrap();
        assert!(!writer.is_finished(), "writer must wait for receive window credit");
        resume_tx.send(()).unwrap();
        writer.await.unwrap(); server.await.unwrap();
    }).await.unwrap();
}

/// Force the real TCP I/O adapter to split the h2 preface, HPACK headers, DATA,
/// protobuf envelope, and trailers independently from HTTP/2 frame boundaries.
struct Fragmented<T>(T);
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Fragmented<T> {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, out: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        if out.remaining() == 0 { return std::task::Poll::Ready(Ok(())); }
        let mut bytes = [0; 3];
        let n = out.remaining().min(bytes.len());
        let mut small = tokio::io::ReadBuf::new(&mut bytes[..n]);
        let result = std::task::ready!(std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, &mut small));
        match result {
            Ok(()) => { out.put_slice(small.filled()); std::task::Poll::Ready(Ok(())) },
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
}
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Fragmented<T> {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, &data[..data.len().min(2)])
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn grpc_lower_stream_hooks_handle_fragmented_tcp_and_completed_server_drop() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind_over("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("fragments"),
            std::sync::Arc::new(|socket| Box::pin(async move {
                Ok(Box::pin(Fragmented(socket)) as crate::common::net::BoxStream)
            }))).await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = TcpStream::connect(address).await.unwrap();
        let mut outgoing = GrpcDialer::new(GrpcConfig::new("fragments"))
            .dial_over(Box::pin(Fragmented(socket)), &destination(address), false).await.unwrap();
        let (mut incoming, _) = listener.accept().await.unwrap();
        outgoing.write_all(b"request").await.unwrap();
        let mut request = [0; 7]; incoming.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        incoming.write_all(b"response").await.unwrap(); incoming.shutdown().await.unwrap();
        drop(incoming); // Preserve final status even though request is still open.
        let mut response = Vec::new(); outgoing.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        drop(outgoing); listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_malformed_inbound_messages_fail_with_error_status_not_clean_eof() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("bad")).await.unwrap();
        let mut sender = client(listener.local_addr().unwrap()).await;
        let mut oversized = vec![0]; oversized.extend_from_slice(&((MAX_MESSAGE + 1) as u32).to_be_bytes());
        for (wire, code) in [(vec![1, 0, 0, 0, 0], "13"), (vec![0, 0, 0], "13"), (encode_grpc_frame(&[10, 3, 1]), "13"), (oversized, "8")] {
            sender = sender.ready().await.unwrap();
            let (response, mut send) = sender.send_request(request("/bad/Tun"), false).unwrap();
            let writer = tokio::spawn(async move {
                let _ = try_send_fragments(&mut send, Bytes::from(wire), 1).await;
                let _ = send.send_data(Bytes::new(), true);
            });
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
            drop(stream);
            let response = response.await.unwrap();
            let (_, trailers) = drain(response.into_body()).await;
            assert_eq!(trailers.unwrap()["grpc-status"], code);
            writer.await.unwrap();
        }
        listener.close().await.unwrap();
    }).await.unwrap();
}


#[tokio::test]
async fn grpc_cancel_pending_lower_handshake_drops_its_stream() {
    tokio::time::timeout(LIMIT, async {
        let (io, mut peer) = tokio::io::duplex(1);
        let dialer = GrpcDialer::new(GrpcConfig::new("cancel-handshake"));
        let target = destination("127.0.0.1:443".parse().unwrap());
        let mut dialing = Box::pin(dialer.dial_over(Box::pin(io), &target, false));
        futures::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(dialing.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        }).await;
        drop(dialing);
        let mut prefix = Vec::new(); peer.read_to_end(&mut prefix).await.unwrap();
        assert!(prefix.len() <= 1);
    }).await.unwrap();
}


#[tokio::test]
async fn grpc_idle_streams_release_unused_connection_send_credit() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("fair")).await.unwrap();
        let mut sender = client(listener.local_addr().unwrap()).await;
        let mut held = Vec::new();
        for _ in 0..12 {
            sender = sender.ready().await.unwrap();
            let (response, send) = sender.send_request(request("/fair/Tun"), false).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"x").await.unwrap();
            let mut recv = response.await.unwrap().into_body();
            let mut wire = Vec::new();
            while wire.len() < 8 {
                let bytes = recv.data().await.unwrap().unwrap();
                wire.extend_from_slice(&bytes);
                recv.flow_control().release_capacity(bytes.len()).unwrap();
            }
            assert_eq!(decode_hunk(Bytes::copy_from_slice(decode_grpc_frame(&wire).unwrap().0), false).unwrap().concat(), b"x");
            // Leave both halves open: an idle earlier RPC must not prevent the
            // next RPC from sending through the same 65535-byte connection.
            held.push((stream, send, recv));
        }
        drop(held);
        listener.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn grpc_peer_reset_before_dispatch_preserves_other_requests() {
    tokio::time::timeout(LIMIT, async {
        let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("racing-reset")).await.unwrap();
        let mut sender = client(listener.local_addr().unwrap()).await;
        for path in ["/wrong/Tun", "/racing-reset/Tun"] {
            sender = sender.ready().await.unwrap();
            let (response, mut send) = sender.send_request(request(path), false).unwrap();
            send.send_reset(h2::Reason::CANCEL);
            drop(send); drop(response);
        }
        sender = sender.ready().await.unwrap();
        let (response, send) = sender.send_request(request("/racing-reset/Tun"), true).unwrap();
        let mut recv = response.await.unwrap().into_body();
        let (mut surviving, _) = loop {
            let (mut candidate, peer) = listener.accept().await.unwrap();
            match candidate.read(&mut [0]).await {
                Err(_) => continue,
                Ok(0) => break (candidate, peer),
                Ok(n) => panic!("unexpected request payload: {n}"),
            }
        };
        surviving.shutdown().await.unwrap();
        assert!(recv.data().await.is_none());
        assert_eq!(recv.trailers().await.unwrap().unwrap()["grpc-status"], "0");
        drop(send); drop(surviving);
        listener.close().await.unwrap();
    }).await.unwrap();
}


#[tokio::test]
async fn grpc_listener_close_cancels_a_pending_lower_acceptor() {
    tokio::time::timeout(LIMIT, async {
        let (started, ready) = tokio::sync::oneshot::channel();
        let started = std::sync::Arc::new(std::sync::Mutex::new(Some(started)));
        let acceptor: super::hub::LowerStreamAcceptor = std::sync::Arc::new(move |socket| {
            let signal = started.lock().unwrap().take();
            Box::pin(async move {
                if let Some(signal) = signal { let _ = signal.send(()); }
                let result = futures::future::pending::<crate::common::errors::Result<crate::common::net::BoxStream>>().await;
                drop(socket); // Keep the lower socket owned until cancellation.
                result
            })
        });
        let listener = GrpcListener::bind_over("127.0.0.1:0".parse().unwrap(), GrpcConfig::new("lower-cancel"), acceptor).await.unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        ready.await.unwrap();
        listener.close().await.unwrap();
        match socket.read(&mut [0]).await {
            Ok(0) | Err(_) => {},
            Ok(n) => panic!("unexpected bytes from cancelled lower acceptor: {n}"),
        }
    }).await.unwrap();
}
