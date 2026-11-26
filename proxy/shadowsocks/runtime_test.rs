use super::{Client, Server, datagram::Codec, runtime};
use crate::{
    common::{errors::{Error, Result}, net::{BoxStream, Destination, Network, datagram::{BoxDatagram, Datagram, MAX_DATAGRAM_SIZE}}, protocol::{SessionContext, User}},
    features::{inbound::{InboundDispatcher, InboundHandler}, outbound::OutboundHandler},
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use shadowsocks::{config::ServerType, relay::tcprelay::crypto_io::{EncryptedWriter, StreamType}};
use std::{io, net::SocketAddr, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf}, net::{TcpListener, UdpSocket}};
use crate::transport::internet::dialer::Dialer as StreamDialer;

const METHODS: [&str; 4] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"];
const PASSWORD: &str = "classic-test-password";
const LIMIT: Duration = Duration::from_secs(30);

fn target() -> Destination { Destination::from_domain_port("example.com", 443) }
fn remote() -> SocketAddr { "127.0.0.1:35000".parse().unwrap() }
fn udp(mut destination: Destination) -> Destination { destination.network = Network::Udp; destination }

// Both directions force short reads/writes and Pending between successful
// operations. Capture the transport bytes, not the decrypted stream bytes.
struct Fragmented<S> {
    inner: S,
    pending_read: bool,
    pending_write: bool,
    input: Arc<Mutex<Vec<u8>>>,
    output: Arc<Mutex<Vec<u8>>>,
}
impl<S> Fragmented<S> {
    fn new(inner: S) -> Self {
        Self { inner, pending_read: false, pending_write: false, input: Arc::default(), output: Arc::default() }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Fragmented<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 { return Poll::Ready(Ok(())); }
        if this.pending_read {
            this.pending_read = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut bytes = [0; 7];
        let length = bytes.len().min(buffer.remaining());
        let mut short = ReadBuf::new(&mut bytes[..length]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut short) {
            Poll::Ready(Ok(())) => {
                this.input.lock().unwrap().extend_from_slice(short.filled());
                buffer.put_slice(short.filled());
                this.pending_read = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmented<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write {
            this.pending_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..bytes.len().min(5)]) {
            Poll::Ready(Ok(length)) => {
                this.output.lock().unwrap().extend_from_slice(&bytes[..length]);
                this.pending_write = true;
                Poll::Ready(Ok(length))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[test]
fn methods_match_go_aliases_and_reject_unwired_modes() {
    for name in [
        "aes-128-gcm", "AEAD_AES_128_GCM", "aes-256-gcm", "aead_aes_256_gcm",
        "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305",
        "xchacha20-poly1305", "AEAD_XCHACHA20_POLY1305", "xchacha20-ietf-poly1305",
    ] {
        assert!(Server::try_new("test", name, "x").is_ok(), "{name}");
        assert!(Client::try_new("test", target(), name, "x").is_ok(), "{name}");
        assert!(super::validator::MethodValidator::is_supported(name));
    }
    for name in ["", "none", "plain", "aes-128-cfb", "2022-blake3-aes-128-gcm", "des-cbc"] {
        assert!(matches!(Server::try_new("test", name, PASSWORD), Err(Error::Unsupported(_))));
        assert!(Client::try_new("test", target(), name, PASSWORD).is_err());
    }
    assert!(Server::try_new("test", METHODS[0], "").is_err());
    assert!(Client::try_new("test", Destination::from_domain_port("host", 0), METHODS[0], PASSWORD).is_err());
    assert!(Server::try_new("test", METHODS[0], PASSWORD).unwrap().with_networks(false, false).is_err());
    assert!(super::is_valid_password(super::protocol::CipherType::Aes128Gcm, "x"));
    assert!(!super::is_valid_password(super::protocol::CipherType::None, PASSWORD));
}

#[tokio::test]
async fn trait_tcp_authenticates_fragmented_io_server_first_and_half_close() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            for destination in [target(), "192.0.2.1:80".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap()] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let user = User::with_email(uuid::Uuid::nil(), "classic@example", 7);
                let server: Arc<dyn InboundHandler> = Arc::new(Server::try_new("classic-in", method, PASSWORD).unwrap().with_user(user));
                let expected = destination.clone();
                // Crosses the 0x3fff record boundary several times.
                let payload: Vec<u8> = (0..50_000).map(|index| (index % 251) as u8).collect();
                let request = payload.clone();
                let worker = tokio::spawn(async move {
                    let (stream, peer) = listener.accept().await.unwrap();
                    let stream = Fragmented::new(stream);
                    let input = stream.input.clone();
                    let output = stream.output.clone();
                    let mut accepted = server.handle_connection(Box::pin(stream), peer).await.unwrap();
                    assert_eq!(accepted.session.destination, expected);
                    assert_eq!(accepted.session.source, Some(peer));
                    assert_eq!(accepted.session.user.as_ref().unwrap().email, "classic@example");
                    assert_eq!(accepted.session.user.as_ref().unwrap().level, 7);
                    // No client payload is needed to finish the target handshake.
                    accepted.stream.write_all(b"server-first greeting").await.unwrap();
                    let mut received = Vec::new();
                    accepted.stream.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, request);
                    accepted.stream.write_all(b"response after client EOF").await.unwrap();
                    accepted.stream.shutdown().await.unwrap();
                    let mut address_bytes = BytesMut::new();
                    runtime::address(&expected).unwrap().write_to_buf(&mut address_bytes);
                    assert!(!input.lock().unwrap().windows(address_bytes.len()).any(|part| part == address_bytes.as_ref()));
                    assert!(!output.lock().unwrap().windows(21).any(|part| part == b"server-first greeting"));
                });
                let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("classic-out", address.into(), method, PASSWORD).unwrap());
                let mut stream = client.connect(&SessionContext::new("test", destination)).await.unwrap();
                let mut greeting = [0; 21];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(&greeting, b"server-first greeting");
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"response after client EOF");
                worker.await.unwrap();
            }
        }
    }).await.unwrap();
}

async fn request_wire(method: &str, destination: Destination, body: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Client::try_new("capture", listener.local_addr().unwrap().into(), method, PASSWORD).unwrap();
    let capture = async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        stream.read_to_end(&mut wire).await.unwrap();
        wire
    };
    let send = async {
        let mut stream = OutboundHandler::connect(&client, &SessionContext::new("test", destination)).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let (wire, ()) = tokio::join!(capture, send);
    wire
}

async fn accept_wire(server: &Server, wire: Vec<u8>) -> Result<(Destination, Vec<u8>)> {
    let (mut sender, stream) = tokio::io::duplex(7);
    let writer = tokio::spawn(async move {
        for part in wire.chunks(3) { sender.write_all(part).await?; }
        sender.shutdown().await
    });
    let result = async {
        let mut accepted = InboundHandler::handle_connection(server, Box::pin(Fragmented::new(stream)), remote()).await?;
        let mut payload = Vec::new();
        accepted.stream.read_to_end(&mut payload).await?;
        Ok((accepted.session.destination, payload))
    }.await;
    let _ = writer.await;
    result
}

async fn raw_stream_wire(method: &str, payload: &[u8]) -> Vec<u8> {
    let config = runtime::account(method, PASSWORD).unwrap();
    let salt = vec![0x45; config.method().salt_len()];
    let mut writer = EncryptedWriter::new(StreamType::Client, config.method(), config.key(), &salt);
    let mut wire = Vec::new();
    futures::future::poll_fn(|cx| writer.poll_write_encrypted(cx, &mut wire, payload)).await.unwrap();
    wire
}

#[tokio::test]
async fn trait_tcp_rejects_replays_wrong_password_tampering_truncation_and_bad_targets() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            let wire = request_wire(method, target(), b"authenticated body").await;
            let config = runtime::account(method, PASSWORD).unwrap();
            let salt_len = config.method().salt_len();
            let server = Server::try_new("in", method, PASSWORD).unwrap();
            let mut bad_tag = wire.clone();
            bad_tag[salt_len + 18] ^= 0x80;
            assert!(accept_wire(&server, bad_tag).await.is_err());
            // Failed authentication must not poison the replay cache.
            assert_eq!(accept_wire(&server, wire.clone()).await.unwrap(), (target(), b"authenticated body".to_vec()));
            assert!(accept_wire(&server, wire.clone()).await.is_err());
            let wrong = Server::try_new("in", method, "different-password").unwrap();
            assert!(accept_wire(&wrong, wire.clone()).await.is_err());
            for length in [0, 1, salt_len - 1, salt_len + 1, salt_len + 19, wire.len() - 1] {
                let server = Server::try_new("in", method, PASSWORD).unwrap();
                assert!(accept_wire(&server, wire[..length].to_vec()).await.is_err(), "{method}: {length}");
            }
            for target in [&[9, 0, 0][..], &[3, 5, b'a'][..], &[1, 127, 0][..], &[3, 0, 0, 80][..]] {
                let server = Server::try_new("in", method, PASSWORD).unwrap();
                let malformed = raw_stream_wire(method, target).await;
                assert!(accept_wire(&server, malformed).await.is_err());
            }
        }
    }).await.unwrap();
}

fn malformed_udp(method: &str, plaintext: &[u8]) -> Vec<u8> {
    let config = runtime::account(method, PASSWORD).unwrap();
    let method = config.method();
    let salt = vec![0x75; method.salt_len()];
    let mut cipher = shadowsocks::crypto::v1::Cipher::new(method, config.key(), &salt);
    let mut body = plaintext.to_vec();
    body.resize(body.len() + method.tag_len(), 0);
    cipher.encrypt_packet(&mut body);
    [salt, body].concat()
}

#[test]
fn udp_engine_authentication_replay_size_and_malformed_address_guards() {
    for method in METHODS {
        let sender = Codec::new(method, PASSWORD, runtime::context(ServerType::Local)).unwrap();
        let receiver = Codec::new(method, PASSWORD, runtime::context(ServerType::Server)).unwrap();
        for destination in [udp(target()), udp("192.0.2.1:53".parse().unwrap()), udp("[2001:db8::1]:53".parse().unwrap())] {
            let wire = sender.encode(&destination, b"").unwrap();
            let mut bad = wire.to_vec();
            *bad.last_mut().unwrap() ^= 1;
            assert!(receiver.decode(&bad).is_err());
            assert_eq!(receiver.decode(&wire).unwrap(), (destination.clone(), Bytes::new()));
            assert!(receiver.decode(&wire).is_err());
            let wrong = Codec::new(method, "wrong", runtime::context(ServerType::Server)).unwrap();
            assert!(wrong.decode(&wire).is_err());
            for length in [0, 1, wire.len() - 1] { assert!(wrong.decode(&wire[..length]).is_err()); }
            assert!(matches!(sender.encode(&destination, &vec![0; MAX_DATAGRAM_SIZE]), Err(Error::BufferOverflow)));
        }
        for malformed in [&[3, 3, b'f', b'o', b'o'][..], &[3, 0, 0, 53][..], &[4, 0][..], &[9, 0, 0][..]] {
            let wire = malformed_udp(method, malformed);
            assert!(receiver.decode(&wire).is_err());
        }
    }
}

struct Echo;
#[async_trait]
impl InboundDispatcher for Echo {
    async fn dispatch_stream(&self, mut stream: BoxStream, _session: SessionContext) -> Result<()> {
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok(())
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, session: SessionContext) -> Result<()> {
        assert_eq!(session.destination.network, Network::Udp);
        while let Some(packet) = packets.recv().await? {
            let reply = Datagram { payload: packet.payload, source: Some(packet.destination), destination: packet.source.unwrap() };
            packets.send(reply).await?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn trait_native_tcp_udp_preserves_packets_sources_cancellation_and_close() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            let server: Arc<dyn InboundHandler> = Arc::new(Server::try_new("native", method, PASSWORD).unwrap().with_networks(true, true).unwrap());
            let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            // Cancelling accept before a packet arrives must preserve binding.
            assert!(tokio::time::timeout(Duration::from_millis(10), listener.accept(Arc::new(Echo))).await.is_err());
            let worker = tokio::spawn(async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept(Arc::new(Echo)) => match accepted {
                            Ok(task) => { children.spawn(task); }
                            Err(Error::Closed) => break,
                            Err(error) => panic!("native accept: {error}"),
                        },
                        completed = children.join_next(), if !children.is_empty() => { completed.unwrap().unwrap().unwrap(); }
                    }
                }
                children.abort_all();
                while children.join_next().await.is_some() {}
            });
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("native", address.into(), method, PASSWORD).unwrap());
            let source = Destination::udp("192.0.2.20".parse().unwrap(), 53000);
            let mut session = SessionContext::new("test", udp(target()));
            session.source = Some(remote());
            let packets = client.connect_datagram(&session).await.unwrap();
            assert!(tokio::time::timeout(Duration::from_millis(10), packets.recv()).await.is_err());
            // Malformed and oversize wire packets cannot kill native accept.
            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            attacker.send_to(&[0; 3], address).await.unwrap();
            for (destination, payload) in [(udp(target()), Bytes::new()), (udp("192.0.2.1:53".parse().unwrap()), Bytes::from_static(b"one")), (udp("[2001:db8::1]:53".parse().unwrap()), Bytes::from_static(b"two"))] {
                packets.send(Datagram { payload: payload.clone(), source: Some(source.clone()), destination: destination.clone() }).await.unwrap();
                let reply = packets.recv().await.unwrap().unwrap();
                assert_eq!(reply.payload, payload);
                assert_eq!(reply.source, Some(destination));
                assert_eq!(reply.destination, source);
            }
            assert!(matches!(packets.send(Datagram { payload: Bytes::new(), source: None, destination: target() }).await, Err(Error::Protocol(_))));
            assert!(matches!(packets.send(Datagram { payload: Bytes::from(vec![0; MAX_DATAGRAM_SIZE]), source: None, destination: udp(target()) }).await, Err(Error::BufferOverflow)));
            let mut stream = client.connect(&SessionContext::new("test", target())).await.unwrap();
            stream.write_all(b"co-bound TCP").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"co-bound TCP");
            let pending = packets.clone();
            let waiting = tokio::spawn(async move { pending.recv().await });
            packets.close().await.unwrap();
            assert!(waiting.await.unwrap().unwrap().is_none());
            assert!(matches!(packets.send(Datagram::new(Bytes::new(), udp(target())).unwrap()).await, Err(Error::Closed)));
            server.close().await.unwrap();
            worker.await.unwrap();
            // All native socket ownership must be released after close/drop.
            let tcp = TcpListener::bind(address).await.unwrap();
            let udp = UdpSocket::bind(address).await.unwrap();
            drop((tcp, udp));
        }
    }).await.unwrap();
}

#[derive(serde::Deserialize, serde::Serialize)]
struct GoFixture {
    go_commit: String,
    method: String,
    password: String,
    destination: String,
    request: String,
    response: String,
    udp: String,
    request_body: String,
    response_body: String,
    udp_body: String,
    #[serde(default)]
    udp_response: Option<String>,
}

async fn response_wire(method: &str, request: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    let (peer, stream) = tokio::io::duplex(11);
    let (mut reader, mut writer) = tokio::io::split(peer);
    let server = Server::try_new("fixture", method, PASSWORD).unwrap();
    let serve = async move {
        let mut accepted = InboundHandler::handle_connection(&server, Box::pin(Fragmented::new(stream)), remote()).await.unwrap();
        let mut request_body = Vec::new();
        accepted.stream.read_to_end(&mut request_body).await.unwrap();
        accepted.stream.write_all(&body).await.unwrap();
        accepted.stream.shutdown().await.unwrap();
    };
    let request = async move { writer.write_all(&request).await.unwrap(); writer.shutdown().await.unwrap(); };
    let capture = async move {
        let mut wire = Vec::new();
        reader.read_to_end(&mut wire).await.unwrap();
        wire
    };
    let ((), (), wire) = tokio::join!(serve, request, capture);
    wire
}

// Run on Linux after generate.sh, then pass the emitted Rust JSONL back to the
// same Go helper. This is explicitly ignored until independent Go bytes exist;
// ordinary Rust round trips are not evidence of Go interoperability.
#[tokio::test]
#[ignore = "requires SS_CLASSIC_GO_VECTORS and SS_CLASSIC_RUST_VECTORS on the Linux runner"]
async fn independent_pinned_go_fixtures_both_directions_through_traits() {
    tokio::time::timeout(LIMIT, async {
        let input = std::env::var("SS_CLASSIC_GO_VECTORS").expect("Go vector JSONL path");
        let output = std::env::var("SS_CLASSIC_RUST_VECTORS").expect("Rust output JSONL path");
        let text = std::fs::read_to_string(input).unwrap();
        let mut methods = std::collections::HashSet::new();
        let mut reverse = String::new();
        for line in text.lines() {
            let mut fixture: GoFixture = serde_json::from_str(line).unwrap();
            assert_eq!(fixture.go_commit, "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7");
            assert_eq!(fixture.password, PASSWORD);
            assert!(METHODS.contains(&fixture.method.as_str()));
            assert!(methods.insert(fixture.method.clone()));
            let expected: Destination = fixture.destination.parse().unwrap();
            let request = hex::decode(&fixture.request).unwrap();
            let body = hex::decode(&fixture.request_body).unwrap();
            let server = Server::try_new("fixture", &fixture.method, PASSWORD).unwrap();
            assert_eq!(accept_wire(&server, request.clone()).await.unwrap(), (expected.clone(), body.clone()));
            let response_body = hex::decode(&fixture.response_body).unwrap();
            let rust_response = response_wire(&fixture.method, request, response_body.clone()).await;

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("fixture", listener.local_addr().unwrap().into(), &fixture.method, PASSWORD).unwrap());
            let go_response = hex::decode(&fixture.response).unwrap();
            let mock_go = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                for fragment in go_response.chunks(3) { stream.write_all(fragment).await.unwrap(); }
                stream.shutdown().await.unwrap();
                request
            });
            let mut stream = client.connect(&SessionContext::new("fixture", expected.clone())).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, response_body);
            let rust_request = mock_go.await.unwrap();

            // Check Go UDP replies through OutboundHandler/DatagramTransport.
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("fixture", socket.local_addr().unwrap().into(), &fixture.method, PASSWORD).unwrap());
            let session = SessionContext::new("fixture", udp(expected.clone()));
            let packets = client.connect_datagram(&session).await.unwrap();
            let udp_body = hex::decode(&fixture.udp_body).unwrap();
            packets.send(Datagram::new(udp_body.clone(), udp(expected.clone())).unwrap()).await.unwrap();
            let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let rust_udp = buffer[..length].to_vec();
            let go_udp = hex::decode(&fixture.udp).unwrap();
            socket.send_to(&go_udp, peer).await.unwrap();
            let reply = packets.recv().await.unwrap().unwrap();
            assert_eq!(reply.payload.as_ref(), udp_body.as_slice());
            assert_eq!(reply.source, Some(udp(expected.clone())));
            assert_eq!(reply.destination, super::datagram::udp_destination(peer));
            packets.close().await.unwrap();

            // Check independent Go UDP input through the native inbound trait.
            let server: Arc<dyn InboundHandler> = Arc::new(Server::try_new("fixture", &fixture.method, PASSWORD).unwrap().with_networks(false, true).unwrap());
            let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            socket.send_to(&go_udp, listener.local_addr().unwrap()).await.unwrap();
            let task = listener.accept(Arc::new(Echo)).await.unwrap();
            let worker = tokio::spawn(task);
            let (length, _) = socket.recv_from(&mut buffer).await.unwrap();
            let rust_udp_response = buffer[..length].to_vec();
            drop(listener);
            worker.await.unwrap().unwrap();
            fixture.request = hex::encode(rust_request);
            fixture.response = hex::encode(rust_response);
            fixture.udp = hex::encode(rust_udp);
            fixture.udp_response = Some(hex::encode(rust_udp_response));
            reverse.push_str(&serde_json::to_string(&fixture).unwrap());
            reverse.push('\n');
        }
        assert_eq!(methods.len(), METHODS.len());
        std::fs::write(output, reverse).unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn trait_outbound_authenticates_responses_and_rejects_replayed_salt() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            let wire = raw_stream_wire(method, b"authenticated response").await;
            let mut malformed = wire.clone();
            *malformed.last_mut().unwrap() ^= 1;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new("out", listener.local_addr().unwrap().into(), method, PASSWORD).unwrap());
            let worker = tokio::spawn(async move {
                for response in [malformed, wire.clone(), wire] {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            for attempt in 0..3 {
                let mut stream = client.connect(&SessionContext::new("test", target())).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut plaintext = Vec::new();
                let result = stream.read_to_end(&mut plaintext).await;
                if attempt == 1 {
                    result.unwrap();
                    assert_eq!(plaintext, b"authenticated response");
                } else {
                    assert!(result.is_err());
                    assert!(plaintext.is_empty());
                }
            }
            worker.await.unwrap();
        }
        let invalid = Client::new("out", target(), "none", PASSWORD);
        assert!(matches!(OutboundHandler::start(&invalid).await, Err(Error::Unsupported(_))));
        assert!(matches!(OutboundHandler::connect(&invalid, &SessionContext::new("test", target())).await, Err(Error::Unsupported(_))));
        let disabled = Server::try_new("in", METHODS[0], PASSWORD).unwrap().with_networks(false, true).unwrap();
        let (_, stream) = tokio::io::duplex(1);
        assert!(matches!(disabled.handle_connection(Box::pin(stream), remote()).await, Err(Error::Unsupported(_))));
    }).await.unwrap();
}

#[tokio::test]
async fn native_bind_failure_and_unpolled_task_drop_release_owned_resources() {
    tokio::time::timeout(LIMIT, async {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let server = Server::try_new("in", METHODS[0], PASSWORD).unwrap().with_networks(true, true).unwrap();
        assert!(server.bind_native(address).await.is_err());
        // A failed UDP bind must release the earlier TCP bind.
        let tcp = TcpListener::bind(address).await.unwrap();
        drop((tcp, occupied));
        let server = Server::try_new("in", METHODS[0], PASSWORD).unwrap().with_networks(false, true).unwrap();
        let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let codec = Codec::new(METHODS[0], PASSWORD, runtime::context(ServerType::Local)).unwrap();
        sender.send_to(&codec.encode(&udp(target()), b"first").unwrap(), address).await.unwrap();
        let unpolled = listener.accept(Arc::new(Echo)).await.unwrap();
        drop(unpolled);
        sender.send_to(&codec.encode(&udp(target()), b"second").unwrap(), address).await.unwrap();
        // A fresh task for the same peer proves the dropped task's guard removed
        // the previous route instead of leaving an undrainable association.
        let second = listener.accept(Arc::new(Echo)).await.unwrap();
        drop(listener);
        second.await.unwrap();
        let rebound = UdpSocket::bind(address).await.unwrap();
        drop(rebound);
        server.close().await.unwrap();
        assert!(matches!(server.bind_native(address).await, Err(Error::Closed)));
    }).await.unwrap();
}

struct MemoryDialer {
    server: Destination,
    stream: Mutex<Option<BoxStream>>,
}
#[async_trait]
impl StreamDialer for MemoryDialer {
    async fn dial(&self, destination: &Destination) -> Result<BoxStream> {
        assert_eq!(destination, &self.server);
        self.stream.lock().unwrap().take().ok_or(Error::Closed)
    }
}

#[tokio::test]
async fn trait_tcp_uses_injected_dialer_for_authenticated_server_route() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            let endpoint = Destination::from_domain_port("classic-transport.invalid", 8388);
            let (stream, peer) = tokio::io::duplex(29);
            let stream = Fragmented::new(stream);
            let wire = stream.output.clone();
            let dialer: Arc<dyn StreamDialer> = Arc::new(MemoryDialer {
                server: endpoint.clone(), stream: Mutex::new(Some(Box::pin(stream))),
            });
            let client: Arc<dyn OutboundHandler> = Arc::new(
                Client::try_new("injected", endpoint, method, PASSWORD).unwrap().with_dialer(dialer),
            );
            let server: Arc<dyn InboundHandler> = Arc::new(Server::try_new("injected", method, PASSWORD).unwrap());
            let worker = tokio::spawn(async move {
                let mut accepted = server.handle_connection(Box::pin(Fragmented::new(peer)), remote()).await.unwrap();
                assert_eq!(accepted.session.destination, target());
                accepted.stream.write_all(b"server-first").await.unwrap();
                let mut payload = Vec::new();
                accepted.stream.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, b"injected request");
                accepted.stream.write_all(b"injected response").await.unwrap();
                accepted.stream.shutdown().await.unwrap();
            });
            let mut stream = client.connect(&SessionContext::new("test", target())).await.unwrap();
            let mut greeting = [0; 12];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"server-first");
            stream.write_all(b"injected request").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"injected response");
            worker.await.unwrap();
            assert!(!wire.lock().unwrap().windows(16).any(|part| part == b"injected request"));
        }
    }).await.unwrap();
}

#[tokio::test]
async fn trait_client_close_cancels_pending_injected_handshake() {
    tokio::time::timeout(LIMIT, async {
        let endpoint = Destination::from_domain_port("blocked-transport.invalid", 8388);
        // The eager encrypted header cannot fit until the peer reads.
        let (stream, mut peer) = tokio::io::duplex(1);
        let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new(
            "close-handshake", endpoint.clone(), METHODS[0], PASSWORD,
        ).unwrap().with_dialer(Arc::new(MemoryDialer {
            server: endpoint, stream: Mutex::new(Some(Box::pin(stream))),
        })));
        let session = SessionContext::new("test", target());
        let mut connect = client.connect(&session);
        futures::future::poll_fn(|cx| {
            assert!(connect.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        client.close().await.unwrap();
        assert!(matches!(connect.await, Err(Error::Closed)));
        let mut partial_header = Vec::new();
        peer.read_to_end(&mut partial_header).await.unwrap();
        assert_eq!(partial_header.len(), 1);
    }).await.unwrap();
}

#[tokio::test]
async fn trait_client_close_cancels_all_pending_udp_receives_and_releases_sockets() {
    tokio::time::timeout(LIMIT, async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new(
            "close", peer.local_addr().unwrap().into(), METHODS[0], PASSWORD,
        ).unwrap());
        let session = SessionContext::new("test", udp(target()));
        let mut retained = Vec::new();
        let mut pending = Vec::new();
        let mut addresses = Vec::new();
        let mut wire = vec![0; MAX_DATAGRAM_SIZE + 1];
        for _ in 0..3 {
            let packets = client.connect_datagram(&session).await.unwrap();
            packets.send(Datagram::new(Bytes::from_static(b"request"), udp(target())).unwrap()).await.unwrap();
            let (_, address) = peer.recv_from(&mut wire).await.unwrap();
            addresses.push(address);
            // Poll the actual receive to Pending before closing the handler.
            let mut receive = Box::pin({ let packets = packets.clone(); async move { packets.recv().await } });
            futures::future::poll_fn(|cx| {
                assert!(receive.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            pending.push(receive);
            retained.push(packets);
        }
        client.close().await.unwrap();
        client.close().await.unwrap();
        for receive in pending { assert!(receive.await.unwrap().is_none()); }
        for packets in &retained {
            assert!(packets.recv().await.unwrap().is_none());
            assert!(matches!(packets.send(Datagram::new(Bytes::new(), udp(target())).unwrap()).await, Err(Error::Closed)));
        }
        // Retaining transports must not retain their OS sockets after close.
        for address in addresses { drop(UdpSocket::bind(address).await.unwrap()); }
        assert!(matches!(client.connect_datagram(&session).await, Err(Error::Closed)));
        assert!(matches!(client.connect(&SessionContext::new("test", target())).await, Err(Error::Closed)));
        assert!(matches!(client.start().await, Err(Error::Closed)));
    }).await.unwrap();
}

#[tokio::test]
async fn trait_udp_reply_uses_local_endpoint_or_session_source_and_preserves_packet_override() {
    tokio::time::timeout(LIMIT, async {
        for method in METHODS {
            for session_source in [None, Some(remote())] {
                let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let client: Arc<dyn OutboundHandler> = Arc::new(Client::try_new(
                    "reply-address", peer.local_addr().unwrap().into(), method, PASSWORD,
                ).unwrap());
                let destination = udp(target());
                let mut session = SessionContext::new("test", destination.clone());
                session.source = session_source;
                let packets = client.connect_datagram(&session).await.unwrap();
                let codec = Codec::new(method, PASSWORD, runtime::context(ServerType::Server)).unwrap();
                let explicit = Destination::udp("192.0.2.25".parse().unwrap(), 54000);
                let other = Destination::udp("192.0.2.25".parse().unwrap(), 54001);
                let mut buffer = vec![0; MAX_DATAGRAM_SIZE + 1];
                for (packet_source, expected_override) in [
                    (None, None),
                    (Some(explicit.clone()), Some(explicit.clone())),
                    (None, Some(explicit.clone())),
                ] {
                    packets.send(Datagram {
                        payload: Bytes::from_static(b"request"),
                        source: packet_source.clone(), destination: destination.clone(),
                    }).await.unwrap();
                    // The mock peer observes the actual connected client socket,
                    // independently of both logical source-address fields.
                    let (length, local) = peer.recv_from(&mut buffer).await.unwrap();
                    assert_ne!(local.port(), 0);
                    assert!(!local.ip().is_unspecified());
                    assert_eq!(codec.decode(&buffer[..length]).unwrap(),
                        (destination.clone(), Bytes::from_static(b"request")));
                    let wire = codec.encode(&destination, b"reply").unwrap();
                    peer.send_to(&wire, local).await.unwrap();
                    let reply = packets.recv().await.unwrap().unwrap();
                    assert_eq!(reply.payload.as_ref(), b"reply");
                    assert_eq!(reply.source, Some(destination.clone()));
                    let fallback = super::datagram::udp_destination(session_source.unwrap_or(local));
                    assert_eq!(reply.destination, expected_override.unwrap_or(fallback));
                    if packet_source.is_some() {
                        assert!(matches!(packets.send(Datagram {
                            payload: Bytes::from_static(b"mixed source"),
                            source: Some(other.clone()), destination: destination.clone(),
                        }).await, Err(Error::Protocol(_))));
                    }
                }
                packets.close().await.unwrap();
                client.close().await.unwrap();
            }
        }
    }).await.unwrap();
}

struct CapturePackets {
    accepted: tokio::sync::mpsc::UnboundedSender<BoxDatagram>,
}
#[async_trait]
impl InboundDispatcher for CapturePackets {
    async fn dispatch_stream(&self, _stream: BoxStream, _session: SessionContext) -> Result<()> {
        Err(Error::Unsupported("test stream dispatch".into()))
    }
    async fn dispatch_datagrams(&self, packets: BoxDatagram, _session: SessionContext) -> Result<()> {
        self.accepted.send(packets).map_err(|_| Error::Closed)?;
        std::future::pending().await
    }
}

#[tokio::test]
async fn native_listener_drop_releases_socket_with_retained_udp_transport() {
    tokio::time::timeout(LIMIT, async {
        let server: Arc<dyn InboundHandler> = Arc::new(
            Server::try_new("retained", METHODS[0], PASSWORD).unwrap().with_networks(false, true).unwrap(),
        );
        let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
        let address = listener.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let codec = Codec::new(METHODS[0], PASSWORD, runtime::context(ServerType::Local)).unwrap();
        peer.send_to(&codec.encode(&udp(target()), b"request").unwrap(), address).await.unwrap();
        let (accepted, mut captures) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(listener.accept(Arc::new(CapturePackets { accepted })).await.unwrap());
        let packets = captures.recv().await.unwrap();
        assert_eq!(packets.recv().await.unwrap().unwrap().payload.as_ref(), b"request");
        let mut receive = Box::pin(packets.recv());
        futures::future::poll_fn(|cx| {
            assert!(receive.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        drop(listener);
        assert!(receive.await.unwrap().is_none());
        task.await.unwrap().unwrap();
        assert!(matches!(packets.send(Datagram::new(Bytes::new(), udp(target())).unwrap()).await, Err(Error::Closed)));
        drop(UdpSocket::bind(address).await.unwrap());
        server.close().await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn native_listener_drop_and_handler_close_release_unpolled_tcp_children() {
    tokio::time::timeout(LIMIT, async {
        for handler_close in [false, true] {
            let server: Arc<dyn InboundHandler> = Arc::new(
                Server::try_new("unpolled", METHODS[0], PASSWORD).unwrap().with_networks(true, true).unwrap(),
            );
            let mut listener = server.bind_native("127.0.0.1:0".parse().unwrap()).await.unwrap().unwrap();
            let address = listener.local_addr().unwrap();
            let mut peers = Vec::new();
            let mut tasks = Vec::new();
            for _ in 0..3 {
                peers.push(tokio::net::TcpStream::connect(address).await.unwrap());
                tasks.push(listener.accept(Arc::new(Echo)).await.unwrap());
            }
            if handler_close { server.close().await.unwrap(); } else { drop(listener); }
            // Observe EOF before polling or dropping any returned task.
            for peer in &mut peers {
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            }
            for task in tasks { task.await.unwrap(); }
            drop(UdpSocket::bind(address).await.unwrap());
        }
    }).await.unwrap();
}
