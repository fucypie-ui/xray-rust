use super::*;
use crate::features::inbound::InboundHandler as _;
use crate::features::outbound::OutboundHandler as _;
use crate::common::protocol::SessionContext;
use crate::proxy::shadowsocks_2022::{Client, Server, Shadowsocks2022Config};
use super::super::cipher::{STREAM_NONCE_SIZE, increase_nonce};
use super::super::kdf::{derive_session_subkey, parse_key};
use base64::Engine as _;
use serde::Deserialize;
use std::io::Cursor;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Vector {
    method: String, timestamp: u64, destination: String,
    psk: String, salt: String, response_salt: String, subkey: String,
    request: String, response: String, padding: String, early_data: String,
    request_body: String, response_initial: String, response_body: String,
}

fn bytes(hex: &str) -> Vec<u8> { hex::decode(hex).unwrap() }

fn append_frame(wire: &mut Vec<u8>, cipher: &mut CipherState, payload: &[u8]) {
    wire.extend(cipher.seal(&u16::try_from(payload.len()).unwrap().to_be_bytes()).unwrap());
    wire.extend(cipher.seal(payload).unwrap());
}

fn open_frame(wire: &[u8], cipher: &mut CipherState) -> Vec<u8> {
    let length = cipher.open(&wire[..18]).unwrap();
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    assert_eq!(wire.len(), 18 + length + AEAD_TAG_SIZE);
    cipher.open(&wire[18..]).unwrap()
}

#[tokio::test]
async fn ss2022_go_wire_vectors_both_directions() {
    let vectors: Vec<Vector> = include_str!("testdata/go-vectors.jsonl").lines().filter(|line| !line.trim().is_empty()).map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(vectors.len(), 2, "AES128 and AES256 reference records are required");
    let mut methods = Vec::new();
    for vector in vectors {
        let method = CipherMethod::parse(&vector.method).unwrap();
        methods.push(method);
        let (key, salt) = (bytes(&vector.psk), bytes(&vector.salt));
        assert_eq!(derive_session_subkey(&key, &salt, method.key_length()), bytes(&vector.subkey));
        let destination: Destination = vector.destination.parse().unwrap();
        let (mut request, mut writer) = encode_request(method, &key, &salt, &destination, &bytes(&vector.padding), &bytes(&vector.early_data), vector.timestamp).unwrap();
        append_frame(&mut request, &mut writer, &bytes(&vector.request_body));
        assert_eq!(request, bytes(&vector.request), "{} request differs from Go", vector.method);
        let mut input = Cursor::new(request.clone());
        let mut parsed = read_request_at(&mut input, method, &key, vector.timestamp).await.unwrap();
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.early_data, bytes(&vector.early_data));
        assert_eq!(open_frame(&request[usize::try_from(input.position()).unwrap()..], &mut parsed.cipher), bytes(&vector.request_body));

        let (mut response, mut writer) = encode_response(method, &key, &bytes(&vector.response_salt), &salt, &bytes(&vector.response_initial), vector.timestamp).unwrap();
        append_frame(&mut response, &mut writer, &bytes(&vector.response_body));
        assert_eq!(response, bytes(&vector.response), "{} response differs from Go", vector.method);
        let fixed_end = 2 * method.key_length() + 11 + AEAD_TAG_SIZE;
        let (mut reader, length) = decode_response_header(method, &key, &salt, &response[..fixed_end], vector.timestamp).unwrap();
        let initial_end = fixed_end + length + AEAD_TAG_SIZE;
        assert_eq!(reader.open(&response[fixed_end..initial_end]).unwrap(), bytes(&vector.response_initial));
        assert_eq!(open_frame(&response[initial_end..], &mut reader), bytes(&vector.response_body));
    }
    assert!(methods.contains(&CipherMethod::Aes128Gcm));
    assert!(methods.contains(&CipherMethod::Aes256Gcm));
}

#[test]
fn ss2022_nonce_and_key_parsing() {
    let mut nonce = [0; STREAM_NONCE_SIZE];
    assert!(increase_nonce(&mut nonce));
    assert_eq!(nonce[0], 1);
    nonce[0] = 255;
    assert!(increase_nonce(&mut nonce));
    assert_eq!(&nonce[..3], &[0, 1, 0]);
    nonce = [255; STREAM_NONCE_SIZE];
    assert!(!increase_nonce(&mut nonce));
    assert_eq!(nonce, [0; STREAM_NONCE_SIZE]);
    let encoded = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
    assert_eq!(parse_key(&encoded, 16).unwrap(), vec![7; 16]);
    assert_eq!(parse_key(&format!("{}\r\n", encoded), 16).unwrap(), vec![7; 16]);
    assert_eq!(parse_key("raw-key-16-bytes", 16).unwrap(), b"raw-key-16-bytes");
    assert!(parse_key("YQ==", 16).is_err());
    // A successfully decoded, wrong-size base64 string must not use raw fallback.
    assert!(parse_key("abcdefghijklmnop", 16).is_err());
}

#[test]
fn ss2022_socks_address_bytes_and_bounds() {
    let cases = [
        ("192.0.2.1:443", "01c000020101bb"),
        ("[2001:db8::1]:53", "0420010db80000000000000000000000010035"),
        ("example.com:80", "030b6578616d706c652e636f6d0050"),
    ];
    for (text, expected) in cases {
        let destination: Destination = text.parse().unwrap();
        let encoded = encode_address(&destination).unwrap();
        assert_eq!(encoded, bytes(expected));
        assert_eq!(decode_address(&encoded).unwrap(), (destination.clone(), encoded.len()));
        let mut flags = encoded.clone(); flags[0] |= 0xf0;
        assert!(decode_address(&flags).is_err());
        for end in 0..encoded.len() { assert!(decode_address(&encoded[..end]).is_err()); }
    }
    assert!(encode_address(&Destination::from_domain_port("x".repeat(256), 80)).is_err());
    assert_eq!(decode_address(&[3, 0, 0, 80]).unwrap().0, Destination::from_domain_port("", 80));
    assert!(decode_address(&[2, 0, 0, 80]).is_err());
    assert!(encode_address(&Destination::udp(Address::Domain("example.com".into()), 53)).is_err());
}

fn raw_request(method: CipherMethod, key: &[u8], salt: &[u8], kind: u8, timestamp: u64, variable: &[u8]) -> Vec<u8> {
    let mut cipher = CipherState::new(method, key, salt).unwrap();
    let mut fixed = vec![kind];
    fixed.extend(timestamp.to_be_bytes());
    fixed.extend(u16::try_from(variable.len()).unwrap().to_be_bytes());
    let mut output = salt.to_vec();
    output.extend(cipher.seal(&fixed).unwrap());
    output.extend(cipher.seal(variable).unwrap());
    output
}

#[tokio::test]
async fn ss2022_request_authentication_timestamp_padding_and_truncation() {
    for method in [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm] {
        let (key, salt) = (vec![7; method.key_length()], vec![8; method.key_length()]);
        let destination = Destination::from_domain_port("example.com", 443);
        let now = unix_time().unwrap();
        let (wire, _) = encode_request(method, &key, &salt, &destination, &[0], b"early", now).unwrap();
        for offset in 0..wire.len() {
            let mut tampered = wire.clone(); tampered[offset] ^= 0x80;
            assert!(read_request_at(&mut Cursor::new(tampered), method, &key, now).await.is_err(), "tamper at {offset}");
        }
        for end in 0..wire.len() {
            assert!(read_request_at(&mut Cursor::new(&wire[..end]), method, &key, now).await.is_err());
        }
        assert!(read_request_at(&mut Cursor::new(&wire), method, &vec![9; method.key_length()], now).await.is_err());
        for timestamp in [now - 31, now + 31, u64::MAX] {
            let (wire, _) = encode_request(method, &key, &salt, &destination, &[0], &[], timestamp).unwrap();
            assert!(read_request_at(&mut Cursor::new(wire), method, &key, now).await.is_err());
        }
        for timestamp in [now - 30, now + 30] {
            let (wire, _) = encode_request(method, &key, &salt, &destination, &[0], &[], timestamp).unwrap();
            assert!(read_request_at(&mut Cursor::new(wire), method, &key, now).await.is_ok());
        }
        let mut no_padding = encode_address(&destination).unwrap();
        no_padding.extend([0, 0]);
        let wire = raw_request(method, &key, &salt, HEADER_TYPE_CLIENT, now, &no_padding);
        assert!(read_request_at(&mut Cursor::new(wire), method, &key, now).await.is_err());
        let wire = raw_request(method, &key, &salt, HEADER_TYPE_SERVER, now, &no_padding);
        assert!(read_request_at(&mut Cursor::new(wire), method, &key, now).await.is_err());
        *no_padding.last_mut().unwrap() = 1; // claims padding that is not present
        let wire = raw_request(method, &key, &salt, HEADER_TYPE_CLIENT, now, &no_padding);
        assert!(read_request_at(&mut Cursor::new(wire), method, &key, now).await.is_err());
    }
}

#[tokio::test]
async fn ss2022_response_binding_and_authentication() {
    for method in [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm] {
        let (key, salt, server_salt) = (vec![1; method.key_length()], vec![2; method.key_length()], vec![3; method.key_length()]);
        let now = unix_time().unwrap();
        let (mut wire, mut writer) = encode_response(method, &key, &server_salt, &salt, b"initial", now).unwrap();
        append_frame(&mut wire, &mut writer, b"body");
        let fixed_end = 2 * method.key_length() + 11 + AEAD_TAG_SIZE;
        assert!(decode_response_header(method, &key, &vec![5; method.key_length()], &wire[..fixed_end], now).is_err());
        assert!(decode_response_header(method, &vec![5; method.key_length()], &salt, &wire[..fixed_end], now).is_err());
        assert!(decode_response_header(method, &key, &salt, &wire[..fixed_end], now + 31).is_err());
        let mut fixed_cipher = CipherState::new(method, &key, &server_salt).unwrap();
        let mut wrong_type = fixed_cipher.open(&wire[method.key_length()..fixed_end]).unwrap();
        wrong_type[0] = HEADER_TYPE_CLIENT;
        let mut fixed_cipher = CipherState::new(method, &key, &server_salt).unwrap();
        let mut bad_header = server_salt.clone();
        bad_header.extend(fixed_cipher.seal(&wrong_type).unwrap());
        assert!(decode_response_header(method, &key, &salt, &bad_header, now).is_err());
        for offset in [0, method.key_length(), fixed_end - 1, fixed_end, fixed_end + 7 + 15, wire.len() - 1] {
            let mut tampered = wire.clone(); tampered[offset] ^= 1;
            let response = ResponseContext { method, key: key.clone(), client_salt: salt.clone() };
            let mut stream = EncryptedStream::new(Box::pin(Cursor::new(tampered)), None, None, ReadStage::ResponseHeader(response), Vec::new(), None);
            let mut output = Vec::new();
            assert_eq!(stream.read_to_end(&mut output).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(stream.read_u8().await.is_err(), "authentication failure must be terminal");
            if offset < fixed_end + 7 + AEAD_TAG_SIZE { assert!(output.is_empty()); }
        }
        // An authenticated header with no initial payload uses nonce 1 for the next length.
        let (mut empty, mut writer) = encode_response(method, &key, &server_salt, &salt, &[], now).unwrap();
        append_frame(&mut empty, &mut writer, b"later");
        let response = ResponseContext { method, key: key.clone(), client_salt: salt.clone() };
        let mut stream = EncryptedStream::new(Box::pin(Cursor::new(empty)), None, None, ReadStage::ResponseHeader(response), Vec::new(), None);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"later");
    }
}

#[tokio::test]
async fn ss2022_shared_replay_state_and_no_cache_poisoning() {
    let method = CipherMethod::Aes128Gcm;
    let (key, salt) = (vec![1; 16], vec![2; 16]);
    let (wire, _) = encode_request(method, &key, &salt, &Destination::from_domain_port("example.com", 80), &[0], &[], unix_time().unwrap()).unwrap();
    let filter = ReplayFilter::default();
    let mut invalid = wire.clone(); *invalid.last_mut().unwrap() ^= 1;
    assert!(accept_tcp(Box::pin(Cursor::new(invalid)), method, key.clone(), &filter).await.is_err());
    assert!(accept_tcp(Box::pin(Cursor::new(wire.clone())), method, key.clone(), &filter).await.is_ok());
    assert!(accept_tcp(Box::pin(Cursor::new(wire)), method, key, &filter).await.is_err());
    let filter = ReplayFilter::default();
    let now = Instant::now();
    filter.check_at(&salt, now).unwrap();
    assert!(filter.check_at(&salt, now + Duration::from_secs(60)).is_err());
    filter.check_at(&salt, now + Duration::from_secs(120)).unwrap();
}

#[tokio::test]
async fn ss2022_body_chunk_authentication_zero_length_and_truncation() {
    for method in [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm] {
        let (key, salt) = (vec![1; method.key_length()], vec![2; method.key_length()]);
        let (request, mut writer) = encode_request(method, &key, &salt, &Destination::from_domain_port("example.com", 80), &[0], &[], unix_time().unwrap()).unwrap();
        let mut body = Vec::new();
        append_frame(&mut body, &mut writer, b"authenticated payload");
        let mut invalid_bodies = Vec::new();
        for offset in [0, 17, 18, body.len() - 1] {
            let mut tampered = body.clone(); tampered[offset] ^= 1; invalid_bodies.push(tampered);
        }
        for end in [1, 17, 18, body.len() - 1] { invalid_bodies.push(body[..end].to_vec()); }
        let (_, mut zero_writer) = encode_request(method, &key, &salt, &Destination::from_domain_port("example.com", 80), &[0], &[], unix_time().unwrap()).unwrap();
        invalid_bodies.push(zero_writer.seal(&[0, 0]).unwrap());
        for body in invalid_bodies {
            let mut wire = request.clone(); wire.extend(body);
            let (_, mut stream) = accept_tcp(Box::pin(Cursor::new(wire)), method, key.clone(), &ReplayFilter::default()).await.unwrap();
            let mut output = Vec::new();
            assert!(stream.read_to_end(&mut output).await.is_err());
            assert!(output.is_empty(), "unauthenticated payload must not escape");
        }
    }
}

struct Fragmented<S> { inner: S, limit: usize, read_pending: bool, write_pending: bool }

impl<S: AsyncRead + Unpin> AsyncRead for Fragmented<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_pending { this.read_pending = false; cx.waker().wake_by_ref(); return Poll::Pending; }
        this.read_pending = true;
        let length = output.remaining().min(this.limit);
        let mut small = ReadBuf::new(output.initialize_unfilled_to(length));
        let result = Pin::new(&mut this.inner).poll_read(cx, &mut small);
        let filled = small.filled().len();
        output.advance(filled);
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmented<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_pending { this.write_pending = false; cx.waker().wake_by_ref(); return Poll::Pending; }
        this.write_pending = true;
        Pin::new(&mut this.inner).poll_write(cx, &input[..input.len().min(this.limit)])
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_flush(cx) }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_shutdown(cx) }
}

fn fragmented<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(stream: S) -> BoxStream {
    Box::pin(Fragmented { inner: stream, limit: 7, read_pending: false, write_pending: false })
}

#[derive(Default)]
struct GateState { open: bool, wire: Vec<u8> }

struct GatedWriter(std::sync::Arc<std::sync::Mutex<GateState>>);

impl AsyncRead for GatedWriter {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Poll::Pending }
}

impl AsyncWrite for GatedWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        let mut gate = self.0.lock().unwrap();
        if !gate.open { return Poll::Pending; }
        gate.wire.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

#[test]
fn ss2022_cancel_pending_write_and_retry_different_shorter_buffer() {
    let method = CipherMethod::Aes128Gcm;
    let (key, salt) = (vec![1; 16], vec![2; 16]);
    let gate = std::sync::Arc::new(std::sync::Mutex::new(GateState::default()));
    let writer = CipherState::new(method, &key, &salt).unwrap();
    let mut encrypted = EncryptedStream::new(Box::pin(GatedWriter(gate.clone())), None, Some(writer), ReadStage::Length, Vec::new(), None);
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let first = b"previous accepted record";
    assert!(matches!(Pin::new(&mut encrypted).poll_write(&mut cx, first), Poll::Ready(Ok(length)) if length == first.len()));
    assert!(gate.lock().unwrap().wire.is_empty());
    assert!(matches!(Pin::new(&mut encrypted).poll_write(&mut cx, b"cancel this pending write"), Poll::Pending));
    // Cancel that operation and retry with an entirely different, shorter input.
    gate.lock().unwrap().open = true;
    assert!(matches!(Pin::new(&mut encrypted).poll_write(&mut cx, b"x"), Poll::Ready(Ok(1))));
    let wire = gate.lock().unwrap().wire.clone();
    let first_end = 18 + first.len() + AEAD_TAG_SIZE;
    let mut reader = CipherState::new(method, &key, &salt).unwrap();
    assert_eq!(open_frame(&wire[..first_end], &mut reader), first);
    assert_eq!(open_frame(&wire[first_end..], &mut reader), b"x");
    assert!(encrypted.write_wire.is_empty());
}

#[tokio::test]
async fn ss2022_read_drives_accepted_ciphertext_without_explicit_flush() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let method = CipherMethod::Aes128Gcm;
        let key = vec![1; 16];
        let (client, server) = tokio::io::duplex(31);
        let worker = tokio::spawn(async move {
            let (_, mut encrypted) = accept_tcp(fragmented(server), method, vec![1; 16], &ReplayFilter::default()).await.unwrap();
            let mut ping = [0; 4];
            encrypted.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            encrypted.write_all(b"pong").await.unwrap();
            encrypted.shutdown().await.unwrap();
        });
        let mut encrypted = connect_tcp(fragmented(client), method, key, &Destination::from_domain_port("example.com", 443)).await.unwrap();
        encrypted.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        encrypted.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        worker.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_simultaneous_bidirectional_backpressure() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let method = CipherMethod::Aes256Gcm;
        let key = vec![1; 32];
        let (client, server) = tokio::io::duplex(31);
        let worker = tokio::spawn(async move {
            let (_, encrypted) = accept_tcp(fragmented(server), method, vec![1; 32], &ReplayFilter::default()).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(encrypted);
            let read = tokio::spawn(async move {
                let mut payload = Vec::new();
                reader.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, vec![0x11; MAX_PACKET_SIZE]);
            });
            let write = tokio::spawn(async move {
                writer.write_all(&vec![0x22; MAX_PACKET_SIZE]).await.unwrap();
                writer.shutdown().await.unwrap();
            });
            let (read, write) = tokio::join!(read, write);
            read.unwrap(); write.unwrap();
        });
        let encrypted = connect_tcp(fragmented(client), method, key, &Destination::from_domain_port("example.com", 443)).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(encrypted);
        let read = tokio::spawn(async move {
            let mut payload = Vec::new();
            reader.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, vec![0x22; MAX_PACKET_SIZE]);
        });
        let write = tokio::spawn(async move {
            writer.write_all(&vec![0x11; MAX_PACKET_SIZE]).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let (read, write) = tokio::join!(read, write);
        read.unwrap(); write.unwrap();
        worker.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_fragmented_pending_large_bidirectional_stream() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for method in [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm] {
            let key = vec![4; method.key_length()];
            let destination = Destination::from_domain_port("example.com", 443);
            let payload = vec![0x5a; 2 * MAX_PACKET_SIZE + 17];
            let expected = payload.clone();
            let server_key = key.clone();
            let target = destination.clone();
            let (client, server) = tokio::io::duplex(31);
            let worker = tokio::spawn(async move {
                let (actual, mut encrypted) = accept_tcp(fragmented(server), method, server_key, &ReplayFilter::default()).await.unwrap();
                assert_eq!(actual, target);
                let mut received = Vec::new();
                encrypted.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected);
                encrypted.write_all(&received).await.unwrap();
                encrypted.shutdown().await.unwrap();
            });
            let mut encrypted = connect_tcp(fragmented(client), method, key, &destination).await.unwrap();
            encrypted.write_all(&payload).await.unwrap();
            encrypted.shutdown().await.unwrap();
            let mut received = Vec::new();
            encrypted.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            worker.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_loopback_handlers_and_empty_server_response() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for name in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
            let method = CipherMethod::parse(name).unwrap();
            let config = Shadowsocks2022Config { method: name.into(), key: base64::engine::general_purpose::STANDARD.encode(vec![6; method.key_length()]), network: Some("tcp".into()) };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = Server::try_new("ss2022-in", config.clone()).unwrap();
            let worker = tokio::spawn(async move {
                let (stream, remote) = listener.accept().await.unwrap();
                let mut inbound = server.handle_connection(Box::pin(stream), remote).await.unwrap();
                assert_eq!(inbound.session.destination, Destination::from_domain_port("example.com", 443));
                let mut payload = [0; 4];
                inbound.stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                // No response payload: shutdown still emits an authenticated response.
                inbound.stream.shutdown().await.unwrap();
            });
            let client = Client::try_new("ss2022-out", address.into(), config).unwrap();
            let mut stream = client.connect(&SessionContext::new("test", Destination::from_domain_port("example.com", 443))).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            worker.await.unwrap();
        }
    }).await.unwrap();
}
