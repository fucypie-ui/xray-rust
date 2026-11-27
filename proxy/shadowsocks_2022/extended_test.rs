use super::{cipher::{CipherMethod, CipherState}, identity::tcp_headers, multi_server::{MultiUserServer, UserAccount}, packet::{DecodedPacket, PacketCodec, MAX_DATAGRAM_SIZE}, protocol::{HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER}, relay_server::{RelayServer, RelayTarget}, stream, udp_session::{ClientUdpSession, SlidingWindow, UdpAssociation}, Server, Shadowsocks2022Config};
use crate::{common::{net::{Destination, Network}, protocol::User}, features::inbound::InboundHandler};
use base64::Engine as _;
use std::{io::Cursor, time::Duration};
use serde::Deserialize;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const METHODS: [CipherMethod; 3] = [CipherMethod::Aes128Gcm, CipherMethod::Aes256Gcm, CipherMethod::ChaCha20Poly1305];
fn method_name(method: CipherMethod) -> &'static str {
    match method { CipherMethod::Aes128Gcm => "2022-blake3-aes-128-gcm", CipherMethod::Aes256Gcm => "2022-blake3-aes-256-gcm", CipherMethod::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305" }
}
fn udp_destination() -> Destination { let mut dest = Destination::from_domain_port("example.com", 443); dest.network = Network::Udp; dest }
fn identity(email: &str) -> User { User::with_email(uuid::Uuid::new_v4(), email, 7) }
fn server(method: CipherMethod, key: &[u8]) -> Server {
    Server::try_new("test", Shadowsocks2022Config { method: method_name(method).into(), key: base64::engine::general_purpose::STANDARD.encode(key), network: Some("tcp".into()) }).unwrap()
}
fn unhex(hex: &str) -> Vec<u8> { hex::decode(hex).unwrap() }
fn append_frame(wire: &mut Vec<u8>, cipher: &mut CipherState, payload: &[u8]) {
    wire.extend(cipher.seal(&u16::try_from(payload.len()).unwrap().to_be_bytes()).unwrap());
    wire.extend(cipher.seal(payload).unwrap());
}

#[derive(Deserialize)]
struct ExtendedVector {
    method: String, timestamp: u64, keys: Vec<String>, salt: String, response_salt: String,
    destination: String, padding: String, early_data: String, request: String, response: String,
    request_body: String, response_initial: String, response_body: String,
    udp_request: String, udp_response: String, client_session_id: u64, server_session_id: u64,
    udp_request_payload: String, udp_response_payload: String,
}

#[test]
fn ss2022_extended_go_vectors_engine_tcp_eih_and_udp() {
    // Fail explicitly if the remote-produced fixture has not yet been frozen.
    // Do not substitute Rust-produced bytes for independent Go evidence.
    let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/proxy/shadowsocks_2022/testdata/go-extended-vectors.jsonl")).expect("run the remote generate-extended.sh and freeze its Go JSONL");
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&bytes)),
        "349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0",
        "independent Go fixture checksum mismatch; never replace the expected digest to match Rust output",
    );
    let file = std::str::from_utf8(&bytes).expect("independent Go fixture must be UTF-8");
    let vectors: Vec<ExtendedVector> = file.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(vectors.len(), 3);
    let mut methods = Vec::new();
    for vector in vectors {
        let method = CipherMethod::parse(&vector.method).unwrap(); methods.push(method);
        let keys: Vec<Vec<u8>> = vector.keys.iter().map(|key| unhex(key)).collect();
        let key = keys.last().unwrap();
        let salt = unhex(&vector.salt);
        let destination: Destination = vector.destination.parse().unwrap();
        let (mut request, mut writer) = stream::encode_request(method, key, &salt, &destination, &unhex(&vector.padding), &unhex(&vector.early_data), vector.timestamp).unwrap();
        append_frame(&mut request, &mut writer, &unhex(&vector.request_body));
        let mut chain_request = salt.clone();
        chain_request.extend(tcp_headers(method, &keys, &salt).unwrap());
        chain_request.extend_from_slice(&request[salt.len()..]);
        assert_eq!(chain_request, unhex(&vector.request));
        let (mut response, mut writer) = stream::encode_response(method, key, &unhex(&vector.response_salt), &salt, &unhex(&vector.response_initial), vector.timestamp).unwrap();
        append_frame(&mut response, &mut writer, &unhex(&vector.response_body));
        assert_eq!(response, unhex(&vector.response));
        let mut udp_dest = destination; udp_dest.network = Network::Udp;
        let codec = PacketCodec::new(method, keys.clone()).unwrap();
        let packet = DecodedPacket { session_id: vector.client_session_id, packet_id: 0, header_type: HEADER_TYPE_CLIENT, timestamp: vector.timestamp, client_session_id: None, destination: udp_dest.clone(), payload: unhex(&vector.udp_request_payload) };
        let nonce = std::array::from_fn(|i| 0xc0 + i as u8);
        let wire = codec.encode_at(&packet, &[], &nonce).unwrap();
        assert_eq!(wire, unhex(&vector.udp_request));
        assert_eq!(codec.decode_at(&wire, HEADER_TYPE_CLIENT, vector.timestamp).unwrap(), packet);
        let reply = DecodedPacket { session_id: vector.server_session_id, packet_id: 0, header_type: HEADER_TYPE_SERVER, timestamp: vector.timestamp, client_session_id: Some(vector.client_session_id), destination: udp_dest, payload: unhex(&vector.udp_response_payload) };
        let nonce = std::array::from_fn(|i| 0xe0 + i as u8);
        let wire = codec.encode_at(&reply, &[], &nonce).unwrap();
        assert_eq!(wire, unhex(&vector.udp_response));
        let mut client = ClientUdpSession::with_session_id(method, keys, vector.client_session_id).unwrap();
        assert_eq!(client.decode_at(&wire, vector.timestamp).unwrap(), reply);
        assert!(client.decode_at(&wire, vector.timestamp).is_err());
    }
    for method in METHODS { assert!(methods.contains(&method)); }
}

#[tokio::test]
async fn ss2022_chacha_tcp_authentication_and_half_close() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let method = CipherMethod::ChaCha20Poly1305;
        let (client, remote) = tokio::io::duplex(91);
        let worker = tokio::spawn(async move {
            let (_, mut stream) = stream::accept_tcp(Box::pin(remote), method, vec![1; 32], &super::replay::ReplayFilter::default()).await.unwrap();
            let mut payload = Vec::new(); stream.read_to_end(&mut payload).await.unwrap(); assert_eq!(payload, b"chacha request");
            stream.write_all(b"chacha response").await.unwrap(); stream.shutdown().await.unwrap();
        });
        let mut stream = stream::connect_tcp(Box::pin(client), method, vec![1; 32], &Destination::from_domain_port("example.com",443)).await.unwrap();
        stream.write_all(b"chacha request").await.unwrap(); stream.shutdown().await.unwrap();
        let mut response=Vec::new(); stream.read_to_end(&mut response).await.unwrap(); assert_eq!(response,b"chacha response");
        worker.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn ss2022_tcp_relay_chain_multiuser_identity_and_authentication() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for method in [CipherMethod::Aes128Gcm,CipherMethod::Aes256Gcm] {
            let size=method.key_length();
            let keys=vec![vec![1;size],vec![2;size],vec![3;size]];
            let relay=RelayServer::new("relay",method,keys[0].clone(),vec![RelayTarget{key:keys[1].clone(),destination:Destination::from_domain_port("next-hop",8388),user:identity("relay@example")}]).unwrap();
            let multi=MultiUserServer::new("multi",method,keys[1].clone()).unwrap();
            multi.add_account(UserAccount{key:keys[2].clone(),user:identity("user@example")}).unwrap();
            let (client,remote)=tokio::io::duplex(79);
            // Keep each stream path in one joined server future; no detached bridges.
            let worker=tokio::spawn(async move {
                let remote_addr="127.0.0.1:11000".parse().unwrap();
                let mut forwarded=relay.handle_connection(Box::pin(remote),remote_addr).await.unwrap();
                assert_eq!(forwarded.session.destination,Destination::from_domain_port("next-hop",8388));
                assert_eq!(forwarded.session.user.unwrap().email,"relay@example");
                let mut first = [0; 128];
                let count = forwarded.stream.read(&mut first).await.unwrap();
                assert_eq!(count, method.key_length() + 43);
                let reconstructed = super::identity::PrefixedStream { prefix: first[..count].to_vec(), offset: 0, inner: forwarded.stream };
                let mut accepted=multi.handle_connection(Box::pin(reconstructed),remote_addr).await.unwrap();
                assert_eq!(accepted.session.user.unwrap().email,"user@example");
                assert_eq!(accepted.session.destination,Destination::from_domain_port("example.com",443));
                let mut ping=[0;4]; accepted.stream.read_exact(&mut ping).await.unwrap(); assert_eq!(&ping,b"ping");
                accepted.stream.write_all(b"pong").await.unwrap(); accepted.stream.shutdown().await.unwrap();
            });
            let mut client=stream::connect_tcp_chain(Box::pin(client),method,keys,&Destination::from_domain_port("example.com",443)).await.unwrap();
            client.write_all(b"ping").await.unwrap(); let mut response=Vec::new(); client.read_to_end(&mut response).await.unwrap(); assert_eq!(response,b"pong");
            worker.await.unwrap();
        }
    }).await.unwrap();
}

#[test]
fn ss2022_udp_packet_authentication_truncation_and_bounds() {
    for method in METHODS {
        let key=vec![7;method.key_length()]; let codec=PacketCodec::new(method,vec![key]).unwrap();
        let packet=DecodedPacket {session_id:1,packet_id:0,header_type:HEADER_TYPE_CLIENT,timestamp:1700000000,client_session_id:None,destination:udp_destination(),payload:b"udp payload".to_vec()};
        let wire=codec.encode_at(&packet,&[0;3],&[9;24]).unwrap();
        assert_eq!(codec.decode_at(&wire,HEADER_TYPE_CLIENT,1700000000).unwrap(),packet);
        for index in 0..wire.len() { let mut corrupt=wire.clone(); corrupt[index]^=1; assert!(codec.decode_at(&corrupt,HEADER_TYPE_CLIENT,1700000000).is_err()); }
        for end in 0..wire.len() { assert!(codec.decode_at(&wire[..end],HEADER_TYPE_CLIENT,1700000000).is_err()); }
        assert!(codec.decode_at(&wire,HEADER_TYPE_SERVER,1700000000).is_err());
        assert!(codec.decode_at(&wire,HEADER_TYPE_CLIENT,1700000031).is_err());
        let mut large=packet.clone(); large.payload=vec![0;MAX_DATAGRAM_SIZE]; assert!(codec.encode_at(&large,&[],&[0;24]).is_err());
        large.payload.clear(); assert!(codec.decode_at(&codec.encode_at(&large,&[],&[0;24]).unwrap(),HEADER_TYPE_CLIENT,1700000000).unwrap().payload.is_empty());
    }
}

#[test]
fn ss2022_udp_eih_relay_multiuser_replay_and_reply_binding() {
    for method in [CipherMethod::Aes128Gcm,CipherMethod::Aes256Gcm] {
        let size=method.key_length(); let keys=vec![vec![1;size],vec![2;size],vec![3;size]];
        let relay=RelayServer::new("relay",method,keys[0].clone(),vec![RelayTarget{key:keys[1].clone(),destination:Destination::from_domain_port("next-hop",8388),user:identity("relay@example")}]).unwrap();
        let multi=MultiUserServer::new("multi",method,keys[1].clone()).unwrap();
        multi.add_account(UserAccount{key:keys[2].clone(),user:identity("user@example")}).unwrap();
        let mut client=ClientUdpSession::with_session_id(method,keys.clone(),123).unwrap();
        let wire=client.encode(udp_destination(),b"ping").unwrap();
        let forwarded=relay.relay_datagram(&wire).unwrap(); assert_eq!(forwarded.wire.len()+16,wire.len()); assert_eq!(forwarded.destination.network,Network::Udp);
        let remote="127.0.0.1:11000".parse().unwrap();
        let incoming=multi.decode_datagram(&forwarded.wire,remote).unwrap(); assert_eq!(incoming.packet.payload,b"ping"); assert_eq!(incoming.user.unwrap().email,"user@example");
        assert!(multi.decode_datagram(&forwarded.wire,remote).is_err());
        let (reply_remote,wire)=multi.reply_datagram(&incoming.reply,udp_destination(),b"pong").unwrap(); assert_eq!(reply_remote,remote);
        let mut wrong_client=ClientUdpSession::with_session_id(method,keys,124).unwrap(); assert!(wrong_client.decode(&wire).is_err());
        assert_eq!(client.decode(&wire).unwrap().payload,b"pong"); assert!(client.decode(&wire).is_err());
        multi.remove_account("USER@EXAMPLE").unwrap();
        let next=client.encode(udp_destination(),b"after removal").unwrap(); assert!(multi.decode_datagram(&relay.relay_datagram(&next).unwrap().wire,remote).is_err());
    }
}

#[tokio::test]
async fn ss2022_native_udp_association_single_user_loopback() {
    tokio::time::timeout(Duration::from_secs(5),async {
        for method in METHODS {
            let key=vec![4;method.key_length()]; let inbound=server(method,&key);
            let socket=tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(); let address=Destination::from(socket.local_addr().unwrap());
            let worker=tokio::spawn(async move {
                let mut buffer=vec![0;MAX_DATAGRAM_SIZE+1]; let (length,remote)=socket.recv_from(&mut buffer).await.unwrap();
                let packet=inbound.decode_datagram(&buffer[..length],remote).unwrap(); assert_eq!(packet.packet.payload,b"ping");
                assert!(inbound.decode_datagram(&buffer[..length],remote).is_err());
                let (remote,wire)=inbound.reply_datagram(&packet.reply,packet.packet.destination,b"pong").unwrap(); socket.send_to(&wire,remote).await.unwrap();
            });
            let client=UdpAssociation::connect(&address,method,vec![key]).await.unwrap(); client.send(udp_destination(),b"ping").await.unwrap();
            let (source,payload)=client.recv().await.unwrap(); assert_eq!(source,udp_destination()); assert_eq!(payload,b"pong"); worker.await.unwrap();
        }
    }).await.unwrap();
}

#[test]
fn ss2022_udp_sliding_window_matches_go_boundaries() {
    let mut window=SlidingWindow::default(); assert!(window.check_and_add(0)); assert!(!window.check(0));
    assert!(window.check_and_add(9000)); assert!(!window.check(871)); assert!(window.check_and_add(872)); assert!(!window.check(872));
    assert!(window.check_and_add(8999)); assert!(!window.check(8999)); assert!(window.check_and_add(u64::MAX)); assert!(!window.check(9000)); assert!(!window.check(u64::MAX));
}

#[test]
fn ss2022_udp_server_session_rotation_and_authentication_before_mutation() {
    let method=CipherMethod::Aes128Gcm; let keys=vec![vec![1;16]]; let codec=PacketCodec::new(method,keys.clone()).unwrap();
    let mut client=ClientUdpSession::with_session_id(method,keys,123).unwrap();
    let response=|session_id,packet_id,now,client_id| codec.encode_at(&DecodedPacket{session_id,packet_id,header_type:HEADER_TYPE_SERVER,timestamp:now,client_session_id:Some(client_id),destination:udp_destination(),payload:vec![1]},&[],&[0;24]).unwrap();
    assert!(client.decode_at(&response(1,0,1000,124),1000).is_err());
    client.decode_at(&response(1,0,1000,123),1000).unwrap(); client.decode_at(&response(2,0,1000,123),1000).unwrap();
    let mut invalid=response(3,0,1000,123); *invalid.last_mut().unwrap()^=1; assert!(client.decode_at(&invalid,1000).is_err());
    assert!(client.decode_at(&response(3,0,1000,123),1000).is_err());
    client.decode_at(&response(1,1,1030,123),1030).unwrap();
    assert!(client.decode_at(&response(3,0,1089,123),1089).is_err()); client.decode_at(&response(3,0,1090,123),1090).unwrap();
    // Session 2 is the old session after rotation. Its age is over 60 seconds.
    assert!(client.decode_at(&response(2,1,1091,123),1091).is_err());
    // Retain the expired slot so another packet cannot re-admit the same session.
    assert!(client.decode_at(&response(2,1,1091,123),1091).is_err());
    // A distinct authenticated session can still rotate after the old age limit.
    client.decode_at(&response(1,2,1091,123),1091).unwrap();
}

#[test]
fn ss2022_upstream_dns_padding_budget_all_methods() {
    for method in METHODS {
        let keys = vec![vec![1; method.key_length()]];
        let codec = PacketCodec::new(method, keys.clone()).unwrap();
        let mut client = ClientUdpSession::with_session_id(method, keys, 123).unwrap();
        let mut destination = udp_destination();
        destination.port = 53;
        for length in [0, 1, 899, 900, 901] {
            let payload = vec![7; length];
            let unpadded = client.encode_at(destination.clone(), &payload, stream::unix_time().unwrap(), &[], &[0; 24]).unwrap();
            // Exercise the actual automatic random-padding branch, checking its range.
            for _ in 0..32 {
                let wire = client.encode(destination.clone(), &payload).unwrap();
                let padding = wire.len().checked_sub(unpadded.len()).unwrap();
                if length < stream::MAX_PADDING_LENGTH {
                    assert!((1..=stream::MAX_PADDING_LENGTH - length).contains(&padding));
                    assert!(length + padding <= stream::MAX_PADDING_LENGTH);
                } else {
                    assert_eq!(padding, 0);
                }
                assert!(wire.len() <= MAX_DATAGRAM_SIZE);
                let packet = codec.decode_at(&wire, HEADER_TYPE_CLIENT, stream::unix_time().unwrap()).unwrap();
                assert_eq!(packet.destination, destination);
                assert_eq!(packet.payload, payload);
            }
        }
        let payload = vec![7; 899];
        let unpadded = client.encode_at(destination.clone(), &payload, stream::unix_time().unwrap(), &[], &[0; 24]).unwrap();
        // Explicit caller-supplied padding and decoder acceptance are unchanged.
        let explicit = client.encode_at(destination.clone(), &payload, stream::unix_time().unwrap(), &[0; stream::MAX_PADDING_LENGTH], &[0; 24]).unwrap();
        assert_eq!(explicit.len(), unpadded.len() + stream::MAX_PADDING_LENGTH);
        assert_eq!(codec.decode_at(&explicit, HEADER_TYPE_CLIENT, stream::unix_time().unwrap()).unwrap().payload, payload);
        destination.port = 443;
        let unpadded = client.encode_at(destination.clone(), &payload, stream::unix_time().unwrap(), &[], &[0; 24]).unwrap();
        for _ in 0..32 {
            let wire = client.encode(destination.clone(), &payload).unwrap();
            assert_eq!(wire.len(), unpadded.len());
            assert_eq!(codec.decode_at(&wire, HEADER_TYPE_CLIENT, stream::unix_time().unwrap()).unwrap().payload, payload);
        }
    }
}

#[test]
fn ss2022_upstream_expired_old_session_is_not_readmitted_all_methods() {
    for method in METHODS {
        let keys = vec![vec![1; method.key_length()]];
        let codec = PacketCodec::new(method, keys.clone()).unwrap();
        let mut client = ClientUdpSession::with_session_id(method, keys, 123).unwrap();
        let response = |session_id, packet_id, now, client_id| codec.encode_at(&DecodedPacket {
            session_id, packet_id, header_type: HEADER_TYPE_SERVER, timestamp: now,
            client_session_id: Some(client_id), destination: udp_destination(), payload: vec![1],
        }, &[], &[0; 24]).unwrap();
        client.decode_at(&response(1, 0, 1000, 123), 1000).unwrap();
        client.decode_at(&response(2, 0, 1000, 123), 1000).unwrap();
        let expired = response(1, 1, 1061, 123);
        for _ in 0..3 {
            assert_eq!(client.decode_at(&expired, 1061).unwrap_err().to_string(), "old UDP server session expired");
        }
        let mut corrupt = response(3, u64::MAX, 1061, 123);
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(client.decode_at(&corrupt, 1061).is_err());
        assert_eq!(client.decode_at(&response(3, u64::MAX, 1061, 124), 1061).unwrap_err().to_string(), "UDP client session ID mismatch");
        // Rejections preserve the current session and its existing replay bits.
        client.decode_at(&response(2, 1, 1061, 123), 1061).unwrap();
        assert_eq!(client.decode_at(&response(2, 0, 1061, 123), 1061).unwrap_err().to_string(), "UDP packet ID not unique");
        // A clock step back exposes the retained old replay window at the exact boundary.
        assert_eq!(client.decode_at(&response(1, 0, 1060, 123), 1060).unwrap_err().to_string(), "UDP packet ID not unique");
        client.decode_at(&response(1, 1, 1060, 123), 1060).unwrap();
        // Fresh IDs rejected while expired were not consumed; refreshing old blocks a third ID.
        assert_eq!(client.decode_at(&response(3, 0, 1119, 123), 1119).unwrap_err().to_string(), "UDP server rotated sessions too quickly");
        client.decode_at(&response(3, 0, 1120, 123), 1120).unwrap();
        client.decode_at(&response(3, 1, 1120, 123), 1120).unwrap();
        client.decode_at(&response(2, 2, 1120, 123), 1120).unwrap();
        assert_eq!(client.decode_at(&response(2, 2, 1120, 123), 1120).unwrap_err().to_string(), "UDP packet ID not unique");
    }
}

#[test]
fn ss2022_upstream_server_rotation_sixty_second_boundaries_all_methods() {
    for method in METHODS {
        let keys = vec![vec![1; method.key_length()]];
        let codec = PacketCodec::new(method, keys.clone()).unwrap();
        let response = |session_id, packet_id, now| codec.encode_at(&DecodedPacket {
            session_id, packet_id, header_type: HEADER_TYPE_SERVER, timestamp: now,
            client_session_id: Some(123), destination: udp_destination(), payload: vec![1],
        }, &[], &[0; 24]).unwrap();
        for age in [59, 60, 61] {
            let now = 1000 + age;
            let mut client = ClientUdpSession::with_session_id(method, keys.clone(), 123).unwrap();
            client.decode_at(&response(1, 0, 1000), 1000).unwrap();
            client.decode_at(&response(2, 0, 1000), 1000).unwrap();
            let old = client.decode_at(&response(1, 1, now), now);
            if age <= 60 {
                old.unwrap();
                assert_eq!(client.decode_at(&response(1, 1, now), now).unwrap_err().to_string(), "UDP packet ID not unique");
            } else {
                assert_eq!(old.unwrap_err().to_string(), "old UDP server session expired");
                assert_eq!(client.decode_at(&response(1, 1, now), now).unwrap_err().to_string(), "old UDP server session expired");
            }
            client.decode_at(&response(2, 1, now), now).unwrap();
            // Test third-session admission independently of the old packet refreshing last_seen.
            let mut client = ClientUdpSession::with_session_id(method, keys.clone(), 123).unwrap();
            client.decode_at(&response(1, 0, 1000), 1000).unwrap();
            client.decode_at(&response(2, 0, 1000), 1000).unwrap();
            let third = client.decode_at(&response(3, 0, now), now);
            if age < 60 {
                assert_eq!(third.unwrap_err().to_string(), "UDP server rotated sessions too quickly");
                client.decode_at(&response(3, 0, 1060), 1060).unwrap();
            } else {
                third.unwrap();
                assert_eq!(client.decode_at(&response(3, 0, now), now).unwrap_err().to_string(), "UDP packet ID not unique");
            }
        }
    }
}

#[tokio::test]
async fn ss2022_unknown_tcp_eih_does_not_authenticate() {
    let method=CipherMethod::Aes128Gcm; let multi=MultiUserServer::new("test",method,vec![1;16]).unwrap();
    multi.add_account(UserAccount{key:vec![2;16],user:identity("known@example")}).unwrap();
    let salt=vec![3;16]; let (request,_)=stream::encode_request(method,&[9;16],&salt,&Destination::from_domain_port("example.com",443),&[0],&[],stream::unix_time().unwrap()).unwrap();
    let mut wire=salt.clone(); wire.extend(tcp_headers(method,&[vec![1;16],vec![9;16]],&salt).unwrap()); wire.extend_from_slice(&request[salt.len()..]);
    assert!(multi.handle_connection(Box::pin(Cursor::new(wire)),"127.0.0.1:1".parse().unwrap()).await.is_err());
    assert!(MultiUserServer::new("bad",CipherMethod::ChaCha20Poly1305,vec![1;32]).is_err());
    assert!(super::kdf::parse_psk_list("bad:bad",method).is_err());
    assert!(PacketCodec::new(CipherMethod::ChaCha20Poly1305,vec![vec![1;32],vec![2;32]]).is_err());
}

#[test]
fn ss2022_multiuser_management_matches_go_email_and_key_indices() {
    let method = CipherMethod::Aes128Gcm;
    let server = MultiUserServer::new("multi", method, vec![1; 16]).unwrap();
    let first = UserAccount { key: vec![2; 16], user: identity("First@Example") };
    let second = UserAccount { key: vec![2; 16], user: identity("Second@Example") };
    server.add_account(first.clone()).unwrap();
    assert!(server.add_account(UserAccount { key: vec![3; 16], user: identity("FIRST@EXAMPLE") }).is_err());
    server.add_account(second.clone()).unwrap();
    assert_eq!(server.user_count().unwrap(), 2);
    assert_eq!(server.users().unwrap().len(), 2);
    assert_eq!(server.user_by_email("first@example").unwrap(), Some(first.user));
    assert_eq!(server.account(&super::kdf::user_psk_hash(&second.key)).unwrap().user, second.user);
    server.remove_account("FIRST@EXAMPLE").unwrap();
    assert_eq!(server.user_count().unwrap(), 1);
    assert!(server.user_by_email("first@example").unwrap().is_none());
    // Go removes the shared hash even when another email alias still exists.
    assert!(server.account(&super::kdf::user_psk_hash(&second.key)).is_err());
    assert!(server.remove_account("").is_err());
    assert!(server.remove_account("absent@example").is_err());
}
