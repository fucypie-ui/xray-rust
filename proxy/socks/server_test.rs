use super::Server;
use crate::common::errors::Result;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::inbound::InboundHandler;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

fn password_server() -> Server {
    Server::with_auth("socks-auth", HashMap::from([("a".into(), "bc".into())]))
}

// Send a complete wire vector through the actual inbound handler. Capture both
// the emitted handshake and any bytes passed to the application's stream.
async fn exchange(server: Server, wire: &[u8]) -> (Result<SessionContext>, Vec<u8>, Vec<u8>) {
    timeout(Duration::from_secs(5), async {
        let (mut client, stream) = tokio::io::duplex(32768);
        client.write_all(wire).await.unwrap();
        client.shutdown().await.unwrap();
        let remote = "127.0.0.1:54321".parse().unwrap();
        let result = server.handle_connection(Box::pin(stream), remote).await;
        let mut payload = Vec::new();
        let session = match result {
            Ok(mut inbound) => {
                inbound.stream.read_to_end(&mut payload).await.unwrap();
                Ok(inbound.session)
            }
            Err(error) => Err(error),
        };
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (session, reply, payload)
    }).await.unwrap()
}

#[tokio::test]
async fn socks5_rejects_unoffered_and_empty_auth_methods() {
    for greeting in [&[5, 1, 2][..], &[5, 0], &[5, 2, 1, 255]] {
        let (result, reply, _) = exchange(Server::new("socks-in"), greeting).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 255]);
    }
    let (result, reply, _) = exchange(password_server(), &[5, 1, 0]).await;
    assert!(result.is_err());
    assert_eq!(reply, [5, 255]);
}

#[tokio::test]
async fn socks5_connect_and_tor_commands_match_go() {
    for command in [1, 0xf0, 0xf1] {
        // Go ignores VER and RSV in the request after a valid negotiation.
        let wire = [5, 3, 2, 0, 1, 4, command, 0xff, 1, 1, 2, 3, 4, 1, 187, b'x'];
        let (result, reply, payload) = exchange(Server::new("socks-in"), &wire).await;
        let session = result.unwrap();
        assert_eq!(session.destination, Destination::tcp(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443));
        assert_eq!(session.inbound_tag, "socks-in");
        assert_eq!(session.source, Some("127.0.0.1:54321".parse().unwrap()));
        assert!(session.user.is_none());
        assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(payload, b"x");
    }
}

#[tokio::test]
async fn socks5_rejects_bind_udp_and_unknown_command_before_reading_address() {
    for command in [0, 2, 3, 4, 255] {
        let (result, reply, _) = exchange(Server::new("socks-in"), &[5, 1, 0, 5, command, 0]).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
}

#[tokio::test]
async fn socks5_password_go_vector_and_session_identity() {
    // The 0x05 subnegotiation version is the Go TestReadUsernamePassword vector.
    let wire = b"\x05\x02\x00\x02\x05\x01a\x02bc\x05\x01\x00\x03\x0bexample.com\x01\xbbping";
    let (result, reply, payload) = exchange(password_server(), wire).await;
    let session = result.unwrap();
    assert_eq!(session.destination, Destination::from_domain_port("example.com", 443));
    assert_eq!(session.user.unwrap().email, "a");
    assert_eq!(reply, [5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(payload, b"ping");
}

#[tokio::test]
async fn socks5_password_failures_emit_go_auth_failure_only() {
    for credentials in [b"\x01\x01a\x02bd".as_slice(), b"\x01\x01z\x02bc", b"\x01\x01\xff\x02bc"] {
        let mut wire = vec![5, 1, 2];
        wire.extend_from_slice(credentials);
        let (result, reply, _) = exchange(password_server(), &wire).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2, 1, 255]);
    }
    let (result, reply, _) = exchange(Server::with_auth("empty", HashMap::new()), b"\x05\x01\x02\x01\x00\x00").await;
    assert!(result.is_err());
    assert_eq!(reply, [5, 2, 1, 255]);
}

#[tokio::test]
async fn socks5_accepts_configured_empty_credentials_like_go() {
    let server = Server::with_auth("empty-account", HashMap::from([("".into(), "".into())]));
    let wire = b"\x05\x01\x02\x01\x00\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50";
    let (result, reply, _) = exchange(server, wire).await;
    assert!(result.unwrap().user.is_none());
    assert_eq!(reply, [5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn socks5_rejects_truncated_credentials_without_success_reply() {
    let credentials = [1, 1, b'a', 2, b'b', b'c'];
    for end in 0..credentials.len() {
        let mut wire = vec![5, 1, 2];
        wire.extend_from_slice(&credentials[..end]);
        let (result, reply, _) = exchange(password_server(), &wire).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2]);
    }
}

#[tokio::test]
async fn socks5_accepts_maximum_credential_and_domain_lengths() {
    let username = "a".repeat(255);
    let password = "b".repeat(255);
    let domain = "c".repeat(255);
    let server = Server::with_auth("max", HashMap::from([(username.clone(), password.clone())]));
    let mut wire = vec![5, 1, 2, 1, 255];
    wire.extend_from_slice(username.as_bytes());
    wire.push(255);
    wire.extend_from_slice(password.as_bytes());
    wire.extend_from_slice(&[5, 1, 0, 3, 255]);
    wire.extend_from_slice(domain.as_bytes());
    wire.extend_from_slice(&[255, 255]);
    let (result, reply, _) = exchange(server, &wire).await;
    let session = result.unwrap();
    assert_eq!(session.user.unwrap().email, username);
    assert_eq!(session.destination, Destination::from_domain_port(domain, 65535));
    assert_eq!(reply, [5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn socks5_accepts_ipv6_and_normalizes_ipv4_mapped_addresses() {
    for (ip, expected) in [
        (Ipv6Addr::LOCALHOST, Address::Ipv6(Ipv6Addr::LOCALHOST)),
        (Ipv4Addr::LOCALHOST.to_ipv6_mapped(), Address::Ipv4(Ipv4Addr::LOCALHOST)),
    ] {
        let mut wire = vec![5, 1, 0, 5, 1, 0, 4];
        wire.extend_from_slice(&ip.octets());
        wire.extend_from_slice(&[0, 80]);
        let (result, reply, payload) = exchange(Server::new("socks-in"), &wire).await;
        assert_eq!(result.unwrap().destination, Destination::tcp(expected, 80));
        assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(payload.is_empty());
    }
}

#[tokio::test]
async fn socks5_never_returns_a_tunnel_for_truncated_or_invalid_addresses() {
    let wire = b"\x05\x01\x00\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    for end in 3..wire.len() {
        let (result, reply, _) = exchange(Server::new("socks-in"), &wire[..end]).await;
        assert!(result.is_err(), "prefix {end}");
        assert_eq!(reply, [5, 0]);
    }
    for address in [b"\x02".as_slice(), b"\x03\x00\x00\x50", b"\x03\x03a/b\x00\x50"] {
        let mut wire = vec![5, 1, 0, 5, 1, 0];
        wire.extend_from_slice(address);
        let (result, reply, _) = exchange(Server::new("socks-in"), &wire).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 0]);
    }
}

#[tokio::test]
async fn socks4_connect_ignores_user_id_and_preserves_payload() {
    let wire = b"\x04\x01\x00\x50\x01\x02\x03\x04\xffuser\x00ping";
    let (result, reply, payload) = exchange(Server::new("socks4"), wire).await;
    assert_eq!(result.unwrap().destination, Destination::tcp(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80));
    assert_eq!(reply, [0, 90, 0, 0, 0, 0, 0, 0]);
    assert_eq!(payload, b"ping");
}

#[tokio::test]
async fn socks4a_matches_go_first_octet_detection_and_domain_parsing() {
    for ip in [[0, 0, 0, 1], [0, 1, 2, 3], [0, 0, 0, 0]] {
        for (domain, expected) in [
            ("example.com", Address::Domain("example.com".into())),
            ("127.0.0.1", Address::Ipv4(Ipv4Addr::LOCALHOST)),
            ("[::1]", Address::Ipv6(Ipv6Addr::LOCALHOST)),
        ] {
            let mut wire = vec![4, 1, 1, 187];
            wire.extend_from_slice(&ip);
            wire.push(0);
            wire.extend_from_slice(domain.as_bytes());
            wire.extend_from_slice(b"\0data");
            let (result, reply, payload) = exchange(Server::new("socks4a"), &wire).await;
            assert_eq!(result.unwrap().destination, Destination::tcp(expected, 443));
            assert_eq!(reply, [0, 90, 0, 0, 0, 0, 0, 0]);
            assert_eq!(payload, b"data");
        }
    }
}

#[tokio::test]
async fn socks4_rejects_password_mode_and_unsupported_commands() {
    // Password mode rejects immediately after VER and CMD, as Go does.
    let (result, reply, _) = exchange(password_server(), &[4, 1]).await;
    assert!(result.is_err());
    assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
    for command in [0, 2, 3, 255] {
        let (result, reply, _) = exchange(Server::new("socks4"), &[4, command, 0, 80, 1, 2, 3, 4, 0]).await;
        assert!(result.is_err());
        assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
    }
}

#[tokio::test]
async fn socks4a_truncation_and_unterminated_fields_never_return_success() {
    let wire = b"\x04\x01\x00\x50\x00\x00\x00\x01user\x00example.com\x00";
    for end in 0..wire.len() {
        let (result, reply, _) = exchange(Server::new("socks4a"), &wire[..end]).await;
        assert!(result.is_err(), "prefix {end}");
        assert!(reply.is_empty());
    }
    let mut wire = vec![4, 1, 0, 80, 1, 2, 3, 4];
    wire.extend_from_slice(&[b'a'; 8192]);
    let (result, reply, _) = exchange(Server::new("socks4"), &wire).await;
    assert!(result.is_err());
    assert!(reply.is_empty());
}

#[tokio::test]
async fn socks5_fragmented_password_handshake_and_bidirectional_payload() {
    timeout(Duration::from_secs(5), async {
        // A one-byte transport buffer forces reads and writes across boundaries.
        let (mut client, stream) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            let remote: SocketAddr = "127.0.0.1:54321".parse().unwrap();
            let mut inbound = password_server().handle_connection(Box::pin(stream), remote).await.unwrap();
            assert_eq!(inbound.session.destination.network, Network::Tcp);
            let mut payload = [0; 4];
            inbound.stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            inbound.stream.write_all(b"pong").await.unwrap();
        });
        for byte in [5, 1, 2] { client.write_all(&[byte]).await.unwrap(); }
        let mut selected = [0; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        for byte in [1, 1, b'a', 2, b'b', b'c'] { client.write_all(&[byte]).await.unwrap(); }
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [1, 0]);
        for byte in [5, 1, 0, 1, 127, 0, 0, 1, 0, 80] { client.write_all(&[byte]).await.unwrap(); }
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        client.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        task.await.unwrap();
    }).await.unwrap();
}
