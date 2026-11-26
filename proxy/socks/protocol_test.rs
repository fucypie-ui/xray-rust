use super::protocol::{SocksProtocol, read_address_port, read_until_null, read_username_password};
use crate::common::net::{Address, Destination};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

// From Xray-core/proxy/socks/protocol_test.go: the version byte is ignored.
#[tokio::test]
async fn read_username_password_go_vectors() {
    let input = [0x05, 0x01, b'a', 0x02, b'b', b'c'];
    let mut reader = input.as_slice();
    let (username, password) = read_username_password(&mut reader).await.unwrap();
    assert_eq!(username, b"a");
    assert_eq!(password, b"bc");
    assert!(reader.is_empty());

    let input = [0x05, 0x18, b'a', 0x02, b'b', b'c'];
    assert!(read_username_password(&mut input.as_slice()).await.is_err());
}

#[tokio::test]
async fn read_username_password_checks_every_truncation() {
    let input = [1, 1, b'a', 2, b'b', b'c'];
    for end in 0..input.len() {
        assert!(read_username_password(&mut &input[..end]).await.is_err(), "prefix {end}");
    }
    let input = [1, 1, 0xff, 1, 0xfe, b'x'];
    let mut reader = input.as_slice();
    assert_eq!(read_username_password(&mut reader).await.unwrap(), (vec![0xff], vec![0xfe]));
    assert_eq!(reader, b"x");
    assert_eq!(read_username_password(&mut [1, 0, 0].as_slice()).await.unwrap(), (vec![], vec![]));
}

#[tokio::test]
async fn read_until_null_go_vectors_and_buffer_boundary() {
    let mut reader = b"ab\0payload".as_slice();
    assert_eq!(read_until_null(&mut reader).await.unwrap(), b"ab");
    assert_eq!(reader, b"payload");
    assert!(read_until_null(&mut b"a".as_slice()).await.is_err());
    assert_eq!(read_until_null(&mut b"\0".as_slice()).await.unwrap(), b"");

    let mut maximum = vec![b'a'; 8191];
    maximum.push(0);
    assert_eq!(read_until_null(&mut maximum.as_slice()).await.unwrap().len(), 8191);
    let overrun = vec![b'a'; 8192];
    assert!(read_until_null(&mut overrun.as_slice()).await.is_err());
}

#[tokio::test]
async fn address_reader_matches_go_normalization_and_domain_validation() {
    let vectors = [
        ("example.com", Address::Domain("example.com".into())),
        ("_service.Example-1", Address::Domain("_service.Example-1".into())),
        ("127.0.0.1", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        ("[::1]", Address::Ipv6(Ipv6Addr::LOCALHOST)),
        ("[::ffff:127.0.0.1]", Address::Ipv4(Ipv4Addr::LOCALHOST)),
        ("2001:db8::1", Address::Ipv6("2001:db8::1".parse().unwrap())),
        ("123.example", Address::Domain("123.example".into())),
    ];
    for (domain, expected) in vectors {
        let mut wire = vec![3, domain.len() as u8];
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&[0x01, 0xbb, b'x']);
        let mut reader = wire.as_slice();
        assert_eq!(read_address_port(&mut reader).await.unwrap(), Destination::tcp(expected, 443));
        assert_eq!(reader, b"x");
    }
    for domain in ["", "bad/name", "has space", "bad\0name", "é.example", "abcd::1"] {
        let mut wire = vec![3, domain.len() as u8];
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&[0, 80]);
        assert!(read_address_port(&mut wire.as_slice()).await.is_err(), "{domain:?}");
    }
}

#[tokio::test]
async fn address_reader_checks_all_families_and_truncations() {
    let mut v6 = vec![4];
    v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    v6.extend_from_slice(&[0x04, 0x00]);
    let vectors = [vec![1, 1, 2, 3, 4, 0x04, 0x00], v6, vec![3, 1, b'a', 0x04, 0x00]];
    for wire in vectors {
        assert_eq!(read_address_port(&mut wire.as_slice()).await.unwrap().port, 1024);
        for end in 0..wire.len() {
            assert!(read_address_port(&mut &wire[..end]).await.is_err(), "{wire:?}, prefix {end}");
        }
    }
    for atyp in [0, 2, 5, 16, 255] {
        assert!(read_address_port(&mut [atyp].as_slice()).await.is_err());
    }
    let mut mapped = vec![4];
    mapped.extend_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
    mapped.extend_from_slice(&[0, 80]);
    assert_eq!(read_address_port(&mut mapped.as_slice()).await.unwrap().address, Address::Ipv4(Ipv4Addr::LOCALHOST));
}

#[tokio::test]
async fn client_emits_go_password_and_connect_vectors() {
    timeout(Duration::from_secs(5), async {
        let (mut client, mut peer) = tokio::io::duplex(64);
        let target = Destination::from_domain_port("example.com", 443);
        let peer_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            peer.write_all(&[5, 2]).await.unwrap();
            let mut credentials = [0; 6];
            peer.read_exact(&mut credentials).await.unwrap();
            assert_eq!(credentials, [1, 1, b'a', 2, b'b', b'c']);
            // Go ignores the version in the password and CONNECT replies.
            peer.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 18];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"\x05\x01\x00\x03\x0bexample.com\x01\xbb");
            peer.write_all(b"\x04\x00\x7f\x03\x03bnd\x04\x00data").await.unwrap();
        });
        SocksProtocol::client_handshake_with_auth(&mut client, &target, Some(("a", "bc"))).await.unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"data");
        peer_task.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn client_ipv4_and_ipv6_requests_preserve_payload_after_bound_address() {
    timeout(Duration::from_secs(5), async {
        let mut v6 = vec![5, 0, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 80]);
        let mut ipv6_request = vec![5, 1, 0, 4];
        ipv6_request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6_request.extend_from_slice(&[0, 80]);
        let cases = [
            (Destination::tcp(Address::Ipv4(Ipv4Addr::LOCALHOST), 80), vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 80], vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 80]),
            (Destination::tcp(Address::Ipv6(Ipv6Addr::LOCALHOST), 80), ipv6_request, v6),
        ];
        for (target, expected_request, mut reply) in cases {
            reply.extend_from_slice(b"data");
            let (mut client, mut peer) = tokio::io::duplex(64);
            let task = tokio::spawn(async move {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                peer.write_all(&[5, 0]).await.unwrap();
                let mut request = vec![0; expected_request.len()];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(request, expected_request);
                peer.write_all(&reply).await.unwrap();
            });
            SocksProtocol::client_handshake(&mut client, &target).await.unwrap();
            let mut payload = [0; 4];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"data");
            task.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn client_rejects_method_downgrade_password_failure_and_request_failure() {
    timeout(Duration::from_secs(5), async {
        // Replies are pipelined; no peer task is needed for these small vectors.
        for reply in [
            vec![4, 2],
            vec![5, 0],
            vec![5, 255],
            vec![5, 2, 1, 255],
            vec![5, 2, 1, 0, 5, 7, 0],
            vec![5, 2, 1, 0, 5, 0, 0, 2],
            vec![5, 2, 1, 0, 5, 0, 0, 1, 127],
        ] {
            let (mut client, mut peer) = tokio::io::duplex(128);
            peer.write_all(&reply).await.unwrap();
            peer.shutdown().await.unwrap();
            let target = Destination::from_domain_port("example.com", 443);
            assert!(SocksProtocol::client_handshake_with_auth(&mut client, &target, Some(("a", "bc"))).await.is_err(), "{reply:?}");
        }
    }).await.unwrap();
}

#[tokio::test]
async fn client_rejects_length_overflow_and_udp_before_writing() {
    let target = Destination::from_domain_port("example.com", 443);
    let oversized = "a".repeat(256);
    let cases = [
        (Destination::from_domain_port(&oversized, 443), None),
        (target.clone(), Some((oversized.as_str(), "pass"))),
        (target, Some(("user", oversized.as_str()))),
        (Destination::udp(Address::Ipv4(Ipv4Addr::LOCALHOST), 53), None),
    ];
    for (target, account) in cases {
        let (mut client, mut peer) = tokio::io::duplex(128);
        assert!(SocksProtocol::client_handshake_with_auth(&mut client, &target, account).await.is_err());
        drop(client);
        let mut emitted = Vec::new();
        peer.read_to_end(&mut emitted).await.unwrap();
        assert!(emitted.is_empty());
    }
}
