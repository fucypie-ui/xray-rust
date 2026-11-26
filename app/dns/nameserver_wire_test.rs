use super::nameserver::{
    NameServer, build_dns_query_typed, parse_dns_response_with_ttl, try_build_dns_query_with_ecs,
};
use super::nameserver_tcp::TcpNameServer;
use super::nameserver_udp::UdpNameServer;
use super::nameserver_doh::DohNameServer;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn spawn_server<F>(future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), future).await.expect("loopback DNS server stalled");
    })
}

// Hand-packed fixtures keep these tests independent of the production decoder.
fn answer(query: &[u8], records: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for (rtype, ttl, data) in records {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&rtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(data);
    }
    response
}

#[test]
fn dns_wire_go_cname_ttl_limits_address_ttl() {
    // dnscommon.go parseResponse uses every answer TTL, including CNAMEs.
    let query = build_dns_query_typed("www.example.com", 1);
    // www.example.com CNAME example.com; example.com A 8.8.8.8.
    // Offset 16 points past the initial www label to example.com.
    let mut response = answer(&query, &[(5, 7, &[0xc0, 0x10]), (1, 300, &[8, 8, 8, 8])]);
    let address_owner = query.len() + 14;
    response[address_owner..address_owner + 2].copy_from_slice(&[0xc0, 0x10]);
    let (ips, ttl) = parse_dns_response_with_ttl(&response, "WWW.EXAMPLE.COM.").unwrap();
    assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    assert_eq!(ttl, 7);
}

#[test]
fn dns_wire_go_zero_ttl_is_one_second() {
    let query = build_dns_query_typed("example.com", 1);
    let response = answer(&query, &[(1, 0, &[8, 8, 4, 4])]);
    assert_eq!(parse_dns_response_with_ttl(&response, "example.com").unwrap().1, 1);
}

#[test]
fn dns_wire_maximum_ttl_is_not_a_missing_ttl() {
    let query = build_dns_query_typed("example.com", 1);
    let response = answer(&query, &[(1, u32::MAX, &[8, 8, 4, 4])]);
    assert_eq!(parse_dns_response_with_ttl(&response, "example.com").unwrap().1, u32::MAX);
}

#[test]
fn dns_wire_rejects_partial_answer_instead_of_caching_prefix() {
    let query = build_dns_query_typed("example.com", 1);
    let mut response = answer(&query, &[(1, 30, &[8, 8, 8, 8]), (1, 30, &[8, 8, 4, 4])]);
    response.pop();
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
}

#[test]
fn dns_wire_rejects_query_opcode_class_and_question_mismatches() {
    let query = build_dns_query_typed("example.com", 1);
    let valid = answer(&query, &[(1, 30, &[8, 8, 8, 8])]);
    for (byte, mask) in [(2, 0x80), (2, 0x08), (query.len() - 1, 0x02)] {
        let mut response = valid.clone();
        response[byte] ^= mask;
        assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
    }
    assert!(parse_dns_response_with_ttl(&valid, "other.example").is_err());
}

#[test]
fn dns_wire_rejects_truncated_response_even_with_complete_address() {
    let query = build_dns_query_typed("example.com", 1);
    let mut response = answer(&query, &[(1, 30, &[8, 8, 8, 8])]);
    response[2] |= 0x02;
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
}

#[test]
fn dns_wire_rejects_compression_loop_and_bad_address_length() {
    let query = build_dns_query_typed("example.com", 1);
    let mut response = answer(&query, &[(1, 30, &[8, 8, 8, 8])]);
    let offset = query.len();
    response[offset..offset + 2].copy_from_slice(&(0xc000 | offset as u16).to_be_bytes());
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
    let response = answer(&query, &[(1, 30, &[8, 8, 8])]);
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
}

#[test]
fn dns_wire_every_truncated_prefix_is_rejected() {
    let query = build_dns_query_typed("example.com", 1);
    let response = answer(&query, &[(1, 30, &[8, 8, 8, 8]), (1, 30, &[8, 8, 4, 4])]);
    for length in 0..response.len() {
        assert!(parse_dns_response_with_ttl(&response[..length], "example.com").is_err(), "accepted prefix of {length} bytes");
    }
}

#[test]
fn dns_wire_invalid_names_are_rejected_before_transport() {
    for domain in [format!("{}.example", "x".repeat(64)), "x.".repeat(128), "example..com".into()] {
        assert!(try_build_dns_query_with_ecs(&domain, 1, None).is_err(), "accepted invalid name {domain}");
    }
    let query = try_build_dns_query_with_ecs("example.com.", 28, None).unwrap();
    assert_eq!(&query[query.len() - 4..], &[0, 28, 0, 1]);
}

#[test]
fn dns_wire_address_class_and_ipv4_mapped_aaaa_are_ignored() {
    let query = build_dns_query_typed("example.com", 1);
    let mut response = answer(&query, &[(1, 30, &[1, 1, 1, 1]), (1, 30, &[8, 8, 8, 8])]);
    response[query.len() + 5] = 3; // CH class on the first answer.
    assert_eq!(parse_dns_response_with_ttl(&response, "example.com").unwrap().0,
        vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    let query = build_dns_query_typed("example.com", 28);
    let response = answer(&query, &[(28, 30, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8])]);
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
}

#[test]
fn dns_wire_error_codes_include_edns_extended_rcode() {
    let query = build_dns_query_typed("example.com", 1);
    let mut response = answer(&query, &[(1, 30, &[8, 8, 8, 8])]);
    response[3] |= 3; // NXDOMAIN must not expose an address.
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
    response[3] &= 0xf0;
    response[10..12].copy_from_slice(&[0, 1]);
    response.extend_from_slice(&[0, 0, 41, 5, 70, 1, 0, 0, 0, 0, 0]); // BADVERS (16).
    assert!(parse_dns_response_with_ttl(&response, "example.com").is_err());
}

#[tokio::test]
async fn dns_wire_no_families_means_no_query() {
    // A closed port is safe because no socket should be opened.
    let addr = "127.0.0.1:0".parse().unwrap();
    assert!(UdpNameServer::new(addr).query_ip_with_opt("example.com", false, false).await.is_err());
    assert!(TcpNameServer::new(addr).query_ip_with_opt("example.com", false, false).await.is_err());
}

#[tokio::test]
async fn dns_wire_udp_large_response_is_not_cut_at_2048_bytes() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = spawn_server(async move {
        let mut buf = [0; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let address: &[u8] = &[8, 8, 8, 8];
        let response = answer(&buf[..n], &vec![(1, 13, address); 200]);
        assert!(response.len() > 2048);
        socket.send_to(&response, peer).await.unwrap();
    });
    let ns = UdpNameServer::with_timeout(addr, Duration::from_secs(2));
    let (ips, ttl) = ns.query_ip_with_opt("example.com", true, false).await.unwrap();
    assert_eq!(ips.len(), 200);
    assert_eq!(ttl, 13);
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_udp_ignores_wrong_transaction_and_question() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = spawn_server(async move {
        let mut buf = [0; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let query = &buf[..n];
        let mut wrong_id = answer(query, &[(1, 30, &[1, 1, 1, 1])]);
        wrong_id[0] ^= 0x80;
        socket.send_to(&wrong_id, peer).await.unwrap();
        let mut wrong_question = answer(query, &[(1, 30, &[2, 2, 2, 2])]);
        wrong_question[13] = b'X';
        socket.send_to(&wrong_question, peer).await.unwrap();
        let mut wrong_type = answer(query, &[(1, 30, &[3, 3, 3, 3])]);
        wrong_type[n - 3] = 28;
        socket.send_to(&wrong_type, peer).await.unwrap();
        socket.send_to(&answer(query, &[(1, 17, &[8, 8, 8, 8])]), peer).await.unwrap();
    });
    let ns = UdpNameServer::with_timeout(addr, Duration::from_secs(2));
    let (ips, ttl) = ns.query_ip_with_opt("example.com", true, false).await.unwrap();
    assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    assert_eq!(ttl, 17);
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_udp_edns_retry_after_truncation() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = spawn_server(async move {
        let mut buf = [0; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let first_id = [buf[0], buf[1]];
        assert_eq!(&buf[10..12], &[0, 0]);
        let mut truncated = answer(&buf[..n], &[]);
        truncated[2] |= 2;
        socket.send_to(&truncated, peer).await.unwrap();
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        assert_ne!(&buf[..2], &first_id);
        assert_eq!(&buf[10..12], &[0, 1]);
        assert_eq!(&buf[n - 8..n - 6], &1350u16.to_be_bytes());
        // Remove the OPT before appending the answer section.
        let mut query = buf[..n - 11].to_vec();
        query[10..12].copy_from_slice(&[0, 0]);
        socket.send_to(&answer(&query, &[(1, 9, &[8, 8, 4, 4])]), peer).await.unwrap();
    });
    let ns = UdpNameServer::with_timeout(addr, Duration::from_secs(2));
    assert_eq!(ns.query_ip_with_opt("example.com", true, false).await.unwrap().1, 9);
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_udp_dual_stack_is_concurrent_and_filters_families() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = spawn_server(async move {
        let mut pending = Vec::new();
        // Waiting for both requests before replying catches sequential queries.
        for _ in 0..2 {
            let mut buf = vec![0; 4096];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            buf.truncate(n);
            pending.push((buf, peer));
        }
        for (query, peer) in pending {
            let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            let response = if qtype == 1 {
                answer(&query, &[(1, 30, &[8, 8, 8, 8])])
            } else {
                // An A answer to AAAA must never escape the IPv6 query path.
                answer(&query, &[(1, 1, &[1, 1, 1, 1]), (28, 20, &[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])])
            };
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let ns = UdpNameServer::with_timeout(addr, Duration::from_secs(2));
    let (ips, ttl) = ns.query_ip_with_opt("example.com", true, true).await.unwrap();
    assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]);
    // Go limits TTL using all answer headers, even a skipped record.
    assert_eq!(ttl, 1);
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_tcp_reads_fragmented_length_and_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = spawn_server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; size as usize];
        stream.read_exact(&mut query).await.unwrap();
        let response = answer(&query, &[(1, 23, &[8, 8, 8, 8])]);
        let mut framed = (response.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&response);
        for byte in framed {
            stream.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let ns = TcpNameServer::with_timeout(addr, Duration::from_secs(2));
    assert_eq!(ns.query_ip_with_opt("example.com", true, false).await.unwrap().1, 23);
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_tcp_rejects_transaction_mismatch_and_short_frame() {
    for short_frame in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = spawn_server(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap();
            let mut query = vec![0; size as usize];
            stream.read_exact(&mut query).await.unwrap();
            let mut response = answer(&query, &[(1, 23, &[8, 8, 8, 8])]);
            response[0] ^= 1;
            if short_frame { response.truncate(4); }
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let ns = TcpNameServer::with_timeout(addr, Duration::from_secs(2));
        assert!(ns.query_ip_with_opt("example.com", true, false).await.is_err());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn dns_wire_tcp_rejects_incomplete_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = spawn_server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; size as usize];
        stream.read_exact(&mut query).await.unwrap();
        let response = answer(&query, &[(1, 23, &[8, 8, 8, 8])]);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response[..response.len() - 1]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let ns = TcpNameServer::with_timeout(addr, Duration::from_secs(2));
    assert!(ns.query_ip_with_opt("example.com", true, false).await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_tcp_deadline_covers_prefix_and_body_together() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = spawn_server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; size as usize];
        stream.read_exact(&mut query).await.unwrap();
        let response = answer(&query, &[(1, 23, &[8, 8, 8, 8])]);
        tokio::time::sleep(Duration::from_millis(60)).await;
        if stream.write_u16(response.len() as u16).await.is_err() { return; }
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = stream.write_all(&response).await;
    });
    let ns = TcpNameServer::with_timeout(addr, Duration::from_millis(100));
    assert!(matches!(ns.query_ip_with_opt("example.com", true, false).await, Err(crate::common::errors::Error::Timeout)));
    task.await.unwrap();
}

#[tokio::test]
async fn dns_wire_doh_uses_zero_id_and_checks_transaction() {
    for wrong_id in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = spawn_server(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
                assert!(header.len() <= 4096);
            }
            let text = String::from_utf8(header).unwrap();
            let length: usize = text.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.eq_ignore_ascii_case("content-length") { value.trim().parse().ok() } else { None }
            }).unwrap();
            let mut query = vec![0; length];
            stream.read_exact(&mut query).await.unwrap();
            assert_eq!(&query[..2], &[0, 0]);
            let mut response = answer(&query, &[(1, 19, &[8, 8, 8, 8])]);
            if wrong_id { response[0] = 1; }
            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let ns = DohNameServer::with_timeout(format!("http://{addr}/dns-query"), Duration::from_secs(2));
        let result = ns.query_ip_with_opt("example.com", true, false).await;
        if wrong_id { assert!(result.is_err()); } else { assert_eq!(result.unwrap().1, 19); }
        task.await.unwrap();
    }
}
