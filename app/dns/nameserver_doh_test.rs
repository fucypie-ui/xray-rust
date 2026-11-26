#[cfg(test)]
mod tests {
    use super::super::nameserver::NameServer;
    use super::super::nameserver_doh::DohNameServer;
    use crate::common::errors::Result;
    use crate::transport::internet::tls::tls::TlsServer;
    use std::net::IpAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Independent, complete DNS response: example.com IN A 8.8.8.8, TTL 19, ID 0.
    fn dns_answer() -> Vec<u8> {
        vec![
            0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 19, 0, 4, 8, 8, 8, 8,
        ]
    }

    async fn read_request(stream: &mut TcpStream) {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() <= 4096);
        }
        let text = String::from_utf8(header).unwrap();
        let length: usize = text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        }).unwrap();
        let mut query = vec![0; length];
        stream.read_exact(&mut query).await.unwrap();
        assert_eq!(&query[..2], &[0, 0]);
    }

    async fn http_exchange(parts: Vec<Vec<u8>>) -> Result<(Vec<IpAddr>, u32)> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                for part in parts {
                    // The client may close early after rejecting an oversized frame.
                    if stream.write_all(&part).await.is_err() { return; }
                    tokio::task::yield_now().await;
                }
                let _ = stream.shutdown().await;
            }).await.expect("loopback DoH server stalled");
        });
        let ns = DohNameServer::with_timeout(format!("http://{addr}/dns-query"), Duration::from_secs(3));
        let result = ns.query_ip_with_opt("example.com", true, false).await;
        task.await.unwrap();
        result
    }

    fn http_header(framing: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n{framing}Connection: close\r\n\r\n").into_bytes()
    }

    #[tokio::test]
    async fn dns_doh_rejects_short_content_length_body() {
        let body = dns_answer();
        let header = http_header(&format!("Content-Length: {}\r\n", body.len() + 1));
        let error = http_exchange(vec![header, body]).await.unwrap_err();
        assert!(error.to_string().contains("Incomplete DoH HTTP body"), "{error}");
    }

    #[tokio::test]
    async fn dns_doh_rejects_invalid_and_oversized_content_length() {
        for length in [usize::MAX.to_string(), format!("{}0", usize::MAX),
            "65536".into(), "-1".into(), "+45".into(), "bad".into(), String::new()]
        {
            let header = http_header(&format!("Content-Length: {length}\r\n"));
            let error = http_exchange(vec![header, dns_answer()]).await.unwrap_err();
            assert!(error.to_string().contains("DoH HTTP Content-Length"), "{length}: {error}");
        }
    }

    #[tokio::test]
    async fn dns_doh_rejects_ambiguous_http_framing() {
        for framing in [
            "Content-Length: 45\r\nContent-Length: 46\r\n",
            "Content-Length: 45\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
        ] {
            assert!(http_exchange(vec![http_header(framing), dns_answer()]).await.is_err());
        }
    }

    #[tokio::test]
    async fn dns_doh_preserves_fragmented_content_length_and_close_delimited() {
        for framing in [format!("Content-Length: {}\r\n", dns_answer().len()), String::new()] {
            let body = dns_answer();
            let (ips, ttl) = http_exchange(vec![http_header(&framing), body[..17].to_vec(), body[17..].to_vec()]).await.unwrap();
            assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
            assert_eq!(ttl, 19);
        }
    }

    #[tokio::test]
    async fn dns_doh_preserves_fragmented_chunked_with_trailers() {
        for trailers in [b"\r\n".as_slice(), b"X-Trace: loopback\r\nX-End: yes\r\n\r\n".as_slice()] {
            let body = dns_answer();
            let mut wire = http_header("Transfer-Encoding: Chunked\r\n");
            for part in body.chunks(13) {
                wire.extend_from_slice(format!("{:x};dns=test\r\n", part.len()).as_bytes());
                wire.extend_from_slice(part);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n");
            wire.extend_from_slice(trailers);
            // Split size lines, data, CRLFs, and trailers across writes.
            let parts = wire.chunks(3).map(<[u8]>::to_vec).collect();
            let (ips, ttl) = http_exchange(parts).await.unwrap();
            assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
            assert_eq!(ttl, 19);
        }
    }

    #[tokio::test]
    async fn dns_doh_rejects_overflowing_chunk_lengths() {
        for size in [format!("{:x}", usize::MAX), format!("{:x}0", usize::MAX), "10000".into()] {
            let error = http_exchange(vec![http_header("Transfer-Encoding: chunked\r\n"),
                format!("{size}\r\n").into_bytes(), dns_answer()]).await.unwrap_err();
            assert!(error.to_string().contains("DoH chunk"), "{size}: {error}");
        }
    }

    #[tokio::test]
    async fn dns_doh_rejects_incomplete_and_malformed_chunked() {
        let body = dns_answer();
        for suffix in [b"".as_slice(), b"\r\n", b"\r\n0\r\n", b"\r\n0\r\nX-End: yes\r\n", b"xx0\r\n\r\n"] {
            let mut chunk = format!("{:x}\r\n", body.len()).into_bytes();
            chunk.extend_from_slice(&body);
            chunk.extend_from_slice(suffix);
            assert!(http_exchange(vec![http_header("Transfer-Encoding: chunked\r\n"), chunk]).await.is_err());
        }
        for ending in [b"2".as_slice(), b"2d\r\nshort", b"0\r\nbad trailer\r\n\r\n"] {
            assert!(http_exchange(vec![http_header("Transfer-Encoding: chunked\r\n"), ending.to_vec()]).await.is_err());
        }
    }

    #[tokio::test]
    async fn dns_doh_rejects_oversized_wire_response_and_headers() {
        let mut body = dns_answer();
        body.resize(65537, 0);
        let error = http_exchange(vec![http_header(""), body]).await.unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        let mut header = b"HTTP/1.1 200 OK\r\nX-Padding: ".to_vec();
        header.resize(65537, b'x');
        let error = http_exchange(vec![header]).await.unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[tokio::test]
    async fn dns_doh_rejects_loopback_untrusted_tls_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let server = TlsServer::from_der_with_alpn(
            vec![cert.cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            vec![b"h2".to_vec()],
        ).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (stream, _) = listener.accept().await.unwrap();
                server.accept(Box::pin(stream)).await.is_err()
            }).await.expect("loopback TLS server stalled")
        });
        let ns = DohNameServer::with_timeout(format!("https://{addr}/dns-query"), Duration::from_secs(3));
        let error = ns.query_ip_with_opt("example.com", true, false).await.unwrap_err();
        assert!(error.to_string().contains("TLS handshake failed"), "{error}");
        assert!(task.await.unwrap(), "client accepted an untrusted certificate");
    }

    #[test]
    fn test_doh_nameserver_creation() {
        let doh = DohNameServer::new("https://1.1.1.1/dns-query");
        assert_eq!(doh.url(), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_edns0_client_subnet_encoding() {
        use super::super::nameserver::{build_dns_query_typed, build_dns_query_with_ecs};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let plain = build_dns_query_typed("example.com", 1);
        assert_eq!(&plain[10..12], &[0x00, 0x00]);

        let v4 = build_dns_query_with_ecs(
            "example.com",
            1,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );
        assert_eq!(&v4[10..12], &[0x00, 0x01]);
        assert_eq!(v4.len(), plain.len() + 22);
        assert_eq!(&v4[v4.len() - 3..], &[1, 2, 3]);

        let v6 = build_dns_query_with_ecs(
            "example.com",
            28,
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x1234, 0x5600, 0, 0, 0, 1,
            ))),
        );
        assert_eq!(&v6[10..12], &[0x00, 0x01]);
        assert_eq!(v6.len(), plain.len() + 31);
        assert_eq!(&v6[v6.len() - 12..], &[0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0]);
    }
}
