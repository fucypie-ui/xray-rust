use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

use crate::common::errors::{Error, Result};
use crate::common::net::{BoxStream, Destination};
use crate::common::protocol::{RequestCommand, SessionContext};
use crate::features::outbound::OutboundHandler;
use crate::proxy::http::client::HttpClient;
use crate::proxy::socks::client::Client as SocksClient;
use crate::proxy::trojan::client::Client as TrojanClient;
use crate::proxy::trojan::protocol::{RequestHeader, hash_password};
use crate::transport::internet::dialer::Dialer;

struct MemoryDialer {
    server: Destination,
    stream: Mutex<Option<BoxStream>>,
}

#[async_trait]
impl Dialer for MemoryDialer {
    async fn dial(&self, destination: &Destination) -> Result<BoxStream> {
        assert_eq!(destination, &self.server);
        self.stream.lock().unwrap().take().ok_or(Error::Closed)
    }
}

fn memory_transport(server: &Destination) -> (Arc<dyn Dialer>, DuplexStream) {
    let (client, peer) = tokio::io::duplex(4096);
    let dialer = MemoryDialer {
        server: server.clone(),
        stream: Mutex::new(Some(Box::pin(client))),
    };
    (Arc::new(dialer), peer)
}

#[tokio::test]
async fn trojan_handshake_uses_configured_dialer() {
    timeout(Duration::from_secs(5), async {
        let server = Destination::from_domain_port("trojan.invalid", 443);
        let target = Destination::from_domain_port("example.com", 80);
        let (dialer, mut peer) = memory_transport(&server);
        let expected_target = target.clone();
        let peer_task = tokio::spawn(async move {
            let request = RequestHeader::decode(&mut peer).await.unwrap();
            assert_eq!(request.destination, expected_target);
            assert_eq!(request.command, RequestCommand::Tcp);
            assert_eq!(request.password_hash, hash_password("secret"));
            let mut payload = [0; 4];
            peer.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            peer.write_all(b"pong").await.unwrap();
        });
        let client = TrojanClient::new("test", server, "secret", None, None)
            .with_dialer(dialer);
        let mut stream = client.connect(&SessionContext::new("test", target)).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        peer_task.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn socks_handshake_uses_configured_dialer_with_and_without_auth() {
    timeout(Duration::from_secs(5), async {
        for authenticated in [false, true] {
            let server = Destination::from_domain_port("socks.invalid", 1080);
            let target = Destination::from_domain_port("example.com", 443);
            let (dialer, mut peer) = memory_transport(&server);
            let peer_task = tokio::spawn(async move {
                let method = if authenticated { 2 } else { 0 };
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, method]);
                peer.write_all(&[5, method]).await.unwrap();
                if authenticated {
                    let mut credentials = [0; 6];
                    peer.read_exact(&mut credentials).await.unwrap();
                    assert_eq!(&credentials, b"\x01\x01a\x02bc");
                    peer.write_all(&[1, 0]).await.unwrap();
                }
                let mut request = [0; 18];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"\x05\x01\x00\x03\x0bexample.com\x01\xbb");
                peer.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00pong").await.unwrap();
                let mut payload = [0; 4];
                peer.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
            });
            let client = if authenticated {
                SocksClient::with_auth("test", server, "a", "bc")
            } else {
                SocksClient::new("test", server)
            }.with_dialer(dialer);
            let mut stream = client.connect(&SessionContext::new("test", target)).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            peer_task.await.unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn http_handshake_uses_configured_dialer_with_and_without_auth() {
    timeout(Duration::from_secs(5), async {
        for authenticated in [false, true] {
            let server = Destination::from_domain_port("http.invalid", 8080);
            let target = Destination::from_domain_port("example.com", 443);
            let (dialer, mut peer) = memory_transport(&server);
            let peer_task = tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(peer.read_u8().await.unwrap());
                    assert!(request.len() < 2048);
                }
                let mut expected = String::from("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: Keep-Alive\r\n");
                if authenticated {
                    expected.push_str("Proxy-Authorization: Basic YTpiYw==\r\n");
                }
                expected.push_str("\r\n");
                assert_eq!(request, expected.as_bytes());
                peer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\npong").await.unwrap();
                let mut payload = [0; 4];
                peer.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
            });
            let client = if authenticated {
                HttpClient::with_auth("test", server, "a", "bc")
            } else {
                HttpClient::new("test", server)
            }.with_dialer(dialer);
            let mut stream = client.connect(&SessionContext::new("test", target)).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            peer_task.await.unwrap();
        }
    }).await.unwrap();
}
