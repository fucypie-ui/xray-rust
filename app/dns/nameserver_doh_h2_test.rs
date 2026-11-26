use super::{DohNameServer, MAX_DOH_RESPONSE_LEN};
use bytes::Bytes;
use crate::common::errors::Result;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

// Exercise the real H2 body reader over loopback, below TLS authentication.
// The public HTTPS path has a separate untrusted-certificate regression.
async fn h2_exchange(body: Vec<u8>, content_length: Option<usize>) -> Result<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = tokio::spawn(async move {
                let mut request_body = request.into_body();
                while let Some(chunk) = request_body.data().await {
                    let chunk = chunk.unwrap();
                    request_body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                let mut builder = http::Response::builder().status(200)
                    .header(http::header::CONTENT_TYPE, "application/dns-message");
                if let Some(length) = content_length {
                    builder = builder.header(http::header::CONTENT_LENGTH, length.to_string());
                }
                let mut stream = respond.send_response(builder.body(()).unwrap(), false).unwrap();
                stream.send_data(Bytes::from(body), false).unwrap();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("x-end", http::HeaderValue::from_static("loopback"));
                stream.send_trailers(trailers).unwrap();
            });
            // Keep driving buffered DATA and trailers until the client closes.
            while let Some(Ok(_)) = connection.accept().await {}
            response.await.unwrap();
        }).await.expect("loopback DoH H2 server stalled");
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (sender, connection) = h2::client::handshake(tcp).await.unwrap();
    let driver = tokio::spawn(connection);
    let ns = DohNameServer::with_timeout(format!("https://{addr}/dns-query"), Duration::from_secs(3));
    let query = super::try_build_dns_query_with_ecs("example.com", 1, None).unwrap();
    let result = ns.send_h2_query(sender, "127.0.0.1", addr.port(), "/dns-query", &query).await;
    driver.abort();
    let _ = driver.await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn dns_doh_h2_accepts_exact_body_limit_and_trailers() {
    let body = vec![0x5a; MAX_DOH_RESPONSE_LEN];
    assert_eq!(h2_exchange(body.clone(), Some(body.len())).await.unwrap(), body);
}

#[tokio::test]
async fn dns_doh_h2_rejects_oversized_body_instead_of_returning_prefix() {
    let error = h2_exchange(vec![0x5a; MAX_DOH_RESPONSE_LEN + 1], None).await.unwrap_err();
    assert!(error.to_string().contains("exceeds size limit"), "{error}");
}

#[tokio::test]
async fn dns_doh_h2_rejects_short_content_length_body() {
    assert!(h2_exchange(vec![0x5a; 45], Some(46)).await.is_err());
}

#[tokio::test]
async fn dns_doh_h2_rejects_oversized_declared_length() {
    for length in [MAX_DOH_RESPONSE_LEN + 1, usize::MAX] {
        let error = h2_exchange(vec![0x5a; 45], Some(length)).await.unwrap_err();
        // H2 can reject the mismatched END_STREAM before the application sees headers.
        assert!(!error.to_string().contains("timeout"), "{error}");
    }
}
