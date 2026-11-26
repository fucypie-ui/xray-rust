//! Opt-in live interoperability tests. The byte-oracle tests are unconditional.
use super::{HysteriaClient, HysteriaIncoming, HysteriaServer, hysteria_test::{client_config, server_config, tls_configs}};
use crate::{common::{net::Destination, protocol::SessionContext}, features::outbound::OutboundHandler};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn peer() -> std::path::PathBuf {
    std::env::var_os("XRAY_HYSTERIA_GO_PEER").expect("build the pinned peer with testing/hysteria-reference/build-peer.sh and set XRAY_HYSTERIA_GO_PEER").into()
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future).await.expect("Go Hysteria interoperability timed out")
}
#[tokio::test]
#[ignore = "requires pinned Go peer binary; run on Ubuntu with XRAY_HYSTERIA_GO_PEER"]
async fn hysteria_go_peer_client_omitted_datagram_parameter() {
    bounded(async {
        let (tls, _, der) = tls_configs();
        let mut listener = HysteriaServer::new("go-peer", server_config()).bind("127.0.0.1:0".parse().unwrap(), tls).unwrap();
        let address = listener.local_addr().unwrap();
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut work = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    incoming = listener.accept() => {
                        work.spawn(async move {
                            match incoming.unwrap() {
                                HysteriaIncoming::Tcp(request) => {
                                    let incoming = request.accept().await.unwrap();
                                    let (mut read, mut write) = tokio::io::split(incoming.stream);
                                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                                }
                                HysteriaIncoming::Udp { session, .. } => {
                                    while let Ok(packet) = session.recv().await { session.send(&packet.address, &packet.data).await.unwrap(); }
                                }
                            }
                        });
                    }
                    result = work.join_next(), if !work.is_empty() => { result.unwrap().unwrap(); }
                }
            }
        });
        let output = tokio::process::Command::new(peer()).arg("--mode=client").arg(format!("--address={address}"))
            .arg(format!("--root-der={}", hex::encode(der))).arg("--omit-datagram=true")
            .kill_on_drop(true).output().await.unwrap();
        let _ = done_tx.send(()); server.await.unwrap();
        assert!(output.status.success(), "Go client failed: {}", String::from_utf8_lossy(&output.stderr));
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true); assert_eq!(result["omitted_datagram_parameter"], true);
    }).await;
}
#[tokio::test]
#[ignore = "requires pinned Go peer binary; run on Ubuntu with XRAY_HYSTERIA_GO_PEER"]
async fn hysteria_go_peer_server_tcp_udp_and_rejection() {
    bounded(async {
        let mut child = tokio::process::Command::new(peer()).arg("--mode=server").arg("--address=127.0.0.1:0")
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready: serde_json::Value = serde_json::from_str(&stdout.next_line().await.unwrap().expect("Go peer readiness")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(hex::decode(ready["certificate_der"].as_str().unwrap()).unwrap())).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(roots).with_no_client_auth();
        let client = HysteriaClient::with_tls("rust-peer", ready["address"].as_str().unwrap().parse::<Destination>().unwrap(), client_config(), Arc::new(tls));
        let mut stream = client.connect(&SessionContext::new("test", "example.com:443".parse().unwrap())).await.unwrap();
        stream.write_all(b"Rust-to-Go-QUIC").await.unwrap();
        let mut response = [0; 15]; stream.read_exact(&mut response).await.unwrap(); assert_eq!(&response, b"Rust-to-Go-QUIC");
        let error = client.connect(&SessionContext::new("test", "reject.example:443".parse().unwrap())).await.err().unwrap();
        assert!(error.to_string().contains("Go peer rejected destination"));
        let session = client.open_udp().await.unwrap(); let data = vec![0x31; 6000];
        session.send("dns.example:53", &data).await.unwrap();
        let response = session.recv().await.unwrap(); assert_eq!(response.address, "dns.example:53"); assert_eq!(response.data, data);
        child.kill().await.unwrap();
    }).await;
}
