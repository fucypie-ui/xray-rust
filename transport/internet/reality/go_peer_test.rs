//! Explicit Linux-only live peer gate. Never starts Go in production paths.
//! Build the pinned oracle with testing/reality-reference/build-peer.sh, then:
//! XRAY_GO_REALITY_PEER_BIN=/absolute/path/go-reality-peer cargo test --lib \
//!   transport::internet::reality::go_peer_test -- --ignored --nocapture
use super::{RealityClient, RealityConfig, RealityServer};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use x25519_dalek::{PublicKey, StaticSecret};

fn peer() -> Command {
    let executable = std::env::var_os("XRAY_GO_REALITY_PEER_BIN")
        .expect("live Go gate requires XRAY_GO_REALITY_PEER_BIN; build the exact pinned reference on Linux");
    let mut command = Command::new(executable);
    command.kill_on_drop(true).stderr(Stdio::inherit());
    command
}

async fn start(args: &[&str]) -> (Child, String) {
    let mut child = peer().args(args).stdout(Stdio::piped()).spawn().expect("start pinned Go peer");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = lines.next_line().await.unwrap().expect("Go listener must report readiness");
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    (child, value["address"].as_str().unwrap().to_owned())
}

async fn echo(mut stream: crate::common::net::BoxStream) {
    let mut bytes = [0; 19];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"authenticated-vless");
    stream.write_all(b"reality-auth-ok").await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the independently built, pinned Linux Go reference binary"]
async fn rust_client_authenticates_pinned_go_server_classical_and_hybrid_targets() {
    for hybrid in [false, true] {
        tokio::time::timeout(Duration::from_secs(35), async {
            // Pinned Go Server requires six target probes for one SNI, plus
            // the actual REALITY connection. Serve all seven concurrently.
            let mut cover_args = vec!["cover", "--connections", "7"];
            if hybrid { cover_args.push("--hybrid"); }
            let (mut cover, dest) = start(&cover_args).await;
            let (mut server, address) = start(&["server", "--dest", &dest, "--fragment"]).await;
            let public = PublicKey::from(&StaticSecret::from([7; 32]));
            let client = RealityClient::new("www.example.com", &hex::encode(public.as_bytes()), "01020304").unwrap();
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut stream = client.connect(Box::pin(socket)).await.expect("Rust client must authenticate real Go server");
            stream.write_all(b"authenticated-vless").await.unwrap(); stream.flush().await.unwrap();
            let mut response = [0; 15]; stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"reality-auth-ok");
            drop(stream);
            assert!(server.wait().await.unwrap().success());
            assert!(cover.wait().await.unwrap().success());
        }).await.expect("live Go server handshake timed out");
    }
}

#[tokio::test]
#[ignore = "requires the independently built, pinned Linux Go reference binary"]
async fn pinned_go_client_authenticates_rust_server_classical_and_hybrid_targets() {
    for hybrid in [false, true] {
        tokio::time::timeout(Duration::from_secs(35), async {
            let cover_args = if hybrid { vec!["cover", "--hybrid"] } else { vec!["cover"] };
            let (mut cover, dest) = start(&cover_args).await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let server = RealityServer::new(&RealityConfig {
                private_key: Some(hex::encode([7; 32])), short_ids: vec!["01020304".into()],
                server_names: vec!["www.example.com".into()], dest: Some(dest), max_time_diff: Some(60_000),
                ..Default::default()
            }).unwrap();
            let task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let stream = server.accept(Box::pin(socket)).await.unwrap().expect("real Go client must authenticate Rust server");
                echo(stream).await;
            });
            let output = peer().args(["client", "--address", &address, "--fragment"]).stderr(Stdio::piped()).output().await.unwrap();
            assert!(output.status.success(), "Go client rejected REALITY (hybrid={hybrid}, status={}): stdout={} stderr={}",
                output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            assert!(String::from_utf8_lossy(&output.stdout).contains("authenticated"));
            task.await.unwrap();
            assert!(cover.wait().await.unwrap().success());
        }).await.expect("live Go client handshake timed out");
    }
}

#[tokio::test]
#[ignore = "requires the independently built, pinned Linux Go reference binary"]
async fn pinned_go_client_with_wrong_short_id_is_forwarded_and_never_authenticated() {
    tokio::time::timeout(Duration::from_secs(35), async {
        let (mut cover, dest) = start(&["cover"]).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = RealityServer::new(&RealityConfig {
            private_key: Some(hex::encode([7; 32])), short_ids: vec!["01020304".into()],
            server_names: vec!["www.example.com".into()], dest: Some(dest), ..Default::default()
        }).unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(server.accept(Box::pin(socket)).await.unwrap().is_none());
        });
        let status = peer().args(["client", "--address", &address, "--short-id", "ffffffff"]).status().await.unwrap();
        assert!(!status.success(), "Go client must refuse the target's unrelated certificate");
        task.await.unwrap();
        assert!(cover.wait().await.unwrap().success());
    }).await.expect("live negative Go gate timed out");
}
