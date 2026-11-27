//! Mandatory when selected: no helper/environment means failure, never a skip.
use super::{GrpcConfig, GrpcDialer, GrpcListener};
use crate::common::net::{Address, Destination};
use crate::transport::internet::dialer::Dialer;
use serde::Deserialize;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

const PIN: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const AUTHORITY: &str = "gun.reference.invalid:8443";
const LIMIT: Duration = Duration::from_secs(40);
fn payload(n: usize, salt: usize) -> Vec<u8> { (0..n).map(|i| (i * 73 + i / 251 + salt) as u8).collect() }
fn binary() -> std::ffi::OsString {
    assert_eq!(std::env::consts::OS, "linux", "pinned Go gRPC tests require Linux");
    std::env::var_os("XRAY_GRPC_GO_PEER").expect("mandatory selected gRPC test: set XRAY_GRPC_GO_PEER to the pinned Linux helper; helper absence is a failure")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    event: String,
    reference: String,
    mode: String,
    address: String,
    service_name: String,
    multi_mode: bool,
    authority: String,
    scenario: String,
    bytes_sent: usize,
    bytes_received: usize,
}
struct Peer {
    child: Child,
    stdout: BufReader<ChildStdout>,
    stderr: tokio::task::JoinHandle<Vec<u8>>,
}
impl Peer {
    async fn start(mode: &str, address: SocketAddr, service: &str, multi: bool, scenario: &str) -> Self {
        let control = serde_json::json!({
            "mode": mode, "address": address.to_string(), "service_name": service,
            "multi_mode": multi, "authority": AUTHORITY, "scenario": scenario,
        });
        let mut child = Command::new(binary()).kill_on_drop(true)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().expect("start pinned gRPC helper");
        let mut stderr = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).await.unwrap(); bytes
        });
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(format!("{control}\n").as_bytes()).await.unwrap();
        stdin.shutdown().await.unwrap(); drop(stdin);
        Self { child, stdout, stderr }
    }
    async fn event(&mut self, kind: &str, mode: &str, service: &str, multi: bool, scenario: &str) -> Event {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).await.unwrap();
        assert!(n != 0 && n <= 16 * 1024 && line.ends_with('\n'), "missing/invalid helper JSON event: {line:?}");
        let event: Event = serde_json::from_str(&line).expect("stdout must contain only strict JSON events");
        assert_eq!(event.event, kind); assert_eq!(event.reference, PIN);
        assert_eq!(event.mode, mode); assert_eq!(event.service_name, service);
        assert_eq!(event.multi_mode, multi); assert_eq!(event.authority, AUTHORITY);
        assert_eq!(event.scenario, scenario);
        let address: SocketAddr = event.address.parse().expect("helper endpoint");
        assert!(address.ip().is_loopback() && address.is_ipv4() && address.port() != 0);
        event
    }
    async fn finish(mut self) {
        let mut extra = String::new(); self.stdout.read_to_string(&mut extra).await.unwrap();
        let status = self.child.wait().await.unwrap();
        let stderr = self.stderr.await.unwrap();
        assert!(extra.is_empty(), "unexpected stdout after done: {extra}");
        assert!(status.success(), "Go helper {status}: {}", String::from_utf8_lossy(&stderr));
    }
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_GRPC_GO_PEER built on Linux"]
async fn grpc_go_reference_rust_client_go_server() {
    // Resolve first so a missing helper can never turn into a skipped matrix.
    let _ = binary();
    for service in ["GunService", "", "/hello /world!/read|write"] {
        for multi in [false, true] {
            for scenario in ["roundtrip", "denied"] {
                tokio::time::timeout(LIMIT, async {
                    let mut peer = Peer::start("server", "127.0.0.1:0".parse().unwrap(), service, multi, scenario).await;
                    let ready = peer.event("ready", "server", service, multi, scenario).await;
                    assert_eq!(ready.bytes_sent, 0); assert_eq!(ready.bytes_received, 0);
                    let addr: SocketAddr = ready.address.parse().unwrap();
                    let config = GrpcConfig { multi_mode: multi, authority: AUTHORITY.into(), user_agent: "p0u27-rust".into(), ..GrpcConfig::new(service) };
                    let mut stream = GrpcDialer::new(config).dial(&Destination::tcp(Address::from(addr.ip()), addr.port())).await.unwrap();
                    stream.write_all(&payload(196_613, 19)).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    let result = stream.read_to_end(&mut reply).await;
                    if scenario == "denied" {
                        let error = result.unwrap_err().to_string();
                        assert!(error.contains("gRPC status 7") && error.contains("denied: 100% café"), "{error}");
                        assert!(reply.is_empty());
                    } else { result.unwrap(); assert_eq!(reply, payload(131_079, 167)); }
                    drop(stream);
                    let done = peer.event("done", "server", service, multi, scenario).await;
                    assert_eq!(done.address, ready.address);
                    assert_eq!(done.bytes_sent, if scenario == "denied" { 0 } else { 131_079 });
                    assert_eq!(done.bytes_received, 196_613);
                    peer.finish().await;
                }).await.expect("pinned Go server case timed out");
            }
        }
    }
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_GRPC_GO_PEER built on Linux"]
async fn grpc_go_reference_go_client_rust_server() {
    let _ = binary();
    for service in ["GunService", "", "/hello /world!/read|write"] {
        for multi in [false, true] {
            tokio::time::timeout(LIMIT, async {
                let listener = GrpcListener::bind("127.0.0.1:0".parse().unwrap(), GrpcConfig::new(service)).await.unwrap();
                let address = listener.local_addr().unwrap();
                let mut peer = Peer::start("client", address, service, multi, "roundtrip").await;
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = vec![0; 196_613]; stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload(196_613, 19));
                stream.write_all(&payload(131_079, 167)).await.unwrap();
                stream.shutdown().await.unwrap();
                // grpc-go's native net.Conn has not closed its request half.
                // Handler drop after final trailers must preserve successful EOF.
                drop(stream);
                let done = peer.event("done", "client", service, multi, "roundtrip").await;
                assert_eq!(done.address, address.to_string());
                assert_eq!(done.bytes_sent, 196_613); assert_eq!(done.bytes_received, 131_079);
                peer.finish().await;
                listener.close().await.unwrap();
            }).await.expect("pinned Go client case timed out");
        }
    }
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_GRPC_GO_PEER built on Linux"]
async fn grpc_go_reference_strict_control_rejects_invalid_json() {
    let executable = binary();
    let valid = serde_json::json!({
        "mode":"server", "address":"127.0.0.1:0", "service_name":"GunService",
        "multi_mode":false, "authority":AUTHORITY, "scenario":"roundtrip",
    }).to_string();
    // Keep every unrelated field valid, so each negative case exercises the
    // named parser rule rather than accidentally failing for missing fields.
    for (control, diagnostic) in [
        (valid.replacen('{', r#"{"mode":"client","#, 1), "unknown/duplicate/invalid"),
        (valid.replacen('{', r#"{"unknown":true,"#, 1), "unknown/duplicate/invalid"),
        (format!("{valid} {{}}"), "trailing JSON"),
        (valid.replace(r#""mode":"server""#, r#""mode":null"#), "null control"),
        (valid.replace(r#""multi_mode":false"#, r#""multi_mode":"false""#), "cannot unmarshal"),
        (r#"{"mode":"server"}"#.into(), "missing JSON control field"),
        ("[]".into(), "expected JSON control object"),
        ("{".into(), "unexpected end of JSON input"),
    ] {
        tokio::time::timeout(LIMIT, async {
            let mut child = Command::new(&executable).kill_on_drop(true)
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap(); input.write_all(control.as_bytes()).await.unwrap();
            input.shutdown().await.unwrap(); drop(input);
            let output = child.wait_with_output().await.unwrap();
            assert!(!output.status.success()); assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic), "missing parser diagnostic {diagnostic:?}: {}", String::from_utf8_lossy(&output.stderr));
        }).await.unwrap();
    }
}
