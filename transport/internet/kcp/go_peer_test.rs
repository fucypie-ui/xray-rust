//! Selected Linux CI gate; missing XRAY_KCP_GO_PEER is a hard failure.
//! Build testing/kcp-reference/build-peer.sh against the pinned Go checkout.
//! cargo test --locked --lib transport::internet::kcp::go_peer_test -- --ignored
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio_util::sync::CancellationToken;

use super::{KcpConfig, KcpDialer, KcpListener};

const REFERENCE: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const REQUEST_SIZE: usize = 65_539;
const RESPONSE_SIZE: usize = 49_159;
const SESSION_LIMIT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct Event {
    event: String,
    source: String,
    address: SocketAddr,
    mtu: u32,
}

struct Peer {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

impl Peer {
    fn spawn(mode: &str, address: SocketAddr, mtu: u32) -> Self {
        let executable = std::env::var_os("XRAY_KCP_GO_PEER").expect(
            "selected live mKCP tests require XRAY_KCP_GO_PEER; build the pinned helper on Linux",
        );
        let mut child = Command::new(executable)
            .args(["--mode", mode, "--address", &address.to_string(), "--mtu", &mtu.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start pinned Go mKCP peer");
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self { child, lines }
    }

    async fn event(&mut self, expected: &str, mtu: u32) -> SocketAddr {
        let line = self.lines.next_line().await.unwrap().expect("Go peer exited before expected event");
        let event: Event = serde_json::from_str(&line).expect("Go peer event JSON");
        assert_eq!(event.event, expected);
        assert_eq!(event.source, REFERENCE);
        assert_eq!(event.mtu, mtu);
        assert_ne!(event.address.port(), 0);
        event.address
    }

    async fn finish(mut self) {
        self.child.stdin.take().unwrap().write_all(b"exit\n").await.unwrap();
        assert!(self.child.wait().await.unwrap().success(), "Go mKCP peer failed");
        assert!(self.lines.next_line().await.unwrap().is_none(), "unexpected Go peer output");
    }
}

fn config(mtu: u32) -> KcpConfig {
    KcpConfig { mtu, ..KcpConfig::default() }
}

fn payload(size: usize, salt: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 73 + i / 251 + salt) as u8).collect()
}

async fn write_payload<W: AsyncWrite + Unpin>(writer: &mut W, size: usize, salt: usize) {
    let data = payload(size, salt);
    let mut offset = 0;
    for chunk in [1, 17, 4093, 137, 8191].into_iter().cycle() {
        let end = (offset + chunk).min(data.len());
        writer.write_all(&data[offset..end]).await.unwrap();
        offset = end;
        if offset == data.len() { break; }
    }
    writer.flush().await.unwrap();
}

async fn read_payload<R: AsyncRead + Unpin>(reader: &mut R, size: usize, salt: usize) {
    let expected = payload(size, salt);
    let mut buffer = [0; 997];
    let mut offset = 0;
    while offset < size {
        let count = buffer.len().min(size - offset);
        reader.read_exact(&mut buffer[..count]).await.unwrap();
        assert_eq!(&buffer[..count], &expected[offset..offset + count], "binary payload at {offset}");
        offset += count;
    }
}

#[tokio::test]
#[ignore = "requires XRAY_KCP_GO_PEER built from the pinned production Go module on Linux"]
async fn rust_client_to_pinned_go_listener_binary_fragmentation_shutdown_and_eof() {
    for mtu in [1350, 200] {
        tokio::time::timeout(SESSION_LIMIT, async {
            let mut peer = Peer::spawn("server", "127.0.0.1:0".parse().unwrap(), mtu);
            let address = peer.event("ready", mtu).await;
            assert!(address.ip().is_loopback());
            // Default constructor codec: raw production packets, no test mask.
            let connection = KcpDialer::dial_with_config(
                address, 0x4b43, config(mtu), CancellationToken::new(),
            ).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(connection.clone().into_stream());
            write_payload(&mut writer, REQUEST_SIZE, 0x31).await;
            read_payload(&mut reader, RESPONSE_SIZE, 0xa7).await;
            assert!(connection.stats().receiving_next as usize >= RESPONSE_SIZE.div_ceil((mtu - 18) as usize));
            // Exercise AsyncWrite's half-close entry point. Go mKCP only has
            // full Close: local reads end and subsequent writes must fail.
            writer.shutdown().await.unwrap();
            assert_eq!(reader.read(&mut [0; 1]).await.unwrap(), 0);
            assert_eq!(writer.write(&[0xff]).await.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
            peer.event("complete", mtu).await; // Go verified exact bytes and EOF.
            connection.wait_closed().await;
            assert!(connection.is_terminated());
            peer.finish().await;
        }).await.unwrap_or_else(|_| panic!("Rust client -> pinned Go listener timed out (MTU {mtu})"));
    }
}

#[tokio::test]
#[ignore = "requires XRAY_KCP_GO_PEER built from the pinned production Go module on Linux"]
async fn pinned_go_client_to_rust_listener_binary_fragmentation_close_and_eof() {
    for mtu in [1350, 200] {
        tokio::time::timeout(SESSION_LIMIT, async {
            let listener = KcpListener::bind_with_config(
                "127.0.0.1:0".parse().unwrap(), config(mtu), CancellationToken::new(),
            ).await.unwrap();
            let mut peer = Peer::spawn("client", listener.local_addr().unwrap(), mtu);
            peer.event("ready", mtu).await;
            let (connection, address) = listener.accept().await.unwrap();
            assert!(address.ip().is_loopback());
            let (mut reader, mut writer) = tokio::io::split(connection.clone().into_stream());
            read_payload(&mut reader, REQUEST_SIZE, 0x31).await;
            assert!(connection.stats().receiving_next as usize >= REQUEST_SIZE.div_ceil((mtu - 18) as usize));
            write_payload(&mut writer, RESPONSE_SIZE, 0xa7).await;
            // Go initiates Close after validating the independent response.
            assert_eq!(reader.read(&mut [0; 1]).await.unwrap(), 0, "expected EOF without trailing bytes");
            assert_eq!(writer.write(&[0xff]).await.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
            writer.shutdown().await.unwrap();
            connection.wait_closed().await;
            assert!(connection.is_terminated());
            peer.event("complete", mtu).await;
            peer.finish().await;
            listener.close().await.unwrap();
            assert_eq!(listener.active_connections(), 0);
        }).await.unwrap_or_else(|_| panic!("Pinned Go client -> Rust listener timed out (MTU {mtu})"));
    }
}
