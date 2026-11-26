use super::*;
use etherparse::{Ipv4Header, UdpHeader};
use packet::IpHeader;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf, duplex};
use tokio::sync::oneshot;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(3);

struct FallibleDevice {
    inner: DuplexStream,
    fail_read: oneshot::Receiver<()>,
}

impl AsyncRead for FallibleDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(Ok(())) = Pin::new(&mut self.fail_read).poll(cx) {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "injected device read failure")));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FallibleDevice {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn udp_packet() -> Vec<u8> {
    NetworkPacket {
        ip: IpHeader::Ipv4(Ipv4Header::new(8, 64, IpNumber::UDP, [192, 0, 2, 1], [198, 51, 100, 1]).unwrap()),
        transport: TransportHeader::Udp(UdpHeader {
            source_port: 12345,
            destination_port: 53,
            length: 8,
            checksum: 0,
        }),
        payload: None,
    }.to_bytes().unwrap()
}

#[tokio::test]
async fn dropping_ipstack_releases_device_with_a_live_accepted_stream() {
    let (device, mut peer) = duplex(4096);
    let mut stack = IpStack::new(IpStackConfig::default(), device);
    peer.write_all(&udp_packet()).await.unwrap();
    let stream = timeout(DEADLINE, stack.accept()).await.unwrap().unwrap();
    assert!(matches!(stream, IpStackStream::Udp(_)));
    drop(stack);
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
    // An independently retained stream must not keep the device task alive.
    drop(stream);
}

#[tokio::test]
async fn dropping_ipstack_before_device_task_is_polled_releases_device() {
    let (device, mut peer) = duplex(64);
    let stack = IpStack::new(IpStackConfig::default(), device);
    drop(stack);
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn session_removal_waiter_is_owned_even_while_stream_is_alive() {
    let mut sessions = SessionCollection::new();
    let mut session_tasks = JoinSet::new();
    let (remove_tx, mut remove_rx) = mpsc::unbounded_channel();
    let (up_tx, _up_rx) = mpsc::unbounded_channel();
    let (accept_tx, mut accept_rx) = mpsc::unbounded_channel();
    process_device_read(
        &udp_packet(),
        &mut sessions,
        &remove_tx,
        &up_tx,
        &IpStackConfig::default(),
        &accept_tx,
        &mut session_tasks,
    ).await.unwrap();
    let stream = accept_rx.recv().await.unwrap();
    assert_eq!(session_tasks.len(), 1);
    drop(remove_tx);
    // The waiter's sender closes when its owner exits, without stream Drop
    // being required to resolve the pending destroy notification first.
    session_tasks.shutdown().await;
    assert!(timeout(DEADLINE, remove_rx.recv()).await.unwrap().is_none());
    drop(stream);
}

async fn assert_device_read_exit(fail: bool, packet_information: bool) {
    let (device, mut peer) = duplex(4096);
    let (fail_tx, fail_read) = oneshot::channel();
    let mut config = IpStackConfig::default();
    config.packet_information(packet_information);
    let mut stack = IpStack::new(config, FallibleDevice { inner: device, fail_read });
    let mut packet = Vec::new();
    if packet_information { packet.extend_from_slice(&[0, 0, 8, 0]); }
    packet.extend(udp_packet());
    peer.write_all(&packet).await.unwrap();
    // Exercise the actual device loop with a live session-removal child.
    let stream = timeout(DEADLINE, stack.accept()).await.unwrap().unwrap();
    assert!(matches!(stream, IpStackStream::Udp(_)));
    if fail {
        fail_tx.send(()).unwrap();
    } else {
        // Half-close only the producer: keep its reader open to observe device Drop.
        peer.shutdown().await.unwrap();
    }
    let result = timeout(DEADLINE, &mut stack.handle).await.unwrap().unwrap();
    if fail {
        assert!(matches!(result, Err(IpStackError::IoError(ref error)) if error.kind() == std::io::ErrorKind::ConnectionReset));
    } else {
        result.unwrap();
    }
    // Keep IpStack and the accepted stream alive: loop termination alone must
    // close accept (without producing empty flows), drain children and drop I/O.
    assert!(matches!(timeout(DEADLINE, stack.accept()).await.unwrap(), Err(IpStackError::AcceptError)));
    assert_eq!(timeout(DEADLINE, peer.read(&mut [0])).await.unwrap().unwrap(), 0);
    drop(stream);
}

#[tokio::test]
async fn device_eof_closes_accept_and_releases_device_with_live_stream() {
    assert_device_read_exit(false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn device_eof_with_packet_information_closes_accept_without_panicking() {
    assert_device_read_exit(false, true).await;
}

#[tokio::test]
async fn device_read_error_closes_accept_and_releases_device_with_live_stream() {
    assert_device_read_exit(true, false).await;
}
