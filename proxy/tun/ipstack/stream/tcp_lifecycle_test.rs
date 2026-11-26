use super::*;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(3);

fn tcp_stream() -> (IpStackTcpStream, PacketReceiver, oneshot::Receiver<()>) {
    let (up_tx, up_rx) = mpsc::unbounded_channel();
    let (destroy_tx, destroy_rx) = oneshot::channel();
    let tcp = TcpHeader {
        syn: true,
        sequence_number: 100,
        window_size: 4096,
        ..Default::default()
    };
    let config = Arc::new(TcpConfig {
        last_ack_timeout: Duration::from_secs(3600),
        close_wait_timeout: Duration::from_secs(3600),
        two_msl: Duration::from_secs(3600),
        ..Default::default()
    });
    let stream = IpStackTcpStream::new(
        "192.0.2.1:12345".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
        tcp,
        up_tx,
        1500,
        Some(destroy_tx),
        config,
    ).unwrap();
    (stream, up_rx, destroy_rx)
}

#[tokio::test]
async fn dropping_tcp_stream_before_first_poll_aborts_background_task() {
    let (stream, mut upstream, destroyed) = tcp_stream();
    drop(stream);
    // The task was never polled, so cancellation drops rather than sends its
    // destroy notification; both must wake the owning session-removal waiter.
    assert!(timeout(DEADLINE, destroyed).await.unwrap().is_err());
    assert!(timeout(DEADLINE, upstream.recv()).await.unwrap().is_none());
}

#[tokio::test]
async fn dropping_tcp_stream_aborts_main_task_on_current_thread_runtime() {
    let (stream, mut upstream, destroyed) = tcp_stream();
    let syn_ack = timeout(DEADLINE, upstream.recv()).await.unwrap().unwrap();
    assert!(matches!(syn_ack.transport, TransportHeader::Tcp(ref tcp) if tcp.syn && tcp.ack));
    drop(stream);
    let _ = timeout(DEADLINE, destroyed).await.unwrap();
    assert!(timeout(DEADLINE, upstream.recv()).await.unwrap().is_none());
}

async fn assert_close_timer_stops(state: TcpState, inflight: bool) {
    let (stream, mut upstream, destroyed) = tcp_stream();
    timeout(DEADLINE, upstream.recv()).await.unwrap().unwrap();
    let (seq, ack) = {
        let mut tcb = stream.tcb.lock().unwrap();
        tcb.change_state(state);
        let ack = tcb.get_seq().0;
        if inflight { tcb.add_inflight_packet(vec![1]).unwrap(); }
        (tcb.get_ack().0, ack)
    };
    stream.stream_sender.send(NetworkPacket {
        ip: IpHeader::Ipv4(Ipv4Header::new(20, 64, IpNumber::TCP, [192, 0, 2, 1], [198, 51, 100, 1]).unwrap()),
        transport: TransportHeader::Tcp(TcpHeader {
            sequence_number: seq,
            acknowledgment_number: ack,
            window_size: 4096,
            ack: true,
            fin: true,
            ..Default::default()
        }),
        payload: None,
    }).unwrap();
    // The response is queued in the same synchronous packet handler which
    // spawns the long-lived timer, before the main task yields.
    timeout(DEADLINE, upstream.recv()).await.unwrap().unwrap();
    let weak_tcb = Arc::downgrade(&stream.tcb);
    drop(stream);
    let _ = timeout(DEADLINE, destroyed).await.unwrap();
    while timeout(DEADLINE, upstream.recv()).await.unwrap().is_some() {}
    timeout(DEADLINE, async {
        while weak_tcb.upgrade().is_some() { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert!(weak_tcb.upgrade().is_none(), "close timer retained TCP state");
}

#[tokio::test]
async fn dropping_tcp_stream_aborts_last_ack_timer() {
    assert_close_timer_stops(TcpState::Established, false).await;
}

#[tokio::test]
async fn dropping_tcp_stream_aborts_close_wait_timer() {
    assert_close_timer_stops(TcpState::Established, true).await;
}

#[tokio::test]
async fn dropping_tcp_stream_aborts_time_wait_timer() {
    assert_close_timer_stops(TcpState::FinWait1, false).await;
}
