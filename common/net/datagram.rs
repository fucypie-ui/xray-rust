//! Packet transports never infer packet boundaries from stream reads.
use crate::common::errors::{Error, Result};
use crate::common::net::Destination;
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, watch};

pub const MAX_DATAGRAM_SIZE: usize = 65_507;
pub const DEFAULT_PACKET_QUEUE: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub payload: Bytes,
    pub source: Option<Destination>,
    pub destination: Destination,
}

impl Datagram {
    pub fn new(payload: impl Into<Bytes>, destination: Destination) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        Ok(Self { payload, source: None, destination })
    }
}

/// `recv` is cancellation safe; only one receiver is required. Sending and
/// receiving must work concurrently. `None` denotes closure, never an empty UDP
/// packet. Implementations must reject oversize packets instead of truncating.
#[async_trait]
pub trait DatagramTransport: Send + Sync {
    async fn recv(&self) -> Result<Option<Datagram>>;
    async fn send(&self, packet: Datagram) -> Result<()>;
    async fn close(&self) -> Result<()> { Ok(()) }
}

pub type BoxDatagram = Arc<dyn DatagramTransport>;

/// Bounded, full duplex adapter, useful for native protocol engines and tests.
pub struct DatagramChannel {
    sender: mpsc::Sender<Datagram>,
    receiver: Mutex<mpsc::Receiver<Datagram>>,
    closed: watch::Sender<bool>,
}

pub fn datagram_pair(capacity: usize) -> (BoxDatagram, BoxDatagram) {
    let (a_tx, a_rx) = mpsc::channel(capacity.max(1));
    let (b_tx, b_rx) = mpsc::channel(capacity.max(1));
    let (closed, _) = watch::channel(false);
    (Arc::new(DatagramChannel { sender: a_tx, receiver: Mutex::new(b_rx), closed: closed.clone() }),
     Arc::new(DatagramChannel { sender: b_tx, receiver: Mutex::new(a_rx), closed }))
}

#[async_trait]
impl DatagramTransport for DatagramChannel {
    async fn recv(&self) -> Result<Option<Datagram>> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Ok(None); }
        let mut receiver = self.receiver.lock().await;
        tokio::select! {
            biased;
            _ = closed.changed() => Ok(None),
            packet = receiver.recv() => Ok(packet),
        }
    }
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.payload.len() > MAX_DATAGRAM_SIZE { return Err(Error::BufferOverflow); }
        let mut closed = self.closed.subscribe();
        if *closed.borrow() { return Err(Error::Closed); }
        tokio::select! {
            biased;
            _ = closed.changed() => Err(Error::Closed),
            result = self.sender.send(packet) => result.map_err(|_| Error::Closed),
        }
    }
    async fn close(&self) -> Result<()> {
        self.closed.send_replace(true);
        Ok(())
    }
}

/// Relays whole packets in both directions. Cancelling this future drops both
/// receive futures; explicit completion also closes each protocol association.
pub async fn relay_datagrams(left: BoxDatagram, right: BoxDatagram) -> Result<()> {
    async fn copy(from: &BoxDatagram, to: &BoxDatagram) -> Result<()> {
        while let Some(packet) = from.recv().await? { to.send(packet).await?; }
        Ok(())
    }
    let result = tokio::select! {
        result = copy(&left, &right) => result,
        result = copy(&right, &left) => result,
    };
    let (a, b) = tokio::join!(left.close(), right.close());
    result.and(a).and(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn packet(value: u8) -> Datagram {
        Datagram::new(Bytes::from(vec![value]), Destination::udp("127.0.0.1".parse().unwrap(), 53)).unwrap()
    }
    #[tokio::test]
    async fn bounded_queue_applies_backpressure_and_close_wakes_blocked_sender() {
        let (left, right) = datagram_pair(1);
        left.send(packet(1)).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), left.send(packet(2))).await.is_err());
        assert_eq!(right.recv().await.unwrap().unwrap(), packet(1));
        left.send(packet(2)).await.unwrap();
        let sender = left.clone();
        let blocked = tokio::spawn(async move { sender.send(packet(3)).await });
        right.close().await.unwrap();
        assert!(matches!(tokio::time::timeout(Duration::from_secs(2), blocked).await.unwrap().unwrap(), Err(Error::Closed)));
        assert!(left.recv().await.unwrap().is_none());
    }
    #[tokio::test]
    async fn empty_packet_is_distinct_from_eof_and_receive_cancellation_keeps_next_packet() {
        let (left, right) = datagram_pair(1);
        assert!(tokio::time::timeout(Duration::from_millis(10), right.recv()).await.is_err());
        let mut empty = packet(1); empty.payload = Bytes::new();
        left.send(empty.clone()).await.unwrap();
        assert_eq!(right.recv().await.unwrap().unwrap(), empty);
        left.close().await.unwrap();
        assert!(right.recv().await.unwrap().is_none());
    }
}
