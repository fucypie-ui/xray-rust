//! Native packet adapters. No packet boundary is inferred from stream reads.
use async_trait::async_trait;
use bytes::Bytes;
use std::{collections::HashMap, future::poll_fn, net::SocketAddr, sync::Mutex, task::Poll, time::{Duration, Instant}};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use crate::common::{errors::{Error, Result}, net::{Destination, Network, datagram::{Datagram, DatagramTransport}}};
use super::{device::WireGuardDevice, stack::WireGuardUdpSocket};

const MAX_FLOWS: usize = 64;
const IDLE: Duration = Duration::from_secs(120);

pub(super) fn udp_destination(address: SocketAddr) -> Destination {
    let mut destination = Destination::from(address); destination.network = Network::Udp; destination
}

struct Flow { socket: WireGuardUdpSocket, reply_to: Destination, active: Instant }

pub(super) struct WireGuardDatagrams {
    device: WireGuardDevice,
    flows: Mutex<HashMap<(SocketAddr, Option<Destination>), Flow>>,
    changed: Notify,
    closed: CancellationToken,
}
impl WireGuardDatagrams {
    pub fn new(device: WireGuardDevice) -> Self {
        let closed = device.child_cancellation();
        Self { device, flows: Mutex::new(HashMap::new()), changed: Notify::new(), closed }
    }
    fn expire(&self) {
        self.flows.lock().unwrap_or_else(|error| error.into_inner()).retain(|_, flow| flow.active.elapsed() < IDLE);
    }
}
#[async_trait]
impl DatagramTransport for WireGuardDatagrams {
    async fn send(&self, packet: Datagram) -> Result<()> {
        if packet.payload.len() > 65507 { return Err(Error::BufferOverflow); }
        if self.closed.is_cancelled() { return Err(Error::Closed); }
        if packet.destination.network != Network::Udp { return Err(Error::Config("WireGuard datagram destination must be UDP".into())); }
        let destination = super::client::resolve_destination(&self.device, &packet.destination).await?;
        let key = (destination, packet.source.clone());
        // Do not hold the flow map over an await. A short-lived Arc is unnecessary:
        // packet enqueue itself is nonblocking and waits on the socket's waker.
        let send = poll_fn(|cx| {
            if self.closed.is_cancelled() { return Poll::Ready(Err(Error::Closed)); }
            let mut flows = self.flows.lock().unwrap_or_else(|error| error.into_inner());
            flows.retain(|_, flow| flow.active.elapsed() < IDLE);
            if !flows.contains_key(&key) {
                if flows.len() >= MAX_FLOWS { return Poll::Ready(Err(Error::BufferOverflow)); }
                let socket = self.device.connect_udp(destination)?;
                let reply_to = packet.source.clone().unwrap_or(udp_destination(socket.local_addr()?));
                flows.insert(key.clone(), Flow { socket, reply_to, active: Instant::now() });
                self.changed.notify_one();
            }
            let flow = flows.get_mut(&key).expect("flow inserted under map lock");
            flow.active = Instant::now();
            match flow.socket.poll_send(cx, &packet.payload) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())), Poll::Pending => Poll::Pending,
            }
        });
        tokio::select! { biased; _ = self.closed.cancelled() => Err(Error::Closed), result = send => result }
    }
    async fn recv(&self) -> Result<Option<Datagram>> {
        let mut buffer = vec![0; 65535];
        loop {
            if self.closed.is_cancelled() { return Ok(None); }
            tokio::select! {
                biased;
                _ = self.closed.cancelled() => return Ok(None),
                _ = self.changed.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(30)) => self.expire(),
                packet = poll_fn(|cx| {
                    let mut flows = self.flows.lock().unwrap_or_else(|error| error.into_inner());
                    for ((remote, _), flow) in flows.iter_mut() {
                        match flow.socket.poll_recv(cx, &mut buffer) {
                            Poll::Ready(Ok(length)) => {
                                flow.active = Instant::now();
                                return Poll::Ready(Ok(Some(Datagram { payload: Bytes::copy_from_slice(&buffer[..length]),
                                    source: Some(udp_destination(*remote)), destination: flow.reply_to.clone() })));
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())), Poll::Pending => {},
                        }
                    }
                    Poll::Pending
                }) => return packet,
            }
        }
    }
    async fn close(&self) -> Result<()> {
        self.closed.cancel(); self.flows.lock().unwrap_or_else(|error| error.into_inner()).clear();
        self.changed.notify_waiters(); Ok(())
    }
}
