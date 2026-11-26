//! Bounded, authenticated Hysteria datagram sessions. No stream emulation.
use super::conn::HysteriaConn;
use crate::{common::errors::{Error, Result}, proxy::hysteria::{Defragger, UDPMessage, frag_udp_message}};
use bytes::Bytes;
use std::{collections::HashMap, sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering}}, time::{Duration, Instant}};
use tokio::sync::mpsc;

const SESSION_LIMIT: usize = 128;
const QUEUE_LIMIT: usize = 8;
// The Go limit is a DATAGRAM frame size, including type/length overhead.
const GO_DATAGRAM_PAYLOAD: usize = 1197;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramPacket { pub address: String, pub data: Vec<u8> }
struct SessionState { closed: AtomicBool, last_activity: Mutex<Instant>, next_packet: AtomicU16, closing: tokio::sync::watch::Sender<bool> }
impl SessionState {
    fn new() -> Self { Self { closed: AtomicBool::new(false), last_activity: Mutex::new(Instant::now()), next_packet: AtomicU16::new(1), closing: tokio::sync::watch::channel(false).0 } }
    fn close(&self) { self.closed.store(true, Ordering::Release); self.closing.send_replace(true); }
    fn touch(&self) { *self.last_activity.lock().expect("UDP activity mutex") = Instant::now(); }
}
struct Entry { state: Arc<SessionState>, tx: mpsc::Sender<DatagramPacket>, defragger: Defragger }

/// A whole-datagram API. The caller must preserve packet boundaries and addresses.
pub struct UdpSession {
    id: u32,
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    state: Arc<SessionState>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<DatagramPacket>>,
    // Client sessions keep the authenticated H3 driver alive when cloned clients
    // are dropped. Server sessions are owned by the listener's connection task.
    _owner: Option<HysteriaConn>,
    write_lock: tokio::sync::Mutex<()>,
}
impl UdpSession {
    pub fn id(&self) -> u32 { self.id }
    pub fn remote_addr(&self) -> std::net::SocketAddr { self.conn.remote_address() }
    pub fn close(&self) { self.state.close(); }
    pub async fn recv(&self) -> Result<DatagramPacket> {
        if self.state.closed.load(Ordering::Acquire) { return Err(Error::Closed); }
        let mut closing = self.state.closing.subscribe();
        if *closing.borrow() { return Err(Error::Closed); }
        let mut receiver = self.receiver.lock().await;
        let packet = tokio::select! {
            biased;
            _ = closing.changed() => return Err(Error::Closed),
            packet = receiver.recv() => packet.ok_or(Error::Closed)?,
        };
        self.state.touch();
        Ok(packet)
    }
    pub async fn send(&self, address: &str, data: &[u8]) -> Result<()> {
        let _writing = self.write_lock.lock().await;
        let mut closing = self.state.closing.subscribe();
        if self.state.closed.load(Ordering::Acquire) { return Err(Error::Closed); }
        let maximum = self.conn.max_datagram_size().ok_or_else(|| Error::Unsupported("QUIC peer did not negotiate datagrams".into()))?.min(GO_DATAGRAM_PAYLOAD);
        let mut message = UDPMessage::new(self.id, 0, address.to_owned(), data.to_vec());
        // Validate before fragmentation (including empty and oversized payloads).
        message.encode()?;
        if message.size() > maximum { message.packet_id = self.state.next_packet.fetch_add(1, Ordering::Relaxed); }
        let fragments = frag_udp_message(&message, maximum);
        if fragments.is_empty() { return Err(Error::Protocol("Hysteria UDP address/packet exceeds fragment capacity".into())); }
        for fragment in fragments {
            let encoded = Bytes::from(fragment.encode()?);
            tokio::select! {
                biased;
                _ = closing.changed() => return Err(Error::Closed),
                result = self.conn.send_datagram_wait(encoded) => result.map_err(|error| Error::Protocol(format!("Hysteria datagram send: {error}")))?,
            }
        }
        self.state.touch();
        Ok(())
    }
    fn keep_alive(&mut self, owner: HysteriaConn) { self._owner = Some(owner); }
}
impl Drop for UdpSession { fn drop(&mut self) { self.close(); } }

pub(crate) struct DatagramManager {
    conn: quinn::Connection,
    endpoint: quinn::Endpoint,
    sessions: Mutex<HashMap<u32, Entry>>,
    incoming: Option<mpsc::Sender<UdpSession>>,
    next: AtomicU32,
    idle: Duration,
}
impl DatagramManager {
    pub fn new(conn: quinn::Connection, endpoint: quinn::Endpoint, idle: Duration, incoming: Option<mpsc::Sender<UdpSession>>) -> Arc<Self> {
        Arc::new(Self { conn, endpoint, sessions: Mutex::new(HashMap::new()), incoming, next: AtomicU32::new(1), idle })
    }
    fn insert(&self, id: u32, entries: &mut HashMap<u32, Entry>) -> UdpSession {
        let (tx, rx) = mpsc::channel(QUEUE_LIMIT);
        let state = Arc::new(SessionState::new());
        entries.insert(id, Entry { state: state.clone(), tx, defragger: Defragger::new() });
        UdpSession { id, conn: self.conn.clone(), _endpoint: self.endpoint.clone(), state,
            receiver: tokio::sync::Mutex::new(rx), _owner: None, write_lock: tokio::sync::Mutex::new(()) }
    }
    pub fn open(&self, owner: HysteriaConn) -> Result<UdpSession> {
        let mut entries = self.sessions.lock().expect("UDP sessions mutex");
        self.clean(&mut entries);
        if entries.len() >= SESSION_LIMIT { return Err(Error::Protocol("Hysteria UDP session limit reached".into())); }
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !entries.contains_key(&id) {
                let mut session = self.insert(id, &mut entries);
                session.keep_alive(owner);
                return Ok(session);
            }
        }
    }
    fn clean(&self, entries: &mut HashMap<u32, Entry>) {
        entries.retain(|_, entry| {
            let expired = entry.state.closed.load(Ordering::Acquire)
                || entry.tx.is_closed()
                || entry.state.last_activity.lock().expect("UDP activity mutex").elapsed() >= self.idle;
            if expired { entry.state.close(); }
            !expired
        });
    }
    fn feed(&self, message: UDPMessage) {
        let mut entries = self.sessions.lock().expect("UDP sessions mutex");
        let id = message.session_id;
        if !entries.contains_key(&id) {
            let Some(incoming) = &self.incoming else { return; };
            self.clean(&mut entries);
            if entries.len() >= SESSION_LIMIT { return; }
            let session = self.insert(id, &mut entries);
            if incoming.try_send(session).is_err() { entries.remove(&id); return; }
        }
        let entry = entries.get_mut(&id).expect("inserted UDP session");
        if entry.state.closed.load(Ordering::Acquire) { return; }
        // Invalid/partial fragments never prolong idle sessions.
        if let Some(message) = entry.defragger.feed(message)
            && entry.tx.try_send(DatagramPacket { address: message.address, data: message.data }).is_ok() {
            entry.state.touch();
        }
    }
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                result = self.conn.read_datagram() => {
                    let Ok(bytes) = result else { break; };
                    if let Ok(message) = UDPMessage::decode(&bytes) { self.feed(message); }
                }
                _ = interval.tick() => self.clean(&mut self.sessions.lock().expect("UDP sessions mutex")),
            }
        }
        let mut entries = self.sessions.lock().expect("UDP sessions mutex");
        for entry in entries.values() { entry.state.close(); }
        entries.clear();
    }
}
