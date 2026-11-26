use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use crate::common::errors::{Error, Result};
use crate::common::mux::mux::ClientStrategy;
use crate::common::net::Destination;
use crate::common::signal::done::Done;

#[derive(Clone)]
pub struct Session {
    pub id: u16,
    pub target: Option<Destination>,
    pub sender: Option<mpsc::Sender<Vec<u8>>>,
    pub closed: bool,
    pub done: Arc<Done>,
    receiver: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
}

impl Session {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            target: None,
            sender: None,
            closed: false,
            done: Arc::new(Done::new()),
            receiver: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
    pub fn close(&mut self) {
        if self.closed { return; }
        self.closed = true;
        self.done.close();
    }
    pub fn with_channel(id: u16, target: Destination, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let mut session = Self::new(id);
        session.target = Some(target);
        session.sender = Some(sender);
        session.receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
        session
    }
    /// The receive half is retained until the session consumer takes it.
    pub async fn take_receiver(&self) -> Option<mpsc::Receiver<Vec<u8>>> { self.receiver.lock().await.take() }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<u16, Session>>>,
    count: Arc<AtomicU64>,
    next: AtomicU16,
    closed: Arc<AtomicBool>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::with_capacity(16))),
            count: Arc::new(AtomicU64::new(0)),
            next: AtomicU16::new(0),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn closed(&self) -> bool { self.closed.load(Ordering::Relaxed) }
    pub fn is_closed(&self) -> bool { self.closed() }
    pub fn size(&self) -> usize {
        let guard = self.sessions.read().unwrap();
        guard.len()
    }
    pub fn count(&self) -> usize { self.count.load(Ordering::Relaxed) as usize }
    pub fn allocate(&self, strategy: &ClientStrategy) -> Option<Session> {
        let mut guard = self.sessions.write().unwrap();
        if self.closed.load(Ordering::Relaxed)
            || (strategy.max_concurrency > 0 && guard.len() >= strategy.max_concurrency as usize)
            || (strategy.max_connection > 0 && self.count.load(Ordering::Relaxed) >= u64::from(strategy.max_connection))
        { return None; }
        let id = (0..=u16::MAX).find_map(|_| {
            let id = self.next.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            (!guard.contains_key(&id)).then_some(id)
        })?;
        self.count.fetch_add(1, Ordering::SeqCst);
        let session = Session::new(id);
        guard.insert(id, session.clone());
        Some(session)
    }
    pub async fn allocate_channel(&self, target: Destination, sender: mpsc::Sender<Vec<u8>>) -> Result<Session> {
        let mut guard = self.sessions.write().unwrap();
        if self.closed.load(Ordering::Relaxed) { return Err(Error::Closed); }
        let id = (0..=u16::MAX).find_map(|_| {
            let id = self.next.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            (!guard.contains_key(&id)).then_some(id)
        }).ok_or(Error::BufferOverflow)?;
        self.count.fetch_add(1, Ordering::SeqCst);
        let mut session = Session::new(id);
        (session.target, session.sender) = (Some(target), Some(sender));
        guard.insert(id, session.clone());
        Ok(session)
    }
    pub fn add(&self, session: &Session) -> bool {
        let mut guard = self.sessions.write().unwrap();
        if self.closed.load(Ordering::Relaxed) || guard.contains_key(&session.id) { return false; }
        self.count.fetch_add(1, Ordering::SeqCst);
        guard.insert(session.id, session.clone());
        true
    }
    pub fn remove(&self, _locked: bool, id: u16) -> Option<Session> {
        let mut guard = self.sessions.write().unwrap();
        if self.closed.load(Ordering::Relaxed) { return None; }
        let mut session = guard.remove(&id)?;
        session.close();
        Some(session)
    }
    pub fn get(&self, id: u16) -> Option<Session> {
        let guard = self.sessions.read().unwrap();
        if self.closed.load(Ordering::Relaxed) { return None; }
        guard.get(&id).cloned()
    }
    pub fn close_if_no_session_and_idle(&self, check_size: usize, check_count: usize) -> bool {
        let mut guard = self.sessions.write().unwrap();
        if self.closed.load(Ordering::Relaxed) { return true; }
        let curr_count = self.count.load(Ordering::Relaxed) as usize;
        if !guard.is_empty() || check_size != 0 || check_count != curr_count { return false; }
        self.closed.store(true, Ordering::SeqCst);
        guard.clear();
        true
    }
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) { return; }
        let mut guard = self.sessions.write().unwrap();
        for (_, mut session) in guard.drain() { session.close(); }
    }
}

impl Default for SessionManager {
    fn default() -> Self { Self::new() }
}
