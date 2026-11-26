use crate::common::{errors::{Error, Result}, protocol::User};
use super::{aead::AuthIdGenerator, encoding::{RequestHeader, command_key}};
use std::{collections::{HashMap, HashSet}, sync::{Mutex, RwLock}};
use uuid::Uuid;

struct Entry { user: User, auth: AuthIdGenerator }
#[derive(Default)]
struct History {
    auth_current: HashSet<[u8; 16]>,
    auth_previous: HashSet<[u8; 16]>,
    last_rotation: Option<u64>,
    sessions: HashMap<([u8; 16], [u8; 16], [u8; 16]), u64>,
}

/// Authentication and both Go replay filters are shared across connections.
pub struct MemoryValidator {
    users: RwLock<HashMap<[u8; 16], Entry>>,
    history: Mutex<History>,
}
impl MemoryValidator {
    pub fn new() -> Self { Self { users: RwLock::new(HashMap::new()), history: Mutex::new(History::default()) } }
    pub fn add(&self, user: User) -> Result<()> {
        let entry = Entry { auth: AuthIdGenerator::new(&command_key(&user.id)), user };
        self.users.write().map_err(|_| Error::Other("VMess user lock poisoned".into()))?
            .insert(*entry.user.id.as_bytes(), entry);
        Ok(())
    }
    pub fn remove(&self, id: &Uuid) -> Result<bool> {
        Ok(self.users.write().map_err(|_| Error::Other("VMess user lock poisoned".into()))?.remove(id.as_bytes()).is_some())
    }
    pub fn get(&self, id: &Uuid) -> Option<User> {
        self.users.read().ok()?.get(id.as_bytes()).map(|entry| entry.user.clone())
    }
    pub fn count(&self) -> usize { self.users.read().map_or(0, |users| users.len()) }
    pub fn authenticate(&self, auth_id: &[u8; 16], now: u64) -> Result<User> {
        let users = self.users.read().map_err(|_| Error::Other("VMess user lock poisoned".into()))?;
        let entry = users.values().find(|entry| entry.auth.timestamp(auth_id).is_some())
            .ok_or_else(|| Error::AuthFailed("unknown VMess AuthID".into()))?;
        if !entry.auth.matches(auth_id, now, 120) {
            return Err(Error::AuthFailed("VMess AuthID timestamp outside 120-second window".into()));
        }
        let mut history = self.history.lock().map_err(|_| Error::Other("VMess replay lock poisoned".into()))?;
        let last = *history.last_rotation.get_or_insert(now);
        if now.saturating_sub(last) >= 120 {
            history.auth_previous = std::mem::take(&mut history.auth_current);
            history.last_rotation = Some(now);
        }
        if history.auth_current.contains(auth_id) || history.auth_previous.contains(auth_id) {
            return Err(Error::AuthFailed("replayed VMess AuthID".into()));
        }
        history.auth_current.insert(*auth_id);
        Ok(entry.user.clone())
    }
    pub fn register_session(&self, request: &RequestHeader, now: u64) -> Result<()> {
        self.register_session_parts(&request.user_id, request.request_body_key, request.request_body_iv, now)
    }
    pub fn register_session_parts(&self, user: &Uuid, key: [u8; 16], iv: [u8; 16], now: u64) -> Result<()> {
        let mut history = self.history.lock().map_err(|_| Error::Other("VMess replay lock poisoned".into()))?;
        history.sessions.retain(|_, expires| *expires > now);
        let id = (*user.as_bytes(), key, iv);
        if history.sessions.contains_key(&id) {
            return Err(Error::AuthFailed("replayed VMess body key/IV session".into()));
        }
        history.sessions.insert(id, now.saturating_add(180));
        Ok(())
    }
}
impl Default for MemoryValidator { fn default() -> Self { Self::new() } }
