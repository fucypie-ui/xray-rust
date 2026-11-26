use std::collections::HashSet;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use super::cipher::invalid_data;

const ROTATE_INTERVAL: Duration = Duration::from_secs(60);
// Fail closed at capacity rather than evicting still-live replay entries.
const MAX_SALTS_PER_GENERATION: usize = 65_536;

pub struct ReplayFilter {
    inner: Mutex<Generations>,
}

struct Generations {
    current: HashSet<Vec<u8>>,
    previous: HashSet<Vec<u8>>,
    last_clean: Instant,
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self { inner: Mutex::new(Generations { current: HashSet::new(), previous: HashSet::new(), last_clean: Instant::now() }) }
    }
}

impl ReplayFilter {
    pub fn check_and_insert(&self, salt: &[u8]) -> io::Result<()> {
        self.check_at(salt, Instant::now())
    }

    pub(crate) fn check_at(&self, salt: &[u8], now: Instant) -> io::Result<()> {
        if salt.len() != 16 && salt.len() != 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid SS2022 replay salt length"));
        }
        let mut inner = self.inner.lock().map_err(|_| io::Error::other("SS2022 replay lock poisoned"))?;
        if now.duration_since(inner.last_clean) >= ROTATE_INTERVAL {
            inner.previous = std::mem::take(&mut inner.current);
            inner.last_clean = now;
        }
        if inner.current.contains(salt) || inner.previous.contains(salt) {
            return Err(invalid_data("SS2022 salt not unique"));
        }
        if inner.current.len() >= MAX_SALTS_PER_GENERATION {
            return Err(io::Error::other("SS2022 replay filter capacity reached"));
        }
        inner.current.insert(salt.to_vec());
        Ok(())
    }
}
