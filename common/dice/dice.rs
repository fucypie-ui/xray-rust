use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

pub fn roll(n: usize) -> usize {
    if n <= 1 { return 0; }
    rand::rng().random_range(0..n)
}

pub fn roll_int63n(n: i64) -> i64 {
    if n <= 1 { return 0; }
    rand::rng().random_range(0..n)
}

pub fn roll_deterministic(n: usize, seed: i64) -> usize {
    if n <= 1 { return 0; }
    let mut rng = StdRng::seed_from_u64(seed as u64);
    rng.random_range(0..n)
}

pub fn roll_uint16() -> u16 { rand::rng().random() }

pub fn roll_uint64() -> u64 { rand::rng().random() }

pub use roll_uint16 as roll_u16;
pub use roll_uint64 as roll_u64;

pub struct DeterministicDice {
    rng: StdRng,
}

impl DeterministicDice {
    pub fn new(seed: i64) -> Self { Self { rng: StdRng::seed_from_u64(seed as u64), } }
    pub fn roll(&mut self, n: usize) -> usize {
        if n <= 1 { return 0; }
        self.rng.random_range(0..n)
    }
}
