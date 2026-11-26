use rand::RngExt;

pub fn generate_random_padding(min_len: usize, max_len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let len = rng.random_range(min_len..=max_len);
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf[..]);
    buf
}
