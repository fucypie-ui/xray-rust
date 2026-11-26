pub const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padding { pub min: usize, pub max: usize }
impl Padding {
    pub fn new(min: usize, max: usize) -> Self { Self { min, max } }
    pub fn generate_string(&self) -> String {
        if self.min >= self.max { return String::new(); }
        let random = generate_padding(8);
        let value = u64::from_ne_bytes(random.try_into().expect("eight random bytes"));
        let size = self.min + value as usize % (self.max - self.min);
        generate_padding(size).into_iter().map(|value| char::from(PADDING_CHARS[usize::from(value) % PADDING_CHARS.len()])).collect()
    }
}
pub fn generate_padding(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    rustls::crypto::ring::default_provider().secure_random.fill(&mut bytes).expect("operating system random source");
    bytes
}
