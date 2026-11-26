//! X25519MLKEM768 for the ring rustls provider. All entropy comes from the OS.
//! The wire layout is ML-KEM-768 || X25519, as in Go crypto/tls.
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};
use x25519_dalek::{PublicKey, StaticSecret};

pub(super) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    SystemRandom::new().fill(&mut bytes).map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok(bytes)
}

fn invalid() -> Error {
    Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare)
}

pub(super) fn shared(secret: &StaticSecret, peer: &[u8]) -> Result<[u8; 32], Error> {
    let peer: [u8; 32] = peer.try_into().map_err(|_| invalid())?;
    let secret = secret.diffie_hellman(&PublicKey::from(peer));
    if !secret.was_contributory() { return Err(invalid()); }
    Ok(secret.to_bytes())
}

#[derive(Debug)]
struct HybridGroup;
static HYBRID: HybridGroup = HybridGroup;

pub(super) fn provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![&HYBRID, rustls::crypto::ring::kx_group::X25519];
    provider
}

impl SupportedKxGroup for HybridGroup {
    fn name(&self) -> NamedGroup { NamedGroup::X25519MLKEM768 }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool { version == ProtocolVersion::TLSv1_3 }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(Exchange::new(self.name())?))
    }
    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if peer.len() != 1216 { return Err(invalid()); }
        let key = EncapsulationKey768::new(peer[..1184].try_into().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        // The deterministic API accepts explicit *uniform* randomness, supplied
        // here by ring's OS CSPRNG, avoiding rand_core version coupling.
        let (ciphertext, kem_secret) = key.encapsulate_deterministic(&random::<32>()?.into());
        let private = StaticSecret::from(random::<32>()?);
        let classical = shared(&private, &peer[1184..])?;
        let mut public = ciphertext.to_vec();
        public.extend_from_slice(PublicKey::from(&private).as_bytes());
        let mut secret = [0; 64];
        secret[..32].copy_from_slice(&kem_secret);
        secret[32..].copy_from_slice(&classical);
        Ok(CompletedKeyExchange { group: self.name(), pub_key: public, secret: SharedSecret::from(secret.as_slice()) })
    }
}

pub(super) struct Exchange {
    pub(super) private: StaticSecret,
    kem: Option<DecapsulationKey768>,
    public: Vec<u8>,
    group: NamedGroup,
}

impl Exchange {
    pub(super) fn new(group: NamedGroup) -> Result<Self, Error> {
        if !matches!(group, NamedGroup::X25519 | NamedGroup::X25519MLKEM768) { return Err(invalid()); }
        let private = StaticSecret::from(random::<32>()?);
        let kem = if group == NamedGroup::X25519MLKEM768 {
            Some(DecapsulationKey768::from_seed(Seed::from(random::<64>()?)))
        } else { None };
        let mut public = kem.as_ref().map_or_else(Vec::new, |key| key.encapsulation_key().to_bytes().to_vec());
        public.extend_from_slice(PublicKey::from(&private).as_bytes());
        Ok(Self { private, kem, public, group })
    }
}

impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if let Some(kem) = &self.kem {
            if peer.len() != 1120 { return Err(invalid()); }
            let ciphertext = peer[..1088].try_into().map_err(|_| invalid())?;
            let pq = kem.decapsulate(ciphertext);
            let classical = shared(&self.private, &peer[1088..])?;
            let mut secret = [0; 64];
            secret[..32].copy_from_slice(&pq);
            secret[32..].copy_from_slice(&classical);
            Ok(SharedSecret::from(secret.as_slice()))
        } else {
            Ok(SharedSecret::from(shared(&self.private, peer)?.as_slice()))
        }
    }
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(shared(&self.private, peer)?.as_slice()))
    }
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        (self.group == NamedGroup::X25519MLKEM768).then(|| (NamedGroup::X25519, &self.public[1184..]))
    }
    fn pub_key(&self) -> &[u8] { &self.public }
    fn group(&self) -> NamedGroup { self.group }
}
