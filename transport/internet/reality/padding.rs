//! TLS 1.3 record padding for REALITY's target-sized flights with ring.
//! The pinned rustls fork exposes padding, but its ring provider uses the
//! rejecting default. Keep its key schedule, decryption and suite limits.
use ring::aead;
use rustls::crypto::cipher::{
    AeadKey, Iv, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion, SupportedCipherSuite, Tls13CipherSuite};
use std::sync::LazyLock;

struct PaddedAead {
    suite: rustls::CipherSuite,
    base: &'static dyn Tls13AeadAlgorithm,
    algorithm: &'static aead::Algorithm,
}

static ALGORITHMS: LazyLock<[PaddedAead; 3]> = LazyLock::new(|| {
    use rustls::crypto::ring::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};
    [
        (TLS13_AES_256_GCM_SHA384, &aead::AES_256_GCM),
        (TLS13_AES_128_GCM_SHA256, &aead::AES_128_GCM),
        (TLS13_CHACHA20_POLY1305_SHA256, &aead::CHACHA20_POLY1305),
    ].map(|(suite, algorithm)| PaddedAead { suite: suite.suite(), base: suite.tls13().unwrap().aead_alg, algorithm })
});

static SUITES: LazyLock<Vec<Tls13CipherSuite>> = LazyLock::new(|| {
    rustls::crypto::ring::default_provider().cipher_suites.iter().filter_map(|suite| {
        let suite = suite.tls13()?;
        let aead_alg = ALGORITHMS.iter().find(|algorithm| algorithm.suite == suite.common.suite)?;
        Some(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: suite.common.suite, hash_provider: suite.common.hash_provider,
                confidentiality_limit: suite.common.confidentiality_limit,
            },
            hkdf_provider: suite.hkdf_provider, aead_alg, quic: suite.quic,
        })
    }).collect()
});

pub(super) fn cipher_suites() -> Vec<SupportedCipherSuite> {
    SUITES.iter().map(SupportedCipherSuite::Tls13).collect()
}

impl Tls13AeadAlgorithm for PaddedAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(PaddedEncrypter::new(self.algorithm, key.as_ref(), iv))
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> { self.base.decrypter(key, iv) }
    fn key_len(&self) -> usize { self.base.key_len() }
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> { self.base.extract_keys(key, iv) }
    fn fips(&self) -> bool { self.base.fips() }
}

struct PaddedEncrypter { key: aead::LessSafeKey, iv: Iv }
impl PaddedEncrypter {
    fn new(algorithm: &'static aead::Algorithm, key: &[u8], iv: Iv) -> Self {
        Self { key: aead::LessSafeKey::new(aead::UnboundKey::new(algorithm, key).expect("TLS suite provides its required key length")), iv }
    }
}
impl MessageEncrypter for PaddedEncrypter {
    fn encrypt(&mut self, message: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        self.encrypt_with_padding(message, seq, 0)
    }
    fn encrypt_with_padding(&mut self, message: OutboundPlainMessage<'_>, seq: u64, padding: usize) -> Result<OutboundOpaqueMessage, Error> {
        // Bound TLSInnerPlaintext before allocation or nonce use, including the
        // inner type and every padding byte. Match rustls's receive-side limit.
        let plain_len = message.payload.len().checked_add(1).and_then(|len| len.checked_add(padding))
            .filter(|len| *len <= 16_385).ok_or(Error::EncryptError)?;
        let total = plain_len + self.key.algorithm().tag_len();
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&[u8::from(message.typ)]);
        payload.extend(std::iter::repeat_n(&0, padding));
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        self.key.seal_in_place_append_tag(nonce, aead::Aad::from(make_tls13_aad(total)), &mut payload)
            .map_err(|_| Error::EncryptError)?;
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize { payload_len + 1 + self.key.algorithm().tag_len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(payload: &[u8]) -> OutboundPlainMessage<'_> {
        OutboundPlainMessage { typ: ContentType::Handshake, version: ProtocolVersion::TLSv1_3, payload: payload.into() }
    }

    #[test]
    fn target_sized_records_authenticate_inner_type_and_zero_padding_for_every_suite() {
        for adapter in ALGORITHMS.iter() {
            let key = vec![7; adapter.algorithm.key_len()];
            for padding in [0, 1, 257, 1024] {
                let mut encrypter = PaddedEncrypter::new(adapter.algorithm, &key, Iv::from([3; 12]));
                let record = encrypter.encrypt_with_padding(message(b"handshake\0"), 17, padding).unwrap();
                let wire = record.encode();
                assert_eq!(&wire[..3], &[23, 3, 3]);
                assert_eq!(wire.len(), 5 + 10 + 1 + padding + 16);
                assert_eq!(u16::from_be_bytes([wire[3], wire[4]]) as usize, wire.len() - 5);
                let open = |wire: &[u8], seq| {
                    let key = aead::LessSafeKey::new(aead::UnboundKey::new(adapter.algorithm, &key).unwrap());
                    let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&Iv::from([3; 12]), seq).0);
                    let mut bytes = wire[5..].to_vec();
                    let plaintext = key.open_in_place(nonce, aead::Aad::from(&wire[..5]), &mut bytes)?;
                    Ok::<_, ring::error::Unspecified>(plaintext.to_vec())
                };
                let plaintext = open(&wire, 17).unwrap();
                assert_eq!(&plaintext[..10], b"handshake\0");
                assert_eq!(plaintext[10], 22);
                assert!(plaintext[11..].iter().all(|byte| *byte == 0));
                assert!(open(&wire, 18).is_err());
                let mut tampered = wire;
                *tampered.last_mut().unwrap() ^= 1;
                assert!(open(&tampered, 17).is_err());
            }
        }
        assert_eq!(cipher_suites().len(), 3);
    }

    #[test]
    fn zero_padding_matches_stock_ring_and_oversized_padding_is_rejected() {
        for adapter in ALGORITHMS.iter().filter(|adapter| adapter.key_len() == 32) {
            let mut padded = adapter.encrypter(AeadKey::from([7; 32]), Iv::from([3; 12]));
            let mut stock = adapter.base.encrypter(AeadKey::from([7; 32]), Iv::from([3; 12]));
            assert_eq!(padded.encrypt(message(b"bytes"), 9).unwrap().encode(), stock.encrypt(message(b"bytes"), 9).unwrap().encode());
            assert!(padded.encrypt_with_padding(message(b"bytes"), 10, usize::MAX).is_err());
            assert!(padded.encrypt_with_padding(message(b"bytes"), 10, 16_385 - 5).is_err());
            let full = vec![0; 16_384];
            assert!(padded.encrypt_with_padding(message(&full), 10, 1).is_err());
            assert_eq!(padded.encrypt(message(&full), 10).unwrap().encode().len(), 16_406);
        }
    }
}
