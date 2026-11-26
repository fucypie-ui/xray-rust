//! REALITY authenticates an Ed25519 public key with HMAC-SHA512(AuthKey, key).
//! CertificateVerify separately proves possession of the Ed25519 private key.
use ring::hmac;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate};

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::PermissionDenied, "REALITY certificate authentication failed") }

pub(super) fn verify_certificate(der: &[u8], auth: &[u8; 32]) -> io::Result<[u8; 32]> {
    let (trailing, certificate) = X509Certificate::from_der(der).map_err(|_| invalid())?;
    let spki = certificate.public_key();
    if !trailing.is_empty() || spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || spki.algorithm.parameters.is_some()
        || certificate.signature_algorithm.algorithm.to_id_string() != "1.3.101.112"
        || certificate.signature_algorithm.parameters.is_some()
        || certificate.tbs_certificate.signature.algorithm.to_id_string() != "1.3.101.112"
        || certificate.tbs_certificate.signature.parameters.is_some()
        || spki.subject_public_key.unused_bits != 0 || certificate.signature_value.unused_bits != 0 {
        return Err(invalid());
    }
    let public: [u8; 32] = spki.subject_public_key.data.as_ref().try_into().map_err(|_| invalid())?;
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA512, auth), &public, certificate.signature_value.data.as_ref())
        .map_err(|_| invalid())?;
    Ok(public)
}

pub(super) fn certified_key(auth: &[u8; 32]) -> io::Result<rustls::sign::CertifiedKey> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(io::Error::other)?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0]));
    let certificate = params.self_signed(&key).map_err(io::Error::other)?;
    let mut der = certificate.der().to_vec();
    let (trailing, parsed) = X509Certificate::from_der(&der).map_err(|_| invalid())?;
    if !trailing.is_empty() || parsed.signature_value.data.len() != 64 { return Err(invalid()); }
    let public = parsed.public_key().subject_public_key.data.as_ref();
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, auth), public);
    // signatureValue is the final certificate field; require exact placement.
    if der.get(der.len().saturating_sub(64)..) != Some(parsed.signature_value.data.as_ref()) { return Err(invalid()); }
    let offset = der.len() - 64;
    der[offset..].copy_from_slice(tag.as_ref());
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&private).map_err(io::Error::other)?;
    Ok(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(der)], signing))
}

// Pinned Go REALITY sets hs.sigAlg = Ed25519, including for Chrome profiles
// that omit it from signature_algorithms. uTLS still verifies the real
// CertificateVerify signature. Limit this selection rule to REALITY servers;
// retain the ring signer and the HMAC-authenticated Ed25519 certificate.
#[derive(Debug)]
struct RealitySigningKey(Arc<dyn rustls::sign::SigningKey>);
impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(&self, _: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }
    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> { self.0.public_key() }
    fn algorithm(&self) -> rustls::SignatureAlgorithm { self.0.algorithm() }
}

pub(super) fn server_config(auth: &[u8; 32]) -> io::Result<Arc<rustls::ServerConfig>> {
    let mut key = certified_key(auth)?;
    key.key = Arc::new(RealitySigningKey(key.key));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(super::kx::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).map_err(io::Error::other)?
        .with_no_client_auth().with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    config.send_tls13_tickets = 0;
    // Go REALITY's NextProtos is nil. Do not advertise an invented protocol.
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::SigningKey;

    #[test]
    fn reality_selects_and_proves_ed25519_with_chrome_signature_schemes() {
        let auth = [7; 32];
        let key = certified_key(&auth).unwrap();
        let public = verify_certificate(&key.cert[0], &auth).unwrap();
        let offered = [rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::RSA_PSS_SHA256];
        assert!(key.key.choose_scheme(&offered).is_none(), "ordinary TLS must respect the offered schemes");
        let signer = RealitySigningKey(key.key).choose_scheme(&offered).expect("Go REALITY selects Ed25519 even when Chrome omits it");
        assert_eq!(signer.scheme(), rustls::SignatureScheme::ED25519);
        let signature = signer.sign(b"TLS 1.3 CertificateVerify transcript").unwrap();
        let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public);
        verifier.verify(b"TLS 1.3 CertificateVerify transcript", &signature).unwrap();
        assert!(verifier.verify(b"modified transcript", &signature).is_err());
        assert!(verify_certificate(&key.cert[0], &[8; 32]).is_err());
    }
}
