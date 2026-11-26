//! Connection-scoped REALITY client hooks, adapted from cfal/shoes (MIT).
//! See README.md for the exact upstream revisions and attribution.
use super::certificate::verify_certificate;
use super::kx::{Exchange, shared};
use super::reality::{derive_auth_key, seal_session_id};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn invalid() -> Error { Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure) }

#[derive(Default)]
pub(super) struct Verification {
    auth: Option<[u8; 32]>,
    pub(super) authenticated: bool,
    peer: Option<[u8; 32]>,
}

pub(super) struct ClientHooks {
    server: [u8; 32],
    short_id: Vec<u8>,
    shared: Option<[u8; 32]>,
    context: Arc<Mutex<Verification>>,
}
impl fmt::Debug for ClientHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("RealityClientHooks") }
}

struct Verifier {
    context: Arc<Mutex<Verification>>,
    fallback: Arc<rustls::client::WebPkiServerVerifier>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("RealityCertificateVerifier") }
}

pub(super) fn configuration(server: [u8; 32], short_id: Vec<u8>)
    -> Result<(Arc<rustls::ClientConfig>, ClientHooks, Arc<Mutex<Verification>>), Error>
{
    let context = Arc::new(Mutex::new(Verification::default()));
    let provider = Arc::new(super::kx::provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let fallback = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build().map_err(|error| Error::General(error.to_string()))?;
    let verifier = Arc::new(Verifier { context: context.clone(), fallback, algorithms: provider.signature_verification_algorithms });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let hooks = ClientHooks { server, short_id, shared: None, context: context.clone() };
    Ok((Arc::new(config), hooks, context))
}

impl rustls::reality::ClientHooks for ClientHooks {
    fn start_key_exchange(&mut self, group: &'static dyn SupportedKxGroup) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let exchange = Exchange::new(group.name())?;
        self.shared = Some(shared(&exchange.private, &self.server)?);
        Ok(Box::new(exchange))
    }
    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error> {
        let shared = self.shared.take().ok_or_else(invalid)?;
        let random = hello.get(6..38).ok_or_else(invalid)?;
        let auth = derive_auth_key(&shared, &random[..20]);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::FailedToGetCurrentTime)?.as_secs() as u32;
        let mut aad = hello.to_vec();
        aad.get_mut(39..71).ok_or_else(invalid)?.fill(0);
        let session = seal_session_id(&auth, &random[20..], super::reality::CLIENT_VERSION, timestamp, &self.short_id, &aad)
            .map_err(|error| Error::General(error.to_string()))?;
        self.context.lock().map_err(|_| invalid())?.auth = Some(auth);
        Ok(session)
    }
    fn server_hello(&mut self, _client: &[u8], _server: &[u8]) -> Result<(), Error> { Ok(()) }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(&self, cert: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, Error> {
        let mut context = self.context.lock().map_err(|_| invalid())?;
        let auth = context.auth.take().ok_or_else(invalid)?;
        if let Ok(public) = verify_certificate(cert, &auth) {
            if !intermediates.is_empty() { return Err(invalid()); }
            context.authenticated = true;
            context.peer = Some(public);
            return Ok(ServerCertVerified::assertion());
        }
        // A genuine public certificate is recognized only through PKIX. The
        // caller refuses to expose this redirected connection to VLESS.
        self.fallback.verify_server_cert(cert, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> { Err(invalid()) }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, signature: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        let context = self.context.lock().map_err(|_| invalid())?;
        if context.authenticated {
            if signature.scheme != SignatureScheme::ED25519 { return Err(invalid()); }
            let peer = context.peer.ok_or_else(invalid)?;
            let (_, parsed) = x509_parser::parse_x509_certificate(cert).map_err(|_| invalid())?;
            if parsed.public_key().subject_public_key.data.as_ref() != peer { return Err(invalid()); }
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, peer)
                .verify(message, signature.signature()).map_err(|_| invalid())?;
            Ok(HandshakeSignatureValid::assertion())
        } else {
            rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
        }
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.algorithms.supported_schemes() }
}
