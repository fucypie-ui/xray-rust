use super::config::RealityConfig;
use super::{certificate, hello, hooks, kx, stream::RealityStream};
use crate::common::errors::{Error, Result};
use crate::common::net::BoxStream;
use base64::Engine;
use ring::{aead, hkdf};
use std::collections::HashSet;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Matches the authoritative Xray-core 67756b3 client metadata.
pub(super) const CLIENT_VERSION: (u8, u8, u8) = (26, 11, 9);

pub fn decode_reality_key32(raw: &str) -> Result<[u8; 32]> {
    let text = raw.trim();
    let bytes = if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(text).map_err(|err| Error::Config(format!("Invalid REALITY hex key: {err}")))?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim_end_matches('='))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(text))
            .map_err(|err| Error::Config(format!("Invalid REALITY key: {err}")))?
    };
    let len = bytes.len();
    bytes.try_into().map_err(|_| Error::Config(format!("REALITY key must be 32 bytes, got {len}")))
}

fn decode_short_id(text: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(text).map_err(|_| Error::Config("REALITY short ID must be even-length hexadecimal".into()))?;
    if bytes.len() > 8 { return Err(Error::Config("REALITY short ID cannot exceed eight bytes".into())); }
    let mut padded = vec![0; 8];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Ok(padded)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityAuthSession {
    pub version: (u8, u8, u8),
    pub timestamp: u32,
    pub short_id: Vec<u8>,
}

pub fn derive_auth_key(shared_secret: &[u8; 32], random_salt_20: &[u8]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, random_salt_20);
    let extracted = salt.extract(shared_secret);
    let info = [b"REALITY".as_slice()];
    let expanded = extracted.expand(&info, hkdf::HKDF_SHA256).expect("fixed SHA256 HKDF output length");
    let mut auth = [0; 32];
    expanded.fill(&mut auth).expect("fixed SHA256 HKDF output length");
    auth
}

fn cipher(auth: &[u8; 32]) -> Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::AES_256_GCM, auth).map(aead::LessSafeKey::new)
        .map_err(|_| Error::Crypto("Invalid REALITY authentication key".into()))
}

pub fn seal_session_id(auth_key: &[u8; 32], nonce_12: &[u8], version: (u8, u8, u8), timestamp: u32, short_id: &[u8], client_hello_raw: &[u8]) -> Result<[u8; 32]> {
    if short_id.len() > 8 { return Err(Error::Config("REALITY short ID cannot exceed eight bytes".into())); }
    let mut plaintext = vec![0; 16];
    plaintext[..3].copy_from_slice(&[version.0, version.1, version.2]);
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..8 + short_id.len()].copy_from_slice(short_id);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_12).map_err(|_| Error::Crypto("REALITY nonce must be 12 bytes".into()))?;
    cipher(auth_key)?.seal_in_place_append_tag(nonce, aead::Aad::from(client_hello_raw), &mut plaintext)
        .map_err(|_| Error::Crypto("REALITY session authentication failed".into()))?;
    plaintext.try_into().map_err(|_| Error::Crypto("Invalid REALITY session ID length".into()))
}

pub fn open_session_id(auth_key: &[u8; 32], nonce_12: &[u8], sealed_session_id: &[u8; 32], client_hello_raw: &[u8]) -> Result<RealityAuthSession> {
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_12).map_err(|_| Error::Crypto("REALITY nonce must be 12 bytes".into()))?;
    let mut ciphertext = *sealed_session_id;
    let key = cipher(auth_key)?;
    let plaintext = key.open_in_place(nonce, aead::Aad::from(client_hello_raw), &mut ciphertext)
        .map_err(|_| Error::AuthFailed("REALITY session authentication failed".into()))?;
    if plaintext.len() != 16 { return Err(Error::AuthFailed("Invalid REALITY session metadata length".into())); }
    Ok(RealityAuthSession {
        version: (plaintext[0], plaintext[1], plaintext[2]),
        timestamp: u32::from_be_bytes(plaintext[4..8].try_into().map_err(|_| Error::AuthFailed("Invalid REALITY timestamp".into()))?),
        short_id: plaintext[8..16].to_vec(),
    })
}

fn parse_version(version: Option<&str>) -> Result<Option<(u8, u8, u8)>> {
    let Some(version) = version.filter(|v| !v.is_empty()) else { return Ok(None); };
    let components: std::result::Result<Vec<u8>, _> = version.split('.').map(str::parse).collect();
    let components = components.map_err(|_| Error::Config("Invalid REALITY client version".into()))?;
    if components.len() > 3 { return Err(Error::Config("REALITY client version has more than three components".into())); }
    let mut result = [0; 3];
    result[..components.len()].copy_from_slice(&components);
    Ok(Some((result[0], result[1], result[2])))
}

pub struct RealityServer {
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<Vec<u8>>,
    pub private_key: Option<StaticSecret>,
    pub dest: Option<String>,
    /// Kept for callers of the original API; zero means unlimited, as in Go.
    pub max_time_diff_sec: u32,
    max_time_diff_ms: u64,
    min_client_version: Option<(u8, u8, u8)>,
    max_client_version: Option<(u8, u8, u8)>,
}

impl RealityServer {
    pub fn new(config: &RealityConfig) -> Result<Self> {
        let short_ids = config.short_ids.iter().map(|id| decode_short_id(id)).collect::<Result<_>>()?;
        let private_key = config.private_key.as_deref().map(decode_reality_key32).transpose()?.map(StaticSecret::from);
        if private_key.is_none() { return Err(Error::Config("REALITY server requires a private key".into())); }
        let max_time_diff_ms = config.max_time_diff.unwrap_or(0);
        Ok(Self {
            server_names: config.server_names.iter().cloned().collect(), short_ids, private_key,
            dest: config.dest.clone(), max_time_diff_sec: (max_time_diff_ms / 1000).min(u32::MAX as u64) as u32,
            max_time_diff_ms, min_client_version: parse_version(config.min_client_ver.as_deref())?,
            max_client_version: parse_version(config.max_client_ver.as_deref())?,
        })
    }

    pub async fn accept(&self, mut client: BoxStream) -> Result<Option<BoxStream>> {
        let dest = self.dest.as_ref().ok_or_else(|| Error::Config("REALITY server requires a fallback target".into()))?;
        // Like Go, connect before reading/authenticating ClientHello and mirror
        // all its bytes while reading; target connection failure is not hidden.
        let mut target = tokio::net::TcpStream::connect(dest).await?;
        target.set_nodelay(true)?;
        let (wire, parsed) = match hello::read_client_hello(&mut client, &mut target).await {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let authenticated = parsed.filter(|hello| self.validate_server_name(&hello.server_name))
            .and_then(|hello| self.authenticate(&hello).ok().map(|auth| (hello, auth)));
        let Some((hello, auth)) = authenticated else {
            return Self::forward(client, target, &[]).await;
        };
        let flight = hello::read_target_flight(&mut target).await?;
        let staged = match self.stage_server(&wire, &hello, &auth, &flight) {
            Ok(staged) => staged,
            Err(error) if error.kind() == io::ErrorKind::Unsupported => return Self::forward(client, target, &flight.raw).await,
            Err(error) => return Err(error.into()),
        };
        let stream = RealityStream::with_output(client, staged.0, staged.1).handshake().await?;
        drop(target);
        Ok(Some(Box::pin(stream)))
    }

    fn stage_server(&self, wire: &[u8], hello: &hello::ClientHello, auth: &[u8; 32], flight: &hello::TargetFlight)
        -> io::Result<(rustls::Connection, Vec<u8>)>
    {
        let plan = hello::flight_plan(flight)?;
        let mut handshake = hello.aad.clone();
        handshake[39..71].copy_from_slice(&hello.session);
        let prepared = rustls::reality::PreparedServerHello::new(&handshake, &flight.records[0][5..], &kx::provider())
            .map_err(|_| io::Error::from(io::ErrorKind::Unsupported))?.with_flight_plan(plan);
        let expected_hello = prepared.server_hello().to_vec();
        let config = certificate::server_config(auth)?;
        let server = rustls::ServerConnection::new_reality(config, prepared).map_err(io::Error::other)?;
        let mut connection = rustls::Connection::Server(server);
        let mut input = io::Cursor::new(wire);
        while (input.position() as usize) < wire.len() {
            let n = connection.read_tls(&mut input)?;
            if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
            connection.process_new_packets().map_err(|error| match error {
                rustls::Error::PeerIncompatible(rustls::PeerIncompatible::RealityUnsupported) => io::Error::from(io::ErrorKind::Unsupported),
                error => io::Error::new(io::ErrorKind::InvalidData, error),
            })?;
        }
        let mut output = Vec::new();
        while connection.wants_write() {
            if connection.write_tls(&mut output)? == 0 { return Err(io::ErrorKind::WriteZero.into()); }
        }
        hello::verify_staged(&output, flight, &expected_hello).map_err(|_| io::Error::from(io::ErrorKind::Unsupported))?;
        Ok((connection, output))
    }

    async fn forward(mut client: BoxStream, mut target: tokio::net::TcpStream, preread: &[u8]) -> Result<Option<BoxStream>> {
        client.write_all(preread).await?;
        client.flush().await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        Ok(None)
    }

    fn authenticate(&self, hello: &hello::ClientHello) -> Result<[u8; 32]> {
        let auth = self.auth_key(&hello.public, &hello.random)?;
        let session = open_session_id(&auth, &hello.random[20..], &hello.session, &hello.aad)?;
        self.validate_session(&session, self.max_time_diff_ms)?;
        Ok(auth)
    }

    fn auth_key(&self, public: &[u8; 32], random: &[u8; 32]) -> Result<[u8; 32]> {
        let private = self.private_key.as_ref().ok_or_else(|| Error::Config("REALITY server has no private key".into()))?;
        let shared = kx::shared(private, public).map_err(|_| Error::AuthFailed("Invalid REALITY X25519 key share".into()))?;
        Ok(derive_auth_key(&shared, &random[..20]))
    }

    fn validate_session(&self, session: &RealityAuthSession, max_ms: u64) -> Result<()> {
        self.validate_session_at(session, max_ms, SystemTime::now())
    }

    pub(super) fn validate_session_at(&self, session: &RealityAuthSession, max_ms: u64, now: SystemTime) -> Result<()> {
        if !self.validate_short_id(&session.short_id) { return Err(Error::AuthFailed("Unrecognized REALITY short ID".into())); }
        if self.min_client_version.is_some_and(|min| session.version < min) || self.max_client_version.is_some_and(|max| session.version > max) {
            return Err(Error::AuthFailed("Unsupported REALITY client version".into()));
        }
        if max_ms != 0 {
            let client_time = UNIX_EPOCH + Duration::from_secs(session.timestamp as u64);
            let delta = now.duration_since(client_time).unwrap_or_else(|error| error.duration());
            if delta > Duration::from_millis(max_ms) { return Err(Error::AuthFailed("REALITY timestamp outside allowed window".into())); }
        }
        Ok(())
    }

    pub fn validate_short_id(&self, id: &[u8]) -> bool {
        if id.len() > 8 { return false; }
        let mut padded = [0; 8];
        padded[..id.len()].copy_from_slice(id);
        // Constant-time compare every configured identifier; empty lists deny.
        self.short_ids.iter().fold(false, |matched, candidate| {
            let equal = candidate.iter().zip(padded).fold(0u8, |diff, (left, right)| diff | (left ^ right)) == 0;
            matched | (candidate.len() == 8 && equal)
        })
    }
    pub fn validate_server_name(&self, sni: &str) -> bool { self.server_names.contains(sni) }

    pub fn verify_client_hello(&self, client_pub: &[u8; 32], random: &[u8; 32], session: &[u8; 32], raw: &[u8], max_time_diff_sec: u32) -> Result<RealityAuthSession> {
        let auth = self.auth_key(client_pub, random)?;
        let session = open_session_id(&auth, &random[20..], session, raw)?;
        self.validate_session(&session, u64::from(max_time_diff_sec) * 1000)?;
        Ok(session)
    }
}

pub struct RealityClient {
    pub public_key: PublicKey,
    pub short_id: Vec<u8>,
    pub server_name: String,
    spider_path: String,
}

impl RealityClient {
    pub fn new(server_name: &str, public_key: &str, short_id: &str) -> Result<Self> {
        match rustls::pki_types::ServerName::try_from(server_name.to_owned()) {
            Ok(rustls::pki_types::ServerName::DnsName(_)) => {}
            _ => return Err(Error::Config("REALITY requires a DNS server name".into())),
        }
        let public_key = PublicKey::from(decode_reality_key32(public_key)?);
        Ok(Self { public_key, short_id: decode_short_id(short_id)?, server_name: server_name.to_owned(), spider_path: "/".into() })
    }

    /// Runtime config adapter, including the authenticated-target spider path.
    pub fn from_config(config: &RealityConfig, fallback_server_name: &str) -> Result<Self> {
        let name = config.server_name.as_deref().filter(|name| !name.is_empty()).unwrap_or(fallback_server_name);
        let public = config.public_key.as_deref().ok_or_else(|| Error::Config("REALITY client requires a public key".into()))?;
        Self::new(name, public, config.short_id.as_deref().unwrap_or(""))?
            .with_spider_path(config.spider_x.as_deref().unwrap_or("/"))
    }

    pub fn with_spider_path(mut self, path: &str) -> Result<Self> {
        // Only same-origin paths are accepted; never turn a failed authentication
        // into a request to a URL provided by an untrusted peer.
        if !path.starts_with('/') || path.starts_with("//") || path.bytes().any(|b| b <= 0x20 || b == 0x7f)
            || path.len() > 2048 {
            return Err(Error::Config("REALITY spiderX must be a same-origin HTTP path".into()));
        }
        self.spider_path = path.to_owned();
        Ok(self)
    }

    pub async fn connect(&self, stream: BoxStream) -> Result<BoxStream> {
        let (config, hooks, verification) = hooks::configuration(*self.public_key.as_bytes(), self.short_id.clone())
            .map_err(|error| Error::Protocol(format!("REALITY client configuration failed: {error}")))?;
        let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| Error::Config("Invalid REALITY server name".into()))?;
        let client = rustls::ClientConnection::new_reality(config, name, Box::new(hooks))
            .map_err(|error| Error::Protocol(format!("REALITY ClientHello failed: {error}")))?;
        let stream = RealityStream::new(stream, rustls::Connection::Client(client)).handshake().await?;
        let authenticated = verification.lock().map_err(|_| Error::AuthFailed("REALITY verification state unavailable".into()))?.authenticated;
        if !authenticated {
            let name = self.server_name.clone();
            let path = self.spider_path.clone();
            // Reuse only this PKIX-verified connection. A detached, bounded
            // cover request never receives VLESS bytes or becomes a proxy stream.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(10), spider(stream, name, path)).await;
            });
            return Err(Error::AuthFailed("REALITY received a genuine target certificate (redirection or authentication failure)".into()));
        }
        Ok(Box::pin(stream))
    }

    pub fn auth_client_hello(&self, secret: EphemeralSecret, random: &[u8; 32], raw: &[u8]) -> Result<[u8; 32]> {
        let shared = secret.diffie_hellman(&self.public_key);
        if !shared.was_contributory() { return Err(Error::AuthFailed("Invalid REALITY server key".into())); }
        let auth = derive_auth_key(shared.as_bytes(), &random[..20]);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::Crypto("System clock precedes Unix epoch".into()))?.as_secs() as u32;
        seal_session_id(&auth, &random[20..], CLIENT_VERSION, timestamp, &self.short_id, raw)
    }
    pub fn generate_auth(&self) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from(kx::random::<32>().expect("OS random source unavailable"));
        let public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&self.public_key);
        (*public.as_bytes(), *shared.as_bytes())
    }
}

async fn spider(mut stream: RealityStream, name: String, path: String) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    if stream.negotiated_h2() {
        let (mut sender, connection) = h2::client::handshake(stream).await.map_err(io::Error::other)?;
        let request = http::Request::builder().method("GET").uri(format!("https://{name}{path}"))
            .header("user-agent", "Mozilla/5.0").body(()).map_err(io::Error::other)?;
        let request = async move {
            let (response, _) = sender.send_request(request, true).map_err(io::Error::other)?;
            let mut body = response.await.map_err(io::Error::other)?.into_body();
            let mut total = 0;
            while let Some(bytes) = body.data().await {
                let bytes = bytes.map_err(io::Error::other)?;
                total += bytes.len();
                body.flow_control().release_capacity(bytes.len()).map_err(io::Error::other)?;
                if total >= 64 * 1024 { break; }
            }
            Ok(())
        };
        tokio::pin!(connection);
        tokio::select! { result = request => result, result = &mut connection => result.map_err(io::Error::other) }
    } else {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut bytes = [0; 4096];
        let mut total = 0;
        while total < 64 * 1024 {
            let n = stream.read(&mut bytes).await?;
            if n == 0 { break; }
            total += n;
        }
        Ok(())
    }
}
