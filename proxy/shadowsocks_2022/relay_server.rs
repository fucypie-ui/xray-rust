//! An AES relay removes exactly one EIH and forwards the remaining encrypted stream.
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use crate::{common::{errors::{Error, Result}, net::{BoxStream, Destination, Network}, protocol::{SessionContext, User}}, features::inbound::{InboundHandler, InboundResult, NativeInboundListener}};
use super::{cipher::CipherMethod, identity::{PrefixedStream, tcp_identity}, kdf::user_psk_hash};

#[derive(Clone)]
pub struct RelayTarget { pub key: Vec<u8>, pub destination: Destination, pub user: User }

#[derive(Clone)]
pub struct RelayServer {
    tag: String,
    pub(crate) method: CipherMethod,
    pub(crate) key: Vec<u8>,
    targets: HashMap<[u8; 16], RelayTarget>,
    networks: super::config::Networks,
    native: Arc<super::native::NativeState>,
}

impl RelayServer {
    pub fn with_network(mut self, network: Option<&str>) -> Result<Self> {
        self.networks = super::config::Networks::parse(network)?;
        Ok(self)
    }
    pub fn new(tag: impl Into<String>, method: CipherMethod, key: Vec<u8>, targets: Vec<RelayTarget>) -> Result<Self> {
        if method.is_chacha() || key.len() != method.key_length() { return Err(Error::Config("SS2022 relay requires an AES method and a valid key".into())); }
        let mut by_hash = HashMap::new();
        for target in targets {
            if target.key.len() != method.key_length() || target.destination.network != Network::Tcp || target.destination.port == 0 { return Err(Error::Config("invalid SS2022 relay destination".into())); }
            by_hash.insert(user_psk_hash(&target.key), target);
        }
        Ok(Self { tag: tag.into(), method, key, targets: by_hash, networks: super::config::Networks::BOTH, native: Arc::new(super::native::NativeState::default()) })
    }
    pub fn target(&self, hash: &[u8; 16]) -> Result<RelayTarget> {
        self.targets.get(hash).cloned().ok_or_else(|| Error::Protocol("unknown SS2022 relay identity".into()))
    }
    #[cfg(test)]
    pub(super) async fn bind_with_limits(&self, address: SocketAddr, limits: super::native::RelayLimits) -> Result<Option<Box<dyn NativeInboundListener>>> {
        super::native::bind_relay_with_limits(self.clone(), self.networks, &self.native, address, limits).await
    }
    async fn accept(&self, mut stream: BoxStream, remote: SocketAddr) -> Result<InboundResult> {
        let mut salt = vec![0; self.method.key_length()];
        let mut eih = [0; 16];
        stream.read_exact(&mut salt).await?;
        stream.read_exact(&mut eih).await?;
        let target = self.target(&tcp_identity(self.method, &self.key, &salt, &eih)?)?;
        // Go requires the next hop's salt/EIH/fixed header in its first read.
        // Buffer a complete possible multi-user fixed header before dispatch so
        // the relay copy loop cannot write only the salt as its first batch.
        let mut prefix = salt;
        let start = prefix.len();
        prefix.resize(start + 16 + 11 + super::cipher::AEAD_TAG_SIZE, 0);
        stream.read_exact(&mut prefix[start..]).await?;
        let mut session = SessionContext::new(&self.tag, target.destination);
        session.source = Some(remote);
        session.user = Some(target.user);
        Ok(InboundResult { stream: Box::pin(PrefixedStream { prefix, offset: 0, inner: stream }), session })
    }
}

#[async_trait]
impl InboundHandler for RelayServer {
    fn tag(&self) -> &str { &self.tag }
    async fn close(&self) -> Result<()> { self.native.close(); Ok(()) }
    async fn bind_native(&self, address: SocketAddr) -> Result<Option<Box<dyn NativeInboundListener>>> {
        super::native::bind_relay(self.clone(), self.networks, &self.native, address).await
    }
    async fn handle_connection(&self, stream: BoxStream, remote: SocketAddr) -> Result<InboundResult> {
        if !self.networks.tcp { return Err(Error::Unsupported("SS2022 relay inbound TCP is disabled".into())); }
        tokio::time::timeout(Duration::from_secs(10), self.accept(stream, remote)).await.map_err(|_| Error::Timeout)?
    }
}

pub struct RelayDatagram { pub destination: Destination, pub wire: Vec<u8>, pub user: User, pub session_id: u64 }
impl RelayServer {
    /// Route an encrypted UDP request after removing exactly one identity layer.
    /// Downstream response bytes pass through unchanged at the runtime boundary.
    pub fn relay_datagram(&self, wire: &[u8]) -> Result<RelayDatagram> {
        use super::{identity::{HeaderCipher, udp_identity}, packet::{MAX_DATAGRAM_SIZE, decrypt_header}};
        if wire.len() < 32 || wire.len() > MAX_DATAGRAM_SIZE { return Err(Error::Protocol("invalid relay UDP length".into())); }
        let raw = decrypt_header(self.method, &self.key, &wire[..16])?;
        let eih = wire[16..32].try_into().map_err(|_| Error::Protocol("short relay UDP EIH".into()))?;
        let hash = udp_identity(&HeaderCipher::new(self.method, &self.key)?, &raw, &eih);
        let target = self.target(&hash)?;
        let mut forwarded = HeaderCipher::new(self.method, &target.key)?.encrypt(&raw).to_vec();
        forwarded.extend_from_slice(&wire[32..]);
        let mut destination = target.destination;
        destination.network = Network::Udp;
        Ok(RelayDatagram { destination, wire: forwarded, user: target.user, session_id: u64::from_be_bytes(raw[..8].try_into().map_err(|_| Error::Protocol("short UDP session ID".into()))?) })
    }
}
