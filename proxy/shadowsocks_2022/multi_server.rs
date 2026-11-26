//! Authenticated AES multi-user TCP inbound; compatibility metadata types live separately.
use std::{collections::HashMap, io, net::SocketAddr, sync::RwLock, time::Duration};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use crate::{common::{errors::{Error, Result}, net::BoxStream, protocol::{SessionContext, User}}, features::inbound::{InboundHandler, InboundResult}};
use super::{cipher::{CipherMethod, invalid_data}, identity::tcp_identity, kdf::user_psk_hash, replay::ReplayFilter, stream::accept_tcp_with_salt};

#[derive(Clone)]
pub struct UserAccount { pub key: Vec<u8>, pub user: User }

#[derive(Default)]
struct Accounts {
    by_hash: HashMap<[u8; 16], UserAccount>,
    by_email: HashMap<String, UserAccount>,
    count: usize,
}

pub struct MultiUserServer {
    tag: String,
    pub(crate) method: CipherMethod,
    pub(crate) master_key: Vec<u8>,
    accounts: RwLock<Accounts>,
    replay: ReplayFilter,
    datagrams: std::sync::Mutex<super::udp_session::ServerUdpSessions>,
}

impl MultiUserServer {
    pub fn new(tag: impl Into<String>, method: CipherMethod, master_key: Vec<u8>) -> Result<Self> {
        if method.is_chacha() || master_key.len() != method.key_length() { return Err(Error::Config("SS2022 multi-user requires an AES method and a valid master key".into())); }
        Ok(Self { tag: tag.into(), method, master_key, accounts: RwLock::new(Accounts::default()), replay: ReplayFilter::default(), datagrams: std::sync::Mutex::new(super::udp_session::ServerUdpSessions::new(method)) })
    }
    pub fn add_account(&self, account: UserAccount) -> Result<()> {
        if account.key.len() != self.method.key_length() {
            return Err(Error::Config("invalid SS2022 user key length".into()));
        }
        let mut accounts = self.accounts.write()
            .map_err(|_| Error::Other("SS2022 account lock poisoned".into()))?;
        let email = account.user.email.to_lowercase();
        if !email.is_empty() && accounts.by_email.contains_key(&email) {
            return Err(Error::Config("duplicate SS2022 user email".into()));
        }
        // Match Go's two indices: a repeated key selects the most recently
        // added account, while email-based listing still retains each alias.
        accounts.by_hash.insert(user_psk_hash(&account.key), account.clone());
        if !email.is_empty() { accounts.by_email.insert(email, account); }
        accounts.count += 1;
        Ok(())
    }

    pub fn remove_account(&self, email: &str) -> Result<()> {
        if email.is_empty() { return Err(Error::Config("empty SS2022 user email".into())); }
        let mut accounts = self.accounts.write()
            .map_err(|_| Error::Other("SS2022 account lock poisoned".into()))?;
        let account = accounts.by_email.remove(&email.to_lowercase())
            .ok_or_else(|| Error::NotFound("SS2022 user not found".into()))?;
        accounts.by_hash.remove(&user_psk_hash(&account.key));
        accounts.count -= 1;
        Ok(())
    }

    pub fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        let accounts = self.accounts.read()
            .map_err(|_| Error::Other("SS2022 account lock poisoned".into()))?;
        Ok(accounts.by_email.get(&email.to_lowercase()).map(|account| account.user.clone()))
    }

    pub fn users(&self) -> Result<Vec<User>> {
        let accounts = self.accounts.read()
            .map_err(|_| Error::Other("SS2022 account lock poisoned".into()))?;
        Ok(accounts.by_email.values().map(|account| account.user.clone()).collect())
    }

    pub fn user_count(&self) -> Result<usize> {
        Ok(self.accounts.read()
            .map_err(|_| Error::Other("SS2022 account lock poisoned".into()))?.count)
    }

    pub fn account(&self, hash: &[u8; 16]) -> io::Result<UserAccount> {
        self.accounts.read().map_err(|_| io::Error::other("SS2022 account lock poisoned"))?
            .by_hash.get(hash).cloned().ok_or_else(|| invalid_data("unknown SS2022 identity"))
    }

    async fn accept(&self, mut stream: BoxStream, remote: SocketAddr) -> Result<InboundResult> {
        let mut salt = vec![0; self.method.key_length()];
        let mut eih = [0; 16];
        stream.read_exact(&mut salt).await?;
        stream.read_exact(&mut eih).await?;
        let hash = tcp_identity(self.method, &self.master_key, &salt, &eih)?;
        let account = self.account(&hash)?;
        let (destination, stream) = accept_tcp_with_salt(stream, self.method, account.key, salt, &self.replay).await?;
        let mut session = SessionContext::new(&self.tag, destination);
        session.source = Some(remote);
        session.user = Some(account.user);
        Ok(InboundResult { stream: Box::pin(stream), session })
    }
}

#[async_trait]
impl InboundHandler for MultiUserServer {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, stream: BoxStream, remote: SocketAddr) -> Result<InboundResult> {
        tokio::time::timeout(Duration::from_secs(10), self.accept(stream, remote)).await.map_err(|_| Error::Timeout)?
    }
}

impl MultiUserServer {
    pub fn decode_datagram(&self, wire: &[u8], remote: SocketAddr) -> Result<super::udp_session::InboundDatagram> {
        use super::{identity::{HeaderCipher, udp_identity}, packet::{PacketCodec, MAX_DATAGRAM_SIZE, decrypt_header}, stream::unix_time};
        if wire.len() < 48 || wire.len() > MAX_DATAGRAM_SIZE { return Err(invalid_data("invalid EIH UDP packet length").into()); }
        let raw = decrypt_header(self.method, &self.master_key, &wire[..16])?;
        let eih = wire[16..32].try_into().map_err(|_| invalid_data("short UDP EIH"))?;
        let hash = udp_identity(&HeaderCipher::new(self.method, &self.master_key)?, &raw, &eih);
        let account = self.account(&hash)?;
        let now = unix_time()?;
        let packet = PacketCodec::new(self.method, vec![account.key.clone()])?.decode_aes_body_at(&raw, &wire[32..], now)?;
        Ok(self.datagrams.lock().map_err(|_| io::Error::other("SS2022 UDP lock poisoned"))?.accept_at(packet, account.key, Some(account.user), remote, now)?)
    }
    pub fn reply_datagram(&self, token: &super::udp_session::ReplyToken, source: crate::common::net::Destination, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>)> {
        Ok(self.datagrams.lock().map_err(|_| io::Error::other("SS2022 UDP lock poisoned"))?.reply(token, source, payload)?)
    }
}
