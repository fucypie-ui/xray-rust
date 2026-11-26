pub const PROTOCOL_NAME: &str = "socks";
pub const VERSION_5: u8 = 0x05;
pub const VERSION_4: u8 = 0x04;

use crate::common::errors::{Error, Result};
use crate::common::net::{Address, BoxStream, Destination};
use crate::common::protocol::{SessionContext, User};
use crate::features::inbound::{InboundHandler, InboundResult};
use super::protocol::{
    AUTH_NO_AUTH, AUTH_NO_MATCH, AUTH_PASSWORD, CMD_TCP_CONNECT, CMD_TOR_RESOLVE,
    CMD_TOR_RESOLVE_PTR, SOCKS4_REQUEST_GRANTED, SOCKS4_REQUEST_REJECTED,
    STATUS_COMMAND_NOT_SUPPORTED, STATUS_SUCCESS, read_address_port, read_until_null,
    read_username_password,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Server {
    tag: String,
    accounts: Option<HashMap<String, String>>,
}

impl Server {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into(), accounts: None }
    }

    /// Require password authentication, even when the account map is empty.
    pub fn with_auth(tag: impl Into<String>, accounts: HashMap<String, String>) -> Self {
        Self { tag: tag.into(), accounts: Some(accounts) }
    }

    async fn handshake4(&self, stream: &mut BoxStream, command: u8) -> Result<Destination> {
        if self.accounts.is_some() {
            stream.write_all(&[0, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]).await?;
            stream.flush().await?;
            return Err(Error::Protocol("SOCKS4 is not allowed when auth is required".into()));
        }
        let port = stream.read_u16().await?;
        let mut ip = [0; 4];
        stream.read_exact(&mut ip).await?;
        // USERID is ignored, including bytes that are not UTF-8.
        read_until_null(stream).await?;
        let address = if ip[0] == 0 {
            // Match Go's SOCKS4a detection (the first octet, not just 0.0.0.x).
            let domain = String::from_utf8(read_until_null(stream).await?)
                .map_err(|_| Error::Protocol("Invalid SOCKS4a domain string".into()))?;
            crate::common::net::parse_address(&domain)
        } else {
            Address::Ipv4(Ipv4Addr::from(ip))
        };
        let status = if command == CMD_TCP_CONNECT { SOCKS4_REQUEST_GRANTED } else { SOCKS4_REQUEST_REJECTED };
        stream.write_all(&[0, status, 0, 0, 0, 0, 0, 0]).await?;
        stream.flush().await?;
        if command != CMD_TCP_CONNECT {
            return Err(Error::Protocol(format!("Unsupported SOCKS4 command: {}", command)));
        }
        Ok(Destination::tcp(address, port))
    }

    async fn handshake5(&self, stream: &mut BoxStream, method_count: u8) -> Result<(Destination, Option<User>)> {
        let mut methods = vec![0; method_count as usize];
        stream.read_exact(&mut methods).await?;
        let expected = if self.accounts.is_some() { AUTH_PASSWORD } else { AUTH_NO_AUTH };
        if !methods.contains(&expected) {
            stream.write_all(&[VERSION_5, AUTH_NO_MATCH]).await?;
            stream.flush().await?;
            return Err(Error::Protocol("No matching SOCKS5 auth method".into()));
        }
        stream.write_all(&[VERSION_5, expected]).await?;
        stream.flush().await?;
        let mut user = None;
        if let Some(accounts) = &self.accounts {
            let (username, password) = read_username_password(stream).await?;
            let account = accounts.iter().find(|(name, secret)| {
                name.as_bytes() == username.as_slice() && secret.as_bytes() == password.as_slice()
            });
            let Some((name, _)) = account else {
                stream.write_all(&[0x01, AUTH_NO_MATCH]).await?;
                stream.flush().await?;
                return Err(Error::Protocol("Invalid SOCKS5 username or password".into()));
            };
            stream.write_all(&[0x01, STATUS_SUCCESS]).await?;
            stream.flush().await?;
            if !name.is_empty() {
                user = Some(User::with_email(uuid::Uuid::nil(), name.clone(), 0));
            }
        }
        let mut header = [0; 3];
        stream.read_exact(&mut header).await?;
        // Like Go, Tor RESOLVE commands currently use the TCP CONNECT path.
        if !matches!(header[1], CMD_TCP_CONNECT | CMD_TOR_RESOLVE | CMD_TOR_RESOLVE_PTR) {
            stream.write_all(&[VERSION_5, STATUS_COMMAND_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            stream.flush().await?;
            return Err(Error::Protocol(format!("Unsupported SOCKS5 command: {}", header[1])));
        }
        let destination = read_address_port(stream).await?;
        stream.write_all(&[VERSION_5, STATUS_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        stream.flush().await?;
        Ok((destination, user))
    }
}

#[async_trait]
impl InboundHandler for Server {
    fn tag(&self) -> &str { &self.tag }
    async fn handle_connection(&self, mut stream: BoxStream, remote_addr: SocketAddr) -> Result<InboundResult> {
        let mut header = [0; 2];
        stream.read_exact(&mut header).await?;
        let (destination, user) = match header[0] {
            VERSION_4 => (self.handshake4(&mut stream, header[1]).await?, None),
            VERSION_5 => self.handshake5(&mut stream, header[1]).await?,
            version => return Err(Error::Protocol(format!("Unsupported SOCKS version: {}", version))),
        };
        let mut session = SessionContext::new(&self.tag, destination);
        session.source = Some(remote_addr);
        session.user = user;
        Ok(InboundResult { stream, session })
    }
}
