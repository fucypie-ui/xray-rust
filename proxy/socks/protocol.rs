use crate::common::errors::{Error, Result};
use crate::common::net::{Address, Destination, Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS4_VERSION: u8 = 0x04;

pub const CMD_TCP_CONNECT: u8 = 0x01;
pub const CMD_TCP_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const CMD_TOR_RESOLVE: u8 = 0xF0;
pub const CMD_TOR_RESOLVE_PTR: u8 = 0xF1;

pub const SOCKS4_REQUEST_GRANTED: u8 = 90;
pub const SOCKS4_REQUEST_REJECTED: u8 = 91;

pub const AUTH_NO_AUTH: u8 = 0x00;
pub const AUTH_PASSWORD: u8 = 0x02;
pub const AUTH_NO_MATCH: u8 = 0xFF;

pub const STATUS_SUCCESS: u8 = 0x00;
pub const STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;

pub struct SocksProtocol;

impl SocksProtocol {
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &Destination,
    ) -> Result<()> {
        Self::client_handshake_with_auth(stream, target, None).await
    }

    /// Establish a TCP tunnel, optionally authenticating with a SOCKS account.
    pub async fn client_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &Destination,
        account: Option<(&str, &str)>,
    ) -> Result<()> {
        // BoxStream has no datagram boundaries or associated TCP lifetime. Do not
        // silently send CONNECT for a UDP destination.
        if target.network != Network::Tcp {
            return Err(Error::Unsupported(
                "SOCKS UDP outbound requires a datagram transport".into(),
            ));
        }
        let mut req = vec![SOCKS5_VERSION, CMD_TCP_CONNECT, 0x00];
        write_address_port(&mut req, target)?;
        if let Some((username, password)) = account
            && (username.len() > 255 || password.len() > 255)
        {
            return Err(Error::Protocol(
                "SOCKS5 username and password must fit in one-byte lengths".into(),
            ));
        }
        let auth = if account.is_some() { AUTH_PASSWORD } else { AUTH_NO_AUTH };
        stream.write_all(&[SOCKS5_VERSION, 0x01, auth]).await?;
        stream.flush().await?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION || resp[1] != auth {
            return Err(Error::Protocol(format!("SOCKS5 auth negotiation failed: {:?}", resp)));
        }
        if let Some((username, password)) = account {
            let mut credentials = vec![0x01, username.len() as u8];
            credentials.extend_from_slice(username.as_bytes());
            credentials.push(password.len() as u8);
            credentials.extend_from_slice(password.as_bytes());
            stream.write_all(&credentials).await?;
            stream.flush().await?;
            stream.read_exact(&mut resp).await?;
            // Go ClientHandshake checks STATUS, not the subnegotiation version.
            if resp[1] != STATUS_SUCCESS {
                return Err(Error::Protocol(format!(
                    "SOCKS5 server rejects account: 0x{:02X}", resp[1]
                )));
            }
        }
        stream.write_all(&req).await?;
        stream.flush().await?;
        let mut reply_hdr = [0u8; 3];
        stream.read_exact(&mut reply_hdr).await?;
        if reply_hdr[1] != STATUS_SUCCESS {
            return Err(Error::Protocol(format!("SOCKS5 server replied error status: 0x{:02X}", reply_hdr[1])));
        }
        // Consume exactly BND.ADDR and BND.PORT, leaving application data intact.
        read_address_port(stream).await?;
        Ok(())
    }
}

pub(super) async fn read_address_port<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Destination> {
    let address = match reader.read_u8().await? {
        0x01 => {
            let mut ip = [0; 4];
            reader.read_exact(&mut ip).await?;
            Address::Ipv4(Ipv4Addr::from(ip))
        }
        0x04 => {
            let mut ip = [0; 16];
            reader.read_exact(&mut ip).await?;
            Address::ipv6(Ipv6Addr::from(ip))
        }
        0x03 => {
            let len = reader.read_u8().await? as usize;
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).await?;
            let domain = String::from_utf8(bytes)
                .map_err(|_| Error::Protocol("Invalid SOCKS5 domain string".into()))?;
            parse_domain(domain)?
        }
        atyp => return Err(Error::Protocol(format!("Unsupported SOCKS5 ATYP: {}", atyp))),
    };
    Ok(Destination::tcp(address, reader.read_u16().await?))
}

fn parse_domain(domain: String) -> Result<Address> {
    // common/protocol/address.go recognizes IP literals only with these prefixes.
    if domain.starts_with('[') || domain.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        let literal = domain.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(&domain);
        if let Ok(ip) = literal.trim().parse::<IpAddr>() {
            return Ok(Address::from(ip));
        }
    }
    if domain.is_empty() || !domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')) {
        return Err(Error::Protocol("Invalid SOCKS5 domain name".into()));
    }
    Ok(Address::Domain(domain))
}

fn write_address_port(output: &mut Vec<u8>, target: &Destination) -> Result<()> {
    match &target.address {
        Address::Ipv4(ip) => {
            output.push(0x01);
            output.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            output.push(0x04);
            output.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            let len = u8::try_from(domain.len())
                .map_err(|_| Error::Protocol("SOCKS5 domain exceeds 255 bytes".into()))?;
            output.extend_from_slice(&[0x03, len]);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

/// Go's ReadUntilNull permits at most buf.Size bytes, including the terminator.
pub(super) async fn read_until_null<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    for _ in 0..8192 {
        let byte = reader.read_u8().await?;
        if byte == 0 {
            return Ok(value);
        }
        value.push(byte);
    }
    Err(Error::Protocol("SOCKS4 null-terminated field exceeds buffer size".into()))
}

/// Keep credentials as bytes: Go strings need not be valid UTF-8.
pub(super) async fn read_username_password<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut header = [0; 2];
    reader.read_exact(&mut header).await?;
    let mut username = vec![0; header[1] as usize];
    reader.read_exact(&mut username).await?;
    let mut password = vec![0; reader.read_u8().await? as usize];
    reader.read_exact(&mut password).await?;
    Ok((username, password))
}
