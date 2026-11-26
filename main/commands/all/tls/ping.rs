use crate::main::commands::base::command::Command;
use crate::common::errors::{Error, Result};
use crate::transport::internet::tls::NoCertificateVerification;
use clap::{Args, Parser};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Args, Debug)]
pub struct PingOptions {
    #[arg(value_name = "DOMAIN")]
    pub domain: String,
    #[arg(long)]
    pub ip: Option<IpAddr>,
    #[arg(long, default_value = "10s", value_parser = super::cert::parse_duration)]
    pub timeout: Duration,
}

#[derive(Parser)]
struct PingCli {
    #[command(flatten)]
    options: PingOptions,
}

fn target(domain: &str) -> Result<(String, u16)> {
    if let Ok(address) = domain.parse::<SocketAddr>() {
        if address.port() == 0 { return Err(Error::Config("TLS target port must be nonzero".into())); }
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return Ok((ip.to_string(), 443));
    }
    if let Some((host, port)) = domain.rsplit_once(':') {
        let port = port.parse::<u16>().map_err(|_| Error::Config(format!("Invalid TLS target port: {port}")))?;
        if host.is_empty() || host.contains(':') || port == 0 {
            return Err(Error::Config(format!("Invalid TLS target: {domain}")));
        }
        return Ok((host.to_owned(), port));
    }
    if domain.is_empty() || domain.chars().any(|c| matches!(c, '/' | '[' | ']')) {
        return Err(Error::Config(format!("Invalid TLS target: {domain}")));
    }
    Ok((domain.to_owned(), 443))
}

async fn probe(address: SocketAddr, name: ServerName<'static>, config: ClientConfig, timeout: Duration) -> Result<String> {
    let stream = tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect(address).await?;
        TlsConnector::from(Arc::new(config)).connect(name, tcp).await
    }).await.map_err(|_| Error::Protocol(format!("TLS connection to {address} timed out")))??;
    let connection = stream.get_ref().1;
    let version = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "unknown",
    };
    let certificates = connection.peer_certificates().unwrap_or_default();
    let total: usize = certificates.iter().map(|cert| cert.len()).sum();
    let alpn = connection.alpn_protocol().map(String::from_utf8_lossy).unwrap_or_else(|| "none".into());
    Ok(format!("Handshake succeeded\nTLS Version: {version}\nALPN: {alpn}\nCertificate chain's total length: {total} (certs count: {})", certificates.len()))
}

async fn ping_with_roots(options: &PingOptions, roots: RootCertStore) -> Result<String> {
    let (domain, port) = target(&options.domain)?;
    let name = ServerName::try_from(domain.clone()).map_err(|e| Error::Config(format!("Invalid TLS server name: {e}")))?;
    let address = if let Some(ip) = options.ip {
        SocketAddr::new(ip, port)
    } else {
        tokio::time::timeout(options.timeout, tokio::net::lookup_host((domain.as_str(), port)))
            .await.map_err(|_| Error::Protocol("TLS target DNS lookup timed out".into()))??
            .next().ok_or_else(|| Error::Protocol(format!("No IP addresses found for {domain}")))?
    };
    let builder = || ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().map_err(|e| Error::Config(format!("TLS configuration failed: {e}")));
    // Like Go, the first probe has no SNI and does not authenticate the peer.
    // The second probe uses the requested host name and validates its chain.
    let mut anonymous = builder()?.dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    anonymous.enable_sni = false;
    anonymous.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut verified = builder()?.with_root_certificates(roots).with_no_client_auth();
    verified.alpn_protocols = anonymous.alpn_protocols.clone();
    let first = probe(address, name.clone(), anonymous, options.timeout).await;
    let second = probe(address, name, verified, options.timeout).await;
    let first = first.unwrap_or_else(|error| format!("Handshake failure: {error}"));
    let header = format!("TLS ping: {}\nUsing IP: {address}\n-------------------\nPinging without SNI (unverified)\n{first}\n-------------------\nPinging with SNI (verified)", options.domain);
    match second {
        Ok(second) => Ok(format!("{header}\n{second}\n-------------------\nTLS ping finished")),
        Err(error) => Err(Error::Protocol(format!("{header}\nHandshake failure: {error}"))),
    }
}

pub async fn execute_ping(options: &PingOptions) -> Result<String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ping_with_roots(options, roots).await
}

pub fn cmd_ping() -> Command {
    Command::new("ping", "xray tls ping [-ip IP] <domain[:port]>", "Probe remote server TLS handshake and certificates")
    .with_run(|args| {
        let argv = std::iter::once("ping").chain(args.iter().copied()).map(std::ffi::OsString::from);
        let cli = PingCli::try_parse_from(crate::main::cli::normalize_go_flags(argv))
            .map_err(|e| Error::Config(e.to_string()))?;
        // Command callbacks are synchronous and may be called inside an
        // existing Tokio runtime. A dedicated thread avoids nested block_on.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(execute_ping(&cli.options))
        }).join().map_err(|_| Error::Other("TLS probe worker panicked".into()))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use rustls_pki_types::pem::PemObject;

    #[test]
    fn parses_domains_ports_and_ipv6() {
        assert_eq!(target("example.com").unwrap(), ("example.com".into(), 443));
        assert_eq!(target("example.com:8443").unwrap(), ("example.com".into(), 8443));
        assert_eq!(target("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert_eq!(target("::1").unwrap(), ("::1".into(), 443));
        for value in ["", "https://example.com", "example.com:abc", "example.com:65536", "example.com:0", "127.0.0.1:0", "[::1]:0"] {
            assert!(target(value).is_err(), "accepted {value}");
        }
        assert!(cmd_ping().execute(&[]).is_err());
        assert!(cmd_ping().execute(&["--ip=invalid", "example.com"]).is_err());
    }

    fn local_tls() -> (TlsAcceptor, RootCertStore) {
        let options = super::super::cert::CertOptions {
            domain: vec!["localhost".into()], name: "Local TLS test".into(), org: "Xray test".into(),
            ca: false, json: true, file: None, expire: Duration::from_secs(3600),
        };
        let (cert, key) = super::super::cert::generate_certificate(&options).unwrap();
        let cert = rustls_pki_types::CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key).unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        (TlsAcceptor::from(Arc::new(config)), roots)
    }

    #[tokio::test]
    async fn performs_two_real_handshakes_and_preserves_sni_with_ip_override() {
        let (acceptor, roots) = local_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut names = Vec::new();
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = acceptor.accept(tcp).await.unwrap();
                names.push(tls.get_ref().1.server_name().map(str::to_owned));
            }
            names
        });
        let options = PingOptions { domain: format!("localhost:{port}"), ip: Some("127.0.0.1".parse().unwrap()), timeout: Duration::from_secs(5) };
        let output = ping_with_roots(&options, roots).await.unwrap();
        assert_eq!(output.matches("Handshake succeeded").count(), 2);
        assert!(output.contains("TLS Version: TLS 1."));
        assert!(output.contains("ALPN: h2"));
        let names = tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        assert_eq!(names, vec![None, Some("localhost".into())]);
    }

    #[tokio::test]
    async fn rejects_untrusted_certificate_instead_of_claiming_success() {
        let (acceptor, _) = local_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(tcp).await;
            }
        });
        let options = PingOptions { domain: format!("localhost:{port}"), ip: Some("127.0.0.1".parse().unwrap()), timeout: Duration::from_secs(5) };
        let error = ping_with_roots(&options, RootCertStore::empty()).await.unwrap_err().to_string();
        assert!(error.contains("Handshake failure"));
        assert!(!error.contains("TLS ping finished"));
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_hostname_mismatch_even_for_a_trusted_certificate() {
        let (acceptor, roots) = local_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(tcp).await;
            }
        });
        let options = PingOptions { domain: format!("wrong.example:{port}"), ip: Some("127.0.0.1".parse().unwrap()), timeout: Duration::from_secs(5) };
        let error = ping_with_roots(&options, roots).await.unwrap_err().to_string();
        assert!(error.contains("Handshake failure"));
        assert!(!error.contains("TLS ping finished"));
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn refuses_plain_tcp_and_times_out_stalled_peers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 { connections.push(listener.accept().await.unwrap().0); }
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(connections);
        });
        let options = PingOptions { domain: address.to_string(), ip: None, timeout: Duration::from_millis(25) };
        let error = execute_ping(&options).await.unwrap_err().to_string();
        assert!(error.contains("timed out"));
        tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    }
}
