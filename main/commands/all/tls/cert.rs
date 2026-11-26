use crate::common::errors::{Error, Result};
use crate::main::commands::base::command::Command;
use clap::{Args, Parser};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Args, Debug)]
pub struct CertOptions {
    #[arg(long, value_parser = nonempty_domain)]
    pub domain: Vec<String>,
    #[arg(long, default_value = "Xray Inc")]
    pub name: String,
    #[arg(long, default_value = "Xray Inc")]
    pub org: String,
    #[arg(long, default_value_t = false, default_missing_value = "true", num_args = 0..=1, require_equals = true, action = clap::ArgAction::Set)]
    pub ca: bool,
    #[arg(long, default_value_t = true, default_missing_value = "true", num_args = 0..=1, require_equals = true, action = clap::ArgAction::Set)]
    pub json: bool,
    #[arg(long, value_name = "PREFIX")]
    pub file: Option<PathBuf>,
    #[arg(long, default_value = "2160h", value_parser = parse_duration)]
    pub expire: Duration,
}

#[derive(Parser)]
struct CertCli {
    #[command(flatten)]
    options: CertOptions,
}

fn nonempty_domain(value: &str) -> std::result::Result<String, String> {
    if value.is_empty() { Err("empty domain".into()) } else { Ok(value.into()) }
}

/// Positive Go-style durations, including compound units and fractions. The
/// 100-year bound prevents timestamp overflow while exceeding normal lifetimes.
pub fn parse_duration(value: &str) -> std::result::Result<Duration, String> {
    let mut rest = value.strip_prefix('+').unwrap_or(value);
    let mut nanos = 0_u64;
    if rest.is_empty() { return Err(format!("invalid duration: {value}")); }
    while !rest.is_empty() {
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
        if end == 0 { return Err(format!("invalid duration: {value}")); }
        let number = &rest[..end];
        rest = &rest[end..];
        let units = [("ns", 1_u64), ("us", 1_000), ("µs", 1_000), ("μs", 1_000), ("ms", 1_000_000), ("s", 1_000_000_000), ("m", 60_000_000_000), ("h", 3_600_000_000_000)];
        let Some((unit, scale)) = units.iter().find(|(unit, _)| rest.starts_with(*unit)) else { return Err(format!("duration requires ns, us, ms, s, m, or h units: {value}")); };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if (whole.is_empty() && fraction.is_empty()) || !fraction.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!("invalid duration: {value}"));
        }
        let whole = if whole.is_empty() { 0 } else { whole.parse::<u64>().map_err(|_| format!("duration overflow: {value}"))? };
        // Multiplication from the least significant decimal digit preserves
        // nanosecond precision without floats or a limit on fraction length.
        let fraction = fraction.bytes().rev().fold(0_u64, |carry, digit| (u64::from(digit - b'0') * scale + carry) / 10);
        nanos = whole.checked_mul(*scale).and_then(|n| n.checked_add(fraction))
            .and_then(|n| nanos.checked_add(n)).ok_or_else(|| format!("duration overflow: {value}"))?;
        rest = &rest[unit.len()..];
    }
    if nanos == 0 || nanos > 100 * 366 * 24 * 3600 * 1_000_000_000 {
        return Err("duration must be positive and at most 100 years".into());
    }
    Ok(Duration::from_nanos(nanos))
}

pub fn generate_certificate(options: &CertOptions) -> Result<(String, String)> {
    let mut params = CertificateParams::new(options.domain.clone())
        .map_err(|e| Error::Config(format!("Invalid certificate domain: {e}")))?;
    params.distinguished_name.push(DnType::CommonName, options.name.clone());
    params.distinguished_name.push(DnType::OrganizationName, options.org.clone());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Config(format!("Invalid system time: {e}")))?;
    let now = rcgen::date_time_ymd(1970, 1, 1) + now;
    params.not_before = now - Duration::from_secs(3600);
    params.not_after = now + options.expire;
    params.key_usages = vec![KeyUsagePurpose::KeyEncipherment, KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if options.ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    }
    let key = KeyPair::generate().map_err(|e| Error::Config(format!("Failed to generate private key: {e}")))?;
    let cert = params.self_signed(&key).map_err(|e| Error::Config(format!("Failed to generate certificate: {e}")))?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub fn execute_cert(options: &CertOptions) -> Result<String> {
    let (cert, key) = generate_certificate(options)?;
    if let Some(prefix) = &options.file {
        // Append suffixes, rather than replacing a suffix already in the prefix.
        for (suffix, contents) in [(".crt", &cert), (".key", &key)] {
            let mut path = prefix.as_os_str().to_os_string();
            path.push(suffix);
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.mode(0o600);
            }
            use std::io::Write;
            let mut file = open.open(&path).map_err(|e| Error::Config(format!("Failed to save {}: {e}", PathBuf::from(&path).display())))?;
            file.write_all(contents.as_bytes()).map_err(|e| Error::Config(format!("Failed to save {}: {e}", PathBuf::from(&path).display())))?;
        }
    }
    if options.json {
        serde_json::to_string_pretty(&serde_json::json!({
            "certificate": cert.lines().collect::<Vec<_>>(),
            "key": key.lines().collect::<Vec<_>>(),
        })).map_err(|e| Error::Config(format!("Failed to encode certificate: {e}")))
    } else {
        Ok(String::new())
    }
}

pub fn generate_self_signed_cert(domain: &str) -> Result<(String, String)> {
    let subject_alt_names = vec![domain.to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| Error::Config(format!("Failed to generate self-signed cert: {}", e)))?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    Ok((cert_pem, key_pem))
}

pub fn cmd_cert() -> Command {
    Command::new("cert", "xray tls cert [--domain=example.com] [--ca] [--expire=2160h]", "Generate self-signed TLS certificates")
    .with_run(|args| {
        let argv = std::iter::once("cert").chain(args.iter().copied()).map(std::ffi::OsString::from);
        let cli = CertCli::try_parse_from(crate::main::cli::normalize_go_flags(argv))
            .map_err(|e| Error::Config(e.to_string()))?;
        execute_cert(&cli.options)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::pem::PemObject;

    #[test]
    fn duration_units_and_invalid_values() {
        assert_eq!(parse_duration("1h30m0.5s").unwrap(), Duration::from_millis(5_400_500));
        assert_eq!(parse_duration("+2µs3ns").unwrap(), Duration::from_nanos(2003));
        assert_eq!(parse_duration(".5s").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("1.s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("1.000000001s").unwrap(), Duration::from_nanos(1_000_000_001));
        assert_eq!(parse_duration("0.000000000999999999999999999999s1ns").unwrap(), Duration::from_nanos(1));
        for value in ["", "+", "0", "0s", "-1h", "2d", "1", ".s", "1..2s", "NaNs", "999999999999999999999h"] {
            assert!(parse_duration(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn generated_json_contains_matching_certificate_and_key() {
        let output = cmd_cert().execute(&["-domain=example.com", "--domain=www.example.com", "--name=Example", "--org=Example Inc", "--ca", "--expire=240h"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        let pem = |field: &str| json[field].as_array().unwrap().iter().map(|line| line.as_str().unwrap()).collect::<Vec<_>>().join("\n");
        let cert = rustls_pki_types::CertificateDer::from_pem_slice(pem("certificate").as_bytes()).unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(pem("key").as_bytes()).unwrap();
        // rustls validates that the generated key matches the certificate.
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
    }

    #[test]
    fn files_are_written_with_appended_suffixes_and_json_can_be_disabled() {
        let directory = std::env::temp_dir().join(format!("xray-cli-cert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let prefix = directory.join("example.pem");
        let output = cmd_cert().execute(&["--domain=localhost", "--json=false", "--file", prefix.to_str().unwrap()]).unwrap();
        assert!(output.is_empty());
        assert!(std::fs::read_to_string(directory.join("example.pem.crt")).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(std::fs::read_to_string(directory.join("example.pem.key")).unwrap().contains("BEGIN PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(directory.join("example.pem.key")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_file(directory.join("example.pem.crt")).unwrap();
        std::fs::remove_file(directory.join("example.pem.key")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn errors_are_not_reported_as_success() {
        assert!(cmd_cert().execute(&["--domain="]).is_err());
        assert!(cmd_cert().execute(&["--unknown"]).is_err());
        assert!(cmd_cert().execute(&["--expire=-1h"]).is_err());
        let prefix = std::env::temp_dir().join(format!("xray-missing-{}/cert", uuid::Uuid::new_v4()));
        assert!(cmd_cert().execute(&["--file", prefix.to_str().unwrap()]).is_err());
    }
}
