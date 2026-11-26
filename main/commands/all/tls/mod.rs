pub mod cert;
pub mod ech;
pub mod hash;
pub mod ping;
pub mod tls;

pub use tls::cmd_tls;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tls_commands() {
        let cmd = cmd_tls();
        assert_eq!(cmd.name, "tls");
        assert_eq!(cmd.subcommands.len(), 4);
        let cert_res = cmd.execute(&["cert", "--domain=test.local"]).unwrap();
        assert!(cert_res.contains("BEGIN CERTIFICATE"));
        assert!(cert_res.contains("BEGIN PRIVATE KEY"));
        let ech_res = cmd.execute(&["ech"]).unwrap();
        assert!(ech_res.contains("ECH Private Key:"));
        let hash_res = cmd.execute(&["hash", "dummy-cert-data"]).unwrap();
        assert!(hash_res.contains("Certificate hash:"));
        // Successful TLS probing is covered by ping's local-server tests.
        // The command group must also propagate input errors without network I/O.
        assert!(cmd.execute(&["ping"]).is_err());
        assert!(cmd.execute(&["ping", "--ip=not-an-ip", "example.com"]).is_err());
    }
}
