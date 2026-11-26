use crate::common::errors::Error;

pub fn unsupported_api(operation: &str, server: &str) -> Error {
    Error::Unsupported(format!("API {operation} at {server}: gRPC API transport is not implemented"))
}

pub struct ApiClientConfig {
    pub server: String,
    pub timeout: u64,
}

impl ApiClientConfig {
    pub fn unsupported(&self, operation: &str) -> crate::common::errors::Result<String> {
        Err(unsupported_api(operation, &self.server))
    }

    pub fn parse(args: &[&str]) -> Self {
        let mut config = Self { server: "127.0.0.1:8080".into(), timeout: 3 };
        let mut args = args.iter().copied();
        while let Some(arg) = args.next() {
            let (flag, inline) = arg.split_once('=').map_or((arg, None), |(flag, value)| (flag, Some(value)));
            match flag {
                "-s" | "--s" | "-server" | "--server" => {
                    if let Some(value) = inline.or_else(|| args.next()) { config.server = value.into(); }
                }
                "-t" | "--t" | "-timeout" | "--timeout" => {
                    if let Some(value) = inline.or_else(|| args.next()).and_then(|value| value.parse().ok()) { config.timeout = value; }
                }
                _ => {}
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_api_defaults_match_go() {
        let config = ApiClientConfig::parse(&[]);
        assert_eq!(config.server, "127.0.0.1:8080");
        assert_eq!(config.timeout, 3);
    }

    #[test]
    fn server_and_timeout_aliases_are_used_in_unsupported_errors() {
        for args in [vec!["-s=localhost:9000", "-t=7"], vec!["--server", "localhost:9000", "--timeout", "7"], vec!["-server=localhost:9000", "-timeout=7"]] {
            let config = ApiClientConfig::parse(&args);
            assert_eq!(config.server, "localhost:9000");
            assert_eq!(config.timeout, 7);
            let error = config.unsupported("query-stats").unwrap_err().to_string();
            assert!(error.contains("localhost:9000"));
            assert!(error.contains("not implemented"));
        }
    }
}
