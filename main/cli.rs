use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

use super::commands::all::tls::{cert::CertOptions, ping::PingOptions};
use super::commands::all::{mlkem768::Mlkem768Options, x25519::X25519Options};

#[derive(Parser, Debug)]
#[command(name = "xray", version, about = "Xray Core in Rust")]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    #[arg(long, default_value_t = false, default_missing_value = "true", num_args = 0..=1, require_equals = true, action = clap::ArgAction::Set)]
    pub test: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Run {
        #[arg(short, long, default_value = "config.json", value_name = "FILE")]
        config: PathBuf,
        #[arg(long, default_value_t = false, default_missing_value = "true", num_args = 0..=1, require_equals = true, action = clap::ArgAction::Set)]
        test: bool,
    },
    Test {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    Version,
    Uuid {
        #[arg(short = 'i', long = "i", default_value = "", allow_hyphen_values = true)]
        input: String,
    },
    #[command(args_override_self = true)]
    X25519(X25519Options),
    #[command(args_override_self = true)]
    Mlkem768(Mlkem768Options),
    Tls {
        #[command(subcommand)]
        subcmd: TlsCommands,
    },
    /// API transport is not implemented; requests return an explicit error.
    Api {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        server: String,
        #[arg(short = 't', long, default_value_t = 3)]
        timeout: u64,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TlsCommands {
    Ping(PingOptions),
    Cert(CertOptions),
}

/// Go flags accept both one and two leading dashes. Normalize only known
/// long flags, preserving values (including non-UTF-8 file names) and `--`.
pub fn normalize_go_flags(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut literal = false;
    let mut needs_value = false;
    args.into_iter()
        .enumerate()
        .map(|(index, arg)| {
            if index == 0 || literal {
                return arg;
            }
            if needs_value {
                needs_value = false;
                return arg;
            }
            if arg == "--" {
                literal = true;
                return arg;
            }
            let Some(text) = arg.to_str() else { return arg };
            let name = text.trim_start_matches('-').split('=').next().unwrap_or("");
            let takes_value = matches!(name, "config" | "c" | "i" | "domain" | "name" | "org" | "file" | "expire" | "ip" | "timeout" | "server" | "s" | "t");
            needs_value = text.starts_with('-') && takes_value && !text.contains('=');
            if text.starts_with('-') && !text.starts_with("--")
                && matches!(name, "config" | "domain" | "name" | "org" | "file" | "expire" | "ip" | "timeout" | "server" | "ca" | "json" | "test" | "std-encoding")
            {
                OsString::from(format!("-{text}"))
            } else {
                arg
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(normalize_go_flags(args.iter().copied().map(OsString::from)))
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn key_commands_reach_the_shared_options_with_go_flags() {
        for flag in ["-std-encoding", "--std-encoding"] {
            let cli = parse(&["xray", "x25519", "-i", "old", flag, "--i", "-new"]).unwrap();
            let Some(Commands::X25519(options)) = cli.command else { panic!("expected x25519") };
            assert_eq!(options.input, "-new");
            assert!(options.std_encoding);
        }
        let cli = parse(&["xray", "mlkem768", "-i=old", "--i", "-seed"]).unwrap();
        let Some(Commands::Mlkem768(options)) = cli.command else { panic!("expected mlkem768") };
        assert_eq!(options.input, "-seed");
        assert!(parse(&["xray", "x25519", "--std-encoding=maybe"]).is_err());
        assert!(parse(&["xray", "mlkem768", "--i"]).is_err());
    }

    #[test]
    fn go_certificate_flags_and_repeated_domains() {
        let cli = parse(&["xray", "tls", "cert", "-domain=example.com", "-domain", "www.example.com", "-name", "Example", "-ca", "-json=false", "-expire=240h"]).unwrap();
        let Some(Commands::Tls { subcmd: TlsCommands::Cert(options) }) = cli.command else { panic!("expected cert") };
        assert_eq!(options.domain, ["example.com", "www.example.com"]);
        assert_eq!(options.name, "Example");
        assert!(options.ca);
        assert!(!options.json);
        assert_eq!(options.expire.as_secs(), 240 * 3600);
    }

    #[test]
    fn go_uuid_input_and_test_mode() {
        assert!(matches!(parse(&["xray", "uuid", "-i", "example"]).unwrap().command, Some(Commands::Uuid { input }) if input == "example"));
        assert!(matches!(parse(&["xray", "run", "-config=custom.json", "-test"]).unwrap().command, Some(Commands::Run { config, test: true }) if config == PathBuf::from("custom.json")));
        assert!(parse(&["xray", "tls", "ping"]).is_err());
        assert!(parse(&["xray", "tls", "ping", "--ip=not-an-ip", "example.com"]).is_err());
        assert!(parse(&["xray", "-test", "-c", "custom.json"]).unwrap().test);
        assert!(matches!(parse(&["xray", "run", "-test=false"]).unwrap().command, Some(Commands::Run { test: false, .. })));
    }

    #[test]
    fn flag_values_and_literal_arguments_are_preserved() {
        let args = ["xray", "tls", "cert", "-name", "-domain", "--", "-domain"];
        let normalized = normalize_go_flags(args.iter().copied().map(OsString::from));
        assert_eq!(normalized, ["xray", "tls", "cert", "--name", "-domain", "--", "-domain"].map(OsString::from));
    }

    #[test]
    fn uuid_input_can_start_with_a_hyphen() {
        for input in ["-example", "-domain", "--test"] {
            let cli = parse(&["xray", "uuid", "-i", input]).unwrap();
            assert!(matches!(cli.command, Some(Commands::Uuid { input: parsed }) if parsed == input));
        }
        assert!(parse(&["xray", "uuid", "-i"]).is_err());
    }

    #[test]
    fn certificate_defaults_and_boolean_assignments() {
        let cli = parse(&["xray", "tls", "cert", "-ca=false"]).unwrap();
        let Some(Commands::Tls { subcmd: TlsCommands::Cert(options) }) = cli.command else { panic!("expected cert") };
        assert!(options.domain.is_empty());
        assert_eq!(options.name, "Xray Inc");
        assert_eq!(options.org, "Xray Inc");
        assert!(!options.ca);
        assert!(options.json);
        assert_eq!(options.expire.as_secs(), 90 * 24 * 3600);
        assert!(parse(&["xray", "tls", "cert", "--json=maybe"]).is_err());
    }

    #[test]
    fn ip_override_and_explicit_port_reach_the_ping_options() {
        let cli = parse(&["xray", "tls", "ping", "-ip", "::1", "--timeout=500ms", "example.com:8443"]).unwrap();
        let Some(Commands::Tls { subcmd: TlsCommands::Ping(options) }) = cli.command else { panic!("expected ping") };
        assert_eq!(options.domain, "example.com:8443");
        assert_eq!(options.ip, Some("::1".parse().unwrap()));
        assert_eq!(options.timeout, std::time::Duration::from_millis(500));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_configuration_paths_are_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(vec![b'c', 0xff, b'.', b'j', b's', b'o', b'n']);
        let cli = Cli::try_parse_from(normalize_go_flags([OsString::from("xray"), OsString::from("-config"), path.clone()])).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from(path)));
    }
}
