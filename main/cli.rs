use clap::{Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::fmt;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyCommandKind {
    X25519,
    Mlkem768,
}

impl KeyCommandKind {
    fn from_name(name: &OsStr) -> Option<Self> {
        if name == "x25519" { Some(Self::X25519) }
        else if name == "mlkem768" { Some(Self::Mlkem768) }
        else { None }
    }

    fn usage(self) -> &'static str {
        // These are Command.Usage(), not the longer 'xray help' pages.
        match self {
            Self::X25519 => "usage: xray x25519 [-i \"private key (base64.RawURLEncoding)\"] [--std-encoding]\nRun 'xray help x25519' for details.\n",
            Self::Mlkem768 => "usage: xray mlkem768 [-i \"seed (base64.RawURLEncoding)\"]\nRun 'xray help mlkem768' for details.\n",
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct KeyCommandOptions {
    pub input: String,
    pub std_encoding: bool,
}

#[derive(Debug)]
pub struct KeyArgumentError {
    message: String,
}

impl KeyArgumentError {
    fn new(command: KeyCommandKind, diagnostic: Option<String>) -> Self {
        let message = match diagnostic {
            Some(diagnostic) => format!("{diagnostic}\n{}", command.usage()),
            None => command.usage().into(),
        };
        Self { message }
    }
}

impl fmt::Display for KeyArgumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for KeyArgumentError {}

pub(crate) fn parse_go_bool(input: &str) -> std::result::Result<bool, String> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean value: {input}")),
    }
}

/// Parse only the flags owned by Go's two key utilities. Go accepts a flag
/// value separately or after '=', never as an attached short-option value.
/// Its flag parser stops before the first positional argument or after '--';
/// these utilities ignore all remaining arguments.
pub fn parse_go_key_args<I, S>(command: KeyCommandKind, args: I) -> Result<KeyCommandOptions, KeyArgumentError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut options = KeyCommandOptions::default();
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let argument = argument.as_ref().to_string_lossy();
        if argument == "--" || argument.len() < 2 {
            break;
        }
        let Some(flag) = argument.strip_prefix('-') else { break };
        let flag = flag.strip_prefix('-').unwrap_or(flag);
        if flag.starts_with('-') || flag.starts_with('=') {
            return Err(KeyArgumentError::new(command, Some(format!("bad flag syntax: {argument}"))));
        }
        let (name, value) = flag.split_once('=').map_or((flag, None), |(name, value)| (name, Some(value)));
        match name {
            "i" => {
                options.input = match value {
                    Some(value) => value.to_owned(),
                    // A dash-leading value, including '--' or '-h', belongs
                    // to -i rather than being parsed as another flag.
                    None => args.next().map(|value| value.as_ref().to_string_lossy().into_owned())
                        .ok_or_else(|| KeyArgumentError::new(command, Some("flag needs an argument: -i".into())))?,
                };
            }
            "std-encoding" if command == KeyCommandKind::X25519 => {
                let value = value.unwrap_or("true");
                options.std_encoding = parse_go_bool(value).map_err(|_| KeyArgumentError::new(command,
                    Some(format!("invalid boolean value {value:?} for -std-encoding: parse error"))))?;
            }
            "h" | "help" => return Err(KeyArgumentError::new(command, None)),
            _ => return Err(KeyArgumentError::new(command, Some(format!("flag provided but not defined: -{name}")))),
        }
    }
    Ok(options)
}

/// Keep Clap's error behavior for every unrelated command. Key-command usage
/// (including explicit help) is always written to stderr with status 2.
#[derive(Debug)]
pub enum CliParseError {
    Clap(clap::Error),
    Key(KeyArgumentError),
}

impl CliParseError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Clap(error) => error.exit_code(),
            Self::Key(_) => 2,
        }
    }

    pub fn use_stderr(&self) -> bool {
        match self {
            Self::Clap(error) => error.use_stderr(),
            Self::Key(_) => true,
        }
    }

    pub fn exit(&self) -> ! {
        match self {
            Self::Clap(error) => error.exit(),
            Self::Key(error) => {
                eprint!("{error}");
                std::process::exit(self.exit_code());
            }
        }
    }
}

impl fmt::Display for CliParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clap(error) => fmt::Display::fmt(error, formatter),
            Self::Key(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for CliParseError {}

fn key_command_index(args: &[OsString]) -> Option<(usize, KeyCommandKind)> {
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if let Some(command) = KeyCommandKind::from_name(argument) {
            return Some((index, command));
        }
        let argument = argument.to_str()?;
        let (name, value) = argument.split_once('=').map_or((argument, None), |(name, value)| (name, Some(value)));
        match name {
            "-c" | "--config" | "-config" => {
                if value.is_none() { index += 1; }
            }
            "--test" | "-test" => {}
            // Preserve Clap's existing global -cFILE spelling. It must not
            // be confused with a key command's prohibited -iVALUE spelling.
            _ if argument.starts_with("-c") => {}
            _ => return None,
        }
        index += 1;
    }
    None
}

/// Executable entry point: retain normal Clap parsing except for the raw
/// arguments after x25519/mlkem768, which share the Command adapters' parser.
pub fn try_parse_go_cli<I, S>(args: I) -> Result<Cli, CliParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some((index, command)) = key_command_index(&args) else {
        return Cli::try_parse_from(normalize_go_flags(args)).map_err(CliParseError::Clap);
    };
    // Let Clap validate the unchanged global prefix and populate its options.
    // Do not send the key flags to Clap's short-option/help interpretation.
    let mut cli = Cli::try_parse_from(normalize_go_flags(args[..=index].iter().cloned()))
        .map_err(CliParseError::Clap)?;
    let options = parse_go_key_args(command, &args[index + 1..]).map_err(CliParseError::Key)?;
    cli.command = Some(match command {
        KeyCommandKind::X25519 => Commands::X25519(X25519Options { input: options.input, std_encoding: options.std_encoding }),
        KeyCommandKind::Mlkem768 => Commands::Mlkem768(Mlkem768Options { input: options.input }),
    });
    Ok(cli)
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

    fn parse(args: &[&str]) -> Result<Cli, CliParseError> {
        try_parse_go_cli(args.iter().copied())
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
    fn key_flags_reject_attached_short_values_and_exit_two_on_parse_errors() {
        for command in ["x25519", "mlkem768"] {
            for flag in ["-iVALUE", "--iVALUE", "--unknown", "-i", "---i=value", "-=value"] {
                let error = parse(&["xray", command, flag]).unwrap_err();
                assert!(matches!(&error, CliParseError::Key(_)));
                assert_eq!(error.exit_code(), 2, "{command} {flag}");
                assert!(error.use_stderr(), "{command} {flag}");
                assert!(error.to_string().contains(&format!("usage: xray {command} ")));
            }
            let error = parse(&["xray", command, "-iVALUE"]).unwrap_err();
            assert!(error.to_string().starts_with("flag provided but not defined: -iVALUE\n"));
        }
        let error = parse(&["xray", "x25519", "--std-encoding=maybe"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.use_stderr());
        assert!(error.to_string().starts_with("invalid boolean value \"maybe\" for -std-encoding: parse error\n"));
    }

    #[test]
    fn key_flags_stop_at_first_positional_or_explicit_terminator() {
        for command in [KeyCommandKind::X25519, KeyCommandKind::Mlkem768] {
            for terminator in ["ignored", "--", "-", ""] {
                let options = parse_go_key_args(command,
                    ["-i", "valid", terminator, "--unknown", "-i", "bad", "--help"]).unwrap();
                assert_eq!(options.input, "valid");
                assert!(!options.std_encoding);
            }
            let options = parse_go_key_args(command, ["--", "-i", "ignored", "--help"]).unwrap();
            assert_eq!(options, KeyCommandOptions::default());
        }
        let options = parse_go_key_args(KeyCommandKind::X25519,
            ["-i", "valid", "--std-encoding", "false", "--std-encoding=false", "--unknown"]).unwrap();
        assert_eq!(options.input, "valid");
        assert!(options.std_encoding); // Separate "false" is positional in Go.
        for name in ["x25519", "mlkem768"] {
            for terminator in ["ignored", "--"] {
                let cli = parse(&["xray", name, "-i", "valid", terminator, "--unknown", "-i", "bad"]).unwrap();
                match cli.command.unwrap() {
                    Commands::X25519(options) => assert_eq!(options.input, "valid"),
                    Commands::Mlkem768(options) => assert_eq!(options.input, "valid"),
                    _ => panic!("expected key command"),
                }
            }
        }
    }

    #[test]
    fn key_flags_preserve_equals_repetition_and_dash_leading_values() {
        for command in [KeyCommandKind::X25519, KeyCommandKind::Mlkem768] {
            for args in [vec!["-i", "-value"], vec!["--i=-value"], vec!["-i=old", "--i", "-value"]] {
                assert_eq!(parse_go_key_args(command, args).unwrap().input, "-value");
            }
            for value in ["--", "-h", "--help", "--unknown"] {
                assert_eq!(parse_go_key_args(command, ["-i", value]).unwrap().input, value);
            }
            assert_eq!(parse_go_key_args(command, ["--i=value=with=equals"]).unwrap().input, "value=with=equals");
        }
        let options = parse_go_key_args(KeyCommandKind::X25519,
            ["--std-encoding=T", "-std-encoding=0", "--std-encoding=True"]).unwrap();
        assert!(options.std_encoding);
    }

    #[test]
    fn key_help_matches_go_usage_and_always_selects_stderr_exit_two() {
        let cases = [
            ("x25519", "usage: xray x25519 [-i \"private key (base64.RawURLEncoding)\"] [--std-encoding]\nRun 'xray help x25519' for details.\n"),
            ("mlkem768", "usage: xray mlkem768 [-i \"seed (base64.RawURLEncoding)\"]\nRun 'xray help mlkem768' for details.\n"),
        ];
        for (command, expected_usage) in cases {
            for flag in ["-h", "--h", "-help", "--help", "-h=anything", "--help=false"] {
                let error = parse(&["xray", command, flag]).unwrap_err();
                assert!(matches!(&error, CliParseError::Key(_)));
                assert_eq!(error.to_string(), expected_usage, "{command} {flag}");
                assert_eq!(error.exit_code(), 2);
                assert!(error.use_stderr());
            }
        }
    }

    #[test]
    fn key_parsing_preserves_global_options_and_unrelated_clap_commands() {
        let cli = parse(&["xray", "--config", "x25519"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("x25519")));
        assert!(cli.command.is_none());
        let cli = parse(&["xray", "-test", "-config", "custom.json", "x25519", "-i", "valid", "ignored", "--unknown"]).unwrap();
        assert!(cli.test);
        assert_eq!(cli.config, Some(PathBuf::from("custom.json")));
        assert!(matches!(cli.command, Some(Commands::X25519(options)) if options.input == "valid"));
        assert!(matches!(parse(&["xray", "uuid", "-iVALUE"]).unwrap().command,
            Some(Commands::Uuid { input }) if input == "VALUE"));
        for args in [vec!["xray", "--help"], vec!["xray", "uuid", "--help"], vec!["xray", "tls", "cert", "--help"]] {
            let error = parse(&args).unwrap_err();
            assert!(matches!(&error, CliParseError::Clap(_)));
            assert_eq!(error.exit_code(), 0);
            assert!(!error.use_stderr());
        }
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
        let cli = try_parse_go_cli([OsString::from("xray"), OsString::from("-config"), path.clone()]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from(path.clone())));
        let error = try_parse_go_cli([OsString::from("xray"), OsString::from("-config"), path, OsString::from("x25519"), OsString::from("--help")]).unwrap_err();
        assert!(matches!(&error, CliParseError::Key(_)));
        assert_eq!(error.exit_code(), 2);
        assert!(error.use_stderr());
    }
}
