use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use xray_core::app::log::init_logger_ext;
use xray_core::core::{Instance, get_format_by_extension, load_config};
use xray_core::infra::conf::Config;
use xray_core::main::cli::{Cli, Commands, TlsCommands, try_parse_go_cli};
use xray_core::main::commands::all::tls::{cert::execute_cert, ping::execute_ping};
use xray_core::main::commands::all::uuid::generate_uuid;
use xray_core::main::commands::all::{mlkem768::execute_mlkem768, x25519::execute_x25519};

fn resolve_path(config_path: &PathBuf) -> PathBuf {
    if config_path.exists() {
        config_path.clone()
    } else if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(config_path);
            if candidate.exists() {
                candidate
            } else {
                config_path.clone()
            }
        } else {
            config_path.clone()
        }
    } else {
        config_path.clone()
    }
}

fn find_config_path(cli: &Cli) -> Option<PathBuf> {
    match &cli.command {
        Some(Commands::Run { config, .. }) => Some(config.clone()),
        Some(Commands::Test { config }) => Some(config.clone()),
        None => Some(cli.config.clone().unwrap_or_else(|| PathBuf::from("config.json"))),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = try_parse_go_cli(std::env::args_os()).unwrap_or_else(|error| error.exit());
    let (mut log_level, mut log_file) = ("info".to_string(), None);
    if let Some(cfg_path) = find_config_path(&cli)
        && let Ok(cfg) = load_config_file(&resolve_path(&cfg_path)) && let Some(log_cfg) = cfg.log
    {
        if let Some(level) = log_cfg.loglevel.filter(|s| !s.is_empty()) { log_level = level; }
        log_file = log_cfg.error.or(log_cfg.access).filter(|s| !s.is_empty());
    }
    init_logger_ext(&log_level, log_file.as_deref());
    match cli.command {
        Some(Commands::Version) => println!("Xray-core {} (Rust)", env!("CARGO_PKG_VERSION")),
        Some(Commands::Uuid { input }) => println!("{}", generate_uuid(&input)?),
        Some(Commands::X25519(options)) => println!("{}", execute_x25519(&options)?),
        Some(Commands::Mlkem768(options)) => println!("{}", execute_mlkem768(&options)?),
        Some(Commands::Tls { subcmd }) => {
            let output = match subcmd {
                TlsCommands::Ping(options) => execute_ping(&options).await?,
                TlsCommands::Cert(options) => execute_cert(&options)?,
            };
            if !output.is_empty() { println!("{output}"); }
        }
        Some(Commands::Api { server, timeout: _, args }) => {
            let operation = args.first().map(String::as_str).unwrap_or("request");
            let mut shared_args = vec![format!("--server={server}")];
            shared_args.extend(args.iter().cloned());
            let shared_args = shared_args.iter().map(String::as_str).collect::<Vec<_>>();
            let config = xray_core::main::commands::all::api::shared::ApiClientConfig::parse(&shared_args);
            return Err(xray_core::main::commands::all::api::shared::unsupported_api(operation, &config.server).into());
        }
        Some(Commands::Test { config }) | Some(Commands::Run { config, test: true }) => test_config(config)?,
        Some(Commands::Run { config, test: false }) => run_instance(config).await?,
        None => {
            let config = cli.config.unwrap_or_else(|| PathBuf::from("config.json"));
            if cli.test { test_config(config)?; } else { run_instance(config).await?; }
        }
    }
    Ok(())
}

fn test_config(config_path: PathBuf) -> Result<()> {
    let resolved = resolve_path(&config_path);
    let config = load_config_file(&resolved)?;
    let _ = config.build().context("Configuration build failed")?;
    println!("Configuration OK.");
    Ok(())
}

fn load_config_file(path: &Path) -> Result<Config> {
    let format = get_format_by_extension(path.extension().and_then(|ext| ext.to_str()).unwrap_or(""));
    if format.is_empty() {
        anyhow::bail!("Failed to get format of {:?}", path);
    }
    let content = std::fs::read(path)
        .with_context(|| format!("Failed to read config file {:?}", path))?;
    load_config(&format, &content)
        .with_context(|| format!("Failed to parse {} config", format.to_ascii_uppercase()))
}

async fn run_instance(config_path: PathBuf) -> Result<()> {
    let resolved = resolve_path(&config_path);
    info!("Starting Xray Core (Rust Edition)...");
    info!("Loading configuration from: {:?}", resolved);
    let config = load_config_file(&resolved)?;
    let instance = Instance::from_config(config).with_context(|| "Failed to initialize Xray instance")?;
    let _tasks = instance.start().await.with_context(|| "Failed to start inbounds")?;
    info!("Xray-core is running. Press Ctrl+C to terminate.");
    tokio::signal::ctrl_c().await.with_context(|| "Failed to listen for ctrl_c signal")?;
    info!("Received interrupt signal, shutting down...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/config-reference/generated").join(name)
    }

    struct TestConfigFile(PathBuf);

    impl TestConfigFile {
        fn new(extension: &str, content: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!("xray-config-{}", uuid::Uuid::new_v4())).with_extension(extension);
            std::fs::write(&path, content).unwrap();
            Self(path)
        }
    }

    impl Drop for TestConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn config_path_is_only_used_for_config_commands() {
        let cli = try_parse_go_cli(["xray", "run", "-c", "custom.json"]).unwrap();
        assert_eq!(find_config_path(&cli), Some(PathBuf::from("custom.json")));
        let cli = try_parse_go_cli(["xray", "uuid"]).unwrap();
        assert_eq!(find_config_path(&cli), None);
        for command in ["x25519", "mlkem768"] {
            let cli = try_parse_go_cli(["xray", command, "-i", "seed"]).unwrap();
            assert_eq!(find_config_path(&cli), None);
        }
        let cli = try_parse_go_cli(["xray"]).unwrap();
        assert_eq!(find_config_path(&cli), Some(PathBuf::from("config.json")));
    }

    #[test]
    fn executable_key_usage_errors_use_stderr_and_exit_two_before_execution() {
        for command in ["x25519", "mlkem768"] {
            for flag in ["-h", "-help", "--help", "-iATTACHED", "--unknown", "-i"] {
                let error = try_parse_go_cli(["xray", command, flag]).unwrap_err();
                assert!(matches!(&error, xray_core::main::cli::CliParseError::Key(_)));
                assert_eq!(error.exit_code(), 2);
                assert!(error.use_stderr());
                assert!(error.to_string().ends_with(&format!("Run 'xray help {command}' for details.\n")));
            }
        }
        let help = try_parse_go_cli(["xray", "--help"]).unwrap_err();
        assert_eq!(help.exit_code(), 0);
        assert!(!help.use_stderr());
    }

    #[test]
    fn executable_loads_and_tests_pinned_configs_in_all_supported_formats() {
        for name in ["json-comments.json", "yaml.yaml", "toml.toml", "json-comments.pb"] {
            let path = fixture_path(name);
            let built = load_config_file(&path).unwrap_or_else(|error| panic!("{name}: {error:#}")).build().unwrap();
            assert!(built.stats_enabled, "{name}");
            assert_eq!(built.default_outbound_tag.as_deref(), Some("direct"), "{name}");
            assert_eq!(built.outbounds.len(), 1, "{name}");
            assert!(built.outbounds.contains_key("direct"), "{name}");
            test_config(path).unwrap_or_else(|error| panic!("{name}: {error:#}"));
        }
    }

    #[test]
    fn executable_selects_conventional_extensions_case_insensitively() {
        for (name, extensions) in [
            ("json-comments.json", &["json", "jsonc", "JSONC"][..]),
            ("yaml.yaml", &["yaml", "yml", "YML"][..]),
            ("toml.toml", &["toml", "TOML"][..]),
            ("json-comments.pb", &["pb", "protobuf", "PB", "PROTOBUF"][..]),
        ] {
            let bytes = std::fs::read(fixture_path(name)).unwrap();
            for extension in extensions {
                let file = TestConfigFile::new(extension, &bytes);
                let config = load_config_file(&file.0).unwrap();
                assert!(config.stats.is_some(), "{extension}");
                assert_eq!(config.outbounds[0].tag.as_deref(), Some("direct"), "{extension}");
            }
        }
    }

    #[test]
    fn executable_protobuf_input_is_not_required_to_be_utf8() {
        let path = fixture_path("policy-zero-negative.pb");
        let bytes = std::fs::read(&path).unwrap();
        assert!(std::str::from_utf8(&bytes).is_err());
        let native = load_config_file(&path).unwrap().build().unwrap();
        let json = load_config_file(&fixture_path("policy-zero-negative.json")).unwrap().build().unwrap();
        assert!(native.stats_enabled);
        for level in [0, 1, 2, 999] {
            assert_eq!(native.policy_manager.for_level(level), json.policy_manager.for_level(level), "level {level}");
        }
        assert_eq!(native.policy_manager.for_system(), json.policy_manager.for_system());
        test_config(path).unwrap();
    }

    #[test]
    fn executable_decode_errors_keep_format_context() {
        for (name, format, cause) in [
            ("invalid-json.json", "JSON", "failed to read config file"),
            ("invalid-yaml.yaml", "YAML", "failed to convert yaml to json"),
            ("invalid-toml.toml", "TOML", "failed to convert toml to map"),
        ] {
            let error = test_config(fixture_path(name)).unwrap_err();
            assert_eq!(error.to_string(), format!("Failed to parse {format} config"));
            assert!(format!("{error:#}").contains(cause), "{name}: {error:#}");
        }
        for bytes in [&[0x0a, 0xff][..], br#"{"stats":{}}"#.as_slice()] {
            let file = TestConfigFile::new("pb", bytes);
            let error = test_config(file.0.clone()).unwrap_err();
            assert_eq!(error.to_string(), "Failed to parse PROTOBUF config");
            assert!(format!("{error:#}").contains("failed to decode xray.core.Config"));
        }
    }

    #[test]
    fn unknown_formats_fail_explicitly_before_json_decoding() {
        for extension in ["unknown", ""] {
            let file = TestConfigFile::new(extension, b"{}");
            let error = load_config_file(&file.0).unwrap_err().to_string();
            assert!(error.starts_with("Failed to get format of "), "{error}");
        }
    }

    #[test]
    fn executable_test_mode_keeps_build_failures() {
        for name in ["empty-api-tag.json", "empty-metrics.json", "removed-reverse.json", "burst-missing-ping.json"] {
            assert!(load_config_file(&fixture_path(name)).is_ok(), "{name}");
            let error = test_config(fixture_path(name)).unwrap_err();
            assert_eq!(error.to_string(), "Configuration build failed", "{name}");
        }
    }

    #[test]
    fn config_read_and_parse_errors_are_not_success() {
        let path = std::env::temp_dir().join(format!("xray-config-{}.json", uuid::Uuid::new_v4()));
        assert!(load_config_file(&path).is_err());
        std::fs::write(&path, "not JSON").unwrap();
        assert!(load_config_file(&path).unwrap_err().to_string().contains("parse JSON"));
        std::fs::write(&path, r#"{"log":{"loglevel":"warning"}}"#).unwrap();
        assert_eq!(load_config_file(&path).unwrap().log.unwrap().loglevel.as_deref(), Some("warning"));
        std::fs::remove_file(path).unwrap();
    }
}
