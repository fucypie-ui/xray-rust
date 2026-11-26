use super::*;
use crate::features::feature::TYPE_STATS_MANAGER;
use serde_json::Value;

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("../testing/config-reference/generated/fixtures.json")).unwrap()
}

#[test]
fn go_oracle_loader_and_build_results() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 19);
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let parsed = load_config(fixture["format"].as_str().unwrap(), fixture["input"].as_str().unwrap().as_bytes());
        if fixture.get("decode_error").is_some() {
            assert!(parsed.is_err(), "{} decoded unexpectedly", name);
            continue;
        }
        let config = parsed.unwrap_or_else(|error| panic!("{}: {}", name, error));
        let built = config.build();
        if let Some(expected) = fixture["build_error"].as_str() {
            let error = built.err().unwrap_or_else(|| panic!("{} built unexpectedly", name)).to_string();
            let expected = expected.rsplit(" > ").next().unwrap_or(expected).trim_start_matches("infra/conf: ").trim_start_matches("common/errors: ");
            assert!(error.contains(expected), "{}: {} (expected {})", name, error, expected);
        } else {
            built.unwrap_or_else(|error| panic!("{}: {}", name, error));
        }
    }
}

#[test]
fn genuine_go_protobuf_matches_effective_json_config() {
    for fixture in fixtures() {
        let Some(file) = fixture["protobuf"].as_str() else { continue; };
        let bytes = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/config-reference/generated").join(file)).unwrap();
        let native = load_config("protobuf", &bytes).unwrap_or_else(|error| panic!("{}: {}", file, error));
        let json = load_config(fixture["format"].as_str().unwrap(), fixture["input"].as_str().unwrap().as_bytes()).unwrap();
        let native = native.build().unwrap_or_else(|error| panic!("{}: {}", file, error));
        let json = json.build().unwrap();
        assert_eq!(native.stats_enabled, json.stats_enabled, "{} stats", file);
        assert_eq!(native.default_outbound_tag, json.default_outbound_tag, "{} default route", file);
        let mut native_tags: Vec<_> = native.outbounds.keys().collect(); native_tags.sort();
        let mut json_tags: Vec<_> = json.outbounds.keys().collect(); json_tags.sort();
        assert_eq!(native_tags, json_tags, "{} outbounds", file);
        assert_eq!(native.inbounds.len(), json.inbounds.len(), "{} inbounds", file);
        for ((native_addr, native_handler), (json_addr, json_handler)) in native.inbounds.iter().zip(&json.inbounds) {
            assert_eq!(native_addr, json_addr, "{} listen", file);
            assert_eq!(native_handler.tag(), json_handler.tag(), "{} inbound tag", file);
        }
        for level in [0, 1, 2, 999] {
            assert_eq!(native.policy_manager.for_level(level), json.policy_manager.for_level(level), "{} level {}", file, level);
        }
        assert_eq!(native.policy_manager.for_system(), json.policy_manager.for_system(), "{} system", file);
        let mut native_features: Vec<_> = native.features.iter().map(|feature| feature.feature_type()).collect(); native_features.sort();
        let mut json_features: Vec<_> = json.features.iter().map(|feature| feature.feature_type()).collect(); json_features.sort();
        assert_eq!(native_features, json_features, "{} features", file);
    }
}

#[test]
fn formats_are_real_and_unknown_or_invalid_inputs_fail() {
    assert!(load_config("yaml", b"stats: [").is_err());
    assert!(load_config("toml", b"[stats").is_err());
    assert!(load_config("json", b"{bad}").is_err());
    assert!(load_config("protobuf", br#"{"stats":{}}"#).is_err());
    assert!(load_config("protobuf", &[0x0a, 0xff]).is_err());
    assert!(load_config("unknown-format", b"{}").is_err());
    assert_eq!(get_format("CONFIG.YML"), "yaml");
    assert_eq!(get_format("config.pb"), "protobuf");
    assert_eq!(get_format("config.unknown"), "");
}

#[test]
fn root_registers_exactly_one_stats_feature_and_uses_the_shared_store() {
    for enabled in [false, true] {
        let raw = if enabled { r#"{"stats":{},"api":{"tag":"api","services":["StatsService"]}}"# } else { r#"{"api":{"tag":"api","services":["StatsService"]}}"# };
        let built = load_config("json", raw.as_bytes()).unwrap().build().unwrap();
        assert_eq!(built.stats_enabled, enabled);
        assert_eq!(built.features.iter().filter(|feature| feature.feature_type() == TYPE_STATS_MANAGER).count(), 1);
        assert!(built.stats_manager.all_counters().is_empty());
    }
}

#[test]
fn file_merge_propagates_missing_and_malformed_inputs() {
    let missing = std::env::temp_dir().join(format!("xray-config-{}.json", uuid::Uuid::new_v4()));
    let sources = [ConfigSource::new(missing.to_string_lossy().into_owned(), "json")];
    assert!(get_merged_config(&sources).is_err());
    std::fs::write(&missing, b"{invalid}").unwrap();
    let result = get_merged_config(&sources);
    std::fs::remove_file(&missing).unwrap();
    assert!(result.is_err());
}
