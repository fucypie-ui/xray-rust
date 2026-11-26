use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;
use serde_json::Value;

pub fn build_json_config(raw_json: &str) -> Result<Value> {
    serde_json::from_str(raw_json).map_err(|e| Error::Config(e.to_string()))
}

pub fn merge_configs(configs: &[Config]) -> Config {
    let mut merged = Config::default();
    for config in configs { merged.override_with(config.clone(), "tail"); }
    merged
}

pub fn build_config_from_slices(raw_jsons: &[&str]) -> Result<Config> {
    let mut configs = Vec::new();
    for raw in raw_jsons {
        let conf: Config = crate::core::config::load_config("json", raw.as_bytes())?;
        configs.push(conf);
    }
    Ok(merge_configs(&configs))
}
