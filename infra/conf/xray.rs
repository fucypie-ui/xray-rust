use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;
use serde_json::Value;
use std::path::Path;

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load_from_json_str(json_str: &str) -> Result<Config> {
        crate::core::config::load_config("json", json_str.as_bytes())
    }
    pub fn load_from_json_value(val: Value) -> Result<Config> {
        serde_json::from_value::<Config>(val).map_err(|e| Error::Config(format!("JSON value conversion error: {}", e)))
    }
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Config> {
        let path = path.as_ref();
        let content = std::fs::read(path)
            .map_err(|error| Error::Config(format!("Failed to read config file: {}", error)))?;
        let format = crate::core::config::get_format(&path.to_string_lossy());
        crate::core::config::load_config(&format, &content)
    }
}
