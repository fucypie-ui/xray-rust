use super::format::{CONFIG_FORMAT_JSON, CONFIG_FORMAT_PROTOBUF, CONFIG_FORMAT_TOML, CONFIG_FORMAT_YAML};
use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

pub type ConfigLoader = fn(&[u8]) -> Result<Config>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub name: String,
    pub format: String,
}

impl ConfigSource {
    pub fn new(name: impl Into<String>, format: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: format.into(),
        }
    }
}

pub struct ConfigFormat {
    pub name: String,
    pub extensions: Vec<String>,
    pub loader: ConfigLoader,
}

impl ConfigFormat {
    pub fn new(name: impl Into<String>, extensions: Vec<String>, loader: ConfigLoader) -> Self {
        Self {
            name: name.into(),
            extensions,
            loader,
        }
    }
}

static LOADERS_BY_NAME: LazyLock<RwLock<HashMap<String, ConfigLoader>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(CONFIG_FORMAT_JSON.to_string(), json_loader as ConfigLoader);
    map.insert(CONFIG_FORMAT_YAML.to_string(), yaml_loader as ConfigLoader);
    map.insert(CONFIG_FORMAT_TOML.to_string(), toml_loader as ConfigLoader);
    map.insert(CONFIG_FORMAT_PROTOBUF.to_string(), crate::infra::conf::native::decode_config as ConfigLoader);
    RwLock::new(map)
});

static LOADERS_BY_EXT: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("json".to_string(), CONFIG_FORMAT_JSON.to_string());
    map.insert("jsonc".to_string(), CONFIG_FORMAT_JSON.to_string());
    map.insert("yaml".to_string(), CONFIG_FORMAT_YAML.to_string());
    map.insert("yml".to_string(), CONFIG_FORMAT_YAML.to_string());
    map.insert("toml".to_string(), CONFIG_FORMAT_TOML.to_string());
    map.insert("pb".to_string(), CONFIG_FORMAT_PROTOBUF.to_string());
    map.insert("protobuf".to_string(), CONFIG_FORMAT_PROTOBUF.to_string());
    RwLock::new(map)
});

fn json_loader(data: &[u8]) -> Result<Config> {
    // Local Go configs permit Java and Python style comments. Keep serde_json
    // responsible for JSON grammar, numbers, escapes and diagnostic positions.
    let reader = json_comments::StripComments::new(data);
    let mut decoder = serde_json::Deserializer::from_reader(reader);
    serde::Deserialize::deserialize(&mut decoder)
        .map_err(|error| Error::Config(format!("failed to read config file at line {} char {}: {}", error.line(), error.column(), error)))
}

fn yaml_loader(data: &[u8]) -> Result<Config> {
    let value: serde_json::Value = serde_yaml_ng::from_slice(data)
        .map_err(|error| Error::Config(format!("failed to convert yaml to json: {}", error)))?;
    serde_json::from_value(value).map_err(|error| Error::Config(format!("failed to read config file: {}", error)))
}

fn toml_loader(data: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(data)
        .map_err(|error| Error::Config(format!("failed to read config file: {}", error)))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| Error::Config(format!("failed to convert toml to map: {}", error)))?;
    let value = serde_json::to_value(value)
        .map_err(|error| Error::Config(format!("failed to convert map to json: {}", error)))?;
    serde_json::from_value(value).map_err(|error| Error::Config(format!("failed to read config file: {}", error)))
}

pub fn register_config_loader(format: ConfigFormat) -> Result<()> {
    let name = format.name.to_lowercase();
    let mut names = LOADERS_BY_NAME.write().map_err(|_| Error::Config("Loader lock poisoned".into()))?;
    let mut exts = LOADERS_BY_EXT.write().map_err(|_| Error::Config("Loader lock poisoned".into()))?;
    if names.contains_key(&name) { return Err(Error::Config(format!("{} already registered.", format.name))); }
    let extensions: Vec<_> = format.extensions.iter().map(|ext| ext.to_lowercase()).collect();
    // Validate the entire registration before changing either registry.
    let mut seen = std::collections::HashSet::new();
    for extension in &extensions {
        if !seen.insert(extension.clone()) {
            return Err(Error::Config(format!("{} already registered to {}", extension, name)));
        }
        if let Some(existing) = exts.get(extension) {
            return Err(Error::Config(format!("{} already registered to {}", extension, existing)));
        }
    }
    names.insert(name.clone(), format.loader);
    for extension in extensions { exts.insert(extension, name.clone()); }
    Ok(())
}

pub fn get_extension(filename: &str) -> String {
    if let Some(idx) = filename.rfind('.') {
        filename[idx + 1..].to_string()
    } else {
        String::new()
    }
}

pub fn get_format_by_extension(ext: &str) -> String {
    LOADERS_BY_EXT.read().ok().and_then(|extensions| extensions.get(&ext.to_lowercase()).cloned()).unwrap_or_default()
}

pub fn get_format(filename: &str) -> String { get_format_by_extension(&get_extension(filename)) }

pub fn load_config(format_name: &str, data: &[u8]) -> Result<Config> {
    let fmt = if format_name == "auto" {
        CONFIG_FORMAT_JSON
    } else {
        format_name
    };
    let loader = *LOADERS_BY_NAME.read()
        .map_err(|_| Error::Config("Config loader lock poisoned".into()))?
        .get(&fmt.to_lowercase()).ok_or_else(|| Error::Config(format!("Unsupported config format: {}", format_name)))?;
    // Registered loaders may themselves invoke the registry.
    loader(data)
}

pub fn get_merged_config(files: &[ConfigSource]) -> Result<String> {
    let mut merged = Config::default();
    for source in files {
        let format = if source.format.is_empty() || source.format == "auto" {
            get_format(&source.name)
        } else { source.format.clone() };
        let bytes = std::fs::read(&source.name)
            .map_err(|error| Error::Config(format!("failed to read config file {}: {}", source.name, error)))?;
        let config = load_config(&format, &bytes)?;
        merged.override_with(config, &source.name);
    }
    serde_json::to_string(&merged)
        .map_err(|error| Error::Config(format!("Failed to serialize merged config: {}", error)))
}

#[cfg(test)]
#[path = "config_test.rs"]
mod tests;

pub use crate::infra::conf::Config as CoreConfig;
