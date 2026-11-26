use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;

pub const YAML_FORMAT: &str = "YAML";
pub const FORMAT_YAML: &str = YAML_FORMAT;

pub fn load_yaml_from_str(_content: &str) -> Result<Config> {
    Err(Error::Unsupported("YAML configuration decoding is not implemented; use JSON".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_yaml_format_const() { assert_eq!(YAML_FORMAT, "YAML"); }

    #[test]
    fn yaml_loader_does_not_masquerade_as_json_decoder() {
        for content in ["log:\n  loglevel: warning", r#"{"log":{"loglevel":"warning"}}"#] {
            assert!(matches!(load_yaml_from_str(content), Err(Error::Unsupported(_))));
        }
    }
}
