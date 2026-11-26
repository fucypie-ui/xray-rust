use crate::common::errors::{Error, Result};
use crate::infra::conf::Config;

pub const TOML_FORMAT: &str = "TOML";
pub const FORMAT_TOML: &str = TOML_FORMAT;

pub fn load_toml_from_str(_content: &str) -> Result<Config> {
    Err(Error::Unsupported("TOML configuration decoding is not implemented; use JSON".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_toml_format_const() { assert_eq!(TOML_FORMAT, "TOML"); }

    #[test]
    fn toml_loader_does_not_masquerade_as_json_decoder() {
        for content in ["[log]\nloglevel = \"warning\"", r#"{"log":{"loglevel":"warning"}}"#] {
            assert!(matches!(load_toml_from_str(content), Err(Error::Unsupported(_))));
        }
    }
}
