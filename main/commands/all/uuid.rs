use crate::main::commands::base::command::Command;
use uuid::Uuid;
use crate::common::errors::{Error, Result};
use clap::Parser;

#[derive(Parser)]
struct UuidArgs {
    #[arg(short = 'i', long = "i", default_value = "", allow_hyphen_values = true)]
    input: String,
}

pub fn generate_uuid(input: &str) -> Result<Uuid> {
    if input.is_empty() {
        Ok(Uuid::new_v4())
    } else if input.len() <= 30 {
        // Xray uses the nil namespace, rather than the DNS namespace. The
        // limit is in UTF-8 bytes, matching Go len(string).
        Ok(Uuid::new_v5(&Uuid::nil(), input.as_bytes()))
    } else {
        Err(Error::Config("Input must be within 30 bytes.".into()))
    }
}

pub fn cmd_uuid() -> Command {
    Command::new("uuid", "xray uuid [-i input]", "Generate UUIDv4 or UUIDv5 (VLESS)").with_run(|args| {
        let args = UuidArgs::try_parse_from(std::iter::once("uuid").chain(args.iter().copied()))
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(generate_uuid(&args.input)?.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_uuid_command() {
        let cmd = cmd_uuid();
        let out = cmd.execute(&[]).unwrap();
        assert_eq!(out.len(), 36);
        assert!(Uuid::parse_str(&out).is_ok());
        assert_eq!(Uuid::parse_str(&out).unwrap().get_version_num(), 4);
    }

    #[test]
    fn deterministic_uuid_matches_go_nil_namespace() {
        assert_eq!(cmd_uuid().execute(&["-i", "example"]).unwrap(), "feb54431-301b-52bb-a6dd-e1e93e81bb9e");
        assert_eq!(generate_uuid("example").unwrap(), generate_uuid("example").unwrap());
        assert_ne!(generate_uuid("example").unwrap(), generate_uuid("Example").unwrap());
    }

    #[test]
    fn uuid_input_limit_counts_bytes() {
        assert!(generate_uuid(&"a".repeat(30)).is_ok());
        assert!(generate_uuid(&"a".repeat(31)).is_err());
        assert!(generate_uuid(&"é".repeat(15)).is_ok());
        assert!(generate_uuid(&"é".repeat(16)).is_err());
        assert!(cmd_uuid().execute(&["-i"]).is_err());
        assert!(cmd_uuid().execute(&["--unknown"]).is_err());
    }

    #[test]
    fn command_accepts_hyphen_prefixed_input_without_treating_it_as_flags() {
        for input in ["-example", "-domain", "--test"] {
            let output = cmd_uuid().execute(&["-i", input]).unwrap();
            assert_eq!(output, generate_uuid(input).unwrap().to_string());
            assert_eq!(Uuid::parse_str(&output).unwrap().get_version_num(), 5);
        }
    }
}
