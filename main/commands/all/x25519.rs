use super::curve25519::format_curve25519;
use crate::common::errors::{Error, Result};
use crate::main::commands::base::command::Command;
use clap::{Args, Parser};

#[derive(Args, Debug, Default)]
pub struct X25519Options {
    #[arg(short = 'i', long = "i", default_value = "", allow_hyphen_values = true)]
    pub input: String,
    #[arg(long, default_value_t = false, default_missing_value = "true", num_args = 0..=1, require_equals = true, action = clap::ArgAction::Set, value_parser = parse_go_bool)]
    pub std_encoding: bool,
}

#[derive(Parser)]
#[command(args_override_self = true)]
struct X25519Cli {
    #[command(flatten)]
    options: X25519Options,
}

fn parse_go_bool(input: &str) -> std::result::Result<bool, String> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean value: {input}")),
    }
}

pub fn execute_x25519(options: &X25519Options) -> Result<String> {
    format_curve25519(&options.input, options.std_encoding)
}

pub fn cmd_x25519() -> Command {
    Command::new("x25519", "xray x25519 [-i key] [--std-encoding]", "Generate key pair for X25519 key exchange (REALITY, VLESS Encryption)").with_run(|args| {
        let argv = std::iter::once("x25519").chain(args.iter().copied()).map(std::ffi::OsString::from);
        let cli = X25519Cli::try_parse_from(crate::main::cli::normalize_go_flags(argv))
            .map_err(|error| Error::Config(error.to_string()))?;
        execute_x25519(&cli.options)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::curve25519::gen_curve25519;
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    fn decode_output(output: &str, standard: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        let decode = |line: &str, prefix: &str| {
            let encoded = line.strip_prefix(prefix).unwrap();
            if standard { STANDARD.decode(encoded).unwrap() } else { URL_SAFE_NO_PAD.decode(encoded).unwrap() }
        };
        (decode(lines[0], "PrivateKey: "), decode(lines[1], "Password (PublicKey): "), decode(lines[2], "Hash32: "))
    }

    #[test]
    fn x25519_url_and_standard_output_match_every_go_fixture_in_either_flag_order() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testing/crypto-reference/vectors.json");
        let json = std::fs::read_to_string(path)
            .expect("freeze the independent Go vectors using testing/crypto-reference/generate.sh on Linux");
        let fixtures: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vectors = fixtures["x25519"].as_array().unwrap();
        assert_eq!(vectors.len(), 5);
        for vector in vectors {
            let input = vector["input"].as_str().unwrap();
            let expected = format!("PrivateKey: {}\nPassword (PublicKey): {}\nHash32: {}", vector["private_key"].as_str().unwrap(), vector["public_key"].as_str().unwrap(), vector["hash32"].as_str().unwrap());
            assert_eq!(cmd_x25519().execute(&["-i", input]).unwrap(), expected);
            assert_eq!(cmd_x25519().execute(&[&format!("--i={input}")]).unwrap(), expected);
            let to_standard = |field: &str| STANDARD.encode(URL_SAFE_NO_PAD.decode(vector[field].as_str().unwrap()).unwrap());
            let standard_input = to_standard("input");
            let standard_expected = format!("PrivateKey: {}\nPassword (PublicKey): {}\nHash32: {}", to_standard("private_key"), to_standard("public_key"), to_standard("hash32"));
            for args in [vec!["-i", standard_input.as_str(), "--std-encoding"], vec!["--std-encoding", "--i", standard_input.as_str()], vec!["-std-encoding", "-i", standard_input.as_str()]] {
                assert_eq!(cmd_x25519().execute(&args).unwrap(), standard_expected);
            }
        }
    }

    #[test]
    fn generated_x25519_output_has_matching_keys_hash_and_encoding() {
        for standard in [false, true] {
            let args = if standard { vec!["--std-encoding"] } else { vec![] };
            let output = cmd_x25519().execute(&args).unwrap();
            let (private, public, hash32) = decode_output(&output, standard);
            let (expected_private, expected_public, expected_hash) = gen_curve25519(Some(&private)).unwrap();
            assert_eq!(private, expected_private);
            assert_eq!(public, expected_public);
            assert_eq!(hash32, expected_hash);
            let encoded = if standard { STANDARD.encode(&private) } else { URL_SAFE_NO_PAD.encode(&private) };
            let mut again = args;
            again.extend(["-i", &encoded]);
            assert_eq!(cmd_x25519().execute(&again).unwrap(), output);
            assert_ne!(decode_output(&cmd_x25519().execute(&[]).unwrap(), false).0, private);
        }
    }

    #[test]
    fn x25519_rejects_bad_lengths_encodings_missing_values_and_unknown_flags() {
        let command = cmd_x25519();
        for length in [1, 16, 31, 33, 64] {
            assert_eq!(command.execute(&["-i", &URL_SAFE_NO_PAD.encode(vec![0; length])]).unwrap(), "Invalid length of X25519 private key.");
        }
        for input in ["!", "\n", "not base64", "====", "AA=="] {
            assert_eq!(command.execute(&["-i", input]).unwrap(), "Invalid length of X25519 private key.");
        }
        let raw = URL_SAFE_NO_PAD.encode([255u8; 32]);
        let padded = STANDARD.encode([255u8; 32]);
        assert_eq!(command.execute(&["-i", &padded]).unwrap(), "Invalid length of X25519 private key.");
        assert_eq!(command.execute(&["--std-encoding", "-i", &raw]).unwrap(), "Invalid length of X25519 private key.");
        for args in [vec!["-i"], vec!["--i"], vec!["--unknown"], vec!["--std-encoding=maybe"], vec!["-std"]] {
            assert!(command.execute(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn x25519_repeated_flags_go_boolean_spellings_and_input_starting_with_hyphen() {
        let command = cmd_x25519();
        let input = URL_SAFE_NO_PAD.encode([248u8; 32]);
        assert!(input.starts_with('-'));
        let expected = command.execute(&["-i", &input]).unwrap();
        assert_eq!(command.execute(&["-i", "bad", "--i", &input]).unwrap(), expected);
        for value in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(command.execute(&["-i", &input, &format!("--std-encoding={value}")]).unwrap(), expected);
        }
        let standard = STANDARD.encode([248u8; 32]);
        for value in ["1", "t", "T", "TRUE", "true", "True"] {
            let output = command.execute(&["-i", &standard, &format!("--std-encoding={value}")]).unwrap();
            assert_eq!(decode_output(&output, true).0, gen_curve25519(Some(&[248u8; 32])).unwrap().0);
        }
        assert_eq!(command.execute(&["--std-encoding", "--std-encoding=false", "-i", &input]).unwrap(), expected);
    }

    #[test]
    fn x25519_base64_matches_go_newlines_trailing_bits_and_partial_decode_output() {
        let command = cmd_x25519();
        let input = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let expected = command.execute(&["-i", &input]).unwrap();
        let multiline = format!("{}\r\n{}", &input[..20], &input[20..]);
        assert_eq!(command.execute(&["-i", &multiline]).unwrap(), expected);
        let mut noncanonical = input;
        noncanonical.pop();
        noncanonical.push('B');
        assert_eq!(command.execute(&["-i", &noncanonical]).unwrap(), expected);

        let standard = STANDARD.encode([0u8; 32]);
        let standard_expected = command.execute(&["-i", &standard, "--std-encoding"]).unwrap();
        // Go ignores DecodeString's error once a complete padded key has
        // already been returned, so this diagnostic-free case is intentional.
        let trailing_garbage = format!("{standard}!");
        assert_eq!(command.execute(&["-i", &trailing_garbage, "--std-encoding"]).unwrap(), standard_expected);
        assert_eq!(decode_output(&command.execute(&["-i="]).unwrap(), false).0.len(), 32);
    }
}
