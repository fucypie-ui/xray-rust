use super::curve25519::decode_go_base64;
use crate::common::errors::{Error, Result};
use crate::main::commands::base::command::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Args, Parser};
use ml_kem::{DecapsulationKey768, KeyExport, Seed};
use rand::RngCore;

#[derive(Args, Debug, Default)]
pub struct Mlkem768Options {
    #[arg(short = 'i', long = "i", default_value = "", allow_hyphen_values = true)]
    pub input: String,
}

#[derive(Parser)]
#[command(args_override_self = true)]
struct Mlkem768Cli {
    #[command(flatten)]
    options: Mlkem768Options,
}

/// The seed is the FIPS 203 d || z representation also accepted by Go's
/// crypto/mlkem.NewDecapsulationKey768. Its fixed size prevents silently
/// substituting an all-zero seed when a caller supplies malformed input.
pub fn gen_mlkem768(input_seed: Option<&[u8; 64]>) -> ([u8; 64], Vec<u8>, [u8; 32]) {
    let mut seed = [0u8; 64];
    match input_seed {
        Some(input) => seed.copy_from_slice(input),
        None => rand::thread_rng().fill_bytes(&mut seed),
    }
    // Use our existing rand 0.8 only for the seed; the deterministic
    // constructor avoids coupling its rand_core version to ml-kem's.
    let key = DecapsulationKey768::from_seed(Seed::from(seed));
    let client = key.encapsulation_key().to_bytes().to_vec();
    let hash32 = *blake3::hash(&client).as_bytes();
    (seed, client, hash32)
}

pub fn execute_mlkem768(options: &Mlkem768Options) -> Result<String> {
    let input_seed = if options.input.is_empty() {
        None
    } else {
        let decoded = decode_go_base64(&options.input, false);
        let Ok(seed) = <[u8; 64]>::try_from(decoded.as_slice()) else {
            // The Go command prints this diagnostic and returns normally.
            return Ok("Invalid length of ML-KEM-768 seed.".into());
        };
        Some(seed)
    };
    let (seed, client, hash32) = gen_mlkem768(input_seed.as_ref());
    Ok(format!(
        "Seed: {}\nClient: {}\nHash32: {}",
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(&client),
        URL_SAFE_NO_PAD.encode(hash32),
    ))
}

pub fn cmd_mlkem768() -> Command {
    Command::new("mlkem768", "xray mlkem768 [-i seed]", "Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption)").with_run(|args| {
        let argv = std::iter::once("mlkem768").chain(args.iter().copied()).map(std::ffi::OsString::from);
        let cli = Mlkem768Cli::try_parse_from(crate::main::cli::normalize_go_flags(argv))
            .map_err(|error| Error::Config(error.to_string()))?;
        execute_mlkem768(&cli.options)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_vectors() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testing/crypto-reference/vectors.json");
        let json = std::fs::read_to_string(path)
            .expect("freeze the independent Go vectors using testing/crypto-reference/generate.sh on Linux");
        serde_json::from_str(&json).unwrap()
    }

    fn parse_output(output: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        let decode = |line: &str, prefix: &str| {
            URL_SAFE_NO_PAD.decode(line.strip_prefix(prefix).unwrap()).unwrap()
        };
        (decode(lines[0], "Seed: "), decode(lines[1], "Client: "), decode(lines[2], "Hash32: "))
    }

    #[test]
    fn deterministic_mlkem768_matches_full_go_public_keys_and_blake3_hashes() {
        let fixtures = fixture_vectors();
        let vectors = fixtures["mlkem768"].as_array().unwrap();
        assert_eq!(vectors.len(), 5);
        for vector in vectors {
            let name = vector["name"].as_str().unwrap();
            let encoded_seed = vector["seed"].as_str().unwrap();
            let decoded = URL_SAFE_NO_PAD.decode(encoded_seed).unwrap();
            let seed: [u8; 64] = decoded.try_into().unwrap();
            let (returned_seed, public, hash32) = gen_mlkem768(Some(&seed));
            assert_eq!(returned_seed, seed, "{name}");
            assert_eq!(public.len(), 1184, "{name}");
            assert_eq!(URL_SAFE_NO_PAD.encode(&public), vector["client"].as_str().unwrap(), "{name}");
            assert_eq!(URL_SAFE_NO_PAD.encode(hash32), vector["hash32"].as_str().unwrap(), "{name}");
            let expected = format!("Seed: {encoded_seed}\nClient: {}\nHash32: {}", vector["client"].as_str().unwrap(), vector["hash32"].as_str().unwrap());
            for args in [vec!["-i", encoded_seed], vec!["--i", encoded_seed]] {
                assert_eq!(cmd_mlkem768().execute(&args).unwrap(), expected, "{name}");
            }
            assert_eq!(cmd_mlkem768().execute(&[&format!("-i={encoded_seed}")]).unwrap(), expected);
        }
    }

    #[test]
    fn seed_is_d_followed_by_z_and_z_does_not_change_public_key() {
        let seed = std::array::from_fn(|i| i as u8);
        let mut changed_z = seed;
        changed_z[32..].fill(0);
        let (first_seed, first_public, first_hash) = gen_mlkem768(Some(&seed));
        let (second_seed, second_public, second_hash) = gen_mlkem768(Some(&changed_z));
        assert_ne!(first_seed, second_seed);
        assert_eq!(first_public, second_public);
        assert_eq!(first_hash, second_hash);
        let mut changed_d = seed;
        changed_d[0] ^= 1;
        assert_ne!(first_public, gen_mlkem768(Some(&changed_d)).1);
    }

    #[test]
    fn generated_mlkem768_key_roundtrips_its_seed_and_hash() {
        let command = cmd_mlkem768();
        let output = command.execute(&[]).unwrap();
        let (seed, public, hash) = parse_output(&output);
        assert_eq!(seed.len(), 64);
        assert_eq!(public.len(), 1184);
        assert_eq!(hash.as_slice(), blake3::hash(&public).as_bytes());
        assert_eq!(command.execute(&["-i", &URL_SAFE_NO_PAD.encode(&seed)]).unwrap(), output);
        assert_ne!(parse_output(&command.execute(&[]).unwrap()).0, seed);
        assert_eq!(parse_output(&command.execute(&["-i="]).unwrap()).1.len(), 1184);
    }

    #[test]
    fn invalid_seed_lengths_encoding_and_flags_do_not_generate_keys() {
        for length in [1, 31, 32, 63, 65, 96] {
            let value = URL_SAFE_NO_PAD.encode(vec![0; length]);
            assert_eq!(cmd_mlkem768().execute(&["-i", &value]).unwrap(), "Invalid length of ML-KEM-768 seed.");
        }
        for value in ["!", "\n", "not base64", "====", "AA=="] {
            assert_eq!(cmd_mlkem768().execute(&["-i", value]).unwrap(), "Invalid length of ML-KEM-768 seed.");
        }
        for args in [vec!["-i"], vec!["--i"], vec!["--unknown"], vec!["--std-encoding"]] {
            assert!(cmd_mlkem768().execute(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn repeated_input_uses_the_last_seed_and_go_base64_accepts_newlines_and_trailing_bits() {
        let command = cmd_mlkem768();
        let encoded = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let expected = command.execute(&["-i", &encoded]).unwrap();
        assert_eq!(command.execute(&["-i", "bad", "-i", &encoded]).unwrap(), expected);
        let multiline = format!("{}\r\n{}", &encoded[..40], &encoded[40..]);
        assert_eq!(command.execute(&["-i", &multiline]).unwrap(), expected);
        let mut noncanonical = encoded;
        noncanonical.pop();
        noncanonical.push('B');
        assert_eq!(command.execute(&["-i", &noncanonical]).unwrap(), expected);
    }
}
