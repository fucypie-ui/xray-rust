use crate::common::errors::{Error, Result};
use crate::main::commands::base::command::Command;
use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Match Go's non-strict DecodeString, including ignored CR/LF and returned
/// partial output. The Go commands deliberately ignore the decoding error and
/// validate the decoded length. Decode in quanta to preserve that behavior.
pub(super) fn decode_go_base64(input: &str, standard: bool) -> Vec<u8> {
    let config = GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(if standard {
            DecodePaddingMode::RequireCanonical
        } else {
            DecodePaddingMode::RequireNone
        });
    let alphabet = if standard { &alphabet::STANDARD } else { &alphabet::URL_SAFE };
    let engine = GeneralPurpose::new(alphabet, config);
    let input: Vec<u8> = input.bytes().filter(|byte| !matches!(byte, b'\r' | b'\n')).collect();
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for quantum in input.chunks(4) {
        let Ok(decoded) = engine.decode(quantum) else { break };
        output.extend_from_slice(&decoded);
        if standard && quantum.contains(&b'=') {
            break;
        }
    }
    output
}

pub fn gen_curve25519(input_key: Option<&[u8]>) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let mut private = [0u8; 32];
    match input_key {
        Some(input) if input.len() == 32 => private.copy_from_slice(input),
        Some(input) if !input.is_empty() => {
            return Err(Error::Config("Invalid length of X25519 private key.".into()));
        }
        _ => rand::rng().fill_bytes(&mut private),
    }
    // Print the clamped scalar, rather than just relying on X25519 to clamp
    // internally. This is the private-key representation printed by Go.
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = *PublicKey::from(&StaticSecret::from(private)).as_bytes();
    let hash32 = *blake3::hash(&public).as_bytes();
    Ok((private, public, hash32))
}

pub(super) fn format_curve25519(input: &str, standard: bool) -> Result<String> {
    let private = if input.is_empty() {
        None
    } else {
        let decoded = decode_go_base64(input, standard);
        if decoded.len() != 32 {
            // Like Go's Curve25519Genkey, print the diagnostic and return.
            return Ok("Invalid length of X25519 private key.".into());
        }
        Some(decoded)
    };
    let (private, public, hash32) = gen_curve25519(private.as_deref())?;
    let encode = |bytes: &[u8]| {
        if standard { STANDARD.encode(bytes) } else { URL_SAFE_NO_PAD.encode(bytes) }
    };
    Ok(format!(
        "PrivateKey: {}\nPassword (PublicKey): {}\nHash32: {}",
        encode(&private), encode(&public), encode(&hash32),
    ))
}

/// Retain the existing Rust alias, with the same validated options and output
/// as the actual Go x25519 command.
pub fn cmd_curve25519() -> Command {
    let mut command = super::x25519::cmd_x25519();
    command.name = "curve25519".into();
    command.usage = "xray curve25519 [-i key] [--std-encoding]".into();
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve25519_matches_go_private_public_and_blake3_fixtures() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testing/crypto-reference/vectors.json");
        let json = std::fs::read_to_string(path)
            .expect("freeze the independent Go vectors using testing/crypto-reference/generate.sh on Linux");
        let fixtures: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vectors = fixtures["x25519"].as_array().unwrap();
        assert_eq!(vectors.len(), 5);
        for vector in vectors {
            let name = vector["name"].as_str().unwrap();
            let input = URL_SAFE_NO_PAD.decode(vector["input"].as_str().unwrap()).unwrap();
            let (private, public, hash32) = gen_curve25519(Some(&input)).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.encode(private), vector["private_key"].as_str().unwrap(), "{name}");
            assert_eq!(URL_SAFE_NO_PAD.encode(public), vector["public_key"].as_str().unwrap(), "{name}");
            assert_eq!(URL_SAFE_NO_PAD.encode(hash32), vector["hash32"].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn rfc7748_alice_and_clamping_invariance() {
        let input = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let (private, public, hash32) = gen_curve25519(Some(&input)).unwrap();
        assert_eq!(hex::encode(private), "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a");
        assert_eq!(hex::encode(public), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hash32, *blake3::hash(&public).as_bytes());
        let mut equivalent = private;
        equivalent[0] |= 7;
        equivalent[31] ^= 192;
        assert_eq!(gen_curve25519(Some(&equivalent)).unwrap(), (private, public, hash32));
    }

    #[test]
    fn generated_curve25519_keys_are_clamped_reproducible_and_fresh() {
        let first = gen_curve25519(None).unwrap();
        let (private, public, hash32) = first;
        assert_eq!(private[0] & 7, 0);
        assert_eq!(private[31] & 192, 64);
        assert_eq!(public, *PublicKey::from(&StaticSecret::from(private)).as_bytes());
        assert_eq!(hash32, *blake3::hash(&public).as_bytes());
        assert_eq!(gen_curve25519(Some(&private)).unwrap(), first);
        assert_ne!(gen_curve25519(None).unwrap().0, private);
        assert_ne!(gen_curve25519(Some(&[])).unwrap().0, private);
        for length in [1, 16, 31, 33, 64] {
            assert!(gen_curve25519(Some(&vec![0; length])).is_err());
        }
    }

    #[test]
    fn go_decoder_keeps_partial_quanta_and_accepts_noncanonical_bits() {
        assert_eq!(decode_go_base64("Z\rm\n9vYg", false), b"foob");
        assert_eq!(decode_go_base64("Zh", false), b"f");
        assert_eq!(decode_go_base64("Zh==", true), b"f");
        assert_eq!(decode_go_base64("Zm9v!AAA", false), b"foo");
        assert_eq!(decode_go_base64("Zm9vYg==!", true), b"foob");
        assert_eq!(decode_go_base64("Zm9vYg==", false), b"foo");
        assert_eq!(decode_go_base64("Zm9vYg", true), b"foo");
        assert!(decode_go_base64("Zg=", true).is_empty());
        assert!(decode_go_base64("Zg=!", true).is_empty());
        assert!(decode_go_base64(" A", false).is_empty());
    }

    #[test]
    fn curve25519_alias_uses_validated_input_and_flags() {
        let input = URL_SAFE_NO_PAD.encode([255u8; 32]);
        let expected = format_curve25519(&input, false).unwrap();
        assert_eq!(cmd_curve25519().execute(&["-i", &input]).unwrap(), expected);
        assert!(cmd_curve25519().execute(&["--unknown"]).is_err());
        assert!(cmd_curve25519().execute(&["-i"]).is_err());
    }
}
