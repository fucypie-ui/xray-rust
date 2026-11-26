use super::{CryptionReader, CryptionWriter, StreamCipher, new_chacha20_stream};
use std::io::Cursor;

// Copied from Xray-core/common/crypto/chacha20_test.go, TestChaCha20Stream.
const ZERO_KEY_STREAM: &str = concat!(
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed",
    "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
);

#[test]
fn chacha20_matches_go_vectors_for_both_nonce_lengths() {
    let cases = [
        ([0u8; 32], vec![0u8; 8], ZERO_KEY_STREAM.to_string()),
        ([0u8; 32], vec![0u8; 12], ZERO_KEY_STREAM[..128].to_string()),
        ([0x55u8; 32], vec![0x55u8; 8], concat!(
            "bea9411aa453c5434a5ae8c92862f564396855a9ea6e22d6d3b50ae1b3663311",
            "a4a3606c671d605ce16c3aece8e61ea145c59775017bee2fa6f88afc758069f7",
            "e0b8f676e644216f4d2a3422d7fa36c6c4931aca950e9da42788e6d0b6d1cd83",
            "8ef652e97b145b14871eae6c6804c7004db5ac2fce4c68c726d004b10fcaba86",
        ).to_string()),
    ];
    for (key, nonce, expected) in cases {
        let expected = hex::decode(expected).unwrap();
        // Exercise every possible two-write split, including block boundaries.
        for split in 0..=expected.len() {
            let mut actual = vec![0u8; expected.len()];
            let mut cipher = new_chacha20_stream(&key, &nonce).unwrap();
            cipher.encrypt(&mut actual[..split]).unwrap();
            cipher.encrypt(&mut []).unwrap();
            cipher.encrypt(&mut actual[split..]).unwrap();
            assert_eq!(actual, expected, "nonce {} bytes, split {split}", nonce.len());
        }
    }
}

#[test]
fn chacha20_fragmentation_does_not_change_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(4097).collect();
    let mut expected = plaintext.clone();
    new_chacha20_stream(&key, &nonce).unwrap().encrypt(&mut expected).unwrap();
    for chunk_size in [1, 2, 3, 7, 31, 63, 64, 65, 127, 1023] {
        let mut actual = plaintext.clone();
        let mut cipher = new_chacha20_stream(&key, &nonce).unwrap();
        for chunk in actual.chunks_mut(chunk_size) {
            cipher.encrypt(chunk).unwrap();
        }
        assert_eq!(actual, expected, "write size {chunk_size}");
        let mut cipher = new_chacha20_stream(&key, &nonce).unwrap();
        for chunk in actual.chunks_mut(chunk_size + 1) {
            cipher.decrypt(chunk).unwrap();
        }
        assert_eq!(actual, plaintext, "read size {}", chunk_size + 1);
    }
}

#[test]
fn chacha20_set_counter_discards_cached_keystream() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut cipher = new_chacha20_stream(&key, &nonce).unwrap();
    cipher.encrypt(&mut [0u8; 3]).unwrap();
    cipher.set_counter(0);
    let mut actual = [0u8; 64];
    cipher.encrypt(&mut actual).unwrap();
    assert_eq!(hex::encode(actual), &ZERO_KEY_STREAM[..128]);
}

#[test]
fn chacha20_rejects_invalid_key_and_nonce_lengths() {
    for size in [0, 16, 31, 33, 64] {
        assert!(new_chacha20_stream(&vec![0; size], &[0; 12]).is_err());
    }
    for size in [0, 7, 9, 11, 13, 24] {
        assert!(new_chacha20_stream(&[0; 32], &vec![0; size]).is_err());
    }
}

#[tokio::test]
async fn chacha20_cryption_io_handles_different_read_and_write_boundaries() {
    let key = [0x53u8; 32];
    let nonce = [0x17u8; 8];
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(1025).collect();
    let mut sink = Cursor::new(Vec::new());
    let mut writer = CryptionWriter::new(&mut sink, new_chacha20_stream(&key, &nonce).unwrap());
    for chunk in plaintext.chunks(7) {
        writer.write(&mut chunk.to_vec()).await.unwrap();
    }
    let mut reader = CryptionReader::new(
        Cursor::new(sink.into_inner()),
        new_chacha20_stream(&key, &nonce).unwrap(),
    );
    let mut actual = Vec::new();
    let mut buffer = [0u8; 11];
    loop {
        let count = reader.read(&mut buffer).await.unwrap();
        if count == 0 { break; }
        actual.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(actual, plaintext);
}
