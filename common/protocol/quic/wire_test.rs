use super::{CryptoStream, PacketReader, expand_label, version_spec};
use hkdf::Hkdf;
use sha2::Sha256;

#[test]
fn initial_key_derivation_matches_published_v1_values() {
    // RFC 9001 Appendix A.1: the same salt, DCID and labels used by Go.
    let dcid = hex::decode("8394c8f03e515708").unwrap();
    let (salt, label, packet_type) = version_spec(1).unwrap();
    assert_eq!((label, packet_type), ("quic", 0));
    let initial = Hkdf::<Sha256>::new(Some(salt), &dcid);
    let secret = expand_label::<32>(&initial, "client in").unwrap();
    assert_eq!(hex::encode(secret), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    let client = Hkdf::<Sha256>::from_prk(&secret).unwrap();
    assert_eq!(hex::encode(expand_label::<16>(&client, "quic key").unwrap()), "1f369613dd76d5467730efcbe3b1a22d");
    assert_eq!(hex::encode(expand_label::<12>(&client, "quic iv").unwrap()), "fa044b2f42a3fd3b46fb255c");
    assert_eq!(hex::encode(expand_label::<16>(&client, "quic hp").unwrap()), "9f50449e04a0e810283a1e9933adedd2");
    assert_eq!(version_spec(0xff00_001d).unwrap().1, "quic");
    assert_eq!(version_spec(0x6b33_43cf).unwrap().1, "quicv2");
    assert!(version_spec(0).is_err());
}

#[test]
fn short_varint_handles_all_encodings_and_go_size_limit() {
    for (wire, value) in [
        (&[0x25][..], 37),
        (&[0x7f, 0xff][..], 16383),
        (&[0x80, 0, 0xff, 0xff][..], 65535),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 37][..], 37),
    ] {
        let mut reader = PacketReader::new(wire);
        assert_eq!(reader.varint().unwrap(), value);
        assert_eq!(reader.pos, wire.len());
        for len in 0..wire.len() {
            assert!(PacketReader::new(&wire[..len]).varint().is_err());
        }
    }
    for wire in [&[0x80, 1, 0, 0][..], &[0xff; 8][..]] {
        assert!(PacketReader::new(wire).varint().is_err());
    }
}

#[test]
fn crypto_frames_reassemble_out_of_order_and_track_holes() {
    let mut crypto = CryptoStream::default();
    crypto.read_frames(&[6, 3, 3, b'd', b'e', b'f']).unwrap();
    assert_eq!(crypto.data, b"\0\0\0def");
    assert_eq!(crypto.received, [false, false, false, true, true, true]);
    crypto.read_frames(&[6, 0, 3, b'a', b'b', b'c']).unwrap();
    assert_eq!(crypto.data, b"abcdef");
    assert!(crypto.received.iter().all(|received| *received));
    // Retransmission/overlap does not truncate the stream.
    crypto.read_frames(&[6, 1, 2, b'b', b'c']).unwrap();
    assert_eq!(crypto.data, b"abcdef");
}

#[test]
fn initial_frames_skip_ack_ranges_ecn_close_and_padding() {
    let mut crypto = CryptoStream::default();
    crypto.read_frames(&[
        0, 0, 1, // PADDING, PING
        2, 9, 0, 1, 0, 0, 0, // ACK with one range
        3, 9, 0, 0, 0, 0, 0, 0, // ACK_ECN with three counts
        0x1c, 0, 6, 2, b'o', b'k', // transport CONNECTION_CLOSE
        6, 0, 1, b'x',
    ]).unwrap();
    assert_eq!(crypto.data, b"x");
}

#[test]
fn malformed_initial_frames_are_rejected_without_large_allocations() {
    for wire in [
        &[2][..], // truncated ACK
        &[2, 0, 0, 1, 0][..], // missing ACK range
        &[3, 0, 0, 0, 0, 0, 0][..], // missing third ECN count
        &[6, 0, 2, b'a'][..], // truncated CRYPTO
        &[6, 0x80, 0, 0x7f, 0xff, 1, b'a'][..], // exceeds reassembly limit
        &[6, 0x80, 1, 0, 0, 0][..], // offset exceeds Go short-varint limit
        &[0x1c, 0, 0, 2, b'a'][..], // truncated close reason
        &[0x1d, 0, 0][..], // application close is not valid in Initial
        &[0x08, 0, 0][..], // STREAM is not valid in Initial
    ] {
        let mut crypto = CryptoStream::default();
        assert!(crypto.read_frames(wire).is_err(), "{wire:?}");
        assert!(crypto.data.is_empty());
    }
}
