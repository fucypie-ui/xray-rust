#[cfg(test)]
mod tests {
    use super::super::sniff::sniff_quic;

    #[test]
    fn test_quic_sniff_empty() {
        assert!(sniff_quic(&[]).is_err());
    }

    fn packet(fixture: &str) -> Vec<u8> {
        hex::decode(fixture.split_whitespace().collect::<String>()).unwrap()
    }

    // Frozen captures from common/protocol/quic/sniff_test.go, not output of a
    // Rust encoder: these exercise key derivation, header protection and AEAD.
    #[test]
    fn go_initial_packet_vectors() {
        for (fixture, domain) in [
            (include_str!("testdata/go_v1.hex"), "www.google.com"),
            (include_str!("testdata/go_v1_pn4.hex"), "www.google.com"),
            (include_str!("testdata/go_v2.hex"), "test.example.com"),
            (include_str!("testdata/go_fragmented.hex"), "play.google.com"),
        ] {
            let data = packet(fixture);
            let original = data.clone();
            assert_eq!(sniff_quic(&data).unwrap().domain(), domain);
            assert_eq!(data, original);
        }
    }

    #[test]
    fn go_fragmented_initial_needs_more_and_accepts_datagram_padding() {
        let data = packet(include_str!("testdata/go_fragmented.hex"));
        let first = &data[..1250];
        let expected = crate::common::protocol::protocol::err_proto_need_more_data().to_string();
        assert_eq!(sniff_quic(first).unwrap_err().to_string(), expected);
        let mut padded = first.to_vec();
        padded.extend_from_slice(&[0; 31]);
        assert_eq!(sniff_quic(&padded).unwrap_err().to_string(), expected);
        padded.extend_from_slice(&data[1250..]);
        assert_eq!(sniff_quic(&padded).unwrap().domain(), "play.google.com");
        let mut reordered = data[1250..].to_vec();
        reordered.extend_from_slice(first);
        assert_eq!(sniff_quic(&reordered).unwrap().domain(), "play.google.com");
        let mut retransmitted = first.to_vec();
        retransmitted.extend_from_slice(&data);
        assert_eq!(sniff_quic(&retransmitted).unwrap().domain(), "play.google.com");
    }

    #[test]
    fn cleartext_client_hello_is_not_an_authenticated_initial() {
        let record = packet(include_str!("../tls/testdata/go_1.hex"));
        let mut fake_quic = record[5..].to_vec();
        // The old heuristic accepted any ClientHello-shaped buffer with its
        // first two high bits set, without checking version or encryption.
        fake_quic[0] = 0xc0;
        assert!(sniff_quic(&fake_quic).is_err());
    }

    #[test]
    fn coalesced_non_initial_packet_is_skipped() {
        // v1 Handshake long header, empty CIDs, four-byte protected payload.
        let mut data = vec![0xe0, 0, 0, 0, 1, 0, 0, 4, 0, 0, 0, 0];
        data.extend_from_slice(&packet(include_str!("testdata/go_v1.hex")));
        assert_eq!(sniff_quic(&data).unwrap().domain(), "www.google.com");
    }

    #[test]
    fn authenticated_initial_rejects_tampering_and_every_truncation() {
        let data = packet(include_str!("testdata/go_v1.hex"));
        for len in 0..data.len() {
            assert!(sniff_quic(&data[..len]).is_err(), "truncation at {len}");
        }
        let mut tampered = data.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sniff_quic(&tampered).is_err());
        for invalid in [
            "cb00000001081c8c6d5aeb53d54400000090709b8600000000000000000000000000000000",
            "cb00000001081c8c6d5aeb53d54400000090709b86",
        ] {
            assert!(sniff_quic(&hex::decode(invalid).unwrap()).is_err());
        }
    }
}
