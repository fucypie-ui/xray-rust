use super::Sniffer;
use crate::common::common::ERR_NO_CLUE;
use crate::common::errors::Error;
use crate::common::net::Network;
use crate::common::protocol::protocol::err_proto_need_more_data;

const TLS_VECTORS: [(&str, &str); 4] = [
    (include_str!("../../common/protocol/tls/testdata/go_1.hex"), "c.s-microsoft.com"),
    (include_str!("../../common/protocol/tls/testdata/go_2.hex"), "www07.clicktale.net"),
    (include_str!("../../common/protocol/tls/testdata/go_3.hex"), "dogfish"),
    (include_str!("../../common/protocol/tls/testdata/go_4.hex"), "10.42.0.243"),
];
const QUIC_VECTORS: [(&str, &str); 4] = [
    (include_str!("../../common/protocol/quic/testdata/go_v1.hex"), "www.google.com"),
    (include_str!("../../common/protocol/quic/testdata/go_v1_pn4.hex"), "www.google.com"),
    (include_str!("../../common/protocol/quic/testdata/go_v2.hex"), "test.example.com"),
    (include_str!("../../common/protocol/quic/testdata/go_fragmented.hex"), "play.google.com"),
];

fn packet(fixture: &str) -> Vec<u8> {
    hex::decode(fixture.split_whitespace().collect::<String>()).unwrap()
}

fn assert_error(sniffer: &Sniffer, payload: &[u8], network: Network, expected: &str) {
    let error = sniffer.sniff(payload, network).unwrap_err();
    assert!(matches!(error, Error::Protocol(ref message) if message == expected), "{error}");
}

fn need_more_data_message() -> String {
    match err_proto_need_more_data() {
        Error::Protocol(message) => message,
        error => panic!("unexpected need-more-data error: {error}"),
    }
}

#[test]
fn go_tls_records_reach_dispatcher_and_public_sni_helper() {
    let sniffer = Sniffer::new(None);
    for (fixture, domain) in TLS_VECTORS {
        let mut data = packet(fixture);
        let original = data.clone();
        let result = sniffer.sniff(&data, Network::Tcp).unwrap();
        assert_eq!(result.protocol(), "tls");
        assert_eq!(result.domain(), domain);
        assert_eq!(Sniffer::sniff_tls_sni(&data).as_deref(), Some(domain));
        assert_eq!(data, original);
        assert!(sniffer.sniff(&data, Network::Udp).is_err());
        data.extend_from_slice(&[0xff, 0, 0xff]);
        assert_eq!(sniffer.sniff(&data, Network::Tcp).unwrap().domain(), domain);
    }
}

#[test]
fn go_quic_initials_reach_dispatcher_and_public_sni_helper() {
    let sniffer = Sniffer::new(None);
    for (fixture, domain) in QUIC_VECTORS {
        let data = packet(fixture);
        let original = data.clone();
        let result = sniffer.sniff(&data, Network::Udp).unwrap();
        assert_eq!(result.protocol(), "quic");
        assert_eq!(result.domain(), domain);
        assert_eq!(Sniffer::sniff_quic_sni(&data).as_deref(), Some(domain));
        assert_eq!(data, original);
        assert!(sniffer.sniff(&data, Network::Tcp).is_err());
    }
}

#[test]
fn tls_every_record_truncation_is_no_clue_and_retries_complete() {
    let sniffer = Sniffer::new(None);
    for (fixture, domain) in TLS_VECTORS {
        let data = packet(fixture);
        for len in 0..data.len() {
            assert_error(&sniffer, &data[..len], Network::Tcp, ERR_NO_CLUE);
            assert!(Sniffer::sniff_tls_sni(&data[..len]).is_none());
            assert_eq!(Sniffer::is_incomplete_tls_client_hello(&data[..len]), len != 0);
        }
        assert!(!Sniffer::is_incomplete_tls_client_hello(&data));
        assert_eq!(sniffer.sniff(&data, Network::Tcp).unwrap().domain(), domain);
    }
    assert!(!Sniffer::is_incomplete_tls_client_hello(b"GET /"));
    assert!(!Sniffer::is_incomplete_tls_client_hello(&[0x16, 2]));
}

#[test]
fn invalid_synthetic_tls_record_lengths_are_not_accepted() {
    let sniffer = Sniffer::new(None);
    let data = packet(TLS_VECTORS[0].0);
    for length in [0, u16::try_from(data.len()).unwrap()] {
        let mut invalid = data.clone();
        invalid[3..5].copy_from_slice(&length.to_be_bytes());
        assert_error(&sniffer, &invalid, Network::Tcp, ERR_NO_CLUE);
        assert!(Sniffer::sniff_tls_sni(&invalid).is_none());
    }
}

#[test]
fn tls_malformed_sni_lengths_and_cipher_suites_are_rejected() {
    let sniffer = Sniffer::new(None);
    let data = packet(TLS_VECTORS[0].0);
    let name = TLS_VECTORS[0].1.as_bytes();
    let offset = data.windows(name.len()).position(|window| window == name).unwrap();
    for index in [offset - 1, offset - 3, offset - 6, 45] {
        let mut invalid = data.clone();
        // Name length, name type, extension length, odd cipher-suite length.
        invalid[index] ^= 1;
        assert_error(&sniffer, &invalid, Network::Tcp, "unknown content");
        assert!(Sniffer::sniff_tls_sni(&invalid).is_none());
    }
    let mut trailing_dot = data.clone();
    trailing_dot[offset + name.len() - 1] = b'.';
    assert_error(&sniffer, &trailing_dot, Network::Tcp, "unknown content");
}

#[test]
fn tls_go_no_clue_and_protocol_need_more_data_stay_distinct() {
    let sniffer = Sniffer::new(None);
    let mut data = packet(TLS_VECTORS[0].0);
    // Go ReadClientHello defers an invalid session-ID length as ErrNoClue.
    data[43] = 33;
    assert_error(&sniffer, &data, Network::Tcp, ERR_NO_CLUE);
    let mut data = packet(TLS_VECTORS[0].0);
    let name = TLS_VECTORS[0].1.as_bytes();
    let offset = data.windows(name.len()).position(|window| window == name).unwrap();
    for byte in 0..=b' ' {
        data[offset + name.len() - 1] = byte;
        assert_error(&sniffer, &data, Network::Tcp, &need_more_data_message());
        assert!(Sniffer::sniff_tls_sni(&data).is_none());
    }
}

#[test]
fn quic_fragment_retries_preserve_need_more_data_and_authentication() {
    let sniffer = Sniffer::new(None);
    let data = packet(QUIC_VECTORS[3].0);
    let mut buffered = data[..1250].to_vec();
    assert_error(&sniffer, &buffered, Network::Udp, &need_more_data_message());
    assert!(Sniffer::sniff_quic_sni(&buffered).is_none());
    buffered.extend_from_slice(&[0; 31]);
    assert_error(&sniffer, &buffered, Network::Udp, &need_more_data_message());
    buffered.extend_from_slice(&data[1250..]);
    assert_eq!(sniffer.sniff(&buffered, Network::Udp).unwrap().domain(), "play.google.com");
    let mut reversed = data[1250..].to_vec();
    reversed.extend_from_slice(&data[..1250]);
    assert_eq!(sniffer.sniff(&reversed, Network::Udp).unwrap().domain(), "play.google.com");
    let mut retransmitted = data[..1250].to_vec();
    retransmitted.extend_from_slice(&data);
    assert_eq!(sniffer.sniff(&retransmitted, Network::Udp).unwrap().domain(), "play.google.com");
}

#[test]
fn quic_tampered_captures_are_rejected_by_dispatcher_and_helper() {
    let sniffer = Sniffer::new(None);
    for (fixture, _) in QUIC_VECTORS {
        let mut data = packet(fixture);
        data[100] ^= 1; // Authenticated ciphertext, not a header or UDP padding.
        assert_error(&sniffer, &data, Network::Udp, "unknown content");
        assert!(Sniffer::sniff_quic_sni(&data).is_none());
    }
    let mut data = packet(QUIC_VECTORS[0].0);
    *data.last_mut().unwrap() ^= 1; // First capture ends with its AEAD tag.
    assert_error(&sniffer, &data, Network::Udp, "unknown content");
    assert!(Sniffer::sniff_quic_sni(&data).is_none());
}

#[test]
fn cleartext_tls_at_old_quic_heuristic_offset_is_rejected() {
    let sniffer = Sniffer::new(None);
    let tls = packet(TLS_VECTORS[0].0);
    let mut fake = vec![0; 40];
    fake[0] = 0xc0;
    fake.extend_from_slice(&tls);
    assert_eq!(Sniffer::sniff_tls_sni(&fake[40..]).as_deref(), Some(TLS_VECTORS[0].1));
    assert_error(&sniffer, &fake, Network::Udp, "unknown content");
    assert!(Sniffer::sniff_quic_sni(&fake).is_none());
    // A real Initial with an injected cleartext record still must pass AEAD.
    let mut injected = packet(QUIC_VECTORS[0].0);
    injected[40..40 + tls.len()].copy_from_slice(&tls);
    assert_error(&sniffer, &injected, Network::Udp, "unknown content");
    assert!(Sniffer::sniff_quic_sni(&injected).is_none());
}

#[test]
fn quic_every_initial_truncation_is_rejected() {
    let sniffer = Sniffer::new(None);
    let data = packet(QUIC_VECTORS[0].0);
    for len in 0..data.len() {
        assert!(sniffer.sniff(&data[..len], Network::Udp).is_err(), "truncation at {len}");
    }
}

fn incomplete_initial() -> Vec<u8> {
    let mut data = vec![0xc0, 0, 0, 0, 1, 8];
    data.extend_from_slice(&[1; 8]);
    data.push(8);
    data.extend_from_slice(&[2; 8]);
    data.extend_from_slice(&[0, 0x40, 0x40, 0, 0, 0, 0]); // No token; 64-byte payload missing.
    data
}

#[test]
fn quic_incomplete_payload_is_no_clue_but_truncated_header_is_rejected() {
    let sniffer = Sniffer::new(None);
    let data = incomplete_initial();
    assert_error(&sniffer, &data, Network::Udp, ERR_NO_CLUE);
    assert_error(&sniffer, &data[..23], Network::Udp, "unknown content"); // Missing token length.
    assert_error(&sniffer, &data[..25], Network::Udp, "unknown content"); // Incomplete varint.
    let mut missing_token = data[..23].to_vec();
    missing_token.extend_from_slice(&[9, 1, 2]);
    assert_error(&sniffer, &missing_token, Network::Udp, "unknown content");
    let mut unknown_version = data.clone();
    unknown_version[4] = 42;
    assert_error(&sniffer, &unknown_version, Network::Udp, "unknown content");
}

#[test]
fn quic_later_incomplete_packet_does_not_hide_prior_authentication_failure() {
    let sniffer = Sniffer::new(None);
    let fragmented = packet(QUIC_VECTORS[3].0);
    let mut data = fragmented[..1250].to_vec();
    data.extend_from_slice(&[0; 17]);
    data.extend_from_slice(&incomplete_initial());
    assert_error(&sniffer, &data, Network::Udp, ERR_NO_CLUE);
    data[100] ^= 1;
    assert_error(&sniffer, &data, Network::Udp, "unknown content");
}

fn initial_with_frames(frames: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::aes::Aes128;
    use aes_gcm::aes::cipher::{Block, BlockEncrypt};
    use aes_gcm::Aes128Gcm;

    // RFC 9001 Appendix A.1 client keys for this fixed DCID. These do not
    // depend on the Rust decoder or its HKDF implementation.
    let key = hex::decode("1f369613dd76d5467730efcbe3b1a22d").unwrap();
    let iv: [u8; 12] = hex::decode("fa044b2f42a3fd3b46fb255c").unwrap().try_into().unwrap();
    let hp_key = hex::decode("9f50449e04a0e810283a1e9933adedd2").unwrap();
    let mut packet = vec![0xc0, 0, 0, 0, 1, 8];
    packet.extend_from_slice(&hex::decode("8394c8f03e515708").unwrap());
    packet.extend_from_slice(&[0, 0]); // Empty SCID and token.
    let length = u8::try_from(1 + frames.len() + 16).unwrap();
    assert!(length < 64);
    packet.push(length);
    let pn_offset = packet.len();
    packet.push(0);
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher.encrypt(&iv.into(), Payload { msg: frames, aad: &packet }).unwrap();
    packet.extend_from_slice(&ciphertext);
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let mut mask = Block::<Aes128>::from(sample);
    Aes128::new_from_slice(&hp_key).unwrap().encrypt_block(&mut mask);
    packet[0] ^= mask[0] & 0x0f;
    packet[pn_offset] ^= mask[1];
    packet
}

#[test]
fn quic_later_incomplete_packet_does_not_hide_malformed_authenticated_frames() {
    let sniffer = Sniffer::new(None);
    assert_error(&sniffer, &initial_with_frames(&[0; 20]), Network::Udp, &need_more_data_message());
    for frame in [2, 3, 6, 0x1c] {
        let mut frames = vec![0; 20];
        frames.push(frame); // Valid AEAD, but missing the frame's required fields.
        let mut data = initial_with_frames(&frames);
        assert!(matches!(crate::common::protocol::quic::sniff::sniff_quic(&data),
            Err(Error::Protocol(message)) if message == "truncated quic data"));
        assert_error(&sniffer, &data, Network::Udp, "unknown content");
        data.extend_from_slice(&incomplete_initial());
        assert_error(&sniffer, &data, Network::Udp, "unknown content");
    }
}

#[test]
fn quic_incomplete_classification_validates_packets_without_resetting_stream_holes() {
    let sniffer = Sniffer::new(None);
    // A CRYPTO byte at offset 32000 keeps the combined stream incomplete,
    // even when a later packet contains a complete standalone ClientHello.
    let mut data = initial_with_frames(&[6, 0x80, 0, 0x7d, 0, 1, 0]);
    data.extend_from_slice(&packet(QUIC_VECTORS[0].0));
    assert_error(&sniffer, &data, Network::Udp, &need_more_data_message());
    data.extend_from_slice(&incomplete_initial());
    assert_error(&sniffer, &data, Network::Udp, ERR_NO_CLUE);
}

#[test]
fn quic_coalesced_handshake_is_skipped_before_initial() {
    let sniffer = Sniffer::new(None);
    let mut data = vec![0xe0, 0, 0, 0, 1, 0, 0, 4, 0, 0, 0, 0];
    // Go considers parsed QUIC without a ClientHello a protocol match.
    assert_error(&sniffer, &data, Network::Udp, &need_more_data_message());
    data.extend_from_slice(&packet(QUIC_VECTORS[0].0));
    assert_eq!(sniffer.sniff(&data, Network::Udp).unwrap().domain(), "www.google.com");
}

#[test]
fn go_pending_no_clue_is_returned_only_after_other_sniffers_run() {
    let sniffer = Sniffer::new(None);
    for network in [Network::Tcp, Network::Udp] {
        for payload in [&b""[..], &b"x"[..], &b"not a header"[..]] {
            assert_error(&sniffer, payload, network, ERR_NO_CLUE);
        }
        assert_error(&sniffer, &[0xff; 40], network, "unknown content");
    }
    assert_error(&sniffer, b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n", Network::Tcp, ERR_NO_CLUE);
    let http = b"GET / HTTP/1.1\r\nHost: later.example\r\n\r\n";
    assert_eq!(sniffer.sniff(http, Network::Tcp).unwrap().domain(), "later.example");
}

#[test]
fn go_aggregation_prioritizes_success_need_more_data_and_pending() {
    fn pending(_: &[u8]) -> crate::common::errors::Result<super::SniffResult> {
        Err(super::no_clue())
    }
    fn rejected(_: &[u8]) -> crate::common::errors::Result<super::SniffResult> {
        Err(Error::Protocol("not this protocol".into()))
    }
    fn need_more(_: &[u8]) -> crate::common::errors::Result<super::SniffResult> {
        Err(err_proto_need_more_data())
    }
    fn must_not_run(_: &[u8]) -> crate::common::errors::Result<super::SniffResult> {
        panic!("sniffer ran after a conclusive result");
    }
    let http = b"GET / HTTP/1.1\r\nHost: priority.example\r\n\r\n";
    assert_eq!(super::sniff_content(http, &[pending, Sniffer::sniff_http, must_not_run]).unwrap().domain(), "priority.example");
    let error = super::sniff_content(http, &[pending, need_more, must_not_run]).unwrap_err();
    assert!(super::is_need_more_data(&error));
    let error = super::sniff_content(http, &[rejected, need_more, Sniffer::sniff_http]).unwrap_err();
    assert!(super::is_need_more_data(&error));
    let error = super::sniff_content(http, &[pending, rejected]).unwrap_err();
    assert!(matches!(error, Error::Protocol(message) if message == ERR_NO_CLUE));
    let error = super::sniff_content(http, &[rejected, rejected]).unwrap_err();
    assert!(matches!(error, Error::Protocol(message) if message == "unknown content"));
}

#[test]
fn http_methods_hosts_and_binary_bodies_keep_existing_behavior() {
    let sniffer = Sniffer::new(None);
    for method in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE"] {
        let mut payload = format!("{method} / HTTP/1.1\r\nhOsT: Mixed.Example:8080\r\n\r\n").into_bytes();
        payload.extend_from_slice(&[0xff, 0, 0xfe]);
        let result = sniffer.sniff(&payload, Network::Tcp).unwrap();
        assert_eq!(result.protocol(), "http");
        assert_eq!(result.domain(), "Mixed.Example");
    }
    assert_eq!(sniffer.sniff(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", Network::Tcp).unwrap().domain(), "2001:db8::1");
    assert_eq!(Sniffer::sniff_http_host(b"GET / HTTP/1.1\r\nHost: partial.example").as_deref(), Some("partial.example"));
}

#[test]
fn multibyte_http_header_crossing_byte_five_does_not_panic() {
    let sniffer = Sniffer::new(None);
    // Byte 5 is inside the second é in this valid UTF-8 header line.
    let payload = "GET / HTTP/1.1\r\nX-éé: ignored\r\nhOsT: safe.example:8080\r\n\r\n";
    assert_eq!(Sniffer::sniff_http_host(payload.as_bytes()).as_deref(), Some("safe.example"));
    let result = sniffer.sniff(payload.as_bytes(), Network::Tcp).unwrap();
    assert_eq!(result.protocol(), "http");
    assert_eq!(result.domain(), "safe.example");
    let no_host = "GET / HTTP/1.1\r\nX-éé: ignored\r\n\r\n";
    assert!(Sniffer::sniff_http_host(no_host.as_bytes()).is_none());
    assert_error(&sniffer, no_host.as_bytes(), Network::Tcp, ERR_NO_CLUE);
}

#[test]
fn bittorrent_and_utp_fallback_keep_existing_network_behavior() {
    let sniffer = Sniffer::new(None);
    let mut bittorrent = vec![19];
    bittorrent.extend_from_slice(b"BitTorrent protocol");
    bittorrent.extend_from_slice(&[0; 48]);
    let mut utp = vec![0; 20];
    utp[0] = 0x41;
    for network in [Network::Tcp, Network::Udp] {
        let result = sniffer.sniff(&bittorrent, network).unwrap();
        assert_eq!(result.protocol(), "bittorrent");
        assert!(result.domain().is_empty());
        let result = sniffer.sniff(&utp, network).unwrap();
        assert_eq!(result.protocol(), "utp");
        assert!(result.domain().is_empty());
    }
}

#[test]
fn shared_sniffer_does_not_retain_one_connections_protocol() {
    let sniffer = Sniffer::new(None);
    let fragmented = packet(QUIC_VECTORS[3].0);
    assert_error(&sniffer, &fragmented[..1250], Network::Udp, &need_more_data_message());
    assert_eq!(sniffer.sniff(b"GET / HTTP/1.1\r\nHost: independent.example\r\n\r\n", Network::Tcp).unwrap().domain(), "independent.example");
    assert_eq!(sniffer.sniff(&packet(TLS_VECTORS[0].0), Network::Tcp).unwrap().protocol(), "tls");
    assert_eq!(sniffer.sniff(&fragmented, Network::Udp).unwrap().protocol(), "quic");
}
