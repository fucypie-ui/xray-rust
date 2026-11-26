#[cfg(test)]
mod tests {
    use super::super::sniff::{read_client_hello, sniff_tls};

    #[test]
    fn go_tls_record_vectors_and_truncation() {
        for (fixture, domain) in [
            (include_str!("testdata/go_1.hex"), "c.s-microsoft.com"),
            (include_str!("testdata/go_2.hex"), "www07.clicktale.net"),
            (include_str!("testdata/go_3.hex"), "dogfish"),
            (include_str!("testdata/go_4.hex"), "10.42.0.243"),
        ] {
            let mut data = hex::decode(fixture.split_whitespace().collect::<String>()).unwrap();
            assert_eq!(sniff_tls(&data).unwrap().domain(), domain);
            for len in 0..data.len() {
                assert!(sniff_tls(&data[..len]).is_err(), "truncation at {len}");
            }
            // Go sniffs only the first record, even when later bytes are not TLS.
            data.extend_from_slice(&[0xff, 0, 0xff]);
            assert_eq!(sniff_tls(&data).unwrap().domain(), domain);
        }
    }

    // A minimal ClientHello with the layout consumed by Go ReadClientHello.
    // The SNI extension bytes are supplied directly, including all lengths,
    // so malformed wire lengths are tested independently of any TLS encoder.
    fn hello(extensions: &[u8], ciphers: &[u8]) -> Vec<u8> {
        let mut data = vec![1, 0, 0, 0, 3, 3];
        data.extend_from_slice(&[0; 32]);
        data.push(0); // Session ID length
        data.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
        data.extend_from_slice(ciphers);
        data.extend_from_slice(&[1, 0]); // null compression
        data.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        data.extend_from_slice(extensions);
        let len = (data.len() - 4) as u32;
        data[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        data
    }

    #[test]
    fn go_client_hello_rejects_malformed_sni_and_cipher_lengths() {
        for extension in [
            // Empty HostName (RFC 6066).
            &[0, 0, 0, 5, 0, 3, 0, 0, 0][..],
            // namesLen is smaller than the actual list.
            &[0, 0, 0, 6, 0, 0, 0, 0, 1, b'a'][..],
            // Trailing dot is forbidden in a server_name HostName.
            &[0, 0, 0, 7, 0, 5, 0, 0, 2, b'a', b'.'][..],
            // Declared HostName length exceeds the extension.
            &[0, 0, 0, 6, 0, 4, 0, 0, 2, b'a'][..],
            // Unknown name type followed by a truncated name header.
            &[0, 0, 0, 7, 0, 5, 1, 0, 0, 0, 0][..],
        ] {
            assert!(read_client_hello(&hello(extension, &[0x13, 1])).is_err(), "{extension:?}");
        }
        let valid_sni = [0, 0, 0, 6, 0, 4, 0, 0, 1, b'a'];
        assert!(read_client_hello(&hello(&valid_sni, &[0x13])).is_err());
        assert_eq!(read_client_hello(&hello(&valid_sni, &[0x13, 1])).unwrap(), "a");
    }

    #[test]
    fn go_client_hello_control_bytes_request_more_data() {
        let expected = crate::common::protocol::protocol::err_proto_need_more_data().to_string();
        for byte in 0..=b' ' {
            let extension = [0, 0, 0, 7, 0, 5, 0, 0, 2, b'a', byte];
            assert_eq!(read_client_hello(&hello(&extension, &[0x13, 1])).unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn go_client_hello_skips_unknown_extensions_and_name_types() {
        let extension = [
            0x0a, 0x0a, 0, 1, 0xff, // GREASE extension
            0, 0, 0, 12, 0, 10,
            1, 0, 1, b'x', // unknown server_name type
            0, 0, 3, b'A', b'.', b'b',
        ];
        let data = hello(&extension, &[0x13, 1]);
        assert_eq!(read_client_hello(&data).unwrap(), "A.b");
        for length in 0..data.len() {
            assert!(read_client_hello(&data[..length]).is_err(), "truncation at {length}");
        }
    }

    #[test]
    fn test_tls_headers() {
        let input1 = vec![
            0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4, 0x03, 0x03, 0x1a, 0xac, 0xb2,
            0xa8, 0xfe, 0xb4, 0x96, 0x04, 0x5b, 0xca, 0xf7, 0xc1, 0xf4, 0x2e, 0x53, 0x24, 0x6e,
            0x34, 0x0c, 0x58, 0x36, 0x71, 0x97, 0x59, 0xe9, 0x41, 0x66, 0xe2, 0x43, 0xa0, 0x13,
            0xb6, 0x00, 0x00, 0x20, 0x1a, 0x1a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
            0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,
            0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x7b, 0xba, 0xba,
            0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00,
            0x00, 0x11, 0x63, 0x2e, 0x73, 0x2d, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
            0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
            0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
            0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c,
            0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0b,
            0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0xaa, 0xaa, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x18, 0xaa, 0xaa, 0x00, 0x01, 0x00,
        ];

        let header = sniff_tls(&input1).unwrap();
        assert_eq!(header.domain(), "c.s-microsoft.com");
        assert_eq!(header.protocol(), "tls");
    }
}
