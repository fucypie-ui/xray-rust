use super::{WireGuardConfig, WireGuardPeer, create_ipc_request, parse_endpoints};

#[test]
fn ipc_export_uses_normalized_keys_psk_and_allowed_ips() {
    let config = WireGuardConfig {
        secret_key: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".into(),
        peers: vec![WireGuardPeer {
            public_key: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".into(),
            pre_shared_key: Some(hex::encode([7;32])), endpoint: "198.51.100.1:51820".into(),
            keepalive: 25, allowed_ips: vec!["10.2.0.7/24".into()],
            ..WireGuardPeer::default()
        }], ..WireGuardConfig::default()
    };
    // Use an independent Go-derived public key; base64 normalization is tested by
    // constructing its textual input from the known bytes, not the tunnel engine.
    let mut config = config;
    use base64::Engine as _;
    config.peers[0].public_key = base64::engine::general_purpose::STANDARD
        .encode(hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap());
    let ipc = create_ipc_request(&config, false, Some(51820)).unwrap();
    assert!(ipc.contains("private_key=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n"));
    assert!(ipc.contains("public_key=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\n"));
    assert!(ipc.contains(&format!("preshared_key={}\n", hex::encode([7;32]))));
    assert!(ipc.contains("allowed_ip=10.2.0.0/24\n"));
    assert!(ipc.contains("listen_port=51820\n"));
    assert!(ipc.contains("persistent_keepalive_interval=25\n"));
}

#[test]
fn interface_address_prefixes_match_go_host_address_behavior() {
    let (addresses, v4, v6) = parse_endpoints(&["10.77.0.2/24".into(), "fd77::2/64".into()]).unwrap();
    assert_eq!(addresses[0].to_string(), "10.77.0.2"); assert!(v4 && v6);
    assert!(parse_endpoints(&["10.77.0.2/33".into()]).is_err());
    assert!(parse_endpoints(&["fd77::2/129".into()]).is_err());
    assert!(parse_endpoints(&["localhost".into()]).is_err());
}
