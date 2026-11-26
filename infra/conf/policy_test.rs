use super::policy::PolicyConfig;
use std::time::Duration;

#[test]
fn json_policy_preserves_zero_negative_stats_and_byte_units() {
    let json = r#"{"levels":{"0":{"handshake":0,"connIdle":0,"uplinkOnly":0,"downlinkOnly":0,"bufferSize":-3},"1":{"handshake":7,"connIdle":11,"bufferSize":4,"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true},"2":null},"system":{"statsInboundUplink":true,"statsOutboundDownlink":true}}"#;
    let config: PolicyConfig = serde_json::from_str(json).unwrap();
    let built = config.build().unwrap();
    assert!(!built.level.contains_key(&2));
    let manager = crate::app::policy::Instance::new(&built).unwrap();
    let zero = manager.for_level(0);
    assert_eq!(zero.timeouts.handshake, Duration::ZERO);
    assert_eq!(zero.timeouts.connection_idle, Duration::ZERO);
    assert_eq!(zero.timeouts.uplink_only, Duration::ZERO);
    assert_eq!(zero.timeouts.downlink_only, Duration::ZERO);
    assert_eq!(zero.buffer.per_connection, -1);
    let one = manager.for_level(1);
    assert_eq!(one.timeouts.handshake, Duration::from_secs(7));
    assert_eq!(one.timeouts.connection_idle, Duration::from_secs(11));
    assert_eq!(one.buffer.per_connection, 4096);
    assert!(one.stats.user_uplink && one.stats.user_downlink && one.stats.user_online);
    let system = manager.for_system().stats;
    assert!(system.inbound_uplink && system.outbound_downlink);
    assert!(!system.inbound_downlink && !system.outbound_uplink);
}
#[test]
fn invalid_unsigned_policy_levels_and_timeouts_fail() {
    for raw in [r#"{"levels":{"bad":{}}}"#, r#"{"levels":{"-1":{}}}"#, r#"{"levels":{"1":{"handshake":-1}}}"#, r#"{"levels":{"1":{"connIdle":"bad"}}}"#] {
        assert!(serde_json::from_str::<PolicyConfig>(raw).is_err(), "{}", raw);
    }
}
#[test]
fn per_instance_buffer_env_applies_to_default_and_overridden_levels() {
    let config = crate::core::config::load_config("json", br#"{"env":{"xray.ray.buffer.size":"0"},"policy":{"levels":{"1":{"connIdle":9},"2":{"bufferSize":2}}}}"#).unwrap().build().unwrap();
    assert_eq!(config.policy_manager.for_level(999).buffer.per_connection, -1);
    assert_eq!(config.policy_manager.for_level(1).buffer.per_connection, -1);
    assert_eq!(config.policy_manager.for_level(2).buffer.per_connection, 2048);
}
#[test]
fn buffer_env_parser_preserves_wrapping_and_architecture_default() {
    use crate::features::policy::policy::buffer_size_from_env;
    assert_eq!(buffer_size_from_env(Some("0")), -1);
    assert_eq!(buffer_size_from_env(Some("1")), 1024 * 1024);
    assert_eq!(buffer_size_from_env(Some("4096")), 0);
    assert_eq!(buffer_size_from_env(Some("invalid")), buffer_size_from_env(None));
    assert_eq!(buffer_size_from_env(Some("-17")), buffer_size_from_env(None));
}
#[test]
fn duration_parser_accepts_go_fractional_compound_signed_values() {
    use super::observatory::duration_ns;
    assert_eq!(duration_ns(Some("2.5s")).unwrap(), 2_500_000_000);
    assert_eq!(duration_ns(Some("1m2.5s")).unwrap(), 62_500_000_000);
    assert_eq!(duration_ns(Some("-250ms")).unwrap(), -250_000_000);
    assert!(duration_ns(Some("1fortnight")).is_err());
}
