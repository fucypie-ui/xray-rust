use super::condition::{DomainMatcher, IpMatcher, Rule, SessionRoutingContext};
use crate::common::net::find_process::ProcessInfo;
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::{SessionContext, User};
use crate::features::routing::RoutingContext;
use std::net::IpAddr;
use uuid::Uuid;

fn session() -> SessionContext {
    SessionContext::new("in", Destination::tcp(Address::Domain("example.com".into()), 443))
}

// Go app/router/condition_test.go TestRoutingRule: alternatives within a
// condition are ORed, whereas separate conditions are ANDed.
#[test]
fn go_routing_rule_domain_vectors() {
    let mut rule = Rule::new("out");
    rule.domain_matchers = [
        "example.com",
        "domain:google.com",
        r"regexp:^facebook\.com$",
    ].into_iter().map(DomainMatcher::parse).collect();
    for (domain, expected) in [
        ("example.com", true),
        ("www.example.com.www", true),
        ("example.co", false),
        ("www.google.com", true),
        ("notgoogle.com", false),
        ("facebook.com", true),
        ("www.facebook.com", false),
        ("FACEBOOK.COM", true),
    ] {
        let session = SessionContext::new("in", Destination::tcp(Address::Domain(domain.into()), 80));
        assert_eq!(rule.matches(&session), expected, "{domain}");
    }
    let session = SessionContext::new("in", Destination::tcp(Address::ip("8.8.8.8".parse().unwrap()), 80));
    assert!(!rule.matches(&session));
}

#[test]
fn regex_patterns_are_case_sensitive_but_routing_input_is_lowercased() {
    for (pattern, domain, expected) in [
        (r"regexp:^example\.com$", "EXAMPLE.COM", true),
        (r"regexp:^EXAMPLE\.COM$", "EXAMPLE.COM", false),
        (r"regexp:(?i)^EXAMPLE\.COM$", "EXAMPLE.COM", true),
        (r"regexp:^example\.com$", "example.com.", false),
        (r"regexp:^example\.com\.$", "EXAMPLE.COM.", true),
        ("full:Example.COM", "EXAMPLE.COM", true),
        ("keyword:Example", "MY.EXAMPLE.COM", true),
    ] {
        assert_eq!(DomainMatcher::parse(pattern).matches(domain), expected, "{pattern}: {domain}");
    }
}

#[test]
fn full_and_domain_matchers_preserve_trailing_dots_and_label_boundaries() {
    for (pattern, domain, expected) in [
        ("full:example.com", "example.com.", false),
        ("full:example.com.", "example.com", false),
        ("full:example.com.", "EXAMPLE.COM.", true),
        ("domain:example.com", "x.example.com", true),
        ("domain:example.com", "xexample.com", false),
        ("domain:example.com", "x.example.com.", false),
        ("domain:example.com.", "x.example.com.", true),
        ("domain:example.com.", "xexample.com.", false),
    ] {
        assert_eq!(DomainMatcher::parse(pattern).matches(domain), expected, "{pattern}: {domain}");
    }
}

// Go common/geodata/rule_parser.go parseCustomDomainRule expands dotless
// patterns to a regex; the supplied expression is deliberately not escaped.
#[test]
fn dotless_matches_only_single_label_names() {
    for (pattern, domain, expected) in [
        ("dotless:", "localhost", true),
        ("dotless:", "router-name", true),
        ("dotless:", "localhost.", false),
        ("dotless:", "router.lan", false),
        ("dotless:local", "my-localhost", true),
        ("dotless:local", "printer", false),
        ("dotless:local", "local.lan", false),
        ("dotless:loc[ae]l", "LOCALHOST", true),
        ("dotless:LOCAL", "LOCALHOST", false),
    ] {
        assert_eq!(DomainMatcher::parse(pattern).matches(domain), expected, "{pattern}: {domain}");
    }
    let mut rule = Rule::new("out");
    rule.domain_matchers.push(DomainMatcher::parse("dotless:"));
    let mut session = session();
    session.destination.address = Address::Domain(String::new());
    session.original_destination = None;
    assert!(!rule.matches(&session), "Go DomainMatcher.Apply rejects an empty target domain");
}

#[test]
fn protocol_prefixes_are_case_sensitive_and_empty_entries_are_ignored() {
    let mut rule = Rule::new("out");
    rule.protocols = vec![String::new(), "http".into()];
    for (protocol, expected) in [
        ("http", true),
        ("http/1.1", true),
        ("http2", true),
        ("HTTP/1.1", false),
        ("tls", false),
        ("", false),
    ] {
        assert_eq!(rule.matches_protocol(protocol), expected, "{protocol}");
        let mut session = session();
        session.sniffed_protocol = Some(protocol.into());
        assert_eq!(rule.matches(&session), expected, "{protocol}");
    }
    rule.protocols = vec![String::new()];
    assert!(!rule.matches_protocol("tls"));
}

#[test]
fn user_regexes_and_empty_values_follow_go_user_matcher() {
    let mut rule = Rule::new("out");
    rule.user_emails = vec![
        String::new(),
        "admin@example.com".into(),
        r"regexp:^staff[0-9]+@example\.com$".into(),
        "regexp:[invalid".into(),
        "regexp:".into(),
    ];
    for (email, expected) in [
        ("admin@example.com", true),
        ("ADMIN@example.com", false),
        ("staff123@example.com", true),
        ("staff@example.com", false),
        ("", false),
        ("regexp:", true),
        ("regexp:[invalid", false),
    ] {
        assert_eq!(rule.matches_user(email), expected, "{email}");
    }
    rule.user_emails = vec!["regexp:^$".into()];
    assert!(!rule.matches_user(""));
}

#[test]
fn empty_inbound_tag_cannot_match_an_empty_configured_entry() {
    let mut rule = Rule::new("out");
    rule.inbound_tags = vec![String::new(), "in".into()];
    assert!(rule.matches(&session()));
    let mut session = session();
    session.inbound_tag.clear();
    assert!(!rule.matches(&session));
}

#[test]
fn separate_conditions_are_conjunctive_and_port_range_endpoints_are_inclusive() {
    let mut rule = Rule::new("out");
    rule.inbound_tags = vec!["in".into(), "other".into()];
    rule.domain_matchers.push(DomainMatcher::parse("full:example.com"));
    rule.ip_matchers.push(IpMatcher::parse("192.168.0.0/16").unwrap());
    rule.source_ip_matchers.push(IpMatcher::parse("10.0.0.0/8").unwrap());
    rule.port_ranges = vec![(1000, 1100)];
    rule.source_port_ranges = vec![(9993, 9999)];
    rule.protocols = vec!["http".into()];
    rule.user_emails = vec!["admin@example.com".into()];
    rule.network = Some(Network::Tcp);
    let mut session = session();
    session.sniffed_protocol = Some("http/1.1".into());
    session.source = Some("10.0.0.1:9993".parse().unwrap());
    session.user = Some(User::with_email(Uuid::nil(), "admin@example.com", 0));
    let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "192.168.0.1".parse().unwrap()];
    for port in [1000, 1005, 1100] {
        session.destination.port = port;
        assert!(rule.matches_with_ips(&session, &ips), "{port}");
    }
    session.source = Some("10.0.0.1:9999".parse().unwrap());
    assert!(rule.matches_with_ips(&session, &ips));
    for port in [999, 1101] {
        session.destination.port = port;
        assert!(!rule.matches_with_ips(&session, &ips));
    }
    session.destination.port = 1000;
    session.destination.network = Network::Udp;
    assert!(!rule.matches_with_ips(&session, &ips));
    session.destination.network = Network::Tcp;
    session.source = Some("10.0.0.1:9992".parse().unwrap());
    assert!(!rule.matches_with_ips(&session, &ips));
    session.source = Some("11.0.0.1:9993".parse().unwrap());
    assert!(!rule.matches_with_ips(&session, &ips));
    session.source = Some("10.0.0.1:9993".parse().unwrap());
    assert!(!rule.matches_with_ips(&session, &ips[..1]));
    session.user = None;
    assert!(!rule.matches_with_ips(&session, &ips));
}

#[test]
fn process_names_paths_and_special_tokens_follow_go_exact_comparisons() {
    let info = ProcessInfo { pid: 0, name: "curl".into(), path: "/usr/bin/curl".into() };
    let mut rule = Rule::new("out");
    for (pattern, expected) in [
        ("curl", true),
        ("curl.exe", true),
        ("curl.exe.exe", false),
        ("CURL", false),
        ("/usr/bin/curl", true),
        ("/USR/bin/curl", false),
        ("/usr/bin/", true),
        ("/USR/bin/", false),
        ("self/", false),
        ("xray/", false),
    ] {
        rule.process = vec![pattern.into()];
        assert_eq!(rule.matches_process_info(Some(&info)), expected, "{pattern}");
    }
    let unrelated_xray = ProcessInfo { name: "xray".into(), ..info.clone() };
    rule.process = vec!["xray/".into()];
    assert!(!rule.matches_process_info(Some(&unrelated_xray)));
    let current_exe = std::env::current_exe().unwrap();
    let current_path = current_exe.to_string_lossy();
    let current_path = if cfg!(windows) { current_path.replace('\\', "/") } else { current_path.into_owned() };
    let another_instance = ProcessInfo { path: current_path, ..info.clone() };
    assert!(rule.matches_process_info(Some(&another_instance)));
    rule.process = vec!["self/".into()];
    assert!(!rule.matches_process_info(Some(&another_instance)));
    let this_process = ProcessInfo { pid: std::process::id(), ..info };
    assert!(rule.matches_process_info(Some(&this_process)));
    assert!(!rule.matches_process_info(None));
}

#[test]
fn rejected_conditions_leave_process_cache_untouched() {
    let mut rule = Rule::new("out");
    rule.ip_matchers.push(IpMatcher::parse("8.8.8.8").unwrap());
    rule.process.push("self/".into());
    let session = session();
    let context = SessionRoutingContext::new(&session);
    let mut cache = None;
    assert!(!rule.matches_context(&context, Vec::new, &mut cache));
    assert!(cache.is_none());
}

#[test]
fn process_cache_reuses_success_and_failure_for_later_rules() {
    let mut session = session();
    session.source = Some("127.0.0.1:12345".parse().unwrap());
    let context = SessionRoutingContext::new(&session);
    let mut rule = Rule::new("out");
    rule.process.push("self/".into());
    let mut cache = Some(Some(ProcessInfo {
        pid: std::process::id(), name: "self".into(), path: String::new(),
    }));
    assert!(rule.matches_context(&context, Vec::new, &mut cache));
    assert!(rule.matches_context(&context, Vec::new, &mut cache));
    let mut failed_cache = Some(None);
    assert!(!rule.matches_context(&context, Vec::new, &mut failed_cache));
    assert_eq!(failed_cache, Some(None));
}

#[test]
fn session_adapter_preserves_route_target_and_original_ip_support() {
    let mut session = session();
    session.sniffed_domain = Some("sniffed.test".into());
    session.route_target = Some(Destination::tcp(Address::Domain("route.test".into()), 8443));
    session.original_destination = Some(Destination::tcp(Address::ip("192.168.0.1".parse().unwrap()), 443));
    let context = SessionRoutingContext::new(&session);
    assert_eq!(context.get_target_domain(), Some("route.test"));
    assert_eq!(context.get_target_port(), 8443);
    assert_eq!(context.get_target_ips(), vec!["192.168.0.1".parse::<IpAddr>().unwrap()]);
}
