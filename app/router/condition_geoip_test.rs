#[cfg(test)]
mod tests {
    use super::super::condition::IpMatcher;
    use super::super::condition_geoip::{Cidr, GeoIpMatcher, HeuristicGeoIpMatcher};
    use std::net::IpAddr;

    #[test]
    fn test_geoip_condition_check() {
        let cidr = Cidr::parse("1.0.1.0/24").unwrap();
        assert!(cidr.contains(&"1.0.1.5".parse().unwrap()));
        assert!(!cidr.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_parsers_reject_out_of_range_prefixes_and_extra_components() {
        for raw in [
            "1.2.3.4/33", "1.2.3.4/255", "::1/129", "::1/255",
            "1.2.3.4/24/8", "::1/64/128", "1.2.3.4//",
            "1.2.3.4/-1", "::1/-1", "1.2.3.4/not-a-prefix",
            "not-an-ip/24", "/24", "",
        ] {
            assert!(Cidr::parse(raw).is_none(), "Cidr accepted {raw}");
            assert!(IpMatcher::parse(raw).is_none(), "IpMatcher accepted {raw}");
        }
    }

    #[test]
    fn cidr_default_masks_and_non_network_addresses_follow_go_parse_cidr() {
        for (raw, prefix, inside, outside) in [
            ("8.8.8.8", 32, "8.8.8.8", "8.8.8.7"),
            ("8.8.8.8/", 32, "8.8.8.8", "8.8.8.7"),
            ("91.108.4.0/16", 16, "91.108.255.254", "91.109.0.0"),
            ("2001:db8::1", 128, "2001:db8::1", "2001:db8::2"),
            ("2001:db8::1/", 128, "2001:db8::1", "2001:db8::2"),
            ("2001:db8:1234:5678::abcd/64", 64, "2001:db8:1234:5678:ffff:ffff:ffff:ffff", "2001:db8:1234:5679::"),
        ] {
            let cidr = Cidr::parse(raw).unwrap();
            assert_eq!(cidr.prefix, prefix, "{raw}");
            let matcher = IpMatcher::parse(raw).unwrap();
            let inside = inside.parse().unwrap();
            let outside = outside.parse().unwrap();
            assert!(cidr.contains(&inside), "{raw}");
            assert!(!cidr.contains(&outside), "{raw}");
            assert!(matcher.matches(&inside), "{raw}");
            assert!(!matcher.matches(&outside), "{raw}");
        }
    }

    // Go common/geodata/ip_matcher_test.go TestIPMatcherFullCIDR4/6.
    #[test]
    fn full_cidrs_cover_only_their_address_family() {
        let v4 = Cidr::parse("0.0.0.0/0").unwrap();
        let v6 = Cidr::parse("::/0").unwrap();
        let rule_v4 = IpMatcher::parse("0.0.0.0/0").unwrap();
        let rule_v6 = IpMatcher::parse("::/0").unwrap();
        for raw in ["0.0.0.0", "255.255.255.255", "192.168.1.1", "::", "2001:cdba::3257:9652", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
            let ip: IpAddr = raw.parse().unwrap();
            assert_eq!(v4.contains(&ip), ip.is_ipv4(), "{raw}");
            assert_eq!(v6.contains(&ip), ip.is_ipv6(), "{raw}");
            assert_eq!(rule_v4.matches(&ip), ip.is_ipv4(), "{raw}");
            assert_eq!(rule_v6.matches(&ip), ip.is_ipv6(), "{raw}");
        }
    }

    // Go TestIPReverseMatcher and TestIPReverseMatcher2 deliberately distinguish
    // an absent IPv6 family from a present-but-unmatched IPv6 family.
    #[test]
    fn reverse_matching_never_matches_an_absent_address_family() {
        let v4_nets = vec![Cidr::parse("8.8.8.8/32").unwrap(), Cidr::parse("91.108.4.0/16").unwrap()];
        let mut v4_only = HeuristicGeoIpMatcher::new(v4_nets.clone(), true);
        let mut dual_nets = v4_nets;
        dual_nets.push(Cidr::parse("fe80::").unwrap());
        let dual = HeuristicGeoIpMatcher::new(dual_nets, true);
        for (raw, v4_expected, dual_expected) in [
            ("8.8.8.8", false, false),
            ("91.108.255.254", false, false),
            ("1.1.1.1", true, true),
            ("2001:cdba::3257:9652", false, true),
            ("fe80::", false, false),
        ] {
            let ip = raw.parse().unwrap();
            assert_eq!(v4_only.matches_ip(&ip), v4_expected, "{raw}");
            assert_eq!(dual.matches_ip(&ip), dual_expected, "{raw}");
        }
        v4_only.toggle_reverse();
        assert!(v4_only.matches_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!v4_only.matches_ip(&"1.1.1.1".parse().unwrap()));
        v4_only.set_reverse(true);
        assert!(v4_only.matches_ip(&"1.1.1.1".parse().unwrap()));
        let v6_only = HeuristicGeoIpMatcher::new(vec![Cidr::parse("fe80::").unwrap()], true);
        assert!(!v6_only.matches_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn invalid_or_empty_sets_cannot_become_match_all_when_reversed() {
        for cidrs in [Vec::new(), vec![Cidr::new("8.8.8.8".parse().unwrap(), 33), Cidr::new("::1".parse().unwrap(), 129)]] {
            let matcher = HeuristicGeoIpMatcher::new(cidrs, true);
            for raw in ["1.1.1.1", "8.8.8.8", "::1", "2001:db8::1"] {
                assert!(!matcher.matches_ip(&raw.parse().unwrap()), "{raw}");
            }
        }
    }

    #[test]
    fn mapped_ipv4_is_matched_in_the_ipv4_family_like_go_std_ip_conversion() {
        let mapped = "::ffff:8.8.8.8".parse().unwrap();
        assert!(Cidr::parse("8.8.8.0/24").unwrap().contains(&mapped));
        assert!(!Cidr::parse("::/0").unwrap().contains(&mapped));
        assert!(IpMatcher::parse("8.8.8.8").unwrap().matches(&mapped));
        assert!(IpMatcher::parse("::ffff:8.8.8.8").unwrap().matches(&"8.8.8.8".parse().unwrap()));
        assert_eq!(Cidr::parse("::ffff:8.8.8.8").unwrap().prefix, 32);
        assert!(Cidr::parse("::ffff:8.8.8.8/128").is_none());
        let positive = HeuristicGeoIpMatcher::new(vec![Cidr::parse("8.8.8.8").unwrap()], false);
        assert!(positive.matches_ip(&mapped));
        let negative = HeuristicGeoIpMatcher::new(vec![Cidr::parse("1.1.1.1").unwrap()], true);
        assert!(negative.matches_ip(&mapped));
    }

    #[test]
    fn list_operations_keep_any_all_filter_and_reverse_family_semantics_consistent() {
        let matcher = HeuristicGeoIpMatcher::new(vec![Cidr::parse("8.8.8.0/24").unwrap()], true);
        let ips: Vec<IpAddr> = ["8.8.8.8", "1.1.1.1", "2001:db8::1", "1.1.1.1"]
            .into_iter().map(|s| s.parse().unwrap()).collect();
        assert!(matcher.any_match(&ips));
        assert!(!matcher.all_match(&ips));
        assert!(!matcher.any_match(&[]));
        assert!(!matcher.all_match(&[]));
        assert!(matcher.all_match(&[ips[1], ips[3]]));
        let (matched, unmatched) = matcher.filter_ips(&ips);
        assert_eq!(matched, vec![ips[1], ips[3]]);
        assert_eq!(unmatched, vec![ips[0], ips[2]]);
    }
}
