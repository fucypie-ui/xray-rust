use super::balancing::{Balancer, BalancingStrategy, RandomStrategy, RoundRobinStrategy};
use super::condition::{DomainMatcher, IpMatcher, Rule, SessionRoutingContext};
use super::router::{DomainStrategy, Router};
use crate::common::net::{Address, Destination, Network};
use crate::common::protocol::SessionContext;
use crate::features::routing::{RouteContext, Router as CoreRouter, RouterFeature, RoutingContext};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn domain_session() -> SessionContext {
    SessionContext::new("in", Destination::tcp(Address::Domain("example.test".into()), 443))
}

fn ip_rule(tag: &str, cidr: &str) -> Rule {
    let mut rule = Rule::new(tag);
    rule.ip_matchers.push(IpMatcher::parse(cidr).unwrap());
    rule
}

fn domain_rule(tag: &str) -> Rule {
    let mut rule = Rule::new(tag);
    rule.domain_matchers.push(DomainMatcher::parse("full:example.test"));
    rule
}

fn router_with_answer(
    rules: Vec<Rule>,
    strategy: DomainStrategy,
    answer: &[&str],
) -> (Router, Arc<AtomicUsize>) {
    let mut router = Router::new(rules, Some("default".into()));
    router.set_domain_strategy(strategy);
    let lookups = Arc::new(AtomicUsize::new(0));
    let count = lookups.clone();
    let answer: Vec<IpAddr> = answer.iter().map(|s| s.parse().unwrap()).collect();
    router.set_ip_resolver(Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        answer.clone()
    }));
    (router, lookups)
}

async fn assert_both_routes(router: &Router, session: &SessionContext, expected: &str) {
    assert_eq!(router.pick_outbound(session), Some(expected), "RouterFeature");
    let context = SessionRoutingContext::new(session);
    assert_eq!(router.pick_route(&context).await.unwrap(), expected, "CoreRouter");
}

// Go TestIPOnDemand and TestIPIfNonMatchDomain resolve example.com to
// 192.168.0.1. Exercise both Rust routing interfaces with the same vectors.
#[tokio::test]
async fn go_domain_strategy_ip_routing_vectors() {
    for strategy in [DomainStrategy::AsIs, DomainStrategy::IpOnDemand, DomainStrategy::IpIfNonMatch] {
        let (router, lookups) = router_with_answer(
            vec![ip_rule("private", "192.168.0.0/16")], strategy, &["192.168.0.1"],
        );
        let expected = if strategy == DomainStrategy::AsIs { "default" } else { "private" };
        assert_both_routes(&router, &domain_session(), expected).await;
        assert_eq!(lookups.load(Ordering::SeqCst), if strategy == DomainStrategy::AsIs { 0 } else { 2 });
    }
}

#[tokio::test]
async fn on_demand_never_resolves_before_an_earlier_domain_rule_matches() {
    let (router, lookups) = router_with_answer(
        vec![domain_rule("domain"), ip_rule("ip", "192.168.0.0/16")],
        DomainStrategy::IpOnDemand, &["192.168.0.1"],
    );
    assert_both_routes(&router, &domain_session(), "domain").await;
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn early_rejected_conditions_do_not_trigger_on_demand_dns() {
    for field in ["inbound", "network", "protocol", "port", "source_port", "user", "local_os"] {
        let mut rejected = ip_rule("wrong", "192.168.0.0/16");
        match field {
            "inbound" => rejected.inbound_tags.push("different".into()),
            "network" => rejected.network = Some(Network::Udp),
            "protocol" => rejected.protocols.push("http".into()),
            "port" => rejected.ports.push(80),
            "source_port" => rejected.source_ports.push(1234),
            "user" => rejected.user_emails.push("admin@example.com".into()),
            "local_os" => rejected.local_os.push("not-a-goos".into()),
            _ => unreachable!(),
        }
        let (router, lookups) = router_with_answer(
            vec![rejected, domain_rule("domain")], DomainStrategy::IpOnDemand, &["192.168.0.1"],
        );
        assert_both_routes(&router, &domain_session(), "domain").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 0, "{field}");
    }
}

#[tokio::test]
async fn target_ip_condition_precedes_domain_and_source_ip_as_in_go_build_condition() {
    for condition in ["domain", "source_ip"] {
        let mut rejected = ip_rule("wrong", "192.168.0.0/16");
        if condition == "domain" {
            rejected.domain_matchers.push(DomainMatcher::parse("full:different.test"));
        } else {
            rejected.source_ip_matchers.push(IpMatcher::parse("10.0.0.0/8").unwrap());
        }
        let (router, lookups) = router_with_answer(
            vec![rejected, domain_rule("domain")], DomainStrategy::IpOnDemand, &["192.168.0.1"],
        );
        assert_both_routes(&router, &domain_session(), "domain").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 2, "{condition}");
    }
}

#[tokio::test]
async fn successful_and_failed_dns_answers_are_cached_once_per_route_selection() {
    for answer in [vec!["192.168.0.1"], Vec::new()] {
        let (router, lookups) = router_with_answer(
            vec![ip_rule("first", "10.0.0.0/8"), ip_rule("second", "172.16.0.0/12"), domain_rule("domain")],
            DomainStrategy::IpOnDemand, &answer,
        );
        assert_both_routes(&router, &domain_session(), "domain").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
        assert_both_routes(&router, &domain_session(), "domain").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 4, "cache must not survive a different route selection");
    }
}

#[tokio::test]
async fn failed_custom_resolver_never_falls_through_to_system_dns() {
    let session = SessionContext::new("in", Destination::tcp(Address::Domain("localhost".into()), 443));
    for strategy in [DomainStrategy::IpOnDemand, DomainStrategy::IpIfNonMatch] {
        let (router, lookups) = router_with_answer(
            vec![ip_rule("system-v4", "127.0.0.0/8"), ip_rule("system-v6", "::1")], strategy, &[],
        );
        assert_both_routes(&router, &session, "default").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn if_non_match_finishes_the_entire_first_pass_before_resolving() {
    let (router, lookups) = router_with_answer(
        vec![ip_rule("ip", "192.168.0.0/16"), domain_rule("domain")],
        DomainStrategy::IpIfNonMatch, &["192.168.0.1"],
    );
    assert_both_routes(&router, &domain_session(), "domain").await;
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn if_non_match_second_pass_restarts_at_the_first_rule_and_reuses_dns() {
    let (router, lookups) = router_with_answer(
        vec![ip_rule("first", "10.0.0.0/8"), ip_rule("second", "192.168.0.0/16"), ip_rule("third", "192.168.0.0/16")],
        DomainStrategy::IpIfNonMatch, &["192.168.0.1"],
    );
    assert_both_routes(&router, &domain_session(), "second").await;
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_dns_strategy_without_a_reached_ip_condition_performs_no_lookup() {
    for strategy in [DomainStrategy::IpIfNonMatch, DomainStrategy::IpOnDemand] {
        let mut rejected = domain_rule("wrong");
        rejected.inbound_tags.push("different".into());
        let (router, lookups) = router_with_answer(vec![rejected], strategy, &["192.168.0.1"]);
        assert_both_routes(&router, &domain_session(), "default").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn literal_ip_targets_never_trigger_dns_for_any_strategy() {
    let session = SessionContext::new("in", Destination::tcp(Address::ip("127.0.0.1".parse().unwrap()), 443));
    for strategy in [DomainStrategy::AsIs, DomainStrategy::IpIfNonMatch, DomainStrategy::IpOnDemand] {
        let (router, lookups) = router_with_answer(vec![ip_rule("loopback", "127.0.0.0/8")], strategy, &[]);
        assert_both_routes(&router, &session, "loopback").await;
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }
}

// A context can supply a routing domain and original target IP simultaneously
// (e.g. a sniffed route target). Go ResolvableContext prefers successful DNS
// answers, and falls back to the original IPs only after DNS fails.
struct DomainAndIpContext {
    base: RouteContext,
    ips: Vec<IpAddr>,
}

impl DomainAndIpContext {
    fn new() -> Self {
        Self {
            base: RouteContext::new(Destination::tcp(Address::Domain("example.test".into()), 443)),
            ips: vec!["192.168.0.1".parse().unwrap()],
        }
    }
}

impl RoutingContext for DomainAndIpContext {
    fn get_inbound_tag(&self) -> &str { self.base.get_inbound_tag() }
    fn get_source_ips(&self) -> Vec<IpAddr> { self.base.get_source_ips() }
    fn get_source_port(&self) -> u16 { self.base.get_source_port() }
    fn get_target_ips(&self) -> Vec<IpAddr> { self.ips.clone() }
    fn get_target_port(&self) -> u16 { self.base.get_target_port() }
    fn get_target_domain(&self) -> Option<&str> { self.base.get_target_domain() }
    fn get_network(&self) -> Network { self.base.get_network() }
    fn get_protocol(&self) -> Option<&str> { self.base.get_protocol() }
    fn get_user(&self) -> Option<&str> { self.base.get_user() }
    fn get_attributes(&self) -> &HashMap<String, String> { self.base.get_attributes() }
    fn get_skip_dns_resolve(&self) -> bool { self.base.get_skip_dns_resolve() }
}

#[tokio::test]
async fn on_demand_prefers_dns_over_original_ips_and_falls_back_on_failure() {
    for (answer, expected) in [(vec!["8.8.8.8"], "resolved"), (Vec::new(), "original")] {
        let (router, lookups) = router_with_answer(
            vec![ip_rule("original", "192.168.0.0/16"), ip_rule("resolved", "8.8.8.8")],
            DomainStrategy::IpOnDemand, &answer,
        );
        assert_eq!(router.pick_route(&DomainAndIpContext::new()).await.unwrap(), expected);
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        let mut session = domain_session();
        session.original_destination = Some(Destination::tcp(Address::ip("192.168.0.1".parse().unwrap()), 443));
        assert_both_routes(&router, &session, expected).await;
        assert_eq!(lookups.load(Ordering::SeqCst), 3);
    }
}

#[tokio::test]
async fn if_non_match_can_resolve_even_when_original_target_ips_exist() {
    let (router, lookups) = router_with_answer(
        vec![ip_rule("resolved", "8.8.8.8")], DomainStrategy::IpIfNonMatch, &["8.8.8.8"],
    );
    assert_eq!(router.pick_route(&DomainAndIpContext::new()).await.unwrap(), "resolved");
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn skip_dns_resolve_applies_to_both_domain_strategies() {
    for strategy in [DomainStrategy::IpOnDemand, DomainStrategy::IpIfNonMatch] {
        let (router, lookups) = router_with_answer(vec![ip_rule("resolved", "8.8.8.8")], strategy, &["8.8.8.8"]);
        let mut context = DomainAndIpContext::new();
        context.base.skip_dns_resolve = true;
        assert_eq!(router.pick_route(&context).await.unwrap(), "default");
        context.ips.clear();
        assert_eq!(router.pick_route(&context).await.unwrap(), "default");
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn skip_dns_resolve_preserves_literal_ip_rules() {
    let (router, lookups) = router_with_answer(
        vec![ip_rule("original", "192.168.0.0/16")], DomainStrategy::IpOnDemand, &["8.8.8.8"],
    );
    let mut context = DomainAndIpContext::new();
    context.base.skip_dns_resolve = true;
    assert_eq!(router.pick_route(&context).await.unwrap(), "original");
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resolved_ipv6_answers_participate_in_the_same_rule_order() {
    let (router, lookups) = router_with_answer(
        vec![ip_rule("v4", "192.168.0.0/16"), ip_rule("v6", "2001:db8::/32")],
        DomainStrategy::IpOnDemand, &["8.8.8.8", "2001:db8::1234"],
    );
    assert_both_routes(&router, &domain_session(), "v6").await;
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn route_target_domain_is_the_domain_sent_to_the_resolver() {
    let mut session = domain_session();
    session.sniffed_domain = Some("sniffed.test".into());
    session.route_target = Some(Destination::tcp(Address::Domain("route.test".into()), 8443));
    let mut rule = ip_rule("routed", "8.8.8.8");
    rule.ports.push(8443);
    let mut router = Router::new(vec![rule], None);
    router.set_domain_strategy(DomainStrategy::IpOnDemand);
    router.set_ip_resolver(Arc::new(|domain| {
        assert_eq!(domain, "route.test");
        vec!["8.8.8.8".parse().unwrap()]
    }));
    assert_both_routes(&router, &session, "routed").await;
}

struct EmptyTagStrategy;

impl BalancingStrategy for EmptyTagStrategy {
    fn name(&self) -> &str { "empty" }
    fn pick_outbound(&self, _tags: &[String]) -> Option<String> { Some(String::new()) }
}

#[tokio::test]
async fn balancer_fallback_can_be_outside_both_selectors_and_candidates() {
    let strategies: [Arc<dyn BalancingStrategy>; 2] = [
        Arc::new(EmptyTagStrategy), Arc::new(RoundRobinStrategy::new(None)),
    ];
    for strategy in strategies {
        let candidates = if strategy.name() == "empty" { vec!["node-1".into()] } else { vec!["unselected".into()] };
        let balancer = Balancer::with_candidates(
            "balance", vec!["node-".into()], candidates, strategy, Some("direct".into()),
        );
        let mut router = Router::new(vec![Rule::with_balancer("balance"), Rule::new("later")], Some("default".into()));
        router.add_balancer("balance", Arc::new(balancer));
        assert_both_routes(&router, &domain_session(), "direct").await;
    }
}

#[tokio::test]
async fn failed_balancer_does_not_fall_through_to_a_later_rule_or_retry_dns() {
    for exists in [false, true] {
        let (mut router, lookups) = router_with_answer(
            vec![Rule::with_balancer("balance"), ip_rule("later", "8.8.8.8"), Rule::new("last")],
            DomainStrategy::IpIfNonMatch, &["8.8.8.8"],
        );
        if exists {
            router.add_balancer("balance", Arc::new(Balancer::with_candidates(
                "balance", vec!["node-".into()], vec!["node-1".into()], Arc::new(EmptyTagStrategy), None,
            )));
        }
        let session = domain_session();
        assert_eq!(router.pick_outbound(&session), Some("default"));
        assert!(router.pick_route(&SessionRoutingContext::new(&session)).await.is_err());
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn empty_balancer_fallback_is_an_absent_result() {
    let balancer = Balancer::with_candidates(
        "balance", vec!["node-".into()], vec!["node-1".into()], Arc::new(EmptyTagStrategy), Some(String::new()),
    );
    assert_eq!(balancer.pick(), None);
    assert_eq!(balancer.pick_outbound(&[]), None);
}

#[tokio::test]
async fn strategy_owned_fallback_remains_available_through_the_borrowed_api() {
    let observatory = Arc::new(crate::app::observatory::Observatory::new(
        "http://example.test", std::time::Duration::from_secs(10), vec![],
    ));
    observatory.record_status("node-1", false, 100, None);
    let strategy = Arc::new(RandomStrategy::with_fallback(Some("strategy-fallback".into()), Some(observatory)));
    let balancer = Balancer::with_candidates("balance", vec!["node-".into()], vec!["node-1".into()], strategy, None);
    let mut router = Router::new(vec![Rule::with_balancer("balance")], Some("default".into()));
    router.add_balancer("balance", Arc::new(balancer));
    assert_both_routes(&router, &domain_session(), "strategy-fallback").await;
}

#[test]
fn round_robin_wraps_the_index_using_each_calls_pool_size_like_go() {
    let strategy = RoundRobinStrategy::new(Some("fallback".into()));
    let large_pool = vec!["a".into(), "b".into(), "c".into()];
    let small_pool = vec!["a".into(), "b".into()];
    for expected in ["a", "b", "c"] {
        assert_eq!(strategy.pick_outbound(&large_pool).as_deref(), Some(expected));
    }
    assert_eq!(strategy.pick_outbound(&small_pool).as_deref(), Some("a"));
    assert_eq!(strategy.pick_outbound(&[]).as_deref(), Some("fallback"));
    assert_eq!(strategy.pick_outbound(&large_pool).as_deref(), Some("b"));
    assert_eq!(strategy.pick_outbound(&small_pool).as_deref(), Some("a"));
}
