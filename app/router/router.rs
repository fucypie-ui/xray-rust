use super::balancing::Balancer;
use super::condition::{Rule, SessionRoutingContext};
use crate::common::errors::{Error, Result};
use crate::common::protocol::SessionContext;
use crate::features::feature::{Feature, TYPE_ROUTER};
use crate::features::routing::context::RoutingContext;
use crate::features::routing::{Router as CoreRouterTrait, RouterFeature};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

impl DomainStrategy {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ipifnonmatch" | "ip_if_non_match" => Self::IpIfNonMatch,
            "ipondemand" | "ip_on_demand" => Self::IpOnDemand,
            _ => Self::AsIs,
        }
    }
}

pub type DomainIpResolverFn = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

#[derive(Clone)]
pub struct Router {
    pub domain_strategy: DomainStrategy,
    pub rules: Vec<Rule>,
    pub balancers: HashMap<String, Arc<Balancer>>,
    pub default_tag: Option<String>,
    ip_resolver: Option<DomainIpResolverFn>,
}

impl Router {
    pub fn new(rules: Vec<Rule>, default_tag: Option<String>) -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules,
            balancers: HashMap::new(),
            default_tag,
            ip_resolver: None,
        }
    }
    pub fn with_balancers(
        rules: Vec<Rule>,
        balancers: HashMap<String, Arc<Balancer>>,
        default_tag: Option<String>,
    ) -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules,
            balancers,
            default_tag,
            ip_resolver: None,
        }
    }
    pub fn set_domain_strategy(&mut self, strategy: DomainStrategy) { self.domain_strategy = strategy; }
    pub fn set_ip_resolver(&mut self, resolver: DomainIpResolverFn) { self.ip_resolver = Some(resolver); }
    pub fn add_balancer(&mut self, tag: impl Into<String>, balancer: Arc<Balancer>) {
        self.balancers.insert(tag.into(), balancer);
    }
    pub fn add_rule(&mut self, rule: Rule, append: bool) {
        if append {
            self.rules.push(rule);
        } else {
            self.rules.insert(0, rule);
        }
    }
    pub fn remove_rule(&mut self, rule_tag: &str) -> Result<()> {
        let before = self.rules.len();
        self.rules.retain(|r| r.tag != rule_tag);
        if self.rules.len() == before { return Err(Error::Other(format!("rule '{}' not found", rule_tag))); }
        Ok(())
    }
    pub fn list_rule(&self) -> &[Rule] { &self.rules }
    pub fn r#type(&self) -> &'static str { TYPE_ROUTER }
    pub fn start(&self) -> Result<()> { Ok(()) }
    pub fn close(&self) -> Result<()> { Ok(()) }
    fn resolve_domain_ips(&self, domain: &str, port: u16) -> Vec<IpAddr> {
        if let Some(ref f) = self.ip_resolver {
            // An installed resolver is authoritative, including an empty/failed
            // answer. Falling through to system DNS would bypass DNS policy.
            return f(domain);
        }
        (domain, port).to_socket_addrs().map(|it| it.map(|sa| sa.ip()).collect()).unwrap_or_default()
    }
    fn resolve_rule_target<'a>(&'a self, rule: &'a Rule) -> Option<&'a str> {
        if let Some(tag) = &rule.balancer_tag {
            let balancer = self.balancers.get(tag)?;
            let picked = balancer.pick()?;
            return balancer.candidates.iter()
                .chain(&balancer.selectors)
                .chain(&balancer.fallback_tag)
                .find(|s| **s == picked)
                .map(String::as_str)
                .or_else(|| balancer.strategy.fallback_tag().filter(|tag| *tag == picked));
        }
        (!rule.tag.is_empty()).then_some(rule.tag.as_str())
    }
    fn pick_rule(&self, context: &dyn RoutingContext) -> Option<&Rule> {
        let mut cached_ips: Option<Vec<IpAddr>> = None;
        let mut cached_proc = None;
        let domain = context.get_target_domain()
            .filter(|d| !d.is_empty() && !context.get_skip_dns_resolve());
        let mut eval_pass = |with_dns: bool| {
            for rule in &self.rules {
                let target_ips = || {
                    if with_dns && let Some(domain) = domain {
                        cached_ips.get_or_insert_with(|| {
                            let resolved = self.resolve_domain_ips(domain, context.get_target_port());
                            if resolved.is_empty() { context.get_target_ips() } else { resolved }
                        }).clone()
                    } else {
                        context.get_target_ips()
                    }
                };
                if rule.matches_context(context, target_ips, &mut cached_proc) { return Some(rule); }
            }
            None
        };
        if let Some(rule) = eval_pass(self.domain_strategy == DomainStrategy::IpOnDemand) {
            return Some(rule);
        }
        if self.domain_strategy == DomainStrategy::IpIfNonMatch && domain.is_some() {
            return eval_pass(true);
        }
        None
    }
}

impl Feature for Router {
    fn feature_type(&self) -> &'static str { TYPE_ROUTER }
}

impl RouterFeature for Router {
    fn pick_outbound(&self, session: &SessionContext) -> Option<&str> {
        let context = SessionRoutingContext::new(session);
        self.pick_rule(&context)
            .and_then(|rule| self.resolve_rule_target(rule))
            .or(self.default_tag.as_deref())
    }
}

#[async_trait]
impl CoreRouterTrait for Router {
    async fn pick_route(&self, ctx: &dyn RoutingContext) -> Result<String> {
        if let Some(rule) = self.pick_rule(ctx) {
            // Matching is final before balancing, as in Go's PickRoute/GetTag.
            // A failed balancer must not accidentally select a later rule.
            if let Some(tag) = &rule.balancer_tag {
                let balancer = self.balancers.get(tag)
                    .ok_or_else(|| Error::NotFound(format!("balancer '{tag}' not found")))?;
                return balancer.pick().filter(|tag| !tag.is_empty())
                    .ok_or_else(|| Error::Other("balancing strategy returns empty tag".into()));
            }
            if !rule.tag.is_empty() { return Ok(rule.tag.clone()); }
        }
        self.default_tag.clone().ok_or_else(|| Error::NotFound("No matching route found".into()))
    }
}
