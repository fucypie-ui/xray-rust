//! Independent generated grpc-go clients through configured root runtimes.
//! All three ignored groups are mandatory when explicitly selected.
use crate::core::Instance;
use crate::infra::conf::Config;
use futures::FutureExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::net::{SocketAddr, TcpListener};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

const PIN: &str = "67756b3674d56b72c7a7e675e8dcd3f883e1b2f7";
const COUNTER: &str = "reflection.reference.sentinel";
const VALUE: i64 = 424242;
const ROUTED: &str = "api-reflection.reference.invalid:18080";
const TAG: &str = "reflection-api";
const PROFILES: [&str; 4] = ["full", "stats", "reflection", "disabled"];
const VERSIONS: [&str; 2] = ["v1", "v1alpha"];
const OUTPUT_LIMIT: u64 = 65536;

fn binary() -> std::ffi::OsString {
    assert_eq!(std::env::consts::OS, "linux", "pinned reflection tests require Linux");
    std::env::var_os("XRAY_API_REFLECTION_GO_PEER").expect(
        "mandatory selected reflection live test: set XRAY_API_REFLECTION_GO_PEER to the pinned Linux helper; absence is a failure",
    )
}

// One absolute deadline covers each entire group, including case startup,
// controls, helper execution, process reaping and runtime shutdown. No timeout
// cancels a future owning a child: reserve its final second for kill AND wait.
// Work, including helper reaping, stops five seconds before the group end so
// root close/join cannot be starved by a helper timeout or an assertion failure.
struct Group { deadline: Instant, work_deadline: Instant }
impl Group {
    fn new() -> Self {
        let deadline = Instant::now() + Duration::from_secs(60);
        Self { deadline, work_deadline: deadline - Duration::from_secs(5) }
    }
    fn check(&self) { assert!(Instant::now() < self.deadline, "reflection live group exceeded 60 seconds"); }
    fn check_work(&self) { assert!(Instant::now() < self.work_deadline, "reflection work exceeded 55 seconds; five seconds reserved for root teardown"); }

    async fn process(&self, control: &[u8]) -> Output {
        let executable = binary();
        let started = Instant::now();
        let end = (started + Duration::from_secs(15)).min(self.work_deadline);
        assert!(end > started + Duration::from_secs(1), "reflection group budget exhausted before starting helper");
        let work_end = end - Duration::from_secs(1);
        let mut child = Command::new(executable).kill_on_drop(true)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().expect("start pinned API reflection helper");
        let mut stdin = child.stdin.take().expect("piped helper stdin");
        let mut stdout = child.stdout.take().expect("piped helper stdout").take(OUTPUT_LIMIT + 1);
        let mut stderr = child.stderr.take().expect("piped helper stderr").take(OUTPUT_LIMIT + 1);
        let mut out = Vec::new();
        let mut err = Vec::new();
        // No assertion or fallible unwrap occurs while the child is live. Even
        // input/read errors are reported only after wait (or kill+wait) finishes.
        let work = timeout_at(work_end, async {
            tokio::join!(
                async {
                    let result = stdin.write_all(control).await;
                    let closed = stdin.shutdown().await;
                    drop(stdin);
                    result.and(closed)
                },
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err),
                child.wait(),
            )
        }).await;
        let (input, output, diagnostic, status) = match work {
            Ok(result) => result,
            Err(_) => {
                // Tokio Child::kill sends the kill and waits for process exit.
                let reaped = timeout_at(end, child.kill()).await;
                assert!(matches!(reaped, Ok(Ok(()))), "could not kill/wait timed-out reflection helper: {reaped:?}");
                panic!("reflection helper exceeded its bounded execution window: {}", String::from_utf8_lossy(&err));
            }
        };
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                let reaped = timeout_at(end, child.kill()).await;
                panic!("wait for reflection helper failed: {error}; kill/wait cleanup: {reaped:?}");
            }
        };
        if let Err(error) = input {
            assert!(!status.success() && error.kind() == std::io::ErrorKind::BrokenPipe, "write/close helper control failed: {error}");
        }
        output.expect("read helper stdout");
        diagnostic.expect("drain helper stderr");
        assert!(out.len() <= OUTPUT_LIMIT as usize && err.len() <= OUTPUT_LIMIT as usize, "oversized helper output");
        self.check_work();
        Output { status, stdout: out, stderr: err }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    event: String,
    reference: String,
    grpc_version: String,
    protobuf_version: String,
    go_version: String,
    mode: String,
    address: String,
    socks: String,
    version: String,
    profile: String,
    result: Outcome,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Outcome {
    services: Vec<String>,
    handler_files: Vec<String>,
    handler_sha256: String,
    checks: Vec<String>,
    queries: usize,
    echoes: usize,
    not_found: usize,
    fresh_closures: usize,
    repeated_roots: usize,
    clean_eof: usize,
    empty_eof: usize,
    terminal_code: u32,
    cancelled_code: u32,
    dynamic_queries: usize,
    dynamic_value: i64,
    lookup_errors: Vec<LookupObservation>,
    streams: Vec<StreamObservation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LookupObservation {
    query: String,
    code: i32,
    message: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MetadataEntry {
    key: String,
    values_base64: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamObservation {
    scenario: String,
    eof: bool,
    code: u32,
    message: String,
    headers: Vec<MetadataEntry>,
    trailers: Vec<MetadataEntry>,
}

fn assert_matches_baseline(actual: &Outcome, baseline: &Outcome, context: &str) {
    let comparable = |raw: &Outcome| {
        let mut comparison = raw.clone();
        // protobuf-go v1.36.12 reflect/protoregistry/registry.go:80 and
        // internal/errors/errors.go:26-37: NotFound uses one binary-seeded
        // separator, ASCII space or NBSP. Canonicalize ONLY that exact sentinel.
        // Keep the raw Outcome/JSON intact. No other diagnostic (including any
        // terminal message), header, trailer, or metadata value is normalized.
        for observed in &mut comparison.lookup_errors {
            if observed.message == "proto:\u{00a0}not found" {
                observed.message = "proto: not found".into();
            }
        }
        comparison
    };
    assert_eq!(comparable(actual), comparable(baseline), "{context}; raw Rust observation={actual:#?}; raw executed pinned Go observation={baseline:#?}");
}

fn validate_streams(outcome: &Outcome, expected: &[(&str, u32, bool)]) {
    assert_eq!(outcome.streams.len(), expected.len(), "missing observed stream terminations");
    for (observed, &(scenario, code, eof)) in outcome.streams.iter().zip(expected) {
        assert_eq!(observed.scenario, scenario);
        assert_eq!((observed.code, observed.eof), (code, eof));
        if eof { assert!(observed.message.is_empty(), "clean EOF carried a status diagnostic"); }
        else { assert!(!observed.message.is_empty(), "terminal status diagnostic was not captured"); }
        // Validate only the deterministic map representation here. Exact message
        // text and ALL metadata bytes/values are compared to an executed Go
        // baseline by Outcome equality; no allowlist or filtering removes them.
        for metadata in [&observed.headers, &observed.trailers] {
            assert!(metadata.iter().all(|entry| !entry.key.is_empty()));
            assert!(metadata.windows(2).all(|pair| pair[0].key < pair[1].key), "metadata keys must be sorted and unique");
        }
    }
}

fn control(mode: &str, address: &str, socks: &str, version: &str, profile: &str) -> Value {
    json!({"mode":mode, "address":address, "socks":socks, "version":version, "profile":profile, "timeout_ms":12000})
}

fn expected_services(profile: &str) -> Vec<String> {
    let mut names = vec!["grpc.reflection.v1.ServerReflection".to_owned(), "grpc.reflection.v1alpha.ServerReflection".to_owned()];
    if profile == "full" {
        for suffix in ["log.command.LoggerService", "proxyman.command.HandlerService", "router.command.RoutingService", "stats.command.StatsService"] {
            names.push(format!("xray.app.{suffix}"));
            names.push(format!("v2ray.core.app.{suffix}"));
        }
        names.push("xray.core.app.observatory.command.ObservatoryService".into());
    } else if profile == "stats" {
        names.push("xray.app.stats.command.StatsService".into());
        names.push("v2ray.core.app.stats.command.StatsService".into());
    }
    names.sort();
    names
}

fn validate(outcome: &Outcome, profile: &str) {
    if profile == "disabled" {
        assert!(outcome.services.is_empty() && outcome.handler_files.is_empty() && outcome.handler_sha256.is_empty());
        assert_eq!(outcome.checks, ["disabled_reflection_terminal_12"]);
        assert_eq!((outcome.queries, outcome.echoes, outcome.not_found), (0, 0, 0));
        assert_eq!((outcome.fresh_closures, outcome.repeated_roots, outcome.clean_eof, outcome.empty_eof), (0, 0, 0, 0));
        assert_eq!((outcome.terminal_code, outcome.cancelled_code), (12, 0));
        assert_eq!((outcome.dynamic_queries, outcome.dynamic_value), (0, 0));
        assert!(outcome.lookup_errors.is_empty());
        validate_streams(outcome, &[("disabled", 12, false)]);
        return;
    }
    assert_eq!(outcome.services, expected_services(profile));
    assert_eq!(outcome.handler_files, [
        "app/proxyman/command/command.proto", "common/protocol/user.proto",
        "common/serial/typed_message.proto", "core/config.proto",
    ]);
    assert_eq!(outcome.handler_sha256.len(), 64);
    assert!(outcome.handler_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!((outcome.queries, outcome.echoes, outcome.not_found), (28, 28, 5));
    assert_eq!((outcome.fresh_closures, outcome.repeated_roots, outcome.clean_eof, outcome.empty_eof), (4, 6, 5, 1));
    assert_eq!((outcome.terminal_code, outcome.cancelled_code), (3, 1));
    let missing = ["missing_filename", "missing_symbol", "missing_extension", "missing_type", "legacy_alias_symbol"];
    assert_eq!(outcome.lookup_errors.len(), missing.len());
    for (observed, query) in outcome.lookup_errors.iter().zip(missing) {
        assert_eq!(observed.query, query);
        assert_eq!(observed.code, 5);
        assert!(!observed.message.is_empty(), "lookup diagnostic was not captured");
    }
    validate_streams(outcome, &[
        ("main", 0, true), ("fresh", 0, true), ("empty", 0, true),
        ("missing_oneof", 3, false), ("missing_oneof_recovery", 0, true),
        ("cancelled", 1, false), ("survivor", 0, true),
    ]);
    let mut checks = vec![
        "all_five_query_variants", "both_reflection_schemas", "cancellation_code_1_concurrent_isolation",
        "clean_eof_after_requests", "empty_stream_clean_eof", "feature_set_extension_1002",
        "fresh_stream_cache_reset", "handler_four_file_fresh_registry", "host_original_request_echo",
        "missing_code_5_then_recovery", "missing_oneof_terminal_3_then_recovery",
        "repeated_root_dependencies_once", "send_recv_before_close_send", "sorted_service_visibility",
    ];
    if matches!(profile, "full" | "stats") {
        checks.push("dynamic_canonical_query_stats");
        assert_eq!((outcome.dynamic_queries, outcome.dynamic_value), (1, VALUE));
    } else { assert_eq!((outcome.dynamic_queries, outcome.dynamic_value), (0, 0)); }
    checks.sort();
    assert_eq!(outcome.checks, checks);
}

async fn probe(group: &Group, mode: &str, address: &str, socks: &str, version: &str, profile: &str) -> Outcome {
    let input = control(mode, address, socks, version, profile).to_string();
    let output = group.process(input.as_bytes()).await;
    assert!(output.status.success(), "reflection helper {}: {}", output.status, String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.ends_with(b"\n") && output.stdout.iter().filter(|&&byte| byte == b'\n').count() == 1, "expected exactly one stdout JSONL event");
    let event: Event = serde_json::from_slice(&output.stdout).expect("strict reflection stdout JSON event");
    assert_eq!(event.event, "done");
    assert_eq!(event.reference, PIN);
    assert_eq!(event.grpc_version, "1.85.0");
    assert_eq!(event.protobuf_version, "v1.36.12");
    assert!(event.go_version.starts_with("go1.27"));
    assert_eq!(event.mode, mode);
    assert_eq!(event.socks, socks);
    assert_eq!(event.version, version);
    assert_eq!(event.profile, profile);
    if mode == "baseline" {
        let endpoint: SocketAddr = event.address.parse().expect("actual configured Go Commander endpoint");
        assert!(endpoint.is_ipv4() && endpoint.ip().is_loopback() && endpoint.port() != 0);
    } else { assert_eq!(event.address, address); }
    validate(&event.result, profile);
    event.result
}

fn services(profile: &str) -> Vec<&'static str> {
    match profile {
        "full" => vec!["ReflectionService", "HandlerService", "LoggerService", "StatsService", "RoutingService", "ObservatoryService"],
        "stats" => vec!["ReflectionService", "StatsService"],
        "reflection" => vec!["ReflectionService"],
        "disabled" => vec!["StatsService"],
        _ => panic!("unknown test profile"),
    }
}

struct Root {
    instance: Instance,
    // A handle stays in its slot until its await completes. A timeout borrows it
    // instead of consuming/detaching it; completed handles are never polled twice.
    tasks: Vec<Option<JoinHandle<()>>>,
    address: String,
    close_attempted: bool,
}
struct CleanupReport {
    errors: Vec<String>,
    close_panic: Option<Box<dyn std::any::Any + Send>>,
}
impl Root {
    async fn compare(group: &Group, profile: &str, routed: bool) -> usize {
        group.check_work();
        // Config::build currently skips port-zero inbounds. Neither Commander
        // exposes its bound port. Keep a reservation through construction, then
        // release immediately before start and fail explicitly on bind races.
        let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
        let address = reservation.local_addr().unwrap();
        let mut config = json!({
            "api":{"tag":TAG, "listen":if routed {String::new()} else {address.to_string()}, "services":services(profile)},
            "stats":{}, "observatory":{"subjectSelector":[]},
            "outbounds":[{"tag":"reflection-deny", "protocol":"blackhole", "settings":{}}],
            "policy":{"system":{"statsOutboundUplink":true, "statsOutboundDownlink":true}},
        });
        if routed {
            config["inbounds"] = json!([{"tag":"reflection-socks", "listen":"127.0.0.1", "port":address.port(), "protocol":"socks", "settings":{"auth":"noauth", "udp":false}}]);
            config["routing"] = json!({"domainStrategy":"AsIs", "rules":[{
                "type":"field", "inboundTag":["reflection-socks"],
                "domain":["full:api-reflection.reference.invalid"], "port":"18080", "network":"tcp", "outboundTag":TAG,
            }]});
        }
        let config: Config = serde_json::from_value(config).expect("root reflection configuration");
        // from_config calls the public root Config::build; no private endpoint,
        // reflection function, descriptor pool, or ServiceOutbound is invoked.
        let instance = Instance::from_config(config).expect("build configured root reflection runtime");
        // Establish the owner BEFORE startup, seeding, or any runtime assertion.
        // Existing futures::FutureExt catches ordinary assertion/startup/probe
        // panics without swallowing them. No outer timeout cancels a live helper.
        let mut root = Self { instance, tasks: Vec::new(), address: address.to_string(), close_attempted: false };
        let attempted = AssertUnwindSafe(async {
            root.instance.stats_manager.register_counter(COUNTER).set(VALUE);
            drop(reservation);
            root.tasks = timeout_at(group.work_deadline, root.instance.start()).await
                .expect("root reflection startup exceeded work deadline")
                .expect("start configured root reflection runtime")
                .into_iter().map(Some).collect();
            assert!(root.instance.is_running());
            assert!(root.instance.get_feature("commander").is_some());
            if routed { assert_eq!(root.instance.inbound_manager.listen_addresses(), [address]); }
            else { assert!(root.instance.inbound_manager.listen_addresses().is_empty()); }
            let mut completed = 0;
            for version in VERSIONS {
                let baseline = probe(group, "baseline", "127.0.0.1:0", "", version, profile).await;
                if routed {
                    let before = root.traffic(TAG);
                    let actual = probe(group, "client", ROUTED, &root.address, version, profile).await;
                    assert_matches_baseline(&actual, &baseline, "SOCKS-routed result differs from actual Go Commander baseline");
                    let after = root.traffic(TAG);
                    assert!(after[0] > before[0] && after[1] > before[1], "tagged API outbound must carry both directions: {before:?} -> {after:?}");
                    assert_eq!(root.traffic("reflection-deny"), [0, 0], "reflection traffic reached the default blackhole outbound");
                } else {
                    let actual = probe(group, "client", &root.address, "", version, profile).await;
                    assert_matches_baseline(&actual, &baseline, "configured-listen result differs from actual Go Commander baseline");
                    assert_eq!(root.traffic(TAG), [0, 0], "direct API listener unexpectedly used routed outbound");
                }
                assert_eq!(root.instance.stats_manager.get_counter(COUNTER).unwrap().value(), VALUE);
                completed += 1;
            }
            group.check_work();
            completed
        }).catch_unwind().await;
        // Both success and every caught ordinary failure await the same teardown
        // before returning/resuming. Cleanup diagnostics never replace the
        // original panic payload; a cleanup-only failure still fails the test.
        let CleanupReport { errors, close_panic } = root.finish(group).await;
        match attempted {
            Ok(completed) => {
                if let Some(original) = close_panic {
                    eprintln!("root teardown failed: {}", errors.join("; "));
                    resume_unwind(original);
                }
                assert!(errors.is_empty(), "bounded root reflection teardown failed: {}", errors.join("; "));
                completed
            }
            Err(original) => {
                if !errors.is_empty() { eprintln!("root teardown also failed while preserving original failure: {}", errors.join("; ")); }
                resume_unwind(original)
            }
        }
    }

    fn traffic(&self, tag: &str) -> [i64; 2] {
        ["uplink", "downlink"].map(|direction| self.instance.stats_manager.get_counter(&format!("outbound>>>{tag}>>>traffic>>>{direction}")).map_or(0, |counter| counter.value()))
    }

    async fn finish(&mut self, group: &Group) -> CleanupReport {
        let end = (Instant::now() + Duration::from_secs(5)).min(group.deadline);
        let graceful_end = end - Duration::from_secs(2);
        let mut errors = Vec::new();
        let mut close_panic = None;
        self.close_attempted = true;
        match catch_unwind(AssertUnwindSafe(|| self.instance.close())) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("close root reflection runtime: {error}")),
            Err(original) => {
                let detail = original.downcast_ref::<String>().map(String::as_str)
                    .or_else(|| original.downcast_ref::<&str>().copied()).unwrap_or("non-string panic payload");
                errors.push(format!("close root reflection runtime panicked: {detail}"));
                close_panic = Some(original);
            }
        }
        for slot in &mut self.tasks {
            if let Some(task) = slot.as_mut() {
                match timeout_at(graceful_end, &mut *task).await {
                    Ok(joined) => {
                        let _ = slot.take(); // Await completed; safe to release.
                        if let Err(error) = joined {
                            if !error.is_cancelled() { errors.push(format!("root listener task panicked: {error}")); }
                        }
                    }
                    Err(_) => {
                        errors.push("root task graceful join exceeded its subbudget; aborting and awaiting retained handles".into());
                        break;
                    }
                }
            }
        }
        // Abort ALL outstanding tasks before awaiting any; otherwise one slow
        // task could consume the reserve before later tasks are even cancelled.
        for task in self.tasks.iter().flatten() { task.abort(); }
        for slot in &mut self.tasks {
            if let Some(task) = slot.as_mut() {
                match timeout_at(end, &mut *task).await {
                    Ok(joined) => {
                        let _ = slot.take();
                        if let Err(error) = joined {
                            if !error.is_cancelled() { errors.push(format!("aborted root task panicked: {error}")); }
                        }
                    }
                    Err(_) => errors.push("aborted root task did not join within the reserved group deadline".into()),
                }
            }
        }
        if self.instance.is_running() { errors.push("root still reports running after close".into()); }
        if Instant::now() >= group.deadline { errors.push("root cleanup exceeded the 60-second group deadline".into()); }
        CleanupReport { errors, close_panic }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        // Emergency fallback for external cancellation, not the ordinary test
        // failure path. compare always awaits finish before propagating a panic.
        if !self.close_attempted { let _ = self.instance.close(); }
        for task in self.tasks.iter().flatten() { task.abort(); }
    }
}

async fn strict_controls(group: &Group) -> usize {
    let valid = control("client", "127.0.0.1:1", "", "v1", "full");
    let encoded = valid.to_string();
    let changed = |key: &str, value: Value| { let mut input = valid.clone(); input[key] = value; input.to_string() };
    let mut bad_socks = valid.clone();
    bad_socks["address"] = json!(ROUTED);
    bad_socks["socks"] = json!("192.0.2.1:1080");
    let mut baseline_socks = bad_socks.clone();
    baseline_socks["mode"] = json!("baseline");
    baseline_socks["socks"] = json!("127.0.0.1:1080");
    let cases = [
        (encoded.replacen('{', r#"{"mode":"baseline","#, 1), "unknown/duplicate/invalid"),
        (encoded.replacen('{', r#"{"unknown":true,"#, 1), "unknown/duplicate/invalid"),
        (format!("{encoded} {{}}"), "trailing JSON"),
        (changed("mode", Value::Null), "null control field"),
        (changed("timeout_ms", json!("12000")), "cannot unmarshal"),
        (changed("timeout_ms", json!(1.5)), "cannot unmarshal"),
        (r#"{"mode":"client"}"#.into(), "missing JSON control field"),
        ("[]".into(), "expected JSON control object"),
        ("{".into(), "unexpected end of JSON input"),
        (format!("{encoded}{}", " ".repeat(65537)), "JSON control exceeds 64 KiB"),
        (changed("mode", json!("server")), "unsupported mode"),
        (changed("version", json!("v2")), "unsupported reflection version"),
        (changed("profile", json!("unknown")), "unsupported profile"),
        (changed("timeout_ms", json!(0)), "timeout_ms must be in 1..15000"),
        (changed("timeout_ms", json!(15001)), "timeout_ms must be in 1..15000"),
        (changed("address", json!("192.0.2.1:80")), "IPv4 loopback"),
        (changed("address", json!("127.0.0.1:0")), "IPv4 loopback"),
        (bad_socks.to_string(), "IPv4 loopback"),
        (changed("socks", json!("127.0.0.1:1080")), "SOCKS requires client mode and the fixed routed target"),
        (baseline_socks.to_string(), "SOCKS requires client mode and the fixed routed target"),
    ];
    let mut completed = 0;
    for (input, diagnostic) in cases {
        let output = group.process(input.as_bytes()).await;
        assert!(!output.status.success(), "invalid control unexpectedly succeeded");
        assert!(output.stdout.is_empty(), "invalid control emitted stdout");
        assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic), "missing strict-control diagnostic {diagnostic:?}: {}", String::from_utf8_lossy(&output.stderr));
        completed += 1;
    }
    assert_eq!(completed, 20);
    completed
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_API_REFLECTION_GO_PEER built on Linux"]
async fn api_reflection_go_reference_commander_baseline() {
    let _ = binary();
    let group = Group::new();
    let mut completed = 0;
    for profile in PROFILES {
        for version in VERSIONS {
            probe(&group, "baseline", "127.0.0.1:0", "", version, profile).await;
            completed += 1;
        }
    }
    assert_eq!(completed, 8, "eight actual Go Commander probe cases required");
    assert_eq!(strict_controls(&group).await, 20);
    group.check();
    eprintln!("reflection-live commander_baseline: cases={completed}, strict_controls=20, successful_helpers=8");
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_API_REFLECTION_GO_PEER built on Linux"]
async fn api_reflection_go_reference_configured_listen() {
    let _ = binary();
    let group = Group::new();
    let mut completed = 0;
    for profile in PROFILES {
        completed += Root::compare(&group, profile, false).await;
    }
    assert_eq!(completed, 8, "eight actual Rust listener / Go baseline pairs required");
    group.check();
    eprintln!("reflection-live configured_listen: pairs={completed}, successful_helpers=16");
}

#[tokio::test]
#[ignore = "mandatory when selected; requires XRAY_API_REFLECTION_GO_PEER built on Linux"]
async fn api_reflection_go_reference_tagged_service_outbound() {
    let _ = binary();
    let group = Group::new();
    let mut completed = 0;
    for profile in PROFILES {
        completed += Root::compare(&group, profile, true).await;
    }
    assert_eq!(completed, 8, "eight actual SOCKS / route / tagged API outbound / Go baseline pairs required");
    group.check();
    eprintln!("reflection-live tagged_service_outbound: pairs={completed}, successful_helpers=16");
}
