# Xray-core parity status

Full 1:1 compatibility is **not established**. A matching directory layout, file count, or Rust-to-Rust round trip does not prove that the Go and Rust implementations interoperate.

## Reference snapshot

- Go source: the adjacent `Xray-core/` checkout, commit `67756b3` (`common/bytespool, common/buf: Pool array pointers to avoid allocations`).
- Rust starting point: commit `2962787` (`v3.5.1`).
- Current continuation branch: `port/parity-ci`.
- Existing conversion ledgers are historical inventories; their 100% claims are not a verified baseline.

## Earlier validated work

| Area | Work | Verification status |
| --- | --- | --- |
| Raw ChaCha20 stream | Preserve unused keystream between calls; accept Go's 8- and 12-byte nonce forms; expose `new_chacha20_stream`; reset buffered state when setting the counter. | Exact Go vectors, every two-call split, multi-block fragmentation, invalid inputs, and differently fragmented encrypted I/O passed as part of baseline runner validation. |
| SOCKS | SOCKS4/4a and SOCKS5 handshake validation, method negotiation, password authentication, and runtime configuration integration. | Independent wire fixtures, fragmented-I/O tests, and Config::build-to-handshake tests passed in the combined Linux run at `dc4e878`. |
| DNS | Decode/validate DNS messages with Hickory; UDP transaction matching and EDNS retry; concurrent A/AAAA queries; bounded TCP/DoH exchanges; remaining cache TTL and family/disable options. DoH verifies TLS certificates and requires complete bounded HTTP framing. DoQ now fails explicitly. | All 41 added regression tests passed at `11ef08e`: the first 28 wire/transport/cache cases plus 13 DoH loopback cases covering certificate rejection, length overflow, incomplete framing, valid fragmentation/trailers, and H2 size limits. |
| Routing | Shared ordered conditions across both router interfaces; lazy cached DNS and retry semantics; fallback-tag handling; matcher/CIDR corrections; bounded round-robin state. | The 40 added regression tests, including Go-derived vectors, passed in the combined Linux run at `dc4e878`. |
| Protocol sniffing | Authenticate/decrypt QUIC Initial packets (draft-29/v1/v2), bounded CRYPTO reassembly, stricter TLS/SNI parsing, and production dispatcher integration. | All eight captured fixtures match adjacent Go sources byte-for-byte. Go QUIC reference tests and the combined Rust Linux run at `dc4e878` passed, including corrected SNI length tests. |
| CLI | Shared command parser, Go-style flags, actual TLS certificate/probe operations, UUIDv5 input, and explicit errors for unimplemented API/YAML/TOML behavior. | Parser, key/certificate, TLS loopback, UUID, file, and failure-path tests passed in the combined Linux run at `dc4e878`. |

## Follow-up execution: ccaffb0 and Mux supervisor race

Source `ccaffb033487d0075da64b6df40dc8007107f9c4` passes Rust CI 45901191650: **1,175 library / 9 binary**, no failures, 18 ordinary ignored, locked check/debug/release, 15 built-CLI comparisons, 21 argument/error checks and documentation command (zero runnable cases). Protocol 45901191660 passes strict Clippy and **17/17** live cases; classic byte workflow 45901193171 passes its required trait test and reverse Go decoding. The earlier classic scenario and concurrent Mux case both pass in the ordinary suite.

Additional isolated probe 45901313190 prevents promotion: with unchanged ccaffb0 source, the strict open-peer BrokenPipe regression fails **4/10** times, while concurrent payload/metadata/close passes **40/40** and the clean-EOF regression **10/10**. Injecting the old 1c938da runtime beneath the new single-attempt EOF test produces **4/5** expected BrokenPipe failures and one pass, so this first fixture is red-capable but not deterministic. Its 60 patched-source invocations therefore give 56 passes, four failures; the probe is correctly FAILED. Baseline unmodified-source probe 45900794913 separately reproduces the original concurrent BrokenPipe **7/40** times.

A follow-up source correction prioritizes the I/O driver and, on a channel-derived Ok/Closed result, awaits its authoritative completion before cleanup. This addresses channel closure becoming visible on another worker before the task result is joinable. Paired regressions now run 64 scenarios each; the open-peer test uses two workers and requires exact BrokenPipe. This follow-up is source-only pending a new exact-revision Linux run; no failure is waived. Other lane sources remain excluded. Evidence: combined-ccaffb0/ and combined-1c938da/mux-close-probe/ under the approved evidence directory.

## Previous executed source: 1c938da

Revision `1c938daac7a3105f64e8cc26c11e2dbe2cfcdc54` passes strict Clippy, all 17 selected live cases (including the first two SS2022 UDP groups), and bidirectional classic independent-byte validation. Ordinary CI records 1,171 library passes, two failures and 18 ignored cases; nine binary cases and locked check/debug/release pass, while CLI/docs are skipped. The two failures are Mux close `BrokenPipe` and an invalid older classic scenario inbound shape. The detailed follow-up at the end preserves run identities and scope. This is not an all-green integrated checkpoint.

The next source change supervises Mux read/write together to prioritize simultaneous clean EOF, adds paired EOF/open-peer write-error regressions, and corrects the classic scenario input to top-level inbound method/password. Existing echo, metadata, empty-packet, strict join and frozen-byte assertions remain. These corrections await remote Linux execution. Classic live peers, SS2022 relay UDP and gRPC Gun changes remain outside this snapshot.

## Last fully passing integrated Linux snapshot: 98f42c8

Native SS2022/config integration `98f42c8419bdd75893de2b99f3c422f7c1a7b5a1` passed Rust CI `45897222837`: locked all-target checking, debug/release builds, **1,151 library tests passed / 0 failed / 15 ignored**, **9 binary tests passed**, **15 built-CLI comparisons**, and the documentation command (zero runnable tests). All eight new native tests and five new configuration cases executed. Same-revision workflow `45897222798` passed strict all-target Clippy and all 15 required live cases: REALITY 3/3, WireGuard 8/8, Hysteria 2/2 and mKCP 2/2, with zero ignored in those gates. The independent-byte test at the production SS2022 handler boundary uses frozen Go packets, not a live Go peer.

The preceding complete checkpoint `fd2d231005e8d518e9b3cf76816e79cd2f33a92b` passed all three workflows: Rust CI `45896822590` (**1,138 library / 9 binary / 15 CLI comparisons**, zero failures; 15 ordinary ignored live cases), protocol interoperability `45896822633` (**REALITY 3/3, WireGuard 8/8, Hysteria 2/2, mKCP 2/2**, all 15 executed with zero ignored, plus strict all-target Clippy), and all eight independent Go-reference jobs `45896822491`. The mKCP gate exercises both directions at MTUs 1350 and 200, exact binary fragmentation, EOF, post-close writes and terminal state. It establishes those scenarios, not all mKCP options or protocol composition.

SS2022 native relay UDP remains unsupported. The native queue/flow/address/idle bounds and one logical source per outbound association are not policy parity. A live Go SS2022 gate is being added separately. Classic Shadowsocks source/configuration and its reviewed engine dependency remain separate, uncommitted integration work. The isolated `port/classic-engine-lock` branch prepares a Linux-generated lock only; it is not a runtime parity checkpoint.

Evidence directories: `/data/data/com.termux/files/usr/tmp/opencode/combined-98f42c8/` and `/data/data/com.termux/files/usr/tmp/opencode/combined-fd2d231/`, including complete logs and exact-SHA result JSON.

## Previous executed Linux snapshot: d977720

Rust CI `45896320540` succeeded at `d97772052d4d154bd2403f6d5fa59ed95d911f24`: locked all-target checking, debug/release builds, **1,138 library tests passed / 0 failed / 15 ignored**, **9 binary tests passed**, and **15 built-CLI comparisons** against pinned Go output. The documentation-test command passed with zero runnable tests. The VMess UDP fragmentation/EOF regression passed while retaining both ciphers, duplex capacity 32 and the 10-second timeout.

Interop `45896320441` again passed **REALITY 3/3, WireGuard 8/8, Hysteria 2/2 and strict Clippy**. Its two new mKCP cases executed but failed strict readiness JSON parsing because production Go diagnostics appeared on stdout. The full interoperability workflow therefore failed, and mKCP live sessions remain unproved. All eight independent Go-reference jobs passed in `45896320504`. The 15 ordinary ignored tests are required separately by live gates; they are not ordinary passes.

Helper logging correction `fd2d231005e8d518e9b3cf76816e79cd2f33a92b` subsequently passed the complete gates recorded above. Native SS2022 integration `98f42c8` subsequently passed ordinary Linux CI: actual BoxDatagram outbound, single-user/AES multi-user network-selective native listeners, cancellation/socket cleanup, eight native tests and five configuration tests. No live Go SS2022 gate exists yet. Classic Shadowsocks remains separate uncommitted work.

Raw evidence: `/data/data/com.termux/files/usr/tmp/opencode/combined-d977720/`, including complete CI/interop/reference logs and result JSON. Source freezes and helper builds are kept distinct from executed engine evidence.

## Previous executed Linux snapshot: cf9510e

Revision `cf9510e4a5c98607ba5ae8e8efd32ad9891ab833` passed locked all-target checking and debug/release builds in Rust CI `45895829517`. The ordinary library suite executed **1,137 passed / 1 failed / 13 ignored**; binary tests passed **9/9**, including the shared byte-loader regressions for JSONC/YAML/TOML/protobuf. The only library failure was `proxy::vmess::reference_test::runtime_udp_datagrams_remain_separate_under_fragmentation`: a 10-second teardown timeout. Key-command comparison and documentation steps remained skipped, so full Rust CI failed.

Protocol interoperability run `45895829521` succeeded at the same revision: **REALITY 3/3, WireGuard 8/8, Hysteria 2/2**, with all 13 selected cases actually executed and zero ignored within those gates. Strict all-target Clippy passed. These results validate the represented engine scenarios, including authenticated REALITY exchanges, WireGuard dual-stack fragmentation and Hysteria teardown; broader configuration, options, routing and protocol composition remain partial.

Source `d97772052d4d154bd2403f6d5fa59ed95d911f24` has been pushed for a new Linux run. It preserves Go's VMess EOF rule and drains the remaining raw terminal tail in the bounded-duplex regression before awaiting peer teardown. It also includes `480560d`'s two required bidirectional live pinned-Go mKCP tests at MTUs 1350 and 200. Protocol run `45896320441` executed both new mKCP cases but failed readiness parsing because Go diagnostics preceded JSON on stdout; session interoperability is still unproved. The other 13 live cases and strict Clippy passed again. Ordinary CI `45896320540` subsequently succeeded as recorded above. The live workflow now requires 15 cases across four engines. mKCP full-close semantics remain distinct from TCP half-close.

SS2022 native UDP/configuration and classic Shadowsocks runtime changes were excluded from that tested snapshot; the following SS2022 source integration is recorded above. SS2022 omitted/null JSON selects TCP; an empty JSON array produces an empty native list, whose constructor default selects TCP+UDP. Go folds network-token case without trimming whitespace. Unknown/Unix network selections and relay UDP remain explicitly unsupported in the pending Rust integration.

Raw evidence: `/data/data/com.termux/files/usr/tmp/opencode/combined-cf9510e/ci-clean.log` and `interop-full-clean.log`, with corresponding job-result JSON. Earlier results below are historical and do not replace this revision-scoped evidence.

## Earlier integrated protocol snapshot: 517a155

Integrated source `517a155` passed Ubuntu all-target checking and debug/release builds. Full protocol parity is not established: ordinary tests and required live gates found failures. Targeted follow-up fixes are being collected for the next Linux run. The frozen integration includes authenticated VMess, REALITY hooks, the mKCP runtime, encrypted BoringTun/smoltcp WireGuard, QUIC/H3 Hysteria, extended SS2022 codecs, native listeners/datagrams, bounded multiplex dispatch, and root configuration/policy/services. See `md/PARITY_MATRIX.md` for current call paths, historical findings and remaining work.

- First combined source `584cd13` failed Ubuntu Rust CI run `45892518490` on missing SS2022 dependency and configuration/REALITY/Hysteria API issues. The live jobs stopped at compilation; none established interoperability.
- Fixes through `c92390f` include the latest reviewed `shadowsocks-crypto 0.8.0`, Linux-resolved lock from run `45893018658`, native protobuf map conversion, task ownership, REALITY type annotation, hash encoding, and duplicate test registration. Recheck run `45893215688` found probe URL inference plus a release-only unnecessary mutable binding; `7463794` corrects those reports.
- `517a155` includes multiplex generation/close fixes, native packet routing tests, and all 12 independently generated Go Mux records. Ubuntu Rust CI `45893541120` passed all-target check and debug/release builds. Its library suite finished with **1,120 passed / 8 failed / 13 ignored**; executable tests passed 4/4. The subsequent key-command comparison and documentation-test steps were skipped after failure.
- The eight library failures are native protobuf port ranges, level-one default policy, VMess UDP fragmentation shutdown, two WireGuard UDP cases, and three REALITY cases. All Mux runtime tests (including the 12-record independent comparison), KCP tests, SS2022 tests and Hysteria ordinary tests passed in that same suite; those scoped results do not turn the overall run green.
- Protocol workflow `45893541110` executed all required cases: **REALITY 1 passed / 2 failed; WireGuard 3 passed / 5 failed; Hysteria 1 passed / 1 failed**. Strict all-target Clippy reported 20 errors. Passing live cases are limited to their exact scenarios; no full-engine live gate passed.
- All eight independent Go reference jobs passed in run `45893018590`: config, Hysteria, KCP, Mux, REALITY, SS2022, VMess and WireGuard. Peer-helper builds are Go-side evidence; they do not validate Rust engines. SS2022 extended records were frozen from successful job `140158378278` in run `45892518463`.
- The protocol workflow requires at least three REALITY, eight WireGuard and two Hysteria live tests, with no ignored or zero-test success. Mandatory frozen-byte tests remain unconditional. The native/Freedom/Mux tests executed; scoped successes and engine failures are distinguished above.
- Dependencies now contain 73 direct entries across both manifests (70 unique packages). The earlier 72-entry dependency-branch pass is revision-scoped and does not validate the later engines or new SS2022 dependency.
- Follow-up source through `089fd8e` fixes strict-lint reports, Hysteria TCP/QUIC teardown, protobuf port range names, the Go level-one policy override, and WireGuard readiness logging/IPv6 ingress reassembly. `1ec1a9c` routes executable JSONC/YAML/TOML/protobuf input through the shared byte loader. These changes and `e811ca8`'s mandatory SS2022 fixture hash still await the next Linux run; no earlier PASS is assigned to them.

## Current cryptography and lifecycle continuation

- Cryptographic utilities now generate actual ML-KEM-768 keys from the Go-compatible 64-byte seed, return the full 1184-byte encapsulation key, and use BLAKE3 for Hash32. X25519 now prints the clamped private key and Go output labels. The shared executable dispatch uses these implementations, including the existing VLESS encryption utility caller.
- Checkpoint `81c18a1` passed Linux [run 45886462115](https://github.com/fucypie-ui/xray-rust/actions/runs/45886462115): **910 library tests and 3 binary tests passed**, with 15 built-CLI comparisons against independent Go fixtures, locked all-target checks, debug/release builds, and the documentation command (zero runnable doc tests). Further argument-grammar fixes and the combined SS2022/lifecycle changes are not covered by this checkpoint.
- Pinned Go fixture generation passed [run 45885788457](https://github.com/fucypie-ui/xray-rust/actions/runs/45885788457) using Go 1.27.4 and source `67756b3`. Regeneration also passed at `81c18a1` in [run 45886462164](https://github.com/fucypie-ui/xray-rust/actions/runs/45886462164), including byte-for-byte comparison of the frozen key fixtures. See `testing/REFERENCE_FIXTURES.md` for provenance, hashes and regeneration instructions.
- SS2022 now includes AES/ChaCha TCP, identity-chain/relay codecs and UDP session primitives. Its extended Go fixtures and Rust comparisons passed at `517a155`; native UDP runtime wiring and the overall ordinary suite subsequently passed at `98f42c8`; live Go SS2022 and relay UDP remain open.

## Build and test coverage

Baseline commit `c73a8d1` passed runner checks, debug/release builds, unit/scenario tests, and doc tests in [run 45881139481](https://github.com/fucypie-ui/xray-rust/actions/runs/45881139481). Its Linux library suite reported **717 passed, 0 failed**. That run predates the combined module changes in this batch; it does not validate them.

The first Linux-only module run, [45881825820](https://github.com/fucypie-ui/xray-rust/actions/runs/45881825820), passed at `38e0f65`: **784 library tests passed**, plus debug/release builds and documentation tests. This establishes a passing DNS/SOCKS checkpoint, before the routing, CLI, and sniffer integration.

The integrated source at `9c15663` passed all-target checks and debug/release builds in [run 45882535945](https://github.com/fucypie-ui/xray-rust/actions/runs/45882535945). Its library suite reported **882 passed, 1 failed**: a negative SNI test shortened `c.s-microsoft.com` by one byte and incorrectly expected rejection. The unchanged Go capture contains `c.s-microsoft.com`; this test performs byte extraction, not a live DNS or website check. The three binary configuration tests passed. This run is not a passing combined checkpoint.

The corrected combined checkpoint, `dc4e878`, passed [run 45883176927](https://github.com/fucypie-ui/xray-rust/actions/runs/45883176927): **884 library tests and 3 binary tests passed, 0 failed**, with no ignored or filtered tests. Locked all-target checks, debug/release builds, and the documentation-test command also passed; the current documentation suite contains zero runnable tests. This run includes DNS/SOCKS, routing, CLI, authenticated QUIC/TLS sniffing, and the SNI test correction, but predates the additional DoH authentication/framing fixes.

The final code checkpoint for the preceding batch, `11ef08e`, passed [run 45883644317](https://github.com/fucypie-ui/xray-rust/actions/runs/45883644317): **897 library tests and 3 binary tests passed, 0 failed**, with no ignored or filtered tests. All 13 additional DoH tests passed. Locked all-target checks, debug/release library and binary builds, and the documentation-test command passed on Ubuntu 24.04; the documentation suite still contains zero runnable tests. This checkpoint validates all code changes in that batch together.

`.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch:

- Ubuntu 24.04 only: locked all-target checks, library/binary builds, serial unit/scenario tests, and documentation tests. Windows jobs were removed at the user's request.
- Ubuntu 24.04: an additional release build to cover release-only configuration.
- Failures remain visible; no test exclusions, warning overrides, or `continue-on-error` are used.

Rust is not installed and builds are not performed on the local Android device, as requested to conserve storage. Windows, privileged TUN/Wintun operation, Android/iOS packaging, and `debug_panel/dioxus_app` are not covered by this Linux-only workflow. Passing CI alone does not establish full cross-implementation interoperability.

## Confirmed open work

The production engines below are integrated source, with remaining behavior and validation gaps. Historical plaintext/substitute findings are preserved in the matrix's baseline column; they do not describe the new implementation.

| Priority | Area | Next required result |
| --- | --- | --- |
| P0 | Combined Linux validation | Complete gates passed at `fd2d231`, including all 15 live cases. Native SS2022 ordinary CI passed at `98f42c8` (1,151 library/9 binary); all 15 existing live cases and strict Clippy passed on that same revision. |
| P0 | VMess, REALITY, WireGuard and Hysteria | Preserve the 13 passing REALITY/WireGuard/Hysteria live cases at `cf9510e`; complete broader independent and configured-runtime acceptance. VMess still needs anti-probing drainer parity; REALITY advanced fingerprint/ML-DSA/spider behavior, WireGuard dynamic/platform APIs, and Hysteria Brutal remain incomplete. |
| P0 | Shadowsocks | SS2022 native/config passed ordinary CI at `98f42c8`; finish relay UDP and live SS2022 peers. Classic encrypted runtime/config and its new engine lock remain separate and unvalidated. |
| P1 | mKCP and multiplex | Both required live mKCP tests passed at `fd2d231`; preserve full-close/EOF behavior and extend option/multiplex interoperability. KCP seed/header settings follow current Go's raw no-op behavior unless an explicit finalmask selects a legacy codec. |
| P1 | Binary config and root services | Shared byte-loader dispatch from `1ec1a9c` passed all nine binary tests at `cf9510e`. Complete remaining CLI merge/source/flag semantics, RPC/reflection/API CLI methods, advanced FakeDNS, environment/geodata and observatory routing. |
| P1 | Remaining transports, masks, routing and platform options | Work through every current matrix row, including MASQUE, XDrive, gRPC/XHTTP composition, TLS/ECH options, DNS-over-QUIC and socket/OS behavior. |

## Remaining gaps in this batch

- SOCKS: full UDP relay, actual gateway bind addresses, HTTP fallback, and policy/retry behavior. Outbound UDP is explicitly unsupported.
- DNS: negative/per-family caching, in-flight query coalescing, stale background refresh, real DoQ, and routed UDP integration tests. Malformed partial answers are rejected more strictly than Go's current parser.
- Routing: attributes/local-IP/local-port/VLESS-route conditions, external geodata validation, negative-CIDR unions, outbound-manager candidate selection, and complete observatory/least-load semantics.
- Sniffing: complete HTTP/domain-address parity, encrypted draft-29 fixture coverage, typed need-more-data errors, and non-UTF-8 SNI representation. The shared sniffer does not retain Go's per-connection candidate pruning; dispatcher buffering remains TLS-specific, so fragmented QUIC currently needs accumulated datagrams from its caller.
- CLI: real gRPC API transport, complete config-loading/exit-code parity, uTLS fingerprints/PQ reporting, and other utilities. Certificate durations currently require positive values capped at 100 years.

Passing checkpoints above describe their exact commits. Later unvalidated work must not be attributed to an earlier passing checkpoint. The remaining protocol/runtime gaps above still prevent a full 1:1 compatibility claim.

## Following source changes awaiting Linux execution

The next integration adds the maintained `shadowsocks` 1.25.0 classic engine: authenticated TCP and native packet-preserving UDP for the four pinned-Go AEAD methods, shared replay rejection, configured user metadata/network selection, injected stream dialers, cancellation and socket-release regressions. Thirteen ordinary runtime cases, five configuration cases and one selected independent-byte fixture case have been added; these counts describe source, not executed results. Classic multi-user accounts, UOT/mux, probing drain, nonplain configuration composition and TCP high-bit address flags remain open. The multiple-server Pingora dispatch remains an explicit Rust extension.

A separate frozen SS2022 live lane now supplies production Go client/server helpers and two selected tests: five cipher/account configurations in each direction and 60 exact UDP request/reply pairs. Three single-user methods and AES128/AES256 EIH are represented. Empty Go-client packets use production UDP session APIs because the pinned full Process path drops empty buffers. Relay is excluded. The module and mandatory Linux workflow gate are wired, but neither compilation nor live success is asserted before the new revision runs.

The classic multiple-server extension now forwards start/close to every child, cancels pending TCP/UDP connects and rejects wrapper reuse after close. Four ordinary lifecycle regression cases are added in source. Its shared Pingora idle pool retains existing eviction/timeout semantics and external holders can still access that pool; immediate draining is not claimed. All following integrated source still awaits Linux results.

### 292f689 combined run: upstream compile failure

Rust CI `45899217447`, protocol interop/Clippy `45899216622` and classic byte gate `45899216595` failed before Rust assertions: enabling shared crypto v2 exposed eleven missing `CipherCategory::Aead2022` match arms in shadowsocks 1.25.0 with the selected classic-only engine features. Go classic vector generation and the live SS2022 helper build succeeded, but neither constitutes Rust wire/live acceptance. Parent diagnosis retained the direct SS2022 crypto feature and enabled the corresponding upstream engine feature. Linux lock preparation `45899647196` succeeded; the corrected combined revision still needs compilation and executed gates. The last fully passing integrated ordinary/live baseline remains 98f42c8.

Linux runs at `1e8ae98367d4a6bc2c93f05aedf64a90976e9025` (`45899856179`, `45899856134`, `45899856091`) no longer report the upstream enum mismatch. They still stop before Rust assertions because the classic client imports `Pin` redundantly inside a select expansion; strict Clippy additionally flags a cloned one-element slice in a wrapper regression. The follow-up qualifies `std::pin::Pin` at the handshake call and uses `std::slice::from_ref` in the test. No warning allowances, test skips or protocol changes are introduced. Integrated executed evidence is still pending.

### Executed follow-up: 1c938da

At `1c938daac7a3105f64e8cc26c11e2dbe2cfcdc54`, Rust CI `45900139028` passes locked check/debug/release and nine binary tests, but the library reports **1,171 passed / 2 failed / 18 ignored**. All 13 classic runtime, five classic config and four wrapper lifecycle additions pass. The two failures are a Mux close `BrokenPipe` at the strict server-join assertion and an older full relay scenario using inbound `settings.servers` (not the Go inbound method/password schema). The scenario input is being corrected while preserving its successful SOCKS-to-classic-to-Freedom echo assertion; Mux diagnosis and an unchanged-source 40-iteration remote probe remain separate. CLI comparisons and doc steps were skipped, so this is not a fully passing integrated checkpoint.

Classic independent-byte workflow `45900139172` succeeds: one required Rust trait test executes with zero ignored, four AEAD methods, TCP/UDP Go-to-Rust and Go production reverse decoding of Rust output. The downloaded three JSONL digests match the artifact SHA256SUMS. This is byte evidence, not live classic sessions. Protocol workflow `45900139064` succeeds with strict Clippy and **17/17** required live tests: REALITY 3, WireGuard 8, Hysteria 2, mKCP 2 and the first SS2022 2. SS2022 covers five configurations per direction and 60 request/reply pairs; Go-client empty packets use production session APIs because pinned Process drops empty buffers. Relay UDP and following classic live/gRPC source stay excluded. Exact logs/artifacts are under `combined-1c938da/` in the approved evidence directory.
