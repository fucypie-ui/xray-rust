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

## Current integrated protocol snapshot

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
- SS2022 now includes AES/ChaCha TCP, identity-chain/relay codecs and UDP session primitives. Its extended Go fixtures and Rust comparisons passed at `517a155`; native UDP runtime wiring and a successful overall Rust run remain open.

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
| P0 | Combined Linux validation | All-target check and debug/release builds passed at `517a155`. Fix the eight library failures and 20 Clippy errors, then repeat all checks on one exact integration revision. |
| P0 | VMess, REALITY, WireGuard and Hysteria | Pass independent byte fixtures plus nonempty live pinned-Go gates. VMess still needs anti-probing drainer parity; REALITY advanced fingerprint/ML-DSA/spider behavior, WireGuard dynamic/platform APIs, and Hysteria Brutal remain incomplete. |
| P0 | Shadowsocks | Extended SS2022 assertions passed at `517a155`; finish native UDP/relay binding and live peers. Classic Shadowsocks still requires its own encrypted runtime review. |
| P1 | mKCP and multiplex | Go-frame/trace and native/loss/cancellation tests passed at `517a155`; add live Go mKCP sessions and broader multiplex interoperability. KCP seed/header settings follow current Go's raw no-op behavior unless an explicit finalmask selects a legacy codec. |
| P1 | Binary config and root services | Shared byte-loader dispatch is integrated at `1ec1a9c` and awaits its Linux executable tests. Complete remaining CLI merge/source/flag semantics, RPC/reflection/API CLI methods, advanced FakeDNS, environment/geodata and observatory routing. |
| P1 | Remaining transports, masks, routing and platform options | Work through every current matrix row, including MASQUE, XDrive, gRPC/XHTTP composition, TLS/ECH options, DNS-over-QUIC and socket/OS behavior. |

## Remaining gaps in this batch

- SOCKS: full UDP relay, actual gateway bind addresses, HTTP fallback, and policy/retry behavior. Outbound UDP is explicitly unsupported.
- DNS: negative/per-family caching, in-flight query coalescing, stale background refresh, real DoQ, and routed UDP integration tests. Malformed partial answers are rejected more strictly than Go's current parser.
- Routing: attributes/local-IP/local-port/VLESS-route conditions, external geodata validation, negative-CIDR unions, outbound-manager candidate selection, and complete observatory/least-load semantics.
- Sniffing: complete HTTP/domain-address parity, encrypted draft-29 fixture coverage, typed need-more-data errors, and non-UTF-8 SNI representation. The shared sniffer does not retain Go's per-connection candidate pruning; dispatcher buffering remains TLS-specific, so fragmented QUIC currently needs accumulated datagrams from its caller.
- CLI: real gRPC API transport, complete config-loading/exit-code parity, uTLS fingerprints/PQ reporting, and other utilities. Certificate durations currently require positive values capped at 100 years.

Passing checkpoints above describe their exact commits. Later unvalidated work must not be attributed to an earlier passing checkpoint. The remaining protocol/runtime gaps above still prevent a full 1:1 compatibility claim.
