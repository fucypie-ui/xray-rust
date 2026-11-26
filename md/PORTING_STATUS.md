# Xray-core parity status

Full 1:1 compatibility is **not established**. A matching directory layout, file count, or Rust-to-Rust round trip does not prove that the Go and Rust implementations interoperate.

## Reference snapshot

- Go source: the adjacent `Xray-core/` checkout, commit `67756b3` (`common/bytespool, common/buf: Pool array pointers to avoid allocations`).
- Rust starting point: commit `2962787` (`v3.5.1`).
- Current continuation branch: `port/parity-ci`.
- Existing conversion ledgers are historical inventories; their 100% claims are not a verified baseline.

## Current continuation work

| Area | Work | Verification status |
| --- | --- | --- |
| Raw ChaCha20 stream | Preserve unused keystream between calls; accept Go's 8- and 12-byte nonce forms; expose `new_chacha20_stream`; reset buffered state when setting the counter. | Exact Go vectors, every two-call split, multi-block fragmentation, invalid inputs, and differently fragmented encrypted I/O passed as part of baseline runner validation. |
| SOCKS | SOCKS4/4a and SOCKS5 handshake validation, method negotiation, password authentication, and runtime configuration integration. | Independent wire fixtures, fragmented-I/O tests, and Config::build-to-handshake tests passed in the combined Linux run at `dc4e878`. |
| DNS | Decode/validate DNS messages with Hickory; UDP transaction matching and EDNS retry; concurrent A/AAAA queries; bounded TCP/DoH exchanges; remaining cache TTL and family/disable options. DoH verifies TLS certificates and requires complete bounded HTTP framing. DoQ now fails explicitly. | The first 28 added regression tests using hand-packed messages and loopback UDP/TCP/HTTP peers passed at `dc4e878`. An additional 13 DoH loopback tests cover certificate rejection, length overflow, incomplete framing, valid fragmentation/trailers, and H2 size limits; runner validation is pending. |
| Routing | Shared ordered conditions across both router interfaces; lazy cached DNS and retry semantics; fallback-tag handling; matcher/CIDR corrections; bounded round-robin state. | The 40 added regression tests, including Go-derived vectors, passed in the combined Linux run at `dc4e878`. |
| Protocol sniffing | Authenticate/decrypt QUIC Initial packets (draft-29/v1/v2), bounded CRYPTO reassembly, stricter TLS/SNI parsing, and production dispatcher integration. | All eight captured fixtures match adjacent Go sources byte-for-byte. Go QUIC reference tests and the combined Rust Linux run at `dc4e878` passed, including corrected SNI length tests. |
| CLI | Shared command parser, Go-style flags, actual TLS certificate/probe operations, UUIDv5 input, and explicit errors for unimplemented API/YAML/TOML behavior. | Parser, key/certificate, TLS loopback, UUID, file, and failure-path tests passed in the combined Linux run at `dc4e878`. |

## Build and test coverage

Baseline commit `c73a8d1` passed runner checks, debug/release builds, unit/scenario tests, and doc tests in [run 45881139481](https://github.com/fucypie-ui/xray-rust/actions/runs/45881139481). Its Linux library suite reported **717 passed, 0 failed**. That run predates the combined module changes in this batch; it does not validate them.

The first Linux-only module run, [45881825820](https://github.com/fucypie-ui/xray-rust/actions/runs/45881825820), passed at `38e0f65`: **784 library tests passed**, plus debug/release builds and documentation tests. This establishes a passing DNS/SOCKS checkpoint, before the routing, CLI, and sniffer integration.

The integrated source at `9c15663` passed all-target checks and debug/release builds in [run 45882535945](https://github.com/fucypie-ui/xray-rust/actions/runs/45882535945). Its library suite reported **882 passed, 1 failed**: a negative SNI test shortened `c.s-microsoft.com` by one byte and incorrectly expected rejection. The unchanged Go capture contains `c.s-microsoft.com`; this test performs byte extraction, not a live DNS or website check. The three binary configuration tests passed. This run is not a passing combined checkpoint.

The corrected combined checkpoint, `dc4e878`, passed [run 45883176927](https://github.com/fucypie-ui/xray-rust/actions/runs/45883176927): **884 library tests and 3 binary tests passed, 0 failed**, with no ignored or filtered tests. Locked all-target checks, debug/release builds, and the documentation-test command also passed; the current documentation suite contains zero runnable tests. This run includes DNS/SOCKS, routing, CLI, authenticated QUIC/TLS sniffing, and the SNI test correction, but predates the additional DoH authentication/framing fixes.

`.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch:

- Ubuntu 24.04 only: locked all-target checks, library/binary builds, serial unit/scenario tests, and documentation tests. Windows jobs were removed at the user's request.
- Ubuntu 24.04: an additional release build to cover release-only configuration.
- Failures remain visible; no test exclusions, warning overrides, or `continue-on-error` are used.

Rust is not installed and builds are not performed on the local Android device, as requested to conserve storage. Windows, privileged TUN/Wintun operation, Android/iOS packaging, and `debug_panel/dioxus_app` are not covered by this Linux-only workflow. Passing CI alone does not establish full cross-implementation interoperability.

## Confirmed open work

These findings are based on source comparisons. They are not live interoperability test results. P0 items prevent claiming protocol compatibility or equivalent authentication.

| Priority | Area and evidence | Next bounded implementation |
| --- | --- | --- |
| P0 | VMess: `proxy/vmess/encoding/encoding.rs` writes a plaintext UUID/header, and inbound/outbound return the raw stream. Go uses AEAD sessions in `proxy/vmess/encoding/client.go` and `server.go`. | Implement authenticated request/response headers, then body encryption/framing, with Go-to-Rust and Rust-to-Go tests. |
| P0 | REALITY: the configured VLESS client uses ordinary TLS with insecure certificate acceptance; `auth_client_hello` is not on that path. The server creates a normal self-signed certificate. See `proxy/vless/outbound/outbound.rs`, `transport/internet/reality/reality.rs`, and Go's `transport/internet/reality/reality.go`. | Integrate actual ClientHello session-ID authentication, key-share handling, and AuthKey-bound certificate verification. |
| P0 | Shadowsocks 2022: `proxy/shadowsocks_2022/protocol.rs` writes an unencrypted alternate header; configured Shadowsocks still selects legacy handlers. Go's `proxy/shadowsocks_2022/stream.go` derives subkeys and seals headers/chunks. | Implement single-user AES-2022 TCP salt/KDF/header/chunk processing and method selection, then EIH/relay/UDP. |
| P0 | WireGuard: `proxy/wireguard/client.rs` sends application bytes directly over UDP, without a WireGuard device, handshake, or tunnel stack. The runtime config model also misses standard camelCase key fields. | Correct config mapping, then connect a real WireGuard device and userspace IP stack before advertising tunnel support. |
| P0 | Hysteria: `proxy/hysteria/client.rs` opens TCP; `transport/internet/hysteria/` contains transport/counter scaffolding instead of the Go QUIC and HTTP/3 authentication path. | Establish real QUIC plus HTTP/3 authentication and one TCP stream before UDP/congestion-control work. |
| P0 | ML-KEM: `main/commands/all/mlkem768.rs` hashes a seed instead of generating an ML-KEM key pair. | Use a real algorithm implementation and authoritative known-answer tests. |
| P1 | mKCP: `transport/internet/kcp/listener.rs` has no receive/demultiplex loop, and connections require manually driven input/flush. | Add session acceptance, timed retransmission, a blocking async stream adapter, and config integration. |
| P1 | Root configuration: `infra/conf/conf.rs` omits executable wiring for policy, API, metrics, stats, reverse, and observatory settings present in Go's root builder. | Connect policy from JSON through registered features and real session use, then complete the remaining app slices. |
| P1 | Lifecycle: `core/xray.rs` does not retain/cancel all listener tasks, start/close every registered feature, or defer unresolved feature dependencies as Go does. | Implement complete shutdown with owned handles/cancellation, then deferred dependency resolution. |
| P1 | Protobuf: `core/config.rs` registers the JSON loader under the protobuf format. | Decode real protobuf and convert it into executable configuration. |
| P1 | DNS-over-QUIC: `app/dns/nameserver_quic.rs` now returns an explicit unimplemented error; no QUIC connection is established. | Implement a real DoQ connection and wire query path with a local QUIC test peer. |
| P1 | YAML/TOML: real decoders and loader integration remain absent. | Implement actual format conversion and equivalent validation; explicit unsupported errors are preferable to accepting JSON under another format name. |

## Remaining gaps in this batch

- SOCKS: full UDP relay, actual gateway bind addresses, HTTP fallback, and policy/retry behavior. Outbound UDP is explicitly unsupported.
- DNS: negative/per-family caching, in-flight query coalescing, stale background refresh, real DoQ, and routed UDP integration tests. Malformed partial answers are rejected more strictly than Go's current parser.
- Routing: attributes/local-IP/local-port/VLESS-route conditions, external geodata validation, negative-CIDR unions, outbound-manager candidate selection, and complete observatory/least-load semantics.
- Sniffing: complete HTTP/domain-address parity, encrypted draft-29 fixture coverage, typed need-more-data errors, and non-UTF-8 SNI representation. The shared sniffer does not retain Go's per-connection candidate pruning; dispatcher buffering remains TLS-specific, so fragmented QUIC currently needs accumulated datagrams from its caller.
- CLI: real gRPC API transport, complete config-loading/exit-code parity, uTLS fingerprints/PQ reporting, and other utilities. Certificate durations currently require positive values capped at 100 years. `curve25519.rs` still computes Hash32 with SHA-256 rather than Go's BLAKE3.

Passing checkpoints above describe their exact commits; pending DoH changes are not covered by those results.
