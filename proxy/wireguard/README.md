# Authenticated userspace WireGuard

The runtime uses BoringTun's Noise engine and a WireGuard-local smoltcp IP
stack. Application bytes enter real TCP/UDP sockets. Only authenticated
WireGuard ciphertext reaches outer UDP. There is no Go runtime process,
plaintext fallback, root requirement, or dependency on proxy/tun/ipstack.

## Primary-source dependency review (2026-11-27)

Reviewed registry metadata, exact released crate archives, Cargo manifests,
licenses, and source APIs before implementing the engine. The parent owns
Cargo.toml/Cargo.lock changes and Ubuntu validation.

| Component | Reviewed release | Published | License | Source revision |
| --- | --- | --- | --- | --- |
| BoringTun | 0.7.1 | 2026-05-01 | BSD-3-Clause | 051c9d47dc9c5cb36e461b7d36dcd673820dc98b |
| smoltcp | 0.14.0 | 2026-08-17 | 0BSD | cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3 |
| netstack-smoltcp (not selected) | 0.2.5 | 2026-11-05 | MIT OR Apache-2.0 | Registry release inspected |

BoringTun and smoltcp were the newest non-yanked registry releases when
reviewed. smoltcp declares Rust 1.91 minimum; BoringTun's manifest declares no
MSRV. No dependency source is vendored here.

Primary sources:

- https://crates.io/api/v1/crates/boringtun/0.7.1
- https://docs.rs/boringtun/0.7.1/boringtun/noise/struct.Tunn.html
- https://github.com/cloudflare/boringtun/tree/051c9d47dc9c5cb36e461b7d36dcd673820dc98b
- https://crates.io/api/v1/crates/smoltcp/0.14.0
- https://docs.rs/smoltcp/0.14.0/smoltcp/iface/struct.Interface.html
- https://github.com/smoltcp-rs/smoltcp/tree/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3
- https://crates.io/api/v1/crates/netstack-smoltcp/0.2.5
- https://github.com/cavivie/netstack-smoltcp
- https://www.wireguard.com/protocol/

BoringTun exposes Tunn::new, encapsulate, decapsulate and update_timers, plus
X25519 reexports, without enabling privileged device/CLI defaults. Its engine
owns Noise handshakes, AEAD, cookies, replay windows, rekey and key expiry.
This adapter selects peers, validates inner sources, handles socket I/O,
and schedules engine timers.

A direct smoltcp IP-medium adapter supports outbound sockets and transparent
inbound forwarding. netstack-smoltcp was considered but its forwarding-oriented
API and early UDP packet extraction did not fit this outbound/reassembly path.
Async socket wakers support the Tokio wrappers.

smoltcp 0.14's IP medium neither emits nor reassembles IPv6 fragments. A small
WireGuard-only adapter emits IPv6 UDP fragments using smoltcp's UDP checksum
codec; every fragment still passes allowedIPs routing and Noise encryption.
Authenticated IPv6 ingress is reassembled before socket provisioning, then
passed through smoltcp's ordinary transport/checksum validation. Reassembly
allows at most 16 concurrent datagrams, 128 fragments per datagram and 65535
IPv6 payload bytes, with a fixed 60-second lifetime. Overlap poisons the whole
datagram until expiry; atomic fragments are processed independently. IPv4
fragmentation and reassembly use smoltcp. AnyIP supports both families through the shared
InterfaceInner::has_ip_addr check; no destination aliases are needed.

Requested dependencies (default features disabled):

- boringtun 0.7.1
- smoltcp 0.14.0 features: std, async, medium-ip, proto-ipv4, proto-ipv6,
  socket-tcp, socket-udp, proto-ipv4-fragmentation, proto-ipv6-fragmentation,
  reassembly-buffer-size-65536, fragmentation-buffer-size-65536,
  iface-max-addr-count-8

## Entry points and behavior

- Client::try_new(tag, config) validates synchronously. Client::new retains its
  infallible signature; start/connect validate before opening sockets. All
  flows share one lazily opened device/IP stack.
- OutboundHandler::connect returns a real userspace TCP BoxStream. A legacy UDP
  stream adapter remains for direct callers; native runtime UDP uses
  connect_datagram and never guesses packet boundaries from stream reads.
- OutboundHandler::connect_datagram returns a multi-destination BoxDatagram.
  send routes each packet independently; recv preserves the actual remote
  source and original local source from send as its destination. Empty UDP
  payloads are packets. Oversize payloads return an error.
- WireGuardDevice::bind(config, listen) provides connect_tcp/connect_udp,
  outer local address, MTU, counters, and explicit close/join.
- WireGuardServer::bind(tag, config, listen).await provides TCP accept and
  recv_datagram with payload/session/source/destination/reply. Replies originate
  from the original tunneled target.
- WireGuardInbound::try_new(tag, config) implements bind_native and supplies a
  NativeInboundListener. It dispatches authenticated TCP streams and per-flow
  UDP packet transports to InboundDispatcher. The stream-only inbound path
  returns Unsupported.

Keys accept hexadecimal, standard base64, and URL base64 with canonical
optional padding. JSON supports Go's secretKey, publicKey, preSharedKey,
keepAlive, allowedIPs, remoteDNS, email and level names plus prior snake_case
aliases. Validation rejects invalid/self/low-order/duplicate keys, malformed
prefixes/endpoints, bad reserved lengths, unsuitable interface addresses,
and MTU outside 576..65475 (minimum 1280 with IPv6). MTU zero selects 1420.
Interface CIDRs retain the host address. Omitted allowedIPs supplies both
default routes; an explicit empty list owns no addresses. Receive and transmit
use longest-prefix/last-exact-owner cryptokey routing. Only authenticated
handshake/data may roam endpoints. Configuration Debug and parse errors redact
secret keys.

Destination DNS runs through the authenticated tunnel, with UDP and TCP fallback
for TC. Only the outer peer endpoint uses system DNS. Empty remoteDNS supplies
Go's four default Cloudflare resolvers; literal destinations bypass DNS.

Inbound sessions retain peer email and level. The common User requires a UUID
but WireGuard authenticates public keys: a stable custom UUID derives from the
first 16 public-key bytes with version/variant bits set. This is a runtime
identity adapter, not authentication.

Bounds: 256 packet slots, 256 stack sockets, 64 outbound UDP flow tuples,
64 accepted TCP streams, 256 server datagrams, and 32 packets per native UDP
association. Incomplete TCP opens expire at 30 seconds and idle UDP at 120.
Socket leases, cancellation, explicit shutdown and retained worker handles
control lifecycle. Dropping a listener cancels its children and device.
TCP FIN/half-close preserves reads in the opposite direction.

## Independent gates and validation status

Authoritative read-only Go checkout: Xray-core commit
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. The helper under
testing/wireguard-reference was frozen before the Rust Noise/stack code.
The parent reported six successful helper-matrix jobs in run 45889388738;
that validates the helper, not this Rust implementation.

Required compile-time fixture:

    testing/wireguard-reference/generated/wireguard-key-vectors.json
    SHA256 711505b1551b672f0cbb84c7135ef1a12f33a21a618e67ee52b72050881ffed0

The always-run key test verifies its hash and both X25519 public keys against
Go outputs. Missing fixtures cause compilation failure. Ordinary tests also
cover config/IPC normalization, routing, PSK success/failure, tamper/replay,
unknown-peer/plaintext rejection, roaming, keepalive/retransmission timers,
encrypted TCP/UDP IPv4/IPv6 loopback, fragmentation, empty packets, native
per-destination dispatch/transparent targets, half-close, metadata, and shutdown.

Run only on the parent's remote Ubuntu runner:

~~~sh
cargo test --lib proxy::wireguard:: -- --nocapture
cargo test --lib testing::scenarios::wireguard_test:: -- --nocapture
test -n "$XRAY_WIREGUARD_REFERENCE"
cargo test --lib proxy::wireguard::device::tests::live_go_ -- --include-ignored --nocapture
~~~

Exactly eight live_go_ tests cover TCP/UDP, IPv4/IPv6, both Rust-to-Go and
Go-to-Rust. UDP includes 8192-byte fragmented packets; outbound UDP additionally
checks empty datagrams and original source metadata through connect_datagram.
They are explicitly ignored in ordinary runs and fail when explicitly selected
without XRAY_WIREGUARD_REFERENCE. Ignored results are never live interop passes.
CI must require the variable and verify all eight test matches.

No Rust/Cargo/Go commands, installations, builds or tests ran on the Android
editing host. Remote Rust compile/test results must be recorded by the parent;
this note describes implemented gates, not passing test results.

Linux run 45893541110 at commit 517a155 executed all eight live WireGuard
tests: three passed and five failed. Four Rust-to-Go cases failed before
traffic because helper diagnostics polluted readiness stdout; reverse
fragmented IPv6 UDP timed out. Ordinary Linux tests also timed out in
encrypted dual-stack UDP loopback and native multi-destination UDP. Source
inspection found that smoltcp's IP-medium IPv6 dispatch has no Fragment
header branch, despite the `proto-ipv6-fragmentation` feature name. The
WireGuard-local ingress adapter and helper stderr logger address those
causes. Added regressions cover reordered ingress/socket provisioning, UDP
checksum validation, overlap, expiry, atomic fragments and bounded buffers.
These fixes require the next remote Linux round; no local toolchain was run.

## Remaining scope limits

- Always userspace: no kernel TUN/backend, privileged interface, or kernel module.
  noKernelTun is not a Rust backend selector.
- No live peer add/remove, UAPI server, endpoint DNS refresh, or mutable device
  configuration.
- No application ICMP sockets, raw-IP forwarding API, multicast proxy API, or
  IPv6 jumbograms. Stack-internal ICMP is separate from application forwarding.
- Native UDP uses the common 65507-byte payload limit for both families.
  Inbound overload drops packets at bounded queues; flow maps are bounded.
- Worker counters do not replace Go's policy/statistics manager. Dispatcher
  integration passes metadata into parent-owned routing/policy/accounting.
- Long-duration rekey/expiry, packet loss/reordering, and concurrency soak tests
  are not claimed. BoringTun supplies those protocol timers; the adapter still
  requires the remote gates above to pass.
