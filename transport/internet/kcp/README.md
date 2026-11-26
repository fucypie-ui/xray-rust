# Rust mKCP runtime

This directory implements Xray mKCP, using the wire and worker behavior of
XTLS/Xray-core commit `67756b3674d56b72c7a7e675e8dcd3f883e1b2f7`. The runtime owns UDP input,
timed retransmission, acknowledgments, flow and congestion windows, close
handshakes, and a native Tokio byte stream.

## Engine selection and provenance

Existing Rust engines were reviewed before implementation. Matrix-Zhang/kcp
(commit 8c0603ad352d6a5c6f61a4b606a4dc4e702d9e10) and tokio_kcp 0.10.0 use
ordinary KCP: 24-byte little-endian headers and 32-bit conversations. Those
engines cannot emit Go mKCP bytes unchanged. Go mKCP uses big-endian fields,
16-bit conversations, and DATA/ACK/CMD headers of 18/17/16 bytes.

The private clock-free engine and wire parser were adapted from
[aimalygin/xray-rust](https://github.com/aimalygin/xray-rust/tree/bedc00345ab47eb36abbc78d51d168ccf216f504/crates/xray-transport/src/kcp),
pinned to commit `bedc00345ab47eb36abbc78d51d168ccf216f504`.
The adapted files are engine.rs, engine/tests.rs, wire.rs, and wire/tests.rs.
Their MPL-2.0 headers, scoped LICENSE-MPL-2.0, and NOTICE are retained here.
No root license or Cargo manifest changes are required.

Local modifications relocate the modules, expose connection state/statistics,
restore Go's repeated ACK entries instead of upstream Rust's coalescing,
and adapt tests and imports. The original Tokio runtime, constructors,
listener, stream adapter, and integration tests are separate from those
adapted files. References used for comparison:

- [Authoritative Go implementation](https://github.com/XTLS/Xray-core/tree/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/kcp).
- [Ordinary Rust KCP](https://github.com/Matrix-Zhang/kcp/blob/8c0603ad352d6a5c6f61a4b606a4dc4e702d9e10/src/kcp.rs).
- [Tokio KCP wrapper](https://github.com/Matrix-Zhang/tokio_kcp).

## Runtime API

- `KcpDialer::dial_with_config(addr, conv, config, cancellation).await`
  returns a live KcpConnection. IPv4 and IPv6 bind families are supported.
- `ConfiguredKcpDialer::new(config, cancellation)?` implements the existing
  global Dialer trait, resolving Destination through the core DNS helper and
  returning BoxStream. UDP has no handshake, so successful construction does
  not prove remote reachability or choose among reachable address families.
- `KcpListener::bind_with_config(addr, config, cancellation).await` starts
  one receiver and demultiplexes by (remote SocketAddr, conversation u16).
  `accept_stream()` and `accept_box_stream()` return (stream, peer).
- `KcpConnection::from_socket_with_config(conv, Arc<UdpSocket>, peer, config,
  cancellation)` and `KcpListener::from_socket_with_config(socket, config,
  cancellation)` attach sockets configured by the core system layer.
  A listener socket must be unconnected. The driver must be the only receiver
  on supplied sockets; caller-held socket clones retain their OS lifetime.
- `connection.into_stream()` returns KcpStream (AsyncRead + AsyncWrite);
  `into_box_stream()` returns the existing Send + Sync BoxStream.
- Writes queue up to Go's sending-buffer limit (including Go's one-segment
  allowance past the computed size). Flush waits for acknowledgments.
  Shutdown drains accepted output, then begins the Go close handshake.
  Reads yield ordered bytes, block without data, and return zero on EOF.
- `connection.cancel().await` cancels and joins its driver;
  `listener.close().await` cancels and joins input and all owned sessions.
  Cancellation wakes blocked I/O. Dropping the last application handle
  requests graceful close; the session map holds no application lease.
  Closed handles retain addresses/statistics but do not retain sockets.

KcpListenerOptions bounds active sessions, pending accepts, and per-session
input packets (defaults 4096/1024/1024). Overflow drops packets for ARQ
recovery and never stalls other sessions. Public connection clones should
have at most one outstanding read, write, flush, and close waiter each per
session; concurrent byte-stream operations can interleave application data.

## Configuration and packet transforms

KcpConfig accepts snake_case and Go camelCase names. Defaults are MTU 1350,
TTI 50 ms, uplink/downlink 5/20 MiB/s, cwndMultiplier 1, and maxSendingWindow
2 MiB. Validation rejects invalid MTU/TTI, empty sending windows, zero
multipliers, and capacity arithmetic overflow before spawning tasks.

At the pinned Go commit, legacy congestion/readBufferSize/writeBufferSize,
seed, and header settings do not select engine behavior. In particular, seed
does not enable packet encryption. Default packets are raw mKCP segments.

DatagramCodec wraps one whole outgoing datagram and unwraps one incoming
datagram. The with_codec/options constructors accept Arc<dyn DatagramCodec>
for external finalmask composition. PlainPacketCodec is identity;
LegacyPacketCodec::original() and ::with_seed(password) reuse the existing
Original checksum/XOR and AES-128-GCM finalmask implementations. Authentication
failures are discarded before session allocation/activity updates. MTU counts
the raw mKCP segment; mask overhead is additional, as in Go.

## Independent fixtures and tests

The frozen helper is `testing/kcp-reference/generate.sh GO_REFERENCE_ROOT
OUTPUT_DIRECTORY`. It copies Go privately, injects the package-local oracle,
and writes `OUTPUT_DIRECTORY/kcp-reference.json`. It never modifies the
reference source. The independently generated fixture is required by
`transport::internet::kcp::runtime_test::go_reference_byte_and_session_vectors`.
Its default path is `CARGO_MANIFEST_DIR/testing/kcp-reference/generated`;
XRAY_KCP_REFERENCE_DIR overrides the directory in remote CI. Missing or
invalid fixtures fail the test; there is no skip path.

The Go oracle compares DATA/ACK/CMD bytes, compound/truncated datagram parsing,
a deterministic loss/reordering session trace, received stream bytes, and RTT
updates. Engine tests cover ordered delivery, send/receive windows, ACK batch
limits/repetition, fast retransmit, loss adaptation, RTO, pings, idle timeout,
and close state deadlines. Runtime tests additionally cover fragmentation,
BoxStream duplex loopback, a real UDP loss/reorder/duplication relay, timer-only
retransmission, two peers reusing one conversation, cancellation, EOF, listener
limits, explicit encrypted masks, socket release, and the global Dialer trait.

## Verification and integration boundary

No local Rust/Cargo/Go build or tests were run on Android. The parent reports
that the remote Go helper passed (run 45889388738), and the installed fixture
SHA-256 is 6d20d46fc9494333b3e003b80b3a73dfb87005d6674885badd269e675e90f63b.
Rust compilation and execution remain a required parent Ubuntu CI gate.
Existing Tokio/full, tokio-util CancellationToken, async-trait, rand, serde,
serde_json, and hex APIs are reused; this change adds no dependencies.

Global configuration/transport registration, generic proxyman native-inbound
adapters, system socket options, and finalmask-chain construction are owned
outside this directory. KCP is a stream transport: adapters must dispatch an
accepted BoxStream through the generic protocol path with its peer address,
without protocol-specific configuration casts. No local evidence yet proves
a live Go-to-Rust UDP exchange; the independent Go trace and live Rust network
tests are separate gates. Duplicate ACK storage intentionally follows Go and
can grow until the sender advances SendingNext. There is no shared UDP port
rebinding or authenticated peer migration feature.
