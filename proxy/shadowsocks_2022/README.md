# Shadowsocks 2022 TCP scope

The runtime implements authenticated **single-user TCP** for
2022-blake3-aes-128-gcm and 2022-blake3-aes-256-gcm, using the adjacent
Go Xray-core sources at 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7 as the wire
reference (cipher.go, kdf.go, stream.go, and packet.go's address decoder).
This is a bounded implementation, not complete Shadowsocks 2022 parity.

Implemented behavior:

- Standard-base64 PSKs with Go's literal-key fallback and exact 16/32-byte key
  lengths; BLAKE3 derive-key context "shadowsocks 2022 session subkey", with
  PSK || salt as key material. No legacy Shadowsocks password KDF.
- Independent random client/server salts, AES-GCM fixed and variable handshake
  chunks, zero-based little-endian 96-bit nonces, and authenticated big-endian
  two-byte body lengths followed by authenticated payload chunks (1–65,535 bytes).
- Client/server header types, a 30-second timestamp window, server binding to the
  original client salt, request padding, incoming early data, and SOCKS address
  encoding for IPv4, IPv6 and domains.
- Lazy response authentication and lazy server headers, including an authenticated
  empty response on async shutdown. Outbound connect sends the request before
  returning; authentication of the peer completes on the first read.
- A shared, synchronized replay filter per inbound handler. It uses Go's two
  generations and 60-second rotation interval, inserts only after full request
  authentication, and fails closed at 65,536 salts per generation.
- Native async streams with bounded buffering, authenticated reads, short I/O,
  half-close, backpressure, and buffered writes. Accepted writes are owned by the
  stream; call flush or shutdown before dropping an output-only stream. Reads
  also drive pending output without blocking incoming data on write backpressure.

Runtime JSON uses protocol: "shadowsocks" and dispatches according to method.
Inbound settings use method, password, and optional network: "tcp". Outbound
settings accept a flat address/port/method/password object or exactly one
entry in servers. Method matching is case-insensitive. Legacy Shadowsocks
settings retain their existing handler dispatch. Invalid SS2022 keys and unsupported
SS2022 combinations fail during configuration building instead of falling through
to the legacy handler. An omitted network means this implementation's TCP path.

Explicit gaps and differences:

- No ChaCha20 SS2022, UDP, UDP-over-TCP, EIH/PSK chains, multi-user sessions,
  relays, multiplexing, or TLS/Reality/WebSocket/gRPC/XHTTP/finalmask
  transport configuration. The existing multi-user/relay collection types are
  metadata only; they are not functional network handlers.
- The server uses a fixed 10-second handshake timeout rather than Go's policy
  manager. Generic boxed streams do not expose the underlying TCP socket for
  Go's forced-RST-on-invalid-handshake behavior.
- Initial salt/fixed headers tolerate transport fragmentation using exact-length
  reads; the reference Go code requires a complete initial header in one read.
- Domain bytes must fit the Rust String representation (UTF-8); the Go packet
  decoder can retain arbitrary byte strings. TCP payload EOF has the protocol's
  normal record-boundary truncation limitations; there is no extra close record.
- The old public SessionHeader codec remains solely for source compatibility
  with previous metadata callers/tests. It is plaintext metadata, **not a SIP022
  wire codec**. Neither runtime handler uses it. Use stream::connect_tcp and
  stream::accept_tcp or the Client/Server handlers for network traffic.

The testdata/go-vectors.jsonl file contains independently generated Go known-answer
records for both methods, including deterministic salts/time, handshake chunks,
early/initial payloads, subsequent length/payload chunks, and KDF outputs in both
directions. Regeneration uses:

~~~sh
bash testing/ss2022-reference/generate.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY
~~~

Rust tests compare complete bytes and cover authentication, tampering, replay,
timestamp limits, padding, malformed/truncated records, fragmentation, cancellation,
simultaneous split-stream backpressure, loopback handlers, and runtime JSON dispatch.
Run them on the authorized remote Linux runner with:

~~~sh
cargo test --locked --lib ss2022_ -- --nocapture
~~~
