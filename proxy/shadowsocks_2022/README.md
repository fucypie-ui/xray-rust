# Shadowsocks 2022 implementation status

The wire reference is adjacent Go Xray-core commit
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. The original AES single-user TCP
checkpoint has independent Go fixtures. The expanded implementation below is
**built in debug/release and passed its SS2022 tests in Linux run 45893541120
at 517a155**. The full library suite failed elsewhere (1,120 passed / 8 failed),
and no live SS2022 Go/Rust gate ran. This is not complete Shadowsocks 2022 parity.

## TCP runtime

The existing protocol: "shadowsocks" configuration dispatches to SS2022 handlers
for all three methods:

- 2022-blake3-aes-128-gcm
- 2022-blake3-aes-256-gcm
- 2022-blake3-chacha20-poly1305

The official MIT-licensed shadowsocks-crypto 0.8.0 engine supplies TCP KDF/AEAD
and UDP body AEAD. The port retains Go-specific framing, EIH, validation and
runtime routing. The manifest declares the engine and c92390f imports its
Linux-resolved lock from parity-preparation run 45893018658:

~~~toml
shadowsocks-crypto = { version = "0.8.0", default-features = false, features = ["v2"] }
~~~

The lane uses aes-gcm 0.11.1 block-cipher traits and arrays, and rand 0.10.4
SysRng/TryRng and RngExt APIs. It has no rcgen use.

Implemented TCP paths:

- Single-user inbound and outbound for all three methods. Standard-base64 PSKs
  retain Go's exact-length checks and literal-key fallback. Independent salts,
  authenticated fixed/variable headers, length/payload records, timestamps,
  request-salt binding, early data and replay filtering remain in the adapter.
- AES outbound colon-separated PSK chains. Earlier keys encrypt EIH blocks;
  the final key encrypts the stream. TCP identity keys use the salt-derived
  "shadowsocks 2022 identity subkey" context and BLAKE3 user-key hashes.
- AES multi-user inbound through MultiUserServer. Fully authenticated requests
  carry the selected email and level. Account add/remove, email lookup, listing
  and count preserve Go's separate email/hash indices and last-key selection.
- AES relay inbound through RelayServer. It selects the next hop by EIH, removes
  one EIH and forwards the original encrypted stream, including the salt. A
  bounded initial prefix includes a possible next-hop multi-user fixed header;
  the copy loop does not emit the salt alone as its first batch. A relay cannot
  authenticate the final body's AEAD; that is the destination server's job.
- Native poll-based encrypted streams retain bounded per-direction buffering,
  short I/O, half-close, cancellation-safe plaintext acceptance, read-driven
  output progress and independent split-task wakeups. Flush or shut down an
  output-only stream before dropping it.

Inbound JSON uses method/password, optional network: "tcp", and optional users
or clients. Each user has password, email and level; relay entries also have
address and port. As in Go, clients overrides users, including an empty clients
array, and the first selected user's address chooses relay mode. User method
must be empty. ChaCha rejects PSK chains, multi-user and relay mode.

Outbound JSON accepts a flat address/port/method/password object or exactly one
entry in servers. Method matching is case-insensitive. Existing root helper
signatures and legacy Shadowsocks dispatch are unchanged. Single-user inbound
email and level now survive into session metadata.

## UDP codec and association

Concrete UDP APIs exist, but **configuration still rejects native UDP until the
new shared native listener/dispatcher contract is connected and tested**:

- Server::decode_datagram / reply_datagram and the equivalent MultiUserServer
  methods authenticate whole packets, preserve destinations and return an
  opaque ReplyToken. Tokens bind to one handler and one live session instance;
  replayed packets cannot rebind a response to a different remote address.
- RelayServer::relay_datagram strips one UDP EIH, re-encrypts the session/packet
  header for the next hop and returns encrypted bytes plus a session ID and
  destination. Responses must pass through unchanged. The shared listener must
  cache and close the per-client relay route; the stateless codec is not that
  listener.
- Client::connect_datagram currently exposes a concrete UdpAssociation with
  packet-preserving send/receive, system DNS integration and no bridge tasks.
  It has not yet overridden OutboundHandler::connect_datagram. The next chunk
  must adapt this to common::net::datagram::DatagramTransport / BoxDatagram,
  including close/cancellation semantics, then wire inbound bind_native and
  packet dispatch. Never flatten packet boundaries into BoxStream reads.
- AES uses a separately encrypted 16-byte session/packet header and a session
  body key. UDP EIH uses raw AES keys and XOR with that header, unlike TCP EIH.
  ChaCha uses a 24-byte nonce and XChaCha20-Poly1305 over header and body.
- Session replay windows use Go's 128-block ring and 8,128-packet lookback.
  Client state retains current/old server sessions and the 60-second rotation
  rules. Authenticated server state expires after 500 idle seconds, is bounded
  to 65,536 entries, and reserves packet IDs before emitting ciphertext.
  Authentication and metadata checks precede replay/session mutation.

## Remaining runtime work and explicit differences

- Native UDP bind/dispatch and the BoxDatagram outbound adapter are pending.
  Omitted/null JSON network means TCP in pinned Go via NetworkList.Build(nil).
  An empty native network list instead defaults to TCP+UDP in the Go SS2022
  constructors; both entry paths need their own acceptance tests.
- UDP-over-TCP and mux are not SS2022 cipher codecs in the pinned Go package.
  Its outbound JSON has no consumed uot setting. Generic mux, packet adaptation
  and stream wrappers belong to the shared runtime and need integration tests.
  TLS/Reality/WebSocket/gRPC/XHTTP/finalmask and enabled mux/uot settings remain
  rejected here until those paths are actually wired.
- The server uses a fixed 10-second handshake timeout instead of Go policies.
  BoxStream cannot perform Go's forced TCP reset for invalid handshakes.
- Exact-length Rust reads tolerate fragmented initial headers; Go requires a
  complete initial header in one read. Relay prefix batching reduces accidental
  splitting but cannot control packet segmentation in the network.
- Domain bytes must be UTF-8 in the Rust String address model. Go can retain
  arbitrary byte strings. Packet output is bounded to 8,192 bytes and rejects
  oversize input rather than reproducing Go buffer-write truncation behavior.
- The old public SessionHeader remains plaintext compatibility metadata only.
  Runtime TCP/UDP handlers do not use it as their wire codec.

## Independent reference evidence and verification

Frozen testdata/go-vectors.jsonl remains unchanged and authoritative for the two
original AES methods. Its SHA-256 is
 af1b7f607dba629ba63ac306fc8594a1e8b751d0185050053aa7d648e29c7aeb.
The original 17-test checkpoint and its generator/helper are preserved.

The separate extended helper exercises production Go TCP/EIH/UDP writers for all
three ciphers. It normalizes random salts/nonces and wall time to deterministic
values using Go's own cipher operations. Run only on the authorized Linux runner:

~~~sh
bash testing/ss2022-reference/generate-extended.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY
~~~

Three independent records are frozen verbatim in
testdata/go-extended-vectors.jsonl with go-extended-provenance.json. SHA-256:
349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0.
They came from successful SS2022 job 140158378278 in run 45892518463
(generator 584cd13, pinned Go source above, Go 1.27.4 linux/amd64).
The byte comparisons passed at 517a155. Commit e811ca8 additionally makes
the fixture hash mandatory before decoding; that change awaits the next run.
The original two-argument ss2022-reference/generate.sh interface is unchanged.

To repeat the SS2022 suite on the remote Linux runner:

~~~sh
cargo test --locked --lib ss2022_ -- --nocapture
~~~

The additional tests cover ChaCha TCP half-close, relay-to-multi-user TCP,
configuration dispatch, typed users/clients, UDP authentication/truncation,
EIH routing, replay, packet-ID exhaustion, server-session rotation, reply-token
lifetime, account indices and native UDP association loopback. No Go or Rust
build, test, toolchain install or compilation was run locally for this lane.
