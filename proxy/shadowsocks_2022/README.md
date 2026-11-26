# Shadowsocks 2022 implementation status

The wire reference is adjacent Go Xray-core commit
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. The expanded implementation,
including native UDP/configuration source 98f42c8, passed Linux Rust CI
45897222837: **1,151 library/nine binary tests**, locked checking,
debug/release builds and 15 CLI comparisons. All eight new native and five
configuration cases executed. Workflow 45897222798 passed strict Clippy and
the existing 15 REALITY/WireGuard/Hysteria/mKCP live cases. No live SS2022
Go/Rust gate has run; full SS2022 parity remains open.

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

Inbound JSON uses method/password, optional network as a string or string array,
and optional users or clients. Omitted/null JSON selects TCP; [] reaches the
native constructor default of TCP+UDP. Case, order and duplicates do not change
selection; whitespace is not trimmed, following Go Network.Build. Unknown/Unix
values are explicitly unsupported in this Rust runtime. Each user has password, email and level; relay entries also have
address and port. As in Go, clients overrides users, including an empty clients
array, and the first selected user's address chooses relay mode. User method
must be empty. ChaCha rejects PSK chains, multi-user and relay mode.

Outbound JSON accepts a flat address/port/method/password object or exactly one
entry in servers. Method matching is case-insensitive. Existing root helper
signatures and legacy Shadowsocks dispatch are unchanged. Single-user inbound
email and level now survive into session metadata.

## UDP codec and association

Source 98f42c8 connects the existing codecs to the shared runtime. All eight
new native and five new config tests passed ordinary Linux CI 45897222837:

- Server::decode_datagram / reply_datagram and the equivalent MultiUserServer
  methods authenticate whole packets, preserve destinations and return an
  opaque ReplyToken. Tokens bind to one handler and one live session instance;
  replayed packets cannot rebind a response to a different remote address.
- RelayServer::relay_datagram strips one UDP EIH, re-encrypts the session/packet
  header for the next hop and returns encrypted bytes plus a session ID and
  destination. Responses must pass through unchanged. The shared listener must
  cache and close the per-client relay route; the stateless codec is not that
  listener.
- OutboundHandler::connect_datagram returns a real BoxDatagram adapter around
  UdpAssociation. It selects UDP from the session destination even when server
  endpoint metadata says TCP, preserving one whole packet per send/recv. Replies
  retain the remote source and original local destination. Packet source takes
  precedence over the session-source/local-socket fallback; mixed original
  sources in one association are explicitly rejected.
- Server and AES MultiUserServer implement bind_native: TCP-only returns None
  for the shared TCP path, UDP-only binds one datagram socket, and TCP+UDP binds
  both to the same port with rollback. Clones share replay/account/session state.
  Handler close, listener/task drop and cancelled I/O release owned sockets and
  wake packet operations, including retained transports and unpolled TCP tasks.
- AES uses a separately encrypted 16-byte session/packet header and a session
  body key. UDP EIH uses raw AES keys and XOR with that header, unlike TCP EIH.
  ChaCha uses a 24-byte nonce and XChaCha20-Poly1305 over header and body.
- Session replay windows use Go's 128-block ring and 8,128-packet lookback.
  Client state retains current/old server sessions and the 60-second rotation
  rules. Authenticated server state expires after 500 idle seconds, is bounded
  to 65,536 entries, and reserves packet IDs before emitting ciphertext.
  Authentication and metadata checks precede replay/session mutation.

## Remaining runtime work and explicit differences

- Native UDP and its configuration passed ordinary Linux CI at 98f42c8;
  the same-revision existing live/Clippy gates passed. Native relay UDP still
  needs a cached passthrough route and close lifecycle; selections containing UDP are rejected during configuration.
- Native flow limits are fixed: 256 flows, 32 queued packets per flow, 64
  authenticated remote addresses per flow and a 500-second idle limit. These
  bounds and one original source per outbound association are not policy parity.
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
the fixture hash mandatory before decoding; that check passed at cf9510e
and d977720.
The original two-argument ss2022-reference/generate.sh interface is unchanged.

To repeat the SS2022 suite on the remote Linux runner:

~~~sh
cargo test --locked --lib ss2022_ -- --nocapture
~~~

The additional tests cover ChaCha TCP half-close, relay-to-multi-user TCP,
configuration dispatch, typed users/clients, UDP authentication/truncation,
EIH routing, replay, packet-ID exhaustion, server-session rotation, reply-token
lifetime, account indices and native UDP association loopback. The extension
adds eight native tests and five configuration tests covering real traits,
empty/large packets, source metadata, network selection/rollback, replay and
authenticated migration, queue isolation, account updates and socket release.
One native test feeds frozen Go packets through production handler decoders at
the recorded fixture time; this is independent-byte evidence, not a live peer.
All 13 new tests executed and passed in Rust CI 45897222837 at 98f42c8.
No Go or Rust build, test, toolchain install or compilation was run locally
for this lane.
