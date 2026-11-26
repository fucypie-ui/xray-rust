# VMess AEAD lane

The behavioral reference is Xray-core commit
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. The local read-only checkout is
../Xray-core (the originally requested ../Xray-core67756b3 path does not exist).

## Engine research and choice

Before implementation, the existing local codec and complete Go encoding,
aead and common/crypto implementations were inspected. The old local codec
was unsuitable: clear UUID, unchecked checksum, HKDF substituted for nested
HMAC, XOR substituted for AES AuthID, LCG substituted for SHAKE, and raw
unprotected body streams.

Primary Rust engines inspected on 2026-11-27:

* https://github.com/cfal/shoes/tree/master/src/vmess and its Cargo.toml:
  MIT; genuine inbound/outbound AEAD and UDP support. Rejected as a wholesale
  engine dependency because it is a full proxy application (publish=false),
  couples protocol code to its resolver, stream reader, handler, selector,
  AWS-LC and multiplex layers, and brings unrelated forked dependencies.
* https://github.com/eycorsican/leaf/tree/master/leaf/src/proxy/vmess:
  Apache-2.0 (repository LICENSE); genuine AEAD KDF, SHAKE and stream codec,
  but this protocol directory is
  outbound-only and its crypto abstraction is coupled to Leaf. It cannot
  supply the required inbound validation and replay state without substantial
  adaptation. It was used to cross-check the protocol construction.

Chosen approach: replace the existing local engine in place using the pinned
Go algorithms and existing RustCrypto AES-GCM/ChaCha/MD5/SHA256 primitives.
Reuse RustCrypto SHAKE128 from the small shake crate (0.1.0, current stable
verified through crates.io and https://github.com/RustCrypto/XOFs). No source
code was copied from shoes or Leaf. No third-party engine license obligations
are introduced by the research. RustCrypto shake is MIT OR Apache-2.0,
compatible with this repository. Go remains an external reference, not vendored
source. The fixture adapter is original code calling Go's exported functions
and session methods within a disposable package-local test.

## Implemented interfaces

* Request headers use command-key MD5, AES AuthID with IEEE CRC32, a 120-second
  timestamp window, shared two-generation AuthID replay filtering, and shared
  180-second UUID/body-key/IV session replay filtering. Empty user sets deny all.
* Nested VMess HMAC KDF (not HKDF), header length/payload AES-GCM with AuthID AAD,
  connection nonce, request FNV-1a, domain/IP parsing and header padding.
* AEAD response length/payload, response-byte validation, SHA256 response key/IV.
* AES-128-GCM and ChaCha20-Poly1305 body security, plain/masked/authenticated
  lengths, SHAKE128 masking, global padding, request/response nonce counters,
  Go's request-derived response authenticated-length key/IV, and authenticated
  terminal writes. As in Go, readers recognize the terminal length before
  consuming its tag/padding (it carries no application bytes). Unsupported
  plaintext/legacy/none/zero security fails closed,
  matching the pinned body codec's supported cipher set.
* Poll-based AsyncRead/AsyncWrite runtime streams (no detached codec tasks),
  backpressure, fragmented transport reads/writes, partial application reads,
  half-close/NoTerminationSignal, bounded frames, and TCP/TLS outbound handlers.
* UDP command framing: each AsyncWrite is one packet and each AsyncRead returns
  at most one frame (small read buffers retain the remainder). The typed
  VmessStream::send_packet/recv_packet methods preserve full packet boundaries;
  BoxStream itself has no packet metadata or datagram interface. Both
  DatagramTransport::send and VmessStream::send_packet explicitly reject empty
  UDP packets with Unsupported: an empty VMess body frame signals EOF. Go's
  packet writer silently drops empty packets; this API reports that limitation.
  Mux payloads use the shared multiplex codec, which preserves empty UDP Data
  frames. The pinned Go buffer size is 8192 bytes; stream payload
  limits reserve the length field, authentication tag, and maximum padding.
  Oversized UDP writes return errors rather than being split into packets. This
  is an explicit API difference: Go's packet writer silently drops packets that
  do not fit its buffer. The Rust error leaves the stream writer failed.

Native Mux command header encoding/decoding is implemented. Parent-owned global
Mux.Cool/XUDP dispatch must use Server::accept_session and Client::open_session;
the generic InboundHandler rejects Mux rather than returning an unimplemented
session as successful. The generic outbound trait selects ordinary UDP command
2 because it cannot express Mux/XUDP packet metadata. Configuration wiring for
security, options and NoTerminationSignal belongs to the parent; builder methods
are provided. Anti-probing randomized drain timing from Go's global drain/policy
infrastructure is not reproduced by this scoped codec. These are integration
gaps; do not claim whole-application 100% parity until the parent closes them.

## Validation

No Rust/Cargo/Go installation, compilation or execution was performed locally.
The parent must run Linux GitHub Actions. Run the independent reference helper:

    bash testing/vmess-reference/generate.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY

Install vmess-vectors.json as proxy/vmess/testdata/go-vectors.json. The Rust
fixture tests require that file and report a clear failure if it is absent;
they do not silently skip independent validation. The generator is deterministic
and covers both ciphers, TCP/UDP, all six meaningful masking/padding/length option
combinations, KDF/AuthID/header/response bytes and SHAKE output. Rust tests also
cover corrupted authentication, wrong keys, replay, timestamp boundaries,
header/body truncation, incremental I/O, bidirectional loopback and UDP packets.
