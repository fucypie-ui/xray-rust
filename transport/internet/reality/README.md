# REALITY runtime transport

This module implements authenticated REALITY TLS 1.3 client and server connections.
VLESS outbound calls RealityClient::connect before returning a transport stream.
The server returns Some(stream) only after authenticated TLS completes; rejected
connections are forwarded to the configured target and return None.

## Authority and engine choice

Protocol authority is the read-only adjacent Xray-core checkout at
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7, especially
transport/internet/reality/reality.go and config.go. Its go.mod pins
XTLS/REALITY v0.0.0-20261108101329-4bb46b2afd8b.

Existing engines were investigated before implementation:

- The crates.io reality package does not supply the required runtime engine.
- [Shoes](https://github.com/cfal/shoes/tree/5941f7d9610674ae6750a020521dc8bf8aba15c8/src/reality)
  supplies maintained REALITY client/server logic and interoperability tests.
  Its connection-local rustls adapter, target-flight checks, certificate binding,
  and hybrid key-exchange structure are the basis of this adaptation.
- The selected [cfal/rustls fork](https://github.com/cfal/rustls/tree/f1a23c187330386e9e7f14a21dbae368034dc430)
  is pinned at f1a23c187330386e9e7f14a21dbae368034dc430, version 0.23.46,
  licensed Apache-2.0 OR ISC OR MIT. Connection-scoped new_reality hooks modify
  the real TLS handshake; this module does not substitute ordinary TLS.

The Cargo dependency coordinator owns the global patch and lockfile. This module
requires the pinned rustls fork with ring/std, ring 0.17.14, ml-kem 0.3.4 with
zeroize, x509-parser 0.18.1 without default features, and rcgen 0.14.10. It reuses
existing x25519-dalek, webpki-roots, h2, http, tokio and other project dependencies.
There is no additional TLS provider and no production Go subprocess.

Files hooks.rs, kx.rs, hello.rs, certificate.rs and the server staging logic in
reality.rs adapt Shoes concepts and code to this project's interfaces, ring
provider and RustCrypto ML-KEM implementation. Shoes copyright is
Copyright (c) 2021-2023 Alex Lau <github@alau.ca>. The complete required notice is
in LICENSE-SHOES-MIT. The rustls fork remains a separate Cargo dependency under
its upstream license; no vendored fork source is included here.

## Authentication and forwarding

- ClientHello is built by rustls, with a 32-byte session ID. Client hooks bind
  X25519 authentication to the actual TLS key share, including its hybrid
  component. The pinned Go server requires X25519MLKEM768 before optional X25519.
- AuthKey is HKDF-SHA256(ECDH, random[0..20], "REALITY", 32). AES-256-GCM uses
  random[20..32] as nonce and the entire handshake-framed ClientHello with zeroed
  session bytes as AAD. The plaintext is version[3], reserved[1], Unix seconds
  big endian[4], and an exact zero-padded short ID[8].
- Server policy checks exact SNI, complete short ID, inclusive client-version
  bounds and an absolute millisecond time window. A zero time limit disables
  timestamp restriction, matching Go. Empty short-ID lists deny authentication;
  an explicitly configured empty string allows only the all-zero short ID.
- A client accepts a REALITY leaf only after HMAC-SHA512(AuthKey, Ed25519 key)
  authenticates its certificate signature field. The actual TLS
  CertificateVerify must independently prove possession of that key using
  Ed25519. All-zero/low-order X25519 secrets and malformed DER are rejected.
- An unrelated target certificate must pass normal WebPKI DNS/chain/time checks.
  It never authenticates a VLESS stream. Instead, a bounded same-origin cover GET
  reuses that verified TLS connection over negotiated h2 or HTTP/1.1, and the
  caller receives an authentication error. This is a bounded spider fallback,
  not Go's full randomized crawl and shared path cache.
- The server opens the target before authentication and mirrors the complete
  received ClientHello wire, retaining TLS record fragmentation. After successful
  auth it admits the target flight, generates a fresh server key exchange and
  AuthKey-bound certificate, and stages the complete synthetic flight before
  writing anything synthetic. Unsupported target shapes fall back to the
  original target bytes. Rejected auth forwards bytes without a proxy stream.

The supported target flight shapes are ServerHello, compatibility CCS and either
one combined encrypted handshake record or four separate encrypted handshake
records, optionally followed by one target-sized padding record. HRR, PSK/0-RTT,
other key-exchange groups and unsupported layouts are forwarded. Initial target
flight admission is capped at 128 KiB and five seconds; socket/TLS buffers are
bounded and fragmented reads and writes are supported.

## Verification and current limits

The mandatory Go fixture is fixtures/go-vectors.json, SHA256
4643f0ca070c22783dc22dfebc20a8d353fcbc2579895ed02cd7195c2e5687b5.
It is included at Rust test compile time and hash-checked, with no missing-file
skip. It was generated independently with the pinned Go module, not from Rust
outputs. Tests cover raw ClientHello parsing, ECDH/HKDF/AEAD/certificate bytes,
bit tampering, exact ID/version/time policy, malformed/truncated key shares,
hybrid exchange, forged CertificateVerify, live fragmented Rust client/server
traffic, forwarding, large records and TLS truncation detection.

Run ordinary gates on the remote Linux validation lane:

    cargo test --lib transport::internet::reality -- --nocapture

The separate live Go gates invoke the real pinned Xray UClient and XTLS REALITY
server in both directions with classical and hybrid TLS target selection. They
are explicit ignored tests because they require an independently built oracle;
when invoked, a missing oracle is a failure. They do not replace the mandatory
fixture gate. See testing/reality-reference/README.md for the build and test
commands. No local toolchain install, build or test is needed on Android.

Remaining scope limits are ML-DSA-65 extra certificate authentication,
byte-for-byte browser ClientHello fingerprint impersonation, Go's full randomized
spider scheduling, PROXY-protocol target headers, Unix-domain target addresses
and target fallback rate limits. The current config type exposes none of the
ML-DSA fields. The selected implementation authenticates X25519/ML-KEM TLS and
Ed25519 exactly as above; it does not claim those optional features.

Remote compilation and live interoperability must be checked in the integration
lane; source-level implementation alone is not evidence that those gates passed.
