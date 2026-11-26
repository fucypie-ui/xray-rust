# Independent pinned Go REALITY oracle

Run on a disposable **Linux** runner checkout of Xray-core at
67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. The adjacent authoritative checkout is
read-only during development. These scripts use a temporary package directory in
the disposable Go module so the pinned go.mod/go.sum govern resolution; they
remove only their temporary main.go and directory. They do not modify Go sources.

## Frozen vectors

    testing/reality-reference/generate.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY

This compiles main.go against pinned uTLS, builds a real Chrome hybrid ClientHello,
and derives authentication bytes using Go crypto/ecdh, HKDF, AES-GCM, HMAC-SHA512
and x509. Output vectors.json includes the full input record, zeroed AAD, metadata,
ECDH public keys/shared secret, AuthKey, session ID and bound Ed25519 certificate.
The deterministic input stream does not guarantee stable uTLS randomized extension
ordering across independent runs. Preserve and review the actual frozen vector;
do not regenerate expected data from the Rust implementation.

The checked-in mandatory fixture is
transport/internet/reality/fixtures/go-vectors.json, SHA256
4643f0ca070c22783dc22dfebc20a8d353fcbc2579895ed02cd7195c2e5687b5.
Rust include_str! requires it at compile time and the test checks that exact hash.
Any replacement requires intentional provenance review and a hash update.

The fixture generator is frozen separately from the live peer. The peer helper
is not consulted when creating the frozen vector, and vectors alone do not prove
live TLS interoperability.

## Bidirectional live Go handshakes

    testing/reality-reference/build-peer.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY
    XRAY_GO_REALITY_PEER_BIN=/absolute/OUTPUT_DIRECTORY/go-reality-peer \
      cargo test --lib transport::internet::reality::go_peer_test -- --ignored --nocapture

build-peer.sh compiles peer.go alone. It calls the pinned Xray-core REALITY UClient
and the pinned XTLS/REALITY Server directly; it does not copy or reimplement those
handshakes in Rust or Go. Its local TLS cover server has an ordinary P-256 ECDSA
certificate and supports X25519 or X25519MLKEM768 target selection. The client
asserts UConn.Verified, then exchanges exact application bytes. The negative gate
uses a wrong short ID and requires rejection without an authenticated Rust stream.
Socket splitting exercises fragmented TLS across engine boundaries and forwards
the CloseWrite half-close interface required by the pinned REALITY server. The
cover certificate uses a scheme actually advertised by the pinned Chrome profile;
the authenticated REALITY certificate remains Ed25519. Positive Go-client failures
report the exit status, stdout and stderr rather than hiding the peer's error.
The direct Go Server call starts its required DetectPostHandshakeRecordsLens
probes. For that direction, the cover accepts seven concurrent connections:
six probes (two per ALPN profile for one SNI) and the real handshake. The reverse
and negative directions retain the single-connection cover.

The Go binary is test-only, launched exclusively by cfg(test) Rust code. Runtime
REALITY transport never starts this binary or any other subprocess. These gates
require an explicitly set executable path; they fail when invoked without it.
Record the source commit, Go version and complete test results with any remote
validation artifact. No Go or Rust commands should be run on the Android host.
