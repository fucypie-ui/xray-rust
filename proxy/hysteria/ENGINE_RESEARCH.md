# Hysteria QUIC engine and compatibility

Reference: Xray-core 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7.
This lane owns only proxy/hysteria, transport/internet/hysteria, and
testing/hysteria-reference. Shared traits, configuration builders, dependency
manifests/lockfiles, and CI workflows belong to the parent lanes.

## Engine choice and licenses

Use upstream Quinn 0.11.12, quinn-proto 0.11.19, h3 0.0.8, and h3-quinn 0.0.10
with the repository's globally selected rustls provider. Quinn implements actual
QUIC v1, TLS 1.3, recovery, stream multiplexing and DATAGRAMs; h3 implements
HTTP/3/QPACK. The scoped adapter diverts Hysteria 0x401 streams before HTTP/3
frame parsing, while retaining and driving H3 control streams for the connection
lifetime. It does not implement QUIC cryptography or recovery itself.

Research performed before selecting this integration:

* trustrusty/rsteria2 0.1.1, revision
  9d5f582ac0ba6eb7f8e7aa417b4221d22596c3e2 (MIT), provides client-side Hysteria,
  fragmentation, Brutal and obfuscation helpers. It does not supply the required
  server path. Its auth lifetime pattern cannot be copied unchanged with official
  h3 0.0.8: dropping the last SendRequest closes the QUIC connection.
* crapthings/hysteria-rust, revision
  96a5e251da4b3589ad20af8be2cad5a4bc9c5c50 (MIT), supplies both sides, but is an
  unpublished workspace coupled to patched h3/quinn-proto/rustls. A direct
  dependency would require global patches conflicting with the parent lane.
* Quinn and h3 are MIT OR Apache-2.0. They are dependencies, not vendored code.
  No implementation from either candidate Hysteria engine is copied into this
  lane. Wire formats and behavior are ported from the pinned authoritative Go
  source; preserve the repository's existing source-license obligations.

Upstream API sources inspected:

* https://github.com/quinn-rs/quinn/tree/quinn-0.11.12
* https://github.com/quinn-rs/quinn/tree/quinn-proto-0.11.19
* https://github.com/hyperium/h3/tree/h3-v0.0.8
* https://github.com/hyperium/h3/tree/h3-quinn-v0.0.10
* https://github.com/apernet/quic-go/tree/2895f039137a
* https://github.com/trustrusty/rsteria2/tree/9d5f582ac0ba6eb7f8e7aa417b4221d22596c3e2
* https://github.com/crapthings/hysteria-rust/tree/96a5e251da4b3589ad20af8be2cad5a4bc9c5c50

Exact additions requested from the manifest lane (do not edit manifests here):

- quinn = "=0.11.12", default-features = false,
  features = ["runtime-tokio", "rustls-ring"]
- quinn-proto = "=0.11.19", default-features = false (unified with Quinn)
- h3 = "=0.0.8", features =
  ["i-implement-a-third-party-backend-and-opt-into-breaking-changes"]
- h3-quinn = "=0.0.10"

All other imports use existing workspace dependencies. The parent selects one
rustls revision globally; this lane neither adds another rustls nor changes the
provider selection.

## Implemented runtime paths

Client: TLS-verified UDP/QUIC -> HTTP/3 POST https://hysteria/auth -> status 233 ->
multiplexed TCP requests/responses and typed UDP associations. The connection is
reused until closed; a later request reconnects after connection failure. Endpoint,
H3 driver and SendRequest ownership survive for active client streams/sessions.
Default TLS uses WebPKI roots. with_tls accepts the global caller's TLS policy.
There is no automatic certificate-verification bypass.

Server: HysteriaServer::with_tls(tag, config, Arc<rustls::ServerConfig>) supplies
the certificate configuration. bind_native binds a dedicated QUIC listener and
returns native stream/datagram tasks. Generic TCP handle_connection returns an
explicit error. For TCP, the task calls dispatcher.connect_stream BEFORE sending
success, then relays the established destination. A failed route sends rejection.
For UDP, the task retains the first packet to initialize routing and sends every
packet with its original source/destination meaning through DatagramTransport.

The lower-level HysteriaServer::bind(address, tls) and typed HysteriaIncoming API
remain available for direct integration/tests. Pending TCP requests expose
session, accept(), and reject(). UDP sessions expose recv()/send(address,payload).
Proxy user authentication preserves email and level in routing metadata. UDP is
advertised only in proxy-user mode (nonempty users); transport-only authentication
advertises false, matching the Go listener's validator distinction.

UDP limits: 128 sessions per connection, 8 queued packets per session, at most
65,507 payload bytes, at most 255 fragments, one pending packet per session,
idle expiry, duplicate suppression, and bounded incoming listener queues. A new
packet ID/count replaces old fragment state, as in Go. Empty UDP payloads are
explicitly rejected because Go's parser requires a nonempty payload. Concurrent
sends on one association serialize fragments to avoid interleaving pending IDs.
Outbound packet associations retain one original local source, including when
remote replies use a different target address. They reject mixing multiple local
sources into one association.

## Go DATAGRAM transport-parameter policy

The exact pinned Xray client sets EnableDatagrams=true and
OmitMaxDatagramFrameSize=true. Its listener sets
AssumePeerMaxDatagramFrameSize=1200. In apernet/quic-go 2895f039137a,
connection.go constructs an omitted parameter in that case, and
peerMaxDatagramFrameSize applies the configured assumption when the peer has no
positive advertised value.

Official Quinn otherwise cannot send DATAGRAMs to an omitting peer. The dedicated
Hysteria server crypto adapter delegates every TLS/crypto operation and changes
only the server's local interpretation of peer transport parameters. It uses the
public TransportParameters::write/read APIs and inserts the missing 0x20 TLV with
QUIC-varint value 1200. Explicitly advertised values, including zero, are retained
(a conservative narrowing of Go's fallback). TLS transcript bytes, certificates,
keys and verification are untouched. This policy is never applied to a client or
a generic QUIC endpoint. Malformed parameters fail closed. Sending still occurs
only after Hysteria authentication.

This path has source-level verification and dedicated unit coverage. Actual
Go-peer validation is a separate required Ubuntu run before claiming Go UDP
interoperability; no runtime result is claimed in this source snapshot.

## Explicit limitations

This is not full behavioral parity with every Xray QUIC setting. These options
fail explicitly rather than quietly using a different algorithm/transport:

- Brutal/force-brutal pacing, nonzero up_mbps, or disable-loss-compensation.
  Quinn's congestion-window controller cannot reproduce Go's rate pacer without
  an engine change. Default, bbr, and reno are the supported choices.
- Nonstandard Go BBR profiles. Quinn's BBR algorithm is reused; exact Go BBR
  congestion-state evolution is not asserted. down_mbps advertises receive
  capacity and does not imply a local traffic shaper.
- File/proxy masquerade. 404 and string/status/header responses are supported.
- Obfuscation, port hopping, Chrome QUIC/TLS impersonation, and unknown config
  keys. Global configuration builders must reject unsupported QUIC knobs before
  constructing this engine; no plain UDP/TCP replacement may be selected.
- QUIC initial/max receive-window growth tuning is represented by Quinn's receive
  limits, not a byte-identical replica of Go's adaptive flow-control mechanism.
- Active TLS behavior supplied through with_tls is the caller's responsibility.
  The default uses genuine certificate/name verification and never retries with
  an insecure verifier.

## Required fixture and Ubuntu validation

The Go-derived file proxy/hysteria/testdata/go-vectors.jsonl is mandatory,
compile-time included, and SHA256-pinned to:

6f5147a6034af06cbe7b2aa14873eaee96d893af63f554c761152f76879ad2f2

It contains exactly two records: actual Go TCP/UDP/fragment serializers/parsers,
and authentication decisions from Go's real httpHandler.AuthHTTP. Fixture tests
do not skip when absent. XRAY_HYSTERIA_REFERENCE_FILE optionally selects another
readable generated file for comparison; it never makes the frozen oracle optional.

generate.sh GO_REFERENCE_ROOT OUTPUT_DIRECTORY now archives the pinned source
into a disposable directory before injecting fixture tests, so the authoritative
checkout remains read-only. The generated JSONL filename remains
hysteria-vectors.jsonl. It does not rewrite the frozen Rust fixture.

Run in Ubuntu CI (the parent owns the workflow):

	sudo-free shell environment with existing Go and Rust toolchains
	bash testing/hysteria-reference/generate.sh /path/to/Xray-core /path/to/vectors
	cargo test --lib hysteria -- --nocapture
	bash testing/hysteria-reference/build-peer.sh /path/to/Xray-core /absolute/path/hysteria-go-peer
	XRAY_HYSTERIA_GO_PEER=/absolute/path/hysteria-go-peer cargo test --lib hysteria_go_peer -- --ignored --nocapture

The two live Go-peer tests require that explicitly built peer binary and fail if
it is missing. They are marked ignored only because they require a second Go
runtime/build artifact; ordinary mandatory fixture and QUIC-loopback tests run
without that binary. Live tests check Rust->Go TCP/UDP/rejection and Go->Rust
TCP plus 6,000-byte fragmented UDP with the client's DATAGRAM parameter omitted.
Both sides trust explicit generated test certificates; neither disables TLS
verification. No local Rust, Cargo, Go, installation, build, or test command was
run while preparing this lane. Ubuntu compilation and test results must be
reported separately.
