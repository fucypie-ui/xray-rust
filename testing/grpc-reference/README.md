# P0U27 Gun transport handoff

Status: source-complete candidate, **not compiled or runtime validated in this lane**.
Only transport/internet/grpc/** and testing/grpc-reference/** were written.
The parent owns configuration wiring, manifests, workflows, and remote validation.
Freeze date: 2026-11-27. Reference: 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7.

## Implementation

- Replaces the plain-TCP GrpcDialer/GrpcListener stand-ins with a real h2 client/server handshake and an AsyncRead/AsyncWrite adapter. Existing new/dial/bind/local_addr/accept signatures remain. No extra dependencies are requested: reuse h2 0.4.21, http 1.5.0, prost 0.14.6, Tokio, futures, and bytes already declared.
- Uses prost messages matching pinned Hunk (singular bytes field 1) and MultiHunk (repeated bytes field 1). Both modes work as byte streams, skip empty messages without reporting EOF, and preserve nonempty byte order. A Rust write emits one field in either mode; multi-entry inbound messages are decoded in order.
- Implements legacy and custom service paths with byte-level Go PathEscape semantics. Empty service remains empty, producing //Tun or //TunMulti; DEFAULT_SERVICE_NAME remains an explicit constant, not an implicit fallback. Listeners register both methods independently of multi_mode. Ambiguous identical custom listener paths are rejected; use /service/Tun|TunMulti. Single custom client paths remain supported.
- Sends HTTP/2 POST, application/grpc protobuf media type, te: trailers, and configured authority/literal user-agent. Native grpc-web, JSON codecs, compression, and per-RPC grpc-timeout are not accepted as equivalent transports.
- Validates response HTTP status/content-type/encoding, trailers-only status and final trailers. Missing/invalid/duplicate/nonzero grpc-status, truncated envelope/protobuf, RST and failed connections produce read errors. Already returned bytes remain returned when a later status fails. Messages with unsupported compression/reserved flags are not decoded as plaintext.
- Client shutdown ends only the request half and retains response reads. Server shutdown sends grpc-status: 0 trailers; a completed server handler can drop while the request half is still open without replacing its queued trailers with CANCEL. Dropping an unfinished stream explicitly resets that stream. Listener close cancels accept, lower/h2 handshakes, and all its active connections; it is an abrupt shutdown, not graceful RPC draining. Rejection/header-send failures caused by a racing peer reset are isolated to that RPC.

## Bounds and flow control

- Received protobuf record cap: 4 MiB, excluding the five-byte gRPC envelope. Oversized inbound requests receive RESOURCE_EXHAUSTED (8); malformed/compressed envelopes and protobuf receive INTERNAL (13). Unsupported request encoding, deadline metadata, or unknown methods receive UNIMPLEMENTED (12). Non-gRPC media receives HTTP 415.
- MultiHunk preflights at most 4096 occurrences of field 1 before prost allocates its repeated vector. This is an intentional additional limit, narrower than unrestricted Go protobuf. Unknown fields retain prost skip/recursion semantics. The MultiHunk element-limit failure is currently INTERNAL (13).
- Application writes are at most 16 KiB and reserve/check h2 send capacity before enqueueing. h2 per-stream send-buffer allowance is capped at 16 KiB + 16. A tiny peer window may require queueing one one-byte protobuf record whose envelope exceeds the available credit; h2 still fragments it and enforces window credit on the wire. Subsequent writes wait for capacity; no unbounded send_data loop or application pump exists. Accepted bytes enqueue immediately, without requiring a later application flush/read. Unused reservations are returned after each enqueue so idle multiplexed streams cannot hoard connection credit. flush checks send/reset state; it is not remote acknowledgement or a socket-fsync promise.
- Receive credit is released exactly once as DATA enters the bounded assembler, so a record larger than its window can finish. One record plus one default-size h2 DATA frame, one decoded record, and bounded repeated-field bookkeeping are retained; records are consumed before assembling subsequent records. h2's own receive queues are separately constrained by negotiated windows/frame accounting.
- Receive window defaults to 65535; connection credit is 1 MiB. Positive configured stream windows below 65535 use that floor; 0..=16777216 is accepted, negative/larger values fail explicitly. Both local h2 builders apply the selected receive window. This is static flow control, not grpc-go's dynamic BDP/window growth; the pinned Go server does not expose this field through its server options.
- Server caps: 64 connections, 32 HTTP/2 streams per connection, 128 admitted application streams overall, 32 queued accepts, and 16 KiB header lists. Admission overflow receives status 8. Lower security handshake and h2 handshake each have a 10-second bound. A dropped client gives its driver up to one second to flush queued close/reset frames, then releases the socket. These are local policies, not claims of Go connection-cache/retry parity.

## Explicit option gaps / changed defaults

| Option / behavior | Candidate behavior |
| --- | --- |
| service_name / serviceName | Supported, preserving empty, escaped and custom paths. |
| multi_mode / multiMode | Supported. Listener accepts Tun and TunMulti. |
| authority | Supported as client HTTP/2 authority; never used as an implicit TLS SNI override or server host ACL. |
| user_agent literal | Exact header, without a library suffix. |
| user_agent = golang | Omits the user-agent header, matching the pin's explicit golang override. |
| user_agent = empty/chrome/firefox/edge | Explicit Unsupported; Go's time/CPU/random browser fingerprints are not synthesized. |
| constructor / serde omitted user_agent | Defaults to golang, an explicit local default difference from Go's omitted/empty browser alias. Parent must choose and disclose its configuration default. |
| idle_timeout / health_check_timeout / permit_without_stream | Any nonzero/true setting fails Unsupported. Constructor timeout defaults change from the old unused 10/20 to 0/0. h2 still handles mandatory peer PING acknowledgements. |
| initial_windows_size | Static bounded receive-window behavior above; values outside 0..=16 MiB fail Unsupported. |
| compression / grpc-web / other codecs | Unsupported. Compression negotiation is identity only; unknown transport-config JSON fields fail deserialization. |
| grpc-timeout | Request explicitly receives status 12; no unsupported server deadline is silently ignored. Caller future cancellation and RST are supported. |
| connection caching / retry / graceful GOAWAY drain | Not implemented as Go-equivalent policies. Rust opens one h2 connection per dial; server accepts multiplexed h2 clients. Listener close is cancellation. |
| TLS / REALITY / socket options / masks / trusted-forwarded metadata | Parent-owned lower transport/configuration integration. No security setting is interpreted or downgraded here. |

The pre-existing unused HunkConnection/MultiConnection compatibility holders remain; production dial/listen paths use GunStream, not those holders or the framing-only GrpcStream utilities.

## Minimal parent wiring requirements

1. Instantiate the real GrpcDialer/GrpcListener in the grpc transport arms; do not retain the old generic TCP fallback. Preserve empty service names, multiMode, authority, and all timeout/window/user-agent fields. Pass unsupported requests through validation, or reject them at configuration construction, rather than dropping fields.
2. The separately owned configuration adapter must forward authority/user_agent and normalize signed Go timeout/window values <=0 before engine validation. This transport deliberately rejects raw negative window sizes. The parent must decide explicitly whether omitted browser UA is rejected or the documented golang default is the product policy. The announced plain/TLS rustls adapters, ALPN checks, root-close cancellation, consumed-TLS stripping, and explicit composition rejections are separate work and are not validated by this freeze.
3. Plain prior-knowledge h2 uses existing constructors/trait methods. For an already established secure/masked/base stream, call GrpcDialer::dial_over(BoxStream, &Destination, secure: bool). secure chooses the HTTP :scheme only; the parent negotiates/verifies TLS ALPN h2 and chooses authority from explicit value/TLS server name/destination as appropriate.
4. For inbound security use GrpcListener::bind_over(SocketAddr, GrpcConfig, hub::LowerStreamAcceptor). The acceptor takes TcpStream and returns a boxed Send future yielding Result<BoxStream>; the parent performs TLS/REALITY and verifies h2 negotiation. Listener cancellation also cancels that lower handshake. Current bind constructors still own socket creation; socket-level options, externally bound listeners, PROXY protocol, and trusted XFF processing need separate adapters or explicit rejection by the parent.
5. Wire listener shutdown to close(). Pending accepts and connection tasks then terminate. No global client shutdown API is added to the unchanged Dialer trait; each stream owns its driver's lifetime. Parent feature-wide cancellation must also cover lower streams while a native wrapper is retained.

The public lower contracts are frozen without changes from coordination: pub(crate) GrpcConfig::validate(&self) -> Result<()>, pub hub::LowerStreamAcceptor = Arc<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send>> + Send + Sync>, GrpcDialer::dial_over(&self, BoxStream, &Destination, bool) -> Result<BoxStream>, GrpcListener::bind_over(SocketAddr, GrpcConfig, LowerStreamAcceptor) -> Result<Self>, and listener accept/local_addr/close. Both lower hooks are async, as are bind/accept/close; local_addr is synchronous.

## Source-only verification and tests provided

Performed here: pinned Go source and official h2/prost/tonic source research (see research.md), manual source/API/lifecycle review, git diff --check, bash -n on the build script, ownership/hash checks, and test-source registration/count checks.

Refreeze correction: parent review inferred a race between close completion notification and destruction of the captured listener. The supervisor now explicitly drops the listener after aborting/joining children and before notifying completion. The existing close/cancellation regression uses two Tokio workers and eight bounded iterations, with a synchronous same-address TCP bind/listen immediately after close returns and before further read/await cleanup, retaining the old listener wrapper and both returned streams. It matches Tokio's socket reuse policy to avoid TIME_WAIT-only failures. No sleeps, timeout increases, new test functions, or public API changes were added. This is source reasoning and unrun regression coverage, not an executed failure or red/green proof. Counts remain 16 ordinary transport regressions, one existing constructor regression, and three ignored Go tests.

Not performed here: ANY Rust/Cargo/Go command, compiler, build, test, formatter, code generation, dependency installation, Clippy, remote execution, commit, or push. Parent-reported green checkpoints predate this candidate and do not validate it.

Provided, all unrun:

- 16 new ordinary regression functions plus the updated existing constructor regression (17 total in this module): localhost TCP both modes, larger-than-window byte exchanges, per-byte DATA fragmentation, forced 2/3-byte lower TCP I/O, delayed response headers, authority/UA, empty and repeated protobuf fields, malformed/oversized messages, status/trailer failures including late errors, multiple h2 streams, idle-stream connection-credit fairness, reset-before-dispatch isolation, one-byte flow-control stalls/resume, cancelled pending client handshake and lower server acceptor, stream drop, listener shutdown, and explicit option rejection.
- 3 ignored-but-mandatory-when-selected Go tests: Rust client -> Go server (3 service forms x 2 modes x roundtrip/denied = 12 cases), pinned production Go client -> Rust server (3 forms x 2 modes = 6 cases), and eight strict-control negative cases (otherwise-valid controls verify the specific rejection diagnostic). No helper means panic/failure, never success/skip.
- Go server uses the exact pinned generated service bindings, custom registration helper, and Hunk/MultiHunk connection adapters atop grpc-go. It does not invoke Xray's async top-level Gun Listen constructor. Go client invokes the pinned production Gun Dial with serviceName/multiMode/authority. All HTTP/2/protobuf framing is independently owned by Go libraries, not Rust-generated fixtures.
- Control: one strict JSON object on stdin followed by EOF; exact required keys, no nulls/duplicates/unknown fields/trailing JSON. Only ready/done JSON lines go to stdout; diagnostics and Go logging go to stderr. Helper has a 35-second watchdog; Rust cases use deadlines and kill-on-drop subprocesses. No fixture-only result substitutes for a live exchange.

## Parent Linux commands (NOT run here)

Run from the Rust repository root on Linux. The reference checkout must have HEAD at 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7.

    bash testing/grpc-reference/build-peer.sh ../Xray-core /tmp/xray-grpc-go-peer
    cargo test --locked --lib transport::internet::grpc::
    XRAY_GRPC_GO_PEER=/tmp/xray-grpc-go-peer cargo test --locked --lib grpc_go_reference_ -- --ignored --nocapture
    cargo clippy --locked --all-targets -- -D warnings

The builder uses git archive of the exact pin into a disposable tree, GOWORK=off, and go build -mod=readonly. The script requires Linux coreutils realpath and rejects OUTPUT_BINARY paths inside the Go reference checkout. It does not copy a mutable Go checkout or modify its manifests. It rejects Android/Termux; no workflow/dependency edits are included. Select all three grpc_go_reference_ tests explicitly in the parent live gate; ordinary cargo test leaves them ignored by design. Parent should additionally retain its full ordinary/Clippy/stress gates and any separate TLS/REALITY integration gates.

At the final audit, Cargo.toml/Cargo.lock and app/pingora_bridge/outbound.rs still matched the saved pre-lane hashes. Configuration files were concurrently changing in the separately authorized adapter lane; they are neither frozen nor attributed to this transport lane. Other lanes' untracked/modified files were preserved.

SHA256SUMS lists every changed/new deliverable except itself, with repository-relative paths. Its own digest is supplied in the handoff. Verify with sha256sum -c testing/grpc-reference/SHA256SUMS before integration. This snapshot is frozen after final source checks; runtime correctness remains for parent remote review/compile/live validation.

## Parent Linux follow-up: initial integrated source 3070574

Protocol run 45945074781 compiles the peer and Rust live tests. Both actual byte-exchange groups pass, while the strict-control group fails because the malformed object case expects the substring EOF but the pinned decoder reports unexpected end of JSON input. The follow-up changes only that expected diagnostic, retaining nonzero child exit, empty stdout, all eight negative cases and their specific diagnostics. Strict all-target Clippy separately rejects a constant cfg assertion and a redundant two-element vec; the follow-up uses the already accepted classic-test OS assertion pattern and an array repeat. No lint allowance, timeout increase, helper/parser change or production transport change is made. All seven pre-existing live lanes (24 cases) and the classic byte workflow pass at 3070574. Rust CI 45945074711 also passes locked check/debug/release, 1202 library tests (28 ordinary ignored), nine binary tests, all16 required transport regressions, the existing10relay/1classic required gates, 15CLI comparisons and21argument checks; documentation has zero runnable cases. The combined checkpoint is still not promoted because Clippy and the strict-control group fail. This follow-up has no inherited execution credit.
