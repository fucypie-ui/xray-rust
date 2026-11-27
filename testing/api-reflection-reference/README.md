# Pinned API reflection live reference

This helper uses the production generated grpc-go v1 and v1alpha reflection
clients. Baseline mode builds and starts an actual Xray core from
`infra/conf.Config.Build`, including its real Commander and configured services,
and runs the same client exchanges against that server. It does not register a
replacement reflection server or use descriptor fixtures as successful traffic.

The immutable reference is
`67756b3674d56b72c7a7e675e8dcd3f883e1b2f7`. The archive's existing locks require
Go 1.27, grpc-go 1.85.0, protobuf 1.36.12 and x/net 0.63.0. The helper checks its
actual Go/grpc/protobuf build versions and reports them with the full reference
pin in its only successful stdout JSONL event. No dependencies or generated
sources are added, and the existing bundled 92-file Rust pool is not changed.

## Remote Linux build and execution

Run these commands on the parent's remote Linux builder, from the Rust repository
root. Do not execute Go, Rust, Cargo, formatters or live tests on Android. The
builder must already have Go 1.27 and the repository's Rust toolchain available;
`GOTOOLCHAIN=local` refuses an automatic Go toolchain installation.

```sh
git -C ../Xray-core rev-parse HEAD
sha256sum -c testing/api-reflection-reference/SHA256SUMS
bash testing/api-reflection-reference/build-peer.sh ../Xray-core "$PWD/../api-reflection-go-peer"
export XRAY_API_REFLECTION_GO_PEER="$PWD/../api-reflection-go-peer"
cargo test --locked --lib api_reflection_go_reference_ -- --list --ignored
cargo test --locked --lib api_reflection_go_reference_ -- --ignored --nocapture --test-threads=1
```

The builder requires the exact reference HEAD, exports only that commit with
`git archive` to a disposable directory, copies `peer.go` there, and invokes
`GOWORK=off GOTOOLCHAIN=local go build -mod=readonly -trimpath -buildvcs=false`.
It leaves the reference checkout and its module files untouched, forbids an
output inside that checkout, and removes its own disposable archive on exit.

The production reflection owner registers the new test file under the reflection
module with `#[path = "reflection_go_peer_test.rs"]`. That registration is outside
this five-file lane. The list command must show exactly the following three
ignored tests, with no zero-test substitute. Each explicitly selected group fails
if `XRAY_API_REFLECTION_GO_PEER` is absent or the platform is not Linux.

| Live group suffix | Required completed cases | Successful helper processes | Negative controls |
| --- | ---: | ---: | ---: |
| `commander_baseline` | 8 actual Go Commander probes | 8 | 20 |
| `configured_listen` | 8 Rust direct-listener / Go baseline pairs | 16 | 0 |
| `tagged_service_outbound` | 8 Rust SOCKS-routing / Go baseline pairs | 16 | 0 |
| Total | 24 cases or pairs across 3 groups | 40 | 20 |

All test names begin with `api_reflection_go_reference_`. Each group prints its
completed counts only after its required assertions succeed. These are executable
matrix counts, not results claimed by this source-only freeze.

Each group has a shared absolute 60-second deadline covering startup, all cases,
controls, subprocess I/O, reaping and root shutdown. Its work deadline is the
absolute group end minus five seconds (at most 55 seconds from group creation).
Startup and the entire helper budget, including kill/wait, use that earlier
deadline. Each root teardown has at most five seconds, capped by the original
group end: at most three seconds to close/join, then a reserved two seconds to
abort and await every still-owned task. A graceful-join timeout remains a test
failure even if the subsequent abort/join succeeds. A task that cannot be joined
by the final deadline is explicitly reported as cleanup failure, never a pass.

The root owner exists before startup and all runtime assertions. The existing
`futures::FutureExt::catch_unwind` captures startup/probe/assertion failures;
the same awaited teardown runs before the original panic payload is resumed.
JoinHandles remain in owned slots across borrowed timeouts and are removed only
after their await completes. Close errors or panics do not skip the joins. A
close panic is resumed after teardown if there is no earlier failure; otherwise
its diagnostic accompanies the original failure. `Drop` is an emergency fallback
for external cancellation, not the ordinary-failure cleanup mechanism.

This join claim covers handles returned by the public `Instance::start` API.
The public runtime owns feature-internal accept/connection tasks and startup
rollback; it exposes cancellation through `close` but no JoinHandles for those
private tasks. The harness cannot claim independent joins for inaccessible
tasks or preempt synchronous runtime code. Those are production lifecycle
responsibilities. No new ordinary tests or dependencies were added for this fix;
bounded cleanup behavior still needs remote execution/review.

A helper process retains its maximum 15-second parent budget, with its final
second reserved for kill and wait; positive controls request a 12-second RPC
context. The helper also has its own 15-second watchdog covering stdin and all
other work. Group budget exhaustion fails rather than silently dropping
remaining cases. The harness sends one JSON object then closes stdin,
concurrently drains bounded stdout/stderr, waits for exit, and rejects extra
stdout, missing fields or unknown event fields (including all nested observation
objects). Timed-out children are killed and awaited; `kill_on_drop(true)` is an
additional safeguard. These are cooperative async deadlines, not preemption of
a stalled operating system or blocked synchronous code.

## Profiles and routing proof

Every group uses both generated protocol clients for each of these four profiles:

| Profile | Configured API services | Expected sorted ListServices count |
| --- | --- | ---: |
| `full` | Reflection, Handler, Logger, Stats, Routing, Observatory | 11 |
| `stats` | Reflection, Stats | 4 |
| `reflection` | Reflection only | 2 |
| `disabled` | Stats only, without Reflection | unavailable; terminal status 12 |

The expected lists include canonical names and the `v2ray.core.app` aliases for
Handler, Logger, Stats and Routing; Observatory has only its canonical
`xray.core.app.observatory.command.ObservatoryService` name. Both reflection
services appear whenever reflection is enabled. Exact sorted equality excludes
all disabled services and unwanted Observatory aliases. Descriptors remain
globally discoverable even when their RPC service is not registered.

Rust instances use only root `Config` construction, `Instance::from_config`
(which calls `Config::build`), feature startup/shutdown, and the public shared
stats manager. The tests never call private endpoint or reflection functions.
A sentinel counter named `reflection.reference.sentinel` is seeded to `424242`
in each real runtime and checked after traffic without resetting it.

The direct test sets an actual `api.listen` address and verifies that it does
not increment tagged API outbound traffic. The routed test leaves `api.listen`
empty, starts a real configured SOCKS5 inbound, and uses the existing x/net SOCKS5
context dialer to send grpc-go traffic to
`api-reflection.reference.invalid:18080`. An explicit inbound-tag/domain/port/TCP
rule selects the configured `reflection-api` outbound. The default outbound is
a blackhole. Both public outbound byte counters must increase for the API tag
for every routed probe, while blackhole counters remain zero. Thus a successful
case requires SOCKS negotiation, the dispatcher/router and the tagged
`ServiceOutbound`; a hidden direct API listener cannot satisfy it.

The Go baseline uses its actual configured direct Commander listener; it is not
a claim that Go's separate tagged-outbound route was exercised. The routed half
of each comparison is the actual Rust root route described above. No DNS or
external network endpoint is needed. Empty Observatory selectors prevent probes.

Neither Commander exposes its bound API port; Rust root configuration currently
skips port-zero inbounds. The harness therefore holds a kernel-selected loopback
port reservation through construction and releases it immediately before startup.
Bind races fail explicitly; there is no retry, polling, private accessor or fake
endpoint fallback.

## Reflection exchanges and assertions

Every enabled probe performs exactly 28 successful request/response exchanges,
each checking both the nonempty UTF-8 `host` echo and protobuf-equal
`original_request`, before closing its sending half:

| Exchanges | Scenario |
| ---: | --- |
| 1 | Exact sorted ListServices, with a nonempty ignored filter |
| 5 | Handler service, file, method and message symbols, then its core/config dependency as root |
| 10 | Five missing queries, each followed by ListServices recovery on the same stream |
| 1 | AllExtensionNumbersOfType for google.protobuf.FeatureSet, exactly [1002] |
| 2 | FileContainingExtension for FeatureSet 1002, then its repeated root |
| 1 | Stats.QueryStats method descriptor |
| 2 | v1 and v1alpha reflection schema files and bidirectional method descriptors |
| 1 | Fresh-stream Handler closure with a new empty cache and registry |
| 1 | Recovery on a new stream after missing-oneof terminal status 3 |
| 4 | Concurrent independent Handler closures, cancellation status 1, surviving repeated root and ListServices |
| 28 | Total |

These cover all five reflection query variants: ListServices, FileByFilename,
FileContainingSymbol, FileContainingExtension and AllExtensionNumbersOfType.
The five missing queries are a filename, canonical symbol, extension number,
containing type and legacy service alias that has no actual descriptor. Each
must return an in-message status 5 with a nonempty diagnostic, not a failed
stream. A request with no query oneof must instead terminate the stream with
status 3. Reflection disabled must terminate with status 12.

The first Handler descriptor response must contain exactly these four files:

```text
app/proxyman/command/command.proto
common/protocol/user.proto
common/serial/typed_message.proto
core/config.proto
```

The received descriptors build a fresh `protoregistry.Files` through
`protodesc.NewFiles`, resolving imports only from the returned graph; a missing
dependency cannot be filled by `GlobalFiles`. Reconstructed descriptors are
compared with the linked pinned source descriptors as an independent authority.
A deterministic sorted four-file descriptor-set SHA-256 is returned and compared
between each Rust probe and its actually executed Go Commander baseline.

Each enabled probe asserts four independently fresh Handler closures, six
repeated-root responses, dependency suppression within each stream, and reset on
fresh streams. The requested root must be included first even when sent earlier;
already sent dependencies must not be retransmitted. Extension 1002 and its
containing FeatureSet must resolve from the reflected descriptor registry.

Five normal streams must finish with clean EOF after CloseSend, including one
empty stream. Cancellation of one active reflection stream must leave a
concurrent stream and its independent descriptor cache working on the same
ClientConn. Normal requests always send and receive before CloseSend, preventing
a server that buffers until request EOF from passing.

The full and stats profiles also construct `dynamicpb` input/output messages
from the returned Stats service descriptors and invoke the canonical unary
`/xray.app.stats.command.StatsService/QueryStats` path. They require exactly the
real sentinel counter and value. The reflection-only profile still reflects
Stats descriptors but cannot claim a dynamic Stats RPC success.

For each enabled probe, the exact result counters are: queries 28, echoes 28,
in-message not-found 5, fresh Handler closures 4, repeated roots 6, clean EOFs 5,
empty EOFs 1, terminal invalid-argument 3, and cancellation 1. Dynamic queries
are 1 with value 424242 for full/stats, otherwise 0. Disabled probes have no
successful reflection exchange and exactly terminal status 12.

## Observed diagnostics and response metadata

Every missing-query response contributes its actual query identifier, error code
and complete raw error message to `lookup_errors`. The five identifiers are
`missing_filename`, `missing_symbol`, `missing_extension`, `missing_type` and
`legacy_alias_symbol`. The generated clients perform the same capture against
both Rust and the actually started pinned Go Commander. An assertion accepting
any nonempty diagnostic is no longer the comparison boundary: the paired
outcomes include those observed strings.

Each enabled probe also records seven actual stream terminations in order:
`main`, `fresh`, `empty`, `missing_oneof`, `missing_oneof_recovery`, `cancelled`
and `survivor`. Each record contains `scenario`, `eof`, the actual terminal
`code` and raw `message`, plus separately observed public `Header()` and
`Trailer()` metadata in `headers` and `trailers`. Disabled probes record only
`disabled`, with actual terminal code 12 and its message and both metadata maps.
Clean EOF is identified from the received `io.EOF` and represented by the gRPC
OK status obtained from a nil status error, with the independent `eof` flag.
Neither terminal diagnostics nor metadata are filled from an expected outcome.

Both metadata APIs are read only after terminal `Recv`. In particular, the empty
stream calls `CloseSend` and then `Recv` before `Header`, so a correctly deferred
headers/trailers-only server cannot deadlock waiting for an unsent half-close.
The same ordering captures the missing-oneof, disabled, and cancellation cases.
Metadata maps become arrays of `key` / `values_base64` records sorted only by
key; every per-key value, duplicate and value order is preserved, and base64
preserves arbitrary bytes including binary metadata. Empty metadata maps encode
as empty arrays. No header/trailer key or value is excluded by the harness.

All outcome fields participate in paired equality, with exactly one permitted
comparison projection: the entire lookup-message sentinel
`proto:\u00a0not found` (NBSP after the colon) is compared as
`proto: not found` (ASCII space). The raw stdout JSON fields and parsed raw
outcomes remain unchanged; mismatch diagnostics include both raw outcomes.
Only those two complete sentinel strings are equivalent. There is no general
whitespace normalization, trimming, diagnostic substring matching, normalization
of terminal messages, or metadata normalization beyond sorting map keys.

This narrow choice is required by the pinned protobuf dependency, which chooses
its error-prefix separator from the Go executable's binary hash. It must not
hide query-specific text or other error differences. The exact version-tagged
primary sources inspected for this revision are:

- [Xray Commander reflection registration at the full reference pin](https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/app/commander/service.go#L17-L21), which calls grpc-go's actual reflection registration.
- [grpc-go v1.85.0 reflection handlers](https://github.com/grpc/grpc-go/blob/v1.85.0/reflection/internal/internal.go#L101-L245): resolver errors become code-5 responses with `err.Error()`; missing oneof becomes code 3.
- [protobuf-go v1.36.12 registry sentinel](https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/reflect/protoregistry/registry.go#L75-L80), [error prefix](https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/internal/errors/errors.go#L26-L37) and [binary-seeded choice](https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/internal/detrand/rand.go#L24-L40): the lookup failure is the shared NotFound sentinel, not query-specific text.
- [grpc-go v1.85.0 status writer](https://github.com/grpc/grpc-go/blob/v1.85.0/internal/transport/http2_server.go#L1098-L1120): without prior messages/headers it emits trailers only, and writes `grpc-message` even for the empty success message.
- [grpc-go v1.85.0 public Header/Trailer implementation](https://github.com/grpc/grpc-go/blob/v1.85.0/stream.go#L985-L1036), [header decoder](https://github.com/grpc/grpc-go/blob/v1.85.0/internal/transport/http2_client.go#L1560-L1595) and [header/trailer placement](https://github.com/grpc/grpc-go/blob/v1.85.0/internal/transport/http2_client.go#L1659-L1675): `content-type` remains observable, while reserved status/message fields are consumed into the status API.
- [grpc-go v1.85.0 unknown-service status](https://github.com/grpc/grpc-go/blob/v1.85.0/server.go#L1604-L1614), used when reflection is disabled.

Consequently the public-client comparison detects `content-type` moving between
Header and Trailer for empty and first-error streams. It does not independently
prove wire-level presence of an empty `grpc-message`, its percent encoding, or
other reserved fields consumed by grpc-go. Encoding, malformed-wire and raw-h2
cases remain with the production owner's tests; this revision adds no duplicate
wire cases. Deferred headers, correct NotFound text and exact public status/
metadata behavior are required production compatibility, not helper exceptions.
The production author owns those corrections; none are written in this lane.

The baseline group additionally executes 20 strict negative controls covering
duplicate/unknown/missing/null fields, wrong and fractional numeric types,
nonobject/malformed/trailing/oversized JSON, unsupported mode/version/profile,
both timeout bounds, nonloopback or zero-port endpoints, and invalid SOCKS
combinations. Every control must exit unsuccessfully, emit no stdout and match
its specific stderr diagnostic.

## Control and event contract

Send exactly these six fields on stdin, followed by EOF; all fields are required,
including the empty direct-mode `socks` string:

```json
{"mode":"baseline","address":"127.0.0.1:0","socks":"","version":"v1","profile":"full","timeout_ms":12000}
```

`mode` is `baseline` or `client`; `version` is `v1` or `v1alpha`; `profile` is
one of the four matrix profiles. `timeout_ms` is an integer in 1..15000. Direct
addresses must be IPv4 loopback, with a nonzero port except that baseline mode
may request port zero. Nonempty `socks` requires client mode, an IPv4 loopback
SOCKS endpoint with nonzero port, and exactly the fixed routed target above.
Controls over 65536 bytes are rejected. No command-line arguments are accepted.

Success emits exactly one JSON object plus newline, with fields `event` (done),
`reference`, `grpc_version`, `protobuf_version`, `go_version`, `mode`, `address`,
`socks`, `version`, `profile` and `result`. `address` is the actual bound endpoint
for baseline mode and the requested destination otherwise. `result` contains
`services`, `handler_files`, `handler_sha256`, `checks`, `queries`, `echoes`,
`not_found`, `fresh_closures`, `repeated_roots`, `clean_eof`, `empty_eof`,
`terminal_code`, `cancelled_code`, `dynamic_queries`, `dynamic_value`,
`lookup_errors` and `streams`. Every lookup observation requires `query`, `code`
and `message`; every stream observation requires `scenario`, `eof`, `code`,
`message`, `headers` and `trailers`. Both metadata arrays require `key` and
`values_base64` in each entry. Unknown, missing, duplicate, null or incorrectly
typed observation fields are rejected by the strict Rust schema. Failures are
nonzero exits with diagnostics on stderr. Baseline build/start alone does not
produce a success event: the required actual exchanges must complete.

## Freeze scope and verification limits

This lane owns only `peer.go`, `build-peer.sh`, this README, `SHA256SUMS` and
`infra/conf/runtime/reflection_go_peer_test.rs`. The manifest contains the four
payload hashes relative to the Rust repository root and intentionally excludes
itself; the accompanying handoff reports the manifest's separate hash.

This is a source-only freeze. Only source inspection, shell syntax parsing,
whitespace/scope checks, static matrix/schema checks and SHA-256 verification
were performed locally. No local Go/Rust/Cargo compilation, execution, tests,
formatting, generated fixtures, installations, commits or staging were performed.
The documented three-group counts and routing assertions are requirements to
verify remotely, not measured live passes. This lane supplies no raw-h2 frame,
fragmentation, bounds or backpressure tests; those belong to the production
reflection owner. Its descriptor pool, services and registration remain owned
by that lane, and rpc-reference research is owned separately.
