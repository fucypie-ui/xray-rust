# Independent Go reference fixtures

The authoritative source is XTLS/Xray-core commit
`67756b3674d56b72c7a7e675e8dcd3f883e1b2f7`. Fixtures are generated on
Linux and frozen verbatim. These are deterministic public test inputs.
The table lists represented operations, not complete protocol compatibility.

| Frozen file | Represented coverage | SHA-256 |
| --- | --- | --- |
| `testing/crypto-reference/vectors.json` | Five ML-KEM-768 complete public-key/hash vectors and five X25519 clamped key/public-key/hash vectors. | `0b9a9571123e5dbbc0f78d35eb5e64790699ebf2d7067018640181a5b6feab95` |
| `proxy/shadowsocks_2022/testdata/go-vectors.jsonl` | AES-128/256 TCP KDF, request/response headers and body bytes. | `af1b7f607dba629ba63ac306fc8594a1e8b751d0185050053aa7d648e29c7aeb` |
| `proxy/shadowsocks_2022/testdata/go-extended-vectors.jsonl` | Three AES/ChaCha records covering TCP identity chains and UDP requests/responses. | `349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0` |
| `proxy/vmess/testdata/go-vectors.json` | AuthID/KDF/request/response plus 24 authenticated body option/cipher/command combinations. | `25315d8abb22636487b7fea89971b78d1ffe824e8c2abab7daaeca48e92e6f4c` |
| `transport/internet/reality/fixtures/go-vectors.json` | ClientHello/ECDH/HKDF/AEAD and authentication-certificate vectors. | `4643f0ca070c22783dc22dfebc20a8d353fcbc2579895ed02cd7195c2e5687b5` |
| `proxy/hysteria/testdata/go-vectors.jsonl` | Pinned-Go Hysteria wire records consumed by mandatory Rust assertions. | `6f5147a6034af06cbe7b2aa14873eaee96d893af63f554c761152f76879ad2f2` |
| `testing/wireguard-reference/generated/wireguard-key-vectors.json` | WireGuard key derivation/configuration vectors; not encrypted live sessions. | `711505b1551b672f0cbb84c7135ef1a12f33a21a618e67ee52b72050881ffed0` |
| `testing/kcp-reference/generated/kcp-reference.json` | Ten mKCP byte/parser cases, seven deterministic session trace entries and five RTO observations. | `6d20d46fc9494333b3e003b80b3a73dfb87005d6674885badd269e675e90f63b` |
| `testing/mux-reference/generated/mux-vectors.jsonl` | Twelve VLESS multiplex metadata/payload frame records, including packet boundaries. | `dd2496a796d24a860f55ac9f251e73664ccd8aa2de22e2cfa2614b0d670261c3` |

`testing/config-reference/generated` contains pinned-Go JSON/YAML/TOML,
protobuf messages, descriptors, default/error cases, and its own SHA256SUMS
and source/generator/toolchain records. Keep native protobuf bytes and their
descriptors together when comparing effective configuration.

## Provenance and execution scope

The original crypto/AES fixtures came from Linux reference run 45885788457.
SS2022 extended records were downloaded from successful job 140158378278 in
run 45892518463, generated at Rust source 584cd13 with Go 1.27.4 linux/amd64.
All artifact SHA256SUMS entries and source/generator pins were verified before
freezing at 1ea1cf2. See the adjacent go-extended-provenance.json.

The corrected Mux helper succeeded in run 45893018590 at generator source
1ea1cf2. Its 12 records, SHA256SUMS and provenance/source/toolchain files were
verified and frozen in 517a155. All eight independent engine-reference jobs
(config, Hysteria, KCP, Mux, REALITY, SS2022, VMess and WireGuard) succeeded
in that run. Passing helper generation does not establish Rust interoperability.

At 517a155, Linux Rust CI 45893541120 passed all-target checking and
debug/release builds. Its library suite finished with 1,120 passed, 8 failed
and 13 ignored. The Mux encode/decode comparison, SS2022 extended comparison,
KCP traces and other represented byte assertions passed; runtime failures
remain. Separate live workflow 45893541110 executed all 13 required cases:
REALITY 1/3, WireGuard 3/8 and Hysteria 1/2 passed. No complete live gate passed.
See ../md/PORTING_STATUS.md for current failures and follow-up revisions.

At cf9510e4a5c98607ba5ae8e8efd32ad9891ab833, Rust CI 45895829517 passed
checking and debug/release builds. It executed 1,137 passing library tests,
one failing VMess teardown test and 13 ignored live cases; all nine binary
tests passed. The extended SS2022 comparison now included e811ca8's mandatory
hash assertion and passed. Live workflow 45895829521 separately executed and
passed all three REALITY, eight WireGuard and two Hysteria cases, plus strict
Clippy. Full Rust CI remained failed; key/doc steps were skipped.

Rust CI 45896320540 at d977720 succeeded: 1,138 library tests and nine binary
tests passed, with 15 live tests ignored for separate required gates, 15 built
CLI comparisons passed and the documentation command passed (zero runnable
tests). This includes the VMess raw-transport drain after protocol EOF in its
bounded-duplex regression. That source also adds two live pinned-Go mKCP cases. The initial
mKCP run 45896320441 compiled and executed both cases but failed both at
strict readiness parsing: a diagnostic timestamp appeared on stdout before
the expected JSON. This is not session interoperability evidence. The
existing 13 live cases and Clippy passed again in that run.

At fd2d231005e8d518e9b3cf76816e79cd2f33a92b, Rust CI 45896822590
passed 1,138 library/nine binary tests and 15 CLI comparisons. Required live
workflow 45896822633 passed REALITY 3/3, WireGuard 8/8, Hysteria 2/2 and
mKCP 2/2: all 15 selected cases executed, none ignored. Strict Clippy and all
eight Go-reference jobs (45896822491) passed. The mKCP success covers both
directions, MTUs 1350/200, exact binary payloads, fragmentation, EOF and close.

Native SS2022/config source 98f42c8 passed ordinary Rust CI 45897222837:
1,151 library/nine binary tests and 15 CLI comparisons, zero failures. Its
eight new native and five config cases all executed, including frozen Go
requests through production handler decoders at the fixture timestamp. This
is not a live SS2022 peer result. Workflow 45897222798 passed strict Clippy
and the existing 15 REALITY/WireGuard/Hysteria/mKCP live cases at that revision.

Do not change an oracle or its expected digest merely to match Rust output.

## Regeneration

Use the authorized Linux runner, pinned source checkout and reference Go
toolchain. Existing helpers under testing/{crypto,ss2022,vmess,reality,hysteria,
wireguard,kcp,mux,config}-reference retain their documented interfaces; consult
each generate.sh/build-peer.sh before invoking it. For example:

~~~sh
bash testing/crypto-reference/generate.sh /path/to/pinned/Xray-core /path/to/output
bash testing/ss2022-reference/generate.sh /path/to/pinned/Xray-core /path/to/output
bash testing/ss2022-reference/generate-extended.sh /path/to/pinned/Xray-core /path/to/output
~~~

The parity-preparation and engine-reference workflows produce artifacts remotely.
Verify every artifact checksum, exact Go source commit, generator commit and
record coverage before importing bytes. Preserve generator provenance beside
new frozen files. Run the actual Rust assertions and nonempty live gates on
the same integration revision before awarding their distinct evidence.
No Rust or Go toolchain installation, compilation or tests run on Android.

## Following classic AEAD and SS2022 live gates (source only)

`.github/workflows/classic-shadowsocks.yml` generates four pinned-Go classic AEAD vectors on Linux, requires the ignored Rust trait test to execute, then requires production Go decoders to accept the emitted Rust TCP request/response and UDP request/native-response bytes. The helper stages `git archive` and uses read-only module resolution; the authority checkout must remain clean. Missing vectors, empty filters, ignored selected cases and failed reverse decoding are fatal. This is independent byte evidence, not a live classic Go session.

The SS2022 matrix in `protocol-interop.yml` builds `testing/ss2022-reference/peer.go` against the exact pinned Go commit and requires both ignored `proxy::shadowsocks_2022::go_peer_test` cases to execute. The source specifies five configurations per direction and six pairs each: 60 UDP exchanges total. It distinguishes the full production Process path from production UDP session APIs for empty Go-client packets. Relay is outside this gate. These are pending source registrations until exact-revision Linux results are recorded.

## First passing classic byte and live SS2022 gates: 1c938da

Rust source `1c938daac7a3105f64e8cc26c11e2dbe2cfcdc54` passes classic reference workflow `45900139172`. The required Rust inbound/outbound trait comparison executes one test (zero failures/ignores), across AES-128-GCM, AES-256-GCM, ChaCha20-IETF-Poly1305 and XChaCha20-IETF-Poly1305. Go production TCP request/response and UDP decoders accept the emitted Rust records, including native inbound UDP replies; Go-generated packets are accepted through the Rust trait boundaries. All three downloaded JSONL hashes match the artifact manifest. Generation uses isolated git-archive staging from Go `67756b3674d56b72c7a7e675e8dcd3f883e1b2f7`; the authority checkout remains clean. These randomly salted runtime artifacts are not new deterministic frozen fixtures or live sessions.

The same revision passes protocol workflow `45900139064`: all 17 selected live cases execute with no ignores and strict Clippy passes. The first two SS2022 grouped UDP tests cover three single-user ciphers plus AES-128/AES-256 EIH, in both directions, with 60 exact request/reply pairs. Nonempty Go-client packets use production Process; its two empty-packet cases use production session APIs because pinned Process drops empty buffers. Empty/large payloads, addresses, user attribution, cancellation, closure and retained-transport socket release execute. No relay or live TCP SS2022 result is implied.

Ordinary CI `45900139028` still fails two cases: Mux carrier-close BrokenPipe and an old classic relay scenario inbound shape; 1,171 library/nine binary tests pass, 18 library cases are ignored for separately required fixture/live gates. All 13 new classic runtime, five configuration and four wrapper regressions pass. Check/debug/release pass; CLI/docs are skipped. Keep these scoped successes distinct from an all-green revision. Full metadata/logs and classic artifacts: `/data/data/com.termux/files/usr/tmp/opencode/combined-1c938da/`.

## Latest validated checkpoint: 1f3ccf7

Exact Rust source `1f3ccf7a9dce9c74be49c6653e8c1dbfbfe81e73` passes Rust CI **45902294727**: locked all-target check, debug/release builds, **1,183 library passed / 0 failed / 23 ignored**, **9 binary passed**, **15 built-CLI comparisons / 21 argument-error checks**, and the documentation command (zero runnable cases). The separate mandatory native relay gate executes **8/8 tests, zero ignored**; these eight are also included in the ordinary library total. Relay network-selection and socket-release configuration assertions execute successfully.

Protocol workflow **45902294649** passes strict all-target Clippy and **22 selected live tests, all executed, zero ignored**: REALITY 3, WireGuard 8, Hysteria 2, mKCP 2, SS2022 2, classic Shadowsocks 5. The new classic groups cover four AEAD methods, **96 exact positive request/reply pairs** and **eight wrong-password TCP rejection attempts**. Eight empty Go-client UDP pairs use exported production UDPReader/UDPWriter because the pinned Process copy path drops empty buffers; the other 88 use production Process handlers. UDP authentication negatives, multi-user classic, UOT/mux, nonplain classic transports/security and upstream TCP high-bit address flags remain outside this acceptance.

Classic byte workflow **45902296973** passes the one required Rust trait comparison and Go production reverse decoding across four methods and TCP/UDP. Downloaded evidence confirms both full source commits and all **three JSONL artifact SHA-256 hashes** (four records per file). Native SS2022 relay has now passed compiled runtime, bounded-route/lifecycle, frozen-Go-byte and configured-network tests; **live multihop relay Go acceptance is still pending**. Existing two SS2022 live groups revalidate five non-relay configurations per direction and 60 pairs; this does not establish live SS2022 TCP/relay or full option parity.

The unchanged Mux source/tests retain the separate 31b56a3 probe **45901766900** (five expected old-runtime failures, sixty fixed-source passes); it is prior exact-revision evidence, not a new probe at 1f3ccf7. Unfinished Gun transport/configuration and live relay helper source remain excluded. The latest all-green scoped integration checkpoint is 1f3ccf7; full Xray-core parity remains unestablished.

A subsequent read-only lifecycle review found that a retained, already-polled pending native accept future can hold cloned UDP/TCP socket references after handler close returns. The passing gates above do not cover this condition. A common native socket-storage correction and retained-future regressions are in progress, with an isolated Linux old-runtime-red/fixed-runtime-green probe prepared. This source finding is not an executed failure yet; immediate rebind under that condition remains unvalidated.

A following source candidate replaces cloned listening sockets with revocable, poll-scoped storage in both classic and SS2022 native listeners and serializes UDP writers. Three new nonignored regressions retain a polled pending accept through close and immediate TCP/UDP rebind: classic (four methods), SS2022 endpoint (three methods), and SS2022 relay (two AES methods). The original classic runtime cases and all eight relay cases remain byte-for-byte intact. Required Linux gates increase the relay module to ten and independently require the classic regression. Isolated probe workflow `14b9ee3164d0ad3a1e39f010ba0e43cc208cba16` overlays both old native runtimes for fifteen expected failures, then restores the candidate for thirty selected passes plus the full ten-test relay module. The source has not yet compiled or executed; no result is implied for this candidate. Gun and new live multihop helper source remain excluded.

Evidence: `/data/data/com.termux/files/usr/tmp/opencode/combined-1f3ccf7/`, including exact-SHA job summaries, full logs, verified classic artifacts and `scoped-interop-reference-evidence.json`.

## Follow-up native socket candidate: 60a0df2

Rust CI `45903940071` at `60a0df20d755a394fc0db29593ae40ae1c09406f` passes locked checking, debug/release builds and nine binary tests, but ordinary library selection reports **1,185 passed / one failed / 23 ignored**. The failed new endpoint regression calls the pre-existing AES-only relay configuration helper for its ChaCha20 endpoint iteration and panics `relay is AES only`. The following correction constructs the endpoint configuration directly while preserving all three ciphers, both port-rebind assertions, and the original eight relay tests. Required relay/classic/CLI/docs steps after the failed suite are skipped and earn no execution credit.

Isolated probe `45903977966`, workflow `14b9ee3164d0ad3a1e39f010ba0e43cc208cba16`, proves the actual old-runtime socket failure **15/15 times** across classic, SS2022 endpoint and SS2022 relay. On restored 60a0df2 source, classic passes ten selected invocations and relay passes ten; all ten endpoint invocations and the full relay module fail on the same ChaCha20 test setup, so the probe correctly fails (**20/31 fixed-source invocations pass**). Preserve this failed artifact as evidence; do not promote 60a0df2. Classic byte run `45903939973` passes its required trait test and production Go reverse decoding, and all three downloaded JSONL hashes/source pins match. Protocol/Clippy results are recorded separately when complete.

No production socket code changes in the next correction; Gun and live multihop relay candidates remain separate pending integration. Latest fully passing scoped source remains 1f3ccf7.

## Previous validated checkpoint: 31b56a3

Exact tested Rust source: `31b56a3e27e53da35b351025e120d5e71437f76b`. Rust CI **45901728795** passes locked all-target check, debug/release builds, **1,175 library / 9 binary tests**, **15 built-CLI comparisons / 21 argument-error checks**, and the documentation command (zero runnable cases). Ordinary library selection reports 18 ignored; these are not counted as executed passes. Protocol workflow **45901728777** passes strict all-target Clippy and **17 selected live tests**, all executed with zero ignored: REALITY 3, WireGuard 8, Hysteria 2, mKCP 2, SS2022 2. Classic independent-byte workflow **45901730474** passes its one mandatory Rust trait test and Go production reverse decoding for the four AEAD methods across TCP/UDP.

Mux probe **45901766900**, workflow revision `104b578ce898f67b1b21e78dff407faa156ba2e8`, checks out the exact 31b56a3 source. Its old-runtime comparison (`1c938daac7a3105f64e8cc26c11e2dbe2cfcdc54` runtime under the strengthened regression) fails as expected **5/5** times. Restored fixed source passes **60/60 invocations**: ten EOF regressions, ten exact open-peer BrokenPipe regressions, and forty original concurrent TCP/UDP payload/metadata/close scenarios. Each paired regression executes 64 internal scenarios. No assertions, strict joins or timeouts were weakened. This supersedes ccaffb0's failed open-peer probe and promotes 31b56a3 to the latest fully passing scoped integration checkpoint; it does not establish full Xray-core parity.

Next source integration registers five classic live groups (four AEAD methods, 96 positive request/reply pairs, eight wrong-password TCP attempts) and eight native AES SS2022 relay regression tests, plus network-selection/socket-release acceptance. Classic live files passed a limited read-only source review; helper compilation and execution remain pending. Eight empty Go-client classic UDP pairs use exported production UDPReader/UDPWriter because the pinned Process path drops empty buffers; UDP authentication negatives are outside this gate. Native relay source has bounded cached routes and lifecycle/independent-byte coverage but has no inherited compilation, runtime or live-peer acceptance. Both new groups require nonempty Linux gates. Unfinished Gun transport and new live relay helper files remain excluded from this source integration.

Evidence: `/data/data/com.termux/files/usr/tmp/opencode/combined-31b56a3/`, including exact-SHA job summaries, complete logs and downloaded Mux per-invocation artifact. Earlier sections below are historical revision-scoped records.

## Follow-up execution: ccaffb0 and Mux supervisor race

Source `ccaffb033487d0075da64b6df40dc8007107f9c4` passes Rust CI 45901191650: **1,175 library / 9 binary**, no failures, 18 ordinary ignored, locked check/debug/release, 15 built-CLI comparisons, 21 argument/error checks and documentation command (zero runnable cases). Protocol 45901191660 passes strict Clippy and **17/17** live cases; classic byte workflow 45901193171 passes its required trait test and reverse Go decoding. The earlier classic scenario and concurrent Mux case both pass in the ordinary suite.

Additional isolated probe 45901313190 prevents promotion: with unchanged ccaffb0 source, the strict open-peer BrokenPipe regression fails **4/10** times, while concurrent payload/metadata/close passes **40/40** and the clean-EOF regression **10/10**. Injecting the old 1c938da runtime beneath the new single-attempt EOF test produces **4/5** expected BrokenPipe failures and one pass, so this first fixture is red-capable but not deterministic. Its 60 patched-source invocations therefore give 56 passes, four failures; the probe is correctly FAILED. Baseline unmodified-source probe 45900794913 separately reproduces the original concurrent BrokenPipe **7/40** times.

A follow-up source correction prioritizes the I/O driver and, on a channel-derived Ok/Closed result, awaits its authoritative completion before cleanup. This addresses channel closure becoming visible on another worker before the task result is joinable. Paired regressions now run 64 scenarios each; the open-peer test uses two workers and requires exact BrokenPipe. This follow-up is source-only pending a new exact-revision Linux run; no failure is waived. Other lane sources remain excluded. Evidence: combined-ccaffb0/ and combined-1c938da/mux-close-probe/ under the approved evidence directory.
