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
