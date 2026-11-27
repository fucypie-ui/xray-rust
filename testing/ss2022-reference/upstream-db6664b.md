# SS2022 source audit: Go db6664b against accepted Rust 3f16a55

Research date: 2026-11-27. **Source deductions and proposed verification only. No production patch, reference migration, new fixture, build, test, runtime measurement or new interoperability result is delivered by this note.** The accepted Go reference remains `67756b3`; db6664b is a review candidate. The new note is explicitly excluded from the statsquery snapshot until separate review.

## Authority and scope

| Authority | Exact pin / identity | Role |
| --- | --- | --- |
| Old Go reference | `67756b3674d56b72c7a7e675e8dcd3f883e1b2f7` | Baseline for immutable old/new comparison. |
| Reviewed Go change | `db6664bd689ea5b5933cc4ab9a686b0ee01a178c` | SS2022 refinements/fixes; all ten changed SS2022 paths below. |
| Actual adjacent Go HEAD, start | `4d0bfb4d0d543f9efa4efcc5301d715c5c6ec768` | Clean read-only checkout; HEAD is later than the reviewed SS2022 pin. |
| Accepted Rust | `3f16a550980f050e5dfb80bd141f181e9d15dc00` | Sole Rust implementation/evidence authority; read through exact git-show snapshots, never unfinished working-source files. |
| Existing engine | `shadowsocks-crypto 0.8.0`; crate VCS `2ac3f4f6194476ff7b7be2a43c3a83e33510663b` | Preserve the accepted engine and adapter seams. |

The cached commit metadata identifies db6664b as “SS2022 proxy: Refinements & fixes (#7488)” and closing issue #7486. The immutable old/new diff contains exactly ten SS2022 paths, **367 insertions / 257 deletions**; the complete diff, per-file numstat and all twenty old/new file snapshots are retained in the cache. The separate actual-HEAD/latest-history, DialSystem and issue #7479 lanes belong to the parent and are not audited here. Local observations and hashes are in `audit-observations.json` and the final `delivery-receipt.json` described below. [reviewed Go commit][S21]

The crate archive was acquired as source only. Its SHA-256 is `b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5`, matching the accepted lockfile and official version metadata. The accepted dependency disables default features and enables `v2`. Source extraction, text inspection and hashing do not constitute engine execution. [manifest dependency][S22] [locked engine][S23] [official version metadata][S24] [published crate VCS record][S148]

## Triage of every changed SS2022 path

Paths are relative to `proxy/shadowsocks_2022/`. Counts are added / deleted lines, not a risk score.

| Path | + / − | Classification and significance | Immutable sources |
| --- | --- | --- | --- |
| `inbound.go` | 12 / 18 | Constructor supplies one user to the server codec; decode now returns its committed session. Removes the second user-initialization step. Behavioral authentication/state change lives in the codec; caller/API refactor here. | [old][S01] / [new][S02] |
| `inbound_multi.go` | 26 / 76 | Moves AES multi-user UDP decode and response encoding into UDPMultiServerCodec; lookup callback supplies account/key. Removes early session allocation from this caller and requires a client header. Behavioral fix plus extraction. | [old][S03] / [new][S04] |
| `inbound_relay.go` | 5 / 7 | Locks the entire read/check/initialize of session.User. Previously an unlocked initial read preceded the locked write. Synchronization fix; relay framing and endpoint-authentication limitations remain. | [old][S05] / [new][S06] |
| `outbound.go` | 3 / 3 | UDPCodec field/constructor becomes UDPClientCodec/NewUDPClientCodec. Client/server role split; no independent wire change in this file. | [old][S07] / [new][S08] |
| `packet.go` | 278 / 133 | Role-specific codecs, noncreating lookups, post-validation Commit, authenticated client transitions, replay commit locking, empty-key-list error, DNS padding budget and ChaCha server-init retry cleanup. Main behavioral delta. | [old][S09] / [new][S10] |
| `relay_test.go` | 4 / 3 | Adapts server constructor and three-result DecodePacket calls. No new test cases in this diff. | [old][S11] / [new][S12] |
| `replay.go` | 23 / 7 | Adds noncreating Get and locked Commit with identity/replay recheck, key/cipher/user cache and activity update. Window arithmetic is unchanged. | [old][S13] / [new][S14] |
| `shadowsocks_2022.go` | 9 / 3 | EnsureLink detaches per-connection cancellation and shallow-copies inbound metadata before assigning its user. Session lifecycle and metadata-isolation fix. | [old][S15] / [new][S16] |
| `shadowsocks_2022_test.go` | 6 / 6 | Constructor and decode-result adaptations only. Existing tests remain; no regression cases added by these hunks. | [old][S17] / [new][S18] |
| `stream.go` | 1 / 1 | Allocates space for exactly len(pskList)-1 EIH blocks instead of len(pskList). Allocation-size correction; actual emitted EIH loop and write length do not change. | [old][S19] / [new][S20] |

## Old Go / new Go / Rust seam / remaining proof

| Concern | Old Go 67756b3 | New Go db6664b | Accepted Rust seam | Remaining proof / bounded action |
| --- | --- | --- | --- | --- |
| AES endpoint session allocation | Single-user decoder and multi-user caller create session/replay-window state before body AEAD. | Get is noncreating; derive a transient cipher if needed; authenticate, parse timestamp/address, require client type, then GetOrCreate and Commit. | Server and MultiUserServer authenticate before locking/inserting into ServerUdpSessions. | No equivalent structural allocation fix is indicated for Rust. Prove rejected junk cannot grow endpoint state or refresh activity. [old single decoder][S25] [old multi caller][S26] [new single decoder][S27] [new multi decoder][S28] [Rust single ordering][S29] [Rust multi ordering][S30] |
| Replay atomicity and window | Separately locked check and add permit duplicate decodes to pass the check concurrently. | Commit rechecks and adds under one session lock; client state also has a locked commit. The 128 × 64-bit ring and 8,128 inclusive lookback are unchanged. | Mutable SlidingWindow::check_and_add under endpoint/session ownership or mutex. | Preserve Rust sequencing; add concurrent duplicate delivery and exact ring-edge tests. Do not claim whole-Go race freedom from these locks. [old replay methods][S31] [new replay state][S32] [new client commit][S33] [Rust window][S34] |
| Client receive state poisoning | AES may create/rotate server state from a decrypted but unauthenticated header; ChaCha transitions before validating parsed direction/client binding. | Lookup has no transition; authentication, parsing, server type and client-session binding precede creation/transition. New transitions serialize and recheck. | ClientUdpSession::decode_at authenticates and checks binding before transition. | Retain this protection; prove tampered/high-ID/new-session responses cannot change current/old state or consume a valid ID. [old client decode][S35] [new transition][S36] [new client decode][S37] [Rust client decode][S38] |
| Expired old server slot | Rejecting an old session older than 60 seconds clears the old slot. | Rejects it while retaining the old state/window. | Rust still assigns self.old = None on this rejection. | Candidate P2: retain the slot, with repeated expired-session attempts and third-session timing tests; change the old expectation/comment together. [old slot clearing][S39] [new slot retention][S40] [Rust expired-old branch][S41] [old rotation expectation][S42] |
| DNS padding and wire size | If port 53 and payload <900, chooses padding 1..900 independently of payload. | Chooses 1..(900−payload length); payload + padding ≤900. | ClientUdpSession::encode still uses 1..900. | Candidate P1: narrow only the random range. Retain the final 8,192-byte wire bound and test 0/1/899/900/901 payloads. [old DNS padding][S43] [new DNS and length checks][S44] [Rust DNS padding][S45] |
| Multi-key response format | Multi-user response wrapper already uses the selected user PSK, not the master key. | Response encoder moves to UDPMultiServerCodec; the session encoder still emits no response EIH and uses the supplied user key. | ServerUdpSessions::reply_at constructs PacketCodec from the stored final key only; response EIH count is zero. | Preserved behavior, not a newly invented wire change. Prove final-key response decryption through both relay hops in both directions. [old response wrapper][S46] [new multi response call][S47] [new response encoding][S48] [Rust response key][S49] [Rust response EIH rule][S50] |
| Cached identity / account changes | Multi-user sessions already cache user/key once established. | Reuses cached user/key/cipher; cold lookup only, plus pointer-identity conflict rejection in Commit. | MultiUserServer resolves EIH/account every packet; ServerUdpSessions binds key bytes and returns stored user metadata. | Account removal and duplicate-key alias changes can differ; keep the existing rejection-after-removal policy pending an explicit compatibility decision. Test warm/cold same-ID collisions. [old identity caching][S51] [new cached identity][S52] [new identity commit][S53] [Rust account indices][S54] [Rust key binding][S55] |
| Rebinding / per-connection cancellation | EnsureLink inherits the first connection context and mutates the inherited inbound pointer. | Session context uses WithoutCancel plus its own cancellation; copies inbound metadata before setting User. Authenticated endpoint decode still gates UpdateConn. | Authenticated accept_at updates remote only after identity/replay checks. Native flows own SessionContext values, cancellation and reply tokens. | Prove cancelling old peer processing does not kill a valid migrated association; retain handler/listener close and socket revocation. [old link context][S56] [new link context][S57] [new endpoint rebinding][S58] [Rust native flow creation][S59] |
| Relay initialization and trust boundary | Session user initialization has an unlocked read. Relay routes by encrypted header/EIH, not final body authentication. | Locks read/check/write. Still cannot verify the downstream body AEAD. | RelayServer removes one identity layer; bounded RelayListener retains initial route metadata and updates the physical reply peer. | Exercise parallel first packets and ID/identity collisions. Endpoint junk-memory criteria must not be applied as though the relay possessed the final secret. [new relay initialization][S60] [Rust relay framing][S61] [Rust relay route ownership][S62] |
| Wall clock / replay lifetimes | Wire timestamps use wall time; UDP session ages use Unix seconds; old/current rule uses 60s; endpoint cleanup uses 500s and insertion-triggered checks after >30s. | Same clock model and cleanup policy; Commit updates LastActive. | Timestamp abs_diff ≤30; UDP ages use saturating_sub, 500s session retention and lazy cleanup; TCP replay uses monotonic Instant and two bounded generations; native flow idle uses Instant. | Test +/−30/31 wire timestamps, 59/60/61 old-slot ages, 499/500/501 endpoint ages and backward clocks. Do not blindly substitute Go signed/float arithmetic. [Go timestamp parser][S63] [Go session cleanup][S64] [Rust UDP lifetime][S65] [Rust timestamp arithmetic][S66] [Rust TCP replay generations][S67] |
| Nonces and exhaustion | TCP has an incrementing 96-bit nonce; AES UDP derives nonce from raw header bytes 4..16; ChaCha UDP uses an explicit 24-byte random nonce. | Same nonce design; no separate nonce-algorithm fix appears in these hunks. ChaCha server initialization now resets ServerSessionID on cipher-construction error to permit retry. | Existing 0.8 engine takes immutable UDP nonce slices, mutates local body buffers; adapter guards TCP failure/exhaustion and UDP checked packet IDs. | Keep engine, terminal decrypt failure, checked counters and local copies; add corrupt-then-valid UDP/input immutability and TCP failure tests. Do not copy Go atomic counter wrap. [Go nonce and init paths][S68] [Rust packet buffer ownership][S69] [Rust TCP failure guard][S70] [Rust UDP counter guard][S71] |
| Bounds and TCP allocation | Existing client request encoders calculate full wire size; TCP allocates one surplus EIH block. | UDP client still checks total wire ≤buf.Size; server/client decode outer minima are preliminary checks, followed by authenticated parsing. TCP allocation subtracts one EIH block. | PacketCodec rejects wire >8,192 with checked body/address reads; Vec-based TCP appends actual EIH entries. | Preserve stronger Rust bounds and oversize rejection; cover complete wire lengths and malformed authenticated bodies. No framing rewrite is warranted by the allocation hunk. [Go regular buffer size][S72] [Go TCP write sequence][S73] [Rust bounded packet decoder][S74] [Rust TCP EIH appending][S75] |

## Behavioral conclusions and patch boundaries

### Authentication and retained memory

The AES issue is concrete in source: old GetOrCreate allocates ServerUDPSession plus its 128-word replay ring before AEAD, so randomized untrusted headers can leave persistent map entries after body rejection. New single/multi AES decode keeps unauthenticated work transient, validates body/timestamp/address/direction, then commits an authenticated packet to state. ChaCha previously authenticated the outer ciphertext before session creation, but created state before the remaining parsed-header/type checks; it now finishes those checks first. The replay ring alone occupies 1,024 bytes of uint64 storage; this is a source-level storage calculation, not a heap benchmark. [old allocating manager][S76] [old ChaCha ordering][S77] [new endpoint ordering][S78]

Issue #7486 is an upstream reporter's experiment. Its roughly 148 MB retained-heap result after 100,000 random 48-byte datagrams is **not a measurement made here**, and the full report/configuration is intentionally not copied. The selected metadata records the parent-cache SHA-256 and original issue URL. The fix assessment above comes from the immutable implementation, not from treating the report's benchmark or claimed tests as local evidence. [upstream issue metadata][S79]

Rust already avoids this unauthenticated session-map insertion and caps authenticated endpoint sessions at 65,536. It is nevertheless not a claim of zero allocation on junk: decoding can allocate transient cipher/body buffers. Its native layer separately limits 256 flows, 32 queued packets per flow and 64 peer addresses. Preserve these protections. Authenticated-state retention is lazy: the endpoint map cleans on later accepted traffic (or handler drop), not a guaranteed independent timer. Handler/native close revokes sockets, but does not itself prove that every cached endpoint session is immediately deallocated while the handler is retained. New Go's manager also has no hard session-capacity limit here and its cleanup is triggered on new insertion; the change does not bound arbitrary authenticated session creation. [Rust session cap and cleanup][S80] [Rust native limits][S81] [Rust flow admission][S82] [Go lazy cleanup][S83]

Avoid the broader assertion that every rejected new-Go packet leaves all activity untouched: GetOrCreate refreshes existing LastActive before a later Commit can reject (notably the authenticated ChaCha duplicate path and concurrent creation cases). The warranted fix is no persistent session allocation from an unauthenticated AES body, plus serialized replay commits. Rust's key/replay checks precede remote/last_seen mutation; test and retain that stronger sequence. [Go creation/activity ordering][S84] [Go ChaCha commit caller][S85] [Rust replay and remote ordering][S86]

### P1 — narrow DNS padding adjustment

Proposed production scope: only ClientUdpSession::encode's DNS padding upper bound, from MAX_PADDING_LENGTH to MAX_PADDING_LENGTH−payload.len(), under the existing payload.len()<MAX_PADDING_LENGTH guard. Keep encode_at deterministic and capable of accepting explicit caller-supplied padding; do not globally prohibit decoders from accepting larger valid padding. Candidate tests should check port 53 with payload lengths 0, 1, 899, 900 and 901 for each method; require positive padding only below 900, sum ≤900 there, zero at/above 900, and no automatic padding for other ports. Exercise the real random-padding branch repeatedly for its range invariant, not an exact random byte expectation. This remains a proposal; no padding code or tests were changed. [padding seam][S87] [new Go range][S88]

### P2 — retain an expired old-server slot when rejecting it

Proposed production scope: remove only self.old = None from the >60s old-slot rejection. Source deduction: with A old and B current, a fresh authenticated A packet at age 61 is rejected by Rust but clears A's replay/identity slot; an immediate repeat can then be treated as a new server session and pass a newly empty window. New Go keeps rejecting A while its old slot remains. This does not mean a packet older than the ±30s wire window can bypass timestamp validation: construct a fresh timestamp for the expired *session*, and test the repeated packet at the same now. No exploit execution is claimed. [Rust clearing branch and transition][S89] [new Go retention rule][S90]

Update ss2022_udp_server_session_rotation_and_authentication_before_mutation's final assertion and comment together: the accepted test currently expects the cleared slot to allow another rotation. Add all-method 59/60/61 boundary tests, repeated expired-old packets, current-session continuation, a third ID, invalid-tag/wrong-client responses, and exact preservation of replay state after rejection. At age exactly 60, the old session remains eligible (>60 expires) while the third-session guard (<60 blocks) permits a transition; preserve that boundary rather than rounding it. [existing test requiring revision][S91]

### P3 — retain existing Rust authentication, engine and lifecycle ownership

No production rewrite is indicated for the Go codec split, Commit helper extraction, relay user locking or TCP allocation correction. Rust's mutable/mutex seams already provide serialized state mutation; inbound metadata is constructed as owned SessionContext values. The Go lifetime fix requires **behavioral verification**, not removal of Rust cancellation. Keep listener/handler close, task-drop cancellation, generation-bound reply tokens, checked UDP IDs and terminal TCP AEAD failure. Existing native tests cover replay/rebinding/drop/close shapes and must be extended or rerun against the candidate pin, without claiming that source presence proves execution. [native replay/rebinding test source][S92] [native close ownership][S93] [generation-bound reply state][S94] [relay close test source][S95]

The engine is not a reason to replace the adapter. Published 0.8 UDP AES derives its session subkey from PSK+big-endian session ID and accepts an explicit nonce slice; ChaCha UDP uses XChaCha20Poly1305 with an explicit nonce slice. The v2 crypto files include the corresponding v1 primitive implementation; those included files are cached too. PacketCodec decrypts into owned vectors and passes immutable wire-derived nonce slices, so failed UDP authentication must not mutate caller wire/nonce or advance a hidden per-packet nonce. By contrast, TcpCipher advances its internal nonce even on decrypt failure; CipherState marks that failure terminal. Preserve that distinction and test corrupt-then-valid UDP separately from terminal TCP. [engine UDP AES][S96] [engine UDP ChaCha][S97] [v2 included primitive][S98] [published primitive ownership][S99] [engine TCP progression][S100] [adapter terminal failure][S101]

The stream.go hunk corrects requested allocation by sixteen bytes for any valid nonempty PSK list; it does not remove sixteen emitted bytes. Both versions write only len(pskList)−1 EIHs and finally write handshakeBuf.Bytes(), whose length tracks appended bytes, not unused allocation capacity. Rust already appends actual EIHs to its request Vec. Verify deterministic TCP bytes and boundary allocations later; do not change TCP framing or confuse UDP DNS padding with the unchanged TCP padding policy. [old allocation and EIH loop][S102] [new allocation and final write][S103] [buffer allocation and length][S104] [buffer write length][S105] [Rust EIH request construction][S106]

### P4 — expose identity-policy differences before changing them

Warm Go multi-user sessions already skipped fresh EIH account lookup at the old pin; db6664b preserves that caching, and adds a user-pointer check when committing competing decodes. Rust instead resolves the account each packet and explicitly tests rejection after account removal. Duplicate key aliases share the hash index (latest alias), while email indices retain aliases; existing Rust session state stores the first user and compares key bytes, not account-pointer identity. Required comparison cases: remove/readd a live account, duplicate-key aliases with changed metadata, same client ID under different keys, concurrent first packets resolving different users, and mutations before/after session expiry. These are not authorization to weaken Rust revocation, add warm-session bypasses or promise identical user attribution. Decide any intentional divergence only after the new-pin evidence. [Rust removal regression][S107] [Rust alias policy][S108] [Go user pointer guard][S109]

Wire freshness and state retention must remain distinct. Rust uses unsigned abs_diff for the wire timestamp and saturating_sub for UDP ages; a wall-clock rollback can retain old state longer rather than turn a negative age into a large expiry. Go uses signed Unix-second subtraction (and float absolute value for wire timestamps). Include extreme encoded timestamps and forward/backward clock steps in deterministic seam tests; do not copy signed overflow behavior. Rust TCP replay rotation is lazy: it shifts at most one generation when checked after a 60-second interval, so two generations are not an unconditional 120-second garbage-collection deadline after a long idle gap. Native idle ownership instead uses monotonic Instant. These policies are not changed by the reviewed Go diff. [Rust timestamp arithmetic][S66] [Rust UDP lifetime][S65] [Rust TCP replay generations][S67] [Go timestamp parser][S63] [Rust native flow creation][S59]

### Packet bounds to preserve

Go PacketMinimalHeaderSize=30 is an outer filter, not the minimum complete valid client/server datagram; the multi-user outer minimum is 2×16+16+11=59, likewise before the address requirement. ChaCha additionally checks nonce+tag before opening and then checks plaintext. Valid empty-payload packets still need address/header/tag bytes. The parser checks direction, ±30s timestamp, optional client binding, padding extent and address extent; the client binding check is done by client decode. Rust's stateless decoder does not itself enforce replay; the session types do. [Go size constants][S110] [Go multi preliminary bound][S111] [Go authenticated parser][S112] [Rust parser and state division][S113]

For unpadded IPv4, source-calculated complete minima are AES client 50 bytes, AES server 58, AES multi-client with one EIH 66, ChaCha client 74 and ChaCha server 82; add EIHs and longer addresses to actual wire overhead, not the payload allowance. Test below/at each complete minimum, every address truncation, authenticated impossible padding, and wire lengths 8,191/8,192/8,193 for each role/address family. New Go retains fixed regular buffer size 8,192 for client output. Its server encoder still writes into fixed buffers without checking every payload Write result and has no analogous final client-style total bound in that function; Rust should continue rejecting oversize output rather than copying truncation. There is no new universal decoder upper-bound guarantee implied by this diff. [Go request total bounds][S114] [Go server body writes][S115] [Go fixed buffer write contract][S116] [Rust final wire bound][S117]

## Why existing helpers and evidence are insufficient for db6664b

| Existing material at accepted Rust | What it actually establishes from source/provenance | Why it is insufficient / bounded next work |
| --- | --- | --- |
| Original AES vectors and reference_test.go | Two frozen AES records; original fixture SHA-256 af1b7f607dba629ba63ac306fc8594a1e8b751d0185050053aa7d648e29c7aeb. Helper constructs deterministic crypto/framing bytes. | Preserve verbatim. They do not execute new session allocation/Commit, lifecycle, ChaCha or live traffic. [original helper][S118] |
| Extended vectors/helper | Three cipher records at port 443. Production writers plus normalization replace random wall time, ChaCha nonces and TCP response salt; helper directly seeds private session/server IDs and AES ciphers. | Does not exercise DNS random padding, real clock boundaries, nonce freshness, inbound Commit, junk retention, concurrency or live relay routing. Preserve original files; a later isolated new-pin generator needs separate outputs/provenance. [normalization][S119] [generation scenarios][S120] |
| Frozen extended provenance | Old Go 67756b3, generator 584cd1332f414592687c552452bad634cef989cc, workflow run 45892518463, job 140158378278, artifact 15152217167, Go go1.27.4 linux/amd64, three records, SHA-256 349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0. | Provenance explicitly says no live Rust interoperability result; it cannot be relabeled db6664b. [frozen provenance][S121] |
| Both live peer builders and Rust event checks | Builders archive exact old pin into scratch; nonrelay and relay helper JSON plus Rust assertions also embed 67756b3. | Simply supplying a new checkout fails the pin gate. Retain old builders/evidence; propose separate candidate-pin peers and synchronized event assertions. [nonrelay builder][S122] [relay builder][S123] [nonrelay reference constant][S124] [relay reference constant][S125] |
| Live nonrelay tests | Source defines two ignored selected tests, five configurations per direction, 60 exact request/reply pairs. Nonempty Go outbound uses Process; empty pairs use UDPWriter/UDPReader and explicit session-labelled events. | This is coverage design, not a new run. Reexecute all five per direction at db6664b; ensure no filtering/skip can count as success and add the rejected-packet/state observations below. [nonrelay selected suite][S126] [Go empty boundary][S127] |
| Live two-relay tests | Two ignored tests, four AES/final-role configurations per direction, two real relay hops; 48 exact request/reply pairs and hop byte traces. | Reexecute both directions with new pin. Empty/rebinding traffic is session API traffic, not full outbound-handler proof. No ChaCha relay is supported. [relay selected suite contract][S128] [two-hop Go-client checks][S129] [reverse relay test][S130] |
| Native/configuration tests | Accepted source covers native traits, replay/rebinding, queue/flow limits, drops/close, frozen Go bytes at fixture time, configured network/role selection and authenticated TCP/configuration routing. | Codec/unit evidence and direct constructors do not prove new-Go configured-root interoperability. Preserve and reuse tests; add a configured-root packet path for candidate pin. [frozen native fixture boundary][S131] [configuration packet selection][S132] [configuration authenticated handlers][S133] |

The exported client helper surface is **not automatically broken** by the role split: NewUDPPacketCodec remains as a forwarding compatibility constructor returning UDPClientCodec, and the accepted peers use inferred types plus unchanged NewClientSession/UDPWriter/UDPReader calls. The extended generator's private fields used for normalization are still present. Conversely, external consumers explicitly naming UDPCodec, invoking its old two-result server DecodePacket, constructing NewUDPServerCodec without the new user argument, or calling removed DecryptAESPayload need adaptation. The two changed upstream test files demonstrate those constructor/result adaptations, not new regression coverage. Build compatibility is a source-based expectation only; it has not been compiled here. [new compatibility constructor][S134] [extended helper private seams][S135] [peer exported session seam][S136] [upstream test adaptations][S137]

Do not run the accepted generators against the protected adjacent checkout: both copy a temporary test file into the supplied Go source directory before go test and remove it on exit. A later authorized Linux proof must use a disposable exact-pin source tree, distinct output directory and retained generator source/hash; this note authorizes no execution. Both accepted workflows still select the old Go pin. The protocol workflow explicitly selects ignored nonrelay/relay tests with a minimum of two each; workflow source alone is not a successful run. The README contains earlier historical “no live SS2022 gate” prose, so do not use it to override the later accepted live-test/workflow source or invent a latest CI outcome. [original generator writes][S138] [extended generator writes][S139] [live workflow selection][S140] [live workflow Go pin][S141] [fixture workflow pin][S142] [historical README qualification][S143]

## Required new pinned-Go Linux evidence before compatibility credit

This is a proposed acceptance matrix, **not results**. Keep Go review authority fixed at db6664bd689ea5b5933cc4ab9a686b0ee01a178c; do not use the adjacent later HEAD as an implicit substitute. Record the exact reviewed Rust test/implementation commit (accepted 3f16a55 if unchanged, or a separately reviewed follow-up), accepted base, engine lock/checksum, helper/generator hashes, compiler versions, Linux architecture, commands, test counts, case counts, fixture hashes and raw artifact checksums. Preserve all old proofs and manifests; new evidence needs a distinct name and lineage.

| Gate | Required cases and observations | Evidence boundary / rejection conditions |
| --- | --- | --- |
| L1 Nonrelay live UDP | Both directions; AES-128 single, AES-256 single, ChaCha single, AES-128 multi and AES-256 multi. Retain six exact request/reply pairs per configuration, empty and nonempty payloads, per-packet destination/source metadata, user/level, one-vs-two session counts and close checks. | Baseline minimum: two selected tests actually executed, ten configurations, 60 pairs. Empty Go outbound session APIs must stay explicitly labelled; no helper absence, zero selected tests or skipped cases count as success. |
| L2 Two-hop AES live UDP | Go client → two Rust relays → Go final single/multi endpoint; reverse Rust client → two pinned-Go relays → Rust final endpoint. Both AES methods and both final roles per direction. Capture encrypted headers/EIH removal, request bytes and identical response pass-through at every hop; empty pairs with rebinding and final-user key decryption. | Baseline minimum: two selected tests, eight configurations, 48 pairs, actual two-hop topology. State whether handler or session API generated each pair. ChaCha relay/multi remains unsupported; test rejection rather than fabricating a relay case. |
| L3 Rejected requests / memory | Single AES-128/AES-256/ChaCha and AES multi-user. Bounded deterministic corpus of random/truncated bytes, wrong key/EIH/tag, authenticated wrong type, invalid timestamp, impossible padding/address, same-ID wrong identity and concurrent duplicates. Follow every rejection family with valid traffic on the same listener. | Retained endpoint session/window count, replay state, remote, activity and dispatch count must remain as specified; rejected packets cannot consume the next valid ID or rebind a reply. Observe Rust state directly at existing seams with test-only instrumentation if needed; memory measurements must identify allocator/GC/method and be newly attributable. Do not reuse issue #7486 reporter numbers as run data. |
| L4 Rejected responses / rotation | All three single-user ciphers plus AES multi-key final-key replies: corrupt/new/high-ID response then valid response; wrong ClientSessionID/type, duplicates, out-of-order IDs, 59/60/61 old-slot ages, repeated expired-old packet and third-session rotation. | Assert both current/old slot identity and replay contents. At most one concurrent duplicate may be delivered. Deterministic clock tests must actually call the production _at seam; time injection/helper adaptation must be separately reviewed and never become a second wire codec. |
| L5 Window and bounds | IDs 0, 63, 64, ring wrap, inclusive lookback 8,128, rejected 8,129, large jumps, near u64::MAX and checked exhaustion; wire complete minima and 8,191/8,192/8,193 for IPv4/IPv6/domain and every EIH depth. DNS payload 0/1/899/900/901, explicit padding, empty replies and non-DNS controls. | No panic, truncation, replay-window poisoning or counter wrap. Deterministic new vectors complement but do not replace live packets, runtime random-padding coverage or replay tests. Keep stronger Rust fail-closed limits. |
| L6 Migration and lifecycle | Authenticated next packet from a new source migrates endpoint reply remote. Replay/wrong key/tag from a new source does not. Cancel first peer/connection while the association continues; verify fresh replies and unchanged user metadata. Then explicit close, idle expiry, unpolled/dropped/aborted tasks, retained handles and immediate socket rebinding. | Distinguish per-connection cancellation from session/listener ownership. New Go WithoutCancel means helper shutdown must verify detached response workers/links are terminated by explicit ownership/idle close, not just wait for Process to return. Listener/handler close must still revoke Rust sockets. |
| L7 Configured root and account policy | Construct handlers through real Config::build with protocol shadowsocks and explicit UDP selection; all three single-user methods, users/clients AES multi, two-hop relay configuration, JSON default/array behavior and native typed-message adaptation where supported. Include removed/readded users, duplicate-key aliases and same-ID different-key races. | Direct constructors and codec-only tests cannot substitute for configuration/shared-dispatcher integration. Record any intentional Go/Rust revocation/identity policy differences; never claim one-to-one parity while they remain unresolved. |
| L8 TCP/allocation and engine preservation | All methods, AES identity chains, normalized old/new handshake byte comparison, early data/half-close and malformed records; record nonce progression/terminal failure tests through the existing 0.8 adapter. | Verify the sixteen-byte allocation correction does not imply a wire deletion; do not migrate the engine or replace Go framing/EIH with a different stack. New normalized vectors require their own exact pin and generator provenance. |

The configured-root seams are already present: build_2022_inbound selects single/multi/relay, gives clients precedence and defaults omitted JSON network to TCP; build_2022_outbound is a separate factory. The native typed adapter maps SS2022 key to password and users to clients. Existing Config::build tests verify UDP trait selection and network binding, but do not run a new-Go live peer through the full root path. Reuse these factories and native listener/dispatcher boundaries for L7. [inbound configuration factory][S144] [outbound factory][S145] [typed descriptor adaptation][S146] [configured UDP trait test][S147]

After separately authorizing and reviewing candidate-specific helper pins/event assertions in a disposable Linux lane, the later runner should execute the selected nonrelay and relay modules explicitly, alongside the deterministic suite. The module filters below are acceptance proposals, not commands run for this note; their helper environment variables must point to newly attested db6664b binaries, and the runner must fail unless the selected counts in L1/L2 are met.

```sh
# Reviewed Rust candidate checkout on Linux, after candidate helpers exist:
cargo test --locked --lib proxy::shadowsocks_2022::go_peer_test -- --ignored --nocapture
cargo test --locked --lib proxy::shadowsocks_2022::relay_go_peer_test -- --ignored --nocapture
cargo test --locked --lib ss2022_ -- --nocapture
# Separate disposable exact-db6664b Go tree with reviewed regression tests:
go test -race ./proxy/shadowsocks_2022
```

Retain the test listing, exact executed test names and full logs; a successful command exit with zero selected cases is not evidence. New Go regression tests should directly cover rejected-junk state allocation and duplicate Commit races because the two upstream test-file deltas only adapt APIs. No existing workflow or proof is modified here.

## Cache integrity and delivery boundary

Owned repository output: `testing/ss2022-reference/upstream-db6664b.md` only. Owned temporary cache: `/data/data/com.termux/files/usr/tmp/opencode/upstream-db6664b-primary/` only. Existing production/proof sources, workflows, fixtures, checksums, reference pins and all statsquery work remain outside write ownership. No Go/Rust/Cargo command, build, test, formatter, installation, fixture generation, child agent or watcher was run for this audit.

The final source manifest maps each snapshot to its exact pin/path/origin URL, acquisition description, byte count and SHA-256. Rust source URLs follow the read-only observed origin lainzyy/xray-rust; crypto source URLs follow the official metadata repository shadowsocks/shadowsocks-crypto. Public link availability is not substituted for the local immutable git-show/blob and verified crate snapshots. All line references below are checked against the cached source lengths. Complete file snapshots, not selected quotation fragments, are retained.

- `source-manifest.json` SHA-256: **147c5c0f636c66e06e61ea89134491c27d7290d3293a439ffdbffeb59ae870e1**.
- `primary-sources.sha256` SHA-256: **70e1be6eb5d55d0615793169a276287ef9a7fb6c284f93cc05135684a98f74fc**. This index covers all primary snapshots and cache metadata including the source manifest and citation ledger; it excludes itself and the later delivery receipt to avoid recursive hashing.
- `delivery-receipt.json` records this note's final SHA-256, both hashes above, output-ownership comparison and the completion Go HEAD/status read. The note's own SHA is external to its bytes to avoid an impossible self-referential checksum.
- Old AES and extended fixture hashes are independently recomputed from accepted git-show copies in this cache; the crate archive hash is independently checked against Cargo.lock. No prior checksum/manifest is overwritten.

Completion status: **research only; compatibility, regression-free status and parity with db6664b remain unproved**. The final receipt must show Go HEAD equal to the start observation and clean porcelain status. Any live proof or reference migration requires a separate reviewed change.

## Immutable primary references

[S01]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound.go
[S02]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound.go
[S03]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound_multi.go
[S04]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound_multi.go
[S05]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound_relay.go
[S06]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound_relay.go
[S07]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/outbound.go
[S08]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/outbound.go
[S09]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go
[S10]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go
[S11]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/relay_test.go
[S12]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/relay_test.go
[S13]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/replay.go
[S14]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go
[S15]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/shadowsocks_2022.go
[S16]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/shadowsocks_2022.go
[S17]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/shadowsocks_2022_test.go
[S18]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/shadowsocks_2022_test.go
[S19]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/stream.go
[S20]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/stream.go
[S21]: https://github.com/XTLS/Xray-core/commit/db6664bd689ea5b5933cc4ab9a686b0ee01a178c
[S22]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/Cargo.toml#L82
[S23]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/Cargo.lock#L3265-L3273
[S24]: https://crates.io/api/v1/crates/shadowsocks-crypto/0.8.0
[S25]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go#L236-L284
[S26]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound_multi.go#L281-L343
[S27]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L324-L410
[S28]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L142-L214
[S29]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/server.rs#L81-L90
[S30]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/multi_server.rs#L127-L135
[S31]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/replay.go#L100-L119
[S32]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L16-L124
[S33]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L522-L544
[S34]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L7-L26
[S35]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go#L618-L705
[S36]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L581-L620
[S37]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L742-L850
[S38]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L66-L88
[S39]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go#L449-L495
[S40]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L581-L598
[S41]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L67-L88
[S42]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/extended_test.rs#L192-L207
[S43]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go#L502-L519
[S44]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L626-L690
[S45]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L54-L64
[S46]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound_multi.go#L355-L362
[S47]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound_multi.go#L280-L308
[S48]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L412-L519
[S49]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L137-L147
[S50]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/packet.rs#L47-L72
[S51]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/inbound_multi.go#L300-L344
[S52]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L153-L213
[S53]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L106-L123
[S54]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/multi_server.rs#L39-L87
[S55]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L129-L135
[S56]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/shadowsocks_2022.go#L48-L103
[S57]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/shadowsocks_2022.go#L48-L107
[S58]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound.go#L157-L185
[S59]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native.rs#L148-L181
[S60]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/inbound_relay.go#L199-L268
[S61]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_server.rs#L75-L90
[S62]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native.rs#L315-L380
[S63]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L274-L321
[S64]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L126-L187
[S65]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L114-L147
[S66]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/stream.rs#L16-L27
[S67]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/replay.rs#L7-L48
[S68]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L412-L483
[S69]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/packet.rs#L32-L111
[S70]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/cipher.rs#L44-L98
[S71]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L59-L64
[S72]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/common/buf/buffer.go#L10-L17
[S73]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/stream.go#L332-L392
[S74]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/packet.rs#L76-L141
[S75]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/identity.rs#L37-L45
[S76]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/replay.go#L131-L170
[S77]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/packet.go#L196-L233
[S78]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L324-L409
[S79]: https://github.com/XTLS/Xray-core/issues/7486
[S80]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L111-L135
[S81]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native.rs#L1-L31
[S82]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native.rs#L148-L179
[S83]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L146-L187
[S84]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L106-L172
[S85]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L329-L359
[S86]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L129-L135
[S87]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L54-L64
[S88]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L626-L639
[S89]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L67-L88
[S90]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L581-L619
[S91]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/extended_test.rs#L192-L207
[S92]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native_test.rs#L261-L331
[S93]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native.rs#L20-L48
[S94]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/udp_session.rs#L92-L147
[S95]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_native_test.rs#L620-L715
[S96]: https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/src/v2/udp/aes_gcm.rs#L18-L54
[S97]: https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/src/v2/udp/chacha20_poly1305.rs#L1-L27
[S98]: https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/src/v2/crypto/aes_gcm.rs#L1
[S99]: https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/src/v1/aeadcipher/aes_gcm.rs#L123-L193
[S100]: https://github.com/shadowsocks/shadowsocks-crypto/blob/2ac3f4f6194476ff7b7be2a43c3a83e33510663b/src/v2/tcp/mod.rs#L127-L153
[S101]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/cipher.rs#L69-L87
[S102]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/proxy/shadowsocks_2022/stream.go#L332-L357
[S103]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/stream.go#L332-L392
[S104]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/common/buf/buffer.go#L75-L86
[S105]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/common/buf/buffer.go#L244-L252
[S106]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/identity.rs#L37-L45
[S107]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/extended_test.rs#L147-L164
[S108]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/multi_server.rs#L39-L87
[S109]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/replay.go#L106-L123
[S110]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/shadowsocks_2022.go#L155-L165
[S111]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L142-L151
[S112]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L239-L321
[S113]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/packet.rs#L76-L141
[S114]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L626-L739
[S115]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L452-L515
[S116]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/common/buf/buffer.go#L244-L252
[S117]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/packet.rs#L32-L52
[S118]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/reference_test.go#L1-L65
[S119]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/extended_reference_test.go#L20-L76
[S120]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/extended_reference_test.go#L79-L148
[S121]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/testdata/go-extended-provenance.json
[S122]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/build-peer.sh#L8-L30
[S123]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-relay-reference/build-peer.sh#L8-L30
[S124]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/go_peer_test.rs#L17-L31
[S125]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_go_peer_test.rs#L19-L36
[S126]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/go_peer_test.rs#L187-L280
[S127]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/peer.go#L401-L431
[S128]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_go_peer_test.rs#L1-L9
[S129]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_go_peer_test.rs#L367-L425
[S130]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/relay_go_peer_test.rs#L428-L516
[S131]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/native_test.rs#L376-L405
[S132]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/shadowsocks.rs#L709-L834
[S133]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/shadowsocks.rs#L957-L1055
[S134]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/packet.go#L20-L76
[S135]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/extended_reference_test.go#L109-L133
[S136]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/peer.go#L401-L431
[S137]: https://github.com/XTLS/Xray-core/blob/db6664bd689ea5b5933cc4ab9a686b0ee01a178c/proxy/shadowsocks_2022/shadowsocks_2022_test.go#L265-L303
[S138]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/generate.sh#L11-L28
[S139]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/testing/ss2022-reference/generate-extended.sh#L11-L28
[S140]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/.github/workflows/protocol-interop.yml#L45-L56
[S141]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/.github/workflows/protocol-interop.yml#L79-L102
[S142]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/.github/workflows/engine-reference.yml#L41-L52
[S143]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/proxy/shadowsocks_2022/README.md#L3-L10
[S144]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/shadowsocks.rs#L147-L216
[S145]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/shadowsocks.rs#L219-L268
[S146]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/native.rs#L297-L301
[S147]: https://github.com/lainzyy/xray-rust/blob/3f16a550980f050e5dfb80bd141f181e9d15dc00/infra/conf/shadowsocks.rs#L805-L834
[S148]: https://crates.io/api/v1/crates/shadowsocks-crypto/0.8.0/download
