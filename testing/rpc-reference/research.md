# RPC reflection: external engine and dependency feasibility

Retrieved **2026-11-27**. Scope: official reflection protocols and reusable libraries only. This does not map the pinned Xray Go root RPC integration; that belongs to the separate source scout. All recommendations below are unrun design inferences.

## Recommendation and verified dependency baseline

**Prefer the existing h2 + prost + prost-reflect stack**, using existing descriptor bytes and the parent's shared gRPC transport layer. The inspected libraries cover protobuf encoding, dynamic descriptors and HTTP/2; a new protobuf/HTTP/2 codec is not justified. Reflection dispatch, per-stream descriptor state and the actual service registry still require integration. Do not claim full grpc-go parity or a complete gRPC engine from these libraries alone. [H2] [Pool] [Dynamic] [Wire]

Read-only observations from root `Cargo.toml`/`Cargo.lock`: h2 **0.4.21**, http **1.5.0**, prost **0.14.6**, prost-reflect **0.16.5** (`serde` enabled), transitive prost-types **0.14.6**, Tokio **1.54.1**; no tonic/tonic-reflection/tonic-prost package was found. These are manifest/lock facts, not resolution or compilation results.

Official crates.io APIs report the following latest non-yanked stable releases on the retrieval date; selected `versions` records agree with `max_stable_version`. [C-reflection] [C-tonic] [C-codec] [C-reflect] [C-prost] [C-h2]

| Crate | Latest stable | Published (UTC date) | Relation to root |
| --- | --- | --- | --- |
| tonic-reflection | 0.14.9 | 2026-10-29 | Additional dependency; Rust 1.88 minimum |
| tonic / tonic-prost | 0.14.9 / 0.14.9 | 2026-10-29 | Additional dependencies |
| prost-reflect | 0.16.5 | 2026-07-09 | Already locked |
| prost | 0.14.6 | 2026-11-12 | Already locked |
| h2 | 0.4.21 | 2026-11-24 | Already locked |

## Official protocol contract

- Both versions define **bidirectional streaming** `ServerReflectionInfo`: respond as requests arrive rather than waiting for request EOF. Routes are `/grpc.reflection.v1.ServerReflection/ServerReflectionInfo` and `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`. Their defined message fields have matching wire tags/types, but their protobuf package/service identities differ. The canonical v1alpha file is deprecated; that does not remove compatibility clients. [V1] [Alpha] [Wire]
- Request fields: `host=1`; oneof `file_by_filename=3`, `file_containing_symbol=4`, `file_containing_extension=5`, `all_extension_numbers_of_type=6`, `list_services=7`. A present empty `list_services` value is valid; its contents are ignored. Replies carry `valid_host=1`, `original_request=2`, and a result or `error_response` oneof. [V1] [Alpha]
- A file response contains repeated opaque **serialized FileDescriptorProto** values, not serialized FileDescriptorSet values. Resolve filename, symbol or extension to its defining file and include its transitive imports. Previously delivered descriptors may be omitted on the same stream; the design document scopes suppression to stream/valid_host. The document includes historical illustrative schemas: use the canonical protos for current names/tags. [V1] [Protocol]
- Extension-number enumeration is best effort; the schema permits UNIMPLEMENTED when unsupported. An absent extension, a known message with no extensions, and an unknown message need not have the same outcome. [V1] [Go-engine]

## grpc-go upstream reference behavior

This section inspects upstream library snapshot `b78156ea35afe68ada1ef1600e8cd813ac23a45d`, not the root project's integration or its selected grpc-go revision. [Go-register] [Go-engine]

- `reflection.Register` registers **v1alpha and v1**, using a v1 implementation plus conversion adapter; `RegisterV1` registers only v1. Default descriptor/extension resolvers are GlobalFiles/GlobalTypes. [Go-register]
- The handler receives/sends repeatedly. `valid_host` echoes request `host`; `original_request` contains the request, including error replies. Host is not used here to select another resolver. [Go-engine]
- Descriptor traversal is breadth first. **Always resend the requested root**, even if already sent; suppress previously sent imports by file path. The map lasts for the stream and is not partitioned by host. Missing root placeholders yield not-found; imported placeholders are skipped. These are implementation details beyond the optional protocol suppression rule. [Go-engine]
- Lookup failures produce **in-band ErrorResponse NOT_FOUND (5)** and the stream continues. Missing/invalid request variant instead terminates with gRPC INVALID_ARGUMENT (3); receive/send errors propagate, and request EOF ends normally. Do not turn every lookup miss into final error trailers. [Go-engine]
- Service names come from the registered-service provider and are sorted. Extension numbers are sorted; known types with no registered extensions return an empty list, while unresolved names can return NOT_FOUND. Descriptor presence and service registration are separate concepts. [Go-engine]

## tonic-reflection 0.14.9: reusable, with material limits

Inspected release tag `tonic-v0.14.9`, dereferenced commit `4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70`. [T-tag]

| Concern | Inspected behavior / consequence |
| --- | --- |
| Streaming and host | v1/v1alpha handlers process streamed requests; successful replies echo host and original request. A one-item response channel supplies basic backpressure. [T-v1] [T-alpha] |
| Descriptor closure | Filename/symbol lookup returns **one file only**, with no transitive traversal or per-stream sent-file set. Registering imports makes them separately queryable; it does not make a single reply contain the closure. [T-v1] [T-alpha] |
| Errors | Lookup errors become stream `Err(Status)` and terminate handling; no in-band reflection ErrorResponse is sent. This differs from grpc-go continuation. [T-v1] [T-alpha] |
| Extensions | File-containing-extension returns NOT_FOUND/unsupported. All-extension-numbers returns a default empty response, including empty base_type_name, without checking the type. [T-v1] [T-alpha] |
| Advertisement | Builder defaults to all services in supplied descriptors, not the live router. `with_service_name` supplies an explicit list. Build v1 and v1alpha separately and register both routes when desired; each build auto-includes only its own reflection descriptor by default. [T-builder] |
| Descriptor options | The encoded-set registration path preserves raw per-file bytes/custom options; decoded prost-types sets have already lost unknown options. [T-builder] |

Its state/index is private and the public engine is tied to Tonic streaming/service types; it is not a transport-neutral resolver to plug directly into h2. Even disabling default features still retains tonic + tonic-prost dependencies. The server feature adds prost-types/Tokio/tokio-stream. [T-builder] [T-lib] [T-manifest]

Version compatibility is plausible: reflection/tonic-prost accept prost **^0.14**, tonic accepts http **^1.1.0**, and its optional h2 dependency accepts **^0.4**. Those ranges admit the root versions. However tonic introduces HTTP-body/Tower service abstractions; tonic-reflection alone does **not** force Hyper transport. Enabling tonic server/transport adds Hyper and Tower transport machinery. Its Rust 1.88 minimum is an additional unverified toolchain requirement. No Cargo resolution or target build was run. [T-deps] [TC-deps] [T-manifest] [T-core] [C-reflection]

**Engine-reuse alternative:** Tonic + tonic-prost provide established gRPC streaming/framing and generated service types, but stock tonic-reflection still requires behavior changes for closure, Go-style errors and extensions. A custom handler on Tonic would reuse transport rather than supply those missing semantics automatically. Do not add it merely to obtain protobuf message structs or descriptors: even the generated-only configuration retains tonic dependencies. [T-generated] [T-v1] [T-manifest]

## Reuse existing descriptors first

1. **Existing build output:** consume any already-produced, parent-identified FileDescriptorSet bytes or existing DescriptorPool; do not regenerate fixtures/code or run a build just to obtain them. Root `build.rs`, read without execution, only emits a rerun directive and conditional MSVC linker argument; it does not itself generate descriptors. Existing artifact locations/completeness were not inspected inside reserved adapters or evidence. No assertion of global artifact absence is made.
2. Decode original bytes with `DescriptorPool::decode`, which retains extension options, then use `FileDescriptor::encode_to_vec` for each reflection response entry. Avoid a prost-types decode/re-encode round trip. This preserves supported options, **not a claim of byte-identical Go serialization**. [Pool] [File]
3. Use library file lookup and `FileDescriptor::dependencies()` for closure; maintain bounded per-stream sent state outside the pool. Message/service lookups and service-method traversal support symbol indexing; cover nested messages, fields, enum values, methods and extensions where required rather than assuming message lookup alone implements all symbols. `MessageDescriptor::get_extension(number)` and `extensions()` provide extension resolution/enumeration. [Pool] [File] [Message] [R-api]
4. `DynamicMessage::decode` and its prost Message encoding implement reflection request/response protobufs **if their descriptors are present**. An application-only descriptor set may omit the reflection schemas. Require the parent's vetted existing v1/v1alpha descriptors and their imports; otherwise obtain them through the approved descriptor/codegen delivery path before claiming this route is ready. There is no demonstrated need for a hand-written protobuf decoder or new descriptor engine. [Dynamic] [Pool] [V1] [Alpha]
5. Keep advertised services tied to actual RPC registration, including reflection versions actually exposed; do not advertise every schema service just because its descriptor is embedded. Descriptor closure and service visibility must remain independent. [Go-register] [Go-engine] [T-builder]

`h2` supplies HTTP/2 DATA, trailers and flow control, **not native gRPC records/status semantics**. Reuse the parent's existing bounded gRPC adapter if available; its presence/correctness was not inspected here. It must support fragmented/coalesced five-byte-prefixed records, concurrent receive/send, bounded allocation/queues, cancellation, and final grpc-status trailers. HTTP/2 DATA boundaries are not message boundaries. If that layer is missing or inadequate, evaluate Tonic core transport before authoring another general codec; that decision remains outside this research. [H2] [H-recv] [H-send] [Wire]

## Access and validation limits

The client exposes no callable `web.run`; the available websearch integration returned HTTP 403. Direct HTTPS reads of official crates.io APIs, docs.rs and GitHub raw/API sources succeeded and support the citations. Initial guessed tags (`v0.14.9`, `v0.16.5`) returned 404; the actual names above were verified through official tag metadata. All links were retrieved on **2026-11-27**.

No local Rust/Cargo/Go execution, installation, compilation, testing, formatting, code/fixture generation, status polling/watchers, git staging/commits/pushes or further agents were used. Only this new repository note was written. Reserved adapter paths, workflows and evidence were not inspected or changed; root manifests/lock were read only for dependency feasibility. No pinned Go integration audit was duplicated. Later integration still needs protocol/interoperability validation, especially closure/repeated requests, miss-then-success on one stream, extension cases, exact registration, both versions and transport failure handling.

## Primary sources (retrieved 2026-11-27)

[C-reflection]: https://crates.io/api/v1/crates/tonic-reflection
[C-tonic]: https://crates.io/api/v1/crates/tonic
[C-codec]: https://crates.io/api/v1/crates/tonic-prost
[C-reflect]: https://crates.io/api/v1/crates/prost-reflect
[C-prost]: https://crates.io/api/v1/crates/prost
[C-h2]: https://crates.io/api/v1/crates/h2
[V1]: https://github.com/grpc/grpc-proto/blob/a0515b76877ff1298b0f430198043705a216541d/grpc/reflection/v1/reflection.proto
[Alpha]: https://github.com/grpc/grpc-proto/blob/a0515b76877ff1298b0f430198043705a216541d/grpc/reflection/v1alpha/reflection.proto
[Protocol]: https://github.com/grpc/grpc/blob/53d07c6918376181c0f80ffb36231b51650f4424/doc/server-reflection.md
[Wire]: https://github.com/grpc/grpc/blob/53d07c6918376181c0f80ffb36231b51650f4424/doc/PROTOCOL-HTTP2.md
[Go-register]: https://github.com/grpc/grpc-go/blob/b78156ea35afe68ada1ef1600e8cd813ac23a45d/reflection/serverreflection.go
[Go-engine]: https://github.com/grpc/grpc-go/blob/b78156ea35afe68ada1ef1600e8cd813ac23a45d/reflection/internal/internal.go
[T-tag]: https://api.github.com/repos/grpc/grpc-rust/git/tags/ecb8a92ac08fe47920a2b4ffea9167001b98b79e
[T-builder]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/src/server/mod.rs
[T-v1]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/src/server/v1.rs
[T-alpha]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/src/server/v1alpha.rs
[T-lib]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/src/lib.rs
[T-manifest]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/Cargo.toml
[T-deps]: https://crates.io/api/v1/crates/tonic/0.14.9/dependencies
[TC-deps]: https://crates.io/api/v1/crates/tonic-prost/0.14.9/dependencies
[T-core]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic/Cargo.toml
[T-generated]: https://github.com/grpc/grpc-rust/blob/4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70/tonic-reflection/src/generated/grpc_reflection_v1.rs
[Pool]: https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.DescriptorPool.html
[File]: https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.FileDescriptor.html
[Message]: https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.MessageDescriptor.html
[Dynamic]: https://docs.rs/prost-reflect/0.16.5/prost_reflect/struct.DynamicMessage.html
[R-api]: https://github.com/andrewhickman/prost-reflect/blob/2d0e1847a07d2582ae3edf84dbb80f2684961fef/prost-reflect/src/descriptor/api.rs
[H2]: https://docs.rs/h2/0.4.21/h2/
[H-recv]: https://docs.rs/h2/0.4.21/h2/struct.RecvStream.html
[H-send]: https://docs.rs/h2/0.4.21/h2/struct.SendStream.html
