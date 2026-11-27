# P0U27: gRPC transport primary-source research

Research date: 2026-11-27. Scope: source inspection only; no implementation or dependency changes.

## Evidence and recommendation

- **Inspected pinned Go facts** below come from local Git objects at `67756b3674d56b72c7a7e675e8dcd3f883e1b2f7` in `../Xray-core`; HEAD matched that pin and the Go worktree was clean. Public links identify the same revision. Its manifest pins grpc-go 1.85.0. [G-mod]
- **Inspected Rust dependency facts:** the working repository's Cargo.toml/Cargo.lock already contain h2 0.4.21, http 1.5.0 and prost 0.14.6; Tokio full, futures and bytes are available. These are local manifest observations, not compilation results.
- **Recommendation / unrun design inference:** reuse h2/prost for these two small streaming schemas. The APIs below cover the necessary HTTP/2 mechanics and protobuf encoding; correctness still requires an explicit bounded gRPC adapter. No additional dependency is demonstrated necessary or authorized.
- h2 0.4.21 and prost 0.14.6 are published, non-yanked releases. Inspected tags resolve respectively to `d1a9b403a6fc180c47e720274ad8f819d5187716` and `894f4a7f9c41f1afb8455fb6e521c067815f608d`. [H-release] [P-release] [H-tag] [P-tag]

## Pinned Go behavior

- Schema: `Hunk.data` is singular `bytes`, field 1; `MultiHunk.data` is `repeated bytes`, field 1. `Tun` and `TunMulti` are bidirectional streams. The dialer chooses by `multiMode` and uses the custom-name methods, rather than the generated package-qualified default route. [G-schema] [G-dial] [G-service]
- Single mode sends one Hunk per `Write` and retains received bytes across partial reads. Multi mode sends one MultiHunk per `WriteMultiBuffer`, preserves nonempty buffer order and skips empty elements on read/write. Both closers invoke their cancellation callback if present, then `CloseSend` when implemented; otherwise they close their done signal. Do not infer that every close is a full transport reset. [G-hunk] [G-multi]
- The server registers **both** methods, independently of the client's mode choice. Each handler waits for its connection cancellation and returns nil; listener close calls `grpc.Server.Stop()`. The client caches grpc ClientConns by destination/settings and reuses non-Shutdown entries. [G-hub] [G-dial]
- Authority precedence in `dial.go`: explicit `authority`, then TLS server name, then domain destination only without REALITY, otherwise empty. TLS/REALITY are applied by the custom dialer; the server's TLS credentials request ALPN `h2`. HTTP/2 authority is distinct from TLS SNI. [G-dial] [G-hub]
- Client keepalive options are installed when either timeout is positive or `permit_without_stream` is true; server keepalive parameters depend on positive timeouts. `initial_windows_size > 0` sets only grpc-go's `WithInitialWindowSize` in Xray. Configuration construction clamps negative window sizes to zero and nonpositive timeouts to zero. [G-dial] [G-hub] [G-conf]
- grpc-go 1.85.0's `WithInitialWindowSize` also sets `StaticWindowSize = true`; its transport applies the size only when at least the default window. A positive but too-small Xray setting can therefore disable BDP growth without applying that small size. h2 window setters alone do not reproduce grpc-go's dynamic flow-control policy. [GO-window] [GO-transport]

### serviceName and escaped paths

- Without a leading slash, Go applies `url.PathEscape` to the **whole** serviceName, and chooses `Tun`/`TunMulti`. Final route construction is exactly `"/" + escapedService + "/" + escapedMethod`. Example: `hello/world!` becomes `/hello%2Fworld%21/Tun`. [G-path] [G-tests] [G-service]
- With a leading slash, the service is the substring between the first and last slash, split on slash, escaped per segment and rejoined. The suffix after the last slash supplies method names: first pipe component for Tun; second for TunMulti if present, otherwise first. Each chosen method is separately PathEscaped. [G-path]
- Thus `/my/sample/path/a|b` registers `/my/sample/path/a` and `/my/sample/path/b`; client `multiMode` with `/my/sample/path/b` calls the second route. Test expectations include `/hello /world!/a|b` → service `hello%20/world%21`, and a method containing `%` → `%25`. [G-path] [G-tests] [G-service]
- Edge cases must not be normalized away: `/foo` produces an empty service and route `//foo`; an empty serviceName reaches these helpers unchanged and produces `//Tun` or `//TunMulti`. The inspected configuration builder supplies no GunService fallback. These are source-derived paths, not successful interoperability observations. [G-conf] [G-path] [G-tests] [G-service]
- **Adapter implication:** preserve case, repeated slashes and the already escaped path; do not URL-decode, clean path segments, or escape the assembled URI again. Go PathEscape semantics, including percent and UTF-8 bytes, require byte-level compatibility checks; generic form/query escaping is not a substitute. [G-path] [G-tests] [RPC]

### Browser user-agent aliases

- The switch is case-sensitive: empty or `chrome` → `utils.ChromeUA`; `firefox` → FirefoxUA; `edge` → MSEdgeUA; `golang` → empty; any other string passes through. Xray overwrites grpc-go's internal UserAgent to avoid its usual `grpc-go/version` suffix; `golang` does not request that default suffix. [G-dial]
- These browser values are generated at initialization from version functions using time and a CPU-seeded PRNG, not fixed version literals. At this pin MSEdgeUA is literally `ChromeUA + "Edg/" + version + ".0.0.0"`, with no inserted space. Preserve this distinction if exact wire parity matters. The dialer itself warns against browser UAs for native gRPC; an alias does not enable gRPC-Web. [G-UA] [G-dial]

## h2 0.4.21: exact API and ownership requirements

- h2 accepts an already negotiated `T: tokio::io::AsyncRead + AsyncWrite + Unpin`. It supplies neither TLS/ALPN nor HTTP/1 upgrade negotiation; cleartext prior knowledge is another supported starting point. [H-lib]
- `h2::client::handshake(io).await` returns `Result<(SendRequest<Bytes>, Connection<T, Bytes>), h2::Error>`. `client::Builder::handshake::<T, B>(io)` supports `B: bytes::Buf`. The implementation writes the client preface and stages initial SETTINGS; it does **not** wait for server SETTINGS. [H-client]
- `SendRequest::ready(self)` consumes the handle and returns a future yielding `Result<SendRequest<B>, Error>`; alternatively `poll_ready(&mut self, cx)` returns `Poll<Result<(), Error>>`. After readiness, `send_request(Request<()>, false)` returns `Result<(ResponseFuture, SendStream<B>), Error>`; awaiting ResponseFuture yields `Result<Response<RecvStream>, Error>`. Use HTTP/2 version and an absolute URI supplying scheme, authority and the escaped path. [H-client]
- The client Connection is a `Future<Output = Result<(), Error>>` and must remain polled concurrently with stream work, commonly in a Tokio task. Handles do not drive I/O. Record driver failures and propagate them; aborting/dropping this owner drops the underlying I/O and notifies streams of EOF rather than draining pending frames. [H-client] [H-connection]
- `h2::server::handshake(io)` returns `Handshake<T, Bytes>`; awaiting yields `Result<server::Connection<T, Bytes>, Error>`. Server handshake flushes server SETTINGS and reads the client preface. `accept(&mut self).await` returns `Option<Result<(Request<RecvStream>, SendResponse<B>), Error>>` and advances the connection. [H-server]
- Dispatch accepted streams concurrently and promptly resume accept; awaiting an entire handler before polling the connection can stall that handler. When not accepting, drive `poll_closed(&mut self, cx) -> Poll<Result<(), Error>>`, e.g. using the existing futures `poll_fn`. Some module prose incorrectly says `poll_close` and that graceful shutdown is unimplemented; the actual 0.4.21 public methods are authoritative. [H-server]
- `SendResponse::send_response(Response<()>, false) -> Result<SendStream<B>, Error>` leaves room for body/trailers. `SendStream::send_trailers(HeaderMap) -> Result<(), Error>` closes the send half; sending more data or trailers then fails. Explicit cancellation uses `send_reset(Reason)`, returning unit; `poll_reset(cx) -> Poll<Result<Reason, Error>>` observes resets. Reset is not graceful EOF. [H-server] [H-share] [RPC]

### Bounded sending and receiving

- `reserve_capacity(&mut self, usize)` requests a **total outstanding** send allowance, not an additive amount; sends reduce it. `reserve_capacity(0)` cancels unused reservation. `capacity(&self) -> usize` reports currently assigned capacity. [H-send-doc]
- `poll_capacity(&mut self, cx) -> Poll<Option<Result<usize, Error>>>` reports the total assigned capacity, not a delta. Grants may be partial; consume available bytes promptly instead of waiting for an entire gRPC record. Handle Pending, error and None; the implementation returns None after the send side stops streaming. [H-send-doc] [H-send-internal]
- `send_data(B, end_of_stream) -> Result<(), Error>` can enqueue **unbounded** data when called without respecting capacity. Recommended loop: reserve a bounded remaining chunk, wait/check capacity, send no more than the available bytes, and bound the producer queue by bytes as well as item count. Holding unused grants can starve other streams. [H-send-doc]
- Both builders expose `max_send_buffer_size(usize)`: this stops reporting more send capacity around a per-stream buffered threshold; it is **not** a hard rejection limit on arbitrary repeated send_data calls. Retain application backpressure. `initial_window_size(u32)` and `initial_connection_window_size(u32)` configure separate receive windows, both defaulting to 65,535. [H-client] [H-server]
- `max_frame_size(u32)` bounds HTTP/2 frame payload, not gRPC message size; valid range 16,384–16,777,215. Bound headers and stream admission separately. In 0.4.21, `data_frame_budget(usize)` also limits small-DATA-frame memory overhead; the automatic budget is half the target connection window, minimum 25,600, and exhaustion closes with ENHANCE_YOUR_CALM. Retain these protections. [H-client] [H-server]
- `RecvStream::data(&mut self).await -> Option<Result<Bytes, Error>>` receives DATA. `flow_control(&mut self) -> &mut FlowControl`, then `release_capacity(usize) -> Result<(), Error>`, restores **stream and connection** credit. Track every consumed DATA byte, including gRPC's five-byte prefix; never release a byte twice or more than received. Dropping a returned Bytes alone does not release credit. [H-recv-doc] [H-flow-doc]
- **Buffering inference:** release credit when bytes enter a bounded, budgeted assembler or are consumed downstream. Holding all credit until a whole message arrives can deadlock for messages larger than the window; returning it into an unbounded application queue defeats backpressure. Budget incomplete records, decoded values, queued output and aggregate concurrent streams separately. [H-share]
- Drain DATA, then inspect `RecvStream::trailers(&mut self).await -> Result<Option<HeaderMap>, Error>`. Dropping RecvStream clears queued receive data but deliberately does not itself force RST while sending may continue. Implicit cancellation depends on remaining stream references; use explicit reset when immediate cancellation is intended. [H-share] [H-drop]

### Drop and shutdown

- Finish a client's request half with final DATA having end_of_stream=true, including empty DATA if needed. Keep receiving and driving the connection for the response's final status; half-close is not cancellation. The SendStream docs warn that an unfinished dropped send stream cancels the exchange, but internal reference ownership matters, so do not rely on drop timing for a precise reset. [H-send-doc] [H-drop] [RPC]
- Client Connection exposes no server-style graceful_shutdown method. Stop new requests, finish active streams, release response/stream/ping handles and every SendRequest clone, and keep polling the driver; with no streams/other references the client initiates NO_ERROR GOAWAY. Retaining a clone can keep it alive. An application deadline and forced cancellation are separate policy decisions. [H-client] [H-connection] [H-drop]
- Server `graceful_shutdown(&mut self)` initiates GOAWAY draining: in-flight requests may still arrive for about one RTT, and active streams finish before closure. Continue driving/dispatching through closure. `abrupt_shutdown(&mut self, Reason)` also requires polling to flush GOAWAY but closes without waiting for active streams. Dropping the Connection is not either completed shutdown procedure. [H-server] [H-connection]

## prost 0.14.6 and bounded gRPC records

- Derive contract, without source implementation: `#[derive(Clone, PartialEq, ::prost::Message)]`; Hunk's data uses `#[prost(bytes = "vec", tag = "1")]` on `Vec<u8>`; MultiHunk uses `#[prost(bytes = "vec", repeated, tag = "1")]` on `Vec<Vec<u8>>`. A `bytes = "bytes"` field may instead use Bytes / Vec<Bytes> with identical wire types. Bytes are length-delimited, never packed numeric fields. [G-schema] [P-scalar]
- Default prost features already include derive/std. Message derive supplies Default and Debug, so adding it to existing types requires avoiding conflicting derives; no prost-build, protoc, build script or new dependency is required for manually declared messages. These are source-supported API conclusions, not a compile result. [P-readme] [P-derive]
- `Message::encoded_len()` measures protobuf bytes; `encode`/`encode_to_vec` emit those bytes; `Message::decode(buf: impl Buf) -> Result<Self, DecodeError>` consumes the supplied buffer and requires Self: Default. prost's `encode_length_delimited`/`decode_length_delimited` use a protobuf **varint** delimiter, not the gRPC envelope. [P-message]
- **Recommended boundary:** assemble exactly one five-byte gRPC prefix, validate its flag and big-endian u32 length, reject over-limit lengths **before** reserving their declared size, use checked length conversions/addition, then decode only that record's payload. HTTP/2 DATA can split the prefix/body or contain multiple records. Retain only bounded leftovers and treat EOF mid-prefix or mid-payload as failure. [RPC] [P-message] [GO-framing]
- grpc-go 1.85.0 defaults receive limits to **4 MiB of serialized message**, both client/server; Xray sets no override in the inspected dial/listen code. A 4 MiB receive cap therefore matches that default. Outbound protobuf overhead must also fit the peer's cap; imposing a symmetric send cap is a proposed local policy, not Go's much larger default send limit. [GO-client-limit] [GO-server-limit] [G-dial] [G-hub]
- prost decode has no configurable total-byte or repeated-element allocation budget. Its bytes decoder validates field length against remaining input, but repeated empty bytes still allocate Vec entries. A byte cap bounds input, not decoded heap overhead. If tighter element/heap bounds are needed, count/validate fields before derive decoding or account conservatively; a post-decode count check is too late to prevent allocation. Extra count limits narrow the valid protobuf inputs accepted and must be documented. [P-message] [P-encoding]
- Preserve protobuf semantics: missing Hunk.data means empty; duplicate singular bytes use the last value; repeated fields preserve order. Keep normal unknown-field handling and the default recursion protection (100), relevant even to these flat schemas because unknown groups can nest. Do not enable `no-recursion-limit`. Treat empty payload messages as messages, not transport EOF. [P-readme] [P-encoding] [RPC]

## gRPC contract the adapter must supply

- Send native HTTP/2 POST, content-type application/grpc (or application/grpc+proto), te: trailers and the exact escaped route. Responses use HTTP 200 plus gRPC status; non-gRPC request media types should receive HTTP 415. This is native gRPC, not gRPC-Web framing. [RPC]
- Emit flag 0 plus a four-byte big-endian protobuf length. With compression unsupported, advertise at most identity and reject unsupported request grpc-encoding as UNIMPLEMENTED (12); unsupported compressed responses are client INTERNAL (13). Flag 1 with absent/identity encoding, or flags outside 0/1, are INTERNAL (13). Never pass compressed bytes to prost or silently clear the flag. No compressor is configured by the inspected Xray transport itself. [RPC] [Compression] [GO-framing] [GO-server-limit] [G-dial] [G-hub]
- Finish normal server responses with trailers carrying grpc-status: 0 via send_trailers; do not close DATA first and lose the trailers. Send nonzero grpc-status for errors, with properly percent-encoded grpc-message when present; immediate failures may be trailers-only in the initial end-stream HEADERS. Accept that form on clients as well as final trailers. [RPC] [H-share]
- After DATA ends, validate final status before reporting successful EOF. HTTP 200 alone, missing/malformed status, premature EOF, RST_STREAM and connection failure are not success; synthesize an application-visible error where protocol status is absent. For Go-aligned oversized-message rejection use RESOURCE_EXHAUSTED (8); error policy must not accidentally hide already delivered data or a later nonzero status. [RPC] [GO-framing]

## Maintained tonic alternative; dependency decision

- The requested former `hyperium/tonic` repository redirects to maintained `grpc/grpc-rust`. crates.io reports stable tonic **0.14.9**, published 2026-10-29; inspected tag `tonic-v0.14.9` dereferences to `4c0f455c264fe2ec9f9ab5d0cc7fd2824d5daf70`. [T-repo] [T-release] [T-tag]
- `tonic::client::Grpc::streaming(request, PathAndQuery, codec)` supports explicit paths; tonic handles envelopes, statuses/trailers and message limits. Its default decode cap is 4 MiB with `max_decoding_message_size(usize)` override. In 0.14 the prost codec is the separate `tonic_prost::ProstCodec<T, U>` / tonic-prost crate (prost 0.14 compatible), rather than tonic::codec::ProstCodec. [T-client] [T-decode] [T-prost]
- Default tonic features enable router/transport/codegen; its transport brings Hyper/Tower and related dependencies. Compression features are opt-in. Stock `Endpoint::user_agent` prepends a custom value to tonic's own suffix, conflicting with Xray's exact-UA replacement. Custom server routing and lower-level transport/header control would still require investigation. [T-cargo] [T-endpoint]
- **Decision:** do not add tonic or tonic-prost for this bounded task. Reconsider only if a later correctness requirement exceeds a carefully audited h2/prost adapter; that would require separate dependency authorization, not a change made by this research.

## Unrun assumptions and remaining caveats

No Rust, Cargo or Go execution, builds, tests, formatters, code generation or toolchain installation were performed; no delegation occurred. Public sources were read over HTTP and pinned Go files with Git. Only this note was written.
The adapter recommendations are unrun design inferences, not proof of Go interoperability, bounded peak RSS, fairness, TLS/REALITY integration, keepalive/reconnect parity, exact browser-UA bytes or graceful cancellation. Highest-value later checks: fragmented/coalesced and empty records, maximum sizes and empty-field amplification, stalled/concurrent windows, compressed/invalid frames, late/missing status and trailers-only replies, custom escaped paths, and handle-drop/GOAWAY races. No such checks were run or implemented here.

## Primary sources

[G-mod]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/go.mod
[G-schema]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/encoding/stream.proto
[G-path]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/config.go#L17-L59
[G-tests]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/config_test.go
[G-service]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/encoding/customSeviceName.go
[G-dial]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/dial.go
[G-hub]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/hub.go
[G-hunk]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/encoding/hunkconn.go
[G-multi]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/transport/internet/grpc/encoding/multiconn.go
[G-UA]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/common/utils/browser.go
[G-conf]: https://github.com/XTLS/Xray-core/blob/67756b3674d56b72c7a7e675e8dcd3f883e1b2f7/infra/conf/transport_method.go#L585-L618
[H-release]: https://crates.io/api/v1/crates/h2/0.4.21
[P-release]: https://crates.io/api/v1/crates/prost/0.14.6
[H-tag]: https://api.github.com/repos/hyperium/h2/git/ref/tags/v0.4.21
[P-tag]: https://api.github.com/repos/tokio-rs/prost/git/ref/tags/v0.14.6
[H-lib]: https://github.com/hyperium/h2/blob/v0.4.21/src/lib.rs#L25-L47
[H-client]: https://github.com/hyperium/h2/blob/v0.4.21/src/client.rs
[H-server]: https://github.com/hyperium/h2/blob/v0.4.21/src/server.rs
[H-share]: https://github.com/hyperium/h2/blob/v0.4.21/src/share.rs
[H-send-doc]: https://docs.rs/h2/0.4.21/h2/struct.SendStream.html
[H-recv-doc]: https://docs.rs/h2/0.4.21/h2/struct.RecvStream.html
[H-flow-doc]: https://docs.rs/h2/0.4.21/h2/struct.FlowControl.html
[H-send-internal]: https://github.com/hyperium/h2/blob/v0.4.21/src/proto/streams/send.rs#L383-L414
[H-drop]: https://github.com/hyperium/h2/blob/v0.4.21/src/proto/streams/streams.rs#L1646-L1726
[H-connection]: https://github.com/hyperium/h2/blob/v0.4.21/src/proto/connection.rs
[P-readme]: https://github.com/tokio-rs/prost/blob/v0.14.6/README.md
[P-scalar]: https://github.com/tokio-rs/prost/blob/v0.14.6/prost-derive/src/field/scalar.rs
[P-derive]: https://github.com/tokio-rs/prost/blob/v0.14.6/prost-derive/src/lib.rs#L205-L240
[P-message]: https://github.com/tokio-rs/prost/blob/v0.14.6/prost/src/message.rs
[P-encoding]: https://github.com/tokio-rs/prost/blob/v0.14.6/prost/src/encoding.rs
[RPC]: https://github.com/grpc/grpc/blob/53d07c6918376181c0f80ffb36231b51650f4424/doc/PROTOCOL-HTTP2.md
[Compression]: https://github.com/grpc/grpc/blob/53d07c6918376181c0f80ffb36231b51650f4424/doc/compression.md
[GO-framing]: https://github.com/grpc/grpc-go/blob/v1.85.0/rpc_util.go#L783-L806
[GO-client-limit]: https://github.com/grpc/grpc-go/blob/v1.85.0/clientconn.go#L138-L140
[GO-server-limit]: https://github.com/grpc/grpc-go/blob/v1.85.0/server.go
[GO-window]: https://github.com/grpc/grpc-go/blob/v1.85.0/dialoptions.go#L208-L259
[GO-transport]: https://github.com/grpc/grpc-go/blob/v1.85.0/internal/transport/http2_client.go#L403-L412
[T-repo]: https://api.github.com/repos/hyperium/tonic
[T-release]: https://crates.io/api/v1/crates/tonic
[T-tag]: https://api.github.com/repos/grpc/grpc-rust/git/tags/ecb8a92ac08fe47920a2b4ffea9167001b98b79e
[T-client]: https://github.com/grpc/grpc-rust/blob/tonic-v0.14.9/tonic/src/client/grpc.rs
[T-decode]: https://github.com/grpc/grpc-rust/blob/tonic-v0.14.9/tonic/src/codec/decode.rs
[T-prost]: https://github.com/grpc/grpc-rust/tree/tonic-v0.14.9/tonic-prost
[T-cargo]: https://github.com/grpc/grpc-rust/blob/tonic-v0.14.9/tonic/Cargo.toml
[T-endpoint]: https://github.com/grpc/grpc-rust/blob/tonic-v0.14.9/tonic/src/transport/channel/endpoint.rs#L221-L242
