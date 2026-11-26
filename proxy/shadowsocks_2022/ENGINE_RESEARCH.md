# Official Rust engine evaluation

Checked crates.io published manifests and the official tagged GitHub source before extending the AES checkpoint. No local Rust/Go build or install was used.

- shadowsocks 1.25.0: MIT, Rust 1.91. Its aead-cipher-2022 feature enables the v2 crypto engine plus AWS-LC, rand, aes and lru_time_cache. The default includes DNS and legacy AEAD. Public ProxyClientStream::from_stream and ProxyServerStream::from_stream_with_user_manager cover TCP/EIH; the latter exposes user_key after handshake. Full stream replacement would change existing cancellation, empty response and precise Go-fixture behavior, and it does not supply this port's routing/runtime interface or a Go-specific relay. Source: https://crates.io/api/v1/crates/shadowsocks and https://github.com/shadowsocks/shadowsocks-rust/tree/v1.25.0/crates/shadowsocks/src/relay/tcprelay/proxy_stream
- shadowsocks-crypto 0.8.0: MIT, Rust 1.85. Selected dependency: default-features = false, features = ["v2"]. v2::tcp::TcpCipher::new(CipherKind, key, salt) derives the BLAKE3 session subkey; encrypt_packet/decrypt_packet operate in place on buffers including the 16-byte tag. The engine increments its 96-bit nonce after each operation; the adapter makes authentication failures terminal and separately guards exhaustion. Source: https://github.com/shadowsocks/shadowsocks-crypto/blob/v0.8.0/src/v2/tcp/mod.rs
- v2::udp::UdpCipher::new(CipherKind, key, session_id) derives the AES body key from the big-endian session ID; ChaCha uses the PSK directly and XChaCha's 24-byte nonce. encrypt_packet/decrypt_packet encrypt the body, despite the broad doc comment: AES header encryption and EIH remain the caller's responsibility. Source: https://github.com/shadowsocks/shadowsocks-crypto/tree/v0.8.0/src/v2/udp
- Dependency features/manifests/license verified from https://crates.io/api/v1/crates/shadowsocks-crypto and https://github.com/shadowsocks/shadowsocks-crypto/blob/v0.8.0/Cargo.toml . Pure Rust v2 avoids requesting a new native C toolchain. No v2-extra methods are enabled: the Go reference does not support ChaCha8.

## Authoritative Go target

Adjacent read-only Xray-core commit 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7. TCP and UDP support AES128, AES256 and ChaCha20. Multi-user, EIH chains and relays are AES-only. Go inbound defaults to both TCP and UDP. Go infra/conf/shadowsocks.go selects normal, multi-user or relay mode from users, using users[0].address to distinguish multi-user and relay. EIH TCP derives identity keys with "shadowsocks 2022 identity subkey" and encrypts the first 16 BLAKE3 hash bytes of the next PSK. UDP EIH uses the raw AES key and XORs the hash with the decrypted 16-byte session/packet header. The SS2022 Go package contains no UOT or mux codec: those depend on the generic runtime's packet/stream adaptation, not the SS2022 cipher.

## Shared runtime integration after initial compile

The parent integrated dependency/API migration commit c698496. This lane now uses
rand 0.10.4 SysRng/TryRng/RngExt and aes-gcm 0.11.1 BlockCipherEncrypt /
BlockCipherDecrypt with fixed arrays. The selected shadowsocks-crypto 0.8.0 v2 dependency was declared at 1ea1cf2
and its Linux-resolved lock imported at c92390f. The prepared manifest was
byte-identical to the reviewed source.

The concrete shared native contract is in common/net/datagram.rs and
features/{inbound,outbound}:

- Datagram { payload: bytes::Bytes, source: Option<Destination>, destination }.
- DatagramTransport: async recv(&self) -> Result<Option<Datagram>>, send(&self,
  Datagram) -> Result<()>, and close; BoxDatagram = Arc<dyn DatagramTransport>.
- OutboundHandler::connect_datagram(&SessionContext) -> Result<BoxDatagram>.
- InboundHandler::dispatch_connection(stream, remote, Arc<dyn InboundDispatcher>),
  plus bind_native and NativeInboundListener for UDP binding/lifecycle.

The first expanded source snapshot deliberately does not change these contracts.
After remote compilation, adapt UdpAssociation to BoxDatagram and bind the
concrete Server/MultiUserServer decode/reply APIs through native inbound packet
listeners. Keep the opaque ReplyToken per live association. Relay routing needs
a per-client session route whose responses bypass SS2022 body encoding. Its
RelayDatagram carries the next-hop destination, session ID, user and raw wire.
Use bounded queues and preserve one packet per send/recv. Explicit close and
cancellation must release sockets and listener children. Native UDP config stays
rejected until this binding exists; no stream-read packet inference is permitted.

Generic mux/UOT/wrappers are a later shared-runtime chunk after the initial
compile. The pinned Go SS2022 outbound chooses TCP/UDP from the requested target
and uses the generic internet dialer. Its infra/conf/shadowsocks.go target type
contains no uot field. No SS2022-specific UOT wire format should be invented.
Current helper signatures build_2022_inbound(tag, raw, stream) and
build_2022_outbound(tag, raw, stream, mux) are preserved for the root owner.

## Verification handoff

Linux run 45893541120 at 517a155 passed all-target checking, debug/release
builds and the SS2022 test cases, including extended Go byte comparisons. The
full library suite failed in eight other tests; no live SS2022 peer gate ran.
The three-record fixture and provenance were frozen at 1ea1cf2 with SHA-256
349343ccb3730746d51afa5bfef25470d7184fccc9476eeeb8343c81278fb9b0.
Commit e811ca8 adds its unconditional digest check before decoding; that
new check awaits remote execution. README.md and ../../md/PORTING_STATUS.md
record the remaining native UDP integration and runtime limits. The original
AES fixture, Go helper and generator have not changed.
