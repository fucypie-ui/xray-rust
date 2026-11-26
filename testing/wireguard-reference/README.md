# Independent WireGuard reference

The helper is frozen before the Rust engine implementation. It uses only
wireguard-go, its gVisor-backed userspace stack, and Go's X25519 implementation
from the authoritative Go checkout's pinned module graph. No Rust code or
runtime Go helper is used by the product.

Run only on the remote Ubuntu validation runner:

```sh
bash testing/wireguard-reference/generate.sh /path/to/Xray-core /path/to/output
XRAY_WIREGUARD_REFERENCE=/path/to/output/wireguard-reference cargo test proxy::wireguard
```

Outputs: `wireguard-reference` (executable) and
`wireguard-key-vectors.json` (RFC 7748 private keys with public keys independently
computed by Go). The executable's `-mode serve` emits one readiness JSON line
containing the actual encrypted UDP endpoint and dual-stack TCP/UDP echo
addresses; keep stdin open for the lifetime of the peer. `probe-tcp` and
`probe-udp` initiate connections through an independently configured Go peer.
Optional `-preshared-key`, `-keepalive`, `-mtu`, and `-peer-endpoint` allow
authentication, timers, reduced MTU and reverse-direction checks.

The reference source tree remains read-only: the script copies its go.mod and
go.sum into a disposable staging directory and writes build outputs only to
the requested output directory.

After Linux run 45893541110 at Rust commit 517a155, the helper's device
diagnostics were moved from wireguard-go's default stdout logger to stderr.
The initial keepalive can report an unknown endpoint before a serving peer
learns the Rust endpoint; stdout must remain strict readiness JSON. The
generator runs a Go regression test for that separation before building.
This changes diagnostic plumbing only: the pinned Go module graph, protocol
implementation, keys, vector generation and fixture bytes are unchanged.
The key fixture SHA256 remains
`711505b1551b672f0cbb84c7135ef1a12f33a21a618e67ee52b72050881ffed0`.
