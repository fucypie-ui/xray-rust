# TLS wire fixtures

These four ClientHello records are frozen byte-for-byte from the four cases in
the local `Xray-core/common/protocol/tls/sniff_test.go` `TestTLSHeaders` test.
Whitespace is removed before decoding.

| File | Expected domain | Bytes |
| --- | --- | --- |
| `go_1.hex` | `c.s-microsoft.com` | 205 |
| `go_2.hex` | `www07.clicktale.net` | 243 |
| `go_3.hex` | `dogfish` | 235 |
| `go_4.hex` | `10.42.0.243` | 264 |

These records cover empty and nonempty session IDs, GREASE extensions, TLS
versions, an unqualified server name, and an IP literal in SNI.
