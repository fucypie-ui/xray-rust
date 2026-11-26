# QUIC wire fixtures

These hex captures are frozen byte-for-byte from the local Go reference at
`Xray-core/common/protocol/quic/sniff_test.go`. They are independent of Rust
packet encoders. Whitespace is for readability and is removed by the tests.

| File | Go test | Expected domain | Bytes |
| --- | --- | --- | --- |
| `go_v1.hex` | `TestSniffQUIC` | `www.google.com` | 554 |
| `go_v1_pn4.hex` | `TestSniffQUICPacketNumberLength4` | `www.google.com` | 1200 |
| `go_v2.hex` | `TestSniffQUICv2` | `test.example.com` | 10240 |
| `go_fragmented.hex` | `TestSniffQUICIncompleteServerName` | `play.google.com` | 2500 |

The fragmented capture consists of two 1250-byte datagrams. The first alone
must request more data; concatenating both, including with zero padding
between them, must recover the domain.
