# Dependency upgrade audit

Verified from the official crates.io API on 2026-11-26T20:05:36.798243+00:00 (UTC).

Maximum semantic version with no prerelease component and yanked=false; official crates.io API; all direct, target, dev and build dependency sections in both manifests.

The table records registry evidence, not a build-success claim. Linux resolver and CI results are recorded below after validation. No Rust, Cargo, rustc, or Go installation or execution is performed on Android.
| Manifest / section | Dependency (registry package) | Previous requirement | Latest stable / new requirement | Published (UTC) | Source |
| --- | --- | --- | --- | --- | --- |
| `Cargo.toml` / `dependencies` | `tokio` (`tokio`) | `1.40` | `1.54.1` / `1.54.1` | 2026-10-21T21:05:43.950213Z | [crates.io API](https://crates.io/api/v1/crates/tokio) |
| `Cargo.toml` / `dependencies` | `tokio-util` (`tokio-util`) | `0.7` | `0.7.20` / `0.7.20` | 2026-10-09T11:02:11.456952Z | [crates.io API](https://crates.io/api/v1/crates/tokio-util) |
| `Cargo.toml` / `dependencies` | `bytes` (`bytes`) | `1.7` | `1.12.2` / `1.12.2` | 2026-11-17T20:58:59.774443Z | [crates.io API](https://crates.io/api/v1/crates/bytes) |
| `Cargo.toml` / `dependencies` | `h2` (`h2`) | `0.4` | `0.4.21` / `0.4.21` | 2026-11-24T21:40:58.329957Z | [crates.io API](https://crates.io/api/v1/crates/h2) |
| `Cargo.toml` / `dependencies` | `http` (`http`) | `1` | `1.5.0` / `1.5.0` | 2026-07-29T14:57:21.755258Z | [crates.io API](https://crates.io/api/v1/crates/http) |
| `Cargo.toml` / `dependencies` | `futures` (`futures`) | `0.3` | `0.3.34` / `0.3.34` | 2026-08-11T12:13:28.064590Z | [crates.io API](https://crates.io/api/v1/crates/futures) |
| `Cargo.toml` / `dependencies` | `async-trait` (`async-trait`) | `0.1` | `0.1.92` / `0.1.92` | 2026-08-08T07:10:35.376083Z | [crates.io API](https://crates.io/api/v1/crates/async-trait) |
| `Cargo.toml` / `dependencies` | `thiserror` (`thiserror`) | `1.0` | `2.0.21` / `2.0.21` | 2026-09-23T20:24:07.771104Z | [crates.io API](https://crates.io/api/v1/crates/thiserror) |
| `Cargo.toml` / `dependencies` | `anyhow` (`anyhow`) | `1.0` | `1.0.105` / `1.0.105` | 2026-11-23T06:21:21.769182Z | [crates.io API](https://crates.io/api/v1/crates/anyhow) |
| `Cargo.toml` / `dependencies` | `serde` (`serde`) | `1.0` | `1.0.229` / `1.0.229` | 2026-07-18T23:05:13.266456Z | [crates.io API](https://crates.io/api/v1/crates/serde) |
| `Cargo.toml` / `dependencies` | `serde_json` (`serde_json`) | `1.0` | `1.0.154` / `1.0.154` | 2026-10-11T15:31:46.076577Z | [crates.io API](https://crates.io/api/v1/crates/serde_json) |
| `Cargo.toml` / `dependencies` | `tracing` (`tracing`) | `0.1` | `0.1.44` / `0.1.44` | 2025-12-18T14:26:12.360139Z | [crates.io API](https://crates.io/api/v1/crates/tracing) |
| `Cargo.toml` / `dependencies` | `tracing-subscriber` (`tracing-subscriber`) | `0.3` | `0.3.23` / `0.3.23` | 2026-03-13T10:04:15.571048Z | [crates.io API](https://crates.io/api/v1/crates/tracing-subscriber) |
| `Cargo.toml` / `dependencies` | `uuid` (`uuid`) | `1.10` | `1.29.3` / `1.29.3` | 2026-11-17T01:19:44.774559Z | [crates.io API](https://crates.io/api/v1/crates/uuid) |
| `Cargo.toml` / `dependencies` | `rustls` (`rustls`) | `0.23` | `0.23.46` / `0.23.46` | 2026-10-14T09:54:15.075873Z | [crates.io API](https://crates.io/api/v1/crates/rustls) |
| `Cargo.toml` / `dependencies` | `tokio-rustls` (`tokio-rustls`) | `0.26` | `0.26.6` / `0.26.6` | 2026-09-28T09:18:10.392472Z | [crates.io API](https://crates.io/api/v1/crates/tokio-rustls) |
| `Cargo.toml` / `dependencies` | `webpki-roots` (`webpki-roots`) | `0.26` | `1.0.12` / `1.0.12` | 2026-11-10T21:08:56.515281Z | [crates.io API](https://crates.io/api/v1/crates/webpki-roots) |
| `Cargo.toml` / `dependencies` | `rustls-pki-types` (`rustls-pki-types`) | `1.8` | `1.16.0` / `1.16.0` | 2026-11-10T17:38:32.491976Z | [crates.io API](https://crates.io/api/v1/crates/rustls-pki-types) |
| `Cargo.toml` / `dependencies` | `rcgen` (`rcgen`) | `0.13` | `0.14.10` / `0.14.10` | 2026-08-28T21:30:01.600392Z | [crates.io API](https://crates.io/api/v1/crates/rcgen) |
| `Cargo.toml` / `dependencies` | `clap` (`clap`) | `4.5` | `4.6.10` / `4.6.10` | 2026-11-24T21:41:19.477913Z | [crates.io API](https://crates.io/api/v1/crates/clap) |
| `Cargo.toml` / `dependencies` | `rand` (`rand`) | `0.8` | `0.10.4` / `0.10.4` | 2026-11-15T13:54:26.803018Z | [crates.io API](https://crates.io/api/v1/crates/rand) |
| `Cargo.toml` / `dependencies` | `httparse` (`httparse`) | `1.9` | `1.10.1` / `1.10.1` | 2025-03-03T14:44:09.975762Z | [crates.io API](https://crates.io/api/v1/crates/httparse) |
| `Cargo.toml` / `dependencies` | `socket2` (`socket2`) | `0.5` | `0.6.5` / `0.6.5` | 2026-07-13T19:45:58.436336Z | [crates.io API](https://crates.io/api/v1/crates/socket2) |
| `Cargo.toml` / `dependencies` | `sha2` (`sha2`) | `0.10` | `0.11.2` / `0.11.2` | 2026-11-25T15:26:54.368320Z | [crates.io API](https://crates.io/api/v1/crates/sha2) |
| `Cargo.toml` / `dependencies` | `blake3` (`blake3`) | `1.8` | `1.8.7` / `1.8.7` | 2026-08-20T09:09:56.903547Z | [crates.io API](https://crates.io/api/v1/crates/blake3) |
| `Cargo.toml` / `dependencies` | `ml-kem` (`ml-kem`) | `=0.3.2` | `0.3.4` / `=0.3.4` | 2026-10-31T22:07:26.669701Z | [crates.io API](https://crates.io/api/v1/crates/ml-kem) |
| `Cargo.toml` / `dependencies` | `hex` (`hex`) | `0.4` | `0.4.3` / `0.4.3` | 2021-03-03T10:48:58.682837Z | [crates.io API](https://crates.io/api/v1/crates/hex) |
| `Cargo.toml` / `dependencies` | `aes-gcm` (`aes-gcm`) | `0.10` | `0.11.1` / `0.11.1` | 2026-08-21T20:55:46.824964Z | [crates.io API](https://crates.io/api/v1/crates/aes-gcm) |
| `Cargo.toml` / `dependencies` | `chacha20poly1305` (`chacha20poly1305`) | `0.10` | `0.11.0` / `0.11.0` | 2026-06-28T17:41:38.459924Z | [crates.io API](https://crates.io/api/v1/crates/chacha20poly1305) |
| `Cargo.toml` / `dependencies` | `x25519-dalek` (`x25519-dalek`) | `2.0` | `3.0.0` / `3.0.0` | 2026-07-06T16:23:00.505143Z | [crates.io API](https://crates.io/api/v1/crates/x25519-dalek) |
| `Cargo.toml` / `dependencies` | `hkdf` (`hkdf`) | `0.12` | `0.13.0` / `0.13.0` | 2026-03-30T14:36:50.965552Z | [crates.io API](https://crates.io/api/v1/crates/hkdf) |
| `Cargo.toml` / `dependencies` | `tokio-tungstenite` (`tokio-tungstenite`) | `0.24` | `0.30.0` / `0.30.0` | 2026-07-11T12:58:44.438987Z | [crates.io API](https://crates.io/api/v1/crates/tokio-tungstenite) |
| `Cargo.toml` / `dependencies` | `md-5` (`md-5`) | `0.10` | `0.11.0` / `0.11.0` | 2026-03-27T14:59:39.677170Z | [crates.io API](https://crates.io/api/v1/crates/md-5) |
| `Cargo.toml` / `dependencies` | `regex` (`regex`) | `1.10` | `1.13.2` / `1.13.2` | 2026-11-18T02:53:15.314583Z | [crates.io API](https://crates.io/api/v1/crates/regex) |
| `Cargo.toml` / `dependencies` | `sha1` (replaces `sha-1`) | `0.10` | `0.11.0` / `0.11.0` | 2026-03-27T14:07:50.054737Z | [crates.io API](https://crates.io/api/v1/crates/sha1) |
| `Cargo.toml` / `dependencies` | `base64` (`base64`) | `0.22` | `0.23.1` / `0.23.1` | 2026-08-04T12:34:31.976297Z | [crates.io API](https://crates.io/api/v1/crates/base64) |
| `Cargo.toml` / `dependencies` | `network-interface` (`network-interface`) | `2` | `2.0.5` / `2.0.5` | 2026-01-03T10:29:06.529758Z | [crates.io API](https://crates.io/api/v1/crates/network-interface) |
| `Cargo.toml` / `dependencies` | `ipnet` (`ipnet`) | `2` | `2.12.2` / `2.12.2` | 2026-09-06T05:45:08.121491Z | [crates.io API](https://crates.io/api/v1/crates/ipnet) |
| `Cargo.toml` / `dependencies` | `ahash` (`ahash`) | `0.8` | `0.8.14` / `0.8.14` | 2026-11-25T08:49:47.332278Z | [crates.io API](https://crates.io/api/v1/crates/ahash) |
| `Cargo.toml` / `dependencies` | `etherparse` (`etherparse`) | `0.20` | `0.21.1` / `0.21.1` | 2026-11-23T20:07:30.406021Z | [crates.io API](https://crates.io/api/v1/crates/etherparse) |
| `Cargo.toml` / `dependencies` | `log` (`log`) | `0.4` | `0.4.35` / `0.4.35` | 2026-10-30T21:36:19.748360Z | [crates.io API](https://crates.io/api/v1/crates/log) |
| `Cargo.toml` / `dependencies` | `pingora-pool` (`pingora-pool`) | `0.9.1` | `0.9.1` / `0.9.1` | 2026-11-03T00:42:38.995976Z | [crates.io API](https://crates.io/api/v1/crates/pingora-pool) |
| `Cargo.toml` / `dependencies` | `pingora-http` (`pingora-http`) | `0.9.1` | `0.9.1` / `0.9.1` | 2026-11-03T00:43:37.391167Z | [crates.io API](https://crates.io/api/v1/crates/pingora-http) |
| `Cargo.toml` / `dependencies` | `pingora-timeout` (`pingora-timeout`) | `0.9.1` | `0.9.1` / `0.9.1` | 2026-11-03T00:19:43.450231Z | [crates.io API](https://crates.io/api/v1/crates/pingora-timeout) |
| `Cargo.toml` / `dependencies` | `hickory-resolver` (`hickory-resolver`) | `0.26` | `0.26.4` / `0.26.4` | 2026-11-24T15:39:00.259212Z | [crates.io API](https://crates.io/api/v1/crates/hickory-resolver) |
| `Cargo.toml` / `dependencies` | `hickory-proto` (`hickory-proto`) | `0.26` | `0.26.4` / `0.26.4` | 2026-11-24T15:38:41.575834Z | [crates.io API](https://crates.io/api/v1/crates/hickory-proto) |
| `Cargo.toml` / `target.cfg(not(target_os = "android")).dependencies` | `pingora-core` (`pingora-core`) | `0.9.1` | `0.9.1` / `0.9.1` | 2026-11-03T00:44:09.614684Z | [crates.io API](https://crates.io/api/v1/crates/pingora-core) |
| `Cargo.toml` / `target.cfg(not(target_os = "android")).dependencies` | `pingora-load-balancing` (`pingora-load-balancing`) | `0.9.1` | `0.9.1` / `0.9.1` | 2026-11-03T00:44:34.896169Z | [crates.io API](https://crates.io/api/v1/crates/pingora-load-balancing) |
| `Cargo.toml` / `target.cfg(all(not(windows), not(target_os = "android"))).dependencies` | `tun` (`tun`) | `0.8.14` | `0.8.15` / `0.8.15` | 2026-11-18T08:11:31.620839Z | [crates.io API](https://crates.io/api/v1/crates/tun) |
| `Cargo.toml` / `target.cfg(windows).dependencies` | `xray-rs-window` (`xray-rs-window`) | `0.1.0` | `0.1.0` / `0.1.0` | 2026-11-22T14:05:23.203306Z | [crates.io API](https://crates.io/api/v1/crates/xray-rs-window) |
| `Cargo.toml` / `target.cfg(windows).dependencies` | `wintun` (`wintun-rs`) | `0.0.6` | `0.0.6` / `0.0.6` | 2026-10-05T06:30:14.304985Z | [crates.io API](https://crates.io/api/v1/crates/wintun-rs) |
| `Cargo.toml` / `target.cfg(windows).dependencies` | `windows` (`windows`) | `0.62` | `0.62.2` / `0.62.2` | 2025-10-06T19:19:49.704461Z | [crates.io API](https://crates.io/api/v1/crates/windows) |
| `debug_panel/dioxus_app/Cargo.toml` / `dependencies` | `dioxus` (`dioxus`) | `0.7.10` | `0.7.10` / `0.7.10` | 2026-07-30T23:14:52.497403Z | [crates.io API](https://crates.io/api/v1/crates/dioxus) |
| `debug_panel/dioxus_app/Cargo.toml` / `dependencies` | `reqwest` (`reqwest`) | `0.12` | `0.13.5` / `0.13.5` | 2026-09-08T20:55:26.479356Z | [crates.io API](https://crates.io/api/v1/crates/reqwest) |
| `debug_panel/dioxus_app/Cargo.toml` / `dependencies` | `serde` (`serde`) | `1.0` | `1.0.229` / `1.0.229` | 2026-07-18T23:05:13.266456Z | [crates.io API](https://crates.io/api/v1/crates/serde) |
| `debug_panel/dioxus_app/Cargo.toml` / `dependencies` | `serde_json` (`serde_json`) | `1.0` | `1.0.154` / `1.0.154` | 2026-10-11T15:31:46.076577Z | [crates.io API](https://crates.io/api/v1/crates/serde_json) |
| `debug_panel/dioxus_app/Cargo.toml` / `dependencies` | `tokio` (`tokio`) | `1.40` | `1.54.1` / `1.54.1` | 2026-10-21T21:05:43.950213Z | [crates.io API](https://crates.io/api/v1/crates/tokio) |
| `Cargo.toml` / `dependencies` | `boringtun` (`boringtun`) | New dependency | `0.7.1` / `0.7.1` | 2026-05-01T22:53:45.364117Z | [crates.io API](https://crates.io/api/v1/crates/boringtun) |
| `Cargo.toml` / `dependencies` | `smoltcp` (`smoltcp`) | New dependency | `0.14.0` / `0.14.0` | 2026-08-17T01:47:21.367822Z | [crates.io API](https://crates.io/api/v1/crates/smoltcp) |
| `Cargo.toml` / `dependencies` | `quinn` (`quinn`) | New dependency | `0.11.12` / `0.11.12` | 2026-09-14T10:08:47.662258Z | [crates.io API](https://crates.io/api/v1/crates/quinn) |
| `Cargo.toml` / `dependencies` | `h3` (`h3`) | New dependency | `0.0.8` / `0.0.8` | 2025-05-06T15:37:32.883527Z | [crates.io API](https://crates.io/api/v1/crates/h3) |
| `Cargo.toml` / `dependencies` | `h3-quinn` (`h3-quinn`) | New dependency | `0.0.10` / `0.0.10` | 2025-05-06T20:35:46.241359Z | [crates.io API](https://crates.io/api/v1/crates/h3-quinn) |
| `Cargo.toml` / `dependencies` | `ring` (`ring`) | New dependency | `0.17.14` / `0.17.14` | 2025-03-11T19:42:03.889273Z | [crates.io API](https://crates.io/api/v1/crates/ring) |
| `Cargo.toml` / `dependencies` | `x509-parser` (`x509-parser`) | New dependency | `0.18.1` / `0.18.1` | 2026-02-05T09:30:31.546618Z | [crates.io API](https://crates.io/api/v1/crates/x509-parser) |
| `Cargo.toml` / `dependencies` | `serde_yaml_ng` (`serde_yaml_ng`) | New dependency | `0.10.0` / `0.10.0` | 2024-05-26T19:57:45.710414Z | [crates.io API](https://crates.io/api/v1/crates/serde_yaml_ng) |
| `Cargo.toml` / `dependencies` | `toml` (`toml`) | New dependency | `1.2.3+spec-1.1.0` / `1.2.3` | 2026-11-25T01:44:12.122385Z | [crates.io API](https://crates.io/api/v1/crates/toml) |
| `Cargo.toml` / `dependencies` | `prost` (`prost`) | New dependency | `0.14.6` / `0.14.6` | 2026-11-12T17:42:17.010527Z | [crates.io API](https://crates.io/api/v1/crates/prost) |
| `Cargo.toml` / `dependencies` | `prost-reflect` (`prost-reflect`) | New dependency | `0.16.5` / `0.16.5` | 2026-07-09T22:11:04.717484Z | [crates.io API](https://crates.io/api/v1/crates/prost-reflect) |
| `Cargo.toml` / `dependencies` | `json_comments` (`json_comments`) | New dependency | `0.2.2` / `0.2.2` | 2023-11-03T06:07:26.854567Z | [crates.io API](https://crates.io/api/v1/crates/json_comments) |
| `Cargo.toml` / `dependencies` | `shake` (`shake`) | New dependency | `0.1.0` / `0.1.0` | 2026-05-15T17:16:58.539249Z | [crates.io API](https://crates.io/api/v1/crates/shake) |
| `Cargo.toml` / `dependencies` | `quinn-proto` (`quinn-proto`) | New dependency | `0.11.19` / `0.11.19` | 2026-09-30T09:13:59.040527Z | [crates.io API](https://crates.io/api/v1/crates/quinn-proto) |
| `Cargo.toml` / `dependencies` | `go-parse-duration` (`go-parse-duration`) | New dependency | `0.1.1` / `0.1.1` | 2021-07-17T16:59:25.917332Z | [crates.io API](https://crates.io/api/v1/crates/go-parse-duration) |

## Migration and Linux validation

The former sha-1 package was also verified: its latest stable release is 0.10.1 ([official API](https://crates.io/api/v1/crates/sha-1)). Its maintained successor sha1 0.11.0 is required for the digest 0.11 ecosystem used by HKDF 0.13. The SHA-1 algorithm and Shadowsocks subkey bytes stay unchanged. Both original and replacement registry evidence are in DEPENDENCY_UPGRADE.json.

Pending Linux resolution, API migrations, strict CI, and pinned Go fixture comparison.

## Approved REALITY source override

The root rustls dependency remains 0.23.46 with ring/std/tls12. Its source is the approved [cfal/rustls revision](https://raw.githubusercontent.com/cfal/rustls/f1a23c187330386e9e7f14a21dbae368034dc430/rustls/Cargo.toml), pinned to `f1a23c187330386e9e7f14a21dbae368034dc430`; the upstream Cargo manifest reports version 0.23.46 and license Apache-2.0 OR ISC OR MIT. The Linux resolver audit checks the Git source and full revision as well as the package version. The standalone Dioxus manifest continues to resolve registry rustls through its own graph. TLS 1.3-only REALITY configuration belongs to the separate REALITY integration lane.

Cargo ignores SemVer build metadata in requirements. The TOML requirement is therefore 1.2.3 to avoid a Cargo manifest warning; the audited and locked package version remains 1.2.3+spec-1.1.0. smoltcp enables async and iface-max-addr-count-8 in addition to the requested IP/TCP/UDP/fragmentation features. quinn-proto explicitly disables default features.
