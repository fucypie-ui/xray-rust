# Dependency upgrade audit

Official crates.io API recheck covers all 74 direct entries (71 unique registry packages), from 2026-11-26T21:25:48.284025+00:00 through 2026-11-26T21:28:04.891290+00:00 (UTC). All selections are non-yanked stable. BLAKE3 advanced from 1.8.7 to 1.8.8 since the prior audit; the reviewed classic Shadowsocks engine is 1.25.0.

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
| `Cargo.toml` / `dependencies` | `blake3` (`blake3`) | `1.8` | `1.8.8` / `1.8.8` | 2026-11-26T21:01:42.814118Z | [crates.io API](https://crates.io/api/v1/crates/blake3) |
| `Cargo.toml` / `dependencies` | `ml-kem` (`ml-kem`) | `=0.3.2` | `0.3.4` / `=0.3.4` | 2026-10-31T22:07:26.669701Z | [crates.io API](https://crates.io/api/v1/crates/ml-kem) |
| `Cargo.toml` / `dependencies` | `hex` (`hex`) | `0.4` | `0.4.3` / `0.4.3` | 2021-03-03T10:48:58.682837Z | [crates.io API](https://crates.io/api/v1/crates/hex) |
| `Cargo.toml` / `dependencies` | `aes-gcm` (`aes-gcm`) | `0.10` | `0.11.1` / `0.11.1` | 2026-08-21T20:55:46.824964Z | [crates.io API](https://crates.io/api/v1/crates/aes-gcm) |
| `Cargo.toml` / `dependencies` | `chacha20poly1305` (`chacha20poly1305`) | `0.10` | `0.11.0` / `0.11.0` | 2026-06-28T17:41:38.459924Z | [crates.io API](https://crates.io/api/v1/crates/chacha20poly1305) |
| `Cargo.toml` / `dependencies` | `x25519-dalek` (`x25519-dalek`) | `2.0` | `3.0.0` / `3.0.0` | 2026-07-06T16:23:00.505143Z | [crates.io API](https://crates.io/api/v1/crates/x25519-dalek) |
| `Cargo.toml` / `dependencies` | `hkdf` (`hkdf`) | `0.12` | `0.13.0` / `0.13.0` | 2026-03-30T14:36:50.965552Z | [crates.io API](https://crates.io/api/v1/crates/hkdf) |
| `Cargo.toml` / `dependencies` | `tokio-tungstenite` (`tokio-tungstenite`) | `0.24` | `0.30.0` / `0.30.0` | 2026-07-11T12:58:44.438987Z | [crates.io API](https://crates.io/api/v1/crates/tokio-tungstenite) |
| `Cargo.toml` / `dependencies` | `md-5` (`md-5`) | `0.10` | `0.11.0` / `0.11.0` | 2026-03-27T14:59:39.677170Z | [crates.io API](https://crates.io/api/v1/crates/md-5) |
| `Cargo.toml` / `dependencies` | `regex` (`regex`) | `1.10` | `1.13.2` / `1.13.2` | 2026-11-18T02:53:15.314583Z | [crates.io API](https://crates.io/api/v1/crates/regex) |
| `Cargo.toml` / `dependencies` | `sha1` (`sha1`) | `0.10` | `0.11.0` / `0.11.0` | 2026-03-27T14:07:50.054737Z | [crates.io API](https://crates.io/api/v1/crates/sha1) |
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
| `Cargo.toml` / `dependencies` | `boringtun` (`boringtun`) | `new (protocol/config/REALITY integration)` | `0.7.1` / `0.7.1` | 2026-05-01T22:53:45.364117Z | [crates.io API](https://crates.io/api/v1/crates/boringtun) |
| `Cargo.toml` / `dependencies` | `smoltcp` (`smoltcp`) | `new (protocol/config/REALITY integration)` | `0.14.0` / `0.14.0` | 2026-08-17T01:47:21.367822Z | [crates.io API](https://crates.io/api/v1/crates/smoltcp) |
| `Cargo.toml` / `dependencies` | `quinn` (`quinn`) | `new (protocol/config/REALITY integration)` | `0.11.12` / `0.11.12` | 2026-09-14T10:08:47.662258Z | [crates.io API](https://crates.io/api/v1/crates/quinn) |
| `Cargo.toml` / `dependencies` | `h3` (`h3`) | `new (protocol/config/REALITY integration)` | `0.0.8` / `0.0.8` | 2025-05-06T15:37:32.883527Z | [crates.io API](https://crates.io/api/v1/crates/h3) |
| `Cargo.toml` / `dependencies` | `h3-quinn` (`h3-quinn`) | `new (protocol/config/REALITY integration)` | `0.0.10` / `0.0.10` | 2025-05-06T20:35:46.241359Z | [crates.io API](https://crates.io/api/v1/crates/h3-quinn) |
| `Cargo.toml` / `dependencies` | `ring` (`ring`) | `new (protocol/config/REALITY integration)` | `0.17.14` / `0.17.14` | 2025-03-11T19:42:03.889273Z | [crates.io API](https://crates.io/api/v1/crates/ring) |
| `Cargo.toml` / `dependencies` | `x509-parser` (`x509-parser`) | `new (protocol/config/REALITY integration)` | `0.18.1` / `0.18.1` | 2026-02-05T09:30:31.546618Z | [crates.io API](https://crates.io/api/v1/crates/x509-parser) |
| `Cargo.toml` / `dependencies` | `serde_yaml_ng` (`serde_yaml_ng`) | `new (protocol/config/REALITY integration)` | `0.10.0` / `0.10.0` | 2024-05-26T19:57:45.710414Z | [crates.io API](https://crates.io/api/v1/crates/serde_yaml_ng) |
| `Cargo.toml` / `dependencies` | `toml` (`toml`) | `new (protocol/config/REALITY integration)` | `1.2.3+spec-1.1.0` / `1.2.3` | 2026-11-25T01:44:12.122385Z | [crates.io API](https://crates.io/api/v1/crates/toml) |
| `Cargo.toml` / `dependencies` | `prost` (`prost`) | `new (protocol/config/REALITY integration)` | `0.14.6` / `0.14.6` | 2026-11-12T17:42:17.010527Z | [crates.io API](https://crates.io/api/v1/crates/prost) |
| `Cargo.toml` / `dependencies` | `prost-reflect` (`prost-reflect`) | `new (protocol/config/REALITY integration)` | `0.16.5` / `0.16.5` | 2026-07-09T22:11:04.717484Z | [crates.io API](https://crates.io/api/v1/crates/prost-reflect) |
| `Cargo.toml` / `dependencies` | `json_comments` (`json_comments`) | `new (protocol/config/REALITY integration)` | `0.2.2` / `0.2.2` | 2023-11-03T06:07:26.854567Z | [crates.io API](https://crates.io/api/v1/crates/json_comments) |
| `Cargo.toml` / `dependencies` | `shake` (`shake`) | `new (VMess/Hysteria integration)` | `0.1.0` / `0.1.0` | 2026-05-15T17:16:58.539249Z | [crates.io API](https://crates.io/api/v1/crates/shake) |
| `Cargo.toml` / `dependencies` | `quinn-proto` (`quinn-proto`) | `new (VMess/Hysteria integration)` | `0.11.19` / `0.11.19` | 2026-09-30T09:13:59.040527Z | [crates.io API](https://crates.io/api/v1/crates/quinn-proto) |
| `Cargo.toml` / `dependencies` | `go-parse-duration` (`go-parse-duration`) | `new (configuration integration)` | `0.1.1` / `0.1.1` | 2021-07-17T16:59:25.917332Z | [crates.io API](https://crates.io/api/v1/crates/go-parse-duration) |
| `Cargo.toml` / `dependencies` | `shadowsocks-crypto` (`shadowsocks-crypto`) | `new (SS2022 engine integration)` | `0.8.0` / `0.8.0` | 2026-08-26T18:13:19.682516Z | [crates.io API](https://crates.io/api/v1/crates/shadowsocks-crypto) |
| `Cargo.toml` / `dependencies` | `shadowsocks` (`shadowsocks`) | `New dependency` | `1.25.0` / `=1.25.0` | 2026-08-26T18:31:08.872950Z | [crates.io API](https://crates.io/api/v1/crates/shadowsocks) |

## Migration and Linux validation

The former sha-1 package was also verified: its latest stable release is 0.10.1 ([official API](https://crates.io/api/v1/crates/sha-1)). Its maintained successor sha1 0.11.0 is required for the digest 0.11 ecosystem used by HKDF 0.13. The SHA-1 algorithm and Shadowsocks subkey bytes stay unchanged. Both original and replacement registry evidence are in DEPENDENCY_UPGRADE.json.

Linux resolution passed for all 72 direct manifest entries (67 root including target-specific dependencies, 5 standalone desktop) in [run 45889627673](https://github.com/fucypie-ui/xray-rust/actions/runs/45889627673/job/140148780991), using commit 72d16e477faac0efe98888fa2ae5b944e88a0d13. Both lockfiles were downloaded from the latest-dependency-locks artifact without local Cargo. The compact resolver reports are committed under dependency-resolution/. The resolver verified every selected version and the full pinned rustls Git source.

The standalone Dioxus desktop app passed all-target checking with RUSTFLAGS=-D warnings on Ubuntu 24.04 with the committed locks in [run 45889801380](https://github.com/fucypie-ui/xray-rust/actions/runs/45889801380/job/140149536848). This checks native Linux GTK/WebKit compilation, not Windows/macOS/Android packaging or graphical runtime operation.

Pinned Go fixture regeneration and byte-for-byte comparison passed again in [run 45890416251](https://github.com/fucypie-ui/xray-rust/actions/runs/45890416251/job/140151409287), retaining Go reference 67756b3674d56b72c7a7e675e8dcd3f883e1b2f7.

Root validation passed on source commit df2dfcd213d81c231d1630e933451bc8a827f10e in [Rust CI run 45890735841](https://github.com/fucypie-ui/xray-rust/actions/runs/45890735841):

- [Native job 140152579828](https://github.com/fucypie-ui/xray-rust/actions/runs/45890735841/job/140152579828): cargo check --locked --all-targets; cargo build --locked --lib --bins; cargo test --locked --all-targets --no-fail-fast -- --test-threads=1; built key-command comparison against pinned Go vectors; and cargo test --locked --doc --no-fail-fast -- --test-threads=1 all passed.
- [Release job 140152580078](https://github.com/fucypie-ui/xray-rust/actions/runs/45890735841/job/140152580078): cargo build --locked --release --lib --bins passed with the existing release profile.

These results validate this isolated dependency snapshot. The parent's newer uncommitted protocol/configuration engines require their own combined-snapshot Linux validation.

## Approved REALITY source override

The root rustls dependency remains 0.23.46 with ring/std/tls12. Its source is the approved [cfal/rustls revision](https://raw.githubusercontent.com/cfal/rustls/f1a23c187330386e9e7f14a21dbae368034dc430/rustls/Cargo.toml), pinned to `f1a23c187330386e9e7f14a21dbae368034dc430`; the upstream Cargo manifest reports version 0.23.46 and license Apache-2.0 OR ISC OR MIT. The Linux resolver audit checks the Git source and full revision as well as the package version. The standalone Dioxus manifest continues to resolve registry rustls through its own graph. TLS 1.3-only REALITY configuration belongs to the separate REALITY integration lane.

Cargo ignores SemVer build metadata in requirements. The TOML requirement is therefore 1.2.3 to avoid a Cargo manifest warning; the audited and locked package version remains 1.2.3+spec-1.1.0. smoltcp enables async and iface-max-addr-count-8 in addition to the requested IP/TCP/UDP/fragmentation features. quinn-proto explicitly disables default features.

## API migrations

- rand 0.10: use rng(), random()/random_range(), Rng for raw bytes, RngExt for extension methods, and SysRng plus TryRng for fallible OS entropy. Sampling bounds and OS-error propagation are unchanged.
- x25519-dalek 3: pass a mutable RNG reference to random_from_rng. ML-KEM 0.3.4 retains the deterministic 64-byte seed constructor and pinned Go key/vector comparisons.
- RustCrypto: use checked slice/array conversions instead of deprecated from_slice, KeyInit for HMAC construction, and BlockCipherEncrypt for AES blocks in both the QUIC sniffer and its wire tests. AEAD nonce bytes, counter direction, payloads, tags and AAD are unchanged.
- rcgen 0.14.10: use CertifiedKey.signing_key in place of key_pair. Defaults remain crypto, pem and ring. KeyPair::generate_for(&PKCS_ED25519) and CertificateParams::self_signed are available with this selection.
- tokio-tungstenite 0.30: binary/ping/pong payloads use bytes::Bytes, preserving payload contents and bridge behavior. Existing websocket tests retain their assertions.
- socket2 0.6: socket2::Socket uses set_tcp_nodelay; Tokio and standard-library TcpStream keep set_nodelay.
- reqwest 0.13: the standalone desktop manifest uses the renamed rustls feature in place of rustls-tls.

The strict Rust lint policy and existing tests remain enabled. Cargo can report unused staged engine/configuration dependencies in this isolated dependency lane until the parent integrates the corresponding implementations; no lint suppressions were added.

## Parent integration notes

The complete manifests/audit/workflow handoff is available through commit 72d16e477faac0efe98888fa2ae5b944e88a0d13. Linux-generated lockfiles and compact direct-resolution reports are in 5e440d62aef7c23e435fdf85f0bfd9c951e72629. Compiler fixes follow in c6908fac50480852c31f0ae20f5e8858f396d2e2 and dff8e100a3275a138ebffeffd02327bc6458b2e4.

The parent REALITY lane has replaced the older AES-GCM implementation with ring. Keep that newer implementation when integrating: do not replay this branch's baseline transport/internet/reality/reality.rs AES-array migration over it. Use the rcgen signing_key migration wherever its current tests still access key_pair.

For Linux scenario validation, df2dfcd213d81c231d1630e933451bc8a827f10e cherry-picks the parent's committed e28be5b4fd5eee51c6e372e3eab649c91bc88466 test-lifetime fix. testing/scenarios/common.rs must preserve both retained Vec<Instance>/close-before-abort cleanup and rand 0.10's Rng/rng API. The parent already has the lifetime fix and should avoid applying it twice. No uncommitted files from the parent worktree were imported.

## SS2022 integration supplement

The SS2022 integration adds one root dependency: `shadowsocks-crypto 0.8.0`, with default features disabled and only `v2` enabled. A fresh official registry query confirms it is the newest non-yanked stable release; the exact evidence is appended to `DEPENDENCY_UPGRADE.json`. The current manifest census is 73 direct entries / 70 unique packages. Earlier 72-entry Linux reports above remain historical evidence for their own revision.

Ubuntu parity-preparation run `45893018658` at `1ea1cf2` resolved the new root lock conservatively. Its prepared manifest was byte-identical to the reviewed manifest before importing the lock at `c92390f`. The resolved crate checksum is `b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5`. This resolver pass is not a successful combined Rust compile/test claim; see `PORTING_STATUS.md` for later diagnostics and validation.

## Classic Shadowsocks engine addition

Official registry metadata checked 2026-11-26T21:20:44.600Z selects non-yanked stable shadowsocks 1.25.0, requiring Rust 1.91. The reviewed tagged manifest enables `aead-cipher-extra` and `security-replay-attack-detect` with default features disabled; the direct shadowsocks-crypto v2 selection remains unchanged. This reuses upstream classic AEAD/KDF and replay engines for all four pinned-Go classic methods. Source: https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks/Cargo.toml .

The current manifest census is 74 direct entries / 71 unique registry packages; the earlier 72-entry resolver and desktop results above remain historical. The SS2022 crypto engine was subsequently added before this classic engine. This classic addition awaits Linux lock resolution and integrated runtime tests; registry evidence is not compiler or interoperability evidence.

Conservative root lock resolution succeeded on Linux in run `45897529501`, source `ebd0da6564ef7d418d616feb019921d819b3ade8` on `port/classic-engine-lock`. The downloaded root manifest exactly matched the reviewed local manifest; lock SHA-256 is `e675edcb75dbc9fbd81a3eba0da39c3b82080dc182479f177290908780aeefa7`. No existing locked package was removed or upgraded; the engine and its new transitive packages were added. The approved rustls Git revision remains exact. The broader root/desktop resolver audit is separately pending in `45897791439`; compilation and runtime parity of the classic adapter remain unvalidated.

The first expanded-graph audit `45897791439` failed because `cargo update` selected newly published BLAKE3 1.8.8 while the recorded registry audit still required 1.8.7; desktop checking was skipped. All 71 official package records were rechecked, with BLAKE3 the only changed selection. The manifest and complete 74-entry audit now request 1.8.8. This is an evidence/requirement correction, not a weakened resolver check; a new Linux audit and lock are required.

Refreshed Linux resolver `45898502428`, source `7a5251f314ec362b6203376772ad4565fec04baf`, passed both audit commands: 69 direct root entries plus five desktop entries. Imported root lock SHA-256 is `4b05ea27496b36d81dcc9ebf1192365adf0254b27810796b08dbcaeea790e0f6`. Compared with the first classic preparation lock, only BLAKE3 1.8.7→1.8.8 and its `constant_time_eq` dependency 0.4.2→0.6.2 changed. The root rustls Git override remains exact; the unchanged desktop lock continues to resolve registry rustls 0.23.46. The desktop compile job remains separately pending; resolver success does not establish runtime or protocol parity.

Completed result: `45898502428` is SUCCESS at preparation source `7a5251f314ec362b6203376772ad4565fec04baf`. Both the root/desktop resolver audit and Linux Dioxus `cargo check --locked --all-targets` with strict warnings passed. This validates the resolver snapshot and desktop source; the following integrated classic/SS2022 source still requires its own ordinary, Clippy and interoperability runs.

### Combined-feature compiler regression and correction

Integrated source `292f689eaf3039e1ec2191e5d04dee6f8c259ae9` failed Linux check/release, strict Clippy and selected Rust test compilation (`45899217447`, `45899216622`, `45899216595`) inside upstream shadowsocks 1.25.0. Direct `shadowsocks-crypto/v2` unified the `CipherCategory::Aead2022` variant, while the classic engine dependency lacked its matching `aead-cipher-2022` cfg arms. Eleven upstream non-exhaustive matches prevented execution of Rust assertions. The tagged upstream manifest and source confirm that enabling the engine feature restores those arms. The engine dependency now also enables `aead-cipher-2022`; direct crypto `features = ["v2"]`, engine version, method dispatch and rustls override remain unchanged. A new Linux-generated lock and combined compile/test rerun are required. No Rust byte/live success is claimed for 292f689.

Linux preparation `45899647196` at isolated dependency source `308e8304c4f81c14c28f6b78dd300f3ee773585e` succeeded. The downloaded manifest exactly matches the reviewed feature correction. Imported lock SHA-256 `b5965930ce49da4ed90646850c9dc9033a6bb23890cdebd471df2d388769cb15` adds only `lru_time_cache` 0.11.11, with no locked package removals/upgrades; it also records the upstream feature-enabled edges to existing aes/rand packages. Direct entry census remains 74/71 unique; root rustls source pin is unchanged. This is resolver evidence pending integrated compiler/runtime confirmation.
