# Learnings & Conventions

## Project: vhost-user-wireguard

## [2026-04-30] Session Start

### Architecture Constraints (from plan)
- Single-threaded datapath - NO Mutex<Tunn>, Arc<Tunn>, or RefCell<Tunn>
- Tunn owned by value inside PeerWrapper - &mut self from handle_event is sufficient
- NO async/tokio/futures anywhere
- Pure modules: wire/, arp/, dhcp/, wg/ - NO I/O. Only datapath/ and ops/ perform I/O
- NO trait-everything - only add trait when ≥2 implementations exist

### Dependency Pinning
- vm-memory MUST be exact-pinned: `vm-memory = "=0.17.1"`
- vhost-user-backend = 0.22 requires this exact version

### boringtun 0.7.0 API
- Tunn::new is INFALLIBLE (returns Self, not Result) - breaking change from 0.6.x
- Tunn::decapsulate after WriteToNetwork requires drain loop: decapsulate(None, &[], &mut dst) until Done
- RateLimiter requires Some(src_ip) as src_addr - NEVER pass None

### WireGuard Discipline
- WG peer endpoints are IP literals only (no DNS resolution)
- Daemon WG UDP socket binds :: with IPV6_V6ONLY=0 for dual-stack outbound
- 1Hz timer fd uses CLOCK_MONOTONIC (NOT CLOCK_REALTIME)
- Watchdog liveness gated by per-worker heartbeat counter

### DHCP Discipline (RFC 2131)
- DHCPINFORM response MUST NOT include options 51, 54, 58, 59
- DHCPDECLINE: declined IPs go into probation for dhcp.decline_probation_secs
- Only /30 subnets accepted in MVP

### vhost-user Discipline
- External fds (UDP socket, timer, exit eventfd) MUST be re-registered on every reconnect
- Token IDs > num_queues(); tokens 0..num_queues reserved for vrings
- VIRTIO_NET header is exactly 12 bytes (virtio_net_hdr_v1, NOT 10-byte legacy)
- Feature set: VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_MTU | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | VIRTIO_RING_F_EVENT_IDX
- NO offload features, NO CTRL_VQ, NO MQ

### Error Handling Rules
- NO unwrap()/expect() outside: main.rs init, tests, SAFETY-commented proven cases
- NO Box<dyn Error> in library code - use thiserror-derived errors
- NO as casts between numeric types (use try_from) - exception: as RawFd, as u8 after range check
- NO swallow errors with let _ = ... except documented fire-and-forget

### Naming Rules  
- NO generic names: data, tmp, result, value, item, info, obj, ctx
- NO abbreviations < 4 letters except: ip, mac, dhcp, arp, wg, udp, tcp, vm, tx, rx
- NO cfg for "config" - use config

### Logging Rules
- NO packet payloads, decrypted IP, WG handshake, DHCP payloads in logs
- Public keys logged as first 8 base64 chars + "..."
- info! for per-packet events FORBIDDEN - use trace!
- NO tracing::instrument on per-packet functions

### SPDX Headers Required
- Every *.rs file must start with: // SPDX-License-Identifier: MIT OR Apache-2.0

## T1: Project Scaffolding (2026-04-30)

- `cargo init --bin --name vhost-user-wireguard` creates src/main.rs + Cargo.toml; then edit Cargo.toml in-place
- `vm-memory = "=0.17.1"` exact pin required — vhost-user-backend 0.22 needs exactly 0.17.1
- Rust 2024 edition resolves cleanly with all listed deps (246 packages locked)
- All 7 module stubs (arp, config, datapath, dhcp, ops, wire, wg) compile as empty files with just SPDX header
- `cargo check` passes clean: `Finished dev profile [unoptimized + debuginfo]`
- Cargo.lock committed (binary crate convention)
- Git root commit: 6c2e3c3 — 22 files, 4800 insertions

## T3: error.rs

- `serde_json` was not in Cargo.toml from T1 — had to add `serde_json = "1"` to [dependencies]
- `dhcproto::error::DecodeError` and `dhcproto::error::EncodeError` are the correct error types for dhcproto 0.14
- `tracing_subscriber::filter::ParseError` is the correct type for `LoggingError::InvalidFilter`
- `base64::DecodeError` is correct for base64 0.22
- All error enums compile cleanly with thiserror derives

## T8: datapath/vnet.rs (2026-04-30)

- `virtio_net_hdr_v1` in virtio-bindings 0.2.7 has a bindgen anonymous union for csum fields:
  - Direct fields: `flags: u8`, `gso_type: u8`, `hdr_len: u16`, `gso_size: u16`, `num_buffers: u16`
  - `csum_start`/`csum_offset` are inside `__bindgen_anon_1.__bindgen_anon_1` (nested union/struct)
  - Must use `unsafe {}` to read `csum_start`/`csum_offset` from the union
  - To construct: use `virtio_net_hdr_v1__bindgen_ty_1 { __bindgen_anon_1: virtio_net_hdr_v1__bindgen_ty_1__bindgen_ty_1 { csum_start, csum_offset } }`
- `VIRTIO_NET_HDR_GSO_NONE` is `u32 = 0` — cast to `u8` is safe (value is 0)
- `virtio_net_hdr_v1__bindgen_ty_1` and `virtio_net_hdr_v1__bindgen_ty_1__bindgen_ty_1` must be imported explicitly
- Helper `make_anon(csum_start, csum_offset)` pattern avoids repeating the nested union construction
- `std::mem::size_of::<virtio_net_hdr_v1>()` == 12 confirmed by test
- 6 tests pass: size_is_12, round_trip, rx_header_num_buffers, tx_valid_gso_none, tx_invalid_gso_nonzero, parse_too_short

## T9: config/mod.rs type definitions (2026-04-30)

- `ip_network = "0.4"` does NOT enable serde by default — must use `ip_network = { version = "0.4", features = ["serde"] }`
- `mac_address = "1"` does NOT enable serde by default — must use `mac_address = { version = "1", features = ["serde"] }`
- Both `ip_network::Ipv4Network`, `ip_network::IpNetwork`, and `mac_address::MacAddress` have serde support behind feature flags
- `#[serde(deny_unknown_fields)]` on every config struct prevents TOML typos from silently being ignored
- No I/O, no sub-module declarations, no Default impls — pure type definitions only
- `cargo check` passes clean after enabling serde features on both crates

## T10: LeaseStore (src/dhcp/lease.rs)
- `Ipv4Addr::from(u32)` and `u32::from(Ipv4Addr)` work cleanly for pool range iteration
- `HashMap<[u8;6], Lease>` keyed by MAC; IP lookup requires `.values().find()`
- `HashMap::entry().or_insert()` used for bind to handle both new and existing leases
- `retain` on HashMap is clean for GC of expired Offered leases and probation entries
- `Duration::from_secs(u64::from(lease_secs))` avoids `as` cast for u32→u64
- Probation map `HashMap<Ipv4Addr, SystemTime>` checked before pool allocation
- `decline()` uses `leases.retain(|_, l| l.ip != ip)` to remove all leases for declined IP

## T11: AllowedIpsRouter (src/wg/routing.rs) (2026-04-30)

- `ip_network_table::IpNetworkTable<T>` API (v0.2.0):
  - `IpNetworkTable::new()` — creates empty table
  - `.insert(network: impl Into<IpNetwork>, data: T) -> Option<T>` — inserts, returns old value if replaced
  - `.longest_match(ip: impl Into<IpAddr>) -> Option<(IpNetwork, &T)>` — returns (matched_network, &data)
  - `.longest_match_ipv4(ip: Ipv4Addr) -> Option<(Ipv4Network, &T)>` — IPv4-specific variant
- For `lookup_v4`: use `longest_match(IpAddr::V4(ip)).map(|(_, v)| *v)` — destructure tuple, dereference value
- Longest-prefix match works correctly: /24 beats /8 for 10.0.0.x addresses
- 3 tests pass: test_lookup_match, test_lookup_no_match, test_longest_prefix_wins
- `cargo test --lib wg::routing` passes clean (0.67s compile)

## T2: CI + Dev Tooling (2026-04-30)

- `.github/workflows/ci.yml` uses 5 jobs: build, test, clippy, fmt, deny
- `EmbarkStudios/cargo-deny-action@v2` is the current major version for cargo-deny GHA action
- `dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2` is the standard Rust GHA combo
- clippy job uses `-D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::as_conversions` matching project error handling rules
- `deny.toml` allows: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS-2016, CC0-1.0, OpenSSL
- `.pre-commit-config.yaml` uses `repo: local` with system language hooks (no pre-commit managed envs)
- Both YAML files validated clean with `python3 -c "import yaml; yaml.safe_load(...)"`
- Commit: b0c8ef0 — 3 files, 100 insertions

## T4-T7: Wire parsers (eth/ipv4/udp/arp)

- Zero-copy parsers use `&'a [u8]` lifetime-bound structs; `new()` validates length, accessors use `try_into().unwrap()` safely
- `try_into().unwrap()` on fixed-size slices is acceptable in accessors when `new()` already validated the minimum length
- IPv4 `new()` checks: len >= 20, version == 4, len >= ihl*4
- ARP for IPv4/Ethernet is always 28 bytes fixed
- `cargo test --lib wire` ran 12 tests (3 per module), all passed
- No new Cargo.toml dependencies needed — only `std::net::Ipv4Addr` from std
