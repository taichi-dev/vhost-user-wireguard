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

## T12: TOML loader (src/config/toml.rs)

- `ConfigError::FileRead` is a struct variant `{ path: PathBuf, source: io::Error }`, NOT a tuple — must use named fields when constructing it.
- `Dhcp.reservations: Vec<DhcpReservation>` has no `#[serde(default)]`, so the minimal valid TOML must include `reservations = []` explicitly.
- `toml::from_str::<Config>` returns `toml::de::Error` which implements `From` for `ConfigError::TomlParse` via `#[from]`, so `?` works directly.
- `deny_unknown_fields` on all structs means top-level unknown keys (e.g. `unknown_key = "oops"`) cause a `TomlParse` error — confirmed by test.
- `tempfile::NamedTempFile` is already in dev-dependencies; use `write_all` then pass `.path()` to `load()`.

## T13: config/cli.rs — clap CLI override layer (2026-04-30)

- `#[derive(clap::Parser, Debug, Default)]` on CliArgs — Default needed for test construction with `..Default::default()`
- `ip_network::Ipv4Network` and `mac_address::MacAddress` both implement `std::str::FromStr`, so clap parses them directly via `Option<Ipv4Network>` / `Option<MacAddress>` fields
- Test module needs explicit imports: `use super::super::{Dhcp, DhcpPool, Network, VhostUser, Vm, Wireguard};` — `use super::*` only brings in `Config` and `CliArgs`/`apply_overrides` from cli.rs
- Pre-existing compile errors in `src/wg/keys.rs` (`StaticSecret` not Debug) prevent `cargo test --lib` from running all tests; use `cargo test --lib 'config::cli'` to filter and compile only the needed subset
- `cargo check` passes clean (0 errors, 0 warnings) after removing unused struct imports from the non-test scope
- 3 tests pass: test_no_overrides_unchanged, test_socket_override, test_listen_port_override

## T14: WireGuard Key Loader (keys.rs)

- `x25519_dalek::StaticSecret` does NOT implement `Debug` — avoid `{:?}` in assert messages for `Result<StaticSecret, _>`; use `.is_ok()` / `.is_err()` / `matches!()` without debug format
- `WgError::KeyBase64` uses `#[from] base64::DecodeError` — the `?` operator on `STANDARD.decode()` auto-converts via From, no manual mapping needed
- `WgError::KeyFileRead` has named fields `{ path, source }` — not a tuple variant
- `rustix::fs::stat()` returns `Stat` with `st_mode: u32`; mask with `& 0o077` to check group/world bits
- `rustix::fs::RawOsError` → `std::io::Error::from_raw_os_error(e.raw_os_error())` for conversion
- For test file permissions: `std::os::unix::fs::PermissionsExt` + `std::fs::set_permissions` works fine (rustix not needed in tests)
- `tempfile::NamedTempFile` keeps file alive while handle is in scope — assign to variable, not `_`

## T16: Atomic-write JSON lease persistence (src/dhcp/persist.rs)

- `DhcpError::LeaseFileIo` is a struct variant `{ path: PathBuf, source: io::Error }` — NOT a tuple variant; must use named fields
- `DhcpError::LeaseFileVersion` is a struct variant `{ version: u32 }` — NOT a unit variant; must pass `{ version: snap.version }`
- `SystemTime` has no serde support by default — use a custom `mod serde_system_time` with `serialize`/`deserialize` fns and `#[serde(with = "serde_system_time")]` on each `SystemTime` field
- `LeaseState` enum variants with `SystemTime` fields each need `#[serde(with = "serde_system_time")]` on the field individually
- Atomic write pattern: write to `<path>.tmp` → `sync_all()` → `fs::rename()` → open parent dir → `sync_all()` on dir
- `fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)` for creating parent dir with Unix permissions
- `std::os::unix::fs::DirBuilderExt` must be imported for `.mode()` on `DirBuilder`
- Corrupt file rename: `path.with_extension(format!("corrupt.{ts}"))` — note this replaces the existing extension; for `leases.json` it produces `leases.corrupt.TIMESTAMP` (not `leases.json.corrupt.TIMESTAMP`)
- `cargo test --lib dhcp::persist` compiles only the needed subset — passes even when other modules (options.rs) have pre-existing errors
- Pre-existing `cargo check` failure in `src/dhcp/options.rs` (`unresolved import ipnet`) is NOT caused by T16 changes
- 5 tests pass: roundtrip, missing_file, corrupt_json, wrong_version, atomic_write

## T19: ops/logging.rs — tracing-subscriber setup

- `LoggingError::InvalidFilter` has named fields `{ filter: String, source: ParseError }`, not a tuple variant — must use struct syntax when constructing.
- `tracing_subscriber::fmt().json().with_env_filter(filter).try_init()` returns `Result<(), impl Error>` — map_err to `LoggingError::AlreadyInstalled`.
- Global subscriber can only be set once per process; tests must accept `AlreadyInstalled` as a valid outcome on second call.
- Pre-existing compilation errors in `src/dhcp/options.rs` (E0507 move errors) and `src/ops/systemd.rs` (E0133 unsafe env var calls) block `cargo test` for the whole crate — not caused by logging.rs.
- `cargo check 2>&1 | grep "ops/logging"` returns empty = no errors in our file.

## T17: ARP responder (src/arp/mod.rs) — 2026-04-30

- ARP/Ethernet constants: `ETHERTYPE_ARP = 0x0806`, `ARP_OPERATION_REQUEST = 1`.
- `handle_arp_request` is a pure function: `&[u8] → Option<Vec<u8>>` — no I/O, no state.
- Flow: parse EthFrame → check ethertype=ARP → parse ArpPacket → check operation=REQUEST → check target_ip=gateway → build_arp_reply (sender=gateway, target=requester) → build_eth_frame (dst=vm_mac, src=gateway_mac).
- `?` operator on `EthFrame::new` and `ArpPacket::new` naturally handles malformed frames (returns `None`).
- 6 tests pass: gateway request returns reply, other IP ignored, ARP reply ignored, non-ARP ethertype ignored, malformed ETH frame, malformed ARP packet.
- `build_raw_arp_request` and `build_raw_eth_frame` test helpers replicate minimal wire format to avoid coupling test to production builders.
- `cargo test --lib arp` runs 6 tests + 3 existing wire/arp tests = 9 total, all passing.
- `cargo check` passes clean.

## T21: systemd.rs — sd_notify integration

- `sd_notify::notify(false, &[NotifyState::Ready])` returns `Ok(false)` when NOTIFY_SOCKET is not set — treat as success, not error.
- All notify functions are best-effort: log warnings on error, always return `Ok(())`.
- `WATCHDOG_USEC` env var holds microseconds; return `Duration::from_micros(usec / 2)` for half-interval pinging.
- Rust 2024 edition: `std::env::set_var` and `remove_var` are now `unsafe` — wrap in `unsafe {}` blocks in tests.
- `cargo test --lib ops::systemd` filters correctly to run only that module's tests.

## T15: DhcpOptionsBuilder (src/dhcp/options.rs) (2026-04-30)

- `ipnet` is a transitive dep of `dhcproto` but must be added explicitly to Cargo.toml to use directly
- `dhcproto::v4::DhcpOption::ClasslessStaticRoute` takes `Vec<(ipnet::Ipv4Net, Ipv4Addr)>` — typed, not raw bytes
- `ip_network::Ipv4Network::netmask()` returns `u8` (prefix length), NOT `Ipv4Addr` — name is misleading
- `ip_network::Ipv4Network::network_address()` returns `Ipv4Addr`
- `ipnet::Ipv4Net::new(addr: Ipv4Addr, prefix_len: u8)` — conversion from ip_network to ipnet is straightforward
- Builder pattern: methods must take `self` (not `&mut self`) and return `Self` for chaining to work with `build(self)`
- `dhcproto::v4::DhcpOption` variants: `Renewal` (58), `Rebinding` (59) — NOT `RenewalTime`/`RebindingTime`
- `DhcpOptions::get(OptionCode::X)` returns `Option<&DhcpOption>` — use for presence checks
- Broadcast address formula: `(gateway & mask) | !mask` — works cleanly with `u32::from(Ipv4Addr)`
- 6 tests pass: ack_has_lease_options, inform_excludes_lease_options, classless_routes_24, classless_routes_default, nak_has_message, builder_chaining

## T20: ops/caps.rs — Capability dropping and privilege reduction

- `rustix 0.38` has `setuid`/`setgid` in `rustix::thread::{set_thread_uid, set_thread_gid}` (NOT in `rustix::process`) — gated behind the `thread` feature
- `Uid`/`Gid` types are re-exported from `rustix::thread::{Uid, Gid}`; `rustix::ugid` is private
- `rustix::thread::Uid::from_raw(uid)` and `Gid::from_raw(gid)` are `unsafe` because they require a valid uid/gid value
- `rustix` functions return `rustix::io::Errno` (NOT `std::io::Error`) — call `.into()` to convert
- `rustix::thread::set_no_new_privs(bool)` is available for `PR_SET_NO_NEW_PRIVS`
- `caps::clear(None, CapSet::*)` clears capability sets for the current process; returns `CapsError` which implements `Display`
- `CapsError` tuple field is `pub(crate)` — can't access directly; use `e.to_string()` for error messages
- User/group lookup: parse `/etc/passwd` and `/etc/group` manually (line by line, colon-separated) since rustix has no `getpwnam`/`getgrnam`
- setgid MUST be called before setuid (can't setgid after dropping root privilege)
- 4 tests pass: test_drop_capabilities_no_panic, test_drop_privileges_no_user_no_group, test_drop_privileges_unknown_user, test_drop_privileges_unknown_group

## T18: ICMPv4 Type 3 Code 4 PMTU Generator (src/wire/icmp.rs)

- `build_icmp_frag_needed(original_ip_packet, next_hop_mtu, src_ip) -> Vec<u8>` builds a complete IPv4/ICMPv4 packet
- ICMP payload = original IP header + first 8 bytes of original IP payload (RFC 792)
- ICMP header layout: type(1) code(1) checksum(2) unused(2) next_hop_mtu(2)
- IPv4 wrapper: version=4, IHL=5, TTL=64, proto=1, src=gateway IP, dst=original sender IP
- Internet checksum: one's complement sum of 16-bit words; verifying a valid packet yields 0
- Pre-existing compile errors in src/ops/caps.rs (rustix Errno type mismatch) do not affect wire module tests
- `cargo test --lib wire::icmp` runs successfully in isolation despite top-level compile errors

## T24: Peer wrapper (src/wg/peer.rs) (2026-04-30)

- `boringtun::noise::Tunn::new(static_private, peer_public, preshared_key, persistent_keepalive: Option<u16>, index: u32, rate_limiter: Option<Arc<RateLimiter>>) -> Self` is INFALLIBLE.
  - `persistent_keepalive` is `Option<u16>` (NOT `Option<u32>` as the plan hinted) — pass through directly with no `.map(|k| k as u32)` cast.
- `boringtun::noise::TunnResult` variants (lifetime `'a` on the buffer): `Done`, `Err(WireGuardError)`, `WriteToNetwork(&'a mut [u8])`, `WriteToTunnelV4(&'a mut [u8], Ipv4Addr)`, `WriteToTunnelV6(&'a mut [u8], Ipv6Addr)`.
- `RateLimiter::new(public_key: &PublicKey, limit: u64) -> Self` returns `Self` (NOT `Arc<Self>`); caller must `Arc::new(...)`.
- `x25519_dalek::StaticSecret` derives `Clone` (under `static_secrets` feature), so `our_static_secret.clone()` works for moving into `Tunn::new` while keeping the original.
- `x25519_dalek::PublicKey: Copy` — pass by value freely.
- `ip_network::IpNetwork::contains<I: Into<IpAddr>>(&self, ip: I) -> bool` — works directly with `IpAddr::V4(ipv4_addr)`.
- Drain pattern uses `tunn.decapsulate(None, &[], out)` — empty datagram triggers `send_queued_packet`. Real traffic MUST pass `Some(src_addr.ip())` (rate limiter uses it).
- `current_endpoint`/`last_decap_at` updates ONLY fire on `WriteToTunnelV4` (data-plane after established session). Handshake responses produce `WriteToNetwork` and do NOT update endpoint — verified by test.
- Returning enums with `usize` (not `&'a mut [u8]`) avoids leaking the mut borrow of the output buffer through the Peer methods, so callers can use `out` after the call without lifetime gymnastics.
- `WireGuardError::ConnectionExpired` is the specific variant from `update_timers` that signals session death; all other Err variants from update_timers are best-mapped to `Done`.
- 8 tests pass: new_peer_created, allowed_ip_check_match, allowed_ip_check_no_match, encapsulate_produces_output, decapsulate_updates_endpoint, drain_returns_done, update_timers_no_panic, decapsulate_invalid_returns_err.

## T22: config/validate.rs — semantic validation collecting all issues (2026-04-30)

- `ip_network::Ipv4Network` has NO `prefix_len()` method — the prefix length is returned by `.netmask() -> u8` (name is misleading). Confirmed with source at `~/.cargo/registry/src/.../ip_network-0.4.1/src/ipv4_network.rs:140`.
- `Ipv4Network::network_address() -> Ipv4Addr` and `broadcast_address() -> Ipv4Addr` both work as expected for /30. For /31 the broadcast equals the second host (no distinction).
- `Ipv4Network::contains(ip)` includes BOTH the network and broadcast address — must filter those out separately (e.g. for `dhcp.pool.start != network_addr`).
- `mac_address::MacAddress` derives `Hash + Eq + Copy`, so `HashSet<MacAddress>` works directly for dedup.
- `MacAddress` Display uppercases hex (e.g. `52:54:00:AA:BB:CC` not `aa:bb:cc`) — keep test expectations uppercase.
- `Path::parent()` returns `Some("")` for relative bare filenames; check `parent.as_os_str().is_empty()` before calling `.exists()` to avoid spurious "does not exist" failures.
- `u16::is_power_of_two()` is provided directly by std for primitive integer types (no extra trait import).
- Validation pattern: collect issues into `Vec<String>`, run ALL checks unconditionally, return `Err(ConfigError::Validation { issues })` only at the end. Lets users see every problem in a single error report.
- For deduplicated string fingerprints (WG public keys), `HashSet<&str>` over `&peer.public_key.as_str()` avoids cloning while iterating.
- 30 tests pass: 1 happy-path, 16 rejection paths (one per check) plus multiple sub-cases (gateway=net OR gateway=bcast, mtu high vs low, queue_size three failure modes, both/neither WG keys), and a multi-issue test that asserts ≥4 issues collected at once.
- `cargo test --lib 'config::validate'` runs the filtered test set; `cargo check` exits 0 with no new warnings.

## T23: DhcpServer state machine (src/dhcp/mod.rs) — 2026-04-30

- `dhcproto::v4::Message`: use `set_opcode(Opcode::BootReply)`, `set_chaddr(&[u8])`, `set_yiaddr/set_ciaddr/set_giaddr/set_siaddr`, `set_xid`, `set_secs`, `set_flags`, `set_opts(DhcpOptions)`, `set_htype(HType::Eth)`.
- `Message::default()` sets opcode to `BootRequest` and gives a random `xid` — must override opcode when building replies.
- `dhcproto::v4::Flags::default().set_broadcast()` builds flag with broadcast bit set; `flags.broadcast() -> bool` reads it.
- `DhcpOptions::msg_type() -> Option<MessageType>` is the cleanest way to dispatch on option 53 (instead of matching on `get(OptionCode::MessageType)`).
- For `OptionCode::RequestedIpAddress` extraction: `match opts.get(OptionCode::RequestedIpAddress) { Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip), _ => None }`.
- DHCP REQUEST flavor dispatch (RFC 2131 §4.3.2):
  - SELECTING: option 54 set + option 50 set
  - INIT-REBOOT: no option 54, option 50 set, ciaddr=0 — match against existing lease, else NAK
  - RENEWING/REBINDING: no option 54, no option 50, ciaddr set — distinguish reply unicast/broadcast by `flags.broadcast()` (clients set this bit when broadcasting)
- For NAK: ALWAYS broadcast per RFC 2131 §4.3.2; set broadcast flag on the reply.
- For RENEWING ACK: unicast to ciaddr (not yiaddr=0; yiaddr stays as the lease IP).
- IPv4 header checksum: one's complement sum of 16-bit big-endian words, fold carries until ≤16 bits, then bitwise-NOT. Handles odd-length headers via shift-left-by-8 padding (not needed for fixed 20-byte IPv4 header but defensive).
- IPv4 prefix → subnet mask: `Ipv4Addr::from(!((1u32 << (32 - prefix_len)) - 1))`. Special-case `prefix_len == 0` (avoid `1u32 << 32` UB) and `>= 32` (return 255.255.255.255).
- `ip_network::Ipv4Network::broadcast_address()` returns the broadcast IP directly — simpler than computing it manually.
- UDP checksum is OPTIONAL for IPv4 — sending zero is RFC-compliant (RFC 768) and avoids the pseudo-header complexity. Receivers see this as "no checksum" and skip verification.
- `dhcproto::v4::Encoder::new(&mut buf)` borrows mutably; wrap in a `{ ... }` scope so the borrow drops before re-using `buf`.
- `Message::chaddr() -> &[u8]` returns slice of length `hlen` (typically 6 for Ethernet); convert to `[u8;6]` defensively with length check.
- For tests: `mac_address::MacAddress::from([u8; 6])` works directly; `MacAddress::bytes() -> [u8; 6]` returns the raw bytes.
- `DhcpServer::new` takes `Vm` struct (gets both `mac` and `mtu`) — cleaner than separate `vm_mac` + `mtu` fields. Spec said "add vm_mac as a field" but passing the whole `Vm` is cleaner since MTU is also needed for option 26.
- `tempfile::TempDir` for tests — leases.json path doesn't exist yet, so `LeaseFile::load()` returns empty snapshot.
- `LeaseStore::leases_for_snapshot()` added as `pub(crate)` helper to expose lease iteration for `checkpoint()` without leaking internal HashMap.
- 13 dhcp::tests pass: discover→offer, selecting→ack, init-reboot match→ack, init-reboot mismatch→nak, renewing unicast ack, rebinding broadcast ack, decline→probation, release→released, inform excludes lease opts, chaddr mismatch drops, unknown msg type drops, full DORA, checkpoint persists.
- `cargo check` clean; `cargo test --lib dhcp` 30 tests pass (5 lease + 6 options + 5 persist + 13 mod + 1 covered persist).
- Pre-existing clippy errors in `src/wg/routing.rs` (unwrap in tests) do not affect dhcp module — all my unwraps are inside `#[cfg(test)] mod tests`.

## T25: src/wg/mod.rs (WgEngine) — 2026-04-30

### vmm_sys_util 0.15 TimerFd API divergence from task spec
- Task spec referenced `TimerFd::new_custom(ClockId::Monotonic, false, false)` — this method does NOT exist in vmm_sys_util 0.15.
- `TimerFd::new()` is the correct API; it always uses `CLOCK_MONOTONIC | TFD_CLOEXEC` internally.
- Task spec referenced `timer_fd.read()` — actual API is `timer_fd.wait()` (returns `u64` of expirations; blocks if not yet expired, returns immediately when readable from epoll loop).
- Verified CLOCK_MONOTONIC at runtime by reading `/proc/self/fdinfo/<fd>` and asserting `clockid: 1`.

### Linux `IPV6_V6ONLY` MUST precede `bind(2)`
- `UdpSocket::bind("[::]:0")` followed by `set_ipv6_v6only(&socket, false)` returns `EINVAL` (errno 22).
- Workaround: build the socket via `rustix::net::socket(INET6, DGRAM, None)` → `set_ipv6_v6only(&fd, false)` → `rustix::net::bind(&fd, &addr)` → `UdpSocket::from(owned_fd)`.
- `std::net::UdpSocket: From<OwnedFd>` enables zero-copy hand-off after low-level setup.
- `rustix::net::SocketAddr` is re-exported from `core::net::SocketAddr` (same type as `std::net::SocketAddr`); pass `SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))` to `rustix::net::bind`.

### boringtun receiver_idx encoding
- `Tunn::new(... index: u32 ...)` stores `index << 8` as the seed for boringtun's local index allocator.
- Concrete consequence: for any incoming non-handshake-init datagram, `receiver_idx >> 8 == peer_idx_we_passed`. Used as a cheap lookup hint when `recv_idx_to_peer` cache is cold.
- HandshakeInit messages have NO receiver_idx field (only sender_idx) — single-peer fast path or `parse_handshake_anon` enumeration is required.

### rustix Errno ↔ std::io::Error
- `rustix::io::Errno: Into<std::io::Error>` — use `e.into()` directly, no manual `from_raw_os_error`.
- `vmm_sys_util::errno::Error` is NOT directly convertible; use `std::io::Error::from_raw_os_error(e.errno())`.

### Public key parsing reuses preshared parser
- `parse_preshared_key_base64` returns `[u8; 32]` which is exactly what `x25519_dalek::PublicKey::from([u8;32])` consumes.
- Avoids a redundant `parse_public_key_base64` helper in `wg::keys`.

### WgError::PeerNotFound semantics
- The `index: usize` field is currently used loosely — for "no route found" we pass `0` as a sentinel. Future revision could add a `NoRoute { dst_ip }` variant for clarity (out of T25 scope: error.rs untouched).
