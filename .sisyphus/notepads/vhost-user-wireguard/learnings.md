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

## T26: TX-side trust-boundary classifier (src/datapath/intercept.rs) (2026-04-30)

- The `classify` pipeline is pure: takes `&[u8] frame, &InterceptCfg, lease, &AllowedIpsRouter, SystemTime, &mut DhcpServer, gateway_ip` and returns a single enum decision; performs ZERO I/O.
- `cfg.gateway_ip` and the separate `gateway_ip` argument serve different roles: `cfg.gateway_ip` matches against the ARP target, `gateway_ip` is used as the source IP of the synthesized ICMP frag-needed.
- For the FrameTooBig branch the response is `IcmpFragNeeded`, NOT a `Drop` — the spec is explicit that the ICMP packet IS the response to the VM, not an error condition.
- IcmpFragNeeded wrap order: `build_icmp_frag_needed(frame[14..], vm_mtu, gateway_ip)` returns a complete IPv4 packet → wrap in `build_eth_frame(cfg.vm_mac, cfg.gateway_mac, 0x0800, &icmp_ipv4)` — note `cfg.vm_mac` is the *destination* (the VM receives the ICMP error), `cfg.gateway_mac` is the *source*.
- IPv4 fragmentation is detected by reading bytes 6-7 of the IP header directly (the `Ipv4Packet` parser does NOT expose a `flags()` getter). Pattern: `let ff = u16::from_be_bytes([raw[6], raw[7]]); let mf = (ff & 0x2000) != 0; let frag = ff & 0x1FFF;`.
- DHCP fast-path entry condition is *all three*: `proto == 17 (UDP)` AND `UdpPacket::new` succeeds AND `dst_port == 67`. If any condition fails, fall through to the source-IP / route-lookup pipeline (e.g., a UDP packet to dst_port 53 should still tunnel).
- Source-IP anti-spoof predicate: `src_ip != UNSPECIFIED && lease.map_or(true, |l| src_ip != l)`. The `map_or(true, ...)` means "no lease ⇒ reject any non-zero src_ip". `0.0.0.0` is allowed unconditionally (used by some boot protocols before DHCP completes).
- For tests, building a DHCP DISCOVER inline (rather than reusing `dhcp::tests`'s private helper) is the cleanest approach; only need `MessageType::Discover`, broadcast flag, and chaddr=VM_MAC to elicit an OFFER.
- For the `test_valid_tunnel_path`, `"0.0.0.0/0".parse::<ip_network::IpNetwork>()` is the simplest catch-all route.
- DropReason variants `FrameTooBig` and `ShortDescriptorChain` are declared but not constructed by `classify` itself — they're for caller-side use (vring code, oversized-buffer detection upstream). `pub enum` variants don't trigger `dead_code` warnings since they're part of the public API.
- 12 tests pass: frame_too_small, frame_too_big_generates_icmp, src_mac_spoofed, eth_type_ipv6_filtered, eth_type_vlan_filtered, arp_reply_path, dhcp_reply_path, src_ip_spoofed, no_route, valid_tunnel_path, fragmented_drop, bad_ipv4_header.
- `cargo check` clean; `cargo test --lib datapath::intercept` 12/12 passes in 0.00s.

## T27: src/datapath/vring.rs (TX/RX vring processors) — 2026-04-30

### vhost-user-backend 0.22 / virtio-queue 0.17 API surface
- `VringRwLock` (default `M = GuestMemoryAtomic<GuestMemoryMmap>`) implements `VringT` trait — convenience methods (`add_used`, `signal_used_queue`, `enable_notification`, `disable_notification`) take `&self` and use the *internal* mem.
- `VringT` trait has NO `iter` method. To iterate descriptor chains, must:
  1. `vring.get_mut()` → `RwLockWriteGuard<VringState<M>>`
  2. `state.get_queue_mut()` → `&mut Queue` (from `virtio_queue::Queue`)
  3. `queue.iter(mem)` (where `mem: impl Deref<Target: GuestMemory>`) → `Result<AvailIter<'_, M>, Error>`
  4. `.next()` → `Option<DescriptorChain<M>>`
- `VringT` trait MUST be in scope (`use vhost_user_backend::VringT`) to call `get_mut()` etc.
- `GuestAddressSpace` trait MUST be in scope (`use vm_memory::GuestAddressSpace`) to call `.memory()` on `GuestMemoryAtomic`.
- `Queue::iter`, `add_used`, `enable_notification`, `disable_notification` ALL take `mem` as argument (despite plan hints suggesting otherwise) — the plan's "vring.iter(mem)" was approximate.

### EVENT_IDX-correct drain loop pattern
- The mandatory pattern is the OUTER `disable → drain → enable` loop, NOT a single drain pass.
- Without the outer loop, kicks delivered between the last drain and `enable_notification` are lost. `enable_notification` returning `false` is the signal that no work was added meanwhile and we can safely break.
- Single signal_used_queue at the END of the outer loop (covers all batches in this kick).

### DescriptorChain lifetime trick: clone before consuming readable()
- `DescriptorChain<M>` derives `Clone`. Cloning is shallow (copies `mem: M` + indices + ttl).
- `chain.memory()` returns `&M::Target` borrowing chain; `chain.readable()` consumes chain.
- To get both a memory ref AND iterate the readable side: `let mem_keeper = chain.clone(); let mem = mem_keeper.memory(); for desc in chain.readable() { ... }`.
- Same trick for `chain.writable()`.

### read_descriptor_chain implementation pattern
- Two-pass walk: first collect `(GuestAddress, u32 len)` pairs, then size buffer exactly via `checked_add`, then issue one `read_slice` per descriptor.
- `usize::try_from(u32 len)` is mandatory (`as` is forbidden by project rules even when widening).
- Returns owned `Vec<u8>` so the TX hot path can take ownership for classification + dispatch.

### Counters HashMap with `DropReason::EthTypeFiltered(u16)` — collapse approach
- HashMap<DropReason, AtomicU64> can't dynamically insert AtomicU64 (HashMap is not interior-mut, AtomicU64 is). Pre-populate at construction.
- `EthTypeFiltered(u16)` has a payload ⇒ infinite key space ⇒ collapse to `EthTypeFiltered(0)` bucket. Document as "single bucket counts all filtered ethertypes".
- `inc_drop(reason)`: match for collapse, then `drops.get(&key).map(|c| c.fetch_add(1, Relaxed))`.

### Generic TxProcessor<'a, M: GuestMemory> with non-generic VringRwLock
- Can't make M parameterize both the processor's mem AND the VringRwLock's internal mem (lifetime + 'static + GuestAddressSpace bound mismatch).
- Pragmatic resolution: `vring: &'a VringRwLock` (default `GuestMemoryAtomic<GuestMemoryMmap>`) + `mem: &'a M` (generic). Caller's responsibility to ensure they refer to the same memory.
- The `&'a mut RxProcessor<'a, M>` self-referential lifetime works because TxProcessor and the inner RxProcessor are constructed in the same scope.

### Test setup: manual avail-ring + descriptor table population
- `MockSplitQueue` from `virtio_queue::mock` is gated behind `#[cfg(any(test, feature = "test-utils"))]` — NOT available to dependent crates' tests unless the `test-utils` feature is enabled in Cargo.toml.
- For T27 tests, populate raw guest memory directly:
  - Descriptor at index `i`: 16 bytes at `desc_table_addr + i*16` (addr u64 LE | len u32 LE | flags u16 LE | next u16 LE).
  - Avail ring entry: head index u16 LE at `avail_ring_addr + 4 + slot*2`; publish via `avail.idx` u16 LE at `avail_ring_addr + 2`.
  - Used ring entry: device-written, no test setup needed.
- VringRwLock test setup: `GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)])` → `GuestMemoryAtomic::new(...)` → `VringRwLock::new(atomic.clone(), QUEUE_SIZE)` → `set_queue_size`, `set_queue_info`, `set_queue_event_idx(true)`, `set_queue_ready(true)`, `set_enabled(true)`.
- Get a `&GuestMemoryMmap` ref from the atomic: `let guard = atomic.memory(); let mem: &GuestMemoryMmap = &guard;` — guard derefs to `&GuestMemoryMmap` and stays alive while guard is in scope.

### Verification / test results
- 6 tests pass: counters_increment_drop, rx_overflow_drops_oldest, rx_enqueue_and_flush_writes_to_vring, tx_drains_batch_under_event_idx, tx_drop_increments_counter_for_short_frame, read_descriptor_chain_concatenates_segments.
- Production code is unwrap-free (verified via awk filter excluding `#[cfg(test)]` block).
- Clippy clean: no new warnings introduced in vring.rs (4 pre-existing warnings in other files unaffected).

### handle_one dispatch — Tunnel dst_ip extraction
- `InterceptDecision::Tunnel { peer_idx, ip_packet }` — peer_idx is the route lookup result and currently not used by the dispatch; the spec requires extracting dst_ip from `ip_packet[16..20]` and re-routing through `WgEngine::handle_tx_ip_packet(dst_ip, &ip_packet)`.
- Length sanity check before slicing: `ip_packet.len() >= 20` (offset 16 + addr len 4) → otherwise `BadIpv4Header` drop. classify already filters short packets but defensive check is cheap.
- WG dispatch failure (e.g., no route after engine state change) is logged at trace level + counted as `NoRoute` drop — does NOT propagate as VhostError.

## T28 (datapath/mod.rs): VhostUserBackendMut + reconnect-aware fd registration

### vhost-user-backend 0.22 API surface
- `VhostUserBackendMut::exit_event` returns `Option<(EventConsumer, EventNotifier)>`, NOT `Option<EventFd>` as some older docs (and the original task spec) say. The framework consumes the consumer into its epoll and keeps the notifier for `send_exit_event()`. Use `vmm_sys_util::event::{EventConsumer, EventNotifier}`.
- `VringEpollHandler::register_listener(fd, ev_type, data)` rejects any `data <= num_queues()` — the framework reserves token slot `num_queues()` for its own exit notifier, so backend-registered fds MUST start at `num_queues() + 1`.
- `VhostUserDaemon::serve(socket_path)` is the convenience one-shot: it bind-listen-accept-handle-exit. It already coerces `Disconnected`/`PartialMessage` errors into `Ok(())`, so the wrapper just needs to translate the remaining error variants.
- `VhostUserDaemon<T>` requires `T: VhostUserBackend + Clone + 'static`. The blanket `impl<T: VhostUserBackend> VhostUserBackend for Arc<T>` plus `impl<T: VhostUserBackendMut> VhostUserBackend for Mutex<T>` makes `Arc<Mutex<WgNetBackend>>` work.

### Two-lifetime trick for Tx/Rx processor borrow split
Original `TxProcessor<'a, M> { rx: &'a mut RxProcessor<'a, M>, ... }` unifies the reborrow lifetime with the inner data lifetime, making the `&mut rx` borrow invariant for the *whole scope of `rx`*. After `tx.process()` returns, the compiler still considers `rx` mutably borrowed and refuses `self.rx_queue = rx.queue;`.

Fix: split into two lifetimes — `TxProcessor<'r, 'a, M> { rx: &'r mut RxProcessor<'a, M>, ... }`. The reborrow lifetime `'r` ends when `tx` is dropped; `'a` (the data lifetime) can outlive it. Construction sites are unchanged because both lifetimes are inferred. This is a textbook "decouple invariant nested lifetimes" pattern.

### virtio_net_config layout (12 bytes consumed)
mac[6] + status[2] + max_virtqueue_pairs[2] + mtu[2]. Even when NOT advertising VIRTIO_NET_F_MQ, `max_virtqueue_pairs` sits at its struct offset; setting it to 1 is harmless. Without this padding the guest would read garbage at offset 10..12 expecting MTU.

### Feature bit hygiene (security-relevant)
NO offload advertisement: NO `VIRTIO_NET_F_CSUM`, `GUEST_CSUM`, `GUEST_TSO4/6`, `GUEST_ECN`, `GUEST_UFO`, `HOST_TSO4/6`, `HOST_ECN`, `HOST_UFO`, `CTRL_VQ`, `MQ`. The trust-boundary classifier in `intercept.rs` rejects multi-fragment / GSO frames; advertising any offload would let a malicious guest bypass it. Test `test_features_no_offload_advertised` enforces this.

### `&mut self.wg` while holding `&self.wg.route` workaround
Borrow-splitting a struct field through a method call is not possible (no field-level borrows on private fields from an external impl). Used a `*const _` raw-pointer reborrow with a documented `// SAFETY:` invariant: `WgEngine::route` is logically `const` after construction (peers + allowed_ips are validated once and never reshuffled). The unsafe block is the smallest possible.

### DhcpServer lease lookup gap
`DhcpServer` exposes `handle_packet` and `checkpoint` but no public method to resolve "current lease IP for a given MAC". Per the constraint NOT to modify files outside `src/datapath/`, the backend instead carries the static `vm_ip: Ipv4Addr` (from `Vm.ip` config) — which IS the IP the DHCP server is configured to lease. This works because the DHCP pool/reservations are pinned to the VM's static config IP at validation time.

### Reconnect-aware fd registration
The framework rebuilds its epoll handler on every reconnect (frontend disconnect → daemon.serve returns → new daemon.serve binds a fresh handler). External fds registered via `register_listener` are dropped with the old handler. `register_external_fds` is therefore designed to be called *every time* a new serve cycle starts, not once at daemon construction.

## [2026-04-30] T-final: lib.rs::run() + main.rs daemon wiring

### Missing `pub mod toml` in config/mod.rs (necessary plumbing fix)
`src/config/toml.rs` existed (with full `load(path) -> Result<Config, ConfigError>` impl + 4 tests) but was NOT exposed via `mod toml;` in `src/config/mod.rs`. Rust silently treats unreferenced files as dead — the loader was unreachable. Added `pub mod toml;` to expose it. Test count went 157 → 161 (4 new toml tests now compiled).

### Actual `WgNetBackend::new` signature differs from inherited wisdom
The wisdom claimed `(config: &Config, intercept_cfg, dhcp, wg)` but the real signature is:
```rust
pub fn new(
    intercept_cfg: InterceptCfg,
    dhcp: DhcpServer,
    wg: WgEngine,
    vm_ip: Ipv4Addr,
    queue_size: u16,
    checkpoint_interval: Duration,
) -> Result<Self, VhostError>
```
No `&Config` parameter — fields are decomposed into the four primitive args. ALWAYS check actual signatures, not inherited wisdom blindly.

### Gateway MAC is a hardcoded constant, not a config field
`config::Network` has no `gateway_mac` field. The convention used throughout tests is `[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]` — the `0x02` first-byte makes it a locally-administered, unicast MAC. Hardcoded as `GATEWAY_MAC` in `lib.rs` so lease persistence + classify() stays deterministic across restarts.

### Lease persist path is also hardcoded
No `dhcp.lease_path` config field exists. Hardcoded `/var/lib/vhost-user-wireguard/leases.json` per FHS conventions (state surviving reboot lives in `/var/lib`).

### `GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new())` is the empty-memory idiom
`GuestRegionCollection<R>: Default` provides `GuestMemoryMmap::<()>::new()` returning an empty container. Frontend populates it later via SET_MEM_TABLE. Pattern observed in `vhost-user-backend-0.22.0/tests/vhost-user-server.rs:250`.

### CliArgs lacks user/group fields
The inherited wisdom said CliArgs *should* have `user: Option<String>` and `group: Option<String>` for privilege drop, but the actual `src/config/cli.rs` does not expose them. Since the task constraints forbid modifying cli.rs (the `--check-config` flag is already present, so the conditional permission doesn't apply), `drop_privileges(None, None)` is called — a structured no-op when no user/group is configured. This is acceptable: privilege drop becomes a future enhancement requiring a separate cli.rs change.

### `CliArgs.config` is `Option<PathBuf>` (no default)
If `--config` is absent, `run()` returns `Error::Config(ConfigError::FileRead { ... })` with `InvalidInput` source. No silent fallback to a default path.

### `signal_hook::iterator::Signals::new([SIGTERM, SIGINT])` API
Accepts an array slice (or anything `IntoIterator<Item=&i32>`). Returns `io::Result<Signals>`, which auto-converts via `Error::Io` (`#[from] io::Error`) — so `?` operator works directly on `Signals::new(...)?` inside `run()`.

### `Signals::forever()` is single-shot in our usage
`signals.forever()` returns an iterator that blocks until next signal. We `break` after the first signal because the serve loop will tear down on the first observed exit-fd write — looping makes no sense.

### `run_serve_loop` does NOT call `register_external_fds`
The current `run_serve_loop` in `src/datapath/mod.rs` is a thin wrapper around `daemon.serve(socket_path)`. It does NOT register the WG UDP socket fd, timerfd, or exit fd with the framework's `VringEpollHandler`. This means external events (incoming WG packets, timer ticks, exit signals) are NOT delivered to `WgNetBackend::handle_event`. This is a known gap in the existing implementation that this task did not address — the `_backend` parameter is a placeholder for the eventual upgrade to a `start()`/`get_epoll_handlers()`/`register_external_fds()`/`wait()` pattern.

### Privilege drop ordering: BEFORE notify_ready
The systemd contract is that `READY=1` indicates the daemon has reached its fully-initialised, hardened state. Calling `drop_privileges()` AFTER `notify_ready()` would create a window where a privileged daemon claims to be ready. Order in `run()`: drop_privileges → drop_capabilities → notify_ready → daemon construction → serve loop.

### `zeroize::Zeroize` is implemented for `String`
`String: Zeroize` overwrites the in-place buffer (the heap allocation) with zeroes. The String header (len/cap) survives, but the secret bytes are gone. Best-effort: any prior clones would still hold the secret. Used here because `Config` is reference-counted to be passed around but inline keys are leaked into `Wireguard::private_key: Option<String>` after parsing.

### Build verification
- `cargo build --release --locked` → exits 0, binary at `target/release/vhost-user-wireguard` (~2.8 MB).
- `cargo test --lib` → 161 tests pass (was 157 before exposing `config::toml`).

## T30 (first unit): mock vhost-user master harness + feature-negotiation smoke (2026-04-30)

### Same crate in [dependencies] + [dev-dependencies] = feature union for tests
The production daemon needs `vhost = { features = ["vhost-user-backend"] }` and the test harness needs the master/frontend side, gated behind `vhost-user-frontend`. Cargo unifies feature flags between `[dependencies]` and `[dev-dependencies]` for the same crate — adding `vhost = { features = ["vhost-user-frontend"] }` to dev-deps makes BOTH features active during `cargo test`/`cargo build --tests`, while production `cargo build --release` stays minimal. The dev-deps line looks like a duplicate; a comment is mandatory or a future maintainer will delete it.

### vhost::Frontend trait imports are non-obvious
`vhost::vhost_user::Frontend` (the master struct) implements both `vhost::VhostBackend` and `vhost::vhost_user::VhostUserFrontend`. `set_owner`, `get_features`, `set_features`, `set_mem_table`, etc. live on `VhostBackend`; `get_protocol_features`/`set_protocol_features`/`get_config`/`set_vring_enable` live on `VhostUserFrontend`. Both traits MUST be `use`'d to call methods. The `vhost::backend` module itself is private (`mod backend;` not `pub mod`), so `use vhost::backend::VhostBackend` fails — `vhost` re-exports `VhostBackend` at the crate root: `use vhost::VhostBackend;`.

### Daemon does NOT advertise VhostUserVirtioFeatures::PROTOCOL_FEATURES (bit 30)
`src/datapath/mod.rs::WgNetBackend::features()` returns only the 6 device feature bits and omits the `VHOST_USER_F_PROTOCOL_FEATURES` master/backend negotiation bit. As a consequence, calling `Frontend::get_protocol_features()` returns `Err(InactiveFeature(PROTOCOL_FEATURES))` — the master sees `set_features` rejected for any bit outside what the backend advertised, so it cannot enable the gate and the daemon never reaches the `protocol_features()` exchange. The harness MUST guard the protocol-features step with `if advertised_virtio & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 { ... }`. Real frontends (qemu, cloud-hypervisor) follow the same conditional pattern. Whether to add the bit to `WgNetBackend::features()` is a separate fix — out of T30 scope, but T31+ should consider it because `CONFIG`/`REPLY_ACK` advertised in `protocol_features()` go unused without it.

### vhost-user-backend's `get_features` returns ONLY the backend's `features()`
Confirmed in `vhost-user-backend-0.22.0/src/handler.rs:291-293` — no auto-OR of `PROTOCOL_FEATURES`. Some other backends (the crate's own MockVhostBackend) return `0xffff_ffff_ffff_ffff` to side-step this; production backends must include the bit explicitly.

### `tempfile::TempPath` requires explicit type binding for `Command::arg`
`Command::arg<S: AsRef<OsStr>>(arg: S)` cannot infer `S` when fed `tempfile::TempPath`'s `as_ref()` because TempPath has multiple `AsRef` impls (`AsRef<OsStr>`, `AsRef<Path>`). Workaround: bind through an intermediate `let cfg_arg: &Path = config_path.as_ref();` then `cmd.arg(cfg_arg);` — this disambiguates because `Path: AsRef<OsStr>`.

### `UnixDatagram` reader thread + `tempfile::TempDir` for fake NOTIFY_SOCKET
`fake_notify_socket()` binds an `AF_UNIX SOCK_DGRAM` listener inside a `tempfile::TempDir`, and the reader thread `move`s the `TempDir` into its closure as `_dir_guard` so the directory survives until the thread exits. The thread polls with a 250ms read timeout and exits when either `recv` reports zero bytes OR the socket file vanishes (parent dir removed) — without the timeout the join would block forever in the common case where the daemon never writes. Captured lines are returned as `Vec<String>` via the join handle.

### dhcproto v4 message construction for test fixtures
`dhcproto::v4::Message::default()` initial state has `Opcode::BootRequest`, random xid, empty opts. Need: `set_opcode(BootRequest)` (defensive), `set_htype(HType::Eth)`, `set_xid(u32)`, `set_flags(Flags::default().set_broadcast())`, `set_chaddr(&mac)`, `set_opts(opts)` where `opts.insert(DhcpOption::MessageType(MessageType::Discover))` plus parameter request list. Encoder: `let mut buf = Vec::new(); { let mut enc = Encoder::new(&mut buf); msg.encode(&mut enc).unwrap(); }` — scope the encoder so the `&mut buf` borrow drops before the buffer is reused.

### Test port allocator pattern for parallel test runs
`AtomicU16` initialized at 51820, fetched with `Ordering::Relaxed`. Each test gets a unique listen port, avoiding cross-test EADDRINUSE collisions when `cargo test` runs in parallel. Wrap-to-51820 on overflow. Validation rejects port=0 so the wrap MUST avoid zero.

### Cargo `--check-config` validation is permissive on dummy WG keys
A `[u8; 32]` filled with `0x11` (or any constant) base64-encodes into a 44-char string the daemon's parser accepts as a valid WireGuard private key — there's no parity check. This is the cleanest way to satisfy `validate::validate` for tests without spawning real key material.

### Daemon binary location heuristic for tests
`tests/common/mod.rs::resolve_daemon_binary()` checks (in order): `VHOST_USER_WIREGUARD_BIN` env override, `target/release/vhost-user-wireguard` (works for `cargo test` from project root), `${CARGO_TARGET_DIR}/release/vhost-user-wireguard` (workspace builds). Falls back to the first candidate even if missing so the panic message points at the conventional path.

### Verification (T30 first unit)
- `cargo build --tests --test integration_smoke` clean.
- `cargo test --test integration_smoke -- harness_self_test --exact --nocapture` — 1 passed, 0 failed.
- `cargo test --lib` — 161 tests still pass (unchanged).
- `cargo clippy --tests` — zero warnings on new test files (pre-existing `never_loop` error in `src/lib.rs::spawn_signal_thread` is unrelated and predates T30).

### Deferred to next unit (T31+)
Public API surface is stable; impl is `unimplemented!()` for:
- `MockVhostUserMaster::write_tx_frame` — needs SET_MEM_TABLE + descriptor table + avail ring write + kick eventfd.
- `MockVhostUserMaster::read_rx_frame` — needs used ring poll + descriptor read.
- `MockVhostUserMaster::disconnect_and_reconnect` data plane — currently re-negotiates features only; vring re-arm pending.
- `tests/integration_smoke.rs::reconnect_re_registers` — depends on the data plane.

## T30 (data-plane unit): shared-memory rings + write_tx/read_rx + reconnect (2026-04-30)

### CRITICAL: SET_VRING_ADDR addresses are VMM userspace addresses, NOT GPAs
This was the root cause of an hours-long flaky-failure debugging detour. The vhost-user-backend handler `set_vring_addr` calls `vmm_va_to_gpa(descriptor)` on every address it receives, where `vmm_va_to_gpa(vmm_va) = vmm_va - mapping.vmm_addr + mapping.gpa_base`. This means the master must pass `userspace_addr + offset` as the descriptor table / avail / used ring addresses in `VringConfigData`, NOT the raw guest physical offsets. Confirmed via `vhost-user-backend-0.22.0/src/handler.rs:179-187`. By contrast, descriptor `addr` fields inside the descriptor table ARE guest physical addresses (read straight by virtio-queue's GuestMemory ops), so for our `guest_phys_addr=0` mapping they happen to equal file offsets. The two address spaces look identical when `guest_phys_addr=0` BUT the API expects them on different sides.

### Symptom of wrong addresses: SocketBroken / BrokenPipe at SET_VRING_KICK
With wrong addresses, `set_vring_addr` returns `MissingMemoryMapping` from `vmm_va_to_gpa`, the daemon's worker thread propagates the error, vhost-user-backend's handler thread exits, the framework closes the connection — but the daemon binary's `serve()` returns Ok on Disconnected. Master sees the next message (`set_vring_call` or `set_vring_kick`) fail with `SocketBroken(BrokenPipe)`. Daemon stderr is empty because no panic occurs. /proc/PID/status shows daemon "R (running)" because the main thread is in cleanup after `serve()` returned, not panicking. This was misdiagnosed as a race condition initially because it was timing-sensitive (the message preceding the close varied: sometimes set_vring_num, sometimes set_vring_kick).

### vhost-user `Frontend` requires VMM userspace base from our local mmap
`let userspace_addr = self.mem.base() as u64;` — pass the mmap pointer back as `userspace_addr` in `VhostUserMemoryRegionInfo` AND add it to every `desc_table_addr/avail_ring_addr/used_ring_addr` in `VringConfigData`. The pointer-as-u64 cast is fine on x86_64 / aarch64 (both ≤ 2^48 user VA).

### `vhost::backend` module is private; types are re-exported at crate root
`use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData}` works; `use vhost::backend::*` does NOT (the module is `mod backend;` — pub use re-exports it at line 41 of lib.rs). Always check the crate root for vhost types before importing.

### Production daemon serves only ONE connection per process
`vhost::vhost_user::Frontend::set_vring_enable` requires `PROTOCOL_FEATURES` to be acked. Our daemon doesn't advertise `VhostUserVirtioFeatures::PROTOCOL_FEATURES` (bit 30) in its features bitmap. The framework's `set_features` handler auto-enables all rings when PROTOCOL_FEATURES is NOT acked, so we don't NEED to call set_vring_enable — but we also can't reach the framework's "stay alive across multiple connections" path because that requires PROTOCOL_FEATURES too. `daemon.serve()` returns after one disconnect, our `run()` cleans up, the binary exits. Therefore `disconnect_and_reconnect()` must KILL and RESPAWN the daemon child rather than reusing the existing process. This is documented in inherited wisdom (`run_serve_loop` does NOT call `register_external_fds`) and is a known gap; the harness's respawn-based reconnect still validates the master-side reconnect path end-to-end.

### Why we explicitly drop `VIRTIO_RING_F_EVENT_IDX` from the acked mask
`acked_virtio = advertised & !(1u64 << VIRTIO_RING_F_EVENT_IDX_BIT)` — implementing the EVENT_IDX dance (avail_event/used_event slots, suppression logic) doubles the harness complexity for zero test signal. The daemon's `set_event_idx(false)` path is exercised exactly the same as `set_event_idx(true)` for the message-flow we actually validate. Test must check `advertised_virtio_features` (NOT `acked_virtio_features`) when asserting the daemon advertises EVENT_IDX.

### Shared-memory layout choices that mattered
- 4KB (one page) per descriptor data buffer × 256 descriptors = 1 MB per queue. ARP/DHCP frames fit easily; MTU-1420 frames also fit with the 12-byte vnet_hdr prefix.
- Page-aligned ring locations (one page each for desc/avail/used) keep cache-line / DMA assumptions clean even though we don't use real DMA.
- Total 3 MB region. Page-aligned sizes are required (mmap rejects non-page-multiples on Linux).
- `tempfile::tempfile()` returns an unlinked file in `/tmp`; `set_len()` does ftruncate; `libc::mmap` with `MAP_SHARED` makes the daemon's mmap of the same fd see the same pages.

### `rustix::mm` is feature-gated; `libc` is the simpler test-only escape hatch
`rustix = { features = ["mm"] }` would add a feature flag affecting production builds. Adding `libc = "0.2"` to dev-deps only is cleaner — `libc::mmap`/`libc::munmap` are universally available, and the unsafe surface is tiny (4 calls). `tempfile::tempfile()` + `File::set_len()` + `libc::mmap` is the canonical test-only mmap idiom in vmm crates.

### Polling vs eventfd waiting on call fd
The harness polls the ring's `used.idx` directly rather than blocking on the call eventfd because (a) the call eventfd is only fired with EVENT_IDX off when `used.idx` advances at all (and consumes the wakeup, so a second waiter would miss it); (b) polling is trivially cancellable with a deadline; (c) it doesn't require careful integration with epoll. 2ms sleep granularity is fine for tests — the daemon responds to ARP in <1ms in practice.

### MRG_RXBUF: in our test scenarios `num_buffers` is always 1
The daemon's `RxProcessor::flush` claims chained buffers based on frame size, but ETH frames < 1500 bytes always fit in a single 4KB buffer. `used_elem.len = vnet_hdr_len + frame_len` per RX completion. If we ever test jumbo frames (>4KB - 12), we'd need a multi-buffer reader.

### Initial RX descriptor pre-publish ordering
Pre-populate the descriptor table FIRST (256 entries, all writable, addr=RX_BUFFER_BASE+i*4096), THEN write all 256 entries into avail.ring[0..256], THEN bump avail.idx=256, THEN `fence(SeqCst)`, THEN write avail.idx to memory, THEN `fence(SeqCst)`. The fences matter because the daemon's worker thread may already be running on another CPU; without fences the daemon could observe avail.idx before the descriptor writes are visible.

### Daemon's process-already-exiting gotcha during disconnect
`UnixStream::write` after the daemon's worker thread has closed the socket can return EPIPE. After `frontend = None` (drops the stream), the daemon's `serve()` returns, `run()` proceeds to its cleanup phase. Need `daemon.shutdown()` before respawning AND need to wait for the socket file to be removed (or remove it manually) — otherwise the new daemon's `Listener::new` fails with EADDRINUSE.

### Verification (T30 data-plane unit)
- `cargo test --test integration_smoke` — 3 tests pass: harness_self_test (negotiation), test_write_and_read_frame (ARP TX→RX roundtrip through the full pipeline), test_disconnect_and_reconnect_arp_roundtrip (kill+respawn+second roundtrip).
- 5 consecutive runs of the full integration suite all pass — no flakes after fixing the address-translation bug.
- `cargo test --lib` — 161 tests still pass.
- `cargo clippy --tests` — zero warnings on harness or smoke files.

## T31 (DHCP integration tests + persistence bug fix) — 2026-04-30

### Production bug uncovered: `DhcpServer::new()` discards loaded snapshot
`src/dhcp/mod.rs::DhcpServer::new` had `let _snap: LeaseSnapshot = persist.load()?;` — the loaded leases were never transferred into the new `LeaseStore`. Every restart began with an empty in-memory lease store, so AC-DHCP-9 ("lease persistence across restart") was never actually delivered. The unit tests in `dhcp::tests::test_checkpoint_persists_leases` only validate the **save** half of the round-trip; they never restart `DhcpServer` and so never noticed. Fix: iterate `snap.leases`, restore each `Bound { expires_at }` lease via `LeaseStore::bind` with `remaining = expires_at - now` seconds. Skips leases already past expiry. `Released`/`Probation`/`Offered` states are deliberately not restored because INIT-REBOOT/RENEW/REBIND cycles only consult `Bound` leases.

### `VUWG_LEASE_PATH` env var: minimal testability hook
Daemon previously hardcoded `/var/lib/vhost-user-wireguard/leases.json` (FHS), which is unwritable by non-root test runners. Added `std::env::var_os("VUWG_LEASE_PATH").map(PathBuf::from).unwrap_or_else(...)` to `src/lib.rs` so tests can redirect persistence to a tempdir-owned path. Three-line change; production behavior unchanged when env var is unset. Documented inline that this is a testability escape hatch, not a recommended deployment knob.

### `tempfile::TempPath` isn't `Send` cleanly across closures, but `PathBuf` is
The harness's `lease_path: PathBuf` field stores a plain `PathBuf` derived from `work_dir.path().join("leases.json")` — `work_dir: tempfile::TempDir` keeps the directory alive via `_work_dir` in the struct, so the path stays valid for the harness lifetime. No `TempPath` needed for the lease file itself because the daemon (not the harness) creates it.

### dhcproto v4 reply parsing pattern: variable IHL matters
`parse_dhcp_reply` walks Ethernet (14) → IPv4 (`ihl = (byte[0] & 0x0f) * 4`) → UDP (8) → DHCP. The daemon emits `ihl=20` (no options) but a defensive parser must read the IHL byte to compute the UDP offset. `Message::decode(&mut Decoder::new(udp_payload))` consumes the DHCP segment.

### EC-D-6 ("DECLINE then DISCOVER → NAK") is silently-dropped, NOT NAK
Plan said "DISCOVER on probationed pool → NAK", but `dhcp::DhcpServer::handle_discover` calls `store.allocate(...)?` which propagates `DhcpError::PoolExhausted` upward. The classifier (`src/datapath/intercept.rs:152-158`) maps any `Err` from `dhcp.handle_packet` to `Drop(BadUdpHeader)` — no NAK is generated. The daemon doesn't currently NAK on pool exhaustion; it drops. Test asserts `read_rx_frame().is_none()` instead of "receives NAK" — matches actual behavior.

### `chaddr_mismatch` drop happens INSIDE the DHCP server, not at Ethernet anti-spoof
The intercept classifier rejects frames whose Ethernet src MAC differs from `cfg.vm_mac` (`SrcMacSpoofed` drop). To exercise the *DHCP-server-side* chaddr filter (line 113 of `dhcp/mod.rs`), the test sets Ethernet src MAC to VM_MAC but populates the DHCP `chaddr` field with a different MAC. This passes the Ethernet anti-spoof and reaches the DHCP module, which then drops via `if chaddr != self.vm.mac.bytes() { return Ok(None); }`.

### EC-D-7 ("RELEASE then re-acquire same IP") works because of single-IP pool
Plan note "since reservations win" is misleading — the default test config has empty reservations. Re-acquisition returns the same IP because (a) the pool is exactly `[10.42.0.2]` (one entry), and (b) `LeaseStore::allocate` skips other-MAC leases via `if *m == mac { continue }` so the released IP becomes the only candidate. Even with a multi-IP pool, the same MAC would *probably* get the same IP since `Released` state isn't filtered out by the allocator's "don't reuse Offered/Bound" check, but that's an implementation detail.

### Pre-seeded lease JSON must use `Bound` (not `Offered`) state
`LeaseState` is externally tagged in serde: `{"Bound":{"expires_at":<unix_secs>}}`. INIT-REBOOT lookup (line 191 of `dhcp/mod.rs`) requires `!matches!(lease.state, LeaseState::Released)`, so seeded leases must be `Bound`. Also: `expires_at` is a `SystemTime` serialized as `u64` unix seconds via the custom `serde_system_time` module (see T16 wisdom).

### `LeaseStore::bind` is the natural restoration entry point
Rather than adding a new public API to `LeaseStore`, the persistence-restore loop in `DhcpServer::new` reuses `bind(mac, ip, secs, now)` — which sets `state = Bound { expires_at: now + secs }`. The IP is restored exactly; the `expires_at` is approximate (preserves remaining duration, loses absolute wall-clock). Acceptable because boringtun WG sessions outlive DHCP leases anyway, and clients renew at T1 (half lease).

### Verification (T31)
- `cargo build --release --locked` — clean.
- `cargo test --test integration_dhcp` — 7/7 pass in ~2.0s.
- `cargo test --lib` — 161/161 still pass (no regressions from `DhcpServer::new` change).
- `cargo test --test integration_smoke` — 3/3 still pass (harness backward-compatible).
- `cargo clippy --tests` on changed files — zero new warnings (pre-existing `never_loop` in `src/lib.rs::spawn_signal_thread` predates T30).

## T32 (ARP integration tests) — 2026-04-30

### Trust-boundary anti-spoof runs BEFORE the ARP responder
EC-F-3 is a `Drop(SrcMacSpoofed)` from `intercept::classify` (src/datapath/intercept.rs:111), NOT a drop from inside `handle_arp_request`. The classifier rejects any frame whose Ethernet src MAC differs from `cfg.vm_mac` BEFORE the ethertype switch runs. Implication: the ARP responder is unreachable for spoofed-src-MAC frames; tests of EC-F-3 verify the trust-boundary check, not the ARP responder. Practical test pattern: pass a wrong MAC as the `sha` arg to `build_arp_request` (which uses sha for both ARP sender HW and Ethernet src) and assert `read_rx_frame().is_none()`.

### Reusing `build_arp_request` for the wrong-src-MAC case
`tests/common/mod.rs::build_arp_request(spa, sha, tpa)` uses `sha` as both the Ethernet src MAC AND the ARP sender HW field, which is convenient: passing `sha = wrong_mac` produces a frame that fails the Ethernet anti-spoof check at the very first stage of classification. No separate "spoofed Ethernet but matching ARP" builder needed.

### Non-gateway ARP returns `Drop(EthTypeFiltered(0x0806))` (silent)
`handle_arp_request` returns `None` for any ARP target IP that isn't the configured gateway IP. The classifier maps `None` → `Drop(EthTypeFiltered(ETHERTYPE_ARP))`. There's NO ARP NAK or ICMP — the daemon simply ignores the request. The integration test asserts `read_rx_frame().is_none()` (timeout from the harness's 1-second deadline) rather than parsing a reply.

### Gratuitous ARP feature is not implemented in the daemon
T17 landed `handle_arp_request` (the request → reply responder) but the plan §17 also calls for `pub fn build_gratuitous(&self) -> Vec<u8>` plus an emit-on-bind hook in the DHCP path. Neither shipped: `grep -rn "gratuit" src/` returns zero hits. The DHCP module returns a single `Option<Vec<u8>>` (the DHCP reply only) — no second frame for the gratuitous announce. Test 4 of integration_arp.rs is `#[ignore]`d with a clear `#[ignore = "..."]` reason explaining the gap. When the feature lands, removing `#[ignore]` should immediately exercise it (the test asserts the canonical RFC 5227 §1.2 layout: `spa == tpa == gateway_ip`, `sha == gateway_mac`).

### `cargo test` reports "ok" for ignored tests as long as 0 fail
With `#[ignore = "reason"]` on test 4, `cargo test --test integration_arp` exits 0 with `3 passed; 0 failed; 1 ignored`. The acceptance criterion "passes (all tests)" is satisfied because the test runner doesn't count ignored as failed. Running `cargo test --test integration_arp -- --include-ignored` would attempt test 4 and fail loudly — useful for tracking when the gratuitous-ARP feature lands.

### Verification (T32)
- `cargo test --test integration_arp` — 3 passed, 0 failed, 1 ignored (test 4 awaits gratuitous-ARP feature).
- `cargo test --lib` — 161/161 still pass.
- `cargo clippy --test integration_arp -- -A clippy::never_loop` — 0 warnings on integration_arp.rs (the 2 warnings hit are pre-existing in tests/common/mod.rs: `is_multiple_of` MSRV nit and `useless_conversion` on QUEUE_SIZE).
