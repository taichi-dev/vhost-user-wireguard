# vhost-user-wireguard - Userspace WireGuard vhost-user-net Daemon

## TL;DR

> **Quick Summary**: Build a Rust daemon that exposes a virtio-net (L2 Ethernet) device to one KVM/QEMU/Cloud-Hypervisor guest via vhost-user, tunnels guest traffic through WireGuard (userspace via boringtun), and serves DHCPv4 to the guest from a per-VM /30 micro-subnet. Configured via TOML with full CLI override. **One process per VM** (single-tenant by design).
>
> **Deliverables**:
> - Single Rust binary `vhost-user-wireguard` (lib + bin in one crate)
> - TOML schema with full CLI override surface (`--kebab-case` per leaf)
> - DHCPv4 server with static reservations + dynamic pool, JSON lease persistence
> - boringtun-backed userspace WireGuard with bidirectional peer config
> - Local ARP responder for the virtual gateway, ICMPv4 PMTU generation
> - Hostile-guest hardening: ethertype whitelist, MAC/IP anti-spoofing, frame-size enforcement
> - Capability-dropping privilege model + systemd notify/watchdog
> - Structured tracing logs (text + JSON)
> - GitHub Actions CI (build + test + clippy + fmt + cargo-deny), pre-commit hooks
> - Systemd template unit (`vhost-user-wg@.service`) + commented example TOML
> - Integration test suite + 1 smoke validation against real vhost-user-backend reconnect lifecycle
>
> **Estimated Effort**: Large (37 implementation tasks + 4 final-wave reviews)
> **Parallel Execution**: YES — 6 waves, 11/10/6/3/8/4 tasks per wave
> **Critical Path**: T1 → T9 → T12 → T22 → T26 → T27 → T28 → T29 → final reviews
> **License**: Dual MIT OR Apache-2.0
> **Build Target**: Linux x86_64 (glibc), latest-stable Rust MSRV

---

## Context

### Original Request

> "Need a project to provide networking using WireGuard for KVM virtual machines.
> 1. Should be a rust project
> 2. Use vhost-user
> 3. Have built in DHCP
> 4. use toml as config
> 5. All config params can also be specified in command line.
> 6. Ask me if I have something missing"

### Interview Summary (3 rounds)

**Round 1 — architecture (5 questions)**: Per-VM WireGuard identity. boringtun userspace WG. L2 Ethernet to guests. Static reservations + dynamic pool DHCP. IPv4 only.

**Round 2 — operational shape (6 questions)**: One UDP port per process, **one process per VM** (single-tenant). Per-VM /30 micro-subnet (isolated). Bidirectional WG via TOML peers (standard wg-quick semantics). DHCP leases persist (JSON), WG keys in TOML. Ops: tracing logs (text+JSON) + capability dropping + systemd notify/watchdog. NOT: Prometheus metrics, control socket, hot reload. Test: TDD with `cargo test`.

**Round 3 — repo & build (6 questions)**: License: dual MIT/Apache-2.0. Build target: Linux x86_64 glibc only. MSRV: track latest stable. vhost-user mode: server+client (configurable). CLI: typed clap flags (`--wireguard-listen-port 51820`). Dev tooling: GHA CI + cargo-deny + rustfmt + clippy + systemd template + pre-commit hooks (no Debian, no Docker).

### Confirmed Requirements R1–R21

R1 Rust. R2 vhost-user. R3 embedded DHCP. R4 TOML. R5 every param overridable on CLI. R6 boringtun. R7 L2 Ethernet to guest. R8 per-VM WG identity. R9 static reservations + dynamic pool. R10 IPv4 only. R11 one process per VM. R12 per-VM /30 micro-subnet. R13 bidirectional WG via TOML. R14 DHCP lease persistence via JSON; WG keys in TOML. R15 tracing logs (text + JSON). R16 capability dropping. R17 systemd notify/watchdog. R18 TDD with `cargo test` + agent-executed QA. R19 NO Prometheus metrics. R20 NO control socket. R21 NO hot reload.

### Metis Review (consolidated)

Metis identified **5 top-priority gaps** that have been addressed in this plan:

1. **Hostile-guest threat model** — added "Trust Boundary" specification (per-frame validation pipeline, ethertype whitelist, source-IP/MAC anti-spoofing, rate limits).
2. **Bootstrap and reconnect ordering** — `vhost-user-backend = 0.22` recreates `VringEpollHandler` per connection; external fds (UDP socket, timer, exit eventfd) MUST be re-registered on every reconnect. Captured as explicit task with smoke validation.
3. **Drop the `Mutex<Tunn>`** — single-threaded datapath; `Tunn` is owned by value inside the backend. The `Mutex` in earlier drafts was a cargo-cult from EasyTier (which IS multi-threaded).
4. **DHCP correctness on /30** — full state machine: DECLINE (with probation), RELEASE, INFORM (per RFC 2131 §4.3.5: NO lease/server-id options), INIT-REBOOT (NAK-vs-ACK decision).
5. **PMTU + frame-size end-to-end** — ICMPv4 Type 3 Code 4 generation when guest exceeds `vm.mtu`, `IP_DONTFRAG` on the WG UDP socket, config validation rejecting MTUs that don't fit, partial-RX-descriptor drop policy.

Plus source-verified facts now baked in:
- `boringtun = 0.7.0`'s `Tunn::new` is **infallible** (returns `Self`, not `Result`) — breaking change from 0.6.x
- `Tunn::decapsulate` after `WriteToNetwork` requires the **drain loop**: `decapsulate(None, &[], &mut dst)` until `Done`
- `RateLimiter` requires `Some(src_ip)` as `src_addr` — never pass `None`
- WG peer endpoints are **IP literals only** (no DNS resolution; rejected at config-load)
- Daemon WG UDP socket binds `::` with `IPV6_V6ONLY=0` for dual-stack outbound (guest stack remains IPv4)
- 1Hz timer fd uses `CLOCK_MONOTONIC`; boringtun internally uses `CLOCK_BOOTTIME`
- Watchdog liveness is gated by a per-worker heartbeat counter, not by main-thread liveness
- `vm-memory = "=0.17.1"` is exact-pinned by `vhost-user-backend = 0.22` — mirror the pin

---

## Work Objectives

### Core Objective

Ship a single, tested, statically-validated Rust binary that, given a TOML config and a vhost-user Unix socket, presents one virtio-net device to a guest VM, tunnels its traffic over WireGuard, and serves DHCPv4 — without requiring the kernel WireGuard module, without requiring root after init, and without external dependencies (no `dnsmasq`, no DB).

### Concrete Deliverables

- `target/release/vhost-user-wireguard` (single binary)
- `examples/example-vm.toml` (commented reference config exercising every TOML field)
- `packaging/systemd/vhost-user-wg@.service` (template unit)
- `README.md`, `CONTRIBUTING.md`
- `LICENSE-MIT`, `LICENSE-APACHE`
- `.github/workflows/ci.yml` (build + test + clippy + fmt + cargo-deny)
- `deny.toml`, `rustfmt.toml`, `clippy.toml`, `.pre-commit-config.yaml`
- 5+ integration test files in `tests/` covering DHCP, ARP, WG, hostile-guest, smoke

### Definition of Done

- [ ] All 37 implementation tasks pass their per-task acceptance criteria.
- [ ] All 4 final-wave reviews (F1–F4) APPROVE.
- [ ] User explicitly approves after seeing F1-F4 verdicts.
- [ ] `cargo build --release --locked` exits 0.
- [ ] `cargo test --locked --all-targets` reports `0 failed`.
- [ ] `cargo clippy --locked --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::as_conversions` exits 0.
- [ ] `cargo fmt --all -- --check` exits 0.
- [ ] `cargo deny check` exits 0.
- [ ] A real Linux guest under Cloud Hypervisor: boots, DHCPs, completes WG handshake, ICMP-pings a remote peer through the tunnel, evidence captured to `.sisyphus/evidence/`.

### Must Have

- One-process-per-VM model (no multi-VM tenancy in a single process)
- Single Rust binary, no kernel module dependency
- L2 Ethernet to guest with full ARP responder for the virtual gateway
- DHCPv4 with static reservations + dynamic pool + DECLINE probation + INFORM + INIT-REBOOT
- Lease persistence as atomic-write JSON (parent-dir fsync)
- boringtun userspace WireGuard, bidirectional peer config in TOML
- TOML config with `serde(deny_unknown_fields)` + typed clap CLI override per leaf
- Capability dropping after socket binds; `CAP_NET_BIND_SERVICE` not retained post-bind
- systemd notify (`READY=1`, `WATCHDOG=1`, `STOPPING=1`); worker-heartbeat-gated watchdog
- Structured tracing logs with text + JSON formatters
- ICMPv4 Type 3 Code 4 generation on oversized guest frames
- Dual-stack underlay: WG UDP socket binds `::` with `IPV6_V6ONLY=0`
- Vhost-user reconnect: external fds re-registered on every new connection
- Rate-limited handshake DoS protection (boringtun `RateLimiter` with `Some(src_ip)`)
- Trust-boundary enforcement: ethertype whitelist, src_mac == vm.mac, src_ip == leased_ip

### Must NOT Have — Hard Constraints (paste-ready guardrails for every task)

> The following constraints are **non-negotiable enforcement teeth**. The orchestrator (Sisyphus) will reject any task completion that violates them. They appear here once and are referenced from every task.

#### Architectural

- MUST NOT call vring, UDP socket, timer, or filesystem APIs from inside `wire/`, `arp/`, `dhcp/`, or `wg/` modules. These modules are **pure** (bytes/config in, decoded packets/decisions/outbound bytes out). Only `datapath/` and `ops/` perform I/O.
- MUST NOT use `Mutex<Tunn>`, `RefCell<Tunn>`, or `Arc<Tunn>` — single datapath worker owns each `Tunn` by value. `&mut self` from `VhostUserBackendMut::handle_event` is sufficient.
- MUST NOT trait-everything. `wire/`, `dhcp/`, `arp/` use concrete types. Add a trait only when ≥2 implementations exist or DI is required for testing that closures/generics cannot solve.
- MUST NOT introduce `async`/`tokio`/`futures` anywhere. The datapath is synchronous epoll. "Future-proofing" is forbidden.
- MUST NOT add a builder pattern unless the struct has ≥6 fields and ≥3 of them are optional.
- MUST NOT define traits in module A whose only impl lives in module B (premature abstraction).
- MUST NOT add `tracing::instrument` to any function called per packet (encap, decap, classify, write_vring, parse_*, build_*). Only on init/shutdown/config paths.

#### Error handling

- MUST NOT use `unwrap()` or `expect()` outside of: (a) `main.rs` and `lib.rs::run()` initialization, (b) tests, (c) construction-proven cases with a `// SAFETY:` comment naming the invariant. Hot paths (per-packet, per-WG-datagram) forbid `unwrap` absolutely; use `?`, `let .. else`, or explicit drop+log.
- MUST NOT use `as` casts between numeric types where truncation/sign change is possible. Use `u32::try_from(x)?`. Acceptable: `as RawFd`, `as u8` after explicit range check.
- MUST NOT use `Box<dyn Error>` or `anyhow::Error` in library code. Errors are `thiserror`-derived. `anyhow` is acceptable only in `main.rs` exit handler.
- MUST NOT swallow errors with `let _ = ...` except for documented fire-and-forget paths (e.g. best-effort `sd_notify`). Always either propagate with `?` or log with context.
- MUST NOT panic on any code path reachable post-`sd_notify(READY=1)` except via `unreachable!()` with documented invariant.

#### Naming

- MUST NOT use generic names `data`, `tmp`, `result`, `value`, `item`, `info`, `obj`, `ctx` for variables holding domain types. Use `frame`, `udp_datagram`, `ip_packet`, `lease_record`, `peer_state`, `tunn_result`, etc.
- MUST NOT abbreviate to fewer than 4 letters except: `ip`, `mac`, `dhcp`, `arp`, `wg`, `udp`, `tcp`, `vm`, `tx`, `rx`. No `cfg` for "config".

#### Logging

- MUST NOT log packet payloads, decrypted IP packets, WG handshake contents, DHCP option payloads (other than message-type and addresses), or private/preshared key material — at any log level.
- MUST NOT log fingerprintable identifiers in plaintext. Public keys are logged as first 8 base64 chars + "...". Private/preshared keys are NEVER logged.
- MUST NOT use `info!` for per-packet events. Per-packet → `trace!`. Per-event-loop iteration → `debug!`. Per-second-or-rarer state changes → `info!`.
- MUST NOT use `tracing` field formatting that allocates per packet. Stringify lazily via `tracing::field::display(...)` or precompute fingerprints.

#### Test discipline

- MUST NOT write tests for `serde` round-trips of `#[derive]`d types (already tested by serde). Exception: lease-file format (golden-file test required).
- MUST NOT write tests for `#[derive]`d traits (`Debug`, `Clone`, `Eq`).
- MUST NOT mock `dhcproto`, `boringtun`, or `vhost-user-backend`. Use real types; DI happens at the I/O boundary (UDP socket, timer, vring), not at parsing/crypto.
- MUST NOT add a fixture that re-implements `validate()` to bypass it. Tests go through `Config::from_toml` + `validate()`, or a `Config::for_testing()` constructor that itself calls `validate()`.

#### Dependencies

- MUST NOT re-implement parsing/serialization that exists in `dhcproto`, `boringtun`, `virtio-bindings`, or `vm-memory`. No hand-rolled DHCP option parser, no hand-rolled ChaCha20-Poly1305, no hand-rolled virtio header structs.
- MUST NOT add a dependency for a single helper function that fits in ≤30 lines of std-only Rust.

#### vhost-user discipline

- MUST NOT block the worker thread inside `handle_event`. All I/O is non-blocking.
- MUST NOT touch a vring before `update_memory()` has been called and `mem: Option<GuestMemoryAtomic>` is `Some`. UDP packets arriving before vring readiness are dropped.
- MUST NOT register external fds into the framework epoll BEFORE `VhostUserDaemon::start()` has accepted a frontend connection. Registration happens after `get_epoll_handlers()` returns non-empty handlers AND must be **repeated on every reconnect**. Token IDs > `num_queues()`; tokens 0..num_queues are reserved for vrings; token = num_queues is the framework exit event.
- MUST NOT advertise `VIRTIO_NET_F_CTRL_VQ`, `VIRTIO_NET_F_MQ`, `VIRTIO_NET_F_HASH_REPORT`, `VIRTIO_NET_F_RSC_EXT`, any GSO/TSO/USO offload feature, any `VIRTIO_NET_F_GUEST_*` or `VIRTIO_NET_F_HOST_*` offload feature in MVP. Reject these if the frontend negotiates them.
- MUST NOT use the legacy 10-byte `virtio_net_hdr`. With `VIRTIO_NET_F_MRG_RXBUF` always negotiated, the header is the 12-byte `virtio_net_hdr_v1`. On RX always set `num_buffers = 1`.

#### WireGuard discipline

- MUST NOT pass `None` as `src_addr` to `Tunn::decapsulate`. Always pass `Some(src_ip)`. Without it, the rate limiter cannot send cookie replies and the daemon is vulnerable to handshake flooding.
- MUST NOT skip the decapsulate-drain loop. After ANY `decapsulate` call returning `WriteToNetwork`, repeat with `decapsulate(None, &[], &mut dst)` until `Done`.
- MUST NOT trust `Tunn` to enforce AllowedIPs. After `WriteToTunnelV4(packet, src_ip)`, daemon explicitly checks `src_ip ∈ peer.allowed_ips`. Reject otherwise.
- MUST NOT use `CLOCK_REALTIME` for the daemon's 1Hz timer fd. Use `CLOCK_MONOTONIC`. NTP corrections must not perturb WG handshake cadence.

#### DHCP discipline

- MUST NOT include options 51 (Lease Time), 54 (Server ID), 58 (Renewal), 59 (Rebinding) in DHCPACK responses to DHCPINFORM (RFC 2131 §4.3.5).
- MUST NOT skip DHCPDECLINE handling. Declined IPs go into probation for `dhcp.decline_probation_secs` (default 86400) before re-offer.
- MUST NOT accept a DHCP REQUEST without verifying `chaddr` and (if present) option 61 against the existing lease. INIT-REBOOT REQUEST with non-matching IP gets NAK.

#### Configuration discipline

- MUST NOT accept any subnet other than /30 in MVP. /29, /31, /32 are rejected at config-load time with a specific error message naming the rejected prefix length.
- MUST NOT resolve hostnames in `wireguard.peer.endpoint`. Validation rejects any value that is not a valid `SocketAddr`.
- MUST NOT silently ignore unknown TOML keys. Use `serde(deny_unknown_fields)` on every config struct.
- MUST NOT accept WireGuard private-key or preshared-key **files** with mode permitting world or group read. Refuse to start if `mode & 0o077 != 0`. (Inline-key forms in TOML / `--wireguard-private-key` / `VHOST_USER_WG_PRIVATE_KEY` env var bypass this file-mode check — the operator owns securing the TOML file or environment in that case. Documented in README.)

#### Privilege discipline

- MUST NOT keep `CAP_NET_BIND_SERVICE` after the UDP socket is bound. Default `caps_keep = []` after the privilege-drop step.
- MUST NOT proceed past `sd_notify(READY=1)` until ALL of: config parsed and validated → keys loaded → vhost-user socket bound → WG UDP socket bound → lease store loaded (or initialized empty) → tracing subscriber installed → capabilities dropped → exit handler registered. Order is fixed.

### Must NOT Have — Scope-Out (forbidden additions to this MVP)

The following are explicitly OUT of scope and orchestrator rejects PRs proposing them:

#### Networking-stack creep
IPv6 inside the guest (DHCPv6, RA, ICMPv6/NDP, IPv6 routing). Multiqueue. VLAN/802.1Q. GSO/TSO/USO/GRO/LRO/checksum offload. Multicast routing, IGMP. BGP/OSPF/RIP. Bridge/switch behaviour, MAC learning across multiple ports. Connection tracking. QoS / shaping. DPI. TCP-MSS clamping.

#### WireGuard-stack creep
Kernel-WG fallback. Endpoint hostnames with DNS resolution. WG-over-TCP / WG-over-WebSocket. AmneziaWG / wireproxy / WG protocol obfuscation. Multiple WG instances per process. Per-peer rate-limit configuration knobs.

#### Operations creep
Prometheus `/metrics`. StatsD/OTLP exporters. Web UI / admin dashboard. HTTP/gRPC/JSON-RPC control plane. Unix-domain control socket. SIGHUP-triggered config reload. Live `wg-quick`-style on-the-fly peer add/remove. Live migration. Distributed lease coordination. HA/failover. GeoIP routing.

#### DHCP-stack creep
DHCPv6 server. Router Advertisements. DHCP relay/forwarding. Dynamic DNS update from DHCP (beyond echoing option 12). Per-host class-based options (dora's "client classes"). DHCPv4-over-IPv6. Encrypted lease file. SQL/SQLite/sled lease backend.

#### Config / tooling creep
TOML schema versioning beyond a single `schema_version` field. Backwards-compat parsing of older formats. YAML/HCL/JSON config alternatives. Separate `vhost-user-wg-validate` binary (validation runs on `--check-config` flag of the main binary). Auto-generation of TOML from CLI flags (`--save-config`). Web/HTTP-served config editing.

#### Test / build / packaging creep
musl static binary. Cross-compilation for aarch64/riscv64/ppc64le. Windows/macOS targets. Dockerfile/OCI images. Ansible/Salt/Puppet. Helm chart. snap/flatpak.

#### "While we're here" creep
- Refactoring rust-vmm crates upstream "since we found a bug." File the bug; do not fork.
- Re-implementing `sd_notify` "more cleanly" instead of using a published wrapper.
- A custom logging format "richer than tracing-subscriber's JSON."
- A custom `tokio` runtime swap-out (we don't have tokio).
- "Just adding seccomp" without a separate plan and threat-model review.

---

## Trust Boundary (Hostile-Guest Threat Model)

The guest is **untrusted**. Every frame leaving the TX vring is a potential attack. The daemon validates each frame through a fixed pipeline before it is allowed to mutate any host or peer state.

### TX-side per-frame pipeline (in order; first failure drops the frame)

1. **Descriptor sanity**: descriptor chain ≥ 14 (Ethernet) + 12 (vnet hdr) bytes; reject otherwise (`frame_too_small_drops`).
2. **Vnet header parse**: 12-byte `virtio_net_hdr_v1` extracted; `gso_type` must be `VIRTIO_NET_HDR_GSO_NONE`; reject otherwise (offload was rejected at feature-negotiation, this is defense-in-depth).
3. **Frame size cap**: total frame length (post-vnet-strip) ≤ `vm.mtu + 14`; if exceeded, **drop AND generate ICMPv4 Type 3 Code 4** with `next_hop_mtu = vm.mtu`, queue back to RX vring (PMTU signal).
4. **src_mac match**: source MAC == `vm.mac` (the MAC we advertised via `VIRTIO_NET_F_MAC`); reject otherwise (`src_mac_spoofing_drops`, warn 1/sec).
5. **Ethertype whitelist**: 0x0800 (IPv4) or 0x0806 (ARP) only; everything else (incl. 0x86DD IPv6, 0x8100 VLAN) drop (`eth_type_filter_drops`, trace 1/sec/type).
6. **ARP path**: ethertype = 0x0806 → ARP responder. ARP target IP must equal `network.gateway`; otherwise drop. Reply with daemon's `gateway_mac`.
7. **DHCP path**: ethertype = 0x0800 + IPv4 proto = 17 (UDP) + dst port = 67 → DHCP server. Source IP must be `0.0.0.0` (DISCOVER) or `vm.ip` (REQUEST/RENEW/RELEASE/INFORM/DECLINE).
8. **IPv4 routing path**: ethertype = 0x0800, not DHCP. Source IP must equal the leased IP for `vm.mac`; reject if not (`src_ip_spoofing_drops`). Exception: src_ip = 0.0.0.0 only allowed for DHCPDISCOVER, not for general traffic.
9. **AllowedIPs match**: dest IP must match a peer's `allowed_ips` (longest-prefix). If no match: drop (`no_route_drops`, debug 1/sec).
10. **Encapsulate**: `peer.tunn.encapsulate(ip_packet, &mut buf)` → send UDP datagram.

### RX-side per-datagram pipeline

1. **UDP recvfrom** the WG socket → datagram + source addr.
2. **Decapsulate**: `peer.tunn.decapsulate(Some(src_ip), datagram, &mut buf)` (always `Some`).
3. Handle `TunnResult`:
   - `WriteToNetwork`: send to peer's stored endpoint, then drain loop until `Done`.
   - `WriteToTunnelV4(packet, src_ip)`: verify `src_ip ∈ peer.allowed_ips`; if violation drop with warn (`wg_allowed_ips_violations`); if valid wrap in Ethernet (src=`gateway_mac`, dst=`vm.mac`, type=0x0800), prepend vnet header, queue on RX vring.
   - `WriteToTunnelV6(...)`: drop (IPv4-only daemon), debug log.
   - `Err(InvalidMac)`: drop, trace.
   - `Err(DuplicateCounter)` / `Err(InvalidCounter)`: drop, trace (normal under reordering).
   - `Err(NoCurrentSession)`: drop, debug. Timer will trigger handshake.
   - `Err(UnderLoad)`: programmer error (only with `None` src_addr) — error log + drop.
4. **Endpoint roaming**: on successful decap, if `src_addr` differs from peer's stored endpoint, **update** the stored endpoint.
5. **No-buffer drop**: if RX vring has no available descriptor, drop the packet (`rx_no_buffer_drops`); never block.

### Edge-case behaviour reference

> Each task that touches the datapath references the relevant EC-* identifiers. The complete table:

#### Frames (EC-F)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-F-1 | Ethertype not 0x0800/0x0806 | Drop, `eth_type_filter_drops`++, trace 1/sec/type |
| EC-F-2 | 802.1Q VLAN tag (ethertype 0x8100) | Same as EC-F-1 (no VLAN unwrapping) |
| EC-F-3 | src_mac ≠ vm.mac | Drop, `src_mac_spoofing_drops`++, warn 1/sec |
| EC-F-4 | Bad IPv4/UDP checksum | Drop, no recompute, counter |
| EC-F-5 | src_ip ≠ leased IP (with src_ip ≠ 0 exception for DHCPDISCOVER) | Drop, `src_ip_spoofing_drops`++, warn 1/sec |
| EC-F-6 | Frame > vm.mtu+14 | Drop + generate ICMPv4 T3C4 (next_hop_mtu=vm.mtu); `frame_too_big_drops`++ |
| EC-F-7 | Frame < 14 bytes | Drop, `frame_too_small_drops`++, debug |
| EC-F-8 | Descriptor chain too small for headers | Drop, counter, warn (likely buggy guest) |
| EC-F-9 | No RX descriptor available | Drop, `rx_no_buffer_drops`++, warn 1/sec; **never block** |

#### DHCP (EC-D)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-D-1 | dhcproto parse error | Drop, `dhcp_parse_errors`++, debug |
| EC-D-2 | DISCOVER from MAC ≠ vm.mac | Drop, `dhcp_unexpected_chaddr`++ |
| EC-D-3 | INIT-REBOOT REQUEST (no server-id, has option 50) | If lease matches: ACK with remaining lease time. Else: NAK ("lease not found / mismatch") |
| EC-D-4 | RENEWING REQUEST (ciaddr set, server-id present) | Extend lease, unicast ACK to ciaddr |
| EC-D-5 | REBINDING REQUEST (broadcast, ciaddr set, no server-id) | Extend lease, broadcast ACK |
| EC-D-6 | DHCPDECLINE | Mark IP "in probation" for `dhcp.decline_probation_secs` (default 86400). Probation → DISCOVER from same MAC gets NAK |
| EC-D-7 | DHCPRELEASE | Mark lease released; pool entry freed. Static reservations: lease entry removed but reservation remains |
| EC-D-8 | DHCPINFORM | Reply DHCPACK with requested options (subnet, router, DNS, MTU, broadcast, classless static routes, domain search). MUST NOT include 51, 54, 58, 59 (RFC 2131 §4.3.5) |
| EC-D-9 | Pool exhaustion (post-MVP > /30) | NAK with "no addresses available" |
| EC-D-10 | REQUEST with requested IP outside /30 | NAK |
| EC-D-11 | Burst > 1000 DHCP packets/sec from vm.mac | Rate-limit to ≤100 pps; excess silently dropped at debug; `dhcp_rate_limited`++ |

#### WireGuard (EC-W)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-W-1 | UDP from unknown peer (receiver_idx unknown) | Parse header for HandshakeInit; if `parse_handshake_anon` identifies a known peer, dispatch. Else drop, `wg_unknown_peer_drops`++ |
| EC-W-2 | Known peer pubkey, new src endpoint | Pass to `decapsulate`; if Ok: update peer.endpoint (roaming) |
| EC-W-3 | `Tunn::decapsulate` → `Err(InvalidMac)` | Drop, trace |
| EC-W-4 | `Err(UnderLoad)` | Programmer error (passed `None`); error log + drop |
| EC-W-5 | `Err(DuplicateCounter)` | Drop, trace (normal) |
| EC-W-6 | `Err(InvalidCounter)` | Drop, trace (normal) |
| EC-W-7 | `Err(NoCurrentSession)` | Drop, debug. Timer triggers handshake |
| EC-W-8 | `update_timers` → `Err(ConnectionExpired)` | Info log "wg_connection_expired_initiating_rehandshake"; `format_handshake_initiation(&mut buf, true)` and send |
| EC-W-9 | `decapsulate` → `WriteToNetwork` | Send to peer src_addr. Then drain: `decapsulate(None, &[], &mut dst)` until Done |
| EC-W-10 | `WriteToTunnelV4(pkt, src_ip)` | Verify src_ip ∈ allowed_ips. If yes: wrap Ethernet, prepend vnet, queue RX. If no: drop, `wg_allowed_ips_violations`++, warn |
| EC-W-11 | `WriteToTunnelV6(...)` | Drop (IPv4-only), debug |
| EC-W-12 | NTP -3600s clock jump | WG unaffected (CLOCK_BOOTTIME). DHCP lease expiry uses SystemTime — may immediate-expire; documented |
| EC-W-13 | Peer's UDP endpoint becomes unreachable | Handshakes time out per boringtun's REKEY_ATTEMPT_TIME (90s); ConnectionExpired retry; daemon does NOT re-resolve DNS |

#### vhost-user lifecycle (EC-V)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-V-1 | Frontend disconnects mid-operation | `serve()` returns Ok. Daemon **exits** (MVP choice; let systemd restart) |
| EC-V-2 | Frontend RESET_OWNER | Framework calls `reset_device()`. Vrings disabled. Flush pending RX (drop), keep WG state and DHCP leases |
| EC-V-3 | New SET_MEM_TABLE | Framework calls `update_memory(new_mem)`. Store new `Arc<GuestMemoryAtomic>`; in-flight reads finish on old memory (atomic swap is safe) |
| EC-V-4 | SET_VRING_BASE non-zero (resume) | Framework handles automatically; no daemon-side state |
| EC-V-5 | SIGTERM mid-encapsulate | Signal handler sets atomic; main writes to exit eventfd; worker drains in-flight; main joins worker; lease checkpoint written; exit 0 |
| EC-V-6 | SIGKILL | Lease file = last successful checkpoint. On restart: load, free expired, continue. Corrupt JSON → rename `.corrupt.<ts>` and start empty |

#### Filesystem (EC-FS)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-FS-1 | Lease checkpoint ENOSPC | Warn "lease_checkpoint_failed,error=ENOSPC,continuing"; in-memory authoritative; retry next interval |
| EC-FS-2 | Lease checkpoint EROFS | Same as EC-FS-1 |
| EC-FS-3 | Lease file corrupt JSON at startup | Rename `<file>.corrupt.<ts>`; warn; start empty |
| EC-FS-4 | Lease file parent dir missing at startup | Create with mode 0700; if EACCES error and exit non-zero |
| EC-FS-5 | Final lease checkpoint on SIGTERM hits ENOSPC | Log error; proceed to exit (do not hang) |

#### Time (EC-T)

| ID | Condition | Behaviour |
|----|-----------|-----------|
| EC-T-1 | Host clock backward 3600s | WG unaffected. DHCP leases pre-jump appear "in future" — remain valid until original expiration |
| EC-T-2 | Host clock forward 86400s | DHCP leases all appear expired → GC'd; clients renew. WG unaffected |
| EC-T-3 | Daemon uptime > 24.8 days | No-op; CLOCK_BOOTTIME and SystemTime are 64-bit |

---

## Verification Strategy

### Test Decision

- **Infrastructure exists**: NO (greenfield)
- **Decision**: **TDD with cargo test** (RED-GREEN-REFACTOR per task)
- **Framework**: `cargo test` (unit + `tests/` integration)
- **Per-task QA**: ALWAYS — every task has agent-executed QA scenarios in addition to unit/integration tests

### Per-task QA Tools

- **TUI/CLI verification**: `interactive_bash` (tmux) — start daemon, drive with stdin, observe stderr/stdout
- **Network verification**: `Bash` with `socat`/`tcpdump`/`ip`/`ss` — capture packets, verify routes, verify lease files
- **VM verification (smoke + final)**: `Bash` invoking `cloud-hypervisor` with vhost-user-net pointed at the daemon, plus a Linux guest image; verify guest behaviour via serial console
- **Library/Module unit tests**: `cargo test` per task; evidence is the test output redirected to a file

### Evidence Convention

All evidence files go to `.sisyphus/evidence/task-{N}-{slug}.{ext}`. Final-wave evidence goes to `.sisyphus/evidence/final-qa/`. Common types:
- `*.txt` — terminal output (daemon logs, cargo test output)
- `*.pcap` — packet captures
- `*.json` — lease files, parsed dhcproto messages
- `*.log` — structured tracing logs (text or JSON)

### Global Acceptance Criteria

> Run in CI for every PR; the orchestrator gates task completion on these as well.

#### Build / Lint / Static-Analysis

| ID | Verification | Expected |
|----|---|---|
| AC-BUILD-1 | `cargo build --release --locked` | exit 0 |
| AC-BUILD-2 | `cargo build --release --locked --all-targets --all-features` | exit 0 |
| AC-BUILD-3 | `cargo test --locked --all-targets` | "0 failed" |
| AC-BUILD-4 | `cargo clippy --locked --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::as_conversions -A clippy::unwrap_used::tests -A clippy::expect_used::tests` | exit 0 |
| AC-BUILD-5 | `cargo fmt --all -- --check` | exit 0 |
| AC-BUILD-6 | `cargo deny check` | exit 0 (advisories, bans, licenses, sources) |
| AC-BUILD-7 | `cargo doc --no-deps --locked` | exit 0, no warnings |
| AC-BUILD-8 | `grep -rE '\.unwrap\(\)\|\.expect\(' src/{datapath,wg,dhcp,arp,wire}/ \| grep -v '// SAFETY:'` | zero output |
| AC-BUILD-9 | `grep -rE '\bas (u8\|u16\|u32\|u64\|i8\|i16\|i32\|i64\|usize\|isize)\b' src/ \| grep -v '// SAFETY:' \| grep -v 'as RawFd'` | zero output |
| AC-BUILD-10 | `grep -rE 'tracing::instrument' src/{datapath,wg,dhcp,arp,wire}/` | zero output |
| AC-BUILD-11 | Every `*.rs` under `src/` starts with SPDX header `// SPDX-License-Identifier: MIT OR Apache-2.0` | enforced by script |
| AC-BUILD-12 | `cargo audit --deny warnings` | exit 0 |

#### Configuration

| ID | Verification | Expected |
|----|---|---|
| AC-CFG-1 | `./vhost-user-wireguard --config examples/example-vm.toml --check-config` | exit 0; stdout "config OK" |
| AC-CFG-2 | TOML with `network.subnet = "10.0.0.0/29"` | reject; stderr matches `subnet must be /30 \(got /29\)` |
| AC-CFG-3 | TOML with `network.subnet = "10.0.0.0/31"` | reject; stderr matches `subnet must be /30` |
| AC-CFG-4 | TOML with `wireguard.peer.endpoint = "hub.example.com:51820"` | reject; stderr matches `endpoint must be IP:port` |
| AC-CFG-5 | TOML with reservation IP outside subnet | reject; stderr matches `reservation .* outside subnet` |
| AC-CFG-6 | TOML with `dhcp.pool.start > dhcp.pool.end` | reject; stderr matches `pool start .* > pool end` |
| AC-CFG-7 | TOML with unknown top-level key (`[wirequard]`) | reject; stderr matches `unknown field 'wirequard'` |
| AC-CFG-8 | WG `private_key_file` mode 0644 | refuse to start; stderr matches `world or group readable` |
| AC-CFG-8b | TOML with both `wireguard.private_key_file` AND `wireguard.private_key` | reject; stderr matches `must specify exactly one of private_key_file or private_key` |
| AC-CFG-8c | TOML with neither `wireguard.private_key_file` nor `wireguard.private_key` | reject; stderr matches `must specify either private_key_file or private_key` |
| AC-CFG-8d | TOML with `wireguard.private_key = "<valid 32-byte base64>"` (inline) | accepted; daemon starts; no file-mode check performed |
| AC-CFG-8e | `VHOST_USER_WG_PRIVATE_KEY` env var set + TOML has neither file nor inline | accepted; key loaded from env |
| AC-CFG-9 | CLI `--vhost-user-socket /tmp/x.sock` overrides TOML | `ss -ln` lists `/tmp/x.sock` |

#### vhost-user lifecycle

| ID | Verification | Expected |
|----|---|---|
| AC-VU-1 | Cloud-Hypervisor frontend connects | device reports "up" within 10s; daemon log `event=vhost_user_ready` |
| AC-VU-2 | Frontend kill -9 + reconnect | log contains `event=frontend_disconnected` then `event=frontend_reconnected,fds_re_registered=true` within 5s; UDP traffic resumes |
| AC-VU-3 | virtio-net header is exactly 12 bytes | `cargo test --test integration_smoke -- --exact test_vnet_header_size_is_12` passes |
| AC-VU-4 | Daemon rejects unsupported features (MQ, CTRL_VQ, TSO/USO/GSO) | `cargo test --test integration_features -- --exact test_unsupported_features_rejected` passes |

#### DHCP — happy path

| ID | Verification | Expected |
|----|---|---|
| AC-DHCP-1 | Linux guest DHCPs | `ip -4 addr show eth0` shows leased IP within 10s; daemon log `event=dhcp_ack` |
| AC-DHCP-2 | After ACK, default route via gateway | `ip -4 route` shows `default via <gw>` |
| AC-DHCP-3 | After ACK, DNS configured | `cat /etc/resolv.conf` (or `systemd-resolve --status`) shows configured DNS |
| AC-DHCP-4 | `ping -c 3 <gateway>` from guest | 0% loss; daemon log shows 3 `event=arp_request_handled` |

#### DHCP — edge cases

| ID | Verification | Expected |
|----|---|---|
| AC-DHCP-5 | DHCPDECLINE handling | `event=dhcp_decline,probation_until=...`; subsequent DISCOVER within probation gets NAK |
| AC-DHCP-6 | DHCPRELEASE handling | lease marked released; subsequent DISCOVER receives same IP |
| AC-DHCP-7 | DHCPINFORM excludes 51/54/58/59 | `cargo test --test integration_dhcp -- --exact test_inform_response_excludes_lease_options` passes |
| AC-DHCP-8 | INIT-REBOOT ACK/NAK logic | `cargo test --test integration_dhcp -- --exact test_init_reboot_ack_match_and_nak_mismatch` passes |
| AC-DHCP-9 | Lease persistence across restart | restart < 500ms RTT to remembered IP |
| AC-DHCP-10 | Disk-full during checkpoint | log `event=lease_checkpoint_failed,error=ENOSPC`; daemon does NOT exit |

#### WireGuard

| ID | Verification | Expected |
|----|---|---|
| AC-WG-1 | Handshake with reference peer | log `event=wg_handshake_complete` within 3s |
| AC-WG-2 | ICMP echo through tunnel | `ping -c 5 <peer-ip>` 0% loss |
| AC-WG-3 | AllowedIPs enforcement | `cargo test --test integration_wg -- --exact test_allowed_ips_violation_dropped` passes |
| AC-WG-4 | Handshake-flood rate limiting | `cargo test --test integration_wg -- --exact test_handshake_flood_rate_limited` passes; ≤10 successful handshakes / 1000 attempts/sec |
| AC-WG-5 | Endpoint roaming | `cargo test --test integration_wg -- --exact test_endpoint_roaming` passes |
| AC-WG-6 | Replay protection | `event=wg_decap_replay_dropped` for duplicate packet |
| AC-WG-7 | Connection-expired re-handshake | `event=wg_handshake_initiated,reason=session_expired` after artificial expiry |
| AC-WG-8 | Decap-drain loop | `cargo test --test integration_wg -- --exact test_decap_drain_loop` passes |
| AC-WG-9 | Clock-jump immunity | `cargo test --test integration_wg -- --exact test_clock_jump_does_not_break_handshakes` passes |

#### Hostile guest

| ID | Verification | Expected |
|----|---|---|
| AC-SEC-1 | IPv6 frame from guest | dropped; `eth_type_filter_drops`++ |
| AC-SEC-2 | 802.1Q VLAN frame from guest | dropped; counter++ |
| AC-SEC-3 | IPv4 with src_ip ≠ leased | dropped; `src_ip_spoofing_drops`++ |
| AC-SEC-4 | Frame with src_mac ≠ vm.mac | dropped; counter++ |
| AC-SEC-5 | Jumbo frame (9000 bytes) with vm.mtu=1420 | ICMPv4 T3C4 generated; verified via `tcpdump -i tap0 'icmp[icmptype]==icmp-unreach && icmp[icmpcode]==4'` |

#### Privilege

| ID | Verification | Expected |
|----|---|---|
| AC-PRIV-1 | After daemon start | `cat /proc/$pid/status \| grep -E 'Uid\|Gid\|CapEff'`: Uid effective ≠ 0, CapEff = 0000000000000000 |
| AC-PRIV-2 | `getcap /proc/$pid/exe` | no file capabilities OR matches systemd unit |
| AC-PRIV-3 | Attempt to bind another privileged port | EPERM |

#### systemd

| ID | Verification | Expected |
|----|---|---|
| AC-SD-1 | `READY=1` sent exactly once | verified via `socat UNIX-RECV - \| grep -m1 READY=1` |
| AC-SD-2 | `WATCHDOG=1` at interval ≥ WATCHDOG_USEC/2 | ≥3 within 90s when WATCHDOG_USEC=30000000 |
| AC-SD-3 | Worker stall detection | block worker 60s → daemon killed by systemd (SIGABRT/SIGTERM) |
| AC-SD-4 | SIGTERM handling | `STOPPING=1` sent; exit 0 within 3s; final lease checkpoint written |

#### Performance (smoke)

| ID | Verification | Expected |
|----|---|---|
| AC-PERF-1 | Encap throughput single-thread | `cargo bench --bench encap_throughput` ≥ 1 Gbps (or ≥ 500 Mbps on GitHub runner) |
| AC-PERF-2 | DHCP DISCOVER → ACK round-trip | p50 < 100ms over 100 iterations |

#### Logging

| ID | Verification | Expected |
|----|---|---|
| AC-LOG-1 | 1Mpps stream for 10s at info level | log output < 1 MB |
| AC-LOG-2 | No secret leakage | `cargo test --test integration_log -- --exact test_no_secret_leakage` passes (greps the captured log for key bytes) |
| AC-LOG-3 | JSON log format | every line valid JSON via `jq -e .` |

#### License + headers

| ID | Verification | Expected |
|----|---|---|
| AC-LIC-1 | `LICENSE-MIT` and `LICENSE-APACHE` exist | files present at repo root |
| AC-LIC-2 | `Cargo.toml` license field | `license = "MIT OR Apache-2.0"` |
| AC-LIC-3 | SPDX header per file | enforced by AC-BUILD-11 |

---

## Execution Strategy

### Parallel Execution Waves

> Maximize throughput. Each wave completes before the next begins. Final-wave reviews run in parallel after ALL implementation tasks complete.

```
Wave 1 (11 tasks - START IMMEDIATELY, all independent):
├── T1:  Project scaffolding [quick]
├── T2:  CI + dev tooling [quick]
├── T3:  src/error.rs [quick]
├── T4:  src/wire/eth.rs [quick]
├── T5:  src/wire/ipv4.rs [quick]
├── T6:  src/wire/udp.rs [quick]
├── T7:  src/wire/arp.rs [quick]
├── T8:  src/datapath/vnet.rs [quick]
├── T9:  src/config/mod.rs (types only) [quick]
├── T10: src/dhcp/lease.rs [quick]
└── T11: src/wg/routing.rs [quick]

Wave 2 (10 tasks - depend only on Wave 1):
├── T12: src/config/toml.rs (depends T9) [quick]
├── T13: src/config/cli.rs (depends T9) [quick]
├── T14: src/wg/keys.rs (depends T3) [quick]
├── T15: src/dhcp/options.rs (depends T9) [quick]
├── T16: src/dhcp/persist.rs (depends T10) [quick]
├── T17: src/arp/mod.rs (depends T4, T7) [unspecified-low]
├── T18: src/wire/icmp.rs (depends T5, T6) [quick]
├── T19: src/ops/logging.rs (depends T3) [quick]
├── T20: src/ops/caps.rs (depends T3) [unspecified-low]
└── T21: src/ops/systemd.rs (depends T3) [quick]

Wave 3 (5 tasks - depend on Wave 2):
├── T22: src/config/validate.rs (depends T12, T13) [unspecified-high]
├── T23: src/dhcp/mod.rs (server state machine; depends T10, T12, T15, T16) [deep]
├── T24: src/wg/peer.rs (depends T11, T14) [unspecified-high]
├── T25: src/wg/mod.rs (engine; depends T24) [deep]
└── T26: src/datapath/intercept.rs (depends T17, T18, T23, T11) [unspecified-high]

Wave 4 (3 tasks - integration):
├── T27: src/datapath/vring.rs (depends T8, T26, T25) [deep]
├── T28: src/datapath/mod.rs (backend + reconnect; depends T27, T9) [deep]
└── T29: src/lib.rs + src/main.rs (depends T28, T19, T20, T21, T22) [deep]

Wave 5 (8 tasks - tests + packaging + docs):
├── T30: tests/common/ mock vhost-user master (depends T29) [unspecified-high]
├── T31: tests/integration_dhcp.rs (depends T30) [unspecified-high]
├── T32: tests/integration_arp.rs (depends T30) [unspecified-low]
├── T33: tests/integration_wg.rs (depends T30) [deep]
├── T34: tests/integration_sec.rs (depends T30) [unspecified-high]
├── T35: tests/integration_smoke.rs (VAL-1 reconnect; depends T29) [unspecified-high]
├── T36: packaging/ (systemd unit + example TOML) [quick]
└── T37: README + CONTRIBUTING + man-style docs [writing]

Final Wave (4 parallel reviews, then user explicit okay):
├── F1: Plan compliance audit [oracle]
├── F2: Code quality review [unspecified-high]
├── F3: Real manual QA against Cloud Hypervisor [unspecified-high]
└── F4: Scope fidelity check [deep]
→ Present consolidated results → Wait for user "okay" → Plan complete.

Critical Path: T1 → T9 → T12 → T22 → T26 → T27 → T28 → T29 → T35 → F1-F4 → user okay
Parallel Speedup: ~70% faster than sequential
Max Concurrent: 11 (Wave 1)
```

### Dependency Matrix (top-level)

| Task | Depends on | Blocks |
|------|------------|--------|
| T1–T11 | none | T12–T21 |
| T12 | T9 | T22, T23, T29 |
| T13 | T9 | T22, T29 |
| T14 | T3 | T24 |
| T15 | T9 | T23 |
| T16 | T10 | T23 |
| T17 | T4, T7 | T26 |
| T18 | T5, T6 | T26 |
| T19 | T3 | T29 |
| T20 | T3 | T29 |
| T21 | T3 | T29 |
| T22 | T12, T13 | T29 |
| T23 | T10, T12, T15, T16 | T26 |
| T24 | T11, T14 | T25 |
| T25 | T24 | T26, T27 |
| T26 | T17, T18, T23, T11 | T27 |
| T27 | T8, T26, T25 | T28 |
| T28 | T27, T9 | T29, T30 |
| T29 | T28, T19, T20, T21, T22 | T30, T35 |
| T30 | T29 | T31, T32, T33, T34 |
| T31–T34 | T30 | F-wave |
| T35 | T29 | F-wave |
| T36, T37 | T1 (so basically Wave 1) | F-wave |

### Agent Dispatch Summary

| Wave | # tasks | Categories used |
|------|---------|-----------------|
| 1 | 11 | quick × 11 |
| 2 | 10 | quick × 8, unspecified-low × 2 |
| 3 | 5 | unspecified-high × 3, deep × 2 |
| 4 | 3 | deep × 3 |
| 5 | 8 | unspecified-high × 5, unspecified-low × 1, quick × 1, writing × 1 |
| F | 4 | oracle, unspecified-high × 2, deep |

---

## TODOs

> **Implementation + Test = ONE Task. Never separate.**
> Every task includes: Recommended Agent Profile + Parallelization + References + Acceptance Criteria + QA Scenarios + Commit info.
> A task without QA Scenarios is INCOMPLETE and will be rejected by F1/F2.

- [x] 1. **Project scaffolding** — Cargo.toml, license files, .gitignore, repo skeleton

  **What to do**:
  - `cargo init --bin --name vhost-user-wireguard` in the working directory.
  - Edit `Cargo.toml`: set `[package]` `name`, `version = "0.1.0"`, `edition = "2024"`, `license = "MIT OR Apache-2.0"`, `description`, `repository`, `readme = "README.md"`, `categories = ["network-programming", "virtualization"]`, `keywords = ["wireguard", "vhost-user", "kvm", "dhcp", "virtio"]`. Add `[lib]` and `[[bin]]` entries pointing to `src/lib.rs` and `src/main.rs`.
  - Add the EXACT dependency set with pinned minor versions: `vhost = { version = "0.16", features = ["vhost-user-backend"] }`, `vhost-user-backend = "0.22"`, `virtio-queue = "0.17"`, `virtio-bindings = "0.2.7"`, `vm-memory = "=0.17.1"` (exact pin REQUIRED), `vmm-sys-util = "0.15"`, `boringtun = "0.7.0"`, `dhcproto = "0.14"`, `ip_network_table = "0.2"`, `ip_network = "0.4"`, `serde = { version = "1", features = ["derive"] }`, `toml = "0.8"`, `clap = { version = "4", features = ["derive", "env"] }`, `thiserror = "1"`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "fmt"] }`, `rustix = { version = "0.38", features = ["fs", "process", "net", "termios"] }`, `caps = "0.5"`, `sd-notify = "0.4"`, `mac_address = "1"`, `rand = "0.8"`, `base64 = "0.22"`, `x25519-dalek = { version = "2", features = ["static_secrets"] }`. Dev dependencies: `tempfile = "3"`, `assert_cmd = "2"`, `predicates = "3"`.
  - Add `[profile.release]` with `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`.
  - Write `LICENSE-MIT` (standard MIT) and `LICENSE-APACHE` (standard Apache-2.0 with appendix); add SPDX headers.
  - Create `src/main.rs` with placeholder `fn main() -> std::process::ExitCode { std::process::ExitCode::SUCCESS }` and SPDX header.
  - Create `src/lib.rs` empty placeholder with SPDX header.
  - Create empty module dirs as `mod.rs` stubs: `src/{config,datapath,wire,arp,dhcp,wg,ops}/mod.rs`.
  - Create `.gitignore` with `target/`, `Cargo.lock` for libraries (KEEP — this is a binary, so commit Cargo.lock), `.sisyphus/evidence/`, `*.swp`, `*.swo`.
  - Create `rustfmt.toml` (settings: `edition = "2024"`, `max_width = 100`, `imports_granularity = "Module"`, `group_imports = "StdExternalCrate"`).
  - Create `clippy.toml` (settings: `msrv = "1.85"` or whatever the latest stable is on day-of, `avoid-breaking-exported-api = true`).
  - Initialize git repo: `git init`, first commit.

  **Must NOT do**: Don't pull dependencies for one-liner helpers. Don't add `tokio`, `async-std`, `futures`, `anyhow` (anyhow only allowed in main.rs exit handler — but not yet). Don't add a workspace structure. Don't add Docker/Dockerfile. Don't pin patch versions of well-behaved crates (only `vm-memory` is exact-pinned). Don't use `*` or `^` version specifiers.

  **Recommended Agent Profile**:
  - **Category**: `quick` — Pure scaffolding; no logic.
  - **Skills**: `git-master` (initial commit + .gitignore hygiene).
    - `git-master`: needed for proper repo init + atomic first commit + .gitignore patterns.
  - **Skills Evaluated but Omitted**: `frontend-ui-ux` (no UI), `playwright` (no browser).

  **Parallelization**:
  - **Can Run In Parallel**: YES — Wave 1, no dependencies.
  - **Parallel Group**: Wave 1 with T2–T11.
  - **Blocks**: All other tasks (everyone needs Cargo.toml).
  - **Blocked By**: None (start immediately).

  **References**:
  - **Pattern**: rust-vmm `vhost-device-template` (https://github.com/rust-vmm/vhost-device/tree/main/template) — mirror its Cargo.toml structure exactly.
  - **External**: SPDX license list (https://spdx.org/licenses/MIT.html, /Apache-2.0.html) — standard text to copy. Rust 2024 edition stabilization notes (https://doc.rust-lang.org/edition-guide/rust-2024/index.html).
  - **WHY**: vhost-device-template has the canonical dependency configuration for vhost-user-backend 0.22; copying it exactly avoids version-skew bugs we already verified. SPDX texts are non-negotiable upstream-required content.

  **Acceptance Criteria** (TDD enabled):
  - [ ] `cargo test --lib wg::keys` passes (≥9 tests including 3 inline-form scenarios).
  - [ ] AC-CFG-8: refuse keyfile with mode 0644.
  - [ ] AC-CFG-8d: inline key string accepted without mode check.

  **QA Scenarios**:

  ```
  Scenario: Mode 0644 keyfile rejected with explicit error
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::keys::tests::reject_world_readable -- --exact --nocapture`
      2. Test creates tempfile, sets mode 0644, writes a valid base64 key, calls load_private_key, asserts Err(WgError::KeyFileMode { mode: 0o644, .. })
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-14-mode-reject.log

  Scenario: Mode 0600 accepted, key parses
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::keys::tests::accept_secure_mode -- --exact --nocapture`
      2. Test sets mode 0600, asserts Ok(StaticSecret) returned
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-14-accept.log

  Scenario: Fingerprint never reveals key bytes
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::keys::tests::fingerprint_is_short -- --exact`
      2. Test asserts fingerprint(pk).len() == 11 ("xxxxxxxx..." 8+3) AND no character of fingerprint matches the 9th+ char of full base64
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-14-fingerprint.log
  ```

  **Commit**: YES — `feat(wg): add WG key loader with strict file-mode check`. Pre-commit: `cargo test --lib wg::keys`.

- [x] 15. **src/dhcp/options.rs — DHCP option builder for ACK/OFFER/NAK**

  **What to do**:
  - `pub struct DhcpOptionsBuilder { ... }` wrapping `dhcproto::v4::DhcpOptions`.
  - Methods: `new(msg_type: dhcproto::v4::MessageType) -> Self`; `with_server_id(addr: Ipv4Addr)`; `with_lease_time(secs: u32)` (option 51); `with_renewal(secs: u32)` (option 58 = lease/2); `with_rebinding(secs: u32)` (option 59 = lease*7/8); `with_subnet_mask(mask: Ipv4Addr)`; `with_router(gateway: Ipv4Addr)`; `with_dns(servers: &[Ipv4Addr])`; `with_search_domains(domains: &[String])`; `with_mtu(mtu: u16)`; `with_classless_routes(routes: &[ClasslessRoute])`; `with_hostname(name: &str)`; `with_broadcast(addr: Ipv4Addr)`; `with_message(msg: &str)` (option 56 for NAK reason); `build() -> dhcproto::v4::DhcpOptions`.
  - Helper: `pub fn build_inform_response(server_id: Ipv4Addr, network: &Network, dns: &[Ipv4Addr], search: &[String], mtu: u16) -> DhcpOptions` — explicitly EXCLUDES options 51, 54, 58, 59 per RFC 2131 §4.3.5.
  - Unit tests: ACK contains 51/54/58/59; INFORM-response excludes 51/54/58/59 (AC-DHCP-7); NAK contains option 56 message; classless static routes encode correctly per RFC 3442 (compact form).

  **Must NOT do**: NO option 60 (vendor class) or 61 (client identifier) writes — those are client-only. NO option 82 (relay agent) — out of scope. NO encoding multiple identical options (e.g. two option-3 routers) — pack them into one.

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 2. **Blocks**: T23. **Blocked By**: T9.

  **References**:
  - **External**: RFC 2131 (esp. §4.3.5 for INFORM rules), RFC 2132 (option semantics), RFC 3442 (classless static routes encoding). dhcproto's `DhcpOptions` API.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib dhcp::options` passes (≥6 tests).
  - [ ] `cargo test --test integration_dhcp test_inform_response_excludes_lease_options` (placeholder until T31) — for now, `cargo test --lib dhcp::options::tests::inform_excludes_lease_options` passes.

  **QA Scenarios**:

  ```
  Scenario: ACK includes 51/54/58/59
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::options::tests::ack_has_lease_options -- --exact --nocapture`
    Expected Result: All 4 options present in built DhcpOptions
    Evidence: .sisyphus/evidence/task-15-ack.log

  Scenario: INFORM response excludes 51/54/58/59 (RFC 2131 §4.3.5)
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::options::tests::inform_excludes_lease_options -- --exact --nocapture`
      2. Build INFORM response; iterate options; assert NONE has code 51, 54, 58, or 59
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-15-inform.log

  Scenario: Classless routes encode per RFC 3442
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::options::tests::classless_routes -- --exact`
      2. Test inputs route 192.168.1.0/24 via 10.0.0.1; expects compact encoding [24, 192, 168, 1, 10, 0, 0, 1] (8 bytes)
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-15-classless.log
  ```

  **Commit**: YES — `feat(dhcp): add DHCP option builder with RFC 2131/2132/3442 compliance`. Pre-commit: `cargo test --lib dhcp::options`.

- [x] 16. **src/dhcp/persist.rs — atomic-write JSON lease persistence**

  **What to do**:
  - `pub struct LeaseFile { path: PathBuf }`. Methods: `new(path: PathBuf) -> Self`; `load(&self) -> Result<LeaseSnapshot, DhcpError>` (returns empty + warn-log on corrupt JSON, renaming the file to `<path>.corrupt.<unix_ts>` per EC-FS-3); `save(&self, snap: &LeaseSnapshot) -> Result<(), DhcpError>` (write to `<path>.tmp`, fsync the temp, rename to `<path>`, fsync the parent directory).
  - `pub struct LeaseSnapshot { pub leases: Vec<Lease>, pub probation: Vec<(Ipv4Addr, SystemTime)>, pub schema_version: u32 }`. Implement `From<&LeaseStore>` and `fn apply_to(self, store: &mut LeaseStore)`.
  - Schema version = 1. Future-incompatible loads return `Err`. `gc-on-load`: drop expired Bound leases.
  - Helpers: `ensure_parent_dir(path: &Path) -> io::Result<()>` — creates with mode 0700 if missing (EC-FS-4).
  - Unit tests: round-trip, partial-write recovery (simulate by writing the .tmp without rename), corrupt JSON triggers rename, missing parent dir gets created with mode 0700, ENOSPC simulated returns DhcpError but does not panic.

  **Must NOT do**: NO async file I/O. NO sled/sqlite/sqlx. NO ad-hoc binary format — JSON only. NO `unwrap` on permissions/metadata. NO `chmod` on existing files (only on creation).

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 2. **Blocks**: T23. **Blocked By**: T10.

  **References**:
  - **External**: `tempfile::NamedTempFile::persist` for the atomic-rename idiom — but use raw `fs` to control the parent-dir fsync explicitly. `rustix::fs::fsync`.
  - **Pattern**: `etcd`/`bolt` atomic-rename pattern: write-fsync-rename-fsync(parent).

  **Acceptance Criteria**:
  - [ ] `cargo test --lib dhcp::persist` passes (≥6 tests including ENOSPC simulation via tmpfs).
  - [ ] AC-DHCP-9 (persistence across restart) — covered by integration test in T31.

  **QA Scenarios**:

  ```
  Scenario: Save/load round-trip preserves all leases
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::persist::tests::round_trip -- --exact --nocapture`
      2. Test creates LeaseStore, populates 3 leases + 1 probation entry, saves to tempfile, loads new LeaseStore, asserts equivalent state
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-16-roundtrip.log

  Scenario: Corrupt JSON quarantined and load returns empty
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::persist::tests::corrupt_json_quarantined -- --exact --nocapture`
      2. Test writes invalid JSON to lease file, calls load, asserts result is empty AND <path>.corrupt.<ts> file exists
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-16-corrupt.log

  Scenario: ENOSPC during save returns Err without panic, does not corrupt existing file
    Tool: cargo test (with manual setup or feature-flagged tmpfs path)
    Steps:
      1. `cargo test --lib dhcp::persist::tests::enospc_preserves_existing -- --ignored --exact` (mark `#[ignore]` because needs root for tmpfs; orchestrator runs in CI with sufficient privs)
      2. Pre-populate /tmp/tiny-lease.json with valid snap; mount tiny tmpfs at /tmp/tiny-lease/; attempt save of larger snap; assert Err returned and original file unchanged
    Expected Result: Existing file preserved; Err returned with std::io::ErrorKind::StorageFull or similar
    Evidence: .sisyphus/evidence/task-16-enospc.log
  ```

  **Commit**: YES — `feat(dhcp): add atomic-write JSON lease persistence + parent-dir fsync`. Pre-commit: `cargo test --lib dhcp::persist`.

- [x] 17. **src/arp/mod.rs — ARP responder for the virtual gateway**

  **What to do**:
  - `pub struct ArpResponder { gateway_ip: Ipv4Addr, gateway_mac: [u8; 6] }`. Method: `pub fn handle_request(&self, eth_in: &[u8]) -> Option<Vec<u8>>`. Parses Ethernet → ARP; verifies request is for `gateway_ip`; if yes builds reply: Ethernet (dst=requester_sha, src=gateway_mac, ethertype=ARP), ARP reply (op=Reply, sha=gateway_mac, spa=gateway_ip, tha=requester_sha, tpa=requester_spa). Returns `Some(reply_bytes)` or `None` (drop).
  - Method: `pub fn build_gratuitous(&self) -> Vec<u8>` — for sending gratuitous ARP advertising the gateway MAC on lease-bind (helps guests with stale ARP caches).
  - Unit tests: well-formed request → valid reply, request for non-gateway IP → None, malformed ARP → None, gratuitous ARP has the right structure.

  **Must NOT do**: NO learning of guest MAC (already known from config). NO replies to ARP for any IP other than `gateway_ip`. NO ARP-spoofing detection — guest is already untrusted; we just don't help. NO IPv6 NDP (out of scope). NO support for non-Ethernet/non-IPv4 ARP.

  **Recommended Agent Profile**: `unspecified-low` — combines T4 + T7 outputs into a small state-free responder.

  **Parallelization**: Wave 2. **Blocks**: T26. **Blocked By**: T4 (eth), T7 (arp).

  **References**: RFC 826 §"Reply" packet construction.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib arp` passes (≥4 tests).

  **QA Scenarios**:

  ```
  Scenario: ARP request for gateway IP gets correct reply
    Tool: cargo test
    Steps:
      1. `cargo test --lib arp::tests::request_for_gateway -- --exact --nocapture`
      2. Test builds an ARP request from MAC=aa:..:01 spa=10.42.0.2 asking who-has 10.42.0.1; ArpResponder { gateway_ip=10.42.0.1, gateway_mac=02:..:fe } handles it; asserts reply has src=02:..:fe, dst=aa:..:01, op=Reply, spa=10.42.0.1, tpa=10.42.0.2
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-17-reply.log

  Scenario: ARP request for non-gateway IP returns None
    Tool: cargo test
    Steps:
      1. `cargo test --lib arp::tests::request_for_other_ip_dropped -- --exact`
      2. ARP for 10.42.0.99 returns None
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-17-drop.log
  ```

  **Commit**: YES — `feat(arp): add ARP responder for the virtual gateway`. Pre-commit: `cargo test --lib arp`.

- [x] 18. **src/wire/icmp.rs — ICMPv4 generator for fragmentation-needed (Type 3 Code 4)**

  **What to do**:
  - `pub fn build_dest_unreachable_frag_needed(src_mac: [u8;6], dst_mac: [u8;6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, next_hop_mtu: u16, original_packet: &[u8]) -> Vec<u8>`. Builds Ethernet + IPv4 + ICMPv4 (type=3, code=4), with the inner ICMP payload containing the offending IPv4 header + first 8 bytes of its data (per RFC 792). Sets `next_hop_mtu` in the unused field of the ICMP header (RFC 1191).
  - `pub fn build_echo_reply(...)` is OUT of scope (we don't impersonate hosts). Only ICMPv4 T3C4 generation is required for PMTU.
  - Unit tests: structure matches RFC 792 + RFC 1191 wire format; checksums correct; truncates inner-packet payload to header+8 bytes when input is larger; output frame is exactly 14+20+8+(20+8) = 70 bytes for a typical input.

  **Must NOT do**: NO support for other ICMP types/codes (no echo, no time-exceeded, no redirect). NO ICMPv6. NO sending of arbitrary ICMP — this is exclusively for PMTU response.

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 2. **Blocks**: T26. **Blocked By**: T5 (ipv4), T6 (udp).

  **References**:
  - **External**: RFC 792 (ICMP types/codes), RFC 1191 §4 (PMTUD message format with next-hop MTU in word 2).

  **Acceptance Criteria**:
  - [ ] `cargo test --lib wire::icmp` passes (≥3 tests including byte-layout verification against a hand-computed reference frame).

  **QA Scenarios**:

  ```
  Scenario: ICMPv4 T3C4 byte layout matches RFC 1191 reference
    Tool: cargo test
    Steps:
      1. `cargo test --lib wire::icmp::tests::frag_needed_layout -- --exact --nocapture`
      2. Test builds frame for src_ip=10.42.0.1, dst_ip=10.42.0.2, next_hop_mtu=1420, oversized packet; asserts byte layout: [eth(14)][ipv4(20)][icmp_type=3, code=4, checksum, unused=0, mtu=1420 (big-endian), inner_ipv4_hdr(20), inner_data(8)]
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-18-layout.log

  Scenario: Outer IPv4 + inner ICMP checksums both valid
    Tool: cargo test
    Steps:
      1. `cargo test --lib wire::icmp::tests::checksums_valid -- --exact`
      2. Test computes checksum over outer IP header (must verify to 0); test computes checksum over ICMP message (must verify to 0)
    Expected Result: Both checksums verify
    Evidence: .sisyphus/evidence/task-18-checksums.log
  ```

  **Commit**: YES — `feat(wire): add ICMPv4 Type 3 Code 4 generator (RFC 792/1191)`. Pre-commit: `cargo test --lib wire::icmp`.

- [x] 19. **src/ops/logging.rs — tracing-subscriber installation (text + JSON)**

  **What to do**:
  - `pub fn install(level: &str, format: LogFormat) -> Result<(), Error>`. Builds `tracing_subscriber::fmt` layer in either text or JSON mode based on `format`. Filter from `EnvFilter::try_new(level)?`. Sets the dispatcher globally via `set_global_default`. JSON mode uses `with_target(true).with_thread_ids(false).with_thread_names(false).with_file(false).with_line_number(false)` — minimal noise. Text mode uses default `with_target(false)` and ANSI when stderr is a TTY.
  - Helper `pub struct PubKeyFingerprint<'a>(pub &'a x25519_dalek::PublicKey)` implementing `tracing::Value` so log lines can write `peer = %fingerprint(pk)` cheaply (precomputes).
  - Verify that no log call inside the crate uses `info!` for per-packet events: provide a `clippy.toml` rule entry or a custom `#[deny(...)]` if feasible (otherwise enforce via grep in CI from T2).
  - Unit tests: install with text format succeeds; install with JSON format succeeds; double-install returns Err (or is a no-op, but document); fingerprint format `len() == 11`.

  **Must NOT do**: NO global state outside the dispatcher. NO panicking on install failure (return `Err` so `main.rs` can decide). NO log calls before `install()` is called (the dispatcher swallows them, but the SQL violates ordering). NO sensitive value logging — see Logging hard-constraints. NO `tracing-appender` writing to files (systemd captures stderr).

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 2. **Blocks**: T29. **Blocked By**: T3.

  **References**:
  - **External**: tracing-subscriber docs (https://docs.rs/tracing-subscriber/0.3) — fmt::Subscriber and EnvFilter sections.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib ops::logging` passes (≥3 tests).
  - [ ] AC-LOG-3: a smoke run of the daemon at `--ops-log-format=json` produces lines that all parse as valid JSON (verified at integration in T35).

  **QA Scenarios**:

  ```
  Scenario: JSON formatter emits one valid JSON object per line
    Tool: Bash
    Steps:
      1. Write a small example/test that calls `install(level="info", LogFormat::Json)` and emits 3 events with varied fields.
      2. Run via `cargo run --example log_smoke -- --json 2>&1 | tee .sisyphus/evidence/task-19-json.log`
      3. `while read line; do echo "$line" | jq -e . >/dev/null || (echo BAD: $line; exit 1); done < .sisyphus/evidence/task-19-json.log`
    Expected Result: jq exits 0 for every line; 3 events captured
    Evidence: .sisyphus/evidence/task-19-json.log

  Scenario: Per-packet trace events suppressed at info level
    Tool: cargo test
    Steps:
      1. `cargo test --lib ops::logging::tests::filter_suppresses_trace -- --exact --nocapture`
      2. Test installs with level="info", emits one trace! and one info! within the test, captures via tracing-test, asserts only info! is recorded
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-19-filter.log
  ```

  **Commit**: YES — `feat(ops): add tracing-subscriber installer (text + JSON)`. Pre-commit: `cargo test --lib ops::logging`.

- [x] 20. **src/ops/caps.rs — privilege drop (setgid/setuid + capability dropping)**

  **What to do**:
  - `pub fn drop_privileges(drop_user: Option<&str>, drop_group: Option<&str>, caps_keep: &[&str]) -> Result<(), PrivilegeError>`.
  - Sequence (each step on failure returns Err with a specific variant): (1) resolve user/group names to ids via `users` crate or `nix::unistd::User::from_name`. (2) `prctl(PR_SET_KEEPCAPS, 1)` so caps survive setuid. (3) `setgroups([gid])` (clear supplementary groups). (4) `setgid(gid)`. (5) `setuid(uid)`. (6) Build `caps::CapsHashSet` from `caps_keep` (e.g. `["CAP_NET_BIND_SERVICE", "CAP_SYS_NICE"]`) — empty set means drop all. (7) Apply via `caps::set(None, CapSet::Effective, &caps)`, `CapSet::Permitted`, `CapSet::Inheritable`. (8) `prctl(PR_SET_NO_NEW_PRIVS, 1)`. (9) Drop ambient caps. (10) Verify final state: read `/proc/self/status`, parse Uid/CapEff lines, assert match expected.
  - Helper `pub fn current_uid_gid_caps() -> Result<(u32, u32, u64), PrivilegeError>` for tests.
  - Unit tests: when invoked as non-root, `current_uid_gid_caps` returns the caller's identity; verify `prctl(NO_NEW_PRIVS)` is set after a no-op drop call (drop_user=None, drop_group=None, caps_keep=[]).
  - Integration tests (in T34/sec): full drop sequence requires root; gated `#[ignore]` and run by orchestrator with sudo.

  **Must NOT do**: NO retaining `CAP_NET_BIND_SERVICE` post-bind by default. NO drop-then-restore. NO running setuid/setgid in the wrong order (must be group first, then user). NO `unwrap` on libc/rustix calls. NO support for capabilities by raw integer — names only.

  **Recommended Agent Profile**: `unspecified-low` — small but careful syscall sequencing.

  **Parallelization**: Wave 2. **Blocks**: T29. **Blocked By**: T3.

  **References**:
  - **External**: `caps` crate docs. capabilities(7) man page. prctl(2) man page (PR_SET_KEEPCAPS, PR_SET_NO_NEW_PRIVS).
  - **Pattern**: virtiofsd's privilege-drop sequence (`virtiofsd/src/main.rs::drop_privileges`).

  **Acceptance Criteria**:
  - [ ] `cargo test --lib ops::caps` passes (≥3 non-privileged tests).
  - [ ] Integration test (in T34) verifies AC-PRIV-1, AC-PRIV-2, AC-PRIV-3.

  **QA Scenarios**:

  ```
  Scenario: NO_NEW_PRIVS bit set after a no-op drop
    Tool: cargo test
    Steps:
      1. `cargo test --lib ops::caps::tests::no_new_privs_set -- --exact --nocapture`
      2. Test calls drop_privileges(None, None, &[]); reads /proc/self/status; asserts NoNewPrivs: 1
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-20-nnp.log

  Scenario: Privileged drop sequence (root only, gated)
    Tool: Bash (orchestrator runs with sudo)
    Steps:
      1. `sudo cargo test --test integration_sec ops_caps_full_drop -- --ignored --exact --nocapture` — captured to .sisyphus/evidence/task-20-full-drop.log
      2. Test forks; child calls drop_privileges("nobody", "nogroup", &[]); child reads /proc/self/status and prints Uid + CapEff; parent asserts CapEff == "0000000000000000" and Uid line shows non-zero effective uid
    Expected Result: Test passes; evidence shows zero CapEff
    Evidence: .sisyphus/evidence/task-20-full-drop.log
  ```

  **Commit**: YES — `feat(ops): add privilege drop with setuid+capability shedding`. Pre-commit: `cargo test --lib ops::caps`.

- [x] 21. **src/ops/systemd.rs — sd_notify wrapper + watchdog with worker heartbeat**

  **What to do**:
  - `pub fn ready() -> Result<(), Error>` — sends `READY=1` via `sd-notify` crate. No-op (Ok) if `NOTIFY_SOCKET` env var unset (developer mode).
  - `pub fn stopping() -> Result<(), Error>` — sends `STOPPING=1`.
  - `pub fn watchdog_supported() -> Option<Duration>` — reads `WATCHDOG_USEC`, returns `Some(Duration::from_micros(usec / 2))` (half the requested interval, per systemd best practice).
  - `pub struct WatchdogPetter { period: Duration, heartbeat: Arc<AtomicU64>, last_seen: AtomicU64, exit_flag: Arc<AtomicBool> }`. Method `pub fn run(self)` loops: sleep `period`, read `heartbeat.load(Ordering::Acquire)`, if it changed since last_seen update last_seen and call `sd_notify("WATCHDOG=1")`, else SKIP the notify (worker is stalled — let systemd kill us). Exit when `exit_flag` set.
  - Helper `pub struct Heartbeat(Arc<AtomicU64>)`. `impl Heartbeat { pub fn pulse(&self) { self.0.fetch_add(1, Ordering::Release); } }` — called by the worker per epoll iteration.
  - Unit tests: `ready()` is a no-op when NOTIFY_SOCKET is unset; `watchdog_supported()` returns Some when WATCHDOG_USEC is set; `WatchdogPetter` skips notify when heartbeat is stuck (use a fake clock + capture sent messages via mocked socket — or alternately, just unit-test the decision logic without actually opening the socket).

  **Must NOT do**: NO blocking the main thread waiting for systemd. NO panicking on missing NOTIFY_SOCKET (developer mode = no systemd). NO writing to NOTIFY_SOCKET from inside the worker thread (only WatchdogPetter writes; everything else goes through it).

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 2. **Blocks**: T29. **Blocked By**: T3.

  **References**:
  - **External**: `sd-notify` crate docs. `sd_notify(3)` man page. systemd.service(5) for `Type=notify`, `WatchdogSec=`.
  - **Pattern**: systemd's own python-init's watchdog implementation.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib ops::systemd` passes (≥4 tests).
  - [ ] AC-SD-1, AC-SD-2, AC-SD-3 covered by integration tests in T35.

  **QA Scenarios**:

  ```
  Scenario: WatchdogPetter skips notify when worker heartbeat is stuck
    Tool: cargo test
    Steps:
      1. `cargo test --lib ops::systemd::tests::watchdog_skips_on_stalled_worker -- --exact --nocapture`
      2. Test creates Heartbeat shared with WatchdogPetter; never calls pulse(); runs petter for 3 iterations; asserts the mocked socket received ZERO WATCHDOG=1 lines
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-21-stall.log

  Scenario: WatchdogPetter pets when worker is alive
    Tool: cargo test
    Steps:
      1. `cargo test --lib ops::systemd::tests::watchdog_pets_when_alive -- --exact --nocapture`
      2. Test calls heartbeat.pulse() between each petter iteration; asserts mocked socket received N >= 3 WATCHDOG=1 lines
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-21-pets.log
  ```

  **Commit**: YES — `feat(ops): add sd_notify wrapper + heartbeat-gated watchdog`. Pre-commit: `cargo test --lib ops::systemd`.

- [x] 22. **src/config/validate.rs — semantic validation pass**

  **What to do**:
  - `pub fn validate(cfg: &Config) -> Result<(), ConfigError>`. Runs ALL checks; collects ALL errors into a `ConfigError::Validation { issues: Vec<String> }` so user sees the full list, not one-at-a-time.
  - Checks (with exact error message templates):
    1. **Subnet is /30** — reject `/29`, `/31`, `/32`, `/0..28` with `"network.subnet must be /30 (got /{n})"`.
    2. **Gateway is in subnet** — `"network.gateway {ip} is outside network.subnet {sub}"`.
    3. **Gateway ≠ network/broadcast** — `"network.gateway {ip} cannot be the network or broadcast address"`.
    4. **MTU range** — `vm.mtu` between 576 and 9000 (Ethernet practical range); reject `"vm.mtu {n} out of range [576, 9000]"`.
    5. **MTU vs WG overhead** — vm.mtu + 60 (IPv4 + UDP + WG overhead) ≤ 1500 typically (the host's WG-side path MTU). Warn (not reject) if too high; reject only if `vm.mtu > 1420` and user hasn't set `--ops-allow-large-mtu` (a boolean override).
    6. **DHCP pool subset of subnet** — pool start/end within subnet, pool start ≤ pool end, pool start > network address, pool end < broadcast.
    7. **DHCP reservation IPs in subnet** — each reservation IP within subnet AND not equal to gateway.
    8. **DHCP reservation MAC unique** — no two reservations share a MAC.
    9. **DHCP reservation IP unique** — no two reservations share an IP, no IP overlaps with pool.
    10. **WG private key source resolves** — EXACTLY ONE of `wireguard.private_key_file` and `wireguard.private_key` must be set; reject `"wireguard: must specify exactly one of private_key_file or private_key (got both)"` or `"wireguard: must specify either private_key_file or private_key (got neither)"`. If file form: defer to T14's mode check + load. If inline form: T14's parser validates base64 + length only. Same rule per peer for preshared (but with at-most-one semantics; both unset = no PSK).
    11. **WG endpoints are SocketAddr literals** — verified by serde's `SocketAddr` parsing (rejects hostnames at parse time); double-check no peer.endpoint string contains alphabetic characters.
    12. **WG peer public keys are unique** — no two peers with the same public key.
    13. **Listen port valid** — `wireguard.listen_port` ≠ 0 (auto-allocate is forbidden; must be deterministic for systemd port management).
    14. **vhost-user.socket parent directory exists** — `"vhost_user.socket parent dir {p} does not exist"`.
    15. **vhost-user.queue_size is power-of-2 between 64 and 4096** (virtio constraint).
    16. **vhost-user.num_queues is 1 or 2** — MVP supports 1 RX + 1 TX (= 2 by virtio convention) or 1 (control-only edge case rejected, so always 2).

  - Unit tests: every rejection path has a test with the exact stderr message; one happy-path test loads `examples/example-vm.toml` and passes.

  **Must NOT do**: NO actually opening the WG private key file here (T14's `load_private_key` does that on demand at the proper init step). NO touching the filesystem to test write permissions on the lease DB (it's allowed to not exist yet — daemon creates it). NO network reachability check on WG endpoints (out of scope; daemon doesn't control DNS/routing).

  **Recommended Agent Profile**: `unspecified-high` — many small rules but high attention-to-detail.

  **Parallelization**: Wave 3. **Blocks**: T29. **Blocked By**: T12, T13.

  **References**:
  - **Pattern**: dora-server's config validation — collects-all-errors-and-reports-once idiom.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib config::validate` passes (≥21 tests, including 3 new tests covering AC-CFG-8b/c/d for inline-key validation).
  - [ ] AC-CFG-2..6, 8b, 8c verified through unit tests.
  - [ ] Validation collects all errors at once (test that sets up a config with 5 issues and verifies all 5 appear).

  **QA Scenarios**:

  ```
  Scenario: All 16 validation rules have a corresponding rejection test
    Tool: Bash + cargo test
    Steps:
      1. `cargo test --lib config::validate -- --list 2>&1 | wc -l` (header + N tests; N >= 18)
      2. Run `cargo test --lib config::validate -- --nocapture` and capture to .sisyphus/evidence/task-22-validate.log
    Expected Result: Test count >= 18; all pass
    Evidence: .sisyphus/evidence/task-22-validate.log

  Scenario: Validation collects multi-issue errors
    Tool: cargo test
    Steps:
      1. `cargo test --lib config::validate::tests::collects_multiple_issues -- --exact --nocapture`
      2. Test feeds config with: subnet=/29, gateway outside subnet, listen_port=0; expects err with all 3 issues
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-22-multi.log
  ```

  **Commit**: YES — `feat(config): add semantic validation collecting all issues`. Pre-commit: `cargo test --lib config::validate`.

- [x] 23. **src/dhcp/mod.rs — DHCPv4 server state machine**

  **What to do**:
  - `pub struct DhcpServer { network: Network, dhcp_cfg: Dhcp, store: LeaseStore, persist: LeaseFile, last_checkpoint: Instant, gateway_mac: [u8;6] }`. Method: `pub fn handle_packet(&mut self, eth_in: &[u8], now: SystemTime) -> Result<Option<Vec<u8>>, DhcpError>`. Returns `Some(reply_bytes)` (full Ethernet frame ready for RX vring) or `None` (dropped).
  - State-machine logic per `DhcpOptions::get(MessageType)`:
    - **DISCOVER**: Allocate IP (reservation first, then pool). Set lease state=Offered, expires_at=now+60s. Build OFFER with 51/54/58/59 + subnet/router/dns/mtu/classless routes/hostname. Apply rate limit (EC-D-11): if vm.mac sent > 100 DHCP packets in last 1s, drop silently.
    - **REQUEST**: Determine flavor (SELECTING/INIT-REBOOT/RENEWING/REBINDING) per RFC 2131 §4.3.2 by inspecting server-id (54), requested-IP (50), ciaddr, broadcast flag.
      - SELECTING (server-id matches us, option 50 set): bind, ACK with full options.
      - INIT-REBOOT (no server-id, option 50 set): if lease record matches → ACK with remaining lease; else → NAK (EC-D-3).
      - RENEWING (no server-id, ciaddr set, unicast): extend lease, unicast ACK to ciaddr (EC-D-4).
      - REBINDING (no server-id, ciaddr set, broadcast): extend lease, broadcast ACK (EC-D-5).
    - **DECLINE**: Mark IP probation for `decline_probation_secs` (EC-D-6); log warn; no reply.
    - **RELEASE**: Mark lease released (EC-D-7); no reply.
    - **INFORM**: Build reply WITHOUT 51/54/58/59 (EC-D-8, AC-DHCP-7); use `build_inform_response`.
    - **Other** (BOOTREQUEST, etc.): drop.
  - **Rate limit**: token bucket per vm.mac, refill 100/sec, burst 200. Excess silently dropped at debug level.
  - **chaddr verification**: REQUEST/DECLINE/RELEASE/INFORM with `chaddr ≠ vm.mac` → drop (EC-D-2).
  - **Periodic checkpoint**: caller (T28) invokes `pub fn checkpoint(&mut self) -> Result<(), DhcpError>` from a 1Hz timer; checkpoint frequency configurable via `dhcp.checkpoint_secs`.
  - **GC**: each `handle_packet` call runs `store.gc(now)`.
  - Helpers: build full Ethernet+IPv4+UDP+DHCP frame (server→client direction). Source MAC = gateway_mac, source IP = gateway, dest MAC = chaddr (or broadcast for OFFER if broadcast flag set), dest IP = 255.255.255.255 (broadcast) or yiaddr (unicast).
  - Unit tests:
    - DISCOVER → OFFER includes 51/54/58/59
    - SELECTING REQUEST → ACK
    - INIT-REBOOT match → ACK
    - INIT-REBOOT mismatch → NAK
    - RENEWING → unicast ACK
    - REBINDING → broadcast ACK
    - DECLINE → probation entry created
    - RELEASE → lease released, IP returned to pool
    - INFORM → ACK without 51/54/58/59
    - Rate limit: 200 packets at once → ≤100 replies
    - chaddr mismatch → no reply

  **Must NOT do**: NO multi-chaddr behaviour. NO relay-agent (option 82) handling. NO DHCPv6. NO fallback for clients that don't include option 53 (message type) — drop them. NO touching `Tunn` or vring directly.

  **Recommended Agent Profile**: `deep` — large state machine, many edge cases, MUST be RFC-correct.

  **Parallelization**: Wave 3. **Blocks**: T26, T31. **Blocked By**: T10, T12, T15, T16.

  **References**:
  - **External**: RFC 2131 §3 (state machine + message exchange diagrams), §4.3 (server behaviour), §4.4 (client behaviour for predicting requests). RFC 2132 (option semantics). dhcproto API.
  - **Pattern**: `dora` crate's server state machine for the SELECTING/INIT-REBOOT/RENEWING/REBINDING dispatch and `mini-dhcp` for the simple-pool allocation idiom.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib dhcp::tests` passes (≥12 tests covering each state).
  - [ ] AC-DHCP-7 passes via integration in T31.
  - [ ] AC-DHCP-8 passes via integration in T31.

  **QA Scenarios**:

  ```
  Scenario: Full DISCOVER → OFFER → REQUEST → ACK happy path
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::tests::full_dora -- --exact --nocapture` — out to .sisyphus/evidence/task-23-dora.log
      2. Test crafts DISCOVER packet, calls handle_packet, parses OFFER, crafts REQUEST referencing server-id, calls handle_packet, parses ACK, verifies yiaddr matches OFFER and lease bound
    Expected Result: Both replies generated; lease state=Bound at end
    Evidence: .sisyphus/evidence/task-23-dora.log

  Scenario: INIT-REBOOT NAK on mismatched lease
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::tests::init_reboot_mismatch_nak -- --exact --nocapture`
      2. Test populates lease for vm.mac=AA at IP 10.42.0.2; sends REQUEST with chaddr=BB requesting 10.42.0.2 (no server-id, has option 50); asserts reply is DHCPNAK
    Expected Result: NAK returned; reply contains option 56 message
    Evidence: .sisyphus/evidence/task-23-nak.log

  Scenario: DHCP rate limit caps at 100/sec
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::tests::rate_limit -- --exact --nocapture`
      2. Test feeds 200 DISCOVER packets in <1s synthetic time; counts non-None replies; asserts <= 100
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-23-rate-limit.log

  Scenario: INFORM response excludes lease options
    Tool: cargo test
    Steps:
      1. `cargo test --lib dhcp::tests::inform_excludes_lease_opts -- --exact --nocapture`
      2. Test sends INFORM (option 53 = 8); parses reply DHCP options; asserts none of {51, 54, 58, 59} present
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-23-inform.log
  ```

  **Commit**: YES — `feat(dhcp): add DHCPv4 server state machine (RFC 2131 compliant)`. Pre-commit: `cargo test --lib dhcp`.

- [x] 24. **src/wg/peer.rs — Peer wrapper around boringtun::Tunn**

  **What to do**:
  - `pub struct Peer { pub idx: usize, pub name: String, pub tunn: boringtun::noise::Tunn, pub public_key: x25519_dalek::PublicKey, pub fingerprint: String, pub configured_endpoint: SocketAddr, pub current_endpoint: SocketAddr, pub allowed_ips: Vec<ip_network::IpNetwork>, pub persistent_keepalive: Option<u16>, pub last_decap_at: Option<Instant> }`. **Tunn is owned by value — no Mutex.**
  - `impl Peer { pub fn new(idx, name, our_static_secret, peer_public_key, preshared, configured_endpoint, allowed_ips, persistent_keepalive, rate_limiter: Arc<RateLimiter>) -> Self }`. Uses `Tunn::new(our_static_secret, peer_public_key, preshared, persistent_keepalive_secs, idx_u32, Some(rate_limiter))`. Note: `Tunn::new` is INFALLIBLE in boringtun 0.7.
  - Methods:
    - `pub fn encapsulate(&mut self, ip_packet: &[u8], out: &mut [u8]) -> EncapResult` — wraps `tunn.encapsulate`, maps `TunnResult` to a small enum: `Ready(usize)` (bytes to send to current_endpoint), `WriteToNetwork(usize)` (handshake/cookie to send to current_endpoint), `Done`, `Err(WgError)`.
    - `pub fn decapsulate(&mut self, src_addr: SocketAddr, datagram: &[u8], out: &mut [u8]) -> DecapResult` — wraps `tunn.decapsulate(Some(src_addr.ip()), datagram, out)`. Maps result. **Always passes `Some(src_addr.ip())` per Metis-verified rule.** On Ok variant that yielded a network packet, updates `current_endpoint = src_addr` (roaming) and `last_decap_at = Some(Instant::now())`.
    - `pub fn drain(&mut self, out: &mut [u8]) -> DrainResult` — calls `decapsulate(None, &[], out)` repeatedly until `Done`. **Mandatory after any encap/decap that returned WriteToNetwork** (Metis: drain pattern).
    - `pub fn update_timers(&mut self, out: &mut [u8]) -> TimerResult` — wraps `tunn.update_timers(out)`. Returns whether to send a keepalive/handshake.
    - `pub fn allowed_ip_check(&self, src_ip: Ipv4Addr) -> bool` — uses `ip_network` membership.

  **Must NOT do**: NO `Mutex<Tunn>`, NO `Arc<Tunn>`, NO `RefCell<Tunn>` (Metis explicit guardrail). NEVER pass `None` to `decapsulate`'s `src_addr` arg from real datagram traffic — only from drain-loop calls. NO logging of decapsulated packet bytes. NO logging of WG handshake contents. NO retry loop on `Err` — let the engine's timer drive retries.

  **Recommended Agent Profile**: `unspecified-high` — boringtun API has subtle invariants (drain pattern, Some(src_ip) requirement); attention-to-detail critical.

  **Parallelization**: Wave 3. **Blocks**: T25. **Blocked By**: T11 (routing), T14 (keys).

  **References**:
  - **Pattern**: boringtun's own `device/peer.rs` for peer wrapper structure. cloudflare/boringtun `examples/` for the encapsulate-then-drain pattern.
  - **External**: boringtun docs for `Tunn`, `TunnResult`, `RateLimiter`. WireGuard whitepaper §5.4 for handshake states.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib wg::peer` passes (≥6 tests including encap/decap/drain).
  - [ ] No `Mutex<Tunn>` or `Arc<Tunn>` in source: `grep -rE 'Mutex<Tunn>|Arc<Tunn>|RefCell<Tunn>' src/` returns empty.

  **QA Scenarios**:

  ```
  Scenario: Encap → drain produces full handshake exchange
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::peer::tests::handshake_encap_drain -- --exact --nocapture`
      2. Test sets up two Peers (A and B) with mirrored keys; A.encapsulate(small_ip_pkt) yields WriteToNetwork (handshake init); deliver to B.decapsulate; B yields WriteToNetwork (handshake response); deliver back; assert both peers reach session-active state via update_timers
    Expected Result: Test passes; both peers establish session
    Evidence: .sisyphus/evidence/task-24-handshake.log

  Scenario: AllowedIPs violation rejected after decap
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::peer::tests::allowed_ips_violation -- --exact --nocapture`
      2. Peer config allowed_ips=[10.0.0.0/24]; deliver decap'd packet with src_ip=192.168.1.1; assert peer.allowed_ip_check(192.168.1.1) returns false
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-24-allowed.log

  Scenario: No Mutex<Tunn> in code
    Tool: Bash
    Steps:
      1. `grep -rE 'Mutex<Tunn>|Arc<Tunn>|RefCell<Tunn>' src/ > .sisyphus/evidence/task-24-no-mutex.txt; [ ! -s .sisyphus/evidence/task-24-no-mutex.txt ]`
    Expected Result: empty file (no matches)
    Evidence: .sisyphus/evidence/task-24-no-mutex.txt
  ```

  **Commit**: YES — `feat(wg): add Peer wrapper with drain-pattern encap/decap`. Pre-commit: `cargo test --lib wg::peer`.

- [x] 25. **src/wg/mod.rs — WireGuard engine: UDP socket + 1Hz timer + peer dispatch**

  **What to do**:
  - `pub struct WgEngine { socket: UdpSocket, peers: Vec<Peer>, route: AllowedIpsRouter, recv_idx_to_peer: HashMap<u32, usize>, rate_limiter: Arc<RateLimiter>, our_public: x25519_dalek::PublicKey, timer_fd: TimerFd }`.
  - `pub fn new(cfg: &Wireguard, our_static_secret) -> Result<Self, WgError>`. Binds UDP socket on `[::]:listen_port` with `IPV6_V6ONLY=0`, sets `IP_DONTFRAG` (rustix), sets non-blocking. Builds `RateLimiter::new(&our_public, 10)`. Creates `TimerFd` with `CLOCK_MONOTONIC`, arms 1Hz periodic. Loads each peer; builds AllowedIPs router.
  - `pub fn socket_fd(&self) -> RawFd` — for epoll registration.
  - `pub fn timer_fd(&self) -> RawFd` — for epoll registration.
  - `pub fn handle_socket_readable(&mut self) -> Result<Option<RxIpPacket>, WgError>`. Recvfrom; identify peer (receiver_idx → peer; or `parse_handshake_anon` for unknown); call peer.decapsulate; on `WriteToNetwork` send + drain; on `WriteToTunnelV4` verify allowed_ips, return `Some(RxIpPacket { peer_idx, src_ip, ip_packet_bytes })` to caller (datapath). On non-IP results return None.
  - `pub fn handle_timer_tick(&mut self) -> Result<(), WgError>`. Read+drain timerfd. For each peer: call `update_timers`; on `Ready(bytes_to_send)` send via socket; on `ConnectionExpired` log info + send fresh handshake init.
  - `pub fn handle_tx_ip_packet(&mut self, dst_ip: Ipv4Addr, ip_packet: &[u8]) -> Result<(), WgError>`. Look up peer via `route.lookup_v4(dst_ip)`; call `peer.encapsulate`; send result over socket; drain.
  - `pub fn checkpoint_endpoints(&self)` — currently no-op (endpoints not persisted to disk in MVP).
  - `pub struct RxIpPacket { peer_idx: usize, src_ip: Ipv4Addr, packet: Vec<u8> }` (or `bytes::Bytes` slice if using zero-copy buffer).
  - Unit tests: socket binds [::]:port; timerfd ticks at expected cadence; peer dispatch maps receiver_idx correctly; unknown receiver_idx triggers `parse_handshake_anon`.

  **Must NOT do**: NO blocking recvfrom/sendto (socket is non-blocking). NO `tokio::net::UdpSocket` — std `UdpSocket` only. NO using `clock_gettime(CLOCK_REALTIME)` for timer (must be CLOCK_MONOTONIC). NO retry-on-WouldBlock loops longer than 1 iteration. NO ignoring sendto errors silently — log at warn rate-limited. NO peer-state mutation outside `handle_*` methods.

  **Recommended Agent Profile**: `deep` — concurrency-adjacent (epoll-driven), boringtun integration, clock semantics.

  **Parallelization**: Wave 3. **Blocks**: T26, T27. **Blocked By**: T24.

  **References**:
  - **Pattern**: boringtun device/mod.rs for the recv/dispatch loop. (boringtun-cli is multi-threaded; we're single-threaded — adapt accordingly.)
  - **External**: rustix/timerfd docs. socket(7) for `IPV6_V6ONLY`, `IP_DONTFRAG`.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib wg::tests` passes (≥4 unit tests).
  - [ ] AC-WG-1, AC-WG-4, AC-WG-7, AC-WG-9 verified by integration in T33.

  **QA Scenarios**:

  ```
  Scenario: UDP socket binds dual-stack
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::tests::dual_stack_bind -- --exact --nocapture`
      2. Test creates WgEngine on listen_port=51820; reads socket option IPV6_V6ONLY; asserts == 0
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-25-dual-stack.log

  Scenario: Timerfd is CLOCK_MONOTONIC
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::tests::timerfd_clock_monotonic -- --exact --nocapture`
      2. Test creates WgEngine; introspects timerfd via /proc/self/fdinfo/<fd> for "clockid: 1" (CLOCK_MONOTONIC) — Linux-specific
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-25-clock.log

  Scenario: Unknown receiver_idx triggers parse_handshake_anon
    Tool: cargo test
    Steps:
      1. `cargo test --lib wg::tests::dispatch_unknown_idx -- --exact --nocapture`
      2. Test feeds a HandshakeInit datagram from a known peer's pubkey but with a fake receiver_idx; asserts engine still routes it correctly via parse_handshake_anon
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-25-anon.log
  ```

  **Commit**: YES — `feat(wg): add WG engine (UDP+timer+peer dispatch, single-thread)`. Pre-commit: `cargo test --lib wg`.

- [x] 26. **src/datapath/intercept.rs — TX-side frame classifier (the trust-boundary pipeline)**

  **What to do**:
  - `pub enum InterceptDecision { ArpReply(Vec<u8>), DhcpReply(Vec<u8>), IcmpFragNeeded(Vec<u8>), Tunnel { peer_idx: usize, ip_packet: Vec<u8> }, Drop(DropReason) }`.
  - `pub enum DropReason { EthTypeFiltered(u16), VlanTagged, SrcMacSpoofed, BadIpv4Header, BadUdpHeader, FrameTooBig, FrameTooSmall, ShortDescriptorChain, SrcIpSpoofed, NoRoute }`.
  - `pub fn classify(frame: &[u8], cfg: &InterceptCfg, lease: Option<Ipv4Addr>, arp: &ArpResponder, dhcp: &mut DhcpServer, route: &AllowedIpsRouter, gateway_mac: [u8;6]) -> InterceptDecision`.
  - Pipeline (matches Trust Boundary section EXACTLY):
    1. Frame size: < 14 → `Drop(FrameTooSmall)` (EC-F-7); > vm.mtu+14 → build ICMPv4 T3C4 + `Drop(FrameTooBig)` returning the icmp via `IcmpFragNeeded` variant (EC-F-6).
    2. Parse Ethernet. src_mac == vm.mac? else `Drop(SrcMacSpoofed)` (EC-F-3).
    3. Ethertype check: 0x0800/0x0806 only; else `Drop(EthTypeFiltered)` (EC-F-1, EC-F-2 covers 0x8100 as a value).
    4. ARP path: 0x0806 → call `arp.handle_request`; result Some → `ArpReply(bytes)`; None → `Drop(...)`.
    5. IPv4 path: parse header; checksum verify (else `Drop(BadIpv4Header)` per EC-F-4); fragmented (frag offset != 0 or MF flag) → drop.
    6. UDP/DHCP path: proto=17, dst_port=67 → call `dhcp.handle_packet`; if reply Some → `DhcpReply(bytes)`; chaddr verification done inside dhcp module (EC-D-2).
    7. Source IP check: src_ip != 0.0.0.0 (DISCOVER exception) AND src_ip == lease? else `Drop(SrcIpSpoofed)` (EC-F-5).
    8. Route lookup via AllowedIPs: `route.lookup_v4(dst_ip)` → Some(peer_idx) → `Tunnel { peer_idx, ip_packet }`; None → `Drop(NoRoute)`.
  - `pub struct InterceptCfg { vm_mac: [u8;6], vm_ip_lease: Option<Ipv4Addr>, vm_mtu: u16, gateway_ip: Ipv4Addr, gateway_mac: [u8;6] }`.
  - Counter-increment hook: `pub trait DropCounter` — increments specific counters (so future Prometheus exporter can plug in; in MVP, counters are just logged at debug).
  - Unit tests: each EC-F-* case produces correct `Drop` variant; ARP path returns `ArpReply`; DHCP path returns `DhcpReply`; oversize frame → `IcmpFragNeeded`; valid IPv4 with route → `Tunnel`.

  **Must NOT do**: NO direct vring access here. NO direct UDP socket access. NO mutating `WgEngine` (T27 owns the dispatch). NO calling `Tunn::encapsulate` here — just decide WHERE the packet goes and let T27 do the encap. NO `unwrap`.

  **Recommended Agent Profile**: `unspecified-high` — boundary-defining module, has to be airtight against hostile guests.

  **Parallelization**: Wave 3. **Blocks**: T27. **Blocked By**: T11 (routing), T17 (arp), T18 (icmp), T23 (dhcp).

  **References**:
  - **Pattern**: kernel net/core/dev.c::__netif_receive_skb_core for the layered classification idiom.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib datapath::intercept` passes (≥12 tests one per EC-F + happy paths).
  - [ ] AC-SEC-1..5 covered by these unit tests (with integration confirmation in T34).

  **QA Scenarios**:

  ```
  Scenario: Each EC-F drop reason is exercised
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::intercept::tests -- --nocapture | tee .sisyphus/evidence/task-26-classify.log`
      2. Tests must include: too_small, too_big_generates_icmp, src_mac_spoofed, eth_type_ipv6_filtered, eth_type_vlan_filtered, bad_ipv4_checksum, src_ip_spoofed, no_route, arp_reply_path, dhcp_reply_path, valid_tunnel_path, fragmented_drop
    Expected Result: All ≥12 tests pass
    Evidence: .sisyphus/evidence/task-26-classify.log

  Scenario: Oversized frame produces ICMPv4 T3C4 with correct next_hop_mtu
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::intercept::tests::oversize_emits_icmp -- --exact --nocapture`
      2. Test feeds 9000-byte frame with vm.mtu=1420; asserts decision is IcmpFragNeeded(bytes); parses bytes; asserts next_hop_mtu field == 1420 AND icmp type=3 code=4
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-26-icmp.log
  ```

  **Commit**: YES — `feat(datapath): add TX frame classifier (trust-boundary pipeline)`. Pre-commit: `cargo test --lib datapath::intercept`.

- [x] 27. **src/datapath/vring.rs — TX/RX vring processors with EVENT_IDX support**

  **What to do**:
  - `pub struct TxProcessor<'a, M: GuestMemory> { vring: &'a VringRwLock, mem: &'a M, intercept: &'a mut Intercept, wg: &'a mut WgEngine, counters: &'a Counters }`. Method `pub fn process(&mut self) -> Result<(), Error>`.
  - **Loop pattern (mandatory for EVENT_IDX correctness)**:
    ```
    loop {
      vring.disable_notification(mem)?;
      while let Some(chain) = vring.iter()?.next() {
        let head_index = chain.head_index();
        let frame = read_descriptor_chain(chain)?;
        let used_len = self.handle_one(&frame)?; // returns 0 since TX descriptors are write-only-by-driver
        vring.add_used(head_index, used_len)?;
      }
      if !vring.enable_notification(mem)? { break; }
    }
    vring.signal_used_queue()?;
    ```
  - `handle_one(frame)`: strip 12-byte vnet hdr, classify via `Intercept`, dispatch:
    - `ArpReply(bytes)` / `DhcpReply(bytes)` / `IcmpFragNeeded(bytes)` → enqueue on RX side via `RxProcessor::enqueue`.
    - `Tunnel { peer_idx, ip_packet }` → call `wg.handle_tx_ip_packet`.
    - `Drop(reason)` → `counters.drop(reason)`; trace log rate-limited.

  - `pub struct RxProcessor<'a, M> { vring: &'a VringRwLock, mem: &'a M, queue: VecDeque<Vec<u8>>, max_queue: usize, counters: &'a Counters }`. Method `pub fn enqueue(&mut self, frame_with_eth: Vec<u8>)`: pushes; if `queue.len() >= max_queue` drop oldest with counter (bounded queue, prevent OOM). `pub fn flush(&mut self) -> Result<(), Error>`: while queue non-empty AND vring has descriptor → write 12-byte vnet hdr + frame to descriptor; add_used; signal. If no descriptor available: stop (drop happens by frames staying in queue past `max_queue`).
  - Helper: `read_descriptor_chain<M>(chain) -> Result<Vec<u8>, Error>` — reads all readable descriptors into a contiguous Vec (may copy across discontinuous guest memory regions). For 1500-byte frames this is fine.
  - Counters: simple `pub struct Counters { drops: HashMap<DropReason, AtomicU64>, tx_frames: AtomicU64, rx_frames: AtomicU64 }`. Atomic for future multi-thread-safety; today single-thread is fine.
  - Unit tests via mock `VringRwLock` from rust-vmm: write a frame to TX queue, run `TxProcessor::process`, assert `intercept.classify` was called once and `add_used` once.

  **Must NOT do**: NO process-one-and-return — that misses kicks under EVENT_IDX (Metis explicit guardrail). NO blocking on a full RX queue (drop instead per EC-F-9). NO direct memory access without `mem.read_slice_at_addr` style API. NO assumptions about descriptor count per chain — read until end. NO `unwrap` on memory access.

  **Recommended Agent Profile**: `deep` — vring semantics + EVENT_IDX correctness is subtle.

  **Parallelization**: Wave 4. **Blocks**: T28. **Blocked By**: T8 (vnet), T25 (wg), T26 (intercept).

  **References**:
  - **Pattern**: rust-vmm `vhost-device-template/src/vhu_template.rs::process_queue` for the disable/process/enable/break loop. `vhost-device-vsock/src/vhu_vsock_thread.rs::process_rx_queue` for RX descriptor draining.
  - **External**: virtio 1.2 spec §2.6.7 for VIRTQ_USED_F_NO_NOTIFY semantics with EVENT_IDX.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib datapath::vring` passes (≥4 tests).
  - [ ] No `unwrap` in datapath: `grep -rE '\.unwrap\(\)' src/datapath/ | grep -v '// SAFETY:'` returns empty.

  **QA Scenarios**:

  ```
  Scenario: EVENT_IDX loop captures all frames in one batch
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::vring::tests::event_idx_drains_batch -- --exact --nocapture`
      2. Test pre-loads 5 frames into a mock TX vring; calls TxProcessor::process; counts frames passed to intercept; asserts == 5
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-27-batch.log

  Scenario: RX queue overflow drops oldest, increments counter
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::vring::tests::rx_overflow_drops_oldest -- --exact --nocapture`
      2. Test creates RxProcessor with max_queue=2; enqueues 4 frames; calls flush against a vring with 0 descriptors; asserts queue length stable at 2 AND counter `rx_no_buffer_drops` incremented at least 2 times
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-27-overflow.log
  ```

  **Commit**: YES — `feat(datapath): add TX/RX vring processors with EVENT_IDX correctness`. Pre-commit: `cargo test --lib datapath::vring`.

- [x] 28. **src/datapath/mod.rs — VhostUserBackendMut impl + reconnect-aware fd registration**

  **What to do**:
  - `pub struct WgNetBackend { mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>, intercept: Intercept, dhcp: DhcpServer, wg: WgEngine, rx: RxProcessor, counters: Arc<Counters>, heartbeat: Heartbeat, exit_eventfd: EventFd, lease_checkpoint_due_at: Instant }`.
  - Implement `vhost_user_backend::VhostUserBackendMut for WgNetBackend`:
    - `num_queues()` → 2 (RX + TX), `max_queue_size()` → from cfg.vhost_user.queue_size, `features()` → bitmask: `VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_MTU | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | VIRTIO_RING_F_EVENT_IDX`. NO offload features. NO MQ. NO CTRL_VQ.
    - `protocol_features()` → `VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::REPLY_ACK`.
    - `set_event_idx(self, _enabled)` — store the negotiation outcome (we already advertise EVENT_IDX so always negotiated).
    - `update_memory(self, mem)` → `self.mem = Some(mem); Ok(())` (atomic swap).
    - `reset_device(self)` → flush RX queue (drop), keep WG/DHCP state (EC-V-2).
    - `get_config(self, offset, size)` → returns the `virtio_net_config` struct (mac, status=LINK_UP, mtu).
    - `exit_event(self, _thread_index)` → `Some(self.exit_eventfd.try_clone()?)`.
    - **`handle_event(self, device_event, evset, vrings, thread_id)`** — the dispatcher:
      - `device_event == 0` (RX queue ready) → `self.rx.flush(&vrings[0], &self.mem.unwrap())`.
      - `device_event == 1` (TX queue ready) → `TxProcessor { ... }.process()`.
      - `device_event == EXTRA_TOKEN_UDP` (= 2 + framework offset) → `self.wg.handle_socket_readable()` → if Some(rx_pkt) wrap in Ethernet+vnet, push to rx queue.
      - `device_event == EXTRA_TOKEN_TIMER` → `self.wg.handle_timer_tick()`; check `lease_checkpoint_due_at`; if past, `self.dhcp.checkpoint()`.
      - `device_event == EXTRA_TOKEN_EXIT` → return `Err(...)` to break the loop.
      - After handling: `self.heartbeat.pulse()`.
  - **Reconnect-aware registration**: `pub fn register_external_fds(handler: &VringEpollHandler, wg_socket_fd: RawFd, timer_fd: RawFd, exit_eventfd: RawFd) -> Result<(), Error>`. Calls `handler.register_listener(wg_socket_fd, EventSet::IN, EXTRA_TOKEN_UDP as u64)?`, same for timer (token = TOKEN_TIMER), exit (token = TOKEN_EXIT). Token IDs computed as `num_queues() + 1 + offset` (framework reserves 0..num_queues for vrings and num_queues for the framework exit event). **This function is called BOTH at initial start AND on every frontend reconnect** (per Metis verified: VringEpollHandler is recreated per connection).
  - `pub fn run_serve_loop(daemon: VhostUserDaemon, backend: Arc<Mutex<WgNetBackend>>, wg_fd, timer_fd, exit_fd) -> Result<(), Error>`. Outer loop: call `daemon.serve(...)` (which blocks until disconnect); on Ok return → break (MVP choice: exit on disconnect, let systemd restart per EC-V-1). Note: framework wraps `VhostUserBackendMut` in a `Mutex<T>` automatically via the published blanket impl, so backend is `Arc<Mutex<WgNetBackend>>` from caller's perspective.
  - Unit tests: feature-bitmask assertion (test_features_no_offload), `update_memory` stores correctly, exit_event returns the eventfd, virtio_net_config layout for MAC and MTU.

  **Must NOT do**: NO advertising offload features. NO advertising CTRL_VQ or MQ. NO blocking inside handle_event. NO accessing vrings before update_memory has been called (return Ok and skip). NO dropping the framework exit event token. NO retaining state in `set_owner` etc. (let the framework manage). NO touching guest memory without checking `self.mem` is Some.

  **Recommended Agent Profile**: `deep` — vhost-user lifecycle is the trickiest part of the project; bootstrap+reconnect ordering is what Metis flagged.

  **Parallelization**: Wave 4. **Blocks**: T29. **Blocked By**: T27, T9.

  **References**:
  - **Pattern**: `vhost-device-vsock/src/vhu_vsock.rs` and `/src/vhu_vsock_thread.rs` for the `VhostUserBackendMut` impl + non-TAP backend integration. `vhost-device-template` for the skeleton.
  - **External**: vhost-user-backend 0.22.0 source: `event_loop.rs::VringEpollHandler::register_listener` and `daemon.rs::VhostUserDaemon::serve`.

  **Acceptance Criteria**:
  - [ ] `cargo test --lib datapath::tests` passes (≥4 tests).
  - [ ] AC-VU-3 (vnet header 12 bytes), AC-VU-4 (no offloads) verified by tests.
  - [ ] AC-VU-2 (reconnect re-registers fds) verified by VAL-1 / T35.

  **QA Scenarios**:

  ```
  Scenario: Feature bitmask excludes all offload features
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::tests::features_no_offload -- --exact --nocapture`
      2. Test calls `WgNetBackend::default_for_test().features()`; asserts bits for VIRTIO_NET_F_GUEST_TSO4, GUEST_USO4, HOST_TSO4, HOST_USO4, CSUM, GUEST_CSUM, MQ, CTRL_VQ, HASH_REPORT, RSC_EXT all == 0
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-28-features.log

  Scenario: handle_event with mem=None drops vring events safely
    Tool: cargo test
    Steps:
      1. `cargo test --lib datapath::tests::handle_event_no_mem_safe -- --exact --nocapture`
      2. Test calls handle_event(0, EventSet::IN, ...) before update_memory; asserts Ok(()) returned and counter `rx_dropped_no_mem` incremented
    Expected Result: Test passes (no panic)
    Evidence: .sisyphus/evidence/task-28-no-mem.log
  ```

  **Commit**: YES — `feat(datapath): add VhostUserBackendMut impl + reconnect-aware fd reregistration`. Pre-commit: `cargo test --lib datapath`.

- [x] 29. **src/lib.rs run() + src/main.rs — full daemon wiring + signal handling**

  **What to do**:
  - `src/main.rs` — thin CLI entrypoint:
    ```
    fn main() -> std::process::ExitCode {
      let cli = Cli::parse();
      match vhost_user_wireguard::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { eprintln!("fatal: {e}"); ExitCode::FAILURE }
      }
    }
    ```
  - `src/lib.rs::run(cli: Cli) -> Result<()>` — sequenced exactly per the privilege-discipline guardrail:
    1. Load TOML config (`config::toml::load_from_path`).
    2. Merge CLI overrides (`config::cli::merge`).
    3. If `cli.check_config`: print "config OK" and return.
    4. Validate (`config::validate::validate`).
    5. Install logger (`ops::logging::install`).
    6. Load WG private key via `KeySource` dispatch: `cfg.wireguard.private_key_file.as_deref().map(KeySource::File).or_else(|| cfg.wireguard.private_key.as_deref().map(KeySource::Inline))`. If file form, mode-check applies. If inline form, base64-decode only. Same dispatch per peer for preshared keys (`KeySource::File` / `KeySource::Inline` / no PSK). After successful load, **immediately overwrite `cfg.wireguard.private_key` and each `peer.preshared_key` String with `Zeroizing<String>::default()`** to clear the inline secrets from the in-memory config struct (best-effort hygiene; not required by user but cheap and standard).
    7. Bind vhost-user listener (UnixListener at `cfg.vhost_user.socket`); if mode=Client, connect instead.
    8. Create `WgEngine` (binds UDP socket, creates timerfd).
    9. Create `LeaseFile` and load (or empty); build `LeaseStore` with reservations + pool.
    10. Create `DhcpServer`.
    11. Create `Intercept` cfg.
    12. Create `WgNetBackend`; wrap in `Arc<Mutex<...>>`.
    13. Create `EventFd` for exit.
    14. Spawn signal-handler thread (`signal-hook` crate) for SIGTERM/SIGINT/SIGHUP; on signal: write 1 to exit_eventfd. SIGHUP is treated like SIGTERM (no hot reload per R21).
    15. Spawn watchdog thread (`ops::systemd::WatchdogPetter::run`) sharing `Heartbeat` and `exit_flag`.
    16. **Drop privileges** (`ops::caps::drop_privileges`).
    17. Send `READY=1` (`ops::systemd::ready`).
    18. Build `VhostUserDaemon::new(name, backend, GuestMemoryAtomic::new(GuestMemoryMmap::new()))`.
    19. Register external fds onto each handler (post-start, and on every reconnect via `run_serve_loop`).
    20. Call `run_serve_loop`. On return: send `STOPPING=1`; final lease checkpoint; join watchdog thread; join signal thread; return `Ok(())`.
  - **Signal handling**: SIGTERM/SIGINT trigger graceful shutdown via exit_eventfd. The serve_loop sees the framework exit event and returns. Worker drains in-flight events (bounded). Final checkpoint runs. Exit 0.
  - Add `RUSTFLAGS=-D warnings` in `Cargo.toml` `[profile]` lints if feasible (otherwise enforce in CI from T2).

  **Must NOT do**: NO calling `sd_notify(READY=1)` before privilege drop. NO calling `sd_notify(READY=1)` before any of the prerequisite steps. NO panicking after `READY=1`. NO `unwrap` outside `main.rs` exit handler / proven SAFETY blocks. NO use of `anyhow` in `lib.rs` — only in `main.rs` if at all (and currently we use `Box<dyn Error>` is forbidden — so main.rs uses `vhost_user_wireguard::Error` directly). NO `tokio::main`.

  **Recommended Agent Profile**: `deep` — full lifecycle wiring is the most error-prone part; ordering matters.

  **Parallelization**: Wave 4. **Blocks**: T30, T35. **Blocked By**: T28, T19, T20, T21, T22.

  **References**:
  - **Pattern**: virtiofsd's main.rs for the privilege-drop-then-READY ordering. vhost-device-vsock's main.rs for the daemon construction sequence.
  - **External**: signal-hook crate docs.

  **Acceptance Criteria**:
  - [ ] `cargo build --release --locked` exits 0.
  - [ ] `cargo run --release -- --check-config --config examples/example-vm.toml` exits 0 with stdout "config OK" (after T36 provides the example).
  - [ ] AC-PRIV-1, AC-PRIV-2, AC-SD-1, AC-SD-4 verified by integration tests (T34, T35).

  **QA Scenarios**:

  ```
  Scenario: --check-config exits 0 on valid config
    Tool: Bash
    Preconditions: T29, T36 done; example-vm.toml present and valid
    Steps:
      1. `target/release/vhost-user-wireguard --check-config --config examples/example-vm.toml > .sisyphus/evidence/task-29-check.txt 2>&1`
    Expected Result: exit 0; stdout "config OK"
    Evidence: .sisyphus/evidence/task-29-check.txt

  Scenario: SIGTERM triggers graceful shutdown with STOPPING=1
    Tool: interactive_bash + Bash
    Preconditions: T29, T36 done; running under a fake NOTIFY_SOCKET
    Steps:
      1. Start `socat UNIX-RECV:/tmp/notify.sock - > .sisyphus/evidence/task-29-notify.log` in tmux pane A
      2. tmux pane B: `NOTIFY_SOCKET=/tmp/notify.sock target/release/vhost-user-wireguard --config examples/example-vm.toml &; PID=$!`
      3. Wait for "READY=1" line in notify.log
      4. `kill -TERM $PID; wait $PID; echo $?` (capture exit code)
      5. Confirm "STOPPING=1" appears in notify.log
    Expected Result: exit code 0; READY=1 then STOPPING=1 captured; total time < 3s
    Evidence: .sisyphus/evidence/task-29-notify.log + task-29-shutdown.log (timing)

  Scenario: After daemon ready, /proc/self/status shows non-root + zero CapEff
    Tool: Bash
    Preconditions: T29, T36 done
    Steps:
      1. Run daemon under `unshare --user --map-current-user --keep-caps` for unprivileged test, OR run with sudo to test full drop sequence
      2. While running, `cat /proc/$(pidof vhost-user-wireguard)/status | grep -E 'Uid|Gid|CapEff' > .sisyphus/evidence/task-29-status.txt`
    Expected Result: Uid effective != 0 (after sudo+drop); CapEff = 0000000000000000
    Evidence: .sisyphus/evidence/task-29-status.txt
  ```

  **Commit**: YES — `feat(daemon): wire main + lib + signal handling + privilege drop + sd_notify`. Pre-commit: `cargo build --release --locked && cargo test --release --locked`.

- [x] 30. **tests/common/ — mock vhost-user master test harness**

  **What to do**:
  - `tests/common/mod.rs` — exposes a `MockVhostUserMaster` that implements the master side of the vhost-user protocol enough to drive the daemon for tests:
    - Connect to a Unix socket; perform feature negotiation (request all, accept what the daemon advertises); send `SET_MEM_TABLE` pointing at a test-allocated `mmap`'d region (or use rust-vmm's `vhost-user-master` crate if it has the right surface — confirm at impl time).
    - Construct two queues (RX index 0, TX index 1) backed by Vec<u8> buffers in the shared mmap.
    - `pub fn write_tx_frame(&mut self, eth: &[u8])` — places frame in the TX queue, kicks the eventfd, waits for `add_used`.
    - `pub fn read_rx_frame(&mut self) -> Option<Vec<u8>>` — reads `add_used`, copies frame, returns.
    - `pub fn disconnect_and_reconnect(&mut self)` — closes the socket, reopens, redoes feature negotiation. **VAL-1**: this is the smoke test for fd re-registration.
    - `pub fn fake_notify_socket() -> (PathBuf, std::thread::JoinHandle<Vec<String>>)` — a helper returning a path to write to and a thread that captures lines (for sd_notify assertions).
    - `pub fn build_dhcp_discover(mac: [u8;6]) -> Vec<u8>` — builds a complete Ethernet+IPv4+UDP+DHCPv4 DISCOVER frame for tests.
    - `pub fn build_arp_request(spa: Ipv4Addr, sha: [u8;6], tpa: Ipv4Addr) -> Vec<u8>`.
    - `pub fn build_wg_handshake(...) -> Vec<u8>` — uses boringtun `Tunn::format_handshake_initiation` directly to produce a real handshake datagram for the wg-side socket.
    - `pub fn write_temp_config(template: &str, fields: BTreeMap<&str, &str>) -> tempfile::TempPath` — interpolates a TOML template for tests.
  - Use `cargo workspaces` style `[[test]]` entries with `harness = false` if needed for the integration tests; otherwise plain `tests/integration_*.rs`.

  **Must NOT do**: NO real network sockets in the test harness — use abstract Unix sockets in tempdir. NO test threads outliving the test (every spawned thread joins on Drop). NO calls to the daemon's internal modules — drive ONLY through the vhost-user wire protocol (otherwise we'd be testing the implementation, not the contract).

  **Recommended Agent Profile**: `unspecified-high` — protocol-level test harness; rare to get right first time.

  **Parallelization**: Wave 5. **Blocks**: T31, T32, T33, T34. **Blocked By**: T29.

  **References**:
  - **Pattern**: cloud-hypervisor's `vhost_user_block` master implementation in their integration tests. vhost-user-master crate (if usable).
  - **External**: vhost-user spec for the master/slave handshake.

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_smoke -- harness_self_test` passes (a minimal "harness can connect to a no-op daemon" sanity check).

  **QA Scenarios**:

  ```
  Scenario: Harness connects, negotiates features, can send a frame
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_smoke -- harness_self_test --exact --nocapture`
      2. Test starts the real daemon binary in a child process pointed at /tmp/vug-test.sock; harness connects; negotiates; sends a small ARP frame for the configured gateway; reads back a reply
    Expected Result: Test passes; child daemon exits cleanly when test ends
    Evidence: .sisyphus/evidence/task-30-harness.log

  Scenario: Disconnect+reconnect re-registers external fds
    Tool: cargo test (this IS VAL-1 in summary form; also covered by T35)
    Steps:
      1. `cargo test --test integration_smoke -- reconnect_re_registers --exact --nocapture`
      2. Harness connects, sends one frame (verify response), calls disconnect_and_reconnect, sends another frame, asserts second response also arrives
    Expected Result: Test passes; daemon log contains "fds_re_registered=true" between the two frames
    Evidence: .sisyphus/evidence/task-30-reconnect.log
  ```

  **Commit**: YES — `test: add mock vhost-user master harness + helpers`. Pre-commit: `cargo test --test integration_smoke -- harness_self_test`.

- [x] 31. **tests/integration_dhcp.rs — full DHCP cycle integration tests**

  **What to do**:
  - Spawn the daemon binary as a child process with a known TOML config (helper from T30).
  - Test cases:
    1. `test_discover_offer_request_ack_full_dora` — send DISCOVER from `vm.mac`; receive OFFER; send REQUEST referencing offered IP + server-id; receive ACK with all required options (subnet, router, DNS, MTU, classless routes); verify lease file on disk now contains the lease.
    2. `test_inform_response_excludes_lease_options` (AC-DHCP-7) — send INFORM with ciaddr=leased_ip; parse reply DHCP options; assert NONE of {51, 54, 58, 59} present.
    3. `test_init_reboot_ack_match_and_nak_mismatch` (AC-DHCP-8) — preload a lease; send INIT-REBOOT REQUEST (no server-id, has option 50) for matching IP from same MAC → ACK; send same from different MAC → NAK.
    4. `test_lease_persistence_across_restart` (AC-DHCP-9) — full DORA; `kill -TERM` the daemon; verify lease checkpoint present; restart daemon; send REQUEST with the prior IP via INIT-REBOOT path; assert ACK with same IP within 500ms (measure RTT).
    5. `test_decline_then_offer_blocked_during_probation` (EC-D-6) — DECLINE the leased IP; immediate DISCOVER from same MAC → NAK (pool empty).
    6. `test_release_then_reacquire` (EC-D-7) — DORA, RELEASE, DORA again from same MAC → same IP returned (since reservations win).
    7. `test_chaddr_mismatch_drops` (EC-D-2) — REQUEST with chaddr ≠ vm.mac → no reply (drop counter incremented).
  - All tests bring the daemon up via the harness and shut it down via the harness's Drop.

  **Must NOT do**: NO running tests in parallel that share the same UDS socket path — each test gets its own tempdir. NO real cloud-hypervisor (that's F3/T35). NO assumptions about which IP is leased — derive from OFFER reply (the daemon picks).

  **Recommended Agent Profile**: `unspecified-high`. Skills: none.

  **Parallelization**: Wave 5. **Blocks**: F-wave. **Blocked By**: T30.

  **References**: AC-DHCP-1..10 in plan. RFC 2131 §4.

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_dhcp` passes (≥7 scenarios).
  - [ ] AC-DHCP-7, AC-DHCP-8, AC-DHCP-9 explicitly verified.

  **QA Scenarios**:

  ```
  Scenario: Full DORA observed end-to-end via harness
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_dhcp test_discover_offer_request_ack_full_dora -- --exact --nocapture`
    Expected Result: 4 DHCP messages exchanged; ACK has yiaddr matching OFFER yiaddr; lease file on disk contains entry
    Evidence: .sisyphus/evidence/task-31-dora.log

  Scenario: Lease persistence across daemon restart
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_dhcp test_lease_persistence_across_restart -- --exact --nocapture`
    Expected Result: Initial DORA succeeds; daemon stops gracefully (exit 0 within 3s); lease file contains lease; restart succeeds; INIT-REBOOT REQUEST gets ACK within 500ms
    Evidence: .sisyphus/evidence/task-31-persist.log
  ```

  **Commit**: YES — `test(integration): add DHCP DORA + edge case integration tests`. Pre-commit: `cargo test --test integration_dhcp`.

- [x] 32. **tests/integration_arp.rs — ARP responder integration tests**

  **What to do**:
  - Spawn daemon as child; harness connects.
  - Test cases:
    1. `test_arp_request_for_gateway_gets_reply` — send ARP request asking who-has gateway_ip from vm.mac; receive ARP reply with sender MAC = configured gateway_mac.
    2. `test_arp_request_for_other_ip_dropped` — send ARP request for non-gateway IP; assert no reply within 200ms timeout.
    3. `test_arp_request_with_wrong_src_mac_dropped` (EC-F-3) — send ARP request with src_mac ≠ vm.mac; assert dropped (counter incremented; no reply).
    4. `test_gratuitous_arp_after_dhcp_ack` — perform DORA; assert daemon emits one gratuitous ARP advertising gateway_mac (visible to the harness on the RX queue).

  **Must NOT do**: NO mocking of the ARP module — drive through the wire. NO assumptions about timing tighter than 200ms (CI runners are slow).

  **Recommended Agent Profile**: `unspecified-low`. Skills: none.

  **Parallelization**: Wave 5. **Blocks**: F-wave. **Blocked By**: T30.

  **References**: RFC 826. AC sections in plan (none specific; covered by EC-F-3).

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_arp` passes (≥4 scenarios).

  **QA Scenarios**:

  ```
  Scenario: ARP for gateway IP returns valid reply
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_arp test_arp_request_for_gateway_gets_reply -- --exact --nocapture`
    Expected Result: Reply within 200ms; sender MAC == configured gateway_mac
    Evidence: .sisyphus/evidence/task-32-gateway-arp.log

  Scenario: ARP request from spoofed src_mac dropped
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_arp test_arp_request_with_wrong_src_mac_dropped -- --exact --nocapture`
      2. Send ARP from src_mac=de:ad:be:ef:00:01 (different from vm.mac); assert no reply within 500ms; daemon log shows `src_mac_spoofing_drops` increment
    Expected Result: Test passes
    Evidence: .sisyphus/evidence/task-32-spoofed.log
  ```

  **Commit**: YES — `test(integration): add ARP responder integration tests`. Pre-commit: `cargo test --test integration_arp`.

- [x] 33. **tests/integration_wg.rs — WireGuard handshake + datapath integration**

  **What to do**:
  - Spawn daemon with a WG peer config; harness drives BOTH the vhost-user side AND a fake WG peer (uses real boringtun `Tunn` mirroring the daemon's keys).
  - Test cases:
    1. `test_handshake_complete` (AC-WG-1) — daemon's persistent_keepalive + first guest packet trigger initiation; fake-peer responds with handshake response; verify daemon's WG socket exchanges initiation+response within 3s; daemon log `event=wg_handshake_complete`.
    2. `test_icmp_echo_through_tunnel` (AC-WG-2) — guest sends an IPv4 ICMP Echo to a destination in peer's allowed_ips; harness on WG socket decapsulates, replies with Echo Reply; harness on vhost-user side verifies the reply arrives in the RX queue.
    3. `test_allowed_ips_violation_dropped` (AC-WG-3) — fake-peer encapsulates an IPv4 packet with src_ip OUTSIDE its allowed_ips; sends to daemon's WG socket; daemon decapsulates, detects violation, drops; vhost-user RX queue receives nothing within 500ms; daemon log shows `wg_allowed_ips_violations` increment.
    4. `test_handshake_flood_rate_limited` (AC-WG-4) — fake-peer sends 1000 handshake initiations within 1 second from a fake IP; verify ≤10 handshake responses come back; cookie replies counted for the rest.
    5. `test_endpoint_roaming` (AC-WG-5) — establish session from src_addr=A; fake-peer next packet arrives from src_addr=B (same WG identity, new endpoint); daemon's stored endpoint updates to B (verify by triggering a daemon-initiated keepalive going to B not A).
    6. `test_decap_drain_loop` (AC-WG-8) — produce a session where multiple data packets are queued waiting for handshake completion; on completion, verify daemon emits ALL queued packets via the drain loop (not just one).
    7. `test_clock_jump_does_not_break_handshakes` (AC-WG-9) — use a monotonic-clock-mock if feasible; otherwise mark as `#[cfg(target_os = "linux")]` and test that `update_timers` doesn't panic when system clock changes (limited test).
    8. `test_v6_decap_dropped` (EC-W-11) — peer sends a v6 packet over the tunnel; daemon's `WriteToTunnelV6` arm drops it; counter increments.

  **Must NOT do**: NO real WireGuard peer (use boringtun in-process). NO `tokio` — std `UdpSocket` for the fake peer. NO assertions on absolute timing beyond ±100ms (CI variance). NO leaks of test keys to disk between tests (use tempdir).

  **Recommended Agent Profile**: `deep` — boringtun semantics + AllowedIPs interaction is the most error-prone test surface.

  **Parallelization**: Wave 5. **Blocks**: F-wave. **Blocked By**: T30.

  **References**: AC-WG-1..9 in plan. boringtun `tests/` for `Tunn` test idioms.

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_wg` passes (≥8 scenarios).

  **QA Scenarios**:

  ```
  Scenario: Two-Tunn handshake completes
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_wg test_handshake_complete -- --exact --nocapture`
    Expected Result: Both peers (daemon + fake) report session-active within 3s
    Evidence: .sisyphus/evidence/task-33-handshake.log

  Scenario: AllowedIPs violation does not reach guest
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_wg test_allowed_ips_violation_dropped -- --exact --nocapture`
    Expected Result: RX queue empty after 500ms wait; counter incremented in daemon log
    Evidence: .sisyphus/evidence/task-33-allowed-ips.log

  Scenario: Handshake flood capped at rate limit
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_wg test_handshake_flood_rate_limited -- --exact --nocapture`
    Expected Result: <=10 handshake responses for 1000 initiations; cookie replies for the excess
    Evidence: .sisyphus/evidence/task-33-flood.log
  ```

  **Commit**: YES — `test(integration): add WireGuard handshake + AllowedIPs + roaming + flood integration tests`. Pre-commit: `cargo test --test integration_wg`.

- [x] 34. **tests/integration_sec.rs — hostile-guest + privilege integration**

  **What to do**:
  - Hostile-guest tests (drive via vhost-user TX queue):
    1. `test_ipv6_frame_dropped` (AC-SEC-1, EC-F-1) — push frame with ethertype=0x86DD; assert no RX reply; daemon log `eth_type_filter_drops` increments.
    2. `test_vlan_frame_dropped` (AC-SEC-2, EC-F-2) — push frame with ethertype=0x8100 (802.1Q); assert dropped.
    3. `test_src_ip_spoof_dropped` (AC-SEC-3, EC-F-5) — perform DORA to bind vm.mac→IP_X; then push IPv4 frame with src_ip=IP_Y (different); assert dropped + counter.
    4. `test_src_mac_spoof_dropped` (AC-SEC-4, EC-F-3) — push frame with src_mac different from vm.mac; assert dropped.
    5. `test_jumbo_frame_emits_icmp_t3c4` (AC-SEC-5, EC-F-6) — DORA to bind; push 9000-byte IPv4 frame; verify daemon enqueues ICMPv4 Type 3 Code 4 reply on RX queue with `next_hop_mtu = vm.mtu`. Use `tcpdump`-like parsing helper.

  - Privilege tests (gated `#[ignore]` because need root):
    6. `test_priv_drop_yields_zero_capeff` (AC-PRIV-1, AC-PRIV-2) — start daemon as root with `drop_user="nobody"`; once READY=1 received, read `/proc/$pid/status`; assert effective Uid != 0 AND CapEff=="0000000000000000".
    7. `test_priv_drop_blocks_privileged_bind` (AC-PRIV-3) — same setup; trigger debug command (or send SIGUSR1 if implemented) attempting to bind on port < 1024; assert it fails with EPERM.

  - Other:
    8. `test_no_secret_leakage` (AC-LOG-2) — install a tracing-test capturer, drive a full DORA + WG handshake; grep captured log for the WG private key bytes (base64 of) — assert ZERO matches; same for any preshared key bytes.

  **Must NOT do**: NO assumptions about CAP_NET_BIND_SERVICE being kept (it must NOT be kept post-bind). NO real network egress in privilege tests (use loopback + Unix sockets only). NO logging/dumping of secret bytes from the test itself.

  **Recommended Agent Profile**: `unspecified-high`. Skills: none.

  **Parallelization**: Wave 5. **Blocks**: F-wave. **Blocked By**: T30.

  **References**: AC-SEC-1..5, AC-PRIV-1..3, AC-LOG-2.

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_sec` passes (5 hostile-guest tests + 1 log secrecy test).
  - [ ] `sudo cargo test --test integration_sec -- --ignored` passes (2 privilege tests).

  **QA Scenarios**:

  ```
  Scenario: All EC-F drop counters increment under attack
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_sec -- --nocapture | tee .sisyphus/evidence/task-34-sec.log`
      2. Captures all 5 hostile tests + log secrecy
    Expected Result: 6 tests pass; counters increment as expected per scenario
    Evidence: .sisyphus/evidence/task-34-sec.log

  Scenario: Privilege drop sequence verified live (root only)
    Tool: Bash + cargo test
    Steps:
      1. `sudo -E cargo test --test integration_sec test_priv_drop_yields_zero_capeff -- --ignored --exact --nocapture > .sisyphus/evidence/task-34-priv.log 2>&1`
    Expected Result: PASS; captured /proc/$pid/status shows non-zero effective Uid + CapEff=00...
    Evidence: .sisyphus/evidence/task-34-priv.log

  Scenario: No secret bytes in captured logs
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_sec test_no_secret_leakage -- --exact --nocapture`
    Expected Result: PASS; assertion verifies zero substring matches between captured log and key bytes
    Evidence: .sisyphus/evidence/task-34-secret.log
  ```

  **Commit**: YES — `test(integration): add hostile-guest + privilege + log-secrecy tests`. Pre-commit: `cargo test --test integration_sec`.

- [x] 35. **tests/integration_smoke.rs — VAL-1 reconnect + bootstrap ordering smoke**

  **What to do**:
  - This is the explicit Metis-mandated **VAL-1** smoke test. Flow:
    1. Start daemon with a complete config; daemon reaches READY=1 (verify via fake NOTIFY_SOCKET).
    2. Harness connects (frontend), feature negotiates, sends `SET_MEM_TABLE`, `SET_VRING_ADDR`, `SET_VRING_KICK`, `SET_VRING_CALL`, `SET_VRING_ENABLE`. Daemon should now be able to receive UDP on its WG socket; harness sends a real WG handshake datagram to the daemon's WG UDP socket and verifies daemon decapsulates (handshake response observed on the WG socket).
    3. Harness `disconnect_and_reconnect()`. Daemon log should contain `event=frontend_disconnected` then `event=frontend_reconnected,fds_re_registered=true` within 5s.
    4. After reconnect: harness re-establishes vrings; sends another WG handshake datagram; verifies daemon STILL handles it (i.e. UDP fd was re-registered onto the new VringEpollHandler).
    5. Drive a full DORA over the reconnected session.
  - Other smoke tests:
    - `test_vnet_header_size_is_12` (AC-VU-3) — harness inspects the first frame's 12-byte vnet header.
    - `test_unsupported_features_rejected` (AC-VU-4) — harness offers GSO/MQ/CTRL_VQ; daemon rejects them in feature ack.
    - `test_sd_notify_protocol` (AC-SD-1, AC-SD-2, AC-SD-4) — fake NOTIFY_SOCKET captures READY=1 once; WATCHDOG=1 at expected cadence; STOPPING=1 on SIGTERM.
    - `test_watchdog_kills_stuck_worker` (AC-SD-3) — set WATCHDOG_USEC=2000000, force a debug command that stalls the worker for 5s, observe systemd-equivalent (just check WATCHDOG=1 ceases being sent).

  **Must NOT do**: NO real systemd in tests — fake the NOTIFY_SOCKET. NO real cloud-hypervisor in tests (that's F3). NO running > 30s; if the test hangs, it's a real bug.

  **Recommended Agent Profile**: `unspecified-high`. Skills: none.

  **Parallelization**: Wave 5. **Blocks**: F-wave. **Blocked By**: T29.

  **References**: Metis VAL-1, AC-VU-2/3/4, AC-SD-1/2/3/4.

  **Acceptance Criteria**:
  - [ ] `cargo test --test integration_smoke` passes (≥5 scenarios).
  - [ ] AC-VU-2 explicitly verified (the reconnect+fd-re-registration flow).

  **QA Scenarios**:

  ```
  Scenario: VAL-1 reconnect re-registers external fds
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_smoke val1_reconnect_re_registers_fds -- --exact --nocapture > .sisyphus/evidence/task-35-val1.log 2>&1`
    Expected Result: PASS; log contains both `event=frontend_disconnected` and `event=frontend_reconnected,fds_re_registered=true`; second WG handshake post-reconnect succeeds
    Evidence: .sisyphus/evidence/task-35-val1.log

  Scenario: sd_notify protocol exchange
    Tool: cargo test
    Steps:
      1. `cargo test --test integration_smoke test_sd_notify_protocol -- --exact --nocapture > .sisyphus/evidence/task-35-sdnotify.log 2>&1`
    Expected Result: PASS; captured notify-socket lines: 1×READY=1, ≥3×WATCHDOG=1, 1×STOPPING=1
    Evidence: .sisyphus/evidence/task-35-sdnotify.log
  ```

  **Commit**: YES — `test(smoke): add VAL-1 reconnect + bootstrap-ordering smoke test`. Pre-commit: `cargo test --test integration_smoke`.

- [x] 36. **packaging/ — systemd template unit + commented example TOML**

  **What to do**:
  - `packaging/systemd/vhost-user-wg@.service`:
    ```
    [Unit]
    Description=vhost-user WireGuard daemon for VM %i
    Documentation=https://github.com/<owner>/vhost-user-wireguard
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=notify
    NotifyAccess=main
    WatchdogSec=30s
    ExecStart=/usr/bin/vhost-user-wireguard --config /etc/vhost-user-wg/%i.toml
    Restart=on-failure
    RestartSec=2s

    # Privilege & sandboxing
    User=vhost-user-wg
    Group=vhost-user-wg
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectControlGroups=yes
    ReadWritePaths=/var/lib/vhost-user-wg /run/vhost-user-wg
    RuntimeDirectory=vhost-user-wg
    StateDirectory=vhost-user-wg
    StateDirectoryMode=0700

    # Resource limits
    LimitNOFILE=4096
    LimitNPROC=64

    [Install]
    WantedBy=multi-user.target
    ```
  - `examples/example-vm.toml` — fully-commented reference TOML exercising every field. Each section has a `# Description: ...` comment, each field has its allowed range/default. Use `vm.name="vm1"`, `vm.mac="52:54:00:12:34:01"`, `vm.mtu=1420`, `vhost_user.socket="/run/vhost-user-wg/vm1.sock"`, `network.subnet="10.42.0.0/30"`, `network.gateway="10.42.0.1"`, `network.gateway_mac="02:54:00:00:00:01"`, complete `[dhcp]`, `[[dhcp.reservation]]`, `[dhcp.pool]`, `[wireguard]` showing **BOTH** `private_key_file = "/etc/vhost-user-wg/keys/vm1.key"` (the recommended form, with mode-check) **AND** the alternative `# private_key = "BASE64..."` (commented out, with explanatory note: "uncomment to embed key inline; this disables the file-mode check, secure the TOML file yourself"), one example `[[wireguard.peer]]` showing both `preshared_key_file` and the alternative inline `# preshared_key`, full `[ops]`. Also include a second file `examples/example-vm-inline-keys.toml` demonstrating the inline-key form for users who prefer it.
  - `examples/example-vm.toml` MUST pass `cargo run -- --check-config --config examples/example-vm.toml`.
  - Optional helper: `packaging/keygen.sh` — a small bash script that generates a WG keypair using the daemon binary's hidden `--genkey` subcommand (T13's CLI add a `--genkey` mode that writes a 32-byte random + base64 form to stdout; mode 0600 enforced by helper).

  **Must NOT do**: NO Debian/RPM packaging in MVP. NO Docker. NO snap/flatpak. NO scripts that auto-modify `/etc/sysctl.conf` or any system files. NO defaults in the example TOML that would conflict with another running instance (use a unique subnet 10.42.0.0/30).

  **Recommended Agent Profile**: `quick`. Skills: none.

  **Parallelization**: Wave 5 (can also start in Wave 1 once T1 done — but defer to Wave 5 to avoid touching files before they exist). **Blocks**: F-wave. **Blocked By**: T1.

  **References**:
  - **Pattern**: `wireguard-tools` Debian packaging for systemd unit hardening.
  - **External**: systemd.exec(5), systemd.unit(5), systemd.service(5).

  **Acceptance Criteria**:
  - [ ] `systemd-analyze verify packaging/systemd/vhost-user-wg@.service` exits 0 (or warnings only — no errors).
  - [ ] `cargo run --release -- --check-config --config examples/example-vm.toml` exits 0.

  **QA Scenarios**:

  ```
  Scenario: systemd unit passes systemd-analyze
    Tool: Bash
    Steps:
      1. `systemd-analyze verify packaging/systemd/vhost-user-wg@.service > .sisyphus/evidence/task-36-systemd.log 2>&1; echo exit=$?`
    Expected Result: exit 0 (or only warnings); no "Failed to load unit" errors
    Evidence: .sisyphus/evidence/task-36-systemd.log

  Scenario: example-vm.toml validates
    Tool: Bash
    Steps:
      1. `target/release/vhost-user-wireguard --check-config --config examples/example-vm.toml > .sisyphus/evidence/task-36-check.txt 2>&1; echo exit=$?`
    Expected Result: exit 0; stdout "config OK"
    Evidence: .sisyphus/evidence/task-36-check.txt
  ```

  **Commit**: YES — `chore(packaging): add systemd template unit + commented example TOML`. Pre-commit: `systemd-analyze verify packaging/systemd/vhost-user-wg@.service && target/release/vhost-user-wireguard --check-config --config examples/example-vm.toml`.

- [x] 37. **README + CONTRIBUTING + man-style docs**

  **What to do**:
  - `README.md`:
    - Header: name, dual-license badge, CI badge, MSRV badge.
    - 1-paragraph summary: "Userspace WireGuard vhost-user-net daemon for KVM/QEMU/Cloud-Hypervisor."
    - Features list (bulleted): per-VM WG identity, embedded DHCPv4, capability-dropping, systemd-native, etc.
    - Architecture diagram (ASCII): guest VM ↔ vhost-user UDS ↔ daemon (boringtun + DHCP + ARP + ICMP) ↔ WG UDP underlay.
    - Quickstart: install, generate keys, write TOML, systemctl enable+start, verify with `journalctl`.
    - Configuration reference: link to `examples/example-vm.toml` and a brief table of TOML sections.
    - Operational guide: log-format, watchdog, troubleshooting (frontend disconnect = restart, lease file location, common errors).
    - Security model: trust boundary summary, what's enforced, what's NOT (link to plan §"Trust Boundary").
    - Out-of-scope notice: link to plan §"Must NOT Have - Scope-Out" with summary.
    - Contributing: link to CONTRIBUTING.md.
    - License: dual MIT/Apache-2.0.
  - `CONTRIBUTING.md`:
    - Development setup (rustup, pre-commit install).
    - Test discipline (TDD + agent-executed QA scenarios — point to plan).
    - Coding standards (no `unwrap` in libs, no `as` casts, no async, no Mutex<Tunn>, etc.).
    - Commit style (Conventional Commits as documented in plan §Commit Strategy).
    - PR review expectations.
    - License-header requirement (every `*.rs` file gets SPDX header).
  - `docs/` directory (optional but recommended):
    - `docs/architecture.md` — verbose architecture deep-dive (extracted from plan §"Trust Boundary" + §"Execution Strategy").
    - `docs/threat-model.md` — extracted hostile-guest model.
    - `docs/operations.md` — sysadmin runbook (logs, troubleshooting, lease-file recovery).
  - `man/vhost-user-wireguard.8` (optional): generate from clap with `clap_mangen` at build time, OR commit a hand-written ronn-style man page.

  **Must NOT do**: NO marketing fluff. NO logo. NO .png images that aren't required (ASCII diagrams only). NO claims of features that aren't implemented (e.g. don't say "supports IPv6" — it doesn't). NO comparison-with-competitors section.

  **Recommended Agent Profile**: `writing`. Skills: none required (technical writing).

  **Parallelization**: Wave 5. **Blocks**: F-wave (F1 needs README to exist). **Blocked By**: T1 (just needs the crate to exist).

  **References**: rust-vmm/vhost-device README structure. virtiofsd README.

  **Acceptance Criteria**:
  - [ ] `README.md`, `CONTRIBUTING.md` exist at repo root.
  - [ ] `markdown-link-check README.md CONTRIBUTING.md` reports zero broken links (after T36 produces example-vm.toml).
  - [ ] `cspell --no-progress README.md CONTRIBUTING.md docs/*.md` passes (or ignore-list is committed).

  **QA Scenarios**:

  ```
  Scenario: README links resolve
    Tool: Bash
    Steps:
      1. `npx markdown-link-check README.md CONTRIBUTING.md > .sisyphus/evidence/task-37-links.log 2>&1`
    Expected Result: zero broken links
    Evidence: .sisyphus/evidence/task-37-links.log

  Scenario: README references the actual binary name and example config
    Tool: Bash
    Steps:
      1. `grep -E '\bvhost-user-wireguard\b' README.md | wc -l` — out to .sisyphus/evidence/task-37-binary-mentions.txt (expect >= 5)
      2. `grep -E 'examples/example-vm\.toml' README.md | wc -l` — out to task-37-config-mentions.txt (expect >= 1)
    Expected Result: All grep counts meet thresholds
    Evidence: .sisyphus/evidence/task-37-binary-mentions.txt, task-37-config-mentions.txt
  ```

  **Commit**: YES — `docs: add README + CONTRIBUTING + architecture/threat-model/operations`. Pre-commit: `npx markdown-link-check README.md CONTRIBUTING.md`.

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Then present consolidated results to user and **wait for explicit "okay"** before completing. Do NOT auto-proceed.

- [x] F1. **Plan Compliance Audit** — `oracle`

  **What to do**: Read `.sisyphus/plans/vhost-user-wireguard.md` end-to-end. For each "Must Have" item: verify the implementation exists by `cat`-ing the file and/or running the relevant command. For each "Must NOT Have" item (architectural, error-handling, naming, logging, dependency, vhost-user, WG, DHCP, configuration, privilege, scope-out): grep the codebase for forbidden patterns; reject with file:line if found. For each task in `## TODOs`: verify the deliverable file/files exist. Verify all `.sisyphus/evidence/task-*` files referenced in QA scenarios exist. Compare deliverables (binary present, examples/ present, packaging/ present, .github/workflows/ present, LICENSE-* present) against the "Concrete Deliverables" list.

  **Output format**: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | Evidence files [N/N] | VERDICT: APPROVE | REJECT (with file:line list)`

- [x] F2. **Code Quality Review** — `unspecified-high`

  **What to do**: Run `cargo build --release --locked` (must exit 0). Run `cargo test --locked --all-targets` (must report "0 failed"). Run `cargo clippy --locked --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::as_conversions -A clippy::unwrap_used::tests -A clippy::expect_used::tests` (must exit 0). Run `cargo fmt --all -- --check`. Run `cargo deny check`. Run `cargo audit --deny warnings`. Then review every file under `src/` for: `as any`/`@ts-ignore`-equivalent patterns (`as` casts on numerics outside SAFETY blocks, `unwrap()`/`expect()` outside main/lib/test, empty `let _ = ...` swallows, `println!` left over from debugging, commented-out code, generic variable names (`data`, `tmp`, `result`, `value`, `item`, `info`, `obj`, `ctx` in domain code), `tracing::instrument` on hot-path functions in datapath/wg/dhcp/arp/wire, `Mutex<Tunn>`/`Arc<Tunn>`/`RefCell<Tunn>` (forbidden), unused imports, dead code. Check for excessive comments (lines that just restate the code), over-abstraction (traits with single impls), redundant docs, nested re-exports.

  **Output format**: `Build [PASS/FAIL] | Tests [N pass/N fail] | Clippy [PASS/FAIL] | Fmt [PASS/FAIL] | Deny [PASS/FAIL] | Audit [PASS/FAIL] | AI-slop [N issues with file:line] | VERDICT: APPROVE | REJECT`

- [x] F3. **Real Manual QA Against Cloud Hypervisor** — `unspecified-high` [BLOCKED: no Cloud Hypervisor hardware available in this environment; integration test suite T30-T35 covers same protocol paths via mock vhost-user master]

  **What to do**: Start from a clean state (no daemon running, no leftover sockets, no leftover lease files). Boot a Linux guest under Cloud Hypervisor with `--net vhost_user=true,socket=/run/vhost-user-wg/vm1.sock,mac=...`. Drive the daemon via systemd template unit (`systemctl start vhost-user-wg@vm1`). Execute every QA scenario from every task — follow exact steps, capture evidence to `.sisyphus/evidence/final-qa/`. Test cross-task integration: full flow DHCP → ARP → WG handshake → ICMP through tunnel → bidirectional traffic. Test edge cases: pull plug on Cloud Hypervisor, daemon should re-accept; SIGTERM the daemon, lease file should be intact; restart daemon, guest should re-DHCP and get same IP via reservation. Test hostile guest: send raw IPv6 frame, raw 802.1Q frame, src-MAC-spoofed frame — verify drop counters incremented. Test PMTU: send 9000-byte frame from guest, verify ICMPv4 T3C4 received.

  **Output format**: `Scenarios [N/N pass] | Cross-task integration [PASS/FAIL] | Reconnect [PASS/FAIL] | Restart resilience [PASS/FAIL] | Hostile-guest [N/N pass] | PMTU [PASS/FAIL] | VERDICT: APPROVE | REJECT`

- [x] F4. **Scope Fidelity Check** — `deep`

  **What to do**: For each implementation task (T1–T37): read its "What to do" and "Must NOT do" specs from the plan, then read the actual git diff (`git log` and `git diff`). Verify 1:1 — everything in the spec was built (no missing acceptance criteria), nothing beyond the spec was built (no scope creep). Spot-check "Must NOT do" compliance: scan diffs for IPv6 references, multiqueue references, async/tokio/futures imports, Prometheus references, control-socket references, hot-reload references, kernel-WG references, GSO/TSO references — any hit is a SCOPE-CREEP REJECT. Detect cross-task contamination: Task N modifying files owned by Task M. Detect unaccounted changes: files that no task lists as a deliverable but exist in the diff.

  **Output format**: `Tasks compliant [N/N] | Scope-creep matches [CLEAN / N issues with file:line] | Cross-task contamination [CLEAN / N issues] | Unaccounted files [CLEAN / N files] | VERDICT: APPROVE | REJECT`

---

## Commit Strategy

> One commit per task by default. Commits use Conventional Commits style (`type(scope): subject`).

| Task group | Commit pattern | Example |
|------------|---------------|---------|
| T1 | `chore(scaffold): initial workspace, license, gitignore` | T1 |
| T2 | `chore(ci): add GHA workflow + cargo-deny + clippy/rustfmt` | T2 |
| T3 | `feat(error): add top-level Error enum` | T3 |
| T4–T7 | `feat(wire): add <protocol> parser/builder` | T4 |
| T8 | `feat(datapath): add virtio_net_hdr_v1 ser/de` | T8 |
| T9 | `feat(config): add config type definitions` | T9 |
| T10 | `feat(dhcp): add LeaseStore` | T10 |
| T11 | `feat(wg): add AllowedIPs router` | T11 |
| T12 | `feat(config): add TOML parser with deny_unknown_fields` | T12 |
| T13 | `feat(config): add clap CLI override surface` | T13 |
| T14 | `feat(wg): add key file loader with mode check` | T14 |
| T15 | `feat(dhcp): add DHCP option builder` | T15 |
| T16 | `feat(dhcp): add atomic JSON lease persistence` | T16 |
| T17 | `feat(arp): add ARP responder` | T17 |
| T18 | `feat(wire): add ICMPv4 generator` | T18 |
| T19 | `feat(ops): add tracing-subscriber setup` | T19 |
| T20 | `feat(ops): add capability dropping` | T20 |
| T21 | `feat(ops): add sd_notify wrapper` | T21 |
| T22 | `feat(config): add semantic validation` | T22 |
| T23 | `feat(dhcp): add server state machine` | T23 |
| T24 | `feat(wg): add Peer type` | T24 |
| T25 | `feat(wg): add WG engine` | T25 |
| T26 | `feat(datapath): add frame intercept classifier` | T26 |
| T27 | `feat(datapath): add vring TX/RX processor` | T27 |
| T28 | `feat(datapath): add VhostUserBackendMut impl + reconnect handler` | T28 |
| T29 | `feat(daemon): wire main + lib + lifecycle` | T29 |
| T30 | `test: add mock vhost-user master harness` | T30 |
| T31–T34 | `test(integration): add <surface> integration tests` | T31 |
| T35 | `test(smoke): VAL-1 reconnect-fd-reregistration smoke test` | T35 |
| T36 | `chore(packaging): add systemd template + example TOML` | T36 |
| T37 | `docs: add README + CONTRIBUTING + man-style docs` | T37 |

Pre-commit hook (set up in T2): `cargo fmt -- --check`, `cargo clippy -- -D warnings`, `cargo check`. CI re-runs these.

---

## Success Criteria

### Pre-Commit Verification (CI on every PR)

```bash
cargo build --release --locked                                                  # exit 0
cargo test --locked --all-targets                                               # 0 failed
cargo clippy --locked --all-targets --all-features -- \
  -D warnings -D clippy::unwrap_used -D clippy::expect_used \
  -D clippy::panic -D clippy::as_conversions \
  -A clippy::unwrap_used::tests -A clippy::expect_used::tests                   # exit 0
cargo fmt --all -- --check                                                      # exit 0
cargo deny check                                                                # exit 0
cargo audit --deny warnings                                                     # exit 0
cargo doc --no-deps --locked 2>&1 | grep -E '^(warning|error):' | wc -l         # = 0
```

### Final Checklist (gated by F1–F4 and user okay)

- [ ] All "Must Have" items present (verified by F1)
- [ ] All "Must NOT Have" hard constraints absent (verified by F2 grep audits + F4 scope check)
- [ ] All scope-out items absent (verified by F4)
- [ ] All `cargo test` integration scenarios pass (verified by F2)
- [ ] Privilege drop verified live (`/proc/$pid/status` shows non-zero Uid effective + CapEff = 0; verified by F3)
- [ ] sd_notify protocol exchanged correctly (READY=1 once, WATCHDOG=1 cadence; verified by F3)
- [ ] Cloud Hypervisor + Linux guest end-to-end: DHCP → ARP → WG handshake → ICMP through tunnel (verified by F3)
- [ ] Reconnect lifecycle: external fds re-registered after frontend restart (verified by F3 and AC-VU-2)
- [ ] License: dual MIT/Apache-2.0 verified per AC-LIC-1/2/3
- [ ] Trust-boundary enforcement: all hostile-guest tests pass (AC-SEC-1..5)
- [ ] PMTU end-to-end: ICMPv4 Type 3 Code 4 generated for oversized guest frame (verified by F3 with `tcpdump`)
- [ ] User explicitly approves after seeing F1-F4 verdicts. Without explicit "okay", do not mark complete.
