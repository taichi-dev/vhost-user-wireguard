# Issues & Gotchas

## Project: vhost-user-wireguard

## [2026-04-30] Known Issues from Plan

- Plan's TODO section is missing explicit entries for T2-T13 (only T1, T15-T37, F1-F4 have checkboxes)
- Task "1" in TODO has T14 (wg/keys) acceptance criteria mixed in - likely plan generation error
- T2-T13 must be executed as part of T1's "Wave 1" even though they lack explicit checkboxes

## F2 Final Wave Code Quality Review (2026-04-30)

### REJECT — clippy fails with `cargo clippy --all-targets -- -D warnings`

11 lints fire (1 hard `deny`, 10 default-`warn` promoted to errors by `-D warnings`):

**Hard `#[deny(clippy::never_loop)]` — real bug-bait, not stylistic:**
- `src/lib.rs:254` — `for signal in signals.forever() { ...; break; }`. Doc comment claims "exits after a single signal" so the intent is correct, but writing it as a `for { break; }` is a deny-level lint. Fix: `if let Some(signal) = signals.forever().next() { ... }`.

**`-D warnings` promotes these (each ≤2-char fix):**
- `src/datapath/mod.rs:459, 462, 466, 471` — six occurrences of `io::Error::new(io::ErrorKind::Other, ...)` → `io::Error::other(...)` (clippy::io_other_error, MSRV 1.74).
- `src/datapath/intercept.rs:167` — `lease.map_or(true, |leased| src_ip != leased)` → `lease != Some(src_ip)` (clippy::unnecessary_map_or).
- `src/config/validate.rs:54` — `mtu < 576 || mtu > 9000` → `!(576..=9000).contains(&mtu)` (clippy::manual_range_contains).
- `src/config/validate.rs:211` — same pattern with `qs`.
- `src/wg/routing.rs:12` — `AllowedIpsRouter::new()` without `Default` (clippy::new_without_default).

CI configured with `-D warnings` will fail. Total fix is mechanical (~15 minutes).

### Test results: ALL PASS
- `cargo test --lib`: 161/161 pass
- `cargo test --tests`: 31 pass + 4 ignored (2 require root, 1 deferred feature, 1 deferred gratuitous-ARP). 0 failures.

### Critical invariants — VERIFIED
- vnet header is exactly 12 bytes: `src/datapath/vnet.rs` (parse rejects <12; serialize returns `[u8; 12]`; integration test `test_vnet_header_size_is_12` passes).
- DHCP INFORM excludes options 51, 54, 58, 59: `src/dhcp/options.rs:116` `build_inform_response` only calls `with_subnet_mask/router/dns/mtu/broadcast`. Test `test_inform_excludes_lease_options` (mod.rs:934) asserts all four are absent. `handle_inform` (mod.rs:259) sets `yiaddr=UNSPECIFIED, siaddr=UNSPECIFIED`.
- WG decapsulate always passes `Some(src_ip)`: `src/wg/peer.rs:146` `tunn.decapsulate(Some(src_addr.ip()), ...)`. The only `None` is in `drain()` (line 168) which is correct per boringtun docs.
- Drain loop after `WriteToNetwork` runs until `Done`: `src/wg/mod.rs:317-329` `drain_peer` is `loop { match drain { WriteToNetwork=>send; Done=>return } }`. Called from both decap (line 180) and encap (line 307) on `WriteToNetwork`.
- Token IDs > num_queues(): `EXTRA_TOKEN_UDP/TIMER/EXIT = NUM_QUEUES+1/+2/+3 = 3/4/5`, NUM_QUEUES=2.
- Feature set: `src/datapath/mod.rs:339-344` advertises exactly `VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_MTU | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | VIRTIO_RING_F_EVENT_IDX`. No offloads.
- 10-step intercept pipeline: `src/datapath/intercept.rs:79-178` matches plan order (size→ethertype→MAC→IPv4→fragment→DHCP→src IP→route).
- EVENT_IDX TX drain: `src/datapath/vring.rs:329-364` is canonical (outer loop, disable→drain→enable, signal once).

### Error handling
- No production-path `unwrap()/expect()/panic!()` outside tests.
- `let _ = store.bind(...)` in `dhcp/mod.rs:72` swallows lease-restore error during constructor — minor, persisted lease conflict at boot is non-actionable.
- `let _ = notify_stopping()` and `let _ = b.signal_exit()` in `lib.rs:225, 228` are intentional best-effort teardown (commented).
- All other error paths log via `tracing::warn!/trace!/error!` — no silent swallowing in datapath.

### Verdict: REJECT
Single blocker: clippy not clean. Fix is mechanical (≤15 min), 11 sites listed above. After fix, code is APPROVE-ready: all tests pass, all critical invariants hold, error handling is sound.
