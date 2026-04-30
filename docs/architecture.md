# Architecture

This document describes the internal structure of `vhost-user-wireguard` in enough detail to understand how the pieces fit together, where the interesting complexity lives, and why certain design choices were made.

---

## Overview

`vhost-user-wireguard` is a single Rust binary that exposes a virtio-net device to one KVM guest via the vhost-user protocol, and tunnels that guest's traffic through WireGuard. One process per VM. No shared state between instances.

The binary is structured as a library crate (`src/lib.rs`) with a thin `main.rs` wrapper. All logic lives in the library so it can be unit-tested without spawning a process.

---

## Module Map

```
src/
  lib.rs          -- top-level run() orchestration
  main.rs         -- CLI entry point, calls run()
  config/
    mod.rs        -- Config struct definitions (serde)
    cli.rs        -- clap CLI args + override application
    toml.rs       -- TOML file loading
    validate.rs   -- config validation (collects all errors)
  datapath/
    mod.rs        -- WgNetBackend (vhost-user-backend impl)
    intercept.rs  -- trust boundary classifier (TX path)
    serve.rs      -- vhost-user serve loop
  dhcp/
    mod.rs        -- DhcpServer: packet handling + lease management
    lease.rs      -- LeaseFile: JSON persistence
    pool.rs       -- address allocation
  wg/
    mod.rs        -- WgEngine: boringtun wrapper
    keys.rs       -- key loading (file + inline base64)
  arp/
    mod.rs        -- ARP responder
  wire/
    mod.rs        -- Ethernet/IPv4/ICMP frame parsing helpers
  ops/
    caps.rs       -- privilege drop + capability drop
    logging.rs    -- tracing subscriber setup
    systemd.rs    -- sd_notify wrappers
  error.rs        -- top-level Error enum (thiserror)
```

---

## Startup Sequence

`run()` in `src/lib.rs` is the single entrypoint. It runs sequentially:

1. **Load config** from TOML file (`config::toml::load`)
2. **Apply CLI overrides** on top of the loaded config
3. **`--check-config` early exit**: validate and print "config OK", then return
4. **Full validation**: collect every config error in one pass, return `Err` if any
5. **Install tracing subscriber** (text or JSON, with env-filter)
6. **Load WireGuard private key** from file or inline base64
7. **Build `WgEngine`**: initialises boringtun, loads per-peer preshared keys
8. **Zeroize inline key strings** still resident in the `Config` struct
9. **Build `DhcpServer`**: loads lease file, initialises pool and reservations
10. **Build `InterceptCfg`**: trust boundary parameters consumed by the TX classifier
11. **Build `WgNetBackend`**: wires together the engine, DHCP server, and intercept config; creates the shutdown `EventFd`
12. **Spawn signal thread**: converts SIGTERM/SIGINT into a write to the shutdown `EventFd`
13. **Drop privileges**: `setgid` then `setuid` to the configured user/group
14. **Drop capabilities**: all capabilities removed after privilege drop
15. **`READY=1`** to systemd
16. **Run vhost-user serve loop**: blocks until the frontend disconnects or a shutdown signal arrives
17. **Teardown**: `STOPPING=1` to systemd, poke the shutdown `EventFd` to wake the signal thread, join it

Steps 13 and 14 happen before step 15 deliberately. systemd interprets `READY=1` as "fully initialised", and we don't want any privileged code paths to run after that point.

---

## Data Path

### RX path (guest to WireGuard)

```
Guest virtqueue (TX ring)
  |
  | virtio-net frame (L2 Ethernet)
  |
WgNetBackend::process_tx_queue()
  |
InterceptCfg::classify()   <-- trust boundary (10 steps, see below)
  |
  +-- ARP? --> ARP responder --> reply to guest virtqueue (RX ring)
  |
  +-- DHCP? --> DhcpServer::handle() --> reply to guest virtqueue (RX ring)
  |
  +-- IPv4 unicast --> WgEngine::encapsulate() --> UDP socket (WireGuard underlay)
```

### TX path (WireGuard to guest)

```
UDP socket (WireGuard underlay)
  |
WgEngine::decapsulate()
  |
  | decrypted IPv4 payload
  |
WgNetBackend::inject_to_guest()
  |
  | wrap in Ethernet frame (src: gateway MAC, dst: vm MAC)
  |
Guest virtqueue (RX ring)
```

The daemon also generates ICMPv4 Type 3 Code 4 (fragmentation needed) messages when a packet exceeds the WireGuard MTU. These are injected directly into the guest RX ring without going through the WireGuard engine.

---

## Trust Boundary Classifier

`InterceptCfg::classify()` in `src/datapath/intercept.rs` is the 10-step pipeline that every frame from the guest must pass before being forwarded:

| Step | Check | Action on failure |
|------|-------|-------------------|
| 1 | Frame length >= 14 bytes | Drop |
| 2 | Parse Ethernet header | Drop |
| 3 | Source MAC == `vm.mac` | Drop |
| 4 | Ethertype is ARP (0x0806) or IPv4 (0x0800) | Drop |
| 5 | ARP fast-path | Respond locally, don't forward |
| 6 | Parse IPv4 header | Drop |
| 7 | IP_MF flag or fragment_offset != 0 | Drop |
| 8 | DHCP fast-path (UDP dst port 67) | Handle locally, don't forward |
| 9 | Source IP == assigned VM IP (after DHCP bind) | Drop |
| 10 | Route lookup | Forward to WireGuard |

Steps 5 and 8 are "fast paths" that consume the frame locally and generate a reply without forwarding to WireGuard. This means ARP and DHCP traffic never leaves the host.

Step 9 is only enforced after the VM has received a DHCP lease. Before that, the source IP check is skipped so the VM can send DHCP Discover/Request frames.

---

## WireGuard Engine

`WgEngine` in `src/wg/mod.rs` wraps boringtun's `Tunn` struct. It owns:

- The private key (loaded once at startup, never stored in the config after zeroization)
- A `Vec<Peer>` where each peer holds a `Tunn` instance and its allowed-IP routing table entry
- An `IpNetworkTable` for O(log n) longest-prefix-match routing

`WgEngine::encapsulate()` takes a raw IPv4 payload, looks up the destination in the routing table, and calls `Tunn::encapsulate()` on the matching peer. The result is a WireGuard UDP packet ready to send.

`WgEngine::decapsulate()` takes a raw UDP payload from the underlay socket, calls `Tunn::decapsulate()` on each peer until one accepts it (or all reject it), and returns the decrypted IPv4 payload.

boringtun handles the WireGuard handshake, key rotation, and replay protection internally. The daemon doesn't need to know about any of that.

---

## DHCP Server

`DhcpServer` in `src/dhcp/mod.rs` is a minimal DHCPv4 server that handles:

- **DISCOVER**: allocate an address from the pool (or return the reserved address for this MAC), send OFFER
- **REQUEST**: confirm the offered address, send ACK or NAK
- **DECLINE**: mark the address as in probation for `decline_probation_secs`
- **RELEASE**: return the address to the pool

The server uses a /30 subnet by design. The gateway takes one address; the VM gets the other. The pool is typically a single address (`start == end`).

Leases are persisted to a JSON file every `checkpoint_secs` seconds. On startup, the file is loaded and existing leases are restored. If the file is corrupt, it's renamed and the server starts fresh.

The lease file path defaults to `/var/lib/vhost-user-wg/leases.json` but can be overridden with `$VUWG_LEASE_PATH`. This override exists so integration tests can redirect persistence to a tempdir without root.

---

## Privilege Model

The daemon needs `CAP_NET_BIND_SERVICE` to bind the WireGuard UDP port (if < 1024). It starts as root, then:

1. `setgid(vhost-user-wg)` -- drop group first
2. `setuid(vhost-user-wg)` -- then drop user
3. `caps::drop_all()` -- remove all capabilities

After step 3, the process has no capabilities and runs as an unprivileged user. The systemd unit adds further sandboxing:

- `ProtectSystem=strict`: filesystem is read-only except for `ReadWritePaths`
- `PrivateTmp=yes`: private `/tmp`
- `PrivateDevices=yes`: no access to device nodes
- `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`
- `NoNewPrivileges=yes`: no `setuid` binaries can gain privileges

---

## Signal Handling

A dedicated `signal-handler` thread is spawned before the serve loop starts. It uses `signal_hook` to register for SIGTERM and SIGINT, then blocks on `Signals::forever()`. When a signal arrives, it writes to the backend's shutdown `EventFd`, which wakes the serve loop and causes it to exit cleanly.

The signal thread exits after the first signal. There's no point looping because the serve loop tears down on the first observed shutdown event.

---

## Error Handling

All errors are typed. The top-level `Error` enum in `src/error.rs` has variants for each subsystem (`Config`, `Wg`, `Dhcp`, `Vhost`, etc.). Each subsystem has its own error enum derived with `thiserror`.

`Box<dyn Error>` is not used anywhere in library code. This keeps error handling explicit and makes it possible to match on specific error variants in tests.

---

## Threading Model

The daemon is effectively single-threaded from a data-path perspective:

- **Main thread**: runs the vhost-user serve loop (blocking)
- **Signal thread**: waits for SIGTERM/SIGINT, writes to the shutdown `EventFd`

There are no worker threads, no thread pools, no async runtimes. The vhost-user serve loop is driven by `epoll` internally (inside the `vhost-user-backend` crate). The daemon's own code is synchronous.

The `WgNetBackend` is wrapped in `Arc<Mutex<_>>` because the vhost-user framework requires it (the backend trait is `Send + Sync`). In practice, the mutex is only contended between the main thread and the signal thread, and the signal thread only holds it briefly to write to the `EventFd`.

---

## Key Design Decisions

**One process per VM.** This is a deliberate choice. It means:
- No shared state between VMs (no cross-VM information leakage)
- A crash in one VM's daemon doesn't affect others
- systemd can manage each VM's daemon independently
- The trust boundary is simpler (no need to demultiplex between VMs)

The trade-off is higher memory overhead per VM. For typical deployments (tens of VMs per host), this is acceptable.

**No async.** The vhost-user serve loop is blocking. Adding async would complicate the privilege-drop sequence (you can't drop privileges after spawning a tokio runtime without careful coordination) and the signal handling (signal-safe code is hard to write in async contexts). The synchronous model is simpler and easier to reason about.

**boringtun over kernel WireGuard.** The daemon runs as an unprivileged user after startup. Kernel WireGuard requires `CAP_NET_ADMIN` to configure. boringtun is pure userspace and needs no special capabilities after the UDP socket is bound.
