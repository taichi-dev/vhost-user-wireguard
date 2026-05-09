# vhost-user-wireguard

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/owner/vhost-user-wireguard/actions/workflows/ci.yml/badge.svg)](https://github.com/owner/vhost-user-wireguard/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](https://www.rust-lang.org)

Userspace WireGuard vhost-user-net daemon for KVM/QEMU/Cloud-Hypervisor. Each VM gets its own process, its own WireGuard identity, and an embedded DHCPv4 server. The daemon speaks the vhost-user protocol over a Unix socket, so the guest sees a standard virtio-net device with no kernel module required on the host.

**Note: This is a pure vibe coding artifact with little testing, use at your own risk**

---

## Features

- **Per-VM WireGuard identity** via [boringtun](https://github.com/cloudflare/boringtun) (pure userspace, no kernel module)
- **Embedded DHCPv4 server** with static MAC reservations, dynamic pool, and JSON lease persistence
- **Local ARP responder** for the virtual gateway (no ARP traffic escapes to the underlay)
- **ICMPv4 PMTU generation** (Type 3 Code 4) so path MTU discovery works inside the VM
- **Adaptive busy polling** of the data path (UDP socket + TX virtqueue) for low-latency burst traffic
- **Hostile-guest hardening**: ethertype whitelist, MAC/IP anti-spoofing, frame-size enforcement
- **Capability-dropping privilege model**: starts as root, drops to a dedicated user, then drops all capabilities
- **systemd-native**: `Type=notify`, watchdog heartbeat, `ProtectSystem=strict`, and more
- **Structured logs**: text or JSON via `--log-format text|json`
- **Config validation**: `--check-config` validates without starting the daemon

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │  Guest VM                                               │
  │  virtio-net (L2 Ethernet)                               │
  └──────────────────────┬──────────────────────────────────┘
                         │
              vhost-user Unix socket
                         │
  ┌──────────────────────▼──────────────────────────────────┐
  │  vhost-user-wireguard daemon                            │
  │                                                         │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │ Trust        │  │ DHCPv4       │  │ ARP          │  │
  │  │ Boundary     │  │ Server       │  │ Responder    │  │
  │  │ Classifier   │  │              │  │              │  │
  │  └──────┬───────┘  └──────────────┘  └──────────────┘  │
  │         │                                               │
  │  ┌──────▼───────────────────────────────────────────┐   │
  │  │  WireGuard Engine (boringtun)                    │   │
  │  └──────────────────────────┬───────────────────────┘   │
  └─────────────────────────────┼───────────────────────────┘
                                │
              WireGuard UDP socket (dual-stack)
                                │
  ┌─────────────────────────────▼───────────────────────────┐
  │  WireGuard peer (remote host / gateway)                 │
  └─────────────────────────────────────────────────────────┘
```

The daemon is single-threaded by design. One process per VM. The vhost-user serve loop drives everything: RX frames from the guest go through the trust boundary classifier before being handed to boringtun; TX frames from boringtun are delivered directly to the guest virtqueue.

---

## Quickstart

### 1. Install

```bash
cargo install --path .
# or copy the release binary
cp target/release/vhost-user-wireguard /usr/bin/
```

### 2. Create a dedicated user

```bash
useradd --system --no-create-home --shell /sbin/nologin vhost-user-wg
mkdir -p /etc/vhost-user-wg /run/vhost-user-wg /var/lib/vhost-user-wg
chown vhost-user-wg:vhost-user-wg /run/vhost-user-wg /var/lib/vhost-user-wg
chmod 0700 /var/lib/vhost-user-wg
```

### 3. Generate WireGuard keys

```bash
wg genkey | tee /etc/vhost-user-wg/vm1.key | wg pubkey > /etc/vhost-user-wg/vm1.pub
chmod 0600 /etc/vhost-user-wg/vm1.key
chown vhost-user-wg:vhost-user-wg /etc/vhost-user-wg/vm1.key
```

### 4. Write a config file

Copy `examples/example-vm.toml` to `/etc/vhost-user-wg/vm1.toml` and edit:

```toml
[vm]
mac = "52:54:00:12:34:01"
mtu = 1420
ip  = "10.42.0.2"

[vhost_user]
socket     = "/run/vhost-user-wg/vm1.sock"
queue_size = 256
num_queues = 2

[network]
subnet  = "10.42.0.0/30"
gateway = "10.42.0.1"
dns     = ["8.8.8.8"]

[wireguard]
private_key_file = "/etc/vhost-user-wg/vm1.key"
listen_port      = 51820

[[wireguard.peers]]
name       = "gateway"
public_key = "<peer-pubkey>"
endpoint   = "192.0.2.1:51820"
allowed_ips = ["0.0.0.0/0"]

[dhcp]
decline_probation_secs = 3600
checkpoint_secs        = 60
reservations           = []

[dhcp.pool]
start = "10.42.0.2"
end   = "10.42.0.2"
```

Validate before starting:

```bash
vhost-user-wireguard --check-config --config /etc/vhost-user-wg/vm1.toml
# config OK
```

### 5. Enable and start via systemd

```bash
systemctl enable --now vhost-user-wg@vm1.service
```

The unit file is a template: `vm1` maps to `/etc/vhost-user-wg/vm1.toml`.

### 6. Verify

```bash
journalctl -u vhost-user-wg@vm1.service -f
```

You should see `ready` logged once the daemon has dropped privileges and signalled systemd.

---

## Configuration Reference

Full annotated example: [`examples/example-vm.toml`](examples/example-vm.toml)

| Section | Key fields | Notes |
|---------|-----------|-------|
| `[vm]` | `mac`, `mtu`, `ip` | MAC must match the virtio-net device; MTU 1420 recommended |
| `[vhost_user]` | `socket`, `queue_size` | Socket parent dir must exist before start |
| `[network]` | `subnet`, `gateway`, `dns` | Only /30 subnets accepted |
| `[wireguard]` | `private_key_file` or `private_key`, `listen_port` | Exactly one key source required |
| `[[wireguard.peers]]` | `public_key`, `endpoint`, `allowed_ips` | Repeat section for each peer |
| `[dhcp]` | `checkpoint_secs`, `reservations` | Leases persisted to JSON |
| `[dhcp.pool]` | `start`, `end` | Dynamic pool range |
| `[busy_poll]` | `budget_us`, `initial_packets`, `min_packets`, `max_packets` | Adaptive busy-poll tuning; `budget_us=0` disables |

CLI flags override any TOML value. Run `vhost-user-wireguard --help` for the full list.

---

## Operational Guide

### Log format

```bash
# Human-readable (default)
vhost-user-wireguard --config vm1.toml --log-format text

# Machine-readable JSON (for log aggregators)
vhost-user-wireguard --config vm1.toml --log-format json
```

Log level is controlled by `--log-filter` (default: `info`). Accepts any `tracing` filter string, e.g. `--log-filter vhost_user_wireguard=debug`.

### Watchdog

The systemd unit sets `WatchdogSec=30s`. The daemon sends `WATCHDOG=1` on every successful virtqueue poll cycle. If the process hangs, systemd will restart it after 30 seconds.

### DHCP lease file

Leases are written to `/var/lib/vhost-user-wg/leases.json` (or `$VUWG_LEASE_PATH` if set). The file is flushed every `checkpoint_secs` seconds. If the file is corrupt on startup, it's renamed to `leases.json.bak.<timestamp>` and the server starts with an empty table.

### Troubleshooting

**Frontend disconnect / VM restart**

The daemon exits when the vhost-user frontend disconnects. The systemd unit has `Restart=on-failure`, so it will restart automatically. If you need the daemon to survive VM reboots without restarting, set `Restart=always`.

**"missing --config" error**

The `--config` flag is required. There is no default config path.

**"config OK" but daemon won't start**

Check that the socket parent directory exists and is writable by `vhost-user-wg`. Check that the private key file is readable by `vhost-user-wg`.

**Guest gets no DHCP lease**

Confirm `vm.mac` in the config matches the MAC address configured on the virtio-net device in QEMU/Cloud-Hypervisor. The trust boundary classifier drops frames from unknown MACs.

**High CPU on the host**

boringtun is pure userspace. Under sustained throughput, expect one CPU core to be saturated. This is expected behaviour for a single-queue userspace WireGuard implementation.

---

## Security Model

See [`docs/threat-model.md`](docs/threat-model.md) for the full analysis. Summary:

**What the daemon enforces:**

- Ethertype whitelist: only ARP (0x0806) and IPv4 (0x0800) frames accepted from the guest
- Source MAC check: frames with a MAC other than `vm.mac` are dropped silently
- IP fragment rejection: fragmented IPv4 packets are dropped
- Source IP anti-spoof: after DHCP bind, frames with a source IP other than the assigned address are dropped
- Frame size enforcement: frames shorter than 14 bytes (Ethernet header) are dropped

**What the daemon does NOT enforce:**

- The guest can still send arbitrary traffic to its assigned IP and MAC
- There is no rate limiting
- There is no content inspection beyond the trust boundary classifier
- The WireGuard peer is trusted once the handshake completes

**Privilege model:**

The daemon starts as root (needed to bind the WireGuard UDP port), then calls `setgid`/`setuid` to drop to the `vhost-user-wg` user, then drops all Linux capabilities. The systemd unit adds further sandboxing via `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, and related directives.

---

## Out of Scope

The following are explicitly not supported and will not be added without a design discussion:

- IPv6 (IPv4 only)
- Multiqueue (single queue pair)
- Prometheus metrics endpoint
- Control socket / hot reload
- Kernel WireGuard module (`wireguard.ko`)
- GSO/TSO offloads

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
