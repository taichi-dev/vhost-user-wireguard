# Operations Runbook

This document is for sysadmins managing `vhost-user-wireguard` in production. It covers installation, day-to-day operations, and troubleshooting.

---

## Installation

### From source

```bash
git clone https://github.com/owner/vhost-user-wireguard
cd vhost-user-wireguard
cargo build --release
cp target/release/vhost-user-wireguard /usr/bin/
```

### System user and directories

```bash
# Create the daemon user
useradd --system --no-create-home --shell /sbin/nologin vhost-user-wg

# Runtime socket directory (cleared on reboot)
mkdir -p /run/vhost-user-wg
chown vhost-user-wg:vhost-user-wg /run/vhost-user-wg
chmod 0750 /run/vhost-user-wg

# State directory (persists across reboots)
mkdir -p /var/lib/vhost-user-wg
chown vhost-user-wg:vhost-user-wg /var/lib/vhost-user-wg
chmod 0700 /var/lib/vhost-user-wg

# Config directory
mkdir -p /etc/vhost-user-wg
chmod 0750 /etc/vhost-user-wg
```

### systemd unit

Copy the template unit file:

```bash
cp packaging/systemd/vhost-user-wg@.service /etc/systemd/system/
systemctl daemon-reload
```

The `@` makes it a template unit. The instance name (e.g., `vm1` in `vhost-user-wg@vm1.service`) maps to `/etc/vhost-user-wg/vm1.toml`.

---

## Per-VM Setup

### 1. Generate WireGuard keys

```bash
VM=vm1

# Generate private key
wg genkey > /etc/vhost-user-wg/${VM}.key
chmod 0600 /etc/vhost-user-wg/${VM}.key
chown vhost-user-wg:vhost-user-wg /etc/vhost-user-wg/${VM}.key

# Derive public key (share this with the WireGuard peer)
wg pubkey < /etc/vhost-user-wg/${VM}.key > /etc/vhost-user-wg/${VM}.pub
cat /etc/vhost-user-wg/${VM}.pub
```

### 2. Write the config file

```bash
cp examples/example-vm.toml /etc/vhost-user-wg/vm1.toml
# Edit /etc/vhost-user-wg/vm1.toml with the correct values
```

Key fields to set:

- `vm.mac`: must match the MAC address on the virtio-net device in QEMU/Cloud-Hypervisor
- `vm.ip`: the IP address the VM will receive via DHCP
- `vhost_user.socket`: path to the Unix socket (e.g., `/run/vhost-user-wg/vm1.sock`)
- `network.subnet`: the /30 subnet (e.g., `10.42.0.0/30`)
- `network.gateway`: the gateway IP (e.g., `10.42.0.1`)
- `wireguard.private_key_file`: path to the key file
- `wireguard.listen_port`: UDP port for WireGuard
- `[[wireguard.peers]]`: at least one peer with `public_key`, `endpoint`, `allowed_ips`

### 3. Validate the config

```bash
vhost-user-wireguard --check-config --config /etc/vhost-user-wg/vm1.toml
# config OK
```

If validation fails, the error message lists every problem found. Fix them all before proceeding.

### 4. Configure QEMU/Cloud-Hypervisor

The VM must be configured to use the vhost-user socket. Example QEMU flags:

```bash
-netdev type=vhost-user,id=net0,chardev=char0,vhostforce=on \
-chardev socket,id=char0,path=/run/vhost-user-wg/vm1.sock \
-device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:01
```

The `mac` in the QEMU flags must match `vm.mac` in the config.

For Cloud-Hypervisor:

```json
{
  "net": [{
    "vhost_user": true,
    "vhost_socket": "/run/vhost-user-wg/vm1.sock",
    "mac": "52:54:00:12:34:01"
  }]
}
```

### 5. Start the daemon

The daemon must be running before the VM starts (it creates the socket that the VM connects to).

```bash
systemctl enable --now vhost-user-wg@vm1.service
```

Check it started:

```bash
systemctl status vhost-user-wg@vm1.service
journalctl -u vhost-user-wg@vm1.service -n 20
```

You should see a log line containing `ready` once the daemon has dropped privileges and signalled systemd.

---

## Day-to-Day Operations

### Starting and stopping

```bash
# Start
systemctl start vhost-user-wg@vm1.service

# Stop (sends SIGTERM, daemon exits cleanly)
systemctl stop vhost-user-wg@vm1.service

# Restart
systemctl restart vhost-user-wg@vm1.service
```

### Checking status

```bash
systemctl status vhost-user-wg@vm1.service
```

The `Active:` line shows whether the daemon is running. The `Watchdog:` line shows the last watchdog ping time.

### Viewing logs

```bash
# Follow live
journalctl -u vhost-user-wg@vm1.service -f

# Last 100 lines
journalctl -u vhost-user-wg@vm1.service -n 100

# Since a specific time
journalctl -u vhost-user-wg@vm1.service --since "2024-01-01 12:00:00"

# JSON format (if daemon was started with --log-format json)
journalctl -u vhost-user-wg@vm1.service -o json | jq .
```

### Managing multiple VMs

Each VM is a separate systemd instance:

```bash
# List all vhost-user-wg instances
systemctl list-units 'vhost-user-wg@*'

# Start all
systemctl start 'vhost-user-wg@*.service'

# Stop all
systemctl stop 'vhost-user-wg@*.service'
```

---

## Embedding the Config in libvirt XML

For libvirt deployments, the daemon TOML config can live inside the domain
XML under `<metadata>`. A qemu hook reads it on `prepare/begin`, writes it
to `/run/vhost-user-wg/<domain>.toml` (ephemeral tmpfs, recreated on every
VM start), and starts the systemd unit. On `release/end` it stops the unit
and removes the file. This keeps the VM definition and its network policy
in a single editable artefact (`virsh edit <domain>`).

### Install the hook

libvirt only invokes a single hook file at `/etc/libvirt/hooks/qemu`, which
makes it awkward for multiple tools to coexist. vhost-user-wireguard ships
its hook as a *drop-in* under `qemu.d/` plus a reference dispatcher script
that runs every drop-in in turn. Pick the install path that matches your
existing setup.

**Path A — no existing libvirt qemu hook (typical):** install the reference
dispatcher and our drop-in.

```bash
# Reference dispatcher (only when /etc/libvirt/hooks/qemu does not exist).
sudo install -m 0755 packaging/libvirt-hook/qemu /etc/libvirt/hooks/qemu

# The drop-in (always).
sudo install -d -m 0755 /etc/libvirt/hooks/qemu.d
sudo install -m 0755 packaging/libvirt-hook/qemu.d/vhost-user-wg \
    /etc/libvirt/hooks/qemu.d/vhost-user-wg

sudo systemctl restart libvirtd     # libvirtd loads hooks at startup
```

**Path B — you already use the `qemu.d/` dispatcher pattern** (e.g.,
VFIO-Tools): install only the drop-in; your existing dispatcher will pick
it up on the next libvirtd restart.

```bash
sudo install -m 0755 packaging/libvirt-hook/qemu.d/vhost-user-wg \
    /etc/libvirt/hooks/qemu.d/vhost-user-wg
sudo systemctl restart libvirtd
```

**Path C — you have a custom `/etc/libvirt/hooks/qemu` script:** do **not**
overwrite it. Either migrate to the drop-in pattern (move your existing
logic into `qemu.d/<your-tool>` and install our reference dispatcher), or
invoke our drop-in from your hook with `exec /etc/libvirt/hooks/qemu.d/vhost-user-wg "$@"` (preserving stdin).

The drop-in is a Python 3 script with no third-party dependencies. It
silently exits 0 for any domain that has no `<vuwg:config>` metadata block,
so it is safe to run for every VM.

### Author the domain

See `examples/vm-with-embedded-config.xml` for a complete, ready-to-edit
template. The relevant fragment is:

```xml
<domain type='kvm'>
  <name>vm1</name>
  ...
  <metadata>
    <vuwg:config xmlns:vuwg='https://github.com/taichi-dev/vhost-user-wireguard'>
      <vuwg:toml><![CDATA[
[vm]
mac = "52:54:00:12:34:01"
mtu = 1420
ip  = "10.66.66.2"

[vhost_user]
socket = "/run/vhost-user-wg/vm1.sock"
...
]]></vuwg:toml>
    </vuwg:config>
  </metadata>
  <devices>
    <interface type='vhostuser'>
      <mac address='52:54:00:12:34:01'/>
      <source type='unix' path='/run/vhost-user-wg/vm1.sock' mode='client'/>
      <model type='virtio'/>
      <driver queues='1' rx_queue_size='256' tx_queue_size='256'/>
    </interface>
  </devices>
</domain>
```

The socket path in `<interface>` MUST match `[vhost_user].socket` in the
embedded TOML. By convention the daemon's socket lives at
`/run/vhost-user-wg/<domain>.sock`, which is also where the hook expects to
find it.

### Lifecycle

| libvirt event       | hook action                                                    |
|---------------------|---------------------------------------------------------------|
| `prepare/begin`     | Write `/run/vhost-user-wg/<domain>.toml` (mode 0600, owned by `vhost-user-wg`), `systemctl start vhost-user-wg@<domain>`, wait for socket, chgrp `libvirt-qemu` (or fall back to `chmod 0666`). |
| `release/end`       | `systemctl stop vhost-user-wg@<domain>`, remove the TOML file. |
| Any other event/phase | No-op.                                                       |

Hook output is logged to the journal under tag `vhost-user-wg-hook`:

```bash
journalctl -t vhost-user-wg-hook -f
```

### Editing the config

`virsh edit <domain>` opens the full XML in `$EDITOR`. Modify the embedded
TOML and save. The change applies on the next `virsh start <domain>` — live
edits to a running domain are not reloaded; stop and start the VM. The
rendered TOML at `/run/vhost-user-wg/<domain>.toml` is overwritten by the
hook on every start, so the canonical source of truth is always the XML.

---

## Log Format

### Text format (default)

```
2024-01-01T12:00:00.000000Z  INFO vhost_user_wireguard: ready
2024-01-01T12:00:01.000000Z  INFO vhost_user_wireguard::datapath: frontend_connected
2024-01-01T12:00:05.000000Z DEBUG vhost_user_wireguard::dhcp: dhcp_discover mac=52:54:00:12:34:01
2024-01-01T12:00:05.000000Z DEBUG vhost_user_wireguard::dhcp: dhcp_offer ip=10.42.0.2
```

### JSON format

Start with `--log-format json` (or set in the systemd unit's `ExecStart`):

```json
{"timestamp":"2024-01-01T12:00:00.000000Z","level":"INFO","target":"vhost_user_wireguard","message":"ready"}
```

JSON format is recommended for log aggregators (Loki, Elasticsearch, etc.).

### Log levels

Default level is `info`. Override with `--log-filter`:

```bash
# Debug everything
--log-filter debug

# Debug only the DHCP module
--log-filter vhost_user_wireguard::dhcp=debug

# Info for everything, debug for datapath
--log-filter info,vhost_user_wireguard::datapath=debug
```

The filter syntax is the same as `RUST_LOG`. See the [tracing-subscriber docs](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) for the full syntax.

---

## DHCP Lease Management

### Lease file location

Default: `/var/lib/vhost-user-wg/leases.json`

Override with `$VUWG_LEASE_PATH`:

```bash
VUWG_LEASE_PATH=/tmp/test-leases.json vhost-user-wireguard --config vm1.toml
```

### Viewing leases

```bash
cat /var/lib/vhost-user-wg/leases.json | jq .
```

### Clearing leases

Stop the daemon, delete or rename the lease file, then restart:

```bash
systemctl stop vhost-user-wg@vm1.service
mv /var/lib/vhost-user-wg/leases.json /var/lib/vhost-user-wg/leases.json.bak
systemctl start vhost-user-wg@vm1.service
```

The daemon will start with an empty lease table. The VM will get a fresh DHCP lease on next boot.

### Corrupt lease file

If the lease file is corrupt (invalid JSON, truncated, etc.), the daemon renames it to `leases.json.bak.<timestamp>` and starts with an empty table. You'll see a log line like:

```
WARN vhost_user_wireguard::dhcp: lease_file_corrupt path=/var/lib/vhost-user-wg/leases.json
```

---

## Watchdog

The systemd unit sets `WatchdogSec=30s`. The daemon sends `WATCHDOG=1` on every successful virtqueue poll cycle. If the daemon hangs (deadlock, infinite loop, etc.), systemd will restart it after 30 seconds.

To check watchdog status:

```bash
systemctl status vhost-user-wg@vm1.service
# Look for: Watchdog: last ping at ...
```

---

## Updating the Daemon

1. Build or download the new binary.
2. Stop the daemon: `systemctl stop vhost-user-wg@vm1.service`
3. Replace the binary: `cp vhost-user-wireguard /usr/bin/`
4. Start the daemon: `systemctl start vhost-user-wg@vm1.service`

The VM will lose network connectivity while the daemon is stopped. If the VM is running, it will reconnect automatically when the daemon restarts (the vhost-user frontend reconnects on socket availability).

For zero-downtime updates, you'd need to live-migrate the VM to another host first. The daemon doesn't support hot reload.

---

## Troubleshooting

### Daemon won't start: "missing --config"

The `--config` flag is required. Check the `ExecStart` line in the systemd unit:

```bash
systemctl cat vhost-user-wg@vm1.service
# ExecStart=/usr/bin/vhost-user-wireguard --config /etc/vhost-user-wg/%i.toml
```

The `%i` expands to the instance name. Make sure `/etc/vhost-user-wg/vm1.toml` exists.

### Daemon won't start: config validation error

Run `--check-config` to see all errors:

```bash
vhost-user-wireguard --check-config --config /etc/vhost-user-wg/vm1.toml
```

Common errors:

- `subnet must be a /30`: only /30 subnets are accepted
- `gateway must be inside subnet`: gateway IP must be in the configured subnet
- `vm.ip must be inside subnet`: VM IP must be in the configured subnet
- `exactly one of private_key or private_key_file must be set`: set one, not both, not neither
- `queue_size must be a power of 2`: valid values are 64, 128, 256, 512, 1024, 2048, 4096

### Daemon won't start: socket directory doesn't exist

```
Error: failed to create vhost-user socket: No such file or directory
```

Create the parent directory:

```bash
mkdir -p /run/vhost-user-wg
chown vhost-user-wg:vhost-user-wg /run/vhost-user-wg
```

### Daemon exits immediately after VM disconnects

This is expected behaviour. The daemon exits when the vhost-user frontend disconnects. The systemd unit has `Restart=on-failure`, so it restarts automatically. If you want the daemon to stay running between VM reboots, change `Restart=on-failure` to `Restart=always` in the unit file.

### Guest gets no DHCP lease

Check that `vm.mac` in the config matches the MAC address on the virtio-net device. The trust boundary classifier drops frames from unknown MACs before they reach the DHCP server.

```bash
# Check what MAC QEMU is using
virsh domiflist vm1
# or check the QEMU command line
ps aux | grep qemu | grep mac
```

Also check the daemon logs for DHCP-related messages:

```bash
journalctl -u vhost-user-wg@vm1.service --log-filter vhost_user_wireguard::dhcp=debug
```

### Guest has an IP but can't reach the WireGuard peer

Check that the WireGuard peer is reachable from the host:

```bash
# Check if the WireGuard UDP port is reachable
nc -u -z <peer-ip> <peer-port>
```

Check the daemon logs for WireGuard handshake messages:

```bash
journalctl -u vhost-user-wg@vm1.service -n 50
```

Check that `allowed_ips` in the config covers the destination the guest is trying to reach.

### High CPU usage

boringtun is pure userspace. Under sustained throughput, one CPU core will be saturated. This is expected. If CPU usage is high even with no traffic, check for:

- A tight loop in the vhost-user serve loop (check for log spam)
- A misconfigured watchdog causing rapid restarts
- An overly aggressive `[busy_poll]` configuration (see below)

### Tuning busy polling

After every event the daemon runs a short adaptive busy-poll window: it drains the WireGuard UDP socket and the TX virtqueue in a tight loop until either the time budget elapses or no source has work. This cuts per-packet latency under burst traffic by ~5–10× (no epoll round-trip per datagram) at the cost of a small amount of CPU spent spinning when the loop exits.

Defaults are conservative — `budget_us = 50` (50 μs) with an adaptive UDP batch growing from 8 toward 64 packets per burst. The packet budget doubles when a burst saturates the current budget (sustained traffic) and halves when it comes in under half the budget (idle).

Tuning knobs (in the `[busy_poll]` section of the TOML, all overridable on the CLI as `--busy-poll-*`):

| Field | Default | Effect |
|-------|---------|--------|
| `budget_us` | `50` | Per-event time budget. Set to `0` to disable busy polling entirely. Higher = better burst latency, more idle CPU. |
| `initial_packets` | `8` | Starting per-burst UDP batch size. |
| `min_packets` | `1` | Lower bound on the adaptive batch. |
| `max_packets` | `64` | Upper bound on the adaptive batch. Capped at 4096. |

When in doubt:

- **Latency-sensitive workload** (e.g. RPC, gaming): try `budget_us = 100` and `max_packets = 128`.
- **CPU-sensitive workload** (idle most of the time): set `budget_us = 0` to disable.
- **Bulk throughput**: defaults are usually fine; the adaptive batch climbs on its own.

The loop exits early on the first no-progress pass, so an idle daemon does NOT burn the full `budget_us` every event — it spins for a few hundred nanoseconds at most when there is no work.

### "backend_mutex_poisoned" in logs

```
ERROR vhost_user_wireguard: backend_mutex_poisoned_in_signal_thread
```

This means a thread panicked while holding the backend mutex. The daemon will likely exit shortly after. Check the logs for the panic message. This is a bug; please report it.

---

## Monitoring

The daemon doesn't expose a metrics endpoint. Monitor it via:

- **systemd**: `systemctl status`, `journalctl`
- **Log aggregation**: ship logs to Loki/Elasticsearch with `--log-format json`
- **Process monitoring**: check that the process is running with your preferred process monitor

Key log events to alert on:

| Event | Log message | Severity |
|-------|------------|---------|
| Daemon ready | `ready` | Info |
| Frontend connected | `frontend_connected` | Info |
| Frontend disconnected | `frontend_disconnected` | Warning |
| Shutdown signal received | `received_shutdown_signal` | Info |
| Lease file corrupt | `lease_file_corrupt` | Warning |
| Signal thread panic | `signal_thread_panicked` | Error |
| Backend mutex poisoned | `backend_mutex_poisoned` | Error |
