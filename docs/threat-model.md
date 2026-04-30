# Threat Model

This document describes the security assumptions, trust boundaries, and known limitations of `vhost-user-wireguard`. It's written for operators who need to understand what the daemon protects against and what it doesn't.

---

## Threat Actors

### Hostile guest VM

The primary threat actor is a guest VM that has been compromised or is intentionally malicious. The guest controls the virtio-net device and can send arbitrary Ethernet frames to the daemon. We assume the guest will:

- Send frames with spoofed source MACs
- Send frames with spoofed source IPs
- Send frames with unusual or malformed ethertypes
- Send fragmented IP packets
- Send oversized frames
- Attempt to exhaust the daemon's resources (CPU, memory, file descriptors)
- Attempt to escape its assigned IP range and reach other VMs or the host

### Compromised WireGuard peer

A WireGuard peer that has been compromised can send arbitrary decrypted traffic to the daemon. Once the WireGuard handshake completes, the peer is trusted at the IP layer. The daemon does not inspect or filter traffic arriving from the WireGuard underlay.

### Local host attacker

An attacker with local access to the host (but not root) can:

- Read the vhost-user Unix socket path (it's in `/run/vhost-user-wg/`)
- Attempt to connect to the socket and impersonate a VM frontend

The daemon does not authenticate the vhost-user frontend. Socket permissions are the only protection here (see [Socket Security](#socket-security) below).

---

## Trust Boundary

The trust boundary is the 10-step classifier in `src/datapath/intercept.rs`. Every frame from the guest must pass all applicable steps before being forwarded to WireGuard.

### Step-by-step

**Step 1: Frame size**

Frames shorter than 14 bytes (the minimum Ethernet header) are dropped. This prevents the parser from reading past the end of the buffer.

**Step 2: Ethernet parse**

The Ethernet header is parsed. If parsing fails (which shouldn't happen after step 1, but is checked defensively), the frame is dropped.

**Step 3: Source MAC check**

The source MAC in the Ethernet header must match `vm.mac` from the config. Frames from any other MAC are dropped silently. This prevents the guest from impersonating other VMs or the gateway.

**Step 4: Ethertype filter**

Only two ethertypes are accepted:
- `0x0806` (ARP)
- `0x0800` (IPv4)

All other ethertypes (IPv6, VLAN tags, 802.1Q, etc.) are dropped. This is a strict whitelist, not a blacklist.

**Step 5: ARP fast-path**

ARP frames are handled locally by the ARP responder. The daemon responds to ARP requests for the gateway IP with the gateway MAC. ARP frames are never forwarded to WireGuard. This means the guest cannot use ARP to probe the host network.

**Step 6: IPv4 parse**

The IPv4 header is parsed. Malformed headers (wrong version, header length too short, total length exceeding frame size) cause the frame to be dropped.

**Step 7: Fragment rejection**

IPv4 fragments (IP_MF flag set, or fragment_offset != 0) are dropped. Fragmented packets are a common source of parsing complexity and evasion techniques. The daemon doesn't need to reassemble fragments because the VM's MTU is set to 1420 (below the WireGuard MTU), so fragmentation shouldn't occur in normal operation.

**Step 8: DHCP fast-path**

UDP packets destined for port 67 (DHCP server) are handled locally by the DHCP server. DHCP traffic is never forwarded to WireGuard.

**Step 9: Source IP anti-spoof**

After the VM has received a DHCP lease, the source IP in the IPv4 header must match the assigned VM IP. Frames with any other source IP are dropped. This prevents the guest from sending traffic that appears to originate from other VMs or arbitrary IPs.

Before DHCP bind (i.e., before the VM has an IP), this check is skipped so the VM can send DHCP Discover/Request frames (which have source IP 0.0.0.0).

**Step 10: Route lookup**

The destination IP is looked up in the WireGuard routing table. If no peer has an `allowed_ips` entry that matches the destination, the frame is dropped. This prevents the guest from sending traffic to destinations that aren't reachable through WireGuard.

---

## What the Daemon Protects Against

| Threat | Protection |
|--------|-----------|
| MAC spoofing | Step 3: source MAC check |
| IP spoofing (after DHCP bind) | Step 9: source IP check |
| Non-IP traffic (IPv6, VLAN, etc.) | Step 4: ethertype whitelist |
| IP fragmentation attacks | Step 7: fragment rejection |
| ARP poisoning / ARP probing | Step 5: ARP handled locally |
| DHCP starvation / rogue DHCP | Step 8: DHCP handled locally |
| Traffic to unreachable destinations | Step 10: route lookup |
| Malformed frames | Steps 1, 2, 6: size and parse checks |

---

## What the Daemon Does NOT Protect Against

### Rate limiting

There is no rate limiting. A hostile guest can saturate the host CPU by sending frames as fast as the virtio-net device allows. The daemon will process every frame through the trust boundary classifier, which is cheap, but boringtun's encryption is not free. Under sustained attack, expect one CPU core to be fully saturated.

### Traffic volume from WireGuard peers

Traffic arriving from WireGuard peers is not rate-limited or filtered beyond what WireGuard itself provides (replay protection, authentication).

### DHCP exhaustion

The DHCP pool is typically a single address (the VM's assigned IP). A hostile guest can send DHCP DECLINE to put that address in probation, then send DISCOVER to get a new one. With a single-address pool, this effectively denies the VM network access for `decline_probation_secs`. This is a denial-of-service against the VM itself, not against other VMs.

### Content inspection

The daemon does not inspect the payload of IPv4 packets beyond what's needed for the trust boundary checks. A hostile guest can send arbitrary application-layer traffic to any destination reachable through WireGuard.

### WireGuard peer trust

Once the WireGuard handshake completes, the peer is trusted. The daemon does not verify that traffic from a peer is "expected" in any application-layer sense. If a peer sends traffic that looks like it's from a different VM's IP, the daemon will deliver it to the guest.

### vhost-user frontend authentication

The vhost-user protocol has no authentication. Any process that can connect to the Unix socket can act as a VM frontend. Socket permissions (`/run/vhost-user-wg/` is owned by `vhost-user-wg:vhost-user-wg` with mode 0700) are the only protection. If an attacker gains access to the `vhost-user-wg` user, they can connect to any VM's socket.

---

## Socket Security

The vhost-user Unix socket is created at the path specified in `vhost_user.socket`. The daemon creates the socket file; the parent directory must exist before the daemon starts.

Recommended permissions:

```bash
# Parent directory: owned by vhost-user-wg, mode 0750
# (QEMU/Cloud-Hypervisor must be in the vhost-user-wg group)
chown vhost-user-wg:vhost-user-wg /run/vhost-user-wg
chmod 0750 /run/vhost-user-wg
```

The socket file itself inherits the daemon's umask. Set `UMask=0077` in the systemd unit if you want the socket to be accessible only by the daemon user.

---

## Key Material

### Private key

The WireGuard private key is loaded once at startup from a file or inline base64. After loading:

1. The key is passed to boringtun, which copies it internally.
2. The inline base64 string in the `Config` struct is zeroized (overwritten with zeros) before the struct is used further.
3. The key file is not kept open after loading.

The key material lives in boringtun's internal state for the lifetime of the process. It's not written to disk by the daemon (the file was already there before startup).

### Preshared keys

Per-peer preshared keys follow the same lifecycle as the private key: loaded once, passed to boringtun, inline strings zeroized.

---

## Privilege Escalation Surface

After startup, the daemon runs as an unprivileged user with no capabilities. The attack surface for privilege escalation is:

- **boringtun**: a pure Rust WireGuard implementation. Memory safety bugs in boringtun could allow arbitrary code execution, but not privilege escalation (no capabilities to abuse).
- **vhost-user-backend**: the vhost-user protocol implementation. Memory safety bugs here could allow the guest to corrupt daemon memory.
- **The daemon's own code**: written in safe Rust. `unsafe` blocks are limited to FFI calls (rustix, caps) and are reviewed carefully.

The systemd sandboxing (`ProtectSystem=strict`, `PrivateDevices`, etc.) limits what a compromised daemon process can do even if code execution is achieved.

---

## Multi-VM Isolation

Each VM gets its own daemon process. There is no shared state between daemons. A compromise of one daemon does not directly affect others.

The only shared resource is the host network stack (the WireGuard UDP socket). Each daemon binds its own UDP port. If two daemons are configured with the same port, the second one will fail to bind.

---

## Out-of-Scope Threats

The following are outside the scope of this threat model:

- **Host kernel vulnerabilities**: if the host kernel is compromised, all bets are off.
- **Hypervisor vulnerabilities**: if QEMU/Cloud-Hypervisor is compromised, the guest can escape the VM entirely.
- **Physical access**: an attacker with physical access to the host can read memory, bypass disk encryption, etc.
- **WireGuard cryptographic weaknesses**: the daemon relies on WireGuard's security properties. If WireGuard's cryptography is broken, the tunnel is broken.
- **Supply chain attacks**: the daemon depends on several crates. A malicious dependency could compromise the daemon.
