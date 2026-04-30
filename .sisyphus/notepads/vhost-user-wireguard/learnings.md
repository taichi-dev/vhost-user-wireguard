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
