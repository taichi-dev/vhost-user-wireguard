# Unresolved Blockers

## Project: vhost-user-wireguard

(none yet)

## Project: vhost-user-wireguard

### Gratuitous ARP after DHCP ACK is not implemented (discovered during T32)

**What the plan §17 calls for**:
- `arp::ArpResponder::build_gratuitous() -> Vec<u8>` — a gratuitous ARP frame advertising `(gateway_mac, gateway_ip, gateway_ip)` per RFC 5227 §1.2.
- A hook in the DHCP path that emits one such frame onto the RX queue immediately after a successful `MessageType::Ack` so guests with stale ARP caches see the gateway MAC announce as soon as they bind.

**Current state**:
- `src/arp/mod.rs` only contains `handle_arp_request` (request → reply responder).
- `grep -rn "gratuit" src/` returns zero hits; no gratuitous ARP construction exists anywhere in the daemon.
- `src/dhcp/mod.rs` returns a single `Option<Vec<u8>>` from `handle_packet`. There is no multi-frame reply mechanism — the classifier (`src/datapath/intercept.rs:152-158`) maps `Ok(Some(reply))` to a single `InterceptDecision::DhcpReply(_)`. The architecture needs minor extension to support emitting a follow-up gratuitous ARP onto `WgNetBackend::rx_queue` after the DHCP ACK is queued.

**Test impact**:
- `tests/integration_arp.rs::test_gratuitous_arp_after_dhcp_ack` is `#[ignore]`d. The ignore reason cites this entry. The test body is correct as-written: when the feature ships, removing `#[ignore]` exercises it immediately.

**Suggested implementation skeleton** (for whoever picks this up):
1. Add `pub fn build_gratuitous(gateway_mac: [u8;6], gateway_ip: Ipv4Addr) -> Vec<u8>` in `src/arp/mod.rs` (Ethernet dst = broadcast `[0xff;6]`, src = gateway_mac, ethertype = 0x0806; ARP op=2 reply, sha=gateway_mac, spa=gateway_ip, tha=`[0;6]` or `[0xff;6]`, tpa=gateway_ip).
2. Either change `DhcpServer::handle_packet` return to `Vec<Vec<u8>>` (multi-frame), OR push the gratuitous frame directly onto `WgNetBackend::rx_queue` from inside the DHCP fast-path branch in `WgNetBackend::run_tx` after `InterceptDecision::DhcpReply` is enqueued, gated on the inner DHCP message type being `Ack`.
3. Track lease-bind state in `DhcpServer` so the gratuitous ARP only fires once per ACK (not on every renewal — guests don't need repeated announces during a stable lease).
4. When the feature lands, remove `#[ignore]` from `test_gratuitous_arp_after_dhcp_ack` and update the module docstring in `tests/integration_arp.rs`.
