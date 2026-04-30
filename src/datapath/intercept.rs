// SPDX-License-Identifier: MIT OR Apache-2.0

//! TX-side frame classifier (the trust-boundary pipeline).
//!
//! Decides whether a TX frame from the VM should be replied to in-band
//! (ARP, DHCP), reflected back as an ICMPv4 "Fragmentation Needed",
//! tunneled to a WireGuard peer, or silently dropped (with a structured reason).
//!
//! This module performs NO I/O. All side effects (vring access, UDP send,
//! WG state transitions) are the caller's responsibility.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::arp::handle_arp_request;
use crate::dhcp::DhcpServer;
use crate::wg::routing::AllowedIpsRouter;
use crate::wire::eth::{EthFrame, build_eth_frame};
use crate::wire::icmp::build_icmp_frag_needed;
use crate::wire::ipv4::Ipv4Packet;
use crate::wire::udp::UdpPacket;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPPROTO_UDP: u8 = 17;
const DHCP_SERVER_PORT: u16 = 67;
const ETH_HEADER_LEN: usize = 14;
const IPV4_FLAGS_MF: u16 = 0x2000;
const IPV4_FRAG_OFFSET_MASK: u16 = 0x1FFF;

/// Reason a TX frame was dropped by the trust-boundary pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DropReason {
    EthTypeFiltered(u16),
    VlanTagged,
    SrcMacSpoofed,
    BadIpv4Header,
    BadUdpHeader,
    FrameTooBig,
    FrameTooSmall,
    ShortDescriptorChain,
    SrcIpSpoofed,
    NoRoute,
    FragmentedPacket,
}

/// What the datapath should do with a TX frame from the VM.
pub enum InterceptDecision {
    /// In-band ARP reply (already wrapped in an Ethernet frame, ready for RX vring).
    ArpReply(Vec<u8>),
    /// In-band DHCP reply (already wrapped in an Ethernet frame, ready for RX vring).
    DhcpReply(Vec<u8>),
    /// ICMPv4 Type 3 Code 4 ("Fragmentation Needed") wrapped in an Ethernet frame
    /// addressed back to the VM.
    IcmpFragNeeded(Vec<u8>),
    /// Forward the inner IP packet through WireGuard peer `peer_idx`.
    Tunnel { peer_idx: usize, ip_packet: Vec<u8> },
    /// Silently drop with a structured reason (intended for counters/logging).
    Drop(DropReason),
}

/// Static configuration consumed by [`classify`].
pub struct InterceptCfg {
    pub vm_mac: [u8; 6],
    pub vm_mtu: u16,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: [u8; 6],
}

/// Classify a single TX Ethernet frame from the VM.
///
/// Implements the trust-boundary pipeline: frame size sanity, source MAC
/// anti-spoof, ethertype filter, ARP fast path, IPv4 sanity, fragment reject,
/// DHCP fast path, source IP anti-spoof, and final route lookup.
///
/// The function performs NO I/O and is fully deterministic given its inputs
/// (modulo the side-effecting [`DhcpServer`] state machine).
pub fn classify(
    frame: &[u8],
    cfg: &InterceptCfg,
    lease: Option<Ipv4Addr>,
    route: &AllowedIpsRouter,
    now: SystemTime,
    dhcp: &mut DhcpServer,
    gateway_ip: Ipv4Addr,
) -> InterceptDecision {
    // 1. Frame size sanity. A frame shorter than the Ethernet header is
    //    unparseable; one larger than vm_mtu + Ethernet header triggers an
    //    ICMPv4 PMTU response (NOT a drop).
    if frame.len() < ETH_HEADER_LEN {
        return InterceptDecision::Drop(DropReason::FrameTooSmall);
    }
    let max_frame_len = usize::from(cfg.vm_mtu) + ETH_HEADER_LEN;
    if frame.len() > max_frame_len {
        let icmp_ipv4 =
            build_icmp_frag_needed(&frame[ETH_HEADER_LEN..], cfg.vm_mtu, gateway_ip);
        let icmp_eth =
            build_eth_frame(cfg.vm_mac, cfg.gateway_mac, ETHERTYPE_IPV4, &icmp_ipv4);
        return InterceptDecision::IcmpFragNeeded(icmp_eth);
    }

    // 2. Parse Ethernet header.
    let eth = match EthFrame::new(frame) {
        Some(e) => e,
        None => return InterceptDecision::Drop(DropReason::FrameTooSmall),
    };

    // 3. Source MAC anti-spoof. The VM may only emit frames sourced from its
    //    configured MAC.
    if eth.src_mac() != cfg.vm_mac {
        return InterceptDecision::Drop(DropReason::SrcMacSpoofed);
    }

    // 4. Ethertype filter (and 5. ARP fast path).
    let ethertype = eth.ethertype();
    match ethertype {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_ARP => {
            return match handle_arp_request(frame, cfg.gateway_ip, cfg.gateway_mac, cfg.vm_mac)
            {
                Some(reply) => InterceptDecision::ArpReply(reply),
                None => InterceptDecision::Drop(DropReason::EthTypeFiltered(ETHERTYPE_ARP)),
            };
        }
        ETHERTYPE_VLAN => return InterceptDecision::Drop(DropReason::VlanTagged),
        other => return InterceptDecision::Drop(DropReason::EthTypeFiltered(other)),
    }

    // 6. Parse IPv4.
    let ip_payload = eth.payload();
    let ip = match Ipv4Packet::new(ip_payload) {
        Some(p) => p,
        None => return InterceptDecision::Drop(DropReason::BadIpv4Header),
    };

    // 7. Reject IP fragments. We refuse to forward fragments at the trust
    //    boundary so that downstream code can rely on a single self-contained
    //    IP datagram per call.
    let flags_frag = u16::from_be_bytes([ip_payload[6], ip_payload[7]]);
    let mf_set = (flags_frag & IPV4_FLAGS_MF) != 0;
    let frag_offset = flags_frag & IPV4_FRAG_OFFSET_MASK;
    if mf_set || frag_offset != 0 {
        return InterceptDecision::Drop(DropReason::FragmentedPacket);
    }

    // 8. DHCP fast path. Only takes the path when the inner UDP datagram is
    //    well-formed AND addressed to the BOOTP/DHCP server port.
    if ip.protocol() == IPPROTO_UDP {
        if let Some(udp) = UdpPacket::new(ip.payload()) {
            if udp.dst_port() == DHCP_SERVER_PORT {
                return match dhcp.handle_packet(frame, now) {
                    Ok(Some(reply)) => InterceptDecision::DhcpReply(reply),
                    Ok(None) => {
                        InterceptDecision::Drop(DropReason::EthTypeFiltered(ETHERTYPE_IPV4))
                    }
                    Err(_) => InterceptDecision::Drop(DropReason::BadUdpHeader),
                };
            }
        }
    }

    // 9. Source IP anti-spoof. Allow 0.0.0.0 (used by some boot protocols)
    //    or an exact match against the active DHCP lease; everything else is
    //    rejected.
    let src_ip = ip.src_ip();
    if src_ip != Ipv4Addr::UNSPECIFIED && lease != Some(src_ip) {
        return InterceptDecision::Drop(DropReason::SrcIpSpoofed);
    }

    // 10. Route lookup against the WireGuard allowed-IPs trie.
    match route.lookup_v4(ip.dst_ip()) {
        Some(peer_idx) => InterceptDecision::Tunnel {
            peer_idx,
            ip_packet: ip_payload.to_vec(),
        },
        None => InterceptDecision::Drop(DropReason::NoRoute),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::UNIX_EPOCH;

    use ip_network::Ipv4Network;
    use mac_address::MacAddress;
    use tempfile::TempDir;

    use crate::config::{Dhcp, DhcpPool, Network, Vm};

    const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);

    fn make_cfg() -> InterceptCfg {
        InterceptCfg {
            vm_mac: VM_MAC,
            vm_mtu: 1420,
            gateway_ip: GW_IP,
            gateway_mac: GW_MAC,
        }
    }

    fn make_dhcp_server(persist_dir: &TempDir) -> DhcpServer {
        let network = Network {
            subnet: Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap(),
            gateway: GW_IP,
            dns: vec![GW_IP],
        };
        let dhcp_cfg = Dhcp {
            pool: DhcpPool {
                start: Ipv4Addr::new(10, 0, 0, 100),
                end: Ipv4Addr::new(10, 0, 0, 105),
            },
            decline_probation_secs: 600,
            checkpoint_secs: 60,
            reservations: vec![],
        };
        let vm = Vm {
            mtu: 1420,
            mac: MacAddress::from(VM_MAC),
            ip: VM_IP,
        };
        let path = persist_dir.path().join("leases.json");
        DhcpServer::new(network, dhcp_cfg, GW_MAC, vm, path).unwrap()
    }

    fn build_ipv4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        body: &[u8],
        mf: bool,
        frag_offset: u16,
    ) -> Vec<u8> {
        let total_len = u16::try_from(20 + body.len()).unwrap();
        let mut bytes = Vec::with_capacity(usize::from(total_len));
        bytes.push(0x45); // version=4, IHL=5
        bytes.push(0x00);
        bytes.extend_from_slice(&total_len.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]); // identification
        let mf_bits = if mf { IPV4_FLAGS_MF } else { 0 };
        let flags_frag = mf_bits | (frag_offset & IPV4_FRAG_OFFSET_MASK);
        bytes.extend_from_slice(&flags_frag.to_be_bytes());
        bytes.push(64); // TTL
        bytes.push(proto);
        bytes.extend_from_slice(&[0, 0]); // header checksum (left zero for tests)
        bytes.extend_from_slice(&src.octets());
        bytes.extend_from_slice(&dst.octets());
        bytes.extend_from_slice(body);
        bytes
    }

    fn build_arp_request(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut arp = vec![0u8; 28];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
        arp[4] = 6; // hlen
        arp[5] = 4; // plen
        arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // op = REQUEST
        arp[8..14].copy_from_slice(&sender_mac);
        arp[14..18].copy_from_slice(&sender_ip.octets());
        arp[24..28].copy_from_slice(&target_ip.octets());
        arp
    }

    fn build_dhcp_discover(vm_mac: [u8; 6]) -> Vec<u8> {
        use dhcproto::v4::{
            DhcpOption, DhcpOptions, Encodable, Encoder, Flags, HType, Message, MessageType,
            Opcode,
        };

        let mut opts = DhcpOptions::default();
        opts.insert(DhcpOption::MessageType(MessageType::Discover));

        let mut dhcp = Message::default();
        dhcp.set_opcode(Opcode::BootRequest);
        dhcp.set_htype(HType::Eth);
        dhcp.set_chaddr(&vm_mac);
        dhcp.set_flags(Flags::default().set_broadcast());
        dhcp.set_opts(opts);

        let mut dhcp_buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut dhcp_buf);
            dhcp.encode(&mut enc).unwrap();
        }

        let udp_len = u16::try_from(8 + dhcp_buf.len()).unwrap();
        let mut udp = Vec::with_capacity(usize::from(udp_len));
        udp.extend_from_slice(&68u16.to_be_bytes()); // src port (client)
        udp.extend_from_slice(&67u16.to_be_bytes()); // dst port (server)
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum (skipped)
        udp.extend_from_slice(&dhcp_buf);

        let ipv4 = build_ipv4(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 17, &udp, false, 0);
        build_eth_frame([0xff; 6], vm_mac, 0x0800, &ipv4)
    }

    #[test]
    fn test_frame_too_small() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let frame = vec![0u8; 10];
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::FrameTooSmall)
        ));
    }

    #[test]
    fn test_frame_too_big_generates_icmp() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        // 9000-byte frame with a valid IPv4 header so build_icmp_frag_needed
        // has a packet to reflect.
        let body = vec![0u8; 9000 - 14 - 20];
        let ipv4 = build_ipv4(VM_IP, Ipv4Addr::new(8, 8, 8, 8), 17, &body, false, 0);
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &ipv4);
        assert!(frame.len() > usize::from(cfg.vm_mtu) + 14);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        match result {
            InterceptDecision::IcmpFragNeeded(reply) => {
                // Must be at least an Ethernet header + IPv4 header + ICMP header.
                assert!(reply.len() >= 14 + 20 + 8);
                // Outer Ethernet is addressed to the VM.
                assert_eq!(&reply[0..6], &VM_MAC);
                assert_eq!(&reply[6..12], &GW_MAC);
                assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), 0x0800);
            }
            _ => panic!("expected IcmpFragNeeded"),
        }
    }

    #[test]
    fn test_src_mac_spoofed() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let ipv4 = build_ipv4(VM_IP, Ipv4Addr::new(8, 8, 8, 8), 6, &[0u8; 4], false, 0);
        let wrong_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let frame = build_eth_frame(GW_MAC, wrong_mac, 0x0800, &ipv4);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::SrcMacSpoofed)
        ));
    }

    #[test]
    fn test_eth_type_ipv6_filtered() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let frame = build_eth_frame([0xff; 6], VM_MAC, 0x86DD, &[0u8; 40]);
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::EthTypeFiltered(0x86DD))
        ));
    }

    #[test]
    fn test_eth_type_vlan_filtered() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let frame = build_eth_frame([0xff; 6], VM_MAC, 0x8100, &[0u8; 4]);
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::VlanTagged)
        ));
    }

    #[test]
    fn test_arp_reply_path() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let arp = build_arp_request(VM_MAC, VM_IP, GW_IP);
        let frame = build_eth_frame([0xff; 6], VM_MAC, 0x0806, &arp);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        match result {
            InterceptDecision::ArpReply(reply) => {
                assert!(reply.len() >= 14 + 28);
                assert_eq!(&reply[0..6], &VM_MAC);
                assert_eq!(&reply[6..12], &GW_MAC);
                assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), 0x0806);
            }
            _ => panic!("expected ArpReply"),
        }
    }

    #[test]
    fn test_dhcp_reply_path() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let frame = build_dhcp_discover(VM_MAC);
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        match result {
            InterceptDecision::DhcpReply(reply) => {
                // Outer Ethernet must carry IPv4.
                assert!(reply.len() >= 14 + 20 + 8);
                assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), 0x0800);
            }
            _ => panic!("expected DhcpReply"),
        }
    }

    #[test]
    fn test_src_ip_spoofed() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        // Use TCP (proto=6) to bypass the DHCP fast path entirely.
        let ipv4 = build_ipv4(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(8, 8, 8, 8),
            6,
            &[0u8; 4],
            false,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &ipv4);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::SrcIpSpoofed)
        ));
    }

    #[test]
    fn test_no_route() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let ipv4 = build_ipv4(VM_IP, Ipv4Addr::new(8, 8, 8, 8), 6, &[0u8; 4], false, 0);
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &ipv4);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::NoRoute)
        ));
    }

    #[test]
    fn test_valid_tunnel_path() {
        let cfg = make_cfg();
        let mut route = AllowedIpsRouter::new();
        let net: ip_network::IpNetwork = "0.0.0.0/0".parse().unwrap();
        route.insert(net, 42);
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        let ipv4 = build_ipv4(VM_IP, Ipv4Addr::new(8, 8, 8, 8), 6, &[0u8; 4], false, 0);
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &ipv4);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        match result {
            InterceptDecision::Tunnel { peer_idx, ip_packet } => {
                assert_eq!(peer_idx, 42);
                assert_eq!(ip_packet, ipv4);
            }
            _ => panic!("expected Tunnel"),
        }
    }

    #[test]
    fn test_fragmented_drop() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        // MF flag set => packet is a non-final fragment.
        let ipv4 = build_ipv4(VM_IP, Ipv4Addr::new(8, 8, 8, 8), 6, &[0u8; 4], true, 0);
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &ipv4);
        let result = classify(&frame, &cfg, Some(VM_IP), &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::FragmentedPacket)
        ));
    }

    #[test]
    fn test_bad_ipv4_header() {
        let cfg = make_cfg();
        let route = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp_server(&dir);
        // Version field set to 5 — Ipv4Packet::new will reject it.
        let bad_ipv4 = vec![0x55; 20];
        let frame = build_eth_frame(GW_MAC, VM_MAC, 0x0800, &bad_ipv4);
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::BadIpv4Header)
        ));
    }
}
