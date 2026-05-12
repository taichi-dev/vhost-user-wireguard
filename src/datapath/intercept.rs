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

use etherparse::icmpv4::DestUnreachableHeader;
use etherparse::{
    EtherType, Ethernet2Slice, Icmpv4Type, IpNumber, Ipv4Slice, PacketBuilder, UdpSlice,
};

use crate::arp::handle_arp_request;
use crate::dhcp::DhcpServer;
use crate::wg::routing::AllowedIpsRouter;

const DHCP_SERVER_PORT: u16 = 67;
const ETH_HEADER_LEN: usize = 14;
const ICMP_FRAG_NEEDED_TTL: u8 = 64;

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
        return InterceptDecision::IcmpFragNeeded(build_frag_needed_reply(
            &frame[ETH_HEADER_LEN..],
            cfg,
            gateway_ip,
        ));
    }

    // 2. Parse Ethernet header.
    let eth = match Ethernet2Slice::from_slice_without_fcs(frame) {
        Ok(e) => e,
        Err(_) => return InterceptDecision::Drop(DropReason::FrameTooSmall),
    };

    // 3. Source MAC anti-spoof. The VM may only emit frames sourced from its
    //    configured MAC.
    if eth.source() != cfg.vm_mac {
        return InterceptDecision::Drop(DropReason::SrcMacSpoofed);
    }

    // 4. Ethertype filter (and 5. ARP fast path).
    let ethertype = eth.ether_type();
    match ethertype {
        EtherType::IPV4 => {}
        EtherType::ARP => {
            return match handle_arp_request(frame, cfg.gateway_ip, cfg.gateway_mac, cfg.vm_mac) {
                Some(reply) => InterceptDecision::ArpReply(reply),
                None => InterceptDecision::Drop(DropReason::EthTypeFiltered(EtherType::ARP.0)),
            };
        }
        EtherType::VLAN_TAGGED_FRAME => return InterceptDecision::Drop(DropReason::VlanTagged),
        other => return InterceptDecision::Drop(DropReason::EthTypeFiltered(other.0)),
    }

    // 6. Parse IPv4.
    let ip_payload = eth.payload_slice();
    let ip = match Ipv4Slice::from_slice(ip_payload) {
        Ok(p) => p,
        Err(_) => return InterceptDecision::Drop(DropReason::BadIpv4Header),
    };

    // 7. Reject IP fragments. We refuse to forward fragments at the trust
    //    boundary so that downstream code can rely on a single self-contained
    //    IP datagram per call.
    if ip.is_payload_fragmented() {
        return InterceptDecision::Drop(DropReason::FragmentedPacket);
    }

    // 8. DHCP fast path. Only takes the path when the inner UDP datagram is
    //    well-formed AND addressed to the BOOTP/DHCP server port.
    if ip.header().protocol() == IpNumber::UDP {
        if let Ok(udp) = UdpSlice::from_slice(ip.payload().payload) {
            if udp.destination_port() == DHCP_SERVER_PORT {
                return match dhcp.handle_packet(frame, now) {
                    Ok(Some(reply)) => InterceptDecision::DhcpReply(reply),
                    Ok(None) => {
                        InterceptDecision::Drop(DropReason::EthTypeFiltered(EtherType::IPV4.0))
                    }
                    Err(_) => InterceptDecision::Drop(DropReason::BadUdpHeader),
                };
            }
        }
    }

    // 9. Source IP anti-spoof. Allow 0.0.0.0 (used by some boot protocols)
    //    or an exact match against the active DHCP lease; everything else is
    //    rejected.
    let src_ip = ip.header().source_addr();
    if src_ip != Ipv4Addr::UNSPECIFIED && lease != Some(src_ip) {
        return InterceptDecision::Drop(DropReason::SrcIpSpoofed);
    }

    // 10. Route lookup against the WireGuard allowed-IPs trie.
    match route.lookup_v4(ip.header().destination_addr()) {
        Some(peer_idx) => InterceptDecision::Tunnel {
            peer_idx,
            ip_packet: ip_payload.to_vec(),
        },
        None => InterceptDecision::Drop(DropReason::NoRoute),
    }
}

/// RFC 792: ICMP Destination Unreachable carries the offending IP header
/// plus the first 8 bytes of its payload (so the original sender can match
/// the reply against an in-flight 4-tuple).
fn build_frag_needed_reply(
    original_ip_packet: &[u8],
    cfg: &InterceptCfg,
    gateway_ip: Ipv4Addr,
) -> Vec<u8> {
    let orig = match Ipv4Slice::from_slice(original_ip_packet) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let orig_header = orig.header().slice();
    let orig_payload_prefix = &orig.payload().payload[..orig.payload().payload.len().min(8)];
    let mut icmp_data = Vec::with_capacity(orig_header.len() + orig_payload_prefix.len());
    icmp_data.extend_from_slice(orig_header);
    icmp_data.extend_from_slice(orig_payload_prefix);

    let dst_ip = orig.header().source();
    let builder = PacketBuilder::ethernet2(cfg.gateway_mac, cfg.vm_mac)
        .ipv4(gateway_ip.octets(), dst_ip, ICMP_FRAG_NEEDED_TTL)
        .icmpv4(Icmpv4Type::DestinationUnreachable(
            DestUnreachableHeader::FragmentationNeeded {
                next_hop_mtu: cfg.vm_mtu,
            },
        ));
    let mut buf = Vec::with_capacity(builder.size(icmp_data.len()));
    // `PacketBuilder::write` into a `Vec<u8>` cannot fail for in-range payloads
    // (vector growth is the only I/O sink). Treat any unexpected error as a
    // soft drop — the caller already tolerates an empty reply.
    if builder.write(&mut buf, &icmp_data).is_err() {
        return Vec::new();
    }
    buf
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use ip_network::Ipv4Network;
    use mac_address::MacAddress;
    use tempfile::TempDir;

    use super::*;
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
        proto: IpNumber,
        body: &[u8],
        mf: bool,
        frag_offset: u16,
    ) -> Vec<u8> {
        use etherparse::{IpFragOffset, Ipv4Header};
        let mut header =
            Ipv4Header::new(body.len() as u16, 64, proto, src.octets(), dst.octets()).unwrap();
        header.more_fragments = mf;
        header.fragment_offset = IpFragOffset::try_new(frag_offset).unwrap();
        let mut bytes = Vec::with_capacity(20 + body.len());
        header.write(&mut bytes).unwrap();
        bytes.extend_from_slice(body);
        bytes
    }

    fn build_eth_frame(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        ether_type: EtherType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + payload.len());
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&ether_type.0.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        use etherparse::{ArpHardwareId, ArpOperation, ArpPacket};
        ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &sender_mac,
            &sender_ip.octets(),
            &[0u8; 6],
            &target_ip.octets(),
        )
        .unwrap()
        .to_bytes()
        .to_vec()
    }

    fn build_dhcp_discover(vm_mac: [u8; 6]) -> Vec<u8> {
        use dhcproto::v4::{
            DhcpOption, DhcpOptions, Encodable, Encoder, Flags, HType, Message, MessageType, Opcode,
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

        let builder = PacketBuilder::ethernet2(vm_mac, [0xff; 6])
            .ipv4(
                Ipv4Addr::UNSPECIFIED.octets(),
                Ipv4Addr::BROADCAST.octets(),
                64,
            )
            .udp(68, 67);
        let mut frame = Vec::with_capacity(builder.size(dhcp_buf.len()));
        builder.write(&mut frame, &dhcp_buf).unwrap();
        frame
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
        // 9000-byte frame with a valid IPv4 header so build_frag_needed_reply
        // has a packet to reflect.
        let body = vec![0u8; 9000 - 14 - 20];
        let ipv4 = build_ipv4(
            VM_IP,
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::UDP,
            &body,
            false,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &ipv4);
        assert!(frame.len() > usize::from(cfg.vm_mtu) + ETH_HEADER_LEN);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
        match result {
            InterceptDecision::IcmpFragNeeded(reply) => {
                let eth = Ethernet2Slice::from_slice_without_fcs(&reply).unwrap();
                assert_eq!(eth.destination(), VM_MAC);
                assert_eq!(eth.source(), GW_MAC);
                assert_eq!(eth.ether_type(), EtherType::IPV4);
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
        let ipv4 = build_ipv4(
            VM_IP,
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::TCP,
            &[0u8; 4],
            false,
            0,
        );
        let wrong_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let frame = build_eth_frame(GW_MAC, wrong_mac, EtherType::IPV4, &ipv4);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
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
        let frame = build_eth_frame([0xff; 6], VM_MAC, EtherType::IPV6, &[0u8; 40]);
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
        let frame = build_eth_frame([0xff; 6], VM_MAC, EtherType::VLAN_TAGGED_FRAME, &[0u8; 4]);
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
        let frame = build_eth_frame([0xff; 6], VM_MAC, EtherType::ARP, &arp);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
        match result {
            InterceptDecision::ArpReply(reply) => {
                let eth = Ethernet2Slice::from_slice_without_fcs(&reply).unwrap();
                assert_eq!(eth.destination(), VM_MAC);
                assert_eq!(eth.source(), GW_MAC);
                assert_eq!(eth.ether_type(), EtherType::ARP);
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
                let eth = Ethernet2Slice::from_slice_without_fcs(&reply).unwrap();
                assert_eq!(eth.ether_type(), EtherType::IPV4);
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
        // Use TCP to bypass the DHCP fast path entirely.
        let ipv4 = build_ipv4(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::TCP,
            &[0u8; 4],
            false,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &ipv4);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
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
        let ipv4 = build_ipv4(
            VM_IP,
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::TCP,
            &[0u8; 4],
            false,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &ipv4);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
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
        let ipv4 = build_ipv4(
            VM_IP,
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::TCP,
            &[0u8; 4],
            false,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &ipv4);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
        match result {
            InterceptDecision::Tunnel {
                peer_idx,
                ip_packet,
            } => {
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
        let ipv4 = build_ipv4(
            VM_IP,
            Ipv4Addr::new(8, 8, 8, 8),
            IpNumber::TCP,
            &[0u8; 4],
            true,
            0,
        );
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &ipv4);
        let result = classify(
            &frame,
            &cfg,
            Some(VM_IP),
            &route,
            UNIX_EPOCH,
            &mut dhcp,
            GW_IP,
        );
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
        // Version field set to 5 — Ipv4Slice::from_slice will reject it.
        let bad_ipv4 = vec![0x55; 20];
        let frame = build_eth_frame(GW_MAC, VM_MAC, EtherType::IPV4, &bad_ipv4);
        let result = classify(&frame, &cfg, None, &route, UNIX_EPOCH, &mut dhcp, GW_IP);
        assert!(matches!(
            result,
            InterceptDecision::Drop(DropReason::BadIpv4Header)
        ));
    }
}
