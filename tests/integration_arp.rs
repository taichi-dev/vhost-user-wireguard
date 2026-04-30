// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end ARP-responder integration tests against the real daemon binary.
//!
//! Each test owns a fresh [`MockVhostUserMaster`]: its own work tempdir, its
//! own vhost-user socket path, its own lease-file path (via the
//! `VUWG_LEASE_PATH` env var), and its own listen-port allocation. There is
//! no shared state between tests, so they may safely run in parallel.
//!
//! Coverage:
//!   * `test_arp_request_for_gateway_gets_reply` — happy path; ARP for the
//!     configured gateway IP gets a well-formed reply with the configured
//!     gateway MAC.
//!   * `test_arp_request_for_other_ip_dropped` — ARP for any non-gateway IP
//!     is silently dropped (the daemon only impersonates the gateway).
//!   * `test_arp_request_with_wrong_src_mac_dropped` (EC-F-3) — Ethernet
//!     src-MAC anti-spoof: a frame whose Ethernet src differs from the
//!     configured `vm.mac` is dropped BEFORE reaching the ARP responder
//!     (`Drop(SrcMacSpoofed)` in `intercept::classify`).
//!   * `test_gratuitous_arp_after_dhcp_ack` — `#[ignore]`d. The plan §17
//!     calls for `build_gratuitous` plus an emit-on-bind hook, but T17
//!     deferred the emission side (only `handle_arp_request` landed). When
//!     that feature ships, remove the `#[ignore]` and the test will
//!     immediately exercise it. Tracked in `problems.md`.

mod common;

use std::net::Ipv4Addr;

use dhcproto::v4::{
    DhcpOption, DhcpOptions, Flags, HType, Message, MessageType, Opcode, OptionCode,
};
use dhcproto::{Decodable as _, Decoder, Encodable as _, Encoder};

use common::{
    GATEWAY_IP, GATEWAY_MAC, MockVhostUserMaster, VM_IP, VM_MAC, build_arp_request,
    build_dhcp_discover,
};

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ARP_OPER_REPLY: u16 = 2;
const IPPROTO_UDP: u8 = 17;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

// === ARP reply assertion helper ===

/// Walk the Ethernet + ARP headers of `frame` and assert it is a well-formed
/// ARP reply matching the given `(sha, spa, tha, tpa)` tuple. Panics on any
/// structural mismatch — the daemon must always emit RFC-826-compliant
/// replies.
fn assert_arp_reply(
    frame: &[u8],
    expected_sha: [u8; 6],
    expected_spa: Ipv4Addr,
    expected_tha: [u8; 6],
    expected_tpa: Ipv4Addr,
) {
    assert!(
        frame.len() >= 14 + 28,
        "ARP reply too short: {} bytes (need ≥42)",
        frame.len()
    );
    assert_eq!(
        &frame[0..6],
        &expected_tha,
        "Ethernet dst must echo requester MAC"
    );
    assert_eq!(
        &frame[6..12],
        &expected_sha,
        "Ethernet src must be the replier MAC"
    );
    assert_eq!(
        u16::from_be_bytes([frame[12], frame[13]]),
        ETHERTYPE_ARP,
        "ethertype must be ARP (0x0806)"
    );
    assert_eq!(
        u16::from_be_bytes([frame[14 + 6], frame[14 + 7]]),
        ARP_OPER_REPLY,
        "ARP opcode must be REPLY (2)"
    );
    assert_eq!(
        &frame[14 + 8..14 + 14],
        &expected_sha,
        "ARP sender HW addr must match"
    );
    assert_eq!(
        &frame[14 + 14..14 + 18],
        &expected_spa.octets(),
        "ARP sender proto addr must match"
    );
    assert_eq!(
        &frame[14 + 18..14 + 24],
        &expected_tha,
        "ARP target HW addr must match"
    );
    assert_eq!(
        &frame[14 + 24..14 + 28],
        &expected_tpa.octets(),
        "ARP target proto addr must match"
    );
}

// === Tests ===

#[test]
fn test_arp_request_for_gateway_gets_reply() {
    let mut master = MockVhostUserMaster::spawn();

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);

    let reply = master
        .read_rx_frame()
        .expect("daemon never replied to ARP for the gateway IP");
    assert_arp_reply(&reply, GATEWAY_MAC, GATEWAY_IP, VM_MAC, VM_IP);
}

#[test]
fn test_arp_request_for_other_ip_dropped() {
    let mut master = MockVhostUserMaster::spawn();

    // ARP for any IP other than the configured gateway must be silently
    // dropped: the daemon impersonates the gateway only and refuses to
    // help the guest discover anyone else (`handle_arp_request` returns
    // None → the classifier emits `Drop(EthTypeFiltered(0x0806))`).
    let other_ip = Ipv4Addr::new(10, 42, 0, 99);
    let request = build_arp_request(VM_IP, VM_MAC, other_ip);
    master.write_tx_frame(&request);

    assert!(
        master.read_rx_frame().is_none(),
        "ARP for non-gateway IP must produce no reply"
    );
}

#[test]
fn test_arp_request_with_wrong_src_mac_dropped() {
    let mut master = MockVhostUserMaster::spawn();

    // EC-F-3: Ethernet src-MAC anti-spoof. `intercept::classify`
    // (src/datapath/intercept.rs:111) rejects any frame whose Ethernet
    // src MAC differs from `cfg.vm_mac` with `Drop(SrcMacSpoofed)`
    // BEFORE the ARP fast path runs. The harness's `build_arp_request`
    // uses the `sha` argument as both ARP sender HW and Ethernet src,
    // so passing a non-VM MAC exercises the anti-spoof check.
    let wrong_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x42];
    let request = build_arp_request(VM_IP, wrong_mac, GATEWAY_IP);
    master.write_tx_frame(&request);

    assert!(
        master.read_rx_frame().is_none(),
        "ARP whose Ethernet src MAC differs from vm.mac must be silently dropped"
    );
}

#[test]
#[ignore = "gratuitous ARP on lease-bind is not yet implemented in the daemon \
    (plan §17 calls for `build_gratuitous` + emit-on-bind hook; T17 only landed \
    `handle_arp_request`). Tracked in .sisyphus/notepads/vhost-user-wireguard/problems.md."]
fn test_gratuitous_arp_after_dhcp_ack() {
    let mut master = MockVhostUserMaster::spawn();

    // Step 1: full DORA (DISCOVER → OFFER, REQUEST → ACK).
    let discover = build_dhcp_discover(VM_MAC);
    master.write_tx_frame(&discover);
    let offer_frame = master
        .read_rx_frame()
        .expect("daemon never produced an OFFER");
    let offer = parse_dhcp_reply(&offer_frame);
    assert_eq!(
        offer.opts().msg_type(),
        Some(MessageType::Offer),
        "DISCOVER must yield an OFFER"
    );
    let yiaddr = offer.yiaddr();

    let request =
        build_dhcp_request_selecting(VM_MAC, GATEWAY_IP, yiaddr, offer.xid());
    master.write_tx_frame(&request);
    let ack_frame = master
        .read_rx_frame()
        .expect("daemon never produced an ACK");
    let ack = parse_dhcp_reply(&ack_frame);
    assert_eq!(
        ack.opts().msg_type(),
        Some(MessageType::Ack),
        "REQUEST must yield an ACK"
    );

    // Step 2: after the ACK the daemon must emit one gratuitous ARP
    // advertising the gateway MAC. Per RFC 5227 §1.2 a gratuitous ARP
    // sets `spa == tpa`. The harness will see the frame on the RX queue
    // exactly once.
    let grat_frame = master
        .read_rx_frame()
        .expect("daemon never emitted a gratuitous ARP after DHCP ACK");
    assert!(
        grat_frame.len() >= 14 + 28,
        "gratuitous ARP too short: {} bytes",
        grat_frame.len()
    );
    assert_eq!(
        u16::from_be_bytes([grat_frame[12], grat_frame[13]]),
        ETHERTYPE_ARP,
        "gratuitous frame must be ARP"
    );
    assert_eq!(
        &grat_frame[14 + 8..14 + 14],
        &GATEWAY_MAC,
        "gratuitous ARP sha must be gateway MAC"
    );
    assert_eq!(
        &grat_frame[14 + 14..14 + 18],
        &GATEWAY_IP.octets(),
        "gratuitous ARP spa must be gateway IP"
    );
    assert_eq!(
        &grat_frame[14 + 24..14 + 28],
        &GATEWAY_IP.octets(),
        "gratuitous ARP tpa must equal spa (RFC 5227 §1.2)"
    );
}

// === DHCP helpers (subset of integration_dhcp.rs needed for test 4) ===

/// Build a DHCP REQUEST in SELECTING state (broadcast, server-id +
/// requested-ip set). Mirrors `build_dhcp_request_selecting` from
/// integration_dhcp.rs.
fn build_dhcp_request_selecting(
    mac: [u8; 6],
    server_id: Ipv4Addr,
    requested_ip: Ipv4Addr,
    xid: u32,
) -> Vec<u8> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::MessageType(MessageType::Request));
    opts.insert(DhcpOption::ServerIdentifier(server_id));
    opts.insert(DhcpOption::RequestedIpAddress(requested_ip));
    opts.insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::InterfaceMtu,
    ]));

    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest);
    msg.set_htype(HType::Eth);
    msg.set_xid(xid);
    msg.set_flags(Flags::default().set_broadcast());
    msg.set_chaddr(&mac);
    msg.set_opts(opts);

    let mut dhcp_buf = Vec::with_capacity(512);
    {
        let mut enc = Encoder::new(&mut dhcp_buf);
        msg.encode(&mut enc).expect("encode dhcp request");
    }

    let udp_len = u16::try_from(8 + dhcp_buf.len()).expect("udp length fits");
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp.extend_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(&dhcp_buf);

    let total_len = u16::try_from(20 + udp.len()).expect("ip length fits");
    let mut ip = Vec::with_capacity(usize::from(total_len));
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.push(64);
    ip.push(IPPROTO_UDP);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    ip.extend_from_slice(&Ipv4Addr::BROADCAST.octets());
    let csum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);

    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

/// One's-complement Internet checksum (RFC 1071) over an IPv4 header.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut iter = header.chunks_exact(2);
    for chunk in iter.by_ref() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    let remainder = iter.remainder();
    if let [last] = remainder {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let lo = u16::try_from(sum & 0xFFFF).expect("low 16 bits fit");
    !lo
}

/// Walk Ethernet → IPv4 (variable IHL) → UDP → DHCP and return the parsed
/// reply. Panics on any malformed layer because the daemon must always
/// emit RFC-compliant replies.
fn parse_dhcp_reply(eth_frame: &[u8]) -> Message {
    assert!(
        eth_frame.len() >= 14,
        "frame too short for Ethernet header"
    );
    assert_eq!(
        u16::from_be_bytes([eth_frame[12], eth_frame[13]]),
        ETHERTYPE_IPV4,
        "reply ethertype must be IPv4",
    );
    let ip_payload = &eth_frame[14..];
    assert!(!ip_payload.is_empty(), "missing IP header");
    let ihl = usize::from(ip_payload[0] & 0x0f) * 4;
    assert!(ip_payload.len() >= ihl + 8, "IP+UDP shorter than headers");
    assert_eq!(ip_payload[9], IPPROTO_UDP, "reply must be UDP");
    let dhcp_offset = ihl + 8;
    let dhcp_payload = &ip_payload[dhcp_offset..];
    Message::decode(&mut Decoder::new(dhcp_payload)).expect("decode dhcp reply")
}
