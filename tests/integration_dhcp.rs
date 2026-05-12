// SPDX-License-Identifier: MIT OR Apache-2.0

// Integration tests use panic-on-failure as the natural assertion idiom;
// suppress the production-only restriction lints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions
)]

//! End-to-end DHCP integration tests against the real daemon binary.
//!
//! Each test owns a fresh [`MockVhostUserMaster`]: its own work tempdir, its
//! own vhost-user socket path, its own lease-file path (via the
//! `VUWG_LEASE_PATH` env var), and its own listen-port allocation. There is
//! no shared state between tests, so they may safely run in parallel.
//!
//! Coverage for the plan's DHCP acceptance criteria:
//!   * `test_discover_offer_request_ack_full_dora` — full DORA round-trip.
//!   * `test_inform_response_excludes_lease_options` — AC-DHCP-7.
//!   * `test_init_reboot_ack_match_and_nak_mismatch` — AC-DHCP-8.
//!   * `test_lease_persistence_across_restart` — AC-DHCP-9.
//!   * `test_decline_then_offer_blocked_during_probation` — EC-D-6.
//!   * `test_release_then_reacquire` — EC-D-7.
//!   * `test_chaddr_mismatch_drops` — EC-D-2.

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::{MockVhostUserMaster, VM_MAC, build_dhcp_discover};
use dhcproto::v4::{
    DhcpOption, DhcpOptions, Flags, HType, Message, MessageType, Opcode, OptionCode,
};
use dhcproto::{Decodable as _, Decoder, Encodable as _, Encoder};

const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 2);
const SERVER_ID: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

// === DHCP message-builder helpers ===
//
// Each builder produces a complete Ethernet frame (14 + 20 + 8 + N bytes)
// ready for the master's TX queue. Source MAC always matches the chaddr
// argument unless `eth_src_mac` is explicitly overridden — the daemon's
// trust-boundary classifier rejects frames whose Ethernet source MAC
// differs from the configured VM MAC, so almost all builders use VM_MAC
// for the Ethernet header.

fn build_dhcp_request_selecting(
    mac: [u8; 6],
    server_id: Ipv4Addr,
    requested_ip: Ipv4Addr,
    xid: u32,
) -> Vec<u8> {
    build_dhcp_frame(
        mac,
        mac,
        MessageType::Request,
        vec![
            DhcpOption::ServerIdentifier(server_id),
            DhcpOption::RequestedIpAddress(requested_ip),
        ],
        Ipv4Addr::UNSPECIFIED,
        true,
        xid,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
    )
}

fn build_dhcp_request_init_reboot(mac: [u8; 6], requested_ip: Ipv4Addr, xid: u32) -> Vec<u8> {
    build_dhcp_frame(
        mac,
        mac,
        MessageType::Request,
        vec![DhcpOption::RequestedIpAddress(requested_ip)],
        Ipv4Addr::UNSPECIFIED,
        true,
        xid,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
    )
}

fn build_dhcp_inform(mac: [u8; 6], ciaddr: Ipv4Addr, xid: u32) -> Vec<u8> {
    build_dhcp_frame(
        mac,
        mac,
        MessageType::Inform,
        vec![],
        ciaddr,
        false,
        xid,
        ciaddr,
        SERVER_ID,
    )
}

fn build_dhcp_decline(
    mac: [u8; 6],
    declined_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    xid: u32,
) -> Vec<u8> {
    build_dhcp_frame(
        mac,
        mac,
        MessageType::Decline,
        vec![
            DhcpOption::RequestedIpAddress(declined_ip),
            DhcpOption::ServerIdentifier(server_id),
        ],
        Ipv4Addr::UNSPECIFIED,
        false,
        xid,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
    )
}

fn build_dhcp_release(mac: [u8; 6], leased_ip: Ipv4Addr, server_id: Ipv4Addr, xid: u32) -> Vec<u8> {
    build_dhcp_frame(
        mac,
        mac,
        MessageType::Release,
        vec![DhcpOption::ServerIdentifier(server_id)],
        leased_ip,
        false,
        xid,
        leased_ip,
        server_id,
    )
}

/// Build a REQUEST whose Ethernet src MAC == VM MAC but whose DHCP chaddr
/// is `wrong_chaddr`. This exercises the DHCP-server-side chaddr filter
/// without tripping the upstream Ethernet anti-spoof check.
fn build_dhcp_request_chaddr_mismatch(
    eth_src_mac: [u8; 6],
    wrong_chaddr: [u8; 6],
    requested_ip: Ipv4Addr,
    xid: u32,
) -> Vec<u8> {
    build_dhcp_frame(
        eth_src_mac,
        wrong_chaddr,
        MessageType::Request,
        vec![DhcpOption::RequestedIpAddress(requested_ip)],
        Ipv4Addr::UNSPECIFIED,
        true,
        xid,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_dhcp_frame(
    eth_src_mac: [u8; 6],
    chaddr: [u8; 6],
    msg_type: MessageType,
    extra_opts: Vec<DhcpOption>,
    ciaddr: Ipv4Addr,
    broadcast_flag: bool,
    xid: u32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::MessageType(msg_type));
    for opt in extra_opts {
        opts.insert(opt);
    }
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
    msg.set_ciaddr(ciaddr);
    if broadcast_flag {
        msg.set_flags(Flags::default().set_broadcast());
    }
    msg.set_chaddr(&chaddr);
    msg.set_opts(opts);

    let mut dhcp_buf = Vec::with_capacity(512);
    {
        let mut enc = Encoder::new(&mut dhcp_buf);
        msg.encode(&mut enc).expect("encode dhcp message");
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
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let csum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);

    let dst_mac: [u8; 6] = if broadcast_flag || dst_ip == Ipv4Addr::BROADCAST {
        [0xff; 6]
    } else {
        common::GATEWAY_MAC
    };

    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&eth_src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

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

// === Reply parsing ===

/// Parse the DHCP reply embedded inside an Ethernet frame produced by the
/// daemon. Walks Ethernet → IPv4 (variable IHL) → UDP → DHCP. Panics on
/// any malformed layer because the daemon must always emit RFC-compliant
/// replies.
fn parse_dhcp_reply(eth_frame: &[u8]) -> Message {
    assert!(eth_frame.len() >= 14, "frame too short for Ethernet header");
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
    let udp_offset = ihl;
    let dhcp_offset = udp_offset + 8;
    let dhcp_payload = &ip_payload[dhcp_offset..];
    Message::decode(&mut Decoder::new(dhcp_payload)).expect("decode dhcp reply")
}

/// Drive a single DHCP exchange and return the parsed reply. Panics with a
/// helpful diagnostic if no reply arrives within the harness's RX timeout.
fn dhcp_round_trip(master: &mut MockVhostUserMaster, request_frame: &[u8]) -> Message {
    master.write_tx_frame(request_frame);
    let reply_frame = master
        .read_rx_frame()
        .expect("daemon never produced a DHCP reply");
    parse_dhcp_reply(&reply_frame)
}

/// Drive a DORA exchange (DISCOVER + REQUEST) and return the leased IP.
/// Used as a setup helper by tests that exercise post-DORA behavior.
fn run_dora(master: &mut MockVhostUserMaster) -> Ipv4Addr {
    let discover = build_dhcp_discover(VM_MAC);
    let offer = dhcp_round_trip(master, &discover);
    assert_eq!(
        offer.opts().msg_type(),
        Some(MessageType::Offer),
        "DISCOVER must yield an OFFER"
    );
    let yiaddr = offer.yiaddr();
    assert_ne!(yiaddr, Ipv4Addr::UNSPECIFIED, "OFFER yiaddr must be set");

    let request = build_dhcp_request_selecting(VM_MAC, SERVER_ID, yiaddr, offer.xid());
    let ack = dhcp_round_trip(master, &request);
    assert_eq!(
        ack.opts().msg_type(),
        Some(MessageType::Ack),
        "REQUEST must yield an ACK"
    );
    assert_eq!(ack.yiaddr(), yiaddr, "ACK yiaddr must match OFFER yiaddr");
    yiaddr
}

// === Tests ===

#[test]
fn test_discover_offer_request_ack_full_dora() {
    let mut master = MockVhostUserMaster::spawn();

    let discover = build_dhcp_discover(VM_MAC);
    let offer = dhcp_round_trip(&mut master, &discover);
    assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
    let yiaddr = offer.yiaddr();
    assert_eq!(yiaddr, VM_IP, "/30 single-host pool must offer 10.42.0.2");

    let server_id_opt = offer.opts().get(OptionCode::ServerIdentifier);
    assert!(
        matches!(server_id_opt, Some(DhcpOption::ServerIdentifier(_))),
        "OFFER must include option 54"
    );

    let request = build_dhcp_request_selecting(VM_MAC, SERVER_ID, yiaddr, offer.xid());
    let ack = dhcp_round_trip(&mut master, &request);
    assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
    assert_eq!(ack.yiaddr(), yiaddr);
    assert_eq!(ack.xid(), offer.xid(), "ACK xid must echo REQUEST xid");

    for code in [
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::InterfaceMtu,
        OptionCode::AddressLeaseTime,
        OptionCode::ServerIdentifier,
        OptionCode::Renewal,
        OptionCode::Rebinding,
    ] {
        assert!(
            ack.opts().get(code).is_some(),
            "ACK is missing option {code:?}"
        );
    }

    if let Some(DhcpOption::Router(routers)) = ack.opts().get(OptionCode::Router) {
        assert_eq!(
            routers,
            &vec![SERVER_ID],
            "ACK router must point at gateway"
        );
    } else {
        panic!("ACK option 3 is not a Router list");
    }

    if let Some(DhcpOption::InterfaceMtu(mtu)) = ack.opts().get(OptionCode::InterfaceMtu) {
        assert_eq!(*mtu, 1420u16, "ACK MTU must match config");
    } else {
        panic!("ACK option 26 is not an InterfaceMtu");
    }
}

#[test]
fn test_inform_response_excludes_lease_options() {
    let mut master = MockVhostUserMaster::spawn();

    let leased = run_dora(&mut master);

    let inform = build_dhcp_inform(VM_MAC, leased, 0xDEADBEEF);
    let reply = dhcp_round_trip(&mut master, &inform);

    assert_eq!(reply.opts().msg_type(), Some(MessageType::Ack));
    assert_eq!(
        reply.yiaddr(),
        Ipv4Addr::UNSPECIFIED,
        "INFORM ACK yiaddr MUST be 0 per RFC 2131 §4.3.5"
    );

    for forbidden in [
        OptionCode::AddressLeaseTime,
        OptionCode::ServerIdentifier,
        OptionCode::Renewal,
        OptionCode::Rebinding,
    ] {
        assert!(
            reply.opts().get(forbidden).is_none(),
            "INFORM ACK MUST NOT include option {forbidden:?} (RFC 2131 §4.3.5)"
        );
    }

    for required in [
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::InterfaceMtu,
    ] {
        assert!(
            reply.opts().get(required).is_some(),
            "INFORM ACK should still include option {required:?}"
        );
    }
}

#[test]
fn test_init_reboot_ack_match_and_nak_mismatch() {
    let mut master = MockVhostUserMaster::spawn();

    let leased = run_dora(&mut master);

    let req_match = build_dhcp_request_init_reboot(VM_MAC, leased, 0xAAAA1111);
    let ack = dhcp_round_trip(&mut master, &req_match);
    assert_eq!(
        ack.opts().msg_type(),
        Some(MessageType::Ack),
        "INIT-REBOOT for matching IP must ACK"
    );
    assert_eq!(ack.yiaddr(), leased, "ACK yiaddr must echo lease IP");

    let mismatched_ip = Ipv4Addr::new(192, 168, 99, 1);
    let req_mismatch = build_dhcp_request_init_reboot(VM_MAC, mismatched_ip, 0xAAAA2222);
    let nak = dhcp_round_trip(&mut master, &req_mismatch);
    assert_eq!(
        nak.opts().msg_type(),
        Some(MessageType::Nak),
        "INIT-REBOOT for non-matching IP must NAK"
    );
    assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED, "NAK yiaddr MUST be 0");
}

#[test]
fn test_lease_persistence_across_restart() {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let expires_at = now_secs + 3600;
    let seed_json = format!(
        r#"{{"version":1,"leases":[{{"mac":[82,84,0,18,52,1],"ip":"10.42.0.2","state":{{"Bound":{{"expires_at":{expires_at}}}}},"hostname":null}}]}}"#
    );
    let mut master = MockVhostUserMaster::spawn_with_seeded_lease(&seed_json);

    assert!(
        master.lease_path().exists(),
        "seed lease file must exist on disk before daemon spawn"
    );

    let request = build_dhcp_request_init_reboot(VM_MAC, VM_IP, 0xCAFE_F00D);
    let start = Instant::now();
    master.write_tx_frame(&request);
    let reply_frame = master
        .read_rx_frame()
        .expect("daemon never replied to post-restart INIT-REBOOT");
    let elapsed = start.elapsed();
    let reply = parse_dhcp_reply(&reply_frame);

    assert_eq!(
        reply.opts().msg_type(),
        Some(MessageType::Ack),
        "post-restart INIT-REBOOT must ACK (lease was loaded from disk)"
    );
    assert_eq!(
        reply.yiaddr(),
        VM_IP,
        "post-restart ACK must yield the originally-leased IP"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "post-restart ACK round-trip took {elapsed:?}, must be <500ms"
    );
}

#[test]
fn test_decline_then_offer_blocked_during_probation() {
    let mut master = MockVhostUserMaster::spawn();

    let leased = run_dora(&mut master);

    let decline = build_dhcp_decline(VM_MAC, leased, SERVER_ID, 0xDEC1_1111);
    master.write_tx_frame(&decline);
    assert!(
        master.read_rx_frame().is_none(),
        "DECLINE must not generate any reply"
    );

    let discover = build_dhcp_discover(VM_MAC);
    master.write_tx_frame(&discover);
    assert!(
        master.read_rx_frame().is_none(),
        "DISCOVER on fully-probationed pool must produce no reply (PoolExhausted is dropped)"
    );
}

#[test]
fn test_release_then_reacquire() {
    let mut master = MockVhostUserMaster::spawn();

    let first_ip = run_dora(&mut master);

    let release = build_dhcp_release(VM_MAC, first_ip, SERVER_ID, 0xBEEF_0001);
    master.write_tx_frame(&release);
    assert!(
        master.read_rx_frame().is_none(),
        "RELEASE must not generate any reply"
    );

    let second_ip = run_dora(&mut master);
    assert_eq!(
        second_ip, first_ip,
        "second DORA from same MAC must yield the same IP after RELEASE"
    );
}

#[test]
fn test_chaddr_mismatch_drops() {
    let mut master = MockVhostUserMaster::spawn();

    run_dora(&mut master);

    let wrong_chaddr = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x42];
    let req = build_dhcp_request_chaddr_mismatch(VM_MAC, wrong_chaddr, VM_IP, 0xBAD0_CAFE);
    master.write_tx_frame(&req);
    assert!(
        master.read_rx_frame().is_none(),
        "REQUEST with chaddr != vm.mac must be silently dropped"
    );
}
