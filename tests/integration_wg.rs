// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end WireGuard handshake + datapath integration tests against the
//! real daemon binary.
//!
//! Each test owns a fresh [`MockVhostUserMaster`] PLUS a fresh in-process
//! "fake peer" — a `boringtun::noise::Tunn` driven on a vanilla `std::net::UdpSocket`
//! — that plays the role of the remote WireGuard endpoint. We deliberately
//! do NOT spawn a real `wg` peer: the goal is to exercise the daemon's
//! handshake / decap / encap / drain / roaming / rate-limit codepaths end
//! to end, and a handcrafted `Tunn` gives us bit-level control without
//! pulling in privileged kernel state.
//!
//! Coverage:
//!   * `test_handshake_complete` (AC-WG-1) — fake-peer-initiated handshake;
//!     verify daemon emits a HandshakeResponse within 3 s.
//!   * `test_icmp_echo_through_tunnel` (AC-WG-2) — full DORA → tunnel echo;
//!     fake peer replies; master sees decapsulated reply on RX vring.
//!   * `test_allowed_ips_violation_dropped` (AC-WG-3) — peer encapsulates
//!     an IPv4 packet sourced OUTSIDE its allowed_ips; daemon drops; RX
//!     stays empty within 500 ms.
//!   * `test_handshake_flood_rate_limited` (AC-WG-4) — 1000 init packets in
//!     rapid succession; ≤10 HandshakeResponses come back, the rest are
//!     CookieReplies (msg type 3).
//!   * `test_endpoint_roaming` (AC-WG-5) — same WG identity, two src ports;
//!     daemon updates `current_endpoint` to the new port and routes the
//!     next outbound packet there.
//!   * `test_decap_drain_loop` (AC-WG-8) — five queued VM packets must all
//!     be emitted by the daemon's drain loop after the handshake completes.
//!   * `test_clock_jump_does_not_break_handshakes` (AC-WG-9, Linux) —
//!     daemon survives several timer ticks without panicking and stays
//!     responsive to ARP.
//!   * `test_v6_decap_dropped` (EC-W-11) — daemon drops a peer-supplied
//!     IPv6 packet (`WriteToTunnelV6` arm); RX stays empty.
//!
//! ### Port allocation
//!
//! Within one test binary `cargo test` runs tests in parallel; cross-test
//! binary execution is serial (cargo runs one test executable at a time).
//! [`alloc_listen_port`] in `tests/common/mod.rs` therefore guarantees
//! per-binary uniqueness, which is what we need. Both the daemon's
//! `listen_port` and the fake peer's UDP port come from the same allocator.

mod common;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use boringtun::noise::Tunn;
use boringtun::noise::TunnResult;
use boringtun::noise::rate_limiter::RateLimiter;
use dhcproto::v4::{
    DhcpOption, DhcpOptions, Flags, HType, Message, MessageType, Opcode, OptionCode,
};
use dhcproto::{Decodable as _, Decoder, Encodable as _, Encoder};
use rand::RngCore as _;
use x25519_dalek::{PublicKey, StaticSecret};

use common::{
    GATEWAY_IP, GATEWAY_MAC, MockVhostUserMaster, VM_IP, VM_MAC, alloc_listen_port,
    build_arp_request, build_dhcp_discover,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

const WG_MSG_TYPE_HANDSHAKE_INIT: u32 = 1;
const WG_MSG_TYPE_HANDSHAKE_RESP: u32 = 2;
const WG_MSG_TYPE_COOKIE_REPLY: u32 = 3;
const WG_HANDSHAKE_INIT_SZ: usize = 148;
const WG_HANDSHAKE_RESP_SZ: usize = 92;

const PEER_ALLOWED_IPS: &str = "10.0.0.0/24";

// === Key generation =========================================================

fn b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

fn random_secret() -> StaticSecret {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    StaticSecret::from(bytes)
}

/// Two fresh X25519 keypairs (daemon side + fake-peer side) generated per
/// test so no test ever leaks key material to another. The daemon's static
/// secret is base64-encoded into the inline `private_key = "…"` field of
/// the TOML config; the peer public key goes into `[[wireguard.peers]]`.
struct WgKeys {
    daemon_priv: StaticSecret,
    daemon_pub: PublicKey,
    peer_priv: StaticSecret,
    peer_pub: PublicKey,
}

impl WgKeys {
    fn new() -> Self {
        let daemon_priv = random_secret();
        let peer_priv = random_secret();
        Self {
            daemon_pub: PublicKey::from(&daemon_priv),
            peer_pub: PublicKey::from(&peer_priv),
            daemon_priv,
            peer_priv,
        }
    }
}

// === Daemon spawn helper ====================================================

/// Build a TOML config with REAL keys baked in, allocate a listen port, and
/// spawn the daemon. Returns the master harness plus the daemon's listen
/// port and the fake peer port (both already substituted into the config).
///
/// We deliberately bypass [`MockVhostUserMaster::spawn_with_config_template`]
/// because that helper hardcodes `fake_wg_key(0x11)` / `fake_wg_key(0x22)`
/// — we need the cryptographically-valid keys we just generated. The
/// harness still owns the work tempdir, lease path, and stderr capture; we
/// just construct the TOML ourselves and feed it via `write_temp_config`
/// directly.
struct DaemonSetup {
    master: MockVhostUserMaster,
    peer_port: u16,
    keys: WgKeys,
    daemon_addr: SocketAddr,
}

fn spawn_daemon_with_peer(persistent_keepalive: Option<u16>) -> DaemonSetup {
    let keys = WgKeys::new();
    let daemon_port = alloc_listen_port();
    let peer_port = alloc_listen_port();
    let template = build_wg_config_template(
        &keys,
        daemon_port,
        peer_port,
        PEER_ALLOWED_IPS,
        persistent_keepalive,
    );
    let master = MockVhostUserMaster::spawn_with_config_template(&template);
    DaemonSetup {
        master,
        peer_port,
        keys,
        daemon_addr: format!("127.0.0.1:{daemon_port}").parse().expect("daemon addr"),
    }
}

/// Build a TOML config template with REAL X25519 keys hardcoded in. The
/// only placeholder left for the harness to substitute is `{vu_socket}`
/// (filled by `MockVhostUserMaster` from its work-tempdir socket path).
/// `{wg_priv}`, `{wg_peer_pub}`, and `{wg_port}` would be substituted by
/// the harness with `fake_wg_key`-derived defaults — by NOT including
/// those placeholders in the rendered template, we keep our real keys.
fn build_wg_config_template(
    keys: &WgKeys,
    daemon_listen_port: u16,
    fake_peer_port: u16,
    allowed_ips: &str,
    persistent_keepalive: Option<u16>,
) -> String {
    let priv_b64 = b64(keys.daemon_priv.as_bytes());
    let pub_b64 = b64(keys.peer_pub.as_bytes());
    let pk_line = persistent_keepalive
        .map(|n| format!("persistent_keepalive = {n}\n"))
        .unwrap_or_default();
    format!(
        r#"
[wireguard]
private_key = "{priv_b64}"
listen_port = {daemon_listen_port}

[[wireguard.peers]]
name = "test-peer"
public_key = "{pub_b64}"
endpoint = "127.0.0.1:{fake_peer_port}"
allowed_ips = ["{allowed_ips}"]
{pk_line}
[vhost_user]
socket = "{{vu_socket}}"
queue_size = 256
num_queues = 2

[network]
subnet = "10.42.0.0/30"
gateway = "10.42.0.1"
dns = ["8.8.8.8"]

[vm]
mtu = 1420
mac = "52:54:00:12:34:01"
ip = "10.42.0.2"

[dhcp]
decline_probation_secs = 60
checkpoint_secs = 300
reservations = []

[dhcp.pool]
start = "10.42.0.2"
end = "10.42.0.2"
"#
    )
}

// === Fake peer ==============================================================

/// Build a fresh `Tunn` for the fake peer side. Mirrors the daemon's own
/// per-peer construction in [`crate::wg::WgEngine::new`] but with our
/// generated keypair instead of config-derived keys.
fn make_fake_peer_tunn(keys: &WgKeys) -> Tunn {
    let limiter = Arc::new(RateLimiter::new(&keys.peer_pub, 1024));
    Tunn::new(
        keys.peer_priv.clone(),
        keys.daemon_pub,
        None,
        None,
        1,
        Some(limiter),
    )
}

/// Bind a UDP socket on the given port (loopback only) with a 200 ms
/// receive timeout so tests can poll without blocking forever.
fn bind_peer_socket(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind(format!("127.0.0.1:{port}"))
        .unwrap_or_else(|e| panic!("bind fake peer port {port}: {e}"));
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set peer recv timeout");
    socket
}

/// Receive from the fake peer socket up to `deadline`. Returns the next
/// datagram and its source address, or `None` on timeout.
fn recv_until(
    socket: &UdpSocket,
    deadline: Instant,
) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 1600];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                buf.truncate(n);
                return Some((buf, src));
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("peer recv error: {e}"),
        }
    }
    None
}

/// Extract the WireGuard message type (LE u32 in the first 4 bytes).
fn wg_msg_type(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        datagram[0],
        datagram[1],
        datagram[2],
        datagram[3],
    ]))
}

// === IPv4 / ICMP / UDP frame builders =======================================

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut iter = header.chunks_exact(2);
    for chunk in iter.by_ref() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = iter.remainder() {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let lo = u16::try_from(sum & 0xFFFF).expect("low 16 bits fit");
    !lo
}

fn icmp_checksum(payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut iter = payload.chunks_exact(2);
    for chunk in iter.by_ref() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = iter.remainder() {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let lo = u16::try_from(sum & 0xFFFF).expect("low 16 bits fit");
    !lo
}

/// Build an ICMPv4 Echo Request *IP packet* (no Ethernet header). Suitable
/// as boringtun's `encapsulate` plaintext (peer→daemon path) AND, prefixed
/// with an Ethernet header, as the VM TX frame (daemon→peer path).
fn build_icmp_echo_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    icmp_type: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let mut icmp = Vec::with_capacity(icmp_len);
    icmp.push(icmp_type);
    icmp.push(0); // code
    icmp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = icmp_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let total_len = u16::try_from(20 + icmp_len).expect("ip length fits");
    let mut ip = Vec::with_capacity(usize::from(total_len));
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.push(64);
    ip.push(IPPROTO_ICMP);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let csum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Wrap `ip_payload` in an Ethernet header addressed from the VM to the
/// gateway MAC. Used to build frames that the master puts on TX.
fn wrap_eth_v4(ip_payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + ip_payload.len());
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&VM_MAC);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(ip_payload);
    frame
}

/// Build a minimal IPv6 packet with a TCP header (next header = 6) so the
/// peer-side `Tunn::decapsulate` recognises it as a v6 datagram and the
/// daemon's `WriteToTunnelV6` arm fires.
fn build_ipv6_packet(payload_len: u16) -> Vec<u8> {
    let mut ipv6 = Vec::with_capacity(40 + usize::from(payload_len));
    // version=6, traffic class=0, flow label=0
    ipv6.push(0x60);
    ipv6.push(0x00);
    ipv6.extend_from_slice(&[0x00, 0x00]);
    // payload length
    ipv6.extend_from_slice(&payload_len.to_be_bytes());
    // next header = 59 (No Next Header), hop limit = 64
    ipv6.push(59);
    ipv6.push(64);
    // src = ::1
    let mut src = [0u8; 16];
    src[15] = 1;
    ipv6.extend_from_slice(&src);
    // dst = ::2
    let mut dst = [0u8; 16];
    dst[15] = 2;
    ipv6.extend_from_slice(&dst);
    ipv6.resize(40 + usize::from(payload_len), 0);
    ipv6
}

// === DHCP DORA helper (subset of integration_dhcp.rs) ======================

const SERVER_ID: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);

#[allow(clippy::too_many_arguments)]
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

/// Walk Eth → IP → UDP → DHCP and return the parsed reply, panicking on
/// any malformed layer.
fn parse_dhcp_reply(eth_frame: &[u8]) -> Message {
    assert!(eth_frame.len() >= 14, "frame too short");
    assert_eq!(
        u16::from_be_bytes([eth_frame[12], eth_frame[13]]),
        ETHERTYPE_IPV4,
        "reply ethertype must be IPv4",
    );
    let ip_payload = &eth_frame[14..];
    let ihl = usize::from(ip_payload[0] & 0x0f) * 4;
    assert_eq!(ip_payload[9], IPPROTO_UDP, "reply must be UDP");
    let dhcp_offset = ihl + 8;
    Message::decode(&mut Decoder::new(&ip_payload[dhcp_offset..]))
        .expect("decode dhcp reply")
}

/// Drive a full DORA against the master so the daemon's anti-spoof check
/// admits subsequent VM-sourced traffic with `src_ip == VM_IP`.
fn run_dora(master: &mut MockVhostUserMaster) {
    let discover = build_dhcp_discover(VM_MAC);
    master.write_tx_frame(&discover);
    let offer_frame = master.read_rx_frame().expect("daemon never produced OFFER");
    let offer = parse_dhcp_reply(&offer_frame);
    assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
    let yiaddr = offer.yiaddr();

    let request = build_dhcp_request_selecting(VM_MAC, SERVER_ID, yiaddr, offer.xid());
    master.write_tx_frame(&request);
    let ack_frame = master.read_rx_frame().expect("daemon never produced ACK");
    let ack = parse_dhcp_reply(&ack_frame);
    assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
    assert_eq!(ack.yiaddr(), VM_IP);
}

// === Tests ==================================================================

/// AC-WG-1: Fake peer initiates a handshake; daemon decapsulates the
/// initiation, generates a HandshakeResponse, and sends it back to the
/// configured endpoint within 3 s.
#[test]
fn test_handshake_complete() {
    let setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    // Format the handshake initiation and send it to the daemon.
    let mut init_buf = vec![0u8; 256];
    let init_len = match tunn.format_handshake_initiation(&mut init_buf, false) {
        TunnResult::WriteToNetwork(buf) => buf.len(),
        other => panic!("expected handshake init, got {other:?}"),
    };
    assert_eq!(init_len, WG_HANDSHAKE_INIT_SZ, "init must be exactly 148 bytes");
    socket
        .send_to(&init_buf[..init_len], setup.daemon_addr)
        .expect("send init to daemon");

    // Wait up to 3 s for the daemon's response.
    let deadline = Instant::now() + Duration::from_secs(3);
    let (reply, _src) = recv_until(&socket, deadline).expect(
        "daemon never produced a handshake response within 3 s of receiving the init",
    );
    assert_eq!(
        wg_msg_type(&reply),
        Some(WG_MSG_TYPE_HANDSHAKE_RESP),
        "daemon's reply must be a HandshakeResponse (msg type 2)"
    );
    assert_eq!(
        reply.len(),
        WG_HANDSHAKE_RESP_SZ,
        "HandshakeResponse must be exactly 92 bytes"
    );

    // Confirm the response decapsulates cleanly so that we know it was
    // generated by a peer holding the matching static key — i.e. the
    // daemon really did process our init, not just bounce random bytes.
    let mut decap_buf = vec![0u8; 2048];
    let result =
        tunn.decapsulate(Some(setup.daemon_addr.ip()), &reply, &mut decap_buf);
    // After receive_handshake_response boringtun emits a keepalive via
    // WriteToNetwork. Either WriteToNetwork or Done means handshake OK.
    match result {
        TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
        other => panic!("response decap failed: {other:?}"),
    }
}

/// AC-WG-2: Full ICMP echo through the tunnel. VM does DORA, then sends an
/// ICMP echo to a destination inside the peer's allowed_ips. The fake peer
/// decapsulates, builds an Echo Reply, encapsulates it back to the daemon,
/// and we observe the decapsulated reply on the master's RX vring.
#[test]
fn test_icmp_echo_through_tunnel() {
    let mut setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    run_dora(&mut setup.master);

    // Bootstrap session: peer initiates handshake.
    let mut buf = vec![0u8; 2048];
    let init_len = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("init failed: {other:?}"),
    };
    socket
        .send_to(&buf[..init_len], setup.daemon_addr)
        .expect("send init");
    let (reply, _) = recv_until(&socket, Instant::now() + Duration::from_secs(3))
        .expect("no handshake response from daemon");
    let _ = tunn.decapsulate(Some(setup.daemon_addr.ip()), &reply, &mut buf);

    // VM TX: ICMP Echo Request → 10.0.0.5.
    let dst = Ipv4Addr::new(10, 0, 0, 5);
    let echo_req = build_icmp_echo_v4(VM_IP, dst, ICMP_ECHO_REQUEST, 0xCAFE, 1, b"hi");
    setup.master.write_tx_frame(&wrap_eth_v4(&echo_req));

    // Receive the encrypted echo on the fake peer socket. After the data
    // packet may also come queued keepalives; we drain until we see the
    // first WriteToTunnelV4.
    let deadline = Instant::now() + Duration::from_secs(3);
    let plaintext = drain_until_ipv4(&socket, &mut tunn, deadline)
        .expect("daemon never forwarded the echo to the peer");
    assert!(plaintext.starts_with(&[0x45]), "expected IPv4 header");
    // Sanity-check it's the same packet (same dst).
    assert_eq!(&plaintext[16..20], &dst.octets(), "decap dst must match");

    // Build an Echo Reply, swapping src/dst.
    let echo_reply = build_icmp_echo_v4(dst, VM_IP, ICMP_ECHO_REPLY, 0xCAFE, 1, b"hi");
    let mut encap_buf = vec![0u8; 2048];
    let encap_len = match tunn.encapsulate(&echo_reply, &mut encap_buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("peer encap failed: {other:?}"),
    };
    socket
        .send_to(&encap_buf[..encap_len], setup.daemon_addr)
        .expect("send echo reply");

    // Master should now see the decapsulated reply on its RX vring.
    let rx = setup
        .master
        .read_rx_frame()
        .expect("daemon never delivered the echo reply to the VM");
    assert!(rx.len() >= 14 + 20 + 8, "rx frame too short: {} bytes", rx.len());
    assert_eq!(&rx[0..6], &VM_MAC, "Eth dst must be VM MAC");
    assert_eq!(&rx[6..12], &GATEWAY_MAC, "Eth src must be gateway MAC");
    assert_eq!(
        u16::from_be_bytes([rx[12], rx[13]]),
        ETHERTYPE_IPV4,
        "ethertype must be IPv4"
    );
    // ICMP type at byte (14 + 20) must be ECHO_REPLY (0).
    assert_eq!(rx[14 + 20], ICMP_ECHO_REPLY, "ICMP type must be Echo Reply");
}

/// Receive WG datagrams on `socket`, feed them to `tunn`, and return the
/// first plaintext IPv4 payload (i.e. `WriteToTunnelV4`). Loops on
/// keepalives, errors, or non-V4 results.
fn drain_until_ipv4(
    socket: &UdpSocket,
    tunn: &mut Tunn,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    while Instant::now() < deadline {
        let (datagram, src) = recv_until(socket, deadline)?;
        let mut out = vec![0u8; 2048];
        match tunn.decapsulate(Some(src.ip()), &datagram, &mut out) {
            TunnResult::WriteToTunnelV4(packet, _ip) => return Some(packet.to_vec()),
            TunnResult::WriteToNetwork(reply) => {
                // Echo back any handshake/keepalive boringtun produces.
                let bytes = reply.to_vec();
                socket.send_to(&bytes, src).ok();
            }
            _ => {}
        }
        // Drain queue.
        loop {
            let mut drain_out = vec![0u8; 2048];
            match tunn.decapsulate(None, &[], &mut drain_out) {
                TunnResult::WriteToTunnelV4(packet, _ip) => {
                    return Some(packet.to_vec());
                }
                TunnResult::WriteToNetwork(_) => {}
                _ => break,
            }
        }
        let _ = &mut buf; // keep the alloc alive, avoid clippy
    }
    None
}

/// AC-WG-3: A peer-encapsulated IPv4 packet whose `src_ip` is OUTSIDE the
/// peer's allowed_ips must be silently dropped at the daemon. The master
/// must observe nothing on RX within 500 ms.
#[test]
fn test_allowed_ips_violation_dropped() {
    let mut setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    // Bootstrap session.
    let mut buf = vec![0u8; 2048];
    let init_len = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("init: {other:?}"),
    };
    socket.send_to(&buf[..init_len], setup.daemon_addr).unwrap();
    let (reply, _) = recv_until(&socket, Instant::now() + Duration::from_secs(3))
        .expect("no response");
    let _ = tunn.decapsulate(Some(setup.daemon_addr.ip()), &reply, &mut buf);

    // Build an IPv4 packet whose src is OUTSIDE 10.0.0.0/24 — say
    // 192.168.99.5 — and encapsulate it through the fake peer.
    let bad_src = Ipv4Addr::new(192, 168, 99, 5);
    let pkt = build_icmp_echo_v4(bad_src, VM_IP, ICMP_ECHO_REPLY, 0xBAD, 1, b"x");
    let mut encap_buf = vec![0u8; 2048];
    let encap_len = match tunn.encapsulate(&pkt, &mut encap_buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("encap: {other:?}"),
    };
    socket
        .send_to(&encap_buf[..encap_len], setup.daemon_addr)
        .expect("send violating packet");

    // Read RX with 500 ms deadline. Master's read_rx_frame() has a 1 s
    // deadline so we just check it ultimately returns None.
    let start = Instant::now();
    let result = setup.master.read_rx_frame();
    let elapsed = start.elapsed();
    assert!(
        result.is_none(),
        "daemon must drop allowed-IPs violation, got {} bytes",
        result.map(|f| f.len()).unwrap_or(0),
    );
    assert!(
        elapsed >= Duration::from_millis(400),
        "drop must be silent: harness returned in {elapsed:?} (expected ~1 s timeout)"
    );
}

/// AC-WG-4: Flood the daemon with 1000 handshake initiations from a single
/// src IP. The daemon's RateLimiter (limit=10/s) admits up to 10 valid
/// HandshakeResponses; the rest are CookieReplies (msg type 3).
#[test]
fn test_handshake_flood_rate_limited() {
    let setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    // Use a separate Tunn for flooding so its handshake state can be
    // re-rolled with `force_resend=true` 1000 times without exhausting
    // its internal index counter.
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    let flood_start = Instant::now();
    let mut sent = 0;
    let mut buf = vec![0u8; 256];
    while sent < 1000 && flood_start.elapsed() < Duration::from_millis(900) {
        match tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(b) => {
                let _ = socket.send_to(b, setup.daemon_addr);
                sent += 1;
            }
            other => panic!("init #{sent}: {other:?}"),
        }
    }
    assert!(sent >= 100, "must send at least 100 inits, only sent {sent}");

    // Drain replies for up to 1.5 s past the last send. Count by msg type.
    let drain_deadline = Instant::now() + Duration::from_millis(1500);
    let mut handshake_responses = 0u32;
    let mut cookie_replies = 0u32;
    let mut other_msgs = 0u32;
    while let Some((datagram, _src)) = recv_until(&socket, drain_deadline) {
        match wg_msg_type(&datagram) {
            Some(WG_MSG_TYPE_HANDSHAKE_RESP) => handshake_responses += 1,
            Some(WG_MSG_TYPE_COOKIE_REPLY) => cookie_replies += 1,
            _ => other_msgs += 1,
        }
    }

    assert!(
        handshake_responses <= 10,
        "rate limiter must cap handshake responses at 10, got {handshake_responses}"
    );
    assert!(
        cookie_replies > 0,
        "rate-limited inits must produce at least one cookie reply (limit hit)"
    );
    assert_eq!(
        other_msgs, 0,
        "every reply must be either HandshakeResponse or CookieReply"
    );
}

/// AC-WG-5: A fake peer establishes a session from src port A, then sends
/// the next data packet from src port B (same WG identity, fresh socket).
/// The daemon's stored `current_endpoint` must update to B; we verify by
/// inducing daemon→peer traffic and observing that B (not A) receives it.
#[test]
fn test_endpoint_roaming() {
    let mut setup = spawn_daemon_with_peer(None);
    let socket_a = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    run_dora(&mut setup.master);

    // Bootstrap session via socket A.
    let mut buf = vec![0u8; 2048];
    let init_len = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("init: {other:?}"),
    };
    socket_a
        .send_to(&buf[..init_len], setup.daemon_addr)
        .unwrap();
    let (reply, _) = recv_until(&socket_a, Instant::now() + Duration::from_secs(3))
        .expect("no response on A");
    let _ = tunn.decapsulate(Some(setup.daemon_addr.ip()), &reply, &mut buf);

    // Step 1: fake peer (port A) sends a data packet so the daemon's
    // current_endpoint locks onto A.
    let data = build_icmp_echo_v4(
        Ipv4Addr::new(10, 0, 0, 7),
        VM_IP,
        ICMP_ECHO_REPLY,
        0xAAAA,
        1,
        b"a",
    );
    let mut encap_buf = vec![0u8; 2048];
    let n = match tunn.encapsulate(&data, &mut encap_buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("encap A: {other:?}"),
    };
    socket_a
        .send_to(&encap_buf[..n], setup.daemon_addr)
        .unwrap();
    let _ = setup.master.read_rx_frame(); // sink the decapsulated packet

    // Step 2: switch to socket B (a fresh ephemeral port). Same Tunn —
    // same session keys — but new src endpoint.
    let port_b = alloc_listen_port();
    let socket_b = bind_peer_socket(port_b);

    // Step 3: send a data packet from B. Daemon must update current_endpoint to B.
    let data2 = build_icmp_echo_v4(
        Ipv4Addr::new(10, 0, 0, 7),
        VM_IP,
        ICMP_ECHO_REPLY,
        0xBBBB,
        2,
        b"b",
    );
    let n2 = match tunn.encapsulate(&data2, &mut encap_buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("encap B: {other:?}"),
    };
    socket_b
        .send_to(&encap_buf[..n2], setup.daemon_addr)
        .unwrap();
    let _ = setup.master.read_rx_frame(); // sink the decapsulated packet

    // Step 4: induce daemon→peer traffic by having the VM TX a packet.
    let echo = build_icmp_echo_v4(
        VM_IP,
        Ipv4Addr::new(10, 0, 0, 9),
        ICMP_ECHO_REQUEST,
        0xCCCC,
        3,
        b"verify",
    );
    setup.master.write_tx_frame(&wrap_eth_v4(&echo));

    // Step 5: socket B must receive the encrypted echo; socket A must not.
    let deadline = Instant::now() + Duration::from_secs(2);
    let got_b = recv_until(&socket_b, deadline);
    assert!(
        got_b.is_some(),
        "after roaming, daemon must send next outbound to port B"
    );
    let got_a = recv_until(&socket_a, Instant::now() + Duration::from_millis(200));
    assert!(
        got_a.is_none(),
        "after roaming, port A must not receive new traffic"
    );
}

/// AC-WG-8: Multiple VM packets queued before the handshake completes are
/// all emitted by the daemon's drain loop after the response arrives —
/// not just the first one.
#[test]
fn test_decap_drain_loop() {
    let mut setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    run_dora(&mut setup.master);

    // VM TX five ICMP echoes BEFORE any handshake. Each call to
    // boringtun's `encapsulate` with no session queues the plaintext and
    // emits a handshake init (only the first call's init goes to the
    // wire; subsequent calls return Done because a handshake is in
    // progress).
    let dst = Ipv4Addr::new(10, 0, 0, 11);
    const N_PKTS: u16 = 5;
    for seq in 0..N_PKTS {
        let echo = build_icmp_echo_v4(VM_IP, dst, ICMP_ECHO_REQUEST, 0xDA1A, seq, b"q");
        setup.master.write_tx_frame(&wrap_eth_v4(&echo));
    }

    // Read the daemon's first init.
    let (init, _src) = recv_until(&socket, Instant::now() + Duration::from_secs(3))
        .expect("daemon never emitted handshake init for queued packets");
    assert_eq!(
        wg_msg_type(&init),
        Some(WG_MSG_TYPE_HANDSHAKE_INIT),
        "daemon's first emission must be a HandshakeInit"
    );

    // Decapsulate the init and reply.
    let mut buf = vec![0u8; 2048];
    let resp_len = match tunn.decapsulate(Some(setup.daemon_addr.ip()), &init, &mut buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("init decap: {other:?}"),
    };
    socket
        .send_to(&buf[..resp_len], setup.daemon_addr)
        .expect("send response");

    // Drain encrypted frames from the daemon. Count the ones that
    // decapsulate to a non-empty IPv4 payload — those are the queued
    // VM packets that the daemon's drain loop emitted. The keepalive
    // boringtun emits after handshake completion has zero plaintext and
    // returns Done from `validate_decapsulated_packet`.
    let mut got_ipv4 = 0u16;
    let deadline = Instant::now() + Duration::from_secs(3);
    while got_ipv4 < N_PKTS {
        let Some((datagram, src)) = recv_until(&socket, deadline) else {
            break;
        };
        let mut decap_buf = vec![0u8; 2048];
        if let TunnResult::WriteToTunnelV4(_, _) =
            tunn.decapsulate(Some(src.ip()), &datagram, &mut decap_buf)
        {
            got_ipv4 += 1;
        }
        // Drain peer's own queue (boringtun may batch).
        loop {
            let mut drain_buf = vec![0u8; 2048];
            match tunn.decapsulate(None, &[], &mut drain_buf) {
                TunnResult::WriteToTunnelV4(_, _) => got_ipv4 += 1,
                TunnResult::Done => break,
                _ => continue,
            }
        }
    }

    assert_eq!(
        got_ipv4, N_PKTS,
        "daemon's drain loop must emit ALL {N_PKTS} queued packets, got {got_ipv4}"
    );
}

/// AC-WG-9 (Linux only): The daemon's WG `update_timers` runs on a
/// CLOCK_MONOTONIC `timerfd` that is by construction immune to wall-clock
/// jumps. We can't test a real clock change without root, but we CAN
/// confirm that the daemon survives several timer ticks (each of which
/// invokes `update_timers` per peer) without panicking, and stays
/// responsive to in-band traffic afterward.
#[test]
#[cfg(target_os = "linux")]
fn test_clock_jump_does_not_break_handshakes() {
    let mut setup = spawn_daemon_with_peer(Some(1));

    // Wait through ≥3 timer ticks. With a 1 Hz timerfd that's ~3 s.
    std::thread::sleep(Duration::from_millis(3200));

    // The daemon must still respond to ARP. If `update_timers` had panicked
    // the daemon would have terminated and this round-trip would time out.
    let req = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    setup.master.write_tx_frame(&req);
    let reply = setup
        .master
        .read_rx_frame()
        .expect("daemon stopped responding after timer ticks");
    assert_eq!(&reply[0..6], &VM_MAC, "ARP reply must echo VM MAC");
}

/// EC-W-11: The daemon's per-peer decapsulator drops `WriteToTunnelV6`
/// results — IPv6 forwarding is not yet wired through the rest of the
/// datapath. Encapsulate an IPv6 packet through the fake peer and verify
/// nothing arrives on the master's RX vring.
#[test]
fn test_v6_decap_dropped() {
    let mut setup = spawn_daemon_with_peer(None);
    let socket = bind_peer_socket(setup.peer_port);
    let mut tunn = make_fake_peer_tunn(&setup.keys);

    // Bootstrap session (so encapsulate produces a data packet, not an init).
    let mut buf = vec![0u8; 2048];
    let init_len = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("init: {other:?}"),
    };
    socket.send_to(&buf[..init_len], setup.daemon_addr).unwrap();
    let (reply, _) = recv_until(&socket, Instant::now() + Duration::from_secs(3))
        .expect("no response");
    let _ = tunn.decapsulate(Some(setup.daemon_addr.ip()), &reply, &mut buf);

    // Encapsulate a 48-byte IPv6 packet (header + 8-byte zero payload).
    let v6 = build_ipv6_packet(8);
    let mut encap_buf = vec![0u8; 2048];
    let n = match tunn.encapsulate(&v6, &mut encap_buf) {
        TunnResult::WriteToNetwork(b) => b.len(),
        other => panic!("encap v6: {other:?}"),
    };
    socket
        .send_to(&encap_buf[..n], setup.daemon_addr)
        .expect("send v6 packet");

    // Master's RX queue must NOT receive anything.
    let result = setup.master.read_rx_frame();
    assert!(
        result.is_none(),
        "daemon must drop V6 tunnel packets, got {} bytes",
        result.map(|f| f.len()).unwrap_or(0),
    );
}


