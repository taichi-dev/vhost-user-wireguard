// SPDX-License-Identifier: MIT OR Apache-2.0

//! WireGuard engine: owns the UDP socket, the 1Hz timer fd, and the per-peer
//! state. Single-threaded by construction — no `Mutex`, no `Arc<Tunn>`,
//! `&mut self` on every datapath entry point.
//!
//! Wireup:
//! - `new()`: bind dual-stack UDP socket, arm CLOCK_MONOTONIC timerfd at 1Hz,
//!   build per-peer state from config.
//! - `handle_socket_readable()`: drain one UDP datagram, dispatch to peer,
//!   return decapsulated IPv4 packet if any.
//! - `handle_timer_tick()`: tick every peer's `update_timers`, sending
//!   keepalives or re-handshakes as needed.
//! - `handle_tx_ip_packet()`: encapsulate an outbound IPv4 packet and send it.

pub mod keys;
pub mod peer;
pub mod routing;
pub mod uring;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use vmm_sys_util::timerfd::TimerFd;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Wireguard;
use crate::error::WgError;
use crate::wg::peer::{DecapResult, DrainResult, EncapResult, Peer, TimerResult};
use crate::wg::routing::AllowedIpsRouter;
use crate::wg::uring::WgUring;

/// Default scratch buffer for outbound encrypted bytes from boringtun.
const OUT_BUF_LEN: usize = 2048;

/// Default rate-limit on inbound handshake messages from a single src IP.
const RATE_LIMIT_PER_SEC: u64 = 10;

/// A decapsulated IPv4 packet handed up to the datapath.
pub struct RxIpPacket {
    pub peer_idx: usize,
    pub src_ip: Ipv4Addr,
    pub packet: Vec<u8>,
}

/// WireGuard engine: UDP socket + timer + peer dispatch.
pub struct WgEngine {
    pub socket: UdpSocket,
    pub uring: WgUring,
    pub peers: Vec<Peer>,
    pub route: AllowedIpsRouter,
    /// Maps boringtun-assigned local index → peer slot.
    /// Populated lazily from observed handshake completions.
    pub recv_idx_to_peer: HashMap<u32, usize>,
    pub rate_limiter: Arc<RateLimiter>,
    pub our_public: PublicKey,
    pub timer_fd: TimerFd,
}

impl WgEngine {
    /// Build the engine from validated config + the daemon's static secret.
    pub fn new(cfg: &Wireguard, our_static_secret: &StaticSecret) -> Result<Self, WgError> {
        let our_public = PublicKey::from(our_static_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&our_public, RATE_LIMIT_PER_SEC));

        // Linux requires IPV6_V6ONLY to be set BEFORE bind(2). Build the
        // socket manually so we can clear it for dual-stack v4-mapped
        // accept of remote endpoints, then convert to std::net::UdpSocket.
        let bind_err = |source: std::io::Error| WgError::SocketBind {
            port: cfg.listen_port,
            source,
        };
        let owned_fd = rustix::net::socket(
            rustix::net::AddressFamily::INET6,
            rustix::net::SocketType::DGRAM,
            None,
        )
        .map_err(|e| bind_err(e.into()))?;
        rustix::net::sockopt::set_ipv6_v6only(&owned_fd, false).map_err(|e| bind_err(e.into()))?;
        let bind_addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            cfg.listen_port,
            0,
            0,
        ));
        rustix::net::bind(&owned_fd, &bind_addr).map_err(|e| bind_err(e.into()))?;
        let socket = UdpSocket::from(owned_fd);
        // Socket stays in BLOCKING mode: io_uring is the sole I/O path now and
        // installs its own internal poll watch only when the socket can block.
        // Marking it non-blocking would make every RecvMsg complete with
        // -EAGAIN immediately and lose the poll-watch path, so packets that
        // arrive later would never generate CQEs.

        let mut timer_fd = TimerFd::new().map_err(timerfd_err)?;
        timer_fd
            .reset(Duration::from_secs(1), Some(Duration::from_secs(1)))
            .map_err(timerfd_err)?;

        let mut peers: Vec<Peer> = Vec::with_capacity(cfg.peers.len());
        let mut route = AllowedIpsRouter::new();
        for (idx, peer_cfg) in cfg.peers.iter().enumerate() {
            // Public keys share the 32-byte base64 wire format with preshared keys.
            let peer_public_bytes =
                crate::wg::keys::parse_preshared_key_base64(&peer_cfg.public_key)?;
            let peer_public = PublicKey::from(peer_public_bytes);

            let preshared = if let Some(path) = &peer_cfg.preshared_key_file {
                Some(crate::wg::keys::load_preshared_key(path)?)
            } else if let Some(s) = &peer_cfg.preshared_key {
                Some(crate::wg::keys::parse_preshared_key_base64(s)?)
            } else {
                None
            };

            let peer = Peer::new(
                idx,
                peer_cfg.name.clone(),
                our_static_secret,
                peer_public,
                preshared,
                peer_cfg.endpoint,
                peer_cfg.allowed_ips.clone(),
                peer_cfg.persistent_keepalive,
                Arc::clone(&rate_limiter),
            );

            for net in &peer_cfg.allowed_ips {
                route.insert(*net, idx);
            }
            peers.push(peer);
        }

        let uring = WgUring::new(socket.as_raw_fd())?;

        Ok(Self {
            socket,
            uring,
            peers,
            route,
            recv_idx_to_peer: HashMap::new(),
            rate_limiter,
            our_public,
            timer_fd,
        })
    }

    /// io_uring eventfd registered for epoll / event-loop dispatch.
    /// Replaces the old `socket_fd()` registration: the framework's epoll
    /// now wakes up on ring completions, not on socket readability.
    pub fn ring_eventfd(&self) -> RawFd {
        self.uring.eventfd()
    }

    pub fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    pub fn timer_fd_raw(&self) -> RawFd {
        self.timer_fd.as_raw_fd()
    }

    /// Flush any io_uring SQEs queued by `handle_tx_ip_packet` /
    /// `handle_timer_tick` / `drain_peer`. Called once per TX-vring drain
    /// batch so the kernel sees all encrypted outbound packets in a single
    /// `io_uring_enter` syscall instead of one syscall per packet.
    pub fn submit_uring(&mut self) -> Result<(), WgError> {
        self.uring.submit()
    }

    /// Drain a single completed recv from the io_uring CQ, dispatching it
    /// through boringtun. Returns `Ok(None)` if no recv CQE was ready or if
    /// the datagram resolved to a non-tunnel outcome (handshake, cookie,
    /// allowed-ip violation).
    pub fn handle_socket_readable(&mut self) -> Result<Option<RxIpPacket>, WgError> {
        let mut out: Option<RxIpPacket> = None;
        self.handle_socket_burst(1, |pkt| {
            out = Some(pkt);
        })?;
        Ok(out)
    }

    /// Drain up to `max_packets` completed UDP recvs from the io_uring CQ.
    /// Each datagram that yields a tunnel-bound IPv4 packet is passed to
    /// `sink`; non-tunnel datagrams (handshakes, cookies, replies boringtun
    /// consumed internally) still count toward the budget.
    ///
    /// Returns the number of datagrams consumed. Send completions accrued
    /// during the same wake-up are reaped opportunistically (their slots are
    /// returned to the pool) but do not count toward `max_packets`.
    pub fn handle_socket_burst<F>(
        &mut self,
        max_packets: usize,
        mut sink: F,
    ) -> Result<usize, WgError>
    where
        F: FnMut(RxIpPacket),
    {
        if max_packets == 0 {
            return Ok(0);
        }
        self.uring.drain_eventfd();
        let mut datagrams: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(max_packets);
        let consumed = self.uring.handle_completions(max_packets, |src, buf| {
            datagrams.push((src, buf.to_vec()));
        })?;
        for (src_addr, datagram) in datagrams {
            if let Some(pkt) = self.process_datagram(src_addr, &datagram)? {
                sink(pkt);
            }
        }
        self.uring.submit()?;
        Ok(consumed)
    }

    /// Decapsulate one UDP datagram (already drained from the ring) through
    /// boringtun and either emit a tunnel-bound IP packet or absorb the
    /// datagram (handshake, cookie, drop). Side effects:
    ///   * Outbound responses go straight back through the io_uring SQ.
    ///   * Allowed-IP-violating tunnel packets are logged + dropped.
    fn process_datagram(
        &mut self,
        src_addr: SocketAddr,
        datagram: &[u8],
    ) -> Result<Option<RxIpPacket>, WgError> {
        let peer_idx = match self.identify_peer(datagram) {
            Some(idx) => idx,
            None => {
                let (msg_type, receiver_idx) = match Tunn::parse_incoming_packet(datagram) {
                    Ok(Packet::HandshakeInit(_)) => ("HandshakeInit", None),
                    Ok(Packet::HandshakeResponse(p)) => ("HandshakeResponse", Some(p.receiver_idx)),
                    Ok(Packet::PacketCookieReply(p)) => ("CookieReply", Some(p.receiver_idx)),
                    Ok(Packet::PacketData(p)) => ("PacketData", Some(p.receiver_idx)),
                    Err(_) => ("invalid", None),
                };
                tracing::trace!(
                    bytes = datagram.len(),
                    %src_addr,
                    msg_type,
                    receiver_idx = ?receiver_idx,
                    "wg_unknown_peer_for_datagram"
                );
                return Ok(None);
            }
        };

        let mut out = vec![0u8; OUT_BUF_LEN];
        let result = self.peers[peer_idx].decapsulate(src_addr, datagram, &mut out);
        match result {
            DecapResult::WriteToNetwork(len) => {
                let endpoint = self.peers[peer_idx].current_endpoint;
                self.uring.queue_send(&out[..len], endpoint)?;
                self.drain_peer(peer_idx, &mut out)?;
                Ok(None)
            }
            DecapResult::WriteToTunnelV4 { src_ip, packet_len } => {
                if !self.peers[peer_idx].allowed_ip_check(src_ip) {
                    tracing::warn!(
                        ?src_ip,
                        peer = %self.peers[peer_idx].name,
                        "wg_allowed_ip_violation"
                    );
                    return Ok(None);
                }
                let packet = out[..packet_len].to_vec();
                Ok(Some(RxIpPacket {
                    peer_idx,
                    src_ip,
                    packet,
                }))
            }
            DecapResult::Done => Ok(None),
            DecapResult::Err(e) => {
                tracing::trace!(error = %e, "wg_decapsulate_error");
                Ok(None)
            }
        }
    }

    /// boringtun encodes `peer_idx` in the upper 24 bits of the local index
    /// (`local_idx = peer_idx << 8 | session_bits`), so when an exact lookup
    /// in `recv_idx_to_peer` misses we can cheaply derive the slot via `>> 8`.
    /// HandshakeInit carries no receiver index; we fall through to the
    /// single-peer fast path (multi-peer dispatch would parse the static
    /// pubkey field, deferred).
    fn identify_peer(&self, datagram: &[u8]) -> Option<usize> {
        let receiver_idx = match Tunn::parse_incoming_packet(datagram).ok()? {
            Packet::HandshakeInit(_) => {
                return (self.peers.len() == 1).then_some(0);
            }
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
        };
        if let Some(&idx) = self.recv_idx_to_peer.get(&receiver_idx) {
            return Some(idx);
        }
        // `receiver_idx >> 8` is at most 16_777_215, which fits in usize on all
        // supported targets (we only build for 32- and 64-bit pointer widths).
        let hint = usize::try_from(receiver_idx >> 8).ok()?;
        (hint < self.peers.len()).then_some(hint)
    }

    /// Tick all peer timers. Caller must invoke when the timer fd is readable.
    pub fn handle_timer_tick(&mut self) -> Result<(), WgError> {
        let _expirations = self.timer_fd.wait().map_err(timerfd_err)?;

        let mut out = [0u8; OUT_BUF_LEN];
        for idx in 0..self.peers.len() {
            let result = self.peers[idx].update_timers(&mut out);
            match result {
                TimerResult::Ready(len) => {
                    let endpoint = self.peers[idx].current_endpoint;
                    self.uring.queue_send(&out[..len], endpoint)?;
                }
                TimerResult::ConnectionExpired => {
                    tracing::info!(
                        peer = %self.peers[idx].name,
                        "wg_connection_expired_initiating_rehandshake"
                    );
                    let send_len = match self.peers[idx]
                        .tunn
                        .format_handshake_initiation(&mut out, true)
                    {
                        TunnResult::WriteToNetwork(buf) => Some(buf.len()),
                        _ => None,
                    };
                    if let Some(len) = send_len {
                        let endpoint = self.peers[idx].current_endpoint;
                        self.uring.queue_send(&out[..len], endpoint)?;
                    }
                }
                TimerResult::Done => {}
            }
        }
        self.uring.submit()?;
        Ok(())
    }

    pub fn handle_tx_ip_packet(
        &mut self,
        dst_ip: Ipv4Addr,
        ip_packet: &[u8],
    ) -> Result<(), WgError> {
        let peer_idx = self
            .route
            .lookup_v4(dst_ip)
            .ok_or(WgError::PeerNotFound { index: 0 })?;

        let mut out = vec![0u8; OUT_BUF_LEN.max(ip_packet.len() + 64)];
        let result = self.peers[peer_idx].encapsulate(ip_packet, &mut out);
        match result {
            EncapResult::WriteToNetwork(len) | EncapResult::Ready(len) => {
                let endpoint = self.peers[peer_idx].current_endpoint;
                self.uring.queue_send(&out[..len], endpoint)?;
                self.drain_peer(peer_idx, &mut out)?;
                Ok(())
            }
            EncapResult::Done => Ok(()),
            EncapResult::Err(e) => Err(e),
        }
    }

    fn drain_peer(&mut self, peer_idx: usize, out: &mut [u8]) -> Result<(), WgError> {
        loop {
            match self.peers[peer_idx].drain(out) {
                DrainResult::WriteToNetwork(len) => {
                    let endpoint = self.peers[peer_idx].current_endpoint;
                    self.uring.queue_send(&out[..len], endpoint)?;
                }
                DrainResult::Done => return Ok(()),
            }
        }
    }
}

/// Adapt a `vmm_sys_util` errno-wrapper into a `WgError::TimerFd`.
fn timerfd_err(e: vmm_sys_util::errno::Error) -> WgError {
    WgError::TimerFd(std::io::Error::from_raw_os_error(e.errno()))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ip_network::IpNetwork;

    use super::*;
    use crate::config::{WgPeer, Wireguard};

    fn make_secret(byte: u8) -> StaticSecret {
        StaticSecret::from([byte; 32])
    }

    fn pubkey_b64(byte: u8) -> String {
        let secret = StaticSecret::from([byte; 32]);
        let public = PublicKey::from(&secret);
        STANDARD.encode(public.as_bytes())
    }

    fn endpoint() -> SocketAddr {
        "203.0.113.1:51820".parse().unwrap()
    }

    fn allowed_net(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    fn make_cfg(peers: Vec<WgPeer>) -> Wireguard {
        Wireguard {
            private_key_file: None,
            private_key: None,
            // listen_port=0 → ephemeral, OS-assigned. Avoids collisions on parallel runs.
            listen_port: 0,
            peers,
        }
    }

    fn one_peer_cfg() -> Wireguard {
        make_cfg(vec![WgPeer {
            name: "p1".into(),
            public_key: pubkey_b64(2),
            preshared_key: None,
            preshared_key_file: None,
            endpoint: endpoint(),
            allowed_ips: vec![allowed_net("10.0.0.0/24")],
            persistent_keepalive: None,
        }])
    }

    #[test]
    fn test_socket_binds_dual_stack() {
        let our_secret = make_secret(1);
        let cfg = one_peer_cfg();
        let engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let v6only = rustix::net::sockopt::get_ipv6_v6only(&engine.socket).expect("getsockopt");
        assert!(!v6only, "expected IPV6_V6ONLY=0 for dual-stack bind");
        // Sanity: the socket is reachable as a raw fd ≥ 0.
        assert!(engine.socket_fd() >= 0);
    }

    #[test]
    fn test_timer_fd_is_monotonic() {
        let our_secret = make_secret(3);
        let cfg = one_peer_cfg();
        let engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let fd = engine.timer_fd_raw();
        assert!(fd >= 0);
        let path = format!("/proc/self/fdinfo/{fd}");
        let contents = std::fs::read_to_string(&path).expect("fdinfo should be readable");
        // Linux fdinfo for timerfd: `clockid: <n>` where 1 == CLOCK_MONOTONIC.
        let mut clockid_line = None;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("clockid:") {
                clockid_line = Some(rest.trim().to_string());
                break;
            }
        }
        let clockid = clockid_line.expect("clockid: line should be present in fdinfo");
        assert_eq!(clockid, "1", "expected CLOCK_MONOTONIC (1), got {clockid}");
    }

    #[test]
    fn test_allowed_ips_router_populated() {
        let our_secret = make_secret(5);
        let cfg = make_cfg(vec![WgPeer {
            name: "p1".into(),
            public_key: pubkey_b64(6),
            preshared_key: None,
            preshared_key_file: None,
            endpoint: endpoint(),
            allowed_ips: vec![allowed_net("10.0.0.0/24")],
            persistent_keepalive: None,
        }]);
        let engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        assert_eq!(engine.route.lookup_v4("10.0.0.1".parse().unwrap()), Some(0));
        assert_eq!(
            engine.route.lookup_v4("10.0.0.255".parse().unwrap()),
            Some(0)
        );
        assert_eq!(engine.route.lookup_v4("192.168.1.1".parse().unwrap()), None);
    }

    #[test]
    fn test_handle_tx_no_route_returns_err() {
        let our_secret = make_secret(7);
        let cfg = make_cfg(vec![WgPeer {
            name: "p1".into(),
            public_key: pubkey_b64(8),
            preshared_key: None,
            preshared_key_file: None,
            endpoint: endpoint(),
            allowed_ips: vec![allowed_net("10.0.0.0/24")],
            persistent_keepalive: None,
        }]);
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let ip_packet = [0u8; 64];
        let result = engine.handle_tx_ip_packet("192.168.99.1".parse().unwrap(), &ip_packet);
        assert!(matches!(result, Err(WgError::PeerNotFound { .. })));
    }

    #[test]
    fn test_engine_with_zero_peers() {
        // Edge case: no peers configured. Engine should still build cleanly,
        // and any tx attempt should fail with PeerNotFound.
        let our_secret = make_secret(9);
        let cfg = make_cfg(vec![]);
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        assert!(engine.peers.is_empty());
        let result = engine.handle_tx_ip_packet("10.0.0.1".parse().unwrap(), &[0u8; 64]);
        assert!(matches!(result, Err(WgError::PeerNotFound { .. })));
    }

    #[test]
    fn test_handle_socket_readable_returns_none_on_idle_ring() {
        let our_secret = make_secret(11);
        let cfg = one_peer_cfg();
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let r = engine.handle_socket_readable().expect("idle ring");
        assert!(r.is_none(), "expected no datagram on fresh socket");
    }

    #[test]
    fn test_identify_peer_uses_data_receiver_index_not_counter() {
        let our_secret = make_secret(13);
        let cfg = one_peer_cfg();
        let engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let receiver_idx = 0u32;
        let counter = 256u64;
        let mut datagram = vec![0u8; 32];
        datagram[0..4].copy_from_slice(&4u32.to_le_bytes());
        datagram[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
        datagram[8..16].copy_from_slice(&counter.to_le_bytes());

        assert_eq!(engine.identify_peer(&datagram), Some(0));
    }

    #[test]
    fn test_identify_peer_uses_handshake_response_receiver_index() {
        let our_secret = make_secret(15);
        let cfg = one_peer_cfg();
        let engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let sender_idx = 256u32;
        let receiver_idx = 0u32;
        let mut datagram = vec![0u8; 92];
        datagram[0..4].copy_from_slice(&2u32.to_le_bytes());
        datagram[4..8].copy_from_slice(&sender_idx.to_le_bytes());
        datagram[8..12].copy_from_slice(&receiver_idx.to_le_bytes());

        assert_eq!(engine.identify_peer(&datagram), Some(0));
    }

    #[test]
    fn test_handle_socket_burst_returns_zero_on_idle_socket() {
        let our_secret = make_secret(17);
        let cfg = one_peer_cfg();
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        let mut count = 0usize;
        let drained = engine
            .handle_socket_burst(64, |_pkt| count += 1)
            .expect("burst should not error");
        assert_eq!(drained, 0, "idle socket drains zero datagrams");
        assert_eq!(count, 0, "sink should not be invoked");
    }

    #[test]
    fn test_handle_socket_burst_drains_real_handshake_initiations() {
        // Send max_packets + extras handshake datagrams from a peer socket
        // to the engine's WG socket. The burst should consume exactly
        // max_packets datagrams (none are tunnel-bound, so the sink is
        // never called, but the count includes Consumed datagrams).
        use std::net::SocketAddr;

        let our_secret = make_secret(19);
        let cfg = one_peer_cfg();
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");

        // The engine's socket binds to the OS-assigned port (listen_port=0).
        let local_addr: SocketAddr = {
            let fd = engine.socket_fd();
            // SAFETY: the fd is owned by `engine.socket` and remains valid
            // for the duration of this getsockname call.
            let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
            let any = rustix::net::getsockname(borrowed).expect("getsockname");
            match any {
                rustix::net::SocketAddrAny::V6(v6) => {
                    SocketAddr::V6(std::net::SocketAddrV6::new(*v6.ip(), v6.port(), 0, 0))
                }
                _ => panic!("expected v6 bind"),
            }
        };
        // For dual-stack v6 sockets bound to ::, target IPv4 loopback via the
        // v4-mapped form so the kernel routes the datagram to our socket.
        let dst: SocketAddr = format!("[::1]:{}", local_addr.port()).parse().unwrap();
        let sender = std::net::UdpSocket::bind("[::1]:0").expect("sender bind");

        // Push 5 handshake-init-shaped datagrams (msg_type=1, 148 bytes is
        // the real on-wire size, but our identify_peer only needs >= 4 bytes
        // for type and our handle_socket_readable will fall through with
        // None for unknown peers — they still count as Consumed).
        let mut datagram = vec![0u8; 148];
        datagram[0..4].copy_from_slice(&1u32.to_le_bytes());
        for _ in 0..5 {
            sender.send_to(&datagram, dst).expect("send");
        }

        // Give the kernel time to deliver the datagrams to the engine socket.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut tunnel_count = 0usize;
        let drained = engine
            .handle_socket_burst(3, |_pkt| tunnel_count += 1)
            .expect("burst");
        assert_eq!(
            drained, 3,
            "should drain exactly the budget (3 of 5 enqueued)"
        );
        assert_eq!(tunnel_count, 0, "no tunnel packets from junk handshakes");

        let drained2 = engine.handle_socket_burst(64, |_pkt| {}).expect("burst2");
        assert_eq!(drained2, 2, "remaining 2 datagrams drained on second call");
    }
}
