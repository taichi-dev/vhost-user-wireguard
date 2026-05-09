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

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::TunnResult;
use boringtun::noise::rate_limiter::RateLimiter;
use vmm_sys_util::timerfd::TimerFd;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Wireguard;
use crate::error::WgError;
use crate::wg::peer::{DecapResult, DrainResult, EncapResult, Peer, TimerResult};
use crate::wg::routing::AllowedIpsRouter;

/// Maximum size of a WireGuard UDP datagram on the wire (MTU + WG overhead).
const MAX_DATAGRAM: usize = 1500 + 32 + 16;

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
        socket.set_nonblocking(true).map_err(bind_err)?;

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

        Ok(Self {
            socket,
            peers,
            route,
            recv_idx_to_peer: HashMap::new(),
            rate_limiter,
            our_public,
            timer_fd,
        })
    }

    /// UDP socket fd for epoll / event-loop registration.
    pub fn socket_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Timer fd for epoll / event-loop registration.
    pub fn timer_fd_raw(&self) -> RawFd {
        self.timer_fd.as_raw_fd()
    }

    /// Drain one UDP datagram from the socket.
    /// Returns `Ok(None)` on `WouldBlock` or non-actionable result.
    pub fn handle_socket_readable(&mut self) -> Result<Option<RxIpPacket>, WgError> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, src_addr) = match self.socket.recv_from(&mut buf) {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(WgError::SocketSend(e)),
        };
        let datagram = &buf[..n];

        let peer_idx = match self.identify_peer(datagram) {
            Some(idx) => idx,
            None => {
                tracing::trace!(bytes = n, "wg_unknown_peer_for_datagram");
                return Ok(None);
            }
        };

        let mut out = vec![0u8; OUT_BUF_LEN];
        let result = self.peers[peer_idx].decapsulate(src_addr, datagram, &mut out);
        match result {
            DecapResult::WriteToNetwork(len) => {
                let endpoint = self.peers[peer_idx].current_endpoint;
                self.socket
                    .send_to(&out[..len], endpoint)
                    .map_err(WgError::SocketSend)?;
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

    /// Identify which peer a datagram is destined for.
    ///
    /// boringtun encodes `peer_idx` in the upper 24 bits of the local index it
    /// hands out (`local_idx = peer_idx << 8 | session_bits`), so messages
    /// that carry a receiver index can cheaply derive the peer slot from it.
    ///
    /// The receiver index is not at a single offset for all message types:
    /// handshake responses carry `sender_idx` first and `receiver_idx` at
    /// bytes 8..12, while data packets and cookie replies carry
    /// `receiver_idx` at bytes 4..8. Reading bytes 8..12 for data packets
    /// reads the packet counter; low-throughput traffic then appears to work
    /// until the counter reaches 256 and the shifted value no longer resolves
    /// to peer 0.
    fn identify_peer(&self, datagram: &[u8]) -> Option<usize> {
        if datagram.len() < 4 {
            return None;
        }
        let msg_type = u32::from_le_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);

        if msg_type == 1 {
            // HandshakeInit: no receiver_idx. Single-peer fast path.
            if self.peers.len() == 1 {
                return Some(0);
            }
            // Multi-peer: best-effort fall-through to None (the datagram is
            // effectively dropped). A future revision can extend this with a
            // parse_handshake_anon-driven match against each peer's public key.
            return None;
        }

        let receiver_idx = match msg_type {
            // HandshakeResponse: type || sender_idx || receiver_idx || ...
            2 if datagram.len() >= 12 => {
                u32::from_le_bytes([datagram[8], datagram[9], datagram[10], datagram[11]])
            }
            // CookieReply and PacketData: type || receiver_idx || ...
            3 | 4 if datagram.len() >= 8 => {
                u32::from_le_bytes([datagram[4], datagram[5], datagram[6], datagram[7]])
            }
            _ => return None,
        };
        if let Some(&idx) = self.recv_idx_to_peer.get(&receiver_idx) {
            return Some(idx);
        }
        // SAFETY: receiver_idx >> 8 is at most u32::MAX >> 8 = 16_777_215, fits in usize on all supported platforms
        let hint = (receiver_idx >> 8) as usize;
        if hint < self.peers.len() {
            return Some(hint);
        }
        None
    }

    /// Tick all peer timers. Caller must invoke when the timer fd is readable.
    pub fn handle_timer_tick(&mut self) -> Result<(), WgError> {
        // Drain the timerfd so it stays edge-triggerable.
        let _expirations = self.timer_fd.wait().map_err(timerfd_err)?;

        let mut out = [0u8; OUT_BUF_LEN];
        for idx in 0..self.peers.len() {
            let result = self.peers[idx].update_timers(&mut out);
            match result {
                TimerResult::Ready(len) => {
                    let endpoint = self.peers[idx].current_endpoint;
                    self.socket
                        .send_to(&out[..len], endpoint)
                        .map_err(WgError::SocketSend)?;
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
                        self.socket
                            .send_to(&out[..len], endpoint)
                            .map_err(WgError::SocketSend)?;
                    }
                }
                TimerResult::Done => {}
            }
        }
        Ok(())
    }

    /// Encapsulate and emit one outbound IPv4 packet to its routed peer.
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
                self.socket
                    .send_to(&out[..len], endpoint)
                    .map_err(WgError::SocketSend)?;
                self.drain_peer(peer_idx, &mut out)?;
                Ok(())
            }
            EncapResult::Done => Ok(()),
            EncapResult::Err(e) => Err(e),
        }
    }

    /// Drain any packets boringtun queued for the peer (handshake retransmits,
    /// session-deferred sends).
    fn drain_peer(&mut self, peer_idx: usize, out: &mut [u8]) -> Result<(), WgError> {
        loop {
            match self.peers[peer_idx].drain(out) {
                DrainResult::WriteToNetwork(len) => {
                    let endpoint = self.peers[peer_idx].current_endpoint;
                    self.socket
                        .send_to(&out[..len], endpoint)
                        .map_err(WgError::SocketSend)?;
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
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ip_network::IpNetwork;
    use std::net::SocketAddr;

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
    fn test_socket_is_nonblocking() {
        let our_secret = make_secret(11);
        let cfg = one_peer_cfg();
        let mut engine = WgEngine::new(&cfg, &our_secret).expect("engine should build");
        // No data ever sent → recv_from should immediately return WouldBlock,
        // surfacing as Ok(None).
        let r = engine.handle_socket_readable().expect("non-blocking recv");
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
}
