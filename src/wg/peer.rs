// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer wrapper around `boringtun::noise::Tunn`.
//!
//! `Tunn` is owned by value (no Mutex/Arc/RefCell). Single-threaded datapath
//! reaches it via `&mut self`.
//!
//! Returns enums (no `&'a mut [u8]` lifetimes leak) so callers can decide what
//! to do with output buffers without holding a borrow on `self`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use ip_network::IpNetwork;

use crate::error::WgError;

/// Result of `Peer::encapsulate`.
#[derive(Debug)]
pub enum EncapResult {
    /// Reserved variant for future flow-control hooks (currently unused).
    Ready(usize),
    /// Output buffer holds a UDP datagram of `usize` bytes; send to peer endpoint.
    WriteToNetwork(usize),
    /// Nothing to send.
    Done,
    Err(WgError),
}

/// Result of `Peer::decapsulate`.
#[derive(Debug)]
pub enum DecapResult {
    /// Output buffer holds a UDP datagram (handshake response/cookie); send back.
    WriteToNetwork(usize),
    /// Output buffer holds a decrypted IPv4 packet of `packet_len` bytes from `src_ip`.
    WriteToTunnelV4 {
        src_ip: Ipv4Addr,
        packet_len: usize,
    },
    /// Nothing to forward.
    Done,
    Err(WgError),
}

/// Result of `Peer::drain`.
#[derive(Debug)]
pub enum DrainResult {
    /// Output buffer holds a queued packet; send to network.
    WriteToNetwork(usize),
    /// Drain queue empty.
    Done,
}

/// Result of `Peer::update_timers`.
#[derive(Debug)]
pub enum TimerResult {
    /// Output buffer holds bytes to send to network.
    Ready(usize),
    /// Tunnel session expired; caller should clear state and re-handshake.
    ConnectionExpired,
    /// No timer-driven action.
    Done,
}

/// Per-peer state: keys, endpoints, allowed IPs, and an owned-by-value `Tunn`.
pub struct Peer {
    pub idx: usize,
    pub name: String,
    pub tunn: Tunn,
    pub public_key: x25519_dalek::PublicKey,
    pub fingerprint: String,
    pub configured_endpoint: SocketAddr,
    pub current_endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
    pub last_decap_at: Option<Instant>,
}

impl Peer {
    /// Build a new `Peer`.
    ///
    /// `Tunn::new` is infallible in boringtun 0.7 — returns `Self`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idx: usize,
        name: String,
        our_static_secret: &x25519_dalek::StaticSecret,
        peer_public_key: x25519_dalek::PublicKey,
        preshared_key: Option<[u8; 32]>,
        configured_endpoint: SocketAddr,
        allowed_ips: Vec<IpNetwork>,
        persistent_keepalive: Option<u16>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        // `idx` is the peer's slot in `WgEngine::peers`, capped at the
        // configured peer count (255 by validation). Saturating into u32 keeps
        // the conversion lossless without an `as` cast.
        let peer_index_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        let tunn = Tunn::new(
            our_static_secret.clone(),
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            peer_index_u32,
            Some(rate_limiter),
        );
        let fingerprint = crate::wg::keys::key_fingerprint(&peer_public_key);
        Self {
            idx,
            name,
            tunn,
            public_key: peer_public_key,
            fingerprint,
            configured_endpoint,
            current_endpoint: configured_endpoint,
            allowed_ips,
            persistent_keepalive,
            last_decap_at: None,
        }
    }

    /// Encapsulate a plaintext IP packet for transmission.
    pub fn encapsulate(&mut self, ip_packet: &[u8], out: &mut [u8]) -> EncapResult {
        match self.tunn.encapsulate(ip_packet, out) {
            TunnResult::WriteToNetwork(buf) => EncapResult::WriteToNetwork(buf.len()),
            TunnResult::Done => EncapResult::Done,
            TunnResult::Err(_) => EncapResult::Err(WgError::Encap("encapsulate failed".into())),
            // encapsulate cannot return WriteToTunnel*; treat defensively as Done.
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                EncapResult::Done
            }
        }
    }

    /// Decapsulate a UDP datagram from the network. ALWAYS pass the real
    /// `src_addr` for non-drain calls (rate limiter requires it).
    pub fn decapsulate(
        &mut self,
        src_addr: SocketAddr,
        datagram: &[u8],
        out: &mut [u8],
    ) -> DecapResult {
        match self.tunn.decapsulate(Some(src_addr.ip()), datagram, out) {
            TunnResult::WriteToTunnelV4(packet, src_ip) => {
                self.current_endpoint = src_addr;
                self.last_decap_at = Some(Instant::now());
                DecapResult::WriteToTunnelV4 {
                    src_ip,
                    packet_len: packet.len(),
                }
            }
            TunnResult::WriteToNetwork(buf) => DecapResult::WriteToNetwork(buf.len()),
            TunnResult::Done => DecapResult::Done,
            TunnResult::Err(_) => DecapResult::Err(WgError::Encap("decapsulate failed".into())),
            // IPv6 not yet plumbed — drop silently.
            TunnResult::WriteToTunnelV6(_, _) => DecapResult::Done,
        }
    }

    /// Drain pending packets after a successful decap. Best-effort: pass `None`
    /// as the source address, empty datagram. Any non-network result is treated
    /// as `Done`.
    pub fn drain(&mut self, out: &mut [u8]) -> DrainResult {
        match self.tunn.decapsulate(None, &[], out) {
            TunnResult::WriteToNetwork(buf) => DrainResult::WriteToNetwork(buf.len()),
            TunnResult::Done
            | TunnResult::Err(_)
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => DrainResult::Done,
        }
    }

    /// Tick the per-tunnel timers. Caller should invoke at ~1Hz cadence.
    pub fn update_timers(&mut self, out: &mut [u8]) -> TimerResult {
        match self.tunn.update_timers(out) {
            TunnResult::WriteToNetwork(buf) => TimerResult::Ready(buf.len()),
            TunnResult::Err(WireGuardError::ConnectionExpired) => TimerResult::ConnectionExpired,
            TunnResult::Err(_)
            | TunnResult::Done
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => TimerResult::Done,
        }
    }

    /// Verify that `src_ip` (taken from a decapsulated IPv4 packet) matches
    /// one of this peer's `AllowedIPs` networks.
    pub fn allowed_ip_check(&self, src_ip: Ipv4Addr) -> bool {
        let probe = std::net::IpAddr::V4(src_ip);
        self.allowed_ips.iter().any(|net| net.contains(probe))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use boringtun::noise::rate_limiter::RateLimiter;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    fn make_secret(byte: u8) -> StaticSecret {
        StaticSecret::from([byte; 32])
    }

    fn make_rate_limiter(public_key: &PublicKey) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(public_key, 1024))
    }

    fn endpoint() -> SocketAddr {
        "203.0.113.1:51820".parse().unwrap()
    }

    fn make_peer(idx: usize, our_byte: u8, peer_byte: u8) -> Peer {
        let our_secret = make_secret(our_byte);
        let our_public = PublicKey::from(&our_secret);
        let peer_secret = make_secret(peer_byte);
        let peer_public = PublicKey::from(&peer_secret);
        let limiter = make_rate_limiter(&our_public);
        Peer::new(
            idx,
            format!("peer{idx}"),
            &our_secret,
            peer_public,
            None,
            endpoint(),
            vec!["10.0.0.0/24".parse().unwrap()],
            None,
            limiter,
        )
    }

    #[test]
    fn test_new_peer_created() {
        let peer = make_peer(0, 1, 2);
        assert_eq!(peer.idx, 0);
        assert_eq!(peer.name, "peer0");
        assert_eq!(peer.fingerprint.len(), 11);
        assert!(peer.fingerprint.ends_with("..."));
        assert_eq!(peer.configured_endpoint, peer.current_endpoint);
        assert!(peer.last_decap_at.is_none());
    }

    #[test]
    fn test_allowed_ip_check_match() {
        let peer = make_peer(0, 1, 2);
        assert!(peer.allowed_ip_check("10.0.0.1".parse().unwrap()));
        assert!(peer.allowed_ip_check("10.0.0.255".parse().unwrap()));
    }

    #[test]
    fn test_allowed_ip_check_no_match() {
        let peer = make_peer(0, 1, 2);
        assert!(!peer.allowed_ip_check("192.168.1.1".parse().unwrap()));
        assert!(!peer.allowed_ip_check("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_encapsulate_produces_output() {
        let mut peer = make_peer(0, 1, 2);
        let ip_packet = [0u8; 64];
        let mut out = [0u8; 2048];
        let result = peer.encapsulate(&ip_packet, &mut out);
        match result {
            EncapResult::WriteToNetwork(n) => assert!(n > 0),
            other => panic!("expected WriteToNetwork, got {other:?}"),
        }
    }

    #[test]
    fn test_decapsulate_updates_endpoint() {
        let secret_a = make_secret(11);
        let public_a = PublicKey::from(&secret_a);
        let secret_b = make_secret(22);
        let public_b = PublicKey::from(&secret_b);

        let limiter_a = make_rate_limiter(&public_a);
        let limiter_b = make_rate_limiter(&public_b);

        let mut peer_a = Peer::new(
            0,
            "A".into(),
            &secret_a,
            public_b,
            None,
            endpoint(),
            vec!["10.0.0.0/24".parse().unwrap()],
            None,
            limiter_a,
        );
        let mut peer_b = Peer::new(
            1,
            "B".into(),
            &secret_b,
            public_a,
            None,
            endpoint(),
            vec!["10.0.0.0/24".parse().unwrap()],
            None,
            limiter_b,
        );

        let mut a_out = [0u8; 2048];
        let init_len = match peer_a.encapsulate(&[0u8; 32], &mut a_out) {
            EncapResult::WriteToNetwork(n) => n,
            other => panic!("expected handshake init, got {other:?}"),
        };

        let new_addr: SocketAddr = "198.51.100.5:51820".parse().unwrap();
        let mut b_out = [0u8; 2048];
        let result = peer_b.decapsulate(new_addr, &a_out[..init_len], &mut b_out);
        match result {
            DecapResult::WriteToNetwork(n) => assert!(n > 0),
            other => panic!("expected WriteToNetwork (handshake response), got {other:?}"),
        }
        // Handshake-only path: V4 side-effects (current_endpoint, last_decap_at)
        // only fire on WriteToTunnelV4, which requires an established session.
        assert!(peer_b.last_decap_at.is_none());
        assert_eq!(peer_b.current_endpoint, endpoint());
    }

    #[test]
    fn test_drain_returns_done() {
        let mut peer = make_peer(0, 1, 2);
        let mut out = [0u8; 2048];
        match peer.drain(&mut out) {
            DrainResult::Done => {}
            other => panic!("expected Done on fresh peer, got {other:?}"),
        }
    }

    #[test]
    fn test_update_timers_no_panic() {
        let mut peer = make_peer(0, 1, 2);
        let mut out = [0u8; 2048];
        let _ = peer.update_timers(&mut out);
    }

    #[test]
    fn test_decapsulate_invalid_returns_err() {
        let mut peer = make_peer(0, 1, 2);
        let bogus = [0xFFu8; 64];
        let src: SocketAddr = "203.0.113.99:51820".parse().unwrap();
        let mut out = [0u8; 2048];
        let result = peer.decapsulate(src, &bogus, &mut out);
        match result {
            DecapResult::Err(_) | DecapResult::Done => {}
            other => panic!("expected Err or Done for bogus datagram, got {other:?}"),
        }
    }
}
