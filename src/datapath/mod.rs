// SPDX-License-Identifier: MIT OR Apache-2.0

//! vhost-user-net backend wiring.
//!
//! [`WgNetBackend`] is the [`VhostUserBackendMut`] implementation that owns the
//! [`WgEngine`], the [`DhcpServer`] and the bounded RX queue, and dispatches
//! events from five sources:
//!
//! | `device_event`        | source                           | action                          |
//! |-----------------------|----------------------------------|---------------------------------|
//! | `0`                   | guest RX vring kick              | drain pending `rx_queue` to vring|
//! | `1`                   | guest TX vring kick              | run [`TxProcessor`], then RX flush|
//! | `EXTRA_TOKEN_UDP` (3) | WG UDP socket readable           | decap → push into `rx_queue`    |
//! | `EXTRA_TOKEN_TIMER`(4)| WG 1 Hz timerfd                  | tick peer timers, checkpoint    |
//! | `EXTRA_TOKEN_EXIT` (5)| externally registered shutdown fd| break the serve loop with `Err` |
//!
//! On reconnect the `vhost-user-backend` framework rebuilds its internal
//! [`VringEpollHandler`] from scratch — every external fd we registered with
//! [`register_external_fds`] is therefore lost and must be re-registered. The
//! caller is responsible for invoking [`register_external_fds`] each time
//! `daemon.serve()` returns and the same backend is rebound to a fresh socket.
//!
//! `EVENT_IDX`-correct drain semantics live in [`vring`]; this module is only
//! the dispatch + state-glue layer.

pub mod intercept;
pub mod vnet;
pub mod vring;

use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use std::net::Ipv4Addr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost_user_backend::{VhostUserBackend, VhostUserBackendMut, VhostUserDaemon, VringEpollHandler, VringRwLock};
use virtio_bindings::bindings::virtio_net::{
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MTU, VIRTIO_NET_F_STATUS,
    VIRTIO_NET_S_LINK_UP,
};
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::event::{EventConsumer, EventNotifier};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::datapath::intercept::InterceptCfg;
use crate::datapath::vring::{Counters, RxProcessor, TxProcessor};
use crate::dhcp::DhcpServer;
use crate::error::{Error, VhostError};
use crate::wg::{RxIpPacket, WgEngine};
use crate::wire::eth::build_eth_frame;

/// VIRTIO_F_VERSION_1: feature bit 32, marks the device as 1.0-compliant.
const VIRTIO_F_VERSION_1_BIT: u32 = 32;

/// EtherType for IPv4. Used when wrapping decapsulated packets back into
/// Ethernet frames for delivery to the guest.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// Number of virtqueues we expose: one RX, one TX. We do NOT advertise MQ.
const NUM_QUEUES: u16 = 2;

/// Soft cap on the persistent backend RX queue. When exceeded,
/// [`RxProcessor::enqueue`] evicts the oldest frame (and bumps a counter).
const DEFAULT_RX_QUEUE_DEPTH: usize = 256;

/// `device_event` token identifying the RX virtqueue (queue 0).
const RX_QUEUE_EVENT: u16 = 0;
/// `device_event` token identifying the TX virtqueue (queue 1).
const TX_QUEUE_EVENT: u16 = 1;
/// First epoll token slot available to backend-registered fds. The framework
/// reserves `0..=num_queues()` (the queues plus its own exit notifier).
const EXTRA_TOKEN_UDP: u16 = NUM_QUEUES + 1;
/// Token assigned to the WireGuard 1 Hz timerfd.
const EXTRA_TOKEN_TIMER: u16 = NUM_QUEUES + 2;
/// Token assigned to the externally-driven shutdown fd. Distinct from the
/// framework's `exit_event` so that callers can request shutdown without
/// poking at the daemon's internals.
const EXTRA_TOKEN_EXIT: u16 = NUM_QUEUES + 3;

/// vhost-user backend implementing a vhost-user-net device whose datapath is
/// a userspace WireGuard tunnel.
///
/// The backend is `&mut self`-driven (see the note on [`VhostUserBackendMut`])
/// and is therefore wrapped in a `Mutex` by the daemon. All datapath state —
/// RX queue, peer state, DHCP lease store, counters — lives on this struct.
pub struct WgNetBackend {
    /// Guest memory handle. `None` until the frontend issues `SET_MEM_TABLE`;
    /// every event handler must early-return `Ok(())` if `mem` is still `None`.
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// Static, pre-validated trust-boundary config (VM MAC, gateway, MTU).
    intercept_cfg: InterceptCfg,
    /// DHCP server state machine. Single-threaded; mutated on every TX kick.
    dhcp: DhcpServer,
    /// WireGuard engine: UDP socket, peer table, 1 Hz timerfd.
    wg: WgEngine,
    /// Bounded RX queue of pre-built Ethernet frames waiting for guest
    /// descriptors. Drained inside [`Self::flush_rx`].
    rx_queue: VecDeque<Vec<u8>>,
    /// Atomic observability counters, shared with [`TxProcessor`]/[`RxProcessor`].
    counters: Arc<Counters>,
    /// Externally-driven shutdown fd. Notifying it breaks the serve loop.
    exit_eventfd: EventFd,
    /// Monotonic deadline for the next DHCP lease checkpoint.
    lease_checkpoint_due_at: Instant,
    /// Cadence of the DHCP lease checkpoint (e.g. 60 s from config).
    checkpoint_interval: Duration,
    /// VM static IP, used as the source-IP anti-spoof anchor in [`classify`].
    vm_ip: Ipv4Addr,
    /// Maximum descriptor chains per virtqueue, surfaced via [`Self::max_queue_size`].
    queue_size: u16,
    /// Tracks whether the frontend negotiated `VIRTIO_RING_F_EVENT_IDX`.
    event_idx: bool,
    /// Soft cap on [`Self::rx_queue`]; older frames are evicted on overflow.
    rx_max_queue: usize,
}

impl WgNetBackend {
    /// Construct a fresh backend. Ownership of [`DhcpServer`] and [`WgEngine`]
    /// is transferred in; the caller must not retain references to them.
    ///
    /// `vm_ip` is the static guest IP used as the source-IP anti-spoof anchor.
    /// `queue_size` controls the maximum descriptor chains per virtqueue.
    /// `checkpoint_interval` is the DHCP lease checkpoint cadence.
    pub fn new(
        intercept_cfg: InterceptCfg,
        dhcp: DhcpServer,
        wg: WgEngine,
        vm_ip: Ipv4Addr,
        queue_size: u16,
        checkpoint_interval: Duration,
    ) -> Result<Self, VhostError> {
        let exit_eventfd = EventFd::new(EFD_NONBLOCK).map_err(VhostError::EventFd)?;
        Ok(Self {
            mem: None,
            intercept_cfg,
            dhcp,
            wg,
            rx_queue: VecDeque::new(),
            counters: Arc::new(Counters::new()),
            exit_eventfd,
            lease_checkpoint_due_at: Instant::now() + checkpoint_interval,
            checkpoint_interval,
            vm_ip,
            queue_size,
            event_idx: false,
            rx_max_queue: DEFAULT_RX_QUEUE_DEPTH,
        })
    }

    /// Read-only access to the counters, intended for metrics endpoints.
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// Raw fd of the UDP socket — needed by [`register_external_fds`] callers
    /// that don't already hold a [`WgEngine`] reference.
    pub fn wg_socket_fd(&self) -> RawFd {
        self.wg.socket_fd()
    }

    /// Raw fd of the WireGuard 1 Hz timerfd.
    pub fn wg_timer_fd(&self) -> RawFd {
        self.wg.timer_fd_raw()
    }

    /// Raw fd of the externally-driven shutdown fd.
    pub fn exit_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        self.exit_eventfd.as_raw_fd()
    }

    /// Notify the externally-driven shutdown fd. The next epoll iteration
    /// will then surface `EXTRA_TOKEN_EXIT` and the serve loop will exit.
    pub fn signal_exit(&self) -> Result<(), VhostError> {
        self.exit_eventfd.write(1).map_err(VhostError::EventFd)
    }

    /// Borrow the configured guest memory if the frontend has set it; otherwise
    /// `None`. Callers must early-return on `None` rather than indexing into
    /// `vrings`, since the framework calls `update_memory` *after* the first
    /// few configuration messages.
    fn memory(&self) -> Option<&GuestMemoryAtomic<GuestMemoryMmap>> {
        self.mem.as_ref()
    }

    /// Flush as many queued RX frames into the RX vring as the guest has
    /// descriptors for. Quietly tolerates a missing memory handle.
    fn flush_rx(&mut self, rx_vring: &VringRwLock) -> Result<(), VhostError> {
        let Some(mem_atomic) = self.memory() else {
            return Ok(());
        };
        let mem_handle = mem_atomic.memory();
        let mem_ref: &GuestMemoryMmap = &mem_handle;

        let queue = std::mem::take(&mut self.rx_queue);
        let mut rx = RxProcessor {
            vring: rx_vring,
            mem: mem_ref,
            max_queue: self.rx_max_queue,
            queue,
            counters: &self.counters,
        };
        let result = rx.flush();
        self.rx_queue = rx.queue;
        result
    }

    /// Run the TX drain pipeline: classify each TX frame, enqueue any in-band
    /// RX replies, encapsulate any tunnel-bound packets through [`WgEngine`].
    /// After draining TX, also flush any RX frames that the in-band replies
    /// produced so the guest sees them in the same kick window.
    fn run_tx(
        &mut self,
        rx_vring: &VringRwLock,
        tx_vring: &VringRwLock,
    ) -> Result<(), VhostError> {
        let Some(mem_atomic) = self.memory() else {
            return Ok(());
        };
        let mem_handle = mem_atomic.memory();
        let mem_ref: &GuestMemoryMmap = &mem_handle;

        let queue = std::mem::take(&mut self.rx_queue);
        let mut rx = RxProcessor {
            vring: rx_vring,
            mem: mem_ref,
            max_queue: self.rx_max_queue,
            queue,
            counters: &self.counters,
        };

        // SAFETY: `wg.route` is owned by `wg`; we re-borrow it as `&` for the
        // duration of the TX scan. boringtun never mutates the trie.
        let router_ptr: *const _ = &self.wg.route;
        // We can't take `&self.wg.route` and `&mut self.wg` simultaneously
        // through normal borrow rules. The route table is immutable for the
        // lifetime of the engine (peers + allowed_ips are validated once at
        // boot and never reshuffled), so we pin it through a raw pointer.
        // SAFETY: the raw pointer is valid because `self` is alive for the
        // whole TX loop, and no method on `WgEngine` mutates `route`.
        let router = unsafe { &*router_ptr };

        let tx_result: Result<(), VhostError>;
        {
            let mut tx = TxProcessor {
                vring: tx_vring,
                mem: mem_ref,
                rx: &mut rx,
                intercept_cfg: &self.intercept_cfg,
                router,
                dhcp: &mut self.dhcp,
                wg: &mut self.wg,
                counters: &self.counters,
                lease: Some(self.vm_ip),
                gateway_ip: self.intercept_cfg.gateway_ip,
            };
            tx_result = tx.process();
        }
        self.rx_queue = rx.queue;
        tx_result?;

        self.flush_rx(rx_vring)?;
        Ok(())
    }

    /// Drain one decapsulated IPv4 packet from the WG socket (if any), wrap
    /// it in an Ethernet frame addressed back to the VM, and push it onto
    /// the bounded RX queue (oldest-evicted on overflow).
    fn handle_wg_socket_readable(
        &mut self,
        rx_vring: &VringRwLock,
    ) -> Result<(), VhostError> {
        match self.wg.handle_socket_readable() {
            Ok(Some(RxIpPacket {
                peer_idx: _,
                src_ip: _,
                packet,
            })) => {
                let frame = build_eth_frame(
                    self.intercept_cfg.vm_mac,
                    self.intercept_cfg.gateway_mac,
                    ETHERTYPE_IPV4,
                    &packet,
                );
                if self.rx_queue.len() >= self.rx_max_queue {
                    self.rx_queue.pop_front();
                }
                self.rx_queue.push_back(frame);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::trace!(error = %error, "wg_socket_readable_error");
            }
        }
        self.flush_rx(rx_vring)?;
        Ok(())
    }

    /// Tick the WG timer (handshake retransmits, keepalives, dead-peer
    /// recovery) and, if past the lease checkpoint deadline, persist the
    /// DHCP lease database. Both side effects are idempotent and bounded.
    fn handle_timer_tick(&mut self) -> Result<(), VhostError> {
        if let Err(error) = self.wg.handle_timer_tick() {
            tracing::warn!(error = %error, "wg_timer_tick_error");
        }
        let now = Instant::now();
        if now >= self.lease_checkpoint_due_at {
            if let Err(error) = self.dhcp.checkpoint() {
                tracing::warn!(error = %error, "dhcp_checkpoint_error");
            }
            self.lease_checkpoint_due_at = now + self.checkpoint_interval;
        }
        Ok(())
    }
}

impl VhostUserBackendMut for WgNetBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        usize::from(NUM_QUEUES)
    }

    fn max_queue_size(&self) -> usize {
        usize::from(self.queue_size)
    }

    fn features(&self) -> u64 {
        // We deliberately do NOT advertise any offload features
        // (CSUM, GUEST/HOST_TSO4/6, UFO, etc.), nor CTRL_VQ or MQ.
        // The trust-boundary pipeline assumes raw, single-fragment frames.
        (1u64 << VIRTIO_F_VERSION_1_BIT)
            | (1u64 << VIRTIO_NET_F_MAC)
            | (1u64 << VIRTIO_NET_F_MTU)
            | (1u64 << VIRTIO_NET_F_MRG_RXBUF)
            | (1u64 << VIRTIO_NET_F_STATUS)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        // CONFIG so the frontend reads our MAC/MTU/STATUS layout;
        // REPLY_ACK so message-level errors surface synchronously.
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> IoResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn reset_device(&mut self) {
        // Clear in-flight RX frames so a reconnecting guest doesn't see
        // stale traffic, but keep persistent state (peer keys, lease store)
        // intact so re-attach is seamless.
        self.rx_queue.clear();
        self.event_idx = false;
        self.mem = None;
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        // virtio_net_config layout (12 bytes consumed, fixed by the C struct):
        //   mac[6] + status[2] + max_virtqueue_pairs[2] + mtu[2]
        // We do NOT advertise VIRTIO_NET_F_MQ, but the spec leaves
        // max_virtqueue_pairs at its struct offset. Setting it to 1 is
        // harmless; the guest must not read it without the feature.
        let mut config = [0u8; 12];
        config[0..6].copy_from_slice(&self.intercept_cfg.vm_mac);
        let status = u16::try_from(VIRTIO_NET_S_LINK_UP).unwrap_or(1);
        config[6..8].copy_from_slice(&status.to_le_bytes());
        config[8..10].copy_from_slice(&1u16.to_le_bytes());
        config[10..12].copy_from_slice(&self.intercept_cfg.vm_mtu.to_le_bytes());

        let total = u32::try_from(config.len()).unwrap_or(0);
        if offset >= total {
            return Vec::new();
        }
        let end = offset.saturating_add(size).min(total);
        let start_usize = match usize::try_from(offset) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let end_usize = match usize::try_from(end) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        config[start_usize..end_usize].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        // Hand out a dup of the underlying eventfd, split into a
        // (consumer, notifier) pair so the framework can register the
        // consumer with epoll and keep the notifier for `send_exit_event`.
        let consumer_clone = self.exit_eventfd.try_clone().ok()?;
        let notifier_clone = self.exit_eventfd.try_clone().ok()?;
        // SAFETY: `into_raw_fd` consumes the EventFd and transfers fd
        // ownership to the EventConsumer / EventNotifier wrappers.
        let consumer = unsafe {
            <EventConsumer as std::os::unix::io::FromRawFd>::from_raw_fd(
                consumer_clone.into_raw_fd(),
            )
        };
        let notifier = unsafe {
            <EventNotifier as std::os::unix::io::FromRawFd>::from_raw_fd(
                notifier_clone.into_raw_fd(),
            )
        };
        Some((consumer, notifier))
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        _evset: EventSet,
        vrings: &[Self::Vring],
        _thread_id: usize,
    ) -> IoResult<()> {
        // Until update_memory has populated `self.mem`, we cannot safely
        // dereference any descriptor chain. Drop the kick on the floor.
        if self.memory().is_none() {
            return Ok(());
        }

        // The framework hands us a slice of length `num_queues()`, indexed
        // by virtqueue number. RX = 0, TX = 1.
        let rx_vring = match vrings.get(usize::from(RX_QUEUE_EVENT)) {
            Some(v) => v,
            None => return Ok(()),
        };
        let tx_vring_opt = vrings.get(usize::from(TX_QUEUE_EVENT));

        match device_event {
            RX_QUEUE_EVENT => self
                .flush_rx(rx_vring)
                .map_err(|e| io::Error::other(e.to_string())),
            TX_QUEUE_EVENT => {
                let tx_vring = match tx_vring_opt {
                    Some(v) => v,
                    None => return Ok(()),
                };
                self.run_tx(rx_vring, tx_vring)
                    .map_err(|e| io::Error::other(e.to_string()))
            }
            EXTRA_TOKEN_UDP => self
                .handle_wg_socket_readable(rx_vring)
                .map_err(|e| io::Error::other(e.to_string())),
            EXTRA_TOKEN_TIMER => {
                self.handle_timer_tick()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                // Timer ticks may have unblocked WG TX (handshake completion);
                // pump the RX queue in case anything backed up.
                self.flush_rx(rx_vring)
                    .map_err(|e| io::Error::other(e.to_string()))
            }
            EXTRA_TOKEN_EXIT => {
                // Returning Err propagates up through the framework's
                // VringEpollHandler::run loop and breaks `daemon.serve()`.
                Err(io::Error::other(
                    "shutdown requested via EXTRA_TOKEN_EXIT",
                ))
            }
            other => {
                tracing::warn!(token = other, "unknown_handle_event_token");
                Ok(())
            }
        }
    }
}

/// Register the WG UDP socket, the WG timerfd and the externally-driven
/// shutdown fd with the framework's [`VringEpollHandler`].
///
/// This MUST be re-invoked every time the daemon's serve loop terminates and
/// is restarted: on reconnect the framework rebuilds its epoll handler from
/// scratch and any previously-registered fds are dropped.
///
/// Token assignment is fixed at compile time
/// ([`EXTRA_TOKEN_UDP`], [`EXTRA_TOKEN_TIMER`], [`EXTRA_TOKEN_EXIT`]) and
/// must match the dispatch table inside [`WgNetBackend::handle_event`].
pub fn register_external_fds<T>(
    handler: &VringEpollHandler<T>,
    wg_socket_fd: RawFd,
    timer_fd: RawFd,
    exit_fd: RawFd,
) -> Result<(), VhostError>
where
    T: VhostUserBackend,
{
    handler
        .register_listener(wg_socket_fd, EventSet::IN, u64::from(EXTRA_TOKEN_UDP))
        .map_err(VhostError::EventFd)?;
    handler
        .register_listener(timer_fd, EventSet::IN, u64::from(EXTRA_TOKEN_TIMER))
        .map_err(VhostError::EventFd)?;
    handler
        .register_listener(exit_fd, EventSet::IN, u64::from(EXTRA_TOKEN_EXIT))
        .map_err(VhostError::EventFd)?;
    Ok(())
}

/// Run the daemon's serve loop until the frontend disconnects (or until
/// [`WgNetBackend::signal_exit`] is invoked).
///
/// Sequence:
///
/// 1. Create the [`Listener`].
/// 2. Call [`VhostUserDaemon::start`] — non-blocking; the framework spawns
///    a worker thread that builds the [`VringEpollHandler`] and begins
///    accepting connections.
/// 3. Call [`VhostUserDaemon::get_epoll_handlers`] and feed every external
///    fd ([`WgEngine::socket_fd`], [`WgEngine::timer_fd_raw`], the
///    backend's exit fd) to [`register_external_fds`] so the framework's
///    epoll loop dispatches `EXTRA_TOKEN_UDP` / `EXTRA_TOKEN_TIMER` /
///    `EXTRA_TOKEN_EXIT` events into [`WgNetBackend::handle_event`].
/// 4. Call [`VhostUserDaemon::wait`] which blocks until the worker exits.
///
/// We CANNOT use [`VhostUserDaemon::serve`] because it bundles `start +
/// wait` into one call, leaving no window in which to register the
/// external fds with the freshly-built epoll handler. Without registration
/// the WG datapath would never run — the daemon would only respond to
/// guest-driven kicks on the virtqueues, not to inbound UDP.
///
/// Disconnect-shaped errors are coerced to `Ok(())` to match the behaviour
/// of [`VhostUserDaemon::serve`] (the framework treats `Disconnected` and
/// `PartialMessage` as expected outcomes).
pub fn run_serve_loop(
    mut daemon: VhostUserDaemon<Arc<Mutex<WgNetBackend>>>,
    backend: Arc<Mutex<WgNetBackend>>,
    socket_path: &Path,
) -> Result<(), Error> {
    use vhost::vhost_user::Listener;

    let (wg_socket_fd, timer_fd, exit_fd) = {
        let b = backend.lock().map_err(|_| {
            Error::Vhost(VhostError::Backend("backend mutex poisoned".to_string()))
        })?;
        (b.wg_socket_fd(), b.wg_timer_fd(), b.exit_fd())
    };

    let mut listener = Listener::new(socket_path, true)
        .map_err(|e| Error::Vhost(VhostError::Backend(e.to_string())))?;
    daemon
        .start(&mut listener)
        .map_err(|e| Error::Vhost(VhostError::Backend(e.to_string())))?;

    for handler in daemon.get_epoll_handlers() {
        register_external_fds(&handler, wg_socket_fd, timer_fd, exit_fd)?;
    }

    match daemon.wait() {
        Ok(()) => Ok(()),
        Err(e) => {
            let s = e.to_string();
            if s.contains("Disconnected") || s.contains("PartialMessage") {
                Ok(())
            } else {
                Err(Error::Vhost(VhostError::Backend(s)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ip_network::Ipv4Network;
    use mac_address::MacAddress;
    use tempfile::TempDir;
    use x25519_dalek::StaticSecret;

    use crate::config::{Dhcp, DhcpPool, Network, Vm, Wireguard};

    const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);

    fn make_intercept_cfg() -> InterceptCfg {
        InterceptCfg {
            vm_mac: VM_MAC,
            vm_mtu: 1420,
            gateway_ip: GW_IP,
            gateway_mac: GW_MAC,
        }
    }

    fn make_dhcp(persist_dir: &TempDir) -> DhcpServer {
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

    fn make_wg() -> WgEngine {
        let secret = StaticSecret::from([1u8; 32]);
        let cfg = Wireguard {
            private_key_file: None,
            private_key: None,
            listen_port: 0,
            peers: vec![],
        };
        WgEngine::new(&cfg, &secret).unwrap()
    }

    fn make_backend(persist_dir: &TempDir) -> WgNetBackend {
        WgNetBackend::new(
            make_intercept_cfg(),
            make_dhcp(persist_dir),
            make_wg(),
            VM_IP,
            256,
            Duration::from_secs(60),
        )
        .expect("backend new")
    }

    #[test]
    fn test_features_no_offload_advertised() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        let features = backend.features();

        // Required core bits.
        assert!(
            features & (1u64 << VIRTIO_F_VERSION_1_BIT) != 0,
            "VIRTIO_F_VERSION_1 not advertised"
        );
        assert!(
            features & (1u64 << VIRTIO_NET_F_MAC) != 0,
            "VIRTIO_NET_F_MAC not advertised"
        );
        assert!(
            features & (1u64 << VIRTIO_NET_F_MTU) != 0,
            "VIRTIO_NET_F_MTU not advertised"
        );
        assert!(
            features & (1u64 << VIRTIO_NET_F_MRG_RXBUF) != 0,
            "VIRTIO_NET_F_MRG_RXBUF not advertised"
        );
        assert!(
            features & (1u64 << VIRTIO_NET_F_STATUS) != 0,
            "VIRTIO_NET_F_STATUS not advertised"
        );
        assert!(
            features & (1u64 << VIRTIO_RING_F_EVENT_IDX) != 0,
            "VIRTIO_RING_F_EVENT_IDX not advertised"
        );

        // Forbidden bits (offload features). Bit numbers are from the
        // virtio_net spec; we never want any of these advertised because
        // the trust-boundary pipeline rejects multi-fragment / GSO frames.
        const VIRTIO_NET_F_CSUM: u32 = 0;
        const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
        const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
        const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
        const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
        const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
        const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
        const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
        const VIRTIO_NET_F_HOST_ECN: u32 = 13;
        const VIRTIO_NET_F_HOST_UFO: u32 = 14;
        const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
        const VIRTIO_NET_F_MQ: u32 = 22;

        for bit in [
            VIRTIO_NET_F_CSUM,
            VIRTIO_NET_F_GUEST_CSUM,
            VIRTIO_NET_F_GUEST_TSO4,
            VIRTIO_NET_F_GUEST_TSO6,
            VIRTIO_NET_F_GUEST_ECN,
            VIRTIO_NET_F_GUEST_UFO,
            VIRTIO_NET_F_HOST_TSO4,
            VIRTIO_NET_F_HOST_TSO6,
            VIRTIO_NET_F_HOST_ECN,
            VIRTIO_NET_F_HOST_UFO,
            VIRTIO_NET_F_CTRL_VQ,
            VIRTIO_NET_F_MQ,
        ] {
            assert_eq!(
                features & (1u64 << bit),
                0,
                "feature bit {bit} should NOT be advertised"
            );
        }
    }

    #[test]
    fn test_update_memory_stores_handle() {
        let dir = TempDir::new().unwrap();
        let mut backend = make_backend(&dir);
        assert!(backend.mem.is_none(), "fresh backend has no memory");

        let gmm = GuestMemoryMmap::<()>::from_ranges(&[(
            vm_memory::GuestAddress(0),
            0x10000,
        )])
        .unwrap();
        let atomic = GuestMemoryAtomic::new(gmm);
        backend.update_memory(atomic).expect("update_memory");

        assert!(backend.mem.is_some(), "memory should be stored");
    }

    #[test]
    fn test_exit_event_returns_clones() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        let pair = backend.exit_event(0);
        assert!(pair.is_some(), "exit_event must hand back a pair");
        let (consumer, notifier) = pair.unwrap();
        // notifying through the cloned notifier must surface on the
        // cloned consumer (kernel-side same eventfd counter).
        notifier.notify().expect("notify");
        consumer.consume().expect("consume");
    }

    #[test]
    fn test_get_config_starts_with_mac() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        let cfg = backend.get_config(0, 12);
        assert_eq!(cfg.len(), 12, "full read of virtio_net_config is 12 bytes");
        assert_eq!(&cfg[0..6], &VM_MAC, "first 6 bytes are MAC");
        // status is little-endian, low byte = 1 (LINK_UP).
        assert_eq!(u16::from_le_bytes([cfg[6], cfg[7]]), 1);
        // MTU at offset 10..12, little-endian.
        assert_eq!(u16::from_le_bytes([cfg[10], cfg[11]]), 1420);
    }

    #[test]
    fn test_num_queues_is_two_no_mq() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        assert_eq!(backend.num_queues(), 2, "RX + TX, no MQ");
    }

    #[test]
    fn test_reset_device_clears_rx_queue() {
        let dir = TempDir::new().unwrap();
        let mut backend = make_backend(&dir);
        backend.rx_queue.push_back(vec![1, 2, 3]);
        backend.reset_device();
        assert!(backend.rx_queue.is_empty());
        assert!(!backend.event_idx);
        assert!(backend.mem.is_none());
    }

    #[test]
    fn test_protocol_features_are_minimal() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        let pf = backend.protocol_features();
        assert!(pf.contains(VhostUserProtocolFeatures::CONFIG));
        assert!(pf.contains(VhostUserProtocolFeatures::REPLY_ACK));
    }

    #[test]
    fn test_signal_exit_writes_to_eventfd() {
        let dir = TempDir::new().unwrap();
        let backend = make_backend(&dir);
        backend.signal_exit().expect("signal_exit");
        // The exit_event consumer can now consume the pending notification.
        let (consumer, _notifier) = backend.exit_event(0).expect("exit_event");
        consumer.consume().expect("consume after signal_exit");
    }
}
