// SPDX-License-Identifier: MIT OR Apache-2.0

//! TX/RX vring processors implementing the `VIRTIO_RING_F_EVENT_IDX`-correct
//! drain loop.
//!
//! - [`TxProcessor`] drains the TX vring, classifies each frame through the
//!   trust-boundary pipeline ([`crate::datapath::intercept::classify`]) and
//!   dispatches the resulting [`InterceptDecision`]:
//!   * `ArpReply` / `DhcpReply` / `IcmpFragNeeded` are queued onto the RX vring
//!     via [`RxProcessor::enqueue`] (in-band reply).
//!   * `Tunnel` packets are encapsulated by the [`WgEngine`].
//!   * `Drop` packets bump a structured counter and are silently discarded.
//! - [`RxProcessor`] buffers RX frames in a bounded `VecDeque` and writes them
//!   into the RX vring (with a prepended 12-byte `virtio_net_hdr_v1`) as guest
//!   descriptors become available. On overflow the oldest frame is evicted; the
//!   datapath is therefore *non-blocking* with respect to a stalled guest.
//! - [`Counters`] aggregates per-vring atomic observability counters.
//!
//! The mandatory drain pattern is:
//!
//! ```text
//! loop {
//!     vring.disable_notification();
//!     while let Some(chain) = vring.iter(mem)?.next() { ... process ... }
//!     if !vring.enable_notification()? { break; }
//! }
//! vring.signal_used_queue();
//! ```
//!
//! Re-enabling notifications (and re-checking that no chain was added in the
//! meantime) is the atomic operation that closes the kick window: under
//! `EVENT_IDX` we must NOT process-one-and-return, or genuine kicks would be
//! lost.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use vhost_user_backend::{VringRwLock, VringT};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{Bytes, GuestMemory};

use crate::datapath::intercept::{DropReason, InterceptCfg, InterceptDecision, classify};
use crate::datapath::vnet;
use crate::dhcp::DhcpServer;
use crate::error::VhostError;
use crate::wg::WgEngine;
use crate::wg::routing::AllowedIpsRouter;

/// Length of the `virtio_net_hdr_v1` that prefixes every vring frame.
const VNET_HDR_LEN: usize = 12;
/// Byte offset of the IPv4 destination address inside an IPv4 header.
const IPV4_DST_OFFSET: usize = 16;
/// Length of an IPv4 address in bytes.
const IPV4_ADDR_LEN: usize = 4;

/// Per-vring atomic observability counters.
///
/// `drops` is keyed by [`DropReason`] with all fixed-shape variants
/// pre-inserted; the [`DropReason::EthTypeFiltered`] variant is collapsed to a
/// single bucket (with payload `0`) so that the overall key set is bounded.
/// `tx_frames` and `rx_frames` count successful dispatches in each direction;
/// `rx_no_buffer_drops` counts frames evicted from the RX queue because the
/// queue was full when [`RxProcessor::enqueue`] was invoked.
pub struct Counters {
    pub drops: HashMap<DropReason, AtomicU64>,
    pub tx_frames: AtomicU64,
    pub rx_frames: AtomicU64,
    pub rx_no_buffer_drops: AtomicU64,
}

impl Counters {
    /// Build a fresh counter set with every known [`DropReason`] bucket
    /// initialized to `0`.
    pub fn new() -> Self {
        let mut drops = HashMap::new();
        drops.insert(DropReason::EthTypeFiltered(0), AtomicU64::new(0));
        drops.insert(DropReason::VlanTagged, AtomicU64::new(0));
        drops.insert(DropReason::SrcMacSpoofed, AtomicU64::new(0));
        drops.insert(DropReason::BadIpv4Header, AtomicU64::new(0));
        drops.insert(DropReason::BadUdpHeader, AtomicU64::new(0));
        drops.insert(DropReason::FrameTooBig, AtomicU64::new(0));
        drops.insert(DropReason::FrameTooSmall, AtomicU64::new(0));
        drops.insert(DropReason::ShortDescriptorChain, AtomicU64::new(0));
        drops.insert(DropReason::SrcIpSpoofed, AtomicU64::new(0));
        drops.insert(DropReason::NoRoute, AtomicU64::new(0));
        drops.insert(DropReason::FragmentedPacket, AtomicU64::new(0));
        Self {
            drops,
            tx_frames: AtomicU64::new(0),
            rx_frames: AtomicU64::new(0),
            rx_no_buffer_drops: AtomicU64::new(0),
        }
    }

    /// Atomically bump the drop bucket associated with `reason`.
    ///
    /// `EthTypeFiltered(*)` is collapsed to `EthTypeFiltered(0)` (a single
    /// bucket). Other variants increment their exact slot. Reasons that are
    /// not pre-registered in the map are silently ignored — the map is built
    /// in [`Counters::new`] to cover every known variant.
    pub fn inc_drop(&self, reason: &DropReason) {
        let key = drop_reason_key(reason);
        if let Some(counter) = self.drops.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

fn drop_reason_key(reason: &DropReason) -> DropReason {
    match reason {
        DropReason::EthTypeFiltered(_) => DropReason::EthTypeFiltered(0),
        other => other.clone(),
    }
}

/// Concatenate every readable descriptor of `chain` into a contiguous owned
/// buffer.
///
/// This is a two-pass walk: first we collect the (address, length) pairs so we
/// can size the output buffer exactly, then we issue one `read_slice` per
/// descriptor. Returning `Vec<u8>` is intentional — the TX hot path takes
/// ownership of the frame for the duration of classification + dispatch.
pub fn read_descriptor_chain<M>(chain: DescriptorChain<M>) -> Result<Vec<u8>, VhostError>
where
    M: Deref + Clone,
    M::Target: GuestMemory,
{
    // Cloning the chain is cheap (it copies the internal index/ttl pair plus
    // the M handle) and lets us hold a memory reference past the consuming
    // `readable()` call below.
    let mem_keeper = chain.clone();
    let mem: &M::Target = mem_keeper.memory();

    let mut segments: Vec<(vm_memory::GuestAddress, u32)> = Vec::new();
    for desc in chain.readable() {
        segments.push((desc.addr(), desc.len()));
    }

    let mut total: usize = 0;
    for (_, len) in &segments {
        let len_usize = usize::try_from(*len)
            .map_err(|_| VhostError::Vring("descriptor length exceeds usize".to_string()))?;
        total = total
            .checked_add(len_usize)
            .ok_or_else(|| VhostError::Vring("descriptor chain length overflow".to_string()))?;
    }

    let mut buf = vec![0u8; total];
    let mut offset: usize = 0;
    for (addr, len) in segments {
        let len_usize = usize::try_from(len)
            .map_err(|_| VhostError::Vring("descriptor length exceeds usize".to_string()))?;
        mem.read_slice(&mut buf[offset..offset + len_usize], addr)
            .map_err(|e| VhostError::GuestMemory(e.to_string()))?;
        offset += len_usize;
    }
    Ok(buf)
}

/// Write `header` followed by `frame` into the writable side of `chain`.
///
/// Returns the total number of bytes written (always `header.len() +
/// frame.len()` on success). Returns `VhostError::Vring` when the writable
/// segments cannot accommodate the full payload.
fn write_frame_to_chain<M>(
    chain: DescriptorChain<M>,
    header: &[u8],
    frame: &[u8],
) -> Result<u32, VhostError>
where
    M: Deref + Clone,
    M::Target: GuestMemory,
{
    let mem_keeper = chain.clone();
    let mem: &M::Target = mem_keeper.memory();

    let mut payload = Vec::with_capacity(header.len() + frame.len());
    payload.extend_from_slice(header);
    payload.extend_from_slice(frame);

    let mut payload_offset: usize = 0;
    let mut bytes_written: usize = 0;
    for desc in chain.writable() {
        if payload_offset >= payload.len() {
            break;
        }
        let desc_len = usize::try_from(desc.len())
            .map_err(|_| VhostError::Vring("descriptor length exceeds usize".to_string()))?;
        let chunk_len = (payload.len() - payload_offset).min(desc_len);
        mem.write_slice(
            &payload[payload_offset..payload_offset + chunk_len],
            desc.addr(),
        )
        .map_err(|e| VhostError::GuestMemory(e.to_string()))?;
        payload_offset += chunk_len;
        bytes_written += chunk_len;
    }
    if payload_offset < payload.len() {
        return Err(VhostError::Vring(
            "RX descriptor chain too small for vnet header + frame".to_string(),
        ));
    }
    u32::try_from(bytes_written)
        .map_err(|_| VhostError::Vring("RX written length exceeds u32".to_string()))
}

/// RX-side processor: bounded pending queue + RX vring writer.
///
/// `enqueue` pushes onto an internal `VecDeque`, evicting the oldest entry
/// (and bumping `rx_no_buffer_drops`) when the queue is at capacity. `flush`
/// drains as many queued frames as the guest currently has descriptors for,
/// stopping the moment no descriptor is available — never blocking, never
/// dropping mid-frame.
pub struct RxProcessor<'a, M: GuestMemory> {
    pub vring: &'a VringRwLock,
    pub mem: &'a M,
    pub max_queue: usize,
    pub queue: VecDeque<Vec<u8>>,
    pub counters: &'a Counters,
}

impl<'a, M: GuestMemory> RxProcessor<'a, M> {
    /// Build a new RX processor.
    pub fn new(
        vring: &'a VringRwLock,
        mem: &'a M,
        max_queue: usize,
        counters: &'a Counters,
    ) -> Self {
        Self {
            vring,
            mem,
            max_queue,
            queue: VecDeque::new(),
            counters,
        }
    }

    /// Append `frame` to the pending queue, dropping the oldest entry on
    /// overflow.
    pub fn enqueue(&mut self, frame: Vec<u8>) {
        if self.queue.len() >= self.max_queue {
            self.queue.pop_front();
            self.counters
                .rx_no_buffer_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        self.queue.push_back(frame);
    }

    /// Drain queued frames into the RX vring until either the queue is empty
    /// or there are no available descriptor chains. Signals the guest exactly
    /// once if at least one frame was delivered.
    pub fn flush(&mut self) -> Result<(), VhostError> {
        // Pre-build the 12-byte virtio_net_hdr_v1 for every frame we deliver.
        let header = vnet::serialize(&vnet::rx_header());

        let mut state = self.vring.get_mut();
        let mut delivered = false;
        while !self.queue.is_empty() {
            let chain_opt = state
                .get_queue_mut()
                .iter(self.mem)
                .map_err(|e| VhostError::Vring(e.to_string()))?
                .next();
            let Some(chain) = chain_opt else {
                break;
            };
            let head_index = chain.head_index();
            let Some(frame) = self.queue.pop_front() else {
                // Defensive: invariant is queue.len() > 0 here. If we ever
                // reach this branch we have already pulled a chain off the
                // avail ring and must release it (with used_len = 0) rather
                // than leak it.
                state
                    .add_used(head_index, 0)
                    .map_err(|e| VhostError::Vring(e.to_string()))?;
                break;
            };
            let used_len = write_frame_to_chain(chain, &header, &frame)?;
            state
                .add_used(head_index, used_len)
                .map_err(|e| VhostError::Vring(e.to_string()))?;
            self.counters.rx_frames.fetch_add(1, Ordering::Relaxed);
            delivered = true;
        }
        if delivered {
            state.signal_used_queue().map_err(VhostError::EventFd)?;
        }
        Ok(())
    }
}

/// TX-side processor: drains the TX vring, classifies, and dispatches.
pub struct TxProcessor<'a, M: GuestMemory> {
    pub vring: &'a VringRwLock,
    pub mem: &'a M,
    pub rx: &'a mut RxProcessor<'a, M>,
    pub intercept_cfg: &'a InterceptCfg,
    pub router: &'a AllowedIpsRouter,
    pub dhcp: &'a mut DhcpServer,
    pub wg: &'a mut WgEngine,
    pub counters: &'a Counters,
    pub lease: Option<Ipv4Addr>,
    pub gateway_ip: Ipv4Addr,
}

impl<'a, M: GuestMemory> TxProcessor<'a, M> {
    /// Run the full `EVENT_IDX`-correct drain loop on the TX vring.
    ///
    /// This is the entrypoint invoked from the worker on every TX kick. It
    /// MUST drain everything it sees and re-arm notifications under the rules
    /// laid out in the module-level docstring; processing only one chain per
    /// kick would lose interrupts under EVENT_IDX.
    pub fn process(&mut self) -> Result<(), VhostError> {
        let mut state = self.vring.get_mut();
        loop {
            state
                .disable_notification()
                .map_err(|e| VhostError::Vring(e.to_string()))?;

            loop {
                let chain_opt = state
                    .get_queue_mut()
                    .iter(self.mem)
                    .map_err(|e| VhostError::Vring(e.to_string()))?
                    .next();
                let Some(chain) = chain_opt else {
                    break;
                };
                let head_index = chain.head_index();
                let frame = read_descriptor_chain(chain)?;
                self.handle_one(&frame);
                // TX descriptors are device-readable: nothing was written back
                // by us, so the used length is 0.
                state
                    .add_used(head_index, 0)
                    .map_err(|e| VhostError::Vring(e.to_string()))?;
            }

            if !state
                .enable_notification()
                .map_err(|e| VhostError::Vring(e.to_string()))?
            {
                break;
            }
        }
        state.signal_used_queue().map_err(VhostError::EventFd)?;
        Ok(())
    }

    /// Strip the 12-byte vnet header, classify the underlying Ethernet frame,
    /// and dispatch the resulting [`InterceptDecision`].
    fn handle_one(&mut self, raw: &[u8]) {
        if raw.len() < VNET_HDR_LEN {
            self.counters.inc_drop(&DropReason::ShortDescriptorChain);
            return;
        }
        let frame = &raw[VNET_HDR_LEN..];
        let decision = classify(
            frame,
            self.intercept_cfg,
            self.lease,
            self.router,
            SystemTime::now(),
            self.dhcp,
            self.gateway_ip,
        );
        match decision {
            InterceptDecision::ArpReply(reply)
            | InterceptDecision::DhcpReply(reply)
            | InterceptDecision::IcmpFragNeeded(reply) => {
                self.rx.enqueue(reply);
                self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
            }
            InterceptDecision::Tunnel {
                peer_idx: _,
                ip_packet,
            } => {
                if ip_packet.len() < IPV4_DST_OFFSET + IPV4_ADDR_LEN {
                    self.counters.inc_drop(&DropReason::BadIpv4Header);
                    return;
                }
                let dst_ip = Ipv4Addr::new(
                    ip_packet[IPV4_DST_OFFSET],
                    ip_packet[IPV4_DST_OFFSET + 1],
                    ip_packet[IPV4_DST_OFFSET + 2],
                    ip_packet[IPV4_DST_OFFSET + 3],
                );
                match self.wg.handle_tx_ip_packet(dst_ip, &ip_packet) {
                    Ok(()) => {
                        self.counters.tx_frames.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::trace!(error = %error, "wg_tx_dispatch_error");
                        self.counters.inc_drop(&DropReason::NoRoute);
                    }
                }
            }
            InterceptDecision::Drop(reason) => {
                self.counters.inc_drop(&reason);
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
    use vhost_user_backend::VringT;
    use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
    use x25519_dalek::StaticSecret;

    use crate::config::{Dhcp, DhcpPool, Network, Vm, Wireguard};
    use crate::wire::eth::build_eth_frame;

    const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);

    const DESC_TABLE_ADDR: u64 = 0x1000;
    const AVAIL_RING_ADDR: u64 = 0x2000;
    const USED_RING_ADDR: u64 = 0x3000;
    const BUFFER_BASE: u64 = 0x5000;
    const QUEUE_SIZE: u16 = 8;

    /// Build a fresh memory region + a configured (but empty) VringRwLock.
    fn setup_vring() -> (GuestMemoryAtomic<GuestMemoryMmap>, VringRwLock) {
        let gmm = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let atomic = GuestMemoryAtomic::new(gmm);
        let vring = VringRwLock::new(atomic.clone(), QUEUE_SIZE).unwrap();
        vring.set_queue_size(QUEUE_SIZE);
        vring
            .set_queue_info(DESC_TABLE_ADDR, AVAIL_RING_ADDR, USED_RING_ADDR)
            .unwrap();
        vring.set_queue_event_idx(true);
        vring.set_queue_ready(true);
        vring.set_enabled(true);
        (atomic, vring)
    }

    /// Write a single descriptor at `desc_idx` in the descriptor table.
    fn write_desc(
        mem: &GuestMemoryMmap,
        desc_idx: u16,
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    ) {
        let off = u64::from(desc_idx) * 16;
        mem.write_slice(&addr.to_le_bytes(), GuestAddress(DESC_TABLE_ADDR + off))
            .unwrap();
        mem.write_slice(&len.to_le_bytes(), GuestAddress(DESC_TABLE_ADDR + off + 8))
            .unwrap();
        mem.write_slice(&flags.to_le_bytes(), GuestAddress(DESC_TABLE_ADDR + off + 12))
            .unwrap();
        mem.write_slice(&next.to_le_bytes(), GuestAddress(DESC_TABLE_ADDR + off + 14))
            .unwrap();
    }

    /// Append a chain head index to the avail ring at slot `slot`, then
    /// publish the new `idx` value.
    fn publish_avail(mem: &GuestMemoryMmap, slot: u16, head_idx: u16, total_idx: u16) {
        // ring[slot] sits at avail_ring + 4 + slot*2 (after flags+idx header).
        mem.write_slice(
            &head_idx.to_le_bytes(),
            GuestAddress(AVAIL_RING_ADDR + 4 + u64::from(slot) * 2),
        )
        .unwrap();
        // avail.idx is at avail_ring + 2 (after flags).
        mem.write_slice(
            &total_idx.to_le_bytes(),
            GuestAddress(AVAIL_RING_ADDR + 2),
        )
        .unwrap();
    }

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

    fn make_wg_engine() -> WgEngine {
        let secret = StaticSecret::from([1u8; 32]);
        let cfg = Wireguard {
            private_key_file: None,
            private_key: None,
            listen_port: 0,
            peers: vec![],
        };
        WgEngine::new(&cfg, &secret).unwrap()
    }

    #[test]
    fn test_counters_increment_drop() {
        let counters = Counters::new();
        counters.inc_drop(&DropReason::FrameTooSmall);
        counters.inc_drop(&DropReason::FrameTooSmall);
        counters.inc_drop(&DropReason::NoRoute);
        // EthTypeFiltered(0x86DD) collapses to EthTypeFiltered(0).
        counters.inc_drop(&DropReason::EthTypeFiltered(0x86DD));
        counters.inc_drop(&DropReason::EthTypeFiltered(0xFFEE));

        assert_eq!(
            counters
                .drops
                .get(&DropReason::FrameTooSmall)
                .unwrap()
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            counters
                .drops
                .get(&DropReason::NoRoute)
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            counters
                .drops
                .get(&DropReason::EthTypeFiltered(0))
                .unwrap()
                .load(Ordering::Relaxed),
            2
        );
        // Counters not bumped stay at 0.
        assert_eq!(
            counters
                .drops
                .get(&DropReason::SrcMacSpoofed)
                .unwrap()
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_rx_overflow_drops_oldest() {
        let (atomic, vring) = setup_vring();
        let mem_handle = atomic.memory();
        let mem: &GuestMemoryMmap = &mem_handle;
        let counters = Counters::new();
        let mut rx = RxProcessor::new(&vring, mem, 2, &counters);

        rx.enqueue(vec![1; 10]);
        rx.enqueue(vec![2; 10]);
        rx.enqueue(vec![3; 10]); // should evict the first frame.

        assert_eq!(rx.queue.len(), 2);
        assert_eq!(rx.queue.front().unwrap()[0], 2);
        assert_eq!(rx.queue.back().unwrap()[0], 3);
        assert_eq!(counters.rx_no_buffer_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_rx_enqueue_and_flush_writes_to_vring() {
        let (atomic, vring) = setup_vring();
        let mem_handle = atomic.memory();
        let mem: &GuestMemoryMmap = &mem_handle;

        // One writable descriptor large enough for header + frame.
        write_desc(mem, 0, BUFFER_BASE, 256, 0x2 /* WRITE */, 0);
        publish_avail(mem, 0, 0, 1);

        let counters = Counters::new();
        let mut rx = RxProcessor::new(&vring, mem, 32, &counters);
        let frame: Vec<u8> = (0..40u8).collect();
        rx.enqueue(frame.clone());
        rx.flush().unwrap();

        // After flush the queue is empty and the frame counter is bumped.
        assert!(rx.queue.is_empty());
        assert_eq!(counters.rx_frames.load(Ordering::Relaxed), 1);

        // Verify the on-wire layout: 12 bytes vnet header (zeros, num_buffers=1)
        // followed by the 40-byte payload.
        let mut buf = [0u8; 12 + 40];
        mem.read_slice(&mut buf, GuestAddress(BUFFER_BASE)).unwrap();
        // Header: flags=0 gso_type=0 hdr_len=0 gso_size=0 csum_*=0 num_buffers=1.
        assert_eq!(&buf[..10], &[0u8; 10]);
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 1);
        assert_eq!(&buf[12..], frame.as_slice());
    }

    #[test]
    fn test_tx_drains_batch_under_event_idx() {
        // Three TX chains in the avail ring. A correct EVENT_IDX-aware loop
        // must drain ALL of them in a single call to `process`.
        let (atomic, vring) = setup_vring();
        let mem_handle = atomic.memory();
        let mem: &GuestMemoryMmap = &mem_handle;

        // Each chain points at a 32-byte buffer that holds a tiny ethertype
        // 0x86DD (IPv6) frame: classify will reject with EthTypeFiltered, no
        // WG/DHCP path is exercised. The frame is a 12-byte vnet header
        // followed by an Ethernet frame whose ethertype is 0x86DD.
        const FRAME_SIZE: u32 = 32;
        for chain_idx in 0u16..3 {
            let buf_addr = BUFFER_BASE + u64::from(chain_idx) * 64;
            // 12-byte vnet header (all zeros).
            mem.write_slice(&[0u8; 12], GuestAddress(buf_addr)).unwrap();
            // 14-byte Ethernet header: dst=ff:..., src=VM_MAC, ethertype=0x86DD.
            let eth = build_eth_frame([0xff; 6], VM_MAC, 0x86DD, &[0u8; 6]);
            mem.write_slice(&eth, GuestAddress(buf_addr + 12)).unwrap();
            write_desc(mem, chain_idx, buf_addr, FRAME_SIZE, 0, 0);
            publish_avail(mem, chain_idx, chain_idx, chain_idx + 1);
        }

        let counters = Counters::new();
        let intercept_cfg = make_intercept_cfg();
        let router = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp(&dir);
        let mut wg = make_wg_engine();

        // Set up a separate (unused) RX vring; flush is never invoked here.
        let rx_gmm =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx_atomic = GuestMemoryAtomic::new(rx_gmm);
        let rx_vring = VringRwLock::new(rx_atomic.clone(), QUEUE_SIZE).unwrap();
        rx_vring.set_queue_size(QUEUE_SIZE);
        rx_vring
            .set_queue_info(DESC_TABLE_ADDR, AVAIL_RING_ADDR, USED_RING_ADDR)
            .unwrap();
        rx_vring.set_queue_event_idx(true);
        rx_vring.set_queue_ready(true);
        rx_vring.set_enabled(true);
        let rx_mem_handle = rx_atomic.memory();
        let rx_mem: &GuestMemoryMmap = &rx_mem_handle;
        let mut rx = RxProcessor::new(&rx_vring, rx_mem, 32, &counters);

        let mut tx = TxProcessor {
            vring: &vring,
            mem,
            rx: &mut rx,
            intercept_cfg: &intercept_cfg,
            router: &router,
            dhcp: &mut dhcp,
            wg: &mut wg,
            counters: &counters,
            lease: Some(VM_IP),
            gateway_ip: GW_IP,
        };
        tx.process().unwrap();

        // All three chains went through the EthTypeFiltered drop path.
        let eth_drops = counters
            .drops
            .get(&DropReason::EthTypeFiltered(0))
            .unwrap()
            .load(Ordering::Relaxed);
        assert_eq!(eth_drops, 3);
        // No frames were tunneled.
        assert_eq!(counters.tx_frames.load(Ordering::Relaxed), 0);
        // Vring's next_avail should now be 3.
        assert_eq!(vring.queue_next_avail(), 3);
    }

    #[test]
    fn test_tx_drop_increments_counter_for_short_frame() {
        // A single chain whose payload is below the vnet header threshold:
        // handle_one short-circuits on raw.len() < VNET_HDR_LEN and bumps
        // `ShortDescriptorChain`.
        let (atomic, vring) = setup_vring();
        let mem_handle = atomic.memory();
        let mem: &GuestMemoryMmap = &mem_handle;

        write_desc(mem, 0, BUFFER_BASE, 4, 0, 0);
        publish_avail(mem, 0, 0, 1);

        let counters = Counters::new();
        let intercept_cfg = make_intercept_cfg();
        let router = AllowedIpsRouter::new();
        let dir = TempDir::new().unwrap();
        let mut dhcp = make_dhcp(&dir);
        let mut wg = make_wg_engine();

        let rx_gmm =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx_atomic = GuestMemoryAtomic::new(rx_gmm);
        let rx_vring = VringRwLock::new(rx_atomic.clone(), QUEUE_SIZE).unwrap();
        rx_vring.set_queue_size(QUEUE_SIZE);
        rx_vring
            .set_queue_info(DESC_TABLE_ADDR, AVAIL_RING_ADDR, USED_RING_ADDR)
            .unwrap();
        rx_vring.set_queue_ready(true);
        let rx_mem_handle = rx_atomic.memory();
        let rx_mem: &GuestMemoryMmap = &rx_mem_handle;
        let mut rx = RxProcessor::new(&rx_vring, rx_mem, 32, &counters);

        let mut tx = TxProcessor {
            vring: &vring,
            mem,
            rx: &mut rx,
            intercept_cfg: &intercept_cfg,
            router: &router,
            dhcp: &mut dhcp,
            wg: &mut wg,
            counters: &counters,
            lease: Some(VM_IP),
            gateway_ip: GW_IP,
        };
        tx.process().unwrap();

        assert_eq!(
            counters
                .drops
                .get(&DropReason::ShortDescriptorChain)
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_read_descriptor_chain_concatenates_segments() {
        // Build a two-descriptor read-only chain and verify it concatenates.
        let gmm = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // First half at 0x5000 (8 bytes), second half at 0x6000 (8 bytes).
        gmm.write_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8], GuestAddress(0x5000))
            .unwrap();
        gmm.write_slice(&[9u8, 10, 11, 12, 13, 14, 15, 16], GuestAddress(0x6000))
            .unwrap();

        // Set up a queue with the two-descriptor chain.
        let atomic = GuestMemoryAtomic::new(gmm);
        let vring = VringRwLock::new(atomic.clone(), QUEUE_SIZE).unwrap();
        vring.set_queue_size(QUEUE_SIZE);
        vring
            .set_queue_info(DESC_TABLE_ADDR, AVAIL_RING_ADDR, USED_RING_ADDR)
            .unwrap();
        vring.set_queue_ready(true);
        let mem_handle = atomic.memory();
        let mem: &GuestMemoryMmap = &mem_handle;

        // Descriptor 0: read-only, len=8, NEXT to desc 1.
        write_desc(mem, 0, 0x5000, 8, 0x1 /* NEXT */, 1);
        // Descriptor 1: read-only, len=8, terminal.
        write_desc(mem, 1, 0x6000, 8, 0, 0);
        publish_avail(mem, 0, 0, 1);

        // Pull the chain out of the avail ring and read it.
        let chain = {
            let mut state = vring.get_mut();
            state.get_queue_mut().iter(mem).unwrap().next().unwrap()
        };
        let buf = read_descriptor_chain(chain).unwrap();
        assert_eq!(
            buf,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }
}
