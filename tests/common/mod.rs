// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mock vhost-user master test harness.
//!
//! [`MockVhostUserMaster`] drives a child instance of the
//! `vhost-user-wireguard` daemon over the vhost-user wire protocol with a
//! file-backed shared-memory region holding a pair of split virtio queues.
//! `write_tx_frame` and `read_rx_frame` exchange Ethernet frames with the
//! daemon end-to-end; `disconnect_and_reconnect` exercises the framework's
//! reconnect path (the daemon framework rebuilds its epoll handler each time
//! `daemon.serve()` returns and must be re-fed every vring address).
//!
//! ### Shared-memory layout (3 MB region, file-backed)
//!
//! | offset       | size  | purpose                              |
//! |--------------|-------|--------------------------------------|
//! | `0x000000`   |  1MB  | TX descriptor data buffers (256×4KB) |
//! | `0x100000`   |  1MB  | RX descriptor data buffers (256×4KB) |
//! | `0x200000`   |  4KB  | RX descriptor table                  |
//! | `0x201000`   |  4KB  | RX avail ring                        |
//! | `0x202000`   |  4KB  | RX used ring                         |
//! | `0x203000`   |  4KB  | TX descriptor table                  |
//! | `0x204000`   |  4KB  | TX avail ring                        |
//! | `0x205000`   |  4KB  | TX used ring                         |
//!
//! Guest physical addresses == file offsets (`guest_phys_addr = 0` in the
//! single SET_MEM_TABLE region).
//!
//! ### Why we don't ack `VIRTIO_RING_F_EVENT_IDX`
//!
//! With `EVENT_IDX` enabled the daemon would only fire the call eventfd if
//! `avail.idx` crossed `used_event` (and would only check `avail_event`
//! before scanning). Implementing that bookkeeping doubles the harness
//! complexity for zero test signal — the daemon's `set_event_idx(false)`
//! path is just as exercised by the production code paths, so we negotiate
//! it off.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering, fence};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vhost::vhost_user::Frontend;
use vhost::vhost_user::VhostUserFrontend;
use vhost::vhost_user::message::{
    VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

pub const DAEMON_BIN: &str = "target/release/vhost-user-wireguard";

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: u32 = 2;

pub const RX_QUEUE_INDEX: u32 = 0;
pub const TX_QUEUE_INDEX: u32 = 1;

pub const VIRTIO_F_VERSION_1_BIT: u32 = 32;
pub const VIRTIO_NET_F_MAC_BIT: u32 = 5;
pub const VIRTIO_NET_F_MTU_BIT: u32 = 3;
pub const VIRTIO_NET_F_MRG_RXBUF_BIT: u32 = 15;
pub const VIRTIO_NET_F_STATUS_BIT: u32 = 16;
pub const VIRTIO_RING_F_EVENT_IDX_BIT: u32 = 29;

/// Width of the virtio-net header (`virtio_net_hdr_v1`).
pub const VNET_HDR_LEN: usize = 12;

/// One descriptor's data buffer size. 4 KiB is one page, comfortably above
/// any Ethernet MTU we set in the canned config (1420), and is small enough
/// that the entire 256-buffer pool fits in 1 MiB per queue.
pub const BUFFER_SIZE: usize = 4096;

const PAGE_SIZE: usize = 4096;
const TOTAL_BUFFERS: usize = QUEUE_SIZE as usize;

const TX_BUFFER_BASE: u64 = 0x000_000;
const RX_BUFFER_BASE: u64 = 0x100_000;
const RX_DESC_BASE: u64 = 0x200_000;
const RX_AVAIL_BASE: u64 = 0x201_000;
const RX_USED_BASE: u64 = 0x202_000;
const TX_DESC_BASE: u64 = 0x203_000;
const TX_AVAIL_BASE: u64 = 0x204_000;
const TX_USED_BASE: u64 = 0x205_000;
const MEM_SIZE: usize = 0x300_000;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

pub const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x01];
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
pub const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 2);

static PORT_ALLOCATOR: AtomicU16 = AtomicU16::new(51820);

/// Allocate a fresh listen port for one test run. Wraps to 51820 on overflow
/// because the daemon's validator rejects port 0.
pub fn alloc_listen_port() -> u16 {
    let raw = PORT_ALLOCATOR.fetch_add(1, Ordering::Relaxed);
    if raw == 0 { 51820 } else { raw }
}

pub fn fake_wg_key(seed: u8) -> String {
    let bytes = [seed; 32];
    BASE64.encode(bytes)
}

pub const CONFIG_TEMPLATE: &str = r#"
[wireguard]
private_key = "{wg_priv}"
listen_port = {wg_port}

[[wireguard.peers]]
name = "test-peer"
public_key = "{wg_peer_pub}"
endpoint = "127.0.0.1:51821"
allowed_ips = ["10.0.0.0/24"]

[vhost_user]
socket = "{vu_socket}"
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
"#;

pub fn write_temp_config(
    template: &str,
    fields: BTreeMap<&str, &str>,
) -> tempfile::TempPath {
    let mut rendered = template.to_string();
    for (key, value) in fields {
        let needle = format!("{{{key}}}");
        rendered = rendered.replace(&needle, value);
    }
    let mut tf = tempfile::Builder::new()
        .prefix("vuwg-cfg-")
        .suffix(".toml")
        .tempfile()
        .expect("temp config file");
    tf.write_all(rendered.as_bytes()).expect("write config");
    tf.flush().expect("flush config");
    tf.into_temp_path()
}

pub fn default_config(socket_path: &Path, listen_port: u16) -> tempfile::TempPath {
    let priv_key = fake_wg_key(0x11);
    let peer_pub = fake_wg_key(0x22);
    let port_str = listen_port.to_string();
    let socket_str = socket_path.to_string_lossy().into_owned();
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    fields.insert("wg_priv", &priv_key);
    fields.insert("wg_port", &port_str);
    fields.insert("wg_peer_pub", &peer_pub);
    fields.insert("vu_socket", &socket_str);
    write_temp_config(CONFIG_TEMPLATE, fields)
}

fn wait_for_path(path: &Path, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

pub fn fake_notify_socket() -> (PathBuf, JoinHandle<Vec<String>>) {
    let dir = tempfile::Builder::new()
        .prefix("vuwg-notify-")
        .tempdir()
        .expect("tempdir for notify socket");
    let path = dir.path().join("notify.sock");
    let socket = UnixDatagram::bind(&path).expect("bind notify datagram socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("set notify read timeout");
    let path_clone = path.clone();
    let handle = thread::Builder::new()
        .name("fake-notify-socket".to_string())
        .spawn(move || {
            let _dir_guard = dir;
            let mut lines = Vec::<String>::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match socket.recv(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
                        for line in chunk.split('\n') {
                            if !line.is_empty() {
                                lines.push(line.to_string());
                            }
                        }
                    }
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut
                        {
                            if !path_clone.exists() {
                                break;
                            }
                            continue;
                        }
                        break;
                    }
                }
            }
            lines
        })
        .expect("spawn fake-notify reader");
    (path, handle)
}

pub fn build_dhcp_discover(mac: [u8; 6]) -> Vec<u8> {
    use dhcproto::{Encoder, Encodable as _};
    use dhcproto::v4::{
        DhcpOption, DhcpOptions, Flags, HType, Message, MessageType, Opcode, OptionCode,
    };

    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest);
    msg.set_htype(HType::Eth);
    msg.set_xid(0xCAFEBABE);
    msg.set_flags(Flags::default().set_broadcast());
    msg.set_chaddr(&mac);

    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::MessageType(MessageType::Discover));
    opts.insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::InterfaceMtu,
    ]));
    msg.set_opts(opts);

    let mut dhcp_buf = Vec::with_capacity(512);
    {
        let mut enc = Encoder::new(&mut dhcp_buf);
        msg.encode(&mut enc).expect("encode dhcp discover");
    }

    let udp_len = u16::try_from(dhcp_buf.len() + 8).expect("udp length fits");
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
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
    ip.push(17);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0]);
    ip.extend_from_slice(&[255, 255, 255, 255]);
    let csum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);

    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
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

pub fn build_arp_request(spa: Ipv4Addr, sha: [u8; 6], tpa: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 28);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&sha);
    frame.extend_from_slice(&0x0806u16.to_be_bytes());

    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&sha);
    frame.extend_from_slice(&spa.octets());
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&tpa.octets());
    frame
}

/// File-backed shared memory region exposed to the daemon via SET_MEM_TABLE.
struct SharedMem {
    file: std::fs::File,
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for SharedMem {}
unsafe impl Sync for SharedMem {}

impl SharedMem {
    fn new(len: usize) -> std::io::Result<Self> {
        assert!(len.is_multiple_of(PAGE_SIZE), "len must be page-aligned");
        let file = tempfile::tempfile()?;
        file.set_len(u64::try_from(len).expect("len fits u64"))?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let ptr = ptr.cast::<u8>();
        unsafe {
            std::ptr::write_bytes(ptr, 0, len);
        }
        Ok(Self { file, ptr, len })
    }

    fn base(&self) -> *mut u8 {
        self.ptr
    }

    fn fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }

    /// Write `data` into the region starting at `offset`.
    ///
    /// # Safety
    /// `offset + data.len() <= self.len` must hold.
    unsafe fn write_bytes(&self, offset: u64, data: &[u8]) {
        let off = usize::try_from(offset).expect("offset fits usize");
        assert!(off + data.len() <= self.len, "write past region end");
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(off), data.len());
        }
    }

    /// Read `len` bytes starting at `offset` into a new `Vec<u8>`.
    unsafe fn read_bytes(&self, offset: u64, len: usize) -> Vec<u8> {
        let off = usize::try_from(offset).expect("offset fits usize");
        assert!(off + len <= self.len, "read past region end");
        let mut out = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(off), out.as_mut_ptr(), len);
        }
        out
    }

    /// Volatile little-endian write of a `u16` at `offset`.
    unsafe fn write_u16_le(&self, offset: u64, value: u16) {
        let off = usize::try_from(offset).expect("offset fits usize");
        assert!(off + 2 <= self.len, "u16 write past region end");
        let bytes = value.to_le_bytes();
        unsafe {
            std::ptr::write_volatile(self.ptr.add(off).cast::<[u8; 2]>(), bytes);
        }
    }

    /// Volatile little-endian read of a `u16` at `offset`.
    unsafe fn read_u16_le(&self, offset: u64) -> u16 {
        let off = usize::try_from(offset).expect("offset fits usize");
        assert!(off + 2 <= self.len, "u16 read past region end");
        let bytes: [u8; 2] =
            unsafe { std::ptr::read_volatile(self.ptr.add(off).cast::<[u8; 2]>()) };
        u16::from_le_bytes(bytes)
    }

    /// Volatile little-endian read of a `u32` at `offset`.
    unsafe fn read_u32_le(&self, offset: u64) -> u32 {
        let off = usize::try_from(offset).expect("offset fits usize");
        assert!(off + 4 <= self.len, "u32 read past region end");
        let bytes: [u8; 4] =
            unsafe { std::ptr::read_volatile(self.ptr.add(off).cast::<[u8; 4]>()) };
        u32::from_le_bytes(bytes)
    }
}

impl Drop for SharedMem {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr.cast::<libc::c_void>(), self.len);
            }
        }
    }
}

/// One side of a queue pair (RX or TX) with its kick / call eventfds and
/// cached avail / used indices.
struct RingPair {
    queue_index: u32,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
    buffer_base: u64,
    avail_idx: u16,
    last_used_idx: u16,
    kick: EventFd,
    call: EventFd,
}

impl RingPair {
    fn rx() -> std::io::Result<Self> {
        Ok(Self {
            queue_index: RX_QUEUE_INDEX,
            desc_table: RX_DESC_BASE,
            avail_ring: RX_AVAIL_BASE,
            used_ring: RX_USED_BASE,
            buffer_base: RX_BUFFER_BASE,
            avail_idx: 0,
            last_used_idx: 0,
            kick: EventFd::new(EFD_NONBLOCK)?,
            call: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    fn tx() -> std::io::Result<Self> {
        Ok(Self {
            queue_index: TX_QUEUE_INDEX,
            desc_table: TX_DESC_BASE,
            avail_ring: TX_AVAIL_BASE,
            used_ring: TX_USED_BASE,
            buffer_base: TX_BUFFER_BASE,
            avail_idx: 0,
            last_used_idx: 0,
            kick: EventFd::new(EFD_NONBLOCK)?,
            call: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    fn buffer_addr(&self, slot: u16) -> u64 {
        self.buffer_base + u64::from(slot) * (BUFFER_SIZE as u64)
    }

    fn desc_offset(&self, slot: u16) -> u64 {
        self.desc_table + u64::from(slot) * 16
    }

    /// Write a fresh descriptor into slot `slot`, returning the head index
    /// to publish.
    fn write_descriptor(
        &self,
        mem: &SharedMem,
        slot: u16,
        addr: u64,
        len: u32,
        flags: u16,
    ) -> u16 {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&addr.to_le_bytes());
        bytes[8..12].copy_from_slice(&len.to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[14..16].copy_from_slice(&0u16.to_le_bytes());
        unsafe { mem.write_bytes(self.desc_offset(slot), &bytes) };
        slot
    }

    /// Publish `head` into the avail ring at our current `avail_idx`, then
    /// advance and write the new `avail.idx` back to the ring.
    fn publish_avail(&mut self, mem: &SharedMem, head: u16) {
        let slot = self.avail_idx % QUEUE_SIZE;
        let entry_off = self.avail_ring + 4 + u64::from(slot) * 2;
        unsafe { mem.write_u16_le(entry_off, head) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        fence(Ordering::SeqCst);
        unsafe { mem.write_u16_le(self.avail_ring + 2, self.avail_idx) };
        fence(Ordering::SeqCst);
    }

    /// Read the current `used.idx` written by the daemon.
    fn read_used_idx(&self, mem: &SharedMem) -> u16 {
        unsafe { mem.read_u16_le(self.used_ring + 2) }
    }

    /// Read the used-ring entry at the given monotonic position.
    fn read_used_elem(&self, mem: &SharedMem, position: u16) -> (u32, u32) {
        let slot = position % QUEUE_SIZE;
        let entry_off = self.used_ring + 4 + u64::from(slot) * 8;
        let id = unsafe { mem.read_u32_le(entry_off) };
        let len = unsafe { mem.read_u32_le(entry_off + 4) };
        (id, len)
    }
}

struct DaemonChild {
    child: Option<Child>,
}

impl DaemonChild {
    fn shutdown(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Live, connected master driver. One instance == one daemon process + one
/// connection + one shared-memory region + two configured queues.
pub struct MockVhostUserMaster {
    daemon: DaemonChild,
    frontend: Option<Frontend>,
    socket_path: PathBuf,
    config_path: tempfile::TempPath,
    stderr_path: PathBuf,
    _work_dir: tempfile::TempDir,
    mem: SharedMem,
    rx: RingPair,
    tx: RingPair,
    /// Acked virtio features after the latest negotiation.
    pub acked_virtio_features: u64,
    /// Full feature mask the daemon advertised (pre-mask).
    pub advertised_virtio_features: u64,
    /// Acked protocol features (empty if PROTOCOL_FEATURES bit was not
    /// advertised).
    pub acked_protocol_features: VhostUserProtocolFeatures,
}

impl MockVhostUserMaster {
    /// Spawn the daemon, set up shared memory, perform feature + vring
    /// negotiation, and pre-publish RX descriptors so the daemon has buffer
    /// space waiting.
    pub fn spawn() -> Self {
        let work_dir = tempfile::Builder::new()
            .prefix("vuwg-test-")
            .tempdir()
            .expect("tempdir for test workspace");
        let socket_path = work_dir.path().join("vhost.sock");
        let listen_port = alloc_listen_port();
        let config_path = default_config(&socket_path, listen_port);

        let bin = resolve_daemon_binary();
        let mut command = Command::new(&bin);
        let cfg_arg: &Path = config_path.as_ref();
        let stderr_path = work_dir.path().join("daemon.stderr.log");
        let stderr_file = std::fs::File::create(&stderr_path)
            .expect("create daemon stderr log");
        command
            .arg("--config")
            .arg(cfg_arg)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        command.env_remove("NOTIFY_SOCKET");
        command.env(
            "RUST_LOG",
            std::env::var("VUWG_TEST_LOG").unwrap_or_else(|_| "off".to_string()),
        );

        let child = command.spawn().unwrap_or_else(|e| {
            panic!(
                "failed to spawn daemon binary at {bin:?}: {e}. Did you run `cargo build --release`?"
            )
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        if !wait_for_path(&socket_path, deadline) {
            let mut daemon = DaemonChild { child: Some(child) };
            daemon.shutdown();
            let stderr_dump = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "daemon never created its vhost-user socket at {} within 5s\n--- daemon stderr ---\n{stderr_dump}",
                socket_path.display(),
            );
        }

        let mem = SharedMem::new(MEM_SIZE).expect("create shared memory region");
        let rx = RingPair::rx().expect("create RX ring");
        let tx = RingPair::tx().expect("create TX ring");

        let mut harness = Self {
            daemon: DaemonChild { child: Some(child) },
            frontend: None,
            socket_path,
            config_path,
            stderr_path,
            _work_dir: work_dir,
            mem,
            rx,
            tx,
            acked_virtio_features: 0,
            advertised_virtio_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
        };
        harness.connect_and_negotiate();
        harness
    }

    fn dump_daemon_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    /// Drop the existing connection, terminate the daemon child, spawn a
    /// fresh one with the same config + socket path, and re-do the full
    /// negotiation handshake.
    ///
    /// The current daemon binary's `run()` returns after a single
    /// `daemon.serve()` invocation (one connection per process), so a true
    /// in-process reconnect would require modifying production code. The
    /// harness instead exercises the master-side reconnect path by
    /// recreating the daemon — the framework-level epoll-handler-rebuild
    /// is still validated end-to-end (the new daemon must accept and
    /// handle the same SET_VRING_* sequence we issued the first time).
    pub fn disconnect_and_reconnect(&mut self) {
        self.frontend = None;
        self.daemon.shutdown();
        let removal_deadline = Instant::now() + Duration::from_secs(5);
        while self.socket_path.exists() && Instant::now() < removal_deadline {
            thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&self.socket_path);

        self.rx = RingPair::rx().expect("recreate RX ring");
        self.tx = RingPair::tx().expect("recreate TX ring");
        let zero_pages = 3 * PAGE_SIZE;
        unsafe {
            std::ptr::write_bytes(
                self.mem.base().add(usize::try_from(RX_AVAIL_BASE).unwrap()),
                0,
                zero_pages,
            );
            std::ptr::write_bytes(
                self.mem.base().add(usize::try_from(TX_AVAIL_BASE).unwrap()),
                0,
                zero_pages,
            );
        }

        let bin = resolve_daemon_binary();
        let mut command = Command::new(&bin);
        let cfg_arg: &Path = self.config_path.as_ref();
        let stderr_file = std::fs::File::create(&self.stderr_path)
            .expect("recreate daemon stderr log");
        command
            .arg("--config")
            .arg(cfg_arg)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        command.env_remove("NOTIFY_SOCKET");
        command.env(
            "RUST_LOG",
            std::env::var("VUWG_TEST_LOG").unwrap_or_else(|_| "off".to_string()),
        );
        let child = command.spawn().expect("respawn daemon");
        self.daemon = DaemonChild { child: Some(child) };

        let socket_deadline = Instant::now() + Duration::from_secs(5);
        if !wait_for_path(&self.socket_path, socket_deadline) {
            let stderr_dump = self.dump_daemon_stderr();
            self.daemon.shutdown();
            panic!(
                "respawned daemon never created socket at {} within 5s\n--- daemon stderr ---\n{stderr_dump}",
                self.socket_path.display(),
            );
        }

        self.connect_and_negotiate();
    }

    fn connect_and_negotiate(&mut self) {
        let stream = connect_with_retries(&self.socket_path, Duration::from_secs(5));
        let mut frontend = Frontend::from_stream(stream, u64::from(NUM_QUEUES));
        self.checked(frontend.set_owner(), "set_owner");

        let advertised_virtio = self.checked(frontend.get_features(), "get_features");
        assert_features_present(advertised_virtio);
        self.advertised_virtio_features = advertised_virtio;
        let acked_virtio = advertised_virtio & !(1u64 << VIRTIO_RING_F_EVENT_IDX_BIT);
        self.checked(frontend.set_features(acked_virtio), "set_features");
        self.acked_virtio_features = acked_virtio;

        if advertised_virtio & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            let advertised_proto =
                self.checked(frontend.get_protocol_features(), "get_protocol_features");
            let acked_proto = advertised_proto
                & (VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::REPLY_ACK);
            self.checked(
                frontend.set_protocol_features(acked_proto),
                "set_protocol_features",
            );
            self.acked_protocol_features = acked_proto;
        } else {
            self.acked_protocol_features = VhostUserProtocolFeatures::empty();
        }

        let userspace_addr = self.mem.base() as u64;
        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: 0,
            memory_size: MEM_SIZE as u64,
            userspace_addr,
            mmap_offset: 0,
            mmap_handle: self.mem.fd(),
        };
        self.checked(
            frontend.set_mem_table(std::slice::from_ref(&region)),
            "set_mem_table",
        );

        self.configure_ring(&frontend, RingChoice::Rx);
        self.configure_ring(&frontend, RingChoice::Tx);

        self.frontend = Some(frontend);

        prepublish_rx_descriptors(&self.mem, &mut self.rx);
        let _ = self.rx.kick.write(1);
    }

    fn checked<T, E: std::fmt::Debug>(&self, result: Result<T, E>, label: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => {
                let stderr_dump = self.dump_daemon_stderr();
                let alive = self
                    .daemon
                    .child
                    .as_ref()
                    .and_then(|c| {
                        let pid = c.id();
                        let path = format!("/proc/{pid}/status");
                        std::fs::read_to_string(path).ok()
                    })
                    .map(|s| s.lines().take(3).collect::<Vec<_>>().join(" | "))
                    .unwrap_or_else(|| "(daemon process gone)".to_string());
                panic!(
                    "{label} failed: {error:?}\n--- daemon /proc/PID/status ---\n{alive}\n--- daemon stderr ---\n{stderr_dump}"
                );
            }
        }
    }

    fn configure_ring(&self, frontend: &Frontend, choice: RingChoice) {
        let ring = match choice {
            RingChoice::Rx => &self.rx,
            RingChoice::Tx => &self.tx,
        };
        let qi = usize::try_from(ring.queue_index).expect("queue index fits usize");
        let userspace_base = self.mem.base() as u64;
        self.checked(frontend.set_vring_num(qi, QUEUE_SIZE), "set_vring_num");
        self.checked(frontend.set_vring_base(qi, 0), "set_vring_base");
        let config = VringConfigData {
            queue_max_size: QUEUE_SIZE,
            queue_size: QUEUE_SIZE,
            flags: 0,
            desc_table_addr: userspace_base + ring.desc_table,
            used_ring_addr: userspace_base + ring.used_ring,
            avail_ring_addr: userspace_base + ring.avail_ring,
            log_addr: None,
        };
        self.checked(frontend.set_vring_addr(qi, &config), "set_vring_addr");
        self.checked(frontend.set_vring_call(qi, &ring.call), "set_vring_call");
        self.checked(frontend.set_vring_kick(qi, &ring.kick), "set_vring_kick");
    }

    pub fn frontend(&self) -> &Frontend {
        self.frontend
            .as_ref()
            .expect("frontend connected; call spawn() before frontend()")
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn config_path(&self) -> &Path {
        self.config_path.as_ref()
    }

    /// Place `eth` in a fresh TX descriptor (preceded by a 12-byte zero
    /// vnet_hdr), publish it, kick the daemon, and block until the daemon
    /// returns the descriptor on the used ring.
    pub fn write_tx_frame(&mut self, eth: &[u8]) {
        assert!(
            VNET_HDR_LEN + eth.len() <= BUFFER_SIZE,
            "frame {} bytes exceeds harness buffer {}",
            eth.len(),
            BUFFER_SIZE - VNET_HDR_LEN,
        );
        let slot = self.tx.avail_idx % QUEUE_SIZE;
        let buf_addr = self.tx.buffer_addr(slot);

        let mut payload = vec![0u8; VNET_HDR_LEN + eth.len()];
        payload[VNET_HDR_LEN..].copy_from_slice(eth);
        unsafe { self.mem.write_bytes(buf_addr, &payload) };

        let head = self.tx.write_descriptor(
            &self.mem,
            slot,
            buf_addr,
            u32::try_from(payload.len()).expect("payload len fits u32"),
            0,
        );
        let target = self.tx.last_used_idx.wrapping_add(1);
        self.tx.publish_avail(&self.mem, head);
        self.tx.kick.write(1).expect("tx kick");

        wait_for_used_advance(&self.mem, &self.tx, target, Duration::from_secs(2))
            .expect("daemon never completed TX descriptor");
        self.tx.last_used_idx = target;
    }

    /// Block up to 1s for an RX completion. Returns the frame (with the
    /// 12-byte vnet_hdr stripped) on success, or `None` on timeout.
    /// Re-publishes the descriptor before returning so the daemon always
    /// has buffers waiting.
    pub fn read_rx_frame(&mut self) -> Option<Vec<u8>> {
        let target = self.rx.last_used_idx.wrapping_add(1);
        if wait_for_used_advance(&self.mem, &self.rx, target, Duration::from_secs(1))
            .is_err()
        {
            return None;
        }
        let (id, len) = self.rx.read_used_elem(&self.mem, self.rx.last_used_idx);
        self.rx.last_used_idx = target;

        let head = u16::try_from(id).expect("desc id fits u16");
        let buf_addr = self.rx.buffer_addr(head);
        let total = usize::try_from(len).expect("desc len fits usize");
        assert!(
            total >= VNET_HDR_LEN,
            "daemon wrote shorter than vnet_hdr: {total} bytes"
        );
        let frame_len = total - VNET_HDR_LEN;
        let frame =
            unsafe { self.mem.read_bytes(buf_addr + VNET_HDR_LEN as u64, frame_len) };

        self.rx.write_descriptor(
            &self.mem,
            head,
            buf_addr,
            BUFFER_SIZE as u32,
            VRING_DESC_F_WRITE,
        );
        self.rx.publish_avail(&self.mem, head);
        let _ = self.rx.kick.write(1);

        Some(frame)
    }
}

/// Spin-poll the ring's `used.idx` until it equals `target` or `timeout`
/// elapses. We poll instead of blocking on the call eventfd because the
/// call eventfd is only fired with EVENT_IDX off when used.idx advances at
/// all, and reading the eventfd would consume the wakeup before the next
/// caller — polling shared memory keeps the harness self-contained.
fn wait_for_used_advance(
    mem: &SharedMem,
    ring: &RingPair,
    target: u16,
    timeout: Duration,
) -> Result<(), ()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let observed = ring.read_used_idx(mem);
        if observed == target
            || observed.wrapping_sub(target) <= u16::from(QUEUE_SIZE)
                && observed != ring.last_used_idx
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
    Err(())
}

enum RingChoice {
    Rx,
    Tx,
}

fn prepublish_rx_descriptors(mem: &SharedMem, rx: &mut RingPair) {
    for i in 0..TOTAL_BUFFERS {
        let slot = u16::try_from(i).expect("queue size fits u16");
        let buf_addr = rx.buffer_addr(slot);
        rx.write_descriptor(mem, slot, buf_addr, BUFFER_SIZE as u32, VRING_DESC_F_WRITE);
        let entry_off = rx.avail_ring + 4 + u64::from(slot) * 2;
        unsafe { mem.write_u16_le(entry_off, slot) };
    }
    rx.avail_idx = QUEUE_SIZE;
    fence(Ordering::SeqCst);
    unsafe { mem.write_u16_le(rx.avail_ring + 2, rx.avail_idx) };
    fence(Ordering::SeqCst);
}

fn connect_with_retries(path: &Path, total: Duration) -> UnixStream {
    let deadline = Instant::now() + total;
    let mut last_error: Option<std::io::Error> = None;
    while Instant::now() < deadline {
        match UnixStream::connect(path) {
            Ok(stream) => return stream,
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    panic!(
        "could not connect to vhost-user socket {} within {:?}: {:?}",
        path.display(),
        total,
        last_error,
    );
}

fn assert_features_present(features: u64) {
    let required = [
        ("VIRTIO_F_VERSION_1", VIRTIO_F_VERSION_1_BIT),
        ("VIRTIO_NET_F_MAC", VIRTIO_NET_F_MAC_BIT),
        ("VIRTIO_NET_F_MTU", VIRTIO_NET_F_MTU_BIT),
        ("VIRTIO_NET_F_MRG_RXBUF", VIRTIO_NET_F_MRG_RXBUF_BIT),
        ("VIRTIO_NET_F_STATUS", VIRTIO_NET_F_STATUS_BIT),
        ("VIRTIO_RING_F_EVENT_IDX", VIRTIO_RING_F_EVENT_IDX_BIT),
    ];
    for (name, bit) in required {
        assert!(
            features & (1u64 << bit) != 0,
            "daemon must advertise {name} (bit {bit}) but features bitmap is {features:#x}"
        );
    }
    let forbidden = [
        ("VIRTIO_NET_F_CSUM", 0u32),
        ("VIRTIO_NET_F_GUEST_CSUM", 1u32),
        ("VIRTIO_NET_F_GUEST_TSO4", 7u32),
        ("VIRTIO_NET_F_GUEST_TSO6", 8u32),
        ("VIRTIO_NET_F_GUEST_UFO", 10u32),
        ("VIRTIO_NET_F_HOST_TSO4", 11u32),
        ("VIRTIO_NET_F_HOST_TSO6", 12u32),
        ("VIRTIO_NET_F_HOST_UFO", 14u32),
        ("VIRTIO_NET_F_CTRL_VQ", 17u32),
        ("VIRTIO_NET_F_MQ", 22u32),
    ];
    for (name, bit) in forbidden {
        assert_eq!(
            features & (1u64 << bit),
            0,
            "daemon must NOT advertise offload feature {name} (bit {bit})"
        );
    }
}

fn resolve_daemon_binary() -> PathBuf {
    if let Ok(custom) = std::env::var("VHOST_USER_WIREGUARD_BIN") {
        return PathBuf::from(custom);
    }
    let candidate = PathBuf::from(DAEMON_BIN);
    if candidate.exists() {
        return candidate;
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let alt = PathBuf::from(target_dir).join("release/vhost-user-wireguard");
        if alt.exists() {
            return alt;
        }
    }
    candidate
}

pub fn drain_stderr(child: &mut Child) -> String {
    let Some(mut handle) = child.stderr.take() else {
        return String::new();
    };
    let mut out = String::new();
    let _ = handle.read_to_string(&mut out);
    out
}
