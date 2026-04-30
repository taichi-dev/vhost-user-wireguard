// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mock vhost-user master test harness for integration tests.
//!
//! [`MockVhostUserMaster`] drives a child instance of the
//! `vhost-user-wireguard` daemon via the vhost-user wire protocol. It is
//! intentionally minimal: this module is the FOUNDATION on which the
//! integration smoke tests build, so the surface area exposed here is the
//! union of every helper required by `tests/integration_smoke.rs`.
//!
//! Scope of THIS unit (T30 / first atomic unit):
//! - Spawn the daemon binary as a child process pointed at a temp-config
//!   and a per-test Unix socket.
//! - Connect a [`vhost::vhost_user::Frontend`] to the daemon and complete
//!   feature/protocol-feature negotiation (the canonical first messages a
//!   real frontend like cloud-hypervisor / qemu would send).
//! - Tear the connection down cleanly and reap the child on `Drop`.
//!
//! Scope DEFERRED to a follow-up unit (T31+):
//! - SET_MEM_TABLE with a memfd-backed shared region.
//! - Manual descriptor-table / avail-ring / used-ring layout in shared mem.
//! - `write_tx_frame`/`read_rx_frame` against those rings.
//! - `disconnect_and_reconnect` data-plane round-trip.
//!
//! The deferred entry points are present as `unimplemented!()` stubs with
//! TODO comments so the API surface is stable for the next iteration.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use vhost::VhostBackend;
use vhost::vhost_user::Frontend;
use vhost::vhost_user::VhostUserFrontend;
use vhost::vhost_user::message::{
    VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};

/// Path to the daemon binary produced by `cargo build --release`.
///
/// The integration tests require the binary to exist before running.
pub const DAEMON_BIN: &str = "target/release/vhost-user-wireguard";

/// Default queue size used by every test.
pub const QUEUE_SIZE: u16 = 256;

/// Number of virtqueues the daemon exposes (RX + TX).
pub const NUM_QUEUES: u32 = 2;

/// Bit indices we expect the daemon to advertise.
///
/// Kept in sync with `src/datapath/mod.rs::WgNetBackend::features`.
pub const VIRTIO_F_VERSION_1_BIT: u32 = 32;
pub const VIRTIO_NET_F_MAC_BIT: u32 = 5;
pub const VIRTIO_NET_F_MTU_BIT: u32 = 3;
pub const VIRTIO_NET_F_MRG_RXBUF_BIT: u32 = 15;
pub const VIRTIO_NET_F_STATUS_BIT: u32 = 16;
pub const VIRTIO_RING_F_EVENT_IDX_BIT: u32 = 29;

/// Source MAC the harness pretends to be (the synthetic VM's NIC).
pub const VM_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x01];

/// Gateway MAC hardcoded in the daemon (`src/lib.rs::GATEWAY_MAC`).
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Subnet gateway used in the canned config: `10.42.0.1`.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);

/// VM IP in the canned config: `10.42.0.2`.
pub const VM_IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 2);

/// Shared monotonic counter used to allocate non-overlapping WireGuard listen
/// ports across concurrent test invocations. Starts well above the IANA
/// ephemeral range.
static PORT_ALLOCATOR: AtomicU16 = AtomicU16::new(51820);

/// Allocate a fresh listen port for one test run. Wraps around so we never
/// hand back zero (zero is rejected by `config::validate`).
pub fn alloc_listen_port() -> u16 {
    let raw = PORT_ALLOCATOR.fetch_add(1, Ordering::Relaxed);
    if raw == 0 { 51820 } else { raw }
}

/// Build a base64 encoding of an arbitrary 32-byte WireGuard secret.
///
/// The bytes do not need to be cryptographically random — we only need a
/// well-formed key the daemon's parser accepts.
pub fn fake_wg_key(seed: u8) -> String {
    let bytes = [seed; 32];
    BASE64.encode(bytes)
}

/// Default TOML template understood by the daemon. Placeholders are
/// `{name}`-style; [`write_temp_config`] interpolates them.
///
/// The template intentionally uses a single-IP DHCP pool (10.42.0.2 .. 10.42.0.2)
/// so the daemon only ever leases the static VM IP.
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

/// Substitute every `{key}` placeholder in `template` with `fields[key]` and
/// write the result to a fresh temp file. Returns the path; the file is
/// retained until the returned [`tempfile::TempPath`] is dropped.
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

/// Build a default config tied to the listen port and vhost-user socket
/// passed in. Returns the temp path of the written config.
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

/// Block until `path` exists or `deadline` elapses. Returns true if the path
/// appeared, false on timeout.
fn wait_for_path(path: &Path, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Set up an `AF_UNIX` datagram socket and a reader thread that captures
/// every newline-separated chunk written to it. Returns the socket path
/// (suitable for the `NOTIFY_SOCKET` env var) and a join handle whose
/// `Vec<String>` payload contains every captured line in arrival order.
///
/// The reader thread terminates as soon as the socket is closed. Callers
/// must ensure the socket file is removed (via [`tempfile::TempDir`]) so
/// the thread can observe EOF; otherwise the join blocks forever.
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

/// Build a complete Ethernet+IPv4+UDP+DHCPv4 DISCOVER frame with the given
/// client MAC address. Used by integration tests to elicit an OFFER from the
/// daemon's DHCP server.
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

/// One's-complement Internet checksum over an IPv4 header.
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

/// Build an Ethernet+ARP request frame asking for `tpa`'s MAC. `spa`/`sha`
/// are the requester's IPv4/MAC, sent as the ARP "sender" tuple.
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

/// State shared between the live harness and its [`Drop`] impl so the child
/// is reaped exactly once.
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

/// Live, connected master driver.
///
/// One instance corresponds to one daemon process and one socket connection.
pub struct MockVhostUserMaster {
    daemon: DaemonChild,
    frontend: Option<Frontend>,
    socket_path: PathBuf,
    config_path: tempfile::TempPath,
    /// Working directory tempdir kept alive for socket / lease files.
    _work_dir: tempfile::TempDir,
    /// Acked virtio features after the latest negotiation.
    pub acked_virtio_features: u64,
    /// Acked protocol features after the latest negotiation.
    pub acked_protocol_features: VhostUserProtocolFeatures,
}

impl MockVhostUserMaster {
    /// Spawn the daemon as a child process and connect a frontend to its
    /// vhost-user socket. Performs the canonical owner/feature/protocol
    /// negotiation handshake before returning.
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
        command
            .arg("--config")
            .arg(cfg_arg)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.env_remove("NOTIFY_SOCKET");
        command.env("RUST_LOG", "off");

        let child = command.spawn().unwrap_or_else(|e| {
            panic!(
                "failed to spawn daemon binary at {bin:?}: {e}. Did you run `cargo build --release`?"
            )
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        if !wait_for_path(&socket_path, deadline) {
            let mut daemon = DaemonChild { child: Some(child) };
            daemon.shutdown();
            panic!(
                "daemon never created its vhost-user socket at {} within 5s",
                socket_path.display()
            );
        }

        let mut harness = Self {
            daemon: DaemonChild { child: Some(child) },
            frontend: None,
            socket_path,
            config_path,
            _work_dir: work_dir,
            acked_virtio_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
        };
        harness.connect_and_negotiate();
        harness
    }

    /// Tear down the existing connection (if any) and re-open it, performing
    /// feature negotiation again.
    ///
    /// TODO(T31+): once the data-plane harness is implemented this must also
    /// re-issue SET_MEM_TABLE and re-arm every vring.
    pub fn disconnect_and_reconnect(&mut self) {
        self.frontend = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        if !wait_for_path(&self.socket_path, deadline) {
            panic!(
                "vhost-user socket vanished at {} during reconnect",
                self.socket_path.display()
            );
        }
        self.connect_and_negotiate();
    }

    fn connect_and_negotiate(&mut self) {
        let stream = connect_with_retries(&self.socket_path, Duration::from_secs(5));
        let mut frontend = Frontend::from_stream(stream, u64::from(NUM_QUEUES));
        frontend.set_owner().expect("set_owner");

        let advertised_virtio = frontend.get_features().expect("get_features");
        assert_features_present(advertised_virtio);
        frontend
            .set_features(advertised_virtio)
            .expect("set_features");
        self.acked_virtio_features = advertised_virtio;

        if advertised_virtio & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            let advertised_proto = frontend
                .get_protocol_features()
                .expect("get_protocol_features");
            let acked_proto = advertised_proto
                & (VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::REPLY_ACK);
            frontend
                .set_protocol_features(acked_proto)
                .expect("set_protocol_features");
            self.acked_protocol_features = acked_proto;
        } else {
            self.acked_protocol_features = VhostUserProtocolFeatures::empty();
        }

        self.frontend = Some(frontend);
    }

    /// Borrow the underlying frontend for tests that need to issue raw
    /// vhost-user requests beyond what the harness already wraps.
    pub fn frontend(&self) -> &Frontend {
        self.frontend
            .as_ref()
            .expect("frontend connected; call spawn() before frontend()")
    }

    /// Path of the daemon's vhost-user socket. Useful if a test wants to
    /// open a second connection.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Path of the rendered TOML configuration the daemon was launched with.
    pub fn config_path(&self) -> &Path {
        self.config_path.as_ref()
    }

    /// Inject a TX-direction Ethernet frame.
    ///
    /// TODO(T31+): backed by the SET_MEM_TABLE-managed shared memory ring
    /// pair. Currently a stub so the public API surface is stable.
    pub fn write_tx_frame(&mut self, _eth: &[u8]) {
        unimplemented!(
            "T30 first-unit harness only covers feature negotiation; \
             write_tx_frame is the next-unit deliverable"
        );
    }

    /// Read one RX-direction Ethernet frame, if available.
    ///
    /// TODO(T31+): backed by the SET_MEM_TABLE-managed shared memory ring
    /// pair. Currently a stub so the public API surface is stable.
    pub fn read_rx_frame(&mut self) -> Option<Vec<u8>> {
        unimplemented!(
            "T30 first-unit harness only covers feature negotiation; \
             read_rx_frame is the next-unit deliverable"
        );
    }
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

/// Locate the daemon binary. Honours `VHOST_USER_WIREGUARD_BIN` for callers
/// that want to test against a custom build.
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

/// Drain any pending stderr from a child process into a `String`. Useful for
/// post-mortem assertions when the daemon exits unexpectedly.
pub fn drain_stderr(child: &mut Child) -> String {
    let Some(mut handle) = child.stderr.take() else {
        return String::new();
    };
    let mut out = String::new();
    let _ = handle.read_to_string(&mut out);
    out
}
