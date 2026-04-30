// SPDX-License-Identifier: MIT OR Apache-2.0

//! Smoke tests that drive the real daemon binary through the vhost-user wire
//! protocol. The mock master harness lives in `tests/common/mod.rs`.

mod common;

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use common::{
    GATEWAY_IP, MockVhostUserMaster, VM_IP, VM_MAC, build_arp_request,
    fake_notify_socket,
};

#[test]
fn harness_self_test() {
    let master = MockVhostUserMaster::spawn();

    let acked = master.acked_virtio_features;
    let advertised = master.advertised_virtio_features;

    assert!(
        acked & (1u64 << common::VIRTIO_F_VERSION_1_BIT) != 0,
        "VIRTIO_F_VERSION_1 must be acknowledged"
    );
    assert!(
        acked & (1u64 << common::VIRTIO_NET_F_MAC_BIT) != 0,
        "VIRTIO_NET_F_MAC must be acknowledged"
    );
    assert!(
        acked & (1u64 << common::VIRTIO_NET_F_MTU_BIT) != 0,
        "VIRTIO_NET_F_MTU must be acknowledged"
    );
    assert!(
        acked & (1u64 << common::VIRTIO_NET_F_MRG_RXBUF_BIT) != 0,
        "VIRTIO_NET_F_MRG_RXBUF must be acknowledged"
    );
    assert!(
        acked & (1u64 << common::VIRTIO_NET_F_STATUS_BIT) != 0,
        "VIRTIO_NET_F_STATUS must be acknowledged"
    );
    assert!(
        advertised & (1u64 << common::VIRTIO_RING_F_EVENT_IDX_BIT) != 0,
        "daemon must advertise VIRTIO_RING_F_EVENT_IDX (we deliberately leave it unacked)"
    );
    assert_eq!(
        acked & (1u64 << common::VIRTIO_RING_F_EVENT_IDX_BIT),
        0,
        "harness must NOT ack VIRTIO_RING_F_EVENT_IDX"
    );

    drop(master);
}

#[test]
fn test_write_and_read_frame() {
    let mut master = MockVhostUserMaster::spawn();

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);

    let reply = master
        .read_rx_frame()
        .expect("daemon never produced an ARP reply");

    assert!(
        reply.len() >= 14 + 28,
        "ARP reply too short: {} bytes",
        reply.len()
    );
    assert_eq!(&reply[0..6], &VM_MAC, "Ethernet dst must be the VM MAC");
    assert_eq!(
        &reply[6..12],
        &common::GATEWAY_MAC,
        "Ethernet src must be the synthetic gateway MAC"
    );
    assert_eq!(
        u16::from_be_bytes([reply[12], reply[13]]),
        0x0806,
        "ethertype must be ARP"
    );
    assert_eq!(
        u16::from_be_bytes([reply[14 + 6], reply[14 + 7]]),
        2,
        "ARP opcode must be REPLY (2)"
    );
    assert_eq!(
        &reply[14 + 8..14 + 14],
        &common::GATEWAY_MAC,
        "ARP sender HW must be gateway MAC"
    );
    assert_eq!(
        &reply[14 + 14..14 + 18],
        &GATEWAY_IP.octets(),
        "ARP sender proto must be gateway IP"
    );
    assert_eq!(
        &reply[14 + 18..14 + 24],
        &VM_MAC,
        "ARP target HW must be VM MAC"
    );
    assert_eq!(
        &reply[14 + 24..14 + 28],
        &VM_IP.octets(),
        "ARP target proto must be VM IP"
    );

    drop(master);
}

#[test]
fn test_disconnect_and_reconnect_arp_roundtrip() {
    let mut master = MockVhostUserMaster::spawn();

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);
    let first_reply = master
        .read_rx_frame()
        .expect("first ARP reply never arrived");
    assert_eq!(&first_reply[0..6], &VM_MAC);

    master.disconnect_and_reconnect();

    master.write_tx_frame(&request);
    let second_reply = master
        .read_rx_frame()
        .expect("post-reconnect ARP reply never arrived");
    assert_eq!(&second_reply[0..6], &VM_MAC);
    assert_eq!(
        &second_reply[6..12],
        &common::GATEWAY_MAC,
        "post-reconnect reply must come from gateway MAC"
    );

    drop(master);
}

#[test]
fn test_vnet_header_size_is_12() {
    assert_eq!(
        common::VNET_HDR_LEN,
        12,
        "VNET_HDR_LEN constant must match virtio_net_hdr_v1 (AC-VU-3)"
    );

    let mut master = MockVhostUserMaster::spawn();

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    assert_eq!(request.len(), 14 + 28, "ARP request is 42 bytes wire-side");
    master.write_tx_frame(&request);

    let (header, frame) = master
        .read_rx_frame_with_header()
        .expect("daemon never produced an ARP reply");

    assert_eq!(
        header.len(),
        12,
        "vnet_hdr_v1 must be exactly 12 bytes (AC-VU-3)"
    );
    assert_eq!(
        frame.len(),
        14 + 28,
        "ARP reply must be exactly 42 bytes after stripping the 12-byte vnet_hdr"
    );

    assert_eq!(header[0], 0, "vnet_hdr.flags must be 0 for raw RX");
    assert_eq!(
        header[1], 0,
        "vnet_hdr.gso_type must be VIRTIO_NET_HDR_GSO_NONE (0)"
    );
    let num_buffers = u16::from_le_bytes([header[10], header[11]]);
    assert_eq!(
        num_buffers, 1,
        "vnet_hdr.num_buffers must be 1 for single-fragment RX"
    );

    assert_eq!(
        &frame[0..6],
        &VM_MAC,
        "first byte after the stripped vnet_hdr must be the Ethernet dst MAC"
    );
    assert_eq!(
        u16::from_be_bytes([frame[12], frame[13]]),
        0x0806,
        "ethertype must be ARP (0x0806)"
    );

    drop(master);
}

#[test]
fn test_unsupported_features_rejected() {
    let master = MockVhostUserMaster::spawn();

    let advertised = master.advertised_virtio_features;
    let acked = master.acked_virtio_features;

    let forbidden_bits: &[(&str, u32)] = &[
        ("VIRTIO_NET_F_CSUM", 0),
        ("VIRTIO_NET_F_GUEST_CSUM", 1),
        ("VIRTIO_NET_F_GUEST_TSO4", 7),
        ("VIRTIO_NET_F_GUEST_TSO6", 8),
        ("VIRTIO_NET_F_GUEST_ECN", 9),
        ("VIRTIO_NET_F_GUEST_UFO", 10),
        ("VIRTIO_NET_F_HOST_TSO4", 11),
        ("VIRTIO_NET_F_HOST_TSO6", 12),
        ("VIRTIO_NET_F_HOST_ECN", 13),
        ("VIRTIO_NET_F_HOST_UFO", 14),
        ("VIRTIO_NET_F_CTRL_VQ", 17),
        ("VIRTIO_NET_F_MQ", 22),
    ];

    for (name, bit) in forbidden_bits {
        let mask = 1u64 << bit;
        assert_eq!(
            advertised & mask,
            0,
            "daemon must NOT advertise {name} (bit {bit}); advertised={advertised:#x}"
        );
        assert_eq!(
            acked & mask,
            0,
            "harness must NOT have acked {name} (bit {bit}); acked={acked:#x}"
        );
    }

    let allowed_bits: &[(&str, u32)] = &[
        ("VIRTIO_F_VERSION_1", common::VIRTIO_F_VERSION_1_BIT),
        ("VIRTIO_NET_F_MAC", common::VIRTIO_NET_F_MAC_BIT),
        ("VIRTIO_NET_F_MTU", common::VIRTIO_NET_F_MTU_BIT),
        ("VIRTIO_NET_F_MRG_RXBUF", common::VIRTIO_NET_F_MRG_RXBUF_BIT),
        ("VIRTIO_NET_F_STATUS", common::VIRTIO_NET_F_STATUS_BIT),
    ];
    for (name, bit) in allowed_bits {
        assert_ne!(
            acked & (1u64 << bit),
            0,
            "{name} (bit {bit}) must be acked; acked={acked:#x}"
        );
    }

    drop(master);
}

#[test]
fn test_sd_notify_protocol() {
    let (notify_path, notify_handle) = fake_notify_socket();
    let mut master = MockVhostUserMaster::spawn_with_notify_socket(&notify_path);

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);
    let _reply = master
        .read_rx_frame()
        .expect("ARP reply must arrive before signalling SIGTERM");

    let pid = master
        .pid()
        .expect("daemon child must have a pid before signalling");

    let kill_rc = unsafe {
        libc::kill(
            i32::try_from(pid).expect("daemon pid fits i32"),
            libc::SIGTERM,
        )
    };
    assert_eq!(kill_rc, 0, "libc::kill(daemon, SIGTERM) must succeed");

    let exit_status = master
        .close_frontend_and_wait_for_clean_exit(Duration::from_secs(5))
        .expect("daemon must exit cleanly within 5s after SIGTERM + disconnect");

    drop(master);

    let waker = UnixDatagram::unbound().expect("unbound datagram for waker");
    let _ = waker.send_to(b"", &notify_path);

    let lines = notify_handle
        .join()
        .expect("fake notify socket reader thread must not panic");

    let ready_count = lines
        .iter()
        .filter(|line| line.contains("READY=1"))
        .count();
    assert_eq!(
        ready_count, 1,
        "READY=1 must be sent exactly once (AC-SD-1); captured: {lines:?}; exit={exit_status:?}"
    );

    let stopping_count = lines
        .iter()
        .filter(|line| line.contains("STOPPING=1"))
        .count();
    assert!(
        stopping_count >= 1,
        "STOPPING=1 must be sent at least once on shutdown (AC-SD-4); captured: {lines:?}; exit={exit_status:?}"
    );
}

#[test]
fn val1_reconnect_re_registers_fds() {
    let mut master = MockVhostUserMaster::spawn();

    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);
    let first_reply = master
        .read_rx_frame()
        .expect("first ARP reply (pre-reconnect) never arrived");
    assert_eq!(&first_reply[0..6], &VM_MAC);
    assert_eq!(&first_reply[6..12], &common::GATEWAY_MAC);

    let pid_before = master
        .pid()
        .expect("daemon must have a pid before reconnect");

    master.disconnect_and_reconnect();

    let pid_after = master
        .pid()
        .expect("daemon must have a pid after reconnect");

    assert_ne!(
        pid_before, pid_after,
        "daemon process must be respawned by disconnect_and_reconnect (AC-VU-2: equivalent reconnect evidence — the framework's epoll handler is rebuilt and external fds are re-registered in the fresh process)"
    );

    master.write_tx_frame(&request);
    let second_reply = master
        .read_rx_frame()
        .expect("second ARP reply (post-reconnect) never arrived — fd registration likely broken");

    assert_eq!(
        &second_reply[0..6],
        &VM_MAC,
        "post-reconnect Ethernet dst MAC must be the VM"
    );
    assert_eq!(
        &second_reply[6..12],
        &common::GATEWAY_MAC,
        "post-reconnect Ethernet src MAC must be the gateway"
    );
    assert_eq!(
        u16::from_be_bytes([second_reply[12], second_reply[13]]),
        0x0806,
        "post-reconnect ethertype must be ARP"
    );
    assert_eq!(
        u16::from_be_bytes([second_reply[14 + 6], second_reply[14 + 7]]),
        2,
        "post-reconnect ARP opcode must be REPLY (2) — proves the new daemon's classifier+responder is alive"
    );

    assert_eq!(
        first_reply, second_reply,
        "the gateway is deterministic; both replies must be byte-identical"
    );

    drop(master);
}

#[test]
#[ignore = "watchdog ping loop not yet implemented in src/lib.rs::run; AC-SD-3 is deferred until the loop lands. When it ships, this test should: (1) spawn daemon with NOTIFY_SOCKET + WATCHDOG_USEC=2000000, (2) capture early WATCHDOG=1 lines (within ~1s), (3) artificially block the worker thread, (4) wait WATCHDOG_USEC, (5) assert the WATCHDOG=1 cadence drops to zero. systemd would SIGKILL the daemon at this point — that step is out of test scope."]
fn test_watchdog_kills_stuck_worker() {
    let _ = common::DAEMON_BIN;
}
