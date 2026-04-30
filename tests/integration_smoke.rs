// SPDX-License-Identifier: MIT OR Apache-2.0

//! Smoke tests that drive the real daemon binary through the vhost-user wire
//! protocol. The mock master harness lives in `tests/common/mod.rs`.

mod common;

use common::{
    GATEWAY_IP, MockVhostUserMaster, VM_IP, VM_MAC, build_arp_request,
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
