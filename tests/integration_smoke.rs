// SPDX-License-Identifier: MIT OR Apache-2.0

//! Smoke tests that drive the real daemon binary through the vhost-user wire
//! protocol. The mock master harness lives in `tests/common/mod.rs`.

mod common;

use common::MockVhostUserMaster;

#[test]
fn harness_self_test() {
    let master = MockVhostUserMaster::spawn();

    let virtio = master.acked_virtio_features;

    assert!(
        virtio & (1u64 << common::VIRTIO_F_VERSION_1_BIT) != 0,
        "VIRTIO_F_VERSION_1 must be acknowledged"
    );
    assert!(
        virtio & (1u64 << common::VIRTIO_NET_F_MAC_BIT) != 0,
        "VIRTIO_NET_F_MAC must be acknowledged"
    );
    assert!(
        virtio & (1u64 << common::VIRTIO_NET_F_MTU_BIT) != 0,
        "VIRTIO_NET_F_MTU must be acknowledged"
    );
    assert!(
        virtio & (1u64 << common::VIRTIO_NET_F_MRG_RXBUF_BIT) != 0,
        "VIRTIO_NET_F_MRG_RXBUF must be acknowledged"
    );
    assert!(
        virtio & (1u64 << common::VIRTIO_NET_F_STATUS_BIT) != 0,
        "VIRTIO_NET_F_STATUS must be acknowledged"
    );
    assert!(
        virtio & (1u64 << common::VIRTIO_RING_F_EVENT_IDX_BIT) != 0,
        "VIRTIO_RING_F_EVENT_IDX must be acknowledged"
    );

    drop(master);
}
