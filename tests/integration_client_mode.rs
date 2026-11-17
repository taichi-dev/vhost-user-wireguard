// SPDX-License-Identifier: MIT OR Apache-2.0

// Integration tests use panic-on-failure as the natural assertion idiom;
// suppress the production-only restriction lints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions
)]

//! `vhost_user.mode = "client"`: the frontend binds the socket and the daemon
//! connects to it (libvirt/QEMU `mode='server'`). This inverts the socket
//! direction, which is what lets the daemon be restarted — or the frontend be
//! restarted — without the guest losing its virtio-net device.
//!
//! These tests drive the real binary through `tests/common`: we play the
//! frontend (we bind, we `accept`), the daemon connects and negotiates.

mod common;

use std::time::Duration;

use common::{GATEWAY_IP, GATEWAY_MAC, MockVhostUserMaster, VM_IP, VM_MAC, build_arp_request};

/// Send one ARP request through the TX queue and assert the daemon answers it
/// on the RX queue. Used as an end-to-end proof that the datapath — not just
/// the vhost-user control channel — is alive.
fn assert_arp_roundtrip(master: &mut MockVhostUserMaster, label: &str) {
    let request = build_arp_request(VM_IP, VM_MAC, GATEWAY_IP);
    master.write_tx_frame(&request);

    let reply = master
        .read_rx_frame()
        .unwrap_or_else(|| panic!("{label}: daemon never produced an ARP reply"));

    assert!(
        reply.len() >= 14 + 28,
        "{label}: ARP reply too short: {} bytes",
        reply.len()
    );
    assert_eq!(
        &reply[0..6],
        &VM_MAC,
        "{label}: Ethernet dst must be VM MAC"
    );
    assert_eq!(
        &reply[6..12],
        &GATEWAY_MAC,
        "{label}: Ethernet src must be the synthetic gateway MAC"
    );
    assert_eq!(
        u16::from_be_bytes([reply[12], reply[13]]),
        0x0806,
        "{label}: ethertype must be ARP"
    );
    assert_eq!(
        u16::from_be_bytes([reply[14 + 6], reply[14 + 7]]),
        2,
        "{label}: ARP opcode must be REPLY (2)"
    );
}

/// The daemon must connect to a socket we already bound, negotiate, and carry
/// traffic. This is the whole point of the client path.
#[test]
fn client_mode_connects_and_serves_traffic() {
    let mut master = MockVhostUserMaster::spawn_client();
    assert_arp_roundtrip(&mut master, "client mode");
    drop(master);
}

/// The frontend may not be up yet when the daemon starts: the socket appears
/// late, so the daemon's first connect attempts fail. It must retry instead of
/// exiting (which would leave the guest with a dead NIC).
#[test]
fn client_mode_retries_until_frontend_listens() {
    let mut master =
        MockVhostUserMaster::spawn_client_with_delayed_listener(Duration::from_secs(1));
    // Reaching this point means the daemon retried through ~4 failed attempts
    // and the negotiation succeeded once the listener appeared.
    assert_arp_roundtrip(&mut master, "delayed listener");
    drop(master);
}

/// The frontend restarts (listener gone for a while, then back): the daemon
/// must reconnect on its own and serve traffic again, without a restart.
#[test]
fn client_mode_reconnects_after_frontend_restart() {
    let mut master = MockVhostUserMaster::spawn_client();
    assert_arp_roundtrip(&mut master, "before frontend restart");

    master.restart_frontend_listener();

    assert_arp_roundtrip(&mut master, "after frontend restart");
    drop(master);
}
