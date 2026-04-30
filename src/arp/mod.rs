// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::wire::arp::{build_arp_reply, ArpPacket};
use crate::wire::eth::{build_eth_frame, EthFrame};
use std::net::Ipv4Addr;

const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_OPERATION_REQUEST: u16 = 1;

pub fn handle_arp_request(
    frame: &[u8],
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    vm_mac: [u8; 6],
) -> Option<Vec<u8>> {
    let eth = EthFrame::new(frame)?;

    if eth.ethertype() != ETHERTYPE_ARP {
        return None;
    }

    let arp = ArpPacket::new(eth.payload())?;

    if arp.operation() != ARP_OPERATION_REQUEST {
        return None;
    }

    if arp.target_proto_addr() != gateway_ip {
        return None;
    }

    let arp_reply = build_arp_reply(
        gateway_mac,
        gateway_ip,
        arp.sender_hw_addr(),
        arp.sender_proto_addr(),
    );

    Some(build_eth_frame(vm_mac, gateway_mac, ETHERTYPE_ARP, &arp_reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_raw_arp_request(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0..2].copy_from_slice(&1u16.to_be_bytes());
        pkt[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[4] = 6;
        pkt[5] = 4;
        pkt[6..8].copy_from_slice(&1u16.to_be_bytes());
        pkt[8..14].copy_from_slice(&sender_mac);
        pkt[14..18].copy_from_slice(&sender_ip.octets());
        pkt[24..28].copy_from_slice(&target_ip.octets());
        pkt
    }

    fn build_raw_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn test_arp_request_for_gateway_returns_reply() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let arp_pkt = build_raw_arp_request(vm_mac, vm_ip, gateway_ip);
        let frame = build_raw_eth_frame(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vm_mac,
            0x0806,
            &arp_pkt,
        );

        let result = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_some());

        let reply = result.unwrap();
        let eth = EthFrame::new(&reply).unwrap();
        assert_eq!(eth.dst_mac(), vm_mac);
        assert_eq!(eth.src_mac(), gateway_mac);
        assert_eq!(eth.ethertype(), 0x0806);

        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.operation(), 2);
        assert_eq!(arp.sender_hw_addr(), gateway_mac);
        assert_eq!(arp.sender_proto_addr(), gateway_ip);
        assert_eq!(arp.target_hw_addr(), vm_mac);
        assert_eq!(arp.target_proto_addr(), vm_ip);
    }

    #[test]
    fn test_arp_request_for_other_ip_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let other_ip = Ipv4Addr::new(10, 0, 0, 100);

        let arp_pkt = build_raw_arp_request(vm_mac, vm_ip, other_ip);
        let frame = build_raw_eth_frame(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vm_mac,
            0x0806,
            &arp_pkt,
        );

        let result = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_none());
    }

    #[test]
    fn test_arp_reply_not_request_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let arp_reply = build_arp_reply(gateway_mac, gateway_ip, vm_mac, vm_ip);
        let frame = build_raw_eth_frame(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vm_mac,
            0x0806,
            &arp_reply,
        );

        let result = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_none());
    }

    #[test]
    fn test_non_arp_ethertype_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let frame = build_raw_eth_frame(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vm_mac,
            0x0800,
            &[0x45, 0x00, 0x00, 0x14],
        );

        let result = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_none());
    }

    #[test]
    fn test_malformed_eth_frame_returns_none() {
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let result = handle_arp_request(&[0u8; 13], gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_none());
    }

    #[test]
    fn test_malformed_arp_packet_returns_none() {
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let frame = build_raw_eth_frame(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vm_mac,
            0x0806,
            &[0u8; 27],
        );

        let result = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac);
        assert!(result.is_none());
    }
}
