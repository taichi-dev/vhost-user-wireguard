// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::Ipv4Addr;

use etherparse::{
    ArpHardwareId, ArpOperation, ArpPacket, ArpPacketSlice, EtherType, Ethernet2Slice,
    PacketBuilder,
};

pub fn handle_arp_request(
    frame: &[u8],
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    vm_mac: [u8; 6],
) -> Option<Vec<u8>> {
    let eth = Ethernet2Slice::from_slice_without_fcs(frame).ok()?;
    if eth.ether_type() != EtherType::ARP {
        return None;
    }

    let arp = ArpPacketSlice::from_slice(eth.payload_slice()).ok()?;
    if arp.operation() != ArpOperation::REQUEST {
        return None;
    }

    let target_ip_octets: [u8; 4] = arp.target_protocol_addr().try_into().ok()?;
    if Ipv4Addr::from(target_ip_octets) != gateway_ip {
        return None;
    }

    let sender_mac: [u8; 6] = arp.sender_hw_addr().try_into().ok()?;
    let sender_ip_octets: [u8; 4] = arp.sender_protocol_addr().try_into().ok()?;

    let reply = ArpPacket::new(
        ArpHardwareId::ETHERNET,
        EtherType::IPV4,
        ArpOperation::REPLY,
        &gateway_mac,
        &gateway_ip.octets(),
        &sender_mac,
        &sender_ip_octets,
    )
    .ok()?;

    let builder = PacketBuilder::ethernet2(gateway_mac, vm_mac).arp(reply);
    let mut buf = Vec::with_capacity(builder.size());
    builder.write(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use etherparse::{ArpEthIpv4Packet, ArpOperation, EtherType, PacketBuilder};

    use super::*;

    fn build_arp_request_frame(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let arp = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &sender_mac,
            &sender_ip.octets(),
            &[0u8; 6],
            &target_ip.octets(),
        )
        .unwrap();
        let builder = PacketBuilder::ethernet2([0xff; 6], sender_mac).arp(arp);
        let mut buf = Vec::with_capacity(builder.size());
        builder.write(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_arp_request_for_gateway_returns_reply() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let frame = build_arp_request_frame(vm_mac, vm_ip, gateway_ip);
        let reply = handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac).unwrap();

        let eth = Ethernet2Slice::from_slice_without_fcs(&reply).unwrap();
        assert_eq!(eth.destination(), vm_mac);
        assert_eq!(eth.source(), gateway_mac);
        assert_eq!(eth.ether_type(), EtherType::ARP);

        let arp_slice = ArpPacketSlice::from_slice(eth.payload_slice()).unwrap();
        let arp_eth: ArpEthIpv4Packet = arp_slice.to_packet().try_into().unwrap();
        assert_eq!(arp_eth.operation, ArpOperation::REPLY);
        assert_eq!(arp_eth.sender_mac, gateway_mac);
        assert_eq!(arp_eth.sender_ipv4_addr(), gateway_ip);
        assert_eq!(arp_eth.target_mac, vm_mac);
        assert_eq!(arp_eth.target_ipv4_addr(), vm_ip);
    }

    #[test]
    fn test_arp_request_for_other_ip_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let other_ip = Ipv4Addr::new(10, 0, 0, 100);

        let frame = build_arp_request_frame(vm_mac, vm_ip, other_ip);
        assert!(handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac).is_none());
    }

    #[test]
    fn test_arp_reply_not_request_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let vm_ip = Ipv4Addr::new(10, 0, 0, 2);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let arp_reply = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REPLY,
            &gateway_mac,
            &gateway_ip.octets(),
            &vm_mac,
            &vm_ip.octets(),
        )
        .unwrap();
        let builder = PacketBuilder::ethernet2([0xff; 6], vm_mac).arp(arp_reply);
        let mut frame = Vec::with_capacity(builder.size());
        builder.write(&mut frame).unwrap();

        assert!(handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac).is_none());
    }

    #[test]
    fn test_non_arp_ethertype_returns_none() {
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);

        let builder = PacketBuilder::ethernet2(vm_mac, [0xff; 6])
            .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(1024, 80);
        let payload = [0u8; 4];
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, &payload).unwrap();

        assert!(handle_arp_request(&frame, gateway_ip, gateway_mac, vm_mac).is_none());
    }

    #[test]
    fn test_malformed_eth_frame_returns_none() {
        let gateway_ip = Ipv4Addr::new(10, 0, 0, 1);
        let gateway_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let vm_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        assert!(handle_arp_request(&[0u8; 13], gateway_ip, gateway_mac, vm_mac).is_none());
    }
}
