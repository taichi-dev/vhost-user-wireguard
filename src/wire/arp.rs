// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct ArpPacket<'a> {
    raw: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn new(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 28 {
            return None;
        }
        Some(Self { raw })
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes([self.raw[6], self.raw[7]])
    }

    pub fn sender_hw_addr(&self) -> [u8; 6] {
        // SAFETY: slice is exactly 6 bytes; ::new enforces raw.len() >= 28
        self.raw[8..14].try_into().unwrap()
    }

    pub fn sender_proto_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(self.raw[14], self.raw[15], self.raw[16], self.raw[17])
    }

    pub fn target_hw_addr(&self) -> [u8; 6] {
        // SAFETY: slice is exactly 6 bytes; ::new enforces raw.len() >= 28
        self.raw[18..24].try_into().unwrap()
    }

    pub fn target_proto_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(self.raw[24], self.raw[25], self.raw[26], self.raw[27])
    }
}

pub fn build_arp_reply(
    sender_mac: [u8; 6],
    sender_ip: std::net::Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: std::net::Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0..2].copy_from_slice(&1u16.to_be_bytes());
    pkt[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[4] = 6;
    pkt[5] = 4;
    pkt[6..8].copy_from_slice(&2u16.to_be_bytes());
    pkt[8..14].copy_from_slice(&sender_mac);
    pkt[14..18].copy_from_slice(&sender_ip.octets());
    pkt[18..24].copy_from_slice(&target_mac);
    pkt[24..28].copy_from_slice(&target_ip.octets());
    pkt
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_new_too_short() {
        assert!(ArpPacket::new(&[0u8; 27]).is_none());
    }

    #[test]
    fn test_fields() {
        let mut raw = [0u8; 28];
        raw[6..8].copy_from_slice(&1u16.to_be_bytes());
        raw[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        raw[14..18].copy_from_slice(&[10, 0, 0, 1]);
        raw[18..24].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        raw[24..28].copy_from_slice(&[192, 168, 1, 2]);
        let pkt = ArpPacket::new(&raw).unwrap();
        assert_eq!(pkt.operation(), 1);
        assert_eq!(pkt.sender_hw_addr(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(pkt.sender_proto_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.target_hw_addr(), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(pkt.target_proto_addr(), Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn test_build_arp_reply() {
        let sender_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let sender_ip = Ipv4Addr::new(10, 0, 0, 1);
        let target_mac = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02];
        let target_ip = Ipv4Addr::new(10, 0, 0, 2);
        let raw = build_arp_reply(sender_mac, sender_ip, target_mac, target_ip);
        let pkt = ArpPacket::new(&raw).unwrap();
        assert_eq!(pkt.operation(), 2);
        assert_eq!(pkt.sender_hw_addr(), sender_mac);
        assert_eq!(pkt.sender_proto_addr(), sender_ip);
        assert_eq!(pkt.target_hw_addr(), target_mac);
        assert_eq!(pkt.target_proto_addr(), target_ip);
    }
}
