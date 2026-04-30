// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct UdpPacket<'a> {
    raw: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn new(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }
        Some(Self { raw })
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]])
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.raw[4], self.raw[5]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw[8..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_too_short() {
        assert!(UdpPacket::new(&[0u8; 7]).is_none());
    }

    #[test]
    fn test_fields() {
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&51820u16.to_be_bytes());
        raw[2..4].copy_from_slice(&12345u16.to_be_bytes());
        raw[4..6].copy_from_slice(&8u16.to_be_bytes());
        let pkt = UdpPacket::new(&raw).unwrap();
        assert_eq!(pkt.src_port(), 51820);
        assert_eq!(pkt.dst_port(), 12345);
        assert_eq!(pkt.length(), 8);
    }

    #[test]
    fn test_payload() {
        let mut raw = vec![0u8; 8];
        raw[0..2].copy_from_slice(&1234u16.to_be_bytes());
        raw[2..4].copy_from_slice(&5678u16.to_be_bytes());
        raw[4..6].copy_from_slice(&13u16.to_be_bytes());
        raw.extend_from_slice(b"hello");
        let pkt = UdpPacket::new(&raw).unwrap();
        assert_eq!(pkt.payload(), b"hello");
    }
}
