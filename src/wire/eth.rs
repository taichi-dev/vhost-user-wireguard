// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct EthFrame<'a> {
    raw: &'a [u8],
}

impl<'a> EthFrame<'a> {
    pub fn new(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 14 {
            return None;
        }
        Some(Self { raw })
    }

    pub fn dst_mac(&self) -> [u8; 6] {
        // SAFETY: slice is exactly 6 bytes; ::new enforces raw.len() >= 14
        self.raw[0..6].try_into().unwrap()
    }

    pub fn src_mac(&self) -> [u8; 6] {
        // SAFETY: slice is exactly 6 bytes; ::new enforces raw.len() >= 14
        self.raw[6..12].try_into().unwrap()
    }

    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.raw[12], self.raw[13]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw[14..]
    }
}

pub fn build_eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_too_short() {
        assert!(EthFrame::new(&[0u8; 13]).is_none());
    }

    #[test]
    fn test_fields() {
        let mut raw = [0u8; 14];
        raw[0..6].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        raw[6..12].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        raw[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let frame = EthFrame::new(&raw).unwrap();
        assert_eq!(frame.dst_mac(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(frame.src_mac(), [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        assert_eq!(frame.ethertype(), 0x0800);
        assert_eq!(frame.payload(), &[] as &[u8]);
    }

    #[test]
    fn test_build_round_trip() {
        let dst = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let src = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02];
        let ethertype = 0x0806u16;
        let payload = b"hello";
        let raw = build_eth_frame(dst, src, ethertype, payload);
        let frame = EthFrame::new(&raw).unwrap();
        assert_eq!(frame.dst_mac(), dst);
        assert_eq!(frame.src_mac(), src);
        assert_eq!(frame.ethertype(), ethertype);
        assert_eq!(frame.payload(), payload);
    }
}
