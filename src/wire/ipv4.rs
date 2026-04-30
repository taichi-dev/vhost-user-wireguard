// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct Ipv4Packet<'a> {
    raw: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 20 {
            return None;
        }
        if (raw[0] >> 4) != 4 {
            return None;
        }
        // SAFETY: raw[0] & 0x0f is 0..=15; multiplied by 4 gives 0..=60, fits in usize
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if raw.len() < ihl {
            return None;
        }
        Some(Self { raw })
    }

    pub fn header_len(&self) -> usize {
        // SAFETY: raw[0] & 0x0f is 0..=15; multiplied by 4 gives 0..=60, fits in usize
        ((self.raw[0] & 0x0f) as usize) * 4
    }

    pub fn protocol(&self) -> u8 {
        self.raw[9]
    }

    pub fn src_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(self.raw[12], self.raw[13], self.raw[14], self.raw[15])
    }

    pub fn dst_ip(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(self.raw[16], self.raw[17], self.raw[18], self.raw[19])
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw[self.header_len()..]
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_too_short() {
        assert!(Ipv4Packet::new(&[0u8; 19]).is_none());
    }

    #[test]
    fn test_new_wrong_version() {
        let mut raw = [0u8; 20];
        raw[0] = 0x65;
        assert!(Ipv4Packet::new(&raw).is_none());
    }

    #[test]
    fn test_fields() {
        let mut raw = [0u8; 20];
        raw[0] = 0x45;
        raw[9] = 17;
        raw[12..16].copy_from_slice(&[10, 0, 0, 1]);
        raw[16..20].copy_from_slice(&[192, 168, 1, 1]);
        let pkt = Ipv4Packet::new(&raw).unwrap();
        assert_eq!(pkt.header_len(), 20);
        assert_eq!(pkt.protocol(), 17);
        assert_eq!(pkt.src_ip(), std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.dst_ip(), std::net::Ipv4Addr::new(192, 168, 1, 1));
    }
}
