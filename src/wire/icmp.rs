// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::Ipv4Addr;

use crate::wire::ipv4::Ipv4Packet;

/// Compute the Internet checksum (RFC 1071) over `data`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        // SAFETY: u16 fits in u32; no truncation
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [byte] = chunks.remainder() {
        // SAFETY: u8 fits in u32; no truncation
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // SAFETY: after folding carries, sum fits in u16
    !(sum as u16)
}

/// Build an ICMPv4 Type 3 Code 4 "Fragmentation Needed" packet.
///
/// Returns a complete IPv4 packet (header + ICMP message) as `Vec<u8>`.
///
/// # Arguments
/// * `original_ip_packet` – the original IPv4 packet that triggered the PMTU event.
/// * `next_hop_mtu`       – the MTU of the next-hop link (placed in ICMP header bytes 6-7).
/// * `src_ip`             – the source IP for the generated packet (typically the gateway IP).
pub fn build_icmp_frag_needed(
    original_ip_packet: &[u8],
    next_hop_mtu: u16,
    src_ip: Ipv4Addr,
) -> Vec<u8> {
    // Parse the original packet to extract fields we need.
    let orig = match Ipv4Packet::new(original_ip_packet) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let orig_hdr_len = orig.header_len();
    let orig_header = &original_ip_packet[..orig_hdr_len];

    // RFC 792: ICMP payload = original IP header + first 8 bytes of original IP payload.
    let orig_payload = orig.payload();
    let payload_bytes = orig_payload.len().min(8);
    let orig_payload_slice = &orig_payload[..payload_bytes];

    // Build ICMP message: 8-byte header + original header + up to 8 bytes of original payload.
    let icmp_data_len = orig_hdr_len + payload_bytes;
    let icmp_total_len = 8 + icmp_data_len;
    let mut icmp: Vec<u8> = Vec::with_capacity(icmp_total_len);

    // ICMP header (8 bytes)
    icmp.push(3); // type = 3 (Destination Unreachable)
    icmp.push(4); // code = 4 (Fragmentation Needed)
    icmp.push(0); // checksum high byte (placeholder)
    icmp.push(0); // checksum low byte (placeholder)
    icmp.push(0); // unused
    icmp.push(0); // unused
    icmp.extend_from_slice(&next_hop_mtu.to_be_bytes()); // bytes 6-7: next-hop MTU

    // ICMP payload
    icmp.extend_from_slice(orig_header);
    icmp.extend_from_slice(orig_payload_slice);

    // Compute and fill in ICMP checksum.
    let csum = checksum(&icmp);
    // SAFETY: csum is u16; shifting/masking to u8 is lossless for each byte
    icmp[2] = (csum >> 8) as u8;
    icmp[3] = (csum & 0xff) as u8;

    // Build IPv4 header (20 bytes, no options).
    // SAFETY: icmp_total_len = 8 + orig_hdr_len(<=60) + payload_bytes(<=8) <= 76; 20+76=96 fits u16
    let total_length: u16 = 20 + icmp_total_len as u16;
    let dst_ip = orig.src_ip(); // send back to the original sender

    let mut ipv4_hdr: Vec<u8> = Vec::with_capacity(20);
    ipv4_hdr.push(0x45); // version=4, IHL=5
    ipv4_hdr.push(0x00); // DSCP/ECN = 0
    ipv4_hdr.extend_from_slice(&total_length.to_be_bytes()); // total length
    ipv4_hdr.extend_from_slice(&[0x00, 0x00]); // identification = 0
    ipv4_hdr.extend_from_slice(&[0x00, 0x00]); // flags=0, fragment offset=0
    ipv4_hdr.push(64); // TTL = 64
    ipv4_hdr.push(1); // protocol = 1 (ICMP)
    ipv4_hdr.extend_from_slice(&[0x00, 0x00]); // header checksum placeholder
    ipv4_hdr.extend_from_slice(&src_ip.octets()); // source IP
    ipv4_hdr.extend_from_slice(&dst_ip.octets()); // destination IP

    // Compute IPv4 header checksum.
    let ip_csum = checksum(&ipv4_hdr);
    // SAFETY: ip_csum is u16; shifting/masking to u8 is lossless for each byte
    ipv4_hdr[10] = (ip_csum >> 8) as u8;
    ipv4_hdr[11] = (ip_csum & 0xff) as u8;

    // Concatenate IPv4 header + ICMP message.
    let mut packet = ipv4_hdr;
    packet.extend_from_slice(&icmp);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4/UDP packet for use as the "original" packet.
    fn make_original_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        // IPv4 header (20 bytes) + 8-byte UDP payload (enough for RFC 792 requirement)
        let total_len: u16 = 28;
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        // 8-byte payload (simulated UDP header)
        pkt[20] = 0x00;
        pkt[21] = 0x50; // src port 80
        pkt[22] = 0x04;
        pkt[23] = 0x00; // dst port 1024
        pkt[24] = 0x00;
        pkt[25] = 0x08; // length
        pkt[26] = 0x00;
        pkt[27] = 0x00; // checksum
        pkt
    }

    #[test]
    fn test_icmp_type_code() {
        let orig_src = Ipv4Addr::new(10, 0, 0, 2);
        let orig_dst = Ipv4Addr::new(8, 8, 8, 8);
        let gw_ip = Ipv4Addr::new(10, 0, 0, 1);
        let orig = make_original_packet(orig_src, orig_dst);

        let pkt = build_icmp_frag_needed(&orig, 1400, gw_ip);
        assert!(pkt.len() >= 28, "packet too short");

        // ICMP starts at byte 20 (after IPv4 header).
        assert_eq!(pkt[20], 3, "ICMP type must be 3");
        assert_eq!(pkt[21], 4, "ICMP code must be 4");
    }

    #[test]
    fn test_icmp_next_hop_mtu() {
        let orig_src = Ipv4Addr::new(10, 0, 0, 2);
        let orig_dst = Ipv4Addr::new(8, 8, 8, 8);
        let gw_ip = Ipv4Addr::new(10, 0, 0, 1);
        let orig = make_original_packet(orig_src, orig_dst);

        let mtu: u16 = 1280;
        let pkt = build_icmp_frag_needed(&orig, mtu, gw_ip);

        // Bytes 26-27 of the full packet (ICMP bytes 6-7) = next-hop MTU.
        let mtu_in_pkt = u16::from_be_bytes([pkt[26], pkt[27]]);
        assert_eq!(mtu_in_pkt, mtu, "next-hop MTU mismatch");
    }

    #[test]
    fn test_icmp_contains_original_header() {
        let orig_src = Ipv4Addr::new(192, 168, 1, 10);
        let orig_dst = Ipv4Addr::new(1, 1, 1, 1);
        let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
        let orig = make_original_packet(orig_src, orig_dst);

        let pkt = build_icmp_frag_needed(&orig, 1500, gw_ip);

        // ICMP payload starts at byte 28 (20 IPv4 + 8 ICMP header).
        // It should begin with the original IP header (20 bytes).
        let icmp_payload = &pkt[28..];
        assert!(
            icmp_payload.len() >= 20,
            "ICMP payload must contain at least the original IP header"
        );
        assert_eq!(
            &icmp_payload[..20],
            &orig[..20],
            "ICMP payload must start with original IP header"
        );
    }

    #[test]
    fn test_icmp_checksum_valid() {
        let orig_src = Ipv4Addr::new(172, 16, 0, 5);
        let orig_dst = Ipv4Addr::new(203, 0, 113, 1);
        let gw_ip = Ipv4Addr::new(172, 16, 0, 1);
        let orig = make_original_packet(orig_src, orig_dst);

        let pkt = build_icmp_frag_needed(&orig, 576, gw_ip);

        // The ICMP portion starts at byte 20.
        let icmp_portion = &pkt[20..];

        // Re-computing the checksum over the ICMP message (with the embedded checksum)
        // should yield 0 for a valid checksum.
        let verify = checksum(icmp_portion);
        assert_eq!(verify, 0, "ICMP checksum verification failed (expected 0)");
    }
}
