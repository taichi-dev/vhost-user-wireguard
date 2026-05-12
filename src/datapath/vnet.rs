// SPDX-License-Identifier: MIT OR Apache-2.0

// virtio constants from `virtio_bindings` arrive as u32 from C but the
// virtio_net_hdr_v1 fields they populate are u8. Each cast site is
// statically known to fit (the affected constants are 0 or single-byte
// flag values). Replacing every cast with `u8::try_from(...).unwrap()`
// would itself violate `clippy::unwrap_used`, so allow `as_conversions`
// at the module level.
#![allow(clippy::as_conversions)]

//! virtio_net_hdr_v1 serialization and deserialization helpers.

use virtio_bindings::bindings::virtio_net::{
    VIRTIO_NET_HDR_GSO_NONE, virtio_net_hdr_v1, virtio_net_hdr_v1__bindgen_ty_1,
    virtio_net_hdr_v1__bindgen_ty_1__bindgen_ty_1,
};

use crate::error::VhostError;

fn make_anon(csum_start: u16, csum_offset: u16) -> virtio_net_hdr_v1__bindgen_ty_1 {
    virtio_net_hdr_v1__bindgen_ty_1 {
        __bindgen_anon_1: virtio_net_hdr_v1__bindgen_ty_1__bindgen_ty_1 {
            csum_start,
            csum_offset,
        },
    }
}

/// Parse 12 bytes into a `virtio_net_hdr_v1`.
///
/// Returns `VhostError::Backend` if `bytes.len() < 12`.
pub fn parse(bytes: &[u8]) -> Result<virtio_net_hdr_v1, VhostError> {
    if bytes.len() < 12 {
        return Err(VhostError::Backend("vnet header too short".to_string()));
    }

    let flags = bytes[0];
    let gso_type = bytes[1];
    let hdr_len = u16::from_le_bytes([bytes[2], bytes[3]]);
    let gso_size = u16::from_le_bytes([bytes[4], bytes[5]]);
    let csum_start = u16::from_le_bytes([bytes[6], bytes[7]]);
    let csum_offset = u16::from_le_bytes([bytes[8], bytes[9]]);
    let num_buffers = u16::from_le_bytes([bytes[10], bytes[11]]);

    Ok(virtio_net_hdr_v1 {
        flags,
        gso_type,
        hdr_len,
        gso_size,
        __bindgen_anon_1: make_anon(csum_start, csum_offset),
        num_buffers,
    })
}

/// Serialize a `virtio_net_hdr_v1` into a 12-byte little-endian array.
pub fn serialize(hdr: &virtio_net_hdr_v1) -> [u8; 12] {
    let (csum_start, csum_offset) = unsafe {
        (
            hdr.__bindgen_anon_1.__bindgen_anon_1.csum_start,
            hdr.__bindgen_anon_1.__bindgen_anon_1.csum_offset,
        )
    };

    let mut buf = [0u8; 12];
    buf[0] = hdr.flags;
    buf[1] = hdr.gso_type;
    buf[2..4].copy_from_slice(&hdr.hdr_len.to_le_bytes());
    buf[4..6].copy_from_slice(&hdr.gso_size.to_le_bytes());
    buf[6..8].copy_from_slice(&csum_start.to_le_bytes());
    buf[8..10].copy_from_slice(&csum_offset.to_le_bytes());
    buf[10..12].copy_from_slice(&hdr.num_buffers.to_le_bytes());
    buf
}

/// Returns a zeroed RX header with `num_buffers = 1` and `gso_type = VIRTIO_NET_HDR_GSO_NONE`.
pub fn rx_header() -> virtio_net_hdr_v1 {
    virtio_net_hdr_v1 {
        flags: 0,
        // SAFETY: VIRTIO_NET_HDR_GSO_NONE == 0, which fits in u8
        gso_type: VIRTIO_NET_HDR_GSO_NONE as u8,
        hdr_len: 0,
        gso_size: 0,
        __bindgen_anon_1: make_anon(0, 0),
        num_buffers: 1,
    }
}

/// Returns `true` iff `hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE`.
pub fn tx_header_is_valid(hdr: &virtio_net_hdr_v1) -> bool {
    // SAFETY: VIRTIO_NET_HDR_GSO_NONE == 0, which fits in u8
    hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_is_12() {
        assert_eq!(std::mem::size_of::<virtio_net_hdr_v1>(), 12);
    }

    #[test]
    fn test_round_trip() {
        let original = virtio_net_hdr_v1 {
            flags: 0x01,
            gso_type: 0x02,
            hdr_len: 0x0304,
            gso_size: 0x0506,
            __bindgen_anon_1: make_anon(0x0708, 0x090a),
            num_buffers: 0x0b0c,
        };
        let bytes = serialize(&original);
        let parsed = parse(&bytes).expect("round-trip parse failed");
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.gso_type, original.gso_type);
        assert_eq!(parsed.hdr_len, original.hdr_len);
        assert_eq!(parsed.gso_size, original.gso_size);
        assert_eq!(parsed.num_buffers, original.num_buffers);
        unsafe {
            assert_eq!(
                parsed.__bindgen_anon_1.__bindgen_anon_1.csum_start,
                original.__bindgen_anon_1.__bindgen_anon_1.csum_start
            );
            assert_eq!(
                parsed.__bindgen_anon_1.__bindgen_anon_1.csum_offset,
                original.__bindgen_anon_1.__bindgen_anon_1.csum_offset
            );
        }
    }

    #[test]
    fn test_rx_header_num_buffers() {
        assert_eq!(rx_header().num_buffers, 1);
    }

    #[test]
    fn test_tx_valid_gso_none() {
        assert!(tx_header_is_valid(&rx_header()));
    }

    #[test]
    fn test_tx_invalid_gso_nonzero() {
        let hdr = virtio_net_hdr_v1 {
            flags: 0,
            gso_type: 1,
            hdr_len: 0,
            gso_size: 0,
            __bindgen_anon_1: make_anon(0, 0),
            num_buffers: 1,
        };
        assert!(!tx_header_is_valid(&hdr));
    }

    #[test]
    fn test_parse_too_short() {
        let result = parse(&[0u8; 11]);
        assert!(result.is_err());
    }
}
