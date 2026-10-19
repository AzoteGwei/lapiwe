//! Microheader encoding and frame validation.
//!
//! Every frame begins with a fixed 16-byte microheader. Fields are stored in
//! network byte order, and the trailing CRC covers the first 12 header bytes
//! together with the payload that follows the header.
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0 | 4 | `SYNC`: container magic |
//! | 4 | 1 | `VER_FLAGS`: high 4 bits hold the on-wire format version `VER = 4`; bit 0 is `is_meta`, bit 1 is `best_effort` |
//! | 5 | 3 | `BLK_IDX`: big-endian u24 |
//! | 8 | 3 | `ESI`: big-endian u24 |
//! | 11 | 1 | `PKT_CODE`: low 3 bits hold `log2(P / 2048)`; high 5 bits reserved |
//! | 12 | 4 | `CRC32C`: big-endian CRC over `packet[0..12) ∪ packet[16..P)` |

use crate::container::params::{
    MICROHEADER_LEN, SYNC, U24_MAX, VER, is_legal_packet_code, packet_size_from_code,
};

/// Decoded microheader fields.
///
/// `pkt_code` keeps all 8 bits. The 5 reserved high bits are counted by
/// [`MicroHeader::rsv_nonzero`] but do not make a frame invalid on their own.
/// `ver_flags` is kept as a raw byte for diagnostics; bits 2–3 are ignored
/// during validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicroHeader {
    pub ver_flags: u8,
    pub blk_idx: u32,
    pub esi: u32,
    pub pkt_code: u8,
}

impl MicroHeader {
    /// Construct a microheader from its fields.
    ///
    /// `blk_idx` and `esi` must fit in 24 bits; this is asserted in debug builds
    /// and re-checked during parsing.
    pub fn new(is_meta: bool, best_effort: bool, blk_idx: u32, esi: u32, pkt_code: u8) -> Self {
        debug_assert!(blk_idx <= U24_MAX && esi <= U24_MAX);
        MicroHeader {
            ver_flags: encode_ver_flags(is_meta, best_effort),
            blk_idx,
            esi,
            pkt_code,
        }
    }

    /// Return whether this is a metadata packet (`VER_FLAGS` bit 0).
    pub fn is_meta(&self) -> bool {
        self.ver_flags & 0x01 != 0
    }

    /// Return whether the `best_effort` flag is set (`VER_FLAGS` bit 1).
    pub fn best_effort(&self) -> bool {
        self.ver_flags & 0x02 != 0
    }

    /// Return the high 4 bits of `VER_FLAGS`, i.e. the on-wire format version.
    pub fn ver(&self) -> u8 {
        self.ver_flags >> 4
    }

    /// Return the low 3 bits of `PKT_CODE`, which select the packet size.
    pub fn packet_code_low(&self) -> u8 {
        self.pkt_code & 0x07
    }

    /// Return the packet size `P = 2048 << (PKT_CODE & 0x07)` implied by
    /// `PKT_CODE`.
    pub fn packet_size_hint(&self) -> usize {
        packet_size_from_code(self.pkt_code)
    }

    /// Return whether any of the 5 reserved bits in `PKT_CODE` is set.
    ///
    /// These bits are counted for diagnostics but do not invalidate a frame.
    pub fn rsv_nonzero(&self) -> bool {
        self.pkt_code & 0xF8 != 0
    }
}

/// Encode `VER_FLAGS` as `(VER << 4) | is_meta | (best_effort << 1)`.
pub fn encode_ver_flags(is_meta: bool, best_effort: bool) -> u8 {
    (VER << 4) | u8::from(is_meta) | (u8::from(best_effort) << 1)
}

/// Write the fixed microheader fields, including `SYNC` and the big-endian
/// 24-bit fields. The CRC bytes are left zeroed; [`seal_packet`] fills them in
/// once the payload is in place.
pub fn write_microheader(packet: &mut [u8], header: &MicroHeader) {
    debug_assert!(packet.len() >= MICROHEADER_LEN);
    debug_assert!(header.blk_idx <= U24_MAX && header.esi <= U24_MAX);
    packet[0..4].copy_from_slice(&SYNC);
    packet[4] = header.ver_flags;
    packet[5..8].copy_from_slice(&header.blk_idx.to_be_bytes()[1..]);
    packet[8..11].copy_from_slice(&header.esi.to_be_bytes()[1..]);
    packet[11] = header.pkt_code;
    packet[12..16].fill(0);
}

/// Compute the `CRC32C` over `packet[0..12)` and `packet[16..]`.
///
/// The four CRC bytes at `packet[12..16)` are excluded from the computation.
///
/// # Errors
///
/// Returns [`FrameDefect::TooShort`] when `packet` is shorter than a
/// microheader, so short input never causes an out-of-bounds panic.
pub fn packet_crc32c(packet: &[u8]) -> Result<u32, FrameDefect> {
    if packet.len() < MICROHEADER_LEN {
        return Err(FrameDefect::TooShort);
    }
    let head = crc32c::crc32c(&packet[..12]);
    Ok(crc32c::crc32c_append(head, &packet[16..]))
}

/// Write the `CRC32C` into the big-endian field at `[12..16)` and return it.
/// The payload must already be in place when this is called.
///
/// # Panics
///
/// Panics if `packet` is shorter than 16 bytes. Constructors in this module
/// always pass a complete frame, so this indicates an encoder bug.
pub fn seal_packet(packet: &mut [u8]) -> u32 {
    let crc = packet_crc32c(packet)
        .expect("seal_packet precondition: complete frame (at least 16 bytes)");
    packet[12..16].copy_from_slice(&crc.to_be_bytes());
    crc
}

/// Reason a candidate frame was rejected. Any of these defects makes the frame
/// unusable; a scanner advances by one byte and tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDefect {
    /// The input is shorter than a 16-byte microheader.
    TooShort,
    /// The four magic bytes do not match `SYNC`.
    SyncMismatch,
    /// The high 4 bits of `VER_FLAGS` do not equal `VER`.
    BadVersion,
    /// `PKT_CODE & 0x07` is greater than 5.
    BadPacketCode,
    /// The packet length differs from the `P` implied by `PKT_CODE`.
    LengthMismatch,
    /// A metadata packet has a non-zero `BLK_IDX` or `ESI`.
    MetaFieldsNonZero,
    /// The stored `CRC32C` does not match the computed value.
    CrcMismatch,
    /// A data packet has `BLK_IDX >= NB`, where `NB` comes from the reference
    /// OTI.
    BlockOutOfRange,
}

/// Parse and validate a complete frame.
///
/// The frame length must equal `P = 2048 << (PKT_CODE & 0x07)`. Validation runs
/// in this order: minimum length, `SYNC`, format version, `PKT_CODE` legality,
/// exact frame length, metadata fields, and finally the CRC.
///
/// A non-zero value in the 5 reserved bits of `PKT_CODE` does **not** invalidate
/// the frame; callers can count such frames with [`MicroHeader::rsv_nonzero`].
///
/// # Errors
///
/// Returns the [`FrameDefect`] describing the first failed check.
pub fn parse_header(packet: &[u8]) -> Result<MicroHeader, FrameDefect> {
    if packet.len() < MICROHEADER_LEN {
        return Err(FrameDefect::TooShort);
    }
    if packet[0..4] != SYNC {
        return Err(FrameDefect::SyncMismatch);
    }
    let ver_flags = packet[4];
    if ver_flags >> 4 != VER {
        return Err(FrameDefect::BadVersion);
    }
    let pkt_code = packet[11];
    if !is_legal_packet_code(pkt_code) {
        return Err(FrameDefect::BadPacketCode);
    }
    if packet.len() != packet_size_from_code(pkt_code) {
        return Err(FrameDefect::LengthMismatch);
    }
    let blk_idx = read_u24(&packet[5..8]);
    let esi = read_u24(&packet[8..11]);
    if ver_flags & 0x01 != 0 && (blk_idx != 0 || esi != 0) {
        return Err(FrameDefect::MetaFieldsNonZero);
    }
    let stored_crc = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    if packet_crc32c(packet)? != stored_crc {
        return Err(FrameDefect::CrcMismatch);
    }
    Ok(MicroHeader {
        ver_flags,
        blk_idx,
        esi,
        pkt_code,
    })
}

/// Check the `BLK_IDX` bound for a data packet against `nb`, the number of
/// source blocks in the reference OTI. Metadata packets always pass.
pub fn check_data_block(header: &MicroHeader, nb: u32) -> Result<(), FrameDefect> {
    if header.is_meta() {
        return Ok(());
    }
    if header.blk_idx >= nb {
        return Err(FrameDefect::BlockOutOfRange);
    }
    Ok(())
}

/// Read a big-endian 24-bit unsigned integer from three bytes.
fn read_u24(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::params::{packet_code_for, symbol_size};

    fn data_packet(p: usize, blk_idx: u32, esi: u32) -> Vec<u8> {
        let code = packet_code_for(p).expect("legal P");
        let mut pkt = vec![0xA5u8; p];
        write_microheader(
            &mut pkt,
            &MicroHeader::new(false, false, blk_idx, esi, code),
        );
        seal_packet(&mut pkt);
        pkt
    }

    #[test]
    fn crc_known_vector() {
        // Standard CRC-32C check vector.
        assert_eq!(crc32c::crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn header_roundtrip_and_crc_flip() {
        let p = 4096;
        let mut pkt = data_packet(p, 7, 9);
        let h = parse_header(&pkt).expect("a freshly sealed frame should be valid");
        assert_eq!((h.blk_idx, h.esi, h.packet_code_low()), (7, 9, 1));
        assert!(!h.is_meta() && !h.best_effort());
        pkt[p - 1] ^= 0x01;
        assert_eq!(parse_header(&pkt), Err(FrameDefect::CrcMismatch));
    }

    #[test]
    fn checksum_covers_body_not_whole_header() {
        // The CRC covers [0..12) ∪ [16..P); [12..16) holds the CRC itself.
        let pkt = data_packet(2048, 0, 0);
        let crc = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
        assert_eq!(crc, packet_crc32c(&pkt).expect("complete frame"));
        assert_eq!(symbol_size(pkt.len()), Some(2032));
        // Short input yields an explicit error instead of a panic.
        assert_eq!(packet_crc32c(&[]), Err(FrameDefect::TooShort));
        assert_eq!(packet_crc32c(&pkt[..15]), Err(FrameDefect::TooShort));
    }
}
