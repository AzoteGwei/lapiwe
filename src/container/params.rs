//! Shared constants and packet-size parameters for the container format.
//!
//! Multi-byte integers are encoded in big-endian byte order. For positive
//! integers, `ceil(a / b)` follows the semantics of `div_ceil`.

/// On-wire container format version stored in the packet header.
///
/// This is distinct from the magic bytes in [`SYNC`].
pub const VER: u8 = 4;

/// RaptorQ scheme identifier used by the container format.
pub const SCHEME: u8 = 4;

/// Length of the fixed per-packet microheader in bytes.
pub const MICROHEADER_LEN: usize = 16;

/// Length of the Object Transmission Information (OTI) field in bytes.
pub const OTI_LEN: usize = 48;

/// Offset of the OTI from the start of a metadata packet.
pub const OTI_OFFSET: usize = MICROHEADER_LEN;

/// Four-byte container magic, ASCII `"LPW1"`.
///
/// The magic identifies the file format; it is not a version number.
pub const SYNC: [u8; 4] = *b"LPW1";

/// Packet sizes, in bytes, accepted by the format.
pub const PACKET_SIZES: [usize; 6] = [2048, 4096, 8192, 16384, 32768, 65536];

/// Default packet size in bytes.
pub const DEFAULT_PACKET_SIZE: usize = 4096;

/// Base packet size for the shift encoded in the low three bits of `PKT_CODE`.
pub const PACKET_SIZE_BASE: usize = 2048;

/// Default metadata packet interval.
pub const DEFAULT_META_EVERY: u64 = 256;

/// Smallest legal metadata packet interval (`M >= 2`).
pub const MIN_META_EVERY: u64 = 2;

/// Number of repair symbols `G` in the effective redundancy lower bound.
pub const G: u64 = 4;

/// Numerator of the minimum redundancy fraction `ε_min = 0.005`.
///
/// The lower bound is
/// `needed_j = max(K_j + G, ceil(1005 * K_j / 1000))`.
pub const EPS_MIN_NUMERATOR: u64 = 1005;

/// Denominator of the minimum redundancy fraction `ε_min = 0.005`.
pub const EPS_MIN_DENOMINATOR: u64 = 1000;

/// Maximum source-block symbol count `K'_max` permitted by RFC 6330.
pub const RFC_KMAX: u64 = 56_403;

/// Largest value representable in a 3-byte field such as `BLK_IDX`, `ESI`, or
/// `NB` (`2^24 - 1`).
pub const U24_MAX: u32 = (1 << 24) - 1;

/// Default per-block encoding memory budget in bytes (16 MiB).
///
/// The encoder derives `K_max` from this budget and the symbol size.
pub const DEFAULT_ENCODE_MAX_MEM: u64 = 16 * 1024 * 1024;

/// Default decoder working-set budget in bytes (64 MiB).
///
/// The budget covers storage for non-source symbols, staging of missing
/// intervals, and auxiliary indexes. It is independent of the encoder's
/// per-block budget and must exceed the scanner ring buffer
/// [`crate::container::scan::RING_CAP`].
pub const DEFAULT_DECODE_MAX_MEM: u64 = 64 * 1024 * 1024;

/// Smallest legal packet size in bytes.
pub const MIN_PACKET_SIZE: usize = PACKET_SIZES[0];

/// Largest legal packet size in bytes.
pub const MAX_PACKET_SIZE: usize = PACKET_SIZES[5];

/// Smallest symbol size in bytes (`T = 2032`).
pub const MIN_SYMBOL_SIZE: usize = MIN_PACKET_SIZE - MICROHEADER_LEN;

/// Largest symbol size in bytes (`T = 65520`).
pub const MAX_SYMBOL_SIZE: usize = MAX_PACKET_SIZE - MICROHEADER_LEN;

/// Return `true` if `p` is one of the supported packet sizes.
pub fn is_legal_packet_size(p: usize) -> bool {
    PACKET_SIZES.contains(&p)
}

/// Return the symbol size `T = P - 16` for a legal packet size `P`.
///
/// Returns `None` if `P` is not a supported packet size.
pub fn symbol_size(p: usize) -> Option<usize> {
    is_legal_packet_size(p).then(|| p - MICROHEADER_LEN)
}

/// Return the packet size encoded in `PKT_CODE`: `P = 2048 << (code & 0x07)`.
///
/// This function performs the raw shift only. Use [`is_legal_packet_code`] to
/// determine whether the result is a supported size.
pub fn packet_size_from_code(code: u8) -> usize {
    PACKET_SIZE_BASE << (code & 0x07)
}

/// Return `true` if the low three bits of `PKT_CODE` select a supported size.
///
/// The upper five bits are ignored.
pub fn is_legal_packet_code(code: u8) -> bool {
    code & 0x07 <= 5
}

/// Return the `PKT_CODE` for a supported packet size `P`, with the upper five
/// bits set to zero.
///
/// Returns `None` if `P` is not a supported packet size.
pub fn packet_code_for(p: usize) -> Option<u8> {
    if !is_legal_packet_size(p) {
        return None;
    }
    let mut k = 0u8;
    let mut v = p / PACKET_SIZE_BASE;
    while v > 1 {
        v >>= 1;
        k += 1;
    }
    Some(k)
}

/// Return `K_max = min(56403, floor(max_mem / T))` for packet size `P`.
///
/// Returns `None` if `P` is not a supported packet size or if `max_mem` is
/// smaller than one symbol (`K_max` would be zero).
pub fn k_max_from_mem(max_mem: u64, p: usize) -> Option<u64> {
    let t = symbol_size(p)? as u64;
    if max_mem < t {
        return None;
    }
    Some((max_mem / t).min(RFC_KMAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_code_roundtrip_for_all_legal_sizes() {
        for p in PACKET_SIZES {
            let code = packet_code_for(p).expect("a legal packet size must have a code");
            assert_eq!(packet_size_from_code(code), p);
            assert!(is_legal_packet_code(code));
        }
        assert_eq!(packet_code_for(2047), None);
        assert_eq!(packet_code_for(4097), None);
        assert_eq!(packet_code_for(3000), None);
    }

    #[test]
    fn symbol_size_bounds_match_spec() {
        assert_eq!(symbol_size(2048), Some(2032));
        assert_eq!(symbol_size(65536), Some(65520));
        assert_eq!(symbol_size(3000), None);
    }

    #[test]
    fn default_k_max_table_matches_spec() {
        // Recompute every row of the default `K_max` table for the 16 MiB
        // encoding budget. The 64 MiB column, formerly the default, is checked
        // as an explicit reference budget.
        let default_budget = [
            (2048usize, 8_256u64),
            (4096, 4_112),
            (8192, 2_052),
            (16384, 1_025),
            (32768, 512),
            (65536, 256),
        ];
        for (p, expected) in default_budget {
            assert_eq!(
                k_max_from_mem(DEFAULT_ENCODE_MAX_MEM, p),
                Some(expected),
                "P={p}"
            );
        }
        // The 64 MiB comparison column uses an independent test constant and
        // must not refer to `DEFAULT_DECODE_MAX_MEM`. The latter is the decoder
        // working-set default, and future changes to it must not silently alter
        // the reference semantics of this table.
        const REF_64MIB: u64 = 64 * 1024 * 1024;
        let reference_budget = [
            (2048usize, 33_026u64),
            (4096, 16_448),
            (8192, 8_208),
            (16384, 4_100),
            (32768, 2_049),
            (65536, 1_024),
        ];
        for (p, expected) in reference_budget {
            assert_eq!(
                k_max_from_mem(REF_64MIB, p),
                Some(expected),
                "P={p} (64 MiB reference column)"
            );
        }
    }

    #[test]
    fn k_max_is_none_below_symbol_size() {
        assert_eq!(k_max_from_mem(2031, 2048), None);
        assert_eq!(k_max_from_mem(2032, 2048), Some(1));
    }

    #[test]
    fn k_max_caps_at_rfc_limit() {
        assert_eq!(k_max_from_mem(u64::MAX, 65536), Some(RFC_KMAX));
    }
}
