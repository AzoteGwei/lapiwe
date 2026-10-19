//! Object transmission information (OTI), metadata packet layout, and
//! baseline OTI accounting.
//!
//! An OTI is 48 bytes long and starts at offset 16 within a metadata packet.
//! Every integer field is stored big-endian:
//!
//! | Relative offset | Length | Field |
//! |---|---|---|
//! | 0 | 8 | `F`: original input size in bytes (big-endian `u64`) |
//! | 8 | 2 | `T`: symbol size (big-endian `u16`) |
//! | 10 | 3 | `NB`: total number of logical blocks (big-endian `u24`) |
//! | 13 | 1 | `N_sub`: number of RaptorQ sub-blocks (fixed at 1) |
//! | 14 | 1 | `SCHEME`: RaptorQ scheme identifier (fixed at 4) |
//! | 15 | 1 | `RSV`: reserved, must be 0 |
//! | 16 | 32 | `BLAKE3`: BLAKE3-256 digest of the original data |
//!
//! A metadata packet consists of a 16-byte micro-header with `is_meta = 1`,
//! `BLK_IDX = 0`, and `ESI = 0`, followed by the 48-byte OTI and `0x00`
//! padding up to the packet size `P`. The CRC is sealed after the payload has
//! been written.
//!
//! Validation covers the frame (through [`parse_header`]) and the OTI
//! semantics: `F >= 1`, `1 <= NB <= 2^24 - 1`, `N_sub = 1`, `SCHEME = 4`,
//! `RSV = 0`, and `T` equal to the symbol size derived from `P`.
//!
//! The first metadata packet that passes both levels of validation becomes the
//! baseline. Later packets are compared with it byte for byte: identical ones
//! increment the agreement counter, differing ones increment the conflict
//! counter, and the baseline is never replaced.

use crate::container::header::{FrameDefect, MicroHeader, parse_header, write_microheader};
use crate::container::params::{
    OTI_LEN, OTI_OFFSET, SCHEME, U24_MAX, packet_code_for, symbol_size,
};

/// Length in bytes of the digest of the original input.
pub const BLAKE3_LEN: usize = 32;

/// Object transmission information: the fixed-size descriptor carried by a
/// metadata packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Oti {
    /// Size of the original input in bytes; must be at least 1.
    pub f: u64,
    /// Symbol size. In a metadata packet this must equal `P - 16`.
    pub t: u16,
    /// Total number of logical blocks, in `1..=2^24 - 1`.
    pub nb: u32,
    /// Number of RaptorQ sub-blocks; fixed at 1.
    pub n_sub: u8,
    /// RaptorQ scheme identifier; fixed at 4.
    pub scheme: u8,
    /// Reserved field; must be 0.
    pub rsv: u8,
    /// BLAKE3-256 digest of the original data, used as the final integrity
    /// criterion.
    pub blake3: [u8; BLAKE3_LEN],
}

impl Oti {
    /// Build an OTI with the fixed field values `N_sub = 1`, `SCHEME = 4`, and
    /// `RSV = 0`.
    pub fn new(f: u64, t: u16, nb: u32, blake3: [u8; BLAKE3_LEN]) -> Self {
        Oti {
            f,
            t,
            nb,
            n_sub: 1,
            scheme: SCHEME,
            rsv: 0,
            blake3,
        }
    }
}

/// Semantic defect in an OTI.
///
/// A structural violation means the packet cannot establish a baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtiDefect {
    /// `F = 0`. Empty input does not define a container.
    FZero,
    /// `NB = 0`.
    NbZero,
    /// `NB` exceeds `2^24 - 1` and does not fit in the 3-byte field.
    NbTooLarge,
    /// `N_sub` is not 1.
    NSubNot1,
    /// `SCHEME` is not 4.
    SchemeNot4,
    /// `RSV` is not 0.
    RsvNonZero,
    /// `T != P - 16`, where `P` is the packet size derived from the frame.
    ///
    /// Frames accepted by [`parse_header`] always have a `P` from the
    /// supported packet-size set, so `P - 16` lies in `[2032, 65520]` and is
    /// a multiple of 8. Comparing `T` against `P - 16` therefore also enforces
    /// the symbol-size range and 8-byte alignment, so separate range and
    /// alignment variants are not needed.
    TNotPacketDerived,
}

/// Defect raised while constructing a metadata packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaBuildError {
    /// `P` is not one of the supported packet sizes.
    IllegalPacketSize,
    /// `NB` does not fit in the 24-bit field.
    NbTooLarge,
}

/// Defect found while parsing a metadata packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaDefect {
    /// The frame failed the validation performed by [`parse_header`].
    Frame(FrameDefect),
    /// The frame is valid but is not a metadata packet (`is_meta = 0`).
    NotMeta,
    /// The frame is valid but the OTI is semantically invalid; the packet is
    /// counted as `bad_meta`.
    Oti(OtiDefect),
}

/// Encode an OTI into its 48-byte big-endian representation.
///
/// # Errors
///
/// Returns [`OtiDefect::NbTooLarge`] if `NB` does not fit in 24 bits.
pub fn encode_oti(oti: &Oti) -> Result<[u8; OTI_LEN], OtiDefect> {
    if oti.nb > U24_MAX {
        return Err(OtiDefect::NbTooLarge);
    }
    let mut bytes = [0u8; OTI_LEN];
    bytes[0..8].copy_from_slice(&oti.f.to_be_bytes());
    bytes[8..10].copy_from_slice(&oti.t.to_be_bytes());
    bytes[10..13].copy_from_slice(&oti.nb.to_be_bytes()[1..]);
    bytes[13] = oti.n_sub;
    bytes[14] = oti.scheme;
    bytes[15] = oti.rsv;
    bytes[16..48].copy_from_slice(&oti.blake3);
    Ok(bytes)
}

/// Decode a 48-byte big-endian OTI.
///
/// This performs no semantic validation; use [`validate_oti`] for that.
pub fn decode_oti(bytes: &[u8; OTI_LEN]) -> Oti {
    let mut f = [0u8; 8];
    f.copy_from_slice(&bytes[0..8]);
    let mut t = [0u8; 2];
    t.copy_from_slice(&bytes[8..10]);
    Oti {
        f: u64::from_be_bytes(f),
        t: u16::from_be_bytes(t),
        nb: (u32::from(bytes[10]) << 16) | (u32::from(bytes[11]) << 8) | u32::from(bytes[12]),
        n_sub: bytes[13],
        scheme: bytes[14],
        rsv: bytes[15],
        blake3: bytes[16..48].try_into().expect("length is fixed at 32"),
    }
}

/// Validate the semantics of an OTI against the packet size `p`.
///
/// The checks run in order: non-zero `F`, non-zero `NB` that fits in 24 bits,
/// `N_sub = 1`, `SCHEME = 4`, `RSV = 0`, and `T` equal to the symbol size
/// derived from `p`.
///
/// # Errors
///
/// Returns the first [`OtiDefect`] that applies.
pub fn validate_oti(oti: &Oti, p: usize) -> Result<(), OtiDefect> {
    if oti.f == 0 {
        return Err(OtiDefect::FZero);
    }
    if oti.nb == 0 {
        return Err(OtiDefect::NbZero);
    }
    if oti.nb > U24_MAX {
        return Err(OtiDefect::NbTooLarge);
    }
    if oti.n_sub != 1 {
        return Err(OtiDefect::NSubNot1);
    }
    if oti.scheme != SCHEME {
        return Err(OtiDefect::SchemeNot4);
    }
    if oti.rsv != 0 {
        return Err(OtiDefect::RsvNonZero);
    }
    let expected_t = symbol_size(p).ok_or(OtiDefect::TNotPacketDerived)? as u16;
    if oti.t != expected_t {
        return Err(OtiDefect::TNotPacketDerived);
    }
    Ok(())
}

/// Build a metadata packet of `p` bytes.
///
/// The packet contains a 16-byte micro-header with `is_meta = 1`,
/// `BLK_IDX = 0`, and `ESI = 0`, followed by the 48-byte OTI and `0x00`
/// padding up to the packet size. The CRC is sealed last.
///
/// This is a low-level constructor and does not validate the OTI semantics;
/// parsing enforces them in [`parse_meta_packet`].
///
/// # Errors
///
/// Returns [`MetaBuildError::IllegalPacketSize`] if `p` is not a supported
/// packet size, or [`MetaBuildError::NbTooLarge`] if `NB` does not fit in
/// 24 bits.
pub fn build_meta_packet(
    p: usize,
    oti: &Oti,
    best_effort: bool,
) -> Result<Vec<u8>, MetaBuildError> {
    let code = packet_code_for(p).ok_or(MetaBuildError::IllegalPacketSize)?;
    let mut packet = vec![0u8; p];
    write_microheader(
        &mut packet,
        &MicroHeader::new(true, best_effort, 0, 0, code),
    );
    let oti_bytes = encode_oti(oti).map_err(|_| MetaBuildError::NbTooLarge)?;
    packet[OTI_OFFSET..OTI_OFFSET + OTI_LEN].copy_from_slice(&oti_bytes);
    crate::container::header::seal_packet(&mut packet);
    Ok(packet)
}

/// Parse a metadata packet and validate both its frame and its OTI.
///
/// # Errors
///
/// Returns [`MetaDefect::Frame`] if the frame is invalid,
/// [`MetaDefect::NotMeta`] if it is not a metadata packet, and
/// [`MetaDefect::Oti`] if the OTI is semantically invalid.
pub fn parse_meta_packet(packet: &[u8]) -> Result<Oti, MetaDefect> {
    let header = parse_header(packet).map_err(MetaDefect::Frame)?;
    if !header.is_meta() {
        return Err(MetaDefect::NotMeta);
    }
    let oti_bytes: &[u8; OTI_LEN] = packet[OTI_OFFSET..OTI_OFFSET + OTI_LEN]
        .try_into()
        .expect("frame length was validated by parse_header");
    let oti = decode_oti(oti_bytes);
    validate_oti(&oti, packet.len()).map_err(MetaDefect::Oti)?;
    Ok(oti)
}

/// Counters for metadata packets observed by a [`MetaTracker`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetaStats {
    /// Number of packets identical to the baseline.
    pub agree_meta: u64,
    /// Number of valid packets that differ from the baseline.
    pub conflict: u64,
    /// Number of packets that pass frame validation but fail OTI validation.
    pub bad_meta: u64,
}

/// Outcome of [`MetaTracker::observe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaDisposition {
    /// The first valid metadata packet established the baseline.
    Baseline,
    /// The packet is byte-for-byte identical to the baseline.
    Agree,
    /// The packet is valid but differs from the baseline; it is counted and
    /// dropped without replacing the baseline.
    Conflict,
    /// The frame is valid (`is_meta = 1`) but the OTI is invalid; it is
    /// counted and never becomes the baseline.
    BadMeta,
    /// The frame failed validation, or it is not a metadata packet: scanner
    /// noise, not counted as metadata.
    Ignored,
}

/// Baseline OTI tracker.
///
/// The first metadata packet that passes validation becomes the baseline.
/// Later conflicts are only counted; the baseline is **never** replaced.
#[derive(Clone, Debug, Default)]
pub struct MetaTracker {
    baseline_packet: Option<Vec<u8>>,
    baseline_oti: Option<Oti>,
    stats: MetaStats,
}

impl MetaTracker {
    /// Return the baseline OTI, or `None` if no baseline has been established
    /// yet.
    pub fn baseline_oti(&self) -> Option<Oti> {
        self.baseline_oti
    }

    /// Return the accumulated counters (`agree_meta`, `conflict`, `bad_meta`).
    pub fn stats(&self) -> MetaStats {
        self.stats
    }

    /// Observe a candidate packet and return its disposition.
    ///
    /// Packets should be supplied in input order. The checks run as follows:
    ///
    /// 1. Frame validation. Invalid frames are scanner-level noise and are
    ///    ignored without entering the metadata counters.
    /// 2. Metadata flag. Data packets are ignored.
    /// 3. OTI validation. Packets with an invalid OTI increment `bad_meta`.
    /// 4. Baseline comparison. The first valid packet becomes the baseline;
    ///    later packets must match it byte for byte, including the
    ///    `best_effort` bit.
    ///
    /// Only packets that pass frame validation, have `is_meta = 1`, and fail
    /// OTI validation increment `bad_meta`. Corrupted frames and frames
    /// rejected at the frame level are always ignored; their accounting
    /// belongs to the scanner, not to the metadata statistics.
    pub fn observe(&mut self, packet: &[u8]) -> MetaDisposition {
        let Ok(header) = parse_header(packet) else {
            return MetaDisposition::Ignored;
        };
        if !header.is_meta() {
            return MetaDisposition::Ignored;
        }
        match parse_meta_packet(packet) {
            Ok(oti) => match &self.baseline_packet {
                None => {
                    self.baseline_packet = Some(packet.to_vec());
                    self.baseline_oti = Some(oti);
                    MetaDisposition::Baseline
                }
                Some(baseline) => {
                    if baseline.as_slice() == packet {
                        self.stats.agree_meta += 1;
                        MetaDisposition::Agree
                    } else {
                        self.stats.conflict += 1;
                        MetaDisposition::Conflict
                    }
                }
            },
            Err(MetaDefect::Oti(_)) => {
                // Frame-valid but OTI-invalid: count it as bad metadata and do
                // not use it as the baseline.
                self.stats.bad_meta += 1;
                MetaDisposition::BadMeta
            }
            Err(MetaDefect::Frame(_) | MetaDefect::NotMeta) => {
                // Defensive branch: the checks above already dispatched on
                // frame validity and `is_meta`, so this is unreachable. Frames
                // rejected at the frame level are not counted either.
                MetaDisposition::Ignored
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::params::DEFAULT_PACKET_SIZE;

    fn sample_oti() -> Oti {
        Oti::new(4096, 4080, 1, [0x5A; BLAKE3_LEN])
    }

    #[test]
    fn oti_roundtrip() {
        let oti = sample_oti();
        let bytes = encode_oti(&oti).expect("valid OTI");
        assert_eq!(decode_oti(&bytes), oti);
    }

    #[test]
    fn meta_packet_roundtrip() {
        let packet = build_meta_packet(DEFAULT_PACKET_SIZE, &sample_oti(), false).expect("build");
        assert_eq!(packet.len(), DEFAULT_PACKET_SIZE);
        assert_eq!(parse_meta_packet(&packet), Ok(sample_oti()));
        // Padding is all zero.
        assert!(packet[OTI_OFFSET + OTI_LEN..].iter().all(|&b| b == 0));
    }

    #[test]
    fn baseline_tracker_counts() {
        let p = DEFAULT_PACKET_SIZE;
        let a = build_meta_packet(p, &sample_oti(), false).expect("A");
        let b =
            build_meta_packet(p, &Oti::new(4096, 4080, 2, [0x00; BLAKE3_LEN]), false).expect("B");
        let mut tracker = MetaTracker::default();
        assert_eq!(tracker.observe(&a), MetaDisposition::Baseline);
        assert_eq!(tracker.observe(&a), MetaDisposition::Agree);
        assert_eq!(tracker.observe(&b), MetaDisposition::Conflict);
        assert_eq!(tracker.observe(&a), MetaDisposition::Agree);
        assert_eq!(
            tracker.baseline_oti(),
            Some(sample_oti()),
            "baseline must not be replaced"
        );
        assert_eq!(
            tracker.stats(),
            MetaStats {
                agree_meta: 2,
                conflict: 1,
                bad_meta: 0,
            }
        );
    }
}
