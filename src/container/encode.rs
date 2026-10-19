//! RaptorQ encoding front end and the minimal encode pipeline.
//!
//! Encoding runs in two passes over the input:
//!
//! - **Pass 1:** [`prescan`] scans the complete input once to determine the
//!   global length `F` and the `BLAKE3-256` digest.
//! - **Pass 2:** [`encode_to`] splits the input into `NB` level blocks and
//!   encodes each block with its own [`raptorq::SourceBlockEncoder`]. Every
//!   block uses the OTI `(K_j·T, T, 1, 1, 8)`; the global object length `F` is
//!   never passed to the crate. The resulting symbols are then interleaved
//!   into `C_total` packets of `P` bytes.
//!
//! [`plan`] resolves the three sources of `C_total`, performs all layout and
//! boundary checks, and applies the effective-redundancy check. When that check
//! fails, the default behavior is to emit nothing and exit with status 2;
//! `--force` continues and sets `best_effort = 1` in every packet.
//!
//! For streaming, [`plan`] returns an [`EncodePlan`]. The CLI scans a file for
//! pass 1, then reads and encodes one block at a time in pass 2, using
//! [`EncodePlan::encode_block`] to place packets into their slots in a seekable
//! temporary file or an in-memory buffer. Peak encoder memory is therefore
//! about `3·K_j·T` for one block rather than about `3F` for the whole input.
//! Standard input is copied to a temporary file by the CLI before the file path
//! is used.
//!
//! The module's contract is that `(F, BLAKE3)` comes from a prior scan of the
//! complete input ([`prescan`]), and that pass 2 reads the same data. Lengths
//! are enforced by [`encode_to`] and [`EncodePlan::block_span`]; verifying
//! content identity with the digest is left to the caller.
//!
//! Packet contents and placement depend only on the input bytes and the encode
//! configuration, so identical inputs produce byte-identical output.

use std::io::Write;

use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder};

use crate::container::counts::{
    DefaultTotal, RedundancyReport, a_j, c_total_from_redundancy, c_total_from_size,
    default_c_total_min, redundancy_report,
};
use crate::container::header::{MicroHeader, seal_packet, write_microheader};
use crate::container::leveling::{LayoutDefect, Leveling, derive_nb, symbol_count};
use crate::container::meta::{BLAKE3_LEN, MetaBuildError, Oti, build_meta_packet};
use crate::container::params::{
    MICROHEADER_LEN, MIN_META_EVERY, U24_MAX, packet_code_for, symbol_size,
};

/// Result of the first encode pass: the global `F` and the global
/// `BLAKE3-256` digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobInfo {
    /// Number of raw input bytes, `F ≥ 1`.
    pub f: u64,
    /// `BLAKE3-256` digest of the raw input, recorded in the global OTI as the
    /// final integrity check.
    pub blake3: [u8; BLAKE3_LEN],
}

/// Scan the complete input to determine `(F, BLAKE3)`; no packets are emitted.
///
/// For file input the CLI performs an equivalent standalone scan. Standard
/// input is spooled to a temporary file first. The scanned bytes must be the
/// same bytes supplied to the second pass.
pub fn prescan(data: &[u8]) -> BlobInfo {
    BlobInfo {
        f: data.len() as u64,
        blake3: *blake3::hash(data).as_bytes(),
    }
}

/// Source of `C_total`, the total number of output packets.
///
/// Only integer arithmetic is used. `--redundancy` is an exact rational, never
/// a floating-point value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotalSpec {
    /// `--size SIZE`: `C_total = floor(SIZE / P)`.
    Size(u64),
    /// `--redundancy NUM/DEN`: total output size as an exact rational
    /// multiplier. The CLI validates the fraction.
    Redundancy { num: u64, den: u64 },
    /// The default `C_total_min`.
    Default,
}

/// Encoding parameters. The global `F` and digest are supplied separately via
/// [`BlobInfo`] and are not stored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeConfig {
    /// Packet size `P`, restricted to the supported set.
    pub p: usize,
    /// Metadata packet interval `M ≥ 2`.
    pub m: u64,
    /// Maximum symbols per block, `K_max = min(56403, floor(M_blk / T))`.
    /// The CLI derives this from `--max-mem`.
    pub k_max: u64,
    /// Source of `C_total`.
    pub total: TotalSpec,
    /// `--force`: continue when the redundancy check fails and set
    /// `best_effort = 1` in every packet.
    pub force: bool,
}

/// Reasons an encode operation can fail.
///
/// [`EncodeError::exit_code`] maps each variant to a CLI exit status.
#[derive(Debug)]
pub enum EncodeError {
    /// Packet size `P` is not in the supported set.
    IllegalPacketSize(usize),
    /// `K_max` is zero because the memory budget is smaller than one symbol.
    KmaxZero,
    /// A layout or format defect, or a numeric overflow while deriving the
    /// layout.
    Layout(LayoutDefect),
    /// `C_total < 2`, leaving no room for data packets. `--force` does not
    /// bypass this check.
    NotPublishable { c_total: u64 },
    /// The largest data ESI, `floor((D−1)/NB)`, does not fit in the 24-bit
    /// header field.
    MaxEsiExceeded { max_esi: u64 },
    /// `C_total · P` overflows `u64`.
    TotalBytesOverflow { c_total: u64, p: usize },
    /// At least one block has fewer available symbols than it needs. On the
    /// default path the encoder emits nothing and exits with status 2.
    RedundancyInsufficient(RedundancyReport),
    /// The second pass received a different number of bytes than the first
    /// pass recorded.
    LengthMismatch { expected: u64, actual: u64 },
    /// The metadata packet could not be built. This is a defensive variant;
    /// valid parameters do not reach it.
    MetaBuild(MetaBuildError),
    /// Writing the output failed.
    Io(std::io::Error),
}

impl EncodeError {
    /// Return the CLI exit status: `2` for insufficient redundancy, `1` for all
    /// other errors.
    pub fn exit_code(&self) -> u8 {
        match self {
            EncodeError::RedundancyInsufficient(_) => 2,
            _ => 1,
        }
    }
}

impl From<LayoutDefect> for EncodeError {
    fn from(defect: LayoutDefect) -> Self {
        EncodeError::Layout(defect)
    }
}

impl From<MetaBuildError> for EncodeError {
    fn from(err: MetaBuildError) -> Self {
        EncodeError::MetaBuild(err)
    }
}

impl From<std::io::Error> for EncodeError {
    fn from(err: std::io::Error) -> Self {
        EncodeError::Io(err)
    }
}

/// Summary of a successful encode, containing the byte-level values reported
/// by the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeSummary {
    /// Global object transmission information: `F`, `T`, `NB`, the number of
    /// sub-blocks, the scheme, the reserved field, and the digest.
    pub oti: Oti,
    /// Derived block layout.
    pub leveling: Leveling,
    /// Total number of output packets and the source of that count.
    pub c_total: u64,
    pub total: TotalSpec,
    /// Number of metadata packets `C_meta = ceil(C_total / M)` and data packets
    /// `D = C_total − C_meta`.
    pub c_meta: u64,
    pub d: u64,
    /// `true` when `--force` was used and the redundancy check failed. Every
    /// packet then has the best-effort bit set.
    pub best_effort: bool,
    /// Redundancy report: the minimum slack `min(a_j − needed_j)` and the
    /// number of affected blocks.
    pub redundancy: RedundancyReport,
    /// Intermediate values from the default `C_total` computation; `None` for
    /// the explicit size and redundancy paths.
    pub default_total: Option<DefaultTotal>,
}

/// Build the OTI for one source block: `(K_j·T, T, 1, 1, 8)`.
///
/// `block_len` is the zero-padded length of that block (`K_j·T`), never the
/// global object length `F`.
pub fn block_oti(block_len: u64, t: u16) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::new(block_len, t, 1, 1, 8)
}

/// Validate the configuration, derive the layout, and compute `C_total`.
///
/// On success the returned [`EncodePlan`] is ready for packet generation.
/// This function writes no output bytes, and it performs every parameter,
/// bound, and redundancy check before any packet can be emitted. If it returns
/// an error, the output target has received zero bytes.
pub fn plan(info: &BlobInfo, cfg: &EncodeConfig) -> Result<EncodePlan, EncodeError> {
    // Validate parameters before any output is produced.
    let t = symbol_size(cfg.p).ok_or(EncodeError::IllegalPacketSize(cfg.p))?;
    if cfg.k_max == 0 {
        return Err(EncodeError::KmaxZero);
    }
    if cfg.m < MIN_META_EVERY {
        return Err(LayoutDefect::MetaEveryTooSmall.into());
    }

    // Derive the block layout and validate its format-level invariants.
    let s = symbol_count(info.f, t as u64)?;
    let nb = derive_nb(s, cfg.k_max)?;
    let leveling = Leveling::derive(info.f, t as u64, nb)?;
    leveling.validate_format()?;

    // Compute C_total from the selected source using integer arithmetic only.
    let (c_total, default_total) = match cfg.total {
        TotalSpec::Size(size) => (
            c_total_from_size(size, cfg.p).ok_or(LayoutDefect::Overflow)?,
            None,
        ),
        TotalSpec::Redundancy { num, den } => (
            c_total_from_redundancy(info.f, num, den, cfg.p).ok_or(LayoutDefect::Overflow)?,
            None,
        ),
        TotalSpec::Default => {
            let dt = default_c_total_min(info.f, t as u64, cfg.m, cfg.k_max)?;
            debug_assert_eq!(
                dt.leveling, leveling,
                "global and local layout derivations must match"
            );
            (dt.c_total_min, Some(dt))
        }
    };

    // At least two packets are needed so that at least one data packet exists.
    // --force does not bypass this requirement.
    if c_total < 2 {
        return Err(EncodeError::NotPublishable { c_total });
    }
    let c_meta = c_total.div_ceil(cfg.m);
    let d = c_total - c_meta;

    // Encoding-side bounds checks, performed before any packet is written.
    // The two checks may be ordered either way; the total byte count is
    // checked first so that it also catches oversized --redundancy values:
    //   - with --size, C_total·P ≤ SIZE ≤ u64::MAX, so it cannot overflow;
    //   - with --redundancy, C_total can reach u64::MAX (the division is done
    //     in u128 first), making C_total·P the first value that can overflow.
    c_total
        .checked_mul(cfg.p as u64)
        .ok_or(EncodeError::TotalBytesOverflow { c_total, p: cfg.p })?;
    // derive_nb and Leveling::derive guarantee NB ≥ 1. The largest data ESI,
    // floor((D−1)/NB), must fit in the 24-bit header field, and C_total ≥ 2
    // already guarantees D ≥ 1.
    let max_esi = (d - 1) / u64::from(nb);
    if max_esi > u64::from(U24_MAX) {
        return Err(EncodeError::MaxEsiExceeded { max_esi });
    }

    // Redundancy check. Without --force, insufficient redundancy is an error
    // and nothing is written; with --force, encoding continues and every
    // packet is marked best-effort.
    let redundancy = redundancy_report(&leveling, d);
    let best_effort = redundancy.min_slack < 0;
    if best_effort && !cfg.force {
        return Err(EncodeError::RedundancyInsufficient(redundancy));
    }

    let oti = Oti::new(info.f, t as u16, nb, info.blake3);
    let code = packet_code_for(cfg.p).ok_or(EncodeError::IllegalPacketSize(cfg.p))?;
    let meta_packet = build_meta_packet(cfg.p, &oti, best_effort)?;
    Ok(EncodePlan {
        oti,
        leveling,
        c_total,
        total: cfg.total,
        c_meta,
        d,
        best_effort,
        redundancy,
        default_total,
        p: cfg.p,
        m: cfg.m,
        code,
        meta_packet,
    })
}

/// A fully validated encode plan shared by the streaming and in-memory paths.
///
/// Usage:
///
/// 1. For each logical block `j` in `0..NB`, take its bytes according to
///    [`EncodePlan::block_span`] (zero-padding the tail to
///    [`EncodePlan::block_bytes`]) and call [`EncodePlan::encode_block`]. Each
///    callback receives a packet slot index and the complete packet, to be
///    stored in a seekable temporary file, an in-memory buffer, or written in
///    order.
/// 2. Write [`EncodePlan::meta_packet`] at every slot returned by
///    [`EncodePlan::meta_slots`].
///
/// The result is byte-for-byte identical to [`encode_to`]: generating packets
/// block by block and placing them by slot is equivalent to generating them in
/// slot order.
#[derive(Clone, Debug)]
pub struct EncodePlan {
    /// Global object transmission information.
    pub oti: Oti,
    /// Derived block layout.
    pub leveling: Leveling,
    /// Total number of output packets and the source of that count.
    pub c_total: u64,
    pub total: TotalSpec,
    /// Number of metadata packets `C_meta = ceil(C_total / M)` and data packets
    /// `D = C_total − C_meta`.
    pub c_meta: u64,
    pub d: u64,
    /// `true` when `--force` was used and redundancy was insufficient. All
    /// packets then carry `best_effort = 1`.
    pub best_effort: bool,
    /// Redundancy report for the chosen layout.
    pub redundancy: RedundancyReport,
    /// Intermediate values from the default `C_total` computation; `None`
    /// otherwise.
    pub default_total: Option<DefaultTotal>,
    /// Packet size `P`.
    p: usize,
    /// Metadata packet interval `M ≥ 2`.
    m: u64,
    /// `PKT_CODE` corresponding to the packet size.
    code: u8,
    /// Metadata packet bytes, identical for every metadata slot in a stream.
    meta_packet: Vec<u8>,
}

impl EncodePlan {
    /// Return the packet size `P`.
    pub fn p(&self) -> usize {
        self.p
    }

    /// Return the metadata packet bytes. Every metadata slot in a stream holds
    /// this same packet.
    pub fn meta_packet(&self) -> &[u8] {
        &self.meta_packet
    }

    /// Return whether slot `i` holds a metadata packet (`i mod M == 0`).
    pub fn is_meta_slot(&self, i: u64) -> bool {
        i % self.m == 0
    }

    /// Iterate over metadata slot indices `0, M, 2M, …` below `C_total`.
    pub fn meta_slots(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.c_total).step_by(self.m as usize)
    }

    /// Return the byte length of block `j`, `K_j·T`.
    pub fn block_bytes(&self, j: u32) -> u64 {
        self.leveling.k_j(j) * self.leveling.t
    }

    /// Return the number of data symbols available to block `j`, `a_j`.
    pub fn data_symbols(&self, j: u32) -> u64 {
        a_j(self.d, self.leveling.nb, j)
    }

    /// Return the `(start, length)` byte range of block `j` within the input.
    ///
    /// `length` is at most [`Self::block_bytes`]; the caller must zero-pad the
    /// remaining bytes.
    pub fn block_span(&self, j: u32) -> (u64, u64) {
        let start = self.leveling.offset_j(j) * self.leveling.t;
        let len = self.block_bytes(j).min(self.oti.f.saturating_sub(start));
        (start, len)
    }

    /// Map data packet `c` to its packet slot: `i = c + floor(c/(M−1)) + 1`.
    ///
    /// Metadata packets do not consume data slots. This is the inverse of
    /// `counts::data_slot`; unit tests check the round trip.
    pub fn slot_of_data(&self, c: u64) -> u64 {
        c + c / (self.m - 1) + 1
    }

    /// Encode block `j` and deliver every data packet to
    /// `emit(slot, packet)`.
    ///
    /// `source` must be exactly `K_j·T` bytes, with the tail already
    /// zero-padded. `packet` is a complete `P`-byte packet (microheader,
    /// payload, and CRC) that is valid only for the duration of the `emit`
    /// call.
    ///
    /// Memory use is constant per block: one copy of the source symbols, the
    /// intermediate symbols, and one packet buffer. Repair symbols are
    /// generated in batches of 32, so peak use is about `3·K_j·T` regardless
    /// of `NB` or the total output size.
    pub fn encode_block<E>(
        &self,
        j: u32,
        source: &[u8],
        mut emit: impl FnMut(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let k = self.leveling.k_j(j);
        let t = self.leveling.t as usize;
        debug_assert_eq!(
            source.len() as u64,
            k * self.leveling.t,
            "block byte count must be exactly K_j·T"
        );
        let count = self.data_symbols(j);
        if count == 0 {
            return Ok(());
        }
        let nb = u64::from(self.leveling.nb);
        let oti = block_oti(k * self.leveling.t, self.leveling.t as u16);
        let encoder = SourceBlockEncoder::new(0, &oti, source);
        let mut packet = vec![0u8; self.p];

        // Source symbols 0..K_j are the systematic copy of the block, and
        // their payload is simply the corresponding slice of `source`. For a
        // single-sub-block configuration the crate builds source symbols as
        // `data.chunks(T)`, so no full-block clone is needed; the
        // `source_symbols_are_block_slices` test verifies this equivalence.
        let source_take = count.min(k);
        for esi in 0..source_take {
            let payload = &source[esi as usize * t..][..t];
            self.fill_data_packet(&mut packet, j, esi as u32, payload);
            emit(self.slot_of_data(esi * nb + u64::from(j)), &packet)?;
        }

        // Repair symbols start at ESI K_j in the container's ESI numbering.
        if count > k {
            let total_repairs = u32::try_from(count - k).expect("ESI must be within 2²⁴−1");
            const REPAIR_CHUNK: u32 = 32;
            let mut done = 0u32;
            while done < total_repairs {
                let n = REPAIR_CHUNK.min(total_repairs - done);
                let packets = encoder.repair_packets(done, n);
                for (i, repaired) in packets.iter().enumerate() {
                    let esi = k as u32 + done + i as u32;
                    self.fill_data_packet(&mut packet, j, esi, repaired.data());
                    emit(
                        self.slot_of_data(u64::from(esi) * nb + u64::from(j)),
                        &packet,
                    )?;
                }
                done += n;
            }
        }
        Ok(())
    }

    /// Build a data packet: a microheader with `is_meta = 0` and bit 1 set to
    /// `best_effort`, followed by the payload and CRC.
    fn fill_data_packet(&self, packet: &mut [u8], blk: u32, esi: u32, payload: &[u8]) {
        debug_assert_eq!(payload.len(), self.p - MICROHEADER_LEN);
        write_microheader(
            packet,
            &MicroHeader::new(false, self.best_effort, blk, esi, self.code),
        );
        packet[MICROHEADER_LEN..].copy_from_slice(payload);
        seal_packet(packet);
    }

    /// Return the encode summary, matching the value returned by [`encode_to`].
    pub fn summary(&self) -> EncodeSummary {
        EncodeSummary {
            oti: self.oti,
            leveling: self.leveling,
            c_total: self.c_total,
            total: self.total,
            c_meta: self.c_meta,
            d: self.d,
            best_effort: self.best_effort,
            redundancy: self.redundancy,
            default_total: self.default_total,
        }
    }

    /// Return an upper bound, in bytes, for the encoder's resident memory:
    /// `(3·min(jobs, NB) + 2)·max_j(K_j·T)`.
    ///
    /// The bound is structural. There are `min(jobs, NB)` workers, each holding
    /// about `3·K_j·T` (block buffer, the crate's copy of the source symbols,
    /// and intermediate symbols), plus one block buffer each for the reader and
    /// the channel. Note that `--max-mem` limits the per-block source budget
    /// (`K_j·T ≤ M_blk`), not this total.
    pub fn mem_hint_bytes(&self, jobs: usize) -> u64 {
        let workers = (jobs as u64).min(u64::from(self.leveling.nb)).max(1);
        (3 * workers + 2) * self.leveling.max_k() * self.leveling.t
    }
}

/// Run the second pass over the complete in-memory input and write `.lpw`
/// bytes to `out`.
///
/// `info` must come from [`prescan`] on the same input. If the lengths differ,
/// [`EncodeError::LengthMismatch`] is returned before anything is written.
///
/// This function shares its packet-generation core with the streaming path
/// ([`EncodePlan::encode_block`]), so both produce identical bytes. The output
/// is assembled in memory and written once; if any step fails, `out` receives
/// no bytes.
pub fn encode_to(
    info: &BlobInfo,
    data: &[u8],
    cfg: &EncodeConfig,
    out: &mut impl Write,
) -> Result<EncodeSummary, EncodeError> {
    // Pass 1 and pass 2 must see the same number of bytes. Content identity is
    // the caller's responsibility and is normally checked with the digest.
    let actual = data.len() as u64;
    if actual != info.f {
        return Err(EncodeError::LengthMismatch {
            expected: info.f,
            actual,
        });
    }
    let plan = plan(info, cfg)?;
    let total_bytes =
        plan.c_total
            .checked_mul(plan.p as u64)
            .ok_or(EncodeError::TotalBytesOverflow {
                c_total: plan.c_total,
                p: plan.p,
            })?;
    let total_bytes = usize::try_from(total_bytes).map_err(|_| LayoutDefect::Overflow)?;
    let mut buffer = vec![0u8; total_bytes];

    // Generate each block and place its packets by slot, using the same core
    // as the streaming path.
    for j in 0..plan.leveling.nb {
        let (start, len) = plan.block_span(j);
        let block_bytes = plan.block_bytes(j);
        let mut block = Vec::with_capacity(block_bytes as usize);
        block.extend_from_slice(&data[start as usize..(start + len) as usize]);
        block.resize(block_bytes as usize, 0);
        plan.encode_block(j, &block, |slot, packet| {
            let off = slot as usize * plan.p;
            buffer[off..off + packet.len()].copy_from_slice(packet);
            Ok::<(), EncodeError>(())
        })?;
    }
    for slot in plan.meta_slots() {
        let off = slot as usize * plan.p;
        buffer[off..off + plan.p].copy_from_slice(plan.meta_packet());
    }
    out.write_all(&buffer)?;
    Ok(plan.summary())
}

/// Encode an in-memory input by running both passes.
///
/// Return the complete `.lpw` byte stream and its summary. On failure no bytes
/// are returned, matching the zero-output guarantee of [`encode_to`].
pub fn encode(data: &[u8], cfg: &EncodeConfig) -> Result<(Vec<u8>, EncodeSummary), EncodeError> {
    let info = prescan(data);
    let mut bytes = Vec::new();
    let summary = encode_to(&info, data, cfg, &mut bytes)?;
    Ok((bytes, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::counts::data_slot;
    use crate::container::params::DEFAULT_PACKET_SIZE;

    fn cfg_default() -> EncodeConfig {
        EncodeConfig {
            p: DEFAULT_PACKET_SIZE,
            m: 256,
            k_max: 16_448,
            total: TotalSpec::Default,
            force: false,
        }
    }

    #[test]
    fn slot_of_data_is_inverse_of_data_slot() {
        // `slot_of_data(c)` and `counts::data_slot(i)` must be inverses,
        // including the jumps over metadata slots.
        let base = plan(
            &BlobInfo {
                f: 300_000,
                blake3: [0x11; BLAKE3_LEN],
            },
            &cfg_default(),
        )
        .expect("encode plan");
        let m = 256u64;
        for c in 0..1_000u64 {
            let i = base.slot_of_data(c);
            assert_eq!(data_slot(i, m), Some(c), "c={c} → i={i}");
            assert_ne!(i % m, 0, "data slots must not land on metadata slots");
        }
        // With the default settings C_total is about 79, so only slot 0 is
        // metadata.
        let slots: Vec<u64> = base.meta_slots().collect();
        assert_eq!(slots, vec![0]);
        // A larger output (C_total = 537) has metadata slots 0, 256, and 512.
        let big = plan(
            &BlobInfo {
                f: 300_000,
                blake3: [0x11; BLAKE3_LEN],
            },
            &EncodeConfig {
                total: TotalSpec::Size(2_200_000),
                ..cfg_default()
            },
        )
        .expect("encode plan");
        assert_eq!(
            big.meta_slots().take(3).collect::<Vec<_>>(),
            vec![0, 256, 512]
        );
    }

    #[test]
    fn source_symbols_are_block_slices() {
        // `encode_block` uses T-byte slices of `source` directly as source
        // symbol payloads, relying on the crate's `data.chunks(T)` construction
        // for a single-sub-block configuration. Verify the first three and the
        // last source symbol byte for byte via `source_packets()`.
        let (k, t) = (5usize, 8usize);
        let data: Vec<u8> = (0..k * t).map(|i| (i * 7 % 251) as u8).collect();
        let oti = block_oti((k * t) as u64, t as u16);
        let encoder = SourceBlockEncoder::new(0, &oti, &data);
        let packets = encoder.source_packets();
        assert_eq!(packets.len(), k);
        for esi in [0usize, 1, 2, k - 1] {
            assert_eq!(
                packets[esi].data(),
                &data[esi * t..(esi + 1) * t],
                "source symbol ESI={esi} must lie within the block"
            );
        }
    }

    #[test]
    fn streamed_block_placement_matches_encode_to() {
        // `EncodePlan::encode_block` plus slot placement must match `encode_to`
        // byte for byte, including multiple blocks and repair symbols
        // (NB = 2, K_j = 2, a_j > K_j).
        let data: Vec<u8> = (0..3 * 4_080 + 17).map(|i| (i % 251) as u8).collect();
        let info = prescan(&data);
        let cfg = EncodeConfig {
            p: DEFAULT_PACKET_SIZE,
            m: 4,
            k_max: 2,                           // 4 symbols → NB = 2
            total: TotalSpec::Size(32 * 4_096), // C_total = 32, D = 24 → 12 symbols/block
            force: false,
        };
        let (expected, _summary) = encode(&data, &cfg).expect("in-memory encoder");
        let plan = plan(&info, &cfg).expect("encode plan");
        let mut buffer = vec![0u8; (plan.c_total * plan.p as u64) as usize];
        for j in 0..plan.leveling.nb {
            let (start, len) = plan.block_span(j);
            let block_bytes = plan.block_bytes(j);
            let mut block = Vec::with_capacity(block_bytes as usize);
            block.extend_from_slice(&data[start as usize..(start + len) as usize]);
            block.resize(block_bytes as usize, 0);
            plan.encode_block(j, &block, |slot, packet| {
                let off = slot as usize * plan.p;
                buffer[off..off + packet.len()].copy_from_slice(packet);
                Ok::<(), EncodeError>(())
            })
            .expect("block encoding");
        }
        for slot in plan.meta_slots() {
            let off = slot as usize * plan.p;
            buffer[off..off + plan.p].copy_from_slice(plan.meta_packet());
        }
        assert_eq!(
            buffer, expected,
            "streaming path must match the in-memory encoder byte for byte"
        );
    }
}
