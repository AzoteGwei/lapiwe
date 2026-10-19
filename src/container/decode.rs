//! Streaming decode engine.
//!
//! This module consumes candidate frames that have already been located in the
//! input (each frame is the complete slice of exactly one packet) and performs
//! its own frame-level validation, including the CRC-32C check. Locating
//! candidates in an input stream is the job of [`crate::container::scan`]; the
//! on-disk ledger used here is implemented in [`crate::container::ledger`].
//!
//! # Responsibilities and storage semantics
//!
//! - **Dispatch and deduplication.** [`DecodeEngine::observe`] dispatches on
//!   `is_meta`: metadata goes to [`MetaTracker`], while data packets are
//!   deduplicated by `(BLK_IDX, ESI)` — the first copy is kept and later copies
//!   increment `dup`. Source-symbol deduplication is handled by the ledger's
//!   arrival bitmap (a `(BLK_IDX, ESI)` pair maps one-to-one onto the global
//!   source symbol index `offset_j + ESI`); repair-symbol deduplication uses the
//!   ledger key set. Packets that arrive before a baseline exists are held in a
//!   bounded buffer (budget plus a drop counter), validated against `NB` when the
//!   baseline is established, and then replayed. The storage strategy — write
//!   through, spill, or read-back — must not change deduplication, counters, or
//!   classification.
//! - **Write-through.** In the `Ready` state a source symbol with `esi < K_j` is
//!   written immediately at `(offset_j + esi) · T`. Zero padding of the trailing
//!   block is written as well and is trimmed by the final `set_len(F)` on the
//!   target.
//! - **Direct solve.** A block whose arrival bits are all set (all source symbols
//!   received) is considered solved immediately and bypasses the solver.
//! - **Budget and spill.** Repair symbols stay inline while the budget allows;
//!   once it is exhausted they are not dropped but appended to the spill store
//!   ([`crate::container::ledger`]). A spill write failure is reported as an I/O
//!   error through [`PacketDisposition::StorageFailed`]
//!   ([`DecodeEngine::storage_error`]) and makes the CLI exit with status 1. The
//!   pre-baseline `pending` buffer retains its bounded policy (budget plus a drop
//!   counter).
//! - **Settlement.** At end of stream [`DecodeEngine::wait_solve`] settles every
//!   block that is still unsolved using a bounded feed of `payload_cap =
//!   needed_j(K_j) + DROP_MARGIN` symbols: all covered source symbols first, then
//!   repair symbols in ascending ESI order (inline payloads are passed directly,
//!   spilled ones are `pread` by the worker). Repair symbols outside the window
//!   stay in the spill file and are not read. A failed batch is retried with a new
//!   window under bounded memory (a fresh `SourceBlockDecoder` per batch, released
//!   between batches; at most [`SETTLE_MAX_ATTEMPTS`] attempts). On success only
//!   the missing ESI symbols are filled with `T` bytes (trailing zeros at or past
//!   `F` are skipped); ranges that already hold data must not be rewritten.
//! - **Verification.** Once all `NB` blocks are solved, the product is read back
//!   (or hashed incrementally under `--stream`) and compared with BLAKE3. The CRC
//!   is only a fast rejection filter; BLAKE3 is authoritative.
//! - **Outcome.** The result is classified by
//!   [`crate::container::outcome::classify`] into one of five categories: `Ok`,
//!   `HashMismatch`, `Insufficient`, `Malformed`, or `NoOti`. The decode side
//!   only reports `max_j(K_j · T)` and never rejects an otherwise valid stream
//!   because of the local `M_blk`.
//!
//! # Baseline OTI
//!
//! A metadata packet that [`MetaTracker`] accepts as the baseline establishes the
//! baseline OTI: `F`, `T`, `NB`, and the BLAKE3 digest of the original object.
//! [`Leveling::derive`] then computes the block layout and `validate_format`
//! checks the format-level bounds. A layout that fails those checks puts the
//! engine in the `Malformed` state, in which data symbols are no longer consumed;
//! without any baseline the result is `NoOti`.
//!
//! # In-place patch mode
//!
//! [`DecodeEngine::with_patch`] (CLI `--patch`) treats readable source-symbol
//! ranges of `TARGET` as received side information. These ranges are trusted
//! without a preliminary check; the final BLAKE3 verification catches content
//! that does not match. The target scan runs in the frame that establishes the
//! baseline OTI, before the pre-baseline `pending` buffer is drained. Symbols that
//! intersect a declared missing range or that fail to read are conservatively
//! considered missing. In-stream symbols and solver write-backs go to the overlay
//! temporary backend inside [`PatchState`] (`--spool-dir`); `TARGET` itself is
//! written only by [`DecodeEngine::commit_patch`], after all blocks are solved,
//! and only for the missing symbol ranges (`min(T, F − off)` truncated; no writes
//! for `Insufficient`, `Malformed`, `NoOti`, or mode errors). The caller then
//! reads back the whole `TARGET` and compares BLAKE3 (a mismatch yields
//! `HashMismatch` and guidance text). [`SymbolSource`] distinguishes overlay from
//! `TARGET` when the solve task is extracted; workers never touch the `written`
//! bitmap.
//!
//! `Insufficient` means that a block was actually left unsolved (fewer than `K_j`
//! symbols so no attempt was made, or attempts failed), not that a solved block
//! was independently judged to have fewer than `needed_j` symbols. The latter
//! would contradict the rule that a fully solved stream succeeds (with
//! `--no-verify`), the direct path (a block is solved once it has all `K_j` source
//! symbols), and the rule that `best_effort` does not change the exit status.
//!
//! # Parallel solving
//!
//! With `jobs > 1` settlement starts `min(jobs, task count, resident limit /
//! (2 · max_j(K_j · T)))` workers in a `std::thread::scope`. Each worker preads
//! the covered source symbols and spilled repair symbols from the ledger and
//! writes back missing ranges itself; results (categories, statistics, product)
//! do not depend on `jobs`. `--jobs` remains only an upper bound: if a worker
//! cannot be started, settlement falls back to serial execution. The resident
//! memory is roughly
//! `min(jobs, NB, cap) · (2 · max_j(K_j · T) + o) + max_mem + O(S/8) + 32 MiB`,
//! where `O(S/8)` is the arrival bitmap (exempt from the budget) and `o` covers
//! per-batch window slack over `K_j` plus allocator overhead.
//!
//! # Memory budget
//!
//! [`DecodeEngine::with_budget`] sets the engine budget to `max_mem − RING_CAP`.
//! It covers the pre-baseline `pending` buffer and the ledger's inline repair
//! symbols (these phases do not overlap, so each stays within the budget). The
//! arrival bitmap (`S/8`, allocated lazily in chunks) and the deduplication key
//! sets (proportional to the number of received packets) are explicitly outside
//! that budget. Per-active-block solve residency of about `2 · K_j · T` is a
//! structural term. Block state has no budget-driven drop path.
//!
//! # `--stream` support
//!
//! [`DecodeEngine::take_solved_block`] reads solved blocks back from the ledger in
//! block order (trimmed to `F`), marks them `emitted`, and feeds their bytes into
//! an incremental BLAKE3 hash so that `finish` can still report the final
//! verification result. For CLI file publishing and stdout spooling the engine
//! writes directly to the target and the caller declares
//! [`DecodeEngine::set_external_verify`], verifying by reading the target back.
//! [`DecodeEngine::take_solved_block_any`] is intended for library tests and
//! consumers that accept blocks in arbitrary order.
//!
//! # Validation in the `Malformed` state
//!
//! When the baseline layout turns out to be malformed, data frames are still
//! checked against the baseline `T`: a frame of a different length is invalid and
//! causes the scanner to retract one byte, and it is counted in `bad_packets`.
//! Cached candidates of the wrong length are re-judged when the baseline is
//! established and treated as bad packets (they never enter a logical block).
//! Cached frames of the same length inside `[0, NB)` are simply reclaimed memory
//! and are not counted in `bad_packets`, whose definition remains "frames that
//! fail frame validation". Cached frames of the same length with `BLK_IDX ≥ NB`
//! are counted as bad packets, consistent with the drain and arrival paths.
//!
//! Decoding uses no randomness: the same input order produces the same result.
//! The patch commit phase (`commit_patch`) is a single-threaded sequential write,
//! so its result does not depend on `--jobs`.

use std::collections::BTreeMap;
use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use raptorq::{EncodingPacket, PayloadId, SourceBlockDecoder};

use crate::container::counts::needed_j;
use crate::container::encode::block_oti;
use crate::container::header::{FrameDefect, parse_header};
use crate::container::ledger::{
    ArrivalBits, Ledger, LedgerStore, RepairSlot, SPILL_HEADER_LEN, VecStore,
};
use crate::container::leveling::Leveling;
use crate::container::meta::{MetaDisposition, MetaStats, MetaTracker, Oti};
use crate::container::outcome::{DecodeOutcome, DecodeSignals, Verify, classify};
use crate::container::params::{DEFAULT_DECODE_MAX_MEM, MICROHEADER_LEN};
use crate::container::scan::RING_CAP;

/// Slack for the settlement feed window: `payload_cap =
/// needed_j(K_j) + DROP_MARGIN`.
///
/// After the baseline is established no drop path exists any more, so this
/// constant bounds the symbols fed to one settlement batch (all source symbols
/// first, then repair symbols in ascending ESI order; see [`settle_block`]).
pub const DROP_MARGIN: u64 = 32;

/// Maximum number of settlement attempts per block.
///
/// When a batch of `payload_cap` symbols fails, the solver retries with the next
/// repair-symbol window under bounded memory (a fresh [`SourceBlockDecoder`] per
/// batch, released between batches). If all attempts fail, the block stays
/// unsolved. The bound keeps worst-case I/O and memory at
/// `O(attempts × payload_cap · T)`.
pub const SETTLE_MAX_ATTEMPTS: usize = 8;

/// Resident-memory limit for settlement workers.
///
/// The worker count is derived from `2 · max_j(K_j · T)` per worker, capped so
/// that the default `--jobs` fan-out stays within roughly 512 MiB. `--jobs` is
/// still only an upper bound; the implementation may run serially.
pub const SETTLE_RESIDENT_LIMIT: u64 = 256 * 1024 * 1024;

/// Decoding configuration (`--no-verify`; other CLI options are interpreted by
/// the CLI layer in `src/cli/decode.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecodeConfig {
    /// `--no-verify`: skip the final BLAKE3 verification; classification uses
    /// [`Verify::Skipped`].
    pub no_verify: bool,
}

/// Engine-level decoding statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Total number of observed candidate frames, including invalid ones.
    pub packets: u64,
    /// Frames that fail frame validation plus data packets with `BLK_IDX ≥ NB`
    /// (the latter once `NB` is known).
    pub bad_packets: u64,
    /// Frames with non-zero high 5 bits of `PKT_CODE`; such frames are still
    /// interpreted from the low 3 bits and only counted, not rejected.
    pub rsv_nonzero: u64,
    /// Duplicate `(BLK_IDX, ESI)` pairs; the first copy is kept.
    pub dup: u64,
    /// Blocks solved directly because all source symbols were received.
    pub direct_blocks: u64,
    /// Blocks solved by the settlement solver.
    pub solved_blocks: u64,
    /// Baseline `NB` (0 until a baseline is established).
    pub total_blocks: u64,
    /// `max_j(K_j · T)` (0 until a valid layout is established).
    pub max_block_bytes: u64,
    /// At least one CRC-valid frame carried `best_effort = 1`.
    pub best_effort: bool,
    /// Frames rejected from `pending` because of the budget before the baseline
    /// was established.
    pub pending_dropped: u64,
    /// Legacy field: symbols whose payload was dropped because of the budget
    /// after the baseline was established.
    ///
    /// The drop path was removed: over-budget repair symbols are spilled, and a
    /// write failure is an I/O error. This field is therefore always 0 in the
    /// current engine and is kept for statistics-line compatibility.
    pub symbols_dropped: u64,
    /// Length of the first frame that passes frame validation (the `P` reported
    /// by inspect; `None` until one is observed).
    pub packet_size: Option<usize>,
    /// Bytes of source symbols written through to target offsets (including
    /// trailing-block zero padding).
    pub written_through_bytes: u64,
    /// Bytes staged on disk. On the decode side this is spilled repair-symbol
    /// payload; the CLI adds its stdout spool to the same counter.
    pub spooled_bytes: u64,
    /// Source symbols missing at settlement time: the sum of
    /// `K_j − received source symbols` over all `NB` blocks.
    pub missing_symbols: u64,
    /// Under `--patch`, blocks fully covered by readable `TARGET` source symbols
    /// (no solver, no stream); always 0 outside patch mode.
    pub patch_known_blocks: u64,
    /// Under `--patch`, source symbols missing from `TARGET` after the target scan
    /// (`S − readable symbols`). These must be recovered from the stream or by the
    /// solver and written back to `TARGET` at commit; always 0 outside patch mode.
    pub patch_missing_symbols: u64,
    /// Symbols written to `TARGET` by the patch commit; always 0 outside patch mode
    /// or before a commit.
    pub patched_symbols: u64,
    /// Bytes written to `TARGET` by the patch commit (the trailing symbol is
    /// truncated to `min(T, F − off)`); always 0 outside patch mode or before a
    /// commit.
    pub patched_bytes: u64,
    /// Number of contiguous ranges written by the patch commit (adjacent symbols
    /// are merged); always 0 outside patch mode.
    pub patched_ranges: u64,
}

impl DecodeStats {
    /// Return the number of solved blocks (direct, solver, and patch-covered
    /// targets).
    pub fn solved_total(&self) -> u64 {
        self.direct_blocks + self.solved_blocks + self.patch_known_blocks
    }
}

/// Location of a source symbol's payload, used to route solver read-back in patch
/// mode.
///
/// Invariant: `arrival[i] ∧ ¬written[i]` implies that the payload is in `TARGET`.
/// The target scan sets arrival bits before any in-stream symbol can do so, and
/// every in-stream write-through also records the symbol in `written`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolSource {
    /// The overlay backend used in `--patch` mode for in-stream arrivals and
    /// solver write-backs.
    Overlay,
    /// `TARGET`, read as patch side information.
    Target,
}

/// Mode errors for in-place patching (the CLI exits with status 1 and prints a
/// single line plus a hint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// `TARGET` length differs from `F`; after the baseline is established it must
    /// be exactly `F` bytes.
    TargetSizeMismatch {
        /// Measured length.
        actual: u64,
        /// Expected length `F`.
        expected: u64,
    },
    /// A declared missing range extends outside `[0, F]`.
    RangeOutOfBounds {
        /// Range start.
        start: u64,
        /// Range length.
        len: u64,
        /// Baseline `F`.
        f: u64,
    },
}

/// Result of the patch commit phase: only missing symbol ranges are written, and
/// only once all blocks are solved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PatchCommit {
    /// Number of symbols written to `TARGET`.
    pub symbols: u64,
    /// Number of bytes written to `TARGET` (the trailing symbol is truncated to
    /// `min(T, F − off)`).
    pub bytes: u64,
    /// Number of contiguous ranges written (adjacent symbols are merged).
    pub ranges: u64,
}

/// State for in-place patching (`--patch TARGET`).
#[derive(Debug)]
struct PatchState {
    /// `TARGET` backend: used for the scan read and the commit write. The engine
    /// does not write it before the commit.
    target: Arc<dyn LedgerStore>,
    /// Declared missing ranges in bytes, `[start, start + len)`; sorted and merged.
    missing_ranges: Vec<(u64, u64)>,
    /// Source symbols whose payload has been written to the overlay (global
    /// indexes, allocated lazily in chunks).
    written: ArrivalBits,
    /// Symbols readable during the target scan (side information).
    known_symbols: u64,
    /// Symbols conservatively marked missing because the target scan could not
    /// read them.
    read_failed_symbols: u64,
    /// Mode error (target size or range bounds); makes the CLI exit with status 1.
    error: Option<PatchError>,
    /// Commit result, filled in after a successful commit.
    commit: Option<PatchCommit>,
}

impl PatchState {
    /// Create the state, sorting and merging the declared missing ranges.
    ///
    /// Merge and bounds arithmetic use saturating addition throughout: inputs
    /// whose `START + LENGTH` overflows `u64` are rejected against `F` by
    /// [`patch_scan`]'s `checked_add`, so this function must not overflow. A debug
    /// panic would make behavior depend on the build profile.
    fn new(target: Arc<dyn LedgerStore>, mut missing_ranges: Vec<(u64, u64)>) -> Self {
        missing_ranges.retain(|&(_, len)| len > 0);
        missing_ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(missing_ranges.len());
        for (start, len) in missing_ranges {
            match merged.last_mut() {
                Some(last) if start <= last.0.saturating_add(last.1) => {
                    let end = last.0.saturating_add(last.1).max(start.saturating_add(len));
                    last.1 = end - last.0;
                }
                _ => merged.push((start, len)),
            }
        }
        PatchState {
            target,
            missing_ranges: merged,
            written: ArrivalBits::new(0),
            known_symbols: 0,
            read_failed_symbols: 0,
            error: None,
            commit: None,
        }
    }

    /// Return whether `[off, off + len)` intersects any declared missing range
    /// (ranges are sorted and merged; binary search).
    ///
    /// Intersection is tested rather than whether the start lies inside a range: a
    /// missing range may cover only the first bytes of a symbol, and that symbol
    /// still has to be recovered from the stream or by the solver, because writes
    /// always cover a whole `T`-byte symbol.
    fn overlaps_missing_range(&self, off: u64, len: u64) -> bool {
        let end = off.saturating_add(len);
        let idx = self.missing_ranges.partition_point(|&(s, _)| s < end);
        match idx.checked_sub(1) {
            Some(i) => {
                let (s, l) = self.missing_ranges[i];
                // Saturating addition is defensive: out-of-range ranges are rejected
                // by `patch_scan`, so normally `s + l ≤ F`.
                s.saturating_add(l) > off
            }
            None => false,
        }
    }
}

/// Read the `T`-byte payload of one source symbol.
///
/// The trailing symbol is truncated to `min(T, F − off)` and zero-padded. Offsets
/// at or beyond `F` yield all zeros; this is defensive because such source symbols
/// are not addressable.
fn read_symbol_padded(store: &dyn LedgerStore, off: u64, t: u64, f: u64) -> io::Result<Vec<u8>> {
    let mut payload = vec![0u8; t as usize];
    if off >= f {
        return Ok(payload);
    }
    let want = usize::try_from((f - off).min(t)).unwrap_or(usize::MAX);
    store.read_at(off, &mut payload[..want])?;
    Ok(payload)
}

/// Read-ahead limit for one target-scan block read.
///
/// At the default `T = 4080` this covers about 16 symbols. A release-build
/// calibration measured roughly 3.3–3.8 GB/s for per-symbol 4 KiB `pread` versus
/// 5.5–6.0 GB/s for 64 KiB block reads (see `tests/container_patch.rs`); larger
/// blocks (1–4 MiB) are no faster and inflate the scan buffer. The buffer is
/// constant-sized and does not affect the memory model.
const PATCH_SCAN_CHUNK_BYTES: usize = 64 * 1024;

/// Scan `TARGET` for readable source symbols.
///
/// This runs in the frame that establishes the baseline OTI; see
/// [`DecodeEngine::with_patch`]. The target is read in source-symbol intervals
/// (granularity `T`): a successful read sets the arrival bit as side information,
/// without write-through or validation. Unreadable symbols and symbols covered by
/// a declared missing range are conservatively considered missing. A block whose
/// source symbols are all readable is marked solved immediately and recorded in
/// `known_blocks` (the caller adds it to `ready`).
///
/// Reads are coalesced: consecutive symbols that do not intersect a missing range
/// are fetched with one `read_at` of at most [`PATCH_SCAN_CHUNK_BYTES`]. If a
/// block read fails, the same interval is retried symbol by symbol: only symbols
/// that read successfully set their arrival bit, and failures increment
/// `read_failed_symbols`. The result is identical to a strictly per-symbol scan,
/// so read coalescing does not weaken the conservative semantics, and symbols
/// covered by a missing range are still not read.
///
/// An `Err` return means that querying or reading the target failed (the CLI
/// exits with status 1). Mode errors (size mismatch, range out of bounds) are
/// stored in [`PatchState::error`] and the scan performs no reads.
fn patch_scan(
    patch: &mut PatchState,
    ledger: &mut Ledger,
    stats: &mut DecodeStats,
    blocks: &mut BTreeMap<u32, BlockState>,
    known_blocks: &mut Vec<u32>,
    layout: &Leveling,
    oti: &Oti,
) -> io::Result<()> {
    // Establish the bitmap first: subsequent in-stream writes and write-backs must
    // record `written`, which the commit phase uses to copy symbols into TARGET.
    patch.written = ArrivalBits::new(layout.s);
    patch.known_symbols = 0;
    patch.read_failed_symbols = 0;
    // TARGET must be exactly F bytes; on mismatch scan nothing, so a forged NB
    // cannot inflate read cost.
    let actual = patch.target.len()?;
    if actual != oti.f {
        patch.error = Some(PatchError::TargetSizeMismatch {
            actual,
            expected: oti.f,
        });
        return Ok(());
    }
    // A declared missing range outside [0, F] is a mode error.
    if let Some(&(start, len)) = patch
        .missing_ranges
        .iter()
        .find(|&&(start, len)| start.checked_add(len).is_none_or(|end| end > oti.f))
    {
        patch.error = Some(PatchError::RangeOutOfBounds {
            start,
            len,
            f: oti.f,
        });
        return Ok(());
    }
    let t = layout.t;
    let f = oti.f;
    let t_usize = usize::try_from(t)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "T exceeds usize"))?;
    // Read-ahead: one `read_at` covers up to PATCH_SCAN_CHUNK_BYTES of consecutive
    // symbols.
    let max_run = (PATCH_SCAN_CHUNK_BYTES / t_usize).max(1) as u64;
    let mut buf = vec![0u8; (max_run as usize) * t_usize];
    for j in 0..layout.nb {
        let k = layout.k_j(j);
        let offset = layout.offset_j(j);
        let mut known = 0u64;
        let mut e = 0u64;
        while e < k {
            let i = offset + e;
            let off = i * t;
            // Defensive skip for `off ≥ F`: such symbols are not addressable.
            if off >= f {
                break;
            }
            let sym_len = (f - off).min(t);
            if patch.overlaps_missing_range(off, sym_len) {
                // Do not read symbols covered by a missing range; a block read never
                // spans one.
                e += 1;
                continue;
            }
            // Coalesce consecutive symbols that remain readable and do not intersect
            // a missing range, without crossing `F`.
            let mut run = 1u64;
            while run < max_run.min(k - e) {
                let next_off = (i + run) * t;
                if next_off >= f {
                    break;
                }
                if patch.overlaps_missing_range(next_off, (f - next_off).min(t)) {
                    break;
                }
                run += 1;
            }
            let end = (off + run * t).min(f);
            let want = usize::try_from(end - off).unwrap_or(usize::MAX);
            match patch.target.read_at(off, &mut buf[..want]) {
                Ok(()) => {
                    for x in 0..run {
                        ledger.arrival_set(i + x);
                    }
                    known += run;
                }
                // The block read failed, so retry the interval symbol by symbol: only
                // a successful single-symbol read is trusted, and failures are
                // conservatively marked missing.
                Err(_) => {
                    for x in 0..run {
                        let so = (i + x) * t;
                        let sl = (f - so).min(t);
                        let w = usize::try_from(sl).unwrap_or(usize::MAX);
                        match patch.target.read_at(so, &mut buf[..w]) {
                            Ok(()) => {
                                ledger.arrival_set(i + x);
                                known += 1;
                            }
                            Err(_) => patch.read_failed_symbols += 1,
                        }
                    }
                }
            }
            e += run;
        }
        if known == 0 {
            continue;
        }
        patch.known_symbols += known;
        let block = blocks.entry(j).or_insert_with(|| BlockState::new(k, t));
        block.source_seen += known;
        if block.source_seen >= k && !block.solved {
            block.solved = true;
            stats.patch_known_blocks += 1;
            known_blocks.push(j);
        }
    }
    // Missing symbols after the target scan: these must be recovered from the stream
    // or by the solver and written back at commit.
    stats.patch_missing_symbols = layout.s.saturating_sub(patch.known_symbols);
    Ok(())
}

/// Disposition of a frame passed to [`DecodeEngine::observe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDisposition {
    /// Metadata candidate with its metadata-tracker disposition (accumulates
    /// `agree_meta`, `conflict`, and `bad_meta`).
    Meta(MetaDisposition),
    /// Data packet stored under `(BLK_IDX, ESI)`; `duplicate = true` means the
    /// first copy was kept and `dup` was incremented.
    Data { blk: u32, esi: u32, duplicate: bool },
    /// Frame-level invalid, or `BLK_IDX ≥ NB`: counted as a bad packet and not
    /// stored.
    Rejected(FrameDefect),
    /// The ledger failed while writing through or spilling. This is an I/O error
    /// (the CLI exits with status 1 and prints a single line plus a hint) and is
    /// never a silent drop.
    ///
    /// After the first failure the engine stays in the failed state and later
    /// `observe` calls return this disposition. Details are available through
    /// [`DecodeEngine::storage_error`].
    StorageFailed,
}

/// Reception and settlement state of one logical block.
///
/// The block does not keep payloads in memory: source symbols are written through
/// to the target as they arrive, and repair symbols go to the ledger. This
/// structure only tracks counters, the solved flag, and the emitted flag. Its
/// memory use is proportional to the number of blocks that received symbols.
#[derive(Debug)]
struct BlockState {
    /// `K_j`.
    k: u64,
    /// Symbol size `T`.
    t: u64,
    /// Number of source symbols whose arrival bit is set (`ESI ∈ [0, K_j)`); solver
    /// write-back does not set arrival bits.
    source_seen: u64,
    /// Number of distinct repair symbols registered (`ESI ≥ K_j`), including keys
    /// registered after the block was solved.
    repair_seen: u64,
    /// Whether the block is solved (directly, or by settlement write-back).
    solved: bool,
    /// Whether the solved bytes have been taken by
    /// [`DecodeEngine::take_solved_block`] or
    /// [`DecodeEngine::take_solved_block_any`]; being solved and `dup` accounting
    /// are unaffected.
    emitted: bool,
    /// Whether early settlement was submitted during the scan. A block is submitted
    /// at most once, and failures are covered by final settlement.
    early_submitted: bool,
}

impl BlockState {
    fn new(k: u64, t: u64) -> Self {
        BlockState {
            k,
            t,
            source_seen: 0,
            repair_seen: 0,
            solved: false,
            emitted: false,
            early_submitted: false,
        }
    }

    /// Return whether the block is solved (directly or by the solver); still true
    /// after its bytes are taken.
    fn is_solved(&self) -> bool {
        self.solved
    }
}

/// Result of accepting one symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Accepted {
    /// Deduplication: the first copy was kept and this frame counted as `dup`.
    duplicate: bool,
    /// This symbol completed the block's source symbols (direct solve).
    direct: bool,
    /// This symbol brought the block to the early-settle threshold
    /// (`needed_j(K_j)`), allowing settlement to overlap the scan.
    settle_ready: bool,
}

/// Shared symbol-acceptance path used in the `Ready` state by both the arrival
/// path and the pre-baseline drain.
///
/// Storage and accounting semantics:
///
/// - A source symbol (`esi < K_j`) is deduplicated through the arrival bitmap and
///   written through to `(offset_j + esi) · T`; `written_through_bytes` counts the
///   payload bytes. Receiving all `K_j` symbols solves the block directly without
///   invoking the solver.
/// - A repair symbol (`esi ≥ K_j`) is deduplicated through the ledger key set and
///   then either kept inline or spilled; `spooled_bytes` counts spilled payloads.
/// - A late symbol for an already solved block only registers its key (keeping the
///   key preserves correct `dup` accounting). A late source symbol still sets its
///   arrival bit and counts as new, but skips write-through, because ranges that
///   already hold data must not be rewritten. Solver write-back does not set
///   arrival bits, so `dup` accounting stays consistent with the direct path.
///
/// An `Err` return means that write-through or spilling failed; the caller reports
/// it as an I/O error instead of silently dropping the symbol.
struct AcceptCtx<'a> {
    ledger: &'a mut Ledger,
    stats: &'a mut DecodeStats,
    blocks: &'a mut BTreeMap<u32, BlockState>,
    /// Patch mode: the `written` bitmap records payloads held in the overlay.
    patch: Option<&'a mut PatchState>,
}

fn accept_symbol(
    ctx: AcceptCtx<'_>,
    layout: &Leveling,
    blk: u32,
    esi: u32,
    payload: Vec<u8>,
) -> io::Result<Accepted> {
    let AcceptCtx {
        ledger,
        stats,
        blocks,
        patch,
    } = ctx;
    let k = layout.k_j(blk);
    let t = layout.t;
    let block = blocks.entry(blk).or_insert_with(|| BlockState::new(k, t));
    debug_assert_eq!(block.k, k, "block-state K_j must match the layout");
    debug_assert_eq!(
        payload.len() as u64,
        block.t,
        "symbol payload length must equal T"
    );
    if block.solved {
        if u64::from(esi) < k {
            if ledger.arrival_set(layout.offset_j(blk) + u64::from(esi)) {
                stats.dup += 1;
                return Ok(Accepted {
                    duplicate: true,
                    direct: false,
                    settle_ready: false,
                });
            }
            block.source_seen += 1;
        } else if ledger.repair_contains(blk, esi) {
            stats.dup += 1;
            return Ok(Accepted {
                duplicate: true,
                direct: false,
                settle_ready: false,
            });
        } else {
            ledger.repair_insert_key_only(blk, esi);
            block.repair_seen += 1;
        }
        return Ok(Accepted {
            duplicate: false,
            direct: false,
            settle_ready: false,
        });
    }
    // Once a block holds `needed_j(K_j)` distinct symbols it may be submitted for
    // early settlement. The required symbol count comes from the RaptorQ
    // probability bound, and the submission point depends only on packet order, not
    // on worker timing.
    let settle_ready = |block: &BlockState| {
        !block.early_submitted && block.source_seen + block.repair_seen >= needed_j(k)
    };
    if u64::from(esi) < k {
        let bit = layout.offset_j(blk) + u64::from(esi);
        if ledger.arrival_set(bit) {
            stats.dup += 1;
            return Ok(Accepted {
                duplicate: true,
                direct: false,
                settle_ready: false,
            });
        }
        block.source_seen += 1;
        ledger.write_source(bit * t, &payload)?;
        if let Some(patch) = patch {
            // In patch mode the in-stream payload lives in the overlay; the commit
            // phase copies only symbols recorded in `written` into TARGET.
            patch.written.set(bit);
        }
        stats.written_through_bytes += payload.len() as u64;
        if block.source_seen == k {
            block.solved = true;
            stats.direct_blocks += 1;
            return Ok(Accepted {
                duplicate: false,
                direct: true,
                settle_ready: false,
            });
        }
    } else {
        if ledger.repair_contains(blk, esi) {
            stats.dup += 1;
            return Ok(Accepted {
                duplicate: true,
                direct: false,
                settle_ready: false,
            });
        }
        if ledger.repair_insert(blk, esi, payload)? {
            stats.spooled_bytes += t;
        }
        block.repair_seen += 1;
    }
    let settle_ready = settle_ready(block);
    Ok(Accepted {
        duplicate: false,
        direct: false,
        settle_ready,
    })
}

/// Engine state: baseline OTI and layout.
#[derive(Debug, Default)]
enum LayoutState {
    /// No metadata packet with a usable baseline has arrived yet (`NoOti`
    /// outcome).
    #[default]
    NoBaseline,
    /// A baseline exists but the derived layout violates format-level bounds
    /// (`Malformed` outcome).
    Malformed { oti: Oti },
    /// A baseline exists and the layout is valid.
    Ready {
        oti: Oti,
        layout: Leveling,
        /// Blocks that received symbols; entries are created lazily (nothing is
        /// preallocated from `NB`).
        blocks: BTreeMap<u32, BlockState>,
    },
}

/// Result of [`DecodeEngine::finish`]: outcome category, engine signals,
/// OTI/layout, and (when everything is solved) the assembled data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeSummary {
    /// Outcome category.
    pub outcome: DecodeOutcome,
    /// Signals used for classification.
    pub signals: DecodeSignals,
    /// Baseline OTI (`None` if not established).
    pub oti: Option<Oti>,
    /// Valid layout (`None` for `NoOti` or `Malformed`).
    pub layout: Option<Leveling>,
    /// Product read back when all blocks are solved and no bytes were taken
    /// incrementally or out of order (trimmed to `F`). The content is not
    /// trustworthy when the outcome is `HashMismatch`.
    pub data: Option<Vec<u8>>,
    /// Snapshot of engine statistics.
    pub stats: DecodeStats,
}

/// Solver input for one block awaiting settlement (extracted from the ledger by
/// the main thread; payload bytes are subject to the budget).
struct SettleTask {
    /// Block index `j`.
    j: u32,
    /// `K_j`.
    k: u64,
    /// Symbol size `T`.
    t: u64,
    /// `offset_j`.
    offset: u64,
    /// `F`; write-back skips trailing zeros at or past `F`.
    f: u64,
    /// Covered source symbols as `(ESI, payload location)`, ascending; in patch
    /// mode the location distinguishes overlay from `TARGET`.
    covered: Vec<(u32, SymbolSource)>,
    /// ESI values of missing source symbols (write-back targets), ascending.
    missing: Vec<u32>,
    /// Repair-symbol payloads, ascending: inline slots carry bytes directly, while
    /// spilled slots carry a location that the worker reads with `pread`.
    repairs: Vec<(u32, RepairSlot)>,
    /// Inline bytes retained (not released) on early submission; final settlement
    /// releases them at once. Always 0 on the final-settlement path, which releases
    /// inline slots when the task is extracted.
    inline_kept: u64,
}

/// Solver result: the decoded bytes of one whole block (`K_j · T`). The caller
/// writes back only the symbols that are still missing at that moment: final
/// settlement uses [`settle_block`], while early submissions are written back when
/// the engine drains results during the scan.
struct SolvedBlock {
    /// Decoded bytes (length `K_j · T`).
    bytes: Vec<u8>,
    /// Symbol size used by the solver. The early path does not re-solve at end of
    /// stream; it only writes back the symbols that are then missing.
    t: u64,
    /// `offset_j`.
    offset: u64,
    /// Missing ESI values, ascending.
    missing: Vec<u32>,
    /// `F`; trailing zeros at or past `F` are not written back.
    f: u64,
}

/// Solve one block: read a bounded set of inputs, feed one batch to a fresh
/// decoder, and return the decoded block bytes without writing them back.
///
/// Blocks with all source symbols present never reach this function; they are
/// solved directly. One batch holds at most `payload_cap = needed_j(K_j) +
/// DROP_MARGIN` symbols: all covered source symbols first, then repair symbols in
/// ascending ESI order. Repair symbols outside the window are not read and stay in
/// the spill file. If a batch fails, the next window is tried under bounded memory
/// (a fresh decoder per batch, released between batches; at most
/// [`SETTLE_MAX_ATTEMPTS`] attempts).
///
/// `Ok(None)` means there were too few symbols or every window failed, so the block
/// remains unsolved.
fn solve_block(
    task: SettleTask,
    store: &dyn LedgerStore,
    spill: &dyn LedgerStore,
    target: Option<&dyn LedgerStore>,
) -> io::Result<Option<SolvedBlock>> {
    let SettleTask {
        j: _,
        k,
        t: t_raw,
        offset,
        f,
        covered,
        missing,
        mut repairs,
        inline_kept: _,
    } = task;
    let block_len = k * t_raw;
    // One-batch window: `payload_cap − covered source symbols`, with a floor of 1.
    let cap = needed_j(k).saturating_add(DROP_MARGIN);
    let window =
        usize::try_from(cap.saturating_sub(covered.len() as u64).max(1)).unwrap_or(usize::MAX);
    let mut start = 0usize;
    for _ in 0..SETTLE_MAX_ATTEMPTS {
        if start >= repairs.len() {
            // No repair symbols left to try (or there were none).
            break;
        }
        let end = start.saturating_add(window).min(repairs.len());
        // Known limitation: when a batch fails, inline payloads taken from that batch
        // are not carried into the next window (`RepairSlot::Inline` is left empty
        // after `take`). Spilled slots remain readable through `SpillLoc` and are
        // unaffected. The first batch holds at least `needed_j + 32` symbols, so the
        // first attempt nearly always succeeds on high-redundancy streams; the chance
        // of needing a retry whose first batch contains inline symbols is about
        // 1e-10. Failed batches are not retained, keeping the per-worker memory bound
        // at one batch of symbols plus the decoded result.
        let mut symbols: Vec<(u32, Vec<u8>)> = Vec::with_capacity(covered.len() + (end - start));
        for &(esi, source) in &covered {
            // The trailing symbol is truncated to `min(T, F − off)` and zero-padded:
            // TARGET is exactly `F` bytes, so the final symbol's zero padding is not
            // stored in the file.
            let payload = match source {
                SymbolSource::Overlay => {
                    read_symbol_padded(store, (offset + u64::from(esi)) * t_raw, t_raw, f)?
                }
                SymbolSource::Target => match target {
                    Some(target) => {
                        read_symbol_padded(target, (offset + u64::from(esi)) * t_raw, t_raw, f)?
                    }
                    None => {
                        // Defensive: a Target source can only be produced in patch
                        // mode, when the task is extracted.
                        return Err(io::Error::other(
                            "patch source symbol is missing the TARGET backend",
                        ));
                    }
                },
            };
            symbols.push((esi, payload));
        }
        for (esi, slot) in repairs[start..end].iter_mut() {
            let (esi, payload) = match slot {
                RepairSlot::Inline(payload) => {
                    // An empty inline slot means key-only registration (a late symbol
                    // for a solved block, or re-registration after an early take).
                    // There is no payload to feed, and a valid payload can never be
                    // empty.
                    if payload.is_empty() {
                        continue;
                    }
                    (*esi, std::mem::take(payload))
                }
                RepairSlot::Spilled(loc) => {
                    let mut payload = vec![0u8; loc.len as usize];
                    spill.read_at(loc.off + SPILL_HEADER_LEN as u64, &mut payload)?;
                    (*esi, payload)
                }
            };
            symbols.push((esi, payload));
        }
        start = end;
        symbols.sort_by_key(|&(esi, _)| esi);
        let oti = block_oti(block_len, t_raw as u16);
        let mut decoder = SourceBlockDecoder::new(0, &oti, block_len);
        let packets = symbols
            .into_iter()
            .map(|(esi, payload)| EncodingPacket::new(PayloadId::new(0, esi), payload));
        let Some(bytes) = decoder.decode(packets) else {
            // This window was insufficient or failed; try the next one. The batch
            // symbols are released before the retry.
            continue;
        };
        return Ok(Some(SolvedBlock {
            bytes,
            t: t_raw,
            offset,
            missing,
            f,
        }));
    }
    Ok(None)
}

/// Write back the payloads of the missing ESI values.
///
/// The trailing symbol is truncated to `min(T, F − off)`: the normal path trims
/// zero padding with the final `set_len(F)`, while a patch `TARGET` must stay
/// exactly `F` bytes.
///
/// The `off ≥ F` branch is unreachable for missing symbols: their global index is
/// at most `S − 1`, so `off ≤ (S − 1) · T < S · T` and `S = ceil(F / T)` implies
/// `(S − 1) · T < F`. The check is kept defensively. Returns the ESI values that
/// were actually written, in ascending order, so the patch commit can record them
/// in `written`.
fn write_back_missing(
    bytes: &[u8],
    t: u64,
    offset: u64,
    f: u64,
    missing: &[u32],
    store: &dyn LedgerStore,
) -> io::Result<Vec<u32>> {
    let mut written = Vec::with_capacity(missing.len());
    for &esi in missing {
        let off = (offset + u64::from(esi)) * t;
        if off >= f {
            continue;
        }
        let start = (u64::from(esi) * t) as usize;
        let want = usize::try_from((f - off).min(t)).unwrap_or(usize::MAX);
        store.write_at(off, &bytes[start..start + want])?;
        written.push(esi);
    }
    Ok(written)
}

/// Result of settling one block at end of stream.
struct SettleOutcome {
    /// The block was solved and its missing ranges were written back.
    solved: bool,
    /// Missing ESI values actually written back, ascending; patch mode records
    /// them in `written`.
    written: Vec<u32>,
}

/// Settle one block at end of stream: solve it and write back only the missing ESI
/// values.
///
/// `Ok(SettleOutcome { solved: false, .. })` means there were too few symbols or
/// every window failed, so the block remains unsolved.
fn settle_block(
    task: SettleTask,
    store: &dyn LedgerStore,
    spill: &dyn LedgerStore,
    target: Option<&dyn LedgerStore>,
) -> io::Result<SettleOutcome> {
    match solve_block(task, store, spill, target)? {
        Some(solved) => {
            let written = write_back_missing(
                &solved.bytes,
                solved.t,
                solved.offset,
                solved.f,
                &solved.missing,
                store,
            )?;
            Ok(SettleOutcome {
                solved: true,
                written,
            })
        }
        None => Ok(SettleOutcome {
            solved: false,
            written: Vec::new(),
        }),
    }
}

/// Main loop of a settlement worker: take tasks from the shared queue, settle them,
/// and store the results.
fn settle_worker(
    queue: &Mutex<VecDeque<SettleTask>>,
    results: &Mutex<Vec<(u32, io::Result<SettleOutcome>)>>,
    store: &dyn LedgerStore,
    spill: &dyn LedgerStore,
    target: Option<&dyn LedgerStore>,
) {
    loop {
        let task = match queue.lock() {
            Ok(mut queue) => queue.pop_front(),
            Err(_) => break,
        };
        let Some(task) = task else {
            break;
        };
        let j = task.j;
        let outcome = settle_block(task, store, spill, target);
        match results.lock() {
            Ok(mut results) => results.push((j, outcome)),
            Err(_) => break,
        }
    }
}

/// Run settlement tasks: with `workers > 1` use `std::thread::scope` (the calling
/// thread also consumes tasks), otherwise run serially. If a worker cannot be
/// started, execution silently falls back to serial because `--jobs` is only an
/// upper bound.
fn run_settle_tasks(
    tasks: Vec<SettleTask>,
    workers: usize,
    store: &dyn LedgerStore,
    spill: &dyn LedgerStore,
    target: Option<&dyn LedgerStore>,
) -> Vec<(u32, io::Result<SettleOutcome>)> {
    if workers <= 1 || tasks.len() <= 1 {
        return tasks
            .into_iter()
            .map(|task| {
                let j = task.j;
                (j, settle_block(task, store, spill, target))
            })
            .collect();
    }
    let queue = Mutex::new(VecDeque::from(tasks));
    let results = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for w in 0..workers {
            // Test injection: exercise the serial fallback when a worker cannot be
            // started.
            #[cfg(test)]
            if FORCE_SETTLE_SPAWN_FAILURE.with(std::cell::Cell::get) {
                break;
            }
            let spawned = thread::Builder::new()
                .name(format!("lapiwe-settle-{w}"))
                .spawn_scoped(scope, || {
                    settle_worker(&queue, &results, store, spill, target)
                })
                .is_ok();
            if !spawned {
                break;
            }
        }
        // The calling thread consumes too, so a total spawn failure degrades to
        // serial execution.
        settle_worker(&queue, &results, store, spill, target);
    });
    match results.into_inner() {
        Ok(results) => results,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Read the first `f` bytes of the product.
///
/// In normal mode this is one read of `f` bytes from the ledger backend. In patch
/// mode each symbol is read from the overlay or from `TARGET` according to the
/// `written` bitmap, which yields the patched product both before and after the
/// commit.
fn read_product_bytes(
    store: &dyn LedgerStore,
    patch: Option<&PatchState>,
    layout: Option<&Leveling>,
    f: u64,
) -> io::Result<Vec<u8>> {
    let Some((patch, layout)) = patch.zip(layout) else {
        let mut data = vec![0u8; usize::try_from(f).unwrap_or(usize::MAX)];
        store.read_at(0, &mut data)?;
        return Ok(data);
    };
    let mut out = Vec::with_capacity(usize::try_from(f).unwrap_or(0));
    let mut i = 0u64;
    while i < layout.s {
        let off = i * layout.t;
        if off >= f {
            break;
        }
        let want = usize::try_from((f - off).min(layout.t)).unwrap_or(usize::MAX);
        let src: &dyn LedgerStore = if patch.written.get(i) {
            store
        } else {
            &*patch.target
        };
        let start = out.len();
        out.resize(start + want, 0u8);
        src.read_at(off, &mut out[start..])?;
        i += 1;
    }
    Ok(out)
}

/// Early settlement result: `(block index, solve result, inline bytes retained by
/// the early take)`.
type EarlyResult = (u32, io::Result<Option<SolvedBlock>>, u64);

/// Early-settlement pool used during scanning to overlap solving with input
/// processing.
///
/// A block is submitted for settlement as soon as it holds `needed_j(K_j)`
/// distinct symbols; workers pread source and spilled repair symbols themselves
/// while the scan continues. The main thread drains decoded blocks during the next
/// [`DecodeEngine::observe`] call, writes back only the ESI values that are still
/// missing at that point (trailing zeros at or past `F` are skipped), and releases
/// the decoded bytes. Final settlement closes and joins the pool before taking its
/// final snapshot.
///
/// Memory: in-flight tasks are limited to the worker count by an atomic gate, and
/// each task carries the inline payloads of its window. One worker's peak is about
/// one batch of symbols plus the decoded result, matching the per-worker
/// `2 · max_j(K_j · T)` term of the memory model.
struct EarlyPool {
    /// Task queue; workers compete for tasks.
    queue: Arc<(Mutex<VecDeque<SettleTask>>, Condvar)>,
    /// Results as `(block index, result, inline bytes retained by the early take)`.
    results: Arc<Mutex<Vec<EarlyResult>>>,
    /// Closed flag; set by final settlement, after which workers exit once the
    /// queue is empty.
    closed: Arc<AtomicBool>,
    /// In-flight task count. At the worker count, scanning stops submitting and
    /// leaves blocks to final settlement.
    inflight: Arc<AtomicUsize>,
    /// Number of results produced but not yet drained (triggers draining).
    pending: Arc<AtomicUsize>,
    /// Number of workers actually started.
    workers: usize,
    /// Worker handles, joined by final settlement.
    handles: Vec<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for EarlyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EarlyPool")
            .field("workers", &self.workers)
            .field("inflight", &self.inflight.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl EarlyPool {
    /// Submit a task; return `false` if the pool is already closed (the caller
    /// returns the slot).
    fn submit(&self, task: SettleTask) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let (lock, cv) = &*self.queue;
        lock.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(task);
        self.inflight.fetch_add(1, Ordering::SeqCst);
        cv.notify_one();
        true
    }

    /// Close the pool and join: wake all workers, wait for the queue to drain, and
    /// return results that were not drained.
    fn close_and_join(self) -> Vec<EarlyResult> {
        self.closed.store(true, Ordering::SeqCst);
        {
            let (_lock, cv) = &*self.queue;
            cv.notify_all();
        }
        for handle in self.handles {
            let _ = handle.join();
        }
        match Arc::try_unwrap(self.results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
            Err(shared) => std::mem::take(&mut *shared.lock().unwrap_or_else(|e| e.into_inner())),
        }
    }
}

/// Shared context for early-settlement workers (queue, results, gates, and storage
/// handles; distributed as `Arc` clones).
#[derive(Clone)]
struct EarlyWorkerCtx {
    queue: Arc<(Mutex<VecDeque<SettleTask>>, Condvar)>,
    results: Arc<Mutex<Vec<EarlyResult>>>,
    closed: Arc<AtomicBool>,
    inflight: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    store: Arc<dyn LedgerStore>,
    spill: Arc<dyn LedgerStore>,
    /// Patch-mode `TARGET` handle, used to re-read side information.
    target: Option<Arc<dyn LedgerStore>>,
}

/// Early-settlement worker: take a task, solve it without write-back, and publish
/// the result.
fn early_worker(ctx: EarlyWorkerCtx) {
    let EarlyWorkerCtx {
        queue,
        results,
        closed,
        inflight,
        pending,
        store,
        spill,
        target,
    } = ctx;
    loop {
        let task = {
            let (lock, cv) = &*queue;
            let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(task) = queue.pop_front() {
                    break task;
                }
                if closed.load(Ordering::SeqCst) {
                    return;
                }
                queue = cv.wait(queue).unwrap_or_else(|e| e.into_inner());
            }
        };
        let j = task.j;
        let inline_kept = task.inline_kept;
        let outcome = solve_block(task, store.as_ref(), spill.as_ref(), target.as_deref());
        if let Ok(mut results) = results.lock() {
            results.push((j, outcome, inline_kept));
        }
        inflight.fetch_sub(1, Ordering::SeqCst);
        pending.fetch_add(1, Ordering::SeqCst);
    }
}

/// Streaming decode engine that consumes candidate frames in input byte order.
#[derive(Debug)]
pub struct DecodeEngine {
    tracker: MetaTracker,
    state: LayoutState,
    /// Data packets received before a baseline exists: `(BLK_IDX, ESI)` to payload,
    /// deduplicated with the first copy kept.
    pending: BTreeMap<(u32, u32), Vec<u8>>,
    /// Engine-side payload budget: `max_mem − RING_CAP`, since the scan ring is a
    /// static deduction.
    budget: u64,
    /// Payload bytes currently held in `pending`, used for the budget check.
    pending_bytes: u64,
    /// Decode ledger: write-through target, spill backend, arrival bitmap, and
    /// repair-symbol table.
    ledger: Ledger,
    /// `--stream`: index of the next block to take (`0..NB`).
    stream_next: u32,
    /// `--stream`: incremental BLAKE3 over the bytes taken so far, trimmed to `F`.
    stream_hasher: blake3::Hasher,
    /// `--stream`: number of bytes taken and hashed (always ≤ `F`).
    stream_hashed: u64,
    /// Block bytes were taken out of order by
    /// [`DecodeEngine::take_solved_block_any`], or the caller declared its own
    /// read-back verification through [`DecodeEngine::set_external_verify`]. The
    /// engine no longer holds the full product, so the caller must verify before
    /// publishing.
    external_verify: bool,
    /// Decode parallelism limit (`--jobs`). The settlement worker count is capped by
    /// `min(jobs, task count, SETTLE_RESIDENT_LIMIT / (2 · max_j(K_j · T)))`;
    /// startup failure falls back to serial execution with identical results.
    jobs: usize,
    /// Solved blocks not yet taken (fast path for
    /// [`DecodeEngine::take_solved_block_any`]; stream takes and stale entries are
    /// filtered lazily by the take side). Maintained in serial mode as well.
    ready: Vec<u32>,
    /// Whether settlement already ran; [`DecodeEngine::wait_solve`] and
    /// [`DecodeEngine::finish`] are idempotent.
    settled: bool,
    /// Early-settlement pool, created lazily when `jobs > 1` and closed and joined
    /// by final settlement.
    early: Option<EarlyPool>,
    /// Blocks solved early; draining writes back only symbols still missing, and
    /// `solved` classification and counters are finalized at end of stream.
    early_solved: BTreeSet<u32>,
    /// Inline bytes retained by early takes, released in one step at final
    /// settlement.
    early_inline_kept: u64,
    /// First ledger I/O error (write-through, spill, or read-back); once set, the
    /// engine is in the failed state.
    storage_error: Option<io::Error>,
    stats: DecodeStats,
    /// In-place patch state (`--patch`; `None` in normal mode).
    patch: Option<PatchState>,
}

// Test injection (only under `cfg(test)`): when true, settlement workers are never
// started and the pure serial fallback is used. Thread-local, so other parallel
// tests in the same process are unaffected.
#[cfg(test)]
thread_local! {
    static FORCE_SETTLE_SPAWN_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl Default for DecodeEngine {
    /// Equivalent to [`DecodeEngine::new`] (default budget
    /// [`DEFAULT_DECODE_MAX_MEM`]). Implemented manually because a derived
    /// `Default` would leave `budget = 0`.
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeEngine {
    /// Create an engine with no baseline OTI, the default budget
    /// [`DEFAULT_DECODE_MAX_MEM`] (64 MiB, CLI `--max-mem`), serial settlement
    /// (`jobs = 1`), and in-memory ledger backends ([`VecStore`]). The CLI
    /// production path supplies file-backed stores instead.
    pub fn new() -> Self {
        Self::with_budget(DEFAULT_DECODE_MAX_MEM)
    }

    /// Create an engine with a total decode budget of `max_mem` bytes.
    ///
    /// The engine budget is `max_mem − RING_CAP` (the scan window is a static
    /// deduction) and covers the pre-baseline `pending` buffer and inline repair
    /// symbols. The arrival bitmap and deduplication key sets are outside that
    /// budget. Uses in-memory ledger backends and serial settlement.
    pub fn with_budget(max_mem: u64) -> Self {
        Self::with_budget_jobs(max_mem, 1)
    }

    /// Like [`DecodeEngine::with_budget`] but with an explicit `jobs` parallelism
    /// limit.
    ///
    /// With `jobs > 1` blocks are settled in parallel: each worker preads its
    /// inputs from the ledger and writes back missing ranges itself. Results, exit
    /// status, and statistics do not depend on `jobs`; `jobs = 1` runs serially with
    /// the same semantics.
    pub fn with_budget_jobs(max_mem: u64, jobs: usize) -> Self {
        Self::with_store(
            Box::new(VecStore::new()),
            Box::new(VecStore::new()),
            max_mem,
            jobs,
        )
    }

    /// Create an engine with explicit ledger backends.
    ///
    /// `store` receives write-through data and is read back for verification (a
    /// temporary output file, the stdout spool, or the patch `TARGET`), while
    /// `spill` holds repair symbols that exceed the budget (a temporary file under
    /// `--spool-dir`).
    ///
    /// Budget and engine semantics are those of
    /// [`DecodeEngine::with_budget_jobs`].
    pub fn with_store(
        store: Box<dyn LedgerStore>,
        spill: Box<dyn LedgerStore>,
        max_mem: u64,
        jobs: usize,
    ) -> Self {
        let budget = max_mem.saturating_sub(RING_CAP as u64);
        DecodeEngine {
            tracker: MetaTracker::default(),
            state: LayoutState::default(),
            pending: BTreeMap::new(),
            budget,
            pending_bytes: 0,
            ledger: Ledger::new(store, spill, budget),
            stream_next: 0,
            stream_hasher: blake3::Hasher::new(),
            stream_hashed: 0,
            external_verify: false,
            jobs,
            ready: Vec::new(),
            settled: false,
            early: None,
            early_solved: BTreeSet::new(),
            early_inline_kept: 0,
            storage_error: None,
            stats: DecodeStats::default(),
            patch: None,
        }
    }

    /// Create an in-place patch engine (CLI `--patch TARGET`).
    ///
    /// - `store` is the overlay temporary backend for in-stream source write-through
    ///   and solver write-back (a temporary file under `--spool-dir`);
    /// - `spill` is the repair-symbol spill backend;
    /// - `target` is `TARGET`: scanned read-only, then written with the missing
    ///   ranges by [`DecodeEngine::commit_patch`] once all blocks are solved. The
    ///   engine does not write it before that point;
    /// - `missing_ranges` are the explicit `--missing-ranges` byte intervals
    ///   `[start, start + len)`. Out-of-bounds ranges are reported as
    ///   [`PatchError::RangeOutOfBounds`] when the baseline is established.
    ///
    /// The target scan runs synchronously in the frame that establishes the baseline
    /// OTI, before the pre-baseline `pending` buffer is drained, and registers
    /// readable source symbols as known side information without write-through or
    /// validation.
    pub fn with_patch(
        store: Box<dyn LedgerStore>,
        spill: Box<dyn LedgerStore>,
        target: Box<dyn LedgerStore>,
        missing_ranges: Vec<(u64, u64)>,
        max_mem: u64,
        jobs: usize,
    ) -> Self {
        let mut engine = Self::with_store(store, spill, max_mem, jobs);
        engine.patch = Some(PatchState::new(Arc::from(target), missing_ranges));
        engine
    }

    /// Return the patch mode error (target size or range bounds), or `None` if there
    /// is none or the engine is not in patch mode.
    ///
    /// The CLI checks this after scanning and before settlement, then prints a
    /// single-line error with a hint (exit status 1).
    pub fn patch_error(&self) -> Option<&PatchError> {
        self.patch.as_ref().and_then(|p| p.error.as_ref())
    }

    /// Return the commit result, or `None` until [`DecodeEngine::commit_patch`]
    /// succeeds.
    pub fn patch_commit(&self) -> Option<&PatchCommit> {
        self.patch.as_ref().and_then(|p| p.commit.as_ref())
    }

    /// Number of symbols conservatively marked missing because the target scan could
    /// not read them (patch mode; diagnostic).
    pub fn patch_read_failed_symbols(&self) -> u64 {
        self.patch.as_ref().map_or(0, |p| p.read_failed_symbols)
    }

    /// Return whether the engine runs in `--patch` mode.
    pub fn is_patch_mode(&self) -> bool {
        self.patch.is_some()
    }

    /// Return where the payload of source symbol `i` is stored (always
    /// [`SymbolSource::Overlay`] outside patch mode).
    fn symbol_source(&self, i: u64) -> SymbolSource {
        match &self.patch {
            Some(p) if !p.written.get(i) => SymbolSource::Target,
            _ => SymbolSource::Overlay,
        }
    }

    /// Read back the product bytes of block `j`, trimmed to `F`.
    ///
    /// Normal mode reads the ledger backend in one call. Patch mode dispatches each
    /// symbol to the overlay or `TARGET` according to the `written` bitmap.
    fn read_block_product(&self, j: u32) -> io::Result<Vec<u8>> {
        let LayoutState::Ready { oti, layout, .. } = &self.state else {
            return Err(io::Error::other(
                "reading a block back requires an established layout",
            ));
        };
        if self.patch.is_none() {
            return read_block_bytes(self.ledger.store(), oti, layout, j);
        }
        let off = layout.offset_j(j) * layout.t;
        let want = usize::try_from((layout.k_j(j) * layout.t).min(oti.f.saturating_sub(off)))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "block length exceeds usize")
            })?;
        let mut bytes = Vec::with_capacity(want);
        let mut i = layout.offset_j(j);
        while bytes.len() < want {
            let sym_off = i * layout.t;
            let src: &dyn LedgerStore = match &self.patch {
                Some(p) if !p.written.get(i) => &*p.target,
                _ => self.ledger.store(),
            };
            let payload = read_symbol_padded(src, sym_off, layout.t, oti.f)?;
            let take = (want - bytes.len()).min(payload.len());
            bytes.extend_from_slice(&payload[..take]);
            i += 1;
        }
        Ok(bytes)
    }

    /// Read the first `f` bytes of the product (patch mode dispatches through the
    /// `written` bitmap). Record the first I/O error in `storage_error` and return
    /// `None` on failure.
    fn read_back_product(&mut self, f: u64) -> Option<Vec<u8>> {
        let layout = match &self.state {
            LayoutState::Ready { layout, .. } => Some(*layout),
            _ => None,
        };
        let result =
            read_product_bytes(self.ledger.store(), self.patch.as_ref(), layout.as_ref(), f);
        match result {
            Ok(data) => Some(data),
            Err(e) => {
                self.storage_error.get_or_insert(e);
                None
            }
        }
    }

    /// Return the engine-side budget (`max_mem − RING_CAP`); for tests and
    /// diagnostics.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Return the decode ledger (write-through, read-back, and spill state); for
    /// tests and diagnostics.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Return the first ledger I/O error (write-through, spill, or read-back).
    ///
    /// Once set, `observe` always returns [`PacketDisposition::StorageFailed`] and
    /// the CLI exits with status 1 (single line plus a hint).
    pub fn storage_error(&self) -> Option<&io::Error> {
        self.storage_error.as_ref()
    }

    /// Return a snapshot of the current statistics.
    pub fn stats(&self) -> DecodeStats {
        self.stats
    }

    /// Return metadata statistics (`agree_meta`, `conflict`, `bad_meta`).
    pub fn meta_stats(&self) -> MetaStats {
        self.tracker.stats()
    }

    /// Return the baseline OTI, or `None` until one is established.
    pub fn baseline_oti(&self) -> Option<Oti> {
        self.tracker.baseline_oti()
    }

    /// Return the established valid layout.
    pub fn layout(&self) -> Option<&Leveling> {
        match &self.state {
            LayoutState::Ready { layout, .. } => Some(layout),
            _ => None,
        }
    }

    /// Observe one candidate frame (a complete slice of exactly `P` bytes) and
    /// return its disposition.
    pub fn observe(&mut self, packet: &[u8]) -> PacketDisposition {
        // Drain early-settlement results during scanning; only take the lock when
        // results are ready.
        if self
            .early
            .as_ref()
            .is_some_and(|pool| pool.pending.load(Ordering::Relaxed) > 0)
        {
            self.drain_early_results();
        }
        if self.storage_error.is_some() {
            // Already failed: stop consuming input; the CLI exits with an I/O error
            // after the scan.
            return PacketDisposition::StorageFailed;
        }
        self.stats.packets += 1;
        let header = match parse_header(packet) {
            Ok(header) => header,
            Err(defect) => {
                // Invalid at frame level (CRC failure or structural overrun): count a
                // bad packet and do not store it.
                self.stats.bad_packets += 1;
                return PacketDisposition::Rejected(defect);
            }
        };
        // Record the length of the first frame that passes frame validation; inspect
        // reports it as `P`.
        if self.stats.packet_size.is_none() {
            self.stats.packet_size = Some(packet.len());
        }
        // The best_effort bit is consistent within a stream; ORing tolerates a
        // truncated stream.
        if header.best_effort() {
            self.stats.best_effort = true;
        }
        // Non-zero high 5 bits of `PKT_CODE` are only counted; frame interpretation is
        // unchanged.
        if header.rsv_nonzero() {
            self.stats.rsv_nonzero += 1;
        }
        if header.is_meta() {
            // Metadata drives the baseline state machine; establishing a baseline
            // initializes the layout.
            let disposition = self.tracker.observe(packet);
            if disposition == MetaDisposition::Baseline {
                if let Some(oti) = self.tracker.baseline_oti() {
                    self.establish_layout(oti);
                }
            }
            return PacketDisposition::Meta(disposition);
        }
        match &mut self.state {
            LayoutState::Ready { layout, blocks, .. } => {
                if header.blk_idx >= layout.nb {
                    // Once a baseline exists, data packets with BLK_IDX ≥ NB are
                    // invalid.
                    self.stats.bad_packets += 1;
                    return PacketDisposition::Rejected(FrameDefect::BlockOutOfRange);
                }
                if (packet.len() - MICROHEADER_LEN) as u64 != layout.t {
                    // The symbol length of a data packet must equal the baseline T. A
                    // valid-looking frame with a different P (an attacker can compute
                    // a CRC for any P) is not a symbol of this object: count a bad
                    // packet and let the scanner retract one byte, so a wrong-length
                    // payload never reaches the solver.
                    self.stats.bad_packets += 1;
                    return PacketDisposition::Rejected(FrameDefect::LengthMismatch);
                }
                let payload = packet[MICROHEADER_LEN..].to_vec();
                match accept_symbol(
                    AcceptCtx {
                        ledger: &mut self.ledger,
                        stats: &mut self.stats,
                        blocks,
                        patch: self.patch.as_mut(),
                    },
                    layout,
                    header.blk_idx,
                    header.esi,
                    payload,
                ) {
                    Ok(accepted) => {
                        if accepted.direct {
                            self.ready.push(header.blk_idx);
                        }
                        if accepted.settle_ready {
                            // Enough symbols are present: submit for early settlement
                            // so solving overlaps the scan.
                            self.maybe_submit_early(header.blk_idx);
                        }
                        PacketDisposition::Data {
                            blk: header.blk_idx,
                            esi: header.esi,
                            duplicate: accepted.duplicate,
                        }
                    }
                    Err(e) => {
                        self.storage_error.get_or_insert(e);
                        PacketDisposition::StorageFailed
                    }
                }
            }
            LayoutState::Malformed { oti } => {
                // The layout is malformed, so symbols are not stored; the BLK_IDX range
                // is still validated.
                if header.blk_idx >= oti.nb {
                    self.stats.bad_packets += 1;
                    return PacketDisposition::Rejected(FrameDefect::BlockOutOfRange);
                }
                // A baseline OTI exists, so a data frame of a different length is
                // invalid here too and makes the scanner retract one byte. There is no
                // exemption in the malformed state: a frame from a stream with another
                // P is not a symbol of this object.
                if (packet.len() - MICROHEADER_LEN) as u64 != u64::from(oti.t) {
                    self.stats.bad_packets += 1;
                    return PacketDisposition::Rejected(FrameDefect::LengthMismatch);
                }
                PacketDisposition::Data {
                    blk: header.blk_idx,
                    esi: header.esi,
                    duplicate: false,
                }
            }
            LayoutState::NoBaseline => {
                // Before a baseline exists, packets cannot be validated against NB;
                // cache them deduplicated by `(blk, esi)`.
                let key = (header.blk_idx, header.esi);
                if self.pending.contains_key(&key) {
                    self.stats.dup += 1;
                    return PacketDisposition::Data {
                        blk: key.0,
                        esi: key.1,
                        duplicate: true,
                    };
                }
                // Accept a new frame only while it fits the budget. A rejected frame is
                // not inserted into `pending` (neither key nor payload) and only
                // increments the counter; classification is unchanged (no OTI still
                // means `NoOti`).
                let payload_bytes = (packet.len() - MICROHEADER_LEN) as u64;
                if self.pending_bytes + payload_bytes > self.budget {
                    self.stats.pending_dropped += 1;
                    return PacketDisposition::Data {
                        blk: key.0,
                        esi: key.1,
                        duplicate: false,
                    };
                }
                self.pending.insert(key, packet[MICROHEADER_LEN..].to_vec());
                self.pending_bytes += payload_bytes;
                PacketDisposition::Data {
                    blk: key.0,
                    esi: key.1,
                    duplicate: false,
                }
            }
        }
    }

    /// Establish the baseline OTI: derive the layout and validate its format-level
    /// bounds. A violation yields `Malformed`; the stream is never rejected because
    /// of the local `M_blk`.
    fn establish_layout(&mut self, oti: Oti) {
        let derived = Leveling::derive(oti.f, oti.t as u64, oti.nb)
            .and_then(|lv| lv.validate_format().map(|()| lv));
        let layout = match derived {
            Ok(layout) => layout,
            Err(_) => {
                // The malformed layout consumes no symbols, so the pre-baseline cache
                // is useless and is reclaimed immediately. Cached candidates of the
                // wrong length are re-judged and counted as bad packets, matching the
                // drain path in `Ready`. Cached frames of the same length with
                // `BLK_IDX ≥ NB` are counted as bad packets too, consistent with the
                // drain and arrival paths. Only same-length frames inside `[0, NB)`
                // are pure memory reclamation and do not count in `bad_packets`.
                let mut wrong_size = 0u64;
                let mut out_of_range = 0u64;
                for (&(blk, _esi), payload) in &self.pending {
                    if blk >= oti.nb {
                        out_of_range += 1;
                    } else if payload.len() as u64 != u64::from(oti.t) {
                        wrong_size += 1;
                    }
                }
                self.pending.clear();
                self.pending_bytes = 0;
                self.stats.bad_packets += out_of_range + wrong_size;
                self.state = LayoutState::Malformed { oti };
                return;
            }
        };
        // Establish the arrival bitmap (`S/8`, allocated lazily in chunks) with the
        // baseline.
        self.ledger.init_arrival(layout.s);
        let mut blocks: BTreeMap<u32, BlockState> = BTreeMap::new();
        // Scan TARGET immediately after establishing the baseline and before draining
        // the pre-baseline `pending` buffer. Readable source symbols become known
        // first, so duplicate in-stream frames count as `dup` and are not written to
        // the overlay.
        let mut patch_known_blocks: Vec<u32> = Vec::new();
        if let Some(patch) = self.patch.as_mut() {
            if let Err(e) = patch_scan(
                patch,
                &mut self.ledger,
                &mut self.stats,
                &mut blocks,
                &mut patch_known_blocks,
                &layout,
                &oti,
            ) {
                // Target I/O failure (length query or read): report it as a ledger I/O
                // error.
                self.storage_error.get_or_insert(e);
            }
        }
        let mut out_of_range = 0u64;
        let mut wrong_size = 0u64;
        let mut direct_ready: Vec<u32> = Vec::new();
        for ((blk, esi), payload) in std::mem::take(&mut self.pending) {
            if blk >= layout.nb {
                // BLK_IDX ≥ NB could not be detected before the baseline; count the bad
                // packet now.
                out_of_range += 1;
                continue;
            }
            if payload.len() as u64 != layout.t {
                // A wrong-length symbol does not belong to this object; it could not be
                // detected before the baseline, so count it now.
                wrong_size += 1;
                continue;
            }
            match accept_symbol(
                AcceptCtx {
                    ledger: &mut self.ledger,
                    stats: &mut self.stats,
                    blocks: &mut blocks,
                    patch: self.patch.as_mut(),
                },
                &layout,
                blk,
                esi,
                payload,
            ) {
                Ok(accepted) => {
                    if accepted.direct {
                        direct_ready.push(blk);
                    }
                }
                Err(e) => {
                    // Write-through or spill failed: record the first error and stop
                    // draining. The engine enters the failed state and the CLI exits
                    // with status 1.
                    self.storage_error.get_or_insert(e);
                    break;
                }
            }
        }
        self.pending_bytes = 0;
        self.stats.bad_packets += out_of_range + wrong_size;
        self.stats.total_blocks = u64::from(layout.nb);
        // Report only max_j(K_j · T). After validation
        // `max K_j = ceil(S/NB) ≤ 56403`, so the product cannot overflow.
        self.stats.max_block_bytes = layout.max_k() * layout.t;
        self.state = LayoutState::Ready {
            oti,
            layout,
            blocks,
        };
        self.ready.extend(direct_ready);
        self.ready.extend(patch_known_blocks);
    }

    /// Declare that the caller performs the final BLAKE3 verification by reading the
    /// target backend back (the CLI file-publishing and stdout-spool paths).
    /// [`DecodeEngine::finish`] then does not read all `F` bytes into memory
    /// (`data = None`) and records `signals.verify` as [`Verify::Skipped`].
    ///
    /// The caller must complete the BLAKE3 verification before publishing and write
    /// the result into `signals`/`outcome` (the CLI trims to `F`, hashes the read-back
    /// in chunks, and classifies). The contract matches
    /// [`DecodeEngine::take_solved_block_any`], but no block bytes are taken: the
    /// engine already wrote them through to the target, and the caller only reads
    /// them back.
    pub fn set_external_verify(&mut self) {
        self.external_verify = true;
    }

    /// Take the bytes of any solved block, returning `(block index, bytes)`.
    ///
    /// Blocks are popped in LIFO order from the ready list, so when several blocks
    /// are ready at the same time their order is unspecified; callers write by
    /// output offset and must not rely on block order.
    ///
    /// Bytes are read back from the ledger target and trimmed to `F`. The trailing
    /// block no longer includes zero padding beyond `F`, and a block is marked solved
    /// only when all of its ranges are available.
    ///
    /// # Verification contract
    ///
    /// This method does not accumulate BLAKE3 (block order is not guaranteed). Once
    /// it is used, [`finish`] always records `verify` as [`Verify::Skipped`] in
    /// `signals.verify`, and the caller must complete the BLAKE3 verification before
    /// publishing and write the result into `signals`/`outcome` (the CLI file output
    /// path trims to `F`, verifies the read-back, and publishes atomically).
    ///
    /// [`finish`]: DecodeEngine::finish
    /// [`Verify::Skipped`]: crate::container::outcome::Verify::Skipped
    pub fn take_solved_block_any(&mut self) -> Option<(u32, Vec<u8>)> {
        loop {
            let j = self.ready.pop()?;
            let bytes = {
                let LayoutState::Ready { blocks, .. } = &self.state else {
                    return None;
                };
                let Some(block) = blocks.get(&j) else {
                    continue;
                };
                if !block.is_solved() || block.emitted {
                    continue;
                }
                match self.read_block_product(j) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        self.storage_error.get_or_insert(e);
                        return None;
                    }
                }
            };
            if let LayoutState::Ready { blocks, .. } = &mut self.state {
                if let Some(block) = blocks.get_mut(&j) {
                    block.emitted = true;
                }
            }
            self.external_verify = true;
            return Some((j, bytes));
        }
    }

    /// Wait for settlement to finish (call before [`DecodeEngine::finish`];
    /// idempotent).
    ///
    /// For every block whose source symbols are incomplete but whose total symbol
    /// count is sufficient, the covered source symbols and repair symbols are read
    /// back and fed to an independent solver in one batch per window, in ascending
    /// ESI order. On success only the missing ESI values are written back (trailing
    /// zeros at or past `F` are skipped). With `jobs > 1` blocks are settled in
    /// parallel and workers pread their own inputs. The stream has ended, so one
    /// settlement pass determines the final state.
    pub fn wait_solve(&mut self) {
        self.settle();
    }

    /// Commit phase for in-place patching: write the missing symbol ranges into
    /// `TARGET` once all blocks are solved.
    ///
    /// - `Ok(None)`: not in patch mode, no valid layout, or at least one block is
    ///   unsolved. In these cases nothing is written to the target, preserving the
    ///   failure invariants for `Insufficient`, `Malformed`, and `NoOti`.
    /// - `Ok(Some(commit))`: copy every symbol recorded in the `written` bitmap
    ///   (in-stream arrivals and solver write-backs, whose payloads live in the
    ///   overlay) into `TARGET`. Only missing ranges are written, and the trailing
    ///   symbol is truncated to `min(T, F − off)`. Readable bytes outside the
    ///   missing list are never rewritten.
    /// - `Err`: an I/O failure during the commit (the CLI exits with status 1). The
    ///   target may already be partially patched; only "no writes before all blocks
    ///   are solved" is guaranteed. After committing, the caller must read the whole
    ///   `TARGET` back and verify BLAKE3.
    pub fn commit_patch(&mut self) -> io::Result<Option<PatchCommit>> {
        self.settle();
        if self.storage_error.is_some() {
            return Ok(None);
        }
        let Some(patch) = self.patch.as_ref() else {
            return Ok(None);
        };
        // Mode error (target size or range bounds): the scan produced no side
        // information, so committing would let in-stream symbols overwrite ranges that
        // should stay readable; do not commit.
        if patch.error.is_some() {
            return Ok(None);
        }
        let (layout, oti) = match &self.state {
            LayoutState::Ready { layout, oti, .. } => (*layout, *oti),
            _ => return Ok(None),
        };
        let all_solved = match &self.state {
            LayoutState::Ready { blocks, .. } => {
                (0..layout.nb).all(|j| blocks.get(&j).is_some_and(|b| b.is_solved()))
            }
            _ => false,
        };
        if !all_solved {
            return Ok(None);
        }
        let f = oti.f;
        let t = layout.t;
        let store = self.ledger.store();
        let patch = self
            .patch
            .as_mut()
            .expect("patch mode was confirmed in the previous branch");
        let mut commit = PatchCommit::default();
        let mut prev_end: Option<u64> = None;
        let mut i = 0u64;
        while i < layout.s {
            if !patch.written.get(i) {
                i += 1;
                continue;
            }
            let off = i * t;
            if off >= f {
                // Defensive: missing symbols cannot reach this offset.
                i += 1;
                continue;
            }
            let want = usize::try_from((f - off).min(t)).unwrap_or(usize::MAX);
            let mut payload = vec![0u8; want];
            // Overlay payload (`store`): write-through stores a full T-byte symbol,
            // while a solver write-back of the trailing symbol may hold only
            // `min(T, F − off)` bytes.
            store.read_at(off, &mut payload).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("patch commit: failed to read overlay symbol {i}: {e}"),
                )
            })?;
            patch.target.write_at(off, &payload)?;
            commit.symbols += 1;
            commit.bytes += want as u64;
            if prev_end != Some(off) {
                commit.ranges += 1;
            }
            prev_end = Some(off + want as u64);
            i += 1;
        }
        self.stats.patched_symbols = commit.symbols;
        self.stats.patched_bytes = commit.bytes;
        self.stats.patched_ranges = commit.ranges;
        patch.commit = Some(commit);
        Ok(Some(commit))
    }

    /// Finish decoding: settle, read back for verification, and classify. Calling it
    /// repeatedly does not change the result.
    ///
    /// In patch mode the internal read-back follows the `written` bitmap and reads
    /// each symbol from the overlay or from `TARGET`, yielding the patched product
    /// both before and after the commit. The CLI production path instead declares
    /// [`DecodeEngine::set_external_verify`] and reads `TARGET` back itself.
    pub fn finish(&mut self, cfg: &DecodeConfig) -> DecodeSummary {
        self.settle();
        // Copy out the state needed for classification: reading back needs
        // `&mut self`, which cannot overlap a borrow of `&self.state`.
        enum Snap {
            None,
            Malformed(Oti),
            Ready {
                oti: Oti,
                layout: Leveling,
                unsolved: bool,
                emitted: bool,
            },
        }
        let snapshot = match &self.state {
            LayoutState::NoBaseline => Snap::None,
            LayoutState::Malformed { oti } => Snap::Malformed(*oti),
            LayoutState::Ready {
                oti,
                layout,
                blocks,
            } => Snap::Ready {
                oti: *oti,
                layout: *layout,
                // At end of stream at least one block is unsolved; taking bytes does
                // not unsolve a block.
                unsolved: (0..layout.nb).any(|j| blocks.get(&j).is_none_or(|b| !b.is_solved())),
                emitted: blocks.values().any(|b| b.emitted),
            },
        };
        let (signals, oti, layout, data) = match snapshot {
            Snap::None => (
                DecodeSignals {
                    baseline_oti: false,
                    layout_malformed: false,
                    insufficient: false,
                    verify: Verify::Skipped,
                },
                None,
                None,
                None,
            ),
            Snap::Malformed(oti) => (
                DecodeSignals {
                    baseline_oti: true,
                    layout_malformed: true,
                    insufficient: false,
                    verify: Verify::Skipped,
                },
                Some(oti),
                None,
                None,
            ),
            Snap::Ready {
                oti,
                layout,
                unsolved,
                emitted,
            } => {
                if unsolved {
                    (
                        DecodeSignals {
                            baseline_oti: true,
                            layout_malformed: false,
                            insufficient: true,
                            verify: Verify::Skipped,
                        },
                        Some(oti),
                        Some(layout),
                        None,
                    )
                } else {
                    // Read back (or use the incremental hash), trim to F, and compare
                    // BLAKE3. Under `--stream` the hash accumulated while taking blocks
                    // ([`DecodeEngine::take_solved_block`]) decides verification and
                    // `data` is `None`. When blocks were taken out of order (file
                    // publishing), the caller is responsible for verification, as
                    // documented on [`DecodeEngine::take_solved_block_any`].
                    let (verify, data) = if cfg.no_verify {
                        let data = if emitted || self.external_verify {
                            None
                        } else {
                            self.read_back_product(oti.f)
                        };
                        (Verify::Skipped, data)
                    } else if self.external_verify {
                        (Verify::Skipped, None)
                    } else if emitted {
                        (Verify::Verified(self.streamed_hash_matches(&oti)), None)
                    } else {
                        match self.read_back_product(oti.f) {
                            Some(data) => (
                                Verify::Verified(*blake3::hash(&data).as_bytes() == oti.blake3),
                                Some(data),
                            ),
                            None => (Verify::Skipped, None),
                        }
                    };
                    (
                        DecodeSignals {
                            baseline_oti: true,
                            layout_malformed: false,
                            insufficient: false,
                            verify,
                        },
                        Some(oti),
                        Some(layout),
                        data,
                    )
                }
            }
        };
        DecodeSummary {
            outcome: classify(signals),
            signals,
            oti,
            layout,
            data,
            stats: self.stats,
        }
    }

    /// Take the bytes of the next solved block in block order (`--stream`). The
    /// returned slice is already trimmed to `F` and can be written out directly.
    /// `None` means the next block is not solved yet (or all blocks were taken).
    ///
    /// Bytes are read back from the ledger target and the block is marked
    /// `emitted`. A later [`DecodeEngine::finish`] reports the final verification
    /// result (`Ok` or `HashMismatch`) from the incremental BLAKE3; the solved state
    /// of the block is unchanged.
    ///
    /// # Partial-consumption limitation
    ///
    /// This API only moves forward in block order (`0..NB`) and taken bytes cannot
    /// be recovered. If the caller fails while writing, `finish` can only verify the
    /// prefix already taken and cannot retry or rewind, so the `--stream` failure
    /// path warns on stderr that the output produced so far is not trustworthy. An
    /// engine that never calls this method (ordinary decode) is unaffected.
    pub fn take_solved_block(&mut self) -> Option<Vec<u8>> {
        let (j, remaining, mut bytes) = {
            let LayoutState::Ready {
                oti,
                layout,
                blocks,
            } = &self.state
            else {
                return None;
            };
            if self.stream_next >= layout.nb {
                return None;
            }
            let j = self.stream_next;
            let block = blocks.get(&j)?;
            if !block.is_solved() || block.emitted {
                return None;
            }
            let bytes = match self.read_block_product(j) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.storage_error.get_or_insert(e);
                    return None;
                }
            };
            (j, oti.f.saturating_sub(self.stream_hashed), bytes)
        };
        // Hash only real data: zero padding beyond F is not hashed and not returned.
        let n = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        bytes.truncate(n);
        self.stream_hasher.update(&bytes);
        self.stream_hashed += n as u64;
        self.stream_next += 1;
        if let LayoutState::Ready { blocks, .. } = &mut self.state {
            if let Some(block) = blocks.get_mut(&j) {
                block.emitted = true;
            }
        }
        Some(bytes)
    }

    /// Settle unsolved blocks. Runs once (idempotent) and settles blocks in parallel
    /// when `jobs > 1`.
    fn settle(&mut self) {
        if self.settled {
            return;
        }
        self.settled = true;
        // Close and join the early pool, completing every task submitted during the
        // scan. All early results are applied here, so solved classification and
        // counters depend on packet order, not on worker timing.
        let early_results = match self.early.take() {
            Some(pool) => pool.close_and_join(),
            None => Vec::new(),
        };
        self.apply_early_results(early_results);
        // Release inline budget retained by early takes in one step; no further
        // symbols can arrive.
        let kept = self.early_inline_kept;
        self.early_inline_kept = 0;
        self.ledger.release_inline_budget(kept);
        if self.storage_error.is_some() {
            return;
        }
        let (layout, oti) = match &self.state {
            LayoutState::Ready { layout, oti, .. } => (*layout, *oti),
            _ => return,
        };
        // Snapshot the per-block counters, then touch the ledger after the borrow
        // ends. Materialize only blocks that already have state: a forged but
        // structurally valid OTI (for example `NB = 2²⁴−1`) must not trigger an
        // allocation over `0..NB`. Blocks that never appeared are accounted for
        // arithmetically with `S = Σ K_j`:
        //   missing_total = Σ_j (K_j − source_seen_j)
        //                 = S − Σ source_seen over blocks that appeared.
        let (snapshot, source_seen_total) = match &self.state {
            LayoutState::Ready { blocks, .. } => {
                let mut seen = 0u64;
                let snapshot: Vec<(u32, u64, u64, u64, bool)> = blocks
                    .iter()
                    .map(|(&j, b)| {
                        seen += b.source_seen;
                        (j, b.k, b.source_seen, b.repair_seen, b.is_solved())
                    })
                    .collect();
                (snapshot, seen)
            }
            _ => return,
        };
        let missing_total = layout.s.saturating_sub(source_seen_total);
        let mut tasks: Vec<SettleTask> = Vec::new();
        let mut restore: Vec<(u32, u32)> = Vec::new();
        for (j, _k, source_seen, repair_seen, solved) in snapshot {
            if solved {
                // Repair payloads of a solved block are no longer needed; the keys are
                // kept for `dup` accounting and nothing is written back.
                for (esi, _) in self.ledger.repair_take_block(j) {
                    restore.push((j, esi));
                }
                continue;
            }
            if source_seen + repair_seen < layout.k_j(j) {
                // Too few symbols for an attempt; the block stays unsolved.
                continue;
            }
            let (task, taken, _kept) = self.extract_settle_task(j, &layout, &oti, false);
            if let Some(task) = task {
                restore.extend(taken);
                tasks.push(task);
            }
        }
        self.stats.missing_symbols += missing_total;
        if !tasks.is_empty() {
            let workers = self.settle_workers(&layout, tasks.len());
            let target = self.patch.as_ref().map(|p| Arc::clone(&p.target));
            let results = run_settle_tasks(
                tasks,
                workers,
                self.ledger.store(),
                self.ledger.spill_store(),
                target.as_deref(),
            );
            for (j, outcome) in results {
                match outcome {
                    Ok(SettleOutcome {
                        solved: true,
                        written,
                    }) => {
                        self.stats.solved_blocks += 1;
                        self.ready.push(j);
                        if let Some(patch) = self.patch.as_mut() {
                            // In patch mode a solver write-back puts missing payloads
                            // in the overlay; record them in `written` so the commit
                            // copies them into TARGET. Arrival bits are not set.
                            let offset = layout.offset_j(j);
                            for &esi in &written {
                                patch.written.set(offset + u64::from(esi));
                            }
                        }
                        if let LayoutState::Ready { blocks, .. } = &mut self.state {
                            if let Some(block) = blocks.get_mut(&j) {
                                block.solved = true;
                            }
                        }
                    }
                    Ok(SettleOutcome { solved: false, .. }) => {}
                    Err(e) => {
                        self.storage_error.get_or_insert(e);
                    }
                }
            }
        }
        // Re-register keys taken during settlement as keys only: they occupy no budget
        // and are not spilled, and `dup` accounting is unchanged.
        for (blk, esi) in restore {
            self.ledger.repair_insert_key_only(blk, esi);
        }
    }

    /// Build the settlement task for block `j` (shared by final settlement and early
    /// submission).
    ///
    /// Returns `(task, keys to restore after settlement, inline bytes retained by an
    /// early take)`:
    /// - `early = false` (end of stream): repair slots are taken and their inline
    ///   budget is released immediately; `kept = 0`.
    /// - `early = true` (during the scan): the inline budget stays reserved so later
    ///   inline/spill decisions match serial execution, and taken ESI values are
    ///   immediately restored as keys so `dup` accounting stays correct during the
    ///   scan; `kept > 0`.
    fn extract_settle_task(
        &mut self,
        j: u32,
        layout: &Leveling,
        oti: &Oti,
        early: bool,
    ) -> (Option<SettleTask>, Vec<(u32, u32)>, u64) {
        let k = layout.k_j(j);
        let covered: Vec<(u32, SymbolSource)> = (0..k)
            .filter(|&e| self.ledger.arrival_get(layout.offset_j(j) + e))
            .map(|e| {
                let i = layout.offset_j(j) + e;
                (e as u32, self.symbol_source(i))
            })
            .collect();
        let missing: Vec<u32> = (0..k)
            .filter(|&e| !self.ledger.arrival_get(layout.offset_j(j) + e))
            .map(|e| e as u32)
            .collect();
        let (repairs, inline_kept) = if early {
            self.ledger.repair_take_block_early(j)
        } else {
            (self.ledger.repair_take_block(j), 0)
        };
        let restore = if early {
            for &(esi, _) in &repairs {
                self.ledger.repair_insert_key_only(j, esi);
            }
            Vec::new()
        } else {
            repairs.iter().map(|&(esi, _)| (j, esi)).collect()
        };
        (
            Some(SettleTask {
                j,
                k,
                t: layout.t,
                offset: layout.offset_j(j),
                f: oti.f,
                covered,
                missing,
                repairs,
                inline_kept,
            }),
            restore,
            inline_kept,
        )
    }

    /// Create the early-settlement pool lazily. If only some workers can be started,
    /// use those; if none can, no pool is created.
    fn ensure_early_pool(&mut self, layout: &Leveling) -> bool {
        if self.early.is_some() {
            return true;
        }
        let workers = self.settle_workers(layout, layout.nb as usize);
        if workers <= 1 {
            return false;
        }
        let queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let results = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let inflight = Arc::new(AtomicUsize::new(0));
        let pending = Arc::new(AtomicUsize::new(0));
        let ctx = EarlyWorkerCtx {
            queue,
            results,
            closed,
            inflight,
            pending,
            store: self.ledger.store_handle(),
            spill: self.ledger.spill_handle(),
            target: self.patch.as_ref().map(|p| Arc::clone(&p.target)),
        };
        let mut handles = Vec::new();
        for w in 0..workers {
            let ctx = ctx.clone();
            match thread::Builder::new()
                .name(format!("lapiwe-settle-early-{w}"))
                .spawn(move || early_worker(ctx))
            {
                Ok(handle) => handles.push(handle),
                Err(_) => break,
            }
        }
        if handles.is_empty() {
            return false;
        }
        self.early = Some(EarlyPool {
            queue: Arc::clone(&ctx.queue),
            results: Arc::clone(&ctx.results),
            closed: Arc::clone(&ctx.closed),
            inflight: Arc::clone(&ctx.inflight),
            pending: Arc::clone(&ctx.pending),
            workers: handles.len(),
            handles,
        });
        true
    }

    /// Submit early settlement once a block holds `needed_j(K_j)` distinct symbols;
    /// the submission point depends only on packet order. If the number of in-flight
    /// tasks has reached the worker count, skip submission and leave the block to
    /// final settlement, keeping memory within the model.
    fn maybe_submit_early(&mut self, blk: u32) {
        if self.storage_error.is_some() {
            return;
        }
        let (layout, oti) = match &self.state {
            LayoutState::Ready { layout, oti, .. } => (*layout, *oti),
            _ => return,
        };
        match self.state_blocks().and_then(|blocks| blocks.get(&blk)) {
            Some(b) if !b.solved && !b.early_submitted => {}
            _ => return,
        }
        if !self.ensure_early_pool(&layout) {
            return;
        }
        let (saturated, closed) = match &self.early {
            Some(pool) => (
                pool.inflight.load(Ordering::SeqCst) >= pool.workers,
                pool.closed.load(Ordering::SeqCst),
            ),
            None => (true, true),
        };
        if saturated || closed {
            // At the in-flight limit: leave the block to final settlement to stay
            // within the memory model. Closure can only happen after final settlement
            // (the scan is over), so the closed check is purely defensive.
            return;
        }
        let (task, _taken, _kept) = self.extract_settle_task(blk, &layout, &oti, true);
        let Some(task) = task else { return };
        let submitted = match &self.early {
            Some(pool) => pool.submit(task),
            None => false,
        };
        // A failed submission (unreachable because the pool closes only at end of
        // stream) does not set the flag; final settlement covers the block.
        if !submitted {
            return;
        }
        if let LayoutState::Ready { blocks, .. } = &mut self.state {
            if let Some(block) = blocks.get_mut(&blk) {
                block.early_submitted = true;
            }
        }
    }

    /// Return the block map when the state is `Ready`.
    fn state_blocks(&self) -> Option<&BTreeMap<u32, BlockState>> {
        match &self.state {
            LayoutState::Ready { blocks, .. } => Some(blocks),
            _ => None,
        }
    }

    /// Drain early-settlement results during the scan. For decoded blocks, write
    /// back only the ESI values that are still missing at that moment (trailing
    /// zeros at or past `F` are skipped), then release the bytes. Solved blocks are
    /// recorded in `early_solved`.
    fn drain_early_results(&mut self) {
        let Some(pool) = &self.early else { return };
        let mut drained = Vec::new();
        if let Ok(mut results) = pool.results.lock() {
            if !results.is_empty() {
                drained = std::mem::take(&mut *results);
            }
        }
        if drained.is_empty() {
            return;
        }
        if let Some(pool) = &self.early {
            pool.pending.fetch_sub(drained.len(), Ordering::SeqCst);
        }
        for (j, outcome, inline_kept) in drained {
            self.early_inline_kept += inline_kept;
            match outcome {
                Err(e) => {
                    self.storage_error.get_or_insert(e);
                }
                Ok(None) => {}
                Ok(Some(solved)) => {
                    let missing_now = self.missing_now(j, &solved.missing);
                    match write_back_missing(
                        &solved.bytes,
                        solved.t,
                        solved.offset,
                        solved.f,
                        &missing_now,
                        self.ledger.store(),
                    ) {
                        Ok(written) => self.mark_patch_written(j, &written),
                        Err(e) => {
                            self.storage_error.get_or_insert(e);
                            continue;
                        }
                    }
                    self.early_solved.insert(j);
                }
            }
        }
    }

    /// Record symbols written back to the overlay by the solver; the commit phase
    /// copies them into TARGET.
    fn mark_patch_written(&mut self, j: u32, written: &[u32]) {
        if let Some(patch) = self.patch.as_mut() {
            if let LayoutState::Ready { layout, .. } = &self.state {
                let offset = layout.offset_j(j);
                for &esi in written {
                    patch.written.set(offset + u64::from(esi));
                }
            }
        }
    }

    /// Apply all early-settlement results at end of stream and release retained
    /// inline budget. Results that were not drained are written back using the final
    /// missing set and then marked solved. Blocks completed by their source symbols
    /// were already counted as direct solves during the scan and are not counted
    /// again, so classification does not depend on `--jobs`.
    fn apply_early_results(&mut self, results: Vec<EarlyResult>) {
        for (j, outcome, inline_kept) in results {
            self.early_inline_kept += inline_kept;
            match outcome {
                Err(e) => {
                    self.storage_error.get_or_insert(e);
                }
                Ok(None) => {}
                Ok(Some(solved)) => {
                    let missing_now = self.missing_now(j, &solved.missing);
                    match write_back_missing(
                        &solved.bytes,
                        solved.t,
                        solved.offset,
                        solved.f,
                        &missing_now,
                        self.ledger.store(),
                    ) {
                        Ok(written) => self.mark_patch_written(j, &written),
                        Err(e) => {
                            self.storage_error.get_or_insert(e);
                            continue;
                        }
                    }
                    self.early_solved.insert(j);
                }
            }
        }
        for j in std::mem::take(&mut self.early_solved) {
            let already = self
                .state_blocks()
                .and_then(|blocks| blocks.get(&j))
                .is_some_and(|b| b.solved);
            if already {
                continue;
            }
            self.stats.solved_blocks += 1;
            self.ready.push(j);
            if let LayoutState::Ready { blocks, .. } = &mut self.state {
                if let Some(block) = blocks.get_mut(&j) {
                    block.solved = true;
                }
            }
        }
    }

    /// Return the ESI values from `candidates` that are still missing in the current
    /// arrival bitmap, preserving ascending order.
    fn missing_now(&self, j: u32, candidates: &[u32]) -> Vec<u32> {
        let LayoutState::Ready { layout, .. } = &self.state else {
            return Vec::new();
        };
        let k = layout.k_j(j) as u32;
        let offset = layout.offset_j(j);
        candidates
            .iter()
            .copied()
            .filter(|&esi| esi < k && !self.ledger.arrival_get(offset + u64::from(esi)))
            .collect()
    }

    /// Return the number of settlement workers:
    /// `min(jobs, task count, resident limit / (2 · max_j(K_j · T)))`, at least 1.
    fn settle_workers(&self, layout: &Leveling, tasks: usize) -> usize {
        if self.jobs <= 1 || tasks <= 1 {
            return 1;
        }
        let max_block = layout.max_k().saturating_mul(layout.t).max(1);
        let by_resident =
            usize::try_from((SETTLE_RESIDENT_LIMIT / (2 * max_block)).max(1)).unwrap_or(usize::MAX);
        self.jobs.min(tasks).min(by_resident)
    }

    /// Return the source-symbol coverage of block `j` as `(distinct symbols
    /// received, K_j)`, or `None` without a valid layout or for an out-of-range
    /// block.
    ///
    /// Only `ESI < K_j` is counted; repair symbols do not increase coverage. Coverage
    /// is measured from the arrival bitmap: solver write-back does not set arrival
    /// bits, while a late replayed source symbol (for an already solved block) does.
    /// The percentage is a diagnostic measure of distinct source symbols received and
    /// does not mean the block can be solved, since repair symbols may fill the gaps.
    /// `inspect` displays this value.
    pub fn block_coverage(&self, j: u32) -> Option<(u64, u64)> {
        match &self.state {
            LayoutState::Ready { layout, .. } if j < layout.nb => {
                let k = layout.k_j(j);
                Some((self.ledger.arrival_count(layout.offset_j(j), k), k))
            }
            _ => None,
        }
    }

    /// Return a coverage summary `(min %, max %, blocks that received symbols)`, or
    /// `None` if no layout exists.
    ///
    /// Per-block coverage is distinct source symbols divided by `K_j`; blocks that
    /// received no symbols count as 0 %. The measurement and its limitations match
    /// [`DecodeEngine::block_coverage`]: coverage does not imply solvability.
    pub fn coverage_bounds(&self) -> Option<(f64, f64, u64)> {
        let LayoutState::Ready { layout, blocks, .. } = &self.state else {
            return None;
        };
        let covered = blocks.len() as u64;
        let mut min = f64::INFINITY;
        let mut max = 0.0f64;
        for &j in blocks.keys() {
            let k = layout.k_j(j);
            let source = self.ledger.arrival_count(layout.offset_j(j), k);
            let pct = 100.0 * source as f64 / k as f64;
            min = min.min(pct);
            max = max.max(pct);
        }
        if covered == 0 || covered < u64::from(layout.nb) {
            min = 0.0;
        }
        Some((min, max, covered))
    }

    /// Final verification for `--stream`: the bytes taken equal exactly `F` and
    /// their incremental BLAKE3 matches the baseline OTI.
    fn streamed_hash_matches(&self, oti: &Oti) -> bool {
        self.stream_hashed == oti.f && *self.stream_hasher.finalize().as_bytes() == oti.blake3
    }
}

/// Read back the target bytes of block `j`, trimmed to `F`. All ranges of the block
/// were placed when it was solved.
fn read_block_bytes(
    store: &dyn LedgerStore,
    oti: &Oti,
    layout: &Leveling,
    j: u32,
) -> io::Result<Vec<u8>> {
    let off = layout.offset_j(j) * layout.t;
    let want = (layout.k_j(j) * layout.t).min(oti.f.saturating_sub(off));
    let want = usize::try_from(want)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block length exceeds usize"))?;
    let mut bytes = vec![0u8; want];
    store.read_at(off, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::header::{MicroHeader, seal_packet, write_microheader};
    use crate::container::meta::{BLAKE3_LEN, build_meta_packet};
    use crate::container::outcome::DecodeOutcome;
    use crate::container::params::{DEFAULT_PACKET_SIZE, packet_code_for};
    use raptorq::SourceBlockEncoder;
    use std::sync::Arc;

    const P4096: usize = DEFAULT_PACKET_SIZE;
    const T4080: usize = P4096 - MICROHEADER_LEN;

    /// Build a CRC-valid container data frame (test-side, independent of the
    /// implementation).
    fn data_frame(blk_idx: u32, esi: u32, payload: &[u8]) -> Vec<u8> {
        let code = packet_code_for(P4096).expect("valid P");
        let mut packet = vec![0u8; P4096];
        write_microheader(
            &mut packet,
            &MicroHeader::new(false, false, blk_idx, esi, code),
        );
        packet[MICROHEADER_LEN..MICROHEADER_LEN + payload.len()].copy_from_slice(payload);
        seal_packet(&mut packet);
        packet
    }

    /// Build a CRC-valid data frame for any valid `P` (test-side, independent of the
    /// implementation).
    fn data_frame_p(p: usize, blk_idx: u32, esi: u32, payload: &[u8]) -> Vec<u8> {
        let code = packet_code_for(p).expect("valid P");
        let mut packet = vec![0u8; p];
        write_microheader(
            &mut packet,
            &MicroHeader::new(false, false, blk_idx, esi, code),
        );
        packet[MICROHEADER_LEN..MICROHEADER_LEN + payload.len()].copy_from_slice(payload);
        seal_packet(&mut packet);
        packet
    }

    #[test]
    fn data_packet_with_other_packet_size_is_rejected_after_baseline() {
        // A T=2032 data frame arriving after a baseline with T=4080 is not a symbol
        // of this object: it must count as a bad packet and never reach the solver.
        let oti = Oti::new((2 * 4080) as u64, 4080, 1, [0x52; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        let frame = data_frame_p(2048, 0, 0, &[0xCD; 2032]);
        assert!(matches!(
            engine.observe(&frame),
            PacketDisposition::Rejected(FrameDefect::LengthMismatch)
        ));
        assert_eq!(engine.stats().bad_packets, 1);
        assert_eq!(engine.stats().pending_dropped, 0);
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Insufficient);
    }

    #[test]
    fn pending_drain_rejects_other_packet_size() {
        // When P differs before and after the baseline, the pre-baseline cache must not
        // enter a block during the drain; establishing the layout counts the cached
        // frames as bad packets.
        let oti = Oti::new((2 * 4080) as u64, 4080, 1, [0x53; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&data_frame_p(2048, 0, 0, &[0xEE; 2032]));
        engine.observe(&data_frame_p(2048, 0, 1, &[0xEF; 2032]));
        engine.observe(&meta);
        assert_eq!(
            engine.stats().bad_packets,
            2,
            "wrong-length cached frames are counted when the baseline is established"
        );
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Insufficient);
    }

    #[test]
    fn malformed_rejects_other_packet_size() {
        // There is no exemption in the `Malformed` state: a P=2048 data frame that
        // arrives after a baseline with T=4080 is not a symbol of this object and must
        // be rejected and counted as a bad packet (the scanner retracts one byte; see
        // tests/container_scan.rs).
        let oti = Oti::new(1, 4080, 2, [0x44; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        assert!(matches!(engine.state, LayoutState::Malformed { .. }));
        let frame = data_frame_p(2048, 0, 0, &[0xCD; 2032]);
        assert!(matches!(
            engine.observe(&frame),
            PacketDisposition::Rejected(FrameDefect::LengthMismatch)
        ));
        assert_eq!(engine.stats().bad_packets, 1);
        // A data frame of the baseline length is still accepted but discarded (the
        // malformed state consumes no symbols and counts no bad packet).
        assert!(matches!(
            engine.observe(&data_frame(0, 0, &[0xAA; T4080])),
            PacketDisposition::Data {
                blk: 0,
                esi: 0,
                duplicate: false,
            }
        ));
        assert_eq!(engine.stats().bad_packets, 1);
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Malformed);
        assert_eq!(result.stats.bad_packets, 1);
    }

    #[test]
    fn malformed_pending_drain_rejects_other_packet_size() {
        // When the baseline is established (including a malformed layout), cached
        // wrong-length candidates are re-judged as bad packets, while cached frames of
        // the baseline length are not counted in `bad_packets`.
        let oti = Oti::new(1, 4080, 2, [0x55; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&data_frame_p(2048, 0, 0, &[0xEE; 2032])); // wrong length
        engine.observe(&data_frame(0, 1, &[0xAA; T4080])); // baseline length
        engine.observe(&meta);
        assert!(
            engine.pending.is_empty(),
            "the cache must be released when the baseline is established"
        );
        assert_eq!(engine.pending_bytes, 0);
        assert_eq!(
            engine.stats().bad_packets,
            1,
            "only wrong-length cached frames are counted"
        );
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Malformed);
        assert_eq!(result.stats.bad_packets, 1);
    }

    #[test]
    fn malformed_pending_drain_counts_block_out_of_range() {
        // When the baseline is established (including a malformed layout), cached
        // frames of the baseline length with `BLK_IDX ≥ NB` count as bad packets,
        // matching the `Ready` drain and arrival paths. Same-length frames inside
        // `[0, NB)` are pure memory reclamation and are not counted.
        let oti = Oti::new(1, 4080, 2, [0x56; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&data_frame(2, 0, &[0xEE; T4080])); // same length, out of range (NB=2)
        engine.observe(&data_frame(1, 0, &[0xEF; T4080])); // same length, in range
        engine.observe(&meta);
        assert!(
            engine.pending.is_empty(),
            "the cache must be released when the baseline is established"
        );
        assert_eq!(engine.pending_bytes, 0);
        assert_eq!(
            engine.stats().bad_packets,
            1,
            "only same-length out-of-range cached frames are counted"
        );
        // Arrival-path cross-check: in the `Malformed` state a data frame with
        // `BLK_IDX ≥ NB` also counts as a bad packet. The order of the length and range
        // checks does not matter; both are invalid frames.
        assert!(matches!(
            engine.observe(&data_frame(2, 0, &[0xAA; T4080])),
            PacketDisposition::Rejected(FrameDefect::BlockOutOfRange)
        ));
        assert_eq!(engine.stats().bad_packets, 2);
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Malformed);
        assert_eq!(result.stats.bad_packets, 2);
    }

    #[test]
    fn pending_same_key_different_length_shadowed_by_first() {
        // Before the baseline exists, shadowing keeps the first frame for a key: a
        // later frame with the same `(BLK_IDX, ESI)` but another length only counts as
        // `dup` and never replaces the first. The first frame's validity is judged
        // when the baseline is established (a wrong length becomes a bad packet and is
        // discarded).
        let oti = Oti::new((2 * 4080) as u64, 4080, 1, [0x57; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");

        // Direction A: the wrong-length frame (P=2048) arrives first, so the correct
        // 4080-byte frame is shadowed (dup=1) and does not replace it.
        let mut engine = DecodeEngine::new();
        assert!(matches!(
            engine.observe(&data_frame_p(2048, 0, 0, &[0xEE; 2032])),
            PacketDisposition::Data {
                duplicate: false,
                ..
            }
        ));
        assert!(matches!(
            engine.observe(&data_frame(0, 0, &[0xAA; T4080])),
            PacketDisposition::Data {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(
            engine.stats().dup,
            1,
            "a later frame must count as dup (the first is kept)"
        );
        engine.observe(&meta);
        assert_eq!(
            engine.stats().bad_packets,
            1,
            "the retained wrong-length first frame is counted as a bad packet when the baseline is established"
        );
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Insufficient);
        assert_eq!(result.stats.dup, 1, "a shadowed frame must not be adopted");

        // Direction B: the correct-length frame arrives first, so the later
        // wrong-length frame only counts as dup, produces no bad packet, and the first
        // frame enters the block.
        let mut engine = DecodeEngine::new();
        assert!(matches!(
            engine.observe(&data_frame(0, 0, &[0xAA; T4080])),
            PacketDisposition::Data {
                duplicate: false,
                ..
            }
        ));
        assert!(matches!(
            engine.observe(&data_frame_p(2048, 0, 0, &[0xEE; 2032])),
            PacketDisposition::Data {
                duplicate: true,
                ..
            }
        ));
        engine.observe(&meta);
        assert_eq!(engine.stats().dup, 1);
        assert_eq!(
            engine.stats().bad_packets,
            0,
            "a valid first frame produces no bad packet"
        );
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(
            result.outcome,
            DecodeOutcome::Insufficient,
            "K_0=2 has only 1 symbol, so it stays unsolved"
        );
    }

    #[test]
    fn malformed_releases_pending() {
        // A malformed layout must release `pending` immediately. F=1, T=4080, NB=2
        // gives KS=0, a format-level violation, so the outcome is `Malformed`.
        let oti = Oti::new(1, 4080, 2, [0x43; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        for esi in 0..3 {
            engine.observe(&data_frame(0, esi, &[0xAA; T4080]));
        }
        assert_eq!(
            engine.pending.len(),
            3,
            "cached by (blk,esi) before the baseline is established"
        );
        engine.observe(&meta);
        assert!(
            engine.pending.is_empty(),
            "Malformed consumes no symbols, so the cache must be released (pure memory reclamation)"
        );
        assert_eq!(
            engine.pending_bytes, 0,
            "budget accounting must be reset to zero as well"
        );
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Malformed);
        // The cached frames match the baseline T (only wrong-length candidates are
        // re-judged), so `bad_packets` stays 0.
        assert_eq!(result.stats.bad_packets, 0);
        assert_eq!(
            result.stats.pending_dropped, 0,
            "this is a release, not a budget drop"
        );
    }

    #[test]
    fn take_solved_block_any_out_of_order_and_external_verify() {
        // Out-of-order take for file publishing: block 1 can be taken as soon as it is
        // solved, without waiting for block 0. After that, `finish` reports
        // `Verify::Skipped` because the caller verifies the read-back; the block still
        // counts as solved and `data` is `None`.
        // F=12140, T=4080 gives S=3, NB=2, K_0=2, K_1=1 after leveling.
        let oti = Oti::new(12_140, 4080, 2, [0x58; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);

        // Block 1 (K=1) is solved first and can still be taken while block 0 is
        // unsolved. Read-back is trimmed to F: block 1 starts at offset 8160, leaving
        // 3980 bytes before F.
        engine.observe(&data_frame(1, 0, &[0x11; T4080]));
        let (j, bytes) = engine
            .take_solved_block_any()
            .expect("block 1 is solved and must be takeable");
        assert_eq!(j, 1);
        assert_eq!(
            bytes.len(),
            3980,
            "read-back is trimmed to F (no zero padding past F)"
        );
        assert_eq!(engine.stats().solved_total(), 1);

        // Block 0 (K=2) is solved next; taking it returns block index 0.
        engine.observe(&data_frame(0, 0, &[0x22; T4080]));
        engine.observe(&data_frame(0, 1, &[0x33; T4080]));
        let (j, bytes) = engine.take_solved_block_any().expect("block 0");
        assert_eq!(j, 0);
        assert_eq!(bytes.len(), 2 * T4080);
        assert_eq!(engine.stats().solved_total(), 2);
        assert!(engine.take_solved_block_any().is_none(), "all taken");

        let summary = engine.finish(&DecodeConfig::default());
        assert_eq!(
            summary.outcome,
            DecodeOutcome::Ok,
            "all blocks solved means Ok (external verification)"
        );
        assert_eq!(
            summary.signals.verify,
            Verify::Skipped,
            "after out-of-order takes the engine draws no BLAKE3 conclusion; the caller verifies the read-back"
        );
        assert!(
            summary.data.is_none(),
            "bytes were taken, so the engine no longer holds data"
        );
    }

    #[test]
    fn budget_excludes_scan_window() {
        // The engine budget is `max_mem` minus the fixed 64 KiB scan ring.
        let engine = DecodeEngine::with_budget(DEFAULT_DECODE_MAX_MEM);
        assert_eq!(engine.budget(), DEFAULT_DECODE_MAX_MEM - RING_CAP as u64);
        let tiny = DecodeEngine::with_budget(1024);
        assert_eq!(
            tiny.budget(),
            0,
            "with a budget below the window the engine side is 0 (saturating subtraction)"
        );
    }

    #[test]
    fn pending_budget_drops_frames_but_keeps_no_oti() {
        // Before the baseline exists, a frame that exceeds the budget is not inserted
        // into `pending` (neither key nor payload) and increments `pending_dropped`;
        // classification is unchanged (no OTI still means `NoOti`).
        let engine_budget = (3 * T4080) as u64;
        let mut engine = DecodeEngine::with_budget(engine_budget + RING_CAP as u64);
        for esi in 0..5 {
            let disposition = engine.observe(&data_frame(0, esi, &[0xAA; T4080]));
            assert!(
                matches!(
                    disposition,
                    PacketDisposition::Data {
                        duplicate: false,
                        ..
                    }
                ),
                "the rejected frame is still a structurally valid data frame (the scanner advances by a whole packet)"
            );
        }
        assert_eq!(
            engine.pending.len(),
            3,
            "only the first 3 frames within budget are accepted"
        );
        assert_eq!(engine.stats().pending_dropped, 2);
        assert_eq!(engine.pending_bytes, 3 * T4080 as u64);

        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(
            result.outcome,
            DecodeOutcome::NoOti,
            "classification is unchanged"
        );
        assert!(result.data.is_none());
        assert_eq!(result.stats.pending_dropped, 2);
    }

    #[test]
    fn post_baseline_repairs_spill_instead_of_dropping() {
        // After the baseline exists, symbols are never dropped because of the budget:
        // over-budget repair symbols are spilled (`spooled_bytes` grows and
        // `symbols_dropped` stays 0).
        let oti = Oti::new((4 * 4080) as u64, 4080, 1, [0x61; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let budget = 2 * T4080 as u64;
        let mut engine = DecodeEngine::with_budget(RING_CAP as u64 + budget);
        assert_eq!(engine.budget(), budget);
        engine.observe(&meta);
        for esi in 100..107u32 {
            engine.observe(&data_frame(0, esi, &[0xAB; T4080]));
        }
        let st = engine.stats();
        assert_eq!(
            st.symbols_dropped, 0,
            "no symbols may be dropped after the baseline"
        );
        assert_eq!(
            engine.ledger().inline_repair_bytes(),
            budget,
            "budget is fully used"
        );
        assert_eq!(
            engine.ledger().spilled_symbols(),
            5,
            "7 repair symbols: 2 inline, 5 spilled"
        );
        assert_eq!(st.spooled_bytes, 5 * T4080 as u64);
        assert_eq!(st.pending_dropped, 0);
    }

    #[test]
    fn budget_no_longer_drops_block_states() {
        // Block state and key sets may use memory proportional to the number of blocks
        // that received symbols, and symbols must not be dropped because of the budget.
        // F=6·T, NB=3, K_j=2.
        let oti = Oti::new(6 * 4080, 4080, 3, [0x61; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::with_budget(RING_CAP as u64 + 1);
        assert_eq!(engine.budget(), 1);
        engine.observe(&meta);
        for blk in 0..3u32 {
            engine.observe(&data_frame(blk, 0, &[0xCD; T4080]));
        }
        let LayoutState::Ready { blocks, .. } = &engine.state else {
            panic!("the baseline must be established as Ready");
        };
        assert_eq!(
            blocks.len(),
            3,
            "all block states are created (no budget drops any more)"
        );
        assert_eq!(engine.stats().symbols_dropped, 0);
        assert_eq!(engine.stats().written_through_bytes, 3 * T4080 as u64);
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::Insufficient);
        assert_eq!(result.stats.symbols_dropped, 0);
    }

    #[test]
    fn forged_nb_does_not_preallocate_states() {
        // Forged metadata with a huge NB (an unauthenticated OTI) must not trigger a
        // one-shot allocation over NB, and the arrival bitmap is allocated lazily in
        // chunks, so a 64-byte packet cannot turn its `S/8` index space into an actual
        // allocation. F=100000·2·T and NB=100000 give KS=2 and ceil(S/NB)=2, which
        // passes the format-level bounds.
        let f = 100_000u64 * 2 * 4080;
        let oti = Oti::new(f, 4080, 100_000, [0x62; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        let LayoutState::Ready { blocks, .. } = &engine.state else {
            panic!("the baseline must be established as Ready");
        };
        assert!(
            blocks.is_empty(),
            "a forged NB must not preallocate block states"
        );
        assert_eq!(
            engine.ledger().arrival_allocated_bytes(),
            0,
            "the arrival bitmap must not be really allocated until symbols arrive (lazy chunks)"
        );
        assert_eq!(engine.stats().total_blocks, 100_000);
        assert_eq!(engine.block_coverage(99_999), Some((0, 2)), "KS=2");
        assert_eq!(engine.block_coverage(100_000), None, "out-of-range block");
    }

    #[test]
    fn default_engine_uses_full_budget() {
        // The default constructor must not leave `budget` at zero.
        let engine = DecodeEngine::default();
        assert_eq!(engine.budget(), DEFAULT_DECODE_MAX_MEM - RING_CAP as u64);
        assert_eq!(engine.budget(), DecodeEngine::new().budget());
    }

    #[test]
    fn take_solved_block_streams_in_order_and_verifies() {
        // Blocks are taken in order (read back and released) and returned trimmed to
        // F; `finish` still reports the final verification from the incremental BLAKE3,
        // and taking out of order or when empty returns `None`.
        // Single block: F=K·T−100, so the trailing symbol is shorter than T and its
        // zero padding is excluded from the output and the hash.
        let (k, t) = (2u64, 4080usize);
        let f = (k * t as u64) - 100;
        let data: Vec<u8> = (0..f).map(|i| (i % 251) as u8).collect();
        let mut oti = Oti::new(f, t as u16, 1, [0u8; BLAKE3_LEN]);
        oti.blake3 = *blake3::hash(&data).as_bytes();
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        assert_eq!(engine.take_solved_block(), None, "no solved block yet");

        // Direct solve: the block is unsolved after the first symbol and solved after
        // the second.
        engine.observe(&data_frame(0, 0, &data[..t]));
        assert_eq!(engine.take_solved_block(), None);
        let mut last = vec![0u8; t];
        last[..(f as usize - t)].copy_from_slice(&data[t..]);
        engine.observe(&data_frame(0, 1, &last));

        let block = engine.take_solved_block().expect("solved");
        assert_eq!(
            block.len(),
            f as usize,
            "the taken block is trimmed to F (zero padding removed)"
        );
        assert_eq!(block, data);
        assert_eq!(
            engine.take_solved_block(),
            None,
            "no more blocks after taking all"
        );
        assert_eq!(engine.stream_next, 1, "one block taken");
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(
            result.outcome,
            DecodeOutcome::Ok,
            "the incremental BLAKE3 matches"
        );
        assert!(
            result.data.is_none(),
            "no `data` is assembled after streaming takes"
        );
    }

    #[test]
    fn take_solved_block_reports_hash_mismatch() {
        // A `HashMismatch` situation (all blocks solved but BLAKE3 differs) is still
        // detected after streaming takes.
        let (k, t) = (2u64, 4080usize);
        let f = k * t as u64;
        let data: Vec<u8> = (0..f).map(|i| (i % 251) as u8).collect();
        let oti = Oti::new(f, t as u16, 1, [0xAA; BLAKE3_LEN]); // deliberately wrong
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        engine.observe(&data_frame(0, 0, &data[..t]));
        engine.observe(&data_frame(0, 1, &data[t..]));
        assert!(engine.take_solved_block().is_some());
        let result = engine.finish(&DecodeConfig::default());
        assert_eq!(result.outcome, DecodeOutcome::HashMismatch);
        assert_eq!(result.data, None);
    }

    #[test]
    fn duplicate_after_direct_keeps_first_and_counts_dup() {
        // Late symbols after a block is solved: a repeated source symbol counts as
        // `dup` and never overwrites the written-through content (the first copy is
        // kept); a new late repair symbol only registers its key (no budget, no spill),
        // and a repeat counts as `dup`.
        let oti = Oti::new((2 * 4080) as u64, 4080, 1, [0x77; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        engine.observe(&data_frame(0, 0, &[0x01; T4080]));
        engine.observe(&data_frame(0, 1, &[0x02; T4080]));
        assert_eq!(engine.stats().direct_blocks, 1);
        let before = engine.ledger().read_back(2 * 4080).expect("read-back");
        assert!(matches!(
            engine.observe(&data_frame(0, 0, &[0x03; T4080])),
            PacketDisposition::Data {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(engine.stats().dup, 1);
        assert_eq!(
            engine.ledger().read_back(2 * 4080).expect("read-back"),
            before,
            "a late duplicate frame must not overwrite bytes already in place"
        );
        assert!(matches!(
            engine.observe(&data_frame(0, 9, &[0x04; T4080])),
            PacketDisposition::Data {
                duplicate: false,
                ..
            }
        ));
        assert!(matches!(
            engine.observe(&data_frame(0, 9, &[0x05; T4080])),
            PacketDisposition::Data {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(engine.stats().dup, 2);
        assert_eq!(
            engine.ledger().spilled_symbols(),
            0,
            "a late repair symbol after solving uses no budget and does not spill"
        );
    }

    // -----------------------------------------------------------------------
    // Library-level tests for the settlement engine
    // -----------------------------------------------------------------------

    /// Generate deterministic data with `F = 4·T4080`, `NB = 2`, and `K_j = 2`, plus
    /// its OTI.
    fn two_block_fixture() -> (Vec<u8>, Oti) {
        let f = 4u64 * 4080;
        let data: Vec<u8> = (0..f).map(|i| (i % 251) as u8).collect();
        let mut oti = Oti::new(f, 4080, 2, [0u8; BLAKE3_LEN]);
        oti.blake3 = *blake3::hash(&data).as_bytes();
        (data, oti)
    }

    /// Feed all source symbols of the `NB=2`, `K_j=2` fixture in block and ESI order.
    fn feed_two_block_sources(engine: &mut DecodeEngine, data: &[u8]) {
        for blk in 0..2u32 {
            for esi in 0..2u32 {
                let start = ((blk * 2 + esi) as usize) * 4080;
                engine.observe(&data_frame(blk, esi, &data[start..start + 4080]));
            }
        }
    }

    /// Build a solver stream where each block lacks one source symbol and provides
    /// two repair symbols (`NB=2`, `K_j=2`).
    fn solver_flow(oti: &Oti, data: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
        let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();
        for blk in 0..2u32 {
            let block = &data[(blk as usize * 2 * 4080)..((blk as usize + 1) * 2 * 4080)];
            let block_oti = block_oti(block.len() as u64, 4080);
            let encoder = SourceBlockEncoder::new(0, &block_oti, block);
            packets.push((blk, 0, encoder.source_packets()[0].data().to_vec()));
            for (i, packet) in encoder.repair_packets(0, 2).into_iter().enumerate() {
                packets.push((blk, 2 + i as u32, packet.data().to_vec()));
            }
        }
        let _ = oti;
        packets
    }

    #[test]
    fn parallel_settle_matches_serial() {
        // Settlement runs in parallel by block and workers pread source symbols
        // themselves; results and statistics do not depend on `jobs`.
        let (data, oti) = two_block_fixture();
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let packets = solver_flow(&oti, &data);

        let run = |jobs: usize| {
            let mut engine = DecodeEngine::with_budget_jobs(DEFAULT_DECODE_MAX_MEM, jobs);
            engine.observe(&meta);
            for (blk, esi, payload) in &packets {
                engine.observe(&data_frame(*blk, *esi, payload));
            }
            let summary = engine.finish(&DecodeConfig::default());
            (summary, engine.stats())
        };
        let (a, sa) = run(1);
        let (b, sb) = run(4);
        assert_eq!(a.outcome, DecodeOutcome::Ok);
        assert_eq!(b.outcome, DecodeOutcome::Ok);
        assert_eq!(a.data, b.data);
        assert_eq!(
            a.data.as_deref(),
            Some(data.as_slice()),
            "parallel products are byte-for-byte equal"
        );
        assert_eq!(sa, sb, "statistics do not depend on `jobs`");
        assert_eq!((sa.direct_blocks, sa.solved_blocks), (0, 2));
        assert_eq!(sa.missing_symbols, 2);
    }

    #[test]
    fn parallel_settle_spawn_failure_falls_back_to_serial() {
        // A worker spawn failure (injected by the test) silently falls back to serial
        // execution with identical results and statistics.
        struct ResetFlag;
        impl Drop for ResetFlag {
            fn drop(&mut self) {
                FORCE_SETTLE_SPAWN_FAILURE.with(|f| f.set(false));
            }
        }
        let _reset = ResetFlag;
        FORCE_SETTLE_SPAWN_FAILURE.with(|f| f.set(true));

        let (data, oti) = two_block_fixture();
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let packets = solver_flow(&oti, &data);

        let mut fallback = DecodeEngine::with_budget_jobs(DEFAULT_DECODE_MAX_MEM, 4);
        fallback.observe(&meta);
        for (blk, esi, payload) in &packets {
            fallback.observe(&data_frame(*blk, *esi, payload));
        }
        let a = fallback.finish(&DecodeConfig::default());

        let mut serial = DecodeEngine::with_budget_jobs(DEFAULT_DECODE_MAX_MEM, 1);
        serial.observe(&meta);
        for (blk, esi, payload) in &packets {
            serial.observe(&data_frame(*blk, *esi, payload));
        }
        let b = serial.finish(&DecodeConfig::default());

        assert_eq!(a.outcome, DecodeOutcome::Ok);
        assert_eq!(a.outcome, b.outcome);
        assert_eq!(a.data, b.data);
        assert_eq!(a.stats, b.stats);
    }

    #[test]
    fn wait_solve_idempotent_and_stale_ready_filtered() {
        // Settlement is idempotent (repeated calls have no effect). Taken blocks leave
        // stale entries in `ready`, which `take_solved_block_any` must filter lazily so
        // that a taken block is not returned again.
        let (data, oti) = two_block_fixture();
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::with_budget_jobs(DEFAULT_DECODE_MAX_MEM, 4);
        engine.observe(&meta);
        feed_two_block_sources(&mut engine, &data);

        engine.wait_solve();
        engine.wait_solve(); // Idempotent: the second call is a no-op.
        assert!((0..2).all(|j| engine.block_coverage(j).is_some()));
        // `--stream` takes all solved blocks in block order.
        assert!(engine.take_solved_block().is_some(), "block 0");
        assert!(engine.take_solved_block().is_some(), "block 1");
        assert!(
            engine.take_solved_block_any().is_none(),
            "stale ready entries of taken blocks must be filtered"
        );
        let summary = engine.finish(&DecodeConfig::default());
        assert_eq!(
            summary.outcome,
            DecodeOutcome::Ok,
            "the incremental BLAKE3 matches"
        );
        assert_eq!(summary.signals.verify, Verify::Verified(true));
        assert!(
            summary.data.is_none(),
            "no `data` is assembled after streaming takes"
        );
    }

    #[test]
    fn forged_huge_nb_settle_uses_arithmetic_missing_total() {
        // A forged but structurally valid OTI (`NB = 2²⁴−1`) must not trigger a full
        // snapshot over NB, which would turn a 4 KiB input into about 512 MiB. Missing
        // symbols of blocks that never appeared are derived arithmetically from `S`.
        // The process stays below a 300 MiB virtual-memory limit.
        let nb = (1u32 << 24) - 1;
        let f = u64::from(nb) * 4080; // S = NB, KS = 1 (within format-level bounds)
        let oti = Oti::new(f, 4080, nb, [0x63; BLAKE3_LEN]);
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
        let mut engine = DecodeEngine::new();
        engine.observe(&meta);
        assert_eq!(engine.stats().total_blocks, u64::from(nb));
        engine.wait_solve(); // A full snapshot here would collect 2²⁴−1 tuples.
        let summary = engine.finish(&DecodeConfig::default());
        assert_eq!(summary.outcome, DecodeOutcome::Insufficient);
        assert_eq!(
            summary.stats.missing_symbols,
            u64::from(nb),
            "missing total = S (filled in arithmetically when no block appeared)"
        );
    }

    /// Spill backend recorder: a real byte buffer plus a log of every `read_at` call,
    /// used to observe read amplification in settlement windows.
    #[derive(Debug, Default)]
    struct SpillRecorder {
        inner: VecStore,
        reads: Mutex<Vec<u64>>,
    }

    impl SpillRecorder {
        fn put(&self, off: u64, payload: &[u8]) {
            self.inner
                .write_at(off, payload)
                .expect("record spilled payload");
        }

        fn read_offsets(&self) -> Vec<u64> {
            self.reads.lock().expect("lock").clone()
        }
    }

    impl LedgerStore for SpillRecorder {
        fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
            self.inner.write_at(off, buf)
        }

        fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_at(off, buf)?;
            self.reads.lock().expect("lock").push(off);
            Ok(())
        }

        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn sync(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn settle_window_caps_spill_reads_to_payload_cap() {
        // One settlement batch feeds at most `payload_cap = needed_j(K_j) +
        // DROP_MARGIN` symbols: all covered source symbols plus a window of repair
        // symbols in ascending ESI order. Repair symbols outside the window stay in the
        // spill and are not read. Shape: K=64, one missing source symbol, and 512 repair
        // symbols, far more than the window.
        const T: usize = 4080;
        let k = 64u64;
        let f = k * T as u64;
        let data: Vec<u8> = (0..f).map(|i| (i % 251) as u8).collect();
        let mut oti = Oti::new(f, T as u16, 1, [0u8; BLAKE3_LEN]);
        oti.blake3 = *blake3::hash(&data).as_bytes();
        let meta = build_meta_packet(P4096, &oti, false).expect("metadata");

        let block_oti = block_oti(f, T as u16);
        let encoder = SourceBlockEncoder::new(0, &block_oti, &data);
        let sources = encoder.source_packets();
        let repairs = encoder.repair_packets(0, 512);
        assert_eq!(repairs.len(), 512);

        let spill = Arc::new(SpillRecorder::default());
        let mut engine = DecodeEngine::with_store(
            Box::new(VecStore::new()),
            Box::new(Arc::clone(&spill)),
            RING_CAP as u64, // Budget 0: spill every repair symbol (no 12-byte header).
            1,
        );
        engine.observe(&meta);
        for (i, packet) in sources.iter().enumerate().skip(1) {
            // Source symbol ESI 0 is missing.
            engine.observe(&data_frame(0, i as u32, packet.data()));
        }
        for (i, packet) in repairs.iter().enumerate() {
            engine.observe(&data_frame(0, k as u32 + i as u32, packet.data()));
        }
        let summary = engine.finish(&DecodeConfig::default());
        assert_eq!(
            summary.outcome,
            DecodeOutcome::Ok,
            "solved within the bounded window"
        );
        assert_eq!(
            &engine.ledger().read_back(f).expect("read-back")[..],
            &data[..]
        );
        assert_eq!(summary.stats.solved_blocks, 1);
        assert_eq!(
            engine.ledger().spilled_symbols(),
            512,
            "all repair symbols are spilled (none dropped)"
        );

        // Window size = payload_cap − covered (63) = needed_j(64) + DROP_MARGIN − 63
        // = 37.
        let cap = needed_j(k) + DROP_MARGIN;
        let window = (cap - (k - 1)) as usize;
        assert_eq!(window, 37, "needed_j(64)=68, DROP_MARGIN=32");
        let reads = spill.read_offsets();
        assert_eq!(
            reads.len(),
            window,
            "only one window of repair symbols is read (the first attempt succeeds, no retry)"
        );
        let stride = (SPILL_HEADER_LEN + T) as u64;
        let expected: Vec<u64> = (0..window as u64)
            .map(|i| i * stride + SPILL_HEADER_LEN as u64)
            .collect();
        assert_eq!(
            reads, expected,
            "window = the first 37 repair symbols in ascending ESI order"
        );
        assert!(
            reads.len() < repairs.len(),
            "the remaining spilled symbols are not read"
        );
    }

    #[test]
    fn settle_retries_next_window_on_failed_batch() {
        // Retry path: a failed batch moves to the next window, with a fresh decoder per
        // batch, release between batches, and a bounded attempt count. White-box
        // construction: the first 100 slots all point to the same ESI (one distinct
        // symbol after batch deduplication, fewer than K), while the second batch holds
        // 100 distinct valid repair symbols and succeeds.
        const T: usize = 4080;
        let k = 64u64;
        let f = k * T as u64;
        let data: Vec<u8> = (0..f).map(|i| (i % 251) as u8).collect();
        let block_oti = block_oti(f, T as u16);
        let encoder = SourceBlockEncoder::new(0, &block_oti, &data);
        let repairs = encoder.repair_packets(0, 100);

        let spill = Arc::new(SpillRecorder::default());
        const REC_BASE: u64 = 10_000;
        const STRIDE: u64 = 4096;
        for (i, packet) in repairs.iter().enumerate() {
            // Record start = REC_BASE + i·STRIDE (space for the 12-byte header); the
            // payload follows at +SPILL_HEADER_LEN.
            spill.put(
                REC_BASE + i as u64 * STRIDE + SPILL_HEADER_LEN as u64,
                packet.data(),
            );
        }
        let cap = needed_j(k) + DROP_MARGIN; // 100
        let window = cap as usize;
        let mut slots: Vec<(u32, RepairSlot)> = Vec::with_capacity(2 * window);
        for _ in 0..window {
            // Point every slot at the same record for the first valid repair symbol,
            // leaving one distinct symbol after deduplication.
            slots.push((
                k as u32,
                RepairSlot::Spilled(crate::container::ledger::SpillLoc {
                    off: REC_BASE,
                    len: T as u32,
                }),
            ));
        }
        for i in 0..window {
            slots.push((
                k as u32 + i as u32,
                RepairSlot::Spilled(crate::container::ledger::SpillLoc {
                    off: REC_BASE + i as u64 * STRIDE,
                    len: T as u32,
                }),
            ));
        }
        let task = SettleTask {
            j: 0,
            k,
            t: T as u64,
            offset: 0,
            f,
            covered: Vec::new(),
            missing: Vec::new(),
            repairs: slots,
            inline_kept: 0,
        };
        let target = VecStore::new();
        assert!(
            settle_block(task, &target, spill.as_ref(), None)
                .expect("no IO error")
                .solved
        );
        let reads = spill.read_offsets();
        assert_eq!(
            reads.len(),
            2 * window,
            "first batch fails -> retry with the second window (window reads per batch)"
        );
        let expected: Vec<u64> = (0..window as u64)
            .map(|i| REC_BASE + i * STRIDE + SPILL_HEADER_LEN as u64)
            .collect();
        assert_eq!(
            &reads[window..],
            &expected[..],
            "second window = valid repair symbols in ascending ESI order"
        );
    }
}
