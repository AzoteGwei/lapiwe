//! Library-level tests for in-place patching of the `.lpw` container format.
//!
//! The tests cover four safety invariants for patching a target file, along
//! with the side-information semantics of the patch API:
//!
//! - (a) on failure paths the `TARGET` is left byte-for-byte unchanged
//!   (`Insufficient`, `NoOti`, and `Malformed`);
//! - (b) only missing ranges are written: ranges that are readable and absent
//!   from the missing list are never touched (verified with the write log and
//!   a byte-for-byte comparison);
//! - (c) nothing is written before decoding completes (the write log is empty
//!   before commit; symbols from the stream only enter the overlay);
//! - (d) the final verdict is left to the caller, which reads back `TARGET`
//!   (covered by the CLI tests; the library tests check the read-back contract
//!   of `finish`).
//!
//! Additional coverage: intersection semantics for the missing list (a range
//! covering only the first bytes of a symbol still marks the whole symbol as
//! missing), conservative marking of read failures, truncation of the last
//! symbol to `min(T, F−off)`, target size and range bounds errors, and union
//! sufficiency (readable target symbols plus stream symbols ≥ `needed_j`)
//! together with independence from `--jobs`.

use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lapiwe::container::decode::{DecodeConfig, DecodeEngine, PacketDisposition, PatchError};
use lapiwe::container::encode::{EncodeConfig, TotalSpec, encode};
use lapiwe::container::header::{MicroHeader, parse_header, seal_packet, write_microheader};
use lapiwe::container::ledger::{FileStore, LedgerStore, VecStore};
use lapiwe::container::meta::{Oti, build_meta_packet};
use lapiwe::container::outcome::DecodeOutcome;
use lapiwe::container::params::packet_code_for;

const P: usize = 4096;
const T: usize = 4080;
const MH: usize = 16;

/// Deterministic test data (xorshift64*); the codec itself uses no randomness.
fn det_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.push((state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
    }
    out
}

/// Build a container data frame with a valid CRC and a payload of exactly `T`
/// bytes.
fn data_frame(blk: u32, esi: u32, payload: &[u8]) -> Vec<u8> {
    let code = packet_code_for(P).expect("valid P");
    let mut packet = vec![0u8; P];
    write_microheader(&mut packet, &MicroHeader::new(false, false, blk, esi, code));
    packet[MH..MH + payload.len()].copy_from_slice(payload);
    seal_packet(&mut packet);
    packet
}

/// A parsed encoded stream: the first metadata packet, all data packets as
/// `(blk, esi, payload)`, and `NB`.
struct Stream {
    meta: Vec<u8>,
    data: Vec<(u32, u32, Vec<u8>)>,
    nb: u32,
}

/// Encode a stream and split it by frame type (parsed independently by the
/// test).
fn encode_stream(bytes: &[u8], k_max: u64, total: TotalSpec) -> Stream {
    let cfg = EncodeConfig {
        p: P,
        m: 256,
        k_max,
        total,
        force: false,
    };
    let (stream, summary) = encode(bytes, &cfg).expect("encode");
    let mut meta = Vec::new();
    let mut data = Vec::new();
    for packet in stream.chunks_exact(P) {
        let header = parse_header(packet).expect("frame validation must pass");
        if header.is_meta() {
            if meta.is_empty() {
                meta = packet.to_vec();
            }
        } else {
            data.push((header.blk_idx, header.esi, packet[MH..].to_vec()));
        }
    }
    Stream {
        meta,
        data,
        nb: summary.leveling.nb,
    }
}

/// In-memory backend that records read and write offsets. It lets tests assert
/// byte-for-byte that nothing is written before commit and that only missing
/// ranges are written.
#[derive(Debug, Default)]
struct RecordingStore {
    inner: Mutex<Recorded>,
}

#[derive(Debug, Default)]
struct Recorded {
    data: Vec<u8>,
    writes: Vec<(u64, usize)>,
    reads: Vec<(u64, usize)>,
}

impl RecordingStore {
    fn new_with(data: Vec<u8>) -> Self {
        let store = Self::default();
        store.inner.lock().expect("lock").data = data;
        store
    }

    fn snapshot(&self) -> Vec<u8> {
        self.inner.lock().expect("lock").data.clone()
    }

    fn writes(&self) -> Vec<(u64, usize)> {
        self.inner.lock().expect("lock").writes.clone()
    }

    fn reads(&self) -> Vec<(u64, usize)> {
        self.inner.lock().expect("lock").reads.clone()
    }
}

impl LedgerStore for RecordingStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("lock");
        let off = usize::try_from(off).expect("offset");
        let end = off + buf.len();
        if inner.data.len() < end {
            inner.data.resize(end, 0);
        }
        inner.data[off..end].copy_from_slice(buf);
        inner.writes.push((off as u64, buf.len()));
        Ok(())
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("lock");
        let off = usize::try_from(off).expect("offset");
        let end = off + buf.len();
        if end > inner.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read out of bounds",
            ));
        }
        buf.copy_from_slice(&inner.data[off..end]);
        inner.reads.push((off as u64, buf.len()));
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.inner.lock().expect("lock").data.len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner
            .lock()
            .expect("lock")
            .data
            .resize(usize::try_from(len).expect("length"), 0);
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Read-failure injection backend: any read overlapping
/// `[fail_from, fail_from + fail_len)` returns an I/O error, so the affected
/// symbols are conservatively marked as missing.
#[derive(Debug)]
struct FailReadStore {
    inner: Arc<RecordingStore>,
    fail_from: u64,
    fail_len: u64,
}

impl FailReadStore {
    fn new(inner: Arc<RecordingStore>, fail_from: u64, fail_len: u64) -> Self {
        Self {
            inner,
            fail_from,
            fail_len,
        }
    }
}

impl LedgerStore for FailReadStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.inner.write_at(off, buf)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = off + buf.len() as u64;
        if off < self.fail_from + self.fail_len && end > self.fail_from {
            return Err(io::Error::other("injected: read failure"));
        }
        self.inner.read_at(off, buf)
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

/// Commit write-failure injection backend: `write_at` returns an I/O error from
/// `fail_from` onward, simulating a failure while `commit_patch` writes back to
/// `TARGET`. Reads, length, and truncation are forwarded to the inner store.
/// This is equivalent to a `/dev/full`-style fault injection; see
/// `test_commit_write_failure_is_partial_and_scoped` below.
#[derive(Debug)]
struct FailWriteStore {
    inner: Arc<RecordingStore>,
    fail_from: u64,
}

impl FailWriteStore {
    fn new(inner: Arc<RecordingStore>, fail_from: u64) -> Self {
        Self { inner, fail_from }
    }
}

impl LedgerStore for FailWriteStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        if off >= self.fail_from {
            return Err(io::Error::other("injected: commit write failure"));
        }
        self.inner.write_at(off, buf)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(off, buf)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }
}

/// Patch flow shape: `F = nblocks · k_j · T` (leveled), with `k_max = k_j`.
struct PatchFlow {
    stream: Stream,
    data: Vec<u8>,
    f: usize,
    k: u64,
    nb: u32,
}

impl PatchFlow {
    /// Build a deterministic shape with `S = nb · k` symbols using the default
    /// redundancy setting; solving tests add redundancy explicitly.
    fn new(seed: u64, nb: u32, k: u64, total: TotalSpec) -> Self {
        let f = (nb as u64 * k * T as u64) as usize;
        let data = det_bytes(f, seed);
        let stream = encode_stream(&data, k, total);
        assert_eq!(stream.nb, nb, "leveled shape: NB matches the fixture");
        PatchFlow {
            stream,
            data,
            f,
            k,
            nb,
        }
    }

    /// Build a shape with `F = nb · k · T − trim` (`0 < trim < T`), so `F` is
    /// **not** a multiple of `T` and the last symbol's payload is
    /// `min(T, F − off) < T`. This exercises the truncated write-back branch;
    /// if `F` were always a multiple of `T`, an implementation that writes a
    /// full `T` bytes per symbol would go unnoticed.
    fn new_tail(seed: u64, nb: u32, k: u64, total: TotalSpec, trim: usize) -> Self {
        assert!(
            trim > 0 && trim < T,
            "trim must be in (0, T): otherwise F is still a multiple of T"
        );
        let f = (nb as u64 * k * T as u64) as usize - trim;
        // trim < T, so S = ceil(F / T) is still nb · k and the leveled NB and
        // K_j are unchanged.
        let data = det_bytes(f, seed);
        let stream = encode_stream(&data, k, total);
        assert_eq!(stream.nb, nb, "leveled shape: NB matches the fixture");
        PatchFlow {
            stream,
            data,
            f,
            k,
            nb,
        }
    }

    /// Initial target contents: a copy of the full data, so every readable
    /// region already holds the correct bytes.
    fn target_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Create a decode engine that patches the given target backend with the
    /// supplied missing ranges and job count.
    fn engine(
        &self,
        target: Box<dyn LedgerStore>,
        ranges: Vec<(u64, u64)>,
        jobs: usize,
    ) -> DecodeEngine {
        DecodeEngine::with_patch(
            Box::new(VecStore::new()),
            Box::new(VecStore::new()),
            target,
            ranges,
            lapiwe::container::params::DEFAULT_DECODE_MAX_MEM,
            jobs,
        )
    }

    /// Feed the metadata packet and all data packets, skipping any `(blk, esi)`
    /// pairs listed in `skip`.
    fn feed(&self, engine: &mut DecodeEngine, skip: &[(u32, u32)]) {
        engine.observe(&self.stream.meta);
        for (blk, esi, payload) in &self.stream.data {
            if skip.contains(&(*blk, *esi)) {
                continue;
            }
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }

    /// Skip ESI values in `esis` for every block (source symbols with ESI < k
    /// only).
    fn skip_per_block(&self, esis: &[u32]) -> Vec<(u32, u32)> {
        let mut skip = Vec::new();
        for blk in 0..self.nb {
            for &esi in esis {
                skip.push((blk, esi));
            }
        }
        skip
    }
}

/// Full in-place patch flow: nothing is written before decoding completes, only
/// missing ranges are written, failure paths leave the target unchanged, and
/// union sufficiency (readable target plus stream symbols) drives solve-based
/// fill-in.
#[test]
fn test_inplace_patch() {
    // Shape: S = 8, k_max = 4, so NB = 2 and K_j = [4, 4].
    let flow = PatchFlow::new(0x4801, 2, 4, TotalSpec::Default);

    // ---- (c) no writes before decoding completes, and (b) only missing ranges
    // are written (pass-through source) ----
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    // Symbol 1 of block 0 is missing; the stream also carries that source
    // symbol.
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(T as u64, T as u64)], 1);
    flow.feed(&mut engine, &[]);
    engine.wait_solve();
    assert!(
        target.writes().is_empty(),
        "(c) MUST NOT write any TARGET bytes before commit: {:?}",
        target.writes()
    );
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved, so commit must succeed");
    assert_eq!(
        target.writes(),
        vec![(T as u64, T)],
        "(b) only the missing symbol range is written (block 0, symbol 1)"
    );
    assert_eq!(
        (commit.symbols, commit.bytes, commit.ranges),
        (1, T as u64, 1)
    );
    let st = engine.stats();
    assert_eq!(st.patch_missing_symbols, 1, "target missing symbols = 1");
    assert_eq!(
        st.missing_symbols, 0,
        "no missing symbols after stream fill-in"
    );
    assert_eq!((st.patched_symbols, st.patched_bytes), (1, T as u64));
    assert_eq!(st.patched_ranges, 1);
    assert_eq!(
        st.patch_known_blocks, 1,
        "block 1 fully readable → resolved without solving"
    );
    assert_eq!(
        &target.snapshot()[..flow.f],
        &flow.data[..],
        "target restored byte for byte"
    );
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok);

    // ---- Solve path: the stream lacks the same source symbol, which is
    // recovered from repair symbols and filled in (the read schedule uses
    // TARGET side information) ----
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(T as u64, T as u64)], 1);
    flow.feed(&mut engine, &flow.skip_per_block(&[1]));
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok, "solve succeeded");
    // finish has already settled the state (idempotent); TARGET still has no
    // writes before commit.
    assert!(
        target.writes().is_empty(),
        "(c) solve fill-in stays in the overlay; TARGET still has zero writes: {:?}",
        target.writes()
    );
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("commit is allowed after a successful solve");
    assert_eq!(
        (commit.symbols, commit.bytes, commit.ranges),
        (1, T as u64, 1)
    );
    assert_eq!(target.writes(), vec![(T as u64, T)]);
    assert_eq!(
        &target.snapshot()[..flow.f],
        &flow.data[..],
        "solve fill-in is byte-for-byte correct"
    );
    assert_eq!(
        engine.stats().solved_blocks,
        1,
        "block 0 goes through the solver"
    );
    assert_eq!(engine.stats().patch_missing_symbols, 1);
    assert_eq!(
        engine.stats().missing_symbols,
        1,
        "symbol still missing at settlement (recovered by the solver)"
    );
    // The solver reads back only the covered TARGET symbols (0, 2, and 3 in
    // block 0; block 1 is complete, so it never enters the solver).
    let reads: Vec<(u64, usize)> = {
        let mut r = target.reads();
        r.sort_unstable();
        r.dedup();
        r
    };
    for esi in [0u64, 2, 3] {
        assert!(
            reads.contains(&(esi * T as u64, T)),
            "solver input must read back TARGET symbol {esi}: {reads:?}"
        );
    }
    assert!(
        !reads.contains(&(T as u64, T)),
        "missing symbols MUST NOT be read back from TARGET (their bytes are untrusted): {reads:?}"
    );

    // ---- (a) Failure path leaves the target byte-for-byte unchanged: the
    // stream is insufficient, so the outcome is `Insufficient` and nothing is
    // written ----
    // Three symbols of block 0 are declared missing and no block 0 symbols
    // (including repair symbols) are fed: one solvable symbol < needed_j, so the
    // block cannot be solved.
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(
        Box::new(Arc::clone(&target)),
        vec![(T as u64, 3 * T as u64)],
        1,
    );
    let skip_block0: Vec<(u32, u32)> = flow
        .stream
        .data
        .iter()
        .filter(|(blk, _, _)| *blk == 0)
        .map(|(blk, esi, _)| (*blk, *esi))
        .collect();
    flow.feed(&mut engine, &skip_block0);
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Insufficient);
    assert_eq!(
        engine.commit_patch().expect("no I/O error"),
        None,
        "must not commit unless every block is solved"
    );
    assert!(
        target.writes().is_empty(),
        "(a) failure path MUST NOT write TARGET: {:?}",
        target.writes()
    );
    assert_eq!(
        &target.snapshot()[..flow.f],
        &flow.data[..],
        "(a) on the failure path the target is unchanged byte for byte (including ranges declared missing but never written)"
    );
}

/// A missing range that intersects a symbol's byte range marks the whole symbol
/// as missing, even if only its first few bytes are covered.
#[test]
fn test_missing_range_intersects_symbol() {
    let flow = PatchFlow::new(0x4802, 1, 4, TotalSpec::Default); // F = 4T
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    // Cover only the middle of symbol 2: the symbol range [2T, 3T) intersects
    // [2T + 100, 2T + 200).
    let start = 2 * T as u64 + 100;
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(start, 100)], 1);
    flow.feed(&mut engine, &flow.skip_per_block(&[2]));
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved");
    assert_eq!(
        (commit.symbols, commit.bytes, commit.ranges),
        (1, T as u64, 1),
        "an intersecting symbol is patched as missing in full"
    );
    assert_eq!(
        target.writes(),
        vec![(2 * T as u64, T)],
        "write granularity is the symbol size T, starting at the missing symbol"
    );
    assert_eq!(&target.snapshot()[..flow.f], &flow.data[..]);
}

/// Symbols whose target read fails are conservatively marked as missing (every
/// source symbol covered by the failing read region).
#[test]
fn test_read_failure_marks_missing() {
    let flow = PatchFlow::new(0x4803, 1, 4, TotalSpec::Default);
    let inner = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let target = Arc::new(FailReadStore::new(
        Arc::clone(&inner),
        2 * T as u64,
        T as u64,
    ));
    // No explicit missing list: readability comes entirely from the read
    // results; reading symbol 2 fails, so it is marked missing.
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    // The stream is complete, including the source symbol for symbol 2.
    flow.feed(&mut engine, &[]);
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved");
    assert_eq!((commit.symbols, commit.bytes), (1, T as u64));
    assert_eq!(
        inner.writes(),
        vec![(2 * T as u64, T)],
        "read-failure symbol is patched"
    );
    assert_eq!(&inner.snapshot()[..flow.f], &flow.data[..]);
    assert_eq!(engine.stats().patch_missing_symbols, 1);
    assert_eq!(
        engine.patch_read_failed_symbols(),
        1,
        "read-failure symbol count is observable (conservative marking)"
    );
}

/// The last symbol is written truncated to `min(T, F − off)`, and the target
/// length stays unchanged.
///
/// The fixture uses `F = 8T − 1000`, which is **not** a multiple of `T`: the
/// last symbol's payload is `min(T, F − off) = 3080 < T = 4080`. An
/// implementation that writes a full `T` bytes is caught directly by the
/// `commit.bytes`, write-log, and target-length assertions.
#[test]
fn test_tail_symbol_truncated_write() {
    let flow = PatchFlow::new_tail(0x4804, 2, 4, TotalSpec::Default, 1000);
    let f = flow.f;
    let target = Arc::new(RecordingStore::new_with(flow.data.clone()));
    // The payload range of the last symbol (global index S − 1) is truncated
    // according to F.
    let s = (f as u64).div_ceil(T as u64);
    let last_off = (s - 1) * T as u64;
    let want = (f as u64 - last_off).min(T as u64);
    assert!(
        want < T as u64,
        "fixture must hit the min(T, F−off) < T branch: want={want} T={T}"
    );
    let mut engine = flow.engine(
        Box::new(Arc::clone(&target)),
        vec![(last_off, want)], // Declare the last symbol missing.
        1,
    );
    // The stream lacks the last symbol's source symbol, so only the solver can
    // recover it.
    let last_esi = (s - 1) % flow.k; // Leveled shape: ESI within the block.
    let last_blk = ((s - 1) / flow.k) as u32;
    flow.feed(&mut engine, &[(last_blk, last_esi as u32)]);
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved");
    assert_eq!(commit.symbols, 1);
    assert_eq!(
        commit.bytes, want,
        "last symbol MUST be truncated to min(T, F−off)"
    );
    assert_eq!(
        target.writes(),
        vec![(last_off, want as usize)],
        "MUST NOT write zero padding at or beyond F"
    );
    assert_eq!(
        target.snapshot().len(),
        f,
        "target length unchanged (exactly F)"
    );
    assert_eq!(&target.snapshot()[..f], &flow.data[..]);
}

/// Failure-path extension: an I/O error occurs partway through commit, **after**
/// decoding has completed.
///
/// `/dev/full` cannot serve as `TARGET` (its length is always 0, which first
/// triggers `TargetSizeMismatch`), and there is no portable way to make
/// `pwrite` fail partway through on an already-open regular file. An equivalent
/// fault injection (`FailWriteStore` starts failing at the second missing
/// symbol) therefore covers the same semantics:
///
/// - missing ranges already written remain **partially patched** (partial
///   writes are allowed; only writes before decoding completes are forbidden);
/// - ranges that are readable and absent from the missing list are **still not
///   rewritten** (the same guarantee holds on failure paths);
/// - a failure reports no commit receipt or statistics
///   (`patch_commit() == None`, `patched_bytes == 0`); the caller surfaces the
///   I/O error as a single CLI line advising that the target may have been
///   partially patched and that a full decode into a new file is recommended
///   (`src/cli/decode.rs::run_patch`).
#[test]
fn test_commit_write_failure_is_partial_and_scoped() {
    // F = 4T, one block, K = 4.
    let flow = PatchFlow::new(0x480A, 1, 4, TotalSpec::Default);
    // Initial target: symbols 0 and 3, which are declared missing, are zeroed
    // to simulate unreadable or corrupt regions; the rest keeps the correct
    // bytes.
    let mut initial = flow.data.clone();
    initial[..T].fill(0);
    initial[3 * T..4 * T].fill(0);
    let inner = Arc::new(RecordingStore::new_with(initial));
    // Commit writes in ascending offset order; `fail_from = 3T` makes it fail
    // after the first missing symbol (offset 0) has been written.
    let target = Arc::new(FailWriteStore::new(Arc::clone(&inner), 3 * T as u64));
    let mut engine = flow.engine(
        Box::new(Arc::clone(&target)),
        vec![(0, T as u64), (3 * T as u64, T as u64)],
        1,
    );
    flow.feed(&mut engine, &[]);
    let err = engine
        .commit_patch()
        .expect_err("an injected commit write failure must be reported");
    assert!(
        err.to_string().contains("injected"),
        "the error must carry the fault source: {err}"
    );
    // (b′) Partial patch: only the first missing symbol has been written, and
    // its bytes match the source.
    assert_eq!(
        inner.writes(),
        vec![(0, T)],
        "only the first missing symbol should be written before the failure: {:?}",
        inner.writes()
    );
    let snapshot = inner.snapshot();
    assert_eq!(
        &snapshot[..T],
        &flow.data[..T],
        "the written missing range must be correct"
    );
    assert_eq!(
        &snapshot[T..3 * T],
        &flow.data[T..3 * T],
        "readable ranges absent from the missing list MUST NOT be rewritten (the same holds on failure paths)"
    );
    assert_eq!(
        &snapshot[3 * T..4 * T],
        &[0u8; T][..],
        "missing ranges after the failure point stay untouched (not written)"
    );
    assert_eq!(snapshot.len(), flow.f, "target length unchanged");
    assert_eq!(
        engine.patch_commit(),
        None,
        "a failure produces no commit receipt"
    );
    assert_eq!(
        engine.stats().patched_bytes,
        0,
        "a failure records no commit statistics"
    );
    assert_eq!(engine.stats().patched_symbols, 0);
    assert_eq!(engine.stats().patched_ranges, 0);
    // The backend keeps failing: a retry also fails, and the write set remains
    // limited to missing ranges (readable regions are never touched).
    assert!(
        engine.commit_patch().is_err(),
        "a retry also fails while the fault persists"
    );
    let snapshot = inner.snapshot();
    assert_eq!(&snapshot[T..3 * T], &flow.data[T..3 * T]);
    assert_eq!(&snapshot[..T], &flow.data[..T]);
}

/// A target size mismatch or an out-of-bounds missing range is a mode error: no
/// scanning and no writes occur.
#[test]
fn test_target_size_and_range_bounds() {
    let flow = PatchFlow::new(0x4805, 1, 4, TotalSpec::Default);

    // Size mismatch: one byte short.
    let mut short = flow.target_bytes();
    short.pop();
    let target = Arc::new(RecordingStore::new_with(short));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    // Even a complete stream must not commit when the mode is invalid; the mode
    // error takes precedence.
    flow.feed(&mut engine, &[]);
    assert_eq!(
        engine.patch_error(),
        Some(&PatchError::TargetSizeMismatch {
            actual: flow.f as u64 - 1,
            expected: flow.f as u64,
        })
    );
    assert!(
        target.reads().is_empty(),
        "a size mismatch means zero scanning"
    );
    assert_eq!(engine.commit_patch().expect("no I/O error"), None);
    assert!(
        target.writes().is_empty(),
        "MUST NOT commit under a mode error"
    );

    // Size mismatch: one byte long.
    let mut long = flow.target_bytes();
    long.push(0);
    let target = Arc::new(RecordingStore::new_with(long));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    engine.observe(&flow.stream.meta);
    assert!(matches!(
        engine.patch_error(),
        Some(PatchError::TargetSizeMismatch { .. })
    ));
    assert!(target.reads().is_empty());

    // Range out of bounds (extends past F).
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(
        Box::new(Arc::clone(&target)),
        vec![(flow.f as u64 - 10, 100)],
        1,
    );
    engine.observe(&flow.stream.meta);
    assert_eq!(
        engine.patch_error(),
        Some(&PatchError::RangeOutOfBounds {
            start: flow.f as u64 - 10,
            len: 100,
            f: flow.f as u64,
        })
    );
    assert!(
        target.reads().is_empty(),
        "out-of-bounds ranges must cause zero target reads"
    );
    assert!(
        target.writes().is_empty(),
        "out of bounds means zero writes"
    );

    // Extreme values (≥ 2^63, or START + LEN overflowing u64): merging and
    // validation must not panic, including in debug builds where unchecked
    // addition would overflow. Such ranges are always treated as out of bounds
    // via checked_add.
    for extreme in [
        vec![(u64::MAX, 1u64)],
        vec![(u64::MAX - 1, 2), (u64::MAX, 1)],
        vec![(i64::MAX as u64, i64::MAX as u64)],
        vec![(1 << 63, 1 << 63)],
    ] {
        let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
        let mut engine = flow.engine(Box::new(Arc::clone(&target)), extreme.clone(), 1);
        engine.observe(&flow.stream.meta);
        assert!(
            matches!(
                engine.patch_error(),
                Some(PatchError::RangeOutOfBounds { .. })
            ),
            "extreme range {extreme:?} must be out of bounds: {:?}",
            engine.patch_error()
        );
        assert!(
            target.reads().is_empty() && target.writes().is_empty(),
            "out of bounds means zero reads and zero writes"
        );
        assert_eq!(engine.commit_patch().expect("no I/O error"), None);
        assert_eq!(&target.snapshot()[..flow.f], &flow.data[..]);
    }
}

/// The `NoOti` and `Malformed` failure paths touch nothing (commit returns
/// `None`).
#[test]
fn test_no_oti_and_malformed_zero_touch() {
    // NoOti: never feed metadata.
    let flow = PatchFlow::new(0x4806, 1, 4, TotalSpec::Default);
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    for (blk, esi, payload) in &flow.stream.data {
        engine.observe(&data_frame(*blk, *esi, payload));
    }
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::NoOti);
    assert_eq!(engine.commit_patch().expect("no I/O error"), None);
    assert!(
        target.reads().is_empty(),
        "no baseline OTI: the target must not be scanned"
    );
    assert!(target.writes().is_empty());
    assert_eq!(&target.snapshot()[..flow.f], &flow.data[..]);

    // Malformed: forge an OTI whose layout is invalid (NB > S, so KS = 0).
    let flow = PatchFlow::new(0x4807, 1, 4, TotalSpec::Default);
    let oti = Oti {
        f: flow.f as u64,
        t: T as u16,
        nb: 8, // S = 4 < NB, so KS = 0: malformed.
        n_sub: 1,
        scheme: 4,
        rsv: 0,
        blake3: [0u8; 32],
    };
    let forged = build_meta_packet(P, &oti, false).expect("build metadata packet");
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    engine.observe(&forged);
    for (blk, esi, payload) in &flow.stream.data {
        engine.observe(&data_frame(*blk, *esi, payload));
    }
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Malformed);
    assert_eq!(engine.commit_patch().expect("no I/O error"), None);
    assert!(
        target.reads().is_empty(),
        "Malformed layout: the target must not be scanned"
    );
    assert!(target.writes().is_empty());
    assert_eq!(&target.snapshot()[..flow.f], &flow.data[..]);
}

/// Sufficiency is measured over the union of readable target symbols and
/// distinct stream symbols (`≥ needed_j`), and the result does not depend on
/// `--jobs` (outcome, statistics, and target bytes are all identical).
#[test]
fn test_union_sufficiency_and_jobs_agnostic() {
    let flow = PatchFlow::new(0x4808, 2, 4, TotalSpec::Redundancy { num: 3, den: 1 });
    let one = {
        let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
        let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(T as u64, T as u64)], 1);
        let mut skip = flow.skip_per_block(&[1]);
        for esi in 0..4 {
            skip.push((1, esi));
        }
        flow.feed(&mut engine, &skip);
        let summary = engine.finish(&DecodeConfig::default());
        let commit = engine
            .commit_patch()
            .expect("commit")
            .expect("commit allowed");
        (
            summary.outcome,
            engine.stats().missing_symbols,
            commit,
            target.snapshot(),
            target.writes(),
        )
    };
    assert_eq!(one.0, DecodeOutcome::Ok, "union is sufficient → Ok");
    assert_eq!(
        one.1, 1,
        "missing symbol count = the 1 declared (block 1 fully readable, none missing)"
    );
    assert_eq!((one.2.symbols, one.2.bytes, one.2.ranges), (1, T as u64, 1));
    assert!(one.2.symbols > 0);
    assert_eq!(&one.3[..flow.f], &flow.data[..]);
    assert_eq!(one.4, vec![(T as u64, T)]);

    let four = {
        let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
        let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(T as u64, T as u64)], 4);
        let mut skip = flow.skip_per_block(&[1]);
        for esi in 0..4 {
            skip.push((1, esi));
        }
        flow.feed(&mut engine, &skip);
        let summary = engine.finish(&DecodeConfig::default());
        let commit = engine
            .commit_patch()
            .expect("commit")
            .expect("commit allowed");
        (
            summary.outcome,
            engine.stats().missing_symbols,
            commit,
            target.snapshot(),
            target.writes(),
        )
    };
    assert_eq!(four.0, one.0, "outcome does not depend on --jobs");
    assert_eq!(
        four.1, one.1,
        "missing symbol count does not depend on --jobs"
    );
    assert_eq!(four.2, one.2, "commit statistics do not depend on --jobs");
    assert_eq!(four.3, one.3, "target bytes do not depend on --jobs");
    assert_eq!(four.4, one.4, "commit write log does not depend on --jobs");
}

/// When a stream symbol overlaps a readable target symbol (a redundant stream
/// frame), it counts as a `dup` and does not enter the overlay.
#[test]
fn test_stream_duplicates_do_not_stage() {
    let flow = PatchFlow::new(0x4809, 1, 4, TotalSpec::Default);
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    // Complete stream: every source symbol overlaps a readable target symbol.
    flow.feed(&mut engine, &[]);
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    let st = engine.stats();
    assert_eq!(
        st.dup, 4,
        "all 4 source symbol frames hit readable target symbols → dup"
    );
    assert_eq!(
        st.written_through_bytes, 0,
        "no symbols need to be written to the overlay"
    );
    assert_eq!(
        st.patch_known_blocks, 1,
        "target fully readable → no solving needed"
    );
    let commit = engine
        .commit_patch()
        .expect("commit")
        .expect("commit allowed");
    assert_eq!(
        commit.symbols, 0,
        "no missing symbols → commit writes zero bytes"
    );
    assert_eq!(target.writes(), Vec::new());
    assert_eq!(
        engine.observe(&data_frame(0, 0, &flow.stream.data[0].2)),
        PacketDisposition::Data {
            blk: 0,
            esi: 0,
            duplicate: true
        }
    );
}

/// Block-level read-ahead during the target scan, and its fallback on failure.
///
/// - Success path: consecutive readable symbols are merged into a single
///   `read_at` call (a block with k = 8 takes one block read instead of eight);
/// - Failure path: if the block read fails, the same range is re-evaluated
///   symbol by symbol. Only symbols whose individual read succeeds are trusted;
///   failed symbols are conservatively marked missing, so read-ahead does not
///   weaken the per-symbol behavior.
#[test]
fn test_scan_chunked_reads_and_fallback() {
    let flow = PatchFlow::new(0x480B, 1, 8, TotalSpec::Default); // F = 8T, one block, K = 8.

    // (i) Success path: one block read covers all eight symbols.
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    flow.feed(&mut engine, &[]);
    assert_eq!(
        target.reads(),
        vec![(0, 8 * T)],
        "consecutive readable symbols must merge into a single block read"
    );
    assert_eq!(engine.stats().patch_known_blocks, 1);
    assert_eq!(engine.stats().patch_missing_symbols, 0);

    // (ii) Failure path: the block read (covering symbol 3) fails, so the range
    // is re-evaluated symbol by symbol.
    let inner = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    let target = Arc::new(FailReadStore::new(
        Arc::clone(&inner),
        3 * T as u64,
        T as u64,
    ));
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), Vec::new(), 1);
    flow.feed(&mut engine, &[]);
    let reads = inner.reads();
    assert_eq!(
        reads,
        (0..8)
            .filter(|&i| i != 3)
            .map(|i| (i * T as u64, T))
            .collect::<Vec<_>>(),
        "after a failed block read, the same range is re-read symbol by symbol (symbol 3 fails, the rest succeed)"
    );
    assert_eq!(
        engine.patch_read_failed_symbols(),
        1,
        "only the symbol whose individual read failed is conservatively marked missing"
    );
    assert_eq!(
        engine.stats().patch_missing_symbols,
        1,
        "a failed block read does not mean the whole block is missing (fallback granularity = symbol)"
    );
    assert_eq!(
        engine.stats().patch_known_blocks,
        0,
        "7/8 symbols → still needs solving"
    );
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved after stream fill-in");
    assert_eq!(
        (commit.symbols, commit.bytes, commit.ranges),
        (1, T as u64, 1),
        "only the read-failure symbol is patched"
    );
    assert_eq!(inner.writes(), vec![(3 * T as u64, T)]);
    assert_eq!(&inner.snapshot()[..flow.f], &flow.data[..]);
}

/// Symbols covered by a missing range are never read during the scan, and
/// block-level read-ahead must stop at missing symbols (no read, no trust).
#[test]
fn test_scan_missing_range_not_read() {
    let flow = PatchFlow::new(0x480C, 1, 8, TotalSpec::Default); // F = 8T, one block, K = 8.
    let target = Arc::new(RecordingStore::new_with(flow.target_bytes()));
    // Cover only the first 100 bytes of symbol 2; intersection marks the whole
    // symbol missing.
    let mut engine = flow.engine(Box::new(Arc::clone(&target)), vec![(2 * T as u64, 100)], 1);
    flow.feed(&mut engine, &[]);
    assert_eq!(
        target.reads(),
        vec![(0, 2 * T), (3 * T as u64, 5 * T)],
        "block reads must split around missing symbols (zero reads of missing symbol ranges)"
    );
    assert_eq!(engine.stats().patch_missing_symbols, 1);
    assert_eq!(engine.stats().patch_known_blocks, 0);
    let commit = engine
        .commit_patch()
        .expect("no I/O error on commit")
        .expect("all blocks solved after stream fill-in");
    assert_eq!(
        (commit.symbols, commit.bytes, commit.ranges),
        (1, T as u64, 1)
    );
    assert_eq!(target.writes(), vec![(2 * T as u64, T)]);
    assert_eq!(&target.snapshot()[..flow.f], &flow.data[..]);
}

/// Read-counting wrapper backend: counts `read_at` calls and bytes read for the
/// target scan calibration.
#[derive(Debug)]
struct CountingStore<S> {
    inner: S,
    reads: AtomicU64,
    bytes: AtomicU64,
}

impl<S: LedgerStore> CountingStore<S> {
    fn new(inner: S) -> Self {
        CountingStore {
            inner,
            reads: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl<S: LedgerStore> LedgerStore for CountingStore<S> {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.inner.write_at(off, buf)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.inner.read_at(off, buf)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }
}

/// `O(S)` target-scan cost calibration (release only, `#[ignore]`).
///
/// This isolates only the target scan performed when the baseline OTI is
/// established (`observe` on the metadata packet); it excludes input stream
/// scanning, solving, and commit. The target is a **real data file** in
/// `CARGO_TARGET_TMPDIR` on the project's reference disk. The test prints scan
/// time, throughput, and `read_at` call counts for the F = 64 MiB and 256 MiB
/// cases for performance documentation. Assertions check structure only (a
/// fully readable target means every block is resolved directly); no
/// machine-dependent throughput thresholds are enforced.
#[test]
#[ignore = "release calibration: target scan O(S) throughput"]
fn test_target_scan_calibration() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("patch-scan-cal");
    fs::create_dir_all(&dir).expect("calibration directory");
    for (f, nb) in [(64u64 << 20, 5u32), (256u64 << 20, 17u32)] {
        let path = dir.join(format!("target-{f}.bin"));
        let data = det_bytes(f as usize, 0xCA11 + f);
        fs::write(&path, &data).expect("write calibration target");
        drop(data);
        let oti = Oti {
            f,
            t: T as u16,
            nb,
            n_sub: 1,
            scheme: 4,
            rsv: 0,
            blake3: [0u8; 32],
        };
        let meta = build_meta_packet(P, &oti, false).expect("metadata packet");
        for rep in 0..2 {
            let file = File::options()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open calibration target");
            let target = Arc::new(CountingStore::new(FileStore::new(file)));
            let mut engine = DecodeEngine::with_patch(
                Box::new(VecStore::new()),
                Box::new(VecStore::new()),
                Box::new(Arc::clone(&target)),
                Vec::new(),
                lapiwe::container::params::DEFAULT_DECODE_MAX_MEM,
                1,
            );
            let t0 = Instant::now();
            engine.observe(&meta);
            let dt = t0.elapsed();
            let st = engine.stats();
            assert_eq!(
                st.patch_known_blocks,
                u64::from(nb),
                "target fully readable → every block resolved directly"
            );
            assert_eq!(st.patch_missing_symbols, 0);
            assert_eq!(engine.patch_read_failed_symbols(), 0);
            let secs = dt.as_secs_f64();
            let reads = target.reads();
            println!(
                "target scan calibration: F={} MiB NB={} rep={} scan={:.3}s throughput={:.0} MiB/s \
                 read_at={} avg={:.1} KiB/read",
                f >> 20,
                nb,
                rep,
                secs,
                (f as f64 / 1048576.0) / secs.max(f64::EPSILON),
                reads,
                target.bytes() as f64 / reads.max(1) as f64 / 1024.0,
            );
        }
    }
}
