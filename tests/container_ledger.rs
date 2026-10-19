//! Library-level decoding-ledger tests for the `.lpw` container format.
//!
//! - `test_source_is_data`: source-symbol payloads match the bytes at
//!   `(offset_j + e) * T` for the write-through, direct and settle-backfill
//!   paths, including the write-log check that data lands on arrival;
//! - `test_bounded_memory`: no decodable symbol is lost under a memory budget;
//!   repairs beyond the budget spill to disk and can be read back while
//!   settling; inline residency stays within the budget;
//! - `test_spill_fault_is_io_error_not_silent_drop`: a failing spill write is
//!   reported by the engine as an I/O error rather than dropped silently;
//! - `test_patch_only_missing`: blocks with all sources bypass the solver;
//!   settling only backfills missing ranges, leaving written ranges
//!   byte-for-byte unchanged; outcome and statistics do not depend on
//!   `--jobs` (including `K_j = 1`).
//!
//! The tests provide two [`LedgerStore`] implementations: `RecordingStore`,
//! which records write and read offsets for byte-level and "backfill only
//! missing" assertions, and `FailStore`, which injects write failures.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use lapiwe::container::decode::{DecodeConfig, DecodeEngine, DecodeStats, PacketDisposition};
use lapiwe::container::encode::{EncodeConfig, TotalSpec, encode};
use lapiwe::container::header::{MicroHeader, parse_header, seal_packet, write_microheader};
use lapiwe::container::ledger::{FileStore, LedgerStore, SPILL_HEADER_LEN, VecStore};
use lapiwe::container::outcome::DecodeOutcome;
use lapiwe::container::params::packet_code_for;

const P: usize = 4096;
const T: usize = 4080;
const MH: usize = 16;

/// Generate deterministic test data with xorshift64*; encoding and decoding
/// themselves must not use randomness.
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

/// Build a container data frame with a valid CRC.
fn data_frame(blk: u32, esi: u32, payload: &[u8]) -> Vec<u8> {
    let code = packet_code_for(P).expect("valid P");
    let mut packet = vec![0u8; P];
    write_microheader(&mut packet, &MicroHeader::new(false, false, blk, esi, code));
    packet[MH..MH + payload.len()].copy_from_slice(payload);
    seal_packet(&mut packet);
    packet
}

/// Parsed encoded stream: the leading metadata packet, all data packets as
/// `(blk, esi, payload)`, and `NB`.
struct Stream {
    meta: Vec<u8>,
    data: Vec<(u32, u32, Vec<u8>)>,
    nb: u32,
}

/// Encode one stream and split it by frame type (parsed independently here).
fn encode_stream(bytes: &[u8], k_max: u64) -> Stream {
    let cfg = EncodeConfig {
        p: P,
        m: 256,
        k_max,
        total: TotalSpec::Default,
        force: false,
    };
    let (stream, summary) = encode(bytes, &cfg).expect("encode");
    let mut meta = Vec::new();
    let mut data = Vec::new();
    for packet in stream.chunks_exact(P) {
        let header = parse_header(packet).expect("frame checksum must pass");
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

/// In-memory backend that records write and read offsets, used for the
/// byte-level "backfill only missing" assertions.
#[derive(Debug, Default)]
struct RecordingStore {
    inner: Mutex<Recorded>,
}

#[derive(Debug, Default)]
struct Recorded {
    data: Vec<u8>,
    writes: Vec<(u64, usize)>,
    reads: Vec<(u64, usize)>,
    /// Combined read/write timeline (`(is_write, offset)`), used to assert
    /// overlapping behavior during scanning.
    ops: Vec<(bool, u64)>,
}

impl RecordingStore {
    fn new() -> Self {
        Self::default()
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

    /// Combined read/write timeline (`true` means write).
    fn ops(&self) -> Vec<(bool, u64)> {
        self.inner.lock().expect("lock").ops.clone()
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
        inner.ops.push((true, off as u64));
        Ok(())
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut inner = self.inner.lock().expect("lock");
        let off = usize::try_from(off).expect("offset");
        let end = off + buf.len();
        if end > inner.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past end",
            ));
        }
        buf.copy_from_slice(&inner.data[off..end]);
        inner.reads.push((off as u64, buf.len()));
        inner.ops.push((false, off as u64));
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

/// Backend that injects write failures (simulating a full disk or missing
/// permission), used to exercise the spill failure path.
#[derive(Debug)]
struct FailStore {
    /// Allow `fail_after` writes to succeed; every later write fails.
    fail_after: usize,
    state: Mutex<(usize, u64)>,
}

impl FailStore {
    fn new(fail_after: usize) -> Self {
        Self {
            fail_after,
            state: Mutex::new((0, 0)),
        }
    }
}

impl LedgerStore for FailStore {
    fn write_at(&self, _off: u64, buf: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().expect("lock");
        if state.0 >= self.fail_after {
            return Err(io::Error::other("injected: spill medium full"));
        }
        state.0 += 1;
        state.1 += buf.len() as u64;
        Ok(())
    }

    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::other("injected: spill medium unreadable"))
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.state.lock().expect("lock").1)
    }

    fn set_len(&self, _len: u64) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Create an engine with the given ledger backends; `store` is a shared handle
/// so the test can inspect it later.
fn engine_with(
    store: Arc<RecordingStore>,
    spill: Box<dyn LedgerStore>,
    max_mem: u64,
    jobs: usize,
) -> DecodeEngine {
    DecodeEngine::with_store(Box::new(store), spill, max_mem, jobs)
}

#[test]
fn test_source_is_data() {
    // The bytes at `(offset_j + e) * T` must equal the source-symbol payload
    // byte for byte; write-through (written on arrival), direct (all sources
    // present) and settle backfill must produce the same mapping.
    let f = 8 * T; // k_max = 4, S = 8, so NB = 2 and K_j = 4
    let data = det_bytes(f, 0x4500);
    let stream = encode_stream(&data, 4);
    assert_eq!(stream.nb, 2, "k_max=4, S=8 → NB=2");

    // Path A (write-through plus direct): every source arrives; no solving.
    let store = Arc::new(RecordingStore::new());
    let spill = Arc::new(VecStore::new());
    let mut engine = engine_with(Arc::clone(&store), Box::new(Arc::clone(&spill)), 1 << 20, 1);
    engine.observe(&stream.meta);
    for (blk, esi, payload) in &stream.data {
        if *esi < 4 {
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }
    let st = engine.stats();
    assert_eq!((st.direct_blocks, st.solved_blocks), (2, 0));
    assert_eq!(
        st.written_through_bytes, f as u64,
        "written-through bytes = F"
    );
    assert_eq!(st.symbols_dropped, 0);
    assert_eq!(
        &store.snapshot()[..f],
        &data[..],
        "write-through happens on arrival: the store snapshot is a byte-for-byte copy of the data"
    );
    let mut writes = store.writes();
    writes.sort();
    let expected: Vec<(u64, usize)> = (0..8).map(|i| (i * T as u64, T)).collect();
    assert_eq!(
        writes, expected,
        "write-through hits (offset_j+e)·T for every symbol"
    );
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));

    // Path B (write-through plus settle backfill): each block is missing
    // ESI 1 and is solved from repair symbols; only the missing ranges are
    // backfilled.
    let store_b = Arc::new(RecordingStore::new());
    let mut engine_b = engine_with(Arc::clone(&store_b), Box::new(VecStore::new()), 1 << 20, 1);
    engine_b.observe(&stream.meta);
    let mut repairs = 0usize;
    for (blk, esi, payload) in &stream.data {
        if *esi < 4 {
            if *esi != 1 {
                engine_b.observe(&data_frame(*blk, *esi, payload));
            }
        } else if *esi < 6 {
            engine_b.observe(&data_frame(*blk, *esi, payload));
            repairs += 1;
        }
    }
    assert_eq!(repairs, 4, "2 repair symbols per block");
    let before = store_b.writes().len();
    let summary_b = engine_b.finish(&DecodeConfig::default());
    assert_eq!(summary_b.outcome, DecodeOutcome::Ok);
    assert_eq!(summary_b.data.as_deref(), Some(data.as_slice()));
    let st_b = engine_b.stats();
    assert_eq!((st_b.direct_blocks, st_b.solved_blocks), (0, 2));
    assert_eq!(st_b.written_through_bytes, 6 * T as u64);
    assert_eq!(st_b.missing_symbols, 2);
    assert_eq!(st_b.symbols_dropped, 0);
    assert_eq!(
        &store_b.snapshot()[..f],
        &data[..],
        "byte-for-byte equal to the source data after backfill"
    );
    let mut backfill: Vec<(u64, usize)> = store_b.writes().into_iter().skip(before).collect();
    backfill.sort();
    assert_eq!(
        backfill,
        vec![(T as u64, T), (5 * T as u64, T)],
        "settling backfills only the missing ESIs (1 in block 0, 5 in block 1)"
    );
}

#[test]
fn test_bounded_memory() {
    // Repair symbols are constrained by a memory budget: inline residency stays
    // within the budget and anything beyond it spills to disk. No decodable
    // symbol may be dropped (`symbols_dropped` stays 0), and settling reads the
    // spilled symbols back to finish decoding.
    let f = 4 * T; // one block, K = 4
    let data = det_bytes(f, 0x4600);
    let stream = encode_stream(&data, 4);
    assert_eq!(stream.nb, 1);

    let budget = 2 * T as u64; // room for exactly two inline repair symbols
    let store = Arc::new(RecordingStore::new());
    let spill = Arc::new(RecordingStore::new());
    let mut engine = engine_with(
        Arc::clone(&store),
        Box::new(Arc::clone(&spill)),
        budget + 65536, // engine budget = max_mem - RING_CAP = budget
        1,
    );
    engine.observe(&stream.meta);
    for (blk, esi, payload) in &stream.data {
        if *esi != 1 {
            // Source symbol ESI 1 is missing; all other sources and every
            // repair symbol are fed in.
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }
    let st = engine.stats();
    {
        let ledger = engine.ledger();
        assert_eq!(
            ledger.inline_repair_bytes(),
            budget,
            "inline repair residency exactly fills the budget"
        );
        assert_eq!(
            ledger.spilled_symbols(),
            2,
            "4 repair symbols: 2 inline, 2 spilled"
        );
        assert!(
            ledger.arrival_allocated_bytes() <= 1 << 20,
            "arrival bitmap chunks are lazily allocated (at most one 1 MiB chunk for small S)"
        );
    }
    assert_eq!(st.spooled_bytes, 2 * T as u64, "spilled payload bytes");
    assert_eq!(
        st.symbols_dropped, 0,
        "no decodable symbol may be dropped under the budget"
    );
    assert_eq!(st.written_through_bytes, 3 * T as u64);
    assert_eq!(
        spill.snapshot().len(),
        2 * (12 + T),
        "spill record = 12B header + payload"
    );

    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(
        summary.outcome,
        DecodeOutcome::Ok,
        "spilled repair symbols can be read back at settle time"
    );
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));
    assert_eq!(engine.stats().solved_blocks, 1);
    assert_eq!(&store.snapshot()[..f], &data[..]);
}

#[test]
fn test_spill_fault_is_io_error_not_silent_drop() {
    // When the spill medium is unavailable (a write fails), the engine reports
    // an I/O error (`StorageFailed`) instead of dropping the symbol silently.
    // The library does not panic; details are available through
    // `storage_error()`.
    let f = 4 * T;
    let data = det_bytes(f, 0x4610);
    let stream = encode_stream(&data, 4);
    let repairs: Vec<(u32, u32, Vec<u8>)> = stream
        .data
        .iter()
        .filter(|(_, esi, _)| *esi >= 4)
        .cloned()
        .collect();
    assert!(repairs.len() >= 2, "at least two repair symbols");

    // Scenario 1: zero budget, so the first repair symbol must spill; the
    // first write is injected as a failure.
    let store = Arc::new(RecordingStore::new());
    let mut engine = engine_with(Arc::clone(&store), Box::new(FailStore::new(0)), 65536, 1);
    engine.observe(&stream.meta);
    let (blk, esi, payload) = &repairs[0];
    assert_eq!(
        engine.observe(&data_frame(*blk, *esi, payload)),
        PacketDisposition::StorageFailed
    );
    assert!(engine.storage_error().is_some(), "must report an I/O error");
    assert_eq!(
        engine.stats().symbols_dropped,
        0,
        "must not be dropped silently"
    );
    assert!(
        !engine.ledger().repair_contains(*blk, *esi),
        "failure leaves no entry (neither key nor payload)"
    );
    assert_eq!(
        engine.observe(&stream.meta),
        PacketDisposition::StorageFailed,
        "observe short-circuits after failure"
    );
    let _ = engine.finish(&DecodeConfig::default()); // must not panic; the error stays readable
    assert!(engine.storage_error().is_some());

    // Scenario 2: the first spill succeeds and the second fails, so only the
    // second reports an error.
    let store2 = Arc::new(RecordingStore::new());
    let mut engine2 = engine_with(Arc::clone(&store2), Box::new(FailStore::new(1)), 65536, 1);
    engine2.observe(&stream.meta);
    let (blk0, esi0, payload0) = &repairs[0];
    assert!(matches!(
        engine2.observe(&data_frame(*blk0, *esi0, payload0)),
        PacketDisposition::Data { .. }
    ));
    assert!(engine2.ledger().repair_contains(*blk0, *esi0));
    assert_eq!(engine2.ledger().spilled_symbols(), 1);
    let (blk1, esi1, payload1) = &repairs[1];
    assert_eq!(
        engine2.observe(&data_frame(*blk1, *esi1, payload1)),
        PacketDisposition::StorageFailed
    );
    assert!(engine2.storage_error().is_some());
    assert!(!engine2.ledger().repair_contains(*blk1, *esi1));
    assert_eq!(engine2.stats().symbols_dropped, 0);
}

/// Deterministic stream in which block 0 has all its sources (direct pass)
/// while blocks 1 and 2 are each missing one source symbol.
struct PatchFlow {
    stream: Stream,
    data: Vec<u8>,
    f: usize,
    missing: Vec<(u32, u32)>,
}

fn patch_flow() -> PatchFlow {
    let f = 12 * T; // k_max = 4, S = 12, so NB = 3 and K_j = 4
    let data = det_bytes(f, 0x4700);
    let stream = encode_stream(&data, 4);
    assert_eq!(stream.nb, 3);
    PatchFlow {
        stream,
        data,
        f,
        missing: vec![(1, 1), (2, 3)],
    }
}

impl PatchFlow {
    /// Feed every packet except those listed in `missing`; return the covered
    /// global source-symbol indices in ascending order.
    fn feed(&self, engine: &mut DecodeEngine) -> Vec<u32> {
        engine.observe(&self.stream.meta);
        let mut covered = Vec::new();
        for (blk, esi, payload) in &self.stream.data {
            if self.missing.contains(&(*blk, *esi)) {
                continue;
            }
            if *esi < 4 {
                covered.push(blk * 4 + esi);
            }
            engine.observe(&data_frame(*blk, *esi, payload));
        }
        covered.sort_unstable();
        covered
    }
}

#[test]
fn test_patch_only_missing() {
    // Blocks with complete sources bypass the solver; settling only backfills
    // the missing ranges and leaves written ranges byte-for-byte unchanged.
    let flow = patch_flow();
    let store = Arc::new(RecordingStore::new());
    let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, 1);
    let covered = flow.feed(&mut engine);
    assert_eq!(covered.len(), 10, "2 of the 12 source symbols are missing");
    assert_eq!(
        engine.stats().direct_blocks,
        1,
        "block 0 has all sources → direct pass, no solving"
    );

    // During scanning only write-through happens: each covered source symbol
    // is written exactly once, at `global source index * T`.
    let mut scan_writes = store.writes();
    scan_writes.sort();
    let expected: Vec<(u64, usize)> = covered
        .iter()
        .map(|&e| (u64::from(e) * T as u64, T))
        .collect();
    assert_eq!(
        scan_writes, expected,
        "scanning only writes through source symbols that have arrived"
    );

    let before = store.writes().len();
    engine.wait_solve();
    // Settling backfills only the T bytes of each missing ESI: block 1's ESI 1
    // maps to global 5, block 2's ESI 3 maps to global 11.
    let mut backfill: Vec<(u64, usize)> = store.writes().into_iter().skip(before).collect();
    backfill.sort();
    assert_eq!(
        backfill,
        vec![(5 * T as u64, T), (11 * T as u64, T)],
        "settling backfills exactly the two missing ranges, without rewriting ranges already in place"
    );
    // Settling reads back only the **covered** source symbols; missing ranges
    // are not read back and must not be rewritten.
    let mut reads = store.reads();
    reads.sort();
    let expected_reads: Vec<(u64, usize)> = covered
        .iter()
        .filter(|&&e| e / 4 != 0)
        .map(|&e| (u64::from(e) * T as u64, T))
        .collect();
    assert_eq!(
        reads, expected_reads,
        "settle readback = covered source symbols of unsolved blocks"
    );
    let st = engine.stats();
    assert_eq!((st.direct_blocks, st.solved_blocks), (1, 2));
    assert_eq!(st.missing_symbols, 2);
    assert_eq!(st.symbols_dropped, 0);
    assert_eq!(
        &store.snapshot()[..flow.f],
        &flow.data[..],
        "byte-for-byte equal to the source data"
    );
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
}

#[test]
fn test_jobs_agnostic_and_k1() {
    // The settle result is independent of `--jobs`: jobs = 1 and jobs = 4 must
    // agree on outcome, statistics and output. `K_j = 1` is the direct special
    // case, where the only source symbol decodes as soon as it arrives.
    let flow = patch_flow();
    let run = |jobs: usize| -> (DecodeOutcome, DecodeStats, Vec<u8>) {
        let store = Arc::new(RecordingStore::new());
        let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, jobs);
        flow.feed(&mut engine);
        let summary = engine.finish(&DecodeConfig::default());
        (summary.outcome, summary.stats, store.snapshot())
    };
    let (o1, s1, b1) = run(1);
    let (o4, s4, b4) = run(4);
    assert_eq!(o1, DecodeOutcome::Ok);
    assert_eq!(o1, o4, "outcome is independent of jobs");
    assert_eq!(s1, s4, "statistics are independent of jobs");
    assert_eq!(b1, b4, "output is independent of jobs");
    assert_eq!(&b1[..flow.f], &flow.data[..]);
    assert_eq!((s4.direct_blocks, s4.solved_blocks), (1, 2));

    // K_j = 1: F = T and NB = 1; the only source symbol goes direct as soon as
    // it arrives (the same for jobs = 1 and 4).
    let data1 = det_bytes(T, 0x4711);
    let stream1 = encode_stream(&data1, 1);
    assert_eq!(stream1.nb, 1);
    for jobs in [1usize, 4] {
        let store = Arc::new(RecordingStore::new());
        let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, jobs);
        engine.observe(&stream1.meta);
        for (blk, esi, payload) in &stream1.data {
            if *esi == 0 {
                engine.observe(&data_frame(*blk, *esi, payload));
            }
        }
        assert_eq!(
            engine.stats().direct_blocks,
            1,
            "K=1 direct pass (jobs={jobs})"
        );
        assert_eq!(engine.stats().solved_blocks, 0);
        let summary = engine.finish(&DecodeConfig::default());
        assert_eq!(summary.outcome, DecodeOutcome::Ok);
        assert_eq!(summary.data.as_deref(), Some(data1.as_slice()));
    }
}

#[test]
fn test_single_pass_stdin() {
    // Single-pass stdin case: the input is fed in 16-byte chunks from a reader
    // that cannot seek (simulating a pipe), and the scanner reads it exactly
    // once (total bytes read equals the stream length, with no rewinding or
    // rereading). The engine performs write-through and settling under the
    // single-pass constraint; the output matches the source byte for byte and
    // buffered-window residency stays bounded.
    use std::io::Read;

    const K_MAX: u64 = 64;
    let f = 4 * K_MAX as usize * T;
    let data = det_bytes(f, 0x4640);
    let stream = encode_stream(&data, K_MAX);
    let mut bytes = stream.meta.clone();
    for (blk, esi, payload) in &stream.data {
        bytes.extend_from_slice(&data_frame(*blk, *esi, payload));
    }

    /// Non-seekable reader that yields 16-byte chunks (it has no `Seek`
    /// implementation; `total` tracks the cumulative bytes read).
    struct Chunked<'a> {
        buf: &'a [u8],
        pos: usize,
        total: usize,
    }
    impl Read for Chunked<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(self.buf.len() - self.pos).min(16);
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            self.total += n;
            Ok(n)
        }
    }

    let mut reader = Chunked {
        buf: &bytes,
        pos: 0,
        total: 0,
    };
    let store = Arc::new(RecordingStore::new());
    let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, 2);
    let stats = lapiwe::container::scan::scan_into(&mut reader, &mut engine).expect("scan");
    assert_eq!(
        reader.total,
        bytes.len(),
        "input must be read exactly once (no seek or rewind)"
    );
    assert_eq!(stats.bytes_scanned, bytes.len() as u64);
    assert!(
        stats.peak_buffered <= lapiwe::container::scan::RING_CAP,
        "scan window residency must be ≤ RING_CAP"
    );
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(
        summary.outcome,
        DecodeOutcome::Ok,
        "single-pass stdin must decode"
    );
    assert_eq!(
        &store.snapshot()[..f],
        &data[..],
        "output is byte-for-byte equal to the source"
    );
}

#[test]
fn test_early_submit_overlaps_and_matches_serial() {
    // Early submission during scanning: a block is submitted for settlement as
    // soon as it reaches `needed_j(K_j)` distinct symbols (the timing depends
    // only on packet order). Decoding then completes before scanning ends and
    // only backfills the ESIs still missing at that point.
    //
    // Assertions: (1) with jobs = 4 the solver reads interleave with the
    // scan-time writes, so overlap really happens, while with jobs = 1 every
    // read follows all writes; (2) outcome, statistics and output match
    // jobs = 1 item by item (direct/solved classification and counters are
    // fixed at end of stream, independent of worker timing).
    const K_MAX: u64 = 64;
    const NB: u32 = 4;
    let f = (K_MAX * u64::from(NB)) as usize * T; // 4 blocks x 64 symbols, S = 256
    let data = det_bytes(f, 0x4650);
    let cfg = EncodeConfig {
        p: P,
        m: 256,
        k_max: K_MAX,
        total: TotalSpec::Redundancy { num: 2, den: 1 },
        force: false,
    };
    let (stream_bytes, summary) = encode(&data, &cfg).expect("encode");
    assert_eq!(summary.leveling.nb, NB);
    let mut meta: Option<Vec<u8>> = None;
    let mut by_block: Vec<Vec<Vec<u8>>> = vec![Vec::new(); NB as usize];
    for packet in stream_bytes.chunks_exact(P) {
        let header = parse_header(packet).expect("frame checksum");
        if header.is_meta() {
            if meta.is_none() {
                meta = Some(packet.to_vec());
            }
            continue;
        }
        if header.esi == 0 {
            // One source symbol is missing per block, so every block must be
            // solved; the redundancy setting supplies enough repair symbols.
            continue;
        }
        by_block[header.blk_idx as usize].push(packet.to_vec());
    }
    let meta = meta.expect("metadata packet");
    assert!(by_block.iter().all(|frames| !frames.is_empty()));

    // `pause_after_first_block`: sleep after block 0 has been fed so the
    // early-settle worker can finish solving that block (50 ms is far longer
    // than the roughly 1 ms needed for one block, making "backfill during
    // scanning" a deterministic event instead of a race).
    let run = |jobs: usize,
               pause_after_first_block: bool|
     -> (DecodeOutcome, DecodeStats, Vec<u8>, Vec<(bool, u64)>) {
        let store = Arc::new(RecordingStore::new());
        let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, jobs);
        engine.observe(&meta);
        for (idx, frames) in by_block.iter().enumerate() {
            for frame in frames {
                engine.observe(frame);
            }
            if pause_after_first_block && idx == 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        let summary = engine.finish(&DecodeConfig::default());
        (
            summary.outcome,
            summary.stats,
            store.snapshot(),
            store.ops(),
        )
    };
    let (o1, s1, b1, ops1) = run(1, false);
    let (o4, s4, b4, ops4) = run(4, true);
    assert_eq!(o1, DecodeOutcome::Ok);
    assert_eq!(o1, o4, "outcome is independent of jobs");
    assert_eq!(
        s1, s4,
        "statistics are independent of jobs (classification is fixed at end of stream)"
    );
    assert_eq!(
        b1[..f],
        data[..],
        "output is byte-for-byte equal to the source"
    );
    assert_eq!(b1, b4, "output is independent of jobs");
    assert_eq!(
        (s4.direct_blocks, s4.solved_blocks),
        (0, u64::from(NB)),
        "each block is missing 1 source symbol → all solved via the solver"
    );

    // (1) Early submission: block 0's solver reads (reads of covered source
    //     symbols) must fall between the scan-time writes, i.e. the first read
    //     precedes the last source-symbol write. That proves solving actually
    //     overlaps scanning. (Backfill writes depend on when the main thread
    //     drains results and may land at end-of-stream settling, so reads are
    //     the criterion.)
    // A source-symbol write offset is `global source index * T`; a backfill
    // write offset is block j's ESI 0 at index `j * K_j`.
    let is_backfill = |off: u64| (0..u64::from(NB)).any(|j| off == j * K_MAX * T as u64);
    let last_source_write = |ops: &[(bool, u64)]| {
        ops.iter()
            .rposition(|&(is_write, off)| is_write && !is_backfill(off))
            .expect("source symbol write exists")
    };
    let first_read = |ops: &[(bool, u64)]| {
        ops.iter()
            .position(|&(is_write, _)| !is_write)
            .expect("solver readback exists")
    };
    assert!(
        first_read(&ops4) < last_source_write(&ops4),
        "early submission must overlap scanning: first solver read (position {}) should precede the last source-symbol write (position {})",
        first_read(&ops4),
        last_source_write(&ops4)
    );
    // (2) Serial control (jobs = 1): every solver read happens after all
    //     source-symbol writes, so nothing is solved during scanning.
    assert!(
        first_read(&ops1) > last_source_write(&ops1),
        "serial path: solver readback must follow all source-symbol writes (first read {}, last source write {})",
        first_read(&ops1),
        last_source_write(&ops1)
    );
    // (3) Both paths must backfill block 0's missing ESI 0 (write offset 0).
    assert!(
        ops1.iter().any(|&(w, off)| w && off == 0),
        "serial path must backfill block 0's missing ESI"
    );
    assert!(
        ops4.iter().any(|&(w, off)| w && off == 0),
        "early-submission path must backfill block 0's missing ESI"
    );
}

#[test]
fn test_tail_zero_pad_not_written_beyond_f() {
    // Trailing zeros of the final symbol (`>= F`) are written by write-through
    // and truncated by `set_len(F)`; settle backfill skips trailing zeros at or
    // beyond `F`, matching `--patch` semantics. F = 2 * T - 100.
    let f = 2 * T - 100;
    let data = det_bytes(f, 0x4720);
    let stream = encode_stream(&data, 2);
    assert_eq!(stream.nb, 1);
    // ESI 0 (the first symbol) is missing and is solved from repair symbols:
    // backfill [0, T), entirely within F.
    let store = Arc::new(RecordingStore::new());
    let mut engine = engine_with(Arc::clone(&store), Box::new(VecStore::new()), 1 << 20, 1);
    engine.observe(&stream.meta);
    for (blk, esi, payload) in &stream.data {
        if *esi >= 1 {
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }
    let before_writes = store.writes().len();
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));
    // Backfill performs exactly one write, [0, T): the missing first symbol,
    // which lies within F.
    let mut backfill_writes: Vec<(u64, usize)> =
        store.writes().into_iter().skip(before_writes).collect();
    backfill_writes.sort();
    assert_eq!(backfill_writes, vec![(0u64, T)]);
    // The logical target length is 2 * T (whole-symbol write-through plus
    // backfill); publishing truncates it to F with `set_len(F)`.
    assert_eq!(
        store.snapshot().len(),
        2 * T,
        "trailing zeros are written, then truncated at finish"
    );
    assert_eq!(&store.snapshot()[..f], &data[..]);
}

#[test]
fn test_solver_input_uses_spilled_repairs() {
    // Spilled repair symbols are read back at settle time and used for solving,
    // not just the inline symbols. A low budget forces all four repair symbols
    // to spill, and no source symbols except one are fed in, so the solver
    // input must come entirely from spilled readbacks.
    let f = 4 * T;
    let data = det_bytes(f, 0x4620);
    let stream = encode_stream(&data, 4);
    let spill = Arc::new(RecordingStore::new());
    let store = Arc::new(RecordingStore::new());
    let mut engine = engine_with(
        Arc::clone(&store),
        Box::new(Arc::clone(&spill)),
        65536, // zero budget: every repair symbol spills
        1,
    );
    engine.observe(&stream.meta);
    for (blk, esi, payload) in &stream.data {
        if *esi != 0 {
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }
    assert_eq!(engine.ledger().inline_repair_bytes(), 0);
    assert_eq!(
        engine.ledger().spilled_symbols(),
        4,
        "all K+4 symbols spilled"
    );
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(
        summary.outcome,
        DecodeOutcome::Ok,
        "spill readback completes solving"
    );
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));
    assert_eq!(engine.stats().spooled_bytes, 4 * T as u64);
    assert_eq!(engine.stats().symbols_dropped, 0);
}

// ---------------------------------------------------------------------------
// `FileStore` integration coverage (the CLI production backend): real-file
// `pread`/`pwrite`/`set_len`, spill readback, and failure paths.
// ---------------------------------------------------------------------------

/// Integration-test sandbox directory, cleaned up on drop and namespaced by
/// process ID under `std::env::temp_dir()`.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("lapiwe-ledger-fs-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Open or truncate a ledger file for reading and writing, which is the
/// contract `FileStore` expects from its caller.
fn rw_file(path: &PathBuf) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("open ledger file")
}

#[test]
fn test_filestore_raw_semantics() {
    // Real-file semantics of the production backend: `pwrite` extends the file
    // (holes read as zeros), a short `pread` reports `UnexpectedEof`, `set_len`
    // truncates and extends, overwriting leaves nearby bytes in place, and
    // `sync` can be called.
    let dir = TempDir::new("raw");
    let path = dir.path("sink.bin");
    let store = FileStore::new(rw_file(&path));
    assert_eq!(store.len().expect("length"), 0);
    store.write_at(4, b"ab").expect("pwrite");
    assert_eq!(
        store.len().expect("length"),
        6,
        "pwrite extends the file automatically"
    );
    let mut buf = [0u8; 6];
    store.read_at(0, &mut buf).expect("pread");
    assert_eq!(&buf, b"\0\0\0\0ab", "holes read as zeros");
    let mut short = [0u8; 7];
    assert_eq!(
        store
            .read_at(0, &mut short)
            .expect_err("read past end")
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    store.set_len(2).expect("truncate");
    assert_eq!(store.len().expect("length"), 2);
    store.set_len(4096).expect("extend (sparse zeros)");
    assert_eq!(store.len().expect("length"), 4096);
    store.write_at(2, b"xyzzy").expect("overwrite");
    let mut buf2 = [0u8; 7];
    store.read_at(0, &mut buf2).expect("pread");
    assert_eq!(
        &buf2, b"\0\0xyzzy",
        "overwrite changes only the target range"
    );
    store.sync().expect("sync");
    drop(store);
    assert_eq!(fs::metadata(&path).expect("stat").len(), 4096);
}

#[test]
fn test_filestore_engine_spill_roundtrip() {
    // The engine runs on real file backends: write-through (pwrite), repair
    // symbols spill (append with a 12-byte header), settling preads them back,
    // only missing ranges are backfilled, and the target matches the source
    // byte for byte. The spill record format is verified independently.
    let dir = TempDir::new("engine");
    let f = 4 * T;
    let data = det_bytes(f, 0x461F);
    let stream = encode_stream(&data, 4);
    assert_eq!(stream.nb, 1);
    let target_path = dir.path("target.bin");
    let spill_path = dir.path("spill.bin");
    let mut engine = DecodeEngine::with_store(
        Box::new(FileStore::new(rw_file(&target_path))),
        Box::new(FileStore::new(rw_file(&spill_path))),
        65536, // engine budget = 0: every repair symbol spills
        1,
    );
    engine.observe(&stream.meta);
    for (blk, esi, payload) in &stream.data {
        if *esi != 1 {
            // Source symbol ESI 1 is missing, so the solver input must come
            // from file readback.
            engine.observe(&data_frame(*blk, *esi, payload));
        }
    }
    let summary = engine.finish(&DecodeConfig::default());
    assert_eq!(
        summary.outcome,
        DecodeOutcome::Ok,
        "file backend solved successfully"
    );
    assert_eq!(summary.stats.solved_blocks, 1);
    assert!(
        summary.stats.spooled_bytes > 0,
        "repair symbols went through the spill path"
    );
    assert_eq!(summary.stats.written_through_bytes, 3 * T as u64);
    let got = fs::read(&target_path).expect("read target");
    assert_eq!(
        &got[..f],
        &data[..],
        "byte-for-byte equal to the source data after write-through + backfill"
    );
    assert_eq!(
        summary.stats.missing_symbols, 1,
        "missing-symbol statistics do not depend on the backend"
    );

    // Spill file: one `blk|esi|len|payload` record per symbol in arrival order
    // (big-endian), byte-for-byte identical to the repair frames in the stream.
    let spill = fs::read(&spill_path).expect("read spill");
    let repairs: Vec<&(u32, u32, Vec<u8>)> =
        stream.data.iter().filter(|(_, esi, _)| *esi >= 4).collect();
    assert!(!repairs.is_empty());
    let mut pos = 0usize;
    for (blk, esi, payload) in repairs {
        let head = &spill[pos..pos + SPILL_HEADER_LEN];
        assert_eq!(
            u32::from_be_bytes(head[0..4].try_into().expect("blk")),
            *blk
        );
        assert_eq!(
            u32::from_be_bytes(head[4..8].try_into().expect("esi")),
            *esi
        );
        assert_eq!(
            u32::from_be_bytes(head[8..12].try_into().expect("len")),
            T as u32
        );
        assert_eq!(
            &spill[pos + SPILL_HEADER_LEN..pos + SPILL_HEADER_LEN + T],
            &payload[..]
        );
        pos += SPILL_HEADER_LEN + T;
    }
    assert_eq!(
        pos,
        spill.len(),
        "spill file contains exactly all repair records"
    );
}

/// Failure path on real media: writing to `/dev/full` fails with ENOSPC, the
/// engine reports `StorageFailed`, nothing is dropped silently and nothing
/// panics; further `observe` calls short-circuit after the failure.
#[cfg(target_os = "linux")]
#[test]
fn test_filestore_spill_fault_is_io_error() {
    let dir = TempDir::new("fault");
    let f = 4 * T;
    let data = det_bytes(f, 0x4602);
    let stream = encode_stream(&data, 4);
    let full = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let mut engine = DecodeEngine::with_store(
        Box::new(FileStore::new(rw_file(&dir.path("target.bin")))),
        Box::new(FileStore::new(full)),
        65536, // budget 0: the first repair symbol must write to the spill medium
        1,
    );
    engine.observe(&stream.meta);
    let mut disposition = None;
    for (blk, esi, payload) in &stream.data {
        if *esi >= 4 {
            disposition = Some(engine.observe(&data_frame(*blk, *esi, payload)));
            break;
        }
    }
    assert_eq!(disposition, Some(PacketDisposition::StorageFailed));
    let err = engine.storage_error().expect("must report an I/O error");
    assert_eq!(err.raw_os_error(), Some(28), "real ENOSPC: {err}");
    assert_eq!(
        engine.stats().symbols_dropped,
        0,
        "must not be dropped silently"
    );
    assert_eq!(
        engine.observe(&stream.meta),
        PacketDisposition::StorageFailed,
        "observe short-circuits after failure"
    );
}

// ---------------------------------------------------------------------------
// Release-only scaling check for `Ledger::repair_take_block` (`#[ignore]`).
// ---------------------------------------------------------------------------

/// Scaling check: `Ledger::repair_take_block` is implemented as
/// `self.repairs.keys().filter(|(b, _)| *b == blk).collect()`, so one call
/// scans `O(current table size)` keys regardless of the target block, and a
/// full pass costs `O(NB * table size)`.
///
/// This test quantifies the quadratic term at the library level: it registers
/// `NB * M` repair keys (key-only, with empty payloads that do not consume
/// inline budget), then takes all `NB` blocks in order and prints
/// `M * NB * (NB + 1) / 2` for the sum of table sizes. That sum is the exact
/// number of key scans for this fixture, because all `NB * M` keys are
/// registered first and `(NB - j) * M` keys remain when block `j` is taken.
/// The measured total time is printed as well.
///
/// For a matrix with `NB = 65` and `M` about `K_j = 1012` this is at most
/// roughly 2.1M scans, i.e. milliseconds and negligible. The quadratic term
/// grows with `NB`, however: extrapolating to the default shape of a 100 GB
/// container (`NB` about 5963, `M` about 4112) gives roughly 7.3e10 scans (on
/// the order of hundreds of seconds), so a `(blk, esi)` range query
/// (`BTreeMap::range`) should replace the scan before that size.
///
/// Release only (`#[ignore]`; run with
/// `cargo test --release -- --ignored test_repair_take_scaling`).
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release-only check (D6 quadratic term); cargo test --release -- --ignored test_repair_take_scaling"]
fn test_repair_take_scaling() {
    use lapiwe::container::ledger::Ledger;
    use std::time::Instant;

    println!(
        "D6 check: repair_take_block scans the whole table (key-only registration, empty payloads)"
    );
    for (nb, m) in [(64u32, 1024u32), (256, 1024), (1024, 256), (1024, 1024)] {
        let mut ledger = Ledger::new(Box::new(VecStore::new()), Box::new(VecStore::new()), 0);
        for blk in 0..nb {
            for esi in 0..m {
                ledger.repair_insert_key_only(blk, esi);
            }
        }
        // Exact number of key scans for this fixture (register everything,
        // then take blocks one at a time): sum_{j=0}^{NB-1} (NB - j) * M.
        let scan_bound = u64::from(m) * u64::from(nb) * (u64::from(nb) + 1) / 2;
        let t0 = Instant::now();
        let mut taken_total = 0usize;
        for blk in 0..nb {
            let taken = ledger.repair_take_block(blk);
            assert_eq!(taken.len(), m as usize, "each block must take all M keys");
            taken_total += taken.len();
        }
        let elapsed = t0.elapsed().as_secs_f64();
        println!(
            "D6 check NB={nb} M={m}: Σ table size (exact scanned-key count)={scan_bound}; took {taken_total} keys; \
             total time={elapsed:.3}s ({:.1} Mscan/s)",
            scan_bound as f64 / elapsed / 1e6,
        );
    }
}
