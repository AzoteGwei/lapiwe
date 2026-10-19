//! Integration tests for the ring scanner.
//!
//! The tests cover a fixed-capacity window of at least 64 KiB, byte-by-byte
//! sliding matches, non-seekable input (a chunked FIFO-style reader), fallback
//! from false `SYNC` candidates (including `PKT_CODE=5`, which forces a full
//! 65536-byte read, and `PKT_CODE=6`, which has no fixed length), overlapping
//! `SYNC` markers, EOF and truncation safety, and bounded memory on random
//! garbage streams (peak window usage never exceeds `RING_CAP`). They also
//! cover the regression where, after a `Malformed` reference packet, a data
//! frame with a different length is rejected and the scanner falls back by one
//! byte.
//!
//! All data is generated deterministically, and every reader is non-seekable
//! (it implements only `Read`).

use std::io::{self, Read};

use lapiwe::container::decode::{DecodeConfig, DecodeEngine};
use lapiwe::container::encode::{EncodeConfig, TotalSpec, encode};
use lapiwe::container::header::{MicroHeader, seal_packet, write_microheader};
use lapiwe::container::meta::{Oti, build_meta_packet};
use lapiwe::container::outcome::DecodeOutcome;
use lapiwe::container::params::{SYNC, packet_code_for};
use lapiwe::container::scan::{RING_CAP, RingScanner, scan_into};

const P4096: usize = 4096;
const M256: u64 = 256;
const K_MAX_4096: u64 = 16_448; // floor(64 MiB / 4080), the default setting

fn enc_cfg(p: usize, m: u64, k_max: u64, total: TotalSpec, force: bool) -> EncodeConfig {
    EncodeConfig {
        p,
        m,
        k_max,
        total,
        force,
    }
}

/// Deterministic test data (xorshift64*; the same family used in
/// `container_decode.rs`).
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

/// A reader that delivers data in fixed-size chunks, simulating a FIFO or
/// pipe: it is non-seekable, and a single `read` may return very little data.
struct ChunkReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
}

impl<'a> ChunkReader<'a> {
    fn new(data: &'a [u8], chunk: usize) -> Self {
        assert!(chunk >= 1);
        ChunkReader {
            data,
            pos: 0,
            chunk,
        }
    }
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.chunk).min(self.data.len() - self.pos);
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Streams deterministic garbage generated on demand. Memory use stays O(1)
/// because the full input is never materialized.
struct GarbageReader {
    state: u64,
    remaining: usize,
}

impl GarbageReader {
    fn new(seed: u64, len: usize) -> Self {
        GarbageReader {
            state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            remaining: len,
        }
    }
}

impl Read for GarbageReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.remaining);
        for b in &mut out[..n] {
            self.state ^= self.state >> 12;
            self.state ^= self.state << 25;
            self.state ^= self.state >> 27;
            *b = (self.state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
        self.remaining -= n;
        Ok(n)
    }
}

/// Build a complete data frame with a valid CRC. `P` must be a valid packet
/// size, and the payload is filled with `fill`.
fn data_frame(p: usize, blk_idx: u32, esi: u32, fill: u8) -> Vec<u8> {
    let code = packet_code_for(p).expect("valid packet size");
    let mut packet = vec![fill; p];
    write_microheader(
        &mut packet,
        &MicroHeader::new(false, false, blk_idx, esi, code),
    );
    seal_packet(&mut packet);
    packet
}

/// Build a fake frame with valid `SYNC` and `VER_FLAGS` bytes and the given
/// `PKT_CODE`. The remaining bytes are deterministic garbage, so the CRC
/// always fails.
fn pseudo_frame(len: usize, code: u8, seed: u64) -> Vec<u8> {
    let mut fake = det_bytes(len, seed);
    fake[0..4].copy_from_slice(&SYNC);
    fake[4] = 0x40; // VER=4, is_meta=0, best_effort=0
    fake[11] = code;
    fake
}

#[test]
fn test_ring_scan() {
    // The window must be at least max(P) = 64 KiB, matches slide one byte at
    // a time, and the reader is non-seekable (13-byte FIFO chunks). The real
    // stream is surrounded by garbage, but every frame must still be
    // recovered and decoded completely.
    let scanner = RingScanner::new(io::empty());
    assert!(
        scanner.capacity() >= 65_536,
        "window must be >= max(P) = 64 KiB"
    );
    assert_eq!(scanner.capacity(), RING_CAP);

    let data = det_bytes(100_000, 0x3000);
    let (bytes, summary) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");
    assert_eq!(summary.leveling.nb, 1);

    let mut stream = det_bytes(777, 0x3001); // leading garbage
    stream.extend_from_slice(&bytes); // real stream
    stream.extend_from_slice(&det_bytes(300, 0x3002)); // trailing garbage

    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(&stream, 13), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(
        result.outcome,
        DecodeOutcome::Ok,
        "the real stream must be recovered around the garbage"
    );
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert_eq!(
        stats.bytes_scanned,
        stream.len() as u64,
        "no extra reads past EOF"
    );
    assert!(
        stats.sync_candidates >= summary.c_total,
        "each real frame hits exactly once (plus occasional garbage candidates)"
    );
    assert!(stats.peak_buffered <= RING_CAP);
}

#[test]
fn test_pseudo_sync_full_read() {
    // Inject false SYNC markers into the FIFO: two pseudo frames with
    // `PKT_CODE=5` (P=65536, forcing a full-window read) and one with
    // `PKT_CODE=6` (low 3 bits > 5, so the length is not fixed). Each must
    // fall back correctly (advance one byte) without running out of memory
    // (the peak equals `RING_CAP` and never exceeds it), and the real stream
    // must be recovered in the end.
    let data = det_bytes(50_000, 0x3010);
    let (bytes, _) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");

    let mut stream = Vec::new();
    for seed in [0x3011u64, 0x3012] {
        stream.extend_from_slice(&pseudo_frame(65_536, 5, seed)); // P=65536
    }
    stream.extend_from_slice(&pseudo_frame(4_096, 6, 0x3013)); // no fixed length -> bad_code
    let mut bad_ver = pseudo_frame(2_048, 0, 0x3014); // fixed length readable, but VER != 4
    bad_ver[4] = 0x30;
    stream.extend_from_slice(&bad_ver);
    stream.extend_from_slice(&bytes);

    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(&stream, 1_000), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(
        result.outcome,
        DecodeOutcome::Ok,
        "must fall back correctly after a fake SYNC and recover the real stream"
    );
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert!(
        stats.crc_failures >= 2,
        "both pseudo frames are read in full and fail their CRC"
    );
    assert!(
        stats.bad_code >= 1,
        "a candidate with low 3 bits > 5 has no fixed length, so it is only counted"
    );
    assert!(
        stats.bad_frames >= 1,
        "the fixed-length VER=3 candidate is fully read and rejected"
    );
    assert_eq!(
        stats.peak_buffered, RING_CAP,
        "must attempt a full 65536-byte read without overflowing the window"
    );
    assert!(stats.peak_buffered <= RING_CAP);
    assert_eq!(stats.bytes_scanned, stream.len() as u64);
}

#[test]
fn test_garbage_stream_no_oom() {
    // A garbage stream must neither exhaust memory nor panic: 16 MiB of
    // deterministic garbage is generated on demand rather than materialized,
    // peak window usage stays exactly at the capacity limit, and the absence
    // of a usable OTI yields `NoOti(3)`.
    let total = 16 * 1024 * 1024usize;
    let mut engine = DecodeEngine::new();
    let stats = scan_into(GarbageReader::new(0x3020, total), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(result.outcome, DecodeOutcome::NoOti);
    assert_eq!(result.outcome.exit_code(), 3);
    assert_eq!(stats.bytes_scanned, total as u64);
    assert_eq!(
        stats.peak_buffered, RING_CAP,
        "the window compacts once full: the peak is exactly the capacity and does not grow with input"
    );
    assert!(stats.peak_buffered <= RING_CAP);
    assert_eq!(
        stats.sync_candidates, 0,
        "deterministic garbage contains no SYNC hits"
    );
    assert_eq!(engine.stats().packets, 0, "no candidates reach the engine");
}

#[test]
fn test_truncated_stream() {
    // EOF and truncation safety: a truncated final frame is counted as
    // truncated, never handed to the engine as a partial frame, and never
    // panics. With too few received symbols the result is `Insufficient(2)`;
    // nothing is invented.
    let data = det_bytes(1024 * 1024, 0x3030);
    let (bytes, summary) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");
    assert_eq!(summary.c_total, 264);

    let cut = 100 * P4096 + P4096 / 2; // 100 complete frames plus half a frame
    let stream = &bytes[..cut];

    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(stream, 61), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(
        result.outcome,
        DecodeOutcome::Insufficient,
        "truncation must not yield invented output"
    );
    assert_eq!(result.outcome.exit_code(), 2);
    assert!(
        stats.truncated >= 1,
        "a partial frame must be counted as truncated"
    );
    assert_eq!(
        engine.stats().packets,
        100,
        "only complete frames reach the engine"
    );
    assert_eq!(stats.bytes_scanned, cut as u64);
    assert_eq!(result.stats.solved_total(), 0);
}

#[test]
fn test_overlapping_sync() {
    // Overlapping and adjacent false SYNC prefixes (`LPW1` three times in a
    // row): each fully read pseudo candidate is rejected by its CRC and the
    // scanner advances only one byte each time, so the first real frame is
    // not swallowed.
    let data = det_bytes(50_000, 0x3040);
    let (bytes, summary) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");

    let mut stream = Vec::from(*b"LPW1LPW1LPW1");
    stream.extend_from_slice(&bytes);

    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(&stream, 7), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert!(
        stats.crc_failures >= 3,
        "all pseudo candidates at offsets 0/4/8 are rejected"
    );
    assert!(stats.sync_candidates >= summary.c_total + 3);
}

#[test]
fn test_dense_pseudo_sync() {
    // Dense false SYNC markers (`LPW1` repeated, so matches are exactly four
    // bytes apart): every candidate must attempt a full P=4096 read and fail
    // its CRC, advancing one byte at a time. Peak window usage stays bounded,
    // with no OOM or panic, and the absence of a usable OTI yields `NoOti(3)`.
    let junk = b"LPW1".repeat(64 * 1024); // 256 KiB
    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(&junk, 997), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(result.outcome, DecodeOutcome::NoOti);
    assert_eq!(stats.bytes_scanned, junk.len() as u64);
    let slots = (junk.len() / 4) as u64; // every 4-byte aligned position is a candidate
    assert_eq!(
        stats.sync_candidates, slots,
        "hit count = number of repetitions"
    );
    assert_eq!(
        stats.crc_failures + stats.truncated,
        slots,
        "each candidate is either read in full and rejected by its CRC or truncated at EOF"
    );
    assert!(stats.crc_failures > 0 && stats.truncated > 0);
    assert_eq!(
        engine.stats().packets,
        stats.crc_failures,
        "only complete candidates reach the engine"
    );
    assert!(
        stats.peak_buffered <= RING_CAP,
        "dense candidates must not overflow the window"
    );
}

#[test]
fn test_empty_and_tiny_streams() {
    // EOF safety: empty and very short streams do not panic, produce no
    // candidates, and yield `NoOti(3)`.
    for len in [0usize, 1, 4, 15, 16] {
        let junk = det_bytes(len, 0x3060 + len as u64);
        let mut engine = DecodeEngine::new();
        let stats = scan_into(ChunkReader::new(&junk, 3), &mut engine).expect("scan");
        let result = engine.finish(&DecodeConfig { no_verify: false });
        assert_eq!(result.outcome, DecodeOutcome::NoOti, "len={len}");
        assert_eq!(stats.bytes_scanned, len as u64);
        assert_eq!(
            stats.sync_candidates, 0,
            "random short garbage does not form SYNC (len={len})"
        );
    }

    // A stream containing only `SYNC` and fewer than 16 bytes of micro-header:
    // the candidate matches but is truncated, so it is counted as truncated
    // and no partial frame is submitted.
    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(b"LPW1", 2), &mut engine).expect("scan");
    assert_eq!(stats.sync_candidates, 1);
    assert_eq!(stats.truncated, 1);
    assert_eq!(engine.stats().packets, 0);
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::NoOti);
}

#[test]
fn test_malformed_other_packet_size_falls_back_one_byte() {
    // A `Malformed` state does not exempt later packets from the rule that
    // their payload length must equal the reference `T`. The stream is a base
    // metadata packet with an invalid layout (F=1, NB=2, so KS=0) followed by
    // a data frame with a different length (P=2048). Once that frame is
    // rejected, the scanner must advance only one byte (observable through
    // `bad_frames`) instead of swallowing the whole packet.
    let oti = Oti::new(1, 4080, 2, [0x45; 32]);
    let mut stream = build_meta_packet(P4096, &oti, false).expect("metadata");
    stream.extend_from_slice(&data_frame(2048, 0, 0, 0xCD));
    let mut engine = DecodeEngine::new();
    let stats = scan_into(&stream[..], &mut engine).expect("scan");

    assert_eq!(
        stats.bad_frames, 1,
        "wrong-length frame rejected, then scan falls back one byte"
    );
    assert_eq!(
        stats.crc_failures, 0,
        "the frame CRC is valid; it was rejected for length, not a CRC failure"
    );
    assert_eq!(
        stats.sync_candidates, 2,
        "reference metadata plus the differently sized data frame"
    );
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Malformed);
    assert_eq!(
        result.stats.bad_packets, 1,
        "\"wrong length\" is counted as a bad packet (F1)"
    );
}

#[test]
fn test_byte_fifo_stream() {
    // Non-seekable byte-level FIFO: each `read` returns exactly one byte, and
    // the whole stream must still be recovered frame by frame.
    let data = det_bytes(4_096, 0x3050);
    let (bytes, _) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");

    let mut engine = DecodeEngine::new();
    let stats = scan_into(ChunkReader::new(&bytes, 1), &mut engine).expect("scan");
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert_eq!(stats.bytes_scanned, bytes.len() as u64);
    assert!(stats.sync_candidates >= 1);
}
