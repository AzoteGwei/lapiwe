//! Integration tests for container decoding.
//!
//! The tests cover metadata/data dispatch, direct and erasure-coded block
//! recovery, block assembly and hash verification, short streams, layout
//! validation, result classification, and `--force` streams. The CLI layer is
//! out of scope: candidate frames are fed to the decoder on `P`-byte
//! boundaries, so frame-scanning robustness is not exercised here.
//!
//! Each block is decoded by an independent `SourceBlockDecoder` with
//! `source_block_id=0` and block OTI `(K_j·T, T, 1, 1, 8)`. BLAKE3 is the
//! only final authority. All test data is generated deterministically; no
//! random source is used.

use lapiwe::container::counts::{a_j, is_meta_slot, needed_j};
use lapiwe::container::decode::{DecodeConfig, DecodeEngine, DecodeSummary};
use lapiwe::container::encode::{EncodeConfig, TotalSpec, block_oti, encode};
use lapiwe::container::header::{MicroHeader, seal_packet, write_microheader};
use lapiwe::container::meta::{Oti, build_meta_packet};
use lapiwe::container::outcome::{DecodeOutcome, Verify};
use lapiwe::container::params::packet_code_for;
use raptorq::{EncodingPacket, SourceBlockDecoder, SourceBlockEncoder};

const P4096: usize = 4096;
const T4080: usize = 4080;
const M256: u64 = 256;
const K_MAX_4096: u64 = 16_448; // floor(64 MiB / 4080); the default tier

fn enc_cfg(p: usize, m: u64, k_max: u64, total: TotalSpec, force: bool) -> EncodeConfig {
    EncodeConfig {
        p,
        m,
        k_max,
        total,
        force,
    }
}

/// Generate deterministic test data with xorshift64*.
/// Encoding and decoding themselves must not use randomness.
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

/// Feed `bytes` to `engine` as complete `P`-byte slots.
fn feed_aligned(engine: &mut DecodeEngine, bytes: &[u8], p: usize) {
    for slot in bytes.chunks_exact(p) {
        engine.observe(slot);
    }
}

fn decode_bytes(bytes: &[u8], p: usize) -> DecodeSummary {
    let mut engine = DecodeEngine::new();
    feed_aligned(&mut engine, bytes, p);
    engine.finish(&DecodeConfig { no_verify: false })
}

fn decode_bytes_no_verify(bytes: &[u8], p: usize) -> DecodeSummary {
    let mut engine = DecodeEngine::new();
    feed_aligned(&mut engine, bytes, p);
    engine.finish(&DecodeConfig { no_verify: true })
}

/// Build a container data frame with a valid CRC. The payload must be at
/// most `T` bytes.
fn data_frame(p: usize, blk_idx: u32, esi: u32, payload: &[u8]) -> Vec<u8> {
    let code = packet_code_for(p).expect("valid P");
    let mut packet = vec![0u8; p];
    write_microheader(
        &mut packet,
        &MicroHeader::new(false, false, blk_idx, esi, code),
    );
    packet[16..16 + payload.len()].copy_from_slice(payload);
    seal_packet(&mut packet);
    packet
}

#[test]
fn test_dispatch_stats() {
    // Metadata/data dispatch, `(blk, esi)` de-duplication keeping the first
    // copy, bad-packet counting, and statistics reporting.
    let f = 1024 * 1024usize;
    let data = det_bytes(f, 0x3100);
    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    assert_eq!((summary.c_total, summary.c_meta, summary.d), (264, 2, 262));

    // Append a duplicate packet (same `(blk, esi)`), an out-of-range bad
    // packet, and conflicting metadata from another stream.
    let mut stream = bytes.clone();
    stream.extend_from_slice(&bytes[P4096..2 * P4096]); // duplicate: (blk=0, esi=0)
    let bad = data_frame(P4096, 1, 0, &[0xAA; T4080]); // NB=1, so BLK_IDX=1 is out of range
    stream.extend_from_slice(&bad);
    let (other, _) = encode(&det_bytes(T4080, 0x3199), &cfg).expect("second stream");
    stream.extend_from_slice(&other[..P4096]); // conflicting metadata (different OTI)

    let mut engine = DecodeEngine::new();
    feed_aligned(&mut engine, &stream, P4096);
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert_eq!(
        result.outcome,
        DecodeOutcome::Ok,
        "conflict/dup/bad packets must not prevent success"
    );
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert_eq!(
        result.stats.dup, 1,
        "duplicate (blk,esi) counts as dup, first copy kept"
    );
    assert_eq!(
        result.stats.bad_packets, 1,
        "BLK_IDX >= NB counts as a bad packet"
    );
    assert_eq!(result.stats.total_blocks, 1);
    assert_eq!(result.stats.max_block_bytes, 258 * 4080, "max_j(K_j*T)");
    assert!(!result.stats.best_effort);
    assert_eq!(
        engine.meta_stats().agree_meta,
        1,
        "metadata in the 256th slot agrees with the baseline"
    );
    assert_eq!(engine.meta_stats().conflict, 1);
    assert_eq!(engine.meta_stats().bad_meta, 0);

    // Dispatch is independent of input order: feeding packets in reverse order
    // (data first, baseline last) still decodes.
    let slots: Vec<&[u8]> = bytes.chunks_exact(P4096).collect();
    let mut engine = DecodeEngine::new();
    for slot in slots.iter().rev() {
        engine.observe(slot);
    }
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    assert_eq!(result.stats.dup, 0);

    // Decoder side of a `--force` stream: the `best_effort` flag must be
    // reported without changing the exit code. D=255 < K=258 and no repair
    // symbols are added, so the block cannot be solved: `Insufficient` (2).
    let forced = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Size(f as u64), true);
    let (forced_bytes, forced_summary) = encode(&data, &forced).expect("--force encode");
    assert!(forced_summary.best_effort);
    let result = decode_bytes(&forced_bytes, P4096);
    assert!(result.stats.best_effort, "must report the best_effort bit");
    assert_eq!(result.outcome, DecodeOutcome::Insufficient);
    assert_eq!(result.outcome.exit_code(), 2);
    assert!(result.data.is_none());
}

#[test]
fn test_direct_path() {
    // A lossless default stream uses the direct path for every block (one
    // direct block per source block), never invokes the solver, and
    // reproduces the input byte for byte.
    for (f, k_max, nb) in [(4_177_921u64, 64u64, 17u32), (4_177_921, 4, 257)] {
        let data = det_bytes(f as usize, 0x3200 ^ f);
        let cfg = enc_cfg(P4096, M256, k_max, TotalSpec::Default, false);
        let (bytes, summary) = encode(&data, &cfg).expect("encode");
        assert_eq!(summary.leveling.nb, nb, "F={f} K_max={k_max}");

        let mut engine = DecodeEngine::new();
        feed_aligned(&mut engine, &bytes, P4096);
        let result = engine.finish(&DecodeConfig { no_verify: false });

        assert_eq!(result.outcome, DecodeOutcome::Ok, "NB={nb}");
        assert_eq!(
            result.stats.direct_blocks,
            u64::from(nb),
            "direct blocks = NB"
        );
        assert_eq!(
            result.stats.solved_blocks, 0,
            "a lossless stream must not invoke the solver"
        );
        assert_eq!(result.stats.solved_total(), u64::from(nb));
        assert_eq!(result.stats.bad_packets, 0);
        assert_eq!(result.data.as_deref(), Some(data.as_slice()), "NB={nb}");
    }
}

/// Enumerate all ways to omit `m` of `k` source symbols, in a fixed order.
fn missing_sets(k: u32, m: u32) -> Vec<Vec<u32>> {
    let idx: Vec<u32> = (0..k).collect();
    let mut out = Vec::new();
    match m {
        1 => {
            for a in &idx {
                out.push(vec![*a]);
            }
        }
        2 => {
            for (i, a) in idx.iter().enumerate() {
                for b in &idx[i + 1..] {
                    out.push(vec![*a, *b]);
                }
            }
        }
        3 => {
            for (i, a) in idx.iter().enumerate() {
                for (j, b) in idx[i + 1..].iter().enumerate() {
                    for c in &idx[i + 2 + j..] {
                        out.push(vec![*a, *b, *c]);
                    }
                }
            }
        }
        _ => unreachable!("m ≤ 3"),
    }
    out
}

/// Search for a singular symbol set and return
/// `(K, singular ESIs, extra ESI, block data)`.
///
/// The desired property is that decoding the singular set returns `None`
/// (exactly K distinct symbols, but a singular matrix), while decoding that
/// set plus one extra symbol succeeds and reproduces the original data. The
/// search order is fixed (K ascending, 1/2/3 missing source symbols plus the
/// same number of repair symbols) so the result is deterministic.
fn find_singular_set() -> (u32, Vec<u32>, u32, Vec<u8>) {
    for k in 3..=32u32 {
        let len = u64::from(k) * T4080 as u64;
        let data = det_bytes(len as usize, 0x3300 + u64::from(k));
        let oti = block_oti(len, T4080 as u16);
        let encoder = SourceBlockEncoder::new(0, &oti, &data);
        let sources = encoder.source_packets();
        let repairs = encoder.repair_packets(0, 8);
        let packet = |esi: u32| -> EncodingPacket {
            if esi < k {
                sources[esi as usize].clone()
            } else {
                repairs[(esi - k) as usize].clone()
            }
        };
        let decode = |esis: &[u32]| -> Option<Vec<u8>> {
            let packets: Vec<EncodingPacket> = esis.iter().map(|&e| packet(e)).collect();
            SourceBlockDecoder::new(0, &oti, len).decode(packets)
        };
        for m in 1..=3u32 {
            for miss in missing_sets(k, m) {
                let mut set: Vec<u32> = (0..k).filter(|i| !miss.contains(i)).collect();
                set.extend(k..k + m);
                let extra = k + m;
                let mut with_extra = set.clone();
                with_extra.push(extra);
                if decode(&set).is_none() && decode(&with_extra).as_deref() == Some(data.as_slice())
                {
                    eprintln!("find_singular_set: k={k} m={m} set={set:?} extra={extra}");
                    return (k, set, extra, data);
                }
            }
        }
    }
    panic!("no deterministic singular K_j subset found (search space too small)");
}

#[test]
fn test_solve_retry() {
    // With exactly K_j distinct singular symbols the decoder must not give up
    // immediately; only at end of stream does it report `Insufficient` (2).
    // Adding one new symbol makes the block solvable: `Ok` (0), byte-identical.
    let (k, singular, extra, data) = find_singular_set();
    let f = u64::from(k) * T4080 as u64;
    let oti = Oti::new(f, T4080 as u16, 1, *blake3::hash(&data).as_bytes());
    let meta = build_meta_packet(P4096, &oti, false).expect("metadata");

    // Rebuild the block's symbol payloads with the same deterministic encoder
    // used by the search.
    let encoder = SourceBlockEncoder::new(0, &block_oti(f, T4080 as u16), &data);
    let sources = encoder.source_packets();
    let repairs = encoder.repair_packets(0, 8);
    let frame = |esi: u32| -> Vec<u8> {
        let payload = if esi < k {
            sources[esi as usize].data()
        } else {
            repairs[(esi - k) as usize].data()
        };
        data_frame(P4096, 0, esi, payload)
    };

    // A: the singular set alone fails to solve; when the stream ends the
    // decoder reports `Insufficient` without panicking or claiming `Ok`.
    let mut engine = DecodeEngine::new();
    engine.observe(&meta);
    for &esi in &singular {
        engine.observe(&frame(esi));
    }
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Insufficient, "K={k}");
    assert!(result.signals.insufficient);
    assert!(result.data.is_none());
    assert_eq!(result.stats.direct_blocks, 0);
    assert_eq!(result.stats.solved_blocks, 0);

    // B: the singular set plus one new symbol retries successfully: `Ok` and a
    // byte-identical result with a matching BLAKE3 hash.
    let mut engine = DecodeEngine::new();
    engine.observe(&meta);
    for &esi in &singular {
        engine.observe(&frame(esi));
    }
    engine.observe(&frame(extra));
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Ok, "K={k}");
    assert_eq!(
        result.stats.solved_blocks, 1,
        "must be solved through the solver"
    );
    assert_eq!(
        result.stats.direct_blocks, 0,
        "missing source symbols must not use the direct path"
    );
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
}

#[test]
fn test_assemble_hash() {
    // Assemble blocks in order, truncate to F, and compare BLAKE3 hashes.
    // Sizes range from 1 byte to several megabytes, including multi-block
    // inputs and a zero-padded final symbol.
    let cases: [(usize, u64, u32); 6] = [
        (1, K_MAX_4096, 1),
        (T4080, K_MAX_4096, 1),
        (T4080 + 1, K_MAX_4096, 1),
        (8 * T4080, K_MAX_4096, 1),
        (1024 * 1024 + 777, 200, 2),
        (4_177_921, 64, 17), // leveling edge case
    ];
    for (f, k_max, nb) in cases {
        let data = det_bytes(f, 0x3400 ^ f as u64);
        let (bytes, summary) = encode(
            &data,
            &enc_cfg(P4096, M256, k_max, TotalSpec::Default, false),
        )
        .expect("encode");
        assert_eq!(summary.leveling.nb, nb, "F={f}");

        let result = decode_bytes(&bytes, P4096);
        assert_eq!(result.outcome, DecodeOutcome::Ok, "F={f}");
        let out = result
            .data
            .expect("a fully solved stream must have assembled data");
        assert_eq!(out.len(), f, "F={f}: output must be truncated to F");
        assert_eq!(out, data, "F={f}");
    }

    // Positive case with M=2, the densest metadata phase.
    for (f, m) in [(4081usize, 2u64), (100_000, 2)] {
        let data = det_bytes(f, 0x3402 ^ f as u64);
        let cfg = enc_cfg(P4096, m, K_MAX_4096, TotalSpec::Default, false);
        let (bytes, _) = encode(&data, &cfg).expect("encode");
        let result = decode_bytes(&bytes, P4096);
        assert_eq!(result.outcome, DecodeOutcome::Ok, "M={m} F={f}");
        assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    }
    // Additional packet sizes, including 8192, 16384, and 32768. The 42 KB
    // payload covers multiple symbols and a zero-padded final symbol.
    for p in [2048usize, 8192, 16_384, 32_768, 65_536] {
        let data = det_bytes(42_000, 0x3400 + p as u64);
        let cfg = enc_cfg(p, M256, 100, TotalSpec::Default, false);
        let (bytes, _) = encode(&data, &cfg).expect("encode");
        let result = decode_bytes(&bytes, p);
        assert_eq!(result.outcome, DecodeOutcome::Ok, "P={p}");
        assert_eq!(result.data.as_deref(), Some(data.as_slice()));
    }
}

#[test]
fn test_blake3_authority() {
    // A valid CRC does not prove a symbol is correct (roughly 2^-32 false
    // positives). After tampering with a payload and resealing the CRC, the
    // direct path still accepts a seemingly valid symbol; only BLAKE3 catches
    // it, yielding `HashMismatch` (4).
    let f = 4081usize;
    let data = det_bytes(f, 0x3500);
    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let (mut bytes, _) = encode(&data, &cfg).expect("encode");
    bytes[P4096 + 100] ^= 0xFF;
    seal_packet(&mut bytes[P4096..2 * P4096]); // reseal, so CRC cannot reject it

    let result = decode_bytes(&bytes, P4096);
    assert_eq!(result.signals.verify, Verify::Verified(false));
    assert_eq!(result.outcome, DecodeOutcome::HashMismatch);
    assert_eq!(result.outcome.exit_code(), 4);
    assert_eq!(
        result.stats.direct_blocks, 1,
        "CRC false-positive symbol still uses the direct path"
    );
    assert_ne!(result.data.as_deref(), Some(data.as_slice()));

    // With `--no-verify`, BLAKE3 is skipped: the outcome is `Ok`, but the data
    // is untrustworthy (the warning belongs to the CLI layer).
    let result = decode_bytes_no_verify(&bytes, P4096);
    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(result.signals.verify, Verify::Skipped);
    assert_ne!(result.data.as_deref(), Some(data.as_slice()));

    // The solver path also uses BLAKE3 as the only authority: with a corrupt
    // symbol the result is either `HashMismatch` (4) or `Insufficient` (2),
    // never `Ok` (0).
    let f2 = 8 * T4080; // K=8, NB=1, D=12 (8 source + 4 repair symbols)
    let data2 = det_bytes(f2, 0x3501);
    let (bytes2, summary2) = encode(&data2, &cfg).expect("encode");
    assert_eq!((summary2.leveling.nb, summary2.d), (1, 12));
    let mut stream = Vec::new();
    stream.extend_from_slice(&bytes2[..P4096]); // metadata
    let mut corrupted = bytes2[P4096..2 * P4096].to_vec(); // ESI 0 (source)
    corrupted[16 + 7] ^= 0x5A;
    seal_packet(&mut corrupted);
    stream.extend_from_slice(&corrupted);
    stream.extend_from_slice(&bytes2[2 * P4096..3 * P4096]); // ESI 1 (source)
    // Drop ESI 2 and 3 (source symbols) and keep ESI 4..11 (4 source + 4
    // repair symbols), so the solver must run.
    stream.extend_from_slice(&bytes2[5 * P4096..]);
    let result = decode_bytes(&stream, P4096);
    assert!(
        matches!(
            result.outcome,
            DecodeOutcome::HashMismatch | DecodeOutcome::Insufficient
        ),
        "bad symbol must not produce Ok, got {:?}",
        result.outcome
    );
    assert_ne!(result.outcome, DecodeOutcome::Ok);
}

#[test]
fn test_short_stream() {
    // Short-stream guarantees: F=1, F=T, and F=T+1 decode completely under
    // the default encoding, and the sufficiency condition can be evaluated.
    for f in [1usize, T4080, T4080 + 1] {
        let data = det_bytes(f, 0x4000 + f as u64);
        let (bytes, summary) = encode(
            &data,
            &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
        )
        .expect("encode");
        for j in 0..summary.leveling.nb {
            let a = a_j(summary.d, summary.leveling.nb, j);
            assert!(
                a >= needed_j(summary.leveling.k_j(j)),
                "F={f} block {j}: default C_total must make every block sufficient"
            );
        }
        let result = decode_bytes(&bytes, P4096);
        assert_eq!(result.outcome, DecodeOutcome::Ok, "F={f}");
        assert_eq!(result.data.as_deref(), Some(data.as_slice()), "F={f}");
    }

    // Without metadata packets, no amount of data symbols is sufficient:
    // `NoOti` (3).
    let data = det_bytes(T4080, 0x4001);
    let (bytes, summary) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");
    assert_eq!(summary.c_total, 6);
    let mut engine = DecodeEngine::new();
    for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
        if !is_meta_slot(i as u64, M256) {
            engine.observe(slot);
        }
    }
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::NoOti);
    assert_eq!(result.outcome.exit_code(), 3);
    assert!(!result.signals.baseline_oti);
    assert!(result.data.is_none());
    assert_eq!(result.stats.total_blocks, 0);
}

#[test]
fn test_decode_ignores_local_m_blk() {
    // The decoder must not reject a valid stream because of a local 64 MiB
    // block limit; it only reports max_j(K_j·T). With F = 1 GiB, T = 4080,
    // NB = 5, max K_j·T is about 214.7 MB, yet the layout stays valid.
    let f = 1u64 << 30;
    let oti = Oti::new(f, 4080, 5, [0x21; 32]);
    let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
    let mut engine = DecodeEngine::new();
    engine.observe(&meta);
    let result = engine.finish(&DecodeConfig { no_verify: false });

    assert!(
        !result.signals.layout_malformed,
        "valid layout must not be judged Malformed"
    );
    let layout = result.layout.expect("layout must be established");
    assert_eq!((layout.nb, layout.ks, layout.r), (5, 52_634, 3));
    assert_eq!(result.stats.max_block_bytes, 52_635 * 4080);
    assert!(result.stats.max_block_bytes > 64 * 1024 * 1024);
    assert_eq!(
        result.outcome,
        DecodeOutcome::Insufficient,
        "must report 2 for insufficient symbols, not reject due to a local budget"
    );
    assert_eq!(engine.baseline_oti(), Some(oti));
}

#[test]
fn test_result_classes_e2e() {
    // One real input per result class, in the order the outcomes take
    // precedence.
    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let data = det_bytes(1024 * 1024, 0x4300);
    let (bytes, _) = encode(&data, &cfg).expect("encode");

    // Ok(0)
    let result = decode_bytes(&bytes, P4096);
    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(result.outcome.exit_code(), 0);

    // `NoOti` (3): pure noise has no usable OTI, so not even a baseline can be
    // established.
    let noise = det_bytes(3 * P4096, 0x4301);
    let mut engine = DecodeEngine::new();
    feed_aligned(&mut engine, &noise, P4096);
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::NoOti);
    assert_eq!(result.outcome.exit_code(), 3);
    assert_eq!(result.stats.bad_packets, 3);

    // `Malformed` (1): the header is valid (F=1, T=P−16, NB=2), but the layout
    // has KS=0; this takes precedence over `Insufficient`.
    let oti = Oti::new(1, 4080, 2, [0x43; 32]);
    let meta = build_meta_packet(P4096, &oti, false).expect("metadata");
    let mut engine = DecodeEngine::new();
    engine.observe(&meta);
    engine.observe(&data_frame(P4096, 0, 0, &[0; T4080])); // extra data changes nothing
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Malformed);
    assert_eq!(result.outcome.exit_code(), 1);
    assert!(result.signals.layout_malformed);
    assert!(result.data.is_none());

    // `Insufficient` (2): a valid stream truncated to 100 of the 258 distinct
    // symbols of block 0.
    let mut engine = DecodeEngine::new();
    let mut taken = 0u64;
    for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
        if is_meta_slot(i as u64, M256) {
            engine.observe(slot);
            continue;
        }
        if taken == 100 {
            break;
        }
        engine.observe(slot);
        taken += 1;
    }
    let result = engine.finish(&DecodeConfig { no_verify: false });
    assert_eq!(result.outcome, DecodeOutcome::Insufficient);
    assert_eq!(result.outcome.exit_code(), 2);
    assert!(result.data.is_none());

    // `HashMismatch` (4): a CRC false positive (tampered payload, resealed)
    // lets every block decode, but BLAKE3 does not match.
    let small = det_bytes(4081, 0x4302);
    let (mut bad, _) = encode(&small, &cfg).expect("encode");
    bad[P4096 + 16 + 32] ^= 0x01; // payload of data slot 1, past the 16-byte micro header
    seal_packet(&mut bad[P4096..2 * P4096]);
    let result = decode_bytes(&bad, P4096);
    assert_eq!(result.outcome, DecodeOutcome::HashMismatch);
    assert_eq!(result.outcome.exit_code(), 4);
    assert_eq!(result.signals.verify, Verify::Verified(false));
}

#[test]
fn test_t2032_multi_block() {
    // Multi-block round trip with T=2032 (P=2048): S > K_max, two block sizes
    // (60 and 61), and truncation of the zero-padded final block. This covers
    // a combination the other tests do not.
    let t = 2032u64;
    let s = 1030u64; // K_max=64 gives NB=17, KS=60, R=10
    let f = (s - 1) * t + 777; // final symbol is partially filled: F mod T ≠ 0
    let data = det_bytes(f as usize, 0x2032);
    let cfg = enc_cfg(2048, M256, 64, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    assert_eq!(
        (summary.leveling.nb, summary.leveling.ks, summary.leveling.r),
        (17, 60, 10),
        "S=1030, K_max=64"
    );
    assert_eq!(summary.leveling.k_j(0), 61);
    assert_eq!(summary.leveling.k_j(9), 61);
    assert_eq!(summary.leveling.k_j(10), 60);
    assert_eq!(summary.leveling.k_j(16), 60);

    let result = decode_bytes(&bytes, 2048);
    assert_eq!(result.outcome, DecodeOutcome::Ok);
    assert_eq!(
        result.stats.direct_blocks, 17,
        "lossless stream uses the direct path everywhere"
    );
    assert_eq!(result.stats.max_block_bytes, 61 * 2032);
    let out = result
        .data
        .expect("a fully solved stream must have assembled data");
    assert_eq!(out.len(), f as usize, "output must be truncated to F");
    assert_eq!(out, data);
}

#[test]
fn test_force_full_source_ok() {
    // With a_j = K_j < needed_j (all source symbols, no repair), a `--force`
    // stream sets best_effort=1, yet each block decodes fully through the
    // direct path, so the outcome is `Ok` (0). The flag must not change the
    // exit code.
    let f = 1024 * 1024usize; // T=4080 gives K=258, needed=262
    let data = det_bytes(f, 0x4200);
    let c_total = 260u64; // D = 260 − ceil(260/256) = 258 = K
    let cfg = enc_cfg(
        P4096,
        M256,
        K_MAX_4096,
        TotalSpec::Size(c_total * P4096 as u64),
        true,
    );
    let (bytes, summary) = encode(&data, &cfg).expect("--force encode");
    assert_eq!(
        (summary.c_total, summary.d, summary.leveling.nb),
        (c_total, 258, 1)
    );
    assert!(summary.best_effort);
    assert_eq!(summary.redundancy.min_slack, -4, "258 < needed_j=262");
    assert_eq!(summary.redundancy.affected_blocks, 1);

    let result = decode_bytes(&bytes, P4096);
    assert!(result.stats.best_effort, "decoder must report the flag");
    assert_eq!(
        result.stats.direct_blocks, 1,
        "all 258 source symbols present -> direct path"
    );
    assert_eq!(result.stats.solved_blocks, 0);
    assert_eq!(
        result.outcome,
        DecodeOutcome::Ok,
        "a_j=K_j<needed_j but the block is already solved -> 0 (reading A would wrongly report 2)"
    );
    assert_eq!(result.outcome.exit_code(), 0);
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
}

#[test]
fn test_rsv_nonzero_stats() {
    // Non-zero reserved bits in the top 5 bits of `PKT_CODE` do not make a
    // frame invalid; the decoder must count them in `rsv_nonzero`.
    let f = 4081usize;
    let data = det_bytes(f, 0x1200);
    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let (bytes, _) = encode(&data, &cfg).expect("encode");

    let mut stream = bytes.clone();
    // Copy a real data packet, set the top 5 bits, and reseal the CRC: it is
    // still accepted and interpreted by the low 3 bits.
    let mut tampered = bytes[P4096..2 * P4096].to_vec();
    tampered[11] |= 0xE8;
    assert_ne!(tampered[11] >> 3, 0, "top 5 bits must be non-zero");
    seal_packet(&mut tampered);
    // Same `(blk, esi)` as the first packet: counts as a duplicate, but
    // `rsv_nonzero` is still counted.
    stream.extend_from_slice(&tampered);

    let result = decode_bytes(&stream, P4096);
    assert_eq!(
        result.outcome,
        DecodeOutcome::Ok,
        "top 5 bits do not make it invalid"
    );
    assert_eq!(result.stats.rsv_nonzero, 1);
    assert_eq!(result.stats.dup, 1, "first copy kept");
    assert_eq!(result.stats.bad_packets, 0);
    assert_eq!(result.data.as_deref(), Some(data.as_slice()));
}
