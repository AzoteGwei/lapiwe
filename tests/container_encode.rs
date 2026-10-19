//! Integration tests for the encoder.
//!
//! These tests cover the encoding side of the container: one independent
//! RaptorQ source block per block, interleaved slot traversal, the redundancy
//! gate, the two-pass structure, and deterministic output. Decoding, the ring
//! scanner, and the CLI surface are covered by other test files.
//!
//! Key invariant: a block OTI is always `(K_j·T, T, 1, 1, 8)`; the global `F`
//! is never passed to the codec crate. All test data is generated
//! deterministically, with no randomness.

use lapiwe::container::counts::{a_j, c_total_from_redundancy, data_slot, is_meta_slot};
use lapiwe::container::encode::{
    BlobInfo, EncodeConfig, EncodeError, TotalSpec, block_oti, encode, encode_to, prescan,
};
use lapiwe::container::header::parse_header;
use lapiwe::container::leveling::Leveling;
use lapiwe::container::meta::parse_meta_packet;
use raptorq::SourceBlockEncoder;

const P4096: usize = 4096;
const T4080: usize = 4080;
const M256: u64 = 256;
const K_MAX_4096: u64 = 16_448; // floor(64 MiB / 4080); default tier for explicit cases

fn enc_cfg(p: usize, m: u64, k_max: u64, total: TotalSpec, force: bool) -> EncodeConfig {
    EncodeConfig {
        p,
        m,
        k_max,
        total,
        force,
    }
}

/// Generate deterministic test data with an xorshift64* generator. The encoder
/// itself must not use any source of randomness.
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

/// Build the expected data for block `j` independently of the encoder, without
/// calling the implementation's block splitter.
fn expected_block_data(data: &[u8], lv: &Leveling, j: u32) -> Vec<u8> {
    let start = lv.offset_j(j) * lv.t;
    let end = ((lv.offset_j(j) + lv.k_j(j)) * lv.t).min(data.len() as u64);
    let mut block = data[start as usize..end as usize].to_vec();
    block.resize((lv.k_j(j) * lv.t) as usize, 0);
    block
}

/// Recompute the payloads for ESIs `0..a_j` of every block independently: source
/// symbols come first, then repair symbols starting at `K_j`.
fn expected_block_payloads(data: &[u8], lv: &Leveling, d: u64) -> Vec<Vec<Vec<u8>>> {
    (0..lv.nb)
        .map(|j| {
            let count = a_j(d, lv.nb, j);
            if count == 0 {
                return Vec::new();
            }
            let k = lv.k_j(j);
            let block = expected_block_data(data, lv, j);
            let oti = block_oti(k * lv.t, lv.t as u16);
            let encoder = SourceBlockEncoder::new(0, &oti, &block);
            let mut payloads: Vec<Vec<u8>> = encoder
                .source_packets()
                .into_iter()
                .take(count.min(k) as usize)
                .map(|packet| packet.data().to_vec())
                .collect();
            if count > k {
                payloads.extend(
                    encoder
                        .repair_packets(0, (count - k) as u32)
                        .into_iter()
                        .map(|packet| packet.data().to_vec()),
                );
            }
            payloads
        })
        .collect()
}

/// Compare a container stream slot by slot: every data packet payload must be
/// equal to the payload of an independently encoded `(blk, ESI)` pair.
fn assert_stream_matches_independent_blocks(
    bytes: &[u8],
    p: usize,
    m: u64,
    lv: &Leveling,
    d: u64,
    data: &[u8],
) {
    let expected = expected_block_payloads(data, lv, d);
    let nb = u64::from(lv.nb);
    for (i, slot) in bytes.chunks_exact(p).enumerate() {
        let i = i as u64;
        let header = parse_header(slot).expect("every encoded frame must be valid");
        if is_meta_slot(i, m) {
            assert!(header.is_meta(), "slot {i}");
            continue;
        }
        assert!(!header.is_meta(), "slot {i}");
        let c = data_slot(i, m).expect("not a metadata slot");
        let blk = c % nb;
        let esi = c / nb;
        assert_eq!(header.blk_idx as u64, blk, "slot {i}");
        assert_eq!(header.esi as u64, esi, "slot {i}");
        let payload = &slot[16..];
        let expected_payload = &expected[blk as usize][esi as usize];
        assert_eq!(payload.len(), lv.t as usize, "slot {i}");
        assert_eq!(
            payload,
            expected_payload.as_slice(),
            "slot {i} (blk={blk}, ESI={esi})"
        );
    }
}

#[test]
fn test_independent_blocks() {
    // NB = 257, above the 255 limit: each block gets its own encoder with block
    // ID 0 and its own OTI. Every packet payload must match an independent
    // per-block encoding.
    let f = 4_177_921usize; // S = 1025
    let data = det_bytes(f, 0x2200);
    let cfg = enc_cfg(P4096, M256, 4, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");

    assert!(summary.leveling.nb > 255, "NB=257 should be usable");
    assert_eq!(summary.leveling.nb, 257);
    assert_eq!(
        (summary.leveling.s, summary.leveling.ks, summary.leveling.r),
        (1025, 3, 254)
    );
    assert_eq!((summary.c_total, summary.d), (2062, 2053));
    assert_eq!(bytes.len(), 2062 * P4096);

    // Every block OTI is (K_j·T, T, 1, 1, 8), and the client must not share
    // the global F.
    for j in 0..summary.leveling.nb {
        let k = summary.leveling.k_j(j);
        let oti = block_oti(k * T4080 as u64, T4080 as u16);
        assert_eq!(oti.transfer_length(), k * T4080 as u64, "block {j}");
        assert_ne!(
            oti.transfer_length(),
            f as u64,
            "block {j} uses the global F"
        );
    }

    // Compare all 2062 packet payloads against independent per-block encoding.
    assert_stream_matches_independent_blocks(
        &bytes,
        P4096,
        M256,
        &summary.leveling,
        summary.d,
        &data,
    );
}

#[test]
fn test_redundancy_gate() {
    // Boundary example: --size 1MiB for a 1MiB input gives C=256 and
    // D=255 < needed=262.
    let f = 1024 * 1024usize;
    let data = det_bytes(f, 0x2600);
    let base = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Size(f as u64), false);
    let info = prescan(&data);

    // Default: no output and exit code 2.
    let mut out = Vec::new();
    let err = encode_to(&info, &data, &base, &mut out).unwrap_err();
    assert_eq!(
        err.exit_code(),
        2,
        "default redundancy insufficient -> exit 2"
    );
    match &err {
        EncodeError::RedundancyInsufficient(report) => {
            assert_eq!(report.min_slack, -7, "255 − 262");
            assert_eq!(report.affected_blocks, 1);
        }
        other => panic!("expected RedundancyInsufficient, got {other:?}"),
    }
    assert!(
        out.is_empty(),
        "insufficient default redundancy must not produce output packets"
    );
    assert!(encode(&data, &base).is_err());

    // --force: encoding continues with best_effort=1 and exit code 0; bit 1 is
    // set in every packet, including metadata.
    let forced = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Size(f as u64), true);
    let (bytes, summary) = encode(&data, &forced).expect("--force should succeed");
    assert_eq!((summary.c_total, summary.c_meta, summary.d), (256, 1, 255));
    assert!(summary.best_effort);
    assert_eq!(summary.redundancy.min_slack, -7);
    assert_eq!(bytes.len(), 256 * P4096);
    for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
        let header = parse_header(slot).expect("valid frame");
        assert!(
            header.best_effort(),
            "slot {i} is missing the best_effort bit"
        );
        assert_eq!(header.is_meta(), is_meta_slot(i as u64, M256), "slot {i}");
    }
    let meta = parse_meta_packet(&bytes[..P4096]).expect("packet 0 is metadata");
    assert_eq!((meta.f, meta.t, meta.nb), (f as u64, 4080, 1));

    // D < 1 (C_total=1): --force does not bypass the check. Exit code 1 and no
    // output.
    for force in [false, true] {
        let c1 = enc_cfg(
            P4096,
            M256,
            K_MAX_4096,
            TotalSpec::Size(P4096 as u64),
            force,
        );
        let mut out = Vec::new();
        let err = encode_to(&info, &data, &c1, &mut out).unwrap_err();
        assert!(
            matches!(err, EncodeError::NotPublishable { c_total: 1 }),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 1);
        assert!(out.is_empty());
    }

    // --redundancy overflow: the exact rational computation overflows, giving
    // exit code 1 and no output.
    let overflow = enc_cfg(
        P4096,
        M256,
        K_MAX_4096,
        TotalSpec::Redundancy {
            num: u64::MAX,
            den: 1,
        },
        true,
    );
    let mut out = Vec::new();
    let err = encode_to(&info, &data, &overflow, &mut out).unwrap_err();
    assert!(matches!(err, EncodeError::Layout(_)), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    assert!(out.is_empty());

    // Default is sufficient: C_total=264, slack=0, best_effort=0, and bit 1
    // clear in every packet.
    let default = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &default).expect("default");
    assert_eq!((summary.c_total, summary.c_meta, summary.d), (264, 2, 262));
    assert_eq!(summary.redundancy.min_slack, 0);
    assert!(!summary.best_effort);
    assert_eq!(bytes.len(), 264 * P4096);
    for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
        let header = parse_header(slot).expect("valid frame");
        assert!(
            !header.best_effort(),
            "slot {i} must not have the best_effort bit"
        );
    }

    // --force with the redundancy requirement already met: normal encoding with
    // best_effort=0, byte-identical to the run without --force.
    let forced_ok = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, true);
    let (bytes2, summary2) = encode(&data, &forced_ok).expect("force with sufficient redundancy");
    assert!(!summary2.best_effort);
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_traversal() {
    // Metadata packets occupy slots 0, M, 2M, ...; data slot indices c are
    // consecutive and metadata does not advance them.
    // blk = c mod NB and ESI = floor(c/NB).
    let cases = [
        // (F, K_max, M, C_total, D)
        (1024 * 1024u64, K_MAX_4096, M256, 264u64, 262u64),
        (4_177_921, 64, M256, 1098, 1093), // leveling stress case
        (4081, 64, 2, 12, 6),              // M=2 phase case
    ];
    for (f, k_max, m, c_total, d) in cases {
        let data = det_bytes(f as usize, f ^ 0x2700);
        let cfg = enc_cfg(P4096, m, k_max, TotalSpec::Default, false);
        let (bytes, summary) = encode(&data, &cfg).expect("encode");
        assert_eq!(summary.c_total, c_total, "F={f} M={m}");
        assert_eq!(summary.d, d, "F={f} M={m}");
        assert_eq!(summary.c_meta + summary.d, summary.c_total);
        assert_eq!(
            bytes.len() as u64,
            c_total * P4096 as u64,
            "output must be exactly C_total·P"
        );
        if f == 4_177_921 {
            assert_eq!(bytes.len(), 4_497_408, "reference case: 1098·4096");
        }

        let nb = u64::from(summary.leveling.nb);
        let mut expected_c = 0u64;
        let mut meta_count = 0u64;
        for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
            let i = i as u64;
            let header = parse_header(slot).expect("valid frame");
            if is_meta_slot(i, m) {
                assert!(header.is_meta(), "slot {i} must be metadata");
                assert_eq!((header.blk_idx, header.esi), (0, 0));
                meta_count += 1;
                continue;
            }
            assert!(!header.is_meta(), "slot {i} must be a data packet");
            assert_eq!(
                data_slot(i, m),
                Some(expected_c),
                "data slots must be contiguous"
            );
            assert_eq!(
                header.blk_idx as u64,
                expected_c % nb,
                "slot {i}: blk=c mod NB"
            );
            assert_eq!(
                header.esi as u64,
                expected_c / nb,
                "slot {i}: ESI=floor(c/NB)"
            );
            expected_c += 1;
        }
        assert_eq!(expected_c, d, "data packet count must equal D");
        assert_eq!(
            meta_count, summary.c_meta,
            "metadata packet count must equal C_meta"
        );
    }
}

#[test]
fn test_determinism() {
    // Two encodings with the same parameters must be byte-identical. Byte
    // equality is stronger than digest equality, so the BLAKE3 comparison is
    // only a cross-check.
    let f = 4_177_921usize;
    let data = det_bytes(f, 0x2800);
    let cfg = enc_cfg(P4096, M256, 64, TotalSpec::Default, false);
    let (a, sa) = encode(&data, &cfg).expect("first run");
    let (b, sb) = encode(&data, &cfg).expect("second run");
    assert_eq!(sa, sb);
    assert_eq!(
        a, b,
        "two encodings with identical parameters must be byte-identical"
    );
    assert_eq!(blake3::hash(&a), blake3::hash(&b));

    // Streams with best_effort=1 are deterministic as well.
    let f_mib = 1024 * 1024usize;
    let data_mib = det_bytes(f_mib, 0x2801);
    let forced = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Size(f_mib as u64), true);
    let (c, sc) = encode(&data_mib, &forced).expect("force first run");
    let (d, sd) = encode(&data_mib, &forced).expect("force second run");
    assert!(sc.best_effort && sd.best_effort);
    assert_eq!(c, d, "best_effort=1 streams must also be deterministic");
}

#[test]
fn test_two_pass() {
    // F and BLAKE3 must be fixed before any packet is written (pass 1 =
    // prescan); pass 2 reuses the same (F, BLAKE3). A length mismatch between
    // the two passes produces an explicit error and no output.
    let f = 1024 * 1024 + 123;
    let data = det_bytes(f, 0x2900);
    let info = prescan(&data);
    assert_eq!(info.f, f as u64);
    assert_eq!(
        info.blake3,
        *blake3::hash(&data).as_bytes(),
        "pass 1 digest must be independently recomputable"
    );

    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    // Both entry points must agree: encode (with its internal prescan) and an
    // explicit prescan followed by encode_to.
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    let mut via_to = Vec::new();
    let summary_to = encode_to(&info, &data, &cfg, &mut via_to).expect("encode_to");
    assert_eq!(bytes, via_to);
    assert_eq!(summary, summary_to);

    // The F and BLAKE3 values in the OTI must come from pass 1. Packet 0 is
    // metadata, and its 48-byte OTI is decoded again.
    let meta = parse_meta_packet(&bytes[..P4096]).expect("packet 0 is metadata");
    assert_eq!(meta.f, info.f);
    assert_eq!(meta.blake3, info.blake3);
    assert_eq!(
        (meta.t, meta.nb, meta.n_sub, meta.scheme, meta.rsv),
        (4080, 1, 1, 4, 0)
    );

    // Different source lengths between the two passes produce LengthMismatch,
    // exit code 1, and no output.
    let wrong = BlobInfo {
        f: info.f - 1,
        ..info
    };
    let mut out = Vec::new();
    let err = encode_to(&wrong, &data, &cfg, &mut out).unwrap_err();
    assert!(
        matches!(err, EncodeError::LengthMismatch { expected, actual }
            if expected == info.f - 1 && actual == info.f),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);
    assert!(out.is_empty());
}

#[test]
fn test_per_block_oti() {
    // Every block OTI is (K_j·T, T, 1, 1, 8); the global F never enters the
    // codec's OTI.
    let f = 4_177_921u64;
    let t = T4080 as u16;
    for k_j in [1u64, 3, 60, 61, 258, 16_448] {
        let oti = block_oti(k_j * T4080 as u64, t);
        assert_eq!(oti.transfer_length(), k_j * T4080 as u64, "K={k_j}");
        assert_eq!(oti.symbol_size(), t, "K={k_j}");
        assert_eq!(oti.source_blocks(), 1, "K={k_j}");
        assert_eq!(oti.sub_blocks(), 1, "K={k_j}");
        assert_eq!(oti.symbol_alignment(), 8, "K={k_j}");
        assert_ne!(
            oti.transfer_length(),
            f,
            "K={k_j}: must not use the global F"
        );
    }

    // Leveling stress case (S=1025, K_max=64, so NB=17): per-block OTIs and
    // in-stream payloads must match an independent per-block encoding at the
    // byte level.
    let data = det_bytes(f as usize, 0x3800);
    let cfg = enc_cfg(P4096, M256, 64, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    assert_eq!(summary.leveling.nb, 17);
    for j in 0..summary.leveling.nb {
        let block_len = summary.leveling.k_j(j) * summary.leveling.t;
        let oti = block_oti(block_len, t);
        assert_eq!(oti.transfer_length(), block_len, "block {j}");
        assert!(
            block_len <= 64 * 1024 * 1024,
            "block {j}: encoder-side K_j*T <= M_blk"
        );
        assert_ne!(oti.transfer_length(), f, "block {j}");
    }
    assert_stream_matches_independent_blocks(
        &bytes,
        P4096,
        M256,
        &summary.leveling,
        summary.d,
        &data,
    );
}

#[test]
fn test_encode_bounds() {
    // The maximum data ESI, floor((D-1)/NB), exceeds 2^24 - 1: exit code 1 and
    // no output.
    // Trigger this with a huge --size; the guard runs before any output is
    // allocated or written.
    let f = 4080usize; // S = 1, so NB = 1
    let data = det_bytes(f, 0x4100);
    let info = prescan(&data);
    let huge = enc_cfg(P4096, M256, 64, TotalSpec::Size(u64::MAX), false);
    let mut out = Vec::new();
    let err = encode_to(&info, &data, &huge, &mut out).unwrap_err();
    assert!(matches!(err, EncodeError::MaxEsiExceeded { .. }), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    assert!(out.is_empty(), "out-of-range input must produce no output");

    // Overflow branch: after the u128 division, --redundancy can still produce
    // a C_total close to u64::MAX. C_total·P then overflows, yielding
    // TotalBytesOverflow before the ESI check, exit code 1, and no output. The
    // --size path always keeps C_total·P <= SIZE, so it cannot reach this
    // branch.
    let overflow = enc_cfg(
        P4096,
        M256,
        64,
        TotalSpec::Redundancy {
            num: u64::MAX,
            den: 1,
        },
        true,
    );
    let err = encode_to(&info, &data, &overflow, &mut out).unwrap_err();
    assert_eq!(err.exit_code(), 1);
    match err {
        EncodeError::TotalBytesOverflow { c_total, p } => {
            assert_eq!(p, P4096);
            let expected =
                c_total_from_redundancy(f as u64, u64::MAX, 1, P4096).expect("still representable");
            assert_eq!(
                c_total, expected,
                "C_total must follow the exact rational formula"
            );
            assert!(
                u128::from(c_total) * P4096 as u128 > u128::from(u64::MAX),
                "this case must actually trigger C_total*P overflow"
            );
        }
        other => panic!("expected TotalBytesOverflow, got {other:?}"),
    }
    assert!(out.is_empty(), "overflow must produce no output");
}

#[test]
fn test_esi_continuity() {
    // Each logical block receives exactly the consecutive ESI sequence 0..a_j:
    // source symbols 0..K_j, then repair symbols starting at K_j.
    let f = 4_177_921usize;
    let data = det_bytes(f, 0x3900);
    let cfg = enc_cfg(P4096, M256, 64, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    let lv = &summary.leveling;

    let mut seen: Vec<Vec<u32>> = vec![Vec::new(); lv.nb as usize];
    for (i, slot) in bytes.chunks_exact(P4096).enumerate() {
        let header = parse_header(slot).expect("valid frame");
        if header.is_meta() {
            assert!(is_meta_slot(i as u64, M256), "slot {i}");
            continue;
        }
        seen[header.blk_idx as usize].push(header.esi);
    }

    let mut total = 0u64;
    for (j, esis) in seen.iter().enumerate() {
        let a = a_j(summary.d, lv.nb, j as u32);
        let k = lv.k_j(j as u32);
        assert_eq!(
            esis.len() as u64,
            a,
            "block {j}: distinct symbol count = a_j"
        );
        assert_eq!(
            *esis,
            (0..a as u32).collect::<Vec<u32>>(),
            "block {j}: ESI values must be contiguous in 0..a_j"
        );
        if a > k {
            // Repair symbols start at K_j: a-1 >= K_j, and there is no gap in
            // [K_j, a).
            assert!(u64::from(esis[a as usize - 1]) >= k, "block {j}");
        }
        assert!(esis.iter().all(|&e| u64::from(e) < a), "block {j}");
        total += a;
    }
    assert_eq!(total, summary.d, "sum of symbols over all blocks = D");
}

#[test]
fn test_force_zero_blocks() {
    // When D < NB, some blocks have a_j = 0: blocks j >= D never receive data
    // symbols. --force output must still be structurally valid: zero-symbol
    // blocks do not appear in the stream and the other blocks are unchanged.
    // The default path rejects the input.
    let f = 1024 * 1024usize; // S = 258
    let data = det_bytes(f, 0x2601);
    let size = 2 * P4096 as u64; // C_total = 2, so D = 1 (above the lower bound)
    let info = prescan(&data);

    // Default: the redundancy requirement fails, giving no output and exit
    // code 2.
    // Slack: a_0 = 1 against needed(52) = 56 gives -55; a_1..4 = 0 gives
    // -56 / -55.
    let deny = enc_cfg(P4096, M256, 64, TotalSpec::Size(size), false);
    let mut out = Vec::new();
    let err = encode_to(&info, &data, &deny, &mut out).unwrap_err();
    match &err {
        EncodeError::RedundancyInsufficient(report) => {
            assert_eq!(report.min_slack, -56);
            assert_eq!(report.affected_blocks, 5);
        }
        other => panic!("expected RedundancyInsufficient, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 2);
    assert!(out.is_empty());

    // --force: encoding continues with a_j = [1,0,0,0,0] and sum(a_j) = D;
    // blocks 1..4 emit no packets, and nothing is written out of bounds.
    let forced = enc_cfg(P4096, M256, 64, TotalSpec::Size(size), true);
    let (bytes, summary) = encode(&data, &forced).expect("--force should succeed");
    assert_eq!((summary.c_total, summary.c_meta, summary.d), (2, 1, 1));
    assert_eq!(
        (summary.leveling.nb, summary.leveling.ks, summary.leveling.r),
        (5, 51, 3)
    );
    assert!(summary.best_effort);
    assert_eq!(summary.redundancy.min_slack, -56);
    let a: Vec<u64> = (0..summary.leveling.nb)
        .map(|j| a_j(summary.d, summary.leveling.nb, j))
        .collect();
    assert_eq!(
        a,
        vec![1, 0, 0, 0, 0],
        "D = 1 < NB => at least one block has a_j = 0"
    );
    assert_eq!(a.iter().sum::<u64>(), summary.d);

    // Stream layout: exactly 2 slots (metadata plus the single data packet),
    // and bit 1 is set in every packet.
    assert_eq!(bytes.len(), 2 * P4096);
    let meta = parse_meta_packet(&bytes[..P4096]).expect("packet 0 is metadata");
    assert_eq!((meta.f, meta.nb), (f as u64, 5));
    let h = parse_header(&bytes[P4096..]).expect("valid data frame");
    assert!(!h.is_meta());
    assert_eq!(
        (h.blk_idx, h.esi),
        (0, 0),
        "the only data packet belongs to block 0, ESI 0"
    );
    for slot in bytes.chunks_exact(P4096) {
        assert!(
            parse_header(slot).expect("valid frame").best_effort(),
            "best_effort bit must be set"
        );
    }
}

#[test]
fn test_in_stream_meta_identity() {
    // All metadata packets in a stream must be byte-identical, including the
    // best_effort bit.
    // Default 1 MiB stream with M=256: metadata occupies slots 0 and 256.
    let f = 1024 * 1024usize;
    let data = det_bytes(f, 0x1900);
    let (bytes, summary) = encode(
        &data,
        &enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false),
    )
    .expect("encode");
    assert_eq!(summary.c_meta, 2);
    let metas: Vec<&[u8]> = bytes
        .chunks_exact(P4096)
        .enumerate()
        .filter(|(i, _)| is_meta_slot(*i as u64, M256))
        .map(|(_, slot)| slot)
        .collect();
    assert_eq!(metas.len(), 2, "C_meta = 2");
    assert_eq!(
        metas[0], metas[1],
        "metadata packets in the stream must be byte-identical"
    );
    let oti = parse_meta_packet(metas[0]).expect("baseline metadata");
    assert_eq!((oti.f, oti.nb), (f as u64, 1));

    // M=2 case: metadata is denser but still byte-identical.
    let f2 = 4081usize; // S = 2, so C_total = 12 and C_meta = 6
    let data2 = det_bytes(f2, 0x1901);
    let (bytes2, summary2) =
        encode(&data2, &enc_cfg(P4096, 2, 64, TotalSpec::Default, false)).expect("M=2 encode");
    assert_eq!((summary2.c_total, summary2.c_meta, summary2.d), (12, 6, 6));
    let metas2: Vec<&[u8]> = bytes2
        .chunks_exact(P4096)
        .enumerate()
        .filter(|(i, _)| is_meta_slot(*i as u64, 2))
        .map(|(_, slot)| slot)
        .collect();
    assert_eq!(metas2.len(), 6);
    for meta in &metas2[1..] {
        assert_eq!(
            *meta, metas2[0],
            "M=2: all metadata packets are byte-identical"
        );
    }
}

#[test]
fn test_no_crypto() {
    // No encryption and no compression: plaintext fragments from the input must
    // appear byte for byte in the output stream, where external tools can find
    // them. The marker is embedded in the payload of data symbol 1 (T=4080) and
    // does not cross a symbol boundary.
    let marker = b"LAPIWE-PLAINTEXT-MARKER-0123456789-ABCDEF";
    let mut data = det_bytes(3 * P4096, 0x3700);
    let at = P4096 + 100; // data symbol 1 covers [4080, 8160), so 4196 is in it
    data[at..at + marker.len()].copy_from_slice(marker);

    let cfg = enc_cfg(P4096, M256, K_MAX_4096, TotalSpec::Default, false);
    let (bytes, summary) = encode(&data, &cfg).expect("encode");
    assert_eq!((summary.leveling.s, summary.leveling.nb), (4, 1));

    let pos = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("plaintext marker must appear byte-for-byte in the output stream (no encryption, no compression)");
    // The marker must land in the packet payload area (offset >= 16 within the
    // frame), i.e. it is not part of the encoded header.
    assert!(
        pos % P4096 >= 16,
        "match position {pos} must be in a data packet payload"
    );
}
