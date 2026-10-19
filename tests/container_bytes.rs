//! Integration tests for the container byte layer.
//!
//! These tests cover the micro-header and frame layout, the metadata packet
//! format, packet-count and layout arithmetic, and decode outcome
//! classification.
//!
//! RaptorQ encoding and decoding and the frame scanner are not covered here.

use lapiwe::container::counts::{
    a_j, c_meta, c_total_from_redundancy, c_total_from_size, data_packets, data_slot,
    default_c_total_min, is_meta_slot, needed_j, publishable, redundancy_report,
};
use lapiwe::container::header::{
    FrameDefect, MicroHeader, check_data_block, encode_ver_flags, packet_crc32c, parse_header,
    seal_packet, write_microheader,
};
use lapiwe::container::leveling::{LayoutDefect, Leveling, derive_nb, rejoin, split_blocks};
use lapiwe::container::meta::{
    BLAKE3_LEN, MetaDefect, MetaDisposition, MetaStats, MetaTracker, Oti, OtiDefect,
    build_meta_packet, decode_oti, encode_oti, parse_meta_packet, validate_oti,
};
use lapiwe::container::outcome::{DecodeOutcome, DecodeSignals, Verify, classify};
use lapiwe::container::params::{
    DEFAULT_ENCODE_MAX_MEM, DEFAULT_META_EVERY, MIN_META_EVERY, PACKET_SIZES, RFC_KMAX, SYNC,
    is_legal_packet_code, k_max_from_mem, packet_code_for, packet_size_from_code,
};

const P4096: usize = 4096;
const T4080: usize = 4080;
const M256: u64 = 256;
const K_MAX_4096: u64 = 16_448; // floor(64 MiB / 4080), explicit reference budget
const K_MAX_ENCODE_4096: u64 = 4_112; // floor(16 MiB / 4080), default encode budget

/// A 64 MiB reference budget, kept as a local constant rather than taken from
/// the decoder's default working-set limit. Changing that default must not
/// silently alter the reference values in this file.
const REF_64MIB: u64 = 64 * 1024 * 1024;

fn data_packet(p: usize, blk_idx: u32, esi: u32, best_effort: bool) -> Vec<u8> {
    let code = packet_code_for(p).expect("legal packet size");
    let mut packet = vec![0xA5u8; p];
    write_microheader(
        &mut packet,
        &MicroHeader::new(false, best_effort, blk_idx, esi, code),
    );
    seal_packet(&mut packet);
    packet
}

fn sample_oti(f: u64, t: u16, nb: u32) -> Oti {
    Oti::new(f, t, nb, [0x42; BLAKE3_LEN])
}

/// Recompute `needed_j` independently, without calling the function under test.
fn expected_needed(k: u64) -> u64 {
    (k + 4).max((k * 1005).div_ceil(1000))
}

/// Brute-force `d_req` from its definition; an independent implementation used
/// to cross-check the redundancy arithmetic.
fn expected_d_req(f: u64, t: u64, k_max: u64) -> u64 {
    let s = f.div_ceil(t);
    let nb = s.div_ceil(k_max).max(1);
    let ks = s / nb;
    let r = s % nb;
    let needed = |j: u64| expected_needed(if j < r { ks + 1 } else { ks });
    let mut d = 1u64;
    loop {
        let q = d / nb;
        let rr = d % nb;
        if (0..nb).all(|j| q + u64::from(j < rr) >= needed(j)) {
            return d;
        }
        d += 1;
    }
}

/// Brute-force the smallest `c` with `D(c) >= d_req`.
fn expected_c_total_min(d_req: u64, m: u64) -> u64 {
    let mut c = 1u64;
    while c - c.div_ceil(m) < d_req {
        c += 1;
    }
    c
}

#[test]
fn test_meta_interval() {
    // Default interval is 256; M=0 and M=1 are rejected; M=2 works.
    assert_eq!(DEFAULT_META_EVERY, 256);
    assert_eq!(MIN_META_EVERY, 2);

    // M=0 or M=1: every M-dependent pure function rejects the input.
    for m in [0u64, 1] {
        assert_eq!(c_meta(100, m), None, "M={m}");
        assert_eq!(data_packets(100, m), None, "M={m}");
        assert_eq!(data_slot(1, m), None, "M={m}");
        assert!(!is_meta_slot(0, m), "M={m}");
        assert!(!publishable(100, m), "M={m}");
        assert_eq!(
            default_c_total_min(1, 4080, m, 64),
            Err(LayoutDefect::MetaEveryTooSmall),
            "M={m}"
        );
    }

    // M=2: c_meta = ceil(c / 2) and d = c - c_meta.
    for (c, meta) in [(2u64, 1u64), (3, 2), (4, 2), (5, 3)] {
        assert_eq!(c_meta(c, 2), Some(meta), "C={c}");
        assert_eq!(data_packets(c, 2), Some(c - meta), "C={c}");
    }
    assert!(is_meta_slot(0, 2) && is_meta_slot(2, 2));
    assert!(!is_meta_slot(1, 2));
    assert!(publishable(2, 2));
    assert!(!publishable(1, 2), "C_total=1 -> D=0");

    // With M=2 and F=1: d_req = 5, so the minimum c is 5 + ceil(5 / 1) = 10.
    let r = default_c_total_min(1, 4080, 2, 64).expect("M=2 is legal");
    assert_eq!((r.d_req, r.c_total_min), (5, 10));
    assert_eq!(c_meta(r.c_total_min, 2), Some(5));
    assert_eq!(data_packets(r.c_total_min, 2), Some(5));
}

#[test]
fn test_microheader() {
    // Data packet: offsets, length and big-endian fields; bytes [0..12) are contiguous.
    let packet = data_packet(P4096, 0x01_02_03, 0x04_05_06, true);
    assert_eq!(&packet[0..4], &SYNC, "SYNC at [0..4)");
    assert_eq!(packet[4], 0x42, "VER=4, bit1 best_effort=1, bit0=0");
    assert_eq!(&packet[5..8], &[0x01, 0x02, 0x03], "BLK_IDX big-endian u24");
    assert_eq!(&packet[8..11], &[0x04, 0x05, 0x06], "ESI big-endian u24");
    assert_eq!(packet[11], 1, "PKT_CODE=log2(4096/2048)");
    let crc = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    assert_eq!(
        crc,
        packet_crc32c(&packet).expect("complete frame"),
        "CRC32C big-endian at [12..16))"
    );

    let header = parse_header(&packet).expect("valid frame");
    assert!(!header.is_meta());
    assert!(header.best_effort());
    assert_eq!(header.ver(), 4);
    assert_eq!((header.blk_idx, header.esi), (0x01_02_03, 0x04_05_06));

    // Metadata packet: is_meta=1, blk_idx=0, esi=0.
    let meta =
        build_meta_packet(P4096, &sample_oti(4096, 4080, 1), false).expect("build metadata packet");
    let mh = parse_header(&meta).expect("valid metadata frame");
    assert!(mh.is_meta() && !mh.best_effort());
    assert_eq!((mh.blk_idx, mh.esi), (0, 0));
    assert_eq!(encode_ver_flags(true, false), 0x41);
    assert_eq!(encode_ver_flags(false, true), 0x42);
}

#[test]
fn test_sync() {
    // SYNC is the four bytes "LPW1"; flipping any one of them breaks the match.
    assert_eq!(SYNC, [0x4C, 0x50, 0x57, 0x31]);
    assert_eq!(&SYNC, b"LPW1");
    for pos in 0..4 {
        let mut packet = data_packet(P4096, 0, 0, false);
        packet[pos] ^= 0x01;
        assert_eq!(
            parse_header(&packet),
            Err(FrameDefect::SyncMismatch),
            "tampered SYNC[{pos}] must be rejected"
        );
    }
}

#[test]
fn test_pkt_code() {
    // p = 2048 << (pkt_code & 0x07); all six codes round-trip; the upper five
    // bits do not affect p.
    for (code, p) in PACKET_SIZES.iter().enumerate() {
        let code = code as u8;
        assert_eq!(packet_size_from_code(code), *p);
        assert_eq!(packet_code_for(*p), Some(code));
        assert!(is_legal_packet_code(code));

        let packet = data_packet(*p, 0, 0, false);
        assert_eq!(parse_header(&packet).expect("valid").packet_size_hint(), *p);
    }
    // Packet code 6 is not legal.
    assert_eq!(packet_size_from_code(6), 2048usize << 6);
    assert!(!is_legal_packet_code(6));
    assert!(!is_legal_packet_code(0xFE));
    // Upper five bits set: still interpreted through the low three bits, and
    // counted as rsv_nonzero.
    let mut packet = data_packet(P4096, 0, 0, false);
    packet[11] = 0x29; // 0b00101_001: upper five bits nonzero, low three bits = 1
    seal_packet(&mut packet);
    let header = parse_header(&packet).expect("upper 5 bits do not affect validity");
    assert_eq!(header.packet_code_low(), 1);
    assert!(header.rsv_nonzero());
    assert_eq!(header.packet_size_hint(), P4096);
}

#[test]
fn test_crc32c() {
    // Known test vector, plus coverage of [0..12) and [16..p).
    assert_eq!(crc32c::crc32c(b"123456789"), 0xE306_9283);
    let packet = data_packet(P4096, 0, 0, false);
    let before = packet_crc32c(&packet).expect("complete frame");
    // Changing the payload changes the CRC (bytes [16..p) are covered).
    let mut payload_flip = packet.clone();
    payload_flip[P4096 - 1] ^= 0x01;
    assert_ne!(
        packet_crc32c(&payload_flip).expect("complete frame"),
        before
    );
    assert_eq!(parse_header(&payload_flip), Err(FrameDefect::CrcMismatch));
    // Changing a header field in [0..12) changes the CRC.
    let mut head_flip = packet.clone();
    head_flip[5] ^= 0x01;
    assert_ne!(packet_crc32c(&head_flip).expect("complete frame"), before);
    // Changing [12..16), the CRC field itself, leaves the computed CRC alone
    // because those bytes are not covered, but the stored value no longer
    // matches the recomputed one.
    let mut crc_field_flip = packet.clone();
    crc_field_flip[12..16].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        packet_crc32c(&crc_field_flip).expect("complete frame"),
        before,
        "CRC does not cover [12..16)"
    );
    assert_eq!(
        parse_header(&crc_field_flip),
        Err(FrameDefect::CrcMismatch),
        "tampered CRC field: stored value does not match recomputed value"
    );
    // Short inputs return an explicit error instead of panicking.
    assert_eq!(packet_crc32c(&[]), Err(FrameDefect::TooShort));
    assert_eq!(packet_crc32c(&packet[..15]), Err(FrameDefect::TooShort));
}

#[test]
fn test_field_bounds() {
    // Packet code above the defined maximum.
    let mut packet = data_packet(P4096, 0, 0, false);
    packet[11] = 6;
    seal_packet(&mut packet);
    assert_eq!(parse_header(&packet), Err(FrameDefect::BadPacketCode));

    // The upper four bits of ver_flags do not hold the format version.
    let mut packet = data_packet(P4096, 0, 0, false);
    packet[4] = 0x31;
    assert_eq!(parse_header(&packet), Err(FrameDefect::BadVersion));

    // Length does not match pkt_code.
    let full = data_packet(P4096, 0, 0, false);
    assert_eq!(
        parse_header(&full[..P4096 - 1]),
        Err(FrameDefect::LengthMismatch)
    );

    // CRC mismatch.
    let mut packet = data_packet(P4096, 0, 0, false);
    packet[16] ^= 0xFF;
    assert_eq!(parse_header(&packet), Err(FrameDefect::CrcMismatch));

    // Metadata packet with blk_idx != 0 while the CRC is still valid.
    let mut packet = vec![0u8; P4096];
    let code = packet_code_for(P4096).expect("code");
    write_microheader(&mut packet, &MicroHeader::new(true, false, 5, 0, code));
    seal_packet(&mut packet);
    assert_eq!(parse_header(&packet), Err(FrameDefect::MetaFieldsNonZero));

    // Data packet with blk_idx >= nb: blk=10 is out of range for nb=10 and
    // valid for nb=11.
    let header = parse_header(&data_packet(P4096, 10, 0, false)).expect("valid frame");
    assert_eq!(check_data_block(&header, 11), Ok(()));
    assert_eq!(
        check_data_block(&header, 10),
        Err(FrameDefect::BlockOutOfRange)
    );
}

#[test]
fn test_meta_packet() {
    let oti = sample_oti(1_048_576, 4080, 1);
    let packet = build_meta_packet(P4096, &oti, false).expect("build");
    // 16 + 48 + (p - 64) = p; the padding is all zero.
    assert_eq!(packet.len(), 16 + 48 + (P4096 - 64));
    assert!(
        packet[64..].iter().all(|&b| b == 0),
        "padding must be all zeros"
    );
    // The OTI occupies 48 bytes starting at offset 16 and round-trips.
    let oti_bytes: &[u8; 48] = packet[16..64].try_into().expect("48B");
    assert_eq!(decode_oti(oti_bytes), oti);
    assert_eq!(parse_meta_packet(&packet), Ok(oti));
    // All metadata packets in a stream are byte-identical: rebuilding with the
    // same parameters yields the same bytes.
    let again = build_meta_packet(P4096, &oti, false).expect("build");
    assert_eq!(packet, again);
    // A differing best_effort bit sets bit 1 of byte 4; the CRC changes with
    // it and every other byte stays the same.
    let forced = build_meta_packet(P4096, &oti, true).expect("build");
    assert_eq!(packet[4] ^ forced[4], 0x02);
    let mut expected = packet.clone();
    expected[4] |= 0x02;
    seal_packet(&mut expected);
    assert_eq!(forced, expected);
    for (i, (&a, &b)) in packet.iter().zip(forced.iter()).enumerate() {
        if i == 4 || (12..16).contains(&i) {
            continue;
        }
        assert_eq!(a, b, "byte {i} must not change with bit1");
    }
    // Frame-level check: a data packet is not a metadata packet.
    assert_eq!(
        parse_meta_packet(&data_packet(P4096, 0, 0, false)),
        Err(MetaDefect::NotMeta)
    );
}

#[test]
fn test_meta_phase() {
    // Positions 0, M and 2M are metadata slots; packet 0 is always metadata.
    assert!(is_meta_slot(0, M256));
    assert!(is_meta_slot(256, M256));
    assert!(is_meta_slot(512, M256));
    assert!(!is_meta_slot(1, M256));
    assert!(!is_meta_slot(255, M256));
    assert!(!is_meta_slot(257, M256));
    assert!(!is_meta_slot(0, 1), "M<2 is illegal (R4)");

    // c_meta = ceil(c_total / M) and d = c_total - c_meta.
    for (c_total, expected_meta) in [
        (1u64, 1u64),
        (6, 1),
        (255, 1),
        (256, 1),
        (257, 2),
        (511, 2),
        (512, 2),
        (513, 3),
    ] {
        assert_eq!(c_meta(c_total, M256), Some(expected_meta), "C={c_total}");
        assert_eq!(
            data_packets(c_total, M256),
            Some(c_total - expected_meta),
            "C={c_total}"
        );
    }
    assert_eq!(c_meta(10, 1), None, "M=1 is illegal");
    assert_eq!(c_meta(10, 0), None, "M=0 is illegal");

    // Short streams: c_total < M still gets an OTI in packet 0; d >= 1
    // whenever c_total >= 2.
    assert!(publishable(2, M256));
    assert!(publishable(100, M256));
    assert!(!publishable(1, M256));

    let count_meta_in = |start: u64, len: u64| {
        (start..start + len)
            .filter(|&i| is_meta_slot(i, M256))
            .count()
    };
    // Any packet-aligned segment of exactly M slots contains exactly one
    // metadata packet, including [0, M) and [M, 2M).
    assert_eq!(count_meta_in(0, 256), 1);
    assert_eq!(count_meta_in(256, 256), 1);
    assert_eq!(count_meta_in(10, 256), 1);
    // A segment shorter than 2M may contain two; starting at packet 0,
    // 511 slots include slots 0 and 256.
    assert_eq!(count_meta_in(0, 511), 2);
    assert_eq!(count_meta_in(0, 257), 2);
    assert_eq!(count_meta_in(0, 100), 1);
    // Any aligned segment of at least M slots contains at least one metadata
    // packet.
    for start in (0..1024).step_by(37) {
        assert!(count_meta_in(start, 256) >= 1, "start={start}");
    }
}

#[test]
fn test_data_slot() {
    // Metadata slots do not advance c; data slot numbers are consecutive;
    // c maps to (blk = c mod nb, esi = c / nb).
    let nb = 17u32;
    let mut expected_c = 0u64;
    for i in 0..(3 * M256 + 5) {
        match data_slot(i, M256) {
            None => assert!(is_meta_slot(i, M256), "i={i} only metadata slots are empty"),
            Some(c) => {
                assert_eq!(c, expected_c, "i={i} data slots must be consecutive");
                expected_c += 1;
            }
        }
    }
    assert_eq!(data_slot(1, M256), Some(0));
    assert_eq!(data_slot(17, M256), Some(16));
    assert_eq!(data_slot(18, M256), Some(17));
    assert_eq!(data_slot(256, M256), None);
    assert_eq!(data_slot(257, M256), Some(255));
    // Round-robin mapping: c=0 gives block 0; c=16 gives block 16;
    // c=17 gives block 0 with esi 1.
    let mapping = |c: u64| (c % u64::from(nb), c / u64::from(nb));
    assert_eq!(mapping(0), (0, 0));
    assert_eq!(mapping(16), (16, 0));
    assert_eq!(mapping(17), (0, 1));
}

#[test]
fn test_oti_layout() {
    let oti = Oti {
        f: 0x0102_0304_0506_0708,
        t: 0x0FF0,
        nb: 0x0A_0B_0C,
        n_sub: 1,
        scheme: 4,
        rsv: 0,
        blake3: [0x11; BLAKE3_LEN],
    };
    let bytes = encode_oti(&oti).expect("encode");
    assert_eq!(
        &bytes[0..8],
        &oti.f.to_be_bytes(),
        "F at offset 0, big-endian u64"
    );
    assert_eq!(
        &bytes[8..10],
        &oti.t.to_be_bytes(),
        "T at offset 8, big-endian u16"
    );
    assert_eq!(
        &bytes[10..13],
        &[0x0A, 0x0B, 0x0C],
        "NB at offset 10, big-endian u24"
    );
    assert_eq!(bytes[13], 1, "N_sub at offset 13");
    assert_eq!(bytes[14], 4, "SCHEME at offset 14");
    assert_eq!(bytes[15], 0, "RSV at offset 15");
    assert_eq!(&bytes[16..48], &[0x11; 32], "BLAKE3 at offset 16, 32 bytes");
    assert_eq!(decode_oti(&bytes), oti, "round-trip matches");

    // nb boundary: 2^24 - 1 encodes, 2^24 is rejected.
    let max_nb = Oti {
        nb: 0x00FF_FFFF,
        ..oti
    };
    assert!(encode_oti(&max_nb).is_ok());
    let over = Oti {
        nb: 0x0100_0000,
        ..oti
    };
    assert_eq!(encode_oti(&over), Err(OtiDefect::NbTooLarge));

    // Semantic validation of the OTI fields.
    assert_eq!(validate_oti(&sample_oti(1, 4080, 1), P4096), Ok(()));
    let bad = |f: u64, t: u16, n_sub: u8, scheme: u8, rsv: u8| Oti {
        f,
        t,
        nb: 1,
        n_sub,
        scheme,
        rsv,
        blake3: [0; 32],
    };
    assert_eq!(
        validate_oti(&bad(0, 4080, 1, 4, 0), P4096),
        Err(OtiDefect::FZero)
    );
    assert_eq!(
        validate_oti(&bad(1, 4080, 2, 4, 0), P4096),
        Err(OtiDefect::NSubNot1)
    );
    assert_eq!(
        validate_oti(&bad(1, 4080, 1, 5, 0), P4096),
        Err(OtiDefect::SchemeNot4)
    );
    assert_eq!(
        validate_oti(&bad(1, 4080, 1, 4, 1), P4096),
        Err(OtiDefect::RsvNonZero)
    );
    assert_eq!(
        validate_oti(&bad(1, 4081, 1, 4, 0), P4096),
        Err(OtiDefect::TNotPacketDerived)
    );
    assert_eq!(validate_oti(&bad(1, 4080, 1, 4, 0), P4096), Ok(()));
}

#[test]
fn test_meta_baseline() {
    let a = build_meta_packet(P4096, &sample_oti(4096, 4080, 1), false).expect("A");
    let b = build_meta_packet(P4096, &sample_oti(4096, 4080, 1), false).expect("A'");
    assert_eq!(a, b, "same OTI, same flags: byte-identical");
    let conflict = build_meta_packet(P4096, &sample_oti(4096, 4080, 2), false).expect("B");
    // A valid CRC with an invalid OTI field (F=0) yields bad_meta.
    let bad = build_meta_packet(P4096, &sample_oti(4096, 4080, 1), false).expect("C");
    let mut bad = bad;
    bad[16..24].copy_from_slice(&0u64.to_be_bytes()); // F=0
    seal_packet(&mut bad);
    assert_eq!(
        parse_meta_packet(&bad),
        Err(MetaDefect::Oti(OtiDefect::FZero))
    );

    let mut tracker = MetaTracker::default();
    assert_eq!(tracker.observe(&a), MetaDisposition::Baseline);
    assert_eq!(tracker.observe(&b), MetaDisposition::Agree);
    assert_eq!(tracker.observe(&conflict), MetaDisposition::Conflict);
    assert_eq!(
        tracker.baseline_oti(),
        Some(sample_oti(4096, 4080, 1)),
        "conflict does not replace the baseline"
    );
    assert_eq!(
        tracker.observe(&a),
        MetaDisposition::Agree,
        "baseline is still A"
    );
    assert_eq!(tracker.observe(&bad), MetaDisposition::BadMeta);
    assert_eq!(tracker.observe(&bad), MetaDisposition::BadMeta);
    // Data packets and frames with a broken CRC do not affect metadata
    // counters.
    assert_eq!(
        tracker.observe(&data_packet(P4096, 0, 0, false)),
        MetaDisposition::Ignored
    );
    let mut crc_broken = a.clone();
    crc_broken[20] ^= 0xFF;
    assert_eq!(tracker.observe(&crc_broken), MetaDisposition::Ignored);
    assert_eq!(
        tracker.stats(),
        MetaStats {
            agree_meta: 2,
            conflict: 1,
            bad_meta: 2,
        }
    );

    // Conflicts are only counted; with a baseline present, every packet
    // decoded and the BLAKE3 hash matching, the outcome is Ok (exit code 0).
    let outcome = classify(DecodeSignals {
        baseline_oti: true,
        layout_malformed: false,
        insufficient: false,
        verify: Verify::Verified(true),
    });
    assert_eq!(outcome, DecodeOutcome::Ok);
    assert_eq!(outcome.exit_code(), 0);
}

#[test]
fn test_bad_meta_semantics() {
    // bad_meta counts only candidates with a valid CRC, a valid frame
    // structure, is_meta=1, and an OTI that fails semantic validation.
    // Structurally invalid frames, data packets, and frames with a broken CRC
    // do not affect the metadata counters; broken-packet accounting belongs
    // to the scanner.
    let good_oti = sample_oti(4096, 4080, 1);
    let good = build_meta_packet(P4096, &good_oti, false).expect("baseline");

    // 1. A valid CRC and frame structure with is_meta=1 but an invalid OTI
    //    yields bad_meta for each case.
    let bad_otis = [
        (Oti::new(0, 4080, 1, [0x42; BLAKE3_LEN]), OtiDefect::FZero),
        (
            Oti::new(4096, 4080, 0, [0x42; BLAKE3_LEN]),
            OtiDefect::NbZero,
        ),
        (
            Oti {
                n_sub: 2,
                ..good_oti
            },
            OtiDefect::NSubNot1,
        ),
        (
            Oti {
                scheme: 5,
                ..good_oti
            },
            OtiDefect::SchemeNot4,
        ),
        (Oti { rsv: 1, ..good_oti }, OtiDefect::RsvNonZero),
        (
            Oti {
                t: 4081,
                ..good_oti
            },
            OtiDefect::TNotPacketDerived,
        ),
    ];
    let mut bad_packets = Vec::new();
    for (oti, defect) in bad_otis {
        let packet = build_meta_packet(P4096, &oti, false).expect("build");
        assert_eq!(parse_meta_packet(&packet), Err(MetaDefect::Oti(defect)));
        bad_packets.push(packet);
    }

    // 2. Structurally invalid frames with a self-consistent CRC are ignored
    //    and do not change metadata statistics.
    let code = packet_code_for(P4096).expect("code");
    let mut r12_invalid = Vec::new();
    for (blk, esi) in [(1u32, 0u32), (0, 3)] {
        let mut pkt = vec![0u8; P4096];
        write_microheader(&mut pkt, &MicroHeader::new(true, false, blk, esi, code));
        seal_packet(&mut pkt);
        assert_eq!(parse_header(&pkt), Err(FrameDefect::MetaFieldsNonZero));
        r12_invalid.push(pkt);
    }
    let mut pkt = good.clone();
    pkt[4] = 0x31;
    seal_packet(&mut pkt);
    assert_eq!(parse_header(&pkt), Err(FrameDefect::BadVersion));
    r12_invalid.push(pkt);
    let mut pkt = good.clone();
    pkt[11] = 6;
    seal_packet(&mut pkt);
    assert_eq!(parse_header(&pkt), Err(FrameDefect::BadPacketCode));
    r12_invalid.push(pkt);
    let mut pkt = good.clone();
    pkt[20] ^= 0xFF;
    assert_eq!(parse_header(&pkt), Err(FrameDefect::CrcMismatch));
    r12_invalid.push(pkt);

    let mut tracker = MetaTracker::default();
    assert_eq!(tracker.observe(&good), MetaDisposition::Baseline);
    for packet in &bad_packets {
        assert_eq!(tracker.observe(packet), MetaDisposition::BadMeta);
    }
    for packet in &r12_invalid {
        assert_eq!(tracker.observe(packet), MetaDisposition::Ignored);
    }
    // Data packets (is_meta=0) do not affect metadata counters either.
    assert_eq!(
        tracker.observe(&data_packet(P4096, 0, 0, false)),
        MetaDisposition::Ignored
    );
    assert_eq!(
        tracker.baseline_oti(),
        Some(good_oti),
        "baseline must not be replaced"
    );
    assert_eq!(
        tracker.stats(),
        MetaStats {
            agree_meta: 0,
            conflict: 0,
            bad_meta: 6,
        }
    );
}

#[test]
fn test_leveling() {
    // Worked layout example: k_max=64, t=4080, s=1025.
    let f = 1024 * 4080 + 1; // S = 1025
    let nb = derive_nb(1025, 64).expect("NB");
    assert_eq!(nb, 17);
    let lv = Leveling::derive(f, 4080, nb).expect("layout");
    assert_eq!((lv.s, lv.ks, lv.r), (1025, 60, 5));
    assert_eq!(lv.validate_format(), Ok(()));

    // The k_j values take only two adjacent values, sum to s, and the offsets
    // are contiguous.
    let mut sum = 0u64;
    let mut prev_end = 0u64;
    for j in 0..lv.nb {
        let k = lv.k_j(j);
        assert!(k == 60 || k == 61, "K_{j} = {k}");
        assert_eq!(
            lv.offset_j(j),
            prev_end,
            "offset_{j} must immediately follow the previous block"
        );
        prev_end = lv.offset_j(j) + k;
        sum += k;
    }
    assert_eq!(sum, lv.s);
    assert_eq!(prev_end, lv.s, "offsets cover through the end of S");
    assert_eq!(lv.max_k() - lv.min_k(), 1);
    assert_eq!(lv.k_j(0), 61);
    assert_eq!(lv.k_j(4), 61);
    assert_eq!(lv.k_j(5), 60);
    assert_eq!(lv.k_j(16), 60);
    assert_eq!(lv.offset_j(5), 305);
    assert_eq!(lv.offset_j(16), 965);

    // The same layout derived from an exact multiple of t yields the same
    // values; only the derived quantities are compared, since f itself
    // differs.
    let lv_exact = Leveling::derive(1025 * 4080, 4080, 17).expect("layout");
    assert_eq!(
        (lv_exact.s, lv_exact.ks, lv_exact.r, lv_exact.nb),
        (lv.s, lv.ks, lv.r, lv.nb)
    );
}

#[test]
fn test_bounds() {
    // Format check: ks >= 1.
    let degenerate = Leveling::derive(1, 2032, 2).expect("derive");
    assert_eq!((degenerate.s, degenerate.ks), (1, 0));
    assert_eq!(degenerate.validate_format(), Err(LayoutDefect::KsZero));

    // Format check: ceil(s / nb) <= 56403.
    let too_many = Leveling::derive((RFC_KMAX + 1) * 2032, 2032, 1).expect("derive");
    assert_eq!(too_many.ks, RFC_KMAX + 1);
    assert_eq!(too_many.validate_format(), Err(LayoutDefect::KmaxExceeded));

    // Encoding side: k_j * t <= block memory budget. Check every block against
    // the default 16 MiB budget.
    let f = 200_000_000u64;
    let k_max = k_max_from_mem(DEFAULT_ENCODE_MAX_MEM, P4096).expect("default budget");
    let nb = derive_nb(f.div_ceil(4080), k_max).expect("NB");
    let lv = Leveling::derive(f, 4080, nb).expect("layout");
    for j in 0..lv.nb {
        assert!(
            lv.block_bytes(j).expect("representable") <= DEFAULT_ENCODE_MAX_MEM,
            "j={j}"
        );
    }
    // Decoding side: the local block budget takes no part in format
    // validation, so a valid stream is not rejected because of a small local
    // budget.
    assert_eq!(
        k_max_from_mem(1000, 2048),
        None,
        "local budget < T is an encode-side issue only"
    );
    assert_eq!(lv.validate_format(), Ok(()));
}

#[test]
fn test_zero_pad() {
    let data: Vec<u8> = (0..4_081u32).map(|i| (i % 251) as u8).collect();
    let blocks = split_blocks(&data, T4080, 1).expect("split blocks");
    assert_eq!(blocks.len(), 1);
    assert_eq!(
        blocks[0].len() % T4080,
        0,
        "block byte count must be a multiple of T"
    );
    assert_eq!(blocks[0].len(), 2 * T4080);
    assert!(
        blocks[0][4081..].iter().all(|&b| b == 0),
        "trailing zero padding"
    );
    assert_eq!(rejoin(&blocks, 4081), data, "rejoin truncates back to F");

    // Multiple blocks: F = 2032 * 3 + 5 with nb=2 gives s=4, ks=2 and r=0.
    let data: Vec<u8> = (0..2032 * 3 + 5u32).map(|i| (i % 97) as u8).collect();
    let lv = Leveling::derive(data.len() as u64, 2032, 2).expect("layout");
    assert_eq!((lv.s, lv.ks, lv.r), (4, 2, 0));
    let blocks = split_blocks(&data, 2032, 2).expect("split blocks");
    assert_eq!(blocks.len(), 2);
    for (j, block) in blocks.iter().enumerate() {
        assert_eq!(block.len() as u64, lv.block_bytes(j as u32).expect(""));
        assert_eq!(block.len() % 2032, 0);
    }
    assert!(blocks[1][2037..].iter().all(|&b| b == 0));
    assert_eq!(rejoin(&blocks, data.len() as u64), data);
    assert_eq!(
        split_blocks(&[], 2032, 2),
        Err(LayoutDefect::ZeroInput),
        "F=0 is rejected"
    );
}

#[test]
fn test_nb_formula() {
    // nb = max(1, ceil(s / k_max)); values above 255 are allowed.
    assert_eq!(derive_nb(1025, 64), Ok(17));
    assert_eq!(derive_nb(1024, 64), Ok(16));
    assert_eq!(derive_nb(1, 64), Ok(1));
    assert_eq!(derive_nb(0, 64), Ok(1), "max(1, ...) (S>=1 when F>=1)");
    assert_eq!(derive_nb(300, 1), Ok(300), "NB > 255");
    assert_eq!(derive_nb(1, 0), Err(LayoutDefect::KmaxZero));
    assert_eq!(
        derive_nb(1 << 24, 1),
        Err(LayoutDefect::NbTooLarge),
        "NB <= 2^24-1"
    );

    // k_max is derived from the memory budget; the default encode table is
    // covered by the params unit tests.
    assert_eq!(
        k_max_from_mem(DEFAULT_ENCODE_MAX_MEM, P4096),
        Some(K_MAX_ENCODE_4096)
    );
    assert_eq!(k_max_from_mem(DEFAULT_ENCODE_MAX_MEM, 65536), Some(256));
    // 64 MiB reference budget: p=4096 gives 16,448.
    assert_eq!(k_max_from_mem(REF_64MIB, P4096), Some(K_MAX_4096));
    assert_eq!(k_max_from_mem(REF_64MIB, 65536), Some(1024));
    assert_eq!(k_max_from_mem(4080, P4096), Some(1));
    assert_eq!(k_max_from_mem(4079, P4096), None);
    assert_eq!(k_max_from_mem(u64::MAX, 2048), Some(RFC_KMAX));
}

#[test]
fn test_packet_counts() {
    // Source 1: --size, rounded down to whole packets.
    assert_eq!(c_total_from_size(4095, P4096), Some(0));
    assert_eq!(c_total_from_size(4096, P4096), Some(1));
    assert_eq!(c_total_from_size(8192, P4096), Some(2));
    assert_eq!(c_total_from_size(8191, P4096), Some(1));
    assert_eq!(c_total_from_size(u64::MAX, P4096), Some(u64::MAX / 4096));
    assert_eq!(
        c_total_from_size(4096, 0),
        None,
        "P=0 division-by-zero guard (QA legacy)"
    );

    // Source 2: --redundancy, using exact rational arithmetic and rounding up
    // (1.3 = 13/10).
    let f = 1024 * 1024;
    assert_eq!(c_total_from_redundancy(f, 13, 10, P4096), Some(333));
    assert_eq!(c_total_from_redundancy(f, 1, 1, P4096), Some(256));
    assert_eq!(c_total_from_redundancy(20480, 13, 10, P4096), Some(7));
    assert_eq!(
        c_total_from_redundancy(f, 0, 10, P4096),
        None,
        "0% is illegal"
    );
    assert_eq!(c_total_from_redundancy(f, 13, 0, P4096), None);
    assert_eq!(
        c_total_from_redundancy(u64::MAX, 4097, 1, 2048),
        None,
        "integer overflow must be rejected"
    );

    // c_meta = ceil, d = c - c_meta; c_total < 2 is the condition that leads
    // to exit code 1.
    let (c, m) = (333u64, M256);
    assert_eq!(c_meta(c, m), Some(2));
    assert_eq!(data_packets(c, m), Some(331));
    assert!(publishable(333, m));
    assert!(!publishable(1, m));
    assert!(!publishable(0, m));
    assert_eq!(data_packets(1, m), Some(0), "C_total=1 -> D=0");

    // Boundary example: --size 1MiB for a 1MiB input gives c=256 and d=255,
    // which is insufficient and leads to exit code 2.
    assert_eq!(c_total_from_size(1024 * 1024, P4096), Some(256));
    assert_eq!(data_packets(256, m), Some(255));
}

#[test]
fn test_result_classes() {
    // One example for each of the five outcome classes, with the full
    // priority order.
    let base = DecodeSignals {
        baseline_oti: true,
        layout_malformed: false,
        insufficient: false,
        verify: Verify::Verified(true),
    };
    let cases = [
        (base, DecodeOutcome::Ok, 0u8),
        (
            DecodeSignals {
                baseline_oti: false,
                layout_malformed: true,
                insufficient: true,
                ..base
            },
            DecodeOutcome::NoOti,
            3,
        ),
        (
            DecodeSignals {
                layout_malformed: true,
                insufficient: true,
                verify: Verify::Verified(false),
                ..base
            },
            DecodeOutcome::Malformed,
            1,
        ),
        (
            DecodeSignals {
                insufficient: true,
                verify: Verify::Verified(false),
                ..base
            },
            DecodeOutcome::Insufficient,
            2,
        ),
        (
            DecodeSignals {
                verify: Verify::Verified(false),
                ..base
            },
            DecodeOutcome::HashMismatch,
            4,
        ),
    ];
    for (signals, expected, code) in cases {
        let outcome = classify(signals);
        assert_eq!(outcome, expected);
        assert_eq!(outcome.exit_code(), code);
    }
    // --no-verify: skipping BLAKE3 yields Ok, never HashMismatch.
    assert_eq!(
        classify(DecodeSignals {
            verify: Verify::Skipped,
            ..base
        }),
        DecodeOutcome::Ok
    );
    // Precedence: NoOti before Malformed, and Malformed before Insufficient.
    assert_eq!(
        classify(DecodeSignals {
            baseline_oti: false,
            ..base
        })
        .exit_code(),
        3
    );
}

#[test]
fn test_default_ctotal() {
    // Short-stream and adversarial cases, cross-checked against independent
    // brute-force computations.
    let cases: [(u64, u64, u64, u64, u64, u64); 6] = [
        // (f, t, m, k_max, d_req, c_total_min)
        (1, 4080, M256, K_MAX_4096, 5, 6),
        (4080, 4080, M256, K_MAX_4096, 5, 6),
        (4081, 4080, M256, K_MAX_4096, 6, 7),
        (1024 * 1024, 4080, M256, K_MAX_4096, 262, 264),
        (1024 * 4080 + 1, 4080, M256, 64, 1093, 1098),
        (4182000, 4080, 256, 64, 1093, 1098),
    ];
    for (f, t, m, k_max, d_req, c_min) in cases {
        let actual = default_c_total_min(f, t, m, k_max).expect("default C_total_min");
        assert_eq!(actual.d_req, d_req, "F={f}");
        assert_eq!(actual.c_total_min, c_min, "F={f}");
        // Cross-check with an independent brute-force computation.
        assert_eq!(
            expected_d_req(f, t, k_max),
            d_req,
            "F={f} independent D_req"
        );
        assert_eq!(expected_c_total_min(d_req, m), c_min, "F={f} independent C");
        // Minimality: c_total_min - 1 does not satisfy the packet requirement.
        let prev = c_min - 1;
        assert!(
            prev - prev.div_ceil(m) < d_req,
            "F={f}: C={prev} still meets the minimum redundancy requirement, so it is not minimal"
        );
    }

    // Layout and metadata/packet counts for the default example.
    let r = default_c_total_min(1024 * 1024, 4080, M256, K_MAX_4096).expect("default C_total_min");
    assert_eq!((r.leveling.nb, r.leveling.s), (1, 258));
    assert_eq!(c_meta(r.c_total_min, M256), Some(2));
    assert_eq!(data_packets(r.c_total_min, M256), Some(r.d_req));
    let r = default_c_total_min(4177921, 4080, M256, 64).expect("default C_total_min");
    assert_eq!((r.leveling.nb, r.leveling.s), (17, 1025));
    assert_eq!(c_meta(r.c_total_min, M256), Some(5));
    assert_eq!(data_packets(r.c_total_min, M256), Some(1093));

    // With M >= 2 and F >= 1, c_total_min is at least 6.
    assert!(r.c_total_min >= 6);

    // M < 2 is rejected.
    assert_eq!(
        default_c_total_min(1, 4080, 1, 64),
        Err(LayoutDefect::MetaEveryTooSmall)
    );
    assert_eq!(MIN_META_EVERY, 2);
    assert_eq!(DEFAULT_META_EVERY, 256);

    // Redundancy report: for s=1025, d_req=1093 is exactly sufficient.
    let report = redundancy_report(&r.leveling, 1093);
    assert_eq!(report.min_slack, 0);
    assert_eq!(report.affected_blocks, 0);
    assert_eq!(a_j(1093, 17, 0), 65);
    assert_eq!(a_j(1093, 17, 5), 64);
    assert_eq!(needed_j(61), 65);
    assert_eq!(needed_j(60), 64);
    // One symbol fewer makes the affected blocks show negative slack.
    let report = redundancy_report(&r.leveling, 1092);
    assert!(report.min_slack < 0);
    assert!(report.affected_blocks > 0);
}
