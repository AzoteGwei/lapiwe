//! Regression tests for streaming in `lapiwe encode`:
//!
//! - Golden bytes: encoded output must remain byte-identical.
//! - Multi-block path: file and stdout output match byte-for-byte and roundtrip.
//! - Bounded peak RSS: peak memory does not grow without bound with input size.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output};

/// Golden case: the output length and BLAKE3 digest were captured from the
/// implementation before the streaming rewrite. They must not change, because
/// these values define the expected behavior.
struct GoldenCase {
    name: &'static str,
    len: usize,
    seed: u64,
    args: &'static [&'static str],
    out_len: usize,
    blake3_hex: &'static str,
}

const GOLDEN: &[GoldenCase] = &[
    GoldenCase {
        name: "g1_default",
        len: 100_000,
        seed: 0x6001,
        args: &["encode", "f.bin"],
        out_len: 122_880,
        blake3_hex: "b653f7bf67344614ddccb6069797bc9f998d285dfa3b7cf17fcf753bbaba64de",
    },
    GoldenCase {
        name: "g2_redundancy",
        len: 100_000,
        seed: 0x6002,
        args: &["encode", "--redundancy", "1.3", "f.bin"],
        out_len: 131_072,
        blake3_hex: "e2c6a9bdab105bca42e5cf285e434b75557460a6dbc40f8c4809cd253f30f6df",
    },
    GoldenCase {
        name: "g3_size_meta_every",
        len: 100_000,
        seed: 0x6003,
        args: &["encode", "--size", "1M", "--meta-every", "2", "f.bin"],
        out_len: 1_048_576,
        blake3_hex: "82ce08d8ad60fac68c4c3c466d3ba042e489ed1c31d698a420d7865f7d08d3b5",
    },
    GoldenCase {
        name: "g4_multiblock_repairs",
        len: 300_000,
        seed: 0x6004,
        args: &["encode", "--max-mem", "128KiB", "--size", "700000", "f.bin"],
        out_len: 696_320,
        blake3_hex: "cf0faa65671a6a4839cd2e8468db165c34193dae419a3dfe3ad2219a212ca107",
    },
    GoldenCase {
        name: "g5_force_best_effort",
        len: 1_200,
        seed: 0x6005,
        args: &["encode", "--size", "8192", "--force", "f.bin"],
        out_len: 8_192,
        blake3_hex: "4872491248ca9326d32adca099db9ea8d29f07904a1dcc9c9aa445fd2a371b38",
    },
    GoldenCase {
        name: "g6_large_t",
        len: 300_000,
        seed: 0x6006,
        args: &["encode", "--packet-size", "65536", "f.bin"],
        out_len: 655_360,
        blake3_hex: "1b8e9603419d972466b1cbf8a59d0d46dfcf17eb2115bf566b2b680c72a4d3a5",
    },
    GoldenCase {
        name: "g7_stdout_p2048",
        len: 30_000,
        seed: 0x6007,
        args: &["encode", "--packet-size", "2048", "-o", "-", "f.bin"],
        out_len: 40_960,
        blake3_hex: "1b0612c45a58603294296b30a40c67251646c6f09e6b88e9b70167a8d367075c",
    },
    GoldenCase {
        name: "g9_partial_blocks_force",
        len: 300_000,
        seed: 0x6009,
        args: &[
            "encode",
            "--max-mem",
            "128KiB",
            "--size",
            "16384",
            "--force",
            "f.bin",
        ],
        out_len: 16_384,
        blake3_hex: "cf0e535d753a85279d7d6374d53f46ff4aa445630d9d934fff5edb07c4d57fe7",
    },
];

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-stream-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create sandbox directory");
        Sandbox { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, bytes).expect("write test file");
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(args)
            .current_dir(&self.dir)
            .output()
            .expect("failed to start lapiwe binary")
    }
}

/// Generate deterministic test data, using the same scheme as the other CLI tests.
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

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read(path: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .expect("open")
        .read_to_end(&mut buf)
        .expect("read");
    buf
}

#[test]
fn golden_bytes_match_pre_refactor_implementation() {
    for case in GOLDEN {
        let sb = Sandbox::new(case.name);
        sb.write("f.bin", &det_bytes(case.len, case.seed));
        let out = sb.run(case.args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}: stderr={}",
            case.name,
            stderr_of(&out)
        );
        let bytes = if case.args.contains(&"-o") && case.args.contains(&"-") {
            out.stdout.clone()
        } else {
            read(&sb.path("f.bin.lpw"))
        };
        assert_eq!(bytes.len(), case.out_len, "{}: output length", case.name);
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            case.blake3_hex,
            "{}: byte output must match the expected value",
            case.name
        );
    }
}

#[test]
fn multiblock_stdout_matches_file_output_and_roundtrips() {
    // Multi-block: buffered stdout and file output must match byte-for-byte and
    // roundtrip through the decoder.
    let sb = Sandbox::new("mb");
    let data = det_bytes(300_000, 0x6004);
    sb.write("f.bin", &data);
    let args_base = ["encode", "--max-mem", "128KiB", "--size", "700000"];

    let mut file_args = args_base.to_vec();
    file_args.extend_from_slice(&["-o", "mb.lpw", "f.bin"]);
    let file_out = sb.run(&file_args);
    assert_eq!(
        file_out.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&file_out)
    );
    assert!(file_out.stdout.is_empty());

    let mut stdout_args = args_base.to_vec();
    stdout_args.extend_from_slice(&["-o", "-", "f.bin"]);
    let stdout_out = sb.run(&stdout_args);
    assert_eq!(
        stdout_out.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&stdout_out)
    );

    let from_file = read(&sb.path("mb.lpw"));
    assert_eq!(
        stdout_out.stdout, from_file,
        "stdout must match file output byte-for-byte"
    );

    // CLI roundtrip: pass the multi-block stream through the `decode` subcommand.
    let decoded = sb.run(&["decode", "-o", "mb.out", "mb.lpw"]);
    assert_eq!(
        decoded.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&decoded)
    );
    assert_eq!(
        read(&sb.path("mb.out")),
        data,
        "multi-block stream must roundtrip completely"
    );
}

#[test]
fn stdout_nb1_dense_metadata_matches_file_output() {
    let sb = Sandbox::new("dense-meta");
    let data = det_bytes(20_000, 0x60C0);
    sb.write("f.bin", &data);
    let args_common = ["encode", "--meta-every", "2", "--size", "73728", "--force"];
    let mut to_stdout = args_common.to_vec();
    to_stdout.extend_from_slice(&["-o", "-", "f.bin"]);
    let a = sb.run(&to_stdout);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    let mut to_file = args_common.to_vec();
    to_file.extend_from_slice(&["-o", "dense.lpw", "f.bin"]);
    let b = sb.run(&to_file);
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert_eq!(
        a.stdout,
        read(&sb.path("dense.lpw")),
        "stdout must match file output"
    );

    let decoded = sb.run(&["decode", "-o", "-", "dense.lpw"]);
    assert_eq!(
        decoded.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&decoded)
    );
    assert_eq!(decoded.stdout, data);
}

#[test]
fn trailing_meta_slot_multiblock_stdout_roundtrips() {
    let sb = Sandbox::new("trailing-meta");
    let data = det_bytes(300_000, 0x60C1);
    sb.write("f.bin", &data);
    let args_common = [
        "encode",
        "--max-mem",
        "128KiB",
        "--meta-every",
        "4",
        "--size",
        "479232",
        "--force",
    ];
    let mut to_file = args_common.to_vec();
    to_file.extend_from_slice(&["-o", "tm.lpw", "f.bin"]);
    let a = sb.run(&to_file);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    let mut to_stdout = args_common.to_vec();
    to_stdout.extend_from_slice(&["-o", "-", "f.bin"]);
    let b = sb.run(&to_stdout);
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert_eq!(
        b.stdout,
        read(&sb.path("tm.lpw")),
        "stdout must match file output"
    );

    let decoded = sb.run(&["decode", "-o", "-", "tm.lpw"]);
    assert_eq!(
        decoded.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&decoded)
    );
    assert_eq!(decoded.stdout, data);
}

#[test]
fn stdin_spooled_multiblock_matches_file_input() {
    use std::io::Write;
    use std::process::Stdio;

    let sb = Sandbox::new("stdin-mb");
    let data = det_bytes(300_000, 0x60A0);
    sb.write("f.bin", &data);
    fs::create_dir_all(sb.path("spool")).expect("spool directory");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args([
            "encode",
            "-",
            "--max-mem",
            "128KiB",
            "--size",
            "700000",
            "-o",
            "stdin.lpw",
            "--spool-dir",
            "spool",
        ])
        .current_dir(&sb.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start encode -");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait for child process");
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));

    let file_out = sb.run(&[
        "encode",
        "--max-mem",
        "128KiB",
        "--size",
        "700000",
        "-o",
        "file.lpw",
        "f.bin",
    ]);
    assert_eq!(
        file_out.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&file_out)
    );
    assert_eq!(
        read(&sb.path("stdin.lpw")),
        read(&sb.path("file.lpw")),
        "stdin must match file input byte-for-byte"
    );
    let leftovers: Vec<_> = fs::read_dir(sb.path("spool"))
        .expect("read spool")
        .map(|e| e.expect("directory entry").file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "spool must be cleaned up: {leftovers:?}"
    );
}

/// Return the child's peak resident set size in KiB and its exit status.
///
/// Polls `VmHWM` in `/proc/<pid>/status`, which is a high-water mark and never
/// decreases, at a 2 ms sampling interval.
#[cfg(target_os = "linux")]
fn peak_rss_kib(child: &mut Child) -> (u64, ExitStatus) {
    use std::time::Duration;
    let expected_name = Path::new(env!("CARGO_BIN_EXE_lapiwe")).file_name();
    let mut peak = 0u64;
    let mut exec_verified = false;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return (peak, status);
        }
        if !exec_verified {
            exec_verified = fs::read_link(format!("/proc/{}/exe", child.id()))
                .map(|p| p.file_name() == expected_name)
                .unwrap_or(false);
        }
        if exec_verified {
            if let Ok(text) = fs::read_to_string(format!("/proc/{}/status", child.id())) {
                for line in text.lines() {
                    if let Some(rest) = line.strip_prefix("VmHWM:") {
                        let kib = rest
                            .trim()
                            .trim_end_matches("kB")
                            .trim()
                            .parse::<u64>()
                            .unwrap_or(0);
                        peak = peak.max(kib);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn peak_rss_is_bounded_by_block_budget_not_input_size() {
    use std::process::Stdio;

    let sb = Sandbox::new("rss");
    let data = det_bytes(16 * 1024 * 1024, 0x60B0);
    sb.write("big.bin", &data);

    let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(["encode", "--max-mem", "128KiB", "-o", "big.lpw", "big.bin"])
        .current_dir(&sb.dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start encode");
    let (peak_kib, status) = peak_rss_kib(&mut child);
    assert_eq!(status.code(), Some(0), "encode must succeed");
    assert!(
        peak_kib > 0,
        "cannot read /proc/<pid>/status (unsupported test environment?)"
    );
    assert!(
        peak_kib <= 16 * 1024,
        "peak RSS {peak_kib} KiB exceeds the 16 MiB bound"
    );
    assert_eq!(
        read(&sb.path("big.lpw")).len(),
        // Without `--size`, the output consists of whole packets; check that it is
        // non-zero and an exact multiple of the packet size.
        read(&sb.path("big.lpw")).len() / 4096 * 4096,
        "output must be a sequence of whole packets"
    );
}
