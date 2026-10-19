//! Integration tests for the `lapiwe encode` command.
//!
//! These tests cover the encoding side of usage and help, stdin input, default
//! naming, numeric options, memory budgets, summaries, `--force`, input safety,
//! two-pass encoding, output-channel separation, SIGPIPE handling, determinism,
//! `--jobs` scaling, large packet sizes, degenerate parameters, non-UTF-8 paths,
//! argument syntax, and warning text.
//!
//! Signal cleanup is covered in `tests/cli_signals.rs`; streaming regressions
//! (golden bytes and peak RSS) in `tests/cli_encode_stream.rs`; decoding and
//! inspection in `tests/cli_decode.rs`.
//!
//! Encoded output is verified by decoding it through the library path (scan plus
//! engine) instead of the `decode` subcommand, so the two layers remain
//! independent.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use lapiwe::container::decode::{DecodeConfig, DecodeEngine};
use lapiwe::container::outcome::DecodeOutcome;
use lapiwe::container::params::SYNC;
use lapiwe::container::scan::scan_into;

const P: usize = 4096;

/// Per-test sandbox directory under `CARGO_TARGET_TMPDIR`, so parallel tests do
/// not collide.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{name}"));
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
        run_os(
            &self.dir,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
        )
    }

    fn run_os(&self, args: &[OsString]) -> Output {
        run_os(&self.dir, args)
    }
}

fn run_os(dir: &Path, args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to spawn lapiwe binary")
}

/// Run the binary with the given data on stdin.
fn run_with_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn lapiwe binary");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait for child process")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Assert the "single-line error" contract: exactly one line (including the
/// trailing newline), with no panic or backtrace text.
fn assert_single_line_error(out: &Output, expect_code: i32) {
    assert_eq!(
        out.status.code(),
        Some(expect_code),
        "stderr={}",
        stderr_of(out)
    );
    let stderr = stderr_of(out);
    assert_eq!(
        stderr.matches('\n').count(),
        1,
        "error message must be a single line: {stderr:?}"
    );
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
    assert!(
        !stderr.contains("backtrace"),
        "must not print a backtrace: {stderr}"
    );
}

/// Generate deterministic test data with xorshift64*.
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

/// Decode a file through the library path: scan, engine, then classification.
fn decode_file(path: &Path) -> lapiwe::container::decode::DecodeSummary {
    let file = File::open(path).expect("open .lpw");
    let mut engine = DecodeEngine::new();
    scan_into(file, &mut engine).expect("scan");
    engine.finish(&DecodeConfig { no_verify: false })
}

fn read(path: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    File::open(path)
        .expect("open")
        .read_to_end(&mut buf)
        .expect("read");
    buf
}

// ---------------------------------------------------------------------------
// Subcommands, help, usage, and default naming
// ---------------------------------------------------------------------------

#[test]
fn test_usage_and_single_line_errors() {
    let sb = Sandbox::new("c03");
    // Missing operand: one-line error with a hint.
    let out = sb.run(&["encode"]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("<IN>"),
        "must mention the missing <IN>"
    );
    // Extra operands: one-line error.
    let out = sb.run(&["encode", "a", "b"]);
    assert_single_line_error(&out, 1);
    // Usage line.
    let out = sb.run(&["encode", "-h"]);
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8(out.stdout).expect("help output must be UTF-8");
    assert!(help.contains("lapiwe encode [OPTIONS] <IN>"), "{help}");
    assert!(
        help.contains("--size"),
        "help must document the --size semantics"
    );
    assert!(
        help.contains("16MiB"),
        "help must state the default 16 MiB value"
    );
}

#[test]
fn test_stdin() {
    // A `-` operand means stdin: `encode - -o -` matches file input byte for
    // byte, and `decode -` restores the original data.
    let sb = Sandbox::new("c04");
    let data = det_bytes(9_000, 0xC04);
    sb.write("f.bin", &data);

    let file_out = sb.run(&["encode", "-o", "-", "f.bin"]);
    assert_eq!(
        file_out.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&file_out)
    );
    let pipe_out = run_with_stdin(&sb.dir, &["encode", "-", "-o", "-"], &data);
    assert_eq!(
        pipe_out.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&pipe_out)
    );
    assert_eq!(
        pipe_out.stdout, file_out.stdout,
        "stdin and file input must match"
    );

    let decoded = run_with_stdin(&sb.dir, &["decode", "-", "-o", "-"], &pipe_out.stdout);
    assert_eq!(
        decoded.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&decoded)
    );
    assert_eq!(decoded.stdout, data);
}

#[test]
fn test_spool_dir() {
    // Staging files for stdin encoding are created under `--spool-dir` and
    // removed once encoding completes.
    let sb = Sandbox::new("c22");
    let data = det_bytes(40_000, 0xC22);
    fs::create_dir_all(sb.path("spool")).expect("spool directory");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(["encode", "-", "-o", "out.lpw", "--spool-dir", "spool"])
        .current_dir(&sb.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn encode -");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    stdin
        .write_all(&data[..1_000])
        .expect("write the first stdin chunk");
    // Keep the pipe open: the staging file must already exist in the configured
    // directory.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let nonempty = fs::read_dir(sb.path("spool"))
            .expect("read spool")
            .next()
            .is_some();
        if nonempty {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the spool staging file"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    stdin
        .write_all(&data[1_000..])
        .expect("write the remaining stdin bytes");
    drop(stdin);
    let out = child.wait_with_output().expect("wait for child process");
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let leftovers: Vec<_> = fs::read_dir(sb.path("spool"))
        .expect("read spool")
        .map(|e| e.expect("directory entry").file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files must be cleaned up: {leftovers:?}"
    );

    let summary = decode_file(&sb.path("out.lpw"));
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));
}

#[test]
fn test_output_default_and_stdout() {
    let sb = Sandbox::new("c05");
    let data = det_bytes(1200, 0xC05);
    sb.write("f.bin", &data);

    // Default output name is <IN>.lpw.
    let out = sb.run(&["encode", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when writing to a file"
    );
    let produced = sb.path("f.bin.lpw");
    let bytes = read(&produced);
    assert_eq!(bytes.len() % P, 0, "output length must be a multiple of P");
    assert_eq!(&bytes[..4], &SYNC);

    // Round-trip through the library decoder.
    let summary = decode_file(&produced);
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));

    // `-o -` writes to stdout.
    let out = sb.run(&["encode", "-o", "-", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(
        out.stdout, bytes,
        "stdout and file output must match byte for byte"
    );
}

// ---------------------------------------------------------------------------
// Numeric options
// ---------------------------------------------------------------------------

#[test]
fn test_size_parse_and_floor() {
    let sb = Sandbox::new("c06");
    sb.write("f.bin", &det_bytes(1200, 0xC06));

    // 1MiB == 1M == 1,048,576: all three spellings produce identical bytes.
    let a = sb.run(&["encode", "--size", "1MiB", "-o", "a.lpw", "f.bin"]);
    let b = sb.run(&["encode", "--size", "1M", "-o", "b.lpw", "f.bin"]);
    let c = sb.run(&["encode", "--size", "1048576", "-o", "c.lpw", "f.bin"]);
    for out in [&a, &b, &c] {
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(out));
    }
    let (ba, bb, bc) = (
        read(&sb.path("a.lpw")),
        read(&sb.path("b.lpw")),
        read(&sb.path("c.lpw")),
    );
    assert_eq!(ba, bb);
    assert_eq!(ba, bc);
    assert_eq!(ba.len(), 256 * P, "floor(1MiB/4096)=256");

    // 1MB = 1,000,000 (decimal) -> floor(1e6/4096) = 244.
    let out = sb.run(&["encode", "--size", "1MB", "-o", "d.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("d.lpw")).len(), 244 * P);

    // Floor semantics: --size 25000 yields floor(25000/4096) = 6 packets, up to
    // P-1 bytes below the target.
    let out = sb.run(&["encode", "--size", "25000", "-o", "e.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("e.lpw")).len(), 6 * P, "25000 floors to 6P");
    assert_eq!(
        25000 - 6 * P,
        424,
        "actual result is 0..P-1 bytes below the target (424 here)"
    );

    // Overflow and invalid values exit with status 1.
    for bad in ["18446744073709551616", "17179869184T", "1.5G", "abc"] {
        let out = sb.run(&["encode", "--size", bad, "f.bin"]);
        assert_single_line_error(&out, 1);
    }
    // --size and --max-mem share one parser: 64M, 64MiB, and the byte count are
    // all accepted.
    for good in ["64M", "64MiB", "67108864"] {
        let out = sb.run(&["encode", "--max-mem", good, "-o", "g.lpw", "f.bin"]);
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    }
}

#[test]
fn test_redundancy_parse() {
    let sb = Sandbox::new("c07");
    // 100,000 bytes with R=1.3: C_total=32 and D=31 >= needed=29, so the
    // redundancy requirement holds.
    sb.write("f.bin", &det_bytes(100_000, 0xC07));

    // 1.3 and 30% are the same exact rational, so the output is identical.
    let a = sb.run(&["encode", "--redundancy", "1.3", "-o", "a.lpw", "f.bin"]);
    let b = sb.run(&["encode", "--redundancy", "30%", "-o", "b.lpw", "f.bin"]);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert_eq!(read(&sb.path("a.lpw")), read(&sb.path("b.lpw")));

    for bad in ["0.2", "0%", "-1", "NaN", "inf", "1e2"] {
        let out = sb.run(&["encode", "--redundancy", bad, "f.bin"]);
        assert_single_line_error(&out, 1);
    }
    // R=1 with C_total=1 is a degenerate parameter set: exit 1.
    sb.write("tiny.bin", &det_bytes(1000, 0xC07A));
    let out = sb.run(&["encode", "--redundancy", "1", "tiny.bin"]);
    assert_single_line_error(&out, 1);
    // R=1 with C_total>=2 does not meet the default redundancy requirement:
    // exit 2 (R=1 can yield either 1 or 2 depending on the degenerate case).
    let out = sb.run(&["encode", "--redundancy", "1", "f.bin"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
}

#[test]
fn test_size_redundancy() {
    let sb = Sandbox::new("c08");
    sb.write("f.bin", &det_bytes(100_000, 0xC08));
    let out = sb.run(&["encode", "--size", "1M", "--redundancy", "1.3", "f.bin"]);
    assert_single_line_error(&out, 1);
    assert!(stderr_of(&out).contains("mutually exclusive"));
    // Supplying only one, or neither, succeeds.
    for args in [
        vec!["encode", "--size", "1M", "f.bin"],
        vec!["encode", "--redundancy", "1.3", "f.bin"],
        vec!["encode", "f.bin"],
    ] {
        let out = sb.run(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} stderr={}",
            stderr_of(&out)
        );
    }
}

#[test]
fn test_packet_size() {
    let sb = Sandbox::new("c09");
    sb.write("f.bin", &det_bytes(3000, 0xC09));
    for p in ["2048", "4096", "8192", "16384", "32768", "65536"] {
        let out = sb.run(&["encode", "--packet-size", p, "-o", "x.lpw", "f.bin"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "P={p} stderr={}",
            stderr_of(&out)
        );
    }
    let out = sb.run(&["encode", "--packet-size", "3000", "f.bin"]);
    assert_single_line_error(&out, 1);
    let stderr = stderr_of(&out);
    for p in ["2048", "8192", "16384", "32768", "65536"] {
        assert!(
            stderr.contains(p),
            "error must list every valid value (missing {p}): {stderr}"
        );
    }
}

#[test]
fn test_meta_every() {
    let sb = Sandbox::new("c10");
    sb.write("f.bin", &det_bytes(2000, 0xC10));
    for bad in ["0", "1"] {
        let out = sb.run(&["encode", "--meta-every", bad, "f.bin"]);
        assert_single_line_error(&out, 1);
    }
    let out = sb.run(&["encode", "--meta-every", "2", "-o", "m2.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
}

#[test]
fn test_block_symbols() {
    let sb = Sandbox::new("c11");
    sb.write("f.bin", &det_bytes(3000, 0xC11));
    for bad in ["0", "56404"] {
        let out = sb.run(&["encode", "--block-symbols", bad, "f.bin"]);
        assert_single_line_error(&out, 1);
    }
    let out = sb.run(&["encode", "--block-symbols", "1", "-o", "k1.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
}

// ---------------------------------------------------------------------------
// Budgets, summaries, --force, and input safety
// ---------------------------------------------------------------------------

#[test]
fn test_max_mem() {
    let sb = Sandbox::new("c12");
    sb.write("f.bin", &det_bytes(3000, 0xC12));
    // Below T: exit 1 and suggest T.
    let out = sb.run(&["encode", "--max-mem", "4079", "f.bin"]);
    assert_single_line_error(&out, 1);
    assert!(stderr_of(&out).contains("4080"), "the suggestion must be T");
    // An explicit --block-symbols over budget exits 1 and suggests
    // floor(max_mem/T).
    let out = sb.run(&["encode", "--block-symbols", "20000", "f.bin"]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("4112"),
        "must suggest floor(max_mem/T) (default 16 MiB / 4080 = 4112): {}",
        stderr_of(&out)
    );
    // Exactly T is valid (K_max=1).
    let out = sb.run(&["encode", "--max-mem", "4080", "-o", "ok.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
}

/// Extract the decimal field between `prefix` and `end` from the stderr
/// summary.
fn field_u64(hay: &str, prefix: &str, end: char) -> u64 {
    let rest = hay
        .split(prefix)
        .nth(1)
        .unwrap_or_else(|| panic!("stderr is missing field `{prefix}`: {hay}"));
    let num: String = rest.chars().take_while(|c| *c != end).collect();
    num.trim().parse().unwrap_or_else(|_| {
        panic!("field `{prefix}` is not a decimal number: {num:?} (stderr={hay})")
    })
}

#[test]
fn test_jobs_hint() {
    let sb = Sandbox::new("c13");
    sb.write("f.bin", &det_bytes(1200, 0xC13));
    let out = sb.run(&["encode", "--jobs", "2", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    // The reported total-memory bound is (3·min(jobs,NB)+2)·max_j(K_j·T). It
    // constrains the per-block source-data budget, not total process residency.
    assert!(
        err.contains("memory upper bound") && err.contains("(3*min(jobs,NB)+2)*max_j(K_j*T)"),
        "stderr must report the total memory upper bound: {err}"
    );
    assert!(
        err.contains("max_mem=") && err.contains("bounds one block's source budget"),
        "the note must explain what max_mem bounds: {err}"
    );
    // The value must equal (3·min(jobs,NB)+2)·max_j(K_j·T), with NB and K_j·T
    // parsed from the summary.
    let nb = field_u64(&err, "NB=", ' ');
    let max_block = field_u64(&err, "bytes_per_block(K_j*T)<=", ' ');
    let expected = (3 * 2u64.min(nb) + 2) * max_block;
    assert!(
        err.contains(&format!("= {expected} bytes")),
        "upper bound must equal (3*min(jobs,NB)+2)*max_j(K_j*T) = {expected}: {err}"
    );

    // Multi-block shape: when NB > jobs the bound clamps to jobs, so
    // min(jobs,NB) applies.
    sb.write("big.bin", &det_bytes(20_000, 0xC13B));
    let out = sb.run(&["encode", "--jobs", "3", "--block-symbols", "1", "big.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    let nb = field_u64(&err, "NB=", ' ');
    assert!(nb >= 3, "shape requires NB >= jobs (actual NB={nb})");
    let max_block = field_u64(&err, "bytes_per_block(K_j*T)<=", ' ');
    let expected = (3 * 3u64.min(nb) + 2) * max_block;
    assert!(
        err.contains(&format!("= {expected} bytes")),
        "when NB>jobs the bound must use min(jobs,NB)=3: {expected}; stderr={err}"
    );

    // An extreme --jobs value yields a one-line error listing the valid range
    // and must not panic.
    let out = sb.run(&["encode", "--jobs", "1025", "f.bin"]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("1..=1024"),
        "error must state the valid range: {}",
        stderr_of(&out)
    );
    // `--jobs 0` likewise reports the full valid range.
    let out = sb.run(&["encode", "--jobs", "0", "f.bin"]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("1..=1024"),
        "`--jobs 0` error must state the full valid range: {}",
        stderr_of(&out)
    );
}

#[test]
fn test_force_zero_output_and_publish() {
    let sb = Sandbox::new("c14");
    sb.write("f.bin", &det_bytes(1200, 0xC14));

    // By default, insufficient redundancy exits 2, writes zero bytes to stdout,
    // and neither creates nor publishes an output file.
    let out = sb.run(&["encode", "--size", "8192", "-o", "no.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when redundancy is insufficient"
    );
    assert!(
        !sb.path("no.lpw").exists(),
        "exit 2 must not publish output"
    );
    // Stdout output is likewise empty.
    let out = sb.run(&["encode", "--size", "8192", "-o", "-", "f.bin"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when redundancy is insufficient"
    );

    // With --force: exit 0, a warning, bit 1 set, and the file published.
    let out = sb.run(&[
        "encode", "--size", "8192", "--force", "-o", "yes.lpw", "f.bin",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let forced = read(&sb.path("yes.lpw"));
    assert_eq!(forced.len(), 2 * P);
    assert_eq!(
        forced[4] & 0x02,
        0x02,
        "every packet's best_effort bit (bit1) must be set"
    );

    // --force does not exempt C_total < 2.
    let out = sb.run(&["encode", "--size", "4096", "--force", "f.bin"]);
    assert_single_line_error(&out, 1);

    // With --force but sufficient redundancy: the normal path runs, bit 1 stays
    // clear, and no insufficient-redundancy warning is printed.
    let out = sb.run(&["encode", "--force", "-o", "ok.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("ok.lpw"))[4] & 0x02, 0);
    assert!(!stderr_of(&out).contains("insufficient effective redundancy"));
}

#[test]
fn test_summary_fields() {
    let sb = Sandbox::new("c15");
    sb.write("f.bin", &det_bytes(100_000, 0xC15));
    let out = sb.run(&["encode", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let stderr = stderr_of(&out);
    for field in [
        "F=",
        "C_total=",
        "C_meta=",
        "D=",
        "NB=",
        "KS=",
        "T=",
        "eps_eff",
        "min(a_j-needed_j)",
        "source=default",
        "metadata_overhead(packet_slots)",
        "best_effort=0",
    ] {
        assert!(
            stderr.contains(field),
            "summary is missing `{field}`: {stderr}"
        );
    }
}

#[test]
fn test_input_safe() {
    let sb = Sandbox::new("c16");
    let data = det_bytes(50_000, 0xC16);
    let input = sb.write("f.bin", &data);
    let before = read(&input);
    let out = sb.run(&["encode", "f.bin", "-o", "out.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&input), before, "encoding must not modify the input");

    // -o pointing at the input itself is rejected, including a ./ normalized
    // path.
    let out = sb.run(&["encode", "f.bin", "-o", "f.bin"]);
    assert_single_line_error(&out, 1);
    let out = sb.run(&["encode", "f.bin", "-o", "./f.bin"]);
    assert_single_line_error(&out, 1);
    assert_eq!(
        read(&input),
        before,
        "input must remain unmodified when the path is rejected"
    );
}

// ---------------------------------------------------------------------------
// Two-pass encoding, output channels, SIGPIPE, and determinism
// ---------------------------------------------------------------------------

#[test]
fn test_stdin_spool_two_pass_roundtrip() {
    let sb = Sandbox::new("c30");
    let data = det_bytes(70_000, 0xC30);
    // stdin input is spooled to a temporary copy and then encoded with the
    // file two-pass path; a separate --spool-dir verifies cleanup.
    let spool = sb.path("spool");
    fs::create_dir_all(&spool).expect("spool directory");
    let out = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(["encode", "-", "-o", "stdin.lpw", "--spool-dir", "spool"])
        .current_dir(&sb.dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin pipe")
                .write_all(&data)
                .expect("write stdin");
            child.wait_with_output()
        })
        .expect("run encode -");
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let leftovers: Vec<_> = fs::read_dir(&spool)
        .expect("read spool")
        .map(|e| e.expect("directory entry").file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files must be cleaned up; leftovers: {leftovers:?}"
    );
    let produced = sb.path("stdin.lpw");
    let summary = decode_file(&produced);
    assert_eq!(summary.outcome, DecodeOutcome::Ok);
    assert_eq!(summary.data.as_deref(), Some(data.as_slice()));

    // The same data from a file must produce identical bytes, so the two-pass
    // and stdin-spool paths agree.
    sb.write("f.bin", &data);
    let out = sb.run(&["encode", "f.bin", "-o", "file.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&produced), read(&sb.path("file.lpw")));
}

#[test]
fn test_channel_purity() {
    let sb = Sandbox::new("c32");
    sb.write("f.bin", &det_bytes(1200, 0xC32));
    // stdout carries only container bytes; the summary goes to stderr, and
    // stdout must match file output byte for byte.
    let out = sb.run(&["encode", "-o", "-", "f.bin"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(&out.stdout[..4], &SYNC);
    assert_eq!(
        out.stdout.len() % P,
        0,
        "stdout must be a whole-packet sequence"
    );
    assert!(stderr_of(&out).contains("summary"));
    let file_out = sb.run(&["encode", "f.bin", "-o", "f.lpw"]);
    assert_eq!(file_out.status.code(), Some(0));
    assert!(file_out.stdout.is_empty());
    assert_eq!(
        out.stdout,
        read(&sb.path("f.lpw")),
        "stdout must match file output"
    );
}

#[test]
fn test_pipes() {
    // A `-` operand composes with zstd and tar; stdin encoding still works in a
    // pipeline after the full input has been spooled.
    // Skip when zstd or tar is unavailable, since those tools are environment
    // dependencies.
    for tool in ["zstd", "tar"] {
        let ok = Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("skipping test_pipes: {tool} is unavailable");
            return;
        }
    }
    let sb = Sandbox::new("c33");
    let data = det_bytes(60_000, 0xC33);
    sb.write("payload.bin", &data);
    let bin = env!("CARGO_BIN_EXE_lapiwe");

    // zstd | encode - -o - | decode - -o - | zstd -d | cmp exercises `-` at both
    // ends.
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail
               zstd -q -c payload.bin \
                 | "$1" encode - -o - 2>/dev/null \
                 | "$1" decode - -o - 2>/dev/null \
                 | zstd -q -dc \
                 | cmp - payload.bin"#,
            "bash",
            bin,
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("failed to spawn bash");
    assert_eq!(
        out.status.code(),
        Some(0),
        "zstd pipeline must be lossless end to end; stderr={}",
        stderr_of(&out)
    );

    // tar | zstd | encode | decode | zstd -d | tar -x covers an archive with
    // subdirectories and a larger file.
    fs::create_dir_all(sb.path("tree/sub")).expect("tree");
    fs::write(sb.path("tree/a.txt"), b"hello lapiwe\n").expect("a.txt");
    fs::write(sb.path("tree/sub/b.bin"), det_bytes(20_000, 0xC33B)).expect("b.bin");
    fs::create_dir_all(sb.path("extracted")).expect("extracted");
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail
               tar -C tree -cf - . \
                 | zstd -q -c \
                 | "$1" encode - -o - 2>/dev/null \
                 | "$1" decode - -o - 2>/dev/null \
                 | zstd -q -dc \
                 | tar -C extracted -xf -"#,
            "bash",
            bin,
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("failed to spawn bash");
    assert_eq!(
        out.status.code(),
        Some(0),
        "tar pipeline must be lossless end to end; stderr={}",
        stderr_of(&out)
    );
    assert_eq!(
        fs::read(sb.path("extracted/a.txt")).expect("a.txt"),
        b"hello lapiwe\n"
    );
    assert_eq!(
        fs::read(sb.path("extracted/sub/b.bin")).expect("b.bin"),
        det_bytes(20_000, 0xC33B)
    );
}

#[test]
fn test_sigpipe_exit_zero() {
    let sb = Sandbox::new("c34");
    // The output must exceed the 64 KiB pipe buffer so that an early reader
    // exit always triggers EPIPE.
    sb.write("f.bin", &det_bytes(200_000, 0xC34));
    let bin = env!("CARGO_BIN_EXE_lapiwe");
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail; { sleep 0.2; exec "$1" encode "$2" -o -; } | head -c 1 > /dev/null"#,
            "bash",
            bin,
            "f.bin",
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("failed to spawn bash");
    assert_eq!(
        out.status.code(),
        Some(0),
        "EPIPE must exit 0 silently; stderr={}",
        stderr_of(&out)
    );
    assert!(!stderr_of(&out).contains("panicked"));

    // With NB>1, stdout output goes through an output spool and is copied out
    // sequentially; EPIPE likewise exits 0 silently.
    sb.write("big.bin", &det_bytes(300_000, 0xC34B));
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail; { sleep 0.2; exec "$1" encode --max-mem 128KiB "$2" -o -; } | head -c 1 > /dev/null"#,
            "bash",
            bin,
            "big.bin",
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("failed to spawn bash");
    assert_eq!(
        out.status.code(),
        Some(0),
        "the multi-block path must also exit 0 silently on EPIPE; stderr={}",
        stderr_of(&out)
    );
    assert!(!stderr_of(&out).contains("panicked"));
}

#[test]
fn test_determinism() {
    let sb = Sandbox::new("c36");
    sb.write("f.bin", &det_bytes(200_000, 0xC36));
    let out = sb.run(&["encode", "f.bin", "-o", "a.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let out = sb.run(&["encode", "f.bin", "-o", "b.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(
        read(&sb.path("a.lpw")),
        read(&sb.path("b.lpw")),
        "two encodes with the same arguments must be byte-identical"
    );
}

// ---------------------------------------------------------------------------
// Degenerate parameters, default visibility, non-UTF-8 paths, syntax, warnings
// ---------------------------------------------------------------------------

#[test]
fn test_jobs_parallel_equivalence() {
    // --jobs only changes parallelism, not output: --jobs 1 and --jobs 3 must
    // produce identical bytes while NB > 1, confirming the per-block parallel
    // path is used.
    let sb = Sandbox::new("c37eq");
    let data = det_bytes(1024 * 1024, 0xC37);
    sb.write("f.bin", &data);
    let a = sb.run(&[
        "encode",
        "--jobs",
        "1",
        "--block-symbols",
        "64",
        "-o",
        "j1.lpw",
        "f.bin",
    ]);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    let b = sb.run(&[
        "encode",
        "--jobs",
        "3",
        "--block-symbols",
        "64",
        "-o",
        "j3.lpw",
        "f.bin",
    ]);
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert!(
        stderr_of(&b).contains("bytes_per_block(K_j*T)<="),
        "the summary should be visible: {}",
        stderr_of(&b)
    );
    let out1 = read(&sb.path("j1.lpw"));
    let out3 = read(&sb.path("j3.lpw"));
    assert_eq!(
        out1, out3,
        "encoding output must be byte-identical across --jobs values"
    );
    let decoded = decode_file(&sb.path("j3.lpw"));
    assert_eq!(
        decoded.outcome,
        DecodeOutcome::Ok,
        "parallel output must be decodable: {:?}",
        decoded.outcome
    );
    assert_eq!(decoded.data.as_deref(), Some(data.as_slice()));
}

/// `--packet-size 32768/65536` works: an encode/decode round-trip is byte for
/// byte identical.
///
/// Throughput calibration and the "significant regression implies suggestion"
/// check are measured separately in release builds.
#[test]
fn test_large_t() {
    for p in ["32768", "65536"] {
        let sb = Sandbox::new(&format!("c39-{p}"));
        let data = det_bytes(300_000, 0xC39);
        sb.write("f.bin", &data);
        let enc = sb.run(&["encode", "--packet-size", p, "-o", "f.lpw", "f.bin"]);
        assert_eq!(
            enc.status.code(),
            Some(0),
            "P={p} stderr={}",
            stderr_of(&enc)
        );
        let dec = sb.run(&["decode", "-o", "f.out", "f.lpw"]);
        assert_eq!(
            dec.status.code(),
            Some(0),
            "P={p} stderr={}",
            stderr_of(&dec)
        );
        assert_eq!(
            read(&sb.path("f.out")),
            data,
            "P={p} round-trip must be byte-identical"
        );
    }
}

/// Release-only scaling calibration
/// (`cargo test --release -- --ignored test_scaling`).
///
/// Pass criteria:
/// - Single-core: lapiwe `--jobs 1` throughput must be at least 50% of a
///   same-machine crate baseline. The baseline uses the same parameters, a
///   release build, and the best of two pure encoding runs.
/// - Parallel: for j in {2, 4}, the lapiwe speedup
///   `t_lapiwe(1)/t_lapiwe(j)` must be at least 0.85 times the crate's
///   same-shape speedup `t_crate(1)/t_crate(j)` for the same block set and
///   worker count. j = 8 (SMT) is not an acceptance point.
///
/// Absolute measurements are still printed for every level: per-level times,
/// the absolute ratios, and the strict reference lines `0.7·j`. Those lines are
/// recorded for reference only and are not pass criteria.
///
/// Workload (fixed before measurement): F=64 MiB, P=4096,
/// `--block-symbols 1024` (NB=17), `--redundancy 2` (roughly as many repair
/// symbols as source symbols, which makes encoding CPU-bound); the best of
/// three runs is used per level.
///
/// Media (fixed before measurement): input and output live in
/// `std::env::temp_dir()` (tmpfs on this machine), separating CPU encoding and
/// core scaling from storage I/O. Reference numbers on disk media
/// (`CARGO_TARGET_TMPDIR`) are not part of the pass line.
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release calibration; run with cargo test --release -- --ignored"]
fn test_scaling() {
    use lapiwe::container::encode::{EncodeConfig, TotalSpec, plan, prescan};
    use std::hint::black_box;
    use std::time::Instant;

    const F: usize = 64 * 1024 * 1024;
    // Separate tmpfs sandbox, removed at the end of the test.
    let dir = std::env::temp_dir().join(format!("lapiwe-c37scaling-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create calibration sandbox");
    let data = det_bytes(F, 0xC37A);
    fs::write(dir.join("f.bin"), &data).expect("write input");

    let cfg = EncodeConfig {
        p: P,
        m: 256,
        k_max: 1024,
        total: TotalSpec::Redundancy { num: 2, den: 1 },
        force: false,
    };
    let plan = plan(&prescan(&data), &cfg).expect("plan");
    assert_eq!(
        plan.leveling.nb, 17,
        "workload shape is fixed (defined before measurement)"
    );

    // Crate baseline: the same blocks, pure encoding; best of two runs for 1,
    // 2, and 4 workers, preceded by one warm-up run to remove first-touch and
    // page-cache bias on the 64 MiB block set.
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for j in 0..plan.leveling.nb {
        let (start, len) = plan.block_span(j);
        let block_bytes = plan.block_bytes(j) as usize;
        let mut block = vec![0u8; block_bytes];
        block[..len as usize].copy_from_slice(&data[start as usize..(start + len) as usize]);
        blocks.push(block);
    }
    let packet_count = plan.d; // total data packets = Σ a_j
    let crate_encode_all = |workers: usize| -> f64 {
        use std::sync::atomic::{AtomicU32, Ordering};
        let nb = plan.leveling.nb;
        let next = AtomicU32::new(0);
        let t0 = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let j = next.fetch_add(1, Ordering::Relaxed);
                        if j >= nb {
                            break;
                        }
                        let k = plan.leveling.k_j(j);
                        let oti = lapiwe::container::encode::block_oti(
                            k * plan.leveling.t,
                            plan.leveling.t as u16,
                        );
                        let encoder =
                            raptorq::SourceBlockEncoder::new(0, &oti, &blocks[j as usize]);
                        let sources = encoder.source_packets();
                        let repairs = encoder.repair_packets(0, (plan.data_symbols(j) - k) as u32);
                        black_box(sources.last().map(|p| p.data()[0]));
                        black_box(repairs.last().map(|p| p.data()[0]));
                    }
                });
            }
        });
        t0.elapsed().as_secs_f64()
    };
    let best_of = |workers: usize| -> f64 {
        (0..2)
            .map(|_| crate_encode_all(workers))
            .fold(f64::INFINITY, f64::min)
    };
    let _warmup = best_of(1); // warm-up (discarded)
    let crate1_t = best_of(1);
    let crate2_t = best_of(2);
    let crate4_t = best_of(4);
    let crate_t = |j: usize| match j {
        2 => crate2_t,
        4 => crate4_t,
        _ => crate1_t,
    };

    // lapiwe CLI: jobs in {1,2,4}, best of three runs per level.
    let mut times = std::collections::BTreeMap::new();
    for jobs in [1usize, 2, 4] {
        let mut best = f64::INFINITY;
        for _ in 0..3 {
            let out_name = format!("j{jobs}.lpw");
            let t = Instant::now();
            let out = run_os(
                &dir,
                &[
                    "encode",
                    "--jobs",
                    &jobs.to_string(),
                    "--block-symbols",
                    "1024",
                    "--redundancy",
                    "2",
                    "-o",
                    &out_name,
                    "f.bin",
                ]
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            );
            let dt = t.elapsed().as_secs_f64();
            assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
            best = best.min(dt);
        }
        times.insert(jobs, best);
    }

    let mib = F as f64 / (1024.0 * 1024.0);
    let base_mibs = mib / crate1_t;
    let cli1_mibs = mib / times[&1];
    println!(
        "scaling report: crate baseline={base_mibs:.1} MiB/s ({packet_count} packets, {crate1_t:.3}s); \
         lapiwe jobs=1 {cli1_mibs:.1} MiB/s ({:.3}s); t(2)={:.3}s t(4)={:.3}s; \
         absolute ratios: 1={:.2} (line 0.50) 2(j=2)={:.2} (strict line 1.40, for reference) 2(j=4)={:.2} (strict line 2.80, for reference); \
         crate same-shape scaling: W2={:.2} W4={:.2}; relative scaling: j=2 {:.2} j=4 {:.2} (line 0.85)",
        times[&1],
        times[&2],
        times[&4],
        cli1_mibs / base_mibs,
        times[&1] / times[&2],
        times[&1] / times[&4],
        crate1_t / crate2_t,
        crate1_t / crate4_t,
        (times[&1] / times[&2]) / (crate1_t / crate2_t),
        (times[&1] / times[&4]) / (crate1_t / crate4_t),
    );

    // Criterion 1: single-core throughput is at least 50% of the same-machine
    // crate baseline.
    assert!(
        cli1_mibs >= 0.5 * base_mibs,
        "scaling check 1 failed: lapiwe jobs=1 {cli1_mibs:.1} MiB/s < 50% of baseline {base_mibs:.1} MiB/s"
    );
    // Criterion 2: speedup is at least 0.85 times the crate's same-shape
    // speedup; j=8 (SMT) is not an acceptance point.
    for j in [2usize, 4] {
        let cli_ratio = times[&1] / times[&j];
        let crate_ratio = crate1_t / crate_t(j);
        assert!(
            cli_ratio >= 0.85 * crate_ratio,
            "scaling check 2 failed: lapiwe speedup t(1)/t({j}) = {cli_ratio:.2} < 0.85x the same-shape crate speedup \
             {crate_ratio:.2} (t1={:.3}s, t{j}={:.3}s, crate(j)={:.3}s)",
            times[&1],
            times[&j],
            crate_t(j)
        );
    }
    // Determinism: jobs 1 and 4 must produce identical bytes.
    assert_eq!(
        read(&dir.join("j1.lpw")),
        read(&dir.join("j4.lpw")),
        "encoding output must be byte-identical across --jobs values"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Diagnostic only, with no pass threshold: the crate `SourceBlockEncoder`'s own
/// parallel scaling limit on this machine.
///
/// The goal is to separate lapiwe's parallel efficiency from the crate and
/// hardware parallel limit when interpreting the scaling calibration. This test
/// is `#[ignore]`d and release-only.
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release diagnostic; cargo test --release -- --ignored crate_parallel_scale_diagnostic"]
fn crate_parallel_scale_diagnostic() {
    use lapiwe::container::encode::{EncodeConfig, TotalSpec, plan, prescan};
    use std::hint::black_box;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    let f_mib: usize = std::env::var("LAPIWE_DIAG_F_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    let f_bytes = f_mib * 1024 * 1024;
    let k_max: u64 = std::env::var("LAPIWE_DIAG_KMAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let data = det_bytes(f_bytes, 0xC37A);
    let cfg = EncodeConfig {
        p: P,
        m: 256,
        k_max,
        total: TotalSpec::Redundancy { num: 2, den: 1 },
        force: false,
    };
    let plan = plan(&prescan(&data), &cfg).expect("plan");
    let nb = plan.leveling.nb;
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for j in 0..nb {
        let (start, len) = plan.block_span(j);
        let block_bytes = plan.block_bytes(j) as usize;
        let mut block = vec![0u8; block_bytes];
        block[..len as usize].copy_from_slice(&data[start as usize..(start + len) as usize]);
        blocks.push(block);
    }
    let mib = f_bytes as f64 / (1024.0 * 1024.0);
    for workers in [1usize, 2, 4, 8] {
        let next = AtomicU32::new(0);
        let t0 = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let j = next.fetch_add(1, Ordering::Relaxed);
                        if j >= nb {
                            break;
                        }
                        let k = plan.leveling.k_j(j);
                        let oti = lapiwe::container::encode::block_oti(
                            k * plan.leveling.t,
                            plan.leveling.t as u16,
                        );
                        let encoder =
                            raptorq::SourceBlockEncoder::new(0, &oti, &blocks[j as usize]);
                        let sources = encoder.source_packets();
                        let repairs = encoder.repair_packets(0, (plan.data_symbols(j) - k) as u32);
                        black_box(sources.last().map(|p| p.data()[0]));
                        black_box(repairs.last().map(|p| p.data()[0]));
                    }
                });
            }
        });
        let dt = t0.elapsed().as_secs_f64();
        println!(
            "crate parallel diagnostic: workers={workers} {:.1} MiB/s ({dt:.3}s)",
            mib / dt
        );
    }
}

#[test]
fn test_degenerate_matrix() {
    let sb = Sandbox::new("c40");
    let empty = sb.write("empty.bin", b"");
    assert_eq!(read(&empty), b"");

    let cases: Vec<Vec<&str>> = vec![
        // F=0.
        vec!["encode", "empty.bin"],
        // C_total < 2 (--size < 2P).
        vec!["encode", "--size", "8191", "empty.bin"],
        // M < 2.
        vec!["encode", "--meta-every", "1", "empty.bin"],
        // --max-mem < T.
        vec!["encode", "--max-mem", "2031", "empty.bin"],
        // K_max out of range.
        vec!["encode", "--block-symbols", "56404", "empty.bin"],
    ];
    for args in cases {
        let out = sb.run(&args);
        assert_single_line_error(&out, 1);
        assert!(
            out.stdout.is_empty(),
            "{args:?} must not produce stdout output"
        );
    }
    sb.write("f.bin", &det_bytes(100, 0xC40));
    // --force does not exempt degenerate parameters.
    let out = sb.run(&["encode", "--size", "4096", "--force", "f.bin"]);
    assert_single_line_error(&out, 1);
    // Smallest valid size is 2P: C_total=2 is valid, but the default redundancy
    // requirement makes the command exit 2.
    let out = sb.run(&["encode", "--size", "8192", "f.bin"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
}

#[test]
fn test_default_visible() {
    let sb = Sandbox::new("c41");
    sb.write("f.bin", &det_bytes(1200, 0xC41));
    let out = sb.run(&["encode", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("default mode"), "{stderr}");
    assert!(stderr.contains("D_req="), "{stderr}");
    assert!(stderr.contains("C_total_min="), "{stderr}");
    // Matches the container recomputation: F=1200, P=4096, M=256, default
    // K_max=4112 -> D_req=5, C_total_min=6.
    assert!(stderr.contains("D_req=5"), "{stderr}");
    assert!(stderr.contains("C_total_min=6"), "{stderr}");
}

#[test]
fn test_non_utf8_paths() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let sb = Sandbox::new("c42");
        let data = det_bytes(3000, 0xC42);
        let in_name = OsString::from_vec(b"in\xff\xfe.bin".to_vec());
        let in_path = sb.dir.join(&in_name);
        fs::write(&in_path, &data).expect("write file with non-UTF-8 name");

        // Non-UTF-8 input path: default naming (path plus .lpw) and explicit -o
        // both work.
        let out = sb.run_os(&[OsString::from("encode"), in_name.clone()]);
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
        let mut default_out = in_name.clone();
        default_out.push(".lpw");
        let produced = sb.dir.join(&default_out);
        let summary = decode_file(&produced);
        assert_eq!(summary.outcome, DecodeOutcome::Ok);
        assert_eq!(summary.data.as_deref(), Some(data.as_slice()));

        // Non-UTF-8 -o value.
        let out_name = OsString::from_vec(b"out\xf0\x28.bin".to_vec());
        let out = sb.run_os(&[
            OsString::from("encode"),
            in_name.clone(),
            OsString::from("-o"),
            out_name.clone(),
        ]);
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
        assert!(sb.dir.join(&out_name).exists());
    }
}

#[test]
fn test_arg_syntax() {
    let sb = Sandbox::new("c43");
    sb.write("f.bin", &det_bytes(1200, 0xC43));

    // `--opt=value` and `--opt value` are equivalent.
    let a = sb.run(&["encode", "--size=1M", "-o", "a.lpw", "f.bin"]);
    let b = sb.run(&["encode", "--size", "1M", "-o", "b.lpw", "f.bin"]);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert_eq!(read(&sb.path("a.lpw")), read(&sb.path("b.lpw")));

    // After `--`, operands are taken literally: a file actually named `-x`
    // exists.
    sb.write("-x", &det_bytes(500, 0xC43B));
    let out = sb.run(&["encode", "--", "-x"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert!(sb.path("-x.lpw").exists());
    // Without `--`, `-x` is an unknown flag -> exit 1.
    let out = sb.run(&["encode", "-x"]);
    assert_single_line_error(&out, 1);

    // Unknown flag, a value attached to a flag that takes none, and a non-UTF-8
    // flag.
    assert_single_line_error(&sb.run(&["encode", "--bogus", "f.bin"]), 1);
    assert_single_line_error(&sb.run(&["encode", "--force=x", "f.bin"]), 1);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'-', 0xff]);
        let out = sb.run_os(&[OsString::from("encode"), bad, OsString::from("f.bin")]);
        assert_single_line_error(&out, 1);
    }
    // Numeric option values must be UTF-8.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0xff, b'G']);
        let out = sb.run_os(&[
            OsString::from("encode"),
            OsString::from("--size"),
            bad,
            OsString::from("f.bin"),
        ]);
        assert_single_line_error(&out, 1);
    }
}

#[test]
fn test_force_warning_text() {
    let sb = Sandbox::new("c45");
    sb.write("f.bin", &det_bytes(1200, 0xC45));
    let out = sb.run(&[
        "encode",
        "--size",
        "8192",
        "--force",
        "-o",
        "f.hard.lpw",
        "f.bin",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("insufficient effective redundancy"),
        "{stderr}"
    );
    assert!(
        stderr.contains("best-effort") || stderr.contains("must not be trusted"),
        "{stderr}"
    );
    // F=1200, D=1, K=1, needed=5 -> min(a_j-needed_j) = -4.
    assert!(
        stderr.contains("min(a_j-needed_j)=-4"),
        "includes the concrete difference: {stderr}"
    );
}
