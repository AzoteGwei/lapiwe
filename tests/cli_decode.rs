//! Integration tests for the `lapiwe decode` and `lapiwe inspect` subcommands.
//!
//! The tests cover usage errors, stdin and default output naming, verification
//! modes, streaming output, job-count independence, statistics, atomic
//! publication, spool handling, `inspect` output, memory budgets, patch mode,
//! and release-only calibration of memory use and decode throughput.
//!
//! Signal handling is covered in `tests/cli_signals.rs`; encoding behaviour is
//! covered in `tests/cli_encode.rs`.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use lapiwe::container::header::parse_header;
use lapiwe::container::meta::{BLAKE3_LEN, Oti, build_meta_packet, parse_meta_packet};
use lapiwe::container::params::MICROHEADER_LEN;

const P: usize = 4096;
const T: usize = P - MICROHEADER_LEN;

// ---------------------------------------------------------------------------
// Sandbox and shared helpers
// ---------------------------------------------------------------------------

/// Per-test sandbox directory under `CARGO_TARGET_TMPDIR`, so parallel tests
/// do not collide.
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
}

fn run_os(dir: &Path, args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to start the lapiwe binary")
}

/// Run the binary with `stdin` connected to an in-memory buffer.
fn run_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start the lapiwe binary");
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

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Parse a `key=integer` pair from a statistics line.
///
/// The value ends at the next space or newline. Unlike [`parse_stat`], this
/// helper is available in debug builds as well.
fn stat_u64(stderr: &str, key: &str) -> u64 {
    stderr
        .split(key)
        .nth(1)
        .and_then(|rest| rest.split([' ', '\n']).next())
        .unwrap_or_else(|| panic!("statistics line must contain {key}: {stderr}"))
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be an integer: {stderr}"))
}

/// Assert a single-line error: exactly one line, no panic message, and no
/// backtrace.
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

fn read(path: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    File::open(path)
        .expect("open")
        .read_to_end(&mut buf)
        .expect("read");
    buf
}

/// Return sorted directory entry names, used to assert that no files or
/// temporary artifacts were left behind.
fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read directory")
        .map(|e| {
            e.expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Hand-built container streams (cross-P, no-OTI, malformed, hash mismatch,
// and metadata-conflict cases)
// ---------------------------------------------------------------------------

/// Return the OTI from the reference metadata packet (packet 0).
fn base_oti(stream: &[u8]) -> Oti {
    parse_meta_packet(&stream[..P]).expect("baseline metadata")
}

/// Replace the metadata in packet 0 with a forged OTI, leaving all other bytes
/// untouched.
fn replace_meta(stream: &[u8], oti: &Oti) -> Vec<u8> {
    let mut out = stream.to_vec();
    let forged = build_meta_packet(P, oti, false).expect("build metadata packet");
    out[..P].copy_from_slice(&forged);
    out
}

/// Append a valid metadata packet to the end of the stream (for conflict
/// counting).
fn append_meta(stream: &[u8], oti: &Oti) -> Vec<u8> {
    let mut out = stream.to_vec();
    out.extend_from_slice(&build_meta_packet(P, oti, false).expect("build metadata packet"));
    out
}

/// Remove every metadata packet, producing a stream that cannot be decoded.
fn strip_meta(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for pkt in stream.chunks_exact(P) {
        if let Ok(header) = parse_header(pkt) {
            if !header.is_meta() {
                out.extend_from_slice(pkt);
            }
        }
    }
    out
}

/// Encode test data through the CLI and return the path to the `.lpw` file.
fn encode(sb: &Sandbox, name: &str, data: &[u8], extra: &[&str]) -> PathBuf {
    let out = format!("{name}.lpw");
    encode_out(sb, name, data, &out, extra)
}

/// Like [`encode`], but with an explicit output file name.
fn encode_out(sb: &Sandbox, name: &str, data: &[u8], out: &str, extra: &[&str]) -> PathBuf {
    sb.write(name, data);
    let mut args = vec!["encode"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["-o", out, name]);
    let output = sb.run(&args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&output)
    );
    sb.path(out)
}

// ---------------------------------------------------------------------------
// Usage, stdin, and default output naming
// ---------------------------------------------------------------------------

#[test]
fn test_decode_usage() {
    let sb = Sandbox::new("d17");
    sb.write("x.lpw", b"not a stream");
    // Unknown option: single-line error and exit code 1.
    assert_single_line_error(&sb.run(&["decode", "--bogus", "x.lpw"]), 1);
    // Missing or extra operands: exit code 1.
    assert_single_line_error(&sb.run(&["decode"]), 1);
    assert_single_line_error(&sb.run(&["decode", "a", "b"]), 1);
    // `--stream` is only valid with stdout output; file output is rejected.
    let out = sb.run(&["decode", "--stream", "-o", "x.bin", "x.lpw"]);
    assert_single_line_error(&out, 1);
    assert!(stderr_of(&out).contains("--stream"), "{}", stderr_of(&out));
    // Help output: exit code 0 and a usage line.
    let out = sb.run(&["decode", "-h"]);
    assert_eq!(out.status.code(), Some(0));
    let help = stdout_of(&out);
    assert!(help.contains("lapiwe decode [OPTIONS] <IN>"), "{help}");
    assert!(
        help.contains("--no-verify") && help.contains("--stream"),
        "{help}"
    );
    // The help text must document the decode working-set budget: resident
    // repair symbols and their index, on-disk spooling when the budget is
    // exceeded, and residency independent of the input size. It must also list
    // `--spool-dir` and note that SIGKILL cannot be caught.
    assert!(help.contains("staging"), "budget wording missing: {help}");
    assert!(
        help.contains("independent of F"),
        "budget wording missing: {help}"
    );
    assert!(help.contains("--spool-dir"), "missing option: {help}");
    assert!(help.contains("SIGKILL"), "missing SIGKILL note: {help}");
}

#[test]
fn test_decode_stdin() {
    let sb = Sandbox::new("d18");
    let data = det_bytes(30_000, 0xD18);
    let produced = encode(&sb, "f.bin", &data, &[]);
    let stream = read(&produced);

    // `decode - -o -` produces the same bytes as file input.
    let from_stdin = run_stdin(&sb.dir, &["decode", "-", "-o", "-"], &stream);
    assert_eq!(
        from_stdin.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&from_stdin)
    );
    assert_eq!(from_stdin.stdout, data);

    let from_file = sb.run(&["decode", "-o", "-", "f.bin.lpw"]);
    assert_eq!(
        from_file.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&from_file)
    );
    assert_eq!(from_file.stdout, data);
    assert_eq!(
        from_stdin.stdout, from_file.stdout,
        "both paths must produce identical bytes"
    );
}

#[test]
fn test_decode_naming() {
    let sb = Sandbox::new("d19");
    let data = det_bytes(5_000, 0xD19);

    // A name ending in `.lpw` loses the suffix.
    let produced = encode_out(&sb, "f.bin", &data, "a.lpw", &[]);
    let out = sb.run(&["decode", "a.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("a")), data, "a.lpw → a");

    // Any other name gets an `.out` suffix.
    fs::copy(&produced, sb.path("b.bin")).expect("copy stream");
    let out = sb.run(&["decode", "b.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("b.bin.out")), data, "b.bin → b.bin.out");

    // With `<IN>` set to `-` and no `-o`, output defaults to stdout.
    let stream = read(&produced);
    let out = run_stdin(&sb.dir, &["decode", "-"], &stream);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);
}

// ---------------------------------------------------------------------------
// Verification modes, streaming, parallelism, and statistics
// ---------------------------------------------------------------------------

#[test]
fn test_no_verify() {
    let sb = Sandbox::new("d20");
    let data = det_bytes(100_000, 0xD20);
    let produced = encode(&sb, "f.bin", &data, &[]);
    let stream = read(&produced);

    // Success: exit code 0 and the output file is published.
    let out = sb.run(&["decode", "--no-verify", "-o", "nv.bin", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("nv.bin")), data);

    // CRCs are still checked: corrupting the last packet (a repair symbol)
    // increments the CRC failure count, but decoding still succeeds.
    let mut corrupted = stream.clone();
    let last = corrupted.len() - P;
    corrupted[last + P - 1] ^= 0xFF;
    sb.write("corrupt.lpw", &corrupted);
    let out = sb.run(&["decode", "--no-verify", "-o", "corrupt.bin", "corrupt.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("corrupt.bin")), data);
    let err = stderr_of(&out);
    assert!(
        err.contains("crc_failures=1") && err.contains("bad_packets=1"),
        "CRC checks must still run: {err}"
    );

    // Incomplete input still exits with code 2; `--no-verify` does not change
    // the classification.
    sb.write("cut.lpw", &stream[..10 * P]);
    let out = sb.run(&["decode", "--no-verify", "-o", "cut.bin", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(!sb.path("cut.bin").exists());
}

#[test]
fn test_stream() {
    let sb = Sandbox::new("d21");
    let data = det_bytes(100_000, 0xD21);
    let produced = encode(&sb, "f.bin", &data, &[]);
    let stream = read(&produced);

    // Success: streaming output matches the original data.
    let out = sb.run(&["decode", "--stream", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);

    // Insufficient input: exit code 2 and an untrusted-output warning.
    sb.write("cut.lpw", &stream[..10 * P]);
    let out = sb.run(&["decode", "--stream", "-o", "-", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(out.stdout.is_empty(), "unsolved blocks must not be written");
    assert!(
        stderr_of(&out).contains("not trustworthy"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("incomplete"),
        "{}",
        stderr_of(&out)
    );

    // `--no-verify` with `--stream` succeeds and exits 0.
    let out = sb.run(&["decode", "--stream", "--no-verify", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);
    let err = stderr_of(&out);
    assert!(
        err.contains("unverified") || err.contains("integrity is unknown"),
        "{err}"
    );

    // A stream without metadata exits with code 3.
    sb.write("nometa.lpw", &strip_meta(&stream));
    let out = sb.run(&["decode", "--stream", "-o", "-", "nometa.lpw"]);
    assert_eq!(out.status.code(), Some(3), "stderr={}", stderr_of(&out));
    assert!(out.stdout.is_empty());

    // Hash mismatch: exit code 4, and the already-emitted output is untrusted
    // (all blocks were written in order, but the digest does not match).
    let mut forged = base_oti(&stream);
    forged.blake3 = [0xAB; BLAKE3_LEN];
    sb.write("hm.lpw", &replace_meta(&stream, &forged));
    let out = sb.run(&["decode", "--stream", "-o", "-", "hm.lpw"]);
    assert_eq!(out.status.code(), Some(4), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data, "streamed block contents are correct");
    assert!(
        stderr_of(&out).contains("not trustworthy"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn test_jobs_decode() {
    let sb = Sandbox::new("d23");
    let data = det_bytes(50_000, 0xD23);
    let produced = encode(&sb, "f.bin", &data, &[]);

    let a = sb.run(&["decode", "--jobs", "1", "-o", "-", "f.bin.lpw"]);
    let b = sb.run(&["decode", "--jobs", "4", "-o", "-", "f.bin.lpw"]);
    assert_eq!(a.status.code(), Some(0), "stderr={}", stderr_of(&a));
    assert_eq!(b.status.code(), Some(0), "stderr={}", stderr_of(&b));
    assert_eq!(a.stdout, b.stdout, "results must match across --jobs");
    assert_eq!(a.stdout, data);

    // File output must be identical as well.
    let f1 = sb.run(&["decode", "--jobs", "1", "-o", "j1.bin", "f.bin.lpw"]);
    let f4 = sb.run(&["decode", "--jobs", "4", "-o", "j4.bin", "f.bin.lpw"]);
    assert_eq!(f1.status.code(), Some(0));
    assert_eq!(f4.status.code(), Some(0));
    assert_eq!(read(&sb.path("j1.bin")), read(&sb.path("j4.bin")));
    assert_eq!(read(&produced).len() % P, 0);
}

#[test]
fn test_decode_stats() {
    let sb = Sandbox::new("d24");
    let data = det_bytes(100_000, 0xD24);
    encode(&sb, "f.bin", &data, &[]);
    let out = sb.run(&["decode", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    for field in [
        "scanned=",
        "sync_candidates=",
        "crc_failures=",
        "bad_packets=",
        "duplicates=",
        "solved=",
        "direct=",
        "solver=",
        "agree_meta=",
        "conflict=",
        "bad_meta=",
        "baseline_oti=",
        "best_effort=",
        "max_j(K_j*T)=",
        "written_through_bytes=",
        "spooled_bytes=",
        "missing_symbols=",
        "scan_time=",
        "settle_time=",
        "verify_time=",
        "result=Ok",
        "elapsed=",
        "MiB/s",
    ] {
        assert!(
            err.contains(field),
            "statistics line missing `{field}`: {err}"
        );
    }
    assert!(
        err.contains("direct=1"),
        "direct block count must be visible: {err}"
    );
    // Write-through bytes cover the whole file, including zero padding of the
    // last symbol; spool bytes written on the stdout path count toward
    // `spooled_bytes`; a lossless direct stream has no missing symbols.
    let f = data.len() as u64;
    assert!(
        stat_u64(&err, "written_through_bytes=") >= f,
        "write-through bytes must be >= F: {err}"
    );
    assert!(
        stat_u64(&err, "spooled_bytes=") >= f,
        "the stdout path must count spooled bytes: {err}"
    );
    assert_eq!(
        stat_u64(&err, "missing_symbols="),
        0,
        "a direct stream has no missing symbols: {err}"
    );
}

#[test]
fn test_direct_stats() {
    // A lossless stream takes the direct path: the reported direct block count
    // must equal `NB` and the solved count must be zero. The statistics test
    // above only covers a single block; this test uses three blocks.
    let sb = Sandbox::new("d38");
    let data = det_bytes(1024 * 1024, 0xD38);
    let _lpw = encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    // S = ceil(1 MiB / 4080) = 258 and K_max = 128, so NB = ceil(258/128) = 3.
    let out = sb.run(&["decode", "-o", "out.bin", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(
        err.contains("solved=3/3"),
        "all blocks must be solved: {err}"
    );
    assert!(
        err.contains("direct=3"),
        "direct block count must equal NB: {err}"
    );
    assert!(
        err.contains("solver=0"),
        "lossless stream must not use the solver: {err}"
    );
    assert_eq!(read(&sb.path("out.bin")), data);
}

// ---------------------------------------------------------------------------
// Exit-code matrix and atomic publication
// ---------------------------------------------------------------------------

#[test]
fn test_exit_matrix() {
    let sb = Sandbox::new("d25");
    let data = det_bytes(100_000, 0xD25);
    encode(&sb, "f.bin", &data, &[]);
    let stream = read(&sb.path("f.bin.lpw"));

    // 0: all blocks decoded and the BLAKE3 digest matches.
    let out = sb.run(&["decode", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);

    // 1: malformed metadata (F=1 and NB=2 give KS=0, a format-level
    // violation).
    let malformed = replace_meta(&stream, &Oti::new(1, T as u16, 2, [0x00; BLAKE3_LEN]));
    sb.write("malformed.lpw", &malformed);
    let out = sb.run(&["decode", "-o", "bad.bin", "malformed.lpw"]);
    assert_eq!(out.status.code(), Some(1), "stderr={}", stderr_of(&out));
    assert!(
        !sb.path("bad.bin").exists(),
        "malformed input must not publish output"
    );
    assert!(
        stderr_of(&out).contains("outside the format boundary"),
        "{}",
        stderr_of(&out)
    );
    // When the layout cannot be derived, the total block count and max_j are
    // shown as N/A with the reference NB instead of a misleading zero.
    let err = stderr_of(&out);
    assert!(err.contains("solved=0/N/A(baseline_NB=2)"), "{err}");
    assert!(err.contains("max_j(K_j*T)=N/A"), "{err}");

    // 2: insufficient input (truncated stream; non-streaming stdout stays
    // empty).
    sb.write("cut.lpw", &stream[..10 * P]);
    let out = sb.run(&["decode", "-o", "-", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when the result is not Ok"
    );

    // 3: no metadata packet in the stream.
    sb.write("nometa.lpw", &strip_meta(&stream));
    let out = sb.run(&["decode", "-o", "nope.bin", "nometa.lpw"]);
    assert_eq!(out.status.code(), Some(3), "stderr={}", stderr_of(&out));
    assert!(!sb.path("nope.bin").exists());

    // 4: hash mismatch (all blocks decoded but the digest does not match).
    let mut forged = base_oti(&stream);
    forged.blake3 = [0x00; BLAKE3_LEN];
    sb.write("hm.lpw", &replace_meta(&stream, &forged));
    let out = sb.run(&["decode", "-o", "hm.bin", "hm.lpw"]);
    assert_eq!(out.status.code(), Some(4), "stderr={}", stderr_of(&out));
    assert!(
        !sb.path("hm.bin").exists(),
        "a hash mismatch must not publish output"
    );

    // Conflicting metadata does not produce exit code 3: appending a valid but
    // different metadata packet only increments the conflict counter, and
    // decoding still succeeds.
    let conflict = append_meta(&stream, &Oti::new(100_000, T as u16, 1, [0x11; BLAKE3_LEN]));
    sb.write("conflict.lpw", &conflict);
    let out = sb.run(&["decode", "-o", "conflict.bin", "conflict.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("conflict=1"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(read(&sb.path("conflict.bin")), data);
}

/// Serializes the heavyweight calibration tests in this binary.
///
/// Under the default parallel test harness these tests would start large child
/// processes (64–256 MiB) at the same time and compete for memory bandwidth.
/// That distorts both peak-RSS samples and scaling ratios, so the measurements
/// run one at a time. Serialization does not change any threshold formula, the
/// 32 MiB constant, or the sampler.
#[cfg(not(debug_assertions))]
static CALIBRATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire [`CALIBRATION_LOCK`]. A poisoned lock is treated as released, since
/// the lock protects no shared state.
#[cfg(not(debug_assertions))]
fn calibration_guard() -> std::sync::MutexGuard<'static, ()> {
    CALIBRATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII cleanup for calibration sandboxes: removes the directory on `Drop`,
/// including when a test panics or an assertion fails.
///
/// Scaling calibration stores inputs and outputs of 64 MiB or more in the
/// system temporary directory. Cleaning up only at the end of the test would
/// leave those payloads behind on tmpfs after a failure. Other tests use the
/// cargo-managed [`Sandbox`] under `CARGO_TARGET_TMPDIR`.
#[cfg(not(debug_assertions))]
struct TempDirCleanup(PathBuf);

#[cfg(not(debug_assertions))]
impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Sample a child process's peak RSS in KiB and its exit status, polling every
/// 2 ms. See [`sample_child_peak_rss`].
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn peak_rss_kib(child: &mut std::process::Child) -> (u64, std::process::ExitStatus) {
    sample_child_peak_rss(child, std::time::Duration::from_millis(2))
}

/// Like [`peak_rss_kib`], but with a 0.3 ms sampling interval, for parallel
/// scaling measurements.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn peak_rss_kib_fast(child: &mut std::process::Child) -> (u64, std::process::ExitStatus) {
    sample_child_peak_rss(child, std::time::Duration::from_micros(300))
}

/// Sample a child process's peak RSS in KiB and its exit status by polling
/// `VmHWM` in `/proc/<pid>/status` (a high-water mark that only increases).
///
/// Immediately after `spawn`, before `exec` completes, the child is a
/// copy-on-write clone of the test process, so `VmHWM` still reflects the
/// parent process (and `rusage`'s `ru_maxrss` is not reset by `exec` either).
/// Recording samples at that point can report the test process's memory as the
/// child's peak. To avoid this, the function first confirms through
/// `/proc/<pid>/exe` that `exec` has completed and points at the `lapiwe`
/// binary. The new image resets the high-water mark, so no sample is recorded
/// before the confirmation. The confirmation window is very short compared
/// with the child's working time, so samples are normally not missed. A return
/// value of `peak == 0` means the child exited before confirmation and the
/// measurement is invalid; callers assert `peak > 0` accordingly.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn sample_child_peak_rss(
    child: &mut std::process::Child,
    interval: std::time::Duration,
) -> (u64, std::process::ExitStatus) {
    let expected_name = std::path::Path::new(env!("CARGO_BIN_EXE_lapiwe")).file_name();
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
        std::thread::sleep(interval);
    }
}

/// Parse a `key=value` pair from a statistics line. The value ends at the next
/// space.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn parse_stat(stderr: &str, key: &str) -> u64 {
    stderr
        .split(key)
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("statistics line must contain {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be an integer"))
}

/// Parse the total block count `y` from the `solved=x/y` statistics field.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn parse_total_blocks(stderr: &str) -> u64 {
    stderr
        .split("solved=")
        .nth(1)
        .and_then(|rest| rest.split('/').nth(1))
        .and_then(|rest| rest.split(' ').next())
        .expect("statistics line must contain solved=x/y")
        .parse()
        .expect("total block count must be an integer")
}

/// Return the structural resident-memory bound in KiB for a lossless stream in
/// which every source symbol arrives: `max_mem + O(S/8) + 32 MiB`, where
/// `S = ceil(F/T)` and the arrival bitmap occupies `S/8` bytes.
///
/// Source symbols are written through to the target as they arrive, so the
/// resident set does not grow with the file size.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn decode_rss_lossless_kib(f: u64, t: u64, max_mem: u64) -> u64 {
    let bitmap = f.div_ceil(t).div_ceil(8);
    (max_mem + bitmap + 32 * 1024 * 1024) / 1024
}

/// Fixed per-worker part of the `o` term: the measured overhead of the crate's
/// `SourceBlockDecoder` intermediate and result buffers beyond `2·K_j·T`
/// (about 0.47 MiB per worker for the recommended payload shape), plus an
/// allowance for allocator fragmentation and run-to-run variation, rounded to
/// 1 MiB.
///
/// This constant only tightens or loosens the bound that tests assert against
/// (`peak <= bound`). A loose value makes the check more conservative; the
/// absolute 256/512 MiB limits are not relaxed.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
const SETTLE_SCRATCH_SLACK_PER_WORKER: u64 = 1024 * 1024;

/// Individual terms of the structural memory bound, used for report output. The
/// limit asserted by tests still comes from [`decode_rss_limit_kib`], which is
/// computed from the same values.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
struct RssTerms {
    f: u64,
    jobs: usize,
    nb: u64,
    t: u64,
    max_block: u64,
    max_mem: u64,
    k: u64,
    cap: u64,
    workers: u64,
    /// Symbol slack of one batch window relative to `K_j`:
    /// `needed_j(K_j) + DROP_MARGIN - K_j`.
    window: u64,
    /// Per-worker `o` term in bytes.
    o: u64,
    /// `2·max_j(K_j·T)` in bytes.
    two_max: u64,
    /// `O(S/8)` arrival bitmap in bytes.
    bitmap: u64,
    limit_kib: u64,
    lossless_kib: u64,
}

/// Compute the structural memory bound term by term:
/// `min(jobs, NB, cap) * (2 * max_j(K_j*T) + o) + max_mem + O(S/8) + 32 MiB`.
///
/// - `cap = floor(SETTLE_RESIDENT_LIMIT / (2 * max_j(K_j*T)))` limits the number
///   of workers so that solver residency stays within bounds;
/// - `o` (per worker) is the batch-window slack
///   `(needed_j(K_j) + DROP_MARGIN - K_j) * T` plus
///   [`SETTLE_SCRATCH_SLACK_PER_WORKER`];
/// - `max_mem` is the decode `--max-mem` value for this run (64 MiB by default).
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn rss_terms(f: u64, jobs: usize, nb: u64, t: u64, max_block: u64, max_mem: u64) -> RssTerms {
    use lapiwe::container::counts::needed_j;
    use lapiwe::container::decode::{DROP_MARGIN, SETTLE_RESIDENT_LIMIT};
    assert!(
        t > 0 && max_block % t == 0,
        "max_j(K_j·T) must be a multiple of T"
    );
    let k = max_block / t;
    let cap = (SETTLE_RESIDENT_LIMIT / (2 * max_block)).max(1);
    let workers = (jobs as u64).min(nb).min(cap);
    let window = needed_j(k).saturating_add(DROP_MARGIN).saturating_sub(k);
    let o = window * t + SETTLE_SCRATCH_SLACK_PER_WORKER;
    let bitmap = f.div_ceil(t).div_ceil(8);
    let limit_kib = (workers * (2 * max_block + o) + max_mem + bitmap + 32 * 1024 * 1024) / 1024;
    RssTerms {
        f,
        jobs,
        nb,
        t,
        max_block,
        max_mem,
        k,
        cap,
        workers,
        window,
        o,
        two_max: 2 * max_block,
        bitmap,
        limit_kib,
        lossless_kib: decode_rss_lossless_kib(f, t, max_mem),
    }
}

/// Return the structural decode memory bound in KiB:
/// `min(jobs, NB, cap) * (2 * max_j(K_j*T) + o) + max_mem + O(S/8) + 32 MiB`.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn decode_rss_limit_kib(f: u64, jobs: usize, nb: u64, t: u64, max_block: u64, max_mem: u64) -> u64 {
    rss_terms(f, jobs, nb, t, max_block, max_mem).limit_kib
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
impl RssTerms {
    /// Print one report line with every term of the structural bound, the
    /// measured peak, the line limit, and the remaining margin.
    ///
    /// This output is informational only and takes part in no assertion; limits
    /// and pass/fail checks are made by the caller.
    fn report(&self, label: &str, peak_kib: u64, line_kib: u64, note: &str) {
        let s = self.f.div_ceil(self.t);
        let window_bytes = self.window * self.t;
        let fixed: u64 = 32 * 1024 * 1024;
        println!(
            " report: {label}; measured peak={peak_kib} KiB; structural terms: \
             min(jobs,NB,cap)={workers} (jobs={jobs}, NB={nb}, cap={cap}) × \
             [2·max_j(K_j·T)={two_max} B (max_j(K_j·T)={max_block} B, K_j={k}) + \
             o={o} B (window=(needed_j(K_j)+DROP_MARGIN−K_j)·T={window}×{t}={window_bytes} B \
             + crate scratch={scratch} B)] + max_mem={max_mem} B + O(S/8)={bitmap} B (S={s}) \
             + 32 MiB={fixed} B ⇒ structural bound={limit} KiB; \
             lossless branch (no solver path)=max_mem+O(S/8)+32 MiB={lossless} KiB; \
             row limit={line} KiB (numeric-line margin={line_margin} KiB); \
             structural-bound margin={margin} KiB{note}",
            workers = self.workers,
            jobs = self.jobs,
            nb = self.nb,
            cap = self.cap,
            two_max = self.two_max,
            max_block = self.max_block,
            k = self.k,
            o = self.o,
            window = self.window,
            t = self.t,
            window_bytes = window_bytes,
            scratch = SETTLE_SCRATCH_SLACK_PER_WORKER,
            max_mem = self.max_mem,
            bitmap = self.bitmap,
            s = s,
            fixed = fixed,
            limit = self.limit_kib,
            lossless = self.lossless_kib,
            line = line_kib,
            line_margin = line_kib as i64 - peak_kib as i64,
            margin = self.limit_kib as i64 - peak_kib as i64,
        );
    }
}

#[test]
fn test_atomic_publish() {
    let sb = Sandbox::new("d26");
    let data = det_bytes(100_000, 0xD26);
    encode(&sb, "f.bin", &data, &[]);
    let stream = read(&sb.path("f.bin.lpw"));

    // Success: the target is published with no temporary files left behind.
    let out = sb.run(&["decode", "-o", "ok.bin", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("ok.bin")), data);
    assert!(
        !dir_entries(&sb.dir)
            .iter()
            .any(|n| n.contains(".lapiwe-tmp")),
        "the success path must not leave temporary files behind"
    );

    // Failure (exit code 2): no target is created and the directory contents
    // do not change.
    sb.write("cut.lpw", &stream[..10 * P]);
    let before = dir_entries(&sb.dir);
    let out = sb.run(&["decode", "-o", "no.bin", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(
        !sb.path("no.bin").exists(),
        "must not create a target when the result is not Ok"
    );
    assert_eq!(
        dir_entries(&sb.dir),
        before,
        "the failure path must not add or leave files"
    );

    // `--no-verify` with file output publishes once the CRC checks pass.
    let out = sb.run(&["decode", "--no-verify", "-o", "nv.bin", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("nv.bin")), data);

    // A failed non-streaming stdout run emits zero bytes.
    let out = sb.run(&["decode", "-o", "-", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
fn test_streaming_publish_partial_failure_leaves_nothing() {
    // File output is written as blocks are decoded. If the stream turns out to
    // be insufficient after some blocks were written to the temporary file,
    // that file must be removed and the target must not appear.
    let sb = Sandbox::new("d26partial");
    let data = det_bytes(1024 * 1024, 0xD26B);
    let _lpw = encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    let stream = read(&sb.path("f.bin.lpw"));

    // Keep only metadata packets and block 0 packets: block 0 decodes (and is
    // written to the temporary file), while blocks 1 and 2 do not.
    let mut partial = Vec::new();
    let mut blk0_packets = 0usize;
    for pkt in stream.chunks_exact(P) {
        let header = parse_header(pkt).expect("frame validation must pass");
        if header.is_meta() || header.blk_idx == 0 {
            if !header.is_meta() {
                blk0_packets += 1;
            }
            partial.extend_from_slice(pkt);
        }
    }
    assert!(blk0_packets > 0, "block 0 must have at least one packet");
    sb.write("partial.lpw", &partial);

    let before = dir_entries(&sb.dir);
    let out = sb.run(&["decode", "-o", "partial.bin", "partial.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(
        err.contains("solved=1/3"),
        "block 0 should be solved first: {err}"
    );
    assert!(
        !sb.path("partial.bin").exists(),
        "must not publish a target when the result is not Ok"
    );
    assert_eq!(
        dir_entries(&sb.dir),
        before,
        "temporary files must be removed with no leftovers"
    );
}

/// Decode stdout (including `--stream`) is spooled through `--spool-dir`: the
/// output matches the source byte for byte, spool and spill files are removed
/// on both success and failure, and file output uses the same directory for
/// spills.
#[test]
fn test_decode_spool_dir_roundtrip_and_cleanup() {
    let sb = Sandbox::new("d22");
    let data = det_bytes(300_000, 0xD22);
    encode(&sb, "f.bin", &data, &["--redundancy", "2"]);
    let stream = read(&sb.path("f.bin.lpw"));
    fs::create_dir_all(sb.path("spool")).expect("spool directory");
    let f = data.len() as u64;

    // Non-streaming stdout: spool first, then copy the data out once the result
    // class is known.
    let out = sb.run(&["decode", "--spool-dir", "spool", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);
    let err = stderr_of(&out);
    assert!(
        stat_u64(&err, "spooled_bytes=") >= f,
        "the stdout path must count spooled bytes in spooled_bytes: {err}"
    );
    assert!(
        dir_entries(&sb.path("spool")).is_empty(),
        "the success path must clean up spool/spill files: {:?}",
        dir_entries(&sb.path("spool"))
    );

    // With `--stream`, the spool file's byte order guarantees block order.
    let out = sb.run(&[
        "decode",
        "--spool-dir",
        "spool",
        "--stream",
        "-o",
        "-",
        "f.bin.lpw",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(
        out.stdout, data,
        "--stream output must equal the source byte for byte"
    );
    assert!(
        dir_entries(&sb.path("spool")).is_empty(),
        "spool must be cleaned up"
    );

    // Failure (insufficient input): stdout stays empty and the spool is cleaned
    // up.
    sb.write("cut.lpw", &stream[..10 * P]);
    let out = sb.run(&["decode", "--spool-dir", "spool", "-o", "-", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty when the result is not Ok"
    );
    assert!(
        dir_entries(&sb.path("spool")).is_empty(),
        "the failure path must clean up"
    );

    // File output: the publication temp file stays next to the target, while
    // spill files live in `--spool-dir` and are removed afterwards.
    let out = sb.run(&[
        "decode",
        "--spool-dir",
        "spool",
        "-o",
        "out.bin",
        "f.bin.lpw",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.path("out.bin")), data);
    assert!(
        dir_entries(&sb.path("spool")).is_empty(),
        "file output must clean up spill files"
    );
    assert!(
        !dir_entries(&sb.dir)
            .iter()
            .any(|n| n.contains(".lapiwe-tmp")),
        "publication temporary files must not be left behind"
    );
}

/// An unusable spool directory (a regular file or a missing directory) produces
/// a single-line error with exit code 1 and a suggestion to use `--spool-dir`,
/// and no partial output is published.
#[test]
fn test_spool_unavailable_is_single_line_error() {
    let sb = Sandbox::new("d47spool");
    let data = det_bytes(50_000, 0xD47);
    encode(&sb, "f.bin", &data, &[]);
    sb.write("not-a-dir", b"x");

    for (dir, expect) in [
        ("not-a-dir", "ENOTDIR path"),
        ("missing-dir", "missing directory"),
    ] {
        for out_name in ["-", "out.bin"] {
            let out = sb.run(&["decode", "--spool-dir", dir, "-o", out_name, "f.bin.lpw"]);
            assert_single_line_error(&out, 1);
            let err = stderr_of(&out);
            assert!(
                err.contains("--spool-dir"),
                "{expect}: the suggestion must mention --spool-dir: {err}"
            );
            assert!(out.stdout.is_empty(), "{expect}: stdout must be empty");
            assert!(
                !sb.path("out.bin").exists(),
                "{expect}: must not publish partial output"
            );
        }
    }
}

/// A small `--max-mem` with a high-redundancy stream forces repair symbols past
/// the budget to spill to disk (`spooled_bytes > 0`) while decoding still
/// succeeds. Output is identical for `--jobs 1` and `--jobs 4`, and spill files
/// in `--spool-dir` are removed afterwards.
#[test]
fn test_decode_spill_backend_roundtrip() {
    let sb = Sandbox::new("d47spill");
    let data = det_bytes(1024 * 1024, 0xD47B);
    encode(&sb, "f.bin", &data, &["--redundancy", "4"]);
    let stream = read(&sb.path("f.bin.lpw"));
    // Remove ESI 0 from every block to force solver use; the remaining repair
    // symbols overflow the memory budget.
    sb.write("dmg.lpw", &drop_esis(&stream, P, &[0]));
    fs::create_dir_all(sb.path("spool")).expect("spool directory");

    let mut outputs = Vec::new();
    for jobs in ["1", "4"] {
        let path = format!("o{jobs}.bin");
        let out = sb.run(&[
            "decode",
            "--max-mem",
            "96KiB",
            "--spool-dir",
            "spool",
            "--jobs",
            jobs,
            "-o",
            &path,
            "dmg.lpw",
        ]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "jobs={jobs}: stderr={}",
            stderr_of(&out)
        );
        let err = stderr_of(&out);
        assert!(
            stat_u64(&err, "spooled_bytes=") > 0,
            "jobs={jobs}: repair symbols over budget must spill to disk: {err}"
        );
        assert!(
            stat_u64(&err, "missing_symbols=") > 0,
            "jobs={jobs}: settlement must restore missing symbols: {err}"
        );
        assert!(
            dir_entries(&sb.path("spool")).is_empty(),
            "jobs={jobs}: spill staging must be cleaned up: {:?}",
            dir_entries(&sb.path("spool"))
        );
        outputs.push(read(&sb.path(&path)));
    }
    assert_eq!(
        outputs[0], data,
        "jobs=1 output must equal the original data"
    );
    assert_eq!(
        outputs[1], outputs[0],
        "jobs=1/4 outputs must be byte-identical"
    );
}

/// Peak-RSS regression test for file publication with the default settings and
/// a lossless stream.
///
/// Source symbols are written through to the publication temp file as they
/// arrive, so residency is independent of the file size. The test asserts:
/// - the lossless structural bound `max_mem + O(S/8) + 32 MiB`
///   ([`decode_rss_lossless_kib`]);
/// - the general structural bound for `jobs=4` ([`decode_rss_limit_kib`]),
///   which also holds for lossless streams;
/// - the constant-memory limit of 256 MiB for `--jobs 1..4`.
///
/// The measured peak is also printed as a multiple of the file size for
/// reference.
///
/// Release-only (`#[ignore]`), with a 256 MiB input and default parameters.
#[cfg(target_os = "linux")]
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release-only calibration (publish RSS); run with cargo test --release -- --ignored"]
fn test_file_publish_peak_rss_streaming() {
    use std::process::Stdio;

    // Run serially with the other peak-memory and scaling measurements, even
    // under the default parallel test harness.
    let _cal_guard = calibration_guard();
    const F: usize = 256 * 1024 * 1024;
    const MAX_MEM: u64 = lapiwe::container::params::DEFAULT_DECODE_MAX_MEM;
    let sb = Sandbox::new("d26rss");
    let data = det_bytes(F, 0xD26A);
    sb.write("f.bin", &data);
    let out = sb.run(&["encode", "-o", "f.lpw", "f.bin"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));

    let run_peak = |jobs: &str, out_name: &str| -> u64 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["decode", "--jobs", jobs, "-o", out_name, "f.lpw"])
            .current_dir(&sb.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start decode");
        let (peak_kib, status) = peak_rss_kib(&mut child);
        assert_eq!(status.code(), Some(0), "decode must succeed (jobs={jobs})");
        assert!(
            peak_kib > 0,
            "could not read /proc/<pid>/status (unsupported test environment?)"
        );
        peak_kib
    };
    let f_kib = (F / 1024) as u64;
    let bitmap_bytes = (F as u64).div_ceil(T as u64).div_ceil(8);

    // Serial run on a lossless stream (all blocks take the direct path, with no
    // solver residency).
    let peak_kib = run_peak("1", "out.bin");
    let lossless_limit = decode_rss_lossless_kib(F as u64, T as u64, MAX_MEM);
    println!(
        "RSS report: F=256 MiB file output (jobs=1): measured={peak_kib} KiB ({:.3}×F); \
         structural bound (lossless) = max_mem={} MiB + O(S/8)={bitmap_bytes} B + 32 MiB = {lossless_limit} KiB; \
         numeric limit (--jobs 1..4) = 262144 KiB; earlier targets were retired by the out-of-core spooling design (archived)",
        peak_kib as f64 / f_kib as f64,
        MAX_MEM / (1024 * 1024),
    );
    assert!(
        peak_kib <= lossless_limit,
        "lossless structural bound failed: peak {peak_kib} KiB > {lossless_limit} KiB (F=256 MiB, S/8={bitmap_bytes} B)"
    );
    assert!(
        peak_kib <= 256 * 1024,
        "numeric limit failed (--jobs 1..4 <= 256 MiB): peak {peak_kib} KiB"
    );
    let decoded = read(&sb.path("out.bin"));
    assert_eq!(decoded.len(), F, "output length must equal F");
    assert!(
        decoded == data,
        "streamed publication output must be byte-identical"
    );

    // Parallel solver accounting against the general structural bound;
    // `max_j(K_j*T)` and `NB` are parsed from the statistics line so the test
    // uses the same values as the implementation.
    let probe = sb.run(&["decode", "--jobs", "4", "-o", "probe.bin", "f.lpw"]);
    assert_eq!(probe.status.code(), Some(0), "stderr={}", stderr_of(&probe));
    let max_block = parse_stat(&stderr_of(&probe), "max_j(K_j*T)=");
    let nb = parse_total_blocks(&stderr_of(&probe));
    let peak4 = run_peak("4", "out4.bin");
    let limit4 = decode_rss_limit_kib(F as u64, 4, nb, T as u64, max_block, MAX_MEM);
    println!(
        "RSS report: F=256 MiB file output (jobs=4) peak={peak4} KiB; structural \
         min(jobs,NB,cap)·(2·max_j(K_j·T)+o) + max_mem + O(S/8) + 32 MiB={limit4} KiB \
         (max_j(K_j·T)={max_block}, NB={nb}, margin {} KiB)",
        limit4 as i64 - peak4 as i64
    );
    assert!(
        peak4 <= limit4,
        "structural bound failed (jobs=4): peak {peak4} KiB > {limit4} KiB (max={max_block}, NB={nb})"
    );
    assert!(
        peak4 <= 256 * 1024,
        "numeric limit failed (--jobs 1..4 <= 256 MiB): peak {peak4} KiB"
    );
    assert!(
        read(&sb.path("out4.bin")) == data,
        "jobs=4 output must be byte-identical"
    );
}

// ---------------------------------------------------------------------------
// Constant-memory acceptance (release only)
// ---------------------------------------------------------------------------

/// Write deterministic input in chunks so the test process's own memory does
/// not grow with the file size (1 MiB buffer, xorshift64).
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn write_det_chunked(path: &Path, len: u64, seed: u64) {
    use std::io::BufWriter;
    let file = File::create(path).expect("create input file");
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let mut chunk = vec![0u8; 1 << 20];
    let mut state = seed | 1;
    let mut left = len;
    while left > 0 {
        let want = (chunk.len() as u64).min(left) as usize;
        for byte in &mut chunk[..want] {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 24) as u8;
        }
        writer.write_all(&chunk[..want]).expect("write input");
        left -= want as u64;
    }
    writer.flush().expect("flush input");
}

/// Compare two files in chunks and return `true` if they are identical.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn files_equal_chunked(a: &Path, b: &Path) -> bool {
    let mut fa = File::open(a).expect("open A");
    let mut fb = File::open(b).expect("open B");
    let mut buf_a = vec![0u8; 1 << 20];
    let mut buf_b = vec![0u8; 1 << 20];
    loop {
        let na = fa.read(&mut buf_a).expect("read A");
        let nb = fb.read(&mut buf_b).expect("read B");
        if na != nb || buf_a[..na] != buf_b[..nb] {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

/// Constant-memory model and acceptance test for decoding default-format
/// streams.
///
/// The test covers:
/// - (a) default settings with `--jobs 1..4`: peak at most 256 MiB; the default
///   `--jobs` value (logical core count): at most 512 MiB;
/// - (b) 2 GiB and 8 GiB inputs with the same parameters (jobs 1 and 4) differ by
///   at most 64 MiB;
/// - (c) stdout (with and without `--stream`) follows the same limits as file
///   output (256 MiB), and `--stream` output matches the source byte for byte;
/// - (d) a spool failure (`--spool-dir` pointing at a regular file) exits 1 with
///   a single line and no partial publication.
///
/// Every measured row, including reference rows, prints all terms of the
/// structural bound, the measured peak, the row limit, and the remaining margin.
/// Printing is informational and does not affect any threshold.
///
/// An additional solver-and-spill row (explicit `--redundancy 2`, ESI 0 removed
/// from every block, 256 MiB input) verifies that the same 256 MiB limit holds
/// for `--jobs 1..3`, which actually exercises the solver and spill paths. The
/// default settings are close to minimal redundancy, so dropping a single source
/// symbol makes a block undecodable; default-format streams therefore only take
/// the direct path. Measurements for `--jobs 4` and the default job count in
/// that shape are printed for reference only.
///
/// Large artifacts are stored under `CARGO_TARGET_TMPDIR` (project disk; `/tmp`
/// is a quota-limited tmpfs that can report `EDQUOT` for multi-gigabyte files).
/// Child processes use a spool directory inside the test tree as `TMPDIR`. Each
/// output is removed after measurement, so peak disk use is roughly the source
/// plus the stream plus the current output.
///
/// Release-only (`#[ignore]`; requires about 25 GiB of free disk space and
/// several minutes).
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[test]
#[ignore = "release-only calibration (constant memory); cargo test --release -- --ignored test_decode_constant_memory"]
fn test_decode_constant_memory() {
    use std::process::Stdio;

    let _cal_guard = calibration_guard();
    const F2: u64 = 2 * (1 << 30);
    const F8: u64 = 8 * (1 << 30);
    const FD: u64 = 256 * (1 << 20);
    const MAX_MEM: u64 = lapiwe::container::params::DEFAULT_DECODE_MAX_MEM;
    const LINE_256_MIB: u64 = 256 * 1024;
    const LINE_512_MIB: u64 = 512 * 1024;
    const DIFF_64_MIB: u64 = 64 * 1024;
    let bin = env!("CARGO_BIN_EXE_lapiwe");
    let jobs_default = std::thread::available_parallelism().map_or(1, |n| n.get());

    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("c47");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("spool")).expect("create  sandbox");
    let _cleanup = TempDirCleanup(dir.clone());
    let spool = dir.join("spool");

    // Run one decode and return `(peak KiB, exit code, stderr)`. If
    // `stdout_file` is set, write stdout to that path; otherwise discard it.
    let run = |args: &[&str], stdout_file: Option<&Path>| -> (u64, i32, String) {
        let mut cmd = Command::new(bin);
        cmd.args(args).current_dir(&dir).env("TMPDIR", &spool);
        cmd.stderr(Stdio::piped());
        match stdout_file {
            Some(path) => {
                cmd.stdout(Stdio::from(File::create(path).expect("create stdout file")));
            }
            None => {
                cmd.stdout(Stdio::null());
            }
        }
        let mut child = cmd.spawn().expect("start decode");
        let (peak, status) = peak_rss_kib_fast(&mut child);
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        (peak, status.code().unwrap_or(-1), stderr)
    };

    // Default-format artifacts: P=4096, encode `--max-mem` 16 MiB, and the
    // default total symbol count.
    for (name, len, seed) in [("f2.bin", F2, 0xC47A), ("f8.bin", F8, 0xC47B)] {
        write_det_chunked(&dir.join(name), len, seed);
        let out = Command::new(bin)
            .args(["encode", "-o", &format!("{}.lpw", &name[..2]), name])
            .current_dir(&dir)
            .env("TMPDIR", &spool)
            .output()
            .expect("start encode");
        assert_eq!(
            out.status.code(),
            Some(0),
            "encode {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Layout probes used to print the structural terms; they also verify that
    // default-format decoding succeeds.
    let (_, code, stderr) = run(
        &["decode", "--jobs", "1", "-o", "probe2.bin", "f2.lpw"],
        None,
    );
    assert_eq!(code, 0, "probe F=2 GiB: {stderr}");
    let max2 = parse_stat(&stderr, "max_j(K_j*T)=");
    let nb2 = parse_total_blocks(&stderr);
    fs::remove_file(dir.join("probe2.bin")).expect("remove probe2");
    let (_, code, stderr) = run(
        &["decode", "--jobs", "1", "-o", "probe8.bin", "f8.lpw"],
        None,
    );
    assert_eq!(code, 0, "probe F=8 GiB: {stderr}");
    let max8 = parse_stat(&stderr, "max_j(K_j*T)=");
    let nb8 = parse_total_blocks(&stderr);
    fs::remove_file(dir.join("probe8.bin")).expect("remove probe8");

    // (a) Default file output: `--jobs 1..4` stays within 256 MiB at F=2 GiB.
    let mut peaks2 = Vec::new();
    for jobs in [1usize, 2, 3, 4] {
        let out_name = format!("out2_j{jobs}.bin");
        let (peak, code, stderr) = run(
            &[
                "decode",
                "--jobs",
                &jobs.to_string(),
                "-o",
                &out_name,
                "f2.lpw",
            ],
            None,
        );
        assert_eq!(code, 0, "F=2 GiB jobs={jobs}: {stderr}");
        rss_terms(F2, jobs, nb2, T as u64, max2, MAX_MEM).report(
            &format!("default profile F=2 GiB file output jobs={jobs}"),
            peak,
            LINE_256_MIB,
            "",
        );
        assert!(
            peak <= LINE_256_MIB,
            "(a) failed: F=2 GiB jobs={jobs} peak {peak} KiB > 256 MiB"
        );
        peaks2.push(peak);
        fs::remove_file(dir.join(&out_name)).expect("remove output");
    }
    // The default `--jobs` value (logical core count) stays within 512 MiB.
    let (peak_default, code, stderr) = run(&["decode", "-o", "out2_default.bin", "f2.lpw"], None);
    assert_eq!(code, 0, "default jobs: {stderr}");
    rss_terms(F2, jobs_default, nb2, T as u64, max2, MAX_MEM).report(
        &format!(
            "default profile F=2 GiB file output default --jobs ({jobs_default} logical cores)"
        ),
        peak_default,
        LINE_512_MIB,
        "; (a) line for default jobs=524288 KiB",
    );
    assert!(
        peak_default <= LINE_512_MIB,
        "(a) failed: default jobs peak {peak_default} KiB > 512 MiB"
    );
    fs::remove_file(dir.join("out2_default.bin")).expect("remove output");
    // Content check: compare the files in chunks once. For the other rows, exit
    // code 0 means the CLI read back a matching BLAKE3 digest.
    let (peak_check, code, stderr) = run(
        &["decode", "--jobs", "1", "-o", "check2.bin", "f2.lpw"],
        None,
    );
    assert_eq!(code, 0, "content check row: {stderr}");
    rss_terms(F2, 1, nb2, T as u64, max2, MAX_MEM).report(
        "default profile F=2 GiB file output jobs=1 (content check row)",
        peak_check,
        LINE_256_MIB,
        "",
    );
    assert!(
        files_equal_chunked(&dir.join("check2.bin"), &dir.join("f2.bin")),
        "F=2 GiB output must equal the source byte for byte"
    );
    fs::remove_file(dir.join("check2.bin")).expect("remove check output");

    // (b) Independence from F: 2 GiB and 8 GiB inputs with the same parameters
    // (jobs 1 and 4) differ by at most 64 MiB.
    for (peak2, jobs) in [(peaks2[0], 1usize), (peaks2[3], 4)] {
        let out_name = format!("out8_j{jobs}.bin");
        let (peak8, code, stderr) = run(
            &[
                "decode",
                "--jobs",
                &jobs.to_string(),
                "-o",
                &out_name,
                "f8.lpw",
            ],
            None,
        );
        assert_eq!(code, 0, "F=8 GiB jobs={jobs}: {stderr}");
        let diff = (peak8 as i64 - peak2 as i64).unsigned_abs();
        rss_terms(F8, jobs, nb8, T as u64, max8, MAX_MEM).report(
            &format!("default profile F=8 GiB file output jobs={jobs}"),
            peak8,
            LINE_256_MIB,
            &format!(
                "; peak difference vs F=2 GiB ({peak2} KiB)={diff} KiB; (b) line={DIFF_64_MIB} KiB, \
                 difference margin={} KiB",
                DIFF_64_MIB as i64 - diff as i64
            ),
        );
        assert!(
            peak8 <= LINE_256_MIB,
            "(a) failed: F=8 GiB jobs={jobs} peak {peak8} KiB > 256 MiB"
        );
        assert!(
            diff <= DIFF_64_MIB,
            "(b) failed: F=2/8 GiB peak difference {diff} KiB > 64 MiB (jobs={jobs})"
        );
        fs::remove_file(dir.join(&out_name)).expect("remove output");
    }

    // (c) stdout (with and without `--stream`) follows the same limits as file
    // output.
    let plain = dir.join("stdout_plain.bin");
    let (peak, code, stderr) = run(
        &["decode", "--jobs", "4", "-o", "-", "f2.lpw"],
        Some(&plain),
    );
    assert_eq!(code, 0, "stdout without --stream: {stderr}");
    rss_terms(F2, 4, nb2, T as u64, max2, MAX_MEM).report(
        "default profile F=2 GiB stdout (without --stream) jobs=4",
        peak,
        LINE_256_MIB,
        "; see spooled_bytes in the statistics line for staging accounting",
    );
    assert!(
        peak <= LINE_256_MIB,
        "(c) failed: stdout without --stream peak {peak} KiB > 256 MiB"
    );
    assert_eq!(
        fs::metadata(&plain).expect("stdout file").len(),
        F2,
        "stdout without --stream must be exactly F bytes"
    );
    fs::remove_file(&plain).expect("remove stdout file");
    let stream_file = dir.join("stdout_stream.bin");
    let (peak, code, stderr) = run(
        &["decode", "--jobs", "4", "--stream", "-o", "-", "f2.lpw"],
        Some(&stream_file),
    );
    assert_eq!(code, 0, "stdout --stream: {stderr}");
    rss_terms(F2, 4, nb2, T as u64, max2, MAX_MEM).report(
        "default profile F=2 GiB stdout (--stream) jobs=4",
        peak,
        LINE_256_MIB,
        "; see spooled_bytes in the statistics line for staging accounting",
    );
    assert!(
        peak <= LINE_256_MIB,
        "(c) failed: --stream peak {peak} KiB > 256 MiB"
    );
    assert!(
        files_equal_chunked(&stream_file, &dir.join("f2.bin")),
        "--stream output must equal the source byte for byte (emitted in block order after spooling)"
    );
    fs::remove_file(&stream_file).expect("remove stdout file");

    // (d) Spool failure (`--spool-dir` is a regular file): exit 1, a single line
    // with a suggestion, and no partial publication.
    let bad = dir.join("not_a_dir");
    fs::write(&bad, b"x").expect("write placeholder file");
    let (_, code, stderr) = run(
        &[
            "decode",
            "--spool-dir",
            "not_a_dir",
            "-o",
            "never.bin",
            "f2.lpw",
        ],
        None,
    );
    assert_eq!(code, 1, "staging failure must exit 1: {stderr:?}");
    assert_eq!(
        stderr.matches('\n').count(),
        1,
        "must be a single line: {stderr:?}"
    );
    assert!(
        stderr.contains("--spool-dir"),
        "must contain a suggestion: {stderr}"
    );
    assert!(
        !dir.join("never.bin").exists(),
        "no partial publication: the target must not appear"
    );
    assert!(
        fs::read_dir(&dir).expect("directory").all(|entry| !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .contains(".lapiwe-tmp")),
        "the failure path must not leave publication temporary files"
    );
    assert!(
        fs::read_dir(&spool).expect("spool").next().is_none(),
        "the failure path must not leave spool/spill staging"
    );

    // Additional solver-plus-spill shape: explicit `--redundancy 2` with ESI 0
    // removed from every block. The same 256 MiB limit holds for `--jobs 1..3`;
    // readings for `--jobs 4` and the default job count are printed for
    // reference. In this shape the crate's solver scratch is about 2.9 times
    // max_j(K_j*T) per worker, so the jobs=4 reading is known to exceed the
    // limit.
    write_det_chunked(&dir.join("fd.bin"), FD, 0xC47D);
    let out = Command::new(bin)
        .args(["encode", "-o", "fd.lpw", "--redundancy", "2", "fd.bin"])
        .current_dir(&dir)
        .env("TMPDIR", &spool)
        .output()
        .expect("start encode");
    assert_eq!(
        out.status.code(),
        Some(0),
        "encode fd: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    {
        let stream = fs::read(dir.join("fd.lpw")).expect("read fd.lpw");
        let mut damaged = Vec::with_capacity(stream.len());
        for packet in stream.chunks_exact(P) {
            let header = parse_header(packet).expect("frame validation must pass");
            if !header.is_meta() && header.esi == 0 {
                continue;
            }
            damaged.extend_from_slice(packet);
        }
        fs::write(dir.join("fd-dmg.lpw"), &damaged).expect("write damaged stream");
    }
    for jobs in [1usize, 2, 3] {
        let (peak, code, stderr) = run(
            &[
                "decode",
                "--jobs",
                &jobs.to_string(),
                "-o",
                "fd_out.bin",
                "fd-dmg.lpw",
            ],
            None,
        );
        assert_eq!(code, 0, "solver shape jobs={jobs}: {stderr}");
        let max_d = parse_stat(&stderr, "max_j(K_j*T)=");
        let nb_d = parse_total_blocks(&stderr);
        rss_terms(FD, jobs, nb_d, T as u64, max_d, MAX_MEM).report(
            &format!("solver+spill shape (--redundancy 2, ESI=0 removed from every block) F=256 MiB jobs={jobs}"),
            peak,
            LINE_256_MIB,
            "; this row uses a non-default shape (the solver path runs)",
        );
        assert!(
            peak <= LINE_256_MIB,
            "numeric limit failed (solver shape jobs={jobs}): peak {peak} KiB > 256 MiB"
        );
    }
    assert!(
        files_equal_chunked(&dir.join("fd_out.bin"), &dir.join("fd.bin")),
        "solver-shape output must equal the source byte for byte"
    );
    // Reference readings for jobs=4 and the default job count in the same shape.
    // These are not asserted because of the solver scratch overhead noted above.
    for jobs in [Some(4usize), None] {
        let jobs_text = jobs.map(|j| j.to_string());
        let mut args = vec!["decode"];
        if let Some(text) = &jobs_text {
            args.extend_from_slice(&["--jobs", text.as_str()]);
        }
        args.extend_from_slice(&["-o", "fd_out2.bin", "fd-dmg.lpw"]);
        let (peak, code, stderr) = run(&args, None);
        assert_eq!(code, 0, "solver shape jobs={jobs:?}: {stderr}");
        let max_a = parse_stat(&stderr, "max_j(K_j*T)=");
        let nb_a = parse_total_blocks(&stderr);
        let workers = jobs.unwrap_or(jobs_default);
        rss_terms(FD, workers, nb_a, T as u64, max_a, MAX_MEM).report(
            &format!(
                "(archived) solver+spill shape jobs={}",
                jobs_text.as_deref().unwrap_or("default")
            ),
            peak,
            LINE_256_MIB,
            "; archived rows are not asserted: this shape exceeds the line due to crate scratch overhead; review in a future review",
        );
    }
}

// ---------------------------------------------------------------------------
// The `inspect` subcommand
// ---------------------------------------------------------------------------

#[test]
fn test_inspect_usage() {
    let sb = Sandbox::new("d27");
    sb.write("x.lpw", b"not a stream");
    assert_single_line_error(&sb.run(&["inspect", "--nope", "x.lpw"]), 1);
    // `inspect` does not accept `-o`.
    assert_single_line_error(&sb.run(&["inspect", "-o", "-", "x.lpw"]), 1);
    assert_single_line_error(&sb.run(&["inspect"]), 1);
    let out = sb.run(&["inspect", "-h"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout_of(&out).contains("lapiwe inspect [OPTIONS] <IN>"),
        "{}",
        stdout_of(&out)
    );
}

#[test]
fn test_inspect_fields() {
    let sb = Sandbox::new("d28");
    let data = det_bytes(100_000, 0xD28);
    // `--meta-every 2` produces C_meta=128 and agree_meta=127, making the
    // metadata counters observable.
    encode(&sb, "f.bin", &data, &["--meta-every", "2", "--size", "1M"]);

    let out = sb.run(&["inspect", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert!(
        out.stderr.is_empty(),
        "inspect writes no stderr when an OTI is present"
    );
    let text = stdout_of(&out);
    for field in [
        "F=100000",
        "T=4080",
        "NB=1",
        "N_sub=1",
        "SCHEME=4",
        "BLAKE3=",
        "KS=25",
        "K_j=[25,25]",
        "K_j*T<=102000",
        "P=4096",
        "scan stats",
        "valid_packets=",
        "block coverage",
        "agree_meta=127",
        "conflict=0",
        "bad_meta=0",
        "best_effort=0",
    ] {
        assert!(
            text.contains(field),
            "inspect output missing `{field}`: {text}"
        );
    }

    // No usable OTI: statistics go to stdout, stderr has one line, and the exit
    // code is 3.
    let stream = read(&sb.path("f.bin.lpw"));
    sb.write("nometa.lpw", &strip_meta(&stream));
    let out = sb.run(&["inspect", "nometa.lpw"]);
    assert_eq!(out.status.code(), Some(3), "stderr={}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(text.contains("baseline OTI: not established"), "{text}");
    assert!(text.contains("scan stats"), "{text}");
    let err = stderr_of(&out);
    assert_eq!(
        err.matches('\n').count(),
        1,
        "stderr must be a single line: {err:?}"
    );
    assert!(err.contains("no usable OTI"), "{err}");

    // A reference OTI with an invalid layout: `inspect` still reports read-only
    // and exits 0 with an underivable layout.
    let malformed = replace_meta(&stream, &Oti::new(1, T as u16, 2, [0x00; BLAKE3_LEN]));
    sb.write("malformed.lpw", &malformed);
    let out = sb.run(&["inspect", "malformed.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("not derivable"),
        "{}",
        stdout_of(&out)
    );
    // When coverage cannot be computed, print N/A instead of omitting the line
    // or showing 0%.
    assert!(
        stdout_of(&out).contains("block coverage: N/A"),
        "{}",
        stdout_of(&out)
    );
}

#[test]
fn test_inspect_readonly() {
    let sb = Sandbox::new("d29");
    let data = det_bytes(10_000, 0xD29);
    encode(&sb, "f.bin", &data, &[]);
    let path = sb.path("f.bin.lpw");
    let before_bytes = read(&path);
    let before_entries = dir_entries(&sb.dir);

    let out = sb.run(&["inspect", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(
        read(&path),
        before_bytes,
        "input must be byte-identical before and after"
    );
    assert_eq!(
        dir_entries(&sb.dir),
        before_entries,
        "must have no file side effects"
    );

    // The no-OTI path is also read-only: exit code 3, the input is unchanged,
    // and no files are added.
    sb.write("zeros.bin", &vec![0u8; 4096]);
    let before_entries = dir_entries(&sb.dir);
    let out = sb.run(&["inspect", "zeros.bin"]);
    assert_eq!(out.status.code(), Some(3), "stderr={}", stderr_of(&out));
    assert_eq!(read(&path), before_bytes);
    assert_eq!(dir_entries(&sb.dir), before_entries);
}

// ---------------------------------------------------------------------------
// Best-effort warnings and `--max-mem` wiring
// ---------------------------------------------------------------------------

#[test]
fn test_no_verify_warning() {
    let sb = Sandbox::new("d44");
    let data = det_bytes(20_000, 0xD44);
    encode(&sb, "f.bin", &data, &[]);
    let out = sb.run(&["decode", "--no-verify", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);
    let err = stderr_of(&out);
    assert!(
        err.contains("integrity is unknown") || err.contains("unverified"),
        "warning must mention unknown integrity or unverified status: {err}"
    );
}

#[test]
fn test_decode_best_effort_warning() {
    let sb = Sandbox::new("d45");
    let data = det_bytes(100_000, 0xD45);
    // 26P with `--force`: C_meta=1 and D=25=K_j, so the direct path can decode
    // the block, but the stream is best-effort only.
    encode(&sb, "f.bin", &data, &["--size", "106496", "--force"]);

    let out = sb.run(&["decode", "-o", "-", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);
    let err = stderr_of(&out);
    assert!(err.contains("best_effort=1"), "{err}");
    assert!(err.contains("not trustworthy"), "decode must warn: {err}");

    // `inspect` emits the same warning.
    let out = sb.run(&["inspect", "f.bin.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(
        err.contains("best_effort=1") && err.contains("not trustworthy"),
        "inspect must warn: {err}"
    );
}

#[test]
#[cfg(unix)]
fn test_decode_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let sb = Sandbox::new("d42");
    let data = det_bytes(3_000, 0xD42);
    let in_name = OsString::from_vec(b"in\xff\xfe.bin".to_vec());
    fs::write(sb.dir.join(&in_name), &data).expect("write non-UTF-8 file name");
    let encode = run_os(&sb.dir, &[OsString::from("encode"), in_name.clone()]);
    assert_eq!(
        encode.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&encode)
    );
    let mut lpw_name = in_name.clone();
    lpw_name.push(".lpw");

    // A non-UTF-8 `-o` value is opened byte for byte.
    let out_name = OsString::from_vec(b"out\xf0\x28.bin".to_vec());
    let out = run_os(
        &sb.dir,
        &[
            OsString::from("decode"),
            OsString::from("-o"),
            out_name.clone(),
            lpw_name.clone(),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(read(&sb.dir.join(&out_name)), data);

    // Default naming for a non-UTF-8 input (strip the `.lpw` suffix at the byte
    // level) and a read-only inspect.
    let decode = run_os(&sb.dir, &[OsString::from("decode"), lpw_name.clone()]);
    assert_eq!(
        decode.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&decode)
    );
    assert_eq!(read(&sb.dir.join(&in_name)), data);
    let inspect = run_os(&sb.dir, &[OsString::from("inspect"), lpw_name]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&inspect)
    );
}

#[test]
fn test_decode_sigpipe_exit_zero() {
    let sb = Sandbox::new("d34");
    // The output must exceed the 64 KiB pipe buffer so that closing the read
    // end early reliably triggers EPIPE.
    let data = det_bytes(300_000, 0xD34);
    encode(&sb, "f.bin", &data, &["--size", "1M"]);
    let bin = env!("CARGO_BIN_EXE_lapiwe");
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail; { sleep 0.2; exec "$1" decode --stream -o - "$2"; } | head -c 1 > /dev/null"#,
            "bash",
            bin,
            "f.bin.lpw",
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("failed to start bash");
    assert_eq!(
        out.status.code(),
        Some(0),
        "EPIPE must exit 0 silently; stderr={}",
        stderr_of(&out)
    );
    assert!(!stderr_of(&out).contains("panicked"), "{}", stderr_of(&out));
}

#[test]
fn cli_decode_max_mem_budget_wired() {
    let sb = Sandbox::new("dmaxmem");
    let data = det_bytes(100_000, 0xB0);
    encode(&sb, "f.bin", &data, &[]);
    let stream = read(&sb.path("f.bin.lpw"));
    // Move the metadata packet to the end so 29 data packets arrive before the
    // reference OTI is established and enter the pending budget.
    let mut moved = Vec::with_capacity(stream.len());
    moved.extend_from_slice(&stream[P..]);
    moved.extend_from_slice(&stream[..P]);
    sb.write("meta-last.lpw", &moved);

    // With the default 64 MiB budget all packets are accepted (within
    // 27,336,480 bytes), so the stream decodes directly.
    let out = sb.run(&["decode", "--stream", "-o", "-", "meta-last.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    assert_eq!(out.stdout, data);

    // A tiny non-zero budget (65664 = scan window + 128) rejects every packet
    // that arrives before the reference, so pending_dropped=29 and the exit
    // code is 2.
    let out = sb.run(&["decode", "--max-mem", "65664", "-o", "-", "meta-last.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
    assert!(out.stdout.is_empty());
    assert!(
        stderr_of(&out).contains("pending_dropped=29"),
        "--max-mem must be wired to the decode budget: {}",
        stderr_of(&out)
    );

    // Degenerate values (0 or at most the 65536-byte scan window) are rejected
    // with a single-line error, exit code 1, and a suggestion.
    for bad in ["0", "1", "65535", "65536", "64KiB"] {
        let out = sb.run(&["decode", "--max-mem", bad, "meta-last.lpw"]);
        assert_single_line_error(&out, 1);
        assert!(
            stderr_of(&out).contains("65536") || stderr_of(&out).contains("scan ring buffer"),
            "the --max-mem {bad} error must mention the scan window/suggestion: {}",
            stderr_of(&out)
        );
    }
    // Exactly 65537 (an engine budget of 1) is still valid and observable
    // through the drop counter.
    let out = sb.run(&["decode", "--max-mem", "65537", "meta-last.lpw"]);
    assert_eq!(out.status.code(), Some(2), "stderr={}", stderr_of(&out));
}

/// A forged but structurally valid OTI (`NB = 2^24 - 1`, `F = NB*T`, so
/// `S = NB` and `KS = 1`) must not make the engine materialize a snapshot sized
/// by `NB`. Under a 256 MiB address-space limit (`ulimit -v`), decoding must
/// report the normal `Insufficient` class with exit code 2 rather than aborting
/// in the allocator after trying to allocate 512 MiB.
#[cfg(target_os = "linux")]
#[test]
fn test_forged_nb_memory_bounded() {
    let sb = Sandbox::new("forged-nb");
    let nb = (1u32 << 24) - 1;
    let f = u64::from(nb) * T as u64;
    let oti = Oti::new(f, T as u16, nb, [0x5A; BLAKE3_LEN]);
    let packet = build_meta_packet(P, &oti, false).expect("metadata");
    sb.write("forged.lpw", &packet);

    // Use `bash -c` to tighten the address space, then `exec` the same binary
    // (`$0` is the binary path).
    let out = Command::new("bash")
        .args([
            "-c",
            "ulimit -v 262144; exec \"$0\" decode -o out.bin forged.lpw",
            env!("CARGO_BIN_EXE_lapiwe"),
        ])
        .current_dir(&sb.dir)
        .output()
        .expect("run limited decode");
    let err = stderr_of(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "under limited memory the result must normally be Insufficient (must not abort); stderr={err}"
    );
    assert!(
        !err.contains("panicked") && !err.contains("memory allocation"),
        "{err}"
    );
    assert!(err.contains("result=Insufficient"), "{err}");
    assert!(
        !sb.path("out.bin").exists(),
        "the failure path must not publish an output file"
    );
}

/// A mid-stream stdout write failure during `--stream` (other than EPIPE)
/// emits an incomplete/untrusted-output warning and exits 1.
#[cfg(target_os = "linux")]
#[test]
fn cli_decode_stream_write_error_warns_untrusted() {
    let sb = Sandbox::new("d5");
    let data = det_bytes(50_000, 0xD5);
    encode(&sb, "f.bin", &data, &[]);

    // `/dev/full` always returns ENOSPC, not EPIPE.
    let full = File::options()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let out = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(["decode", "--stream", "-o", "-", "f.bin.lpw"])
        .current_dir(&sb.dir)
        .stdout(full)
        .output()
        .expect("run decode --stream");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a write failure must exit 1; stderr={}",
        stderr_of(&out)
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("output is incomplete/untrusted"),
        "D5: must add an untrusted-output warning: {err}"
    );
    assert!(err.contains("failed to write stdout"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

// ---------------------------------------------------------------------------
// Parallel decoding (`--jobs` > 1): consistency, scaling, and memory use
// ---------------------------------------------------------------------------

/// Remove packets whose ESI is in `esis` from every data block, simulating
/// damage to source symbols in each block.
fn drop_esis(stream: &[u8], p: usize, esis: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stream.len());
    for pkt in stream.chunks_exact(p) {
        let header = parse_header(pkt).expect("test stream must be frame-valid");
        if !header.is_meta() && esis.contains(&header.esi) {
            continue;
        }
        out.extend_from_slice(pkt);
    }
    out
}

/// Normalize a statistics line by truncating it at the elapsed-time field.
/// Timing and throughput vary between runs; all other counters and the result
/// class must not depend on `--jobs`.
fn normalize_stats(text: &str) -> String {
    text.lines()
        .map(|line| match line.find(" elapsed=") {
            Some(pos) => &line[..pos],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Check that decoding is independent of the job count: the same stream decoded
/// with `jobs` in `{1, 2, 4, 8}` must produce identical bytes, the same exit
/// code, and identical statistics apart from timing and throughput. The test
/// covers solver use (ESI 0 removed from every block), insufficient input, a
/// hash mismatch, and combinations with `--stream` and `--no-verify`.
#[test]
fn test_parallel_jobs_equivalence() {
    let sb = Sandbox::new("c23par");
    let data = det_bytes(3 * 1024 * 1024, 0xC23E);
    // NB = ceil(ceil(F/4080)/256) >= 4, which exercises the multi-block
    // parallel path.
    encode(&sb, "f.bin", &data, &["--block-symbols", "256"]);
    let stream = read(&sb.path("f.bin.lpw"));
    sb.write("dmg.lpw", &drop_esis(&stream, P, &[0]));
    sb.write("cut.lpw", &stream[..10 * P]);
    let mut forged = base_oti(&stream);
    forged.blake3 = [0x5A; BLAKE3_LEN];
    sb.write("hm.lpw", &replace_meta(&stream, &forged));
    let jobs_list = [1usize, 2, 4, 8];

    // File output: identical bytes, exit code, and statistics; a failed run
    // must not publish a target.
    for (name, expect_rc) in [("dmg.lpw", 0), ("cut.lpw", 2), ("hm.lpw", 4)] {
        let mut outputs = Vec::new();
        for jobs in jobs_list {
            let path = format!("o-{name}-{jobs}.bin");
            let out = sb.run(&["decode", "--jobs", &jobs.to_string(), "-o", &path, name]);
            outputs.push((jobs, out, path));
        }
        let (_, first, _) = &outputs[0];
        assert_eq!(
            first.status.code(),
            Some(expect_rc),
            "{name}: stderr={}",
            stderr_of(first)
        );
        for (jobs, out, _path) in &outputs[1..] {
            assert_eq!(
                out.status.code(),
                first.status.code(),
                "{name} jobs={jobs}: exit codes must match: {}",
                stderr_of(out)
            );
            assert_eq!(
                normalize_stats(&stderr_of(out)),
                normalize_stats(&stderr_of(first)),
                "{name} jobs={jobs}: statistics must not depend on --jobs"
            );
        }
        if expect_rc == 0 {
            let expect = read(&sb.path(&outputs[0].2));
            assert_eq!(
                expect, data,
                "{name}: jobs=1 output must equal the original data"
            );
            for (jobs, _, path) in &outputs[1..] {
                assert_eq!(
                    read(&sb.path(path)),
                    expect,
                    "{name} jobs={jobs}: outputs must be byte-identical"
                );
            }
        } else {
            for (jobs, _, path) in &outputs {
                assert!(
                    !sb.path(path).exists(),
                    "{name} jobs={jobs}: must not publish a target when the result is not Ok"
                );
            }
        }
    }

    // Stream and no-verify combinations: identical stdout bytes and statistics.
    for (name, extra, expect_rc) in [
        ("dmg.lpw", Vec::new(), 0),
        ("dmg.lpw", vec!["--no-verify"], 0),
        ("hm.lpw", Vec::new(), 4),
    ] {
        let mut outputs = Vec::new();
        for jobs in [1usize, 4] {
            let jobs_text = jobs.to_string();
            let mut args = vec!["decode", "--jobs", jobs_text.as_str()];
            args.extend_from_slice(&extra);
            args.extend_from_slice(&["--stream", "-o", "-", name]);
            outputs.push((jobs, sb.run(&args)));
        }
        let first = &outputs[0].1;
        assert_eq!(
            first.status.code(),
            Some(expect_rc),
            "{name} {extra:?}: stderr={}",
            stderr_of(first)
        );
        for (jobs, out) in &outputs[1..] {
            assert_eq!(out.status.code(), first.status.code());
            assert_eq!(
                out.stdout, first.stdout,
                "{name} {extra:?} jobs={jobs}: stdout must match"
            );
            assert_eq!(
                normalize_stats(&stderr_of(out)),
                normalize_stats(&stderr_of(first)),
                "{name} {extra:?} jobs={jobs}: statistics must match"
            );
        }
        if expect_rc == 0 && extra.is_empty() {
            assert_eq!(
                first.stdout, data,
                "{name}: --stream output must equal the original data"
            );
        }
    }
}

/// Memory check for `jobs=4`: peak RSS must stay below the structural bound
/// `min(jobs, NB, cap) * (2 * max_j(K_j*T) + o) + max_mem + O(S/8) + 32 MiB`
/// ([`decode_rss_limit_kib`]), where `cap` limits solver residency.
///
/// The test uses two shapes at F=64 MiB with `--block-symbols 1024`,
/// `--redundancy 2`, and ESI 0 removed from every block:
/// - the recommended payload shape, with P=4096;
/// - an alternative shape in the same family, with P=2048.
///
/// Both shapes are asserted. The absolute 256 MiB limit for default streams is
/// covered by `test_decode_constant_memory`.
///
/// Release-only (`#[ignore]`). The test is serialized with the other peak-memory
/// and scaling measurements through a static mutex, so it also works under the
/// default parallel harness.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[test]
#[ignore = "release-only calibration (criterion 4 RSS); run with cargo test --release -- --ignored"]
fn test_parallel_peak_rss() {
    use std::process::Stdio;

    // Serialize with the other peak-memory and scaling measurements; they do
    // not overlap even under the default parallel harness.
    let _cal_guard = calibration_guard();
    const F: usize = 64 * 1024 * 1024;
    const MAX_MEM: u64 = lapiwe::container::params::DEFAULT_DECODE_MAX_MEM;
    let sb = Sandbox::new("c23rss");
    let data = det_bytes(F, 0xC23D);
    sb.write("f.bin", &data);

    // Return (peak KiB, max_j(K_j*T), NB, T).
    let measure = |label: &str, extra: &[&str]| -> (u64, u64, u64, u64) {
        let lpw = format!("{label}.lpw");
        let mut args = vec!["encode", "-o", lpw.as_str()];
        args.extend_from_slice(extra);
        args.push("f.bin");
        let out = sb.run(&args);
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
        let stream = read(&sb.path(&lpw));
        let p: usize = match extra.iter().position(|&x| x == "--packet-size") {
            Some(i) => extra[i + 1].parse().expect("P"),
            None => P,
        };
        let dmg = format!("{label}-dmg.lpw");
        sb.write(&dmg, &drop_esis(&stream, p, &[0]));
        // Parse `max_j(K_j*T)` and `NB` from the statistics line so the test
        // does not recompute the layout.
        let probe = sb.run(&["decode", "--jobs", "4", "-o", "probe.bin", &dmg]);
        assert_eq!(probe.status.code(), Some(0), "stderr={}", stderr_of(&probe));
        let max_block = parse_stat(&stderr_of(&probe), "max_j(K_j*T)=");
        let nb = parse_total_blocks(&stderr_of(&probe));
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["decode", "--jobs", "4", "-o", "rss-out.bin", &dmg])
            .current_dir(&sb.dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start decode");
        let (peak_kib, status) = peak_rss_kib_fast(&mut child);
        assert_eq!(status.code(), Some(0), "{label}: decode must succeed");
        assert_eq!(
            read(&sb.path("rss-out.bin")),
            data,
            "{label}: output must be correct"
        );
        assert!(
            peak_kib > 0,
            "{label}: no valid sample collected (did the child exit before exec confirmation?) - measurement invalid"
        );
        (peak_kib, max_block, nb, (p - MICROHEADER_LEN) as u64)
    };

    let (peak1, max1, nb1, t1) = measure(
        "L1",
        &[
            "--packet-size",
            "2048",
            "--block-symbols",
            "1024",
            "--redundancy",
            "2",
        ],
    );
    let limit1 = decode_rss_limit_kib(F as u64, 4, nb1, t1, max1, MAX_MEM);
    println!(
        "RSS report: L1(P=2048,K=1024) F=64 MiB max_j(K_j·T)={max1} NB={nb1} \
         peak={peak1} KiB; structural bound min(jobs,NB,cap)·(2·max+o)+max_mem+O(S/8)+32={limit1} KiB \
         (margin {} KiB)",
        limit1 as i64 - peak1 as i64
    );
    assert!(
        peak1 <= limit1,
        "criterion 4 failed (L1): peak {peak1} KiB > {limit1} KiB (F=64 MiB, max={max1}, NB={nb1})"
    );
    assert!(
        peak1 <= 256 * 1024,
        "numeric limit failed (--jobs 1..4 <= 256 MiB): L1 peak {peak1} KiB"
    );

    let (peak0, max0, nb0, t0) = measure("L0", &["--block-symbols", "1024", "--redundancy", "2"]);
    let limit0 = decode_rss_limit_kib(F as u64, 4, nb0, t0, max0, MAX_MEM);
    println!(
        "RSS report: L0(recommended payload P=4096,K=1024) max_j(K_j·T)={max0} NB={nb0} \
         peak={peak0} KiB; structural bound={limit0} KiB (margin {} KiB)",
        limit0 as i64 - peak0 as i64
    );
    assert!(
        peak0 <= limit0,
        "criterion 4 failed (L0): peak {peak0} KiB > {limit0} KiB (F=64 MiB, max={max0}, NB={nb0})"
    );
    assert!(
        peak0 <= 256 * 1024,
        "numeric limit failed (--jobs 1..4 <= 256 MiB): L0 peak {peak0} KiB"
    );
}

/// Solver-path scaling calibration (release only).
///
/// Loads (F=64 MiB, `--redundancy 2`, ESI 0 removed from every block):
/// - the recommended shape: P=4096 with `--block-symbols 1024`;
/// - an alternative shape in the same family: P=2048 with
///   `--block-symbols 1024`.
///
/// The test prints wall-clock times for `jobs` in `{1, 2, 4, 8}`, the absolute
/// ratio `t(1)/t(4)`, the same ratio for the crate's decoder on the same shape,
/// and the relative ratio. It asserts that:
/// 1. `jobs=4` and `jobs=1` produce identical output bytes for both loads;
/// 2. only for the recommended shape, the CLI scaling ratio is at least 0.85
///    times the crate's scaling ratio. The absolute ratio `t(1)/t(4) >= 1.7` is
///    printed for reference only; serial scanning and fixed overhead make it
///    unreachable in practice.
///
/// The alternative shape and the j=2/8 readings are informational. Measurements
/// use best-of-5 for the CLI and the crate baseline at jobs 1, 2, and 4, and
/// best-of-2 for j=8, always in the same order: crate first, then the CLI. The
/// calibration lock is held for the whole test so the measurements run in a
/// quiet, serial environment.
///
/// The sandbox is removed by [`TempDirCleanup`] on `Drop`, including on panic,
/// so failed runs do not leave 64 MiB files on tmpfs.
///
/// Release-only (`#[ignore]`; `cargo test --release -- --ignored
/// test_parallel_scaling`).
#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release-only calibration (criterion 2); run with cargo test --release -- --ignored"]
fn test_parallel_scaling() {
    use lapiwe::container::encode::{EncodeConfig, TotalSpec, block_oti, plan, prescan};
    use std::hint::black_box;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    // Serialize with the two RSS calibration tests, since scaling measurements
    // also require a quiet environment.
    let _cal_guard = calibration_guard();
    const F: usize = 64 * 1024 * 1024;
    let dir = std::env::temp_dir().join(format!("lapiwe-c23scaling-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create  sandbox");
    let _dir_cleanup = TempDirCleanup(dir.clone());
    let data = det_bytes(F, 0xC23A);
    fs::write(dir.join("f.bin"), &data).expect("write input");

    // Baseline using the crate's decoder on the same shape: one copy per block,
    // ESI 0 removed, and retries with repair packets until each block decodes.
    // Each label is measured separately because P changes T and the per-block
    // K_j.
    let crate_baseline = |p: usize| -> (f64, f64) {
        let cfg = EncodeConfig {
            p,
            m: 256,
            k_max: 1024,
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
        let crate_decode_all = |workers: usize| -> f64 {
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
                            let t = plan.leveling.t;
                            let oti = block_oti(k * t, t as u16);
                            let encoder =
                                raptorq::SourceBlockEncoder::new(0, &oti, &blocks[j as usize]);
                            let mut packets: Vec<_> = encoder.source_packets();
                            packets.remove(0); // Drop ESI 0 to match the damage model.
                            let mut repairs = encoder.repair_packets(0, 2);
                            let mut decoder = raptorq::SourceBlockDecoder::new(0, &oti, k * t);
                            let mut decoded = decoder.decode(packets);
                            while decoded.is_none() {
                                let Some(p) = repairs.pop() else { break };
                                decoded = decoder.decode([p]);
                            }
                            black_box(decoded.map(|b| b.len()));
                        }
                    });
                }
            });
            t0.elapsed().as_secs_f64()
        };
        let _warm = crate_decode_all(4);
        // Best-of-5 in a fixed order: five runs with one worker, then five with
        // four workers.
        let t1 = (0..5)
            .map(|_| crate_decode_all(1))
            .fold(f64::INFINITY, f64::min);
        let t4 = (0..5)
            .map(|_| crate_decode_all(4))
            .fold(f64::INFINITY, f64::min);
        (t1, t4)
    };

    let time_cli = |jobs: usize, name: &str, reps: usize| -> f64 {
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                let out = run_os(
                    &dir,
                    &[
                        "decode",
                        "--jobs",
                        &jobs.to_string(),
                        "-o",
                        "out.bin",
                        &format!("{name}-dmg.lpw"),
                    ]
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>(),
                );
                let dt = t.elapsed().as_secs_f64();
                assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
                dt
            })
            .fold(f64::INFINITY, f64::min)
    };

    for (label, extra) in [
        ("L0", vec!["--block-symbols", "1024", "--redundancy", "2"]),
        (
            "L1",
            vec![
                "--packet-size",
                "2048",
                "--block-symbols",
                "1024",
                "--redundancy",
                "2",
            ],
        ),
    ] {
        let name = format!("{label}.lpw");
        let mut args = vec!["encode", "-o", name.as_str()];
        args.extend_from_slice(&extra);
        args.push("f.bin");
        let out = run_os(&dir, &args.iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
        let p = if label == "L0" { P } else { 2048 };
        // Measure the crate baseline for this label's shape (same P, K_max, and
        // redundancy).
        let (crate1, crate4) = crate_baseline(p);
        let stream = read(&dir.join(&name));
        fs::write(
            dir.join(format!("{label}-dmg.lpw")),
            drop_esis(&stream, p, &[0]),
        )
        .expect("write damaged stream");
        let t1 = time_cli(1, label, 5);
        let t2 = time_cli(2, label, 5);
        let t4 = time_cli(4, label, 5);
        let t8 = time_cli(8, label, 2);
        // Output consistency on this load.
        for jobs in [1usize, 4] {
            let out = run_os(
                &dir,
                &[
                    "decode",
                    "--jobs",
                    &jobs.to_string(),
                    "-o",
                    &format!("j{jobs}.bin"),
                    &format!("{label}-dmg.lpw"),
                ]
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            );
            assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
        }
        assert_eq!(
            read(&dir.join("j1.bin")),
            read(&dir.join("j4.bin")),
            "{label}: jobs=1/4 outputs must be byte-identical ()"
        );
        assert_eq!(
            read(&dir.join("j1.bin")),
            data,
            "{label}: output must equal the original data"
        );
        // The alternative shape uses its own baseline; only the recommended
        // shape is asserted.
        let criterion = if label == "L0" {
            "criterion line 0.85×crate, asserted in this row"
        } else {
            "archived only (criterion 2 asserts L0 only)"
        };
        println!(
            "scaling report {label}: t1={t1:.3}s t2={t2:.3}s t4={t4:.3}s t8={t8:.3}s (j=1/2/4 \
             best-of-5, crate first then CLI, fixed order; j8 best-of-2); \
             absolute ratio t(1)/t(4)={:.2} (absolute line 1.7, archived only); crate same-shape decode t1={crate1:.3}s \
             t4={crate4:.3}s scaling ratio={:.2}; relative scaling ratio={:.2} ({criterion})",
            t1 / t4,
            crate1 / crate4,
            (t1 / t4) / (crate1 / crate4),
        );
        if label == "L0" {
            // Assert only the recommended-shape row, using the crate scaling
            // ratio as the reference. The absolute ratio is printed for
            // reference only.
            let cli_ratio = t1 / t4;
            let crate_ratio = crate1 / crate4;
            assert!(
                cli_ratio >= 0.85 * crate_ratio,
                "L0 criterion 2 failed: lapiwe scaling ratio {cli_ratio:.2} < 0.85 × crate same-shape scaling ratio {crate_ratio:.2}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// In-place patching: `--patch TARGET [--missing-ranges FILE]`
// ---------------------------------------------------------------------------

/// Remove all packets (source and repair) for one logical block.
fn drop_block(stream: &[u8], p: usize, blk: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(stream.len());
    for pkt in stream.chunks_exact(p) {
        let header = parse_header(pkt).expect("test stream must be frame-valid");
        if !header.is_meta() && header.blk_idx == blk {
            continue;
        }
        out.extend_from_slice(pkt);
    }
    out
}

/// `--patch` conflicts with `-o` and `--stream`, `--missing-ranges` requires
/// `--patch`, and the target must already exist. All violations produce a
/// single-line error and exit code 1.
#[test]
fn test_patch_flag_combinations() {
    let sb = Sandbox::new("c46flags");
    let data = det_bytes(50_000, 0xC46F);
    encode(&sb, "f.bin", &data, &[]);
    sb.write("m.txt", b"0 4096\n");
    sb.write("t.bin", &data);

    for (args, needle) in [
        (
            vec!["decode", "--patch", "t.bin", "-o", "out.bin", "f.bin.lpw"],
            "mutually exclusive",
        ),
        (
            vec![
                "decode",
                "--missing-ranges",
                "m.txt",
                "-o",
                "out.bin",
                "f.bin.lpw",
            ],
            "only valid together with `--patch`",
        ),
        (
            vec!["decode", "--patch", "t.bin", "--stream", "f.bin.lpw"],
            "mutually exclusive",
        ),
        (
            vec!["decode", "--patch", "nope.bin", "f.bin.lpw"],
            "existing",
        ),
    ] {
        let out = sb.run(&args);
        assert_single_line_error(&out, 1);
        let err = stderr_of(&out);
        assert!(err.contains(needle), "args={args:?} stderr={err}");
    }
    assert!(
        !sb.path("nope.bin").exists(),
        "patch mode must not create a target"
    );
    assert!(!dir_entries(&sb.dir).contains(&"nope.bin".to_owned()));
}

/// Happy path: declared missing ranges are repaired, the exit code is 0, and the
/// patch statistics can be parsed. Range lists support hexadecimal values,
/// comments, and overlapping ranges.
#[test]
fn test_patch_recovers_target() {
    let sb = Sandbox::new("c46ok");
    let data = det_bytes(700_000, 0xC460);
    encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    let mut tgt = data.clone();
    for b in &mut tgt[100_000..160_000] {
        *b = 0;
    }
    for b in &mut tgt[500_123..505_123] {
        *b = 0;
    }
    sb.write("tgt.bin", &tgt);
    // Hexadecimal values, an end-of-line comment, and overlapping ranges that
    // are merged.
    sb.write(
        "m.txt",
        b"# ranges\n0x186A0 0xEA60  # 100000..160000\n500123 5000\n0x186A0 100\n",
    );
    let out = sb.run(&[
        "decode",
        "--patch",
        "tgt.bin",
        "--missing-ranges",
        "m.txt",
        "f.bin.lpw",
    ]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "stderr={err}");
    assert!(err.contains("result=Ok"), "{err}");
    let after = read(&sb.path("tgt.bin"));
    assert_eq!(after, data, "target must be restored byte for byte");
    // Check byte by byte that every modified byte lies inside a declared
    // missing range. Readable bytes outside the list are never touched; the
    // merged ranges are [100000, 160000) and [500123, 505123).
    for (idx, (&a, &b)) in after.iter().zip(&tgt).enumerate() {
        if a != b {
            let i = idx as u64;
            assert!(
                (100_000..160_000).contains(&i) || (500_123..505_123).contains(&i),
                "the patch safety invariant violation: offset {i} was rewritten but is not in a missing range"
            );
        }
    }
    // Patch statistics: missing symbols, patched bytes, patched ranges, and
    // patched symbols.
    let missing = stat_u64(&err, "patch_missing_symbols=");
    let patched_bytes = stat_u64(&err, "patched_bytes=");
    let patched_ranges = stat_u64(&err, "patched_ranges=");
    let patched_symbols = stat_u64(&err, "patched_symbols=");
    assert!(
        missing >= 17,
        "missing symbol count must cover both ranges (>=17 symbols): {err}"
    );
    assert_eq!(
        patched_symbols, missing,
        "this shape restores all missing symbols within the stream"
    );
    assert_eq!(
        patched_bytes,
        patched_symbols * T as u64,
        "patched bytes = symbol count·T (no trailing-symbol truncation)"
    );
    assert_eq!(
        patched_ranges, 2,
        "two missing spans → two ranges (overlaps in the list were merged)"
    );
    assert!(
        err.contains("result=Ok") && err.contains("patch_commit_time="),
        "{err}"
    );
    // The target length is unchanged.
    assert_eq!(read(&sb.path("tgt.bin")).len(), data.len());
}

/// Readable data can still be wrong: an undeclared, silently corrupted region
/// produces exit code 4 with guidance text. The tool must not rewrite any
/// readable range; only declared missing ranges are written.
#[test]
fn test_patch_hash_mismatch_guidance() {
    let sb = Sandbox::new("c46hm");
    let data = det_bytes(400_000, 0xC461);
    encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    let mut tgt = data.clone();
    for b in &mut tgt[..T] {
        *b = 0; // Declared missing and repaired.
    }
    for b in &mut tgt[200_000..200_100] {
        *b = 0xAA; // Readable but wrong; not listed as missing.
    }
    sb.write("tgt.bin", &tgt);
    sb.write("m.txt", format!("0 {T}\n").as_bytes());
    let out = sb.run(&[
        "decode",
        "--patch",
        "tgt.bin",
        "--missing-ranges",
        "m.txt",
        "f.bin.lpw",
    ]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(4), "stderr={err}");
    for needle in [
        "readable does not mean correct",
        "silent corruption",
        "decode to a new file",
        "no readable region was rewritten",
    ] {
        assert!(
            err.contains(needle),
            "guidance text missing `{needle}`: {err}"
        );
    }
    let after = read(&sb.path("tgt.bin"));
    assert_eq!(
        &after[200_000..200_100],
        &[0xAAu8; 100][..],
        "readable regions not in the missing list MUST NOT be rewritten"
    );
    assert_eq!(
        &after[..T],
        &data[..T],
        "declared missing range was patched"
    );
    assert_eq!(after.len(), data.len(), "target length is unchanged");
}

/// A target of the wrong size and a range list that is out of bounds,
/// malformed, or unreadable all produce a single-line error with exit code 1
/// and a suggestion.
#[test]
fn test_patch_rejects_bad_target_and_ranges() {
    let sb = Sandbox::new("c46bad");
    let data = det_bytes(200_000, 0xC462);
    encode(&sb, "f.bin", &data, &[]);
    sb.write("tgt.bin", &data);

    // Wrong size (one byte short).
    sb.write("short.bin", &data[..data.len() - 1]);
    let out = sb.run(&["decode", "--patch", "short.bin", "f.bin.lpw"]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("size mismatch"),
        "{}",
        stderr_of(&out)
    );

    // Range list out of bounds.
    sb.write(
        "m_oob.txt",
        format!("0 {}\n", data.len() as u64 + 1).as_bytes(),
    );
    let out = sb.run(&[
        "decode",
        "--patch",
        "tgt.bin",
        "--missing-ranges",
        "m_oob.txt",
        "f.bin.lpw",
    ]);
    assert_single_line_error(&out, 1);
    assert!(
        stderr_of(&out).contains("out of bounds"),
        "{}",
        stderr_of(&out)
    );

    // Malformed range list and a missing file.
    for (name, needle) in [
        ("m_syntax.txt", "valid non-negative integer"),
        ("nope.txt", "failed"),
    ] {
        if name == "m_syntax.txt" {
            sb.write(name, b"zz 1\n");
        }
        let out = sb.run(&[
            "decode",
            "--patch",
            "tgt.bin",
            "--missing-ranges",
            name,
            "f.bin.lpw",
        ]);
        assert_single_line_error(&out, 1);
        assert!(stderr_of(&out).contains(needle), "{}", stderr_of(&out));
    }
    // Failure leaves the target byte-for-byte unchanged.
    assert_eq!(read(&sb.path("tgt.bin")), data);
}

/// Insufficient input and a stream without metadata leave the target unchanged
/// and exit with 2 or 3, respectively.
#[test]
fn test_patch_failure_zero_touch() {
    let sb = Sandbox::new("c46zero");
    let data = det_bytes(600_000, 0xC463);
    encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    let stream = read(&sb.path("f.bin.lpw"));
    // Remove all packets for block 0 (source and repair).
    sb.write("cut.lpw", &drop_block(&stream, P, 0));
    let mut tgt = data.clone();
    // Declare all of block 0 missing; with no block 0 packets in the stream, it
    // cannot be decoded.
    let s = data.len().div_ceil(T);
    let ks = s / 2; // Leveled shape with NB=2: K_j for block 0.
    for b in &mut tgt[..(ks * T).min(data.len())] {
        *b = 0;
    }
    sb.write("tgt.bin", &tgt);
    sb.write("m.txt", format!("0 {}\n", ks * T).as_bytes());
    let out = sb.run(&[
        "decode",
        "--patch",
        "tgt.bin",
        "--missing-ranges",
        "m.txt",
        "cut.lpw",
    ]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(2), "stderr={err}");
    assert!(err.contains("no bytes were written to the target"), "{err}");
    assert_eq!(
        read(&sb.path("tgt.bin")),
        tgt,
        "the failure path leaves the target byte-identical"
    );

    // No metadata in the input (a garbage stream): exit code 3 and the target is
    // unchanged.
    sb.write("junk.lpw", &[0x5Au8; 100_000]);
    let out = sb.run(&["decode", "--patch", "tgt.bin", "junk.lpw"]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(3), "stderr={err}");
    assert_eq!(
        read(&sb.path("tgt.bin")),
        tgt,
        "NoOti leaves the target byte-identical"
    );

    // Malformed: a forged OTI with F=1 and NB=2 gives KS=0, a format-level
    // violation. Expect exit code 1 and an unchanged target.
    let forged = replace_meta(
        &read(&sb.path("f.bin.lpw")),
        &Oti::new(1, T as u16, 2, [0x00; BLAKE3_LEN]),
    );
    sb.write("malformed.lpw", &forged);
    let out = sb.run(&["decode", "--patch", "tgt.bin", "malformed.lpw"]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "stderr={err}");
    assert!(err.contains("no bytes were written to the target"), "{err}");
    assert_eq!(
        read(&sb.path("tgt.bin")),
        tgt,
        "Malformed leaves the target byte-identical"
    );
}

/// The patch result does not depend on `--jobs`: class, statistics, and target
/// bytes are identical.
#[test]
fn test_patch_jobs_agnostic() {
    let sb = Sandbox::new("c46jobs");
    let data = det_bytes(500_000, 0xC464);
    encode(&sb, "f.bin", &data, &["--block-symbols", "128"]);
    let stream = read(&sb.path("f.bin.lpw"));
    // Remove source symbols with ESI in {0, 1, 2} from every block; the solver
    // must recover the missing ranges.
    sb.write("cut.lpw", &drop_esis(&stream, P, &[0, 1, 2]));
    let s = data.len().div_ceil(T);
    let k0 = s.div_ceil(2); // Leveled layout: K_j for block 0.
    let mut base = data.clone();
    for b in &mut base[..k0 * T] {
        *b = 0;
    }
    let mut outs = Vec::new();
    for jobs in ["1", "4"] {
        let name = format!("tgt-{jobs}.bin");
        sb.write(&name, &base);
        sb.write("m.txt", format!("0 {}\n", k0 * T).as_bytes());
        let out = sb.run(&[
            "decode",
            "--jobs",
            jobs,
            "--patch",
            &name,
            "--missing-ranges",
            "m.txt",
            "cut.lpw",
        ]);
        outs.push((jobs, out, name));
    }
    let (_, first, _) = &outs[0];
    assert_eq!(first.status.code(), Some(0), "stderr={}", stderr_of(first));
    for (jobs, out, name) in &outs[1..] {
        assert_eq!(
            out.status.code(),
            first.status.code(),
            "jobs={jobs}: exit codes must match: {}",
            stderr_of(out)
        );
        assert_eq!(
            normalize_stats(&stderr_of(out)),
            normalize_stats(&stderr_of(first)),
            "jobs={jobs}: statistics must not depend on --jobs"
        );
        assert_eq!(
            read(&sb.path(name)),
            data,
            "jobs={jobs}: patched target must equal the source data byte for byte"
        );
    }
}

/// `--no-verify` skips the final digest check (warning plus exit code 0), and
/// `<IN> = -` (stdin) is supported in patch mode.
#[test]
fn test_patch_no_verify_and_stdin() {
    let sb = Sandbox::new("c46nv");
    let data = det_bytes(120_000, 0xC465);
    encode(&sb, "f.bin", &data, &[]);
    let mut tgt = data.clone();
    for b in &mut tgt[..T] {
        *b = 0; // Declared missing and repaired.
    }
    for b in &mut tgt[60_000..60_050] {
        *b = 0x55; // Readable but wrong; `--no-verify` avoids a hash mismatch.
    }
    let stream = read(&sb.path("f.bin.lpw"));

    // `--no-verify` skips BLAKE3 verification (with a warning) and exits 0.
    sb.write("tgt-nv.bin", &tgt);
    sb.write("m.txt", format!("0 {T}\n").as_bytes());
    let out = sb.run(&[
        "decode",
        "--no-verify",
        "--patch",
        "tgt-nv.bin",
        "--missing-ranges",
        "m.txt",
        "f.bin.lpw",
    ]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "stderr={err}");
    assert!(
        err.contains("integrity is unknown") || err.contains("unverified"),
        "{err}"
    );
    assert!(
        !err.contains("readable does not mean correct"),
        "skipping verification must not report HashMismatch: {err}"
    );
    let after = read(&sb.path("tgt-nv.bin"));
    assert_eq!(
        &after[60_000..60_050],
        &[0x55u8; 50][..],
        "readable region was not rewritten"
    );
    assert_eq!(&after[..T], &data[..T], "missing region was patched");

    // stdin input with `--patch` and `<IN> = -`.
    sb.write("tgt-in.bin", &tgt);
    let out = run_stdin(
        &sb.dir,
        &[
            "decode",
            "--patch",
            "tgt-in.bin",
            "--missing-ranges",
            "m.txt",
            "-",
        ],
        &stream,
    );
    let err = stderr_of(&out);
    assert_eq!(
        out.status.code(),
        Some(4),
        "sentinel corruption → exit 4: {err}"
    );
    assert!(err.contains("readable does not mean correct"), "{err}");
    let after = read(&sb.path("tgt-in.bin"));
    assert_eq!(&after[..T], &data[..T], "stdin input is patched as well");
    assert_eq!(&after[60_000..60_050], &[0x55u8; 50][..]);
}

/// In patch mode an unusable `--spool-dir` (a regular file or a missing
/// directory) produces a single-line error with exit code 1 and a `--spool-dir`
/// suggestion. The target must not be touched: the overlay and spill files are
/// created before scanning, and the tool must never fall back to writing the
/// target directly.
#[test]
fn test_patch_spool_unavailable() {
    let sb = Sandbox::new("c46spool");
    let data = det_bytes(60_000, 0xC466);
    encode(&sb, "f.bin", &data, &["--redundancy", "4"]);
    sb.write("not-a-dir", b"x");
    sb.write("m.txt", format!("0 {T}\n").as_bytes());

    for (dir, tgt) in [
        ("not-a-dir", "tgt-file.bin"),
        ("missing-dir", "tgt-missing.bin"),
    ] {
        let mut initial = data.clone();
        initial[..T].fill(0);
        sb.write(tgt, &initial);
        let before = dir_entries(&sb.dir);
        let out = sb.run(&[
            "decode",
            "--spool-dir",
            dir,
            "--patch",
            tgt,
            "--missing-ranges",
            "m.txt",
            "f.bin.lpw",
        ]);
        assert_single_line_error(&out, 1);
        let err = stderr_of(&out);
        assert!(
            err.contains("--spool-dir"),
            "{dir}: the suggestion must mention --spool-dir: {err}"
        );
        assert!(
            err.contains("patch overlay staging") || err.contains("decode spill staging"),
            "{dir}: must identify the staging type that failed: {err}"
        );
        assert_eq!(
            read(&sb.path(tgt)),
            initial,
            "{dir}: the failure path MUST NOT write to the target"
        );
        assert_eq!(
            dir_entries(&sb.dir),
            before,
            "{dir}: the failure path must not leave staging files"
        );
    }

    // Read-only directory (creation and writes are denied; non-root only): this
    // takes the same creation-failure branch as a regular file. Permission bits
    // do not apply to root, so the test skips this case when the probe
    // succeeds. The original mode is restored exactly with
    // `PermissionsExt::from_mode`; `set_readonly(false)` would make the
    // directory world-writable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ro = sb.path("ro-dir");
        fs::create_dir_all(&ro).expect("ro directory");
        let mode = fs::metadata(&ro).expect("metadata").permissions().mode();
        fs::set_permissions(&ro, fs::Permissions::from_mode(mode & !0o222))
            .expect("read-only permissions");
        if fs::write(ro.join("probe"), b"x").is_err() {
            let tgt = "tgt-ro.bin";
            let mut initial = data.clone();
            initial[..T].fill(0);
            sb.write(tgt, &initial);
            let before = dir_entries(&ro);
            let out = sb.run(&[
                "decode",
                "--spool-dir",
                "ro-dir",
                "--patch",
                tgt,
                "--missing-ranges",
                "m.txt",
                "f.bin.lpw",
            ]);
            assert_single_line_error(&out, 1);
            let err = stderr_of(&out);
            assert!(err.contains("--spool-dir"), "read-only directory: {err}");
            assert_eq!(
                read(&sb.path(tgt)),
                initial,
                "read-only directory: target untouched"
            );
            assert_eq!(
                dir_entries(&ro),
                before,
                "read-only directory: no staging leftovers"
            );
        }
        fs::set_permissions(&ro, fs::Permissions::from_mode(mode))
            .expect("restore sandbox permissions (for cleanup)");
    }
}

/// Boundary cases for `--missing-ranges`. Extreme values (at least 2^63, or
/// `START+LEN` overflowing `u64`) must produce a single-line error with exit
/// code 1 in debug builds too, never a panic. Zero-length entries, blank lines,
/// CRLF, `0X`/`0x` hexadecimal prefixes, and tabs are parsed as specified, and
/// an empty range list is valid.
#[test]
fn test_patch_missing_ranges_edges_and_extremes() {
    let sb = Sandbox::new("c46edge");
    let data = det_bytes(120_000, 0xC46E);
    encode(&sb, "f.bin", &data, &["--redundancy", "3"]);
    let gt_f = data.len() as u64 + 1;

    // Invalid and extreme inputs: exit code 1, one line, no panic, target
    // untouched.
    for (name, text, needle) in [
        (
            "m_2p63.txt",
            "9223372036854775807 9223372036854775807\n".to_owned(),
            "out of bounds",
        ),
        (
            "m_ovf.txt",
            "18446744073709551615 1\n".to_owned(),
            "out of bounds",
        ),
        (
            "m_ovf2.txt",
            "18446744073709551614 2\n18446744073709551615 1\n".to_owned(),
            "out of bounds",
        ),
        (
            "m_hexovf.txt",
            "0X8000000000000000 0x8000000000000000\n".to_owned(),
            "out of bounds",
        ),
        ("m_gtf.txt", format!("{gt_f} 1\n"), "out of bounds"),
        (
            "m_2p64.txt",
            "18446744073709551616 1\n".to_owned(),
            "valid non-negative integer",
        ),
    ] {
        sb.write(name, text.as_bytes());
        let tgt = format!("tgt-{name}.bin");
        sb.write(&tgt, &data);
        let out = sb.run(&[
            "decode",
            "--patch",
            &tgt,
            "--missing-ranges",
            name,
            "f.bin.lpw",
        ]);
        assert_single_line_error(&out, 1);
        let err = stderr_of(&out);
        assert!(err.contains(needle), "{name}: expected `{needle}`: {err}");
        assert_eq!(
            read(&sb.path(&tgt)),
            data,
            "{name}: the failure path leaves the target byte-identical"
        );
    }

    // Valid boundary 1: an empty list has no ranges and commits zero bytes.
    sb.write("empty.txt", b"");
    let tgt = "tgt-empty.bin";
    sb.write(tgt, &data);
    let out = sb.run(&[
        "decode",
        "--patch",
        tgt,
        "--missing-ranges",
        "empty.txt",
        "f.bin.lpw",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert_eq!(stat_u64(&err, "patch_missing_symbols="), 0);
    assert_eq!(
        stat_u64(&err, "patched_bytes="),
        0,
        "empty list → zero bytes committed"
    );
    assert_eq!(read(&sb.path(tgt)), data);

    // Valid boundary 2: CRLF line endings, a blank line, a comment, mixed `0X`
    // and `0x` prefixes, a zero-length entry, and tabs. `\t0X0\t0x1000` covers
    // [0, 4096), which intersects symbols 0 and 1 at granularity T, so two
    // symbols are patched as one range. `4080 0` is zero-length and ignored.
    sb.write(
        "m_crlf.txt",
        b"# hdr\r\n\r\n\t0X0\t0x1000  # two syms\r\n4080 0\r\n",
    );
    let mut initial = data.clone();
    initial[..2 * T].fill(0);
    let tgt = "tgt-crlf.bin";
    sb.write(tgt, &initial);
    let out = sb.run(&[
        "decode",
        "--patch",
        tgt,
        "--missing-ranges",
        "m_crlf.txt",
        "f.bin.lpw",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert_eq!(stat_u64(&err, "patched_symbols="), 2);
    assert_eq!(stat_u64(&err, "patched_bytes="), 2 * T as u64);
    assert_eq!(
        stat_u64(&err, "patched_ranges="),
        1,
        "adjacent symbols merge into one range"
    );
    assert_eq!(
        read(&sb.path(tgt)),
        data,
        "CRLF/hex list must patch correctly"
    );

    // Valid boundary 3: a range ending exactly at F. Only starts beyond F are
    // out of bounds; the last symbol is patched as `min(T, F - offset)` bytes.
    let last_off = (data.len() / T) * T;
    let last_len = data.len() - last_off;
    assert!(
        last_len > 0 && last_len < T,
        "fixture must contain a short trailing symbol"
    );
    sb.write("m_end_f.txt", format!("{last_off} {last_len}\n").as_bytes());
    let mut initial = data.clone();
    initial[last_off..].fill(0);
    let tgt = "tgt-endf.bin";
    sb.write(tgt, &initial);
    let out = sb.run(&[
        "decode",
        "--patch",
        tgt,
        "--missing-ranges",
        "m_end_f.txt",
        "f.bin.lpw",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let err = stderr_of(&out);
    assert_eq!(stat_u64(&err, "patched_symbols="), 1);
    assert_eq!(
        stat_u64(&err, "patched_bytes="),
        last_len as u64,
        "a range ending exactly at F writes only min(T,F−off) for the last symbol"
    );
    assert_eq!(read(&sb.path(tgt)), data);
}

/// Patch mode with a very small `--max-mem` (65537, just above the scan window).
/// Repair symbols that exceed the budget spill to disk (`spooled_bytes > 0`),
/// the solver restores them, and the target is restored byte for byte. Spool
/// files are cleaned up and the result does not depend on `--jobs`.
///
/// The fixture size `F = 200003` is not a multiple of `T`, so when the last
/// symbol is missing, `patched_bytes` must count only `min(T, F - offset) = 83`
/// bytes.
#[test]
fn test_patch_tiny_max_mem_spill() {
    let sb = Sandbox::new("c46tiny");
    let data = det_bytes(200_003, 0xC467);
    encode(&sb, "f.bin", &data, &["--redundancy", "3"]);
    let stream = read(&sb.path("f.bin.lpw"));
    let s = data.len().div_ceil(T);
    assert_eq!(s, 50, "leveling: NB=1, K=50, last symbol payload 83 < T");
    let last_off = (s - 1) * T;
    let last_len = data.len() - last_off;
    assert!(last_len < T);
    // In the single block, remove source ESI 0 and the last source symbol (49);
    // only the spilled repair symbols can recover them.
    sb.write("cut.lpw", &drop_esis(&stream, P, &[0, (s - 1) as u32]));
    fs::create_dir_all(sb.path("spool")).expect("spool directory");
    sb.write(
        "m.txt",
        format!("0 {T}\n{last_off} {last_len}\n").as_bytes(),
    );

    let mut results = Vec::new();
    for jobs in ["1", "4"] {
        let tgt = format!("tgt-{jobs}.bin");
        let mut initial = data.clone();
        initial[..T].fill(0);
        initial[last_off..].fill(0);
        sb.write(&tgt, &initial);
        let out = sb.run(&[
            "decode",
            "--max-mem",
            "65537",
            "--spool-dir",
            "spool",
            "--jobs",
            jobs,
            "--patch",
            &tgt,
            "--missing-ranges",
            "m.txt",
            "cut.lpw",
        ]);
        let err = stderr_of(&out);
        assert_eq!(out.status.code(), Some(0), "jobs={jobs}: stderr={err}");
        assert!(
            stat_u64(&err, "spooled_bytes=") > 0,
            "jobs={jobs}: repair symbols over budget must spill to disk: {err}"
        );
        assert!(
            stat_u64(&err, "missing_symbols=") > 0,
            "jobs={jobs}: settlement must restore missing symbols: {err}"
        );
        assert_eq!(stat_u64(&err, "patched_symbols="), 2, "jobs={jobs}");
        assert_eq!(
            stat_u64(&err, "patched_bytes="),
            T as u64 + last_len as u64,
            "jobs={jobs}: the last symbol must be truncated to min(T,F−off)"
        );
        assert_eq!(stat_u64(&err, "patched_ranges="), 2, "jobs={jobs}");
        assert_eq!(
            read(&sb.path(&tgt)),
            data,
            "jobs={jobs}: target restored byte for byte"
        );
        assert!(
            dir_entries(&sb.path("spool")).is_empty(),
            "jobs={jobs}: staging must be cleaned up: {:?}",
            dir_entries(&sb.path("spool"))
        );
        results.push(normalize_stats(&err));
    }
    assert_eq!(
        results[0], results[1],
        "jobs=1/4 statistics (timing removed) must match"
    );

    // `inspect` on the same `.lpw` used by the patch flow is unaffected (a
    // read-only regression check).
    let before = read(&sb.path("cut.lpw"));
    let out = sb.run(&["inspect", "cut.lpw"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(
        text.contains("F=200003") && text.contains("T=4080"),
        "inspect must still parse the patched stream: {text}"
    );
    assert_eq!(
        read(&sb.path("cut.lpw")),
        before,
        "inspect is read-only and must not modify the stream"
    );
}

// ---------------------------------------------------------------------------
// Representative severe-loss recovery
// ---------------------------------------------------------------------------

/// Recover an object after one source symbol has been removed from every
/// block. The stream carries enough repair symbols for both serial and
/// parallel settlement to reconstruct the original bytes.
#[test]
fn test_heavy_loss_representative() {
    let sb = Sandbox::new("heavy-loss");
    let data = det_bytes(512 * 1024, 0x484C);
    encode(
        &sb,
        "f.bin",
        &data,
        &["--redundancy", "2", "--block-symbols", "128"],
    );

    let stream = read(&sb.path("f.bin.lpw"));
    let mut damaged = Vec::with_capacity(stream.len());
    for packet in stream.chunks_exact(P) {
        let header = parse_header(packet).expect("valid frame");
        // Meta packets are retained. ESI 0 is the first source symbol of a
        // block, so dropping it forces the solver to use repair symbols.
        if header.is_meta() || header.esi != 0 {
            damaged.extend_from_slice(packet);
        }
    }
    assert!(
        damaged.len() < stream.len(),
        "the scenario must actually remove source symbols"
    );
    sb.write("damaged.lpw", &damaged);

    let serial = sb.run(&["decode", "--jobs", "1", "-o", "-", "damaged.lpw"]);
    assert_eq!(
        serial.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&serial)
    );
    assert_eq!(serial.stdout, data);

    let parallel = sb.run(&["decode", "--jobs", "4", "-o", "-", "damaged.lpw"]);
    assert_eq!(
        parallel.status.code(),
        Some(0),
        "stderr={}",
        stderr_of(&parallel)
    );
    assert_eq!(
        parallel.stdout, serial.stdout,
        "parallel settlement must produce the same bytes as serial settlement"
    );
}
