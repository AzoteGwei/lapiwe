//! `lapiwe decode` command wiring.
//!
//! The decode pipeline:
//!
//! 1. If `<IN>` is `-`, scan stdin directly (the scanner is not seekable, so no
//!    spooling is required); otherwise open the input file as-is, byte for byte.
//! 2. Output backend:
//!    - File output: a publish temporary file in the target directory is wrapped
//!      in a [`FileStore`], and the engine **writes source symbols through** to
//!      it. After settling, only the missing ranges are backfilled. Once every
//!      block is solved, the file is truncated to `F` and read back in chunks for
//!      BLAKE3 verification (`--no-verify` skips this); on success it is
//!      `sync_all`ed and atomically `rename`d into place. Any non-`Ok` result
//!      leaves the target absent and removes the temporary file via RAII (see
//!      [`super::temp`]).
//!    - Stdout (including `--stream`): a spool temporary file under
//!      `--spool-dir` (default `$TMPDIR`) is the target backend. After scanning
//!      and settling it is copied out in byte order (for `--stream`, the spool's
//!      byte order guarantees block order). On a non-`Ok` outcome stdout stays
//!      empty; `--stream` is the exception and warns that the emitted bytes are
//!      untrusted.
//! 3. Repair symbols that exceed the memory budget are **not dropped**: they are
//!    appended to an overflow temporary file under `--spool-dir`, with only their
//!    keys and positions kept in memory. Failing to create or write a temporary
//!    file is an I/O error (exit 1, one line plus a suggestion).
//! 4. Statistics: symbols written through or spilled (including bytes spooled to
//!    disk on the stdout path), missing symbols, and per-phase timings for
//!    scanning, settling, and verification. The output remains a single `key=value`
//!    line with the existing field prefixes.
//! 5. Exit codes follow the outcome matrix; EPIPE/SIGPIPE exits silently with 0.
//!
//! Memory usage: resident memory is approximately
//! `min(jobs,NB,cap)·(2·max_j(K_j·T) + o) + max_mem + O(S/8) + 32 MiB`,
//! independent of `F`; temporary space is about `F` plus the overflow file (for
//! file output or the stdout spool). `--jobs > 1` only affects settling
//! parallelism (the library uses `thread::scope`, and workers `pread`
//! independently); results, exit codes, and statistics do not depend on `N`.
//! `--jobs` remains an upper bound, and the worker count is clamped by the
//! resident-memory limit. Cleanup of temporary files on `SIGINT/SIGTERM/SIGHUP`
//! is handled centrally by the watchdog in [`super::temp`]; spool and overflow
//! files are registered as soon as they are created.
//!
//! Degenerate parameters: `--max-mem` at or below the scan window (64 KiB) is
//! rejected during argument validation (exit 1). When no layout has been
//! established, the total block count and maximum block size in the statistics
//! display `N/A`.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lapiwe::container::decode::{DecodeConfig, DecodeEngine, DecodeSummary, PatchError};
use lapiwe::container::ledger::FileStore;
use lapiwe::container::outcome::{DecodeOutcome, Verify, classify};
use lapiwe::container::scan::{ScanStats, scan_into};

use super::args::DecodeArgs;
use super::ranges;
use super::temp::{TempGuard, create_temp_for, create_unique};
use super::{exit_code, write_stderr};

/// Output destination. When `-o` is omitted, [`output_target`] chooses the default.
enum OutputTarget {
    Stdout,
    File(PathBuf),
}

/// Choose the default output target when `-o` is omitted.
fn output_target(args: &DecodeArgs) -> OutputTarget {
    match &args.output {
        Some(o) if o == "-" => OutputTarget::Stdout,
        Some(o) => OutputTarget::File(PathBuf::from(o)),
        None if args.input == "-" => OutputTarget::Stdout,
        None => match strip_lpw_suffix(&args.input) {
            Some(stripped) => OutputTarget::File(PathBuf::from(stripped)),
            None => {
                let mut name = args.input.clone();
                name.push(".out");
                OutputTarget::File(PathBuf::from(name))
            }
        },
    }
}

/// Strip the `.lpw` suffix from `input`, comparing raw bytes so that non-UTF-8
/// names are supported.
fn strip_lpw_suffix(input: &OsStr) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        input
            .as_bytes()
            .strip_suffix(b".lpw")
            .map(|b| OsString::from_vec(b.to_vec()))
    }
    #[cfg(not(unix))]
    {
        input.to_str()?.strip_suffix(".lpw").map(OsString::from)
    }
}

/// Human-readable reason for an outcome category, used in error lines.
fn reason(outcome: DecodeOutcome) -> &'static str {
    match outcome {
        DecodeOutcome::NoOti => {
            "no usable baseline OTI (metadata packet missing or all metadata corrupt)"
        }
        DecodeOutcome::Malformed => "baseline OTI layout is outside the format boundary",
        DecodeOutcome::Insufficient => {
            "insufficient data: at least one block remained unsolved at end of stream"
        }
        DecodeOutcome::HashMismatch => "BLAKE3 mismatch: output is not trustworthy",
        DecodeOutcome::Ok => "success",
    }
}

/// Decode target backend: the temporary publish file for file output, or the
/// spool file used for stdout.
///
/// Both serve as the engine ledger's `store` (source symbols are written through
/// and read back during settling). They differ only in how they are published
/// and in what `spooled_bytes` counts: file output is atomically renamed into
/// place, while the stdout path copies bytes out in order once the outcome is
/// known.
struct TargetStore {
    /// Backend path, used for read-back verification, copying, and publishing.
    path: PathBuf,
    /// File backend shared with the engine (`Arc` so it can later be truncated,
    /// synced, and read back).
    store: Arc<FileStore>,
    /// RAII guard: remove the file unless it is published or copied out; also
    /// registers it for signal cleanup.
    guard: TempGuard,
    /// Whether this is the stdout spool, whose on-disk bytes count toward
    /// `spooled_bytes`.
    is_spool: bool,
}

impl TargetStore {
    /// On-disk temporary bytes as reported by the CLI (the stdout spool backend;
    /// zero for file publishing, where overflow is counted separately).
    ///
    /// Use allocated blocks (`st_blocks` on Unix) rather than the logical length:
    /// source symbols are written at block offsets, so unsolved blocks leave
    /// holes, and "bytes spooled to disk" should not include them. Fall back to
    /// the logical length when the allocated size is unavailable.
    fn spooled_bytes(&self) -> u64 {
        if !self.is_spool {
            return 0;
        }
        let Ok(meta) = self.store.file().metadata() else {
            return 0;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let allocated = meta.blocks().saturating_mul(512);
            if allocated == 0 {
                return meta.len();
            }
            allocated.min(meta.len())
        }
        #[cfg(not(unix))]
        {
            meta.len()
        }
    }
}

/// Per-phase timings: scanning, settling, verification, and patch commit.
#[derive(Clone, Copy, Default)]
struct PhaseTimings {
    scan: Duration,
    settle: Duration,
    verify: Duration,
    /// `--patch` commit phase (zero when not patching).
    commit: Duration,
}

/// Decode statistics, printed as a single stderr line. Timings and throughput
/// are measured values.
///
/// When no layout is established (`NoOti`/`Malformed`), the total block count
/// and maximum block size cannot be derived and display `N/A`; for `Malformed`,
/// the baseline `NB` is included. They are never reported as zero.
///
/// The line also reports `written_through_bytes`, `spooled_bytes` (overflow
/// payload plus stdout spool bytes on disk), `missing_symbols`, and the
/// scan/settle/verify timings. Fields use stable `key=value` names in a fixed
/// order so the line remains parseable; the per-phase timings follow the
/// elapsed-time and throughput fields at the end of the line, so comparisons
/// that strip timing fields still work.
fn print_stats(
    scan: &ScanStats,
    engine: &DecodeEngine,
    summary: &DecodeSummary,
    phase: PhaseTimings,
    elapsed: Duration,
    spooled_output: u64,
) {
    let st = engine.stats();
    let meta = engine.meta_stats();
    let secs = elapsed.as_secs_f64();
    let throughput = if secs > 0.0 {
        scan.bytes_scanned as f64 / (1024.0 * 1024.0) / secs
    } else {
        0.0
    };
    let baseline = if engine.baseline_oti().is_some() {
        "established"
    } else {
        "not-established"
    };
    let solved = st.solved_total();
    let (total_blocks, max_block_bytes) = if engine.layout().is_some() {
        (st.total_blocks.to_string(), st.max_block_bytes.to_string())
    } else {
        let total = match engine.baseline_oti() {
            Some(oti) => format!("N/A(baseline_NB={})", oti.nb),
            None => "N/A".to_owned(),
        };
        (total, "N/A".to_owned())
    };
    let _ = write_stderr(&format!(
        "lapiwe: decode stats: scanned={} bytes sync_candidates={} crc_failures={} bad_packets={} \
         bad_frames={} duplicates={} solved={}/{} direct={} solver={} agree_meta={} conflict={} \
         bad_meta={} baseline_oti={} best_effort={} max_j(K_j*T)={} pending_dropped={} \
         symbols_dropped={} written_through_bytes={} spooled_bytes={} missing_symbols={} \
         patch_missing_symbols={} patch_read_failed_symbols={} patched_symbols={} \
         patched_bytes={} patched_ranges={} patch_known_blocks={} result={:?} \
         elapsed={:.3}s throughput={:.2}MiB/s scan_time={:.3}s settle_time={:.3}s \
         verify_time={:.3}s patch_commit_time={:.3}s\n",
        scan.bytes_scanned,
        scan.sync_candidates,
        scan.crc_failures,
        st.bad_packets,
        scan.bad_frames,
        st.dup,
        solved,
        total_blocks,
        st.direct_blocks,
        st.solved_blocks,
        meta.agree_meta,
        meta.conflict,
        meta.bad_meta,
        baseline,
        u8::from(st.best_effort),
        max_block_bytes,
        st.pending_dropped,
        st.symbols_dropped,
        st.written_through_bytes,
        st.spooled_bytes + spooled_output,
        st.missing_symbols,
        st.patch_missing_symbols,
        engine.patch_read_failed_symbols(),
        st.patched_symbols,
        st.patched_bytes,
        st.patched_ranges,
        st.patch_known_blocks,
        summary.outcome,
        secs,
        throughput,
        phase.scan.as_secs_f64(),
        phase.settle.as_secs_f64(),
        phase.verify.as_secs_f64(),
        phase.commit.as_secs_f64()
    ));
}

/// Print warnings to stderr.
fn print_warnings(args: &DecodeArgs, summary: &DecodeSummary, streamed_written: u64) {
    if summary.stats.best_effort {
        // Warn whenever the stream is marked best_effort=1.
        let _ = write_stderr(
            "lapiwe: warning: stream is marked best_effort=1 (insufficient effective redundancy) - output is not trustworthy\n",
        );
    }
    if args.no_verify {
        // Skipping BLAKE3 verification deserves a prominent warning.
        let _ = write_stderr(
            "lapiwe: warning: --no-verify: final BLAKE3 verification skipped; integrity is unknown (unverified)\n",
        );
    }
    if !args.stream {
        return;
    }
    match summary.outcome {
        DecodeOutcome::Ok => {}
        DecodeOutcome::HashMismatch => {
            let _ = write_stderr(
                "lapiwe: warning: --stream: output is not trustworthy (BLAKE3 mismatch)\n",
            );
        }
        DecodeOutcome::Insufficient => {
            let _ = write_stderr(&format!(
                "lapiwe: warning: --stream: output is incomplete and not trustworthy (unsolved blocks remain; {streamed_written} bytes written)\n"
            ));
        }
        DecodeOutcome::NoOti | DecodeOutcome::Malformed => {
            if streamed_written > 0 {
                let _ = write_stderr(&format!(
                    "lapiwe: warning: --stream: output is not trustworthy ({})\n",
                    reason(summary.outcome)
                ));
            }
        }
    }
}

/// Result of writing the `--stream` output.
enum EmitError {
    /// The output side returned EPIPE: stop immediately and exit successfully
    /// without a message.
    EpPipe,
    /// A write failed for a reason other than EPIPE, so the emitted bytes are
    /// untrusted.
    Write(io::Error),
}

/// `--stream`: after settling, read solved blocks from the target backend in
/// block order and write them out.
///
/// [`DecodeEngine::take_solved_block`] marks each block as emitted and updates
/// the running BLAKE3 state; `finish` uses that state for the final verification
/// and classification. Block order follows the byte order of the spool or
/// publish file and the block offsets. Return the number of bytes written, which
/// equals the solved contiguous block prefix (`≤ F`).
fn emit_stream<W: Write>(engine: &mut DecodeEngine, out: &mut W) -> Result<u64, EmitError> {
    let mut written = 0u64;
    while let Some(bytes) = engine.take_solved_block() {
        match out.write_all(&bytes) {
            Ok(()) => written += bytes.len() as u64,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Err(EmitError::EpPipe),
            Err(e) => return Err(EmitError::Write(e)),
        }
    }
    Ok(written)
}

/// Read back the BLAKE3 digest of the first `f` bytes of the target, for file
/// publishing and stdout spool verification.
///
/// Hash in chunks so memory stays independent of `F`. Return `Some(digest)` once
/// `f` bytes have been hashed, or `None` if the file ends early. I/O errors are
/// propagated.
fn hash_published_prefix(path: &Path, f: u64) -> io::Result<Option<[u8; 32]>> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut remaining = f;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}

/// Copy the first `f` bytes of the spool file to stdout in byte order, after the
/// outcome has been confirmed.
///
/// EPIPE exits silently with 0; any other read or write failure prints a
/// single-line error and exits 1. Copy in chunks so memory stays independent of
/// `F`.
fn copy_spool_to_stdout(path: &Path, f: u64) -> u8 {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to read output staging: {e}\n"
            ));
            return exit_code::OTHER;
        }
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut buf = vec![0u8; 1 << 20];
    let mut remaining = f;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => {
                let _ = write_stderr(
                    "lapiwe: error: output staging is shorter than F (internal error)\n",
                );
                return exit_code::OTHER;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = write_stderr(&format!(
                    "lapiwe: error: failed to read output staging: {e}\n"
                ));
                return exit_code::OTHER;
            }
        };
        if let Err(e) = out.write_all(&buf[..n]) {
            return match e.kind() {
                io::ErrorKind::BrokenPipe => exit_code::OK, // Exit silently on EPIPE.
                _ => {
                    let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
                    exit_code::OTHER
                }
            };
        }
        remaining -= n as u64;
    }
    match out.flush() {
        Ok(()) => exit_code::OK,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => exit_code::OK,
        Err(e) => {
            let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
            exit_code::OTHER
        }
    }
}

/// Finish file publishing: truncate to `F`, then `sync_all` and atomically
/// `rename` into place.
///
/// The engine has already written the bytes through to the temporary publish
/// file at block offsets during scanning and settling; read-back verification
/// happened in [`run`], so a hash mismatch never reaches this point. No failure
/// here publishes the target, and the temporary file is removed by RAII.
fn finish_file_publish(target: &Path, sink: TargetStore, f: u64) -> u8 {
    // The output is exactly F bytes; drop the zero padding at the end of the last
    // block here.
    let file = sink.store.file();
    if let Err(e) = file.set_len(f).and_then(|()| file.sync_all()) {
        let _ = write_stderr(&format!("lapiwe: error: failed to write output: {e}\n"));
        return exit_code::OTHER;
    }
    if let Err(e) = fs::rename(&sink.path, target) {
        let _ = write_stderr(&format!(
            "lapiwe: error: atomic publish failed ({} -> {}): {e}\n",
            sink.path.display(),
            target.display()
        ));
        return exit_code::OTHER;
    }
    let mut guard = sink.guard;
    guard.defuse();
    exit_code::OK
}

/// Report a failure to open or read the input as a single-line error and exit 1.
fn input_error(path: &OsStr, e: &io::Error) -> u8 {
    let _ = write_stderr(&format!(
        "lapiwe: error: failed to read input {}: {e}\n",
        Path::new(path).display()
    ));
    exit_code::OTHER
}

/// Report a failure to create a spool or temporary file as a single-line error
/// with a suggestion and exit 1. Never silently fall back to an in-memory
/// backend.
fn spool_create_error(dir: &Path, what: &str, e: &io::Error) -> u8 {
    let _ = write_stderr(&format!(
        "lapiwe: error: failed to create {what} in {}: {e} (consider changing --spool-dir or increasing --max-mem)\n",
        dir.display()
    ));
    exit_code::OTHER
}

/// Report a ledger I/O failure (write-through, overflow, or read-back) as a
/// single-line error with a suggestion and exit 1.
///
/// The publish temporary file for file output and the stdout spool are removed
/// by [`TempGuard`] RAII, so there is no partial publish; on the stdout path
/// without `--stream`, a failure before copying leaves stdout empty.
fn storage_error_line(e: &io::Error) -> u8 {
    let _ = write_stderr(&format!(
        "lapiwe: error: decode staging/write-through failed: {e} (consider increasing --max-mem or changing --spool-dir)\n"
    ));
    exit_code::OTHER
}

/// Run `decode` and return the CLI exit code.
pub fn run(args: &DecodeArgs) -> u8 {
    // `--patch` takes a separate in-place repair path that uses TARGET directly
    // and creates no new file.
    if let Some(target) = &args.patch {
        return run_patch(args, target);
    }
    let target = output_target(args);
    let cfg = DecodeConfig {
        no_verify: args.no_verify,
    };
    let start = Instant::now();

    // Scratch directory for the stdout spool and the repair-symbol overflow;
    // defaults to `$TMPDIR`.
    let spool_dir = match &args.spool_dir {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };

    // The overflow backend is a temporary file under `--spool-dir`. If it cannot
    // be created, exit 1: symbols that could still affect solvability must not
    // be silently dropped, and there is no silent fallback to an in-memory
    // backend.
    let (spill_path, spill_file) = match create_unique(&spool_dir, "lapiwe-decode-spill") {
        Ok(x) => x,
        Err(e) => return spool_create_error(&spool_dir, "decode spill staging", &e),
    };
    let _spill_guard = TempGuard::new(spill_path);

    // Target backend: for file output, a publish temporary file in the target
    // directory; for stdout, a spool temporary file.
    let sink = match &target {
        OutputTarget::File(path) => match create_temp_for(path) {
            Ok((tmp_path, file, guard)) => TargetStore {
                path: tmp_path,
                store: Arc::new(FileStore::new(file)),
                guard,
                is_spool: false,
            },
            Err(e) => {
                let _ = write_stderr(&format!(
                    "lapiwe: error: failed to create a temporary output near {}: {e}\n",
                    path.display()
                ));
                return exit_code::OTHER;
            }
        },
        OutputTarget::Stdout => match create_unique(&spool_dir, "lapiwe-decode-out") {
            Ok((path, file)) => {
                let guard = TempGuard::new(path.clone());
                TargetStore {
                    path,
                    store: Arc::new(FileStore::new(file)),
                    guard,
                    is_spool: true,
                }
            }
            Err(e) => return spool_create_error(&spool_dir, "decode output staging", &e),
        },
    };

    let mut engine = DecodeEngine::with_store(
        Box::new(Arc::clone(&sink.store)),
        Box::new(FileStore::new(spill_file)),
        args.max_mem,
        args.jobs,
    );
    // File output and stdout without `--stream`: the bytes already live in the
    // target backend, so the CLI performs the final BLAKE3 verification by
    // reading back in chunks (`finish` must not read all of `F` into memory).
    // With `--stream`, `take_solved_block` accumulates the digest as blocks are
    // emitted.
    if !args.stream {
        engine.set_external_verify();
    }

    let reader: Box<dyn Read> = if args.input == "-" {
        Box::new(io::stdin().lock())
    } else {
        match File::open(&args.input) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(e) => return input_error(&args.input, &e),
        }
    };

    // Scan and write through: source symbols land in the target backend as they
    // arrive, and direct blocks are solved in place.
    let t_scan = Instant::now();
    let scan_stats = match scan_into(reader, &mut engine) {
        Ok(stats) => stats,
        Err(e) => return input_error(&args.input, &e),
    };
    let scan_time = t_scan.elapsed();
    // A ledger I/O failure (write-through or overflow) is reported as a
    // single-line error with a suggestion; exit 1, removing the temporary
    // backend by RAII.
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // Settle the stream tail. Parallelism is
    // `min(jobs, number of tasks, resident-memory limit / ...)` in the library.
    let t_settle = Instant::now();
    engine.wait_solve();
    let settle_time = t_settle.elapsed();
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // `--stream`: after settling, copy out from the spool in block order (spool
    // first, then copy, for constant memory; block order equals spool byte
    // order). EPIPE exits silently with 0; a non-EPIPE write failure adds an
    // "untrusted" warning and exits 1.
    let mut streamed_written = 0u64;
    let mut verify_time = Duration::ZERO;
    if args.stream {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let t_emit = Instant::now();
        match emit_stream(&mut engine, &mut out) {
            Ok(written) => streamed_written = written,
            Err(EmitError::EpPipe) => return exit_code::OK, // Exit silently with 0 on EPIPE.
            Err(EmitError::Write(e)) => {
                // A mid-stream write failure other than EPIPE means the emitted
                // bytes may be incomplete and cannot be recovered.
                let _ = write_stderr(
                    "lapiwe: warning: --stream: output is incomplete/untrusted (failed to write stdout)\n",
                );
                let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
                return exit_code::OTHER;
            }
        }
        match out.flush() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return exit_code::OK,
            Err(e) => {
                let _ = write_stderr(
                    "lapiwe: warning: --stream: output is incomplete/untrusted (failed to write stdout)\n",
                );
                let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
                return exit_code::OTHER;
            }
        }
        // Verification (the running BLAKE3) happens in the same pass as emission;
        // this timing covers that pass.
        verify_time = t_emit.elapsed();
        if let Some(e) = engine.storage_error() {
            return storage_error_line(e);
        }
    }

    let mut summary = engine.finish(&cfg);
    // A ledger I/O failure during settling or read-back is also reported as an
    // I/O error, before classification and publishing.
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // For file publishing and stdout without `--stream`, perform read-back
    // verification before printing statistics so that the reported outcome
    // reflects the final classification (`--no-verify` skips verification and
    // keeps `Skipped` → `Ok`). Verification reads the target backend in chunks
    // and never keeps `F` resident.
    if !args.stream {
        let t_verify = Instant::now();
        if summary.outcome == DecodeOutcome::Ok && !args.no_verify {
            let oti = summary.oti.expect("Ok results always have a baseline OTI");
            match hash_published_prefix(&sink.path, oti.f) {
                Ok(Some(digest)) => {
                    summary.signals.verify = Verify::Verified(digest == oti.blake3);
                    summary.outcome = classify(summary.signals);
                }
                Ok(None) => {
                    let _ = write_stderr(
                        "lapiwe: error: output staging is shorter than F (internal error)\n",
                    );
                    return exit_code::OTHER;
                }
                Err(e) => {
                    let _ = write_stderr(&format!(
                        "lapiwe: error: read-back verification failed: {e}\n"
                    ));
                    return exit_code::OTHER;
                }
            }
        }
        verify_time = t_verify.elapsed();
    }

    let elapsed = start.elapsed();
    print_stats(
        &scan_stats,
        &engine,
        &summary,
        PhaseTimings {
            scan: scan_time,
            settle: settle_time,
            verify: verify_time,
            commit: Duration::ZERO,
        },
        elapsed,
        sink.spooled_bytes(),
    );
    print_warnings(args, &summary, streamed_written);

    match target {
        OutputTarget::File(path) => {
            if summary.outcome == DecodeOutcome::Ok {
                let f = summary
                    .oti
                    .expect("Ok results always have a baseline OTI")
                    .f;
                drop(engine); // The backend is held by sink's Arc.
                finish_file_publish(&path, sink, f)
            } else {
                // The temporary file (which may hold partial blocks) is removed
                // when the guard is dropped; the target never appears.
                drop(engine);
                drop(sink);
                let _ = write_stderr(&format!(
                    "lapiwe: error: decode failed: {} (no output file published)\n",
                    reason(summary.outcome)
                ));
                summary.outcome.exit_code()
            }
        }
        OutputTarget::Stdout => {
            if args.stream {
                // Bytes were already copied out in block order; warnings and
                // exit codes follow the outcome.
                summary.outcome.exit_code()
            } else if summary.outcome == DecodeOutcome::Ok {
                let f = summary
                    .oti
                    .expect("Ok results always have a baseline OTI")
                    .f;
                drop(engine);
                // Copy out only after confirming `Ok`, so stdout stays empty on
                // failure; the sink guard removes the spool when it is dropped.
                copy_spool_to_stdout(&sink.path, f)
            } else {
                drop(engine);
                drop(sink);
                let _ = write_stderr(&format!(
                    "lapiwe: error: decode failed: {} (zero bytes on stdout)\n",
                    reason(summary.outcome)
                ));
                summary.outcome.exit_code()
            }
        }
    }
}

/// Report a patch-mode error as a single-line error with a suggestion and
/// exit 1.
fn patch_error_line(err: &PatchError) -> u8 {
    match err {
        PatchError::TargetSizeMismatch { actual, expected } => {
            let _ = write_stderr(&format!(
                "lapiwe: error: patch target size mismatch: actual {actual} bytes, baseline F={expected} bytes \
                 (resize the target to F bytes, or decode to a new file)\n"
            ));
        }
        PatchError::RangeOutOfBounds { start, len, f } => {
            let _ = write_stderr(&format!(
                "lapiwe: error: --missing-ranges range out of bounds: [{start}, {}) exceeds [0,{f}] \
                 (fix the missing-range list and retry)\n",
                start.saturating_add(*len)
            ));
        }
    }
    exit_code::OTHER
}

/// Run the `--patch TARGET` in-place repair flow.
///
/// Differences from a regular decode:
///
/// - The output is `TARGET`, opened for reading and writing; it is not created,
///   renamed, or resized.
/// - The engine `store` is an **overlay** temporary file under `--spool-dir`
///   (source symbols written through from the stream and solver write-backs).
///   `TARGET` is written only by [`DecodeEngine::commit_patch`], after all blocks
///   have been solved, and only for the missing ranges: nothing is written
///   before that point, and failure paths leave it untouched.
/// - The final check reads back all `F` bytes of `TARGET` and compares BLAKE3. A
///   mismatch exits 4 with guidance and notes that the tool did not rewrite any
///   readable range.
fn run_patch(args: &DecodeArgs, target: &OsStr) -> u8 {
    let cfg = DecodeConfig {
        no_verify: args.no_verify,
    };
    let start = Instant::now();

    // Scratch directory for the overlay and repair-symbol overflow; defaults to
    // `$TMPDIR`.
    let spool_dir = match &args.spool_dir {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir(),
    };

    // TARGET must already exist; open it for reading and writing, since patch
    // mode never creates a new file.
    let target_file = match File::options().read(true).write(true).open(target) {
        Ok(file) => file,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to open patch target {} for read/write: {e} (--patch requires an existing, writable target)\n",
                Path::new(target).display()
            ));
            return exit_code::OTHER;
        }
    };

    // Parse the missing-range list before scanning; syntax and I/O errors exit 1
    // with a single line. Bounds are checked against `F` once the baseline is
    // established.
    let missing_ranges = match &args.missing_ranges {
        Some(path) => match ranges::read(Path::new(path)) {
            Ok(ranges) => ranges,
            Err(msg) => {
                let _ = write_stderr(&format!("lapiwe: error: {msg}\n"));
                return exit_code::OTHER;
            }
        },
        None => Vec::new(),
    };

    // The overlay (source symbols from the stream plus solver write-backs) and
    // the repair-symbol overflow file are both created under `--spool-dir`. If
    // creation fails, exit 1: never fall back silently to memory or write
    // TARGET directly.
    let (overlay_path, overlay_file) = match create_unique(&spool_dir, "lapiwe-patch-overlay") {
        Ok(x) => x,
        Err(e) => return spool_create_error(&spool_dir, "patch overlay staging", &e),
    };
    let _overlay_guard = TempGuard::new(overlay_path);
    let (spill_path, spill_file) = match create_unique(&spool_dir, "lapiwe-patch-spill") {
        Ok(x) => x,
        Err(e) => return spool_create_error(&spool_dir, "decode spill staging", &e),
    };
    let _spill_guard = TempGuard::new(spill_path);

    let mut engine = DecodeEngine::with_patch(
        Box::new(FileStore::new(overlay_file)),
        Box::new(FileStore::new(spill_file)),
        Box::new(FileStore::new(target_file)),
        missing_ranges,
        args.max_mem,
        args.jobs,
    );
    // The CLI performs the final BLAKE3 check by reading TARGET in chunks
    // (`finish` does not keep `F` resident).
    engine.set_external_verify();

    let reader: Box<dyn Read> = if args.input == "-" {
        Box::new(io::stdin().lock())
    } else {
        match File::open(&args.input) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(e) => return input_error(&args.input, &e),
        }
    };

    // Scan the stream. When the baseline is established, scan the target in the
    // same frame; readable ranges become known symbols.
    let t_scan = Instant::now();
    let scan_stats = match scan_into(reader, &mut engine) {
        Ok(stats) => stats,
        Err(e) => return input_error(&args.input, &e),
    };
    let scan_time = t_scan.elapsed();
    // Target size or missing-range errors are reported as a single line with a
    // suggestion; exit 1 and leave the target untouched.
    if let Some(err) = engine.patch_error() {
        return patch_error_line(err);
    }
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // Settle the stream tail. `--jobs` caps parallelism; in patch mode workers
    // read the overlay or TARGET according to symbol position.
    let t_settle = Instant::now();
    engine.wait_solve();
    let settle_time = t_settle.elapsed();
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // Commit only after **all blocks have been solved**. Write missing ranges
    // only, truncating the final symbol to `min(T, F−off)`. If not everything was
    // solved (`Insufficient`/`Malformed`/`NoOti`), nothing is committed and
    // TARGET bytes stay unchanged.
    let t_commit = Instant::now();
    let commit = match engine.commit_patch() {
        Ok(commit) => commit,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to write patch target: {e} \
                 (the target may be partially repaired; decode to a new file for a full check)\n"
            ));
            return exit_code::OTHER;
        }
    };
    let commit_time = t_commit.elapsed();
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    let mut summary = engine.finish(&cfg);
    if let Some(e) = engine.storage_error() {
        return storage_error_line(e);
    }

    // Read back all of TARGET for the final BLAKE3 check (`--no-verify` skips it
    // with a warning, with the same semantics as the regular decode path).
    let t_verify = Instant::now();
    if !args.no_verify && summary.outcome == DecodeOutcome::Ok {
        let oti = summary.oti.expect("Ok results always have a baseline OTI");
        match hash_published_prefix(Path::new(target), oti.f) {
            Ok(Some(digest)) => {
                summary.signals.verify = Verify::Verified(digest == oti.blake3);
                summary.outcome = classify(summary.signals);
            }
            Ok(None) => {
                let _ = write_stderr(
                    "lapiwe: error: patch target is shorter than F (internal error)\n",
                );
                return exit_code::OTHER;
            }
            Err(e) => {
                let _ = write_stderr(&format!(
                    "lapiwe: error: read-back verification of patch target failed: {e}\n"
                ));
                return exit_code::OTHER;
            }
        }
    }
    let verify_time = t_verify.elapsed();

    let elapsed = start.elapsed();
    print_stats(
        &scan_stats,
        &engine,
        &summary,
        PhaseTimings {
            scan: scan_time,
            settle: settle_time,
            verify: verify_time,
            commit: commit_time,
        },
        elapsed,
        0,
    );
    print_warnings(args, &summary, 0);

    match summary.outcome {
        DecodeOutcome::Ok => exit_code::OK,
        DecodeOutcome::HashMismatch => {
            // Guidance text: readable does not mean correct, silent corruption is
            // possible, and a full decode to a new file is recommended. Also note
            // that no readable range was rewritten; exit 4.
            let _ = write_stderr(
                "lapiwe: warning: patch final BLAKE3 mismatch: readable does not mean correct - the target \
                 may contain silent corruption; only missing regions were written, and no readable region \
                 was rewritten\n",
            );
            let _ = write_stderr(
                "lapiwe: suggestion: decode to a new file for a full check (do not rely on the \
                 \"readable = correct\" assumption in --patch mode)\n",
            );
            if let Some(commit) = engine.patch_commit() {
                let _ = write_stderr(&format!(
                    "lapiwe: note: this commit wrote symbols={} bytes={} ranges={} (TARGET has been partially repaired)\n",
                    commit.symbols, commit.bytes, commit.ranges
                ));
            }
            summary.outcome.exit_code()
        }
        other => {
            // Nothing was fully solved, so the engine wrote no bytes to TARGET.
            let _ = write_stderr(&format!(
                "lapiwe: error: patch failed: {} (no bytes were written to the target)\n",
                reason(other)
            ));
            let _ = commit;
            other.exit_code()
        }
    }
}
