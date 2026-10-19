//! Implementation of the read-only `lapiwe inspect` command.
//!
//! `inspect` scans the input and reports what the decoder observed. It does
//! not assemble the original object, verify the BLAKE3 digest, or write any
//! files, so the input's `sha256` is unchanged before and after a run.
//!
//! Observations are printed to stdout:
//!
//! - **Baseline OTI** — `F` (original input length), `T` (symbol size), `NB`
//!   (number of logical blocks), `N_sub` (RaptorQ sub-block count), `SCHEME`
//!   (RaptorQ scheme identifier), and the BLAKE3-256 value recorded in the
//!   metadata. Reports that no baseline was established when none was found.
//! - **Layout** — derived leveling: `KS`, the `K_j` range, and the `K_j·T`
//!   upper bound. Reports that the layout cannot be derived when the baseline
//!   exists but violates format constraints.
//! - **`P`** — observed packet size, or a note that no valid frame passed
//!   validation.
//! - **Scan statistics** — bytes scanned, SYNC candidates, valid and bad
//!   packets, CRC failures, other bad frames, bad code, truncated frames,
//!   duplicates, and peak buffered bytes.
//! - **Block coverage** — per-block percentage of received symbols when there
//!   are at most [`COVERAGE_LIST_LIMIT`] blocks, otherwise the minimum and
//!   maximum percentage plus the number of blocks with received symbols. Not
//!   available when the layout cannot be derived.
//! - **Metadata** — counts of agreeing, conflicting, and malformed metadata
//!   packets, whether a baseline OTI was established, and the `best_effort`
//!   flag.
//!
//! If no usable OTI is found, a single explanatory line is written to stderr
//! and the command exits with code 3. A stream marked `best_effort=1` produces
//! a warning on stderr.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use lapiwe::container::decode::DecodeEngine;
use lapiwe::container::leveling::Leveling;
use lapiwe::container::meta::Oti;
use lapiwe::container::scan::scan_into;

use super::args::InspectArgs;
use super::{exit_code, write_stderr};

/// Maximum number of blocks for which per-block coverage is listed. Larger
/// objects are summarized by their minimum and maximum coverage instead.
const COVERAGE_LIST_LIMIT: u32 = 32;

/// Run the `inspect` command and return the CLI exit code.
///
/// The input path may be `-` to read from stdin. The command only decodes and
/// observes packets: it never assembles the object, verifies the BLAKE3
/// digest, or writes files.
///
/// Returns [`exit_code::NO_USABLE_OTI`] when no structurally valid metadata
/// packet yielded a baseline OTI, and [`exit_code::OTHER`] when the input
/// cannot be opened, read, or reported to stdout.
pub fn run(args: &InspectArgs) -> u8 {
    let reader: Box<dyn Read> = if args.input == "-" {
        Box::new(io::stdin().lock())
    } else {
        match File::open(&args.input) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(e) => {
                let _ = write_stderr(&format!(
                    "lapiwe: error: failed to read input {}: {e}\n",
                    Path::new(&args.input).display()
                ));
                return exit_code::OTHER;
            }
        }
    };
    let mut engine = DecodeEngine::new();
    let scan = match scan_into(reader, &mut engine) {
        Ok(stats) => stats,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to read input {}: {e}\n",
                Path::new(&args.input).display()
            ));
            return exit_code::OTHER;
        }
    };

    let st = engine.stats();
    let meta = engine.meta_stats();
    let mut lines: Vec<String> = Vec::new();
    match engine.baseline_oti() {
        None => lines.push("lapiwe inspect: baseline OTI: not established".to_owned()),
        Some(oti) => lines.push(format!("lapiwe inspect: {}", oti_line(&oti))),
    }
    match engine.layout() {
        Some(layout) => lines.push(format!("lapiwe inspect: {}", layout_line(layout))),
        None if engine.baseline_oti().is_some() => {
            lines.push(
                "lapiwe inspect: layout: not derivable (outside the format boundary)".to_owned(),
            );
        }
        None => {}
    }
    lines.push(match st.packet_size {
        Some(p) => format!("lapiwe inspect: P={p}"),
        None => "lapiwe inspect: P=not observed (no valid frame passed validation)".to_owned(),
    });
    lines.push(format!(
        "lapiwe inspect: scan stats: scanned={} bytes sync_candidates={} valid_packets={} \
         bad_packets={} crc_failures={} bad_frames={} bad_code={} truncated={} duplicates={} \
         peak_window={}",
        scan.bytes_scanned,
        scan.sync_candidates,
        st.packets - st.bad_packets,
        st.bad_packets,
        scan.crc_failures,
        scan.bad_frames,
        scan.bad_code,
        scan.truncated,
        st.dup,
        scan.peak_buffered
    ));
    if let Some(layout) = engine.layout() {
        lines.push(format!(
            "lapiwe inspect: {}",
            coverage_line(&engine, layout)
        ));
    } else if engine.baseline_oti().is_some() {
        // A baseline OTI exists but the layout cannot be derived (malformed
        // input), so coverage is reported as N/A rather than as 0% or omitted.
        // The baseline `NB` is shown on the OTI line above.
        lines.push("lapiwe inspect: block coverage: N/A (layout not derivable)".to_owned());
    }
    lines.push(format!(
        "lapiwe inspect: metadata: agree_meta={} conflict={} bad_meta={} baseline_oti={} best_effort={}",
        meta.agree_meta,
        meta.conflict,
        meta.bad_meta,
        if engine.baseline_oti().is_some() {
            "established"
        } else {
            "not-established"
        },
        u8::from(st.best_effort)
    ));

    let mut report = lines.join("\n");
    report.push('\n');
    if write_stdout(&report) == exit_code::OTHER {
        return exit_code::OTHER;
    }

    if engine.baseline_oti().is_none() {
        // Statistics have already been printed to stdout; add a single
        // explanatory line on stderr and exit with code 3.
        let note = if st.best_effort {
            "; see also best_effort=1: output is not trustworthy"
        } else {
            ""
        };
        let _ = write_stderr(&format!(
            "lapiwe: error: no usable OTI: no structurally valid metadata packet found{note} (exit 3)\n"
        ));
        return exit_code::NO_USABLE_OTI;
    }
    if st.best_effort {
        // A stream marked `best_effort=1` must produce a warning.
        let _ = write_stderr(
            "lapiwe: warning: stream is marked best_effort=1 (insufficient effective redundancy) - output is not trustworthy\n",
        );
    }
    exit_code::OK
}

/// Format the baseline OTI line: `F`, `T`, `NB`, `N_sub`, `SCHEME`, and the
/// BLAKE3-256 value.
fn oti_line(oti: &Oti) -> String {
    format!(
        "baseline OTI: F={} T={} NB={} N_sub={} SCHEME={} BLAKE3={}",
        oti.f,
        oti.t,
        oti.nb,
        oti.n_sub,
        oti.scheme,
        hex(&oti.blake3)
    )
}

/// Format the derived layout line: `KS`, the `K_j` range, and the `K_j·T`
/// upper bound.
fn layout_line(layout: &Leveling) -> String {
    format!(
        "layout: KS={} K_j=[{},{}] K_j*T<={}",
        layout.ks,
        layout.min_k(),
        layout.max_k(),
        layout.max_k() * layout.t
    )
}

/// Format the block coverage line. When there are at most
/// [`COVERAGE_LIST_LIMIT`] blocks, list each block's percentage; otherwise
/// report the minimum and maximum percentage and how many blocks have received
/// symbols.
fn coverage_line(engine: &DecodeEngine, layout: &Leveling) -> String {
    if layout.nb <= COVERAGE_LIST_LIMIT {
        let mut parts = Vec::with_capacity(layout.nb as usize);
        for j in 0..layout.nb {
            let (source, k) = engine.block_coverage(j).unwrap_or((0, 1));
            parts.push(format!("{:.3}%", 100.0 * source as f64 / k as f64));
        }
        format!("block coverage: [{}]", parts.join(", "))
    } else {
        match engine.coverage_bounds() {
            Some((min, max, covered)) => format!(
                "block coverage: min={min:.3}% max={max:.3}% (blocks with symbols {covered}/{})",
                layout.nb
            ),
            None => "block coverage: not derivable".to_owned(),
        }
    }
}

/// Encode `bytes` as lowercase hexadecimal. Used to display the BLAKE3 value
/// without additional dependencies.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Write `text` to stdout and return an exit code. A broken pipe is treated as
/// success so that output piped into tools such as `head` stays quiet; other
/// I/O failures are reported to stderr and mapped to a generic error code.
fn write_stdout(text: &str) -> u8 {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => exit_code::OK,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => exit_code::OK,
        Err(e) => {
            let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
            exit_code::OTHER
        }
    }
}
