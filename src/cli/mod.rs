//! Command-line interface: argument parsing and dispatch for the `encode`,
//! `decode`, and `inspect` subcommands.
//!
//! # Command-line surface
//!
//! ```text
//! lapiwe <subcommand> [OPTIONS] <IN>
//! ```
//!
//! | Subcommand | Purpose |
//! |------------|---------|
//! | `encode`   | Encode `<IN>` into an `.lpw` fountain stream |
//! | `decode`   | Reconstruct `<IN>` from a sufficient set of `.lpw` remnants |
//! | `inspect`  | Report `.lpw` metadata and scan statistics without decoding |
//!
//! `<IN>` is a required operand; `-` selects standard input. `-h`/`--help`
//! before the subcommand prints the top-level usage text, and after the
//! subcommand prints that command's help. Both go to stdout and exit 0.
//! Command-line errors are reported as a single line on stderr together with
//! a hint to run `lapiwe -h`, and exit with status 1.
//!
//! The `decode` subcommand may buffer data in temporary files; `--spool-dir`
//! selects the directory used for them.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Success, including help output |
//! | 1    | Any other error, including command-line usage errors |
//! | 2    | Insufficient data |
//! | 3    | No usable OTI |
//! | 4    | Final BLAKE3 checksum mismatch |
//!
//! Codes 2 and 4 are produced during decoding and are defined alongside
//! `DecodeOutcome`; see [`lapiwe::container::outcome`]. [`exit_code`] holds
//! the constants used directly by this module.
//!
//! # Signals
//!
//! [`dispatch`] installs a watchdog for `SIGINT`, `SIGTERM`, and `SIGHUP`
//! before parsing arguments (see [`temp`]). On receipt of one of these
//! signals the process removes its temporary files and exits silently.
//! Installation is idempotent. `SIGKILL` cannot be caught, so cleanup is not
//! guaranteed for it. A broken pipe while printing help is treated as a
//! successful run.

mod args;
mod decode;
mod encode;
mod inspect;
mod ranges;
mod size;
mod temp;

use std::ffi::OsString;
use std::io::{self, ErrorKind, Write};

use args::Cmd;

/// Exit codes used directly by the CLI layer.
///
/// The full matrix, including categories determined during decoding, lives in
/// [`lapiwe::container::outcome`]: `DecodeOutcome::exit_code` is the
/// authoritative mapping for codes such as 2 (insufficient data) and 4
/// (BLAKE3 mismatch).
pub mod exit_code {
    pub const OK: u8 = 0;
    pub const OTHER: u8 = 1;
    pub const NO_USABLE_OTI: u8 = 3;
}

/// Top-level usage text, printed for `-h`/`--help` without a subcommand.
const USAGE: &str = "\
Usage: lapiwe <subcommand> [OPTIONS] <IN>

Commands:
  encode   Encode <IN> into a .lpw fountain stream
  decode   Reconstruct <IN> from a sufficient .lpw residue
  inspect  Read .lpw metadata and scan statistics without decoding

Options:
  -h, --help  Print help and exit with status 0

<IN> is required; use `-` for stdin. See `lapiwe <command> -h` for command options.";

/// Help text for `encode`.
const ENCODE_HELP: &str = "\
Usage: lapiwe encode [OPTIONS] <IN>

Encode <IN> into a .lpw fountain stream. When <IN> is `-`, stdin is staged to a temporary file before encoding.
The output consists of C_total packets of P bytes each. With --size, the actual output is floor(SIZE/P)*P bytes and may be up to P-1 bytes shorter than the requested size.

Options:
  -o, --output <PATH>        Output path (`-` for stdout); default: `<IN>.lpw` (stdout when <IN> is `-`)
      --size <SIZE>          Target output size in bytes (bare bytes; K/M/G/T=1024; KB/MB/GB/TB=1000; KiB/MiB/GiB/TiB=1024)
      --redundancy <R>       Total output multiplier including metadata overhead (bare number >= 1, or `30%` for 1.3; net redundancy ~= R*(1-1/M)-1)
      --packet-size <BYTES>  Packet size P: 2048, 4096, 8192, 16384, 32768, 65536 (default 4096)
      --meta-every <M>       Metadata packet interval, M >= 2 (default 256)
      --block-symbols <K>    Maximum source symbols per logical block (default min(56403, floor(max_mem/T)))
      --max-mem <SIZE>       Per-block memory budget (default 16MiB = 16M = 16,777,216; must be >= T)
      --jobs <N>             Parallelism (default: logical CPU count; 1..=1024); total memory bound ~= (3*min(jobs,NB)+2)*max_j(K_j*T)
      --force                Encode even when effective redundancy is insufficient: warning + best_effort=1 (untrusted output) + exit 0
      --spool-dir <DIR>      Staging directory for stdin encoding (default $TMPDIR)
  -h, --help                 Print this help and exit with status 0

--size and --redundancy are mutually exclusive. If both are omitted, the smallest publishable C_total is used (default source).
SIGINT/SIGTERM/SIGHUP: remove temporary files and exit silently; SIGKILL cannot be caught, so cleanup is not guaranteed.";

/// Help text for `decode`.
const DECODE_HELP: &str = "\
Usage: lapiwe decode [OPTIONS] <IN>

Reconstruct the original blob from .lpw residue (read stdin when <IN> is `-`).
If -o is omitted, the default name drops the `.lpw` suffix, otherwise `.out` is appended (stdout when <IN> is `-`).

Options:
  -o, --output <PATH>   Output path (`-` for stdout; default see above)
      --patch <TARGET>  In-place repair: TARGET must exist and be exactly F bytes;
                        readable regions are treated as known symbols; after all blocks
                        are solved, only missing regions are written, then the whole
                        target is read back for a final BLAKE3 check (mutually exclusive with -o/--stream)
      --missing-ranges <FILE>
                        Only with --patch: additional missing ranges, one `START LENGTH`
                        per line (decimal or 0x hex; `#` comments and blank lines ignored)
      --no-verify       Skip the final BLAKE3 check (per-packet CRC-32C is still verified; a warning is printed)
      --stream          Valid only when output is stdout; after settlement, copy the result out block by block
      --jobs <N>        Decode parallelism upper bound (default: logical CPU count; 1..=1024; result is independent of N)
                        Settlement runs per block; resident memory ~= min(N,NB,cap)*(2*max_j(K_j*T)+o)
                        + max_mem + O(S/8) + 32MiB (independent of F)
      --spool-dir <DIR> Decode staging directory (default $TMPDIR): stdout staging, repair-symbol spill,
                        and --patch overlay storage
      --max-mem <SIZE>  Decode working-set budget (default 64MiB; must be > 65536, i.e. larger than the scan window):
                        covers repair-symbol residency, missing-symbol staging, and auxiliary indexes; data over
                        budget spills to --spool-dir, so resident memory is independent of F
  -h, --help            Print this help and exit with status 0

Exit codes: 0 success; 1 other error; 2 insufficient data; 3 no usable OTI; 4 BLAKE3 mismatch.
A patch final-check mismatch (4) reports \"readable != correct\" and suggests a full decode to a new file; readable regions not listed as missing are left unchanged (only missing regions are written).
SIGINT/SIGTERM/SIGHUP: remove temporary files and exit silently; SIGKILL cannot be caught, so cleanup is not guaranteed.";

/// Help text for `inspect`.
const INSPECT_HELP: &str = "\
Usage: lapiwe inspect [OPTIONS] <IN>

Read .lpw OTI/layout/scan statistics without writing files or decoding.

Options:
  -h, --help  Print this help and exit with status 0

When no usable OTI is found: print scan statistics to stdout, a single-line explanation to stderr, and exit 3.";

/// Dispatch to a subcommand and return the process exit code.
///
/// `args` holds the command-line arguments after the program name: the first
/// element selects the subcommand, and the rest are passed to it. The signal
/// watchdog is installed before any argument is examined so that temporary
/// files are cleaned up even if the process is interrupted during parsing.
/// A missing, non-UTF-8, or unknown subcommand is reported as a usage error.
/// Top-level `-h`/`--help` prints the usage text.
pub fn dispatch(args: &[OsString]) -> u8 {
    // Install the SIGINT/SIGTERM/SIGHUP watchdog before parsing. It is
    // idempotent; on a signal it removes temporary files and exits silently.
    temp::install_signal_watchdog();
    let Some((cmd, rest)) = args.split_first() else {
        return usage_error("missing subcommand (available: encode/decode/inspect)");
    };
    let Some(cmd) = cmd.to_str() else {
        return usage_error(&format!(
            "unknown subcommand `{}` (argument is not valid UTF-8)",
            cmd.to_string_lossy()
        ));
    };
    match cmd {
        "-h" | "--help" => print_help(None),
        "encode" | "decode" | "inspect" => {
            let cmd = match cmd {
                "encode" => Cmd::Encode,
                "decode" => Cmd::Decode,
                _ => Cmd::Inspect,
            };
            run_subcommand(cmd, rest)
        }
        other => usage_error(&format!(
            "unknown subcommand `{other}` (available: encode/decode/inspect)"
        )),
    }
}

/// Parse the remaining arguments for `cmd` and run the subcommand.
///
/// Return the subcommand's exit code. Parse failures and failed option
/// validation are reported through [`usage_error`]; `-h`/`--help` after the
/// subcommand prints its help instead of running it.
fn run_subcommand(cmd: Cmd, rest: &[OsString]) -> u8 {
    let raw = match args::parse(cmd, rest) {
        Ok(raw) => raw,
        Err(e) => return usage_error(&e.0),
    };
    if raw.help {
        return print_help(Some(cmd));
    }
    match cmd {
        Cmd::Encode => match args::finish_encode(raw) {
            Ok(parsed) => encode::run(&parsed),
            Err(e) => usage_error(&e.0),
        },
        Cmd::Decode => match args::finish_decode(raw) {
            Ok(parsed) => decode::run(&parsed),
            Err(e) => usage_error(&e.0),
        },
        Cmd::Inspect => match args::finish_inspect(raw) {
            Ok(parsed) => inspect::run(&parsed),
            Err(e) => usage_error(&e.0),
        },
    }
}

/// Print the top-level usage text, or the help text for `cmd`.
///
/// Return 0 on success. A broken pipe while writing means the reader has
/// stopped reading (for example `lapiwe --help | head`), which is treated as
/// success; any other write error is reported on stderr and yields 1.
fn print_help(cmd: Option<Cmd>) -> u8 {
    let text = match cmd {
        None => format!("{USAGE}\n"),
        Some(Cmd::Encode) => format!("{ENCODE_HELP}\n"),
        Some(Cmd::Decode) => format!("{DECODE_HELP}\n"),
        Some(Cmd::Inspect) => format!("{INSPECT_HELP}\n"),
    };
    match write_stdout(&text) {
        // A closed pipe is not an error: exit quietly with status 0.
        Ok(()) => exit_code::OK,
        Err(e) if e.kind() == ErrorKind::BrokenPipe => exit_code::OK,
        Err(e) => {
            let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
            exit_code::OTHER
        }
    }
}

/// Report a usage error as a single line on stderr and return exit code 1.
fn usage_error(msg: &str) -> u8 {
    let _ = write_stderr(&format!(
        "lapiwe: error: {msg} (run `lapiwe -h` for usage)\n"
    ));
    exit_code::OTHER
}

/// Write `text` to stdout and flush it.
///
/// Callers decide how to treat a broken pipe; [`print_help`] maps it to
/// success.
fn write_stdout(text: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}

/// Write `text` to stderr and flush it.
///
/// Callers discard the result: diagnostics must never surface as a panic or
/// backtrace, and a broken pipe while reporting an error must not disturb the
/// intended exit code.
pub fn write_stderr(text: &str) -> io::Result<()> {
    let stderr = io::stderr();
    let mut err = stderr.lock();
    err.write_all(text.as_bytes())?;
    err.flush()
}
