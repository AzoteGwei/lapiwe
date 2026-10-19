//! Command-line entry point for `lapiwe`, a fountain-coding tool based on
//! RaptorQ (RFC 6330) for data redundancy and recovery in UNIX pipelines.
//!
//! The binary gathers the process arguments, passes them to the `cli` module,
//! and exits with the status code that the dispatcher returns. The `encode`,
//! `decode`, and `inspect` subcommands are implemented under `cli`; the
//! container byte layout and the codec live in the library at
//! `lapiwe::container`.
//!
//! Arguments are collected as `OsString` values so that non-UTF-8 UNIX paths
//! pass through unchanged. Commands that require valid UTF-8 validate their
//! arguments themselves and report an error.
//!
//! Exit status: 0 on success, 1 for other errors, 2 for insufficient data,
//! 3 when no usable OTI is available, and 4 when the BLAKE3 check fails. The
//! dispatcher in `cli` owns the exact mapping.

mod cli;

use std::env;
use std::process::ExitCode;

/// Run the CLI and return the process exit status.
///
/// The program name (`argv[0]`) is skipped; every remaining argument is passed
/// to `cli::dispatch` unchanged.
fn main() -> ExitCode {
    // Use `args_os` rather than `args`: UNIX paths may contain arbitrary bytes,
    // whereas `env::args()` panics when an argument is not valid UTF-8.
    let args: Vec<std::ffi::OsString> = env::args_os().skip(1).collect();
    ExitCode::from(cli::dispatch(&args))
}
