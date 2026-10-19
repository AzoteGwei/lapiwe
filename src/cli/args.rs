//! Command-line argument syntax for the `encode`, `decode`, and `inspect`
//! subcommands.
//!
//! The parser is hand-written and follows these rules:
//!
//! 1. The subcommand must be UTF-8 and must be one of `encode`, `decode`,
//!    `inspect`, `-h`, or `--help`.
//! 2. Long options accept both `--opt value` and `--opt=value`.
//! 3. Every argument after `--` is an operand (`-` still means stdin or
//!    stdout).
//! 4. Before `--`, an argument that starts with `-` and is not exactly `-`
//!    must be a known UTF-8 flag; otherwise parsing fails and the CLI exits
//!    with status 1.
//! 5. All other arguments are path operands and may contain any non-NUL byte.
//! 6. The value of `-o/--output` is accepted verbatim as a path, including `-`
//!    and values such as `-foo`.
//! 7. Values of numeric options must be valid UTF-8.
//!
//! This module performs syntax and numeric parsing only. Cross-option
//! constraints such as mutual exclusion, allowed value sets, and memory
//! budgets are checked in [`finish_encode`] and [`finish_decode`].

use std::ffi::{OsStr, OsString};

use lapiwe::container::encode::TotalSpec;
use lapiwe::container::params::{
    DEFAULT_DECODE_MAX_MEM, DEFAULT_ENCODE_MAX_MEM, DEFAULT_META_EVERY, DEFAULT_PACKET_SIZE,
    MIN_META_EVERY, PACKET_SIZES, RFC_KMAX, is_legal_packet_size, k_max_from_mem, symbol_size,
};
use lapiwe::container::scan::RING_CAP;

use super::size::{parse_redundancy, parse_size};

/// A CLI subcommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Encode,
    Decode,
    Inspect,
}

/// An error produced while parsing or validating arguments.
///
/// The contained message is a single line. The caller adds a command-specific
/// prefix for display and exits with status 1.
#[derive(Debug)]
pub struct ParseError(pub String);

/// Options and operands collected by [`parse`], before semantic validation.
#[derive(Default)]
pub struct RawOpts {
    /// Destination path from `-o/--output`.
    pub output: Option<OsString>,
    /// Raw value of `--size`.
    pub size: Option<String>,
    /// Raw value of `--redundancy`.
    pub redundancy: Option<String>,
    /// Raw value of `--packet-size`.
    pub packet_size: Option<String>,
    /// Raw value of `--meta-every`.
    pub meta_every: Option<String>,
    /// Raw value of `--block-symbols`.
    pub block_symbols: Option<String>,
    /// Raw value of `--max-mem`.
    pub max_mem: Option<String>,
    /// Raw value of `--jobs`.
    pub jobs: Option<String>,
    /// Whether `--force` was given.
    pub force: bool,
    /// Temporary directory from `--spool-dir`.
    pub spool_dir: Option<OsString>,
    /// Whether `--no-verify` was given.
    pub no_verify: bool,
    /// Whether `--stream` was given.
    pub stream: bool,
    /// Whether `-h/--help` was given.
    pub help: bool,
    /// In-place repair target from `--patch <TARGET>`.
    /// Mutually exclusive with `-o/--output`.
    pub patch: Option<OsString>,
    /// Missing-range list from `--missing-ranges <FILE>`.
    /// Only valid together with `--patch`.
    pub missing_ranges: Option<OsString>,
    /// Positional arguments, primarily input paths.
    pub operands: Vec<OsString>,
}

/// An option recognized by the parser.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opt {
    Output,
    Size,
    Redundancy,
    PacketSize,
    MetaEvery,
    BlockSymbols,
    MaxMem,
    Jobs,
    Force,
    SpoolDir,
    NoVerify,
    Stream,
    Patch,
    MissingRanges,
    Help,
}

impl Opt {
    /// Return whether this option consumes a value.
    fn takes_value(self) -> bool {
        !matches!(self, Opt::Force | Opt::NoVerify | Opt::Stream | Opt::Help)
    }
}

/// Look up an option by its flag spelling for `cmd`.
///
/// Return `None` when the flag is unknown or is not valid for the given
/// subcommand; the caller reports that as an error.
fn option_of(cmd: Cmd, name: &str) -> Option<Opt> {
    Some(match name {
        "-h" | "--help" => Opt::Help,
        "-o" | "--output" if cmd != Cmd::Inspect => Opt::Output,
        "--size" if cmd == Cmd::Encode => Opt::Size,
        "--redundancy" if cmd == Cmd::Encode => Opt::Redundancy,
        "--packet-size" if cmd == Cmd::Encode => Opt::PacketSize,
        "--meta-every" if cmd == Cmd::Encode => Opt::MetaEvery,
        "--block-symbols" if cmd == Cmd::Encode => Opt::BlockSymbols,
        // Encoding caps a single block by the memory budget; decoding applies
        // its own limit through `--max-mem`.
        "--max-mem" if cmd != Cmd::Inspect => Opt::MaxMem,
        "--jobs" if cmd != Cmd::Inspect => Opt::Jobs,
        "--force" if cmd == Cmd::Encode => Opt::Force,
        // Temporary storage for stdin input during encoding, and for stdout
        // output and budget spill during decoding.
        "--spool-dir" if cmd != Cmd::Inspect => Opt::SpoolDir,
        "--no-verify" if cmd == Cmd::Decode => Opt::NoVerify,
        "--stream" if cmd == Cmd::Decode => Opt::Stream,
        // In-place repair mode and its missing-range list. Both values are
        // paths, as with `-o`.
        "--patch" if cmd == Cmd::Decode => Opt::Patch,
        "--missing-ranges" if cmd == Cmd::Decode => Opt::MissingRanges,
        _ => return None,
    })
}

/// Return `true` if `arg` starts with a hyphen (byte `0x2D`).
///
/// On Unix the raw bytes are inspected. Other platforms use a lossy UTF-8
/// conversion, which is the closest available approximation.
fn starts_with_dash(arg: &OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        arg.as_bytes().first() == Some(&b'-')
    }
    #[cfg(not(unix))]
    {
        arg.to_string_lossy().starts_with('-')
    }
}

/// Parse the argument list for `cmd` into raw options and operands.
///
/// Arguments are scanned from left to right. Before `--`, any argument that
/// begins with `-` and is not exactly `-` is parsed as a flag; all other
/// arguments become operands. Long options accept both `--opt value` and
/// `--opt=value`. After `--`, every remaining argument is an operand.
///
/// # Errors
///
/// Returns [`ParseError`] if a flag is not valid UTF-8, is unknown for `cmd`,
/// is given a value when it does not accept one, or is missing a value.
/// Numeric option values must also be UTF-8. Cross-option validation is
/// deferred to [`finish_encode`], [`finish_decode`], and [`finish_inspect`].
pub fn parse(cmd: Cmd, args: &[OsString]) -> Result<RawOpts, ParseError> {
    let mut opts = RawOpts::default();
    let mut end_of_flags = false;
    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        idx += 1;
        if end_of_flags || arg == "-" || !starts_with_dash(arg) {
            opts.operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            end_of_flags = true;
            continue;
        }
        let Some(text) = arg.to_str() else {
            return Err(ParseError(format!(
                "unknown argument (not UTF-8; flags must be UTF-8): `{}`",
                arg.to_string_lossy()
            )));
        };
        let (name, inline) = match text.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (text, None),
        };
        let Some(opt) = option_of(cmd, name) else {
            return Err(ParseError(format!(
                "unknown argument `{name}` (flags must be UTF-8; arguments after `--` are operands)"
            )));
        };
        if !opt.takes_value() {
            if inline.is_some() {
                return Err(ParseError(format!("`{name}` does not take a value")));
            }
            match opt {
                Opt::Force => opts.force = true,
                Opt::NoVerify => opts.no_verify = true,
                Opt::Stream => opts.stream = true,
                Opt::Help => opts.help = true,
                _ => unreachable!("options that take a value were handled above"),
            }
            continue;
        }
        // The value of `-o/--output` is taken verbatim as a path, even when it
        // starts with a hyphen. The path values of `--patch` and
        // `--missing-ranges` are handled the same way.
        let value: OsString = match inline {
            Some(v) => OsString::from(v),
            None => {
                let Some(v) = args.get(idx) else {
                    return Err(ParseError(format!("option `{name}` requires a value")));
                };
                idx += 1;
                v.clone()
            }
        };
        match opt {
            Opt::Output => opts.output = Some(value),
            Opt::SpoolDir => opts.spool_dir = Some(value),
            Opt::Patch => opts.patch = Some(value),
            Opt::MissingRanges => opts.missing_ranges = Some(value),
            Opt::Size
            | Opt::Redundancy
            | Opt::PacketSize
            | Opt::MetaEvery
            | Opt::BlockSymbols
            | Opt::MaxMem
            | Opt::Jobs => {
                let Some(text) = value.to_str() else {
                    return Err(ParseError(format!("value of `{name}` must be UTF-8")));
                };
                match opt {
                    Opt::Size => opts.size = Some(text.to_owned()),
                    Opt::Redundancy => opts.redundancy = Some(text.to_owned()),
                    Opt::PacketSize => opts.packet_size = Some(text.to_owned()),
                    Opt::MetaEvery => opts.meta_every = Some(text.to_owned()),
                    Opt::BlockSymbols => opts.block_symbols = Some(text.to_owned()),
                    Opt::MaxMem => opts.max_mem = Some(text.to_owned()),
                    Opt::Jobs => opts.jobs = Some(text.to_owned()),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!("flag options were handled above"),
        }
    }
    Ok(opts)
}

/// Return the single `<IN>` operand.
///
/// Exactly one operand is required. Zero or multiple operands are rejected;
/// the error for multiple operands reminds the caller to use `--` when a path
/// itself starts with `-`.
fn single_operand(opts: &RawOpts) -> Result<OsString, ParseError> {
    match opts.operands.len() {
        1 => Ok(opts.operands[0].clone()),
        0 => Err(ParseError(
            "missing operand <IN> (`-` means stdin)".to_owned(),
        )),
        n => Err(ParseError(format!(
            "too many operands ({n}): exactly one <IN> is accepted (use `--` for paths that start with `-`)"
        ))),
    }
}

/// Parse a positive decimal integer option value.
///
/// A value that is not a decimal unsigned integer representable as `u64`
/// produces a [`ParseError`] naming the offending flag.
fn parse_positive(text: &str, flag: &str) -> Result<u64, ParseError> {
    match text.parse::<u64>() {
        Ok(v) => Ok(v),
        Err(_) => Err(ParseError(format!(
            "value of `{flag}` must be a positive decimal integer: `{text}` is invalid"
        ))),
    }
}

/// Return the default `--jobs` value: the number of available logical cores.
///
/// Fall back to 1 if the platform cannot report a parallelism value.
pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Upper bound on `--jobs`.
///
/// Very high parallelism could otherwise make `thread::spawn` fail and panic.
/// Values above this limit are rejected as invalid, with a single-line error
/// that states the allowed range. The limit is far above the logical core
/// count of any realistic machine, so normal use (the default is the number of
/// logical cores) is unaffected.
pub const MAX_JOBS: usize = 1024;

/// Parse and validate `--jobs`.
///
/// The allowed range is 1 through [`MAX_JOBS`]. When the option is absent,
/// return [`default_jobs`].
fn parse_jobs(raw: &Option<String>, flag: &str) -> Result<usize, ParseError> {
    let Some(text) = raw else {
        return Ok(default_jobs());
    };
    let v = parse_positive(text, flag)?;
    if v == 0 {
        return Err(ParseError(format!(
            "`{flag} 0` is invalid: parallelism must be in 1..={MAX_JOBS} (default: available logical CPUs)"
        )));
    }
    let v =
        usize::try_from(v).map_err(|_| ParseError(format!("value of `{flag}` is too large")))?;
    if v > MAX_JOBS {
        return Err(ParseError(format!(
            "`{flag} {v}` is invalid: parallelism must be in 1..={MAX_JOBS} (default: available logical CPUs)"
        )));
    }
    Ok(v)
}

/// Validated arguments for the `encode` subcommand.
pub struct EncodeArgs {
    /// Input path; `-` means stdin.
    pub input: OsString,
    /// Output path. `None` selects the default name (`<IN>.lpw`); when `<IN>`
    /// is `-`, output goes to stdout.
    pub output: Option<OsString>,
    /// Requested output size or redundancy.
    pub total: TotalSpec,
    /// Packet size in bytes.
    pub p: usize,
    /// Number of data packets between metadata packets.
    pub m: u64,
    /// Maximum number of symbols per logical block.
    pub k_max: u64,
    /// Memory budget for a single block, in bytes.
    pub max_mem: u64,
    /// Number of worker threads.
    pub jobs: usize,
    /// Whether `--force` was given, allowing best-effort encoding when the
    /// requested redundancy cannot be met.
    pub force: bool,
    /// Temporary directory, or `None` for the default.
    pub spool_dir: Option<OsString>,
}

/// Validate the parsed `encode` options and build [`EncodeArgs`].
///
/// Checks run in a fixed order so that invalid input yields reproducible
/// errors. `--size` and `--redundancy` are mutually exclusive.
/// `--packet-size` must name a supported packet size and `--meta-every` must
/// be at least [`MIN_META_EVERY`]. The memory budget must be large enough for
/// at least one symbol, and an explicit `--block-symbols` value must be in
/// range and fit within that budget. Finally, `--size` must resolve to at
/// least two packets.
///
/// # Errors
///
/// Returns [`ParseError`] if an operand is missing or duplicated, a numeric
/// value is malformed, mutually exclusive options are combined, or the
/// requested parameters cannot satisfy the memory budget.
pub fn finish_encode(raw: RawOpts) -> Result<EncodeArgs, ParseError> {
    let input = single_operand(&raw)?;

    // `--size` and `--redundancy` are mutually exclusive.
    if raw.size.is_some() && raw.redundancy.is_some() {
        return Err(ParseError(
            "`--size` and `--redundancy` are mutually exclusive: both may be omitted, but only one may be given"
                .to_owned(),
        ));
    }

    // Packet size.
    let p = match &raw.packet_size {
        None => DEFAULT_PACKET_SIZE,
        Some(text) => {
            let v = parse_positive(text, "--packet-size")?;
            let v = usize::try_from(v).unwrap_or(usize::MAX);
            if !is_legal_packet_size(v) {
                return Err(ParseError(format!(
                    "invalid packet size `{text}` (P = 2048*2^k, k in [0,5]); valid values: {}",
                    legal_packet_sizes()
                )));
            }
            v
        }
    };
    let t = symbol_size(p).expect("a valid P always has a T");

    // Metadata interval.
    let m = match &raw.meta_every {
        None => DEFAULT_META_EVERY,
        Some(text) => {
            let v = parse_positive(text, "--meta-every")?;
            if v < MIN_META_EVERY {
                return Err(ParseError(format!(
                    "`--meta-every {v}` is invalid: M must be >= 2 (default 256)"
                )));
            }
            v
        }
    };

    // Memory budget for a single block. The default is 16 MiB, parsed with
    // the same size parser used for `--size`.
    let max_mem = match &raw.max_mem {
        None => DEFAULT_ENCODE_MAX_MEM,
        Some(text) => parse_size(text).map_err(ParseError)?,
    };
    let auto_k_max = k_max_from_mem(max_mem, p).ok_or_else(|| {
        ParseError(format!(
            "`--max-mem` is smaller than the symbol size T={t}: increase it to at least {t} (a symbol needs at least T bytes under the current packet size)"
        ))
    })?;

    // Maximum symbols per logical block. An explicit value is checked against
    // the valid range and the memory budget; it is never silently lowered.
    let k_max = match &raw.block_symbols {
        None => auto_k_max,
        Some(text) => {
            let v = parse_positive(text, "--block-symbols")?;
            if !(1..=RFC_KMAX).contains(&v) {
                return Err(ParseError(format!(
                    "`--block-symbols {v}` is invalid: valid range is 1..={RFC_KMAX} (default: automatic)"
                )));
            }
            if v.checked_mul(t as u64).is_none_or(|bytes| bytes > max_mem) {
                return Err(ParseError(format!(
                    "explicit `--block-symbols {v}` makes K_max*T = {} bytes > max_mem = {max_mem} bytes; \
                     suggested K_max = floor(max_mem/T) = {}",
                    v.saturating_mul(t as u64),
                    max_mem / t as u64
                )));
            }
            v
        }
    };

    // Parallelism. Out-of-range values produce a single-line error rather
    // than a thread-creation panic.
    let jobs = parse_jobs(&raw.jobs, "--jobs")?;

    // Requested output size. It must cover at least two packets.
    let total = if let Some(text) = &raw.size {
        let size = parse_size(text).map_err(ParseError)?;
        if size / (p as u64) < 2 {
            return Err(ParseError(format!(
                "`--size {text}` is too small: C_total = floor(SIZE/P) = {} < 2; \
                 increase --size to at least 2P = {} bytes, or use the default mode",
                size / p as u64,
                (p as u64).saturating_mul(2)
            )));
        }
        TotalSpec::Size(size)
    } else if let Some(text) = &raw.redundancy {
        let (num, den) = parse_redundancy(text).map_err(ParseError)?;
        TotalSpec::Redundancy { num, den }
    } else {
        TotalSpec::Default
    };

    Ok(EncodeArgs {
        input,
        output: raw.output,
        total,
        p,
        m,
        k_max,
        max_mem,
        jobs,
        force: raw.force,
        spool_dir: raw.spool_dir,
    })
}

/// Return the supported packet sizes as a comma-separated list for error
/// messages.
pub fn legal_packet_sizes() -> String {
    PACKET_SIZES
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Validated arguments for the `decode` subcommand.
pub struct DecodeArgs {
    /// Input path; `-` means stdin.
    pub input: OsString,
    /// Output path from `-o/--output`, or `None` when none was given.
    pub output: Option<OsString>,
    /// Whether symbol verification is disabled.
    pub no_verify: bool,
    /// Whether `--stream` was given.
    pub stream: bool,
    /// Decode parallelism. When greater than 1, blocks are solved in parallel;
    /// the result does not depend on this value.
    pub jobs: usize,
    /// Memory budget for decoding. Must be greater than [`RING_CAP`];
    /// otherwise the engine budget is zero and no data can be recovered.
    pub max_mem: u64,
    /// Directory for spooled stdout output and spilled repair symbols.
    /// `None` uses `$TMPDIR`.
    pub spool_dir: Option<OsString>,
    /// In-place repair target from `--patch TARGET`. The target is written
    /// directly; `-o/--output` is not used in this mode.
    pub patch: Option<OsString>,
    /// File listing missing byte ranges from `--missing-ranges FILE`.
    /// Only valid together with `--patch`.
    pub missing_ranges: Option<OsString>,
}

/// Validate the parsed `decode` options and build [`DecodeArgs`].
///
/// `--patch` and `-o/--output` are mutually exclusive, `--missing-ranges`
/// requires `--patch`, and `--patch` cannot be combined with `--stream`.
/// `--stream` additionally requires output to be stdout, either through
/// `-o -` or through an input of `-` with no output flag. The memory budget
/// must exceed the scanner ring buffer, and `--jobs` must be within range.
///
/// # Errors
///
/// Returns [`ParseError`] when an operand is missing or duplicated, an option
/// combination is rejected, or a numeric option is malformed or out of range.
pub fn finish_decode(raw: RawOpts) -> Result<DecodeArgs, ParseError> {
    let input = single_operand(&raw)?;
    // In-place repair writes directly to its target, so `--patch` cannot be
    // combined with `-o/--output` or `--stream`. A missing-range list is only
    // meaningful together with `--patch`.
    if raw.patch.is_some() && raw.output.is_some() {
        return Err(ParseError(
            "`--patch` and `-o/--output` are mutually exclusive: in-place repair writes directly to TARGET"
                .to_owned(),
        ));
    }
    if raw.missing_ranges.is_some() && raw.patch.is_none() {
        return Err(ParseError(
            "`--missing-ranges` is only valid together with `--patch`".to_owned(),
        ));
    }
    if raw.stream && raw.patch.is_some() {
        return Err(ParseError(
            "`--patch` and `--stream` are mutually exclusive: in-place repair writes TARGET and produces no stdout output"
                .to_owned(),
        ));
    }
    // Parallelism: same allowed range as for encode. Blocks are solved in
    // parallel when jobs > 1; the result is independent of this value.
    let jobs = parse_jobs(&raw.jobs, "--jobs")?;
    let max_mem = match &raw.max_mem {
        None => DEFAULT_DECODE_MAX_MEM,
        Some(text) => parse_size(text).map_err(ParseError)?,
    };
    // The scanner ring buffer is always reserved. At or below that size the
    // engine budget is zero and every data symbol would be discarded, so reject
    // the value instead of accepting parameters that can never succeed.
    if max_mem <= RING_CAP as u64 {
        return Err(ParseError(format!(
            "`--max-mem` is too small ({max_mem} bytes): the scan ring buffer alone is {RING_CAP} bytes; \
             the decoder engine budget would be zero; increase it above {RING_CAP} (default: 64MiB)"
        )));
    }
    let output_is_stdout = match &raw.output {
        Some(o) => o == "-",
        None => input == "-",
    };
    // `--stream` is only meaningful when decoding writes to stdout.
    if raw.stream && !output_is_stdout {
        return Err(ParseError(
            "`--stream` is only valid when output is stdout (`-o -`)".to_owned(),
        ));
    }
    Ok(DecodeArgs {
        input,
        output: raw.output,
        no_verify: raw.no_verify,
        stream: raw.stream,
        jobs,
        max_mem,
        spool_dir: raw.spool_dir,
        patch: raw.patch,
        missing_ranges: raw.missing_ranges,
    })
}

/// Validated arguments for the `inspect` subcommand.
///
/// Inspection is read-only and accepts no `-o/--output`.
pub struct InspectArgs {
    /// Container path; `-` means stdin.
    pub input: OsString,
}

/// Validate the parsed `inspect` options and build [`InspectArgs`].
///
/// The only check is that exactly one input operand was given; `parse` already
/// rejects options that are not valid for this subcommand.
///
/// # Errors
///
/// Returns [`ParseError`] if no operand or more than one operand was given.
pub fn finish_inspect(raw: RawOpts) -> Result<InspectArgs, ParseError> {
    let input = single_operand(&raw)?;
    Ok(InspectArgs { input })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_equals_and_space_forms() {
        let raw = parse(Cmd::Encode, &os(&["--size=13G", "f.bin"])).expect("parse");
        assert_eq!(raw.size.as_deref(), Some("13G"));
        let raw = parse(Cmd::Encode, &os(&["--size", "13G", "f.bin"])).expect("parse");
        assert_eq!(raw.size.as_deref(), Some("13G"));
    }

    #[test]
    fn double_dash_ends_flags() {
        let raw = parse(Cmd::Encode, &os(&["--", "-foo"])).expect("parse");
        assert_eq!(raw.operands, os(&["-foo"]));
        assert!(raw.size.is_none());
        // After `--`, `-h` is an operand and does not trigger help.
        let raw = parse(Cmd::Encode, &os(&["--", "-h"])).expect("parse");
        assert!(!raw.help);
        assert_eq!(raw.operands, os(&["-h"]));
    }

    #[test]
    fn output_takes_dash_leading_paths() {
        let raw = parse(Cmd::Encode, &os(&["-o", "-foo", "in.bin"])).expect("parse");
        assert_eq!(raw.output.as_deref(), Some(OsStr::new("-foo")));
        let raw = parse(Cmd::Encode, &os(&["--output=-foo", "in.bin"])).expect("parse");
        assert_eq!(raw.output.as_deref(), Some(OsStr::new("-foo")));
        // A value of exactly `-` for `-o` means stdout; interpretation is left
        // to the caller.
        let raw = parse(Cmd::Encode, &os(&["-o", "-", "in.bin"])).expect("parse");
        assert_eq!(raw.output.as_deref(), Some(OsStr::new("-")));
    }

    #[test]
    fn unknown_and_valueless_flags_reject() {
        assert!(parse(Cmd::Encode, &os(&["--bogus", "in"])).is_err());
        assert!(parse(Cmd::Encode, &os(&["-x", "in"])).is_err());
        assert!(parse(Cmd::Encode, &os(&["--force=x", "in"])).is_err());
        assert!(parse(Cmd::Encode, &os(&["--size"])).is_err(), "no value");
        // Options are scoped to their subcommand and cannot be used across
        // commands.
        assert!(parse(Cmd::Encode, &os(&["--no-verify", "in"])).is_err());
        assert!(parse(Cmd::Decode, &os(&["--size", "1M", "in"])).is_err());
        assert!(parse(Cmd::Inspect, &os(&["-o", "-", "in"])).is_err());
        assert!(parse(Cmd::Inspect, &os(&["--spool-dir", "d", "in"])).is_err());
    }

    #[test]
    fn decode_accepts_spool_dir() {
        // Decode's spool directory for stdout output and budget spill; both
        // forms are equivalent.
        let raw = parse(Cmd::Decode, &os(&["--spool-dir", "spool", "in.lpw"])).expect("parse");
        let args = finish_decode(raw).expect("validate");
        assert_eq!(args.spool_dir.as_deref(), Some(OsStr::new("spool")));
        let raw = parse(Cmd::Decode, &os(&["--spool-dir=spool", "in.lpw"])).expect("parse");
        assert_eq!(raw.spool_dir.as_deref(), Some(OsStr::new("spool")));
        // Omitting the option leaves the directory unset, so the CLI runtime
        // falls back to `$TMPDIR`.
        let args =
            finish_decode(parse(Cmd::Decode, &os(&["in.lpw"])).expect("parse")).expect("validate");
        assert!(args.spool_dir.is_none());
    }

    #[test]
    fn decode_patch_flags_and_exclusions() {
        // Parse `--patch TARGET [--missing-ranges FILE]` in both forms; the
        // values are paths and may start with a hyphen.
        let raw = parse(
            Cmd::Decode,
            &os(&["--patch", "tgt.bin", "--missing-ranges", "m.txt", "in.lpw"]),
        )
        .expect("parse");
        let args = finish_decode(raw).expect("validate");
        assert_eq!(args.patch.as_deref(), Some(OsStr::new("tgt.bin")));
        assert_eq!(args.missing_ranges.as_deref(), Some(OsStr::new("m.txt")));
        let raw = parse(
            Cmd::Decode,
            &os(&["--patch=tgt.bin", "--missing-ranges=m.txt", "in.lpw"]),
        )
        .expect("parse");
        let args = finish_decode(raw).expect("validate");
        assert_eq!(args.patch.as_deref(), Some(OsStr::new("tgt.bin")));
        // `--patch` alone, without a missing-range list, is valid.
        let args = finish_decode(
            parse(Cmd::Decode, &os(&["--patch", "tgt.bin", "in.lpw"])).expect("parse"),
        )
        .expect("validate");
        assert!(args.missing_ranges.is_none());

        // Mutual exclusion and combination checks. Exit status handling belongs
        // to the CLI layer; these tests verify rejection only.
        assert!(
            finish_decode(
                parse(Cmd::Decode, &os(&["--patch", "t", "-o", "out", "in.lpw"]),).expect("parse"),
            )
            .is_err()
        );
        assert!(
            finish_decode(
                parse(Cmd::Decode, &os(&["--missing-ranges", "m.txt", "in.lpw"])).expect("parse"),
            )
            .is_err()
        );
        assert!(
            finish_decode(
                parse(Cmd::Decode, &os(&["--patch", "t", "--stream", "in.lpw"]),).expect("parse"),
            )
            .is_err()
        );
        // Subcommand scoping: encode and inspect reject `--patch` and
        // `--missing-ranges`.
        assert!(parse(Cmd::Encode, &os(&["--patch", "t", "in"])).is_err());
        assert!(parse(Cmd::Inspect, &os(&["--missing-ranges", "m", "in"])).is_err());
        assert!(parse(Cmd::Decode, &os(&["--patch"])).is_err(), "no value");
    }

    #[test]
    fn finish_encode_defaults_and_ranges() {
        let args =
            finish_encode(parse(Cmd::Encode, &os(&["f.bin"])).expect("parse")).expect("validate");
        assert_eq!(args.p, 4096);
        assert_eq!(args.m, 256);
        // Default encode budget is 16 MiB; K_max = floor(16 MiB / 4080) = 4112.
        assert_eq!(args.max_mem, DEFAULT_ENCODE_MAX_MEM);
        assert_eq!(args.k_max, 4_112);
        assert_eq!(args.total, TotalSpec::Default);
        assert!(!args.force);

        let args = finish_encode(
            parse(
                Cmd::Encode,
                &os(&["--size", "1MiB", "--packet-size", "2048", "f"]),
            )
            .expect("parse"),
        )
        .expect("validate");
        assert_eq!(args.total, TotalSpec::Size(1_048_576));
        assert_eq!(args.p, 2048);
        // Default table: P=2048 gives K_max = 8,256.
        assert_eq!(args.k_max, 8_256);

        let args =
            finish_encode(parse(Cmd::Encode, &os(&["--redundancy", "30%", "f"])).expect("parse"))
                .expect("validate");
        assert_eq!(args.total, TotalSpec::Redundancy { num: 13, den: 10 });
    }

    #[test]
    fn finish_encode_rejects_degenerate() {
        let cases: [&[&str]; 8] = [
            &["--size", "1M", "--redundancy", "1.3", "f"], // mutually exclusive
            &["--size", "4096", "f"],                      // below 2P
            &["--packet-size", "3000", "f"],               // unsupported packet size
            &["--meta-every", "1", "f"],                   // metadata interval below 2
            &["--block-symbols", "0", "f"],                // out of range
            &["--block-symbols", "56404", "f"],            // out of range
            &["--max-mem", "2031", "f"],                   // below symbol size T
            &["--block-symbols", "20000", "f"],            // K·T exceeds the 16 MiB default
        ];
        for args in cases {
            assert!(
                finish_encode(parse(Cmd::Encode, &os(args)).expect("parse")).is_err(),
                "{args:?} should be rejected"
            );
        }
        // Too many operands, then too few.
        assert!(finish_encode(parse(Cmd::Encode, &os(&["a", "b"])).expect("parse")).is_err());
        assert!(finish_encode(parse(Cmd::Encode, &os(&[])).expect("parse")).is_err());
    }
}
