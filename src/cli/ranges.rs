//! Parser for the `--missing-ranges <FILE>` input.
//!
//! The file is UTF-8 text with one range per line:
//!
//! ```text
//! START LENGTH
//! ```
//!
//! `START` and `LENGTH` are separated by whitespace, may be decimal or
//! `0x`-prefixed hexadecimal, and are measured in bytes. Each line denotes the
//! half-open interval `[START, START+LENGTH)`. Blank lines are ignored, as is
//! any text from a `#` character to the end of a line. Ranges may overlap or be
//! adjacent; they are sorted and merged into a canonical list.
//!
//! Malformed lines and invalid numbers produce an error that names the line;
//! the CLI exits with a failure status when that happens.
//!
//! Bounds are not validated here because the total payload size `F` is not yet
//! known. Validation against `[0, F]` happens once the base OTI is established
//! during decoding, where `DecodeEngine::patch_error` reports
//! `RangeOutOfBounds`.

use std::fs;
use std::path::Path;

/// Parse the text of a missing-ranges file into a sorted, merged list of
/// `(start, length)` byte ranges.
///
/// The input syntax is described in the module documentation. Zero-length
/// ranges are dropped, and the remaining ranges are sorted and merged, so the
/// result contains disjoint, non-adjacent intervals.
///
/// # Errors
///
/// Returns an error naming the 1-based line number when a line does not contain
/// exactly two fields, or when either field is not a valid non-negative decimal
/// or `0x` hexadecimal integer.
pub fn parse(text: &str) -> Result<Vec<(u64, u64)>, String> {
    let mut ranges = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        // A `#` starts a comment; strip it before splitting on whitespace.
        let line = match raw.find('#') {
            Some(pos) => &raw[..pos],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(start), Some(len)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "line {line_no} requires two fields, `START LENGTH`: `{line}`"
            ));
        };
        if parts.next().is_some() {
            return Err(format!(
                "line {line_no} has too many fields (expected `START LENGTH`): `{line}`"
            ));
        }
        let start = parse_u64(start).ok_or_else(|| {
            format!(
                "line {line_no}: `{start}` is not a valid non-negative integer (decimal or 0x hex)"
            )
        })?;
        let len = parse_u64(len).ok_or_else(|| {
            format!(
                "line {line_no}: `{len}` is not a valid non-negative integer (decimal or 0x hex)"
            )
        })?;
        if len == 0 {
            // A zero-length range denotes the empty set and is ignored. Bounds
            // checks are left to the caller, which knows `F`.
            continue;
        }
        ranges.push((start, len));
    }
    Ok(merge(ranges))
}

/// Read a missing-ranges file from `path` and parse it.
///
/// # Errors
///
/// Returns an error if the file cannot be read, if its contents are not valid
/// UTF-8, or if parsing fails. Messages that concern the file itself include
/// its display path.
pub fn read(path: &Path) -> Result<Vec<(u64, u64)>, String> {
    let bytes = fs::read(path).map_err(|e| {
        format!(
            "failed to read missing-range file {}: {e} (--missing-ranges requires readable UTF-8 text)",
            path.display()
        )
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("missing-range file {} is not UTF-8 text", path.display()))?;
    parse(&text).map_err(|e| format!("missing-range file {}: {e}", path.display()))
}

/// Parse a decimal or `0x`/`0X` hexadecimal unsigned integer.
///
/// Leading and trailing whitespace must already be removed by the caller. An
/// empty digit sequence, or a value that does not fit in `u64`, yields `None`.
fn parse_u64(text: &str) -> Option<u64> {
    let (radix, digits) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (16, digits),
        None => (10, text),
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Sort `ranges` and merge overlapping or adjacent intervals.
///
/// Zero-length ranges are discarded first. All end calculations use saturating
/// addition, so inputs whose `START + LENGTH` exceeds `u64::MAX` cannot
/// overflow: the function neither panics in debug builds nor wraps in release
/// builds. Such extreme inputs are kept as saturated intervals. Whether they
/// lie outside the payload is decided later by the decoder, which uses checked
/// arithmetic against `F` and reports `RangeOutOfBounds`.
pub fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|&(_, len)| len > 0);
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, len) in ranges {
        match merged.last_mut() {
            // Merge when this interval overlaps or touches the previous one,
            // that is, when `start <= end` of the last interval.
            Some(last) if start <= last.0.saturating_add(last.1) => {
                let end = last.0.saturating_add(last.1).max(start.saturating_add(len));
                last.1 = end - last.0;
            }
            _ => merged.push((start, len)),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_hex_comments_and_blank_lines() {
        let text = "\
# comment line
0 4096      # trailing comment
0x2000 0x1000

   16384   4096
";
        assert_eq!(
            parse(text).expect("parse"),
            vec![(0, 4096), (0x2000, 0x1000), (16384, 4096)]
        );
    }

    #[test]
    fn merges_overlapping_and_adjacent_ranges() {
        assert_eq!(
            parse("0 100\n50 100\n200 10\n").expect("parse"),
            vec![(0, 150), (200, 10)]
        );
        // Adjacent ranges merge as well: here the previous end equals the
        // next start.
        assert_eq!(parse("0 10\n10 10\n").expect("parse"), vec![(0, 20)]);
        // Zero-length ranges are ignored.
        assert_eq!(parse("5 0\n7 3\n").expect("parse"), vec![(7, 3)]);
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            "1\n", "1 2 3\n", "a 1\n", "-1 4\n", "1 x\n", "0x 4\n", "1 0xzz\n",
        ] {
            assert!(parse(bad).is_err(), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn extreme_values_saturate_without_panic() {
        // Values at or above 2^63, including sums that overflow `u64`, must not
        // panic in debug builds. The decoder later rejects out-of-bounds
        // intervals using checked arithmetic against `F`.
        assert_eq!(
            parse("9223372036854775807 9223372036854775807\n").expect("parse"),
            vec![(9_223_372_036_854_775_807, 9_223_372_036_854_775_807)]
        );
        assert_eq!(
            parse("18446744073709551615 1\n").expect("parse"),
            vec![(u64::MAX, 1)]
        );
        // Overlapping extremes merge with saturation: no panic, and the start
        // is preserved.
        assert_eq!(
            parse("18446744073709551614 2\n18446744073709551615 1\n").expect("parse"),
            vec![(u64::MAX - 1, 1)]
        );
        // Hexadecimal input follows the same rules (`0x8000000000000000` is
        // 2^63).
        assert_eq!(
            parse("0x8000000000000000 0x8000000000000000\n").expect("parse"),
            vec![(1 << 63, 1 << 63)]
        );
    }

    #[test]
    fn read_rejects_non_utf8_and_missing_files() {
        let dir = std::env::temp_dir().join(format!("lapiwe-ranges-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let bad = dir.join("bad.bin");
        fs::write(&bad, [0xFFu8, 0xFE, 0x00]).expect("write test file");
        assert!(read(&bad).is_err(), "non-UTF-8 must be rejected");
        assert!(read(&dir.join("nope")).is_err(), "missing file must fail");
        let _ = fs::remove_dir_all(&dir);
    }
}
