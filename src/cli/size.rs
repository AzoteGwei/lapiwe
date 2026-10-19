//! Parsing for the `--size` and `--max-mem` sizes and for exact
//! `--redundancy` ratios.
//!
//! Both parsers are pure functions: they use integer arithmetic, check for
//! overflow, and never use floating point or randomness. Callers are
//! responsible for mapping errors to a single stderr line and exit status 1.

/// Parse a size for `--size` and `--max-mem`.
///
/// Accepted forms (suffixes are case-sensitive):
///
/// - Plain bytes: `12345`;
/// - `K/M/G/T`: powers of 1024;
/// - `KB/MB/GB/TB`: powers of 1000 (`MB` is 1000-based as well);
/// - `KiB/MiB/GiB/TiB`: aliases for the 1024-based forms, equal to `K/M/G/T`.
///
/// Only unsigned integer digits are accepted: no decimals, signs, or embedded
/// whitespace. A missing digit prefix, an unknown suffix, or overflow of either
/// the digit value or the multiplication returns a one-line error.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let digits_end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, suffix) = text.split_at(digits_end);
    if digits.is_empty() {
        return Err(format!(
            "invalid size `{text}`: must start with a decimal digit (for example `1048576`, `1M`, or `1MiB`)"
        ));
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size `{text}`: numeric part exceeds u64"))?;
    let multiplier: u64 = match suffix {
        "" => 1,
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024u64.pow(3),
        "T" => 1024u64.pow(4),
        "KB" => 1000,
        "MB" => 1000u64.pow(2),
        "GB" => 1000u64.pow(3),
        "TB" => 1000u64.pow(4),
        "KiB" => 1024,
        "MiB" => 1024u64.pow(2),
        "GiB" => 1024u64.pow(3),
        "TiB" => 1024u64.pow(4),
        other => {
            return Err(format!(
                "invalid size `{text}`: unknown suffix `{other}` (valid: bare bytes, K/M/G/T, KB/MB/GB/TB, KiB/MiB/GiB/TiB)"
            ));
        }
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("invalid size `{text}`: multiplication overflows u64"))
}

/// Parse `--redundancy` into an exact rational `R = num/den`, reduced, with
/// `num, den >= 1`.
///
/// - A bare number (`1`, `1.3`, `2.50`) is the total output multiplier and
///   must be at least 1;
/// - `p%` (`30%`, `12.5%`) means `R = 1 + p/100` (`30%` becomes `13/10`,
///   equivalent to `1.3`);
/// - `R < 1`, `0%`, negative values, `NaN`/`inf` text, an empty string, or
///   multiple decimal points produce an error (exit status 1).
///
/// All arithmetic is integer-based; binary floating point is never used.
pub fn parse_redundancy(text: &str) -> Result<(u64, u64), String> {
    let (body, is_percent) = match text.strip_suffix('%') {
        Some(rest) => (rest, true),
        None => (text, false),
    };
    let (num, den) = parse_decimal(body).ok_or_else(|| {
        format!("invalid redundancy `{text}`: expected a bare number >= 1 or `p%` (for example `1.3` or `30%`; negative numbers, NaN, and inf are not accepted)")
    })?;
    if is_percent {
        if num == 0 {
            return Err(format!(
                "invalid redundancy `{text}`: 0% is not allowed (a bare `1` is the valid lower bound)"
            ));
        }
        // R = 1 + p/100 and p = num/den, so R = (100*den + num) / (100*den).
        let out_den = den
            .checked_mul(100)
            .ok_or_else(|| format!("invalid redundancy `{text}`: multiplication overflows u64"))?;
        let out_num = out_den
            .checked_add(num)
            .ok_or_else(|| format!("invalid redundancy `{text}`: addition overflows u64"))?;
        Ok(reduce(out_num, out_den))
    } else {
        if num < den {
            return Err(format!(
                "invalid redundancy `{text}`: R < 1 (the total output multiplier must be at least 1; use the default mode or `--force` for lower redundancy)"
            ));
        }
        Ok(reduce(num, den))
    }
}

/// Parse a non-negative decimal (`N` or `N.F`, with digits on both sides) as
/// an unreduced `num/den`.
fn parse_decimal(text: &str) -> Option<(u64, u64)> {
    let (int_s, frac_s) = match text.split_once('.') {
        Some((a, b)) => (a, b),
        None => (text, ""),
    };
    if int_s.is_empty() || !int_s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !frac_s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // `1.` is rejected because its fractional part is empty, while `1` is
    // accepted; distinguish the two by the presence of a decimal point.
    if text.contains('.') && frac_s.is_empty() {
        return None;
    }
    let mut num: u64 = int_s.parse().ok()?;
    let mut den: u64 = 1;
    for _ in frac_s.bytes() {
        den = den.checked_mul(10)?;
        num = num.checked_mul(10)?;
    }
    if !frac_s.is_empty() {
        let frac: u64 = frac_s.parse().ok()?;
        num = num.checked_add(frac)?;
    }
    Some((num, den))
}

/// Reduce a fraction by its greatest common divisor; `den >= 1`.
fn reduce(num: u64, den: u64) -> (u64, u64) {
    let mut g = gcd(num, den);
    if g == 0 {
        g = 1;
    }
    (num / g, den / g)
}

/// Return the greatest common divisor of `a` and `b` using the Euclidean
/// algorithm.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_accepts_spec_forms() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("1048576"), Ok(1_048_576));
        assert_eq!(parse_size("1K"), Ok(1024));
        assert_eq!(parse_size("1M"), Ok(1_048_576));
        assert_eq!(parse_size("1MiB"), Ok(1_048_576));
        assert_eq!(parse_size("1MB"), Ok(1_000_000), "MB is 1000-based");
        assert_eq!(parse_size("64M"), Ok(67_108_864));
        assert_eq!(parse_size("64MiB"), Ok(67_108_864));
        assert_eq!(parse_size("2G"), Ok(2 * 1024u64.pow(3)));
        assert_eq!(parse_size("2GB"), Ok(2 * 1000u64.pow(3)));
        assert_eq!(parse_size("3T"), Ok(3 * 1024u64.pow(4)));
        assert_eq!(parse_size("4TiB"), Ok(4 * 1024u64.pow(4)));
    }

    #[test]
    fn parse_size_rejects_bad_forms() {
        for text in [
            "", "K", "M", "1m", "1Kb", "1kib", "1Ki", "1.5G", "-1M", "1 M", "１２",
        ] {
            assert!(parse_size(text).is_err(), "`{text}` should be rejected");
        }
        // Overflow: the digit value itself or the multiplication exceeds u64.
        assert!(parse_size("18446744073709551616").is_err());
        assert!(parse_size("17179869184T").is_err());
        assert!(parse_size("18446744073709551615KB").is_err());
    }

    #[test]
    fn parse_redundancy_exact_rationals() {
        assert_eq!(parse_redundancy("1"), Ok((1, 1)));
        assert_eq!(parse_redundancy("1.3"), Ok((13, 10)));
        assert_eq!(parse_redundancy("30%"), Ok((13, 10)), "30% = 1.3");
        assert_eq!(parse_redundancy("2"), Ok((2, 1)));
        assert_eq!(parse_redundancy("2.50"), Ok((5, 2)));
        assert_eq!(parse_redundancy("100%"), Ok((2, 1)));
        assert_eq!(parse_redundancy("12.5%"), Ok((9, 8)));
        assert_eq!(parse_redundancy("1.0"), Ok((1, 1)));
    }

    #[test]
    fn parse_redundancy_rejects_bad_forms() {
        for text in [
            "0", "0.2", "0%", "0.0%", "-1", "-1%", "NaN", "inf", "1e2", ".5", "5.", "", "%",
            "1.2.3",
        ] {
            assert!(
                parse_redundancy(text).is_err(),
                "`{text}` should be rejected"
            );
        }
    }
}
