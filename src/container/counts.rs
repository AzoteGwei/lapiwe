//! Packet slot and data slot numbering, packet count derivation, and the
//! default minimum output packet count `C_total`.
//!
//! Packet slots are numbered over the output stream. With metadata interval
//! `M`, slot `i` carries a metadata packet when `i mod M == 0`; every other
//! slot carries a data packet. Data slots are numbered separately and increase
//! only for data packets, so metadata packets occupy no data slot:
//!
//! | Quantity | Definition |
//! |----------|------------|
//! | Metadata packets | `C_meta = ceil(C_total / M)` |
//! | Data packets | `D = C_total − C_meta` |
//! | Data slot of a non-metadata slot `i` | `i − (floor(i/M) + 1)` |
//!
//! A stream is publishable when `C_total ≥ 2`, which is equivalent to `D ≥ 1`.
//!
//! `C_total` can be derived from a target stream size (`floor(SIZE / P)`) or
//! from a redundancy ratio (`ceil(F·num / (den·P))`). The default minimum
//! instead finds the smallest data packet count that meets the per-block
//! symbol requirement, then accounts for the metadata packets interleaved with
//! those data packets.

use crate::container::leveling::{LayoutDefect, Leveling, derive_nb, symbol_count};
use crate::container::params::{EPS_MIN_DENOMINATOR, EPS_MIN_NUMERATOR, G, MIN_META_EVERY};

/// Return `needed_j = max(K_j + G, ceil(K_j·(1 + ε_min)))`, the number of
/// distinct data symbols required for block `j` (`ε_min = 0.005`).
///
/// `K_j ≤ 56403` (the format-level upper bound), so `K_j·1005` cannot overflow.
pub fn needed_j(k_j: u64) -> u64 {
    (k_j + G).max((k_j * EPS_MIN_NUMERATOR).div_ceil(EPS_MIN_DENOMINATOR))
}

/// Return the number of distinct data symbols `a_j` actually available to
/// block `j`:
///
/// ```text
/// q = floor(D / NB);  r = D mod NB;  a_j = q + (1 if j < r else 0)
/// ```
pub fn a_j(d: u64, nb: u32, j: u32) -> u64 {
    debug_assert!(nb >= 1 && j < nb);
    let nb64 = u64::from(nb);
    d / nb64 + u64::from(u64::from(j) < d % nb64)
}

/// Redundancy summary: the minimum slack `min(a_j − needed_j)` and the number
/// of blocks with insufficient symbols. Used for the `--force` warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedundancyReport {
    /// `min_j(a_j − needed_j)`; a negative value means effective redundancy is
    /// insufficient.
    pub min_slack: i64,
    /// Number of blocks with `a_j < needed_j`.
    pub affected_blocks: u64,
}

/// Compute the redundancy summary for all blocks in plane order.
///
/// Requires `D ≥ 1`.
pub fn redundancy_report(leveling: &Leveling, d: u64) -> RedundancyReport {
    let mut min_slack = i64::MAX;
    let mut affected_blocks = 0u64;
    for j in 0..leveling.nb {
        let slack = a_j(d, leveling.nb, j) as i64 - needed_j(leveling.k_j(j)) as i64;
        if slack < 0 {
            affected_blocks += 1;
        }
        min_slack = min_slack.min(slack);
    }
    RedundancyReport {
        min_slack,
        affected_blocks,
    }
}

/// Return whether packet slot `i` carries a metadata packet
/// (`i mod M == 0`, with `M ≥ 2`).
pub fn is_meta_slot(i: u64, m: u64) -> bool {
    m >= MIN_META_EVERY && i % m == 0
}

/// Return `C_meta = ceil(C_total / M)`, the number of metadata packets.
///
/// Returns `None` if `M < 2`.
pub fn c_meta(c_total: u64, m: u64) -> Option<u64> {
    (m >= MIN_META_EVERY).then(|| c_total.div_ceil(m))
}

/// Return the number of data packets `D = C_total − C_meta`.
///
/// Returns `None` if `M < 2`.
pub fn data_packets(c_total: u64, m: u64) -> Option<u64> {
    c_meta(c_total, m).map(|meta| c_total - meta)
}

/// Return the data slot index `c` for packet slot `i`.
///
/// Metadata packets do not occupy a data slot and yield `None`. Otherwise
/// `c = i − (floor(i/M) + 1)`.
pub fn data_slot(i: u64, m: u64) -> Option<u64> {
    if m < MIN_META_EVERY {
        return None;
    }
    if i % m == 0 {
        None
    } else {
        Some(i - (i / m + 1))
    }
}

/// Return whether the stream is publishable, which requires `C_total ≥ 2`
/// (equivalently `D ≥ 1`).
pub fn publishable(c_total: u64, m: u64) -> bool {
    data_packets(c_total, m).is_some_and(|d| d >= 1)
}

/// Derive `C_total` from `--size` as `C_total = floor(SIZE / P)`.
///
/// Sizes below `2P` fail the publishability check. Returns `None` when `P = 0`.
pub fn c_total_from_size(size: u64, p: usize) -> Option<u64> {
    (p != 0).then(|| size / p as u64)
}

/// Derive `C_total` from `--redundancy` as
/// `C_total = ceil(F·num / (den·P))`, using exact integer arithmetic.
///
/// `num/den` is the exact fraction for `R` (for example, `1.3 → 13/10`).
/// Values with `R < 1`, `0%`, or negative values are rejected by the CLI;
/// this function only handles positive rationals. Returns `None` for degenerate
/// inputs or when the result does not fit in `u64`.
pub fn c_total_from_redundancy(f: u64, num: u64, den: u64, p: usize) -> Option<u64> {
    if num == 0 || den == 0 || p == 0 {
        return None;
    }
    let numerator = u128::from(f) * u128::from(num);
    let denominator = u128::from(den) * u128::from(p as u64);
    u64::try_from(numerator.div_ceil(denominator)).ok()
}

/// Default `C_total_min` and the inputs used to derive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultTotal {
    /// Minimum number of data packets `D_req` that meets the per-block symbol
    /// requirement.
    pub d_req: u64,
    /// Default output packet count:
    /// `C_total_min = D_req + ceil(D_req / (M−1))`.
    pub c_total_min: u64,
    /// Derived layout (including `NB`, `KS`, and `R`).
    pub leveling: Leveling,
}

/// Derive the default `C_total_min` in O(NB) time using integer arithmetic,
/// with no search, floating point, or randomness.
///
/// `K_max` is supplied by the caller; the default is
/// `min(56403, floor(M_blk / T))`, see
/// [`crate::container::leveling::k_max_from_mem`].
///
/// The symbol count and block layout are derived first. The function then
/// chooses the smallest data packet count `D_req` for which every block `j`
/// has at least `needed_j` distinct symbols. The resulting total includes the
/// metadata packets interleaved with those data packets:
/// `C_total_min = D_req + ceil(D_req / (M−1))`.
///
/// # Errors
///
/// Returns [`LayoutDefect::MetaEveryTooSmall`] if `M < 2` and
/// [`LayoutDefect::Overflow`] if an intermediate value overflows `u64`. Layout
/// defects from [`symbol_count`], [`derive_nb`], and [`Leveling::derive`] are
/// propagated unchanged.
pub fn default_c_total_min(
    f: u64,
    t: u64,
    m: u64,
    k_max: u64,
) -> Result<DefaultTotal, LayoutDefect> {
    if m < MIN_META_EVERY {
        return Err(LayoutDefect::MetaEveryTooSmall);
    }
    let s = symbol_count(f, t)?;
    let nb = derive_nb(s, k_max)?;
    let leveling = Leveling::derive(f, t, nb)?;

    // K_j takes only two values: KS and KS+1, with the first R blocks using
    // KS+1. Walk the prefix and suffix requirements with O(1) state. Because
    // needed_j is non-decreasing in K_j:
    //   suffix[r] = max_{j≥r} needed_j = needed(KS+1) if r < R, else needed(KS);
    //   prefix[r] = max_{j<r}(needed_j − 1), which grows monotonically with r.
    let p1 = needed_j(leveling.max_k());
    let p0 = needed_j(leveling.min_k());
    let nb64 = u64::from(nb);
    let mut prefix = 0u64;
    let mut d_req = u64::MAX;
    for r in 0..nb64 {
        let (suffix, needed_r) = if r < leveling.r { (p1, p1) } else { (p0, p0) };
        let q = prefix.max(suffix);
        let candidate = q
            .checked_mul(nb64)
            .and_then(|v| v.checked_add(r))
            .ok_or(LayoutDefect::Overflow)?;
        d_req = d_req.min(candidate);
        prefix = prefix.max(needed_r - 1);
    }

    let c_total_min = d_req + d_req.div_ceil(m - 1);
    Ok(DefaultTotal {
        d_req,
        c_total_min,
        leveling,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needed_and_a_j_match_spec_examples() {
        assert_eq!(needed_j(1), 5);
        assert_eq!(needed_j(60), 64);
        assert_eq!(needed_j(61), 65);
        assert_eq!(needed_j(258), 262);
        assert_eq!(a_j(1093, 17, 0), 65);
        assert_eq!(a_j(1093, 17, 5), 64);
    }

    #[test]
    fn spec_examples_default_total() {
        let f_1mib = 1024 * 1024;
        let t = 4080;
        let m = 256;
        let k_max = 16_448;

        let r1 = default_c_total_min(1, t, m, k_max).expect("F=1");
        assert_eq!((r1.d_req, r1.c_total_min), (5, 6));

        let r2 = default_c_total_min(4081, t, m, k_max).expect("F=4081");
        assert_eq!((r2.d_req, r2.c_total_min), (6, 7));

        let r3 = default_c_total_min(f_1mib, t, m, k_max).expect("F=1 MiB");
        assert_eq!((r3.d_req, r3.c_total_min), (262, 264));
        assert_eq!(r3.leveling.nb, 1);
    }

    #[test]
    fn spec_leveling_case_default_total() {
        let r = default_c_total_min(4_177_921, 4080, 256, 64).expect("S=1025");
        assert_eq!(r.leveling.nb, 17);
        assert_eq!((r.d_req, r.c_total_min), (1093, 1098));
        assert_eq!(data_packets(r.c_total_min, 256), Some(1093));
    }

    #[test]
    fn data_slot_skips_meta() {
        assert_eq!(data_slot(1, 256), Some(0));
        assert_eq!(data_slot(255, 256), Some(254));
        assert_eq!(data_slot(256, 256), None);
        assert_eq!(data_slot(257, 256), Some(255));
    }
}
