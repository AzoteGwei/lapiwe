//! Leveling block partition and derivation of `NB` and `K_max`.
//!
//! The leveling rules are fully deterministic: a decoder can reproduce the
//! partition from `(F, T, NB)` alone. Given the input size `F`, the symbol size
//! `T`, and the block count `NB`:
//!
//! ```text
//! S = ceil(F / T);  KS = floor(S / NB);  R = S − NB·KS
//! K_j = KS + (1 if j < R else 0)
//! offset_j = j·KS + min(j, R)
//! ```
//!
//! `S` is the total number of symbols, `KS` the minimum number of symbols per
//! block, and `R` the number of blocks that carry one extra symbol. Blocks
//! `0..R` therefore hold `KS + 1` symbols and the remaining blocks hold `KS`.
//! `offset_j` is the symbol index of the first symbol in block `j`, which gives
//! `offset_0 = 0` and `offset_{j+1} = offset_j + K_j`.
//!
//! Invariants:
//!
//! - Every block holds either `KS` or `KS + 1` symbols, so block sizes differ
//!   by at most one symbol.
//! - The blocks are contiguous, cover all `S` symbols without gaps or overlap,
//!   and end at `offset_NB = S`.
//! - The partition depends only on `(F, T, NB)`, never on the payload bytes.
//! - A valid wire layout additionally requires `KS >= 1` and
//!   `ceil(S / NB) <= 56403`, the RFC 6330 `K'_max` limit.

use crate::container::params::{RFC_KMAX, U24_MAX};

/// A layout defect caused by invalid encoder parameters, a format-level
/// boundary, or a size that cannot be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutDefect {
    /// `F = 0`: an empty input does not define a container.
    ZeroInput,
    /// `T = 0`, an invalid symbol size.
    ZeroSymbolSize,
    /// `NB = 0`.
    NbZero,
    /// `NB > 2²⁴−1`, so it does not fit the 24-bit on-wire field.
    NbTooLarge,
    /// `K_max = 0`, which occurs when the metadata block is smaller than `T`.
    KmaxZero,
    /// `ceil(S / NB) > 56403`, exceeding the RFC 6330 `K'_max` limit.
    KmaxExceeded,
    /// `KS < 1`, which would leave at least one block empty.
    KsZero,
    /// The layout cannot be represented without overflow.
    Overflow,
    /// `M < 2`: the metadata interval is too small.
    MetaEveryTooSmall,
}

/// Return the total symbol count `S = ceil(F / T)`.
///
/// # Errors
///
/// Returns [`LayoutDefect::ZeroInput`] when `F` is zero and
/// [`LayoutDefect::ZeroSymbolSize`] when `T` is zero.
pub fn symbol_count(f: u64, t: u64) -> Result<u64, LayoutDefect> {
    if f == 0 {
        return Err(LayoutDefect::ZeroInput);
    }
    if t == 0 {
        return Err(LayoutDefect::ZeroSymbolSize);
    }
    Ok(f.div_ceil(t))
}

/// Return `NB = max(1, ceil(S / K_max))`, the number of logical blocks.
///
/// # Errors
///
/// Returns [`LayoutDefect::KmaxZero`] when `K_max` is zero and
/// [`LayoutDefect::NbTooLarge`] when the result exceeds `2²⁴−1`.
pub fn derive_nb(s: u64, k_max: u64) -> Result<u32, LayoutDefect> {
    if k_max == 0 {
        return Err(LayoutDefect::KmaxZero);
    }
    let nb = s.div_ceil(k_max).max(1);
    if nb > u64::from(U24_MAX) {
        return Err(LayoutDefect::NbTooLarge);
    }
    Ok(nb as u32)
}

/// A leveling layout derived from `(F, T, NB)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leveling {
    /// Total input size in bytes, `F`.
    pub f: u64,
    /// Symbol size in bytes, `T`.
    pub t: u64,
    /// Total number of symbols, `S`.
    pub s: u64,
    /// Number of logical blocks, `NB`.
    pub nb: u32,
    /// Base block size, `KS = floor(S / NB)`.
    pub ks: u64,
    /// Number of blocks of size `KS + 1`, `R = S − NB·KS`.
    pub r: u64,
}

impl Leveling {
    /// Derive the layout from `(F, T, NB)`.
    ///
    /// All three inputs are fixed-width integers, so the derivation itself
    /// cannot overflow. The format-level bounds (`KS >= 1` and the
    /// `K'_max` limit) are checked separately by [`Leveling::validate_format`].
    ///
    /// # Errors
    ///
    /// Returns [`LayoutDefect::ZeroInput`] or
    /// [`LayoutDefect::ZeroSymbolSize`] when `F` or `T` is zero, and
    /// [`LayoutDefect::NbZero`] when `NB` is zero.
    pub fn derive(f: u64, t: u64, nb: u32) -> Result<Self, LayoutDefect> {
        let s = symbol_count(f, t)?;
        if nb == 0 {
            return Err(LayoutDefect::NbZero);
        }
        let nb64 = u64::from(nb);
        Ok(Leveling {
            f,
            t,
            s,
            nb,
            ks: s / nb64,
            r: s % nb64,
        })
    }

    /// Return the number of symbols `K_j` in block `j`.
    ///
    /// Blocks `0..R` contain `KS + 1` symbols; all others contain `KS`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when `j >= NB`.
    pub fn k_j(&self, j: u32) -> u64 {
        debug_assert!(j < self.nb);
        self.ks + u64::from(u64::from(j) < self.r)
    }

    /// Return the symbol index `offset_j` of the first symbol in block `j`.
    ///
    /// The offsets are cumulative, so `offset_0` is zero and
    /// `offset_{j+1} = offset_j + K_j`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when `j >= NB`.
    pub fn offset_j(&self, j: u32) -> u64 {
        debug_assert!(j < self.nb);
        u64::from(j) * self.ks + u64::from(j).min(self.r)
    }

    /// Return the byte length `K_j·T` of block `j`.
    ///
    /// Returns `None` if the multiplication would overflow. An encoder must
    /// additionally ensure that the result does not exceed `M_blk`, the block
    /// memory budget.
    pub fn block_bytes(&self, j: u32) -> Option<u64> {
        self.k_j(j).checked_mul(self.t)
    }

    /// Return the minimum block size in symbols, `min_j K_j`.
    pub fn min_k(&self) -> u64 {
        self.ks
    }

    /// Return the maximum block size in symbols, `max_j K_j`.
    pub fn max_k(&self) -> u64 {
        if self.r > 0 { self.ks + 1 } else { self.ks }
    }

    /// Validate the format-level bounds: `KS >= 1` and
    /// `ceil(S / NB) <= 56403`, the RFC 6330 `K'_max` limit.
    ///
    /// A container that violates either bound is malformed.
    pub fn validate_format(&self) -> Result<(), LayoutDefect> {
        if self.ks < 1 {
            return Err(LayoutDefect::KsZero);
        }
        if self.s.div_ceil(u64::from(self.nb)) > RFC_KMAX {
            return Err(LayoutDefect::KmaxExceeded);
        }
        Ok(())
    }
}

/// Split `data` into blocks according to the leveling layout.
///
/// The final symbol is zero-padded to `T` bytes, so each returned block is
/// exactly `K_j·T` bytes, an integer multiple of `T`.
///
/// # Errors
///
/// Returns [`LayoutDefect::ZeroInput`] for empty input,
/// [`LayoutDefect::Overflow`] if the input length does not fit in `u64`, or any
/// error reported by [`Leveling::derive`].
pub fn split_blocks(data: &[u8], t: usize, nb: u32) -> Result<Vec<Vec<u8>>, LayoutDefect> {
    if data.is_empty() {
        return Err(LayoutDefect::ZeroInput);
    }
    let f = u64::try_from(data.len()).map_err(|_| LayoutDefect::Overflow)?;
    let lv = Leveling::derive(f, t as u64, nb)?;
    let mut blocks = Vec::with_capacity(nb as usize);
    for j in 0..nb {
        let sym_start = lv.offset_j(j);
        let sym_end = sym_start + lv.k_j(j);
        let byte_start = sym_start * lv.t;
        let byte_end = (sym_end * lv.t).min(f);
        let mut block = data[byte_start as usize..byte_end as usize].to_vec();
        block.resize((lv.k_j(j) * t as u64) as usize, 0u8);
        blocks.push(block);
    }
    Ok(blocks)
}

/// Concatenate `blocks` in block order and truncate the result to `F` bytes,
/// reversing the zero padding added by [`split_blocks`].
pub fn rejoin(blocks: &[Vec<u8>], f: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for block in blocks {
        out.extend_from_slice(block);
    }
    out.truncate(f as usize);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_leveling_example_1025() {
        // Leveling example with `K_max = 64`, `T = 4080`, `S = 1025`.
        let lv = Leveling::derive(4_177_921, 4080, 17).expect("derive layout");
        assert_eq!((lv.s, lv.ks, lv.r), (1025, 60, 5));
        assert_eq!(lv.k_j(0), 61);
        assert_eq!(lv.k_j(4), 61);
        assert_eq!(lv.k_j(5), 60);
        assert_eq!(lv.k_j(16), 60);
        assert_eq!(lv.offset_j(0), 0);
        assert_eq!(lv.offset_j(1), 61);
        assert_eq!(lv.offset_j(5), 305);
        assert_eq!(lv.offset_j(16), 965);
        assert_eq!(lv.validate_format(), Ok(()));
    }

    #[test]
    fn split_and_rejoin_roundtrip() {
        let data: Vec<u8> = (0..4081u32).map(|i| (i % 251) as u8).collect();
        let blocks = split_blocks(&data, 4080, 1).expect("split blocks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 4080 * 2);
        assert!(blocks[0][4081..].iter().all(|&b| b == 0));
        assert_eq!(rejoin(&blocks, data.len() as u64), data);
    }
}
