//! Byte-level `.lpw` container format and its encoding and decoding engine.
//!
//! The container stores a byte blob as a sequence of fixed-size packets, each
//! beginning with a 16-byte micro-header. The header carries the on-wire
//! format version (4), the block index, the encoding symbol ID and the packet
//! size code. Every `M`-th packet slot (`M >= 2`) is a metadata packet whose
//! payload starts with a 48-byte OTI record; the remaining slots are data
//! packets carrying RaptorQ encoding symbols. Multi-byte integers are
//! big-endian.
//!
//! Submodule layout:
//!
//! - [`params`]: packet sizes, symbol-size limits, the `SYNC` magic, format and
//!   scheme versions, and memory defaults;
//! - [`header`]: 16-byte micro-header codec, frame validation and the CRC-32C
//!   coverage range;
//! - [`meta`]: 48-byte OTI codec and validation, metadata packet layout, and
//!   reference OTI tracking;
//! - [`leveling`]: deterministic leveling into logical blocks and derivation of
//!   `(S, KS, R, K_j, offset_j)`;
//! - [`counts`]: packet and data slots, the three sources of `C_total`, the
//!   default `C_total_min` and redundancy reporting;
//! - [`encode`]: RaptorQ encoder and the two-pass encoding pipeline (a prescan
//!   for `F` and the BLAKE3 digest, then per-block encoding);
//! - [`decode`]: decoding engine, including packet dispatch and deduplication,
//!   write-through, block settlement, final verification and patch mode;
//! - [`ledger`]: decode-side storage with a write-through sink, an arrival
//!   bitmap and inline or spilled repair symbols;
//! - [`scan`]: streaming scanner for non-seekable inputs, using a fixed 64 KiB
//!   window with a one-byte slide and per-scan statistics;
//! - [`outcome`]: the five decode outcome classes and their exit codes.
//!
//! A decoder needs no out-of-band metadata: the first valid metadata packet
//! establishes the reference OTI, from which the symbol size, block count and
//! leveling layout are derived. CRC-32C is used for fast frame rejection,
//! while the BLAKE3-256 digest in the OTI is the authoritative integrity check.
//! No function uses a random source, so the output depends only on the input.
//!
//! The command-line interface lives in the binary crate and adds no library
//! API.

pub mod counts;
pub mod decode;
pub mod encode;
pub mod header;
pub mod ledger;
pub mod leveling;
pub mod meta;
pub mod outcome;
pub mod params;
pub mod scan;
