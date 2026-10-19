//! Streaming ring scanner and scan statistics.
//!
//! The scanner locates candidate frames byte by byte in a fixed-capacity
//! sliding window ([`RING_CAP`] = `max(P)` = 64 KiB) over a **non-seekable**
//! byte stream. On a `SYNC` match it reads the 16-byte microheader, derives
//! `P` from `PKT_CODE & 0x07`, reads the whole packet, and hands it to a judge
//! that validates the frame structure and `CRC-32C`. On failure it advances by
//! one byte and continues scanning.
//!
//! Guarantees:
//!
//! - **Bounded memory**: the window is allocated once at construction with
//!   [`RING_CAP`] bytes and is afterwards only read, written, and compacted; it
//!   never grows. [`ScanStats::peak_buffered`] is always ≤ [`RING_CAP`],
//!   independent of input length, so even an arbitrarily corrupt stream cannot
//!   exhaust memory.
//! - **EOF and truncation safety**: if the microheader or the full packet
//!   cannot be read, the candidate is counted in [`ScanStats::truncated`] and
//!   the scan advances by one byte. The scanner never panics and never yields a
//!   partial frame.
//! - **Non-seekable input**: only the sequential [`Read`] interface is used.
//! - **Byte-wise sliding**: a failed candidate advances by exactly one byte;
//!   the scanner neither aligns nor skips.
//! - **Single validation pass**: the frame verdict (structure and CRC) comes
//!   from the callback passed to [`RingScanner::run`] ([`scan_into`] uses a
//!   [`DecodeEngine`] as the judge), and each candidate's CRC is computed only
//!   once.
//!
//! Implementation note: the window is a contiguous fixed-capacity sliding
//! buffer, and discarding a prefix compacts it with `copy_within`. This is
//! equivalent to a ring buffer (capacity of at least 64 KiB, byte-wise sliding,
//! bounded memory), but a candidate frame is always contiguous in the window
//! and can be passed to the decode engine without copying. The work per
//! candidate is proportional to `P`.

use std::io::{self, Read};

use crate::container::decode::{DecodeEngine, PacketDisposition};
use crate::container::header::FrameDefect;
use crate::container::params::{
    MAX_PACKET_SIZE, MICROHEADER_LEN, SYNC, is_legal_packet_code, packet_size_from_code,
};

/// Window capacity: `max(P) = 64 KiB`.
///
/// This is a single fixed allocation; the number of bytes resident in the
/// window never exceeds this value.
pub const RING_CAP: usize = MAX_PACKET_SIZE;

/// Scan statistics for the decode path. Metadata counters such as `agree_meta`
/// are kept in [`DecodeEngine`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Total number of bytes actually read from the underlying [`Read`] (stops
    /// growing at EOF).
    pub bytes_scanned: u64,
    /// Number of `SYNC` matches; every match found during the byte-wise scan is
    /// counted.
    pub sync_candidates: u64,
    /// Candidates read in full but rejected because `CRC32C` did not match.
    pub crc_failures: u64,
    /// Frames read in full but rejected for a non-CRC structural defect
    /// (including `BLK_IDX ≥ NB`).
    pub bad_frames: u64,
    /// Candidates where `PKT_CODE & 0x07 > 5`, so no valid `P` can be determined
    /// (they are not passed to the judge).
    pub bad_code: u64,
    /// EOF truncation: candidates where the microheader or the full packet could
    /// not be read (each advances by one byte).
    pub truncated: u64,
    /// Peak number of bytes resident in the window; always ≤ [`RING_CAP`], which
    /// bounds memory use.
    pub peak_buffered: usize,
}

/// Verdict returned by the judge for a candidate frame; the scanner uses it to
/// decide how far to advance the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameVerdict {
    /// The frame is valid (structure and CRC pass): advance by the whole packet
    /// (`P` bytes).
    Accepted,
    /// The frame is invalid: advance by one byte and continue. `defect` is used
    /// only for statistics.
    Rejected(FrameDefect),
}

/// Fixed-capacity streaming scanner that slides one byte at a time.
///
/// [`scan_into`] is the recommended entry point for decoding. `run` may also be
/// used directly, for example to inspect each candidate.
pub struct RingScanner<R: Read> {
    reader: R,
    /// Fixed-capacity window; `buf[..len]` holds the currently resident bytes.
    buf: Vec<u8>,
    /// Number of valid bytes in the window (always ≤ `buf.len()`).
    len: usize,
    /// Length of the window prefix known to contain no `SYNC` match: no frame
    /// can start before this position.
    search_start: usize,
    /// The underlying stream has reached EOF.
    eof: bool,
    /// Counters accumulated during scanning.
    stats: ScanStats,
}

impl<R: Read> RingScanner<R> {
    /// Create a scanner. The window is sized to [`RING_CAP`] immediately and no
    /// further allocation occurs.
    pub fn new(reader: R) -> Self {
        RingScanner {
            reader,
            buf: vec![0u8; RING_CAP],
            len: 0,
            search_start: 0,
            eof: false,
            stats: ScanStats::default(),
        }
    }

    /// Return the window capacity (at least `max(P)` = 64 KiB; it does not grow
    /// with input).
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Return the number of bytes currently resident in the window (always
    /// ≤ [`Self::capacity`]).
    pub fn buffered(&self) -> usize {
        self.len
    }

    /// Return a snapshot of the scan statistics.
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// Scan the entire stream, calling `judge` for every complete candidate
    /// frame and advancing by the whole packet or by one byte according to its
    /// verdict.
    ///
    /// `judge` should only inspect the frame contents and must not retain the
    /// borrowed frame: the next read or call to [`Self::run`] reuses the
    /// window.
    pub fn run<F>(&mut self, judge: F) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> FrameVerdict,
    {
        self.run_until(judge, || false)
    }

    /// Like [`Self::run`], but calls `stop` after each verdict and returns
    /// immediately when it is true.
    ///
    /// This lets the CLI stop reading and decoding early, for example when the
    /// output pipe is closed (`EPIPE`). `stop` should perform only cheap
    /// checks.
    pub fn run_until<F, S>(&mut self, mut judge: F, mut stop: S) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> FrameVerdict,
        S: FnMut() -> bool,
    {
        loop {
            let Some(frame) = self.next_candidate()? else {
                return Ok(());
            };
            let p = frame.len();
            let verdict = judge(frame);
            match verdict {
                FrameVerdict::Accepted => self.drain_front(p),
                FrameVerdict::Rejected(defect) => {
                    if defect == FrameDefect::CrcMismatch {
                        self.stats.crc_failures += 1;
                    } else {
                        self.stats.bad_frames += 1;
                    }
                    self.drain_front(1);
                }
            }
            if stop() {
                return Ok(());
            }
        }
    }

    /// Advance the window until a complete candidate frame of known length `P`
    /// is available. `Ok(None)` means EOF has been reached and no further
    /// candidate can be formed.
    fn next_candidate(&mut self) -> io::Result<Option<&[u8]>> {
        loop {
            let Some(pos) = self.locate_sync()? else {
                return Ok(None);
            };
            self.stats.sync_candidates += 1;
            self.drain_front(pos);
            // Read the 16-byte microheader; if EOF truncates it, count the
            // candidate in `truncated` and advance by one byte.
            if !self.fill_to(MICROHEADER_LEN)? {
                self.stats.truncated += 1;
                self.drain_front(1);
                continue;
            }
            let code = self.buf[11];
            if !is_legal_packet_code(code) {
                // P is outside the legal set (the low three bits are greater
                // than 5), so no length can be determined and there is nothing
                // to pass to the judge.
                self.stats.bad_code += 1;
                self.drain_front(1);
                continue;
            }
            let p = packet_size_from_code(code);
            if !self.fill_to(p)? {
                self.stats.truncated += 1;
                self.drain_front(1);
                continue;
            }
            return Ok(Some(&self.buf[..p]));
        }
    }

    /// Locate the next `SYNC` and return its offset relative to the current
    /// window, reading more data or discarding a window prefix that cannot
    /// start a frame as needed. A `SYNC` spanning a read boundary is found by
    /// retaining the last three bytes.
    ///
    /// Invariant: returns `None` if and only if EOF has been reached and no
    /// `SYNC` can be assembled from the remaining window contents.
    fn locate_sync(&mut self) -> io::Result<Option<usize>> {
        loop {
            let mut i = self.search_start;
            while i + SYNC.len() <= self.len {
                if self.buf[i..i + SYNC.len()] == SYNC {
                    return Ok(Some(i));
                }
                i += 1;
            }
            // No match exists in [0, len - 3); the final three bytes may hold
            // an incomplete `SYNC` prefix.
            self.search_start = self
                .search_start
                .max(self.len.saturating_sub(SYNC.len() - 1));
            if self.eof {
                return Ok(None);
            }
            if self.len == self.buf.len() {
                // The window is full and holds no match: discard the dead
                // prefix, keeping the last three bytes to join with new data.
                let dead = self.len - (SYNC.len() - 1);
                self.drain_front(dead);
                continue;
            }
            self.fill_once()?;
        }
    }

    /// Fill the window up to `want` bytes if possible (capped at [`RING_CAP`]);
    /// return whether `want` was reached.
    fn fill_to(&mut self, want: usize) -> io::Result<bool> {
        let want = want.min(self.buf.len());
        while self.len < want && !self.eof {
            self.fill_once()?;
        }
        Ok(self.len >= want)
    }

    /// Read another chunk from the underlying stream into the end of the
    /// window. A read of zero bytes is treated as EOF.
    fn fill_once(&mut self) -> io::Result<()> {
        debug_assert!(
            self.len < self.buf.len(),
            "must not read when the window is full"
        );
        loop {
            match self.reader.read(&mut self.buf[self.len..]) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(n) => {
                    self.len += n;
                    self.stats.bytes_scanned += n as u64;
                    self.stats.peak_buffered = self.stats.peak_buffered.max(self.len);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Discard the first `k` bytes of the window (`k ≤ len`) and compact it.
    ///
    /// Matching always restarts at position 0 afterwards: advancing may change
    /// the match state of the retained bytes, and rescanning conservatively
    /// cannot miss a candidate. The amortized cost is O(1) per byte.
    fn drain_front(&mut self, k: usize) {
        debug_assert!(k <= self.len);
        self.buf.copy_within(k..self.len, 0);
        self.len -= k;
        self.search_start = 0;
    }
}

/// Scan a non-seekable byte stream and feed candidates to a decode engine.
///
/// Only complete candidate frames of known length are passed to the engine,
/// which performs the frame-level structural and `CRC-32C` validation; the
/// scanner advances by one byte or by the whole packet according to the
/// engine's disposition. Return the scan statistics.
pub fn scan_into<R: Read>(reader: R, engine: &mut DecodeEngine) -> io::Result<ScanStats> {
    let mut scanner = RingScanner::new(reader);
    scanner.run(|frame| match engine.observe(frame) {
        PacketDisposition::Rejected(defect) => FrameVerdict::Rejected(defect),
        // Ledger I/O failure: the frame itself is valid, so advance by the
        // whole packet. The engine has entered a failed state and later calls
        // to `observe` return immediately; the caller reports an I/O error
        // based on `storage_error()`.
        PacketDisposition::StorageFailed => FrameVerdict::Accepted,
        PacketDisposition::Meta(_) | PacketDisposition::Data { .. } => FrameVerdict::Accepted,
    })?;
    Ok(scanner.stats())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_cap_meets_spec_floor() {
        // The window must be at least `max(P)` = 64 KiB.
        const { assert!(RING_CAP == MAX_PACKET_SIZE) };
        const { assert!(RING_CAP >= 65_536) };
    }

    #[test]
    fn scanner_allocates_fixed_window_upfront() {
        let scanner = RingScanner::new(io::empty());
        assert_eq!(scanner.capacity(), RING_CAP);
        assert_eq!(scanner.buffered(), 0);
        assert_eq!(scanner.stats(), ScanStats::default());
    }
}
