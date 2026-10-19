//! Decoding ledger: source-symbol write-through to the output target, an
//! arrival bitmap used for de-duplication, and repair symbols held inline
//! within a byte budget or spilled to a side store when the budget is exceeded.
//!
//! This module is the storage layer of the decoding engine
//! ([`crate::container::decode`]) and implements the following pieces:
//!
//! - **Output target**: a randomly readable and writable [`LedgerStore`] with
//!   `pread`/`pwrite` semantics. The CLI supplies a file-backed store (a
//!   staging file for publication, a stdout spool, or the `--patch` TARGET).
//!   The library default and tests use [`VecStore`], an in-memory store with
//!   equivalent semantics.
//! - **Arrival bitmap**: one bit per source symbol, `S = ceil(F/T)` bits in
//!   total. A bit is set only when a packet carrying that symbol is received;
//!   symbols reconstructed by the solver do not set bits, so they are not
//!   treated as duplicate arrivals. Chunks of 1 MiB are allocated lazily, so a
//!   forged OTI reserves only index slots and does not commit `S/8` bytes up
//!   front. The bitmap is not charged against the inline symbol budget.
//! - **Repair symbols**: symbols within the budget (`max_mem − RING_CAP`) stay
//!   inline in memory. Symbols that exceed the budget are appended to
//!   [`Ledger::spill_store`] instead of being dropped; only their key and
//!   [`SpillLoc`] remain in memory. Each spilled record uses big-endian fields:
//!
//!   ```text
//!   blk:u32 | esi:u32 | len:u32 | payload[len]
//!   ```
//!
//!   Payloads are read back with `pread` in [`Ledger::repair_take_payload`].
//! - **Failures**: errors from creating, writing, or reading the spill store are
//!   returned as [`std::io::Error`] and reported by the engine as I/O errors
//!   (the CLI exits with status 1 and prints one line plus a suggestion). They
//!   must never be silently ignored.
//!
//! This module does not validate frames or interpret the OTI; the engine
//! supplies the `(blk, esi) → offset` mapping according to the flattened
//! layout (`offset_j`/`K_j`).

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex};

/// Randomly readable and writable ledger backend with `pread`/`pwrite`
/// semantics; may be shared between solver workers.
///
/// Methods take `&self`: positional I/O on the file backend is naturally safe
/// to use concurrently, and the in-memory backend synchronizes internally. A
/// short read returns `UnexpectedEof`; a write past the end extends the
/// file or buffer.
pub trait LedgerStore: Send + Sync + fmt::Debug {
    /// Write `buf` starting at `off`, extending the backend if necessary.
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()>;

    /// Read exactly `buf.len()` bytes starting at `off`; return
    /// `UnexpectedEof` if fewer bytes are available.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Return the current backend length in bytes.
    fn len(&self) -> io::Result<u64>;

    /// Return whether the backend is empty (`len() == 0`). This default
    /// implementation satisfies clippy's `len_without_is_empty` lint.
    fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|len| len == 0)
    }

    /// Truncate or extend the backend to `len` bytes.
    fn set_len(&self, len: u64) -> io::Result<()>;

    /// Flush the backend to stable storage (a no-op for the in-memory store).
    fn sync(&self) -> io::Result<()>;
}

/// Transparent forwarding for `Arc<T>`, so the CLI and tests can share one
/// backend handle. `Arc<dyn LedgerStore>` also works.
impl<T: LedgerStore + ?Sized> LedgerStore for std::sync::Arc<T> {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        (**self).write_at(off, buf)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(off, buf)
    }

    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        (**self).set_len(len)
    }

    fn sync(&self) -> io::Result<()> {
        (**self).sync()
    }
}

/// File-backed store used by the CLI (staging file, spool, or spill file).
#[derive(Debug)]
pub struct FileStore {
    file: File,
    /// Serializes seek-plus-read/write on non-Unix platforms. Unix uses
    /// `pread`/`pwrite` and needs no lock.
    #[cfg(not(unix))]
    lock: Mutex<()>,
}

impl FileStore {
    /// Wrap an already opened file. The caller is responsible for opening it
    /// with read and write access.
    pub fn new(file: File) -> Self {
        FileStore {
            file,
            #[cfg(not(unix))]
            lock: Mutex::new(()),
        }
    }

    /// Return the underlying file handle. The CLI needs it for final
    /// `set_len`/`sync_all`/`rename` operations.
    pub fn file(&self) -> &File {
        &self.file
    }
}

#[cfg(unix)]
impl LedgerStore for FileStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.write_all_at(buf, off)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buf, off)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[cfg(not(unix))]
impl LedgerStore for FileStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("ledger file lock poisoned"))?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(off))?;
        file.write_all(buf)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("ledger file lock poisoned"))?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(off))?;
        file.read_exact(buf)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

/// In-memory backend used by the library default and by tests; the CLI uses
/// [`FileStore`].
///
/// Semantics match the file backend: writes extend the buffer (with zero-filled
/// holes), and reads past the end report `UnexpectedEof`.
#[derive(Default)]
pub struct VecStore {
    data: Mutex<Vec<u8>>,
}

impl VecStore {
    /// Create an empty backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a snapshot of the current contents (for tests).
    pub fn snapshot(&self) -> Vec<u8> {
        self.data.lock().map(|d| d.clone()).unwrap_or_default()
    }

    /// Lock the buffer, mapping a poisoned mutex to an I/O error.
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Vec<u8>>> {
        self.data
            .lock()
            .map_err(|_| io::Error::other("in-memory ledger mutex poisoned"))
    }
}

impl fmt::Debug for VecStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.data.lock().map(|d| d.len()).unwrap_or(0);
        f.debug_struct("VecStore").field("len", &len).finish()
    }
}

impl LedgerStore for VecStore {
    fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        let off = usize::try_from(off).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "ledger offset exceeds usize")
        })?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ledger offset overflow"))?;
        let mut data = self.lock()?;
        if data.len() < end {
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let off = usize::try_from(off).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "ledger offset exceeds usize")
        })?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ledger offset overflow"))?;
        let data = self.lock()?;
        if end > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("ledger read out of bounds ({end} > {})", data.len()),
            ));
        }
        buf.copy_from_slice(&data[off..end]);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.lock()?.len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "ledger length exceeds usize")
        })?;
        self.lock()?.resize(len, 0);
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Number of bits per arrival-bitmap chunk: 8 Mbit, or 1 MiB per chunk, which
/// is the lazy allocation granularity.
const CHUNK_BITS: u64 = 1 << 23;

/// Arrival bitmap for source symbols.
///
/// Bit `i` corresponds to global source-symbol index `i = offset_j + e`. A bit
/// is set only when a packet carrying that symbol is received; symbols written
/// back by the solver do not set bits, because a reconstructed symbol is not a
/// received packet. The bitmap is excluded from the inline repair budget.
#[derive(Debug)]
pub struct ArrivalBits {
    len: u64,
    chunks: Vec<Option<Box<[u8]>>>,
    allocated_bytes: u64,
}

impl ArrivalBits {
    /// Create a bitmap for `len` bits. Chunk slots are created up front, but
    /// each 1 MiB chunk is allocated only when first touched.
    pub fn new(len: u64) -> Self {
        let n = usize::try_from(len.div_ceil(CHUNK_BITS)).unwrap_or(usize::MAX);
        Self {
            len,
            chunks: (0..n).map(|_| None).collect(),
            allocated_bytes: 0,
        }
    }

    /// Return the number of bits, `S`.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Return whether `S == 0`. Valid layouts never produce this case; the
    /// check is defensive.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the number of bytes actually allocated, at most `ceil(S/8)`.
    /// Untouched chunks are not counted.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    /// Return whether bit `i` is set. Unallocated chunks read as zero.
    pub fn get(&self, i: u64) -> bool {
        debug_assert!(
            i < self.len,
            "bitmap index out of range: {i} ≥ {}",
            self.len
        );
        let (c, off) = ((i / CHUNK_BITS) as usize, i % CHUNK_BITS);
        match self.chunks.get(c).and_then(|chunk| chunk.as_deref()) {
            Some(bytes) => bytes[(off / 8) as usize] & (1u8 << (off % 8)) != 0,
            None => false,
        }
    }

    /// Set bit `i` and return whether it was already set (`true` means the
    /// symbol arrived more than once).
    pub fn set(&mut self, i: u64) -> bool {
        debug_assert!(
            i < self.len,
            "bitmap index out of range: {i} ≥ {}",
            self.len
        );
        let c = (i / CHUNK_BITS) as usize;
        let off = i % CHUNK_BITS;
        let allocated = &mut self.allocated_bytes;
        let chunk = self.chunks[c].get_or_insert_with(|| {
            *allocated += CHUNK_BITS / 8;
            vec![0u8; (CHUNK_BITS / 8) as usize].into_boxed_slice()
        });
        let byte = (off / 8) as usize;
        let bit = 1u8 << (off % 8);
        let was = chunk[byte] & bit != 0;
        chunk[byte] |= bit;
        was
    }

    /// Count the set bits in `[start, start + len)`, used for block coverage
    /// statistics.
    pub fn count_range(&self, start: u64, len: u64) -> u64 {
        let mut count = 0;
        for i in start..start + len {
            if self.get(i) {
                count += 1;
            }
        }
        count
    }
}

/// Length of a spill record header: `blk:u32 | esi:u32 | len:u32`, stored in
/// big-endian order.
pub const SPILL_HEADER_LEN: usize = 12;

/// Location of a spilled payload in the spill backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpillLoc {
    /// Offset of the record, including the 12-byte header.
    pub off: u64,
    /// Payload length in bytes.
    pub len: u32,
}

/// Slot for a repair (non-source) symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairSlot {
    /// Payload held inline in memory and charged against the budget. After
    /// settlement takes the payload, an empty placeholder remains so later
    /// arrivals are still counted as duplicates.
    Inline(Vec<u8>),
    /// Location of a payload in the spill backend; only the key and location
    /// stay in memory.
    Spilled(SpillLoc),
}

/// Decoding ledger: output target, spill backend, arrival bitmap,
/// repair-symbol table, and inline budget accounting.
///
/// Backends are held as `Arc<dyn LedgerStore>` so settlement workers (parallel
/// stream-tail processing and the early-commit pool used during scanning) can
/// each clone a handle. `pread`/`pwrite` are safe to use concurrently, and
/// [`LedgerStore`] requires `Send + Sync`.
#[derive(Debug)]
pub struct Ledger {
    store: Arc<dyn LedgerStore>,
    spill: Arc<dyn LedgerStore>,
    /// Byte budget for inline repair symbols (`max_mem − RING_CAP`). The
    /// arrival bitmap is not charged against it.
    budget: u64,
    bits: Option<ArrivalBits>,
    repairs: HashMap<(u32, u32), RepairSlot>,
    inline_bytes: u64,
    spill_payload_bytes: u64,
    spilled_symbols: u64,
}

impl Ledger {
    /// Create a ledger with the given target and spill backends and inline
    /// budget.
    pub fn new(store: Box<dyn LedgerStore>, spill: Box<dyn LedgerStore>, budget: u64) -> Self {
        Self::with_shared(Arc::from(store), Arc::from(spill), budget)
    }

    /// Like [`Ledger::new`], but takes shared handles, which the
    /// early-settlement pool needs in order to clone them across threads.
    pub fn with_shared(
        store: Arc<dyn LedgerStore>,
        spill: Arc<dyn LedgerStore>,
        budget: u64,
    ) -> Self {
        Ledger {
            store,
            spill,
            budget,
            bits: None,
            repairs: HashMap::new(),
            inline_bytes: 0,
            spill_payload_bytes: 0,
            spilled_symbols: 0,
        }
    }

    /// Create a ledger whose target and spill backends are both in memory
    /// (no I/O). The CLI passes file-backed stores instead.
    pub fn memory(budget: u64) -> Self {
        Self::new(Box::new(VecStore::new()), Box::new(VecStore::new()), budget)
    }

    /// Return the output target backend, used for source-symbol write-through
    /// and settlement reads.
    pub fn store(&self) -> &dyn LedgerStore {
        self.store.as_ref()
    }

    /// Return the spill backend, which holds repair symbols that exceeded the
    /// inline budget.
    pub fn spill_store(&self) -> &dyn LedgerStore {
        self.spill.as_ref()
    }

    /// Return a shared handle to the output target, for early-settlement
    /// workers.
    pub fn store_handle(&self) -> Arc<dyn LedgerStore> {
        Arc::clone(&self.store)
    }

    /// Return a shared handle to the spill backend, for early-settlement
    /// workers.
    pub fn spill_handle(&self) -> Arc<dyn LedgerStore> {
        Arc::clone(&self.spill)
    }

    /// Return the inline byte budget for repair symbols.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Allocate the arrival bitmap for `S` source symbols when the basis is
    /// established. Repeated calls rebuild it with the latest `s`; normally
    /// the engine calls this once.
    pub fn init_arrival(&mut self, s: u64) {
        self.bits = Some(ArrivalBits::new(s));
    }

    /// Return the arrival bitmap, or `None` if it has not been initialized
    /// (for example, when the OTI is malformed).
    pub fn arrival(&self) -> Option<&ArrivalBits> {
        self.bits.as_ref()
    }

    /// Return whether bit `i` is set.
    pub fn arrival_get(&self, i: u64) -> bool {
        self.bits.as_ref().is_some_and(|bits| bits.get(i))
    }

    /// Set bit `i` and return whether it was already set (`true` means a
    /// duplicate arrival).
    ///
    /// The caller must call `init_arrival` first, which always holds in the
    /// Ready state.
    pub fn arrival_set(&mut self, i: u64) -> bool {
        self.bits
            .as_mut()
            .expect("the arrival bitmap must be allocated in the Ready state")
            .set(i)
    }

    /// Return the number of set bits in `[start, start + len)` (block coverage
    /// statistics).
    pub fn arrival_count(&self, start: u64, len: u64) -> u64 {
        self.bits
            .as_ref()
            .map_or(0, |bits| bits.count_range(start, len))
    }

    /// Return the number of arrival-bitmap bytes actually allocated.
    pub fn arrival_allocated_bytes(&self) -> u64 {
        self.bits.as_ref().map_or(0, |bits| bits.allocated_bytes())
    }

    /// Write one source symbol through to the target: `T` bytes starting at
    /// `(offset_j + esi) * T`.
    pub fn write_source(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.store.write_at(off, buf)
    }

    /// Read a source symbol back from the target for settlement input.
    pub fn read_source(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.store.read_at(off, buf)
    }

    /// Read the first `f` bytes of the target for verification. This is a
    /// convenience helper for library callers.
    pub fn read_back(&self, f: u64) -> io::Result<Vec<u8>> {
        let n = usize::try_from(f)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "F exceeds usize"))?;
        let mut buf = vec![0u8; n];
        self.store.read_at(0, &mut buf)?;
        Ok(buf)
    }

    /// Return whether a repair-symbol key is already registered, which is the
    /// de-duplication test.
    pub fn repair_contains(&self, blk: u32, esi: u32) -> bool {
        self.repairs.contains_key(&(blk, esi))
    }

    /// Insert a repair symbol: keep it inline if the budget allows, otherwise
    /// append it to the spill store. Return whether the symbol was spilled.
    ///
    /// If writing to the spill store fails, return `Err` without recording the
    /// symbol or updating counters. The caller reports the I/O error and must
    /// not silently drop the symbol.
    pub fn repair_insert(&mut self, blk: u32, esi: u32, payload: Vec<u8>) -> io::Result<bool> {
        debug_assert!(!self.repairs.contains_key(&(blk, esi)));
        let len = payload.len() as u64;
        if self.inline_bytes + len <= self.budget {
            self.inline_bytes += len;
            self.repairs.insert((blk, esi), RepairSlot::Inline(payload));
            return Ok(false);
        }
        let off = self.spill.len()?;
        let len_u32 = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "spilled payload exceeds u32 length",
            )
        })?;
        let mut record = Vec::with_capacity(SPILL_HEADER_LEN + payload.len());
        record.extend_from_slice(&blk.to_be_bytes());
        record.extend_from_slice(&esi.to_be_bytes());
        record.extend_from_slice(&len_u32.to_be_bytes());
        record.extend_from_slice(&payload);
        self.spill.write_at(off, &record)?;
        self.repairs.insert(
            (blk, esi),
            RepairSlot::Spilled(SpillLoc { off, len: len_u32 }),
        );
        self.spill_payload_bytes += len;
        self.spilled_symbols += 1;
        Ok(true)
    }

    /// Register only the key of a late repair symbol for an already-solved
    /// block. This charges no budget and writes nothing, preserving
    /// duplicate-arrival accounting.
    pub fn repair_insert_key_only(&mut self, blk: u32, esi: u32) {
        debug_assert!(!self.repairs.contains_key(&(blk, esi)));
        self.repairs
            .insert((blk, esi), RepairSlot::Inline(Vec::new()));
    }

    /// Take a repair symbol's payload for settlement. Inline payloads are
    /// moved out and the slot is left as an empty placeholder; spilled
    /// payloads are read back from [`SpillLoc`].
    ///
    /// Return `Ok(None)` if the key is absent and `Err` if the read fails.
    pub fn repair_take_payload(&mut self, blk: u32, esi: u32) -> io::Result<Option<Vec<u8>>> {
        match self.repairs.get_mut(&(blk, esi)) {
            None => Ok(None),
            Some(RepairSlot::Inline(payload)) => {
                let taken = std::mem::take(payload);
                self.inline_bytes -= taken.len() as u64;
                Ok(Some(taken))
            }
            Some(RepairSlot::Spilled(loc)) => {
                let loc = *loc;
                let mut payload = vec![0u8; loc.len as usize];
                self.spill
                    .read_at(loc.off + SPILL_HEADER_LEN as u64, &mut payload)?;
                Ok(Some(payload))
            }
        }
    }

    /// Take all repair-symbol slots for block `blk` for settlement, ordered by
    /// ESI. Inline payloads move with their slots; spilled entries return a
    /// [`SpillLoc`] that the worker reads itself.
    ///
    /// The keys no longer exist afterwards. After settlement the engine
    /// re-registers them with [`Ledger::repair_insert_key_only`] to keep
    /// duplicate-arrival accounting intact; the inline budget is released at
    /// the same time.
    pub fn repair_take_block(&mut self, blk: u32) -> Vec<(u32, RepairSlot)> {
        self.repair_take_block_impl(blk, true).0
    }

    /// Take the repair-symbol slots for block `blk` during scanning, for early
    /// commit.
    ///
    /// Unlike [`Ledger::repair_take_block`], this does not release the inline
    /// budget immediately: budget accounting remains identical to sequential
    /// settlement, where all symbols are taken at once after arrival. That
    /// keeps the inline-versus-spill decision for later symbols independent of
    /// `--jobs`. Return `(slots, retained_inline_bytes)`; the engine releases
    /// the latter once at stream-tail settlement with
    /// [`Ledger::release_inline_budget`].
    pub fn repair_take_block_early(&mut self, blk: u32) -> (Vec<(u32, RepairSlot)>, u64) {
        self.repair_take_block_impl(blk, false)
    }

    fn repair_take_block_impl(
        &mut self,
        blk: u32,
        release_inline: bool,
    ) -> (Vec<(u32, RepairSlot)>, u64) {
        let keys: Vec<(u32, u32)> = self
            .repairs
            .keys()
            .filter(|&&(b, _)| b == blk)
            .copied()
            .collect();
        let mut taken = Vec::with_capacity(keys.len());
        let mut kept_inline = 0u64;
        for key in keys {
            if let Some(slot) = self.repairs.remove(&key) {
                if let RepairSlot::Inline(payload) = &slot {
                    let len = payload.len() as u64;
                    if release_inline {
                        self.inline_bytes -= len;
                    } else {
                        kept_inline += len;
                    }
                }
                taken.push((key.1, slot));
            }
        }
        taken.sort_by_key(|&(esi, _)| esi);
        (taken, kept_inline)
    }

    /// Release inline budget retained by an early take. The engine calls this
    /// once at stream-tail settlement when it processes early results.
    pub fn release_inline_budget(&mut self, bytes: u64) {
        self.inline_bytes = self.inline_bytes.saturating_sub(bytes);
    }

    /// Return the number of bytes currently held by inline repair symbols;
    /// always at most [`Ledger::budget`].
    pub fn inline_repair_bytes(&self) -> u64 {
        self.inline_bytes
    }

    /// Return the cumulative number of spilled payload bytes, the
    /// decoding-side input to spooled-byte accounting.
    pub fn spilled_payload_bytes(&self) -> u64 {
        self.spill_payload_bytes
    }

    /// Return the cumulative number of spilled symbols.
    pub fn spilled_symbols(&self) -> u64 {
        self.spilled_symbols
    }

    /// Return the number of registered repair-symbol keys, including late
    /// symbols registered by key only.
    pub fn repair_keys(&self) -> usize {
        self.repairs.len()
    }

    /// Return the logical length of the output target.
    pub fn store_len(&self) -> io::Result<u64> {
        self.store.len()
    }

    /// Truncate the target to `f` bytes, used before publishing or verifying a
    /// file. This also applies to the in-memory backend.
    pub fn truncate_store(&self, f: u64) -> io::Result<()> {
        self.store.set_len(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrival_bits_chunked_roundtrip() {
        let mut bits = ArrivalBits::new(1_000_003);
        assert_eq!(bits.len(), 1_000_003);
        assert_eq!(
            bits.allocated_bytes(),
            0,
            "no chunk is allocated before any bit is set"
        );
        assert!(!bits.set(0), "first set returns not-set");
        assert!(bits.set(0), "duplicate set returns already-set");
        assert!(!bits.set(999_999));
        assert!(bits.get(0) && bits.get(999_999));
        assert!(!bits.get(1));
        assert_eq!(bits.count_range(0, 2), 1);
        assert_eq!(bits.count_range(999_990, 13), 1);
        assert_eq!(
            bits.allocated_bytes(),
            CHUNK_BITS / 8,
            "a small bitmap allocates only one chunk"
        );

        // Cross a chunk boundary (CHUNK_BITS = 8 Mbit).
        let mut wide = ArrivalBits::new(CHUNK_BITS + 4);
        assert_eq!(wide.allocated_bytes(), 0);
        assert!(!wide.set(CHUNK_BITS - 1));
        assert!(!wide.set(CHUNK_BITS));
        assert_eq!(
            wide.allocated_bytes(),
            2 * (CHUNK_BITS / 8),
            "touches two chunks"
        );
        assert!(wide.get(CHUNK_BITS - 1) && wide.get(CHUNK_BITS));
        assert!(!wide.get(CHUNK_BITS + 3));
        assert_eq!(wide.count_range(CHUNK_BITS - 1, 2), 2);
    }

    #[test]
    fn vec_store_write_read_set_len() {
        let store = VecStore::new();
        store.write_at(4, b"ab").expect("write");
        assert_eq!(store.len().expect("len"), 6);
        let mut buf = [0u8; 6];
        store.read_at(0, &mut buf).expect("read");
        assert_eq!(&buf, b"\0\0\0\0ab");
        let mut short = [0u8; 7];
        assert_eq!(
            store
                .read_at(0, &mut short)
                .expect_err("out of bounds")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        store.set_len(2).expect("truncate");
        assert_eq!(store.len().expect("len"), 2);
        store.set_len(4).expect("extend");
        assert_eq!(store.snapshot(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn repair_insert_splits_inline_and_spill() {
        let mut ledger = Ledger::new(Box::new(VecStore::new()), Box::new(VecStore::new()), 8);
        assert_eq!(ledger.budget(), 8);
        // The first 4-byte symbol is inline, the second fills the budget
        // exactly, and the third exceeds it and is spilled.
        assert!(!ledger.repair_insert(0, 100, vec![1; 4]).expect("inline"));
        assert!(!ledger.repair_insert(0, 101, vec![2; 4]).expect("inline"));
        assert_eq!(ledger.inline_repair_bytes(), 8);
        assert!(ledger.repair_insert(0, 102, vec![3; 5]).expect("spill"));
        assert_eq!(
            ledger.inline_repair_bytes(),
            8,
            "spill does not consume budget"
        );
        assert_eq!(ledger.spilled_payload_bytes(), 5);
        assert_eq!(ledger.spilled_symbols(), 1);
        assert!(ledger.repair_contains(0, 102));
        // Read back: the inline payload is moved out (the key remains); the
        // spilled payload is read with pread.
        assert_eq!(
            ledger
                .repair_take_payload(0, 100)
                .expect("inline read-back"),
            Some(vec![1; 4])
        );
        assert_eq!(ledger.inline_repair_bytes(), 4);
        assert_eq!(
            ledger.repair_take_payload(0, 102).expect("spill read-back"),
            Some(vec![3; 5])
        );
        assert!(
            ledger.repair_contains(0, 100),
            "key retained after take (duplicate accounting)"
        );
        assert_eq!(
            ledger.repair_take_payload(0, 999).expect("absent key"),
            None
        );
        // Spill record layout: big-endian blk/esi/len followed by the payload.
        let spill = ledger.spill_store();
        assert_eq!(
            spill.len().expect("spill length"),
            (SPILL_HEADER_LEN + 5) as u64
        );
        let mut head = [0u8; SPILL_HEADER_LEN];
        spill.read_at(0, &mut head).expect("read header");
        assert_eq!(&head[0..4], &0u32.to_be_bytes());
        assert_eq!(&head[4..8], &102u32.to_be_bytes());
        assert_eq!(&head[8..12], &5u32.to_be_bytes());
    }

    #[test]
    fn key_only_does_not_touch_budget_or_spill() {
        let mut ledger = Ledger::memory(0);
        ledger.repair_insert_key_only(3, 77);
        assert!(ledger.repair_contains(3, 77));
        assert_eq!(ledger.inline_repair_bytes(), 0);
        assert_eq!(ledger.spilled_symbols(), 0);
        assert_eq!(
            ledger
                .repair_take_payload(3, 77)
                .expect("empty placeholder"),
            Some(Vec::new())
        );
    }
}
