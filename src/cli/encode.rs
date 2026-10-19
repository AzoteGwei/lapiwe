//! Command-line wiring for `lapiwe encode`.
//!
//! Pipeline:
//!
//! 1. If `<IN>` is `-`, copy stdin to a temporary file in `--spool-dir`
//!    (default: `$TMPDIR`).
//! 2. First pass: stream the input to compute its length `F` and BLAKE3
//!    digest.
//! 3. `plan()` validates every parameter and layout bounds up front, so a
//!    rejected configuration creates and publishes no output.
//! 4. Second pass: read one block at a time (each block holds `K_j·T` bytes,
//!    with the final block zero-padded) and call
//!    [`EncodePlan::encode_block`] to produce packets and place them in their
//!    slots:
//!    - file output: write to a temporary file in the destination directory,
//!      then rename it into place atomically;
//!    - stdout with `NB = 1`: write sequentially with no spooling, after all
//!      validation has completed;
//!    - stdout with `NB > 1`: spool the output to `$TMPDIR` (about the size
//!      of the output), validate it, then copy it to stdout.
//!
//!    The BLAKE3 digest is accumulated while reading and compared with the
//!    first pass. On mismatch, file output is not published and stdout
//!    receives no bytes because the copy happens after validation. The
//!    command exits with status 1.
//! 5. A broken pipe on stdout exits silently with status 0.
//! 6. On success, print a summary to stderr, including the requested and
//!    minimum total packet counts in default mode, a memory hint, and a
//!    warning when best-effort encoding was requested.
//!
//! Memory use is bounded by the block size rather than the input size `F`.
//! The peak is roughly `3·K_j·T` (source symbols, intermediate symbols, and
//! one packet buffer) plus a constant. With `--jobs > 1`, blocks are encoded
//! in parallel by [`encode_blocks_parallel`]: the number of workers is
//! `min(jobs, NB)`, and concurrent residency is about
//! `(3·min(jobs, NB) + 2)·max_j(K_j·T)` (three buffers per worker plus one
//! each for the reader and the channel).

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lapiwe::container::encode::{BlobInfo, EncodeConfig, EncodeError, EncodePlan, TotalSpec, plan};
use lapiwe::container::leveling::LayoutDefect;

use super::args::EncodeArgs;
use super::temp::{TempGuard, create_temp_for, create_unique};
use super::{exit_code, write_stderr};

/// Map an encoding failure to a single stderr line and return its exit code.
fn report_error(err: &EncodeError, p: usize) -> u8 {
    let message = match err {
        EncodeError::RedundancyInsufficient(report) => format!(
            "insufficient effective redundancy: min(a_j-needed_j)={} ({} block(s) affected); \
             no output is produced by default (use the default mode, or add `--force` for a best-effort \
             result with best_effort=1)",
            report.min_slack, report.affected_blocks
        ),
        EncodeError::KmaxZero => format!(
            "K_max=0: `--max-mem` is smaller than the symbol size T={}; increase `--max-mem`",
            p.saturating_sub(16)
        ),
        EncodeError::NotPublishable { c_total } => format!(
            "C_total={c_total} < 2 (equivalent to D < 1); increase `--size` to at least 2P={} or use \
             the default mode (`--force` does not bypass this; C_total=2 may still exit with status 2 \
             after the layout check)",
            (p as u64).saturating_mul(2)
        ),
        EncodeError::MaxEsiExceeded { max_esi } => format!(
            "maximum data ESI={max_esi} exceeds the 24-bit field; increase `--packet-size`, reduce the output size, or adjust `--block-symbols`"
        ),
        EncodeError::TotalBytesOverflow { c_total, p } => format!(
            "C_total*P overflows u64 (C_total={c_total}, P={p}); reduce `--size`/`--redundancy` or increase `--packet-size`"
        ),
        EncodeError::Layout(defect) => layout_message(*defect),
        EncodeError::IllegalPacketSize(p) => format!(
            "invalid packet size P={p}; valid values: {}",
            super::args::legal_packet_sizes()
        ),
        EncodeError::LengthMismatch { expected, actual } => format!(
            "input length changed between the two passes (pass1={expected}, pass2={actual}); the input was modified during encoding"
        ),
        EncodeError::MetaBuild(_) => {
            "failed to build metadata packet (internal parameter error)".to_owned()
        }
        EncodeError::Io(e) => format!("I/O error: {e}"),
    };
    let _ = write_stderr(&format!("lapiwe: error: {message}\n"));
    err.exit_code()
}

fn layout_message(defect: LayoutDefect) -> String {
    match defect {
        LayoutDefect::ZeroInput => {
            "input is empty (F=0); an empty input does not define a container - provide at least 1 byte"
                .to_owned()
        }
        LayoutDefect::ZeroSymbolSize => "symbol size is zero (invalid `--packet-size`)".to_owned(),
        LayoutDefect::NbZero => "NB=0 (internal layout error)".to_owned(),
        LayoutDefect::NbTooLarge => {
            "NB exceeds the 24-bit field; increase `--packet-size` or reduce the output size".to_owned()
        }
        LayoutDefect::KmaxZero => {
            "K_max=0: `--max-mem` is smaller than the symbol size T; increase `--max-mem`".to_owned()
        }
        LayoutDefect::KmaxExceeded => {
            "ceil(S/NB) exceeds the RFC 6330 K'_max=56403; increase `--packet-size` or adjust `--block-symbols`"
                .to_owned()
        }
        LayoutDefect::KsZero => "layout KS < 1 (outside the format boundary)".to_owned(),
        LayoutDefect::Overflow => {
            "layout/count overflow of u64; reduce `--size`/`--redundancy` or increase `--packet-size`"
                .to_owned()
        }
        LayoutDefect::MetaEveryTooSmall => {
            "`--meta-every` must be >= 2 (default 256)".to_owned()
        }
    }
}

/// Destination for the encoded output.
enum OutputTarget {
    Stdout,
    File(PathBuf),
}

fn output_target(args: &EncodeArgs) -> OutputTarget {
    match &args.output {
        Some(o) if o == "-" => OutputTarget::Stdout,
        Some(o) => OutputTarget::File(PathBuf::from(o)),
        None if args.input == "-" => OutputTarget::Stdout,
        None => {
            // Default to `<IN>.lpw`: append the suffix without altering the rest
            // of the path.
            let mut name = args.input.clone();
            name.push(".lpw");
            OutputTarget::File(PathBuf::from(name))
        }
    }
}

/// Return whether two paths refer to the same file. Compare the raw paths
/// first, then canonicalized paths; if the destination does not exist yet,
/// compare the canonicalized parent directory joined with the file name.
fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    if let (Ok(ca), Ok(cb)) = (fs::canonicalize(a), fs::canonicalize(b)) {
        return ca == cb;
    }
    match (normalize_parent(a), normalize_parent(b)) {
        (Some(na), Some(nb)) => na == nb,
        _ => false,
    }
}

fn normalize_parent(p: &Path) -> Option<PathBuf> {
    let file = p.file_name()?;
    let parent = match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    fs::canonicalize(parent).ok().map(|dir| dir.join(file))
}

/// First pass: stream the file to compute its length and BLAKE3 digest
/// without retaining its contents in memory.
fn prescan_file(path: &Path) -> io::Result<BlobInfo> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut f = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                f += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(BlobInfo {
        f,
        blake3: *hasher.finalize().as_bytes(),
    })
}

/// Copy stdin to a temporary file in `--spool-dir` (default: `$TMPDIR`).
/// Return the file path and a guard that removes the file on drop.
fn spool_stdin(spool_dir: Option<&OsStr>) -> io::Result<(PathBuf, TempGuard)> {
    let dir = match spool_dir {
        Some(d) => PathBuf::from(d),
        None => std::env::temp_dir(),
    };
    let (path, mut file) = create_unique(&dir, "lapiwe-stdin")?;
    let guard = TempGuard::new(path.clone());
    let mut stdin = io::stdin().lock();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => file.write_all(&buf[..n])?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    file.flush()?;
    Ok((path, guard))
}

/// Failures that can occur during the second pass: reading, writing, the
/// two-pass consistency checks, and thread creation.
enum Pass2Error {
    Read(io::Error),
    Write(io::Error),
    LengthChanged {
        expected: u64,
        actual: u64,
    },
    HashMismatch,
    /// The system could not create another worker thread, typically because
    /// `--jobs` is too large. Reported as a single-line error rather than a
    /// panic.
    ThreadSpawn(io::Error),
}

/// Print a single-line report for a second-pass failure and return exit code 1.
fn report_pass2(err: &Pass2Error, input: &Path) -> u8 {
    let message = match err {
        Pass2Error::Read(e) => format!("failed to read input {}: {e}", input.display()),
        Pass2Error::Write(e) => format!("failed to write output: {e}"),
        Pass2Error::LengthChanged { expected, actual } => format!(
            "input length changed between the two passes (pass1={expected}, pass2={actual}); the input was modified during encoding"
        ),
        Pass2Error::HashMismatch => {
            "input content changed between the two passes (different BLAKE3 digest); the input was \
             modified during encoding, so no stream inconsistent with the OTI is produced"
                .to_owned()
        }
        Pass2Error::ThreadSpawn(e) => format!(
            "failed to create an encoder thread (`--jobs` too large or insufficient system resources): {e}; reduce `--jobs` (valid range 1..={})",
            super::args::MAX_JOBS
        ),
    };
    let _ = write_stderr(&format!("lapiwe: error: {message}\n"));
    exit_code::OTHER
}

/// Block-oriented reader for the second pass. It reads each block's bytes in
/// layout order, zero-pads the final block, and incrementally updates the
/// BLAKE3 hasher.
struct BlockReader<'a> {
    plan: &'a EncodePlan,
    file: File,
    hasher: blake3::Hasher,
    buf: Vec<u8>,
}

impl<'a> BlockReader<'a> {
    fn open(plan: &'a EncodePlan, path: &Path) -> io::Result<Self> {
        Ok(BlockReader {
            plan,
            file: File::open(path)?,
            hasher: blake3::Hasher::new(),
            buf: Vec::new(),
        })
    }

    /// Read the real bytes of block `j` into the internal buffer and update
    /// the hash. The tail of the `K_j·T`-byte buffer remains zero-filled.
    fn read_block(&mut self, j: u32) -> io::Result<()> {
        let (start, len) = self.plan.block_span(j);
        let block_bytes = self.plan.block_bytes(j);
        debug_assert!(start + len <= self.plan.oti.f);
        let Self {
            file, hasher, buf, ..
        } = self;
        file.seek(SeekFrom::Start(start))?;
        // Reuse the buffer: only `[0, block_bytes)` must be valid. Read the
        // real bytes first and zero the tail, which avoids clearing the whole
        // block on every read.
        buf.resize(block_bytes as usize, 0);
        buf[len as usize..].fill(0);
        let real = &mut buf[..len as usize];
        file.read_exact(real)?;
        hasher.update(real);
        Ok(())
    }

    /// Install a reusable block buffer, for example from the parallel path's
    /// buffer pool. `read_block` resizes it as needed.
    fn set_buf(&mut self, buf: Vec<u8>) {
        self.buf = buf;
    }

    /// Return the current block buffer, which holds exactly `K_j·T` bytes
    /// after `read_block`.
    fn buf(&self) -> &[u8] {
        &self.buf
    }

    /// Take the current block buffer, transferring ownership to a worker; the
    /// reader allocates a new one on its next read.
    fn take_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Return the BLAKE3 digest of all bytes read so far. The second pass uses
    /// it to verify that both passes saw the same input.
    fn finish_hash(&self) -> [u8; 32] {
        *self.hasher.clone().finalize().as_bytes()
    }

    /// Return the current length of the underlying file. The second pass
    /// rejects input that was truncated or appended to.
    fn file_len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

/// Seekable packet-slot output backed by a temporary file or an output spool.
struct SeekSink {
    file: File,
    p: usize,
}

impl SeekSink {
    /// Write one whole packet to its slot. Taking `&self` lets parallel
    /// workers write disjoint slots concurrently.
    fn put(&self, slot: u64, packet: &[u8]) -> io::Result<()> {
        write_at(&self.file, slot * self.p as u64, packet)
    }
}

/// Write a whole packet at an absolute offset. Unix uses `pwrite`; other
/// platforms seek and then write.
fn write_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(bytes, offset)
    }
    #[cfg(not(unix))]
    {
        let mut file = file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
}

/// Run the second pass: encode each block, place packets into their slots,
/// write the metadata slots, and verify the BLAKE3 digest.
///
/// When `jobs > 1` and `NB > 1`, blocks are encoded in parallel with
/// `min(jobs, NB)` workers. The main thread reads blocks in order and updates
/// the hash, while workers encode each block and write disjoint packet slots.
/// The output is byte-for-byte identical to the serial path and does not
/// depend on `jobs`.
fn encode_all_blocks(
    plan: &EncodePlan,
    input_path: &Path,
    sink: &SeekSink,
    jobs: usize,
) -> Result<(), Pass2Error> {
    let nb = plan.leveling.nb;
    let workers = jobs.min(nb as usize).max(1);
    if workers > 1 {
        return encode_blocks_parallel(plan, input_path, sink, workers);
    }
    let mut reader = BlockReader::open(plan, input_path).map_err(Pass2Error::Read)?;
    for j in 0..nb {
        reader.read_block(j).map_err(Pass2Error::Read)?;
        plan.encode_block(j, reader.buf(), |slot, packet| sink.put(slot, packet))
            .map_err(Pass2Error::Write)?;
    }
    for slot in plan.meta_slots() {
        sink.put(slot, plan.meta_packet())
            .map_err(Pass2Error::Write)?;
    }
    // Recheck the length (truncation fails during reads; growth is caught
    // here) and the content digest.
    let actual_len = reader.file_len().map_err(Pass2Error::Read)?;
    if actual_len != plan.oti.f {
        return Err(Pass2Error::LengthChanged {
            expected: plan.oti.f,
            actual: actual_len,
        });
    }
    if reader.finish_hash() != plan.oti.blake3 {
        return Err(Pass2Error::HashMismatch);
    }
    Ok(())
}

/// Parallel encoding path used when `jobs > 1`.
///
/// The channel capacity is one, so concurrent residency is roughly the block
/// being read, one block in the channel, and, per worker, a block buffer, a
/// copy of the source symbols, and intermediate symbols: about
/// `(3·workers + 2)·max_j(K_j·T)` bytes. Output is deterministic because slots
/// are disjoint and each slot's contents depend only on its block and ESI.
/// Reading and hashing still happen in block order on the main thread, so the
/// two-pass verification matches the serial path.
fn encode_blocks_parallel(
    plan: &EncodePlan,
    input_path: &Path,
    sink: &SeekSink,
    workers: usize,
) -> Result<(), Pass2Error> {
    let nb = plan.leveling.nb;
    let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>)>(1);
    // Buffer-recycling channel: workers return their block buffer to the
    // reader after encoding, avoiding a fresh allocation per block. It is
    // unbounded so senders never block; blocking here could deadlock when the
    // reader waits to send while all workers wait to recycle. The number of
    // buffers in circulation is bounded by the blocks in flight.
    let (ret_tx, ret_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let rx = std::sync::Mutex::new(rx);
    let first_error: std::sync::Mutex<Option<Pass2Error>> = std::sync::Mutex::new(None);
    // Read failures and worker write failures are both recorded in
    // `first_error`.
    let mut reader = BlockReader::open(plan, input_path).map_err(Pass2Error::Read)?;

    std::thread::scope(|scope| {
        for _ in 0..workers {
            // Thread creation failure must be reported as a single-line error
            // rather than a panic. Workers that already started exit once `tx`
            // is dropped and the channel drains.
            let spawned = std::thread::Builder::new()
                .name("lapiwe-enc".to_owned())
                .spawn_scoped(scope, || {
                    loop {
                        let item = {
                            let guard = rx.lock().expect("worker receiver lock is not poisoned");
                            guard.recv()
                        };
                        let Ok((j, buf)) = item else { break };
                        if let Err(e) =
                            plan.encode_block(j, &buf, |slot, packet| sink.put(slot, packet))
                        {
                            let mut slot = first_error.lock().expect("error lock is not poisoned");
                            if slot.is_none() {
                                *slot = Some(Pass2Error::Write(e));
                            }
                        }
                        let _ = ret_tx.send(buf); // Return the buffer for reuse.
                    }
                });
            if let Err(e) = spawned {
                let mut slot = first_error.lock().expect("error lock is not poisoned");
                if slot.is_none() {
                    *slot = Some(Pass2Error::ThreadSpawn(e));
                }
                break;
            }
        }
        for j in 0..nb {
            if first_error
                .lock()
                .expect("error lock is not poisoned")
                .is_some()
            {
                break;
            }
            // Prefer a recycled buffer; allocate a new one when the pool is
            // empty, as it is at startup.
            let buf = ret_rx.try_recv().unwrap_or_default();
            reader.set_buf(buf);
            if let Err(e) = reader.read_block(j) {
                let mut slot = first_error.lock().expect("error lock is not poisoned");
                if slot.is_none() {
                    *slot = Some(Pass2Error::Read(e));
                }
                break;
            }
            if tx.send((j, reader.take_buf())).is_err() {
                break; // All workers have exited (error path).
            }
        }
        drop(tx); // Close the channel so workers exit after draining it.
    });

    if let Some(e) = first_error
        .into_inner()
        .expect("error lock is not poisoned")
    {
        return Err(e);
    }
    for slot in plan.meta_slots() {
        sink.put(slot, plan.meta_packet())
            .map_err(Pass2Error::Write)?;
    }
    let actual_len = reader.file_len().map_err(Pass2Error::Read)?;
    if actual_len != plan.oti.f {
        return Err(Pass2Error::LengthChanged {
            expected: plan.oti.f,
            actual: actual_len,
        });
    }
    if reader.finish_hash() != plan.oti.blake3 {
        return Err(Pass2Error::HashMismatch);
    }
    Ok(())
}

/// Print the encoding summary, the memory hint, and, when applicable, the
/// best-effort warning. All output goes to stderr.
fn print_summary(args: &EncodeArgs, plan: &EncodePlan) {
    let summary = plan.summary();
    let lv = &summary.leveling;
    let f = summary.oti.f;
    let out_bytes = summary.c_total * args.p as u64;
    let source = match summary.total {
        TotalSpec::Size(_) => "size",
        TotalSpec::Redundancy { .. } => "redundancy",
        TotalSpec::Default => "default",
    };
    let eps_eff = (summary.d as f64 * lv.t as f64) / f as f64 - 1.0;
    let meta_pct = 100.0 * summary.c_meta as f64 / summary.c_total as f64;
    let _ = write_stderr(&format!(
        "lapiwe: summary: F={f} output={out_bytes} bytes C_total={} (source={source}) C_meta={} D={} \
         NB={} KS={} K_j=[{},{}] T={} bytes_per_block(K_j*T)<={} metadata_overhead(packet_slots)={:.3}% \
         net_redundancy~=R*(1-1/M)-1 eps_eff={:.3}% min(a_j-needed_j)={} affected_blocks={} best_effort={}\n",
        summary.c_total,
        summary.c_meta,
        summary.d,
        lv.nb,
        lv.ks,
        lv.min_k(),
        lv.max_k(),
        lv.t,
        lv.max_k() * lv.t,
        meta_pct,
        eps_eff * 100.0,
        summary.redundancy.min_slack,
        summary.redundancy.affected_blocks,
        u8::from(summary.best_effort),
    ));
    if let Some(dt) = summary.default_total {
        let _ = write_stderr(&format!(
            "lapiwe: default mode: D_req={} C_total_min={} (recomputed minimum publishable packet count)\n",
            dt.d_req, dt.c_total_min
        ));
    }
    // Total encoding memory is bounded by (3·min(jobs,NB)+2)·max_j(K_j·T).
    // `--max-mem` limits the source-data budget of a single block, not total
    // process residency.
    let max_block = lv.max_k() * lv.t;
    let hint = plan.mem_hint_bytes(args.jobs);
    let _ = write_stderr(&format!(
        "lapiwe: memory hint: encoding memory upper bound ~= (3*min(jobs,NB)+2)*max_j(K_j*T) = \
         (3*min({}, {})+2)*{max_block} = {hint} bytes (max_mem={} bytes bounds one block's source budget \
         K_j*T <= max_mem, not total process residency)\n",
        args.jobs, lv.nb, args.max_mem
    ));
    if summary.best_effort {
        // The warning states that effective redundancy is insufficient, that
        // the output is best-effort and not trustworthy, and includes
        // `min(a_j−needed_j)` and the number of affected blocks.
        let _ = write_stderr(&format!(
            "lapiwe: warning: insufficient effective redundancy (min(a_j-needed_j)={}, affected_blocks={}; \
             best_effort=1) - the output is best-effort and must not be trusted\n",
            summary.redundancy.min_slack, summary.redundancy.affected_blocks
        ));
    }
}

/// Write file output through a temporary file in the destination directory,
/// then `sync_all` and rename it into place atomically.
fn write_file_atomic(path: &Path, plan: &EncodePlan, input_path: &Path, args: &EncodeArgs) -> u8 {
    let (tmp_path, file, mut guard) = match create_temp_for(path) {
        Ok(x) => x,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to create a temporary output near {}: {e}\n",
                path.display()
            ));
            return exit_code::OTHER;
        }
    };
    let sink = SeekSink { file, p: plan.p() };
    // Validation already happened in `plan()`; any failure here leaves the
    // destination untouched because the guard removes the temporary file.
    if let Err(e) = encode_all_blocks(plan, input_path, &sink, args.jobs) {
        return report_pass2(&e, input_path);
    }
    if let Err(e) = sink.file.sync_all() {
        let _ = write_stderr(&format!("lapiwe: error: failed to sync output: {e}\n"));
        return exit_code::OTHER;
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = write_stderr(&format!(
            "lapiwe: error: atomic publish failed ({} -> {}): {e}\n",
            tmp_path.display(),
            path.display()
        ));
        return exit_code::OTHER;
    }
    guard.defuse();
    print_summary(args, plan);
    exit_code::OK
}

/// Sequential packet-slot writer for `NB = 1`. Data slots arrive in ascending
/// order, and the gaps between them contain only metadata slots, which are
/// filled with [`EncodePlan::meta_packet`].
struct SeqWriter<'a, W: Write> {
    out: &'a mut W,
    plan: &'a EncodePlan,
    next_slot: u64,
}

impl<W: Write> SeqWriter<'_, W> {
    fn put(&mut self, slot: u64, packet: &[u8]) -> io::Result<()> {
        while self.next_slot < slot {
            debug_assert!(
                self.plan.is_meta_slot(self.next_slot),
                "gap must be a metadata slot"
            );
            self.out.write_all(self.plan.meta_packet())?;
            self.next_slot += 1;
        }
        self.out.write_all(packet)?;
        self.next_slot = slot + 1;
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        while self.next_slot < self.plan.c_total {
            debug_assert!(
                self.plan.is_meta_slot(self.next_slot),
                "trailing gap must be a metadata slot"
            );
            self.out.write_all(self.plan.meta_packet())?;
            self.next_slot += 1;
        }
        self.out.flush()
    }
}

/// Write to stdout sequentially without spooling when `NB = 1`. The block is
/// read and the BLAKE3 digest verified before anything is written.
fn write_stdout_nb1(plan: &EncodePlan, input_path: &Path, args: &EncodeArgs) -> u8 {
    let mut reader = match BlockReader::open(plan, input_path) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to read input {}: {e}\n",
                input_path.display()
            ));
            return exit_code::OTHER;
        }
    };
    if let Err(e) = reader.read_block(0) {
        return report_pass2(&Pass2Error::Read(e), input_path);
    }
    // Verify the length and content before writing any stdout bytes, so a
    // failed check produces no output.
    match reader.file_len() {
        Ok(len) if len == plan.oti.f => {}
        Ok(len) => {
            return report_pass2(
                &Pass2Error::LengthChanged {
                    expected: plan.oti.f,
                    actual: len,
                },
                input_path,
            );
        }
        Err(e) => return report_pass2(&Pass2Error::Read(e), input_path),
    }
    if reader.finish_hash() != plan.oti.blake3 {
        return report_pass2(&Pass2Error::HashMismatch, input_path);
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let result = {
        let mut writer = SeqWriter {
            out: &mut out,
            plan,
            next_slot: 0,
        };
        plan.encode_block(0, reader.buf(), |slot, packet| writer.put(slot, packet))
            .and_then(|()| writer.finish())
    };
    if let Err(e) = result {
        return match e.kind() {
            io::ErrorKind::BrokenPipe => exit_code::OK, // A closed pipe is normal.
            _ => {
                let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
                exit_code::OTHER
            }
        };
    }
    print_summary(args, plan);
    exit_code::OK
}

/// Spool stdout output to `$TMPDIR` when `NB > 1` so packets can be written by
/// slot, then copy the spool to stdout after validation succeeds.
fn write_stdout_spooled(plan: &EncodePlan, input_path: &Path, args: &EncodeArgs) -> u8 {
    let dir = std::env::temp_dir();
    let (spool_path, file) = match create_unique(&dir, "lapiwe-encode-out") {
        Ok(x) => x,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to create output staging near {}: {e}\n",
                dir.display()
            ));
            return exit_code::OTHER;
        }
    };
    let guard = TempGuard::new(spool_path.clone());
    let sink = SeekSink { file, p: plan.p() };
    if let Err(e) = encode_all_blocks(plan, input_path, &sink, args.jobs) {
        // Validation failed: nothing is written to stdout, and the guard
        // removes the spool.
        return report_pass2(&e, input_path);
    }
    // Validation passed; copy the spool sequentially. The write handle is
    // dropped and the file is reopened read-only.
    drop(sink);
    let mut file = match File::open(&spool_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to read output staging: {e}\n"
            ));
            return exit_code::OTHER;
        }
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let copied = io::copy(&mut file, &mut out).and_then(|_| out.flush());
    match copied {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return exit_code::OK, // Normal close.
        Err(e) => {
            let _ = write_stderr(&format!("lapiwe: error: failed to write stdout: {e}\n"));
            return exit_code::OTHER;
        }
    }
    drop(guard); // The spool is no longer needed; dropping removes it.
    print_summary(args, plan);
    exit_code::OK
}

/// Run the `encode` command and return the CLI exit code.
pub fn run(args: &EncodeArgs) -> u8 {
    let input_is_stdin = args.input == "-";
    let (input_path, _spool_guard): (PathBuf, Option<TempGuard>) = if input_is_stdin {
        match spool_stdin(args.spool_dir.as_deref()) {
            Ok((path, guard)) => (path, Some(guard)),
            Err(e) => {
                let _ = write_stderr(&format!("lapiwe: error: stdin staging failed: {e}\n"));
                return exit_code::OTHER;
            }
        }
    } else {
        (PathBuf::from(&args.input), None)
    };

    let target = output_target(args);

    // Encoding never modifies its input, so reject `-o` pointing at the input
    // file.
    if let OutputTarget::File(path) = &target {
        if !input_is_stdin && same_path(&input_path, path) {
            let _ = write_stderr(
                "lapiwe: error: `-o` and <IN> refer to the same path; encoding does not modify its input (choose a different output path)\n",
            );
            return exit_code::OTHER;
        }
    }

    // First pass.
    let info = match prescan_file(&input_path) {
        Ok(info) => info,
        Err(e) => {
            let _ = write_stderr(&format!(
                "lapiwe: error: failed to read input {}: {e}\n",
                input_path.display()
            ));
            return exit_code::OTHER;
        }
    };
    if info.f == 0 {
        // Empty input always exits with status 1, even with `--force`.
        let _ = write_stderr(
            "lapiwe: error: input is empty (F=0); an empty input does not define a container - provide at least 1 byte\n",
        );
        return exit_code::OTHER;
    }

    let cfg = EncodeConfig {
        p: args.p,
        m: args.m,
        k_max: args.k_max,
        total: args.total,
        force: args.force,
    };
    // All validation happens here, so a rejected configuration creates no
    // output.
    let plan = match plan(&info, &cfg) {
        Ok(plan) => plan,
        Err(err) => return report_error(&err, args.p),
    };

    match &target {
        OutputTarget::File(path) => write_file_atomic(path, &plan, &input_path, args),
        OutputTarget::Stdout if plan.leveling.nb == 1 => write_stdout_nb1(&plan, &input_path, args),
        OutputTarget::Stdout => write_stdout_spooled(&plan, &input_path, args),
    }
}
