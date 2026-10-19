# lapiwe Performance and Benchmark Report

[简体中文](PERFORMANCE.zh.md)

This report records measured end-to-end throughput, recovery behavior under packet loss, multi-threaded scaling, peak resident memory (RSS), and temporary storage usage. All figures are measurements, not estimates. The measurement method, test conditions, and known limits are described in each section.

The numbers below were collected on the hardware and software described in Section 1. They are a guide to behavior and bottlenecks on one laptop, not a promise for your hardware: storage, CPU frequency scaling, and packet-loss patterns all affect the results.

---

## 1. Test Environment Specifications

### 1.1 Hardware and software

| Item | Configuration |
|---|---|
| CPU | Intel Core i5-8265U (4 physical cores / 8 logical threads, 15 W ULV; `powersave` + turbo, measured 1.9–3.7 GHz) |
| Memory | 16 GiB RAM (15.6 GiB available) |
| Storage | RAM disk: `tmpfs` (7.7 GiB); local encrypted SSD: `btrfs` over LUKS (dm-crypt, zstd:3); severe-loss isolated medium: `/dev/shm` (7.6 GiB available) |
| Toolchain | rustc/cargo 1.97.1 (stable), Rust edition 2024 |
| Core dependencies | `raptorq = 2.0.1`, `blake3 = 1.8.7`, `crc32c = 0.6.8`, `signal-hook = 0.3.18` |
| Build modes | Release (`cargo build --release --locked`) and debug |
| Spool/dump path | `/path/to/spool` (selected with the `$TMPDIR` environment variable) |

### 1.2 Measurement methodology

- **Throughput.** Throughput is the source data size $F$ divided by wall-clock time. Figures use the best of several samples; the sample count is noted in each section. Benchmark cases are serialized within the process. Severe-loss tests interleave baseline and measured runs to reduce CPU frequency drift.
- **Peak RSS.** The parent polls `/proc/<pid>/status` for `VmHWM` every 1 ms and cross-checks the final value against `wait4(2)`/`ru_maxrss`. Sampling starts only after the child has completed `exec`, avoiding copy-on-write artifacts from the parent's address space.
- **Units.** Binary prefixes are used: 1 KiB = 1024 B, 1 MiB = $2^{20}$ B, 1 GiB = $2^{30}$ B. Ratios compare runs on the same machine, with the same data shape, in the same measurement session.
- **Media comparison.** `tmpfs` isolates codec and protocol throughput from disk I/O. The local encrypted SSD measures real storage and filesystem overhead. Results for the two media are reported separately.

### 1.3 RaptorQ codec baseline and complexity

Single-block and multi-block round trips of the underlying algebraic codec at different symbol scales (debug build):

| Case | Configuration | Time | Peak RSS |
|---|---|---:|---:|
| Independent-block round trip | NB=300 independent blocks, T=2032, K=64 | 12.8 s | 12 MiB |
| Source-packet loss solve | T=2032, K=1024, 1/4 of source packets lost | 205.0 s | 17 MiB |
| Large-symbol loss solve | T=65520, K=1024, 1/4 of source packets lost | 231.9 s | 348 MiB |
| Very large metadata derivation | F=1 TiB, per-block OTI derivation only | 0.0 s | — |
| Determinism check | Two encodings with identical parameters, byte comparison | 0.4 s | — |

- **Determinism.** Two independent encodings with the same parameters and input are byte-identical.
- **Independent OTI.** Each data block uses its own OTI ($(K_j \cdot T, T, 1, 1, 8)$). At $T=65520, K=1024$, one block carries $K_j \cdot T = 67,092,480$ bytes of source data.
- **Very large inputs.** For $F > 942$ GB, the tool derives only the metadata structure and does not preallocate the full object; the flow completes without panics.
- **Debug vs release.** Gaussian elimination and matrix work in RaptorQ grow superlinearly with $K$. Increasing $K$ from about 250 to about 2000 raises debug-build time from about 1.4 s to about 433 s (roughly 300×), while the optimized release build takes 0.16 s. Production measurements use release builds.

### 1.4 Test suite and benchmark targets

The repository contains integration tests covering correctness, performance boundaries, and fault tolerance:

| Topic | Test file | Coverage |
|---|---|---|
| Codec baseline and determinism | `tests/container_encode.rs`, `tests/container_decode.rs` | Multi-block and large-block round trips, independent per-block OTI, byte-for-byte determinism |
| Recovery thresholds and representative severe loss | `tests/cli_decode.rs` | Representative loss patterns, decode outcomes, parallel consistency |
| Stream frame synchronization | `tests/container_scan.rs` | Bounded recovery with a fixed 64 KiB ring scanner under adversarial garbage |
| Encode throughput and parallel scaling | `tests/cli_encode.rs` | Multi-thread scaling, symbol-size effects, memory model |
| Decode throughput and multi-thread consistency | `tests/cli_decode.rs` | Consistency across worker counts, representative loss calibration |
| Streaming and constant memory | `tests/cli_decode.rs` | Resident-memory checks across 2 GiB to 8 GiB inputs |
| Ledger and spill state machine | `tests/container_ledger.rs` | Symbol state, inline buffering, and spill-file consistency |
| In-place target patching | `tests/container_patch.rs` | Chunked target reads, sparse overlay writes, patch memory model |
| CLI behavior and signals | `tests/cli_smoke.rs`, `tests/cli_encode.rs`, `tests/cli_encode_stream.rs`, `tests/cli_signals.rs` | Dispatch, help, pipes, stream handling, temporary-file cleanup |

### 1.5 Measurement notes and known limits

1. **Sampling.** Throughput and scaling ratios use best-of-3 or best-of-5 sampling. Calibration cases are serialized within the process to avoid interference.
2. **RSS collection.** Polling starts only after the child `exec`s the target binary, so the parent's cloned address space does not contaminate the resident-memory reading.
3. **Frequency and thermal noise.** A 15 W mobile CPU can vary by ±10%–20% due to frequency scaling and power limits. Relative scaling ratios are used to average out this variation.
4. **Media isolation.** `tmpfs` measurements isolate algorithm and protocol throughput. Encrypted-SSD measurements include real I/O overhead. The two sets of figures are reported separately.

---

## 2. End-to-End Throughput and Recovery Performance

### 2.1 Recovery simulation and tolerance boundary

The end-to-end chain is `encode → inject damage → streaming scan → finish`. The critical boundary is scanned in steps of at most 0.5%. The metric is the minimum solvable residue ratio $\rho_{\min}$, the ratio of the smallest solvable residue size to the total stream size. The theoretical target is $\rho_{\min} \le 1 + \varepsilon_{\text{eff}} + \delta$, with tolerance margin $\delta = 0.02$.

| Configuration | Damage pattern | Minimum solvable residue (packets) | $\rho_{\min}$ (measured) | Theoretical bound $1+\varepsilon_{\text{eff}}+\delta$ | Measured margin |
|---|---|---:|---:|---:|---:|
| 1 MiB / P=4096 / default | contiguous / scattered / multi-segment / corrupt symbols | 4 | 101.5625% | 103.9440% | 2.38 pp |
| 1 MiB / P=4096 / 2.05× redundancy | contiguous 1 MiB (large megabyte-scale loss) | 256 | 105.0781% | 205.1097% | 100.03 pp |
| 512 KiB / P=2048 (T=2032) | contiguous loss | 4 | 101.9531% | 103.9318% | 1.98 pp |
| 8 MiB / P=4096 / k_max=256 (NB=9) | contiguous loss (multi-block interleaving) | 36 = 4·NB | 100.8789% | 103.7981% | 2.92 pp |
| 8 MiB / P=4096 / default | contiguous loss | 11 = D−K | 100.8789% | 102.5821% | 1.70 pp |

- **Damage-injection safety.** When deliberately corrupted symbols are injected (including constructed CRC false positives), corruption is isolated and rejected at verification. No false success is returned; every `Ok` result is also checked byte-for-byte.
- **Measured margin.** The tightest measured margin at $\delta = 0.02$ is 1.70 percentage points (8 MiB, default parameters). This covers the container header overhead and the upper bound on misalignment loss ($\le 1.58\%$).
- **Execution time.** An 8 MiB object takes 0.48–0.67 s end to end in a release build (about 36–64 s in a debug build).

### 2.2 Frame synchronization and stream-contamination recovery

- **Bounded ring scan window.** The stream scanner uses a fixed 64 KiB ring buffer (`RING_CAP = max(P)`), allocated once at startup and never resized during scanning. In a test with 16 MiB of pseudorandom garbage, the scan buffer stays at 64 KiB, so memory is strictly bounded.
- **Recovery from malformed frames.** In tests with forged `SYNC` markers (inducing attempts to read the maximum 65,536-byte frame), dense candidate markers (256 KiB of candidate headers), overlapping sync words, truncated packets, and garbage before or after a valid stream, the scanner falls back one byte at a time and re-locks onto the real stream without panicking.

### 2.3 Passthrough vs solve performance (light loss)

When the stream is complete or nearly complete, the engine can bypass Gaussian elimination and write received source symbols directly (passthrough mode). The table compares fully complete streams with light loss (one source symbol missing per block, which triggers solving):

| Payload size | Passthrough throughput (MiB/s) | Solve throughput (MiB/s) | Speedup |
|---|---:|---:|---:|
| F = 64 MiB | 620.7 | 274.7 | 2.3× |
| F = 256 MiB | 733.0 | 184.0 | 2.85× wall clock / 3.99× statistical |

- Complete streams achieve 100% passthrough for all tested block layouts (NB=3, 5, 17, 65, and others).
- Passthrough throughput is 2.3× to 3.99× the solve path, saving substantial CPU work.

### 2.4 In-place target patching performance

In patch mode, the decoder scans the existing damaged target for missing regions and repairs only those regions, avoiding a full rewrite.

#### 2.4.1 Target scan: 64 KiB chunk reads vs per-symbol reads

This isolates the target-file scan (excluding stream reception and decoding):

| Data size F | Per-symbol `pread` (4 KiB granularity) | 64 KiB chunk reads (6-sample aggregate) | Improvement |
|---:|---|---|---|
| 64 MiB | 0.017–0.019 s (3,316–3,785 MiB/s), 16,449 calls | **0.007–0.009 s** (6,805–9,558 MiB/s), 1,030 calls (63.6 KiB/call) | 93.7% fewer syscalls (÷16); 1.9–2.7× lower idle time on the same machine |
| 256 MiB | 0.088–0.093 s (2,743–2,917 MiB/s), 65,794 calls | **0.028–0.042 s** (6,053–9,271 MiB/s), 4,114 calls (63.7 KiB/call) | 93.7% fewer syscalls (÷16); 2.1–3.3× lower idle time on the same machine |

- **Deterministic metric.** Syscall counts drop from 16,449 / 65,794 to 1,030 / 4,114 (one sixteenth), with an average chunk length of 63.6–63.7 KiB.
- **Share of end-to-end time.** Input-stream CRC and verification dominate the full patch operation (stream scan takes 0.8–2.4 s at F=255 MiB). The target scan is about 1.5–4% of wall-clock time; the benefit is mainly lower syscall overhead and roughly doubled read throughput.

#### 2.4.2 Patch-mode memory and disk usage

Configuration: $P=4096, T=4080$, redundancy 2.0, default memory budget 64 MiB. Three scenarios are measured: intact file, damaged solve (first symbol missing in every block), and forced spill.

**Layout A: `--block-symbols 1024` (one block $K_j \cdot T \approx 4.18$ MiB)**

| Scenario | Data size F | jobs | Peak RSS (KiB) | Spill bytes | Bytes actually written to target |
|---|---|---:|---:|---:|---:|
| Intact | 66,846,720 (63.75 MiB) | 1 / 4 | 6,832–6,956 / 6,828–7,116 | 0 | 0 |
| Damaged solve | 66,846,720 | 1 / 4 | 82,852–82,940 / 96,852–101,512 | 0 | 65,280 |
| Forced spill | 66,846,720 | 1 / 4 | 18,460–18,616 / 58,636–58,744 | 65,802,240 | 65,280 |
| Intact | 267,386,880 (255.0 MiB) | 1 / 4 | 9,420–9,768 / 9,300–9,520 | 0 | 0 |
| Damaged solve | 267,386,880 | 1 / 4 | 89,240–89,396 / 120,348–125,620 | 196,174,560 | 261,120 |
| Forced spill | 267,386,880 | 1 / 4 | 23,872–23,972 / 63,852–64,300 | 263,217,120 | 261,120 |

**Layout B: `--block-symbols 4096` (one block $K_j \cdot T \approx 16.71$ MiB)**

| Scenario | Data size F | jobs | Peak RSS (KiB) | Spill bytes | Bytes actually written to target |
|---|---|---:|---:|---:|---:|
| Damaged solve | 66,846,720 (4 blocks) | 1 / 4 | 120,864–120,924 / 216,896–234,960 | 0 | 16,320 |
| Damaged solve | 267,386,880 (16 blocks) | 1 / 4 | 128,184–128,304 / 279,104–279,488 | 196,174,560 | 65,280 |

- **Sparse writes.** In patch mode, bytes written to the target are exactly the missing-symbol bytes (65,280 / 261,120 B or 16,320 / 65,280 B). There is no full-file rewrite.
- **Memory behavior.** The intact path uses only 6.8–9.8 MiB resident memory. Forced spill gives up the in-memory buffer and therefore has a lower peak RSS than the pure in-memory solve path.

### 2.5 Large symbol sizes

Input $F=256$ MiB, redundancy 2.0, four worker threads:

| Symbol size P | Blocks NB | Source symbols per block $K_j$ | Encode throughput (MiB/s) | Decode throughput (MiB/s) |
|---:|---:|---:|---:|---:|
| 4,096 | 5 | 13,158 | 168.4 | 223.1 |
| 32,768 | 5 | 1,639 | 197.5 | 252.8 |
| 65,536 | 5 | 819 | 196.1 | 280.4 |

- Cross-check run: encode throughput was 119.4 / 148.5 / 146.5 MiB/s. On a 1 GiB input, decode throughput rose from 409 MiB/s at $P=2048$ to about 826 MiB/s at $P=65536$.
- **Conclusion.** Larger $P$ reduces $K$ within a block, which reduces the matrix dimension. Throughput does not degrade; it improves steadily.

---

## 3. Decoding Performance Under Severe Loss

### 3.1 Severe-loss benchmark matrix

Input: $F = 268,435,456$ B (256 MiB), $P=4096, T=4080$, redundancy 2.0. Two block layouts are compared:

- **Default:** maximum block size about 15.7 MiB, NB=17, block source symbols $K_j \in \{3870, 3871\}$.
- **Small-block** (`--block-symbols 1024`): about 4.1 MiB per block, NB=65, block source symbols $K_j \in \{1012, 1013\}$.

Damage pattern: each block drops its first $n_j$ source symbols (respectively 1 symbol, 10% of source symbols, and 30% of source symbols). All repair symbols are retained. Tests run independently on a RAM disk (`tmpfs`) and a local encrypted disk (`btrfs + LUKS`):

| Medium | Layout | Loss | jobs=4 best (s) | Throughput (MiB/s) | Peak RSS (KiB) | jobs=1 best (s) | Throughput (MiB/s) | 8-thread throughput | Stage split: scan / settle / verify (s) |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| tmpfs | default | 1 symbol | 0.959 | 266.8 | 268,484 | 1.303 | 196.5 | — | 0.790 / 0.012 / 0.107 |
| tmpfs | default | 10% | 0.952 | 268.9 | 257,132 | 1.303 | 196.5 | — | 0.768 / 0.014 / 0.117 |
| tmpfs | default | 30% | 0.931 | 274.9 | 252,748 | 1.278 | 200.4 | 243.2 | 0.750 / 0.011 / 0.116 |
| tmpfs | small-block | 1 symbol | 0.874 | 292.9 | 117,948 | 1.150 | 222.6 | — | 0.703 / 0.015 / 0.113 |
| tmpfs | small-block | 10% | 0.869 | 294.7 | 127,320 | 1.133 | 226.0 | — | 0.704 / 0.014 / 0.111 |
| tmpfs | small-block | 30% | 0.864 | 296.4 | 119,928 | 1.116 | 229.3 | 267.3 | 0.692 / 0.015 / 0.111 |
| local encrypted disk | default | 1 symbol | 1.521 | 168.3 | 268,420 | 1.871 | 136.9 | — | 1.120 / 0.011 / 0.115 |
| local encrypted disk | default | 10% | 1.421 | 180.2 | 257,728 | 1.785 | 143.4 | — | 1.085 / 0.012 / 0.111 |
| local encrypted disk | default | 30% | 1.403 | 182.4 | 263,792 | 1.749 | 146.4 | 166.3 | 1.028 / 0.009 / 0.111 |
| local encrypted disk | small-block | 1 symbol | 1.389 | 184.3 | 117,848 | 1.675 | 152.8 | — | 1.023 / 0.014 / 0.110 |
| local encrypted disk | small-block | 10% | 1.379 | 185.7 | 122,544 | 1.666 | 153.7 | — | 1.018 / 0.015 / 0.111 |
| local encrypted disk | small-block | 30% | 1.296 | 197.5 | 128,076 | 1.685 | 151.9 | 167.4 | 0.952 / 0.014 / 0.108 |

- **Recovery completeness.** All 12 configurations returned `Ok` across repeated runs, with 100% of blocks recovered (NB/NB). Every block went through the solve path; the passthrough count was zero.
- **Medium effect.** On tmpfs, jobs=4 throughput is 267–296 MiB/s (jobs=1: 197–229 MiB/s). On the encrypted SSD, end-to-end throughput falls to 168–198 MiB/s (jobs=1: 137–154 MiB/s), dominated by encrypted-filesystem I/O and stream reception.
- **Effect of loss rate.** Going from 1 lost symbol to 30% lost symbols changes end-to-end time by less than ±5%. Higher loss means a shorter stream must be received, which offsets the extra solve work.

### 3.2 Throughput relative to pure-codec baselines

Comparison with same-machine in-memory `raptorq` baselines (A: combined encode/decode throughput; A′: solve-only throughput; B: same-medium stream read plus solve):

| Test row (30% loss) | lapiwe throughput (MiB/s) | Baseline A (MiB/s) | Ratio A | Baseline A′ (MiB/s) | Ratio A′ | Baseline B (MiB/s) | Ratio B |
|---|---:|---:|---:|---:|---:|---:|---:|
| tmpfs / default | 274.9 | 290.1 | **0.948** | 515.7 | 0.533 | 337.4 | 0.815 |
| local encrypted disk / default | 182.4 | 290.1 | **0.629** | 515.7 | 0.354 | 365.7 | 0.499 |
| tmpfs / small-block | 296.4 | 398.0 | **0.745** | 743.9 | 0.398 | 450.4 | 0.658 |
| local encrypted disk / small-block | 197.5 | 398.0 | **0.496** | 743.9 | 0.265 | 458.7 | 0.431 |

- **Single-thread baseline ratio.** With jobs=1, lapiwe is comparable to baseline A (tmpfs/default: **1.120**; tmpfs/small-block: **0.993**).
- **Multi-threading and disk bottleneck.** Under parallelism and real disk I/O, the ratio falls to 0.496–0.745. The cause is analyzed below.
- **Default block-size sensitivity.** Under severe loss, the default layout reaches 0.917–0.999× the throughput of the small-block layout at jobs=4, which is stable overall.

### 3.3 Decode stage breakdown and attribution

Breakdown of the 30% loss rows:

| Test row (30% loss) | End-to-end throughput (MiB/s) | Stream scan and unpack | Tail settlement solve | Full-stream verify | Pure solve baseline A′ | jobs=1 solve-segment throughput | Solve segment / A′ |
|---|---:|---:|---:|---:|---:|---:|---:|
| tmpfs / default | 274.9 | 81% | 1% | 12% | 515.7 | 366.2 | 0.710 |
| local encrypted disk / default | 182.4 | 73% | 1% | 8% | 515.7 | 344.5 | 0.668 |
| tmpfs / small-block | 296.4 | 80% | 2% | 13% | 743.9 | 464.6 | 0.625 |
| local encrypted disk / small-block | 197.5 | 73% | 1% | 8% | 743.9 | 433.2 | 0.582 |

- **Dominant bottleneck.** **73%–81% of end-to-end wall-clock time is spent in stream scanning and unpacking** (stream reception, per-packet CRC checks, write-through of valid symbols, and spill staging of repair symbols). **8%–13% is BLAKE3 verification read-back**, while tail settlement solving is only **1%–2%** (most blocks are solved in parallel while the stream is being scanned).
- **Attribution.** The gap between end-to-end throughput and the pure-codec baseline comes from **data movement across the pipeline** (protocol unpacking, state management, spill read-back, and disk I/O), not from algebraic elimination itself.

### 3.4 Low-redundancy, high-loss case: 1.5× redundancy with 30% source loss

With redundancy reduced to **1.5** (repair symbols equal to 50% of source symbols) and **30% of source symbols lost per block**:

| Data size F | Layout | jobs | Exit code | Result | Blocks solved | Blocks solved via solver | Lost symbols | Peak RSS (KiB) | Wall time (s) |
|---|---|---:|---:|---|---|---|---:|---:|---:|
| 64 MiB | default | 4 | 0 | success (byte-identical) | 5/5 | 5/5 | 4,935 | 161,076 | 0.388 |
| 64 MiB | default | 1 | 0 | success (byte-identical) | 5/5 | 5/5 | 4,935 | 73,652 | 0.369 |
| 64 MiB | small-block | 4 | 0 | success (byte-identical) | 17/17 | 17/17 | 4,947 | 87,628 | 0.309 |
| 64 MiB | small-block | 1 | 0 | success (byte-identical) | 17/17 | 17/17 | 4,947 | 47,736 | 0.308 |
| 256 MiB | default | 4 | 0 | success (byte-identical) | 17/17 | 17/17 | 19,741 | 281,512 (rerun 280,328) | 1.294 |
| 256 MiB | default | 1 | 0 | success (byte-identical) | 17/17 | 17/17 | 19,741 | 117,496 | 1.968 |
| 256 MiB | small-block | 4 | 0 | success (byte-identical) | 65/65 | 65/65 | 19,760 | 128,244 | 1.177 |
| 256 MiB | small-block | 1 | 0 | success (byte-identical) | 65/65 | 65/65 | 19,760 | 85,540 | 1.568 |

- **Recovery success.** Every configuration exited 0, BLAKE3 matched exactly, and 100% of blocks were recovered through the solver. At 256 MiB, spill usage was 64,031,520 B.
- **Theoretical tolerance boundary.** With the same stream configuration, loss rates from 35% up to **48%** still recover completely. At **49%** the decoder reports insufficient symbols and exits safely (fast failure in 0.08–0.09 s, with no partial destructive output). The measured boundary agrees with the theoretical tolerance limit (48.2%–48.7%); at 30% loss there is still about 18 percentage points of margin.

### 3.5 Repair-symbol lookup complexity and microbenchmark

Lookup throughput for the per-block repair-symbol table at extreme block counts and sizes:

| Blocks NB | Repair symbols per block M | Cumulative lookup entries $\Sigma = \frac{M \cdot NB(NB+1)}{2}$ | Total time | Lookup throughput |
|---:|---:|---:|---:|---:|
| 64 | 1,024 | 2,129,920 | 0.013–0.014 s | 152 Mscan/s |
| 256 | 1,024 | 33,685,504 | 0.274–0.294 s | 115 Mscan/s |
| 1,024 | 256 | 134,348,800 | 0.977–1.076 s | 125 Mscan/s |
| 1,024 | 1,024 | 537,395,200 | **4.355–4.469 s** | 121 Mscan/s |

- In a typical configuration (NB=65, M≈1012), the cumulative lookup is about $2.17 \times 10^6$ entries and takes about **0.02 s** (1–2% of wall-clock time), with no significant effect on end-to-end performance.
- At the extrapolated 100 GB scale (NB≈5963, M≈4112), the cumulative scan grows; an interval index (such as `BTreeMap::range`) would amortize lookup time further.

---

## 4. Multi-Threaded Scaling

### 4.1 Encoding throughput and parallel scaling

Workload: $F=64$ MiB, $P=4096$, `--block-symbols 1024` (NB=17), redundancy 2.0, measured on `tmpfs`:

| Metric | Measured | Reference requirement | Result |
|---|---:|---:|---|
| Single-core relative throughput (vs same-machine pure-codec baseline) | 0.60–0.66 | $\ge 0.50$ | meets target |
| Parallel speedup: jobs=2 (relative to same-shape codec ratio) | 0.94–1.04 | $\ge 0.85$ | meets target |
| Parallel speedup: jobs=4 (relative to same-shape codec ratio) | 1.03–1.18 | $\ge 0.85$ | meets target |
| Absolute wall-clock speedup: jobs=4 | 1.53–2.13 | 1.7× reference | as expected |

**Underlying algorithm and hardware memory-bandwidth ceiling (independent probe):**

| Data shape | 2 threads (w=2) | 4 threads (w=4) | 8 threads (w=8) |
|---|---:|---:|---:|
| $K \approx 968$ (current test shape) | 1.77–1.86× | 1.99–2.03× | 1.78–2.01× |
| $K \approx 1012$ | 1.83× | 2.14× | — |
| $K \approx 499$ | 1.87× | 2.86× | — |
| $K \approx 253$ | 1.90× | 3.29× | 2.79× |
| BLAKE3 pure compute (hardware reference) | 2.01× | 4.06× | 4.52× |

- **Hardware characteristics.** At $K \approx 1000$, the underlying RaptorQ library is limited to about 2.0× at four threads by L3 cache and memory-bus bandwidth. lapiwe reaches 91%–105% of that hardware ceiling. For $K \lesssim 256$, the underlying library scales to 3.29×.

### 4.2 Decode parallel scaling and consistency

In the streaming/spill architecture, end-to-end decode time is dominated by stream reception, CRC checks, and source-symbol write-through, which are I/O and serial stages. This differs from pure in-memory matrix solving:

| Check | Evaluation | Measured | Verdict |
|---|---|---|---|
| Parallel consistency | jobs $\in \{1,2,4,8\}$ across file output, streaming output, and no-verify modes | byte-identical output and state | pass |
| Parallel scaling ratio | relative to same-machine pure-codec multi-thread scaling | **0.72** (0.61–0.79 across runs) | bottleneck attributed to streaming reception and disk I/O |
| Memory ceiling | peak RSS within the theoretical structural bound | L0: 97,944–103,012 KiB (limit 133,846); L1: 71,416–77,500 KiB (limit 118,596) | pass |

- The 0.72 relative scaling ratio reflects the serial stream-parsing and single-disk-write bottlenecks. The relevant optimization direction is multi-threaded pipeline I/O, not matrix solving.

---

## 5. Memory Footprint and Spooling Budget

### 5.1 Encoding memory (1 GiB input)

Peak RSS for different symbol sizes and worker counts at a 1 GiB input:

| Encode configuration | jobs=1 | jobs=2 | jobs=4 | jobs=8 |
|---|---:|---:|---:|---:|
| $P=65536\ (T=65520)$ | 191.7 MiB | — | 871.1 MiB | — |
| $P=2048\ (T=2032)$ | 268.3 MiB | — | 962.1 MiB | — |
| Default ($P=4096$) | 225.7 MiB | 532.0 MiB | 899.6 MiB | 1,638.6 MiB |

- **Theoretical structural model.** Peak memory follows $(3 \cdot \min(\text{jobs}, NB) + 2) \cdot \max_j(K_j \cdot T)$. Measured values are +3.0% to +14.1% above the model.
- **Per-block isolation.** Resident memory for a single block is strictly bounded by `--max-mem` (default 16 MiB).
- **Independent of total size.** Encoding peak memory depends only on the number of concurrent blocks and the per-block size, not on the total input size $F$.

### 5.2 Decoding memory and constant-memory streaming

The decode engine uses streaming with on-disk state. Its theoretical memory model is:

- **Solve path:** $\min(\text{jobs}, NB, \text{cap}) \cdot (2 \cdot \max_j(K_j \cdot T) + o) + \text{max\_mem} + \mathcal{O}(S/8) + 32$ MiB
- **Complete-source stream:** $\text{max\_mem} + \mathcal{O}(S/8) + 32$ MiB (independent of total size $F$; $S = \lceil F/T \rceil$)

**Measured resident memory and decoupling from file size:**

| Data layout | Input size F | jobs | Peak RSS (KiB) | Limit |
|---|---:|---:|---:|---:|
| Default | 2 GiB | 1 / 2 / 3 / 4 | 4,720–4,764 | $\le 262,144$ |
| Default | 2 GiB | default (8 logical cores) | 4,720–4,732 | $\le 524,288$ |
| Default | 8 GiB | 1 / 4 | 5,272–5,380 (only 604–780 KiB more than 2 GiB) | $\le 262,144$ / difference $\le 65,536$ |
| Default, stdout | 2 GiB | 4 | normal pipe: 4,696–4,728; `--stream`: 19,964–20,040 | $\le 262,144$ |
| Solve + spill (first symbol missing per block) | 256 MiB | 1 / 2 / 3 | 125,180–125,196 / 172,628–172,748 / 219,484–220,308 | $\le 262,144$ |
| Solve + spill (high concurrency) | 256 MiB | 4 / default | 268,180–268,316 / 407,468–428,488 | evaluation tier |

- **Constant-memory behavior holds.** Increasing input from 2 GiB to 8 GiB (4×) increases peak physical memory by less than 0.8 MiB. Resident memory stays at 4.7–5.3 MiB, fully decoupled from total data size.
- **Severe-loss resident memory.** For a 256 MiB input with 10%–30% source symbols lost, jobs=1 peaks at 88–137 MiB, jobs=4 at 117–268 MiB, and 8 threads at 172–428 MiB, all within the memory budget.

### 5.3 Temporary storage and disk usage

| Scenario | Peak temporary space | Mechanism |
|---|---|---|
| Encode (regular file output) | $\le$ output size + 1 MiB | Output is written to a temporary file and atomically renamed |
| Encode (stdin input) | $F$ (staged input) + $C_{\text{total}} \cdot P$ (staged output) | A 512 MiB input stages about 1,080,705,024 B |
| Decode (regular file output) | About $F$ (target temporary file) + repair spill | Source symbols are written through to the target temporary file; no extra full copy |
| Decode (stdout / streaming) | About $F$ (staged output) + repair spill | A staging buffer smooths streaming output |
| Decode (in-place patch) | Overlay only for **missing symbols** (sparse writes) + spill | Writes only missing regions; no full copy |
| Decode (256 MiB severe loss) | $F$ (target temporary file) + spill | Spill is about 0.19–0.26 GiB; increasing `--max-mem` reduces it |

- **Disk quota warning.** If the default temporary directory `$TMPDIR` is a small RAM disk (for example, a 7.7 GiB `tmpfs` with a user quota), processing very large objects or streams with heavy loss can exhaust it. For large decodes, point `--spool-dir /path/to/spool` at a filesystem with sufficient space.

### 5.4 Extrapolation to 100 GB workloads

Extrapolated from the calibrated model:

- **Decode RAM.** Decoupled from total size $F$. With default settings, memory stays at $\le 256$ MiB for jobs=1..4 and $\le 512$ MiB with 8 threads.
- **Temporary disk space.** File output needs about $100$ GB of temporary publication space. In patch mode, only the actually missing symbol bytes are needed (for 1% missing, about 1 GB of overlay space).
- **Processing time.** Multi-threaded end-to-end throughput is about 150–300 MiB/s, depending on storage and loss severity. A 100 GB object is expected to take roughly 5.5 to 11 minutes.
