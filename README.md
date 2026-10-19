# lapiwe

[![CI](https://img.shields.io/github/actions/workflow/status/AzoteGwei/lapiwe/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AzoteGwei/lapiwe/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AzoteGwei/lapiwe?style=flat-square)](https://github.com/AzoteGwei/lapiwe/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square)](https://www.rust-lang.org/)
[![RFC 6330](https://img.shields.io/badge/RFC-6330-informational?style=flat-square)](https://www.rfc-editor.org/rfc/rfc6330)

English | [简体中文](README.zh.md)

`lapiwe` is a command-line fountain-code tool for UNIX pipelines. It encodes a file or stream into a `.lpw` fountain stream and reconstructs the original bytes from any sufficiently large residue. The erasure code is RaptorQ, as specified in [RFC 6330](https://www.rfc-editor.org/rfc/rfc6330), and is provided by the [`raptorq`](https://github.com/cberner/raptorq) crate.

The tool is deliberately small: three subcommands, a streaming scanner, and a text-only interface. It does not encrypt data, manage keys, or require a daemon.

## Features

- `encode`, `decode`, and `inspect` subcommands.
- RaptorQ forward error correction with per-block object transmission information.
- CRC-32C on every packet and a final BLAKE3-256 digest over the complete object.
- Deterministic encoding: identical input and parameters produce byte-identical output.
- Streaming input and output. The decoder scans non-seekable streams and keeps memory bounded independently of the object size.
- Repair symbols that exceed the in-memory budget spill to a temporary file instead of being discarded.
- Atomic publication of file outputs; partial results are not published as final output.
- In-place repair of an existing target image with `--patch`, writing only the missing or unreadable regions.
- Clear exit codes for scripting.

## Requirements

- Rust 1.85 or newer (Edition 2024).
- Linux or macOS. The CLI relies on UNIX pipes, signals, and file semantics; Windows is not a supported target.

## Build and install

Build an optimized binary with the locked dependency set:

```sh
cargo build --release --locked
```

The binary is written to `target/release/lapiwe`. To install it into `~/.cargo/bin`:

```sh
cargo install --path . --locked
```

## Quick start

```sh
# Encode a file. The default output is <IN>.lpw.
lapiwe encode archive.tar

# Recover it. The default output drops the .lpw suffix.
lapiwe decode -o restored.tar archive.tar.lpw

# Inspect metadata and scan statistics without writing anything.
lapiwe inspect archive.tar.lpw
```

A typical pipeline:

```sh
tar czf - ./data | lapiwe encode - -o data.tgz.lpw
lapiwe decode -o - data.tgz.lpw | tar xzf -
```

## Command-line guide

```text
lapiwe encode [OPTIONS] <IN>
lapiwe decode [OPTIONS] <IN>
lapiwe inspect [OPTIONS] <IN>
```

`<IN>` is required. A value of `-` means standard input. Run `lapiwe <subcommand> --help` for the complete option list. Help, diagnostics, and statistics are printed in English; binary data is written only to stdout.

### encode

`encode` turns the input into a sequence of fixed-size packets. The number of packets is controlled by either `--size` or `--redundancy`:

- `--size <SIZE>` sets the target output size in bytes. The actual output is `floor(SIZE / P) * P` bytes, where `P` is the packet size.
- `--redundancy <R>` sets the total output multiplier, including metadata overhead. A bare number such as `1.3` means 1.3× the source size; `30%` is an equivalent way to write 1.3. The value must be at least 1.
- If neither option is given, the encoder chooses the smallest packet count that meets the redundancy requirement.

Sizes accept the following suffixes:

| Form | Multiplier |
|---|---:|
| `K`, `M`, `G`, `T` | 1024 |
| `KiB`, `MiB`, `GiB`, `TiB` | 1024 |
| `KB`, `MB`, `GB`, `TB` | 1000 |

Other encoding options:

| Option | Meaning |
|---|---|
| `-o, --output <PATH>` | Output path. `-` means stdout. Default: `<IN>.lpw`, or stdout when `<IN>` is `-`. |
| `--packet-size <BYTES>` | Packet size `P`: 2048, 4096, 8192, 16384, 32768, or 65536. Default: 4096. |
| `--meta-every <M>` | Insert a metadata packet every `M` packets. `M >= 2`. Default: 256. |
| `--block-symbols <K>` | Maximum source symbols per logical block. Default: the largest value that fits the memory budget, capped at the RFC 6330 limit. |
| `--max-mem <SIZE>` | Per-block source-data memory budget. Default: 16 MiB. Must be at least the symbol size `T = P - 16`. |
| `--jobs <N>` | Number of block encoders to run in parallel. Default: available logical CPUs. |
| `--force` | Encode even when the effective redundancy is too low. The result is marked `best_effort=1` and should not be trusted. |
| `--spool-dir <DIR>` | Directory used to stage stdin and temporary output. Default: `$TMPDIR`. |

`--size` and `--redundancy` are mutually exclusive. Encoding is deterministic: the same input, options, and tool version produce the same bytes.

When the input is `-`, `encode` first copies stdin to a temporary file so that it can make two passes over the data. The temporary file is removed on normal exit, on error, and on `SIGINT`, `SIGTERM`, or `SIGHUP`.

### decode

`decode` scans a `.lpw` stream, reconstructs the original object, and verifies its BLAKE3 digest.

| Option | Meaning |
|---|---|
| `-o, --output <PATH>` | Output path. `-` means stdout. If omitted, the `.lpw` suffix is removed; if the input has no such suffix, `.out` is appended. With stdin input, the default is stdout. |
| `--no-verify` | Skip the final BLAKE3 check. Per-packet CRC-32C is still verified, and a warning is printed. |
| `--stream` | Valid only when the output is stdout. After reconstruction, copy the result out block by block. |
| `--jobs <N>` | Upper bound on decode workers. The result does not depend on `N`. |
| `--max-mem <SIZE>` | Decoder working-set budget. Default: 64 MiB. Must be greater than the 64 KiB scan window. |
| `--spool-dir <DIR>` | Directory for stdout staging, repair-symbol spill, and patch overlay storage. Default: `$TMPDIR`. |
| `--patch <TARGET>` | Repair an existing target image in place. See below. |
| `--missing-ranges <FILE>` | Additional missing ranges for `--patch`. Requires `--patch`. |

The decoder keeps memory bounded independently of the object size. Source symbols are written through to the output file as they arrive. Repair symbols that do not fit in the memory budget are appended to a spill file and read back during settlement.

### inspect

`inspect` reads the stream without writing files or decoding the object. It prints the baseline object transmission information, the derived block layout, the observed packet size, and scan statistics. If no usable metadata packet is found, it prints the statistics it has and exits with code 3.

### In-place patching

`decode --patch TARGET` treats the readable regions of an existing target as already received symbols. It reconstructs the object, writes only the missing or unreadable regions, and then verifies the complete target with BLAKE3.

```sh
lapiwe decode --patch mirror.img --missing-ranges missing.txt residual.lpw
```

- `TARGET` must already exist and must be exactly `F` bytes long, where `F` is the original object size recorded in the stream.
- `--missing-ranges FILE` describes additional missing regions. The file is UTF-8 text with one `START LENGTH` pair per line. Values may be decimal or `0x` hexadecimal and are measured in bytes. Blank lines and `#` comments are ignored. Overlapping or adjacent ranges are merged.
- No bytes are written to `TARGET` until every block has been solved. Only missing regions are written; readable regions that are not listed as missing are left untouched. The final symbol is truncated to `min(T, F - offset)`.
- If the final BLAKE3 check fails, the target may contain silent corruption in a region that was readable but wrong. The tool reports this and suggests a full decode to a new file. `--no-verify` skips the check and prints a warning.
- `--patch` is mutually exclusive with `-o/--output` and `--stream`. `--missing-ranges` is valid only together with `--patch`.
- Temporary space is proportional to the missing symbols, not to the full object. An overlay stores only missing regions, and repair-symbol spill uses the configured spool directory.

### Pipes and signals

Binary data is written only to stdout; diagnostics are written only to stderr, so the tool composes cleanly with pipelines. A broken pipe (`EPIPE`/`SIGPIPE`) is treated as a normal early consumer exit and results in exit code 0.

On `SIGINT`, `SIGTERM`, or `SIGHUP`, temporary files registered by the process are removed before it exits. `SIGKILL` cannot be caught and therefore cannot guarantee cleanup.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success. |
| `1` | Usage, I/O, layout, or other non-recoverable error. |
| `2` | Not enough symbols to reconstruct the object. |
| `3` | No usable object transmission information (metadata). |
| `4` | Reconstruction completed but the BLAKE3 digest did not match. |

## Memory and temporary storage

`lapiwe` separates the memory budget from the object size:

- Encoding memory is bounded by the number of concurrently encoded blocks and the per-block budget, not by the total input size.
- Decoding memory is bounded by the number of active blocks, the working-set budget, and a small index. Source data is written through to the output as it arrives.
- Repair symbols beyond the budget are spilled to disk rather than dropped.
- File output is written to a temporary file and atomically renamed only after successful verification.
- `--patch` needs space only for the missing regions and spill, not a full copy of the target.

The default temporary directory is `$TMPDIR`. If it is a small tmpfs, point `--spool-dir` at a larger filesystem before decoding large objects or streams with heavy loss. If the spool fills up, the decoder reports a single-line I/O error, exits with code 1, and does not publish a file result. With `--stream`, any bytes already copied to stdout are marked untrusted.

See [`PERFORMANCE.md`](PERFORMANCE.md) for measured throughput, memory footprints, and spooling behavior (also available in [Chinese](PERFORMANCE.zh.md)).

## Data integrity

Every packet carries a CRC-32C that covers the header and payload. The complete object is protected by a BLAKE3-256 digest recorded in the metadata. The decoder uses the per-packet CRC to reject damaged packets and the final digest to decide whether the reconstructed object is correct. `--no-verify` disables only the final digest check; packet-level checking remains active.

`lapiwe` does not encrypt or authenticate data. If confidentiality or cryptographic authenticity is required, encrypt the resulting stream or the original object with an appropriate tool.

The on-wire container format stores version 4 in its header (`VER = 4`). This is the container format version, not the tool release number. The current tool release is 1.0.0.

## RaptorQ and patent notes

`lapiwe` implements the RaptorQ FEC scheme from RFC 6330. It does not implement any Wireless Wide Area Network (WWAN) standard.

Qualcomm's IETF IPR disclosures for RFC 6330 state that it will not assert its essential patent rights against a compliant implementation that does not implement WWAN; the commitment is royalty-free and subject to defensive termination. See [`NOTICE`](NOTICE) and the [IETF IPR search](https://datatracker.ietf.org/ipr/search/?document=rfc6330) for the authoritative record. This is a factual note, not legal advice.

## License

`lapiwe` is dual-licensed under either of:

- the [MIT License](LICENSE-MIT)
- the [Apache License, Version 2.0](LICENSE-APACHE)

You may choose either license. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project is dual-licensed under the same terms, without additional conditions.

Copyright (c) 2026 azote

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build instructions, formatting and lint requirements, the test workflow, and the pull-request process.
