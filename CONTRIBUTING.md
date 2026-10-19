# Contributing to lapiwe

Thank you for your interest in improving `lapiwe`. Contributions of bug reports, documentation fixes, tests, and code are welcome.

## Code of conduct

Be respectful, constructive, and collaborative. Assume good faith, keep discussion focused on the technical work, and avoid personal attacks. Maintainers may moderate discussions that become hostile or off-topic.

## Before you start

- For a small fix, open a pull request directly.
- For a new feature, a protocol change, or a large refactor, open an issue first so the design can be discussed before significant work is done.
- Do not include real paths, credentials, proprietary data, or other sensitive material in issues, commits, tests, or documentation.

## Prerequisites

- Rust 1.85 or newer (Edition 2024).
- `cargo`, `rustfmt`, and `clippy`. Install the latter two with:

  ```sh
  rustup component add rustfmt clippy
  ```

- Linux or macOS for the full test suite. The CLI relies on UNIX signals and filesystem semantics; Windows is not a supported target.

## Build

Debug build:

```sh
cargo build --locked
```

Release build:

```sh
cargo build --release --locked
```

The release binary is written to `target/release/lapiwe`.

## Formatting and linting

All changes must pass formatting and lint checks without warnings:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Run `cargo fmt --all` before committing if the formatting check fails. Do not reformat unrelated files in the same pull request.

## Tests

Run the regular test suite:

```sh
cargo test --locked
```

Release-only calibration tests are marked `#[ignore]` and are not part of the default run. They exercise large objects and can take several minutes:

```sh
cargo test --release --locked -- --ignored
```

If you change the encoder, decoder, ledger, or scanner, add a focused regression test. Prefer deterministic test data and explicit assertions over broad end-to-end scenarios. If you change performance-sensitive code, include before and after measurements and describe the hardware and storage used.

## Code style

- Follow the existing module structure and naming conventions.
- Write Rustdoc for public items: explain what the item does, its important parameters, error conditions, and any memory or I/O behavior that callers need to know.
- Keep comments in English and focused on why something is done, not on restating the code.
- Prefer clear, simple code over clever abstractions.
- Avoid `unsafe` unless it is necessary. If it is, document the invariants that make it sound.
- Do not change binary-format constants, packet layouts, or protocol semantics without an explicit format-version discussion. Compatibility is part of the public interface.

## Pull-request process

1. Fork the repository and create a topic branch from `main`.
2. Make focused commits with clear messages. Explain the problem and the chosen fix, not just the files changed.
3. Ensure the formatting, lint, and test commands above pass.
4. Update documentation and tests in the same pull request when behavior changes.
5. Open a pull request against `main`. Describe the change, the motivation, and how it was tested. Link the relevant issue if one exists.
6. Address review comments with additional commits; avoid force-pushing over a review unless the maintainers ask for it.

Maintainers may ask for a change to be split into smaller pull requests if it mixes unrelated concerns.

## Reporting bugs

Include:

- the `lapiwe` version (the release tag or commit hash);
- the operating system and architecture;
- the exact command line, with any sensitive paths replaced;
- the exit code and the complete stderr output;
- a minimal reproduction if possible.

Do not attach proprietary data. A synthetic input that triggers the problem is usually enough.

## Licensing

`lapiwe` is dual-licensed under the [MIT License](LICENSE-MIT) and the [Apache License, Version 2.0](LICENSE-APACHE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `lapiwe` by you is dual-licensed under the same terms, without additional conditions. By submitting a pull request, you confirm that you have the right to contribute the code under those terms.
