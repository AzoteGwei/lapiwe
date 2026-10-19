//! Smoke tests for the CLI: subcommand dispatch, `-h`/`--help` (exit 0), and
//! unknown arguments (exit 1).
//!
//! These tests also cover required-input notation, SIGPIPE handling, and
//! single-line error formatting.

use std::process::{Command, Output};

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lapiwe"))
        .args(args)
        .output()
        .expect("failed to start the lapiwe binary")
}

#[test]
fn test_subcommand_dispatch() {
    // `encode`, `decode`, and `inspect` all dispatch; an unknown subcommand
    // exits with 1.
    for cmd in ["encode", "decode", "inspect"] {
        let out = run(&[cmd, "-h"]);
        assert_eq!(out.status.code(), Some(0), "{cmd} -h");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("lapiwe {cmd}")),
            "{cmd} -h should print help for the subcommand"
        );
    }
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty());
    assert!(out.stdout.is_empty());
}

#[test]
fn test_subcommand_help_and_unknown_flags() {
    // Subcommand `-h` and `--help` exit 0; unknown flags exit 1 with a
    // single-line error.
    for cmd in ["encode", "decode", "inspect"] {
        for flag in ["-h", "--help"] {
            let out = run(&[cmd, flag]);
            assert_eq!(out.status.code(), Some(0), "{cmd} {flag} should exit 0");
            assert!(!out.stdout.is_empty(), "{cmd} {flag} should print help");
        }
    }
    for args in [
        vec!["encode", "--bogus"],
        vec!["decode", "--bogus"],
        vec!["inspect", "--bogus"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr).matches('\n').count(),
            1,
            "{args:?} error must be a single line"
        );
    }
}

#[test]
fn top_level_help_exits_zero_and_lists_subcommands() {
    for flag in ["-h", "--help"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag} should exit 0");
        let stdout = String::from_utf8(out.stdout).expect("help output should be UTF-8");
        for cmd in ["encode", "decode", "inspect"] {
            assert!(stdout.contains(cmd), "{flag} missing subcommand {cmd}");
        }
        assert!(out.stderr.is_empty(), "{flag} should not write to stderr");
    }
}

#[test]
fn subcommand_help_exits_zero() {
    for cmd in ["encode", "decode", "inspect"] {
        for flag in ["-h", "--help"] {
            let out = run(&[cmd, flag]);
            assert_eq!(out.status.code(), Some(0), "{cmd} {flag} should exit 0");
            assert!(!out.stdout.is_empty(), "{cmd} {flag} should print usage");
            assert!(out.stderr.is_empty(), "{cmd} {flag} stderr must be empty");
        }
    }
}

#[test]
fn unknown_flag_exits_one_with_stderr() {
    for args in [
        vec!["encode", "--bogus"],
        vec!["decode", "-x"],
        vec!["inspect", "--nope"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?} should exit 1");
        assert!(!out.stderr.is_empty(), "{args:?} should write to stderr");
        assert!(out.stdout.is_empty(), "{args:?} should not write to stdout");
    }
}

#[test]
fn unknown_subcommand_exits_one() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty());
    assert!(out.stdout.is_empty());
}

#[test]
fn missing_subcommand_exits_one() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty());
}

#[test]
fn help_uses_required_input_notation() {
    // The usage line is formatted as `lapiwe <subcommand> [OPTIONS] <IN>`.
    // `<IN>` is required, so the help text must not use the optional form
    // `[IN]`.
    let top = run(&["-h"]);
    let stdout = String::from_utf8(top.stdout).expect("help output should be UTF-8");
    assert!(
        stdout.contains("lapiwe <subcommand> [OPTIONS] <IN>"),
        "top-level usage line should be `lapiwe <subcommand> [OPTIONS] <IN>`: {stdout}"
    );
    assert!(
        !stdout.contains("<COMMAND>"),
        "top-level usage line must not use <COMMAND>: {stdout}"
    );

    for cmd in ["encode", "decode", "inspect"] {
        let out = run(&[cmd, "-h"]);
        let stdout = String::from_utf8(out.stdout).expect("help output should be UTF-8");
        assert!(stdout.contains("<IN>"), "help must contain <IN>: {stdout}");
        assert!(!stdout.contains("[IN]"), "no [IN] in help: {stdout}");
        assert!(
            stdout.contains(&format!("lapiwe {cmd} [OPTIONS] <IN>")),
            "{cmd} usage line should contain `lapiwe {cmd} [OPTIONS] <IN>`: {stdout}"
        );
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_argv_exits_one_without_panic() {
    let bad = || OsString::from_vec(vec![0xff, 0xfe]);
    let cases: Vec<Vec<OsString>> = vec![vec![bad()], vec![OsString::from("encode"), bad()]];
    for args in cases {
        let out = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(&args)
            .output()
            .expect("failed to start the lapiwe binary");
        assert_eq!(out.status.code(), Some(1), "{args:?} should exit 1");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("panicked"), "should not panic: {stderr}");
        assert!(!out.stderr.is_empty(), "{args:?} should write to stderr");
        assert!(out.stdout.is_empty(), "{args:?} should not write to stdout");
    }
}

#[test]
fn sigpipe_help_exits_silently_without_panic() {
    // If the stdout pipe closes early, writes fail with EPIPE; the process
    // should exit silently without panicking.
    let bin = env!("CARGO_BIN_EXE_lapiwe");
    let out = Command::new("bash")
        .args([
            "-c",
            r#"set -o pipefail; { sleep 0.2; exec "$1" -h; } | true"#,
            "bash",
            bin,
        ])
        .output()
        .expect("failed to start bash");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "should not panic: {stderr}");
    assert!(stderr.is_empty(), "expected a silent exit: {stderr}");
    assert_eq!(out.status.code(), Some(0), "EPIPE should exit 0 silently");
}

#[test]
fn test_single_line_errors_and_suggestions() {
    // All error messages are single-line and human-readable, with no panics or
    // backtraces.
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["encode", "--packet-size", "3000", "no-such.bin"],
            &["2048", "65536"],
        ),
        (&["encode", "--max-mem", "2031", "no-such.bin"], &["4080"]),
        (
            &["encode", "--block-symbols", "20000", "no-such.bin"],
            &["4112"],
        ),
        (
            &["decode", "--max-mem", "0", "no-such.lpw"],
            &["65536", "scan ring buffer"],
        ),
        (
            &["encode", "--size", "abc", "no-such.bin"],
            &["invalid size"],
        ),
        (&["inspect", "--nope", "no-such.lpw"], &["--nope"]),
    ];
    for (args, expect) in cases {
        let out = run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            stderr.matches('\n').count(),
            1,
            "{args:?} error must be a single line: {stderr:?}"
        );
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert!(!stderr.contains("backtrace"), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?} must not write to stdout");
        for needle in *expect {
            assert!(
                stderr.contains(needle),
                "{args:?} missing suggestion/valid range `{needle}`: {stderr}"
            );
        }
    }
}

#[test]
fn unimplemented_subcommand_exits_one_without_panic() {
    // Scaffolding placeholder behavior; this case still holds once the
    // subcommand is implemented, since a missing input file also exits with 1.
    let out = run(&["encode", "no-such-input.bin"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty());
    assert!(out.stdout.is_empty());
}
