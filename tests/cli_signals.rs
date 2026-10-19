//! Signal cleanup tests: SIGINT, SIGTERM, and SIGHUP must remove temporary
//! files and exit silently with status 128 plus the signal number.
//!
//! Covered scenarios:
//! - `encode -` blocked copying stdin: spool files are removed;
//! - file encode interrupted during pass 2: temporary files in the target
//!   directory are removed and the output is not published;
//! - `decode -` blocked reading stdin: silent exit.
//!
//! SIGKILL cannot be caught, so it is out of scope.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-signal-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create sandbox directory");
        Sandbox { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

fn det_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.push((state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
    }
    out
}

/// Poll until at least one entry appears in `dir`; panic on timeout.
fn wait_for_entry(dir: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let any = fs::read_dir(dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
        if any {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what} ({dir:?})"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read directory")
        .map(|e| {
            e.expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Send a signal to `child` (`kill -SIG <pid>`).
fn send_signal(child: &Child, sig: &str) {
    let status = Command::new("kill")
        .args([format!("-{sig}"), child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{sig} must succeed");
}

/// Wait for the child process to exit and collect its stderr.
fn wait_and_stderr(child: &mut Child) -> (std::process::ExitStatus, Vec<u8>) {
    use std::io::Read;
    let stdin = child.stdin.take();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                drop(stdin);
                panic!("timed out waiting for child process: signal did not cause exit");
            }
        }
    };
    drop(stdin);
    let mut buf = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_end(&mut buf).expect("read stderr");
    }
    (status, buf)
}

/// Signal matrix: `(kill argument, expected exit status 128 + signal number)`.
const SIGNALS: &[(&str, i32)] = &[("INT", 130), ("TERM", 143), ("HUP", 129)];

#[cfg(unix)]
#[test]
fn test_signal_cleanup_encode_spool() {
    for (sig, code) in SIGNALS {
        let sb = Sandbox::new(&format!("spool-{}", sig.to_lowercase()));
        fs::create_dir_all(sb.path("spool")).expect("spool directory");
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["encode", "-", "-o", "out.lpw", "--spool-dir", "spool"])
            .current_dir(&sb.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn encode -");
        // Keep stdin open without writing: the process blocks while copying
        // stdin, and the spool files have already been created.
        wait_for_entry(&sb.path("spool"), "spool staging");
        std::thread::sleep(Duration::from_millis(50));
        send_signal(&child, sig);
        let (status, stderr) = wait_and_stderr(&mut child);
        assert_eq!(
            status.code(),
            Some(*code),
            "SIG{sig}: expected exit code 128+{code}; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "SIG{sig}: must exit silently: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            entries(&sb.path("spool")).is_empty(),
            "SIG{sig}: spool staging must be cleaned up: {:?}",
            entries(&sb.path("spool"))
        );
        assert!(
            !sb.path("out.lpw").exists(),
            "SIG{sig}: output file must not be published"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_signal_cleanup_encode_output_temp() {
    for (sig, code) in SIGNALS {
        let sb = Sandbox::new(&format!("out-{}", sig.to_lowercase()));
        fs::write(sb.path("big.bin"), det_bytes(16 * 1024 * 1024, 0x31A0)).expect("write input");
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["encode", "--max-mem", "128KiB", "-o", "out.lpw", "big.bin"])
            .current_dir(&sb.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn encode");
        // Wait for the output temporary file
        // (`.out.lpw.lapiwe-tmp.<pid>.<seq>`) to appear in the sandbox.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let has_temp = entries(&sb.dir).iter().any(|n| n.contains(".lapiwe-tmp"));
            if has_temp {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for output temporary file"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        send_signal(&child, sig);
        let (status, stderr) = wait_and_stderr(&mut child);
        assert_eq!(
            status.code(),
            Some(*code),
            "SIG{sig}: expected 128+{code}; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        let leftovers: Vec<String> = entries(&sb.dir)
            .into_iter()
            .filter(|n| n.contains(".lapiwe-tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "SIG{sig}: output temporary files must be cleaned up: {leftovers:?}"
        );
        assert!(
            !sb.path("out.lpw").exists(),
            "SIG{sig}: target must not be published"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_signal_cleanup_decode_output_temp() {
    // Decoding to a file creates the publish temporary file before scanning.
    // A signal must remove it and leave the target unpublished.
    for (sig, code) in SIGNALS {
        let sb = Sandbox::new(&format!("dec-out-{}", sig.to_lowercase()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["decode", "-o", "out.bin", "-"])
            .current_dir(&sb.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn decode -");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let has_temp = entries(&sb.dir).iter().any(|n| n.contains(".lapiwe-tmp"));
            if has_temp {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for publish temporary file"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(50));
        send_signal(&child, sig);
        let (status, stderr) = wait_and_stderr(&mut child);
        assert_eq!(
            status.code(),
            Some(*code),
            "SIG{sig}: expected 128+{code}; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "SIG{sig}: must exit silently: {}",
            String::from_utf8_lossy(&stderr)
        );
        let leftovers: Vec<String> = entries(&sb.dir)
            .into_iter()
            .filter(|n| n.contains(".lapiwe-tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "SIG{sig}: publish temporary files must be cleaned up: {leftovers:?}"
        );
        assert!(
            !sb.path("out.bin").exists(),
            "SIG{sig}: target must not be published"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_signal_cleanup_decode_stdin() {
    for (sig, code) in SIGNALS {
        let sb = Sandbox::new(&format!("dec-{}", sig.to_lowercase()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args(["decode", "-o", "-", "-"])
            .current_dir(&sb.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn decode -");
        std::thread::sleep(Duration::from_millis(200));
        send_signal(&child, sig);
        let (status, stderr) = wait_and_stderr(&mut child);
        assert_eq!(
            status.code(),
            Some(*code),
            "SIG{sig}: decode must exit silently with 128+{code}; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "SIG{sig}: must be silent: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            entries(&sb.dir).is_empty(),
            "SIG{sig}: must not leave files behind"
        );
    }
}

/// In `--patch` mode, a signal received mid-scan exits silently, leaves no
/// temporary files, and does not touch the target.
#[cfg(unix)]
#[test]
fn test_signal_cleanup_patch_spool() {
    let data = det_bytes(80_000, 0xC46C);
    for (sig, code) in SIGNALS {
        let sb = Sandbox::new(&format!("patch-{}", sig.to_lowercase()));
        fs::write(sb.path("tgt.bin"), &data).expect("write target");
        fs::write(sb.path("m.txt"), b"0 4080\n").expect("write missing ranges");
        let mut child = Command::new(env!("CARGO_BIN_EXE_lapiwe"))
            .args([
                "decode",
                "--patch",
                "tgt.bin",
                "--missing-ranges",
                "m.txt",
                "--spool-dir",
                ".",
                "-",
            ])
            .current_dir(&sb.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn decode --patch -");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !entries(&sb.dir).iter().any(|n| n.contains("lapiwe-patch")) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for patch spool file"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(50));
        send_signal(&child, sig);
        let (status, stderr) = wait_and_stderr(&mut child);
        assert_eq!(
            status.code(),
            Some(*code),
            "SIG{sig}: expected 128+{code}; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "SIG{sig}: must exit silently: {}",
            String::from_utf8_lossy(&stderr)
        );
        let leftovers: Vec<String> = entries(&sb.dir)
            .into_iter()
            .filter(|n| n.contains("lapiwe-patch"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "SIG{sig}: overlay/spill staging must be cleaned up: {leftovers:?}"
        );
        assert_eq!(
            fs::read(sb.path("tgt.bin")).expect("read target"),
            data,
            "SIG{sig}: must not write TARGET before full decode"
        );
    }
}
