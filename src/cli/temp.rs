//! Temporary-file and atomic-publish helpers shared by the encode and decode
//! paths.
//!
//! Temporary files are removed through one of two mechanisms:
//!
//! - **Normal or error exit**: RAII cleanup. Dropping a [`TempGuard`] removes
//!   its file unless the guard has been defused.
//! - **`SIGINT`, `SIGTERM`, or `SIGHUP`**: [`install_signal_watchdog`] installs
//!   signal-hook handlers and waits for them on a dedicated watchdog thread.
//!   When a signal arrives, the watchdog deletes every unpublished temporary
//!   file in the registry and exits silently with status `128 + signo`. Because
//!   it runs independently of the main thread, cleanup and exit still happen
//!   even if the main thread is blocked in `read`.
//!
//! `SIGKILL` cannot be caught and is therefore outside these guarantees (the
//! `--help` text says so).
//!
//! Temporary files exist only during publishing or while staging stdin. The
//! registry holds just a few paths (at most one input and one output staging
//! file per process), so a plain `Mutex<Vec<PathBuf>>` is sufficient.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Registry of unpublished temporary files used by the signal watchdog.
/// The number of paths is very small.
fn registry() -> &'static Mutex<Vec<PathBuf>> {
    static REGISTRY: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn register_temp(path: &Path) {
    if let Ok(mut paths) = registry().lock() {
        paths.push(path.to_path_buf());
    }
}

fn unregister_temp(path: &Path) {
    if let Ok(mut paths) = registry().lock() {
        paths.retain(|p| p != path);
    }
}

/// Delete every temporary file in the registry and empty it.
///
/// Return the number of entries that were considered for deletion.
///
/// This operation is idempotent: missing files are ignored, since normal
/// cleanup and signal-driven cleanup may race with each other.
pub fn cleanup_registered_temps() -> usize {
    let paths: Vec<PathBuf> = match registry().lock() {
        Ok(mut paths) => std::mem::take(&mut *paths),
        Err(_) => return 0,
    };
    let count = paths.len();
    for path in paths {
        let _ = fs::remove_file(path);
    }
    count
}

/// Install the signal watchdog for `SIGINT`, `SIGTERM`, and `SIGHUP`.
/// Repeated calls have no effect beyond the first.
///
/// On a signal, the watchdog removes the registered temporary files, keeps
/// `stderr` silent, and exits with status `128 + signo`. If handler
/// registration fails (very unlikely), it gives up quietly and the default
/// signal behavior applies.
#[cfg(unix)]
pub fn install_signal_watchdog() {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let Ok(mut signals) = Signals::new([SIGHUP, SIGINT, SIGTERM]) else {
            return;
        };
        let spawned = std::thread::Builder::new()
            .name("lapiwe-signal".to_owned())
            .spawn(move || {
                if let Some(signal) = signals.forever().next() {
                    cleanup_registered_temps();
                    std::process::exit(128 + signal);
                }
            });
        let _ = spawned;
    });
}

/// No-op signal-watchdog installation on platforms without POSIX signals.
///
/// Temporary files are still removed by [`TempGuard`] on normal exit and on
/// error paths. Windows has no `SIGHUP` and the signal-hook iterator API is
/// unavailable there, so no watchdog thread is started.
#[cfg(not(unix))]
pub fn install_signal_watchdog() {}

/// RAII cleanup for a temporary file.
///
/// The file is deleted when the guard is dropped unless it has been defused.
/// The guard also keeps the signal registry up to date.
pub struct TempGuard {
    path: PathBuf,
    keep: bool,
}

impl TempGuard {
    /// Take ownership of an existing temporary file path and register it.
    /// The caller is expected to have created the file with [`create_unique`].
    pub fn new(path: PathBuf) -> Self {
        register_temp(&path);
        TempGuard { path, keep: false }
    }

    /// Mark the file as published: keep it on drop and remove it from the
    /// signal registry.
    pub fn defuse(&mut self) {
        self.keep = true;
        unregister_temp(&self.path);
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        unregister_temp(&self.path);
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create a uniquely named temporary file inside `dir`, refusing to overwrite
/// an existing file (`create_new`).
///
/// The file is opened for both reading and writing: the decode ledger backend
/// ([`crate::container::ledger::FileStore`]) needs `pread`/`pwrite`, for example
/// to read back accounting data after source symbols are written through and to
/// verify a spool file before copying it out.
pub fn create_unique(dir: &Path, prefix: &str) -> io::Result<(PathBuf, File)> {
    let pid = std::process::id();
    for seq in 0..1000u32 {
        let path = dir.join(format!(".{prefix}.{pid}.{seq}"));
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary file sequence exhausted",
    ))
}

/// Create a temporary file in the directory of `target` for publishing.
///
/// Keeping the temporary file beside the destination lets the caller publish it
/// with an atomic rename. The returned [`TempGuard`] provides RAII cleanup and
/// signal registration.
pub fn create_temp_for(target: &Path) -> io::Result<(PathBuf, File, TempGuard)> {
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let prefix = match target.file_name() {
        Some(name) => format!("{}.lapiwe-tmp", name.to_string_lossy()),
        None => "lapiwe-out".to_owned(),
    };
    let (path, file) = create_unique(&dir, &prefix)?;
    let guard = TempGuard::new(path.clone());
    Ok((path, file, guard))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a sandbox directory in the process temporary directory (outside
    /// `CARGO_TARGET_TMPDIR`). The test removes it when finished.
    fn sandbox(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lapiwe-temp-unit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create sandbox");
        dir
    }

    #[test]
    fn registered_temps_are_removed_by_cleanup_and_defuse_exempts() {
        // Exercise the cleanup primitives (tests in this process run serially,
        // so they do not contend for the registry): register two files, remove
        // them all through `cleanup_registered_temps`, and confirm that a
        // defused guard no longer takes part in cleanup.
        let dir = sandbox("cleanup");
        let (a, _fa) = create_unique(&dir, "a").expect("a");
        let (b, _fb) = create_unique(&dir, "b").expect("b");
        let (kept, _fk) = create_unique(&dir, "kept").expect("kept");
        let guard_a = TempGuard::new(a.clone());
        let guard_b = TempGuard::new(b.clone());
        let mut guard_kept = TempGuard::new(kept.clone());
        guard_kept.defuse();
        assert!(a.exists() && b.exists() && kept.exists());

        assert_eq!(
            cleanup_registered_temps(),
            2,
            "two unpublished entries must take part in cleanup"
        );
        assert!(
            !a.exists() && !b.exists(),
            "registered files must be deleted"
        );
        assert!(
            kept.exists(),
            "a defused file must not be deleted by signal cleanup"
        );
        assert_eq!(
            cleanup_registered_temps(),
            0,
            "registry is empty; cleanup is idempotent"
        );
        drop((guard_a, guard_b, guard_kept)); // Must not panic (files are gone or kept).
        assert!(kept.exists(), "a defused file must survive being dropped");
        let _ = fs::remove_dir_all(&dir);
    }
}
