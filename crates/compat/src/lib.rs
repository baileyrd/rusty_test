//! Adapters wiring the `contract` trait boundary to existing, mature crates:
//! cap-std (fs), portable-pty (process/pty), dirs (standard dirs), and
//! std's own file-locking methods (stable since 1.89). This crate is
//! deliberately thin — the primitives it wraps are already cross-platform;
//! the genuinely OS-specific logic is `NativeCapabilities::detect()` and the
//! default-shell selection below.

use std::path::{Path, PathBuf};
use std::process::Command;

use contract::{
    Capabilities, ContractError, DirEntryInfo, FileLock, FsRoot, LockGuard, Metadata, NativePath,
    ProcessOutput, ProcessRunner, ProcessSpec, PtyControl, PtySession, PtySpawn, Result,
    ScopedPath, StandardDirs,
};

fn to_metadata(m: cap_std::fs::Metadata) -> Metadata {
    Metadata {
        len: m.len(),
        is_dir: m.is_dir(),
        is_symlink: m.is_symlink(),
        readonly: m.permissions().readonly(),
        modified: m.modified().ok().map(cap_std::time::SystemTime::into_std),
    }
}

/// A filesystem root scoped by `cap-std`. No path passed through its
/// methods can escape the directory it was opened on.
pub struct Workspace {
    dir: cap_std::fs::Dir,
    /// Kept so `canonicalize` can resolve against the real root. cap-std
    /// deliberately does not expose the directory's own path.
    root: PathBuf,
}

impl Workspace {
    pub fn open_ambient(root: &Path) -> Result<Self> {
        let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
        Ok(Workspace {
            dir,
            root: root.to_path_buf(),
        })
    }
}

impl FsRoot for Workspace {
    fn stat(&self, path: &ScopedPath) -> Result<Metadata> {
        Ok(to_metadata(self.dir.metadata(as_host(path))?))
    }

    fn read_dir(&self, path: &ScopedPath) -> Result<Vec<DirEntryInfo>> {
        collect_dir(self.dir.read_dir(as_host(path))?)
    }

    fn read_to_string(&self, path: &ScopedPath) -> Result<String> {
        Ok(self.dir.read_to_string(as_host(path))?)
    }

    fn write(&self, path: &ScopedPath, contents: &[u8]) -> Result<()> {
        Ok(self.dir.write(as_host(path), contents)?)
    }

    fn create_dir(&self, path: &ScopedPath) -> Result<()> {
        Ok(self.dir.create_dir(as_host(path))?)
    }

    fn remove_file(&self, path: &ScopedPath) -> Result<()> {
        Ok(self.dir.remove_file(as_host(path))?)
    }

    fn read_dir_root(&self) -> Result<Vec<DirEntryInfo>> {
        collect_dir(self.dir.read_dir(Path::new("."))?)
    }

    fn canonicalize(&self, path: &ScopedPath) -> Result<NativePath> {
        // MUST resolve through the capability-scoped `Dir`, never through
        // `std::fs::canonicalize(self.root.join(..))`. The latter reaches
        // around the sandbox: `link/outside.txt` is a perfectly valid
        // `ScopedPath` — the type cannot see through a symlink — so an
        // in-root symlink resolves to a host path outside the root and gets
        // handed back as a `NativePath`. Measured, not hypothetical: the
        // earlier version returned `/tmp/.../outside.txt` for a root of
        // `/tmp/.../root`.
        //
        // `Dir::canonicalize` resolves symlinks *inside* the sandbox and
        // returns a root-relative path, so joining it back onto the root is
        // safe by construction rather than by a prefix check afterwards.
        let inside = self.dir.canonicalize(as_host(path))?;
        let resolved = std::fs::canonicalize(&self.root)?.join(inside);
        Ok(NativePath::from_host(resolved))
    }
}

fn collect_dir(entries: cap_std::fs::ReadDir) -> Result<Vec<DirEntryInfo>> {
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        out.push(DirEntryInfo {
            name: entry.file_name().to_string_lossy().into_owned(),
            metadata: to_metadata(entry.metadata()?),
        });
    }
    Ok(out)
}

/// A `ScopedPath` is already validated: relative, `/`-separated, no `..`,
/// no drive or UNC prefix, no `:` or `\`. `Path::new` on that string is
/// correct on every host, because `/` is a separator everywhere and the
/// spellings that would differ were rejected at construction.
fn as_host(path: &ScopedPath) -> &Path {
    Path::new(path.as_str())
}

struct StdFileLockGuard(std::fs::File);

impl LockGuard for StdFileLockGuard {
    fn unlock(self: Box<Self>) -> Result<()> {
        self.0.unlock()?;
        Ok(())
    }
}

impl FileLock for Workspace {
    fn lock_exclusive(&self, path: &ScopedPath) -> Result<Box<dyn LockGuard>> {
        let file = self.dir.open_with(
            as_host(path),
            cap_std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true),
        )?;
        let file = file.into_std();
        file.lock()?;
        Ok(Box::new(StdFileLockGuard(file)))
    }

    fn lock_shared(&self, path: &ScopedPath) -> Result<Box<dyn LockGuard>> {
        let file = self.dir.open_with(
            as_host(path),
            cap_std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true),
        )?;
        let file = file.into_std();
        file.lock_shared()?;
        Ok(Box::new(StdFileLockGuard(file)))
    }
}

/// Non-interactive process execution via `std::process`, already portable.
pub struct NativeProcessRunner;

impl ProcessRunner for NativeProcessRunner {
    fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput> {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        if !spec.inherit_env {
            cmd.env_clear();
        }
        cmd.envs(&spec.env);
        let output = cmd.output()?;
        Ok(ProcessOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

/// Interactive PTY sessions via `portable-pty`. Known gap: `pixel_width`/
/// `pixel_height` are left at 0, and the stock crate does not pass through
/// ConPTY's `PSEUDOCONSOLE_WIN32_INPUT_MODE` — see
/// `Capabilities::pty_win32_input_mode` in the `contract` crate.
pub struct NativePtySession;

/// How this adapter picks the host's default shell, documented as
/// `PtySession::host_default_shell` requires: `%COMSPEC%` falling back to
/// `cmd.exe` on Windows, `$SHELL` falling back to `/bin/sh` elsewhere.
fn default_shell() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

struct NativePtyControl {
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl PtyControl for NativePtyControl {
    fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.master
            .resize(portable_pty::PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ContractError::Unsupported(e.to_string()))
    }

    fn wait(&mut self) -> Result<i32> {
        let status = self.child.wait()?;
        Ok(status.exit_code() as i32)
    }
}

impl PtySession for NativePtySession {
    /// `ProcessSpec` maps onto `CommandBuilder` field for field. Note that
    /// `CommandBuilder::new` starts from the inherited environment, so
    /// `inherit_env: false` must clear it explicitly — same semantics as
    /// `NativeProcessRunner`'s `env_clear`.
    fn spawn(&self, command: &ProcessSpec, cols: u16, rows: u16) -> Result<PtySpawn> {
        let pty_system = portable_pty::native_pty_system();
        let pair = pty_system
            .openpty(portable_pty::PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ContractError::Unsupported(e.to_string()))?;

        let mut cmd = portable_pty::CommandBuilder::new(&command.program);
        cmd.args(&command.args);
        if let Some(cwd) = &command.cwd {
            cmd.cwd(cwd);
        }
        if !command.inherit_env {
            cmd.env_clear();
        }
        for (key, value) in &command.env {
            cmd.env(key, value);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| ContractError::Unsupported(e.to_string()))?;
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| ContractError::Unsupported(e.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| ContractError::Unsupported(e.to_string()))?;
        Ok(PtySpawn {
            reader,
            writer,
            control: Box::new(NativePtyControl {
                master: pair.master,
                child,
            }),
        })
    }

    fn host_default_shell(&self) -> Result<ProcessSpec> {
        Ok(ProcessSpec::new(default_shell()))
    }
}

/// Capability detection that actually asks the host.
///
/// `contract::Capabilities::conservative_baseline()` answers from `cfg!`
/// alone, which a real host can contradict: conformance observed a
/// `windows-latest` runner create and resolve a symlink while the baseline
/// reported `symlinks: false`. Detection needs I/O, so it lives here rather
/// than in the I/O-free contract crate.
pub struct NativeCapabilities;

impl NativeCapabilities {
    /// Probes what can be probed and falls back to the conservative baseline
    /// for what cannot.
    ///
    /// Performs filesystem I/O in a temporary directory. Callers that cannot
    /// afford that should use the baseline and accept its false negatives.
    pub fn detect() -> Capabilities {
        let baseline = Capabilities::conservative_baseline();
        Capabilities {
            symlinks: probe_symlinks().unwrap_or(baseline.symlinks),
            // Not probed: no portable way to observe POSIX mode bits taking
            // effect without also assuming a filesystem that honors them.
            unix_permissions: baseline.unix_permissions,
            // Not probed: tracks an upstream `portable-pty` gap, not a host
            // property, so there is nothing on the host to ask.
            pty_win32_input_mode: baseline.pty_win32_input_mode,
            advisory_locking: probe_advisory_locking().unwrap_or(baseline.advisory_locking),
        }
    }
}

/// Returns `None` when the probe could not run at all (no temp dir, etc.),
/// which is different from "the host refused" — only the latter is evidence
/// that the capability is absent.
fn probe_symlinks() -> Option<bool> {
    let dir = scratch_dir("caps-symlink")?;
    let target = dir.join("target");
    std::fs::write(&target, b"probe").ok()?;
    let link = dir.join("link");

    #[cfg(unix)]
    let created = std::os::unix::fs::symlink(&target, &link).is_ok();
    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_file(&target, &link).is_ok();
    #[cfg(not(any(unix, windows)))]
    let created = false;

    // Creating the link is not enough — it must also resolve.
    let usable = created && std::fs::read(&link).map(|c| c == b"probe").unwrap_or(false);
    std::fs::remove_dir_all(&dir).ok();
    Some(usable)
}

fn probe_advisory_locking() -> Option<bool> {
    let dir = scratch_dir("caps-lock")?;
    let path = dir.join("lockfile");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .ok()?;
    let locked = file.lock().is_ok();
    if locked {
        file.unlock().ok();
    }
    drop(file);
    std::fs::remove_dir_all(&dir).ok();
    Some(locked)
}

fn scratch_dir(tag: &str) -> Option<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("compat-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Deterministic per-OS config/cache/data directories via the `dirs` crate.
pub struct NativeStandardDirs;

impl StandardDirs for NativeStandardDirs {
    fn config_dir(&self, app: &str) -> Result<PathBuf> {
        dirs::config_dir()
            .map(|p| p.join(app))
            .ok_or_else(|| ContractError::Unsupported("no config dir on this host".into()))
    }

    fn cache_dir(&self, app: &str) -> Result<PathBuf> {
        dirs::cache_dir()
            .map(|p| p.join(app))
            .ok_or_else(|| ContractError::Unsupported("no cache dir on this host".into()))
    }

    fn data_dir(&self, app: &str) -> Result<PathBuf> {
        dirs::data_dir()
            .map(|p| p.join(app))
            .ok_or_else(|| ContractError::Unsupported("no data dir on this host".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(s: &str) -> ScopedPath {
        ScopedPath::new(s).expect("valid scoped path")
    }

    #[test]
    fn workspace_scoped_fs_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("compat-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let ws = Workspace::open_ambient(&tmp).unwrap();

        ws.write(&sp("hello.txt"), b"hi").unwrap();
        assert_eq!(ws.read_to_string(&sp("hello.txt")).unwrap(), "hi");

        let meta = ws.stat(&sp("hello.txt")).unwrap();
        assert_eq!(meta.len, 2);
        assert!(!meta.is_dir);

        let entries = ws.read_dir_root().unwrap();
        assert!(entries.iter().any(|e| e.name == "hello.txt"));

        ws.remove_file(&sp("hello.txt")).unwrap();
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn canonicalize_produces_a_native_path_the_contract_does_not_shape() {
        // The point of `NativePath` is that its spelling is the host's
        // business. All the contract promises is that it resolves and that
        // the human rendering is readable — notably *not* that the two are
        // the same string, which is what the old promise implied.
        let tmp = std::env::temp_dir().join(format!("compat-canon-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let ws = Workspace::open_ambient(&tmp).unwrap();
        ws.write(&sp("f.txt"), b"x").unwrap();

        let native = ws.canonicalize(&sp("f.txt")).unwrap();
        assert!(native.as_os_path().is_absolute());
        let shown = native.display_for_humans();
        assert!(shown.ends_with("f.txt"), "unexpected rendering: {shown}");
        assert!(
            !shown.starts_with(r"\?\"),
            "the human rendering must drop the verbatim prefix: {shown}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Creates a symlink if the host allows it, reporting whether it could.
    fn try_symlink(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            false
        }
    }

    #[test]
    fn canonicalize_does_not_escape_through_an_in_root_symlink() {
        // The scoped root's whole purpose. `link` is a perfectly valid
        // `ScopedPath` — the type cannot see through a symlink — so this can
        // only be enforced during resolution, by the adapter.
        let tmp = std::env::temp_dir().join(format!("compat-canon-esc-{}", std::process::id()));
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(tmp.join("outside.txt"), b"secret").unwrap();

        if !try_symlink(&tmp.join("outside.txt"), &root.join("link")) {
            // No symlink privilege on this host; the escape shape is
            // unreachable here and CI's other hosts cover it.
            std::fs::remove_dir_all(&tmp).ok();
            return;
        }

        let ws = Workspace::open_ambient(&root).unwrap();
        let outcome = ws.canonicalize(&sp("link"));
        let escaped = match &outcome {
            Ok(native) => {
                let shown = native.as_os_path().to_path_buf();
                // Anything resolving outside the root is an escape, however
                // it is spelled.
                !shown.starts_with(std::fs::canonicalize(&root).unwrap())
            }
            Err(_) => false,
        };
        std::fs::remove_dir_all(&tmp).ok();

        assert!(
            !escaped,
            "canonicalize resolved an in-root symlink to a host path outside the \
             scoped root: {outcome:?}"
        );
    }

    #[test]
    fn nested_paths_resolve_through_the_scoped_root() {
        let tmp = std::env::temp_dir().join(format!("compat-nested-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let ws = Workspace::open_ambient(&tmp).unwrap();

        ws.create_dir(&sp("a")).unwrap();
        ws.write(&sp("a/b.txt"), b"nested").unwrap();
        assert_eq!(ws.read_to_string(&sp("a/b.txt")).unwrap(), "nested");

        let listed = ws.read_dir(&sp("a")).unwrap();
        assert!(listed.iter().any(|e| e.name == "b.txt"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn workspace_exclusive_lock_blocks_a_second_holder() {
        let tmp = std::env::temp_dir().join(format!("compat-lock-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let ws = Workspace::open_ambient(&tmp).unwrap();

        let guard = ws.lock_exclusive(&sp("lockfile")).unwrap();
        // A second, independently-opened handle must not acquire the same
        // exclusive lock while `guard` is held.
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.join("lockfile"))
            .unwrap();
        assert!(second.try_lock().is_err());

        guard.unlock().unwrap();
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn process_runner_captures_stdout() {
        let runner = NativeProcessRunner;
        let spec = if cfg!(windows) {
            ProcessSpec::new("cmd").arg("/C").arg("echo hello")
        } else {
            ProcessSpec::new("echo").arg("hello")
        };
        let output = runner.run(&spec).unwrap();
        assert_eq!(output.status, 0);
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    #[test]
    fn standard_dirs_are_non_empty() {
        let dirs = NativeStandardDirs;
        let cfg = dirs.config_dir("compat-test");
        // Every CI host (Windows/Linux/macOS) resolves a config dir; the
        // only intentionally-unsupported case is a minimal/headless host
        // with no home directory, which none of our CI runners are.
        assert!(cfg.is_ok(), "expected a config dir on this host: {cfg:?}");
    }
}
