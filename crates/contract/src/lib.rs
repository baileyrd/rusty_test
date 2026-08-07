//! Portable Process & Filesystem Contract (Phase 0).
//!
//! This crate is the trait boundary only — no OS-specific behavior, no
//! third-party OS adapters. Implementations live in the `compat` crate.
//! See `/CONTRACT.md` at the repo root for the guarantees each trait makes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Stable error surface. Adapters MUST map OS errno/HRESULT into one of
/// the specific variants below where possible. `Io` is the explicit
/// fallback category for OS errors with no better match — its `source`
/// is retained for diagnostics (logging, `Display`) only; callers MUST
/// match on the variant, never on message text, to stay portable.
/// Layer-1 responsibility: errors
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("path escapes scoped root: {0}")]
    PathEscape(String),
    /// The string is not a valid [`ScopedPath`]. Distinct from
    /// `PathEscape`, which means a well-formed path that leaves the root:
    /// this means the spelling itself has no portable meaning.
    #[error("not a portable scoped path: {0}")]
    InvalidPath(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("unsupported on this host: {0}")]
    Unsupported(String),
    #[error("io error: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

impl From<std::io::Error> for ContractError {
    /// Categorizes by `ErrorKind` into a stable variant; only errors with
    /// no better category fall through to `Io`.
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => ContractError::NotFound(err.to_string()),
            std::io::ErrorKind::PermissionDenied => {
                ContractError::PermissionDenied(err.to_string())
            }
            std::io::ErrorKind::Unsupported => ContractError::Unsupported(err.to_string()),
            _ => ContractError::Io { source: err },
        }
    }
}

pub type Result<T, E = ContractError> = std::result::Result<T, E>;

/// A portable, relative path: the *only* thing [`FsRoot`] accepts.
///
/// Always `/`-separated, always relative, and validated at construction so
/// that an unrepresentable path cannot reach an adapter. The rejections are
/// not stylistic — each one is a spelling that means different things on
/// different hosts, measured rather than assumed:
///
/// - **`:`** — a literal filename character on Linux, an alternate-data-stream
///   selector on Windows. This is the one that *must* be a type error:
///   writing `d.txt:s` returns `Ok` on both hosts and leaves `d.txt`
///   unchanged on both, so the divergence is **invisible to any runtime
///   check**. Nothing but rejecting the spelling can catch it.
/// - **`\`** — a legal filename character on Linux, the native separator on
///   Windows. Same shape of problem as `:`.
/// - **leading `/`, drive prefixes (`C:`), UNC/device prefixes (`\\`)** —
///   host roots. A scoped path names something *inside* a root; it cannot
///   carry a root of its own.
/// - **`.` / `..` components** — `..` yields `PathEscape`, preserving that
///   category while moving enforcement to construction, where an escaping
///   path becomes unrepresentable rather than merely rejected later.
///
/// Layer-1 responsibility: paths
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopedPath(String);

impl ScopedPath {
    /// Validates and builds a scoped path. See the type docs for why each
    /// rejection exists.
    pub fn new(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(ContractError::InvalidPath("empty path".into()));
        }
        if input.starts_with('/') {
            return Err(ContractError::PathEscape(format!(
                "{input}: absolute paths name a host root, not a scoped location"
            )));
        }
        if let Some(bad) = input.chars().find(|c| *c == ':' || *c == '\\') {
            return Err(ContractError::InvalidPath(format!(
                "{input}: {bad:?} has no portable meaning (ADS selector or separator on \
                 Windows, an ordinary filename character on Unix)"
            )));
        }

        let mut components = 0usize;
        for component in input.split('/') {
            match component {
                ".." => {
                    return Err(ContractError::PathEscape(format!(
                        "{input}: `..` cannot appear in a scoped path"
                    )))
                }
                "." => {
                    return Err(ContractError::InvalidPath(format!(
                        "{input}: `.` is not a portable component"
                    )))
                }
                "" => {
                    return Err(ContractError::InvalidPath(format!(
                        "{input}: empty component (leading, trailing, or doubled `/`)"
                    )))
                }
                _ => components += 1,
            }
        }
        debug_assert!(components > 0);
        Ok(ScopedPath(input.to_string()))
    }

    /// The `/`-separated spelling. Identical on every host, and safe both to
    /// show a human and to hand back to [`ScopedPath::new`].
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Components, in order. Never empty, never `.` or `..`.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl std::fmt::Display for ScopedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A host-native resolved path — **opaque on purpose**.
///
/// This is what the host says a path really is, and the contract makes no
/// promise about its spelling. On Windows it is typically the verbatim
/// `\\?\C:\...` form; on Unix a plain `/`-rooted path. Measured, on the same
/// file:
///
/// ```text
/// Windows -> \\?\C:\Users\...\real.txt
/// Linux   -> /tmp/.../real.txt
/// ```
///
/// That is why there is no `/`-normalized rendering here and why the type
/// hides its contents. The previous contract promised paths that were
/// canonical *and* `/`-normalized in one breath; on Windows those are
/// mutually exclusive, because verbatim paths do not accept `/` as a
/// separator. Splitting the two is the fix.
///
/// Layer-1 responsibility: paths
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePath(PathBuf);

impl NativePath {
    /// Wraps a host-resolved path. Adapters only.
    pub fn from_host(path: PathBuf) -> Self {
        NativePath(path)
    }

    /// The native path, for handing straight back to a host API.
    pub fn as_os_path(&self) -> &Path {
        &self.0
    }

    /// A **human-facing rendering only.**
    ///
    /// Never pass the result to a host API and never treat it as canonical:
    /// it is lossy for non-UTF-8 names, and on Windows it deliberately strips
    /// the verbatim `\\?\` prefix for readability, which produces a string
    /// the OS may resolve differently than the original. Use
    /// [`NativePath::as_os_path`] for anything the machine will act on.
    pub fn display_for_humans(&self) -> String {
        let raw = self.0.to_string_lossy();
        raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_string()
    }
}

/// Per-host capability flags. Tools MUST check the relevant flag before
/// depending on non-baseline behavior instead of branching on `cfg!(windows)`
/// themselves — that keeps the divergence list in one place (CONTRACT.md).
/// Layer-1 responsibility: capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Conservative baseline, not a hard platform fact: `true` on Unix,
    /// `false` on Windows. Windows *can* create symlinks under Developer
    /// Mode or elevated privilege, but this crate does not yet probe for
    /// that — treat `false` here as "not proven safe to assume," not as
    /// "impossible on this host."
    pub symlinks: bool,
    pub unix_permissions: bool,
    /// Tracks the known `portable-pty` gap: ConPTY's
    /// `PSEUDOCONSOLE_WIN32_INPUT_MODE` / `PASSTHROUGH_MODE` are not passed
    /// through on the stock crate as of this writing.
    pub pty_win32_input_mode: bool,
    pub advisory_locking: bool,
}

impl Capabilities {
    /// The conservative compile-time baseline: what is safe to assume on a
    /// host of this family *without asking it anything*.
    ///
    /// This is **not** detection, and is named so it cannot be mistaken for
    /// it. Deciding capabilities from `cfg!` alone produces answers a real
    /// host can contradict — conformance measured exactly that, creating and
    /// resolving a symlink on a `windows-latest` runner while this function
    /// reports `symlinks: false`. A capability model that CI cannot falsify
    /// will drift from reality silently.
    ///
    /// Real detection needs I/O, and this crate is deliberately I/O-free, so
    /// it lives in the adapter: use `compat::NativeCapabilities::detect()`
    /// whenever you can afford the probe. Reach for this only when you
    /// cannot, and treat a `false` as "not proven safe to assume," never as
    /// "impossible on this host."
    pub fn conservative_baseline() -> Self {
        Capabilities {
            symlinks: cfg!(unix),
            unix_permissions: cfg!(unix),
            pty_win32_input_mode: false,
            advisory_locking: true,
        }
    }
}

/// Metadata for a single filesystem entry, normalized across hosts.
/// Layer-1 responsibility: filesystem
#[derive(Debug, Clone)]
pub struct Metadata {
    pub len: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub readonly: bool,
    pub modified: Option<SystemTime>,
}

/// A directory entry returned by `FsRoot::read_dir`.
/// Layer-1 responsibility: filesystem
#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub name: String,
    pub metadata: Metadata,
}

/// Filesystem operations scoped to a single root directory.
///
/// Takes [`ScopedPath`] rather than `&Path` so that escaping and
/// non-portable spellings are rejected at construction — an unrepresentable
/// path never reaches an adapter. Adapters MUST still enforce scoping
/// themselves: a symlink inside the root pointing out of it is a valid
/// `ScopedPath` and can only be caught during resolution.
///
/// Layer-1 responsibility: filesystem
pub trait FsRoot {
    fn stat(&self, path: &ScopedPath) -> Result<Metadata>;
    fn read_dir(&self, path: &ScopedPath) -> Result<Vec<DirEntryInfo>>;
    fn read_to_string(&self, path: &ScopedPath) -> Result<String>;
    fn write(&self, path: &ScopedPath, contents: &[u8]) -> Result<()>;
    fn create_dir(&self, path: &ScopedPath) -> Result<()>;
    fn remove_file(&self, path: &ScopedPath) -> Result<()>;

    /// Lists the root directory itself.
    ///
    /// A separate operation because `ScopedPath` deliberately cannot spell
    /// "the root": every value has at least one real component, since `.` is
    /// not a portable component. Naming the root explicitly is clearer than
    /// a magic path value that every adapter would have to special-case.
    fn read_dir_root(&self) -> Result<Vec<DirEntryInfo>>;

    /// Resolves a scoped path to what the host says it actually is.
    ///
    /// Exists so [`NativePath`] has a real producer. A type with no way to
    /// obtain it would be another documented guarantee with nothing behind
    /// it, which is the failure this contract keeps having to correct.
    fn canonicalize(&self, path: &ScopedPath) -> Result<NativePath>;
}

/// A process to spawn. `inherit_env` selects between "start from the
/// current process environment" and "start from an empty environment plus
/// `env`" — the contract has no implicit environment merging behavior.
/// Layer-1 responsibility: process
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub inherit_env: bool,
}

impl ProcessSpec {
    pub fn new(program: impl Into<String>) -> Self {
        ProcessSpec {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            inherit_env: true,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }
}

/// Layer-1 responsibility: process
#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Non-interactive process execution: spawn, capture stdout/stderr, wait.
/// Layer-1 responsibility: process
pub trait ProcessRunner {
    fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput>;
}

/// A live interactive PTY session. `Read`/`Write` carry the terminal
/// byte stream; `resize` and `wait` are the only additional primitives the
/// contract promises. Reader and writer are independent streams (as real
/// PTY masters expose) so a caller can pump output on one thread while
/// writing input on another without sharing a lock across a blocking read.
/// Layer-1 responsibility: terminal
pub struct PtySpawn {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub control: Box<dyn PtyControl>,
}

/// Out-of-band control for a live PTY session: resize and wait-for-exit.
///
/// Lifecycle, since ownership is split across `PtySpawn`'s three fields:
/// `reader`, `writer`, and `control` are each independently droppable —
/// dropping one does not drop or close the others. Dropping `control`
/// alone drops only the `MasterPty` handle it holds; `reader` and
/// `writer` are independently-owned clones of the master's read/write
/// ends (`portable-pty`'s `try_clone_reader`/`take_writer`) and are
/// **not** closed by dropping `control` by itself. Whether dropping
/// `control` alone is sufficient to hang up the child is host- and
/// `portable-pty`-handle-ownership-dependent and is **not verified** by
/// this spike's tests — do not depend on it. The only guaranteed way to
/// end a session is to drop `reader`, `writer`, and `control` together,
/// or let the child exit on its own and call `wait` to reap it. `wait`
/// blocks and has a single owner — there is no way for more than one
/// caller to await it. There is no `kill`/`terminate` method in this
/// spike (see CONTRACT.md).
/// Layer-1 responsibility: terminal
pub trait PtyControl: Send {
    fn resize(&mut self, cols: u16, rows: u16) -> Result<()>;
    fn wait(&mut self) -> Result<i32>;
}

/// Opens interactive PTY sessions.
///
/// The primary operation is [`PtySession::spawn`], which runs an explicit
/// command. That is deliberate: when the only way to open a PTY was "run the
/// host's default shell," every observable property of a session — including
/// whether it ever exits — was a function of the user's rc files rather than
/// of this contract, and so could not be stated as a guarantee or tested as
/// one. Command selection is what makes PTY behavior a contract property.
///
/// Callers MUST check `pty_win32_input_mode` before relying on
/// Win32-input-mode escape sequences.
/// Layer-1 responsibility: terminal
pub trait PtySession {
    /// Runs `command` under a new PTY of the given size. `ProcessSpec` is
    /// reused verbatim so that argv/cwd/env semantics — including
    /// `inherit_env` — are identical to `ProcessRunner::run`; a PTY should
    /// not be a second, subtly different way to describe a process.
    fn spawn(&self, command: &ProcessSpec, cols: u16, rows: u16) -> Result<PtySpawn>;

    /// The host's default interactive shell, as a spawnable command.
    ///
    /// Adapters MUST document how they choose it. It is exposed separately
    /// so callers can inspect or override the choice rather than having it
    /// baked into the spawn path.
    fn host_default_shell(&self) -> Result<ProcessSpec>;

    /// Convenience wrapper over [`PtySession::spawn`].
    ///
    /// Behavior of the resulting session depends on the user's shell and
    /// their rc files, which this contract does not govern: a customized
    /// login chain can hand off to another shell that never exits on `exit`.
    /// Nothing about this method is a guarantee beyond "a PTY was opened."
    /// Use [`PtySession::spawn`] for anything that must be deterministic.
    fn spawn_shell(&self, cols: u16, rows: u16) -> Result<PtySpawn> {
        let command = self.host_default_shell()?;
        self.spawn(&command, cols, rows)
    }
}

/// A held advisory lock. Dropping without calling `unlock` MUST still
/// release the lock (adapters implement `Drop`), `unlock` exists only to
/// surface release errors explicitly.
/// Layer-1 responsibility: locking
pub trait LockGuard {
    fn unlock(self: Box<Self>) -> Result<()>;
}

/// Advisory, best-effort file locking. Never mandatory — two processes
/// that ignore the lock can still race. See CONTRACT.md.
/// Layer-1 responsibility: locking
pub trait FileLock {
    fn lock_exclusive(&self, path: &ScopedPath) -> Result<Box<dyn LockGuard>>;
    fn lock_shared(&self, path: &ScopedPath) -> Result<Box<dyn LockGuard>>;
}

/// Deterministic per-OS config/cache/data directories for a named app.
/// Layer-1 responsibility: standard-directories
pub trait StandardDirs {
    fn config_dir(&self, app: &str) -> Result<PathBuf>;
    fn cache_dir(&self, app: &str) -> Result<PathBuf>;
    fn data_dir(&self, app: &str) -> Result<PathBuf>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_internally_consistent() {
        let caps = Capabilities::conservative_baseline();
        // Win32 input mode is a Windows-only gap; it can never be true
        // while symlinks (a Unix-only baseline) is also true.
        assert!(!(caps.pty_win32_input_mode && caps.symlinks));
    }

    #[test]
    fn process_spec_builder_appends_args() {
        let spec = ProcessSpec::new("echo").arg("a").arg("b");
        assert_eq!(spec.args, vec!["a".to_string(), "b".to_string()]);
        assert!(spec.inherit_env);
    }

    #[test]
    fn scoped_path_accepts_portable_relative_spellings() {
        for good in ["a.txt", "a/b/c.txt", "dir/file", "weird name.txt", "dot."] {
            assert!(
                ScopedPath::new(good).is_ok(),
                "{good:?} should be a valid scoped path"
            );
        }
        let p = ScopedPath::new("a/b/c.txt").unwrap();
        assert_eq!(p.as_str(), "a/b/c.txt");
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c.txt"]);
        // The `/` spelling is identical on every host and round-trips.
        assert_eq!(ScopedPath::new(p.as_str()).unwrap(), p);
    }

    #[test]
    fn scoped_path_rejects_colon_because_the_divergence_is_invisible() {
        // Measured on both hosts: writing `d.txt:s` returns Ok and leaves
        // `d.txt` unchanged on Windows *and* Linux — but on Windows it is a
        // stream attached to `d.txt`, and on Linux a file literally named
        // `d.txt:s`. No runtime check can tell those apart, so rejecting the
        // spelling is the only place the difference can be caught.
        assert!(matches!(
            ScopedPath::new("d.txt:s"),
            Err(ContractError::InvalidPath(_))
        ));
        assert!(matches!(
            ScopedPath::new("C:foo"),
            Err(ContractError::InvalidPath(_))
        ));
    }

    #[test]
    fn scoped_path_rejects_backslash_for_the_same_reason_as_colon() {
        // A separator on Windows, an ordinary filename character on Linux.
        assert!(matches!(
            ScopedPath::new(r"a\b"),
            Err(ContractError::InvalidPath(_))
        ));
    }

    #[test]
    fn scoped_path_rejects_host_roots() {
        // Absolute spellings name a host root; a scoped path names something
        // inside one. UNC and drive spellings are caught by the backslash or
        // colon rule, a leading `/` by the root rule.
        assert!(matches!(
            ScopedPath::new("/etc/passwd"),
            Err(ContractError::PathEscape(_))
        ));
        assert!(ScopedPath::new(r"\\srv\share\f").is_err());
        assert!(ScopedPath::new(r"C:\x").is_err());
    }

    #[test]
    fn scoped_path_makes_escape_unrepresentable_and_keeps_the_category() {
        // `..` still yields `PathEscape` — the category survives, the
        // enforcement just moves to construction, where an escaping path
        // cannot be built rather than being rejected on use.
        for escaping in ["../outside", "a/../../outside", ".."] {
            assert!(
                matches!(ScopedPath::new(escaping), Err(ContractError::PathEscape(_))),
                "{escaping:?} should be PathEscape"
            );
        }
    }

    #[test]
    fn scoped_path_rejects_degenerate_shapes() {
        for bad in ["", "a//b", "a/", "/", "./a", "a/./b"] {
            assert!(
                ScopedPath::new(bad).is_err(),
                "{bad:?} should not be a valid scoped path"
            );
        }
    }

    #[test]
    fn native_path_hides_its_spelling_but_renders_for_humans() {
        // The contract promises nothing about the native spelling. It does
        // promise the human rendering is readable, and that the two are
        // allowed to differ — which is exactly what the old single promise
        // ("canonical AND /-normalized") got wrong.
        let verbatim = NativePath::from_host(PathBuf::from(r"\\?\C:\dir\f.txt"));
        assert_eq!(verbatim.display_for_humans(), r"C:\dir\f.txt");
        assert_eq!(
            verbatim.as_os_path(),
            Path::new(r"\\?\C:\dir\f.txt"),
            "as_os_path must hand back the untouched host spelling"
        );

        let plain = NativePath::from_host(PathBuf::from("/tmp/f.txt"));
        assert_eq!(plain.display_for_humans(), "/tmp/f.txt");
    }

    #[test]
    fn io_errors_categorize_into_stable_variants() {
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(matches!(
            ContractError::from(not_found),
            ContractError::NotFound(_)
        ));

        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(matches!(
            ContractError::from(denied),
            ContractError::PermissionDenied(_)
        ));

        let unsupported = std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(matches!(
            ContractError::from(unsupported),
            ContractError::Unsupported(_)
        ));

        // No specific category: falls through to `Io`, source retained.
        let other = std::io::Error::from(std::io::ErrorKind::Other);
        let mapped = ContractError::from(other);
        assert!(matches!(mapped, ContractError::Io { .. }));
        assert!(std::error::Error::source(&mapped).is_some());
    }
}
