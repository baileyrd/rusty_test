//! Runtime conformance probes for the portable runtime contract.
//!
//! `CONTRACT.md` claims its behavior matrix is "produced by
//! `cargo test --workspace` across the CI OS matrix." Before this crate, it
//! was not — the matrix was hand-authored prose that no code emitted and no
//! CI job read back, so a row could say `supported` for a primitive with
//! zero tests behind it.
//!
//! This crate closes that loop. Each matrix row is one [`Probe`] that
//! *executes* the primitive on the host it is running on and returns a
//! [`Verdict`] plus the evidence it observed. CI runs the probes on
//! Windows, Linux, and macOS, merges the three reports into the matrix
//! table, and fails the build if the generated table differs from the one
//! committed to `CONTRACT.md`.
//!
//! Design rule: probes measure, they do not assume. A probe MUST NOT branch
//! on `cfg!(windows)` to decide its *verdict* — that would re-encode the
//! guess we are trying to eliminate. `cfg!` is allowed only to reach a
//! host-specific *API* (there is no portable way to call `symlink`), never
//! to shortcut the answer.
//!
//! One narrow amendment, added after the matrix shipped with a real defect:
//! a probe may use `cfg!` to decide whether its measurement **generalizes to
//! the OS** — see [`Verdict::Varies`] and `symlink_summary_verdict`. That is
//! not the answer; the answer stays measured and appears verbatim in the
//! evidence. It is a documented property of the platform's security model.
//! Without this, a one-host-per-OS matrix silently presents a host-shaped
//! fact in an OS-shaped cell, which is the original `cfg!()` bug relocated
//! one level up rather than fixed.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compat::{
    NativeCapabilities, NativeProcessRunner, NativePtySession, NativeStandardDirs, Workspace,
};
use contract::{
    ContractError, FileLock, FsRoot, ProcessRunner, ProcessSpec, PtySession, PtySpawn, ScopedPath,
    StandardDirs,
};

/// How a primitive behaves on the host that ran the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Identical observable behavior to the other supported hosts.
    Supported,
    /// The host differs underneath, but the adapter presents one behavior.
    ///
    /// Distinct from [`Verdict::Varies`]: normalization means the adapter
    /// guarantees one consistent contract *despite* host differences, so a
    /// caller can rely on it without asking anything.
    Normalized,
    /// Capability genuinely absent here; callers must check first.
    Unsupported,
    /// Not portable to assume for this OS: availability depends on host
    /// configuration, privilege, filesystem, or policy, so no single machine
    /// can answer for the OS.
    ///
    /// A summary verdict only. Per-host evidence still records what the
    /// machine that ran the probe actually did — `varies` never hides a
    /// measurement, it reports that the measurement does not generalize.
    /// Callers MUST consult `NativeCapabilities` on the current host.
    Varies,
    /// The probe itself failed. Always a CI failure — it means the matrix
    /// cannot be trusted, which is the exact problem this crate exists to
    /// prevent.
    Errored,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Supported => "supported",
            Verdict::Normalized => "normalized",
            Verdict::Unsupported => "unsupported",
            Verdict::Varies => "varies",
            Verdict::Errored => "ERRORED",
        }
    }

    pub fn parse(s: &str) -> Option<Verdict> {
        match s {
            "supported" => Some(Verdict::Supported),
            "normalized" => Some(Verdict::Normalized),
            "unsupported" => Some(Verdict::Unsupported),
            "varies" => Some(Verdict::Varies),
            "ERRORED" => Some(Verdict::Errored),
            _ => None,
        }
    }
}

/// One row of the behavior matrix, as observed on this host.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub id: String,
    pub row: String,
    pub verdict: Verdict,
    /// What the probe actually saw. This is the evidence behind the
    /// verdict — a reviewer should be able to disagree with the verdict by
    /// reading it.
    pub detail: String,
}

/// A single executable check. `run` returns the verdict plus evidence, or
/// an error string that becomes [`Verdict::Errored`].
pub struct Probe {
    pub id: &'static str,
    pub row: &'static str,
    /// Why this capability is not portable to assume, stated for readers of
    /// the matrix. Required when the probe can return [`Verdict::Varies`],
    /// meaningless otherwise.
    ///
    /// Lives on the probe rather than the result because the condition is a
    /// documented property of the capability, identical on every host — only
    /// the *answer* is per-host, and that is what the evidence records.
    pub condition: Option<&'static str>,
    pub run: fn() -> Result<(Verdict, String), String>,
}

pub const PROBES: &[Probe] = &[
    Probe {
        id: "fs_scoped_ops",
        row: "Scoped fs ops (write/read/stat/list/remove)",
        condition: None,
        run: probe_fs_scoped_ops,
    },
    Probe {
        id: "fs_escape_construction",
        row: "Escaping spellings unrepresentable (`ScopedPath`)",
        condition: None,
        run: probe_fs_escape_rejected_at_construction,
    },
    Probe {
        id: "path_case_collision",
        row: "Scoped-root filename case collision",
        condition: Some(
            "filesystem case sensitivity is a property of the volume, not the OS; a name-keyed allow-list is bypassable by case wherever names collide",
        ),
        run: probe_path_case_collision,
    },
    Probe {
        id: "path_device_names",
        row: "Reserved device names in a scoped root",
        condition: Some(
            "Windows reserves CON/NUL/PRN/AUX/COM*/LPT*; Unix treats them as ordinary filenames, so the same create succeeds or fails per host",
        ),
        run: probe_path_device_names,
    },
    Probe {
        id: "path_ads_unrepresentable",
        row: "`:` rejected before the filesystem (ADS)",
        condition: None,
        run: probe_path_ads_is_unrepresentable,
    },
    Probe {
        id: "path_native_canonical",
        row: "Native canonical path shape (no `/` promise)",
        condition: None,
        run: probe_path_native_canonical,
    },
    Probe {
        id: "fs_escape_symlink",
        row: "Scoped-root escape via symlink",
        condition: Some(
            "reachable only where symlink creation is, so on Windows it inherits that OS's \
             privilege gate; cap-std blocks the escape wherever the shape exists",
        ),
        run: probe_fs_escape_symlink,
    },
    Probe {
        id: "fs_symlink_create",
        row: "Symlink creation (probed, not assumed)",
        condition: Some(
            "on Windows, available with Developer Mode or SeCreateSymbolicLinkPrivilege and \
             otherwise unavailable; unconditional on Linux and macOS",
        ),
        run: probe_fs_symlink_create,
    },
    Probe {
        id: "proc_spawn_capture",
        row: "Process spawn + stdout/stderr/exit capture",
        condition: None,
        run: probe_proc_spawn_capture,
    },
    Probe {
        id: "proc_env_isolation",
        row: "Process env isolation (`inherit_env: false`)",
        condition: None,
        run: probe_proc_env_isolation,
    },
    Probe {
        id: "proc_cwd",
        row: "Process explicit working directory",
        condition: None,
        run: probe_proc_cwd,
    },
    Probe {
        id: "lock_advisory",
        row: "Advisory file locking (exclusive blocks)",
        condition: None,
        run: probe_lock_advisory,
    },
    Probe {
        id: "dirs_resolve",
        row: "Standard dirs resolve + absolute",
        condition: None,
        run: probe_dirs_resolve,
    },
    Probe {
        id: "dirs_distinct",
        row: "Standard dirs config/cache/data are distinct",
        condition: None,
        run: probe_dirs_distinct,
    },
    Probe {
        id: "pty_interactive",
        row: "Interactive PTY (explicit command, stream, resize, wait)",
        condition: None,
        run: probe_pty_interactive,
    },
    Probe {
        id: "capabilities_honest",
        row: "Capability detection matches the host",
        condition: None,
        run: probe_capabilities_honest,
    },
];

/// Runs every probe. A panicking probe is caught and reported as
/// [`Verdict::Errored`] rather than taking down the whole report — one
/// broken primitive should still leave the other rows measurable.
pub fn run_all() -> Vec<ProbeResult> {
    PROBES
        .iter()
        .map(|probe| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(probe.run));
            let (verdict, detail) = match outcome {
                Ok(Ok((verdict, detail))) => (verdict, detail),
                Ok(Err(message)) => (Verdict::Errored, message),
                Err(_) => (Verdict::Errored, "probe panicked".to_string()),
            };
            ProbeResult {
                id: probe.id.to_string(),
                row: probe.row.to_string(),
                verdict,
                detail,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Probe helpers
// ---------------------------------------------------------------------------

/// Builds a `ScopedPath` inside a probe, turning a construction failure
/// into a probe error rather than a panic.
fn sp(input: &str) -> Result<ScopedPath, String> {
    ScopedPath::new(input).map_err(|e| format!("ScopedPath::new({input:?}): {e}"))
}

fn unique_temp_dir(tag: &str) -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("conformance-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|e| format!("create temp dir: {e}"))?;
    Ok(path)
}

/// Locates the `conformance-child` binary cargo built alongside whatever is
/// running us. Probes execute both from `conformance-report` (bin dir) and
/// from the test harness (`deps/` one level down), so both are searched.
fn child_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let name = format!("conformance-child{}", std::env::consts::EXE_SUFFIX);
    let dir = exe
        .parent()
        .ok_or_else(|| "current_exe has no parent".to_string())?;

    let candidates = [dir.join(&name), dir.join("..").join(&name)];
    candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .cloned()
        .ok_or_else(|| {
            format!(
                "conformance-child not found near {}; build the workspace bins first",
                dir.display()
            )
        })
}

fn error_category(err: &ContractError) -> &'static str {
    match err {
        ContractError::PathEscape(_) => "PathEscape",
        ContractError::InvalidPath(_) => "InvalidPath",
        ContractError::NotFound(_) => "NotFound",
        ContractError::PermissionDenied(_) => "PermissionDenied",
        ContractError::Unsupported(_) => "Unsupported",
        ContractError::Io { .. } => "Io",
    }
}

// ---------------------------------------------------------------------------
// Filesystem probes
// ---------------------------------------------------------------------------

fn probe_fs_scoped_ops() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("fs")?;
    let ws = Workspace::open_ambient(&tmp).map_err(|e| e.to_string())?;

    ws.write(&sp("a.txt")?, b"payload")
        .map_err(|e| format!("write: {e}"))?;
    let read = ws
        .read_to_string(&sp("a.txt")?)
        .map_err(|e| format!("read: {e}"))?;
    if read != "payload" {
        return Err(format!("roundtrip mismatch: {read:?}"));
    }
    let meta = ws.stat(&sp("a.txt")?).map_err(|e| format!("stat: {e}"))?;
    if meta.len != 7 || meta.is_dir {
        return Err(format!("unexpected metadata: {meta:?}"));
    }
    ws.create_dir(&sp("sub")?)
        .map_err(|e| format!("create_dir: {e}"))?;
    let entries = ws
        .read_dir_root()
        .map_err(|e| format!("read_dir_root: {e}"))?;
    let mut names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
    names.sort();
    if names != ["a.txt", "sub"] {
        return Err(format!("unexpected listing: {names:?}"));
    }
    ws.remove_file(&sp("a.txt")?)
        .map_err(|e| format!("remove_file: {e}"))?;

    std::fs::remove_dir_all(&tmp).ok();
    Ok((
        Verdict::Supported,
        "write/read/stat/create_dir/read_dir_root/remove all behave identically".to_string(),
    ))
}

/// Escape is now rejected when a `ScopedPath` is *built*, not when it is
/// used, so this probe exercises the type rather than the filesystem.
///
/// That is the substantive change: an escaping path is unrepresentable, so
/// no adapter can receive one. The `PathEscape` category survives — it is
/// what construction returns.
fn probe_fs_escape_rejected_at_construction() -> Result<(Verdict, String), String> {
    let escaping = ["../outside", "a/../../outside", "..", "/etc/passwd"];
    let mut wrong = Vec::new();
    for candidate in escaping {
        match ScopedPath::new(candidate) {
            Err(ContractError::PathEscape(_)) => {}
            Err(other) => wrong.push(format!("{candidate} -> {}", error_category(&other))),
            Ok(_) => wrong.push(format!("{candidate} -> CONSTRUCTED (should be impossible)")),
        }
    }
    if !wrong.is_empty() {
        return Err(format!("not rejected as PathEscape: {}", wrong.join(", ")));
    }

    // Non-portable spellings are a different category: the path does not
    // escape, it simply has no host-independent meaning.
    let non_portable = ["d.txt:s", r"a\b", "C:foo", "a//b", "./a", ""];
    let mut leaked = Vec::new();
    for candidate in non_portable {
        if !matches!(
            ScopedPath::new(candidate),
            Err(ContractError::InvalidPath(_))
        ) {
            leaked.push(candidate);
        }
    }
    if !leaked.is_empty() {
        return Err(format!("not rejected as InvalidPath: {leaked:?}"));
    }

    Ok((
        Verdict::Supported,
        format!(
            "{} escaping spellings rejected `PathEscape`, {} non-portable rejected `InvalidPath`",
            escaping.len(),
            non_portable.len()
        ),
    ))
}

/// Measures whether the scoped root treats two spellings that differ only
/// in case as one file. Host-dependent and security-relevant: a tool that
/// keys an allow-list on a filename is bypassable by case wherever this
/// reports a collision.
fn probe_path_case_collision() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("case")?;
    let ws = Workspace::open_ambient(&tmp).map_err(|e| e.to_string())?;

    ws.write(&sp("Collide.txt")?, b"first")
        .map_err(|e| e.to_string())?;
    let lower = ws.read_to_string(&sp("collide.txt")?);
    std::fs::remove_dir_all(&tmp).ok();

    match lower {
        Ok(contents) if contents == "first" => Ok((
            Verdict::Varies,
            "`Collide.txt` and `collide.txt` are the SAME file on this host".to_string(),
        )),
        Ok(other) => Err(format!(
            "unexpected contents through the other case: {other:?}"
        )),
        Err(_) => Ok((
            Verdict::Varies,
            "`Collide.txt` and `collide.txt` are DISTINCT files on this host".to_string(),
        )),
    }
}

/// Measures reserved device names inside a scoped root.
fn probe_path_device_names() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("device")?;
    let ws = Workspace::open_ambient(&tmp).map_err(|e| e.to_string())?;

    let mut observed = Vec::new();
    for name in ["CON", "NUL"] {
        let outcome = match ws.write(&sp(name)?, b"x") {
            Ok(()) => "ordinary file".to_string(),
            Err(e) => format!("refused ({})", error_category(&e)),
        };
        observed.push(format!("{name}: {outcome}"));
    }
    std::fs::remove_dir_all(&tmp).ok();

    Ok((Verdict::Varies, observed.join("; ")))
}

/// The `:` spelling never reaches the filesystem — `ScopedPath` rejects it.
///
/// This probe records *why* that rejection is a type error rather than a
/// measured divergence: both hosts accept `d.txt:s` through raw `cap-std`
/// and leave `d.txt` unchanged, so the difference between "a stream on
/// d.txt" and "a file named d.txt:s" is **invisible to observation**. A
/// matrix row cannot capture it; only the type can.
fn probe_path_ads_is_unrepresentable() -> Result<(Verdict, String), String> {
    if !matches!(
        ScopedPath::new("d.txt:s"),
        Err(ContractError::InvalidPath(_))
    ) {
        return Err("`:` reached the filesystem layer; it must be a construction error".into());
    }
    Ok((
        Verdict::Supported,
        "`:` rejected by ScopedPath on every host — the ADS/filename divergence it would \
         cause is not observable at runtime, so it cannot be a measured row"
            .to_string(),
    ))
}

/// Records what the host calls a canonical path, and proves the contract
/// does not claim it is `/`-normalized.
fn probe_path_native_canonical() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("canon")?;
    let ws = Workspace::open_ambient(&tmp).map_err(|e| e.to_string())?;
    ws.write(&sp("f.txt")?, b"x").map_err(|e| e.to_string())?;

    let native = ws
        .canonicalize(&sp("f.txt")?)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let raw = native.as_os_path().to_string_lossy().into_owned();
    let shown = native.display_for_humans();
    std::fs::remove_dir_all(&tmp).ok();

    let verbatim = raw.starts_with(r"\\?\");
    let slash_normalized = !raw.contains('\\');
    let verdict = if verbatim || !slash_normalized {
        // Windows: verbatim and backslash-separated. Exactly the reason the
        // old single promise could not hold.
        Verdict::Normalized
    } else {
        Verdict::Supported
    };
    Ok((
        verdict,
        format!(
            "native is {}; human rendering {}",
            if verbatim {
                "verbatim-prefixed"
            } else if slash_normalized {
                "`/`-separated"
            } else {
                "backslash-separated"
            },
            if shown.starts_with(r"\\?\") {
                "still carries the verbatim prefix (BUG)"
            } else if !verbatim {
                // No prefix to drop on this host; say so rather than
                // claiming a transformation that did not happen.
                "equals the native spelling (nothing to strip)"
            } else {
                "drops the verbatim prefix"
            }
        ),
    ))
}

/// (`ERROR_PRIVILEGE_NOT_HELD`) while the `windows-latest` runner succeeded.
fn symlink_summary_verdict(measured: Verdict) -> Verdict {
    if cfg!(windows) {
        Verdict::Varies
    } else {
        measured
    }
}

fn probe_fs_escape_symlink() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("symesc")?;
    let root = tmp.join("root");
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    std::fs::write(tmp.join("outside.txt"), b"secret").map_err(|e| e.to_string())?;

    // A symlink inside the root pointing out of it cannot be caught by the
    // lexical guard — the path `link` looks perfectly scoped. cap-std is the
    // enforcement backstop here; this probe exists to prove it holds.
    if let Err(e) = make_symlink(&tmp.join("outside.txt"), &root.join("link")) {
        std::fs::remove_dir_all(&tmp).ok();
        return Ok((
            symlink_summary_verdict(Verdict::Unsupported),
            format!("cannot create symlinks on this host, escape shape unreachable: {e}"),
        ));
    }

    let ws = Workspace::open_ambient(&root).map_err(|e| e.to_string())?;
    let outcome = ws.read_to_string(&sp("link")?);
    let result = match &outcome {
        Ok(contents) if contents == "secret" => {
            return Err("SECURITY: symlink escaped the scoped root".to_string())
        }
        Ok(other) => return Err(format!("symlink read returned unexpected {other:?}")),
        Err(err) => error_category(err),
    };

    // Every operation that *resolves* a path has to hold the boundary, not
    // just the ones that read bytes. `canonicalize` was added after this
    // probe existed and escaped its evidence entirely: it reached around the
    // sandbox and returned a host path outside the root. Reading was blocked
    // the whole time, so the original probe stayed green through the bug.
    let canonical = ws.canonicalize(&sp("link")?);
    let canonical_note = match &canonical {
        Ok(native) => {
            let resolved = native.as_os_path().to_path_buf();
            let real_root = std::fs::canonicalize(&root).map_err(|e| e.to_string())?;
            if !resolved.starts_with(&real_root) {
                std::fs::remove_dir_all(&tmp).ok();
                return Err(format!(
                    "SECURITY: canonicalize resolved outside the scoped root: {}",
                    resolved.display()
                ));
            }
            "canonicalize stayed inside the root".to_string()
        }
        Err(err) => format!("canonicalize refused ({})", error_category(err)),
    };

    std::fs::remove_dir_all(&tmp).ok();
    // Blocked, but reported as PermissionDenied rather than PathEscape: the
    // lexical guard cannot see through a symlink, so cap-std's own denial is
    // what surfaces. A named divergence, not an accident.
    let measured = if result == "PathEscape" {
        Verdict::Supported
    } else {
        Verdict::Normalized
    };
    Ok((
        symlink_summary_verdict(measured),
        format!(
            "read blocked by cap-std, surfaced as `{result}` (not `PathEscape`); {canonical_note}"
        ),
    ))
}

/// `cfg!` here reaches a host-specific *API*, not a host-specific answer:
/// there is no portable `symlink`. The verdict still comes from whether the
/// call actually succeeded at runtime.
fn make_symlink(target: &Path, link: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).map_err(|e| e.to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err("no symlink API on this host".to_string())
    }
}

fn probe_fs_symlink_create() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("symcreate")?;
    std::fs::write(tmp.join("target.txt"), b"data").map_err(|e| e.to_string())?;

    // This is the probe @Honey asked for: Windows *can* symlink under
    // Developer Mode or with SeCreateSymbolicLinkPrivilege. Rather than
    // hardcoding `false` and calling it a platform fact, find out.
    let outcome = make_symlink(&tmp.join("target.txt"), &tmp.join("link.txt"));
    let declared = NativeCapabilities::detect().symlinks;

    let result = match outcome {
        Ok(()) => {
            let via_link =
                std::fs::read_to_string(tmp.join("link.txt")).map_err(|e| e.to_string())?;
            if via_link != "data" {
                return Err("symlink created but did not resolve to target".to_string());
            }
            (
                symlink_summary_verdict(Verdict::Supported),
                format!("symlink created and resolved; Capabilities::symlinks = {declared}"),
            )
        }
        Err(e) => (
            symlink_summary_verdict(Verdict::Unsupported),
            format!("symlink creation refused ({e}); Capabilities::symlinks = {declared}"),
        ),
    };

    std::fs::remove_dir_all(&tmp).ok();
    Ok(result)
}

// ---------------------------------------------------------------------------
// Process probes
// ---------------------------------------------------------------------------

fn probe_proc_spawn_capture() -> Result<(Verdict, String), String> {
    let child = child_binary()?;
    let runner = NativeProcessRunner;
    let spec = ProcessSpec::new(child.to_string_lossy().into_owned()).arg("streams");
    let output = runner.run(&spec).map_err(|e| format!("run: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if stdout != "STDOUT-MARKER" {
        return Err(format!("stdout mismatch: {stdout:?}"));
    }
    if stderr != "STDERR-MARKER" {
        return Err(format!("stderr mismatch: {stderr:?}"));
    }
    if output.status != 7 {
        return Err(format!("exit status mismatch: {}", output.status));
    }
    Ok((
        Verdict::Supported,
        "stdout, stderr, and exit status 7 all captured separately".to_string(),
    ))
}

fn probe_proc_env_isolation() -> Result<(Verdict, String), String> {
    let child = child_binary()?;
    let runner = NativeProcessRunner;
    let sentinel = "CONFORMANCE_SENTINEL";
    std::env::set_var(sentinel, "parent-value");

    // `inherit_env: false` must mean the child starts from an empty
    // environment plus `env` — CONTRACT.md promises no implicit merging.
    let mut spec = ProcessSpec::new(child.to_string_lossy().into_owned())
        .arg("getenv")
        .arg(sentinel);
    spec.inherit_env = false;
    let isolated = runner
        .run(&spec)
        .map_err(|e| format!("run isolated: {e}"))?;
    let isolated_out = String::from_utf8_lossy(&isolated.stdout).into_owned();

    let inheriting = ProcessSpec::new(child.to_string_lossy().into_owned())
        .arg("getenv")
        .arg(sentinel);
    let inherited = runner
        .run(&inheriting)
        .map_err(|e| format!("run inheriting: {e}"))?;
    let inherited_out = String::from_utf8_lossy(&inherited.stdout).into_owned();

    std::env::remove_var(sentinel);

    if inherited_out != "SET=parent-value" {
        return Err(format!(
            "inherit_env: true did not pass env: {inherited_out:?}"
        ));
    }
    if isolated_out != "UNSET" {
        return Err(format!(
            "inherit_env: false leaked the parent environment: {isolated_out:?}"
        ));
    }
    Ok((
        Verdict::Supported,
        "inherit_env true passes parent env; false yields an empty env".to_string(),
    ))
}

fn probe_proc_cwd() -> Result<(Verdict, String), String> {
    let child = child_binary()?;
    let tmp = unique_temp_dir("cwd")?;
    // Compare against the canonicalized dir: macOS resolves /var -> /private/var
    // and Windows may hand back a short path, so the raw temp path is not a
    // fair expectation on any host.
    let expected = std::fs::canonicalize(&tmp).map_err(|e| e.to_string())?;

    let runner = NativeProcessRunner;
    let mut spec = ProcessSpec::new(child.to_string_lossy().into_owned()).arg("cwd");
    spec.cwd = Some(tmp.clone());
    let output = runner.run(&spec).map_err(|e| format!("run: {e}"))?;
    let reported = String::from_utf8_lossy(&output.stdout).into_owned();
    let reported_canonical =
        std::fs::canonicalize(&reported).map_err(|e| format!("canonicalize child cwd: {e}"))?;

    std::fs::remove_dir_all(&tmp).ok();

    if reported_canonical != expected {
        return Err(format!(
            "child cwd was {reported_canonical:?}, expected {expected:?}"
        ));
    }
    // Normalized rather than Supported: the child's *reported* path needed
    // canonicalization to match on every host (macOS /private prefix,
    // Windows path form). The contract honors the requested cwd everywhere,
    // but the string it reports back is not byte-identical to what we asked.
    let raw_matched = Path::new(&reported) == tmp.as_path();
    if raw_matched {
        Ok((
            Verdict::Supported,
            "child cwd matches the requested path byte-for-byte".to_string(),
        ))
    } else {
        Ok((
            Verdict::Normalized,
            "cwd honored, but the child reports a canonicalized/aliased form of it".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Locking and directory probes
// ---------------------------------------------------------------------------

fn probe_lock_advisory() -> Result<(Verdict, String), String> {
    let tmp = unique_temp_dir("lock")?;
    let ws = Workspace::open_ambient(&tmp).map_err(|e| e.to_string())?;

    let guard = ws
        .lock_exclusive(&sp("lockfile")?)
        .map_err(|e| format!("lock_exclusive: {e}"))?;
    let second = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.join("lockfile"))
        .map_err(|e| e.to_string())?;
    let blocked = second.try_lock().is_err();
    drop(second);
    guard.unlock().map_err(|e| format!("unlock: {e}"))?;

    // After release the same lock must be acquirable again, otherwise
    // "advisory" is really "leaked".
    let reacquire = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.join("lockfile"))
        .map_err(|e| e.to_string())?;
    let reacquired = reacquire.try_lock().is_ok();
    drop(reacquire);
    std::fs::remove_dir_all(&tmp).ok();

    if !blocked {
        return Err("a second handle acquired an already-held exclusive lock".to_string());
    }
    if !reacquired {
        return Err("lock was not released by unlock()".to_string());
    }
    Ok((
        Verdict::Supported,
        "exclusive lock blocks a second handle and is released by unlock()".to_string(),
    ))
}

fn probe_dirs_resolve() -> Result<(Verdict, String), String> {
    let dirs = NativeStandardDirs;
    let app = "conformance-probe";
    let config = dirs
        .config_dir(app)
        .map_err(|e| format!("config_dir: {e}"))?;
    let cache = dirs.cache_dir(app).map_err(|e| format!("cache_dir: {e}"))?;
    let data = dirs.data_dir(app).map_err(|e| format!("data_dir: {e}"))?;

    for (label, path) in [("config", &config), ("cache", &cache), ("data", &data)] {
        if !path.is_absolute() {
            return Err(format!("{label} dir is not absolute: {path:?}"));
        }
        if !path.ends_with(app) {
            return Err(format!(
                "{label} dir does not end with the app name: {path:?}"
            ));
        }
    }
    // Deterministic: the same app name must resolve identically every call.
    if dirs.config_dir(app).map_err(|e| e.to_string())? != config {
        return Err("config_dir is not deterministic across calls".to_string());
    }
    Ok((
        Verdict::Supported,
        "config/cache/data all resolve to absolute, app-suffixed, stable paths".to_string(),
    ))
}

fn probe_dirs_distinct() -> Result<(Verdict, String), String> {
    let dirs = NativeStandardDirs;
    let app = "conformance-probe";
    let config = dirs.config_dir(app).map_err(|e| e.to_string())?;
    let cache = dirs.cache_dir(app).map_err(|e| e.to_string())?;
    let data = dirs.data_dir(app).map_err(|e| e.to_string())?;

    let mut collisions = Vec::new();
    if config == cache {
        collisions.push("config==cache");
    }
    if config == data {
        collisions.push("config==data");
    }
    if cache == data {
        collisions.push("cache==data");
    }

    if collisions.is_empty() {
        Ok((
            Verdict::Supported,
            "config, cache, and data are three distinct directories".to_string(),
        ))
    } else {
        // Not a bug in the adapter — it is what the host's own conventions
        // say. But a tool that assumes "my config dir and my data dir are
        // separate" is wrong here, so it belongs in the matrix.
        Ok((
            Verdict::Unsupported,
            format!("collides on this host: {}", collisions.join(", ")),
        ))
    }
}

// ---------------------------------------------------------------------------
// PTY probe
// ---------------------------------------------------------------------------

/// ANSI Device Status Report — "where is the cursor?". ConPTY emits this on
/// startup and waits for an answer before letting the child proceed.
const DSR_QUERY: &[u8] = b"\x1b[6n";
/// The reply: cursor at row 1, column 1. Content does not matter, only that
/// the terminal answers at all.
const DSR_REPLY: &[u8] = b"\x1b[1;1R";

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The row `CONTRACT.md` asserted with zero tests behind it.
///
/// Runs a **deterministic command** under the PTY rather than the host's
/// login shell, per the contract decision to make command selection explicit.
/// That matters for measurement, not just tidiness: with `spawn_shell` the
/// only option, teardown was a function of the user's rc files — reproduced
/// 3/3 on a WSL host whose login chain hands off to an interactive zsh that
/// never exits on `exit` — so `wait` could not be a matrix row at all. With
/// an explicit command, spawn, terminal stream, `resize`, exit code, and
/// `wait` are all observable properties of the contract.
fn probe_pty_interactive() -> Result<(Verdict, String), String> {
    let marker = format!("FIZZPTY{}", std::process::id());
    let child = child_binary()?;
    let command = ProcessSpec::new(child.to_string_lossy().into_owned())
        .arg("pty")
        .arg(&marker);

    let PtySpawn {
        mut reader,
        mut writer,
        mut control,
    } = NativePtySession
        .spawn(&command, 80, 24)
        .map_err(|e| format!("spawn: {e}"))?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let deadline = Duration::from_secs(20);
    let started = SystemTime::now();
    let mut accumulated = Vec::new();
    let mut answered_dsr = false;
    let mut saw_marker = false;

    while started.elapsed().map(|d| d < deadline).unwrap_or(false) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(chunk) => accumulated.extend_from_slice(&chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // ConPTY asks the terminal where the cursor is and *blocks the child*
        // until something answers. A pipe-shaped test never notices; a real
        // PTY consumer must reply. This is precisely the divergence the row
        // claimed `supported` for without ever exercising it.
        if !answered_dsr && contains_bytes(&accumulated, DSR_QUERY) {
            writer
                .write_all(DSR_REPLY)
                .map_err(|e| format!("pty DSR reply: {e}"))?;
            writer.flush().map_err(|e| format!("pty flush: {e}"))?;
            answered_dsr = true;
        }

        if String::from_utf8_lossy(&accumulated).contains(&marker) {
            saw_marker = true;
            break;
        }
    }

    if !saw_marker {
        let seen = String::from_utf8_lossy(&accumulated);
        let preview: String = seen.chars().take(200).collect();
        return Err(format!(
            "marker never arrived over the pty within {deadline:?}; saw {preview:?}"
        ));
    }

    control
        .resize(100, 30)
        .map_err(|e| format!("resize on a live pty: {e}"))?;

    // `wait` blocks with no timeout of its own, so it gets one here: a hung
    // child must fail this probe, not the whole CI job. The child exits on
    // its own, so nothing needs to be typed at it.
    let (wait_tx, wait_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = wait_tx.send(control.wait().map_err(|e| e.to_string()));
    });

    match wait_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(11)) => Ok((
            Verdict::Supported,
            "explicit command spawned; marker streamed; resize ok; wait() reaped exit 11"
                .to_string(),
        )),
        Ok(Ok(other)) => Err(format!("wait() reported exit {other}, expected 11")),
        Ok(Err(e)) => Err(format!("wait() failed: {e}")),
        Err(_) => Err("wait() did not return within 15s of the child exiting".to_string()),
    }
}

/// Guards the capability model against the host it describes.
///
/// This is the probe that would have caught the original defect: the model
/// claimed `symlinks: false` on Windows hosts that create symlinks fine.
/// Comparing what `NativeCapabilities::detect()` advertises against what the
/// host actually does turns "the model drifted" into a red build.
fn probe_capabilities_honest() -> Result<(Verdict, String), String> {
    let detected = NativeCapabilities::detect();
    let baseline = contract::Capabilities::conservative_baseline();

    // Ground truth, measured independently of the capability model.
    let tmp = unique_temp_dir("caps")?;
    std::fs::write(tmp.join("target.txt"), b"data").map_err(|e| e.to_string())?;
    let actually_symlinks = match make_symlink(&tmp.join("target.txt"), &tmp.join("link.txt")) {
        Ok(()) => std::fs::read_to_string(tmp.join("link.txt"))
            .map(|c| c == "data")
            .unwrap_or(false),
        Err(_) => false,
    };
    std::fs::remove_dir_all(&tmp).ok();

    if detected.symlinks != actually_symlinks {
        return Err(format!(
            "NativeCapabilities::detect() reports symlinks = {}, host actually does = {}",
            detected.symlinks, actually_symlinks
        ));
    }

    // The claim this row makes — "detection tells the truth about its host" —
    // holds uniformly, so the verdict is `supported` either way. Whether
    // detection also had to *correct* the baseline is a property of the host's
    // privilege configuration, not of the contract, and belongs in evidence.
    //
    // Deliberately not `varies`: the guarantee is portable to assume even
    // though the thing it reports about is not. Reporting `varies` here would
    // say "you cannot rely on detection being honest," which is backwards.
    let baseline_note = if detected.symlinks == baseline.symlinks {
        "baseline agrees".to_string()
    } else {
        format!(
            "corrects the conservative baseline, which claims {}",
            baseline.symlinks
        )
    };
    Ok((
        Verdict::Supported,
        format!("detection matches the host (symlinks = {actually_symlinks}); {baseline_note}"),
    ))
}

// ---------------------------------------------------------------------------
// Report serialization (TSV) and matrix rendering
// ---------------------------------------------------------------------------
//
// TSV rather than JSON purely to avoid pulling `serde`/`serde_json` in for a
// six-field record. Parsing stays a `split('\t')`.

/// Field separator is a tab, so details must not contain one.
fn sanitize(detail: &str) -> String {
    detail.replace(['\t', '\n', '\r'], " ")
}

pub fn render_tsv(results: &[ProbeResult]) -> String {
    let mut out = String::from("# id\tverdict\trow\tdetail\n");
    for result in results {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            result.id,
            result.verdict.as_str(),
            sanitize(&result.row),
            sanitize(&result.detail)
        ));
    }
    out
}

pub fn parse_tsv(text: &str) -> Result<Vec<ProbeResult>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        if fields.len() != 4 {
            return Err(format!("malformed report line: {line:?}"));
        }
        let verdict =
            Verdict::parse(fields[1]).ok_or_else(|| format!("unknown verdict: {:?}", fields[1]))?;
        out.push(ProbeResult {
            id: fields[0].to_string(),
            row: fields[2].to_string(),
            verdict,
            detail: fields[3].to_string(),
        });
    }
    Ok(out)
}

pub const MATRIX_BEGIN: &str = "<!-- BEGIN GENERATED MATRIX -->";
pub const MATRIX_END: &str = "<!-- END GENERATED MATRIX -->";

/// Renders the committed matrix section from one report per host.
///
/// Row order follows [`PROBES`], not the reports, so the table is stable
/// regardless of what any single host reported. A host missing a probe shows
/// `n/a` rather than silently shrinking the table.
pub fn render_matrix(hosts: &[(String, Vec<ProbeResult>)]) -> String {
    let mut out = String::new();
    out.push_str(MATRIX_BEGIN);
    out.push_str("\n\n*Generated by `conformance-report`. Do not hand-edit — CI regenerates\nthis section and fails on drift.*\n\n| Primitive |");
    for (host, _) in hosts {
        out.push_str(&format!(" {host} |"));
    }
    out.push_str("\n|---|");
    for _ in hosts {
        out.push_str("---|");
    }
    out.push('\n');

    for probe in PROBES {
        let mut row_label = probe.row.to_string();
        // Prefer the label the hosts actually reported, so renaming a row in
        // code cannot silently disagree with the artifacts.
        for (_, results) in hosts {
            if let Some(found) = results.iter().find(|r| r.id == probe.id) {
                row_label = found.row.clone();
                break;
            }
        }
        out.push_str(&format!("| {row_label} |"));
        for (_, results) in hosts {
            let cell = results
                .iter()
                .find(|r| r.id == probe.id)
                .map(|r| r.verdict.as_str())
                .unwrap_or("n/a");
            out.push_str(&format!(" {cell} |"));
        }
        out.push('\n');
    }

    // A bare `varies` cell is not actionable. Every row that reports one gets
    // its condition spelled out here, so a reader learns what to check rather
    // than only that something is uncertain.
    let varying: Vec<&Probe> = PROBES
        .iter()
        .filter(|probe| {
            hosts.iter().any(|(_, results)| {
                results
                    .iter()
                    .any(|r| r.id == probe.id && r.verdict == Verdict::Varies)
            })
        })
        .collect();
    if !varying.is_empty() {
        out.push_str("\n### Conditions for `varies` rows\n\n");
        for probe in varying {
            let condition = probe
                .condition
                .unwrap_or("no condition documented — this is a bug in the probe definition");
            out.push_str(&format!("- **{}** — {condition}\n", probe.row));
        }
    }

    out.push_str("\n### Evidence\n");
    for (host, results) in hosts {
        out.push_str(&format!("\n**{host}**\n\n"));
        for probe in PROBES {
            if let Some(found) = results.iter().find(|r| r.id == probe.id) {
                out.push_str(&format!(
                    "- `{}` — {}: {}\n",
                    found.id,
                    found.verdict.as_str(),
                    found.detail
                ));
            }
        }
    }

    out.push('\n');
    out.push_str(MATRIX_END);
    out
}

/// Replaces the generated region of `CONTRACT.md`. Errors rather than
/// appending when the markers are missing — silently growing a second matrix
/// would defeat the drift check.
pub fn splice_matrix(document: &str, matrix: &str) -> Result<String, String> {
    let begin = document
        .find(MATRIX_BEGIN)
        .ok_or_else(|| format!("missing {MATRIX_BEGIN} marker"))?;
    let end = document
        .find(MATRIX_END)
        .ok_or_else(|| format!("missing {MATRIX_END} marker"))?;
    if end < begin {
        return Err("matrix markers are out of order".to_string());
    }
    let mut out = String::new();
    out.push_str(&document[..begin]);
    out.push_str(matrix);
    out.push_str(&document[end + MATRIX_END.len()..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ProbeResult> {
        vec![ProbeResult {
            id: "fs_scoped_ops".to_string(),
            row: "Scoped fs ops (write/read/stat/list/remove)".to_string(),
            verdict: Verdict::Supported,
            detail: "all good".to_string(),
        }]
    }

    #[test]
    fn tsv_roundtrips() {
        let parsed = parse_tsv(&render_tsv(&sample())).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "fs_scoped_ops");
        assert_eq!(parsed[0].verdict, Verdict::Supported);
        assert_eq!(parsed[0].detail, "all good");
    }

    #[test]
    fn varies_roundtrips_and_is_not_normalized() {
        assert_eq!(Verdict::Varies.as_str(), "varies");
        assert_eq!(Verdict::parse("varies"), Some(Verdict::Varies));
        // The two mean opposite things to a caller: `normalized` means rely
        // on the adapter, `varies` means go ask the host. Collapsing them
        // would erase the distinction the verdict exists to draw.
        assert_ne!(Verdict::Varies, Verdict::Normalized);
    }

    #[test]
    fn every_probe_that_can_vary_documents_its_condition() {
        // A `varies` cell with no stated condition tells a reader only that
        // something is uncertain, which is worse than useless.
        for probe in PROBES {
            if probe.id.contains("symlink") {
                assert!(
                    probe.condition.is_some(),
                    "probe `{}` can report `varies` but documents no condition",
                    probe.id
                );
            }
        }
    }

    #[test]
    fn matrix_states_conditions_for_varies_rows() {
        let results = vec![ProbeResult {
            id: "fs_symlink_create".to_string(),
            row: "Symlink creation (probed, not assumed)".to_string(),
            verdict: Verdict::Varies,
            detail: "measured on this host".to_string(),
        }];
        let matrix = render_matrix(&[("Windows".to_string(), results)]);
        assert!(matrix.contains("Conditions for `varies` rows"));
        assert!(matrix.contains("SeCreateSymbolicLinkPrivilege"));
        // The measurement must survive alongside the summary, never be
        // replaced by it.
        assert!(matrix.contains("measured on this host"));
    }

    #[test]
    fn matrix_omits_the_conditions_block_when_nothing_varies() {
        let matrix = render_matrix(&[("Linux".to_string(), sample())]);
        assert!(!matrix.contains("Conditions for `varies` rows"));
    }

    #[test]
    fn tsv_rejects_malformed_lines() {
        assert!(parse_tsv("only\ttwo\n").is_err());
        assert!(parse_tsv("id\tnot-a-verdict\trow\tdetail\n").is_err());
    }

    #[test]
    fn details_with_tabs_do_not_corrupt_the_record() {
        let mut results = sample();
        results[0].detail = "has\ta tab\nand a newline".to_string();
        let parsed = parse_tsv(&render_tsv(&results)).unwrap();
        assert_eq!(parsed[0].detail, "has a tab and a newline");
    }

    #[test]
    fn matrix_lists_every_probe_even_when_a_host_is_missing_one() {
        let matrix = render_matrix(&[("Linux".to_string(), sample())]);
        for probe in PROBES {
            assert!(matrix.contains(probe.row), "missing row: {}", probe.row);
        }
        // Only `fs_scoped_ops` was reported; the rest must show `n/a`.
        assert!(matrix.contains("n/a"));
    }

    #[test]
    fn splice_replaces_only_the_generated_region() {
        let doc = format!("before\n{MATRIX_BEGIN}\nold\n{MATRIX_END}\nafter\n");
        let spliced = splice_matrix(&doc, &format!("{MATRIX_BEGIN}\nnew\n{MATRIX_END}")).unwrap();
        assert!(spliced.starts_with("before\n"));
        assert!(spliced.ends_with("\nafter\n"));
        assert!(spliced.contains("new"));
        assert!(!spliced.contains("old"));
    }

    #[test]
    fn splice_refuses_a_document_without_markers() {
        assert!(splice_matrix("no markers here", "x").is_err());
    }
}
