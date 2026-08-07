# Portable Process & Filesystem Contract — Phase 0

One-page definition of what this runtime promises, and what it explicitly
does not, per host. Any adapter divergence not listed here is a bug, not a
design decision.

## Supported hosts

Windows (MSVC), Linux, macOS. x86_64 and aarch64.

## Baseline guarantees (v1)

| Primitive | Guarantee | Backing crate |
|---|---|---|
| Paths | Three separate concepts, never one value — `ScopedPath` (portable, relative, `/`-separated, the only thing `FsRoot` accepts), an opaque native canonical path with **no** `/` promise, and a human-only display rendering. See [Path semantics](#path-semantics). | `contract`, `cap-std` |
| Filesystem ops | Open/read/write/stat/list/create/remove within a scoped root | `cap-std` |
| File locking | Advisory exclusive/shared locks, best-effort on all hosts | `std::fs::File` (stable since 1.89) |
| Process spawn | Spawn with explicit argv/env/cwd, inherit or capture stdout/stderr, block until exit | `std::process` |
| Stdio / PTY | Byte-stream stdio always; interactive PTY running an explicit `ProcessSpec`, as an unconditional baseline on all three supported hosts | `portable-pty` |
| Environment variables | Read/write current-process env as UTF-8 `HashMap<String, String>` | `std::env` |
| Standard directories | Per-OS config/cache/data dirs for a named app, deterministic | `dirs` |
| Errors | Structured `ContractError` — `PathEscape`/`NotFound`/`PermissionDenied`/`Unsupported` are stable categories; `Io` is the explicit fallback with the OS error retained as `source` for diagnostics only, never for callers to match on | `thiserror` |

## Path semantics

The previous version of this row promised *"canonical, absolute,
`/`-normalized-for-display paths"* as one value. **That is not merely
unimplemented — it cannot be satisfied.** Measured on the same file:

```
Windows   canonicalize -> \\?\C:\Users\...\real.txt
Linux     canonicalize -> /tmp/.../real.txt
```

Windows canonical form is the verbatim `\\?\` prefix, and **verbatim paths do
not accept `/` as a separator.** "Canonical" and "`/`-normalized" are mutually
exclusive there. So the promise is split into three concepts that are never
the same value:

| Concept | What it is | Promise |
|---|---|---|
| **`ScopedPath`** | A portable, relative, `/`-separated path. The only thing `FsRoot` accepts. | Identical spelling on every host; round-trips through `ScopedPath::new` |
| **Native canonical** (`NativePath`) | What the host says a path really is. Opaque. | Resolves. **No** promise about its spelling — it may be verbatim |
| **Display** (`display_for_humans`) | Human-facing rendering only | Readable. Never pass it to a host API; never treat it as canonical |

### What `ScopedPath` rejects, and why

Each rejection is a spelling that means different things on different hosts.
These were measured, not assumed:

- **`:`** — an ADS selector on Windows, an ordinary filename character on
  Linux. **This one must be a type error.** Writing `d.txt:s` returns `Ok` on
  both hosts and leaves `d.txt` unchanged on both, so the difference between
  "a stream attached to `d.txt`" and "a file named `d.txt:s`" is **invisible
  to any runtime check**. It cannot be a measured matrix row; only rejecting
  the spelling catches it.
- **`\`** — a separator on Windows, an ordinary filename character on Linux.
  Same shape of problem.
- **leading `/`, drive prefixes, UNC/device prefixes** — host roots. A scoped
  path names something *inside* a root and cannot carry one.
- **`..`** — returns `PathEscape`, the same category as before. The
  enforcement simply moved to construction, so an escaping path is now
  **unrepresentable** rather than rejected on use.

### Deliberately not in this slice

No `/c/Users` ↔ `C:\Users` translation, and no API that accepts a user-typed
path. That work needs a **typed path intent** — relative, POSIX-absolute, or
Windows-drive-absolute — converted at an explicit resolver.

It must not be inferred from argv or arbitrary text. MSYS2's heuristic
string-rewrite is the documented, recurring source of its own bugs
(`MSYS_NO_PATHCONV` exists to switch it off when it guesses wrong), and the
measurement above shows why the guess is unavoidable: `/tmp/x` is absolute on
Linux and *relative* on Windows, `C:\foo` the reverse. **The same string
legitimately means different things**, so shape alone cannot recover intent.

### Known gap: case-insensitive name collision

Where `path_case_collision` reports a collision, two spellings differing only
in case are the same file. Any allow-list or deny-list a tool keys on a
filename is **bypassable by case on those hosts**. This is measured and
recorded rather than silently case-folded — the contract does not pretend the
hosts agree. Callers that need name-based authorization must fold case
themselves, on hosts where the matrix says it matters.

## Capability model

There are two sources of capability data, and the difference is load-bearing:

- **`compat::NativeCapabilities::detect()`** — asks the host. Performs
  filesystem I/O. **Use this** unless you cannot afford a probe.
- **`contract::Capabilities::conservative_baseline()`** — answers from
  `cfg!` alone, does no I/O, and is named so it cannot be mistaken for
  detection. Use only when a probe is impossible, and read a `false` as
  "not proven safe to assume," never as "impossible on this host."

The split exists because a compile-time table is not falsifiable by CI and
drifted from reality unnoticed: conformance observed a `windows-latest`
runner create and resolve a symlink while the baseline reported
`symlinks: false`. A tool trusting that would refuse a feature that works.
The `capabilities_honest` probe now fails the build whenever detection and
the host disagree.

Known v1 fields:

- `symlinks` — probed by `NativeCapabilities::detect()`. Windows can create
  symlinks under Developer Mode or with `SeCreateSymbolicLinkPrivilege`, and
  a plain Windows host often cannot; the answer is per-host, not per-OS,
  which is why the matrix summarizes it as `varies` on Windows. Of three
  real Windows hosts measured, two refused and one allowed it — so this is
  the common case, not a corner case.
- `unix_permissions` — false on Windows; POSIX mode bits are not emulated.
  Not probed: observing mode bits take effect also assumes a filesystem that
  honors them, so there is no clean thing to ask.
- `pty_win32_input_mode` — tracks the known `portable-pty` gap where
  `PSEUDOCONSOLE_WIN32_INPUT_MODE` / `PASSTHROUGH_MODE` are not passed
  through on the stock crate. Report `false` until we adopt or vendor the
  patched fork.
- `advisory_locking` — true everywhere `std::fs::File::lock`/`lock_shared`
  is available (stable since Rust 1.89); semantics are advisory only,
  never mandatory.

## Explicit non-goals (v1)

- `fork()` / `exec()` process-image replacement semantics.
- POSIX ownership (uid/gid) and permission-bit emulation on Windows.
- Transparent POSIX shell-script portability (`#!/bin/sh` scripts are out of
  scope; this is a Rust runtime contract, not a shell compatibility layer).
- Arbitrary Unix signal delivery. `ProcessRunner::run` is synchronous
  (spawn → capture → wait) and exposes no live handle to signal; `kill`/
  `terminate` for a running child or PTY session is deferred to a future
  live-child trait, not promised in this spike (see `PtyControl`'s
  lifecycle docs in `crates/contract`).
- Sandboxing/capability security in the WASI sense — this contract targets
  real dev-tool filesystem/process access, not a sandbox. (We deliberately
  did not build on WASI/wasmtime for this reason; see PR description.)

## Behavior matrix

Every row below is **measured, not asserted**. `crates/conformance` defines
one probe per row that executes the primitive on the host it runs on;
`.github/workflows/ci.yml` runs the probes on Windows, Linux, and macOS,
merges the three reports, and **fails the build if this section differs from
what the probes reported**. A row cannot claim a behavior that no code
exercised.

**Each column reports the CI reference host for that OS, not every host of
that OS.** One machine per OS runs the probes. Where a capability depends on
the *machine* rather than the OS, a single measurement cannot speak for the
platform, and the summary says so with `varies` instead of generalizing from
a sample of one.

Each primitive is one of:

- **supported** — identical observable behavior across all three hosts.
- **normalized** — the host differs underneath, but the adapter presents one
  behavior. Rely on the adapter; nothing to check.
- **unsupported** — capability genuinely absent here; callers must check
  `NativeCapabilities::detect()` first.
- **varies** — not portable to assume for this OS: availability depends on
  host configuration, privilege, filesystem, or policy. **Callers MUST
  consult `NativeCapabilities` on the current host.** Distinct from
  `normalized`, and not a softer form of it: `normalized` means the adapter
  guarantees one consistent contract despite host differences, while
  `varies` means there is no such guarantee to lean on. The per-host
  evidence below still records what each reference host actually did — a
  `varies` summary never hides a measurement, it reports that the
  measurement does not generalize.
- **ERRORED** — the probe could not run. Always a CI failure: it means the
  matrix cannot be trusted.

Why `varies` exists: the first generated matrix reported Windows symlink
creation as `supported` on the strength of the `windows-latest` runner, while
two other real Windows hosts refused it with `ERROR_PRIVILEGE_NOT_HELD`. That
is a host-shaped fact in an OS-shaped cell — the same defect as the original
compile-time `cfg!()` table, moved up one level rather than fixed.

Regenerate locally with:

```sh
cargo run --bin conformance-report -- probe > report-$(uname -s).tsv
cargo run --bin conformance-report -- write CONTRACT.md \
    Windows=report-windows.tsv Linux=report-linux.tsv macOS=report-macos.tsv
```

<!-- BEGIN GENERATED MATRIX -->

*Generated by `conformance-report`. Do not hand-edit — CI regenerates
this section and fails on drift.*

| Primitive | Windows | Linux | macOS |
|---|---|---|---|
| Scoped fs ops (write/read/stat/list/remove) | supported | supported | supported |
| Scoped-root escape -> `PathEscape` | supported | supported | supported |
| Scoped-root escape via symlink | varies | normalized | normalized |
| Symlink creation (probed, not assumed) | varies | supported | supported |
| Process spawn + stdout/stderr/exit capture | supported | supported | supported |
| Process env isolation (`inherit_env: false`) | supported | supported | supported |
| Process explicit working directory | supported | supported | normalized |
| Advisory file locking (exclusive blocks) | supported | supported | supported |
| Standard dirs resolve + absolute | supported | supported | supported |
| Standard dirs config/cache/data are distinct | unsupported | supported | unsupported |
| Interactive PTY (explicit command, stream, resize, wait) | supported | supported | supported |
| Capability detection matches the host | supported | supported | supported |

### Conditions for `varies` rows

- **Scoped-root escape via symlink** — reachable only where symlink creation is, so on Windows it inherits that OS's privilege gate; cap-std blocks the escape wherever the shape exists
- **Symlink creation (probed, not assumed)** — on Windows, available with Developer Mode or SeCreateSymbolicLinkPrivilege and otherwise unavailable; unconditional on Linux and macOS

### Evidence

**Windows**

- `fs_scoped_ops` — supported: write/read/stat/create_dir/read_dir/remove all behave identically
- `fs_escape_lexical` — supported: 5 escape shapes classified `PathEscape`; interior `a/../b` still resolves
- `fs_escape_symlink` — varies: blocked by cap-std, surfaced as `PermissionDenied` (not `PathEscape`)
- `fs_symlink_create` — varies: symlink created and resolved; Capabilities::symlinks = true
- `proc_spawn_capture` — supported: stdout, stderr, and exit status 7 all captured separately
- `proc_env_isolation` — supported: inherit_env true passes parent env; false yields an empty env
- `proc_cwd` — supported: child cwd matches the requested path byte-for-byte
- `lock_advisory` — supported: exclusive lock blocks a second handle and is released by unlock()
- `dirs_resolve` — supported: config/cache/data all resolve to absolute, app-suffixed, stable paths
- `dirs_distinct` — unsupported: collides on this host: config==data
- `pty_interactive` — supported: explicit command spawned; marker streamed; resize ok; wait() reaped exit 11
- `capabilities_honest` — supported: detection matches the host (symlinks = true); corrects the conservative baseline, which claims false

**Linux**

- `fs_scoped_ops` — supported: write/read/stat/create_dir/read_dir/remove all behave identically
- `fs_escape_lexical` — supported: 5 escape shapes classified `PathEscape`; interior `a/../b` still resolves
- `fs_escape_symlink` — normalized: blocked by cap-std, surfaced as `PermissionDenied` (not `PathEscape`)
- `fs_symlink_create` — supported: symlink created and resolved; Capabilities::symlinks = true
- `proc_spawn_capture` — supported: stdout, stderr, and exit status 7 all captured separately
- `proc_env_isolation` — supported: inherit_env true passes parent env; false yields an empty env
- `proc_cwd` — supported: child cwd matches the requested path byte-for-byte
- `lock_advisory` — supported: exclusive lock blocks a second handle and is released by unlock()
- `dirs_resolve` — supported: config/cache/data all resolve to absolute, app-suffixed, stable paths
- `dirs_distinct` — supported: config, cache, and data are three distinct directories
- `pty_interactive` — supported: explicit command spawned; marker streamed; resize ok; wait() reaped exit 11
- `capabilities_honest` — supported: detection matches the host (symlinks = true); baseline agrees

**macOS**

- `fs_scoped_ops` — supported: write/read/stat/create_dir/read_dir/remove all behave identically
- `fs_escape_lexical` — supported: 5 escape shapes classified `PathEscape`; interior `a/../b` still resolves
- `fs_escape_symlink` — normalized: blocked by cap-std, surfaced as `PermissionDenied` (not `PathEscape`)
- `fs_symlink_create` — supported: symlink created and resolved; Capabilities::symlinks = true
- `proc_spawn_capture` — supported: stdout, stderr, and exit status 7 all captured separately
- `proc_env_isolation` — supported: inherit_env true passes parent env; false yields an empty env
- `proc_cwd` — normalized: cwd honored, but the child reports a canonicalized/aliased form of it
- `lock_advisory` — supported: exclusive lock blocks a second handle and is released by unlock()
- `dirs_resolve` — supported: config/cache/data all resolve to absolute, app-suffixed, stable paths
- `dirs_distinct` — unsupported: collides on this host: config==data
- `pty_interactive` — supported: explicit command spawned; marker streamed; resize ok; wait() reaped exit 11
- `capabilities_honest` — supported: detection matches the host (symlinks = true); baseline agrees

<!-- END GENERATED MATRIX -->

## Reference tools

Three tools exercise the three hardest primitives with minimal surface
area, all built against `contract` only:

1. `tools/stat-tool` — lists a directory and stats each entry through a
   scoped `FsRoot`.
2. `tools/proc-runner` — spawns a child process, captures stdout/stderr,
   reports exit status.
3. `tools/pty-shell` — opens an interactive PTY and spawns the host's
   default shell in it.

`crates/conformance` is not a reference tool but the harness that keeps the
matrix above honest — see its module docs for the rule that probes measure
rather than assume.

### PTY sessions run an explicit command

`PtySession::spawn` takes a `ProcessSpec`, so argv/cwd/env — including
`inherit_env` — mean exactly what they mean for `ProcessRunner::run`. A PTY
is not a second, subtly different way to describe a process.

`spawn_shell` remains as a convenience wrapper over `host_default_shell()`,
but it is explicitly **not** a guarantee beyond "a PTY was opened": the
resulting session depends on the user's shell and rc files, which this
contract does not govern. That is not hypothetical — a WSL host whose login
chain hands off to an interactive zsh never exits on `exit`, reproduced 3/3,
which made `wait` untestable while `spawn_shell` was the only entry point.

Command selection is what promotes spawn, terminal stream, `resize`, exit
code, and `wait` from dotfile properties to contract properties. The
`pty_interactive` probe asserts all five against a fixed command.

## Explicitly deferred prior art decision

WASI/the WASM component model is the industry's existing answer to "one
execution contract, per-host adapters." We are **not** building on
wasmtime/WASI for v1: dev tools need real fs/process access outside a
capability directory, which WASI intentionally restricts. Revisit if a
future phase wants sandboxed plugin execution — don't silently re-derive
WASI's design by accident.
