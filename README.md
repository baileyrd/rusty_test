# portable-runtime-contract

> **Archived — merged into [Rusty Mill](https://github.com/Rusty-Mill/rusty_mill).** This crate now lives at [`crates/rusty_test`](https://github.com/Rusty-Mill/rusty_mill/tree/main/crates/rusty_test) in the Rusty Mill monorepo, which is where active development, issues, and pull requests happen now. This standalone repo is kept for historical reference only.

Phase 0 spike for a cross-platform tool runtime: one execution contract,
per-host adapters — write a tool once, run it the same way on Windows,
Linux, and macOS.

This is deliberately **not** a from-scratch POSIX compatibility layer
(msys2's niche) and **not** a package manager. It's the trait boundary a
future launcher/package manager/SDK could sit on top of, proven out with
three minimal reference tools.

See [`CONTRACT.md`](./CONTRACT.md) for the full guarantee list, capability
model, and explicit non-goals.

## Layout

```
crates/
  contract/   trait boundary only — no OS-specific code, no adapters
  compat/     implements the traits by wrapping cap-std, portable-pty,
              and dirs — mature crates that are already portable — plus
              std's own (stable since 1.89) file locking
tools/
  stat-tool/    scoped filesystem primitive
  proc-runner/  process spawn + stdio capture primitive
  pty-shell/    interactive PTY primitive (manual/interactive, not CI)
```

## Why wrap existing crates instead of writing adapters from scratch

- **cap-std** — capability-scoped filesystem, Windows/Linux/macOS/FreeBSD
  today; it's the foundation Wasmtime uses for WASI.
- **portable-pty** (wezterm) — unified trait over Unix pty + Windows
  ConPTY. Known gap tracked in `Capabilities::pty_win32_input_mode`:
  ConPTY's `PSEUDOCONSOLE_WIN32_INPUT_MODE` / `PASSTHROUGH_MODE` aren't
  passed through by the stock crate.
- **std::fs::File locking** — `lock`/`lock_shared`/`try_lock`/`unlock`,
  stable since Rust 1.89; `flock(2)` on Unix, `LockFileEx` on Windows.
- **dirs** — per-OS config/cache/data directory conventions.

We are explicitly **not** building on WASI/wasmtime for v1: dev tools need
real filesystem/process access outside a capability sandbox directory,
which WASI intentionally restricts. See CONTRACT.md for the full reasoning.

## Try it

```sh
cargo run -p stat-tool -- .
cargo run -p proc-runner -- echo hello
cargo run -p pty-shell         # interactive; exits when the shell exits
```

## Testing

`cargo test --workspace` runs the automated primitives (fs, locking,
process spawn) on every OS in the CI matrix
(`.github/workflows/ci.yml`). `pty-shell` is inherently interactive and is
exercised manually — see `CONTRACT.md`'s behavior matrix for its status
per host.
