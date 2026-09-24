# iotap

macOS CLI that traces the file and network I/O of chosen processes. Given pids or process names,
it reads the kernel trace facility (kdebug, the source `fs_usage` uses) and reports every read and
write syscall with its size, latency and target (file path or socket endpoint). Output is an event
stream plus a summary, JSON Lines (`--json`), or a live terminal UI (`--tui`).

This file is the canonical instruction file for every coding agent. Do not create `CLAUDE.md` or a
`.claude/` directory; anything only one vendor's agent can read is a defect here.

## Build, test, lint

```
cargo build
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Zero warnings is the bar. `unsafe` is denied crate-wide and allowed only under `src/sys/`, which
wraps sysctl, libproc and the C shim behind safe functions. Pin dependencies to stable releases.

## Rules

- Tracing needs root (`sudo`). Only one process can own kdebug at a time; iotap must always
  release it (`KERN_KDREMOVE`) on every exit path, including errors, signals and panics.
- iotap records metadata only: syscall, fd, byte counts, latency, path, socket endpoint. It never
  reads or stores the data being transferred.
- Everything downstream of the kernel reader is deterministic and driven by trace timestamps, never
  by wall-clock time, so recordings replay to identical output.
- Tests must not need root. Kernel-facing behaviour is covered by synthetic record streams and
  recordings; live checks are listed in README.md.

## Commits

Conventional Commits, English, no AI attribution trailers. Title, one blank line, then `- ` bullets
with no blank lines between them. Do not push.
