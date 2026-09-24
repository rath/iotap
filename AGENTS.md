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
  release it (`KERN_KDREMOVE`) on every exit path, including errors, signals and panics. The
  terminal UI must likewise leave raw mode and the alternate screen on every exit path.
- iotap records metadata only: syscall, fd, byte counts, latency, path, socket endpoint. It never
  reads or stores the data being transferred.
- Everything downstream of the kernel reader is deterministic and driven by trace timestamps, never
  by wall-clock time, so recordings replay to identical output. The one exception is presentation:
  the live terminal UI reads the host clock for its elapsed time and its current second, and its
  details panel reads a file's metadata (`lstat`) as it is now.
- Tests must not need root. Kernel-facing behaviour is covered by synthetic record streams built
  with `trace::synth`, the TUI by rendering into ratatui's `TestBackend`. After changing anything
  under `src/sys/`, `src/reader.rs`, the syscall table or `csrc/`, run the root-only checks in
  README.md ("Checking against a live kernel") and say which ones you ran.

## Module map

| Path | Role |
|---|---|
| `src/main.rs` | Entry point; prints errors as `iotap: …` and sets the exit status |
| `src/cli.rs` | Command line (clap derive) |
| `src/app.rs` | Wiring: root check, kdebug setup, reader thread, output modes, signals, replay |
| `src/reader.rs` | Reader thread: drains kdebug, watches processes for exit, exec and new names |
| `src/session.rs` | Deterministic core: records to I/O events, notices, statistics and the summary |
| `src/trace/codes.rs` | kdebug event IDs and the syscall table |
| `src/trace/decode.rs` | Raw `kd_buf` records to typed events |
| `src/trace/pairing.rs` | Pairs syscall entry and return per thread; reassembles lookup paths |
| `src/trace/fdtable.rs` | What each descriptor of each process refers to; checks libproc's answers against the trace |
| `src/trace/procs.rs` | `ProcSource`: libproc when live, fixed answers in tests |
| `src/trace/synth.rs` | Builds record streams exactly as XNU emits them, for tests |
| `src/stats.rs` | Per-target and per-second aggregation |
| `src/record.rs` | `--record` and `--replay` file format |
| `src/output/` | Text and JSON Lines output, shared formatting |
| `src/tui/` | Terminal UI: `state` (keys, selection, pause, event ring), `draw` (rendering), `details` (the details panel), `fit` (names fitted to columns), `clipboard` (copying), the frame loop |
| `src/sys/` | The only unsafe code: kdebug sysctls, libproc, mach time and user accounts behind safe functions |
| `csrc/iotap_shim.c` | Flattens the libproc descriptor structs the `libc` crate lacks |
| `tests/replay.rs` | Runs the built binary on recordings made the way a live trace makes them |

## Commits

Conventional Commits, English, no AI attribution trailers. Title, one blank line, then `- ` bullets
with no blank lines between them. Do not push.
