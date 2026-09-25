# iotap

CLI for macOS and Linux that traces the file and network I/O of chosen processes. Given pids or
process names, it reads what the kernel records of their syscalls (on macOS the kernel trace
facility, kdebug, the source `fs_usage` uses; on Linux an eBPF program of its own) and reports
every read and write syscall with its size, latency and target (file path or socket endpoint).
Output is an event stream plus a summary, JSON Lines (`--json`), or a live terminal UI (`--tui`).

This file is the canonical instruction file for every coding agent. Do not create `CLAUDE.md` or a
`.claude/` directory; anything only one vendor's agent can read is a defect here.

## Build, test, lint

```
cargo build
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Zero warnings is the bar, on macOS and on Linux (aarch64 and x86-64) alike. `unsafe` is denied
crate-wide and allowed only under `src/sys/`, which wraps sysctl, libproc and the C shim on macOS,
and the eBPF program's ring buffer and `/proc` on Linux, behind safe functions. Pin dependencies
to stable releases.

On Linux the build compiles `bpf/iotap.bpf.c` with clang (`CLANG` names another compiler), and
libbpf-rs builds its bundled libbpf, which needs the libelf and zlib development files.

## Rules

- Tracing needs root (`sudo`). Only one process can own kdebug at a time; iotap must always
  release it (`KERN_KDREMOVE`) on every exit path, including errors, signals and panics. On Linux
  the eBPF program stays attached only while iotap holds its links, and the kernel detaches it
  when iotap exits, however it exits. The terminal UI must leave raw mode and the alternate
  screen on every exit path.
- iotap records metadata only: syscall, fd, byte counts, latency, path, socket endpoint. It never
  reads or stores the data being transferred.
- Everything downstream of the kernel reader is deterministic and driven by trace timestamps, never
  by wall-clock time, so recordings replay to identical output. The one exception is presentation:
  the live terminal UI reads the host clock for its elapsed time and its current second, its
  details panel reads a file's metadata (`lstat`) as it is now, and host names (`--resolve`, the
  UI's `n` key) are what the resolver answers now. A name lookup can block for half a minute, so
  only the threads of `hosts` make them, and only for addresses about to be shown.
- Tests must not need root. Kernel-facing behaviour is covered by synthetic record streams built
  with `trace::kdebug::synth` and `trace::linux::synth`, the TUI by rendering into ratatui's
  `TestBackend`. After changing anything under `src/sys/`, `src/reader.rs`, the syscall tables,
  `csrc/` or `bpf/`, run the root-only checks in README.md ("Checking against a live kernel") on
  each system the change affects, and say which ones you ran.

## Module map

| Path | Role |
|---|---|
| `src/main.rs` | Entry point; prints errors as `iotap: …` and sets the exit status |
| `src/cli.rs` | Command line (clap derive) |
| `src/app.rs` | Wiring: root check, trace facility setup, reader thread, output modes, signals, replay |
| `src/target.rs` | Targets to processes: pids, and names, each matched against a process's name and the file names of its executable and of its first argument (`argv[0]`) |
| `src/reader.rs` | Reader thread: drains the kernel through the `Tracer` trait (kdebug and the eBPF program implement it), watches processes for exit, exec and new names |
| `src/session.rs` | Deterministic core: decoded records to I/O events, notices, statistics and the summary |
| `src/trace/mod.rs` | Record batches of each format, what records tell once put together, and the `Decode` trait each format implements |
| `src/trace/call.rs` | A syscall that returned, whatever format its records came in: its role, arguments, result and looked-up path |
| `src/trace/kdebug/mod.rs` | The kdebug record format: the `kd_buf` record and its decoder |
| `src/trace/kdebug/codes.rs` | kdebug event IDs and the syscall table |
| `src/trace/kdebug/decode.rs` | Raw `kd_buf` records to typed events |
| `src/trace/kdebug/pairing.rs` | Pairs syscall entry and return per thread; reassembles lookup paths |
| `src/trace/kdebug/synth.rs` | Builds record streams exactly as XNU emits them, for tests |
| `src/trace/linux/mod.rs` | The record format of iotap's Linux eBPF program, one record per call that returned, and its decoder |
| `src/trace/linux/codes.rs` | The Linux syscall tables for aarch64 and x86-64, and what the eBPF program reads for each call |
| `src/trace/linux/order.rs` | Puts records from the ring buffer in time order and marks where the program dropped some |
| `src/trace/linux/synth.rs` | Builds records exactly as the eBPF program writes them, for tests |
| `src/trace/fdtable.rs` | What each descriptor of each process refers to; checks the answers of libproc or `/proc` against the trace |
| `src/trace/procs.rs` | `ProcSource`: libproc or `/proc` when live, fixed answers in tests |
| `src/stats.rs` | Per-target and per-second aggregation |
| `src/hosts.rs` | Host names of remote addresses for the terminal UI and the text summary: threads that ask the resolver, and the answers so far |
| `src/record.rs` | `--record` and `--replay` file format |
| `src/output/` | Text and JSON Lines output, shared formatting |
| `src/tui/` | Terminal UI: `state` (keys, selection, pause, event ring), `draw` (rendering), `details` (the details panel), `fit` (names fitted to columns), `clipboard` (copying), the frame loop |
| `src/sys/` | The only unsafe code, behind safe functions: `kdebug` sysctls, libproc and the `kern.procargs2` sysctl (`proc/macos`) and mach time on macOS; the eBPF loader and ring buffer (`ebpf`) and `/proc` (`proc/linux`) on Linux; the trace clock, user accounts and the resolver's host names (`dns`) on both |
| `csrc/iotap_shim.c` | Flattens the libproc descriptor structs the `libc` crate lacks |
| `bpf/iotap.bpf.c` | iotap's eBPF program: pairs each traced call's entry and return and writes one record per call, and one per process exit, in the layout `trace::linux::Record` reads |
| `tests/replay.rs` | Runs the built binary on recordings made the way a live trace makes them |

## Commits

Conventional Commits, English, no AI attribution trailers. Title, one blank line, then `- ` bullets
with no blank lines between them. Do not push.
