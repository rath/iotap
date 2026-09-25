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

## Running the live checks

The checks in README.md need root, which only the user gives, once for each run. Never ask for
the password or use it if the user offers it, never add a `NOPASSWD` rule, and never get root
another way, such as through the docker group. sudo remembers an approval only for the terminal
it was given in, so a run is one script that runs in that terminal: every root step uses
`sudo -n`, which fails rather than asks, and the script ends with `sudo -k`. It prints a PASS or
FAIL line for each expectation it can test, and keeps every output in files to read afterwards.

- **macOS.** sudo cannot use Touch ID inside tmux, and an agent's shell cannot answer it at all,
  so the run opens a terminal of its own. Make the script an executable `.command` file that
  begins with `sudo -v` and creates a marker file as its last step, and start it with
  `open -a Terminal run.command`. In the new window the user answers the prompt, with Touch ID
  where `/etc/pam.d/sudo_local` enables `pam_tid.so`, or else with the password, which the agent
  never sees. Wait by testing for the marker in a loop, not by following the log with
  `tail -f | grep`, which can outlive the run. Before a run, make sure no `iotap`, `fs_usage` or
  `ktrace` is running, as kdebug has one owner at a time; if the user's own is, ask them to quit
  it.
- **Linux.** Before each run the user runs `sudo -v` in pane 0.0 of a tmux session named `iotap`
  (`tmux new -s iotap`, `sudo -v`, then detach). The script stops unless `sudo -n true`
  succeeds, and the agent types it into that pane and waits for it:

  ```
  tmux send-keys -t iotap:0.0 'bash ~/iotap-run/run.sh > ~/iotap-run/run.out 2>&1; tmux wait-for -S iotap-run' Enter
  timeout 1800 tmux wait-for iotap-run
  ```

  Look at the pane only with `tmux capture-pane -p -t iotap:0.0`, and send keys only when it
  shows an idle shell prompt: keys sent while sudo asks for the password go into its prompt.
  When the machine is another host, run these through ssh, and first copy the working tree with
  `rsync -az --delete --exclude target --exclude .git ./ <host>:work/iotap/`. A command run
  through ssh may lack cargo on its `PATH`; `source ~/.cargo/env` first.

When writing a run:

- Try it without root first, through `--replay` of a recording from an earlier run, so that a
  mistake in the script does not cost an approval.
- Keep the run directory's path short: a Unix-domain socket path must stay under 104 bytes on
  macOS and 108 on Linux, and agents' temporary directories come close.
- Kill only the processes the run started, by the pids it saved, never by name with `pkill` or
  `killall`: the user's own processes run on the same machine, their iotap among them. After
  `f &`, `$!` is the pid of the subshell that runs the shell function `f`, so `f` should `exec`
  a program whose pid matters.
- A step that hangs can outlast sudo's timeout (five minutes on macOS), after which every later
  `sudo -n` fails. Point `fs_usage` at one quiet process and stop it with INT, INT and TERM under
  a time limit: a system-wide `fs_usage -w` under a flood once took minutes to stop after the
  first INT.
- Drive the terminal UI from a script run with `sudo -n`, so that no sudo stands between it and
  iotap: it starts iotap in a pseudo-terminal, sends keys, and reads the screen through a
  terminal emulator such as Python's pyte. ratatui can overwrite the left half of a wide
  character, which a terminal clears whole but pyte's `Screen.display` fails on; render
  `screen.buffer` instead. sudo drops `PYTHONPATH`, so pass it as
  `sudo -n env PYTHONPATH=… python3 …`.
- `y` in the terminal UI replaces the clipboard. Save the clipboard before the run and restore it
  after, skip the copy check when it holds more than text, and ask the user not to copy anything
  while the run goes on.
- For a slow download from an address with a host name (checks 3 and 10), fetch
  `https://proof.ovh.net/files/100Mb.dat` with `curl -4 --limit-rate 150k -o /dev/null`; its IPv6
  address has no name. A UDP socket connected to any address and polled with `recv` and
  `MSG_DONTWAIT` makes a network row for that address without sending a packet.

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
