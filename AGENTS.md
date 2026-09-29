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

The Python scripts under `scripts/` run on Python 3.9, which macOS ships, and later, and pass
`ruff check scripts && ruff format --check scripts` with the settings in `ruff.toml`. ruff holds
them to the syntax of 3.9 but not to its library; `uvx vermin --target=3.9- --violations scripts`
checks both.

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
  only the threads of `hosts` make them, and only for addresses about to be shown. Text and
  terminal output also write times of day in the local time zone of the machine that shows them,
  where JSON Lines give nanoseconds since the epoch.
- Tests must not need root. Kernel-facing behaviour is covered by synthetic record streams built
  with `trace::kdebug::synth` and `trace::linux::synth`, the TUI by rendering into ratatui's
  `TestBackend`. After changing anything under `src/sys/`, `src/reader.rs`, the syscall tables,
  `csrc/` or `bpf/`, run the root-only checks in README.md ("Checking against a live kernel") on
  each system the change affects, as "Running the live checks" says, and say which ones you ran.

## Running the live checks

`scripts/live/run.py` runs the checks in README.md for the system it runs on, prints PASS or FAIL
for each expectation and a tally at the end, and exits with 0 only when every expectation held.
`run.py 3 8` runs only those checks, and `--list` names them. It checks `target/release/iotap`,
so build that first, and writes every output to `target/live/`, the verdicts to
`target/live/run.log` as well.

The checks need root, which only the user gives, once for each run. Never ask for the password
or use it if the user offers it, never add a `NOPASSWD` rule, and never get root another way,
such as through the docker group. sudo remembers an approval only for the terminal it was given
in, so run.py runs in that terminal: every root step uses `sudo -n`, which fails rather than
asks, and the run ends with `sudo -k`.

- **macOS.** sudo cannot use Touch ID inside tmux, and an agent's shell cannot answer it at all,
  so the run opens a terminal of its own: `open -a Terminal scripts/live/macos.command`. In its
  window the user answers sudo, with Touch ID where `/etc/pam.d/sudo_local` enables `pam_tid.so`,
  or else with the password, which the agent never sees. `target/live/done` then holds the exit
  status; remove it before opening the terminal, since the script removes it only once its window
  has started, and wait for it by testing for the file in a loop, not by following the log with
  `tail -f | grep`, which can outlive the run. run.py will not start while an `iotap`,
  `fs_usage` or `ktrace` runs, as kdebug has one owner at a time: ask the user to quit theirs,
  and not to copy anything during the run, since the terminal UI check uses the pasteboard.
- **Linux.** Before each run the user runs `sudo -v` in pane 0.0 of a tmux session named `iotap`
  (`tmux new -s iotap`, `sudo -v`, then detach), and the agent types the run into that pane and
  waits for it:

  ```
  rm -f target/live/done
  tmux send-keys -t iotap:0.0 'cd ~/work/iotap && python3 scripts/live/run.py; echo $? > target/live/done; tmux wait-for -S iotap-run' Enter
  timeout 1800 tmux wait-for iotap-run
  cat target/live/done
  ```

  A channel keeps a signal that nobody waited for, so the wait can return at once for an earlier
  run: the run is over only when `target/live/done`, removed before it began, exists.

  Look at the pane only with `tmux capture-pane -p -t iotap:0.0`, and send keys only when it
  shows an idle shell prompt: keys sent while sudo asks for the password go into its prompt.
  When the machine is another host, run these through ssh, and first copy the working tree with
  `rsync -az --delete --exclude target --exclude .git ./ <host>:work/iotap/`. A command run
  through ssh may lack cargo on its `PATH`; `source ~/.cargo/env` first.

The terminal UI checks need pyte for the Python that runs run.py, installed or on `PYTHONPATH`;
without it they are skipped. When changing the scripts:

- Try them without root first, so that a mistake costs no approval. A stand-in `sudo` early on
  `PATH`, which runs its command as the caller and ignores `-n`, `-v` and `-k`, takes run.py
  through every step with iotap failing, and tui.py runs as the user against a stand-in iotap
  that replays a recording.
- An expectation that something is absent must also require what shows that iotap ran, or a run
  without root passes it.
- Kill only processes the run started, by their pids, never by name with `pkill` or `killall`:
  the user's own processes run on the same machine, their iotap among them.
- Give every root step a time limit. A step that hangs can outlast sudo's timeout (five minutes
  on macOS), after which every later `sudo -n` fails; a system-wide `fs_usage -w` under a flood
  once took minutes to stop after its first SIGINT.
- sudo passes a signal on only when it comes from outside its own process group, which is the
  run's: send it from another group, or signal iotap from the root shell that started it.
- Keep Unix-domain socket paths under 104 bytes on macOS and 108 on Linux; the traced programs'
  files go to a short directory under `/tmp` for that.

## Module map

| Path | Role |
|---|---|
| `src/main.rs` | Entry point; prints errors as `iotap: …` and sets the exit status |
| `src/cli.rs` | Command line (clap derive) |
| `src/app.rs` | Wiring: root check, trace facility setup, reader thread, output modes, signals, replay |
| `src/target.rs` | Targets to processes: pids, and names, each matched against a process's name and the file names of its executable and of its first argument (`argv[0]`); the running descendants of processes, for `--children` |
| `src/reader.rs` | Reader thread: drains the kernel through the `Tracer` trait (kdebug and the eBPF program implement it), watches processes for exit, exec and new names, and takes up the processes traced ones start |
| `src/session.rs` | Deterministic core: decoded records to I/O events, the interface each went over, notices, statistics and the summary |
| `src/trace/mod.rs` | Record batches of each format, what records tell once put together, and the `Decode` trait each format implements |
| `src/trace/call.rs` | A syscall that returned, whatever format its records came in: its role, arguments, result and looked-up path |
| `src/trace/kdebug/mod.rs` | The kdebug record format: the `kd_buf` record and its decoder |
| `src/trace/kdebug/codes.rs` | kdebug event IDs and the syscall table |
| `src/trace/kdebug/decode.rs` | Raw `kd_buf` records to typed events |
| `src/trace/kdebug/pairing.rs` | Pairs syscall entry and return per thread; reassembles lookup paths |
| `src/trace/kdebug/spawns.rs` | Finds in the records of thread creation and exec, which kdebug makes for every process, the processes that traced ones start and those that run exec |
| `src/trace/kdebug/synth.rs` | Builds record streams exactly as XNU emits them, for tests |
| `src/trace/linux/mod.rs` | The record format of iotap's Linux eBPF program, one record per call that returned and per process that exited or was started, and its decoder |
| `src/trace/linux/codes.rs` | The Linux syscall tables for aarch64 and x86-64, and what the eBPF program reads for each call |
| `src/trace/linux/order.rs` | Puts records from the ring buffer in time order and marks where the program dropped some |
| `src/trace/linux/synth.rs` | Builds records exactly as the eBPF program writes them, for tests |
| `src/trace/fdtable.rs` | What each descriptor of each process refers to; checks the answers of libproc or `/proc` against the trace |
| `src/trace/procs.rs` | `ProcSource`: libproc or `/proc`, and the host's network interfaces, when live; fixed answers in tests |
| `src/stats.rs` | Per-target, per-interface and per-second aggregation |
| `src/interfaces.rs` | Which network interface a socket's traffic goes over: the host's interfaces as last listed, and the rules that name one from a socket's addresses |
| `src/hosts.rs` | Host names of remote addresses for the terminal UI and the text summary: threads that ask the resolver, and the answers so far |
| `src/record.rs` | `--record` and `--replay` file format |
| `src/output/` | Text and JSON Lines output, shared formatting |
| `src/tui/` | Terminal UI: `state` (keys, selection, pause, event ring), `draw` (rendering), `details` (the details panel), `fit` (names fitted to columns), `clipboard` (copying), the frame loop |
| `src/sys/` | The only unsafe code, behind safe functions: `kdebug` sysctls, libproc and the `kern.procargs2` sysctl (`proc/macos`) and mach time on macOS; the eBPF loader and ring buffer (`ebpf`) and `/proc` (`proc/linux`), network namespaces included, on Linux; the trace clock, user accounts, the resolver's host names (`dns`) and the network interfaces (`net`) on both |
| `csrc/iotap_shim.c` | Flattens the libproc descriptor structs the `libc` crate lacks |
| `bpf/iotap.bpf.c` | iotap's eBPF program: pairs each traced call's entry and return and writes one record per call, and one per process exit, in the layout `trace::linux::Record` reads; for `--children` it traces the processes traced ones start, from their start, with a record of each |
| `tests/replay.rs` | Runs the built binary on recordings made the way a live trace makes them |
| `docs/` | The website at iotap.told.me, served by GitHub Pages from this directory: static HTML, CSS and JS with self-hosted fonts and no build step; `CNAME` names the domain. `index.html` is the English page, `ko/`, `zh/` and `ja/` the Korean, Simplified Chinese and Japanese ones, the same page translated by hand, each linking the others with `hreflang`; `assets/og.jpg`, `og-ko.jpg`, `og-zh.jpg` and `og-ja.jpg` are the cards link previews show, rendered from `assets/og-card*.html` as their comments say, and scrapers cache a card under its URL, so a new card takes a new file name. The Korean, Chinese and Japanese pages are set in Pretendard, Noto Sans SC and Pretendard JP, cut down to the characters those pages use: after changing their text, cut them again with `scripts/site/subset_fonts.py` |
| `scripts/site/` | `subset_fonts.py` cuts the fonts of the Korean, Chinese and Japanese pages to the characters the pages show, from the full fonts, which its docstring says where to get |
| `scripts/live/` | The live checks: `run.py` runs README.md's checks for this system with the user's sudo and judges each expectation; `macos.py`, `linux.py` and `shared.py` hold the checks, `harness.py` what they share, `tui.py` drives the terminal UI in a pseudo-terminal, `programs.py` holds programs for them to trace, and `macos.command` starts a run in Terminal.app |

## Commits

Conventional Commits, English, no AI attribution trailers. Title, one blank line, then `- ` bullets
with no blank lines between them. Do not push.
