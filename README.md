# iotap

Trace the file and network I/O of macOS processes.

Give iotap process IDs or names and it reports every read and write syscall those processes make:
the descriptor, the size asked for and the size moved, the latency, and what the descriptor refers
to, a file path or a socket endpoint. It reads the kernel trace facility (kdebug), the source
`fs_usage` uses, so it needs no debugger, no code injection and no changes to the traced program.

```
$ sudo iotap curl
iotap: tracing 4242 (curl); press Ctrl-C to stop
TIME                PID  OP               FD   REQUESTED      RESULT     LATENCY  TARGET
14:13:20.004541    4242  sendto            5         517         517    0.041 ms  tcp 192.168.1.20:61000 -> 93.184.216.34:443
14:13:20.104625    4242  recvfrom          5       16384        4096    0.041 ms  tcp 192.168.1.20:61000 -> 93.184.216.34:443
14:13:20.104708    4242  recvfrom          5       16384      EAGAIN    0.041 ms  tcp 192.168.1.20:61000 -> 93.184.216.34:443
14:13:20.104791    4242  write             4        4096        4096    0.041 ms  /Users/me/page.html
14:13:20.104875    4242  write             1          20          20    0.041 ms  /dev/ttys004
iotap: 4242 (curl) exited

iotap summary: 4242 (curl) traced for 0.1 s

Files (2 targets)
        READ    CALLS     WRITTEN    CALLS  FAILED  TARGET
         0 B        0     4.0 KiB        1       0  /Users/me/page.html
         0 B        0        20 B        1       0  /dev/ttys004

Network (1 target)
    RECEIVED    CALLS        SENT    CALLS  FAILED  TARGET
     4.0 KiB        2       517 B        1       1  tcp 93.184.216.34:443

Totals
  files    read 0 B (0 calls), written 4.0 KiB (2 calls)
  network  received 4.0 KiB (2 calls), sent 517 B (1 call)
  5 calls, 1 failed
```

## Requirements

- macOS. Tracing needs root, so run iotap with `sudo`; replaying a recording does not.
- To build: Rust 1.97.1, which `rust-toolchain.toml` selects, and the Xcode Command Line Tools
  for the small C file that reads descriptor details from libproc.

## Build

```
cargo build --release
sudo ./target/release/iotap <TARGET>...
```

## Usage

```
iotap [OPTIONS] <TARGET>...
iotap --replay <FILE> [OPTIONS]
```

A TARGET is a process ID or a process name. A name matches every running process whose name or
executable file name equals it, ignoring case, and iotap also traces processes started later under
that name. At least one process must match when iotap starts. `-n` makes numeric targets names.

```
sudo iotap 1234                        # one process
sudo iotap Safari                      # every Safari process, and new ones
sudo iotap --tui 1234                  # live terminal UI
sudo iotap --json curl | jq -c 'select(.type == "event")'
sudo iotap -q -d 10 Finder             # summary only, after 10 seconds
sudo iotap --net-only --record t.iotaprec 1234
iotap --replay t.iotaprec              # the same output again, without root
```

| Option | Effect |
|---|---|
| `--tui` | Live terminal UI instead of the event stream |
| `--json` | JSON Lines instead of text |
| `-q`, `--quiet` | No event lines; notices and the summary remain |
| `--files-only`, `--net-only` | Report one kind of I/O |
| `-d`, `--duration SECS` | Stop after this many seconds |
| `--top N` | Rows per table in the text summary; default 30 |
| `--buffer RECORDS` | Kernel buffer size in 64-byte records; default 524288, which is 32 MiB |
| `--record FILE` | Also save the trace for `--replay` |
| `--replay FILE` | Replay a saved trace through any output mode |

Tracing ends on Ctrl-C, when every traced process has exited, or when `--duration` runs out. The
summary follows. A second Ctrl-C exits at once, without a summary. The exit status is 0 after a
normal stop, 1 after an error and 130 after a forced exit.

## Output

### Event stream

One line per call. OP is the operation with `_nocancel` and guarded variants folded into their
base call. RESULT is the byte count, a message count, the errno name of a failed call, or `?` when
the trace does not carry the size. REQUESTED and LATENCY show `-` when they are unknown, such as
for calls that take several buffers or calls that began before tracing did. TIME is local time.

Notices go to stderr, so stdout stays a clean event stream. They report processes that start,
exit or exec, and records the kernel dropped because its buffer was full.

### JSON Lines

With `--json`, every line is one object with a `type` field. Times are nanoseconds since the Unix
epoch.

| `type` | Fields |
|---|---|
| `start` | `time_ns`, `processes` |
| `event` | `time_ns`, `pid`, `tid`, `op`, `dir`, `syscall`, `fd`, `requested`, `bytes`, `messages`, `errno`, `error`, `latency_ns`, `target`, `resolved` |
| `lost_events` | `time_ns` |
| `attached`, `exited` | `pid`, `name` |
| `exec` | `pid`, `path` |
| `summary` | `duration_ns`, `processes`, `totals`, `lost_events`, `unfinished_calls`, `calls_started_before_trace`, `files`, `network`, `other` |

A `target` is `{"kind":"file","path":…}`, `{"kind":"socket","proto":…,"local":…,"remote":…}`
with a `path` for Unix-domain sockets, `{"kind":"other","fd_type":…}` or `{"kind":"unknown"}`.
A file `path` that starts with `…` is only the end of a longer path (see
[Limitations](#limitations)). `resolved` says how iotap learned the target:

- **`traced`** means iotap saw the call that created the descriptor.
- **`snapshot`** means the descriptor was already open when tracing of the process began.
- **`lazy`** means iotap looked the descriptor up when it was first used.
- **`none`** means the descriptor is unknown. Its target is `unknown`, or a bare `socket` when
  the call works only on sockets.

```
{"type":"event","time_ns":1790259200104708333,"pid":4242,"tid":2,"op":"recvfrom","dir":"read","syscall":"recvfrom","fd":5,"requested":16384,"bytes":null,"messages":null,"errno":35,"error":"EAGAIN","latency_ns":41666,"target":{"kind":"socket","proto":"tcp","local":"192.168.1.20:61000","remote":"93.184.216.34:443"},"resolved":"traced"}
```

### Terminal UI

`--tui` shows throughput for the last complete second and in total, then three tabs: files,
network endpoints, and the latest 10,000 events. This is the Files tab after replaying a recorded
download:

```
 iotap  4242 curl (exited)                                                               0:00:12
                FILE READ  FILE WRITTEN  NET RECEIVED      NET SENT
 per second           0 B       1.2 MiB       1.2 MiB           0 B
 total                0 B      14.1 MiB      14.1 MiB         517 B
 End of the recording. Press q for the summary.
 1 Files (2)   2 Network (1)   3 Events (7,205)                                     sort: bytes
       READ   CALLS    WRITTEN   CALLS FAILED IDLE TARGET
        0 B       0   14.1 MiB    3601      0  <1s /Users/me/big.iso
        0 B       0       20 B       1      0  <1s /dev/ttys004

 4242 (curl) exited                      q quit  1-3 tabs  s sort  p pause  ↑↓ PgUp PgDn scroll
```

| Key | Action |
|---|---|
| `1` `2` `3`, Tab, Left, Right | Switch tabs |
| `s` | Sort by bytes, read, write, calls or most recent |
| `p` or Space | Pause the view; tracing goes on |
| Up, Down, Page Up, Page Down, Home, End, or `k` `j` `g` `G` | Scroll; End follows new events again |
| `q`, Esc, Ctrl-C | Quit and print the summary |

The UI stays open after tracing stops and says why it stopped.

### Recordings

`--record FILE` saves the raw kernel records together with every answer libproc gave, and
`--replay FILE` feeds them through the same processing, so a replay reproduces the output of the
live run in any output mode. A recording holds paths and addresses but no transferred data.

## How it works

1. iotap configures kdebug to record BSD syscalls, file-system path lookups and process exits,
   and only for the traced processes.
2. A reader thread drains the kernel buffer at least every 10 ms, so that descriptors can be looked
   up while they are still open. Every 250 ms it also checks the processes for exits, exec and new
   processes with a traced name.
3. The main thread pairs the entry and return record of each syscall, reassembles paths from the
   lookup records, and tracks what each descriptor refers to. When a process is attached, its open
   descriptors come from libproc; after that, the traced open, socket, connect, accept, dup, fcntl
   and close calls keep the table current.
4. Processing after the reader depends only on the records and on libproc's answers, never on
   the clock, which is why recordings replay exactly. Only the live terminal UI reads the clock,
   for its elapsed time and its current second.

## Limitations

- **One owner.** Only one program can use kdebug at a time. iotap cannot run alongside fs_usage,
  ktrace, Instruments or tailspin.
- **Only syscalls.** Memory-mapped file I/O and I/O the kernel does on a process's behalf, such as
  page-cache writeback, never appear.
- **Unknown sizes.** `sendfile` returns its byte count through a pointer the trace does not carry,
  and `sendmsg_x` and `recvmsg_x` return message counts, so iotap counts those calls without bytes.
- **Stale lookups.** A descriptor first seen in use is looked up then. If it was closed and its
  number reused in between, the lookup names the wrong target; such events carry `resolved: lazy`.
- **Children.** The kernel's trace flag is not inherited by forked children, so they are not
  traced. A name target picks up new processes with that name within 250 ms and misses their
  first calls.
- **exec.** exec gives a process a new kernel identity without the trace flag. iotap flags the
  process again within 250 ms and misses the calls in between.
- **Short-lived sockets.** A socket closed before iotap could look it up shows only what the trace
  reveals: its protocol, such as `tcp ?`, the path of a Unix-domain connect, the protocol and
  bound address of the socket it was accepted on, or just `socket`. Descriptors from
  `socketpair` reach the process through memory, so iotap learns them only through libproc.
- **Dropped records.** Under heavy load the kernel buffer can overflow. iotap reports it and the
  totals undercount; a larger `--buffer` helps.
- **Paths.** The kernel reports a path as it resolved it, after following symbolic links, and
  keeps only its last 184 bytes. While the new descriptor is still open, iotap takes the full name
  from libproc. Otherwise a relative path is joined to the working directory or the directory
  descriptor, which is wrong after a link with a relative target other than `/etc`, `/tmp` and
  `/var`, and a truncated path is shown as `…` followed by its end.
- **Recording size.** A recording grows by about 64 bytes per kernel record.

## Checking against a live kernel

The automated tests need no root. They cover everything after the kernel with synthetic record
streams laid out the way XNU emits them, but they cannot exercise the kernel interface itself.
After changing `src/sys/`, `src/reader.rs`, the syscall table or the C file, run these checks:

1. **Writes to a file.** Run `yes > /dev/null &` and then `sudo ./target/release/iotap $!`. Expect
   a stream of `write` lines to `/dev/null`, and after Ctrl-C a summary with one file row.
2. **Byte counts.** Run `dd if=/dev/zero of=/dev/null bs=1m &` and trace its pid. Every `read` of
   `/dev/zero` and every `write` to `/dev/null` should move 1048576 bytes.
3. **Network.** Start a slow download, such as `curl -o /dev/null --limit-rate 100k <URL>`, and run
   `sudo ./target/release/iotap curl`. Expect `tcp … -> <server>:443` rows, and a summary when
   curl exits.
4. **Dropped records.** Trace the `yes` process with `--buffer 1024`. Expect the dropped-records
   notice, and tracing should continue.
5. **Single owner.** While `sudo fs_usage` runs, iotap must fail with the "another tool … is using
   the kernel trace facility" error.
6. **Release.** After iotap exits by Ctrl-C, by `--duration` or because the target exited,
   `sudo fs_usage -t 1` must start normally.
7. **Replay.** Trace with `--record t.iotaprec`, then run `iotap --replay t.iotaprec`. The summary
   must match the live one.
8. **Terminal UI.** Run `sudo ./target/release/iotap --tui $!` against the `yes` process. Try every
   key, then quit; the terminal must be restored and the summary printed.

## Development

See [AGENTS.md](AGENTS.md) for the module map, the rules and the commands every change must pass.
