# iotap

See what a process on your machine is really doing: which files it reads and writes, which
addresses it talks to, and how many bytes go each way. For macOS and Linux.

## Why

Something on your machine is busy and you want to know with what. A process is chewing through
the disk, an app you just installed is talking to somewhere you never asked for, a build step is
slow and you suspect I/O, or a program keeps failing and you want to see which file or
connection it trips on. The usual tools each show a piece: `lsof` and `netstat` list what is open
right now but not what moves through it, Activity Monitor and `top` count bytes but do not say
where they went, and a packet capture shows the traffic of the whole machine with no process
behind it.

iotap watches the processes you name and reports every read and write they make as it happens:
the file or the remote address, how many bytes were asked for and how many moved, how long the
call took, and whether it failed. When the process exits or you press Ctrl-C, it sums this up per
file and per endpoint. Point it at a name and it also picks up processes started later under that
name; add `-f` and it follows every process the traced ones start.

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
    en0    received 4.0 KiB (2 calls), sent 517 B (1 call)
  5 calls, 1 failed
```

Read top to bottom, this is the whole life of one `curl`: it sent a 517-byte request to
93.184.216.34 on port 443, asked for 16 KiB back and got 4 KiB, asked again and found nothing
waiting yet (`EAGAIN`), wrote the 4 KiB to `page.html` and 20 bytes of progress to the terminal,
then exited. The summary at the end is the same story per file and per endpoint, and the
network traffic went over en0, the interface that holds 192.168.1.20.

For a process that runs longer, `--tui` shows the same tables live and lets you drill into any
file or connection, `--json` streams every event as one line for `jq` or a log, and `--record`
saves the trace so you can replay it later, in any of these forms, without root.

## Why it needs root

iotap does not attach a debugger, inject code or change the program it watches; the program runs
exactly as it would otherwise. Instead iotap reads the kernel's own record of what the program
asks for. Every read, write, open and connect a program makes is a system call, and the kernel
can be told to log each one as it happens, with the process it came from, its arguments and its
result.

- On macOS that log is the kernel trace facility, kdebug, the same source Apple's `fs_usage`
  reads. It is built into the kernel, so nothing has to be installed.
- On Linux, iotap loads a small eBPF program of its own onto the kernel's syscall tracepoints.
  The kernel verifies the program before running it and unloads it when iotap exits.

Both are a view into every process on the machine, and that is what only root gets. A user who
could switch on kdebug or load an eBPF program could watch every other user's programs, so the
kernel allows neither to anyone else. That is why tracing needs `sudo`, exactly as `fs_usage`
does, and why iotap says so and stops before it touches anything when run without it. Replaying a
recording reads nothing from the kernel, so it needs no root.

What iotap does with that access is deliberately narrow:

- **Metadata only.** It records the call, the descriptor, byte counts, latency, the path and the
  socket endpoint. It never reads or stores the data being transferred: a process reading your
  SSH key shows up as a read of that file and its size, never its contents. Recordings hold the
  same and nothing more.
- **Only the processes you name**, and with `-f` the processes they start. The kernel is asked to
  record their calls and no others.
- **Nothing left behind.** On macOS only one program can own kdebug at a time, so iotap releases
  it on every exit path, including errors, signals and panics. On Linux the kernel drops the
  eBPF program the moment iotap exits, however it exits. The terminal UI restores the terminal
  the same way.
- **One binary, no daemon.** iotap runs only while you run it, and makes no connections of its
  own; the optional host name lookups (`--resolve`) go through the system's resolver.

## Requirements

- macOS, or Linux 5.8 or later on 64-bit Arm or x86-64 with BPF and syscall tracepoints, as
  distribution kernels have them. Tracing needs root, so run iotap with `sudo` (see
  [Why it needs root](#why-it-needs-root)); replaying a recording does not.
- To build: Rust 1.98.1, which `rust-toolchain.toml` selects, and
  - on macOS, the Xcode Command Line Tools, for the small C file that reads descriptor details
    from libproc;
  - on Linux, clang for the eBPF program, and what the libbpf bundled with libbpf-rs needs to
    build: make, pkg-config, a C compiler, and the libelf and zlib development files. On Debian
    and Ubuntu that is `sudo apt install build-essential clang pkg-config libelf-dev zlib1g-dev`.
    The binary links libelf and zlib.

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

A TARGET is a process ID or a process name. A name matches every running process whose name,
executable's file name or first argument's file name equals it, ignoring case, and iotap also
traces processes started later under that name. At least one process must match when iotap
starts. `-n` makes numeric targets names.

With `-f`, iotap also traces the processes that the traced ones start, and theirs in turn: every
descendant, those running when it starts and those started later. The descriptors a child has
from its parent show their files and endpoints like any others. iotap leaves out itself and the
processes it runs under, such as its `sudo`, so tracing the shell it was started from takes in
the shell's other children. On Linux a child is traced from its start, on macOS from a few
milliseconds after (see [Limitations](#limitations)).

The first argument, `argv[0]`, holds the command a process was started by, and it is the name
`pgrep` and `killall` go by on macOS. The macOS kernel names a process after the file it runs,
links followed, so a program started through a link to a file named after its version, as some
installers set up, has the version for its name and still matches the name of the link. On Linux
a process's name is the one the kernel keeps, at most 15 characters, so a longer name matches
only the file names.

```
sudo iotap 1234                        # one process
sudo iotap Safari                      # every Safari process, and new ones
sudo iotap -f make                     # make and every process it starts
sudo iotap --tui 1234                  # live terminal UI
sudo iotap --tui -q 1234               # the same without the Events tab
sudo iotap --tui --resolve curl        # host names in place of remote addresses
sudo iotap -i wlan0 firefox            # only network I/O over wlan0
sudo iotap --json curl | jq -c 'select(.type == "event")'
sudo iotap -q -d 10 Finder             # summary only, after 10 seconds
sudo iotap --net-only --record t.iotaprec 1234
iotap --replay t.iotaprec              # the same output again, without root
```

| Option | Effect |
|---|---|
| `-f`, `--children` | Also trace every descendant of the traced processes, running or started later |
| `--tui` | Live terminal UI instead of the event stream |
| `--json` | JSON Lines instead of text |
| `-q`, `--quiet` | No event lines; notices and the summary remain. With `--tui`, no Events tab |
| `--files-only`, `--net-only` | Report one kind of I/O |
| `-i`, `--interface NAME` | Report only network I/O over this network interface; repeat for several (see [Network interfaces](#network-interfaces)) |
| `--resolve` | Show remote addresses as host names in the summary, and in the terminal UI from the start (see [Host names](#host-names)); not with `--json` |
| `-d`, `--duration SECS` | Stop after this many seconds |
| `--top N` | Rows per table in the text summary; default 30 |
| `--buffer RECORDS` | Kernel buffer size in 64-byte records; default 524288, which is 32 MiB. On Linux the ring buffer takes as many bytes, rounded up to a power of two |
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
exit or exec, children that iotap could not trace, and records the kernel dropped because its
buffer was full.

### JSON Lines

With `--json`, every line is one object with a `type` field. Times are nanoseconds since the Unix
epoch.

| `type` | Fields |
|---|---|
| `start` | `time_ns`, `processes` |
| `event` | `time_ns`, `pid`, `tid`, `op`, `dir`, `syscall`, `fd`, `requested`, `bytes`, `messages`, `errno`, `error`, `latency_ns`, `target`, `interface`, `resolved` |
| `lost_events` | `time_ns` |
| `attached` | `pid`, `name`, `parent` |
| `untraced` | `pid`, `parent`, `reason` |
| `exec` | `pid`, `path` |
| `exited` | `pid`, `name` |
| `summary` | `duration_ns`, `processes`, `totals`, `interfaces`, `lost_events`, `unfinished_calls`, `calls_started_before_trace`, `untraced_children`, `unknown_interface_calls`, `files`, `network`, `other` |

The `parent` of an `attached` process is the traced process that started it, or null when iotap
does not know it, as for a process attached by its name. An `untraced` object tells of a child
that `-f` could not trace: its `reason` is `ended` when the child ended before iotap could trace
it, and `full` when iotap was tracing as many processes as it can. The summary's
`untraced_children` counts them by reason.

A `target` is `{"kind":"file","path":…}`, `{"kind":"socket","proto":…,"local":…,"remote":…}`
with a `path` for Unix-domain sockets, `{"kind":"other","fd_type":…}` or `{"kind":"unknown"}`.
An event's `interface` is the name of the network interface its I/O went over, `"?"` when iotap
cannot tell it, or null for I/O that goes over none, such as a file's or a Unix-domain
socket's (see [Network interfaces](#network-interfaces)). The summary's `interfaces` sums the
network I/O over each, in the same terms, and `unknown_interface_calls` counts the calls that
`--interface` left out for going over an interface iotap cannot tell.
A file `path` that starts with `…` is only the end of a longer path (see
[Limitations](#limitations)). An `errno` is the traced system's own number, which `error` names.
`resolved` says how iotap learned the target:

- **`traced`** means iotap saw the call that created the descriptor.
- **`snapshot`** means the descriptor was already open when tracing of the process began.
- **`lazy`** means iotap looked the descriptor up when it was first used.
- **`none`** means the descriptor is unknown. Its target is `unknown`, or a bare `socket` when
  the call works only on sockets.

```
{"type":"event","time_ns":1790259200104708333,"pid":4242,"tid":2,"op":"recvfrom","dir":"read","syscall":"recvfrom","fd":5,"requested":16384,"bytes":null,"messages":null,"errno":35,"error":"EAGAIN","latency_ns":41666,"target":{"kind":"socket","proto":"tcp","local":"192.168.1.20:61000","remote":"93.184.216.34:443"},"interface":"en0","resolved":"traced"}
```

### Terminal UI

`--tui` shows throughput for the last complete second and in total, then three tabs: files,
network endpoints, and the latest 10,000 events. `i` adds the network throughput of each
interface below the totals. With `-q` the Events tab is left out, and
events are not kept for it. This is the Files tab after replaying a recorded download:

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

 4242 (curl) exited    q quit  s sort  p pause  i interfaces  r reset  ↑↓ select  enter details
```

| Key | Action |
|---|---|
| `1` `2` `3`, Tab, Left, Right | Switch tabs |
| `s` | Sort by bytes, read, write, calls or most recent |
| `p` or Space | Pause the view; tracing goes on |
| Enter | Show or hide the details of the selected row; with none selected, select the top row and show its details |
| `y` | Copy the selected row's path, or its socket's address |
| `r` | Reset the view: tables, totals and events start again from zero, and the clock shows the time since the reset. The summary still covers the whole trace |
| `n` | Show remote addresses as host names, or as addresses again (see [Host names](#host-names)). The summary printed on quitting does as the UI did |
| `i` | Show the network throughput of each interface below the totals, or hide it again (see [Network interfaces](#network-interfaces)) |
| Up, Down, Page Up, Page Down, Home, End, or `k` `j` `g` `G` | In the Files and Network tabs, select a row and move the selection; the first key selects the top row, or the last row for End. In the Events tab, scroll; End follows new events again |
| Esc | Back out a step: close the details, then let go of the selection, then quit |
| `q`, Ctrl-C | Quit and print the summary |

The UI stays open after tracing stops and says why it stopped.

Nothing is selected at first, and each table shows its top rows as they change. A selected row is
bold, with a mark in the left margin, and the selection stays with its target as the rows
re-sort.

Tables write the home directory of the user who ran sudo as `~`. A path too long for its column
loses directory names from the left, each cut to its first letter as in the fish shell's prompt,
so the file name and the directories nearest it stay whole the longest:
`~/L/A/G/C/Default/Cache/Cache_Data/data_1`. The details panel and `y` use the full path.

The details panel opens below the Files or Network table and shows the selected target:

- its full path or endpoint
- while host names are shown, the name of its remote address, or why there is none
- bytes and calls in each direction, and the failed calls
- mean and longest latency
- when it was first and last used
- the processes that used it
- for a socket, the network interfaces its I/O went over
- for a connection, its local addresses
- its latest events, unless `-q` left out the Events tab

For a file or a Unix-domain socket with a path, the panel also shows what the path is now: kind,
size, time since modification, permissions and owner. It reads this metadata with `lstat` each time
it draws, never the contents, so a replay shows the file on the replaying machine.

`y` copies in every way the system has:

- **The terminal's clipboard (OSC 52).** This reaches the machine you sit at, even over SSH, in
  terminals that allow it: iTerm2 (once "Applications in terminal may access clipboard" is on),
  kitty, WezTerm, Ghostty and Alacritty. tmux passes it on with `set-clipboard on`. Terminal.app
  ignores it.
- **The Mac's pasteboard, on macOS.** `pbcopy` runs as the user who ran sudo, so it works in any
  terminal on the Mac that iotap runs on.

On macOS the status line reports what `pbcopy` did. A terminal never says whether it honoured
OSC 52, so on Linux the status line says only that the terminal was asked.

### Host names

With `--resolve`, or `n` in the terminal UI, remote addresses show as host names:
`tcp www.example.com:443` in place of `tcp 93.184.216.34:443`. iotap asks the system's resolver
through `getnameinfo`, so the name comes from the hosts file, a reverse DNS lookup or multicast
DNS, as the system is set up to look. An answer can take half a minute, so up to 16 threads of
iotap's own wait for them, and an address shows as itself until its name arrives.

Only the addresses shown are looked up, each once: the rows on screen in the terminal UI, and
the rows of the summary, for which iotap waits at most two seconds. Event lines, JSON and
recordings keep the addresses, and replaying with `--resolve` looks the names up again.

### Network interfaces

The kernel's records do not say which network interface a call's data went over, so iotap tells
it from the socket's addresses and the host's interfaces, which it lists with `getifaddrs` as
tracing starts and again when a socket's local address is new to it, at most once a second of
the trace:

- Traffic to a loopback address or to one of the host's own addresses goes over the loopback
  interface, `lo` on Linux and `lo0` on macOS, whichever address it comes from: the kernel
  routes it there.
- Other traffic goes over the interface that holds the socket's local address. A link-local
  IPv6 address goes by the interface it is scoped to.
- A socket without a local address of its own, such as an unconnected UDP socket bound to every
  address, sends each datagram wherever the route to its destination leads, which iotap does
  not see. Its I/O, and that of a socket whose ends iotap never learned, goes over an interface
  iotap cannot tell, shown as `?`.
- Unix-domain, netlink and routing sockets, files and other descriptors go over no interface,
  shown as `none` where interfaces are listed.

`-i NAME` reports only the network I/O over the interface named `NAME`, exactly as
`ip link` or `ifconfig` names it, case included; repeat it for several. File and other I/O is
left out, and so is I/O over an interface iotap cannot tell, which the summary counts. iotap
warns when no interface has the name, but goes on, since the interface may come up later, as a
VPN's does. The text summary lists the network totals of each interface under the network line:

```
  network  received 14.1 MiB (3642 calls), sent 1.8 KiB (12 calls)
    wlan0  received 14.1 MiB (3601 calls), sent 517 B (1 call)
    lo     received 2.0 KiB (21 calls), sent 1.1 KiB (9 calls)
    ?      received 0 B (0 calls), sent 40 B (1 call)
    none   received 1.2 KiB (20 calls), sent 120 B (1 call)
```

In the terminal UI, `i` shows the same below the throughput, with the last complete second
beside the totals. The table's rows are the busiest interfaces first, then `?` and `none`; when
the screen is short, the last row sums the interfaces that did not fit.

```
                FILE READ  FILE WRITTEN  NET RECEIVED      NET SENT
 per second           0 B       1.2 MiB       1.2 MiB           0 B
 total                0 B      14.1 MiB      14.1 MiB       1.8 KiB
 INTERFACE     RECEIVED/S        SENT/S      RECEIVED          SENT
 wlan0            1.2 MiB           0 B      14.1 MiB         517 B
 lo                   0 B           0 B       2.0 KiB       1.1 KiB
 ?                    0 B           0 B           0 B          40 B
 none                 0 B           0 B       1.2 KiB         120 B
```

### Recordings

`--record FILE` saves the raw kernel records together with every answer libproc or `/proc` gave and
when it gave it, and each list of the host's network interfaces, and `--replay FILE` feeds them
through the same processing, so a replay reproduces the output of the live run in any output mode,
except that the text and terminal output write times of day in the local time zone of the machine
that shows them, where JSON Lines give times as nanoseconds since the epoch. A recording holds paths
and addresses but no transferred data. It replays on the operating system it was made on, since its
calls use that system's numbers for errors, address families and flags. iotap writes the file out
each time it has read the trace up to a new point, so the recording of a run that was killed replays
up to about there, and says that it ends abruptly.

## How it works

1. On macOS, iotap configures kdebug to record BSD syscalls, file-system path lookups and process
   exits, and only for the traced processes. On Linux, it loads its eBPF program onto the
   kernel's syscall entry and exit tracepoints and, from Linux 6.16, its process exit tracepoint.
   The program pairs the entry and return of each call of a traced process in the kernel, and
   writes one record per call to a ring buffer, with the path, socket address or pair of new
   descriptors the call took, read from the process's memory as the call returns.
   With `-f`, the Linux program also watches the kernel's task creation tracepoint, which fires
   in the parent before a child can run, and traces each child of a traced process from there.
   On macOS kdebug does not pass tracing on to a child, but it records the creation of every
   thread, whatever process it belongs to, and each exec; from these records iotap finds the
   processes that traced ones start, and flags each for tracing as soon as it reads the record.
2. A reader thread drains the kernel buffer at least every 10 ms, so that descriptors can be looked
   up while they are still open. On Linux the program wakes it sooner once a quarter of the ring
   buffer is full; until then records wait, so that a busy process is read in batches. Every
   250 ms it also checks the processes for exits, exec and new processes with a traced name; with
   `-f`, its first check also takes in any descendant started while tracing began. On Linux,
   calls that return on different processors reach the ring buffer slightly out of order, so the
   reader holds each record until 5 ms after its call returned and passes the records on in the
   order the calls returned.
3. The main thread pairs the entry and return record of each syscall on macOS, reassembles paths
   from the lookup records, and tracks what each descriptor refers to. When a process is attached,
   its open descriptors come from libproc on macOS and from `/proc` on Linux; after that, the
   traced open, socket, connect, accept, dup, fcntl and close calls keep the table current.
4. libproc and `/proc` describe a descriptor as it is when asked, a few milliseconds after the
   traced call. In between, the process may have closed it and received the same number for
   another one. So an event whose target comes from such an answer is held back until the trace
   has been read past the moment of the answer. If the trace shows the descriptor closed before
   then, the answer described whatever held the number at that moment. It still stands when that
   was the same file, which on macOS the kernel's lookups tell by the file's vnode; otherwise the
   event gets what the trace alone knows. An event waits about 10 ms for this, at most about
   100 ms, and longer only while iotap lags behind the kernel.
5. Processing after the reader depends only on the records, on the answers of libproc or
   `/proc` and on the lists of the host's network interfaces, never on the clock, which is why
   recordings replay exactly. Only the live terminal UI
   reads the clock, for its elapsed time and its current second, and host names, when asked for,
   are what the resolver answers at the time. Times of day in text and terminal output are in the
   time zone of the machine that shows them.

## Limitations

- **One owner, on macOS.** Only one program can use kdebug at a time. iotap cannot run alongside
  fs_usage, ktrace, Instruments or tailspin. On Linux several iotap runs, and other eBPF tools,
  can trace at once.
- **Only syscalls.** Memory-mapped file I/O and I/O the kernel does on a process's behalf, such as
  page-cache writeback, never appear. On Linux neither does I/O submitted through io_uring or
  libaio (`io_submit`), nor data that `splice`, `tee`, `vmsplice` or `copy_file_range` move.
- **Unknown sizes.** On macOS, `sendfile` returns its byte count through a pointer the trace does
  not carry, and `sendmsg_x` and `recvmsg_x` return message counts, so iotap counts those calls
  without bytes. On Linux, `sendmmsg` and `recvmmsg` return message counts, and `sendfile` counts
  as a write to its output descriptor.
- **Stale lookups.** iotap discards an answer of libproc or `/proc` when the trace shows the
  descriptor closed before the answer was given, unless the number was by then held by a
  descriptor on the same file, which only macOS lets iotap tell. A descriptor closed in a way the
  trace does not show, as by exec for a close-on-exec descriptor, can still leave a lookup naming
  a later descriptor.
- **Children.** Without `-f`, the processes a traced one starts are not traced. With it, on macOS
  a child is traced from when iotap reads the kernel's record of its creation, a few milliseconds
  after it starts: its first calls are missed, and so is a child that ends sooner, which iotap
  reports. On Linux a child is traced from its start. There `-f` needs the kernel's
  `task_newtask` tracepoint laid out as iotap's program reads it; iotap checks, and refuses `-f`
  where it is not.
- **New processes by name.** A name target picks up processes that start with that name, or take
  it by exec, within 250 ms and misses their first calls under it. On macOS, a process that gives
  itself the name in `argv[0]` later, as Node.js programs do through `process.title`, is picked
  up only if it does so within two seconds of starting or of its latest exec. On Linux such
  programs rename the process too, which iotap notices whenever it happens.
- **exec, on macOS.** exec gives a process a new kernel identity without the trace flag. iotap
  flags the process again once it reads the kernel's record of the exec, usually within 10 ms and
  at most 250 ms later, and misses the calls in between. On Linux tracing goes on through exec.
- **Short-lived sockets.** A socket closed before iotap could look it up shows only what the trace
  reveals: its protocol, such as `tcp ?`, the path of a Unix-domain connect, the protocol and
  bound address of the socket it was accepted on, or just `socket`. On Linux the trace also
  carries the address a connect named, so such a socket keeps its remote end, as in
  `udp -> 127.0.0.53:53`. On macOS, descriptors from `socketpair` reach the process through
  memory, so iotap learns them only through libproc.
- **Dropped records.** Under heavy load the kernel buffer can overflow. iotap reports it and the
  totals undercount; a larger `--buffer` helps.
- **Paths.** The macOS kernel reports a path as it resolved it, after following symbolic links,
  and before macOS 15.4 only its last 184 bytes. On Linux the program reads a path as the process
  passed it. iotap takes the full name from libproc or `/proc` when the new descriptor, or on
  macOS a later one on the same file, still holds its number by the time iotap asks. Otherwise a
  relative path is joined to the working directory or the directory descriptor. On macOS that is
  wrong after a link with a relative target other than `/etc`, `/tmp` and `/var`, and a truncated
  path is shown as `…` followed by its end. A name that is not valid UTF-8 is shown with U+FFFD
  in place of the invalid bytes, so two files whose names differ only in those bytes count as one.
- **32-bit processes, on Linux.** iotap knows the call numbers of 64-bit processes. A 32-bit
  program numbers its calls differently, so its trace is misread; do not trace one.
- **Exits, on Linux before 6.16.** Only from Linux 6.16 does the kernel tell the program when a
  process's last thread exits. On older kernels iotap learns of an exit from its poll of `/proc`,
  up to 250 ms later.
- **Containers, on Linux.** The program knows processes by their IDs outside any PID namespace,
  so run iotap on the host, where it traces processes in containers by those IDs.
- **Recording size.** A recording grows by about 64 bytes per kernel record on macOS, and by
  96 bytes plus the path or address it took per call on Linux.
- **Interfaces.** iotap names the interface that holds a socket's local address and does not
  look up routes, so for a bridge or a bond it names the bridge or the bond, never a member
  port, and it misses where policy routing sends traffic out another interface. Sockets that
  send from every address, and sockets whose ends iotap never learned, count as `?`. On Linux, a
  process in another network namespace than iotap's, as in a container, has other interfaces
  than the ones iotap lists, so its traffic counts as `?` too; run iotap in that namespace to
  tell them apart. A recording made before iotap listed interfaces knows none.
- **Host names.** A reverse lookup finds the name the owner of an address gave it, often one of a
  hosting or CDN provider rather than the name the program looked up, and often none. iotap
  cannot learn the name the program looked up, since it never reads the data programs send or
  receive. Each lookup is a query to the configured DNS servers, and while iotap traces the
  resolver itself, `mDNSResponder` on macOS or `systemd-resolved` on Linux, its own lookups show
  in the trace.

## Checking against a live kernel

The automated tests need no root. They cover everything after the kernel with synthetic record
streams laid out the way XNU and iotap's eBPF program write them, but they cannot exercise the
kernel interface itself. After changing `src/sys/`, `src/reader.rs`, a syscall table, `csrc/` or
`bpf/`, run the checks for each system the change affects.

`scripts/live/run.py` runs them and judges every expectation, printing PASS or FAIL; given check
numbers, it runs only those. Build with `cargo build --release`, then start it in a terminal
where `sudo -v` has been answered: each root step uses `sudo -n`, and the run ends with
`sudo -k`. On macOS, `open -a Terminal scripts/live/macos.command` asks sudo and runs it in a
window of its own, where sudo can use Touch ID. Its outputs go to `target/live/`. The terminal UI
checks need Python's pyte package, the host-name checks a connection to the Internet, and the
interface checks a route to 192.0.2.1, such as a default route.

### macOS

1. **Writes to a file.** Run `yes > /dev/null &` and then `sudo ./target/release/iotap $!`. Expect
   a stream of `write` lines to `/dev/null`, and after Ctrl-C a summary with one file row.
2. **Byte counts.** Run `dd if=/dev/zero of=/dev/null bs=1m &` and trace its pid. Every `read` of
   `/dev/zero` and every `write` to `/dev/null` should move 1048576 bytes.
3. **Network.** Start a slow download, such as `curl -o /dev/null --limit-rate 100k <URL>`, and run
   `sudo ./target/release/iotap curl`. Expect `tcp … -> <server>:443` rows, and a summary when
   curl exits.
4. **Dropped records.** The kernel buffer holds at least 8192 records per CPU, whatever `--buffer`
   asks for, so make iotap fall behind instead. While it traces the `yes` process and one waiting
   to write, stop it with `sudo kill -STOP <iotap pid>` and continue it two seconds later with
   `sudo kill -CONT`. Then kill `yes` and let the other process write a known number of times.
   Expect the dropped-records notice, and tracing to go on and count every one of those writes.
5. **Single owner.** While `sudo fs_usage` runs, iotap must fail with the "another tool … is using
   the kernel trace facility" error.
6. **Release.** After iotap exits by Ctrl-C, by `--duration` or because the target exited,
   `sudo fs_usage -t 1` must start normally.
7. **Replay.** Trace with `--json --record t.iotaprec`, then run
   `iotap --json --replay t.iotaprec`. The replayed output must be identical to the live output.
8. **Terminal UI.** Run `sudo ./target/release/iotap --tui $!` against the `yes` process. Try every
   key, then quit; the terminal must be restored and the summary printed.
9. **Names.** While iotap traces a name, start a process that takes it by exec a second after it
   starts, such as `sh -c 'sleep 1; exec ./mycat'` for a `cat` you built that waits for its input.
   A copy of `/bin/cat` will not do: macOS kills copies of its own programs as they start. Expect
   the "now tracing" notice for it. Then run `yes` through a link to `/usr/bin/yes` and trace the
   link's name; while that runs, start a second `yes` through the link, and a process that takes
   the name in `argv[0]` a second after it starts, as `perl -e 'sleep 1; $0 = "<name>"; …'` does.
   Expect `yes` as the first process's name, and the "now tracing" notice for the other two.
10. **Host names.** Repeat check 3 with `--resolve`, then with `--tui --resolve`. Expect the
    server's host name in place of its address in the summary and in the Network and Events tabs,
    the address and the name in the details panel, and `n` switching between names and
    addresses.
11. **Calls and targets.** Trace a program that opens files through links, along long paths and
    relative to other directories, and one that makes known calls on files, a pipe and TCP, UDP
    and Unix-domain sockets, such as `lab` and `workload` in `scripts/live/programs.py`. Expect
    every file under the path the kernel gives its descriptor (`F_GETPATH`), every call with its
    size, and no socket with a wrong end. A socket closed at once may lack its ends, as
    [Limitations](#limitations) says.
12. **Children.** Trace with `-f` a process that has a child running, and that then starts a child
    that starts one of its own, a child that runs another program by exec, and twenty children
    that each write a little and end at once, such as `family` in `scripts/live/programs.py`.
    Expect the running child among the processes traced from the start, a "now tracing" notice
    naming its parent for each later child, and every write of the children that wait half a
    second before writing. Each child that ended at once must be traced or reported to have
    ended before iotap could trace it, and the summary must count the latter. Traced with `-f`,
    a process that iotap runs under, such as the shell that started it, must take in neither
    iotap nor its sudo, but must take in a process it starts meanwhile.
13. **Network interfaces.** Trace, with `--json` and `--record`, a program that receives on a UDP
    socket connected to an address the default route leads to, sends to 127.0.0.1, to `::1` and
    to the host's own address, sends over a socketpair and from a socket bound to every address,
    each with a size of its own, such as `interfaces` in `scripts/live/programs.py`. Expect the
    `interface` of the first to be the one `route -n get` names, the loopback interface for the
    next three, null for the socketpair and `?` for the last, the summary's `interfaces` to add
    up to its network totals, and the replay to match the live output. With `-i` and that
    interface, expect only its I/O and a count of the calls left out; with `-q -i lo0`, a
    Totals line for `lo0` and no Files table; with a name no interface has, a warning and the
    trace. In the terminal UI, `i` must show a row for each interface, its columns in line with
    the throughput's, and the details of the connected socket its interface.

### Linux

Run these on each processor the change affects. `bpftool prog show` lists the eBPF programs
loaded; iotap's are named `sys_enter`, `sys_exit`, from Linux 6.16 `process_exit`, and with `-f`
`task_newtask`.

1. **Root.** Without sudo, iotap must fail with "tracing with eBPF requires root".
2. **Writes to a file.** Run
   `sh -c 'sleep 1; exec dd if=/dev/zero of=/tmp/x bs=1M count=10 status=none' &` and trace `$!`
   at once. Expect ten `write` lines of 1048576 bytes to `/tmp/x`, and a summary when dd exits.
   dd is gone too soon for an exec notice; trace `sh -c 'sleep 1; exec sleep 1'` for one.
3. **Network.** Serve a file with `python3 -m http.server 8000 --bind 127.0.0.1` and trace a
   `curl -o /dev/null` of it. Expect `tcp 127.0.0.1:… -> 127.0.0.1:8000` rows whose received
   bytes add up to more than the file's size.
4. **Sockets and pipes.** Trace a program that talks over a Unix-domain socket with a path, one in
   the abstract namespace, a pipe and a UDP socket on `::1`, then keeps them open for a second.
   Expect `unix` rows with the path and with `@name`, a `udp [::1]:…` row, and a `pipe` row among
   the other descriptors.
5. **Dropped records.** Trace `yes > /dev/null &` and a process waiting to write with
   `--buffer 1024`, stop iotap with `kill -STOP` and continue it two seconds later. Then kill
   `yes` and let the other process write a known number of times. Expect the dropped-records
   notice, and tracing to go on and count every one of those writes: `yes` can make calls twice
   as fast in one run as in another, so its own count cannot show what iotap missed. Signal iotap
   from a root shell: where sudo runs commands in a pty, as Ubuntu's does, a stopped command
   makes sudo stop its own process group, the script that started it included.
6. **Release.** After iotap exits in any way, even by `sudo kill -KILL` while tracing with `-f`,
   `sudo bpftool prog show` must no longer list its programs.
7. **Several at once.** Two iotap runs tracing the same process must both report all its calls.
8. **A flood.** Record `yes > /dev/null` for three seconds and replay it with `--json`. No event
   may lack its latency but for calls truly under way when tracing began, and the summary must
   count none that were dropped.
9. **Names.** Trace a name, then start a new process with that name and one that takes it by exec,
   each blocked in a read for a second. Expect the "now tracing" notice for both, and their calls.
   Repeat with a name that only `argv[0]` holds, as `bash -c 'exec -a <name> cat'` gives, and
   with a process that takes the name in `argv[0]` a second after it starts, as
   `perl -e 'sleep 1; $0 = "<name>"; …'` does.
10. **Short-lived connections.** Trace a program that connects UDP sockets to a local server and
    closes each at once. Expect `udp -> 127.0.0.1:…` rows, not `udp ?`.
11. **Calls under way.** Trace a process whose read began before iotap started and ends while it
    runs, and one whose read begins while iotap runs and has not ended when it stops. The summary
    must note one call that began before tracing, and with `--json` count one unfinished call.
12. **Replay**, **terminal UI** and **host names**, as on macOS, the last with a download from a
    public server.
13. **Children**, as on macOS, except that every child is traced from its start: each of the
    children that end at once must be traced, with the write it makes.
14. **Network interfaces**, as on macOS, with the interface `ip route get` names and `lo`.

When scripting these checks, signal iotap itself, or send the signal from another process group.
sudo does not pass on a signal that comes from its own process group, which is where `kill -INT $!`
in the script that started `sudo iotap &` sends it from.

## Development

See [AGENTS.md](AGENTS.md) for the module map, the rules and the commands every change must pass.
