# Changelog

## [0.2.0] - 2026-10-02

Measure macOS network traffic even when an application uses Skywalk instead of
ordinary socket read/write syscalls. Radio streaming through AVPlayer, including
vtamp, now appears in the Network tab.

- Add OS-measured TCP/UDP byte counts, interval-average rates, endpoints and
  interfaces on macOS, collected separately from syscall accounting.
- Start the macOS Network tab in **Traffic** view. Press `v` to switch to
  **Syscalls** for call counts, errors, latency and Unix-domain socket I/O.
- Add `network_sample` and `network_status` JSON Lines records and an optional
  `network_traffic` summary. Existing event and syscall summary fields keep their
  meanings; do not add the two accounts together.
- Save network counter observations in version 3 recordings for deterministic
  replay. Versions 1 and 2 remain readable; older iotap versions cannot read
  version 3 recordings.
- Report unavailable or incomplete macOS statistics and keep syscall tracing
  running. Linux retains its syscall-based network accounting.
- Fix crowded TUI hints clipping the host-name status message.

### Upgrade

```sh
brew update
brew upgrade iotap
iotap --version
sudo iotap -q --tui vtamp
```

NetworkStatistics is a private macOS interface; its availability can vary with
the OS version. iotap records metadata only, never transferred data.

## [0.1.0] - 2026-10-02

First release of iotap: trace the file and network I/O of selected processes on
macOS and Linux, with the path or socket endpoint, byte counts, and latency of
each read and write. iotap records metadata only, never the transferred data.

- Select processes by PID or name, and follow their descendants with `--children`.
- Watch an event stream and per-target summary, JSON Lines, or an interactive
  terminal UI with file and network details.
- Filter file or network traffic and network interfaces, and optionally resolve
  remote host names.
- Record traces and replay them deterministically without root.
- Trace through macOS kdebug or an embedded Linux eBPF program; kernel tracing
  needs root and leaves no daemon behind.

### Install

```sh
brew install rath/tap/iotap
iotap --version
sudo iotap --tui 1234
```

Replace `1234` with the PID of a running process. Homebrew installs a prebuilt
binary; Rust is not required. The tap supports Apple Silicon Macs and Linux on
ARM64 or x86-64. Intel Mac users can build from source.

The release also includes `iotap-<target>.tar.gz` archives and `SHA256SUMS`.
Unpack the archive for your platform and put `iotap` on your `PATH`. Linux
binaries require glibc 2.28 or newer, libelf, and zlib (Debian/Ubuntu:
`sudo apt install libelf1 zlib1g`; RHEL/Fedora: `sudo dnf install elfutils-libelf zlib`).
Homebrew manages its own runtime dependencies and has its own OS requirements.

### Requirements and limitations

- Linux tracing needs kernel 5.8 or newer with BPF and syscall tracepoints.
- Only one tracer can own macOS kdebug at a time; stop `fs_usage` or another
  kdebug tracer before starting iotap.
- Memory-mapped I/O and kernel-initiated I/O are not captured. Linux `io_uring`
  and libaio are not captured either.
- See the README for build instructions, all options, and detailed limitations.
