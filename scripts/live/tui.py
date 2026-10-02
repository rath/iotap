"""Drives iotap's terminal UI through a pseudo-terminal and checks what it draws, reading the
screen with pyte. The live checks run it as root, so that iotap is its own child: it needs no
sudo of its own, and takes signals from here.

    tui.py keys BIN PID WRITER WRITTEN COPY
        keys, pausing, the duration running out, signals, a selected file's details, copying it
        (when COPY is 1) and the UI without its Events tab; PID writes to /dev/null, and WRITER
        rewrites WRITTEN, a long path under the home directory
    tui.py names BIN CURL PEER IP NAME SLOW
        host names: CURL downloads from IP, which the resolver names NAME, and PEER has UDP
        sockets connected to 1.1.1.1, to 192.0.2.1, which has no name, and to SLOW, whose lookup
        is slow
    tui.py interfaces BIN PID IFACE LOOPBACK FAR
        the interface table: PID uses IFACE through a UDP socket connected to FAR, and the
        loopback interface LOOPBACK

Prints each screen it looks at, and a PASS or FAIL line for each expectation.
"""

import base64
import fcntl
import os
import platform
import select
import signal
import struct
import subprocess
import sys
import termios
import time

import pyte
from wcwidth import wcwidth

COLS, ROWS = 100, 30
MACOS = platform.system() == "Darwin"


def text_lines(screen):
    """The screen's lines as a terminal shows them. When only the left half of a wide character
    is overwritten, a terminal clears the right half too; pyte keeps it, and its own `display`
    then fails on it."""
    lines = []
    for y in range(screen.lines):
        row = screen.buffer[y]
        out = []
        x = 0
        while x < screen.columns:
            data = row[x].data
            if data and wcwidth(data[0]) == 2:
                if x + 1 < screen.columns and row[x + 1].data == "":
                    out.append(data)
                    x += 2
                    continue
                data = " "
            out.append(data or " ")
            x += 1
        lines.append("".join(out).rstrip())
    return lines


def has(lines, needle):
    return any(needle in line for line in lines)


class Ui:
    """One iotap --tui run in a pseudo-terminal of COLS by ROWS."""

    def __init__(self, name, argv):
        self.name = name
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.ByteStream(self.screen)
        self.raw = []
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

        def controlling_tty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        env = dict(os.environ, TERM="xterm-256color")
        self.proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            # This program starts no threads.
            preexec_fn=controlling_tty,  # noqa: PLW1509
            close_fds=True,
        )
        os.close(slave)
        self.master = master
        print(f"===== {name}: {' '.join(argv)}", flush=True)

    def verdict(self, ok, what):
        print(f"  {'PASS' if ok else 'FAIL'}  {self.name}: {what}", flush=True)

    def pump(self, seconds):
        """Feeds the screen what iotap draws for `seconds`, or until it has exited."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if not ready:
                if self.proc.poll() is not None:
                    return
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.raw.append(chunk)
            self.stream.feed(chunk)

    def keys(self, keys, wait=0.8):
        try:
            os.write(self.master, keys.encode())
        except OSError:
            # iotap has exited and closed the terminal; the verdicts that follow say so.
            return
        self.pump(wait)

    def lines(self):
        return text_lines(self.screen)

    def running(self):
        return self.proc.poll() is None

    def show(self, title):
        print(f"----- {self.name}: {title}")
        lines = self.lines()
        for line in lines:
            if line.strip():
                print(line)
        return lines

    def select(self, needle, tries=8):
        """Moves the selection down until the marked row contains `needle`."""
        for _ in range(tries):
            marked = next((line for line in self.lines() if line.startswith("▌")), "")
            if needle in marked:
                return True
            self.keys("\x1b[B", wait=0.4)
        return False

    def finish(self, expect_rc=0):
        """Waits for iotap to exit and checks that it left the terminal as it found it; returns
        what it printed after leaving the alternate screen."""
        self.pump(10.0)
        try:
            rc = self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = "killed after a timeout"
        self.pump(0.3)
        data = b"".join(self.raw)
        leave = data.rfind(b"\x1b[?1049l")
        after = data[leave + 8 :].decode("utf-8", "replace").replace("\r", "") if leave >= 0 else ""
        self.verdict(rc == expect_rc, f"exit status {rc}, expected {expect_rc}")
        self.verdict(
            b"\x1b[?1049h" in data and leave >= 0 and b"\x1b[?25h" in data,
            "the terminal is restored: alternate screen left, cursor shown",
        )
        print(f"----- {self.name}: output after leaving the alternate screen")
        print(after.strip()[:3000], flush=True)
        return after


def keys(binary, pid, writer, written, copy):
    user = os.environ.get("SUDO_USER", "")

    ui = Ui("A keys", [binary, "--tui", pid])
    ui.pump(2.5)
    ui.show("Files tab, live")
    ui.keys("2")
    ui.show("Network tab")
    if MACOS:
        ui.verdict(has(ui.lines(), "Network: Traffic"), "Network defaults to OS traffic")
        ui.keys("v")
        ui.verdict(has(ui.lines(), "Network: Syscalls"), "v selects syscall accounting")
        ui.keys("v")
        ui.verdict(has(ui.lines(), "Network: Traffic"), "v restores traffic accounting")
    ui.keys("3")
    ui.show("Events tab")
    ui.keys("\x1b[A\x1b[A\x1b[A")
    ui.show("Events after three Up presses")
    ui.keys("1s")
    ui.show("Files sorted by read")
    ui.keys("p")
    before = ui.show("paused")
    ui.pump(1.5)
    later = ui.show("paused, 1.5 s later")
    ui.verdict(
        ui.running() and before[0].startswith(" iotap") and before[0] == later[0],
        "the paused view stays still",
    )
    ui.keys("p", wait=1.5)
    resumed = ui.show("resumed")
    ui.verdict(resumed[0] != later[0], "the view moves again after resuming")
    ui.keys("q", wait=0.1)
    ui.verdict("iotap summary" in ui.finish(), "q prints the summary")

    ui = Ui("B duration", [binary, "--tui", "-d", "2", pid])
    ui.pump(4.5)
    lines = ui.show("after the duration ran out")
    ui.verdict(
        has(lines, "Tracing stopped: the --duration limit was reached."),
        "the UI stays open and says why tracing stopped",
    )
    ui.keys("q", wait=0.1)
    ui.verdict("iotap summary" in ui.finish(), "q prints the summary")

    ui = Ui("C SIGTERM", [binary, "--tui", pid])
    ui.pump(2.5)
    os.kill(ui.proc.pid, signal.SIGTERM)
    ui.verdict("iotap summary" in ui.finish(), "SIGTERM stops it with the summary")

    ui = Ui("D two signals", [binary, "--tui", pid])
    ui.pump(2.5)
    os.kill(ui.proc.pid, signal.SIGTERM)
    os.kill(ui.proc.pid, signal.SIGINT)
    ui.finish(130)

    ui = Ui("E details", [binary, "--tui", writer])
    ui.pump(3.0)
    lines = ui.show("Files tab of a process writing under the home directory")
    rows = [line for line in lines if line.endswith("/data_1.bin")]
    ui.verdict(len(rows) == 1 and "  ~/" in rows[0], "the home directory shows as ~")
    ui.verdict(
        len(rows) == 1 and "a very long directory name" not in rows[0],
        "the long path is cut directory by directory",
    )
    ui.verdict(
        len(rows) == 1 and not any(line.startswith("▌") for line in lines),
        "nothing is selected at first",
    )
    ui.keys("\r")
    lines = ui.show("details")
    ui.verdict(
        any(line.startswith("▌") and line.endswith("/data_1.bin") for line in lines),
        "Enter selects the top row and marks it",
    )
    top = next((i for i, line in enumerate(lines) if "details ─" in line), None)
    read = next((i for i, line in enumerate(lines) if line.startswith(" read ")), None)
    path = "".join(line[1:] for line in lines[top + 1 : read]) if top is not None and read else ""
    ui.verdict(path == written, f"the details show the whole path ({path!r})")
    file_line = next((line for line in lines if line.startswith(" file ")), "")
    ui.verdict(
        "regular file" in file_line and file_line.endswith(" " + user),
        f"the file line names its owner ({file_line.strip()!r})",
    )
    ui.verdict(
        any(line.startswith(" processes ") and writer in line for line in lines),
        "the details name the process",
    )
    ui.verdict(any(line.startswith(" recent ") for line in lines), "the details list recent events")
    if copy == "1":
        mark = len(ui.raw)
        ui.keys("y", wait=1.5)
        # The status line, without the key hints after it.
        status = ui.show("after y")[-1].strip().split("  ")[0]
        said = "copied …/data_1.bin" if MACOS else "asked the terminal to copy …/data_1.bin"
        ui.verdict(said in status, f"the status line says what y did ({status!r})")
        osc = b"\x1b]52;c;" + base64.b64encode(written.encode()) + b"\x1b\\"
        ui.verdict(osc in b"".join(ui.raw[mark:]), "y sends the terminal the path through OSC 52")
    ui.keys("\x1b")
    lines = ui.show("after Esc")
    ui.verdict(
        not has(lines, "details ─") and ui.proc.poll() is None,
        "Esc closes the details and iotap keeps running",
    )
    ui.verdict(any(line.startswith("▌") for line in lines), "the row stays selected after one Esc")
    ui.keys("\x1b")
    lines = ui.show("after a second Esc")
    ui.verdict(
        not any(line.startswith("▌") for line in lines) and ui.proc.poll() is None,
        "a second Esc lets go of the row and iotap keeps running",
    )
    ui.keys("q", wait=0.1)
    ui.verdict("iotap summary" in ui.finish(), "q prints the summary")

    ui = Ui("F quiet", [binary, "-q", "--tui", pid])
    ui.pump(2.5)
    lines = ui.show("quiet UI")
    tabs = next((line for line in lines if "1 Files" in line), "")
    ui.verdict("2 Network" in tabs and "Events" not in tabs, "-q leaves out the Events tab")
    ui.keys("3")
    lines = ui.show("after pressing 3")
    ui.verdict(has(lines, " CALLS "), "3 does not leave the tables")
    ui.keys("r", wait=1.5)
    lines = ui.show("after r")
    ui.verdict(lines[0].endswith("since reset"), "r resets the view")
    ui.keys("q", wait=0.1)
    ui.verdict("iotap summary" in ui.finish(), "q prints the summary")


def names(binary, curl, peer, ip, name, slow):
    server_row = f"tcp {name}:443"
    address_row = f"tcp {ip}:443"

    ui = Ui("G names from the start", [binary, "--tui", "--resolve", curl])
    ui.pump(3.0)
    ui.keys("2", wait=1.5)
    lines = ui.show("Network tab")
    ui.verdict(has(lines, server_row), f"the Network tab shows {server_row}")
    ui.verdict("n addresses" in lines[-1], "the footer offers addresses")
    ui.keys("\r", wait=1.0)
    lines = ui.show("details")
    ui.verdict(f" {address_row}" in lines, "the details keep the address")
    host = next((line for line in lines if line.startswith(" host ")), "")
    ui.verdict(host.endswith(f" {name}"), f"the details name the host ({host.strip()!r})")
    ui.keys("\x1b", wait=0.5)
    ui.keys("3", wait=1.0)
    lines = ui.show("Events tab")
    ui.verdict(any(line.endswith(f"{name}:443") for line in lines), "events name the server")
    ui.keys("n", wait=1.0)
    lines = ui.show("Events tab, after n")
    ui.verdict(any(line.endswith(f"{ip}:443") for line in lines), "n shows the address in events")
    ui.verdict(
        any(line.endswith(f"{ip}:443") for line in lines) and not has(lines[1:-1], name),
        "and no name",
    )
    ui.keys("n", wait=0.5)
    ui.keys("q", wait=0.1)
    ui.verdict(f" {server_row}" in ui.finish(), "the summary after quitting names the server")

    ui = Ui("H names on request", [binary, "--tui", curl])
    ui.pump(2.5)
    ui.keys("2", wait=1.0)
    lines = ui.show("Network tab")
    ui.verdict(has(lines, address_row) and not has(lines, name), "addresses by default")
    ui.verdict("n names" in lines[-1], "the footer offers names")
    ui.keys("n", wait=1.5)
    lines = ui.show("after n")
    ui.verdict(has(lines, server_row), "n names the server")
    ui.verdict(lines[-1].startswith(" showing host names"), "the status line says so")
    ui.keys("n", wait=0.8)
    lines = ui.show("after a second n")
    ui.verdict(
        has(lines, address_row) and not has(lines[1:-1], name), "a second n shows the address"
    )
    ui.keys("q", wait=0.1)
    after = ui.finish()
    ui.verdict(f" {address_row}" in after and name not in after, "the summary does as the UI did")

    ui = Ui("I slow lookups", [binary, "--tui", "--resolve", peer])
    ui.pump(2.0)
    ui.keys("2", wait=1.0)
    if MACOS:
        ui.keys("v")  # These sockets exercise failed calls, not transferred traffic.
    first = ui.show("Network tab")
    ui.verdict(has(first, "udp one.one.one.one:9"), "a quick name shows")
    ui.verdict(has(first, f"udp {slow}:9"), "the slow address shows as itself meanwhile")
    ui.pump(2.0)
    later = ui.show("2 s later")
    ui.verdict(first[0] != later[0], "frames go on while a lookup is under way")
    ui.verdict(ui.select(slow), "the slow row can be selected")
    ui.keys("\r", wait=0.8)
    lines = ui.show("details of the slow row")
    host = next((line for line in lines if line.startswith(" host ")), "")
    ui.verdict(
        any(state in host for state in ("looking up…", "lookup failed", "no name found")),
        f"the details say how its lookup stands ({host.strip()!r})",
    )
    running, started = ui.running(), time.monotonic()
    ui.keys("q", wait=0.1)
    after = ui.finish()
    took = time.monotonic() - started
    ui.verdict(
        running and took < 4.0,
        f"quitting took {took:.1f} s, the summary waiting at most 2 s for names",
    )
    ui.verdict(
        " udp one.one.one.one:9" in after and f" udp {slow}:9" in after,
        "the summary names what it can",
    )


def interfaces(binary, pid, iface, loopback, far):
    ui = Ui("J interfaces", [binary, "--tui", pid])
    ui.pump(2.5)
    if MACOS:
        ui.keys("2v1")  # This scenario checks the interface attributed to each syscall.
    lines = ui.show("Files tab")
    ui.verdict(
        has(lines, "FILE READ") and not has(lines, "INTERFACE"), "no interface table at first"
    )
    ui.verdict("i interfaces" in lines[-1], "the footer offers it")
    ui.keys("i", wait=1.5)
    lines = ui.show("after i")
    header = next((line for line in lines if " INTERFACE " in line), "")
    rates = next((line for line in lines if "FILE READ" in line), "")
    ui.verdict(
        bool(header) and len(header) == len(rates),
        "i shows the interface table, its columns in line with the rates",
    )
    ui.verdict(any(line.startswith(f" {iface} ") for line in lines), f"with a row for {iface}")
    ui.verdict(any(line.startswith(f" {loopback} ") for line in lines), f"and one for {loopback}")
    ui.keys("2", wait=1.0)
    ui.keys("g", wait=0.4)
    ui.verdict(ui.select(f"udp {far}:9", tries=20), f"the socket connected to {far} is selected")
    ui.keys("\r", wait=0.8)
    lines = ui.show("details")
    line = next((line for line in lines if line.startswith(" interface ")), "")
    ui.verdict(line.endswith(f" {iface}"), f"the details name its interface ({line.strip()!r})")
    ui.keys("\x1b", wait=0.3)
    ui.keys("i", wait=0.8)
    lines = ui.show("after a second i")
    ui.verdict(not has(lines, "INTERFACE") and has(lines, "FILE READ"), "a second i hides it")
    ui.keys("q", wait=0.1)
    after = ui.finish()
    ui.verdict(f"\n    {iface} " in after, "the summary lists the network I/O of each interface")


if __name__ == "__main__":
    scenario, args = sys.argv[1], sys.argv[2:]
    {"keys": keys, "names": names, "interfaces": interfaces}[scenario](*args)
