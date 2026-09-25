"""What every live check shares: the run and its verdicts, the processes a check starts, as the
user or as root through sudo, and readers of iotap's output.

Root comes only from the approval sudo holds for the terminal the run started in. Every root step
goes through `sudo -n`, which fails rather than asks.
"""

import contextlib
import json
import os
import platform
import re
import select
import socket
import subprocess
import sys
import time

DEVNULL = subprocess.DEVNULL
PIPE = subprocess.PIPE

MACOS = platform.system() == "Darwin"
LINUX = platform.system() == "Linux"
HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAMS = os.path.join(HERE, "programs.py")


class Check:
    """One numbered check of README.md's "Checking against a live kernel", for one system."""

    def __init__(self, system, number, title, function):
        self.system = system
        self.number = number
        self.title = title
        self.function = function


CHECKS = []


def check(system, number, title):
    """Registers the decorated function as check `number` of `system`, "Darwin" or "Linux"."""

    def register(function):
        CHECKS.append(Check(system, number, title, function))
        return function

    return register


class Run:
    """A run of the live checks: where its files go, what it found, and what it started."""

    def __init__(self, binary, out, work, log):
        self.bin = binary
        # Outputs, kept for reading after the run.
        self.out = out
        # A directory with a short path for the files and sockets the traced programs use.
        self.work = work
        self.log = log
        self.number = None
        self.verdicts = []
        self.processes = []

    def say(self, text=""):
        print(text, flush=True)
        self.log.write(text + "\n")
        self.log.flush()

    def expect(self, ok, what, detail=""):
        """Records whether an expectation held; returns `ok`."""
        verdict = "PASS" if ok else "FAIL"
        self.verdicts.append((self.number, verdict, what))
        self.say(f"  {verdict}  {what}" + (f"  [{detail}]" if detail else ""))
        return bool(ok)

    def skip(self, what, why):
        self.verdicts.append((self.number, "SKIP", what))
        self.say(f"  SKIP  {what}  [{why}]")

    def note(self, text):
        self.say(f"  NOTE  {text}")

    def file(self, name):
        """The path of this check's output file `name`."""
        return os.path.join(self.out, f"{self.number}-{name}")

    def read(self, name):
        try:
            with open(self.file(name), errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def _spawn(self, argv, stdin, stdout, stderr, as_root):
        """Starts `argv`; an output named by a string goes to that file of this check's."""
        with contextlib.ExitStack() as files:

            def sink(target):
                if isinstance(target, str):
                    return files.enter_context(open(self.file(target), "wb"))
                return target

            proc = subprocess.Popen(
                [str(a) for a in argv], stdin=stdin, stdout=sink(stdout), stderr=sink(stderr)
            )
        self.processes.append((proc, as_root))
        return proc

    def start(self, argv, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL):
        """Starts `argv` as the user. The check stops it when it ends, if it still runs."""
        return self._spawn(argv, stdin, stdout, stderr, as_root=False)

    def root_start(self, argv, stdout=DEVNULL, stderr=DEVNULL):
        """Starts `argv` as root through `sudo -n`, in the run's process group."""
        return self._spawn(["sudo", "-n", *argv], DEVNULL, stdout, stderr, as_root=True)

    def root_wait(self, proc, timeout):
        """Waits for a process of `root_start`; stops it after `timeout` seconds and returns None."""
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.note(f"{' '.join(proc.args[2:])[:120]} ran past {timeout} s; stopping it")
            self.stop_root(proc)
            return None

    def root(self, argv, stdout=DEVNULL, stderr=DEVNULL, timeout=60):
        """Runs `argv` as root and returns its exit status, or None if it had to be stopped."""
        return self.root_wait(self.root_start(argv, stdout, stderr), timeout)

    def root_shell(self, script, *args, timeout=60):
        """Runs `script` in a root shell with `args` as $1, $2 and on; returns its exit status.
        A root shell can signal the iotap it started, which the run cannot through sudo."""
        return self.root(["sh", "-c", script, "sh", *args], timeout=timeout)

    def iotap(self, *args, stdout=DEVNULL, stderr=DEVNULL, timeout=60):
        return self.root([self.bin, *args], stdout, stderr, timeout)

    def started(self, name, timeout=10):
        """Waits until iotap's stderr, this check's file `name`, says that tracing began."""
        return wait_for(lambda: "iotap: tracing" in self.read(name), timeout)

    def signal_elsewhere(self, pid, sig):
        """Sends `sig` to `pid` from a process group of its own. sudo passes a signal on to the
        command it runs only when it comes from outside its own process group, which is the
        run's."""
        subprocess.run(["kill", f"-{sig}", str(pid)], preexec_fn=os.setpgrp, check=False)

    def interrupt(self, proc, signals=("INT", "INT", "TERM"), wait=10):
        """Stops a process of `root_start` with each signal in turn until it exits; returns its
        exit status, or None if it had to be killed."""
        for sig in signals:
            if proc.poll() is not None:
                break
            self.signal_elsewhere(proc.pid, sig)
            try:
                proc.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                self.note(f"still running {wait} s after SIG{sig}")
        if proc.poll() is None:
            self.stop_root(proc)
            return None
        return proc.returncode

    def stop(self, proc):
        """Stops a process this run started as the user, and reaps it."""
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_root(self, proc):
        """Stops what sudo runs for a process of `root_start`: TERM, then KILL."""
        for sig in ("TERM", "KILL"):
            if proc.poll() is not None:
                return
            below = descendants(proc.pid)
            if below:
                subprocess.run(
                    ["sudo", "-n", "kill", f"-{sig}", *map(str, below)],
                    stdin=DEVNULL,
                    stdout=DEVNULL,
                    stderr=DEVNULL,
                    check=False,
                )
            try:
                proc.wait(timeout=3)
                return
            except subprocess.TimeoutExpired:
                pass
        # sudo runs as the user who started it, who may kill it.
        proc.kill()
        proc.wait()

    def stop_all(self):
        """Stops every process the run started that still runs, the latest first."""
        for proc, as_root in reversed(self.processes):
            if as_root:
                self.stop_root(proc)
            else:
                self.stop(proc)
        self.processes.clear()


def descendants(pid):
    """Pids of every process below `pid`."""
    listing = subprocess.run(
        ["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, check=False
    ).stdout
    children = {}
    for line in listing.splitlines():
        child, parent = map(int, line.split())
        children.setdefault(parent, []).append(child)
    found, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child)
    return found


def command_name(pid):
    """The kernel's name for `pid`, as ps shows it."""
    name = subprocess.run(
        ["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    return os.path.basename(name.stdout.strip())


def wait_for(ready, timeout, step=0.05):
    """Calls `ready` until it returns true or `timeout` seconds pass; returns its last answer."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if ready():
            return True
        time.sleep(step)
    return bool(ready())


def read_lines(pipe, count, timeout):
    """Up to `count` lines from `pipe`, waiting at most `timeout` seconds in all."""
    lines, rest, end = [], b"", time.monotonic() + timeout
    while len(lines) < count:
        left = end - time.monotonic()
        if left <= 0 or not select.select([pipe], [], [], left)[0]:
            break
        chunk = os.read(pipe.fileno(), 65536)
        if not chunk:
            break
        *done, rest = (rest + chunk).split(b"\n")
        lines.extend(line.decode(errors="replace") for line in done)
    return lines[:count]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(run, directory):
    """Serves `directory` over HTTP on 127.0.0.1; returns the server and its port."""
    port = free_port()
    server = run.start(
        [sys.executable, "-m", "http.server", port, "--bind", "127.0.0.1", "--directory", directory]
    )

    def listening():
        with socket.socket() as s:
            return s.connect_ex(("127.0.0.1", port)) == 0

    wait_for(listening, 10)
    return server, port


def renamer(name, after):
    """A program that writes to stdout and, `after` seconds from its start, takes `name` as its
    first argument. perl's `$0 =` rewrites argv[0] in place; on Linux it renames the process
    too, and on macOS it cannot."""
    script = (
        "($name, $wait) = @ARGV; @ARGV = (); sleep $wait; $0 = $name; $| = 1;"
        ' while (1) { print "y\\n" x 512; select(undef, undef, undef, 0.02) }'
    )
    return ["perl", "-e", script, name, str(after)]


SUMMARY = "iotap summary:"


def summary(text):
    """The summary part of iotap's text output; empty if there is none."""
    at = text.find(SUMMARY)
    return text[at:] if at >= 0 else ""


def before_summary(text):
    at = text.find(SUMMARY)
    return text[:at] if at >= 0 else text


def traced_for(text):
    """The seconds the summary says tracing lasted, or None."""
    m = re.search(r"traced for (\d+\.\d) s", text)
    return float(m.group(1)) if m else None


def written_calls(text):
    """The file write calls the summary's totals count, or None."""
    m = re.search(r"^  files +read .*, written .* \((\d+) calls?\)$", text, re.MULTILINE)
    return int(m.group(1)) if m else None


EVENT = re.compile(
    r"^(\d\d:\d\d:\d\d\.\d{6})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"(-|\d+\.\d{3} ms)  (.*)$"
)


def event_lines(text):
    """The event lines of text output, as dicts of their columns."""
    events = []
    for line in text.splitlines():
        m = EVENT.match(line)
        if m:
            _, pid, op, fd, requested, result, latency, target = m.groups()
            events.append(
                {
                    "pid": int(pid),
                    "op": op,
                    "fd": fd,
                    "requested": requested,
                    "result": result,
                    "latency": latency,
                    "target": target,
                }
            )
    return events


BYTES = r"\d+(?:\.\d)? (?:B|KiB|MiB|GiB|TiB|PiB)"
ROW = re.compile(rf"^ *({BYTES}) +(\d+) +({BYTES}) +(\d+) +(\d+)  (.+)$")


def summary_rows(text):
    """The rows of the summary's tables, as (read or received, calls, written or sent, calls,
    failed, target)."""
    return [m.groups() for m in map(ROW.match, summary(text).splitlines()) if m]


def row(text, target):
    """The summary row of `target`, or None."""
    return next((r for r in summary_rows(text) if r[5] == target), None)


def json_lines(path):
    """The objects of a JSON Lines file; a line that does not parse is {"type": "UNPARSABLE"}."""
    objects = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    objects.append(json.loads(line))
                except json.JSONDecodeError:
                    objects.append({"type": "UNPARSABLE", "line": line[:200]})
    except FileNotFoundError:
        pass
    return objects
