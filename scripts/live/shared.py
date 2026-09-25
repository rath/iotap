"""Parts of the live checks that run on macOS and Linux alike."""

import filecmp
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time

from harness import (
    DEVNULL,
    HERE,
    LINUX,
    MACOS,
    PROGRAMS,
    SUMMARY,
    before_summary,
    renamer,
    summary,
    traced_for,
    wait_for,
    written_calls,
)

# A server with large test files, whose IPv4 address has a host name; its IPv6 address has none.
SERVER = "proof.ovh.net"
# An address whose reverse lookup takes seconds: 30 on macOS and 10 on Ubuntu when this was
# written. The checks hold whether or not it is slow at the moment.
SLOW = "93.184.215.14"


def dropped(run, *options):
    """Stops iotap for two seconds from a root shell, so that the kernel drops records, and
    compares how many calls it counted with a run that was not stopped."""
    yes = run.start(["yes"])
    time.sleep(0.5)
    run.iotap("-q", "-d", "3", *options, yes.pid, stdout="base.out", stderr="base.err")
    script = (
        '"$1" -q -d 8 ' + " ".join(map(shlex.quote, options)) + ' "$2" > "$3" 2> "$4" &'
        ' p=$!; sleep 1.5; kill -STOP "$p"; sleep 2; kill -CONT "$p"; wait "$p"'
    )
    rc = run.root_shell(script, run.bin, yes.pid, run.file("stopped.out"), run.file("stopped.err"))
    out, err = run.read("stopped.out"), run.read("stopped.err")
    run.expect("the kernel dropped trace records" in err, "the notice of dropped records")
    run.expect(
        "Warning: the kernel dropped trace records" in summary(out), "and the summary's warning"
    )
    seconds = traced_for(out)
    run.expect(
        rc == 0 and seconds is not None and seconds >= 7.8,
        "tracing goes on to the end",
        f"exit status {rc}, traced for {seconds} s",
    )
    base, base_seconds, calls = (
        written_calls(run.read("base.out")),
        traced_for(run.read("base.out")),
        written_calls(out),
    )
    if base and base_seconds and calls:
        rate = base / base_seconds
        # Stopped for 2 of 8 s: more than 5 s worth of calls means counting went on afterwards.
        run.expect(
            calls >= rate * 5,
            "calls are counted after the loss",
            f"{calls} calls, {calls / rate:.1f} s worth at {rate:,.0f} a second",
        )
    else:
        run.expect(False, "calls are counted after the loss", f"{base} {base_seconds} {calls}")


def replay(run, workload):
    """Records `workload` in JSON and in text, and replays each recording. Outputs that match
    are removed, being large."""
    proc = run.start(workload)
    time.sleep(0.5)
    for mode, options in (("json", ["--json"]), ("text", [])):
        recording = run.file(f"{mode}.iotaprec")
        rc = run.iotap(
            *options,
            "-d",
            "1",
            "--record",
            recording,
            proc.pid,
            stdout=f"{mode}.live",
            stderr=f"{mode}.live.err",
        )
        with open(run.file(f"{mode}.replay"), "wb") as out:
            again = subprocess.run(
                [run.bin, *options, "--replay", recording], stdout=out, stderr=DEVNULL, check=False
            ).returncode
        live = run.read(f"{mode}.live")
        whole = '"type":"summary"' in live or SUMMARY in live
        same = filecmp.cmp(run.file(f"{mode}.live"), run.file(f"{mode}.replay"), shallow=False)
        if run.expect(
            rc == 0 and again == 0 and whole and same,
            f"the replay of the {mode} recording is identical to the live output",
            f"{live.count(chr(10))} lines",
        ):
            for name in (recording, run.file(f"{mode}.live"), run.file(f"{mode}.replay")):
                os.remove(name)


def argv0_names(run):
    """Names that only argv[0] or a link gives a process."""
    yes = shutil.which("yes")
    tag = os.getpid()
    name = f"iotap-argv0-{tag}"
    # Longer than the 15 characters Linux keeps, whatever the pid.
    link_name = f"iotap-linked-yes-{tag}"
    link = os.path.join(run.work, link_name)
    os.symlink(yes, link)

    first = run.start(["bash", "-c", f'exec -a "$0" {yes}', name])
    time.sleep(0.5)
    run.iotap("-q", "-d", "2", name, stdout="argv0.out", stderr="argv0.err")
    err = run.read("argv0.err")
    run.expect(
        f"tracing {first.pid} (yes)" in err,
        "a name only argv[0] holds finds its process",
        err.splitlines()[0] if err else "",
    )
    run.expect("/dev/null" in summary(run.read("argv0.out")), "and its writes are seen")

    linked = run.start([link])
    time.sleep(0.5)
    run.iotap("-q", "-d", "2", link_name, stdout="link.out", stderr="link.err")
    err = run.read("link.err")
    # macOS names the process after the file the link leads to; Linux after the link, cut short.
    kernel = "yes" if MACOS else link_name[:15]
    run.expect(
        f"tracing {linked.pid} ({kernel})" in err,
        f"a link's name finds the process started through it, which the kernel calls {kernel}",
        err.splitlines()[0] if err else "",
    )
    run.expect("/dev/null" in summary(run.read("link.out")), "and its writes are seen")

    iotap = run.root_start(
        [run.bin, "-q", "-d", "7", link_name], stdout="follow.out", stderr="follow.err"
    )
    run.started("follow.err")
    time.sleep(0.5)
    later = run.start([link])
    by_exec = run.start(["bash", "-c", f'exec -a "$0" {yes}', link_name])
    soon = run.start(renamer(link_name, 1))
    late = run.start(renamer(link_name, 4))
    rc = run.root_wait(iotap, 20)
    said = run.read("follow.err")
    for proc, what in (
        (later, "a second process started through the link"),
        (by_exec, "a process given the name by exec -a"),
        (soon, "a process that takes the name in argv[0] a second after it starts"),
    ):
        run.expect(f"now tracing {proc.pid} (" in said, f"{what} is followed")
    if MACOS:
        # Past the two seconds in which a new process is checked again, nothing changes on macOS.
        run.expect(
            rc == 0 and f"now tracing {late.pid} (" not in said,
            "one that takes it four seconds after it starts is not, as README.md says",
        )
    else:
        run.expect(
            rc == 0 and f"now tracing {late.pid} (" in said,
            "one that takes it four seconds after it starts is followed, as Linux renames it",
        )

    run.iotap("-q", "-d", "1", link_name[:-1], stderr="part.err")
    err = run.read("part.err")
    run.expect(
        f"similar: {link_name} (" in err,
        "part of a name offers the processes that hold it",
        err.strip()[:200],
    )

    if MACOS:
        # Claude Code's native install starts it through a link to a file named after its
        # version, which names the process.
        pgrep = subprocess.run(
            ["pgrep", "-a", "-x", "claude"], capture_output=True, text=True, check=False
        )
        wanted = sorted(int(pid) for pid in pgrep.stdout.split())
        if not wanted:
            run.skip("the claude processes pgrep -x finds", "no claude process runs")
            return
        run.iotap("-q", "-d", "1", "claude", stderr="claude.err")
        first_line = (run.read("claude.err").splitlines() or [""])[0]
        found = sorted(int(pid) for pid in re.findall(r"(\d+) \(", first_line))
        run.expect(
            found == wanted,
            "claude finds the processes pgrep -x claude finds",
            f"pgrep {wanted}, iotap {found}",
        )


def host_names(run):
    """Host names in the summary, a replay and the terminal UI, and how long lookups hold up
    the summary."""
    try:
        ip = socket.getaddrinfo(SERVER, 443, socket.AF_INET)[0][4][0]
        name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
    except OSError as err:
        run.skip("host names", f"{SERVER} or the name of its address cannot be looked up: {err}")
        return
    run.note(f"{SERVER} is {ip}, whose reverse lookup names {name}")
    curl = run.start(
        [
            "curl",
            "-4",
            "-s",
            "-o",
            "/dev/null",
            "--limit-rate",
            "150k",
            f"https://{SERVER}/files/100Mb.dat",
        ]
    )
    peer = run.start(
        [sys.executable, PROGRAMS, "peers", "1.1.1.1", "192.0.2.1", SLOW], stderr="peers.err"
    )
    time.sleep(1.5)

    rc_plain = run.iotap("-q", "-d", "2", curl.pid, stdout="plain.out", stderr="plain.err")
    recording = run.file("names.iotaprec")
    rc_named = run.iotap(
        "-d",
        "2",
        "--resolve",
        "--record",
        recording,
        curl.pid,
        stdout="named.out",
        stderr="named.err",
    )
    plain, named = summary(run.read("plain.out")), summary(run.read("named.out"))
    events = before_summary(run.read("named.out"))
    run.expect(
        rc_plain == 0 and f" tcp {ip}:443" in plain,
        "without --resolve the summary shows the address",
    )
    run.expect(rc_named == 0 and f" tcp {name}:443" in named, "with --resolve it names the server")
    run.expect(bool(named) and f" tcp {ip}:443" not in named, "and leaves out its address")
    run.expect(f"-> {ip}:443" in events, "event lines keep the address")
    run.expect(f"-> {ip}:443" in events and name not in events, "and name no host")

    def replayed(*options):
        return subprocess.run(
            [run.bin, "-q", *options, "--replay", recording],
            capture_output=True,
            text=True,
            check=False,
        )

    run.expect(f" tcp {ip}:443" in replayed().stdout, "the replay shows the address")
    run.expect(
        f" tcp {name}:443" in replayed("--resolve").stdout,
        "the replay with --resolve names the server",
    )
    refused = subprocess.run(
        [run.bin, "--json", "--resolve", "--replay", recording],
        capture_output=True,
        text=True,
        check=False,
    )
    run.expect(
        refused.returncode != 0 and "cannot be used with" in refused.stderr,
        "--json refuses --resolve",
    )

    t0 = time.monotonic()
    rcs = [run.iotap("-q", "-d", "3", peer.pid, stdout="peers-plain.out")]
    t1 = time.monotonic()
    rcs.append(run.iotap("-q", "-d", "3", "--resolve", peer.pid, stdout="peers-named.out"))
    t2 = time.monotonic()
    named = run.read("peers-named.out")
    run.expect(
        rcs == [0, 0] and (t2 - t1) - (t1 - t0) <= 2.5,
        "names hold up the summary by at most 2.5 s",
        f"3 s of tracing took {t1 - t0:.2f} s without names, {t2 - t1:.2f} s with them",
    )
    run.expect(" udp one.one.one.one:9" in named, "1.1.1.1 is named")
    run.expect(" udp 192.0.2.1:9" in named, "192.0.2.1, which has no name, shows as itself")
    run.expect(f" udp {SLOW}:9" in named, f"{SLOW}, whose lookup is slow, shows as itself")

    tui(run, "names", run.bin, curl.pid, peer.pid, ip, name, SLOW)


def tui(run, scenario, *args):
    """Runs a scenario of tui.py as root and takes its verdicts; False if pyte is missing."""
    try:
        import pyte
        import wcwidth
    except ImportError:
        run.skip(
            f"the terminal UI ({scenario})",
            f"{sys.executable} lacks pyte and wcwidth: python3 -m pip install pyte",
        )
        return False
    # sudo drops PYTHONPATH, so tell root's Python where these came from.
    paths = sorted({os.path.dirname(os.path.dirname(m.__file__)) for m in (pyte, wcwidth)})
    rc = run.root(
        [
            "env",
            "PYTHONPATH=" + os.pathsep.join(paths),
            sys.executable,
            os.path.join(HERE, "tui.py"),
            scenario,
            *args,
        ],
        stdout=f"tui-{scenario}.txt",
        stderr=f"tui-{scenario}.err",
        timeout=300,
    )
    for line in run.read(f"tui-{scenario}.txt").splitlines():
        m = re.match(r"^  (PASS|FAIL)  (.*)$", line)
        if m:
            run.expect(m.group(1) == "PASS", m.group(2))
    run.expect(
        rc == 0, f"the driver finished ({scenario})", run.read(f"tui-{scenario}.err").strip()[-300:]
    )
    return True


class Clipboard:
    """The Mac's pasteboard, saved to put back after the copy check. Only text can be put back,
    so `saved` is None when it holds anything else."""

    TEXT = frozenset({"«class utf8»", "«class ut16»", "string", "Unicode text"})

    def __init__(self):
        info = subprocess.run(
            ["osascript", "-e", "clipboard info"], capture_output=True, text=True, check=False
        ).stdout
        kinds = {kind.strip() for kind in info.split(",")} - {""}
        self.other = sorted(kind for kind in kinds - self.TEXT if not kind.isdigit())
        self.saved = None if self.other else self.text()

    @staticmethod
    def text():
        return subprocess.run(["pbpaste"], capture_output=True, check=False).stdout

    def restore(self):
        subprocess.run(["pbcopy"], input=self.saved, check=False)
        return self.text() == self.saved


def terminal_ui(run):
    """Keys, signals, details and copying in the terminal UI."""
    yes = run.start(["yes"])
    cache = os.path.join(
        os.path.expanduser("~"), "Library/Caches" if MACOS else ".cache", "iotap-live"
    )
    written = os.path.join(
        cache,
        "a very long directory name",
        "another long directory name",
        "still going deeper",
        "한글 폴더",
        "data_1.bin",
    )
    writer = run.start([sys.executable, PROGRAMS, "home-writer", written])
    clipboard = Clipboard() if MACOS else None
    # On Linux, y only asks the terminal to copy, and the terminal is tui.py.
    copy = LINUX or clipboard.saved is not None
    try:
        if not run.expect(
            wait_for(lambda: os.path.exists(written), 5),
            "the program writing under the home directory runs",
        ):
            return
        if not tui(run, "keys", run.bin, yes.pid, writer.pid, written, "1" if copy else "0"):
            return
        if MACOS and copy:
            # What else it holds is the user's, and stays out of the log.
            pasted = Clipboard.text().decode(errors="replace")
            run.expect(
                pasted == written,
                "the pasteboard holds the path iotap copied as root",
                "" if pasted == written else f"it holds {len(pasted)} other characters",
            )
        elif MACOS:
            run.skip("copying", f"the clipboard holds more than text: {', '.join(clipboard.other)}")
    finally:
        if MACOS and copy:
            run.expect(clipboard.restore(), "the clipboard holds again what it held before")
        run.stop(writer)
        shutil.rmtree(cache, ignore_errors=True)
