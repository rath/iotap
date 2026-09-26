"""Parts of the live checks that run on macOS and Linux alike."""

import filecmp
import json
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
    descendants,
    json_lines,
    renamer,
    row,
    summary,
    traced_for,
    wait_for,
)

# A server with large test files, whose IPv4 address has a host name; its IPv6 address has none.
SERVER = "proof.ovh.net"
# An address whose reverse lookup takes seconds: 30 on macOS and 10 on Ubuntu when this was
# written. The checks hold whether or not it is slow at the moment.
SLOW = "93.184.215.14"
# A documentation address (TEST-NET-1), reached over the default route, to which the checks
# send nothing.
FAR = "192.0.2.1"


def dropped(run, *options):
    """Stops iotap for two seconds from a root shell while `yes` floods, so that the kernel drops
    records, then kills `yes` and has a program write a known number of times, each of which
    iotap must count. The flood's own count cannot show what iotap missed: `yes` can make calls
    twice as fast in one run as in another, depending on the cores iotap's reader runs on."""
    size, writes = 1 << 20, 4096
    work = os.path.join(run.work, "dropped")
    os.makedirs(work)
    # As iotap names the file: macOS resolves /tmp to /private/tmp.
    work = os.path.realpath(work)
    yes = run.start(["yes"])
    writer = run.start([sys.executable, PROGRAMS, "paced", work, size, writes], stderr="paced.err")
    if not run.expect(
        wait_for(lambda: os.path.exists(os.path.join(work, "ready")), 10), "the writer starts"
    ):
        return
    script = (
        '"$1" -q -d 8 ' + " ".join(map(shlex.quote, options)) + ' "$2" "$3" > "$4" 2> "$5" &'
        ' p=$!; sleep 1.5; kill -STOP "$p"; sleep 2; kill -CONT "$p"; sleep 0.5;'
        # Then only the writer's calls are traced, which come too slowly to fill any buffer.
        ' kill "$2"; : > "$6"; wait "$p"'
    )
    rc = run.root_shell(
        script,
        run.bin,
        yes.pid,
        writer.pid,
        run.file("stopped.out"),
        run.file("stopped.err"),
        os.path.join(work, "go"),
    )
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
    written = row(out, os.path.join(work, "paced"))
    run.expect(
        (written or ())[2:5] == ("1.0 MiB", str(writes), "0"),
        f"all {writes} writes made after the loss are counted",
        str(written),
    )


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


def route_interface(address):
    """The interface of the route to `address`, or None."""
    if MACOS:
        argv, pattern = ["route", "-n", "get", address], r"^\s*interface: (\S+)$"
    else:
        argv, pattern = ["ip", "route", "get", address], r"\bdev (\S+)"
    listing = subprocess.run(argv, capture_output=True, text=True, check=False).stdout
    m = re.search(pattern, listing, re.MULTILINE)
    return m.group(1) if m else None


def interfaces(run):
    """The interface of each way a socket's I/O can go, -i and the terminal UI's table."""
    far = route_interface(FAR)
    if far is None:
        run.skip("network interfaces", f"no route to {FAR}")
        return
    loopback = "lo0" if MACOS else "lo"
    run.note(f"the route to {FAR} goes over {far}")
    work = os.path.join(run.work, "interfaces")
    os.makedirs(work)
    program = run.start(
        [sys.executable, PROGRAMS, "interfaces", work, FAR], stderr="interfaces.program.err"
    )
    if not run.expect(
        wait_for(lambda: os.path.exists(os.path.join(work, "ready")), 10), "the program runs"
    ):
        return
    with open(os.path.join(work, "own")) as f:
        own = f.read()

    recording = run.file("interfaces.iotaprec")
    rc = run.iotap(
        "--json",
        "-d",
        "2",
        "--record",
        recording,
        program.pid,
        stdout="interfaces.json",
        stderr="interfaces.err",
    )
    traced = json_lines(run.file("interfaces.json"))
    events = [o for o in traced if o.get("type") == "event"]
    total = next((o for o in traced if o.get("type") == "summary"), {})
    run.expect(rc == 0 and bool(events), "iotap traces the program", f"exit status {rc}")
    ways = [
        (1111, far, f"a receive on a socket connected to {FAR} goes over {far}"),
        (1222, loopback, "a send to 127.0.0.1 goes over the loopback interface"),
        (1333, loopback, f"a send to the host's own address {own} goes over it too"),
        (1444, None, "a send over a socketpair goes over none"),
        (1555, "?", "a send from a socket bound to every address goes over one iotap cannot tell"),
        (1777, loopback, "a send to ::1 goes over the loopback interface"),
    ]
    no_v6 = "no ::1" in run.read("interfaces.program.err")
    for size, wanted, what in ways:
        if size == 1777 and no_v6:
            run.skip(what, "the host has no ::1")
            continue
        seen = {e.get("interface", "MISSING") for e in events if e.get("requested") == size}
        run.expect(seen == {wanted}, what, f"{sorted(map(str, seen))}")
    for side in ("read", "write"):
        by_interface = sum(i.get(f"{side}_bytes", 0) for i in total.get("interfaces", []))
        whole = total.get("totals", {}).get(f"net_{side}", {}).get("bytes")
        run.expect(
            bool(events) and by_interface == whole,
            f"the summary's interfaces add up to the network total {side}",
            f"{by_interface} of {whole}",
        )

    with open(run.file("interfaces.replay"), "wb") as out:
        again = subprocess.run(
            [run.bin, "--json", "--replay", recording], stdout=out, stderr=DEVNULL, check=False
        ).returncode
    run.expect(
        again == 0
        and bool(events)
        and filecmp.cmp(run.file("interfaces.json"), run.file("interfaces.replay"), shallow=False),
        "the replay of the recording is identical to the live output",
    )

    rc = run.iotap(
        "--json", "-d", "2", "-i", far, program.pid, stdout="only.json", stderr="only.err"
    )
    only = json_lines(run.file("only.json"))
    kept = [o for o in only if o.get("type") == "event"]
    left_out = next((o for o in only if o.get("type") == "summary"), {})
    run.expect(
        rc == 0 and bool(kept) and all(e.get("interface") == far for e in kept),
        f"-i {far} reports only the I/O over {far}",
        f"{len(kept)} events",
    )
    run.expect(
        bool(kept) and left_out.get("unknown_interface_calls", 0) > 0,
        "and counts the calls over an interface iotap cannot tell",
        str(left_out.get("unknown_interface_calls")),
    )
    run.expect(
        f"reporting only network I/O over {far};" in run.read("only.err"),
        "the startup line says so",
    )

    rc = run.iotap("-q", "-d", "2", "-i", loopback, program.pid, stdout="lo.out", stderr="lo.err")
    text = summary(run.read("lo.out"))
    listed = rf"^    {re.escape(loopback)} +received \S+ \S+ \(\d+ calls?\), sent "
    run.expect(
        rc == 0 and re.search(listed, text, re.MULTILINE) and "Files (" not in text,
        f"with -q -i {loopback}, the totals list {loopback} and there is no Files table",
    )
    run.expect("Note: --interface left out " in text, "the summary notes the calls -i left out")

    rc = run.iotap("-q", "-d", "1", "-i", "nosuch0", program.pid, stderr="nosuch.err")
    err = run.read("nosuch.err")
    run.expect(
        rc == 0 and "iotap: tracing" in err and "no network interface is named 'nosuch0'" in err,
        "a name no interface has is warned of, and iotap goes on",
        err.strip().replace("\n", " | ")[:300],
    )
    if far.upper() != far:
        rc = run.iotap("-q", "-d", "1", "-i", far.upper(), program.pid, stderr="case.err")
        run.expect(
            rc == 0 and f"did you mean '{far}'?" in run.read("case.err"),
            "a name in another case is offered the right one",
        )

    tui(run, "interfaces", run.bin, program.pid, far, loopback, FAR)


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


def children(run):
    """A process tree traced with -f, and this run traced with -f, which iotap descends from."""
    # A directory of its own, free of the ready and go files of other checks.
    work = os.path.join(run.work, "family")
    os.makedirs(work)
    pids_file = run.file("family.pids")
    program = run.start(
        [sys.executable, PROGRAMS, "family", pids_file, work], stderr="family.program.err"
    )
    ready = wait_for(lambda: os.path.exists(os.path.join(work, "ready")), 10)
    if not run.expect(ready, "the process tree starts"):
        return
    iotap = run.root_start(
        [run.bin, "-f", "--json", "-d", "30", program.pid],
        stdout="family.json",
        stderr="family.err",
    )
    run.started("family.err")
    open(os.path.join(work, "go"), "w").close()
    rc = run.root_wait(iotap, 40)
    # iotap stops once the tree has ended, unless something went wrong.
    program.wait(15)
    try:
        with open(pids_file) as f:
            pids = json.load(f)
    except (OSError, ValueError) as err:
        run.expect(False, "the process tree runs to its end", str(err))
        return
    err = run.read("family.err")
    traced = Traced(run.file("family.json"), os.path.realpath(work))
    root, early, late, by_exec, grand, brief = (
        pids[role] for role in ("program", "early", "late", "exec", "grand", "brief")
    )
    seconds = traced.summary.get("duration_ns", 0) / 1e9
    run.expect(
        rc == 0 and "and its descendants (1 running now);" in err and 0 < seconds < 20,
        "iotap traces the program and its descendants, and stops once they have all ended",
        f"exit status {rc}, {seconds:.1f} s: " + (err.splitlines() or [""])[0],
    )
    run.expect(
        traced.initial == {root, early} and traced.written("early") == 1 << 20,
        "the child running from the start is traced from the start, with all its writes",
        f"{sorted(traced.initial)}, {traced.written('early')} bytes",
    )
    parents = {pid: traced.attached.get(pid) for pid in (late, by_exec, grand)}
    run.expect(
        parents == {late: root, by_exec: root, grand: late},
        "each child started later is traced with its parent, and so is the grandchild",
        str(parents),
    )
    sizes = tuple(traced.written(name) for name in ("late", "grand", "exec"))
    run.expect(
        sizes == (200_000, 30_000, 300_000),
        "with all their writes, those of the program a child ran by exec among them",
        str(sizes),
    )
    run.expect(
        all(traced.attached.get(pid, traced.untraced.get(pid)) == root for pid in brief),
        "each of the twenty children that end at once is traced or said to have ended untraced",
        f"{sum(pid in traced.attached for pid in brief)} traced, "
        f"{sum(pid in traced.untraced for pid in brief)} not",
    )
    counted = traced.summary.get("untraced_children")
    if LINUX:
        run.expect(
            not traced.untraced
            and counted == {"ended": 0, "full": 0}
            and traced.written("brief") == 2000,
            "every one is traced from its start, with the write it makes at once",
            f"{traced.written('brief')} of 2000 bytes, {counted}",
        )
    else:
        run.expect(
            counted == {"ended": len(traced.untraced), "full": 0},
            "the summary counts those that ended untraced",
            str(counted),
        )
    strangers = traced.pids - {root, early, late, by_exec, grand, *brief}
    run.expect(
        bool(traced.initial) and not strangers,
        "no process outside the tree is traced",
        str(sorted(strangers)),
    )

    me = os.getpid()
    iotap = run.root_start(
        [run.bin, "-f", "--json", "-d", "3", me], stdout="self.json", stderr="self.err"
    )
    run.started("self.err")
    # The sudo that runs iotap, what that sudo runs, and iotap.
    below = {iotap.pid, *descendants(iotap.pid)}
    own = os.path.join(run.work, "own")
    writer = run.start([sys.executable, PROGRAMS, "write", own, "1000", "1"])
    rc = run.root_wait(iotap, 15)
    writer.wait(10)
    traced = Traced(run.file("self.json"), os.path.realpath(run.work))
    run.expect(
        rc == 0 and me in traced.initial and not below & traced.pids,
        "traced with -f, this run takes in neither iotap nor the sudo that runs it",
        f"{sorted(below & traced.pids)} of {sorted(below)}",
    )
    run.expect(
        traced.attached.get(writer.pid) == me and traced.written("own") == 1000,
        "but a process the run starts meanwhile, with its write",
        f"parent {traced.attached.get(writer.pid)}, {traced.written('own')} bytes",
    )


class Traced:
    """What the JSON output of iotap in `path` says was traced; files are under `work`."""

    def __init__(self, path, work):
        objects = json_lines(path)
        self.work = work
        start = next((o for o in objects if o.get("type") == "start"), {})
        self.initial = {p["pid"] for p in start.get("processes", [])}
        self.attached = {o["pid"]: o["parent"] for o in objects if o.get("type") == "attached"}
        self.untraced = {o["pid"]: o["parent"] for o in objects if o.get("type") == "untraced"}
        self.events = [o for o in objects if o.get("type") == "event"]
        self.summary = next((o for o in objects if o.get("type") == "summary"), {})
        self.pids = self.initial | set(self.attached) | {e["pid"] for e in self.events}

    def written(self, name):
        """The bytes written to the file `name` under `work`."""
        path = os.path.join(self.work, name)
        return sum(
            e["bytes"] or 0
            for e in self.events
            if e["dir"] == "write" and e["target"].get("path") == path
        )
