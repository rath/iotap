"""The live checks on Linux, numbered as in README.md."""

import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import time

import shared
from harness import (
    DEVNULL,
    PIPE,
    PROGRAMS,
    check,
    command_name,
    descendants,
    event_lines,
    json_lines,
    row,
    serve,
    summary,
    summary_rows,
    traced_for,
    wait_for,
)

MIB = 1048576


@check("Linux", 1, "Root")
def needs_root(run):
    plain = subprocess.run([run.bin, "1"], capture_output=True, text=True, check=False)
    run.expect(
        plain.returncode == 1 and "tracing with eBPF requires root" in plain.stderr,
        "without sudo iotap says that it needs root",
        plain.stderr.strip(),
    )


@check("Linux", 2, "Writes to a file")
def writes(run):
    target = os.path.join(run.work, "x")
    dd = run.start(
        ["sh", "-c", 'sleep 1; exec dd if=/dev/zero of="$0" bs=1M count=10 status=none', target]
    )
    rc = run.iotap("-d", "30", dd.pid, stdout="dd.out", stderr="dd.err", timeout=40)
    out = run.read("dd.out")
    writes = [e for e in event_lines(out) if e["op"] == "write" and e["target"] == target]
    run.expect(
        len(writes) == 10 and all(e["requested"] == e["result"] == str(MIB) for e in writes),
        "ten write lines of 1048576 bytes to the file",
        f"{len(writes)} writes",
    )
    seconds = traced_for(out)
    run.expect(
        rc == 0 and "exited" in run.read("dd.err") and seconds is not None and seconds < 10,
        "the summary as dd exits",
        f"exit status {rc}, traced for {seconds} s",
    )

    sleeper = run.start(["sh", "-c", "sleep 1; exec sleep 1"])
    rc = run.iotap("-d", "10", sleeper.pid, stderr="exec.err")
    err = run.read("exec.err")
    notice = re.search(rf"^iotap: {sleeper.pid} is now running /\S*/sleep$", err, re.MULTILINE)
    run.expect(
        rc == 0 and notice is not None,
        "an exec is reported with the program's path",
        err.strip().replace("\n", " | "),
    )


@check("Linux", 3, "Network")
def network(run):
    www = os.path.join(run.work, "www")
    os.makedirs(www)
    blob = os.path.join(www, "blob")
    with open(blob, "wb") as f:
        f.write(os.urandom(300_000))
    _, port = serve(run, www)
    copy = os.path.join(run.work, "blob.copy")
    curl = run.start(
        ["sh", "-c", 'sleep 1; exec curl -s -o "$0" "$1"', copy, f"http://127.0.0.1:{port}/blob"]
    )
    rc = run.iotap(
        "--json", "-d", "30", curl.pid, stdout="curl.json", stderr="curl.err", timeout=40
    )
    remote = f"127.0.0.1:{port}"
    tcp = [
        e
        for e in json_lines(run.file("curl.json"))
        if e.get("type") == "event"
        and e["target"].get("proto") == "tcp"
        and e["target"].get("remote") == remote
    ]
    received = sum(e["bytes"] or 0 for e in tcp if e["dir"] == "read")
    run.expect(rc == 0 and bool(tcp), f"calls on tcp 127.0.0.1:… -> {remote}", f"{len(tcp)} calls")
    run.expect(
        received > 300_000,
        "whose received bytes add up to more than the file's size",
        f"{received} bytes",
    )
    run.expect(
        os.path.exists(copy) and filecmp.cmp(blob, copy, shallow=False), "and curl's copy is whole"
    )


@check("Linux", 4, "Sockets and pipes")
def sockets(run):
    name = f"iotap-live-{os.getpid()}"
    program = run.start([sys.executable, PROGRAMS, "sockets", run.work, name])
    rc = run.iotap("-d", "30", program.pid, stdout="sockets.out", stderr="sockets.err", timeout=40)
    targets = [r[5] for r in summary_rows(run.read("sockets.out"))]
    run.expect(
        rc == 0 and f"unix {run.work}/s.sock" in targets, "a unix row with the path", str(targets)
    )
    run.expect(f"unix @{name}" in targets, "a unix row with the abstract name")
    run.expect(
        any(re.fullmatch(r"udp \[::1\]:\d+( \(local\))?", t) for t in targets), "a udp row on ::1"
    )
    run.expect("<pipe>" in targets, "a pipe among the other descriptors")


@check("Linux", 5, "Dropped records")
def dropped(run):
    shared.dropped(run, "--buffer", "1024")


def programs_loaded(run):
    """How many of the kernel's eBPF programs have the names of iotap's."""
    listing = subprocess.run(
        ["sudo", "-n", "bpftool", "prog", "show"],
        stdin=DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    pattern = r"^\d+: \S+\s+name (?:sys_enter|sys_exit|process_exit|task_newtask)\s"
    return len(re.findall(pattern, listing, re.MULTILINE))


@check("Linux", 6, "Release")
def release(run):
    before = programs_loaded(run)
    sleeper = run.start(["sleep", "300"])
    iotap = run.root_start([run.bin, "-f", "-d", "60", sleeper.pid], stderr="kill.err")
    run.started("kill.err")
    during = programs_loaded(run)
    run.expect(
        during - before >= 3,
        "iotap's programs are loaded while it traces, with task_newtask for -f",
        f"{before} before, {during} during",
    )
    killed = [pid for pid in descendants(iotap.pid) if command_name(pid) == "iotap"]
    run.root(["kill", "-KILL", *killed])
    run.root_wait(iotap, 10)
    wait_for(lambda: programs_loaded(run) == before, 5, step=0.25)
    run.expect(
        bool(killed) and programs_loaded(run) == before,
        "and gone after sudo kill -KILL",
        f"killed {killed}",
    )

    rc = run.iotap("-q", "-d", "1", sleeper.pid)
    run.expect(rc == 0 and programs_loaded(run) == before, "and after --duration")
    rc = run.root_shell(
        '"$1" -q -d 15 "$2" > /dev/null & p=$!; sleep 1; kill -INT "$p"; wait "$p"',
        run.bin,
        sleeper.pid,
    )
    run.expect(rc == 0 and programs_loaded(run) == before, "and after SIGINT")


@check("Linux", 7, "Several at once")
def several(run):
    target = os.path.join(run.work, "z")
    dd = run.start(
        ["sh", "-c", 'sleep 1; exec dd if=/dev/zero of="$0" bs=1M count=5 status=none', target]
    )
    first = run.root_start([run.bin, "-q", "-d", "30", dd.pid], stdout="a.out", stderr="a.err")
    second = run.root_start([run.bin, "-q", "-d", "30", dd.pid], stdout="b.out", stderr="b.err")
    rcs = [run.root_wait(first, 40), run.root_wait(second, 40)]
    a, b = run.read("a.out"), run.read("b.out")
    run.expect(
        rcs == [0, 0]
        and row(a, target) == row(b, target) is not None
        and row(a, target)[2:4] == ("5.0 MiB", "5"),
        "both see the five writes of 1 MiB",
        f"{row(a, target)} and {row(b, target)}",
    )
    run.expect(bool(summary_rows(a)) and summary_rows(a) == summary_rows(b), "and the same rows")


@check("Linux", 8, "A flood")
def flood(run):
    yes = run.start(["yes"])
    time.sleep(0.3)
    recording = run.file("flood.iotaprec")
    rc = run.iotap("--json", "-d", "3", "--record", recording, yes.pid, stderr="flood.err")
    run.stop(yes)
    if not run.expect(rc == 0 and os.path.exists(recording), "the flood is recorded"):
        return
    # Millions of lines: count them as they pass rather than keep them.
    with open(run.file("flood.replay.err"), "wb") as err:
        replay = subprocess.Popen(
            [run.bin, "--json", "--replay", recording], stdout=PIPE, stderr=err
        )
    events, missing, late, total = 0, 0, 0, None
    seen = set()
    for line in replay.stdout:
        if line.startswith(b'{"type":"event"'):
            events += 1
            tid = re.search(rb'"tid":(\d+)', line).group(1)
            if b'"latency_ns":null' in line:
                missing += 1
                # A call under way when tracing began is the first of its thread.
                late += tid in seen
            seen.add(tid)
        elif line.startswith(b'{"type":"summary"'):
            total = json.loads(line)
    replay.wait()
    run.expect(events > 100_000, "the flood is traced", f"{events} events")
    run.expect(
        events > 0 and late == 0,
        "no call lacks its latency but one under way when tracing began",
        f"{missing} without, {late} of them after their thread's first call",
    )
    run.expect(
        total is not None and total["lost_events"] == 0, "and the summary counts no dropped records"
    )
    os.remove(recording)


@check("Linux", 9, "Names")
def names(run):
    program = os.path.join(run.work, "iotapdd")
    shutil.copy2(shutil.which("dd"), program)
    run.start([program, "if=/dev/zero", "of=/dev/null", "bs=1M", "count=100000", "status=none"])
    iotap = run.root_start(
        [run.bin, "-q", "-d", "5", "iotapdd"], stdout="names.out", stderr="names.err"
    )
    run.started("names.err")
    time.sleep(0.5)
    # A new process under the name, blocked in a read for a second, long enough for iotap to
    # find it, and one that takes the name by exec a second after iotap saw it as bash.
    late, renamed = os.path.join(run.work, "late"), os.path.join(run.work, "renamed")
    feed = run.start(["sh", "-c", f"sleep 1; head -c {3 * MIB} /dev/zero"], stdout=PIPE)
    newer = run.start(
        [program, f"of={late}", "bs=1M", "iflag=fullblock", "status=none"], stdin=feed.stdout
    )
    feed.stdout.close()
    feed = run.start(["sh", "-c", f"sleep 2; head -c {2 * MIB} /dev/zero"], stdout=PIPE)
    exec_later = 'sleep 1; exec "$0" of="$1" bs=1M iflag=fullblock status=none'
    by_exec = run.start(["bash", "-c", exec_later, program, renamed], stdin=feed.stdout)
    feed.stdout.close()
    newer.wait(15)
    by_exec.wait(15)
    rc = run.root_wait(iotap, 15)
    err, out = run.read("names.err"), run.read("names.out")
    run.expect(
        rc == 0 and f"now tracing {newer.pid} (iotapdd)" in err,
        "a new process with the name is followed",
        err.strip().replace("\n", " | ")[:300],
    )
    run.expect(f"now tracing {by_exec.pid} (iotapdd)" in err, "and so is one that takes it by exec")
    run.expect(
        (row(out, late) or ())[2:4] == ("3.0 MiB", "3"),
        "the first writes 3 MiB",
        str(row(out, late)),
    )
    run.expect(
        (row(out, renamed) or ())[2:4] == ("2.0 MiB", "2"),
        "the second writes 2 MiB",
        str(row(out, renamed)),
    )

    shared.argv0_names(run)


@check("Linux", 10, "Short-lived connections")
def short_lived(run):
    program = run.start([sys.executable, PROGRAMS, "short-udp"], stdout="short.port")
    rc = run.iotap(
        "--json", "-d", "30", program.pid, stdout="short.json", stderr="short.err", timeout=40
    )
    port = run.read("short.port").strip()
    sends = [
        e
        for e in json_lines(run.file("short.json"))
        if e.get("type") == "event" and e["dir"] == "write" and e["target"].get("proto") == "udp"
    ]
    named = [e for e in sends if e["target"].get("remote") == f"127.0.0.1:{port}"]
    run.expect(
        rc == 0 and len(sends) == 20 and len(named) == 20,
        "each of the twenty sends names its remote end, not udp ?",
        f"{len(named)} of {len(sends)} to 127.0.0.1:{port}",
    )


@check("Linux", 11, "Calls under way")
def under_way(run):
    fifo = os.path.join(run.work, "fifo")
    os.mkfifo(fifo)
    # Held open for writing too, so that a read of it never ends.
    held = os.open(fifo, os.O_RDWR)
    try:
        for mode in ("text", "json"):
            # The first read begins before tracing and ends while iotap runs; the second begins
            # while it runs and has not ended when it stops.
            feed = run.start(["sh", "-c", "sleep 3; echo hi"], stdout=PIPE)
            first = run.start(["cat"], stdin=feed.stdout)
            feed.stdout.close()
            second = run.start(["sh", "-c", "sleep 2; exec cat"], stdin=held)
            time.sleep(1)
            options = ["--json"] if mode == "json" else []
            run.iotap(
                *options,
                "-q",
                "-d",
                "5",
                first.pid,
                second.pid,
                stdout=f"calls.{mode}",
                stderr=f"calls.{mode}.err",
            )
            run.stop(second)
            run.stop(first)
    finally:
        os.close(held)
    run.expect(
        "Note: 1 call began before tracing started" in summary(run.read("calls.text")),
        "the summary notes the one call that began before tracing",
    )
    total = (json_lines(run.file("calls.json")) or [{}])[-1]
    run.expect(
        total.get("unfinished_calls") == 1 and total.get("calls_started_before_trace") == 1,
        "--json counts one unfinished call and one that began before tracing",
        f"{total.get('unfinished_calls')} and {total.get('calls_started_before_trace')}",
    )


@check("Linux", 12, "Replay, terminal UI and host names")
def replay_ui_names(run):
    shared.replay(run, ["dd", "if=/dev/zero", "of=/dev/null", "bs=1M"])
    shared.terminal_ui(run)
    shared.host_names(run)


@check("Linux", 13, "Children")
def children(run):
    shared.children(run)
