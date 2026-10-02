"""The live checks on macOS, numbered as in README.md."""

import json
import os
import re
import shutil
import subprocess
import sys
import time

import shared
from harness import (
    HERE,
    PIPE,
    PROGRAMS,
    check,
    event_lines,
    json_lines,
    read_lines,
    row,
    serve,
    summary,
    summary_rows,
    traced_for,
    wait_for,
)

MIB = 1048576


@check("Darwin", 1, "Writes to a file")
def writes(run):
    yes = run.start(["yes"])
    time.sleep(0.5)
    iotap = run.root_start([run.bin, yes.pid], stdout=PIPE, stderr="stream.err")
    lines = read_lines(iotap.stdout, 6, timeout=10)
    iotap.stdout.close()
    rc = run.root_wait(iotap, 15)
    # A write under way when tracing began shows neither its descriptor nor its latency.
    seen = [e for e in event_lines("\n".join(lines)) if e["op"] == "write" and e["fd"] != "-"]
    run.expect(
        len(seen) >= 3 and all(e["target"] == "/dev/null" for e in seen),
        "event lines are writes to /dev/null",
        f"{len(seen)} of the first {len(lines)} lines",
    )
    run.expect(rc == 0, "iotap stops without an error when its output closes", f"exit status {rc}")

    rc = run.iotap("-q", "-d", "3", yes.pid, stdout="quiet.out", stderr="quiet.err")
    out = run.read("quiet.out")
    run.expect(
        rc == 0
        and out.lstrip().startswith("iotap summary:")
        and "Files (1 target)" in out
        and row(out, "/dev/null") is not None,
        "-q prints only the summary, whose one file is /dev/null",
    )
    seconds = traced_for(out)
    run.expect(
        seconds is not None and 2.8 <= seconds <= 3.6,
        "--duration 3 stops it after three seconds",
        f"{seconds} s",
    )

    # Ctrl-C sends SIGINT to iotap itself.
    rc = run.root_shell(
        '"$1" -q -d 15 "$2" > "$3" 2> "$4" & p=$!; sleep 2; kill -INT "$p"; wait "$p"',
        run.bin,
        yes.pid,
        run.file("int.out"),
        run.file("int.err"),
    )
    out = run.read("int.out")
    seconds = traced_for(out)
    run.expect(
        rc == 0 and "/dev/null" in summary(out) and seconds is not None and seconds < 5,
        "SIGINT, as Ctrl-C sends it, stops it with the summary",
        f"exit status {rc}, traced for {seconds} s",
    )
    # kill from another terminal signals sudo, which passes the signal on.
    sudo = run.root_start(
        [run.bin, "-q", "-d", "15", yes.pid], stdout="sudo-int.out", stderr="sudo-int.err"
    )
    time.sleep(2)
    run.signal_elsewhere(sudo.pid, "INT")
    rc = run.root_wait(sudo, 10)
    out = run.read("sudo-int.out")
    seconds = traced_for(out)
    run.expect(
        rc == 0 and "/dev/null" in summary(out) and seconds is not None and seconds < 5,
        "so does SIGINT to sudo from another process group",
        f"exit status {rc}, traced for {seconds} s",
    )


@check("Darwin", 2, "Byte counts")
def byte_counts(run):
    dd = run.start(["dd", "if=/dev/zero", "of=/dev/null", "bs=1m"])
    time.sleep(0.5)
    rc = run.iotap("--json", "-d", "1", dd.pid, stdout="dd.json", stderr="dd.err")
    lines = json_lines(run.file("dd.json"))
    types = [line.get("type") for line in lines]
    run.expect(
        rc == 0
        and types[:1] == ["start"]
        and types[-1:] == ["summary"]
        and "UNPARSABLE" not in types,
        "JSON Lines: a start line, the events and a summary, each line an object",
        f"{len(lines)} lines",
    )
    if types[-1:] != ["summary"]:
        return
    calls = [line for line in lines if line.get("type") == "event"]
    early = [e for e in calls if e["latency_ns"] is None]
    total = lines[-1]
    run.expect(
        len(early) == total["calls_started_before_trace"] and len(early) <= 1,
        "only the call under way when tracing began lacks its latency, and is counted",
        f"{len(early)} without it",
    )
    calls = [e for e in calls if e not in early]
    reads = [e for e in calls if e["op"] == "read"]
    writes = [e for e in calls if e["op"] == "write"]
    run.expect(
        bool(reads)
        and all(
            e["bytes"] == e["requested"] == MIB
            and e["target"] == {"kind": "file", "path": "/dev/zero"}
            for e in reads
        ),
        "every read moves 1048576 bytes from /dev/zero",
        f"{len(reads)} reads",
    )
    run.expect(
        bool(writes)
        and all(
            e["bytes"] == e["requested"] == MIB
            and e["target"] == {"kind": "file", "path": "/dev/null"}
            for e in writes
        ),
        "every write moves 1048576 bytes to /dev/null",
        f"{len(writes)} writes",
    )
    run.expect(
        bool(calls) and all(e["resolved"] == "snapshot" for e in calls),
        "the descriptors come from the snapshot",
    )
    run.expect(
        bool(calls) and all((e["latency_ns"] or 0) > 0 for e in calls),
        "every latency is there and above zero",
    )
    syscalls = sorted({e["syscall"] for e in calls})
    run.expect(
        bool(calls)
        and all(e["pid"] == dd.pid for e in calls)
        and set(syscalls) <= {"read", "write", "read_nocancel", "write_nocancel"},
        "the pid, and the calls' names",
        str(syscalls),
    )
    totals = total["totals"]
    run.expect(
        totals["file_read"]["bytes"] == sum(e["bytes"] for e in reads)
        and totals["file_write"]["calls"] == len(writes),
        "the summary's totals add up the events",
    )


@check("Darwin", 3, "Network")
def network(run):
    www = os.path.join(run.work, "www")
    os.makedirs(www)
    with open(os.path.join(www, "big.bin"), "wb") as f:
        f.write(bytes(16 * MIB))
    server, port = serve(run, www)
    url = f"http://127.0.0.1:{port}/big.bin"
    # Started through a link of a name of its own, so that curls that are not this run's are not
    # traced, and cannot change what it finds.
    name = f"iotap-curl-{os.getpid()}"
    curl = os.path.join(run.work, name)
    os.symlink(shutil.which("curl"), curl)
    first = run.start([curl, "-s", "--limit-rate", "2M", "-o", "/dev/null", url])
    time.sleep(0.5)
    iotap = run.root_start([run.bin, "-q", "-d", "25", name], stdout="curl.out", stderr="curl.err")
    run.started("curl.err")
    time.sleep(1)
    second = run.start([curl, "-s", "--limit-rate", "4M", "-o", "/dev/null", url])
    first.wait(40)
    second.wait(40)
    rc = run.root_wait(iotap, 40)
    out, err = run.read("curl.out"), run.read("curl.err")
    run.expect(
        f"now tracing {second.pid} (curl)" in err,
        "a curl started later is traced too",
        err.strip().replace("\n", " | ")[:300],
    )
    seconds = traced_for(out)
    run.expect(
        rc == 0 and err.count("exited") >= 2 and seconds is not None and seconds < 20,
        "tracing ends once both have exited",
        f"exit status {rc}, traced for {seconds} s",
    )
    # Both connections go to the same place, so they share a row.
    rows = [
        r
        for r in summary_rows(out)
        if re.fullmatch(rf"tcp 127\.0\.0\.1:{port}(  \(\d+ connections\))?", r[5])
    ]
    run.expect(len(rows) == 1, "one tcp row for the server", str(rows))

    third = run.start([curl, "-s", "--limit-rate", "3M", "-o", "/dev/null", url])
    time.sleep(0.5)
    rc = run.iotap("-q", "-d", "3", server.pid, stdout="server.out", stderr="server.err")
    run.stop(third)
    targets = [r[5] for r in summary_rows(run.read("server.out"))]
    run.expect(
        rc == 0 and any(t.endswith("/www/big.bin") for t in targets),
        "the server reads the file it serves",
    )
    run.expect(
        any(re.fullmatch(r"tcp 127\.0\.0\.1:\d+", t) for t in targets),
        "and has a tcp row toward the client",
    )


@check("Darwin", 4, "Dropped records")
def dropped(run):
    shared.dropped(run)


@check("Darwin", 5, "Single owner")
def single_owner(run):
    yes = run.start(["yes"])
    # fs_usage need only own the trace facility: watching this quiet run rather than the whole
    # system keeps it from falling minutes behind, as it once did.
    fs_usage = run.root_start(["fs_usage", "-w", os.getpid()], stderr="fs_usage.err")
    time.sleep(2)
    rc = run.iotap("-d", "1", yes.pid, stderr="iotap.err")
    err = run.read("iotap.err")
    run.expect(
        rc == 1 and "is using the kernel trace facility" in err,
        "iotap refuses to start while fs_usage owns kdebug",
        err.strip()[-160:],
    )
    run.expect(
        "is using the kernel trace facility" in err and "iotap: tracing" not in err,
        "without saying first that it traces",
    )
    rc = run.interrupt(fs_usage)
    run.expect(rc == 0, "fs_usage stops when asked", f"exit status {rc}")


@check("Darwin", 6, "Release")
def release(run):
    yes = run.start(["yes"])
    time.sleep(0.5)

    def released():
        # Watching only this quiet run: system-wide, under the flood from yes, fs_usage writes
        # hundreds of megabytes a second.
        rc = run.root(["fs_usage", "-t", "1", os.getpid()], stderr="fs_usage.err", timeout=30)
        run.expect(rc == 0, "and has let go of kdebug: fs_usage starts", f"exit status {rc}")

    rc = run.iotap("-q", "-d", "1", yes.pid)
    run.expect(rc == 0, "iotap stops at --duration", f"exit status {rc}")
    released()
    began = time.monotonic()
    rc = run.root_shell(
        '"$1" -q -d 15 "$2" > /dev/null & p=$!; sleep 2; kill -INT "$p"; wait "$p"',
        run.bin,
        yes.pid,
    )
    # Without the signal it would run for its 15 seconds and exit with status 0 all the same.
    took = time.monotonic() - began
    run.expect(
        rc == 0 and took < 10, "iotap stops at SIGINT", f"exit status {rc} after {took:.0f} s"
    )
    released()
    rc = run.root_shell(
        '"$1" -q -d 15 "$2" > "$3" & p=$!; sleep 2; kill -INT "$p"; kill -TERM "$p"; wait "$p"',
        run.bin,
        yes.pid,
        run.file("forced.out"),
    )
    run.expect(
        rc == 130 and "iotap summary" not in run.read("forced.out"),
        "a second signal makes it exit at once, without the summary",
        f"exit status {rc}",
    )
    released()

    doomed = run.start(["yes"])
    iotap = run.root_start(
        [run.bin, "-q", "-d", "15", doomed.pid], stdout="exits.out", stderr="exits.err"
    )
    time.sleep(2)
    run.stop(doomed)
    rc = run.root_wait(iotap, 20)
    seconds = traced_for(run.read("exits.out"))
    run.expect(
        rc == 0 and "exited" in run.read("exits.err") and seconds is not None and seconds < 5,
        "iotap stops with the summary when the traced process exits",
        f"exit status {rc}, traced for {seconds} s",
    )
    released()
    rc = run.iotap("-q", "-d", "1", yes.pid)
    run.expect(rc == 0, "and iotap starts again after fs_usage", f"exit status {rc}")


@check("Darwin", 7, "Replay")
def replay(run):
    shared.replay(run, ["dd", "if=/dev/zero", "of=/dev/null", "bs=1m"])


@check("Darwin", 8, "Terminal UI")
def terminal_ui(run):
    shared.terminal_ui(run)


@check("Darwin", 9, "Names")
def names(run):
    cat = os.path.join(run.work, "iotapcat")
    # A copy of /bin/cat will not do: macOS kills copies of its own programs as they start.
    subprocess.run(["cc", "-O2", "-o", cat, os.path.join(HERE, "mycat.c")], check=True)
    # The process under the name when tracing starts, reading a pipe that stays quiet.
    quiet = run.start(["sleep", "8"], stdout=PIPE)
    run.start([cat], stdin=quiet.stdout)
    quiet.stdout.close()
    time.sleep(0.3)
    iotap = run.root_start([run.bin, "-d", "5", "iotapcat"], stdout="exec.out", stderr="exec.err")
    run.started("exec.err")
    # Seen first as sh, it takes the name by exec a second later, and reads until well after.
    feed = run.start(["sh", "-c", "sleep 2.5; echo renamed"], stdout=PIPE)
    renamed = run.start(["sh", "-c", 'sleep 1; exec "$0"', cat], stdin=feed.stdout)
    feed.stdout.close()
    renamed.wait(15)
    rc = run.root_wait(iotap, 15)
    err = run.read("exec.err")
    run.expect(
        rc == 0 and f"now tracing {renamed.pid} (iotapcat)" in err,
        "a process that takes the name by exec is followed",
        err.strip().replace("\n", " | ")[:300],
    )
    run.expect(
        any(
            e["pid"] == renamed.pid and e["op"] == "write"
            for e in event_lines(run.read("exec.out"))
        ),
        "and its write after the exec is seen",
    )

    go = os.path.join(run.work, "go-exec")
    wait_then_exec = 'while [ ! -f "$0" ]; do sleep 0.1; done; exec /bin/cat /dev/zero'
    waiting = run.start(["sh", "-c", wait_then_exec, go])
    time.sleep(0.3)
    iotap = run.root_start(
        [run.bin, "-q", "-d", "4", waiting.pid], stdout="cat.out", stderr="cat.err"
    )
    run.started("cat.err")
    time.sleep(0.5)
    open(go, "w").close()
    rc = run.root_wait(iotap, 15)
    run.expect(
        rc == 0 and f"{waiting.pid} is now running /bin/cat" in run.read("cat.err"),
        "an exec is reported with the program's path",
    )
    targets = [r[5] for r in summary_rows(run.read("cat.out"))]
    run.expect(
        "/dev/zero" in targets and "/dev/null" in targets, "and the new program's calls are traced"
    )

    shared.argv0_names(run)


@check("Darwin", 10, "Host names")
def host_names(run):
    shared.host_names(run)


@check("Darwin", 11, "Calls and targets")
def calls_and_targets(run):
    lab(run)
    workload(run)


@check("Darwin", 12, "Children")
def children(run):
    shared.children(run)


@check("Darwin", 13, "Network interfaces")
def interfaces(run):
    shared.interfaces(run)


@check("Darwin", 14, "Network statistics")
def network_statistics(run):
    client = os.path.join(run.work, "network-client")
    built = subprocess.run(
        [
            "clang",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fobjc-arc",
            "-fblocks",
            os.path.join(HERE, "network_client.m"),
            "-framework",
            "Foundation",
            "-o",
            client,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if not run.expect(built.returncode == 0, "the Foundation client builds", built.stderr):
        return
    url = "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/ntstat.h"
    proc = run.start([client, url], stdout="client.out", stderr="client.err")
    if not run.expect(wait_for(lambda: "ready" in run.read("client.out"), 5), "the client starts"):
        return
    recording = run.file("network.iotaprec")
    rc = run.iotap(
        "--json",
        "--record",
        recording,
        "-d",
        "10",
        proc.pid,
        stdout="network.json",
        stderr="network.err",
        timeout=20,
    )
    lines = json_lines(run.file("network.json"))
    samples = [line for line in lines if line.get("type") == "network_sample"]
    total = next((line for line in lines if line.get("type") == "summary"), {})
    traffic = total.get("network_traffic", {})
    received = sum(sample.get("received_bytes", 0) for sample in samples)
    sent = sum(sample.get("sent_bytes", 0) for sample in samples)
    run.expect(
        rc == 0 and received > 0 and traffic.get("status", {}).get("state") == "active",
        "Foundation traffic is measured independently of syscalls",
        f"received {received}, client: {run.read('client.out').strip()}",
    )
    run.expect(
        bool(samples)
        and traffic.get("received_bytes") == received
        and traffic.get("sent_bytes") == sent,
        "OS totals sum only the network samples",
    )
    run.expect(
        bool(samples)
        and all(sample.get("pid") == proc.pid for sample in samples)
        and any(sample.get("target", {}).get("remote") for sample in samples),
        "samples identify the selected process and its remote endpoint",
    )
    with open(run.file("network.replay"), "wb") as out:
        replayed = subprocess.run(
            [run.bin, "--json", "--replay", recording],
            stdout=out,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    run.expect(
        bool(samples)
        and replayed.returncode == 0
        and run.read("network.json") == run.read("network.replay"),
        "network measurements replay byte for byte",
    )
    measured = subprocess.run(
        ["nettop", "-n", "-P", "-x", "-L", "1", "-p", str(proc.pid), "-J", "bytes_in,bytes_out"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    rows = [line.split(",") for line in measured.stdout.splitlines() if f".{proc.pid}," in line]
    if rows:
        actual = int(rows[-1][1])
        run.expect(
            received > 0 and actual >= received >= actual * 0.8,
            "received bytes agree with nettop within the sampling window",
            f"iotap {received}, nettop {actual}",
        )
    else:
        run.expect(False, "nettop still sees the Foundation client", measured.stderr)


def traced_program(run, name, *args):
    """Starts a program of programs.py that waits to be traced, traces it until it exits, and
    returns what it wrote about itself and the events iotap saw."""
    ready = os.path.join(run.work, "ready")
    for leftover in (ready, os.path.join(run.work, "go")):
        if os.path.exists(leftover):
            os.remove(leftover)
    told = run.file(f"{name}.truth.json")
    program = run.start(
        [sys.executable, PROGRAMS, name, told, run.work, *args], stderr=f"{name}.err"
    )
    if not run.expect(wait_for(lambda: os.path.exists(ready), 20), f"the {name} program is ready"):
        return None, []
    iotap = run.root_start(
        [run.bin, "--json", "-d", "60", program.pid],
        stdout=f"{name}.json",
        stderr=f"{name}.iotap.err",
    )
    run.started(f"{name}.iotap.err")
    time.sleep(0.5)
    open(os.path.join(run.work, "go"), "w").close()
    program.wait(60)
    rc = run.root_wait(iotap, 30)
    run.expect(
        rc == 0 and program.returncode == 0,
        f"the {name} program ran and was traced",
        f"iotap {rc}, program {program.returncode}",
    )
    try:
        with open(told) as f:
            truth = json.load(f)
    except (OSError, ValueError):
        return None, []
    events = [e for e in json_lines(run.file(f"{name}.json")) if e.get("type") == "event"]
    return truth, events


def lab(run):
    """Files opened through links, along long paths and relative to other directories, and
    short-lived sockets: each target as the kernel names it."""
    lab_run, events = traced_program(run, "lab")
    if lab_run is None:
        return
    real = lab_run["lab"]

    def short(text):
        return text.replace(real, "LAB")

    tally, wrong = {}, []

    def count(group, verdict, line):
        tally.setdefault(group, {}).setdefault(verdict, 0)
        tally[group][verdict] += 1
        if verdict in ("WRONG", "missing"):
            wrong.append(f"{group}: {short(line)}")

    for case in lab_run["files"]:
        group = f"files kept open {case['hold']} s"
        found = [
            e
            for e in events
            if e["requested"] == case["size"]
            and e["syscall"] in ("read", "write", "read_nocancel", "write_nocancel")
        ]
        if len(found) != 1:
            count(group, "missing", f"{case['case']}: {len(found)} events")
            continue
        got = found[0]["target"].get("path", json.dumps(found[0]["target"]))
        truth = case["truth"]
        if got == truth:
            verdict = "exact"
        elif os.path.normpath(got) == os.path.normpath(truth):
            verdict = "same file"
        elif got.startswith("…") and truth.endswith(got[1:]):
            # Only the end of a path too long for the trace, as README.md says.
            verdict = "tail"
        else:
            verdict = "WRONG"
        count(group, verdict, f"{case['case']}: {got}, not {truth}")

    def socket_verdict(target, want):
        # A bare socket, whose kind is unknown, is incomplete rather than wrong.
        if target["kind"] == "socket" and target["proto"] == "other":
            return "partial"
        if target["kind"] != "socket" or target["proto"] != want["proto"]:
            return "WRONG"
        missing = False
        for key in ("local", "remote", "path"):
            if key not in want:
                continue
            if key not in target:
                missing = True
            elif os.path.normpath(target[key]) != os.path.normpath(want[key]):
                return "WRONG"
        # A short-lived socket may be gone before iotap can look it up, as README.md says.
        return "partial" if missing else "exact"

    for case in lab_run["sockets"]:
        n = case["size"]
        found = [
            e
            for e in events
            if (e["requested"] == n and e["syscall"].startswith(("sendto", "recvfrom")))
            or (e["syscall"].startswith(("sendmsg", "recvmsg")) and e["bytes"] == n)
        ]
        want = {k: v for k, v in case.items() if k in ("proto", "remote", "local", "path")}
        group = f"sockets: {case['case']}"
        if not found:
            count(group, "missing", f"held {case['hold']} s")
        for e in found:
            count(
                group,
                socket_verdict(e["target"], want),
                f"{e['syscall']} {json.dumps(e['target'])}, wanted {json.dumps(want)}",
            )

    port = lab_run["tcp_port"]
    for served in lab_run["served"]:
        if ":" in served["peer"]:
            want = {"proto": "tcp", "local": f"127.0.0.1:{port}", "remote": served["peer"]}
        else:
            want = {"proto": "unix"}
        group = f"server side: {want['proto']}"
        found = [e for e in events if e["requested"] == 997 and e["bytes"] == served["got"]]
        if not found:
            count(group, "missing", f"the {served['got']} bytes from {served['peer']}")
        for e in found:
            count(
                group,
                socket_verdict(e["target"], want),
                f"{e['syscall']} {json.dumps(e['target'])}, wanted {json.dumps(want)}",
            )

    for group in sorted(tally):
        counts = tally[group]
        run.expect(
            not counts.get("WRONG") and not counts.get("missing"),
            group,
            ", ".join(f"{n} {verdict}" for verdict, n in sorted(counts.items())),
        )
    for line in wrong[:30]:
        run.note(line)


def workload(run):
    """Known reads, writes, dups, a pipe and sockets: each call with its size and target."""
    www = os.path.join(run.work, "www")
    os.makedirs(www, exist_ok=True)
    with open(os.path.join(www, "big.bin"), "wb") as f:
        f.write(bytes(MIB))
    _, port = serve(run, www)
    expected, events = traced_program(run, "workload", port)
    if expected is None:
        return
    used = set()

    def matches(exp, ev):
        if ev["op"] != exp["op"] or (exp["fd"] is not None and ev["fd"] != exp["fd"]):
            return False
        if exp["bytes"] is not None and not exp.get("total") and ev["bytes"] != exp["bytes"]:
            return False
        t = ev["target"]
        # iotap reports paths as the kernel resolved them, through links: /private/etc/hosts.
        if (
            "path" in exp
            and exp.get("proto") != "unix"
            and (
                t.get("kind") != "file"
                or os.path.realpath(t.get("path", "")) != os.path.realpath(exp["path"])
            )
        ):
            return False
        if exp.get("kind") == "pipe" and (t.get("kind") != "other" or t.get("fd_type") != "pipe"):
            return False
        if "proto" in exp and (
            t.get("kind") != "socket" or t.get("proto") not in (exp["proto"], "other")
        ):
            return False
        # A connection closed before iotap could look it up shows only its protocol.
        return "remote" not in exp or t.get("remote", exp["remote"]) == exp["remote"]

    for exp in expected:
        label = f"{exp['op']} on {exp.get('path') or exp.get('kind') or exp.get('proto')}"
        if exp.get("total"):
            got = [i for i, ev in enumerate(events) if i not in used and matches(exp, ev)]
            used.update(got)
            total = sum(events[i]["bytes"] or 0 for i in got)
            run.expect(
                total == exp["bytes"],
                f"{label}, in {len(got)} calls",
                f"{total} of {exp['bytes']} bytes",
            )
            continue
        found = next((i for i, ev in enumerate(events) if i not in used and matches(exp, ev)), None)
        if found is None:
            near = [ev for ev in events if ev["op"] == exp["op"]]
            run.expect(
                False, label, "closest: " + (json.dumps(near[0]["target"]) if near else "none")
            )
            continue
        used.add(found)
        run.expect(True, label, f"fd {events[found]['fd']}, {events[found]['resolved']}")
