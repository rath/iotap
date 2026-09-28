"""Runs the live checks of README.md ("Checking against a live kernel") for this system and judges
each expectation.

    python3 scripts/live/run.py [--bin PATH] [--list] [CHECK ...]

CHECK picks checks by their number in README.md; all of them run by default. Run it in a
terminal where sudo holds an approval, given there with `sudo -v`: every root step uses
`sudo -n`, and the run ends with `sudo -k`. On macOS, `open -a Terminal scripts/live/macos.command`
asks for the approval, with Touch ID where sudo takes it, and runs this.

Outputs go to target/live, and the verdicts to target/live/run.log as well. The exit status is 0
when every expectation held, 1 when one did not, and 2 when the run could not start.
"""

import argparse
import datetime
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import traceback

# Imports from here leave no __pycache__ behind.
sys.dont_write_bytecode = True

import harness

REPO = os.path.dirname(os.path.dirname(harness.HERE))


def refuse(why):
    print(f"run.py: {why}", file=sys.stderr)
    return 2


def obstacle(binary):
    """Why the run cannot start, or None."""
    if not os.access(binary, os.X_OK):
        return f"no iotap at {binary}; build it with cargo build --release"
    if harness.MACOS:
        # Only one tool at a time can own kdebug, and the user's own must not be stopped.
        owners = output(["pgrep", "-l", "-x", "iotap|fs_usage|ktrace"]).splitlines()
        if owners:
            return "these may own the kernel trace facility; quit them first: " + ", ".join(owners)
    approved = subprocess.run(
        ["sudo", "-n", "true"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if approved.returncode != 0:
        return "sudo holds no approval for this terminal; run sudo -v in it first"
    return None


def output(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=False).stdout.strip()


def modified(path):
    """When `path` was modified; 0 if it cannot be looked at, as a link to nothing cannot."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def newest_source():
    """The modification time of the newest file the binary is built from."""
    newest = 0.0
    for top in ("src", "csrc", "bpf", "build.rs", "Cargo.toml", "Cargo.lock"):
        path = os.path.join(REPO, top)
        paths = (
            [path]
            if os.path.isfile(path)
            else [os.path.join(d, f) for d, _, files in os.walk(path) for f in files]
        )
        newest = max([newest] + [modified(p) for p in paths])
    return newest


def main():
    parser = argparse.ArgumentParser(description="Runs iotap's live checks for this system.")
    parser.add_argument(
        "checks",
        nargs="*",
        type=int,
        metavar="CHECK",
        help="numbers of the checks to run, as README.md numbers them",
    )
    parser.add_argument("--bin", help="the iotap to check; target/release/iotap by default")
    parser.add_argument("--list", action="store_true", help="list the checks and exit")
    args = parser.parse_args()

    system = platform.system()
    if system == "Darwin":
        import macos  # noqa: F401
    elif system == "Linux":
        import linux  # noqa: F401
    else:
        return refuse(f"no live checks for {system}")
    checks = [c for c in harness.CHECKS if c.system == system]
    if args.list:
        for c in checks:
            print(f"{c.number:>3}  {c.title}")
        return 0
    unknown = sorted(set(args.checks) - {c.number for c in checks})
    if unknown:
        return refuse(f"no check numbered {', '.join(map(str, unknown))}; see --list")
    chosen = [c for c in checks if not args.checks or c.number in args.checks]

    binary = os.path.abspath(args.bin or os.path.join(REPO, "target", "release", "iotap"))
    out = os.path.join(REPO, "target", "live")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    # From here the run ends with sudo -k however it ends, refused, interrupted, or told to stop
    # by SIGTERM or SIGHUP, which raise as Ctrl-C does.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.default_int_handler)
    try:
        return run_all(chosen, binary, out)
    finally:
        subprocess.run(["sudo", "-k"], check=False)


def run_all(chosen, binary, out):
    """Runs the checks `chosen` against `binary`; returns the exit status."""
    why = obstacle(binary)
    if why:
        # Also where whoever waits for the run looks.
        with open(os.path.join(out, "run.log"), "w") as log:
            log.write(f"run.py: {why}\n")
        return refuse(why)
    # Short, for the paths of Unix-domain sockets, and under /tmp, for the paths through it.
    work = tempfile.mkdtemp(prefix="iotap-", dir="/tmp")
    with open(os.path.join(out, "run.log"), "w") as log:
        run = harness.Run(binary, out, work, log)
        try:
            run_checks(run, chosen, log)
        finally:
            try:
                run.stop_all()
            finally:
                shutil.rmtree(work, ignore_errors=True)
        counts = {
            v: sum(1 for _, verdict, _ in run.verdicts if verdict == v)
            for v in ("PASS", "FAIL", "SKIP")
        }
        run.say(f"== {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
        for number, verdict, what in run.verdicts:
            if verdict != "PASS":
                run.say(f"  {verdict}  {number}: {what}")
    return 1 if counts["FAIL"] else 0


def run_checks(run, chosen, log):
    system = " ".join(platform.uname()[i] for i in (0, 2, 4))
    run.say(f"iotap live checks, {datetime.datetime.now().astimezone():%Y-%m-%d %H:%M %Z}")
    run.say(
        f"  {run.bin}: {output([run.bin, '--version'])}, commit "
        + (output(["git", "-C", REPO, "describe", "--always", "--dirty"]) or "unknown")
    )
    run.say(f"  {system}, Python {platform.python_version()}")
    run.say(f"  outputs in {run.out}, the traced programs' files in {run.work}")
    if os.path.getmtime(run.bin) < newest_source():
        run.note("the binary is older than the sources; cargo build --release rebuilds it")
    if harness.MACOS:
        run.note("copy nothing until the run ends: the terminal UI check uses the clipboard")
    try:
        for c in chosen:
            run.number = c.number
            run.say(f"== {c.number} {c.title}")
            try:
                c.function(run)
            # A check that breaks must not keep the others from running.
            except Exception as err:  # noqa: BLE001
                run.expect(False, "the check ran to its end", f"{type(err).__name__}: {err}")
                log.write(traceback.format_exc())
            finally:
                run.stop_all()
    except KeyboardInterrupt:
        run.say("== interrupted")
        run.verdicts.append((run.number, "FAIL", "the run was interrupted"))


if __name__ == "__main__":
    sys.exit(main())
