"""Programs the live checks trace, each doing I/O the checks know in advance.

    programs.py sockets DIR NAME   Unix-domain sockets at DIR/s.sock and, on Linux, @NAME, a
                                   pipe and a UDP socket on ::1, each used once and kept open
    programs.py short-udp          twenty UDP sockets connected to a local server, each used once
                                   and closed at once; prints the server's port first
    programs.py workload OUT DIR PORT
                                   known reads, writes, dups, a pipe and sockets, one of them a
                                   TCP connection to PORT; writes what it did to OUT as JSON
    programs.py lab OUT DIR        (macOS) files opened through links, long paths and openat,
                                   then sockets, each twice; writes the kernel's path for each
                                   file (F_GETPATH) and what each socket was to OUT as JSON
    programs.py peers ADDR...      UDP sockets connected to each address, polled for a datagram
                                   every 0.2 s until killed; no packet leaves the machine
    programs.py home-writer PATH   rewrites PATH every 100 ms for 90 s
    programs.py write PATH SIZE CHUNKS
                                   writes SIZE bytes to PATH in CHUNKS writes, half a second
                                   after it starts
    programs.py paced DIR SIZE CHUNKS
                                   writes SIZE bytes to DIR/paced in CHUNKS writes, 32 every
                                   millisecond, then waits a minute
    programs.py family OUT DIR     a process tree, each member of which writes a file of its own
                                   in DIR: a child that runs from the start, and once tracing
                                   begins a child that starts a grandchild, a child that runs
                                   `write` by exec, and twenty children that write 100 bytes each
                                   to DIR/brief and end at once; writes the pids to OUT as JSON

workload, lab, family and paced create DIR/ready once set up, then wait for DIR/go before their
I/O.
"""

import fcntl
import json
import os
import shutil
import socket
import sys
import threading
import time
import traceback


def ready_then_go(directory):
    open(os.path.join(directory, "ready"), "w").close()
    wait_for_go(directory)


def wait_for_go(directory):
    while not os.path.exists(os.path.join(directory, "go")):
        time.sleep(0.02)


def sockets(directory, name):
    time.sleep(1)
    path = os.path.join(directory, "s.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(path)
    conn, _ = server.accept()
    client.sendall(b"x" * 1000)
    conn.recv(4096)
    if sys.platform == "linux":
        abstract = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        abstract.bind("\0" + name)
        sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sender.connect("\0" + name)
        sender.send(b"y" * 100)
        abstract.recv(4096)
    r, w = os.pipe()
    os.write(w, b"z" * 10)
    os.read(r, 10)
    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp.bind(("::1", 0))
    udp.sendto(b"u" * 7, udp.getsockname())
    udp.recvfrom(100)
    # Long enough for iotap to look up what it did not see opened.
    time.sleep(1)
    os.unlink(path)


def short_udp():
    time.sleep(1)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    print(port, flush=True)
    for _ in range(20):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.connect(("127.0.0.1", port))
        client.send(b"q" * 30)
        server.recv(100)
        client.close()


def workload(out, directory, port):
    ready_then_go(directory)
    done = []

    def note(op, fd, n=None, **target):
        done.append({"op": op, "fd": fd, "bytes": n, **target})

    fd = os.open("/etc/hosts", os.O_RDONLY)
    note("read", fd, len(os.read(fd, 100_000)), path="/etc/hosts")
    os.close(fd)

    os.chdir("/usr/share/dict")
    fd = os.open("words", os.O_RDONLY)
    note("read", fd, len(os.read(fd, 1000)), path="/usr/share/dict/words")
    os.close(fd)
    os.chdir(directory)

    path = os.path.join(directory, "written.txt")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    note("write", fd, os.write(fd, b"x" * 1234), path=path)
    os.close(fd)
    fd = os.open(path, os.O_RDWR)
    note("pwrite", fd, os.pwrite(fd, b"y" * 10, 100), path=path)
    note("pread", fd, len(os.pread(fd, 50, 0)), path=path)
    note("writev", fd, os.writev(fd, [b"a" * 3, b"b" * 4]), path=path)
    os.lseek(fd, 0, os.SEEK_SET)
    note("readv", fd, os.readv(fd, [bytearray(5), bytearray(6)]), path=path)
    os.close(fd)

    fd = os.open("/etc/hosts", os.O_RDONLY)
    d1 = os.dup(fd)
    note("read", d1, len(os.read(d1, 10)), path="/etc/hosts")
    d2 = fcntl.fcntl(fd, fcntl.F_DUPFD, 50)
    note("read", d2, len(os.read(d2, 10)), path="/etc/hosts")
    os.dup2(fd, 60)
    note("read", 60, len(os.read(60, 10)), path="/etc/hosts")
    for x in (fd, d1, d2, 60):
        os.close(x)

    os.listdir("/usr/share")
    note("getdirentries", None, None, path="/usr/share")

    r, w = os.pipe()
    note("write", w, os.write(w, b"z" * 100), kind="pipe")
    note("read", r, len(os.read(r, 100)), kind="pipe")
    os.close(r)
    os.close(w)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    note("sendto", s.fileno(), s.sendto(b"hello", ("127.0.0.1", 9)), proto="udp")
    s.close()

    c = socket.create_connection(("127.0.0.1", port))
    request = b"GET /big.bin HTTP/1.0\r\n\r\n"
    c.sendall(request)
    note("sendto", c.fileno(), len(request), proto="tcp", remote=f"127.0.0.1:{port}")
    got = 0
    while got < 200_000:
        chunk = c.recv(65536)
        if not chunk:
            break
        got += len(chunk)
    note("recvfrom", c.fileno(), got, proto="tcp", remote=f"127.0.0.1:{port}", total=True)
    c.close()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind("u.sock")
    server.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect("u.sock")
    conn, _ = server.accept()
    note(
        "sendto",
        client.fileno(),
        client.send(b"ping"),
        proto="unix",
        path=os.path.join(directory, "u.sock"),
    )
    note("recvfrom", conn.fileno(), len(conn.recv(4)), proto="unix")
    for x in (client, conn, server):
        x.close()
    os.unlink("u.sock")

    a, b = socket.socketpair()
    note("sendmsg", a.fileno(), a.sendmsg([b"msg"]), proto="unix")
    note("recvmsg", b.fileno(), len(b.recvmsg(10)[0]), proto="unix")
    a.close()
    b.close()

    time.sleep(0.3)
    with open(out, "w") as f:
        json.dump(done, f)


F_GETPATH = 50
# How long the second run of each case keeps its descriptor open.
HOLD = 0.06


def lab(out, directory):
    """Each file case reads or writes its own number of bytes, so that its event can be found."""
    base = os.path.join(directory, "lab")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(os.path.join(base, "sub"))
    real = os.path.realpath(base)
    # The cases through /tmp need the lab under it.
    assert real.startswith("/private/tmp/"), real
    via_tmp = "/tmp" + real[len("/private/tmp") :]
    os.chdir(base)
    cases, sock_cases = [], []
    sizes = iter(range(101, 1000))

    def write_file(path, n=4000):
        with open(path, "wb") as f:
            f.write(b"d" * n)

    def long_path(total):
        p = os.path.join(real, "long")
        while total - len(p) - 1 > 200:
            p = os.path.join(p, "L" * 150)
        p = os.path.join(p, "f" * (total - len(p) - 1 - 4) + ".txt")
        assert len(p) == total, (len(p), total)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        write_file(p)
        return p

    write_file("data.txt")
    write_file("sub/inner.txt")
    write_file("é.txt")
    os.symlink("../data.txt", "sub/rel_up")
    os.symlink("sub", "dirlink")
    os.symlink("../sub", "sub/dirlink2")
    os.symlink("chain2", "chain1")
    os.symlink("data.txt", "chain2")
    os.symlink("/private/etc/hosts", "abs_link")
    os.symlink(via_tmp + "/data.txt", "abs_tmp_link")
    os.makedirs("Fw.framework/Versions/A/Resources")
    write_file("Fw.framework/Versions/A/Resources/Info.plist")
    os.symlink("A", "Fw.framework/Versions/Current")
    os.symlink("Versions/Current/Resources", "Fw.framework/Resources")
    # Lengths around where kdebug splits a looked-up path into records.
    longs = {n: long_path(n) for n in (150, 183, 184, 185, 250, 400)}
    long_rel = os.path.relpath(longs[400], real)
    tmp_rel = os.path.relpath(os.path.join(real, "data.txt"), "/private/tmp")
    ready_then_go(directory)

    def getpath(fd):
        return fcntl.fcntl(fd, F_GETPATH, bytes(1024)).rstrip(b"\0").decode()

    def case(name, arg, opener, write=False):
        for hold in (0, HOLD):
            n = next(sizes)
            fd = opener()
            truth = getpath(fd)
            if write:
                os.write(fd, b"w" * n)
            else:
                os.read(fd, n)
            if hold:
                time.sleep(hold)
            os.close(fd)
            cases.append({"case": name, "arg": arg, "size": n, "hold": hold, "truth": truth})

    def rd(path, **kw):
        return lambda: os.open(path, os.O_RDONLY, **kw)

    case("root link /etc", "/etc/hosts", rd("/etc/hosts"))
    case("final link in another directory", "/usr/share/dict/words", rd("/usr/share/dict/words"))
    case("links with absolute targets", "/etc/localtime", rd("/etc/localtime"))
    case("relative, no link", "data.txt", rd("data.txt"))
    case("absolute, no link", real + "/data.txt", rd(real + "/data.txt"))
    case("absolute through /tmp", via_tmp + "/data.txt", rd(via_tmp + "/data.txt"))
    case("link to absolute target", "abs_link", rd("abs_link"))
    case("link to absolute target through /tmp", "abs_tmp_link", rd("abs_tmp_link"))
    case("link with ../ target", "sub/rel_up", rd("sub/rel_up"))
    case("directory link in cwd", "dirlink/inner.txt", rd("dirlink/inner.txt"))
    case("directory link with ../ target", "sub/dirlink2/inner.txt", rd("sub/dirlink2/inner.txt"))
    case("link chain", "chain1", rd("chain1"))
    case(
        "framework links",
        "Fw.framework/Resources/Info.plist",
        rd("Fw.framework/Resources/Info.plist"),
    )
    for total, path in longs.items():
        case(f"absolute, {total} bytes", path, rd(path))
    case(f"relative, {len(long_rel)} bytes", long_rel, rd(long_rel))
    case("dot-dot", "sub/../data.txt", rd("sub/../data.txt"))
    case("dot and double slash", "./sub//inner.txt", rd("./sub//inner.txt"))
    case("non-ASCII name", "é.txt", rd("é.txt"))
    dfd = os.open("sub", os.O_RDONLY)
    case("openat", "inner.txt @ sub", rd("inner.txt", dir_fd=dfd))
    case("openat with ../", "../data.txt @ sub", rd("../data.txt", dir_fd=dfd))
    os.close(dfd)
    counter = iter(range(1000))
    case(
        "create",
        "new-N.txt",
        lambda: os.open(f"new-{next(counter)}.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644),
        write=True,
    )
    os.chdir("sub")
    case("after chdir sub", "inner.txt", rd("inner.txt"))
    os.chdir("..")
    os.chdir("dirlink")
    case("after chdir through a directory link", "inner.txt", rd("inner.txt"))
    os.chdir("/tmp")
    case("after chdir /tmp", tmp_rel, rd(tmp_rel))
    os.chdir(real)

    def note(name, hold, n, **expect):
        sock_cases.append({"case": name, "hold": hold, "size": n, **expect})

    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(8)
    port = tcp.getsockname()[1]
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix.bind("u.sock")
    unix.listen(8)
    served = []

    def serve(listener):
        while True:
            conn, peer = listener.accept()
            got = len(conn.recv(997))
            served.append(
                {"got": got, "peer": peer if isinstance(peer, str) else f"{peer[0]}:{peer[1]}"}
            )
            conn.sendall(b"r" * 50)
            conn.close()

    for listener in (tcp, unix):
        threading.Thread(target=serve, args=(listener,), daemon=True).start()

    def tcp_client(hold):
        n = next(sizes)
        c = socket.create_connection(("127.0.0.1", port))
        host, local_port = c.getsockname()
        local = f"{host}:{local_port}"
        c.send(b"q" * n)
        c.recv(n)
        time.sleep(hold)
        c.close()
        return n, local

    def udp_send(hold):
        n = next(sizes)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"u" * n, ("127.0.0.1", 9))
        time.sleep(hold)
        s.close()
        return n

    remote = f"127.0.0.1:{port}"
    for hold in (0, 0.005, 0.02, HOLD):
        n, local = tcp_client(hold)
        note("tcp client", hold, n, proto="tcp", remote=remote, local=local)
    for hold in (0, HOLD):
        for how, addr in (("relative", "u.sock"), ("through /tmp", via_tmp + "/u.sock")):
            n = next(sizes)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(addr)
            c.send(b"q" * n)
            c.recv(n)
            time.sleep(hold)
            c.close()
            note(f"unix client, {how}", hold, n, proto="unix", path=real + "/u.sock")
        n = next(sizes)
        a, b = socket.socketpair()
        a.sendmsg([b"m" * n])
        b.recvmsg(n)
        time.sleep(hold)
        a.close()
        b.close()
        note("socketpair", hold, n, proto="unix")
        note("udp", hold, udp_send(hold), proto="udp", remote="127.0.0.1:9")
    # Brief clients one after another: each gets the descriptor the one before just closed.
    for _ in range(12):
        n, local = tcp_client(0)
        note("tcp client, reused number", 0, n, proto="tcp", remote=remote, local=local)
    # UDP sockets whose descriptors go to TCP connections next.
    for _ in range(4):
        note("udp, number then used by tcp", 0, udp_send(0), proto="udp", remote="127.0.0.1:9")
        n, local = tcp_client(0.03)
        note("tcp client after udp", 0.03, n, proto="tcp", remote=remote, local=local)
    time.sleep(0.2)
    os.unlink("u.sock")
    with open(out, "w") as f:
        json.dump(
            {
                "files": cases,
                "sockets": sock_cases,
                "served": served,
                "tcp_port": port,
                "lab": real,
            },
            f,
            indent=1,
        )


def peers(addresses):
    sockets = []
    for addr in addresses:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            # Connecting a UDP socket sends nothing, and neither do the polls.
            s.connect((addr, 9))
        except OSError as err:
            print(f"peers: cannot connect to {addr}: {err}", file=sys.stderr, flush=True)
            continue
        sockets.append(s)
    while True:
        for s in sockets:
            try:
                s.recv(1, socket.MSG_DONTWAIT)
            except OSError:
                pass
        time.sleep(0.2)


def home_writer(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    end = time.monotonic() + 90
    while time.monotonic() < end:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.write(fd, b"x" * 4096)
        os.close(fd)
        time.sleep(0.1)


def write(path, size, chunks):
    # Unbuffered, so each chunk is a write call of its own.
    with open(path, "wb", buffering=0) as f:
        f.writelines(b"c" * (size // chunks) for _ in range(chunks))


def write_later(path, size, chunks):
    time.sleep(0.5)
    write(path, size, chunks)


def paced(directory, size, chunks):
    """Writes too slowly for the records of its writes to fill a trace buffer, however small."""
    ready_then_go(directory)
    chunk = b"p" * (size // chunks)
    with open(os.path.join(directory, "paced"), "wb", buffering=0) as f:
        for n in range(chunks):
            f.write(chunk)
            if n % 32 == 31:
                time.sleep(0.001)
    # Traced until the check that started it stops it.
    time.sleep(60)


def forked(body):
    """Runs `body` in a child process; returns the child's pid."""
    pid = os.fork()
    if pid == 0:
        try:
            body()
        # Whatever happens, the child must not go on with its parent's work.
        except BaseException:  # noqa: BLE001
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    return pid


def family(out, directory):
    """The processes that begin after tracing, but for the twenty brief ones, wait half a
    second before they write, so that on macOS iotap traces them by then."""

    def path(name):
        return os.path.join(directory, name)

    def early():
        wait_for_go(directory)
        write(path("early"), 1 << 20, 4)

    def late():
        write_later(path("late"), 200_000, 2)
        grandchild = forked(lambda: write_later(path("grand"), 30_000, 3))
        with open(path("grand.pid"), "w") as f:
            f.write(str(grandchild))
        os.waitpid(grandchild, 0)

    def by_exec():
        program = os.path.abspath(__file__)
        os.execv(sys.executable, [sys.executable, program, "write", path("exec"), "300000", "3"])

    def brief():
        with open(path("brief"), "ab", buffering=0) as f:
            f.write(b"b" * 100)

    pids = {"program": os.getpid(), "early": forked(early)}
    ready_then_go(directory)
    pids["late"] = forked(late)
    pids["exec"] = forked(by_exec)
    pids["brief"] = []
    for _ in range(20):
        pid = forked(brief)
        os.waitpid(pid, 0)
        pids["brief"].append(pid)
    for role in ("early", "late", "exec"):
        os.waitpid(pids[role], 0)
    with open(path("grand.pid")) as f:
        pids["grand"] = int(f.read())
    with open(out, "w") as f:
        json.dump(pids, f)


def main():
    name, args = sys.argv[1], sys.argv[2:]
    if name == "sockets":
        sockets(*args)
    elif name == "short-udp":
        short_udp()
    elif name == "workload":
        workload(args[0], args[1], int(args[2]))
    elif name == "lab":
        lab(*args)
    elif name == "peers":
        peers(args)
    elif name == "home-writer":
        home_writer(*args)
    elif name == "write":
        write_later(args[0], int(args[1]), int(args[2]))
    elif name == "paced":
        paced(args[0], int(args[1]), int(args[2]))
    elif name == "family":
        family(*args)
    else:
        sys.exit(f"programs.py: no program named {name!r}")


if __name__ == "__main__":
    main()
