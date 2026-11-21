"""Single-purpose witness for the armed Pi gate. No arbitrary executable, path, or operation."""
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager

from .oci_worker_protocol import canonical_json


_NAMES = ("pts", "shm", "hugepages", "ptmx")
_MAX = 16384
# Execute only this source, using the already approved immutable coordinator
# interpreter. Load the trusted stdlib before entering the worker's root.
_PROGRAM = r'''
import ctypes, errno, json, os, signal, socket, struct, sys, time
def main():
    if len(sys.argv) != 10:
        return 1
    rt, ns, ch, exe, uid, gid, parent, mask = map(int, sys.argv[1:9])
    deadline = int(sys.argv[9]) / 1e9
    if min(rt, ns, ch, exe) < 3 or len({rt,ns,ch,exe}) != 4 or min(uid,gid) <= 0 or not (0 < mask < 16 and mask & 1):
        return 1
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    def ctl(key, arg):
        if libc.prctl(key, arg, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl")
    ctl(1, signal.SIGKILL)
    if os.getppid() != parent or not 0 < deadline - time.monotonic() <= 5:
        return 2
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, deadline-time.monotonic()))
    channel = socket.socket(fileno=ch)
    os.close(exe)
    os.setns(ns, os.CLONE_NEWNS)
    os.close(ns)
    os.fchdir(rt)
    os.chroot(".")
    os.chdir("/")
    os.close(rt)
    ctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    ctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
    for bit in range(64):
        if libc.prctl(24, bit, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
            return 3
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    ctl(1, signal.SIGKILL)  # credential transitions clear PDEATHSIG
    if os.getppid() != parent:
        return 4
    dev = os.open("/dev", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    def names():
        out = []
        with os.scandir(dev) as scan:
            for ent in scan:
                n = ent.name
                if len(out) >= 256 or not 0 < len(n) <= 255 or not n.isascii() or not n.isprintable():
                    raise ValueError("unbounded /dev")
                out.append(n)
        return sorted(out)
    def emit(obj):
        raw = json.dumps(obj, separators=(",",":"), sort_keys=True).encode("ascii")
        if len(raw) >= 16384 or channel.send(raw) != len(raw):
            raise ValueError("invalid frame")
    emit(dict(fd=dev, names=names()))
    if channel.recv(2) != b"G":
        return 5
    calls = {}
    for i,name in enumerate(("pts","shm","hugepages","ptmx")):
        if not (mask & (1 << i)):
            continue
        path = name.encode("ascii")
        buf = ctypes.create_string_buffer(256)
        link = name == "ptmx"
        flags = 0 if link else 0o2140000
        ctypes.set_errno(0)
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        rc = (libc.syscall(79, dev, path, ctypes.byref(buf), 0) if link else
              libc.syscall(56, dev, path, flags, 0))
        err = ctypes.get_errno() if rc == -1 else 0
        end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if not link and rc >= 0:
            os.close(rc)
        calls[name] = dict(syscall="newfstatat" if link else "openat", name=name, dirfd=dev,
                           flags=flags, result=rc, errno=err, started_ns=start, finished_ns=end)
    emit(dict(calls=calls, names=names()))
    if channel.recv(2) != b"X":
        return 6
    os.close(dev)
    channel.close()
    return 0
try:
    code = main()
except BaseException:
    code = 7
os._exit(code)
'''


def _need(ok, why):
    if not ok:
        raise ValueError("stopped mask probe: " + why)


def _left(deadline):
    left = deadline - time.monotonic()
    _need(left > 0, "deadline")
    return left


def _recv(sock, deadline, fields):
    sock.settimeout(_left(deadline))
    raw = sock.recv(_MAX)
    _need(0 < len(raw) < _MAX, "missing, oversized or truncated packet")
    value = json.loads(raw)
    _need(type(value) is dict and value.keys() == set(fields) and canonical_json(value) == raw, "unexpected packet")
    return value


def _names(value):
    _need(type(value) is list and len(value) <= 256 and all(type(n) is str and 0 < len(n) <= 255 and
          n not in (".", "..") and "/" not in n and n.isascii() and n.isprintable() for n in value)
          and value == sorted(set(value)), "invalid /dev listing")
    return value


@contextmanager
def _held_child(proc, cleanup_deadline):
    # Popen owns this unreaped child. Never signal a PID obtained from a packet.
    try:
        yield
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=_left(cleanup_deadline))


def _attest_frame(view, worker, helper, dev, child_pid):
    """Require actual bounded principals and the same held view before any go packet."""
    from . import pi_core_state_masks as masks
    from .pi_core_stopped_mask_view import _stat

    subject = view.worker
    masks._subject(subject)
    _need(subject["mount_namespace"] == os.fstat(view.mntns_fd).st_ino and
          subject["user_namespace"] == os.fstat(view.userns_fd).st_ino, "captured namespaces differ")
    # State-volume eligibility is independently checked in the archive. Here
    # actual namespace/file handles and full typed statx identities must match.
    root = masks._stat(_stat(view.root_fd), {"0:0"})
    actual_dev = masks._stat(_stat(view.dev_fd), {"0:0"})
    _need(stat.S_ISDIR(root["mode"]) and stat.S_ISDIR(actual_dev["mode"])
          and masks._stat(dev, {"0:0"}) == actual_dev, "probe not using held worker /dev")
    masks._context(worker, subject, root, {"0:0"}, probe=False)
    masks._context(helper, subject, root, {"0:0"}, probe=True)
    _need(helper["pid"] == child_pid and child_pid not in (subject["pid"], os.getpid()),
          "wrong owned child generation")


def observe_mask_denials(view, *, deadline, cleanup_deadline, interpreter_digest):
    from . import pi_core_node_source_observer as node
    from .pi_core_stopped_mask_view import _probe_frame
    from .runtime_process_profile import require_live_pidfd

    _need(os.uname().sysname == "Linux" and os.uname().machine in ("aarch64", "arm64")
          and os.getuid() == os.geteuid() == 0 and sys.version_info >= (3, 12), "requires protected guest interpreter")
    _need(os.path.samestat(os.stat("/proc/self/ns/user"), os.fstat(view.userns_fd)), "foreign user namespace")
    names = set(view.names)
    _need("pts" in names and names <= set(_NAMES), "unapproved mask names")
    mask = sum(1 << i for i,n in enumerate(_NAMES) if n in names)
    operation = min(deadline, time.monotonic() + 5)
    with ExitStack() as held:
        exe = os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC)
        held.callback(os.close, exe)
        digest, _ = node._hash_readonly(exe, operation, 128 << 20)
        _need(digest == interpreter_digest and os.path.samestat(os.stat(sys.executable), os.fstat(exe)),
              "interpreter identity changed")
        sock, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        held.enter_context(sock)
        held.enter_context(peer)
        fds = (view.root_fd, view.mntns_fd, peer.fileno(), exe)
        _need(min(fds) >= 3 and len(set(fds)) == 4, "overlapping descriptors")
        args = [*fds, view.worker["uid"], view.worker["gid"], os.getpid(), mask, int(operation * 1e9)]
        _left(operation)
        proc = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", _PROGRAM, *map(str, args)],
                                executable=f"/proc/self/fd/{exe}", pass_fds=fds, close_fds=True,
                                env={}, cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        held.enter_context(_held_child(proc, cleanup_deadline))
        peer.close()
        pidfd = os.pidfd_open(proc.pid, 0)
        held.callback(os.close, pidfd)
        first = _recv(sock, operation, ("fd", "names"))
        fd = first["fd"]
        _need(type(fd) is int and 3 <= fd < 1 << 31, "bad /dev descriptor")
        before_names = _names(first["names"])
        _need(set(before_names) & set(_NAMES) == names, "observer/probe mask set differs")
        def frame():
            require_live_pidfd(pidfd)
            _need(os.path.samestat(os.stat(f"/proc/{proc.pid}/exe"), os.fstat(exe)), "probe executable changed")
            worker = view.worker_context()
            helper, dev = _probe_frame(proc.pid, fd, operation)
            _attest_frame(view, worker, helper, dev, proc.pid)
            require_live_pidfd(pidfd)
            return dict(worker=worker, probe=helper, dev_fd=fd, dev_stat=dev,
                        boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        before = frame()
        sock.settimeout(_left(operation))
        _need(sock.send(b"G") == 1, "probe not started")
        actual = _recv(sock, operation, ("calls", "names"))
        after = frame()
        after_names = _names(actual["names"])
        _need(before_names == after_names and all(before[k] == after[k] for k in ("worker", "probe", "dev_fd", "dev_stat"))
              and type(actual["calls"]) is dict and actual["calls"].keys() == names, "incomplete or changed probe")
        sock.settimeout(_left(operation))
        _need(sock.send(b"X") == 1 and proc.wait(timeout=_left(operation)) == 0, "uncertain probe retirement")
    return before, after, before_names, after_names, actual["calls"]
