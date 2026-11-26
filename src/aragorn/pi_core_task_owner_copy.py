"""Resolve the fixed task's transferred copy directory in the service descriptor table."""
from contextlib import ExitStack
import ctypes
import fcntl
import os
import stat

from . import pi_core_task_copy_observation as copy, pi_core_task_guest_binding as binding
from .oci_worker_protocol import canonical_digest
from .pi_core_state_admission import _keys, _need, _uint


def check_source_fd(ticket, directory_fd):
    """Call before lending any directory; for a compute ticket there must be no FD."""
    if "copy" not in ticket:
        _need(directory_fd is None, "unexpected task copy directory")
        return
    identity = ticket["copy"]["directory_identity"]
    _keys(identity, ("device", "inode", "mode", "uid", "gid"))
    meta = os.fstat(_uint(directory_fd, 3, 1 << 31))
    flags = fcntl.fcntl(directory_fd, fcntl.F_GETFL)
    # The reference task fsyncs this directory after its exclusive write. O_PATH cannot do that.
    _need(flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, "O_PATH", 0)
          and not os.fstatvfs(directory_fd).f_flag & os.ST_RDONLY, "copy directory is not a usable writable sink")
    _need(all(type(v) is int for v in identity.values()) and stat.S_ISDIR(meta.st_mode)
          and identity == copy._identity(meta) and identity["mode"] == 0o700
          and [identity["uid"], identity["gid"]] == ticket["service_peer"][1:], "different copy directory at sender")


def _receiver_fds(pid, deadline):
    k = copy.kernel
    with ExitStack() as held:
        proc, mount = k._proc(held)
        _, role = k._role(held, proc, pid, mount)
        table = k._proc_child(held, role, "fd", os.O_RDONLY | os.O_DIRECTORY, mount)
        names = k._names(table, deadline, 256)
        _need(all(n.isdecimal() and n == str(int(n)) and int(n) < 1 << 31 for n in names), "invalid receiver FD table")
        return [int(n) for n in names]


def _same_description(pid, local, remote):
    # ARM64 Linux KCMP_FILE: unlike an inode match this proves the SCM_RIGHTS open description.
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(272), ctypes.c_int(os.getpid()), ctypes.c_int(pid), ctypes.c_int(0),
                          ctypes.c_ulong(local), ctypes.c_ulong(remote))
    if result < 0:
        raise OSError(ctypes.get_errno(), "cannot verify service-side open description")
    _need(result in (0, 1, 2, 3), "unknown open-description comparison")
    return result == 0


def resolve_service_copy(ticket, *, nomination, nomination_pin, service_start_ticks, directory_fd, deadline):
    """After witness connect, before any request byte. A missing kernel proof is never an inode-only match."""
    binding._nomination(ticket, nomination, nomination_pin)
    _need(nomination["manager_peer"] == [os.getpid(), 0, 0] and "copy" in ticket, "not the nominated copy manager")
    _uint(service_start_ticks)
    check_source_fd(ticket, directory_fd)
    pid, uid, gid = nomination["service_peer"]
    identity = ticket["copy"]["directory_identity"]
    expected = dict(unit=copy._UNIT, pid=pid, invocation_id=nomination["service_invocation_id"], start_ticks=service_start_ticks,
                    uid=uid, gid=gid, boot_id=ticket["clock"]["boot_id"], time_ns=ticket["clock"]["time_namespace_inode"])

    def unique_receiver():
        matches = []
        for fd in _receiver_fds(pid, deadline):
            copy.kernel._check(deadline)
            if _same_description(pid, directory_fd, fd):
                matches.append(fd)
        _need(len(matches) == 1 and matches[0] >= 3, "unverified or ambiguous service-side copy FD")
        return matches[0]

    with copy._hold_process(pid) as pidfd:
        fd = unique_receiver()
        guest, remote_dir = copy._read_guest(expected, directory_fd, fd, pidfd, deadline)
        _need(remote_dir == identity and all(guest[k] == v for k, v in expected.items())
              and guest["observer_mount_id"] == guest["service_mount_id"], "different service generation, mount or copy directory")
        _need(unique_receiver() == fd, "service-side copy FD changed")
        copy.native.process.require_live_pidfd(pidfd)
        check_source_fd(ticket, directory_fd)
        request_pin = canonical_digest(ticket["request"])
        fixture = dict(schema="aragorn/pi-core-task-copy-fixture/v1", request_digest=request_pin,
                       guest=guest, directory_identity=identity)
        _need(canonical_digest(fixture) == ticket["copy"]["fixture_digest"], "different nominated copy fixture")
        return copy.ManagedCopyObserver(directory_fd=directory_fd, service_directory_fd=fd, request_digest=request_pin,
                                        guest=guest, directory_identity=identity)
