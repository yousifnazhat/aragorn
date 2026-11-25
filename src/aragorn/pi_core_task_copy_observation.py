"""Independent, guest-side observation of one scheduled reference-task copy."""

from contextlib import ExitStack, contextmanager
import hashlib
import os
import re
import stat
import threading

from . import pi_core_native_supervisor as native, pi_core_stopped_mask_view as kernel
from . import pi_core_sensor_state_observer as proc
from .native_phase3_workload_copy_readback_verify import _identity, _INPUT
from .oci_worker_protocol import canonical_digest
from .pi_core_state_admission import _keys, _need, _pin, _uint, _uuid


_UNIT = "aragorn-pi-task.service"
_GROUP = "/system.slice/" + _UNIT
_TARGET = "allowed-copy.txt"
_RO = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_GUEST_NUMBERS = ("pid", "start_ticks", "uid", "gid", "observer_mount_ns", "service_mount_ns",
                  "time_ns", "observer_mount_id", "service_mount_id")


def _unit(pid, expected_invocation, deadline):
    fields = ("Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ExecMainPID", "ControlGroup")
    code, raw = native._command(("/usr/bin/systemctl", "show", "--all", "--property=" + ",".join(fields), _UNIT), deadline)
    rows = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    expected = dict(Id=_UNIT, ActiveState="active", SubState="running", InvocationID=expected_invocation,
                    MainPID=str(pid), ExecMainPID=str(pid), ControlGroup=_GROUP)
    _need(code == 0 and len(rows) == len(fields) and all(len(row) == 2 for row in rows)
          and dict(rows) == expected, "different task service invocation")
    return dict(rows)["InvocationID"]


@contextmanager
def _hold_process(pid):
    kernel._platform()
    _need(threading.get_native_id() == os.getpid() != pid, "independent guest observer must be the root main thread")
    fd = os.pidfd_open(pid, 0)
    try:
        native.process.require_live_pidfd(fd)
        yield fd
    finally:
        os.close(fd)


def _read_guest(guest, directory_fd, remote_fd, pidfd, deadline):
    pid = guest["pid"]
    kernel._check(deadline)
    native.process.require_live_pidfd(pidfd)
    invocation = _unit(pid, guest["invocation_id"], deadline)
    with ExitStack() as stack:
        root, mid = kernel._proc(stack)
        _, manager = kernel._role(stack, root, os.getpid(), mid)
        _, service = kernel._role(stack, root, pid, mid)
        ticks, _, states, _, creds = kernel._parse_subject(kernel._read(service, "stat", 8192, mid, deadline),
            kernel._read(service, "status", 65536, mid, deadline), pid)
        kernel._limited(creds)
        _need(all(s in ("S", "R", "D") for s in states)
              and kernel._read(service, "cgroup", 8192, mid, deadline) == ("0::" + _GROUP + "\n").encode(),
              "task service is not live in its fixed cgroup")
        time_ns = proc._namespace(stack, manager, "time", mid)
        _need(time_ns == proc._namespace(stack, service, "time", mid), "task service clock namespace differs")
        fds = kernel._proc_child(stack, service, "fd", os.O_RDONLY | os.O_DIRECTORY, mid)
        remote = kernel._magic(stack, fds, str(remote_fd), os.O_PATH | os.O_DIRECTORY, mid)
        actual = dict(unit=_UNIT, invocation_id=invocation, pid=pid, start_ticks=ticks,
            uid=creds["uid"], gid=creds["gid"], boot_id=proc._boot_id(stack, root, mid, deadline), time_ns=time_ns,
            observer_mount_ns=proc._namespace(stack, manager, "mnt", mid),
            service_mount_ns=proc._namespace(stack, service, "mnt", mid),
            observer_mount_id=kernel._stat(directory_fd)["mnt_id"], service_mount_id=kernel._stat(remote)["mnt_id"])
        _need(actual["observer_mount_ns"] != actual["service_mount_ns"], "service lacks a separate mount namespace")
        remote_identity = _identity(os.fstat(remote))
    native.process.require_live_pidfd(pidfd)
    kernel._check(deadline)
    return actual, remote_identity


def _guest_edge(guest, directory_fd, remote_fd, pidfd, directory, deadline):
    actual, remote_directory = _read_guest(guest, directory_fd, remote_fd, pidfd, deadline)
    _need(actual == guest and remote_directory == directory, "different guest generation, namespace or nominated directory")


def _file_identity(meta):
    _need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600
          and meta.st_size == len(_INPUT), "copy target is not the fixed single-link file")
    return dict(_identity(meta), nlink=meta.st_nlink, size=meta.st_size,
                mtime_ns=meta.st_mtime_ns, ctime_ns=meta.st_ctime_ns)


def _same_mount(directory, opened, nominated):
    with ExitStack() as stack:
        named = kernel._own(stack, _TARGET, os.O_PATH | os.O_NOFOLLOW, directory)
        _need(all(kernel._stat(fd)["mnt_id"] == nominated for fd in (directory, opened, named))
              and _file_identity(os.fstat(opened)) == _file_identity(os.fstat(named)), "copy file mount changed")


def _contents(directory, single_name=None):
    with ExitStack() as stack:
        # A fresh open file description on each check; never depend on scandir's prior offset.
        scanfd = kernel._own(stack, ".", _RO | os.O_DIRECTORY, directory)
        with os.scandir(scanfd) as entries:
            first = next(entries, None)
            _need(first is None if single_name is None else first is not None and first.name == single_name
                  and next(entries, None) is None, "copy directory not fresh or contains foreign residue")


class ManagedCopyObserver:
    """The private manager supplies both nominations; neither the worker nor receipt chooses a path."""

    def __init__(self, *, directory_fd, service_directory_fd, request_digest, guest, directory_identity):
        self._fd, self._remote = _uint(directory_fd, 3, 1 << 31), _uint(service_directory_fd, 3, 1 << 31)
        self._request = _pin(request_digest)
        _keys(guest, (*_GUEST_NUMBERS, "unit", "invocation_id", "boot_id"))
        for k in _GUEST_NUMBERS:
            _uint(guest[k])
        _uuid(guest["boot_id"])
        _need(guest["unit"] == _UNIT and isinstance(guest["invocation_id"], str)
              and re.fullmatch("[0-9a-f]{32}", guest["invocation_id"])
              and int(guest["invocation_id"], 16) and guest["observer_mount_ns"] != guest["service_mount_ns"],
              "invalid task service nomination")
        _keys(directory_identity, ("device", "inode", "mode", "uid", "gid"))
        for k in directory_identity:
            _uint(directory_identity[k], 0 if k == "device" else 1)
        _need(directory_identity["mode"] == 0o700 and
              all(directory_identity[k] == guest[k] for k in ("uid", "gid")), "private task-owned copy directory required")
        self._guest, self._dir = dict(guest), dict(directory_identity)
        self._used = False

    @contextmanager
    def observing(self, request_digest, *, deadline):
        kernel._check(deadline)
        _need(not self._used and self._request == request_digest, "copy observation already spent or wrong request")
        self._used = True
        with ExitStack() as stack:
            pidfd = stack.enter_context(_hold_process(self._guest["pid"]))
            directory = kernel._own(stack, ".", _RO | os.O_DIRECTORY, self._fd)
            def guard():
                kernel._check(deadline)
                _need(_identity(os.fstat(directory)) == _identity(os.fstat(self._fd)) == self._dir,
                      "nominated copy directory changed")
                _guest_edge(self._guest, directory, self._remote, pidfd, self._dir, deadline)
            guard()
            # Even unrelated pre-existing residue invalidates the initial fixture.
            _contents(directory)
            active, spent, matched, file_fd, pinned = True, False, False, None, None
            def file_guard():
                named = _file_identity(os.stat(_TARGET, dir_fd=directory, follow_symlinks=False))
                _need(named == pinned == _file_identity(os.fstat(file_fd)) and named["device"] == self._dir["device"]
                      and all(named[k] == self._dir[k] for k in ("uid", "gid")), "copy file identity changed")
                _same_mount(directory, file_fd, self._guest["observer_mount_id"])
                _contents(directory, _TARGET)
            def observe():
                nonlocal spent, matched, file_fd, pinned
                _need(active and not spent, "copy readback already spent or closed")
                spent = True
                guard()
                pinned = _file_identity(os.stat(_TARGET, dir_fd=directory, follow_symlinks=False))
                file_fd = kernel._own(stack, _TARGET, _RO, directory)
                file_guard()
                content = os.read(file_fd, len(_INPUT) + 1)
                _need(content == _INPUT, "independently observed copy bytes differ")
                file_guard()
                matched = True
                fixture = dict(schema="aragorn/pi-core-task-copy-fixture/v1", request_digest=self._request,
                               guest=dict(self._guest), directory_identity=dict(self._dir))
                return dict(fixture, schema="aragorn/pi-core-task-copy-observation/v1", fixture_digest=canonical_digest(fixture),
                            file_identity=dict(pinned), content_hex=content.hex(), content_digest="sha256:"+hashlib.sha256(content).hexdigest(),
                            exclusive_writer_verified=False, phase3_exit_eligible=False)
            try:
                yield observe
                _need(matched, "no successful independent copy readback")
                guard()
                file_guard()
            finally:
                active = False
