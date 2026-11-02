"""Hold one exact Linux fixture and its loopback-only network namespace.

The controller supplies identity from its owned disposable container. This local
guard does not create a fixture, attest installation, or confer effect authority.
"""

from __future__ import annotations

import fcntl
import os
import socket
import stat
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from . import runtime_process_profile as process
from .native_phase3_http_canary_contract import require, validate_fixture


def _namespace(metadata):
    return metadata.st_dev, metadata.st_ino


def _read(path, limit):
    return process._read_virtual_file(Path(path), limit)


def _root_process_status(pid):
    values = {}
    for line in _read(f"/proc/{pid}/status", 16384).splitlines():
        name, separator, remainder = line.partition(b":")
        if separator and name in {b"Uid", b"Gid"}:
            require(name not in values, "HTTP_PROCESS_STATUS_DUPLICATE")
            values[name] = remainder.split()
    require(
        values == {b"Uid": [b"0"] * 4, b"Gid": [b"0"] * 4},
        "HTTP_ROOT_PROCESS_IDENTITY_CHANGED",
    )


def _environment(expected):
    require(
        sys.platform == "linux"
        and os.geteuid() == os.getegid() == 0
        and os.getpid() == threading.get_native_id(),
        "HTTP_LINUX_ROOT_MAIN_THREAD_REQUIRED",
    )
    root = "/docker/" + expected["container_id"]
    require(
        _read("/proc/1/cgroup", 1024)
        == ("0::" + root + "/init.scope\n").encode("ascii"),
        "HTTP_OWNED_FIXTURE_REQUIRED",
    )
    current = _read("/proc/self/cgroup", 1024)
    require(
        (
            current == ("0::" + root + "\n").encode("ascii")
            or current.startswith(("0::" + root + "/").encode("ascii"))
        )
        and current.endswith(b"\n")
        and current.count(b"\n") == 1,
        "HTTP_PROCESS_OUTSIDE_OWNED_FIXTURE",
    )
    require(
        _read("/proc/sys/kernel/random/boot_id", 64)
        == (expected["boot_id"] + "\n").encode("ascii"),
        "HTTP_BOOT_CHANGED",
    )
    require(socket.if_nameindex() == [(1, "lo")], "HTTP_LOOPBACK_ONLY_REQUIRED")


_CLOSE_FAILED = "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED"


def _identity(metadata):
    values = (metadata.st_dev, metadata.st_ino, metadata.st_mode,
              metadata.st_uid, metadata.st_gid)
    require(all(type(value) is int and 0 <= value < 2**63 for value in values)
            and values[1] > 0, _CLOSE_FAILED)
    return values


class _Custody:
    """Local ownership checks, not atomic protection against a hostile FD table."""

    def __init__(self, expected):
        self.pid, self.thread = os.getpid(), threading.get_native_id()
        self.expected = (expected["netns_device"], expected["netns_inode"])
        self.resources = []
        self.cleaning = False
        self.cleanup_interruption = None
        self.owner()

    def owner(self):
        require(os.getpid() == self.pid == threading.get_native_id() == self.thread,
                _CLOSE_FAILED)

    def acquire(self, descriptor, kind, path=None):
        # Record the returned number before the first fallible metadata read.
        row = dict(fd=descriptor, kind=kind, path=path, pin=None, finished=False)
        self.resources.append(row)
        require(type(descriptor) is int and descriptor >= 0
                and all(other is row or other["finished"] or other["fd"] != descriptor
                        for other in self.resources), _CLOSE_FAILED)
        row["pin"] = self.observe(row)
        return row

    def observe(self, row):
        self.owner()
        descriptor = row["fd"]
        held = _identity(os.fstat(descriptor))
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        require(type(flags) is int and 0 <= flags < 2**63
                and type(descriptor_flags) is int and 0 <= descriptor_flags < 2**63
                and descriptor_flags & fcntl.FD_CLOEXEC,
                _CLOSE_FAILED)
        if row["kind"] == "namespace":
            named = _identity(os.stat(row["path"]))
            link = os.readlink(f"/proc/self/fd/{descriptor}")
            require(stat.S_ISREG(held[2]) and stat.S_ISREG(named[2])
                    and held[:2] == named[:2] == self.expected
                    and link == os.readlink(row["path"]) == f"net:[{held[1]}]"
                    and flags & os.O_ACCMODE == os.O_RDONLY, _CLOSE_FAILED)
        elif row["kind"] == "pidfd":
            process.require_live_pidfd(descriptor)
            raw = self.fdinfo(descriptor)
            require(type(raw) is bytes and 0 < len(raw) <= 4096
                    and raw.endswith(b"\n") and b"\0" not in raw and raw.isascii()
                    and [line.partition(b":")[2].strip() for line in raw.splitlines()
                         if line.startswith(b"Pid:")] == [b"1"], _CLOSE_FAILED)
        else:
            require(row["kind"] == "proc" and stat.S_ISREG(held[2])
                    and flags & os.O_ACCMODE == os.O_RDONLY, _CLOSE_FAILED)
        # Association/link reads may themselves run arbitrary Python or fail.
        # Close/read only after their resulting FD flags and held identity agree.
        require(fcntl.fcntl(descriptor, fcntl.F_GETFL) == flags
                and fcntl.fcntl(descriptor, fcntl.F_GETFD) == descriptor_flags
                and _identity(os.fstat(descriptor)) == held, _CLOSE_FAILED)
        self.owner()
        current = held, flags, descriptor_flags
        require(row["pin"] is None or current == row["pin"], _CLOSE_FAILED)
        return current

    def close(self, row):
        require(not row["finished"], _CLOSE_FAILED)
        row["finished"] = True  # A skipped or ambiguous close is never retried.
        require(row["pin"] is not None, _CLOSE_FAILED)
        self.observe(row)
        os.close(row["fd"])

    def remember_interruption(self, exc):
        if (self.cleaning and self.cleanup_interruption is None
                and isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError))):
            self.cleanup_interruption = exc

    def fdinfo(self, descriptor):
        """Read at most 4096 actual bytes through a separately owned proc FD."""
        row = None
        try:
            self.owner()
            fd = os.open(f"/proc/self/fdinfo/{descriptor}",
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            row = self.acquire(fd, "proc")
            raw = bytearray()
            while True:
                self.observe(row)
                chunk = os.read(fd, 4097 - len(raw))
                require(type(chunk) is bytes, _CLOSE_FAILED)
                raw.extend(chunk)
                self.observe(row)
                require(len(raw) <= 4096, _CLOSE_FAILED)
                if not chunk:
                    return bytes(raw)
        finally:
            if row is not None:
                primary = sys.exception()
                # During terminal cleanup an incidental read error is not the
                # outer caller/guard failure. Preserve the first interruption
                # even if this local finally must retain its read exception.
                self.remember_interruption(primary)
                try:
                    self.close(row)
                except BaseException as exc:
                    self.remember_interruption(exc)
                    if primary is not None:
                        primary.add_note(_CLOSE_FAILED)
                    elif isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
                        exc.add_note(_CLOSE_FAILED)
                        raise
                    else:
                        require(False, _CLOSE_FAILED)
                finally:
                    self.resources.remove(row)

    def guard(self):
        for row in tuple(self.resources):
            require(not row["finished"], _CLOSE_FAILED)
            self.observe(row)

    def cleanup(self, primary):
        failed = False
        self.cleaning = True
        try:
            for row in reversed(tuple(self.resources)):
                if row["finished"]:
                    continue
                try:
                    self.close(row)
                except BaseException as exc:
                    failed = True
                    self.remember_interruption(exc)
        finally:
            self.cleaning = False
        if failed:
            if primary is not None:
                primary.add_note(_CLOSE_FAILED)
            elif self.cleanup_interruption is not None:
                self.cleanup_interruption.add_note(_CLOSE_FAILED)
                raise self.cleanup_interruption
            else:
                require(False, _CLOSE_FAILED)


class _Session:
    def __init__(self, expected, namespace_fd, init_namespace_fd, init_pidfd, custody):
        self._expected = dict(expected)
        self._fds = namespace_fd, init_namespace_fd, init_pidfd
        self._pid = os.getpid()
        self._start = process._process_start_time(self._pid)
        self._init_start = process._process_start_time(1)
        self._active = True
        self._custody = custody

    @property
    def identity(self):
        self.guard()
        return {
            "fixture": dict(self._expected),
            "process": {
                "pid": self._pid,
                "start_time_ticks": self._start,
                "uid": 0,
                "gid": 0,
            },
            "init_process": {
                "pid": 1,
                "start_time_ticks": self._init_start,
                "uid": 0,
                "gid": 0,
            },
        }

    def guard(self):
        require(self._active, "HTTP_FIXTURE_SESSION_CLOSED")
        self._custody.guard()
        _environment(self._expected)
        expected = self._expected["netns_device"], self._expected["netns_inode"]
        require(
            _namespace(os.fstat(self._fds[0]))
            == _namespace(os.fstat(self._fds[1]))
            == _namespace(os.stat("/proc/self/ns/net"))
            == _namespace(os.stat("/proc/1/ns/net"))
            == expected,
            "HTTP_NETWORK_NAMESPACE_CHANGED",
        )
        require(
            os.getpid() == self._pid
            and process._process_start_time(self._pid) == self._start
            and process._process_start_time(1) == self._init_start,
            "HTTP_PROCESS_IDENTITY_CHANGED",
        )
        _root_process_status(self._pid)
        _root_process_status(1)
        # Closing custody includes the original live PID 1 association check.
        self._custody.guard()


@contextmanager
def owned_http_fixture(expected_fixture):
    """Retain descriptors until the caller finishes its bounded operation."""
    validate_fixture(expected_fixture)
    expected = dict(expected_fixture)
    custody, session = _Custody(expected), None
    try:
        _environment(expected)
        # Namespace links are kernel handles: opening them intentionally follows
        # the procfs link; the resulting object must match the controller's pin.
        for path in ("/proc/self/ns/net", "/proc/1/ns/net"):
            custody.owner()
            custody.acquire(os.open(path, os.O_RDONLY | os.O_CLOEXEC), "namespace", path)
        custody.owner()
        custody.acquire(os.pidfd_open(1, 0), "pidfd")
        session = _Session(expected, *(row["fd"] for row in custody.resources), custody=custody)
        session.guard()
        try:
            yield session
        finally:
            primary = sys.exception()
            try:
                session.guard()
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("HTTP_FIXTURE_FINAL_GUARD_FAILED")
    finally:
        if session is not None:
            session._active = False
        custody.cleanup(sys.exception())
