"""Hold one exact Linux fixture and its loopback-only network namespace.

The controller supplies identity from its owned disposable container. This local
guard does not create a fixture, attest installation, or confer effect authority.
"""

from __future__ import annotations

import os
import socket
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


class _Session:
    def __init__(self, expected, namespace_fd, init_namespace_fd, init_pidfd):
        self._expected = dict(expected)
        self._fds = namespace_fd, init_namespace_fd, init_pidfd
        self._pid = os.getpid()
        self._start = process._process_start_time(self._pid)
        self._init_start = process._process_start_time(1)
        self._active = True

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
        process.require_live_pidfd(self._fds[2])
        info = _read(f"/proc/self/fdinfo/{self._fds[2]}", 4096)
        require(
            [
                line.split(b":", 1)[1].strip()
                for line in info.splitlines()
                if line.startswith(b"Pid:")
            ]
            == [b"1"],
            "HTTP_INIT_PIDFD_CHANGED",
        )


@contextmanager
def owned_http_fixture(expected_fixture):
    """Retain descriptors until the caller finishes its bounded operation."""
    validate_fixture(expected_fixture)
    expected = dict(expected_fixture)
    descriptors, session = [], None
    try:
        _environment(expected)
        # Namespace links are kernel handles: opening them intentionally follows
        # the procfs link; the resulting object must match the controller's pin.
        descriptors.append(os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC))
        descriptors.append(os.open("/proc/1/ns/net", os.O_RDONLY | os.O_CLOEXEC))
        descriptors.append(os.pidfd_open(1, 0))
        session = _Session(expected, *descriptors)
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
        primary, failed = sys.exception(), False
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException:  # noqa: BLE001 - close remaining owned descriptors even after interruption
                failed = True
        if failed:
            if primary is not None:
                primary.add_note("HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED")
            else:
                require(False, "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED")
