"""Own one fixed UDP socket, cancellation pipe and bounded DNS sample.

No CLI, file retention, protected action, client or complete-interval adapter.
The reviewed fixture helper owns its three descriptors; its private held-FD
layout is pinned as an explicit dependency, never duplicated or closed here.
"""

import errno
import fcntl
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import threading

from . import native_phase3_dns_acquisition as journal
from . import native_phase3_clock_domain as clock
from . import runtime_process_profile as process
from .native_phase3_http_fixture import owned_http_fixture


DnsAcquisitionError = journal.DnsAcquisitionError

# One unresolved owner is held until process exit. There is deliberately no
# recovery/reset API; poisoning prohibits a second socket and bounds retention.
_QUARANTINED_OWNER = None
_ACTIVE_OWNER = None


def _identity(metadata):
    value = dict(device=metadata.st_dev, inode=metadata.st_ino, mode=metadata.st_mode,
                 uid=metadata.st_uid, gid=metadata.st_gid)
    journal._require(all(journal._uint(v, 1 if k == "inode" else 0) for k, v in value.items()), "SOCKET_CHANGED")
    return value


class _Session:
    def __init__(self, cancel_fd):
        self.resources = [dict(fd=cancel_fd, role="CANCEL", obj=None, pin=None)]
        self.cancel_fd = cancel_fd
        self.record = self.request = self.fixture = self.sock = None
        self.namespaces = {}
        self.bound = False
        self.active = True
        self.last_tick = -1
        self.pid = self.tid = None
        self.unreleased_sockets = []
        self.cleanup_codes = []
        self.cleanup_interruption = None
        self.cancel_descriptor_pin = None
        self.entry_owner = None

    @staticmethod
    def observe_owner():
        try:
            value = (os.getpid(), threading.get_native_id(), os.getresuid(), os.getresgid())
            journal._require(journal._uint(value[0], 1) and journal._uint(value[1], 1)
                             and all(type(vector) is tuple and len(vector) == 3
                                     and all(journal._uint(n) for n in vector) for vector in value[2:]), "PROCESS_CHANGED")
            return value
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            raise journal._Fault("PROCESS_CHANGED") from None

    def owner_guard(self):
        journal._require(self.entry_owner is not None, "PROCESS_CHANGED")
        journal._same(self.observe_owner(), self.entry_owner, "PROCESS_CHANGED")

    def own(self, fd, role, obj=None):
        journal._require(type(fd) is int and fd >= 0 and all(r["fd"] != fd for r in self.resources), "SOCKET_CHANGED")
        item = dict(fd=fd, role=role, obj=obj, pin=None)
        self.resources.append(item)
        item["pin"] = _identity(os.fstat(fd))
        return item

    def tick(self):
        try:
            value = clock._stamp()
            journal._require(journal._uint(value) and value >= self.last_tick, "CLOCK_CHANGED")
            self.last_tick = value
            return value
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            raise journal._Fault("CLOCK_CHANGED") from None

    def abi(self):
        try:
            journal._require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("P") == 8
                             and callable(getattr(os, "pidfd_open", None)) and hasattr(clock.time, "CLOCK_BOOTTIME")
                             and getattr(socket, "MSG_DONTWAIT", None) == 64
                             and hasattr(socket, "SOCK_NONBLOCK") and hasattr(socket, "SOCK_CLOEXEC")
                             and hasattr(socket, "SO_REUSEPORT"), "ABI_UNAVAILABLE")
            journal._require(errno.EAGAIN == errno.EWOULDBLOCK == 11, "ABI_UNAVAILABLE")
            release = os.uname().release
            journal._require(type(release) is str and 1 <= len(release) <= 128
                             and all(32 <= ord(c) <= 126 for c in release), "ABI_UNAVAILABLE")
            self.record["kernel_release"] = release
        except (KeyboardInterrupt, SystemExit, MemoryError, journal._Fault):
            raise
        except BaseException:
            raise journal._Fault("ABI_UNAVAILABLE") from None

    def _cancel_guard(self):
        out = self.record["cancellation"]
        try:
            actual = _identity(os.fstat(self.cancel_fd))
            journal._same(actual, self.resources[0]["pin"], "CANCEL_IDENTITY_CHANGED")
            journal._same(actual, self.request["cancellation_identity"], "CANCEL_IDENTITY_CHANGED")
            flags = fcntl.fcntl(self.cancel_fd, fcntl.F_GETFL)
            descriptors = fcntl.fcntl(self.cancel_fd, fcntl.F_GETFD)
            link = os.readlink(f"/proc/self/fd/{self.cancel_fd}")
            descriptor_identity = (flags, descriptors, link)
            if self.cancel_descriptor_pin is None:
                self.cancel_descriptor_pin = descriptor_identity
            else:
                journal._same(descriptor_identity, self.cancel_descriptor_pin, "CANCEL_IDENTITY_CHANGED")
            for name, value in (("status_flags", flags), ("descriptor_flags", descriptors), ("fd_link", link)):
                if out[name] is None:
                    out[name] = value
                else:
                    journal._same(out[name], value, "CANCEL_IDENTITY_CHANGED")
            journal._require(journal._uint(flags) and flags & os.O_ACCMODE == os.O_RDONLY
                             and flags & os.O_NONBLOCK and journal._uint(descriptors) and descriptors & fcntl.FD_CLOEXEC
                             and type(link) is str and link == f"pipe:[{actual['inode']}]" and len(link) <= 64,
                             "CANCEL_IDENTITY_CHANGED")
            journal._same((fcntl.fcntl(self.cancel_fd, fcntl.F_GETFL), fcntl.fcntl(self.cancel_fd, fcntl.F_GETFD)),
                          (flags, descriptors), "CANCEL_IDENTITY_CHANGED")
            journal._same(_identity(os.fstat(self.cancel_fd)), actual, "CANCEL_IDENTITY_CHANGED")
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            self._cancel_mark("IDENTITY_CHANGE")
            raise journal._Fault("CANCEL_IDENTITY_CHANGED") from None

    def _namespace(self, name, fd, path, expected, out=None):
        held, named = os.fstat(fd), os.stat(path)
        values = dict(held_device=held.st_dev, held_inode=held.st_ino,
                      named_device=named.st_dev, named_inode=named.st_ino)
        if out is not None:
            out[name] = values
        journal._require(all(journal._uint(v, 1 if "inode" in k else 0) for k, v in values.items())
                         and stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode), "CLOCK_CHANGED" if name.startswith("time") else "FIXTURE_CHANGED")
        tag = "time" if name.startswith("time") else "net"
        code = "CLOCK_CHANGED" if tag == "time" else "FIXTURE_CHANGED"
        journal._require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) == expected
                         and os.readlink(path) == f"{tag}:[{held.st_ino}]", code)
        if name == "time":
            journal._same(clock._namespace(self.pid, fd), dict(device=held.st_dev, inode=held.st_ino), code)
        return values

    def _namespace_guard(self, out=None):
        if self.fixture is not None:
            expected = self.request["fixture"]
            for name, fd, path in (("network", self.fixture._fds[0], "/proc/self/ns/net"),
                                   ("init_network", self.fixture._fds[1], "/proc/1/ns/net")):
                self._namespace(name, fd, path, (expected["netns_device"], expected["netns_inode"]), out)
        domain = self.request["clock_domain"]
        for name, (fd, path) in self.namespaces.items():
            self._namespace(name, fd, path, (domain["time_namespace_device"], domain["time_namespace_inode"]), out)

    def guard(self):
        journal._require(self.active, "PROCESS_CHANGED")
        self.owner_guard()
        try:
            journal._require(os.getpid() == self.pid == threading.get_native_id() == self.tid
                             and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
                             and self.pid == self.request["observer_process"]["pid"]
                             and process._process_start_time(self.pid) == self.request["observer_process"]["start_time_ticks"], "PROCESS_CHANGED")
        except (KeyboardInterrupt, SystemExit, MemoryError, journal._Fault):
            raise
        except BaseException:
            raise journal._Fault("PROCESS_CHANGED") from None
        if self.fixture is not None:
            try:
                self.fixture.guard()
            except (KeyboardInterrupt, SystemExit, MemoryError):
                raise
            except BaseException:
                raise journal._Fault("FIXTURE_CHANGED") from None
        self._cancel_guard()
        try:
            self._namespace_guard()
        except (KeyboardInterrupt, SystemExit, MemoryError, journal._Fault):
            raise
        except BaseException:
            raise journal._Fault("CLOCK_CHANGED") from None
        if self.sock is not None:
            self.socket_snapshot()
        self._cancel_guard()
        self.owner_guard()

    def _socket_boundary(self):
        item = next(item for item in self.resources if item["obj"] is self.sock)
        fd = item["fd"]
        journal._require(type(self.sock.fileno()) is int and self.sock.fileno() == fd, "SOCKET_CHANGED")
        journal._same(_identity(os.fstat(fd)), item["pin"], "SOCKET_CHANGED")
        flags, descriptors = fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD)
        journal._require(journal._uint(flags) and flags & os.O_NONBLOCK and journal._uint(descriptors)
                         and descriptors & fcntl.FD_CLOEXEC, "SOCKET_CHANGED")
        journal._require(item.get("descriptor_pin") is not None, "SOCKET_CHANGED")
        journal._same((flags, descriptors), item["descriptor_pin"][:2], "SOCKET_CHANGED")
        journal._same(_identity(os.fstat(fd)), item["pin"], "SOCKET_CHANGED")
        journal._require(self.sock.fileno() == fd, "SOCKET_CHANGED")

    def operation_guard(self):
        self._cancel_guard()
        self._socket_boundary()
        self.owner_guard()

    def socket_snapshot(self, target=None):
        try:
            item = next(item for item in self.resources if item["obj"] is self.sock)
            fd = item["fd"]
            journal._require(type(self.sock.fileno()) is int and self.sock.fileno() == fd, "SOCKET_CHANGED")
            current = _identity(os.fstat(fd))
            flags, descriptors = fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD)
            journal._require(journal._uint(flags) and journal._uint(descriptors), "SOCKET_CHANGED")
            values = {**current, "fd_link": os.readlink(f"/proc/self/fd/{fd}"),
                      "host": None, "port": None,
                      "type": self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
                      "reuse_address": self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR),
                      "reuse_port": self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT),
                      "nonblocking": bool(flags & os.O_NONBLOCK) and self.sock.gettimeout() == 0,
                      "cloexec": bool(descriptors & fcntl.FD_CLOEXEC) and not self.sock.get_inheritable()}
            observed = (flags, descriptors, values["fd_link"])
            if "descriptor_pin" not in item:
                item["descriptor_pin"] = observed
            else:
                journal._same(observed, item["descriptor_pin"], "SOCKET_CHANGED")
            address = self.sock.getsockname()
            if type(address) is tuple and len(address) == 2:
                values.update(host=address[0], port=address[1])
            if target is not None:
                target["socket"] = values
            endpoint = (journal.HOST, journal.PORT) if self.bound else ("0.0.0.0", 0)
            journal._same(current, item["pin"], "SOCKET_CHANGED")
            journal._require(stat.S_ISSOCK(current["mode"]) and current["uid"] == current["gid"] == 0
                             and self.sock.family == socket.AF_INET
                             and values["fd_link"] == f"socket:[{current['inode']}]" and len(values["fd_link"]) <= 64
                             and values["host"] == endpoint[0] and type(values["port"]) is int and values["port"] == endpoint[1]
                             and type(values["type"]) is int and values["type"] == socket.SOCK_DGRAM
                             and all(type(values[k]) is int and values[k] == 0 for k in ("reuse_address", "reuse_port"))
                             and values["nonblocking"] and values["cloexec"], "SOCKET_CHANGED")
            try:
                self.sock.getpeername()
            except OSError as exc:
                journal._require(exc.errno == errno.ENOTCONN, "SOCKET_CHANGED")
            else:
                raise journal._Fault("SOCKET_CHANGED")
            self._socket_boundary()
            return values
        except (KeyboardInterrupt, SystemExit, MemoryError, journal._Fault):
            raise
        except BaseException:
            raise journal._Fault("SOCKET_CHANGED") from None

    def _cancel_mark(self, event):
        if self.record is None:
            return
        out = self.record["cancellation"]
        if out["event"] == "NOT_OBSERVED":
            out["event"] = event
            try:
                out["observed_ns"] = self.tick()
            except (KeyboardInterrupt, SystemExit, MemoryError):
                raise
            except BaseException:
                journal._code(self.record, "CLOCK_CHANGED")

    def cancel_events(self, events):
        out = self.record["cancellation"]
        if any(fd != self.cancel_fd or flags & (select.POLLERR | select.POLLNVAL)
               or flags & ~(select.POLLIN | select.POLLHUP) for fd, flags in events):
            self._cancel_mark("IDENTITY_CHANGE")
            raise journal._Fault("CANCEL_IDENTITY_CHANGED")
        if not any(flags & (select.POLLIN | select.POLLHUP) for _, flags in events):
            return
        self.guard()
        self._cancel_guard()
        self.owner_guard()
        try:
            data = os.read(self.cancel_fd, 1)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                out["would_block_reads"] += 1
                journal._require(journal._uint(out["would_block_reads"]), "EVIDENCE_LIMIT")
                self._cancel_guard()
                self.owner_guard()
                return
            self._cancel_mark("READ_ERROR")
            out["read_errno"] = exc.errno if type(exc.errno) is int and 0 < exc.errno < 2**31 else None
            raise journal._Fault("CANCEL_READ_FAILED") from None
        except BaseException:
            self._cancel_mark("READ_ERROR")
            raise
        journal._require(type(data) is bytes and len(data) <= 1, "CANCEL_READ_FAILED")
        out["read_count"] = len(data)
        self._cancel_mark("BYTE" if data else "EOF")
        self._cancel_guard()
        self.owner_guard()
        raise journal._Fault("CANCELLED")

    def check_cancel(self):
        event = self.record["cancellation"]["event"]
        if event in ("BYTE", "EOF"):
            raise journal._Fault("CANCELLED")
        self.guard()
        try:
            poller = select.poll()
            poller.register(self.cancel_fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
            self._cancel_guard()
            self.owner_guard()
            events = poller.poll(0)
            self.guard()
            self.cancel_events(events)
        except (KeyboardInterrupt, SystemExit, MemoryError, journal._Fault):
            raise
        except BaseException:
            raise journal._Fault("POLL_FAILED") from None

    def setup(self):
        for name, path in (("time", "/proc/self/ns/time"), ("time_for_children", "/proc/self/ns/time_for_children")):
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                self.own(fd, "NAMESPACE")
                self.namespaces[name] = (fd, path)
            except (KeyboardInterrupt, SystemExit, MemoryError):
                raise
            except BaseException:
                raise journal._Fault("CLOCK_CHANGED") from None
            self.guard()
        self.check_cancel()
        journal._require(_QUARANTINED_OWNER is None, "SOCKET_CHANGED")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC, socket.IPPROTO_UDP)
            self.own(self.sock.fileno(), "SOCKET", self.sock)
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            raise journal._Fault("SOCKET_CHANGED") from None
        self.check_cancel()
        self.operation_guard()
        try:
            self.sock.bind((journal.HOST, journal.PORT))
            self.bound = True
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            raise journal._Fault("BIND_REFUSED") from None
        self.guard()

    def snapshot(self, edge):
        out = dict(read_started_ns=self.tick(), read_finished_ns=None, observer=None, clock_domain=None,
                   socket=None, proc_udp_raw_hex=None, proc_udp_row=None,
                   raw_process=dict.fromkeys(name for name, _, _ in journal.RAW_SOURCES),
                   namespace_handles=dict.fromkeys(("network", "init_network", "time", "time_for_children")))
        self.record[edge] = out
        try:
            self.guard()
            self._namespace_guard(out["namespace_handles"])
            self.socket_snapshot(out)
            try:
                table = process._read_virtual_file(Path("/proc/net/udp"), 16384)
            except (KeyboardInterrupt, SystemExit, MemoryError):
                raise
            except BaseException:
                raise journal._Fault("PROC_UDP_UNAVAILABLE") from None
            journal._raw(table, 16384, "PROC_UDP_INVALID")
            out["proc_udp_raw_hex"] = table.hex()
            out["proc_udp_row"] = journal._udp(table, out["socket"]["inode"])
            self.guard()
            raw = {}
            for name, path, maximum in journal.RAW_SOURCES:
                code = "CLOCK_CHANGED" if name in ("boot_hex", "timens_offsets_hex") else "PROCESS_CHANGED"
                try:
                    value = process._read_virtual_file(Path(path), maximum)
                    journal._raw(value, maximum, code)
                except (KeyboardInterrupt, SystemExit, MemoryError):
                    raise
                except BaseException:
                    raise journal._Fault(code) from None
                out["raw_process"][name] = value.hex()
                raw[name] = value
                self.guard()
            proc = journal._proc(raw["stat_hex"], raw["status_hex"])
            init = journal._proc(raw["init_stat_hex"], raw["init_status_hex"])
            journal._same(proc, self.request["observer_process"], "PROCESS_CHANGED")
            journal._require(init["pid"] == 1, "PROCESS_CHANGED")
            root = ("0::/docker/" + self.request["fixture"]["container_id"]).encode("ascii")
            journal._require(raw["init_cgroup_hex"] == root + b"/init.scope\n"
                             and raw["cgroup_hex"].endswith(b"\n") and raw["cgroup_hex"].count(b"\n") == 1
                             and (raw["cgroup_hex"] == root + b"\n" or raw["cgroup_hex"].startswith(root + b"/")), "FIXTURE_CHANGED")
            identity = dict(fixture=dict(self.request["fixture"]), process=proc, init_process=init)
            journal._same(self.fixture.identity, identity, "FIXTURE_CHANGED")
            out["observer"] = {**identity, "socket_inode": out["socket"]["inode"]}
            journal._require(raw["boot_hex"] == (self.request["fixture"]["boot_id"] + "\n").encode("ascii"), "CLOCK_CHANGED")
            ns = out["namespace_handles"]["time"]
            domain = dict(clock_id="CLOCK_BOOTTIME", boot_id=raw["boot_hex"][:-1].decode("ascii"),
                          time_namespace_device=ns["held_device"], time_namespace_inode=ns["held_inode"],
                          **journal._offsets(raw["timens_offsets_hex"]))
            out["clock_domain"] = domain
            journal._same(domain, self.request["clock_domain"], "CLOCK_CHANGED")
            self.guard()
        finally:
            journal._finish_mark(self, out, "read_finished_ns")

    def error(self, exc, fallback="RECEIVE_FAILED"):
        if self.record is not None:
            code = "INTERRUPTED" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "EVIDENCE_LIMIT" if isinstance(exc, MemoryError) else exc.code if isinstance(exc, journal._Fault) else fallback
            journal._code(self.record, code)

    def cleanup(self):
        global _QUARANTINED_OWNER
        self.active = False
        while self.resources:
            item = self.resources.pop()
            fd, role, obj = item["fd"], item["role"], item["obj"]
            code = {"CANCEL": "CANCEL_CLOSE_FAILED", "SOCKET": "SOCKET_CLOSE_FAILED", "NAMESPACE": "NAMESPACE_CLOSE_FAILED"}[role]
            attempted = False
            detached_ok = obj is None
            try:
                self.owner_guard()
                if obj is not None:
                    detached = obj.detach()
                    journal._require(type(detached) is int and detached == fd, "SOCKET_CHANGED")
                    detached_ok = True
                current = _identity(os.fstat(fd))
                if role == "CANCEL" and self.record is not None:
                    self.record["cancellation"]["identity_after"] = current
                journal._require(item["pin"] is not None, "CANCEL_IDENTITY_CHANGED" if role == "CANCEL" else "SOCKET_CHANGED")
                journal._same(current, item["pin"], "CANCEL_IDENTITY_CHANGED" if role == "CANCEL" else "SOCKET_CHANGED")
                if role == "CANCEL" and self.cancel_descriptor_pin is not None:
                    journal._same((fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD), os.readlink(f"/proc/self/fd/{fd}")),
                                  self.cancel_descriptor_pin, "CANCEL_IDENTITY_CHANGED")
                if role == "SOCKET":
                    journal._require(item.get("descriptor_pin") is not None, "SOCKET_CHANGED")
                    journal._same((fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD), os.readlink(f"/proc/self/fd/{fd}")),
                                  item["descriptor_pin"], "SOCKET_CHANGED")
                expected_flags = self.cancel_descriptor_pin if role == "CANCEL" else item.get("descriptor_pin") if role == "SOCKET" else None
                if expected_flags is not None:
                    journal._same((fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD)),
                                  expected_flags[:2], "CANCEL_IDENTITY_CHANGED" if role == "CANCEL" else "SOCKET_CHANGED")
                final = _identity(os.fstat(fd))
                if role == "CANCEL" and self.record is not None:
                    self.record["cancellation"]["identity_after"] = final
                journal._same(final, item["pin"], "CANCEL_IDENTITY_CHANGED" if role == "CANCEL" else "SOCKET_CHANGED")
                self.owner_guard()
                attempted = True
                os.close(fd)
                if self.record is not None:
                    if role == "CANCEL":
                        self.record["cancellation"]["closed"] = True
                    elif role == "SOCKET":
                        self.record["socket_closed"] = True
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)) and self.cleanup_interruption is None:
                    self.cleanup_interruption = exc
                if isinstance(exc, journal._Fault) and exc.code == "PROCESS_CHANGED" and self.record is not None:
                    journal._code(self.record, "PROCESS_CHANGED")
                elif not attempted and self.record is not None:
                    journal._code(self.record, {"CANCEL": "CANCEL_IDENTITY_CHANGED", "SOCKET": "SOCKET_CHANGED", "NAMESPACE": "CLOCK_CHANGED"}[role])
                    if role == "CANCEL":
                        try:
                            self._cancel_mark("IDENTITY_CHANGE")
                        except (KeyboardInterrupt, SystemExit, MemoryError) as marked:
                            if self.cleanup_interruption is None:
                                self.cleanup_interruption = marked
                if code not in self.cleanup_codes:
                    self.cleanup_codes.append(code)
                if obj is not None:
                    self.unreleased_sockets.append(obj)
                    if not detached_ok:
                        if _QUARANTINED_OWNER is None:
                            _QUARANTINED_OWNER = self
        if self.record is not None:
            for code in self.cleanup_codes:
                journal._code(self.record, code, cleanup=True)


def capture_dns_acquisition(request_raw: bytes, *, expected_request_digest: str, cancel_fd: int) -> bytes:
    """Consume one cancellation FD and return incomplete sampling bytes only."""
    global _ACTIVE_OWNER
    if type(cancel_fd) is not int or not 0 <= cancel_fd < 2**63:
        raise DnsAcquisitionError("INPUT_REFUSED", None)
    owner, primary = _Session(cancel_fd), None
    try:
        owner.entry_owner = owner.observe_owner()
        owner.pid, owner.tid = owner.entry_owner[:2]
        owner.resources[0]["pin"] = _identity(os.fstat(cancel_fd))
        owner.request = journal._input(request_raw, expected_request_digest)
        owner.record = journal._document(request_raw, expected_request_digest)
        owner.record["cancellation"]["identity_before"] = dict(owner.resources[0]["pin"])
        journal._require(_QUARANTINED_OWNER is None and _ACTIVE_OWNER is None, "SOCKET_CHANGED")
        _ACTIVE_OWNER = owner
        owner.query = journal.readiness_request(owner.request["readiness_nonce"])
        owner.abi()
        owner.guard()
        with owned_http_fixture(owner.request["fixture"]) as fixture:
            owner.fixture = fixture
            try:
                owner.setup()
                owner.snapshot("before")
                owner.guard()
                journal._sample(owner)
            except BaseException as exc:
                primary = exc
                owner.error(exc)
            finally:
                if owner.bound:
                    try:
                        if owner.record["cancellation"]["event"] == "NOT_OBSERVED":
                            owner.check_cancel()
                        owner.snapshot("after")
                    except BaseException as exc:
                        owner.error(exc)
                        if primary is None:
                            primary = exc
                    try:
                        owner.guard()
                    except BaseException as exc:
                        journal._code(owner.record, "FINAL_GUARD_FAILED")
                        owner.error(exc)
                        if primary is None:
                            primary = exc
                owner.cleanup()
                if owner.cleanup_interruption is not None and not isinstance(primary, (KeyboardInterrupt, SystemExit, MemoryError)):
                    primary = owner.cleanup_interruption
                    owner.error(primary)
            if primary is not None:
                raise primary
    except BaseException as exc:
        body_failed = primary is not None
        if primary is None:
            primary = exc
        owner.error(exc, "FIXTURE_CHANGED" if owner.record is not None else "INPUT_REFUSED")
        notes = getattr(exc, "__notes__", ())
        if owner.record is not None:
            if not body_failed and owner.fixture is not None and not owner.active and str(exc) != "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED":
                journal._code(owner.record, "FINAL_GUARD_FAILED")
            if "HTTP_FIXTURE_FINAL_GUARD_FAILED" in notes:
                journal._code(owner.record, "FINAL_GUARD_FAILED")
            if "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED" in notes or str(exc) == "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED":
                journal._code(owner.record, "FIXTURE_CLOSE_FAILED", cleanup=True)
    finally:
        owner.cleanup()
        if _ACTIVE_OWNER is owner:
            _ACTIVE_OWNER = None
        if owner.cleanup_interruption is not None and not isinstance(primary, (KeyboardInterrupt, SystemExit, MemoryError)):
            primary = owner.cleanup_interruption
            owner.error(primary)
    record = owner.record
    if record is not None:
        journal._drop_join(record)
        sample = record["sample"]
        if sample["started_ns"] is not None and sample["finished_ns"] is None:
            try:
                sample["finished_ns"] = owner.tick()
            except BaseException:
                journal._code(record, "CLOCK_CHANGED")
        if record["cancellation"]["event"] in ("BYTE", "EOF"):
            record["status"] = "CANCELLED"
            sample["terminal"] = "CANCELLED"
            journal._code(record, "CANCELLED")
        elif primary is not None or record["errors"] or record["cleanup_codes"]:
            record["status"] = "REFUSED"
            sample["terminal"] = "REFUSED" if sample["started_ns"] is not None else "NOT_STARTED"
        else:
            journal._require(sample["terminal"] == "DEADLINE", "RECEIVE_FAILED")
            record["status"] = "SAMPLED_NOT_COMPLETE"
        try:
            partial = journal.canonical_json(record)
            journal._require(len(partial) <= journal.CAP, "EVIDENCE_LIMIT")
        except MemoryError:
            raise
    else:
        partial = None
    if isinstance(primary, (KeyboardInterrupt, SystemExit, MemoryError)):
        primary.dns_acquisition_partial_raw = partial
        primary.dns_acquisition_cleanup_codes = tuple(record["cleanup_codes"] if record is not None else owner.cleanup_codes)
        raise primary
    if record is None or record["status"] != "SAMPLED_NOT_COMPLETE":
        code = record["errors"][0] if record is not None and record["errors"] else record["cleanup_codes"][0] if record is not None and record["cleanup_codes"] else "INPUT_REFUSED"
        raise DnsAcquisitionError(code, partial, record["cleanup_codes"] if record is not None else owner.cleanup_codes) from primary
    return partial
