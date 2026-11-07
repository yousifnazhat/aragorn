"""Explicit Linux arm64 ptrace source-read custody, never import-time activation.

This initial backend supports ONE stopped task and read/pread64 only. It refuses
threads, file-backed mmap and every unclassified read descriptor. Consequently
normal dynamically linked/threaded Node startup is NOT supported or healthy.
It is a real acquisition engine, not a callback-fed evidence constructor.
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import stat
import threading
import time

from . import pi_core_native_supervisor as native
from . import pi_core_bundle_launch as bundle
from . import pi_core_confined_launch as confined
from . import pi_core_worker_identity as identity
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-source-observation/v1"
INVENTORY_SCHEMA = "aragorn/pi-core-source-inventory/v1"
MAX_RAW, MAX_EVENTS, MAX_FILE = 4 * 1024 * 1024, 4096, 16 * 1024 * 1024
GATE_PATH = Path("/opt/aragorn/pi-runtime/observer/source-gate")
NODE_PATH = Path("/opt/aragorn/pi-runtime/node/bin/node")
ENTRY_PATH = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"
PRODUCER_PATH = Path("/opt/aragorn/src/aragorn/pi_core_source_observer.py")
CHALLENGE_NS = 100_000_000
OPTIONS = 0x10005F
_SEAL = object()
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARM64 = 0xC00000B7
_SEIZE, _INTERRUPT, _SYSCALL, _GETINFO, _GETMSG = 0x4206, 0x4207, 24, 0x420E, 0x4201
_DENIED = frozenset((65, 69, 71, 75, 76, 77, 117, 220, 270, 271, 277, 281, 285, 286, 425, 426, 427, 435))
_ORDINARY = frozenset((56, 57, 62, 79, 80, 93, 94, 98, 113, 124, 134, 135,
                       172, 173, 174, 175, 176, 177, 178, 214, 215, 226, 233, 261, 278))
_BINDINGS = frozenset(("deployment_digest", "runtime_digest", "gate_digest", "node_digest",
                       "producer_digest", "source_inventory_digest"))


class PiSourceObserverError(RuntimeError):
    """The custody object remains attached for explicit, ownership-safe cleanup."""

    def __init__(self, reason, observer=None):
        super().__init__(reason)
        self.observer = observer


def _require(value, reason):
    if not value:
        raise PiSourceObserverError(reason)


def _tick():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _file_identity(value):
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
                nlink=value.st_nlink, uid=value.st_uid, gid=value.st_gid,
                size=value.st_size, mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns)


def _protected_file(fd, maximum=MAX_FILE):
    value = os.fstat(fd)
    _require(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0 and value.st_nlink == 1 and
             not value.st_mode & 0o7222 and 0 <= value.st_size <= maximum,
             "SOURCE_FILE_METADATA")
    return _file_identity(value)


def _hash(fd, deadline, maximum=MAX_FILE):
    before = _protected_file(fd, maximum)
    value, offset = hashlib.sha256(), 0
    while offset < before["size"]:
        _require(time.monotonic() < deadline, "SOURCE_HASH_DEADLINE")
        chunk = os.pread(fd, min(65536, before["size"] - offset), offset)
        _require(chunk, "SOURCE_HASH_SHORT_READ")
        value.update(chunk)
        offset += len(chunk)
    _require(_protected_file(fd, maximum) == before, "SOURCE_CHANGED_WHILE_HASHED")
    return "sha256:" + value.hexdigest(), before


def _open_view(pid, path):
    """Open the captured process's filesystem view, without following leaf links."""
    _require(type(path) is Path or isinstance(path, Path), "SOURCE_PATH_TYPE")
    _require(path.is_absolute() and str(path) == os.path.normpath(str(path)) and
             ".." not in path.parts and str(path) != "/", "SOURCE_PATH")
    directory = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        info = os.fstat(directory)
        _require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, "SOURCE_ROOT_ANCESTRY")
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = next_fd
            info = os.fstat(directory)
            _require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, "SOURCE_ANCESTRY")
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        try:
            _require(stat.S_ISREG(os.fstat(leaf).st_mode), "SOURCE_LEAF_NOT_REGULAR")
            return leaf
        except BaseException:
            os.close(leaf)
            raise
    finally:
        os.close(directory)


class _Entry(ctypes.Structure):
    _fields_ = [("nr", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]


class _Exit(ctypes.Structure):
    _fields_ = [("rval", ctypes.c_int64), ("is_error", ctypes.c_uint8)]


class _Payload(ctypes.Union):
    _fields_ = [("entry", _Entry), ("exit", _Exit)]


class _SyscallInfo(ctypes.Structure):
    _fields_ = [("op", ctypes.c_uint8), ("reserved", ctypes.c_uint8 * 3),
                ("arch", ctypes.c_uint32), ("ip", ctypes.c_uint64), ("sp", ctypes.c_uint64),
                ("payload", _Payload)]


class _Kernel:
    """Exact Linux ABI, constructed only after explicit platform guards."""

    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.libc.syscall.restype = ctypes.c_long

    def ptrace(self, request, pid, address=0, data=0):
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, pid, address, data)
        error = ctypes.get_errno()
        if result == -1 and error:
            raise OSError(error, "ptrace acquisition failed")
        return result

    def duplicate(self, pidfd, fd):
        ctypes.set_errno(0)
        result = self.libc.syscall(ctypes.c_long(438), ctypes.c_int(pidfd), ctypes.c_int(fd), ctypes.c_uint(0))
        if result < 0:
            raise OSError(ctypes.get_errno(), "pidfd_getfd failed")
        return result

    def info(self, pid):
        info = _SyscallInfo()
        size = self.ptrace(_GETINFO, pid, ctypes.sizeof(info), ctypes.byref(info))
        _require(info.arch == _ARM64 and not any(info.reserved), "SYSCALL_ABI")
        _require(info.op in (1, 2) and size == (80 if info.op == 1 else 33), "SYSCALL_INFO_SIZE")
        if info.op == 1:
            return "ENTRY", int(info.payload.entry.nr), list(info.payload.entry.args), None, None
        _require(info.payload.exit.is_error in (0, 1), "SYSCALL_EXIT_ERROR_FLAG")
        return "EXIT", None, None, int(info.payload.exit.rval), bool(info.payload.exit.is_error)

    def message(self, pid):
        value = ctypes.c_ulong()
        self.ptrace(_GETMSG, pid, 0, ctypes.byref(value))
        return value.value


class PiSourceObserver:
    """One owner thread, one task, one immutable observation lifetime.

    Failure never detaches or drops PIDFD/trace custody. The caller must use the
    existing owned-unit cleanup and then close_after_exit(). EXITKILL remains
    armed while the tracer exists. This class never issues a signal to run an
    unobserved task after failure and never retries an effect or activation.
    """

    def __init__(self, seal):
        _require(seal is _SEAL, "PROTECTED_FACTORY_REQUIRED")
        self._seal = seal
        self._thread = threading.get_native_id()
        self._state, self._attached, self._stopped, self._executed = "HELD", False, False, False
        self._owned = self._kernel = None
        self._fds, self._sources, self._events = [], [], []
        self._source_fds, self._ranges = {}, {}
        self._read_paths = set()
        self._pidfd, self._pending, self._syscall = -1, None, None
        self._challenge_nonces = set()
        self._last_challenge_end = 0
        self._last_tick = 0
        self._stops = 0
        self._bindings, self._worker, self._clock = {}, {}, {}
        self._producer_fd = -1
        self._producer_identity = None
        self._last_stop_event = None
        self._pins = ()
        self._executable_identities = {}
        self._close_attempted = False
        self._node_session = None

    def _event(self, kind, *, _cleanup=False, **fields):
        now = _tick()
        _require(now >= self._last_tick, "CLOCK_REGRESSED")
        # Reserve refusal, EXIT-stop, terminal wait and cleanup records. Normal
        # acquisition cannot consume the bounded owned-cleanup evidence space.
        terminal = _cleanup or kind in {"REFUSED", "CLEANUP"}
        _require(len(self._events) < MAX_EVENTS - (0 if terminal else 8), "EVENT_LIMIT")
        self._events.append(dict(seq=len(self._events) + 1, boottime_ns=now, kind=kind, **fields))
        self._last_tick = now

    def _fail(self, error):
        if self._state != "REFUSED":
            self._state = "REFUSED"
            try:
                self._event("REFUSED", code=str(error)[:128])
            except BaseException:
                pass  # Original raw records and attached custody are retained.
        raise PiSourceObserverError(str(error), self) from error

    def _budget(self, deadline):
        _require(type(self) is PiSourceObserver and self._seal is _SEAL and self._state == "HELD" and
                 threading.get_native_id() == self._thread, "OBSERVER_CUSTODY")
        _require(type(deadline) in (int, float) and math.isfinite(deadline) and
                 time.monotonic() < deadline <= self._deadline, "OBSERVER_DEADLINE")

    def _tasks(self):
        if self._node_session is not None:
            return self._node_session._inventory()
        names = os.listdir(f"/proc/{self._worker['pid']}/task")
        _require(all(name.isdecimal() for name in names) and sorted(map(int, names)) == [self._worker["pid"]],
                 "UNSUPPORTED_THREAD_INVENTORY")
        return [self._worker["pid"]]

    def _guard(self, deadline):
        if self._node_session is not None:
            return self._node_session._guard(deadline)
        self._budget(deadline)
        owned = self._owned
        _require(type(owned) is native._Owned and type(owned.plan) is confined.PiConfinedLaunchPlan and
                 type(owned.plan.prepared) is bundle.PreparedPiBundle and
                 type(owned.plan._lease) is confined._PlanLease and owned.plan._lease.active and
                 type(owned.plan.prepared._lease) is bundle._Lease and owned.plan.prepared._lease.active and
                 owned.plan.prepared.expires_at_monotonic_ns > time.monotonic_ns() and
                 self._deadline <= owned.plan.deadline and
                 owned.started and owned.start_attempted and not owned.exit_observed,
                 "WITHDRAWN_NATIVE_CUSTODY")
        current = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                   owned.immutable_digest, owned.cgroup_fd, owned.cgroup_identity,
                   owned.plan._lease, owned.plan.prepared, owned.plan.prepared._lease)
        _require(len(self._pins) == len(current) and owned.plan is self._pins[0] and
                 owned.plan._lease is self._pins[8] and owned.plan.prepared is self._pins[9] and
                 owned.plan.prepared._lease is self._pins[10] and current == self._pins,
                 "ORIGINAL_NATIVE_CUSTODY_CHANGED")
        _require((owned.pid, owned.start_ticks, owned.invocation, owned.plan.unit_name) ==
                 (self._worker["pid"], self._worker["start_ticks"], self._worker["invocation_id"], self._worker["unit"]),
                 "CAPTURED_UNIT_CHANGED")
        process.require_live_pidfd(self._pidfd)
        native._same_generation(owned, native._unit_state(owned.plan.unit_name, deadline), deadline, live=True)
        _require(process._process_start_time(owned.pid) == self._worker["start_ticks"], "PROCESS_REUSED")
        process._require_process_status(owned.pid, self._worker["uid"], self._worker["gid"])
        _require(owned.plan.profile.runtime_digest == owned.plan.runtime_inventory_digest ==
                 owned.plan.prepared.runtime_digest == self._bindings["runtime_digest"] and
                 owned.plan.prepared.deployment_digest == self._bindings["deployment_digest"] and
                 owned.plan.profile.executable_digest == owned.plan.prepared.executable_digest ==
                 self._bindings["node_digest"], "DEPLOYMENT_BINDING_CHANGED")
        _require(_protected_file(self._producer_fd) == self._producer_identity,
                 "PRODUCER_SOURCE_CHANGED")
        self._tasks()
        _require(os.stat(f"/proc/{owned.pid}/ns/time").st_ino == self._clock["time_namespace_inode"] and
                 os.stat("/proc/self/ns/time").st_ino == self._clock["time_namespace_inode"], "TIME_NAMESPACE_CHANGED")
        expected = self._bindings["node_digest" if self._executed else "gate_digest"]
        _require(process._executable_digest(owned.pid) == expected, "EXECUTABLE_CHANGED")
        _require(_file_identity(os.stat(f"/proc/{owned.pid}/exe")) ==
                 self._executable_identities["node" if self._executed else "gate"], "EXECUTABLE_OBJECT_CHANGED")
        for source in self._sources:
            _require(_protected_file(self._source_fds[source["path"]]) == source["identity"], "HELD_SOURCE_CHANGED")

    def _wait(self, deadline, *, initial=False):
        pid = self._worker["pid"]
        while True:
            self._budget(deadline)
            waited, status = os.waitpid(pid, os.WNOHANG | 0x40000000)  # __WALL, exact owned task only.
            if waited:
                break
            time.sleep(min(0.001, deadline - time.monotonic()))
        _require(waited == pid, "UNOWNED_WAIT_RESULT")
        self._stops += 1
        self._stopped = os.WIFSTOPPED(status)
        event = status >> 16 if self._stopped else 0
        stop_signal = os.WSTOPSIG(status) if self._stopped else 0
        op, number, args, result, is_error, message = "NONE", None, None, None, None, None
        if self._stopped and stop_signal == signal.SIGTRAP | 0x80 and event == 0:
            op, number, args, result, is_error = self._kernel.info(pid)
        elif self._stopped and event in (1, 2, 3, 4, 6):
            message = self._kernel.message(pid)
        self._last_stop_event = event
        self._event("STOP", pid=pid, status=status, op=op, syscall=number, args=args,
                    result=result, is_error=is_error, event=event, event_message=message)
        _require(self._stopped, "TASK_EXIT_DURING_OBSERVATION")
        _require(event not in (1, 2, 3, 6), "UNSUPPORTED_TASK_LIFETIME_EVENT")
        if initial:
            _require(event == 128 and op == "NONE" and stop_signal in (5, 19), "PREEXEC_STOP_NOT_ACQUIRED")
            return
        if event == 4:
            _require(not self._executed and message == pid and self._pending is None and self._syscall == 221,
                     "UNEXPECTED_EXEC_TRANSITION")
            _require(process._executable_digest(pid) == self._bindings["node_digest"], "NODE_EXEC_DIGEST")
            self._executed = True
            # Successful exec has a TRACEEXEC event before its syscall-exit
            # stop. Preserve that pairing; an omitted exit is unsupported.
            self._event("EXEC", pid=pid, digest=self._bindings["node_digest"])
            return
        if event == 128:
            _require(op == "NONE" and stop_signal == 5, "INTERRUPT_STOP_SHAPE")
            return
        _require(event == 0 and stop_signal == signal.SIGTRAP | 0x80, "UNSUPPORTED_SIGNAL_STOP")
        if op == "ENTRY":
            _require(self._syscall is None, "UNPAIRED_SYSCALL_ENTRY")
            self._syscall = number
            _require(self._executed or number == 221, "PREEXEC_ONLY_FIXED_EXEC_SUPPORTED")
            _require(number not in _DENIED and not (number == 221 and self._executed), "UNSUPPORTED_SYSCALL")
            _require(number in _ORDINARY or number in (63, 67, 221, 222), "UNCLASSIFIED_SYSCALL")
            if number == 222:
                _require(args[3] & 0x20 and args[4] == (1 << 64) - 1, "UNSUPPORTED_FILE_MAPPING")
            if number in (63, 67):
                _require(self._executed, "READ_BEFORE_NODE_EXEC")
                self._enter_read(number, args, deadline)
        elif op == "EXIT":
            _require(self._syscall is not None, "UNPAIRED_SYSCALL_EXIT")
            if self._syscall == 221:
                _require(self._executed and result == 0 and not is_error, "FIXED_EXEC_FAILED")
            if self._pending is not None:
                self._exit_read(result, is_error, deadline)
            self._syscall = None
        else:
            raise PiSourceObserverError("UNCLASSIFIED_SYSCALL_STOP")

    def _enter_read(self, number, args, deadline):
        _require(self._pending is None and self._tasks() == [self._worker["pid"]], "READ_TASK_CUSTODY")
        fd, count = args[0], args[2]
        _require(0 <= fd <= 0x7fffffff and 0 <= count <= MAX_FILE, "READ_ARGUMENT_BOUNDS")
        duplicate = self._kernel.duplicate(self._pidfd, fd)
        self._fds.append(duplicate)
        observed = _protected_file(duplicate)
        matches = [source for source in self._sources if source["identity"] == observed]
        _require(len(matches) == 1, "UNCLASSIFIED_READ_DESCRIPTOR")
        source = matches[0]
        # pidfd_getfd shares the actual open description. SEEK_CUR only obtains
        # its offset; hashing uses pread and never changes that shared position.
        offset = os.lseek(duplicate, 0, os.SEEK_CUR) if number == 63 else args[3]
        _require(0 <= offset <= source["identity"]["size"] and offset + count <= 2**63 - 1, "READ_RANGE")
        _require(_hash(duplicate, deadline) == (source["digest"], source["identity"]), "READ_SOURCE_DIGEST")
        call_id = len(self._events) + 1
        self._pending = dict(call_id=call_id, duplicate=duplicate, source=source, offset=offset,
                             count=count, fd=fd, syscall=number)
        self._event("READ_ENTER", call_id=call_id, pid=self._worker["pid"],
                    syscall="read" if number == 63 else "pread64", fd=fd,
                    offset=offset, count=count, **source)

    def _exit_read(self, result, is_error, deadline):
        pending = self._pending
        source = pending["source"]
        _require(type(result) is int and type(is_error) is bool and
                 (is_error and -4095 <= result < 0 or not is_error and 0 <= result <= pending["count"]),
                 "READ_RETURN_BOUNDS")
        _require(self._tasks() == [self._worker["pid"]] and
                 _hash(pending["duplicate"], deadline) == (source["digest"], source["identity"]),
                 "READ_SOURCE_CHANGED")
        if not is_error:
            _require(pending["offset"] + result <= source["identity"]["size"], "READ_RETURN_RANGE")
            if pending["syscall"] == 63:
                _require(os.lseek(pending["duplicate"], 0, os.SEEK_CUR) == pending["offset"] + result,
                         "READ_OFFSET_CHANGED")
        self._event("READ_EXIT", call_id=pending["call_id"], pid=self._worker["pid"],
                    result=result, is_error=is_error, identity=source["identity"])
        if not is_error:
            self._read_paths.add(source["path"])
        if result > 0 and not is_error:
            self._ranges[source["path"]].append((pending["offset"], pending["offset"] + result))
        self._pending = None
        # Retain duplicated descriptors to make cleanup ownership explicit.

    def advance(self, *, deadline):
        try:
            self._guard(deadline)
            _require(self._attached and self._stopped, "OBSERVATION_NOT_STOPPED")
            self._kernel.ptrace(_SYSCALL, self._worker["pid"])
            self._stopped = False
            self._wait(deadline)
            self._guard(deadline)
        except BaseException as error:
            self._fail(error)

    def challenge(self, *, nonce, issued_ns, deadline_ns):
        if self._node_session is not None:
            self._budget(self._deadline)
            self._node_session._challenge(nonce, issued_ns, deadline_ns)
            return self._node_session._snapshot()
        try:
            _require(type(nonce) is str and re.fullmatch(r"[a-f0-9]{64}", nonce) and
                     nonce not in self._challenge_nonces and type(issued_ns) is int and type(deadline_ns) is int and
                     deadline_ns - issued_ns == CHALLENGE_NS and
                     self._last_challenge_end < issued_ns <= _tick() < deadline_ns, "CHALLENGE_FRESHNESS")
            self._challenge_nonces.add(nonce)
            remaining = (deadline_ns - _tick()) / 1_000_000_000
            bounded = min(self._deadline, time.monotonic() + remaining)
            self._guard(bounded)
            _require(self._attached and self._stopped and self._syscall is None and self._pending is None,
                     "CHALLENGE_NOT_QUIESCENT")
            before = self._stops
            # A fresh challenge must exercise actual resume/interrupt/wait,
            # not merely report a live PIDFD or an old stopped state.
            self._kernel.ptrace(_SYSCALL, self._worker["pid"])
            self._stopped = False
            self._kernel.ptrace(_INTERRUPT, self._worker["pid"])
            self._wait(bounded)
            self._guard(bounded)
            _require(self._pending is None and self._syscall is None and self._last_stop_event == 128 and
                     self._stops == before + 1 and _tick() < deadline_ns, "CHALLENGE_PENDING_OR_EXPIRED")
            self._event("CHALLENGE", nonce=nonce, issued_ns=issued_ns, deadline_ns=deadline_ns,
                        stops_before=before, stops_after=self._stops, tasks=self._tasks(), all_stopped=True)
            _require(self._events[-1]["boottime_ns"] < deadline_ns, "CHALLENGE_EXPIRED")
            self._last_challenge_end = self._events[-1]["boottime_ns"]
            return self.observation
        except BaseException as error:
            self._fail(error)

    def _complete(self):
        if self._node_session is not None:
            return self._node_session._complete()
        for source in self._sources:
            if source["path"] not in self._read_paths:
                return False
            end = 0
            for lower, upper in sorted(self._ranges[source["path"]]):
                if lower > end:
                    return False
                end = max(end, upper)
            if end != source["identity"]["size"]:
                return False
        return True

    def guard_source_health(self, *, activation, deadline):
        if self._node_session is not None and threading.get_native_id() != self._thread:
            return self._node_session.command("health", activation, deadline)
        try:
            self._guard(deadline)
            value = identity.validate_activation(activation)
            _require(self._owned.activation_raw == canonical_json(value) and
                     identity.read_activation(self._owned.plan.activation_path) == value and
                     value["expires_at_monotonic_ns"] > time.monotonic_ns() and
                     value["activation_id"] == self._owned.plan.prepared.activation_id and
                     value["source_manifest_digest"] == self._owned.plan.prepared.manifest_digest and
                     value["mount_namespace"] == process._mount_namespace(self._worker["pid"]),
                     "OWNED_ACTIVATION_CHANGED")
            _require(self._executed and self._complete() and self._pending is None and
                     value["pid"] == self._worker["pid"] and value["start_time_ticks"] == self._worker["start_ticks"] and
                     value["uid"] == self._worker["uid"] and value["gid"] == self._worker["gid"] and
                     value["cgroup"] == self._worker["cgroup"] and value["boot_id"] == self._clock["boot_id"] and
                     value["runtime_digest"] == self._bindings["runtime_digest"] and
                     value["deployment_digest"] == self._bindings["deployment_digest"] and
                     value["executable_digest"] == self._bindings["node_digest"], "SOURCE_COVERAGE_OR_ACTIVATION")
            issued = _tick()
            _require(time.monotonic() + CHALLENGE_NS / 1_000_000_000 <= deadline, "HEALTH_DEADLINE_TOO_SHORT")
            self.challenge(nonce=secrets.token_hex(32), issued_ns=issued, deadline_ns=issued + CHALLENGE_NS)
            _require(self._complete(), "SOURCE_COVERAGE_CHANGED")
        except BaseException as error:
            self._fail(error)

    @property
    def observation(self):
        if self._node_session is not None:
            return self._node_session.snapshot()
        enters = [event for event in self._events if event["kind"] == "READ_ENTER"]
        exits = [event for event in self._events if event["kind"] == "READ_EXIT"]
        value = dict(schema=SCHEMA, architecture="linux-arm64", bindings=self._bindings, worker=self._worker, clock=self._clock,
                     sources=self._sources, state=self._state, events=self._events,
                     accounting=dict(stops_acquired=self._stops, reads_entered=len(enters), reads_exited=len(exits),
                         bytes_read=sum(max(event["result"], 0) for event in exits), pending_reads=len(enters) - len(exits),
                         refusals=sum(event["kind"] == "REFUSED" for event in self._events), events_retained=len(self._events)))
        raw = canonical_json(value)
        _require(len(raw) <= MAX_RAW, "OBSERVATION_BYTE_LIMIT")
        import json
        return json.loads(raw)

    def begin_owned_stop(self, deadline):
        """Ask the dedicated owner to enter exit-only draining before unit stop."""
        _require(self._node_session is not None, "NODE_OWNER_REQUIRED")
        return self._node_session.command("stop", None, deadline)

    @property
    def health_observation(self):
        """Latest actual held-boundary snapshot, not a post-cleanup recreation."""
        if self._node_session is None:
            return None
        import json
        with self._node_session.lock:
            value = self._node_session.latest_health_observation
            return None if value is None else json.loads(canonical_json(value))

    def shutdown_after_owned_stop(self, deadline):
        """Join the tracer only after all captured tasks and owned FDs close."""
        _require(self._node_session is not None, "NODE_OWNER_REQUIRED")
        self._node_session.command("close", None, deadline)
        self._node_session.thread.join(max(0, deadline - time.monotonic()))
        _require(not self._node_session.thread.is_alive() and self._state == "CLOSED", "NODE_OWNER_NOT_JOINED")

    def close_after_exit(self):
        """Close owned handles only after supervisor-confirmed tracee death."""
        _require(threading.get_native_id() == self._thread and self._state != "CLOSED", "CLEANUP_OWNER")
        _require(not self._close_attempted, "CLEANUP_CLOSE_ALREADY_ATTEMPTED")
        if self._attached:
            _require(native._exited(self._pidfd), "TRACE_CLEANUP_REQUIRES_EXIT")
        self._close_attempted = True
        failures = []
        for descriptor in list(self._fds):
            try:
                os.close(descriptor)
                self._fds.remove(descriptor)
            except OSError as error:
                failures.append(error)
        if failures:
            self._state = "REFUSED"
            self._event("REFUSED", code="SOURCE_HANDLE_CLEANUP_AMBIGUOUS_NO_RETRY")
            self._fail(PiSourceObserverError("SOURCE_HANDLE_CLEANUP_AMBIGUOUS_NO_RETRY"))
        if self._attached:
            self._event("CLEANUP", pid=self._worker["pid"], status="EXIT_OBSERVED")
        self._state = "CLOSED"

    def drain_owned_exit(self, *, deadline):
        """Explicit cleanup only: release an acquired EXIT stop, never detach.

        The supervisor must first stop the exact owned unit. This operation
        never signals a task, resumes an ordinary syscall/signal stop, or
        extends the original deadline. A timeout retains every owned handle.
        """
        _require(type(self) is PiSourceObserver and self._seal is _SEAL and self._attached and
                 threading.get_native_id() == self._thread and self._state != "CLOSED", "CLEANUP_CUSTODY")
        _require(type(deadline) in (int, float) and math.isfinite(deadline) and
                 time.monotonic() < deadline <= self._deadline, "CLEANUP_DEADLINE")
        self._state = "REFUSED"
        pid = self._worker["pid"]
        if self._stopped:
            _require(self._last_stop_event == 6, "CLEANUP_REQUIRES_EXIT_STOP")
            self._kernel.ptrace(7, pid)  # PTRACE_CONT only from PTRACE_EVENT_EXIT.
            self._stopped = False
        while time.monotonic() < deadline:
            waited, status = os.waitpid(pid, os.WNOHANG | 0x40000000)
            if waited == pid:
                event = status >> 16 if os.WIFSTOPPED(status) else 0
                message = self._kernel.message(pid) if event == 6 else None
                self._stops += 1
                self._event("STOP", _cleanup=True, pid=pid, status=status, op="NONE", syscall=None, args=None,
                            result=None, is_error=None, event=event, event_message=message)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    _require(native._exited(self._pidfd), "EXIT_PIDFD_NOT_TERMINAL")
                    return
                self._stopped = os.WIFSTOPPED(status)
                self._last_stop_event = status >> 16 if self._stopped else 0
                _require(self._stopped and self._last_stop_event == 6, "CLEANUP_UNEXPECTED_STOP")
                self._kernel.ptrace(7, pid)
                self._stopped = False
            else:
                _require(waited == 0, "CLEANUP_UNOWNED_WAIT")
            time.sleep(min(0.001, max(0, deadline - time.monotonic())))
        raise PiSourceObserverError("CLEANUP_DEADLINE", self)


def arm_pi_source_observer(owned, *, gate_path, gate_digest, node_path, node_digest,
                           sources, bindings, deadline):
    """Acquire a NEW stopped, pinned pre-exec gate; never attach after HELLO.

    Native launch must first install a reviewed gate artifact and capture its
    exact unit. Existing env→Node plans cannot pass this factory. The gate must
    stop itself before its ONLY exec of the fixed Node/entrypoint command.
    """
    observer = PiSourceObserver(_SEAL)
    observer._deadline = deadline
    observer._owned = owned
    try:
        _require(platform.system() == "Linux" and platform.machine() in {"aarch64", "arm64"} and
                 os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "LINUX_ARM64_ROOT_REQUIRED")
        observer._budget(deadline)
        _require(type(owned) is native._Owned and owned.started and owned.start_attempted and
                 owned.pid > 0 and owned.pidfd >= 0 and owned.start_ticks > 0 and owned.invocation and
                 owned.immutable_digest and owned.connection is None and not owned.exit_observed,
                 "PREEXEC_NATIVE_CUSTODY_REQUIRED")
        _require(type(owned.plan) is confined.PiConfinedLaunchPlan and
                 type(owned.plan.prepared) is bundle.PreparedPiBundle, "NATIVE_PLAN_TYPES")
        _require(type(owned.plan.deadline) in (int, float) and math.isfinite(owned.plan.deadline) and
                 deadline <= owned.plan.deadline, "ORIGINAL_LAUNCH_DEADLINE")
        observer._pins = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                          owned.immutable_digest, owned.cgroup_fd, owned.cgroup_identity,
                          owned.plan._lease, owned.plan.prepared, owned.plan.prepared._lease)
        _require(gate_path == GATE_PATH and node_path == NODE_PATH and type(bindings) is dict and
                 set(bindings) == _BINDINGS and all(type(pin) is str and _PIN.fullmatch(pin) for pin in bindings.values()) and
                 bindings["gate_digest"] == gate_digest and bindings["node_digest"] == node_digest,
                 "SOURCE_BINDINGS")
        argv = owned.plan.systemd_run_argv
        _require(argv[argv.index("--") + 1:] == ("/usr/bin/env", "-i", "HOME=/nonexistent",
                 "PATH=/opt/aragorn/pi-runtime/node/bin", str(GATE_PATH), str(NODE_PATH), ENTRY_PATH),
                 "PREEXEC_GATE_ARGV_REQUIRED")
        observer._bindings = dict(bindings)
        observer._worker = dict(pid=owned.pid, start_ticks=owned.start_ticks, uid=owned.plan.worker_uid,
            gid=owned.plan.worker_gid, cgroup=owned.plan.profile.cgroup, unit=owned.plan.unit_name,
            invocation_id=owned.invocation)
        observer._clock = dict(boot_id=process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64).decode("ascii").strip(),
            clock_id="CLOCK_BOOTTIME", time_namespace_inode=os.stat("/proc/self/ns/time").st_ino)
        observer._pidfd = os.dup(owned.pidfd)
        observer._fds.append(observer._pidfd)
        status = process._read_virtual_file(Path(f"/proc/{owned.pid}/status"), 65536).decode("ascii")
        _require(re.search(r"^State:\s+T\s", status, re.M) and re.search(r"^TracerPid:\s+0$", status, re.M),
                 "PREEXEC_GATE_MUST_BE_UNTRACED_AND_STOPPED")
        process._require_process_status(owned.pid, owned.plan.worker_uid, owned.plan.worker_gid)
        _require(Path(__file__) == PRODUCER_PATH, "PROTECTED_PRODUCER_ORIGIN_REQUIRED")
        producer_fd = _open_view(os.getpid(), PRODUCER_PATH)
        observer._fds.append(producer_fd)
        producer_digest, producer_identity = _hash(producer_fd, deadline)
        _require(producer_digest == bindings["producer_digest"], "PRODUCER_SOURCE_PIN")
        observer._producer_fd, observer._producer_identity = producer_fd, producer_identity
        gate_fd = _open_view(owned.pid, GATE_PATH)
        observer._fds.append(gate_fd)
        observed_gate, gate_identity = _hash(gate_fd, deadline, process._MAX_EXECUTABLE_BYTES)
        _require(observed_gate == gate_digest and process._executable_digest(owned.pid) == gate_digest, "PREEXEC_GATE_BYTES")
        observer._executable_identities["gate"] = gate_identity
        node_fd = _open_view(owned.pid, NODE_PATH)
        observer._fds.append(node_fd)
        observed_node, node_identity = _hash(node_fd, deadline, process._MAX_EXECUTABLE_BYTES)
        _require(observed_node == node_digest, "PINNED_NODE_BYTES")
        observer._executable_identities["node"] = node_identity
        _require(type(sources) is list and 0 < len(sources) <= 512, "SOURCE_INVENTORY_SIZE")
        for value in sources:
            _require(type(value) is dict and set(value) == {"path", "digest"} and
                     type(value["path"]) is str and type(value["digest"]) is str and _PIN.fullmatch(value["digest"]) and
                     value["path"] not in observer._source_fds, "SOURCE_INVENTORY_ENTRY")
            fd = _open_view(owned.pid, Path(value["path"]))
            observer._fds.append(fd)
            digest, metadata = _hash(fd, deadline)
            _require(digest == value["digest"] and not any(row["identity"] == metadata for row in observer._sources),
                     "SOURCE_INVENTORY_BYTES_OR_ALIAS")
            observer._sources.append(dict(path=value["path"], digest=digest, identity=metadata))
            observer._source_fds[value["path"]] = fd
            observer._ranges[value["path"]] = []
        observer._sources.sort(key=lambda value: value["path"])
        _require(canonical_digest(dict(schema=INVENTORY_SCHEMA, sources=observer._sources)) == bindings["source_inventory_digest"],
                 "SOURCE_INVENTORY_PIN")
        observer._guard(deadline)
        observer._kernel = _Kernel()
        observer._kernel.ptrace(_SEIZE, owned.pid, 0, OPTIONS)
        observer._attached = True
        observer._event("ARMED", tasks=observer._tasks(), options=OPTIONS, gate_identity=gate_identity)
        observer._kernel.ptrace(_INTERRUPT, owned.pid)
        observer._wait(deadline, initial=True)
        observer._guard(deadline)
        return observer
    except BaseException as error:
        observer._fail(error)
