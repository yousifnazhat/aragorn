"""Own one Root reader session, protected checkpoint readback and byte replay.

The fixed launcher supplies protected inventories; this module does not acquire
installed source or upstream loss and never grants health/effect authority.
"""

import base64
import copy
import fcntl
import hashlib
import json
import os
import re
import select
import stat
import struct
import sys
import threading
import time

from .native_phase3_broker_reader_protocol import validate_guard_request, validate_guard_response
from .native_phase3_run_reader_transport import ReaderListener, ReaderTransportError
from .native_phase3_run_reader_evidence_verify import verify_reader_evidence
from .native_phase3_run_reader_checkpoint_acquisition import (
    acquire_reader_checkpoint, ReaderCheckpointAcquisitionError,
)
from .native_phase3_run_reader_checkpoint_verify import verify_reader_checkpoint


_ORIGINAL_PID = os.getpid()
_MAX = 2**63 - 1
_AGE = 200000000
_TIMEOUT = 100000000
_PREFIX = "aragorn/native-phase3-reader-"
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
          "effect_authorized", "run_qualified", "phase3_qualified")
_OBSERVED = ("startup_ready_raw", "opening_transport_raw", "notice_raw", "command_raw",
             "command_attempted", "command_bytes_written", "completion_raw",
             "completion_received_ns", "transport_raw", "owned_observed",
             "expectation_raw", "checkpoint_observed", "session_raw")
_PIPE_ROLES = ("NOTICE", "TELEMETRY", "REFRESH", "STDERR", "CANCEL", "COMPLETION")
_PROC_ROLES = ("observer", "reader", "bridge", "supervisor")
_OPEN = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _uint(value, minimum=0, maximum=_MAX):
    _require(type(value) is int and minimum <= value <= maximum, "integer bound")
    return value


def _sum(a, b):
    return _uint(_uint(a) + _uint(b))


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "digest pin")
    return value


def _nonce(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "nonce")


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "record fields")
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _raw(raw, maximum, empty=False):
    _require(type(raw) is bytes and (0 if empty else 1) <= len(raw) <= maximum, "raw byte bound")
    return raw


def _decode(raw, maximum, frame=False):
    _raw(raw, maximum)
    if frame:
        _require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "control framing")
        raw = raw[:-1]
    _require(raw.isascii(), "canonical ASCII")

    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value, "duplicate key")
            value[key] = item
        return value

    def constant(_):
        raise ValueError("nonfinite number")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    _require(type(value) is dict and _canonical(value) == raw, "canonical record")
    return value


def _document(raw, pin, maximum):
    _pin(pin)
    _require(_digest(_raw(raw, maximum)) == pin, "protected input pin")
    return _decode(raw, maximum)


def _process(value):
    _keys(value, "pid start_time_ticks uid gid")
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    _uint(value["uid"], 0, 4294967295)
    _uint(value["gid"], 0, 4294967295)


def _clock(value):
    _keys(value, "boot_id clock_id time_namespace")
    _require(type(value["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "boot identity")
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "clock domain")
    _keys(value["time_namespace"], "device inode")
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _limits():
    return {"stream_continuity": "UNKNOWN", "loss_completeness": "UNKNOWN",
            **dict.fromkeys(_FLAGS, False)}


class ReaderCheckpointSessionError(ValueError):
    """Terminal refusal; local caller must retain this owner until process exit."""

    def __init__(self, original, observed, cleanup, owner):
        super().__init__("reader checkpoint session refused; preserve original observations and owners")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup[:32])
        self.observed = copy.deepcopy(observed)
        self.unaccepted_reader_raw = None
        owned = self.observed.get("owned_observed")
        if type(owned) is dict and type(owned.get("reader")) is dict:
            self.unaccepted_reader_raw = _canonical(owned["reader"])
            owned["reader"] = None
        # This is a local strong reference, never an object/FD transfer to a
        # different supervisor. In particular retain frozen detach exceptions.
        self._owner = owner


class ReaderCheckpointSession:
    """Original Root main-thread owner; every attempted failure is permanent."""

    def __init__(self, *, epoch_raw, expected_epoch_digest,
                 checkpoint_provision_raw, expected_checkpoint_provision_digest,
                 transport_provision_raw, expected_transport_provision_digest,
                 stream_inventory_raw, expected_stream_digest,
                 loop_provision_raw, expected_loop_provision_digest,
                 notice_write_fd, reader_pidfd, refresh_write_fd,
                 completion_read_fd, cancel_read_fd):
        self._owned = {}
        self._unresolved = []
        self._cleanup_errors = []
        self._listener = None
        self._listener_terminal = False
        self._closed = False
        self._failure = None
        self._lock = threading.Lock()
        self._last_tick = -1
        self._deadline = _MAX
        self._state = "OPENING"
        self._observed = dict.fromkeys(_OBSERVED)
        self._observed["command_attempted"] = False
        self._sequence = self._offset = self._records = 0
        self._manifest_pin = self._context_pin = None
        self._seen_contexts, self._seen_admissions = set(), set()
        self._ordinal = self._refresh_ordinal = 0
        self._active = self._first = None
        self._pidfds, self._namespaces = {}, {}
        fds = (notice_write_fd, reader_pidfd, refresh_write_fd, completion_read_fd, cancel_read_fd)
        try:
            # Take each distinct valid descriptor before the first metadata read.
            for fd in fds:
                if type(fd) is int and 3 <= fd <= _MAX and fd not in self._owned:
                    self._owned[fd] = {"identity": None, "pid": "UNKNOWN" if fd == reader_pidfd else None}
            metadata_errors = []
            for fd, entry in self._owned.items():
                try:
                    entry["identity"] = _identity(os.fstat(fd))
                except BaseException as exc:
                    metadata_errors.append(exc)
            if metadata_errors:
                raise metadata_errors[0]
            _require(all(type(fd) is int and 3 <= fd <= _MAX for fd in fds)
                     and len(set(fds)) == 5, "descriptor transfer")
            self._notice, self._reader_transfer, self._refresh, self._completion, self._cancel_fd = fds
            self._context_guard()
            self._owned[reader_pidfd]["pid"] = self._pidfd_pid(reader_pidfd)
            self._validate_inputs(epoch_raw, expected_epoch_digest,
                                  checkpoint_provision_raw, expected_checkpoint_provision_digest,
                                  transport_provision_raw, expected_transport_provision_digest,
                                  stream_inventory_raw, expected_stream_digest,
                                  loop_provision_raw, expected_loop_provision_digest)
            _require(self._owned[reader_pidfd]["pid"] == self._stream["reader"]["pid"], "transferred reader PIDFD")
            for role in _PROC_ROLES:
                pid = self._stream[role]["pid"]
                if role != "observer":
                    fd = os.pidfd_open(pid, 0)
                    self._own(fd, pid=pid)
                    self._pidfds[role] = fd
                fd = os.open(f"/proc/{pid}/ns/time", os.O_RDONLY | os.O_CLOEXEC)
                self._own(fd)
                self._namespaces[role] = fd
            self._deadline = self._loop["startup_deadline_ns"]
            self._guard()
            startup_raw, received = self._frame("startup_ready_raw")
            startup = _keys(_decode(startup_raw, 2048, True),
                            "schema session_id epoch_digest loop_provision_digest stream_digest ready_ns")
            _require(startup["schema"] == _PREFIX + "loop-ready/v1"
                     and startup["session_id"] == self._stream["session_id"]
                     and startup["epoch_digest"] == self._epoch_pin
                     and startup["loop_provision_digest"] == self._loop_pin
                     and startup["stream_digest"] == self._stream_pin
                     and _uint(startup["ready_ns"]) <= received < self._deadline,
                     "startup frame joins")
            self._guard()
            # From call entry the frozen listener alone owns these descriptors,
            # including when its constructor raises and retains cleanup errors.
            self._owned.pop(notice_write_fd)
            self._owned.pop(reader_pidfd)
            try:
                self._listener = ReaderListener(
                    provision_raw=transport_provision_raw,
                    expected_provision_digest=expected_transport_provision_digest,
                    epoch_raw=epoch_raw, expected_epoch_digest=expected_epoch_digest,
                    notice_write_fd=notice_write_fd, reader_pidfd=reader_pidfd)
            except ReaderTransportError as exc:
                self._observed["opening_transport_raw"] = exc.partial_evidence
                self._observed["owned_observed"] = exc.owned_observed
                self._unresolved.append(exc)
                raise
            self._observed["opening_transport_raw"] = _raw(self._listener.opening_evidence_raw, 131072)
            self._guard()
            self._empty_completion()
            self._state = "READY"
            self._deadline = self._loop["session_deadline_ns"]
        except BaseException as exc:
            raise self._refuse(exc) from exc

    def _validate_inputs(self, epoch_raw, epoch_pin, checkpoint_raw, checkpoint_pin,
                         transport_raw, transport_pin, stream_raw, stream_pin, loop_raw, loop_pin):
        e = _keys(_document(epoch_raw, epoch_pin, 32768), "process clock loss_scope policy deployment_digest")
        p = _keys(_document(checkpoint_raw, checkpoint_pin, 8192),
                  "schema epoch_digest session_id reader observer clock stream_digest source_inventory_digest "
                  "access_inventory_digest directories session_deadline_ns")
        t = _keys(_document(transport_raw, transport_pin, 8192),
                  "schema epoch_digest observer directories notice_pipe session_deadline_ns max_requests access_inventory_digest")
        s = _keys(_document(stream_raw, stream_pin, 16384),
                  "schema session_id reader bridge sensor observer supervisor clock source_inventory_digest "
                  "access_inventory_digest pipes upstream_continuity upstream_socket_digest upstream_loss_digest")
        l = _keys(_document(loop_raw, loop_pin, 8192),
                  "schema epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest "
                  "session_id startup_deadline_ns session_deadline_ns max_requests")
        _require(p["schema"] == _PREFIX + "checkpoint-provision/v1"
                 and t["schema"] == "aragorn/native-phase3-run-reader-transport-provision/v1"
                 and s["schema"] == _PREFIX + "stream-inventory/v1"
                 and l["schema"] == _PREFIX + "loop-provision/v1", "provision schema")
        _nonce(s["session_id"])
        _clock(s["clock"])
        for key in ("source_inventory_digest", "access_inventory_digest"):
            _pin(s[key])
        _require(s["upstream_continuity"] == "UNKNOWN" and s["upstream_socket_digest"] is None
                 and s["upstream_loss_digest"] is None, "upstream claim")
        roles = (*_PROC_ROLES, "sensor")
        for role in roles:
            _process(s[role])
            if role in ("reader", "bridge"):
                _require(s[role]["uid"] > 0 and s[role]["gid"] > 0, "non-root role")
            else:
                _require(s[role]["uid"] == s[role]["gid"] == 0, "Root role")
        _require(len({s[r]["pid"] for r in roles}) == 5
                 and s["reader"]["uid"] != s["bridge"]["uid"]
                 and s["reader"]["gid"] != s["bridge"]["gid"]
                 and s["observer"]["pid"] == _ORIGINAL_PID, "process separation")
        proc = _keys(e["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks "
                     "reader_uid reader_gid sensor_uid sensor_gid reader_source_digest sensor_source_digest "
                     "stream_digest program_map_digest")
        for role in ("reader", "sensor"):
            _require({"pid": proc[role + "_pid"], "start_time_ticks": proc[role + "_start_ticks"],
                      "uid": proc[role + "_uid"], "gid": proc[role + "_gid"]} == s[role], "epoch process join")
        for key in ("reader_source_digest", "sensor_source_digest", "program_map_digest"):
            _pin(proc[key])
        _pin(e["deployment_digest"])
        _keys(e["clock"], "boot_id clock_id time_namespace_inode")
        _require(e["clock"] == {"boot_id": s["clock"]["boot_id"], "clock_id": "CLOCK_BOOTTIME",
                                "time_namespace_inode": s["clock"]["time_namespace"]["inode"]}
                 and proc["boot_id"] == s["clock"]["boot_id"] and proc["stream_digest"] == stream_pin,
                 "epoch clock/stream join")
        _keys(e["policy"], "timeout_ns max_age_ns")
        _require(type(e["policy"]["timeout_ns"]) is int and type(e["policy"]["max_age_ns"]) is int
                 and e["policy"] == {"timeout_ns": _TIMEOUT, "max_age_ns": _AGE}, "fixed timing profile")
        scope = e["loss_scope"]
        _require(type(scope) is list and 1 <= len(scope) <= 32, "loss scope bound")
        for pin in scope:
            _pin(pin)
        _require(scope == sorted(set(scope)), "loss scope inventory")
        _require(p["epoch_digest"] == t["epoch_digest"] == l["epoch_digest"] == epoch_pin
                 and p["session_id"] == l["session_id"] == s["session_id"]
                 and p["stream_digest"] == l["stream_digest"] == stream_pin
                 and p["source_inventory_digest"] == s["source_inventory_digest"]
                 and p["access_inventory_digest"] == t["access_inventory_digest"] == s["access_inventory_digest"]
                 and p["reader"] == s["reader"] and p["observer"] == s["observer"]
                 and p["clock"] == s["clock"] and l["checkpoint_provision_digest"] == checkpoint_pin
                 and l["transport_provision_digest"] == transport_pin, "provision joins")
        _keys(t["observer"], "pid start_time_ticks uid gid time_namespace")
        _require(t["observer"] == {**s["observer"], "time_namespace": s["clock"]["time_namespace"]},
                 "transport observer join")
        _require(_uint(l["startup_deadline_ns"], 1) < _uint(l["session_deadline_ns"], 1)
                 == _uint(p["session_deadline_ns"], 1) == _uint(t["session_deadline_ns"], 1)
                 and _uint(l["max_requests"], 1, 4096) == _uint(t["max_requests"], 1, 4096), "lifetime budget")
        for entries, paths, transport in (
            (p["directories"], ("/", "/var", "/var/lib", "/var/lib/aragorn-phase3-reader-events",
                                 "/var/lib/aragorn-phase3-reader-checkpoints"), False),
            (t["directories"], ("/", "/run", "/run/aragorn-phase3-reader"), True)):
            _require(type(entries) is list and len(entries) == len(paths), "directory inventory")
            for i, (entry, path) in enumerate(zip(entries, paths, strict=True)):
                _keys(entry, "path device inode mode uid gid")
                _require(entry["path"] == path, "fixed directory")
                for key in ("device", "inode", "mode", "uid", "gid"):
                    _uint(entry[key], 1 if key == "inode" else 0)
                _require(stat.S_ISDIR(entry["mode"]) and not entry["mode"] & 0o022, "directory permissions")
                if not transport and i == 3:
                    _require((entry["uid"], entry["gid"], entry["mode"]) ==
                             (s["reader"]["uid"], s["reader"]["gid"], stat.S_IFDIR | 0o700), "source owner")
                else:
                    _require(entry["uid"] == 0, "root ancestor")
                if transport and i == 2:
                    _require(entry["gid"] == s["reader"]["gid"] and entry["mode"] == stat.S_IFDIR | 0o710,
                             "listener parent")
                elif (transport or i == 4):
                    _require(entry["gid"] == 0, "Root directory group")
                if not transport and i == 4:
                    _require(entry["mode"] == stat.S_IFDIR | 0o700, "archive permissions")
        pipes = s["pipes"]
        _require(type(pipes) is list and len(pipes) == 6, "six pipes")
        expected = (("OBSERVER", self._notice, [("READER", 3)]),
                    ("BRIDGE", 1, [("READER", 4)]),
                    ("OBSERVER", self._refresh, [("READER", 5)]),
                    ("BRIDGE", 2, [("READER", 6)]),
                    ("SUPERVISOR", None, [("READER", 7), ("OBSERVER", self._cancel_fd)]),
                    ("READER", 8, [("OBSERVER", self._completion)]))
        identities = []
        for entry, role, (writer, number, readers) in zip(pipes, _PIPE_ROLES, expected, strict=True):
            _keys(entry, "role device inode mode uid gid writer readers")
            _require(entry["role"] == role and entry["mode"] == stat.S_IFIFO | 0o600
                     and entry["uid"] == entry["gid"] == 0, "pipe type/owner")
            for key in ("device", "inode", "mode", "uid", "gid"):
                _uint(entry[key], 1 if key == "inode" else 0)
            _keys(entry["writer"], "process fd")
            _require(entry["writer"]["process"] == writer, "pipe writer")
            _uint(entry["writer"]["fd"], 3 if number is None else 0)
            _require(number is None or entry["writer"]["fd"] == number, "writer descriptor")
            _require(type(entry["readers"]) is list and entry["readers"] ==
                     [{"process": r, "fd": n} for r, n in readers], "pipe readers")
            for endpoint in entry["readers"]:
                _uint(endpoint["fd"], 3)
            identities.append((entry["device"], entry["inode"]))
        _require(len(set(identities)) == 6, "pipe identity alias")
        _keys(t["notice_pipe"], "device inode mode uid gid reader_fd")
        _require(t["notice_pipe"] == {**{key: pipes[0][key] for key in ("device", "inode", "mode", "uid", "gid")},
                                      "reader_fd": 3}, "notice pipe join")
        self._epoch, self._provision, self._transport, self._stream, self._loop = e, p, t, s, l
        self._epoch_pin, self._provision_pin, self._stream_pin, self._loop_pin = epoch_pin, checkpoint_pin, stream_pin, loop_pin
        self._provision_raw = checkpoint_raw
        self._local_pipes = {self._notice: pipes[0], self._refresh: pipes[2],
                             self._completion: pipes[5], self._cancel_fd: pipes[4]}

    def _context_guard(self):
        if self._failure is not None:
            raise self._failure
        _require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("=iII") == 12,
                 "Linux credential ABI")
        _require(os.getpid() == _ORIGINAL_PID == threading.get_native_id()
                 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "original Root main thread")

    def _tick(self):
        self._context_guard()
        current = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(self._last_tick <= current < self._deadline, "clock rollback/deadline")
        self._last_tick = current
        return current

    def _own(self, fd, pid=None):
        _require(type(fd) is int and fd >= 0 and fd not in self._owned, "owned descriptor collision")
        self._owned[fd] = {"identity": None, "pid": pid}
        self._owned[fd]["identity"] = _identity(os.fstat(fd))
        _require(not os.get_inheritable(fd), "owned descriptor inheritance")

    def _read_virtual(self, path, maximum):
        fd = os.open(path, _OPEN)
        self._own(fd)
        value, original = b"", None
        try:
            while True:
                piece = os.read(fd, min(4096, maximum + 1 - len(value)))
                _require(type(piece) is bytes, "proc read type")
                value += piece
                _require(len(value) <= maximum, "proc read bound")
                if not piece:
                    break
            self._check_owned(fd, pid_check=False)
        except BaseException as exc:
            original = exc
        try:
            self._close_fd(fd, pid_check=False)
        except BaseException as exc:
            self._cleanup_errors.append(exc)
            if original is None:
                original = exc
        if original is not None:
            raise original
        return value

    def _pidfd_pid(self, fd):
        raw = self._read_virtual(f"/proc/self/fdinfo/{fd}", 4096)
        _require(raw.isascii(), "PIDFD fdinfo encoding")
        fields = [line.partition(b":")[2].strip() for line in raw.splitlines()
                  if line.partition(b":")[0] == b"Pid"]
        _require(len(fields) == 1 and re.fullmatch(rb"[1-9][0-9]*", fields[0]), "PIDFD association")
        return _uint(int(fields[0]), 1, 2147483647)

    def _check_owned(self, fd, pid_check=True):
        entry = self._owned[fd]
        _require(entry["identity"] is not None and _identity(os.fstat(fd)) == entry["identity"], "owned descriptor substitution")
        if pid_check and entry["pid"] is not None:
            _require(self._pidfd_pid(fd) == entry["pid"], "PIDFD reuse")
            _require(_identity(os.fstat(fd)) == entry["identity"], "PIDFD substituted during association")

    def _close_fd(self, fd, pid_check=True):
        entry = self._owned[fd]
        # Consume once before any check/close; descriptor number reuse is never
        # handled by a speculative close or a second cleanup attempt.
        self._owned.pop(fd)
        _require(entry["identity"] is not None and _identity(os.fstat(fd)) == entry["identity"], "foreign descriptor cleanup")
        if pid_check and entry["pid"] is not None:
            _require(type(entry["pid"]) is int, "unknown PIDFD custody")
            _require(self._pidfd_pid(fd) == entry["pid"], "foreign PIDFD cleanup")
        _require(_identity(os.fstat(fd)) == entry["identity"], "foreign descriptor after cleanup observation")
        os.close(fd)

    def _live(self):
        for role, fd in self._pidfds.items():
            self._check_owned(fd)
            _require(not os.get_inheritable(fd), "PIDFD inheritance")
            poller = select.poll()
            poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
            _require(not poller.poll(0), "peer process exit")

    def _process_guard(self):
        self._context_guard()
        self._live()
        for role in _PROC_ROLES:
            expected = self._stream[role]
            pid = expected["pid"]
            before = self._read_virtual(f"/proc/{pid}/stat", 16384)
            status = self._read_virtual(f"/proc/{pid}/status", 16384)
            after = self._read_virtual(f"/proc/{pid}/stat", 16384)
            for raw in (before, after):
                text = raw.decode("ascii")
                marker = text.rfind(") ")
                fields = text[marker + 2:].split() if marker >= 0 else []
                _require(text.startswith(f"{pid} (") and len(fields) >= 20
                         and fields[19].isdigit() and int(fields[19]) == expected["start_time_ticks"], "process start identity")
            wanted = {"Uid", "Gid", "Groups", "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
            values = {}
            for line in status.decode("ascii").splitlines():
                key, sep, value = line.partition(":")
                if key in wanted:
                    _require(sep and key not in values, "duplicate process field")
                    values[key] = value.split()
            for key in ("Uid", "Gid"):
                vector = values.get(key, [])
                _require(len(vector) == 4 and all(re.fullmatch(r"0|[1-9][0-9]*", v) for v in vector)
                         and [int(v) for v in vector] == [expected[key.lower()]] * 4, "process account vectors")
            if role in ("reader", "bridge"):
                _require(values.get("Groups") == [], "supplementary groups")
            if role == "reader":
                _require(values.get("NoNewPrivs") == ["1"], "reader privilege escalation")
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    parts = values.get(key, [])
                    _require(len(parts) == 1 and re.fullmatch(r"[0-9a-fA-F]+", parts[0])
                             and int(parts[0], 16) == 0, "reader capabilities")
            fd = self._namespaces[role]
            self._check_owned(fd)
            held = os.fstat(fd)
            named = os.stat(f"/proc/{pid}/ns/time")
            ns = self._stream["clock"]["time_namespace"]
            _require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) == (ns["device"], ns["inode"])
                     and os.readlink(f"/proc/{pid}/ns/time") == f"time:[{ns['inode']}]", "active time namespace")
        self._live()

    def _pipe_guards(self):
        for pipe in self._stream["pipes"]:
            expected = tuple(pipe[key] for key in ("device", "inode", "mode", "uid", "gid"))
            for endpoint, writing in [(pipe["writer"], True), *((item, False) for item in pipe["readers"])]:
                role, fd = endpoint["process"].lower(), endpoint["fd"]
                pid = self._stream[role]["pid"]
                path = f"/proc/{pid}/fd/{fd}"
                _require(_identity(os.stat(path)) == expected and os.readlink(path) == f"pipe:[{pipe['inode']}]",
                         "peer pipe identity")
                raw = self._read_virtual(f"/proc/{pid}/fdinfo/{fd}", 4096)
                _require(raw.isascii(), "pipe fdinfo encoding")
                values = [line.partition(b":")[2].strip() for line in raw.splitlines()
                          if line.partition(b":")[0] == b"flags"]
                _require(len(values) == 1 and re.fullmatch(rb"[0-7]+", values[0]), "pipe fdinfo flags")
                flags = int(values[0], 8)
                mode = os.O_WRONLY if writing else os.O_RDONLY
                _require(flags & os.O_ACCMODE == mode and flags & os.O_NONBLOCK and flags & os.O_CLOEXEC,
                         "pipe endpoint flags")
                if pid == _ORIGINAL_PID and fd in self._owned:
                    self._check_owned(fd)
                    actual = fcntl.fcntl(fd, fcntl.F_GETFL)
                    _require(actual & os.O_ACCMODE == mode and actual & os.O_NONBLOCK
                             and not os.get_inheritable(fd) and _identity(os.fstat(fd)) == expected,
                             "owned pipe flags")
                _require(_identity(os.stat(path)) == expected and os.readlink(path) == f"pipe:[{pipe['inode']}]",
                         "pipe changed during observation")

    def _local_pipe(self, fd, writing=False):
        """No proc-file read between the final descriptor checks and pipe IO."""
        self._tick()
        self._check_owned(fd, pid_check=False)
        pipe = self._local_pipes[fd]
        expected = tuple(pipe[key] for key in ("device", "inode", "mode", "uid", "gid"))
        _require(os.readlink(f"/proc/self/fd/{fd}") == f"pipe:[{pipe['inode']}]", "local pipe link")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        _require(flags & os.O_ACCMODE == (os.O_WRONLY if writing else os.O_RDONLY)
                 and flags & os.O_NONBLOCK and not os.get_inheritable(fd)
                 and _identity(os.fstat(fd)) == expected, "immediate local pipe custody")
        return self._tick()

    def _cancel(self):
        poller = select.poll()
        poller.register(self._cancel_fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        for fd, flags in poller.poll(0):
            _require(fd == self._cancel_fd and flags == select.POLLIN, "cancellation/pipe error")
        self._local_pipe(self._cancel_fd)
        try:
            value = os.read(self._cancel_fd, 1)
        except BlockingIOError:
            self._local_pipe(self._cancel_fd)
            return
        self._local_pipe(self._cancel_fd)
        _require(type(value) is bytes, "cancel read type")
        raise ValueError("cancelled" if not value else "cancellation pipe data")

    def _guard(self):
        self._tick()
        self._process_guard()
        self._cancel()
        boot = self._read_virtual("/proc/sys/kernel/random/boot_id", 64)
        _require(boot == (self._stream["clock"]["boot_id"] + "\n").encode("ascii"), "boot identity changed")
        self._process_guard()
        self._pipe_guards()
        # These checks follow the final blocking proc reads. Recheck held/named
        # namespaces and local flags without inserting another proc-file read.
        for role, fd in self._namespaces.items():
            self._check_owned(fd, pid_check=False)
            pid = self._stream[role]["pid"]
            named = os.stat(f"/proc/{pid}/ns/time")
            ns = self._stream["clock"]["time_namespace"]
            _require((named.st_dev, named.st_ino) == (ns["device"], ns["inode"])
                     and os.readlink(f"/proc/{pid}/ns/time") == f"time:[{ns['inode']}]", "closing namespace custody")
        for fd in (self._refresh, self._completion):
            self._local_pipe(fd, writing=fd == self._refresh)
        self._cancel()
        return self._tick()

    def _empty_completion(self):
        self._local_pipe(self._completion)
        try:
            raw = os.read(self._completion, 1)
        except BlockingIOError:
            self._local_pipe(self._completion)
            return
        if type(raw) is bytes and raw:
            self._observed["completion_raw"] = ((self._observed["completion_raw"] or b"") + raw)[:2048]
        self._local_pipe(self._completion)
        raise ValueError("unexpected completion bytes/EOF")

    def _frame(self, observed_key):
        raw = b""
        fragment_deadline = self._deadline
        while True:
            self._guard()
            now = self._tick()
            _require(now < fragment_deadline, "fragment deadline")
            poller = select.poll()
            for fd in (self._completion, self._cancel_fd, *self._pidfds.values()):
                poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
            remaining = min(self._deadline, fragment_deadline) - now
            try:
                events = poller.poll(min((remaining + 999999) // 1000000, 2**31 - 1))
            except InterruptedError:
                continue
            # Exit/cancellation must win even if completion is simultaneously ready.
            self._guard()
            for fd, flags in events:
                _require(fd in (self._completion, self._cancel_fd, *self._pidfds.values()), "unexpected poll descriptor")
                if fd != self._completion:
                    _require(fd == self._cancel_fd and flags == select.POLLIN, "process/cancellation event")
                else:
                    _require(flags == select.POLLIN, "completion pipe error")
            if not any(fd == self._completion for fd, _ in events):
                continue
            self._local_pipe(self._completion)
            try:
                piece = os.read(self._completion, 2049 - len(raw))
            except BlockingIOError:
                self._local_pipe(self._completion)
                continue
            _require(type(piece) is bytes and piece, "completion EOF/read type")
            first_fragment = not raw
            raw += piece
            self._observed[observed_key] = raw[:2048]
            read_finished = self._local_pipe(self._completion)
            if first_fragment:
                fragment_deadline = min(self._deadline, _sum(read_finished, _TIMEOUT))
            _require(len(raw) <= 2048, "completion frame capacity")
            received = self._tick()
            _require(received < fragment_deadline, "late fragment completion")
            if b"\n" in raw:
                _decode(raw, 2048, True)
                if observed_key == "completion_raw":
                    self._observed["completion_received_ns"] = received
                self._guard()
                self._empty_completion()
                return raw, received

    def _cleanup(self):
        failures = self._cleanup_errors
        self._cleanup_errors = []
        listener, self._listener = self._listener, None
        if listener is not None:
            self._unresolved.append(listener)
            if not self._listener_terminal:
                self._listener_terminal = True
                try:
                    listener.close()
                except BaseException as exc:
                    failures.append(exc)
                    self._unresolved.append(exc)
        for fd in tuple(self._owned):
            try:
                self._close_fd(fd)
            except BaseException as exc:
                failures.append(exc)
        failures.extend(self._cleanup_errors)
        self._cleanup_errors = []
        return failures

    def _refuse(self, original):
        self._state, self._closed = "REFUSED", True
        failures = self._cleanup()
        error = ReaderCheckpointSessionError(original, self._observed, failures, self)
        self._failure = error
        self._unresolved.append(original)
        return error

    def _operation(self, body):
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise ReaderCheckpointSessionError(ValueError("session closed"), self._observed, (), self)
        if os.getpid() != _ORIGINAL_PID or threading.get_native_id() != _ORIGINAL_PID:
            # A foreign thread must never close the original owner's descriptors.
            self._state = "REFUSED"
            error = ReaderCheckpointSessionError(ValueError("original main process required"), self._observed, (), self)
            self._failure = error
            raise error
        if not self._lock.acquire(blocking=False):
            # Do not close descriptors underneath another active call.
            self._state = "REFUSED"
            error = ReaderCheckpointSessionError(ValueError("session reentry"), self._observed, (), self)
            self._failure = error
            raise error
        try:
            try:
                self._context_guard()
                return body()
            except BaseException as exc:
                raise self._refuse(exc) from exc
        finally:
            self._lock.release()

    def _listener_call(self, name, *args, **kwargs):
        try:
            return getattr(self._listener, name)(*args, **kwargs)
        except ReaderTransportError as exc:
            self._listener_terminal = True
            self._observed["transport_raw"] = exc.partial_evidence
            self._observed["owned_observed"] = exc.owned_observed
            self._unresolved.append(exc)
            raise

    def _context(self, raw, pin, request_raw, phase, received):
        c = _keys(_document(raw, pin, 8192),
                  "schema request_digest effect_digest grant_digest deployment_digest epoch_digest broker "
                  "provider clock exchange_id accepted_boottime_ns deadline_boottime_ns clock_bracket")
        _require(c["schema"] == "aragorn/native-phase3-broker-reader-context/v1", "context schema")
        for key in ("request_digest", "effect_digest", "grant_digest", "deployment_digest", "epoch_digest"):
            _pin(c[key])
        _nonce(c["exchange_id"])
        _process(c["provider"])
        _process(c["broker"])
        _clock(c["clock"])
        _require(c["provider"] == self._stream["observer"] and c["clock"] == self._stream["clock"]
                 and c["epoch_digest"] == self._epoch_pin and c["deployment_digest"] == self._epoch["deployment_digest"]
                 and c["broker"]["uid"] > 0 and c["broker"]["gid"] > 0
                 and c["broker"]["pid"] not in {self._stream[r]["pid"] for r in (*_PROC_ROLES, "sensor")}
                 and c["broker"]["uid"] != self._stream["reader"]["uid"]
                 and c["broker"]["gid"] != self._stream["reader"]["gid"], "context authority join")
        bracket = _keys(c["clock_bracket"], "boottime_before_ns monotonic_ns boottime_after_ns original_monotonic_deadline_ns")
        for value in bracket.values():
            _uint(value)
        remaining = bracket["original_monotonic_deadline_ns"] - bracket["monotonic_ns"]
        _require(0 < remaining <= 500000000
                 and _uint(c["accepted_boottime_ns"]) <= bracket["boottime_before_ns"] <= bracket["boottime_after_ns"]
                 <= _uint(received) < _uint(c["deadline_boottime_ns"], 1)
                 and c["deadline_boottime_ns"] == _sum(bracket["boottime_before_ns"], remaining), "context clock budget")
        request = validate_guard_request(request_raw)
        _require(request["phase"] == phase and request["context_digest"] == pin
                 and all(request[key] == c[key] for key in ("exchange_id", "epoch_digest", "request_digest",
                                                            "effect_digest", "deadline_boottime_ns")), "request/context join")
        return c, request

    def _new_observations(self):
        old = self._observed
        self._observed = dict.fromkeys(_OBSERVED)
        for key in ("startup_ready_raw", "opening_transport_raw"):
            self._observed[key] = old[key]
        self._observed["command_attempted"] = False

    def _completion_record(self, phase, ordinal, challenge, request_pin, trigger_pin, ack=None):
        raw, received = self._frame("completion_raw")
        value = _keys(_decode(raw, 2048, True), "schema session_id epoch_digest phase ordinal request_digest "
                      "challenge_digest trigger_digest sequence_after manifest_digest publication_digest batch_digest completed_ns")
        _require(value["schema"] == _PREFIX + "checkpoint-ready/v1" and value["session_id"] == self._stream["session_id"]
                 and value["epoch_digest"] == self._epoch_pin and value["phase"] == phase
                 and _uint(value["ordinal"], 1) == ordinal and value["request_digest"] == request_pin
                 and value["challenge_digest"] == challenge and value["trigger_digest"] == trigger_pin
                 and _uint(value["sequence_after"], 1) == _sum(self._sequence, 1), "completion joins")
        for key in ("manifest_digest", "publication_digest", "batch_digest"):
            _pin(value[key])
        _require(_uint(value["completed_ns"]) <= received and (ack is None or value["completed_ns"] <= ack),
                 "completion chronology")
        return value

    def _checkpoint(self, phase, trigger_pin, issued, trigger_deadline, completion, owned, reader_raw):
        reader = owned["reader"]
        expectation = dict(schema=_PREFIX + "checkpoint-expectation/v1", provision_digest=self._provision_pin,
                           phase=phase, epoch_digest=self._epoch_pin, request_digest=owned["bindings"]["request"],
                           challenge_digest=owned["bindings"]["challenge"], trigger_digest=trigger_pin,
                           trigger_issued_ns=issued, trigger_deadline_ns=trigger_deadline, deadline_ns=self._deadline,
                           previous_checkpoint_digest=self._manifest_pin, sequence_before=self._sequence,
                           sequence_after=_sum(self._sequence, 1), offset_before=self._offset, records_before=self._records,
                           reader_evidence_digest=owned["evidence_digest"], reader_summary_digest=_digest(reader_raw),
                           reader_connection_epoch=owned["connection_epoch"], reader_ack_ns=reader["ack_ns"],
                           loss_scope_digest=owned["bindings"]["loss_scope"])
        raw = _raw(_canonical(expectation), 8192)
        self._observed["expectation_raw"] = raw
        self._guard()
        try:
            result = acquire_reader_checkpoint(provision_raw=self._provision_raw,
                                               expected_provision_digest=self._provision_pin,
                                               expectation_raw=raw, expected_expectation_digest=_digest(raw))
        except ReaderCheckpointAcquisitionError as exc:
            self._observed["checkpoint_observed"] = exc.observed
            self._unresolved.append(exc)
            raise
        _keys(result, "acquisition_raw acquisition_digest manifest_raw publication_raw batch_raw")
        acquisition = _decode(result["acquisition_raw"], 16384)
        self._observed["checkpoint_observed"] = {
            **{key: result[key] for key in ("manifest_raw", "publication_raw", "batch_raw", "acquisition_raw")},
            "source_files": acquisition["source_files"], "retained_files": acquisition["retained_files"],
            "claim_attempted": True,
        }
        verified = verify_reader_checkpoint(result["manifest_raw"], result["publication_raw"],
                                            result["batch_raw"], result["acquisition_raw"],
                                            provision_raw=self._provision_raw, expectation_raw=raw,
                                            expected_provision_digest=self._provision_pin,
                                            expected_expectation_digest=_digest(raw),
                                            expected_acquisition_digest=result["acquisition_digest"])
        manifest = _decode(result["manifest_raw"], 16384)
        publication = _decode(result["publication_raw"], 2048)
        _require(all(_digest(result[raw_key]) == completion[pin_key] for raw_key, pin_key in
                     (("manifest_raw", "manifest_digest"), ("publication_raw", "publication_digest"),
                      ("batch_raw", "batch_digest"))), "completion acquired bytes differ")
        _require(publication["receipt_prepared_ns"] <= completion["completed_ns"]
                 <= self._observed["completion_received_ns"] <= acquisition["started_ns"], "completion/readback chronology")
        self._guard()
        return result, verified, manifest

    def _finish_acquire(self, phase, request_raw, received, started, owned, reader_raw,
                        verification_raw, completion, checkpoint, verified, manifest):
        self._guard()
        self._empty_completion()
        finished = self._guard()
        _require(started <= self._observed["completion_received_ns"] <= finished
                 and 0 <= finished - owned["reader"]["ack_ns"] < _AGE, "final original ACK freshness")
        record = dict(schema=_PREFIX + "checkpoint-session/v1", operation=phase,
                      session_id=self._stream["session_id"], epoch_digest=self._epoch_pin,
                      context_digest=self._context_pin, request_packet_digest=_digest(request_raw),
                      request_received_ns=received, started_ns=started,
                      completion_received_ns=self._observed["completion_received_ns"], finished_ns=finished,
                      deadline_ns=self._deadline, notice_digest=_digest(self._observed["notice_raw"]),
                      command_digest=None if phase == "CHALLENGE" else _digest(self._observed["command_raw"]),
                      completion_digest=_digest(self._observed["completion_raw"]),
                      transport_digest=_digest(self._observed["transport_raw"]),
                      reader_evidence_digest=owned["evidence_digest"], reader_summary_digest=_digest(reader_raw),
                      checkpoint_acquisition_digest=checkpoint["acquisition_digest"],
                      checkpoint_manifest_digest=completion["manifest_digest"],
                      previous_checkpoint_digest=self._manifest_pin, **_limits())
        self._observed["session_raw"] = _raw(_canonical(record), 8192)
        result = {key: self._observed[key] for key in ("session_raw", "startup_ready_raw", "opening_transport_raw",
                                                      "notice_raw", "command_raw", "completion_raw", "transport_raw", "expectation_raw")}
        result.update(owned=owned, checkpoint=checkpoint, reader_verification_raw=verification_raw,
                      checkpoint_verification_raw=_canonical(verified))
        # Commit only after both real acquisitions, both independent replays and
        # closing guards. Caller mutation cannot alter the held predecessor.
        self._sequence, self._offset, self._records = (manifest[key] for key in ("sequence_after", "offset_after", "records_after"))
        self._manifest_pin = completion["manifest_digest"]
        self._state = "FIRST_ACQUIRED" if phase == "CHALLENGE" else "SECOND_ACQUIRED"
        self._deadline = min(self._active["context"]["deadline_boottime_ns"], self._loop["session_deadline_ns"])
        return copy.deepcopy(result)

    def acquire_challenge(self, *, context_raw, expected_context_digest, request_raw, admission_digest, request_received_ns):
        def body():
            _require(self._state == "READY", "challenge state")
            self._new_observations()
            self._guard()
            self._empty_completion()
            c, request = self._context(context_raw, expected_context_digest, request_raw, "BEFORE_CONNECT", request_received_ns)
            _pin(admission_digest)
            _require(expected_context_digest not in self._seen_contexts and admission_digest not in self._seen_admissions
                     and self._ordinal < self._loop["max_requests"], "admission/context replay")
            started = self._tick()
            _require(request_received_ns <= started, "actual request receipt")
            self._deadline = min(c["deadline_boottime_ns"], _sum(request_received_ns, 250000000), self._loop["session_deadline_ns"])
            accept_deadline = self._deadline - _TIMEOUT
            _require(started < accept_deadline, "initial response budget")
            self._seen_contexts.add(expected_context_digest)
            self._seen_admissions.add(admission_digest)
            self._ordinal += 1
            self._context_pin = expected_context_digest
            self._active = {"context": c, "context_raw": context_raw, "request_raw": request_raw,
                            "received": request_received_ns}
            self._state = "CHALLENGE_ATTEMPTED"
            notice = self._listener_call("begin_request", admission_digest=admission_digest,
                                         request_digest=request["request_digest"], sequence_before=self._sequence,
                                         accept_deadline_ns=accept_deadline, request_deadline_ns=self._deadline)
            self._observed["notice_raw"] = _raw(notice, 2048)
            self._observed["transport_raw"] = _raw(self._listener.last_evidence_raw, 131072)
            n = _keys(_decode(notice, 2048, True), "schema listener_epoch ordinal admission_digest epoch_digest "
                      "request_digest sequence_before issued_ns accept_deadline_ns request_deadline_ns")
            _require(n["ordinal"] == self._ordinal and n["admission_digest"] == admission_digest
                     and n["epoch_digest"] == self._epoch_pin and n["request_digest"] == request["request_digest"]
                     and n["sequence_before"] == self._sequence and n["accept_deadline_ns"] == accept_deadline
                     and n["request_deadline_ns"] == self._deadline, "actual listener notice")
            self._guard()
            result = self._listener_call("accept_request", notice)
            _keys(result, "owned transport_raw transport_digest listener_reusable")
            self._observed["transport_raw"] = _raw(result["transport_raw"], 131072)
            owned = result["owned"]
            self._observed["owned_observed"] = owned
            self._guard()
            transport = _decode(result["transport_raw"], 131072)
            _require(result["listener_reusable"] is True and _digest(result["transport_raw"]) == result["transport_digest"]
                     and all(transport[key] is False for key in (*_FLAGS, "request_timing_verified")), "transport output")
            _keys(owned, "reader challenge_raw claim_raw bindings connection_epoch evidence_raw evidence_digest " + " ".join(_FLAGS))
            _require(all(owned[key] is False for key in _FLAGS) and owned["reader"]["status"] == "ACK"
                     and owned["bindings"]["epoch"] == self._epoch_pin
                     and owned["bindings"]["request"] == request["request_digest"], "successful original reader")
            reader_raw = _raw(_canonical(owned["reader"]), 32768)
            verified = verify_reader_evidence(owned["evidence_raw"], reader_raw, bindings=owned["bindings"],
                                              expected_evidence_digest=owned["evidence_digest"],
                                              expected_reader_digest=_digest(reader_raw),
                                              expected_observer=self._transport["observer"],
                                              expected_connection_epoch=owned["connection_epoch"],
                                              credential_abi="linux-le-ucred32-v1")
            challenge = _keys(_decode(owned["challenge_raw"], 4096),
                              "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
            evidence = _decode(owned["evidence_raw"], 131072)
            _require(base64.b64decode(evidence["challenge_base64"], validate=True) == owned["challenge_raw"]
                     and base64.b64decode(evidence["claim_base64"], validate=True) == owned["claim_raw"]
                     and challenge["sequence_before"] == self._sequence
                     and owned["reader"]["sequence_after"] == _sum(self._sequence, 1)
                     and challenge["deadline_ns"] <= self._deadline, "original challenge joins")
            self._deadline = min(self._deadline, _sum(owned["reader"]["ack_ns"], _AGE))
            completion = self._completion_record("CHALLENGE", self._ordinal, owned["bindings"]["challenge"],
                                                 request["request_digest"], owned["bindings"]["challenge"], owned["reader"]["ack_ns"])
            checkpoint, checked, manifest = self._checkpoint("CHALLENGE", owned["bindings"]["challenge"],
                                                            challenge["issued_ns"], challenge["deadline_ns"],
                                                            completion, owned, reader_raw)
            result = self._finish_acquire("CHALLENGE", request_raw, request_received_ns, started, owned, reader_raw,
                                          _canonical(verified), completion, checkpoint, checked, manifest)
            self._first = copy.deepcopy(result)
            return result
        return self._operation(body)

    def acquire_refresh(self, *, context_raw, expected_context_digest, request_raw,
                        first_response_raw, expected_first_response_digest, request_received_ns):
        def body():
            _require(self._state == "FIRST_ACQUIRED", "refresh state")
            self._new_observations()
            for key in ("notice_raw", "transport_raw"):
                self._observed[key] = self._first[key]
            owned = self._first["owned"]
            self._observed["owned_observed"] = owned
            self._guard()
            self._empty_completion()
            c, request = self._context(context_raw, expected_context_digest, request_raw, "BEFORE_PAYLOAD_SEND", request_received_ns)
            _require(expected_context_digest == self._context_pin and context_raw == self._active["context_raw"], "refresh context changed")
            _pin(expected_first_response_digest)
            _require(_digest(_raw(first_response_raw, 262144)) == expected_first_response_digest
                     and request["previous_response_digest"] == expected_first_response_digest, "original response pin")
            response = validate_guard_response(first_response_raw, request_raw=self._active["request_raw"])
            reader_raw = _canonical(owned["reader"])
            _require(response["status"] == "EVIDENCE" and response["bindings"] == owned["bindings"]
                     and response["reader_connection_epoch"] == owned["connection_epoch"]
                     and response["reader_retention"] == {"digest": owned["evidence_digest"], "bytes": len(owned["evidence_raw"])},
                     "first response evidence authority unavailable")
            for field, raw in (("reader_evidence", owned["evidence_raw"]), ("reader_summary", reader_raw),
                               ("checkpoint_record", self._first["checkpoint"]["acquisition_raw"])):
                _require(base64.b64decode(response[field]["base64"], validate=True) == raw, "original retained artifact changed")
            first_session = _decode(self._first["session_raw"], 8192)
            _require(response["received_ns"] == self._active["received"]
                     and first_session["finished_ns"] <= response["finished_ns"] <= request_received_ns
                     and response["finished_ns"] < first_session["deadline_ns"], "first response timing")
            started = self._tick()
            ack = owned["reader"]["ack_ns"]
            _require(request_received_ns <= started and 0 <= started - ack < _AGE, "original ACK stale")
            self._deadline = min(c["deadline_boottime_ns"], _sum(request_received_ns, _TIMEOUT),
                                 _sum(ack, _AGE), self._loop["session_deadline_ns"])
            self._guard()
            self._refresh_ordinal = _sum(self._refresh_ordinal, 1)
            issued = self._tick()
            command = dict(schema=_PREFIX + "checkpoint-refresh/v1", session_id=self._stream["session_id"],
                           ordinal=self._refresh_ordinal, epoch_digest=self._epoch_pin,
                           request_digest=owned["bindings"]["request"], challenge_digest=owned["bindings"]["challenge"],
                           reader_evidence_digest=owned["evidence_digest"], reader_summary_digest=_digest(reader_raw),
                           reader_connection_epoch=owned["connection_epoch"], previous_checkpoint_digest=self._manifest_pin,
                           sequence_before=self._sequence, second_request_digest=_digest(request_raw),
                           issued_ns=issued, deadline_ns=self._deadline)
            raw = _raw(_canonical(command) + b"\n", 2048)
            self._observed["command_raw"] = raw
            pipe_buf = os.fpathconf(self._refresh, "PC_PIPE_BUF")
            _require(type(pipe_buf) is int and len(raw) <= pipe_buf, "atomic refresh bound")
            self._state = "REFRESH_ATTEMPTED"
            self._observed["command_attempted"] = True
            self._local_pipe(self._refresh, writing=True)
            written = os.write(self._refresh, raw)
            self._observed["command_bytes_written"] = _uint(written, 0, len(raw))
            self._local_pipe(self._refresh, writing=True)
            _require(written == len(raw), "short/ambiguous refresh write")
            self._guard()
            completion = self._completion_record("REFRESH", self._refresh_ordinal, owned["bindings"]["challenge"],
                                                 owned["bindings"]["request"], _digest(raw))
            checkpoint, checked, manifest = self._checkpoint("REFRESH", _digest(raw), issued, self._deadline,
                                                            completion, owned, reader_raw)
            return self._finish_acquire("REFRESH", request_raw, request_received_ns, started, owned, reader_raw,
                                        self._first["reader_verification_raw"], completion, checkpoint, checked, manifest)
        return self._operation(body)

    def _terminal(self, operation, finished):
        return _raw(_canonical(dict(schema=_PREFIX + "checkpoint-session-terminal/v1", operation=operation,
                                    session_id=self._stream["session_id"], context_digest=self._context_pin,
                                    sequence_after=self._sequence, manifest_digest=self._manifest_pin,
                                    finished_ns=finished, **_limits())), 2048)

    def finish_request(self, *, expected_context_digest):
        def body():
            _require(self._state in ("FIRST_ACQUIRED", "SECOND_ACQUIRED")
                     and expected_context_digest == self._context_pin, "finish active context")
            self._guard()
            self._empty_completion()
            raw = self._terminal("FINISH", self._guard())
            self._active = self._first = None
            self._state = "READY"
            self._deadline = self._loop["session_deadline_ns"]
            return raw
        return self._operation(body)

    def close(self):
        def body():
            _require(self._state in ("READY", "FIRST_ACQUIRED", "SECOND_ACQUIRED"), "close state")
            self._guard()
            self._empty_completion()
            self._closed, self._state = True, "CLOSED"
            failures = self._cleanup()
            if failures:
                self._cleanup_errors.extend(failures)
                raise failures[0]
            return self._terminal("CLOSE", self._tick())
        return self._operation(body)
