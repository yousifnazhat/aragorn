"""One authenticated HTTP refusal exchange under the original borrowed broker lock.

The configured sources and Root process domain are protected supplied bindings.
Only local broker/descriptor observations are acquired here. Missing loss never
permits an effect; no positive profile or runtime injection hook exists.
"""

import array
import errno
import fcntl
import hashlib
import importlib
import json
import math
import os
import re
import secrets
import select
import socket
import stat
import struct
import sys
import threading
import time

from .native_phase3_broker_reader_protocol import validate_guard_request, validate_guard_response, ERROR_CODES
from .runtime_http_run_submission import begin_http_submission_locked, SubmissionJournalError
from .runtime_http_action import validate_effect, validate_fixture_binding, effect_for_attempt, action_digests

_PID = os.getpid()
_THREAD = threading.main_thread().ident
_ENTRY = threading.Lock()
_CONFIGURED = False
_BEGUN = False
_CONFIGURATION = None
_QUARANTINE = []
_MAX = 2**63 - 1
_PREFIX = "aragorn/native-phase3-broker-reader-"
_PARENT = "/run/aragorn-phase3-broker-reader"
_ENDPOINT = _PARENT + "/guard.sock"
_CONTROL = "/var/lib/aragorn-runtime-action/control"
_PATHS = ("/", "/run", _PARENT, "/var", "/var/lib", "/var/lib/aragorn-runtime-action", _CONTROL)
_REPORT = "sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9"
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized", "run_qualified", "phase3_qualified")
_OBSERVED = ("provision_raw source_inventory_raw measurement_binding_raw fixture_binding_raw "
             "action_request_raw effect_raw measurement_pending_raw context_raw bound_raw "
             "request_raw response_raw transport_raw ipc_raw record_observations "
             "handle_observations transport_observations journal_error send_attempted bytes_sent").split()
_OPEN = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
_O_PATH = 0x200000
_SO_PASSCRED, _SO_PEERCRED, _SO_PASSPIDFD, _SO_PEERPIDFD = 16, 17, 76, 77
_MSG_DONTWAIT, _MSG_NOSIGNAL, _MSG_CLOEXEC = 0x40, 0x4000, 0x40000000
_SCM_CREDENTIALS, _SCM_PIDFD = 2, 4
_TOKEN = object()

def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _uint(value, minimum=0, maximum=_MAX):
    _require(type(value) is int and minimum <= value <= maximum, "integer bound")
    return value


def _add(a, b):
    return _uint(_uint(a) + _uint(b))


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "record fields")
    return value


def _raw(value, limit):
    _require(type(value) is bytes and 0 < len(value) <= limit, "byte bound")
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "digest pin")
    return value


def _pairs(items):
    result = {}
    for name, value in items:
        _require(name not in result, "duplicate key")
        result[name] = value
    return result


def _decode(raw, bound):
    _raw(raw, bound)
    def invalid(value):
        raise ValueError("nonfinite JSON")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_constant=invalid)
    _require(_canonical(value) == raw, "noncanonical JSON")
    return value


def _document(raw, pin, bound):
    _raw(raw, bound)
    _require(_digest(raw) == _pin(pin), "input digest")
    return _decode(raw, bound)


def _detached(value):
    # Exceptions/socket-owning objects must keep their actual identity.
    if type(value) is dict:
        return {key: _detached(item) for key, item in value.items()}
    if type(value) is list:
        return [_detached(item) for item in value]
    if type(value) is tuple:
        return tuple(_detached(item) for item in value)
    return value


def _metadata(value):
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode, uid=value.st_uid, gid=value.st_gid)


def _meta(value):
    _keys(value, "device inode mode uid gid")
    for key in value:
        _uint(value[key], 1 if key == "inode" else 0)
    return value


def _process(value):
    _keys(value, "pid start_time_ticks uid gid")
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    for key in ("uid", "gid"):
        _uint(value[key], 0, 4294967295)
    return value


def _clock(value):
    _keys(value, "boot_id clock_id time_namespace")
    _require(type(value["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["boot_id"]), "boot ID")
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "clock ID")
    _keys(value["time_namespace"], "device inode")
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


class _Refusal(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.failure_code = code


def _check(condition, code, message):
    if not condition:
        raise _Refusal(code, message)


def _entry_owner():
    _check(os.getpid() == _PID and threading.get_ident() == _THREAD
           and threading.current_thread() is threading.main_thread(),
           "IDENTITY_CHANGED", "original main owner")


def _full(metadata):
    result = dict(_metadata(metadata), nlink=metadata.st_nlink, bytes=metadata.st_size,
                  mtime_ns=metadata.st_mtime_ns, ctime_ns=metadata.st_ctime_ns)
    for key, value in result.items():
        if key in ("mtime_ns", "ctime_ns"):
            _require(type(value) is int and -(2**63) <= value < 2**63, "signed metadata")
        else:
            _uint(value, 1 if key == "inode" else 0)
    return result


class BrokerReaderIpcError(ValueError):
    def __init__(self, code, original, cleanup, observed, owner):
        super().__init__("broker reader client refused")
        self.failure_code = code
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup[:32])
        self.observed = _detached(observed)
        self.unresolved_owner = owner


class _Custody:
    def __init__(self):
        self._thread = threading.get_native_id()
        self._owned, self._borrowed = {}, {}
        self._unresolved, self._cleanup_errors = [], []
        self._first_cleanup_interrupt = None
        self._dirs, self._namespaces, self._records = {}, {}, []
        self._provision = None
        self._deadline, self._mono_deadline = _MAX, _MAX
        self._last_ns = self._last_mono = -1
        self._lock = threading.Lock()
        self._failure = None
        self._closed = False
        self._connection = self._peer_fd = self._peer_raw = None
        self._socket_named = None
        self._context = self._context_pin = self._request = None
        self._received = None
        self._observed = dict.fromkeys(_OBSERVED)
        self._observed.update(record_observations=[], handle_observations=[],
                              transport_observations=[], send_attempted=False)
        self._stage_code = "INPUT_REFUSED"

    def _owner(self):
        prior_code = self._stage_code
        self._stage_code = "IDENTITY_CHANGED"
        _entry_owner()
        _check(threading.get_native_id() == self._thread, "IDENTITY_CHANGED", "native owner")
        if self._provision is not None:
            broker = self._provision["broker"]
            _check(os.getresuid() == (broker["uid"],) * 3
                   and os.getresgid() == (broker["gid"],) * 3,
                   "IDENTITY_CHANGED", "saved account vectors")
        self._stage_code = prior_code

    def _tick(self, *, deadline=True):
        self._owner()
        prior_code = self._stage_code
        self._stage_code = "CLOCK_REFUSED"
        before = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        mono = _uint(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        after = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _check(after >= before >= self._last_ns and mono >= self._last_mono,
               "CLOCK_REFUSED", "clock rollback")
        self._last_ns, self._last_mono = after, mono
        if deadline:
            _check(after < self._deadline and mono < self._mono_deadline,
                   "DEADLINE_EXPIRED", "original deadline")
        self._stage_code = prior_code
        return after

    @staticmethod
    def _row(*, pid=None, obj=None, role=None):
        return dict(identity=None, flags=None, descriptor_flags=None, link=None,
                    pid=pid, object=obj, consumed=False, role=role)

    def _register(self, fd, *, pid=None, obj=None, minimum=0):
        if obj is not None:
            self._unresolved.append(obj)
        _uint(fd, minimum)
        _check(fd not in self._owned and fd not in self._borrowed,
               "IDENTITY_CHANGED", "descriptor alias")
        self._owned[fd] = self._row(pid=pid, obj=obj)
        _require(len(self._owned) <= 64, "descriptor capacity")
        return fd

    def _row_for(self, fd):
        return self._owned[fd] if fd in self._owned else self._borrowed[fd]

    def _initial(self, fd):
        self._owner()
        prior_code = self._stage_code
        self._stage_code = "IDENTITY_CHANGED"
        row = self._row_for(fd)
        row["identity"] = _metadata(os.fstat(fd))
        row["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        row["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        row["link"] = os.readlink(f"/proc/self/fd/{fd}")
        if row["link"] == "anon_inode:[pidfd]" and row["pid"] is None:
            row["pid"] = "UNKNOWN"
        _require(type(row["link"]) is str and row["link"].isascii() and len(row["link"]) <= 4096,
                 "descriptor link")
        self._owner()
        _check(_metadata(os.fstat(fd)) == row["identity"], "IDENTITY_CHANGED", "initial custody")
        self._stage_code = prior_code

    def _own(self, fd, *, pid=None, obj=None):
        self._register(fd, pid=pid, obj=obj)
        self._initial(fd)
        return fd

    def _local(self, fd, *, terminal=False):
        self._owner()
        prior_code = self._stage_code
        self._stage_code = "IDENTITY_CHANGED"
        row = self._row_for(fd)
        _check((terminal or not row["consumed"]) and row["identity"] is not None,
               "IDENTITY_CHANGED", "descriptor unavailable")
        obj = row["object"]
        _check(obj is None or obj.fileno() == fd, "IDENTITY_CHANGED", "socket fileno")
        _check(_metadata(os.fstat(fd)) == row["identity"], "IDENTITY_CHANGED", "held identity")
        link = os.readlink(f"/proc/self/fd/{fd}")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        dflags = fcntl.fcntl(fd, fcntl.F_GETFD)
        self._owner()
        _check(link == row["link"] and flags == row["flags"] and dflags == row["descriptor_flags"]
               and _metadata(os.fstat(fd)) == row["identity"] and (obj is None or obj.fileno() == fd),
               "IDENTITY_CHANGED", "closing flags/link/custody")
        self._stage_code = prior_code
        return row

    def _immediate(self, fd):
        """Finite local checks after a closing clock sample; no proc/path reads."""
        self._owner()
        row = self._row_for(fd)
        obj = row["object"]
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        dflags = fcntl.fcntl(fd, fcntl.F_GETFD)
        self._owner()
        _check(not row["consumed"] and flags == row["flags"] and dflags == row["descriptor_flags"]
               and _metadata(os.fstat(fd)) == row["identity"] and (obj is None or obj.fileno() == fd),
               "IDENTITY_CHANGED", "immediate descriptor custody")

    def _retain_handle(self, fd, *, raw=None, closed=False, row=None):
        row = self._row_for(fd) if row is None else row
        if row["role"] is None:
            return
        snap = dict(role=row["role"], descriptor=fd, observed_ns=self._tick(deadline=False),
                    metadata=row["identity"], flags=row["flags"], descriptor_flags=row["descriptor_flags"],
                    link=row["link"], pidfd_info_raw=raw, closed=closed)
        rows = self._observed["handle_observations"]
        indices = [i for i, item in enumerate(rows) if item["role"] == row["role"]]
        if len(indices) == 2:
            rows.pop(indices[-1])
        rows.append(snap)
        _require(len(rows) <= 10, "handle observation bound")

    def _read(self, path, bound, *, observed=None, key=None):
        self._owner()
        fd = os.open(path, _OPEN)
        previous = self._owned.get(fd)
        original = None
        try:
            self._own(fd)
            result = bytearray()
            while True:
                self._local(fd)
                raw = os.read(fd, bound + 1 - len(result))
                _require(type(raw) is bytes, "read bytes")
                result.extend(raw)
                if observed is not None:
                    observed[key] = bytes(result[:bound])
                self._local(fd)
                _require(len(result) <= bound, "read bound")
                if not raw:
                    return bytes(result)
        except BaseException as exc:
            original = exc
            raise
        finally:
            try:
                if previous is None and fd not in self._borrowed:
                    self._close_fd(fd)
            except BaseException as exc:
                self._note_cleanup(exc)
                if original is None:
                    raise

    def _association(self, fd, *, terminal=False):
        row = self._local(fd, terminal=terminal)
        raw = self._read(f"/proc/self/fdinfo/{fd}", 4096)
        values = re.findall(rb"^Pid:\s*([0-9]+)\s*$", raw, re.MULTILINE)
        _check(len(values) == 1, "IDENTITY_CHANGED", "PIDFD association record")
        pid = _uint(int(values[0]), 1, 2147483647)
        self._local(fd, terminal=terminal)
        if type(row["pid"]) is int:
            _check(pid == row["pid"], "IDENTITY_CHANGED", "PIDFD association changed")
        return pid, raw

    def _live(self, fd):
        row = self._local(fd)
        _check(type(row["pid"]) is int, "IDENTITY_CHANGED", "unknown PIDFD")
        _, raw = self._association(fd)
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        _check(poller.poll(0) == [], "IDENTITY_CHANGED", "process exited")
        self._local(fd)
        self._retain_handle(fd, raw=raw)
        return raw

    def _cancel_guard(self):
        row = self._local(self._cancel)
        expected = {k: self._provision["cancellation_pipe"][k] for k in ("device", "inode", "mode", "uid", "gid")}
        _check(row["identity"] == expected and row["flags"] & os.O_ACCMODE == os.O_RDONLY
               and row["flags"] & os.O_NONBLOCK and row["descriptor_flags"] & fcntl.FD_CLOEXEC
               and row["link"] == f"pipe:[{expected['inode']}]", "IDENTITY_CHANGED", "cancel custody")
        self._retain_handle(self._cancel)
        self._local(self._cancel)

    def _cancelled(self):
        self._cancel_guard()
        self._tick()
        self._immediate(self._cancel)
        try:
            raw = os.read(self._cancel, 1)
        except BlockingIOError:
            self._cancel_guard()
            return
        self._cancel_guard()
        raise _Refusal("PROTOCOL_REFUSED", "cancellation EOF" if raw == b"" else "cancellation data")

    def _close_fd(self, fd):
        if fd not in self._owned or self._owned[fd]["consumed"]:
            return
        self._owner()
        row = self._owned[fd]
        row["consumed"] = True
        self._local(fd, terminal=True)
        info = None
        if row["pid"] is not None:
            _check(type(row["pid"]) is int, "IDENTITY_CHANGED", "unknown closing PIDFD")
            _, info = self._association(fd, terminal=True)
        self._local(fd, terminal=True)
        if row["object"] is not None:
            obj = row["object"]
            self._unresolved.append(obj)
            actual = obj.detach()
            _check(type(actual) is int and actual == fd, "IDENTITY_CHANGED", "detach identity")
            row["object"] = None
            self._local(fd, terminal=True)
        os.close(fd)
        retired = self._owned.pop(fd)
        self._retain_handle(fd, raw=info, closed=True, row=retired)

    def _note_cleanup(self, error):
        if self._first_cleanup_interrupt is None and isinstance(error, (KeyboardInterrupt, SystemExit, MemoryError)):
            self._first_cleanup_interrupt = error
        self._cleanup_errors.append(error)

    def _close_owned(self):
        errors = list(self._cleanup_errors)
        self._cleanup_errors.clear()
        for fd in tuple(self._owned):
            try:
                self._close_fd(fd)
            except BaseException as exc:
                if self._first_cleanup_interrupt is None and isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
                    self._first_cleanup_interrupt = exc
                errors.append(exc)
        errors.extend(self._cleanup_errors)
        self._cleanup_errors.clear()
        if self._owned or self._unresolved or errors:
            _QUARANTINE.append(self)
        return errors

    def _error(self, original, errors=()):
        if self._failure is not None:
            self._failure.observed = _detached(self._observed)
            later = ([] if original is self._failure else [original]) + list(errors)
            self._failure.cleanup_failures = tuple((list(self._failure.cleanup_failures) + later)[:32])
            return self._failure
        code = original.failure_code if isinstance(original, _Refusal) else self._stage_code
        if code not in ERROR_CODES:
            code = "INTERNAL_REFUSAL"
        _QUARANTINE.append(self)
        if isinstance(original, (KeyboardInterrupt, SystemExit, MemoryError)):
            original.failure_code = code
            original.observed = _detached(self._observed)
            original.cleanup_failures = tuple(errors[:32])
            original.unresolved_owner = self
            self._failure = original
            return original
        failure = BrokerReaderIpcError(code, original, errors, self._observed, self)
        self._failure = failure
        return failure

    def _validate(self, provision_raw, provision_pin, source_raw, source_pin, measurement_raw, measurement_pin,
                  fixture_raw, fixture_pin):
        p = _keys(_document(provision_raw, provision_pin, 16384),
                  "schema profile broker provider supervisor clock epoch_digest deployment_digest grant_digest "
                  "measurement_binding_digest fixture_binding_digest source_inventory_digest access_inventory_digest "
                  "reader_session directories cancellation_pipe session_deadline_ns accept_deadline_ns")
        _require(p["schema"] == _PREFIX + "ipc-provision/v1" and p["profile"] == "HTTP_REFUSAL_ONLY", "profile")
        for role in ("broker", "provider", "supervisor"):
            _process(p[role])
            _require((p[role]["uid"] > 0 and p[role]["gid"] > 0) if role == "broker"
                     else p[role]["uid"] == p[role]["gid"] == 0, "role account")
        _require(len({p[r]["pid"] for r in ("broker", "provider", "supervisor")}) == 3
                 and p["broker"]["pid"] == _PID, "role processes")
        _clock(p["clock"])
        for key in p:
            if key.endswith("_digest"):
                _pin(p[key])
        _require(_uint(p["accept_deadline_ns"], 1) < _uint(p["session_deadline_ns"], 1), "service deadlines")
        _keys(p["reader_session"], "epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest loop_provision_digest")
        for pin in p["reader_session"].values():
            _pin(pin)
        _require(p["reader_session"]["epoch_digest"] == p["epoch_digest"], "epoch pin")
        _require(type(p["directories"]) is list and len(p["directories"]) == 7, "directory count")
        for item, path in zip(p["directories"], _PATHS, strict=True):
            _keys(item, "path device inode mode uid gid")
            meta = _meta({k: item[k] for k in ("device", "inode", "mode", "uid", "gid")})
            _require(item["path"] == path and stat.S_ISDIR(meta["mode"]), "directory path/type")
            if path == _PATHS[-1]:
                _require((meta["uid"], meta["gid"], stat.S_IMODE(meta["mode"])) == (p["broker"]["uid"], p["broker"]["gid"], 0o700), "control protections")
            else:
                _require(meta["uid"] == 0 and not meta["mode"] & 0o022, "root ancestry")
            if path == _PARENT:
                _require(meta["gid"] == p["broker"]["gid"] and stat.S_IMODE(meta["mode"]) == 0o710, "endpoint parent")
        cancel = _keys(p["cancellation_pipe"], "device inode mode uid gid writer readers")
        _meta({k: cancel[k] for k in ("device", "inode", "mode", "uid", "gid")})
        _require(cancel["mode"] == stat.S_IFIFO | 0o600 and cancel["uid"] == cancel["gid"] == 0, "cancel pipe metadata")
        _keys(cancel["writer"], "process fd")
        _require(cancel["writer"]["process"] == "SUPERVISOR", "cancel writer")
        _uint(cancel["writer"]["fd"], 3)
        _require(type(cancel["readers"]) is list and len(cancel["readers"]) == 2, "cancel readers")
        for entry, role in zip(cancel["readers"], ("PROVIDER", "BROKER"), strict=True):
            _keys(entry, "process fd")
            _require(entry["process"] == role, "cancel reader role")
            _uint(entry["fd"], 3)
        _require(cancel["readers"][1]["fd"] == self._cancel, "local cancellation FD")
        inventory = _keys(_document(source_raw, source_pin, 65536), "schema predecessor_report_digest entries")
        _require(inventory["schema"] == _PREFIX + "installed-sources/v1" and inventory["predecessor_report_digest"] == _REPORT, "source inventory")
        entries = inventory["entries"]
        _require(type(entries) is list and 1 <= len(entries) <= 128, "source count")
        paths, total = [], 0
        for entry in entries:
            _keys(entry, "path role bytes digest device inode mode uid gid")
            path = entry["path"]
            _require(type(path) is str and path.isascii() and 1 < len(path) <= 4096 and path.startswith("/")
                     and all(part not in ("", ".", "..") for part in path[1:].split("/")) and "\0" not in path, "source path")
            _require(entry["role"] in ("BROKER", "PROVIDER", "SHARED"), "source role")
            _meta({k: entry[k] for k in ("device", "inode", "mode", "uid", "gid")})
            _require(stat.S_ISREG(entry["mode"]) and entry["uid"] == 0 and not entry["mode"] & 0o022, "source protections")
            total += _uint(entry["bytes"], 1, 16777216)
            _pin(entry["digest"])
            paths.append(path)
        _require(paths == sorted(set(paths)) and total <= 67108864 and p["source_inventory_digest"] == source_pin, "source bounds/pin")
        m = _keys(_document(measurement_raw, measurement_pin, 8192),
                  "schema boot_id attempt_id deployment_identity_digest measurement_schedule_digest collection_commitment_digest "
                  "scheduled_measurement_request_digest grant_digest runtime_profile_digest sensor_digest source_pins runtime_digest "
                  "policy_digest active_skill_digest operation_digest path_digest payload_digest")
        _require(m["schema"] == "aragorn/runtime-broker-decision-measurement-binding/v1"
                 and re.fullmatch(r"p3-lab-a0(?:0[1-9]|1[0-9]|2[0-5])", m["attempt_id"])
                 and m["boot_id"] == p["clock"]["boot_id"] and m["grant_digest"] == p["grant_digest"]
                 and m["deployment_identity_digest"] == p["deployment_digest"], "measurement joins")
        for key in m:
            if key.endswith("_digest"):
                _pin(m[key])
        _require(type(m["source_pins"]) is dict and 1 <= len(m["source_pins"]) <= 128, "measurement source count")
        for name, pin in m["source_pins"].items():
            _require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}\.py", name), "source basename")
            _pin(pin)
        f = _keys(_document(fixture_raw, fixture_pin, 16384), "schema fixture expected_broker_uid expected_broker_gid")
        fixture = _keys(f["fixture"], "container_id boot_id netns_device netns_inode")
        _require(f["schema"] == "aragorn/runtime-http-fixture-binding/v1" and type(fixture["container_id"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", fixture["container_id"]) and fixture["boot_id"] == p["clock"]["boot_id"]
                 and f["expected_broker_uid"] == p["broker"]["uid"] and f["expected_broker_gid"] == p["broker"]["gid"], "fixture joins")
        _uint(f["expected_broker_uid"], 1, 4294967295)
        _uint(f["expected_broker_gid"], 1, 4294967295)
        _uint(fixture["netns_device"])
        _uint(fixture["netns_inode"], 1)
        _require(p["measurement_binding_digest"] == measurement_pin and p["fixture_binding_digest"] == fixture_pin, "credential pins")
        validate_fixture_binding(f)
        _require(validate_effect(effect_for_attempt(m["attempt_id"])) == effect_for_attempt(m["attempt_id"]), "HTTP effect")
        _require(all(m[key] == value for key, value in action_digests(m["attempt_id"], f).items()), "HTTP measurement actions")
        self._provision, self._measurement, self._fixture = p, m, f
        self._provision_pin, self._source_pin = provision_pin, source_pin
        self._deadline = p["session_deadline_ns"]
        self._observed.update(provision_raw=provision_raw, source_inventory_raw=source_raw,
                              measurement_binding_raw=measurement_raw, fixture_binding_raw=fixture_raw)

    def _open_views(self, *, control=None):
        # O_PATH permits protected 0710 ancestry search without adding read access.
        for path in _PATHS:
            parent_path = path.rsplit("/", 1)[0] or "/"
            parent = None if path == "/" else self._dirs[parent_path][0]
            name = "/" if path == "/" else path.rsplit("/", 1)[1]
            if path == _CONTROL and control is not None:
                fd = control
            else:
                self._owner()
                fd = os.open(name, _O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                self._own(fd)
            self._dirs[path] = (fd, parent, name)
        for kind in ("time", "mnt"):
            fd = os.open(f"/proc/{_PID}/ns/{kind}", os.O_RDONLY | os.O_CLOEXEC)
            self._own(fd)
            self._namespaces[kind] = fd

    def _directory_guards(self):
        result = []
        for expected in self._provision["directories"]:
            path = expected["path"]
            fd, parent, name = self._dirs[path]
            row = self._local(fd)
            named = _metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
            meta = {k: expected[k] for k in ("device", "inode", "mode", "uid", "gid")}
            _check(row["identity"] == named == meta, "IDENTITY_CHANGED", "directory custody")
            self._local(fd)
            result.append(dict(expected, held=row["identity"], named=named))
        return result

    def _namespace(self):
        result = {}
        for kind, fd in self._namespaces.items():
            row = self._local(fd)
            path = f"/proc/{_PID}/ns/{kind}"
            named = os.stat(path)
            pair = dict(device=named.st_dev, inode=named.st_ino)
            link = os.readlink(path)
            held = {k: row["identity"][k] for k in ("device", "inode")}
            _check(stat.S_ISREG(row["identity"]["mode"]) and held == pair
                   and link == f"{kind}:[{pair['inode']}]" and len(link) <= 128
                   and (kind != "time" or held == self._provision["clock"]["time_namespace"]),
                   "IDENTITY_CHANGED", "namespace custody")
            self._local(fd)
            result["time" if kind == "time" else "mount"] = dict(held=held, named=pair, link=link)
        return result

    def _process(self, snap):
        broker = self._provision["broker"]
        values = []
        for suffix, field in (("stat", "broker_stat_before"), ("status", "broker_status"), ("stat", "broker_stat_after")):
            values.append(self._read(f"/proc/{_PID}/{suffix}", 16384, observed=snap["proc_raw"], key=field))
        before, status, after = values
        for raw in (before, after):
            marker = raw.rfind(b") ")
            fields = raw[marker + 2:].split()
            _check(raw.startswith(f"{_PID} (".encode()) and marker >= 0 and len(fields) >= 20
                   and fields[0] not in (b"Z", b"X", b"x") and fields[19].isdigit()
                   and int(fields[19]) == broker["start_time_ticks"], "IDENTITY_CHANGED", "broker epoch")
        for key, expected in ((b"Uid", broker["uid"]), (b"Gid", broker["gid"])):
            matches = re.findall(rb"^" + key + rb":\s*([^\n]+)$", status, re.MULTILINE)
            _check(len(matches) == 1 and [int(x) for x in matches[0].split()] == [expected] * 4,
                   "IDENTITY_CHANGED", "broker status accounts")
        groups = re.findall(rb"^Groups:([^\n]*)$", status, re.MULTILINE)
        _check(len(groups) == 1 and sorted(int(x) for x in groups[0].split()) == sorted(os.getgroups()),
               "IDENTITY_CHANGED", "supplementary account observation")
        self._owner()

    def _snapshot(self, edge, *, controls=None, flags=None, terminal=False):
        snap = dict(edge=edge, started_ns=self._tick(deadline=not terminal), finished_ns=None,
                    peer_credentials_raw=None, pidfd_info_raw=None,
                    proc_raw={key: None for key in ("broker_stat_before", "broker_status", "broker_stat_after",
                                                   "provider_stat_before", "provider_status", "provider_stat_after")},
                    boot_raw=None, namespaces={"broker": None, "provider": None}, controls=controls,
                    receive_flags=flags, socket_options=None, directories=[])
        rows = self._observed["transport_observations"]
        indices = [i for i, row in enumerate(rows) if row["edge"] == edge]
        if len(indices) == 2:
            rows.pop(indices[-1])
        rows.append(snap)
        _require(len(rows) <= 16, "transport observations bound")
        return snap

    def _boot(self, snap):
        fd = os.open("aragorn-broker-boot-id", _OPEN, dir_fd=self._dirs["/run"][0])
        old = self._owned.get(fd)
        original = None
        try:
            self._own(fd)
            identity = _full(os.fstat(fd))
            _check(stat.S_ISREG(identity["mode"]) and identity["nlink"] == 1
                   and identity["uid"] == identity["gid"] == 0 and not identity["mode"] & 0o022,
                   "IDENTITY_CHANGED", "protected boot metadata")
            self._local(fd)
            raw = os.pread(fd, 65, 0)
            snap["boot_raw"] = raw[:64]
            self._local(fd)
            named = os.stat("aragorn-broker-boot-id", dir_fd=self._dirs["/run"][0], follow_symlinks=False)
            _check(_full(os.fstat(fd)) == identity == _full(named)
                   and raw == (self._provision["clock"]["boot_id"] + "\n").encode(),
                   "IDENTITY_CHANGED", "protected boot changed")
            self._local(fd)
        except BaseException as exc:
            original = exc
            raise
        finally:
            if old is None and fd in self._owned:
                try:
                    self._close_fd(fd)
                except BaseException as exc:
                    self._note_cleanup(exc)
                    if original is None:
                        raise

    def _named_socket(self):
        parent = self._dirs[_PARENT][0]
        actual = _metadata(os.stat("guard.sock", dir_fd=parent, follow_symlinks=False))
        _check(stat.S_ISSOCK(actual["mode"]) and actual["uid"] == 0
               and actual["gid"] == self._provision["broker"]["gid"] and stat.S_IMODE(actual["mode"]) == 0o660,
               "IDENTITY_CHANGED", "guard endpoint protections")
        if self._socket_named is None:
            self._socket_named = actual
        _check(actual == self._socket_named, "IDENTITY_CHANGED", "guard endpoint replaced")

    def _socket_options(self):
        sock = self._connection
        row = self._local(sock.fileno())
        result = dict(fd=sock.fileno(), **row["identity"], nonblocking=sock.gettimeout() == 0.0,
                      noninheritable=not sock.get_inheritable(),
                      passcred=sock.getsockopt(socket.SOL_SOCKET, _SO_PASSCRED),
                      passpidfd=sock.getsockopt(socket.SOL_SOCKET, _SO_PASSPIDFD),
                      sndbuf=sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                      rcvbuf=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                      so_type=sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE))
        _check(stat.S_ISSOCK(row["identity"]["mode"]) and row["flags"] & os.O_NONBLOCK
               and row["descriptor_flags"] & fcntl.FD_CLOEXEC and result["nonblocking"]
               and result["noninheritable"] and result["passcred"] == 1 and result["passpidfd"] == 0
               and result["sndbuf"] >= 262176 and result["rcvbuf"] >= 262176
               and result["so_type"] == socket.SOCK_SEQPACKET, "IDENTITY_CHANGED", "socket flags/options")
        self._local(sock.fileno())
        return result

    def _guard(self, edge, *, terminal=False):
        prior_code = self._stage_code
        self._stage_code = "IDENTITY_CHANGED"
        snap = self._snapshot(edge, terminal=terminal)
        self._process(snap)
        self._boot(snap)
        snap["namespaces"]["broker"] = self._namespace()
        snap["directories"] = self._directory_guards()
        if not terminal:
            self._live(self._supervisor)
            self._cancelled()
        if self._connection is not None:
            self._named_socket()
            snap["socket_options"] = self._socket_options()
            if self._peer_raw is not None:
                raw = self._connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
                snap["peer_credentials_raw"] = raw
                _check(raw == self._peer_raw, "IDENTITY_CHANGED", "peer credentials changed")
                snap["pidfd_info_raw"] = self._live(self._peer_fd)
        elif self._peer_fd is not None and not terminal:
            snap["pidfd_info_raw"] = self._live(self._peer_fd)
        if hasattr(self, "_control"):
            self._borrow_guard()
        if not terminal:
            self._cancelled()
            self._live(self._supervisor)
        for fd in tuple(self._borrowed):
            self._local(fd)
        if self._connection is not None:
            self._socket_options()
        snap["finished_ns"] = self._tick(deadline=not terminal)
        # Only immediate local custody checks follow the final clock sample.
        self._owner()
        final_fds = set(self._borrowed) | {self._cancel, self._supervisor}
        if self._connection is not None:
            final_fds.add(self._connection.fileno())
        if self._peer_fd is not None:
            final_fds.add(self._peer_fd)
        for fd in final_fds:
            self._immediate(fd)
        self._stage_code = prior_code
        return snap["finished_ns"]

    def _result(self, operation, status, started, finished):
        p = self._provision
        raw = _canonical(dict(schema=_PREFIX + "ipc-observation/v1", role="CLIENT", operation=operation,
            provision_digest=getattr(self, "_provision_pin", None), context_digest=self._context_pin,
            exchange_id=None if self._context is None else self._context["exchange_id"],
            request_packet_digest=None if self._observed["request_raw"] is None else _digest(self._observed["request_raw"]),
            response_packet_digest=None if self._observed["response_raw"] is None else _digest(self._observed["response_raw"]),
            started_ns=started, received_ns=self._received, finished_ns=finished, deadline_ns=self._deadline,
            peer=None, context_file_digest=self._context_pin,
            bound_event_digest=None if self._observed["bound_raw"] is None else _digest(self._observed["bound_raw"]),
            measurement_pending_digest=None if self._observed["measurement_pending_raw"] is None else _digest(self._observed["measurement_pending_raw"]),
            status=status, stream_continuity="UNKNOWN", loss_completeness="UNKNOWN", **{key: False for key in _FLAGS}))
        self._observed["ipc_raw"] = _raw(raw, 16384)
        return dict(ipc_raw=raw, observed=_detached(self._observed))


def configure_broker_reader_guard(*, provision_raw, expected_provision_digest,
                                 source_inventory_raw, expected_source_inventory_digest,
                                 measurement_binding_raw, expected_measurement_binding_digest,
                                 fixture_binding_raw, expected_fixture_binding_digest,
                                 ipc_cancel_read_fd, supervisor_pidfd):
    global _CONFIGURED, _CONFIGURATION
    _entry_owner()
    _check(_ENTRY.acquire(False), "INPUT_REFUSED", "configuration reentry")
    try:
        _check(not _CONFIGURED, "INPUT_REFUSED", "configuration consumed")
        _CONFIGURED = True
    finally:
        _ENTRY.release()
    owner = _Custody()
    _CONFIGURATION = owner
    owner._cancel, owner._supervisor = ipc_cancel_read_fd, supervisor_pidfd
    for key, raw, bound in (("provision_raw", provision_raw, 16384), ("source_inventory_raw", source_inventory_raw, 65536),
                            ("measurement_binding_raw", measurement_binding_raw, 8192), ("fixture_binding_raw", fixture_binding_raw, 16384)):
        if type(raw) is bytes:
            owner._observed[key] = raw[:bound]
    try:
        # Collect both valid numbers before any metadata or malformed argument check.
        for fd in (ipc_cancel_read_fd, supervisor_pidfd):
            if type(fd) is int and 3 <= fd <= _MAX and fd not in owner._owned:
                owner._owned[fd] = owner._row()
        if type(supervisor_pidfd) is int and supervisor_pidfd in owner._owned:
            owner._owned[supervisor_pidfd]["pid"] = "UNKNOWN"
        _uint(ipc_cancel_read_fd, 3)
        _uint(supervisor_pidfd, 3)
        _require(ipc_cancel_read_fd != supervisor_pidfd, "configuration alias")
        owner._owned[ipc_cancel_read_fd]["role"] = "IPC_CANCEL"
        owner._owned[supervisor_pidfd]["role"] = "SUPERVISOR_PIDFD"
        _require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("P") == 8
                 and array.array("i").itemsize == 4 and struct.calcsize("=iII") == 12, "native credential ABI")
        owner._validate(provision_raw, expected_provision_digest, source_inventory_raw, expected_source_inventory_digest,
                        measurement_binding_raw, expected_measurement_binding_digest, fixture_binding_raw, expected_fixture_binding_digest)
        owner._stage_code = "IDENTITY_CHANGED"
        for fd in (ipc_cancel_read_fd, supervisor_pidfd):
            owner._initial(fd)
        row = owner._owned[supervisor_pidfd]
        _require(row["link"] == "anon_inode:[pidfd]" and row["descriptor_flags"] & fcntl.FD_CLOEXEC, "supervisor PIDFD")
        actual, _ = owner._association(supervisor_pidfd)
        _require(actual == owner._provision["supervisor"]["pid"], "supervisor identity")
        row["pid"] = actual
        owner._open_views()
        started = owner._tick()
        owner._guard("OPEN")
        _check(owner._last_ns < owner._provision["accept_deadline_ns"], "DEADLINE_EXPIRED", "accept budget spent")
        # Only the two transferred handles live with configuration. Guard creates
        # and owns its own views; none are silently handed across owners.
        for fd in tuple(owner._owned):
            if fd not in (ipc_cancel_read_fd, supervisor_pidfd):
                owner._close_fd(fd)
        owner._dirs.clear()
        owner._namespaces.clear()
        owner._cancelled()
        owner._live(supervisor_pidfd)
        finished = owner._tick()
        _check(finished < owner._provision["accept_deadline_ns"],
               "DEADLINE_EXPIRED", "accept budget spent at closing return")
        owner._immediate(ipc_cancel_read_fd)
        owner._immediate(supervisor_pidfd)
        return owner._result("OPEN", "OPENED", started, finished)
    except BaseException as exc:
        owner._closed = True
        raise owner._error(exc, owner._close_owned()) from exc


class HttpReaderGuard(_Custody):
    def __init__(self, token, configuration, control_fd, lock_fd, config, request_raw, effect_raw, deadline_monotonic):
        _require(token is _TOKEN, "owning begin required")
        super().__init__()
        self._configuration = configuration
        self._provision, self._measurement, self._fixture = configuration._provision, configuration._measurement, configuration._fixture
        self._provision_pin, self._source_pin = configuration._provision_pin, configuration._source_pin
        self._deadline = self._provision["session_deadline_ns"]
        self._cancel, self._supervisor = configuration._cancel, configuration._supervisor
        self._borrowed.update(configuration._owned)
        self._observed.update({key: configuration._observed[key] for key in (
            "provision_raw", "source_inventory_raw", "measurement_binding_raw", "fixture_binding_raw")})
        self._journal = None
        self._journal_poisoned = self._journal_closed = self._finished = self._checked = self._sent = False
        self._control, self._broker_lock = control_fd, lock_fd
        self._stage_code = "INPUT_REFUSED"
        for key, raw in (("action_request_raw", request_raw), ("effect_raw", effect_raw)):
            if type(raw) is bytes:
                self._observed[key] = raw[:4096]
        try:
            for fd in (control_fd, lock_fd):
                if type(fd) is int and 3 <= fd <= _MAX and fd not in self._borrowed:
                    self._borrowed[fd] = self._row()
            _uint(control_fd, 3)
            _uint(lock_fd, 3)
            _require(len({control_fd, lock_fd, self._cancel, self._supervisor}) == 4, "borrowed alias")
            self._borrowed[control_fd]["role"] = "CONTROL_BORROWED"
            self._borrowed[lock_fd]["role"] = "LOCK_BORROWED"
            self._initial(control_fd)
            self._initial(lock_fd)
            _require(type(deadline_monotonic) in (int, float)
                     and (type(deadline_monotonic) is int or math.isfinite(deadline_monotonic)), "original deadline number")
            numerator, denominator = deadline_monotonic.as_integer_ratio()
            self._mono_deadline = _uint(numerator * 1000000000 // denominator, 1)
            self._action, self._effect = self._action_inputs(request_raw, effect_raw)
            self._open_views(control=control_fd)
            self._stage_code = "IDENTITY_CHANGED"
            started = self._guard("OPEN")
            self._stage_code = "RETENTION_FAILED"
            # Importing the public module late avoids the generated core cycle.
            measurement = importlib.import_module(".runtime_broker_decision_measurement", __package__)
            accessor = getattr(measurement, "current_http_guard_pending", None)
            _check(callable(accessor), "INPUT_REFUSED", "public measurement accessor unavailable")
            pending = accessor(expected_request_digest=_digest(request_raw), expected_grant_digest=self._provision["grant_digest"])
            self._validate_pending(pending)
            self._record("PENDING", "decision-measurement-pending.json", 131072, expected=pending)
            self._stage_code = "IDENTITY_CHANGED"
            self._connect()
            self._stage_code = "CLOCK_REFUSED"
            before = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
            mono = _uint(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
            after = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
            remaining = self._mono_deadline - mono
            _check(after >= before >= self._last_ns and mono >= self._last_mono and 0 < remaining <= 500000000,
                   "CLOCK_REFUSED", "original clock bracket")
            deadline = _add(before, remaining)
            _check(after < deadline <= self._provision["session_deadline_ns"], "DEADLINE_EXPIRED", "wire deadline")
            self._deadline, self._last_ns, self._last_mono = deadline, after, mono
            self._context = dict(schema=_PREFIX + "context/v1", request_digest=_digest(request_raw),
                effect_digest=_digest(effect_raw), grant_digest=self._provision["grant_digest"],
                deployment_digest=self._provision["deployment_digest"], epoch_digest=self._provision["epoch_digest"],
                broker=self._provision["broker"], provider=self._provision["provider"], clock=self._provision["clock"],
                exchange_id=secrets.token_hex(32), accepted_boottime_ns=self._pending["accepted_boottime_ns"],
                deadline_boottime_ns=deadline, clock_bracket=dict(boottime_before_ns=before, monotonic_ns=mono,
                    boottime_after_ns=after, original_monotonic_deadline_ns=self._mono_deadline))
            _require(re.fullmatch(r"[0-9a-f]{64}", self._context["exchange_id"]), "minted exchange")
            context_raw = _raw(_canonical(self._context), 8192)
            self._context_pin = _digest(context_raw)
            self._stage_code = "RETENTION_FAILED"
            self._guard("CONTEXT")
            self._journal = begin_http_submission_locked(control_fd, lock_fd, config, context_raw=context_raw,
                                                         expected_context_digest=self._context_pin)
            prefix = "run-reader-" + self._context["request_digest"][7:]
            self._record("CONTEXT", prefix + "-context.json", 8192, expected=context_raw)
            bound_raw = self._record("BOUND", prefix + "-event-0.json", 8192)
            bound = _keys(_decode(bound_raw, 8192), "schema context_digest sequence previous_digest phase checked_ns "
                          "request_packet_digest response_packet_digest transport_digest failure_code intent effect_possible")
            _require(bound["schema"] == "aragorn/native-phase3-broker-submission-event/v1"
                     and bound["context_digest"] == self._context_pin and type(bound["sequence"]) is int and bound["sequence"] == 0
                     and bound["phase"] == "BOUND" and bound["intent"] is False and bound["effect_possible"] is False
                     and all(bound[k] is None for k in ("previous_digest", "request_packet_digest", "response_packet_digest", "transport_digest", "failure_code")), "BOUND prefix")
            checked = _uint(bound["checked_ns"])
            _require(after <= checked < deadline and checked <= self._tick(), "BOUND chronology")
            self._record_guards()
            finished = self._guard("CONTEXT")
            self._opening = self._result("OPEN", "OPENED", started, finished)
        except BaseException as exc:
            primary_code = self._stage_code
            self._remember_journal(exc)
            self._terminal_on_begin_failure(exc)
            self._closed = True
            errors = self._cleanup()
            self._stage_code = primary_code
            raise self._error(exc, errors) from exc

    def _action_inputs(self, request_raw, effect_raw):
        request = _keys(_decode(request_raw, 4096), "schema authority runtime_digest session_id run_id tool_call_id active_skill_digest "
                        "operation_digest path_digest payload_digest policy_digest policy_version issued_at_unix expires_at_unix")
        _require(request["schema"] == "aragorn/runtime-action-request/v1"
                 and request["authority"] == "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY", "action identity")
        for key in ("runtime_digest", "active_skill_digest", "operation_digest", "path_digest", "payload_digest", "policy_digest"):
            _pin(request[key])
            _require(request[key] == self._measurement[key], "measurement action join")
        for key in ("session_id", "run_id", "tool_call_id"):
            _require(type(request[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", request[key]), "action identifier")
        _uint(request["policy_version"], 1)
        _uint(request["issued_at_unix"])
        _uint(request["expires_at_unix"])
        effect = validate_effect(_decode(effect_raw, 4096))
        _require(effect == effect_for_attempt(self._measurement["attempt_id"])
                 and all(request[k] == v for k, v in action_digests(effect["attempt_id"], self._fixture).items()), "effect action join")
        self._observed.update(action_request_raw=request_raw, effect_raw=effect_raw)
        return request, effect

    def _validate_pending(self, raw):
        pending = _keys(_decode(raw, 131072), "schema binding process clock_id acceptance_boundary accepted_boottime_ns "
                        "action_request_digest submission_digest lease_digest runtime_attribution_digest")
        _require(pending["schema"] == "aragorn/runtime-broker-decision-measurement-pending/v1"
                 and pending["clock_id"] == "CLOCK_BOOTTIME"
                 and pending["acceptance_boundary"] == "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM"
                 and _canonical(pending["binding"]) == self._observed["measurement_binding_raw"]
                 and pending["action_request_digest"] == _digest(self._observed["action_request_raw"]), "pending binding")
        for key in ("action_request_digest", "submission_digest", "lease_digest", "runtime_attribution_digest"):
            _pin(pending[key])
        actual = _keys(pending["process"], "boot_id pid uid gid start_time_ticks mount_namespace")
        _require(all(actual[k] == v for k, v in self._provision["broker"].items())
                 and actual["boot_id"] == self._provision["clock"]["boot_id"]
                 and actual["mount_namespace"] == self._namespace()["mount"]["link"], "pending process/domain")
        _require(_uint(pending["accepted_boottime_ns"]) <= self._tick(), "pending acceptance in future")
        self._pending = pending

    def _borrow_guard(self):
        control = self._local(self._control)
        lock = self._local(self._broker_lock)
        broker = self._provision["broker"]
        _check(control["identity"]["mode"] == stat.S_IFDIR | 0o700
               and control["identity"]["uid"] == broker["uid"] and control["identity"]["gid"] == broker["gid"]
               and control["flags"] & os.O_ACCMODE == os.O_RDONLY
               and control["descriptor_flags"] & fcntl.FD_CLOEXEC, "IDENTITY_CHANGED", "borrowed control")
        _check(lock["identity"]["mode"] == stat.S_IFREG | 0o600 and lock["identity"]["uid"] == broker["uid"]
               and lock["identity"]["gid"] == broker["gid"] and lock["flags"] & os.O_ACCMODE == os.O_RDWR
               and lock["descriptor_flags"] & fcntl.FD_CLOEXEC, "IDENTITY_CHANGED", "borrowed lock")
        held_full = _full(os.fstat(self._broker_lock))
        named_full = _full(os.stat("broker.lock", dir_fd=self._control, follow_symlinks=False))
        if not hasattr(self, "_lock_identity"):
            self._lock_identity = held_full
        _check(held_full == named_full == self._lock_identity and held_full["nlink"] == 1,
               "IDENTITY_CHANGED", "named/full lock")
        raw = self._read(f"/proc/self/fdinfo/{self._broker_lock}", 4096)
        fields = {}
        for line in raw.decode("ascii").splitlines():
            key, separator, value = line.partition(":")
            _require(separator and key in ("pos", "flags", "mnt_id", "ino", "lock") and key not in fields,
                     "held lock fdinfo fields")
            fields[key] = value.strip(" \t")
        _require(set(fields) == {"pos", "flags", "mnt_id", "ino", "lock"}, "held lock fdinfo missing")
        for key in ("pos", "flags", "mnt_id", "ino"):
            _require(re.fullmatch(r"[0-7]{1,22}" if key == "flags" else r"[0-9]{1,19}", fields[key]), "fdinfo integer")
        _require(int(fields["flags"], 8) == lock["flags"] | os.O_CLOEXEC
                 and int(fields["ino"]) == held_full["inode"], "fdinfo flags/inode")
        words = re.split(r"[ \t]+", fields["lock"])
        _require(len(words) == 8 and words[:5] == ["1:", "FLOCK", "ADVISORY", "WRITE", str(_PID)]
                 and words[6:] == ["0", "EOF"], "actual held FLOCK owner")
        device = re.fullmatch(r"([0-9a-fA-F]{1,16}):([0-9a-fA-F]{1,16}):([0-9]{1,19})", words[5])
        _require(device is not None and int(device[1], 16) == os.major(held_full["device"])
                 and int(device[2], 16) == os.minor(held_full["device"])
                 and int(device[3]) == held_full["inode"], "held lock device")
        mount = _uint(int(fields["mnt_id"]))
        if not hasattr(self, "_lock_mount"):
            self._lock_mount = mount
        _require(mount == self._lock_mount, "lock mount changed")
        self._local(self._broker_lock)
        _check(_full(os.fstat(self._broker_lock)) == held_full, "IDENTITY_CHANGED", "closing lock identity")
        self._retain_handle(self._control)
        self._retain_handle(self._broker_lock, raw=raw)
        # Actual held-at-read state is not proof of uninterrupted ownership.

    def _record(self, role, name, bound, *, expected=None):
        self._borrow_guard()
        fd = os.open(name, _OPEN, dir_fd=self._control)
        self._own(fd)
        identity = _full(os.fstat(fd))
        broker = self._provision["broker"]
        _require(stat.S_ISREG(identity["mode"]) and stat.S_IMODE(identity["mode"]) == 0o400
                 and identity["uid"] == broker["uid"] and identity["gid"] == broker["gid"]
                 and identity["nlink"] == 1 and 0 < identity["bytes"] <= bound, "record metadata")
        pair = identity["device"], identity["inode"]
        _require(all(pair != (r[2]["device"], r[2]["inode"]) for r in self._records), "record aliases")
        item = dict(role=role, name=name, identity=identity, digest=None)
        self._observed["record_observations"].append(item)
        key = {"PENDING": "measurement_pending_raw", "CONTEXT": "context_raw", "BOUND": "bound_raw"}[role]
        self._records.append((name, fd, identity, None, key))
        raw = self._record_read(name, fd, identity, bound, key)
        if expected is not None:
            _require(raw == expected, "retained original bytes differ")
        item["digest"] = _digest(raw)
        self._records[-1] = (name, fd, identity, raw, key)
        return raw

    def _record_read(self, name, fd, identity, bound, key):
        self._borrow_guard()
        self._local(fd)
        _require(_full(os.fstat(fd)) == identity == _full(os.stat(name, dir_fd=self._control, follow_symlinks=False)), "record opening identity")
        result = bytearray()
        while True:
            self._local(fd)
            raw = os.pread(fd, min(8192, bound + 1 - len(result)), len(result))
            _require(type(raw) is bytes, "record read bytes")
            result.extend(raw)
            self._observed[key] = bytes(result[:bound])
            self._local(fd)
            _require(len(result) <= bound, "record byte bound")
            if not raw:
                break
        _require(len(result) == identity["bytes"] and _full(os.fstat(fd)) == identity
                 == _full(os.stat(name, dir_fd=self._control, follow_symlinks=False)), "record closing identity")
        self._local(fd)
        self._borrow_guard()
        return bytes(result)

    def _record_guards(self):
        for name, fd, identity, expected, key in self._records:
            _require(expected is not None and self._record_read(name, fd, identity, len(expected), key) == expected,
                     "record changed")

    def _connect(self):
        self._named_socket()
        self._connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        sock = self._connection
        fd = sock.fileno()
        self._own(fd, obj=sock)
        self._local(fd)
        sock.setblocking(False)
        self._owner()
        _check(sock.fileno() == fd and _metadata(os.fstat(fd)) == self._owned[fd]["identity"], "IDENTITY_CHANGED", "socket setup")
        self._owned[fd]["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        self._local(fd)
        sock.set_inheritable(False)
        self._owner()
        _check(sock.fileno() == fd and _metadata(os.fstat(fd)) == self._owned[fd]["identity"], "IDENTITY_CHANGED", "socket CLOEXEC")
        self._owned[fd]["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        for option, value in ((_SO_PASSCRED, 1), (_SO_PASSPIDFD, 0), (socket.SO_SNDBUF, 524320), (socket.SO_RCVBUF, 524320)):
            self._local(fd)
            sock.setsockopt(socket.SOL_SOCKET, option, value)
        self._socket_options()
        self._guard("CONNECT")
        self._local(fd)
        self._tick()
        self._immediate(fd)
        result = sock.connect_ex(_ENDPOINT)
        _require(type(result) is int, "connect result")
        if result == errno.EINPROGRESS:
            self._wait(select.POLLOUT, "CONNECT")
            self._local(fd)
            _check(sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, "IDENTITY_CHANGED", "connect completion")
        else:
            _check(result == 0, "IDENTITY_CHANGED", "single connect refused")
        self._socket_options()
        raw = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
        self._peer_raw = raw
        _require(type(raw) is bytes and len(raw) == 12, "peer credential bytes")
        expected = self._provision["provider"]
        _check(struct.unpack("=iII", raw) == (expected["pid"], expected["uid"], expected["gid"]),
               "IDENTITY_CHANGED", "provider kernel identity")
        self._local(fd)
        pidfd = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD)
        self._register(pidfd, pid="UNKNOWN")
        self._peer_fd = pidfd
        self._initial(pidfd)
        _uint(pidfd, 3)
        self._owned[pidfd]["role"] = "PEER_PIDFD"
        row = self._owned[pidfd]
        _check(row["link"] == "anon_inode:[pidfd]" and row["descriptor_flags"] & fcntl.FD_CLOEXEC,
               "IDENTITY_CHANGED", "provider PIDFD type")
        actual, _ = self._association(pidfd)
        _check(actual == expected["pid"], "IDENTITY_CHANGED", "provider PIDFD association")
        row["pid"] = actual
        self._guard("CONNECT")

    def _wait(self, event, edge):
        while True:
            now = self._guard(edge)
            fd = self._connection.fileno()
            poller = select.poll()
            watched = (fd, self._cancel, self._supervisor) + (() if self._peer_fd is None else (self._peer_fd,))
            for item in watched:
                poller.register(item, (event if item == fd else select.POLLIN) | select.POLLERR | select.POLLHUP | select.POLLNVAL)
            self._socket_options()
            self._cancel_guard()
            try:
                events = poller.poll(min((self._deadline - now + 999999) // 1000000, 2147483647))
            except InterruptedError:
                continue
            self._guard(edge)
            ready = False
            for item, flags in events:
                _require(item in watched and type(flags) is int and flags != 0, "poll observation")
                if item == fd:
                    _check(not flags & ~event, "PROTOCOL_REFUSED", "socket readiness error")
                    ready = True
                elif item == self._cancel:
                    _check(not flags & ~(select.POLLIN | select.POLLHUP), "PROTOCOL_REFUSED", "cancel event")
                    self._cancelled()
                else:
                    raise _Refusal("IDENTITY_CHANGED", "supervised process exited")
            if ready:
                self._socket_options()
                return

    def _controls(self, controls, flags, snap):
        _require(type(controls) is list, "ancillary list")
        retained, installed, original = [], [], None
        total = 0
        for item in controls:
            if not (type(item) is tuple and len(item) == 3 and type(item[0]) is int
                    and type(item[1]) is int and type(item[2]) is bytes):
                if original is None:
                    original = ValueError("ancillary shape")
                continue
            level, kind, raw = item
            total += len(raw)
            if len(retained) < 8:
                retained.append(dict(level=level, type=kind, raw=raw[:max(0, 4096 - sum(len(v["raw"]) for v in retained))]))
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, _SCM_PIDFD):
                numbers = array.array("i")
                numbers.frombytes(raw[:len(raw) - len(raw) % 4])
                if len(raw) % 4 and original is None:
                    original = ValueError("partial ancillary FD")
                for fd in numbers:
                    previous = self._owned.get(fd)
                    try:
                        self._register(fd, pid="UNKNOWN" if kind == _SCM_PIDFD else None, minimum=0)
                    except BaseException as exc:
                        if original is None:
                            original = exc
                    finally:
                        if previous is None and fd in self._owned:
                            installed.append(fd)
        # All received handles are tracked before observations on any one handle.
        snap["controls"], snap["receive_flags"] = retained, flags
        # This receipt precedes descriptor/proc observations and validation. The
        # preceding finite loop only adopts already-installed ancillary handles.
        self._received = self._tick()
        for fd in installed:
            try:
                self._initial(fd)
                if self._owned[fd]["pid"] == "UNKNOWN":
                    self._owned[fd]["pid"] = self._association(fd)[0]
            except BaseException as exc:
                if original is None:
                    original = exc
        try:
            if original is not None:
                raise original
            _require(len(controls) <= 8 and total <= 4096 and type(flags) is int
                     and not flags & ~(socket.MSG_EOR | _MSG_CLOEXEC), "receive control flags/bound")
            _require(len(controls) == 1 and controls[0][:2] == (socket.SOL_SOCKET, _SCM_CREDENTIALS)
                     and controls[0][2] == self._peer_raw, "message credentials")
        finally:
            for fd in installed:
                try:
                    self._close_fd(fd)
                except BaseException as exc:
                    self._note_cleanup(exc)

    def _remember_journal(self, exc):
        if isinstance(exc, SubmissionJournalError):
            self._journal_poisoned = True
            self._observed["journal_error"] = exc

    def _terminal_on_begin_failure(self, original):
        # No guard escapes a failed constructor. A completed healthy BOUND
        # journal therefore needs its one terminal attempt here, while the
        # caller still holds the borrowed lock. Expiry/cancellation does not
        # disable the journal's deliberately expiry-tolerant terminal methods.
        if (self._journal is None or self._journal_poisoned
                or self._journal_closed or self._finished):
            return
        prior_code = self._stage_code
        code = original.failure_code if isinstance(original, _Refusal) else prior_code
        if code not in ERROR_CODES:
            code = "INTERNAL_REFUSAL"
        self._finished = True
        try:
            self._journal_call("finish", transport_raw=None, failure_code=code)
            self._journal_call("final_readback")
        except BaseException as exc:
            # _journal_call poisons before propagation; close may dispose its
            # safe handles, but neither finish nor readback is retried.
            self._note_cleanup(exc)
        finally:
            self._stage_code = prior_code

    def _journal_call(self, name, **kwargs):
        _check(self._journal is not None and not self._journal_poisoned and not self._journal_closed,
               "RETENTION_FAILED", "journal unavailable")
        self._stage_code = "RETENTION_FAILED"
        try:
            return getattr(self._journal, name)(**kwargs)
        except BaseException as exc:
            self._journal_poisoned = True
            self._remember_journal(exc)
            raise

    def _cleanup(self):
        errors = []
        if self._journal is not None and not self._journal_closed:
            self._journal_closed = True
            try:
                self._journal.close()
            except BaseException as exc:
                self._remember_journal(exc)
                errors.append(exc)
        errors.extend(self._close_owned())
        return errors

    def _run(self, body, *, terminal=False):
        self._owner()
        _check(self._lock.acquire(False), "INPUT_REFUSED", "guard reentry")
        try:
            if self._closed or (self._failure is not None and not terminal):
                if self._failure is not None:
                    raise self._failure
                raise _Refusal("INPUT_REFUSED", "guard closed")
            try:
                return body()
            except BaseException as exc:
                if exc is self._failure:
                    raise
                self._remember_journal(exc)
                # Ordinary phase failures keep the still-usable journal for the
                # owning terminal path. No recovery or new exchange is possible.
                if self._connection is not None:
                    try:
                        self._close_fd(self._connection.fileno())
                        self._connection = None
                    except BaseException as cleanup:
                        self._note_cleanup(cleanup)
                raise self._error(exc, self._cleanup_errors) from exc
        finally:
            self._lock.release()

    @property
    def opening_result(self):
        self._owner()
        _check(not self._closed and self._failure is None, "INPUT_REFUSED", "opening unavailable")
        return _detached(self._opening)

    def before_connect(self):
        def body():
            _check(not self._sent and not self._checked and not self._finished,
                   "PROTOCOL_REFUSED", "first phase consumed")
            self._sent = True
            started = self._guard("SEND")
            self._stage_code = "PROTOCOL_REFUSED"
            value = dict(schema=_PREFIX + "request/v1", phase="BEFORE_CONNECT", previous_response_digest=None,
                         **{k: self._context[k] for k in ("exchange_id", "epoch_digest", "request_digest", "effect_digest", "deadline_boottime_ns")},
                         context_digest=self._context_pin)
            request_raw = _canonical(value)
            validate_guard_request(request_raw)
            self._request = value
            self._observed["request_raw"] = request_raw
            self._guard("SEND")
            options = self._socket_options()
            _require(options["sndbuf"] >= 2 * len(request_raw) + 32, "actual send capacity")
            self._local(self._connection.fileno())
            self._tick()
            self._immediate(self._connection.fileno())
            self._observed["send_attempted"] = True
            count = self._connection.send(request_raw, _MSG_DONTWAIT | _MSG_NOSIGNAL)
            self._observed["bytes_sent"] = count
            _require(type(count) is int and count == len(request_raw), "single send result")
            self._guard("SEND")
            while True:
                self._wait(select.POLLIN, "RECEIVE")
                snap = self._snapshot("RECEIVE")
                self._socket_options()
                self._cancelled()
                self._local(self._connection.fileno())
                self._tick()
                self._immediate(self._connection.fileno())
                try:
                    raw, controls, flags, address = self._connection.recvmsg(262144, 4096, _MSG_DONTWAIT | _MSG_CLOEXEC)
                except BlockingIOError:
                    continue
                # Ownership of ancillary descriptors precedes fallible clocks.
                if type(raw) is bytes:
                    self._observed["response_raw"] = raw[:262144]
                self._controls(controls, flags, snap)
                snap["finished_ns"] = self._tick()
                _require(address in (None, "", b"") and type(raw) is bytes and 0 < len(raw) <= 262144,
                         "response framing")
                response = validate_guard_response(raw, request_raw=request_raw)
                _require(response["status"] == "REFUSED", "positive profile unavailable")
                self._guard("RECEIVE")
                self._journal_call("record_check", phase="BEFORE_CONNECT", request_raw=request_raw, response_raw=raw)
                self._checked = True
                self._guard("CONTEXT")
                self._stage_code = "CLEANUP_FAILED"
                self._close_fd(self._connection.fileno())
                self._connection = None
                finished = self._guard("EOF")
                result = self._result("BEFORE_CONNECT", "REFUSED", started, finished)
                return dict(request_raw=request_raw, response_raw=raw, **result)
        return self._run(body)

    def before_payload_send(self):
        def body():
            raise _Refusal("PROTOCOL_REFUSED", "refusal profile has no payload phase")
        return self._run(body)

    def finish(self, *, transport_raw, failure_code):
        def body():
            _check(not self._finished, "PROTOCOL_REFUSED", "terminal phase consumed")
            self._finished = True
            started = self._tick(deadline=False)
            if type(transport_raw) is bytes:
                self._observed["transport_raw"] = transport_raw[:32768]
            _require(transport_raw is None or (type(transport_raw) is bytes and 0 < len(transport_raw) <= 32768), "transport bound")
            if transport_raw is not None:
                _decode(transport_raw, 32768)
            _require(failure_code in ERROR_CODES | {"POLICY_REFUSED", "TRANSPORT_REFUSED", "TRANSPORT_INDETERMINATE", "JOURNAL_REFUSED"}, "terminal code")
            self._borrow_guard()
            self._journal_call("finish", transport_raw=transport_raw, failure_code=failure_code)
            self._journal_call("final_readback")
            finished = self._tick(deadline=False)
            result = self._result("FINISH", "REFUSED", started, finished)
            if self._failure is not None:
                # Retention never hides the original cancellation/deadline error.
                self._failure.observed = _detached(self._observed)
                raise self._failure
            return result
        return self._run(body, terminal=True)

    def close(self):
        def body():
            started = self._tick(deadline=False)
            self._closed = True
            errors = self._cleanup()
            try:
                finished = self._tick(deadline=False)
            except BaseException as exc:
                errors.append(exc)
                finished = None
            result = self._result("CLOSE", "CLOSED", started, finished)
            if self._failure is not None:
                self._failure.observed = _detached(self._observed)
                self._failure.cleanup_failures = tuple((list(self._failure.cleanup_failures) + errors)[:32])
                raise self._failure
            if errors:
                original = self._first_cleanup_interrupt or next((e for e in errors if isinstance(e, (KeyboardInterrupt, SystemExit, MemoryError))), errors[0])
                self._stage_code = "CLEANUP_FAILED"
                raise self._error(original, errors)
            return result
        return self._run(body, terminal=True)


def begin_http_guard_locked(control_fd, lock_fd, config, *, request_raw, effect_raw, deadline_monotonic):
    global _BEGUN
    _entry_owner()
    _check(_ENTRY.acquire(False), "INPUT_REFUSED", "begin reentry")
    try:
        _check(_CONFIGURATION is not None and _CONFIGURATION._failure is None
               and not _CONFIGURATION._closed and not _BEGUN, "INPUT_REFUSED", "configuration or attempt unavailable")
        _BEGUN = True
    finally:
        _ENTRY.release()
    return HttpReaderGuard(_TOKEN, _CONFIGURATION, control_fd, lock_fd, config, request_raw, effect_raw, deadline_monotonic)
