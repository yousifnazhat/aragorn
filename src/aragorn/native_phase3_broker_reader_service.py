"""Own one protected broker/reader refusal exchange and its startup barrier.

Installed-source bindings are protected caller inputs, not file/loaded-code
observations. No public option can turn this service into an effect authorizer.
"""

import array
import base64
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import stat
import struct
import sys
import threading
import time

from .native_phase3_broker_reader_protocol import validate_guard_request, validate_guard_response
from .native_phase3_broker_reader_context import acquire_broker_reader_context, BrokerReaderContextError
from .native_phase3_run_reader_checkpoint_session import ReaderCheckpointSession


_PID = os.getpid()
_THREAD = threading.main_thread().ident
_CONSTRUCTION = threading.Lock()
_CONSTRUCTED = False
_QUARANTINE = []
_MAX = 2**63 - 1
_ENDPOINT = "/run/aragorn-phase3-broker-reader/guard.sock"
_PARENT = "/run/aragorn-phase3-broker-reader"
_PATHS = ("/", "/run", _PARENT, "/var", "/var/lib",
          "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-action/control")
_PREFIX = "aragorn/native-phase3-broker-reader-"
_REPORT = "sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9"
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
          "run_qualified", "phase3_qualified")
_OBSERVED = ("provision_raw source_inventory_raw readiness_expectation_raw provider_ready_raw "
             "ready_write_attempted ready_bytes_written context_expectation_raw context_result context_error "
             "request_raw response_raw ipc_raw session_result session_error session_finish_raw "
             "session_close_raw handle_observations transport_observations send_attempted bytes_sent").split()
_OPEN = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
_SO_PASSCRED, _SO_PEERCRED, _SO_PASSPIDFD, _SO_PEERPIDFD = 16, 17, 76, 77
_MSG_DONTWAIT, _MSG_NOSIGNAL, _MSG_CLOEXEC = 0x40, 0x4000, 0x40000000
_SCM_CREDENTIALS, _SCM_PIDFD = 2, 4


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


class BrokerReaderIpcError(ValueError):
    def __init__(self, original, cleanup, observed, owner):
        super().__init__("broker reader service refused")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup[:32])
        self.observed = _detached(observed)
        self.unresolved_owner = owner


class BrokerReaderService:
    def __init__(self, *, provision_raw, expected_provision_digest,
                 source_inventory_raw, expected_source_inventory_digest,
                 measurement_binding_raw, expected_measurement_binding_digest,
                 fixture_binding_raw, expected_fixture_binding_digest,
                 epoch_raw, expected_epoch_digest,
                 checkpoint_provision_raw, expected_checkpoint_provision_digest,
                 transport_provision_raw, expected_transport_provision_digest,
                 stream_inventory_raw, expected_stream_digest,
                 loop_provision_raw, expected_loop_provision_digest,
                 notice_write_fd, reader_pidfd, refresh_write_fd, completion_read_fd,
                 session_cancel_read_fd, ipc_cancel_read_fd, supervisor_pidfd,
                 readiness_expectation_raw, expected_readiness_expectation_digest,
                 provider_ready_write_fd):
        global _CONSTRUCTED
        # A refused second/forked caller never receives ownership of its arguments.
        _require(os.getpid() == _PID and threading.get_ident() == _THREAD
                 and threading.current_thread() is threading.main_thread(), "original main owner")
        _require(_CONSTRUCTION.acquire(False), "construction reentry")
        try:
            _require(not _CONSTRUCTED, "construction consumed")
            _CONSTRUCTED = True
        finally:
            _CONSTRUCTION.release()
        self._thread = threading.get_native_id()
        self._owned, self._dirs, self._namespaces = {}, [], {}
        self._unresolved, self._cleanup_errors = [], []
        self._lock = threading.Lock()
        self._session = self._listener = self._connection = None
        self._session_terminal = False
        self._used = self._closed = False
        self._failure = None
        self._deadline, self._last_ns = _MAX, -1
        self._provision = self._loop = None
        self._peer_fd = self._peer_raw = self._socket_named = None
        self._peer = self._request = self._context_pin = None
        self._received = None
        self._observed = dict.fromkeys(_OBSERVED)
        self._observed.update(ready_write_attempted=False, send_attempted=False,
                              handle_observations=[], transport_observations=[])
        for key, raw, limit in (("provision_raw", provision_raw, 16384),
                                ("source_inventory_raw", source_inventory_raw, 65536),
                                ("readiness_expectation_raw", readiness_expectation_raw, 4096)):
            if type(raw) is bytes:
                self._observed[key] = raw[:limit]
        self._cancel, self._supervisor, self._ready = ipc_cancel_read_fd, supervisor_pidfd, provider_ready_write_fd
        fds = (notice_write_fd, reader_pidfd, refresh_write_fd, completion_read_fd,
               session_cancel_read_fd, ipc_cancel_read_fd, supervisor_pidfd, provider_ready_write_fd)
        try:
            # First register all valid distinct numbers, even if one initial fstat fails.
            for index, fd in enumerate(fds):
                if type(fd) is int and 3 <= fd <= _MAX and fd not in self._owned:
                    self._owned[fd] = self._row(pid="UNKNOWN" if index in (1, 6) else None)
            # Invalid arguments must not be hashed or compared while collecting
            # ownership of later valid transfers. Roles come from positions only.
            for index, role in ((5, "IPC_CANCEL"), (6, "SUPERVISOR_PIDFD"), (7, "PROVIDER_READY")):
                fd = fds[index]
                if type(fd) is int and 3 <= fd <= _MAX:
                    self._owned[fd]["role"] = role
            for index in (1, 6):
                fd = fds[index]
                if type(fd) is int and 3 <= fd <= _MAX:
                    self._owned[fd]["pid"] = "UNKNOWN"
            errors = []
            for fd in self._owned:
                try:
                    self._initial(fd)
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise errors[0]
            _require(all(type(fd) is int and 3 <= fd <= _MAX for fd in fds) and len(set(fds)) == 8,
                     "eight descriptor transfer")
            self._owner()
            _require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("P") == 8
                     and array.array("i").itemsize == 4 and struct.calcsize("=iII") == 12, "native ABI")
            started = self._tick()
            self._validate(provision_raw, expected_provision_digest, source_inventory_raw, expected_source_inventory_digest,
                           measurement_binding_raw, expected_measurement_binding_digest, fixture_binding_raw,
                           expected_fixture_binding_digest, epoch_raw, expected_epoch_digest,
                           checkpoint_provision_raw, expected_checkpoint_provision_digest, transport_provision_raw,
                           expected_transport_provision_digest, stream_inventory_raw, expected_stream_digest,
                           loop_provision_raw, expected_loop_provision_digest, readiness_expectation_raw,
                           expected_readiness_expectation_digest)
            self._deadline = self._loop["startup_deadline_ns"]
            _require(started < self._deadline <= _add(started, 4000000000), "original startup budget")
            self._owned[reader_pidfd]["pid"] = self._pid_association(reader_pidfd)
            _require(self._owned[reader_pidfd]["pid"] == self._stream["reader"]["pid"], "reader PIDFD")
            self._owned[self._supervisor]["pid"] = self._pid_association(self._supervisor)
            _require(self._owned[self._supervisor]["pid"] == self._provision["supervisor"]["pid"], "supervisor PIDFD")
            self._open_ancestry()
            for role in ("provider", "supervisor"):
                self._open_namespaces(role, self._provision[role]["pid"])
            self._guard("OPEN")
            for fd in fds[:5]:
                self._owned.pop(fd)
            try:
                self._session = ReaderCheckpointSession(
                    epoch_raw=epoch_raw, expected_epoch_digest=expected_epoch_digest,
                    checkpoint_provision_raw=checkpoint_provision_raw, expected_checkpoint_provision_digest=expected_checkpoint_provision_digest,
                    transport_provision_raw=transport_provision_raw, expected_transport_provision_digest=expected_transport_provision_digest,
                    stream_inventory_raw=stream_inventory_raw, expected_stream_digest=expected_stream_digest,
                    loop_provision_raw=loop_provision_raw, expected_loop_provision_digest=expected_loop_provision_digest,
                    notice_write_fd=notice_write_fd, reader_pidfd=reader_pidfd, refresh_write_fd=refresh_write_fd,
                    completion_read_fd=completion_read_fd, cancel_read_fd=session_cancel_read_fd)
            except BaseException as exc:
                self._observed["session_error"] = exc
                self._unresolved.append(exc)
                raise
            self._guard("OPEN")
            self._open_listener()
            self._guard("OPEN")
            ready = dict(schema=_PREFIX + "provider-ready/v1", provider=self._provision["provider"],
                         supervisor=self._provision["supervisor"], clock=self._provision["clock"],
                         provision_digest=self._provision_pin, source_inventory_digest=self._source_pin,
                         **self._provision["reader_session"],
                         guard_socket={"path": _ENDPOINT, "metadata": self._socket_named}, ready_ns=self._tick())
            raw = _raw(_canonical(ready) + b"\n", 4096)
            self._handle(self._ready)
            _require(len(raw) <= os.fpathconf(self._ready, "PC_PIPE_BUF"), "atomic ready frame")
            self._handle(self._ready)
            self._observed["provider_ready_raw"] = raw
            self._local(self._ready)
            self._observed["ready_write_attempted"] = True
            count = os.write(self._ready, raw)
            self._observed["ready_bytes_written"] = count
            _require(type(count) is int and count == len(raw), "ready write result")
            self._handle(self._ready)
            finished = self._guard("OPEN")
            self._opening = self._result("OPEN", "OPENED", started, finished)
            self._deadline = self._provision["session_deadline_ns"]
        except BaseException as exc:
            raise self._refuse(exc) from exc

    def _validate(self, provision_raw, provision_pin, source_raw, source_pin, measurement_raw, measurement_pin,
                  fixture_raw, fixture_pin, epoch_raw, epoch_pin, checkpoint_raw, checkpoint_pin,
                  transport_raw, transport_pin, stream_raw, stream_pin, loop_raw, loop_pin, ready_raw, ready_pin):
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
                 and p["provider"]["pid"] == _PID, "role processes")
        _clock(p["clock"])
        for key in p:
            if key.endswith("_digest"):
                _pin(p[key])
        _require(_uint(p["accept_deadline_ns"], 1) < _uint(p["session_deadline_ns"], 1), "service deadlines")
        _keys(p["reader_session"], "epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest loop_provision_digest")
        inputs = ((epoch_raw, epoch_pin, 32768), (checkpoint_raw, checkpoint_pin, 8192),
                  (transport_raw, transport_pin, 8192), (stream_raw, stream_pin, 16384), (loop_raw, loop_pin, 8192))
        docs = [_document(*item) for item in inputs]
        e, cp, tr, st, lp = docs
        expected = dict(zip(("epoch_digest", "checkpoint_provision_digest", "transport_provision_digest", "stream_digest", "loop_provision_digest"),
                            (epoch_pin, checkpoint_pin, transport_pin, stream_pin, loop_pin)))
        _require(p["reader_session"] == expected and p["epoch_digest"] == epoch_pin
                 and e["deployment_digest"] == p["deployment_digest"]
                 and cp["session_deadline_ns"] == tr["session_deadline_ns"] == lp["session_deadline_ns"] == p["session_deadline_ns"]
                 and st["observer"] == p["provider"] and st["supervisor"] == p["supervisor"]
                 and st["clock"] == p["clock"] and st["access_inventory_digest"] == p["access_inventory_digest"], "reader provision joins")
        _uint(lp["startup_deadline_ns"], 1)
        _require(lp["startup_deadline_ns"] < lp["session_deadline_ns"], "startup deadline")
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
        _require(cancel["readers"][0]["fd"] == self._cancel, "local cancellation FD")
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
        ready = _keys(_document(ready_raw, ready_pin, 4096), "schema provider supervisor pipe provider_write_fd supervisor_read_fd provision_digest source_inventory_digest")
        _process(ready["provider"])
        _process(ready["supervisor"])
        _meta(ready["pipe"])
        _require(ready["schema"] == _PREFIX + "bootstrap-readiness-expectation/v1" and ready["provider"] == p["provider"]
                 and ready["supervisor"] == p["supervisor"] and ready["provider_write_fd"] == self._ready
                 and ready["provision_digest"] == provision_pin and ready["source_inventory_digest"] == source_pin
                 and ready["pipe"]["mode"] == stat.S_IFIFO | 0o600 and ready["pipe"]["uid"] == ready["pipe"]["gid"] == 0, "readiness expectation")
        _uint(ready["provider_write_fd"], 3)
        _uint(ready["supervisor_read_fd"], 3)
        _require((ready["pipe"]["device"], ready["pipe"]["inode"]) != (cancel["device"], cancel["inode"]), "pipe alias")
        _require(type(st["pipes"]) is list and len(st["pipes"]) == 6, "reader pipe inventory")
        reader_pipes = {(_uint(item["device"]), _uint(item["inode"], 1)) for item in st["pipes"]}
        _require(len(reader_pipes) == 6 and (cancel["device"], cancel["inode"]) not in reader_pipes
                 and (ready["pipe"]["device"], ready["pipe"]["inode"]) not in reader_pipes, "separate service channels")
        self._provision, self._loop, self._stream, self._ready_expected = p, lp, st, ready
        self._provision_pin, self._source_pin = provision_pin, source_pin
        self._measurement_raw, self._measurement_pin = measurement_raw, measurement_pin
        self._fixture_raw, self._fixture_pin = fixture_raw, fixture_pin
        self._observed.update(provision_raw=provision_raw, source_inventory_raw=source_raw, readiness_expectation_raw=ready_raw)
        expectation = dict(schema=_PREFIX + "context-expectation/v1", **{key: p[key] for key in (
            "broker", "provider", "clock", "grant_digest", "deployment_digest", "epoch_digest", "measurement_binding_digest",
            "fixture_binding_digest", "session_deadline_ns")}, broker_source_pins=m["source_pins"],
            directories=[p["directories"][i] for i in (0, 3, 4, 5, 6)])
        self._observed["context_expectation_raw"] = _raw(_canonical(expectation), 16384)

    def _owner(self):
        _require(os.getpid() == _PID and threading.get_ident() == _THREAD
                 and threading.get_native_id() == self._thread
                 and threading.current_thread() is threading.main_thread()
                 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "original Root owner")

    def _tick(self, *, deadline=True):
        self._owner()
        now = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(now >= self._last_ns, "clock rollback")
        self._last_ns = now
        if deadline:
            _require(now < self._deadline, "original deadline expired")
        return now

    @staticmethod
    def _row(*, pid=None, obj=None):
        return dict(identity=None, flags=None, descriptor_flags=None, link=None,
                    pid=pid, object=obj, consumed=False, role=None)

    def _initial(self, fd):
        self._owner()
        row = self._owned[fd]
        row["identity"] = _metadata(os.fstat(fd))
        row["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        row["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        row["link"] = os.readlink(f"/proc/self/fd/{fd}")
        if row["link"] == "anon_inode:[pidfd]" and row["pid"] is None:
            # All PIDFDs may share anon-inode metadata. Observing this type must
            # require an association even if a later opening guard fails.
            row["pid"] = "UNKNOWN"
        _require(type(row["link"]) is str and row["link"].isascii() and len(row["link"]) <= 4096, "descriptor link")
        self._owner()
        _require(_metadata(os.fstat(fd)) == row["identity"], "opening descriptor custody")

    def _register(self, fd, *, pid=None, obj=None, minimum=3):
        # A newly returned resource is tracked before any fallible identity or
        # clock observation. Unknown custody remains quarantined on refusal.
        if obj is not None:
            self._unresolved.append(obj)
        _uint(fd, minimum)
        if fd in self._owned:
            raise ValueError("owned descriptor alias")
        self._owned[fd] = self._row(pid=pid, obj=obj)
        _require(len(self._owned) <= 32, "descriptor capacity")
        return fd

    def _own(self, fd, *, pid=None, obj=None):
        self._register(fd, pid=pid, obj=obj)
        self._owner()
        self._initial(fd)
        return fd

    def _local(self, fd, *, terminal=False):
        self._owner()
        row = self._owned[fd]
        _require((terminal or not row["consumed"]) and row["identity"] is not None, "owned descriptor unavailable")
        obj = row["object"]
        _require(obj is None or obj.fileno() == fd, "socket descriptor changed")
        _require(_metadata(os.fstat(fd)) == row["identity"], "held descriptor changed")
        link = os.readlink(f"/proc/self/fd/{fd}")
        # Flags and closing identity follow the potentially blocking proc read.
        flags, dflags = fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD)
        self._owner()
        _require(link == row["link"] and flags == row["flags"] and dflags == row["descriptor_flags"]
                 and _metadata(os.fstat(fd)) == row["identity"]
                 and (obj is None or obj.fileno() == fd), "descriptor flags/link/custody")
        return row

    def _read(self, path, bound, *, observed=None, key=None):
        self._owner()
        fd = os.open(path, _OPEN)
        original = None
        try:
            self._own(fd)
            pieces, total = [], 0
            while True:
                self._local(fd)
                piece = os.read(fd, bound + 1 - total)
                _require(type(piece) is bytes, "proc read bytes")
                pieces.append(piece)
                total += len(piece)
                if observed is not None:
                    observed[key] = b"".join(pieces)[:bound]
                self._local(fd)
                _require(total <= bound, "proc byte bound")
                if not piece:
                    return b"".join(pieces)
        except BaseException as exc:
            original = exc
            raise
        finally:
            try:
                self._close_fd(fd)
            except BaseException as exc:
                self._cleanup_errors.append(exc)
                if original is None:
                    raise

    def _pid_association(self, fd):
        self._local(fd)
        raw = self._read(f"/proc/self/fdinfo/{fd}", 4096)
        values = re.findall(rb"^Pid:\s*([0-9]+)\s*$", raw, re.MULTILINE)
        _require(len(values) == 1, "PIDFD association")
        pid = _uint(int(values[0]), 1, 2147483647)
        self._local(fd)
        return pid

    def _live(self, fd):
        row = self._local(fd)
        _require(type(row["pid"]) is int and self._pid_association(fd) == row["pid"], "PIDFD binding")
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        _require(poller.poll(0) == [], "process exited")
        self._local(fd)

    def _retain_handle(self, fd, *, raw=None, closed=False, row=None):
        row = self._owned[fd] if row is None else row
        role = row["role"]
        if role is None:
            return
        snap = dict(role=role, descriptor=fd, observed_ns=self._tick(deadline=False), metadata=row["identity"],
                    flags=row["flags"], descriptor_flags=row["descriptor_flags"], link=row["link"],
                    pidfd_info_raw=raw, closed=closed)
        snapshots = self._observed["handle_observations"]
        indices = [i for i, item in enumerate(snapshots) if item["role"] == role]
        if len(indices) == 2:
            snapshots.pop(indices[-1])
        snapshots.append(snap)

    def _handle(self, fd):
        row = self._local(fd)
        _require(row["descriptor_flags"] & fcntl.FD_CLOEXEC, "handle CLOEXEC")
        info = None
        if fd in (self._cancel, self._ready):
            expected = self._provision["cancellation_pipe"] if fd == self._cancel else self._ready_expected["pipe"]
            expected = {key: expected[key] for key in ("device", "inode", "mode", "uid", "gid")}
            direction = os.O_RDONLY if fd == self._cancel else os.O_WRONLY
            _require(row["identity"] == expected and row["flags"] & os.O_ACCMODE == direction
                     and row["flags"] & os.O_NONBLOCK and row["link"] == f"pipe:[{expected['inode']}]", "pipe custody")
        else:
            info = self._read(f"/proc/self/fdinfo/{fd}", 4096)
            values = re.findall(rb"^Pid:\s*([0-9]+)\s*$", info, re.MULTILINE)
            _require(len(values) == 1 and int(values[0]) == self._provision["supervisor"]["pid"], "supervisor association")
            self._live(fd)
        self._local(fd)
        self._retain_handle(fd, raw=info)
        return self._tick()

    def _cancelled(self):
        self._handle(self._cancel)
        self._local(self._cancel)
        try:
            raw = os.read(self._cancel, 1)
        except BlockingIOError:
            self._handle(self._cancel)
            return
        self._handle(self._cancel)
        _require(False, "IPC cancelled" if raw == b"" else "cancellation data")

    def _open_ancestry(self):
        parent = None
        for path in _PATHS[:3]:
            name = "/" if path == "/" else path.rsplit("/", 1)[1]
            self._owner()
            fd = os.open(name, _OPEN | os.O_DIRECTORY, dir_fd=parent)
            self._own(fd)
            self._dirs.append((path, fd))
            parent = fd

    def _directory_guards(self):
        observed = []
        for index, (path, fd) in enumerate(self._dirs):
            row = self._local(fd)
            named = _metadata(os.stat(path, follow_symlinks=False))
            expected = {key: self._provision["directories"][index][key] for key in ("device", "inode", "mode", "uid", "gid")}
            _require(row["identity"] == named == expected, "directory identity")
            self._local(fd)
            observed.append(dict(self._provision["directories"][index], held=row["identity"], named=named))
        return observed

    def _open_namespaces(self, role, pid):
        for kind in ("time", "mnt"):
            fd = os.open(f"/proc/{pid}/ns/{kind}", os.O_RDONLY | os.O_CLOEXEC)
            self._own(fd)
            self._namespaces[(role, kind)] = fd

    def _namespace(self, role, pid):
        result = {}
        for kind in ("time", "mnt"):
            fd = self._namespaces[(role, kind)]
            row = self._local(fd)
            path = f"/proc/{pid}/ns/{kind}"
            named_stat = os.stat(path)
            named = dict(device=named_stat.st_dev, inode=named_stat.st_ino)
            link = os.readlink(path)
            _require(type(link) is str and link.isascii() and len(link) <= 128
                     and link == f"{kind}:[{named['inode']}]", "namespace link")
            held = {key: row["identity"][key] for key in ("device", "inode")}
            _require(held == named and (kind != "time" or held == self._provision["clock"]["time_namespace"]), "namespace identity/domain")
            self._local(fd)
            result["time" if kind == "time" else "mount"] = dict(held=held, named=named, link=link)
        return result

    def _process_observation(self, expected, *, observed=None, role=None):
        pid = expected["pid"]
        before = self._read(f"/proc/{pid}/stat", 16384, observed=observed, key=None if role is None else role + "_stat_before")
        status = self._read(f"/proc/{pid}/status", 16384, observed=observed, key=None if role is None else role + "_status")
        after = self._read(f"/proc/{pid}/stat", 16384, observed=observed, key=None if role is None else role + "_stat_after")
        for raw in (before, after):
            _require(raw.startswith(str(pid).encode() + b" ("), "stat PID")
            end = raw.rfind(b") ")
            fields = raw[end + 2:].split()
            _require(end >= 0 and len(fields) >= 20 and fields[0] not in (b"Z", b"X", b"x")
                     and int(fields[19]) == expected["start_time_ticks"], "process start/state")
        for key, identity in ((b"Uid", expected["uid"]), (b"Gid", expected["gid"])):
            values = re.findall(rb"^" + key + rb":\s*([^\n]+)$", status, re.MULTILINE)
            _require(len(values) == 1 and [int(v) for v in values[0].split()] == [identity] * 4, "process account vector")
        return before, status, after

    def _socket_options(self, sock):
        fd = sock.fileno()
        row = self._local(fd)
        _require(stat.S_ISSOCK(row["identity"]["mode"]) and row["flags"] & os.O_NONBLOCK
                 and row["descriptor_flags"] & fcntl.FD_CLOEXEC and sock.gettimeout() == 0.0
                 and not sock.get_inheritable(), "socket kernel flags")
        result = dict(fd=fd, **row["identity"], nonblocking=True, noninheritable=True,
                      passcred=sock.getsockopt(socket.SOL_SOCKET, _SO_PASSCRED),
                      passpidfd=sock.getsockopt(socket.SOL_SOCKET, _SO_PASSPIDFD),
                      sndbuf=sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                      rcvbuf=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                      so_type=sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE))
        _require(result["passcred"] == 1 and result["passpidfd"] == 0
                 and result["sndbuf"] >= 262176 and result["rcvbuf"] >= 262176
                 and result["so_type"] == socket.SOCK_SEQPACKET, "socket options")
        self._local(fd)
        return result

    def _configure_socket(self, sock, *, registered_fd=None):
        fd = sock.fileno()
        # Ownership precedes operations that can fail or change descriptor flags.
        if registered_fd is None:
            self._own(fd, obj=sock)
        else:
            _require(fd == registered_fd and self._owned[fd]["object"] is sock, "registered socket owner")
            self._initial(fd)
        self._local(fd)
        sock.setblocking(False)
        row = self._owned[fd]
        self._owner()
        _require(sock.fileno() == fd and _metadata(os.fstat(fd)) == row["identity"], "setblocking custody")
        row["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        self._local(fd)
        sock.set_inheritable(False)
        self._owner()
        _require(sock.fileno() == fd and _metadata(os.fstat(fd)) == row["identity"], "CLOEXEC custody")
        row["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        for option, value in ((_SO_PASSCRED, 1), (_SO_PASSPIDFD, 0),
                              (socket.SO_SNDBUF, 524320), (socket.SO_RCVBUF, 524320)):
            self._local(fd)
            sock.setsockopt(socket.SOL_SOCKET, option, value)
        _require(_metadata(os.fstat(fd)) == row["identity"] and sock.fileno() == fd, "socket setup custody")
        row["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        row["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        self._socket_options(sock)

    def _open_listener(self):
        self._directory_guards()
        try:
            os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("guard endpoint already exists")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        self._listener = sock
        self._configure_socket(sock)
        self._directory_guards()
        self._socket_options(sock)
        sock.bind(_ENDPOINT)
        self._socket_named = _metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False))
        _require(stat.S_ISSOCK(self._socket_named["mode"]) and self._socket_named["uid"] == 0, "new guard endpoint")
        self._directory_guards()
        _require(_metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False)) == self._socket_named,
                 "new endpoint before group change")
        os.chown("guard.sock", 0, self._provision["broker"]["gid"], dir_fd=self._dirs[-1][1], follow_symlinks=False)
        grouped = _metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False))
        _require(grouped == dict(self._socket_named, gid=self._provision["broker"]["gid"]), "new endpoint group custody")
        self._directory_guards()
        _require(_metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False)) == grouped,
                 "new endpoint before mode change")
        os.chmod("guard.sock", 0o660, dir_fd=self._dirs[-1][1], follow_symlinks=False)
        named = _metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False))
        _require((named["device"], named["inode"]) == (self._socket_named["device"], self._socket_named["inode"])
                 and named["mode"] == stat.S_IFSOCK | 0o660 and named["uid"] == 0
                 and named["gid"] == self._provision["broker"]["gid"], "guard endpoint protection")
        self._socket_named = named
        self._socket_options(sock)
        sock.listen(1)
        self._named_guard()

    def _named_guard(self):
        self._directory_guards()
        if self._socket_named is not None:
            _require(_metadata(os.stat("guard.sock", dir_fd=self._dirs[-1][1], follow_symlinks=False))
                     == self._socket_named, "guard pathname changed")
        if self._listener is not None:
            self._socket_options(self._listener)

    def _snapshot(self, snapshot):
        rows = self._observed["transport_observations"]
        indices = [i for i, row in enumerate(rows) if row["edge"] == snapshot["edge"]]
        if len(indices) == 2:
            rows.pop(indices[-1])
        rows.append(snapshot)
        _require(len(rows) <= 16, "observation capacity")

    def _guard(self, edge, *, controls=None, flags=None):
        started = self._tick()
        snap = dict(edge=edge, started_ns=started, finished_ns=None, peer_credentials_raw=None,
                    pidfd_info_raw=None, proc_raw={key: None for key in (
                        "broker_stat_before", "broker_status", "broker_stat_after",
                        "provider_stat_before", "provider_status", "provider_stat_after")},
                    boot_raw=None, namespaces={"broker": None, "provider": None},
                    controls=controls, receive_flags=flags, socket_options=None, directories=[])
        self._snapshot(snap)
        self._handle(self._supervisor)
        self._handle(self._ready)
        self._cancelled()
        boot = self._read("/proc/sys/kernel/random/boot_id", 64, observed=snap, key="boot_raw")
        snap["boot_raw"] = boot
        _require(boot == (self._provision["clock"]["boot_id"] + "\n").encode(), "boot identity")
        for role in ("provider", "supervisor") + (("broker",) if self._connection is not None else ()):
            values = self._process_observation(self._provision[role],
                                               observed=snap["proc_raw"] if role != "supervisor" else None, role=role)
            ns = self._namespace(role, self._provision[role]["pid"])
            if role in ("provider", "broker"):
                snap["proc_raw"].update(dict(zip((role + "_stat_before", role + "_status", role + "_stat_after"), values)))
                snap["namespaces"][role] = ns
        snap["directories"] = self._directory_guards()
        self._named_guard()
        sock = self._connection if self._connection is not None else self._listener
        if sock is not None:
            snap["socket_options"] = self._socket_options(sock)
        if self._connection is not None:
            credentials = self._connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
            snap["peer_credentials_raw"] = credentials
            _require(credentials == self._peer_raw, "peer credentials changed")
            snap["pidfd_info_raw"] = self._read(f"/proc/self/fdinfo/{self._peer_fd}", 4096,
                                               observed=snap, key="pidfd_info_raw")
            self._live(self._peer_fd)
        # Late proc/namespace observations cannot bypass cancellation or final FD guards.
        self._cancelled()
        self._handle(self._supervisor)
        if sock is not None:
            self._socket_options(sock)
        snap["finished_ns"] = self._tick()
        return snap["finished_ns"]

    def _wait(self, sock, edge, *, eof=False):
        while True:
            now = self._guard(edge)
            fd = sock.fileno()
            poller = select.poll()
            watched = (fd, self._cancel, self._supervisor) + (() if self._peer_fd is None else (self._peer_fd,))
            for item in watched:
                poller.register(item, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
            try:
                events = poller.poll(min((self._deadline - now + 999999) // 1000000, 2147483647))
            except InterruptedError:
                continue
            self._guard(edge)
            ready = False
            for item, flags in events:
                _require(item in watched and type(flags) is int and flags != 0, "poll response")
                if item == fd:
                    allowed = select.POLLIN | (select.POLLHUP if eof else 0)
                    _require(not flags & ~allowed, "socket poll error")
                    ready = True
                elif item == self._cancel:
                    _require(flags in (select.POLLIN, select.POLLHUP, select.POLLIN | select.POLLHUP), "cancel poll error")
                    self._cancelled()
                else:
                    raise ValueError("supervised process event")
            if ready:
                self._socket_options(sock)
                return

    def _accept(self):
        self._deadline = self._provision["accept_deadline_ns"]
        while True:
            self._wait(self._listener, "ACCEPT")
            self._socket_options(self._listener)
            try:
                connection, _ = self._listener.accept()
            except BlockingIOError:
                continue
            # The first accepted peer consumes this lifetime, including rejection.
            self._connection = connection
            fd = self._register(connection.fileno(), obj=connection)
            accepted = self._tick()
            self._configure_socket(connection, registered_fd=fd)
            raw = connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
            _require(type(raw) is bytes and len(raw) == 12, "peer credential ABI")
            pid, uid, gid = struct.unpack("=iII", raw)
            expected = self._provision["broker"]
            _require((pid, uid, gid) == (expected["pid"], expected["uid"], expected["gid"]), "admitted broker peer")
            self._peer_raw = raw
            self._socket_options(connection)
            peer_fd = connection.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD)
            self._peer_fd = self._own(peer_fd, pid="UNKNOWN")
            association = self._pid_association(peer_fd)
            self._owned[peer_fd]["pid"] = association
            _require(association == pid, "socket PIDFD peer")
            self._live(peer_fd)
            self._open_namespaces("broker", pid)
            self._peer = dict(expected)
            self._deadline = min(_add(accepted, 250000000), self._provision["session_deadline_ns"])
            self._guard("ACCEPT")
            return

    def _controls(self, controls, flags):
        _require(type(controls) is list, "ancillary list")
        retained, installed, original = [], [], None
        total = 0
        # Pass one registers every actual installed number before the first
        # metadata/owner read. A kernel-installed FD 0..2 still needs custody,
        # despite being invalid for the service's public transferred arguments.
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
                    original = ValueError("partial ancillary descriptor")
                for fd in numbers:
                    already_owned = fd in self._owned
                    try:
                        self._register(fd, pid="UNKNOWN" if kind == _SCM_PIDFD else None, minimum=0)
                    except BaseException as exc:
                        if original is None:
                            original = exc
                    finally:
                        if not already_owned and fd in self._owned:
                            installed.append(fd)
        # Pass two observes separately registered resources. Failure on one does
        # not erase ownership of the remaining descriptors in the same message.
        for fd in installed:
            try:
                self._initial(fd)
                if self._owned[fd]["link"] == "anon_inode:[pidfd]":
                    self._owned[fd]["pid"] = "UNKNOWN"
                    self._owned[fd]["pid"] = self._pid_association(fd)
            except BaseException as exc:
                if original is None:
                    original = exc
        try:
            if original is not None:
                raise original
            _require(len(controls) <= 8 and total <= 4096
                     and type(flags) is int and not flags & ~(socket.MSG_EOR | _MSG_CLOEXEC), "receive flags/control bound")
            _require(len(controls) == 1 and controls[0][:2] == (socket.SOL_SOCKET, _SCM_CREDENTIALS)
                     and controls[0][2] == self._peer_raw, "message credentials")
        finally:
            for fd in installed:
                try:
                    self._close_fd(fd)
                except BaseException as exc:
                    self._cleanup_errors.append(exc)
        return retained

    def _receive(self):
        while True:
            self._wait(self._connection, "RECEIVE")
            self._socket_options(self._connection)
            try:
                raw, controls, flags, _ = self._connection.recvmsg(4097, 4096, _MSG_DONTWAIT | _MSG_CLOEXEC)
            except BlockingIOError:
                continue
            if type(raw) is bytes:
                self._observed["request_raw"] = raw[:4096]
            # Observe receipt before fallible proc/file guards, including a late receipt.
            receipt_failure = None
            try:
                received = self._tick(deadline=False)
                self._received = received
            except BaseException as exc:
                receipt_failure = exc
                received = None
            # Retain actual ancillary prefixes even when validation refuses.
            snap = dict(edge="RECEIVE", started_ns=received, finished_ns=None, peer_credentials_raw=self._peer_raw,
                        pidfd_info_raw=None, proc_raw=dict.fromkeys(("broker_stat_before", "broker_status", "broker_stat_after",
                                                                   "provider_stat_before", "provider_status", "provider_stat_after")),
                        boot_raw=None, namespaces={"broker": None, "provider": None}, controls=[], receive_flags=flags,
                        socket_options=None, directories=[])
            self._snapshot(snap)
            for level, kind, value in controls[:8]:
                snap["controls"].append(dict(level=level, type=kind, raw=value[:max(0, 4096 - sum(len(v["raw"]) for v in snap["controls"]))]))
            try:
                retained = self._controls(controls, flags)
            except BaseException as exc:
                if receipt_failure is not None:
                    self._cleanup_errors.append(exc)
                    raise receipt_failure
                raise
            if receipt_failure is not None:
                raise receipt_failure
            _require(received < self._deadline, "late first packet")
            _raw(raw, 4096)
            request = validate_guard_request(raw)
            _require(request["phase"] == "BEFORE_CONNECT" and request["previous_response_digest"] is None
                     and request["epoch_digest"] == self._provision["epoch_digest"], "first phase")
            self._request, self._received = request, received
            self._deadline = min(request["deadline_boottime_ns"], _add(received, 250000000), self._provision["session_deadline_ns"])
            self._guard("RECEIVE", controls=retained, flags=flags)
            return raw, received

    def _session_call(self, operation, **kwargs):
        _require(self._session is not None and not self._session_terminal, "session unavailable")
        try:
            if operation == "acquire":
                return self._session.acquire_challenge(**kwargs)
            if operation == "finish":
                return self._session.finish_request(**kwargs)
            _require(operation == "close", "internal session operation")
            self._session_terminal = True
            return self._session.close()
        except BaseException as exc:
            self._session_terminal = True
            self._observed["session_error"] = exc
            self._unresolved.extend((self._session, exc))
            raise

    @staticmethod
    def _artifact(raw, bound):
        _raw(raw, bound)
        return dict(base64=base64.b64encode(raw).decode("ascii"), bytes=len(raw), digest=_digest(raw))

    def _response(self, request_raw, session, finished):
        owned = session["owned"]
        evidence = owned["evidence_raw"]
        _raw(evidence, 131072)
        _require(owned["evidence_digest"] == _digest(evidence) and all(owned[key] is False for key in _FLAGS), "owned reader result")
        response = dict(schema=_PREFIX + "response/v1", request_packet_digest=_digest(request_raw),
                        **{key: self._request[key] for key in ("exchange_id", "phase", "context_digest", "epoch_digest", "request_digest", "effect_digest")},
                        received_ns=self._received, finished_ns=finished, status="REFUSED", error_codes=["LOSS_UNAVAILABLE"],
                        reader_connection_epoch=owned["connection_epoch"], bindings=owned["bindings"],
                        reader_evidence=self._artifact(evidence, 131072),
                        reader_summary=self._artifact(_canonical(owned["reader"]), 32768),
                        reader_retention=dict(digest=owned["evidence_digest"], bytes=len(evidence)), loss_record=None,
                        checkpoint_record=self._artifact(session["checkpoint"]["acquisition_raw"], 16384),
                        **dict.fromkeys(_FLAGS, False))
        raw = _raw(_canonical(response), 262144)
        validate_guard_response(raw, request_raw=request_raw)
        return raw

    def _expected_eof(self):
        # Complete datagram already sent; allow HUP only to observe its EOF boundary.
        self._deadline = min(self._request["deadline_boottime_ns"], self._provision["session_deadline_ns"])
        while True:
            self._wait(self._connection, "EOF", eof=True)
            self._socket_options(self._connection)
            try:
                raw, controls, flags, _ = self._connection.recvmsg(4097, 4096, _MSG_DONTWAIT | _MSG_CLOEXEC)
            except BlockingIOError:
                continue
            receipt_failure = None
            try:
                received = self._tick(deadline=False)
            except BaseException as exc:
                receipt_failure, received = exc, None
            snapshot = dict(edge="EOF", started_ns=received, finished_ns=None,
                            peer_credentials_raw=self._peer_raw, pidfd_info_raw=None,
                            proc_raw=dict.fromkeys(("broker_stat_before", "broker_status", "broker_stat_after",
                                                   "provider_stat_before", "provider_status", "provider_stat_after")),
                            boot_raw=None, namespaces={"broker": None, "provider": None},
                            controls=[], receive_flags=flags, socket_options=None, directories=[])
            self._snapshot(snapshot)
            for level, kind, value in controls[:8]:
                snapshot["controls"].append(dict(level=level, type=kind,
                    raw=value[:max(0, 4096 - sum(len(item["raw"]) for item in snapshot["controls"]))]))
            try:
                if controls:
                    self._controls(controls, flags)
            except BaseException as exc:
                if receipt_failure is not None:
                    self._cleanup_errors.append(exc)
                    raise receipt_failure
                raise
            if receipt_failure is not None:
                raise receipt_failure
            self._tick()
            if not (type(raw) is bytes and raw == b"" and controls == [] and flags == 0):
                raise ValueError("extra packet after refusal", raw[:4096] if type(raw) is bytes else None, flags)
            self._guard("EOF")
            return

    def _run(self, body):
        self._owner()
        _require(self._lock.acquire(False), "service reentry")
        try:
            _require(not self._closed and self._failure is None, "terminal service")
            try:
                return body()
            except BaseException as exc:
                raise self._refuse(exc) from exc
        finally:
            self._lock.release()

    @property
    def opening_result(self):
        self._owner()
        _require(self._failure is None and not self._closed, "terminal service")
        return _detached(self._opening)

    def serve_one(self):
        def body():
            _require(not self._used, "exchange consumed")
            self._used = True
            started = self._tick()
            self._accept()
            request_raw, received = self._receive()
            self._guard("CONTEXT")
            expectation = self._observed["context_expectation_raw"]
            try:
                context = acquire_broker_reader_context(
                    self._connection, expectation_raw=expectation, expected_expectation_digest=_digest(expectation),
                    measurement_binding_raw=self._measurement_raw, expected_measurement_binding_digest=self._measurement_pin,
                    fixture_binding_raw=self._fixture_raw, expected_fixture_binding_digest=self._fixture_pin,
                    request_raw=request_raw, request_received_ns=received)
            except BrokerReaderContextError as exc:
                self._observed["context_error"] = exc
                self._unresolved.append(exc)
                raise
            self._observed["context_result"] = context
            self._guard("CONTEXT")
            _keys(context, "context_raw context_digest bound_raw pending_raw submission_verification_raw acquisition_raw acquisition_digest custody_raw")
            _require(_digest(_raw(context["context_raw"], 8192)) == context["context_digest"] == self._request["context_digest"], "actual context pin")
            self._context_pin = context["context_digest"]
            acquired = _decode(context["context_raw"], 8192)
            _require(acquired["grant_digest"] == self._provision["grant_digest"], "admission grant pin")
            self._guard("SESSION")
            result = self._session_call("acquire", context_raw=context["context_raw"], expected_context_digest=self._context_pin,
                                        request_raw=request_raw, admission_digest=acquired["grant_digest"], request_received_ns=received)
            self._observed["session_result"] = result
            finished = self._guard("SESSION")
            response = self._response(request_raw, result, finished)
            self._observed["response_raw"] = response
            self._guard("SEND")
            options = self._socket_options(self._connection)
            _require(options["sndbuf"] >= 2 * len(response) + 32, "actual response capacity")
            self._tick()
            self._local(self._connection.fileno())
            self._observed["send_attempted"] = True
            count = self._connection.sendmsg([response], [], _MSG_DONTWAIT | _MSG_NOSIGNAL)
            self._observed["bytes_sent"] = count
            _require(type(count) is int and count == len(response), "response send result")
            self._guard("SEND")
            self._expected_eof()
            self._guard("SESSION")
            self._observed["session_finish_raw"] = self._session_call("finish", expected_context_digest=self._context_pin)
            self._guard("SESSION")
            fd = self._connection.fileno()
            self._close_fd(fd)
            self._connection = None
            self._close_fd(self._peer_fd)
            self._peer_fd = None
            finished = self._guard("EOF")
            result = self._result("BEFORE_CONNECT", "REFUSED", started, finished)
            self._deadline = self._provision["session_deadline_ns"]
            return result
        return self._run(body)

    def _result(self, operation, status, started, finished):
        context = self._observed["context_result"]
        raw = _raw(_canonical(dict(
            schema=_PREFIX + "ipc-observation/v1", role="SERVICE", operation=operation,
            provision_digest=getattr(self, "_provision_pin", None), context_digest=self._context_pin,
            exchange_id=None if self._request is None else self._request["exchange_id"],
            request_packet_digest=None if self._request is None else _digest(self._observed["request_raw"]),
            response_packet_digest=None if self._observed["response_raw"] is None else _digest(self._observed["response_raw"]),
            started_ns=started, received_ns=self._received, finished_ns=finished, deadline_ns=self._deadline, peer=self._peer,
            context_file_digest=None if context is None else _digest(context["context_raw"]),
            bound_event_digest=None if context is None else _digest(context["bound_raw"]),
            measurement_pending_digest=None if context is None else _digest(context["pending_raw"]),
            status=status, stream_continuity="UNKNOWN", loss_completeness="UNKNOWN", **dict.fromkeys(_FLAGS, False))), 16384)
        self._observed["ipc_raw"] = raw
        return {"ipc_raw": raw, "observed": _detached(self._observed)}

    def _close_fd(self, fd):
        if fd not in self._owned:
            return
        row = self._owned[fd]
        if row["consumed"]:
            return
        self._owner()
        row["consumed"] = True
        self._local(fd, terminal=True)
        info = None
        if row["pid"] is not None:
            _require(type(row["pid"]) is int, "unknown PIDFD association")
            info = self._read(f"/proc/self/fdinfo/{fd}", 4096)
            values = re.findall(rb"^Pid:\s*([0-9]+)\s*$", info, re.MULTILINE)
            _require(len(values) == 1 and int(values[0]) == row["pid"], "closing PIDFD association")
        self._local(fd, terminal=True)
        obj = row["object"]
        if obj is not None:
            self._unresolved.append(obj)
            detached = obj.detach()
            _require(type(detached) is int and detached == fd, "socket detach identity")
            # Detach alone is not a close; preserve the row if later custody fails.
            row["object"] = None
            self._local(fd, terminal=True)
        os.close(fd)
        # The resolved generation is retired before fallible snapshot clocks.
        # A later proc open may legitimately reuse this number during cleanup.
        retired = self._owned.pop(fd)
        self._retain_handle(fd, raw=info, closed=True, row=retired)

    def _cleanup(self):
        errors = list(self._cleanup_errors)
        self._cleanup_errors.clear()
        if self._session is not None and not self._session_terminal:
            try:
                self._observed["session_close_raw"] = self._session_call("close")
            except BaseException as exc:
                errors.append(exc)
        for fd in tuple(self._owned):
            try:
                self._close_fd(fd)
            except BaseException as exc:
                errors.append(exc)
        errors.extend(self._cleanup_errors)
        self._cleanup_errors.clear()
        if self._owned or self._unresolved or errors:
            _QUARANTINE.append(self)
        return errors

    def _refuse(self, original):
        if self._failure is not None:
            return self._failure
        self._closed = True
        errors = self._cleanup()
        try:
            self._tick()
        except BaseException as exc:
            errors.append(exc)
        self._failure = BrokerReaderIpcError(original, errors, self._observed, self)
        _QUARANTINE.append(self)
        return self._failure

    def close(self):
        def body():
            started = self._guard("CLOSE")
            self._closed = True
            errors = self._cleanup()
            if errors:
                self._cleanup_errors.extend(errors)
                raise errors[0]
            finished = self._tick()
            return self._result("CLOSE", "CLOSED", started, finished)
        return self._run(body)
