"""One-attempt Root acquisition of the broker's actual retained pre-connect prefix."""
from __future__ import annotations

import base64
import copy
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

from .native_phase3_broker_reader_protocol import validate_guard_request
from .native_phase3_run_submission_verify import verify_submission_transcript
from .runtime_http_action import validate_fixture_binding, effect_for_attempt, action_digests

_IMPORT_PID = os.getpid()
_ATTEMPTED = False
_ENTRY_LOCK = threading.Lock()
_DIRECTORIES = ("/", "/var", "/var/lib", "/var/lib/aragorn-runtime-action",
                "/var/lib/aragorn-runtime-action/control")
_DIRECTORY_FIELDS = ("device", "inode", "mode", "uid", "gid")
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
          "run_qualified", "phase3_qualified", "request_receipt_authenticity_verified",
          "installed_sources_verified")
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_EDGE_FIELDS = ("started_ns", "finished_ns", "peer_credentials_base64", "peer_pidfd_info_base64",
                "boot_base64", "processes", "socket", "time_namespaces", "broker_mount_namespace",
                "root_directories", "broker_directories", "files")
_OBSERVED_FIELDS = ("request_raw", "caller_request_received_ns", "started_ns", "deadline_ns",
                    "context_raw", "bound_raw", "pending_raw", "submission_verification_raw",
                    "custody_before", "custody_after")


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _uint(value, minimum=0, maximum=2**63 - 1):
    _require(type(value) is int and minimum <= value <= maximum, "UINT")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "PIN")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value, maximum=None):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    _require(maximum is None or len(raw) <= maximum, "ENCODING_BOUND")
    return raw


def _fields(value, fields):
    _require(type(value) is dict and set(value) == set(fields), "FIELD_INVENTORY")


def _parse(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.isascii(), "RAW_BOUND")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("NONFINITE")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        _require(_canonical(value) == raw, "NONCANONICAL_JSON")
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError("JSON_REFUSED") from error
    _require(type(value) is dict, "RECORD_OBJECT")
    return value


def _process(value):
    _fields(value, ("pid", "start_time_ticks", "uid", "gid"))
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    for key in ("uid", "gid"):
        _uint(value[key], 0, 4294967295)


def _uuid(value):
    _require(type(value) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "BOOT_ID")


def _clock(value):
    _fields(value, ("boot_id", "clock_id", "time_namespace"))
    _uuid(value["boot_id"])
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "CLOCK")
    _fields(value["time_namespace"], ("device", "inode"))
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


def _root_owner():
    _require(sys.platform == "linux" and sys.byteorder == "little"
             and struct.calcsize("=iII") == 12, "PLATFORM_ABI")
    _require(os.getpid() == _IMPORT_PID and threading.get_native_id() == _IMPORT_PID
             and threading.current_thread() is threading.main_thread(), "ORIGINAL_MAIN_OWNER")
    for accounts in (os.getresuid(), os.getresgid()):
        _require(type(accounts) is tuple and len(accounts) == 3
                 and all(type(value) is int and value == 0 for value in accounts), "ROOT_ACCOUNTS")


def _identity(info):
    value = {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
             "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
             "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    for key, number in value.items():
        if key in ("mtime_ns", "ctime_ns"):
            _require(type(number) is int and -(2**63) <= number < 2**63, "METADATA_TIME")
        else:
            _uint(number, 1 if key in ("inode", "nlink") else 0)
    return value


def _directory(info, path):
    value = _identity(info)
    _require(stat.S_ISDIR(value["mode"]), "DIRECTORY_TYPE")
    return {"path": path, **{key: value[key] for key in _DIRECTORY_FIELDS}}


def _decimal(raw):
    _require(re.fullmatch(rb"[0-9]{1,20}", raw) is not None, "PROC_INTEGER")
    return _uint(int(raw))


def _stat_process(raw, expected):
    head, separator, tail = raw.rpartition(b")")
    _require(separator and b" (" in head, "PROC_STAT")
    _require(_decimal(head.partition(b" (")[0]) == expected["pid"], "PROC_PID")
    fields = tail.split()
    _require(len(fields) >= 20 and _decimal(fields[19]) == expected["start_time_ticks"], "PROC_START")


def _status_process(raw, expected):
    for field, key in ((b"Uid", "uid"), (b"Gid", "gid")):
        rows = [line.partition(b":")[2].split() for line in raw.splitlines()
                if line.partition(b":")[0] == field]
        _require(len(rows) == 1 and len(rows[0]) == 4, "PROC_ACCOUNT_FIELDS")
        _require([_decimal(value) for value in rows[0]] == [expected[key]] * 4, "PROC_ACCOUNTS")


def _inputs(expectation_raw, expected_expectation_digest, measurement_raw, expected_measurement_digest,
            fixture_raw, expected_fixture_digest, request_raw, received):
    records = []
    for raw, pin, limit in ((expectation_raw, expected_expectation_digest, 16384),
                            (measurement_raw, expected_measurement_digest, 8192),
                            (fixture_raw, expected_fixture_digest, 16384)):
        value = _parse(raw, limit)
        _pin(pin)
        _require(_digest(raw) == pin, "PROTECTED_INPUT_PIN")
        records.append(value)
    expectation, plan, fixture = records
    _fields(expectation, ("schema", "broker", "provider", "clock", "grant_digest", "deployment_digest",
                          "epoch_digest", "measurement_binding_digest", "fixture_binding_digest",
                          "broker_source_pins", "directories", "session_deadline_ns"))
    _require(expectation["schema"] == "aragorn/native-phase3-broker-reader-context-expectation/v1",
             "EXPECTATION_SCHEMA")
    for key in ("grant_digest", "deployment_digest", "epoch_digest", "measurement_binding_digest", "fixture_binding_digest"):
        _pin(expectation[key])
    _require(expectation["measurement_binding_digest"] == expected_measurement_digest
             and expectation["fixture_binding_digest"] == expected_fixture_digest, "INPUT_PIN_JOIN")
    for name in ("broker", "provider"):
        _process(expectation[name])
    broker, provider = expectation["broker"], expectation["provider"]
    _require(broker["pid"] != provider["pid"] and broker["uid"] > 0 and broker["gid"] > 0
             and provider["pid"] == _IMPORT_PID and provider["uid"] == provider["gid"] == 0,
             "EXPECTED_ACCOUNTS")
    _clock(expectation["clock"])
    _uint(expectation["session_deadline_ns"], 1)
    pins = expectation["broker_source_pins"]
    _require(type(pins) is dict and 1 <= len(pins) <= 128, "SOURCE_INVENTORY_BOUND")
    for name, value in pins.items():
        _require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}\.py", name), "SOURCE_BASENAME")
        _pin(value)
    directories = expectation["directories"]
    _require(type(directories) is list and len(directories) == 5, "DIRECTORY_INVENTORY")
    for index, (row, path) in enumerate(zip(directories, _DIRECTORIES)):
        _fields(row, ("path", *_DIRECTORY_FIELDS))
        _require(row["path"] == path, "DIRECTORY_PATH")
        for key in _DIRECTORY_FIELDS:
            _uint(row[key], 1 if key == "inode" else 0)
        _require(stat.S_ISDIR(row["mode"]), "DIRECTORY_TYPE")
        if index < 4:
            _require(row["uid"] == 0 and not row["mode"] & 0o022, "ROOT_ANCESTRY")
        else:
            _require(row["mode"] == stat.S_IFDIR | 0o700 and row["uid"] == broker["uid"]
                     and row["gid"] == broker["gid"], "CONTROL_CUSTODY")
    _fields(plan, ("schema", "boot_id", "attempt_id", "deployment_identity_digest", "measurement_schedule_digest",
                   "collection_commitment_digest", "scheduled_measurement_request_digest", "grant_digest",
                   "runtime_profile_digest", "sensor_digest", "source_pins", "runtime_digest", "policy_digest",
                   "active_skill_digest", "operation_digest", "path_digest", "payload_digest"))
    _require(plan["schema"] == "aragorn/runtime-broker-decision-measurement-binding/v1", "PLAN_SCHEMA")
    _require(plan["boot_id"] == expectation["clock"]["boot_id"] and plan["source_pins"] == pins
             and plan["deployment_identity_digest"] == expectation["deployment_digest"]
             and plan["grant_digest"] == expectation["grant_digest"], "PLAN_BINDINGS")
    for key, value in plan.items():
        if key.endswith("_digest"):
            _pin(value)
    _fields(fixture, ("schema", "fixture", "expected_broker_uid", "expected_broker_gid"))
    fixture = validate_fixture_binding(fixture)
    _require(fixture["fixture"]["boot_id"] == expectation["clock"]["boot_id"]
             and fixture["expected_broker_uid"] == broker["uid"]
             and fixture["expected_broker_gid"] == broker["gid"], "FIXTURE_BINDINGS")
    effect = effect_for_attempt(plan["attempt_id"])
    actions = action_digests(plan["attempt_id"], fixture)
    _require(all(plan[key] == value for key, value in actions.items()), "HTTP_ACTION_PINS")
    _parse(request_raw, 4096)
    request = validate_guard_request(request_raw)
    _require(request["phase"] == "BEFORE_CONNECT" and request["previous_response_digest"] is None,
             "REQUEST_PHASE")
    _uint(received)
    return expectation, plan, fixture, request, effect


class BrokerReaderContextError(ValueError):
    def __init__(self, original, cleanup, observed, owner):
        super().__init__("BROKER_READER_CONTEXT_REFUSED")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup[:32])
        self.observed = copy.deepcopy(observed)
        self.unresolved_owner = owner


class _Acquisition:
    def __init__(self, connection):
        self.connection = connection
        self.observed = dict.fromkeys(_OBSERVED_FIELDS)
        self.handles = {}
        self.cleanup_failures = []
        self.rejected_descriptors = []
        self.borrowed_fd = self.borrowed_identity = self.pidfd = None
        self.deadline = None
        self.last_time = 0
        self.cleaning = False
        self.namespaces = {}
        self.root_directories = []
        self.broker_directories = []
        self.files = []
        self.original_bytes = {}

    def tick(self):
        _root_owner()
        current = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(current >= self.last_time and (self.deadline is None or current < self.deadline), "ACQUISITION_DEADLINE")
        self.last_time = current
        return current

    def own(self, fd, kind):
        if type(fd) is not int or fd < 3 or fd == self.borrowed_fd or fd in self.handles:
            self.rejected_descriptors.append(fd)
            raise ValueError("DESCRIPTOR_ALIAS")
        _require(len(self.handles) < 32, "OWNED_FD_BOUND")
        self.handles[fd] = {"identity": None, "kind": kind, "attempted_close": False}
        self.handles[fd]["identity"] = _identity(os.fstat(fd))
        _require(not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                 "OWNED_INHERITANCE")
        return fd

    def open(self, path, flags, kind, parent=None):
        _require(len(self.handles) < 32, "OWNED_FD_BOUND")
        if not self.cleaning:
            self.tick()
        fd = os.open(path, flags, dir_fd=parent) if parent is not None else os.open(path, flags)
        return self.own(fd, kind)

    def check_fd(self, fd):
        row = self.handles[fd]
        actual = _identity(os.fstat(fd))
        row["observed_identity"] = actual
        expected = row["identity"]
        _require(expected is not None, "UNRESOLVED_DESCRIPTOR")
        keys = _DIRECTORY_FIELDS if row["kind"] == "directory" else actual.keys()
        _require(all(actual[key] == expected[key] for key in keys), "OWNED_DESCRIPTOR_CHANGED")
        _require(not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                 "OWNED_INHERITANCE_CHANGED")
        if row["kind"] != "pidfd":
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            _require(flags & os.O_ACCMODE == os.O_RDONLY and flags & os.O_NONBLOCK,
                     "OWNED_READONLY_NONBLOCKING")
        return actual

    def final_custody(self, fd):
        # Flag/clock/association observations may have invalidated the earlier check.
        _root_owner()
        _require(fd != self.connection.fileno(), "BORROWED_DESCRIPTOR_ALIAS_AT_USE")
        row = self.handles[fd]
        actual = _identity(os.fstat(fd))
        row["observed_identity"] = actual
        expected = row["identity"]
        _require(expected is not None, "UNRESOLVED_DESCRIPTOR")
        keys = _DIRECTORY_FIELDS if row["kind"] == "directory" else actual.keys()
        _require(all(actual[key] == expected[key] for key in keys), "FINAL_DESCRIPTOR_CHANGED")

    def read_fd(self, fd, maximum, target, key, encoded=False):
        self.check_fd(fd)
        self.final_custody(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        raw = b""
        while True:
            if not self.cleaning:
                self.tick()
            self.check_fd(fd)
            self.final_custody(fd)
            piece = os.read(fd, min(16384, maximum + 1 - len(raw)))
            _require(type(piece) is bytes, "READ_TYPE")
            raw += piece
            prefix = raw[:maximum]
            target[key] = base64.b64encode(prefix).decode("ascii") if encoded else prefix
            _require(len(raw) <= maximum, "READ_BOUND")
            if not piece:
                break
        self.check_fd(fd)
        return raw

    def close_fd(self, fd):
        _root_owner()
        row = self.handles[fd]
        _require(not row["attempted_close"], "AMBIGUOUS_CLOSE_NO_RETRY")
        # Consume even failed checks: uncertain ownership never gets a numeric-FD retry.
        row["attempted_close"] = True
        _require(fd != self.connection.fileno(), "BORROWED_DESCRIPTOR_ALIAS_AT_CLOSE")
        self.check_fd(fd)
        if row["kind"] == "pidfd":
            self.pidfd_guard(None)
            self.check_fd(fd)
        self.final_custody(fd)
        os.close(fd)
        del self.handles[fd]

    def proc(self, path, maximum, target, key):
        fd = self.open(path, _OPEN, "proc")
        original = value = None
        try:
            value = self.read_fd(fd, maximum, target, key, encoded=True)
        except BaseException as error:
            original = error
        try:
            self.close_fd(fd)
        except BaseException as error:
            self.cleanup_failures.append(error)
            if original is None:
                original = error
        if original is not None:
            raise original
        return value

    def socket_guard(self, edge):
        connection = self.connection
        fd = connection.fileno()
        _uint(fd, 3)
        actual = _identity(os.fstat(fd))
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        cloexec = bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        passcred = connection.getsockopt(socket.SOL_SOCKET, 16)
        passpidfd = connection.getsockopt(socket.SOL_SOCKET, 76)
        edge["socket"] = {"descriptor": fd, "identity": actual, "peer_pidfd_descriptor": self.pidfd,
                          "nonblocking": bool(flags & os.O_NONBLOCK),
                          "noninheritable": not os.get_inheritable(fd) and cloexec,
                          "passcred": passcred, "passpidfd": passpidfd}
        credentials = connection.getsockopt(socket.SOL_SOCKET, 17, 12)
        if type(credentials) is bytes:
            edge["peer_credentials_base64"] = base64.b64encode(credentials[:12]).decode("ascii")
        _require(type(credentials) is bytes and len(credentials) == 12, "PEER_CREDENTIAL_ABI")
        broker = self.expectation["broker"]
        _require(struct.unpack("=iII", credentials) == (broker["pid"], broker["uid"], broker["gid"]), "PEER_CREDENTIALS")
        _require(connection.family == socket.AF_UNIX
                 and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                 and connection.gettimeout() == 0 and stat.S_ISSOCK(actual["mode"])
                 and flags & os.O_NONBLOCK and not os.get_inheritable(fd) and cloexec
                 and type(passcred) is int and passcred == 1 and type(passpidfd) is int and passpidfd == 0,
                 "BORROWED_SOCKET_PROFILE")
        if self.borrowed_fd is None:
            self.borrowed_fd, self.borrowed_identity = fd, actual
        _require(fd == self.borrowed_fd and actual == self.borrowed_identity, "BORROWED_SOCKET_CHANGED")

    def pidfd_guard(self, edge):
        self.check_fd(self.pidfd)
        target = edge if edge is not None else {}
        raw = self.proc(f"/proc/self/fdinfo/{self.pidfd}", 4096, target, "peer_pidfd_info_base64")
        _require(raw.isascii(), "PIDFD_ENCODING")
        pids = [line.partition(b":")[2].strip() for line in raw.splitlines()
                if line.partition(b":")[0] == b"Pid"]
        _require(len(pids) == 1 and re.fullmatch(rb"[1-9][0-9]*", pids[0])
                 and _decimal(pids[0]) == self.expectation["broker"]["pid"], "PIDFD_ASSOCIATION")
        self.check_fd(self.pidfd)
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        _require(not poller.poll(0), "PEER_NOT_LIVE")
        self.check_fd(self.pidfd)

    def process_guard(self, edge):
        edge["processes"] = {}
        for role in ("broker", "provider"):
            expected = self.expectation[role]
            records = dict.fromkeys(("stat_before_base64", "status_base64", "stat_after_base64"))
            edge["processes"][role] = records
            for filename, key in (("stat", "stat_before_base64"), ("status", "status_base64"), ("stat", "stat_after_base64")):
                raw = self.proc(f"/proc/{expected['pid']}/{filename}", 16384, records, key)
                (_stat_process if filename == "stat" else _status_process)(raw, expected)

    def namespace(self, key, edge=None):
        fd, path, label = self.namespaces[key]
        actual = self.check_fd(fd)
        named = _identity(os.stat(path))  # Intentional proc namespace magic link.
        link = os.readlink(path)
        result = {"device": actual["device"], "inode": actual["inode"], "link": link}
        if edge is not None:
            if label == "time":
                edge["time_namespaces"][key.removesuffix("_time")] = result
            else:
                edge["broker_mount_namespace"] = result
        _require(stat.S_ISREG(actual["mode"]) and stat.S_ISREG(named["mode"])
                 and (actual["device"], actual["inode"]) == (named["device"], named["inode"])
                 and link == f"{label}:[{actual['inode']}]", "NAMESPACE_CHANGED")
        if label == "time":
            _require({k: result[k] for k in ("device", "inode")} == self.expectation["clock"]["time_namespace"],
                     "TIME_NAMESPACE_CHANGED")
        return result

    def directories(self, rows, broker_view):
        results = []
        for index, (fd, path) in enumerate(rows):
            actual = _directory(os.fstat(fd), path)
            self.check_fd(fd)
            if index == 0:
                named = os.stat(f"/proc/{self.expectation['broker']['pid']}/root") if broker_view else os.stat("/", follow_symlinks=False)
            else:
                named = os.stat(path.rsplit("/", 1)[1], dir_fd=rows[index - 1][0], follow_symlinks=False)
            _require(actual == _directory(named, path) == self.expectation["directories"][index], "DIRECTORY_VIEW_CHANGED")
            results.append(actual)
        return results

    def file_guard(self, row):
        actual = self.check_fd(row["fd"])
        for directories in (self.root_directories, self.broker_directories):
            named = _identity(os.stat(row["name"], dir_fd=directories[-1][0], follow_symlinks=False))
            _require(named == actual, "NAMED_FILE_CHANGED")
        broker = self.expectation["broker"]
        _require(actual["mode"] == stat.S_IFREG | 0o400 and actual["nlink"] == 1
                 and actual["uid"] == broker["uid"] and actual["gid"] == broker["gid"]
                 and 1 <= actual["bytes"] <= row["limit"], "CONTROL_FILE_CUSTODY")
        return actual

    def guard(self, edge):
        self.tick()
        self.socket_guard(edge)
        self.pidfd_guard(edge)
        boot = self.proc("/proc/sys/kernel/random/boot_id", 64, edge, "boot_base64")
        _require(boot == (self.expectation["clock"]["boot_id"] + "\n").encode("ascii"), "BOOT_CHANGED")
        self.process_guard(edge)
        edge["time_namespaces"] = dict.fromkeys(("broker", "provider"))
        for role in ("broker", "provider"):
            self.namespace(role + "_time", edge)
        self.namespace("broker_mnt", edge)
        edge["root_directories"] = self.directories(self.root_directories, False)
        edge["broker_directories"] = self.directories(self.broker_directories, True)
        edge["files"] = []
        for row in self.files:
            identity = self.file_guard(row)
            raw = self.observed[row["key"]]
            edge["files"].append({"role": row["role"], "name": row["name"], "identity": identity,
                                  "digest": _digest(raw) if raw is not None else None})
        self.tick()

    def setup(self, edge):
        self.socket_guard(edge)
        _require(len(self.handles) < 32, "OWNED_FD_BOUND")
        self.pidfd = self.connection.getsockopt(socket.SOL_SOCKET, 77)
        edge["socket"]["peer_pidfd_descriptor"] = self.pidfd
        self.own(self.pidfd, "pidfd")
        self.pidfd_guard(edge)
        self.process_guard(edge)
        edge["time_namespaces"] = dict.fromkeys(("broker", "provider"))
        for role, label in (("provider", "time"), ("broker", "time"), ("broker", "mnt")):
            path = f"/proc/{self.expectation[role]['pid']}/ns/{label}"
            fd = self.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, "namespace")
            self.namespaces[role + "_" + label] = (fd, path, label)
            self.namespace(role + "_" + label, edge)
        for broker_view, target in ((False, self.root_directories), (True, self.broker_directories)):
            edge_key = "broker_directories" if broker_view else "root_directories"
            edge[edge_key] = [None] * 5
            for index, path in enumerate(_DIRECTORIES):
                if index == 0:
                    name = f"/proc/{self.expectation['broker']['pid']}/root" if broker_view else "/"
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | os.O_CLOEXEC
                    if not broker_view:
                        flags |= os.O_NOFOLLOW
                    fd = self.open(name, flags, "directory")
                else:
                    fd = self.open(path.rsplit("/", 1)[1], _OPEN | os.O_DIRECTORY, "directory", target[-1][0])
                target.append((fd, path))
                actual = _directory(os.fstat(fd), path)
                edge[edge_key][index] = actual
                _require(actual == self.expectation["directories"][index], "DIRECTORY_VIEW_CHANGED")
        request_hex = self.request["request_digest"][7:]
        names = (f"run-reader-{request_hex}-context.json", f"run-reader-{request_hex}-event-0.json",
                 "decision-measurement-pending.json")
        edge["files"] = []
        for role, key, name, maximum in zip(("CONTEXT", "BOUND", "PENDING"),
                                           ("context_raw", "bound_raw", "pending_raw"), names, (8192, 8192, 131072)):
            fd = self.open(name, _OPEN, "record", self.root_directories[-1][0])
            row = {"fd": fd, "role": role, "key": key, "name": name, "limit": maximum}
            self.files.append(row)
            edge["files"].append({"role": role, "name": name, "identity": self.handles[fd]["identity"], "digest": None})
            self.file_guard(row)
        identities = [self.handles[row["fd"]]["identity"] for row in self.files]
        _require(len({(v["device"], v["inode"]) for v in identities}) == 3, "FILE_ALIAS")

    def capture(self, edge, repeat=False):
        if edge["started_ns"] is None:
            edge["started_ns"] = self.tick()
        self.guard(edge)
        for row in self.files:
            identity = self.file_guard(row)
            raw = self.read_fd(row["fd"], row["limit"], self.observed, row["key"])
            _require(len(raw) == identity["bytes"], "INCOMPLETE_RECORD_READ")
            self.file_guard(row)
            self.guard(edge)
            if repeat:
                _require(raw == self.original_bytes[row["key"]], "RETAINED_BYTES_CHANGED")
            else:
                self.original_bytes[row["key"]] = raw
        edge["finished_ns"] = self.tick()

    def cleanup(self):
        self.cleaning = True
        if self.handles:
            try:
                _root_owner()
            except BaseException as error:
                self.cleanup_failures.append(error)
                return
        for fd in reversed(list(self.handles)):
            if fd not in self.handles or self.handles[fd]["attempted_close"]:
                continue
            try:
                self.close_fd(fd)
            except BaseException as error:
                self.cleanup_failures.append(error)


def _semantic(owner, effect):
    observed, expected = owner.observed, owner.expectation
    context_raw, bound_raw, pending_raw = (observed[k] for k in ("context_raw", "bound_raw", "pending_raw"))
    context = _parse(context_raw, 8192)
    _fields(context, ("schema", "request_digest", "effect_digest", "grant_digest", "deployment_digest", "epoch_digest",
                      "broker", "provider", "clock", "exchange_id", "accepted_boottime_ns", "deadline_boottime_ns", "clock_bracket"))
    context_digest = _digest(context_raw)
    for key in ("grant_digest", "deployment_digest", "epoch_digest", "broker", "provider", "clock"):
        _require(_canonical(context[key]) == _canonical(expected[key]), "ACQUIRED_CONTEXT_JOIN")
    _require(context["effect_digest"] == _digest(_canonical(effect)), "HTTP_EFFECT_JOIN")
    for key in ("request_digest", "effect_digest", "epoch_digest", "exchange_id", "deadline_boottime_ns"):
        _require(context[key] == owner.request[key], "REQUEST_CONTEXT_JOIN")
    _require(owner.request["context_digest"] == context_digest, "ACQUIRED_CONTEXT_PIN")
    pending = _parse(pending_raw, 131072)
    _fields(pending, ("schema", "binding", "process", "clock_id", "acceptance_boundary", "accepted_boottime_ns",
                      "action_request_digest", "submission_digest", "lease_digest", "runtime_attribution_digest"))
    _require(pending["schema"] == "aragorn/runtime-broker-decision-measurement-pending/v1"
             and pending["clock_id"] == "CLOCK_BOOTTIME"
             and pending["acceptance_boundary"] == "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM"
             and _canonical(pending["binding"]) == owner.measurement_raw, "PENDING_BINDING")
    _fields(pending["process"], ("boot_id", "pid", "uid", "gid", "start_time_ticks", "mount_namespace"))
    actual_process = {**expected["broker"], "boot_id": expected["clock"]["boot_id"],
                      "mount_namespace": owner.namespace("broker_mnt")["link"]}
    _require(_canonical(pending["process"]) == _canonical(actual_process), "PENDING_PROCESS")
    for key in ("action_request_digest", "submission_digest", "lease_digest", "runtime_attribution_digest"):
        _pin(pending[key])
    _uint(pending["accepted_boottime_ns"])
    _require(pending["action_request_digest"] == context["request_digest"]
             and pending["accepted_boottime_ns"] == context["accepted_boottime_ns"], "PENDING_REQUEST_ACCEPTANCE")
    replay = verify_submission_transcript(
        context_raw, [bound_raw], {}, expected_context_digest=context_digest,
        expected_request_digest=owner.request["request_digest"], expected_broker=expected["broker"],
        expected_provider=expected["provider"], expected_clock=expected["clock"], expected_terminal_digest=None)
    wanted = {"status": "CONSISTENT_OPEN_PREFIX", "context_digest": context_digest,
              "last_event_digest": _digest(bound_raw), "submission_state": "UNKNOWN", **dict.fromkeys(_FLAGS[:5], False)}
    _require(_canonical(replay) == _canonical(wanted), "INDEPENDENT_PREFIX_REFUSED")
    observed["submission_verification_raw"] = _canonical(replay, 4096)
    bound = _parse(bound_raw, 8192)
    _require(_uint(bound["checked_ns"]) <= observed["caller_request_received_ns"]
             <= observed["started_ns"], "RECEIPT_CHRONOLOGY")
    return context_digest


def acquire_broker_reader_context(
    connection, *, expectation_raw: bytes, expected_expectation_digest: str,
    measurement_binding_raw: bytes, expected_measurement_binding_digest: str,
    fixture_binding_raw: bytes, expected_fixture_binding_digest: str,
    request_raw: bytes, request_received_ns: int,
) -> dict:
    global _ATTEMPTED
    owner = _Acquisition(connection)
    original = None
    entered = False
    context_digest = finished = None
    try:
        _root_owner()
        _require(_ENTRY_LOCK.acquire(blocking=False), "REENTRY")
        entered = True
        _require(not _ATTEMPTED, "ONE_ATTEMPT_CONSUMED")
        _ATTEMPTED = True
        owner.observed["started_ns"] = owner.tick()
        if type(request_raw) is bytes:
            owner.observed["request_raw"] = request_raw[:4096]
        owner.observed["caller_request_received_ns"] = _uint(request_received_ns)
        expectation, plan, fixture, request, effect = _inputs(
            expectation_raw, expected_expectation_digest, measurement_binding_raw, expected_measurement_binding_digest,
            fixture_binding_raw, expected_fixture_binding_digest, request_raw, request_received_ns)
        owner.expectation, owner.request, owner.measurement_raw = expectation, request, measurement_binding_raw
        _require(request_received_ns <= owner.observed["started_ns"], "FUTURE_RECEIPT")
        phase_end = min(_uint(request["deadline_boottime_ns"], 1), _uint(request_received_ns + 250000000),
                        expectation["session_deadline_ns"])
        _require(phase_end >= 100000000, "CHALLENGE_BUDGET")
        owner.deadline = owner.observed["deadline_ns"] = phase_end - 100000000
        _require(owner.observed["started_ns"] < owner.deadline, "ACQUISITION_DEADLINE")
        before = dict.fromkeys(_EDGE_FIELDS)
        before["started_ns"] = owner.observed["started_ns"]
        owner.observed["custody_before"] = before
        owner.setup(before)
        owner.capture(before)
        context_digest = _semantic(owner, effect)
        after = dict.fromkeys(_EDGE_FIELDS)
        owner.observed["custody_after"] = after
        owner.capture(after, repeat=True)
    except BaseException as error:
        original = error
    finally:
        owner.cleanup()
        if entered and hasattr(owner, "expectation"):
            try:
                _root_owner()
                if owner.borrowed_fd is not None:
                    terminal_socket = dict.fromkeys(_EDGE_FIELDS)
                    try:
                        owner.socket_guard(terminal_socket)
                    except BaseException:
                        edge = owner.observed["custody_after"] or owner.observed["custody_before"]
                        for key in ("socket", "peer_credentials_base64"):
                            edge[key] = terminal_socket[key]
                        raise
                finished = owner.tick()
            except BaseException as error:
                if original is None:
                    original = error
                else:
                    owner.cleanup_failures.append(error)
        if entered:
            _ENTRY_LOCK.release()
    if original is not None or owner.cleanup_failures:
        raise BrokerReaderContextError(original or owner.cleanup_failures[0], owner.cleanup_failures,
                                       owner.observed, owner) from original
    try:
        custody_raw = _canonical({"schema": "aragorn/native-phase3-broker-reader-context-custody/v1",
                                  "before": before, "after": after}, 524288)
        acquired = {
            "schema": "aragorn/native-phase3-broker-reader-context-acquisition/v1", "status": "ACQUIRED_BROKER_CONTEXT_PREFIX",
            "expectation_digest": expected_expectation_digest, "measurement_binding_digest": expected_measurement_binding_digest,
            "fixture_binding_digest": expected_fixture_binding_digest, "request_packet_digest": _digest(request_raw),
            "context_digest": context_digest, "bound_digest": _digest(owner.observed["bound_raw"]),
            "pending_digest": _digest(owner.observed["pending_raw"]),
            "submission_verification_digest": _digest(owner.observed["submission_verification_raw"]),
            "custody_digest": _digest(custody_raw), "caller_request_received_ns": request_received_ns,
            "started_ns": owner.observed["started_ns"], "finished_ns": finished, "deadline_ns": owner.deadline,
            "broker": expectation["broker"], "provider": expectation["provider"], "clock": expectation["clock"],
            "broker_mount_namespace": after["broker_mount_namespace"], "source_files": after["files"],
            "submission_state": "UNKNOWN", **dict.fromkeys(_FLAGS, False),
        }
        acquisition_raw = _canonical(acquired, 16384)
        return {"context_raw": owner.observed["context_raw"], "context_digest": context_digest,
                "bound_raw": owner.observed["bound_raw"], "pending_raw": owner.observed["pending_raw"],
                "submission_verification_raw": owner.observed["submission_verification_raw"],
                "acquisition_raw": acquisition_raw, "acquisition_digest": _digest(acquisition_raw), "custody_raw": custody_raw}
    except BaseException as error:
        raise BrokerReaderContextError(error, owner.cleanup_failures, owner.observed, owner) from error
