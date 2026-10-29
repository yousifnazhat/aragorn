"""One provisioned reader loop: byte custody, immutable checkpoints, no health claim."""

import errno
import fcntl
import hashlib
import json
import math
import os
import re
import select
import socket
import stat
import struct
import sys
import threading
import time
import uuid


_PID = os.getpid()
_LOCK = threading.Lock()
_STARTED = False
_MAX = 2**63 - 1
_PREFIX = "aragorn/native-phase3-reader"
_SOURCE = "/var/lib/aragorn-phase3-reader-events"
_ARCHIVE = "/var/lib/aragorn-phase3-reader-checkpoints"
_SOCKET = "/run/aragorn-phase3-reader/challenge.sock"
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PATH = getattr(os, "O_PATH", 0x200000) | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_ERRORS = select.POLLERR | select.POLLHUP | select.POLLNVAL
_FLAGS = dict(acquisition_authenticity_verified=False, sensor_health_verified=False,
              effect_authorized=False, run_qualified=False, phase3_qualified=False)
_UCREDS = struct.Struct("=iII")


def _require(value, message):
    if not value:
        raise ValueError(message)


def _keys(value, fields):
    _require(type(value) is dict and set(value) == set(fields.split()), "record fields differ")
    return value


def _uint(value, minimum=0, maximum=_MAX):
    _require(type(value) is int and minimum <= value <= maximum, "integer outside bound")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "digest differs")
    return value


def _nonce(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "nonce differs")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid(_value):
    raise ValueError("nonfinite JSON number")


def _document(raw, maximum, frame=False):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "record byte bound")
    data = raw[:-1] if frame else raw
    _require(not frame or raw.endswith(b"\n"), "unterminated frame")
    value = json.loads(data.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_invalid)
    _require(_canonical(value) == data, "noncanonical record")
    return value


def _process(value):
    _keys(value, "pid start_time_ticks uid gid")
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    for key in ("uid", "gid"):
        _uint(value[key], 0, 2**32 - 1)


def _clock(value):
    _keys(value, "boot_id clock_id time_namespace")
    _require(type(value["boot_id"]) is str and str(uuid.UUID(value["boot_id"])) == value["boot_id"]
             and value["clock_id"] == "CLOCK_BOOTTIME", "clock identity differs")
    _keys(value["time_namespace"], "device inode")
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


def _directory(value, path, uid, gid=None, permissions=None):
    _keys(value, "path device inode mode uid gid")
    _require(value["path"] == path, "directory path differs")
    for key in ("device", "inode", "mode", "uid", "gid"):
        _uint(value[key], 1 if key == "inode" else 0, 2**32 - 1 if key in ("uid", "gid") else _MAX)
    _require(stat.S_ISDIR(value["mode"]) and not value["mode"] & 0o022
             and value["uid"] == uid and (gid is None or value["gid"] == gid)
             and (permissions is None or stat.S_IMODE(value["mode"]) == permissions),
             "directory ownership differs")


def _inputs(arguments):
    values = {}
    for name, pin_name, limit in (
        ("epoch", "epoch", 32768), ("checkpoint_provision", "checkpoint_provision", 8192),
        ("transport_provision", "transport_provision", 8192),
        ("stream_inventory", "stream", 16384), ("loop_provision", "loop_provision", 8192),
    ):
        raw, pin = arguments[name + "_raw"], arguments["expected_" + pin_name + "_digest"]
        _require(type(raw) is bytes and 0 < len(raw) <= limit, "protected input byte bound")
        _pin(pin)
        _require(_digest(raw) == pin, "independently held input pin differs")
        values[name] = _document(raw, limit)
    e, p, t, inventory, loop = (values[key] for key in (
        "epoch", "checkpoint_provision", "transport_provision", "stream_inventory", "loop_provision"))
    _keys(e, "process clock loss_scope policy deployment_digest")
    process = _keys(e["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks reader_uid "
                    "reader_gid sensor_uid sensor_gid reader_source_digest sensor_source_digest stream_digest program_map_digest")
    for key, value in process.items():
        if key.endswith("_digest"):
            _pin(value)
        elif key != "boot_id":
            _uint(value, 1 if key.endswith(("_pid", "_ticks")) else 0,
                  2147483647 if key.endswith("_pid") else (2**32 - 1 if key.endswith(("_uid", "_gid")) else _MAX))
    _pin(e["deployment_digest"])
    _keys(e["clock"], "boot_id clock_id time_namespace_inode")
    _keys(e["policy"], "timeout_ns max_age_ns")
    _require(e["policy"] == {"timeout_ns": 100000000, "max_age_ns": 200000000}
             and all(type(number) is int for number in e["policy"].values()), "unsupported policy")
    _require(type(e["loss_scope"]) is list and 1 <= len(e["loss_scope"]) <= 32, "loss scope bound")
    for pin in e["loss_scope"]:
        _pin(pin)
    _require(e["loss_scope"] == sorted(set(e["loss_scope"])), "loss scope order")
    _keys(p, "schema epoch_digest session_id reader observer clock stream_digest source_inventory_digest "
          "access_inventory_digest directories session_deadline_ns")
    _keys(t, "schema epoch_digest observer directories notice_pipe session_deadline_ns max_requests access_inventory_digest")
    _keys(inventory, "schema session_id reader bridge sensor observer supervisor clock source_inventory_digest "
          "access_inventory_digest pipes upstream_continuity upstream_socket_digest upstream_loss_digest")
    _keys(loop, "schema epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest "
          "session_id startup_deadline_ns session_deadline_ns max_requests")
    _require(p["schema"] == _PREFIX + "-checkpoint-provision/v1"
             and t["schema"] == "aragorn/native-phase3-run-reader-transport-provision/v1"
             and inventory["schema"] == _PREFIX + "-stream-inventory/v1"
             and loop["schema"] == _PREFIX + "-loop-provision/v1", "input schema differs")
    _nonce(inventory["session_id"])
    _require(p["session_id"] == loop["session_id"] == inventory["session_id"], "session differs")
    for role in ("reader", "bridge", "sensor", "observer", "supervisor"):
        _process(inventory[role])
    _require(len({inventory[role]["pid"] for role in ("reader", "bridge", "sensor", "observer", "supervisor")}) == 5,
             "process aliases")
    reader = inventory["reader"]
    _require(reader["uid"] > 0 and reader["gid"] > 0 and inventory["bridge"]["uid"] > 0
             and inventory["bridge"]["gid"] > 0 and reader["uid"] != inventory["bridge"]["uid"]
             and reader["gid"] != inventory["bridge"]["gid"], "nonroot roles differ")
    for role in ("sensor", "observer", "supervisor"):
        _require(inventory[role]["uid"] == inventory[role]["gid"] == 0, "root role differs")
    for role in ("reader", "sensor"):
        _require(inventory[role] == dict(pid=process[role + "_pid"], start_time_ticks=process[role + "_start_ticks"],
                                        uid=process[role + "_uid"], gid=process[role + "_gid"]), "epoch process differs")
    _clock(inventory["clock"])
    clock = inventory["clock"]
    _require(e["clock"] == dict(boot_id=clock["boot_id"], clock_id="CLOCK_BOOTTIME",
                               time_namespace_inode=clock["time_namespace"]["inode"])
             and type(e["clock"]["time_namespace_inode"]) is int
             and process["boot_id"] == clock["boot_id"], "epoch clock differs")
    _keys(t["observer"], "pid start_time_ticks uid gid time_namespace")
    _process(p["reader"])
    _process(p["observer"])
    _clock(p["clock"])
    _process({key: t["observer"][key] for key in ("pid", "start_time_ticks", "uid", "gid")})
    _keys(t["observer"]["time_namespace"], "device inode")
    _uint(t["observer"]["time_namespace"]["device"])
    _uint(t["observer"]["time_namespace"]["inode"], 1)
    _require(p["reader"] == reader and p["observer"] == inventory["observer"] and p["clock"] == clock
             and t["observer"] == {**inventory["observer"], "time_namespace": clock["time_namespace"]}, "provision roles differ")
    for name in ("epoch", "checkpoint_provision", "transport_provision", "stream"):
        _require(loop[name + "_digest"] == arguments["expected_" + name + "_digest"], "loop pin differs")
    _require(p["epoch_digest"] == t["epoch_digest"] == loop["epoch_digest"]
             and p["stream_digest"] == process["stream_digest"] == loop["stream_digest"], "epoch/stream join differs")
    for key in ("source_inventory_digest", "access_inventory_digest"):
        _pin(inventory[key])
        _require(p[key] == inventory[key], "inventory pin differs")
    _require(t["access_inventory_digest"] == inventory["access_inventory_digest"]
             and inventory["upstream_continuity"] == "UNKNOWN"
             and inventory["upstream_socket_digest"] is inventory["upstream_loss_digest"] is None, "unsupported upstream claim")
    for document in (p, t, loop):
        _uint(document["session_deadline_ns"], 1)
    _uint(loop["startup_deadline_ns"], 1)
    _uint(loop["max_requests"], 1, 4096)
    _uint(t["max_requests"], 1, 4096)
    _require(loop["startup_deadline_ns"] < loop["session_deadline_ns"] == p["session_deadline_ns"] == t["session_deadline_ns"]
             and loop["max_requests"] == t["max_requests"], "lifetime differs")
    _require(type(p["directories"]) is list and len(p["directories"]) == 5
             and type(t["directories"]) is list and len(t["directories"]) == 3, "directory inventory bound")
    for index, path in enumerate(("/", "/var", "/var/lib", _SOURCE, _ARCHIVE)):
        _directory(p["directories"][index], path, reader["uid"] if index == 3 else 0,
                   reader["gid"] if index == 3 else (0 if index == 4 else None), 0o700 if index >= 3 else None)
    for index, path in enumerate(("/", "/run", "/run/aragorn-phase3-reader")):
        _directory(t["directories"][index], path, 0, reader["gid"] if index == 2 else 0, 0o710 if index == 2 else None)
    _require(p["directories"][0] == t["directories"][0], "root directory differs")
    pipes = inventory["pipes"]
    _require(type(pipes) is list and len(pipes) == 6, "pipe count differs")
    layouts = (("NOTICE", "OBSERVER", None, [("READER", 3)]),
               ("TELEMETRY", "BRIDGE", 1, [("READER", 4)]),
               ("REFRESH", "OBSERVER", None, [("READER", 5)]),
               ("STDERR", "BRIDGE", 2, [("READER", 6)]),
               ("CANCEL", "SUPERVISOR", None, [("READER", 7), ("OBSERVER", None)]),
               ("COMPLETION", "READER", 8, [("OBSERVER", None)]))
    per_process, identities = {}, set()
    for pipe, (role, writer, number, readers) in zip(pipes, layouts):
        _keys(pipe, "role device inode mode uid gid writer readers")
        _require(pipe["role"] == role and pipe["mode"] == stat.S_IFIFO | 0o600
                 and type(pipe["mode"]) is int and pipe["uid"] == pipe["gid"] == 0
                 and type(pipe["uid"]) is type(pipe["gid"]) is int, "pipe identity differs")
        _uint(pipe["device"])
        _uint(pipe["inode"], 1)
        identities.add((pipe["device"], pipe["inode"]))
        _require(type(pipe["readers"]) is list and len(pipe["readers"]) == len(readers), "pipe reader count")
        for endpoint, (expected_role, expected_fd) in zip([pipe["writer"], *pipe["readers"]], [(writer, number), *readers]):
            _keys(endpoint, "process fd")
            _uint(endpoint["fd"], 1 if expected_role == "BRIDGE" else 3, 2**31 - 1)
            _require(endpoint["process"] == expected_role and (expected_fd is None or endpoint["fd"] == expected_fd), "pipe endpoint differs")
            used = per_process.setdefault(expected_role, set())
            _require(endpoint["fd"] not in used, "endpoint aliases")
            used.add(endpoint["fd"])
    _require(len(identities) == 6, "pipe inode aliases")
    _keys(t["notice_pipe"], "device inode mode uid gid reader_fd")
    for key, number in t["notice_pipe"].items():
        _uint(number, 1 if key in ("inode", "reader_fd") else 0)
    _require(t["notice_pipe"] == {**{key: pipes[0][key] for key in ("device", "inode", "mode", "uid", "gid")},
                                   "reader_fd": 3}, "notice pipe differs")
    return values


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class ReaderCheckpointLoopError(ValueError):
    def __init__(self, original, owner):
        super().__init__("reader checkpoint loop refused; preserve observations and immutable files")
        self.original_failure = original
        self.cleanup_failures = tuple(owner.cleanup[:32])
        self.observed = dict(owner.observed)
        # The local launch caller must retain this exception until process exit.
        self.unresolved_owner = owner


class _Terminal(Exception):
    pass


class _Reader:
    def __init__(self):
        self.resources, self.cleanup, self.unresolved_sockets = [], [], []
        self.observed = {key: None for key in (
            "session_id startup_ready_raw notice_raw challenge_raw refresh_raw completion_raw ack_raw batch_raw "
            "stderr_raw manifest_raw publication_raw sequence_before sequence_after offset_before records_before").split()}
        self.observed.update(publication_attempted=False, completion_attempted=False, ack_attempted=False)
        self.directories, self.endpoint, self.pidfds = [], [], {}
        self.socket = self.socket_fd = self.peer_pidfd = self.namespace = None
        self.deadline, self.last = _MAX, -1
        self.sequence = self.offset = self.records = self.notice_ordinal = self.refresh_ordinal = 0
        self.previous = self.listener_epoch = self.first = None
        self.seen, self.batch, self.reads = set(), b"", []
        self.parsed = self.batch_records = 0
        self.active = self.waiting_close = False
        self.closed = False

    def _own(self, fd, role, obj=None):
        _uint(fd, 0, 2**31 - 1)
        _require(all(row["fd"] != fd for row in self.resources), "owned descriptor aliases")
        row = dict(fd=fd, role=role, object=obj, identity=None, pid=None)
        self.resources.append(row)
        row["identity"] = _identity(os.fstat(fd))[:5]
        if "PIDFD" in role:
            row["pid"] = self._association(fd)
        return fd

    def _close(self, fd):
        row = next(row for row in self.resources if row["fd"] == fd)
        self.resources.remove(row)  # consume ownership before detach, metadata or close
        try:
            if row["object"] is not None:
                self.unresolved_sockets.append(row["object"])
                actual = row["object"].detach()
                self.unresolved_sockets.remove(row["object"])
                _require(type(actual) is int and actual == fd, "socket detach identity differs")
            _require(row["identity"] is not None and _identity(os.fstat(fd))[:5] == row["identity"], "close custody lost")
            if row.get("sealed") is not None:
                name, sealed = row["sealed"]
                _require(_identity(os.fstat(fd)) == sealed == _identity(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)),
                         "sealed file changed before close")
            if "PIDFD" in row["role"]:
                _require(row["pid"] is not None and self._association(fd) == row["pid"], "close PIDFD association lost")
                _require(_identity(os.fstat(fd))[:5] == row["identity"], "close PIDFD metadata changed")
            os.close(fd)
        except BaseException as exc:
            self.cleanup.append(exc)
            raise

    def _close_all(self):
        self.closed = True
        for row in list(reversed(self.resources)):
            try:
                self._close(row["fd"])
            except BaseException:
                pass

    def _virtual(self, path, maximum):
        fd, error, raw = None, None, b""
        try:
            fd = self._own(os.open(path, _READ), "PROC")
            while True:
                part = os.read(fd, maximum + 1 - len(raw))
                _require(type(part) is bytes, "virtual read type")
                raw += part
                _require(len(raw) <= maximum, "virtual byte bound")
                if not part:
                    break
        except BaseException as exc:
            error = exc
        finally:
            if fd is not None:
                try:
                    self._close(fd)
                except BaseException as exc:
                    error = error or exc
        if error:
            raise error
        return raw

    def _tick(self):
        now = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(self.last <= now < self.deadline, "reader clock rollback or expired deadline")
        self.last = now
        return now

    def _local(self):
        reader = self.inventory["reader"]
        _require(sys.platform == "linux" and sys.byteorder == "little" and _UCREDS.size == 12
                 and os.getpid() == _PID == reader["pid"] == threading.get_native_id()
                 and os.getresuid() == (reader["uid"],) * 3 and os.getresgid() == (reader["gid"],) * 3
                 and os.getgroups() == [], "original restricted reader context differs")

    def _live(self, fd):
        poller = select.poll()
        poller.register(fd, select.POLLIN | _ERRORS)
        _require(not poller.poll(0), "peer process ended")

    def _association(self, fd):
        raw = self._virtual(f"/proc/self/fdinfo/{fd}", 4096)
        values = [line.partition(b":")[2].strip() for line in raw.splitlines() if line.startswith(b"Pid:")]
        _require(len(values) == 1 and re.fullmatch(rb"[1-9][0-9]*", values[0]), "PIDFD association unavailable")
        return _uint(int(values[0]), 1, 2147483647)

    def _pidfd(self, fd, pid):
        self._live(fd)
        _require(self._association(fd) == pid, "PIDFD association differs")
        self._live(fd)

    def _process_readback(self, role):
        expected = self.inventory[role]
        pid = expected["pid"]
        def start(raw):
            text = raw.decode("ascii")
            marker = text.rfind(") ")
            fields = text[marker + 2:].split() if marker >= 0 else []
            _require(text.startswith(f"{pid} (") and len(fields) >= 20 and fields[19].isdigit(), "proc stat differs")
            return _uint(int(fields[19]), 1)
        before = start(self._virtual(f"/proc/{pid}/stat", 16384))
        wanted = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
        values = {}
        for line in self._virtual(f"/proc/{pid}/status", 16384).decode("ascii").splitlines():
            key, separator, value = line.partition(":")
            if key in wanted:
                _require(separator and key not in values, "duplicate process field")
                values[key] = value.split()
        _require(before == start(self._virtual(f"/proc/{pid}/stat", 16384)) == expected["start_time_ticks"], "process start differs")
        for key in ("Uid", "Gid"):
            _require(values.get(key) == [str(expected[key.lower()])] * 4, "process accounts differ")
        if role == "reader":
            _require(values.get("Groups") == [] and values.get("NoNewPrivs") == ["1"], "reader privilege profile differs")
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                field = values.get(key, [])
                _require(len(field) == 1 and re.fullmatch(r"[0-9a-fA-F]+", field[0]) and int(field[0], 16) == 0,
                         "reader capability differs")

    def _metadata(self):
        for row in self.resources:
            _require(row["identity"] is not None and _identity(os.fstat(row["fd"]))[:5] == row["identity"]
                     and not os.get_inheritable(row["fd"]), "held descriptor changed")
        for pipe, fd in zip(self.inventory["pipes"], (3, 4, 5, 6, 7, 8)):
            wanted = tuple(pipe[key] for key in ("device", "inode", "mode", "uid", "gid"))
            _require(_identity(os.fstat(fd))[:5] == wanted
                     and os.readlink(f"/proc/self/fd/{fd}") == f"pipe:[{pipe['inode']}]"
                     and not os.get_inheritable(fd), "pipe custody differs")
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            _require(flags & os.O_ACCMODE == (os.O_WRONLY if fd == 8 else os.O_RDONLY)
                     and flags & os.O_NONBLOCK, "pipe access differs")
        for entry, fd, parent, name in self.directories + self.endpoint:
            expected = tuple(entry[key] for key in ("device", "inode", "mode", "uid", "gid"))
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _require(_identity(os.fstat(fd))[:5] == _identity(named)[:5] == expected, "named custody differs")
        if self.namespace is not None:
            held, named = os.fstat(self.namespace), os.stat(f"/proc/{_PID}/ns/time")
            expected = self.inventory["clock"]["time_namespace"]
            _require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) == (expected["device"], expected["inode"]), "time namespace changed")
        if self.socket is not None:
            _require(self.socket.fileno() == self.socket_fd and self.socket.gettimeout() == 0
                     and not self.socket.get_inheritable()
                     and self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                     and self.socket.getsockopt(socket.SOL_SOCKET, 16) == 1
                     and self.socket.getsockopt(socket.SOL_SOCKET, 76) == 0, "socket custody differs")
            if self.peer_pidfd is not None:
                observer = self.inventory["observer"]
                _require(self.socket.getsockopt(socket.SOL_SOCKET, 17, 12) == _UCREDS.pack(observer["pid"], 0, 0), "root socket peer differs")

    def _guard(self):
        self._local()
        self._tick()
        self._metadata()
        for role, fd in self.pidfds.items():
            self._pidfd(fd, self.inventory[role]["pid"])
        if self.peer_pidfd is not None:
            self._pidfd(self.peer_pidfd, self.inventory["observer"]["pid"])
        for role in ("reader", "observer", "bridge", "supervisor"):
            self._process_readback(role)
        _require(self._virtual("/proc/sys/kernel/random/boot_id", 64) ==
                 (self.inventory["clock"]["boot_id"] + "\n").encode(), "boot identity changed")
        self._metadata()
        for fd in [*self.pidfds.values(), *([self.peer_pidfd] if self.peer_pidfd is not None else [])]:
            self._live(fd)
        self._local()
        return self._tick()

    def _io(self, fd):
        """Immediate held/name/flags point sample after any preceding poll/guard."""
        self._local()
        self._metadata()
        row = next(row for row in self.resources if row["fd"] == fd)
        _require(row["identity"] is not None and _identity(os.fstat(fd))[:5] == row["identity"]
                 and not os.get_inheritable(fd), "I/O descriptor custody differs")
        if 3 <= fd <= 8:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            pipe = self.inventory["pipes"][fd - 3]
            _require(flags & os.O_ACCMODE == (os.O_WRONLY if fd == 8 else os.O_RDONLY)
                     and flags & os.O_NONBLOCK and os.readlink(f"/proc/self/fd/{fd}") == f"pipe:[{pipe['inode']}]",
                     "I/O pipe flags/link differs")
        return self._tick()

    def _poll(self, timeout=0, socket_event=select.POLLIN):
        poller = select.poll()
        for fd in (3, 4, 5, 6, 7):
            poller.register(fd, select.POLLIN | _ERRORS)
        poller.register(8, _ERRORS)
        for fd in self.pidfds.values():
            poller.register(fd, select.POLLIN | _ERRORS)
        if self.socket is not None:
            poller.register(self.socket_fd, socket_event | _ERRORS)
        if self.peer_pidfd is not None:
            poller.register(self.peer_pidfd, select.POLLIN | _ERRORS)
        events = dict(poller.poll(timeout))
        if 7 in events:
            self._io(7)
            _require(not events[7] & (select.POLLERR | select.POLLNVAL), "cancellation pipe error")
            try:
                raw = os.read(7, 1)
            except BlockingIOError:
                _require(not events[7] & select.POLLHUP, "ambiguous cancellation")
            else:
                self._metadata()
                self._local()
                self._tick()
                _require(raw == b"", "unexpected cancellation data")
                raise _Terminal("CANCELLED")
        _require(not any(fd in events for fd in self.pidfds.values())
                 and (self.peer_pidfd is None or self.peer_pidfd not in events), "peer process ended")
        if 6 in events:
            self._io(6)
            try:
                raw = os.read(6, 65536)
                self.observed["stderr_raw"] = raw
            except BlockingIOError:
                _require(not events[6] & _ERRORS, "stderr pipe failed")
            else:
                self._metadata()
                self._local()
                self._tick()
                raise ValueError("bridge stderr data or EOF")
        _require(8 not in events, "completion pipe failed")
        _require(not events.get(4, 0) & _ERRORS, "telemetry pipe error or EOF")
        for fd in (3, 5):
            _require(not events.get(fd, 0) & (select.POLLERR | select.POLLNVAL), "control pipe error")
        return events

    def _boundary(self):
        events = self._poll()
        if self.active and not self.waiting_close:
            _require(3 not in events and 5 not in events, "unexpected control during active operation")
        now = self._guard()
        events = self._poll()
        if self.active and not self.waiting_close:
            _require(3 not in events and 5 not in events, "unexpected control during active operation")
        return now

    def _wait(self, *, allow_control=False, socket_event=select.POLLIN):
        self._boundary()
        remaining = self.deadline - self._tick()
        events = self._poll(min((remaining + 999999) // 1000000, 2**31 - 1), socket_event)
        self._guard()
        if not allow_control:
            _require(3 not in events and 5 not in events, "unexpected control during operation")
        return events

    def _frame(self, fd, key):
        raw, original, assembly = b"", self.deadline, None
        try:
            while True:
                self._boundary()
                self._io(fd)
                try:
                    part = os.read(fd, 2049 - len(raw))
                except BlockingIOError:
                    events = self._wait(allow_control=True)
                    _require((5 if fd == 3 else 3) not in events, "concurrent control frames")
                    if 4 in events:
                        self._telemetry()
                    continue
                _require(type(part) is bytes, "control read type")
                if not part:
                    if not raw and not self.active:
                        raise _Terminal("OWNER_CLOSED")
                    raise ValueError("control EOF during operation")
                raw += part
                self.observed[key] = raw[:2048]
                now = self._tick()
                if assembly is None:
                    _require(now <= _MAX - 100000000, "assembly deadline overflow")
                    assembly = now + 100000000
                    self.deadline = min(original, assembly)
                self._boundary()
                _require(len(raw) <= 2048, "control frame overflow")
                if b"\n" in raw:
                    value = _document(raw, 2048, True)
                    try:
                        self._io(fd)
                        extra = os.read(fd, 1)
                    except BlockingIOError:
                        extra = None
                    _require(extra is None, "surplus control or owner EOF")
                    self._boundary()
                    self.frame_received_ns = now
                    return raw, value
        finally:
            self.deadline = original

    def _syntax(self):
        def integer(text):
            value = int(text)
            _require(-2**63 <= value < 2**63, "JSON integer range")
            return value
        def number(text):
            value = float(text)
            _require(math.isfinite(value), "JSON number overflow")
            return value
        while True:
            end = self.batch.find(b"\n", self.parsed)
            if end < 0:
                _require(len(self.batch) - self.parsed < 65536, "record tail bound")
                return
            raw = self.batch[self.parsed:end]
            _require(0 < len(raw) + 1 <= 65536 and not raw.endswith(b"\r") and not raw.startswith(b"\xef\xbb\xbf"), "record framing")
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid,
                               parse_int=integer, parse_float=number)
            _require(type(value) is dict, "record must be a JSON object")
            self.parsed, self.batch_records = end + 1, self.batch_records + 1
            _require(self.batch_records <= 256 and self.records + self.batch_records <= 4096, "record budget")

    def _telemetry(self):
        self._boundary()
        capacity = min(65536, 262144 - len(self.batch), 4194304 - self.offset - len(self.batch))
        _require(capacity > 0 and len(self.reads) <= 63, "telemetry byte/read budget exhausted")
        started = self._io(4)
        try:
            raw = os.read(4, capacity)
        except BlockingIOError:
            finished = self._tick()
            self._boundary()
            return dict(started_ns=started, finished_ns=finished, offset=self.offset + len(self.batch), bytes=0, outcome="EAGAIN")
        _require(type(raw) is bytes and 0 < len(raw) <= capacity, "telemetry EOF or read result")
        offset = self.offset + len(self.batch)
        self.batch += raw
        self.observed["batch_raw"] = self.batch
        finished = self._tick()
        self.reads.append(dict(started_ns=started, finished_ns=finished, offset=offset, bytes=len(raw), outcome="DATA"))
        _require(len(self.reads) <= 63, "telemetry DATA-read budget exceeded")
        self._syntax()
        self._boundary()
        return None

    def _readback(self, name, fd, expected, raw):
        self._boundary()
        before = _identity(os.fstat(fd))
        _require(before == expected == _identity(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)), "published file identity changed")
        actual = b""
        while len(actual) <= len(raw):
            self._io(fd)
            _require(_identity(os.fstat(fd)) == expected == _identity(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)),
                     "readback file custody changed")
            part = os.pread(fd, min(65536, len(raw) + 1 - len(actual)), len(actual))
            _require(type(part) is bytes, "file readback type")
            actual += part
            if not part:
                break
        _require(actual == raw and _identity(os.fstat(fd)) == expected
                 == _identity(os.stat(name, dir_fd=self.source_fd, follow_symlinks=False)), "published readback differs")
        self._boundary()

    def _publish(self, name, raw):
        self._boundary()
        self.observed["publication_attempted"] = True
        self._io(self.source_fd)
        fd = self._own(os.open(name, _CREATE, 0o400, dir_fd=self.source_fd), "PUBLICATION")
        initial = os.fstat(fd)
        reader = self.inventory["reader"]
        _require(initial.st_mode == stat.S_IFREG | 0o400 and initial.st_uid == reader["uid"]
                 and initial.st_gid == reader["gid"] and initial.st_nlink == 1 and initial.st_size == 0, "new file custody")
        offset = 0
        while offset < len(raw):
            self._boundary()
            self._io(fd)
            count = os.write(fd, raw[offset:])
            _uint(count, 1, len(raw) - offset)
            offset += count
        self._io(fd)
        os.fsync(fd)
        self._boundary()
        self._io(self.source_fd)
        os.fsync(self.source_fd)
        identity = _identity(os.fstat(fd))
        _require(identity[5] == 1 and identity[6] == len(raw), "published file size/links")
        self._readback(name, fd, identity, raw)
        next(row for row in self.resources if row["fd"] == fd)["sealed"] = (name, identity)
        return name, fd, identity, raw

    def _completion(self, value, key):
        raw = _canonical(value) + b"\n"
        _require(len(raw) <= min(2048, _uint(os.fpathconf(8, "PC_PIPE_BUF"), 1)), "completion atomic bound")
        self._boundary()
        self.observed[key] = raw
        if key == "completion_raw":
            self.observed["completion_attempted"] = True
        self._io(8)
        _require(os.write(8, raw) == len(raw), "ambiguous completion write")
        self._boundary()

    def _checkpoint(self, phase, trigger_raw, trigger, received, request, challenge, ordinal):
        self.active = True
        self.deadline = trigger["deadline_ns"]
        self.observed.update(sequence_before=self.sequence, sequence_after=self.sequence + 1,
                             offset_before=self.offset, records_before=self.records,
                             publication_attempted=False, completion_attempted=False)
        while True:
            events = self._poll()
            _require(3 not in events and 5 not in events, "concurrent checkpoint control")
            entry = self._telemetry()
            if entry is not None:
                if self.parsed == len(self.batch):
                    self.reads.append(entry)
                    break
                self._wait()
        drained = self._boundary()
        raw_started = self._tick()
        batch = self.batch
        rows = [self._publish(f"batch-{self.inventory['session_id']}-{self.sequence + 1}.ndjson", batch)]
        raw_finished = self._boundary()
        manifest = dict(schema=_PREFIX + "-checkpoint/v1", provision_digest=self.arguments["expected_checkpoint_provision_digest"],
                        epoch_digest=self.arguments["expected_epoch_digest"], session_id=self.inventory["session_id"],
                        stream_digest=self.arguments["expected_stream_digest"], phase=phase, request_digest=request,
                        challenge_digest=challenge, trigger_digest=_digest(trigger_raw), previous_checkpoint_digest=self.previous,
                        sequence_before=self.sequence, sequence_after=self.sequence + 1, offset_before=self.offset,
                        offset_after=self.offset + len(batch), records_before=self.records, records_after=self.records + self.batch_records,
                        clock=self.inventory["clock"], trigger_received_ns=received, reads=list(self.reads), drain_finished_ns=drained,
                        raw_digest=_digest(batch), raw_bytes=len(batch), raw_records=self.batch_records, raw_publish_started_ns=raw_started,
                        raw_readback_finished_ns=raw_finished, manifest_prepared_ns=self._tick(),
                        loss_scope_digest=_digest(_canonical(self.epoch["loss_scope"])), loss_evidence_digest=None, upstream_loss_state="UNKNOWN")
        manifest_raw = _canonical(manifest)
        _require(len(manifest_raw) <= 16384, "manifest bound")
        self.observed["manifest_raw"] = manifest_raw
        manifest_started = self._tick()
        rows.append(self._publish(("challenge-" if phase == "CHALLENGE" else "refresh-") + _digest(trigger_raw)[7:] + ".json", manifest_raw))
        manifest_finished = self._boundary()
        receipt = dict(schema=_PREFIX + "-checkpoint-publication/v1", manifest_digest=_digest(manifest_raw),
                       raw_digest=_digest(batch), sequence_after=self.sequence + 1,
                       manifest_publish_started_ns=manifest_started, manifest_readback_finished_ns=manifest_finished,
                       receipt_prepared_ns=self._tick())
        receipt_raw = _canonical(receipt)
        _require(len(receipt_raw) <= 2048, "receipt bound")
        self.observed["publication_raw"] = receipt_raw
        rows.append(self._publish("receipt-" + _digest(manifest_raw)[7:] + ".json", receipt_raw))
        _require(len({row[2][:2] for row in rows}) == 3, "publication inode aliases")
        for row in rows:
            self._readback(*row)
        for row in reversed(rows):
            self._close(row[1])
        completed = self._boundary()
        self.sequence += 1
        self.offset, self.records, self.previous = manifest["offset_after"], manifest["records_after"], _digest(manifest_raw)
        self._completion(dict(schema=_PREFIX + "-checkpoint-ready/v1", session_id=self.inventory["session_id"],
                              epoch_digest=self.arguments["expected_epoch_digest"], phase=phase, ordinal=ordinal,
                              request_digest=request, challenge_digest=challenge, trigger_digest=_digest(trigger_raw),
                              sequence_after=self.sequence, manifest_digest=self.previous, publication_digest=_digest(receipt_raw),
                              batch_digest=_digest(batch), completed_ns=completed), "completion_raw")
        self.batch, self.reads, self.parsed, self.batch_records = b"", [], 0, 0
        return completed

    def _endpoint_open(self):
        parent = self.directories[0][1]
        for entry, name in zip(self.transport["directories"][1:], ("run", "aragorn-phase3-reader")):
            fd = self._own(os.open(name, _PATH | os.O_DIRECTORY, dir_fd=parent), "ENDPOINT_DIRECTORY")
            self.endpoint.append((entry, fd, parent, name))
            parent = fd
        fd = self._own(os.open("challenge.sock", _PATH, dir_fd=parent), "SOCKET_PATH")
        held = os.fstat(fd)
        reader = self.inventory["reader"]
        _require(held.st_mode == stat.S_IFSOCK | 0o660 and held.st_uid == 0 and held.st_gid == reader["gid"], "socket pathname custody")
        self.endpoint.append((dict(device=held.st_dev, inode=held.st_ino, mode=held.st_mode, uid=held.st_uid, gid=held.st_gid),
                              fd, parent, "challenge.sock"))

    def _ancillary(self, controls):
        credentials, forbidden, failures = [], False, []
        for level, kind, raw in controls:
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                forbidden = True
                for offset in range(0, len(raw) - len(raw) % 4, 4):
                    fd = struct.unpack_from("=i", raw, offset)[0]
                    if fd >= 0:
                        try:
                            self._own(fd, "UNEXPECTED_ANCILLARY")
                        except BaseException as exc:
                            failures.append(exc)
                        else:
                            try:
                                self._close(fd)
                            except BaseException as exc:
                                failures.append(exc)
            elif level == socket.SOL_SOCKET and kind == 2:
                credentials.append(raw)
            else:
                forbidden = True
        if failures:
            raise failures[0]
        expected = self.inventory["observer"]
        _require(not forbidden and credentials == [_UCREDS.pack(expected["pid"], 0, 0)], "challenge message credentials")

    def _connect(self, notice):
        self.deadline = notice["accept_deadline_ns"]
        if not self.endpoint:
            self._endpoint_open()
        self._boundary()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        self.socket, self.socket_fd = connection, connection.fileno()
        self._own(self.socket_fd, "CLIENT_SOCKET", connection)
        connection.setsockopt(socket.SOL_SOCKET, 16, 1)
        connection.setsockopt(socket.SOL_SOCKET, 76, 0)
        try:
            self._io(self.socket_fd)
            connection.connect(_SOCKET)
        except OSError as exc:
            _require(exc.errno == errno.EINPROGRESS, "one connect attempt failed")
            while True:
                events = self._wait(socket_event=select.POLLOUT)
                _require(not events.get(self.socket_fd, 0) & _ERRORS, "connect poll failed")
                if self.socket_fd in events:
                    _require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, "asynchronous connect failed")
                    break
                if 4 in events:
                    self._telemetry()
        self._boundary()
        self.peer_pidfd = self._own(connection.getsockopt(socket.SOL_SOCKET, 77), "SOCKET_PEER_PIDFD")
        _require(not os.get_inheritable(self.peer_pidfd), "peer PIDFD inherited")
        self._boundary()
        self.deadline = notice["request_deadline_ns"]
        while True:
            events = self._wait()
            _require(not events.get(self.socket_fd, 0) & _ERRORS, "challenge socket ended")
            if self.socket_fd in events:
                try:
                    self._io(self.socket_fd)
                    raw, controls, flags, _ = connection.recvmsg(4097, 4096, socket.MSG_DONTWAIT | 0x40000000)
                except BlockingIOError:
                    continue
                self.observed["challenge_raw"] = raw[:4096]
                self._ancillary(controls)
                received = self._tick()
                self._boundary()
                _require(not flags & ~(socket.MSG_EOR | 0x40000000), "challenge truncated/control flags")
                challenge = _keys(_document(raw, 4096), "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
                _nonce(challenge["nonce"])
                for key in ("issued_ns", "deadline_ns", "sequence_before"):
                    _uint(challenge[key])
                _require(challenge["epoch_digest"] == self.arguments["expected_epoch_digest"]
                         and challenge["request_digest"] == notice["request_digest"]
                         and challenge["boundary"] == "BEFORE_FIRST_EFFECT" and challenge["sequence_before"] == self.sequence
                         and notice["issued_ns"] <= challenge["issued_ns"] <= received < challenge["deadline_ns"]
                         == challenge["issued_ns"] + 100000000 <= notice["request_deadline_ns"], "challenge binding/budget differs")
                return raw, challenge, received
            if 4 in events:
                self._telemetry()

    def _notice(self, raw, notice):
        _keys(notice, "schema listener_epoch ordinal admission_digest epoch_digest request_digest sequence_before issued_ns accept_deadline_ns request_deadline_ns")
        _nonce(notice["listener_epoch"])
        for key in ("admission_digest", "epoch_digest", "request_digest"):
            _pin(notice[key])
        for key in ("ordinal", "sequence_before", "issued_ns", "accept_deadline_ns", "request_deadline_ns"):
            _uint(notice[key])
        now = self._boundary()
        _require(notice["schema"] == "aragorn/native-phase3-run-reader-connect-notice/v1"
                 and notice["epoch_digest"] == self.arguments["expected_epoch_digest"]
                 and notice["sequence_before"] == self.sequence and notice["ordinal"] == self.notice_ordinal + 1
                 and notice["ordinal"] <= self.loop["max_requests"] and notice["admission_digest"] not in self.seen
                 and (self.listener_epoch is None or self.listener_epoch == notice["listener_epoch"])
                 and notice["issued_ns"] <= self.frame_received_ns <= now < notice["accept_deadline_ns"]
                 and notice["accept_deadline_ns"] + 100000000 <= notice["request_deadline_ns"] <= self.loop["session_deadline_ns"], "notice binding/budget/replay")
        self.active = True
        self.notice_ordinal, self.listener_epoch = notice["ordinal"], notice["listener_epoch"]
        self.seen.add(notice["admission_digest"])
        self.observed.update(refresh_raw=None, completion_raw=None, ack_raw=None, ack_attempted=False,
                             manifest_raw=None, publication_raw=None, batch_raw=self.batch,
                             sequence_before=self.sequence, sequence_after=self.sequence + 1,
                             offset_before=self.offset, records_before=self.records,
                             publication_attempted=False, completion_attempted=False)
        challenge_raw, challenge, received = self._connect(notice)
        completed = self._checkpoint("CHALLENGE", challenge_raw, challenge, received, notice["request_digest"], _digest(challenge_raw), notice["ordinal"])
        ack_ns = self._boundary()
        _require(completed <= ack_ns and ack_ns <= _MAX - 200000000, "ACK timing overflow")
        ack = _canonical(dict(schema="aragorn/native-phase3-run-reader-response/v1", epoch_digest=self.arguments["expected_epoch_digest"],
                              challenge_digest=_digest(challenge_raw), request_digest=notice["request_digest"], sequence_after=self.sequence, ack_ns=ack_ns))
        self.observed["ack_raw"], self.observed["ack_attempted"] = ack, True
        self._io(self.socket_fd)
        _require(self.socket.send(ack, socket.MSG_DONTWAIT | 0x4000) == len(ack), "ambiguous ACK send")
        self.waiting_close = True
        self._boundary()
        self.first = dict(request=notice["request_digest"], challenge=_digest(challenge_raw), ack=ack_ns,
                          deadline=notice["request_deadline_ns"], refreshed=False)
        self.deadline = min(notice["request_deadline_ns"], ack_ns + 200000000, self.loop["session_deadline_ns"])

    def _peer_close(self, events):
        flags = events.get(self.socket_fd, 0)
        _require(not flags & (select.POLLERR | select.POLLNVAL), "post-ACK socket error")
        if not flags:
            return
        try:
            self._io(self.socket_fd)
            raw, controls, received_flags, _ = self.socket.recvmsg(1, 4096, socket.MSG_DONTWAIT | 0x40000000)
        except BlockingIOError:
            _require(not flags & select.POLLHUP, "ambiguous peer close")
            return
        if controls:
            self._ancillary(controls)
        _require(raw == b"" and not controls and not received_flags & ~(socket.MSG_EOR | 0x40000000), "unsolicited post-ACK packet")
        self._boundary()
        self._close(self.socket_fd)
        self.socket = self.socket_fd = None
        self._close(self.peer_pidfd)
        self.peer_pidfd = None
        self._boundary()
        self.active = self.waiting_close = False
        self.deadline = self.loop["session_deadline_ns"]

    def _refresh(self, raw, command):
        _keys(command, "schema session_id ordinal epoch_digest request_digest challenge_digest reader_evidence_digest reader_summary_digest "
              "reader_connection_epoch previous_checkpoint_digest sequence_before second_request_digest issued_ns deadline_ns")
        for key in ("epoch_digest", "request_digest", "challenge_digest", "reader_evidence_digest", "reader_summary_digest",
                    "previous_checkpoint_digest", "second_request_digest"):
            _pin(command[key])
        _nonce(command["reader_connection_epoch"])
        for key in ("ordinal", "sequence_before", "issued_ns", "deadline_ns"):
            _uint(command[key])
        now = self._boundary()
        first = self.first
        _require(first is not None and not first["refreshed"] and command["schema"] == _PREFIX + "-checkpoint-refresh/v1"
                 and command["session_id"] == self.inventory["session_id"] and command["epoch_digest"] == self.arguments["expected_epoch_digest"]
                 and command["ordinal"] == self.refresh_ordinal + 1 and command["request_digest"] == first["request"]
                 and command["challenge_digest"] == first["challenge"] and command["previous_checkpoint_digest"] == self.previous
                 and command["sequence_before"] == self.sequence and first["ack"] <= command["issued_ns"] <= self.frame_received_ns <= now
                 < command["deadline_ns"] <= min(first["deadline"], first["ack"] + 200000000, self.loop["session_deadline_ns"]),
                 "refresh binding/budget/replay")
        self.refresh_ordinal, first["refreshed"] = command["ordinal"], True
        self.observed.update(manifest_raw=None, publication_raw=None, completion_raw=None, batch_raw=self.batch,
                             sequence_before=self.sequence, sequence_after=self.sequence + 1,
                             offset_before=self.offset, records_before=self.records,
                             publication_attempted=False, completion_attempted=False)
        self._checkpoint("REFRESH", raw, command, self.frame_received_ns, first["request"], first["challenge"], command["ordinal"])
        self.active = False
        self.deadline = self.loop["session_deadline_ns"]

    def run(self, arguments):
        self.arguments = arguments
        # Receive all transferred ownership before validating any supplied bytes.
        supplied = [(fd, "PIPE") for fd in range(3, 9)] + [(arguments[role + "_pidfd"], "PIDFD") for role in ("observer", "bridge", "supervisor")]
        for fd, role in supplied:
            if type(fd) is int and 3 <= fd <= 2**31 - 1 and all(row["fd"] != fd for row in self.resources):
                self.resources.append(dict(fd=fd, role=role, object=None, identity=None, pid=None))
        errors = []
        for row in self.resources:
            try:
                row["identity"] = _identity(os.fstat(row["fd"]))[:5]
                if "PIDFD" in row["role"]:
                    row["pid"] = self._association(row["fd"])
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise errors[0]
        _require(len(self.resources) == 9 and all(type(arguments[role + "_pidfd"]) is int
                 and arguments[role + "_pidfd"] >= 9 for role in ("observer", "bridge", "supervisor")), "transferred descriptor inventory")
        values = _inputs(arguments)
        self.epoch, self.provision, self.transport, self.inventory, self.loop = (values[key] for key in (
            "epoch", "checkpoint_provision", "transport_provision", "stream_inventory", "loop_provision"))
        self.pidfds = {role: arguments[role + "_pidfd"] for role in ("observer", "bridge", "supervisor")}
        self.observed.update(session_id=self.inventory["session_id"], sequence_before=0, sequence_after=0,
                             offset_before=0, records_before=0, batch_raw=b"")
        self.deadline = self.loop["startup_deadline_ns"]
        self._local()
        for row in self.resources:
            _require(not os.get_inheritable(row["fd"]), "transferred handle inheritable")
        self.namespace = self._own(os.open(f"/proc/{_PID}/ns/time", os.O_RDONLY | os.O_CLOEXEC), "TIME_NAMESPACE")
        parent = None
        for entry, name in zip(self.provision["directories"][:4], ("/", "var", "lib", "aragorn-phase3-reader-events")):
            fd = self._own(os.open(name, _DIR, dir_fd=parent), "SOURCE_DIRECTORY")
            self.directories.append((entry, fd, parent, name))
            parent = fd
        self.source_fd = parent
        ready = self._boundary()
        self._completion(dict(schema=_PREFIX + "-loop-ready/v1", session_id=self.inventory["session_id"],
                              epoch_digest=arguments["expected_epoch_digest"], loop_provision_digest=arguments["expected_loop_provision_digest"],
                              stream_digest=arguments["expected_stream_digest"], ready_ns=ready), "startup_ready_raw")
        self.deadline = self.loop["session_deadline_ns"]
        while True:
            events = self._wait(allow_control=True)
            if self.waiting_close:
                self._peer_close(events)
                if self.waiting_close:
                    if 4 in events:
                        self._telemetry()
                    continue
            _require(not (3 in events and 5 in events), "concurrent control operations")
            if 3 in events:
                raw, notice = self._frame(3, "notice_raw")
                self._notice(raw, notice)
            elif 5 in events:
                raw, command = self._frame(5, "refresh_raw")
                self._refresh(raw, command)
            elif 4 in events:
                self._telemetry()


def run_reader_checkpoint_loop(*, epoch_raw, expected_epoch_digest,
                               checkpoint_provision_raw, expected_checkpoint_provision_digest,
                               transport_provision_raw, expected_transport_provision_digest,
                               stream_inventory_raw, expected_stream_digest,
                               loop_provision_raw, expected_loop_provision_digest,
                               observer_pidfd, bridge_pidfd, supervisor_pidfd):
    """Own fixed FDs3..8 and three transferred PIDFDs until terminal return/refusal."""
    global _STARTED
    owner, original, reason = _Reader(), None, None
    if sys.platform != "linux" or os.getpid() != _PID or threading.get_native_id() != _PID:
        # A foreign caller cannot receive or close the original owner's handles.
        # Check before the lock as a fork could inherit another thread's lock.
        raise ReaderCheckpointLoopError(ValueError("original Linux main process required"), owner)
    with _LOCK:
        if _STARTED:
            raise ReaderCheckpointLoopError(ValueError("reader process already consumed"), owner)
        _STARTED = True
    try:
        owner.run(dict(epoch_raw=epoch_raw, expected_epoch_digest=expected_epoch_digest,
                       checkpoint_provision_raw=checkpoint_provision_raw, expected_checkpoint_provision_digest=expected_checkpoint_provision_digest,
                       transport_provision_raw=transport_provision_raw, expected_transport_provision_digest=expected_transport_provision_digest,
                       stream_inventory_raw=stream_inventory_raw, expected_stream_digest=expected_stream_digest,
                       loop_provision_raw=loop_provision_raw, expected_loop_provision_digest=expected_loop_provision_digest,
                       observer_pidfd=observer_pidfd, bridge_pidfd=bridge_pidfd, supervisor_pidfd=supervisor_pidfd))
    except _Terminal as exc:
        reason = str(exc)
    except BaseException as exc:
        original = exc
    finally:
        owner._close_all()
    if original is not None or owner.cleanup:
        raise ReaderCheckpointLoopError(original or owner.cleanup[0], owner) from (original or owner.cleanup[0])
    try:
        finished = owner._tick()
        owner._local()
        raw = _canonical(dict(schema=_PREFIX + "-loop-terminal/v1", session_id=owner.inventory["session_id"],
                              reason=reason, sequence_after=owner.sequence, manifest_digest=owner.previous, finished_ns=finished,
                              stream_continuity="UNKNOWN", loss_completeness="UNKNOWN", **_FLAGS))
        _require(reason in ("CANCELLED", "OWNER_CLOSED") and len(raw) <= 2048, "terminal result differs")
        return dict(terminal_raw=raw, observed=dict(owner.observed))
    except BaseException as exc:
        raise ReaderCheckpointLoopError(exc, owner) from exc
