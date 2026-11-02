"""Guard one fixed reader listener, atomic notice and owning acquisition transfer.

Launcher/loop/custody replay and external cancellation remain separate. A retained
transport record grants no health, effect or deployment authority.
"""

import base64
import fcntl
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import threading

from . import native_phase3_run_reader_acquisition as acquisition
from . import native_phase3_run_reader_response as leaf


_PATH = "/run/aragorn-phase3-reader/challenge.sock"
_NAME = "challenge.sock"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PATH_FLAGS = getattr(os, "O_PATH", 0x200000) | os.O_NOFOLLOW | os.O_CLOEXEC
_SOCKET_FLAGS = socket.SOCK_SEQPACKET | getattr(socket, "SOCK_NONBLOCK", 0x800) | getattr(socket, "SOCK_CLOEXEC", 0x80000)
_FIELDS = """schema operation status listener_epoch provision_digest epoch_digest
admission_digest request_digest ordinal sequence_before notice_base64
started_ns finished_ns snapshots peer_credentials_base64 accepted_ns
transfer_started_ns transfer_finished_ns owned_evidence_digest challenge_digest
connection_epoch reader_digest descriptor_cleanup failure_type
cleanup_failure_types cleanup_failure_types_complete listener_reusable
acquisition_authenticity_verified sensor_health_verified effect_authorized
run_qualified phase3_qualified request_timing_verified""".split()
_FLAGS = _FIELDS[-6:]
_MAX = 131072
_RESERVE = 8192


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _identity(info, *, path=None, links=False):
    value = dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode,
                 uid=info.st_uid, gid=info.st_gid)
    if path is not None:
        value = {"path": path, **value}
    if links:
        value["nlink"] = info.st_nlink
    for key, number in value.items():
        if key != "path":
            leaf._uint(number, 1 if key == "inode" else 0)
    return value


def _same(actual, expected):
    _require(leaf._canonical(actual) == leaf._canonical(expected), "held/named identity mismatch")


def _encode_bytes(raw):
    return base64.b64encode(raw).decode("ascii")


class ReaderTransportError(ValueError):
    """No usable reader on refusal; original errors and bounded observations survive."""

    def __init__(self, original, partial_evidence, cleanup_failures=(),
                 owned_observed=None, unaccepted_reader_raw=None):
        super().__init__("reader transport refused; preserve notice, socket residue and evidence")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup_failures)
        self.partial_evidence = partial_evidence
        self.owned_observed = owned_observed
        self.unaccepted_reader_raw = unaccepted_reader_raw


class ReaderListener:
    def __init__(self, *, provision_raw, expected_provision_digest, epoch_raw,
                 expected_epoch_digest, notice_write_fd, reader_pidfd):
        self._resources = []
        self._unreleased_sockets = []
        self._lock = threading.Lock()
        self._pid = self._tid = None
        self._last_tick = -1
        self._closed = False
        self._state = "OPENING"
        self._active = None
        self._seen = set()
        self._ordinal = self._last_sequence = 0
        self._listener_epoch = self._provision_digest = self._epoch_digest = None
        self._socket = self._path_fd = None
        self._directories = []
        self._namespaces = {}
        self._owned_observed = None
        self.opening_evidence_raw = self.last_evidence_raw = None
        self._new_evidence("OPEN")
        # Receive ownership before any metadata read; invalid integers are not FDs.
        for fd, role in ((notice_write_fd, "NOTICE_WRITER"), (reader_pidfd, "READER_PIDFD")):
            if type(fd) is int and 3 <= fd < 2**63 and all(row["fd"] != fd for row in self._resources):
                self._resources.append(dict(fd=fd, role=role, obj=None, identity=None))
        try:
            metadata_errors = []
            for row in self._resources:
                try:
                    row["identity"] = self._resource_identity(row)
                except BaseException as exc:
                    metadata_errors.append(exc)
            if metadata_errors:
                raise metadata_errors[0]
            _require(type(notice_write_fd) is int and type(reader_pidfd) is int
                     and 3 <= notice_write_fd < 2**63 and 3 <= reader_pidfd < 2**63
                     and notice_write_fd != reader_pidfd, "transferred descriptors")
            self._writer, self._pidfd = notice_write_fd, reader_pidfd
            self._pid, self._tid = os.getpid(), threading.get_native_id()
            self._context()
            self._validate(provision_raw, expected_provision_digest, epoch_raw, expected_epoch_digest)
            for role, pid in (("observer", self._pid), ("reader", self._process["reader_pid"])):
                leaf.process.require_live_pidfd(self._pidfd)
                fd = os.open(f"/proc/{pid}/ns/time", os.O_RDONLY | os.O_CLOEXEC)
                self._own(fd, "NAMESPACE")
                self._namespaces[role] = (pid, fd)
            for index, entry in enumerate(self._provision["directories"]):
                fd = os.open("/", _DIR_FLAGS) if index == 0 else os.open(
                    "run" if index == 1 else "aragorn-phase3-reader", _DIR_FLAGS,
                    dir_fd=self._directories[-1][1])
                self._own(fd, "ANCESTOR")
                self._directories.append((entry, fd))
            self._e["started_ns"] = self._tick()
            self._guard("before", complete=False)
            _require(self._tick() < self._provision["session_deadline_ns"], "session expired")
            random = os.urandom(32)
            _require(type(random) is bytes and len(random) == 32, "listener entropy")
            self._listener_epoch = random.hex()
            self._e["listener_epoch"] = self._listener_epoch
            self._create_listener()
            self._guard("after")
            self._finish("READY", True, deadline=self._provision["session_deadline_ns"])
            self._state = "READY"
            self.opening_evidence_raw = self.last_evidence_raw
        except BaseException as exc:
            raise self._refusal(exc) from exc

    def _own(self, fd, role, obj=None):
        _require(type(fd) is int and 0 <= fd < 2**63
                 and all(row["fd"] != fd for row in self._resources), "owned descriptor collision")
        row = dict(fd=fd, role=role, obj=obj, identity=None)
        self._resources.append(row)
        row["identity"] = self._resource_identity(row)

    def _resource_identity(self, row, pidfd_raw=None):
        value = _identity(os.fstat(row["fd"]))
        if row["role"] == "NOTICE_WRITER":
            flags = fcntl.fcntl(row["fd"], fcntl.F_GETFL)
            leaf._uint(flags)
            value.update(descriptor_flags=flags, descriptor_noninheritable=not os.get_inheritable(row["fd"]))
        elif row["role"] == "READER_PIDFD":
            raw = pidfd_raw if pidfd_raw is not None else leaf.process._read_virtual_file(
                Path(f"/proc/self/fdinfo/{row['fd']}"), 4096)
            _require(type(raw) is bytes and len(raw) <= 4096, "PIDFD custody bytes")
            pids = [line.partition(":")[2].strip() for line in raw.decode("ascii").splitlines() if line.startswith("Pid:")]
            _require(len(pids) == 1 and (pids[0] == "-1" or pids[0].isdigit()), "PIDFD custody identity")
            pid = int(pids[0])
            _require(pid == -1 or 0 < pid < 2**63, "PIDFD custody PID")
            value["pidfd_pid"] = pid
        return value

    def _advance_path_pin(self):
        self._pathname_value()
        current = _identity(os.fstat(self._path_fd))
        _same(current, {key: self._path_identity[key] for key in current})
        row = next(row for row in self._resources if row["fd"] == self._path_fd)
        row["identity"] = current

    def _context(self):
        _require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("=iII") == 12, "Linux credential ABI")
        _require(os.getpid() == self._pid == self._tid == threading.get_native_id(), "original main process/thread")
        _require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "root identity")

    def _validate(self, provision_raw, provision_pin, epoch_raw, epoch_pin):
        leaf._pin(provision_pin)
        leaf._pin(epoch_pin)
        p = leaf._keys(leaf._decode(provision_raw, 8192), "schema epoch_digest observer directories notice_pipe session_deadline_ns max_requests access_inventory_digest")
        _require(leaf._raw_digest(provision_raw) == provision_pin
                 and p["schema"] == "aragorn/native-phase3-run-reader-transport-provision/v1"
                 and p["epoch_digest"] == epoch_pin, "protected provisioning pin")
        epoch = leaf._keys(leaf._decode(epoch_raw, 32768), "process clock loss_scope policy deployment_digest")
        _require(leaf._raw_digest(epoch_raw) == epoch_pin, "protected epoch pin")
        # Validate frozen inputs without issuing a real challenge or consuming entropy.
        policy = leaf._keys(epoch["policy"], "timeout_ns max_age_ns")
        duration = leaf._uint(policy["timeout_ns"], 1)
        challenge = dict(epoch_digest=epoch_pin, request_digest=epoch_pin, boundary="BEFORE_FIRST_EFFECT",
                         nonce="0" * 64, issued_ns=0, deadline_ns=duration, sequence_before=0)
        bindings = {"epoch": epoch_pin, "request": epoch_pin, "challenge": leaf._digest(challenge),
                    **{key: leaf._digest(epoch[key]) for key in ("process", "clock", "loss_scope", "policy")}}
        leaf._inputs(epoch_raw, leaf._canonical(challenge), bindings, "0" * 64)
        observer = leaf._keys(p["observer"], "pid start_time_ticks uid gid time_namespace")
        for key in ("pid", "start_time_ticks"):
            leaf._uint(observer[key], 1)
        for key in ("uid", "gid"):
            _require(leaf._uint(observer[key]) == 0, "observer account pin")
        ns = leaf._keys(observer["time_namespace"], "device inode")
        leaf._uint(ns["device"])
        leaf._uint(ns["inode"], 1)
        proc = epoch["process"]
        _require(observer["pid"] == self._pid != proc["reader_pid"]
                 and proc["reader_uid"] > 0 and proc["reader_gid"] > 0
                 and ns["inode"] == epoch["clock"]["time_namespace_inode"], "reader/observer pin")
        directories = p["directories"]
        _require(type(directories) is list and len(directories) == 3, "directory inventory")
        for index, path in enumerate(("/", "/run", "/run/aragorn-phase3-reader")):
            entry = leaf._keys(directories[index], "path device inode mode uid gid")
            _require(entry["path"] == path, "fixed directory path")
            for key in ("device", "inode", "mode", "uid", "gid"):
                leaf._uint(entry[key], 1 if key == "inode" else 0)
            _require(stat.S_ISDIR(entry["mode"]) and entry["uid"] == 0, "directory type/owner")
            if index < 2:
                _require(entry["gid"] == 0 and not entry["mode"] & 0o022, "ancestor permissions")
            else:
                _require(entry["gid"] == proc["reader_gid"] and entry["mode"] == stat.S_IFDIR | 0o710, "reader parent permissions")
        pipe = leaf._keys(p["notice_pipe"], "device inode mode uid gid reader_fd")
        for key in pipe:
            leaf._uint(pipe[key], 1 if key == "inode" else 0)
        _require(pipe["mode"] == stat.S_IFIFO | 0o600 and pipe["uid"] == pipe["gid"] == 0
                 and pipe["reader_fd"] == 3, "notice pipe ABI")
        leaf._uint(p["session_deadline_ns"], 1)
        _require(1 <= leaf._uint(p["max_requests"], 1) <= 4096, "request capacity")
        leaf._pin(p["access_inventory_digest"])
        self._provision, self._epoch, self._process = p, epoch, proc
        self._epoch_raw, self._epoch_digest, self._provision_digest = epoch_raw, epoch_pin, provision_pin
        self._e.update(epoch_digest=epoch_pin, provision_digest=provision_pin)

    def _tick(self):
        value = leaf.clock._stamp()
        _require(type(value) is int and self._last_tick <= value < 2**63 and value >= 0, "clock rollback/range")
        self._last_tick = value
        return value

    def _new_evidence(self, operation):
        self._raw_bytes = 0
        self._e = dict.fromkeys(_FIELDS)
        self._e.update(schema="aragorn/native-phase3-run-reader-transport-evidence/v1",
                       operation=operation, status="REFUSED", listener_epoch=self._listener_epoch,
                       provision_digest=self._provision_digest, epoch_digest=self._epoch_digest,
                       snapshots=[], descriptor_cleanup=[], cleanup_failure_types=[],
                       cleanup_failure_types_complete=True, listener_reusable=False)
        self._e.update({flag: False for flag in _FLAGS})
        if self._active is not None:
            for key in ("admission_digest", "request_digest", "ordinal", "sequence_before"):
                self._e[key] = self._active[key]
            self._e["notice_base64"] = _encode_bytes(self._active["raw"])
        self._owned_observed = None

    def _fill(self, target, key, value, raw_bytes=0):
        _require(self._raw_bytes + raw_bytes <= 65536, "raw snapshot budget")
        previous = target.get(key)
        target[key] = value
        try:
            _require(len(leaf._canonical(self._e)) <= _MAX - _RESERVE, "transport evidence budget")
        except BaseException:
            target[key] = previous
            raise
        self._raw_bytes += raw_bytes

    def _raw(self, target, key, raw, maximum):
        _require(type(raw) is bytes and len(raw) <= maximum, "bounded raw observation")
        self._fill(target, key, _encode_bytes(raw), len(raw))

    def _observe(self, name, value, observe):
        _require(len(self._e["snapshots"]) < 32, "snapshot inventory bound")
        record = dict(name=name, started_ns=self._tick(), finished_ns=None, value=value)
        self._fill(self._e, "snapshots", self._e["snapshots"] + [record])
        try:
            observe(value)
        except BaseException:
            try:
                self._fill(record, "finished_ns", self._tick())
            except BaseException:
                pass
            raise
        self._fill(record, "finished_ns", self._tick())
        return value

    def _process_snapshot(self, role, edge):
        pid, nsfd = self._namespaces[role]
        value = dict.fromkeys("stat_before_base64 status_base64 stat_after_base64 boot_base64 time_namespace".split())
        if role == "reader":
            value["pidfd_info_base64"] = None

        def observe(out):
            leaf.process.require_live_pidfd(self._pidfd)
            if role == "reader":
                raw = leaf.process._read_virtual_file(Path(f"/proc/self/fdinfo/{self._pidfd}"), 4096)
                self._raw(out, "pidfd_info_base64", raw, 4096)
                _require([line.partition(":")[2].strip() for line in raw.decode("ascii").splitlines()
                          if line.startswith("Pid:")] == [str(pid)], "reader PIDFD binding")
            raws = []
            for name, filename in (("stat_before", "stat"), ("status", "status"), ("stat_after", "stat")):
                leaf.process.require_live_pidfd(self._pidfd)
                raw = leaf.process._read_virtual_file(Path(f"/proc/{pid}/{filename}"), 16384)
                self._raw(out, name + "_base64", raw, 16384)
                leaf.process.require_live_pidfd(self._pidfd)
                raws.append(raw)
            boot = leaf.process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64)
            self._raw(out, "boot_base64", boot, 64)
            _require(boot == (self._epoch["clock"]["boot_id"] + "\n").encode("ascii"), "boot changed")
            namespace = leaf.clock._namespace(pid, nsfd)
            self._fill(out, "time_namespace", namespace)
            _same(namespace, self._provision["observer"]["time_namespace"])
            actual = leaf._proc_record(pid, *raws, restricted=role == "reader")
            if role == "reader":
                expected = dict(pid=pid, start_time_ticks=self._process["reader_start_ticks"],
                                uid=self._process["reader_uid"], gid=self._process["reader_gid"])
            else:
                expected = {key: self._provision["observer"][key] for key in ("pid", "start_time_ticks", "uid", "gid")}
                _require([line.partition(":")[2].strip() for line in raws[1].decode("ascii").splitlines()
                          if line.startswith("Umask:")] == ["0077"], "protected observer umask")
            _same(actual, expected)
            leaf.process.require_live_pidfd(self._pidfd)
        self._observe(role + "_" + edge, value, observe)

    def _directory_values(self):
        values = []
        for index, (entry, fd) in enumerate(self._directories):
            held = _identity(os.fstat(fd), path=entry["path"])
            named = os.stat("/", follow_symlinks=False) if index == 0 else os.stat(
                "run" if index == 1 else "aragorn-phase3-reader",
                dir_fd=self._directories[index - 1][1], follow_symlinks=False)
            _same(held, entry)
            _same(_identity(named, path=entry["path"]), entry)
            values.append(held)
        return values

    def _directory_snapshot(self, edge):
        def observe(_unused):
            record = self._e["snapshots"][-1]
            values = []
            for index, (entry, fd) in enumerate(self._directories):
                held = _identity(os.fstat(fd), path=entry["path"])
                values.append(held)
                self._fill(record, "value", list(values))
                _same(held, entry)
                named = os.stat("/", follow_symlinks=False) if index == 0 else os.stat(
                    "run" if index == 1 else "aragorn-phase3-reader",
                    dir_fd=self._directories[index - 1][1], follow_symlinks=False)
                values[-1] = _identity(named, path=entry["path"])
                self._fill(record, "value", list(values))
                _same(values[-1], entry)
        self._observe("directories_" + edge, None, observe)

    def _pathname_value(self):
        held = _identity(os.fstat(self._path_fd), links=True)
        named = _identity(os.stat(_NAME, dir_fd=self._directories[-1][1], follow_symlinks=False), links=True)
        _same(held, self._path_identity)
        _same(named, self._path_identity)
        return held

    def _pathname_snapshot(self, edge):
        def observe(_unused):
            record = self._e["snapshots"][-1]
            held = _identity(os.fstat(self._path_fd), links=True)
            self._fill(record, "value", held)
            _same(held, self._path_identity)
            named = _identity(os.stat(_NAME, dir_fd=self._directories[-1][1], follow_symlinks=False), links=True)
            self._fill(record, "value", named)
            _same(named, self._path_identity)
        self._observe("pathname_" + edge, None, observe)

    def _socket_value(self, connection, path):
        _require(connection.family == socket.AF_UNIX
                 and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                 and connection.gettimeout() == 0 and not connection.get_inheritable(), "socket mode/type")
        passcred = connection.getsockopt(socket.SOL_SOCKET, leaf._PASSCRED)
        passpidfd = connection.getsockopt(socket.SOL_SOCKET, leaf._PASSPIDFD)
        _require(type(passcred) is int and type(passpidfd) is int
                 and passcred == 1 and passpidfd == 0, "socket credential options")
        info = os.fstat(connection.fileno())
        _require(stat.S_ISSOCK(info.st_mode), "socket descriptor type")
        _require(connection.getsockname() == path, "fixed socket name")
        return dict(device=info.st_dev, inode=info.st_ino, family=connection.family,
                    type=socket.SOCK_SEQPACKET, nonblocking=True, noninheritable=True,
                    passcred=passcred, passpidfd=passpidfd, path=path)

    def _listener_value(self):
        value = self._socket_value(self._socket, _PATH)
        _same([value["device"], value["inode"]], self._socket_identity)
        return value

    def _listener_snapshot(self, edge):
        self._observe("listener_" + edge, None,
                      lambda _unused: self._fill(self._e["snapshots"][-1], "value", self._listener_value()))

    def _pipe_snapshot(self, edge):
        value = dict.fromkeys("device inode mode uid gid writer_fd reader_fd writer_flags reader_flags writer_noninheritable writer_link reader_link".split())

        def observe(out):
            leaf.process.require_live_pidfd(self._pidfd)
            expected = {key: self._provision["notice_pipe"][key] for key in ("device", "inode", "mode", "uid", "gid")}
            actual = _identity(os.fstat(self._writer))
            self._fill(out, "writer_fd", self._writer)
            self._fill(out, "reader_fd", 3)
            for key, item in actual.items():
                self._fill(out, key, item)
            _same(actual, expected)
            flags = fcntl.fcntl(self._writer, fcntl.F_GETFL)
            self._fill(out, "writer_flags", flags)
            noninheritable = not os.get_inheritable(self._writer)
            self._fill(out, "writer_noninheritable", noninheritable)
            _require(type(flags) is int and flags & os.O_ACCMODE == os.O_WRONLY
                     and flags & os.O_NONBLOCK and noninheritable, "notice writer flags")
            for key, path in (("writer_link", f"/proc/self/fd/{self._writer}"),
                              ("reader_link", f"/proc/{self._process['reader_pid']}/fd/3")):
                link = os.readlink(path)
                _require(type(link) is str and len(link.encode("ascii")) <= 4096, "pipe link bound")
                self._fill(out, key, link, len(link))
                _require(link == f"pipe:[{expected['inode']}]", "anonymous pipe binding")
            _same(_identity(os.stat(f"/proc/{self._process['reader_pid']}/fd/3")), expected)
            raw = leaf.process._read_virtual_file(Path(f"/proc/{self._process['reader_pid']}/fdinfo/3"), 4096)
            values = [line.partition(":")[2].strip() for line in raw.decode("ascii").splitlines() if line.startswith("flags:")]
            _require(len(values) == 1 and values[0] and all(c in "01234567" for c in values[0]), "notice reader fdinfo")
            reader_flags = int(values[0], 8)
            leaf._uint(reader_flags)
            self._fill(out, "reader_flags", reader_flags)
            _require(reader_flags & os.O_ACCMODE == os.O_RDONLY and reader_flags & os.O_NONBLOCK
                     and reader_flags & os.O_CLOEXEC, "notice reader flags")
            # Close the pipe's metadata bracket after its blocking fdinfo read.
            _same(_identity(os.fstat(self._writer)), expected)
            _same(_identity(os.stat(f"/proc/{self._process['reader_pid']}/fd/3")), expected)
            _require(fcntl.fcntl(self._writer, fcntl.F_GETFL) == flags
                     and not os.get_inheritable(self._writer), "notice writer changed during read")
            _require(os.readlink(f"/proc/self/fd/{self._writer}") == out["writer_link"]
                     and os.readlink(f"/proc/{self._process['reader_pid']}/fd/3") == out["reader_link"], "pipe links changed during read")
            leaf.process.require_live_pidfd(self._pidfd)
        self._observe("notice_pipe_" + edge, value, observe)

    def _closing_guard(self, edge, complete, process_records, initial_pipe):
        # Finish all raw proc reads before the final held/named metadata checks.
        leaf.process.require_live_pidfd(self._pidfd)
        raw = leaf.process._read_virtual_file(Path(f"/proc/self/fdinfo/{self._pidfd}"), 4096)
        reader_record = process_records["reader"]
        previous = reader_record["value"]["pidfd_info_base64"]
        if type(raw) is not bytes or len(raw) > 4096 or _encode_bytes(raw) != previous:
            partial = dict.fromkeys(reader_record["value"])
            def changed(out):
                self._raw(out, "pidfd_info_base64", raw, 4096)
                raise ValueError("reader PIDFD readback changed during observations")
            self._observe("reader_" + edge, partial, changed)
        # This is the last raw proc read: no later sample may stale FD3 flags.
        self._pipe_snapshot(edge)
        final_pipe = self._e["snapshots"][-1]["value"]
        _same(final_pipe, initial_pipe)
        for role, (pid, fd) in self._namespaces.items():
            namespace = leaf.clock._namespace(pid, fd)
            record = process_records[role]
            self._fill(record["value"], "time_namespace", namespace)
            _same(namespace, self._provision["observer"]["time_namespace"])
            self._fill(record, "finished_ns", self._tick())
        self._directory_snapshot(edge)
        if complete:
            self._pathname_snapshot(edge)
            self._listener_snapshot(edge)
        for row in self._resources:
            _require(row["identity"] is not None, "missing held descriptor identity")
            _same(self._resource_identity(row, raw if row["role"] == "READER_PIDFD" else None), row["identity"])
        # PIDFD raw reads may also race pipe/name metadata; finish these joins last.
        _same(_identity(os.fstat(self._writer)), {key: final_pipe[key] for key in ("device", "inode", "mode", "uid", "gid")})
        _same(_identity(os.stat(f"/proc/{self._process['reader_pid']}/fd/3")),
              {key: final_pipe[key] for key in ("device", "inode", "mode", "uid", "gid")})
        _require(os.readlink(f"/proc/self/fd/{self._writer}") == final_pipe["writer_link"]
                 and os.readlink(f"/proc/{self._process['reader_pid']}/fd/3") == final_pipe["reader_link"], "closing pipe links")
        leaf.process.require_live_pidfd(self._pidfd)
        self._context()
        self._tick()

    def _guard(self, edge, complete=True):
        self._context()
        records = {}
        self._process_snapshot("observer", edge)
        records["observer"] = self._e["snapshots"][-1]
        self._process_snapshot("reader", edge)
        records["reader"] = self._e["snapshots"][-1]
        self._directory_snapshot(edge)
        if complete:
            self._pathname_snapshot(edge)
            self._listener_snapshot(edge)
        self._pipe_snapshot(edge)
        pipe = dict(self._e["snapshots"][-1]["value"])
        self._closing_guard(edge, complete, records, pipe)

    def _create_listener(self):
        parent = self._directories[-1][1]
        try:
            os.stat(_NAME, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("socket pathname already exists; preserve residue")
        connection = socket.socket(socket.AF_UNIX, _SOCKET_FLAGS)
        self._own(connection.fileno(), "LISTENER", connection)
        self._socket = connection
        connection.setblocking(False)
        connection.set_inheritable(False)
        connection.setsockopt(socket.SOL_SOCKET, leaf._PASSCRED, 1)
        connection.setsockopt(socket.SOL_SOCKET, leaf._PASSPIDFD, 0)
        initial = self._socket_value(connection, "")
        self._socket_identity = [initial["device"], initial["inode"]]
        self._directory_values()
        connection.bind(_PATH)
        self._directory_snapshot("after")
        info = os.stat(_NAME, dir_fd=parent, follow_symlinks=False)
        _require(info.st_mode == stat.S_IFSOCK | 0o700 and info.st_uid == info.st_gid == 0
                 and info.st_nlink == 1, "new socket pathname")
        self._path_identity = _identity(info, links=True)
        fd = os.open(_NAME, _PATH_FLAGS, dir_fd=parent)
        self._own(fd, "PATHNAME")
        self._path_fd = fd
        self._pathname_snapshot("before")
        self._directory_values()
        os.chown(_NAME, 0, self._process["reader_gid"], dir_fd=parent, follow_symlinks=False)
        self._path_identity = {**self._path_identity, "gid": self._process["reader_gid"]}
        self._pathname_snapshot("after")
        self._advance_path_pin()
        self._directory_values()
        self._pathname_snapshot("before")
        os.chmod(_NAME, 0o660, dir_fd=parent, follow_symlinks=False)
        self._path_identity = {**self._path_identity, "mode": stat.S_IFSOCK | 0o660}
        self._pathname_snapshot("after")
        self._advance_path_pin()
        self._directory_values()
        connection.listen(1)
        self._listener_value()

    def _no_queued(self):
        poller = select.poll()
        poller.register(self._socket.fileno(), select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        _require(not poller.poll(0), "unsolicited connection or listener error")

    def _cleanup(self):
        failures = []
        self._closed, self._state = True, "CLOSED"
        while self._resources:
            row = self._resources.pop()
            fd, role, obj = row["fd"], row["role"], row["obj"]
            try:
                if obj is not None:
                    detached = obj.detach()
                    _require(type(detached) is int and detached == fd, "detached descriptor custody")
                _require(row["identity"] is not None, "unknown descriptor identity; close skipped")
                _same(self._resource_identity(row), row["identity"])
            except BaseException as exc:
                failures.append(exc)
                if obj is not None:
                    self._unreleased_sockets.append(obj)
                continue
            try:
                os.close(fd)
                closed = True
            except BaseException as exc:
                failures.append(exc)
                closed = False
            self._e["descriptor_cleanup"].append(dict(fd=fd, role=role, closed=closed))
        self._e["cleanup_failure_types"] = [type(exc).__name__[:128] for exc in failures[:8]]
        self._e["cleanup_failure_types_complete"] = len(failures) <= 8
        return failures

    def _quarantine(self):
        observed = self._owned_observed
        raw = None
        if type(observed) is dict and observed.get("reader") is not None:
            try:
                candidate = leaf._canonical(observed["reader"])
                if len(candidate) <= 32768:
                    raw = candidate
            except BaseException:
                pass
            observed = {**observed, "reader": None}
        return observed, raw

    def _refusal(self, original, cleanup=()):
        failures = list(cleanup) + self._cleanup()
        self._e.update(status="REFUSED", listener_reusable=False, failure_type=type(original).__name__[:128],
                       cleanup_failure_types=[type(exc).__name__[:128] for exc in failures[:8]],
                       cleanup_failure_types_complete=len(failures) <= 8)
        try:
            self._e["finished_ns"] = self._tick()
        except BaseException:
            pass
        self.last_evidence_raw = leaf._canonical(self._e)
        observed, raw = self._quarantine()
        error = ReaderTransportError(original, self.last_evidence_raw, failures, observed, raw)
        # Keep uncertain objects alive for the supervising error/owner path.
        error._unreleased_sockets = tuple(self._unreleased_sockets)
        return error

    def _finish(self, status, reusable, deadline=None):
        finished = self._tick()
        if deadline is not None:
            _require(finished < deadline, "operation deadline expired")
        self._fill(self._e, "finished_ns", finished)
        self._e.update(status=status, listener_reusable=reusable)
        raw = leaf._canonical(self._e)
        _require(len(raw) <= _MAX, "terminal evidence bound")
        self.last_evidence_raw = raw
        return raw

    def _operation(self, operation, body):
        # Wrong-owner/reentrant calls never close descriptors underneath the owner.
        if os.getpid() != self._pid or threading.get_native_id() != self._tid or not self._lock.acquire(False):
            evidence = dict.fromkeys(_FIELDS)
            evidence.update(schema="aragorn/native-phase3-run-reader-transport-evidence/v1", operation=operation,
                            status="REFUSED", snapshots=[], descriptor_cleanup=[], failure_type="ValueError",
                            cleanup_failure_types=[], cleanup_failure_types_complete=True, listener_reusable=False)
            evidence.update({flag: False for flag in _FLAGS})
            raise ReaderTransportError(ValueError("original exclusive owner required"), leaf._canonical(evidence))
        try:
            self._new_evidence(operation)
            if self._closed:
                self._e["failure_type"] = "ValueError"
                self.last_evidence_raw = leaf._canonical(self._e)
                raise ReaderTransportError(ValueError("listener lifetime ended"), self.last_evidence_raw)
            try:
                self._context()
                self._e["started_ns"] = self._tick()
                return body()
            except BaseException as exc:
                if isinstance(exc, ReaderTransportError) and self._closed:
                    raise
                raise self._refusal(exc) from exc
        finally:
            self._lock.release()

    def begin_request(self, *, admission_digest, request_digest, sequence_before,
                      accept_deadline_ns, request_deadline_ns):
        def begin():
            _require(self._state == "READY", "request already outstanding")
            self._guard("before")
            self._no_queued()
            leaf._pin(admission_digest)
            leaf._pin(request_digest)
            baseline = leaf._uint(sequence_before)
            accept_deadline, request_deadline = leaf._uint(accept_deadline_ns), leaf._uint(request_deadline_ns)
            _require(admission_digest not in self._seen and self._ordinal < self._provision["max_requests"], "admission replay/capacity")
            _require(baseline >= self._last_sequence, "sequence baseline regressed")
            now = self._tick()
            _require(now < accept_deadline and accept_deadline + self._epoch["policy"]["timeout_ns"] <= request_deadline
                     <= self._provision["session_deadline_ns"], "request deadline budget")
            ordinal = self._ordinal + 1
            notice = dict(schema="aragorn/native-phase3-run-reader-connect-notice/v1",
                          listener_epoch=self._listener_epoch, ordinal=ordinal, admission_digest=admission_digest,
                          epoch_digest=self._epoch_digest, request_digest=request_digest, sequence_before=baseline,
                          issued_ns=now, accept_deadline_ns=accept_deadline, request_deadline_ns=request_deadline)
            raw = leaf._canonical(notice) + b"\n"
            pipe_buf = os.fpathconf(self._writer, "PC_PIPE_BUF")
            _require(type(pipe_buf) is int and len(raw) <= min(2048, pipe_buf), "atomic notice bound")
            self._seen.add(admission_digest)
            self._ordinal = ordinal
            self._active = {**notice, "raw": raw}
            for key in ("admission_digest", "request_digest", "ordinal", "sequence_before"):
                self._e[key] = notice[key]
            self._fill(self._e, "notice_base64", _encode_bytes(raw))
            _require(self._tick() < accept_deadline, "notice deadline expired")
            written = os.write(self._writer, raw)
            _require(type(written) is int and written == len(raw), "short/ambiguous notice write")
            self._guard("after")
            self._finish("NOTIFIED", False, deadline=accept_deadline)
            self._state = "NOTIFIED"
            return raw
        return self._operation("BEGIN", begin)

    def _wait_accept(self):
        poller = select.poll()
        poller.register(self._socket.fileno(), select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        poller.register(self._pidfd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        while True:
            self._context()
            leaf.process.require_live_pidfd(self._pidfd)
            self._directory_values()
            self._pathname_value()
            self._listener_value()
            remaining = self._active["accept_deadline_ns"] - self._tick()
            _require(remaining > 0, "accept deadline expired")
            try:
                events = poller.poll(min((remaining + 999999) // 1000000, 2**31 - 1))
            except InterruptedError:
                continue
            leaf.process.require_live_pidfd(self._pidfd)
            for fd, flags in events:
                _require(fd == self._socket.fileno() and flags == select.POLLIN, "reader exit/listener poll error")
            if events:
                try:
                    connection, _address = self._socket.accept()
                except (BlockingIOError, InterruptedError):
                    continue
                self._own(connection.fileno(), "ACCEPTED_BEFORE_TRANSFER", connection)
                self._e["accepted_ns"] = self._tick()
                _require(self._e["accepted_ns"] < self._active["accept_deadline_ns"], "accepted late")
                return connection

    def _owned_result(self, owned):
        _require(type(owned) is dict, "owning acquisition result")
        self._owned_observed = owned
        challenge_raw = owned["challenge_raw"]
        epoch, challenge = leaf._inputs(self._epoch_raw, challenge_raw, owned["bindings"], owned["connection_epoch"])
        _require(owned["bindings"]["request"] == self._active["request_digest"]
                 and challenge["sequence_before"] == self._active["sequence_before"]
                 and self._e["transfer_started_ns"] <= challenge["issued_ns"] <= self._e["transfer_finished_ns"]
                 and challenge["deadline_ns"] <= self._active["request_deadline_ns"], "actual issued challenge budget/binding")
        _require(type(owned["evidence_raw"]) is bytes and len(owned["evidence_raw"]) <= 131072
                 and leaf._raw_digest(owned["evidence_raw"]) == owned["evidence_digest"], "owned evidence digest")
        for key in ("sensor_health_verified", "acquisition_authenticity_verified", "effect_authorized", "run_qualified", "phase3_qualified"):
            _require(owned[key] is False, "unsupported owned authority")
        reader = leaf._keys(owned["reader"], "epoch_digest challenge_digest request_digest process_before process_after clock_before clock_after peer status sequence_after ack_ns received_ns")
        for role in ("epoch", "challenge", "request"):
            _require(reader[role + "_digest"] == owned["bindings"][role], "reader binding")
        for role in ("process", "clock"):
            for edge in ("before", "after"):
                _same(reader[role + "_" + edge], epoch[role])
        _same(reader["peer"], dict(pid=self._process["reader_pid"], uid=self._process["reader_uid"], gid=self._process["reader_gid"]))
        sequence = leaf._uint(reader["sequence_after"])
        if reader["status"] == "ACK":
            _require(sequence > self._active["sequence_before"]
                     and challenge["issued_ns"] <= leaf._uint(reader["ack_ns"]) <= leaf._uint(reader["received_ns"]) < challenge["deadline_ns"], "ACK result")
        else:
            _require(reader["status"] == "TIMEOUT" and sequence == self._active["sequence_before"]
                     and reader["ack_ns"] is None and reader["received_ns"] is None, "TIMEOUT result")
        self._e.update(owned_evidence_digest=owned["evidence_digest"], challenge_digest=owned["bindings"]["challenge"],
                       connection_epoch=owned["connection_epoch"], reader_digest=leaf._raw_digest(leaf._canonical(reader)))
        return reader

    def accept_request(self, notice_raw):
        def accept():
            _require(self._state == "NOTIFIED" and type(notice_raw) is bytes
                     and notice_raw == self._active["raw"], "outstanding notice bytes")
            self._guard("before")
            connection = self._wait_accept()
            connection.setblocking(False)
            connection.set_inheritable(False)
            peer = leaf._peer(connection, self._process)
            self._raw(self._e, "peer_credentials_base64", peer, 12)
            leaf._unread(connection)
            self._guard("after")
            started = self._tick()
            _require(started + self._epoch["policy"]["timeout_ns"] <= self._active["request_deadline_ns"], "transfer response budget")
            self._e["transfer_started_ns"] = started
            self._state = "TRANSFERRING"
            # From call entry the frozen owning function alone closes this socket.
            self._resources = [row for row in self._resources if row["obj"] is not connection]
            try:
                owned = acquisition.acquire_owned_reader_response(
                    connection, epoch_raw=self._epoch_raw, expected_epoch_digest=self._epoch_digest,
                    request_digest=self._active["request_digest"], sequence_before=self._active["sequence_before"])
            except acquisition.OwnedReaderResponseError as exc:
                self._owned_observed = exc.observed
                raise
            self._owned_observed = owned
            self._e["transfer_finished_ns"] = self._tick()
            reader = self._owned_result(owned)
            self._guard("after")
            reusable = reader["status"] == "ACK"
            if not reusable:
                failures = self._cleanup()
                if failures:
                    raise self._refusal(failures[0], failures)
            raw = self._finish(reader["status"], reusable)
            if reusable:
                self._last_sequence = reader["sequence_after"]
                self._active, self._state = None, "READY"
            return dict(owned=owned, transport_raw=raw, transport_digest=leaf._raw_digest(raw), listener_reusable=reusable)
        return self._operation("ACCEPT", accept)

    def cancel_request(self, notice_raw):
        def cancel():
            _require(self._state == "NOTIFIED" and type(notice_raw) is bytes
                     and notice_raw == self._active["raw"], "outstanding cancellation notice")
            self._guard("before")
            failures = self._cleanup()
            if failures:
                raise self._refusal(failures[0], failures)
            return self._finish("CANCELLED", False)
        return self._operation("CANCEL", cancel)

    def close(self):
        def close():
            self._guard("before")
            failures = self._cleanup()
            if failures:
                raise self._refusal(failures[0], failures)
            return self._finish("CLOSED", False)
        return self._operation("CLOSE", close)
