"""Finite, fixed broker/Root descriptor bootstrap; no launch or effect authority.

The protected caller supplies unit/source provenance. This leaf retains its own
actual observations, including partial packets, and never queries systemd or
opens credential paths supplied by a packet. No production reset/retry API.
"""

import array
import base64
from copy import deepcopy
import errno
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


_PREFIX = "aragorn/native-phase3-broker-reader-bootstrap-"
_ENDPOINT = "/run/aragorn-phase3-broker-reader/bootstrap.sock"
_PARENT = "/run/aragorn-phase3-broker-reader"
_GUARD = _PARENT + "/guard.sock"
_DIRS = ("/", "/run", _PARENT, "/var", "/var/lib", "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-action/control")
_REPORT = "sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9"
_LIMITATIONS = ["NO_HEALTH_OR_EFFECT_AUTHORITY", "NO_LOSS_COMPLETENESS", "NO_LOADED_SOURCE_ATTESTATION",
                "ROOT_CALLER_OWNS_UNIT_SOURCE_AND_LAUNCH_ACQUISITION", "CLIENT_ROOT_PROC_OBSERVATIONS_UNAVAILABLE", "NO_PHASE3_QUALIFICATION"]
_PACKET_KEYS = {
    "hello": "broker_nonce grant_digest measurement_binding_digest fixture_binding_digest deadline_ns",
    "handles": "hello_digest broker_nonce deadline_ns supervisor clock cancellation_pipe supervisor_pidfd",
    "received": "hello_digest handles_digest broker_nonce deadline_ns cancellation_fd supervisor_pidfd",
    "release": "hello_digest handles_digest received_digest broker_nonce deadline_ns provider_ready_digest provision provision_digest source_inventory source_inventory_digest",
}
_ATTEMPT = None
_ATTEMPT_LOCK = threading.Lock()
_UNRESOLVED_OWNER = None
_PIDFD_UNKNOWN = object()


class BrokerReaderBootstrapError(RuntimeError):
    def __init__(self, original_failure, cleanup_failures, observed, unresolved_owner):
        super().__init__("BROKER_READER_BOOTSTRAP_REFUSED")
        self.original_failure = original_failure
        self.cleanup_failures = cleanup_failures
        self.observed = observed
        self.unresolved_owner = unresolved_owner


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _uint(value, minimum=0, maximum=2**63):
    _require(type(value) is int and minimum <= value < maximum, "unsigned integer")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "digest")
    return value


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "duplicate field")
    return result


def _decode(raw, limit, pin=None):
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "byte bound")
    if pin is not None:
        _require(_digest(raw) == _pin(pin), "input pin")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    _require(_json(value) == raw, "noncanonical")
    return value


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "exact fields")
    return value


def _schema(raw, limit, suffix, names, pin=None):
    value = _keys(_decode(raw, limit, pin), "schema " + names)
    _require(value["schema"] == _PREFIX + suffix + "/v1", "schema")
    return value


def _process(value):
    _keys(value, "pid start_time_ticks uid gid")
    _uint(value["pid"], 1, 2**31)
    _uint(value["start_time_ticks"], 1)
    for name in ("uid", "gid"):
        _uint(value[name], 0, 2**32)
    return value


def _namespace(value):
    _keys(value, "device inode")
    _uint(value["device"])
    _uint(value["inode"], 1)
    return value


def _clock(value):
    _keys(value, "boot_id clock_id time_namespace")
    _require(value["clock_id"] == "CLOCK_BOOTTIME" and type(value["boot_id"]) is str
             and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "clock")
    _namespace(value["time_namespace"])
    return value


def _metadata(value):
    _keys(value, "device inode mode uid gid")
    for name in value:
        _uint(value[name], 1 if name == "inode" else 0, 2**32 if name in ("uid", "gid") else 2**63)
    _require(stat.S_IFMT(value["mode"]) != 0, "metadata type")
    return value


def _meta(info):
    return _metadata(dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode, uid=info.st_uid, gid=info.st_gid))


def _pipe(value):
    _metadata(value)
    _require(value["mode"] == stat.S_IFIFO | 0o600 and value["uid"] == value["gid"] == 0, "root pipe")
    return value


def _path(value):
    _require(type(value) is str and value.isascii() and 0 < len(value) <= 4096 and value.startswith("/")
             and "\0" not in value and (value == "/" or all(p not in ("", ".", "..") for p in value[1:].split("/"))), "absolute path")
    return value


def _packet(raw, name):
    value = _schema(raw, 131072 if name == "release" else 4096, name, _PACKET_KEYS[name])
    _require(type(value["broker_nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["broker_nonce"]), "nonce")
    _uint(value["deadline_ns"], 1)
    for key in value:
        if key.endswith("_digest"):
            _pin(value[key])
    return value


def _inventory(raw, pin):
    value = _keys(_decode(raw, 65536, pin), "schema predecessor_report_digest entries")
    _require(value["schema"] == "aragorn/native-phase3-broker-reader-installed-sources/v1" and value["predecessor_report_digest"] == _REPORT, "source inventory")
    rows = value["entries"]
    _require(type(rows) is list and 1 <= len(rows) <= 128, "source count")
    previous, total = "", 0
    for row in rows:
        _keys(row, "path role bytes digest device inode mode uid gid")
        path = _path(row["path"])
        _require(path > previous and row["role"] in ("BROKER", "PROVIDER", "SHARED"), "source order/role")
        previous = path
        total += _uint(row["bytes"], 1, 16777217)
        _pin(row["digest"])
        meta = _metadata({k: row[k] for k in ("device", "inode", "mode", "uid", "gid")})
        _require(stat.S_ISREG(meta["mode"]) and meta["uid"] == 0 and not meta["mode"] & 0o022, "source protection")
    _require(total <= 67108864, "aggregate source bound")
    return value


def _provision(raw, pin):
    names = "schema profile broker provider supervisor clock epoch_digest deployment_digest grant_digest measurement_binding_digest fixture_binding_digest source_inventory_digest access_inventory_digest reader_session directories cancellation_pipe session_deadline_ns accept_deadline_ns"
    value = _keys(_decode(raw, 16384, pin), names)
    _require(value["schema"] == "aragorn/native-phase3-broker-reader-ipc-provision/v1" and value["profile"] == "HTTP_REFUSAL_ONLY", "refusal-only provision")
    for role in ("broker", "provider", "supervisor"):
        _process(value[role])
        _require((value[role]["uid"] > 0 and value[role]["gid"] > 0) if role == "broker" else value[role]["uid"] == value[role]["gid"] == 0, "process account")
    _require(len({value[r]["pid"] for r in ("broker", "provider", "supervisor")}) == 3, "distinct process")
    _clock(value["clock"])
    for key in value:
        if key.endswith("_digest"):
            _pin(value[key])
    session = _keys(value["reader_session"], "epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest loop_provision_digest")
    for pin_value in session.values():
        _pin(pin_value)
    _require(session["epoch_digest"] == value["epoch_digest"], "epoch")
    _require(_uint(value["accept_deadline_ns"], 1) < _uint(value["session_deadline_ns"], 1), "session deadline")
    rows = value["directories"]
    _require(type(rows) is list and len(rows) == 7, "directories")
    for index, (path, row) in enumerate(zip(_DIRS, rows)):
        _keys(row, "path device inode mode uid gid")
        _require(row["path"] == path, "directory order")
        meta = _metadata({k: row[k] for k in ("device", "inode", "mode", "uid", "gid")})
        _require(stat.S_ISDIR(meta["mode"]), "directory type")
        if index == 6:
            _require(meta["uid"] == value["broker"]["uid"] and meta["gid"] == value["broker"]["gid"] and stat.S_IMODE(meta["mode"]) == 0o700, "control directory")
        elif index == 2:
            _require(meta["uid"] == 0 and meta["gid"] == value["broker"]["gid"] and stat.S_IMODE(meta["mode"]) == 0o710, "endpoint directory")
        else:
            _require(meta["uid"] == 0 and not meta["mode"] & 0o022, "ancestor protection")
    pipe = _keys(value["cancellation_pipe"], "device inode mode uid gid writer readers")
    _pipe({k: pipe[k] for k in ("device", "inode", "mode", "uid", "gid")})
    writer = _keys(pipe["writer"], "process fd")
    _require(writer["process"] == "SUPERVISOR", "writer role")
    _uint(writer["fd"], 3)
    _require(type(pipe["readers"]) is list and len(pipe["readers"]) == 2, "reader count")
    for role, row in zip(("PROVIDER", "BROKER"), pipe["readers"]):
        _keys(row, "process fd")
        _require(row["process"] == role, "reader role")
        _uint(row["fd"], 3)
    return value


def _identity(raw_stat, raw_status):
    match = re.fullmatch(rb"([1-9][0-9]*) \(.*\) ([^\n]+)\n?", raw_stat)
    _require(match is not None, "proc stat")
    fields = match[2].split()
    _require(len(fields) >= 20 and fields[19].isdigit(), "start field")
    vectors = {}
    for key in (b"Uid", b"Gid"):
        lines = [line.split(b":", 1)[1].split() for line in raw_status.splitlines() if line.startswith(key + b":")]
        _require(len(lines) == 1 and len(lines[0]) == 4 and all(x.isdigit() for x in lines[0]), "account vector")
        nums = [int(x) for x in lines[0]]
        _require(len(set(nums)) == 1, "saved/fs accounts")
        vectors[key] = nums[0]
    return _process(dict(pid=int(match[1]), start_time_ticks=int(fields[19]), uid=vectors[b"Uid"], gid=vectors[b"Gid"]))


def _pid_association(raw):
    lines = [line[4:].strip() for line in raw.splitlines() if line.startswith(b"Pid:")]
    _require(len(lines) == 1 and lines[0].isdigit(), "PIDFD association")
    return _uint(int(lines[0]), 1, 2**31)


def _artifact(raw, limit):
    if raw is None:
        return None
    _require(type(raw) is bytes and len(raw) <= limit, "artifact bound")
    return dict(base64=base64.b64encode(raw).decode("ascii"), bytes=len(raw), digest=_digest(raw))


def _encoded(value):
    if type(value) is bytes:
        return _artifact(value, 16384)
    if type(value) is list:
        return [_encoded(v) for v in value]
    if type(value) is dict:
        return {k: _encoded(v) for k, v in value.items()}
    return value


class _Owner:
    def __init__(self, role, deadline):
        global _ATTEMPT
        acquired = _ATTEMPT_LOCK.acquire(blocking=False)
        try:
            if not acquired or _ATTEMPT is not None or _UNRESOLVED_OWNER is not None:
                observed = dict(hello_raw=None, handles_raw=None, received_raw=None, release_raw=None, provider_ready_raw=None,
                                observation_raw=None, send_attempted=False, bytes_sent=None, handle_observations=[], transport_observations=[])
                raise BrokerReaderBootstrapError(ValueError("bootstrap attempt consumed"), (), observed, _UNRESOLVED_OWNER)
            _ATTEMPT = self
        finally:
            if acquired:
                _ATTEMPT_LOCK.release()
        self.role, self.phase, self.state = role, "OPEN", "STARTING"
        self.entry = None
        self.entry_failure = None
        self.deadline = self.original_deadline = deadline
        self.started = self.finished = None
        self.resources, self.handles, self.snapshots, self.cleanup_failures = [], [], [], []
        self.objects = []
        self._file_row = None
        self._latest_socket_observation = None
        self.cleaning = False
        self.packets = dict.fromkeys(_PACKET_KEYS)
        self.ready_raw = None
        self.send_attempted = False
        self.bytes_sent = None
        self.sock = self.listener = self.peer_pidfd = self.cancel = None
        self.peer_creds = self.peer_process = self.self_process = self.clock = None
        self.directories, self.namespaces = [], {}
        self.endpoint_meta = self.endpoint_hold = None
        self.busy = False
        self.provision_raw = self.inventory_raw = None
        self._last_tick = -1
        try:
            self.entry = (os.getpid(), threading.get_native_id(), os.getresuid(), os.getresgid())
        except BaseException as exc:
            self.entry_failure = exc

    def owner_guard(self):
        _require(self.entry == (os.getpid(), threading.get_native_id(), os.getresuid(), os.getresgid()), "original owner")

    def tick(self, deadline=True):
        self.owner_guard()
        now = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(now >= self._last_tick, "clock reversal")
        self._last_tick = now
        if deadline and not self.cleaning:
            _require(now < self.deadline, "startup deadline")
        return now

    def initialize(self):
        if self.entry_failure is not None:
            raise self.entry_failure
        self.started = self.tick(False)
        _require(sys.platform == "linux" and sys.byteorder == "little" and struct.calcsize("P") == 8
                 and array.array("i").itemsize == 4 and struct.calcsize("=iII") == 12
                 and socket.MSG_DONTWAIT == 64 and socket.MSG_CMSG_CLOEXEC == 1073741824
                 and socket.MSG_NOSIGNAL == 16384 and socket.MSG_EOR == 128
                 and socket.AF_UNIX == socket.SCM_RIGHTS == 1 and socket.SCM_CREDENTIALS == 2 and socket.SOCK_SEQPACKET == 5
                 and socket.SO_PASSCRED == 16 and socket.SO_PEERCRED == 17
                 and getattr(socket, "SO_PASSPIDFD", 76) == 76 and getattr(socket, "SO_PEERPIDFD", 77) == 77
                 and os.O_NONBLOCK == 2048 and os.O_CLOEXEC == 524288 and os.O_PATH == 2097152
                 and fcntl.FD_CLOEXEC == 1 and errno.EAGAIN == errno.EWOULDBLOCK == 11, "Linux ABI")
        _require(self.started < _uint(self.deadline, 1) <= self.started + 4000000000 < 2**63, "original startup cap")
        uid, gid = self.entry[2][0], self.entry[3][0]
        _require(all(x == uid for x in self.entry[2]) and all(x == gid for x in self.entry[3]), "saved accounts")
        _require((uid == gid == 0) if self.role == "SERVER" else uid > 0 and gid > 0, "role accounts")
        _require(self.entry[0] == self.entry[1], "main thread")
        snap = self.snapshot("OPEN", "SELF")
        self.self_process = _identity(snap["stat_before_raw"], snap["status_raw"])
        _require(self.self_process["pid"] == self.entry[0] and self.self_process["uid"] == uid and self.self_process["gid"] == gid, "self identity")
        boot = snap["boot_raw"].decode("ascii").removesuffix("\n")
        self.clock = _clock(dict(boot_id=boot, clock_id="CLOCK_BOOTTIME", time_namespace=snap["namespaces"]["self"]["time"]["held"]))

    def adopt(self, fd, role, obj=None, installed=False, ephemeral=False, check_owner=True):
        _uint(fd, 0 if installed else 3)
        _require(not any(r["fd"] == fd and not r["consumed"] for r in self.resources), "owned descriptor alias")
        row = dict(fd=fd, role=role, process_role="SELF", metadata=None, flags=None, descriptor_flags=None,
                   link=None, pidfd_info_raw=None, closed=False)
        association = _PIDFD_UNKNOWN if role in ("PEER_PIDFD", "SUPERVISOR_TRANSFER", "PROVIDER_PIDFD") else None
        resource = dict(fd=fd, role=role, row=row, obj=obj, consumed=False, pid=association, ephemeral=ephemeral)
        self.resources.append(resource)  # Ownership precedes every fallible metadata read.
        if ephemeral:
            if self._file_row is not None and self._file_row["closed"]:
                self.handles.remove(self._file_row)
            self._file_row = row
        _require(len(self.handles) < 32, "handle observation cap")
        self.handles.append(row)
        if check_owner:
            self.owner_guard()
        return resource

    def adopt_ingress(self, pairs, installed=False):
        # Record the entire bounded ingress before an owner/metadata observation.
        # Syntax/alias errors are deferred until later valid numbers are retained.
        accepted, failures = [], []
        for fd, role in pairs:
            try:
                accepted.append(self.adopt(fd, role, installed=installed, check_owner=False))
            except ValueError as exc:
                failures.append(exc)
        if failures:
            raise failures[0]
        self.owner_guard()
        return accepted

    def pin_resource(self, resource):
        row, fd = resource["row"], resource["fd"]
        if row["metadata"] is not None:
            self.resource_guard(resource)
            return resource
        self.owner_guard()
        row["link"] = os.readlink(f"/proc/self/fd/{fd}")
        if row["link"] == "anon_inode:[pidfd]":
            resource["pid"] = _PIDFD_UNKNOWN
        _require(type(row["link"]) is str and row["link"].isascii() and len(row["link"]) <= 128, "descriptor link")
        row["metadata"] = _meta(os.fstat(fd))
        row["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        row["descriptor_flags"] = fcntl.fcntl(fd, fcntl.F_GETFD)
        _require(row["descriptor_flags"] & fcntl.FD_CLOEXEC, "CLOEXEC")
        if resource["pid"] is _PIDFD_UNKNOWN:
            _require(row["link"] == "anon_inode:[pidfd]", "PIDFD link")
            raw = self.read_file(f"/proc/self/fdinfo/{fd}", 4096, row, "pidfd_info_raw")
            resource["pid"] = _pid_association(raw)
        self.resource_guard(resource)
        return resource

    def resource_guard(self, resource):
        self.owner_guard()
        _require(not resource["consumed"], "consumed descriptor")
        _require(resource["pid"] is not _PIDFD_UNKNOWN, "unknown PIDFD association")
        fd, row, obj = resource["fd"], resource["row"], resource["obj"]
        _require(row["metadata"] is not None, "unobserved descriptor")
        if obj is not None:
            _require(obj.fileno() == fd, "object descriptor number")
        if resource["pid"] is not None:
            raw = self.read_file(f"/proc/self/fdinfo/{fd}", 4096, row, "pidfd_info_raw")
            row["pidfd_info_raw"] = raw
            _require(_pid_association(raw) == resource["pid"], "changed PIDFD")
        _require(fcntl.fcntl(fd, fcntl.F_GETFL) == row["flags"] and fcntl.fcntl(fd, fcntl.F_GETFD) == row["descriptor_flags"], "descriptor flags")
        link = os.readlink(f"/proc/self/fd/{fd}")
        if link == "anon_inode:[pidfd]" and resource["pid"] is None:
            resource["pid"] = _PIDFD_UNKNOWN
        _require(link == row["link"], "descriptor link changed")
        _require(fcntl.fcntl(fd, fcntl.F_GETFL) == row["flags"] and fcntl.fcntl(fd, fcntl.F_GETFD) == row["descriptor_flags"], "late descriptor flags")
        if resource["pid"] is not None:
            latest = self.read_file(f"/proc/self/fdinfo/{fd}", 4096, row, "pidfd_info_raw")
            row["pidfd_info_raw"] = latest
            _require(_pid_association(latest) == resource["pid"], "late PIDFD association")
            _require(fcntl.fcntl(fd, fcntl.F_GETFL) == row["flags"] and fcntl.fcntl(fd, fcntl.F_GETFD) == row["descriptor_flags"], "post-association flags")
        _require(_meta(os.fstat(fd)) == row["metadata"], "descriptor identity changed")
        self.owner_guard()

    def quick_guard(self, resource):
        # Final non-proc custody point after timing, immediately before I/O.
        self.owner_guard()
        fd, row = resource["fd"], resource["row"]
        _require(not resource["consumed"], "final I/O ownership")
        _require(resource["pid"] is not _PIDFD_UNKNOWN, "unknown PIDFD association")
        _require(fcntl.fcntl(fd, fcntl.F_GETFL) == row["flags"] and fcntl.fcntl(fd, fcntl.F_GETFD) == row["descriptor_flags"], "final I/O flags")
        _require(_meta(os.fstat(fd)) == row["metadata"], "final I/O identity")
        if resource["obj"] is not None:
            _require(resource["obj"].fileno() == fd, "final I/O object")
        self.owner_guard()

    def close_resource(self, resource):
        global _UNRESOLVED_OWNER
        if resource["consumed"]:
            return
        fd, obj = resource["fd"], resource["obj"]
        prior_cleaning, self.cleaning = self.cleaning, True
        try:
            self.resource_guard(resource)
            if obj is not None:
                resource["detach_attempted"] = True
                detached = obj.detach()
                if type(detached) is int and detached >= 0 and detached != fd:
                    if not any(r["fd"] == detached and not r["consumed"] for r in self.resources):
                        self.adopt(detached, "TRANSIENT", installed=True)
                _require(type(detached) is int and detached == fd, "detach custody")
                resource["obj"] = None
                self.resource_guard(resource)
            self.quick_guard(resource)
            resource["consumed"] = True
            os.close(fd)  # One attempt, even when close raises.
            resource["row"]["closed"] = True
            if resource["ephemeral"]:
                self.resources.remove(resource)
        except BaseException as failure:
            resource["consumed"] = True
            _UNRESOLVED_OWNER = self
            if len(self.cleanup_failures) < 32:
                self.cleanup_failures.append(failure)
            raise
        finally:
            self.cleaning = prior_cleaning

    def read_file(self, path, limit, snapshot=None, field=None, follow=False):
        raw = b""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW))
        resource = self.adopt(fd, "TRANSIENT", ephemeral=True)
        failure = None
        try:
            self.pin_resource(resource)
            _require(resource["row"]["flags"] & os.O_ACCMODE == os.O_RDONLY, "readonly observation")
            if path == "/run/aragorn-broker-boot-id":
                meta = resource["row"]["metadata"]
                _require(stat.S_ISREG(meta["mode"]) and meta["uid"] == 0 and not meta["mode"] & 0o022, "protected boot file")
            while True:
                self.resource_guard(resource)
                self.tick()
                self.quick_guard(resource)
                part = os.read(fd, min(65536, limit + 1 - len(raw)))
                _require(type(part) is bytes, "read result")
                raw += part
                if snapshot is not None:
                    snapshot[field] = raw[:limit]
                _require(len(raw) <= limit, "raw observation cap")
                if not part:
                    break
            self.resource_guard(resource)
            return raw
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                self.close_resource(resource)
            except BaseException:
                if failure is None:
                    raise

    def namespace(self, pid, name):
        path = f"/proc/{pid}/ns/{name}"
        key = (str(pid), name)
        resource = self.namespaces.get(key)
        if resource is None:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            resource = self.adopt(fd, "NAMESPACE")
            self.pin_resource(resource)
            self.namespaces[key] = resource
        self.resource_guard(resource)
        named = _meta(os.stat(path))
        held = resource["row"]["metadata"]
        link = os.readlink(path)
        _require(link == f"{name}:[{held['inode']}]" and (held["device"], held["inode"]) == (named["device"], named["inode"]), "namespace changed")
        self.resource_guard(resource)
        return dict(held={k: held[k] for k in ("device", "inode")}, named={k: named[k] for k in ("device", "inode")}, link=link)

    def blank_snapshot(self, edge, process_role, started_ns=None):
        snap = dict(edge=edge, process_role=process_role, started_ns=self.tick() if started_ns is None else started_ns, finished_ns=None,
                    peer_credentials_raw=None, pidfd_info_raw=None, stat_before_raw=None, status_raw=None,
                    stat_after_raw=None, cgroup_raw=None, cmdline_raw=None, boot_raw=None, executable_digest=None,
                    namespaces=dict(self=None, peer=None, provider=None), socket_options=None, directories=[])
        same = [s for s in self.snapshots if (s["edge"], s["process_role"]) == (edge, process_role)]
        if len(same) == 2:
            self.snapshots.remove(same[-1])
        _require(len(self.snapshots) < 16, "snapshot cap")
        self.snapshots.append(snap)
        return snap

    def snapshot(self, edge, process_role):
        snap = self.blank_snapshot(edge, process_role)
        original = None
        try:
            active_socket = self.sock if self.sock is not None and not self.sock["consumed"] else self.listener
            if active_socket is not None and not active_socket["consumed"]:
                snap["socket_options"] = self.socket_options(active_socket)
            if self.sock is not None and not self.sock["consumed"]:
                snap["peer_credentials_raw"] = self.sock["obj"].getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _require(snap["peer_credentials_raw"] == self.peer_creds, "peer credentials changed")
                if self.peer_pidfd is not None:
                    self.resource_guard(self.peer_pidfd)
                    snap["pidfd_info_raw"] = self.peer_pidfd["row"]["pidfd_info_raw"]
            if process_role == "PEER" and self.role == "CLIENT":
                return snap  # Root proc/source/named namespaces are inaccessible.
            pid = "self" if process_role == "SELF" else self.peer_process["pid"] if process_role == "PEER" else self.provider_process["pid"]
            for field, leaf in (("stat_before_raw", "stat"), ("status_raw", "status"), ("stat_after_raw", "stat"), ("cgroup_raw", "cgroup"), ("cmdline_raw", "cmdline")):
                self.read_file(f"/proc/{pid}/{leaf}", 16384, snap, field)
            process = _identity(snap["stat_before_raw"], snap["status_raw"])
            _require(process == _identity(snap["stat_after_raw"], snap["status_raw"]), "stat/status/stat")
            expected = self.self_process if process_role == "SELF" else self.peer_process if process_role == "PEER" else self.provider_process
            if expected is not None and not (process_role == "PEER" and getattr(self, "_discovering", False)):
                _require(process == expected, "process changed")
            if process_role == "PEER":
                creds = struct.unpack("=iII", self.peer_creds)
                _require((process["pid"], process["uid"], process["gid"]) == creds, "peer process credentials")
            ns = {name: self.namespace(pid, name) for name in ("time", "mnt")}
            snap["namespaces"][process_role.lower()] = dict(time=ns["time"], mount=ns["mnt"])
            boot_path = "/run/aragorn-broker-boot-id" if self.role == "CLIENT" else "/proc/sys/kernel/random/boot_id"
            self.read_file(boot_path, 64, snap, "boot_raw")
            if self.clock is not None:
                _require(snap["boot_raw"].decode("ascii").removesuffix("\n") == self.clock["boot_id"]
                         and ns["time"]["held"] == self.clock["time_namespace"], "clock custody")
            if process_role != "SELF":
                snap["executable_digest"] = _digest(self.read_file(f"/proc/{pid}/exe", 16777216, follow=True))
            for record in self.directories:
                self.resource_guard(record["resource"])
                named = _meta(os.stat(record["path"], follow_symlinks=False))
                snap["directories"].append(dict(path=record["path"], held=record["resource"]["row"]["metadata"], named=named))
                _require(named == record["resource"]["row"]["metadata"], "directory substitution")
            return snap
        except BaseException as exc:
            original = exc
            raise
        finally:
            try:
                snap["finished_ns"] = self.tick(False)
            except BaseException:
                if original is None:
                    raise

    def ancestry(self, broker_gid):
        parent_fd = None
        for path, component in zip(_DIRS[:3], ("/", "run", "aragorn-phase3-broker-reader")):
            fd = os.open(component, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, **({} if parent_fd is None else {"dir_fd": parent_fd}))
            resource = self.adopt(fd, "ANCESTOR")
            self.pin_resource(resource)
            meta = resource["row"]["metadata"]
            _require(stat.S_ISDIR(meta["mode"]) and meta["uid"] == 0 and not meta["mode"] & 0o022, "protected ancestry")
            if path == _PARENT:
                _require(meta["gid"] == broker_gid and stat.S_IMODE(meta["mode"]) == 0o710, "parent accounts/mode")
            self.directories.append(dict(path=path, resource=resource))
            parent_fd = fd
        self.parent_fd = parent_fd

    def endpoint_guard(self):
        for record in self.directories:
            self.resource_guard(record["resource"])
            _require(_meta(os.stat(record["path"], follow_symlinks=False)) == record["resource"]["row"]["metadata"], "named ancestry")
        if self.endpoint_hold is not None and not self.endpoint_hold["consumed"]:
            self.resource_guard(self.endpoint_hold)
            _require(self.endpoint_hold["row"]["metadata"] == self.endpoint_meta, "held pathname endpoint")
        if self.endpoint_meta is not None:
            _require(_meta(os.stat("bootstrap.sock", dir_fd=self.parent_fd, follow_symlinks=False)) == self.endpoint_meta, "named endpoint")
        self.owner_guard()

    def hold_endpoint(self):
        fd = os.open("bootstrap.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
        self.endpoint_hold = self.adopt(fd, "TRANSIENT")
        self.pin_resource(self.endpoint_hold)
        self.endpoint_guard()

    def make_socket(self, role):
        obj = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        self.objects.append(obj)
        resource = self.adopt(obj.fileno(), role, obj)
        self.pin_resource(resource)
        obj.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        obj.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PASSPIDFD", 76), 0)
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            obj.setsockopt(socket.SOL_SOCKET, option, 262176)
        self.socket_options(resource)
        return resource

    def socket_options(self, resource):
        self.resource_guard(resource)
        obj, row = resource["obj"], resource["row"]
        started = self.tick()
        self._latest_socket_observation = (started, None, None)
        opts = dict(fd=resource["fd"], **row["metadata"], nonblocking=bool(fcntl.fcntl(resource["fd"], fcntl.F_GETFL) & os.O_NONBLOCK),
                    noninheritable=not obj.get_inheritable(), passcred=obj.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED),
                    passpidfd=obj.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PASSPIDFD", 76)),
                    sndbuf=obj.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF), rcvbuf=obj.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                    so_type=obj.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE))
        self._latest_socket_observation = (started, self.tick(False), opts)
        _require(obj.family == socket.AF_UNIX and opts["so_type"] == socket.SOCK_SEQPACKET and stat.S_ISSOCK(opts["mode"])
                 and opts["nonblocking"] and opts["noninheritable"] and opts["passcred"] == 1 and opts["passpidfd"] == 0
                 and opts["sndbuf"] >= 262176 and opts["rcvbuf"] >= 262176, "socket profile")
        self.resource_guard(resource)
        return opts

    def authenticate(self, expected_uid, expected_gid):
        obj = self.sock["obj"]
        snap = self.blank_snapshot("ACCEPT" if self.role == "SERVER" else "CONNECT", "PEER")
        raw = obj.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        self.peer_creds = raw
        snap["peer_credentials_raw"] = raw[:12] if type(raw) is bytes else None
        _require(type(raw) is bytes and len(raw) == 12, "native credentials")
        pid, uid, gid = struct.unpack("=iII", raw)
        _require(0 < pid < 2**31 and uid == expected_uid and gid == expected_gid, "authenticated peer accounts")
        fd = obj.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERPIDFD", 77))
        resource = self.adopt(fd, "PEER_PIDFD")
        self.peer_pidfd = resource
        self.pin_resource(resource)
        resource["pid"] = pid
        self.resource_guard(resource)
        snap["pidfd_info_raw"] = resource["row"]["pidfd_info_raw"]
        snap["socket_options"] = self.socket_options(self.sock)
        snap["finished_ns"] = self.tick()
        self.live(resource)
        if self.role == "SERVER":
            # Discover actual start ticks before there is any caller expectation.
            snap = self.snapshot_peer_initial(pid)
            self.peer_process = _identity(snap["stat_before_raw"], snap["status_raw"])
        else:
            self.snapshot("CONNECT", "PEER")

    def snapshot_peer_initial(self, pid):
        # snapshot chooses pid from this binding; start is not used as expected.
        self.peer_process = dict(pid=pid)
        self._discovering = True
        try:
            return self.snapshot("ACCEPT", "PEER")
        finally:
            self._discovering = False

    def live(self, resource):
        self.resource_guard(resource)
        poll = select.poll()
        poll.register(resource["fd"], select.POLLIN | select.POLLHUP | select.POLLERR)
        _require(not poll.poll(0), "PIDFD exit")
        self.resource_guard(resource)

    def guard(self):
        self.owner_guard()
        self.endpoint_guard()
        for resource in tuple(self.resources):
            if not resource["consumed"]:
                self.resource_guard(resource)
        for (pid, name), resource in self.namespaces.items():
            if not resource["consumed"]:
                named = _meta(os.stat(f"/proc/{pid}/ns/{name}"))
                _require((named["device"], named["inode"]) == (resource["row"]["metadata"]["device"], resource["row"]["metadata"]["inode"]), "named namespace custody")
        for resource in (self.peer_pidfd, getattr(self, "supervisor_fd", None), getattr(self, "provider_fd", None)):
            if resource is not None and not resource["consumed"]:
                self.live(resource)
        if self.sock is not None and not self.sock["consumed"]:
            self.socket_options(self.sock)
        if self.cancel is not None and not self.cancel["consumed"]:
            self.check_cancel()
        self.tick()

    def check_cancel(self):
        resource = self.cancel
        self.resource_guard(resource)
        poll = select.poll()
        poll.register(resource["fd"], select.POLLIN | select.POLLHUP | select.POLLERR)
        events = poll.poll(0)
        self.resource_guard(resource)
        if events:
            _require(all(not flags & (select.POLLERR | select.POLLNVAL) for _, flags in events), "cancel poll error")
            self.tick()
            self.quick_guard(resource)
            try:
                raw = os.read(resource["fd"], 1)
            except BlockingIOError as exc:
                _require(exc.errno == 11, "cancel read errno")
                self.resource_guard(resource)
                return
            self.resource_guard(resource)
            _require(False, "cancellation EOF" if raw == b"" else "cancellation data")

    def wait(self, resource, mask):
        while True:
            self.guard()
            poll = select.poll()
            poll.register(resource["fd"], mask | select.POLLERR | select.POLLHUP)
            for other in (self.peer_pidfd, getattr(self, "supervisor_fd", None), getattr(self, "provider_fd", None), self.cancel):
                if other is not None and not other["consumed"] and other is not resource:
                    poll.register(other["fd"], select.POLLIN | select.POLLHUP | select.POLLERR)
            self.guard()
            now = self.tick()
            events = poll.poll(min(50, max(1, (self.deadline - now + 999999) // 1000000)))
            self.guard()  # Exit/cancellation wins simultaneous target readiness.
            if any(fd == resource["fd"] for fd, _ in events):
                _require(all(not flags & (select.POLLERR | select.POLLNVAL) for fd, flags in events if fd == resource["fd"]), "target poll error")
                return next(flags for fd, flags in events if fd == resource["fd"])

    def record_snapshot(self, edge):
        self.snapshot(edge, "SELF")
        self.guard()

    def send(self, name, value, rights=()):
        raw = _json(dict(schema=_PREFIX + name + "/v1", **value))
        _packet(raw, name)
        self.packets[name] = raw
        self.record_snapshot("SEND")
        opts = self.socket_options(self.sock)
        _require(opts["sndbuf"] >= 2 * len(raw) + 32, "send capacity")
        self.guard()
        self.tick()
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights).tobytes())] if rights else []
        self.quick_guard(self.sock)
        self.send_attempted, self.bytes_sent = True, None
        count = self.sock["obj"].sendmsg([raw], ancillary, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        self.bytes_sent = count
        _require(type(count) is int and count == len(raw), "single send uncertain/short")
        self.guard()
        return raw

    def receive(self, name=None, eof=False):
        bound = 1 if eof else 131072 if name == "release" else 4096
        readiness = self.wait(self.sock, select.POLLIN)
        self.record_snapshot("EOF" if eof else "RECEIVE")
        self.guard()
        self.tick()
        self.quick_guard(self.sock)
        raw, controls, flags, address = self.sock["obj"].recvmsg(bound, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8), socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        if name is not None:
            self.packets[name] = raw[:bound]
        installed_numbers, rights_items, credential_items, invalid = [], 0, [], False
        for level, kind, data in controls:
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, getattr(socket, "SCM_PIDFD", 4)):
                rights_items += 1
                for offset in range(0, len(data) - len(data) % 4, 4):
                    fd = struct.unpack("=i", data[offset:offset + 4])[0]
                    installed_numbers.append((fd, "UNEXPECTED_ANCILLARY"))
                invalid |= kind != socket.SCM_RIGHTS or len(data) % 4 != 0
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                credential_items.append(data)
            else:
                invalid = True
        # All actually installed numbers are owned before the first metadata read.
        installed = self.adopt_ingress(installed_numbers, installed=True)
        for resource in installed:
            self.pin_resource(resource)
        _require(not invalid and flags & ~(socket.MSG_EOR | socket.MSG_CMSG_CLOEXEC) == 0, "ancillary/packet flags")
        if eof:
            _require(raw == b"" and not controls and flags & ~socket.MSG_CMSG_CLOEXEC == 0 and readiness & select.POLLHUP, "expected EOF")
            return None, []
        if credential_items:
            latest = next(s for s in reversed(self.snapshots) if s["edge"] == "RECEIVE")
            latest["peer_credentials_raw"] = credential_items[0][:12]
        _require(raw and credential_items == [self.peer_creds], "per-message credentials")
        if name == "handles":
            _require(rights_items == 1 and len(installed) == 2 and all(r["fd"] >= 3 for r in installed), "exact two handles")
        else:
            _require(rights_items == 0 and not installed, "credentials-only packet")
        value = _packet(raw, name)
        self.guard()
        return value, installed

    def remote_handle(self, pid, fd, role, process_role, expected, access, association=None):
        _uint(fd, 3)
        _require(len(self.handles) < 32, "remote observation cap")
        row = dict(fd=fd, role=role, process_role=process_role, metadata=None, flags=None, descriptor_flags=None, link=None, pidfd_info_raw=None, closed=False)
        self.handles.append(row)
        path = f"/proc/{pid}/fd/{fd}"
        row["metadata"] = _meta(os.stat(path))
        row["link"] = os.readlink(path)
        raw = self.read_file(f"/proc/{pid}/fdinfo/{fd}", 4096, row, "pidfd_info_raw")
        row["pidfd_info_raw"] = raw
        lines = [line[6:].strip() for line in raw.splitlines() if line.startswith(b"flags:")]
        _require(len(lines) == 1 and re.fullmatch(rb"[0-7]+", lines[0]), "remote FD flags")
        row["flags"] = int(lines[0], 8)
        _require(row["metadata"] == expected and (access is None or row["flags"] & os.O_ACCMODE == access)
                 and row["flags"] & os.O_CLOEXEC, "remote descriptor custody")
        if association is not None:
            _require(_pid_association(raw) == association and row["link"] == "anon_inode:[pidfd]", "remote PIDFD")
        else:
            _require(row["flags"] & os.O_NONBLOCK and row["link"] == f"pipe:[{expected['inode']}]", "remote pipe")
        _require(_meta(os.stat(path)) == expected and os.readlink(path) == row["link"], "late remote descriptor")
        latest = self.read_file(f"/proc/{pid}/fdinfo/{fd}", 4096, row, "pidfd_info_raw")
        row["pidfd_info_raw"] = latest
        _require(latest == raw, "late remote flags/association")
        _require(_meta(os.stat(path)) == expected, "final remote descriptor identity")
        self.owner_guard()
        return row

    def configure_pipe(self, resource, expected):
        self.pin_resource(resource)
        row = resource["row"]
        _pipe(row["metadata"])
        _require(row["metadata"] == expected and row["flags"] & os.O_ACCMODE == os.O_RDONLY
                 and row["flags"] & os.O_NONBLOCK and row["link"] == f"pipe:[{expected['inode']}]", "read pipe identity")
        self.resource_guard(resource)

    def configure_pidfd(self, resource, pid, expected=None):
        self.pin_resource(resource)
        resource["pid"] = pid
        _require(resource["row"]["link"] == "anon_inode:[pidfd]", "PIDFD link")
        if expected is not None:
            _require(resource["row"]["metadata"] == expected, "PIDFD object identity")
        self.live(resource)

    def observation(self, status):
        self.finished = self.tick(False)
        artifacts = {name: _artifact(raw, 131072 if name == "release" else 4096) for name, raw in self.packets.items()}
        handles, snapshots = _encoded(self.handles), _encoded(self.snapshots)
        _require(len(handles) <= 32 and all(len(_json(row)) <= 8192 for row in handles), "handle encoded cap")
        _require(len(snapshots) <= 16 and all(len(_json(row)) <= 131072 for row in snapshots), "snapshot encoded cap")
        value = dict(schema=_PREFIX + "observation/v1", role=self.role, phase=self.phase, started_ns=self.started,
                     finished_ns=self.finished, deadline_ns=self.deadline, packet_digests={name: None if raw is None else _digest(raw) for name, raw in self.packets.items()},
                     peer=self.peer_process, provider_ready_digest=None if self.ready_raw is None else _digest(self.ready_raw),
                     status=status, limitations=list(_LIMITATIONS), packet_artifacts=artifacts, provider_ready=_artifact(self.ready_raw, 4096),
                     handle_observations=handles, transport_observations=snapshots)
        raw = _json(value)
        _require(len(raw) <= 3145728, "observation total cap")
        return raw

    def cleanup(self, resources=None):
        for resource in reversed(tuple(self.resources if resources is None else resources)):
            if not resource["consumed"]:
                try:
                    self.close_resource(resource)
                except BaseException:
                    pass
        self.state = "CLOSED"

    def fail(self, failure):
        latest = self._latest_socket_observation
        if latest is not None and latest[2] is not None and len(self.snapshots) < 16:
            # These are actual getter times/options, not reconstructed at failure.
            mark, finish, options = latest
            edge = {"OPEN": "OPEN", "HELLO": "ACCEPT", "HANDLES": "TRANSFER", "RELEASE": "READY", "CLOSE": "CLOSE"}[self.phase]
            self.snapshots.append(dict(edge=edge, process_role="SELF", started_ns=mark, finished_ns=finish,
                                       peer_credentials_raw=None, pidfd_info_raw=None, stat_before_raw=None, status_raw=None,
                                       stat_after_raw=None, cgroup_raw=None, cmdline_raw=None, boot_raw=None, executable_digest=None,
                                       namespaces=dict(self=None, peer=None, provider=None), socket_options=options, directories=[]))
        self.state = "FAILED"
        self.cleanup()
        try:
            observed_raw = self.observation("REFUSED")
        except BaseException:
            observed_raw = None
        observed = dict(hello_raw=self.packets["hello"], handles_raw=self.packets["handles"], received_raw=self.packets["received"],
                        release_raw=self.packets["release"], provider_ready_raw=self.ready_raw, observation_raw=observed_raw,
                        send_attempted=self.send_attempted, bytes_sent=self.bytes_sent,
                        handle_observations=deepcopy(self.handles), transport_observations=deepcopy(self.snapshots))
        if isinstance(failure, (KeyboardInterrupt, SystemExit, MemoryError)):
            failure.observed = observed
            failure.cleanup_failures = tuple(self.cleanup_failures)
            failure.unresolved_owner = self if _UNRESOLVED_OWNER is self else None
            raise failure
        raise BrokerReaderBootstrapError(failure, tuple(self.cleanup_failures), observed, self if _UNRESOLVED_OWNER is self else None) from failure

    def enter(self, state, phase):
        # Rejected entry has not accepted caller handles or authority to clean up
        # the existing owner. In particular, reentry must not destroy its caller.
        try:
            _require(not self.busy and self.state == state, "single-use state")
            self.owner_guard()
        except BaseException as exc:
            observed = dict(hello_raw=self.packets["hello"], handles_raw=self.packets["handles"], received_raw=self.packets["received"],
                            release_raw=self.packets["release"], provider_ready_raw=self.ready_raw, observation_raw=None,
                            send_attempted=self.send_attempted, bytes_sent=self.bytes_sent,
                            handle_observations=deepcopy(self.handles), transport_observations=deepcopy(self.snapshots))
            if isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
                exc.observed, exc.cleanup_failures, exc.unresolved_owner = observed, (), None
                raise
            raise BrokerReaderBootstrapError(exc, (), observed, None) from exc
        self.busy = True
        self.phase = phase

    def finish_success(self):
        # Observations and slow closing/association guards precede this deadline.
        # Only finite held-descriptor/owner checks follow it before return/transfer.
        self.guard()
        self.tick()
        for resource in tuple(self.resources):
            if not resource["consumed"]:
                self.quick_guard(resource)
        self.owner_guard()

    def leave(self, state):
        self.state = state
        self.busy = False

    def close(self):
        try:
            _require(not self.busy and self.state != "CLOSED", "close once")
            self.phase = "CLOSE"
            self.owner_guard()
            self.cleanup()
            if self.cleanup_failures:
                raise self.cleanup_failures[0]
            return dict(observation_raw=self.observation("CLOSED"))
        except BaseException as exc:
            self.fail(exc)


class BrokerReaderBootstrapServer(_Owner):
    """Root owns the one fixed listener, accepted peer and transfer copies."""

    def __init__(self, *, broker_uid, broker_gid, startup_deadline_ns, session_deadline_ns):
        super().__init__("SERVER", startup_deadline_ns)
        try:
            self.broker_uid, self.broker_gid = _uint(broker_uid, 1, 2**32), _uint(broker_gid, 1, 2**32)
            self.session_deadline = _uint(session_deadline_ns, 1)
            self.initialize()
            _require(self.deadline < self.session_deadline, "original session deadline")
            self.ancestry(broker_gid)
            try:
                os.stat("bootstrap.sock", dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("existing endpoint retained")
            self.listener = self.make_socket("LISTENER")
            self.endpoint_guard()
            self.socket_options(self.listener)
            self.tick()
            self.quick_guard(self.listener)
            self.listener["obj"].bind(_ENDPOINT)
            self.endpoint_meta = _meta(os.stat("bootstrap.sock", dir_fd=self.parent_fd, follow_symlinks=False))
            _require(stat.S_ISSOCK(self.endpoint_meta["mode"]) and self.endpoint_meta["uid"] == 0, "new endpoint type")
            self.endpoint_guard()
            previous = self.endpoint_meta
            os.chown("bootstrap.sock", 0, broker_gid, dir_fd=self.parent_fd, follow_symlinks=False)
            self.endpoint_meta = _meta(os.stat("bootstrap.sock", dir_fd=self.parent_fd, follow_symlinks=False))
            _require(all(self.endpoint_meta[k] == previous[k] for k in ("device", "inode")), "endpoint changed during chown")
            self.endpoint_guard()
            previous = self.endpoint_meta
            os.chmod("bootstrap.sock", 0o660, dir_fd=self.parent_fd, follow_symlinks=False)
            self.endpoint_meta = _meta(os.stat("bootstrap.sock", dir_fd=self.parent_fd, follow_symlinks=False))
            _require(all(self.endpoint_meta[k] == previous[k] for k in ("device", "inode")), "endpoint changed during chmod")
            _require(self.endpoint_meta["uid"] == 0 and self.endpoint_meta["gid"] == broker_gid and self.endpoint_meta["mode"] == stat.S_IFSOCK | 0o660, "endpoint final custody")
            self.hold_endpoint()
            self.guard()
            self.tick()
            self.quick_guard(self.listener)
            self.listener["obj"].listen(1)
            self.record_snapshot("OPEN")
            self._opening = self.observation("OPENED")
            self.finish_success()
            self.leave("OPEN")
        except BaseException as exc:
            self.fail(exc)

    @property
    def opening_raw(self):
        self.owner_guard()
        return self._opening

    def accept_hello(self):
        self.enter("OPEN", "HELLO")
        try:
            self.tick()
            self.wait(self.listener, select.POLLIN)
            self.guard()
            self.tick()
            self.quick_guard(self.listener)
            obj, _address = self.listener["obj"].accept()
            self.objects.append(obj)
            self.sock = self.adopt(obj.fileno(), "CONNECTION", obj)
            obj.setblocking(False)
            obj.set_inheritable(False)
            self.pin_resource(self.sock)
            obj.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            obj.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PASSPIDFD", 76), 0)
            for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
                obj.setsockopt(socket.SOL_SOCKET, option, 262176)
            self.socket_options(self.sock)
            self.authenticate(self.broker_uid, self.broker_gid)
            hello, _ = self.receive("hello")
            self.deadline = min(self.deadline, hello["deadline_ns"])
            self.tick()
            self.hello = hello
            snap = self.snapshot("ACCEPT", "PEER")
            peer = dict(schema=_PREFIX + "peer/v1", process=self.peer_process, clock=self.clock,
                        mount_namespace=snap["namespaces"]["peer"]["mount"]["held"],
                        credentials_hex=self.peer_creds.hex(), pidfd_info_hex=self.peer_pidfd["row"]["pidfd_info_raw"].hex(), observed_ns=self.tick())
            result = dict(hello_raw=self.packets["hello"], peer_raw=_json(peer), observation_raw=self.observation("RECEIVED"))
            self.finish_success()
            self.leave("HELLO")
            return result
        except BaseException as exc:
            self.fail(exc)

    def peer_expectation(self, raw, pin):
        value = _schema(raw, 16384, "peer-expectation", "broker clock mount_namespace unit invocation_id control_group command_digest executable_digest source_inventory_digest grant_digest measurement_binding_digest fixture_binding_digest observed_before_ns observed_after_ns", pin)
        _require(_process(value["broker"]) == self.peer_process and _clock(value["clock"]) == self.clock, "protected expected peer")
        _namespace(value["mount_namespace"])
        _require(value["unit"] == "aragorn-runtime-lineage-capability-action-broker.service"
                 and type(value["invocation_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["invocation_id"]), "fixed unit expectation")
        _path(value["control_group"])
        for key in value:
            if key.endswith("_digest"):
                _pin(value[key])
        _require(_uint(value["observed_before_ns"]) <= _uint(value["observed_after_ns"]) <= self.tick(), "unit observation chronology")
        for key in ("grant_digest", "measurement_binding_digest", "fixture_binding_digest"):
            _require(value[key] == self.hello[key], "protected credential join")
        self.expected_peer = value
        self.check_expected_peer()
        return value

    def check_expected_peer(self):
        snap = self.snapshot("TRANSFER", "PEER")
        value = self.expected_peer
        _require(snap["cmdline_raw"] and _digest(snap["cmdline_raw"]) == value["command_digest"]
                 and snap["executable_digest"] == value["executable_digest"]
                 and snap["cgroup_raw"] == ("0::" + value["control_group"] + "\n").encode("ascii")
                 and snap["namespaces"]["peer"]["mount"]["held"] == value["mount_namespace"], "unit/source/process join")
        self.live(self.peer_pidfd)

    def offer_handles(self, *, broker_expectation_raw, expected_broker_expectation_digest, ipc_cancel_read_fd, supervisor_pidfd):
        self.enter("HELLO", "HANDLES")
        try:
            cancel, supervisor = self.adopt_ingress(((ipc_cancel_read_fd, "CANCEL_TRANSFER"), (supervisor_pidfd, "SUPERVISOR_TRANSFER")))
            self.tick()
            self.peer_expectation(broker_expectation_raw, expected_broker_expectation_digest)
            self.pin_resource(cancel)
            self.configure_pipe(cancel, cancel["row"]["metadata"])
            self.cancel = cancel
            self.configure_pidfd(supervisor, self.self_process["pid"])
            self.supervisor_fd = supervisor
            offered = dict(hello_digest=_digest(self.packets["hello"]), broker_nonce=self.hello["broker_nonce"], deadline_ns=self.deadline,
                           supervisor=self.self_process, clock=self.clock, cancellation_pipe=cancel["row"]["metadata"],
                           supervisor_pidfd=dict(metadata=supervisor["row"]["metadata"], pid=self.self_process["pid"]))
            self.send("handles", offered, (cancel["fd"], supervisor["fd"]))
            received, _ = self.receive("received")
            self.join_packet(received, "received")
            _uint(received["cancellation_fd"], 3)
            _uint(received["supervisor_pidfd"], 3)
            _require(received["cancellation_fd"] != received["supervisor_pidfd"], "remote descriptor aliases")
            self.received = received
            self.handles_value = _packet(self.packets["handles"], "handles")
            self.check_receiver_handles()
            self.check_expected_peer()
            self.close_resource(supervisor)
            self.close_resource(cancel)
            result = dict(hello_raw=self.packets["hello"], handles_raw=self.packets["handles"], received_raw=self.packets["received"], observation_raw=self.observation("RECEIVED"))
            self.finish_success()
            self.leave("RECEIVED")
            return result
        except BaseException as exc:
            self.fail(exc)

    def join_packet(self, value, name):
        _require(value["broker_nonce"] == self.hello["broker_nonce"] and value["deadline_ns"] == self.deadline, "nonce/deadline join")
        for prior in ("hello", "handles", "received"):
            key = prior + "_digest"
            if key in value:
                _require(value[key] == _digest(self.packets[prior]), "packet chain")

    def check_receiver_handles(self):
        pid = self.peer_process["pid"]
        self.remote_handle(pid, self.received["cancellation_fd"], "CANCEL_RECEIVED", "PEER", self.handles_value["cancellation_pipe"], os.O_RDONLY)
        self.remote_handle(pid, self.received["supervisor_pidfd"], "SUPERVISOR_TRANSFER", "PEER", self.handles_value["supervisor_pidfd"]["metadata"], None, self.self_process["pid"])

    def consume_ready(self, expected, provision):
        ready = self.ready_read
        _require(os.fpathconf(ready["fd"], "PC_PIPE_BUF") >= 4096, "atomic ready frame capacity")
        prefix = b""
        while b"\n" not in prefix:
            self.wait(ready, select.POLLIN)
            self.guard()
            self.tick()
            self.quick_guard(ready)
            try:
                part = os.read(ready["fd"], 4096 - len(prefix))
            except BlockingIOError as exc:
                _require(exc.errno == 11, "ready read errno")
                continue
            try:
                received = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            finally:
                if type(part) is bytes:
                    self.ready_raw = prefix + part  # Preserve actual bytes even if the receipt clock fails.
            _require(type(part) is bytes, "ready read result")
            prefix += part
            _require(_uint(received) >= self._last_tick, "clock reversal")
            self._last_tick = received
            if b"\n" in prefix:
                receipt = self.blank_snapshot("READY", "SELF", started_ns=received)
                receipt["finished_ns"] = received
            _require(received < self.deadline, "startup deadline")
            self.owner_guard()
            _require(part and len(self.ready_raw) <= 4096, "ready prefix/EOF")
            self.resource_guard(ready)
            _require(b"\n" in self.ready_raw or len(self.ready_raw) < 4096, "ready frame bound")
        _require(self.ready_raw.endswith(b"\n") and self.ready_raw.count(b"\n") == 1, "ready surplus")
        frame = _keys(_decode(self.ready_raw[:-1], 4095), "schema provider supervisor clock provision_digest source_inventory_digest epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest loop_provision_digest guard_socket ready_ns")
        _require(frame["schema"] == "aragorn/native-phase3-broker-reader-provider-ready/v1", "ready schema")
        _require(_process(frame["provider"]) == provision["provider"] and _process(frame["supervisor"]) == self.self_process
                 and _clock(frame["clock"]) == self.clock, "ready identity/clock")
        for key in ("provision_digest", "source_inventory_digest"):
            _require(_pin(frame[key]) == expected[key], "ready protected pin")
        for key, pin in provision["reader_session"].items():
            _require(_pin(frame[key]) == pin, "ready reader binding")
        guard = _keys(frame["guard_socket"], "path metadata")
        _require(guard["path"] == _GUARD, "guard path")
        meta = _metadata(guard["metadata"])
        _require(meta["mode"] == stat.S_IFSOCK | 0o660 and meta["uid"] == 0 and meta["gid"] == self.broker_gid, "guard accounts")
        fd = os.open("guard.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
        held = self.adopt(fd, "TRANSIENT")
        self.pin_resource(held)
        _require(held["row"]["metadata"] == meta and _meta(os.stat("guard.sock", dir_fd=self.parent_fd, follow_symlinks=False)) == meta, "guard named/held")
        self.guard()
        _require(_uint(frame["ready_ns"]) <= received < self.deadline, "ready chronology")
        self.resource_guard(ready)
        self.tick()
        self.quick_guard(ready)
        try:
            extra = os.read(ready["fd"], 1)
        except BlockingIOError as exc:
            _require(exc.errno == 11, "surplus read errno")
        else:
            if len(self.ready_raw) < 4096:
                self.ready_raw += extra
            raise ValueError("ready surplus or writer EOF")
        self.remote_handle(self.provider_process["pid"], expected["provider_write_fd"], "READY_WRITER", "PROVIDER", expected["pipe"], os.O_WRONLY)
        self.live(self.provider_fd)
        self.resource_guard(ready)
        self.record_snapshot("READY")
        return held

    def release(self, *, provision_raw, expected_provision_digest, source_inventory_raw, expected_source_inventory_digest, readiness_expectation_raw, expected_readiness_expectation_digest, provider_ready_read_fd, provider_pidfd):
        self.enter("RECEIVED", "RELEASE")
        try:
            ready_read, provider_fd = self.adopt_ingress(((provider_ready_read_fd, "READY_READ"), (provider_pidfd, "PROVIDER_PIDFD")))
            self.tick()
            provision = _provision(provision_raw, expected_provision_digest)
            inventory = _inventory(source_inventory_raw, expected_source_inventory_digest)
            self.join_provision(provision, expected_source_inventory_digest)
            expected = _schema(readiness_expectation_raw, 4096, "readiness-expectation", "provider supervisor pipe provider_write_fd supervisor_read_fd provision_digest source_inventory_digest", expected_readiness_expectation_digest)
            _require(_process(expected["provider"]) == provision["provider"] and _process(expected["supervisor"]) == self.self_process
                     and _pin(expected["provision_digest"]) == expected_provision_digest and _pin(expected["source_inventory_digest"]) == expected_source_inventory_digest
                     and _uint(expected["supervisor_read_fd"], 3) == provider_ready_read_fd, "protected ready expectation")
            _uint(expected["provider_write_fd"], 3)
            _pipe(expected["pipe"])
            _require(expected["pipe"] != self.handles_value["cancellation_pipe"], "separate ready pipe")
            self.provider_process = provision["provider"]
            self.configure_pipe(ready_read, expected["pipe"])
            self.ready_read = ready_read
            self.configure_pidfd(provider_fd, self.provider_process["pid"])
            self.provider_fd = provider_fd
            self.snapshot("READY", "PROVIDER")
            self.remote_handle(self.provider_process["pid"], expected["provider_write_fd"], "READY_WRITER", "PROVIDER", expected["pipe"], os.O_WRONLY)
            self.check_receiver_handles()
            self.check_expected_peer()
            held_guard = self.consume_ready(expected, provision)
            self.check_expected_peer()
            self.check_receiver_handles()
            self.snapshot("READY", "PROVIDER")
            self.remote_handle(self.provider_process["pid"], expected["provider_write_fd"], "READY_WRITER", "PROVIDER", expected["pipe"], os.O_WRONLY)
            self.live(self.provider_fd)
            self.join_provision(provision, expected_source_inventory_digest)
            value = dict(hello_digest=_digest(self.packets["hello"]), handles_digest=_digest(self.packets["handles"]), received_digest=_digest(self.packets["received"]),
                         broker_nonce=self.hello["broker_nonce"], deadline_ns=self.deadline, provider_ready_digest=_digest(self.ready_raw),
                         provision=provision, provision_digest=expected_provision_digest, source_inventory=inventory, source_inventory_digest=expected_source_inventory_digest)
            self.send("release", value)
            self.receive(eof=True)
            for resource in (ready_read, provider_fd, held_guard, self.sock):
                self.close_resource(resource)
            result = dict(hello_raw=self.packets["hello"], handles_raw=self.packets["handles"], received_raw=self.packets["received"], release_raw=self.packets["release"], provider_ready_raw=self.ready_raw, observation_raw=self.observation("RELEASED"))
            self.finish_success()
            self.leave("RELEASED")
            return result
        except BaseException as exc:
            self.fail(exc)

    def join_provision(self, provision, inventory_digest):
        _require(provision["broker"] == self.peer_process and provision["supervisor"] == self.self_process
                 and provision["clock"] == self.clock and provision["source_inventory_digest"] == inventory_digest == self.expected_peer["source_inventory_digest"]
                 and provision["session_deadline_ns"] == self.session_deadline
                 and provision["cancellation_pipe"]["readers"][1]["fd"] == self.received["cancellation_fd"], "final provision join")
        _require(provision["accept_deadline_ns"] > self.tick(), "remaining guard budget")
        for key in ("grant_digest", "measurement_binding_digest", "fixture_binding_digest"):
            _require(provision[key] == self.hello[key], "credential provision pins")
        pipe = {k: provision["cancellation_pipe"][k] for k in ("device", "inode", "mode", "uid", "gid")}
        _require(pipe == self.handles_value["cancellation_pipe"], "provision pipe")
        for expected, actual in zip(provision["directories"][:3], self.directories):
            _require({k: expected[k] for k in ("device", "inode", "mode", "uid", "gid")} == actual["resource"]["row"]["metadata"], "provision ancestry")
        self.endpoint_guard()


class BrokerReaderBootstrapTransfer(_Owner):
    """Own received handles until the one actual configure transfer or close."""

    def take_configuration(self):
        self.enter("RELEASED", "RELEASE")
        try:
            self.tick()
            self.snapshot("TRANSFER", "SELF")
            self.guard()
            config = dict(provision_raw=self.provision_raw, expected_provision_digest=_digest(self.provision_raw),
                          source_inventory_raw=self.inventory_raw, expected_source_inventory_digest=_digest(self.inventory_raw),
                          measurement_binding_raw=self.measurement_raw, expected_measurement_binding_digest=_digest(self.measurement_raw),
                          fixture_binding_raw=self.fixture_raw, expected_fixture_binding_digest=_digest(self.fixture_raw),
                          ipc_cancel_read_fd=self.cancel["fd"], supervisor_pidfd=self.supervisor_fd["fd"], bootstrap_raw=None)
            self.guard()
            for resource in tuple(self.resources):
                if not resource["consumed"] and resource not in (self.cancel, self.supervisor_fd):
                    self.close_resource(resource)
            self.check_cancel()
            self.live(self.supervisor_fd)
            self.resource_guard(self.cancel)
            self.owner_guard()
            self.tick()
            config["bootstrap_raw"] = self.observation("RELEASED")
            self.check_cancel()
            self.live(self.supervisor_fd)
            self.resource_guard(self.cancel)
            self.tick()
            self.quick_guard(self.cancel)
            self.quick_guard(self.supervisor_fd)
            self.cancel["consumed"] = self.supervisor_fd["consumed"] = True
            self.leave("TAKEN")
            return config
        except BaseException as exc:
            self.fail(exc)


def receive_broker_reader_bootstrap(*, capability_grant_raw, expected_capability_grant_digest,
                                    measurement_binding_raw, expected_measurement_binding_digest,
                                    fixture_binding_raw, expected_fixture_binding_digest, startup_deadline_ns):
    owner = BrokerReaderBootstrapTransfer("CLIENT", startup_deadline_ns)
    try:
        owner.initialize()
        for raw, pin, bound in ((capability_grant_raw, expected_capability_grant_digest, 65536), (measurement_binding_raw, expected_measurement_binding_digest, 8192), (fixture_binding_raw, expected_fixture_binding_digest, 16384)):
            _decode(raw, bound, pin)
        owner.measurement_raw, owner.fixture_raw = measurement_binding_raw, fixture_binding_raw
        owner.ancestry(owner.self_process["gid"])
        owner.endpoint_meta = _meta(os.stat("bootstrap.sock", dir_fd=owner.parent_fd, follow_symlinks=False))
        _require(owner.endpoint_meta["mode"] == stat.S_IFSOCK | 0o660 and owner.endpoint_meta["uid"] == 0 and owner.endpoint_meta["gid"] == owner.self_process["gid"], "fixed endpoint protection")
        owner.hold_endpoint()
        owner.sock = owner.make_socket("CONNECTION")
        owner.guard()
        owner.tick()
        try:
            owner.quick_guard(owner.sock)
            owner.sock["obj"].connect(_ENDPOINT)
        except OSError as exc:
            _require(exc.errno in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK), "one connect")
            owner.wait(owner.sock, select.POLLOUT)
            _require(owner.sock["obj"].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, "connect completion")
        owner.authenticate(0, 0)
        owner.hello = dict(broker_nonce=os.urandom(32).hex(), grant_digest=expected_capability_grant_digest, measurement_binding_digest=expected_measurement_binding_digest, fixture_binding_digest=expected_fixture_binding_digest, deadline_ns=owner.deadline)
        owner.send("hello", owner.hello)
        handles, resources = owner.receive("handles")
        _require(handles["hello_digest"] == _digest(owner.packets["hello"]) and handles["broker_nonce"] == owner.hello["broker_nonce"]
                 and handles["deadline_ns"] <= owner.deadline, "handles hello join")
        owner.deadline = handles["deadline_ns"]
        _require(_process(handles["supervisor"])["uid"] == handles["supervisor"]["gid"] == 0
                 and (handles["supervisor"]["pid"], 0, 0) == struct.unpack("=iII", owner.peer_creds)
                 and _clock(handles["clock"]) == owner.clock, "authenticated supervisor binding")
        pidfd_value = _keys(handles["supervisor_pidfd"], "metadata pid")
        _require(_uint(pidfd_value["pid"], 1, 2**31) == handles["supervisor"]["pid"], "supervisor PIDFD join")
        _metadata(pidfd_value["metadata"])
        _pipe(handles["cancellation_pipe"])
        owner.cancel, owner.supervisor_fd = resources
        owner.cancel["role"] = owner.cancel["row"]["role"] = "CANCEL_TRANSFER"
        owner.supervisor_fd["role"] = owner.supervisor_fd["row"]["role"] = "SUPERVISOR_TRANSFER"
        owner.configure_pipe(owner.cancel, handles["cancellation_pipe"])
        owner.configure_pidfd(owner.supervisor_fd, handles["supervisor"]["pid"], pidfd_value["metadata"])
        received = dict(hello_digest=_digest(owner.packets["hello"]), handles_digest=_digest(owner.packets["handles"]), broker_nonce=owner.hello["broker_nonce"], deadline_ns=owner.deadline,
                        cancellation_fd=owner.cancel["fd"], supervisor_pidfd=owner.supervisor_fd["fd"])
        owner.send("received", received)
        release, _ = owner.receive("release")
        _require(release["broker_nonce"] == owner.hello["broker_nonce"] and release["deadline_ns"] == owner.deadline, "release nonce/deadline")
        for prior in ("hello", "handles", "received"):
            _require(release[prior + "_digest"] == _digest(owner.packets[prior]), "release chain")
        provision_raw, inventory_raw = _json(release["provision"]), _json(release["source_inventory"])
        provision = _provision(provision_raw, release["provision_digest"])
        _inventory(inventory_raw, release["source_inventory_digest"])
        _require(provision["broker"] == owner.self_process and provision["supervisor"] == handles["supervisor"]
                 and provision["clock"] == owner.clock and provision["source_inventory_digest"] == release["source_inventory_digest"]
                 and provision["cancellation_pipe"]["readers"][1]["fd"] == owner.cancel["fd"]
                 and {k: provision["cancellation_pipe"][k] for k in ("device", "inode", "mode", "uid", "gid")} == handles["cancellation_pipe"]
                 and owner.original_deadline < provision["session_deadline_ns"] and owner.tick() < provision["accept_deadline_ns"], "client final provision")
        for key in ("grant_digest", "measurement_binding_digest", "fixture_binding_digest"):
            _require(provision[key] == owner.hello[key], "protected client credential pin")
        for expected, actual in zip(provision["directories"][:3], owner.directories):
            _require({k: expected[k] for k in ("device", "inode", "mode", "uid", "gid")} == actual["resource"]["row"]["metadata"], "client provision ancestry")
        owner.provision_raw, owner.inventory_raw = provision_raw, inventory_raw
        owner.snapshot("TRANSFER", "SELF")
        owner.guard()
        owner.close_resource(owner.sock)
        owner.close_resource(owner.peer_pidfd)
        owner.finish_success()
        owner.leave("RELEASED")
        return owner
    except BaseException as exc:
        owner.fail(exc)
