"""One owned-fixture broker readiness listener; never activates a service.

The child observes the broker's startup GET. The parent separately reads the
same broker epoch's AF_UNIX listener without connecting to it. Captured records
are bounded local observations, not loaded-code or Phase 3 qualification.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

from . import native_phase3_http_canary_contract as canary
from . import runtime_http_readiness as readiness
from . import runtime_process_profile as process
from .native_phase3_http_collection import _read_fixed
from .native_phase3_http_fixture import owned_http_fixture, _root_process_status
from .native_phase3_http_readiness_verify import verify_broker_readiness
from .native_phase3_http_sink import open_http_sink
from .oci_worker_protocol import canonical_json

UNIT = "aragorn-runtime-lineage-capability-action-broker.service"
SOCKET = Path("/var/lib/aragorn-runtime-action/control/broker.sock")
_LIMIT = 131072
_FALSE = (*canary.FALSE_FLAGS, "broker_restricted_readiness_verified")


class BrokerReadinessCaptureError(ValueError):
    """A fixed failure with retained partial observations and no effect retry."""


def _require(value, reason):
    if not value:
        raise BrokerReadinessCaptureError(reason)


def _now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _read(path, limit=16384):
    return process._read_virtual_file(Path(path), limit)


def _record(raw):
    return {
        "document": json.loads(raw),
        "digest": canary.digest(raw),
        "bytes": len(raw),
    }


def _namespace(pid):
    metadata = os.stat(f"/proc/{pid}/ns/net")
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _pidfd(pid):
    descriptor = os.pidfd_open(pid, 0)
    try:
        values = [
            line.partition(b":")[2].strip()
            for line in _read(f"/proc/self/fdinfo/{descriptor}", 4096).splitlines()
            if line.startswith(b"Pid:")
        ]
        _require(values == [str(pid).encode("ascii")], "HTTP_READY_PIDFD_CHANGED")
        process.require_live_pidfd(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _send(fd, value):
    raw = canonical_json(value) + b"\n"
    _require(len(raw) <= _LIMIT, "HTTP_READY_CHILD_OUTPUT_LIMIT")
    deadline = time.monotonic() + 3
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_WRITE)
        while raw:
            left = deadline - time.monotonic()
            _require(
                left > 0 and selector.select(left), "HTTP_READY_CHILD_WRITE_TIMEOUT"
            )
            count = os.write(fd, raw)
            _require(count > 0, "HTTP_READY_CHILD_WRITE_FAILED")
            raw = raw[count:]


def _child(fd, fixture, attempt, nonce):
    sink, error_code, exit_code = None, None, 1
    try:

        def interrupted(_number, _frame):
            raise BrokerReadinessCaptureError("HTTP_READY_CHILD_CANCELLED")

        signal.signal(signal.SIGTERM, interrupted)
        # The child needs only its private pipe. Inherited CAS/activation locks
        # must not remain held by a listener after its parent closes them.
        names = os.listdir("/proc/self/fd")
        _require(len(names) <= 1024, "HTTP_READY_INHERITED_FD_LIMIT")
        for name in names:
            descriptor = int(name)
            if descriptor > 2 and descriptor != fd:
                try:
                    os.close(descriptor)
                except OSError as error:
                    # /proc enumeration may list its own already closed fd.
                    if error.errno != errno.EBADF:
                        raise
        with open_http_sink(
            expected_fixture=fixture, attempt_id=attempt, readiness_nonce=nonce
        ) as sink:
            _send(fd, {"kind": "LISTENING", "identity": sink._held.identity})
            # Cold activation is outside the sink's two-second ingress window.
            # Wait for readability only; do not accept or issue a proxy GET.
            with selectors.DefaultSelector() as selector:
                selector.register(sink._listener, selectors.EVENT_READ)
                _require(selector.select(120), "HTTP_READY_STARTUP_DEADLINE")
            _require(sink.observe_readiness(), "HTTP_READY_BROKER_GET_REFUSED")
        exit_code = 0
    except BaseException:
        error_code = "HTTP_READY_CHILD_REFUSED"
    try:
        _send(
            fd,
            {
                "kind": "RESULT",
                "sink": sink.result() if sink is not None else None,
                "error_code": error_code,
            },
        )
    except BaseException:
        exit_code = 1
    try:
        os.close(fd)
    except BaseException:
        exit_code = 1
    os._exit(exit_code)


def _unit():
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=Id,MainPID,ControlGroup,ActiveState,SubState",
            UNIT,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    _require(
        result.returncode == 0 and 0 < len(result.stdout) <= 4096,
        "HTTP_READY_UNIT_READ_REFUSED",
    )
    return result.stdout


def _validate_identity(identity, fixture):
    canary.validate_fixture(fixture)
    _require(
        type(identity) is dict
        and set(identity) == {"fixture", "pid", "start_time_ticks", "uid", "gid"}
        and identity["fixture"] == fixture
        and all(
            type(identity[key]) is int and 0 < identity[key] < 2**63
            for key in ("pid", "start_time_ticks", "uid", "gid")
        )
        and identity["pid"] > 1,
        "HTTP_READY_BROKER_IDENTITY_REFUSED",
    )


def _guard_broker(identity, pidfd):
    pid, fixture = identity["pid"], identity["fixture"]
    process.require_live_pidfd(pidfd)
    process._require_process_status(pid, identity["uid"], identity["gid"])
    _require(
        process._process_start_time(pid) == identity["start_time_ticks"]
        and process._process_cgroup(pid)
        == f"/docker/{fixture['container_id']}/system.slice/{UNIT}"
        and _namespace(pid)
        == {"device": fixture["netns_device"], "inode": fixture["netns_inode"]},
        "HTTP_READY_BROKER_EPOCH_CHANGED",
    )


def _listener_row(unix_raw):
    rows = [line.split() for line in unix_raw.decode("ascii").splitlines()[1:]]
    named = [row for row in rows if len(row) == 8 and row[7] == str(SOCKET)]
    _require(len(named) <= 1, "HTTP_READY_DUPLICATE_SOCKET")
    if not named:
        return None
    row = named[0]
    if row[3:6] != ["00010000", "0001", "01"]:
        return None
    _require(row[6].isdigit() and int(row[6]) > 0, "HTTP_READY_SOCKET_INODE_REFUSED")
    return row[6]


def verify_listener_witness(
    *, witness_raw, expected_raw_digest, expected_broker_identity
):
    """Replay only retained kernel reads; this does not independently recapture."""
    _require(
        type(witness_raw) is bytes
        and 0 < len(witness_raw) <= _LIMIT
        and canary.digest(witness_raw) == expected_raw_digest,
        "HTTP_READY_WITNESS_PIN_CHANGED",
    )
    value = json.loads(witness_raw)
    _require(
        canonical_json(value) == witness_raw
        and type(value) is dict
        and set(value)
        == {
            "schema",
            "broker_identity",
            "unit_raw_hex",
            "stat_raw_hex",
            "status_raw_hex",
            "cgroup_raw_hex",
            "cmdline_raw_hex",
            "unix_raw_hex",
            "network_namespace",
            "fd_links",
            "socket_metadata",
            "pidfd_pid",
            "observed_boottime_ns",
        }
        and value["schema"] == "aragorn/native-http-broker-listener-witness/v1"
        and value["broker_identity"] == expected_broker_identity,
        "HTTP_READY_WITNESS_CHANGED",
    )
    identity = expected_broker_identity
    _validate_identity(identity, identity["fixture"])
    fixture, pid = identity["fixture"], identity["pid"]
    raws = {
        name: bytes.fromhex(value[name + "_raw_hex"])
        for name in ("unit", "stat", "status", "cgroup", "cmdline", "unix")
    }
    pairs = [line.split("=", 1) for line in raws["unit"].decode("ascii").splitlines()]
    _require(
        len(pairs) == 5
        and all(len(pair) == 2 for pair in pairs)
        and dict(pairs)
        == {
            "Id": UNIT,
            "MainPID": str(pid),
            "ActiveState": "active",
            "SubState": "running",
            "ControlGroup": f"/docker/{fixture['container_id']}/system.slice/{UNIT}",
        },
        "HTTP_READY_UNIT_EPOCH_CHANGED",
    )
    stat_text = raws["stat"].decode("ascii")
    marker = stat_text.rfind(") ")
    fields = stat_text[marker + 2 :].split() if marker >= 0 else []
    _require(
        stat_text.startswith(f"{pid} (")
        and len(fields) >= 20
        and fields[19] == str(identity["start_time_ticks"]),
        "HTTP_READY_START_TIME_CHANGED",
    )
    status = [
        line.split(b":", 1) for line in raws["status"].splitlines() if b":" in line
    ]
    _require(len(dict(status)) == len(status), "HTTP_READY_STATUS_DUPLICATE")
    status = {key.decode("ascii"): val.split() for key, val in status}
    _require(
        status.get("Uid") == [str(identity["uid"]).encode()] * 4
        and status.get("Gid") == [str(identity["gid"]).encode()] * 4
        and all(
            status.get(key) == [val.encode()]
            for key, val in readiness._SECURITY.items()
        ),
        "HTTP_READY_RESTRICTIONS_CHANGED",
    )
    argv = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
        *(
            f"/run/credentials/{UNIT}/{name}"
            for name in (
                "runtime-binding",
                "capability-grant",
                "decision-measurement-binding",
            )
        ),
    ]
    _require(
        raws["cmdline"] == b"\0".join(arg.encode() for arg in argv) + b"\0"
        and raws["cgroup"]
        == f"0::/docker/{fixture['container_id']}/system.slice/{UNIT}\n".encode()
        and value["network_namespace"]
        == {"device": fixture["netns_device"], "inode": fixture["netns_inode"]}
        and type(value["pidfd_pid"]) is int
        and value["pidfd_pid"] == pid
        and type(value["observed_boottime_ns"]) is int
        and value["observed_boottime_ns"] > 0,
        "HTTP_READY_KERNEL_IDENTITY_CHANGED",
    )
    metadata = value["socket_metadata"]
    _require(
        type(metadata) is dict
        and set(metadata) == {"device", "inode", "uid", "gid", "mode"}
        and all(type(item) is int for item in metadata.values())
        and metadata["device"] >= 0
        and metadata["inode"] > 0
        and metadata["uid"] == identity["uid"]
        and metadata["gid"] == identity["gid"]
        and metadata["mode"] == 0o660,
        "HTTP_READY_SOCKET_CUSTODY_CHANGED",
    )
    inode, links = _listener_row(raws["unix"]), value["fd_links"]
    _require(
        inode is not None
        and type(links) is dict
        and 0 < len(links) <= 512
        and all(
            type(fd) is str
            and fd.isdigit()
            and type(link) is str
            and link.startswith("socket:[")
            and link.endswith("]")
            and link[8:-1].isdigit()
            for fd, link in links.items()
        )
        and f"socket:[{inode}]" in links.values(),
        "HTTP_READY_PID_DOES_NOT_OWN_LISTENER",
    )
    return {
        "schema": "aragorn/native-http-broker-listener-verification/v1",
        "same_broker_process_listener_verified": True,
        "witness_digest": expected_raw_digest,
        "limitations": [
            "POINT_IN_TIME_LOCAL_ROOT_KERNEL_READBACK",
            "NO_CONNECTION_OR_EFFECT_ATTEMPT",
        ],
        **dict.fromkeys(_FALSE, False),
    }


def _read_listener(identity, pidfd, parent):
    deadline, pid = time.monotonic() + 10, identity["pid"]
    while True:
        _guard_broker(identity, pidfd)
        try:
            metadata = os.stat(SOCKET.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        unix = _read(f"/proc/{pid}/net/unix", 49152)
        if metadata is not None and _listener_row(unix) is not None:
            break
        _require(time.monotonic() < deadline, "HTTP_READY_LISTENER_DEADLINE")
        time.sleep(0.025)  # Read-only startup observation, never a connect retry.
    _require(stat.S_ISSOCK(metadata.st_mode), "HTTP_READY_SOCKET_TYPE_CHANGED")
    links = {}
    names = os.listdir(f"/proc/{pid}/fd")
    _require(len(names) <= 512, "HTTP_READY_BROKER_FD_LIMIT")
    for name in names:
        try:
            link = os.readlink(f"/proc/{pid}/fd/{name}")
        except FileNotFoundError:
            continue
        if link.startswith("socket:["):
            links[name] = link
    unit = _unit()
    value = {
        "schema": "aragorn/native-http-broker-listener-witness/v1",
        "broker_identity": identity,
        "unit_raw_hex": unit.hex(),
        "unix_raw_hex": unix.hex(),
        "fd_links": links,
        "network_namespace": _namespace(pid),
        "pidfd_pid": pid,
        "observed_boottime_ns": _now(),
        "socket_metadata": {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
        },
        **{
            name + "_raw_hex": _read(f"/proc/{pid}/{name}").hex()
            for name in ("stat", "status", "cgroup", "cmdline")
        },
    }
    raw = canonical_json(value)
    verify_listener_witness(
        witness_raw=raw,
        expected_raw_digest=canary.digest(raw),
        expected_broker_identity=identity,
    )
    after = os.stat(SOCKET.name, dir_fd=parent, follow_symlinks=False)
    _guard_broker(identity, pidfd)
    _require(
        _unit() == unit
        and (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode)
        == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
        ),
        "HTTP_READY_LISTENER_CHANGED_DURING_READ",
    )
    return raw


def _witness(identity, pidfd):
    parent = readiness.core._open_protected_directory(
        SOCKET.parent, identity["uid"], "HTTP broker listener parent"
    )
    try:
        before = readiness.core._directory_identity(os.fstat(parent))
        raw = _read_listener(identity, pidfd, parent)
        _require(
            before
            == readiness.core._directory_identity(os.fstat(parent))
            == readiness.core._directory_identity(SOCKET.parent.lstat()),
            "HTTP_READY_SOCKET_PARENT_CHANGED",
        )
        return raw
    finally:
        primary = sys.exception()
        try:
            os.close(parent)
        except BaseException:
            if primary is None:
                raise
            primary.add_note("HTTP_READY_SOCKET_PARENT_CLOSE_FAILED")


class _Capture:
    def __init__(self, fixture, source):
        self.fixture, self.source = fixture, source
        self.pid = self.pidfd = self.reader = self.broker_pidfd = None
        self.buffer, self.consumed, self.reaped = bytearray(), False, False
        self.child_result_received = False
        self.report = {
            "schema": "aragorn/native-http-broker-ready-capture/v1",
            "status": "NOT_STARTED",
            "request": None,
            "claim": None,
            "result": None,
            "sink": None,
            "listener_witness": None,
            "verification": None,
            "listener_verification": None,
            "cleanup_complete": False,
            "cleanup_errors": [],
            **dict.fromkeys(_FALSE, False),
        }

    def _receive(self, seconds):
        deadline = time.monotonic() + seconds
        with selectors.DefaultSelector() as selector:
            selector.register(self.reader, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                left = deadline - time.monotonic()
                _require(
                    left > 0 and selector.select(left), "HTTP_READY_CHILD_READ_TIMEOUT"
                )
                chunk = os.read(self.reader, 4096)
                _require(bool(chunk), "HTTP_READY_CHILD_EARLY_EOF")
                self.buffer.extend(chunk)
                _require(len(self.buffer) <= _LIMIT, "HTTP_READY_CHILD_OUTPUT_LIMIT")
        raw, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        value = json.loads(raw)
        _require(canonical_json(value) == raw, "HTTP_READY_CHILD_ENCODING_CHANGED")
        return value

    def _child_identity(self):
        process.require_live_pidfd(self.pidfd)
        _root_process_status(self.pid)
        _require(
            process._process_cgroup(self.pid) == process._process_cgroup(os.getpid())
            and _namespace(self.pid)
            == {
                "device": self.fixture["netns_device"],
                "inode": self.fixture["netns_inode"],
            },
            "HTTP_READY_CHILD_OUTSIDE_FIXTURE",
        )
        return {
            "fixture": dict(self.fixture),
            "process": {
                "pid": self.pid,
                "start_time_ticks": process._process_start_time(self.pid),
                "uid": 0,
                "gid": 0,
            },
            "init_process": {
                "pid": 1,
                "start_time_ticks": process._process_start_time(1),
                "uid": 0,
                "gid": 0,
            },
        }

    def _reap(self, seconds):
        deadline = time.monotonic() + seconds
        while not self.reaped:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.reaped = True
                return status
            _require(time.monotonic() < deadline, "HTTP_READY_CHILD_EXIT_TIMEOUT")
            time.sleep(0.01)

    def finish(self, *, expected_broker_identity):
        _require(not self.consumed, "HTTP_READY_CAPTURE_ALREADY_CONSUMED")
        self.consumed = True
        _validate_identity(expected_broker_identity, self.fixture)
        message = self._receive(3)
        _require(
            type(message) is dict
            and set(message) == {"kind", "sink", "error_code"}
            and message["kind"] == "RESULT",
            "HTTP_READY_CHILD_PROTOCOL_CHANGED",
        )
        self.child_result_received = True
        if message["sink"] is not None:
            self.report["sink"] = _record(canonical_json(message["sink"]))
        _require(
            message["error_code"] is None and self.report["sink"] is not None,
            "HTTP_READY_CHILD_REFUSED",
        )
        status = self._reap(3)
        _require(
            status == 0 and not self.buffer and os.read(self.reader, 1) == b"",
            "HTTP_READY_CHILD_NOT_CLEAN",
        )
        binding = {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": self.fixture,
            "expected_broker_uid": expected_broker_identity["uid"],
            "expected_broker_gid": expected_broker_identity["gid"],
        }
        for role, path in (
            ("request", readiness.CREDENTIAL),
            ("claim", readiness.CLAIM),
            ("result", readiness.RESULT),
        ):
            raw, _ = readiness._read_owned(
                path,
                uid=0 if role == "request" else binding["expected_broker_uid"],
                gid=binding["expected_broker_gid"],
                mode=0o440 if role == "request" else 0o400,
            )
            self.report[role] = _record(raw)
        self.broker_pidfd = _pidfd(expected_broker_identity["pid"])
        raw = _witness(expected_broker_identity, self.broker_pidfd)
        self.report["listener_witness"] = _record(raw)
        self.report["listener_verification"] = verify_listener_witness(
            witness_raw=raw,
            expected_raw_digest=canary.digest(raw),
            expected_broker_identity=expected_broker_identity,
        )
        self.report["verification"] = verify_broker_readiness(
            **{
                role + "_raw": canonical_json(self.report[role]["document"])
                for role in ("request", "claim", "result", "sink")
            },
            expected_digests={
                role: self.report[role]["digest"]
                for role in ("request", "claim", "result", "sink")
            },
            expected_fixture_binding=binding,
            expected_broker_identity=expected_broker_identity,
            expected_sink_identity=self.sink_identity,
        )
        _require(
            self.report["listener_witness"]["document"]["observed_boottime_ns"]
            >= self.report["result"]["document"]["interval"]["finished_ns"],
            "HTTP_READY_LISTENER_PRECEDES_PROBE",
        )
        _guard_broker(expected_broker_identity, self.broker_pidfd)
        _require(
            _read_fixed(__file__, 0o444, _LIMIT) == self.source,
            "HTTP_READY_SOURCE_CHANGED",
        )
        self.report["status"] = "OBSERVED"
        return self.report

    def close(self):
        failures = self.report["cleanup_errors"]
        if self.pid is not None and not self.reaped:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except BaseException:
                failures.append("HTTP_READY_CHILD_CANCEL_FAILED")
            if not self.child_result_received and self.reader is not None:
                try:
                    message = self._receive(3)
                    if (
                        message.get("kind") == "RESULT"
                        and message.get("sink") is not None
                    ):
                        self.report["sink"] = _record(canonical_json(message["sink"]))
                        self.child_result_received = True
                except BaseException:
                    failures.append("HTTP_READY_PARTIAL_SINK_UNAVAILABLE")
            try:
                self._reap(3)
            except BaseException:
                failures.append("HTTP_READY_CHILD_REAP_FAILED")
                try:
                    os.kill(self.pid, signal.SIGKILL)
                    self._reap(3)
                except BaseException:
                    failures.append("HTTP_READY_CHILD_TERMINATION_FAILED")
        for name in ("reader", "pidfd", "broker_pidfd"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                    setattr(self, name, None)
                except BaseException:
                    failures.append("HTTP_READY_DESCRIPTOR_CLOSE_FAILED")
        _require(not failures, "HTTP_READY_CLEANUP_FAILED")


@contextmanager
def capture_broker_readiness(
    *, expected_fixture, attempt_id, readiness_nonce, expected_source_digest
):
    """Open before activation; call finish once after activation; retain after exit."""
    canary.validate_fixture(expected_fixture)
    canary.canary_bytes(attempt_id)
    canary.readiness_request(readiness_nonce)
    source = _read_fixed(__file__, 0o444, _LIMIT)
    _require(
        canary.digest(source) == expected_source_digest, "HTTP_READY_SOURCE_CHANGED"
    )
    capture, writer = _Capture(dict(expected_fixture), source), None
    try:
        with owned_http_fixture(expected_fixture) as held:
            _require(
                not any(
                    os.path.lexists(path)
                    for path in (readiness.CLAIM, readiness.RESULT)
                ),
                "HTTP_READY_ALREADY_CONSUMED",
            )
            capture.reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            capture.pid = os.fork()
            if capture.pid == 0:
                _child(writer, expected_fixture, attempt_id, readiness_nonce)
            os.close(writer)
            writer = None
            capture.pidfd = _pidfd(capture.pid)
            capture.sink_identity = capture._child_identity()
            message = capture._receive(3)
            if type(message) is dict and message.get("kind") == "RESULT":
                capture.child_result_received = True
                if message.get("sink") is not None:
                    capture.report["sink"] = _record(canonical_json(message["sink"]))
            _require(
                message == {"kind": "LISTENING", "identity": capture.sink_identity}
                and capture._child_identity() == capture.sink_identity,
                "HTTP_READY_SINK_IDENTITY_CHANGED",
            )
            capture.report["status"] = "LISTENING"
            try:
                yield capture
                _require(
                    capture.consumed and capture.report["status"] == "OBSERVED",
                    "HTTP_READY_CAPTURE_UNFINISHED",
                )
                held.guard()
                _require(
                    _read_fixed(__file__, 0o444, _LIMIT) == source,
                    "HTTP_READY_SOURCE_CHANGED",
                )
            finally:
                primary = sys.exception()
                try:
                    capture.close()
                except BaseException:
                    if primary is None:
                        raise
                    primary.add_note("HTTP_READY_CLEANUP_FAILED")
        capture.report["cleanup_complete"] = True
    except BaseException as error:
        capture.report["status"] = "REFUSED"
        error.http_broker_readiness_observation = capture.report
        raise
    finally:
        primary = sys.exception()
        try:
            if writer is not None:
                os.close(writer)
            capture.close()
        except BaseException as error:
            capture.report["cleanup_complete"] = False
            capture.report["status"] = "REFUSED"
            if primary is not None:
                primary.add_note("HTTP_READY_FINAL_CLEANUP_FAILED")
            else:
                error.http_broker_readiness_observation = capture.report
                raise
