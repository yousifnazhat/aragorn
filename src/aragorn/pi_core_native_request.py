"""One-shot native Pi request routing under the supervisor's held custody.

No provider, legacy endpoint or service launcher is enabled here. The fixed new
socket lives beneath the already projected bootstrap directory. Native bootstrap
currently produces no requests; NO_REQUEST is not a useful-task qualification.
Borrowed supervisor/worker/control handles are never closed by this module.
"""

from __future__ import annotations

import json
import math
import os
import select
import socket
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import pi_core_native_supervisor as native
from . import pi_core_confined_launch as confined
from . import pi_core_identity_handoff as channel
from . import pi_core_request_handoff as handoff
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_worker as worker
from .oci_worker_protocol import canonical_json
from .pi_core_sensor_channel import PiSensorChannel

REQUEST_DIRECTORY = Path("/run/aragorn-pi-bootstrap/requests")
REQUEST_SOCKET = REQUEST_DIRECTORY / "request.sock"
_SEAL = object()
_CONSUME_LOCK = threading.Lock()


class PiNativeRequestError(RuntimeError):
    """Native request routing refused or cleanup must be held."""


def _require(value, reason):
    if not value:
        raise PiNativeRequestError(reason)


@dataclass(frozen=True, slots=True)
class PiNativeRequestChannels:
    broker_connection: socket.socket
    sensor_connection: socket.socket
    broker_peer: tuple[int, int, int]
    sensor_peer: tuple[int, int, int]
    binding: worker.RuntimeActionWorkerBinding


def _plan(owned, deadline):
    _require(os.geteuid() == os.getegid() == 0 and type(owned) is native._Owned,
             "native request requires actual root-owned supervisor custody")
    plan = owned.plan
    _require(type(plan) is confined.PiConfinedLaunchPlan and plan._lease.active and
             plan.prepared._lease.active and type(deadline) in (int, float) and deadline <= plan.deadline,
             "native request requires the held original launch plan")
    channel.validate_deadline(deadline)
    _require(owned.directory_fd >= 0 and owned.run_fd >= 0 and owned.directory_identity and
             owned.listener is not None and owned.socket_identity,
             "native bootstrap namespace is not held")
    return plan


def _channels(owned, config, deadline, request_connection=None):
    _plan(owned, deadline)
    _require(type(config) is PiNativeRequestChannels and type(config.binding) is worker.RuntimeActionWorkerBinding,
             "native request channels or binding are invalid")
    peers = (channel._peer(config.broker_peer), channel._peer(config.sensor_peer))
    _require(all(uid > 0 and gid > 0 and pid != os.getpid() for pid, uid, gid in peers),
             "native broker and sensor require separate nonroot service identities")
    _require(peers[0][0] != peers[1][0] and len({peers[0][1], peers[1][1], owned.plan.worker_uid}) == 3 and
             len({peers[0][2], peers[1][2], owned.plan.worker_gid}) == 3,
             "native worker, sensor and broker roles overlap")
    connections = [config.broker_connection, config.sensor_connection, owned.listener]
    if owned.connection is not None:
        connections.append(owned.connection)
    if request_connection is not None:
        connections.append(request_connection)
    dispatch = getattr(owned, "_pi_request_dispatch", None)
    if type(dispatch) is PiNativeRequestDispatch and dispatch.listener is not None:
        connections.append(dispatch.listener)
    descriptors = [connection.fileno() for connection in connections]
    _require(all(type(fd) is int and fd >= 0 for fd in descriptors) and
             len(set(descriptors)) == len(descriptors) and len({id(connection) for connection in connections}) == len(connections),
             "native channels alias or are closed")
    for connection, peer in zip((config.broker_connection, config.sensor_connection), peers):
        _require(connection.getsockopt(socket.SOL_SOCKET, channel._DOMAIN) == socket.AF_UNIX and
                 connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET and
                 tuple(broker._peer_credentials(connection)) == peer,
                 "native protected channel type or actual peer differs")
    if owned.pid:
        _require(all(peer[0] != owned.pid for peer in peers), "native control peer aliases Pi")


class PiNativeRequestCustody:
    """Local guard minted only by this exact held-native adapter, never wire JSON."""

    __slots__ = ("_seal", "_owned", "_dispatch", "_request", "_channels", "_activation", "_pins", "_active", "_deadline")

    def __init__(self, seal=None, *, owned=None, dispatch=None, request=None, channels=None, deadline=None):
        _require(seal is _SEAL, "native request custody requires its protected factory")
        self._seal, self._owned, self._dispatch = seal, owned, dispatch
        self._request, self._channels, self._deadline = request, channels, deadline
        self._activation = identity.validate_activation(broker._parse_canonical_document(owned.activation_raw, "native Pi activation"))
        self._pins = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                      owned.immutable_digest, owned.connection, owned.activation_raw)
        self._active = True

    @property
    def deadline(self):
        return self._deadline

    def guard(self):
        owned = self._owned
        _require(type(self) is PiNativeRequestCustody and self._seal is _SEAL and self._active,
                 "native request custody is not active")
        _plan(owned, self._deadline)
        _require(owned.plan is self._pins[0] and
                 (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                  owned.immutable_digest, owned.connection, owned.activation_raw) == self._pins and
                 owned.started and owned.start_attempted and not owned.exit_observed and
                 owned.request_dispatch_active and getattr(owned, "_pi_request_dispatch", None) is self._dispatch,
                 "native request custody was withdrawn or changed")
        _channels(owned, self._channels, self._deadline, self._request)
        self._dispatch._ownership()
        native._same_generation(owned, native._unit_state(owned.plan.unit_name, self._deadline), self._deadline, live=True)
        _require(identity.read_activation(owned.plan.activation_path) == self._activation,
                 "native request activation changed")
        identity._measured(owned.connection, owned.pidfd, owned.plan.profile, self._activation, self._deadline)
        identity._measured(self._request, owned.pidfd, owned.plan.profile, self._activation, self._deadline)


def handle_native_pi_request(owned, worker_connection, request_channels, *, grant, protected_root, deadline):
    """Consume one actual Pi stream while the exact supervisor-owned unit lives."""
    plan = _plan(owned, deadline)
    _channels(owned, request_channels, deadline, worker_connection)
    dispatch = getattr(owned, "_pi_request_dispatch", None)
    _require(type(dispatch) is PiNativeRequestDispatch and dispatch.owned is owned and
             dispatch.channels is request_channels and dispatch.active and owned.request_dispatch_active and
             deadline == dispatch._action_deadline,
             "native request dispatch scope is not held")
    _require(owned.started and owned.start_attempted and owned.pid > 0 and owned.pidfd >= 0 and
             owned.cgroup_fd >= 0 and owned.cgroup_parent_fd >= 0 and owned.activation_fd >= 0 and
             owned.activation_raw is not None and owned.activation_identity and owned.invocation and
             owned.immutable_digest and owned.connection is not None,
             "native request lacks installed activation and independent unit custody")
    _require(protected_root == Path("/var/lib/aragorn/admitted") and
             worker_connection.getsockopt(socket.SOL_SOCKET, channel._DOMAIN) == socket.AF_UNIX and
             worker_connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
             "native Pi request root or accepted stream differs")
    with _CONSUME_LOCK:
        _require(not owned.request_attempted, "native Pi request already attempted; no retry")
        owned.request_attempted = True
    custody = PiNativeRequestCustody(_SEAL, owned=owned, dispatch=dispatch,
        request=worker_connection, channels=request_channels, deadline=deadline)
    try:
        custody.guard()
        return handoff.handle_pi_request_connection(worker_connection, request_channels.broker_connection,
            activation_path=plan.activation_path, profile=plan.profile, protected_install_root=protected_root,
            grant=grant, binding=request_channels.binding, expected_broker_peer=request_channels.broker_peer,
            deadline=deadline, sensor_channel=PiSensorChannel(request_channels.sensor_connection, request_channels.sensor_peer),
            native_custody=custody)
    finally:
        custody._active = False


class PiNativeRequestDispatch:
    """Owned request endpoint with a bounded bootstrap/request selection loop."""

    def __init__(self, seal, owned, channels, grant, protected_root, deadline, cleanup_deadline=None):
        _require(seal is _SEAL, "native request dispatch requires protected factory")
        cleanup_deadline = deadline if cleanup_deadline is None else cleanup_deadline
        _require(type(deadline) in (int, float) and math.isfinite(deadline) and
                 type(cleanup_deadline) in (int, float) and math.isfinite(cleanup_deadline) and
                 deadline <= cleanup_deadline <= deadline + 5, "native request cleanup budget differs")
        self.owned, self.channels, self.grant = owned, channels, json.loads(canonical_json(grant))
        self.protected_root, self.deadline = protected_root, deadline
        self._action_deadline, self.cleanup_deadline = deadline, cleanup_deadline
        self.directory_fd = -1
        self.directory_identity = self.socket_identity = ()
        self.created = False
        self.listener = None
        self.accepted = None
        self.active = False
        self.closed = False
        self._close_failure = None
        self._remote_custody_hold = False
        self._observation = {"schema": "aragorn/pi-core-native-request-observation/v1",
            "status": "NO_REQUEST", "request_attempted": False, "worker_result": None,
            "cleanup": "NOT_ATTEMPTED", "phase3_exit_eligible": False}

    @property
    def observation(self):
        return json.loads(canonical_json(self._observation))

    def _ownership(self):
        native._resource_ownership(self.owned)
        _require(self.created and self.directory_fd >= 0 and self.directory_identity,
                 "request directory custody is incomplete")
        held = os.fstat(self.directory_fd)
        named = os.stat("requests", dir_fd=self.owned.directory_fd, follow_symlinks=False)
        _require(broker._directory_identity(held) == self.directory_identity == broker._directory_identity(named),
                 "native request directory replaced")
        expected = ["request.sock"] if self.socket_identity else []
        _require(sorted(os.listdir(self.directory_fd)) == expected, "native request directory has unowned residue")
        if self.socket_identity:
            value = os.stat("request.sock", dir_fd=self.directory_fd, follow_symlinks=False)
            _require(broker._file_identity(value) == self.socket_identity, "native request socket replaced")

    def _open(self):
        _plan(self.owned, self.deadline)
        _channels(self.owned, self.channels, self.deadline)
        _require(not self.owned.request_dispatch_active and getattr(self.owned, "_pi_request_dispatch", None) is None,
                 "native request dispatch already exists")
        native._resource_ownership(self.owned)
        os.mkdir("requests", mode=0o711, dir_fd=self.owned.directory_fd)  # Never adopt/repair an existing name.
        self.created = True
        self.owned.request_dispatch_active = True
        self.owned._pi_request_dispatch = self
        self.directory_fd = os.open("requests", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=self.owned.directory_fd)
        before = os.fstat(self.directory_fd)
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0, "new request directory is not root-owned")
        os.fchown(self.directory_fd, 0, self.owned.plan.worker_gid)
        os.fchmod(self.directory_fd, 0o711)
        after = os.fstat(self.directory_fd)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_uid == 0 and
                 after.st_gid == self.owned.plan.worker_gid and stat.S_IMODE(after.st_mode) == 0o711,
                 "new request directory metadata differs")
        self.directory_identity = broker._directory_identity(after)
        self._ownership()
        os.fsync(self.directory_fd)
        os.fsync(self.owned.directory_fd)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.listener.bind(f"/proc/self/fd/{self.directory_fd}/request.sock")
        before = os.stat("request.sock", dir_fd=self.directory_fd, follow_symlinks=False)
        _require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
                 "new request endpoint is not an owned socket")
        os.chown("request.sock", 0, self.owned.plan.worker_gid, dir_fd=self.directory_fd, follow_symlinks=False)
        os.chmod("request.sock", 0o660, dir_fd=self.directory_fd, follow_symlinks=False)
        after = os.stat("request.sock", dir_fd=self.directory_fd, follow_symlinks=False)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_uid == 0 and
                 after.st_gid == self.owned.plan.worker_gid and stat.S_IMODE(after.st_mode) == 0o660 and after.st_nlink == 1,
                 "native request endpoint metadata differs")
        self.socket_identity = broker._file_identity(after)
        self._ownership()
        os.fsync(self.directory_fd)
        self.listener.listen(1)
        self.active = True

    def _close_accepted(self):
        if self.accepted is not None:
            connection, self.accepted = self.accepted, None
            try:
                connection.close()  # A shared stream is never shutdown here.
            except Exception as exc:
                self._close_failure = exc
                self._observation["cleanup"] = "CLEANUP_HOLD"
                raise

    def read_bootstrap_result(self, connection, deadline):
        _require(self.active and not self.closed and connection is self.owned.connection and
                 type(deadline) in (int, float) and deadline <= self._action_deadline,
                 "native request result reader is not the held bootstrap scope")
        self._action_deadline = deadline  # May tighten; never renew the action budget.
        while True:
            _plan(self.owned, deadline)
            self._ownership()
            ready, _, _ = select.select([connection, self.listener], [], [], native._remaining(deadline))
            _require(ready, "native request/bootstrap deadline expired")
            if self.listener in ready:
                _require(not self.owned.request_attempted and not self._observation["request_attempted"],
                         "native request limit reached; no retry")
                self.listener.settimeout(native._remaining(deadline))
                self.accepted, _ = self.listener.accept()
                self._observation["request_attempted"] = True
                self._observation["status"] = "REQUEST_ATTEMPTED"
                self._remote_custody_hold = True
                try:
                    result = handle_native_pi_request(self.owned, self.accepted, self.channels,
                        grant=self.grant, protected_root=self.protected_root, deadline=deadline)
                    self._observation["worker_result"] = result
                    _require(type(result) is dict and result.get("status") == "COMPLETED",
                             "native request did not establish complete broker and sensor cleanup")
                    self._remote_custody_hold = False
                    self._observation.update(status="REQUEST_RETURNED", worker_result=result)
                except Exception as exc:
                    # A local result/refusal cannot prove that a transferred
                    # remote duplicate was closed. Prevent RELEASE and retain
                    # uncertainty even if local request resources clean up.
                    self._remote_custody_hold = True
                    self._observation.update(status="REQUEST_INDETERMINATE", cleanup="CLEANUP_HOLD")
                    error = PiNativeRequestError("native request/sensor completion is unconfirmed")
                    error.observation = self.observation
                    raise error from exc
                finally:
                    self._close_accepted()
                continue
            _require(connection in ready, "native request selector returned an unknown handle")
            return confined._read_bootstrap(connection, deadline)

    def close(self):
        if self.closed:
            return
        self.closed, self.active = True, False
        failure = self._close_failure or (PiNativeRequestError("remote sensor custody is unconfirmed")
                                         if self._remote_custody_hold else None)
        try:
            self._close_accepted()
            if self.created:
                native._remaining(self.cleanup_deadline)
                self._ownership()
                if self.listener is not None:
                    listener, self.listener = self.listener, None
                    listener.close()
                if self.socket_identity:
                    native._remaining(self.cleanup_deadline)
                    os.unlink("request.sock", dir_fd=self.directory_fd)
                    os.fsync(self.directory_fd)
                    _require(native._missing(self.directory_fd, "request.sock"), "native request socket remains")
                    self.socket_identity = ()
                self._ownership()
                native._remaining(self.cleanup_deadline)
                os.rmdir("requests", dir_fd=self.owned.directory_fd)
                os.fsync(self.owned.directory_fd)
                _require(native._missing(self.owned.directory_fd, "requests"), "native request directory remains")
                self.owned.request_dispatch_active = False
                del self.owned._pi_request_dispatch
                native._resource_ownership(self.owned)
            self._observation["cleanup"] = "VERIFIED_OWNED_REQUEST_CLEANUP"
        except Exception as exc:
            failure = exc
            self._observation["cleanup"] = "CLEANUP_HOLD"
        finally:
            for name in ("listener", "directory_fd"):
                value = getattr(self, name)
                setattr(self, name, None if name == "listener" else -1)
                try:
                    if name == "listener" and value is not None:
                        value.close()
                    elif name == "directory_fd" and value >= 0:
                        os.close(value)
                except Exception as exc:
                    failure = failure or exc
                    self._observation["cleanup"] = "CLEANUP_HOLD"
        if failure is not None:
            self._observation["cleanup"] = "CLEANUP_HOLD"
            error = PiNativeRequestError("native request cleanup is unconfirmed; preserve owned resources")
            error.observation = self.observation
            raise error from failure


@contextmanager
def hold_native_pi_request_dispatch(owned, request_channels, *, grant, protected_root, deadline, cleanup_deadline=None):
    dispatch = PiNativeRequestDispatch(_SEAL, owned, request_channels, grant, protected_root, deadline, cleanup_deadline)
    try:
        dispatch._open()
        yield dispatch
    finally:
        dispatch.close()
