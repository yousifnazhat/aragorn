"""Held authentication for three already-connected post-exec service channels.

No listener, connection, socketpair, process or readiness exchange is created.
The caller owns all sockets. This scope owns only new peer PIDFDs and pins the
actual peer/start/cgroup/interpreter to separately approved expectations and a
held installed-runtime closure. This is not loaded Python, unit-generation,
application readiness, effect authority or process-exit proof.

Sensor FSUID/FSGID intentionally differs while measuring Pi. The existing sensor
handler enforces its filesystem identity/capability policy; this channel layer
does not falsely require all four process UID/GID columns to match the sensor.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import socket
import sys
import threading

from . import pi_core_identity_handoff as transport
from . import pi_core_service_provision as provision
from . import runtime_action_broker as broker
from . import runtime_process_profile as process
from .pi_core_native_request import PiNativeRequestChannels
from .runtime_action_worker import RuntimeActionWorkerBinding
from .oci_worker_protocol import canonical_digest, canonical_json

_ROLES = ("action", "sensor", "provider")
_PROCESS_FIELDS = {"pid", "uid", "gid", "start_ticks", "cgroup", "executable_digest"}
_PINS = ("runtime_closure_digest", "binding_digest", "receipt_digest", "python_digest")
_SEAL = object()


class PiServiceChannelsError(RuntimeError):
    """Channel custody refused; no retry, service readiness or cleanup waiver."""


def _require(value, message):
    if not value:
        raise PiServiceChannelsError(message)


def _copy(value):
    return json.loads(canonical_json(value))


def _binding(value):
    _require(type(value) is RuntimeActionWorkerBinding, "service worker binding is invalid")
    for digest in (value.runtime_digest, value.active_skill_digest, value.policy_digest):
        _require(type(digest) is str and transport._DIGEST.fullmatch(digest), "service worker pin is invalid")
    _require(type(value.policy_version) is int and 0 < value.policy_version < 2**53,
             "service worker policy version is invalid")
    return value


def _expectations(value):
    _require(type(value) is dict and set(value) == set(_ROLES), "exact action/sensor/provider expectations required")
    for role in _ROLES:
        expected = value[role]
        _require(type(expected) is dict and set(expected) == _PROCESS_FIELDS, "service process fields differ")
        for field in ("pid", "uid", "gid", "start_ticks"):
            maximum = 2**63 if field == "start_ticks" else 2**31
            _require(type(expected[field]) is int and 0 < expected[field] < maximum,
                     "service process identity is invalid")
        _require(expected["pid"] != os.getpid(), "service peer aliases the root supervisor")
        process._cgroup_path(expected["cgroup"])
        _require(type(expected["executable_digest"]) is str and
                 transport._DIGEST.fullmatch(expected["executable_digest"]), "service interpreter pin is invalid")
    for field in ("pid", "uid", "gid", "cgroup"):
        _require(len({value[role][field] for role in _ROLES}) == 3, "service process roles overlap")
    return _copy(value)


def _deployment_pins(deployment, deadline):
    _require(type(deployment) is provision.PiServiceRuntime, "held service runtime custody is required")
    transport.validate_deadline(deadline)
    _require(deadline <= deployment.deadline, "service channels extend the held runtime deadline")
    deployment.guard(deadline=deadline)
    observed = deployment.observation
    _require(type(observed) is dict, "service runtime metadata is invalid")
    pins = {key: observed.get(key) for key in _PINS}
    _require(all(type(value) is str and transport._DIGEST.fullmatch(value) for value in pins.values()),
             "service runtime pins are incomplete")
    transport.validate_deadline(deadline)
    return pins


def _observe(deadline, operation, *arguments):
    # Frozen process readers have byte/count bounds but no deadline parameter.
    # Bracket each individual read with this call's budget, never the lease's
    # longer deadline. This does not claim preemption of a blocked kernel read.
    transport.validate_deadline(deadline)
    observed = operation(*arguments)
    transport.validate_deadline(deadline)
    return observed


class PiServiceChannels:
    """Scoped channel custody, never constructible from ordinary wire metadata."""

    __slots__ = ("_seal", "_active", "_connections", "_descriptors", "_expected", "_binding",
                 "_deployment", "_pins", "_deadline", "_pidfds", "_request_channels",
                 "_provider_retired", "_provider_retiring", "_cleanup", "_lock", "_lifecycle")

    def __init__(self, seal, connections, expected, binding, deployment, pins, deadline, lifecycle_custody=None):
        _require(seal is _SEAL, "service channel custody requires its protected factory")
        self._seal, self._active = seal, True
        self._connections = tuple(connections[role] for role in _ROLES)
        self._descriptors = tuple(connection.fileno() for connection in self._connections)
        self._expected, self._binding = expected, binding
        self._deployment, self._pins, self._deadline = deployment, pins, deadline
        self._pidfds, self._request_channels = [], None
        self._provider_retired, self._cleanup = False, "HELD"
        self._provider_retiring = False
        self._lock = threading.RLock()
        self._lifecycle = lifecycle_custody

    @property
    def deadline(self):
        return self._deadline

    @property
    def request_channels(self):
        return self._request_channels

    @property
    def provider_connection(self):
        return self._connections[2]

    @property
    def provider_peer(self):
        item = self._expected["provider"]
        return item["pid"], item["uid"], item["gid"]

    @property
    def provider_retired(self):
        return self._provider_retired

    @property
    def observation(self):
        return _copy({"schema": "aragorn/pi-core-service-channels/v1",
            "authority": "AUTHENTICATED_CHANNEL_CUSTODY_NOT_LOADED_CODE_OR_SERVICE_READINESS",
            "expected_processes_digest": canonical_digest(self._expected), **self._pins,
            "active": self._active, "provider_retired": self._provider_retired, "cleanup": self._cleanup,
            "service_ready": False, "unit_lifetime_verified": False, "loaded_code_verified": False,
            "phase3_exit_eligible": False})

    def _check(self, *, deadline=None, allow_provider_exit=False):
        _require(type(self) is PiServiceChannels and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "service channel lease is inactive")
        _require(type(allow_provider_exit) is bool and
                 allow_provider_exit is self._provider_retiring and
                 not (allow_provider_exit and self._provider_retired),
                 "provider exit exception requires the one-shot retirement transition")
        _require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0,
                 "service channel custody requires the Linux root supervisor")
        bounded = self._deadline if deadline is None else deadline
        transport.validate_deadline(bounded)
        _require(bounded <= self._deadline, "service guard cannot extend its held channel deadline")
        if self._lifecycle is not None:
            from .pi_core_service_lifecycle import PiServiceLifecycle
            _require(type(self._lifecycle) is PiServiceLifecycle, "service lifecycle custody differs")
            self._lifecycle.guard_inputs_and_units(self, deadline=bounded,
                                                   allow_provider_exit=allow_provider_exit)
        _require(_deployment_pins(self._deployment, bounded) == self._pins,
                 "installed service runtime custody changed")
        _require(len(self._pidfds) == 3 and len(set(self._pidfds)) == 3,
                 "service peer PIDFD inventory is incomplete")
        for index, role in enumerate(_ROLES):
            transport.validate_deadline(bounded)
            connection, expected = self._connections[index], self._expected[role]
            peer = expected["pid"], expected["uid"], expected["gid"]
            _require(connection.fileno() == self._descriptors[index] and
                     connection.getsockopt(socket.SOL_SOCKET, transport._DOMAIN) == socket.AF_UNIX and
                     connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET and
                     tuple(broker._peer_credentials(connection)) == peer,
                     "service channel descriptor, type or kernel peer changed")
            if role == "provider" and (self._provider_retired or allow_provider_exit):
                continue  # Exact authenticated terminal custody only, never new egress authority.
            transport.require_peer_live(connection, peer, self._pidfds[index], bounded)
            _require(_observe(bounded, process._process_start_time, peer[0]) == expected["start_ticks"] and
                     _observe(bounded, process._process_cgroup, peer[0]) == expected["cgroup"] and
                     _observe(bounded, process._cgroup_processes, expected["cgroup"]) == (peer[0],) and
                     _observe(bounded, process._executable_digest, peer[0]) == expected["executable_digest"] == self._pins["python_digest"],
                     "service process generation, cgroup or interpreter differs")
            _require(_observe(bounded, process._process_start_time, peer[0]) == expected["start_ticks"] and
                     _observe(bounded, process._process_cgroup, peer[0]) == expected["cgroup"] and
                     _observe(bounded, process._cgroup_processes, expected["cgroup"]) == (peer[0],),
                     "service process changed while measured")
            transport.require_peer_live(connection, peer, self._pidfds[index], bounded)
        transport.validate_deadline(bounded)

    def guard(self, *, deadline=None):
        """Use a narrower per-call budget without changing the held lease."""
        _require(type(self) is PiServiceChannels and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "service channel lease is inactive")
        with self._lock:
            self._check(deadline=deadline)

    def retire_provider(self, *, deadline=None):
        """Root calls ONLY after validating the exact authenticated RESULT.

        The provider may already have exited. Retirement is irreversible, keeps
        the peer PIDFD until scope cleanup and must prohibit every future provider
        entry/CHECK in the caller. It does not attest process exit or unit cleanup.
        """
        _require(type(self) is PiServiceChannels and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "service channel lease is inactive")
        with self._lock:
            _require(not self._provider_retired and not self._provider_retiring,
                     "provider channel is already terminal or retiring")
            self._provider_retiring = True
            try:
                self._check(deadline=deadline, allow_provider_exit=True)
            finally:
                self._provider_retiring = False
            self._provider_retired = True

    def _close(self):
        with self._lock:
            if self._cleanup != "HELD":
                _require(self._cleanup == "OWNED_PEER_PIDFDS_CLOSED_NOT_SERVICE_EXIT",
                         "service PIDFD cleanup already failed; no retry")
                return
            self._active = False  # Revoke before touching owned handles.
            descriptors, self._pidfds = self._pidfds, []
            self._cleanup = "CLEANUP_HOLD"
            transport._close_installed(descriptors)
            self._cleanup = "OWNED_PEER_PIDFDS_CLOSED_NOT_SERVICE_EXIT"


@contextmanager
def hold_pi_service_channels(connections, expected_processes, binding, *, deployment, deadline,
                             lifecycle_custody=None):
    """Authenticate borrowed post-exec sockets; close only newly acquired PIDFDs."""
    _require(sys.platform == "linux" and os.geteuid() == os.getegid() == 0,
             "service channel custody requires the Linux root supervisor")
    transport.validate_deadline(deadline)
    expected = _expectations(expected_processes)
    _binding(binding)
    pins = _deployment_pins(deployment, deadline)
    _require(all(item["executable_digest"] == pins["python_digest"] for item in expected.values()),
             "expected service executable differs from protected Python pin")
    _require(type(connections) is dict and set(connections) == set(_ROLES), "exact service channels required")
    selected = tuple(connections[role] for role in _ROLES)
    descriptors = tuple(connection.fileno() for connection in selected)
    _require(len({id(connection) for connection in selected}) == 3 and
             all(type(fd) is int and fd >= 0 for fd in descriptors) and len(set(descriptors)) == 3,
             "service channels alias or are closed")
    lease = PiServiceChannels(_SEAL, connections, expected, binding, deployment, pins, deadline, lifecycle_custody)
    failure = None
    try:
        if lifecycle_custody is not None:
            from .pi_core_service_lifecycle import PiServiceLifecycle
            _require(type(lifecycle_custody) is PiServiceLifecycle, "exact service lifecycle custody required")
            lifecycle_custody._attach_channels(lease)
        for role, connection in zip(_ROLES, selected):
            item = expected[role]
            descriptor = transport.guard_channel(connection, (item["pid"], item["uid"], item["gid"]), deadline)
            _require(type(descriptor) is int and descriptor >= 0 and descriptor not in descriptors and
                     descriptor not in lease._pidfds, "new service PIDFD aliases an existing handle")
            lease._pidfds.append(descriptor)
            _require(not os.get_inheritable(descriptor), "service PIDFD must be close-on-exec")
        lease._request_channels = PiNativeRequestChannels(selected[0], selected[1],
            tuple(expected["action"][key] for key in ("pid", "uid", "gid")),
            tuple(expected["sensor"][key] for key in ("pid", "uid", "gid")), binding, service_custody=lease)
        lease.guard()
        yield lease
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            lease._close()
        except BaseException as error:
            error.pi_service_channel_observation = lease.observation
            raise
        finally:
            if failure is not None:
                failure.pi_service_channel_observation = lease.observation
