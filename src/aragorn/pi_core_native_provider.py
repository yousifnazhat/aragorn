"""One owned Pi provider endpoint; no activation, credentials or API client here.

The supervisor lends its exact service lifetime. This adapter owns only the
worker-facing stream, delegates the protected data operation to the existing
mediator, and never closes or replaces the broker/sensor/provider channels.
"""

from __future__ import annotations

import json
import math
import os
import socket
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import pi_core_identity_handoff as channel
from . import pi_core_native_request as request
from . import pi_core_native_supervisor as native
from . import pi_core_provider_mediation as mediation
from . import pi_core_source_observer as source
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_service_channels import PiServiceChannels
from .pi_core_service_lifecycle import PiServiceLifecycle

PROVIDER_DIRECTORY = Path("/run/aragorn-pi-bootstrap/provider")
PROVIDER_SOCKET = PROVIDER_DIRECTORY / "provider.sock"
_SEAL = object()
_CONSUME_LOCK = threading.Lock()


class PiNativeProviderError(RuntimeError):
    """Provider routing refused, or owned cleanup remains unconfirmed."""


def _require(value, reason):
    if not value:
        raise PiNativeProviderError(reason)


@dataclass(frozen=True, slots=True)
class PiNativeProviderChannels:
    config: broker.RuntimeActionBrokerConfig
    services: PiServiceChannels
    approval: object = None


def _expected_request(plan):
    start = broker._parse_canonical_document(plan.start_bytes, "native provider START")
    _require(type(start) is dict and start.get("schema") == "aragorn/pi-core-bootstrap-start/v3" and
             start.get("provider_status") == "PROTECTED", "provider requires explicitly protected START")
    limits, provider = start.get("limits"), start.get("provider")
    _require(type(limits) is dict and type(limits.get("maxTurns")) is int and limits["maxTurns"] == 1 and
             type(limits.get("maxToolCalls")) is int and limits["maxToolCalls"] == 1 and
             type(limits.get("maxRunMs")) is int and limits["maxRunMs"] > 0 and
             type(provider) is dict and set(provider) == {"route_digest", "max_requests", "request_timeout_ms"} and
             type(provider["max_requests"]) is int and provider["max_requests"] == 1 and
             type(provider["request_timeout_ms"]) is int and provider["request_timeout_ms"] == limits["maxRunMs"],
             "native provider budgets differ from the held START")
    return mediation.validate_provider_request({"schema": mediation.REQUEST_SCHEMA,
        "authority": mediation.REQUEST_AUTHORITY, "activation_id": start.get("activation_id"),
        "route_digest": provider["route_digest"], "sequence": 1,
        "payload": {"schema": "aragorn/pi-core-provider-payload/v1", "model": start.get("model"),
            "messages": [{"role": "system", "content": start.get("system_prompt"), "timestamp": 0,
                          "toolsAdded": [mediation._TOOL]},
                         {"role": "user", "content": [{"type": "text", "text": start.get("task")}], "timestamp": 0}]}})


class PiNativeProviderDispatch:
    """A single attempt under held launch, process, source and service custody."""

    def __init__(self, seal, owned, channels, grant, protected_root, deadline, cleanup_deadline=None):
        _require(seal is _SEAL, "native provider dispatch requires its protected factory")
        cleanup_deadline = deadline if cleanup_deadline is None else cleanup_deadline
        _require(type(deadline) in (int, float) and math.isfinite(deadline) and
                 type(cleanup_deadline) in (int, float) and math.isfinite(cleanup_deadline) and
                 deadline <= cleanup_deadline <= deadline + 5, "native provider cleanup budget differs")
        self._seal, self.owned, self.channels = seal, owned, channels
        self.grant = json.loads(canonical_json(grant))
        self.protected_root, self.deadline, self.cleanup_deadline = protected_root, deadline, cleanup_deadline
        self._plan = owned.plan
        self._expected = _expected_request(self._plan)
        self._channel_pin = channels
        self._start_bytes = self._plan.start_bytes
        self._activation = self._pins = self._observer = None
        self.directory_fd = -1
        self.directory_identity = self.socket_identity = ()
        self.created = self.active = self.closed = False
        self.listener = self.accepted = None
        self._accepted_close_attempted = self._close_failure = None
        self._remote_custody_hold = False
        self._observation = {"schema": "aragorn/pi-core-native-provider-observation/v1",
            "authority": "HELD_PROVIDER_DISPATCH_NOT_USEFUL_PILOT_OR_QUALIFICATION",
            "status": "NO_PROVIDER_REQUEST", "provider_attempted": False,
            "provider_result": None, "cleanup": "NOT_ATTEMPTED", "phase3_exit_eligible": False}

    @property
    def observation(self):
        return json.loads(canonical_json(self._observation))

    def _channels(self, deadline):
        plan = request._plan(self.owned, deadline)
        _require(plan is self._plan and plan.start_bytes == self._start_bytes and
                 self.channels is self._channel_pin and type(self.channels) is PiNativeProviderChannels,
                 "native provider launch or channels changed")
        channels, config = self.channels.services, self.channels.config
        _require(type(channels) is PiServiceChannels and type(channels._lifecycle) is PiServiceLifecycle and
                 channels.request_channels.service_custody is channels and deadline <= channels.deadline and
                 type(config) is broker.RuntimeActionBrokerConfig and config.expected_broker_uid == 0,
                 "native provider requires the exact owned service lifetime and root policy")
        broker._validate_config(config)
        if self.channels.approval is not None:
            from .pi_core_provider_approval import PiProviderApproval
            approval = self.channels.approval
            _require(type(approval) is PiProviderApproval and approval.config == config and
                     approval.route_digest == self._expected["route_digest"],
                     "native provider approval differs from held routing")
            approval.guard(deadline=deadline)
        _require(self.protected_root == Path("/var/lib/aragorn/admitted") and
                 (config.expected_runtime_uid, config.expected_runtime_gid) == (plan.worker_uid, plan.worker_gid) and
                 config.expected_runtime_digest == plan.profile.runtime_digest,
                 "native provider policy differs from the held worker")
        request._channels(self.owned, channels.request_channels, deadline)
        peers = (channels.request_channels.broker_peer, channels.request_channels.sensor_peer,
                 channel._peer(channels.provider_peer))
        _require(len({peer[0] for peer in peers}) == 3 and
                 len({peer[1] for peer in peers} | {plan.worker_uid, 0}) == 5 and
                 len({peer[2] for peer in peers} | {plan.worker_gid, 0}) == 5 and
                 all(peer[0] not in {os.getpid(), self.owned.pid} for peer in peers),
                 "native provider service roles overlap")
        handles = [channels.request_channels.broker_connection, channels.request_channels.sensor_connection,
                   channels.provider_connection, self.owned.listener]
        handles += [value for value in (self.owned.connection, self.listener, self.accepted) if value is not None]
        sibling = getattr(self.owned, "_pi_request_dispatch", None)
        if type(sibling) is request.PiNativeRequestDispatch:
            handles += [value for value in (sibling.listener, sibling.accepted) if value is not None]
        fds = [handle.fileno() for handle in handles]
        _require(all(type(fd) is int and fd >= 0 for fd in fds) and len(set(fds)) == len(fds) and
                 len({id(handle) for handle in handles}) == len(handles), "native provider channels alias or are closed")
        channels.guard(deadline=deadline)

    def _ownership(self):
        native._resource_ownership(self.owned)
        _require(self.created and self.directory_fd >= 0 and self.directory_identity,
                 "provider directory custody is incomplete")
        held = os.fstat(self.directory_fd)
        named = os.stat("provider", dir_fd=self.owned.directory_fd, follow_symlinks=False)
        _require(broker._directory_identity(held) == self.directory_identity == broker._directory_identity(named),
                 "native provider directory replaced")
        _require(sorted(os.listdir(self.directory_fd)) == (["provider.sock"] if self.socket_identity else []),
                 "native provider directory has unowned residue")
        if self.socket_identity:
            value = os.stat("provider.sock", dir_fd=self.directory_fd, follow_symlinks=False)
            _require(broker._file_identity(value) == self.socket_identity, "native provider socket replaced")

    def _open(self):
        self._channels(self.deadline)
        _require(not self.owned.provider_dispatch_active and not self.owned.provider_attempted and
                 getattr(self.owned, "_pi_provider_dispatch", None) is None and
                 not self.channels.services.provider_retired, "native provider dispatch already consumed")
        native._resource_ownership(self.owned)
        os.mkdir("provider", mode=0o711, dir_fd=self.owned.directory_fd)
        self.created = self.owned.provider_dispatch_active = True
        self.owned._pi_provider_dispatch = self
        self.directory_fd = os.open("provider", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=self.owned.directory_fd)
        before = os.fstat(self.directory_fd)
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0, "new provider directory is not root-owned")
        os.fchown(self.directory_fd, 0, self.owned.plan.worker_gid)
        os.fchmod(self.directory_fd, 0o711)
        after = os.fstat(self.directory_fd)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_uid == 0 and
                 after.st_gid == self.owned.plan.worker_gid and stat.S_IMODE(after.st_mode) == 0o711,
                 "new provider directory metadata differs")
        self.directory_identity = broker._directory_identity(after)
        self._ownership()
        os.fsync(self.directory_fd)
        os.fsync(self.owned.directory_fd)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.listener.bind(f"/proc/self/fd/{self.directory_fd}/provider.sock")
        before = os.stat("provider.sock", dir_fd=self.directory_fd, follow_symlinks=False)
        _require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
                 "new provider endpoint is not an owned socket")
        os.chown("provider.sock", 0, self.owned.plan.worker_gid, dir_fd=self.directory_fd, follow_symlinks=False)
        os.chmod("provider.sock", 0o660, dir_fd=self.directory_fd, follow_symlinks=False)
        after = os.stat("provider.sock", dir_fd=self.directory_fd, follow_symlinks=False)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_uid == 0 and
                 after.st_gid == self.owned.plan.worker_gid and stat.S_IMODE(after.st_mode) == 0o660 and after.st_nlink == 1,
                 "native provider endpoint metadata differs")
        self.socket_identity = broker._file_identity(after)
        self._ownership()
        os.fsync(self.directory_fd)
        self.listener.listen(1)
        self.active = True

    def _custody(self, deadline):
        _require(type(self) is PiNativeProviderDispatch and self._seal is _SEAL and self.active and not self.closed and
                 type(deadline) in (int, float) and deadline <= self.deadline and
                 self.owned.provider_dispatch_active and getattr(self.owned, "_pi_provider_dispatch", None) is self,
                 "native provider dispatch scope is not held")
        self._channels(deadline)
        self._ownership()
        owned = self.owned
        _require(owned.started and owned.start_attempted and not owned.exit_observed and owned.pid > 0 and
                 owned.pidfd >= 0 and owned.cgroup_fd >= 0 and owned.cgroup_parent_fd >= 0 and
                 owned.activation_fd >= 0 and owned.activation_identity and owned.activation_raw is not None and
                 owned.invocation and owned.immutable_digest and owned.connection is not None,
                 "native provider lacks independent process and activation custody")
        pins = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                owned.immutable_digest, owned.connection, owned.activation_raw)
        _require(self._pins is None or pins == self._pins, "native provider process generation changed")
        native._same_generation(owned, native._unit_state(owned.plan.unit_name, deadline), deadline, live=True)
        activation = identity.validate_activation(broker._parse_canonical_document(owned.activation_raw, "native Pi activation"))
        _require(identity.read_activation(owned.plan.activation_path) == activation and
                 activation["activation_id"] == self._expected["activation_id"], "native provider activation changed")
        identity._measured(owned.connection, owned.pidfd, owned.plan.profile, activation, deadline)
        observer = owned.source_observer
        configured = self.channels.services.request_channels.source_observer
        _require(type(observer) is source.PiSourceObserver and observer._owned is owned and
                 (configured is None or configured is observer) and
                 (self._observer is None or self._observer is observer) and not owned.source_observer_closed,
                 "native provider source observer is not held")
        # Node tracing belongs to its dedicated thread. The supervisor cannot
        # call the observer's owner-thread-only _budget/_guard here, and full
        # source coverage cannot exist until START loads the provider module.
        from .pi_core_node_source_observer import _NodeSession
        session = observer._node_session
        _require(type(session) is _NodeSession and session.observer is observer and session.owned is owned and
                 deadline <= session.operation_deadline, "native provider Node observation lifetime differs")
        _require(session.lock.acquire(timeout=native._remaining(deadline)),
                 "native provider source observer custody deadline expired")
        try:
            channel.validate_deadline(deadline)
            _require(observer._seal is source._SEAL and observer._state == "HELD" and
                     observer._attached and observer._executed and not observer._close_attempted and
                     session.ready.is_set() and not session.closed.is_set() and not session.stopping and
                     session.failure is None and session.thread.is_alive() and
                     session.thread.native_id == observer._thread,
                     "native provider source observer is not held")
        finally:
            session.lock.release()
        return activation, pins, observer

    def require_start(self, activation, *, deadline):
        _require(self._pins is None and not self.owned.provider_attempted and not self.channels.services.provider_retired,
                 "native provider START already consumed")
        current, pins, observer = self._custody(deadline)
        _require(activation == current, "provider START activation differs from authenticated capture")
        if self.channels.approval is not None:
            self.channels.approval.bind(self._expected, current, deadline=deadline)
        self._activation, self._pins, self._observer = current, pins, observer
        self.deadline = deadline  # The START caller anchors maxRunMs once; never renew it.
        # Dynamic provider source loads after START. Full health is mandatory at
        # mediation, not fabricated here from a bootstrap-only source inventory.

    def _close_accepted(self):
        if self.accepted is None:
            return
        _require(not self._accepted_close_attempted, "accepted provider close is already ambiguous")
        self._accepted_close_attempted = True
        try:
            self.accepted.close()
        except BaseException as exc:
            self._close_failure = exc
            self._observation["cleanup"] = "CLEANUP_HOLD"
            raise
        self.accepted = None

    def serve_once(self, deadline):
        _require(self._pins is not None, "native provider requires authenticated START first")
        self._custody(deadline)
        with _CONSUME_LOCK:
            _require(not self.owned.provider_attempted and not self.channels.services.provider_retired,
                     "native provider attempt already consumed; no retry")
            self.owned.provider_attempted = True  # Even a failed accept consumes the slot.
        self.deadline = deadline
        self._observation.update(provider_attempted=True, status="PROVIDER_ATTEMPTED")
        try:
            self.listener.settimeout(native._remaining(deadline))
            self.accepted, _ = self.listener.accept()
            self._custody(deadline)
            _require(self.accepted.getsockopt(socket.SOL_SOCKET, channel._DOMAIN) == socket.AF_UNIX and
                     self.accepted.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
                     "native provider accepted stream differs")
            identity._measured(self.accepted, self.owned.pidfd, self._plan.profile, self._activation, deadline)
            self._observer.guard_source_health(activation=self._activation, deadline=deadline)
            self._remote_custody_hold = True
            result = mediation.handle_pi_provider_connection(self.accepted, self.channels.services.provider_connection,
                self.channels.config, activation_path=self._plan.activation_path, profile=self._plan.profile,
                protected_install_root=self.protected_root, grant=self.grant,
                expected_provider_peer=self.channels.services.provider_peer, deadline=deadline,
                provider_service=True, service_custody=self.channels.services, source_observer=self._observer,
                expected_request=self._expected)
            _require(type(result) is dict and result.get("status") in {"COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"} and
                     type(result.get("submission_attempted")) is bool, "native provider mediator result is invalid")
            self._observation["provider_result"] = json.loads(canonical_json(result))
            terminal = bool(result.get("provider_service_receipt_digest")) and self.channels.services.provider_retired
            safe = (result.get("cleanup") == "OWNED_HANDLES_CLOSED" and
                    result.get("client_delivery") == "FRAME_AND_EOF_SENT_NOT_ACKNOWLEDGED" and
                    (terminal or (result["status"] == "NOT_SUBMITTED" and not result["submission_attempted"])))
            self._remote_custody_hold = not safe
            _require(safe, "native provider terminal or delivery remains unconfirmed")
            self._observation["status"] = "PROVIDER_RETURNED"
            return self.observation
        except BaseException:
            self._observation["status"] = "PROVIDER_INDETERMINATE" if self._remote_custody_hold else "PROVIDER_NOT_SUBMITTED"
            if self._remote_custody_hold:
                self._observation["cleanup"] = "CLEANUP_HOLD"
            raise
        finally:
            self._close_accepted()

    def require_completed(self, deadline):
        _require(self._pins is not None, "provider START is not authenticated")
        self._custody(deadline)
        result = self._observation["provider_result"]
        _require(self._observation["status"] == "PROVIDER_RETURNED" and type(result) is dict and
                 result.get("status") == "COMPLETED" and result.get("submission_attempted") is True and
                 result.get("request_digest") == canonical_digest(self._expected) and
                 bool(result.get("provider_service_receipt_digest")) and
                 result.get("cleanup") == "OWNED_HANDLES_CLOSED" and
                 result.get("client_delivery") == "FRAME_AND_EOF_SENT_NOT_ACKNOWLEDGED" and
                 self.channels.services.provider_retired and not self._remote_custody_hold and
                 self._close_failure is None and self.accepted is None,
                 "provider completion and retirement are required before protected action")
        self._observer.guard_source_health(activation=self._activation, deadline=deadline)

    def close(self):
        if self.closed:
            _require(self._close_failure is None, "native provider cleanup is held; no automatic retry")
            return
        self.closed, self.active = True, False
        try:
            _require(self._close_failure is None, "native provider accepted close is unconfirmed")
            self._close_accepted()
            _require(not self._remote_custody_hold, "native provider remote custody is unconfirmed")
            if self.created:
                native._remaining(self.cleanup_deadline)
                self._ownership()
                if self.listener is not None:
                    self.listener.close()  # One attempt; retain pointer if close is ambiguous.
                    self.listener = None
                if self.socket_identity:
                    native._remaining(self.cleanup_deadline)
                    os.unlink("provider.sock", dir_fd=self.directory_fd)
                    os.fsync(self.directory_fd)
                    _require(native._missing(self.directory_fd, "provider.sock"), "native provider socket remains")
                    self.socket_identity = ()
                self._ownership()
                native._remaining(self.cleanup_deadline)
                os.rmdir("provider", dir_fd=self.owned.directory_fd)
                os.fsync(self.owned.directory_fd)
                _require(native._missing(self.owned.directory_fd, "provider"), "native provider directory remains")
                os.close(self.directory_fd)
                self.directory_fd = -1
                self.owned.provider_dispatch_active = False
                del self.owned._pi_provider_dispatch
                native._resource_ownership(self.owned)
            self._observation["cleanup"] = "VERIFIED_OWNED_PROVIDER_CLEANUP"
        except BaseException as exc:
            self._close_failure = exc
            self._observation["cleanup"] = "CLEANUP_HOLD"
            error = PiNativeProviderError("native provider cleanup is unconfirmed; preserve owned resources")
            error.observation = self.observation
            raise error from exc


@contextmanager
def hold_native_pi_provider_dispatch(owned, provider_channels, *, grant, protected_root, deadline, cleanup_deadline=None):
    dispatch = PiNativeProviderDispatch(_SEAL, owned, provider_channels, grant, protected_root, deadline, cleanup_deadline)
    try:
        dispatch._open()
        yield dispatch
    finally:
        dispatch.close()
