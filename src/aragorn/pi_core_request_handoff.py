"""One root-read Pi request, bound to a scoped broker channel and live custody.

This module creates no socket, process, listener or provider route. Callers own
both connections and must close each after its single invocation. The bootstrap
identity-only protocol is unchanged. Root and the broker are trusted principals;
an in-process Python object is not protection against a compromised broker.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import pi_core_identity_handoff as transport
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_worker as worker
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-request-handoff/v1"
AUTHORITY = "PROTECTED_WORKER_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
MAX_PACKET_BYTES = 64 * 1024
_SEAL = object()
_BASE = {"schema", "authority", "kind", "nonce"}
_BOUND = _BASE | {"activation_digest", "request_digest", "deadline_ns"}
_FIELDS = {
    "CHALLENGE": _BASE,
    "OFFER": _BOUND | {"activation", "worker_request"},
    "CHECK": _BOUND | {"sequence"},
    "CURRENT": _BOUND | {"sequence"},
    "DONE": _BOUND | {"envelope", "result"},
}


class PiRequestHandoffError(RuntimeError):
    """Protected request handoff refused or became indeterminate."""


def _require(value, reason):
    if not value:
        raise PiRequestHandoffError(reason)


def _copy(value):
    return json.loads(canonical_json(value))


def _packet(kind, **fields):
    return {"schema": SCHEMA, "authority": AUTHORITY, "kind": kind, **fields}


def _validate_packet(value):
    _require(type(value) is dict and type(value.get("kind")) is str and
             value["kind"] in _FIELDS and set(value) == _FIELDS[value["kind"]] and
             value["schema"] == SCHEMA and value["authority"] == AUTHORITY,
             "protected request packet fields differ")
    _require(type(value["nonce"]) is str and transport._NONCE.fullmatch(value["nonce"]) is not None,
             "protected request nonce differs")
    if value["kind"] != "CHALLENGE":
        for field in ("activation_digest", "request_digest"):
            worker._worker_digest(value[field], field)
        _require(type(value["deadline_ns"]) is int and 0 < value["deadline_ns"] < 2**63,
                 "protected request deadline differs")
    if value["kind"] in {"CHECK", "CURRENT"}:
        _require(type(value["sequence"]) is int and 1 <= value["sequence"] <= 16,
                 "protected request challenge sequence exhausted")
    if value["kind"] == "OFFER":
        activation = identity.validate_activation(value["activation"])
        request, _ = worker._worker_request(value["worker_request"])
        _require(value["activation_digest"] == canonical_digest(activation) and
                 value["request_digest"] == canonical_digest(request) and
                 value["deadline_ns"] <= activation["expires_at_monotonic_ns"] and
                 request["session_id"] == activation["session_id"] and
                 request["run_id"] == activation["run_id"], "request offer is not activation-bound")
    _require(len(canonical_json(value)) <= MAX_PACKET_BYTES, "request packet exceeds byte bound")
    return value


def _send(connection, document, deadline, *, rights=()):
    _validate_packet(document)
    _require(len(rights) == (1 if document["kind"] == "OFFER" else 0), "request packet rights differ")
    transport.send_authenticated_packet(connection, document, deadline, rights=rights, max_bytes=MAX_PACKET_BYTES)


def _receive(connection, peer, deadline, *, rights=0):
    document, descriptors = transport.receive_authenticated_packet(connection, peer, deadline,
        expected_rights=rights, max_bytes=MAX_PACKET_BYTES)
    try:
        _validate_packet(document)
        _require(rights == (1 if document["kind"] == "OFFER" else 0), "request packet kind/rights differ")
        return document, descriptors
    except BaseException:
        transport._close_installed(descriptors)
        raise


def validate_projection(envelope, worker_request, activation, binding=None):
    """Check exact create projection; broker still derives protected path identity.

    The root reader cannot attest the broker's filesystem from relay JSON. The
    existing broker must independently compute/verify path_digest under its
    held protected-root descriptor before an effect.
    """
    original, payload = worker._worker_request(worker_request)
    activation = identity.validate_activation(activation)
    request, target, projected_payload = broker._request_effect(envelope)
    broker._validate_runtime_action_request(request)
    expected = {
        "runtime_digest": activation["runtime_digest"],
        "active_skill_digest": activation["active_skill_digest"],
        "policy_digest": activation["policy_digest"],
        "session_id": original["session_id"], "run_id": original["run_id"],
        "tool_call_id": original["tool_call_digest"],
        "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "operation_digest": canonical_digest({"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}),
    }
    _require(original["session_id"] == activation["session_id"] and
             original["run_id"] == activation["run_id"] and target == original["target_name"] and
             projected_payload == payload and all(request[name] == value for name, value in expected.items()),
             "broker envelope is not the protected worker request")
    if binding is not None:
        _require(type(binding) is worker.RuntimeActionWorkerBinding and
                 binding.runtime_digest == expected["runtime_digest"] and
                 binding.active_skill_digest == expected["active_skill_digest"] and
                 binding.policy_digest == expected["policy_digest"] and
                 request["policy_version"] == binding.policy_version,
                 "broker envelope differs from fixed policy binding")
    return _copy(envelope)


def _result(envelope, result, request, activation, binding=None):
    validated = validate_projection(envelope, request, activation, binding)
    _require(type(result) is dict and set(result) == {
        "schema", "authority", "request_digest", "status", "broker_result"}, "worker result fields differ")
    actual_binding = binding or worker.RuntimeActionWorkerBinding(activation["runtime_digest"],
        activation["active_skill_digest"], activation["policy_digest"], validated["request"]["policy_version"])
    outcome = None
    if result["status"] == "COMPLETED":
        outcome = worker._broker_result(result["broker_result"], validated, actual_binding)
    expected = worker._worker_result(canonical_digest(request), result["status"], outcome)
    _require(result == expected, "worker result is not bound to the protected request")
    return _copy(expected)


class PiRequestAuthority:
    """Scoped, exact-type authority minted by the authenticated receiver only."""

    __slots__ = ("_seal", "_connection", "_peer", "_peer_fd", "_worker_fd", "_offer",
                 "_deadline", "_active", "_begun", "_finished", "_sequence", "_lock")

    def __init__(self, seal=None, *, connection=None, peer=None, peer_fd=-1, worker_fd=-1, offer=None, deadline=None):
        _require(seal is _SEAL, "request authority requires authenticated channel custody")
        self._seal, self._connection, self._peer = seal, connection, peer
        self._peer_fd, self._worker_fd, self._offer = peer_fd, worker_fd, _copy(offer)
        self._deadline, self._active = deadline, True
        self._begun, self._finished, self._sequence = False, False, 0
        self._lock = threading.RLock()

    @property
    def activation(self):
        return _copy(self._offer["activation"])

    @property
    def worker_request(self):
        return _copy(self._offer["worker_request"])

    @property
    def request_digest(self):
        return self._offer["request_digest"]

    @property
    def deadline(self):
        return self._deadline

    def _live(self):
        _require(type(self) is PiRequestAuthority and self._seal is _SEAL and self._active and not self._finished,
                 "request authority is not active")
        transport.validate_deadline(self._deadline)
        _require(time.monotonic_ns() < self._offer["deadline_ns"], "request authority expired")
        transport.require_peer_live(self._connection, self._peer, self._peer_fd, self._deadline)
        transport.validate_worker_pidfd(self._worker_fd, self._offer["activation"]["pid"])

    def _fields(self):
        return {key: self._offer[key] for key in ("nonce", "activation_digest", "request_digest", "deadline_ns")}

    def begin(self):
        with self._lock:
            _require(not self._begun, "request authority has already been consumed")
            self._begun = True  # An uncertain guard never restores availability.
            self.guard()

    def guard(self):
        with self._lock:
            try:
                self._live()
                self._sequence += 1
                document = _packet("CHECK", **self._fields(), sequence=self._sequence)
                _send(self._connection, document, self._deadline)
                reply, _ = _receive(self._connection, self._peer, self._deadline)
                _require(reply == {**document, "kind": "CURRENT"}, "protected current-request check differs")
                self._live()
            except BaseException:
                self._active = False
                raise

    def finish(self, envelope, result):
        with self._lock:
            _require(self._begun, "request authority was not consumed")
            self._live()
            outcome = _result(envelope, result, self.worker_request, self.activation)
            self.guard()
            self._finished, self._active = True, False  # No retry even if DONE is uncertain.
            self._close_owned()
            _send(self._connection, _packet("DONE", **self._fields(), envelope=_copy(envelope), result=outcome), self._deadline)

    def _close_owned(self):
        descriptors = [fd for fd in (self._worker_fd, self._peer_fd) if fd >= 0]
        self._worker_fd = self._peer_fd = -1  # Never retry an uncertain close.
        transport._close_installed(descriptors)


@contextmanager
def hold_broker_request_authority(connection, *, expected_supervisor_peer, deadline):
    """Own newly received handles until exit; never trust relay JSON as provenance."""
    transport.validate_deadline(deadline)
    peer = transport._peer(expected_supervisor_peer)
    _require(peer[1:] == (0, 0), "request publisher must be protected root")
    publisher_fd = worker_fd = -1
    authority = None
    try:
        publisher_fd = transport.guard_channel(connection, peer, deadline)
        nonce = secrets.token_hex(16)
        _send(connection, _packet("CHALLENGE", nonce=nonce), deadline)
        offer, descriptors = _receive(connection, peer, deadline, rights=1)
        (worker_fd,) = descriptors
        if worker_fd == publisher_fd:
            worker_fd = -1
            _require(False, "request descriptors alias")
        _require(offer["kind"] == "OFFER" and offer["nonce"] == nonce and
                 offer["activation"]["pid"] != peer[0] and
                 time.monotonic_ns() < offer["deadline_ns"] <= math.floor(deadline * 1_000_000_000),
                 "request offer challenge or lifetime differs")
        bounded = min(deadline, offer["deadline_ns"] / 1_000_000_000)
        authority = PiRequestAuthority(_SEAL, connection=connection, peer=peer,
            peer_fd=publisher_fd, worker_fd=worker_fd, offer=offer, deadline=bounded)
        authority._live()
        yield authority
    finally:
        if authority is not None:
            with authority._lock:
                authority._active = False
                authority._close_owned()
        else:
            transport._close_installed([fd for fd in (worker_fd, publisher_fd) if fd >= 0])


def handle_pi_request_connection(worker_connection, broker_connection, *, activation_path,
        profile, protected_install_root, grant, binding, expected_broker_peer, deadline):
    """Read one actual Pi stream request and hold root custody through broker DONE.

    The worker stream must be separate from multi-turn bootstrap: its canonical
    frame is followed by write-side EOF. No caller JSON argument can substitute
    for bytes read from the actual accepted worker connection.
    """
    _require(os.geteuid() == os.getegid() == 0, "Pi request reader requires root")
    transport.validate_deadline(deadline)
    _require(worker_connection is not broker_connection and worker_connection.fileno() != broker_connection.fileno(),
             "Pi worker and broker channels must be distinct")
    _require(worker_connection.getsockopt(socket.SOL_SOCKET, transport._DOMAIN) == socket.AF_UNIX and
             worker_connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
             "Pi worker request requires its accepted AF_UNIX stream")
    _require(type(profile) is process.RuntimeProcessProfile and type(binding) is worker.RuntimeActionWorkerBinding and
             isinstance(protected_install_root, Path) and protected_install_root.is_absolute() and
             protected_install_root != Path(protected_install_root.anchor), "protected Pi request configuration differs")
    activation = identity.read_activation(activation_path)
    _require(profile.digest == activation["profile_digest"] and binding.runtime_digest == activation["runtime_digest"] and
             binding.active_skill_digest == activation["active_skill_digest"] and binding.policy_digest == activation["policy_digest"],
             "protected Pi request pins differ")
    worker._positive_uint(binding.policy_version, "policy version")
    peer = worker._valid_peer(broker._peer_credentials(worker_connection), "Pi worker")
    _require(peer == (activation["pid"], activation["uid"], activation["gid"]), "Pi request peer is not the activation")
    expected_broker_peer = transport._peer(expected_broker_peer)
    _require(expected_broker_peer[0] != peer[0] and expected_broker_peer[1] != peer[1] and
             expected_broker_peer[2] != peer[2], "broker and Pi worker roles overlap")
    deadline = min(deadline, activation["expires_at_monotonic_ns"] / 1_000_000_000)
    deadline_ns = min(math.floor(deadline * 1_000_000_000), activation["expires_at_monotonic_ns"])
    worker_fd = broker_fd = -1
    request = result = None
    offered = False
    failure = None
    try:
        worker_fd = process.open_peer_pidfd(worker_connection, peer[0])
        measured = identity._measured(worker_connection, worker_fd, profile, activation, deadline)
        with identity.lineage.hold_runtime_active_skill_lineage(peer[0], measured, grant,
                protected_root=protected_install_root, expected_install_uid=0, deadline=deadline) as active:
            identity._lineage_matches(active, activation, profile, protected_install_root)

            def guard():
                identity._remaining(deadline, activation)
                _require(identity.read_activation(activation_path) == activation and
                         identity._measured(worker_connection, worker_fd, profile, activation, deadline) == measured,
                         "protected Pi request identity changed")

            raw_request = broker._read_frame(worker_connection, deadline)
            request, _ = worker._worker_request(raw_request)
            _require(request["session_id"] == activation["session_id"] and request["run_id"] == activation["run_id"],
                     "Pi request session is not the protected activation")
            guard()
            broker_fd = transport.guard_channel(broker_connection, expected_broker_peer, deadline)
            challenge, _ = _receive(broker_connection, expected_broker_peer, deadline)
            _require(challenge["kind"] == "CHALLENGE", "expected broker request challenge")
            fields = {"nonce": challenge["nonce"], "activation_digest": canonical_digest(activation),
                      "request_digest": canonical_digest(request), "deadline_ns": deadline_ns}
            guard()
            transport.require_peer_live(broker_connection, expected_broker_peer, broker_fd, deadline)
            offered = True
            _send(broker_connection, _packet("OFFER", **fields, activation=activation, worker_request=request),
                  deadline, rights=(worker_fd,))
            sequence = 0
            while True:
                document, _ = _receive(broker_connection, expected_broker_peer, deadline)
                transport.require_peer_live(broker_connection, expected_broker_peer, broker_fd, deadline)
                guard()
                if document["kind"] == "DONE":
                    _require(sequence > 0 and all(document[key] == value for key, value in fields.items()),
                             "broker DONE is not bound to this request")
                    result = _result(document["envelope"], document["result"], request, activation, binding)
                    guard()
                    break
                sequence += 1
                expected = _packet("CHECK", **fields, sequence=sequence)
                _require(document == expected and sequence <= 16, "broker request check sequence differs")
                guard()
                _send(broker_connection, {**expected, "kind": "CURRENT"}, deadline)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        failure = exc
    finally:
        try:
            transport._close_installed([fd for fd in (worker_fd, broker_fd) if fd >= 0])
        except (OSError, RuntimeError) as exc:
            failure = failure or exc
    if request is None:
        raise PiRequestHandoffError("Pi request could not be authenticated and read") from failure
    if failure is not None or result is None:
        result = worker._worker_result(canonical_digest(request), "INDETERMINATE" if offered else "NOT_SUBMITTED", None)
    # Only after admission and newly owned handles are released can success be
    # returned. A failed response never establishes absence of broker submission.
    try:
        broker._send_frame(worker_connection, canonical_json(result), deadline)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PiRequestHandoffError("Pi request result delivery is uncertain") from exc
    return result
