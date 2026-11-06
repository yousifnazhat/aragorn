"""Unprivileged, registration-only consumer of a protected Pi identity handoff.

The root publisher owns measurement, boot identity and admission custody. This
consumer observes an authenticated same-kernel AF_UNIX/PIDFD handoff, not the
foreign process's executable, namespace or loaded code. It never reads foreign
/proc entries, opens an activation file, accepts requests or dispatches effects.
The caller retains its connection; only newly received/obtained PIDFDs are owned
here. A registration is local and is always withdrawn before returning/raising.
"""

from __future__ import annotations

import math
import os
import secrets
import socket
import time

from . import pi_core_identity_handoff as handoff
from . import pi_core_worker_identity as identity
from . import runtime_action_worker as worker
from .oci_worker_protocol import canonical_digest

_SCOPE = "IDENTITY_ONLY_NOT_REQUEST_OR_EFFECT_AUTHORITY"


class PiIdentityRelayError(RuntimeError):
    """Registration was refused/withdrawn; observation never authorizes dispatch."""

    def __init__(self, observation: dict):
        super().__init__("protected Pi identity registration failed; no request or effect authority")
        self.observation = dict(observation)


def _require(value: bool, message: str) -> None:
    if not value:
        raise handoff.PiIdentityHandoffError(message)


def _packet(kind: str, **fields) -> dict:
    return {"schema": handoff.SCHEMA, "authority": handoff.AUTHORITY, "kind": kind, **fields}


def consume_pi_identity_handoff(
    connection: socket.socket,
    config: worker.RuntimeActionWorkerConfig,
    *,
    expected_supervisor_pid: int,
    deadline: float,
) -> dict:
    """Register then revoke one identity, without enabling a request endpoint.

    The protected publisher verifies the actual boot ID. Its authenticated
    handoff binds that attestation to the live worker PIDFD and fresh nonce in
    this kernel's clock domain; relay-side boot/profile remeasurement is neither
    performed nor claimed. This preserves the relay's ProcSubset=pid boundary.
    No retry, deadline extension, portable capability or dispatch occurs here.
    """
    observation = {
        "schema": "aragorn/pi-core-identity-relay-observation/v1",
        "status": "REFUSED", "scope": _SCOPE, "activation_digest": None,
        "registration_observed": False, "registration_active": False,
        "registration_withdrawn": True, "worker_pidfd_closed": None,
        "supervisor_pidfd_closed": None, "request_authorized": False,
        "effect_authorized": False, "phase3_exit_eligible": False,
    }
    supervisor_fd = worker_fd = -1
    failure = None
    try:
        handoff.validate_deadline(deadline)
        _require(type(expected_supervisor_pid) is int and 0 < expected_supervisor_pid < 2**31,
                 "invalid protected supervisor PID")
        worker._validate_config(config)
        _require(config.expected_worker_uid > 0 and config.expected_worker_gid > 0,
                 "identity consumer must remain unprivileged")
        peer = (expected_supervisor_pid, 0, 0)
        supervisor_fd = handoff.guard_channel(connection, peer, deadline)
        nonce = secrets.token_hex(16)
        handoff.require_peer_live(connection, peer, supervisor_fd, deadline)
        handoff.send_packet(connection, _packet("CHALLENGE", nonce=nonce), deadline)
        document, rights = handoff.receive_packet(connection, peer, deadline, expected_rights=1)
        # receive_packet owns and closes every installed descriptor on rejection;
        # ownership of its one successful returned PIDFD transfers immediately.
        (worker_fd,) = rights
        if worker_fd == supervisor_fd:
            # A real recvmsg cannot allocate an already-open number; do not
            # double-close if a broken transport violates that invariant.
            worker_fd = -1
            _require(False, "handoff descriptors alias")
        _require(document.get("kind") == "HANDOFF" and document.get("nonce") == nonce,
                 "identity handoff is not bound to the fresh challenge")
        activation = identity.validate_activation(document["activation"])
        digest = canonical_digest(activation)
        _require(document["activation_digest"] == digest, "activation digest differs")
        observation["activation_digest"] = digest
        _require(activation["pid"] != expected_supervisor_pid and
                 activation["uid"] == config.expected_gateway_uid and
                 activation["gid"] == config.expected_gateway_gid and
                 activation["runtime_digest"] == config.binding.runtime_digest and
                 activation["active_skill_digest"] == config.binding.active_skill_digest and
                 activation["policy_digest"] == config.binding.policy_digest,
                 "protected activation differs from fixed relay binding")
        deadline_ns = document["deadline_ns"]
        _require(type(deadline_ns) is int and time.monotonic_ns() < deadline_ns <=
                 min(activation["expires_at_monotonic_ns"], math.floor(deadline * 1_000_000_000)),
                 "handoff lifetime is expired or exceeds original authority")
        bounded_deadline = min(deadline, deadline_ns / 1_000_000_000)

        def guard() -> None:
            handoff.require_peer_live(connection, peer, supervisor_fd, bounded_deadline)
            _require(time.monotonic_ns() < deadline_ns, "identity registration expired")
            handoff.validate_worker_pidfd(worker_fd, activation["pid"])

        guard()
        fields = {"nonce": nonce, "activation_digest": digest, "deadline_ns": deadline_ns}
        observation.update(registration_observed=True, registration_active=True,
                           registration_withdrawn=False)
        handoff.send_packet(connection, _packet("REGISTERED", **fields), bounded_deadline)
        guard()
        revoke, unexpected = handoff.receive_packet(connection, peer, bounded_deadline)
        _require(not unexpected and revoke == _packet("REVOKE", **fields),
                 "identity revocation is not bound to this registration")
        guard()
        observation.update(registration_active=False, registration_withdrawn=True)
        descriptor, worker_fd = worker_fd, -1
        observation["worker_pidfd_closed"] = False
        os.close(descriptor)
        observation["worker_pidfd_closed"] = True
        handoff.require_peer_live(connection, peer, supervisor_fd, bounded_deadline)
        handoff.send_packet(connection, _packet("REVOKED", **fields), bounded_deadline)
        observation["status"] = "IDENTITY_REGISTERED_AND_REVOKED"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
        failure = error
    finally:
        observation.update(registration_active=False, registration_withdrawn=True)
        # Attempt every owned close once even if an earlier close fails. Never
        # close the caller's connection or repeat an uncertain descriptor close.
        for name, descriptor in (("worker_pidfd_closed", worker_fd),
                                 ("supervisor_pidfd_closed", supervisor_fd)):
            if descriptor >= 0:
                observation[name] = False
                try:
                    os.close(descriptor)
                    observation[name] = True
                except OSError as error:
                    failure = failure or error
    if failure is not None:
        observation["status"] = "REFUSED"
        raise PiIdentityRelayError(observation) from failure
    return observation
