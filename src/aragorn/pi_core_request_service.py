"""One-shot Pi create broker caller with independent root and sensor channels.

This function consumes already-accepted connections. It creates no listener,
starts no service, and does not replace or unmask any legacy endpoint. The
operator must provision both channels under their final service identities.
Root provenance is necessary, never a replacement for sensor/grant enforcement.
"""

from __future__ import annotations

import json
import os
import socket

from . import pi_core_identity_handoff as channel
from . import pi_core_request_handoff as handoff
from . import runtime_action_broker as broker
from . import runtime_action_broker_v5 as v5
from . import runtime_action_worker as worker
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_json
from .pi_core_request_broker import mediate_pi_runtime_create


def handle_pi_broker_request(
    supervisor_connection: socket.socket,
    sensor_connection: socket.socket,
    config: v5.RuntimeActionBrokerV5Config,
    *,
    expected_supervisor_pid: int,
    deadline: float,
) -> dict:
    """Require two authenticated inputs and complete exactly one mediated create.

    The caller owns both connections and must close them after this invocation,
    including on failure. No transport or effect retry is permitted. Only a
    successful mediator result can be returned to the supervisor as COMPLETED.
    After possible mediation, response/custody failures remain indeterminate.
    """
    channel.validate_deadline(deadline)
    if type(expected_supervisor_pid) is not int or not 0 < expected_supervisor_pid < 2**31:
        raise broker.RuntimeActionBrokerError("invalid protected supervisor PID")
    v5._validate_config(config)
    base = config.broker.broker.broker
    if (supervisor_connection is sensor_connection or
            supervisor_connection.fileno() == sensor_connection.fileno()):
        raise broker.RuntimeActionBrokerError("Pi root and sensor channels must be distinct")
    if (sensor_connection.getsockopt(socket.SOL_SOCKET, channel._DOMAIN) != socket.AF_UNIX or
            sensor_connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
        raise broker.RuntimeActionBrokerError("Pi sensor requires an accepted local stream")
    peer = worker._valid_peer(broker._peer_credentials(sensor_connection), "Pi sensor")
    if peer[1:] != (base.expected_peer_uid, base.expected_peer_gid):
        raise broker.RuntimeActionBrokerError("Pi sensor peer is not authorized")

    sensor_pidfd = -1
    mediation_started = False
    result = None
    failure = None
    try:
        sensor_pidfd = process.open_peer_pidfd(sensor_connection, peer[0])
        with handoff.hold_broker_request_authority(supervisor_connection,
                expected_supervisor_peer=(expected_supervisor_pid, 0, 0),
                deadline=deadline) as authority:
            bounded_deadline = min(deadline, authority.deadline)
            channel.require_peer_live(sensor_connection, peer, sensor_pidfd, bounded_deadline)
            value = broker._read_frame(sensor_connection, bounded_deadline)
            # Detach mutable input before the mediator derives its exact joins.
            value = json.loads(canonical_json(value))
            channel.require_peer_live(sensor_connection, peer, sensor_pidfd, bounded_deadline)
            mediation_started = True
            result = mediate_pi_runtime_create(value, config, authority=authority,
                                               deadline_monotonic=bounded_deadline)
            envelope = value["issuance"]["profiled_submission"]["envelope"]
            activation = authority.activation
            binding = worker.RuntimeActionWorkerBinding(
                activation["runtime_digest"], activation["active_skill_digest"],
                activation["policy_digest"], envelope["request"]["policy_version"])
            result = worker._broker_result(result, envelope, binding)
            channel.require_peer_live(sensor_connection, peer, sensor_pidfd, bounded_deadline)
            broker._send_frame(sensor_connection, canonical_json(result), bounded_deadline)
            # The reused sensor result reader requires one frame followed by
            # EOF. Finish this write side before root waits for sensor cleanup;
            # a borrowed connection is still closed by its caller, never here.
            sensor_connection.shutdown(socket.SHUT_WR)
            # Complete owned sensor-handle cleanup BEFORE root can see success.
            descriptor, sensor_pidfd = sensor_pidfd, -1
            os.close(descriptor)
            response = worker._worker_result(authority.request_digest, "COMPLETED", result)
            authority.finish(envelope, response)
    except Exception as exc:
        failure = exc
    finally:
        if sensor_pidfd >= 0:
            try:
                os.close(sensor_pidfd)
            except OSError as exc:
                failure = failure or exc
    if failure is not None:
        if mediation_started:
            raise broker.RuntimeActionEffectIndeterminate(
                "Pi request mediation or response is uncertain; do not retry"
            ) from failure
        if isinstance(failure, broker.RuntimeActionBrokerError):
            raise failure
        raise broker.RuntimeActionBrokerError("Pi request origin/sensor custody refused") from failure
    return {
        "schema": "aragorn/pi-core-request-service-observation/v1",
        "authority": "CONNECTED_REQUEST_RESULT_NOT_DEPLOYMENT_OR_PHASE3_QUALIFICATION",
        "status": "COMPLETED", "broker_result": result,
        "sensor_pidfd_closed": True, "phase3_exit_eligible": False,
    }
