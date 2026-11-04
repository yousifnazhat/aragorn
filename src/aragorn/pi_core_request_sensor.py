"""One-shot independent Pi process/action measurement for the managed broker.

The root custody channel supplies candidate request bytes and an actual accepted
Pi stream descriptor, never sensor attribution. The root remains the sole reader
of that stream: this module only authenticates and measures its peer. It opens no
listener or connection, executes no worker, and grants no effect authority.

Dedicated sensor setup must include ONLY its broker GID as a supplementary
group (the sensor primary GID may also be listed). This grants traversal of the
existing broker-owned 0710 effect root after worker FS-identity adoption. The Pi
worker keeps no supplementary groups; neither the directory mode nor worker
permissions are widened. Sensor, broker and worker primary GIDs stay distinct.
"""

from __future__ import annotations

import os
import socket
import sys
import time

from . import pi_core_identity_handoff as transport
from . import pi_core_sensor_channel as custody
from . import runtime_action_broker as broker
from . import runtime_action_observation_publisher as publisher
from . import runtime_action_observation_publisher_v2 as profiled
from . import runtime_action_observation_publisher_v4 as configured
from . import runtime_action_worker as worker
from . import runtime_active_skill_lineage_v2 as lineage
from . import runtime_capability_grant as capability
from . import runtime_lineage_capability_issuer as issuer
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json


class PiRequestSensorError(publisher.RuntimeActionObservationPublisherError):
    """Sensor input or independently measured state was refused."""


def _require(condition, reason):
    if not condition:
        raise PiRequestSensorError(reason)


def _configuration(config):
    configured._validate_config(config)
    selected = config.publisher
    _require(all(value > 0 for value in (
        selected.expected_observer_uid, selected.expected_observer_gid,
        selected.expected_runtime_uid, selected.expected_runtime_gid,
        selected.expected_broker_uid, selected.expected_broker_gid)),
        "Pi sensor, worker and broker identities must be nonroot")
    _require(len({selected.expected_observer_gid, selected.expected_runtime_gid,
                  selected.expected_broker_gid}) == 3,
             "Pi sensor, worker and broker primary groups must be distinct")
    return selected


def _prepared_identity(selected):
    groups = set(os.getgroups())
    _require(selected.expected_broker_gid in groups and
             groups <= {selected.expected_broker_gid, selected.expected_observer_gid},
             "Pi sensor supplementary groups lack exact broker-only traversal")
    status = profiled._process_security_status()
    _require(status == {
        "fsuid": selected.expected_runtime_uid,
        "fsgid": selected.expected_runtime_gid,
        "cap_eff": 0, "cap_prm": 0, "cap_inh": 0, "cap_amb": 0, "cap_bnd": 0,
    }, "Pi sensor filesystem identity is not prepared and capability-free")


def _stream(connection, label):
    _require(connection.getsockopt(socket.SOL_SOCKET, transport._DOMAIN) == socket.AF_UNIX and
             connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
             label + " requires an actual local stream")


def handle_pi_sensor_request(custody_connection, broker_connection,
        config: configured.RuntimeActionObservationPublisherV4Config, *,
        expected_supervisor_pid: int, deadline: float) -> dict:
    """Consume one candidate under an already-prepared sensor FS identity.

    Both supplied connections remain caller-owned. The caller must close them
    after this invocation, including failure, and owns FS-identity restoration.
    Newly acquired PIDFDs and the received worker duplicate close before DONE.
    No read, write, shutdown or timeout operation touches the shared Pi stream.
    """
    return _handle(custody_connection, broker_connection, config,
        expected_supervisor_pid=expected_supervisor_pid, deadline=deadline,
        restore_identity_before_finish=False)


def run_pi_sensor_request(custody_connection, broker_connection,
        config: configured.RuntimeActionObservationPublisherV4Config, *,
        expected_supervisor_pid: int, deadline: float) -> dict:
    """Dedicated one-shot caller: adopt once, drop capabilities, restore once.

    Run only in the dedicated sensor process with its existing limited setup
    capabilities. This is not a reusable service loop. Restoration is attempted
    before DONE on success and exactly once on failure; uncertain restoration is
    never retried automatically.
    """
    selected = _configuration(config)
    transport.validate_deadline(deadline)
    _require(sys.platform == "linux", "Pi sensor identity setup requires Linux")
    # The existing helper restores on failed adoption. Do not retry it here.
    profiled._adopt_runtime_fs_identity(selected.expected_runtime_uid,
        selected.expected_runtime_gid, selected.expected_observer_uid,
        selected.expected_observer_gid)
    return _handle(custody_connection, broker_connection, config,
        expected_supervisor_pid=expected_supervisor_pid, deadline=deadline,
        restore_identity_before_finish=True)


def _handle(custody_connection, broker_connection, config, *,
        expected_supervisor_pid, deadline, restore_identity_before_finish):
    selected = getattr(config, "publisher", None)
    owned = []
    restoration_attempted = False
    submission_attempted = False
    failure = None
    observation = None

    def restore():
        nonlocal restoration_attempted
        if restore_identity_before_finish and not restoration_attempted:
            restoration_attempted = True
            profiled._restore_observer_fs_identity(
                selected.expected_observer_uid, selected.expected_observer_gid)

    def close_owned():
        pending = list(owned)
        owned.clear()  # Every close is attempted once, including uncertain ones.
        if pending:
            transport._close_installed(pending)

    try:
        transport.validate_deadline(deadline)
        selected = _configuration(config)
        _prepared_identity(selected)
        _require(type(expected_supervisor_pid) is int and 0 < expected_supervisor_pid < 2**31,
                 "Pi sensor supervisor PID is invalid")
        _require(custody_connection is not broker_connection and
                 custody_connection.fileno() != broker_connection.fileno(),
                 "Pi sensor custody and broker channels must be distinct")
        _stream(broker_connection, "Pi sensor broker")
        broker_peer = worker._valid_peer(broker._peer_credentials(broker_connection), "Pi broker")
        _require(broker_peer[1:] == (selected.expected_broker_uid, selected.expected_broker_gid),
                 "Pi sensor broker peer is unauthorized")
        broker_fd = process.open_peer_pidfd(broker_connection, broker_peer[0])
        owned.append(broker_fd)
        with custody.hold_sensor_candidate(custody_connection,
                expected_supervisor_pid=expected_supervisor_pid, deadline=deadline) as candidate:
            bounded = candidate.deadline
            _require(bounded <= deadline, "Pi sensor custody extended the original deadline")
            transport.validate_deadline(bounded)
            source = candidate.worker_connection
            _require(source is not custody_connection and source is not broker_connection and
                     source.fileno() not in (custody_connection.fileno(), broker_connection.fileno()),
                     "Pi worker measurement descriptor overlaps a control channel")
            _stream(source, "Pi worker measurement")
            peer = worker._valid_peer(broker._peer_credentials(source), "Pi worker")
            _require(peer[1:] == (selected.expected_runtime_uid, selected.expected_runtime_gid),
                     "Pi measured worker peer is unauthorized")
            worker_fd = process.open_peer_pidfd(source, peer[0])
            owned.append(worker_fd)

            def live():
                candidate.guard()
                transport.require_peer_live(broker_connection, broker_peer, broker_fd, bounded)
                _require(worker._valid_peer(broker._peer_credentials(source), "Pi worker") == peer,
                         "Pi measured worker peer changed")
                process.require_live_pidfd(worker_fd)
                _prepared_identity(selected)
                transport.validate_deadline(bounded)

            def measure():
                live()
                measured = process.measure_runtime_process_profile(peer[0], worker_fd,
                    selected.runtime_profile, expected_uid=peer[1], expected_gid=peer[2])
                live()
                return measured

            before = measure()
            request, payload = worker._worker_request(candidate.request)
            _require(canonical_digest(request) == candidate.request_digest,
                     "Pi sensor candidate request digest differs")
            grant = capability.parse_runtime_capability_grant(config.capability_grant, int(time.time()))
            binding = worker.RuntimeActionWorkerBinding(grant["runtime_digest"],
                grant["active_skill_digest"], grant["policy_digest"], grant["policy_version"])
            with lineage.hold_runtime_active_skill_lineage(peer[0], before, grant,
                    protected_root=config.protected_install_root,
                    expected_install_uid=0, deadline=bounded) as active:
                protected_fd = publisher._open_protected_root(
                    profiled._v1_config(selected, before["active_skill_digest"]))
                owned.append(protected_fd)
                envelope = worker._broker_envelope(request, payload, protected_fd, binding, int(time.time()))
                submission = profiled.build_profiled_submission(
                    envelope, peer, protected_fd, selected, before)
                _require(measure() == before, "Pi process changed during independent measurement")
                issued = capability.issue_profiled_runtime_capability(
                    submission, config.capability_grant, int(time.time()))
                value = {"schema": issuer.LINEAGE_ISSUANCE_SCHEMA,
                    "authority": issuer.LINEAGE_ISSUANCE_AUTHORITY,
                    "lineage": active, "issuance": issued}
                _require(measure() == before, "Pi process changed before capability submission")
                candidate.ready()  # Root may now service broker CHECK/CURRENT.
                live()
                submission_attempted = True
                broker._send_frame(broker_connection, canonical_json(value), bounded)
                broker_connection.shutdown(socket.SHUT_WR)
                response = broker._read_frame(broker_connection, bounded)
                result = worker._broker_result(response, envelope, binding)
                live()
            # The held lineage and every extra owned FD precede custody DONE.
            close_owned()
            restore()
            candidate.finish(result)
            observation = {
                "schema": "aragorn/pi-core-request-sensor-observation/v1",
                "authority": "INDEPENDENT_SENSOR_RESULT_NOT_DEPLOYMENT_OR_PHASE3_QUALIFICATION",
                "status": "COMPLETED", "request_digest": canonical_digest(request),
                "runtime_attribution_digest": canonical_digest(before),
                "broker_result": result, "measurement_handles_closed": True,
                "observer_fs_identity_restored": restore_identity_before_finish,
                "phase3_exit_eligible": False,
            }
    except Exception as exc:
        failure = exc
    finally:
        try:
            close_owned()
        except Exception as exc:
            failure = failure or exc
        try:
            restore()
        except Exception as exc:
            failure = failure or exc
    if failure is not None:
        if submission_attempted:
            raise broker.RuntimeActionEffectIndeterminate(
                "Pi sensor submission or cleanup is uncertain; do not retry") from failure
        raise PiRequestSensorError("Pi independent sensor refused before submission") from failure
    return observation
