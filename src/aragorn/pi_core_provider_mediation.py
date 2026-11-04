"""Protected, one-use Pi data authorization and authenticated service handoff.

This module is NOT an HTTP/provider adapter. It reads no provider credentials,
opens no listener or network connection, and cannot attest TLS/DNS/proxy/redirect
controls. A future provider adapter still needs its own send-time enforcement.
Caller-owned channels are one-shot and must be closed by their owner afterward.
Only metadata/digests are retained here; untrusted completion bytes go to Pi.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import socket
import stat
import time
from contextlib import ExitStack
from pathlib import Path

from . import pi_core_confined_launch as confined
from . import pi_core_identity_handoff as channel
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

REQUEST_SCHEMA = "aragorn/pi-core-provider-request/v1"
REQUEST_AUTHORITY = "PI_PROVIDER_REQUEST_ONLY_NOT_DATA_AUTHORITY"
RESULT_SCHEMA = "aragorn/pi-core-provider-result/v1"
RESULT_AUTHORITY = "PROVIDER_DATA_MEDIATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
APPROVAL_SCHEMA = "aragorn/pi-core-provider-data-approval/v1"
APPROVAL_AUTHORITY = "ROOT_PROVIDER_DATA_APPROVAL_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
SERVICE_SCHEMA = "aragorn/pi-core-provider-service/v1"
SERVICE_AUTHORITY = "PROTECTED_PROVIDER_DATA_HANDOFF_NOT_EGRESS_AUTHORITY"
APPROVAL_NAME = "provider-data-approval.json"
MAX_FRAME = 64 * 1024
MAX_PAYLOAD = 48 * 1024
_SAFE = 2**53 - 1
_TARGET = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DNS = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]*\Z")
_OPERATION = {"schema": "aragorn/pi-core-provider-operation/v1", "operation": "model_inference"}
_TOOL = {"name": "aragorn_runtime_create",
    "description": "Request a single policy-mediated file creation; this tool itself grants no authority.",
    "parameters": {"type": "object", "properties": {
        "content": {"type": "string", "maxLength": 32768},
        "target_name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}(?![\\s\\S])", "maxLength": 128}},
        "required": ["content", "target_name"], "additionalProperties": False}}


class PiProviderMediationError(RuntimeError):
    """A finite provider data contract or protected custody was refused."""


def _require(value, code):
    if not value:
        raise PiProviderMediationError(code)


def _exact(value, fields):
    _require(type(value) is dict and set(value) == fields, "PROVIDER_FIELDS_REFUSED")


def _uint(value, maximum=_SAFE):
    _require(type(value) is int and 0 <= value <= maximum, "PROVIDER_INTEGER_REFUSED")


def _text(value, maximum=32768, *, empty=False):
    try:
        valid = type(value) is str and (empty or bool(value)) and len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    _require(valid, "PROVIDER_TEXT_REFUSED")


def _copy(value):
    return json.loads(canonical_json(value))


def _model(value):
    _exact(value, {"id", "name", "api", "provider", "baseUrl", "reasoning", "input", "cost", "contextWindow", "maxTokens"})
    for field in ("id", "name", "api", "provider", "baseUrl"):
        _text(value[field], 2048)
    _require(type(value["reasoning"]) is bool and value["input"] == ["text"], "PROVIDER_MODEL_REFUSED")
    confined._uint(value["contextWindow"], 1, 10_000_000, "provider contextWindow")
    confined._uint(value["maxTokens"], 1, 1_000_000, "provider maxTokens")
    _exact(value["cost"], {"input", "output", "cacheRead", "cacheWrite"})
    for value in value["cost"].values():
        _uint(value)


def _content(value):
    if type(value) is str:
        _text(value, empty=True)
        return
    _require(type(value) is list and 1 <= len(value) <= 16, "PROVIDER_TEXT_BLOCKS_REFUSED")
    for block in value:
        _exact(block, {"type", "text"})
        _require(block["type"] == "text", "PROVIDER_TEXT_BLOCK_REFUSED")
        _text(block["text"], empty=True)


def validate_provider_request(value):
    """Validate/detach request bytes, never confer data or egress authority."""
    _exact(value, {"schema", "authority", "activation_id", "route_digest", "sequence", "payload"})
    _require(value["schema"] == REQUEST_SCHEMA and value["authority"] == REQUEST_AUTHORITY and
             type(value["activation_id"]) is str and channel._NONCE.fullmatch(value["activation_id"]) is not None and
             type(value["sequence"]) is int and value["sequence"] == 1, "PROVIDER_REQUEST_REFUSED")
    broker._require_digest(value["route_digest"], "provider route digest")
    payload = value["payload"]
    _exact(payload, {"schema", "model", "messages"})
    _require(payload["schema"] == "aragorn/pi-core-provider-payload/v1", "PROVIDER_PAYLOAD_REFUSED")
    _model(payload["model"])
    messages = payload["messages"]
    _require(type(messages) is list and len(messages) == 2, "PROVIDER_INITIAL_TRANSCRIPT_REQUIRED")
    for index, message in enumerate(messages):
        fields = {"role", "content", "timestamp"} | ({"toolsAdded"} if index == 0 else set())
        _exact(message, fields)
        _require(message["role"] == ("system" if index == 0 else "user") and
                 type(message["timestamp"]) is int and message["timestamp"] == 0,
                 "PROVIDER_INITIAL_TRANSCRIPT_REQUIRED")
        _content(message["content"])
    _require(canonical_json(messages[0]["toolsAdded"]) == canonical_json([_TOOL]), "PROVIDER_TOOL_SCHEMA_REFUSED")
    _require(len(canonical_json(payload)) <= MAX_PAYLOAD and len(canonical_json(value)) <= MAX_FRAME,
             "PROVIDER_REQUEST_LIMIT")
    return _copy(value)


def validate_provider_result(value, request_digest):
    _exact(value, {"schema", "authority", "request_digest", "status", "completion"})
    broker._require_digest(request_digest, "provider request digest")
    _require(value["schema"] == RESULT_SCHEMA and value["authority"] == RESULT_AUTHORITY and
             value["request_digest"] == request_digest and
             type(value["status"]) is str and value["status"] in {"COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"},
             "PROVIDER_RESULT_REFUSED")
    completion = value["completion"]
    if value["status"] != "COMPLETED":
        _require(completion is None, "PROVIDER_REFUSAL_COMPLETION_REFUSED")
    else:
        _exact(completion, {"stop_reason", "content", "usage"})
        content = completion["content"]
        _require(type(completion["stop_reason"]) is str and completion["stop_reason"] in {"stop", "toolUse"} and type(content) is list and
                 1 <= len(content) <= 16, "PROVIDER_COMPLETION_REFUSED")
        calls = 0
        for block in content:
            _require(type(block) is dict, "PROVIDER_COMPLETION_BLOCK_REFUSED")
            if block.get("type") == "text":
                _exact(block, {"type", "text"})
                _text(block["text"], empty=True)
            else:
                _exact(block, {"type", "id", "name", "arguments"})
                _require(block["type"] == "toolCall" and block["name"] == "aragorn_runtime_create",
                         "PROVIDER_TOOL_CALL_REFUSED")
                _text(block["id"], 4096)
                args = block["arguments"]
                _exact(args, {"target_name", "content"})
                _require(type(args["target_name"]) is str and _TARGET.fullmatch(args["target_name"]) is not None,
                         "PROVIDER_TOOL_TARGET_REFUSED")
                _text(args["content"], empty=True)
                calls += 1
        _require(calls == (1 if completion["stop_reason"] == "toolUse" else 0), "PROVIDER_TOOL_COUNT_REFUSED")
        _exact(completion["usage"], {"input_tokens", "output_tokens"})
        for count in completion["usage"].values():
            _uint(count)
        _uint(sum(completion["usage"].values()))
    _require(len(canonical_json(value)) <= MAX_FRAME, "PROVIDER_RESULT_LIMIT")
    return _copy(value)


def validate_route(value):
    """Validate a descriptor only; this is not actual destination verification."""
    _exact(value, {"schema", "provider", "api", "model", "endpoint"})
    _require(value["schema"] == "aragorn/pi-core-provider-route/v1", "PROVIDER_ROUTE_REFUSED")
    for field in ("provider", "api", "model"):
        _text(value[field], 2048)
    endpoint = value["endpoint"]
    _exact(endpoint, {"scheme", "host", "port", "path"})
    _require(endpoint["scheme"] == "https" and type(endpoint["port"]) is int and endpoint["port"] == 443 and
             type(endpoint["host"]) is str and _DNS.fullmatch(endpoint["host"]) is not None and
             not endpoint["host"].endswith((".localhost", ".local")) and
             type(endpoint["path"]) is str and len(endpoint["path"]) <= 2048 and
             _PATH.fullmatch(endpoint["path"]) is not None, "PROVIDER_ENDPOINT_DESCRIPTOR_REFUSED")
    return _copy(value)


def _approval(value, request, activation):
    _exact(value, {"schema", "authority", "activation_digest", "route", "data_class", "payload_digest", "max_requests", "request"})
    _require(value["schema"] == APPROVAL_SCHEMA and value["authority"] == APPROVAL_AUTHORITY and
             value["activation_digest"] == canonical_digest(activation) and
             type(value["data_class"]) is str and value["data_class"] in {"PUBLIC", "FABRICATED_OWNED_LAB"} and
             type(value["max_requests"]) is int and value["max_requests"] == 1 and
             value["payload_digest"] == canonical_digest(request["payload"]), "PROVIDER_DATA_APPROVAL_REFUSED")
    route = validate_route(value["route"])
    model = request["payload"]["model"]
    _require(request["route_digest"] == canonical_digest(route) and request["activation_id"] == activation["activation_id"] and
             route["provider"] == model["provider"] and route["api"] == model["api"] and route["model"] == model["id"] and
             model["baseUrl"] == "https://" + route["endpoint"]["host"] + route["endpoint"]["path"],
             "PROVIDER_ROUTE_MODEL_BINDING_REFUSED")
    action = broker._validate_runtime_action_request(value["request"])
    digests = {"operation_digest": canonical_digest(_OPERATION), "path_digest": canonical_digest(route),
               "payload_digest": value["payload_digest"]}
    _require(all(action[key] == activation[key] for key in
                 ("runtime_digest", "session_id", "run_id", "active_skill_digest", "policy_digest")) and
             action["tool_call_id"] == canonical_digest(request) and
             all(action[key] == digest for key, digest in digests.items()), "PROVIDER_ACTION_BINDING_REFUSED")
    return _copy(value), digests


def _result(request_digest, status, completion=None):
    return validate_provider_result({"schema": RESULT_SCHEMA, "authority": RESULT_AUTHORITY,
        "request_digest": request_digest, "status": status, "completion": completion}, request_digest)


def _wall_time():
    value = time.time()
    _require(type(value) in (int, float) and math.isfinite(value) and value >= 0, "PROVIDER_CLOCK_REFUSED")
    return value


def _claim_name(activation):
    return "provider-activation-" + activation["activation_id"] + ".json"


def _absent_claim(control_fd, name):
    try:
        os.stat(name, dir_fd=control_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PiProviderMediationError("PROVIDER_ACTIVATION_ALREADY_SPENT")


def _claim_once(control_fd, activation, request_digest, approval_digest):
    """One exact permanent claim. Any partial file is intentionally retained."""
    name = _claim_name(activation)
    raw = canonical_json({"schema": "aragorn/pi-core-provider-activation-claim/v1",
        "authority": "PERSISTENT_PROVIDER_BUDGET_CONSUMPTION_NOT_EGRESS_AUTHORITY",
        "activation_digest": canonical_digest(activation), "request_digest": request_digest,
        "approval_digest": approval_digest, "status": "SPENT"})
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o400, dir_fd=control_fd)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                 stat.S_IMODE(before.st_mode) == 0o400 and before.st_size == 0, "PROVIDER_CLAIM_METADATA_REFUSED")
        broker.write_all(descriptor, raw)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
                 stat.S_ISREG(after.st_mode) and after.st_uid == 0 and after.st_nlink == 1 and
                 stat.S_IMODE(after.st_mode) == 0o400 and after.st_size == len(raw), "PROVIDER_CLAIM_CHANGED")
        os.fsync(control_fd)
        _require(broker._file_identity(after) == broker._file_identity(os.stat(name, dir_fd=control_fd, follow_symlinks=False)) and
                 broker._read_owned_bytes_at(control_fd, name, max_bytes=4096, expected_uid=0,
                     exact_mode=0o400, label="provider activation claim") == raw, "PROVIDER_CLAIM_READBACK_REFUSED")
    finally:
        os.close(descriptor)


def handle_pi_provider_connection(worker_connection, provider_connection, config, *, activation_path,
        profile, protected_install_root, grant, expected_provider_peer, deadline):
    """Mediate one actual initial Pi request, with no listener/provider execution.

    Caller owns both channels. This owns only newly opened descriptors and holds
    lineage before the broker lock. Cleanup completes before a COMPLETED worker
    response. Protected preexisting state is never overwritten or synthesized.
    """
    _require(os.geteuid() == os.getegid() == 0, "PROVIDER_ROOT_REQUIRED")
    channel.validate_deadline(deadline)
    _require(type(config) is broker.RuntimeActionBrokerConfig and config.expected_broker_uid == 0,
             "PROVIDER_ROOT_CONFIG_REQUIRED")
    broker._validate_config(config)
    _require(type(profile) is process.RuntimeProcessProfile and isinstance(protected_install_root, Path) and
             protected_install_root.is_absolute() and protected_install_root != Path("/"), "PROVIDER_PROFILE_REFUSED")
    peer = channel._peer(expected_provider_peer)
    _require(peer[1] > 0 and peer[2] > 0 and peer[0] != os.getpid(), "PROVIDER_SERVICE_ROLE_REFUSED")
    _require(worker_connection is not provider_connection and worker_connection.fileno() != provider_connection.fileno() and
             worker_connection.getsockopt(socket.SOL_SOCKET, channel._DOMAIN) == socket.AF_UNIX and
             worker_connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
             "PROVIDER_CHANNELS_REFUSED")
    reserved = {path.name for path in (config.socket_path, config.instance_lock_path, config.lock_path,
        config.policy_path, config.revocations_path, config.health_path, config.observation_path, config.state_path)}
    _require(APPROVAL_NAME not in reserved and not any(name.startswith("provider-activation-") for name in reserved),
             "PROVIDER_CONTROL_PATH_OVERLAP")
    activation = identity.read_activation(activation_path)
    _require(profile.digest == activation["profile_digest"] and
             config.expected_runtime_digest == activation["runtime_digest"] and
             (config.expected_runtime_uid, config.expected_runtime_gid) == (activation["uid"], activation["gid"]) and
             peer[0] != activation["pid"] and peer[1] not in {activation["uid"], config.expected_peer_uid} and
             peer[2] not in {activation["gid"], config.expected_peer_gid},
             "PROVIDER_ACTIVATION_ROLE_REFUSED")
    worker_peer = (activation["pid"], activation["uid"], activation["gid"])
    _require(tuple(broker._peer_credentials(worker_connection)) == worker_peer, "PROVIDER_WORKER_PEER_REFUSED")
    deadline = min(deadline, activation["expires_at_monotonic_ns"] / 1_000_000_000)
    worker_fd = provider_fd = control_fd = lock_fd = -1
    locked = submitted = claim_attempted = False
    request = approval = result = decision = None
    failure = cleanup_failure = None
    stage = "IDENTITY"
    held = ExitStack()
    try:
        worker_fd = process.open_peer_pidfd(worker_connection, worker_peer[0])
        measured = identity._measured(worker_connection, worker_fd, profile, activation, deadline)
        active = held.enter_context(identity.lineage.hold_runtime_active_skill_lineage(worker_peer[0], measured, grant,
            protected_root=protected_install_root, expected_install_uid=0, deadline=deadline))
        identity._lineage_matches(active, activation, profile, protected_install_root)

        def guard():
            identity._remaining(deadline, activation)
            _require(identity.read_activation(activation_path) == activation and
                     identity._measured(worker_connection, worker_fd, profile, activation, deadline) == measured,
                     "PROVIDER_WORKER_CUSTODY_CHANGED")
            if provider_fd >= 0:
                channel.require_peer_live(provider_connection, peer, provider_fd, deadline)

        stage = "REQUEST"
        request = validate_provider_request(broker._read_frame(worker_connection, deadline))
        _require(request["activation_id"] == activation["activation_id"], "PROVIDER_REQUEST_ACTIVATION_REFUSED")
        guard()
        stage = "APPROVAL"
        control_fd = broker._open_protected_directory(config.control_root, 0, "provider control root")
        control_identity = broker._directory_identity(os.fstat(control_fd))
        lock_fd = broker._open_lock_file(control_fd, config)
        broker._acquire_lock(lock_fd, deadline)
        locked = True

        def read_approval():
            _require(broker._directory_identity(os.lstat(config.control_root)) ==
                     broker._directory_identity(os.fstat(control_fd)) == control_identity, "PROVIDER_CONTROL_ROOT_CHANGED")
            return broker._load_control(control_fd, config.control_root / APPROVAL_NAME, config, "provider data approval")

        approval, digests = _approval(read_approval(), request, activation)
        # Sample monotonic first: delay between samples shortens the budget.
        # Never derive remaining lifetime from a truncated wall-clock second.
        sampled_monotonic = time.monotonic()
        wall_time = _wall_time()
        now = broker._clock_value(lambda: int(wall_time))
        action = approval["request"]
        _require(action["issued_at_unix"] <= wall_time < action["expires_at_unix"], "PROVIDER_ACTION_EXPIRED")
        deadline = min(deadline, sampled_monotonic + action["expires_at_unix"] - wall_time)
        guard()
        _absent_claim(control_fd, _claim_name(activation))
        stage = "POLICY"
        state, observation_digest, decision, reasons = broker._evaluate_snapshot(control_fd, config, action, digests, now)
        _require(state["effect_journal"] is None, "PROVIDER_PENDING_EFFECT_REFUSED")
        _require(decision["verdict"] == "ALLOW" and not reasons, "PROVIDER_POLICY_REFUSED")
        action_digest = canonical_digest(action)
        _require(len(state["consumed"]) < broker._MAX_CONSUMED and not any(
            entry["request_digest"] == action_digest or entry["observation_digest"] == observation_digest
            for entry in state["consumed"]), "PROVIDER_REPLAY_REFUSED")
        provider_fd = channel.guard_channel(provider_connection, peer, deadline)
        guard()
        stage = "CLAIM"
        claim_attempted = True
        _claim_once(control_fd, activation, canonical_digest(request), canonical_digest(approval))
        state["consumed"].append({"request_digest": action_digest, "observation_digest": observation_digest,
                                  "expires_at_unix": action["expires_at_unix"]})
        state["consumed"] = sorted(state["consumed"], key=canonical_json)
        broker._commit_state(control_fd, config, state)
        stage = "FINAL_POLICY"
        _require(read_approval() == approval, "PROVIDER_APPROVAL_CHANGED")
        guard()
        final_wall_time = _wall_time()
        final_now = broker._clock_value(lambda: int(final_wall_time))
        _require(wall_time <= final_wall_time < action["expires_at_unix"], "PROVIDER_CLOCK_ROLLBACK_OR_EXPIRED")
        current, current_observation, decision, reasons = broker._evaluate_snapshot(
            control_fd, config, action, digests, final_now, minimum_state=state)
        _require(current["effect_journal"] is None and current_observation == observation_digest and
                 decision["verdict"] == "ALLOW" and not reasons and any(
                     entry["request_digest"] == action_digest and entry["observation_digest"] == observation_digest
                     for entry in current["consumed"]), "PROVIDER_FINAL_POLICY_REFUSED")
        guard()
        nonce = secrets.token_hex(16)
        _require(channel._NONCE.fullmatch(nonce) is not None, "PROVIDER_NONCE_REFUSED")
        fields = {"schema": SERVICE_SCHEMA, "authority": SERVICE_AUTHORITY, "nonce": nonce,
                  "deadline_ns": min(math.floor(deadline * 1_000_000_000), activation["expires_at_monotonic_ns"]),
                  "request_digest": canonical_digest(request)}
        packet = {**fields, "kind": "REQUEST", "request": request, "route": approval["route"]}
        _require(len(canonical_json(packet)) <= MAX_FRAME, "PROVIDER_SERVICE_PACKET_LIMIT")
        identity._remaining(deadline, activation)
        _require(final_wall_time <= _wall_time() < action["expires_at_unix"], "PROVIDER_CLOCK_ROLLBACK_OR_EXPIRED")
        stage = "SERVICE"
        submitted = True  # An attempted send is never retried or called not-submitted on failure.
        channel.send_authenticated_packet(provider_connection, packet, deadline, max_bytes=MAX_FRAME)
        reply, rights = channel.receive_authenticated_packet(provider_connection, peer, deadline,
            expected_rights=0, max_bytes=MAX_FRAME)
        _exact(reply, {*fields, "kind", "result"})
        _require(not rights and all(reply[key] == value for key, value in fields.items()) and reply["kind"] == "RESULT",
                 "PROVIDER_SERVICE_REPLY_REFUSED")
        result = validate_provider_result(reply["result"], canonical_digest(request))
        guard()
        _require(read_approval() == approval, "PROVIDER_APPROVAL_CHANGED")
    except BaseException as exc:
        failure = exc
    finally:
        # The lineage lock was acquired first. Release control lock/FDs before
        # lineage, then both retained process handles; attempt every owned close.
        try:
            cleanup_failure = broker._release_lock_and_close(lock_fd, locked, control_fd)
        except BaseException as exc:
            cleanup_failure = exc
        try:
            held.close()
        except BaseException as exc:
            cleanup_failure = cleanup_failure or exc
        try:
            channel._close_installed([fd for fd in (worker_fd, provider_fd) if fd >= 0])
        except BaseException as exc:
            cleanup_failure = cleanup_failure or exc
    if cleanup_failure is not None:
        failure = failure or cleanup_failure
        stage = "CLEANUP"
    status = ("INDETERMINATE" if submitted else "NOT_SUBMITTED") if failure is not None else result["status"]
    if failure is not None and not isinstance(failure, Exception):
        raise failure
    delivery = "NOT_ATTEMPTED"
    if request is not None:
        response = _result(canonical_digest(request), status) if failure is not None else result
        try:
            channel.validate_deadline(deadline)
            broker._send_frame(worker_connection, canonical_json(response), deadline)
            worker_connection.shutdown(socket.SHUT_WR)
            delivery = "FRAME_AND_EOF_SENT_NOT_ACKNOWLEDGED"
        except Exception:
            delivery = "UNCONFIRMED"
            status = "INDETERMINATE" if submitted else "NOT_SUBMITTED"
    return {"schema": "aragorn/pi-core-provider-mediation-observation/v1",
        "authority": "PROVIDER_DATA_GATE_OBSERVATION_NOT_EGRESS_OR_RUN_AUTHORITY",
        "status": status, "request_digest": canonical_digest(request) if request is not None else None,
        "approval_digest": canonical_digest(approval) if approval is not None else None,
        "decision_digest": canonical_digest(decision) if decision is not None else None,
        "activation_digest": canonical_digest(activation), "submission_attempted": submitted,
        "activation_claim": "RETAINED_OR_UNCERTAIN" if claim_attempted else "NOT_ATTEMPTED",
        "cleanup": "CLEANUP_HOLD" if cleanup_failure is not None else "OWNED_HANDLES_CLOSED",
        "client_delivery": delivery, "failure_stage": stage if failure is not None else None,
        "provider_transport_implemented": False, "phase3_eligible": False}
