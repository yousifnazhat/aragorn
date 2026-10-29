"""Pure, independent joins of four retained worker-ingress records.

Caller-held digests are trust anchors, not proof of producer execution or source
custody. No worker, receipt producer, observer, clock or filesystem is imported.
Outer replay must separately bind these records to actual process observations,
the same boot/clock domain, a broker decision and protected-sink observations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from .oci_worker_protocol import canonical_digest, canonical_json


SCHEMA = "aragorn/native-worker-ingress-verification/v1"
AUTHORITY = "RETAINED_WORKER_INGRESS_JOINS_NOT_EVENT_ATTESTATION_OR_LATENCY"
RECORD_SCHEMA = "aragorn/native-worker-ingress-record/v1"
RECORD_AUTHORITY = "WORKER_LOCAL_DURABLE_INGRESS_JOINS_NOT_EFFECT_OR_RUN_AUTHORITY"
STAGES = ("startup", "ingress", "attempt", "action")
MAX_RECORD_BYTES = 192 * 1024
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
    "effect_observed",
    "broker_decision_observed",
    "elapsed_time_derived",
    "clock_domain_verified",
    "boot_observed",
)
RECORD_LIMITATIONS = (
    "AUTHENTICATED_NON_RECEIPT_FRAME_BEFORE_OPEN_ATTEMPT_GATE_NOT_NATIVE_CALL_START",
    "LOCAL_WORKER_OWNED_STORE_NOT_HOSTILE_OWNER_OR_ROOT_RESISTANT",
    "STARTUP_AND_ONE_INGRESS_ONLY_NO_RETRY_REPAIR_OR_RESET",
    "SELF_ACTIVE_TIME_NAMESPACE_ONLY_NO_BOOT_ID_OR_CROSS_PROCESS_CLOCK_PROOF",
    "POINT_IN_TIME_IDENTITY_READBACKS_NOT_CONTINUOUS_IMMUTABILITY",
    "NO_BROKER_DECISION_EFFECT_ACK_ELAPSED_TIME_OR_QUALIFICATION",
    "SYNC_RETENTION_ADDS_UNQUALIFIED_OVERHEAD_NO_HARD_DEADLINE",
)
LIMITATIONS = (
    "CALLER_PINNED_RECORDS_NOT_SOURCE_OR_PRODUCER_EXECUTION_ATTESTATION",
    "RETAINED_INGRESS_ASSOCIATION_NOT_GATEWAY_AUTHENTICATION_OR_NATIVE_CALL_CAUSALITY_PROOF",
    "RECEIPT_TAIL_AND_DIGEST_INVENTORY_NOT_WHOLE_HISTORY_OR_GENESIS_CONTENT_VERIFICATION",
    "PARAMS_DIGEST_NOT_RETAINED_PARAMETER_BYTES_OR_TOOL_SEMANTICS",
    "PATH_DIGEST_SYNTAX_ONLY_NOT_PROTECTED_INODE_OR_SINK_OBSERVATION",
    "NO_BOOT_OR_EXTERNAL_CLOCK_COMPARABILITY_OR_CONTINUOUS_IDENTITY_PROOF",
    "NO_BROKER_FINAL_DECISION_ELAPSED_LATENCY_EFFECT_OR_QUALIFICATION",
)
_EPOCH = {"pid", "start_time_ticks", "uid", "gid"}
_FIELDS = {
    "schema",
    "authority",
    "stage",
    "previous_digest",
    "worker_binding",
    "worker_binding_digest",
    "worker_identity",
    "time_namespace",
    "boottime_ns",
    "body",
    "decision",
    "limitations",
}
_RECEIPT_AUTHORITY = "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
_EVENT_AUTHORITY = (
    "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY"
)


class WorkerIngressVerificationError(ValueError):
    """Pinned ingress records do not support the exact bounded association."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkerIngressVerificationError(message)


def _exact(value: object, keys: set[str], label: str) -> dict:
    _require(type(value) is dict and set(value) == keys, label + " fields changed")
    return value


def _uint(value: object, minimum: int = 0, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid digest",
    )
    return value


def _sized(value: object, limit: int, label: str) -> None:
    _require(len(canonical_json(value)) <= limit, label + " exceeds byte bound")


def _identifier(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", value) is not None
    )


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _noninteger(_value: str) -> None:
    raise WorkerIngressVerificationError("noninteger JSON number")


def _parse(raw: bytes, expected: str) -> dict:
    _require(
        type(raw) is bytes and 0 < len(raw) <= MAX_RECORD_BYTES,
        "record bytes are invalid or oversized",
    )
    _require(
        "sha256:" + hashlib.sha256(raw).hexdigest() == _pin(expected),
        "record differs from caller digest",
    )
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_float=_noninteger,
        parse_constant=_noninteger,
    )
    _require(canonical_json(value) == raw, "record bytes are not canonical")
    return _exact(value, _FIELDS, "ingress record")


def _binding(value: object, expected: str) -> dict:
    value = _exact(
        value,
        {
            "schema",
            "runtime_digest",
            "active_skill_digest",
            "policy_digest",
            "policy_version",
        },
        "worker binding",
    )
    _sized(value, 4096, "worker binding")
    _require(
        value["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and _uint(value["policy_version"], 1, 2**53 - 1),
        "worker binding contract changed",
    )
    for name in ("runtime_digest", "active_skill_digest", "policy_digest"):
        _pin(value[name])
    _require(
        canonical_digest(value) == expected, "worker binding differs from caller digest"
    )
    return value


def _record(
    value: dict,
    stage: str,
    previous: str | None,
    expected_worker: dict,
    binding_digest: str,
) -> None:
    _require(
        value["schema"] == RECORD_SCHEMA
        and value["authority"] == RECORD_AUTHORITY
        and value["stage"] == stage
        and value["previous_digest"] == previous
        and value["limitations"] == list(RECORD_LIMITATIONS),
        "record kind, stage, chain or limitations changed",
    )
    decision = _exact(value["decision"], set(FALSE_FLAGS), "record decision")
    _require(
        all(flag is False for flag in decision.values()), "record claim ceiling changed"
    )
    _require(
        _pin(value["worker_binding_digest"]) == binding_digest,
        "record binding digest changed",
    )
    _binding(value["worker_binding"], binding_digest)
    identity = _exact(
        value["worker_identity"], _EPOCH | {"uids", "gids"}, "worker identity"
    )
    _require(
        all(_uint(identity[key], 1) for key in _EPOCH),
        "worker identity scalar is invalid",
    )
    _require(
        {key: identity[key] for key in _EPOCH} == expected_worker,
        "worker epoch differs from caller identity",
    )
    for key, scalar in (("uids", "uid"), ("gids", "gid")):
        vector = identity[key]
        _require(
            type(vector) is list
            and len(vector) == 4
            and all(_uint(item, 1) and item == identity[scalar] for item in vector),
            "worker account vector changed",
        )
    namespace = _exact(
        value["time_namespace"], {"device", "inode"}, "active time namespace"
    )
    _require(
        _uint(namespace["device"]) and _uint(namespace["inode"], 1),
        "invalid active time namespace",
    )
    _require(_uint(value["boottime_ns"]), "invalid retained boottime stamp")


def _ingress(body: object) -> tuple[dict, bytes]:
    body = _exact(
        body,
        {"worker_request", "worker_request_digest", "gateway_peer"},
        "ingress body",
    )
    peer = _exact(body["gateway_peer"], {"pid", "uid", "gid"}, "gateway peer")
    _require(
        all(_uint(item, 1) for item in peer.values()), "gateway peer scalar is invalid"
    )
    request = _exact(
        body["worker_request"],
        {
            "schema",
            "authority",
            "target_name",
            "payload_base64",
            "session_id",
            "run_id",
            "tool_call_digest",
        },
        "worker request",
    )
    _sized(request, 64 * 1024, "worker request")
    _require(
        request["schema"] == "aragorn/runtime-action-worker-request/v1"
        and request["authority"] == "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
        and type(request["target_name"]) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", request["target_name"])
        is not None
        and all(_identifier(request[name]) for name in ("session_id", "run_id")),
        "worker request contract changed",
    )
    _pin(request["tool_call_digest"])
    encoded = request["payload_base64"]
    _require(
        type(encoded) is str and len(encoded) <= ((32 * 1024 + 2) // 3) * 4,
        "worker payload encoding exceeds bound",
    )
    payload = base64.b64decode(encoded, validate=True)
    _require(
        len(payload) <= 32 * 1024
        and base64.b64encode(payload).decode("ascii") == encoded,
        "worker payload is not canonical",
    )
    _require(
        canonical_digest(request) == _pin(body["worker_request_digest"]),
        "worker request digest changed",
    )
    return request, payload


def _attempt(body: object, request: dict, expected_genesis: str) -> tuple[str, str]:
    body = _exact(
        body,
        {
            "attempt",
            "attempt_digest",
            "receipt_state",
            "receipt_state_digest",
            "genesis_digest",
            "worker_request_digest",
        },
        "attempt body",
    )
    request_pin = canonical_digest(request)
    _require(
        _pin(body["genesis_digest"]) == expected_genesis
        and _pin(body["worker_request_digest"]) == request_pin,
        "attempt caller genesis or request binding changed",
    )
    receipt = _exact(
        body["attempt"],
        {
            "schema",
            "authority",
            "genesis_digest",
            "sequence",
            "previous_digest",
            "event",
        },
        "attempt receipt",
    )
    _sized(receipt, 4096, "attempt receipt")
    state = _exact(
        body["receipt_state"],
        {"schema", "authority", "genesis_digest", "receipts"},
        "receipt state",
    )
    _sized(state, 128 * 1024, "receipt state")
    _require(
        receipt["schema"] == "aragorn/native-tool-receipt/v1"
        and state["schema"] == "aragorn/native-tool-receipt-state/v1"
        and receipt["authority"] == state["authority"] == _RECEIPT_AUTHORITY
        and receipt["genesis_digest"] == state["genesis_digest"] == expected_genesis,
        "native attempt or state contract changed",
    )
    receipt_pin = _pin(body["attempt_digest"])
    state_pin = _pin(body["receipt_state_digest"])
    _require(
        canonical_digest(receipt) == receipt_pin
        and canonical_digest(state) == state_pin,
        "attempt or state digest changed",
    )
    digests = state["receipts"]
    _require(
        type(digests) is list and 1 <= len(digests) <= 1024 and len(digests) % 2 == 1,
        "receipt state is not an open attempt tail",
    )
    for pin in digests:
        _pin(pin)
    _require(
        len(set(digests)) == len(digests)
        and digests[-1] == receipt_pin
        and _uint(receipt["sequence"], 1, 1024)
        and receipt["sequence"] == len(digests)
        and receipt["previous_digest"]
        == (expected_genesis if len(digests) == 1 else digests[-2]),
        "attempt sequence or retained tail changed",
    )
    event = _exact(
        receipt["event"],
        {
            "schema",
            "authority",
            "tool_name",
            "session_id",
            "run_id",
            "session_key_digest",
            "tool_call_digest",
            "params_digest",
            "params_bytes",
            "worker_request_digest",
        },
        "native attempt event",
    )
    _require(
        event["schema"] == "aragorn/native-tool-attempt/v1"
        and event["authority"] == _EVENT_AUTHORITY
        and event["tool_name"] == "aragorn_runtime_create"
        and all(
            _identifier(event[name]) and event[name] == request[name]
            for name in ("session_id", "run_id")
        )
        and event["tool_call_digest"] == request["tool_call_digest"]
        and event["worker_request_digest"] == request_pin
        and _uint(event["params_bytes"], 0, 16 * 1024 * 1024),
        "attempt event differs from worker request",
    )
    for name in (
        "session_key_digest",
        "tool_call_digest",
        "params_digest",
        "worker_request_digest",
    ):
        _pin(event[name])
    return receipt_pin, state_pin


def _action(
    body: object, request: dict, payload: bytes, binding: dict, attempt_pin: str
) -> str:
    body = _exact(
        body,
        {
            "action_request",
            "action_request_digest",
            "worker_request_digest",
            "attempt_digest",
        },
        "action body",
    )
    _require(
        _pin(body["worker_request_digest"]) == canonical_digest(request)
        and _pin(body["attempt_digest"]) == attempt_pin,
        "action association changed",
    )
    action = _exact(
        body["action_request"],
        {
            "schema",
            "authority",
            "runtime_digest",
            "session_id",
            "run_id",
            "tool_call_id",
            "active_skill_digest",
            "operation_digest",
            "path_digest",
            "payload_digest",
            "policy_digest",
            "policy_version",
            "issued_at_unix",
            "expires_at_unix",
        },
        "action request",
    )
    _sized(action, 16384, "action request")
    _require(
        action["schema"] == "aragorn/runtime-action-request/v1"
        and action["authority"] == "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
        and all(
            action[key] == binding[key]
            for key in ("runtime_digest", "active_skill_digest", "policy_digest")
        )
        and _uint(action["policy_version"], 1, 2**53 - 1)
        and action["policy_version"] == binding["policy_version"]
        and all(action[key] == request[key] for key in ("session_id", "run_id"))
        and action["tool_call_id"] == request["tool_call_digest"],
        "action differs from worker binding or request",
    )
    for key in (
        "runtime_digest",
        "active_skill_digest",
        "policy_digest",
        "tool_call_id",
        "operation_digest",
        "path_digest",
        "payload_digest",
    ):
        _pin(action[key])
    _require(
        action["operation_digest"]
        == canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        )
        and action["payload_digest"] == "sha256:" + hashlib.sha256(payload).hexdigest(),
        "action operation or payload differs from ingress",
    )
    _require(
        _uint(action["issued_at_unix"])
        and _uint(action["expires_at_unix"])
        and action["expires_at_unix"] - action["issued_at_unix"] == 5,
        "action request lifetime changed",
    )
    pin = _pin(body["action_request_digest"])
    _require(canonical_digest(action) == pin, "action request digest changed")
    return pin


def verify_worker_ingress_records(
    startup_raw: bytes,
    ingress_raw: bytes,
    attempt_raw: bytes,
    action_raw: bytes,
    *,
    expected_record_digests: dict[str, str],
    expected_worker: dict,
    expected_binding_digest: str,
    expected_genesis_digest: str,
) -> dict:
    """Validate one retained ingress association, never a measured latency."""
    try:
        pins = dict(
            _exact(expected_record_digests, set(STAGES), "expected record pins")
        )
        worker = dict(_exact(expected_worker, _EPOCH, "expected worker epoch"))
        _require(
            all(_uint(value, 1) for value in worker.values()),
            "expected worker scalar is invalid",
        )
        binding_pin, genesis_pin = (
            _pin(expected_binding_digest),
            _pin(expected_genesis_digest),
        )
        records = {}
        previous = None
        for stage, raw in zip(
            STAGES, (startup_raw, ingress_raw, attempt_raw, action_raw), strict=True
        ):
            value = _parse(raw, pins[stage])
            _record(value, stage, previous, worker, binding_pin)
            records[stage] = value
            previous = pins[stage]
        first = records["startup"]
        _require(
            all(
                value["worker_identity"] == first["worker_identity"]
                and value["time_namespace"] == first["time_namespace"]
                and value["worker_binding"] == first["worker_binding"]
                for value in records.values()
            ),
            "worker identity, namespace or binding changed across records",
        )
        stamps = [records[stage]["boottime_ns"] for stage in STAGES]
        _require(
            all(left < right for left, right in zip(stamps, stamps[1:])),
            "ingress chronology is not strictly increasing",
        )
        _exact(first["body"], set(), "startup body")
        request, payload = _ingress(records["ingress"]["body"])
        attempt_pin, state_pin = _attempt(
            records["attempt"]["body"], request, genesis_pin
        )
        action_pin = _action(
            records["action"]["body"],
            request,
            payload,
            first["worker_binding"],
            attempt_pin,
        )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "RETAINED_WORKER_INGRESS_CHAIN_VERIFIED",
            "record_digests": pins,
            "worker_identity": first["worker_identity"],
            "worker_binding_digest": binding_pin,
            "time_namespace": first["time_namespace"],
            "clock_id": "CLOCK_BOOTTIME",
            "stage_boottime_ns": dict(zip(STAGES, stamps, strict=True)),
            "worker_request_digest": canonical_digest(request),
            "attempt_digest": attempt_pin,
            "receipt_state_digest": state_pin,
            "genesis_digest": genesis_pin,
            "action_request_digest": action_pin,
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
        }
    except WorkerIngressVerificationError:
        raise
    except Exception as exc:
        raise WorkerIngressVerificationError(
            "retained worker ingress verification refused"
        ) from exc
