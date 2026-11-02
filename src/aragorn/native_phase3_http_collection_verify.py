"""Independent, finite joins for retained native HTTP collection evidence.

No socket, producer action, clock sampling or effect retry occurs here.  The
consumer reconstructs HTTP claims rather than trusting the producer's HTTP
validator.  Recorded policy decisions and source pins remain custody claims,
not proof of native causation or Phase 3 qualification.
"""

from __future__ import annotations

import json
import re

from . import native_phase3_http_canary_contract as canary
from . import runtime_worker_ingress_verify as ingress
from .oci_worker_protocol import canonical_digest, canonical_json

TOOL = "aragorn_runtime_http_canary"
PROFILED = "aragorn/runtime-observed-http-submission/v2"
_MATCH = {
    "runtime_digest",
    "active_skill_digest",
    "policy_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
}
_MEASURED = {
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
}
_EPOCH = {"pid", "start_time_ticks", "uid", "gid"}
FALSE_FLAGS = (
    "blocked_pre_effect",
    "causal_attribution",
    "measurement_collected",
    "run_eligible",
    "phase3_exit_eligible",
    "live_deployment_attested",
    "generic_collector_semantics_eligible",
    "broker_restricted_readiness_verified",
)


class NativeHttpCollectionVerificationError(ValueError):
    """Fixed retained-evidence refusal, without unclassified diagnostics."""


def _require(condition, reason="HTTP_COLLECTION_BINDING_CHANGED"):
    if not condition:
        raise NativeHttpCollectionVerificationError(reason)


def _exact(value, keys):
    _require(
        type(value) is dict and set(value) == set(keys), "HTTP_COLLECTION_SHAPE_CHANGED"
    )
    return value


def _pin(value):
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "HTTP_COLLECTION_PIN_CHANGED",
    )
    return value


def _uint(value, minimum=0):
    _require(
        type(value) is int and minimum <= value < 2**63,
        "HTTP_COLLECTION_INTEGER_CHANGED",
    )
    return value


def _raw(raw, pin, limit=192 * 1024):
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= limit
        and canary.digest(raw) == _pin(pin),
        "HTTP_COLLECTION_BYTES_CHANGED",
    )
    value = json.loads(raw)
    _require(canonical_json(value) == raw, "HTTP_COLLECTION_NONCANONICAL_BYTES")
    return value


def operation_descriptor():
    return {
        "schema": "aragorn/runtime-http-operation/v1",
        "operation": "http_canary_post",
    }


def effect_for_attempt(attempt_id):
    canary.canary_bytes(attempt_id)
    return {
        "schema": "aragorn/runtime-http-canary-effect/v1",
        "operation": "http_canary_post",
        "attempt_id": attempt_id,
    }


def fixture_binding(value):
    _exact(value, {"schema", "fixture", "expected_broker_uid", "expected_broker_gid"})
    _require(value["schema"] == "aragorn/runtime-http-fixture-binding/v1")
    canary.validate_fixture(value["fixture"])
    for key in ("expected_broker_uid", "expected_broker_gid"):
        _require(_uint(value[key], 1) < 2**31)
    return value


def endpoint_descriptor(binding):
    binding = fixture_binding(binding)
    return {
        "schema": "aragorn/runtime-http-endpoint/v1",
        "fixture_binding_digest": canonical_digest(binding),
        "fixture": binding["fixture"],
        "host": canary.HOST,
        "port": canary.PORT,
        "method": "POST",
        "path": "/aragorn-phase3-canary",
    }


def action_digests(attempt_id, binding):
    return {
        "operation_digest": canonical_digest(operation_descriptor()),
        "path_digest": canonical_digest(endpoint_descriptor(binding)),
        "payload_digest": canary.digest(canary.canary_request(attempt_id)),
    }


def validate_plan_descriptor(descriptor, grant, pins, attempt_id, boot_id):
    """Pure HTTP branch for the existing prepared binding planner."""
    _exact(
        descriptor,
        {
            "schema",
            "fixture_binding_digest",
            "fixture",
            "host",
            "port",
            "method",
            "path",
        },
    )
    canary.validate_fixture(descriptor["fixture"])
    _pin(descriptor["fixture_binding_digest"])
    _require(
        descriptor["schema"] == "aragorn/runtime-http-endpoint/v1"
        and descriptor["host"] == canary.HOST
        and descriptor["port"] == canary.PORT
        and type(descriptor["port"]) is int
        and descriptor["method"] == "POST"
        and descriptor["path"] == "/aragorn-phase3-canary"
        and descriptor["fixture"]["boot_id"] == boot_id
        and canonical_digest(descriptor) == pins["path"]
        and canary.digest(canary.canary_request(attempt_id)) == pins["payload"]
        and grant["operation_digest"] == canonical_digest(operation_descriptor()),
        "HTTP_PLAN_DESCRIPTOR_CHANGED",
    )


def native_join(plan, pending, state, profiled, grant_raw, path):
    """HTTP successor of the frozen consumer's create-specific native join."""
    from .runtime_capability_grant import (
        _profile_attribution,
        parse_runtime_capability_grant,
    )
    from .runtime_action_decision import _request as validate_runtime_action_request

    _exact(
        profiled,
        {
            "schema",
            "authority",
            "envelope",
            "envelope_digest",
            "request_digest",
            "measured_action",
            "runtime_peer",
            "sensor_digest",
            "runtime_attribution",
        },
    )
    _require(
        profiled["schema"] == PROFILED
        and profiled["authority"]
        == "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY"
    )
    envelope = _exact(profiled["envelope"], {"schema", "request", "effect"})
    _require(
        envelope["schema"] == "aragorn/runtime-http-broker-request/v1"
        and envelope["effect"] == effect_for_attempt(plan["attempt_id"])
    )
    request = envelope["request"]
    validate_runtime_action_request(request)
    _require(
        canonical_digest(envelope) == profiled["envelope_digest"]
        and canonical_digest(request) == profiled["request_digest"]
    )
    peer = _exact(profiled["runtime_peer"], {"pid", "uid", "gid"})
    for key in peer:
        _uint(peer[key], 1 if key == "pid" else 0)
    attribution = _profile_attribution(profiled)
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{key: request[key] for key in _MEASURED},
    }
    _require(
        profiled["measured_action"] == measured
        and all(attribution[key] == peer[key] for key in peer)
        and all(
            attribution[key] == plan[key]
            for key in ("runtime_digest", "active_skill_digest")
        )
        and attribution["profile_digest"] == plan["runtime_profile_digest"]
        and profiled["sensor_digest"] == plan["sensor_digest"]
        and all(request[key] == plan[key] for key in _MATCH)
    )
    _exact(state, {"schema", "authority", "grant_digest", "status", "claim", "result"})
    _require(
        state["schema"] == "aragorn/runtime-capability-grant-state/v1"
        and state["authority"]
        == "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and state["grant_digest"] == plan["grant_digest"]
        and state["status"] == "CONSUMED"
    )
    claim = _exact(
        state["claim"],
        {
            "schema",
            "authority",
            "grant_digest",
            "lease_digest",
            "lease",
            "profile_claim",
        },
    )
    profile = claim["profile_claim"]
    claimed = _uint(profile["claimed_at_unix"])
    grant = parse_runtime_capability_grant(grant_raw, claimed)
    validate_plan_descriptor(
        path,
        grant,
        {"path": plan["path_digest"], "payload": plan["payload_digest"]},
        plan["attempt_id"],
        plan["boot_id"],
    )
    lease = _exact(
        claim["lease"],
        {
            "schema",
            "authority",
            "grant_digest",
            "lease_nonce",
            "submission_digest",
            "runtime_attribution_digest",
            "runtime_profile_digest",
            "runtime_digest",
            "active_skill_digest",
            "sensor_digest",
            "request_digest",
            "policy_digest",
            "policy_version",
            "operation_digest",
            "path_digest",
            "payload_digest",
            "issued_at_unix",
            "expires_at_unix",
            "max_actions",
        },
    )
    for key in (
        "grant_digest",
        "submission_digest",
        "runtime_attribution_digest",
        "runtime_profile_digest",
        "runtime_digest",
        "active_skill_digest",
        "sensor_digest",
        "request_digest",
        "policy_digest",
        "operation_digest",
        "path_digest",
        "payload_digest",
    ):
        _pin(lease[key])
    _require(
        lease["schema"] == "aragorn/runtime-capability-lease/v2"
        and lease["authority"]
        == "SENSOR_ISSUED_SINGLE_CAPABILITY_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and type(lease["lease_nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", lease["lease_nonce"]) is not None
        and _uint(lease["max_actions"], 1) == 1
    )
    lease_pin, submission_pin = canonical_digest(lease), canonical_digest(profiled)
    attribution_pin, request_pin = (
        canonical_digest(attribution),
        canonical_digest(request),
    )
    expected_profile = {
        "schema": "aragorn/runtime-http-capability-lease-claim/v1",
        "authority": "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": lease_pin,
        "claimed_at_unix": claimed,
        "submission_digest": submission_pin,
        "runtime_attribution_digest": attribution_pin,
        "envelope_digest": canonical_digest(envelope),
        "request_digest": request_pin,
        "measured_action_digest": canonical_digest(measured),
        **{key: request[key] for key in ("session_id", "run_id", "tool_call_id")},
        "attempt_id": plan["attempt_id"],
        "effect_digest": canonical_digest(envelope["effect"]),
        "profile_pending": {
            "schema": "aragorn/runtime-process-profile-pending/v1",
            "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
            "submission_digest": submission_pin,
            "envelope_digest": canonical_digest(envelope),
            "request_digest": request_pin,
            "measured_action": measured,
            "runtime_attribution": attribution,
            "runtime_attribution_digest": attribution_pin,
        },
    }
    _require(
        canonical_digest(grant) == plan["grant_digest"]
        and claim
        == {
            "schema": "aragorn/runtime-capability-grant-claim/v1",
            "authority": "BROKER_GRANT_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": plan["grant_digest"],
            "lease_digest": lease_pin,
            "lease": lease,
            "profile_claim": expected_profile,
        }
        and pending["submission_digest"] == lease["submission_digest"] == submission_pin
        and pending["action_request_digest"] == lease["request_digest"] == request_pin
        and pending["runtime_attribution_digest"]
        == lease["runtime_attribution_digest"]
        == attribution_pin
        and pending["lease_digest"] == lease_pin
        and lease["grant_digest"] == plan["grant_digest"]
    )
    for key in (
        "runtime_profile_digest",
        "runtime_digest",
        "active_skill_digest",
        "sensor_digest",
        "policy_digest",
        "operation_digest",
    ):
        _require(grant[key] == lease[key] == plan[key])
    _require(
        all(lease[key] == request[key] for key in _MATCH)
        and _uint(lease["policy_version"], 1)
        == request["policy_version"]
        == grant["policy_version"]
        and grant["issued_at_unix"]
        <= request["issued_at_unix"]
        <= _uint(lease["issued_at_unix"])
        <= claimed
        < _uint(lease["expires_at_unix"])
        == request["expires_at_unix"]
        <= grant["expires_at_unix"]
        and 0 < lease["expires_at_unix"] - lease["issued_at_unix"] <= 5
        and 0 < request["expires_at_unix"] - request["issued_at_unix"] <= 5
    )
    return request


def _transport(value, result, request):
    """Recompute transport roles; never accept a producer validation Boolean."""
    _exact(
        value,
        {
            "schema",
            "authority",
            "attempt_id",
            "fixture_binding_digest",
            "effect_digest",
            "action_digests",
            "connect_attempted",
            "sent_bytes",
            "response_bytes",
            "response_digest",
            "status",
            "error_code",
            "identity",
            *canary.FALSE_FLAGS,
        },
    )
    identity = _exact(value["identity"], {"fixture", *_EPOCH})
    for key in _EPOCH:
        _uint(identity[key], 1)
    binding = fixture_binding(
        {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": identity["fixture"],
            "expected_broker_uid": identity["uid"],
            "expected_broker_gid": identity["gid"],
        }
    )
    digests = action_digests(result["attempt_id"], binding)
    _require(
        value["schema"] == "aragorn/runtime-http-action-result/v1"
        and value["authority"]
        == "CREDENTIAL_BOUND_LAB_HTTP_TRANSPORT_ONLY_NOT_POLICY_AUTHORITY"
        and value["attempt_id"] == result["attempt_id"]
        and value["effect_digest"] == result["effect_digest"]
        and value["fixture_binding_digest"] == canonical_digest(binding)
        and value["action_digests"] == digests
        and all(request[key] == digests[key] for key in digests)
        and all(value[key] is False for key in canary.FALSE_FLAGS)
    )
    if result["verdict"] == "ALLOW":
        _require(
            value["status"] == "SENT"
            and value["connect_attempted"] is True
            and _uint(value["sent_bytes"])
            == len(canary.canary_request(result["attempt_id"]))
            and _uint(value["response_bytes"]) == len(canary.RESPONSE_BYTES)
            and value["response_digest"] == canary.digest(canary.RESPONSE_BYTES)
            and value["error_code"] is None
        )
    else:
        _require(
            value["status"] == "NOT_PERFORMED"
            and value["connect_attempted"] is False
            and type(value["sent_bytes"]) is int
            and value["sent_bytes"] == 0
            and type(value["response_bytes"]) is int
            and value["response_bytes"] == 0
            and value["response_digest"] == canary.digest(b"")
            and value["error_code"] == "HTTP_AUTHORIZATION_REFUSED"
        )
    return value


def result_record(claim, receipt, result, request):
    """Reconstruct the consumed result from exact HTTP receipt bytes."""
    from . import runtime_broker_effective_receipt_verify as effective

    profile = claim["profile_claim"]
    _exact(
        receipt,
        {
            "schema",
            "authority",
            "submission_digest",
            "runtime_attribution",
            "runtime_attribution_digest",
            "broker_result",
            "broker_result_digest",
        },
    )
    _exact(
        result,
        {
            "schema",
            "authority",
            "request_digest",
            "effect_digest",
            "attempt_id",
            "observation_digest",
            "verdict",
            "reason_codes",
            "effect_status",
            "decision",
            "payload_decision",
            "transport",
            "run_conformance_eligible",
            "phase3_eligible",
            "production_activation_eligible",
        },
    )
    _pin(result["observation_digest"])
    _require(
        receipt["schema"] == "aragorn/runtime-process-profile-receipt/v1"
        and receipt["authority"]
        == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and receipt["submission_digest"] == profile["submission_digest"]
        and receipt["runtime_attribution_digest"]
        == profile["runtime_attribution_digest"]
        and receipt["runtime_attribution"]
        == profile["profile_pending"]["runtime_attribution"]
        and canonical_digest(receipt["runtime_attribution"])
        == receipt["runtime_attribution_digest"]
        and receipt["broker_result"] == result
        and receipt["broker_result_digest"] == canonical_digest(result)
        and result["schema"] == "aragorn/runtime-http-broker-result/v1"
        and result["authority"]
        == "BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION"
        and result["request_digest"]
        == profile["request_digest"]
        == canonical_digest(request)
        and result["effect_digest"]
        == profile["effect_digest"]
        == canonical_digest(effect_for_attempt(result["attempt_id"]))
        and result["attempt_id"] == profile["attempt_id"]
        and (result["verdict"], result["effect_status"])
        in (("ALLOW", "SENT"), ("BLOCK", "NOT_PERFORMED"))
        and all(
            result[key] is False
            for key in (
                "run_conformance_eligible",
                "phase3_eligible",
                "production_activation_eligible",
            )
        )
    )
    reasons = effective._reasons(result["reason_codes"])
    decision = effective._policy(result["decision"], request)
    payload_decision = effective._policy(result["payload_decision"], request)
    if result["verdict"] == "ALLOW":
        _require(
            decision is not None
            and decision["verdict"] == "ALLOW"
            and reasons == []
            and payload_decision is not None
            and payload_decision["verdict"] == "ALLOW"
            and payload_decision["evaluated_at_unix"] >= decision["evaluated_at_unix"]
            and result["transport"] is not None
        )
    else:
        _require(payload_decision is None and bool(reasons))
        valid = (
            reasons == ["BROKER_REPLAY_BLOCKED"]
            if decision is None
            else (
                decision["verdict"] == "BLOCK"
                and reasons == decision["reason_codes"]
                or set(reasons) <= effective._MISMATCH_REASONS
                or len(reasons) == 1
                and reasons[0] in effective._SINGLE_REASONS
            )
        )
        _require(valid)
    if result["transport"] is not None:
        _transport(result["transport"], result, request)
    return {
        "schema": "aragorn/runtime-capability-grant-result/v1",
        "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": claim["grant_digest"],
        "lease_digest": claim["lease_digest"],
        "profile_result": {
            "schema": "aragorn/runtime-http-capability-lease-result/v1",
            "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "lease_digest": profile["lease_digest"],
            "submission_digest": profile["submission_digest"],
            "profile_receipt_digest": canonical_digest(receipt),
            "broker_result_digest": canonical_digest(result),
            "verdict": result["verdict"],
            "effect_status": result["effect_status"],
        },
    }


def verify_http_worker_ingress(
    raws,
    *,
    expected_record_digests,
    expected_worker,
    expected_binding_digest,
    expected_genesis_digest,
    expected_fixture_binding,
    expected_attempt_id,
):
    """Parse all four records and bind the native params to the fixed HTTP effect."""
    from .runtime_action_decision import _request as validate_runtime_action_request

    _exact(raws, ingress.STAGES)
    _exact(expected_record_digests, ingress.STAGES)
    _exact(expected_worker, _EPOCH)
    records, previous = {}, None
    for stage in ingress.STAGES:
        record = ingress._parse(raws[stage], expected_record_digests[stage])
        ingress._record(
            record, stage, previous, expected_worker, _pin(expected_binding_digest)
        )
        records[stage], previous = record, expected_record_digests[stage]
    first = records["startup"]
    _exact(first["body"], set())
    for value in records.values():
        _require(
            all(
                value[key] == first[key]
                for key in ("worker_identity", "worker_binding", "time_namespace")
            )
        )
    stamps = [records[stage]["boottime_ns"] for stage in ingress.STAGES]
    _require(all(left < right for left, right in zip(stamps, stamps[1:])))
    body = _exact(
        records["ingress"]["body"],
        {"worker_request", "worker_request_digest", "gateway_peer"},
    )
    peer = _exact(body["gateway_peer"], {"pid", "uid", "gid"})
    for value in peer.values():
        _uint(value, 1)
    request = _exact(
        body["worker_request"],
        {
            "schema",
            "authority",
            "attempt_id",
            "session_id",
            "run_id",
            "tool_call_digest",
        },
    )
    _require(
        request["schema"] == "aragorn/runtime-http-worker-request/v1"
        and request["authority"] == "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
        and request["attempt_id"] == expected_attempt_id
        and all(ingress._identifier(request[key]) for key in ("session_id", "run_id"))
    )
    _pin(request["tool_call_digest"])
    request_pin = canonical_digest(request)
    _require(body["worker_request_digest"] == request_pin)
    body = _exact(
        records["attempt"]["body"],
        {
            "attempt",
            "attempt_digest",
            "receipt_state",
            "receipt_state_digest",
            "genesis_digest",
            "worker_request_digest",
        },
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
    )
    state = _exact(
        body["receipt_state"], {"schema", "authority", "genesis_digest", "receipts"}
    )
    genesis = _pin(expected_genesis_digest)
    receipt_pin, state_pin = canonical_digest(receipt), canonical_digest(state)
    _require(
        body["genesis_digest"]
        == receipt["genesis_digest"]
        == state["genesis_digest"]
        == genesis
        and body["worker_request_digest"] == request_pin
        and body["attempt_digest"] == receipt_pin
        and body["receipt_state_digest"] == state_pin
        and receipt["schema"] == "aragorn/native-tool-receipt/v1"
        and state["schema"] == "aragorn/native-tool-receipt-state/v1"
        and receipt["authority"] == state["authority"] == ingress._RECEIPT_AUTHORITY
    )
    rows = state["receipts"]
    _require(type(rows) is list and 1 <= len(rows) <= 1024 and len(rows) % 2 == 1)
    for pin in rows:
        _pin(pin)
    _require(
        len(set(rows)) == len(rows)
        and rows[-1] == receipt_pin
        and _uint(receipt["sequence"], 1) == len(rows)
        and receipt["previous_digest"] == (genesis if len(rows) == 1 else rows[-2])
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
    )
    _pin(event["session_key_digest"])
    params = {
        "attempt_id": expected_attempt_id,
        "__aragorn_run_id": request["run_id"],
        "__aragorn_session_id": request["session_id"],
        "__aragorn_session_key_digest": event["session_key_digest"],
        "__aragorn_tool_call_digest": request["tool_call_digest"],
    }
    # JS JSON.stringify preserves insertion order; this is the actual native
    # parameter object construction, not canonical_json's sorted-key encoding.
    params_raw = json.dumps(params, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    _require(
        event["schema"] == "aragorn/native-tool-attempt/v1"
        and event["authority"] == ingress._EVENT_AUTHORITY
        and event["tool_name"] == TOOL
        and event["worker_request_digest"] == request_pin
        and all(
            event[key] == request[key]
            for key in ("session_id", "run_id", "tool_call_digest")
        )
        and event["params_digest"] == canary.digest(params_raw)
        and _uint(event["params_bytes"]) == len(params_raw)
    )
    body = _exact(
        records["action"]["body"],
        {
            "action_request",
            "action_request_digest",
            "worker_request_digest",
            "attempt_digest",
        },
    )
    action = body["action_request"]
    validate_runtime_action_request(action)
    digests = action_digests(expected_attempt_id, expected_fixture_binding)
    _require(
        body["action_request_digest"] == canonical_digest(action)
        and body["worker_request_digest"] == request_pin
        and body["attempt_digest"] == receipt_pin
        and all(
            action[key] == first["worker_binding"][key]
            for key in (
                "runtime_digest",
                "active_skill_digest",
                "policy_digest",
                "policy_version",
            )
        )
        and all(action[key] == request[key] for key in ("session_id", "run_id"))
        and action["tool_call_id"] == request["tool_call_digest"]
        and all(action[key] == digests[key] for key in digests)
        and action["expires_at_unix"] - action["issued_at_unix"] == 5
    )
    return {
        "record_digests": dict(expected_record_digests),
        "worker_request": request,
        "action_request": action,
        "attempt_digest": receipt_pin,
        "receipt_state_digest": state_pin,
        "stage_boottime_ns": dict(zip(ingress.STAGES, stamps)),
        "time_namespace": first["time_namespace"],
        "native_params_digest": canary.digest(params_raw),
        "gateway_peer": peer,
    }


def verify_native_http_collection(
    *,
    completion_raw,
    expected_completion_digest,
    expected_binding_raw,
    expected_binding_digest,
    expected_broker,
    input_cas,
    evidence_cas,
    ingress_raws,
    expected_ingress_digests,
    expected_worker,
    expected_worker_binding_digest,
    expected_genesis_digest,
    fixture_binding_raw,
    expected_fixture_binding_digest,
    clock_before_raw,
    clock_after_raw,
    expected_clock_before_digest,
    expected_clock_after_digest,
    sink_raw,
    expected_sink_digest,
    expected_sink_identity,
    expected_readiness_nonce,
    driver_raw,
    expected_driver_record_digest,
    terminal_raw,
    expected_terminal_digest,
):
    """Join real worker ingress/final-decision stamps and independent sink bytes.

    Requires the finite rendered broker-verifier successor, never its create
    predecessor.  Returns a bounded native interval; generic collector marks,
    hostile-root custody, semantic applicability and qualification stay false.
    """
    from . import runtime_broker_effective_receipt_verify as effective
    from .native_phase3_clock_domain_verify import verify_native_common_clock_domain

    binding = fixture_binding(
        _raw(fixture_binding_raw, expected_fixture_binding_digest, 4096)
    )
    plan = _raw(expected_binding_raw, expected_binding_digest, 8192)
    _require(
        plan["boot_id"] == binding["fixture"]["boot_id"]
        and binding["expected_broker_uid"] == expected_broker["uid"]
        and binding["expected_broker_gid"] == expected_broker["gid"]
    )
    chain = verify_http_worker_ingress(
        ingress_raws,
        expected_record_digests=expected_ingress_digests,
        expected_worker=expected_worker,
        expected_binding_digest=expected_worker_binding_digest,
        expected_genesis_digest=expected_genesis_digest,
        expected_fixture_binding=binding,
        expected_attempt_id=plan["attempt_id"],
    )
    broker = effective.verify_broker_effective_receipt(
        completion_raw=completion_raw,
        expected_completion_digest=expected_completion_digest,
        expected_binding_raw=expected_binding_raw,
        expected_binding_digest=expected_binding_digest,
        expected_process_identity=expected_broker,
        input_cas=input_cas,
        evidence_cas=evidence_cas,
    )
    _require(
        broker["action_request_digest"] == canonical_digest(chain["action_request"])
        and broker["scheduled_request"]["attempt_id"] == plan["attempt_id"]
        and broker["scheduled_request"]["family"] == "EXFILTRATION"
        and broker["scheduled_request"]["negative_control"] is False
    )
    clock = verify_native_common_clock_domain(
        clock_before_raw,
        clock_after_raw,
        expected_before_digest=expected_clock_before_digest,
        expected_after_digest=expected_clock_after_digest,
        expected_worker=expected_worker,
        expected_broker={key: expected_broker[key] for key in _EPOCH},
    )
    _require(
        clock["clock_domain"]["boot_id"] == plan["boot_id"]
        and clock["clock_domain"]["time_namespace"] == chain["time_namespace"]
    )
    start = chain["stage_boottime_ns"]["ingress"]
    accepted, final = (
        broker["broker_interval"][key]
        for key in ("accepted_boottime_ns", "finalized_boottime_ns")
    )
    _require(
        clock["read_brackets"]["before"]["finished_boottime_ns"]
        <= start
        < chain["stage_boottime_ns"]["action"]
        <= accepted
        < final
        <= clock["read_brackets"]["after"]["started_boottime_ns"]
    )
    sink = canary.verify_http_sink(
        sink_raw,
        expected_raw_digest=expected_sink_digest,
        expected_identity=expected_sink_identity,
        expected_attempt_id=plan["attempt_id"],
        expected_readiness_nonce=expected_readiness_nonce,
    )
    raw_sink = _raw(sink_raw, expected_sink_digest, 64 * 1024)
    _require(
        expected_sink_identity["fixture"] == binding["fixture"]
        and expected_sink_identity["process"]["pid"]
        not in (expected_worker["pid"], expected_broker["pid"])
        and raw_sink["interval"]["started_ns"]
        <= start
        < final
        <= raw_sink["interval"]["finished_ns"]
    )
    completion = _raw(completion_raw, expected_completion_digest, 4096)
    evidence = _raw(
        evidence_cas.read(completion["evidence_digest"], max_bytes=192 * 1024),
        completion["evidence_digest"],
    )
    result_pin = evidence["broker_result_digest"]
    result = _raw(evidence_cas.read(result_pin, max_bytes=192 * 1024), result_pin)
    driver = verify_native_http_driver(
        driver_raw,
        expected_digest=expected_driver_record_digest,
        chain=chain,
        broker_result=result,
        scheduled_request=broker["scheduled_request"],
        fixture=binding["fixture"],
        readiness_nonce=expected_readiness_nonce,
        terminal_raw=terminal_raw,
        expected_terminal_digest=expected_terminal_digest,
        attempt_raw=ingress_raws["attempt"],
        expected_attempt_record_digest=expected_ingress_digests["attempt"],
    )
    if result["transport"] is not None:
        transport = result["transport"]
        _require(
            transport["fixture_binding_digest"] == expected_fixture_binding_digest
            and transport["identity"]
            == {
                "fixture": binding["fixture"],
                **{key: expected_broker[key] for key in _EPOCH},
            }
        )
    # A BLOCK + empty bounded interval is still not independent denial causality.
    # An ALLOW/SENT receipt requires the exact request in the separate sink.
    if result["verdict"] == "ALLOW":
        _require(
            any(
                bytes.fromhex(row["raw_hex"])
                == canary.canary_request(plan["attempt_id"])
                for row in raw_sink["connections"]
            ),
            "HTTP_SENT_WITHOUT_EXACT_SINK_REQUEST",
        )
    return {
        "schema": "aragorn/native-http-collection-verification/v1",
        "authority": "RETAINED_NATIVE_HTTP_JOINS_ONLY_NOT_CAUSATION_OR_PHASE3",
        "status": "BOUNDED_NATIVE_HTTP_COLLECTION_VERIFIED",
        "attempt_id": plan["attempt_id"],
        "deployment_digest": plan["deployment_identity_digest"],
        "binding_digest": expected_binding_digest,
        "completion_digest": expected_completion_digest,
        "fixture_binding_digest": expected_fixture_binding_digest,
        "ingress": chain,
        "broker": broker,
        "clock_domain": clock,
        "sink": sink,
        "native_driver": driver,
        "native_interval": {
            "clock_id": "CLOCK_BOOTTIME",
            "start_boundary": "AUTHENTICATED_WORKER_REQUEST_INGRESS",
            "end_boundary": "SHARED_CORE_EFFECTIVE_FINAL_VERDICT",
            "started_boottime_ns": start,
            "finished_boottime_ns": final,
            "elapsed_ns": final - start,
        },
        "limitations": [
            "GENERIC_COLLECTOR_MARK_BOUNDARIES_NOT_IMPLEMENTED_BY_RETAINED_NATIVE_STAMPS",
            "OPERATOR_PINS_NOT_HOSTILE_ROOT_OR_CONTINUOUS_SOURCE_CUSTODY",
            "RETAINED_NATIVE_ASSOCIATION_NOT_SEMANTIC_APPLICABILITY_OR_CAUSATION",
            "ROOT_NODE_LISTENER_READINESS_NOT_BROKER_RESTRICTED_NETWORK_READINESS",
            "BOUNDED_SINK_INTERVAL_NOT_GLOBAL_ABSENCE_OR_ACCEPTANCE",
        ],
        **dict.fromkeys(FALSE_FLAGS, False),
    }


def verify_native_http_driver(
    raw,
    *,
    expected_digest,
    chain,
    broker_result,
    scheduled_request,
    fixture,
    readiness_nonce,
    terminal_raw,
    expected_terminal_digest,
    attempt_raw,
    expected_attempt_record_digest,
):
    """Join retained native callback bytes, worker response and terminal receipt."""
    value = _exact(
        _raw(raw, expected_digest),
        {
            "schema",
            "authority",
            "status",
            "tool_name",
            "prepared_request",
            "fixture",
            "readiness_nonce",
            "gateway_pid",
            "correlation",
            "worker_request",
            "source_result",
            "native_callback",
            "transcript",
            "provider",
            "raw_callback_projection_is_source_derived",
            "native_ack_wire_capture",
            "phase3_eligible",
            "run_conformance_eligible",
        },
    )
    _require(
        value["schema"] == "aragorn/native-http-tool-driver/v1"
        and value["authority"] == "NATIVE_HTTP_RELAY_ONLY_NOT_CAUSATION_OR_TIMING"
        and value["status"] == "OBSERVED"
        and value["tool_name"] == TOOL
        and value["prepared_request"] == scheduled_request
        and value["fixture"] == fixture
        and value["readiness_nonce"] == readiness_nonce
        and _uint(value["gateway_pid"], 1) == chain["gateway_peer"]["pid"]
        and value["raw_callback_projection_is_source_derived"] is True
        and all(
            value[key] is False
            for key in (
                "native_ack_wire_capture",
                "phase3_eligible",
                "run_conformance_eligible",
            )
        )
    )
    worker_result = {
        "schema": "aragorn/runtime-action-worker-result/v1",
        "authority": "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(chain["worker_request"]),
        "status": "COMPLETED",
        "broker_result": broker_result,
    }
    for name, expected in (
        ("worker_request", chain["worker_request"]),
        ("source_result", worker_result),
    ):
        recorded = _exact(value[name], {"document", "bytes", "digest"})
        _require(
            recorded["document"] == expected
            and recorded["digest"] == canonical_digest(expected)
            and _uint(recorded["bytes"], 1) == len(canonical_json(expected))
        )
    correlation = _exact(
        value["correlation"],
        {"session_id", "run_id", "session_key_digest", "tool_call_digest"},
    )
    attempt = _raw(attempt_raw, expected_attempt_record_digest)["body"]["attempt"]
    _require(all(correlation[key] == attempt["event"][key] for key in correlation))
    callback = _exact(value["native_callback"], {"params_json", "result_json"})
    for text in callback.values():
        _require(type(text) is str and 0 < len(text.encode("utf-8")) <= 131072)
    params_raw, result_raw = (
        callback[key].encode("utf-8") for key in ("params_json", "result_json")
    )
    params = json.loads(params_raw)
    _require(
        canary.digest(params_raw) == chain["native_params_digest"]
        and params["attempt_id"] == scheduled_request["attempt_id"]
    )
    result = _exact(json.loads(result_raw), {"content", "details"})
    expected_text = {
        "schema": "aragorn/runtime-action-worker-tool-result-text/v1",
        "message": "Aragorn "
        + broker_result["verdict"]
        + ": "
        + broker_result["effect_status"],
        "result": worker_result,
    }
    _require(
        result["content"]
        == [{"type": "text", "text": canonical_json(expected_text).decode("ascii")}]
        and result["details"]
        == {
            "schema": "aragorn/runtime-action-worker-openclaw-details/v1",
            "status": "completed" if broker_result["verdict"] == "ALLOW" else "blocked",
            "source_result": worker_result,
        }
    )
    terminal = _exact(
        _raw(terminal_raw, expected_terminal_digest, 4096),
        {
            "schema",
            "authority",
            "genesis_digest",
            "sequence",
            "previous_digest",
            "event",
        },
    )
    _require(
        terminal["schema"] == "aragorn/native-tool-receipt/v1"
        and terminal["authority"] == ingress._RECEIPT_AUTHORITY
        and terminal["genesis_digest"] == attempt["genesis_digest"]
        and _uint(terminal["sequence"], 2) == attempt["sequence"] + 1
        and terminal["previous_digest"] == chain["attempt_digest"]
        and terminal["event"]
        == {
            "schema": "aragorn/native-tool-terminal/v1",
            "authority": ingress._EVENT_AUTHORITY,
            "tool_name": TOOL,
            **correlation,
            "attempt_digest": chain["attempt_digest"],
            "outcome": "RETURNED",
            "result_digest": canary.digest(result_raw),
            "result_bytes": len(result_raw),
            "error_code": None,
        }
    )
    transcript = _exact(value["transcript"], {"bytes", "digest"})
    _pin(transcript["digest"])
    _require(_uint(transcript["bytes"], 1) <= 16 * 1024 * 1024)
    provider = _exact(value["provider"], {"request_count", "records"})
    _require(
        type(provider["request_count"]) is int
        and provider["request_count"] == 2
        and type(provider["records"]) is list
        and len(provider["records"]) == 2
    )
    for offset, record in enumerate(provider["records"]):
        _exact(
            record,
            {"sequence", "request_bytes", "tool_contract_digest", "result_text_digest"},
        )
        _require(
            _uint(record["sequence"], 1) == offset + 1
            and _uint(record["request_bytes"], 1) <= 4 * 1024 * 1024
        )
        _pin(record["tool_contract_digest"])
        _require(
            record["result_text_digest"]
            == (None if offset == 0 else canary.digest(canonical_json(expected_text)))
        )
    _require(
        provider["records"][0]["tool_contract_digest"]
        == provider["records"][1]["tool_contract_digest"]
    )
    return {
        "driver_record_digest": expected_digest,
        "terminal_digest": expected_terminal_digest,
        "callback_result_digest": canary.digest(result_raw),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
