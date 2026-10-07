"""Finite HTTP receipt contracts for the pinned common-runtime successor.

The root grant, measured process attribution and one-shot state machine remain
the existing implementations. These pure helpers only describe their HTTP
variant; they neither issue authority nor perform or retry a network effect.
"""

from __future__ import annotations

import re

from . import native_phase3_http_canary_contract as canary
from . import runtime_action_broker as broker
from . import runtime_http_action as http
from . import runtime_http_broker as mediation
from .oci_worker_protocol import canonical_digest, canonical_json

PROFILED_SCHEMA = "aragorn/runtime-observed-http-submission/v2"
CLAIM_SCHEMA = "aragorn/runtime-http-capability-lease-claim/v1"
LEASE_RESULT_SCHEMA = "aragorn/runtime-http-capability-lease-result/v1"
_CLAIM_AUTHORITY = "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
_RESULT_AUTHORITY = "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
_CLAIM_FIELDS = {
    "schema",
    "authority",
    "lease_digest",
    "claimed_at_unix",
    "submission_digest",
    "runtime_attribution_digest",
    "envelope_digest",
    "request_digest",
    "measured_action_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "attempt_id",
    "effect_digest",
    "profile_pending",
}
_RESULT_FIELDS = {
    "schema",
    "authority",
    "lease_digest",
    "submission_digest",
    "profile_receipt_digest",
    "broker_result_digest",
    "verdict",
    "effect_status",
}
_PAIRS = {("ALLOW", "SENT"), ("BLOCK", "NOT_PERFORMED")}


def _require(condition, reason="HTTP capability receipt is unbound"):
    if not condition:
        raise broker.RuntimeActionBrokerError(reason)


def is_http_profiled(value):
    return type(value) is dict and value.get("schema") == PROFILED_SCHEMA


def is_http_claim(value):
    return type(value) is dict and value.get("schema") == CLAIM_SCHEMA


def observed_from_profile(value):
    """Remove only the separately validated profile; preserve real HTTP types."""
    _require(is_http_profiled(value))
    observed = {**value, "schema": mediation.SUBMISSION_SCHEMA}
    observed.pop("runtime_attribution", None)
    return mediation.observed_submission(observed)


def build_grant_claim(grant, lease, observed, attribution, submission_digest, now):
    observed = mediation.observed_submission(observed)
    request, effect = mediation.request_effect(observed["envelope"])
    measured = observed["measured_action"]
    pending = {
        "schema": "aragorn/runtime-process-profile-pending/v1",
        "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
        "submission_digest": submission_digest,
        "envelope_digest": observed["envelope_digest"],
        "request_digest": observed["request_digest"],
        "measured_action": measured,
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
    }
    profile_claim = {
        "schema": CLAIM_SCHEMA,
        "authority": _CLAIM_AUTHORITY,
        "lease_digest": canonical_digest(lease),
        "claimed_at_unix": now,
        "submission_digest": submission_digest,
        "runtime_attribution_digest": canonical_digest(attribution),
        "envelope_digest": observed["envelope_digest"],
        "request_digest": observed["request_digest"],
        "measured_action_digest": canonical_digest(measured),
        **{key: request[key] for key in ("session_id", "run_id", "tool_call_id")},
        "attempt_id": effect["attempt_id"],
        "effect_digest": canonical_digest(effect),
        "profile_pending": pending,
    }
    validate_claim(profile_claim, canonical_digest(lease))
    # Detach all caller-owned nested objects before the durable claim is written.
    return broker._parse_canonical_document(
        canonical_json(
            {
                "schema": "aragorn/runtime-capability-grant-claim/v1",
                "authority": "BROKER_GRANT_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "grant_digest": canonical_digest(grant),
                "lease_digest": canonical_digest(lease),
                "lease": lease,
                "profile_claim": profile_claim,
            }
        ),
        "HTTP grant claim",
    )


def validate_claim(value, expected_lease_digest):
    from . import runtime_action_broker_v3 as profile

    value = broker._exact(value, _CLAIM_FIELDS, "HTTP capability claim")
    _require(
        value["schema"] == CLAIM_SCHEMA
        and value["authority"] == _CLAIM_AUTHORITY
        and value["lease_digest"] == expected_lease_digest
    )
    for field in (
        "lease_digest",
        "submission_digest",
        "runtime_attribution_digest",
        "envelope_digest",
        "request_digest",
        "measured_action_digest",
        "effect_digest",
    ):
        broker._require_digest(value[field], "HTTP claim " + field)
    broker._uint(value["claimed_at_unix"], "HTTP claim time")
    for field in ("session_id", "run_id", "tool_call_id"):
        _require(type(value[field]) is str and bool(value[field]))
    try:
        effect = http.effect_for_attempt(value["attempt_id"])
    except (ValueError, TypeError, KeyError) as error:
        raise broker.RuntimeActionBrokerError(
            "HTTP claim attempt is invalid"
        ) from error
    _require(value["effect_digest"] == canonical_digest(effect))
    pending = broker._exact(
        value["profile_pending"],
        profile._PROFILE_PENDING_FIELDS,
        "HTTP profile pending",
    )
    measured = broker._exact(
        pending["measured_action"],
        broker._MEASURED_ACTION_FIELDS,
        "HTTP measured action",
    )
    _require(
        pending["schema"] == "aragorn/runtime-process-profile-pending/v1"
        and pending["authority"] == "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY"
        and all(
            pending[field] == value[field]
            for field in (
                "submission_digest",
                "envelope_digest",
                "request_digest",
                "runtime_attribution_digest",
            )
        )
        and measured["schema"] == "aragorn/measured-runtime-action/v1"
        and canonical_digest(measured) == value["measured_action_digest"]
        and canonical_digest(pending["runtime_attribution"])
        == value["runtime_attribution_digest"]
        and all(
            measured[field] == value[field]
            for field in ("session_id", "run_id", "tool_call_id")
        )
        and measured["operation_digest"]
        == canonical_digest(http.operation_descriptor())
        and measured["payload_digest"]
        == canary.digest(canary.canary_request(value["attempt_id"]))
    )
    return value


def _recorded_decision(decision, result, request_digest):
    reasons = result["reason_codes"]
    if type(reasons) is not list or any(type(code) is not str for code in reasons):
        return False
    if decision is None:
        return (
            result["verdict"] == "BLOCK"
            and result["effect_status"] == "NOT_PERFORMED"
            and reasons == ["BROKER_REPLAY_BLOCKED"]
        )
    if (
        type(decision) is not dict
        or decision.get("schema") != "aragorn/runtime-action-decision/v1"
        or decision.get("authority")
        != "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        or decision.get("request_digest") != request_digest
        or type(decision.get("reason_codes")) is not list
        or any(
            type(code) is not str
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is None
            or code.startswith("BROKER_")
            for code in decision["reason_codes"]
        )
        or decision["reason_codes"] != sorted(set(decision["reason_codes"]))
        or decision.get("verdict") not in {"ALLOW", "BLOCK"}
        or (decision["verdict"] == "ALLOW") != (decision["reason_codes"] == [])
        or reasons == ["BROKER_REPLAY_BLOCKED"]
    ):
        return False
    if result["verdict"] == "ALLOW":
        return decision["verdict"] == "ALLOW" and reasons == []
    if result["verdict"] != "BLOCK" or not reasons:
        return False
    if decision["verdict"] == "BLOCK" and reasons == decision["reason_codes"]:
        return True
    snapshots = {
        "BROKER_RUNTIME_PIN_MISMATCH",
        "BROKER_SENSOR_PIN_MISMATCH",
        "BROKER_EFFECT_MEASUREMENT_MISMATCH",
        "BROKER_EFFECT_BINDING_MISMATCH",
    }
    final = {
        "BROKER_CLOCK_ROLLBACK",
        "BROKER_CLOCK_UNSTABLE",
        "BROKER_CLAIM_STATE_CHANGED",
        "BROKER_DEADLINE_EXPIRED",
    }
    return (reasons == sorted(set(reasons)) and set(reasons) <= snapshots) or (
        len(reasons) == 1 and reasons[0] in final
    )


def validate_broker_result(value, claim):
    """Validate HTTP policy/transport roles, not independent sink observation."""
    validate_claim(claim, claim["lease_digest"])
    fields = {
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
    }
    result = broker._exact(value, fields, "HTTP broker result")
    broker._require_digest(result["observation_digest"], "HTTP observation digest")
    _require(
        result["schema"] == mediation.RESULT_SCHEMA
        and result["authority"] == mediation.RESULT_AUTHORITY
        and all(
            result[key] == claim[key]
            for key in ("request_digest", "effect_digest", "attempt_id")
        )
        and (result["verdict"], result["effect_status"]) in _PAIRS
        and _recorded_decision(result["decision"], result, claim["request_digest"])
        and all(
            result[key] is False
            for key in (
                "run_conformance_eligible",
                "phase3_eligible",
                "production_activation_eligible",
            )
        )
    )
    transport = result["transport"]
    if result["verdict"] == "BLOCK":
        _require(result["payload_decision"] is None)
        if transport is None:
            return result
    else:
        _require(
            _recorded_decision(
                result["payload_decision"], result, claim["request_digest"]
            )
        )
    _require(type(transport) is dict and type(transport.get("identity")) is dict)
    identity = transport["identity"]
    try:
        binding = http.validate_fixture_binding(
            {
                "schema": http.BINDING_SCHEMA,
                "fixture": identity["fixture"],
                "expected_broker_uid": identity["uid"],
                "expected_broker_gid": identity["gid"],
            }
        )
        transport = http.validate_result(
            transport,
            effect=http.effect_for_attempt(claim["attempt_id"]),
            fixture_binding=binding,
        )
    except (ValueError, TypeError, KeyError) as error:
        raise broker.RuntimeActionBrokerError(
            "HTTP transport receipt refused"
        ) from error
    _require(
        transport["status"] == result["effect_status"]
        and all(
            transport["action_digests"][key]
            == claim["profile_pending"]["measured_action"][key]
            for key in ("operation_digest", "path_digest", "payload_digest")
        )
    )
    return result


def profile_result_record(claim, receipt):
    from . import runtime_action_broker_v3 as profile

    validate_claim(claim, claim["lease_digest"])
    document = broker._exact(
        receipt, profile._PROFILE_RECEIPT_FIELDS, "HTTP profile receipt"
    )
    _require(
        document["schema"] == "aragorn/runtime-process-profile-receipt/v1"
        and document["authority"]
        == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and document["submission_digest"] == claim["submission_digest"]
        and document["runtime_attribution_digest"]
        == claim["runtime_attribution_digest"]
        and document["runtime_attribution"]
        == claim["profile_pending"]["runtime_attribution"]
    )
    result = validate_broker_result(document["broker_result"], claim)
    _require(document["broker_result_digest"] == canonical_digest(result))
    return {
        "schema": LEASE_RESULT_SCHEMA,
        "authority": _RESULT_AUTHORITY,
        "lease_digest": claim["lease_digest"],
        "submission_digest": claim["submission_digest"],
        "profile_receipt_digest": canonical_digest(document),
        "broker_result_digest": canonical_digest(result),
        "verdict": result["verdict"],
        "effect_status": result["effect_status"],
    }


def validate_lease_result(value, claim):
    validate_claim(claim, claim["lease_digest"])
    value = broker._exact(value, _RESULT_FIELDS, "HTTP capability result")
    _require(
        value["schema"] == LEASE_RESULT_SCHEMA
        and value["authority"] == _RESULT_AUTHORITY
        and value["lease_digest"] == claim["lease_digest"]
        and value["submission_digest"] == claim["submission_digest"]
        and (value["verdict"], value["effect_status"]) in _PAIRS
    )
    for key in (
        "lease_digest",
        "submission_digest",
        "profile_receipt_digest",
        "broker_result_digest",
    ):
        broker._require_digest(value[key], "HTTP capability result " + key)
    return value
