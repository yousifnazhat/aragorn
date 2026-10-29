"""Read-only successor joins for recorded policy and effective broker outcomes.

This verifier never imports the renderer or executes evidence-named code. Source
pins and broker identity remain operator custody claims, not attestation. A
recorded broker-only BLOCK reason is not independently established causality.
"""

from __future__ import annotations

import re
from typing import Any

from . import runtime_action_broker_v4 as v4
from . import runtime_broker_decision_measurement_verify as prior
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json

_LIMIT = prior._LIMIT
_RETAINED_LIMITS = [
    "EXCLUDES_V5_LINEAGE_TRANSPORT_AND_ISSUANCE_VALIDATION",
    "NOT_SINK_RESIDUE_OR_INDEPENDENT_CAUSAL_ATTRIBUTION_PROOF",
    "NOT_TASK_BASELINE_OR_OVERHEAD_MEASUREMENT",
    "RECORDED_EFFECTIVE_BLOCK_DOES_NOT_PROVE_BROKER_REASON_OR_POLICY_CAUSALITY",
    "ROOT_OPERATOR_AND_BROKER_CUSTODY_NOT_EXTERNAL_ATTESTATION",
]
_MISMATCH_REASONS = {
    "BROKER_RUNTIME_PIN_MISMATCH",
    "BROKER_SENSOR_PIN_MISMATCH",
    "BROKER_EFFECT_MEASUREMENT_MISMATCH",
    "BROKER_EFFECT_BINDING_MISMATCH",
}
_SINGLE_REASONS = {
    "BROKER_CLOCK_ROLLBACK",
    "BROKER_CLOCK_UNSTABLE",
    "BROKER_CLAIM_STATE_CHANGED",
    "BROKER_DEADLINE_EXPIRED",
}


class BrokerEffectiveReceiptVerificationError(ValueError):
    """Retained bytes do not support the successor's bounded receipt statement."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BrokerEffectiveReceiptVerificationError(message)


def _reasons(value: object) -> list[str]:
    _require(
        type(value) is list
        and all(
            type(code) is str
            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is not None
            for code in value
        )
        and value == sorted(set(value)),
        "invalid or noncanonical reason vector",
    )
    return value


def _policy(value: object, request: dict) -> dict | None:
    if value is None:
        return None
    decision = prior._exact(
        value,
        {
            "schema",
            "authority",
            "request_digest",
            "active_context_digest",
            "measured_action_digest",
            "policy_digest",
            "policy_version",
            "evaluated_at_unix",
            "revocation_snapshot_digest",
            "revocation_generation",
            "minimum_revocation_generation",
            "mediator_health_digest",
            "mediator_health_epoch",
            "minimum_mediator_health_epoch",
            "verdict",
            "reason_codes",
        },
    )
    reasons = _reasons(decision["reason_codes"])
    _require(
        decision["schema"] == "aragorn/runtime-action-decision/v1"
        and decision["authority"]
        == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and decision["request_digest"] == canonical_digest(request)
        and decision["policy_digest"] == request["policy_digest"]
        and decision["policy_version"] == request["policy_version"]
        and decision["verdict"] in ("ALLOW", "BLOCK")
        and ((decision["verdict"] == "ALLOW") == (reasons == []))
        and not any(code.startswith("BROKER_") for code in reasons),
        "recorded policy decision is unbound or claims a broker reason",
    )
    for key in ("active_context_digest", "measured_action_digest"):
        if decision[key] is not None:
            prior._pin(decision[key])
    for key in (
        "request_digest",
        "policy_digest",
        "revocation_snapshot_digest",
        "mediator_health_digest",
    ):
        prior._pin(decision[key])
    for key in (
        "policy_version",
        "revocation_generation",
        "minimum_revocation_generation",
        "mediator_health_epoch",
        "minimum_mediator_health_epoch",
    ):
        prior._integer(decision[key], 1)
    prior._integer(decision["evaluated_at_unix"])
    return decision


def _result_record(claim: dict, receipt: dict, result: dict, request: dict) -> dict:
    """Reconstruct the record from real receipt bytes, never the old equality rule."""
    profile = claim["profile_claim"]
    prior._exact(
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
    prior._exact(
        result,
        {
            "schema",
            "authority",
            "request_digest",
            "observation_digest",
            "target_name",
            "verdict",
            "reason_codes",
            "effect_status",
            "decision",
        },
    )
    prior._pin(result["observation_digest"])
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
        and result["schema"] == "aragorn/runtime-action-broker-result/v1"
        and result["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and result["request_digest"]
        == profile["request_digest"]
        == canonical_digest(request)
        and result["target_name"] == profile["target_name"]
        and (result["verdict"], result["effect_status"])
        in (("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")),
        "successor receipt or effective result is unbound",
    )
    reasons = _reasons(result["reason_codes"])
    decision = _policy(result["decision"], request)
    if result["verdict"] == "ALLOW":
        valid = (
            decision is not None and decision["verdict"] == "ALLOW" and reasons == []
        )
    elif decision is None:
        valid = reasons == ["BROKER_REPLAY_BLOCKED"]
    else:
        valid = bool(reasons) and (
            (decision["verdict"] == "BLOCK" and reasons == decision["reason_codes"])
            or set(reasons) <= _MISMATCH_REASONS
            or (len(reasons) == 1 and reasons[0] in _SINGLE_REASONS)
        )
    _require(valid, "unsupported policy/effective broker outcome relation")
    return {
        "schema": "aragorn/runtime-capability-grant-result/v1",
        "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": claim["grant_digest"],
        "lease_digest": claim["lease_digest"],
        "profile_result": {
            "schema": "aragorn/runtime-capability-lease-result/v1",
            "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "lease_digest": profile["lease_digest"],
            "submission_digest": profile["submission_digest"],
            "profile_receipt_digest": canonical_digest(receipt),
            "broker_result_digest": canonical_digest(result),
            "verdict": result["verdict"],
            "effect_status": result["effect_status"],
        },
    }


def verify_broker_effective_receipt(
    *,
    completion_raw: bytes,
    expected_completion_digest: str,
    expected_binding_raw: bytes,
    expected_binding_digest: str,
    expected_process_identity: dict,
    input_cas: CAS,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Verify a v2 retained chain, not policy causation, effects or full latency."""
    try:
        return _verify(
            completion_raw,
            expected_completion_digest,
            expected_binding_raw,
            expected_binding_digest,
            expected_process_identity,
            input_cas,
            evidence_cas,
        )
    except BrokerEffectiveReceiptVerificationError:
        raise
    except Exception as exc:
        raise BrokerEffectiveReceiptVerificationError(
            "effective broker receipt verification refused"
        ) from exc


def _verify(
    completion_raw,
    completion_digest,
    binding_raw,
    binding_digest,
    process,
    input_cas,
    evidence_cas,
):
    _require(
        isinstance(input_cas, CAS)
        and input_cas.read_only
        and isinstance(evidence_cas, CAS)
        and evidence_cas.read_only,
        "read-only evidence stores are required",
    )
    plan = prior._binding(binding_raw, binding_digest)
    process = prior._process(
        prior._parse(canonical_json(process), 4096), plan["boot_id"]
    )
    retained = {}

    def read(store: CAS, digest: str, limit: int = _LIMIT) -> bytes:
        raw = store.read(prior._pin(digest), max_bytes=limit)
        _require(bool(raw) and prior._digest(raw) == digest, "retained bytes changed")
        retained[(store, digest)] = raw
        return raw

    scheduled = prior._scheduled_request(plan, read, input_cas)
    completion = prior._exact(
        prior._parse(completion_raw, 4096),
        {"schema", "pending_digest", "evidence_digest"},
    )
    _require(
        prior._digest(completion_raw) == prior._pin(completion_digest)
        and completion["schema"]
        == "aragorn/runtime-broker-decision-measurement-complete/v2",
        "completion differs from the operator-held successor pin",
    )
    prior._pin(completion["pending_digest"])
    evidence = prior._exact(
        prior._parse(read(evidence_cas, completion["evidence_digest"])),
        {
            "schema",
            "authority",
            "pending",
            "effective_final_decision",
            "consumed_grant_state_digest",
            "profile_receipt_digest",
            "broker_result_digest",
            "decision",
            "limitations",
        },
    )
    _require(
        evidence["schema"] == "aragorn/runtime-broker-decision-measurement/v2"
        and evidence["authority"]
        == "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3"
        and evidence["limitations"] == _RETAINED_LIMITS,
        "unsupported successor evidence contract",
    )
    eligibility = prior._exact(
        evidence["decision"],
        {"phase3_exit_eligible", "run_eligible", "quantitative_metrics_eligible"},
    )
    _require(
        all(value is False for value in eligibility.values()),
        "evidence exceeds its authority",
    )
    pending = prior._exact(
        evidence["pending"],
        {
            "schema",
            "binding",
            "process",
            "clock_id",
            "acceptance_boundary",
            "accepted_boottime_ns",
            "action_request_digest",
            "submission_digest",
            "lease_digest",
            "runtime_attribution_digest",
        },
    )
    _require(
        pending["schema"] == "aragorn/runtime-broker-decision-measurement-pending/v1"
        and canonical_digest(pending) == completion["pending_digest"]
        and canonical_json(pending["binding"]) == binding_raw
        and prior._process(pending["process"], plan["boot_id"]) == process
        and pending["clock_id"] == "CLOCK_BOOTTIME"
        and pending["acceptance_boundary"] == prior._ACCEPTED,
        "pending acceptance differs from operator custody pins",
    )
    for key in (
        "action_request_digest",
        "submission_digest",
        "lease_digest",
        "runtime_attribution_digest",
    ):
        prior._pin(pending[key])
    final = prior._exact(
        evidence["effective_final_decision"],
        {
            "finalized_boottime_ns",
            "verdict",
            "reason_codes",
            "observation_digest",
            "policy_decision_digest",
        },
    )
    accepted = prior._integer(pending["accepted_boottime_ns"])
    finalized = prior._integer(final["finalized_boottime_ns"])
    _require(finalized > accepted, "broker interval is not strictly increasing")
    prior._pin(final["observation_digest"])
    if final["policy_decision_digest"] is not None:
        prior._pin(final["policy_decision_digest"])
    _reasons(final["reason_codes"])
    state = v4._state(
        prior._parse(read(evidence_cas, evidence["consumed_grant_state_digest"])),
        plan["grant_digest"],
    )
    _require(
        state["status"] == "CONSUMED", "incomplete grant is not a completed sample"
    )
    request = prior._native_join(
        plan,
        pending,
        state,
        prior._parse(read(evidence_cas, pending["submission_digest"])),
        read(input_cas, plan["grant_digest"], 64 * 1024),
        prior._parse(read(input_cas, plan["path_digest"], 4096), 4096),
    )
    receipt = prior._parse(read(evidence_cas, evidence["profile_receipt_digest"]))
    result = prior._parse(read(evidence_cas, evidence["broker_result_digest"]))
    record = _result_record(state["claim"], receipt, result, request)
    policy_digest = (
        canonical_digest(result["decision"]) if result["decision"] is not None else None
    )
    _require(
        state["result"] == record
        and record["profile_result"]["profile_receipt_digest"]
        == evidence["profile_receipt_digest"]
        and record["profile_result"]["broker_result_digest"]
        == evidence["broker_result_digest"]
        and result["request_digest"] == pending["action_request_digest"]
        and all(
            result[key] == final[key]
            for key in ("verdict", "reason_codes", "observation_digest")
        )
        and policy_digest == final["policy_decision_digest"],
        "consumption, receipt, policy and effective decision disagree",
    )
    for (store, digest), original in retained.items():
        _require(
            store.read(digest, max_bytes=len(original)) == original,
            "final evidence custody changed",
        )
    policy = result["decision"]
    return {
        "schema": "aragorn/runtime-broker-decision-measurement-verification/v2",
        "authority": "RETAINED_BROKER_RECEIPT_JOINS_AND_LOCAL_INTERVAL_ONLY",
        "completion_digest": completion_digest,
        "binding_digest": binding_digest,
        "evidence_digest": completion["evidence_digest"],
        "scheduled_request": scheduled,
        "action_request_digest": pending["action_request_digest"],
        "submission_digest": pending["submission_digest"],
        "grant_digest": plan["grant_digest"],
        "lease_digest": pending["lease_digest"],
        "broker_process_custody_claim": process,
        "receipt_chain": "VERIFIED",
        "recorded_broker_outcome": {
            key: result[key] for key in ("verdict", "reason_codes", "effect_status")
        },
        "recorded_policy_outcome": None
        if policy is None
        else {
            "digest": policy_digest,
            "verdict": policy["verdict"],
            "reason_codes": policy["reason_codes"],
        },
        "broker_interval": {
            "clock_id": "CLOCK_BOOTTIME",
            "start_boundary": prior._ACCEPTED,
            "end_boundary": "SHARED_CORE_EFFECTIVE_FINAL_VERDICT",
            "accepted_boottime_ns": accepted,
            "finalized_boottime_ns": finalized,
            "elapsed_ns": finalized - accepted,
            "scope": "ONE_BROKER_PROCESS_ONLY",
        },
        "decision": {**eligibility, "generic_collector_semantics_eligible": False},
        "limitations": [
            *_RETAINED_LIMITS,
            "NO_CROSS_PROCESS_CLOCK_DOMAIN_OR_CHRONOLOGY_PROOF",
            "NO_INDEPENDENT_POLICY_EVALUATION_OR_PHYSICAL_EFFECT_PROOF",
            "SOURCE_PINS_AND_PROCESS_IDENTITY_ARE_OPERATOR_CUSTODY_NOT_ATTESTATION",
            "PROFILED_SUBMISSION_AND_PROTECTED_ROOT_DESCRIPTOR_REQUIRED_AS_EXTRA_RETAINED_INPUTS",
        ],
    }
