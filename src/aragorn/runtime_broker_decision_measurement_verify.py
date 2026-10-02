"""Read-only receipt-chain verification for one broker-owned timing sample.

The operator must independently retain the completion/binding pins and broker
process identity. They are custody claims, not host attestation. This verifier
does not execute an action, sample a clock, read a target, import evidence-named
code, or turn recorded verdicts into attribution/residue/Phase 3 qualification.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as v4
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity
from .phase3_quantitative_metrics import build_phase3_measurement_schedule
from .runtime_capability_grant import (
    _canonical_profiled_submission,
    _profile_attribution,
    parse_runtime_capability_grant,
)

_LIMIT = 128 * 1024
_PLAN_LIMIT = 1024 * 1024
_MATCH = {
    "runtime_digest",
    "policy_digest",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
}
_SOURCES = {
    "runtime_action_broker.py",
    "runtime_action_broker_v4.py",
    "runtime_action_broker_v5.py",
    "runtime_action_service_v5.py",
    "runtime_broker_decision_measurement.py",
    "phase3_deployment.py",
    "phase3_quantitative_metrics.py",
}
_BINDING_KEYS = {
    "schema",
    "boot_id",
    "attempt_id",
    "deployment_identity_digest",
    "measurement_schedule_digest",
    "collection_commitment_digest",
    "scheduled_measurement_request_digest",
    "grant_digest",
    "runtime_profile_digest",
    "sensor_digest",
    "source_pins",
    *_MATCH,
}
_MEASURED = (
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
)
_ACCEPTED = "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM"
_RETAINED_LIMITS = [
    "EXCLUDES_V5_LINEAGE_TRANSPORT_AND_ISSUANCE_VALIDATION",
    "NOT_SINK_RESIDUE_OR_INDEPENDENT_CAUSAL_ATTRIBUTION_PROOF",
    "NOT_TASK_BASELINE_OR_OVERHEAD_MEASUREMENT",
    "EXISTING_CONSUMPTION_CHECKS_CAN_REFUSE_REPLAY_OR_MIXED_VERDICT_BLOCKS",
    "ROOT_OPERATOR_AND_BROKER_CUSTODY_NOT_EXTERNAL_ATTESTATION",
]


class BrokerDecisionMeasurementVerificationError(ValueError):
    """The retained bytes cannot support this bounded receipt-chain statement."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BrokerDecisionMeasurementVerificationError(message)


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid evidence pin",
    )
    return value


def _integer(value: object, minimum: int = 0) -> int:
    _require(type(value) is int and minimum <= value < 2**63, "invalid integer")
    return value


def _exact(value: object, fields: set[str]) -> dict:
    _require(type(value) is dict and set(value) == fields, "unexpected document shape")
    return value


def _parse(raw: bytes, limit: int = _LIMIT) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded document")
    return broker._parse_canonical_document(raw, "broker measurement evidence")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _binding(raw: bytes, digest: str) -> dict:
    _require(_digest(raw) == _pin(digest), "operator binding bytes changed")
    plan = _exact(_parse(raw, 4096), _BINDING_KEYS)
    _require(
        plan["schema"] == "aragorn/runtime-broker-decision-measurement-binding/v1"
        and type(plan["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", plan["boot_id"]
        )
        is not None
        and type(plan["attempt_id"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", plan["attempt_id"])
        is not None,
        "invalid operator binding",
    )
    for key in _BINDING_KEYS - {"schema", "boot_id", "attempt_id", "source_pins"}:
        _pin(plan[key])
    for source_digest in _exact(plan["source_pins"], _SOURCES).values():
        _pin(source_digest)
    return plan


def _process(value: object, boot_id: str) -> dict:
    process = _exact(
        value, {"boot_id", "pid", "uid", "gid", "start_time_ticks", "mount_namespace"}
    )
    _require(process["boot_id"] == boot_id, "broker boot custody claim changed")
    for key in ("pid", "uid", "start_time_ticks"):
        _integer(process[key], 1)
    _integer(process["gid"])
    _require(
        type(process["mount_namespace"]) is str
        and re.fullmatch(r"mnt:\[[0-9]+\]", process["mount_namespace"]) is not None,
        "invalid broker process custody claim",
    )
    return process


def _scheduled_request(plan: dict, read, input_cas: CAS) -> dict:
    commitment = _exact(
        _parse(
            read(input_cas, plan["collection_commitment_digest"], _PLAN_LIMIT),
            _PLAN_LIMIT,
        ),
        {
            "schema",
            "collection_id",
            "schedule_digest",
            "deployment",
            "sources",
            "collector_digest",
            "metrics_implementation_digest",
            "clock_id",
            "prepared_boottime_ns",
        },
    )
    _require(
        commitment["schema"] == "aragorn/phase3-measurement-collection-commitment/v1"
        and commitment["schedule_digest"] == plan["measurement_schedule_digest"]
        and commitment["clock_id"] == "CLOCK_BOOTTIME"
        and commitment["metrics_implementation_digest"]
        == plan["source_pins"]["phase3_quantitative_metrics.py"]
        and type(commitment["collection_id"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", commitment["collection_id"]) is not None,
        "measurement commitment changed",
    )
    _pin(commitment["collector_digest"])
    _integer(commitment["prepared_boottime_ns"])
    for source in _exact(
        commitment["sources"], {"execute", "verify", "identity_reader"}
    ).values():
        _exact(source, {"module", "function", "path", "bytes", "digest"})
        _pin(source["digest"])
        _require(
            _integer(source["bytes"], 1) <= _PLAN_LIMIT
            and all(
                type(source[key]) is str and 0 < len(source[key]) <= 4096
                for key in ("module", "function", "path")
            ),
            "invalid committed callback identity",
        )
    deployment = resolve_phase3_deployment_identity(
        canonical_json(commitment["deployment"]),
        expected_digest=plan["deployment_identity_digest"],
        evidence_cas=input_cas,
    )
    # Include all seven raw artifacts in the final custody readback as well.
    for digest in deployment["bindings"].values():
        read(input_cas, digest, _PLAN_LIMIT)
    raw = read(input_cas, plan["measurement_schedule_digest"], _PLAN_LIMIT)
    schedule = _parse(raw, _PLAN_LIMIT)
    attempts, overhead = schedule["attempt_schedule"], schedule["overhead_schedule"]
    rebuilt = build_phase3_measurement_schedule(
        expected_attempt_ids=attempts["attempt_ids"],
        expected_attempt_families=attempts["attempt_families"],
        expected_unattributed_attempt_id=attempts[
            "unattributed_negative_control_attempt_id"
        ],
        expected_overhead_pair_bindings=overhead["pair_bindings"],
        **{"expected_" + key: value for key, value in schedule["bindings"].items()},
    )
    _require(
        canonical_json(rebuilt) == raw
        and schedule["bindings"]["runtime_identity_digest"]
        == plan["deployment_identity_digest"]
        and plan["attempt_id"] in attempts["attempt_ids"],
        "measurement schedule differs from the binding",
    )
    request = {
        "kind": "attempt",
        "attempt_id": plan["attempt_id"],
        "family": attempts["attempt_families"][plan["attempt_id"]],
        "negative_control": plan["attempt_id"]
        == attempts["unattributed_negative_control_attempt_id"],
        "collection_digest": plan["collection_commitment_digest"],
        "deployment_digest": plan["deployment_identity_digest"],
    }
    _require(
        canonical_digest(request) == plan["scheduled_measurement_request_digest"],
        "scheduled request changed",
    )
    return request


def _native_join(
    plan: dict, pending: dict, state: dict, profiled: dict, grant_raw: bytes, path: dict
) -> dict:
    claim, lease = state["claim"], state["claim"]["lease"]
    claimed = claim["profile_claim"]["claimed_at_unix"]
    grant = parse_runtime_capability_grant(grant_raw, claimed)
    _require(canonical_digest(grant) == plan["grant_digest"], "grant changed")
    profiled = _canonical_profiled_submission(profiled)
    attribution = _profile_attribution(profiled)
    legacy = {**profiled, "schema": "aragorn/runtime-observed-create-submission/v1"}
    legacy.pop("runtime_attribution")
    legacy = broker._observed_submission(legacy)
    request, target, payload = broker._request_effect(legacy["envelope"])
    measured, peer = legacy["measured_action"], legacy["runtime_peer"]
    _exact(path, {"schema", "root_device", "root_inode", "target_name"})
    _integer(path["root_device"])
    _integer(path["root_inode"], 1)
    _require(
        path["schema"] == "aragorn/runtime-protected-path/v1"
        and path["target_name"] == target
        and canonical_digest(path) == plan["path_digest"]
        and canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        )
        == plan["operation_digest"]
        and _digest(payload) == plan["payload_digest"]
        and all(request[key] == plan[key] for key in _MATCH)
        and measured
        == {
            "schema": "aragorn/measured-runtime-action/v1",
            **{key: request[key] for key in _MEASURED},
        }
        and all(attribution[key] == peer[key] for key in ("pid", "uid", "gid"))
        and all(
            attribution[key] == plan[key]
            for key in ("runtime_digest", "active_skill_digest")
        )
        and attribution["profile_digest"] == plan["runtime_profile_digest"]
        and legacy["sensor_digest"] == plan["sensor_digest"],
        "native create action differs from its operator binding",
    )
    _require(
        pending["submission_digest"] == canonical_digest(profiled)
        and pending["action_request_digest"] == canonical_digest(request)
        and pending["runtime_attribution_digest"] == canonical_digest(attribution)
        and pending["lease_digest"] == canonical_digest(lease)
        and claim
        == v4._build_claim(
            grant, lease, legacy, attribution, pending["submission_digest"], claimed
        ),
        "native request/claim/measurement joins changed",
    )
    grant_fields = {
        "runtime_profile_digest",
        "runtime_digest",
        "active_skill_digest",
        "sensor_digest",
        "policy_digest",
        "operation_digest",
    }
    _require(
        all(grant[key] == lease[key] == plan[key] for key in grant_fields)
        and all(lease[key] == request[key] for key in _MATCH)
        and grant["policy_version"]
        == lease["policy_version"]
        == request["policy_version"]
        and grant["issued_at_unix"]
        <= request["issued_at_unix"]
        <= lease["issued_at_unix"]
        <= claimed
        < lease["expires_at_unix"]
        == request["expires_at_unix"]
        <= grant["expires_at_unix"]
        and 0 < lease["expires_at_unix"] - lease["issued_at_unix"] <= 5
        and 0 < request["expires_at_unix"] - request["issued_at_unix"] <= 5,
        "native grant authorization or lease lifetime differs",
    )
    return request


def verify_broker_decision_measurement(
    *,
    completion_raw: bytes,
    expected_completion_digest: str,
    expected_binding_raw: bytes,
    expected_binding_digest: str,
    expected_process_identity: dict,
    input_cas: CAS,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Verify retained joins; return only a same-broker interval and recorded facts.

    Input CAS additionally needs raw grant and protected-path descriptor. Evidence
    CAS additionally needs the canonical profiled submission at its recorded
    digest; the original 73-file timing profile alone does not retain it.
    Neither callback source metadata nor a broker's policy-decision record is
    independently re-executed. No returned field is generic collector semantics.
    """
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
    except BrokerDecisionMeasurementVerificationError:
        raise
    except Exception as exc:
        raise BrokerDecisionMeasurementVerificationError(
            "broker evidence verification refused"
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
    plan = _binding(binding_raw, binding_digest)
    process = _process(_parse(canonical_json(process), 4096), plan["boot_id"])
    retained = {}

    def read(store: CAS, digest: str, limit: int = _LIMIT) -> bytes:
        raw = store.read(_pin(digest), max_bytes=limit)
        _require(bool(raw) and _digest(raw) == digest, "retained bytes changed")
        retained[(store, digest)] = raw
        return raw

    scheduled = _scheduled_request(plan, read, input_cas)
    completion = _exact(
        _parse(completion_raw, 4096), {"schema", "pending_digest", "evidence_digest"}
    )
    _require(
        _digest(completion_raw) == _pin(completion_digest)
        and completion["schema"]
        == "aragorn/runtime-broker-decision-measurement-complete/v1",
        "completion differs from the operator-held pin",
    )
    _pin(completion["pending_digest"])
    evidence = _exact(
        _parse(read(evidence_cas, completion["evidence_digest"])),
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
        evidence["schema"] == "aragorn/runtime-broker-decision-measurement/v1"
        and evidence["authority"]
        == "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3"
        and evidence["limitations"] == _RETAINED_LIMITS,
        "unsupported measurement evidence contract",
    )
    eligibility = _exact(
        evidence["decision"],
        {"phase3_exit_eligible", "run_eligible", "quantitative_metrics_eligible"},
    )
    _require(
        all(value is False for value in eligibility.values()),
        "retained evidence exceeds its authority",
    )
    pending = _exact(
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
        and _process(pending["process"], plan["boot_id"]) == process
        and pending["clock_id"] == "CLOCK_BOOTTIME"
        and pending["acceptance_boundary"] == _ACCEPTED,
        "pending acceptance differs from operator custody pins",
    )
    for key in (
        "action_request_digest",
        "submission_digest",
        "lease_digest",
        "runtime_attribution_digest",
    ):
        _pin(pending[key])
    final = _exact(
        evidence["effective_final_decision"],
        {
            "finalized_boottime_ns",
            "verdict",
            "reason_codes",
            "observation_digest",
            "policy_decision_digest",
        },
    )
    accepted = _integer(pending["accepted_boottime_ns"])
    finalized = _integer(final["finalized_boottime_ns"])
    _require(finalized > accepted, "broker interval is not strictly increasing")
    _pin(final["observation_digest"])
    _pin(final["policy_decision_digest"])
    _require(
        type(final["reason_codes"]) is list
        and all(
            type(code) is str
            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is not None
            for code in final["reason_codes"]
        ),
        "invalid final reason codes",
    )
    state = v4._state(
        _parse(read(evidence_cas, evidence["consumed_grant_state_digest"])),
        plan["grant_digest"],
    )
    _require(
        state["status"] == "CONSUMED", "incomplete grant cannot be a completed sample"
    )
    receipt = _parse(read(evidence_cas, evidence["profile_receipt_digest"]))
    result = _parse(read(evidence_cas, evidence["broker_result_digest"]))
    record = v4._result_record(state["claim"], receipt)
    _require(
        state["result"] == record
        and receipt["broker_result"] == result
        and record["profile_result"]["profile_receipt_digest"]
        == evidence["profile_receipt_digest"]
        and record["profile_result"]["broker_result_digest"]
        == evidence["broker_result_digest"]
        and result["request_digest"] == pending["action_request_digest"]
        and all(
            result[key] == final[key]
            for key in ("verdict", "reason_codes", "observation_digest")
        )
        and canonical_digest(result["decision"]) == final["policy_decision_digest"],
        "consumption, receipt, and effective decision disagree",
    )
    request = _native_join(
        plan,
        pending,
        state,
        _parse(read(evidence_cas, pending["submission_digest"])),
        read(input_cas, plan["grant_digest"], 64 * 1024),
        _parse(read(input_cas, plan["path_digest"], 4096), 4096),
    )
    decision = _exact(
        result["decision"],
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
    for key in ("active_context_digest", "measured_action_digest"):
        if decision[key] is not None:
            _pin(decision[key])
    for key in (
        "request_digest",
        "policy_digest",
        "revocation_snapshot_digest",
        "mediator_health_digest",
    ):
        _pin(decision[key])
    for key in (
        "policy_version",
        "revocation_generation",
        "minimum_revocation_generation",
        "mediator_health_epoch",
        "minimum_mediator_health_epoch",
    ):
        _integer(decision[key], 1)
    _integer(decision["evaluated_at_unix"])
    _require(
        decision.get("policy_digest") == request["policy_digest"]
        and type(decision.get("policy_version")) is int
        and decision["policy_version"] == request["policy_version"],
        "recorded policy decision differs from authorized policy",
    )
    # These are readbacks only. No target/process inspection or CAS write occurs.
    for (store, digest), original in retained.items():
        _require(
            store.read(digest, max_bytes=len(original)) == original,
            "final evidence custody changed",
        )
    return {
        "schema": "aragorn/runtime-broker-decision-measurement-verification/v1",
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
        "broker_interval": {
            "clock_id": "CLOCK_BOOTTIME",
            "start_boundary": _ACCEPTED,
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
