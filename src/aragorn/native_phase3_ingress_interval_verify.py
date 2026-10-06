"""Join retained worker ingress to an effective broker final decision, offline.

Three existing independent consumers retain their exact contracts. This module
adds cross-record identity, action and chronology joins; it does not observe a
process, execute an adapter, import a producer, sample a clock or write a CAS.
The derived interval is conditional on caller-pinned local evidence, not live
attestation, continuous namespace custody, native-call causality or a metric.
"""

from __future__ import annotations

import hashlib
import json

from . import native_phase3_clock_domain_verify as clocks
from . import runtime_broker_effective_receipt_verify as broker
from . import runtime_worker_ingress_verify as worker
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/native-phase3-ingress-interval-verification/v1"
AUTHORITY = (
    "RETAINED_INGRESS_TO_EFFECTIVE_FINAL_INTERVAL_NOT_LIVE_LATENCY_OR_QUALIFICATION"
)
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "live_deployment_attested",
    "admission_qualified",
    "route_qualified",
    "run_eligible",
    "phase3_eligible",
    "phase3_exit_eligible",
    "metrics_eligible",
    "quantitative_metrics_eligible",
    "generic_collector_semantics_eligible",
    "application_acknowledged",
    "effect_observed",
    "blocked_pre_effect_verified",
    "residue_verified",
    "causal_attribution_verified",
)
LIMITATIONS = (
    "CALLER_PINNED_LOCAL_RECORDS_NOT_SOURCE_PLACEMENT_OR_EXECUTION_ATTESTATION",
    "AUTHENTICATED_NON_RECEIPT_FRAME_NOT_SOCKET_ACCEPT_GATEWAY_DISPATCH_OR_NATIVE_CALL_START",
    "EFFECTIVE_FINAL_VERDICT_EXCLUDES_FINAL_RECORD_PERSISTENCE_RESPONSE_DELIVERY_AND_SINK_ACKNOWLEDGMENT",
    "INTERVAL_INCLUDES_SYNCHRONOUS_RETENTION_AND_DISPATCH_OVERHEAD_NOT_UNINSTRUMENTED_LATENCY",
    "POINT_IN_TIME_SHARED_ACTIVE_NAMESPACE_READBACKS_NOT_CONTINUOUS_CLOCK_OR_IDENTITY_CUSTODY",
    "WORKER_STARTUP_MAY_PRECEDE_PRECLOCK_OBSERVATION_NO_STARTUP_BOOT_ATTESTATION",
    "V1_COLLECTION_COMMITMENT_CLOCK_NOT_JOINED_OR_REINTERPRETED_AS_WORKER_EVENTS",
    "NATIVE_RECEIPT_TAIL_AND_GENESIS_PIN_NOT_WHOLE_HISTORY_OR_GENESIS_CONTENT_VERIFICATION",
    "RECORDED_BROKER_OUTCOME_NOT_INDEPENDENT_POLICY_EFFECT_RESIDUE_OR_CAUSALITY_PROOF",
    "ONE_ATTRIBUTED_RETAINED_INTERVAL_NOT_CAMPAIGN_TASK_OVERHEAD_OR_PHASE3_QUALIFICATION",
)
_EPOCH = ("pid", "start_time_ticks", "uid", "gid")


class NativeIngressIntervalVerificationError(ValueError):
    """Retained evidence does not close over one bounded native interval."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeIngressIntervalVerificationError(reason)


def verify_native_ingress_interval(
    *,
    startup_raw: bytes,
    ingress_raw: bytes,
    attempt_raw: bytes,
    action_raw: bytes,
    expected_record_digests: dict[str, str],
    clock_before_raw: bytes,
    clock_after_raw: bytes,
    expected_clock_before_digest: str,
    expected_clock_after_digest: str,
    completion_raw: bytes,
    expected_completion_digest: str,
    expected_binding_raw: bytes,
    expected_binding_digest: str,
    expected_worker: dict,
    expected_broker_process: dict,
    expected_worker_binding_digest: str,
    expected_genesis_digest: str,
    input_cas: CAS,
    evidence_cas: CAS,
) -> dict:
    """Derive the recorded ingress-to-effective-final interval, never metrics.

    The four worker records, two clock observations and completion bytes must
    already be retained in ``evidence_cas``. The broker binding and its existing
    plan closure must be retained in ``input_cas``. Both stores are read-only.
    The caller supplies independently held process and digest expectations.
    Startup can precede the external preclock read; the ingress-to-final events
    themselves must lie between the two external observation brackets.
    """
    try:
        _require(
            type(input_cas) is CAS
            and input_cas.read_only is True
            and type(evidence_cas) is CAS
            and evidence_cas.read_only is True,
            "exact read-only CAS stores are required",
        )
        _require(
            type(expected_record_digests) is dict, "worker record pins are missing"
        )
        _require(
            type(expected_worker) is dict and type(expected_broker_process) is dict,
            "caller process expectations must be exact objects",
        )
        pins = dict(expected_record_digests)
        # Detach caller-owned dictionaries before any store read or verifier call.
        expected_worker = json.loads(canonical_json(expected_worker))
        expected_broker_process = json.loads(canonical_json(expected_broker_process))
        retained = {}

        def read(store: CAS, pin: str, limit: int) -> bytes:
            raw = store.read(pin, max_bytes=limit)
            _require(
                type(raw) is bytes
                and 0 < len(raw) <= limit
                and "sha256:" + hashlib.sha256(raw).hexdigest() == pin,
                "retained interval input differs from its pin",
            )
            key = (store, pin)
            _require(
                key not in retained or retained[key] == raw,
                "retained interval input changed",
            )
            retained[key] = raw
            return raw

        raw_records = dict(
            zip(
                worker.STAGES,
                (startup_raw, ingress_raw, attempt_raw, action_raw),
                strict=True,
            )
        )
        _require(set(pins) == set(raw_records), "worker record pin inventory changed")
        for stage, raw in raw_records.items():
            _require(
                type(raw) is bytes
                and read(evidence_cas, pins[stage], worker.MAX_RECORD_BYTES) == raw,
                "worker record is not retained",
            )
        for raw, pin, limit in (
            (clock_before_raw, expected_clock_before_digest, 16384),
            (clock_after_raw, expected_clock_after_digest, 16384),
            (completion_raw, expected_completion_digest, 4096),
        ):
            _require(
                type(raw) is bytes and read(evidence_cas, pin, limit) == raw,
                "clock observation or completion is not retained",
            )
        _require(
            type(expected_binding_raw) is bytes
            and read(input_cas, expected_binding_digest, 4096) == expected_binding_raw,
            "broker binding is not retained",
        )

        ingress = worker.verify_worker_ingress_records(
            startup_raw,
            ingress_raw,
            attempt_raw,
            action_raw,
            expected_record_digests=pins,
            expected_worker=expected_worker,
            expected_binding_digest=expected_worker_binding_digest,
            expected_genesis_digest=expected_genesis_digest,
        )
        broker_arguments = {
            "completion_raw": completion_raw,
            "expected_completion_digest": expected_completion_digest,
            "expected_binding_raw": expected_binding_raw,
            "expected_binding_digest": expected_binding_digest,
            "expected_process_identity": expected_broker_process,
            "input_cas": input_cas,
            "evidence_cas": evidence_cas,
        }
        final = broker.verify_broker_effective_receipt(**broker_arguments)
        broker_process = final["broker_process_custody_claim"]
        domain = clocks.verify_native_common_clock_domain(
            clock_before_raw,
            clock_after_raw,
            expected_before_digest=expected_clock_before_digest,
            expected_after_digest=expected_clock_after_digest,
            expected_worker=expected_worker,
            expected_broker={key: broker_process[key] for key in _EPOCH},
        )
        _require(
            ingress["clock_id"]
            == final["broker_interval"]["clock_id"]
            == domain["clock_domain"]["clock_id"]
            == "CLOCK_BOOTTIME"
            and ingress["time_namespace"] == domain["clock_domain"]["time_namespace"]
            and broker_process["boot_id"] == domain["clock_domain"]["boot_id"],
            "worker namespace or broker boot differs from the external domain",
        )
        scheduled = final["scheduled_request"]
        _require(
            scheduled["kind"] == "attempt" and scheduled["negative_control"] is False,
            "only one attributed native attempt is supported",
        )
        _require(
            ingress["action_request_digest"] == final["action_request_digest"],
            "worker and broker action digests differ",
        )
        # The broker consumer already validates this actual profiled submission.
        # Read its retained bytes, rather than inventing a predecessor envelope or
        # inferring the worker epoch from a request digest alone.
        submission_raw = read(evidence_cas, final["submission_digest"], 128 * 1024)
        submission = json.loads(submission_raw)
        _require(
            canonical_json(submission) == submission_raw,
            "profiled submission is not canonical",
        )
        action = json.loads(action_raw)["body"]["action_request"]
        _require(
            canonical_json(action) == canonical_json(submission["envelope"]["request"]),
            "actual action request bytes differ across worker and broker",
        )
        attribution = submission["runtime_attribution"]
        _require(
            all(
                type(attribution[key]) is int
                and attribution[key] == expected_worker[key]
                for key in _EPOCH
            )
            and all(
                type(submission["runtime_peer"][key]) is int
                and submission["runtime_peer"][key] == expected_worker[key]
                for key in ("pid", "uid", "gid")
            ),
            "broker profile attribution is not the observed ingress worker epoch",
        )
        stamps = ingress["stage_boottime_ns"]
        accepted = final["broker_interval"]["accepted_boottime_ns"]
        finalized = final["broker_interval"]["finalized_boottime_ns"]
        brackets = domain["read_brackets"]
        _require(
            brackets["before"]["finished_boottime_ns"]
            <= stamps["ingress"]
            < stamps["attempt"]
            < stamps["action"]
            <= accepted
            < finalized
            <= brackets["after"]["started_boottime_ns"],
            "native interval is outside its external brackets or causal order",
        )

        # Recompute the existing broker closure after the new cross-record reads,
        # then read back every directly used raw input. No callbacks or writes run.
        _require(
            canonical_json(broker.verify_broker_effective_receipt(**broker_arguments))
            == canonical_json(final),
            "broker closure changed during interval verification",
        )
        for (store, pin), original in retained.items():
            _require(
                read(store, pin, len(original)) == original,
                "final interval input custody changed",
            )
        result = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "RETAINED_INGRESS_TO_EFFECTIVE_FINAL_INTERVAL_VERIFIED",
            "input_digests": {
                "worker_records": pins,
                "clock_before": expected_clock_before_digest,
                "clock_after": expected_clock_after_digest,
                "broker_completion": expected_completion_digest,
                "broker_binding": expected_binding_digest,
                "profiled_submission": final["submission_digest"],
            },
            "component_verification_digests": {
                "worker_ingress": canonical_digest(ingress),
                "clock_domain": canonical_digest(domain),
                "broker_effective_receipt": canonical_digest(final),
            },
            "worker_identity": expected_worker,
            "broker_process_custody_claim": broker_process,
            "clock_domain": domain["clock_domain"],
            "scheduled_request": scheduled,
            "worker_binding_digest": expected_worker_binding_digest,
            "genesis_digest": expected_genesis_digest,
            "worker_request_digest": ingress["worker_request_digest"],
            "attempt_digest": ingress["attempt_digest"],
            "action_request_digest": ingress["action_request_digest"],
            "retained_interval": {
                "clock_id": "CLOCK_BOOTTIME",
                "start_boundary": "AUTHENTICATED_NON_RECEIPT_FRAME_BEFORE_OPEN_ATTEMPT_GATE",
                "end_boundary": "SHARED_CORE_EFFECTIVE_FINAL_VERDICT",
                "ingress_boottime_ns": stamps["ingress"],
                "finalized_boottime_ns": finalized,
                "elapsed_ns": finalized - stamps["ingress"],
            },
            "chronology": {
                "worker_stages": stamps,
                "broker_accepted_boottime_ns": accepted,
                "external_read_brackets": brackets,
            },
            "recorded_broker_outcome": final["recorded_broker_outcome"],
            "recorded_policy_outcome": final["recorded_policy_outcome"],
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
        }
        _require(
            len(canonical_json(result)) <= 16384, "interval summary exceeds its bound"
        )
        return result
    except NativeIngressIntervalVerificationError:
        raise
    except Exception as exc:
        raise NativeIngressIntervalVerificationError(
            "retained native interval verification refused"
        ) from exc
