"""Fail-closed quantitative qualification for one bounded Phase 3 campaign."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json

INPUT_SCHEMA = "aragorn/phase3-quantitative-metrics-evidence/v1"
OUTPUT_SCHEMA = "aragorn/phase3-quantitative-metrics-leaf/v1"
MEASUREMENT_SCHEDULE_SCHEMA = "aragorn/phase3-measurement-schedule/v1"
AUTHORITY = (
    "BOUNDED_PHASE3_QUANTITATIVE_METRICS_LEAF_ONLY_NOT_PHASE3_EXIT_EDR_"
    "INSTALLER_OR_RELEASE_AUTHORITY"
)
CLOCK_ID = "CLOCK_BOOTTIME"
TASK_TIMING_BOUNDARY = "TASK_ACCEPTED_TO_TASK_COMPLETED"
EXPECTED_ATTEMPTS = 100
EXPECTED_OVERHEAD_PAIRS = 100
ATTRIBUTION_THRESHOLD_NUMERATOR = 99
ATTRIBUTION_THRESHOLD_DENOMINATOR = 100
LATENCY_THRESHOLD_NS = 500_000_000
OVERHEAD_SCALE = 100
OVERHEAD_LIMIT = 110

_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_INTEGER = (1 << 63) - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FAMILIES = {"DESTRUCTIVE", "EXFILTRATION", "OTHER"}
_INPUT_KEYS = {
    "attempts",
    "baseline_samples",
    "bindings",
    "clock_id",
    "instrumented_samples",
    "schema",
}
_BINDING_KEYS = {
    "campaign_contract_digest",
    "gate_manifest_digest",
    "measurement_schedule_digest",
    "metrics_implementation_digest",
    "runtime_identity_digest",
}
_ATTEMPT_KEYS = {
    "attempt_id",
    "attributed",
    "blocked_pre_effect",
    "decision_finalized_boottime_ns",
    "family",
    "negative_control",
    "request_accepted_boottime_ns",
    "residue_detected",
}
_PAIR_BINDING_KEYS = {"host_profile_digest", "input_digest", "task_digest"}
_SAMPLE_KEYS = {
    "completed_boottime_ns",
    "host_profile_digest",
    "input_digest",
    "pair_id",
    "started_boottime_ns",
    "status",
    "task_digest",
    "timing_boundary",
}
_LIMITATIONS = [
    "QUANTITATIVE_METRICS_LEAF_ONLY",
    "INPUT_OBSERVATION_SEMANTICS_REQUIRE_INDEPENDENT_QUALIFICATION",
    "NO_PHASE3_EXIT_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]


class Phase3QuantitativeMetricsError(ValueError):
    """The evidence cannot support the bounded quantitative metrics leaf."""


def metrics_implementation_digest() -> str:
    """Return the digest of the exact metrics verifier module bytes."""

    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def build_phase3_measurement_schedule(
    *,
    expected_attempt_ids: list[str],
    expected_attempt_families: dict[str, str],
    expected_overhead_pair_bindings: dict[str, dict[str, str]],
    expected_unattributed_attempt_id: str,
    expected_gate_manifest_digest: str,
    expected_campaign_contract_digest: str,
    expected_runtime_identity_digest: str,
) -> dict[str, Any]:
    """Build the canonical caller-held schedule committed before outcomes exist."""

    attempt_ids = _inventory(
        expected_attempt_ids,
        expected=EXPECTED_ATTEMPTS,
        label="expected attempt IDs",
    )
    attempt_families = _attempt_families(expected_attempt_families, attempt_ids)
    negative_control_id = _identifier(
        expected_unattributed_attempt_id,
        "expected unattributed negative-control attempt ID",
    )
    if negative_control_id not in attempt_ids:
        raise Phase3QuantitativeMetricsError(
            "unattributed negative-control attempt is outside the inventory"
        )
    overhead_pair_bindings = _overhead_pair_bindings(expected_overhead_pair_bindings)
    bindings = {
        "campaign_contract_digest": _digest(
            expected_campaign_contract_digest,
            "expected campaign contract digest",
        ),
        "gate_manifest_digest": _digest(
            expected_gate_manifest_digest, "expected gate manifest digest"
        ),
        "runtime_identity_digest": _digest(
            expected_runtime_identity_digest, "expected runtime identity digest"
        ),
    }
    return {
        "schema": MEASUREMENT_SCHEDULE_SCHEMA,
        "bindings": bindings,
        "attempt_schedule": {
            "attempt_count": EXPECTED_ATTEMPTS,
            "attempt_families": attempt_families,
            "attempt_ids": attempt_ids,
            "unattributed_negative_control_attempt_id": negative_control_id,
        },
        "overhead_schedule": {
            "pair_bindings": overhead_pair_bindings,
            "pair_count": EXPECTED_OVERHEAD_PAIRS,
        },
    }


def qualify_phase3_quantitative_metrics_bytes(
    raw: bytes,
    *,
    expected_attempt_ids: list[str],
    expected_attempt_families: dict[str, str],
    expected_overhead_pair_bindings: dict[str, dict[str, str]],
    expected_unattributed_attempt_id: str,
    expected_gate_manifest_digest: str,
    expected_campaign_contract_digest: str,
    expected_runtime_identity_digest: str,
    expected_measurement_schedule_digest: str,
    expected_metrics_implementation_digest: str,
) -> dict[str, Any]:
    """Parse canonical evidence strictly and qualify its quantitative metrics."""

    if type(raw) is not bytes or not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise Phase3QuantitativeMetricsError(
            "metrics evidence must be bounded non-empty bytes"
        )
    if b"\x00" in raw:
        raise Phase3QuantitativeMetricsError("metrics evidence contains NUL")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_noninteger_number,
            parse_float=_reject_noninteger_number,
        )
    except Phase3QuantitativeMetricsError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise Phase3QuantitativeMetricsError(
            "metrics evidence is not strict JSON"
        ) from exc
    try:
        encoded = canonical_json(document)
    except ValueError as exc:
        raise Phase3QuantitativeMetricsError(
            "metrics evidence is not canonical JSON"
        ) from exc
    if encoded != raw:
        raise Phase3QuantitativeMetricsError(
            "metrics evidence bytes are not canonical JSON"
        )
    return qualify_phase3_quantitative_metrics(
        document,
        expected_attempt_ids=expected_attempt_ids,
        expected_attempt_families=expected_attempt_families,
        expected_overhead_pair_bindings=expected_overhead_pair_bindings,
        expected_unattributed_attempt_id=expected_unattributed_attempt_id,
        expected_gate_manifest_digest=expected_gate_manifest_digest,
        expected_campaign_contract_digest=expected_campaign_contract_digest,
        expected_runtime_identity_digest=expected_runtime_identity_digest,
        expected_measurement_schedule_digest=expected_measurement_schedule_digest,
        expected_metrics_implementation_digest=expected_metrics_implementation_digest,
    )


def qualify_phase3_quantitative_metrics(
    evidence: object,
    *,
    expected_attempt_ids: list[str],
    expected_attempt_families: dict[str, str],
    expected_overhead_pair_bindings: dict[str, dict[str, str]],
    expected_unattributed_attempt_id: str,
    expected_gate_manifest_digest: str,
    expected_campaign_contract_digest: str,
    expected_runtime_identity_digest: str,
    expected_measurement_schedule_digest: str,
    expected_metrics_implementation_digest: str,
) -> dict[str, Any]:
    """Return a PASS leaf only after independently recomputing every metric."""

    document = _exact_object(evidence, _INPUT_KEYS, "metrics evidence")
    _exact_string(document["schema"], INPUT_SCHEMA, "metrics evidence schema")
    _exact_string(document["clock_id"], CLOCK_ID, "metrics evidence clock_id")

    implementation_digest = _digest(
        expected_metrics_implementation_digest,
        "expected metrics implementation digest",
    )
    if implementation_digest != metrics_implementation_digest():
        raise Phase3QuantitativeMetricsError("metrics implementation digest changed")

    schedule = build_phase3_measurement_schedule(
        expected_attempt_ids=expected_attempt_ids,
        expected_attempt_families=expected_attempt_families,
        expected_overhead_pair_bindings=expected_overhead_pair_bindings,
        expected_unattributed_attempt_id=expected_unattributed_attempt_id,
        expected_gate_manifest_digest=expected_gate_manifest_digest,
        expected_campaign_contract_digest=expected_campaign_contract_digest,
        expected_runtime_identity_digest=expected_runtime_identity_digest,
    )
    schedule_digest = _digest(
        expected_measurement_schedule_digest,
        "expected measurement schedule digest",
    )
    if schedule_digest != canonical_digest(schedule):
        raise Phase3QuantitativeMetricsError("measurement schedule digest changed")
    attempt_schedule = schedule["attempt_schedule"]
    overhead_schedule = schedule["overhead_schedule"]
    attempt_ids = attempt_schedule["attempt_ids"]
    attempt_families = attempt_schedule["attempt_families"]
    negative_control_id = attempt_schedule["unattributed_negative_control_attempt_id"]
    overhead_pair_bindings = overhead_schedule["pair_bindings"]

    bindings = _bindings(
        document["bindings"],
        expected_gate_manifest_digest=expected_gate_manifest_digest,
        expected_campaign_contract_digest=expected_campaign_contract_digest,
        expected_runtime_identity_digest=expected_runtime_identity_digest,
        expected_measurement_schedule_digest=schedule_digest,
        expected_metrics_implementation_digest=implementation_digest,
    )
    attempts = _exact_list(
        document["attempts"], EXPECTED_ATTEMPTS, "attempt observations"
    )
    observed_attempt_ids = [
        _identifier(
            _exact_object(value, _ATTEMPT_KEYS, f"attempts[{index}]")["attempt_id"],
            f"attempts[{index}].attempt_id",
        )
        for index, value in enumerate(attempts)
    ]
    _reconcile_inventory(observed_attempt_ids, attempt_ids, "attempt observation IDs")

    attributed_count = 0
    negative_controls: list[str] = []
    latencies: list[int] = []
    family_counts = {family: 0 for family in _FAMILIES}
    family_blocked = {family: 0 for family in _FAMILIES}
    family_residue_free = {family: 0 for family in _FAMILIES}

    for index, raw_attempt in enumerate(attempts):
        label = f"attempts[{index}]"
        attempt = _exact_object(raw_attempt, _ATTEMPT_KEYS, label)
        family = attempt["family"]
        if type(family) is not str or family not in _FAMILIES:
            raise Phase3QuantitativeMetricsError(f"{label}.family is unsupported")
        if family != attempt_families[attempt["attempt_id"]]:
            raise Phase3QuantitativeMetricsError(
                f"{label}.family changed from the caller-held schedule"
            )
        attributed = _boolean(attempt["attributed"], f"{label}.attributed")
        negative_control = _boolean(
            attempt["negative_control"], f"{label}.negative_control"
        )
        blocked = _boolean(attempt["blocked_pre_effect"], f"{label}.blocked_pre_effect")
        residue = _boolean(attempt["residue_detected"], f"{label}.residue_detected")
        accepted = _integer(
            attempt["request_accepted_boottime_ns"],
            f"{label}.request_accepted_boottime_ns",
            minimum=0,
        )
        finalized = _integer(
            attempt["decision_finalized_boottime_ns"],
            f"{label}.decision_finalized_boottime_ns",
            minimum=0,
        )
        if finalized < accepted:
            raise Phase3QuantitativeMetricsError(
                f"{label} decision precedes request acceptance"
            )
        if blocked and residue:
            raise Phase3QuantitativeMetricsError(
                f"{label} pre-effect block has residue"
            )

        if attributed:
            attributed_count += 1
        if negative_control:
            negative_controls.append(attempt["attempt_id"])
        latencies.append(finalized - accepted)
        family_counts[family] += 1
        family_blocked[family] += int(blocked)
        family_residue_free[family] += int(not residue)

    if negative_controls != [negative_control_id]:
        raise Phase3QuantitativeMetricsError(
            "exactly one declared unattributed negative control is required"
        )
    negative_control = attempts[attempt_ids.index(negative_control_id)]
    if negative_control["attributed"] is not False:
        raise Phase3QuantitativeMetricsError(
            "negative control must remain unattributed"
        )
    if (
        negative_control["blocked_pre_effect"] is not True
        or negative_control["residue_detected"] is not False
    ):
        raise Phase3QuantitativeMetricsError(
            "unattributed negative control was not blocked pre-effect residue-free"
        )

    attribution_left = ATTRIBUTION_THRESHOLD_DENOMINATOR * attributed_count
    attribution_right = ATTRIBUTION_THRESHOLD_NUMERATOR * EXPECTED_ATTEMPTS
    if attribution_left < attribution_right:
        raise Phase3QuantitativeMetricsError(
            "attempt attribution is below the exact 99 percent threshold"
        )

    blocking: dict[str, dict[str, Any]] = {}
    for family in ("EXFILTRATION", "DESTRUCTIVE"):
        denominator = family_counts[family]
        if denominator == 0:
            raise Phase3QuantitativeMetricsError(
                f"{family.lower()} family denominator must be nonzero"
            )
        if family_blocked[family] != denominator:
            raise Phase3QuantitativeMetricsError(
                f"{family.lower()} family is not fully blocked pre-effect"
            )
        if family_residue_free[family] != denominator:
            raise Phase3QuantitativeMetricsError(
                f"{family.lower()} family is not residue-free"
            )
        blocking[family.lower()] = {
            "blocked_pre_effect": family_blocked[family],
            "denominator": denominator,
            "residue_free": family_residue_free[family],
            "status": "PASS",
        }

    sorted_latencies = sorted(latencies)
    nearest_rank = (95 * len(sorted_latencies) + 99) // 100
    p95_ns = sorted_latencies[nearest_rank - 1]
    if p95_ns >= LATENCY_THRESHOLD_NS:
        raise Phase3QuantitativeMetricsError(
            "p95 synchronous decision latency is not strictly below 500 ms"
        )

    baseline = _samples(
        document["baseline_samples"],
        overhead_pair_bindings,
        "baseline samples",
    )
    instrumented = _samples(
        document["instrumented_samples"],
        overhead_pair_bindings,
        "instrumented samples",
    )
    baseline_total = sum(baseline)
    instrumented_total = sum(instrumented)
    overhead_left = OVERHEAD_SCALE * instrumented_total
    overhead_right = OVERHEAD_LIMIT * baseline_total
    if overhead_left >= overhead_right:
        raise Phase3QuantitativeMetricsError(
            "task overhead is not strictly below 10 percent"
        )

    return {
        "schema": OUTPUT_SCHEMA,
        "authority": AUTHORITY,
        "input_digest": canonical_digest(document),
        "bindings": dict(bindings),
        "inventory": {
            "attempt_count": EXPECTED_ATTEMPTS,
            "attempt_families_digest": canonical_digest(attempt_families),
            "attempt_ids_digest": canonical_digest(attempt_ids),
            "clock_id": CLOCK_ID,
            "overhead_pair_count": EXPECTED_OVERHEAD_PAIRS,
            "overhead_pair_bindings_digest": canonical_digest(overhead_pair_bindings),
            "unattributed_negative_control_attempt_id": negative_control_id,
        },
        "attribution": {
            "attributed": attributed_count,
            "comparison_left": attribution_left,
            "comparison_right": attribution_right,
            "denominator": EXPECTED_ATTEMPTS,
            "status": "PASS",
            "unattributed": EXPECTED_ATTEMPTS - attributed_count,
        },
        "blocking": {
            **blocking,
            "unattributed_negative_control": {
                "attempt_id": negative_control_id,
                "blocked_pre_effect": True,
                "residue_detected": False,
                "status": "PASS",
            },
        },
        "latency": {
            "comparison": "STRICTLY_LESS_THAN",
            "nearest_rank": nearest_rank,
            "p95_ns": p95_ns,
            "sample_count": len(latencies),
            "status": "PASS",
            "threshold_ns": LATENCY_THRESHOLD_NS,
        },
        "overhead": {
            "baseline_total_ns": baseline_total,
            "comparison": "STRICTLY_LESS_THAN",
            "comparison_left": overhead_left,
            "comparison_right": overhead_right,
            "instrumented_total_ns": instrumented_total,
            "pair_count": len(baseline),
            "status": "PASS",
        },
        "decision": {"status": "PASS"},
        "limitations": list(_LIMITATIONS),
    }


def _bindings(
    value: object,
    *,
    expected_gate_manifest_digest: str,
    expected_campaign_contract_digest: str,
    expected_runtime_identity_digest: str,
    expected_measurement_schedule_digest: str,
    expected_metrics_implementation_digest: str,
) -> dict[str, str]:
    bindings = _exact_object(value, _BINDING_KEYS, "metrics bindings")
    expected = {
        "campaign_contract_digest": _digest(
            expected_campaign_contract_digest,
            "expected campaign contract digest",
        ),
        "gate_manifest_digest": _digest(
            expected_gate_manifest_digest, "expected gate manifest digest"
        ),
        "measurement_schedule_digest": _digest(
            expected_measurement_schedule_digest,
            "expected measurement schedule digest",
        ),
        "metrics_implementation_digest": _digest(
            expected_metrics_implementation_digest,
            "expected metrics implementation digest",
        ),
        "runtime_identity_digest": _digest(
            expected_runtime_identity_digest, "expected runtime identity digest"
        ),
    }
    for key, expected_value in expected.items():
        actual = _digest(bindings[key], f"metrics bindings.{key}")
        if actual != expected_value:
            raise Phase3QuantitativeMetricsError(f"metrics bindings.{key} changed")
    return expected


def _inventory(value: object, *, expected: int, label: str) -> list[str]:
    values = _exact_list(value, expected, label)
    identifiers = [
        _identifier(item, f"{label}[{index}]") for index, item in enumerate(values)
    ]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != expected:
        raise Phase3QuantitativeMetricsError(f"{label} must be sorted and unique")
    return identifiers


def _attempt_families(value: object, attempt_ids: list[str]) -> dict[str, str]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise Phase3QuantitativeMetricsError(
            "expected attempt families must be an exact object"
        )
    if set(value) != set(attempt_ids):
        raise Phase3QuantitativeMetricsError(
            "expected attempt families do not exactly reconcile with attempt IDs"
        )
    output: dict[str, str] = {}
    for attempt_id in attempt_ids:
        family = value[attempt_id]
        if type(family) is not str or family not in _FAMILIES:
            raise Phase3QuantitativeMetricsError(
                f"expected attempt family for {attempt_id} is unsupported"
            )
        output[attempt_id] = family
    for family in ("EXFILTRATION", "DESTRUCTIVE"):
        if family not in output.values():
            raise Phase3QuantitativeMetricsError(
                f"expected {family.lower()} family denominator must be nonzero"
            )
    return output


def _overhead_pair_bindings(
    value: object,
) -> dict[str, dict[str, str]]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise Phase3QuantitativeMetricsError(
            "expected overhead pair bindings must be an exact object"
        )
    pair_ids = list(value)
    if (
        len(pair_ids) != EXPECTED_OVERHEAD_PAIRS
        or pair_ids != sorted(pair_ids)
        or len(set(pair_ids)) != EXPECTED_OVERHEAD_PAIRS
    ):
        raise Phase3QuantitativeMetricsError(
            "expected overhead pair bindings must contain exactly 100 sorted "
            "unique pair IDs"
        )
    output: dict[str, dict[str, str]] = {}
    for index, pair_id_value in enumerate(pair_ids):
        pair_id = _identifier(pair_id_value, f"expected overhead pair IDs[{index}]")
        raw_binding = _exact_object(
            value[pair_id],
            _PAIR_BINDING_KEYS,
            f"expected overhead pair bindings.{pair_id}",
        )
        output[pair_id] = {
            key: _digest(
                raw_binding[key],
                f"expected overhead pair bindings.{pair_id}.{key}",
            )
            for key in sorted(_PAIR_BINDING_KEYS)
        }
    return output


def _reconcile_inventory(observed: list[str], expected: list[str], label: str) -> None:
    if observed != expected or len(set(observed)) != len(expected):
        raise Phase3QuantitativeMetricsError(
            f"{label} do not exactly reconcile with the expected inventory"
        )


def _samples(
    value: object,
    expected_bindings: dict[str, dict[str, str]],
    label: str,
) -> list[int]:
    values = _exact_list(value, EXPECTED_OVERHEAD_PAIRS, label)
    durations: list[int] = []
    observed_ids: list[str] = []
    for index, raw_sample in enumerate(values):
        item_label = f"{label}[{index}]"
        sample = _exact_object(raw_sample, _SAMPLE_KEYS, item_label)
        pair_id = _identifier(sample["pair_id"], f"{item_label}.pair_id")
        observed_ids.append(pair_id)
        if pair_id not in expected_bindings:
            raise Phase3QuantitativeMetricsError(
                f"{item_label}.pair_id is outside the caller-held inventory"
            )
        for key in sorted(_PAIR_BINDING_KEYS):
            actual = _digest(sample[key], f"{item_label}.{key}")
            if actual != expected_bindings[pair_id][key]:
                raise Phase3QuantitativeMetricsError(
                    f"{item_label}.{key} changed from the caller-held binding"
                )
        _exact_string(
            sample["timing_boundary"],
            TASK_TIMING_BOUNDARY,
            f"{item_label}.timing_boundary",
        )
        _exact_string(sample["status"], "COMPLETED", f"{item_label}.status")
        started = _integer(
            sample["started_boottime_ns"],
            f"{item_label}.started_boottime_ns",
            minimum=0,
        )
        completed = _integer(
            sample["completed_boottime_ns"],
            f"{item_label}.completed_boottime_ns",
            minimum=0,
        )
        if completed <= started:
            raise Phase3QuantitativeMetricsError(
                f"{item_label} completion must follow task acceptance"
            )
        durations.append(completed - started)
    _reconcile_inventory(observed_ids, list(expected_bindings), f"{label} pair IDs")
    return durations


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise Phase3QuantitativeMetricsError(f"{label} must be an exact object")
    if set(value) != keys:
        raise Phase3QuantitativeMetricsError(f"{label} has missing or unknown fields")
    return value


def _exact_list(value: object, length: int, label: str) -> list[Any]:
    if type(value) is not list or len(value) != length:
        raise Phase3QuantitativeMetricsError(
            f"{label} must contain exactly {length} entries"
        )
    return value


def _exact_string(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise Phase3QuantitativeMetricsError(f"{label} changed")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise Phase3QuantitativeMetricsError(
            f"{label} must be a bounded canonical identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise Phase3QuantitativeMetricsError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise Phase3QuantitativeMetricsError(f"{label} must be an exact boolean")
    return value


def _integer(value: object, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_INTEGER:
        raise Phase3QuantitativeMetricsError(f"{label} must be a bounded exact integer")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise Phase3QuantitativeMetricsError(
                f"metrics evidence repeats JSON key: {key}"
            )
        output[key] = value
    return output


def _reject_noninteger_number(value: str) -> Any:
    raise Phase3QuantitativeMetricsError(
        f"metrics evidence contains non-integer number: {value}"
    )
