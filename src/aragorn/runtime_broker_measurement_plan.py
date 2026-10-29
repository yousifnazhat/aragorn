"""Prepare one measured grant's inputs without activating or authorizing anything.

The collection commitment must already exist. This module never invents a clock
reading, grants authority, imports an adapter, or touches a runtime service. Its
caller-held pins identify inputs, not an attested deployment. The output CAS is
a fresh, caller-owned staging store; installing its contents under the broker's
ownership and publishing the root-owned credential remain explicit operations.
"""

from __future__ import annotations

import json
import re
from io import BytesIO
from typing import Any

from . import phase3_quantitative_metrics as metrics
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity
from .runtime_action_broker import _TARGET_NAME
from .runtime_capability_grant import parse_runtime_capability_grant

_LIMIT = 1024 * 1024
_SOURCES = {
    "runtime_action_broker.py",
    "runtime_action_broker_v4.py",
    "runtime_action_broker_v5.py",
    "runtime_action_service_v5.py",
    "runtime_broker_decision_measurement.py",
    "phase3_deployment.py",
    "phase3_quantitative_metrics.py",
}


class BrokerMeasurementPlanError(ValueError):
    """The operator-held collection and grant inputs do not form one exact plan."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BrokerMeasurementPlanError(message)


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid input digest",
    )
    return value


def _parse(raw: bytes) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= _LIMIT, "unbounded input")
    try:
        value = json.loads(raw)
        _require(
            type(value) is dict and canonical_json(value) == raw, "noncanonical input"
        )
        return value
    except (UnicodeError, ValueError, TypeError) as exc:
        raise BrokerMeasurementPlanError("invalid canonical input") from exc


def _uint(value: object) -> bool:
    return type(value) is int and 0 <= value < 2**63


def prepare_broker_decision_measurement_binding(
    *,
    source_cas: CAS,
    target_cas: CAS,
    expected_commitment_digest: str,
    expected_schedule_digest: str,
    expected_deployment_digest: str,
    expected_grant_digest: str,
    expected_path_digest: str,
    expected_payload_digest: str,
    expected_collector_digest: str,
    expected_collection_source_pins: dict[str, str],
    expected_broker_source_pins: dict[str, str],
    expected_boot_id: str,
    scheduled_request: dict,
) -> dict[str, Any]:
    """Resolve, bind and copy one existing plan into a fresh private staging CAS.

    ``source_cas`` is read-only and must contain the actual prepared commitment,
    schedule, seven deployment artifacts, raw canonical grant and protected-path
    descriptor. Broker pins come from the operator's exact staged profile. The
    request must be one attributed attempt in that schedule; the unattributed
    negative control cannot be represented by this V4-only measurement profile.

    No clock is sampled. Grant structure is checked, but liveness and runtime
    ownership must be checked at activation. A partially populated target after
    a failure is never cleared or reused automatically.
    """
    _require(source_cas.read_only and not target_cas.read_only, "incorrect CAS access")
    _require(
        source_cas.root.resolve() != target_cas.root.resolve()
        and not any((target_cas.root / "blobs" / "sha256").iterdir()),
        "target CAS must be distinct and fresh",
    )
    pins = {
        "commitment": expected_commitment_digest,
        "schedule": expected_schedule_digest,
        "deployment": expected_deployment_digest,
        "grant": expected_grant_digest,
        "path": expected_path_digest,
        "payload": expected_payload_digest,
        "collector": expected_collector_digest,
    }
    for value in pins.values():
        _pin(value)
    _require(
        type(expected_collection_source_pins) is dict
        and set(expected_collection_source_pins)
        == {"execute", "verify", "identity_reader"}
        and type(expected_broker_source_pins) is dict
        and set(expected_broker_source_pins) == _SOURCES,
        "source pin inventory changed",
    )
    for value in (
        *expected_collection_source_pins.values(),
        *expected_broker_source_pins.values(),
    ):
        _pin(value)
    _require(
        type(expected_boot_id) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected_boot_id
        )
        is not None,
        "invalid operator-held boot identity",
    )
    retained: dict[str, bytes] = {}

    def read(digest: str) -> bytes:
        raw = source_cas.read(_pin(digest), max_bytes=_LIMIT)
        _require(bool(raw), "empty plan input")
        retained[digest] = raw
        return raw

    commitment = _parse(read(pins["commitment"]))
    _require(
        set(commitment)
        == {
            "schema",
            "collection_id",
            "schedule_digest",
            "deployment",
            "sources",
            "collector_digest",
            "metrics_implementation_digest",
            "clock_id",
            "prepared_boottime_ns",
        }
        and commitment["schema"]
        == "aragorn/phase3-measurement-collection-commitment/v1"
        and type(commitment["collection_id"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", commitment["collection_id"]) is not None
        and commitment["schedule_digest"] == pins["schedule"]
        and commitment["collector_digest"] == pins["collector"]
        and commitment["metrics_implementation_digest"]
        == metrics.metrics_implementation_digest()
        == expected_broker_source_pins["phase3_quantitative_metrics.py"]
        and commitment["clock_id"] == metrics.CLOCK_ID
        and _uint(commitment["prepared_boottime_ns"]),
        "commitment differs from the operator-held plan",
    )
    sources = commitment["sources"]
    _require(
        type(sources) is dict and set(sources) == set(expected_collection_source_pins),
        "committed source inventory changed",
    )
    for name, source in sources.items():
        _require(
            type(source) is dict
            and set(source) == {"module", "function", "path", "bytes", "digest"}
            and source["digest"] == expected_collection_source_pins[name]
            and type(source["bytes"]) is int
            and 0 < source["bytes"] <= _LIMIT
            and all(
                type(source[key]) is str and 0 < len(source[key]) <= 4096
                for key in ("module", "function", "path")
            )
            and source["path"].startswith("/"),
            "committed adapter source differs from the operator pin",
        )
    _require(
        sources["execute"]["module"] != sources["verify"]["module"]
        and sources["execute"]["path"] != sources["verify"]["path"],
        "executor and verifier are not separate",
    )
    deployment_raw = canonical_json(commitment["deployment"])
    deployment = resolve_phase3_deployment_identity(
        deployment_raw, expected_digest=pins["deployment"], evidence_cas=source_cas
    )
    for digest in deployment["bindings"].values():
        read(digest)
    retained[pins["deployment"]] = deployment_raw
    schedule_raw = read(pins["schedule"])
    schedule = _parse(schedule_raw)
    try:
        attempts, overhead = schedule["attempt_schedule"], schedule["overhead_schedule"]
        rebuilt = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts["attempt_ids"],
            expected_attempt_families=attempts["attempt_families"],
            expected_unattributed_attempt_id=attempts[
                "unattributed_negative_control_attempt_id"
            ],
            expected_overhead_pair_bindings=overhead["pair_bindings"],
            **{"expected_" + key: value for key, value in schedule["bindings"].items()},
        )
        _require(
            canonical_json(rebuilt) == schedule_raw
            and schedule["bindings"]["runtime_identity_digest"] == pins["deployment"],
            "schedule deployment or contents changed",
        )
        _require(type(scheduled_request) is dict, "missing scheduled request")
        attempt_id = scheduled_request["attempt_id"]
        _require(
            attempt_id in attempts["attempt_ids"]
            and attempt_id != attempts["unattributed_negative_control_attempt_id"],
            "V4 measurement cannot represent this attempt or negative control",
        )
        request = {
            "kind": "attempt",
            "attempt_id": attempt_id,
            "family": attempts["attempt_families"][attempt_id],
            "negative_control": False,
            "collection_digest": pins["commitment"],
            "deployment_digest": pins["deployment"],
        }
        _require(
            canonical_json(request) == canonical_json(scheduled_request),
            "scheduled request changed",
        )
    except (KeyError, TypeError, metrics.Phase3QuantitativeMetricsError) as exc:
        raise BrokerMeasurementPlanError(
            "invalid scheduled measurement request"
        ) from exc
    grant = parse_runtime_capability_grant(read(pins["grant"]))
    descriptor = _parse(read(pins["path"]))
    _require(
        set(descriptor) == {"schema", "root_device", "root_inode", "target_name"}
        and descriptor["schema"] == "aragorn/runtime-protected-path/v1"
        and _uint(descriptor["root_device"])
        and _uint(descriptor["root_inode"])
        and descriptor["root_inode"] > 0
        and type(descriptor["target_name"]) is str
        and _TARGET_NAME.fullmatch(descriptor["target_name"]) is not None
        and grant["operation_digest"]
        == canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        ),
        "unsupported protected action descriptor",
    )
    binding = {
        "schema": "aragorn/runtime-broker-decision-measurement-binding/v1",
        "boot_id": expected_boot_id,
        "attempt_id": attempt_id,
        "deployment_identity_digest": pins["deployment"],
        "measurement_schedule_digest": pins["schedule"],
        "collection_commitment_digest": pins["commitment"],
        "scheduled_measurement_request_digest": canonical_digest(request),
        "grant_digest": pins["grant"],
        "source_pins": dict(expected_broker_source_pins),
        **{
            name: grant[name]
            for name in (
                "runtime_profile_digest",
                "sensor_digest",
                "runtime_digest",
                "policy_digest",
                "active_skill_digest",
                "operation_digest",
            )
        },
        "path_digest": pins["path"],
        "payload_digest": pins["payload"],
    }
    binding_raw = canonical_json(binding)
    _require(len(binding_raw) <= 4096, "binding exceeds credential boundary")
    # Read every supplied blob again before writing anything to the staging CAS.
    for digest, raw in retained.items():
        if digest != pins["deployment"]:
            _require(
                source_cas.read(digest, max_bytes=_LIMIT) == raw,
                "plan input left custody",
            )
    retained[canonical_digest(binding)] = binding_raw
    for digest, raw in retained.items():
        _require(
            target_cas.put_expected(
                BytesIO(raw), expected_digest=digest, max_bytes=_LIMIT
            )
            == digest,
            "input staging failed",
        )
    for digest, raw in retained.items():
        _require(
            target_cas.read(digest, max_bytes=_LIMIT) == raw,
            "staged input readback failed",
        )
        if digest not in {pins["deployment"], canonical_digest(binding)}:
            _require(
                source_cas.read(digest, max_bytes=_LIMIT) == raw,
                "source custody changed during staging",
            )
    return {
        "schema": "aragorn/runtime-broker-measurement-prepared-inputs/v1",
        "authority": "CALLER_OWNED_INPUT_STAGING_ONLY_NOT_PROVISIONING_OR_MEASUREMENT",
        "binding": binding,
        "binding_digest": canonical_digest(binding),
        "input_blobs": [
            {"digest": digest, "bytes": len(raw)}
            for digest, raw in sorted(retained.items())
        ],
        "decision": {
            "deployed": False,
            "measurement_collected": False,
            "quantitative_metrics_eligible": False,
            "phase3_exit_eligible": False,
        },
        "limitations": [
            "OPERATOR_PINS_NOT_LIVE_DEPLOYMENT_OR_CLOCK_DOMAIN_ATTESTATION",
            "NO_GRANT_LIVENESS_CHECK_OR_RUNTIME_STATE_RESET",
            "REQUIRES_EXPLICIT_ROOT_CREDENTIAL_AND_BROKER_OWNED_INPUT_INSTALLATION",
            "RAW_PROFILED_SUBMISSION_MUST_BE_RETAINED_SEPARATELY_FOR_RECEIPT_VERIFICATION",
            "NO_UNATTRIBUTED_CONTROL_FULL_REQUEST_LATENCY_RESIDUE_OR_TASK_TIMING",
        ],
    }
