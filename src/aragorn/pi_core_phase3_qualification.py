"""Additive managed-profile composition; not a verifier registry or a live runner.

Every expected pin and callable comes from the operator's independently reviewed
freeze. Inventory shape/source custody cannot prove surface completeness: a pinned
semantic consumer must establish that from retained raw observations. No default
consumer is provided, and absent D2/D3 evidence cannot qualify this profile.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from .phase3_exit_qualification import (
    Phase3ExitQualificationError,
    Phase3SemanticVerifier,
    _digest,
    _pin,
    _qualify_phase3_requirements,
    _result,
    _verify_source,
)
from .phase3_reference_tasks import describe_tasks
from .phase3_quantitative_metrics import build_phase3_measurement_schedule, metrics_implementation_digest


PROFILE = "pi-core-managed-phase3/v1"
MANIFEST_DIGEST = "sha256:1c765fb473f25103fc094b0b379d549af726f4608a90672fd1c211cec2a9e5c5"
_BOUNDARY = "MP1/EXTERNAL_OS_BROKER_AND_OUT_OF_PROCESS_SENSOR"
_MEASUREMENTS = "MP1/MEASUREMENT_SEMANTICS"
_DOCUMENT_LIMIT = 64 * 1024 - 1
_SOURCE_LIMIT = 1024 * 1024
_EVIDENCE_LIMIT = 16 * 1024 * 1024


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Phase3ExitQualificationError(reason)


def _document(raw: bytes) -> dict[str, Any]:
    """Reuse the strict duplicate/integer/canonical parser; documents omit LF."""
    _require(type(raw) is bytes, "managed document must be bytes")
    return load_phase3_exit_gate_manifest_bytes(raw + b"\n")


def _manifest(raw: bytes) -> dict[str, Any]:
    _require(
        type(raw) is bytes and _digest(raw) == MANIFEST_DIGEST,
        "managed manifest differs from the fixed approved contract",
    )
    return load_phase3_exit_gate_manifest_bytes(raw)


def required_pi_core_phase3_evidence_ids(manifest_raw: bytes) -> tuple[str, ...]:
    """Return the fixed 29 MP1 IDs, never IDs supplied by runtime evidence."""
    required = tuple(_manifest(manifest_raw)["requirements"])
    _require(
        len(required) == len(set(required)) == 29
        and all(key.startswith("MP1/") for key in required),
        "managed manifest must retain exactly 29 MP1 requirements",
    )
    return required


def _blob(cas: CAS, pin: str, limit: int) -> bytes:
    raw = cas.read(_pin(pin), max_bytes=limit)
    _require(bool(raw), "managed artifact must be nonempty")
    return raw


def _inventory(raw, pin, deployment_pin, manifest, cas):
    _require(_digest(raw) == _pin(pin), "surface inventory differs from frozen pin")
    inventory = _document(raw)
    _require(
        set(inventory) == {"schema", "profile", "deployment_identity_digest", "sources", "surfaces"}
        and inventory["schema"] == "aragorn/pi-core-managed-surface-inventory/v1"
        and inventory["profile"] == PROFILE
        and inventory["deployment_identity_digest"] == deployment_pin,
        "surface inventory is invalid or from a different deployment",
    )
    sources, surfaces = inventory["sources"], inventory["surfaces"]
    _require(type(sources) is dict and bool(sources), "source-bound inventory is required")
    for path, source_pin in sources.items():
        _require(
            type(path) is str and 0 < len(path) <= 512
            and not PurePosixPath(path).is_absolute()
            and str(PurePosixPath(path)) == path
            and not any(part in {".", ".."} for part in path.split("/")),
            "inventory source path must be a normalized relative identity",
        )
        _blob(cas, source_pin, _SOURCE_LIMIT)
    _require(type(surfaces) is list and bool(surfaces), "surface rows are required")
    ids, entrypoints, groups, covered, used_sources, dispositions = set(), set(), set(), set(), set(), set()
    for row in surfaces:
        _require(
            type(row) is dict and set(row) == {
                "surface_id", "group", "disposition", "entrypoint", "source_paths", "requirements"
            },
            "surface row fields are invalid",
        )
        surface_id, entrypoint = row["surface_id"], row["entrypoint"]
        _require(
            type(surface_id) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", surface_id) is not None
            and surface_id not in ids
            and type(entrypoint) is str and 0 < len(entrypoint) <= 512
            and entrypoint not in entrypoints,
            "duplicate or invalid surface identity",
        )
        _require(
            row["group"] in manifest["surface_groups"]
            and row["disposition"] in {"SUPPORTED", "DENIED"},
            "surface must be supported or denied; N/A is not coverage",
        )
        for field, allowed in (("source_paths", sources), ("requirements", manifest["requirements"])):
            values = row[field]
            _require(
                type(values) is list and bool(values)
                and all(type(value) is str for value in values)
                and len(values) == len(set(values)) and set(values) <= set(allowed),
                "surface source/requirement references are incomplete or duplicated",
            )
        ids.add(surface_id)
        entrypoints.add(entrypoint)
        groups.add(row["group"])
        dispositions.add(row["disposition"])
        covered.update(row["requirements"])
        used_sources.update(row["source_paths"])
    _require(
        groups == set(manifest["surface_groups"])
        and covered == set(manifest["requirements"])
        and used_sources == set(sources)
        and dispositions == {"SUPPORTED", "DENIED"},
        "incomplete source-bound surface inventory",
    )
    return inventory, ids


def _surface_evidence(raw, inventory_pin, deployment_pin, surface_ids, cas):
    evidence = _document(raw)
    _require(
        set(evidence) == {"schema", "surface_inventory_digest", "deployment_identity_digest", "evidence_by_surface"}
        and evidence["schema"] == "aragorn/pi-core-managed-surface-evidence/v1"
        and evidence["surface_inventory_digest"] == inventory_pin
        and evidence["deployment_identity_digest"] == deployment_pin
        and type(evidence["evidence_by_surface"]) is dict
        and set(evidence["evidence_by_surface"]) == surface_ids,
        "surface evidence is incomplete or unbound",
    )
    for pin in evidence["evidence_by_surface"].values():
        _blob(cas, pin, _EVIDENCE_LIMIT)
    return evidence


def _campaign(raw, inventory_pin, deployment_pin, manifest, schedule, reference_source_pin, cas):
    contract = _document(raw)
    _require(
        set(contract) == {
            "schema", "profile", "deployment_identity_digest", "surface_inventory_digest",
            "attempt_operations", "pair_tasks", "task_descriptors", "pair_ordering"
        }
        and contract["schema"] == "aragorn/pi-core-managed-campaign/v1"
        and contract["profile"] == PROFILE
        and contract["deployment_identity_digest"] == deployment_pin
        and contract["surface_inventory_digest"] == inventory_pin
        and contract["pair_ordering"] == "BASELINE_FIRST",
        "managed campaign is invalid or unbound",
    )
    operations, tasks = contract["attempt_operations"], contract["pair_tasks"]
    descriptors = contract["task_descriptors"]
    _require(
        type(operations) is dict and type(tasks) is dict and type(descriptors) is dict
        and all(type(value) is str for value in operations.values())
        and all(type(value) is str for value in tasks.values())
        and Counter(operations.values()) == manifest["attempts"]
        and Counter(tasks.values()) == manifest["pairs"]
        and set(descriptors) == set(manifest["pairs"]),
        "managed campaign requires 25 attempts per operation and 25 pairs per task",
    )
    try:
        attempts, pairs = schedule["attempt_schedule"], schedule["overhead_schedule"]
        _require(set(operations) == set(attempts["attempt_ids"]), "campaign attempt identities differ")
        _require(set(tasks) == set(pairs["pair_bindings"]), "campaign pair identities differ")
        for attempt_id, operation in operations.items():
            expected_family = "EXFILTRATION" if operation in {"HTTP", "DNS"} else "DESTRUCTIVE"
            _require(attempts["attempt_families"][attempt_id] == expected_family, "operation family differs")
        control = attempts["unattributed_negative_control_attempt_id"]
        _require(operations[control] in {"TRUNCATE", "UNLINK"}, "unattributed control must be destructive")
        for task, descriptor_pin in descriptors.items():
            descriptor = _document(_blob(cas, descriptor_pin, _DOCUMENT_LIMIT))
            _require(
                descriptor["module_source_digest"] == reference_source_pin,
                "task source differs from independently reviewed reference implementation",
            )
            source = _blob(cas, descriptor["module_source_digest"], _SOURCE_LIMIT)
            _require(descriptor == describe_tasks(source)[task], "existing reference task descriptor differs")
            _blob(cas, descriptor["input"]["digest"], _SOURCE_LIMIT)
            for pair_id, selected_task in tasks.items():
                if selected_task == task:
                    binding = pairs["pair_bindings"][pair_id]
                    _require(
                        binding["task_digest"] == descriptor_pin
                        and binding["input_digest"] == descriptor["input"]["digest"],
                        "pair does not bind the existing task and equivalent input",
                    )
    except (KeyError, TypeError) as exc:
        raise Phase3ExitQualificationError("managed campaign schedule is incomplete") from exc
    return contract


def qualify_pi_core_phase3_exit(
    *, manifest_raw: bytes, deployment_raw: bytes, expected_deployment_digest: str,
    expected_campaign_contract_digest: str, measurement_schedule: dict[str, Any],
    expected_measurement_schedule_digest: str, expected_metrics_implementation_digest: str,
    expected_reference_task_source_digest: str,
    evidence_by_requirement: dict[str, str], verifiers: dict[str, Phase3SemanticVerifier],
    surface_inventory_raw: bytes, expected_surface_inventory_digest: str,
    surface_evidence_digest: str, surface_verifier: Phase3SemanticVerifier, evidence_cas: CAS,
) -> dict[str, Any]:
    """Compose only the managed profile; all pins/callables are operator inputs.

    The surface consumer must independently compare the frozen source closure to
    supported and denied entrypoints and verify every surface's raw evidence. The
    29 consumers must prove their properties, including consumed-source identity,
    sensor loss accounting, clock validity, actual attempts, and task equivalence.
    Supplying a PASS receipt is not an alternative to these executable consumers.
    """
    manifest = _manifest(manifest_raw)
    required = required_pi_core_phase3_evidence_ids(manifest_raw)
    deployment_pin = _pin(expected_deployment_digest)
    inventory_pin = _pin(expected_surface_inventory_digest)
    reference_source_pin = _pin(expected_reference_task_source_digest)
    _blob(evidence_cas, reference_source_pin, _SOURCE_LIMIT)
    _require(type(surface_inventory_raw) is bytes, "surface inventory bytes required")
    inventory, surface_ids = _inventory(surface_inventory_raw, inventory_pin, deployment_pin, manifest, evidence_cas)
    # Retained inventory lets independent consumers resolve the exact frozen bytes.
    _require(_blob(evidence_cas, inventory_pin, _DOCUMENT_LIMIT) == surface_inventory_raw, "inventory custody differs")
    surface_pin = _pin(surface_evidence_digest)
    surface_raw = _blob(evidence_cas, surface_pin, _DOCUMENT_LIMIT)
    _surface_evidence(surface_raw, inventory_pin, deployment_pin, surface_ids, evidence_cas)
    campaign_pin = _pin(expected_campaign_contract_digest)
    campaign_raw = _blob(evidence_cas, campaign_pin, _DOCUMENT_LIMIT)
    _campaign(campaign_raw, inventory_pin, deployment_pin, manifest, measurement_schedule, reference_source_pin, evidence_cas)
    # Establish core joins before any semantic callback, including the separate
    # surface consumer. The shared composer rechecks these after its callbacks.
    resolve_phase3_deployment_identity(deployment_raw, expected_digest=deployment_pin, evidence_cas=evidence_cas)
    _require(_pin(expected_metrics_implementation_digest) == metrics_implementation_digest(), "metrics implementation differs from frozen pin")
    try:
        attempts = measurement_schedule["attempt_schedule"]
        rebuilt_schedule = build_phase3_measurement_schedule(
            expected_attempt_ids=attempts["attempt_ids"],
            expected_attempt_families=attempts["attempt_families"],
            expected_unattributed_attempt_id=attempts["unattributed_negative_control_attempt_id"],
            expected_overhead_pair_bindings=measurement_schedule["overhead_schedule"]["pair_bindings"],
            expected_gate_manifest_digest=MANIFEST_DIGEST,
            expected_campaign_contract_digest=campaign_pin,
            expected_runtime_identity_digest=deployment_pin,
        )
        _require(
            canonical_json(measurement_schedule) == canonical_json(rebuilt_schedule)
            and _digest(canonical_json(rebuilt_schedule)) == _pin(expected_measurement_schedule_digest),
            "managed schedule differs from frozen pin",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise Phase3ExitQualificationError("managed schedule is invalid") from exc
    # Preflight every explicit semantic consumer before calling any of them.
    for label, mapping in (("evidence", evidence_by_requirement), ("verifiers", verifiers)):
        _require(type(mapping) is dict and set(mapping) == set(required), f"incomplete managed {label}")
    for key in required:
        _blob(evidence_cas, evidence_by_requirement[key], _EVIDENCE_LIMIT)
        _verify_source(verifiers[key])
    surface_verifier_identity = _verify_source(surface_verifier)
    joins = {
        "profile": PROFILE,
        "surface_inventory_digest": inventory_pin,
        "surface_evidence_digest": surface_pin,
        "reference_task_source_digest": reference_source_pin,
    }
    context = {
        **joins, "requirement_id": _BOUNDARY, "verification_scope": "SOURCE_BOUND_SURFACE_COMPLETENESS",
        "evidence_digest": surface_pin, "deployment_identity_digest": deployment_pin,
        "gate_manifest_digest": MANIFEST_DIGEST, "campaign_contract_digest": campaign_pin,
        "measurement_schedule_digest": _pin(expected_measurement_schedule_digest),
    }
    surface_result = _result(surface_verifier.verify(surface_raw, dict(context), CAS(evidence_cas.root, read_only=True)), context)
    _verify_source(surface_verifier)
    result = _qualify_phase3_requirements(
        required=required, gate_manifest_digest=MANIFEST_DIGEST, measurements_id=_MEASUREMENTS,
        deployment_raw=deployment_raw, expected_deployment_digest=deployment_pin,
        expected_campaign_contract_digest=campaign_pin, measurement_schedule=measurement_schedule,
        expected_measurement_schedule_digest=expected_measurement_schedule_digest,
        expected_metrics_implementation_digest=expected_metrics_implementation_digest,
        evidence_by_requirement=evidence_by_requirement, verifiers=verifiers, evidence_cas=evidence_cas,
        extra_context=joins, prerequisite_pass=surface_result["status"] == "PASS",
    )
    if result["decision"]["phase3_exit_eligible"]:
        # The shared metrics parser already established canonical complete samples.
        metrics = json.loads(_blob(evidence_cas, evidence_by_requirement[_MEASUREMENTS], _EVIDENCE_LIMIT))
        baseline = {sample["pair_id"]: sample for sample in metrics["baseline_samples"]}
        for sample in metrics["instrumented_samples"]:
            _require(
                baseline[sample["pair_id"]]["completed_boottime_ns"] <= sample["started_boottime_ns"],
                "managed paired tasks must execute baseline first without overlap",
            )
    # Re-read all managed joins after consumers; CAS presence is not semantic proof.
    _inventory(_blob(evidence_cas, inventory_pin, _DOCUMENT_LIMIT), inventory_pin, deployment_pin, manifest, evidence_cas)
    _surface_evidence(_blob(evidence_cas, surface_pin, _DOCUMENT_LIMIT), inventory_pin, deployment_pin, surface_ids, evidence_cas)
    _campaign(_blob(evidence_cas, campaign_pin, _DOCUMENT_LIMIT), inventory_pin, deployment_pin, manifest, measurement_schedule, reference_source_pin, evidence_cas)
    _verify_source(surface_verifier)
    result.update(
        schema="aragorn/pi-core-managed-phase3-qualification/v1", profile=PROFILE,
        authority="PI_CORE_MANAGED_PHASE3_ONLY_NOT_OPENCLAW_UNIVERSAL_EDR_OR_RELEASE_AUTHORITY",
        surface_inventory_digest=inventory_pin, surface_evidence_digest=surface_pin,
        reference_task_source_digest=reference_source_pin,
        surface_verifier=surface_verifier_identity, surface_verification=surface_result,
        surface_count=len(inventory["surfaces"]),
    )
    result["limitations"].append("SOURCE_BOUND_SURFACE_COMPLETENESS_REQUIRES_INDEPENDENT_SEMANTIC_VERIFICATION")
    return result
