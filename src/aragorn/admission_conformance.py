"""Fail-closed validation for admission-runtime conformance results."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MANDATORY_ADMISSION_SCENARIOS = {
    "DET-01": ("identical-canonical-input-replay",),
    "ADM-01": ("exact-admitted-bytes",),
    "ADM-02": (
        "install",
        "update",
        "direct-write",
        "rename",
        "symlink",
        "auto-discovery",
        "reload",
        "restart",
    ),
    "ADM-03": ("policy-failure", "policy-tampering"),
}
_STATUSES = frozenset({"PASS", "FAIL", "NOT_TESTED"})


class AdmissionConformanceError(ValueError):
    """A conformance result is incomplete or its aggregate decision is forged."""


def validate_admission_conformance(document: Mapping[str, Any]) -> str:
    """Validate scenario coverage and return the derived profile status."""

    if document.get("schema") != "aragorn/admission-conformance-result/v1":
        raise AdmissionConformanceError("admission conformance schema is unsupported")
    properties = document.get("properties")
    if not isinstance(properties, list):
        raise AdmissionConformanceError("properties must be a list")
    property_ids = [
        item.get("id") if isinstance(item, Mapping) else None for item in properties
    ]
    if property_ids != list(MANDATORY_ADMISSION_SCENARIOS):
        raise AdmissionConformanceError(
            "properties must contain every mandatory property in canonical order"
        )

    property_statuses = []
    for item in properties:
        property_id = item["id"]
        scenarios = item.get("scenarios")
        if not isinstance(scenarios, list):
            raise AdmissionConformanceError(f"{property_id} scenarios must be a list")
        scenario_ids = [
            scenario.get("id") if isinstance(scenario, Mapping) else None
            for scenario in scenarios
        ]
        if scenario_ids != list(MANDATORY_ADMISSION_SCENARIOS[property_id]):
            raise AdmissionConformanceError(
                f"{property_id} scenarios do not cover every mandatory path"
            )

        scenario_statuses = []
        for scenario in scenarios:
            label = f"{property_id}/{scenario['id']}"
            status = scenario.get("status")
            if status not in _STATUSES:
                raise AdmissionConformanceError(f"{label} has an invalid status")
            evidence = scenario.get("evidence_digests")
            reasons = scenario.get("reason_codes")
            if not isinstance(evidence, list) or evidence != sorted(set(evidence)):
                raise AdmissionConformanceError(
                    f"{label} evidence digests must be sorted and unique"
                )
            if not isinstance(reasons, list) or reasons != sorted(set(reasons)):
                raise AdmissionConformanceError(
                    f"{label} reason codes must be sorted and unique"
                )
            if status in {"PASS", "FAIL"} and not evidence:
                raise AdmissionConformanceError(f"{label} requires retained evidence")
            if status == "PASS" and reasons:
                raise AdmissionConformanceError(
                    f"{label} PASS cannot contain reason codes"
                )
            if status in {"FAIL", "NOT_TESTED"} and not reasons:
                raise AdmissionConformanceError(f"{label} requires a reason code")
            scenario_statuses.append(status)

        derived_property_status = _aggregate(scenario_statuses)
        if item.get("status") != derived_property_status:
            raise AdmissionConformanceError(
                f"{property_id} status does not match its scenarios"
            )
        property_statuses.append(derived_property_status)

    derived_profile_status = _aggregate(property_statuses)
    decision = document.get("decision")
    if not isinstance(decision, Mapping):
        raise AdmissionConformanceError("decision must be an object")
    if decision.get("status") != derived_profile_status:
        raise AdmissionConformanceError("profile status does not match its properties")
    eligible = derived_profile_status == "PASS"
    if decision.get("installer_work_eligible") is not eligible:
        raise AdmissionConformanceError(
            "installer eligibility does not match the derived profile status"
        )
    return derived_profile_status


def _aggregate(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "NOT_TESTED" in statuses:
        return "NOT_TESTED"
    return "PASS"
