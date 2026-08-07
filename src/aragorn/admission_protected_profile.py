"""Compose retained exact-profile OpenClaw route qualifications."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .admission_evidence import AdmissionEvidenceError
from .admission_routes import AdmissionRouteInventoryError
from .admission_runtime_profile import (
    validate_openclaw_protected_consumer_profile,
)
from .oci_worker_protocol import canonical_digest

_SCHEMA = "aragorn/admission-protected-profile-route-coverage/v1"
_PROFILE = "openclaw-2026.7.1-protected-consumer"
_PROFILE_DIGEST = (
    "sha256:be2f1cec6f70fbc18be19e04556c2b52331cec61405950512e3fcd48ff26c906"
)
_CONFIG_DIGEST = (
    "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6"
)
_QUALIFICATIONS = {
    "sha256:4c293f05c8464cf37fd88f9119dba61af03df302a7255eb9b284b655faa6fef2": (
        "aragorn/admission-protected-route-qualification/v1",
        "ADM-02/update/workshop-proposal-apply",
    ),
    "sha256:9256ae1795fe34aaa8b49c1500b29ba024ef1da1873638fb213de311aae2d90e": (
        "aragorn/admission-protected-archive-route-qualification/v1",
        "ADM-02/update/archive-source-force-replacement",
    ),
}
_DECISION = {
    "status": "PARTIAL_ROUTE_COVERAGE",
    "aggregate_admission_eligible": False,
    "admission_profile_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
}


def compose_openclaw_protected_profile_coverage(
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    route_qualifications: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compose exact pinned route PASSes without aggregate authority."""

    try:
        validate_openclaw_protected_consumer_profile(
            route_profile,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
    except AdmissionRouteInventoryError as exc:
        raise AdmissionEvidenceError(f"invalid route inventory: {exc}") from exc
    if isinstance(route_qualifications, (str, bytes, Mapping)):
        raise AdmissionEvidenceError("route qualifications must be a sequence")

    qualified: dict[str, str] = {}
    try:
        for document in route_qualifications:
            if not isinstance(document, Mapping):
                raise AdmissionEvidenceError("route qualification must be an object")
            digest = canonical_digest(document)
            expected = _QUALIFICATIONS.get(digest)
            if expected is None:
                raise AdmissionEvidenceError("unknown or forged route qualification")
            schema, route_id = expected
            if route_id in qualified:
                raise AdmissionEvidenceError("duplicate route qualification")
            if (
                document["schema"] != schema
                or document["profile"] != _PROFILE
                or document["runtime"] != route_profile["runtime"]
                or document["bindings"]["profile_digest"] != _PROFILE_DIGEST
                or document["bindings"]["configuration_digest"] != _CONFIG_DIGEST
                or document["route"]["id"] != route_id
                or document["route"]["status"] != "PASS"
                or document["decision"]
                != {
                    "status": "ROUTE_PASS",
                    "admission_profile_eligible": False,
                    "installer_work_eligible": False,
                    "phase3_exit_eligible": False,
                }
            ):
                raise AdmissionEvidenceError("route qualification binding changed")
            qualified[route_id] = digest
    except (KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid route qualification: {exc}") from exc

    if len(qualified) != len(_QUALIFICATIONS):
        raise AdmissionEvidenceError("both pinned route qualifications are required")

    route_ids = [
        f"{route['id']}/{path['id']}"
        for route in route_inventory["routes"]
        for path in route["paths"]
    ]
    routes = [
        {
            "id": route_id,
            "status": "PASS" if route_id in qualified else "NOT_TESTED",
            "qualification_digest": qualified.get(route_id),
        }
        for route_id in route_ids
    ]
    if len(routes) != 21 or len(qualified) != 2:
        raise AdmissionEvidenceError("protected route coverage count changed")

    return {
        "schema": _SCHEMA,
        "assurance": "EXACT_PINNED_ROUTE_COMPOSITION_ONLY_NOT_AGGREGATE_AUTHORITY",
        "profile": {
            "name": _PROFILE,
            "digest": _PROFILE_DIGEST,
            "runtime": dict(route_profile["runtime"]),
        },
        "route_inventory_canonical_digest": canonical_digest(route_inventory),
        "routes": routes,
        "counts": {"PASS": 2, "NOT_TESTED": 19},
        "decision": dict(_DECISION),
        "limitations": [
            "ONLY_TWO_EXACT_ROUTE_QUALIFICATIONS_COMPOSED",
            "NO_AGGREGATE_ADMISSION_INSTALLER_OR_PHASE3_AUTHORITY",
        ],
    }
