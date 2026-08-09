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

_PROFILE = "openclaw-2026.7.1-protected-consumer"
_PROFILE_DIGEST = (
    "sha256:be2f1cec6f70fbc18be19e04556c2b52331cec61405950512e3fcd48ff26c906"
)
_CONFIG_DIGEST = (
    "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6"
)
_QUALIFICATIONS_V1 = {
    "sha256:4c293f05c8464cf37fd88f9119dba61af03df302a7255eb9b284b655faa6fef2": (
        "aragorn/admission-protected-route-qualification/v1",
        "ADM-02/update/workshop-proposal-apply",
        "PASS",
    ),
    "sha256:9256ae1795fe34aaa8b49c1500b29ba024ef1da1873638fb213de311aae2d90e": (
        "aragorn/admission-protected-archive-route-qualification/v1",
        "ADM-02/update/archive-source-force-replacement",
        "PASS",
    ),
    "sha256:e81299d455895e22a3de643789f6d57f5f47ae645c01d6161eed58f7fffd9744": (
        "aragorn/admission-protected-config-route-qualification/v1",
        "ADM-02/update/config-entry-activation",
        "PASS",
    ),
}
_QUALIFICATIONS_V2 = {
    **_QUALIFICATIONS_V1,
    "sha256:481e386a9ca9f1389aa1d21d97b01a86fc89191aac6941ebe486f7d19b58f378": (
        "aragorn/admission-protected-prompt-rebuild-route-qualification/v1",
        "ADM-02/reload/missing-prompt-blob-rebuild",
        "PASS",
    ),
}
_QUALIFICATIONS_V3 = {
    **_QUALIFICATIONS_V2,
    "sha256:203bbbcfc020f0c325001aaeda4b6e9a944d56703ffee600b7561040843096ff": (
        "aragorn/admission-protected-session-snapshot-route-qualification/v1",
        "ADM-02/reload/session-snapshot-consumer",
        "FAIL",
    ),
    "sha256:7ad2cdeb8b79d2be870184106a7992844037f49d78e8b97ae67ac6dbb7c5e052": (
        "aragorn/admission-protected-cron-rescan-route-qualification/v1",
        "ADM-02/reload/cron-rescan",
        "PASS",
    ),
}
_DECISION = {
    "status": "PARTIAL_ROUTE_COVERAGE",
    "aggregate_admission_eligible": False,
    "admission_profile_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
}
_DECISION_V3 = {**_DECISION, "status": "FAIL"}


def compose_openclaw_protected_profile_coverage(
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    route_qualifications: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compose exact pinned route PASSes without aggregate authority."""

    return _compose_openclaw_protected_profile_coverage(
        route_profile,
        route_inventory,
        runtime_candidates,
        route_qualifications,
        qualifications=_QUALIFICATIONS_V1,
        schema="aragorn/admission-protected-profile-route-coverage/v1",
    )


def compose_openclaw_protected_profile_coverage_v2(
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    route_qualifications: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compose four exact route PASSes without aggregate authority."""

    return _compose_openclaw_protected_profile_coverage(
        route_profile,
        route_inventory,
        runtime_candidates,
        route_qualifications,
        qualifications=_QUALIFICATIONS_V2,
        schema="aragorn/admission-protected-profile-route-coverage/v2",
    )


def compose_openclaw_protected_profile_coverage_v3(
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    route_qualifications: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compose five route PASSes and one route FAIL without aggregate authority."""

    return _compose_openclaw_protected_profile_coverage(
        route_profile,
        route_inventory,
        runtime_candidates,
        route_qualifications,
        qualifications=_QUALIFICATIONS_V3,
        schema="aragorn/admission-protected-profile-route-coverage/v3",
        decision=_DECISION_V3,
        limitations=(
            "FIVE_EXACT_ROUTE_PASSES_AND_ONE_EXACT_ROUTE_FAILURE_COMPOSED",
            "KNOWN_EXACT_ROUTE_FAILURE_PREVENTS_AGGREGATE_AUTHORITY",
            "NO_AGGREGATE_ADMISSION_INSTALLER_OR_PHASE3_AUTHORITY",
        ),
    )


def _compose_openclaw_protected_profile_coverage(
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    route_qualifications: Sequence[Mapping[str, Any]],
    *,
    qualifications: Mapping[str, tuple[str, str, str]],
    schema: str,
    decision: Mapping[str, Any] = _DECISION,
    limitations: Sequence[str] | None = None,
) -> dict[str, Any]:
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

    qualified: dict[str, tuple[str, str]] = {}
    try:
        for document in route_qualifications:
            if not isinstance(document, Mapping):
                raise AdmissionEvidenceError("route qualification must be an object")
            digest = canonical_digest(document)
            expected = qualifications.get(digest)
            if expected is None:
                raise AdmissionEvidenceError("unknown or forged route qualification")
            qualification_schema, route_id, expected_status = expected
            if route_id in qualified:
                raise AdmissionEvidenceError("duplicate route qualification")
            if (
                document["schema"] != qualification_schema
                or document["profile"] != _PROFILE
                or document["runtime"] != route_profile["runtime"]
                or document["bindings"]["profile_digest"] != _PROFILE_DIGEST
                or document["bindings"]["configuration_digest"] != _CONFIG_DIGEST
                or document["route"]["id"] != route_id
                or document["route"]["status"] != expected_status
                or document["decision"]
                != {
                    "status": f"ROUTE_{expected_status}",
                    "admission_profile_eligible": False,
                    "installer_work_eligible": False,
                    "phase3_exit_eligible": False,
                }
            ):
                raise AdmissionEvidenceError("route qualification binding changed")
            qualified[route_id] = (digest, expected_status)
    except (KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid route qualification: {exc}") from exc

    if len(qualified) != len(qualifications):
        raise AdmissionEvidenceError("all pinned route qualifications are required")

    route_ids = [
        f"{route['id']}/{path['id']}"
        for route in route_inventory["routes"]
        for path in route["paths"]
    ]
    routes = [
        {
            "id": route_id,
            "status": qualified[route_id][1]
            if route_id in qualified
            else "NOT_TESTED",
            "qualification_digest": qualified[route_id][0]
            if route_id in qualified
            else None,
        }
        for route_id in route_ids
    ]
    pass_count = sum(route["status"] == "PASS" for route in routes)
    fail_count = sum(route["status"] == "FAIL" for route in routes)
    if len(routes) != 21 or len(qualified) != len(qualifications):
        raise AdmissionEvidenceError("protected route coverage count changed")
    counts = {"PASS": pass_count}
    if fail_count:
        counts["FAIL"] = fail_count
    counts["NOT_TESTED"] = 21 - pass_count - fail_count
    if limitations is None:
        count_word = {3: "THREE", 4: "FOUR"}.get(pass_count)
        if count_word is None or fail_count:
            raise AdmissionEvidenceError("unsupported protected route coverage count")
        limitations = (
            f"ONLY_{count_word}_EXACT_ROUTE_QUALIFICATIONS_COMPOSED",
            "NO_AGGREGATE_ADMISSION_INSTALLER_OR_PHASE3_AUTHORITY",
        )

    return {
        "schema": schema,
        "assurance": "EXACT_PINNED_ROUTE_COMPOSITION_ONLY_NOT_AGGREGATE_AUTHORITY",
        "profile": {
            "name": _PROFILE,
            "digest": _PROFILE_DIGEST,
            "runtime": dict(route_profile["runtime"]),
        },
        "route_inventory_canonical_digest": canonical_digest(route_inventory),
        "routes": routes,
        "counts": counts,
        "decision": dict(decision),
        "limitations": list(limitations),
    }
