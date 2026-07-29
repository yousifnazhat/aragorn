"""Semantic route closure for the narrow OpenClaw protected-consumer profile."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .admission_evidence import (
    AdmissionEvidenceError,
    verify_openclaw_restart_evidence,
)
from .admission_routes import validate_openclaw_2026_7_1_route_inventory
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json

_PROFILE_SCHEMA = "aragorn/admission-runtime-profile/v1"
_PROFILE_NAME = "openclaw-2026.7.1-protected-consumer"
_ASSURANCE = "DECLARED_NARROW_PROFILE_SEMANTICALLY_BOUND_TO_RETAINED_ROOT_INVARIANT"
_CONTROLS = {
    "active_skill_source": "exact-allowlisted-protected-bytes",
    "configuration": "read-only",
    "discovery_roots": "read-only",
    "network": "none",
    "plugins": "disabled",
    "runtime_tree": "read-only",
    "skill_watch": "disabled",
    "update_authority": "external-aragorn-broker-only",
}
_LIMITATIONS = [
    "BROKER_TO_RUNTIME_ACTIVATION_NOT_COMPOSED",
    "CONTAINED_PROFILE_HAS_NO_PROVIDER_NETWORK",
    "DOCKER_CONTROL_PLANE_SELF_REPORTED",
    "ROUTE_RESULTS_DERIVED_FROM_SHARED_ROOT_INVARIANT_NOT_ROUTE_BY_ROUTE_EXECUTION",
]
_ROUTE_CONTROLS = {
    "ADM-02/update/archive-source-force-replacement": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/update/clawhub-tracked-replacement": (
        "discovery_roots",
        "network",
        "update_authority",
    ),
    "ADM-02/update/config-entry-activation": (
        "active_skill_source",
        "configuration",
    ),
    "ADM-02/update/core-updater-plugin-replacement": (
        "plugins",
        "runtime_tree",
        "update_authority",
    ),
    "ADM-02/update/curator-restore-activation": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/update/plugin-enable-activation": (
        "configuration",
        "plugins",
    ),
    "ADM-02/update/plugin-force-reinstall": (
        "discovery_roots",
        "plugins",
        "update_authority",
    ),
    "ADM-02/update/plugin-package-skill-replacement": (
        "discovery_roots",
        "plugins",
        "update_authority",
    ),
    "ADM-02/update/workshop-proposal-apply": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/reload/chat-session-snapshot-consumer": ("active_skill_source",),
    "ADM-02/reload/config-invalidation": (
        "active_skill_source",
        "configuration",
    ),
    "ADM-02/reload/cron-rescan": ("active_skill_source",),
    "ADM-02/reload/filesystem-watch-invalidation": (
        "active_skill_source",
        "skill_watch",
    ),
    "ADM-02/reload/fresh-session-reset": ("active_skill_source",),
    "ADM-02/reload/manual-plugin-invalidation": (
        "active_skill_source",
        "plugins",
    ),
    "ADM-02/reload/missing-prompt-blob-rebuild": ("active_skill_source",),
    "ADM-02/reload/plugin-skill-dir-activation": (
        "active_skill_source",
        "plugins",
    ),
    "ADM-02/reload/remote-eligibility-invalidation": (
        "active_skill_source",
        "network",
    ),
    "ADM-02/reload/sandbox-per-run-rescan": ("active_skill_source",),
    "ADM-02/reload/session-snapshot-consumer": ("active_skill_source",),
    "ADM-02/reload/workshop-invalidation": (
        "active_skill_source",
        "discovery_roots",
    ),
}
_RESTART_EVIDENCE = sorted(
    (
        "sha256:e67b2522a705d9f9efbd447da68aae61af6964f51dd9275d2d956688389ebbfa",
        "sha256:f9b08c63b414b0f91b5cc14deeb91a86a8a0b4aa3151e52702395004dde7dcb3",
    )
)


def validate_openclaw_protected_consumer_profile(
    profile: Mapping[str, Any],
    *,
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> None:
    """Validate the exact narrow profile without granting runtime conformance."""

    validate_openclaw_2026_7_1_route_inventory(
        route_inventory,
        runtime_candidates,
    )
    if set(profile) != {
        "assurance",
        "controls",
        "decision",
        "limitations",
        "name",
        "routes",
        "runtime",
        "schema",
    }:
        raise AdmissionEvidenceError("protected-consumer profile shape changed")
    if (
        profile["schema"] != _PROFILE_SCHEMA
        or profile["name"] != _PROFILE_NAME
        or profile["assurance"] != _ASSURANCE
        or profile["controls"] != _CONTROLS
        or profile["limitations"] != _LIMITATIONS
        or profile["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
    ):
        raise AdmissionEvidenceError("protected-consumer profile boundary changed")

    inventory_runtime = route_inventory["runtime"]
    if profile["runtime"] != {
        "commit": inventory_runtime["commit_sha1"],
        "name": "openclaw-contained",
        "source_tree": inventory_runtime["tree_sha1"],
        "version": inventory_runtime["version"],
    }:
        raise AdmissionEvidenceError("protected-consumer runtime binding changed")

    inventory_routes = [
        f"{route['id']}/{path['id']}"
        for route in route_inventory["routes"]
        for path in route["paths"]
    ]
    expected_routes = [
        {
            "controls": list(controls),
            "id": route_id,
            "outcome": (
                "DENIED"
                if route_id.startswith("ADM-02/update/")
                else "PROTECTED_BYTES_ONLY"
            ),
        }
        for route_id, controls in _ROUTE_CONTROLS.items()
    ]
    if inventory_routes != list(_ROUTE_CONTROLS):
        raise AdmissionEvidenceError("protected-consumer inventory coverage changed")
    if profile["routes"] != expected_routes:
        raise AdmissionEvidenceError("protected-consumer route mediation changed")


def verify_openclaw_protected_consumer_routes(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Retain exact route coverage without promoting unexecuted scenarios."""

    validate_openclaw_protected_consumer_profile(
        route_profile,
        route_inventory=route_inventory,
        runtime_candidates=runtime_candidates,
    )
    verify_openclaw_restart_evidence(source_receipt, evidence_cas=evidence_cas)

    runtime = source_receipt["bindings"]["runtime"]
    profile_runtime = route_profile["runtime"]
    if (
        runtime["name"] != profile_runtime["name"]
        or runtime["version"] != profile_runtime["version"]
        or runtime["commit"] != profile_runtime["commit"]
    ):
        raise AdmissionEvidenceError(
            "protected-consumer source receipt runtime changed"
        )

    raw_profile = canonical_json(dict(route_profile)) + b"\n"
    profile_digest = "sha256:" + hashlib.sha256(raw_profile).hexdigest()
    try:
        if evidence_cas.read(profile_digest, max_bytes=128 * 1024) != raw_profile:
            raise AdmissionEvidenceError(
                "retained protected-consumer profile bytes changed"
            )
    except CASError as exc:
        raise AdmissionEvidenceError(
            "protected-consumer profile is not retained"
        ) from exc

    return {
        "evidence_digests": sorted((*_RESTART_EVIDENCE, profile_digest)),
        "installer_work_eligible": False,
        "limitations": list(_LIMITATIONS),
        "profile": _PROFILE_NAME,
        "scenario_statuses": {
            route["id"]: route["status"] for route in route_inventory["routes"]
        },
    }


def load_runtime_profile(raw: bytes) -> dict[str, Any]:
    """Load one profile while rejecting duplicate keys and non-objects."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AdmissionEvidenceError(
                    f"duplicate protected-consumer profile key: {key}"
                )
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                AdmissionEvidenceError(
                    f"invalid protected-consumer JSON constant: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(
            f"protected-consumer profile is invalid JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise AdmissionEvidenceError("protected-consumer profile must be an object")
    return value
