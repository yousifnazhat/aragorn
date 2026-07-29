"""Release-pinned semantic Phase 1 acquisition-lock aggregation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .cas import CAS, CASError
from .github_recursive_live_archive import (
    GitHubRecursiveLiveArchiveError,
    verify_github_recursive_live_archive,
)
from .oci_worker_protocol import canonical_digest
from .protected_transition_live_archive import (
    ProtectedTransitionLiveArchiveError,
    verify_protected_transition_live_archive,
)

_RECURSIVE_ARCHIVE = (
    "sha256:5c1465dde68a3e40c6d97790809ae24bed9c0320efb3b934fe853a46b0abc292"
)
_RECURSIVE_INVENTORY = (
    "sha256:5ba46a3f1278e7573158022b385b1a233cdd5e451e41c8f6d3e4932eb7effb2c"
)
_TRANSITION_ARCHIVE = (
    "sha256:3754f7ae4787ced43351ec0d2c696062f563e60543c381f769b86339823a5ac7"
)
_RECURSIVE_ARCHIVE_NAME = (
    "phase1-github-recursive-anthropics-claude-plugins-"
    "hook-development-6b708ace-2026-07-29.tar.gz"
)
_RELEASE_WORKLOAD = {
    "schema": "aragorn/phase1-acquisition-lock-workload/v2",
    "leaf_digests": {
        "recursive": {
            "archive": _RECURSIVE_ARCHIVE,
            "inventory": _RECURSIVE_INVENTORY,
        },
        "protected_transition": {"archive": _TRANSITION_ARCHIVE},
    },
    "recursive_request": {
        "schema": "aragorn/github-gateway-request/v1",
        "owner": "anthropics",
        "repository": "claude-plugins-official",
        "commit": "6b708ace50a2a9869c3d21ca7df2b04defc82f2b",
        "skill_path": "plugins/plugin-dev/skills/hook-development",
    },
    "thresholds": {
        "installed_trees": 2,
        "installed_files": 4,
        "tree_mismatches": 0,
        "static_captured": 13,
        "static_total": 13,
        "static_minimum_percent": 95,
        "unresolved_required": 18,
        "unresolved_allowed_outcomes": ["ERROR", "REVIEW"],
    },
}
_ENVELOPE_KEYS = {"schema", "scope", "leaf_digests", "workload_digest"}


class Phase1AcquisitionLockV2Error(ValueError):
    """The v2 evidence envelope or aggregate is untrusted."""


class _MissingLeaf(Exception):
    pass


class _InvalidLeaf(Exception):
    pass


def phase1_acquisition_lock_workload_v2() -> dict[str, Any]:
    """Return an independent copy of the release-owned workload."""

    return deepcopy(_RELEASE_WORKLOAD)


PHASE1_ACQUISITION_LOCK_WORKLOAD_V2_DIGEST = canonical_digest(
    phase1_acquisition_lock_workload_v2()
)


def derive_phase1_acquisition_lock_milestone_v2(
    evidence: Mapping[str, Any],
    *,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Re-verify every pinned leaf and derive the three v2 claims."""

    _validate_envelope(evidence)
    if not evidence_cas.read_only:
        raise Phase1AcquisitionLockV2Error("Phase 1 v2 evidence CAS must be read-only")

    recursive, recursive_status = _recursive_leaf(evidence_cas)
    transition, transition_status = _transition_leaf(evidence_cas)
    installed = _installed_claim(transition, transition_status)
    static = _static_claim(recursive, recursive_status)
    unresolved = _unresolved_claim(recursive, recursive_status)
    claims = {
        "installed_digest_integrity": installed,
        "static_artifact_capture": static,
        "unresolved_required_non_allow": unresolved,
    }
    decision_status = _aggregate([claim["status"] for claim in claims.values()])
    return {
        "schema": "aragorn/phase1-acquisition-lock-milestone/v2",
        "source_evidence_digest": canonical_digest(evidence),
        "workload_digest": PHASE1_ACQUISITION_LOCK_WORKLOAD_V2_DIGEST,
        "claims": claims,
        "decision": {
            "status": decision_status,
            "acquisition_lock_exit_eligible": decision_status == "PASS",
            "reason_codes": [
                {
                    "installed_digest_integrity": (
                        "INSTALLED_DIGEST_INTEGRITY_NOT_PASS"
                    ),
                    "static_artifact_capture": ("STATIC_ARTIFACT_CAPTURE_NOT_PASS"),
                    "unresolved_required_non_allow": (
                        "UNRESOLVED_REQUIRED_NON_ALLOW_NOT_PASS"
                    ),
                }[name]
                for name, claim in claims.items()
                if claim["status"] != "PASS"
            ],
        },
    }


def verify_phase1_acquisition_lock_milestone_v2(
    evidence: Mapping[str, Any],
    milestone: Mapping[str, Any],
    *,
    evidence_cas: CAS,
) -> None:
    """Reject caller-supplied aggregate fields by recomputing the milestone."""

    expected = derive_phase1_acquisition_lock_milestone_v2(
        evidence,
        evidence_cas=evidence_cas,
    )
    if milestone != expected:
        raise Phase1AcquisitionLockV2Error(
            "Phase 1 v2 milestone does not match its derived aggregate"
        )


def _validate_envelope(evidence: Mapping[str, Any]) -> None:
    workload = phase1_acquisition_lock_workload_v2()
    if (
        not isinstance(evidence, Mapping)
        or set(evidence) != _ENVELOPE_KEYS
        or evidence.get("schema") != "aragorn/phase1-acquisition-lock-evidence/v2"
        or evidence.get("scope") != "supported-acquisition-lock/v2"
        or evidence.get("leaf_digests") != workload["leaf_digests"]
        or evidence.get("workload_digest") != PHASE1_ACQUISITION_LOCK_WORKLOAD_V2_DIGEST
    ):
        raise Phase1AcquisitionLockV2Error(
            "Phase 1 v2 evidence is not the release-owned envelope"
        )


def _recursive_leaf(cas: CAS) -> tuple[dict[str, Any] | None, str]:
    leaves = _RELEASE_WORKLOAD["leaf_digests"]["recursive"]
    with TemporaryDirectory(prefix="aragorn-phase1-v2-recursive-") as temporary:
        root = Path(temporary)
        paths, status = _materialize(
            cas,
            {
                "archive": (
                    leaves["archive"],
                    root / _RECURSIVE_ARCHIVE_NAME,
                ),
                "inventory": (
                    leaves["inventory"],
                    root / "inventory.json",
                ),
            },
            root,
        )
        if status != "PASS":
            return None, status
        try:
            return (
                verify_github_recursive_live_archive(
                    paths["archive"],
                    expected_archive_digest=leaves["archive"],
                    inventory_path=paths["inventory"],
                    expected_inventory_digest=leaves["inventory"],
                    expected_request=_RELEASE_WORKLOAD["recursive_request"],
                ),
                "PASS",
            )
        except (GitHubRecursiveLiveArchiveError, OSError):
            return None, "FAIL"


def _transition_leaf(cas: CAS) -> tuple[dict[str, Any] | None, str]:
    digest = _RELEASE_WORKLOAD["leaf_digests"]["protected_transition"]["archive"]
    with TemporaryDirectory(prefix="aragorn-phase1-v2-transition-") as temporary:
        root = Path(temporary)
        paths, status = _materialize(
            cas,
            {"archive": (digest, root / "transition.tar.gz")},
            root,
        )
        if status != "PASS":
            return None, status
        try:
            return (
                verify_protected_transition_live_archive(
                    paths["archive"],
                    expected_archive_digest=digest,
                ),
                "PASS",
            )
        except (ProtectedTransitionLiveArchiveError, OSError):
            return None, "FAIL"


def _materialize(
    cas: CAS,
    leaves: dict[str, tuple[str, Path]],
    root: Path,
) -> tuple[dict[str, Path], str]:
    paths: dict[str, Path] = {}
    missing = False
    for name, (digest, destination) in leaves.items():
        try:
            paths[name] = _materialize_leaf(cas, digest, destination, root)
        except _MissingLeaf:
            missing = True
        except _InvalidLeaf:
            return {}, "FAIL"
    return ({}, "NOT_TESTED") if missing else (paths, "PASS")


def _materialize_leaf(
    cas: CAS,
    digest: str,
    destination: Path,
    root: Path,
) -> Path:
    value = digest.removeprefix("sha256:")
    blob = cas.root / "blobs" / "sha256" / value[:2] / value[2:]
    try:
        os.lstat(blob)
    except FileNotFoundError as exc:
        raise _MissingLeaf from exc
    except OSError as exc:
        raise _InvalidLeaf from exc
    try:
        return cas.materialize(digest, destination, root=root)
    except CASError as exc:
        raise _InvalidLeaf from exc


def _installed_claim(
    replay: dict[str, Any] | None,
    leaf_status: str,
) -> dict[str, Any]:
    if replay is None:
        return {
            "trees": 0,
            "files": 0,
            "mismatches": 0,
            "changed_paths": 0,
            "status": leaf_status,
        }
    thresholds = _RELEASE_WORKLOAD["thresholds"]
    trees = 2
    files = sum(
        replay[label]["installed_file_count"] for label in ("install", "update")
    )
    mismatches = replay["transition"]["tree_mismatches"]
    changed = sum(
        len(replay["transition"][field])
        for field in ("added_paths", "removed_paths", "changed_paths")
    )
    passed = (
        trees == thresholds["installed_trees"]
        and files == thresholds["installed_files"]
        and mismatches == thresholds["tree_mismatches"]
        and changed > 0
        and replay["transition"]["byte_changing"] is True
    )
    return {
        "trees": trees,
        "files": files,
        "mismatches": mismatches,
        "changed_paths": changed,
        "status": "PASS" if passed else "FAIL",
    }


def _static_claim(
    replay: dict[str, Any] | None,
    leaf_status: str,
) -> dict[str, Any]:
    minimum = _RELEASE_WORKLOAD["thresholds"]["static_minimum_percent"]
    if replay is None:
        return {
            "captured": 0,
            "total": 0,
            "percent": None,
            "minimum_percent": minimum,
            "status": leaf_status,
        }
    captured, total = replay["static_captured"], replay["static_total"]
    percent = None if not total else 100.0 * captured / total
    passed = (
        captured == _RELEASE_WORKLOAD["thresholds"]["static_captured"]
        and total == _RELEASE_WORKLOAD["thresholds"]["static_total"]
        and percent is not None
        and percent >= minimum
    )
    return {
        "captured": captured,
        "total": total,
        "percent": percent,
        "minimum_percent": minimum,
        "status": "PASS" if passed else "FAIL",
    }


def _unresolved_claim(
    replay: dict[str, Any] | None,
    leaf_status: str,
) -> dict[str, Any]:
    thresholds = _RELEASE_WORKLOAD["thresholds"]
    allowed = thresholds["unresolved_allowed_outcomes"]
    if replay is None:
        return {
            "qualifying": 0,
            "total": 0,
            "allowed_outcomes": allowed,
            "observed_outcome": None,
            "status": leaf_status,
        }
    total = len(replay["unresolved"])
    outcome = replay["outcome"]
    qualifying = (
        total if outcome in allowed and replay["allow_possible"] is False else 0
    )
    return {
        "qualifying": qualifying,
        "total": total,
        "allowed_outcomes": allowed,
        "observed_outcome": outcome,
        "status": (
            "PASS"
            if total == thresholds["unresolved_required"] and qualifying == total
            else "FAIL"
        ),
    }


def _aggregate(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    return "PASS" if statuses and set(statuses) == {"PASS"} else "NOT_TESTED"
