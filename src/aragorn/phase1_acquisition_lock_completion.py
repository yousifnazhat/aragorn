"""Compositional completion gate for bounded Phase 1 acquisition locking."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .cas import CAS
from .oci_worker_protocol import canonical_digest
from .phase1_acquisition_lock_v2 import (
    Phase1AcquisitionLockV2Error,
    verify_phase1_acquisition_lock_milestone_v2,
)
from .protected_recursive_v4_live_archive import (
    ProtectedRecursiveV4LiveArchiveError,
    verify_protected_recursive_v4_live_archive,
)
from .supported_ingress_live_archive import (
    SupportedIngressLiveArchiveError,
    verify_supported_ingress_live_archive,
)

_EXPECTED_HISTORICAL_METRICS = {
    "installed_digest_integrity": {
        "trees": 2,
        "files": 4,
        "mismatches": 0,
        "changed_paths": 1,
        "status": "PASS",
    },
    "static_artifact_capture": {
        "captured": 13,
        "total": 13,
        "percent": 100.0,
        "minimum_percent": 95,
        "status": "PASS",
    },
    "unresolved_required_non_allow": {
        "qualifying": 18,
        "total": 18,
        "allowed_outcomes": ["ERROR", "REVIEW"],
        "observed_outcome": "ERROR",
        "status": "PASS",
    },
}
_EXPECTED_CURRENT_METRICS = {
    "implementation": {
        "source_commit": "c87b82b9b7a4b8465b9958d33d997fd014f49257",
        "package_tree_digest": (
            "sha256:26f93ed9bafb847bd0616b9533cf8d8100a3dadb3980038bba2536699603fb22"
        ),
        "broker_digest": (
            "sha256:377b1a5330cc6b9bea1984917804ee7c59538d53ac5e283a75f3394d438616ff"
        ),
    },
    "installed_trees": 2,
    "installed_files": 4,
    "installed_digest_mismatches": 0,
    "changed_paths": 1,
    "static_references_resolved": 13,
    "static_references_total": 13,
    "minimum_static_reference_resolution_percent": 95,
    "unresolved_required_fail_closed": 18,
    "unresolved_required_total": 18,
    "observed_outcome": "ERROR",
    "status": "PASS",
}
_LIMITATIONS = [
    "SUPPORTED_PROFILE_IS_PUBLIC_GITHUB_EXACT_COMMIT_ONLY",
    "GENERAL_ARCHIVES_PRIVATE_REPOS_LFS_SUBMODULES_AND_DYNAMIC_FETCH_UNSUPPORTED",
    "ONE_BYTE_IDENTICAL_AND_ONE_BYTE_CHANGING_UPDATE_LIVE_SLICE_ONLY",
    "LEGACY_INSTALL_UPDATE_AND_RELEASE_ERROR_CASES_HAVE_NO_RETAINED_CAS",
    "NO_INSTALLER_AUTHORITY",
    "NO_RUNTIME_CONFORMANCE_AUTHORITY",
    "NO_PUBLIC_RELEASE_AUTHORITY",
]


class Phase1AcquisitionLockCompletionError(ValueError):
    """One or more release-pinned Phase 1 completion leaves are untrusted."""


def derive_phase1_acquisition_lock_completion_v3(
    evidence_v2: Mapping[str, Any],
    milestone_v2: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    supported_ingress_archive: str | Path,
    request_v4_archive: str | Path,
) -> dict[str, Any]:
    """Re-verify the three pinned leaves and derive the bounded completion claim."""

    try:
        verify_phase1_acquisition_lock_milestone_v2(
            evidence_v2,
            milestone_v2,
            evidence_cas=evidence_cas,
        )
        if milestone_v2.get(
            "claims"
        ) != _EXPECTED_HISTORICAL_METRICS or milestone_v2.get("decision") != {
            "status": "PASS",
            "acquisition_lock_exit_eligible": True,
            "reason_codes": [],
        }:
            raise Phase1AcquisitionLockCompletionError(
                "historical Phase 1 v2 numerical baseline is not PASS"
            )

        ingress = verify_supported_ingress_live_archive(supported_ingress_archive)
        if ingress.get("qualification") != {
            "status": "PASS",
            "supported_ingress_qualified": True,
            "installer_work_eligible": False,
            "runtime_conformance_qualified": False,
            "public_release_eligible": False,
        }:
            raise Phase1AcquisitionLockCompletionError(
                "supported production ingress is not qualified"
            )
        current_metrics = ingress.get("current_runtime_numerical_gate")
        if current_metrics != _EXPECTED_CURRENT_METRICS:
            raise Phase1AcquisitionLockCompletionError(
                "current c87 production ingress numerical gate is not PASS"
            )
        evidence_coverage = ingress.get("evidence_coverage")
        if evidence_coverage != {
            "fully_replayed_cases": [
                "byte-update-base",
                "byte-update-next",
                "recursive-metrics",
            ],
            "live_summary_only_cases": [
                "install",
                "release-error",
                "update",
            ],
        }:
            raise Phase1AcquisitionLockCompletionError(
                "current c87 evidence coverage is overstated or incomplete"
            )

        request_v4 = verify_protected_recursive_v4_live_archive(request_v4_archive)
        qualification = request_v4.get("qualification", {})
        if (
            request_v4.get("status") != "PASS"
            or qualification.get("automatic_release_pin_custody_qualified") is not True
            or qualification.get("installer_work_eligible") is not False
            or qualification.get("runtime_conformance_qualified") is not False
            or qualification.get("public_release_eligible") is not False
        ):
            raise Phase1AcquisitionLockCompletionError(
                "request-v4 release-pin custody is not qualified"
            )
        ingress_release = ingress.get("cases", {}).get("release-error", {})
        custody_release = request_v4.get("release_error", {})
        release_binding = {
            "request": custody_release.get("request"),
            "release_pin_set_digest": custody_release.get("release_pin_set_digest"),
            "release_asset_result_digests": custody_release.get(
                "release_asset_result_digests"
            ),
        }
        if release_binding != {
            "request": ingress_release.get("source_request"),
            "release_pin_set_digest": ingress_release.get("release_pin_set_digest"),
            "release_asset_result_digests": ingress_release.get(
                "release_asset_result_digests"
            ),
        }:
            raise Phase1AcquisitionLockCompletionError(
                "request-v4 release-pin custody is not bound to the c87 ingress"
            )

        return {
            "schema": "aragorn/phase1-acquisition-lock-completion/v3",
            "scope": "public-github-exact-commit-supported-acquisition/v1",
            "leaf_receipts": {
                "historical_numerical_baseline_v2": canonical_digest(milestone_v2),
                "current_c87_supported_ingress": canonical_digest(ingress),
                "request_v4_release_pin_custody": canonical_digest(request_v4),
            },
            "claims": {
                "current_runtime_numerical_gate": deepcopy(current_metrics),
                "supported_ingress": {
                    "profile": ingress["profile"],
                    "observed_production_path_cases": 6,
                    "fully_replayed_cases": 3,
                    "fully_replayed_successful_cases": 2,
                    "fully_replayed_fail_closed_cases": 1,
                    "live_summary_only_cases": 3,
                    "status": "PASS",
                },
                "request_v4_release_pin_custody": {
                    "automatic_release_pin_custody_qualified": True,
                    "current_runtime_cross_bound": True,
                    **release_binding,
                    "status": "PASS",
                },
            },
            "decision": {
                "status": "PASS",
                "bounded_acquisition_lock_complete": True,
                "installer_work_eligible": False,
                "runtime_conformance_qualified": False,
                "public_release_eligible": False,
            },
            "limitations": deepcopy(_LIMITATIONS),
        }
    except Phase1AcquisitionLockCompletionError:
        raise
    except (
        Phase1AcquisitionLockV2Error,
        SupportedIngressLiveArchiveError,
        ProtectedRecursiveV4LiveArchiveError,
        OSError,
    ) as exc:
        raise Phase1AcquisitionLockCompletionError(
            f"cannot derive Phase 1 acquisition-lock completion: {exc}"
        ) from exc


def verify_phase1_acquisition_lock_completion_v3(
    evidence_v2: Mapping[str, Any],
    milestone_v2: Mapping[str, Any],
    completion_v3: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    supported_ingress_archive: str | Path,
    request_v4_archive: str | Path,
) -> None:
    """Reject caller-supplied completion fields by recomputing every leaf."""

    expected = derive_phase1_acquisition_lock_completion_v3(
        evidence_v2,
        milestone_v2,
        evidence_cas=evidence_cas,
        supported_ingress_archive=supported_ingress_archive,
        request_v4_archive=request_v4_archive,
    )
    if completion_v3 != expected:
        raise Phase1AcquisitionLockCompletionError(
            "Phase 1 v3 completion does not match its derived aggregate"
        )
