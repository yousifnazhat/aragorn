"""Fail-closed Phase 1 acquisition-lock milestone aggregation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .admission_conformance import validate_admission_conformance
from .admission_evidence import AdmissionEvidenceError
from .admission_evidence_workshop import (
    verify_openclaw_update_reload_coverage_v3,
)
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json
from .protected_install_transition_replay import (
    ProtectedInstallTransitionReplayError,
    verify_protected_install_transition_replay,
)

_INPUT_KEYS = {"schema", "scope", "workload", "workload_digest"}
_MAX_JSON_BYTES = 8 * 1024 * 1024
_RELEASE_WORKLOAD_JSON = """
{
  "artifacts": [
    {
      "artifact_id": "anthropics-template-install-skill-md",
      "required": true,
      "resolution": "STATICALLY_RESOLVABLE"
    },
    {
      "artifact_id": "anthropics-template-update-skill-md",
      "required": true,
      "resolution": "STATICALLY_RESOLVABLE"
    },
    {
      "artifact_id": "openai-figma-required-references",
      "allowed_outcomes": ["ERROR", "REVIEW"],
      "required": true,
      "resolution": "UNRESOLVED"
    }
  ],
  "installed_checks": [
    {
      "check_id": "protected-install-skill",
      "expected_digest": "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa",
      "operation": "install"
    },
    {
      "check_id": "protected-update-skill",
      "expected_digest": "sha256:8c62d28fbc672785c57b8d996bbc2568eabc3adda434ee13f3341cebf33b95d8",
      "operation": "update"
    }
  ],
  "leaf_digests": {
    "protected_transition": {
      "archive": "sha256:738a57537a9c1ad24736f0cb5a3ce9507debb830f632ec4e7606d09ee6302aec",
      "capture": "sha256:85f043ce3b49711251129d877996f0e6e7d31c09da56b46af50704d98d4867dd",
      "consumed": "sha256:94faa277bb26b623899c75e927ad488b189b95b5b29cbcaec3fa9b6001d75a3d",
      "install": "sha256:71bfaa2318576443841ee7b6de097ba0df07c19ad1be22d42bed39c058fb0d04",
      "stale": "sha256:e7d1a12400fbe2cdb8337018c6db26ad129ea8b876a4dbd432b50ca723e9356a",
      "update": "sha256:42e0cf87abb76f4a3c65c7f97c2c5d89a9c277ee5a0772da86300da292473a9c"
    },
    "runtime_conformance": {
      "receipt": "sha256:dd681d09043c4582dcc198db91f0784f4e8fc33eea7dd0113abac397ad62987e",
      "route_inventory": "sha256:406a3d3b6d33bff924bbc658e62d7f3c563f36acc1fd354388969ef9001a2df7",
      "runtime_candidates": "sha256:1e8ad12c57e0414b83c1a28612f8c67e1c0d9ea03d19403d8f2dc6b6887ab6b8"
    },
    "unresolved_required": {
      "evidence": "sha256:53c63ec7da8252ce51a130af0405896d9b311f3da727fc1174d667d9719cb78f",
      "retention": "sha256:dfd4967294efec67e616d970cb11554793b0eb048a7a709f0597cfc6c6ee0cbb"
    }
  },
  "schema": "aragorn/phase1-acquisition-lock-workload/v1",
  "thresholds": {
    "installed_digest_mismatches": 0,
    "static_capture_minimum_percent": 95,
    "unresolved_allowed_outcomes": ["ERROR", "REVIEW"],
    "unresolved_required_percent": 100
  },
  "workload_id": "phase1-retained-evidence-2026-07-29"
}
"""


class Phase1AcquisitionLockError(ValueError):
    """Phase 1 evidence is malformed, untrusted, or inconsistent."""


def phase1_acquisition_lock_workload() -> dict[str, Any]:
    """Return a fresh copy of the release-owned Phase 1 workload."""

    return json.loads(_RELEASE_WORKLOAD_JSON)


PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST = canonical_digest(
    phase1_acquisition_lock_workload()
)


def derive_phase1_acquisition_lock_milestone(
    evidence: Mapping[str, Any],
    *,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Re-verify release-pinned leaves and derive an honest Phase 1 receipt."""

    _validate_envelope(evidence)
    if not evidence_cas.read_only:
        raise Phase1AcquisitionLockError("Phase 1 evidence CAS must be read-only")

    workload = phase1_acquisition_lock_workload()
    leaves = workload["leaf_digests"]
    transition, transition_status = _verify_transition(
        evidence_cas,
        leaves["protected_transition"],
    )
    runtime_status = _verify_runtime(
        evidence_cas,
        leaves["runtime_conformance"],
    )
    unresolved_outcomes, unresolved_status = _verify_unresolved(
        evidence_cas,
        leaves["unresolved_required"],
    )

    installed = _installed_claim(workload, transition, transition_status)
    static = _static_claim(workload)
    unresolved = _unresolved_claim(
        workload,
        unresolved_outcomes,
        unresolved_status,
    )
    replay = _replay_claim(leaves["protected_transition"], transition_status)
    statuses = [
        installed["status"],
        static["status"],
        unresolved["status"],
        runtime_status,
        *(item["status"] for item in replay.values()),
    ]
    decision_status = _aggregate_status(statuses)
    reasons = sorted(
        {
            {
                "installed_digest_integrity": "INSTALLED_DIGEST_INTEGRITY_INCOMPLETE",
                "static_artifact_capture": "STATIC_ARTIFACT_CAPTURE_INCOMPLETE",
                "unresolved_required_non_allow": "UNRESOLVED_REQUIRED_EVIDENCE_INELIGIBLE",
                "runtime_conformance": "RUNTIME_CONFORMANCE_NOT_PASS",
                "supported_install_replay": "SUPPORTED_INSTALL_REPLAY_INELIGIBLE",
                "supported_update_replay": "SUPPORTED_UPDATE_REPLAY_INELIGIBLE",
            }[label]
            for label, status in (
                ("installed_digest_integrity", installed["status"]),
                ("static_artifact_capture", static["status"]),
                ("unresolved_required_non_allow", unresolved["status"]),
                ("runtime_conformance", runtime_status),
                ("supported_install_replay", replay["install"]["status"]),
                ("supported_update_replay", replay["update"]["status"]),
            )
            if status != "PASS"
        }
    )

    return {
        "schema": "aragorn/phase1-acquisition-lock-milestone/v1",
        "source_evidence_digest": canonical_digest(evidence),
        "workload_digest": PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST,
        "claims": {
            "installed_digest_integrity": installed,
            "static_artifact_capture": static,
            "unresolved_required_non_allow": unresolved,
            "runtime_conformance": {
                "result_digest": leaves["runtime_conformance"]["receipt"],
                "status": runtime_status,
            },
            "supported_replay": replay,
        },
        "decision": {
            "status": decision_status,
            "phase1_exit_eligible": decision_status == "PASS",
            "reason_codes": reasons,
        },
    }


def verify_phase1_acquisition_lock_milestone(
    evidence: Mapping[str, Any],
    milestone: Mapping[str, Any],
    *,
    evidence_cas: CAS,
) -> None:
    """Reject a milestone whose aggregate differs from re-verified evidence."""

    expected = derive_phase1_acquisition_lock_milestone(
        evidence,
        evidence_cas=evidence_cas,
    )
    if milestone != expected:
        raise Phase1AcquisitionLockError(
            "Phase 1 milestone does not match its derived aggregate"
        )


def _validate_envelope(evidence: Mapping[str, Any]) -> None:
    if not isinstance(evidence, Mapping) or set(evidence) != _INPUT_KEYS:
        raise Phase1AcquisitionLockError(
            "Phase 1 evidence fields are incomplete or unknown"
        )
    if evidence["schema"] != "aragorn/phase1-acquisition-lock-evidence/v1":
        raise Phase1AcquisitionLockError("unsupported Phase 1 evidence schema")
    if evidence["scope"] != "supported-acquisition-lock/v1":
        raise Phase1AcquisitionLockError("unsupported Phase 1 evidence scope")
    workload = phase1_acquisition_lock_workload()
    if evidence["workload"] != workload:
        raise Phase1AcquisitionLockError("Phase 1 workload is not release-owned")
    if (
        evidence["workload_digest"] != PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST
        or canonical_digest(evidence["workload"]) != evidence["workload_digest"]
    ):
        raise Phase1AcquisitionLockError("Phase 1 workload digest does not match")


def _verify_transition(
    cas: CAS,
    digests: Mapping[str, str],
) -> tuple[dict[str, Any] | None, str]:
    names = ("archive", "install", "update", "consumed", "stale", "capture")
    try:
        with TemporaryDirectory(prefix="aragorn-phase1-aggregate-") as temporary:
            root = Path(temporary)
            paths = {
                name: cas.materialize(digests[name], root / name, root=root)
                for name in names
            }
            result = verify_protected_install_transition_replay(
                paths["archive"],
                paths["install"],
                paths["update"],
                paths["consumed"],
                paths["stale"],
                paths["capture"],
            )
    except CASError:
        return None, "NOT_TESTED"
    except (OSError, ProtectedInstallTransitionReplayError):
        return None, "FAIL"
    return result, "PASS" if result["phase1_exit_eligible"] else "EVIDENCE_ONLY"


def _verify_runtime(cas: CAS, digests: Mapping[str, str]) -> str:
    try:
        receipt = _read_document(cas, digests["receipt"], canonical=True)
        inventory = _read_document(cas, digests["route_inventory"], canonical=False)
        candidates = _read_document(
            cas,
            digests["runtime_candidates"],
            canonical=False,
        )
        verify_openclaw_update_reload_coverage_v3(
            receipt,
            evidence_cas=cas,
            route_inventory=inventory,
            runtime_candidates=candidates,
        )
        return validate_admission_conformance(receipt)
    except CASError:
        return "NOT_TESTED"
    except (AdmissionEvidenceError, Phase1AcquisitionLockError):
        return "FAIL"


def _verify_unresolved(
    cas: CAS,
    digests: Mapping[str, str],
) -> tuple[list[str], str]:
    try:
        evidence = _read_document(cas, digests["evidence"], canonical=True)
        retention = _read_document(cas, digests["retention"], canonical=True)
        evidence_binding = retention["evidence"]["negative"]
        observation = retention["negative"]
        if (
            evidence.get("schema")
            != "aragorn/openclaw-github-protected-install-broker-evidence/v1"
            or evidence.get("slice_status") not in {"ERROR", "REVIEW"}
            or retention.get("schema")
            != "aragorn/phase1-agent-skill-protected-install-live-retention/v1"
            or retention.get("phase1_exit_eligible") is not False
            or evidence_binding.get("file_digest") != digests["evidence"]
            or observation.get("closure_status") != "incomplete"
            or not isinstance(observation.get("unresolved_count"), int)
            or observation["unresolved_count"] < 1
            or observation.get("result", {}).get("slice_status")
            != evidence["slice_status"]
        ):
            return [], "FAIL"
        # Exact historical bytes are retained, but no semantic verifier grants
        # them Phase 1 exit authority.
        return [evidence["slice_status"]], "EVIDENCE_ONLY"
    except (CASError, KeyError, TypeError):
        return [], "NOT_TESTED"
    except Phase1AcquisitionLockError:
        return [], "FAIL"


def _installed_claim(
    workload: Mapping[str, Any],
    transition: Mapping[str, Any] | None,
    transition_status: str,
) -> dict[str, Any]:
    if transition is None:
        return {"checked": 0, "mismatches": 0, "status": transition_status}
    mismatches = sum(
        transition["installed"][item["operation"]]["skill_digest"]
        != item["expected_digest"]
        for item in workload["installed_checks"]
    )
    status = transition_status
    if transition_status == "PASS":
        status = "PASS" if not mismatches else "FAIL"
    return {
        "checked": len(workload["installed_checks"]),
        "mismatches": mismatches,
        "status": status,
    }


def _static_claim(workload: Mapping[str, Any]) -> dict[str, Any]:
    static = [
        item
        for item in workload["artifacts"]
        if item["resolution"] == "STATICALLY_RESOLVABLE"
    ]
    return {
        "captured": 0,
        "total": len(static),
        "minimum_percent": workload["thresholds"][
            "static_capture_minimum_percent"
        ],
        "status": "NOT_TESTED",
    }


def _unresolved_claim(
    workload: Mapping[str, Any],
    outcomes: list[str],
    evidence_status: str,
) -> dict[str, Any]:
    unresolved = [
        item
        for item in workload["artifacts"]
        if item["required"] and item["resolution"] == "UNRESOLVED"
    ]
    allowed = workload["thresholds"]["unresolved_allowed_outcomes"]
    qualifying = sum(outcome in allowed for outcome in outcomes)
    status = evidence_status
    if evidence_status == "PASS":
        status = "PASS" if qualifying == len(unresolved) else "FAIL"
    return {
        "qualifying": qualifying if evidence_status == "PASS" else 0,
        "total": len(unresolved),
        "required_percent": workload["thresholds"][
            "unresolved_required_percent"
        ],
        "allowed_outcomes": allowed,
        "observed_outcomes": outcomes,
        "status": status,
    }


def _replay_claim(
    digests: Mapping[str, str],
    status: str,
) -> dict[str, dict[str, str]]:
    return {
        operation: {
            "status": status,
            "evidence_digest": digests[operation],
        }
        for operation in ("install", "update")
    }


def _aggregate_status(statuses: list[str]) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if all(status == "PASS" for status in statuses):
        return "PASS"
    return "NOT_TESTED"


def _read_document(cas: CAS, digest: str, *, canonical: bool) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_JSON_BYTES)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise Phase1AcquisitionLockError(
                    f"duplicate Phase 1 leaf key: {key}"
                )
            result[key] = value
        return result

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                Phase1AcquisitionLockError(
                    f"invalid Phase 1 leaf JSON constant: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Phase1AcquisitionLockError(
            f"Phase 1 leaf is invalid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise Phase1AcquisitionLockError("Phase 1 leaf must be an object")
    if canonical and canonical_json(document) + b"\n" != raw:
        raise Phase1AcquisitionLockError(
            "Phase 1 leaf is not canonical JSON plus LF"
        )
    return document
