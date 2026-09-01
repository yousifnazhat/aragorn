"""Qualify the V3 workshop invalidation subsequence from a shared capture."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v3_workshop_proposal_apply as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/workshop-invalidation"
_SOURCE_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"

_PARENT_SOURCE = {
    "commit": "c823ae2ae05f3b919c2e391a6852b8f8bafa1046",
    "parent": "01e4bff5b406087a70e784436e0e8909eefded8a",
    "tree": "cbaab758aa381de4e0367ba8917e71aadbf07cb3",
}
_PARENT_MODULE = {
    "blob": "b65996bee83f182270fee8425d798a468044e592",
    "bytes": 84_088,
    "digest": "sha256:6e43aef6ca014100e5c192d414c3616528c2004195e20cb90fc9cd22f2c5cad8",
    "path": (
        "src/aragorn/admission_protected_final_combined_v3_workshop_proposal_apply.py"
    ),
}
_PARENT_RECEIPT = {
    "blob": "2428339fe8b2cd6ec2eb646657833d01e78bef5d",
    "bytes": 10_583,
    "digest": "sha256:81f90c85a5c8bae8b0bcb6a4ec0bf737337ce9bb3dd506d7a9354da0144eb82d",
    "path": (
        "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
        "workshop-proposal-apply-route-coverage-v1-2026-08-28.json"
    ),
}
_PARENT_RESULT_DIGEST = (
    "sha256:e1c47a4e1dc966b2d61ecb7e525a223df1d9de1f31f019cf9dcc9726209837dd"
)


def verify_openclaw_final_combined_v3_workshop_invalidation(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return only the shared-capture V3 workshop invalidation PASS."""

    try:
        signed_parent = _verify_parent_source()
        qualification = (
            parent.verify_openclaw_final_combined_v3_workshop_proposal_apply(
                evidence_cas=evidence_cas
            )
        )
        _verify_parent_result(qualification, signed_parent)
        raw = parent.v3_contract.contract._read_blob(
            evidence_cas, parent._EVIDENCE, "V3 shared workshop invalidation"
        )
        evidence = parent.v3_contract.contract._load_canonical_json(
            raw, parent._EVIDENCE, "V3 shared workshop invalidation"
        )
        _verify_reload_bridge(evidence)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 shared workshop invalidation evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] == _ROUTE else "NOT_TESTED",
        }
        for item in qualification["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v3-workshop-"
            "invalidation-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_V3_WORKSHOP_"
            "INVALIDATION_ROUTE_FROM_SHARED_CAPTURE_ONLY"
        ),
        "bindings": {
            "configuration": dict(qualification["bindings"]["configuration"]),
            "image": qualification["bindings"]["image"],
            "parent_qualification_canonical_digest": _PARENT_RESULT_DIGEST,
            "parent_receipt": dict(_PARENT_RECEIPT),
            "parent_verifier": {
                **_PARENT_SOURCE,
                "digest": _PARENT_MODULE["digest"],
                "path": _PARENT_MODULE["path"],
            },
            "profile": dict(qualification["bindings"]["profile"]),
            "runtime_lock": dict(qualification["bindings"]["runtime_lock"]),
            "shared_capture": {
                "capture_relationship": (
                    "SHARED_WITH_WORKSHOP_PROPOSAL_APPLY_NOT_INDEPENDENT_CAPTURE"
                ),
                "source_route": _SOURCE_ROUTE,
            },
            "skill": dict(qualification["bindings"]["skill"]),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_proposal_apply_observation": dict(
                qualification["bindings"]["workshop_proposal_apply_observation"]
            ),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in parent.v3_contract.contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_WORKSHOP_INVALIDATION_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "NO_NATIVE_INDEPENDENT_WORKSHOP_INVALIDATION_ROUTE_EXECUTION",
            "RAW_CAPTURE_ROUTE_ID_REMAINS_WORKSHOP_PROPOSAL_APPLY",
            "PARENT_UPDATE_ROUTE_PASS_IS_VALIDATION_BASIS_NOT_COMPOSED_AS_SECOND_PASS",
            "ONE_POST_APPLY_NEXT_SAME_SESSION_PROTECTED_SNAPSHOT_AND_STORE_TRANSITION_ONLY",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NEXT_SAME_SESSION_TURN_FAILED_WITH_NETWORK_ERROR_NO_MODEL_REPLY_OR_DELIVERY_CLAIM",
            "NO_MODEL_PROVIDER_REQUEST_OR_SUCCESS_CLAIM",
            "FINAL_SKILLS_STATUS_IS_EXTERNAL_AUTHORITY_DENIAL_NOT_SUCCESSFUL_CATALOG_RESPONSE",
            "NO_CATALOG_AVAILABILITY_OR_WORKSHOP_DISCOVERY_CLAIM",
            "WORKSHOP_RESIDUE_PERSISTS_THROUGH_FINAL_OBSERVATION",
            "NO_PRE_EFFECT_NO_MUTATION_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            "STORE_TRANSITION_CHRONOLOGY_USES_SESSION_ENTRY_UPDATED_AT_NO_FILE_MTIME_RETAINED",
            "SESSION_STORE_AND_PROMPT_RAW_BYTES_NOT_RETAINED",
            "APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "native_independent_route_execution": False,
            "pass_basis": (
                "SIGNED_EXACT_CURRENT_V3_POST_APPLY_NEXT_SAME_SESSION_"
                "PROTECTED_SNAPSHOT_AND_STORE_TRANSITION"
            ),
            "shared_capture_independent": False,
            "source_capture_route": _SOURCE_ROUTE,
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(qualification["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_parent_source() -> Mapping[str, Any]:
    module_path = Path(parent.__file__).resolve(strict=True)
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.v3_contract.config.base.legacy._git
    if (
        module_path != (root / _PARENT_MODULE["path"]).resolve(strict=True)
        or module_path.stat().st_size != _PARENT_MODULE["bytes"]
        or _digest(module_path.read_bytes()) != _PARENT_MODULE["digest"]
        or Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 workshop invalidation parent changed")
    parent.v3_contract.config.base._verify_commit(_PARENT_SOURCE)
    signed: dict[str, bytes] = {}
    for identity in (_PARENT_MODULE, _PARENT_RECEIPT):
        entry = git(
            [
                "ls-tree",
                "-z",
                "--full-name",
                _PARENT_SOURCE["commit"],
                "--",
                identity["path"],
            ]
        )
        expected = (
            f"100644 blob {identity['blob']}\t{identity['path']}".encode() + b"\0"
        )
        if entry != expected:
            raise AdmissionEvidenceError(
                "V3 workshop invalidation signed parent tree changed"
            )
        raw = git(
            ["cat-file", "blob", identity["blob"]],
            maximum=int(identity["bytes"]) + 1,
        )
        oid = hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest()
        if (
            oid != identity["blob"]
            or len(raw) != identity["bytes"]
            or raw != (root / identity["path"]).read_bytes()
            or _digest(raw) != identity["digest"]
        ):
            raise AdmissionEvidenceError(
                "V3 workshop invalidation signed parent blob changed"
            )
        signed[identity["path"]] = raw
    receipt_raw = signed[_PARENT_RECEIPT["path"]]
    receipt = json.loads(
        receipt_raw,
        object_pairs_hook=parent.contract.base.legacy.parent._reject_duplicates,
        parse_constant=parent.contract.base.legacy.parent._reject_constant,
    )
    if (
        not isinstance(receipt, Mapping)
        or receipt_raw != canonical_json(receipt) + b"\n"
        or canonical_digest(receipt) != _PARENT_RESULT_DIGEST
    ):
        raise AdmissionEvidenceError(
            "V3 workshop invalidation signed parent receipt changed"
        )
    return receipt


def _verify_parent_result(
    qualification: Mapping[str, Any], signed_parent: Mapping[str, Any]
) -> None:
    expected_routes = [
        {
            "id": route,
            "status": "PASS" if route == _SOURCE_ROUTE else "NOT_TESTED",
        }
        for route in parent.v3_contract.contract._ROUTES
    ]
    decision = qualification["decision"]
    eligibility = parent.v3_contract.contract._ELIGIBILITY_KEYS
    if any(
        type(decision[key]) is not bool or decision[key] is not False
        for key in eligibility
    ):
        raise AdmissionEvidenceError(
            "V3 workshop invalidation parent eligibility changed"
        )
    if (
        canonical_digest(qualification) != _PARENT_RESULT_DIGEST
        or canonical_json(qualification) != canonical_json(signed_parent)
        or qualification["schema"]
        != (
            "aragorn/admission-protected-final-combined-v3-workshop-proposal-"
            "apply-route-coverage/v1"
        )
        or qualification["profile"]
        != {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": expected_routes,
        }
        or qualification["bindings"]["verifier_implementation_digest"]
        != _PARENT_MODULE["digest"]
        or qualification["bindings"]["workshop_proposal_apply_observation"]["digest"]
        != parent._EVIDENCE["digest"]
        or decision
        != {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in eligibility},
        }
    ):
        raise AdmissionEvidenceError("V3 workshop invalidation parent result changed")


def _verify_reload_bridge(evidence: Mapping[str, Any]) -> None:
    """Recompute only the post-apply facts promoted as workshop invalidation."""

    parent._verify_scalar_types(evidence)
    observation = evidence["route_observation"]
    document = observation["document"]
    action = document["actions"][0]
    after = action["observations"]
    route = {
        "action_id": "workshop-protected-apply",
        "id": _SOURCE_ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    if (
        evidence["route_id"] != _SOURCE_ROUTE
        or evidence["decision"]["route_pass_count"] != 0
        or evidence["decision"]["route_fail_count"] != 0
        or evidence["decision"]["route_not_tested_count"] != 21
        or document["selected_route_ids"] != [_SOURCE_ROUTE]
        or document["routes"] != [route]
        or observation["route"] != route
        or action["id"] != "workshop-protected-apply"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 workshop invalidation source route changed")

    # Reuse the signed parent's exact command, snapshot, catalog, and proposal
    # validators, then join only the post-apply facts needed by this child route.
    parent._verify_observations(action, document["run_nonce"])
    initial = after["initial_snapshot"]
    immediate = after["immediate_post_apply_snapshot"]
    final = after["final_snapshot"]
    initial_entry = initial["entry"]
    final_entry = final["entry"]
    initial_store = initial["file"]
    final_store = final["file"]
    next_turn = after["next_same_session_turn"]
    commands = action["commands"]
    applied_at = after["native_apply_result"]["response"]["value"]["record"][
        "appliedAt"
    ]
    parse = parent.contract.base.legacy._parse_time
    applied_ms = parent.contract.base.legacy._epoch_ms(applied_at)
    if (
        initial != immediate
        or after["target_final"] != after["target_after_apply"]
        or initial_entry["session_id"] != final_entry["session_id"]
        or initial_entry["skill_names"] != final_entry["skill_names"]
        or initial_entry["prompt"] != final_entry["prompt"]
        or initial_entry["snapshot_version"] >= final_entry["snapshot_version"]
        or final_entry["snapshot_version"] != applied_ms
        or initial_entry["updated_at"] >= final_entry["updated_at"]
        or initial_store["path"] != final_store["path"]
        or initial_store["device"] != final_store["device"]
        or initial_store["digest"] == final_store["digest"]
        or initial_store["inode"] == final_store["inode"]
        or after["catalog_before"]["response"]["value"]
        == after["catalog_after_apply"]["response"]["value"]
        or after["catalog_after_apply"]["response"]["value"]
        != after["final_catalog"]["response"]["value"]
        or commands
        != [
            after["catalog_before"]["command"],
            *after["initial_turn"]["commands"],
            after["native_proposal_result"]["command"],
            after["native_apply_result"]["command"],
            after["catalog_after_apply"]["command"],
            *next_turn["commands"],
            after["final_catalog"]["command"],
        ]
        or not (
            parse(after["native_apply_result"]["command"]["started_at"])
            <= parse(applied_at)
            <= parse(after["native_apply_result"]["command"]["completed_at"])
            <= parse(after["target_after_apply_observed_at"])
            <= parse(after["catalog_after_apply"]["command"]["started_at"])
            < parse(next_turn["send"]["command"]["started_at"])
            <= parse(next_turn["wait"]["command"]["completed_at"])
            <= parse(after["final_snapshot_observed_at"])
            <= parse(after["final_catalog"]["command"]["started_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop invalidation post-apply transition changed"
        )
