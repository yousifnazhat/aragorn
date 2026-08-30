"""Describe and sequence a non-authoritative V3 admission campaign."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any


class CampaignContractError(ValueError):
    """The campaign or a subfixture attestation left its fail-closed contract."""


_CONTRACT_SCHEMA = "aragorn/openclaw-final-admission-v3-campaign-contract/v1"
_RUN_SCHEMA = "aragorn/openclaw-final-admission-v3-campaign-observation/v1"
_REQUEST_SCHEMA = "aragorn/openclaw-final-admission-v3-subfixture-request/v1"
_AUTHORITY = (
    "BOUND_V3_CAMPAIGN_SKELETON_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_"
    "OR_RELEASE_AUTHORITY"
)
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)
_CURRENT_PARENT = (
    (
        "configuration_canonical_digest",
        "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
    ),
    (
        "image_id",
        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f",
    ),
    (
        "profile_canonical_digest",
        "sha256:9e73029de2f4e26b8dea9c8ac8bc5bc182c9669b01fb20657ec6177d99d31532",
    ),
    (
        "runtime_lock_canonical_digest",
        "sha256:4b58803f600def6a63737e68882cff0de09e3c1780b417c9f93caa8a9d37d43c",
    ),
    ("runtime_source_commit", "7fa98d8e21b6d5937f25a7f19445ff683bb980bf"),
    ("runtime_source_tree", "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44"),
    (
        "runtime_tree_digest",
        "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
    ),
    (
        "runtime_volume",
        "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
    ),
)
_ADM02_ROUTES = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_ADM02_FORMAL_SCENARIOS = (
    "install",
    "update",
    "direct-write",
    "rename",
    "symlink",
    "auto-discovery",
    "reload",
    "restart",
)
_ADM02_STANDALONE_CASES = tuple(
    f"ADM-02/{scenario}"
    for scenario in _ADM02_FORMAL_SCENARIOS
    if scenario not in {"update", "reload"}
)
_ADM03_SCENARIOS = ("ADM-03/policy-failure", "ADM-03/policy-tampering")
_CASE_IDS = (
    "DET-01",
    "ADM-01/exact-admitted-bytes",
    *_ADM02_STANDALONE_CASES,
    *_ADM02_ROUTES,
    *_ADM03_SCENARIOS,
)
_REGRESSION_ORACLES = (
    (
        "ADM-02/update/config-entry-activation",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "config-entry-activation-route-coverage-v1-2026-08-28.json"
        ),
    ),
    (
        "ADM-02/update/plugin-enable-activation",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "plugin-enable-activation-route-coverage-v1-2026-08-28.json"
        ),
    ),
    (
        "ADM-02/update/plugin-force-reinstall",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "plugin-force-reinstall-route-coverage-v1-2026-08-28.json"
        ),
    ),
    (
        "ADM-02/update/workshop-proposal-apply",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "workshop-proposal-apply-route-coverage-v1-2026-08-28.json"
        ),
    ),
    (
        "ADM-02/reload/cron-rescan",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "cron-rescan-route-coverage-v1-2026-08-30.json"
        ),
    ),
    (
        "ADM-02/reload/fresh-session-reset",
        (
            "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
            "fresh-session-reset-route-coverage-v1-2026-08-28.json"
        ),
    ),
)
_CONTRACT_LIMITATIONS = [
    "SKELETON_ONLY_NO_NATIVE_CAMPAIGN_CAPTURE_EXECUTED",
    "THIRTY_ONE_FRESH_ISOLATED_SUBFIXTURES_REQUIRED",
    "SIX_EXISTING_RECEIPTS_ARE_REGRESSION_ORACLES_ONLY",
    "REGRESSION_ORACLES_CANNOT_PROMOTE_CAMPAIGN_ELIGIBILITY",
    "SUBFIXTURE_BACKEND_AND_SEMANTIC_COMPOSER_NOT_IMPLEMENTED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_RUN_LIMITATIONS = [
    *_CONTRACT_LIMITATIONS,
    "BACKEND_FRESHNESS_AND_DESTRUCTION_ARE_ATTESTED_NOT_INDEPENDENTLY_VERIFIED",
    "CALLBACK_NOT_BOUND_TO_DISPATCHER_OR_EXECUTABLE_BYTES",
    "EVIDENCE_REFERENCES_ARE_SYNTAX_ONLY_NOT_CAS_RESOLVED",
    "DECLARED_REGRESSION_ORACLES_ARE_NOT_VERIFIED_OR_USED",
    "OBSERVED_OR_FAIL_RESULTS_ARE_NOT_SEMANTIC_PASS_QUALIFICATIONS",
]


def current_v3_parent_identity() -> dict[str, str]:
    """Return a copy of the exact parent proposed for isolated subfixtures."""

    return dict(_CURRENT_PARENT)


def build_openclaw_final_v3_campaign_contract(
    *,
    campaign_nonce: str,
    parent_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the ordered, non-executing V3 campaign contract."""

    if (
        type(campaign_nonce) is not str
        or re.fullmatch(r"[0-9a-f]{64}", campaign_nonce) is None
    ):
        raise CampaignContractError(
            "campaign nonce must be 64 lowercase hex characters"
        )
    parent = _parent_identity(
        current_v3_parent_identity() if parent_identity is None else parent_identity
    )
    parent_digest = _digest(_canonical(parent))
    oracles = dict(_REGRESSION_ORACLES)
    cases = []
    for ordinal, case_id in enumerate(_CASE_IDS):
        oracle_path = oracles.get(case_id)
        cases.append(
            {
                "case_id": case_id,
                "family": case_id.split("/", 1)[0],
                "fixture_id": f"{campaign_nonce}-{ordinal:02d}",
                "isolation": {
                    "destroy_before_next": True,
                    "fresh": True,
                    "network": "none",
                    "parent_identity_digest": parent_digest,
                    "reuse": False,
                },
                "ordinal": ordinal,
                "regression_oracle": (
                    None
                    if oracle_path is None
                    else {
                        "authority": ("REGRESSION_ORACLE_ONLY_NOT_CAMPAIGN_EVIDENCE"),
                        "path": oracle_path,
                    }
                ),
            }
        )
    return {
        "schema": _CONTRACT_SCHEMA,
        "authority": _AUTHORITY,
        "campaign_nonce": campaign_nonce,
        "decision": _decision(
            "V3_CAMPAIGN_SKELETON_NOT_EXECUTED",
            observed=0,
            failed=0,
            not_tested=len(_CASE_IDS),
        ),
        "expected_counts": {
            "ADM-01": 1,
            "ADM-02-FORMAL-STANDALONE": len(_ADM02_STANDALONE_CASES),
            "ADM-02-ROUTES": len(_ADM02_ROUTES),
            "ADM-03": len(_ADM03_SCENARIOS),
            "DET-01": 1,
            "TOTAL": len(_CASE_IDS),
        },
        "formal_claims": _false_formal_claims(),
        "frozen_parent": {"digest": parent_digest, "identity": parent},
        "limitations": list(_CONTRACT_LIMITATIONS),
        "ordered_cases": cases,
    }


def validate_openclaw_final_v3_campaign_contract(
    contract: dict[str, Any],
) -> dict[str, Any]:
    """Return a canonical copy only when the full contract is exact."""

    if type(contract) is not dict:
        raise CampaignContractError("campaign contract must be an object")
    try:
        nonce = contract["campaign_nonce"]
        parent = contract["frozen_parent"]["identity"]
    except (KeyError, TypeError) as exc:
        raise CampaignContractError(
            "campaign contract bindings are incomplete"
        ) from exc
    expected = build_openclaw_final_v3_campaign_contract(
        campaign_nonce=nonce, parent_identity=parent
    )
    if _canonical(contract) != _canonical(expected):
        raise CampaignContractError("campaign contract changed")
    return _copy_json(expected)


def run_openclaw_final_v3_campaign(
    contract: dict[str, Any],
    execute_subfixture: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Sequence exact subfixture requests without granting qualification authority."""

    bound = validate_openclaw_final_v3_campaign_contract(contract)
    results = []
    seen_evidence_refs: set[str] = set()
    counts = {"FAIL": 0, "NOT_TESTED": 0, "OBSERVED": 0}
    for case in bound["ordered_cases"]:
        request = {
            "schema": _REQUEST_SCHEMA,
            "authority": "FRESH_SUBFIXTURE_REQUEST_ONLY_NOT_QUALIFICATION_AUTHORITY",
            "campaign_nonce": bound["campaign_nonce"],
            "case": _copy_json(case),
            "frozen_parent": _copy_json(bound["frozen_parent"]),
        }
        result = _subfixture_result(execute_subfixture(_copy_json(request)), case)
        reused = seen_evidence_refs.intersection(result["evidence_refs"])
        if reused:
            raise CampaignContractError(
                "fresh subfixtures cannot reuse evidence references"
            )
        seen_evidence_refs.update(result["evidence_refs"])
        counts[result["outcome"]] += 1
        results.append(result)
    return {
        "schema": _RUN_SCHEMA,
        "authority": _AUTHORITY,
        "campaign_nonce": bound["campaign_nonce"],
        "contract_digest": _digest(_canonical(bound)),
        "decision": _decision(
            "V3_CAMPAIGN_EXECUTION_RECORDED_NOT_QUALIFIED",
            observed=counts["OBSERVED"],
            failed=counts["FAIL"],
            not_tested=counts["NOT_TESTED"],
        ),
        "execution": {
            "attested_fresh_subfixture_count": len(results),
            "ordered_case_ids": [result["case_id"] for result in results],
            "results": results,
        },
        "formal_claims": _false_formal_claims(),
        "frozen_parent": _copy_json(bound["frozen_parent"]),
        "limitations": list(_RUN_LIMITATIONS),
        "declared_regression_oracles": [
            case["regression_oracle"]["path"]
            for case in bound["ordered_cases"]
            if case["regression_oracle"] is not None
        ],
    }


def _parent_identity(value: dict[str, Any]) -> dict[str, str]:
    if type(value) is not dict or set(value) != {key for key, _ in _CURRENT_PARENT}:
        raise CampaignContractError("frozen parent identity keys changed")
    output = dict(value)
    digest_keys = {
        "configuration_canonical_digest",
        "image_id",
        "profile_canonical_digest",
        "runtime_lock_canonical_digest",
        "runtime_tree_digest",
    }
    if any(
        type(output[key]) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", output[key]) is None
        for key in digest_keys
    ):
        raise CampaignContractError("frozen parent digest changed")
    if any(
        type(output[key]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", output[key]) is None
        for key in ("runtime_source_commit", "runtime_source_tree")
    ):
        raise CampaignContractError("frozen parent source identity changed")
    if (
        type(output["runtime_volume"]) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", output["runtime_volume"])
        is None
    ):
        raise CampaignContractError("frozen parent runtime volume changed")
    if output != dict(_CURRENT_PARENT):
        raise CampaignContractError("frozen parent identity changed")
    return output


def _subfixture_result(value: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "case_id",
        "destroyed",
        "evidence_refs",
        "fixture_id",
        "fresh",
        "outcome",
        "parent_identity_digest",
    }
    if type(value) is not dict or set(value) != keys:
        raise CampaignContractError("subfixture result keys changed")
    result = dict(value)
    if (
        type(result["case_id"]) is not str
        or result["case_id"] != case["case_id"]
        or type(result["fixture_id"]) is not str
        or result["fixture_id"] != case["fixture_id"]
        or type(result["parent_identity_digest"]) is not str
        or result["parent_identity_digest"]
        != case["isolation"]["parent_identity_digest"]
        or result["fresh"] is not True
        or result["destroyed"] is not True
    ):
        raise CampaignContractError("subfixture isolation or parent binding changed")
    if type(result["outcome"]) is not str or result["outcome"] not in {
        "FAIL",
        "NOT_TESTED",
        "OBSERVED",
    }:
        raise CampaignContractError("subfixture outcome cannot grant PASS authority")
    refs = result["evidence_refs"]
    if (
        type(refs) is not list
        or refs != sorted(set(refs))
        or any(
            type(ref) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", ref) is None
            for ref in refs
        )
    ):
        raise CampaignContractError("subfixture evidence references changed")
    if (result["outcome"] == "NOT_TESTED") != (refs == []):
        raise CampaignContractError(
            "subfixture outcome and evidence references disagree"
        )
    return _copy_json(result)


def _decision(
    status: str, *, observed: int, failed: int, not_tested: int
) -> dict[str, Any]:
    return {
        "status": status,
        "case_fail_count": failed,
        "case_not_tested_count": not_tested,
        "case_observed_count": observed,
        "case_total": observed + failed + not_tested,
        **{key: False for key in _ELIGIBILITY_KEYS},
    }


def _false_formal_claims() -> dict[str, Any]:
    return {
        "ADM-01": False,
        "ADM-02": {
            "formal_scenarios": {
                scenario: False for scenario in _ADM02_FORMAL_SCENARIOS
            },
            "routes": {route: False for route in _ADM02_ROUTES},
        },
        "ADM-03": {scenario: False for scenario in _ADM03_SCENARIOS},
        "DET-01": False,
    }


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise CampaignContractError("campaign value is not canonical JSON") from exc


def _copy_json(value: Any) -> Any:
    return json.loads(_canonical(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
