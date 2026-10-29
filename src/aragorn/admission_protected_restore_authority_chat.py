"""Qualify the native chat subsequence from the restore-authority prompt capture."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_restore_authority_prompt as prompt
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/chat-session-snapshot-consumer"
_PARENT_DIGEST = (
    "sha256:5c094cb8c6ff21110cd644251e125068582acaaa423a31c418db49d80fd8c1e7"
)
_PROMPT_IMPLEMENTATION_DIGEST = (
    "sha256:86d9ca8113f73b29e324f117caa5ca36d872557de7e302960b4e68f96facaf29"
)
_DEPENDENCY_IMPLEMENTATION_DIGESTS = {
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "legacy_prompt": "sha256:99e50bd0b18723a0bb37ca8afea04ef8b40c6fd3e159c6e17f26320f4f7c586c",
    "runtime_profile": "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b",
}
_LIMITATIONS = [
    "EIGHT_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "CHAT_ROUTE_REUSES_SHARED_PROMPT_REBUILD_CAPTURE_NOT_INDEPENDENT_EXECUTION",
    "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
    "ONE_MISSING_PROMPT_BLOB_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
    "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_OR_SUCCESSFUL_REPLY_DELIVERY_CLAIM",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "THIRTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_chat(
    parent_qualification: Mapping[str, Any], *, evidence_cas: CAS
) -> dict[str, Any]:
    """Add only the native chat-session consumer PASS to seven routes."""

    try:
        parent = json.loads(canonical_json(parent_qualification))
        _verify_parent(parent)
        evidence = prompt._read_evidence(evidence_cas)
        _verify_chat_subsequence(evidence)
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
            f"invalid restore-authority chat evidence: {exc}"
        ) from exc

    result = copy.deepcopy(parent)
    for route in result["profile"]["routes"]:
        if route["id"] == _ROUTE:
            route["status"] = "PASS"
            break
    else:  # pragma: no cover - frozen parent validation reaches this first
        raise AdmissionEvidenceError("chat route missing")
    result.update(
        {
            "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_EIGHT_ROUTE_COVERAGE_ONLY",
            "bindings": {
                "parent_qualification_canonical_digest": _PARENT_DIGEST,
                "prompt_rebuild_evidence_canonical_digest": prompt._EVIDENCE[
                    "canonical_digest"
                ],
                "prompt_rebuild_evidence_digest": prompt._EVIDENCE["digest"],
                "prompt_verifier_implementation_digest": (
                    _PROMPT_IMPLEMENTATION_DIGEST
                ),
                "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            },
            "limitations": list(_LIMITATIONS),
            "schema": "aragorn/admission-protected-restore-authority-chat-route-coverage/v1",
            "source_recorded_at": max(
                parent["source_recorded_at"], evidence["recorded_at"]
            ),
        }
    )
    result["profile"]["counts"] = {"fail": 0, "not_tested": 13, "pass": 8}
    return result


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_parent(parent: Mapping[str, Any]) -> None:
    statuses = {item["id"]: item["status"] for item in parent["profile"]["routes"]}
    if (
        canonical_digest(parent) != _PARENT_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-session-consumer-route-coverage/v1"
        or parent["profile"]["counts"] != {"fail": 0, "not_tested": 14, "pass": 7}
        or list(statuses.values()).count("PASS") != 7
        or statuses.get(_ROUTE) != "NOT_TESTED"
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("seven-route parent qualification changed")


def _verify_chat_subsequence(evidence: Mapping[str, Any]) -> None:
    dependencies = {
        "archive": prompt.archive,
        "curator": prompt.curator,
        "legacy_prompt": prompt.prompt,
        "runtime_profile": prompt.runtime_profile,
    }
    if (
        _digest(Path(prompt.__file__).read_bytes()) != _PROMPT_IMPLEMENTATION_DIGEST
        or any(
            _digest(Path(module.__file__).read_bytes())
            != _DEPENDENCY_IMPLEMENTATION_DIGESTS[name]
            for name, module in dependencies.items()
        )
        or canonical_digest(evidence) != prompt._EVIDENCE["canonical_digest"]
    ):
        raise AdmissionEvidenceError("restore-authority chat source changed")

    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    nonce = evidence["run_nonce"]
    if (
        evidence["schema"] != prompt._EVIDENCE["schema"]
        or evidence["route"]
        != {
            "action_id": "missing-prompt-blob-rebuild",
            "id": "ADM-02/reload/missing-prompt-blob-rebuild",
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or action["id"] != "missing-prompt-blob-rebuild"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or after["boundary_after"] != before["boundary_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["protected_root_trees_after"] != before["protected_root_trees_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
    ):
        raise AdmissionEvidenceError("restore-authority chat state changed")

    prompt._verify_commands(action, nonce, evidence["recorded_at"])
    prompt._verify_rebuild(after, nonce)
