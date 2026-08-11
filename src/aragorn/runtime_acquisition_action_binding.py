"""Compose retained acquisition evidence with one qualified runtime action."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import runtime_action_worker_activation_expiry_systemd_evidence as p37c
from . import supported_ingress_live_archive as phase1
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

_SCHEMA = "aragorn/runtime-acquisition-action-binding-qualification/v1"
_ASSURANCE = (
    "SEMANTICALLY_REPLAY_VERIFIED_CROSS_CAPTURE_EXACT_ACQUIRED_SKILL_CONTENT_"
    "TO_ONE_COHERENT_RUNTIME_ACTION"
)
_PHASE1_RECEIPT_PATH = (
    "benchmark/receipts/phase1-supported-ingress-live-qualification-2026-07-29.json"
)
_PHASE1_RECEIPT_BYTES = 8_707
_PHASE1_RECEIPT_RAW_DIGEST = (
    "sha256:9e9242b17c36dad9df9faf19071f5669fcb3d76baba30f68fb0626a442bac259"
)
_PHASE1_RECEIPT_DIGEST = (
    "sha256:bc71a4fa94fa4f1a1029823c44c2ab7913c0e4e797455d034548e5c076467221"
)
_PHASE1_VERIFIER_DIGEST = (
    "sha256:39b9daec8f0ad0dcda7d69b561f25a8b9e138780c36fd33fa5921e3bd8751d9f"
)
_P37C_RECEIPT_PATH = (
    "benchmark/receipts/phase3-runtime-action-worker-activation-expiry-systemd-"
    "qualification-v1-2026-08-09.json"
)
_P37C_RECEIPT_BYTES = 6_655
_P37C_RECEIPT_RAW_DIGEST = (
    "sha256:e01fdcf8e18ecd02ddbbaece02a7b4abe14dd2635396d1ffa7bb9a8f9ed61eb7"
)
_P37C_RECEIPT_DIGEST = (
    "sha256:62d04b3615832f2da7713d5ac7eb2ae14e859454d810f421b79b54d427876fa1"
)
_P37C_VERIFIER_DIGEST = (
    "sha256:46e527ed0977ea5e2778cd775527515732002acf3051a580b786c8f90bcfda97"
)
_SOURCE_REQUEST = {
    "commit": "00756142ab04c82a447693cf373c4e0c554d1005",
    "owner": "anthropics",
    "repository": "skills",
    "schema": "aragorn/github-gateway-request/v1",
    "skill_path": "template",
}
_MANIFEST_DIGEST = (
    "sha256:9b15b6b43f0afe9cfe02ede35b8c50e32e8394c17b9aad792964805f08589470"
)
_TREE_DIGEST = "sha256:d409d3747207c4ac4b50002c256557c43262457e988de92189b9f8324beb5b7b"
_SKILL_DIGEST = (
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
)
_QUARANTINE_RECEIPT_DIGEST = (
    "sha256:e24f8de8ceee83e43c3fedfd0f9d03099f877d23387cfe8aa8d8ba7d3910c383"
)
_PHASE1_CONTEXT_ID = (
    "sha256:def0e64589c30d8b1a857269880e167bac3cda323afe6904d88a9a68f31bd36d"
)
_PHASE1_SKILL_MEMBER = (
    "protected-after-install/skills/.aragorn-versions/aragorn-admitted/"
    "def0e64589c30d8b1a857269880e167bac3cda323afe6904d88a9a68f31bd36d-"
    "9b15b6b43f0afe9cfe02ede35b8c50e32e8394c17b9aad792964805f08589470/"
    "SKILL.md"
)
_PHASE1_CLAIM_MEMBER = (
    "protected-after-install/skills/.aragorn-install-claims/"
    "def0e64589c30d8b1a857269880e167bac3cda323afe6904d88a9a68f31bd36d.json"
)
_LIMITATIONS = [
    "ONE_PHASE1_PUBLIC_GITHUB_EXACT_COMMIT_INSTALL_ONLY",
    "ONE_P3_7C_COHERENT_SINGLE_FILE_CREATE_ACTION_ONLY",
    "LIVE_INSTALL_QUARANTINE_CAS_NOT_RETAINED",
    "CROSS_CAPTURE_CONTENT_JOIN_NOT_CONTINUOUS_CUSTODY_OR_SAME_TRANSACTION",
    "P3_6B_EVALUATOR_REBOUND_CAS_CUSTODY",
    "P3_6B_ADAPTED_PYTHON_3_12_AND_CURRENT_MODULE_RELEASE_NOT_PHASE1_PRODUCTION_RELEASE_IDENTITY",
    "PHASE1_INSTALL_CASE_IS_RETAINED_LIVE_SUMMARY_NOT_FULL_CAS_REPLAY",
    "EXACT_CONTENT_IDENTITY_NOT_SEMANTIC_SKILL_CAUSATION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "NO_NATIVE_HOST_AUTOMATIC_RENEWAL_CONCURRENCY_REBOOT_CRASH_OR_POWER_LOSS_QUALIFICATION",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DECISION = {
    "aggregate_gate_eligible": False,
    "cross_capture_exact_skill_content_binding": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "one_coherent_allow_created_consumed_action": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "same_custody_epoch": False,
    "same_release_identity": False,
    "semantic_skill_causation_established": False,
    "status": "P3_8A_CROSS_CAPTURE_EXACT_CONTENT_TO_COHERENT_ACTION_PASS",
}


def runtime_acquisition_action_binding_qualification(
    phase1_archive_path: str | Path,
    phase1_receipt: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    *,
    implementation_digest: str | None,
) -> dict[str, Any]:
    """Return the bounded exact-content acquisition-to-action qualification."""

    phase1_receipt = _snapshot(phase1_receipt)
    p37c_observation = _snapshot(p37c_observation)
    p37b_observation = _snapshot(p37b_observation)
    p36b_observation = _snapshot(p36b_observation)
    p37b_receipt = _snapshot(p37b_receipt)
    p37c_receipt = _snapshot(p37c_receipt)
    _expect(
        _raw_digest(Path(phase1.__file__).read_bytes()) == _PHASE1_VERIFIER_DIGEST,
        "Phase1 verifier implementation pin changed",
    )
    expected_phase1 = phase1.verify_supported_ingress_live_archive(phase1_archive_path)
    _require_receipt(
        phase1_receipt,
        expected_phase1,
        digest=_PHASE1_RECEIPT_DIGEST,
        raw_digest=_PHASE1_RECEIPT_RAW_DIGEST,
        size=_PHASE1_RECEIPT_BYTES,
        label="Phase1",
    )
    expected_p37c = p37c.runtime_action_worker_activation_expiry_systemd_qualification(
        p37c_observation,
        p37b_observation,
        p36b_observation,
        p37b_receipt,
        expected_digest=p37c._EVIDENCE_DIGEST,
        implementation_digest=_P37C_VERIFIER_DIGEST,
    )
    _require_receipt(
        p37c_receipt,
        expected_p37c,
        digest=_P37C_RECEIPT_DIGEST,
        raw_digest=_P37C_RECEIPT_RAW_DIGEST,
        size=_P37C_RECEIPT_BYTES,
        label="P3.7c",
    )

    raw = phase1._pinned_bytes(
        phase1_archive_path,
        phase1.ARCHIVE_DIGEST,
        "supported-ingress live archive",
        phase1._MAX_ARCHIVE_BYTES,
    )
    archive = phase1._load(raw)
    install = phase1._verify_case(archive, "install", phase1._EXPECTED_CASES["install"])
    coordinator = phase1._json(
        archive, "protected-after-install/coordinator-active.json", newline=False
    )
    phase1_transaction = phase1._json(archive, _PHASE1_CLAIM_MEMBER, newline=False)
    phase1_skill = phase1._file(archive, _PHASE1_SKILL_MEMBER, 0o444)

    _verify_cross_capture_binding(
        install,
        coordinator,
        phase1_transaction,
        phase1_skill,
        p36b_observation,
        p37c_observation,
    )

    verifier_digest = _raw_digest(Path(__file__).read_bytes())
    _expect(
        implementation_digest is not None and implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    coherent = p37c_observation["cases"]["coherent_consumed"]
    receipt = coherent["receipt"]
    grant_state = coherent["grant_state"]
    fresh_grant = p37c_observation["inputs"]["fresh_grant"]
    return {
        "assurance": _ASSURANCE,
        "bindings": {
            "content": {
                "bytes": len(phase1_skill),
                "manifest_digest": _MANIFEST_DIGEST,
                "phase1_context_id": _PHASE1_CONTEXT_ID,
                "quarantine_receipt_digest": _QUARANTINE_RECEIPT_DIGEST,
                "skill_digest": _SKILL_DIGEST,
                "source_request": dict(_SOURCE_REQUEST),
                "tree_digest": _TREE_DIGEST,
            },
            "implementation": {
                "phase1_verifier_digest": _PHASE1_VERIFIER_DIGEST,
                "p37c_verifier_digest": _P37C_VERIFIER_DIGEST,
                "verifier_implementation_digest": verifier_digest,
            },
            "phase1": {
                "archive": {
                    "bytes": len(raw),
                    "digest": phase1.ARCHIVE_DIGEST,
                    "path": phase1.ARCHIVE_PATH,
                },
                "receipt": {
                    "bytes": _PHASE1_RECEIPT_BYTES,
                    "canonical_digest": _PHASE1_RECEIPT_DIGEST,
                    "path": _PHASE1_RECEIPT_PATH,
                    "raw_digest": _PHASE1_RECEIPT_RAW_DIGEST,
                },
                "release_identity_digest": phase1_receipt["runtime"][
                    "release_identity_digest"
                ],
                "source_commit": phase1_receipt["source"]["commit"],
            },
            "p3_7c": {
                "observation": {
                    "bytes": p37c._EVIDENCE_BYTES,
                    "canonical_digest": p37c._EVIDENCE_DIGEST,
                    "path": p37c._RETAINED_PATH,
                    "raw_digest": p37c._EVIDENCE_RAW_DIGEST,
                },
                "receipt": {
                    "bytes": _P37C_RECEIPT_BYTES,
                    "canonical_digest": _P37C_RECEIPT_DIGEST,
                    "path": _P37C_RECEIPT_PATH,
                    "raw_digest": _P37C_RECEIPT_RAW_DIGEST,
                },
            },
            "runtime_action": {
                "consumed_state_digest": grant_state["digest"],
                "fresh_grant_digest": fresh_grant["digest"],
                "profile_digest": p37c_observation["profiles"]["worker"]["digest"],
                "profile_receipt_digest": receipt["digest"],
                "target_digest": coherent["target"]["digest"],
            },
        },
        "cases": {
            "cross_capture_content_binding": {
                "bytes": 140,
                "skill_digest": _SKILL_DIGEST,
                "status": "PASS",
            },
            "phase1_production_install": {
                "source": "anthropics/skills@00756142ab04c82a447693cf373c4e0c554d1005:template",
                "status": "PASS",
                "verdict": "COMPLETED_NOT_INSTALLER_AUTHORITY",
            },
            "p3_7c_coherent_action": {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
        },
        "decision": dict(_DECISION),
        "limitations": list(_LIMITATIONS),
        "schema": _SCHEMA,
        "source_recorded_at": p37c_observation["recorded_at"],
    }


def _verify_cross_capture_binding(
    install: Any,
    coordinator: Mapping[str, Any],
    phase1_transaction: Mapping[str, Any],
    phase1_skill: bytes,
    p36b_observation: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
) -> None:
    phase1_source = install.broker["source"]
    p36b_producer = p36b_observation["producer"]
    p37c_inputs = p37c_observation["inputs"]
    p37c_producer = p37c_inputs["producer"]
    coherent = p37c_observation["cases"]["coherent_consumed"]
    receipt = coherent["receipt"]
    grant_state = coherent["grant_state"]
    grant_document = p37c_inputs["fresh_grant"]["document"]
    attribution = receipt["document"]["runtime_attribution"]
    lease = grant_state["document"]["claim"]["lease"]

    _expect(
        all(
            value == _SOURCE_REQUEST
            for value in (
                install.summary["source_request"],
                install.result["source_request"],
                phase1_source["request"],
                coordinator["expected_active"]["source_request"],
                p36b_producer["request"]["document"]["source_request"],
            )
        ),
        "source request binding changed",
    )
    _expect(
        all(
            value == _MANIFEST_DIGEST
            for value in (
                install.result["manifest_digest"],
                phase1_source["manifest_digest"],
                install.broker["transaction"]["manifest_digest"],
                coordinator["expected_active"]["manifest_digest"],
                phase1_transaction["manifest_digest"],
                p36b_producer["request"]["document"]["manifest_digest"],
                p36b_producer["transaction"]["manifest_digest"],
                p36b_observation["grant"]["document"]["source_manifest_digest"],
                p37c_producer["transaction"]["manifest_digest"],
                grant_document["source_manifest_digest"],
            )
        ),
        "manifest binding changed",
    )
    _expect(
        all(
            value == _TREE_DIGEST
            for value in (
                phase1_source["tree_digest"],
                install.broker["transaction"]["tree_digest"],
                install.broker["active"]["tree_digest"],
                coordinator["tree_digest"],
                phase1_transaction["tree_digest"],
                p36b_producer["transaction"]["tree_digest"],
                p36b_observation["active_install"]["verified_lineage"]["tree_digest"],
                p37c_producer["transaction"]["tree_digest"],
            )
        ),
        "tree binding changed",
    )
    _expect(
        install.result["context_id"] == _PHASE1_CONTEXT_ID
        and install.result["quarantine_receipt_digest"] == _QUARANTINE_RECEIPT_DIGEST
        and phase1_source["quarantine_receipt_digest"] == _QUARANTINE_RECEIPT_DIGEST
        and coordinator["expected_active"]["quarantine_receipt_digest"]
        == _QUARANTINE_RECEIPT_DIGEST
        and phase1_transaction == install.broker["transaction"],
        "Phase1 protected install binding changed",
    )
    _expect(
        len(phase1_skill) == 140 and _raw_digest(phase1_skill) == _SKILL_DIGEST,
        "Phase1 active skill changed",
    )
    _expect(
        all(
            value == _SKILL_DIGEST
            for value in (
                p36b_producer["tree_entry"]["digest"],
                p36b_observation["profile"]["skill"]["digest"],
                p36b_observation["grant"]["document"]["active_skill_digest"],
                p37c_producer["skill"]["digest"],
                p37c_producer["projected_skill"]["digest"],
                grant_document["active_skill_digest"],
                coherent["correlation"]["active_skill_digest"],
                attribution["active_skill_digest"],
                lease["active_skill_digest"],
            )
        ),
        "active skill content binding changed",
    )

    broker_result = receipt["document"]["broker_result"]
    grant_result = grant_state["document"]["result"]["profile_result"]
    driver_result = coherent["driver"]["output"]["scenario"]["proof"]["observed"]
    _expect(
        driver_result["status"] == "COMPLETED"
        and broker_result["verdict"] == "ALLOW"
        and broker_result["effect_status"] == "CREATED"
        and grant_state["document"]["status"] == "CONSUMED"
        and grant_state["document"]["grant_digest"]
        == p37c_inputs["fresh_grant"]["digest"]
        and grant_result["profile_receipt_digest"] == receipt["digest"]
        and grant_result["verdict"] == broker_result["verdict"]
        and grant_result["effect_status"] == broker_result["effect_status"]
        and coherent["target"]["digest"] == coherent["correlation"]["payload_digest"],
        "coherent action binding changed",
    )


def _require_receipt(
    supplied: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    digest: str,
    raw_digest: str,
    size: int,
    label: str,
) -> None:
    encoded = canonical_json(supplied)
    _expect(encoded == canonical_json(expected), f"{label} receipt changed")
    _expect(
        canonical_digest(supplied) == digest
        and _raw_digest(encoded + b"\n") == raw_digest
        and len(encoded) + 1 == size,
        f"{label} receipt identity changed",
    )


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    document = json.loads(canonical_json(value))
    _expect(isinstance(document, dict), "input is not a JSON object")
    return document


def _expect(condition: bool, message: str) -> None:
    if condition is not True:
        raise AdmissionEvidenceError(message)
