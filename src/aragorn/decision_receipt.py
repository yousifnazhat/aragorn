"""Semantic replay for retained decision/v2 evidence summaries."""

from __future__ import annotations

import json
import re
from typing import Any

from .admission_decision import AdmissionDecisionError, parse_policy
from .analyzer_receipt import (
    AnalyzerReceiptError,
    summarize_analyzer_run,
    verify_analyzer_run,
)
from .artifact_closure import (
    ArtifactClosureError,
    load_verified_retained_manifest,
)
from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, canonical_json
from .policy import evaluate_policy


_AUTHORITY = "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_DECISION_BYTES = 8 * 1024 * 1024
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_ANALYZERS = 16


class DecisionReceiptError(ValueError):
    """A retained decision is malformed, incomplete, or inconsistent."""


def verify_decision_v2(
    cas: CAS,
    decision_digest: str,
    *,
    expected_manifest_digest: str,
    expected_policy_digest: str,
    expected_analyzer_verifier_digest: str,
) -> dict[str, Any]:
    """Re-derive one evidence summary without granting installer authority."""

    try:
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        policy_digest = _digest(expected_policy_digest, "expected policy digest")
        verifier_digest = _digest(
            expected_analyzer_verifier_digest,
            "expected analyzer verifier digest",
        )
        decision, raw_decision = _canonical_document(
            cas.read(
                _digest(decision_digest, "decision digest"),
                max_bytes=_MAX_DECISION_BYTES,
            ),
            "decision",
        )
        _exact_keys(
            decision,
            {
                "schema",
                "authority",
                "verdict",
                "manifest_digest",
                "tree_digest",
                "artifact_digests",
                "policy",
                "analyzers",
                "reason_codes",
            },
            "decision",
        )
        if decision["schema"] != "aragorn/decision/v2":
            raise DecisionReceiptError("decision schema is unsupported")
        if decision["authority"] != _AUTHORITY:
            raise DecisionReceiptError("decision overstates its authority")
        if decision["manifest_digest"] != manifest_digest:
            raise DecisionReceiptError("decision is bound to another manifest")

        manifest = load_verified_retained_manifest(cas, manifest_digest)
        policy_record = decision["policy"]
        _exact_keys(
            policy_record,
            {"id", "version", "digest"},
            "decision policy",
        )
        if policy_record["digest"] != policy_digest:
            raise DecisionReceiptError("decision policy identity is untrusted")
        policy_document, _raw_policy = _canonical_document(
            cas.read(policy_digest, max_bytes=_MAX_POLICY_BYTES),
            "policy",
        )
        validated_policy, policy = parse_policy(policy_document)

        analyzer_records = decision["analyzers"]
        if (
            not isinstance(analyzer_records, list)
            or len(analyzer_records) > _MAX_ANALYZERS
        ):
            raise DecisionReceiptError("decision analyzer list is invalid")
        results = []
        expected_records = []
        for index, record in enumerate(analyzer_records):
            if not isinstance(record, dict):
                raise DecisionReceiptError(
                    f"decision analyzer summary {index} is invalid"
                )
            run_receipt_digest = _digest(
                record.get("run_receipt_digest"),
                f"decision analyzer summary {index} run receipt digest",
            )
            result = verify_analyzer_run(
                cas,
                run_receipt_digest,
                expected_subject_digest=manifest["tree_digest"],
                expected_verifier_digest=verifier_digest,
            )
            results.append(result)
            expected_records.append(
                summarize_analyzer_run(
                    result,
                    run_receipt_digest=run_receipt_digest,
                )
            )
        names = [result.name for result in results]
        if names != sorted(set(names)):
            raise DecisionReceiptError(
                "decision analyzer summaries must be sorted by unique name"
            )

        evaluated = evaluate_policy(
            policy,
            closure=manifest["closure"],
            results=results,
        )
        expected = {
            "schema": "aragorn/decision/v2",
            "authority": _AUTHORITY,
            "verdict": evaluated.verdict,
            "manifest_digest": manifest_digest,
            "tree_digest": manifest["tree_digest"],
            "artifact_digests": sorted(entry["digest"] for entry in manifest["files"]),
            "policy": {
                "id": validated_policy["id"],
                "version": validated_policy["version"],
                "digest": policy_digest,
            },
            "analyzers": expected_records,
            "reason_codes": list(evaluated.reason_codes),
        }
        if raw_decision != canonical_json(expected):
            raise DecisionReceiptError(
                "decision summary does not match replayed evidence and policy"
            )
        return decision
    except DecisionReceiptError:
        raise
    except (
        AdmissionDecisionError,
        AnalyzerReceiptError,
        ArtifactClosureError,
        CASError,
        WorkerProtocolError,
    ) as exc:
        raise DecisionReceiptError(f"cannot verify retained decision: {exc}") from exc


def _canonical_document(raw: bytes, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        if not isinstance(document, dict) or canonical_json(document) != raw:
            raise DecisionReceiptError(f"{label} is not a canonical JSON object")
        return document, raw
    except DecisionReceiptError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError, WorkerProtocolError) as exc:
        raise DecisionReceiptError(f"{label} is invalid: {exc}") from exc


def _exact_keys(document: object, expected: set[str], label: str) -> None:
    if not isinstance(document, dict) or set(document) != expected:
        raise DecisionReceiptError(f"{label} fields are invalid")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DecisionReceiptError(f"{label} is invalid")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise DecisionReceiptError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise DecisionReceiptError(f"non-finite JSON number: {value}")
