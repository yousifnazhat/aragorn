"""Semantic replay for retained decision evidence summaries."""

from __future__ import annotations

import json
import re
from io import BytesIO
from typing import Any

from .admission_artifact_graph import (
    AdmissionArtifactGraphError,
    verify_admission_artifact_graph,
)
from .admission_decision import (
    AdmissionDecisionError,
    parse_policy,
    policy_artifact_graph_profiles,
)
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
_MAX_RELEASE_ASSETS = 16
_PROFILE_NOT_ALLOWED = "ARTIFACT_GRAPH_PROFILE_NOT_ALLOWED"


class DecisionReceiptError(ValueError):
    """A retained decision is malformed, incomplete, or inconsistent."""


def retain_decision_v3(
    cas: CAS,
    *,
    manifest_digest: str,
    artifact_graph_digest: str,
    policy_digest: str,
    analyzer_run_receipt_digests: list[str] | tuple[str, ...],
    analyzer_verifier_digest: str,
    artifact_graph_verifier_digest: str,
    expected_quarantine_receipt_digest: str | None = None,
    expected_gateway_profile_digest: str | None = None,
    expected_release_asset_result_digests: list[str] | tuple[str, ...] = (),
) -> str:
    """Retain a decision derived from replayed graph and analyzer evidence."""

    run_receipt_digests = _run_receipt_digests(analyzer_run_receipt_digests)
    release_asset_result_digests = _release_asset_result_digests(
        expected_release_asset_result_digests
    )
    receipt_digest, gateway_profile_digest = _optional_github_trust_digests(
        expected_quarantine_receipt_digest,
        expected_gateway_profile_digest,
    )
    records = [{"run_receipt_digest": digest} for digest in run_receipt_digests]
    try:
        decision = _derive_decision_v3(
            cas,
            manifest_digest=_digest(manifest_digest, "manifest digest"),
            artifact_graph_digest=_digest(
                artifact_graph_digest,
                "artifact graph digest",
            ),
            policy_digest=_digest(policy_digest, "policy digest"),
            analyzer_records=records,
            expected_run_receipt_digests=run_receipt_digests,
            analyzer_verifier_digest=_digest(
                analyzer_verifier_digest,
                "analyzer verifier digest",
            ),
            artifact_graph_verifier_digest=_digest(
                artifact_graph_verifier_digest,
                "artifact graph verifier digest",
            ),
            expected_quarantine_receipt_digest=receipt_digest,
            expected_gateway_profile_digest=gateway_profile_digest,
            expected_release_asset_result_digests=release_asset_result_digests,
        )
        raw = canonical_json(decision)
        return cas.put(BytesIO(raw), max_bytes=_MAX_DECISION_BYTES)
    except DecisionReceiptError:
        raise
    except (
        AdmissionArtifactGraphError,
        AdmissionDecisionError,
        AnalyzerReceiptError,
        ArtifactClosureError,
        CASError,
        WorkerProtocolError,
    ) as exc:
        raise DecisionReceiptError(f"cannot retain decision: {exc}") from exc


def verify_decision_v3(
    cas: CAS,
    decision_digest: str,
    *,
    expected_manifest_digest: str,
    expected_artifact_graph_digest: str,
    expected_policy_digest: str,
    expected_analyzer_run_receipt_digests: list[str] | tuple[str, ...],
    expected_analyzer_verifier_digest: str,
    expected_artifact_graph_verifier_digest: str,
    expected_quarantine_receipt_digest: str | None = None,
    expected_gateway_profile_digest: str | None = None,
    expected_release_asset_result_digests: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Re-derive one graph-bound evidence summary without installer authority."""

    try:
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        graph_digest = _digest(
            expected_artifact_graph_digest,
            "expected artifact graph digest",
        )
        policy_digest = _digest(expected_policy_digest, "expected policy digest")
        run_receipt_digests = _run_receipt_digests(
            expected_analyzer_run_receipt_digests,
        )
        release_asset_result_digests = _release_asset_result_digests(
            expected_release_asset_result_digests
        )
        analyzer_verifier_digest = _digest(
            expected_analyzer_verifier_digest,
            "expected analyzer verifier digest",
        )
        graph_verifier_digest = _digest(
            expected_artifact_graph_verifier_digest,
            "expected artifact graph verifier digest",
        )
        receipt_digest, gateway_profile_digest = _optional_github_trust_digests(
            expected_quarantine_receipt_digest,
            expected_gateway_profile_digest,
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
                "artifact_graph_digest",
                "tree_digest",
                "artifact_digests",
                "policy",
                "analyzers",
                "reason_codes",
            },
            "decision",
        )
        if decision["schema"] != "aragorn/decision/v3":
            raise DecisionReceiptError("decision schema is unsupported")
        if decision["authority"] != _AUTHORITY:
            raise DecisionReceiptError("decision overstates its authority")
        if decision["manifest_digest"] != manifest_digest:
            raise DecisionReceiptError("decision is bound to another manifest")
        if decision["artifact_graph_digest"] != graph_digest:
            raise DecisionReceiptError("decision is bound to another artifact graph")

        policy_record = decision["policy"]
        _exact_keys(
            policy_record,
            {"id", "version", "digest"},
            "decision policy",
        )
        if policy_record["digest"] != policy_digest:
            raise DecisionReceiptError("decision policy identity is untrusted")
        expected = _derive_decision_v3(
            cas,
            manifest_digest=manifest_digest,
            artifact_graph_digest=graph_digest,
            policy_digest=policy_digest,
            analyzer_records=decision["analyzers"],
            expected_run_receipt_digests=run_receipt_digests,
            analyzer_verifier_digest=analyzer_verifier_digest,
            artifact_graph_verifier_digest=graph_verifier_digest,
            expected_quarantine_receipt_digest=receipt_digest,
            expected_gateway_profile_digest=gateway_profile_digest,
            expected_release_asset_result_digests=release_asset_result_digests,
        )
        if raw_decision != canonical_json(expected):
            raise DecisionReceiptError(
                "decision summary does not match replayed evidence and policy"
            )
        return decision
    except DecisionReceiptError:
        raise
    except (
        AdmissionArtifactGraphError,
        AdmissionDecisionError,
        AnalyzerReceiptError,
        ArtifactClosureError,
        CASError,
        WorkerProtocolError,
    ) as exc:
        raise DecisionReceiptError(f"cannot verify retained decision: {exc}") from exc


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
        validated_policy, policy = _load_policy(cas, policy_digest)
        results, expected_records = _replay_analyzers(
            cas,
            decision["analyzers"],
            tree_digest=manifest["tree_digest"],
            verifier_digest=verifier_digest,
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


def _derive_decision_v3(
    cas: CAS,
    *,
    manifest_digest: str,
    artifact_graph_digest: str,
    policy_digest: str,
    analyzer_records: object,
    expected_run_receipt_digests: list[str] | None = None,
    analyzer_verifier_digest: str,
    artifact_graph_verifier_digest: str,
    expected_quarantine_receipt_digest: str | None,
    expected_gateway_profile_digest: str | None,
    expected_release_asset_result_digests: tuple[str, ...] = (),
) -> dict[str, Any]:
    graph = verify_admission_artifact_graph(
        cas,
        artifact_graph_digest,
        expected_manifest_digest=manifest_digest,
        expected_verifier_digest=artifact_graph_verifier_digest,
        expected_quarantine_receipt_digest=expected_quarantine_receipt_digest,
        expected_gateway_profile_digest=expected_gateway_profile_digest,
        expected_release_asset_result_digests=(expected_release_asset_result_digests),
    )
    validated_policy, policy = _load_policy(cas, policy_digest)
    results, expected_records = _replay_analyzers(
        cas,
        analyzer_records,
        tree_digest=graph["tree_digest"],
        verifier_digest=analyzer_verifier_digest,
        expected_run_receipt_digests=expected_run_receipt_digests,
    )
    evaluated = evaluate_policy(
        policy,
        closure=graph["closure"],
        results=results,
    )
    if graph["profile"] not in policy_artifact_graph_profiles(validated_policy):
        verdict = "ERROR"
        reason_codes = [_PROFILE_NOT_ALLOWED]
    else:
        verdict = evaluated.verdict
        reason_codes = list(evaluated.reason_codes)
    return {
        "schema": "aragorn/decision/v3",
        "authority": _AUTHORITY,
        "verdict": verdict,
        "manifest_digest": manifest_digest,
        "artifact_graph_digest": artifact_graph_digest,
        "tree_digest": graph["tree_digest"],
        "artifact_digests": sorted(
            artifact["digest"] for artifact in graph["artifacts"]
        ),
        "policy": {
            "id": validated_policy["id"],
            "version": validated_policy["version"],
            "digest": policy_digest,
        },
        "analyzers": expected_records,
        "reason_codes": reason_codes,
    }


def _load_policy(cas: CAS, policy_digest: str) -> tuple[dict[str, Any], Any]:
    policy_document, _raw_policy = _canonical_document(
        cas.read(policy_digest, max_bytes=_MAX_POLICY_BYTES),
        "policy",
    )
    return parse_policy(policy_document)


def _replay_analyzers(
    cas: CAS,
    analyzer_records: object,
    *,
    tree_digest: str,
    verifier_digest: str,
    expected_run_receipt_digests: list[str] | None = None,
) -> tuple[list[Any], list[dict[str, Any]]]:
    if not isinstance(analyzer_records, list) or len(analyzer_records) > _MAX_ANALYZERS:
        raise DecisionReceiptError("decision analyzer list is invalid")
    receipt_digests = []
    for index, record in enumerate(analyzer_records):
        if not isinstance(record, dict):
            raise DecisionReceiptError(f"decision analyzer summary {index} is invalid")
        receipt_digests.append(
            _digest(
                record.get("run_receipt_digest"),
                f"decision analyzer summary {index} run receipt digest",
            )
        )
    if (
        expected_run_receipt_digests is not None
        and receipt_digests != expected_run_receipt_digests
    ):
        raise DecisionReceiptError("decision analyzer receipt selection is untrusted")

    results = []
    expected_records = []
    for run_receipt_digest in receipt_digests:
        result = verify_analyzer_run(
            cas,
            run_receipt_digest,
            expected_subject_digest=tree_digest,
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
    return results, expected_records


def _run_receipt_digests(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_ANALYZERS:
        raise DecisionReceiptError("expected analyzer run receipt list is invalid")
    digests = [_digest(item, "expected analyzer run receipt digest") for item in value]
    if len(digests) != len(set(digests)):
        raise DecisionReceiptError(
            "expected analyzer run receipt digests must be unique"
        )
    return digests


def _release_asset_result_digests(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_RELEASE_ASSETS:
        raise DecisionReceiptError(
            "expected release asset result digest list is invalid"
        )
    digests = tuple(
        sorted(_digest(item, "expected release asset result digest") for item in value)
    )
    if len(digests) != len(set(digests)):
        raise DecisionReceiptError(
            "expected release asset result digests must be unique"
        )
    return digests


def _optional_github_trust_digests(
    receipt_digest: object,
    gateway_profile_digest: object,
) -> tuple[str | None, str | None]:
    if receipt_digest is None and gateway_profile_digest is None:
        return None, None
    if receipt_digest is None or gateway_profile_digest is None:
        raise DecisionReceiptError(
            "quarantine receipt and gateway profile digests must be supplied together"
        )
    return (
        _digest(receipt_digest, "expected quarantine receipt digest"),
        _digest(gateway_profile_digest, "expected gateway profile digest"),
    )


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
