"""Canonical, runtime-bound admission policy decisions."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from .analyze import AnalyzerResult, Observation
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
    validate_subject_manifest,
)
from .policy import Policy, evaluate_policy

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_:.-]{0,255}\Z")
_MAX_INPUT_BYTES = 8 * 1024 * 1024
_MAX_ANALYZERS = 16
_MAX_OBSERVATIONS = 10_000
_MAX_SOURCE_EVIDENCE_DIGESTS = 64
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class AdmissionDecisionError(ValueError):
    """A canonical admission input is malformed or incompletely bound."""


def evaluate_admission(document: object) -> dict[str, Any]:
    """Return a deterministic policy decision bound to every authority input."""

    request = _exact_object(
        document,
        {
            "schema",
            "case_id",
            "manifest",
            "evidence",
            "policy",
            "target_runtime",
        },
        "admission input",
    )
    if request["schema"] != "aragorn/admission-decision-input/v1":
        raise AdmissionDecisionError("admission input schema is unsupported")
    case_id = request["case_id"]
    if not isinstance(case_id, str) or _IDENTIFIER.fullmatch(case_id) is None:
        raise AdmissionDecisionError("admission input case id is invalid")

    manifest = _manifest(request["manifest"])
    evidence, results = _evidence(request["evidence"], manifest["tree_digest"])
    policy_document, policy = parse_policy(request["policy"])
    target_runtime = _target_runtime(request["target_runtime"])
    decision = evaluate_policy(
        policy,
        closure=manifest["closure"],
        results=results,
    )
    return {
        "schema": "aragorn/admission-decision/v1",
        "authority": "POLICY_DECISION_ONLY_NOT_INSTALLER_AUTHORITY",
        "case_id": case_id,
        "request_digest": canonical_digest(request),
        "manifest_digest": canonical_digest(manifest),
        "evidence_set_digest": canonical_digest(evidence),
        "policy_digest": canonical_digest(policy_document),
        "target_runtime_digest": canonical_digest(target_runtime),
        "verdict": decision.verdict,
        "reason_codes": list(decision.reason_codes),
    }


def _manifest(value: object) -> dict[str, Any]:
    manifest = _exact_object(
        value,
        {"schema", "source", "tree_digest", "files", "closure"},
        "admission manifest",
    )
    if manifest["schema"] != "aragorn/admission-manifest/v1":
        raise AdmissionDecisionError("admission manifest schema is unsupported")
    subject = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": manifest["tree_digest"],
        "files": manifest["files"],
    }
    try:
        validate_subject_manifest(subject)
    except WorkerProtocolError as exc:
        raise AdmissionDecisionError(f"invalid admission manifest: {exc}") from exc

    source = _exact_object(
        manifest["source"],
        {"kind", "path"},
        "admission manifest source",
    )
    if source != {
        "kind": "contained_conformance_fixture",
        "path": "/profile/state/skills/aragorn-admitted",
    }:
        raise AdmissionDecisionError("admission manifest source is unsupported")

    closure = _exact_object(
        manifest["closure"],
        {"scope", "status", "unresolved"},
        "admission manifest closure",
    )
    _text(closure["scope"], "admission manifest closure scope")
    if closure["status"] not in {"complete", "incomplete"}:
        raise AdmissionDecisionError("admission manifest closure status is invalid")
    _sorted_strings(
        closure["unresolved"],
        "admission manifest unresolved item",
    )
    return manifest


def _evidence(
    value: object,
    tree_digest: str,
) -> tuple[dict[str, Any], tuple[AnalyzerResult, ...]]:
    evidence = _exact_object(
        value,
        {
            "source_evidence_digests",
            "source_receipt_digest",
            "analyzer_results",
        },
        "admission evidence set",
    )
    source_digests = evidence["source_evidence_digests"]
    if not isinstance(source_digests, list):
        raise AdmissionDecisionError("source evidence digests must be a list")
    if not 1 <= len(source_digests) <= _MAX_SOURCE_EVIDENCE_DIGESTS:
        raise AdmissionDecisionError("source evidence digest count is invalid")
    for digest in source_digests:
        _digest(digest, "source evidence digest")
    if source_digests != sorted(set(source_digests)):
        raise AdmissionDecisionError(
            "source evidence digests must be sorted and unique"
        )
    _digest(
        evidence["source_receipt_digest"],
        "source admission receipt digest",
    )
    analyzer_results = evidence["analyzer_results"]
    if not isinstance(analyzer_results, list):
        raise AdmissionDecisionError("analyzer results must be a list")
    if not 1 <= len(analyzer_results) <= _MAX_ANALYZERS:
        raise AdmissionDecisionError("analyzer result count is invalid")
    _canonical_order(analyzer_results, "analyzer results")
    results = tuple(
        _analyzer_result(item, tree_digest) for item in analyzer_results
    )
    if len({result.name for result in results}) != len(results):
        raise AdmissionDecisionError("analyzer result names must be unique")
    if sum(len(result.observations) for result in results) > _MAX_OBSERVATIONS:
        raise AdmissionDecisionError("analyzer observation count exceeds limit")
    return evidence, results


def _analyzer_result(value: object, tree_digest: str) -> AnalyzerResult:
    document = _exact_object(
        value,
        {
            "name",
            "version",
            "config_digest",
            "executable_digest",
            "subject_digest",
            "status",
            "observations",
            "error_code",
        },
        "analyzer result",
    )
    name = _identifier(document["name"], "analyzer name")
    version = _text(document["version"], "analyzer version")
    config_digest = _digest(document["config_digest"], "analyzer config digest")
    executable_digest = _digest(
        document["executable_digest"],
        "analyzer executable digest",
    )
    subject_digest = _digest(
        document["subject_digest"],
        "analyzer subject digest",
    )
    if subject_digest != tree_digest:
        raise AdmissionDecisionError("analyzer result is bound to another manifest")
    status = document["status"]
    if status not in {"ok", "error"}:
        raise AdmissionDecisionError("analyzer result status is invalid")
    observations_raw = document["observations"]
    if not isinstance(observations_raw, list):
        raise AdmissionDecisionError("analyzer observations must be a list")
    _canonical_order(observations_raw, "analyzer observations")
    observations = tuple(
        _observation(item, tree_digest) for item in observations_raw
    )
    error_code = document["error_code"]
    if status == "ok":
        if error_code is not None:
            raise AdmissionDecisionError("successful analyzer has an error code")
    elif (
        observations
        or not isinstance(error_code, str)
        or _REASON_CODE.fullmatch(error_code) is None
    ):
        raise AdmissionDecisionError("failed analyzer result is malformed")
    return AnalyzerResult(
        name=name,
        version=version,
        config_digest=config_digest,
        executable_digest=executable_digest,
        status=status,
        observations=observations,
        error_code=error_code,
    )


def _observation(value: object, tree_digest: str) -> Observation:
    document = _exact_object(
        value,
        {"schema", "subject_digest", "reason_code", "severity"},
        "analyzer observation",
    )
    if document["schema"] != "aragorn/observation/v1":
        raise AdmissionDecisionError("observation schema is unsupported")
    if _digest(document["subject_digest"], "observation subject digest") != tree_digest:
        raise AdmissionDecisionError("observation is bound to another manifest")
    reason_code = document["reason_code"]
    if not isinstance(reason_code, str) or _REASON_CODE.fullmatch(reason_code) is None:
        raise AdmissionDecisionError("observation reason code is invalid")
    severity = document["severity"]
    if severity not in _SEVERITIES:
        raise AdmissionDecisionError("observation severity is invalid")
    return Observation(
        schema=document["schema"],
        subject_digest=tree_digest,
        reason_code=reason_code,
        severity=severity,
        document_json=canonical_json(document).decode("ascii"),
    )


def parse_policy(value: object) -> tuple[dict[str, Any], Policy]:
    document = _exact_object(
        value,
        {
            "schema",
            "id",
            "version",
            "required_analyzers",
            "hard_deny_reason_codes",
            "review_severities",
        },
        "admission policy",
    )
    if document["schema"] != "aragorn/policy/v1":
        raise AdmissionDecisionError("admission policy schema is unsupported")
    _identifier(document["id"], "admission policy id")
    version = document["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise AdmissionDecisionError("admission policy version is invalid")
    required = _sorted_strings(
        document["required_analyzers"],
        "required analyzer",
    )
    if not 1 <= len(required) <= _MAX_ANALYZERS or any(
        _IDENTIFIER.fullmatch(item) is None for item in required
    ):
        raise AdmissionDecisionError("required analyzer set is invalid")
    hard_denies = _sorted_strings(
        document["hard_deny_reason_codes"],
        "hard-deny reason code",
    )
    if len(hard_denies) > _MAX_OBSERVATIONS or any(
        _REASON_CODE.fullmatch(item) is None for item in hard_denies
    ):
        raise AdmissionDecisionError("hard-deny reason code is invalid")
    severities = _sorted_strings(
        document["review_severities"],
        "review severity",
    )
    if not set(severities) <= _SEVERITIES:
        raise AdmissionDecisionError("review severity is invalid")
    return document, Policy(
        required_analyzers=tuple(required),
        hard_deny_reason_codes=frozenset(hard_denies),
        review_severities=frozenset(severities),
    )


def _target_runtime(value: object) -> dict[str, Any]:
    target = _exact_object(
        value,
        {"runtime", "adapter", "environment"},
        "target runtime",
    )
    runtime = _exact_object(
        target["runtime"],
        {
            "name",
            "version",
            "repository_url",
            "commit",
            "source_tree_digest",
            "runtime_tree_digest",
        },
        "target runtime identity",
    )
    _identifier(runtime["name"], "target runtime name")
    for field in ("version", "repository_url"):
        _text(runtime[field], f"target runtime {field}")
    if not isinstance(runtime["commit"], str) or _COMMIT.fullmatch(
        runtime["commit"]
    ) is None:
        raise AdmissionDecisionError("target runtime commit is invalid")
    _digest(runtime["source_tree_digest"], "target runtime source tree digest")
    _digest(runtime["runtime_tree_digest"], "target runtime installed tree digest")

    adapter = _exact_object(
        target["adapter"],
        {"name", "implementation_digest", "configuration_digest"},
        "target runtime adapter",
    )
    _identifier(adapter["name"], "target runtime adapter name")
    _digest(
        adapter["implementation_digest"],
        "target runtime adapter implementation digest",
    )
    _digest(
        adapter["configuration_digest"],
        "target runtime adapter configuration digest",
    )

    environment = _exact_object(
        target["environment"],
        {"worker_digest", "os_profile_digest"},
        "target runtime environment",
    )
    _digest(
        environment["worker_digest"],
        "target runtime worker digest",
    )
    _digest(
        environment["os_profile_digest"],
        "target runtime OS profile digest",
    )
    return target


def _canonical_order(items: list[object], label: str) -> None:
    try:
        encoded = [canonical_json(item) for item in items]
    except (RecursionError, WorkerProtocolError) as exc:
        raise AdmissionDecisionError(f"{label} is not canonical JSON: {exc}") from exc
    if encoded != sorted(set(encoded)):
        raise AdmissionDecisionError(f"{label} must be sorted and unique")


def _sorted_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise AdmissionDecisionError(f"{label} values must be a list")
    cleaned = [_text(item, label) for item in value]
    if cleaned != sorted(set(cleaned)):
        raise AdmissionDecisionError(f"{label} values must be sorted and unique")
    return cleaned


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AdmissionDecisionError(f"{label} shape is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionDecisionError(f"{label} is not a canonical SHA-256 digest")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AdmissionDecisionError(f"{label} must be non-empty normalized text")
    return value


def _identifier(value: object, label: str) -> str:
    text = _text(value, label)
    if _IDENTIFIER.fullmatch(text) is None:
        raise AdmissionDecisionError(f"{label} is invalid")
    return text


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise AdmissionDecisionError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise AdmissionDecisionError(f"non-finite JSON number: {value}")


def main() -> int:
    """Evaluate one canonical admission request from stdin."""

    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    try:
        if len(raw) > _MAX_INPUT_BYTES:
            raise AdmissionDecisionError("admission input exceeds 8 MiB")
        document = json.loads(
            raw,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
        if raw != canonical_json(document) + b"\n":
            raise AdmissionDecisionError("admission input is not canonical JSON")
        result = evaluate_admission(document)
    except (
        AdmissionDecisionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        WorkerProtocolError,
    ) as exc:
        print(f"admission decision rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
