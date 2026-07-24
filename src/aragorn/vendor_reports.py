"""Fail-closed normalization of pinned third-party scanner reports."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from typing import Any

from .analyze import (
    OBSERVATION_SCHEMA,
    Observation,
    _reject_duplicate_json_keys,
    _reject_json_constant,
)


MAX_VENDOR_REPORT_BYTES = 8 * 1024 * 1024
# Reserve four records for NVIDIA completion, incompleteness, aggregate-risk,
# and filtering observations so the shared 10,000-observation contract holds.
_MAX_FINDINGS = 9_996
_MAX_COMPONENTS = 10_000
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CANONICAL_RULE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_RESERVED_REASON_CODES = frozenset(
    {
        "CISCO_SCAN_COMPLETED",
        "NVIDIA_AGGREGATE_RISK_HIGH",
        "NVIDIA_ANALYSIS_INCOMPLETE",
        "NVIDIA_FINDINGS_FILTERED",
        "NVIDIA_SCAN_COMPLETED",
    }
)
_CISCO_ANALYZERS = (
    "static_analyzer",
    "bytecode",
    "pipeline",
    "behavioral_analyzer",
)
_CISCO_POLICY_FINGERPRINT = (
    "7e571f3db6d7aa3d0c8a40e9ae8f8f6a0f0a721fe518e59f71943a11b418c91f"
)
_CISCO_FINDING_KEYS = frozenset(
    {
        "id",
        "rule_id",
        "category",
        "severity",
        "title",
        "description",
        "file_path",
        "line_number",
        "snippet",
        "remediation",
        "analyzer",
        "metadata",
    }
)
_NVIDIA_ISSUE_KEYS = frozenset(
    {
        "id",
        "category",
        "pattern",
        "severity",
        "confidence",
        "location",
        "finding",
        "explanation",
        "remediation",
        "code_snippet",
        "intent",
        "tags",
    }
)


class VendorReportError(ValueError):
    """A vendor report did not satisfy the pinned trusted contract."""


def normalize_cisco_report(
    raw_report: bytes,
    *,
    subject_digest: str,
    returncode: int,
    expected_workspace: str = "/workspace",
) -> tuple[Observation, ...]:
    """Normalize one Cisco AI Skill Scanner 2.0.12 single-skill JSON report."""

    report, report_digest = _load_report(raw_report)
    _subject(subject_digest)
    workspace = _workspace(expected_workspace)
    if isinstance(returncode, bool) or not isinstance(returncode, int) or returncode != 0:
        raise VendorReportError("Cisco completed reports require exit status 0")

    _keys(
        report,
        required={
            "skill_name",
            "skill_path",
            "is_safe",
            "max_severity",
            "findings_count",
            "findings",
            "scan_duration_seconds",
            "duration_ms",
            "analyzers_used",
            "timestamp",
            "scan_metadata",
        },
        optional={"analyzers_failed"},
        field="Cisco report",
    )
    _text(report["skill_name"], "skill_name", 512, empty=False)
    if report["skill_path"] != expected_workspace:
        raise VendorReportError("Cisco skill_path does not match the workspace")
    _workspace(report["skill_path"])
    if not isinstance(report["is_safe"], bool):
        raise VendorReportError("Cisco is_safe must be a boolean")
    maximum_severity = _text(
        report["max_severity"], "Cisco max_severity", 16, empty=False
    )
    if maximum_severity not in {*_SEVERITIES, "SAFE"}:
        raise VendorReportError("Cisco max_severity is invalid")

    findings = _list(report["findings"], "Cisco findings", _MAX_FINDINGS)
    finding_count = _integer(report["findings_count"], "Cisco findings_count", minimum=0)
    if finding_count != len(findings):
        raise VendorReportError("Cisco findings_count does not match findings")

    seconds = _number(
        report["scan_duration_seconds"],
        "Cisco scan_duration_seconds",
        minimum=0,
        maximum=86_400,
    )
    milliseconds = _integer(
        report["duration_ms"],
        "Cisco duration_ms",
        minimum=0,
        maximum=86_400_000,
    )
    if int(seconds * 1000) != milliseconds:
        raise VendorReportError("Cisco duration fields are incoherent")
    _timestamp(report["timestamp"], "Cisco timestamp")

    analyzers = _list(report["analyzers_used"], "Cisco analyzers_used", 16)
    if tuple(analyzers) != _CISCO_ANALYZERS:
        raise VendorReportError("Cisco analyzer coverage is incomplete or unexpected")
    if "analyzers_failed" in report:
        failed = _list(report["analyzers_failed"], "Cisco analyzers_failed", 16)
        if failed:
            raise VendorReportError("Cisco reported an analyzer failure")

    metadata = _object(report["scan_metadata"], "Cisco scan_metadata")
    _keys(
        metadata,
        required={
            "policy_name",
            "policy_version",
            "policy_preset_base",
            "policy_fingerprint_sha256",
        },
        field="Cisco scan_metadata",
    )
    expected_policy = {
        "policy_name": "strict",
        "policy_version": "1.0",
        "policy_preset_base": "strict",
        "policy_fingerprint_sha256": _CISCO_POLICY_FINGERPRINT,
    }
    if metadata != expected_policy:
        raise VendorReportError("Cisco strict policy fingerprint is not pinned")

    observations: list[Observation] = [
        _observation(
            subject_digest,
            "CISCO_SCAN_COMPLETED",
            "info",
            {
                "vendor": "cisco-ai-skill-scanner",
                "vendor_version": "2.0.12",
                "report_sha256": report_digest,
                "finding_count": finding_count,
                "analyzers": list(_CISCO_ANALYZERS),
            },
        )
    ]
    observed_severities: list[str] = []
    for index, value in enumerate(findings):
        finding = _object(value, f"Cisco finding {index}")
        _exact_keys(finding, _CISCO_FINDING_KEYS, f"Cisco finding {index}")
        rule_id = _text(finding["rule_id"], "Cisco rule_id", 1024, empty=False)
        finding_id = _text(finding["id"], "Cisco finding id", 1024, empty=False)
        category = _text(finding["category"], "Cisco category", 256, empty=False)
        severity = _text(
            finding["severity"], "Cisco finding severity", 16, empty=False
        )
        if severity not in _SEVERITIES:
            raise VendorReportError("Cisco finding severity is invalid")
        observed_severities.append(severity)
        title = _text(finding["title"], "Cisco title", 512, empty=False)
        description = _text(
            finding["description"], "Cisco description", 2048, empty=False
        )
        remediation = _optional_text(
            finding["remediation"], "Cisco remediation", 2048
        )
        _optional_text(finding["snippet"], "Cisco snippet", 4096)
        file_path = _optional_relative_path(
            finding["file_path"], workspace, "Cisco file_path"
        )
        line_number = _optional_integer(
            finding["line_number"], "Cisco line_number", minimum=1
        )
        analyzer = _optional_text(finding["analyzer"], "Cisco analyzer", 128)
        if analyzer not in {None, "static", "bytecode", "pipeline", "behavioral", "analyzability"}:
            raise VendorReportError("Cisco finding names an unexpected analyzer")
        finding_metadata = _object(finding["metadata"], "Cisco finding metadata")
        _bounded_json(finding_metadata, "Cisco finding metadata", 64 * 1024)

        evidence: dict[str, Any] = {
            "vendor": "cisco-ai-skill-scanner",
            "vendor_version": "2.0.12",
            "report_sha256": report_digest,
            "finding": {
                "id": finding_id,
                "rule_id": rule_id,
                "category": category,
                "file_path": file_path,
                "line_number": line_number,
                "analyzer": analyzer,
                "title": title,
                "description": description,
                "remediation": remediation,
            },
        }
        observations.append(
            _observation(
                subject_digest,
                _reason_code("CISCO", rule_id),
                severity.lower(),
                evidence,
            )
        )

    maximum = (
        max(observed_severities, key=("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").index)
        if observed_severities
        else "SAFE"
    )
    if maximum_severity != maximum:
        raise VendorReportError("Cisco max_severity does not match findings")
    is_safe = maximum not in {"HIGH", "CRITICAL"}
    if report["is_safe"] is not is_safe:
        raise VendorReportError("Cisco is_safe does not match findings")
    return _sorted(observations)


def normalize_nvidia_report(
    raw_report: bytes,
    *,
    subject_digest: str,
    returncode: int,
    expected_workspace: str = "/workspace",
) -> tuple[Observation, ...]:
    """Normalize one NVIDIA SkillSpector 2.4.3 single-skill JSON report."""

    report, report_digest = _load_report(raw_report)
    _subject(subject_digest)
    workspace = _workspace(expected_workspace)
    _exact_keys(
        report,
        {
            "skill",
            "risk_assessment",
            "components",
            "issues",
            "suppressed_count",
            "suppressed",
            "metadata",
            "analysis_completeness",
        },
        "NVIDIA report",
    )

    skill = _object(report["skill"], "NVIDIA skill")
    _exact_keys(skill, {"name", "source", "scanned_at"}, "NVIDIA skill")
    _text(skill["name"], "NVIDIA skill name", 512, empty=False)
    if skill["source"] != expected_workspace:
        raise VendorReportError("NVIDIA skill source does not match the workspace")
    _workspace(skill["source"])
    _timestamp(skill["scanned_at"], "NVIDIA scanned_at")

    risk = _object(report["risk_assessment"], "NVIDIA risk_assessment")
    _exact_keys(risk, {"score", "severity", "recommendation"}, "NVIDIA risk_assessment")
    score = _integer(risk["score"], "NVIDIA risk score", minimum=0, maximum=100)
    band = "CRITICAL" if score >= 81 else "HIGH" if score >= 51 else "MEDIUM" if score >= 21 else "LOW"
    recommendation = "DO_NOT_INSTALL" if score >= 51 else "CAUTION" if score >= 21 else "SAFE"
    if risk["severity"] != band or risk["recommendation"] != recommendation:
        raise VendorReportError("NVIDIA risk assessment fields are incoherent")
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or returncode not in {0, 1}
    ):
        raise VendorReportError("NVIDIA completed reports require exit status 0 or 1")
    if (score <= 50 and returncode != 0) or (score > 50 and returncode != 1):
        raise VendorReportError("NVIDIA exit status does not match risk score")

    components = _list(report["components"], "NVIDIA components", _MAX_COMPONENTS)
    if not components:
        raise VendorReportError("NVIDIA report must cover at least one component")
    component_paths: set[str] = set()
    executable_paths: set[str] = set()
    for index, value in enumerate(components):
        component = _object(value, f"NVIDIA component {index}")
        _exact_keys(
            component,
            {"path", "type", "lines", "executable", "size_bytes"},
            f"NVIDIA component {index}",
        )
        path = _relative_path(component["path"], workspace, "NVIDIA component path")
        if path in component_paths:
            raise VendorReportError("NVIDIA component paths must be unique")
        component_paths.add(path)
        _text(component["type"], "NVIDIA component type", 128, empty=False)
        _integer(component["lines"], "NVIDIA component lines", minimum=0)
        if not isinstance(component["executable"], bool):
            raise VendorReportError("NVIDIA component executable must be a boolean")
        if component["executable"]:
            executable_paths.add(path)
        _integer(component["size_bytes"], "NVIDIA component size_bytes", minimum=0)

    metadata = _object(report["metadata"], "NVIDIA metadata")
    _exact_keys(
        metadata,
        {
            "has_executable_scripts",
            "skillspector_version",
            "llm_requested",
            "llm_available",
            "meta_analysis_applied",
            "filtering_mode",
        },
        "NVIDIA metadata",
    )
    if metadata != {
        "has_executable_scripts": bool(executable_paths),
        "skillspector_version": "2.4.3",
        "llm_requested": False,
        "llm_available": False,
        "meta_analysis_applied": False,
        "filtering_mode": "heuristic",
    }:
        raise VendorReportError("NVIDIA no-LLM configuration is incomplete")

    if _integer(report["suppressed_count"], "NVIDIA suppressed_count", minimum=0) != 0:
        raise VendorReportError("NVIDIA suppressed findings are not allowed")
    if _list(report["suppressed"], "NVIDIA suppressed", _MAX_FINDINGS):
        raise VendorReportError("NVIDIA suppressed findings are not allowed")

    issues = _list(report["issues"], "NVIDIA issues", _MAX_FINDINGS)
    completeness = _object(
        report["analysis_completeness"], "NVIDIA analysis_completeness"
    )
    _exact_keys(
        completeness,
        {
            "total_components",
            "scanned_components",
            "coverage_percent",
            "llm_analysis",
            "findings_before_filtering",
            "findings_after_filtering",
            "limitations",
            "is_complete",
        },
        "NVIDIA analysis_completeness",
    )
    total = _integer(
        completeness["total_components"], "NVIDIA total_components", minimum=0
    )
    scanned = _integer(
        completeness["scanned_components"], "NVIDIA scanned_components", minimum=0
    )
    coverage = _number(
        completeness["coverage_percent"],
        "NVIDIA coverage_percent",
        minimum=0,
        maximum=100,
    )
    if total != len(components) or scanned != total or coverage != 100:
        raise VendorReportError("NVIDIA component coverage is incomplete")
    if completeness["llm_analysis"] != "skipped":
        raise VendorReportError("NVIDIA LLM analysis must be skipped")
    before = _integer(
        completeness["findings_before_filtering"],
        "NVIDIA findings_before_filtering",
        minimum=0,
    )
    after = _integer(
        completeness["findings_after_filtering"],
        "NVIDIA findings_after_filtering",
        minimum=0,
    )
    if before < after or after != len(issues):
        raise VendorReportError("NVIDIA finding counts are incoherent")
    dropped = before - after
    expected_limitations = ["LLM meta-analysis was disabled (--no-llm)"]
    if dropped:
        expected_limitations.append(
            f"{dropped} finding(s) filtered by meta-analyzer or heuristics"
        )
    if completeness["limitations"] != expected_limitations:
        raise VendorReportError("NVIDIA limitations do not match scan configuration")
    if completeness["is_complete"] is not False:
        raise VendorReportError("NVIDIA no-LLM report must declare incomplete analysis")

    observations: list[Observation] = [
        _observation(
            subject_digest,
            "NVIDIA_SCAN_COMPLETED",
            "info",
            {
                "vendor": "nvidia-skillspector",
                "vendor_version": "2.4.3",
                "report_sha256": report_digest,
                "finding_count": len(issues),
                "component_count": len(components),
            },
        ),
        _observation(
            subject_digest,
            "NVIDIA_ANALYSIS_INCOMPLETE",
            "medium",
            {
                "vendor": "nvidia-skillspector",
                "vendor_version": "2.4.3",
                "report_sha256": report_digest,
                "is_complete": False,
                "llm_analysis": "skipped",
                "limitations": expected_limitations,
            },
        ),
    ]
    if score > 50:
        observations.append(
            _observation(
                subject_digest,
                "NVIDIA_AGGREGATE_RISK_HIGH",
                "critical" if score >= 81 else "high",
                {
                    "vendor": "nvidia-skillspector",
                    "vendor_version": "2.4.3",
                    "report_sha256": report_digest,
                    "score": score,
                    "severity": band,
                    "recommendation": recommendation,
                },
            )
        )
    for index, value in enumerate(issues):
        issue = _object(value, f"NVIDIA issue {index}")
        _exact_keys(issue, _NVIDIA_ISSUE_KEYS, f"NVIDIA issue {index}")
        rule_id = _text(issue["id"], "NVIDIA issue id", 1024, empty=False)
        severity = _text(issue["severity"], "NVIDIA issue severity", 16, empty=False)
        if severity not in _SEVERITIES - {"INFO"}:
            raise VendorReportError("NVIDIA issue severity is invalid")
        confidence = _number(
            issue["confidence"], "NVIDIA confidence", minimum=0, maximum=1
        )
        category = _optional_text(issue["category"], "NVIDIA category", 256)
        pattern = _optional_text(issue["pattern"], "NVIDIA pattern", 512)
        _optional_text(issue["finding"], "NVIDIA finding snippet", 4096)
        explanation = _optional_text(
            issue["explanation"], "NVIDIA explanation", 2048
        )
        if not explanation:
            raise VendorReportError("NVIDIA explanation must not be empty")
        remediation = _optional_text(
            issue["remediation"], "NVIDIA remediation", 2048
        )
        _optional_text(issue["code_snippet"], "NVIDIA code_snippet", 4096)
        intent = _optional_text(issue["intent"], "NVIDIA intent", 512)
        tags = _list(issue["tags"], "NVIDIA tags", 64)
        normalized_tags = [
            _text(tag, "NVIDIA tag", 128, empty=False) for tag in tags
        ]
        location = _object(issue["location"], "NVIDIA location")
        _exact_keys(
            location, {"file", "start_line", "end_line"}, "NVIDIA location"
        )
        file_path = _relative_path(
            location["file"], workspace, "NVIDIA location file"
        )
        if file_path not in component_paths:
            raise VendorReportError("NVIDIA issue path is outside component coverage")
        start_line = _integer(
            location["start_line"], "NVIDIA start_line", minimum=1
        )
        end_line = _optional_integer(
            location["end_line"], "NVIDIA end_line", minimum=start_line
        )
        observations.append(
            _observation(
                subject_digest,
                _reason_code("NVIDIA", rule_id),
                severity.lower(),
                {
                    "vendor": "nvidia-skillspector",
                    "vendor_version": "2.4.3",
                    "report_sha256": report_digest,
                    "finding": {
                        "rule_id": rule_id,
                        "category": category,
                        "pattern": pattern,
                        "confidence": confidence,
                        "file_path": file_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "explanation": explanation,
                        "remediation": remediation,
                        "intent": intent,
                        "tags": normalized_tags,
                    },
                },
            )
        )
    if dropped:
        observations.append(
            _observation(
                subject_digest,
                "NVIDIA_FINDINGS_FILTERED",
                "medium",
                {
                    "vendor": "nvidia-skillspector",
                    "vendor_version": "2.4.3",
                    "report_sha256": report_digest,
                    "findings_before": before,
                    "findings_after": after,
                    "findings_filtered": dropped,
                },
            )
        )
    return _sorted(observations)


def _load_report(raw_report: bytes) -> tuple[dict[str, Any], str]:
    if not isinstance(raw_report, bytes):
        raise VendorReportError("vendor report must be bytes")
    if len(raw_report) > MAX_VENDOR_REPORT_BYTES:
        raise VendorReportError("vendor report exceeds the input byte limit")
    report_digest = "sha256:" + hashlib.sha256(raw_report).hexdigest()
    try:
        document = json.loads(
            raw_report.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        _finite(document)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise VendorReportError(f"vendor report is invalid JSON: {exc}") from exc
    return _object(document, "vendor report"), report_digest


def _finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("invalid Unicode scalar value") from exc
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _bounded_json(value: Any, field: str, maximum_bytes: int) -> None:
    try:
        canonical = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise VendorReportError(f"{field} is not canonical JSON: {exc}") from exc
    if len(canonical) > maximum_bytes:
        raise VendorReportError(f"{field} exceeds its byte limit")


def _subject(value: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise VendorReportError("subject_digest must be a lowercase sha256 digest")


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VendorReportError(f"{field} must be an object")
    return value


def _list(value: Any, field: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise VendorReportError(f"{field} must be an array")
    if len(value) > maximum:
        raise VendorReportError(f"{field} exceeds its item limit")
    return value


def _keys(
    value: dict[str, Any],
    *,
    required: set[str],
    field: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    if not required <= value.keys() or not value.keys() <= required | optional:
        raise VendorReportError(f"{field} has missing or unknown fields")


def _exact_keys(value: dict[str, Any], expected: set[str] | frozenset[str], field: str) -> None:
    if value.keys() != expected:
        raise VendorReportError(f"{field} has missing or unknown fields")


def _text(
    value: Any, field: str, maximum_bytes: int, *, empty: bool = True
) -> str:
    if not isinstance(value, str):
        raise VendorReportError(f"{field} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VendorReportError(f"{field} is not valid Unicode text") from exc
    if (not empty and not value) or len(encoded) > maximum_bytes:
        raise VendorReportError(f"{field} is empty or exceeds its byte limit")
    return value


def _optional_text(value: Any, field: str, maximum_bytes: int) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum_bytes)


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorReportError(f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        raise VendorReportError(f"{field} is outside its allowed range")
    return value


def _optional_integer(
    value: Any,
    field: str,
    *,
    minimum: int,
) -> int | None:
    if value is None:
        return None
    return _integer(value, field, minimum=minimum)


def _number(
    value: Any,
    field: str,
    *,
    minimum: float,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VendorReportError(f"{field} must be a number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise VendorReportError(f"{field} must be finite") from exc
    if not math.isfinite(result):
        raise VendorReportError(f"{field} must be finite")
    if result < minimum or (maximum is not None and result > maximum):
        raise VendorReportError(f"{field} is outside its allowed range")
    return result


def _timestamp(value: Any, field: str) -> None:
    text = _text(value, field, 128, empty=False)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorReportError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise VendorReportError(f"{field} must include a UTC offset")


def _workspace(value: Any) -> PurePosixPath:
    text = _text(value, "workspace", 4096, empty=False)
    path = PurePosixPath(text)
    if not path.is_absolute() or str(path) != text or ".." in path.parts:
        raise VendorReportError("workspace must be a canonical absolute POSIX path")
    return path


def _relative_path(value: Any, workspace: PurePosixPath, field: str) -> str:
    text = _text(value, field, 4096, empty=False)
    if "\\" in text or any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise VendorReportError(f"{field} is not a canonical POSIX path")
    path = PurePosixPath(text)
    if path.is_absolute():
        if str(path) != text:
            raise VendorReportError(f"{field} is not canonical")
        try:
            path = path.relative_to(workspace)
        except ValueError as exc:
            raise VendorReportError(f"{field} escapes the workspace") from exc
    elif str(path) != text:
        raise VendorReportError(f"{field} is not canonical")
    if not path.parts or str(path) == "." or any(part in {".", ".."} for part in path.parts):
        raise VendorReportError(f"{field} escapes the workspace")
    return path.as_posix()


def _optional_relative_path(
    value: Any, workspace: PurePosixPath, field: str
) -> str | None:
    if value is None:
        return None
    return _relative_path(value, workspace, field)


def _reason_code(vendor: str, rule_id: str) -> str:
    candidate = f"{vendor}_{rule_id}"
    if (
        len(candidate) <= 128
        and _CANONICAL_RULE.fullmatch(rule_id)
        and candidate not in _RESERVED_REASON_CODES
    ):
        return candidate
    digest = hashlib.sha256(rule_id.encode("utf-8")).hexdigest().upper()
    return f"{vendor}_RULE_SHA256_{digest}"


def _observation(
    subject_digest: str,
    reason_code: str,
    severity: str,
    evidence: dict[str, Any],
) -> Observation:
    document = {
        "schema": OBSERVATION_SCHEMA,
        "subject_digest": subject_digest,
        "reason_code": reason_code,
        "severity": severity,
        "evidence": evidence,
    }
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return Observation(
        schema=OBSERVATION_SCHEMA,
        subject_digest=subject_digest,
        reason_code=reason_code,
        severity=severity,
        document_json=canonical,
    )


def _sorted(observations: list[Observation]) -> tuple[Observation, ...]:
    return tuple(
        sorted(
            observations,
            key=lambda observation: (
                observation.reason_code,
                observation.severity,
                observation.document_json,
            ),
        )
    )
