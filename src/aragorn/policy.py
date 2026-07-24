"""Deterministic fail-closed admission policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .analyze import AnalyzerResult, Observation


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True, slots=True)
class Policy:
    required_analyzers: tuple[str, ...] = ()
    hard_deny_reason_codes: frozenset[str] = field(default_factory=frozenset)
    review_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"medium", "high", "critical"})
    )

    def __post_init__(self) -> None:
        required = _clean_strings(self.required_analyzers, "required analyzer")
        deny_codes = _clean_strings(self.hard_deny_reason_codes, "hard-deny reason code")
        severities = tuple(
            sorted(
                _clean_strings(self.review_severities, "review severity"),
                key=lambda severity: _SEVERITY_RANK.get(severity.lower(), -1),
            )
        )
        normalized_severities = tuple(severity.lower() for severity in severities)
        unknown = sorted(set(normalized_severities) - _SEVERITY_RANK.keys())
        if unknown:
            raise ValueError(f"unknown review severity: {', '.join(unknown)}")
        object.__setattr__(self, "required_analyzers", required)
        object.__setattr__(self, "hard_deny_reason_codes", frozenset(deny_codes))
        object.__setattr__(self, "review_severities", frozenset(normalized_severities))


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: str
    reason_codes: tuple[str, ...] = ()


def evaluate_policy(
    policy: Policy,
    *,
    closure: Mapping[str, object],
    results: Iterable[AnalyzerResult],
) -> Decision:
    """Return ERROR, DENY, REVIEW, or ALLOW in that precedence order."""

    ordered_results = tuple(
        sorted(
            results,
            key=lambda result: (
                result.name,
                result.version,
                result.config_digest,
                result.status,
                result.error_code or "",
            ),
        )
    )
    errors: set[str] = set()
    unresolved = closure.get("unresolved", []) if isinstance(closure, Mapping) else None
    if (
        not isinstance(closure, Mapping)
        or closure.get("status") != "complete"
        or closure.get("scope") != "artifact_graph"
        or not isinstance(unresolved, list)
        or bool(unresolved)
    ):
        errors.add("ARTIFACT_CLOSURE_INCOMPLETE")

    required_analyzers = frozenset(policy.required_analyzers)
    for analyzer_name in policy.required_analyzers:
        matching = tuple(result for result in ordered_results if result.name == analyzer_name)
        if not matching:
            errors.add(f"REQUIRED_ANALYZER_MISSING:{analyzer_name}")

    for result in ordered_results:
        if result.ok:
            continue
        prefix = (
            "REQUIRED_ANALYZER_FAILED"
            if result.name in required_analyzers
            else "ANALYZER_FAILED"
        )
        errors.add(f"{prefix}:{result.name}:{result.error_code or 'UNKNOWN'}")
    if errors:
        return Decision("ERROR", tuple(sorted(errors)))

    observations = tuple(
        sorted(
            (
                observation
                for result in ordered_results
                if result.ok
                for observation in result.observations
            ),
            key=_observation_key,
        )
    )
    unknown_severities = {
        observation.severity
        for observation in observations
        if observation.severity not in _SEVERITY_RANK
    }
    if unknown_severities:
        return Decision(
            "ERROR",
            tuple(f"UNKNOWN_SEVERITY:{severity}" for severity in sorted(unknown_severities)),
        )

    hard_denies = sorted(
        {
            observation.reason_code
            for observation in observations
            if observation.reason_code in policy.hard_deny_reason_codes
        }
    )
    if hard_denies:
        return Decision("DENY", tuple(hard_denies))

    if policy.review_severities:
        threshold = min(_SEVERITY_RANK[severity] for severity in policy.review_severities)
        review_reasons = sorted(
            {
                observation.reason_code
                for observation in observations
                if _SEVERITY_RANK[observation.severity] >= threshold
            }
        )
        if review_reasons:
            return Decision("REVIEW", tuple(review_reasons))

    return Decision("ALLOW")


def _clean_strings(values: Iterable[str], label: str) -> tuple[str, ...]:
    cleaned: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        cleaned.add(value.strip())
    return tuple(sorted(cleaned))


def _observation_key(observation: Observation) -> tuple[str, str, str, str]:
    return (
        observation.reason_code,
        observation.severity,
        observation.subject_digest,
        observation.document_json,
    )
