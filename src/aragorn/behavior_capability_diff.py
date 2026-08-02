"""Deterministic category-only declared-versus-observed behavior diff."""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_json

SCHEMA = "aragorn/behavior-capability-diff/v1"
AUTHORITY = "CATEGORY_DIFF_ONLY_NOT_BEHAVIOR_EVIDENCE_OR_AUTHORITY"
SCOPE = "category-only/v1"
CAPABILITY_KINDS = frozenset(
    {
        "file-read",
        "file-write",
        "memory-write",
        "network-connect",
        "process-exec",
        "tool-call",
    }
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CAPABILITY_FIELDS = (
    "declared_capabilities",
    "observed_capabilities",
    "matched_capabilities",
    "undeclared_observed_capabilities",
    "declared_not_observed_capabilities",
)
_FIELDS = {
    "schema",
    "authority",
    "scope",
    "subject_digest",
    *_CAPABILITY_FIELDS,
}


class BehaviorCapabilityDiffError(ValueError):
    """A behavior capability diff is malformed or internally inconsistent."""


def derive_behavior_capability_diff(
    *,
    subject_digest: str,
    declared_capabilities: Collection[str],
    observed_capabilities: Collection[str],
) -> dict[str, Any]:
    """Derive a category-only diff without making a behavior or safety claim."""

    subject = _digest(subject_digest, "subject digest")
    declared = _capabilities(declared_capabilities, "declared capabilities")
    observed = _capabilities(observed_capabilities, "observed capabilities")
    declared_set = set(declared)
    observed_set = set(observed)
    return {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "scope": SCOPE,
        "subject_digest": subject,
        "declared_capabilities": declared,
        "observed_capabilities": observed,
        "matched_capabilities": sorted(declared_set & observed_set),
        "undeclared_observed_capabilities": sorted(observed_set - declared_set),
        "declared_not_observed_capabilities": sorted(declared_set - observed_set),
    }


def verify_behavior_capability_diff(
    document: object,
    *,
    expected_subject_digest: str,
    expected_declared_capabilities: Collection[str],
    expected_observed_capabilities: Collection[str],
) -> dict[str, Any]:
    """Re-derive one submitted diff from caller-held subject and capability sets."""

    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise BehaviorCapabilityDiffError("behavior capability diff shape is invalid")
    for field in _CAPABILITY_FIELDS:
        value = document[field]
        if not isinstance(value, list) or value != _capabilities(value, field):
            raise BehaviorCapabilityDiffError(f"{field} must be a canonical array")
    expected = derive_behavior_capability_diff(
        subject_digest=expected_subject_digest,
        declared_capabilities=expected_declared_capabilities,
        observed_capabilities=expected_observed_capabilities,
    )
    try:
        matches = canonical_json(document) == canonical_json(expected)
    except (RecursionError, WorkerProtocolError) as exc:
        raise BehaviorCapabilityDiffError(
            f"behavior capability diff is not canonical JSON: {exc}"
        ) from exc
    if not matches:
        raise BehaviorCapabilityDiffError(
            "behavior capability diff does not match caller-held inputs"
        )
    return expected


def _capabilities(value: object, label: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        raise BehaviorCapabilityDiffError(f"{label} must be a bounded collection")
    if len(value) > len(CAPABILITY_KINDS):
        raise BehaviorCapabilityDiffError(f"{label} exceed the category limit")
    items = list(value)
    if any(not isinstance(item, str) or item not in CAPABILITY_KINDS for item in items):
        raise BehaviorCapabilityDiffError(f"{label} contain an unknown category")
    return sorted(set(items))


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BehaviorCapabilityDiffError(f"{label} is not a canonical SHA-256 digest")
    return value
