"""Deterministic, digest-bound decisions for one measured runtime action."""

from __future__ import annotations

import re
from typing import Any

from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_POLICY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_MAX_ALLOW_RULES = 64
_MAX_REVOKED_SKILLS = 1024
_MAX_REQUEST_LIFETIME_SECONDS = 5
_MAX_REVOCATION_LIFETIME_SECONDS = 15
_MAX_HEALTH_LIFETIME_SECONDS = 15

_REQUEST_FIELDS = {
    "schema",
    "authority",
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
    "policy_digest",
    "policy_version",
    "issued_at_unix",
    "expires_at_unix",
}
_ATTRIBUTION_FIELDS = (
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
)
_ACTION_FIELDS = ("operation_digest", "path_digest", "payload_digest")
_MEASUREMENT_FIELDS = _ATTRIBUTION_FIELDS + _ACTION_FIELDS
_RULE_FIELDS = {
    "runtime_digest",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
}


class RuntimeActionStateError(ValueError):
    """Trusted decision state is malformed, so no effect may proceed."""


class _InvalidRequest(ValueError):
    pass


def evaluate_runtime_action(
    request: object,
    policy: object,
    *,
    now_unix: int,
    active: object | None,
    measured_action: object | None,
    revocations: object,
    minimum_revocation_generation: int,
    mediator_health: object,
    minimum_mediator_health_epoch: int,
) -> dict[str, Any]:
    """Return ALLOW only when every request, state, and measurement binding matches.

    Inputs are decoded JSON values. The later transport layer remains responsible
    for canonical byte framing, peer authentication, replay consumption, and the
    effect itself.
    """

    now = _integer(now_unix, "trusted current time")
    minimum_generation = _positive_integer(
        minimum_revocation_generation,
        "minimum revocation generation",
    )
    minimum_health_epoch = _positive_integer(
        minimum_mediator_health_epoch,
        "minimum mediator health epoch",
    )
    policy_document, allow_rules = _policy(policy)
    revocation_document, revoked_skills = _revocations(revocations)
    health_document = _health(mediator_health)
    active_document = None if active is None else _active(active)
    measured_document = (
        None if measured_action is None else _measured_action(measured_action)
    )

    request_digest = _document_digest(request, "runtime action request")
    policy_digest = _document_digest(policy_document, "runtime action policy")
    revocation_digest = _document_digest(
        revocation_document,
        "runtime action revocations",
    )
    health_digest = _document_digest(health_document, "runtime mediator health")
    active_digest = (
        None
        if active_document is None
        else _document_digest(active_document, "runtime active context")
    )
    measured_digest = (
        None
        if measured_document is None
        else _document_digest(measured_document, "measured runtime action")
    )

    try:
        action_request = _request(request)
    except _InvalidRequest:
        reasons = ["ACTION_REQUEST_INVALID"]
    else:
        reasons = []
        if active_document is None:
            reasons.append("ACTION_UNATTRIBUTED")
        elif any(
            action_request[field] != active_document[field]
            for field in _ATTRIBUTION_FIELDS
        ):
            reasons.append("ACTION_ATTRIBUTION_MISMATCH")

        if measured_document is None:
            reasons.append("ACTION_UNMEASURED")
        elif any(
            action_request[field] != measured_document[field]
            for field in _MEASUREMENT_FIELDS
        ):
            reasons.append("ACTION_MEASUREMENT_MISMATCH")

        issued = action_request["issued_at_unix"]
        expires = action_request["expires_at_unix"]
        if (
            issued > now
            or now >= expires
            or expires <= issued
            or expires - issued > _MAX_REQUEST_LIFETIME_SECONDS
        ):
            reasons.append("ACTION_REQUEST_STALE")

        if (
            action_request["policy_digest"] != policy_digest
            or action_request["policy_version"] != policy_document["version"]
        ):
            reasons.append("POLICY_BINDING_MISMATCH")
        if action_request["active_skill_digest"] in revoked_skills:
            reasons.append("ACTIVE_SKILL_REVOKED")
        if (
            revocation_document["source_digest"]
            != policy_document["revocation_source_digest"]
        ):
            reasons.append("REVOCATION_SOURCE_BINDING_MISMATCH")
        if (
            revocation_document["observed_at_unix"] > now
            or now >= revocation_document["expires_at_unix"]
        ):
            reasons.append("REVOCATION_SNAPSHOT_STALE")
        if revocation_document["generation"] < minimum_generation:
            reasons.append("REVOCATION_ROLLBACK")

        if health_document["runtime_digest"] != action_request["runtime_digest"] or (
            active_document is not None
            and health_document["runtime_digest"] != active_document["runtime_digest"]
        ):
            reasons.append("MEDIATOR_HEALTH_BINDING_MISMATCH")
        if health_document["sensor_digest"] != policy_document["sensor_digest"]:
            reasons.append("MEDIATOR_SENSOR_BINDING_MISMATCH")
        if (
            health_document["observed_at_unix"] > now
            or now >= health_document["expires_at_unix"]
        ):
            reasons.append("MEDIATOR_HEALTH_STALE")
        if health_document["status"] != "healthy":
            reasons.append("MEDIATOR_UNHEALTHY")
        if health_document["epoch"] < minimum_health_epoch:
            reasons.append("MEDIATOR_HEALTH_ROLLBACK")

        rule = {field: action_request[field] for field in _RULE_FIELDS}
        if rule not in allow_rules:
            reasons.append("ACTION_NOT_ALLOWED")

    reasons = sorted(set(reasons))
    return {
        "schema": "aragorn/runtime-action-decision/v1",
        "authority": (
            "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        ),
        "request_digest": request_digest,
        "active_context_digest": active_digest,
        "measured_action_digest": measured_digest,
        "policy_digest": policy_digest,
        "policy_version": policy_document["version"],
        "evaluated_at_unix": now,
        "revocation_snapshot_digest": revocation_digest,
        "revocation_generation": revocation_document["generation"],
        "minimum_revocation_generation": minimum_generation,
        "mediator_health_digest": health_digest,
        "mediator_health_epoch": health_document["epoch"],
        "minimum_mediator_health_epoch": minimum_health_epoch,
        "verdict": "ALLOW" if not reasons else "BLOCK",
        "reason_codes": reasons,
    }


def _request(value: object) -> dict[str, Any]:
    try:
        document = _exact(
            value, _REQUEST_FIELDS, "runtime action request", request=True
        )
        if document["schema"] != "aragorn/runtime-action-request/v1":
            raise _InvalidRequest
        if document["authority"] != "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY":
            raise _InvalidRequest
        for field in ("runtime_digest", "active_skill_digest", *_ACTION_FIELDS):
            _digest(document[field], field, request=True)
        for field in ("session_id", "run_id", "tool_call_id"):
            _identifier(document[field], field, request=True)
        _digest(document["policy_digest"], "policy digest", request=True)
        _positive_integer(document["policy_version"], "policy version", request=True)
        _integer(document["issued_at_unix"], "request issue time", request=True)
        _integer(document["expires_at_unix"], "request expiry", request=True)
        return document
    except _InvalidRequest:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise _InvalidRequest from exc


def _policy(value: object) -> tuple[dict[str, Any], list[dict[str, str]]]:
    document = _exact(
        value,
        {
            "schema",
            "id",
            "version",
            "default",
            "sensor_digest",
            "revocation_source_digest",
            "allow",
        },
        "runtime action policy",
    )
    if document["schema"] != "aragorn/runtime-action-policy/v1":
        raise RuntimeActionStateError("runtime action policy schema is unsupported")
    if (
        not isinstance(document["id"], str)
        or _POLICY_ID.fullmatch(document["id"]) is None
    ):
        raise RuntimeActionStateError("runtime action policy id is invalid")
    _positive_integer(document["version"], "runtime action policy version")
    _digest(document["sensor_digest"], "runtime action policy sensor digest")
    _digest(
        document["revocation_source_digest"],
        "runtime action policy revocation source digest",
    )
    if document["default"] != "BLOCK":
        raise RuntimeActionStateError("runtime action policy must default to BLOCK")
    values = document["allow"]
    if not isinstance(values, list) or len(values) > _MAX_ALLOW_RULES:
        raise RuntimeActionStateError("runtime action allow rules are invalid")
    rules = []
    for candidate in values:
        rule = _exact(candidate, _RULE_FIELDS, "runtime action allow rule")
        rules.append({field: _digest(rule[field], field) for field in _RULE_FIELDS})
    _canonical_order(rules, "runtime action allow rules")
    return document, rules


def _active(value: object) -> dict[str, Any]:
    document = _exact(
        value,
        {"schema", *_ATTRIBUTION_FIELDS},
        "runtime active context",
    )
    if document["schema"] != "aragorn/runtime-active-context/v1":
        raise RuntimeActionStateError("runtime active context schema is unsupported")
    _digest(document["runtime_digest"], "active runtime digest")
    _digest(document["active_skill_digest"], "active skill digest")
    for field in ("session_id", "run_id", "tool_call_id"):
        _identifier(document[field], f"active {field}")
    return document


def _measured_action(value: object) -> dict[str, Any]:
    document = _exact(
        value,
        {"schema", *_MEASUREMENT_FIELDS},
        "measured runtime action",
    )
    if document["schema"] != "aragorn/measured-runtime-action/v1":
        raise RuntimeActionStateError("measured runtime action schema is unsupported")
    for field in ("runtime_digest", "active_skill_digest", *_ACTION_FIELDS):
        _digest(document[field], f"measured {field}")
    for field in ("session_id", "run_id", "tool_call_id"):
        _identifier(document[field], f"measured {field}")
    return document


def _revocations(value: object) -> tuple[dict[str, Any], set[str]]:
    document = _exact(
        value,
        {
            "schema",
            "source_digest",
            "generation",
            "observed_at_unix",
            "expires_at_unix",
            "skill_digests",
        },
        "runtime action revocations",
    )
    if document["schema"] != "aragorn/runtime-action-revocations/v1":
        raise RuntimeActionStateError("runtime action revocation schema is unsupported")
    _digest(document["source_digest"], "runtime action revocation source digest")
    _positive_integer(document["generation"], "runtime action revocation generation")
    observed = _integer(
        document["observed_at_unix"],
        "runtime action revocation observation time",
    )
    expires = _integer(
        document["expires_at_unix"],
        "runtime action revocation expiry",
    )
    if expires <= observed or expires - observed > _MAX_REVOCATION_LIFETIME_SECONDS:
        raise RuntimeActionStateError("runtime action revocation lifetime is invalid")
    values = document["skill_digests"]
    if not isinstance(values, list) or len(values) > _MAX_REVOKED_SKILLS:
        raise RuntimeActionStateError("revoked skill digests are invalid")
    digests = [_digest(item, "revoked skill digest") for item in values]
    if digests != sorted(set(digests)):
        raise RuntimeActionStateError("revoked skill digests must be sorted and unique")
    return document, set(digests)


def _health(value: object) -> dict[str, Any]:
    document = _exact(
        value,
        {
            "schema",
            "runtime_digest",
            "sensor_digest",
            "epoch",
            "status",
            "observed_at_unix",
            "expires_at_unix",
        },
        "runtime mediator health",
    )
    if document["schema"] != "aragorn/runtime-mediator-health/v1":
        raise RuntimeActionStateError("runtime mediator health schema is unsupported")
    _digest(document["runtime_digest"], "mediator runtime digest")
    _digest(document["sensor_digest"], "mediator sensor digest")
    _positive_integer(document["epoch"], "mediator health epoch")
    if document["status"] not in ("healthy", "unhealthy"):
        raise RuntimeActionStateError("runtime mediator health status is invalid")
    observed = _integer(document["observed_at_unix"], "mediator observation time")
    expires = _integer(document["expires_at_unix"], "mediator health expiry")
    if expires <= observed or expires - observed > _MAX_HEALTH_LIFETIME_SECONDS:
        raise RuntimeActionStateError("runtime mediator health lifetime is invalid")
    return document


def _exact(
    value: object,
    fields: set[str],
    label: str,
    *,
    request: bool = False,
) -> dict[str, Any]:
    error = _InvalidRequest if request else RuntimeActionStateError
    if not isinstance(value, dict) or set(value) != fields:
        raise error(f"{label} fields are invalid")
    return value


def _document_digest(value: object, label: str) -> str:
    try:
        return canonical_digest(value)
    except (RecursionError, WorkerProtocolError) as exc:
        raise RuntimeActionStateError(f"{label} is not JSON-compatible") from exc


def _canonical_order(values: list[object], label: str) -> None:
    try:
        encoded = [canonical_json(value) for value in values]
    except (RecursionError, WorkerProtocolError) as exc:
        raise RuntimeActionStateError(f"{label} are not canonical JSON") from exc
    if encoded != sorted(set(encoded)):
        raise RuntimeActionStateError(f"{label} must be sorted and unique")


def _digest(value: object, label: str, *, request: bool = False) -> str:
    error = _InvalidRequest if request else RuntimeActionStateError
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise error(f"{label} is not a canonical SHA-256 digest")
    return value


def _identifier(value: object, label: str, *, request: bool = False) -> str:
    error = _InvalidRequest if request else RuntimeActionStateError
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise error(f"{label} is invalid")
    return value


def _integer(value: object, label: str, *, request: bool = False) -> int:
    error = _InvalidRequest if request else RuntimeActionStateError
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise error(f"{label} is invalid")
    return value


def _positive_integer(value: object, label: str, *, request: bool = False) -> int:
    integer = _integer(value, label, request=request)
    if integer == 0:
        error = _InvalidRequest if request else RuntimeActionStateError
        raise error(f"{label} is invalid")
    return integer
