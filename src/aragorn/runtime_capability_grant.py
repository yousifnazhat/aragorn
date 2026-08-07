"""Pure contract for one root grant and one exact profiled runtime lease."""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_digest, canonical_json
from .runtime_action_broker import (
    _OBSERVED_SUBMISSION_FIELDS,
    RuntimeActionBrokerError,
    _exact,
    _observed_submission,
    _parse_canonical_document,
    _positive_uint,
    _require_digest,
    _uint,
)
from .runtime_action_broker_v2 import _ATTRIBUTION_FIELDS
from .runtime_process_profile import ATTRIBUTION_AUTHORITY, ATTRIBUTION_SCHEMA

RuntimeCapabilityGrantError = RuntimeActionBrokerError

GRANT_SCHEMA = "aragorn/runtime-capability-grant/v1"
GRANT_AUTHORITY = (
    "ROOT_RUNTIME_CAPABILITY_GRANT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
)
LEASE_SCHEMA = "aragorn/runtime-capability-lease/v2"
LEASE_AUTHORITY = (
    "SENSOR_ISSUED_SINGLE_CAPABILITY_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
)
ISSUANCE_SCHEMA = "aragorn/profiled-runtime-capability-issuance/v1"
ISSUANCE_AUTHORITY = "SENSOR_ISSUANCE_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"

_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_GRANT_BYTES = 64 * 1024
_MAX_GRANT_LIFETIME_SECONDS = 300
_GRANT_FIELDS = {
    "schema",
    "authority",
    "grant_id",
    "source_manifest_digest",
    "install_context_digest",
    "runtime_profile_digest",
    "runtime_digest",
    "active_skill_digest",
    "sensor_digest",
    "policy_digest",
    "policy_version",
    "operation_digest",
    "issued_at_unix",
    "expires_at_unix",
    "max_actions",
}
_GRANT_DIGEST_FIELDS = {
    "source_manifest_digest",
    "install_context_digest",
    "runtime_profile_digest",
    "runtime_digest",
    "active_skill_digest",
    "sensor_digest",
    "policy_digest",
    "operation_digest",
}
_MEASURED_BINDINGS = (
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
)


def parse_runtime_capability_grant(
    raw: bytes,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Validate canonical grant bytes; optionally require current liveness."""

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_GRANT_BYTES:
        raise RuntimeActionBrokerError("runtime capability grant is invalid")
    grant = _exact(
        _parse_canonical_document(raw, "runtime capability grant"),
        _GRANT_FIELDS,
        "runtime capability grant",
    )
    if (
        grant["schema"] != GRANT_SCHEMA
        or grant["authority"] != GRANT_AUTHORITY
        or not isinstance(grant["grant_id"], str)
        or _HEX_64.fullmatch(grant["grant_id"]) is None
    ):
        raise RuntimeActionBrokerError("runtime capability grant is invalid")
    for field in _GRANT_DIGEST_FIELDS:
        _require_digest(grant[field], f"runtime capability grant {field}")
    _positive_uint(grant["policy_version"], "runtime capability grant policy version")
    max_actions = _positive_uint(
        grant["max_actions"], "runtime capability grant max actions"
    )
    if max_actions != 1:
        raise RuntimeActionBrokerError(
            "runtime capability grant max actions is invalid"
        )
    issued = _uint(grant["issued_at_unix"], "runtime capability grant issue time")
    expires = _uint(grant["expires_at_unix"], "runtime capability grant expiry")
    if expires <= issued or expires - issued > _MAX_GRANT_LIFETIME_SECONDS:
        raise RuntimeActionBrokerError("runtime capability grant lifetime is invalid")
    if now_unix is not None:
        now = _uint(now_unix, "trusted capability issuance time")
        if issued > now or now >= expires:
            raise RuntimeActionBrokerError("runtime capability grant is stale")
    return grant


def issue_profiled_runtime_capability(
    submission: object,
    grant_raw: bytes,
    now_unix: int,
) -> dict[str, Any]:
    """Issue one exact lease from a locally built, profile-attributed submission."""

    now = _uint(now_unix, "trusted capability issuance time")
    grant = parse_runtime_capability_grant(grant_raw, now)
    profiled = _canonical_profiled_submission(submission)
    attribution = _profile_attribution(profiled)
    legacy = {**profiled, "schema": "aragorn/runtime-observed-create-submission/v1"}
    legacy.pop("runtime_attribution")
    observed = _observed_submission(legacy)
    request = observed["envelope"]["request"]
    measured = observed["measured_action"]

    if any(measured[field] != request[field] for field in _MEASURED_BINDINGS):
        raise RuntimeActionBrokerError("profiled runtime measurement is unbound")
    peer = observed["runtime_peer"]
    if (
        (attribution["pid"], attribution["uid"], attribution["gid"])
        != (peer["pid"], peer["uid"], peer["gid"])
        or attribution["runtime_digest"] != request["runtime_digest"]
        or attribution["active_skill_digest"] != request["active_skill_digest"]
    ):
        raise RuntimeActionBrokerError("profiled runtime attribution is unbound")

    bindings = {
        "runtime_profile_digest": attribution["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": observed["sensor_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
    }
    if any(grant[field] != value for field, value in bindings.items()):
        raise RuntimeActionBrokerError("profiled runtime capability grant is unbound")

    request_issued = _uint(request["issued_at_unix"], "runtime request issue time")
    request_expires = _uint(request["expires_at_unix"], "runtime request expiry")
    if not (
        grant["issued_at_unix"]
        <= request_issued
        <= now
        < request_expires
        <= grant["expires_at_unix"]
    ):
        raise RuntimeActionBrokerError("profiled runtime capability time is unbound")

    nonce = secrets.token_hex(32)
    if not isinstance(nonce, str) or _HEX_64.fullmatch(nonce) is None:
        raise RuntimeActionBrokerError("runtime capability lease nonce is invalid")
    grant_digest = canonical_digest(grant)
    lease = {
        "schema": LEASE_SCHEMA,
        "authority": LEASE_AUTHORITY,
        "grant_digest": grant_digest,
        "lease_nonce": nonce,
        "submission_digest": canonical_digest(profiled),
        "runtime_attribution_digest": canonical_digest(attribution),
        "request_digest": observed["request_digest"],
        "runtime_profile_digest": attribution["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": observed["sensor_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
        "path_digest": request["path_digest"],
        "payload_digest": request["payload_digest"],
        "issued_at_unix": now,
        "expires_at_unix": request_expires,
        "max_actions": 1,
    }
    return {
        "schema": ISSUANCE_SCHEMA,
        "authority": ISSUANCE_AUTHORITY,
        "grant_digest": grant_digest,
        "lease": lease,
        "profiled_submission": profiled,
    }


def _canonical_profiled_submission(value: object) -> dict[str, Any]:
    try:
        raw = canonical_json(value)
    except (RecursionError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(
            f"profiled runtime submission is invalid: {exc}"
        ) from exc
    document = _exact(
        _parse_canonical_document(raw, "profiled runtime submission"),
        _OBSERVED_SUBMISSION_FIELDS | {"runtime_attribution"},
        "profiled runtime submission",
    )
    if document["schema"] != "aragorn/runtime-observed-create-submission/v2":
        raise RuntimeActionBrokerError("profiled runtime submission is required")
    return document


def _profile_attribution(profiled: dict[str, Any]) -> dict[str, Any]:
    attribution = _exact(
        profiled["runtime_attribution"],
        _ATTRIBUTION_FIELDS,
        "runtime process profile attribution",
    )
    if (
        attribution["schema"] != ATTRIBUTION_SCHEMA
        or attribution["authority"] != ATTRIBUTION_AUTHORITY
    ):
        raise RuntimeActionBrokerError("runtime process profile attribution is invalid")
    for field in (
        "profile_digest",
        "runtime_digest",
        "executable_digest",
        "active_skill_digest",
    ):
        _require_digest(attribution[field], f"runtime attribution {field}")
    _positive_uint(attribution["pid"], "runtime attribution pid")
    _uint(attribution["uid"], "runtime attribution uid")
    _uint(attribution["gid"], "runtime attribution gid")
    _positive_uint(attribution["start_time_ticks"], "runtime attribution start time")
    namespace = _exact(
        attribution["mount_namespace"],
        {"device", "inode"},
        "runtime attribution mount namespace",
    )
    _uint(namespace["device"], "runtime attribution mount device")
    _positive_uint(namespace["inode"], "runtime attribution mount inode")
    skill_path = attribution["skill_path"]
    if (
        not isinstance(skill_path, str)
        or not Path(skill_path).is_absolute()
        or Path(skill_path).name != "SKILL.md"
        or not isinstance(attribution["cgroup"], str)
        or not attribution["cgroup"].startswith("/")
    ):
        raise RuntimeActionBrokerError("runtime process profile attribution is invalid")
    return attribution
