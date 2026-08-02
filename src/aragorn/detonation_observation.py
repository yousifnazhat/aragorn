"""CAS-bound normalized observation for one detonation source event."""

from __future__ import annotations

import json
import re
from io import BytesIO
from types import MappingProxyType
from typing import Any

from .analyze import _reject_duplicate_json_keys, _reject_json_constant
from .behavior_capability_diff import CAPABILITY_KINDS
from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, canonical_json

SCHEMA = "aragorn/detonation-observation/v1"
SOURCE_SCHEMA = "aragorn/detonation-source-event/v1"
AUTHORITY = "NORMALIZED_SOURCE_EVENT_ONLY_NOT_EXECUTION_OR_BEHAVIOR_AUTHORITY"
MAX_SOURCE_EVENT_BYTES = 4 * 1024
MAX_OBSERVATIONS = 10_000

SOURCE_OPERATIONS = MappingProxyType(
    {
        "file-open-read": "file-read",
        "file-open-write": "file-write",
        "memory-write": "memory-write",
        "network-connect": "network-connect",
        "process-exec": "process-exec",
        "tool-call": "tool-call",
    }
)

_MAX_OBSERVATION_BYTES = 16 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY_FIELDS = (
    "subject_digest",
    "input_manifest_digest",
    "input_tree_digest",
    "run_request_digest",
    "normalizer_implementation_digest",
)
_FIELDS = {
    "schema",
    "authority",
    *_IDENTITY_FIELDS,
    "source_event_digest",
    "capability",
}


class DetonationObservationError(ValueError):
    """A normalized source-event observation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def retain_detonation_observation(
    cas: CAS,
    source_event: bytes,
    *,
    subject_digest: str,
    input_manifest_digest: str,
    input_tree_digest: str,
    run_request_digest: str,
    normalizer_implementation_digest: str,
) -> str:
    """Retain one raw source event and its non-authoritative normalized category."""

    identity = _identity(
        subject_digest,
        input_manifest_digest,
        input_tree_digest,
        run_request_digest,
        normalizer_implementation_digest,
    )
    category = _source_capability(source_event)
    try:
        source_event_digest = cas.put(
            BytesIO(source_event), max_bytes=MAX_SOURCE_EVENT_BYTES
        )
        document = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            **identity,
            "source_event_digest": source_event_digest,
            "capability": category,
        }
        raw = canonical_json(document)
        return cas.put(BytesIO(raw), max_bytes=_MAX_OBSERVATION_BYTES)
    except (CASError, WorkerProtocolError) as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot retain detonation observation: {exc}"
        ) from exc


def verify_detonation_observation(
    cas: CAS,
    observation_digest: str,
    *,
    expected_subject_digest: str,
    expected_input_manifest_digest: str,
    expected_input_tree_digest: str,
    expected_run_request_digest: str,
    expected_normalizer_implementation_digest: str,
    expected_source_event_digest: str,
) -> dict[str, Any]:
    """Verify one observation against caller-held identities and raw-event digest."""

    expected = _identity(
        expected_subject_digest,
        expected_input_manifest_digest,
        expected_input_tree_digest,
        expected_run_request_digest,
        expected_normalizer_implementation_digest,
    )
    source_digest = _digest(expected_source_event_digest, "expected source event")
    try:
        raw = cas.read(
            _digest(observation_digest, "observation"),
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        document = _canonical_document(
            raw, code="OBSERVATION_INVALID", label="detonation observation"
        )
        if set(document) != _FIELDS:
            raise DetonationObservationError(
                "OBSERVATION_INVALID", "detonation observation fields are invalid"
            )
        if document["schema"] != SCHEMA or document["authority"] != AUTHORITY:
            raise DetonationObservationError(
                "OBSERVATION_INVALID",
                "detonation observation schema or authority is invalid",
            )
        if {field: document[field] for field in _IDENTITY_FIELDS} != expected:
            raise DetonationObservationError(
                "IDENTITY_MISMATCH", "detonation observation identity changed"
            )
        if _digest(document["source_event_digest"], "source event") != source_digest:
            raise DetonationObservationError(
                "IDENTITY_MISMATCH", "detonation source event identity changed"
            )
        source_event = cas.read(source_digest, max_bytes=MAX_SOURCE_EVENT_BYTES)
        if _source_capability(source_event) != _capability(document["capability"]):
            raise DetonationObservationError(
                "CAPABILITY_MISMATCH",
                "detonation capability does not match its retained source event",
            )
        return document
    except DetonationObservationError:
        raise
    except CASError as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot verify detonation observation: {exc}"
        ) from exc


def observed_capabilities(
    cas: CAS,
    expected_observations: dict[str, str],
    *,
    expected_subject_digest: str,
    expected_input_manifest_digest: str,
    expected_input_tree_digest: str,
    expected_run_request_digest: str,
    expected_normalizer_implementation_digest: str,
) -> tuple[str, ...]:
    """Verify a bounded observation-to-source map and return its categories."""

    if (
        type(expected_observations) is not dict
        or len(expected_observations) > MAX_OBSERVATIONS
    ):
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "observation set is not a bounded mapping"
        )
    try:
        bindings = tuple(expected_observations.items())
    except RuntimeError as exc:
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "observation set changed during snapshot"
        ) from exc
    if len(bindings) > MAX_OBSERVATIONS:
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "observation set exceeds its bound"
        )
    if any(
        not isinstance(observation, str) or not isinstance(source, str)
        for observation, source in bindings
    ):
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "observation set contains a non-digest value"
        )
    if len({source for _, source in bindings}) != len(bindings):
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "source event is bound more than once"
        )
    categories = {
        verify_detonation_observation(
            cas,
            observation_digest,
            expected_subject_digest=expected_subject_digest,
            expected_input_manifest_digest=expected_input_manifest_digest,
            expected_input_tree_digest=expected_input_tree_digest,
            expected_run_request_digest=expected_run_request_digest,
            expected_normalizer_implementation_digest=(
                expected_normalizer_implementation_digest
            ),
            expected_source_event_digest=source_event_digest,
        )["capability"]
        for observation_digest, source_event_digest in sorted(bindings)
    }
    return tuple(sorted(categories))


def _canonical_document(raw: bytes, *, code: str, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(document, dict) or canonical_json(document) != raw:
            raise DetonationObservationError(
                code,
                f"{label} must be a canonical JSON object",
            )
        return document
    except DetonationObservationError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError, WorkerProtocolError) as exc:
        raise DetonationObservationError(code, f"{label} is invalid: {exc}") from exc


def _source_capability(raw: object) -> str:
    if not isinstance(raw, bytes) or not raw:
        raise DetonationObservationError(
            "SOURCE_EVENT_INVALID", "source event must be non-empty bytes"
        )
    if len(raw) > MAX_SOURCE_EVENT_BYTES:
        raise DetonationObservationError(
            "SOURCE_EVENT_OVERSIZED", "source event exceeds its byte limit"
        )
    document = _canonical_document(
        raw, code="SOURCE_EVENT_INVALID", label="detonation source event"
    )
    if set(document) != {"schema", "operation", "detail"}:
        raise DetonationObservationError(
            "SOURCE_EVENT_INVALID", "detonation source event fields are invalid"
        )
    if document["schema"] != SOURCE_SCHEMA:
        raise DetonationObservationError(
            "SOURCE_EVENT_INVALID", "detonation source event schema is invalid"
        )
    operation = document["operation"]
    detail = document["detail"]
    if not isinstance(operation, str) or operation not in SOURCE_OPERATIONS:
        raise DetonationObservationError(
            "SOURCE_EVENT_INVALID", "detonation source operation is unsupported"
        )
    if not isinstance(detail, str) or len(detail) > 2048 or "\x00" in detail:
        raise DetonationObservationError(
            "SOURCE_EVENT_INVALID", "detonation source detail is invalid"
        )
    return SOURCE_OPERATIONS[operation]


def _identity(
    subject_digest: object,
    input_manifest_digest: object,
    input_tree_digest: object,
    run_request_digest: object,
    normalizer_implementation_digest: object,
) -> dict[str, str]:
    values = (
        subject_digest,
        input_manifest_digest,
        input_tree_digest,
        run_request_digest,
        normalizer_implementation_digest,
    )
    return {
        field: _digest(value, field.replace("_", " "))
        for field, value in zip(_IDENTITY_FIELDS, values, strict=True)
    }


def _capability(value: object) -> str:
    if not isinstance(value, str) or value not in CAPABILITY_KINDS:
        raise DetonationObservationError(
            "CAPABILITY_INVALID", "detonation capability is unsupported"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DetonationObservationError(
            "IDENTITY_INVALID", f"{label} digest is invalid"
        )
    return value
