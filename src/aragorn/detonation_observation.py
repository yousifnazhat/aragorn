"""CAS-bound normalized observation for one detonation source event."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection
from io import BytesIO
from types import MappingProxyType
from typing import Any

from .analyze import _reject_duplicate_json_keys, _reject_json_constant
from .behavior_capability_diff import (
    CAPABILITY_KINDS,
    BehaviorCapabilityDiffError,
    derive_behavior_capability_diff,
    verify_behavior_capability_diff,
)
from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, canonical_json

SCHEMA = "aragorn/detonation-observation/v1"
SOURCE_SCHEMA = "aragorn/detonation-source-event/v1"
AUTHORITY = "NORMALIZED_SOURCE_EVENT_ONLY_NOT_EXECUTION_OR_BEHAVIOR_AUTHORITY"
DIFF_RECEIPT_SCHEMA = "aragorn/detonation-capability-diff-receipt/v1"
DIFF_RECEIPT_AUTHORITY = (
    "SELECTED_OBSERVATION_SET_DIFF_ONLY_NOT_EXECUTION_COMPLETENESS_ISOLATION_OR_"
    "ADMISSION_AUTHORITY"
)
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
_MAX_CAPABILITY_DIFF_BYTES = 16 * 1024
_MAX_DIFF_RECEIPT_BYTES = 2 * 1024 * 1024
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
_DIFF_RECEIPT_FIELDS = {
    "schema",
    "authority",
    *_IDENTITY_FIELDS,
    "declared_capabilities",
    "observation_bindings",
    "capability_diff_digest",
}
_BINDING_FIELDS = {"observation_digest", "source_event_digest"}


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

    source_event_digest, observation_digest, raw = (
        derive_detonation_observation_binding(
            source_event,
            subject_digest=subject_digest,
            input_manifest_digest=input_manifest_digest,
            input_tree_digest=input_tree_digest,
            run_request_digest=run_request_digest,
            normalizer_implementation_digest=normalizer_implementation_digest,
        )
    )
    try:
        cas.put_expected(
            BytesIO(source_event),
            expected_digest=source_event_digest,
            max_bytes=MAX_SOURCE_EVENT_BYTES,
        )
        cas.put_expected(
            BytesIO(raw),
            expected_digest=observation_digest,
            max_bytes=_MAX_OBSERVATION_BYTES,
        )
        return observation_digest
    except CASError as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot retain detonation observation: {exc}"
        ) from exc


def derive_detonation_observation_binding(
    source_event: bytes,
    *,
    subject_digest: str,
    input_manifest_digest: str,
    input_tree_digest: str,
    run_request_digest: str,
    normalizer_implementation_digest: str,
) -> tuple[str, str, bytes]:
    """Derive one source/observation binding without mutating the CAS."""

    identity = _identity(
        subject_digest,
        input_manifest_digest,
        input_tree_digest,
        run_request_digest,
        normalizer_implementation_digest,
    )
    category = _source_capability(source_event)
    try:
        source_event_digest = "sha256:" + hashlib.sha256(source_event).hexdigest()
        document = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            **identity,
            "source_event_digest": source_event_digest,
            "capability": category,
        }
        raw = canonical_json(document)
        observation_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        return source_event_digest, observation_digest, raw
    except WorkerProtocolError as exc:
        raise DetonationObservationError(
            "OBSERVATION_INVALID", f"cannot derive detonation observation: {exc}"
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

    identity = _identity(
        expected_subject_digest,
        expected_input_manifest_digest,
        expected_input_tree_digest,
        expected_run_request_digest,
        expected_normalizer_implementation_digest,
    )
    bindings = _snapshot_observation_bindings(expected_observations)
    return _observed_capabilities_from_bindings(cas, bindings, identity)


def retain_detonation_capability_diff(
    cas: CAS,
    observation_bindings: dict[str, str],
    *,
    subject_digest: str,
    input_manifest_digest: str,
    input_tree_digest: str,
    run_request_digest: str,
    normalizer_implementation_digest: str,
    declared_capabilities: Collection[str],
) -> str:
    """Retain one selected observation set and its re-derived category diff."""

    identity = _identity(
        subject_digest,
        input_manifest_digest,
        input_tree_digest,
        run_request_digest,
        normalizer_implementation_digest,
    )
    bindings = _snapshot_observation_bindings(observation_bindings)
    categories = _observed_capabilities_from_bindings(cas, bindings, identity)
    capability_diff = _derive_capability_diff(
        subject_digest=identity["subject_digest"],
        declared_capabilities=declared_capabilities,
        observed_capabilities=categories,
    )
    try:
        capability_diff_digest = cas.put(
            BytesIO(canonical_json(capability_diff)),
            max_bytes=_MAX_CAPABILITY_DIFF_BYTES,
        )
        receipt = {
            "schema": DIFF_RECEIPT_SCHEMA,
            "authority": DIFF_RECEIPT_AUTHORITY,
            **identity,
            "declared_capabilities": capability_diff["declared_capabilities"],
            "observation_bindings": [
                {
                    "observation_digest": observation_digest,
                    "source_event_digest": source_event_digest,
                }
                for observation_digest, source_event_digest in bindings
            ],
            "capability_diff_digest": capability_diff_digest,
        }
        return cas.put(
            BytesIO(canonical_json(receipt)), max_bytes=_MAX_DIFF_RECEIPT_BYTES
        )
    except (CASError, WorkerProtocolError) as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot retain detonation capability diff: {exc}"
        ) from exc


def verify_detonation_capability_diff(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_observations: dict[str, str],
    expected_subject_digest: str,
    expected_input_manifest_digest: str,
    expected_input_tree_digest: str,
    expected_run_request_digest: str,
    expected_normalizer_implementation_digest: str,
    expected_declared_capabilities: Collection[str],
) -> dict[str, Any]:
    """Replay a selected observation set into its exact retained category diff."""

    expected_identity = _identity(
        expected_subject_digest,
        expected_input_manifest_digest,
        expected_input_tree_digest,
        expected_run_request_digest,
        expected_normalizer_implementation_digest,
    )
    expected_bindings = _snapshot_observation_bindings(expected_observations)
    expected_declared = _derive_capability_diff(
        subject_digest=expected_identity["subject_digest"],
        declared_capabilities=expected_declared_capabilities,
        observed_capabilities=(),
    )["declared_capabilities"]
    try:
        receipt = _canonical_document(
            cas.read(
                _digest(receipt_digest, "capability diff receipt"),
                max_bytes=_MAX_DIFF_RECEIPT_BYTES,
            ),
            code="DIFF_RECEIPT_INVALID",
            label="detonation capability diff receipt",
        )
        if set(receipt) != _DIFF_RECEIPT_FIELDS:
            raise DetonationObservationError(
                "DIFF_RECEIPT_INVALID",
                "detonation capability diff receipt fields are invalid",
            )
        if (
            receipt["schema"] != DIFF_RECEIPT_SCHEMA
            or receipt["authority"] != DIFF_RECEIPT_AUTHORITY
        ):
            raise DetonationObservationError(
                "DIFF_RECEIPT_INVALID",
                "detonation capability diff receipt schema or authority is invalid",
            )
        if {field: receipt[field] for field in _IDENTITY_FIELDS} != expected_identity:
            raise DetonationObservationError(
                "IDENTITY_MISMATCH",
                "detonation capability diff receipt identity changed",
            )
        if receipt["declared_capabilities"] != expected_declared:
            raise DetonationObservationError(
                "IDENTITY_MISMATCH",
                "detonation declared capabilities changed",
            )
        receipt_bindings = _receipt_observation_bindings(
            receipt["observation_bindings"]
        )
        if receipt_bindings != expected_bindings:
            raise DetonationObservationError(
                "IDENTITY_MISMATCH",
                "detonation selected observation set changed",
            )
        categories = _observed_capabilities_from_bindings(
            cas, receipt_bindings, expected_identity
        )
        capability_diff_digest = _digest(
            receipt["capability_diff_digest"], "capability diff"
        )
        capability_diff = _canonical_document(
            cas.read(
                capability_diff_digest,
                max_bytes=_MAX_CAPABILITY_DIFF_BYTES,
            ),
            code="CAPABILITY_DIFF_INVALID",
            label="detonation capability diff",
        )
        try:
            verify_behavior_capability_diff(
                capability_diff,
                expected_subject_digest=expected_identity["subject_digest"],
                expected_declared_capabilities=expected_declared,
                expected_observed_capabilities=categories,
            )
        except BehaviorCapabilityDiffError as exc:
            raise DetonationObservationError(
                "CAPABILITY_DIFF_INVALID",
                f"detonation capability diff is invalid: {exc}",
            ) from exc
        return receipt
    except DetonationObservationError:
        raise
    except CASError as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot verify detonation capability diff: {exc}"
        ) from exc


def derive_detonation_capability_diff_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_observations: dict[str, str],
    expected_subject_digest: str,
    expected_input_manifest_digest: str,
    expected_input_tree_digest: str,
    expected_run_request_digest: str,
    expected_normalizer_implementation_digest: str,
    expected_declared_capabilities: Collection[str],
) -> dict[str, int]:
    """Return the exact verified receipt, diff, observation, and source closure."""

    receipt_id = _digest(receipt_digest, "capability diff receipt")
    receipt = verify_detonation_capability_diff(
        cas,
        receipt_id,
        expected_observations=expected_observations,
        expected_subject_digest=expected_subject_digest,
        expected_input_manifest_digest=expected_input_manifest_digest,
        expected_input_tree_digest=expected_input_tree_digest,
        expected_run_request_digest=expected_run_request_digest,
        expected_normalizer_implementation_digest=(
            expected_normalizer_implementation_digest
        ),
        expected_declared_capabilities=expected_declared_capabilities,
    )
    limits = {
        receipt_id: _MAX_DIFF_RECEIPT_BYTES,
        receipt["capability_diff_digest"]: _MAX_CAPABILITY_DIFF_BYTES,
    }
    for observation_digest, source_event_digest in _receipt_observation_bindings(
        receipt["observation_bindings"]
    ):
        limits[observation_digest] = _MAX_OBSERVATION_BYTES
        limits[source_event_digest] = MAX_SOURCE_EVENT_BYTES
    try:
        return {
            digest: len(cas.read(digest, max_bytes=limit))
            for digest, limit in sorted(limits.items())
        }
    except CASError as exc:
        raise DetonationObservationError(
            "CAS_FAILURE", f"cannot derive detonation capability diff closure: {exc}"
        ) from exc


def _snapshot_observation_bindings(
    expected_observations: object,
) -> tuple[tuple[str, str], ...]:
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
    return _canonical_observation_bindings(bindings)


def _canonical_observation_bindings(
    bindings: tuple[tuple[object, object], ...],
) -> tuple[tuple[str, str], ...]:
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
    normalized = tuple(
        (
            _digest(observation, "observation"),
            _digest(source, "source event"),
        )
        for observation, source in bindings
    )
    if len({observation for observation, _ in normalized}) != len(normalized):
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "observation is bound more than once"
        )
    if len({source for _, source in normalized}) != len(normalized):
        raise DetonationObservationError(
            "OBSERVATION_SET_INVALID", "source event is bound more than once"
        )
    return tuple(sorted(normalized))


def _receipt_observation_bindings(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or len(value) > MAX_OBSERVATIONS:
        raise DetonationObservationError(
            "DIFF_RECEIPT_INVALID",
            "detonation receipt observation bindings are not a bounded array",
        )
    raw_bindings: list[tuple[object, object]] = []
    for raw_binding in value:
        if not isinstance(raw_binding, dict) or set(raw_binding) != _BINDING_FIELDS:
            raise DetonationObservationError(
                "DIFF_RECEIPT_INVALID",
                "detonation receipt observation binding fields are invalid",
            )
        raw_bindings.append(
            (
                raw_binding["observation_digest"],
                raw_binding["source_event_digest"],
            )
        )
    bindings = tuple(raw_bindings)
    canonical = _canonical_observation_bindings(bindings)
    if bindings != canonical:
        raise DetonationObservationError(
            "DIFF_RECEIPT_INVALID",
            "detonation receipt observation bindings are not canonical",
        )
    return canonical


def _observed_capabilities_from_bindings(
    cas: CAS,
    bindings: tuple[tuple[str, str], ...],
    identity: dict[str, str],
) -> tuple[str, ...]:
    categories = {
        verify_detonation_observation(
            cas,
            observation_digest,
            expected_subject_digest=identity["subject_digest"],
            expected_input_manifest_digest=identity["input_manifest_digest"],
            expected_input_tree_digest=identity["input_tree_digest"],
            expected_run_request_digest=identity["run_request_digest"],
            expected_normalizer_implementation_digest=(
                identity["normalizer_implementation_digest"]
            ),
            expected_source_event_digest=source_event_digest,
        )["capability"]
        for observation_digest, source_event_digest in bindings
    }
    return tuple(sorted(categories))


def _derive_capability_diff(
    *,
    subject_digest: str,
    declared_capabilities: Collection[str],
    observed_capabilities: Collection[str],
) -> dict[str, Any]:
    try:
        return derive_behavior_capability_diff(
            subject_digest=subject_digest,
            declared_capabilities=declared_capabilities,
            observed_capabilities=observed_capabilities,
        )
    except BehaviorCapabilityDiffError as exc:
        raise DetonationObservationError(
            "CAPABILITY_DIFF_INVALID",
            f"detonation capability diff inputs are invalid: {exc}",
        ) from exc


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
