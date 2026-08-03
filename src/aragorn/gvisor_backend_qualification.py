"""Verify one exact-profile gVisor backend qualification evidence batch."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .cas import CAS, CASError
from .gvisor_backend_probe import (
    GVisorBackendProbeError,
    derive_gvisor_backend_controls,
)
from .gvisor_runtime import _read_lock
from .oci_worker_protocol import WorkerProtocolError, _digest, canonical_json

LOCK_SCHEMA = "aragorn/gvisor-backend-qualification-lock/v1"
LOCK_AUTHORITY = "PIN_ONLY_NOT_BACKEND_QUALIFICATION_OR_PHASE2_EXIT_AUTHORITY"
RECEIPT_SCHEMA = "aragorn/gvisor-backend-qualification-receipt/v1"
RECEIPT_AUTHORITY = (
    "EXACT_COLIMA_GVISOR_RUNSC_SYSTRAP_CANARY_THREE_RUN_NEGATIVE_CONTROL_"
    "QUALIFICATION_ONLY_NOT_HOST_HYPERVISOR_HARDWARE_ATTESTATION_GENERAL_ESCAPE_"
    "ABSENCE_CAPTURE_COMPLETENESS_VARIED_SCENARIOS_ADMISSION_OR_PHASE2_EXIT_"
    "AUTHORITY"
)
PROFILE = "colima-gvisor-runsc-systrap-canary-negative-controls/v1"
RUN_REQUEST_SCHEMA = "aragorn/gvisor-backend-qualification-run-request/v1"
CONTROL_EVIDENCE_SCHEMA = "aragorn/gvisor-backend-qualification-controls/v1"
CLEANUP_EVIDENCE_SCHEMA = "aragorn/gvisor-backend-qualification-cleanup/v1"

_RUNS = 3
_MAX_LOCK_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_EVIDENCE_DOCUMENT_BYTES = 256 * 1024
_MAX_EVIDENCE_BLOB_BYTES = 2 * 1024 * 1024
_MAX_IMPLEMENTATION_BYTES = 16 * 1024 * 1024
_MAX_PROBE_BYTES = 16 * 1024 * 1024
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")

_CONTROL_EXPECTATIONS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "identity-profile",
        {
            "capability_masks_zero": True,
            "gid": 65534,
            "no_new_privileges": True,
            "supplementary_groups": [],
            "uid": 65534,
        },
    ),
    (
        "tmpfs-write-positive",
        {"attempted": True, "cleaned": True, "succeeded": True},
    ),
    (
        "tcp-sink-positive-control",
        {"attempted": True, "control_token_received": True},
    ),
    (
        "udp-sink-positive-control",
        {"attempted": True, "control_token_received": True},
    ),
    (
        "host-file-isolation",
        {"attempted": True, "host_unchanged": True, "visible": False},
    ),
    (
        "host-process-isolation",
        {"attempted": True, "host_alive": True, "visible": False},
    ),
    (
        "tcp-egress-denied",
        {"attempted": True, "probe_token_received": False},
    ),
    (
        "udp-egress-denied",
        {"attempted": True, "probe_token_received": False},
    ),
    (
        "rootfs-write-denied",
        {"artifact_absent": True, "attempted": True, "succeeded": False},
    ),
    (
        "input-mutation-denied",
        {
            "host_unchanged": True,
            "read_control_succeeded": True,
            "rename_succeeded": False,
            "unlink_succeeded": False,
            "write_succeeded": False,
        },
    ),
    (
        "tmpfs-exec-denied",
        {"attempted": True, "succeeded": False, "write_control_succeeded": True},
    ),
    (
        "mount-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "namespace-create-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "device-create-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "privilege-escalation-denied",
        {
            "setgid_attempted": True,
            "setgid_succeeded": False,
            "setuid_attempted": True,
            "setuid_succeeded": False,
        },
    ),
)
_CONTROL_IDS = [control_id for control_id, _expected in _CONTROL_EXPECTATIONS]
_ARTIFACT_FIELDS = {
    "container_live_inspect",
    "container_post_inspect",
    "container_pre_inspect",
    "egress_observer",
    "host_sentinel_post",
    "host_sentinel_pre",
    "probe_stderr",
    "probe_stdout",
    "runner_identity_post",
    "runner_identity_pre",
    "runtime_registration",
}
_LOCK_FIELDS = {
    "schema",
    "authority",
    "profile",
    "runs",
    "runtime_lock_digest",
    "probe_digest",
    "controls",
}
_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "profile",
    "status",
    "lock_digest",
    "runtime_lock_digest",
    "probe_digest",
    "implementation_digest",
    "runs",
}
_RUN_FIELDS = {
    "run_id",
    "container_id",
    "run_request_digest",
    "control_evidence_digest",
    "cleanup_evidence_digest",
}


class GVisorBackendQualificationError(ValueError):
    """A backend qualification contract is malformed or unbound."""


def load_gvisor_backend_qualification_lock(
    path: str | Path,
) -> tuple[bytes, dict[str, Any]]:
    """Load one canonical exact-profile qualification lock from disk."""

    try:
        raw = _read_lock(path, "gVisor backend qualification")
        return raw, _qualification_lock(raw)
    except GVisorBackendQualificationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise GVisorBackendQualificationError(
            f"cannot load gVisor backend qualification lock: {exc}"
        ) from exc


def verify_gvisor_backend_qualification(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> dict[str, Any]:
    """Replay one caller-pinned three-run qualification receipt."""

    receipt, _limits = _verify_qualification(
        cas,
        receipt_digest,
        expected_lock_digest=expected_lock_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_implementation_digest=expected_implementation_digest,
    )
    return receipt


def derive_gvisor_backend_qualification_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> dict[str, int]:
    """Return every verified blob required to replay the qualification."""

    _receipt, limits = _verify_qualification(
        cas,
        receipt_digest,
        expected_lock_digest=expected_lock_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_implementation_digest=expected_implementation_digest,
    )
    try:
        return {
            digest: len(cas.read(digest, max_bytes=maximum))
            for digest, maximum in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorBackendQualificationError(
            f"cannot derive gVisor backend qualification closure: {exc}"
        ) from exc


def _verify_qualification(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> tuple[dict[str, Any], dict[str, int]]:
    try:
        receipt_id = _digest(receipt_digest, "backend qualification receipt")
        lock_id = _digest(expected_lock_digest, "backend qualification lock")
        runtime_lock_id = _digest(
            expected_runtime_lock_digest, "backend qualification runtime lock"
        )
        implementation_id = _digest(
            expected_implementation_digest,
            "backend qualification verifier implementation",
        )
        receipt = _canonical_object(
            cas.read(receipt_id, max_bytes=_MAX_RECEIPT_BYTES),
            "backend qualification receipt",
        )
        _exact_fields(receipt, _RECEIPT_FIELDS, "backend qualification receipt")
        if (
            receipt["schema"] != RECEIPT_SCHEMA
            or receipt["authority"] != RECEIPT_AUTHORITY
            or receipt["profile"] != PROFILE
            or receipt["status"] != "PASS"
        ):
            raise GVisorBackendQualificationError(
                "backend qualification receipt authority is unsupported"
            )
        if receipt["lock_digest"] != lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt lock digest drifted"
            )
        if receipt["runtime_lock_digest"] != runtime_lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt runtime lock digest drifted"
            )
        if receipt["implementation_digest"] != implementation_id:
            raise GVisorBackendQualificationError(
                "backend qualification verifier implementation drifted"
            )

        lock = _qualification_lock(cas.read(lock_id, max_bytes=_MAX_LOCK_BYTES))
        if lock["runtime_lock_digest"] != runtime_lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification lock runtime identity drifted"
            )
        probe_id = _digest(lock["probe_digest"], "backend qualification probe")
        if receipt["probe_digest"] != probe_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt probe digest drifted"
            )

        limits = {
            receipt_id: _MAX_RECEIPT_BYTES,
            lock_id: _MAX_LOCK_BYTES,
            runtime_lock_id: _MAX_LOCK_BYTES,
            implementation_id: _MAX_IMPLEMENTATION_BYTES,
            probe_id: _MAX_PROBE_BYTES,
        }
        for digest, maximum in limits.items():
            cas.verify(digest, max_bytes=maximum)
        _verify_runs(
            cas,
            receipt["runs"],
            lock_digest=lock_id,
            runtime_lock_digest=runtime_lock_id,
            implementation_digest=implementation_id,
            probe_digest=probe_id,
            limits=limits,
        )
        return receipt, limits
    except GVisorBackendQualificationError:
        raise
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorBackendQualificationError(
            f"cannot verify gVisor backend qualification: {exc}"
        ) from exc


def _verify_runs(
    cas: CAS,
    value: object,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    implementation_digest: str,
    probe_digest: str,
    limits: dict[str, int],
) -> None:
    if not isinstance(value, list) or len(value) != _RUNS:
        raise GVisorBackendQualificationError(
            "backend qualification requires exactly three run records"
        )
    run_ids: list[str] = []
    container_ids: set[str] = set()
    primary_evidence: set[str] = set()
    for index, raw_run in enumerate(value):
        label = f"backend qualification runs[{index}]"
        run = _object(raw_run, label)
        _exact_fields(run, _RUN_FIELDS, label)
        run_id = _hex(run["run_id"], _RUN_ID, f"{label}.run_id")
        container_id = _hex(
            run["container_id"], _CONTAINER_ID, f"{label}.container_id"
        )
        if run_id in run_ids or container_id in container_ids:
            raise GVisorBackendQualificationError(
                "backend qualification repeats a run or container ID"
            )
        run_ids.append(run_id)
        container_ids.add(container_id)
        digests = {
            field: _digest(run[field], f"{label}.{field}")
            for field in (
                "run_request_digest",
                "control_evidence_digest",
                "cleanup_evidence_digest",
            )
        }
        if primary_evidence.intersection(digests.values()):
            raise GVisorBackendQualificationError(
                "backend qualification repeats run-bound evidence"
            )
        primary_evidence.update(digests.values())
        _verify_run_request(
            cas,
            digests["run_request_digest"],
            lock_digest=lock_digest,
            runtime_lock_digest=runtime_lock_digest,
            implementation_digest=implementation_digest,
            probe_digest=probe_digest,
            run_id=run_id,
        )
        artifacts = _verify_control_evidence(
            cas,
            digests["control_evidence_digest"],
            lock_digest=lock_digest,
            runtime_lock_digest=runtime_lock_digest,
            probe_digest=probe_digest,
            run_id=run_id,
            container_id=container_id,
        )
        _verify_cleanup_evidence(
            cas,
            digests["cleanup_evidence_digest"],
            lock_digest=lock_digest,
            run_id=run_id,
            container_id=container_id,
        )
        for digest in digests.values():
            limits[digest] = _MAX_EVIDENCE_DOCUMENT_BYTES
        for digest in artifacts.values():
            limits[digest] = max(
                limits.get(digest, 0),
                _MAX_EVIDENCE_BLOB_BYTES,
            )
            cas.verify(digest, max_bytes=_MAX_EVIDENCE_BLOB_BYTES)
    if run_ids != sorted(run_ids):
        raise GVisorBackendQualificationError(
            "backend qualification run records must be sorted by run ID"
        )


def _verify_run_request(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    implementation_digest: str,
    probe_digest: str,
    run_id: str,
) -> None:
    request = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification run request",
    )
    expected = {
        "schema": RUN_REQUEST_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "implementation_digest": implementation_digest,
        "probe_digest": probe_digest,
        "run_id": run_id,
    }
    if _canonical_bytes(request) != _canonical_bytes(expected):
        raise GVisorBackendQualificationError(
            "backend qualification run request is unbound"
        )


def _verify_control_evidence(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    probe_digest: str,
    run_id: str,
    container_id: str,
) -> dict[str, str]:
    evidence = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification control evidence",
    )
    _exact_fields(
        evidence,
        {
            "schema",
            "lock_digest",
            "runtime_lock_digest",
            "probe_digest",
            "run_id",
            "container_id",
            "controls",
            "artifacts",
        },
        "backend qualification control evidence",
    )
    if {
        "schema": evidence["schema"],
        "lock_digest": evidence["lock_digest"],
        "runtime_lock_digest": evidence["runtime_lock_digest"],
        "probe_digest": evidence["probe_digest"],
        "run_id": evidence["run_id"],
        "container_id": evidence["container_id"],
    } != {
        "schema": CONTROL_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "run_id": run_id,
        "container_id": container_id,
    }:
        raise GVisorBackendQualificationError(
            "backend qualification control evidence is unbound"
        )
    controls = evidence["controls"]
    if not isinstance(controls, list) or len(controls) != len(_CONTROL_EXPECTATIONS):
        raise GVisorBackendQualificationError(
            "backend qualification control evidence is incomplete"
        )
    artifacts = _object(evidence["artifacts"], "backend qualification artifacts")
    _exact_fields(artifacts, _ARTIFACT_FIELDS, "backend qualification artifacts")
    artifact_digests = {
        field: _digest(value, f"backend qualification artifacts.{field}")
        for field, value in artifacts.items()
    }
    try:
        derived_controls = derive_gvisor_backend_controls(
            cas.read(
                artifact_digests["probe_stdout"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["probe_stderr"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["host_sentinel_pre"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["host_sentinel_post"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["egress_observer"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            expected_run_id=run_id,
        )
    except GVisorBackendProbeError as exc:
        raise GVisorBackendQualificationError(str(exc)) from exc
    for index, ((control_id, expected), raw_control, derived) in enumerate(
        zip(_CONTROL_EXPECTATIONS, controls, derived_controls, strict=True)
    ):
        control = _object(
            raw_control, f"backend qualification controls[{index}]"
        )
        _exact_fields(
            control,
            {"control_id", "observed"},
            f"backend qualification controls[{index}]",
        )
        if (
            derived["control_id"] != control_id
            or _canonical_bytes(derived["observed"]) != _canonical_bytes(expected)
            or control["control_id"] != control_id
            or _canonical_bytes(control["observed"])
            != _canonical_bytes(derived["observed"])
        ):
            raise GVisorBackendQualificationError(
                f"backend qualification control failed: {control_id}"
            )
    return artifact_digests


def _verify_cleanup_evidence(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    run_id: str,
    container_id: str,
) -> None:
    cleanup = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification cleanup evidence",
    )
    expected = {
        "schema": CLEANUP_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "run_id": run_id,
        "container_id": container_id,
        "container_absent": True,
        "trace_files_absent": True,
        "host_sentinels_unchanged": True,
        "sinks_closed": True,
    }
    if _canonical_bytes(cleanup) != _canonical_bytes(expected):
        raise GVisorBackendQualificationError(
            "backend qualification cleanup did not complete"
        )


def _qualification_lock(raw: bytes) -> dict[str, Any]:
    lock = _canonical_object(raw, "backend qualification lock")
    _exact_fields(lock, _LOCK_FIELDS, "backend qualification lock")
    if (
        lock["schema"] != LOCK_SCHEMA
        or lock["authority"] != LOCK_AUTHORITY
        or lock["profile"] != PROFILE
        or lock["runs"] != _RUNS
        or lock["controls"] != _CONTROL_IDS
    ):
        raise GVisorBackendQualificationError(
            "backend qualification lock profile is unsupported"
        )
    lock["runtime_lock_digest"] = _digest(
        lock["runtime_lock_digest"], "backend qualification runtime lock"
    )
    lock["probe_digest"] = _digest(
        lock["probe_digest"], "backend qualification probe"
    )
    return lock


def _canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GVisorBackendQualificationError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or _canonical_bytes(document) != raw:
        raise GVisorBackendQualificationError(f"{label} is not canonical JSON")
    return document


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value)
    except WorkerProtocolError as exc:
        raise GVisorBackendQualificationError(str(exc)) from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GVisorBackendQualificationError(f"{label} must be an object")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GVisorBackendQualificationError(
            f"{label} has missing or unknown fields"
        )


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GVisorBackendQualificationError(f"{label} is not canonical hex")
    return value
