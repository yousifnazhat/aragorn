"""Replay one bounded init-time gVisor remote-trace capture window."""

from __future__ import annotations

import json
import re
import struct
from io import BytesIO
from typing import TYPE_CHECKING, Any

from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, _digest, canonical_json

if TYPE_CHECKING:
    from .gvisor_remote_trace_receiver import GVisorRemoteTraceResult

SCHEMA = "aragorn/gvisor-remote-trace-capture-receipt/v1"
SCHEMA_V2 = "aragorn/gvisor-remote-trace-capture-receipt/v2"
AUTHORITY = (
    "ONE_CALLER_PINNED_MONITOR_RECORDED_INIT_TIME_GVISOR_REMOTE_SESSION_QUIESCED_"
    "WINDOW_ZERO_REPORTED_DROPS_AND_RAW_WIRE_CLOSURE_ONLY_NOT_MONITOR_RUNTIME_"
    "HOST_OR_WORKLOAD_ATTESTATION_ALL_POINT_COVERAGE_EVENT_SEMANTIC_VALIDITY_"
    "ADMISSION_OR_PHASE2_EXIT_AUTHORITY"
)
AUTHORITY_V2 = (
    "ONE_CALLER_PINNED_MONITOR_RECORDED_GVISOR_REMOTE_SESSION_DOCKER_CREATE_"
    "START_QUIESCED_WINDOW_ZERO_REPORTED_DROPS_AND_RAW_WIRE_CLOSURE_ONLY_NOT_"
    "MONITOR_RUNTIME_HOST_OR_WORKLOAD_ATTESTATION_ALL_POINT_COVERAGE_EVENT_"
    "SEMANTIC_VALIDITY_ADMISSION_OR_PHASE2_EXIT_AUTHORITY"
)
PROFILE = "gvisor-remote-default-pod-init-seqpacket/v1"
LIFECYCLE_SCHEMA = "aragorn/gvisor-remote-trace-lifecycle/v1"
LIFECYCLE_SCHEMA_V2 = "aragorn/gvisor-remote-trace-lifecycle/v2"
FRAME_MANIFEST_SCHEMA = "aragorn/gvisor-remote-trace-frame-manifest/v1"
SESSION_NAME = "Default"
SOCKET_ENDPOINT = "/run/aragorn/gvisor-events.sock"
WIRE_VERSION = 1

_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_LIFECYCLE_BYTES = 64 * 1024
_MAX_STATUS_BYTES = 64 * 1024
_MAX_HANDSHAKE_BYTES = 1024
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_FRAME_BYTES = 1024 * 1024 - 1
_MAX_FRAMES = 65_536
_MAX_RAW_BYTES = 256 * 1024 * 1024
_MAX_RUNTIME_LOCK_BYTES = 64 * 1024
_MAX_IMPLEMENTATION_BYTES = 16 * 1024 * 1024
_MAX_WORKLOAD_RECEIPT_BYTES = 1024 * 1024
_HEADER = struct.Struct("<HHI")
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_POINT_NAME = re.compile(r"[a-z0-9_]+(?:/[a-z0-9_.*-]+)+\Z")
_FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_FINAL_STATUS = re.compile(
    r'SESSIONS \(1\)\n"Default"\n[ \t]+Sink: "remote", dropped: 0\n\Z'
)
_LIFECYCLE_EVENTS = [
    "listener-ready",
    "sandbox-start-requested",
    "remote-connected",
    "handshake-complete",
    "workload-quiesced",
    "final-session-status-captured",
    "connection-eof",
]
_LIFECYCLE_EVENTS_V2 = [
    "listener-ready",
    "docker-container-created",
    "docker-start-requested",
    "remote-connected",
    "handshake-complete",
    "workload-quiesced",
    "final-session-status-captured",
    "connection-eof",
]
_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "profile",
    "status",
    "run_id",
    "sandbox_id",
    "container_id",
    "runtime_lock_digest",
    "session_config_digest",
    "monitor_implementation_digest",
    "workload_receipt_digest",
    "lifecycle_digest",
    "sentry_handshake_digest",
    "monitor_handshake_digest",
    "final_session_status_digest",
    "frame_manifest_digest",
    "frame_count",
    "raw_frame_bytes",
}


class GVisorRemoteTraceCaptureError(ValueError):
    """Remote-trace evidence is malformed, incomplete, or unbound."""


def retain_gvisor_remote_trace_capture(
    cas: CAS,
    result: GVisorRemoteTraceResult,
    *,
    run_id: str,
    sandbox_id: str,
    container_id: str,
    runtime_lock_digest: str,
    session_config_digest: str,
    monitor_implementation_digest: str,
    workload_receipt_digest: str,
    lifecycle_bytes: bytes,
    final_trace_list_bytes: bytes,
    receipt_schema: str = SCHEMA,
) -> str:
    """Retain and replay one already-validated receiver result."""

    try:
        receipt_authority, _lifecycle_schema, _lifecycle_events = (
            _capture_contract(receipt_schema)
        )
        retained_run_id = _hex(run_id, _RUN_ID, "remote trace run ID")
        retained_sandbox_id = _hex(
            sandbox_id, _CONTAINER_ID, "remote trace sandbox ID"
        )
        retained_container_id = _hex(
            container_id, _CONTAINER_ID, "remote trace container ID"
        )
        pins = {
            "runtime_lock_digest": _digest(
                runtime_lock_digest, "remote trace runtime lock"
            ),
            "session_config_digest": _digest(
                session_config_digest, "remote trace session config"
            ),
            "monitor_implementation_digest": _digest(
                monitor_implementation_digest,
                "remote trace monitor implementation",
            ),
            "workload_receipt_digest": _digest(
                workload_receipt_digest, "remote trace workload receipt"
            ),
        }
        if (
            type(result.sentry_handshake) is not bytes
            or type(result.monitor_handshake) is not bytes
            or not isinstance(result.frames, tuple)
            or any(type(frame) is not bytes for frame in result.frames)
            or type(lifecycle_bytes) is not bytes
            or type(final_trace_list_bytes) is not bytes
        ):
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace retention inputs must be immutable bytes"
            )
        frame_count = _integer(
            result.frame_count, 1, _MAX_FRAMES, "remote trace frame count"
        )
        raw_frame_bytes = _integer(
            result.raw_frame_bytes,
            _HEADER.size + 1,
            _MAX_RAW_BYTES,
            "remote trace raw byte count",
        )
        if frame_count != len(result.frames) or raw_frame_bytes != sum(
            len(frame) for frame in result.frames
        ):
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace receiver accounting changed"
            )

        frames = []
        for sequence, raw in enumerate(result.frames):
            size = _integer(
                len(raw),
                _HEADER.size + 1,
                _MAX_FRAME_BYTES,
                "remote trace frame size",
            )
            _header_size, message_type, dropped_count = _HEADER.unpack_from(raw)
            frame_digest = cas.put(BytesIO(raw), max_bytes=size)
            frames.append(
                {
                    "sequence": sequence,
                    "digest": frame_digest,
                    "size": size,
                    "message_type": message_type,
                    "dropped_count": dropped_count,
                }
            )
        frame_manifest = {
            "schema": FRAME_MANIFEST_SCHEMA,
            "run_id": retained_run_id,
            "sandbox_id": retained_sandbox_id,
            "container_id": retained_container_id,
            "session_config_digest": pins["session_config_digest"],
            "frames": frames,
        }
        frame_manifest_digest = cas.put(
            BytesIO(canonical_json(frame_manifest)), max_bytes=_MAX_MANIFEST_BYTES
        )
        lifecycle_digest = cas.put(
            BytesIO(lifecycle_bytes), max_bytes=_MAX_LIFECYCLE_BYTES
        )
        sentry_handshake_digest = cas.put(
            BytesIO(result.sentry_handshake), max_bytes=_MAX_HANDSHAKE_BYTES
        )
        monitor_handshake_digest = cas.put(
            BytesIO(result.monitor_handshake), max_bytes=_MAX_HANDSHAKE_BYTES
        )
        final_session_status_digest = cas.put(
            BytesIO(final_trace_list_bytes), max_bytes=_MAX_STATUS_BYTES
        )
        receipt = {
            "schema": receipt_schema,
            "authority": receipt_authority,
            "profile": PROFILE,
            "status": "RECORDED",
            "run_id": retained_run_id,
            "sandbox_id": retained_sandbox_id,
            "container_id": retained_container_id,
            **pins,
            "lifecycle_digest": lifecycle_digest,
            "sentry_handshake_digest": sentry_handshake_digest,
            "monitor_handshake_digest": monitor_handshake_digest,
            "final_session_status_digest": final_session_status_digest,
            "frame_manifest_digest": frame_manifest_digest,
            "frame_count": frame_count,
            "raw_frame_bytes": raw_frame_bytes,
        }
        receipt_digest = cas.put(
            BytesIO(canonical_json(receipt)), max_bytes=_MAX_RECEIPT_BYTES
        )
        verify_gvisor_remote_trace_capture(
            cas,
            receipt_digest,
            expected_runtime_lock_digest=pins["runtime_lock_digest"],
            expected_session_config_digest=pins["session_config_digest"],
            expected_monitor_implementation_digest=(
                pins["monitor_implementation_digest"]
            ),
            expected_workload_receipt_digest=pins["workload_receipt_digest"],
        )
        return receipt_digest
    except GVisorRemoteTraceCaptureError:
        raise
    except (AttributeError, CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorRemoteTraceCaptureError(
            f"cannot retain gVisor remote trace capture: {exc}"
        ) from exc


def verify_gvisor_remote_trace_capture(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_runtime_lock_digest: str,
    expected_session_config_digest: str,
    expected_monitor_implementation_digest: str,
    expected_workload_receipt_digest: str,
) -> dict[str, Any]:
    """Verify one caller-pinned configured and quiesced capture window."""

    receipt, _limits = _verify(
        cas,
        receipt_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_session_config_digest=expected_session_config_digest,
        expected_monitor_implementation_digest=(
            expected_monitor_implementation_digest
        ),
        expected_workload_receipt_digest=expected_workload_receipt_digest,
    )
    return receipt


def derive_gvisor_remote_trace_capture_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_runtime_lock_digest: str,
    expected_session_config_digest: str,
    expected_monitor_implementation_digest: str,
    expected_workload_receipt_digest: str,
) -> dict[str, int]:
    """Return every verified byte string required to replay the window."""

    _receipt, limits = _verify(
        cas,
        receipt_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_session_config_digest=expected_session_config_digest,
        expected_monitor_implementation_digest=(
            expected_monitor_implementation_digest
        ),
        expected_workload_receipt_digest=expected_workload_receipt_digest,
    )
    try:
        return {
            digest: len(cas.read(digest, max_bytes=maximum))
            for digest, maximum in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorRemoteTraceCaptureError(
            f"cannot derive gVisor remote trace closure: {exc}"
        ) from exc


def _verify(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_runtime_lock_digest: str,
    expected_session_config_digest: str,
    expected_monitor_implementation_digest: str,
    expected_workload_receipt_digest: str,
) -> tuple[dict[str, Any], dict[str, int]]:
    try:
        receipt_id = _digest(receipt_digest, "remote trace receipt")
        pins = {
            "runtime_lock_digest": _digest(
                expected_runtime_lock_digest, "remote trace runtime lock"
            ),
            "session_config_digest": _digest(
                expected_session_config_digest, "remote trace session config"
            ),
            "monitor_implementation_digest": _digest(
                expected_monitor_implementation_digest,
                "remote trace monitor implementation",
            ),
            "workload_receipt_digest": _digest(
                expected_workload_receipt_digest, "remote trace workload receipt"
            ),
        }
        receipt = _canonical_object(
            cas.read(receipt_id, max_bytes=_MAX_RECEIPT_BYTES),
            "gVisor remote trace receipt",
        )
        _exact(receipt, _RECEIPT_FIELDS, "gVisor remote trace receipt")
        authority, lifecycle_schema, lifecycle_events = _capture_contract(
            receipt["schema"]
        )
        if (
            receipt["authority"] != authority
            or receipt["profile"] != PROFILE
            or receipt["status"] != "RECORDED"
        ):
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace receipt authority is unsupported"
            )
        for field, expected in pins.items():
            if receipt[field] != expected:
                raise GVisorRemoteTraceCaptureError(
                    f"gVisor remote trace {field} drifted"
                )
        run_id = _hex(receipt["run_id"], _RUN_ID, "remote trace run ID")
        sandbox_id = _hex(
            receipt["sandbox_id"], _CONTAINER_ID, "remote trace sandbox ID"
        )
        container_id = _hex(
            receipt["container_id"], _CONTAINER_ID, "remote trace container ID"
        )
        frame_count = _integer(
            receipt["frame_count"], 1, _MAX_FRAMES, "remote trace frame count"
        )
        raw_bytes = _integer(
            receipt["raw_frame_bytes"],
            _HEADER.size + 1,
            _MAX_RAW_BYTES,
            "remote trace raw byte count",
        )
        evidence = {
            field: _digest(receipt[field], f"remote trace {field}")
            for field in (
                "lifecycle_digest",
                "sentry_handshake_digest",
                "monitor_handshake_digest",
                "final_session_status_digest",
                "frame_manifest_digest",
            )
        }

        limits = {
            receipt_id: _MAX_RECEIPT_BYTES,
            pins["runtime_lock_digest"]: _MAX_RUNTIME_LOCK_BYTES,
            pins["session_config_digest"]: _MAX_CONFIG_BYTES,
            pins["monitor_implementation_digest"]: _MAX_IMPLEMENTATION_BYTES,
            pins["workload_receipt_digest"]: _MAX_WORKLOAD_RECEIPT_BYTES,
            evidence["lifecycle_digest"]: _MAX_LIFECYCLE_BYTES,
            evidence["sentry_handshake_digest"]: _MAX_HANDSHAKE_BYTES,
            evidence["monitor_handshake_digest"]: _MAX_HANDSHAKE_BYTES,
            evidence["final_session_status_digest"]: _MAX_STATUS_BYTES,
            evidence["frame_manifest_digest"]: _MAX_MANIFEST_BYTES,
        }
        for digest, maximum in limits.items():
            cas.verify(digest, max_bytes=maximum)
        _verify_session_config(
            cas.read(pins["session_config_digest"], max_bytes=_MAX_CONFIG_BYTES)
        )
        _verify_lifecycle(
            cas.read(evidence["lifecycle_digest"], max_bytes=_MAX_LIFECYCLE_BYTES),
            run_id=run_id,
            sandbox_id=sandbox_id,
            container_id=container_id,
            pins=pins,
            expected_schema=lifecycle_schema,
            expected_events=lifecycle_events,
        )
        handshake = b"\x08\x01"
        for field in ("sentry_handshake_digest", "monitor_handshake_digest"):
            if cas.read(evidence[field], max_bytes=_MAX_HANDSHAKE_BYTES) != handshake:
                raise GVisorRemoteTraceCaptureError(
                    "gVisor remote trace v1 handshake changed"
                )
        _verify_final_status(
            cas.read(
                evidence["final_session_status_digest"],
                max_bytes=_MAX_STATUS_BYTES,
            )
        )
        frame_limits = _verify_frame_manifest(
            cas,
            cas.read(
                evidence["frame_manifest_digest"], max_bytes=_MAX_MANIFEST_BYTES
            ),
            run_id=run_id,
            sandbox_id=sandbox_id,
            container_id=container_id,
            session_config_digest=pins["session_config_digest"],
            frame_count=frame_count,
            raw_bytes=raw_bytes,
        )
        for digest, maximum in frame_limits.items():
            limits[digest] = max(limits.get(digest, 0), maximum)
        return receipt, limits
    except GVisorRemoteTraceCaptureError:
        raise
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorRemoteTraceCaptureError(
            f"cannot verify gVisor remote trace capture: {exc}"
        ) from exc


def _verify_session_config(raw: bytes) -> None:
    config = _canonical_object(raw.removesuffix(b"\n"), "gVisor pod init config")
    _exact(config, {"trace_session"}, "gVisor pod init config")
    session = _object(config["trace_session"], "gVisor trace session")
    _exact(
        session,
        {"name", "points", "ignore_missing", "sinks"},
        "gVisor trace session",
    )
    if session["name"] != SESSION_NAME or session["ignore_missing"] is not False:
        raise GVisorRemoteTraceCaptureError(
            "gVisor trace session must be strict Default"
        )
    points = session["points"]
    if not isinstance(points, list) or not 1 <= len(points) <= 4096:
        raise GVisorRemoteTraceCaptureError("gVisor trace point set is invalid")
    names = []
    for index, value in enumerate(points):
        point = _object(value, f"gVisor trace point[{index}]")
        _exact(
            point,
            {"name", "optional_fields", "context_fields"},
            f"gVisor trace point[{index}]",
        )
        name = point["name"]
        if not isinstance(name, str) or _POINT_NAME.fullmatch(name) is None:
            raise GVisorRemoteTraceCaptureError("gVisor trace point name is invalid")
        _field_names(point["optional_fields"], "gVisor optional fields")
        _field_names(point["context_fields"], "gVisor context fields")
        names.append(name)
    if names != sorted(set(names)) or "container/start" not in names:
        raise GVisorRemoteTraceCaptureError(
            "gVisor trace points must be unique, sorted, and include container/start"
        )
    if session["sinks"] != [
        {
            "name": "remote",
            "config": {
                "backoff": "25us",
                "backoff_max": "1ms",
                "endpoint": SOCKET_ENDPOINT,
                "retries": 3,
            },
            "ignore_setup_error": False,
        }
    ]:
        raise GVisorRemoteTraceCaptureError(
            "gVisor trace session remote sink profile changed"
        )


def _verify_lifecycle(
    raw: bytes,
    *,
    run_id: str,
    sandbox_id: str,
    container_id: str,
    pins: dict[str, str],
    expected_schema: str,
    expected_events: list[str],
) -> None:
    lifecycle = _canonical_object(raw, "gVisor remote trace lifecycle")
    expected = {
        "schema": expected_schema,
        "run_id": run_id,
        "sandbox_id": sandbox_id,
        "container_id": container_id,
        "session_config_digest": pins["session_config_digest"],
        "monitor_implementation_digest": pins["monitor_implementation_digest"],
        "workload_receipt_digest": pins["workload_receipt_digest"],
        "events": expected_events,
    }
    if _canonical_bytes(lifecycle) != _canonical_bytes(expected):
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace lifecycle is incomplete or unbound"
        )


def _capture_contract(schema: object) -> tuple[str, str, list[str]]:
    if schema == SCHEMA:
        return AUTHORITY, LIFECYCLE_SCHEMA, _LIFECYCLE_EVENTS
    if schema == SCHEMA_V2:
        return AUTHORITY_V2, LIFECYCLE_SCHEMA_V2, _LIFECYCLE_EVENTS_V2
    raise GVisorRemoteTraceCaptureError(
        "gVisor remote trace receipt authority is unsupported"
    )


def _verify_final_status(raw: bytes) -> None:
    try:
        status = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace final status is not ASCII"
        ) from exc
    if _FINAL_STATUS.fullmatch(status) is None:
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace final status is not zero-drop Default remote"
        )


def _verify_frame_manifest(
    cas: CAS,
    raw: bytes,
    *,
    run_id: str,
    sandbox_id: str,
    container_id: str,
    session_config_digest: str,
    frame_count: int,
    raw_bytes: int,
) -> dict[str, int]:
    manifest = _canonical_object(raw, "gVisor remote trace frame manifest")
    _exact(
        manifest,
        {
            "schema",
            "run_id",
            "sandbox_id",
            "container_id",
            "session_config_digest",
            "frames",
        },
        "gVisor remote trace frame manifest",
    )
    if {
        "schema": manifest["schema"],
        "run_id": manifest["run_id"],
        "sandbox_id": manifest["sandbox_id"],
        "container_id": manifest["container_id"],
        "session_config_digest": manifest["session_config_digest"],
    } != {
        "schema": FRAME_MANIFEST_SCHEMA,
        "run_id": run_id,
        "sandbox_id": sandbox_id,
        "container_id": container_id,
        "session_config_digest": session_config_digest,
    }:
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace frame manifest is unbound"
        )
    frames = manifest["frames"]
    if not isinstance(frames, list) or len(frames) != frame_count:
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace frame inventory is incomplete"
        )
    total = 0
    container_starts = 0
    limits: dict[str, int] = {}
    for sequence, value in enumerate(frames):
        frame = _object(value, f"gVisor remote trace frame[{sequence}]")
        _exact(
            frame,
            {"sequence", "digest", "size", "message_type", "dropped_count"},
            f"gVisor remote trace frame[{sequence}]",
        )
        if _integer(
            frame["sequence"], sequence, sequence, "gVisor remote trace sequence"
        ) != sequence:
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace frame sequence is not contiguous"
            )
        size = _integer(
            frame["size"],
            _HEADER.size + 1,
            _MAX_FRAME_BYTES,
            "gVisor remote trace frame size",
        )
        digest = _digest(frame["digest"], "gVisor remote trace frame")
        wire = cas.read(digest, max_bytes=size)
        if len(wire) != size:
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace frame size changed"
            )
        header_size, message_type, dropped_count = _HEADER.unpack_from(wire)
        recorded_message_type = _integer(
            frame["message_type"], 1, 65_535, "gVisor remote trace message type"
        )
        recorded_drops = _integer(
            frame["dropped_count"], 0, 2**32 - 1, "gVisor remote trace drop count"
        )
        if (
            header_size != _HEADER.size
            or not 1 <= message_type <= 65_535
            or dropped_count != 0
            or recorded_message_type != message_type
            or recorded_drops != dropped_count
        ):
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace frame header is invalid or reports drops"
            )
        container_starts += message_type == 1
        total += size
        if total > _MAX_RAW_BYTES:
            raise GVisorRemoteTraceCaptureError(
                "gVisor remote trace raw evidence exceeds its byte limit"
            )
        limits[digest] = max(limits.get(digest, 0), size)
    if total != raw_bytes or container_starts != 1:
        raise GVisorRemoteTraceCaptureError(
            "gVisor remote trace totals or container/start anchor changed"
        )
    return limits


def _canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GVisorRemoteTraceCaptureError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or _canonical_bytes(document) != raw:
        raise GVisorRemoteTraceCaptureError(f"{label} is not canonical JSON")
    return document


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value)
    except WorkerProtocolError as exc:
        raise GVisorRemoteTraceCaptureError(str(exc)) from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GVisorRemoteTraceCaptureError(f"{label} must be an object")
    return value


def _exact(value: dict[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise GVisorRemoteTraceCaptureError(f"{label} has missing or unknown fields")


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GVisorRemoteTraceCaptureError(f"{label} is not canonical hex")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GVisorRemoteTraceCaptureError(f"{label} is outside its bounded range")
    return value


def _field_names(value: object, label: str) -> None:
    if (
        not isinstance(value, list)
        or len(value) > 32
        or value != sorted(set(value))
        or any(
            not isinstance(field, str) or _FIELD_NAME.fullmatch(field) is None
            for field in value
        )
    ):
        raise GVisorRemoteTraceCaptureError(f"{label} are invalid")
