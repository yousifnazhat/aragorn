"""Bounded, offline Tetragon v1.7.0 process JSON normalization.

This is a deliberately restricted protobuf-JSON profile, not a collector or a
general protobuf implementation. Unknown event variants and unsupported optional
fields fail closed. Input bytes and all caller-reported window checks are bound,
but neither vendor authenticity nor delivery completeness is established. No
network, kernel, process-control, policy publication, or filesystem writes occur.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .oci_worker_protocol import canonical_json as _canonical

SOURCE_COMMIT = "1de2ed8ebea18e56257dc59597aa13bf8f0e471e"
SOURCE_LOCK_DIGEST = (
    "sha256:b7d69c22590952fbf717fb3c293c5ebff4391c7c02f1787f1e28aa185efcb9b9"
)
PROFILE = "tetragon-v1.7.0-restricted-process-json/v1"
MAX_RECORD_BYTES = 64 * 1024
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 4096
MAX_ANCESTORS = 32
_MAX_SOURCE_LOCK_BYTES = 32 * 1024
_U32 = (1 << 32) - 1
_U64 = (1 << 64) - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z\Z"
)
_PROCESS_FIELDS = {
    "exec_id",
    "pid",
    "uid",
    "cwd",
    "binary",
    "arguments",
    "flags",
    "start_time",
    "auid",
    "docker",
    "parent_exec_id",
    "refcnt",
    "tid",
    "ns",
    "in_init_tree",
}
_NAMESPACES = {
    "uts",
    "ipc",
    "mnt",
    "pid",
    "pid_for_children",
    "net",
    "time",
    "time_for_children",
    "cgroup",
    "user",
}
LOSS_METRICS = (
    "tetragon_bpf_missed_events_total",
    "tetragon_events_missing_process_info_total",
    "tetragon_export_ratelimit_events_dropped_total",
    "tetragon_handler_errors_total",
    "tetragon_notify_overflowed_events_total",
    "tetragon_observer_ringbuf_errors_total",
    "tetragon_observer_ringbuf_events_lost_total",
    "tetragon_observer_ringbuf_queue_events_lost_total",
)
_CEILINGS = {
    "producer_authenticity_verified": False,
    "release_image_verified": False,
    "runtime_attribution_verified": False,
    "semantic_skill_causation_verified": False,
    "continuous_coverage_verified": False,
    "delivery_completeness_verified": False,
    "wall_time_ordering_verified": False,
    "pre_effect_prevention_verified": False,
    "run_conformance_eligible": False,
    "phase3_eligible": False,
}


class TetragonProcessError(ValueError):
    """A source pin, restricted event, or reported window is invalid."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TetragonProcessError("duplicate JSON key")
        result[key] = value
    return result


def _bad_number(_value: str) -> Any:
    raise TetragonProcessError("noninteger JSON number")


def _json(raw: bytes, maximum: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum or b"\0" in raw:
        raise TetragonProcessError("invalid raw byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_float=_bad_number,
            parse_constant=_bad_number,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise TetragonProcessError("invalid JSON") from exc
    if type(value) is not dict:
        raise TetragonProcessError("JSON object required")
    return value


def _keys(value: object, allowed: set[str], required: set[str]) -> dict[str, Any]:
    if type(value) is not dict or not required <= set(value) <= allowed:
        raise TetragonProcessError("unsupported or missing fields")
    return value


def _text(value: object, maximum: int, *, empty: bool = False) -> str:
    if type(value) is not str or (not value and not empty):
        raise TetragonProcessError("invalid string")
    try:
        if len(value.encode("utf-8", "strict")) > maximum or "\0" in value:
            raise TetragonProcessError("invalid string bound")
    except UnicodeError as exc:
        raise TetragonProcessError("invalid string encoding") from exc
    return value


def _uint(value: object, maximum: int = _U32, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= maximum:
        raise TetragonProcessError("invalid unsigned integer")
    return value


def _time(value: object) -> tuple[int, int]:
    text = _text(value, 30)
    match = _TIMESTAMP.fullmatch(text)
    if not match:
        raise TetragonProcessError("unsupported protobuf UTC timestamp")
    try:
        stamp = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        seconds = (stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)).days * 86400
        seconds += stamp.hour * 3600 + stamp.minute * 60 + stamp.second
    except ValueError as exc:
        raise TetragonProcessError("invalid timestamp date") from exc
    return seconds, int((match[2] or "0").ljust(9, "0"))


def verify_source_lock(raw: bytes) -> dict[str, Any]:
    """Check the exact candidate manifest, not acquired blobs or signatures."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_SOURCE_LOCK_BYTES:
        raise TetragonProcessError("invalid candidate source lock byte bound")
    if _digest(raw) != SOURCE_LOCK_DIGEST:
        raise TetragonProcessError("candidate source lock pin changed")
    lock = _json(raw, _MAX_SOURCE_LOCK_BYTES)
    if _canonical(lock) + b"\n" != raw:
        raise TetragonProcessError("noncanonical candidate source lock")
    return lock


def verify_upstream_source_file(lock_raw: bytes, path: str, content: bytes) -> None:
    """Check one selected blob against the fixed source manifest."""
    lock = verify_source_lock(lock_raw)
    matches = [record for record in lock["files"] if record["path"] == path]
    if len(matches) != 1:
        raise TetragonProcessError("unknown selected upstream path")
    record = matches[0]
    if type(content) is not bytes or len(content) != record["bytes"]:
        raise TetragonProcessError("upstream source size changed")
    # Git SHA-1 is a second source-tree join, never a release signature.
    blob = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()
    if _digest(content) != record["digest"] or blob != record["git_blob"]:
        raise TetragonProcessError("upstream source digest changed")


def verify_upstream_source_files(raw: bytes, sources: Mapping[str, bytes]) -> str:
    """Audit every acquired selected blob; this is not a full build closure."""
    lock = verify_source_lock(raw)
    if not isinstance(sources, Mapping) or set(sources) != {
        record["path"] for record in lock["files"]
    }:
        raise TetragonProcessError("selected upstream inventory changed")
    for record in lock["files"]:
        verify_upstream_source_file(raw, record["path"], sources[record["path"]])
    return SOURCE_LOCK_DIGEST


def _process(value: object) -> dict[str, Any]:
    p = _keys(value, _PROCESS_FIELDS, {"exec_id", "pid", "start_time"})
    _text(p["exec_id"], 1024)  # Vendor identity remains opaque, not an authority token.
    _uint(p["pid"], positive=True)
    _time(p["start_time"])
    for field in ("uid", "auid", "refcnt", "tid"):
        if field in p:
            _uint(p[field], positive=field == "tid")
    for field in ("cwd", "binary", "arguments", "flags", "parent_exec_id"):
        if field in p:
            _text(p[field], 16 * 1024 if field == "arguments" else 4096, empty=True)
    if "docker" in p:
        prefix = _text(p["docker"], 15, empty=True)
        if prefix and not re.fullmatch(r"[0-9a-f]{15}", prefix):
            raise TetragonProcessError("unsupported vendor container prefix")
    if "in_init_tree" in p and type(p["in_init_tree"]) is not bool:
        raise TetragonProcessError("invalid init-tree boolean")
    if "ns" in p:
        for ns in _keys(p["ns"], _NAMESPACES, set()).values():
            item = _keys(ns, {"inum", "is_host"}, {"inum"})
            _uint(item["inum"], positive=True)
            if "is_host" in item and type(item["is_host"]) is not bool:
                raise TetragonProcessError("invalid namespace boolean")
    return p


def _identities(processes: list[dict[str, Any]]) -> None:
    identities: dict[str, tuple[int, tuple[int, int]]] = {}
    reverse: dict[tuple[int, tuple[int, int]], str] = {}
    parents: dict[str, str] = {}
    for p in processes:
        key = p["exec_id"]
        identity = p["pid"], _time(p["start_time"])
        if key in identities and identities[key] != identity:
            raise TetragonProcessError("conflicting vendor execution identity")
        if identity in reverse and reverse[identity] != key:
            raise TetragonProcessError("conflicting process identity alias")
        identities[key] = identity
        reverse[identity] = key
        parent = p.get("parent_exec_id")
        if parent:
            if key in parents and parents[key] != parent:
                raise TetragonProcessError("conflicting parent execution identity")
            parents[key] = parent
    # Cross-record chains can exceed MAX_ANCESTORS. Finish each node only once,
    # so a long chain does not restart the full walk for every process record.
    completed: set[str] = set()
    for key in list(parents):
        visiting: set[str] = set()
        while key in parents and key not in completed:
            if key in visiting:
                raise TetragonProcessError("cyclic vendor ancestry")
            visiting.add(key)
            key = parents[key]
        completed.update(visiting)


def _event(raw: bytes) -> dict[str, Any]:
    event = _json(raw, MAX_RECORD_BYTES)
    variants = set(event) & {"process_exec", "process_exit"}
    if len(variants) != 1:
        raise TetragonProcessError("unsupported event variant or loss notification")
    kind = next(iter(variants))
    _keys(
        event, {kind, "node_name", "time", "cluster_name"}, {kind, "node_name", "time"}
    )
    _text(event["node_name"], 255)
    if "cluster_name" in event:
        _text(event["cluster_name"], 255, empty=True)
    _time(event["time"])
    fields = {"process", "parent", "ancestors"}
    if kind == "process_exit":
        fields |= {"signal", "status", "time"}
    body = _keys(event[kind], fields, {"process"})
    process = _process(body["process"])
    parent = _process(body["parent"]) if "parent" in body else None
    ancestors = body.get("ancestors", [])
    if type(ancestors) is not list or len(ancestors) > MAX_ANCESTORS:
        raise TetragonProcessError("invalid ancestor bound")
    ancestors = [_process(item) for item in ancestors]
    all_processes = [process, *([parent] if parent is not None else []), *ancestors]
    if len({p["exec_id"] for p in all_processes}) != len(all_processes):
        raise TetragonProcessError("duplicate ancestry entry")
    _identities(all_processes)
    # v1.7.0 independently calls ktime.ToProto for cached process start, outer
    # event time, and exit-body time. DecodeKtime samples ClockGettime/time.Now
    # anew, so even equal kernel ktimes can produce reversed wall timestamps.
    # These values are parsed and retained, not rounded or ordered. Identity
    # consistency above still requires the exact cached start for each exec_id.
    if parent is not None and process.get("parent_exec_id") != parent["exec_id"]:
        raise TetragonProcessError("immediate parent does not join")
    if "status" in body:
        _uint(body["status"])
    if "signal" in body:
        _text(body["signal"], 64, empty=True)
    if "time" in body:
        _time(body["time"])
    return {
        "raw_digest": _digest(raw),
        "raw_bytes": len(raw),
        "kind": kind,
        "vendor_record": event,
        "wall_time_ordering_verified": False,
        "unavailable_attribution": {
            "full_container_id": None,
            "cgroup_path": None,
            "namespace_local_pid": None,
            "executable_digest": None,
            "active_skill_digest": None,
            "run_id": None,
            "tool_call_id": None,
        },
        "execution_origin": "UNVERIFIED_VENDOR_RECORD_NOT_PROVEN_LIVE_EXEC",
    }


def normalize_process_capture(
    raw: bytes,
    *,
    source_lock: bytes,
    window: object,
) -> dict[str, Any]:
    """Normalize selected raw NDJSON only after exact source/window guards.

    Window fields are caller reports, NOT acquired or authenticated here. Even
    zero reported drops, EOF, and quiescence never grant completeness. Labelled
    metric families must already be summed by a future verified metrics adapter.
    This function does not accept a Prometheus text scrape as that proof.
    """
    verify_source_lock(source_lock)
    fields = {
        "schema",
        "origin",
        "profile",
        "producer_instance_before",
        "producer_instance_after",
        "node_name",
        "opened_at",
        "closed_at",
        "reader_ready_before_window",
        "reader_reached_eof",
        "producer_quiesced",
        "final_status_collected",
        "collector_restarts",
        "reader_drops",
        "reader_errors",
        "metrics_before",
        "metrics_after",
        "raw_digest",
        "raw_bytes",
    }
    w = _keys(window, fields, fields)
    if w["schema"] != "aragorn/tetragon-reported-window/v1" or w["profile"] != PROFILE:
        raise TetragonProcessError("unsupported reported window profile")
    if type(w["origin"]) is not str or w["origin"] not in {
        "SYNTHETIC_TEST",
        "CALLER_REPORTED_NOT_ATTESTED",
    }:
        raise TetragonProcessError("unsupported input authority")
    instance = _text(w["producer_instance_before"], 64)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", instance)
        or w["producer_instance_after"] != instance
    ):
        raise TetragonProcessError("producer instance changed")
    for name in (
        "reader_ready_before_window",
        "reader_reached_eof",
        "producer_quiesced",
        "final_status_collected",
    ):
        if w[name] is not True:
            raise TetragonProcessError("reported capture lifecycle incomplete")
    for name in ("collector_restarts", "reader_drops", "reader_errors"):
        if _uint(w[name], _U64) != 0:
            raise TetragonProcessError("reported restart or reader loss")
    for name in ("metrics_before", "metrics_after"):
        for value in _keys(w[name], set(LOSS_METRICS), set(LOSS_METRICS)).values():
            if _uint(value, _U64) != 0:
                raise TetragonProcessError(
                    "reported collector loss or processing error"
                )
    start, end = _time(w["opened_at"]), _time(w["closed_at"])
    if start >= end:
        raise TetragonProcessError("invalid capture interval")
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_CAPTURE_BYTES
        or not raw.endswith(b"\n")
    ):
        raise TetragonProcessError("invalid capture byte bound or missing final LF")
    if w["raw_digest"] != _digest(raw) or _uint(
        w["raw_bytes"], MAX_CAPTURE_BYTES
    ) != len(raw):
        raise TetragonProcessError("reported raw inventory changed")
    lines = raw.splitlines(keepends=True)
    if not 0 < len(lines) <= MAX_RECORDS or any(
        not line.endswith(b"\n") or line.endswith(b"\r\n") for line in lines
    ):
        raise TetragonProcessError("invalid NDJSON record framing")
    events = [_event(line) for line in lines]
    records = [event["vendor_record"] for event in events]
    _text(w["node_name"], 255)
    if any(
        record["node_name"] != w["node_name"]
        or not start <= _time(record["time"]) <= end
        for record in records
    ):
        raise TetragonProcessError("event outside reported producer window")
    all_processes = []
    for event, record in zip(events, records, strict=True):
        body = record[event["kind"]]
        all_processes.extend(
            [
                body["process"],
                *([body["parent"]] if "parent" in body else []),
                *body.get("ancestors", []),
            ]
        )
    _identities(all_processes)
    return {
        "schema": "aragorn/tetragon-selected-process-observation/v1",
        "authority": "OFFLINE_SELECTED_VENDOR_RECORDS_ONLY_NOT_RUNTIME_OR_COVERAGE_AUTHORITY",
        "profile": PROFILE,
        "source_commit": SOURCE_COMMIT,
        "source_lock_digest": SOURCE_LOCK_DIGEST,
        "input_origin": w["origin"],
        "raw_digest": _digest(raw),
        "raw_bytes": len(raw),
        "reported_window_digest": _digest(_canonical(w)),
        "event_count": len(events),
        "events": events,
        "reported_zero_loss_checks": True,
        "limitations": [
            "RESTRICTED_OPTIONAL_FIELDS_NOT_GENERAL_VENDOR_SCHEMA_SUPPORT",
            "WINDOW_AND_METRICS_ARE_CALLER_REPORTS_NOT_SENSOR_ATTESTATION",
            "VENDOR_EXPORT_COUNTERS_DO_NOT_PROVE_SUCCESSFUL_DELIVERY",
            "VENDOR_EXEC_ID_AND_DEBUG_FLAGS_DO_NOT_PROVE_LIVE_EXEC_OR_CAUSAL_ATTRIBUTION",
            "INDEPENDENT_KTIME_WALL_CLOCK_CONVERSIONS_DO_NOT_ESTABLISH_CROSS_FIELD_ORDER",
            "HOST_PID_NOT_NAMESPACE_PID_CONTAINER_PREFIX_NOT_FULL_ID",
            "NO_CONTINUOUS_COLLECTION_SEMANTIC_LIFECYCLE_OR_PRE_EFFECT_ENFORCEMENT",
        ],
        **_CEILINGS,
    }
