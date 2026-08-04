"""Derive the bounded Phase 2 exit from three independently replayed leaves."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import evaluate_files
from aragorn.cas import CAS, CASError
from aragorn.gvisor_backend_qualification import (
    GVisorBackendQualificationError,
    _qualification_lock,
    verify_gvisor_backend_qualification,
)
from aragorn.gvisor_remote_trace_capture import (
    GVisorRemoteTraceCaptureError,
    verify_gvisor_remote_trace_capture,
)
from aragorn.gvisor_runtime import _canary_lock, _runtime_lock
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/phase2-exit-gate-report/v1"
AUTHORITY = (
    "BOUNDED_EXERCISED_PHASE2_CONFIGURED_POINT_COMPLETENESS_METRICS_AND_EXACT_"
    "BACKEND_QUALIFICATION_ONLY_NOT_TRUSTED_SENTRY_RUNTIME_HOST_HYPERVISOR_"
    "HARDWARE_ATTESTATION_PHASE3_EDR_ADMISSION_OR_PUBLIC_RELEASE_AUTHORITY"
)
SCOPE = "bounded-exercised-phase2/v1"
RUNTIME_SOURCE_COMMIT = "9f3e9a3fba9416ea1f5832d82923d95830479096"
RUNTIME_ARCHITECTURE = "arm64"
EXPECTED_CELLS = 100
EXPECTED_RUNS = 3
REMOTE_RECEIPT_SCHEMA = "aragorn/gvisor-remote-trace-capture-receipt/v2"
REMOTE_PROFILE = "gvisor-remote-default-pod-init-seqpacket/v1"
METRICS_SCHEMA = "aragorn/benchmark-phase2-metrics-checkpoint/v3"
MISSING_METRICS_REQUIREMENTS = [
    "CAPTURE_COMPLETENESS_REQUIRED",
    "QUALIFIED_ISOLATED_BACKEND_REQUIRED",
]
REQUIRED_POINTS = (
    "container/start",
    "sentry/clone",
    "sentry/task_exit",
    "syscall/execve/enter",
    "syscall/execve/exit",
    "syscall/openat/enter",
    "syscall/openat/exit",
    "syscall/write/enter",
    "syscall/write/exit",
)
LIMITATIONS = [
    "CONFIGURED_POINTS_ONLY_NOT_UNIVERSAL_EVENT_COMPLETENESS",
    "SENTRY_AND_DOCKER_EVIDENCE_ARE_NOT_TRUSTED_ATTESTATION",
    "ZERO_REPORTED_DROPS_DOES_NOT_PROVE_ABSENCE_OF_UNREPORTED_EVENTS",
    "OPERATOR_AUTHORED_HELD_OUT_MATRIX_IS_NOT_INDEPENDENT_EFFICACY_EVIDENCE",
    "NO_PHASE3_RUNTIME_PREVENTION_OR_EDR_AUTHORITY",
    "NO_ADMISSION_INSTALLER_OR_PUBLIC_RELEASE_AUTHORITY",
]

_HEADER = struct.Struct("<HHI")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_FRAME_BYTES = 1024 * 1024 - 1
_MAX_STRING_BYTES = 64 * 1024
_MAX_REPEATED = 256

# field -> (wire type, kind, repeated)
_CONTEXT_SPEC = {
    1: (0, "int", False),
    2: (0, "int", False),
    4: (0, "int", False),
    6: (2, "text", False),
    9: (2, "text", False),
}
_EXIT_SPEC = {1: (0, "int", False), 2: (0, "int", False)}
_PAYLOAD_SPECS = {
    1: {
        1: (2, "message", False),
        2: (2, "text", False),
        3: (2, "text", False),
        4: (2, "text", True),
        5: (2, "text", True),
        6: (0, "int", False),
    },
    2: {
        1: (2, "message", False),
        3: (0, "int", False),
        4: (0, "int", False),
        5: (0, "int", False),
        6: (0, "int", False),
    },
    5: {1: (2, "message", False), 2: (0, "int", False)},
    7: {
        1: (2, "message", False),
        2: (2, "message", False),
        3: (0, "int", False),
        4: (0, "int", False),
        5: (2, "text", False),
        6: (2, "text", False),
        7: (0, "int", False),
        8: (0, "int", False),
    },
    11: {
        1: (2, "message", False),
        2: (2, "message", False),
        3: (0, "int", False),
        4: (0, "int", False),
        5: (2, "text", False),
        6: (2, "text", False),
        7: (2, "text", True),
        8: (2, "text", True),
        9: (0, "int", False),
    },
    34: {
        1: (2, "message", False),
        2: (2, "message", False),
        3: (0, "int", False),
        4: (0, "int", False),
        5: (2, "text", False),
        6: (0, "int", False),
        7: (0, "int", False),
        8: (0, "int", False),
        9: (0, "int", False),
    },
}
_REQUIRED_FIELDS = {
    1: {1, 2, 3, 4},
    2: {1, 3, 4, 5, 6},
    5: {1},
    7: {1, 3, 4, 6},
    11: {1, 3, 6, 7},
    34: {1, 3, 4, 6},
}
_SYSCALL_NUMBERS = {7: 56, 11: 221, 34: 64}
_POINTS = {
    1: "container/start",
    2: "sentry/clone",
    5: "sentry/task_exit",
    7: "syscall/openat",
    11: "syscall/execve",
    34: "syscall/write",
}


class Phase2ExitGateError(ValueError):
    """One or more Phase 2 exit leaves did not replay exactly."""


def gate_implementation_digest(path: str | Path = __file__) -> str:
    """Return the exact evaluator-script identity held by the operator."""

    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def evaluate_phase2_exit(
    work_root: str | Path,
    backend_state: str | Path,
    *,
    expected_coverage_lock_digest: str,
    backend_receipt_digest: str,
    expected_backend_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_backend_implementation_digest: str,
    expected_gate_implementation_digest: str,
) -> dict[str, Any]:
    """Recompute all three leaves and derive one bounded completion report."""

    expected_gate = _digest(
        expected_gate_implementation_digest, "expected gate implementation"
    )
    if gate_implementation_digest() != expected_gate:
        raise Phase2ExitGateError("Phase 2 gate implementation digest changed")
    root = Path(work_root).resolve(strict=True)
    suite = root / "suite/phase2-suite.json"
    outcomes_path = root / "results/outcomes.jsonl"
    metrics_path = root / "results/report.json"
    coverage_path = root / "coverage-lock.json"
    evidence_path = root / "evidence"
    for label, path in (
        ("suite", suite),
        ("outcomes", outcomes_path),
        ("metrics report", metrics_path),
        ("coverage lock", coverage_path),
    ):
        if not path.is_file() or path.is_symlink():
            raise Phase2ExitGateError(f"Phase 2 {label} is unavailable")

    expected_coverage = _digest(expected_coverage_lock_digest, "expected coverage lock")
    coverage_raw, coverage = _canonical_file(coverage_path, "Phase 2 coverage lock")
    if _raw_digest(coverage_raw) != expected_coverage:
        raise Phase2ExitGateError("Phase 2 coverage lock digest changed")
    if coverage.get("schema") != "aragorn/benchmark-phase2-coverage-lock/v3":
        raise Phase2ExitGateError("Phase 2 exit requires the v3 coverage lock")

    metrics = evaluate_files(
        suite,
        outcomes_path,
        evidence_state=evidence_path,
        phase2_metrics_checkpoint=True,
        phase2_coverage_lock=coverage_path,
        expected_phase2_coverage_lock_digest=expected_coverage,
    )
    _metrics_leaf(metrics, _canonical_file(metrics_path, "Phase 2 metrics report")[1])
    outcomes = _json_lines(outcomes_path)
    if len(outcomes) != EXPECTED_CELLS:
        raise Phase2ExitGateError("Phase 2 exit requires exactly 100 outcomes")

    evidence = CAS(evidence_path, read_only=True)
    capture = _capture_leaf(
        evidence,
        outcomes,
        coverage,
        metrics,
        expected_runtime_lock_digest=_digest(
            expected_runtime_lock_digest, "expected runtime lock"
        ),
    )
    backend = _backend_leaf(
        CAS(Path(backend_state).resolve(strict=True), read_only=True),
        backend_receipt_digest=_digest(backend_receipt_digest, "backend receipt"),
        expected_backend_lock_digest=_digest(
            expected_backend_lock_digest, "expected backend lock"
        ),
        expected_runtime_lock_digest=_digest(
            expected_runtime_lock_digest, "expected runtime lock"
        ),
        expected_backend_implementation_digest=_digest(
            expected_backend_implementation_digest,
            "expected backend implementation",
        ),
        expected_canary_lock_digest=coverage["gvisor"]["lock_digest"],
    )
    return {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "scope": SCOPE,
        "gate_implementation_digest": expected_gate,
        "metrics": {
            "status": "PASS",
            "report_digest": canonical_digest(metrics),
            "coverage_lock_digest": expected_coverage,
            "suite_digest": metrics["suite_digest"],
            "outcomes_digest": metrics["outcomes_digest"],
            "candidate": metrics["candidate"],
            "scenario_schedule": metrics["scenario_schedule"],
        },
        "capture": capture,
        "backend": backend,
        "decision": {
            "status": "PASS",
            "phase2_exit_eligible": True,
            "phase3_engineering_eligible": True,
            "phase3_edr_claim_eligible": False,
            "public_release_eligible": False,
            "reason_codes": [],
        },
        "limitations": list(LIMITATIONS),
    }


def verify_phase2_exit(
    report: object,
    work_root: str | Path,
    backend_state: str | Path,
    **pins: str,
) -> None:
    """Reject supplied completion fields by recomputing every leaf."""

    if report != evaluate_phase2_exit(work_root, backend_state, **pins):
        raise Phase2ExitGateError("Phase 2 exit report does not match replay")


def _metrics_leaf(derived: dict[str, Any], recorded: object) -> None:
    if recorded != derived:
        raise Phase2ExitGateError("recorded Phase 2 metrics report changed")
    if (
        derived.get("schema") != METRICS_SCHEMA
        or derived.get("phase2_exit_eligible") is not False
        or derived.get("missing_phase2_exit_requirements")
        != MISSING_METRICS_REQUIREMENTS
        or derived.get("decision")
        != {"evaluable": True, "metrics_passed": True, "reason_codes": []}
    ):
        raise Phase2ExitGateError("Phase 2 v3 numerical metrics are not PASS")


def _capture_leaf(
    cas: CAS,
    outcomes: list[dict[str, Any]],
    coverage: dict[str, Any],
    metrics: dict[str, Any],
    *,
    expected_runtime_lock_digest: str,
) -> dict[str, Any]:
    gvisor = _object(coverage.get("gvisor"), "coverage gVisor binding")
    canary_digest = _digest(gvisor.get("lock_digest"), "matrix canary lock")
    canary = _canary_lock(cas.read(canary_digest, max_bytes=64 * 1024))
    remote_pin = _object(canary.get("remote_trace"), "matrix remote trace pin")
    if (
        canary.get("schema") != "aragorn/gvisor-detonation-canary-lock/v2"
        or canary.get("runtime_lock_digest") != expected_runtime_lock_digest
        or remote_pin.get("profile") != REMOTE_PROFILE
    ):
        raise Phase2ExitGateError("matrix remote canary profile changed")
    runtime = _runtime_lock(cas.read(expected_runtime_lock_digest, max_bytes=64 * 1024))
    if (
        runtime["release"]["source_commit"] != RUNTIME_SOURCE_COMMIT
        or runtime["image"]["architecture"] != RUNTIME_ARCHITECTURE
    ):
        raise Phase2ExitGateError("matrix runtime source or architecture changed")
    session_digest = _digest(
        remote_pin.get("session_config_digest"), "remote session configuration"
    )
    monitor_digest = _digest(
        remote_pin.get("monitor_implementation_digest"),
        "remote monitor implementation",
    )
    _verify_session_configuration(cas.read(session_digest, max_bytes=64 * 1024))

    schedule = metrics["scenario_schedule"]
    cells: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    workload_receipts: set[str] = set()
    remote_receipts: set[str] = set()
    run_ids: set[str] = set()
    container_ids: set[str] = set()
    frame_total = 0
    byte_total = 0
    for index, outcome in enumerate(outcomes):
        label = f"outcomes[{index}]"
        if not isinstance(outcome, dict):
            raise Phase2ExitGateError(f"{label} must be an object")
        run_number = outcome.get("run_id")
        if type(run_number) is not int or not 1 <= run_number <= len(schedule):
            raise Phase2ExitGateError(f"{label} run is invalid")
        scenario = schedule[run_number - 1]
        envelope_digest = _digest(outcome.get("evidence_digest"), f"{label} evidence")
        envelope = _canonical_cas(cas, envelope_digest, f"{label} envelope")
        if envelope.get("scenario_id") != scenario:
            raise Phase2ExitGateError(f"{label} scenario changed")
        workload_digest = _digest(
            envelope.get("gvisor_receipt_digest"), f"{label} workload receipt"
        )
        remote_digest = _digest(
            envelope.get("remote_trace_receipt_digest"), f"{label} remote receipt"
        )
        workload = _canonical_cas(cas, workload_digest, f"{label} workload")
        run_request = _canonical_cas(
            cas,
            _digest(workload.get("run_request_digest"), f"{label} run request"),
            f"{label} run request",
        )
        container_id = _container_id(run_request.get("container_id"), label)
        workload_run_id = _run_id(workload.get("run_id"), label)
        remote = verify_gvisor_remote_trace_capture(
            cas,
            remote_digest,
            expected_runtime_lock_digest=expected_runtime_lock_digest,
            expected_session_config_digest=session_digest,
            expected_monitor_implementation_digest=monitor_digest,
            expected_workload_receipt_digest=workload_digest,
        )
        if (
            remote.get("schema") != REMOTE_RECEIPT_SCHEMA
            or remote.get("profile") != REMOTE_PROFILE
            or remote.get("run_id") != workload_run_id
            or remote.get("sandbox_id") != container_id
            or remote.get("container_id") != container_id
            or remote.get("workload_receipt_digest") != workload_digest
            or run_request.get("runtime_lock_digest") != expected_runtime_lock_digest
            or run_request.get("scenario_id") != scenario
        ):
            raise Phase2ExitGateError(f"{label} remote/workload binding changed")
        counts = _decode_capture(cas, remote, scenario=scenario)
        if set(counts) != set(REQUIRED_POINTS) or any(
            counts[point] < 1 for point in REQUIRED_POINTS
        ):
            raise Phase2ExitGateError(f"{label} lacks configured-point coverage")
        for point, count in counts.items():
            totals[point] += count
        frame_total += remote["frame_count"]
        byte_total += remote["raw_frame_bytes"]
        cells.append(
            {
                "case_id": outcome["case_id"],
                "run_id": run_number,
                "scenario_id": scenario,
                "evidence_digest": envelope_digest,
                "workload_receipt_digest": workload_digest,
                "remote_receipt_digest": remote_digest,
                "gvisor_run_id": workload_run_id,
                "container_id": container_id,
                "frame_manifest_digest": remote["frame_manifest_digest"],
                "point_counts": dict(sorted(counts.items())),
            }
        )
        for value, seen, name in (
            (workload_digest, workload_receipts, "workload receipt"),
            (remote_digest, remote_receipts, "remote receipt"),
            (workload_run_id, run_ids, "gVisor run ID"),
            (container_id, container_ids, "container ID"),
        ):
            if value in seen:
                raise Phase2ExitGateError(f"Phase 2 capture repeats {name}")
            seen.add(value)
    if len(cells) != EXPECTED_CELLS:
        raise Phase2ExitGateError("Phase 2 capture cell count changed")
    return {
        "status": "PASS",
        "profile": "pinned-gvisor-remote-v1-configured-point-protobuf/v1",
        "canary_lock_digest": canary_digest,
        "runtime_lock_digest": expected_runtime_lock_digest,
        "runtime_source_commit": RUNTIME_SOURCE_COMMIT,
        "architecture": RUNTIME_ARCHITECTURE,
        "session_config_digest": session_digest,
        "monitor_implementation_digest": monitor_digest,
        "cells": len(cells),
        "complete_cells": len(cells),
        "unique_remote_receipts": len(remote_receipts),
        "frame_count": frame_total,
        "raw_frame_bytes": byte_total,
        "required_points": list(REQUIRED_POINTS),
        "observed_point_counts": dict(sorted(totals.items())),
        "matrix_bindings_digest": canonical_digest(cells),
    }


def _backend_leaf(
    cas: CAS,
    *,
    backend_receipt_digest: str,
    expected_backend_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_backend_implementation_digest: str,
    expected_canary_lock_digest: str,
) -> dict[str, Any]:
    receipt = verify_gvisor_backend_qualification(
        cas,
        backend_receipt_digest,
        expected_lock_digest=expected_backend_lock_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_implementation_digest=expected_backend_implementation_digest,
    )
    lock_raw = cas.read(expected_backend_lock_digest, max_bytes=64 * 1024)
    lock = _qualification_lock(lock_raw)
    canary_digest = _digest(lock.get("canary_lock_digest"), "backend canary lock")
    if canary_digest != expected_canary_lock_digest:
        raise Phase2ExitGateError("backend and matrix canary locks differ")
    canary = _canary_lock(cas.read(canary_digest, max_bytes=64 * 1024))
    runtime = _runtime_lock(cas.read(expected_runtime_lock_digest, max_bytes=64 * 1024))
    if (
        canary.get("schema") != "aragorn/gvisor-detonation-canary-lock/v2"
        or canary.get("runtime_lock_digest") != expected_runtime_lock_digest
        or canary.get("daemon_config_digest") != lock.get("daemon_config_digest")
        or runtime["release"]["source_commit"] != RUNTIME_SOURCE_COMMIT
        or runtime["image"]["architecture"] != RUNTIME_ARCHITECTURE
    ):
        raise Phase2ExitGateError("backend qualification profile is not matrix exact")
    runs = receipt.get("runs")
    if not isinstance(runs, list) or len(runs) != EXPECTED_RUNS:
        raise Phase2ExitGateError("backend qualification does not contain three runs")
    return {
        "status": "PASS",
        "receipt_digest": backend_receipt_digest,
        "lock_digest": expected_backend_lock_digest,
        "canary_lock_digest": canary_digest,
        "runtime_lock_digest": expected_runtime_lock_digest,
        "implementation_digest": expected_backend_implementation_digest,
        "runs": len(runs),
        "unique_run_ids": len({run["run_id"] for run in runs}),
        "unique_container_ids": len({run["container_id"] for run in runs}),
    }


def _decode_capture(
    cas: CAS,
    receipt: dict[str, Any],
    *,
    scenario: str,
) -> Counter[str]:
    manifest = _canonical_cas(
        cas,
        _digest(receipt.get("frame_manifest_digest"), "frame manifest"),
        "frame manifest",
    )
    frames = manifest.get("frames")
    if not isinstance(frames, list) or len(frames) != receipt.get("frame_count"):
        raise Phase2ExitGateError("remote frame manifest is incomplete")
    container_id = _container_id(receipt.get("container_id"), "remote receipt")
    counts: Counter[str] = Counter()
    pending: dict[tuple[int, int], tuple[tuple[int, int, object], ...]] = {}
    previous_time = 0
    starts = 0
    byte_total = 0
    for sequence, item in enumerate(frames):
        frame = _object(item, f"frame[{sequence}]")
        wire = cas.read(
            _digest(frame.get("digest"), "frame digest"), max_bytes=_MAX_FRAME_BYTES
        )
        if len(wire) != frame.get("size") or len(wire) < _HEADER.size + 1:
            raise Phase2ExitGateError("remote frame size changed")
        header_size, message_type, dropped = _HEADER.unpack_from(wire)
        if (
            header_size != _HEADER.size
            or dropped != 0
            or message_type not in _PAYLOAD_SPECS
        ):
            raise Phase2ExitGateError(
                "remote frame header or message type is unsupported"
            )
        fields = _protobuf_fields(wire[_HEADER.size :], f"frame[{sequence}] payload")
        _validate_fields(
            fields,
            _PAYLOAD_SPECS[message_type],
            _REQUIRED_FIELDS[message_type],
            f"frame[{sequence}] payload",
        )
        context_raw = _single(fields, 1, f"frame[{sequence}] context")
        assert isinstance(context_raw, bytes)
        context = _protobuf_fields(context_raw, f"frame[{sequence}] context")
        _validate_fields(
            context,
            _CONTEXT_SPEC,
            set(_CONTEXT_SPEC),
            f"frame[{sequence}] context",
        )
        timestamp = _integer(_single(context, 1, "context time"), "context time")
        thread_id = _integer(_single(context, 2, "context thread"), "context thread")
        group_id = _integer(_single(context, 4, "context group"), "context group")
        observed_container = _text(
            _single(context, 6, "context container"), "context container"
        )
        process_name = _text(_single(context, 9, "context process"), "context process")
        if (
            timestamp <= previous_time
            or thread_id <= 0
            or group_id <= 0
            or observed_container != container_id
            or not process_name
        ):
            raise Phase2ExitGateError("remote frame context changed or is unordered")
        previous_time = timestamp
        _validate_text_fields(fields, _PAYLOAD_SPECS[message_type])
        point = _POINTS[message_type]
        if message_type == 1:
            starts += 1
            if sequence != 0 or starts != 1:
                raise Phase2ExitGateError(
                    "container/start is not the single first frame"
                )
            start_id = _text(
                _single(fields, 2, "container start id"), "container start id"
            )
            args = [_text(value, "container start arg") for value in _values(fields, 4)]
            environment = _environment(
                _values(fields, 5), "container start environment"
            )
            if (
                start_id != container_id
                or args != ["/bin/sleep", "30"]
                or environment
                != {
                    "ARAGORN_SCENARIO": scenario,
                    "HOSTNAME": container_id[:12],
                    "PATH": "/bin",
                }
            ):
                raise Phase2ExitGateError(
                    "container/start identity or scenario changed"
                )
            counts[point] += 1
        elif message_type in _SYSCALL_NUMBERS:
            sysno = _integer(_single(fields, 3, "syscall number"), "syscall number")
            if sysno != _SYSCALL_NUMBERS[message_type]:
                raise Phase2ExitGateError("remote syscall number is not pinned arm64")
            is_exit = bool(_values(fields, 2))
            if is_exit:
                exit_raw = _single(fields, 2, "syscall exit")
                assert isinstance(exit_raw, bytes)
                _validate_fields(
                    _protobuf_fields(exit_raw, "syscall exit"),
                    _EXIT_SPEC,
                    set(),
                    "syscall exit",
                )
            signature = tuple(
                (number, wire_type, value)
                for number, wire_type, value in fields
                if number not in {1, 2}
            )
            key = (message_type, thread_id)
            if is_exit:
                if pending.pop(key, None) != signature:
                    raise Phase2ExitGateError("syscall exit has no matching enter")
                counts[f"{point}/exit"] += 1
            else:
                if key in pending:
                    raise Phase2ExitGateError("syscall enter overlaps a pending call")
                pending[key] = signature
                counts[f"{point}/enter"] += 1
        else:
            counts[point] += 1
        byte_total += len(wire)
    if starts != 1 or pending or byte_total != receipt.get("raw_frame_bytes"):
        raise Phase2ExitGateError(
            "remote capture is incomplete or has dangling syscalls"
        )
    return counts


def _verify_session_configuration(raw: bytes) -> None:
    document = _canonical_bytes(raw.removesuffix(b"\n"), "remote session configuration")
    session = _object(document.get("trace_session"), "remote trace session")
    expected = [
        ("container/start", ["env"]),
        ("sentry/clone", []),
        ("sentry/task_exit", []),
        ("syscall/execve/enter", ["envv"]),
        ("syscall/execve/exit", ["envv"]),
        ("syscall/openat/enter", ["fd_path"]),
        ("syscall/openat/exit", ["fd_path"]),
        ("syscall/write/enter", ["fd_path"]),
        ("syscall/write/exit", ["fd_path"]),
    ]
    points = session.get("points")
    if (
        not isinstance(points, list)
        or any(not isinstance(point, dict) for point in points)
        or [(point.get("name"), point.get("optional_fields")) for point in points]
        != expected
        or any(
            point.get("context_fields")
            != ["container_id", "group_id", "process_name", "thread_id", "time"]
            for point in points
        )
    ):
        raise Phase2ExitGateError("remote session is not the exact nine-point profile")


def _protobuf_fields(raw: bytes, label: str) -> list[tuple[int, int, object]]:
    fields: list[tuple[int, int, object]] = []
    offset = 0
    while offset < len(raw):
        key, offset = _varint(raw, offset, label)
        number, wire_type = key >> 3, key & 7
        if number == 0:
            raise Phase2ExitGateError(f"{label} contains field zero")
        if wire_type == 0:
            value, offset = _varint(raw, offset, label)
        elif wire_type == 1:
            end = offset + 8
            if end > len(raw):
                raise Phase2ExitGateError(f"{label} fixed64 is truncated")
            value, offset = raw[offset:end], end
        elif wire_type == 2:
            size, offset = _varint(raw, offset, label)
            end = offset + size
            if end > len(raw):
                raise Phase2ExitGateError(f"{label} bytes field is truncated")
            value, offset = raw[offset:end], end
        elif wire_type == 5:
            end = offset + 4
            if end > len(raw):
                raise Phase2ExitGateError(f"{label} fixed32 is truncated")
            value, offset = raw[offset:end], end
        else:
            raise Phase2ExitGateError(f"{label} uses unsupported protobuf wire type")
        fields.append((number, wire_type, value))
        if len(fields) > 4096:
            raise Phase2ExitGateError(f"{label} has too many protobuf fields")
    return fields


def _varint(raw: bytes, offset: int, label: str) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(raw):
            raise Phase2ExitGateError(f"{label} varint is truncated")
        byte = raw[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise Phase2ExitGateError(f"{label} varint overflows uint64")
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            if index and value < 1 << (7 * index):
                raise Phase2ExitGateError(f"{label} varint is not minimal")
            return value, offset
    raise Phase2ExitGateError(f"{label} varint exceeds ten bytes")


def _validate_fields(
    fields: list[tuple[int, int, object]],
    spec: dict[int, tuple[int, str, bool]],
    required: set[int],
    label: str,
) -> None:
    counts = Counter(number for number, _wire, _value in fields)
    if not required.issubset(counts):
        raise Phase2ExitGateError(f"{label} lacks required fields")
    for number, wire_type, _value in fields:
        rule = spec.get(number)
        if rule is None or wire_type != rule[0]:
            raise Phase2ExitGateError(f"{label} has an unknown or mistyped field")
        if not rule[2] and counts[number] != 1:
            raise Phase2ExitGateError(f"{label} repeats a scalar field")
        if rule[2] and counts[number] > _MAX_REPEATED:
            raise Phase2ExitGateError(f"{label} repeats a field too many times")


def _validate_text_fields(
    fields: list[tuple[int, int, object]],
    spec: dict[int, tuple[int, str, bool]],
) -> None:
    for number, _wire, value in fields:
        if spec[number][1] == "text":
            _text(value, f"protobuf field {number}")


def _single(fields: list[tuple[int, int, object]], number: int, label: str) -> object:
    values = _values(fields, number)
    if len(values) != 1:
        raise Phase2ExitGateError(f"{label} must occur exactly once")
    return values[0]


def _values(fields: list[tuple[int, int, object]], number: int) -> list[object]:
    return [value for field, _wire, value in fields if field == number]


def _environment(values: list[object], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        item = _text(value, label)
        if "=" not in item:
            raise Phase2ExitGateError(f"{label} entry has no equals sign")
        name, content = item.split("=", 1)
        if not name or name in result:
            raise Phase2ExitGateError(f"{label} repeats or omits a name")
        result[name] = content
    return result


def _text(value: object, label: str) -> str:
    if not isinstance(value, bytes) or len(value) > _MAX_STRING_BYTES:
        raise Phase2ExitGateError(f"{label} is not bounded bytes")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Phase2ExitGateError(f"{label} is not UTF-8") from exc
    if "\x00" in text:
        raise Phase2ExitGateError(f"{label} contains NUL")
    return text


def _integer(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise Phase2ExitGateError(f"{label} is not a uint64")
    return value


def _canonical_file(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    return raw, _canonical_bytes(raw.removesuffix(b"\n"), label)


def _canonical_cas(cas: CAS, digest: str, label: str) -> dict[str, Any]:
    return _canonical_bytes(cas.read(digest, max_bytes=_MAX_DOCUMENT_BYTES), label)


def _canonical_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Phase2ExitGateError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise Phase2ExitGateError(f"{label} is not a canonical JSON object")
    return document


def _json_lines(path: Path) -> list[dict[str, Any]]:
    rows = []
    for index, raw in enumerate(path.read_bytes().splitlines()):
        document = _canonical_bytes(raw, f"outcomes line {index + 1}")
        rows.append(document)
    return rows


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Phase2ExitGateError(f"{label} must be an object")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise Phase2ExitGateError(f"{label} is not a SHA-256 digest")
    return value


def _run_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise Phase2ExitGateError(f"{label} run ID is invalid")
    return value


def _container_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _CONTAINER_ID.fullmatch(value) is None:
        raise Phase2ExitGateError(f"{label} container ID is invalid")
    return value


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root")
    parser.add_argument("backend_state")
    parser.add_argument("--expected-coverage-lock-digest", required=True)
    parser.add_argument("--backend-receipt-digest", required=True)
    parser.add_argument("--expected-backend-lock-digest", required=True)
    parser.add_argument("--expected-runtime-lock-digest", required=True)
    parser.add_argument("--expected-backend-implementation-digest", required=True)
    parser.add_argument("--expected-gate-implementation-digest", required=True)
    parser.add_argument("--verify-report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    pins = {
        "expected_coverage_lock_digest": arguments.expected_coverage_lock_digest,
        "backend_receipt_digest": arguments.backend_receipt_digest,
        "expected_backend_lock_digest": arguments.expected_backend_lock_digest,
        "expected_runtime_lock_digest": arguments.expected_runtime_lock_digest,
        "expected_backend_implementation_digest": (
            arguments.expected_backend_implementation_digest
        ),
        "expected_gate_implementation_digest": (
            arguments.expected_gate_implementation_digest
        ),
    }
    try:
        report = evaluate_phase2_exit(
            arguments.work_root,
            arguments.backend_state,
            **pins,
        )
        if arguments.verify_report is not None:
            supplied = _canonical_file(
                Path(arguments.verify_report), "Phase 2 exit report"
            )[1]
            verify_phase2_exit(
                supplied,
                arguments.work_root,
                arguments.backend_state,
                **pins,
            )
    except (
        Phase2ExitGateError,
        GVisorBackendQualificationError,
        GVisorRemoteTraceCaptureError,
        CASError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "aragorn/error/v1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    sys.stdout.buffer.write(canonical_json(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
