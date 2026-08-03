"""Run one prepared, lock-bound Phase 2 gVisor matrix sequentially."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Sequence
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from .acquire import InventoryError
from .behavior_capability_diff import (
    BehaviorCapabilityDiffError,
    verify_behavior_capability_diff,
)
from .benchmark import (
    _MAX_EVIDENCE_BYTES,
    _PHASE2_GVISOR_EVIDENCE_AUTHORITY,
    _PHASE2_GVISOR_EVIDENCE_AUTHORITY_V2,
    _PHASE2_GVISOR_EVIDENCE_AUTHORITY_V3,
    _PHASE2_GVISOR_EVIDENCE_SCHEMA,
    _PHASE2_GVISOR_EVIDENCE_SCHEMA_V2,
    _PHASE2_GVISOR_EVIDENCE_SCHEMA_V3,
    _PHASE2_RUNS_PER_CASE,
    BenchmarkError,
    _digest,
    _identifier,
    _read_bounded,
    _read_canonical_document,
    _relative_path,
    _validate_phase2_coverage_lock,
    evaluate_files,
    load_suite_for_run,
)
from .cas import CAS, CASError
from .gvisor_runtime import (
    ARTIFACT_SCHEMA_V4,
    ARTIFACT_SCHEMA_V5,
    GVisorRuntimeError,
    collect_gvisor_acquired_artifact,
    collect_gvisor_remote_traced_acquired_artifact,
    verify_gvisor_acquired_artifact,
)
from .oci_worker_protocol import WorkerProtocolError, canonical_json

_INDEX_SCHEMA = "aragorn/phase2-matrix-operator-index/v1"
_INDEX_AUTHORITY = "RELATIVE_PATH_HINTS_ONLY_NOT_EVIDENCE_OR_PHASE2_AUTHORITY"
_INDEX_FIELDS = {
    "schema",
    "authority",
    "coverage_lock_digest",
    "suite_path",
    "coverage_lock_path",
    "evidence_state_path",
    "results_path",
    "cases",
}
_CASE_FIELDS = {"case_id", "source_state_path"}
_OUTCOME_SCHEMA = "aragorn/benchmark-outcome/v1"
_REVIEW_REASON = "UNDECLARED_OBSERVED_CAPABILITY"
_EXPECTED_CASES = 20
_EXPECTED_OUTCOMES = _EXPECTED_CASES * _PHASE2_RUNS_PER_CASE

Collector = Callable[..., str | tuple[str, str]]


class Phase2MatrixRunError(ValueError):
    """A prepared Phase 2 matrix cannot be run without weakening its bindings."""


def run_phase2_matrix(
    work_root: str | os.PathLike[str],
    *,
    expected_coverage_lock_digest: str,
    _collector: Collector | None = None,
) -> dict[str, Any]:
    """Collect, retain, and evaluate exactly one prepared 20-by-5 matrix."""

    root = _work_root(work_root)
    index_path = root / "operator-index.json"
    index = _load_index(index_path)
    expected_lock = _digest(
        expected_coverage_lock_digest,
        "caller-held expected Phase 2 coverage lock digest",
    )
    if index["coverage_lock_digest"] != expected_lock:
        raise Phase2MatrixRunError(
            "operator index coverage lock does not match the caller-held digest"
        )

    suite_path = _existing_file(root, index["suite_path"], "suite_path")
    lock_path = _existing_file(root, index["coverage_lock_path"], "coverage_lock_path")
    evidence_path = _output_directory(
        root, index["evidence_state_path"], "evidence_state_path"
    )
    results_path = _new_output_path(root, index["results_path"], "results_path")

    indexed_sources = _indexed_sources(root, index["cases"])
    boundaries = [
        ("suite", suite_path.parent),
        ("coverage lock", lock_path),
        ("operator index", index_path),
        ("evidence state", evidence_path),
        ("results", results_path),
        *(
            (f"source state for {case_id}", path)
            for case_id, path in indexed_sources.items()
        ),
    ]
    for position, (label, path) in enumerate(boundaries):
        for other_label, other_path in boundaries[position + 1 :]:
            if _paths_overlap(path, other_path):
                raise Phase2MatrixRunError(f"{label} overlaps {other_label}")

    evidence = CAS(evidence_path)
    suite = load_suite_for_run(
        suite_path,
        evidence,
        required_purpose="evidence_smoke",
    )
    binding = _validate_phase2_coverage_lock(
        lock_path,
        expected_digest=expected_lock,
        suite_digest=suite["digest"],
        runs_per_case=suite["runs_per_case"],
        cases=suite["cases"],
        systems=suite["systems"],
        manifests=suite["manifests"],
    )
    case_ids = sorted(binding["cases"])
    if (
        suite["runs_per_case"] != _PHASE2_RUNS_PER_CASE
        or len(case_ids) != _EXPECTED_CASES
        or set(suite["cases"]) != set(case_ids)
        or set(indexed_sources) != set(case_ids)
    ):
        raise Phase2MatrixRunError(
            "prepared matrix must contain exactly 20 locked cases and five runs"
        )
    if len(suite["systems"]) != 1 or binding["candidate_key"] not in suite["systems"]:
        raise Phase2MatrixRunError(
            "prepared matrix must contain only the locked Aragorn candidate"
        )

    source_states = {
        case_id: CAS(indexed_sources[case_id], read_only=True) for case_id in case_ids
    }
    system = suite["systems"][binding["candidate_key"]]
    remote_trace = binding.get("remote_trace")
    collector = _collector or (
        collect_gvisor_remote_traced_acquired_artifact
        if remote_trace is not None
        else collect_gvisor_acquired_artifact
    )
    outcomes: list[dict[str, Any]] = []

    # ponytail: serial by design; the collector owns one host-global lock.
    for case_id in case_ids:
        pins = binding["cases"][case_id]
        for run_id in range(1, _PHASE2_RUNS_PER_CASE + 1):
            run_pins = dict(pins)
            scenario_schedule = binding["scenario_schedule"]
            scenario_id = (
                scenario_schedule[run_id - 1]
                if scenario_schedule is not None
                else None
            )
            if scenario_id is not None:
                run_pins["expected_scenario_id"] = scenario_id
            capture_pins = dict(run_pins)
            capture_pins["normalization_profile"] = capture_pins.pop(
                "expected_normalization_profile"
            )
            collected = collector(
                evidence,
                source_states[case_id],
                **capture_pins,
            )
            remote_receipt_digest: str | None = None
            if remote_trace is not None:
                if type(collected) is not tuple or len(collected) != 2:
                    raise Phase2MatrixRunError(
                        "remote collector must return exactly two receipt digests"
                    )
                receipt_digest = _digest(
                    collected[0], "Phase 2 gVisor workload receipt"
                )
                remote_receipt_digest = _digest(
                    collected[1], "Phase 2 gVisor remote trace receipt"
                )
            else:
                if not isinstance(collected, str):
                    raise Phase2MatrixRunError(
                        "gVisor collector must return one receipt digest"
                    )
                receipt_digest = collected
            receipt = verify_gvisor_acquired_artifact(
                evidence,
                receipt_digest,
                **run_pins,
            )
            _reject_unknown_attribution_scope(evidence, receipt)
            verdict, reason_codes = _verdict_from_verified_diff(
                evidence,
                receipt,
                run_pins,
            )
            envelope = {
                "schema": (
                    _PHASE2_GVISOR_EVIDENCE_SCHEMA_V3
                    if remote_receipt_digest is not None
                    else (
                        _PHASE2_GVISOR_EVIDENCE_SCHEMA_V2
                        if scenario_id is not None
                        else _PHASE2_GVISOR_EVIDENCE_SCHEMA
                    )
                ),
                "authority": (
                    _PHASE2_GVISOR_EVIDENCE_AUTHORITY_V3
                    if remote_receipt_digest is not None
                    else (
                        _PHASE2_GVISOR_EVIDENCE_AUTHORITY_V2
                        if scenario_id is not None
                        else _PHASE2_GVISOR_EVIDENCE_AUTHORITY
                    )
                ),
                "coverage_lock_digest": expected_lock,
                "suite_digest": suite["digest"],
                "case_id": case_id,
                "tree_digest": pins["expected_tree_digest"],
                "run_id": run_id,
                "system": system,
                "gvisor_receipt_digest": receipt_digest,
                "verdict": verdict,
                "reason_codes": reason_codes,
            }
            if scenario_id is not None:
                envelope["scenario_id"] = scenario_id
            if remote_receipt_digest is not None:
                envelope["remote_trace_receipt_digest"] = remote_receipt_digest
            evidence_digest = evidence.put(
                BytesIO(canonical_json(envelope)),
                max_bytes=_MAX_EVIDENCE_BYTES,
            )
            outcomes.append(
                {
                    "schema": _OUTCOME_SCHEMA,
                    "suite_digest": suite["digest"],
                    "case_id": case_id,
                    "tree_digest": pins["expected_tree_digest"],
                    "run_id": run_id,
                    "system": system,
                    "evidence_digest": evidence_digest,
                    "verdict": verdict,
                    "reason_codes": reason_codes,
                }
            )

    if len(outcomes) != _EXPECTED_OUTCOMES:
        raise Phase2MatrixRunError(
            "Phase 2 matrix did not produce exactly 100 outcomes"
        )
    outcome_bytes = b"".join(canonical_json(item) + b"\n" for item in outcomes)
    staged_results = _results_stage(results_path)
    published = False
    try:
        staged_outcomes = staged_results / "outcomes.jsonl"
        _write_result(staged_outcomes, outcome_bytes)
        report = evaluate_files(
            suite_path,
            staged_outcomes,
            evidence_state=evidence_path,
            phase2_metrics_checkpoint=True,
            phase2_coverage_lock=lock_path,
            expected_phase2_coverage_lock_digest=expected_lock,
        )
        _write_result(staged_results / "report.json", canonical_json(report) + b"\n")
        _fsync_directory(staged_results)
        os.rename(staged_results, results_path)
        published = True
        _fsync_directory(results_path.parent)
    except BaseException:
        if published:
            _remove_results(results_path)
        _remove_results(staged_results)
        raise
    return report


def _reject_unknown_attribution_scope(cas: CAS, receipt: object) -> None:
    if not isinstance(receipt, dict) or receipt.get("schema") not in {
        ARTIFACT_SCHEMA_V4,
        ARTIFACT_SCHEMA_V5,
    }:
        raise Phase2MatrixRunError("collector did not verify a supported gVisor receipt")
    attribution = _read_canonical_document(
        cas,
        receipt.get("attribution_manifest_digest"),
        "Phase 2 attribution manifest",
        max_bytes=2 * 1024 * 1024,
    )
    events = attribution.get("events")
    if not isinstance(events, list):
        raise Phase2MatrixRunError("verified attribution manifest has invalid events")
    if any(
        isinstance(event, dict) and event.get("scope") == "unknown" for event in events
    ):
        raise Phase2MatrixRunError("verified replay has an unknown attribution scope")


def _verdict_from_verified_diff(
    cas: CAS,
    receipt: object,
    pins: dict[str, Any],
) -> tuple[str, list[str]]:
    if not isinstance(receipt, dict) or receipt.get("schema") not in {
        ARTIFACT_SCHEMA_V4,
        ARTIFACT_SCHEMA_V5,
    }:
        raise Phase2MatrixRunError("collector did not verify a supported gVisor receipt")
    diff_receipt = _read_canonical_document(
        cas,
        receipt.get("capability_diff_receipt_digest"),
        "Phase 2 capability diff receipt",
        max_bytes=2 * 1024 * 1024,
    )
    capability_diff = _read_canonical_document(
        cas,
        diff_receipt.get("capability_diff_digest"),
        "Phase 2 capability diff",
        max_bytes=16 * 1024,
    )
    verified = verify_behavior_capability_diff(
        capability_diff,
        expected_subject_digest=pins["expected_tree_digest"],
        expected_declared_capabilities=pins["expected_declared_capabilities"],
        expected_observed_capabilities=capability_diff.get("observed_capabilities"),
    )
    if verified["undeclared_observed_capabilities"]:
        return "REVIEW", [_REVIEW_REASON]
    return "ALLOW", []


def _load_index(path: Path) -> dict[str, Any]:
    raw = _read_bounded(path)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Phase2MatrixRunError(f"operator index is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or set(document) != _INDEX_FIELDS:
        raise Phase2MatrixRunError("operator index fields are invalid")
    if raw != canonical_json(document):
        raise Phase2MatrixRunError("operator index must use canonical JSON bytes")
    if document["schema"] != _INDEX_SCHEMA or document["authority"] != _INDEX_AUTHORITY:
        raise Phase2MatrixRunError("operator index authority is unsupported")
    document["coverage_lock_digest"] = _digest(
        document["coverage_lock_digest"], "operator index coverage_lock_digest"
    )
    raw_cases = document["cases"]
    if not isinstance(raw_cases, list) or len(raw_cases) != _EXPECTED_CASES:
        raise Phase2MatrixRunError("operator index must contain exactly 20 cases")
    normalized_cases = []
    seen: set[str] = set()
    for index, raw_case in enumerate(raw_cases):
        label = f"operator index cases[{index}]"
        if not isinstance(raw_case, dict) or set(raw_case) != _CASE_FIELDS:
            raise Phase2MatrixRunError(f"{label} fields are invalid")
        case_id = _identifier(raw_case["case_id"], f"{label}.case_id")
        if case_id in seen:
            raise Phase2MatrixRunError("operator index repeats a case")
        seen.add(case_id)
        normalized_cases.append(
            {
                "case_id": case_id,
                "source_state_path": _canonical_relative(
                    raw_case["source_state_path"], f"{label}.source_state_path"
                ),
            }
        )
    if [item["case_id"] for item in normalized_cases] != sorted(seen):
        raise Phase2MatrixRunError("operator index cases must be sorted by case_id")
    document["cases"] = normalized_cases
    for field in (
        "suite_path",
        "coverage_lock_path",
        "evidence_state_path",
        "results_path",
    ):
        document[field] = _canonical_relative(document[field], field)
    return document


def _work_root(value: str | os.PathLike[str]) -> Path:
    try:
        root = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixRunError(f"cannot resolve work root: {exc}") from exc
    if not root.is_dir():
        raise Phase2MatrixRunError("work root must be a directory")
    return root


def _canonical_relative(value: object, label: str) -> str:
    try:
        return _relative_path(value, label).as_posix()
    except BenchmarkError as exc:
        raise Phase2MatrixRunError(str(exc)) from exc


def _hint(root: Path, value: str, label: str) -> Path:
    relative = PurePosixPath(_canonical_relative(value, label))
    return root.joinpath(*relative.parts)


def _existing_file(root: Path, value: str, label: str) -> Path:
    path = _hint(root, value, label)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixRunError(f"{label} cannot be resolved: {exc}") from exc
    if resolved != path or not resolved.is_file():
        raise Phase2MatrixRunError(f"{label} must name a regular file without links")
    return resolved


def _existing_directory(root: Path, value: str, label: str) -> Path:
    path = _hint(root, value, label)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixRunError(f"{label} cannot be resolved: {exc}") from exc
    if resolved != path or not resolved.is_dir():
        raise Phase2MatrixRunError(f"{label} must name a directory without links")
    return resolved


def _output_directory(root: Path, value: str, label: str) -> Path:
    path = _hint(root, value, label)
    if path.exists() or path.is_symlink():
        return _existing_directory(root, value, label)
    _safe_parent(path, label)
    return path


def _new_output_path(root: Path, value: str, label: str) -> Path:
    path = _hint(root, value, label)
    _safe_parent(path, label)
    if path.exists() or path.is_symlink():
        raise Phase2MatrixRunError(f"{label} already exists")
    return path


def _safe_parent(path: Path, label: str) -> None:
    try:
        resolved = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixRunError(f"{label} parent cannot be resolved: {exc}") from exc
    if resolved != path.parent or not resolved.is_dir():
        raise Phase2MatrixRunError(f"{label} parent must be a directory without links")


def _indexed_sources(root: Path, raw_cases: list[dict[str, str]]) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    seen_paths: set[Path] = set()
    for item in raw_cases:
        case_id = item["case_id"]
        path = _existing_directory(
            root,
            item["source_state_path"],
            f"source_state_path for {case_id}",
        )
        if path in seen_paths:
            raise Phase2MatrixRunError("operator index reuses a source state path")
        seen_paths.add(path)
        sources[case_id] = path
    return sources


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _results_stage(target: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))


def _write_result(path: Path, raw: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remove_results(path: Path) -> None:
    if path.exists():
        parent = path.parent
        shutil.rmtree(path)
        _fsync_directory(parent)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aragorn.phase2_matrix_run",
        description="Run one prepared lock-bound Phase 2 gVisor matrix.",
    )
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--expected-coverage-lock-digest", required=True)
    arguments = parser.parse_args(argv)
    try:
        report = run_phase2_matrix(
            arguments.work_root,
            expected_coverage_lock_digest=arguments.expected_coverage_lock_digest,
        )
    except (
        BehaviorCapabilityDiffError,
        BenchmarkError,
        CASError,
        GVisorRuntimeError,
        InventoryError,
        OSError,
        Phase2MatrixRunError,
        WorkerProtocolError,
    ) as exc:
        print(f"phase2 matrix run failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
