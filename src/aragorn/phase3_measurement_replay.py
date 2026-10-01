"""Read-only receipt-to-metrics replay using an operator-selected semantic verifier.

This module never imports or executes a collection adapter or reads live runtime
identity. Pins must come from the operator's frozen plan. The already imported
receipt verifier remains trusted application code: its source pin establishes
identity, not correctness, independence of dependencies, or boundary placement.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import phase3_quantitative_metrics as metrics
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity

_DOCUMENT_LIMIT = 1024 * 1024
_RECEIPT_LIMIT = 64 * 1024
_MAX_INTEGER = (1 << 63) - 1
_ATTEMPT = ("REQUEST_ACCEPTED", "DECISION_FINALIZED")
_TASK = ("TASK_ACCEPTED", "TASK_COMPLETED")


class Phase3MeasurementReplayError(ValueError):
    """Retained measurements cannot be reconstructed from the frozen receipts."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise Phase3MeasurementReplayError(message)


def _pin(value: object) -> str:
    _expect(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid operator-held or evidence digest",
    )
    return value


def _object(value: object, keys: set[str], label: str) -> dict:
    _expect(type(value) is dict and set(value) == keys, label + " inventory changed")
    return value


def _integer(value: object) -> int:
    _expect(type(value) is int and 0 <= value <= _MAX_INTEGER, "invalid boottime value")
    return value


def _pairs(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        _expect(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _number(_: str) -> None:
    raise Phase3MeasurementReplayError("noninteger JSON number")


def _parse(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw, object_pairs_hook=_pairs, parse_float=_number, parse_constant=_number
        )
        _expect(
            type(value) is dict and canonical_json(value) == raw,
            "noncanonical evidence",
        )
        return value
    except (UnicodeError, ValueError) as exc:
        raise Phase3MeasurementReplayError("invalid canonical evidence JSON") from exc


def _source(verify: Callable, digest: str) -> dict:
    module = sys.modules.get(getattr(verify, "__module__", ""))
    _expect(
        inspect.isfunction(verify)
        and verify.__closure__ is None
        and verify.__name__ == verify.__qualname__
        and verify.__name__ != "<lambda>"
        and module is not None
        and getattr(module, verify.__name__, None) is verify,
        "receipt verifier is not a trusted imported top-level function",
    )
    filename = inspect.getsourcefile(verify)
    _expect(type(filename) is str, "receipt verifier source is unavailable")
    path = Path(filename).absolute()
    _expect(
        path.resolve(strict=True) == path, "receipt verifier source path is indirect"
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        _expect(
            stat.S_ISREG(before.st_mode) and 0 < before.st_size <= _DOCUMENT_LIMIT,
            "receipt verifier source is not bounded regular data",
        )
        raw = stream.read(_DOCUMENT_LIMIT + 1)
        after = os.fstat(stream.fileno())
    named = path.lstat()
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    _expect(
        len(raw) == before.st_size
        and all(
            getattr(before, key) == getattr(after, key) == getattr(named, key)
            for key in fields
        )
        and "sha256:" + hashlib.sha256(raw).hexdigest() == digest,
        "receipt verifier source differs from its operator-held pin",
    )
    return {
        "module": verify.__module__,
        "function": verify.__name__,
        "path": str(path),
        "bytes": len(raw),
        "digest": digest,
    }


def replay_phase3_measurement_collection(
    *,
    evidence_cas: CAS,
    expected_collection_digest: str,
    expected_commitment_digest: str,
    expected_deployment_digest: str,
    expected_measurement_schedule_digest: str,
    expected_metrics_implementation_digest: str,
    expected_collector_digest: str,
    expected_source_pins: dict[str, str],
    verify: Callable,
) -> dict[str, Any]:
    """Rebuild exactly 100 attempts and 200 task samples without executing them.

    ``verify(raw_receipt, request, boundaries)`` has the collector callback
    contract. Its output is recalculated for every retained receipt. Recorded
    verifier outputs must match, but are never used as the semantic authority.
    Arithmetic qualification is intentionally separate; a replay PASS means
    linkage is intact, not that measurements meet any Phase 3 thresholds.
    """
    pins = {
        "collection": _pin(expected_collection_digest),
        "commitment": _pin(expected_commitment_digest),
        "deployment": _pin(expected_deployment_digest),
        "schedule": _pin(expected_measurement_schedule_digest),
        "metrics": _pin(expected_metrics_implementation_digest),
        "collector": _pin(expected_collector_digest),
    }
    _object(
        expected_source_pins, {"execute", "verify", "identity_reader"}, "source pins"
    )
    source_pins = {key: _pin(value) for key, value in expected_source_pins.items()}
    verifier_source = _source(verify, source_pins["verify"])
    _expect(
        metrics.metrics_implementation_digest() == pins["metrics"],
        "metrics implementation changed",
    )
    retained: dict[str, int] = {}

    def read(digest: str, limit: int = _DOCUMENT_LIMIT) -> bytes:
        digest = _pin(digest)
        raw = evidence_cas.read(digest, max_bytes=limit)
        _expect(bool(raw), "empty retained evidence")
        retained[digest] = min(limit, retained.get(digest, limit))
        return raw

    collection = _object(
        _parse(read(pins["collection"])),
        {
            "schema",
            "authority",
            "commitment_digest",
            "commitment_readback_boottime_ns",
            "evidence_digest",
            "provenance",
            "metrics_qualification",
            "limitations",
        },
        "collection",
    )
    _expect(
        collection["schema"] == "aragorn/phase3-measurement-collection/v1"
        and collection["commitment_digest"] == pins["commitment"],
        "collection is not bound to the frozen commitment",
    )
    commitment = _object(
        _parse(read(pins["commitment"])),
        {
            "schema",
            "collection_id",
            "schedule_digest",
            "deployment",
            "sources",
            "collector_digest",
            "metrics_implementation_digest",
            "clock_id",
            "prepared_boottime_ns",
        },
        "commitment",
    )
    _expect(
        commitment["schema"] == "aragorn/phase3-measurement-collection-commitment/v1"
        and type(commitment["collection_id"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", commitment["collection_id"]) is not None
        and commitment["schedule_digest"] == pins["schedule"]
        and commitment["collector_digest"] == pins["collector"]
        and commitment["metrics_implementation_digest"] == pins["metrics"]
        and commitment["clock_id"] == metrics.CLOCK_ID,
        "commitment differs from the frozen collection plan",
    )
    deployment_raw = canonical_json(commitment["deployment"])
    resolve_phase3_deployment_identity(
        deployment_raw, expected_digest=pins["deployment"], evidence_cas=evidence_cas
    )
    sources = _object(commitment["sources"], set(source_pins), "committed sources")
    for key, source in sources.items():
        _object(
            source,
            {"module", "function", "path", "bytes", "digest"},
            "committed source",
        )
        _expect(
            source["digest"] == source_pins[key]
            and type(source["bytes"]) is int
            and 0 < source["bytes"] <= _DOCUMENT_LIMIT
            and all(
                type(source[field]) is str and 0 < len(source[field]) <= 4096
                for field in ("module", "function", "path")
            )
            and Path(source["path"]).is_absolute(),
            "committed source identity differs from frozen pins",
        )
    _expect(
        sources["verify"] == verifier_source
        and sources["execute"]["module"] != verifier_source["module"]
        and sources["execute"]["path"] != verifier_source["path"],
        "receipt verifier identity or separation differs from commitment",
    )
    schedule_raw = read(pins["schedule"])
    schedule = _parse(schedule_raw)
    try:
        attempts, overhead = schedule["attempt_schedule"], schedule["overhead_schedule"]
        rebuilt_schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts["attempt_ids"],
            expected_attempt_families=attempts["attempt_families"],
            expected_overhead_pair_bindings=overhead["pair_bindings"],
            expected_unattributed_attempt_id=attempts[
                "unattributed_negative_control_attempt_id"
            ],
            **{"expected_" + key: value for key, value in schedule["bindings"].items()},
        )
        _expect(
            canonical_json(rebuilt_schedule) == schedule_raw,
            "measurement schedule changed",
        )
    except (KeyError, TypeError, metrics.Phase3QuantitativeMetricsError) as exc:
        raise Phase3MeasurementReplayError(
            "invalid frozen measurement schedule"
        ) from exc
    _expect(
        schedule["bindings"]["runtime_identity_digest"] == pins["deployment"],
        "schedule deployment differs",
    )
    previous = _integer(collection["commitment_readback_boottime_ns"])
    _expect(
        _integer(commitment["prepared_boottime_ns"]) <= previous,
        "commitment chronology changed",
    )
    evidence = {
        "schema": metrics.INPUT_SCHEMA,
        "bindings": {
            **schedule["bindings"],
            "measurement_schedule_digest": pins["schedule"],
            "metrics_implementation_digest": pins["metrics"],
        },
        "clock_id": metrics.CLOCK_ID,
        "attempts": [],
        "baseline_samples": [],
        "instrumented_samples": [],
    }
    requests = [
        {
            "kind": "attempt",
            "attempt_id": identifier,
            "family": attempts["attempt_families"][identifier],
            "negative_control": identifier
            == attempts["unattributed_negative_control_attempt_id"],
        }
        for identifier in attempts["attempt_ids"]
    ]
    requests += [
        {"kind": "task", "mode": mode, "pair_id": pair_id, **binding}
        for pair_id, binding in overhead["pair_bindings"].items()
        for mode in ("baseline", "instrumented")
    ]
    provenance = collection["provenance"]
    _expect(
        type(provenance) is list and len(provenance) == len(requests) == 300,
        "measurement inventory changed",
    )
    for entry, request in zip(provenance, requests, strict=True):
        _object(
            entry,
            {"request", "receipt_digest", "verified_observation_digest"},
            "provenance",
        )
        bound_request = {
            **request,
            "collection_digest": pins["commitment"],
            "deployment_digest": pins["deployment"],
        }
        _expect(
            canonical_json(entry["request"]) == canonical_json(bound_request),
            "measurement request differs from frozen schedule",
        )
        raw = read(entry["receipt_digest"], _RECEIPT_LIMIT)
        receipt = _object(
            _parse(raw),
            {
                "schema",
                "request_digest",
                "deployment_digest",
                "boundaries",
                "observation",
            },
            "receipt",
        )
        request_digest = canonical_digest(bound_request)
        _expect(
            receipt["schema"] == "aragorn/phase3-local-measurement-receipt/v1"
            and receipt["request_digest"] == request_digest
            and receipt["deployment_digest"] == pins["deployment"],
            "receipt request or deployment join changed",
        )
        names = _ATTEMPT if request["kind"] == "attempt" else _TASK
        boundaries = _object(receipt["boundaries"], set(names), "receipt boundaries")
        start, end = (_integer(boundaries[name]) for name in names)
        _expect(previous <= start < end, "receipt boottime chronology changed")
        previous = end
        _expect(
            _source(verify, source_pins["verify"]) == verifier_source,
            "receipt verifier changed",
        )
        verified = verify(
            raw, json.loads(canonical_json(bound_request)), dict(boundaries)
        )
        _expect(
            _source(verify, source_pins["verify"]) == verifier_source,
            "receipt verifier changed",
        )
        _object(
            verified,
            {"receipt_digest", "request_digest", "deployment_digest", "semantics"},
            "replayed verification",
        )
        _expect(
            verified["receipt_digest"] == entry["receipt_digest"]
            and verified["request_digest"] == request_digest
            and verified["deployment_digest"] == pins["deployment"],
            "replayed verification is not bound to the raw receipt",
        )
        semantics = _object(
            verified["semantics"],
            {"attributed", "blocked_pre_effect", "residue_detected"}
            if names == _ATTEMPT
            else {"completed"},
            "replayed semantics",
        )
        _expect(
            all(type(value) is bool for value in semantics.values()),
            "nonboolean replayed semantics",
        )
        _expect(
            canonical_json(verified)
            == read(entry["verified_observation_digest"], _RECEIPT_LIMIT),
            "retained semantic result differs from independent replay",
        )
        if names == _ATTEMPT:
            evidence["attempts"].append(
                {key: value for key, value in request.items() if key != "kind"}
                | semantics
                | {
                    "request_accepted_boottime_ns": start,
                    "decision_finalized_boottime_ns": end,
                }
            )
        else:
            _expect(semantics["completed"] is True, "replayed task did not complete")
            evidence[request["mode"] + "_samples"].append(
                {
                    key: value
                    for key, value in request.items()
                    if key not in {"kind", "mode"}
                }
                | {
                    "status": "COMPLETED",
                    "timing_boundary": metrics.TASK_TIMING_BOUNDARY,
                    "started_boottime_ns": start,
                    "completed_boottime_ns": end,
                }
            )
    _expect(
        canonical_json(evidence) == read(collection["evidence_digest"]),
        "raw metrics differ from replayed receipt evidence",
    )
    # A verifier is trusted code, but cannot silently remove retained inputs.
    resolve_phase3_deployment_identity(
        deployment_raw, expected_digest=pins["deployment"], evidence_cas=evidence_cas
    )
    for digest, limit in retained.items():
        evidence_cas.verify(digest, max_bytes=limit)
    _expect(
        _source(verify, source_pins["verify"]) == verifier_source
        and metrics.metrics_implementation_digest() == pins["metrics"],
        "verification implementation changed during replay",
    )
    return {
        "schema": "aragorn/phase3-measurement-semantic-replay/v1",
        "authority": "RETAINED_RECEIPT_TO_METRICS_LINKAGE_ONLY_NOT_PHASE3_OR_LIVE_ATTESTATION",
        "bindings": {
            "collection_digest": pins["collection"],
            "commitment_digest": pins["commitment"],
            "evidence_digest": collection["evidence_digest"],
            "deployment_identity_digest": pins["deployment"],
            "measurement_schedule_digest": pins["schedule"],
            "metrics_implementation_digest": pins["metrics"],
            "collector_digest": pins["collector"],
            **schedule["bindings"],
        },
        "verifier": verifier_source,
        "counts": {
            "attempts": 100,
            "baseline_samples": 100,
            "instrumented_samples": 100,
        },
        "decision": {
            "status": "PASS",
            "phase3_exit_eligible": False,
            "quantitative_thresholds_qualified": False,
        },
        "limitations": [
            "SEMANTIC_VERIFIER_AND_OPERATOR_HELD_PINS_ARE_TRUSTED_INPUTS",
            "SOURCE_FILE_PINS_NOT_CORRECTNESS_OR_DEPENDENCY_CLOSURE",
            "RECEIPT_TIMING_PLACEMENT_AND_LIVE_IDENTITY_REQUIRE_SEPARATE_QUALIFICATION",
            "NO_EXECUTION_IDENTITY_READER_OR_CLOCK_SAMPLING",
            "NO_QUANTITATIVE_THRESHOLD_OR_PHASE3_EXIT_AUTHORITY",
        ],
    }
