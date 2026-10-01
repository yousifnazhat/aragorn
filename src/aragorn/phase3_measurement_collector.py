"""Collect bounded local measurements; adapter semantics need separate qualification.

There is no command runner or adapter-import CLI. An embedding runtime supplies
three already imported, source-pinned functions: ``execute(request, mark)``,
``verify(receipt_bytes, request, boundaries)``, and ``identity_reader()``.
Execution calls ``mark`` at the actual named runtime boundaries, receiving the
collector's CLOCK_BOOTTIME timestamp. The verifier independently interprets the
retained receipt. These are trusted local callbacks, not a sandbox: their source
pins identify selected files, not dependency closure or trustworthy semantics.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import secrets
import stat
import sys
import time
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from types import FunctionType
from typing import Any

from . import phase3_quantitative_metrics as metrics
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity

_RECEIPT_LIMIT = 64 * 1024
_SOURCE_LIMIT = 1024 * 1024
_RECEIPT_SCHEMA = "aragorn/phase3-local-measurement-receipt/v1"
_ATTEMPT_BOUNDARIES = ("REQUEST_ACCEPTED", "DECISION_FINALIZED")
_TASK_BOUNDARIES = ("TASK_ACCEPTED", "TASK_COMPLETED")


class Phase3MeasurementCollectionError(ValueError):
    """A collection boundary, source, deployment or receipt was not bound."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise Phase3MeasurementCollectionError(message)


def _boottime_ns() -> int:
    _expect(
        sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"),
        "Linux CLOCK_BOOTTIME is required; no fallback clock is accepted",
    )
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _source(function: Callable, expected_digest: str) -> dict[str, Any]:
    _expect(
        isinstance(function, FunctionType)
        and function.__closure__ is None
        and function.__qualname__ == function.__name__
        and function.__name__ != "<lambda>",
        "adapter must be an imported top-level function without a closure",
    )
    module = sys.modules.get(function.__module__)
    _expect(
        module is not None and getattr(module, function.__name__, None) is function,
        "adapter function is not its module's current export",
    )
    filename = inspect.getsourcefile(function)
    _expect(type(filename) is str, "adapter has no inspectable source file")
    path = Path(filename).absolute()
    _expect(path.resolve(strict=True) == path, "adapter source path is indirect")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        _expect(
            stat.S_ISREG(before.st_mode) and 0 < before.st_size <= _SOURCE_LIMIT,
            "adapter source is not a bounded regular file",
        )
        raw = stream.read(_SOURCE_LIMIT + 1)
        after = os.fstat(stream.fileno())
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
    named = path.stat()
    _expect(
        all(
            getattr(before, key) == getattr(after, key) == getattr(named, key)
            for key in fields
        )
        and len(raw) == before.st_size
        and "sha256:" + hashlib.sha256(raw).hexdigest() == expected_digest,
        "adapter source changed or does not match its supplied pin",
    )
    return {
        "module": function.__module__,
        "function": function.__name__,
        "path": str(path),
        "bytes": len(raw),
        "digest": expected_digest,
    }


def _store(store: CAS, raw: bytes, limit: int) -> str:
    _expect(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded evidence bytes")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    _expect(
        store.put_expected(BytesIO(raw), expected_digest=digest, max_bytes=limit)
        == digest
        and store.read(digest, max_bytes=limit) == raw,
        "evidence retention or readback failed",
    )
    return digest


def _schedule(value: dict) -> tuple[dict, dict]:
    try:
        attempts, overhead, bindings = (
            value["attempt_schedule"],
            value["overhead_schedule"],
            value["bindings"],
        )
        arguments = {
            "expected_attempt_ids": attempts["attempt_ids"],
            "expected_attempt_families": attempts["attempt_families"],
            "expected_unattributed_attempt_id": attempts[
                "unattributed_negative_control_attempt_id"
            ],
            "expected_overhead_pair_bindings": overhead["pair_bindings"],
            **{"expected_" + key: item for key, item in bindings.items()},
        }
        rebuilt = metrics.build_phase3_measurement_schedule(**arguments)
        _expect(canonical_json(rebuilt) == canonical_json(value), "schedule changed")
    except (KeyError, TypeError, metrics.Phase3QuantitativeMetricsError) as exc:
        raise Phase3MeasurementCollectionError(
            "invalid fixed measurement schedule"
        ) from exc
    # Detach every mutable nested value from the caller before callbacks run.
    return json.loads(canonical_json(rebuilt)), json.loads(canonical_json(arguments))


def collect_phase3_measurements(
    schedule: dict,
    *,
    deployment: dict,
    evidence_cas: CAS,
    execute: Callable,
    verify: Callable,
    identity_reader: Callable,
    source_pins: dict[str, str],
) -> dict[str, Any]:
    """Execute exactly 100 local attempts and 100 paired local tasks, without retries.

    Requests contain only committed identifiers/digests and a fresh collection
    identity, never commands or targets. ``execute`` returns <=64 KiB canonical
    receipt bytes with schema, request_digest, deployment_digest, boundaries and
    observation. ``verify`` returns the matching receipt_digest, request_digest,
    deployment_digest and semantics. Attempt semantics are the three booleans
    attributed/blocked_pre_effect/residue_detected; task semantics are completed.
    A false completed result aborts collection. Threshold failures are retained
    as failures, never repaired or replaced by generated measurements.

    Boundary placement, inertness, callback termination and receipt truth remain
    the embedding adapter's responsibility; source pins do not establish them.
    """
    schedule, arguments = _schedule(schedule)
    deployment_raw = canonical_json(deployment)
    deployment = resolve_phase3_deployment_identity(
        deployment_raw,
        expected_digest=schedule["bindings"]["runtime_identity_digest"],
        evidence_cas=evidence_cas,
    )
    callbacks = {
        "execute": execute,
        "verify": verify,
        "identity_reader": identity_reader,
    }
    _expect(
        type(source_pins) is dict and set(source_pins) == set(callbacks),
        "adapter source pin inventory changed",
    )
    sources = {name: _source(fn, source_pins[name]) for name, fn in callbacks.items()}
    _expect(
        sources["execute"]["module"] != sources["verify"]["module"]
        and sources["execute"]["path"] != sources["verify"]["path"],
        "execution and receipt verification need distinct pinned modules",
    )
    implementation = metrics.metrics_implementation_digest()
    collector_digest = (
        "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    schedule_raw = canonical_json(schedule)
    schedule_digest = _store(evidence_cas, schedule_raw, metrics._MAX_DOCUMENT_BYTES)
    commitment = {
        "schema": "aragorn/phase3-measurement-collection-commitment/v1",
        "collection_id": secrets.token_hex(32),
        "schedule_digest": schedule_digest,
        "deployment": deployment,
        "sources": sources,
        "collector_digest": collector_digest,
        "metrics_implementation_digest": implementation,
        "clock_id": metrics.CLOCK_ID,
        "prepared_boottime_ns": _boottime_ns(),
    }
    commitment_raw = canonical_json(commitment)
    commitment_digest = _store(
        evidence_cas, commitment_raw, metrics._MAX_DOCUMENT_BYTES
    )
    committed_at = _boottime_ns()
    evidence = {
        "schema": metrics.INPUT_SCHEMA,
        "bindings": {
            **schedule["bindings"],
            "measurement_schedule_digest": schedule_digest,
            "metrics_implementation_digest": implementation,
        },
        "clock_id": metrics.CLOCK_ID,
        "attempts": [],
        "baseline_samples": [],
        "instrumented_samples": [],
    }
    provenance = []

    def guard() -> None:
        _expect(
            {name: _source(fn, source_pins[name]) for name, fn in callbacks.items()}
            == sources
            and canonical_json(identity_reader()) == deployment_raw
            and metrics.metrics_implementation_digest() == implementation
            and "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            == collector_digest,
            "adapter source or live deployment identity changed",
        )

    def sample(request: dict, names: tuple[str, str]) -> tuple[dict, dict]:
        request = {
            **request,
            "collection_digest": commitment_digest,
            "deployment_digest": schedule["bindings"]["runtime_identity_digest"],
        }
        request_digest = canonical_digest(request)
        guard()
        stamps: dict[str, int] = {}
        active = True

        def mark(name: str) -> int:
            _expect(
                active and len(stamps) < 2 and name == names[len(stamps)],
                "adapter timing boundary is duplicate, late or out of order",
            )
            stamp = _boottime_ns()
            _expect(
                type(stamp) is int
                and stamp >= committed_at
                and (not stamps or stamp > next(iter(stamps.values()))),
                "CLOCK_BOOTTIME boundary did not advance",
            )
            stamps[name] = stamp
            return stamp

        try:
            raw = execute(json.loads(canonical_json(request)), mark)
        finally:
            active = False
        _expect(tuple(stamps) == names, "adapter omitted a timing boundary")
        receipt_digest = _store(evidence_cas, raw, _RECEIPT_LIMIT)
        try:
            receipt = json.loads(
                raw,
                object_pairs_hook=metrics._reject_duplicate_pairs,
                parse_constant=metrics._reject_noninteger_number,
                parse_float=metrics._reject_noninteger_number,
            )
        except (UnicodeError, ValueError) as exc:
            raise Phase3MeasurementCollectionError("invalid adapter receipt") from exc
        _expect(
            type(receipt) is dict
            and set(receipt)
            == {
                "schema",
                "request_digest",
                "deployment_digest",
                "boundaries",
                "observation",
            }
            and canonical_json(receipt) == raw
            and receipt["schema"] == _RECEIPT_SCHEMA
            and receipt["request_digest"] == request_digest
            and receipt["deployment_digest"] == request["deployment_digest"]
            and canonical_json(receipt["boundaries"]) == canonical_json(stamps),
            "adapter receipt does not bind this request and measured boundaries",
        )
        guard()
        verified = verify(raw, json.loads(canonical_json(request)), dict(stamps))
        _expect(
            type(verified) is dict
            and set(verified)
            == {"receipt_digest", "request_digest", "deployment_digest", "semantics"}
            and verified["receipt_digest"] == receipt_digest
            and verified["request_digest"] == request_digest
            and verified["deployment_digest"] == request["deployment_digest"],
            "independent verifier did not bind the retained receipt",
        )
        semantics = verified["semantics"]
        keys = (
            {"attributed", "blocked_pre_effect", "residue_detected"}
            if names == _ATTEMPT_BOUNDARIES
            else {"completed"}
        )
        _expect(
            type(semantics) is dict
            and set(semantics) == keys
            and all(type(item) is bool for item in semantics.values()),
            "invalid verified observation semantics",
        )
        guard()
        provenance.append(
            {
                "request": request,
                "receipt_digest": receipt_digest,
                "verified_observation_digest": _store(
                    evidence_cas, canonical_json(verified), _RECEIPT_LIMIT
                ),
            }
        )
        return semantics, stamps

    attempts = schedule["attempt_schedule"]
    for attempt_id in attempts["attempt_ids"]:
        request = {
            "kind": "attempt",
            "attempt_id": attempt_id,
            "family": attempts["attempt_families"][attempt_id],
            "negative_control": attempt_id
            == attempts["unattributed_negative_control_attempt_id"],
        }
        semantics, stamps = sample(request, _ATTEMPT_BOUNDARIES)
        evidence["attempts"].append(
            {key: value for key, value in request.items() if key != "kind"}
            | semantics
            | {
                "request_accepted_boottime_ns": stamps[_ATTEMPT_BOUNDARIES[0]],
                "decision_finalized_boottime_ns": stamps[_ATTEMPT_BOUNDARIES[1]],
            }
        )
    # Pair immediately, preserving sorted inventory and avoiding a second campaign.
    for pair_id, binding in schedule["overhead_schedule"]["pair_bindings"].items():
        for mode in ("baseline", "instrumented"):
            request = {"kind": "task", "mode": mode, "pair_id": pair_id, **binding}
            semantics, stamps = sample(request, _TASK_BOUNDARIES)
            _expect(semantics["completed"] is True, "adapter task did not complete")
            evidence[mode + "_samples"].append(
                {
                    "pair_id": pair_id,
                    **binding,
                    "status": "COMPLETED",
                    "timing_boundary": metrics.TASK_TIMING_BOUNDARY,
                    "started_boottime_ns": stamps[_TASK_BOUNDARIES[0]],
                    "completed_boottime_ns": stamps[_TASK_BOUNDARIES[1]],
                }
            )
    evidence_digest = _store(
        evidence_cas, canonical_json(evidence), metrics._MAX_DOCUMENT_BYTES
    )
    try:
        qualification = metrics.qualify_phase3_quantitative_metrics(
            evidence,
            **arguments,
            expected_measurement_schedule_digest=schedule_digest,
            expected_metrics_implementation_digest=implementation,
        )
    except metrics.Phase3QuantitativeMetricsError as exc:
        qualification = {"decision": {"status": "FAIL"}, "reason": str(exc)}
    # A callback may have removed evidence without changing the live identity.
    # Refuse publication unless the original plan and every identity artifact
    # remain in custody after measurement and arithmetic qualification finish.
    guard()
    resolve_phase3_deployment_identity(
        deployment_raw,
        expected_digest=schedule["bindings"]["runtime_identity_digest"],
        evidence_cas=evidence_cas,
    )
    _expect(
        evidence_cas.read(schedule_digest, max_bytes=metrics._MAX_DOCUMENT_BYTES)
        == schedule_raw
        and evidence_cas.read(commitment_digest, max_bytes=metrics._MAX_DOCUMENT_BYTES)
        == commitment_raw,
        "committed schedule or collection identity left custody",
    )
    result = {
        "schema": "aragorn/phase3-measurement-collection/v1",
        "authority": "LOCAL_ADAPTER_MEASUREMENTS_AND_ARITHMETIC_ONLY_NOT_SOURCE_SEMANTIC_OR_PHASE3_QUALIFICATION",
        "commitment_digest": commitment_digest,
        "commitment_readback_boottime_ns": committed_at,
        "evidence_digest": evidence_digest,
        "provenance": provenance,
        "metrics_qualification": qualification,
        "limitations": [
            "PINNED_MODULE_FILES_NOT_EXECUTED_DEPENDENCY_CLOSURE_OR_TRUSTWORTHY_SEMANTICS",
            "TRUSTED_LOCAL_CALLBACK_BOUNDARIES_REQUIRE_INDEPENDENT_QUALIFICATION",
            "NO_CALLBACK_TIMEOUT_OR_AUTOMATIC_RETRY",
            "NO_ADMISSION_RUN_PHASE3_OR_RELEASE_AUTHORITY",
        ],
    }
    return {
        **result,
        "collection_digest": _store(
            evidence_cas, canonical_json(result), metrics._MAX_DOCUMENT_BYTES
        ),
    }
