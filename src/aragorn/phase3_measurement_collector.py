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
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import FunctionType
from typing import Any

from . import phase3_quantitative_metrics as metrics
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity

_RECEIPT_LIMIT = 64 * 1024
_SOURCE_LIMIT = 1024 * 1024
_RECEIPT_SCHEMA = "aragorn/phase3-local-measurement-receipt/v1"
_ATTEMPT_BOUNDARIES = ("REQUEST_ACCEPTED", "DECISION_FINALIZED")
_TASK_BOUNDARIES = ("TASK_ACCEPTED", "TASK_COMPLETED")
_PREPARED_CLAIMS = "phase3-prepared-attempt-claims"


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


def prepare_phase3_measurement_collection(
    schedule: dict,
    *,
    deployment: dict,
    evidence_cas: CAS,
    execute: Callable,
    verify: Callable,
    identity_reader: Callable,
    source_pins: dict[str, str],
) -> dict[str, Any]:
    """Retain the exact collection commitment without invoking any callback.

    The imported functions are inspected only to verify their source identities.
    In particular, ``identity_reader`` is not called: resolving the supplied
    deployment artifacts is not live deployment attestation. Linux
    CLOCK_BOOTTIME records preparation and readback, not action execution.
    The returned detached context is not execution or qualification authority.
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
    _expect(
        type(commitment["prepared_boottime_ns"]) is int
        and type(committed_at) is int
        and 0 <= commitment["prepared_boottime_ns"] <= committed_at < 2**63,
        "preparation CLOCK_BOOTTIME chronology is invalid",
    )
    _expect(
        {name: _source(fn, source_pins[name]) for name, fn in callbacks.items()}
        == sources
        and metrics.metrics_implementation_digest() == implementation
        and "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        == collector_digest,
        "preparation source identities changed",
    )
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
        "prepared schedule or commitment left custody",
    )
    return json.loads(
        canonical_json(
            {
                "schema": "aragorn/phase3-measurement-preparation/v1",
                "authority": "COMMITMENT_PREPARATION_ONLY_NOT_EXECUTION_LIVE_IDENTITY_OR_QUALIFICATION",
                "commitment_digest": commitment_digest,
                "commitment_readback_boottime_ns": committed_at,
                "commitment": commitment,
                "schedule": schedule,
                "schedule_digest": schedule_digest,
                "arguments": arguments,
                "deployment": deployment,
                "sources": sources,
                "collector_digest": collector_digest,
                "metrics_implementation_digest": implementation,
                "decision": {
                    "measurement_collected": False,
                    "phase3_exit_eligible": False,
                    "quantitative_metrics_eligible": False,
                },
            }
        )
    )


def _sample(
    request: dict,
    names: tuple[str, str],
    *,
    evidence_cas: CAS,
    execute: Callable,
    verify: Callable,
    guard: Callable,
    committed_at: int,
) -> tuple[dict, dict, dict]:
    """One callback/receipt boundary shared by the old campaign and new attempt."""
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
    # A later identity callback must not mutate a verifier-owned dictionary
    # after its schema/semantics checks but before evidence retention.
    verified = json.loads(canonical_json(verified))
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
    provenance = {
        "request": request,
        "receipt_digest": receipt_digest,
        "verified_observation_digest": _store(
            evidence_cas, canonical_json(verified), _RECEIPT_LIMIT
        ),
    }
    return semantics, stamps, provenance


def _prepared_context(
    raw: bytes, digest: str, store: CAS, callbacks: dict, pins: dict
) -> dict:
    """Revalidate caller-retained v1 preparation without invoking its callbacks."""
    _expect(
        isinstance(store, CAS)
        and not store.read_only
        and type(raw) is bytes
        and 0 < len(raw) <= metrics._MAX_DOCUMENT_BYTES
        and type(digest) is str
        and "sha256:" + hashlib.sha256(raw).hexdigest() == digest,
        "invalid pinned preparation bytes or evidence store",
    )
    prepared = json.loads(
        raw,
        object_pairs_hook=metrics._reject_duplicate_pairs,
        parse_constant=metrics._reject_noninteger_number,
        parse_float=metrics._reject_noninteger_number,
    )
    _expect(
        type(prepared) is dict
        and set(prepared)
        == {
            "schema",
            "authority",
            "commitment_digest",
            "commitment_readback_boottime_ns",
            "commitment",
            "schedule",
            "schedule_digest",
            "arguments",
            "deployment",
            "sources",
            "collector_digest",
            "metrics_implementation_digest",
            "decision",
        }
        and canonical_json(prepared) == raw
        and prepared["schema"] == "aragorn/phase3-measurement-preparation/v1"
        and prepared["authority"]
        == "COMMITMENT_PREPARATION_ONLY_NOT_EXECUTION_LIVE_IDENTITY_OR_QUALIFICATION"
        and canonical_json(prepared["decision"])
        == canonical_json(
            {
                "measurement_collected": False,
                "phase3_exit_eligible": False,
                "quantitative_metrics_eligible": False,
            }
        ),
        "prepared context contract changed",
    )
    schedule, arguments = _schedule(prepared["schedule"])
    _expect(
        canonical_json(arguments) == canonical_json(prepared["arguments"])
        and canonical_digest(schedule) == prepared["schedule_digest"],
        "prepared schedule or arguments changed",
    )
    deployment = resolve_phase3_deployment_identity(
        canonical_json(prepared["deployment"]),
        expected_digest=schedule["bindings"]["runtime_identity_digest"],
        evidence_cas=store,
    )
    _expect(
        type(pins) is dict and set(pins) == set(callbacks),
        "adapter source pin inventory changed",
    )
    sources = {name: _source(fn, pins[name]) for name, fn in callbacks.items()}
    _expect(
        sources["execute"]["module"] != sources["verify"]["module"]
        and sources["execute"]["path"] != sources["verify"]["path"]
        and canonical_json(sources) == canonical_json(prepared["sources"])
        and metrics.metrics_implementation_digest()
        == prepared["metrics_implementation_digest"]
        and "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        == prepared["collector_digest"],
        "prepared source identities changed",
    )
    commitment = prepared["commitment"]
    _expect(type(commitment) is dict, "missing prepared commitment")
    identifier, stamp = (
        commitment.get("collection_id"),
        commitment.get("prepared_boottime_ns"),
    )
    readback = prepared["commitment_readback_boottime_ns"]
    _expect(
        type(identifier) is str
        and re.fullmatch(r"[0-9a-f]{64}", identifier) is not None
        and type(stamp) is int
        and type(readback) is int
        and 0 <= stamp <= readback < 2**63
        and canonical_json(commitment)
        == canonical_json(
            {
                "schema": "aragorn/phase3-measurement-collection-commitment/v1",
                "collection_id": identifier,
                "schedule_digest": prepared["schedule_digest"],
                "deployment": deployment,
                "sources": sources,
                "collector_digest": prepared["collector_digest"],
                "metrics_implementation_digest": prepared[
                    "metrics_implementation_digest"
                ],
                "clock_id": metrics.CLOCK_ID,
                "prepared_boottime_ns": stamp,
            }
        )
        and canonical_digest(commitment) == prepared["commitment_digest"],
        "original prepared commitment or chronology changed",
    )
    for pin, original in (
        (digest, raw),
        (prepared["commitment_digest"], canonical_json(commitment)),
        (prepared["schedule_digest"], canonical_json(schedule)),
    ):
        _expect(
            store.read(pin, max_bytes=metrics._MAX_DOCUMENT_BYTES) == original,
            "prepared context left evidence custody",
        )
    return prepared


@contextmanager
def _prepared_attempt_claim(store: CAS, claim: dict):
    """Hold a permanent exclusive claim; no failure path removes or resets it."""
    root = store.root.absolute()
    _expect(root.resolve(strict=True) == root, "indirect prepared claim root")
    raw = canonical_json(claim)
    _expect(len(raw) <= 4096, "unbounded prepared claim")
    root_fd = directory_fd = claim_fd = -1
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def private_directory(fd: int) -> os.stat_result:
        metadata = os.fstat(fd)
        _expect(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "unsafe prepared claim directory",
        )
        return metadata

    def inode(metadata):
        return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid

    try:
        root_fd = os.open(root, flags)
        root_identity = inode(private_directory(root_fd))
        try:
            os.mkdir(_PREPARED_CLAIMS, mode=0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(_PREPARED_CLAIMS, flags, dir_fd=root_fd)
        directory_identity = inode(private_directory(directory_fd))
        os.fsync(root_fd)
        name = claim["commitment_digest"][7:] + ".json"
        try:
            claim_fd = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError as exc:
            raise Phase3MeasurementCollectionError(
                "prepared commitment already claimed; retry refused"
            ) from exc
        # Persist the name before writing. Even an interrupted/partial claim is final.
        os.fsync(directory_fd)
        offset = 0
        while offset < len(raw):
            written = os.write(claim_fd, raw[offset:])
            _expect(written > 0, "prepared claim write failed")
            offset += written
        os.fchmod(claim_fd, 0o400)
        os.fsync(claim_fd)
        os.fsync(directory_fd)
        claimed = os.fstat(claim_fd)

        def guard_claim() -> None:
            _expect(
                root.resolve(strict=True) == root
                and inode(os.stat(root, follow_symlinks=False)) == root_identity
                and inode(private_directory(root_fd)) == root_identity
                and inode(
                    os.stat(_PREPARED_CLAIMS, dir_fd=root_fd, follow_symlinks=False)
                )
                == directory_identity
                and inode(private_directory(directory_fd)) == directory_identity,
                "prepared claim directory left custody",
            )
            current = os.fstat(claim_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
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
                all(
                    getattr(claimed, field)
                    == getattr(current, field)
                    == getattr(named, field)
                    for field in fields
                )
                and stat.S_ISREG(current.st_mode)
                and stat.S_IMODE(current.st_mode) == 0o400
                and current.st_uid == os.geteuid()
                and current.st_nlink == 1
                and current.st_size == len(raw)
                and os.pread(claim_fd, 4097, 0) == raw,
                "permanent prepared claim left custody",
            )

        guard_claim()
        yield guard_claim, raw
        guard_claim()
    finally:
        active_error = sys.exc_info()[1]
        close_error = None
        for descriptor in (claim_fd, directory_fd, root_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if close_error is None:
                        close_error = error
        if close_error is not None and active_error is None:
            raise close_error


def collect_prepared_phase3_attempt(
    preparation_raw: bytes,
    *,
    expected_preparation_digest: str,
    scheduled_request: dict,
    evidence_cas: CAS,
    execute: Callable,
    verify: Callable,
    identity_reader: Callable,
    source_pins: dict[str, str],
) -> dict[str, Any]:
    """Consume one original commitment once, never a campaign or retry authority.

    The caller must already retain the canonical preparation report in the same
    private CAS. One attributed attempt is accepted; tasks and the negative
    control are refused. A durable commitment-keyed claim precedes every callback
    and is never removed, including on interruption or incomplete evidence.
    v1 preparation has no boot/time-namespace identity: timestamp ordering alone
    cannot prove a shared clock domain. Callbacks remain trusted local adapters;
    retained broker stamps cannot substitute for calling the live ``mark`` hook.
    """
    try:
        callbacks = {
            "execute": execute,
            "verify": verify,
            "identity_reader": identity_reader,
        }
        _expect(type(source_pins) is dict, "invalid adapter source pins")
        pins = dict(source_pins)
        prepared = _prepared_context(
            preparation_raw, expected_preparation_digest, evidence_cas, callbacks, pins
        )
        attempts = prepared["schedule"]["attempt_schedule"]
        _expect(type(scheduled_request) is dict, "missing prepared attempt request")
        attempt_id = scheduled_request.get("attempt_id")
        _expect(
            type(attempt_id) is str
            and attempt_id in attempts["attempt_ids"]
            and attempt_id != attempts["unattributed_negative_control_attempt_id"],
            "prepared attempt must be attributed; negative controls and tasks are refused",
        )
        request = {
            "kind": "attempt",
            "attempt_id": attempt_id,
            "family": attempts["attempt_families"][attempt_id],
            "negative_control": False,
            "collection_digest": prepared["commitment_digest"],
            "deployment_digest": prepared["schedule"]["bindings"][
                "runtime_identity_digest"
            ],
        }
        _expect(
            canonical_json(scheduled_request) == canonical_json(request),
            "prepared attempt request changed",
        )
        started = _boottime_ns()
        _expect(
            type(started) is int
            and prepared["commitment_readback_boottime_ns"] <= started < 2**63,
            "prepared attempt CLOCK_BOOTTIME chronology is invalid",
        )
        claim = {
            "schema": "aragorn/phase3-prepared-attempt-claim/v1",
            "preparation_digest": expected_preparation_digest,
            "commitment_digest": prepared["commitment_digest"],
            "request_digest": canonical_digest(request),
            "claimed_boottime_ns": started,
            "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
        }
        with _prepared_attempt_claim(evidence_cas, claim) as (claim_guard, claim_raw):
            claim_digest = _store(evidence_cas, claim_raw, 4096)

            def guard() -> None:
                claim_guard()
                _prepared_context(
                    preparation_raw,
                    expected_preparation_digest,
                    evidence_cas,
                    callbacks,
                    pins,
                )
                _expect(
                    canonical_json(identity_reader())
                    == canonical_json(prepared["deployment"]),
                    "prepared attempt live deployment identity changed",
                )
                # The identity callback is trusted code, but it may still alter
                # sources or custody. Recheck before the next callback/effect.
                _prepared_context(
                    preparation_raw,
                    expected_preparation_digest,
                    evidence_cas,
                    callbacks,
                    pins,
                )
                claim_guard()

            semantics, stamps, retained = _sample(
                request,
                _ATTEMPT_BOUNDARIES,
                evidence_cas=evidence_cas,
                execute=execute,
                verify=verify,
                guard=guard,
                committed_at=started,
            )
            _expect(
                all(
                    type(stamp) is int and 0 <= stamp < 2**63
                    for stamp in stamps.values()
                ),
                "prepared attempt clock is outside its bound",
            )
            guard()
            for pin, limit in (
                (claim_digest, 4096),
                (retained["receipt_digest"], _RECEIPT_LIMIT),
                (retained["verified_observation_digest"], _RECEIPT_LIMIT),
            ):
                evidence_cas.verify(pin, max_bytes=limit)
            result = {
                "schema": "aragorn/phase3-prepared-attempt-collection/v1",
                "authority": "LOCAL_PREPARED_ATTEMPT_ONLY_NOT_CAMPAIGN_OR_PHASE3_QUALIFICATION",
                "preparation_digest": expected_preparation_digest,
                "commitment_digest": prepared["commitment_digest"],
                "commitment_readback_boottime_ns": prepared[
                    "commitment_readback_boottime_ns"
                ],
                "request": request,
                "request_digest": canonical_digest(request),
                "receipt_digest": retained["receipt_digest"],
                "verified_observation_digest": retained["verified_observation_digest"],
                "boundaries": stamps,
                "semantics": semantics,
                "claim_digest": claim_digest,
                "decision": dict.fromkeys(
                    (
                        "phase3_exit_eligible",
                        "run_eligible",
                        "quantitative_metrics_eligible",
                        "generic_collector_semantics_eligible",
                    ),
                    False,
                ),
                "limitations": [
                    "ONE_ATTRIBUTED_ATTEMPT_NOT_100_ATTEMPT_OR_PAIRED_TASK_CAMPAIGN",
                    "V1_PREPARATION_HAS_NO_SAME_BOOT_OR_TIME_NAMESPACE_PROOF",
                    "COLLECTOR_CALLBACK_STAMPS_NOT_RETAINED_BROKER_OR_CROSS_PROCESS_TIMING",
                    "SOURCE_PINNED_TRUSTED_CALLBACKS_NOT_INDEPENDENT_SEMANTIC_OR_RESIDUE_PROOF",
                    "PERMANENT_LOCAL_CLAIM_NOT_HOSTILE_OWNER_RESISTANT_OR_CROSS_STORE_REPLAY_PREVENTION",
                    "NO_CALLBACK_TIMEOUT_EMBEDDING_ADAPTER_MUST_BOUND_EXECUTION",
                    "NO_AUTOMATIC_RETRY_OR_PHASE3_QUALIFICATION",
                ],
            }
            result_digest = _store(
                evidence_cas, canonical_json(result), metrics._MAX_DOCUMENT_BYTES
            )
            # No callback may run after these final source/input/output checks.
            _prepared_context(
                preparation_raw,
                expected_preparation_digest,
                evidence_cas,
                callbacks,
                pins,
            )
            for pin, limit in (
                (result_digest, metrics._MAX_DOCUMENT_BYTES),
                (claim_digest, 4096),
                (retained["receipt_digest"], _RECEIPT_LIMIT),
                (retained["verified_observation_digest"], _RECEIPT_LIMIT),
            ):
                evidence_cas.verify(pin, max_bytes=limit)
            claim_guard()
            return {**result, "collection_digest": result_digest}
    except Phase3MeasurementCollectionError:
        raise
    except Exception as exc:
        raise Phase3MeasurementCollectionError(
            "prepared attempt collection refused; any claim remains final"
        ) from exc


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
    prepared = prepare_phase3_measurement_collection(
        schedule,
        deployment=deployment,
        evidence_cas=evidence_cas,
        execute=execute,
        verify=verify,
        identity_reader=identity_reader,
        source_pins=source_pins,
    )
    schedule = prepared["schedule"]
    arguments = prepared["arguments"]
    deployment = prepared["deployment"]
    deployment_raw = canonical_json(deployment)
    callbacks = {
        "execute": execute,
        "verify": verify,
        "identity_reader": identity_reader,
    }
    sources = prepared["sources"]
    implementation = prepared["metrics_implementation_digest"]
    collector_digest = prepared["collector_digest"]
    schedule_raw = canonical_json(schedule)
    schedule_digest = prepared["schedule_digest"]
    commitment_raw = canonical_json(prepared["commitment"])
    commitment_digest = prepared["commitment_digest"]
    committed_at = prepared["commitment_readback_boottime_ns"]
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
        semantics, stamps, retained = _sample(
            request,
            names,
            evidence_cas=evidence_cas,
            execute=execute,
            verify=verify,
            guard=guard,
            committed_at=committed_at,
        )
        provenance.append(retained)
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
    try:
        evidence_cas.verify(evidence_digest, max_bytes=metrics._MAX_DOCUMENT_BYTES)
        for entry in provenance:
            evidence_cas.verify(entry["receipt_digest"], max_bytes=_RECEIPT_LIMIT)
            evidence_cas.verify(
                entry["verified_observation_digest"], max_bytes=_RECEIPT_LIMIT
            )
    except CASError as exc:
        raise Phase3MeasurementCollectionError(
            "collected evidence or sample receipt left custody"
        ) from exc
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
