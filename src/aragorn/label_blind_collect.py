"""Collect a complete label-free worker batch into independently verified evidence."""

from __future__ import annotations

import argparse
import fcntl
from io import BytesIO
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Sequence

from .benchmark import BenchmarkError, evaluate, load_suite_for_run
from .cas import CAS, CASError
from .label_blind_prepare import (
    PrepareError,
    validate_private_dispatch,
    validate_worker_worklist,
)
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
    validate_subject_manifest,
    validate_worker_request,
    validate_worker_result,
    verify_request_result_binding,
    verify_request_subject,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_NONCE_BATCH_FILE = re.compile(r"([0-9a-f]{64})\.json\Z")
_HEX = frozenset("0123456789abcdef")
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_MAX_BLOB_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_BYTES = 512 * 1024 * 1024
_MAX_BLOBS = 25_000
_MAX_JOBS = 200_000
_RESULT_DIGEST_FIELDS = (
    "baseline_lock_digest",
    "baseline_entry_digest",
    "effective_config_digest",
    "oci_index_digest",
    "oci_platform_manifest_digest",
    "build_provenance_manifest_digest",
    "index_inspect_digest",
    "platform_inspect_digest",
    "image_config_digest",
    "prestart_container_inspect_digest",
    "postrun_container_inspect_digest",
    "stdout_digest",
    "stderr_digest",
)


class CollectError(ValueError):
    """A worker batch cannot be imported as complete verified evidence."""


def collect_files(
    suite_path: str | os.PathLike[str],
    *,
    dispatch_digest: str,
    control_state: str | os.PathLike[str],
    jobs_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Collect every prepared job exactly once; return only after full verification."""

    suite_file = _existing_file(suite_path, "benchmark suite")
    control_root = _existing_directory(control_state, "control CAS")
    jobs_path = _existing_directory(jobs_root, "jobs root")
    ledger_path = control_root / "nonce-ledger"
    _require_separate_paths(
        suite_file,
        control_root,
        jobs_path,
    )
    if not isinstance(dispatch_digest, str) or _DIGEST.fullmatch(dispatch_digest) is None:
        raise CollectError("dispatch_digest is invalid")

    control_cas = CAS(control_root)
    loaded = load_suite_for_run(
        suite_file,
        control_cas,
        required_purpose="evidence_smoke",
    )
    dispatch = _read_canonical_cas_object(
        control_cas,
        dispatch_digest,
        max_bytes=_MAX_MANIFEST_BYTES,
        label="private dispatch",
    )
    try:
        validate_private_dispatch(dispatch)
    except PrepareError as exc:
        raise CollectError(f"private dispatch is invalid: {exc}") from exc
    _verify_dispatch_matrix(dispatch, loaded, dispatch_digest)

    expected_job_ids = {entry["job_id"] for entry in dispatch["jobs"]}
    root_entries = _directory_entries(
        jobs_path,
        "jobs root",
        maximum=_MAX_JOBS + 1,
    )
    worklist_path = root_entries.pop("worklist.json", None)
    if worklist_path is None:
        raise CollectError("jobs root has no canonical worker worklist")
    worklist_raw = _read_stable_read_only_file(
        worklist_path,
        max_bytes=_MAX_MANIFEST_BYTES,
        label="worker worklist",
    )
    worklist = _decode_canonical_object(worklist_raw, "worker worklist")
    try:
        validate_worker_worklist(worklist)
    except PrepareError as exc:
        raise CollectError(f"worker worklist is invalid: {exc}") from exc
    expected_worklist = [
        {
            "job_id": entry["job_id"],
            "request_digest": entry["request_digest"],
        }
        for entry in dispatch["jobs"]
    ]
    if worklist["jobs"] != expected_worklist:
        raise CollectError("worker worklist does not match the private dispatch")
    actual_jobs = root_entries
    if set(actual_jobs) != expected_job_ids:
        raise CollectError("jobs root does not contain the exact dispatch job set")

    pending: list[dict[str, Any]] = []
    v3_outcomes: list[dict[str, Any]] = []
    for entry in dispatch["jobs"]:
        job_directory = actual_jobs[entry["job_id"]]
        _require_real_directory(job_directory, "job directory")
        job_entries = _directory_entries(job_directory, "job directory", maximum=3)
        if set(job_entries) != {"input", "output", "request.json"}:
            raise CollectError(
                f"job {entry['job_id']} is incomplete or has unknown entries"
            )
        request_raw = _read_stable_read_only_file(
            job_entries["request.json"],
            max_bytes=_MAX_REQUEST_BYTES,
            label="worker request",
        )
        request = _decode_canonical_object(request_raw, "worker request")
        try:
            validate_worker_request(request)
        except WorkerProtocolError as exc:
            raise CollectError(f"worker request is invalid: {exc}") from exc
        if canonical_digest(request) != entry["request_digest"]:
            raise CollectError("worker request digest changed after preparation")

        input_cas = CAS(job_entries["input"], read_only=True)
        subject = _read_canonical_cas_object(
            input_cas,
            request["subject"]["manifest_digest"],
            max_bytes=_MAX_MANIFEST_BYTES,
            label="worker subject manifest",
        )
        try:
            validate_subject_manifest(subject)
            verify_request_subject(request, subject)
        except WorkerProtocolError as exc:
            raise CollectError(f"worker subject is invalid: {exc}") from exc
        input_blobs = _enumerate_canonical_cas(job_entries["input"])
        expected_input = {
            request["subject"]["manifest_digest"],
            *(item["digest"] for item in subject["files"]),
        }
        if set(input_blobs) != expected_input:
            raise CollectError("worker input CAS is not the exact subject closure")

        output_cas = CAS(job_entries["output"], read_only=True)
        output_blobs = _enumerate_canonical_cas(job_entries["output"])
        total_bytes = sum(output_blobs.values())
        if total_bytes > _MAX_OUTPUT_BYTES:
            raise CollectError("worker output CAS exceeds the total byte limit")
        result, result_digest = _find_worker_result(output_cas, output_blobs)
        try:
            validate_worker_result(result)
            verify_request_result_binding(request, result)
        except WorkerProtocolError as exc:
            raise CollectError(f"worker result is invalid: {exc}") from exc
        _verify_dispatch_job(entry, request, result, loaded)
        expected_output = _expected_worker_output(
            output_cas,
            request,
            subject,
            result,
            result_digest,
        )
        if set(output_blobs) != expected_output:
            raise CollectError("worker output CAS is not the exact result closure")

        for digest, size in sorted(output_blobs.items()):
            content = output_cas.read(digest, max_bytes=size)
            if len(content) != size:
                raise CollectError("worker output blob size changed during import")
            if control_cas.put(BytesIO(content), max_bytes=size) != digest:
                raise CollectError("worker output digest changed during import")

        closure = {
            "schema": "aragorn/benchmark-worker-output-closure/v1",
            "job_id": request["job_id"],
            "request_digest": entry["request_digest"],
            "result_digest": result_digest,
            "blobs": [
                {"digest": digest, "size": size}
                for digest, size in sorted(output_blobs.items())
            ],
            "total_bytes": total_bytes,
        }
        closure_digest = _put_json(control_cas, closure)
        nested = _nested_v3(entry, result)
        nested_digest = _put_json(control_cas, nested)
        v3_outcome = _outcome(entry, result, nested_digest)
        v3_outcomes.append(v3_outcome)
        pending.append(
            {
                "entry": entry,
                "request": request,
                "result": result,
                "result_digest": result_digest,
                "closure_digest": closure_digest,
                "nested_digest": nested_digest,
            }
        )

    # This first pass invokes the independent OCI verifier before consuming nonces.
    evaluate(
        loaded["canonical"],
        v3_outcomes,
        loaded["root"],
        evidence_state=control_root,
    )

    ledger_id = _nonce_ledger_id(
        suite_digest=loaded["digest"],
        dispatch_digest=dispatch_digest,
        pending=pending,
    )
    v4_outcomes: list[dict[str, Any]] = []
    collection_jobs: list[dict[str, str]] = []
    nonce_receipts: list[dict[str, str]] = []
    for item in pending:
        request = item["request"]
        entry = item["entry"]
        receipt = {
            "schema": "aragorn/benchmark-worker-nonce-consumption/v1",
            "ledger_id": ledger_id,
            "dispatch_digest": dispatch_digest,
            "job_id": request["job_id"],
            "nonce": request["nonce"],
            "request_digest": entry["request_digest"],
            "result_digest": item["result_digest"],
        }
        receipt_raw = canonical_json(receipt)
        receipt_digest = _put_bytes(control_cas, receipt_raw)
        nonce_receipts.append(receipt)
        v4 = {
            "schema": "aragorn/benchmark-evidence/v4",
            "suite_digest": entry["suite_digest"],
            "case_id": entry["case_id"],
            "tree_digest": entry["tree_digest"],
            "run_id": entry["run_id"],
            "system": dict(entry["system"]),
            "verdict": item["result"]["verdict"],
            "reason_codes": list(item["result"]["reason_codes"]),
            "nested_evidence_digest": item["nested_digest"],
            "worker": {
                "assurance": "unsigned_label_free_protocol_not_isolated_or_attested",
                "ledger_id": ledger_id,
                "dispatch_digest": dispatch_digest,
                "job_id": request["job_id"],
                "nonce": request["nonce"],
                "request_digest": entry["request_digest"],
                "result_digest": item["result_digest"],
                "subject_manifest_digest": request["subject"]["manifest_digest"],
                "output_closure_digest": item["closure_digest"],
                "nonce_receipt_digest": receipt_digest,
            },
        }
        v4_digest = _put_json(control_cas, v4)
        v4_outcomes.append(_outcome(entry, item["result"], v4_digest))
        collection_jobs.append(
            {
                "job_id": request["job_id"],
                "request_digest": entry["request_digest"],
                "result_digest": item["result_digest"],
                "output_closure_digest": item["closure_digest"],
                "nonce_receipt_digest": receipt_digest,
                "nested_evidence_digest": item["nested_digest"],
                "evidence_digest": v4_digest,
            }
        )

    report = evaluate(
        loaded["canonical"],
        v4_outcomes,
        loaded["root"],
        evidence_state=control_root,
    )
    report_digest = _put_json(control_cas, report)
    outcomes_digest = canonical_digest(
        sorted(
            v4_outcomes,
            key=lambda item: (
                item["system"]["name"],
                item["case_id"],
                item["run_id"],
            ),
        )
    )
    collection = {
        "schema": "aragorn/benchmark-collection/v1",
        "assurance": "unsigned_label_free_protocol_not_isolated_or_attested",
        "ledger_id": ledger_id,
        "suite_digest": loaded["digest"],
        "dispatch_digest": dispatch_digest,
        "outcomes_digest": outcomes_digest,
        "report_digest": report_digest,
        "jobs": sorted(collection_jobs, key=lambda item: item["job_id"]),
    }
    collection_digest = _put_json(control_cas, collection)
    _commit_nonce_batch(
        ledger_path,
        ledger_id=ledger_id,
        suite_digest=loaded["digest"],
        dispatch_digest=dispatch_digest,
        collection_digest=collection_digest,
        receipts=nonce_receipts,
    )
    return {
        "schema": "aragorn/benchmark-collection-result/v1",
        "assurance": collection["assurance"],
        "suite_digest": loaded["digest"],
        "dispatch_digest": dispatch_digest,
        "ledger_id": ledger_id,
        "collection_digest": collection_digest,
        "outcomes_digest": outcomes_digest,
        "report_digest": report_digest,
        "job_count": len(v4_outcomes),
    }


def _nonce_ledger_id(
    *,
    suite_digest: str,
    dispatch_digest: str,
    pending: list[dict[str, Any]],
) -> str:
    return canonical_digest(
        {
            "schema": "aragorn/benchmark-worker-nonce-ledger-id/v1",
            "suite_digest": suite_digest,
            "dispatch_digest": dispatch_digest,
            "jobs": sorted(
                (
                    {
                        "job_id": item["request"]["job_id"],
                        "nonce": item["request"]["nonce"],
                        "request_digest": item["entry"]["request_digest"],
                        "result_digest": item["result_digest"],
                    }
                    for item in pending
                ),
                key=lambda item: item["job_id"],
            ),
        }
    )


def _verify_dispatch_matrix(
    dispatch: dict[str, Any], loaded: dict[str, Any], dispatch_digest: str
) -> None:
    if canonical_digest(dispatch) != dispatch_digest:
        raise CollectError("private dispatch digest is not canonical")
    expected = {
        (system_key, case_id, run_id)
        for system_key in loaded["systems"]
        for case_id in loaded["cases"]
        for run_id in range(1, loaded["runs_per_case"] + 1)
    }
    actual = {
        (
            (
                entry["system"]["name"],
                entry["system"]["version"],
                entry["system"]["implementation_digest"],
                entry["system"]["config_digest"],
            ),
            entry["case_id"],
            entry["run_id"],
        )
        for entry in dispatch["jobs"]
    }
    if actual != expected:
        raise CollectError("private dispatch does not cover the exact suite matrix")
    for entry in dispatch["jobs"]:
        case = loaded["cases"].get(entry["case_id"])
        manifest = loaded["manifests"].get(entry["case_id"])
        if case is None or manifest is None:
            raise CollectError("private dispatch references an unknown case")
        if entry["suite_digest"] != loaded["digest"]:
            raise CollectError("private dispatch suite digest changed")
        if entry["tree_digest"] != case["tree_digest"]:
            raise CollectError("private dispatch tree digest changed")
        if entry["private_manifest_digest"] != canonical_digest(manifest):
            raise CollectError("private dispatch manifest digest changed")


def _verify_dispatch_job(
    entry: dict[str, Any],
    request: dict[str, Any],
    result: dict[str, Any],
    loaded: dict[str, Any],
) -> None:
    comparisons = {
        "job_id": (request["job_id"], entry["job_id"]),
        "request_digest": (result["request_digest"], entry["request_digest"]),
        "system": (request["system"], entry["system"]),
        "tree_digest": (request["subject"]["tree_digest"], entry["tree_digest"]),
    }
    for field, (actual, expected) in comparisons.items():
        if actual != expected:
            raise CollectError(f"private dispatch changed worker {field}")
    manifest = loaded["manifests"][entry["case_id"]]
    if canonical_digest(manifest) != entry["private_manifest_digest"]:
        raise CollectError("private manifest changed after preparation")


def _find_worker_result(
    cas: CAS, blobs: dict[str, int]
) -> tuple[dict[str, Any], str]:
    candidates: list[tuple[dict[str, Any], str]] = []
    for digest, size in sorted(blobs.items()):
        if size > _MAX_DOCUMENT_BYTES:
            continue
        raw = cas.read(digest, max_bytes=size)
        if not raw.startswith(b"{"):
            continue
        try:
            document = _decode_object(raw, "worker output JSON candidate")
        except CollectError:
            continue
        if document.get("schema") != "aragorn/benchmark-worker-result/v1":
            continue
        if canonical_json(document) != raw:
            raise CollectError("worker result is not canonical JSON")
        candidates.append((document, digest))
    if len(candidates) != 1:
        raise CollectError("worker output must contain exactly one result")
    return candidates[0]


def _expected_worker_output(
    cas: CAS,
    request: dict[str, Any],
    subject: dict[str, Any],
    result: dict[str, Any],
    result_digest: str,
) -> set[str]:
    effective = _read_canonical_cas_object(
        cas,
        result["effective_config_digest"],
        max_bytes=_MAX_DOCUMENT_BYTES,
        label="effective OCI configuration",
    )
    docker_digest = effective.get("docker_executable_digest")
    if not isinstance(docker_digest, str) or _DIGEST.fullmatch(docker_digest) is None:
        raise CollectError("effective OCI configuration has no Docker digest")
    expected = {
        result["request_digest"],
        result_digest,
        result["subject_manifest_digest"],
        docker_digest,
        *(item["digest"] for item in subject["files"]),
        *(result[field] for field in _RESULT_DIGEST_FIELDS),
        *result["observation_digests"],
    }
    for receipt in result["runner_receipts"].values():
        expected.update(receipt.values())
    if request["subject"]["manifest_digest"] != result["subject_manifest_digest"]:
        raise CollectError("worker result changed subject manifest identity")
    return expected


def _nested_v3(entry: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-evidence/v3",
        "suite_digest": entry["suite_digest"],
        "case_id": entry["case_id"],
        "tree_digest": entry["tree_digest"],
        "verified_subject_digest": result["verified_subject_digest"],
        "run_id": entry["run_id"],
        "system": dict(result["system"]),
        "manifest_digest": entry["private_manifest_digest"],
        **{
            field: result[field]
            for field in (
                *_RESULT_DIGEST_FIELDS,
                "runner_receipts",
                "observation_digests",
                "execution",
                "normalization",
                "verdict",
                "reason_codes",
            )
        },
    }


def _outcome(
    entry: dict[str, Any], result: dict[str, Any], evidence_digest: str
) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        "suite_digest": entry["suite_digest"],
        "case_id": entry["case_id"],
        "tree_digest": entry["tree_digest"],
        "run_id": entry["run_id"],
        "system": dict(entry["system"]),
        "evidence_digest": evidence_digest,
        "verdict": result["verdict"],
        "reason_codes": list(result["reason_codes"]),
    }


def _enumerate_canonical_cas(root: Path) -> dict[str, int]:
    _require_real_directory(root, "CAS root")
    root_entries = _directory_entries(root, "CAS root", maximum=1)
    if set(root_entries) != {"blobs"}:
        raise CollectError("CAS root has noncanonical entries")
    blobs_entries = _directory_entries(
        root_entries["blobs"], "CAS blobs directory", maximum=1
    )
    if set(blobs_entries) != {"sha256"}:
        raise CollectError("CAS blobs directory has noncanonical entries")
    prefix_entries = _directory_entries(
        blobs_entries["sha256"], "CAS SHA-256 directory", maximum=256
    )
    result: dict[str, int] = {}
    for prefix, prefix_path in prefix_entries.items():
        if len(prefix) != 2 or any(character not in _HEX for character in prefix):
            raise CollectError("CAS has a noncanonical digest prefix")
        _require_real_directory(prefix_path, "CAS digest prefix")
        files = _directory_entries(prefix_path, "CAS digest prefix", maximum=_MAX_BLOBS)
        if not files:
            raise CollectError("CAS has an empty digest prefix")
        for suffix, blob_path in files.items():
            if len(suffix) != 62 or any(character not in _HEX for character in suffix):
                raise CollectError("CAS has a noncanonical blob name")
            metadata = os.lstat(blob_path)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise CollectError("CAS blob is not a regular file")
            if metadata.st_size > _MAX_BLOB_BYTES:
                raise CollectError("CAS blob exceeds the per-blob limit")
            digest = f"sha256:{prefix}{suffix}"
            result[digest] = metadata.st_size
            if len(result) > _MAX_BLOBS:
                raise CollectError("CAS exceeds the blob count limit")
    return result


def _read_canonical_cas_object(
    cas: CAS, digest: str, *, max_bytes: int, label: str
) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=max_bytes)
    return _decode_canonical_object(raw, label)


def _decode_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    document = _decode_object(raw, label)
    if canonical_json(document) != raw:
        raise CollectError(f"{label} is not canonical JSON")
    return document


def _decode_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
        _finite(document)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CollectError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CollectError(f"{label} must be a JSON object")
    return document


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise CollectError(f"non-finite JSON value: {value}")


def _finite(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise CollectError("non-finite JSON number")
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _prepare_nonce_ledger(path: Path) -> None:
    if not os.path.lexists(path):
        _require_real_directory(path.parent, "nonce ledger parent")
        try:
            os.mkdir(path, 0o700)
            _fsync_directory(path.parent, "nonce ledger parent")
        except OSError as exc:
            raise CollectError(f"cannot create nonce ledger: {exc}") from exc
    _require_private_directory(path, "nonce ledger")
    for name in ("batches", ".staging"):
        child = path / name
        if not os.path.lexists(child):
            try:
                os.mkdir(child, 0o700)
                _fsync_directory(path, "nonce ledger")
            except OSError as exc:
                raise CollectError(f"cannot create nonce ledger {name}: {exc}") from exc
        _require_private_directory(child, f"nonce ledger {name}")
    lock_path = path / ".lock"
    if not os.path.lexists(lock_path):
        descriptor = -1
        try:
            descriptor = os.open(
                lock_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.fsync(descriptor)
            _fsync_directory(path, "nonce ledger")
        except FileExistsError:
            pass
        except OSError as exc:
            raise CollectError(f"cannot create nonce ledger lock: {exc}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    metadata = os.lstat(lock_path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (
            os.name == "posix"
            and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            )
        )
    ):
        raise CollectError("nonce ledger lock must be private and regular")
    entries = _directory_entries(path, "nonce ledger", maximum=3)
    if set(entries) != {".lock", ".staging", "batches"}:
        raise CollectError("nonce ledger has unknown entries")


def _fsync_directory(path: Path, label: str) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise CollectError(f"cannot persist {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _commit_nonce_batch(
    root: Path,
    *,
    ledger_id: str,
    suite_digest: str,
    dispatch_digest: str,
    collection_digest: str,
    receipts: list[dict[str, str]],
) -> str:
    for value in (ledger_id, suite_digest, dispatch_digest, collection_digest):
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise CollectError("nonce batch identity is invalid")
    if not receipts or len(receipts) > _MAX_JOBS:
        raise CollectError("nonce batch size is invalid")
    nonces = [receipt.get("nonce") for receipt in receipts]
    if (
        any(not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None for nonce in nonces)
        or len(set(nonces)) != len(nonces)
    ):
        raise CollectError("nonce batch contains an invalid or repeated nonce")
    if any(
        receipt.get("ledger_id") != ledger_id
        or receipt.get("dispatch_digest") != dispatch_digest
        for receipt in receipts
    ):
        raise CollectError("nonce receipts do not match their batch identity")
    batch = {
        "schema": "aragorn/benchmark-worker-nonce-batch/v1",
        "ledger_id": ledger_id,
        "suite_digest": suite_digest,
        "dispatch_digest": dispatch_digest,
        "collection_digest": collection_digest,
        "receipts": sorted(receipts, key=lambda item: item["nonce"]),
    }
    raw = canonical_json(batch)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise CollectError("nonce batch exceeds its byte limit")
    batch_digest = canonical_digest(batch)
    _prepare_nonce_ledger(root)
    stage_path = _stage_nonce_batch(root / ".staging", raw)
    try:
        _publish_nonce_batch(
            root,
            stage_path,
            batch_digest.removeprefix("sha256:") + ".json",
            set(nonces),
        )
    finally:
        try:
            os.unlink(stage_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise CollectError(f"cannot remove staged nonce batch: {exc}") from exc
    return batch_digest


def _stage_nonce_batch(staging: Path, content: bytes) -> Path:
    descriptor = -1
    path = staging / f"{secrets.token_hex(16)}.tmp"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
        return path
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise CollectError(f"cannot stage nonce batch: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _publish_nonce_batch(
    root: Path,
    stage_path: Path,
    filename: str,
    requested_nonces: set[str],
) -> None:
    lock_fd = batches_fd = -1
    try:
        lock_fd = os.open(
            root / ".lock",
            os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        consumed = _consumed_nonces(root / "batches")
        if requested_nonces & consumed:
            committed = root / "batches" / filename
            if os.path.lexists(committed) and _same_nonce_batch(
                committed, stage_path
            ):
                return
            raise CollectError("worker nonce was already consumed by another batch")
        batches_fd = os.open(
            root / "batches",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.link(
            stage_path,
            filename,
            dst_dir_fd=batches_fd,
            follow_symlinks=False,
        )
        os.fsync(batches_fd)
    except CollectError:
        raise
    except FileExistsError as exc:
        raise CollectError("nonce batch was already committed") from exc
    except OSError as exc:
        raise CollectError(f"cannot publish nonce batch: {exc}") from exc
    finally:
        if batches_fd >= 0:
            os.close(batches_fd)
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def _same_nonce_batch(first: Path, second: Path) -> bool:
    first_raw = _read_stable_read_only_file(
        first,
        max_bytes=_MAX_MANIFEST_BYTES,
        label="committed nonce batch",
    )
    second_raw = _read_stable_read_only_file(
        second,
        max_bytes=_MAX_MANIFEST_BYTES,
        label="staged nonce batch",
    )
    return first_raw == second_raw


def _consumed_nonces(batches: Path) -> set[str]:
    entries = _directory_entries(batches, "nonce batches", maximum=_MAX_JOBS)
    consumed: set[str] = set()
    receipt_count = 0
    for filename, path in sorted(entries.items()):
        match = _NONCE_BATCH_FILE.fullmatch(filename)
        if match is None:
            raise CollectError("nonce batches contain an invalid filename")
        raw = _read_stable_read_only_file(
            path,
            max_bytes=_MAX_MANIFEST_BYTES,
            label="nonce batch",
        )
        batch = _decode_canonical_object(raw, "nonce batch")
        if canonical_digest(batch) != f"sha256:{match.group(1)}":
            raise CollectError("nonce batch filename does not match its content")
        if set(batch) != {
            "schema",
            "ledger_id",
            "suite_digest",
            "dispatch_digest",
            "collection_digest",
            "receipts",
        } or batch["schema"] != "aragorn/benchmark-worker-nonce-batch/v1":
            raise CollectError("nonce batch fields are invalid")
        for field in (
            "ledger_id",
            "suite_digest",
            "dispatch_digest",
            "collection_digest",
        ):
            if not isinstance(batch[field], str) or _DIGEST.fullmatch(batch[field]) is None:
                raise CollectError("nonce batch digest is invalid")
        receipts = batch["receipts"]
        if not isinstance(receipts, list) or not receipts:
            raise CollectError("nonce batch receipts are invalid")
        receipt_nonces = [
            receipt.get("nonce") if isinstance(receipt, dict) else None
            for receipt in receipts
        ]
        if (
            any(not isinstance(nonce, str) for nonce in receipt_nonces)
            or receipt_nonces != sorted(receipt_nonces)
            or len(receipt_nonces) != len(set(receipt_nonces))
        ):
            raise CollectError("nonce batch receipts are not sorted and unique")
        job_ids: set[str] = set()
        requests: set[str] = set()
        results: set[str] = set()
        for receipt in receipts:
            _validate_nonce_receipt(receipt)
            if (
                receipt["ledger_id"] != batch["ledger_id"]
                or receipt["dispatch_digest"] != batch["dispatch_digest"]
            ):
                raise CollectError("nonce receipt is unbound from its batch")
            nonce = receipt["nonce"]
            if (
                receipt["job_id"] in job_ids
                or receipt["request_digest"] in requests
                or receipt["result_digest"] in results
            ):
                raise CollectError("nonce batch repeats a worker binding")
            job_ids.add(receipt["job_id"])
            requests.add(receipt["request_digest"])
            results.add(receipt["result_digest"])
            if nonce in consumed:
                raise CollectError("nonce ledger repeats a consumed nonce")
            consumed.add(nonce)
            receipt_count += 1
            if receipt_count > _MAX_JOBS:
                raise CollectError("nonce ledger exceeds its receipt limit")
        expected_ledger_id = canonical_digest(
            {
                "schema": "aragorn/benchmark-worker-nonce-ledger-id/v1",
                "suite_digest": batch["suite_digest"],
                "dispatch_digest": batch["dispatch_digest"],
                "jobs": sorted(
                    (
                        {
                            "job_id": receipt["job_id"],
                            "nonce": receipt["nonce"],
                            "request_digest": receipt["request_digest"],
                            "result_digest": receipt["result_digest"],
                        }
                        for receipt in receipts
                    ),
                    key=lambda item: item["job_id"],
                ),
            }
        )
        if expected_ledger_id != batch["ledger_id"]:
            raise CollectError("nonce batch ledger identity is unbound")
    return consumed


def _validate_nonce_receipt(receipt: object) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "ledger_id",
        "dispatch_digest",
        "job_id",
        "nonce",
        "request_digest",
        "result_digest",
    }:
        raise CollectError("nonce receipt fields are invalid")
    if receipt["schema"] != "aragorn/benchmark-worker-nonce-consumption/v1":
        raise CollectError("nonce receipt schema is invalid")
    if (
        not isinstance(receipt["job_id"], str)
        or _JOB_ID.fullmatch(receipt["job_id"]) is None
    ):
        raise CollectError("nonce receipt job ID is invalid")
    if (
        not isinstance(receipt["nonce"], str)
        or _NONCE.fullmatch(receipt["nonce"]) is None
    ):
        raise CollectError("nonce receipt nonce is invalid")
    for field in ("ledger_id", "dispatch_digest", "request_digest", "result_digest"):
        if (
            not isinstance(receipt[field], str)
            or _DIGEST.fullmatch(receipt[field]) is None
        ):
            raise CollectError("nonce receipt digest is invalid")


def _put_json(cas: CAS, document: object) -> str:
    return _put_bytes(cas, canonical_json(document))


def _put_bytes(cas: CAS, content: bytes) -> str:
    return cas.put(BytesIO(content), max_bytes=len(content))


def _existing_file(value: str | os.PathLike[str], label: str) -> Path:
    path = _absolute_path(value).resolve(strict=True)
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise CollectError(f"{label} must be a regular file")
    return path


def _existing_directory(value: str | os.PathLike[str], label: str) -> Path:
    path = _absolute_path(value).resolve(strict=True)
    _require_real_directory(path, label)
    return path


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    except (TypeError, ValueError, OSError) as exc:
        raise CollectError(f"invalid filesystem path: {exc}") from exc


def _require_separate_paths(*paths: Path) -> None:
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            try:
                first.relative_to(second)
            except ValueError:
                pass
            else:
                raise CollectError("collector paths must not overlap")
            try:
                second.relative_to(first)
            except ValueError:
                pass
            else:
                raise CollectError("collector paths must not overlap")


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise CollectError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise CollectError(f"{label} must be a real directory")


def _require_private_directory(path: Path, label: str) -> None:
    _require_real_directory(path, label)
    metadata = os.lstat(path)
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise CollectError(f"{label} must be private and owned by the current user")


def _directory_entries(path: Path, label: str, *, maximum: int) -> dict[str, Path]:
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        raise CollectError(f"cannot enumerate {label}: {exc}") from exc
    if len(entries) > maximum:
        raise CollectError(f"{label} exceeds its entry count limit")
    result: dict[str, Path] = {}
    for entry in entries:
        if entry.name in result:
            raise CollectError(f"{label} repeats an entry")
        result[entry.name] = path / entry.name
    return result


def _read_stable_read_only_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o222:
            raise CollectError(f"{label} must be a read-only regular file")
        if before.st_size > max_bytes:
            raise CollectError(f"{label} exceeds {max_bytes} bytes")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            raw = source.read(max_bytes + 1)
            after = os.fstat(source.fileno())
        if len(raw) > max_bytes or len(raw) != before.st_size:
            raise CollectError(f"{label} changed while it was read")
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise CollectError(f"{label} changed while it was read")
        return raw
    except CollectError:
        raise
    except OSError as exc:
        raise CollectError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CollectError(message)


def main(argv: Sequence[str] | None = None) -> int:
    parser = ArgumentParser(
        prog="python -m aragorn.label_blind_collect",
        description="Collect one complete label-free OCI benchmark batch.",
    )
    parser.add_argument("suite", type=Path)
    parser.add_argument("--dispatch-digest", required=True)
    parser.add_argument("--control-state", type=Path, required=True)
    parser.add_argument("--jobs-root", type=Path, required=True)
    try:
        arguments = parser.parse_args(argv)
        document = collect_files(
            arguments.suite,
            dispatch_digest=arguments.dispatch_digest,
            control_state=arguments.control_state,
            jobs_root=arguments.jobs_root,
        )
    except (
        BenchmarkError,
        CASError,
        CollectError,
        OSError,
        PrepareError,
        RuntimeError,
        ValueError,
        WorkerProtocolError,
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
    print(canonical_json(document).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
