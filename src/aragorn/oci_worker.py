"""Execute one unsigned, label-blind OCI benchmark worker request."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from io import BytesIO
import json
import math
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Any, Callable, Iterator, Sequence

from .benchmark import BenchmarkError
from .cas import CAS, CASError
from .cli import _within
from .oci_benchmark_runner import (
    RunnerError,
    _oci_workspace,
    _preflight,
    _retain_docker,
    _retain_execution_evidence,
    identify as _identify,
)
from .oci_runtime import (
    LOCK,
    VerificationError,
    _sha256,
    _verify_docker_unchanged,
    resolve_docker,
    run_baseline,
)
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_json,
    canonical_request_digest,
    validate_subject_manifest,
    validate_worker_request,
    validate_worker_result,
    verify_request_result_binding,
    verify_request_subject,
)


_MAX_REQUEST_BYTES = 64 * 1024
_MAX_SUBJECT_MANIFEST_BYTES = 128 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_DOCKER_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_CLOSURE_BLOBS = 25_000
_HEX = frozenset("0123456789abcdef")


class WorkerError(ValueError):
    """A one-job worker request cannot be executed without ambiguity."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise WorkerError(message)


def identity(
    *,
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> tuple[dict[str, str], ...]:
    """Return the effective identities this local worker can execute."""

    return _identify(
        lock_path=lock_path,
        docker_executable=docker_executable,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )


def run(
    request_path: str | os.PathLike[str],
    *,
    request_digest: str,
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Execute one canonical request over a separate read-only subject CAS."""

    request_file, input_path, output_path, local_lock = _resolve_boundaries(
        request_path,
        input_state,
        output_state,
        lock_path,
    )
    raw_request = _read_file_bounded(
        request_file,
        max_bytes=_MAX_REQUEST_BYTES,
        label="worker request",
    )
    request = _validate_canonical_object(
        raw_request,
        label="worker request",
        validator=validate_worker_request,
    )
    if canonical_request_digest(request) != request_digest:
        raise WorkerError("worker request digest does not match canonical content")

    input_cas = CAS(input_path, read_only=True)
    manifest_digest = request["subject"]["manifest_digest"]
    manifest, raw_manifest = _read_canonical_object(
        input_cas,
        manifest_digest,
        max_bytes=_MAX_SUBJECT_MANIFEST_BYTES,
        label="subject manifest",
        validator=validate_subject_manifest,
    )
    verify_request_subject(request, manifest)

    docker = resolve_docker(docker_executable)
    if _paths_overlap(docker.path, input_path) or _paths_overlap(
        docker.path, output_path
    ):
        raise WorkerError("Docker executable must be outside worker CAS roots")
    scratch_root = _resolve_workspace_root(
        workspace_root,
        forbidden=(request_file, input_path, output_path, local_lock, docker.path),
    )

    with _output_transaction(output_path) as (output_cas, staging_path):
        _copy_exact(output_cas, raw_request, request_digest, "worker request")
        _copy_exact(
            output_cas,
            raw_manifest,
            manifest_digest,
            "subject manifest",
        )
        _verify_and_copy_subject(input_cas, output_cas, manifest)

        limits = request["limits"]
        prepared = _select_preflight(
            request,
            lock_path=local_lock,
            docker_executable=docker.path,
        )
        docker_digest = _retain_docker(output_cas, prepared.docker)
        effective = _load_object(
            prepared.effective_config_json,
            "effective OCI configuration",
        )
        if effective.get("docker_executable_digest") != docker_digest:
            raise WorkerError(
                "effective OCI configuration names another Docker executable"
            )

        with tempfile.TemporaryDirectory(
            prefix=".aragorn-worker-",
            dir=scratch_root,
        ) as temporary:
            opaque_root = Path(temporary).resolve(strict=True)
            with _oci_workspace(
                input_cas,
                manifest,
                parent=opaque_root,
                forbidden_roots=(
                    input_path,
                    staging_path,
                    local_lock,
                    request_file,
                ),
            ) as workspace:
                execution = run_baseline(
                    prepared.baseline["name"],
                    workspace=workspace,
                    expected_tree_digest=request["subject"]["tree_digest"],
                    lock_path=local_lock,
                    docker_executable=prepared.docker.path,
                    timeout_seconds=limits["timeout_seconds"],
                    output_limit_bytes=limits["output_bytes"],
                    expected_effective_config_json=(
                        prepared.effective_config_json
                    ),
                )
                retained = _retain_execution_evidence(
                    output_cas,
                    subject_digest=request["subject"]["tree_digest"],
                    prepared=prepared,
                    result=execution,
                )

        result = {
            "schema": "aragorn/benchmark-worker-result/v1",
            "job_id": request["job_id"],
            "nonce": request["nonce"],
            "request_digest": request_digest,
            "subject_manifest_digest": manifest_digest,
            "tree_digest": request["subject"]["tree_digest"],
            "system": dict(request["system"]),
            **retained,
        }
        validate_worker_result(result)
        verify_request_result_binding(request, result)
        _verify_docker_unchanged(prepared.docker)
        result_json = canonical_json(result)
        result_digest = _sha256(result_json)
        _copy_exact(
            output_cas,
            result_json,
            result_digest,
            "worker result",
        )
        _verify_result_closure(
            output_cas,
            request_digest=request_digest,
            raw_request=raw_request,
            manifest=manifest,
            manifest_digest=manifest_digest,
            raw_manifest=raw_manifest,
            docker_digest=docker_digest,
            result=result,
            result_digest=result_digest,
            raw_result=result_json,
        )
    return result


def _resolve_boundaries(
    request_path: str | os.PathLike[str],
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    lock_path: str | os.PathLike[str],
) -> tuple[Path, Path, Path, Path]:
    try:
        request_file = _read_only_file_path(
            request_path,
            "worker request",
        )
        input_path = Path(input_state).expanduser().resolve(strict=True)
        output_path = Path(output_state).expanduser().resolve(strict=False)
        local_lock = Path(lock_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkerError(f"cannot resolve worker paths: {exc}") from exc
    if not input_path.is_dir():
        raise WorkerError("worker input state must be a directory")
    if output_path.exists():
        raise WorkerError("worker output state must be a fresh path")
    if _paths_overlap(input_path, output_path):
        raise WorkerError("worker input and output CAS roots must not overlap")
    if _paths_overlap(request_file, input_path) or _paths_overlap(
        request_file,
        output_path,
    ):
        raise WorkerError("worker request must be separate from both CAS roots")
    if _paths_overlap(local_lock, input_path) or _paths_overlap(
        local_lock, output_path
    ):
        raise WorkerError("baseline lock must be outside worker CAS roots")
    return request_file, input_path, output_path, local_lock


def _paths_overlap(first: Path, second: Path) -> bool:
    return _within(first, second) or _within(second, first)


def _resolve_workspace_root(
    value: str | os.PathLike[str] | None,
    *,
    forbidden: tuple[Path, ...],
) -> Path | None:
    if value is None:
        return None
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        _reject_controlled_symlinks(supplied, "worker workspace root")
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except WorkerError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError(f"invalid worker workspace root: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise WorkerError("worker workspace root must be a real directory")
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise WorkerError(
            "worker workspace root must be private and owned by the current user"
        )
    if any(_paths_overlap(path, forbidden_path) for forbidden_path in forbidden):
        raise WorkerError("worker workspace root overlaps a protected worker path")
    return path


def _reject_controlled_symlinks(path: Path, label: str) -> None:
    current = Path(path.anchor)
    try:
        controlled = _writable_by_current_user(os.lstat(current))
    except OSError as exc:
        raise WorkerError(f"cannot inspect {label}: {exc}") from exc
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise WorkerError(f"cannot inspect {label}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) and controlled:
            raise WorkerError(f"{label} must not use a controllable symlink")
        if stat.S_ISDIR(metadata.st_mode) and _writable_by_current_user(metadata):
            controlled = True


def _writable_by_current_user(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == os.geteuid():
        return bool(mode & stat.S_IWUSR)
    if metadata.st_gid in {os.getegid(), *os.getgroups()}:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


@contextmanager
def _output_transaction(
    output_path: Path,
) -> Iterator[tuple[CAS, Path]]:
    parent = output_path.parent
    try:
        parent = parent.resolve(strict=True)
        metadata = os.lstat(parent)
    except OSError as exc:
        raise WorkerError(f"cannot inspect worker output parent: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise WorkerError("worker output parent must be a real directory")
    if os.name == "posix":
        if metadata.st_uid != os.geteuid():
            raise WorkerError(
                "worker output parent must be owned by the current user"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise WorkerError(
                "worker output parent must not be group or other writable"
            )

    staging = Path(
        tempfile.mkdtemp(
            prefix=".aragorn-worker-output-",
            dir=parent,
        )
    ).resolve(strict=True)
    published = False
    completed = False
    try:
        yield CAS(staging), staging
        if os.path.lexists(output_path):
            raise WorkerError("worker output state stopped being fresh")
        os.rename(staging, output_path)
        published = True
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        completed = True
    finally:
        if not completed:
            cleanup = output_path if published else staging
            try:
                if os.path.lexists(cleanup):
                    shutil.rmtree(cleanup)
            except OSError as exc:
                raise WorkerError(
                    f"cannot remove unpublished worker output: {exc}"
                ) from exc
            if os.path.lexists(cleanup):
                raise WorkerError("cannot remove unpublished worker output")


def _read_canonical_object(
    cas: CAS,
    digest: str,
    *,
    max_bytes: int,
    label: str,
    validator: Callable[[object], None],
) -> tuple[dict[str, Any], bytes]:
    raw = cas.read(digest, max_bytes=max_bytes)
    return (
        _validate_canonical_object(
            raw,
            label=label,
            validator=validator,
        ),
        raw,
    )


def _validate_canonical_object(
    raw: bytes,
    *,
    label: str,
    validator: Callable[[object], None],
) -> dict[str, Any]:
    document = _decode_object(raw, label)
    validator(document)
    if canonical_json(document) != raw:
        raise WorkerError(f"{label} is not canonical JSON")
    return document


def _read_only_file_path(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        supplied = Path(
            os.path.abspath(os.path.expanduser(os.fspath(value)))
        )
        supplied_metadata = os.lstat(supplied)
        if stat.S_ISLNK(supplied_metadata.st_mode):
            raise WorkerError(f"{label} must not be a symlink")
        path = supplied.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError(f"invalid {label} path: {exc}") from exc
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise WorkerError(f"cannot inspect {label}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise WorkerError(f"{label} path must not contain symlinks")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise WorkerError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise WorkerError(f"{label} must be a regular file")
    if metadata.st_mode & 0o222:
        raise WorkerError(f"{label} must be read-only")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise WorkerError(f"{label} must be owned by the current user")
    return path


def _read_file_bounded(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise WorkerError(f"{label} must be a regular file")
        if before.st_mode & 0o222:
            raise WorkerError(f"{label} must be read-only")
        if os.name == "posix" and before.st_uid != os.geteuid():
            raise WorkerError(f"{label} must be owned by the current user")
        if before.st_size > max_bytes:
            raise WorkerError(f"{label} exceeds {max_bytes} bytes")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            raw = source.read(max_bytes + 1)
            after = os.fstat(source.fileno())
        if len(raw) > max_bytes:
            raise WorkerError(f"{label} exceeds {max_bytes} bytes")
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(raw) != before.st_size:
            raise WorkerError(f"{label} changed while it was read")
        return raw
    except WorkerError:
        raise
    except OSError as exc:
        raise WorkerError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _decode_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
        _finite(document)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WorkerError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise WorkerError(f"{label} must be a JSON object")
    return document


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise WorkerError(f"non-finite JSON value: {value}")


def _finite(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise WorkerError("non-finite JSON number")
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _copy_exact(
    cas: CAS,
    content: bytes,
    expected_digest: str,
    label: str,
) -> None:
    actual = cas.put(BytesIO(content), max_bytes=len(content))
    if actual != expected_digest:
        raise WorkerError(f"retained {label} digest changed")


def _verify_and_copy_subject(
    input_cas: CAS,
    output_cas: CAS,
    manifest: dict[str, Any],
) -> None:
    for entry in manifest["files"]:
        content = input_cas.read(entry["digest"], max_bytes=entry["size"])
        if len(content) != entry["size"]:
            raise WorkerError(
                f"subject blob size does not match manifest: {entry['path']}"
            )
        _copy_exact(
            output_cas,
            content,
            entry["digest"],
            f"subject blob {entry['path']}",
        )


def _select_preflight(
    request: dict[str, Any],
    *,
    lock_path: Path,
    docker_executable: Path,
):
    limits = request["limits"]
    prepared = _preflight(
        lock_path=lock_path,
        docker_executable=docker_executable,
        timeout_seconds=limits["timeout_seconds"],
        output_limit_bytes=limits["output_bytes"],
    )
    selected = [item for item in prepared if item.system == request["system"]]
    if len(selected) != 1:
        raise WorkerError(
            "worker request does not match one derived local baseline identity"
        )
    item = selected[0]
    comparisons = {
        "baseline lock": (
            _sha256(item.raw_lock),
            request["baseline"]["lock_digest"],
        ),
        "baseline entry": (
            _sha256(item.selected_json),
            request["baseline"]["entry_digest"],
        ),
        "effective configuration": (
            _sha256(item.effective_config_json),
            request["system"]["config_digest"],
        ),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerError(f"worker request {label} changed before launch")
    return item


def _load_object(raw: bytes, label: str) -> dict[str, Any]:
    document = _decode_object(raw, label)
    if canonical_json(document) != raw:
        raise WorkerError(f"{label} is not canonical JSON")
    return document


def _verify_result_closure(
    cas: CAS,
    *,
    request_digest: str,
    raw_request: bytes,
    manifest: dict[str, Any],
    manifest_digest: str,
    raw_manifest: bytes,
    docker_digest: str,
    result: dict[str, Any],
    result_digest: str,
    raw_result: bytes,
) -> None:
    if cas.read(request_digest, max_bytes=_MAX_REQUEST_BYTES) != raw_request:
        raise WorkerError("retained worker request changed")
    if (
        cas.read(manifest_digest, max_bytes=_MAX_SUBJECT_MANIFEST_BYTES)
        != raw_manifest
    ):
        raise WorkerError("retained subject manifest changed")
    for entry in manifest["files"]:
        content = cas.read(entry["digest"], max_bytes=entry["size"])
        if len(content) != entry["size"]:
            raise WorkerError(
                f"retained subject blob size changed: {entry['path']}"
            )

    digest_fields = (
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
    for field in digest_fields:
        cas.verify(result[field], max_bytes=_MAX_EVIDENCE_BYTES)
    for receipt in result["runner_receipts"].values():
        for digest in receipt.values():
            cas.verify(digest, max_bytes=_MAX_EVIDENCE_BYTES)
    for digest in result["observation_digests"]:
        cas.verify(digest, max_bytes=_MAX_EVIDENCE_BYTES)

    effective = _load_object(
        cas.read(
            result["effective_config_digest"],
            max_bytes=_MAX_EVIDENCE_BYTES,
        ),
        "retained effective OCI configuration",
    )
    if effective.get("docker_executable_digest") != docker_digest:
        raise WorkerError("retained effective configuration changed Docker identity")
    cas.verify(docker_digest, max_bytes=_MAX_DOCKER_BYTES)

    retained_result = cas.read(
        result_digest,
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    if retained_result != raw_result:
        raise WorkerError("retained worker result changed")
    decoded_result = _validate_canonical_object(
        retained_result,
        label="retained worker result",
        validator=validate_worker_result,
    )
    if decoded_result != result:
        raise WorkerError("retained worker result does not match generated result")

    expected = {
        request_digest,
        manifest_digest,
        docker_digest,
        result_digest,
        *(entry["digest"] for entry in manifest["files"]),
        *(result[field] for field in digest_fields),
        *(
            digest
            for receipt in result["runner_receipts"].values()
            for digest in receipt.values()
        ),
        *result["observation_digests"],
    }
    actual = _enumerate_canonical_cas(cas.root)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise WorkerError(
            "worker output CAS is not the exact result closure; "
            f"missing={missing!r}, extra={extra!r}"
        )
    for digest in sorted(actual):
        cas.verify(digest, max_bytes=_MAX_DOCKER_BYTES)


def _enumerate_canonical_cas(root: Path) -> set[str]:
    _require_real_directory(root, "worker output CAS root")
    root_entries = _directory_entries(root, "worker output CAS root")
    if set(root_entries) != {"blobs"}:
        raise WorkerError("worker output CAS root has noncanonical entries")
    _require_real_directory(
        root_entries["blobs"],
        "worker output CAS blobs directory",
    )
    blobs_entries = _directory_entries(
        root_entries["blobs"],
        "worker output CAS blobs directory",
    )
    if set(blobs_entries) != {"sha256"}:
        raise WorkerError("worker output CAS blobs directory is noncanonical")
    sha_root = blobs_entries["sha256"]
    _require_real_directory(
        sha_root,
        "worker output CAS SHA-256 directory",
    )
    prefix_entries = _directory_entries(
        sha_root,
        "worker output CAS SHA-256 directory",
    )
    if len(prefix_entries) > 256:
        raise WorkerError("worker output CAS has too many digest prefixes")

    digests: set[str] = set()
    for prefix, prefix_path in prefix_entries.items():
        if len(prefix) != 2 or any(character not in _HEX for character in prefix):
            raise WorkerError("worker output CAS has a noncanonical digest prefix")
        metadata = os.lstat(prefix_path)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise WorkerError("worker output CAS digest prefix is not a directory")
        blob_entries = _directory_entries(
            prefix_path,
            "worker output CAS digest prefix",
        )
        if not blob_entries:
            raise WorkerError("worker output CAS has an empty digest prefix")
        for suffix, blob_path in blob_entries.items():
            if len(suffix) != 62 or any(
                character not in _HEX for character in suffix
            ):
                raise WorkerError(
                    "worker output CAS has a noncanonical blob name"
                )
            blob_metadata = os.lstat(blob_path)
            if not stat.S_ISREG(blob_metadata.st_mode) or stat.S_ISLNK(
                blob_metadata.st_mode
            ):
                raise WorkerError("worker output CAS blob is not a regular file")
            digests.add(f"sha256:{prefix}{suffix}")
            if len(digests) > _MAX_OUTPUT_CLOSURE_BLOBS:
                raise WorkerError("worker output CAS exceeds its blob count limit")
    return digests


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise WorkerError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise WorkerError(f"{label} is not a real directory")


def _directory_entries(path: Path, label: str) -> dict[str, Path]:
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        raise WorkerError(f"cannot enumerate {label}: {exc}") from exc
    if len(entries) > _MAX_OUTPUT_CLOSURE_BLOBS:
        raise WorkerError(f"{label} exceeds its entry count limit")
    result: dict[str, Path] = {}
    for entry in entries:
        if entry.name in result:
            raise WorkerError(f"{label} repeats an entry")
        result[entry.name] = path / entry.name
    return result


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python -m aragorn.oci_worker",
        description="Execute one label-blind digest-bound OCI benchmark job.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    identity_command = commands.add_parser("identity")
    identity_command.add_argument("--lock", type=Path, default=LOCK)
    identity_command.add_argument("--docker", default="docker")
    identity_command.add_argument("--timeout", type=float, default=120.0)
    identity_command.add_argument(
        "--output-limit",
        type=int,
        default=1024 * 1024,
    )
    identity_command.set_defaults(action=_identity_command)

    run_command = commands.add_parser("run")
    run_command.add_argument("request", type=Path)
    run_command.add_argument("--request-digest", required=True)
    run_command.add_argument("--input-state", type=Path, required=True)
    run_command.add_argument("--output-state", type=Path, required=True)
    run_command.add_argument("--lock", type=Path, default=LOCK)
    run_command.add_argument("--docker", default="docker")
    run_command.add_argument(
        "--workspace-root",
        type=Path,
        help="private Docker-shared parent for opaque worker workspaces",
    )
    run_command.set_defaults(action=_run_command)
    return parser


def _identity_command(args: argparse.Namespace) -> dict[str, Any]:
    systems = identity(
        lock_path=args.lock,
        docker_executable=args.docker,
        timeout_seconds=args.timeout,
        output_limit_bytes=args.output_limit,
    )
    return {
        "schema": "aragorn/benchmark-system-identities/v1",
        "systems": systems,
    }


def _run_command(args: argparse.Namespace) -> dict[str, Any]:
    return run(
        args.request,
        request_digest=args.request_digest,
        input_state=args.input_state,
        output_state=args.output_state,
        lock_path=args.lock,
        docker_executable=args.docker,
        workspace_root=args.workspace_root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        document = arguments.action(arguments)
        print(canonical_json(document).decode("ascii"))
        return 0
    except (
        BenchmarkError,
        CASError,
        OSError,
        RunnerError,
        RuntimeError,
        ValueError,
        VerificationError,
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


if __name__ == "__main__":
    raise SystemExit(main())
