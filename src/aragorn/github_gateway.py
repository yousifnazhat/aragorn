"""Privilege-separated, credential-free GitHub acquisition gateway."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from .artifact_closure import canonical_json, load_verified_retained_manifest
from .benchmark_handoff_v2 import (
    HandoffError,
    build_handoff_manifest,
    export_declared_byte_transport,
    import_declared_byte_transport,
)
from .cas import CAS, CASError
from .github_acquire import (
    _COMMIT,
    _OWNER,
    _REPOSITORY,
    _parse_skill_path,
    acquire_github_commit,
)
from .oci_runtime import _ProcessResult, _run_bounded

REQUEST_SCHEMA = "aragorn/github-gateway-request/v1"
RESULT_SCHEMA = "aragorn/github-gateway-result/v1"
QUARANTINE_AUTHORITY = "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
SOURCE_ASSURANCE = "github_api_membership_asserted_blob_identity_reverified"
_REQUEST_KEYS = {"schema", "owner", "repository", "commit", "skill_path"}
_RESULT_KEYS = {
    "schema",
    "request_digest",
    "manifest_digest",
    "handoff_manifest_digest",
}
_MAX_WIRE_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_GATEWAY_SECONDS = 180.0
_MAX_PACKAGE_ENTRIES = 1_000
_DEFAULT_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_ISOLATED_ENTRYPOINT = (
    "import sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "from aragorn.github_gateway import main;"
    "raise SystemExit(main())"
)
_FIXED_LIMITS = {
    "max_depth": 8,
    "max_files": 10_000,
    "max_file_size": 16 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
    "max_api_requests": 20_050,
    "max_api_bytes": 384 * 1024 * 1024,
    "timeout_seconds": 120.0,
}


class GitHubGatewayError(ValueError):
    """The acquisition gateway failed closed."""


@dataclass(frozen=True, slots=True)
class GatewayQuarantineReceipt:
    """Self-consistent inert bytes retained without admission authority."""

    authority: str
    source_assurance: str
    request_digest: str
    manifest_digest: str
    tree_digest: str
    file_count: int
    handoff_manifest_digest: str
    quarantine_state: Path


def build_gateway_request(
    owner: str,
    repository: str,
    commit: str,
    skill_path: str,
) -> dict[str, str]:
    """Build one canonical, credential-free acquisition request."""

    request = {
        "schema": REQUEST_SCHEMA,
        "owner": owner,
        "repository": repository,
        "commit": commit,
        "skill_path": skill_path,
    }
    _validate_request(request)
    return request


def run_worker(
    request: object,
    job_root: str | os.PathLike[str],
) -> dict[str, str]:
    """Acquire one exact public source and export its declared byte closure."""

    frozen = _freeze_request(request)
    request_digest = _digest(canonical_json(frozen))
    root = _create_job_root(job_root)
    source_cas = CAS(root / "state")
    manifest = acquire_github_commit(
        _repository_url(frozen),
        frozen["commit"],
        frozen["skill_path"],
        source_cas,
        **_FIXED_LIMITS,
        bearer_token=None,
    )
    raw_manifest = canonical_json(manifest)
    if len(raw_manifest) > _MAX_MANIFEST_BYTES:
        raise GitHubGatewayError("GitHub source manifest exceeds its byte limit")
    manifest_digest = source_cas.put(
        BytesIO(raw_manifest),
        max_bytes=len(raw_manifest),
    )
    verified = load_verified_retained_manifest(source_cas, manifest_digest)
    _require_requested_source(verified, frozen)
    transport = build_handoff_manifest(
        kind="github_source",
        root_digest=manifest_digest,
        blobs=_source_closure(source_cas, manifest_digest, verified),
    )
    transport_digest = export_declared_byte_transport(
        source_cas,
        transport,
        root / "bundle",
    )
    result = {
        "schema": RESULT_SCHEMA,
        "request_digest": request_digest,
        "manifest_digest": manifest_digest,
        "handoff_manifest_digest": transport_digest,
    }
    _validate_result(result)
    return result


def quarantine_through_gateway(
    request: object,
    *,
    gateway_root: str | os.PathLike[str],
    quarantine_state: str | os.PathLike[str],
    worker_uid: int,
    worker_gid: int,
    process_timeout_seconds: float = 130.0,
    python_executable: str | os.PathLike[str] = sys.executable,
    package_root: str | os.PathLike[str] = _DEFAULT_PACKAGE_ROOT,
) -> GatewayQuarantineReceipt:
    """Quarantine one source assertion; this function cannot authorize it."""

    frozen = _freeze_request(request)
    raw_request = canonical_json(frozen)
    if (
        isinstance(process_timeout_seconds, bool)
        or not isinstance(process_timeout_seconds, (int, float))
        or not 0 < process_timeout_seconds <= _MAX_GATEWAY_SECONDS
    ):
        raise GitHubGatewayError(
            f"process_timeout_seconds must be between 0 and {_MAX_GATEWAY_SECONDS:g}"
        )
    _require_distinct_principal(worker_uid, worker_gid)
    gateway, quarantine = _prepare_paths(
        gateway_root,
        quarantine_state,
        worker_uid=worker_uid,
    )
    executable = _trusted_python_executable(python_executable)
    protected_package = _trusted_package_root(package_root)
    job_root = gateway / f"job-{secrets.token_hex(16)}"
    command = _gateway_command(
        executable,
        protected_package,
        "worker",
        "--job-root",
        os.fspath(job_root),
    )
    environment = {
        "HOME": os.fspath(gateway),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    try:
        try:
            process = _run_bounded(
                command,
                timeout=float(process_timeout_seconds),
                stdout_limit=_MAX_WIRE_BYTES,
                stderr_limit=_MAX_WIRE_BYTES,
                shared_limit=2 * _MAX_WIRE_BYTES,
                env=environment,
                stdin_bytes=raw_request + b"\n",
                cwd=os.path.sep,
                user=worker_uid,
                group=worker_gid,
                extra_groups=(),
                umask=0o077,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise GitHubGatewayError(
                f"cannot launch acquisition gateway: {exc}"
            ) from exc
        result = _require_success_result(process)
        return _accept_gateway_output(
            frozen,
            result,
            job_root=job_root,
            quarantine_state=quarantine,
            worker_uid=worker_uid,
        )
    finally:
        _remove_worker_job(job_root, expected_uid=worker_uid)


def _accept_gateway_output(
    request: dict[str, str],
    result: dict[str, str],
    *,
    job_root: Path,
    quarantine_state: Path,
    worker_uid: int,
) -> GatewayQuarantineReceipt:
    """Import and semantically verify a completed distinct-principal handoff."""

    _validate_result(result)
    expected_request_digest = _digest(canonical_json(request))
    if result["request_digest"] != expected_request_digest:
        raise GitHubGatewayError("gateway result is bound to a different request")
    _require_private_directory(job_root, expected_uid=worker_uid, label="gateway job")
    bundle = job_root / "bundle"
    _require_private_directory(bundle, expected_uid=worker_uid, label="gateway bundle")

    staging = quarantine_state.parent / (
        f".{quarantine_state.name}.import-{secrets.token_hex(16)}"
    )
    if os.path.lexists(staging):
        raise GitHubGatewayError("broker quarantine staging path already exists")
    published = False
    try:
        destination = CAS(staging)
        try:
            handoff = import_declared_byte_transport(
                bundle,
                destination,
                expected_manifest_digest=result["handoff_manifest_digest"],
                expected_kind="github_source",
                expected_root_digest=result["manifest_digest"],
            )
            manifest = load_verified_retained_manifest(
                destination,
                result["manifest_digest"],
            )
        except (CASError, HandoffError, ValueError) as exc:
            raise GitHubGatewayError(
                f"gateway quarantine verification failed: {exc}"
            ) from exc
        _require_requested_source(manifest, request)
        expected_closure = _source_closure(
            destination,
            result["manifest_digest"],
            manifest,
        )
        actual_closure = {entry["digest"]: entry["size"] for entry in handoff["blobs"]}
        if actual_closure != expected_closure:
            raise GitHubGatewayError(
                "gateway handoff contains bytes outside the verified source closure"
            )
        receipt = GatewayQuarantineReceipt(
            authority=QUARANTINE_AUTHORITY,
            source_assurance=SOURCE_ASSURANCE,
            request_digest=expected_request_digest,
            manifest_digest=result["manifest_digest"],
            tree_digest=manifest["tree_digest"],
            file_count=len(manifest["files"]),
            handoff_manifest_digest=result["handoff_manifest_digest"],
            quarantine_state=quarantine_state,
        )
        if os.path.lexists(quarantine_state):
            raise GitHubGatewayError("broker quarantine is no longer a fresh path")
        os.rename(staging, quarantine_state)
        try:
            _fsync_directory(quarantine_state.parent)
        except OSError:
            _remove_broker_staging(quarantine_state)
            raise
        published = True
        return receipt
    except OSError as exc:
        raise GitHubGatewayError(f"cannot publish broker quarantine: {exc}") from exc
    finally:
        if not published:
            _remove_broker_staging(staging)


def _freeze_request(request: object) -> dict[str, str]:
    try:
        frozen = json.loads(canonical_json(request))
    except (RuntimeError, TypeError, ValueError) as exc:
        raise GitHubGatewayError(f"gateway request is invalid: {exc}") from exc
    _validate_request(frozen)
    return frozen


def _validate_request(request: object) -> None:
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS:
        raise GitHubGatewayError("gateway request has missing or unknown fields")
    if request.get("schema") != REQUEST_SCHEMA:
        raise GitHubGatewayError("gateway request schema is unsupported")
    owner = request.get("owner")
    repository = request.get("repository")
    commit = request.get("commit")
    skill_path = request.get("skill_path")
    if (
        not isinstance(owner, str)
        or owner != owner.lower()
        or _OWNER.fullmatch(owner) is None
        or owner.endswith("-")
    ):
        raise GitHubGatewayError("gateway owner is not canonical")
    if (
        not isinstance(repository, str)
        or repository != repository.lower()
        or _REPOSITORY.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
    ):
        raise GitHubGatewayError("gateway repository is not canonical")
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise GitHubGatewayError("gateway commit is not an exact lowercase SHA-1")
    try:
        parts = _parse_skill_path(skill_path)
    except ValueError as exc:
        raise GitHubGatewayError(f"gateway skill path is not canonical: {exc}") from exc
    normalized_path = "." if not parts else "/".join(parts)
    if skill_path != normalized_path:
        raise GitHubGatewayError("gateway skill path is not canonical")


def _validate_result(result: object) -> None:
    if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
        raise GitHubGatewayError("gateway result has missing or unknown fields")
    if result.get("schema") != RESULT_SCHEMA:
        raise GitHubGatewayError("gateway result schema is unsupported")
    for field in (
        "request_digest",
        "manifest_digest",
        "handoff_manifest_digest",
    ):
        value = result.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise GitHubGatewayError(f"gateway result {field} is invalid")


def _decode_request_line(raw: bytes) -> dict[str, str]:
    document = _decode_canonical_line(raw, "gateway request")
    _validate_request(document)
    return document


def _decode_result_line(raw: bytes) -> dict[str, str]:
    document = _decode_canonical_line(raw, "gateway result")
    _validate_result(document)
    return document


def _decode_canonical_line(raw: bytes, label: str) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or not raw.endswith(b"\n")
        or len(raw) > _MAX_WIRE_BYTES
    ):
        raise GitHubGatewayError(f"{label} must be one bounded canonical JSON line")
    content = raw[:-1]
    try:
        document = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GitHubGatewayError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != content:
        raise GitHubGatewayError(f"{label} must use canonical JSON")
    return document


def _source_closure(
    cas: CAS,
    manifest_digest: str,
    manifest: dict[str, Any],
) -> dict[str, int]:
    raw_manifest = cas.read(manifest_digest, max_bytes=_MAX_MANIFEST_BYTES)
    if canonical_json(manifest) != raw_manifest:
        raise GitHubGatewayError("verified GitHub manifest bytes are not canonical")
    closure = {manifest_digest: len(raw_manifest)}
    for entry in manifest["files"]:
        previous = closure.setdefault(entry["digest"], entry["size"])
        if previous != entry["size"]:
            raise GitHubGatewayError(
                "source closure repeats a digest with another size"
            )
    return closure


def _require_requested_source(
    manifest: dict[str, Any],
    request: dict[str, str],
) -> None:
    source = manifest.get("source")
    expected = {
        "owner": request["owner"],
        "repository": request["repository"],
        "commit": request["commit"],
        "skill_path": request["skill_path"],
    }
    if not isinstance(source, dict) or any(
        source.get(field) != value for field, value in expected.items()
    ):
        raise GitHubGatewayError("GitHub manifest source does not match the request")


def _require_success_result(process: _ProcessResult) -> dict[str, str]:
    if process.termination_failed:
        raise GitHubGatewayError("gateway did not terminate after forced shutdown")
    if process.output_exceeded:
        raise GitHubGatewayError("gateway exceeded its output byte limit")
    if process.timed_out:
        raise GitHubGatewayError(
            "gateway exceeded its process-group wall-clock deadline"
        )
    if process.io_error is not None:
        raise GitHubGatewayError(f"gateway I/O failed: {process.io_error}")
    if process.returncode != 0:
        raise GitHubGatewayError(
            f"gateway exited unsuccessfully with status {process.returncode}"
        )
    if process.stderr:
        raise GitHubGatewayError("successful gateway wrote to standard error")
    return _decode_result_line(process.stdout)


def _require_distinct_principal(worker_uid: int, worker_gid: int) -> None:
    if os.name != "posix" or _broker_euid() != 0:
        raise GitHubGatewayError(
            "gateway supervisor requires a privileged POSIX broker"
        )
    for label, value in (("worker_uid", worker_uid), ("worker_gid", worker_gid)):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value < 2**31
        ):
            raise GitHubGatewayError(f"{label} must identify a non-root principal")
    if worker_uid == _broker_euid():
        raise GitHubGatewayError("gateway worker UID must differ from the broker")


def _prepare_paths(
    gateway_root: str | os.PathLike[str],
    quarantine_state: str | os.PathLike[str],
    *,
    worker_uid: int,
) -> tuple[Path, Path]:
    gateway = _require_private_directory(
        gateway_root,
        expected_uid=worker_uid,
        label="gateway root",
    )
    quarantine = _fresh_private_path(
        quarantine_state,
        expected_uid=_broker_euid(),
        label="broker quarantine",
    )
    if _paths_overlap(gateway, quarantine):
        raise GitHubGatewayError("gateway root and broker quarantine must not overlap")
    return gateway, quarantine


def _require_private_directory(
    value: str | os.PathLike[str],
    *,
    expected_uid: int,
    label: str,
) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GitHubGatewayError(f"invalid {label}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise GitHubGatewayError(
            f"{label} must be a private real directory owned by UID {expected_uid}"
        )
    return path


def _fresh_private_path(
    value: str | os.PathLike[str],
    *,
    expected_uid: int,
    label: str,
) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        if not supplied.name or supplied == Path(supplied.anchor):
            raise GitHubGatewayError(f"{label} must not be a filesystem root")
        parent = supplied.parent.resolve(strict=True)
        path = parent / supplied.name
        metadata = os.lstat(parent)
    except GitHubGatewayError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GitHubGatewayError(f"invalid {label}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise GitHubGatewayError(
            f"{label} parent must be a private real directory "
            f"owned by UID {expected_uid}"
        )
    if os.path.lexists(path):
        raise GitHubGatewayError(f"{label} must be a fresh path")
    return path


def _create_job_root(value: str | os.PathLike[str]) -> Path:
    path = _fresh_private_path(
        value,
        expected_uid=os.geteuid(),
        label="gateway job",
    )
    try:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        raise GitHubGatewayError(f"cannot create gateway job: {exc}") from exc
    return _require_private_directory(
        path,
        expected_uid=os.geteuid(),
        label="gateway job",
    )


def _trusted_python_executable(value: str | os.PathLike[str]) -> Path:
    try:
        supplied = Path(os.fspath(value))
        if not supplied.is_absolute():
            raise GitHubGatewayError("gateway Python executable must be absolute")
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except GitHubGatewayError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GitHubGatewayError(f"invalid gateway Python executable: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != _broker_euid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise GitHubGatewayError(
            "gateway Python executable must be broker-owned, executable, "
            "and not group or other writable"
        )
    _require_protected_ancestors(path)
    return path


def _trusted_package_root(value: str | os.PathLike[str]) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        root = supplied.resolve(strict=True)
        root_metadata = os.lstat(root)
        names = sorted(entry.name for entry in os.scandir(root))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise GitHubGatewayError(f"invalid gateway package root: {exc}") from exc
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != _broker_euid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
        or names != ["aragorn"]
    ):
        raise GitHubGatewayError(
            "gateway package root must contain only a broker-owned, "
            "non-writable aragorn package"
        )
    _require_protected_ancestors(root)

    pending = [root / "aragorn"]
    entries_seen = 0
    required = {"__init__.py", "github_gateway.py"}
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise GitHubGatewayError(
                f"cannot inspect gateway package tree: {exc}"
            ) from exc
        if directory == root / "aragorn" and not required.issubset(
            entry.name for entry in entries
        ):
            raise GitHubGatewayError("gateway package is missing required module files")
        for entry in entries:
            entries_seen += 1
            if entries_seen > _MAX_PACKAGE_ENTRIES:
                raise GitHubGatewayError("gateway package tree is too large")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise GitHubGatewayError(
                    f"cannot inspect gateway package entry: {exc}"
                ) from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != _broker_euid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise GitHubGatewayError(
                    "gateway package contains an unprotected entry"
                )
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(Path(entry.path))
            elif not stat.S_ISREG(metadata.st_mode):
                raise GitHubGatewayError(
                    "gateway package contains a special filesystem entry"
                )
    return root


def _require_protected_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise GitHubGatewayError(
                f"cannot inspect protected path ancestry: {exc}"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != _broker_euid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise GitHubGatewayError(
                "gateway executable and package ancestors must be "
                "broker-owned and not group or other writable"
            )
        if current == Path(current.anchor):
            return
        current = current.parent


def _gateway_command(
    executable: Path,
    package_root: Path,
    *arguments: str,
) -> tuple[str, ...]:
    return (
        os.fspath(executable),
        "-I",
        "-c",
        _ISOLATED_ENTRYPOINT,
        os.fspath(package_root),
        *arguments,
    )


def _remove_worker_job(path: Path, *, expected_uid: int) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        return
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or not shutil.rmtree.avoids_symlink_attacks
    ):
        return
    try:
        shutil.rmtree(path)
    except OSError:
        pass


def _remove_broker_staging(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        return
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != _broker_euid()
        or not shutil.rmtree.avoids_symlink_attacks
    ):
        return
    try:
        shutil.rmtree(path)
    except OSError:
        pass


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _repository_url(request: dict[str, str]) -> str:
    return f"https://github.com/{request['owner']}/{request['repository']}"


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubGatewayError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise GitHubGatewayError(f"non-finite JSON number: {value}")


def _broker_euid() -> int:
    return os.geteuid()


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GitHubGatewayError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python -m aragorn.github_gateway",
        description="Internal credential-free GitHub acquisition worker.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    worker = commands.add_parser("worker")
    worker.add_argument("--job-root", type=Path, required=True)
    worker.set_defaults(action=_worker_command)
    return parser


def _worker_command(args: argparse.Namespace) -> dict[str, str]:
    request = _decode_request_line(sys.stdin.buffer.read(_MAX_WIRE_BYTES + 1))
    return run_worker(request, args.job_root)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = arguments.action(arguments)
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (CASError, HandoffError, OSError, RuntimeError, ValueError) as exc:
        error = {
            "schema": "aragorn/error/v1",
            "error": type(exc).__name__,
            "message": str(exc),
        }
        sys.stderr.buffer.write(canonical_json(error) + b"\n")
        sys.stderr.buffer.flush()
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
