"""Privilege-separated, credential-free GitHub acquisition gateway."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import resource
import secrets
import shutil
import socket
import stat
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
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
    _resolve_public_api_addresses,
    _validate_pinned_addresses,
    acquire_github_commit,
)
from .oci_runtime import (
    VerificationError,
    _hash_regular_file,
    _ProcessResult,
    _run_bounded,
)

REQUEST_SCHEMA = "aragorn/github-gateway-request/v1"
RESULT_SCHEMA = "aragorn/github-gateway-result/v1"
ADDRESS_RESULT_SCHEMA = "aragorn/github-gateway-address-result/v1"
QUARANTINE_AUTHORITY = "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
SOURCE_ASSURANCE = "github_api_membership_asserted_blob_identity_reverified"
_REQUEST_KEYS = {"schema", "owner", "repository", "commit", "skill_path"}
_RESULT_KEYS = {
    "schema",
    "request_digest",
    "manifest_digest",
    "handoff_manifest_digest",
}
_ADDRESS_RESULT_KEYS = {"schema", "addresses"}
_MAX_WIRE_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_GATEWAY_SECONDS = 180.0
_MAX_RESOLUTION_SECONDS = 10.0
_MAX_PACKAGE_ENTRIES = 1_000
_MAX_PROCESS_CENSUS_BYTES = 1024 * 1024
_MAX_PROCESS_CENSUS_EXECUTABLE_BYTES = 4 * 1024 * 1024
_MAX_SYSTEMD_EXECUTABLE_BYTES = 4 * 1024 * 1024
_MAX_MOUNTINFO_BYTES = 1024 * 1024
_SYSTEMD_CLEANUP_SECONDS = 10.0
_GATEWAY_TRANSFER_BYTES = 512 * 1024 * 1024
_GATEWAY_TRANSFER_INODES = 20_000
_DEFAULT_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_PROCESS_CENSUS_PATH = Path("/bin/ps")
_SYSTEMD_RUN_PATH = Path("/usr/bin/systemd-run")
_SYSTEMCTL_PATH = Path("/usr/bin/systemctl")
_SYSTEMD_CGROUP_ROOT = Path("/sys/fs/cgroup/system.slice")
_UID_LEASE_ROOT = Path("/var/run/aragorn-gateway")
_ISOLATED_ENTRYPOINT = """\
import errno
import os
import resource
import socket
import sys

expected_uid = int(sys.argv.pop(1))
expected_gid = int(sys.argv.pop(1))
identity = (
    os.getuid(),
    os.geteuid(),
    os.getgid(),
    os.getegid(),
)
groups = os.getgroups()
base_environment = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "TZ",
}
systemd_environment = base_environment | {
    "ARAGORN_DENIED_PROBE",
    "INVOCATION_ID",
    "SYSTEMD_EXEC_PID",
}
darwin_environment = base_environment | {"__CF_USER_TEXT_ENCODING"}
environment_keys = set(os.environ)
if (
    not sys.flags.isolated
    or not sys.flags.no_site
    or identity != (expected_uid, expected_uid, expected_gid, expected_gid)
    or (sys.platform == "linux" and environment_keys != systemd_environment)
    or (
        sys.platform == "darwin"
        and environment_keys not in (base_environment, darwin_environment)
    )
    or sys.platform not in {"darwin", "linux"}
):
    raise SystemExit(70)
if environment_keys == darwin_environment:
    encoding = os.environ["__CF_USER_TEXT_ENCODING"].split(":")
    if (
        sys.platform != "darwin"
        or len(encoding) != 3
        or any(
            len(item) <= 2
            or not item.startswith("0x")
            or any(character not in "0123456789abcdefABCDEF" for character in item[2:])
            for item in encoding
        )
    ):
        raise SystemExit(70)
if environment_keys == systemd_environment:
    invocation_id = os.environ["INVOCATION_ID"]
    systemd_pid = os.environ["SYSTEMD_EXEC_PID"]
    probe_port = os.environ["ARAGORN_DENIED_PROBE"]
    if (
        sys.platform != "linux"
        or len(invocation_id) != 32
        or any(character not in "0123456789abcdef" for character in invocation_id)
        or not systemd_pid.isdigit()
        or int(systemd_pid) != os.getpid()
        or not probe_port.isdigit()
        or not 0 < int(probe_port) <= 65535
        or len(groups) > 1
        or any(group != expected_gid for group in groups)
    ):
        raise SystemExit(70)
    process_status = {}
    with open("/proc/self/status", encoding="ascii") as source:
        for line in source:
            key, separator, value = line.partition(":")
            if separator and key in {
                "NoNewPrivs",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
            }:
                process_status[key] = value.strip()
    if process_status != {
        "NoNewPrivs": "1",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
    }:
        raise SystemExit(70)
    with open("/proc/self/cgroup", encoding="ascii") as source:
        cgroup_entry = source.read(4097)
    if (
        len(cgroup_entry) > 4096
        or not cgroup_entry.endswith("\\n")
        or not cgroup_entry.startswith("0::/system.slice/aragorn-gateway-")
        or not cgroup_entry.endswith(".service\\n")
    ):
        raise SystemExit(70)
    cgroup_root = "/sys/fs/cgroup" + cgroup_entry[3:-1]
    with open(cgroup_root + "/pids.max", encoding="ascii") as source:
        pids_max = source.read(17).strip()
    with open(cgroup_root + "/pids.current", encoding="ascii") as source:
        pids_current = source.read(17).strip()
    with open(cgroup_root + "/cgroup.procs", encoding="ascii") as source:
        cgroup_procs = source.read(65).split()
    with open(cgroup_root + "/cgroup.threads", encoding="ascii") as source:
        cgroup_threads = source.read(65).split()
    with open(cgroup_root + "/cgroup.subtree_control", encoding="ascii") as source:
        subtree_control = source.read(65).split()
    if (
        pids_max != "1"
        or pids_current != "1"
        or cgroup_procs != [str(os.getpid())]
        or cgroup_threads != [str(os.getpid())]
        or subtree_control
        or any(entry.is_dir(follow_symlinks=False) for entry in os.scandir(cgroup_root))
    ):
        raise SystemExit(70)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(("127.0.0.1", int(probe_port)))
    except TimeoutError:
        pass
    except OSError:
        raise SystemExit(70)
    else:
        raise SystemExit(70)
    finally:
        probe.close()
resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
try:
    child = os.fork()
except OSError as exc:
    if exc.errno != errno.EAGAIN:
        raise
else:
    if child == 0:
        os._exit(70)
    os.waitpid(child, 0)
    raise SystemExit(70)
sys.path.insert(0, sys.argv.pop(1))
from aragorn.github_gateway import main
raise SystemExit(main())
"""
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
    *,
    pinned_addresses: list[str] | tuple[str, ...],
) -> dict[str, str]:
    """Acquire one exact public source and export its declared byte closure."""

    frozen = _freeze_request(request)
    request_digest = _digest(canonical_json(frozen))
    root = _create_job_root(job_root)
    source_cas = CAS(root / "state")
    acquisition_options: dict[str, object] = {
        **_FIXED_LIMITS,
        "bearer_token": None,
        "_pinned_addresses": pinned_addresses,
    }
    manifest = acquire_github_commit(
        _repository_url(frozen),
        frozen["commit"],
        frozen["skill_path"],
        source_cas,
        **acquisition_options,
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
    environment = {
        "HOME": os.fspath(gateway),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    with _exclusive_uid_lease(_UID_LEASE_ROOT, worker_uid):
        try:
            _require_idle_uid(worker_uid, "before launch")
            _require_gateway_entries(
                gateway,
                (),
                worker_uid=worker_uid,
                stage="before launch",
            )
            try:
                resolver = _run_gateway_process(
                    _gateway_command(
                        executable,
                        protected_package,
                        worker_uid,
                        worker_gid,
                        "resolve",
                    ),
                    timeout=min(
                        float(process_timeout_seconds),
                        _MAX_RESOLUTION_SECONDS,
                    ),
                    environment=environment,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    allowed_addresses=("127.0.0.53",),
                    writable_root=gateway,
                    postflight_stage="after resolver shutdown",
                )
                _require_gateway_entries(
                    gateway,
                    (),
                    worker_uid=worker_uid,
                    stage="after resolver shutdown",
                )
                pinned_addresses = _require_address_result(resolver)
                command = _gateway_command(
                    executable,
                    protected_package,
                    worker_uid,
                    worker_gid,
                    "worker",
                    "--job-root",
                    os.fspath(job_root),
                    *(
                        item
                        for address in pinned_addresses
                        for item in ("--endpoint", address)
                    ),
                )
                process = _run_gateway_process(
                    command,
                    timeout=float(process_timeout_seconds),
                    environment=environment,
                    worker_uid=worker_uid,
                    worker_gid=worker_gid,
                    allowed_addresses=pinned_addresses,
                    writable_root=gateway,
                    postflight_stage="after worker shutdown",
                    stdin_bytes=raw_request + b"\n",
                )
                _require_gateway_entries(
                    gateway,
                    (job_root.name,),
                    worker_uid=worker_uid,
                    stage="after worker shutdown",
                )
            except GitHubGatewayError:
                raise
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
        _remove_worker_job(job_root, expected_uid=worker_uid)
        _require_gateway_entries(
            job_root.parent,
            (),
            worker_uid=worker_uid,
            stage="before quarantine publication",
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


def _decode_address_result_line(raw: bytes) -> tuple[str, ...]:
    document = _decode_canonical_line(raw, "gateway address result")
    if (
        set(document) != _ADDRESS_RESULT_KEYS
        or document.get("schema") != ADDRESS_RESULT_SCHEMA
        or not isinstance(document.get("addresses"), list)
    ):
        raise GitHubGatewayError("gateway address result is invalid")
    addresses = document["addresses"]
    try:
        canonical = tuple(
            endpoint[3][0] for endpoint in _validate_pinned_addresses(addresses)
        )
    except ValueError as exc:
        raise GitHubGatewayError(f"gateway address result is invalid: {exc}") from exc
    if tuple(addresses) != canonical:
        raise GitHubGatewayError("gateway address result is not canonical")
    return canonical


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
    return _decode_result_line(_require_success_output(process))


def _require_address_result(process: _ProcessResult) -> tuple[str, ...]:
    return _decode_address_result_line(_require_success_output(process))


def _require_success_output(process: _ProcessResult) -> bytes:
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
    return process.stdout


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


@contextmanager
def _exclusive_uid_lease(control_root: Path, worker_uid: int) -> Iterator[None]:
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - non-POSIX import guard
        raise GitHubGatewayError("gateway UID locking is unsupported") from exc

    root = _require_private_directory(
        control_root,
        expected_uid=_broker_euid(),
        label="gateway control root",
    )
    root_fd = -1
    lock_fd = -1
    try:
        try:
            root_fd = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            opened_root = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or opened_root.st_uid != _broker_euid()
                or stat.S_IMODE(opened_root.st_mode) & 0o077
            ):
                raise GitHubGatewayError("gateway control root changed while opened")
            lock_fd = os.open(
                f".uid-{worker_uid}.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
            lock = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock.st_mode)
                or lock.st_uid != _broker_euid()
                or stat.S_IMODE(lock.st_mode) != 0o600
                or lock.st_nlink != 1
            ):
                raise GitHubGatewayError("gateway UID lock is not a protected file")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise GitHubGatewayError(
                    f"gateway worker UID {worker_uid} is already leased"
                ) from exc
        except GitHubGatewayError:
            raise
        except OSError as exc:
            raise GitHubGatewayError(f"cannot lock gateway worker UID: {exc}") from exc
        yield
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _require_idle_uid(worker_uid: int, stage: str) -> None:
    peers = _uid_processes(worker_uid)
    if peers:
        raise GitHubGatewayError(
            f"gateway worker UID {worker_uid} has peer processes "
            f"{stage}: {','.join(map(str, peers))}"
        )


def _run_gateway_process(
    command: Sequence[str],
    *,
    timeout: float,
    environment: dict[str, str],
    worker_uid: int,
    worker_gid: int,
    allowed_addresses: Sequence[str],
    writable_root: Path,
    postflight_stage: str,
    stdin_bytes: bytes | None = None,
) -> _ProcessResult:
    try:
        if sys.platform == "linux":
            return _run_systemd_gateway_process(
                command,
                timeout=timeout,
                environment=environment,
                worker_uid=worker_uid,
                worker_gid=worker_gid,
                allowed_addresses=allowed_addresses,
                writable_root=writable_root,
                stdin_bytes=stdin_bytes,
            )
        if sys.platform != "darwin":
            raise GitHubGatewayError(
                "gateway process containment is unsupported on this platform"
            )
        return _run_bounded(
            command,
            timeout=timeout,
            stdout_limit=_MAX_WIRE_BYTES,
            stderr_limit=_MAX_WIRE_BYTES,
            shared_limit=2 * _MAX_WIRE_BYTES,
            env=environment,
            stdin_bytes=stdin_bytes,
            cwd=os.path.sep,
            user=worker_uid,
            group=worker_gid,
            extra_groups=(),
            umask=0o077,
        )
    finally:
        _require_idle_uid(worker_uid, postflight_stage)


def _run_systemd_gateway_process(
    command: Sequence[str],
    *,
    timeout: float,
    environment: dict[str, str],
    worker_uid: int,
    worker_gid: int,
    allowed_addresses: Sequence[str],
    writable_root: Path,
    stdin_bytes: bytes | None,
) -> _ProcessResult:
    _require_systemd_host()
    systemd_run, run_identity = _trusted_root_executable(
        _SYSTEMD_RUN_PATH,
        _MAX_SYSTEMD_EXECUTABLE_BYTES,
        "systemd-run",
    )
    systemctl, control_identity = _trusted_root_executable(
        _SYSTEMCTL_PATH,
        _MAX_SYSTEMD_EXECUTABLE_BYTES,
        "systemctl",
    )
    addresses = _systemd_allowed_addresses(allowed_addresses)
    writable = _systemd_writable_root(writable_root)
    unit = f"aragorn-gateway-{secrets.token_hex(12)}.service"
    runtime = f"{timeout:.6f}s"
    properties = (
        "AmbientCapabilities=",
        "CapabilityBoundingSet=",
        "Delegate=no",
        "IPAddressDeny=any",
        "KeyringMode=private",
        "KillMode=control-group",
        "LimitNOFILE=64",
        "LockPersonality=yes",
        "MemoryDenyWriteExecute=yes",
        "MemoryMax=512M",
        "MemorySwapMax=0",
        "NoNewPrivileges=yes",
        "PrivateDevices=yes",
        "PrivateTmp=yes",
        "InaccessiblePaths=/tmp /var/tmp",
        "ProcSubset=pid",
        "ProtectClock=yes",
        "ProtectControlGroups=yes",
        "ProtectHome=yes",
        "ProtectHostname=yes",
        "ProtectKernelLogs=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelTunables=yes",
        "ProtectProc=invisible",
        "ProtectSystem=strict",
        "RemoveIPC=yes",
        "Restart=no",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        f"RuntimeMaxSec={runtime}",
        "SendSIGKILL=yes",
        "SocketBindDeny=any",
        "SystemCallArchitectures=native",
        "SystemCallErrorNumber=EPERM",
        "SystemCallFilter=@system-service",
        "TasksMax=1",
        "TimeoutStopSec=5s",
        "UMask=0077",
        "UnsetEnvironment=LOGNAME USER SHELL MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE",
        f"ReadWritePaths={writable}",
        *(f"IPAddressAllow={address}" for address in addresses),
    )
    with _denied_network_listener() as probe_port:
        service_environment = {
            **environment,
            "ARAGORN_DENIED_PROBE": str(probe_port),
        }
        argv = (
            os.fspath(systemd_run),
            "--system",
            "--no-ask-password",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            f"--unit={unit}",
            f"--uid={worker_uid}",
            f"--gid={worker_gid}",
            "--working-directory=/",
            "--expand-environment=no",
            *(
                f"--setenv={key}={value}"
                for key, value in sorted(service_environment.items())
            ),
            *(f"--property={value}" for value in properties),
            "--",
            *command,
        )
        try:
            return _run_bounded(
                argv,
                timeout=timeout + _SYSTEMD_CLEANUP_SECONDS,
                stdout_limit=_MAX_WIRE_BYTES,
                stderr_limit=_MAX_WIRE_BYTES,
                shared_limit=2 * _MAX_WIRE_BYTES,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
                stdin_bytes=stdin_bytes,
                cwd=os.path.sep,
            )
        finally:
            _stop_systemd_unit(systemctl, unit)
            _reverify_root_executable(systemd_run, run_identity, "systemd-run")
            _reverify_root_executable(systemctl, control_identity, "systemctl")


@contextmanager
def _denied_network_listener() -> Iterator[int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        yield listener.getsockname()[1]
        listener.setblocking(False)
        try:
            connection, _address = listener.accept()
        except BlockingIOError:
            pass
        else:
            connection.close()
            raise GitHubGatewayError(
                "systemd gateway network-denial probe was reachable"
            )
    except GitHubGatewayError:
        raise
    except OSError as exc:
        raise GitHubGatewayError(
            f"cannot verify systemd gateway network denial: {exc}"
        ) from exc
    finally:
        listener.close()


def _systemd_allowed_addresses(value: Sequence[str]) -> tuple[str, ...]:
    addresses = tuple(value)
    if addresses == ("127.0.0.53",):
        return addresses
    try:
        canonical = tuple(
            endpoint[3][0] for endpoint in _validate_pinned_addresses(addresses)
        )
    except ValueError as exc:
        raise GitHubGatewayError(f"invalid systemd network boundary: {exc}") from exc
    if canonical != addresses:
        raise GitHubGatewayError("systemd network boundary is not canonical")
    return canonical


def _systemd_writable_root(value: Path) -> str:
    text = os.fspath(value)
    try:
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GitHubGatewayError(f"invalid systemd writable root: {exc}") from exc
    if (
        not value.is_absolute()
        or resolved != value
        or any(character.isspace() or character in "\0:\\" for character in text)
    ):
        raise GitHubGatewayError("systemd writable root is not canonical")
    _require_bounded_transfer_mount(value)
    return text


def _require_bounded_transfer_mount(path: Path) -> None:
    raw = _read_virtual_file(
        Path("/proc/self/mountinfo"),
        _MAX_MOUNTINFO_BYTES,
        "gateway mount table",
    )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitHubGatewayError("gateway mount table is not ASCII") from exc
    matches: list[tuple[set[str], str]] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if (
            separator >= 6
            and len(fields) >= separator + 4
            and fields[4] == os.fspath(path)
        ):
            matches.append((set(fields[5].split(",")), fields[separator + 1]))
    required_options = {"rw", "nosuid", "nodev", "noexec"}
    if (
        len(matches) != 1
        or matches[0][1] != "tmpfs"
        or not required_options.issubset(matches[0][0])
    ):
        raise GitHubGatewayError(
            "gateway root must be one rw,nosuid,nodev,noexec tmpfs mount"
        )
    try:
        filesystem = os.statvfs(path)
    except OSError as exc:
        raise GitHubGatewayError(f"cannot inspect gateway tmpfs limits: {exc}") from exc
    total_bytes = filesystem.f_frsize * filesystem.f_blocks
    if (
        not 0 < total_bytes <= _GATEWAY_TRANSFER_BYTES
        or not 0 < filesystem.f_files <= _GATEWAY_TRANSFER_INODES
    ):
        raise GitHubGatewayError("gateway tmpfs limits exceed the fixed boundary")


def _require_systemd_host() -> None:
    if _read_virtual_file(Path("/proc/1/comm"), 32, "PID 1 command") != b"systemd\n":
        raise GitHubGatewayError("gateway requires systemd as host PID 1")
    for namespace in ("pid", "mnt", "user", "cgroup"):
        try:
            broker = os.stat(f"/proc/self/ns/{namespace}")
            host = os.stat(f"/proc/1/ns/{namespace}")
        except OSError as exc:
            raise GitHubGatewayError(
                f"cannot verify host {namespace} namespace: {exc}"
            ) from exc
        if (broker.st_dev, broker.st_ino) != (host.st_dev, host.st_ino):
            raise GitHubGatewayError(
                f"gateway broker is outside the host {namespace} namespace"
            )
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise GitHubGatewayError("gateway requires a mounted cgroup v2 hierarchy")
    cgroup = _read_virtual_file(
        Path("/proc/self/cgroup"),
        4096,
        "broker cgroup membership",
    )
    if not cgroup.startswith(b"0::/") or cgroup.count(b"\n") != 1:
        raise GitHubGatewayError("gateway broker cgroup membership is invalid")


def _stop_systemd_unit(systemctl: Path, unit: str) -> None:
    environment = {"LANG": "C", "LC_ALL": "C", "PATH": os.defpath}
    stop = _run_bounded(
        (
            os.fspath(systemctl),
            "--system",
            "--no-ask-password",
            "--no-pager",
            "stop",
            unit,
        ),
        timeout=_SYSTEMD_CLEANUP_SECONDS,
        stdout_limit=4 * 1024,
        stderr_limit=4 * 1024,
        shared_limit=8 * 1024,
        env=environment,
        cwd=os.path.sep,
    )
    if (
        stop.timed_out
        or stop.output_exceeded
        or stop.termination_failed
        or stop.io_error is not None
        or stop.returncode not in {0, 5}
    ):
        raise GitHubGatewayError("cannot stop the systemd gateway unit")
    show = _run_bounded(
        (
            os.fspath(systemctl),
            "--system",
            "--no-ask-password",
            "--no-pager",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Job",
        ),
        timeout=_SYSTEMD_CLEANUP_SECONDS,
        stdout_limit=4 * 1024,
        stderr_limit=4 * 1024,
        shared_limit=8 * 1024,
        env=environment,
        cwd=os.path.sep,
    )
    if (
        show.timed_out
        or show.output_exceeded
        or show.termination_failed
        or show.io_error is not None
        or show.returncode != 0
        or show.stderr
    ):
        raise GitHubGatewayError("cannot verify the stopped systemd gateway unit")
    state: dict[str, str] = {}
    try:
        lines = show.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitHubGatewayError("systemd gateway unit state is not ASCII") from exc
    for line in lines:
        key, separator, value = line.partition("=")
        if (
            not separator
            or key not in {"LoadState", "ActiveState", "SubState", "Job"}
            or key in state
        ):
            raise GitHubGatewayError("systemd gateway unit state is invalid")
        state[key] = value
    if (
        set(state) != {"LoadState", "ActiveState", "SubState", "Job"}
        or state["LoadState"] not in {"loaded", "not-found"}
        or state["ActiveState"] != "inactive"
        or state["SubState"] != "dead"
        or state["Job"]
    ):
        raise GitHubGatewayError("systemd gateway unit did not stop completely")
    cgroup = _SYSTEMD_CGROUP_ROOT / unit
    try:
        metadata = os.lstat(cgroup)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GitHubGatewayError(
            f"cannot inspect stopped systemd gateway cgroup: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise GitHubGatewayError("systemd gateway cgroup is not a directory")
    procs = _read_virtual_file(
        cgroup / "cgroup.procs",
        4096,
        "stopped gateway cgroup processes",
    )
    events = _read_virtual_file(
        cgroup / "cgroup.events",
        4096,
        "stopped gateway cgroup events",
    )
    if procs.strip() or b"populated 0\n" not in events:
        raise GitHubGatewayError("systemd gateway cgroup remains populated")
    try:
        if any(entry.is_dir(follow_symlinks=False) for entry in os.scandir(cgroup)):
            raise GitHubGatewayError("systemd gateway cgroup retains a child cgroup")
    except OSError as exc:
        raise GitHubGatewayError(
            f"cannot inspect stopped systemd gateway cgroup: {exc}"
        ) from exc


def _trusted_root_executable(
    configured: Path,
    maximum: int,
    label: str,
) -> tuple[Path, tuple[str, tuple[int, int, int, int]]]:
    try:
        path = configured.resolve(strict=True)
        metadata = os.lstat(path)
        digest, identity, _mode = _hash_regular_file(path, maximum, label)
    except (OSError, RuntimeError, VerificationError) as exc:
        raise GitHubGatewayError(f"invalid {label} executable: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != _broker_euid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise GitHubGatewayError(f"{label} executable is not protected")
    _require_protected_ancestors(path)
    return path, (digest, identity)


def _reverify_root_executable(
    path: Path,
    expected: tuple[str, tuple[int, int, int, int]],
    label: str,
) -> None:
    try:
        observed = _hash_regular_file(path, _MAX_SYSTEMD_EXECUTABLE_BYTES, label)
    except (OSError, VerificationError) as exc:
        raise GitHubGatewayError(f"cannot reverify {label}: {exc}") from exc
    if observed[:2] != expected:
        raise GitHubGatewayError(f"{label} executable changed during use")


def _read_virtual_file(path: Path, maximum: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GitHubGatewayError(f"{label} is not a regular file")
        raw = os.read(descriptor, maximum + 1)
    except GitHubGatewayError:
        raise
    except OSError as exc:
        raise GitHubGatewayError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > maximum:
        raise GitHubGatewayError(f"{label} exceeds its byte limit")
    return raw


def _uid_processes(worker_uid: int) -> tuple[int, ...]:
    executable, expected = _trusted_process_census_executable()
    process = _run_bounded(
        (os.fspath(executable), "-A", "-o", "pid=", "-o", "ruid="),
        timeout=2.0,
        stdout_limit=_MAX_PROCESS_CENSUS_BYTES,
        stderr_limit=4 * 1024,
        shared_limit=_MAX_PROCESS_CENSUS_BYTES + 4 * 1024,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
        cwd=os.path.sep,
    )
    if (
        process.timed_out
        or process.output_exceeded
        or process.termination_failed
        or process.io_error is not None
        or process.returncode != 0
        or process.stderr
    ):
        raise GitHubGatewayError("gateway worker UID census failed closed")
    try:
        observed = _hash_regular_file(
            executable,
            _MAX_PROCESS_CENSUS_EXECUTABLE_BYTES,
            "process census executable",
        )
    except (OSError, VerificationError) as exc:
        raise GitHubGatewayError(
            f"cannot reverify process census executable: {exc}"
        ) from exc
    if observed[:2] != expected:
        raise GitHubGatewayError("process census executable changed during use")
    return _parse_uid_census(process.stdout, worker_uid)


def _trusted_process_census_executable() -> tuple[
    Path, tuple[str, tuple[int, int, int, int]]
]:
    return _trusted_root_executable(
        _PROCESS_CENSUS_PATH,
        _MAX_PROCESS_CENSUS_EXECUTABLE_BYTES,
        "process census",
    )


def _parse_uid_census(raw: bytes, worker_uid: int) -> tuple[int, ...]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitHubGatewayError("process census is not ASCII") from exc
    if not lines or len(lines) > 65_536:
        raise GitHubGatewayError("process census row count is invalid")
    seen: set[int] = set()
    matches: list[int] = []
    for line in lines:
        fields = line.split()
        uid_text = fields[1] if len(fields) == 2 else ""
        if (
            len(fields) != 2
            or not fields[0].isdigit()
            or not (uid_text.isdigit() or uid_text in {"-1", "-2"})
            or int(fields[0]) <= 0
            or int(fields[1]) >= 2**31
        ):
            raise GitHubGatewayError("process census row is invalid")
        pid, uid = map(int, fields)
        if pid in seen:
            raise GitHubGatewayError("process census repeats a PID")
        seen.add(pid)
        if uid == worker_uid:
            matches.append(pid)
    if 1 not in seen:
        raise GitHubGatewayError("process census does not contain PID 1")
    return tuple(sorted(matches))


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


def _require_gateway_entries(
    root: Path,
    expected: Sequence[str],
    *,
    worker_uid: int,
    stage: str,
) -> None:
    protected = _require_private_directory(
        root,
        expected_uid=worker_uid,
        label="gateway root",
    )
    try:
        names = tuple(sorted(entry.name for entry in os.scandir(protected)))
    except OSError as exc:
        raise GitHubGatewayError(f"cannot inspect gateway root {stage}: {exc}") from exc
    if names != tuple(sorted(expected)):
        raise GitHubGatewayError(f"gateway root contains unexpected entries {stage}")


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
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise GitHubGatewayError(
            "gateway Python executable must be broker-owned, executable, "
            "free of privilege bits, and not group or other writable"
        )
    _require_protected_ancestors(path)
    _reject_file_capabilities(path)
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


def _reject_file_capabilities(path: Path) -> None:
    if sys.platform != "linux":
        return
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise GitHubGatewayError(
            "cannot verify gateway Python file capabilities on this platform"
        )
    try:
        capabilities = getxattr(
            path,
            "security.capability",
            follow_symlinks=False,
        )
    except OSError as exc:
        absent = {
            errno.ENODATA,
            errno.ENOTSUP,
            getattr(errno, "ENOATTR", errno.ENODATA),
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if exc.errno in absent:
            return
        raise GitHubGatewayError(
            f"cannot verify gateway Python file capabilities: {exc}"
        ) from exc
    if capabilities:
        raise GitHubGatewayError(
            "gateway Python executable must not carry file capabilities"
        )


def _gateway_command(
    executable: Path,
    package_root: Path,
    expected_uid: int,
    expected_gid: int,
    *arguments: str,
) -> tuple[str, ...]:
    return (
        os.fspath(executable),
        "-I",
        "-S",
        "-c",
        _ISOLATED_ENTRYPOINT,
        str(expected_uid),
        str(expected_gid),
        os.fspath(package_root),
        *arguments,
    )


def _remove_worker_job(path: Path, *, expected_uid: int) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GitHubGatewayError(f"cannot inspect gateway worker job: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or not shutil.rmtree.avoids_symlink_attacks
    ):
        raise GitHubGatewayError("gateway worker job is not safe to remove")
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise GitHubGatewayError(f"cannot remove gateway worker job: {exc}") from exc


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
    worker.add_argument("--endpoint", action="append", required=True)
    worker.set_defaults(action=_worker_command)
    resolver = commands.add_parser("resolve")
    resolver.set_defaults(action=_resolver_command)
    return parser


def _worker_command(args: argparse.Namespace) -> dict[str, str]:
    _require_worker_process_limit()
    request = _decode_request_line(sys.stdin.buffer.read(_MAX_WIRE_BYTES + 1))
    return run_worker(request, args.job_root, pinned_addresses=args.endpoint)


def _resolver_command(_args: argparse.Namespace) -> dict[str, object]:
    _require_worker_process_limit()
    return {
        "schema": ADDRESS_RESULT_SCHEMA,
        "addresses": list(_resolve_public_api_addresses()),
    }


def _require_worker_process_limit() -> None:
    if resource.getrlimit(resource.RLIMIT_NPROC) != (1, 1):
        raise GitHubGatewayError("gateway worker process limit is not enforced")


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
