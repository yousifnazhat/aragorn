"""Digest-bound OCI baseline verification and execution."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import threading
from dataclasses import dataclass, replace
from typing import Any, BinaryIO, Sequence

from .acquire import InventoryError, inventory_local
from .docker_identity import (
    DOCKER_CONTEXT_TEMPLATE,
    DOCKER_INFO_TEMPLATE,
    DOCKER_VERSION_TEMPLATE,
    DockerIdentityError,
    DockerIdentityReceipt,
    normalize_docker_identity,
    parse_docker_context,
)


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "benchmark" / "baselines.lock.json"
_BLOB_PATH = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARCHIVE_OVERHEAD = 16 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 10_000
_MAX_METADATA_BLOB = 16 * 1024 * 1024
_MAX_INSPECT_BYTES = 1024 * 1024
_MAX_DOCKER_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_OUTPUT_BYTES = 8 * 1024 * 1024
_DOCKER_TIMEOUT_SECONDS = 30.0
_EXPECTED_IDENTITIES = {
    "cisco-skill-scanner": {
        "version": "2.0.12",
        "repository": "https://github.com/cisco-ai-defense/skill-scanner",
        "commit": "605afdc5c7ea887c07e2afeb0fadc1452c07bfa7",
        "release": "2.0.12",
        "local_tag": "aragorn/cisco-skill-scanner:2.0.12",
        "distribution": {
            "kind": "pypi-wheel",
            "package": "cisco-ai-skill-scanner==2.0.12",
            "sha256": "e49f979e97b7842549b1f531dc5f426c9780d798a0b21f0125044e3b5ae4a1f7",
        },
        "profile": {
            "mode": "local-static",
            "network": "deny",
            "arguments": [
                "scan",
                "{workspace}",
                "--use-behavioral",
                "--policy",
                "strict",
                "--format",
                "json",
                "--compact",
            ],
            "environment": {},
            "disabled_features": [
                "aidefense",
                "llm",
                "meta-analysis",
                "virustotal",
            ],
        },
    },
    "skillspector": {
        "version": "2.4.3+git.a54947c",
        "repository": "https://github.com/NVIDIA/SkillSpector",
        "commit": "a54947c307fe19a24a43db55f6148e181a987a67",
        "release": None,
        "local_tag": "aragorn/skillspector:2.4.3-a54947c",
        "distribution": {"kind": "git-source", "package": None, "sha256": None},
        "profile": {
            "mode": "local-static",
            "network": "deny",
            "arguments": ["scan", "{workspace}", "--no-llm", "--format", "json"],
            "environment": {"SKILLSPECTOR_OSV_TIMEOUT": "0.2"},
            "disabled_features": ["llm"],
        },
    },
}
_NORMALIZATIONS = {
    "cisco-skill-scanner": (
        "cisco-ai-skill-scanner-2.0.12/v1",
        "cisco-ai-skill-scanner-2.0.12/v2",
    ),
    "skillspector": (
        "nvidia-skillspector-2.4.3/v1",
        "nvidia-skillspector-2.4.3/v2",
    ),
}
_EXPECTED_RUNTIME = {
    "engine": "docker",
    "pull": "never",
    "network": "none",
    "read_only_rootfs": True,
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "user": "65532:65532",
    "workdir": "/opt/aragorn-control",
    "pids_limit": 256,
    "memory_bytes": 2147483648,
    "memory_swap_bytes": 2147483648,
    "cpus": 2,
    "nofile_soft": 1024,
    "nofile_hard": 1024,
    "tmpfs": {
        "destination": "/tmp",
        "size_bytes": 536870912,
        "options": ["rw", "noexec", "nosuid", "nodev", "mode=1777"],
    },
    "workspace": {"destination": "/workspace", "read_only": True},
}


class VerificationError(ValueError):
    """A local image does not match its closure-candidate lock."""


@dataclass(frozen=True, slots=True)
class DockerExecutable:
    """Resolved Docker CLI identity."""

    path: Path
    digest: str
    identity: tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class ImageVerification:
    """Bounded raw evidence for a verified local OCI image graph."""

    name: str
    image_reference: str
    raw_index_inspect: bytes
    raw_platform_inspect: bytes
    raw_oci_index_json: bytes
    raw_oci_platform_manifest_json: bytes
    raw_build_provenance_manifest_json: bytes
    raw_config_json: bytes
    image_entrypoint: tuple[str, ...]
    image_environment: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OCIExecutionResult:
    """One inspected, executed, and cleaned-up OCI baseline."""

    baseline_name: str
    version: str
    docker_path: str
    docker_digest: str
    image_reference: str
    index_digest: str
    platform_manifest_digest: str
    config_digest: str
    container_id: str
    raw_lock: bytes
    selected_baseline_json: bytes
    effective_config_json: bytes
    raw_index_inspect: bytes
    raw_platform_inspect: bytes
    raw_oci_index_json: bytes
    raw_oci_platform_manifest_json: bytes
    raw_build_provenance_manifest_json: bytes
    raw_config_json: bytes
    raw_prestart_container_inspect: bytes
    raw_postrun_container_inspect: bytes
    raw_stdout: bytes
    raw_stderr: bytes
    returncode: int
    verified_subject_digest: str
    raw_pre_context_inspect: bytes = b""
    raw_pre_daemon_version: bytes = b""
    raw_pre_daemon_info: bytes = b""
    raw_post_context_inspect: bytes = b""
    raw_post_daemon_version: bytes = b""
    raw_post_daemon_info: bytes = b""
    runner_identity_json: bytes = b""


@dataclass(frozen=True, slots=True)
class OCIExecutionError:
    """Fail-closed OCI execution error with all available bounded evidence."""

    error_code: str
    message: str
    baseline_name: str | None = None
    docker_path: str | None = None
    docker_digest: str | None = None
    image_reference: str | None = None
    container_id: str | None = None
    raw_lock: bytes = b""
    selected_baseline_json: bytes = b""
    effective_config_json: bytes = b""
    raw_index_inspect: bytes = b""
    raw_platform_inspect: bytes = b""
    raw_oci_index_json: bytes = b""
    raw_oci_platform_manifest_json: bytes = b""
    raw_build_provenance_manifest_json: bytes = b""
    raw_config_json: bytes = b""
    raw_prestart_container_inspect: bytes = b""
    raw_postrun_container_inspect: bytes = b""
    raw_stdout: bytes = b""
    raw_stderr: bytes = b""
    returncode: int | None = None
    verified_subject_digest: str | None = None
    raw_pre_context_inspect: bytes = b""
    raw_pre_daemon_version: bytes = b""
    raw_pre_daemon_info: bytes = b""
    raw_post_context_inspect: bytes = b""
    raw_post_daemon_version: bytes = b""
    raw_post_daemon_info: bytes = b""
    runner_identity_json: bytes = b""


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    timed_out: bool = False
    output_exceeded: bool = False
    termination_failed: bool = False
    io_error: str | None = None


@dataclass(slots=True)
class _RunnerReceiptBuffer:
    """Raw runner evidence retained even when a later capture step fails."""

    raw_context: bytes = b""
    raw_version: bytes = b""
    raw_info: bytes = b""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(raw: bytes, label: str) -> Any:
    if len(raw) > _MAX_METADATA_BLOB:
        raise VerificationError(f"{label} exceeds 16 MiB")
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                VerificationError(f"non-finite JSON value: {value}")
            ),
        )
        _finite(document)
        return document
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VerificationError(f"invalid {label} JSON: {exc}") from exc


def _finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise VerificationError("non-finite JSON number")
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _read_file_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise VerificationError(f"{label} must be a regular file")
        if opened.st_size > limit:
            raise VerificationError(f"{label} exceeds its byte limit")
        raw = source.read(limit + 1)
        closed = os.fstat(source.fileno())
    if len(raw) > limit:
        raise VerificationError(f"{label} exceeds its byte limit")
    if _file_identity(opened) != _file_identity(closed) or len(raw) != opened.st_size:
        raise VerificationError(f"{label} changed while it was read")
    return raw


def load_baseline_lock(
    path: str | os.PathLike[str] = LOCK,
) -> tuple[bytes, tuple[dict[str, Any], ...]]:
    """Load and strictly validate the only two executable baseline profiles."""

    raw = _read_file_bounded(
        Path(path).expanduser().resolve(strict=True),
        1024 * 1024,
        "baseline lock",
    )
    lock = _load(raw, "baseline lock")
    if not isinstance(lock, dict):
        raise VerificationError("baseline lock must be an object")
    _exact_keys(lock, {"schema", "observed_at", "baselines"}, "baseline lock")
    _expect(lock.get("schema"), "aragorn/baseline-lock/v1", "baseline lock schema")
    if not isinstance(lock.get("observed_at"), str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", lock["observed_at"]
    ) is None:
        raise VerificationError("baseline lock observed_at must be an ISO date")
    baselines = lock.get("baselines")
    if not isinstance(baselines, list) or len(baselines) != 2:
        raise VerificationError("baseline lock must contain exactly two baselines")
    names: list[str] = []
    for index, baseline in enumerate(baselines):
        if not isinstance(baseline, dict):
            raise VerificationError(f"baseline[{index}] must be an object")
        _validate_baseline(baseline, index)
        names.append(baseline["name"])
    if len(set(names)) != len(names):
        raise VerificationError("baseline names must be unique")
    if set(names) != set(_EXPECTED_IDENTITIES):
        raise VerificationError("baseline lock does not contain the two pinned baselines")
    return raw, tuple(baselines)


def _validate_baseline(baseline: dict[str, Any], index: int) -> None:
    label = f"baseline[{index}]"
    _exact_keys(
        baseline,
        {
            "name",
            "version",
            "repository",
            "commit",
            "release",
            "license",
            "distribution",
            "profile",
            "build",
            "image",
            "runtime_profile",
            "attestation_status",
        },
        label,
    )
    name = baseline.get("name")
    if name not in _EXPECTED_IDENTITIES:
        raise VerificationError(f"{label} is not an approved pinned baseline")
    expected = _EXPECTED_IDENTITIES[name]
    for field in ("version", "repository", "commit", "release", "distribution", "profile"):
        _expect(baseline.get(field), expected[field], f"{name} {field}")
    _expect(baseline.get("license"), "Apache-2.0", f"{name} license")
    _expect(
        baseline.get("attestation_status"),
        "oci_closure_candidate_runner_attestation_pending",
        f"{name} attestation status",
    )
    _expect(baseline.get("runtime_profile"), _EXPECTED_RUNTIME, f"{name} runtime profile")

    build = baseline.get("build")
    if not isinstance(build, dict):
        raise VerificationError(f"{name} build must be an object")
    _exact_keys(
        build,
        {
            "dockerfile_sha256",
            "build_input_sha256",
            "dependency_lock_sha256",
            "frontend_digest",
            "python_image_digest",
            "uv_image_digest",
            "artifacts",
        },
        f"{name} build",
    )
    for field in (
        "dockerfile_sha256",
        "build_input_sha256",
        "dependency_lock_sha256",
    ):
        if not isinstance(build[field], str) or re.fullmatch(
            r"[0-9a-f]{64}", build[field]
        ) is None:
            raise VerificationError(f"{name} build {field} is not a SHA-256")
    for field in ("frontend_digest", "python_image_digest", "uv_image_digest"):
        if not isinstance(build[field], str) or _DIGEST.fullmatch(build[field]) is None:
            raise VerificationError(f"{name} build {field} is not a SHA-256")
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise VerificationError(f"{name} build artifacts must be non-empty")
    artifact_names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise VerificationError(f"{name} build artifact must be an object")
        _exact_keys(artifact, {"name", "sha256"}, f"{name} build artifact")
        artifact_name = artifact.get("name")
        artifact_digest = artifact.get("sha256")
        if (
            not isinstance(artifact_name, str)
            or not artifact_name
            or artifact_name in artifact_names
        ):
            raise VerificationError(f"{name} build artifact name is invalid or repeated")
        if not isinstance(artifact_digest, str) or re.fullmatch(
            r"[0-9a-f]{64}", artifact_digest
        ) is None:
            raise VerificationError(f"{name} build artifact digest is invalid")
        artifact_names.add(artifact_name)
    required_artifacts = {
        "cisco-skill-scanner": {"cisco-ai-skill-scanner-wheel"},
        "skillspector": {
            "forbiddenfruit-sdist",
            "setuptools-build-wheel",
            "forbiddenfruit-derived-wheel",
            "skillspector-dist-info",
        },
    }[name]
    if artifact_names != required_artifacts:
        raise VerificationError(f"{name} build artifact set is not exact")

    image = baseline.get("image")
    if not isinstance(image, dict):
        raise VerificationError(f"{name} image must be an object")
    _exact_keys(
        image,
        {
            "local_tag",
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "build_provenance_manifest_digest",
            "os",
            "architecture",
            "size_bytes",
        },
        f"{name} image",
    )
    _expect(image.get("local_tag"), expected["local_tag"], f"{name} local tag")
    for field in (
        "index_digest",
        "platform_manifest_digest",
        "config_digest",
        "build_provenance_manifest_digest",
    ):
        if not isinstance(image[field], str) or _DIGEST.fullmatch(image[field]) is None:
            raise VerificationError(f"{name} image {field} is not a SHA-256")
    _expect(image.get("os"), "linux", f"{name} image operating system")
    if image.get("architecture") not in {"arm64", "amd64"}:
        raise VerificationError(f"{name} image architecture is unsupported")
    if (
        isinstance(image.get("size_bytes"), bool)
        or not isinstance(image.get("size_bytes"), int)
        or image["size_bytes"] <= 0
    ):
        raise VerificationError(f"{name} image size is invalid")


def _exact_keys(document: dict[str, Any], expected: set[str], label: str) -> None:
    if set(document) != expected:
        raise VerificationError(f"{label} fields are not exact")


def resolve_docker(executable: str | os.PathLike[str] = "docker") -> DockerExecutable:
    """Resolve and hash a regular executable Docker CLI."""

    candidate = os.fspath(executable)
    located = (
        shutil.which(candidate)
        if os.path.sep not in candidate and not os.path.isabs(candidate)
        else candidate
    )
    if located is None:
        raise VerificationError("docker executable was not found")
    path = Path(located).expanduser().resolve(strict=True)
    digest, identity, mode = _hash_regular_file(path, _MAX_DOCKER_BYTES, "docker")
    if mode & 0o111 == 0:
        raise VerificationError("docker executable is not executable")
    return DockerExecutable(path=path, digest=digest, identity=identity)


def _hash_regular_file(
    path: Path, maximum: int, label: str
) -> tuple[str, tuple[int, int, int, int], int]:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise VerificationError(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise VerificationError(f"{label} size is outside its bound")
        size = 0
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise VerificationError(f"{label} exceeds its byte limit")
            hasher.update(chunk)
        after = os.fstat(source.fileno())
    identity = _file_identity(before)
    if identity != _file_identity(after) or size != before.st_size:
        raise VerificationError(f"{label} changed while it was hashed")
    return f"sha256:{hasher.hexdigest()}", identity, before.st_mode


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _verify_docker_unchanged(docker: DockerExecutable) -> None:
    digest, identity, _mode = _hash_regular_file(
        docker.path, _MAX_DOCKER_BYTES, "docker"
    )
    if digest != docker.digest or identity != docker.identity:
        raise VerificationError("docker executable changed during execution")


def _docker_environment(
    control: Path,
    *,
    docker_config: Path | None = None,
    docker_host: str | None = None,
) -> dict[str, str]:
    """Return a whitelist-only Docker CLI environment."""

    safe_path = os.pathsep.join(
        item
        for item in os.defpath.split(os.pathsep)
        if item and os.path.isabs(item)
    )
    selected_config = (
        docker_config
        if docker_config is not None
        else Path(os.environ.get("DOCKER_CONFIG", Path.home() / ".docker"))
    ).expanduser()
    config_text = os.fspath(selected_config)
    if (
        not selected_config.is_absolute()
        or any(character in config_text for character in ("\0", "\n", "\r"))
    ):
        raise VerificationError("DOCKER_CONFIG must resolve to an absolute path")
    environment = {
        "DOCKER_CONFIG": config_text,
        "HOME": os.fspath(control),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": safe_path,
        "TMPDIR": os.fspath(control),
        "XDG_CONFIG_HOME": os.fspath(control),
    }
    if docker_host is not None:
        _context, endpoint = parse_docker_context(
            _canonical_json(
                {
                    "Name": "pinned",
                    "DockerEndpoint": {
                        "Host": docker_host,
                        "SkipTLSVerify": False,
                        "TLSMaterialCount": 0,
                    },
                }
            )
        )
        environment["DOCKER_HOST"] = endpoint
    return environment


def _fresh_pinned_docker_environment(
    control: Path,
    endpoint: str,
) -> dict[str, str]:
    """Pin Docker to one endpoint with an empty private CLI config."""

    docker_config = control / "docker-config"
    docker_config.mkdir(mode=0o700)
    docker_config.chmod(0o700)
    metadata = docker_config.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(docker_config.iterdir())
    ):
        raise VerificationError("pinned Docker config is not a fresh private directory")
    return _docker_environment(
        control,
        docker_config=docker_config,
        docker_host=endpoint,
    )


def _capture_docker_document(
    docker: DockerExecutable,
    arguments: Sequence[str],
    *,
    env: dict[str, str],
    label: str,
) -> bytes:
    """Capture one bounded, template-targeted Docker identity document."""

    result = _run_bounded(
        [os.fspath(docker.path), *arguments],
        timeout=_DOCKER_TIMEOUT_SECONDS,
        stdout_limit=_MAX_INSPECT_BYTES,
        stderr_limit=_MAX_INSPECT_BYTES,
        shared_limit=2 * _MAX_INSPECT_BYTES,
        env=env,
    )
    _require_command(result, label)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"{label} failed: {message}")
    return result.stdout


def _capture_pre_runner_identity(
    docker: DockerExecutable,
    control: Path,
    evidence: _RunnerReceiptBuffer,
) -> tuple[dict[str, str], dict[str, str], DockerIdentityReceipt]:
    """Discover the current local context, then pin all daemon commands."""

    _verify_docker_unchanged(docker)
    discovery_environment = _docker_environment(control)
    evidence.raw_context = _capture_docker_document(
        docker,
        ("context", "inspect", "--format", DOCKER_CONTEXT_TEMPLATE),
        env=discovery_environment,
        label="docker context inspect",
    )
    _context, endpoint = parse_docker_context(evidence.raw_context)
    execution_environment = _fresh_pinned_docker_environment(control, endpoint)
    evidence.raw_version = _capture_docker_document(
        docker,
        ("version", "--format", DOCKER_VERSION_TEMPLATE),
        env=execution_environment,
        label="docker version",
    )
    evidence.raw_info = _capture_docker_document(
        docker,
        ("info", "--format", DOCKER_INFO_TEMPLATE),
        env=execution_environment,
        label="docker info",
    )
    receipt = normalize_docker_identity(
        evidence.raw_context,
        evidence.raw_version,
        evidence.raw_info,
    )
    _verify_docker_unchanged(docker)
    return discovery_environment, execution_environment, receipt


def _capture_post_runner_identity(
    docker: DockerExecutable,
    *,
    discovery_environment: dict[str, str],
    execution_environment: dict[str, str],
    expected: DockerIdentityReceipt,
    evidence: _RunnerReceiptBuffer,
) -> DockerIdentityReceipt:
    """Re-read context and the exact preselected daemon after execution."""

    evidence.raw_context = _capture_docker_document(
        docker,
        ("context", "inspect", "--format", DOCKER_CONTEXT_TEMPLATE),
        env=discovery_environment,
        label="docker context inspect",
    )
    parse_docker_context(evidence.raw_context)
    evidence.raw_version = _capture_docker_document(
        docker,
        ("version", "--format", DOCKER_VERSION_TEMPLATE),
        env=execution_environment,
        label="docker version",
    )
    evidence.raw_info = _capture_docker_document(
        docker,
        ("info", "--format", DOCKER_INFO_TEMPLATE),
        env=execution_environment,
        label="docker info",
    )
    receipt = normalize_docker_identity(
        evidence.raw_context,
        evidence.raw_version,
        evidence.raw_info,
    )
    if receipt.document_json != expected.document_json:
        raise DockerIdentityError("Docker runner identity changed")
    return receipt


def _environment_mapping(entries: Sequence[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in entries:
        name, separator, value = entry.partition("=")
        if (
            not separator
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or name in result
        ):
            raise VerificationError(f"{label} has an invalid or repeated variable")
        result[name] = value
    return result


def _inspect(
    docker: Path,
    reference: str,
    platform: str | None = None,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    document, _raw = _inspect_with_raw(docker, reference, platform, env=env)
    return document


def _inspect_with_raw(
    docker: Path,
    reference: str,
    platform: str | None = None,
    *,
    env: dict[str, str] | None = None,
) -> tuple[dict[str, Any], bytes]:
    command = [os.fspath(docker), "image", "inspect"]
    if platform is not None:
        command.extend(("--platform", platform))
    command.append(reference)
    result = _run_bounded(
        command,
        timeout=_DOCKER_TIMEOUT_SECONDS,
        stdout_limit=_MAX_INSPECT_BYTES,
        stderr_limit=_MAX_INSPECT_BYTES,
        shared_limit=_MAX_INSPECT_BYTES,
        env=env,
    )
    _require_command(result, "docker image inspect")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"docker inspect failed for {reference}: {message}")
    document = _load(result.stdout, "docker inspect")
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise VerificationError("docker inspect must return exactly one image object")
    return document[0], result.stdout


def _expect(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise VerificationError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def _digest_reference(tag: str, index_digest: str) -> str:
    if "@" in tag or not tag or _DIGEST.fullmatch(index_digest) is None:
        raise VerificationError("baseline image reference is invalid")
    last_slash = tag.rfind("/")
    last_colon = tag.rfind(":")
    repository = tag[:last_colon] if last_colon > last_slash else tag
    if not repository:
        raise VerificationError("baseline image repository is invalid")
    return f"{repository}@{index_digest}"


def _run_bounded(
    argv: Sequence[str],
    *,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    shared_limit: int,
    env: dict[str, str] | None,
    stdout_sink: BinaryIO | None = None,
    retain_stdout: bool = True,
    stdin_bytes: bytes | None = None,
    cwd: str | os.PathLike[str] = os.path.sep,
    user: int | None = None,
    group: int | None = None,
    extra_groups: Sequence[int] | None = None,
    umask: int = -1,
) -> _ProcessResult:
    """Run one command with hard pipe-read limits."""

    popen_options: dict[str, Any] = {
        "stdin": subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": cwd,
        "env": env,
        "shell": False,
        "close_fds": True,
        "start_new_session": os.name == "posix",
    }
    if user is not None:
        popen_options.update(
            user=user,
            group=group,
            extra_groups=extra_groups,
            umask=umask,
        )
    process = subprocess.Popen(tuple(argv), **popen_options)
    assert process.stdout is not None
    assert process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {"stdout": 0, "stderr": 0, "total": 0}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    lock = threading.Lock()
    overflow = threading.Event()
    io_errors: list[str] = []

    def read_stream(label: str, stream: Any) -> None:
        try:
            while chunk := os.read(stream.fileno(), 64 * 1024):
                with lock:
                    remaining = min(
                        limits[label] - counts[label],
                        shared_limit - counts["total"],
                    )
                    kept = chunk[: max(0, remaining)]
                    if label == "stdout" and stdout_sink is not None and kept:
                        stdout_sink.write(kept)
                    if label != "stdout" or retain_stdout:
                        buffers[label].extend(kept)
                    counts[label] += len(kept)
                    counts["total"] += len(kept)
                    exceeded = len(kept) != len(chunk)
                if exceeded:
                    overflow.set()
                    _kill_process(process)
                    return
        except (OSError, ValueError) as exc:
            with lock:
                io_errors.append(f"{label}: {exc}")
            _kill_process(process)

    readers = (
        threading.Thread(
            target=read_stream, args=("stdout", process.stdout), daemon=True
        ),
        threading.Thread(
            target=read_stream, args=("stderr", process.stderr), daemon=True
        ),
    )
    for reader in readers:
        reader.start()

    writer: threading.Thread | None = None
    if stdin_bytes is not None:
        assert process.stdin is not None

        def write_stdin() -> None:
            try:
                process.stdin.write(stdin_bytes)
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                with lock:
                    io_errors.append(f"stdin: {exc}")
                _kill_process(process)
            finally:
                try:
                    process.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass

        writer = threading.Thread(target=write_stdin, daemon=True)
        writer.start()

    timed_out = False
    termination_failed = False
    try:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(process)
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                termination_failed = True
        # A successful command may leave children holding the pipes open.
        # Every caller starts a fresh session, so retire that process group
        # before collecting the final bounded output.
        _kill_process(process)
        if writer is not None:
            writer.join(timeout=1.0)
            if writer.is_alive():
                _kill_process(process)
                writer.join(timeout=1.0)
            if writer.is_alive():
                io_errors.append("command input writer did not stop")
        for reader in readers:
            reader.join(timeout=1.0)
        if any(reader.is_alive() for reader in readers):
            _kill_process(process)
            for reader in readers:
                reader.join(timeout=1.0)
        if any(reader.is_alive() for reader in readers):
            io_errors.append("Docker output reader did not stop")
    except BaseException:
        _kill_process(process)
        try:
            process.wait(timeout=1.0)
        except BaseException:
            pass
        raise
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
        process.stdout.close()
        process.stderr.close()
    return _ProcessResult(
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        returncode=process.returncode,
        timed_out=timed_out,
        output_exceeded=overflow.is_set(),
        termination_failed=termination_failed,
        io_error="; ".join(sorted(io_errors)) if io_errors else None,
    )


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            # _run_bounded always starts a fresh session whose PGID is the
            # leader PID. The leader may already be reaped while descendants
            # still retain its stdout/stderr descriptors.
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    try:
        if process.poll() is None:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _require_command(result: _ProcessResult, label: str) -> None:
    if result.termination_failed:
        raise VerificationError(f"{label} did not terminate after SIGKILL")
    if result.output_exceeded:
        raise VerificationError(f"{label} exceeded its output byte limit")
    if result.timed_out:
        raise VerificationError(f"{label} timed out")
    if result.io_error is not None:
        raise VerificationError(f"{label} output failed: {result.io_error}")


def _save_image(
    docker: Path,
    reference: str,
    output: BinaryIO,
    *,
    maximum_bytes: int,
    env: dict[str, str] | None = None,
) -> None:
    result = _run_bounded(
        [os.fspath(docker), "image", "save", reference],
        timeout=120.0,
        stdout_limit=maximum_bytes,
        stderr_limit=_MAX_INSPECT_BYTES,
        shared_limit=maximum_bytes + _MAX_INSPECT_BYTES,
        env=env,
        stdout_sink=output,
        retain_stdout=False,
    )
    _require_command(result, "docker image save")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"docker image save failed for {reference}: {message}")


def _read_oci_archive(
    archive: BinaryIO, image: dict[str, Any]
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes]:
    metadata_digests = {
        image["index_digest"],
        image["platform_manifest_digest"],
        image["config_digest"],
        image["build_provenance_manifest_digest"],
    }
    blobs: dict[str, int] = {}
    metadata: dict[str, bytes] = {}
    members = 0
    try:
        with tarfile.open(fileobj=archive, mode="r:") as bundle:
            for member in bundle:
                members += 1
                if members > _MAX_ARCHIVE_MEMBERS:
                    raise VerificationError("OCI archive exceeds its member limit")
                if member.issym() or member.islnk() or member.isdev():
                    raise VerificationError("OCI archive contains a link or device")
                match = _BLOB_PATH.fullmatch(member.name)
                if match is None:
                    continue
                if not member.isfile():
                    raise VerificationError("OCI blob member is not a regular file")
                digest = f"sha256:{match.group(1)}"
                if digest in blobs:
                    raise VerificationError(f"OCI archive repeats blob {digest}")
                source = bundle.extractfile(member)
                if source is None:
                    raise VerificationError(f"cannot read OCI blob {digest}")
                hasher = hashlib.sha256()
                retained = bytearray()
                size = 0
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    hasher.update(chunk)
                    if digest in metadata_digests:
                        if size > _MAX_METADATA_BLOB:
                            raise VerificationError("OCI metadata blob exceeds 16 MiB")
                        retained.extend(chunk)
                actual = f"sha256:{hasher.hexdigest()}"
                if actual != digest or size != member.size:
                    raise VerificationError(f"OCI blob content does not match {digest}")
                blobs[digest] = size
                if digest in metadata_digests:
                    metadata[digest] = bytes(retained)
    except tarfile.TarError as exc:
        raise VerificationError(f"invalid OCI archive: {exc}") from exc

    missing = sorted(metadata_digests - metadata.keys())
    if missing:
        raise VerificationError(f"OCI archive is missing locked metadata: {', '.join(missing)}")
    index = _object(_load(metadata[image["index_digest"]], "OCI index"), "OCI index")
    platform = _object(
        _load(metadata[image["platform_manifest_digest"]], "OCI platform manifest"),
        "OCI platform manifest",
    )
    provenance = _object(
        _load(
            metadata[image["build_provenance_manifest_digest"]],
            "OCI build provenance manifest",
        ),
        "OCI build provenance manifest",
    )
    config = _object(
        _load(metadata[image["config_digest"]], "OCI image config"),
        "OCI image config",
    )
    _verify_oci_graph(index, platform, provenance, config, blobs, image)
    return (
        config,
        metadata[image["index_digest"]],
        metadata[image["platform_manifest_digest"]],
        metadata[image["build_provenance_manifest_digest"]],
        metadata[image["config_digest"]],
    )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    return value


def _descriptors(value: Any, blobs: dict[str, int], label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise VerificationError(f"{label} must be a non-empty array")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        descriptor = _object(item, f"{label}[{index}]")
        digest = descriptor.get("digest")
        size = descriptor.get("size")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise VerificationError(f"{label}[{index}] has an invalid digest")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise VerificationError(f"{label}[{index}] has an invalid size")
        if digest in result:
            raise VerificationError(f"{label} repeats descriptor {digest}")
        if blobs.get(digest) != size:
            raise VerificationError(f"{label}[{index}] does not match a retained blob")
        result[digest] = descriptor
    return result


def _verify_oci_graph(
    index: dict[str, Any],
    platform: dict[str, Any],
    provenance: dict[str, Any],
    config: dict[str, Any],
    blobs: dict[str, int],
    image: dict[str, Any],
) -> None:
    _expect(index.get("schemaVersion"), 2, "OCI index schema version")
    _expect(
        index.get("mediaType"),
        "application/vnd.oci.image.index.v1+json",
        "OCI index media type",
    )
    manifests = _descriptors(index.get("manifests"), blobs, "OCI index manifests")
    platform_descriptor = manifests.get(image["platform_manifest_digest"])
    provenance_descriptor = manifests.get(image["build_provenance_manifest_digest"])
    if platform_descriptor is None or provenance_descriptor is None or len(manifests) != 2:
        raise VerificationError("OCI index does not contain exactly the locked image and provenance")
    _expect(
        platform_descriptor.get("platform"),
        {"architecture": image["architecture"], "os": image["os"]},
        "OCI platform descriptor",
    )
    _expect(
        provenance_descriptor.get("platform"),
        {"architecture": "unknown", "os": "unknown"},
        "OCI provenance platform descriptor",
    )
    _expect(
        provenance_descriptor.get("annotations"),
        {
            "vnd.docker.reference.digest": image["platform_manifest_digest"],
            "vnd.docker.reference.type": "attestation-manifest",
        },
        "OCI provenance descriptor annotations",
    )

    _expect(platform.get("schemaVersion"), 2, "OCI platform manifest schema version")
    platform_config = _object(platform.get("config"), "OCI platform config descriptor")
    _expect(platform_config.get("digest"), image["config_digest"], "OCI config digest")
    _descriptors([platform_config], blobs, "OCI platform config")
    _descriptors(platform.get("layers"), blobs, "OCI platform layers")

    _expect(provenance.get("schemaVersion"), 2, "OCI provenance schema version")
    provenance_config = _object(
        provenance.get("config"), "OCI provenance config descriptor"
    )
    _descriptors([provenance_config], blobs, "OCI provenance config")
    provenance_layers = _descriptors(
        provenance.get("layers"), blobs, "OCI provenance layers"
    )
    if len(provenance_layers) != 1:
        raise VerificationError("OCI provenance must contain exactly one statement")
    statement = next(iter(provenance_layers.values()))
    _expect(statement.get("mediaType"), "application/vnd.in-toto+json", "provenance media type")
    _expect(
        statement.get("annotations", {}).get("in-toto.io/predicate-type"),
        "https://slsa.dev/provenance/v1",
        "provenance predicate type",
    )
    _expect(config.get("architecture"), image["architecture"], "OCI config architecture")
    _expect(config.get("os"), image["os"], "OCI config operating system")


def _export_and_verify(
    docker: Path,
    reference: str,
    image: dict[str, Any],
    *,
    env: dict[str, str] | None = None,
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes]:
    with tempfile.TemporaryFile() as archive:
        maximum = image["size_bytes"] + _MAX_ARCHIVE_OVERHEAD
        _save_image(
            docker,
            reference,
            archive,
            maximum_bytes=maximum,
            env=env,
        )
        archive_size = archive.tell()
        if archive_size > maximum:
            raise VerificationError("OCI archive exceeds the locked image size bound")
        archive.seek(0)
        return _read_oci_archive(archive, image)


def verify_image(
    docker: Path,
    baseline: dict[str, Any],
    *,
    env: dict[str, str],
) -> ImageVerification:
    """Verify the locked index, platform, config, and provenance graph."""

    name = baseline["name"]
    image = baseline["image"]
    runtime = baseline["runtime_profile"]
    tag = image["local_tag"]
    index, raw_index_inspect = _inspect_with_raw(docker, tag, env=env)
    platform_name = f"{image['os']}/{image['architecture']}"
    platform, raw_platform_inspect = _inspect_with_raw(
        docker, tag, platform_name, env=env
    )

    _expect(index.get("Id"), image["index_digest"], f"{name} index digest")
    _expect(
        index.get("Descriptor", {}).get("digest"),
        image["index_digest"],
        f"{name} index descriptor",
    )
    _expect(platform.get("Id"), image["platform_manifest_digest"], f"{name} manifest")
    _expect(platform.get("Os"), image["os"], f"{name} operating system")
    _expect(platform.get("Architecture"), image["architecture"], f"{name} architecture")
    _expect(index.get("Size"), image["size_bytes"], f"{name} image size")

    digest_reference = _digest_reference(tag, image["index_digest"])
    (
        raw_config,
        raw_oci_index_json,
        raw_oci_platform_manifest_json,
        raw_build_provenance_manifest_json,
        raw_config_json,
    ) = _export_and_verify(
        docker, digest_reference, image, env=env
    )
    config = raw_config.get("config")
    if not isinstance(config, dict):
        raise VerificationError(f"{name} image config is missing")
    _expect(config.get("User"), runtime["user"], f"{name} default user")
    _expect(config.get("WorkingDir"), runtime["workdir"], f"{name} control workdir")
    expected_entrypoint = {
        "cisco-skill-scanner": ["/opt/venv/bin/skill-scanner"],
        "skillspector": ["/opt/venv/bin/python", "-P", "-m", "skillspector.cli"],
    }[name]
    _expect(config.get("Entrypoint"), expected_entrypoint, f"{name} entrypoint")
    environment = config.get("Env")
    if (
        not isinstance(environment, list)
        or any(not isinstance(item, str) or "\0" in item for item in environment)
    ):
        raise VerificationError(f"{name} image environment is invalid")
    _environment_mapping(environment, f"{name} image environment")

    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise VerificationError(f"{name} image labels are missing")
    expected_labels = {
        "org.opencontainers.image.source": baseline["repository"],
        "org.opencontainers.image.revision": baseline["commit"],
        "org.opencontainers.image.version": baseline["release"]
        or baseline["version"].split("+", 1)[0],
        "dev.aragorn.baseline.build-input-sha256": baseline["build"][
            "build_input_sha256"
        ],
        "dev.aragorn.baseline.lock-sha256": baseline["build"][
            "dependency_lock_sha256"
        ],
        "dev.aragorn.closure-status": "candidate-not-runner-attested",
    }
    artifact_hashes = {
        artifact["name"]: artifact["sha256"] for artifact in baseline["build"]["artifacts"]
    }
    if name == "cisco-skill-scanner":
        expected_labels["dev.aragorn.baseline.distribution-sha256"] = artifact_hashes[
            "cisco-ai-skill-scanner-wheel"
        ]
    else:
        expected_labels["dev.aragorn.baseline.derived-wheel-sha256"] = artifact_hashes[
            "forbiddenfruit-derived-wheel"
        ]
        expected_labels["dev.aragorn.baseline.dist-info-sha256"] = artifact_hashes[
            "skillspector-dist-info"
        ]
    for key, value in expected_labels.items():
        _expect(labels.get(key), value, f"{name} label {key}")

    directory = "cisco" if name == "cisco-skill-scanner" else "nvidia"
    dockerfile = ROOT / "baselines" / directory / "Dockerfile"
    dockerfile_digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    _expect(
        dockerfile_digest,
        baseline["build"]["dockerfile_sha256"],
        f"{name} Dockerfile digest",
    )
    return ImageVerification(
        name=name,
        image_reference=digest_reference,
        raw_index_inspect=raw_index_inspect,
        raw_platform_inspect=raw_platform_inspect,
        raw_oci_index_json=raw_oci_index_json,
        raw_oci_platform_manifest_json=raw_oci_platform_manifest_json,
        raw_build_provenance_manifest_json=raw_build_provenance_manifest_json,
        raw_config_json=raw_config_json,
        image_entrypoint=tuple(expected_entrypoint),
        image_environment=tuple(environment),
    )


def _build_create_argv(
    docker: Path,
    baseline: dict[str, Any],
    verification: ImageVerification,
    workspace: Path,
    container_name: str,
) -> tuple[tuple[str, ...], tuple[str, ...], dict[str, str]]:
    runtime = baseline["runtime_profile"]
    profile = baseline["profile"]
    workspace_text = os.fspath(workspace)
    if any(character in workspace_text for character in ("\0", "\n", "\r", ",")):
        raise VerificationError("workspace path cannot be represented by Docker --mount")
    arguments = tuple(
        runtime["workspace"]["destination"] if item == "{workspace}" else item
        for item in profile["arguments"]
    )
    if (
        profile["arguments"].count("{workspace}") != 1
        or any("{" in item or "}" in item for item in arguments)
    ):
        raise VerificationError("baseline arguments have an invalid workspace placeholder")

    image_environment = _environment_mapping(
        verification.image_environment, f"{baseline['name']} image environment"
    )
    profile_environment = profile["environment"]
    if any(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
        or not isinstance(value, str)
        or "\0" in value
        for name, value in profile_environment.items()
    ):
        raise VerificationError("baseline environment is invalid")
    expected_environment = {**image_environment, **profile_environment}
    tmpfs = runtime["tmpfs"]
    tmpfs_options = [
        *tmpfs["options"][:-1],
        f"size={tmpfs['size_bytes']}",
        tmpfs["options"][-1],
    ]
    command = [
        os.fspath(docker),
        "create",
        "--name",
        container_name,
        "--pull",
        runtime["pull"],
        "--platform",
        f"{baseline['image']['os']}/{baseline['image']['architecture']}",
        "--network",
        runtime["network"],
        "--read-only",
        "--cap-drop",
        runtime["cap_drop"][0],
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        runtime["user"],
        "--workdir",
        runtime["workdir"],
        "--pids-limit",
        str(runtime["pids_limit"]),
        "--memory",
        str(runtime["memory_bytes"]),
        "--memory-swap",
        str(runtime["memory_swap_bytes"]),
        "--cpus",
        str(runtime["cpus"]),
        "--ulimit",
        f"nofile={runtime['nofile_soft']}:{runtime['nofile_hard']}",
        "--tmpfs",
        f"{tmpfs['destination']}:{','.join(tmpfs_options)}",
        "--mount",
        (
            f"type=bind,source={workspace_text},"
            f"destination={runtime['workspace']['destination']},readonly"
        ),
    ]
    for name in sorted(profile_environment):
        command.extend(("--env", f"{name}={profile_environment[name]}"))
    command.append(verification.image_reference)
    command.extend(arguments)
    return tuple(command), arguments, expected_environment


def _build_effective_config_json(
    *,
    baseline: dict[str, Any],
    raw_lock: bytes,
    selected_json: bytes,
    docker: DockerExecutable,
    verification: ImageVerification,
    arguments: Sequence[str],
    effective_environment: dict[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
    runner_identity_json: bytes,
    normalization: str | None = None,
) -> bytes:
    """Build the single canonical runtime identity used by preflight and runs."""

    runner_identity = _load(runner_identity_json, "Docker runner identity")
    if not isinstance(runner_identity, dict):
        raise VerificationError("Docker runner identity must be an object")
    supported_normalizations = _NORMALIZATIONS[baseline["name"]]
    selected_normalization = (
        supported_normalizations[0] if normalization is None else normalization
    )
    if selected_normalization not in supported_normalizations:
        raise VerificationError("OCI normalization policy is unsupported")
    return _canonical_json(
        {
            "schema": "aragorn/benchmark-oci-system-config/v2",
            "name": baseline["name"],
            "version": baseline["version"],
            "baseline_lock_digest": _sha256(raw_lock),
            "baseline_entry_digest": _sha256(selected_json),
            "docker_executable_digest": docker.digest,
            "runner_identity": runner_identity,
            "image": {
                "reference": verification.image_reference,
                "index_digest": baseline["image"]["index_digest"],
                "platform_manifest_digest": baseline["image"][
                    "platform_manifest_digest"
                ],
                "config_digest": baseline["image"]["config_digest"],
                "os": baseline["image"]["os"],
                "architecture": baseline["image"]["architecture"],
                "size_bytes": baseline["image"]["size_bytes"],
            },
            "entrypoint": list(verification.image_entrypoint),
            "arguments": list(arguments),
            "environment": effective_environment,
            "runtime_profile": baseline["runtime_profile"],
            "limits": {
                "timeout_seconds": float(timeout_seconds),
                "output_bytes": output_limit_bytes,
            },
            "normalization": selected_normalization,
        }
    )


def _parse_single_inspect(raw: bytes, label: str) -> dict[str, Any]:
    document = _load(raw, label)
    if (
        not isinstance(document, list)
        or len(document) != 1
        or not isinstance(document[0], dict)
    ):
        raise VerificationError(f"{label} must contain exactly one object")
    return document[0]


def _inspect_container(
    docker: Path, container_id: str, env: dict[str, str]
) -> tuple[dict[str, Any], bytes]:
    result = _run_bounded(
        [os.fspath(docker), "container", "inspect", container_id],
        timeout=_DOCKER_TIMEOUT_SECONDS,
        stdout_limit=_MAX_INSPECT_BYTES,
        stderr_limit=_MAX_INSPECT_BYTES,
        shared_limit=_MAX_INSPECT_BYTES,
        env=env,
    )
    _require_command(result, "docker container inspect")
    if result.returncode != 0:
        raise VerificationError(
            "docker container inspect failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return _parse_single_inspect(result.stdout, "docker container inspect"), result.stdout


def _verify_container(
    container: dict[str, Any],
    *,
    container_id: str,
    baseline: dict[str, Any],
    verification: ImageVerification,
    workspace: Path,
    arguments: tuple[str, ...],
    expected_environment: dict[str, str],
    phase: str,
) -> None:
    runtime = baseline["runtime_profile"]
    image = baseline["image"]
    _expect(container.get("Id"), container_id, "container ID")
    _expect(container.get("Image"), image["index_digest"], "container image index")
    manifest = _object(
        container.get("ImageManifestDescriptor"),
        "container image manifest descriptor",
    )
    _expect(
        manifest.get("digest"),
        image["platform_manifest_digest"],
        "container image platform manifest",
    )
    _expect(
        manifest.get("mediaType"),
        "application/vnd.oci.image.manifest.v1+json",
        "container image manifest media type",
    )
    _expect(
        manifest.get("platform"),
        {"architecture": image["architecture"], "os": image["os"]},
        "container image manifest platform",
    )
    execution = [*verification.image_entrypoint, *arguments]
    _expect(container.get("Path"), execution[0], "container executable path")
    _expect(container.get("Args"), execution[1:], "container executable arguments")

    state = _object(container.get("State"), "container State")
    if phase == "prestart":
        _expect(state.get("Status"), "created", "prestart container status")
        _expect(state.get("Running"), False, "prestart container running state")
        _expect(state.get("Dead"), False, "prestart container dead state")
        _expect(state.get("OOMKilled"), False, "prestart container OOM state")
        _expect(state.get("ExitCode"), 0, "prestart container exit code")
    elif phase != "postrun":
        raise VerificationError("container verification phase is invalid")

    config = _object(container.get("Config"), "container Config")
    _expect(config.get("Image"), verification.image_reference, "container image reference")
    _expect(config.get("Entrypoint"), list(verification.image_entrypoint), "entrypoint")
    _expect(config.get("Cmd"), list(arguments), "container arguments")
    _expect(config.get("User"), runtime["user"], "container user")
    _expect(config.get("WorkingDir"), runtime["workdir"], "container working directory")
    _expect(config.get("ExposedPorts"), None, "container exposed ports")
    environment = config.get("Env")
    if not isinstance(environment, list) or any(
        not isinstance(item, str) for item in environment
    ):
        raise VerificationError("container environment is invalid")
    _expect(
        _environment_mapping(environment, "container environment"),
        expected_environment,
        "container environment",
    )

    host = _object(container.get("HostConfig"), "container HostConfig")
    _expect(host.get("NetworkMode"), runtime["network"], "container network")
    _expect(host.get("ReadonlyRootfs"), True, "read-only root filesystem")
    _expect(host.get("CapDrop"), runtime["cap_drop"], "dropped capabilities")
    _expect(
        host.get("SecurityOpt"),
        ["no-new-privileges=true"],
        "security options",
    )
    _expect(host.get("Privileged"), False, "privileged mode")
    if host.get("CapAdd") not in (None, []):
        raise VerificationError("container has added capabilities")
    if host.get("Devices") not in (None, []):
        raise VerificationError("container has host devices")
    if host.get("DeviceRequests") not in (None, []):
        raise VerificationError("container has device requests")
    _expect(host.get("PublishAllPorts"), False, "published ports")
    if host.get("PortBindings") not in (None, {}):
        raise VerificationError("container has port bindings")
    _expect(host.get("PidsLimit"), runtime["pids_limit"], "PID limit")
    _expect(host.get("Memory"), runtime["memory_bytes"], "memory limit")
    _expect(host.get("MemorySwap"), runtime["memory_swap_bytes"], "swap limit")
    _expect(host.get("NanoCpus"), int(runtime["cpus"] * 1_000_000_000), "CPU limit")
    _expect(
        host.get("Ulimits"),
        [
            {
                "Name": "nofile",
                "Hard": runtime["nofile_hard"],
                "Soft": runtime["nofile_soft"],
            }
        ],
        "nofile limit",
    )
    tmpfs = runtime["tmpfs"]
    expected_tmpfs = ",".join(
        [
            *tmpfs["options"][:-1],
            f"size={tmpfs['size_bytes']}",
            tmpfs["options"][-1],
        ]
    )
    _expect(
        host.get("Tmpfs"),
        {tmpfs["destination"]: expected_tmpfs},
        "tmpfs policy",
    )
    host_mounts = host.get("Mounts")
    if not isinstance(host_mounts, list) or len(host_mounts) != 1:
        raise VerificationError("container must have exactly one HostConfig mount")
    host_mount = _object(host_mounts[0], "container HostConfig mount")
    _expect(host_mount.get("Type"), "bind", "HostConfig mount type")
    _expect(host_mount.get("Source"), os.fspath(workspace), "HostConfig mount source")
    _expect(
        host_mount.get("Target"),
        runtime["workspace"]["destination"],
        "HostConfig mount target",
    )
    _expect(host_mount.get("ReadOnly"), True, "HostConfig mount mode")

    mounts = container.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise VerificationError("container must have exactly one resolved mount")
    mount = _object(mounts[0], "container mount")
    _expect(mount.get("Type"), "bind", "mount type")
    _expect(mount.get("Source"), os.fspath(workspace), "mount source")
    _expect(
        mount.get("Destination"),
        runtime["workspace"]["destination"],
        "mount destination",
    )
    _expect(mount.get("RW"), False, "mount read-only mode")
    if mount.get("Mode") not in ("", "ro"):
        raise VerificationError("mount mode is not read-only")
    network_settings = _object(
        container.get("NetworkSettings"), "container NetworkSettings"
    )
    networks = _object(network_settings.get("Networks"), "container networks")
    if set(networks) not in (set(), {"none"}):
        raise VerificationError("container has a network other than none")
    if network_settings.get("Ports") not in (None, {}):
        raise VerificationError("container has published ports")


def _stop_and_inspect_container(
    docker: Path,
    container_id: str,
    env: dict[str, str],
) -> tuple[dict[str, Any], bytes]:
    """Stop a still-running bounded execution and retain its final state."""

    container, raw = _inspect_container(docker, container_id, env)
    state = _object(container.get("State"), "container State")
    if state.get("Running") is not True:
        return container, raw
    stopped = _run_bounded(
        [os.fspath(docker), "kill", "--signal", "KILL", container_id],
        timeout=_DOCKER_TIMEOUT_SECONDS,
        stdout_limit=_MAX_INSPECT_BYTES,
        stderr_limit=_MAX_INSPECT_BYTES,
        shared_limit=_MAX_INSPECT_BYTES,
        env=env,
    )
    _require_command(stopped, "docker kill")
    if stopped.returncode != 0:
        raise VerificationError(
            "docker kill failed: "
            + stopped.stderr.decode("utf-8", errors="replace").strip()
        )
    return _inspect_container(docker, container_id, env)


def _cleanup_container(
    docker: Path,
    container_name: str,
    env: dict[str, str],
) -> str | None:
    """Remove a possibly created container and prove its unique name is absent."""

    try:
        removal = _run_bounded(
            [os.fspath(docker), "rm", "-f", container_name],
            timeout=_DOCKER_TIMEOUT_SECONDS,
            stdout_limit=_MAX_INSPECT_BYTES,
            stderr_limit=_MAX_INSPECT_BYTES,
            shared_limit=_MAX_INSPECT_BYTES,
            env=env,
        )
        if removal.termination_failed or removal.timed_out:
            return "docker rm -f did not terminate cleanly"
        if removal.output_exceeded or removal.io_error is not None:
            return "docker rm -f output could not be verified"

        absence = _run_bounded(
            [
                os.fspath(docker),
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{container_name}$",
                "--format",
                "{{.ID}}",
            ],
            timeout=_DOCKER_TIMEOUT_SECONDS,
            stdout_limit=_MAX_INSPECT_BYTES,
            stderr_limit=_MAX_INSPECT_BYTES,
            shared_limit=_MAX_INSPECT_BYTES,
            env=env,
        )
        _require_command(absence, "docker ps cleanup verification")
        if absence.returncode != 0:
            message = absence.stderr.decode("utf-8", errors="replace").strip()
            return f"docker ps cleanup verification failed: {message}"
        if absence.stdout.strip():
            return "container still exists after docker rm -f"
        return None
    except (OSError, VerificationError) as exc:
        return str(exc)


def _verify_exit_state(container: dict[str, Any], returncode: int) -> None:
    state = _object(container.get("State"), "container State")
    _expect(state.get("Status"), "exited", "container exit status")
    _expect(state.get("Running"), False, "container running state")
    _expect(state.get("Dead"), False, "container dead state")
    _expect(state.get("OOMKilled"), False, "container OOM state")
    _expect(state.get("ExitCode"), returncode, "container exit code")


def run_baseline(
    baseline_name: str,
    *,
    workspace: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
    expected_tree_digest: str,
    expected_effective_config_json: bytes | None = None,
    normalization: str | None = None,
) -> OCIExecutionResult | OCIExecutionError:
    """Run a pinned OCI baseline only after inspecting its effective policy."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0 < timeout_seconds <= 3600
    ):
        return OCIExecutionError(
            error_code="INVALID_CONFIGURATION",
            message="timeout must be finite, greater than zero, and at most 3600",
            baseline_name=baseline_name if isinstance(baseline_name, str) else None,
        )
    if not isinstance(expected_tree_digest, str) or _DIGEST.fullmatch(
        expected_tree_digest
    ) is None:
        return OCIExecutionError(
            error_code="INVALID_CONFIGURATION",
            message="expected tree digest must be a lowercase SHA-256 digest",
            baseline_name=baseline_name if isinstance(baseline_name, str) else None,
        )
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 1 <= output_limit_bytes <= MAX_RUNTIME_OUTPUT_BYTES
    ):
        return OCIExecutionError(
            error_code="INVALID_CONFIGURATION",
            message="output limit must be between 1 and 8388608 bytes",
            baseline_name=baseline_name if isinstance(baseline_name, str) else None,
        )
    if expected_effective_config_json is not None and (
        not isinstance(expected_effective_config_json, bytes)
        or not expected_effective_config_json
        or len(expected_effective_config_json) > _MAX_METADATA_BLOB
    ):
        return OCIExecutionError(
            error_code="INVALID_CONFIGURATION",
            message="expected effective config must be bounded non-empty bytes",
            baseline_name=baseline_name if isinstance(baseline_name, str) else None,
        )
    try:
        workspace_path = Path(workspace).expanduser().resolve(strict=True)
        if not workspace_path.is_dir():
            raise VerificationError("workspace must be a directory")
        raw_lock, baselines = load_baseline_lock(lock_path)
        selected = [item for item in baselines if item["name"] == baseline_name]
        if len(selected) != 1:
            raise VerificationError("requested baseline is not in the exact lock")
        baseline = selected[0]
        docker = resolve_docker(docker_executable)
    except (OSError, TypeError, ValueError, VerificationError) as exc:
        return OCIExecutionError(
            error_code="CONFIGURATION_FAILED",
            message=str(exc),
            baseline_name=baseline_name if isinstance(baseline_name, str) else None,
        )

    selected_json = _canonical_json(baseline)
    verification: ImageVerification | None = None
    container_id: str | None = None
    raw_prestart_container_inspect = b""
    raw_postrun_container_inspect = b""
    effective_config_json = b""
    verified_subject_digest: str | None = None
    start_result = _ProcessResult(b"", b"", None)
    pre_runner = _RunnerReceiptBuffer()
    post_runner = _RunnerReceiptBuffer()
    runner_identity_json = b""

    def failure(code: str, message: str) -> OCIExecutionError:
        return OCIExecutionError(
            error_code=code,
            message=message,
            baseline_name=baseline["name"],
            docker_path=os.fspath(docker.path),
            docker_digest=docker.digest,
            image_reference=(
                verification.image_reference if verification is not None else None
            ),
            container_id=container_id,
            raw_lock=raw_lock,
            selected_baseline_json=selected_json,
            effective_config_json=effective_config_json,
            raw_index_inspect=(
                verification.raw_index_inspect if verification is not None else b""
            ),
            raw_platform_inspect=(
                verification.raw_platform_inspect
                if verification is not None
                else b""
            ),
            raw_oci_index_json=(
                verification.raw_oci_index_json if verification is not None else b""
            ),
            raw_oci_platform_manifest_json=(
                verification.raw_oci_platform_manifest_json
                if verification is not None
                else b""
            ),
            raw_build_provenance_manifest_json=(
                verification.raw_build_provenance_manifest_json
                if verification is not None
                else b""
            ),
            raw_config_json=(
                verification.raw_config_json if verification is not None else b""
            ),
            raw_prestart_container_inspect=raw_prestart_container_inspect,
            raw_postrun_container_inspect=raw_postrun_container_inspect,
            raw_stdout=start_result.stdout,
            raw_stderr=start_result.stderr,
            returncode=start_result.returncode,
            verified_subject_digest=verified_subject_digest,
            raw_pre_context_inspect=pre_runner.raw_context,
            raw_pre_daemon_version=pre_runner.raw_version,
            raw_pre_daemon_info=pre_runner.raw_info,
            raw_post_context_inspect=post_runner.raw_context,
            raw_post_daemon_version=post_runner.raw_version,
            raw_post_daemon_info=post_runner.raw_info,
            runner_identity_json=runner_identity_json,
        )

    with tempfile.TemporaryDirectory(prefix="aragorn-docker-control-") as control:
        try:
            (
                discovery_environment,
                environment,
                runner_identity,
            ) = _capture_pre_runner_identity(
                docker,
                Path(control),
                pre_runner,
            )
            runner_identity_json = runner_identity.document_json
        except (
            DockerIdentityError,
            OSError,
            subprocess.SubprocessError,
            VerificationError,
        ) as exc:
            return failure("RUNNER_IDENTITY_FAILED", str(exc))
        if expected_effective_config_json is not None:
            try:
                expected_config = _load(
                    expected_effective_config_json,
                    "preflight effective configuration",
                )
                normalized_identity = _load(
                    runner_identity_json,
                    "Docker runner identity",
                )
                if (
                    not isinstance(expected_config, dict)
                    or expected_config.get("schema")
                    != "aragorn/benchmark-oci-system-config/v2"
                    or expected_config.get("runner_identity")
                    != normalized_identity
                ):
                    raise VerificationError(
                        "runner identity changed after preflight"
                    )
            except VerificationError as exc:
                return failure("RUNNER_IDENTITY_CHANGED", str(exc))
        try:
            verification = verify_image(docker.path, baseline, env=environment)
        except (OSError, subprocess.SubprocessError, VerificationError) as exc:
            return failure("IMAGE_VERIFICATION_FAILED", str(exc))

        container_name = f"aragorn-{secrets.token_hex(12)}"
        try:
            create_argv, arguments, expected_environment = _build_create_argv(
                docker.path,
                baseline,
                verification,
                workspace_path,
                container_name,
            )
            effective_config_json = _build_effective_config_json(
                baseline=baseline,
                raw_lock=raw_lock,
                selected_json=selected_json,
                docker=docker,
                verification=verification,
                arguments=arguments,
                effective_environment=expected_environment,
                timeout_seconds=float(timeout_seconds),
                output_limit_bytes=output_limit_bytes,
                runner_identity_json=runner_identity_json,
                normalization=normalization,
            )
        except VerificationError as exc:
            return failure("CONFIGURATION_FAILED", str(exc))
        if (
            expected_effective_config_json is not None
            and effective_config_json != expected_effective_config_json
        ):
            return failure(
                "RUNNER_IDENTITY_CHANGED",
                "effective runtime configuration changed after preflight",
            )

        outcome: OCIExecutionResult | OCIExecutionError
        create_result = _ProcessResult(b"", b"", None)
        create_attempted = False
        try:
            try:
                try:
                    subject = inventory_local(workspace_path)
                except InventoryError as exc:
                    raise VerificationError(
                        f"cannot verify workspace identity: {exc}"
                    ) from exc
                if subject["tree_digest"] != expected_tree_digest:
                    raise VerificationError(
                        "workspace tree digest does not match the expected subject"
                    )
                verified_subject_digest = subject["tree_digest"]
                create_attempted = True
                create_result = _run_bounded(
                    create_argv,
                    timeout=_DOCKER_TIMEOUT_SECONDS,
                    stdout_limit=_MAX_INSPECT_BYTES,
                    stderr_limit=_MAX_INSPECT_BYTES,
                    shared_limit=_MAX_INSPECT_BYTES,
                    env=environment,
                )
                _require_command(create_result, "docker create")
                if create_result.returncode != 0:
                    raise VerificationError(
                        "docker create failed: "
                        + create_result.stderr.decode(
                            "utf-8", errors="replace"
                        ).strip()
                    )
                candidate_id = create_result.stdout.decode("ascii").strip()
                if _CONTAINER_ID.fullmatch(candidate_id) is None:
                    raise VerificationError("docker create returned an invalid container ID")
                container_id = candidate_id
            except (OSError, UnicodeDecodeError, VerificationError) as exc:
                outcome = failure("CREATE_FAILED", str(exc))
            else:
                try:
                    container, raw_prestart_container_inspect = _inspect_container(
                        docker.path,
                        container_id,
                        environment,
                    )
                    _verify_container(
                        container,
                        container_id=container_id,
                        baseline=baseline,
                        verification=verification,
                        workspace=workspace_path,
                        arguments=arguments,
                        expected_environment=expected_environment,
                        phase="prestart",
                    )
                except (OSError, VerificationError) as exc:
                    outcome = failure("CONTAINER_POLICY_MISMATCH", str(exc))
                else:
                    try:
                        start_result = _run_bounded(
                            [
                                os.fspath(docker.path),
                                "start",
                                "--attach",
                                container_id,
                            ],
                            timeout=float(timeout_seconds),
                            stdout_limit=output_limit_bytes,
                            stderr_limit=output_limit_bytes,
                            shared_limit=output_limit_bytes,
                            env=environment,
                        )
                    except OSError as exc:
                        outcome = failure("START_FAILED", str(exc))
                    else:
                        retained_error = (
                            (
                                "OUTPUT_LIMIT_EXCEEDED",
                                (
                                    "container output exceeded "
                                    f"{output_limit_bytes} bytes"
                                ),
                            )
                            if start_result.output_exceeded
                            else (
                                (
                                    "TIMEOUT",
                                    (
                                        "container exceeded "
                                        f"{float(timeout_seconds):g} seconds"
                                    ),
                                )
                                if start_result.timed_out
                                else None
                            )
                        )
                        if start_result.termination_failed:
                            outcome = failure(
                                "TERMINATION_FAILED",
                                "docker start did not terminate after SIGKILL",
                            )
                        elif (
                            retained_error is None
                            and start_result.io_error is not None
                        ):
                            outcome = failure(
                                "OUTPUT_READ_FAILED", start_result.io_error
                            )
                        elif (
                            retained_error is None
                            and start_result.returncode is None
                        ):
                            outcome = failure(
                                "START_FAILED", "docker start returned no exit status"
                            )
                        else:
                            try:
                                if retained_error is None:
                                    (
                                        container,
                                        raw_postrun_container_inspect,
                                    ) = _inspect_container(
                                        docker.path,
                                        container_id,
                                        environment,
                                    )
                                else:
                                    (
                                        container,
                                        raw_postrun_container_inspect,
                                    ) = _stop_and_inspect_container(
                                        docker.path,
                                        container_id,
                                        environment,
                                    )
                                _verify_container(
                                    container,
                                    container_id=container_id,
                                    baseline=baseline,
                                    verification=verification,
                                    workspace=workspace_path,
                                    arguments=arguments,
                                    expected_environment=expected_environment,
                                    phase="postrun",
                                )
                                try:
                                    subject_after = inventory_local(workspace_path)
                                except InventoryError as exc:
                                    raise VerificationError(
                                        f"cannot re-verify workspace identity: {exc}"
                                    ) from exc
                                if subject_after["tree_digest"] != expected_tree_digest:
                                    raise VerificationError(
                                        "workspace tree digest changed during execution"
                                    )
                                if retained_error is not None:
                                    state = _object(
                                        container.get("State"), "container State"
                                    )
                                    exit_code = state.get("ExitCode")
                                    if isinstance(exit_code, bool) or not isinstance(
                                        exit_code, int
                                    ):
                                        raise VerificationError(
                                            "container exit code is invalid"
                                        )
                                    start_result = _ProcessResult(
                                        stdout=start_result.stdout,
                                        stderr=start_result.stderr,
                                        returncode=exit_code,
                                        timed_out=start_result.timed_out,
                                        output_exceeded=(
                                            start_result.output_exceeded
                                        ),
                                    )
                                assert start_result.returncode is not None
                                _verify_exit_state(container, start_result.returncode)
                            except (OSError, VerificationError) as exc:
                                outcome = failure(
                                    "POST_EXECUTION_INSPECT_FAILED", str(exc)
                                )
                            else:
                                if retained_error is not None:
                                    outcome = failure(*retained_error)
                                else:
                                    outcome = OCIExecutionResult(
                                        baseline_name=baseline["name"],
                                        version=baseline["version"],
                                        docker_path=os.fspath(docker.path),
                                        docker_digest=docker.digest,
                                        image_reference=verification.image_reference,
                                        index_digest=baseline["image"]["index_digest"],
                                        platform_manifest_digest=baseline["image"][
                                            "platform_manifest_digest"
                                        ],
                                        config_digest=baseline["image"]["config_digest"],
                                        container_id=container_id,
                                        raw_lock=raw_lock,
                                        selected_baseline_json=selected_json,
                                        effective_config_json=effective_config_json,
                                        raw_index_inspect=verification.raw_index_inspect,
                                        raw_platform_inspect=(
                                            verification.raw_platform_inspect
                                        ),
                                        raw_oci_index_json=(
                                            verification.raw_oci_index_json
                                        ),
                                        raw_oci_platform_manifest_json=(
                                            verification.raw_oci_platform_manifest_json
                                        ),
                                        raw_build_provenance_manifest_json=(
                                            verification.raw_build_provenance_manifest_json
                                        ),
                                        raw_config_json=verification.raw_config_json,
                                        raw_prestart_container_inspect=(
                                            raw_prestart_container_inspect
                                        ),
                                        raw_postrun_container_inspect=(
                                            raw_postrun_container_inspect
                                        ),
                                        raw_stdout=start_result.stdout,
                                        raw_stderr=start_result.stderr,
                                        returncode=start_result.returncode,
                                        verified_subject_digest=(
                                            verified_subject_digest
                                        ),
                                        raw_pre_context_inspect=(
                                            pre_runner.raw_context
                                        ),
                                        raw_pre_daemon_version=(
                                            pre_runner.raw_version
                                        ),
                                        raw_pre_daemon_info=pre_runner.raw_info,
                                        runner_identity_json=runner_identity_json,
                                    )
        finally:
            cleanup_error = (
                _cleanup_container(docker.path, container_name, environment)
                if create_attempted
                else None
            )
        post_identity_error: str | None = None
        try:
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=environment,
                expected=runner_identity,
                evidence=post_runner,
            )
        except (
            DockerIdentityError,
            OSError,
            subprocess.SubprocessError,
            VerificationError,
        ) as exc:
            post_identity_error = str(exc)
        docker_identity_error: str | None = None
        try:
            _verify_docker_unchanged(docker)
        except (OSError, VerificationError) as exc:
            docker_identity_error = str(exc)

        if cleanup_error is not None:
            outcome = failure("CLEANUP_FAILED", cleanup_error)
        elif post_identity_error is not None:
            outcome = failure(
                "RUNNER_IDENTITY_CHANGED",
                post_identity_error,
            )
        elif docker_identity_error is not None:
            outcome = failure("DOCKER_IDENTITY_CHANGED", docker_identity_error)
        elif isinstance(outcome, OCIExecutionError):
            outcome = failure(outcome.error_code, outcome.message)
        else:
            outcome = replace(
                outcome,
                raw_post_context_inspect=post_runner.raw_context,
                raw_post_daemon_version=post_runner.raw_version,
                raw_post_daemon_info=post_runner.raw_info,
            )
        return outcome


def _canonical_json(document: Any) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def verify(docker: DockerExecutable, baseline: dict[str, Any]) -> dict[str, str]:
    """Compatibility wrapper for the standalone image-verification report."""

    with tempfile.TemporaryDirectory(prefix="aragorn-docker-control-") as control:
        pre = _RunnerReceiptBuffer()
        post = _RunnerReceiptBuffer()
        discovery_environment, execution_environment, identity = (
            _capture_pre_runner_identity(docker, Path(control), pre)
        )
        try:
            verify_image(
                docker.path,
                baseline,
                env=execution_environment,
            )
        finally:
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=execution_environment,
                expected=identity,
                evidence=post,
            )
    image = baseline["image"]
    return {
        "name": baseline["name"],
        "index_digest": image["index_digest"],
        "platform_manifest_digest": image["platform_manifest_digest"],
        "config_digest": image["config_digest"],
        "build_provenance_manifest_digest": image[
            "build_provenance_manifest_digest"
        ],
        "attestation_status": baseline["attestation_status"],
    }


def main() -> int:
    docker = resolve_docker()
    _raw_lock, baselines = load_baseline_lock()
    verified = [verify(docker, baseline) for baseline in baselines]
    _verify_docker_unchanged(docker)
    print(
        json.dumps(
            {"schema": "aragorn/baseline-image-verification/v1", "images": verified},
            sort_keys=True,
        )
    )
    return 0
