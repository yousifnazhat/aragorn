"""Retain and replay one pinned gVisor runtime-path smoke."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from .analyze import _reject_duplicate_json_keys, _reject_json_constant
from .cas import CAS, CASError
from .docker_identity import DockerIdentityError, normalize_docker_identity
from .oci_runtime import (
    VerificationError,
    _capture_docker_document,
    _capture_post_runner_identity,
    _capture_pre_runner_identity,
    _cleanup_container,
    _inspect_container,
    _require_bounded_tmpfs_mount,
    _require_command,
    _run_bounded,
    _RunnerReceiptBuffer,
    _verify_container_security_profile,
    _verify_docker_unchanged,
    resolve_docker,
)
from .oci_worker_protocol import WorkerProtocolError, canonical_json

ROOT = Path(__file__).parents[2]
LOCK = ROOT / "benchmark" / "gvisor-runtime-v1.lock.json"
CANARY_LOCK = ROOT / "benchmark" / "gvisor-detonation-canary-v1.lock.json"
SCHEMA = "aragorn/gvisor-runtime-smoke-receipt/v1"
LOCK_SCHEMA = "aragorn/gvisor-runtime-lock/v1"
IMPLEMENTATION_SCHEMA = "aragorn/gvisor-runtime-implementation/v1"
CANARY_SCHEMA = "aragorn/gvisor-detonation-canary-receipt/v1"
CANARY_LOCK_SCHEMA = "aragorn/gvisor-detonation-canary-lock/v1"
CANARY_IMPLEMENTATION_SCHEMA = "aragorn/gvisor-detonation-canary-implementation/v1"
CANARY_RUN_REQUEST_SCHEMA = "aragorn/gvisor-detonation-canary-run-request/v1"
CANARY_LOG_MANIFEST_SCHEMA = "aragorn/gvisor-detonation-canary-log-manifest/v1"
CANARY_CLEANUP_SCHEMA = "aragorn/gvisor-detonation-canary-cleanup/v1"
ARTIFACT_SCHEMA = "aragorn/gvisor-acquired-artifact-receipt/v1"
ARTIFACT_SCHEMA_V2 = "aragorn/gvisor-acquired-artifact-receipt/v2"
ARTIFACT_IMPLEMENTATION_SCHEMA = "aragorn/gvisor-acquired-artifact-implementation/v1"
ARTIFACT_RUN_REQUEST_SCHEMA = "aragorn/gvisor-acquired-artifact-run-request/v1"
ARTIFACT_RUN_REQUEST_SCHEMA_V2 = "aragorn/gvisor-acquired-artifact-run-request/v2"
ARTIFACT_NORMALIZATION_PROFILE = "successful-openat-execve-set/v1"
AUTHORITY = (
    "RUNTIME_PATH_SMOKE_ONLY_NOT_RUNTIME_ATTESTATION_ISOLATION_OR_DETONATION_AUTHORITY"
)
LOCK_AUTHORITY = "PIN_ONLY_NOT_RUNTIME_ATTESTATION"
CANARY_AUTHORITY = (
    "SAME_RUN_PINNED_GVISOR_CANARY_EVIDENCE_ONLY_NOT_CAPTURE_COMPLETENESS_RUNTIME_"
    "ATTESTATION_ISOLATION_OR_ADMISSION_AUTHORITY"
)
CANARY_LOCK_AUTHORITY = "PIN_ONLY_NOT_RUNTIME_ATTESTATION_OR_DETONATION_AUTHORITY"
ARTIFACT_AUTHORITY = (
    "ONE_INERT_ACQUIRED_ARTIFACT_SAME_RUN_EVIDENCE_ONLY_NOT_CAPTURE_COMPLETENESS_"
    "RUNTIME_ATTESTATION_ISOLATION_BACKEND_QUALIFICATION_ADMISSION_OR_PHASE2_EXIT_"
    "AUTHORITY"
)

_MAX_LOCK_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_JSON_EVIDENCE_BYTES = 1024 * 1024
_MAX_PROCESS_BYTES = 64 * 1024
_MAX_STREAM_BYTES = 64 * 1024
_MAX_IMPLEMENTATION_MANIFEST_BYTES = 64 * 1024
_MAX_IMPLEMENTATION_SOURCE_BYTES = 1024 * 1024
_MAX_RUNTIME_BINARY_BYTES = 128 * 1024 * 1024
_MAX_DOCKER_BINARY_BYTES = 512 * 1024 * 1024
_MAX_CANARY_RUN_REQUEST_BYTES = 64 * 1024
_MAX_CANARY_LOG_MANIFEST_BYTES = 64 * 1024
_MAX_CANARY_CLEANUP_BYTES = 4 * 1024
_MAX_ARTIFACT_BYTES = 64 * 1024
_CANARY_LOG_STORE_BYTES = 8 * 1024 * 1024
_CANARY_LOG_STORE_INODES = 32
_DOCKER_TIMEOUT_SECONDS = 30.0
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA512 = re.compile(r"sha512:[0-9a-f]{128}\Z")
_GIT = re.compile(r"[0-9a-f]{40}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_LIMITS = {
    "runtime_version": _MAX_STREAM_BYTES,
    "installed_binaries": _MAX_JSON_EVIDENCE_BYTES,
    "daemon_config": _MAX_JSON_EVIDENCE_BYTES,
    "runtime_registration": _MAX_JSON_EVIDENCE_BYTES,
    "docker_executable": _MAX_JSON_EVIDENCE_BYTES,
    "helper_implementations": _MAX_JSON_EVIDENCE_BYTES,
    "runner_pre": _MAX_JSON_EVIDENCE_BYTES,
    "runner_post": _MAX_JSON_EVIDENCE_BYTES,
    "image_inspect": _MAX_JSON_EVIDENCE_BYTES,
    "container_pre_inspect": _MAX_JSON_EVIDENCE_BYTES,
    "container_live_inspect": _MAX_JSON_EVIDENCE_BYTES,
    "container_processes": _MAX_PROCESS_BYTES,
    "container_stdout": _MAX_STREAM_BYTES,
    "container_stderr": _MAX_STREAM_BYTES,
    "container_post_inspect": _MAX_JSON_EVIDENCE_BYTES,
}
_CANARY_EVIDENCE_LIMITS = {
    **_EVIDENCE_LIMITS,
    "backend_log_manifest": _MAX_CANARY_LOG_MANIFEST_BYTES,
    "container_cleanup": _MAX_CANARY_CLEANUP_BYTES,
}
_ARTIFACT_EVIDENCE_LIMITS = {
    **_CANARY_EVIDENCE_LIMITS,
    "artifact_source": _MAX_JSON_EVIDENCE_BYTES,
}
_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "lock_digest",
    "implementation_digest",
    "run_id",
    "captured_at",
    "evidence",
    "status",
}
_CANARY_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "lock_digest",
    "runtime_lock_digest",
    "implementation_digest",
    "run_id",
    "captured_at",
    "subject_digest",
    "input_manifest_digest",
    "input_tree_digest",
    "run_request_digest",
    "normalizer_implementation_digest",
    "capability_diff_receipt_digest",
    "evidence",
    "status",
}
_ARTIFACT_RECEIPT_FIELDS = {
    *_CANARY_RECEIPT_FIELDS,
    "quarantine_receipt_digest",
    "gateway_profile_digest",
    "source_closure_digest",
    "entrypoint",
}
_ARTIFACT_RECEIPT_V2_FIELDS = {
    *_ARTIFACT_RECEIPT_FIELDS,
    "normalization_profile",
}
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CAPTURED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_HELPER_MODULES = (
    "__init__.py",
    "acquire.py",
    "analyze.py",
    "cas.py",
    "docker_identity.py",
    "oci_runtime.py",
    "oci_worker_protocol.py",
)
_IMPLEMENTATION_MODULES = ("gvisor_runtime.py", *_HELPER_MODULES)
_CANARY_HELPER_MODULES = (
    *_HELPER_MODULES,
    "behavior_capability_diff.py",
    "detonation_observation.py",
)
_CANARY_IMPLEMENTATION_MODULES = ("gvisor_runtime.py", *_CANARY_HELPER_MODULES)
_ARTIFACT_HELPER_MODULES = (
    *_CANARY_HELPER_MODULES,
    "artifact_closure.py",
    "benchmark_handoff_v2.py",
    "github_quarantine_receipt.py",
    "github_source_proof.py",
)
_ARTIFACT_IMPLEMENTATION_MODULES = (
    "gvisor_runtime.py",
    *_ARTIFACT_HELPER_MODULES,
)
_ARTIFACT_ENTRYPOINT = "run.sh"
_ARTIFACT_TARGET = "/aragorn-input/run.sh"
_ARTIFACT_TREE_DIGEST = (
    "sha256:633b89b98302bb94817ab43154c8a57a5412b8ee8e3e26fb005fdf8aff247344"
)
_ARTIFACT_ENTRYPOINT_DIGEST = (
    "sha256:90c00b307b706ca7357a2e46aaa5f11132cb3223861cd0401f39782c7b7f6fb8"
)
_ARTIFACT_ENTRYPOINT_SIZE = 79
_ARTIFACT_GITHUB_SOURCE = {
    "host": "github.com",
    "owner": "yousifnazhat",
    "repository": "agent-skill-inert-fixture",
    "skill_path": ".",
}
_TRACE_MESSAGE = re.compile(
    r"strace\.go:\d+\] \[\s*(?P<tgid>\d+):\s*(?P<tid>\d+)\] "
    r"(?P<process>\S+) (?P<phase>[EX]) (?P<body>.+)\Z"
)
_TRACE_CALL = re.compile(r"(?P<syscall>openat|execve)\((?P<arguments>.*)\)\Z")
_TRACE_DURATION = re.compile(r"[0-9.]+(?:ns|µs|ms|s)\Z")
_TRACE_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}\Z"
)
_TRACE_FAILURE = re.compile(r"-[1-9][0-9]* errno=[1-9][0-9]* \(.+\)\Z")
# ponytail: fixed-profile grammar; version the profile before widening trace syntax.
_TRACE_OPENAT_ARGUMENTS = re.compile(
    r"AT_FDCWD /, 0x[0-9a-f]+ (?P<path>/[^\x00\r\n]*), "
    r"(?P<flags>[A-Z0-9_|x]+), 0o[0-7]+\Z"
)
_TRACE_EXECVE_ARGUMENTS = re.compile(
    r"0x[0-9a-f]+ (?P<path>/[^,\x00\r\n]*), 0x[0-9a-f]+ "
    r"(?P<argv>\[.*\]), 0x[0-9a-f]+ (?P<environment>\[.*\])\Z"
)
_TracePair = tuple[tuple[int, int], str, str, str, str, int, int]


@dataclass(frozen=True, slots=True)
class _FileCapability:
    path: Path
    descriptor: int
    digest: str
    identity: tuple[int, int, int, int, int, int, int, int]
    metadata: dict[str, int | str]


@dataclass(frozen=True, slots=True)
class _VerifiedCanary:
    receipt: dict[str, Any]
    lock: dict[str, Any]
    implementation_files: dict[str, str]
    evidence: dict[str, bytes]
    identity: dict[str, str]
    observation_bindings: dict[str, str]


@dataclass(frozen=True, slots=True)
class _AcquiredArtifact:
    quarantine_receipt_digest: str
    gateway_profile_digest: str
    source_closure_digest: str
    manifest_digest: str
    tree_digest: str
    entrypoint_digest: str
    entrypoint_size: int
    materialized_path: Path


class GVisorRuntimeError(ValueError):
    """A gVisor pin or runtime-path smoke failed closed."""


def load_gvisor_runtime_lock(
    path: str | Path = LOCK,
) -> tuple[bytes, dict[str, Any]]:
    """Load and validate the signed-repository trust pin."""

    raw = _read_lock(path, "gVisor runtime")
    return raw, _runtime_lock(raw)


def load_gvisor_detonation_canary_lock(
    path: str | Path = CANARY_LOCK,
) -> tuple[bytes, dict[str, Any]]:
    """Load and validate the fixed traced-canary trust pin."""

    raw = _read_lock(path, "gVisor detonation canary")
    return raw, _canary_lock(raw)


def _read_lock(path: str | Path, label: str) -> bytes:
    try:
        candidate = Path(path).expanduser().resolve(strict=True)
        with candidate.open("rb") as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= _MAX_LOCK_BYTES
            ):
                raise GVisorRuntimeError(f"{label} lock is not a bounded regular file")
            raw = source.read(_MAX_LOCK_BYTES + 1)
            if len(raw) != metadata.st_size or os.fstat(source.fileno()) != metadata:
                raise GVisorRuntimeError(f"{label} lock changed while read")
    except (OSError, RuntimeError) as exc:
        raise GVisorRuntimeError(f"cannot read {label} lock: {exc}") from exc
    return raw


def _retain_implementation(
    cas: CAS,
    *,
    expected_digest: str,
    schema: str,
    modules: tuple[str, ...],
    opened: list[_FileCapability],
    label: str,
) -> tuple[dict[str, str], dict[str, _FileCapability]]:
    source_root = Path(__file__).resolve(strict=True).parent
    capabilities: dict[str, _FileCapability] = {}
    for module_name in modules:
        capability = _open_file_capability(
            source_root / module_name,
            expected_digest=None,
            maximum=_MAX_IMPLEMENTATION_SOURCE_BYTES,
            executable=False,
            label=f"{label} implementation {module_name}",
        )
        opened.append(capability)
        capabilities[module_name] = capability
    files = {module: capability.digest for module, capability in capabilities.items()}
    raw = canonical_json({"schema": schema, "files": files})
    if _raw_digest(raw) != expected_digest:
        raise GVisorRuntimeError(f"{label} implementation identity changed")
    cas.put_expected(
        BytesIO(raw),
        expected_digest=expected_digest,
        max_bytes=_MAX_IMPLEMENTATION_MANIFEST_BYTES,
    )
    for capability in capabilities.values():
        cas.put_expected(
            BytesIO(_read_open_file(capability, _MAX_IMPLEMENTATION_SOURCE_BYTES)),
            expected_digest=capability.digest,
            max_bytes=_MAX_IMPLEMENTATION_SOURCE_BYTES,
        )
    return files, capabilities


def collect_gvisor_runtime_smoke(
    cas: CAS,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    lock_path: str | Path = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
) -> str:
    """Execute, retain, and replay one fixed gVisor runtime-path smoke."""

    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise GVisorRuntimeError("gVisor runtime capture requires Linux root")
    expected_lock = _digest(expected_lock_digest, "expected lock")
    expected_implementation = _digest(
        expected_verifier_implementation_digest,
        "expected verifier implementation",
    )
    opened: list[_FileCapability] = []
    container_name: str | None = None
    docker_environment: dict[str, str] | None = None
    try:
        implementation_files, implementation_capabilities = _retain_implementation(
            cas,
            expected_digest=expected_implementation,
            schema=IMPLEMENTATION_SCHEMA,
            modules=_IMPLEMENTATION_MODULES,
            opened=opened,
            label="gVisor runtime",
        )
        helper_implementations = [
            {
                "module": module,
                "file": implementation_capabilities[module].metadata,
            }
            for module in _HELPER_MODULES
        ]
        lock_file = _open_file_capability(
            Path(lock_path).expanduser().resolve(strict=True),
            expected_digest=expected_lock,
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor runtime lock",
            retain=cas,
        )
        opened.append(lock_file)
        lock_raw = _read_open_file(lock_file, _MAX_LOCK_BYTES)
        lock = _runtime_lock(lock_raw)

        installed = []
        runsc: _FileCapability | None = None
        for binary in lock["binaries"]:
            capability = _open_file_capability(
                Path(binary["path"]),
                expected_digest=binary["digest"],
                maximum=_MAX_RUNTIME_BINARY_BYTES,
                executable=True,
                label=f"gVisor binary {binary['path']}",
            )
            opened.append(capability)
            installed.append(capability.metadata)
            if binary["path"] == lock["runtime"]["path"]:
                runsc = capability
        if runsc is None:
            raise GVisorRuntimeError("gVisor runtime binary is absent")
        daemon = _open_file_capability(
            Path("/etc/docker/daemon.json"),
            expected_digest=lock["daemon_config_digest"],
            maximum=_MAX_JSON_EVIDENCE_BYTES,
            executable=False,
            label="Docker daemon configuration",
        )
        opened.append(daemon)

        docker = resolve_docker(docker_executable)
        _verify_protected_path(docker.path)
        docker_metadata = _path_metadata(docker.path, docker.digest)
        run_id = secrets.token_hex(16)
        captured_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        evidence: dict[str, bytes] = {
            "installed_binaries": canonical_json(installed),
            "daemon_config": _read_open_file(daemon, _MAX_JSON_EVIDENCE_BYTES),
            "docker_executable": canonical_json(docker_metadata),
            "helper_implementations": canonical_json(helper_implementations),
        }
        pre_runner = _RunnerReceiptBuffer()
        post_runner = _RunnerReceiptBuffer()

        with tempfile.TemporaryDirectory(prefix="aragorn-gvisor-control-") as control:
            control_path = Path(control)
            runtime_version = _run_bounded(
                [os.fspath(runsc.path), "--version"],
                timeout=_DOCKER_TIMEOUT_SECONDS,
                stdout_limit=_MAX_STREAM_BYTES,
                stderr_limit=_MAX_STREAM_BYTES,
                shared_limit=2 * _MAX_STREAM_BYTES,
                env=_command_environment(control_path),
            )
            _require_success(runtime_version, "runsc --version")
            if runtime_version.stderr:
                raise GVisorRuntimeError("runsc --version produced stderr")
            evidence["runtime_version"] = runtime_version.stdout

            discovery_environment, docker_environment, runner_identity = (
                _capture_pre_runner_identity(docker, control_path, pre_runner)
            )
            evidence["runner_pre"] = _runner_bundle(pre_runner)
            evidence["runtime_registration"] = _capture_docker_document(
                docker,
                ("info", "--format", '{{json (index .Runtimes "runsc-systrap")}}'),
                env=docker_environment,
                label="Docker runtime registration",
            )
            evidence["image_inspect"] = _docker_output(
                docker.path,
                ("image", "inspect", lock["image"]["reference"]),
                env=docker_environment,
                label="Docker image inspect",
            )

            container_name = f"aragorn-gvisor-smoke-{run_id}"
            create = _docker_result(
                docker.path,
                _create_arguments(
                    image=lock["image"]["reference"],
                    profile=lock["smoke"],
                    runtime=lock["runtime"]["name"],
                    container_name=container_name,
                    run_label=f"aragorn.runtime-smoke.run_id={run_id}",
                ),
                env=docker_environment,
                label="Docker create",
            )
            try:
                container_id = create.stdout.decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise GVisorRuntimeError("Docker create returned non-ASCII") from exc
            if _CONTAINER.fullmatch(container_id) is None:
                raise GVisorRuntimeError(
                    "Docker create returned an invalid container ID"
                )

            pre, evidence["container_pre_inspect"] = _inspect_container(
                docker.path, container_id, docker_environment
            )
            _verify_container(lock, pre, phase="prestart", run_id=run_id)
            started = _docker_result(
                docker.path,
                ("start", container_id),
                env=docker_environment,
                label="Docker start",
            )
            if started.stdout.strip() != container_id.encode("ascii"):
                raise GVisorRuntimeError(
                    "Docker start returned a different container ID"
                )

            live, evidence["container_live_inspect"] = _wait_for_live_container(
                docker.path, container_id, docker_environment
            )
            _verify_container(lock, live, phase="live", run_id=run_id)
            evidence["container_processes"] = _capture_processes(
                lock,
                container_id=container_id,
                sandbox_pid=live["State"]["Pid"],
                runsc=runsc,
            )
            live_after, _raw_live_after = _inspect_container(
                docker.path, container_id, docker_environment
            )
            _verify_container(lock, live_after, phase="live", run_id=run_id)
            if live_after["State"]["Pid"] != live["State"]["Pid"]:
                raise GVisorRuntimeError("gVisor sandbox PID changed during capture")

            waited = _docker_result(
                docker.path,
                ("wait", container_id),
                env=docker_environment,
                label="Docker wait",
                timeout=20.0,
            )
            if waited.stdout != b"0\n" or waited.stderr:
                raise GVisorRuntimeError("gVisor smoke did not exit cleanly")
            logs = _docker_result(
                docker.path,
                ("logs", container_id),
                env=docker_environment,
                label="Docker logs",
            )
            evidence["container_stdout"] = logs.stdout
            evidence["container_stderr"] = logs.stderr
            post, evidence["container_post_inspect"] = _inspect_container(
                docker.path, container_id, docker_environment
            )
            _verify_container(lock, post, phase="postrun", run_id=run_id)

            _cleanup_container_strict(
                docker.path,
                container_name,
                docker_environment,
                label="Docker",
            )
            container_name = None
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=docker_environment,
                expected=runner_identity,
                evidence=post_runner,
            )
            evidence["runner_post"] = _runner_bundle(post_runner)

        _verify_docker_unchanged(docker)
        for capability in opened:
            _verify_file_capability(capability)
        captured = _evidence_snapshot(evidence)
        _verify_evidence(
            lock,
            captured,
            run_id=run_id,
            implementation_files=implementation_files,
        )
        evidence_digests = {
            name: cas.put(BytesIO(raw), max_bytes=_EVIDENCE_LIMITS[name])
            for name, raw in sorted(captured.items())
        }
        receipt = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "lock_digest": expected_lock,
            "implementation_digest": expected_implementation,
            "run_id": run_id,
            "captured_at": captured_at,
            "evidence": evidence_digests,
            "status": "PASS",
        }
        return cas.put(BytesIO(canonical_json(receipt)), max_bytes=_MAX_RECEIPT_BYTES)
    except GVisorRuntimeError:
        raise
    except (
        CASError,
        DockerIdentityError,
        OSError,
        RuntimeError,
        VerificationError,
        WorkerProtocolError,
    ) as exc:
        raise GVisorRuntimeError(f"gVisor runtime capture failed: {exc}") from exc
    finally:
        try:
            if container_name is not None and docker_environment is not None:
                _cleanup_container_strict(
                    docker.path,
                    container_name,
                    docker_environment,
                    label="Docker",
                )
        finally:
            for capability in reversed(opened):
                os.close(capability.descriptor)


def collect_gvisor_detonation_canary(
    cas: CAS,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    lock_path: str | Path = CANARY_LOCK,
    runtime_lock_path: str | Path = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
) -> str:
    """Capture one fixed same-run gVisor trace and replay its category diff."""

    return _collect_gvisor_detonation(
        cas,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
        lock_path=lock_path,
        runtime_lock_path=runtime_lock_path,
        docker_executable=docker_executable,
        artifact=None,
        artifact_normalization_profile=None,
    )


def collect_gvisor_acquired_artifact(
    cas: CAS,
    source_cas: CAS,
    *,
    expected_quarantine_receipt_digest: str,
    expected_manifest_digest: str,
    expected_tree_digest: str,
    expected_gateway_profile_digest: str,
    expected_entrypoint_digest: str,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    normalization_profile: str | None = None,
    lock_path: str | Path = CANARY_LOCK,
    runtime_lock_path: str | Path = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
) -> str:
    """Execute the one pinned inert acquired-artifact profile under gVisor."""

    _artifact_normalization_profile(normalization_profile)
    source_root = source_cas.root.resolve()
    output_root = cas.root.resolve()
    if (
        not source_cas.read_only
        or source_root.is_relative_to(output_root)
        or output_root.is_relative_to(source_root)
    ):
        raise GVisorRuntimeError(
            "acquired artifact source must be a separate read-only quarantine CAS"
        )
    receipt_digest = _digest(
        expected_quarantine_receipt_digest,
        "expected quarantine receipt",
    )
    manifest_digest = _digest(expected_manifest_digest, "expected source manifest")
    tree_digest = _digest(expected_tree_digest, "expected source tree")
    gateway_profile_digest = _digest(
        expected_gateway_profile_digest,
        "expected gateway profile",
    )
    entrypoint_digest = _digest(
        expected_entrypoint_digest,
        "expected artifact entrypoint",
    )
    if (
        tree_digest != _ARTIFACT_TREE_DIGEST
        or entrypoint_digest != _ARTIFACT_ENTRYPOINT_DIGEST
    ):
        raise GVisorRuntimeError("acquired artifact fixed profile changed")
    try:
        from .artifact_closure import load_verified_retained_manifest
        from .github_quarantine_receipt import (
            derive_github_quarantine_closure,
            verify_github_quarantine_receipt,
        )

        quarantine = verify_github_quarantine_receipt(
            source_cas,
            receipt_digest,
            expected_manifest_digest=manifest_digest,
            expected_gateway_profile_digest=gateway_profile_digest,
        )
        manifest = load_verified_retained_manifest(source_cas, manifest_digest)
        if (
            manifest["tree_digest"] != tree_digest
            or quarantine["tree_digest"] != tree_digest
        ):
            raise GVisorRuntimeError("acquired artifact tree identity changed")
        entrypoint = _fixed_artifact_entrypoint(manifest)
        closure = derive_github_quarantine_closure(
            source_cas,
            receipt_digest,
            expected_manifest_digest=manifest_digest,
            expected_gateway_profile_digest=gateway_profile_digest,
        )
        for digest, size in closure.items():
            cas.put_expected(
                BytesIO(source_cas.read(digest, max_bytes=size)),
                expected_digest=digest,
                max_bytes=size,
            )
        with tempfile.TemporaryDirectory(
            prefix="aragorn-gvisor-artifact-",
            dir="/run",
        ) as materialized:
            materialized_path = cas.materialize(
                entrypoint_digest,
                Path(materialized) / _ARTIFACT_ENTRYPOINT,
                root=materialized,
            )
            artifact = _AcquiredArtifact(
                quarantine_receipt_digest=receipt_digest,
                gateway_profile_digest=gateway_profile_digest,
                source_closure_digest=quarantine["source_closure_digest"],
                manifest_digest=manifest_digest,
                tree_digest=tree_digest,
                entrypoint_digest=entrypoint_digest,
                entrypoint_size=entrypoint["size"],
                materialized_path=materialized_path,
            )
            return _collect_gvisor_detonation(
                cas,
                expected_lock_digest=expected_lock_digest,
                expected_verifier_implementation_digest=(
                    expected_verifier_implementation_digest
                ),
                lock_path=lock_path,
                runtime_lock_path=runtime_lock_path,
                docker_executable=docker_executable,
                artifact=artifact,
                artifact_normalization_profile=normalization_profile,
            )
    except GVisorRuntimeError:
        raise
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorRuntimeError(
            f"cannot prepare acquired artifact capture: {exc}"
        ) from exc


def _collect_gvisor_detonation(
    cas: CAS,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    lock_path: str | Path,
    runtime_lock_path: str | Path,
    docker_executable: str | os.PathLike[str],
    artifact: _AcquiredArtifact | None,
    artifact_normalization_profile: str | None,
) -> str:
    """Capture one fixed profile without accepting caller-supplied observations."""

    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise GVisorRuntimeError("gVisor detonation canary capture requires Linux root")
    expected_lock = _digest(expected_lock_digest, "expected canary lock")
    expected_implementation = _digest(
        expected_verifier_implementation_digest,
        "expected canary verifier implementation",
    )
    opened: list[_FileCapability] = []
    container_name: str | None = None
    trace_container_id: str | None = None
    canary_lock: dict[str, Any] | None = None
    docker_environment: dict[str, str] | None = None
    docker_path: Path | None = None
    coordination = -1
    try:
        implementation_schema = (
            ARTIFACT_IMPLEMENTATION_SCHEMA
            if artifact is not None
            else CANARY_IMPLEMENTATION_SCHEMA
        )
        implementation_modules = (
            _ARTIFACT_IMPLEMENTATION_MODULES
            if artifact is not None
            else _CANARY_IMPLEMENTATION_MODULES
        )
        helper_modules = (
            _ARTIFACT_HELPER_MODULES if artifact is not None else _CANARY_HELPER_MODULES
        )
        capture_label = (
            "gVisor acquired artifact"
            if artifact is not None
            else "gVisor detonation canary"
        )
        coordination = os.open(
            "/run/lock/aragorn-gvisor-canary.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            fcntl.flock(coordination, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GVisorRuntimeError(
                "another gVisor detonation canary capture is active"
            ) from exc

        implementation_files, implementation_capabilities = _retain_implementation(
            cas,
            expected_digest=expected_implementation,
            schema=implementation_schema,
            modules=implementation_modules,
            opened=opened,
            label=capture_label,
        )
        helper_implementations = [
            {
                "module": module,
                "file": implementation_capabilities[module].metadata,
            }
            for module in helper_modules
        ]
        canary_file = _open_file_capability(
            Path(lock_path).expanduser().resolve(strict=True),
            expected_digest=expected_lock,
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor detonation canary lock",
            retain=cas,
        )
        opened.append(canary_file)
        canary_lock = _canary_lock(_read_open_file(canary_file, _MAX_LOCK_BYTES))
        runtime_lock_digest = canary_lock["runtime_lock_digest"]
        runtime_file = _open_file_capability(
            Path(runtime_lock_path).expanduser().resolve(strict=True),
            expected_digest=runtime_lock_digest,
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor runtime lock",
            retain=cas,
        )
        opened.append(runtime_file)
        runtime_lock = _runtime_lock(_read_open_file(runtime_file, _MAX_LOCK_BYTES))

        installed = []
        runsc: _FileCapability | None = None
        for binary in runtime_lock["binaries"]:
            capability = _open_file_capability(
                Path(binary["path"]),
                expected_digest=binary["digest"],
                maximum=_MAX_RUNTIME_BINARY_BYTES,
                executable=True,
                label=f"gVisor binary {binary['path']}",
            )
            opened.append(capability)
            installed.append(capability.metadata)
            if binary["path"] == canary_lock["runtime"]["path"]:
                runsc = capability
        if runsc is None:
            raise GVisorRuntimeError("gVisor canary runtime binary is absent")
        daemon = _open_file_capability(
            Path("/etc/docker/daemon.json"),
            expected_digest=canary_lock["daemon_config_digest"],
            maximum=_MAX_JSON_EVIDENCE_BYTES,
            executable=False,
            label="Docker daemon configuration",
        )
        opened.append(daemon)
        profile = (
            _artifact_profile(canary_lock)
            if artifact is not None
            else canary_lock["canary"]
        )
        bind_mount: dict[str, str] | None = None
        if artifact is not None:
            artifact_file = _open_file_capability(
                artifact.materialized_path.resolve(strict=True),
                expected_digest=artifact.entrypoint_digest,
                maximum=_MAX_ARTIFACT_BYTES,
                executable=False,
                label="materialized acquired artifact entrypoint",
            )
            opened.append(artifact_file)
            bind_mount = {
                "source": os.fspath(artifact_file.path),
                "destination": _ARTIFACT_TARGET,
            }

        docker = resolve_docker(docker_executable)
        docker_path = docker.path
        _verify_protected_path(docker.path)
        run_id = secrets.token_hex(16)
        captured_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        evidence: dict[str, bytes] = {
            "installed_binaries": canonical_json(installed),
            "daemon_config": _read_open_file(daemon, _MAX_JSON_EVIDENCE_BYTES),
            "docker_executable": canonical_json(
                _path_metadata(docker.path, docker.digest)
            ),
            "helper_implementations": canonical_json(helper_implementations),
        }
        if artifact is not None:
            evidence["artifact_source"] = canonical_json(artifact_file.metadata)
        pre_runner = _RunnerReceiptBuffer()
        post_runner = _RunnerReceiptBuffer()

        with tempfile.TemporaryDirectory(
            prefix="aragorn-gvisor-canary-control-"
        ) as control:
            control_path = Path(control)
            runtime_version = _run_bounded(
                [os.fspath(runsc.path), "--version"],
                timeout=_DOCKER_TIMEOUT_SECONDS,
                stdout_limit=_MAX_STREAM_BYTES,
                stderr_limit=_MAX_STREAM_BYTES,
                shared_limit=2 * _MAX_STREAM_BYTES,
                env=_command_environment(control_path),
            )
            _require_success(runtime_version, "runsc --version")
            if runtime_version.stderr:
                raise GVisorRuntimeError("runsc --version produced stderr")
            evidence["runtime_version"] = runtime_version.stdout

            discovery_environment, docker_environment, runner_identity = (
                _capture_pre_runner_identity(docker, control_path, pre_runner)
            )
            evidence["runner_pre"] = _runner_bundle(pre_runner)
            runtime_name = canary_lock["runtime"]["name"]
            evidence["runtime_registration"] = _capture_docker_document(
                docker,
                (
                    "info",
                    "--format",
                    f'{{{{json (index .Runtimes "{runtime_name}")}}}}',
                ),
                env=docker_environment,
                label="Docker canary runtime registration",
            )
            evidence["image_inspect"] = _docker_output(
                docker.path,
                ("image", "inspect", runtime_lock["image"]["reference"]),
                env=docker_environment,
                label="Docker image inspect",
            )
            prior_canary_logs = frozenset(
                path.name
                for path in _canary_log_directory(
                    canary_lock, require_headroom=True
                ).iterdir()
            )

            container_name = (
                f"aragorn-gvisor-artifact-{run_id}"
                if artifact is not None
                else f"aragorn-gvisor-canary-{run_id}"
            )
            run_label = (
                f"aragorn.acquired-artifact.run_id={run_id}"
                if artifact is not None
                else f"aragorn.detonation-canary.run_id={run_id}"
            )
            create = _docker_result(
                docker.path,
                _create_arguments(
                    image=runtime_lock["image"]["reference"],
                    profile=profile,
                    runtime=canary_lock["runtime"]["name"],
                    container_name=container_name,
                    run_label=run_label,
                    tmpfs=profile["tmpfs"],
                    bind_mount=bind_mount,
                ),
                env=docker_environment,
                label="Docker canary create",
            )
            try:
                container_id = create.stdout.decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise GVisorRuntimeError(
                    "Docker canary create returned non-ASCII"
                ) from exc
            if _CONTAINER.fullmatch(container_id) is None:
                raise GVisorRuntimeError(
                    "Docker canary create returned an invalid container ID"
                )
            trace_container_id = container_id
            pre, evidence["container_pre_inspect"] = _inspect_container(
                docker.path, container_id, docker_environment
            )
            _verify_detonation_container(
                runtime_lock,
                canary_lock,
                pre,
                phase="prestart",
                run_id=run_id,
                artifact=artifact,
                bind_mount=bind_mount,
            )
            _require_canary_logs_new(
                canary_lock,
                container_id,
                prior_canary_logs,
            )
            started = _docker_result(
                docker.path,
                ("start", container_id),
                env=docker_environment,
                label="Docker canary start",
            )
            if started.stdout.strip() != container_id.encode("ascii"):
                raise GVisorRuntimeError(
                    "Docker canary start returned a different container ID"
                )

            live, evidence["container_live_inspect"] = _wait_for_live_container(
                docker.path, container_id, docker_environment
            )
            _verify_detonation_container(
                runtime_lock,
                canary_lock,
                live,
                phase="live",
                run_id=run_id,
                artifact=artifact,
                bind_mount=bind_mount,
            )
            evidence["container_processes"] = _capture_processes(
                runtime_lock,
                container_id=container_id,
                sandbox_pid=live["State"]["Pid"],
                runsc=runsc,
            )
            waited = _docker_result(
                docker.path,
                ("wait", container_id),
                env=docker_environment,
                label="Docker canary wait",
                timeout=20.0,
            )
            if waited.stdout != b"0\n" or waited.stderr:
                raise GVisorRuntimeError(
                    "gVisor detonation canary did not exit cleanly"
                )
            logs = _docker_result(
                docker.path,
                ("logs", container_id),
                env=docker_environment,
                label="Docker canary logs",
            )
            evidence["container_stdout"] = logs.stdout
            evidence["container_stderr"] = logs.stderr
            post, evidence["container_post_inspect"] = _inspect_container(
                docker.path, container_id, docker_environment
            )
            _verify_detonation_container(
                runtime_lock,
                canary_lock,
                post,
                phase="postrun",
                run_id=run_id,
                artifact=artifact,
                bind_mount=bind_mount,
            )
            evidence["backend_log_manifest"] = _capture_canary_logs(
                cas, canary_lock, container_id, opened
            )

            _cleanup_container_strict(
                docker.path,
                container_name,
                docker_environment,
                label="Docker canary",
            )
            container_name = None
            evidence["container_cleanup"] = _capture_cleanup_absence(
                docker.path, container_id, docker_environment
            )
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=docker_environment,
                expected=runner_identity,
                evidence=post_runner,
            )
            evidence["runner_post"] = _runner_bundle(post_runner)

        _verify_docker_unchanged(docker)
        for capability in opened:
            _verify_file_capability(capability)
        if trace_container_id is None:
            raise GVisorRuntimeError("gVisor canary trace identity is absent")
        _cleanup_canary_logs_strict(canary_lock, trace_container_id)
        trace_container_id = None
        evidence_limits = (
            _ARTIFACT_EVIDENCE_LIMITS
            if artifact is not None
            else _CANARY_EVIDENCE_LIMITS
        )
        captured = _evidence_snapshot(evidence, expected=evidence_limits)
        source_events, container_id = _verify_detonation_evidence(
            cas,
            runtime_lock,
            canary_lock,
            captured,
            run_id=run_id,
            implementation_files=implementation_files,
            artifact=artifact,
            artifact_normalization_profile=artifact_normalization_profile,
        )
        run_request = (
            _artifact_run_request(
                runtime_lock,
                canary_lock,
                artifact,
                run_id=run_id,
                container_id=container_id,
                implementation_digest=expected_implementation,
                normalization_profile=artifact_normalization_profile,
            )
            if artifact is not None
            else _canary_run_request(
                runtime_lock,
                canary_lock,
                run_id=run_id,
                container_id=container_id,
                input_manifest_digest=expected_lock,
                implementation_digest=expected_implementation,
            )
        )
        run_request_digest = cas.put(
            BytesIO(run_request), max_bytes=_MAX_CANARY_RUN_REQUEST_BYTES
        )
        from .detonation_observation import (
            retain_detonation_capability_diff,
            retain_detonation_observation,
        )

        observation_bindings: dict[str, str] = {}
        identity = (
            _artifact_identity(
                artifact,
                run_request_digest,
                expected_implementation,
            )
            if artifact is not None
            else _canary_identity(
                runtime_lock,
                expected_lock,
                run_request_digest,
                expected_implementation,
            )
        )
        for source_event in source_events:
            observation_digest = retain_detonation_observation(
                cas, source_event, **identity
            )
            observation_bindings[observation_digest] = _raw_digest(source_event)
        capability_diff_receipt_digest = retain_detonation_capability_diff(
            cas,
            observation_bindings,
            **identity,
            declared_capabilities=profile["declared_capabilities"],
        )
        evidence_digests = {
            name: cas.put(BytesIO(raw), max_bytes=evidence_limits[name])
            for name, raw in sorted(captured.items())
        }
        receipt = {
            "schema": (
                ARTIFACT_SCHEMA_V2
                if artifact is not None and artifact_normalization_profile is not None
                else ARTIFACT_SCHEMA if artifact is not None else CANARY_SCHEMA
            ),
            "authority": (
                ARTIFACT_AUTHORITY if artifact is not None else CANARY_AUTHORITY
            ),
            "lock_digest": expected_lock,
            "runtime_lock_digest": runtime_lock_digest,
            "implementation_digest": expected_implementation,
            "run_id": run_id,
            "captured_at": captured_at,
            **identity,
            "capability_diff_receipt_digest": capability_diff_receipt_digest,
            "evidence": evidence_digests,
            "status": "RECORDED",
        }
        if artifact is not None:
            receipt.update(
                {
                    "quarantine_receipt_digest": (artifact.quarantine_receipt_digest),
                    "gateway_profile_digest": artifact.gateway_profile_digest,
                    "source_closure_digest": artifact.source_closure_digest,
                    "entrypoint": _artifact_entrypoint(artifact),
                }
            )
            if artifact_normalization_profile is not None:
                receipt["normalization_profile"] = artifact_normalization_profile
        receipt_digest = cas.put(
            BytesIO(canonical_json(receipt)), max_bytes=_MAX_RECEIPT_BYTES
        )
        if artifact is None:
            verify_gvisor_detonation_canary(
                cas,
                receipt_digest,
                expected_lock_digest=expected_lock,
                expected_verifier_implementation_digest=expected_implementation,
            )
        else:
            verify_gvisor_acquired_artifact(
                cas,
                receipt_digest,
                expected_quarantine_receipt_digest=(artifact.quarantine_receipt_digest),
                expected_manifest_digest=artifact.manifest_digest,
                expected_tree_digest=artifact.tree_digest,
                expected_gateway_profile_digest=artifact.gateway_profile_digest,
                expected_entrypoint_digest=artifact.entrypoint_digest,
                expected_lock_digest=expected_lock,
                expected_verifier_implementation_digest=expected_implementation,
                expected_normalization_profile=artifact_normalization_profile,
            )
        return receipt_digest
    except GVisorRuntimeError:
        raise
    except (
        CASError,
        DockerIdentityError,
        OSError,
        RuntimeError,
        VerificationError,
        WorkerProtocolError,
    ) as exc:
        raise GVisorRuntimeError(
            f"gVisor detonation canary capture failed: {exc}"
        ) from exc
    finally:
        try:
            if (
                container_name is not None
                and docker_environment is not None
                and docker_path is not None
            ):
                _cleanup_container_strict(
                    docker_path,
                    container_name,
                    docker_environment,
                    label="Docker canary",
                )
        finally:
            try:
                if trace_container_id is not None and canary_lock is not None:
                    _cleanup_canary_logs_strict(canary_lock, trace_container_id)
            finally:
                for capability in reversed(opened):
                    os.close(capability.descriptor)
                if coordination >= 0:
                    os.close(coordination)


def _cleanup_container_strict(
    docker: Path,
    container_name: str,
    environment: dict[str, str],
    *,
    label: str,
) -> None:
    if error := _cleanup_container(docker, container_name, environment):
        raise GVisorRuntimeError(f"{label} cleanup failed: {error}")


def _command_environment(control: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(control),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": os.fspath(control),
    }


def _require_success(result: Any, label: str, *, allow_stderr: bool = False) -> None:
    _require_command(result, label)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GVisorRuntimeError(f"{label} failed: {message}")
    if result.stderr and not allow_stderr:
        raise GVisorRuntimeError(f"{label} produced unexpected stderr")


def _docker_result(
    docker: Path,
    arguments: tuple[str, ...],
    *,
    env: dict[str, str],
    label: str,
    timeout: float = _DOCKER_TIMEOUT_SECONDS,
    allow_stderr: bool = False,
) -> Any:
    result = _run_bounded(
        [os.fspath(docker), *arguments],
        timeout=timeout,
        stdout_limit=_MAX_JSON_EVIDENCE_BYTES,
        stderr_limit=_MAX_JSON_EVIDENCE_BYTES,
        shared_limit=2 * _MAX_JSON_EVIDENCE_BYTES,
        env=env,
    )
    _require_success(result, label, allow_stderr=allow_stderr)
    return result


def _docker_output(
    docker: Path,
    arguments: tuple[str, ...],
    *,
    env: dict[str, str],
    label: str,
) -> bytes:
    return _docker_result(docker, arguments, env=env, label=label).stdout


def _create_arguments(
    *,
    image: str,
    profile: dict[str, Any],
    runtime: str,
    container_name: str,
    run_label: str,
    tmpfs: dict[str, str] | None = None,
    bind_mount: dict[str, str] | None = None,
) -> tuple[str, ...]:
    arguments = [
        "create",
        "--pull",
        "never",
        "--platform",
        "linux/arm64",
        "--name",
        container_name,
        "--label",
        run_label,
        "--runtime",
        runtime,
        "--network",
        profile["network_mode"],
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        profile["user"],
        "--pids-limit",
        str(profile["pids_limit"]),
        "--memory",
        str(profile["memory_bytes"]),
        "--memory-swap",
        str(profile["memory_swap_bytes"]),
        "--cpus",
        f"{profile['nano_cpus'] / 1_000_000_000:g}",
        "--ulimit",
        f"nofile={profile['nofile_soft']}:{profile['nofile_hard']}",
    ]
    if tmpfs is not None:
        arguments.extend(("--tmpfs", f"{tmpfs['destination']}:{tmpfs['options']}"))
    if bind_mount is not None:
        arguments.extend(
            (
                "--mount",
                (
                    f"type=bind,source={bind_mount['source']},"
                    f"destination={bind_mount['destination']},readonly"
                ),
            )
        )
    return (
        *arguments,
        "--env",
        profile["environment"][0],
        image,
        *profile["command"],
    )


def _canary_log_paths(
    canary_lock: dict[str, Any], container_id: str
) -> dict[str, Path]:
    directory = Path(canary_lock["trace"]["directory"])
    return {
        command: directory / f"{container_id}.{container_id}.{command}.jsonl"
        for command in canary_lock["trace"]["commands"]
    }


def _canary_log_directory(
    canary_lock: dict[str, Any], *, require_headroom: bool = False
) -> Path:
    directory = Path(canary_lock["trace"]["directory"])
    _verify_protected_path(directory / "placeholder")
    _require_host_mount_namespace()
    value = directory.lstat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise GVisorRuntimeError("gVisor canary trace directory is unsafe")
    try:
        filesystem = _require_bounded_tmpfs_mount(
            directory,
            maximum_bytes=_CANARY_LOG_STORE_BYTES,
            maximum_inodes=_CANARY_LOG_STORE_INODES,
            label="gVisor canary trace store",
        )
    except VerificationError as exc:
        raise GVisorRuntimeError(str(exc)) from exc
    if require_headroom:
        required_files = len(canary_lock["trace"]["commands"]) + 1
        required_bytes = canary_lock["trace"]["max_log_bytes"] * required_files
        if (
            filesystem.f_frsize * filesystem.f_bavail < required_bytes
            or filesystem.f_favail < required_files
        ):
            raise GVisorRuntimeError(
                "gVisor canary trace store lacks bounded run headroom"
            )
    return directory


def _mount_namespace_identity(pid: int | str) -> tuple[int, int]:
    if (
        not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
    ) and pid != "self":
        raise GVisorRuntimeError("mount namespace process identity is invalid")
    try:
        value = os.stat(f"/proc/{pid}/ns/mnt")
    except OSError as exc:
        raise GVisorRuntimeError(f"cannot inspect mount namespace for {pid}: {exc}") from exc
    return value.st_dev, value.st_ino


def _require_host_mount_namespace() -> tuple[int, int]:
    identity = _mount_namespace_identity("self")
    if identity != _mount_namespace_identity(1):
        raise GVisorRuntimeError("collector is outside the host mount namespace")
    return identity


def _cleanup_canary_logs_strict(
    canary_lock: dict[str, Any], container_id: str
) -> None:
    if _CONTAINER.fullmatch(container_id) is None:
        raise GVisorRuntimeError("gVisor canary trace identity is invalid")
    prefix = f"{container_id}.{container_id}."
    try:
        directory = _canary_log_directory(canary_lock)
        for path in tuple(directory.iterdir()):
            name = path.name
            if (
                name.startswith(prefix)
                and name.endswith(".jsonl")
                and len(name) > len(prefix) + len(".jsonl")
            ):
                path.unlink()
        if any(path.name.startswith(prefix) for path in directory.iterdir()):
            raise GVisorRuntimeError("gVisor canary trace cleanup was incomplete")
    except GVisorRuntimeError:
        raise
    except OSError as exc:
        raise GVisorRuntimeError(f"gVisor canary trace cleanup failed: {exc}") from exc


def _require_canary_logs_new(
    canary_lock: dict[str, Any],
    container_id: str,
    prior_names: frozenset[str],
) -> None:
    _canary_log_directory(canary_lock)
    for path in _canary_log_paths(canary_lock, container_id).values():
        if path.name in prior_names:
            raise GVisorRuntimeError(f"gVisor canary trace path was reused: {path}")


def _capture_canary_logs(
    cas: CAS,
    canary_lock: dict[str, Any],
    container_id: str,
    opened: list[_FileCapability],
) -> bytes:
    _canary_log_directory(canary_lock)
    files = []
    maximum = canary_lock["trace"]["max_log_bytes"]
    for command, path in _canary_log_paths(canary_lock, container_id).items():
        capability = _open_file_capability(
            path,
            expected_digest=None,
            maximum=maximum,
            executable=False,
            label=f"gVisor canary {command} log",
        )
        opened.append(capability)
        raw = _read_open_file(capability, maximum)
        if cas.put(BytesIO(raw), max_bytes=maximum) != capability.digest:
            raise GVisorRuntimeError("gVisor canary log CAS identity changed")
        files.append({"command": command, "file": capability.metadata})
    return canonical_json(
        {
            "schema": CANARY_LOG_MANIFEST_SCHEMA,
            "container_id": container_id,
            "files": files,
        }
    )


def _capture_cleanup_absence(
    docker: Path, container_id: str, env: dict[str, str]
) -> bytes:
    result = _run_bounded(
        [os.fspath(docker), "container", "inspect", container_id],
        timeout=_DOCKER_TIMEOUT_SECONDS,
        stdout_limit=_MAX_STREAM_BYTES,
        stderr_limit=_MAX_STREAM_BYTES,
        shared_limit=2 * _MAX_STREAM_BYTES,
        env=env,
    )
    _require_command(result, "Docker canary cleanup inspect")
    try:
        stderr = result.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GVisorRuntimeError("Docker canary cleanup response is not UTF-8") from exc
    if (
        result.returncode != 1
        or result.stdout != b"[]\n"
        or container_id not in stderr
        or "No such container" not in stderr
    ):
        raise GVisorRuntimeError("Docker canary cleanup absence was not observed")
    return canonical_json(
        {
            "schema": CANARY_CLEANUP_SCHEMA,
            "container_id": container_id,
            "absent": True,
        }
    )


def _canary_identity(
    runtime_lock: dict[str, Any],
    input_manifest_digest: str,
    run_request_digest: str,
    implementation_digest: str,
) -> dict[str, str]:
    subject = runtime_lock["image"]["digest"]
    return {
        "subject_digest": subject,
        "input_manifest_digest": input_manifest_digest,
        "input_tree_digest": subject,
        "run_request_digest": run_request_digest,
        "normalizer_implementation_digest": implementation_digest,
    }


def _canary_run_request(
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    *,
    run_id: str,
    container_id: str,
    input_manifest_digest: str,
    implementation_digest: str,
) -> bytes:
    profile = canary_lock["canary"]
    return canonical_json(
        {
            "schema": CANARY_RUN_REQUEST_SCHEMA,
            "authority": "FIXED_CANARY_REQUEST_ONLY_NOT_ARTIFACT_EXECUTION_AUTHORITY",
            "run_id": run_id,
            "container_id": container_id,
            "subject_digest": runtime_lock["image"]["digest"],
            "input_manifest_digest": input_manifest_digest,
            "input_tree_digest": runtime_lock["image"]["digest"],
            "normalizer_implementation_digest": implementation_digest,
            "runtime_lock_digest": canary_lock["runtime_lock_digest"],
            "runtime": canary_lock["runtime"],
            "image_digest": runtime_lock["image"]["digest"],
            "command": profile["command"],
            "environment": profile["environment"],
            "token_digest": profile["token_digest"],
            "declared_capabilities": profile["declared_capabilities"],
        }
    )


def _artifact_normalization_profile(value: str | None) -> str | None:
    if value not in (None, ARTIFACT_NORMALIZATION_PROFILE):
        raise GVisorRuntimeError(
            "gVisor acquired artifact normalization profile is unsupported"
        )
    return value


def _artifact_profile(canary_lock: dict[str, Any]) -> dict[str, Any]:
    base = canary_lock["canary"]
    fields = (
        "environment",
        "user",
        "network_mode",
        "read_only",
        "cap_drop",
        "security_opt",
        "pids_limit",
        "memory_bytes",
        "memory_swap_bytes",
        "nano_cpus",
        "nofile_soft",
        "nofile_hard",
        "tmpfs",
        "declared_capabilities",
    )
    return {
        **{field: base[field] for field in fields},
        "command": ["/bin/sh", _ARTIFACT_TARGET],
        "source_events": [
            {
                "schema": "aragorn/detonation-source-event/v1",
                "operation": "file-open-read",
                "detail": "gvisor-json-strace:openat:O_RDONLY:" + _ARTIFACT_TARGET,
            },
            {
                "schema": "aragorn/detonation-source-event/v1",
                "operation": "process-exec",
                "detail": "gvisor-json-strace:execve:/bin/sha256sum",
            },
        ],
    }


def _artifact_entrypoint(artifact: _AcquiredArtifact) -> dict[str, Any]:
    return {
        "path": _ARTIFACT_ENTRYPOINT,
        "digest": artifact.entrypoint_digest,
        "size": artifact.entrypoint_size,
        "executable": True,
        "container_path": _ARTIFACT_TARGET,
    }


def _fixed_artifact_entrypoint(manifest: dict[str, Any]) -> dict[str, Any]:
    source = _object(manifest.get("source"), "acquired artifact source")
    if (
        manifest.get("schema") != "aragorn/github-manifest/v1"
        or manifest.get("tree_digest") != _ARTIFACT_TREE_DIGEST
        or {field: source.get(field) for field in _ARTIFACT_GITHUB_SOURCE}
        != _ARTIFACT_GITHUB_SOURCE
    ):
        raise GVisorRuntimeError("acquired artifact source profile changed")
    matches = [
        item for item in manifest["files"] if item["path"] == _ARTIFACT_ENTRYPOINT
    ]
    if len(matches) != 1:
        raise GVisorRuntimeError("acquired artifact entrypoint is absent or ambiguous")
    entrypoint = matches[0]
    if (
        entrypoint["digest"] != _ARTIFACT_ENTRYPOINT_DIGEST
        or entrypoint["size"] != _ARTIFACT_ENTRYPOINT_SIZE
        or entrypoint["executable"] is not True
    ):
        raise GVisorRuntimeError("acquired artifact entrypoint profile changed")
    return entrypoint


def _artifact_identity(
    artifact: _AcquiredArtifact,
    run_request_digest: str,
    implementation_digest: str,
) -> dict[str, str]:
    return {
        "subject_digest": artifact.tree_digest,
        "input_manifest_digest": artifact.manifest_digest,
        "input_tree_digest": artifact.tree_digest,
        "run_request_digest": run_request_digest,
        "normalizer_implementation_digest": implementation_digest,
    }


def _artifact_run_request(
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    artifact: _AcquiredArtifact,
    *,
    run_id: str,
    container_id: str,
    implementation_digest: str,
    normalization_profile: str | None = None,
) -> bytes:
    selected_normalization = _artifact_normalization_profile(normalization_profile)
    profile = _artifact_profile(canary_lock)
    request = {
        "schema": (
            ARTIFACT_RUN_REQUEST_SCHEMA_V2
            if selected_normalization is not None
            else ARTIFACT_RUN_REQUEST_SCHEMA
        ),
        "authority": (
            "ONE_INERT_ACQUIRED_ARTIFACT_REQUEST_ONLY_NOT_GENERAL_EXECUTION_"
            "OR_ADMISSION_AUTHORITY"
        ),
        "run_id": run_id,
        "container_id": container_id,
        "subject_digest": artifact.tree_digest,
        "input_manifest_digest": artifact.manifest_digest,
        "input_tree_digest": artifact.tree_digest,
        "normalizer_implementation_digest": implementation_digest,
        "quarantine_receipt_digest": artifact.quarantine_receipt_digest,
        "gateway_profile_digest": artifact.gateway_profile_digest,
        "source_closure_digest": artifact.source_closure_digest,
        "runtime_lock_digest": canary_lock["runtime_lock_digest"],
        "runtime": canary_lock["runtime"],
        "image_digest": runtime_lock["image"]["digest"],
        "entrypoint": _artifact_entrypoint(artifact),
        "command": profile["command"],
        "environment": profile["environment"],
        "mount": {
            "destination": _ARTIFACT_TARGET,
            "read_only": True,
        },
        "declared_capabilities": profile["declared_capabilities"],
    }
    if selected_normalization is not None:
        request["normalization_profile"] = selected_normalization
    return canonical_json(request)


def _read_canary_logs(
    cas: CAS,
    raw_manifest: bytes,
    canary_lock: dict[str, Any],
    container_id: str,
) -> dict[str, bytes]:
    manifest = _json_object(raw_manifest, "gVisor canary log manifest", canonical=True)
    _exact_keys(
        manifest,
        {"schema", "container_id", "files"},
        "gVisor canary log manifest",
    )
    commands = canary_lock["trace"]["commands"]
    if (
        manifest["schema"] != CANARY_LOG_MANIFEST_SCHEMA
        or manifest["container_id"] != container_id
        or not isinstance(manifest["files"], list)
        or len(manifest["files"]) != len(commands)
    ):
        raise GVisorRuntimeError("gVisor canary log manifest identity changed")
    expected_paths = _canary_log_paths(canary_lock, container_id)
    maximum = canary_lock["trace"]["max_log_bytes"]
    logs: dict[str, bytes] = {}
    for expected_command, item in zip(commands, manifest["files"], strict=True):
        entry = _object(item, "gVisor canary log entry")
        _exact_keys(entry, {"command", "file"}, "gVisor canary log entry")
        metadata = _file_metadata_document(entry["file"], "gVisor canary log")
        if (
            entry["command"] != expected_command
            or metadata["path"] != os.fspath(expected_paths[expected_command])
            or metadata["uid"] != 0
            or metadata["gid"] != 0
            or metadata["mode"] & 0o022
            or not 0 < metadata["size"] <= maximum
        ):
            raise GVisorRuntimeError("gVisor canary log metadata changed")
        digest = _digest(metadata["digest"], "gVisor canary log")
        try:
            raw = cas.read(digest, max_bytes=maximum)
        except CASError as exc:
            raise GVisorRuntimeError(f"cannot read gVisor canary log: {exc}") from exc
        if len(raw) != metadata["size"]:
            raise GVisorRuntimeError("gVisor canary log size changed")
        logs[expected_command] = raw
    return logs


def _parse_canary_trace(
    raw: bytes,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    container_id: str,
) -> tuple[bytes, ...]:
    pairs = _parse_trace_pairs(
        raw,
        runtime_lock,
        canary_lock,
        container_id,
        command=canary_lock["canary"]["command"],
    )
    token_path = canary_lock["canary"]["token_path"]
    write: tuple[tuple[int, int], int] | None = None
    execute: tuple[tuple[int, int], int] | None = None
    read: tuple[tuple[int, int], int] | None = None
    for key, process, syscall, arguments, result, entered_at, _exited_at in pairs:
        if syscall == "openat" and token_path in arguments:
            if _canary_open_arguments(arguments, token_path, write=True):
                if write is not None or process != "sh" or not _successful_fd(result):
                    raise GVisorRuntimeError("gVisor canary token write is ambiguous")
                write = (key, entered_at)
            elif _canary_open_arguments(arguments, token_path, write=False):
                if (
                    read is not None
                    or process != "sha256sum"
                    or not _successful_fd(result)
                ):
                    raise GVisorRuntimeError("gVisor canary token read is ambiguous")
                read = (key, entered_at)
            else:
                raise GVisorRuntimeError("gVisor canary token access changed")
        elif syscall == "execve" and (
            "/bin/sha256sum" in arguments or token_path in arguments
        ):
            if (
                execute is not None
                or process != "sh"
                or result != "0 (0x0)"
                or not _canary_exec_arguments(arguments, container_id, token_path)
            ):
                raise GVisorRuntimeError("gVisor canary process execution is ambiguous")
            execute = (key, entered_at)
    if write is None or execute is None or read is None:
        raise GVisorRuntimeError("gVisor canary target events are incomplete")
    if not (write[1] < execute[1] < read[1] and execute[0] == read[0]):
        raise GVisorRuntimeError("gVisor canary target event ordering changed")
    return tuple(
        canonical_json(event) for event in canary_lock["canary"]["source_events"]
    )


def _parse_trace_pairs(
    raw: bytes,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    container_id: str,
    *,
    command: list[str],
) -> tuple[_TracePair, ...]:
    trace = canary_lock["trace"]
    records = _canary_log_records(raw, canary_lock, "boot")
    pending: dict[tuple[int, int], tuple[str, str, str, int]] = {}
    pairs: list[_TracePair] = []
    headers = {
        name: 0
        for name in (
            "version",
            "args",
            "platform",
            "filesystem",
            "network",
            "strace",
            "exec",
        )
    }
    messages: list[str] = []
    version = runtime_lock["release"]["version"]
    for index, record in enumerate(records):
        message = record["msg"]
        messages.append(message)
        if message.startswith("cli.go:276] Version "):
            if (
                not message.startswith(f"cli.go:276] Version release-{version}, ")
                or ", arm64, " not in message
                or ", linux, " not in message
            ):
                raise GVisorRuntimeError("gVisor canary trace version changed")
            headers["version"] += 1
        elif message.startswith("cli.go:278] Args: "):
            if (
                container_id not in message
                or " boot " not in message
                or not message.endswith(f" {container_id}]")
            ):
                raise GVisorRuntimeError("gVisor canary trace process identity changed")
            headers["args"] += 1
        elif message.startswith("config.go:533] Platform:"):
            if message != "config.go:533] Platform: systrap":
                raise GVisorRuntimeError("gVisor canary trace platform changed")
            headers["platform"] += 1
        elif message.startswith("config.go:535] FileAccess:"):
            if not message.startswith(
                "config.go:535] FileAccess: exclusive / Directfs: false / Overlay:"
            ):
                raise GVisorRuntimeError("gVisor canary trace filesystem changed")
            headers["filesystem"] += 1
        elif message.startswith("config.go:536] Network:"):
            if message != "config.go:536] Network: none":
                raise GVisorRuntimeError("gVisor canary trace network changed")
            headers["network"] += 1
        elif message.startswith("config.go:539] Debug:"):
            if message != (
                "config.go:539] Debug: true. Strace: true, max size: 256, "
                "syscalls: openat,execve"
            ):
                raise GVisorRuntimeError("gVisor canary trace configuration changed")
            headers["strace"] += 1
        elif message.startswith("kernel.go:1293] EXEC: []string"):
            encoded = message.removeprefix("kernel.go:1293] EXEC: []string")
            if not encoded.startswith("{") or not encoded.endswith("}"):
                raise GVisorRuntimeError("gVisor canary command record is malformed")
            try:
                observed_command = json.loads("[" + encoded[1:-1] + "]")
            except (ValueError, RecursionError) as exc:
                raise GVisorRuntimeError(
                    f"gVisor canary command record is invalid: {exc}"
                ) from exc
            if observed_command != command:
                raise GVisorRuntimeError("gVisor canary command changed")
            headers["exec"] += 1

        if not message.startswith("strace.go:"):
            continue
        matched = _TRACE_MESSAGE.fullmatch(message)
        if matched is None:
            raise GVisorRuntimeError("gVisor canary syscall record is malformed")
        key = (int(matched["tgid"]), int(matched["tid"]))
        body = matched["body"]
        result: str | None = None
        if matched["phase"] == "X":
            call_body, separator, outcome = body.rpartition(") = ")
            if not separator:
                raise GVisorRuntimeError("gVisor canary syscall exit is malformed")
            value, duration_separator, duration = outcome.rpartition(" (")
            if (
                not duration_separator
                or not duration.endswith(")")
                or _TRACE_DURATION.fullmatch(duration[:-1]) is None
            ):
                raise GVisorRuntimeError("gVisor canary syscall duration is malformed")
            body = call_body + ")"
            result = value
        call = _TRACE_CALL.fullmatch(body)
        if call is None or call["syscall"] not in trace["syscalls"]:
            raise GVisorRuntimeError("gVisor canary syscall is unsupported")
        process = matched["process"]
        arguments = call["arguments"]
        if matched["phase"] == "E":
            if key in pending:
                raise GVisorRuntimeError("gVisor canary syscall entry is interleaved")
            pending[key] = (process, call["syscall"], arguments, index)
            continue
        entered = pending.pop(key, None)
        if entered is None or entered[:3] != (process, call["syscall"], arguments):
            raise GVisorRuntimeError("gVisor canary syscall pair changed")
        pairs.append(
            (key, process, call["syscall"], arguments, result or "", entered[3], index)
        )
    if pending:
        raise GVisorRuntimeError("gVisor canary syscall trace is truncated")
    if any(count == 0 for count in headers.values()):
        raise GVisorRuntimeError("gVisor canary trace headers are incomplete")
    if not messages or messages[-1] != "cli.go:316] Exiting with status: 0":
        raise GVisorRuntimeError("gVisor canary trace did not terminate cleanly")
    return tuple(pairs)


def _parse_artifact_trace(
    raw: bytes,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    container_id: str,
    *,
    normalization_profile: str | None = None,
) -> tuple[bytes, ...]:
    selected_normalization = _artifact_normalization_profile(normalization_profile)
    pairs = _parse_trace_pairs(
        raw,
        runtime_lock,
        canary_lock,
        container_id,
        command=_artifact_profile(canary_lock)["command"],
    )
    _require_artifact_trace_anchors(pairs, container_id)
    if selected_normalization is None:
        return tuple(
            canonical_json(event)
            for event in _artifact_profile(canary_lock)["source_events"]
        )
    return _normalize_successful_artifact_events(pairs)


def _require_artifact_trace_anchors(
    pairs: tuple[_TracePair, ...], container_id: str
) -> None:
    execute: tuple[tuple[int, int], int] | None = None
    read: tuple[tuple[int, int], int] | None = None
    for key, process, syscall, arguments, result, entered_at, _exited_at in pairs:
        if (
            syscall == "execve"
            and "/bin/sha256sum" in arguments
            and _ARTIFACT_TARGET in arguments
        ):
            if (
                execute is not None
                or process != "sh"
                or result != "0 (0x0)"
                or not _canary_exec_arguments(
                    arguments,
                    container_id,
                    _ARTIFACT_TARGET,
                )
            ):
                raise GVisorRuntimeError(
                    "gVisor acquired artifact execution is ambiguous"
                )
            execute = (key, entered_at)
        elif (
            syscall == "openat"
            and process == "sha256sum"
            and _ARTIFACT_TARGET in arguments
        ):
            if (
                read is not None
                or not _canary_open_arguments(
                    arguments,
                    _ARTIFACT_TARGET,
                    write=False,
                )
                or not _successful_fd(result)
            ):
                raise GVisorRuntimeError("gVisor acquired artifact read is ambiguous")
            read = (key, entered_at)
    if (
        execute is None
        or read is None
        or not (execute[1] < read[1] and execute[0] == read[0])
    ):
        raise GVisorRuntimeError("gVisor acquired artifact events are incomplete")


def _normalize_successful_artifact_events(
    pairs: tuple[_TracePair, ...],
) -> tuple[bytes, ...]:
    events: set[tuple[str, str]] = set()
    for _key, _process, syscall, arguments, result, _entered, _exited in pairs:
        if _TRACE_FAILURE.fullmatch(result) is not None:
            continue
        if syscall == "openat":
            if not _successful_fd(result):
                raise GVisorRuntimeError(
                    "gVisor acquired artifact successful openat result is malformed"
                )
            matched = _TRACE_OPENAT_ARGUMENTS.fullmatch(arguments)
            if matched is None:
                raise GVisorRuntimeError(
                    "gVisor acquired artifact successful openat is malformed"
                )
            access = set(matched["flags"].split("|")) & {
                "O_RDONLY",
                "O_WRONLY",
                "O_RDWR",
            }
            if len(access) != 1:
                raise GVisorRuntimeError(
                    "gVisor acquired artifact successful openat access is ambiguous"
                )
            path = matched["path"]
            modes = (
                ("read", "write")
                if access == {"O_RDWR"}
                else ("read",) if access == {"O_RDONLY"} else ("write",)
            )
            for mode in modes:
                events.add(
                    (
                        f"file-open-{mode}",
                        _artifact_trace_detail("openat", mode, path),
                    )
                )
            continue
        if result != "0 (0x0)":
            raise GVisorRuntimeError(
                "gVisor acquired artifact successful execve result is malformed"
            )
        matched = _TRACE_EXECVE_ARGUMENTS.fullmatch(arguments)
        if matched is None:
            raise GVisorRuntimeError(
                "gVisor acquired artifact successful execve is malformed"
            )
        try:
            argv = json.loads(matched["argv"])
            environment = json.loads(matched["environment"])
        except (ValueError, RecursionError) as exc:
            raise GVisorRuntimeError(
                f"gVisor acquired artifact successful execve is invalid: {exc}"
            ) from exc
        path = matched["path"]
        if (
            not isinstance(argv, list)
            or not argv
            or argv[0] != path
            or any(not isinstance(value, str) for value in argv)
            or not isinstance(environment, list)
            or any(not isinstance(value, str) for value in environment)
        ):
            raise GVisorRuntimeError(
                "gVisor acquired artifact successful execve arguments are invalid"
            )
        events.add(
            (
                "process-exec",
                _artifact_trace_detail("execve", None, path),
            )
        )
    return tuple(
        sorted(
            canonical_json(
                {
                    "schema": "aragorn/detonation-source-event/v1",
                    "operation": operation,
                    "detail": detail,
                }
            )
            for operation, detail in events
        )
    )


def _artifact_trace_detail(syscall: str, mode: str | None, path: str) -> str:
    detail = ":".join(
        part
        for part in ("gvisor-json-strace", syscall, mode, path)
        if part is not None
    )
    if len(detail) > 2048:
        raise GVisorRuntimeError("gVisor acquired artifact event path is oversized")
    return detail


def _canary_open_arguments(arguments: str, path: str, *, write: bool) -> bool:
    flags = "O_WRONLY|O_CREAT|O_TRUNC" if write else "O_RDONLY|0x0"
    mode = "0o666" if write else "0o0"
    return (
        re.fullmatch(
            rf"AT_FDCWD /, 0x[0-9a-f]+ {re.escape(path)}, {re.escape(flags)}, {mode}",
            arguments,
        )
        is not None
    )


def _successful_fd(result: str) -> bool:
    matched = re.fullmatch(r"([0-9]+) \(0x([0-9a-f]+)\)", result)
    return matched is not None and int(matched[1]) == int(matched[2], 16)


def _canary_exec_arguments(arguments: str, container_id: str, token_path: str) -> bool:
    matched = re.fullmatch(
        rf"0x[0-9a-f]+ /bin/sha256sum, 0x[0-9a-f]+ "
        rf"\[\"/bin/sha256sum\", \"{re.escape(token_path)}\"\], "
        r"0x[0-9a-f]+ (?P<environment>\[.*\])",
        arguments,
    )
    if matched is None:
        return False
    try:
        environment = json.loads(matched["environment"])
    except (ValueError, RecursionError):
        return False
    return environment == [
        f"HOSTNAME={container_id[:12]}",
        "SHLVL=1",
        "HOME=/home",
        "PATH=/bin",
        "PWD=/",
    ]


def _wait_for_live_container(
    docker: Path, container_id: str, env: dict[str, str]
) -> tuple[dict[str, Any], bytes]:
    deadline = time.monotonic() + 3.0
    while True:
        container, raw = _inspect_container(docker, container_id, env)
        state = _object(container.get("State"), "container state")
        if state.get("Running") is True:
            return container, raw
        if state.get("Status") in {"dead", "exited"} or time.monotonic() >= deadline:
            raise GVisorRuntimeError("gVisor smoke did not reach a live state")
        time.sleep(0.05)


def _runner_bundle(buffer: _RunnerReceiptBuffer) -> bytes:
    return canonical_json(
        {
            "context": _json_value(buffer.raw_context, "Docker context"),
            "version": _json_value(buffer.raw_version, "Docker version"),
            "info": _json_value(buffer.raw_info, "Docker info"),
        }
    )


def _runner_receipt(raw: bytes, label: str) -> Any:
    bundle = _json_object(raw, label, canonical=True)
    _exact_keys(bundle, {"context", "version", "info"}, label)
    try:
        return normalize_docker_identity(
            canonical_json(bundle["context"]),
            canonical_json(bundle["version"]),
            canonical_json(bundle["info"]),
        )
    except (DockerIdentityError, WorkerProtocolError) as exc:
        raise GVisorRuntimeError(f"{label} is invalid: {exc}") from exc


def _stat_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _metadata(path: Path, digest: str, value: os.stat_result) -> dict[str, int | str]:
    return {
        "path": os.fspath(path),
        "digest": digest,
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _verify_protected_path(path: Path) -> None:
    if not path.is_absolute():
        raise GVisorRuntimeError(f"protected path must be absolute: {path}")
    current = path.parent
    while True:
        value = current.lstat()
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != 0
            or stat.S_IMODE(value.st_mode) & 0o022
        ):
            raise GVisorRuntimeError(
                f"protected path has an unsafe ancestor: {current}"
            )
        if current.parent == current:
            return
        current = current.parent


def _digest_descriptor(descriptor: int, maximum: int, label: str) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise GVisorRuntimeError(f"{label} is not a bounded regular file")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if offset != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise GVisorRuntimeError(f"{label} changed while hashed")
    return f"sha256:{digest.hexdigest()}"


def _open_file_capability(
    path: Path,
    *,
    expected_digest: str | None,
    maximum: int,
    executable: bool,
    label: str,
    retain: CAS | None = None,
) -> _FileCapability:
    _verify_protected_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        value = os.fstat(descriptor)
        mode = stat.S_IMODE(value.st_mode)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != 0
            or mode & 0o022
            or (executable and not mode & 0o111)
        ):
            raise GVisorRuntimeError(f"{label} ownership or mode is unsafe")
        observed = _digest_descriptor(descriptor, maximum, label)
        if expected_digest is not None and observed != _digest(expected_digest, label):
            raise GVisorRuntimeError(f"{label} digest changed")
        if retain is not None:
            if expected_digest is None:
                raise GVisorRuntimeError(f"{label} has no retained expected digest")
            with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source:
                source.seek(0)
                retain.put_expected(
                    source,
                    expected_digest=expected_digest,
                    max_bytes=maximum,
                )
        after = os.fstat(descriptor)
        if _stat_identity(value) != _stat_identity(after):
            raise GVisorRuntimeError(f"{label} changed while opened")
        return _FileCapability(
            path=path,
            descriptor=descriptor,
            digest=observed,
            identity=_stat_identity(value),
            metadata=_metadata(path, observed, value),
        )
    except BaseException:
        os.close(descriptor)
        raise


def _verify_file_capability(capability: _FileCapability) -> None:
    descriptor_value = os.fstat(capability.descriptor)
    path_value = capability.path.lstat()
    if (
        _stat_identity(descriptor_value) != capability.identity
        or _stat_identity(path_value) != capability.identity
        or _digest_descriptor(
            capability.descriptor,
            max(capability.identity[5], 1),
            os.fspath(capability.path),
        )
        != capability.digest
    ):
        raise GVisorRuntimeError(f"file capability changed: {capability.path}")


def _read_open_file(capability: _FileCapability, maximum: int) -> bytes:
    size = capability.identity[5]
    if size > maximum:
        raise GVisorRuntimeError(f"file capability is oversized: {capability.path}")
    raw = os.pread(capability.descriptor, size, 0)
    if len(raw) != size:
        raise GVisorRuntimeError(
            f"file capability read was incomplete: {capability.path}"
        )
    _verify_file_capability(capability)
    return raw


def _path_metadata(path: Path, digest: str) -> dict[str, int | str]:
    _verify_protected_path(path)
    value = path.lstat()
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != 0
        or mode & 0o022
        or not mode & 0o111
    ):
        raise GVisorRuntimeError(f"executable path is unsafe: {path}")
    return _metadata(path, digest, value)


def _file_metadata_document(value: object, label: str) -> dict[str, Any]:
    document = _object(value, label)
    _exact_keys(
        document,
        {
            "path",
            "digest",
            "device",
            "inode",
            "mode",
            "uid",
            "gid",
            "size",
            "mtime_ns",
            "ctime_ns",
        },
        label,
    )
    if (
        not isinstance(document["path"], str)
        or not document["path"].startswith("/")
        or not isinstance(document["digest"], str)
        or _DIGEST.fullmatch(document["digest"]) is None
        or any(
            type(document[field]) is not int or document[field] < 0
            for field in (
                "device",
                "inode",
                "mode",
                "uid",
                "gid",
                "size",
                "mtime_ns",
                "ctime_ns",
            )
        )
        or document["size"] <= 0
        or document["mode"] > 0o7777
    ):
        raise GVisorRuntimeError(f"{label} metadata is invalid")
    return document


def _read_proc_bytes(directory: int, name: str, maximum: int) -> bytes:
    descriptor = os.open(
        name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=directory
    )
    try:
        chunks = bytearray()
        while chunk := os.read(descriptor, min(8192, maximum - len(chunks) + 1)):
            chunks.extend(chunk)
            if len(chunks) > maximum:
                raise GVisorRuntimeError(f"/proc/{name} exceeds its byte limit")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _parse_proc_stat(raw: bytes, pid: int) -> tuple[int, int]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GVisorRuntimeError("process stat is not ASCII") from exc
    marker = text.rfind(") ")
    if marker < 0 or not text.startswith(f"{pid} ("):
        raise GVisorRuntimeError("process stat is malformed")
    fields = text[marker + 2 :].split()
    if len(fields) < 20 or not fields[1].isdigit() or not fields[19].isdigit():
        raise GVisorRuntimeError("process stat fields are malformed")
    return int(fields[1]), int(fields[19])


def _parse_proc_status(raw: bytes) -> tuple[list[int], list[int]]:
    values: dict[str, list[int]] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GVisorRuntimeError("process status is not ASCII") from exc
    for line in lines:
        name, separator, remainder = line.partition(":")
        if separator and name in {"Uid", "Gid"}:
            fields = remainder.split()
            if len(fields) != 4 or any(not field.isdigit() for field in fields):
                raise GVisorRuntimeError(f"process {name} is malformed")
            values[name] = [int(field) for field in fields]
    if set(values) != {"Uid", "Gid"}:
        raise GVisorRuntimeError("process credentials are incomplete")
    return values["Uid"], values["Gid"]


def _parse_cmdline(raw: bytes) -> list[str]:
    if not raw or not raw.endswith(b"\0"):
        raise GVisorRuntimeError("process command line is incomplete")
    try:
        return [item.decode("utf-8") for item in raw[:-1].split(b"\0")]
    except UnicodeDecodeError as exc:
        raise GVisorRuntimeError("process command line is not UTF-8") from exc


def _capture_process(pid: int) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(f"/proc/{pid}", flags)
    executable = -1
    try:
        first_stat = _read_proc_bytes(directory, "stat", 16 * 1024)
        ppid, starttime = _parse_proc_stat(first_stat, pid)
        uids, gids = _parse_proc_status(
            _read_proc_bytes(directory, "status", 64 * 1024)
        )
        argv = _parse_cmdline(_read_proc_bytes(directory, "cmdline", 64 * 1024))
        executable = os.open(
            "exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=directory
        )
        executable_value = os.fstat(executable)
        executable_digest = _digest_descriptor(
            executable, _MAX_DOCKER_BINARY_BYTES, f"process {pid} executable"
        )
        executable_path = Path(os.readlink("exe", dir_fd=directory))
        second_ppid, second_starttime = _parse_proc_stat(
            _read_proc_bytes(directory, "stat", 16 * 1024), pid
        )
        if (ppid, starttime) != (second_ppid, second_starttime):
            raise GVisorRuntimeError("process identity changed during capture")
        return {
            "pid": pid,
            "ppid": ppid,
            "starttime": starttime,
            "uids": uids,
            "gids": gids,
            "argv": argv,
            "exe": _metadata(executable_path, executable_digest, executable_value),
        }
    finally:
        if executable >= 0:
            os.close(executable)
        os.close(directory)


def _peek_process_argv(pid: int) -> list[str] | None:
    directory = -1
    try:
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        directory = os.open(f"/proc/{pid}", flags)
        return _parse_cmdline(_read_proc_bytes(directory, "cmdline", 64 * 1024))
    except (GVisorRuntimeError, OSError):
        return None
    finally:
        if directory >= 0:
            os.close(directory)


def _capture_processes(
    lock: dict[str, Any], *, container_id: str, sandbox_pid: int, runsc: _FileCapability
) -> bytes:
    roles: dict[str, dict[str, Any]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        argv = _peek_process_argv(pid)
        if argv is None or container_id not in argv:
            continue
        name = Path(argv[0]).name
        role = {
            "runsc-gofer": "gofer",
            "runsc-sandbox": "sandbox",
            "containerd-shim-runc-v2": "shim",
        }.get(name)
        if role is None or role in roles:
            continue
        try:
            process = _capture_process(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        process["role"] = role
        roles[role] = process
    if set(roles) != {"gofer", "sandbox", "shim"}:
        raise GVisorRuntimeError("live gVisor process graph is incomplete")
    host_mount_namespace = _require_host_mount_namespace()
    if _mount_namespace_identity(roles["shim"]["pid"]) != host_mount_namespace:
        raise GVisorRuntimeError("gVisor shim is outside the host mount namespace")
    for role in ("gofer", "sandbox"):
        executable = roles[role]["exe"]
        if (
            executable["digest"] != runsc.digest
            or executable["device"] != runsc.identity[0]
            or executable["inode"] != runsc.identity[1]
        ):
            raise GVisorRuntimeError("live process is not the pinned runsc inode")
    for process in roles.values():
        try:
            current = _capture_process(process["pid"])
        except (FileNotFoundError, ProcessLookupError) as exc:
            raise GVisorRuntimeError("gVisor process exited during capture") from exc
        if current["starttime"] != process["starttime"]:
            raise GVisorRuntimeError("gVisor process identity changed after capture")
    try:
        with Path("/proc/sys/kernel/random/boot_id").open("rb") as source:
            raw_boot_id = source.read(65)
        if len(raw_boot_id) > 64:
            raise GVisorRuntimeError("Linux boot identity is oversized")
        boot_id = raw_boot_id.decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise GVisorRuntimeError(f"cannot read Linux boot identity: {exc}") from exc
    document = {
        "boot_id": boot_id,
        "processes": [
            {**roles[role], "role": role} for role in ("gofer", "sandbox", "shim")
        ],
    }
    raw = canonical_json(document)
    _verify_processes(
        lock,
        raw,
        container_id=container_id,
        sandbox_pid=sandbox_pid,
        installed_runsc=runsc.metadata,
    )
    return raw


def _implementation_manifest(
    raw: bytes,
    *,
    schema: str = IMPLEMENTATION_SCHEMA,
    modules: tuple[str, ...] = _IMPLEMENTATION_MODULES,
    label: str = "gVisor runtime",
) -> dict[str, str]:
    document = _json_object(raw, f"{label} implementation manifest", canonical=True)
    _exact_keys(
        document,
        {"schema", "files"},
        f"{label} implementation manifest",
    )
    if document["schema"] != schema:
        raise GVisorRuntimeError(f"{label} implementation schema changed")
    files = _object(document["files"], f"{label} implementation files")
    if set(files) != set(modules):
        raise GVisorRuntimeError(f"{label} implementation inventory changed")
    return {
        module: _digest(files[module], f"{label} implementation {module}")
        for module in modules
    }


def _read_implementation(
    cas: CAS,
    digest: str,
    *,
    schema: str = IMPLEMENTATION_SCHEMA,
    modules: tuple[str, ...] = _IMPLEMENTATION_MODULES,
    label: str = "gVisor runtime",
) -> dict[str, str]:
    try:
        files = _implementation_manifest(
            cas.read(digest, max_bytes=_MAX_IMPLEMENTATION_MANIFEST_BYTES),
            schema=schema,
            modules=modules,
            label=label,
        )
        for source_digest in files.values():
            cas.verify(source_digest, max_bytes=_MAX_IMPLEMENTATION_SOURCE_BYTES)
        return files
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot verify {label} implementation: {exc}"
        ) from exc


def verify_gvisor_runtime_smoke(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
) -> dict[str, Any]:
    """Replay one smoke against caller-held lock and verifier identities."""

    expected_lock = _digest(expected_lock_digest, "expected lock")
    expected_verifier = _digest(
        expected_verifier_implementation_digest,
        "expected verifier implementation",
    )
    try:
        receipt = _json_object(
            cas.read(_digest(receipt_digest, "receipt"), max_bytes=_MAX_RECEIPT_BYTES),
            "gVisor runtime smoke receipt",
            canonical=True,
        )
        if set(receipt) != _RECEIPT_FIELDS:
            raise GVisorRuntimeError("gVisor runtime smoke receipt fields are invalid")
        if (
            receipt["schema"] != SCHEMA
            or receipt["authority"] != AUTHORITY
            or receipt["status"] != "PASS"
        ):
            raise GVisorRuntimeError(
                "gVisor runtime smoke receipt overstates or changes its result"
            )
        if _digest(receipt["lock_digest"], "receipt lock") != expected_lock:
            raise GVisorRuntimeError("gVisor runtime lock identity changed")
        if (
            _digest(
                receipt["implementation_digest"],
                "receipt verifier implementation",
            )
            != expected_verifier
        ):
            raise GVisorRuntimeError("gVisor runtime verifier identity changed")
        if (
            not isinstance(receipt["run_id"], str)
            or _RUN_ID.fullmatch(receipt["run_id"]) is None
            or not isinstance(receipt["captured_at"], str)
            or _CAPTURED_AT.fullmatch(receipt["captured_at"]) is None
        ):
            raise GVisorRuntimeError("gVisor runtime capture identity is invalid")
        evidence_digests = receipt["evidence"]
        if not isinstance(evidence_digests, dict) or set(evidence_digests) != set(
            _EVIDENCE_LIMITS
        ):
            raise GVisorRuntimeError("gVisor runtime evidence inventory is invalid")
        lock_raw = cas.read(expected_lock, max_bytes=_MAX_LOCK_BYTES)
        implementation_files = _read_implementation(cas, expected_verifier)
        lock = _runtime_lock(lock_raw)
        captured = {
            name: cas.read(
                _digest(evidence_digests[name], f"{name} evidence"),
                max_bytes=_EVIDENCE_LIMITS[name],
            )
            for name in _EVIDENCE_LIMITS
        }
        _verify_evidence(
            lock,
            captured,
            run_id=receipt["run_id"],
            implementation_files=implementation_files,
        )
        return receipt
    except GVisorRuntimeError:
        raise
    except CASError as exc:
        raise GVisorRuntimeError(f"cannot verify gVisor runtime smoke: {exc}") from exc


def verify_gvisor_detonation_canary(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
) -> dict[str, Any]:
    """Replay one fixed same-run canary against caller-held trust identities."""

    return _verify_gvisor_detonation_canary(
        cas,
        receipt_digest,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
    ).receipt


def verify_gvisor_acquired_artifact(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_quarantine_receipt_digest: str,
    expected_manifest_digest: str,
    expected_tree_digest: str,
    expected_gateway_profile_digest: str,
    expected_entrypoint_digest: str,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    expected_normalization_profile: str | None = None,
) -> dict[str, Any]:
    """Replay one exact acquired-artifact run without promoting custody."""

    return _verify_gvisor_acquired_artifact(
        cas,
        receipt_digest,
        expected_quarantine_receipt_digest=expected_quarantine_receipt_digest,
        expected_manifest_digest=expected_manifest_digest,
        expected_tree_digest=expected_tree_digest,
        expected_gateway_profile_digest=expected_gateway_profile_digest,
        expected_entrypoint_digest=expected_entrypoint_digest,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
        expected_normalization_profile=expected_normalization_profile,
    ).receipt


def _verify_gvisor_acquired_artifact(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_quarantine_receipt_digest: str,
    expected_manifest_digest: str,
    expected_tree_digest: str,
    expected_gateway_profile_digest: str,
    expected_entrypoint_digest: str,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    expected_normalization_profile: str | None = None,
) -> _VerifiedCanary:
    expected_normalization = _artifact_normalization_profile(
        expected_normalization_profile
    )
    expected_receipt = _digest(receipt_digest, "acquired artifact receipt")
    expected_quarantine = _digest(
        expected_quarantine_receipt_digest,
        "expected quarantine receipt",
    )
    expected_manifest = _digest(expected_manifest_digest, "expected source manifest")
    expected_tree = _digest(expected_tree_digest, "expected source tree")
    expected_gateway = _digest(
        expected_gateway_profile_digest,
        "expected gateway profile",
    )
    expected_entrypoint = _digest(
        expected_entrypoint_digest,
        "expected artifact entrypoint",
    )
    if (
        expected_tree != _ARTIFACT_TREE_DIGEST
        or expected_entrypoint != _ARTIFACT_ENTRYPOINT_DIGEST
    ):
        raise GVisorRuntimeError("gVisor acquired artifact fixed profile changed")
    expected_lock = _digest(expected_lock_digest, "expected canary lock")
    expected_implementation = _digest(
        expected_verifier_implementation_digest,
        "expected artifact verifier implementation",
    )
    try:
        receipt = _json_object(
            cas.read(expected_receipt, max_bytes=_MAX_RECEIPT_BYTES),
            "gVisor acquired artifact receipt",
            canonical=True,
        )
        expected_fields = (
            _ARTIFACT_RECEIPT_V2_FIELDS
            if expected_normalization is not None
            else _ARTIFACT_RECEIPT_FIELDS
        )
        expected_schema = (
            ARTIFACT_SCHEMA_V2
            if expected_normalization is not None
            else ARTIFACT_SCHEMA
        )
        if set(receipt) != expected_fields:
            raise GVisorRuntimeError("gVisor acquired artifact receipt fields changed")
        if (
            receipt["schema"] != expected_schema
            or receipt["authority"] != ARTIFACT_AUTHORITY
            or receipt["status"] != "RECORDED"
            or receipt["quarantine_receipt_digest"] != expected_quarantine
            or receipt["gateway_profile_digest"] != expected_gateway
            or _digest(receipt["lock_digest"], "artifact canary lock") != expected_lock
            or _digest(receipt["implementation_digest"], "artifact implementation")
            != expected_implementation
        ):
            raise GVisorRuntimeError("gVisor acquired artifact authority changed")
        if (
            expected_normalization is not None
            and receipt["normalization_profile"] != expected_normalization
        ):
            raise GVisorRuntimeError(
                "gVisor acquired artifact normalization profile changed"
            )
        if (
            not isinstance(receipt["run_id"], str)
            or _RUN_ID.fullmatch(receipt["run_id"]) is None
            or not isinstance(receipt["captured_at"], str)
            or _CAPTURED_AT.fullmatch(receipt["captured_at"]) is None
        ):
            raise GVisorRuntimeError("gVisor acquired artifact capture is invalid")

        canary_lock = _canary_lock(cas.read(expected_lock, max_bytes=_MAX_LOCK_BYTES))
        runtime_lock_digest = _digest(
            receipt["runtime_lock_digest"],
            "gVisor runtime lock",
        )
        if runtime_lock_digest != canary_lock["runtime_lock_digest"]:
            raise GVisorRuntimeError("gVisor artifact runtime lock changed")
        runtime_lock = _runtime_lock(
            cas.read(runtime_lock_digest, max_bytes=_MAX_LOCK_BYTES)
        )
        implementation_files = _read_implementation(
            cas,
            expected_implementation,
            schema=ARTIFACT_IMPLEMENTATION_SCHEMA,
            modules=_ARTIFACT_IMPLEMENTATION_MODULES,
            label="gVisor acquired artifact",
        )

        from .artifact_closure import load_verified_retained_manifest
        from .github_quarantine_receipt import (
            verify_transported_github_quarantine_receipt,
        )

        quarantine = verify_transported_github_quarantine_receipt(
            cas,
            expected_quarantine,
            expected_manifest_digest=expected_manifest,
            expected_gateway_profile_digest=expected_gateway,
        )
        manifest = load_verified_retained_manifest(cas, expected_manifest)
        if (
            manifest["tree_digest"] != expected_tree
            or quarantine["tree_digest"] != expected_tree
            or receipt["source_closure_digest"] != quarantine["source_closure_digest"]
        ):
            raise GVisorRuntimeError("gVisor acquired source identity changed")
        manifest_entrypoint = _fixed_artifact_entrypoint(manifest)
        entrypoint = _object(receipt["entrypoint"], "artifact entrypoint")
        _exact_keys(
            entrypoint,
            {"path", "digest", "size", "executable", "container_path"},
            "artifact entrypoint",
        )
        if entrypoint != {
            "path": _ARTIFACT_ENTRYPOINT,
            "digest": expected_entrypoint,
            "size": manifest_entrypoint["size"],
            "executable": True,
            "container_path": _ARTIFACT_TARGET,
        }:
            raise GVisorRuntimeError("gVisor acquired entrypoint identity changed")

        evidence_digests = receipt["evidence"]
        if not isinstance(evidence_digests, dict) or set(evidence_digests) != set(
            _ARTIFACT_EVIDENCE_LIMITS
        ):
            raise GVisorRuntimeError("gVisor acquired artifact evidence is incomplete")
        evidence = {
            name: cas.read(
                _digest(evidence_digests[name], f"{name} evidence"),
                max_bytes=_ARTIFACT_EVIDENCE_LIMITS[name],
            )
            for name in _ARTIFACT_EVIDENCE_LIMITS
        }
        source = _file_metadata_document(
            _json_value(evidence["artifact_source"], "artifact source"),
            "artifact source",
        )
        artifact = _AcquiredArtifact(
            quarantine_receipt_digest=expected_quarantine,
            gateway_profile_digest=expected_gateway,
            source_closure_digest=quarantine["source_closure_digest"],
            manifest_digest=expected_manifest,
            tree_digest=expected_tree,
            entrypoint_digest=expected_entrypoint,
            entrypoint_size=manifest_entrypoint["size"],
            materialized_path=Path(source["path"]),
        )
        run_request_digest = _digest(
            receipt["run_request_digest"],
            "artifact run request",
        )
        expected_identity = _artifact_identity(
            artifact,
            run_request_digest,
            expected_implementation,
        )
        if {
            field: receipt[field]
            for field in (
                "subject_digest",
                "input_manifest_digest",
                "input_tree_digest",
                "run_request_digest",
                "normalizer_implementation_digest",
            )
        } != expected_identity:
            raise GVisorRuntimeError("gVisor acquired artifact binding changed")
        source_events, container_id = _verify_detonation_evidence(
            cas,
            runtime_lock,
            canary_lock,
            evidence,
            run_id=receipt["run_id"],
            implementation_files=implementation_files,
            artifact=artifact,
            artifact_normalization_profile=expected_normalization,
        )
        if cas.read(
            run_request_digest,
            max_bytes=_MAX_CANARY_RUN_REQUEST_BYTES,
        ) != _artifact_run_request(
            runtime_lock,
            canary_lock,
            artifact,
            run_id=receipt["run_id"],
            container_id=container_id,
            implementation_digest=expected_implementation,
            normalization_profile=expected_normalization,
        ):
            raise GVisorRuntimeError("gVisor acquired artifact run request changed")
        observation_bindings = _verify_observation_diff(
            cas,
            source_events,
            expected_identity,
            canary_lock["canary"]["declared_capabilities"],
            receipt["capability_diff_receipt_digest"],
        )
        return _VerifiedCanary(
            receipt=receipt,
            lock=canary_lock,
            implementation_files=implementation_files,
            evidence=evidence,
            identity=expected_identity,
            observation_bindings=observation_bindings,
        )
    except GVisorRuntimeError:
        raise
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorRuntimeError(
            f"cannot verify gVisor acquired artifact: {exc}"
        ) from exc


def _verify_gvisor_detonation_canary(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
) -> _VerifiedCanary:
    expected_lock = _digest(expected_lock_digest, "expected canary lock")
    expected_implementation = _digest(
        expected_verifier_implementation_digest,
        "expected canary verifier implementation",
    )
    try:
        receipt = _json_object(
            cas.read(
                _digest(receipt_digest, "canary receipt"), max_bytes=_MAX_RECEIPT_BYTES
            ),
            "gVisor detonation canary receipt",
            canonical=True,
        )
        if set(receipt) != _CANARY_RECEIPT_FIELDS:
            raise GVisorRuntimeError("gVisor canary receipt fields are invalid")
        if (
            receipt["schema"] != CANARY_SCHEMA
            or receipt["authority"] != CANARY_AUTHORITY
            or receipt["status"] != "RECORDED"
            or _digest(receipt["lock_digest"], "canary lock") != expected_lock
            or _digest(receipt["implementation_digest"], "canary implementation")
            != expected_implementation
        ):
            raise GVisorRuntimeError("gVisor canary receipt authority changed")
        if (
            not isinstance(receipt["run_id"], str)
            or _RUN_ID.fullmatch(receipt["run_id"]) is None
            or not isinstance(receipt["captured_at"], str)
            or _CAPTURED_AT.fullmatch(receipt["captured_at"]) is None
        ):
            raise GVisorRuntimeError("gVisor canary capture identity is invalid")
        canary_lock = _canary_lock(cas.read(expected_lock, max_bytes=_MAX_LOCK_BYTES))
        runtime_lock_digest = _digest(
            receipt["runtime_lock_digest"], "gVisor runtime lock"
        )
        if runtime_lock_digest != canary_lock["runtime_lock_digest"]:
            raise GVisorRuntimeError("gVisor canary runtime lock identity changed")
        runtime_lock = _runtime_lock(
            cas.read(runtime_lock_digest, max_bytes=_MAX_LOCK_BYTES)
        )
        implementation_files = _read_implementation(
            cas,
            expected_implementation,
            schema=CANARY_IMPLEMENTATION_SCHEMA,
            modules=_CANARY_IMPLEMENTATION_MODULES,
            label="gVisor detonation canary",
        )
        expected_identity = _canary_identity(
            runtime_lock,
            expected_lock,
            _digest(receipt["run_request_digest"], "canary run request"),
            expected_implementation,
        )
        if {
            field: receipt[field]
            for field in (
                "subject_digest",
                "input_manifest_digest",
                "input_tree_digest",
                "run_request_digest",
                "normalizer_implementation_digest",
            )
        } != expected_identity:
            raise GVisorRuntimeError("gVisor canary evidence identity changed")
        evidence_digests = receipt["evidence"]
        if not isinstance(evidence_digests, dict) or set(evidence_digests) != set(
            _CANARY_EVIDENCE_LIMITS
        ):
            raise GVisorRuntimeError("gVisor canary evidence inventory is invalid")
        evidence = {
            name: cas.read(
                _digest(evidence_digests[name], f"{name} evidence"),
                max_bytes=_CANARY_EVIDENCE_LIMITS[name],
            )
            for name in _CANARY_EVIDENCE_LIMITS
        }
        source_events, container_id = _verify_detonation_evidence(
            cas,
            runtime_lock,
            canary_lock,
            evidence,
            run_id=receipt["run_id"],
            implementation_files=implementation_files,
            artifact=None,
            artifact_normalization_profile=None,
        )
        expected_run_request = _canary_run_request(
            runtime_lock,
            canary_lock,
            run_id=receipt["run_id"],
            container_id=container_id,
            input_manifest_digest=expected_lock,
            implementation_digest=expected_implementation,
        )
        if (
            cas.read(
                expected_identity["run_request_digest"],
                max_bytes=_MAX_CANARY_RUN_REQUEST_BYTES,
            )
            != expected_run_request
        ):
            raise GVisorRuntimeError("gVisor canary run request changed")
        observation_bindings = _verify_observation_diff(
            cas,
            source_events,
            expected_identity,
            canary_lock["canary"]["declared_capabilities"],
            receipt["capability_diff_receipt_digest"],
        )
        return _VerifiedCanary(
            receipt=receipt,
            lock=canary_lock,
            implementation_files=implementation_files,
            evidence=evidence,
            identity=expected_identity,
            observation_bindings=observation_bindings,
        )
    except GVisorRuntimeError:
        raise
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot verify gVisor detonation canary: {exc}"
        ) from exc


def _verify_observation_diff(
    cas: CAS,
    source_events: tuple[bytes, ...],
    identity: dict[str, str],
    declared_capabilities: list[str],
    receipt_digest: object,
) -> dict[str, str]:
    from .detonation_observation import (
        derive_detonation_observation_binding,
        verify_detonation_capability_diff,
    )

    bindings = {}
    for source_event in source_events:
        source_digest, observation_digest, _raw = derive_detonation_observation_binding(
            source_event, **identity
        )
        bindings[observation_digest] = source_digest
    verify_detonation_capability_diff(
        cas,
        _digest(receipt_digest, "capability diff receipt"),
        expected_observations=bindings,
        **{f"expected_{field}": value for field, value in identity.items()},
        expected_declared_capabilities=declared_capabilities,
    )
    return bindings


def derive_gvisor_runtime_smoke_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
) -> dict[str, int]:
    """Return the exact verified CAS closure for generic byte transport."""

    receipt_id = _digest(receipt_digest, "receipt")
    receipt = verify_gvisor_runtime_smoke(
        cas,
        receipt_id,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
    )
    implementation_files = _read_implementation(cas, receipt["implementation_digest"])
    limits = {
        receipt_id: _MAX_RECEIPT_BYTES,
        receipt["lock_digest"]: _MAX_LOCK_BYTES,
        receipt["implementation_digest"]: _MAX_IMPLEMENTATION_MANIFEST_BYTES,
        **{
            digest: _MAX_IMPLEMENTATION_SOURCE_BYTES
            for digest in implementation_files.values()
        },
        **{
            digest: _EVIDENCE_LIMITS[name]
            for name, digest in receipt["evidence"].items()
        },
    }
    try:
        return {
            digest: len(cas.read(digest, max_bytes=limit))
            for digest, limit in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot derive gVisor runtime smoke closure: {exc}"
        ) from exc


def derive_gvisor_detonation_canary_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
) -> dict[str, int]:
    """Return the complete verified CAS closure for one traced canary."""

    receipt_id = _digest(receipt_digest, "canary receipt")
    verified = _verify_gvisor_detonation_canary(
        cas,
        receipt_id,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
    )
    receipt = verified.receipt
    canary_lock = verified.lock
    from .detonation_observation import derive_detonation_capability_diff_closure

    diff_closure = derive_detonation_capability_diff_closure(
        cas,
        receipt["capability_diff_receipt_digest"],
        expected_observations=verified.observation_bindings,
        **{f"expected_{field}": value for field, value in verified.identity.items()},
        expected_declared_capabilities=canary_lock["canary"]["declared_capabilities"],
    )
    log_manifest = _json_object(
        verified.evidence["backend_log_manifest"],
        "gVisor canary log manifest",
        canonical=True,
    )
    log_digests = {
        _file_metadata_document(item["file"], "gVisor canary log")["digest"]
        for item in log_manifest["files"]
    }
    limits = {
        receipt_id: _MAX_RECEIPT_BYTES,
        receipt["lock_digest"]: _MAX_LOCK_BYTES,
        receipt["runtime_lock_digest"]: _MAX_LOCK_BYTES,
        receipt["implementation_digest"]: _MAX_IMPLEMENTATION_MANIFEST_BYTES,
        receipt["run_request_digest"]: _MAX_CANARY_RUN_REQUEST_BYTES,
        **{
            digest: _MAX_IMPLEMENTATION_SOURCE_BYTES
            for digest in verified.implementation_files.values()
        },
        **{
            digest: _CANARY_EVIDENCE_LIMITS[name]
            for name, digest in receipt["evidence"].items()
        },
        **{digest: canary_lock["trace"]["max_log_bytes"] for digest in log_digests},
    }
    limits.update(
        {
            digest: max(limits.get(digest, 0), size)
            for digest, size in diff_closure.items()
        }
    )
    try:
        return {
            digest: len(cas.read(digest, max_bytes=limit))
            for digest, limit in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot derive gVisor detonation canary closure: {exc}"
        ) from exc


def derive_gvisor_acquired_artifact_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_quarantine_receipt_digest: str,
    expected_manifest_digest: str,
    expected_tree_digest: str,
    expected_gateway_profile_digest: str,
    expected_entrypoint_digest: str,
    expected_lock_digest: str,
    expected_verifier_implementation_digest: str,
    expected_normalization_profile: str | None = None,
) -> dict[str, int]:
    """Return the exact acquired-source and same-run evidence closure."""

    receipt_id = _digest(receipt_digest, "acquired artifact receipt")
    verified = _verify_gvisor_acquired_artifact(
        cas,
        receipt_id,
        expected_quarantine_receipt_digest=expected_quarantine_receipt_digest,
        expected_manifest_digest=expected_manifest_digest,
        expected_tree_digest=expected_tree_digest,
        expected_gateway_profile_digest=expected_gateway_profile_digest,
        expected_entrypoint_digest=expected_entrypoint_digest,
        expected_lock_digest=expected_lock_digest,
        expected_verifier_implementation_digest=(
            expected_verifier_implementation_digest
        ),
        expected_normalization_profile=expected_normalization_profile,
    )
    receipt = verified.receipt
    canary_lock = verified.lock
    from .detonation_observation import derive_detonation_capability_diff_closure
    from .github_quarantine_receipt import (
        derive_transported_github_quarantine_closure,
    )

    diff_closure = derive_detonation_capability_diff_closure(
        cas,
        receipt["capability_diff_receipt_digest"],
        expected_observations=verified.observation_bindings,
        **{f"expected_{field}": value for field, value in verified.identity.items()},
        expected_declared_capabilities=canary_lock["canary"]["declared_capabilities"],
    )
    source_closure = derive_transported_github_quarantine_closure(
        cas,
        receipt["quarantine_receipt_digest"],
        expected_manifest_digest=receipt["input_manifest_digest"],
        expected_gateway_profile_digest=receipt["gateway_profile_digest"],
    )
    log_manifest = _json_object(
        verified.evidence["backend_log_manifest"],
        "gVisor artifact log manifest",
        canonical=True,
    )
    log_digests = {
        _file_metadata_document(item["file"], "gVisor artifact log")["digest"]
        for item in log_manifest["files"]
    }
    limits = {
        receipt_id: _MAX_RECEIPT_BYTES,
        receipt["lock_digest"]: _MAX_LOCK_BYTES,
        receipt["runtime_lock_digest"]: _MAX_LOCK_BYTES,
        receipt["implementation_digest"]: _MAX_IMPLEMENTATION_MANIFEST_BYTES,
        receipt["run_request_digest"]: _MAX_CANARY_RUN_REQUEST_BYTES,
        **{
            digest: _MAX_IMPLEMENTATION_SOURCE_BYTES
            for digest in verified.implementation_files.values()
        },
        **{
            digest: _ARTIFACT_EVIDENCE_LIMITS[name]
            for name, digest in receipt["evidence"].items()
        },
        **{digest: canary_lock["trace"]["max_log_bytes"] for digest in log_digests},
    }
    for closure in (source_closure, diff_closure):
        limits.update(
            {
                digest: max(limits.get(digest, 0), size)
                for digest, size in closure.items()
            }
        )
    try:
        return {
            digest: len(cas.read(digest, max_bytes=limit))
            for digest, limit in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot derive gVisor acquired artifact closure: {exc}"
        ) from exc


def _verify_evidence(
    lock: dict[str, Any],
    evidence: dict[str, bytes],
    *,
    run_id: str,
    implementation_files: dict[str, str],
) -> None:
    observed_binaries = _verify_runtime_identity_evidence(
        lock,
        evidence,
        implementation_files=implementation_files,
        runtime=lock["runtime"],
        daemon_config_digest=lock["daemon_config_digest"],
        helper_modules=_HELPER_MODULES,
        label="gVisor runtime",
    )
    pre = _inspect(evidence["container_pre_inspect"], "prestart container")
    live = _inspect(evidence["container_live_inspect"], "live container")
    post = _inspect(evidence["container_post_inspect"], "postrun container")
    container_id = _verify_container(lock, pre, phase="prestart", run_id=run_id)
    if _verify_container(lock, live, phase="live", run_id=run_id) != container_id:
        raise GVisorRuntimeError("live container identity changed")
    if _verify_container(lock, post, phase="postrun", run_id=run_id) != container_id:
        raise GVisorRuntimeError("postrun container identity changed")
    for field in ("Created", "Image", "Path", "Args"):
        if pre.get(field) != live.get(field) or pre.get(field) != post.get(field):
            raise GVisorRuntimeError(f"container {field} changed across the smoke")
    _verify_processes(
        lock,
        evidence["container_processes"],
        container_id=container_id,
        sandbox_pid=live["State"]["Pid"],
        installed_runsc=observed_binaries[lock["runtime"]["path"]],
    )
    if evidence["container_stdout"] or evidence["container_stderr"]:
        raise GVisorRuntimeError("inert gVisor smoke produced unexpected output")


def _verify_runtime_identity_evidence(
    runtime_lock: dict[str, Any],
    evidence: dict[str, bytes],
    *,
    implementation_files: dict[str, str],
    runtime: dict[str, Any],
    daemon_config_digest: str,
    helper_modules: tuple[str, ...],
    label: str,
) -> dict[str, dict[str, Any]]:
    if set(implementation_files) != {"gvisor_runtime.py", *helper_modules}:
        raise GVisorRuntimeError(f"{label} implementation inventory changed")
    if (
        evidence["runtime_version"]
        != runtime_lock["runtime"]["version_output"].encode()
    ):
        raise GVisorRuntimeError("gVisor runtime version changed")
    binaries = _json_value(evidence["installed_binaries"], "installed binaries")
    if not isinstance(binaries, list) or len(binaries) != len(runtime_lock["binaries"]):
        raise GVisorRuntimeError("installed gVisor binary inventory changed")
    expected_binaries = {
        item["path"]: item["digest"] for item in runtime_lock["binaries"]
    }
    observed_binaries: dict[str, dict[str, Any]] = {}
    for binary in binaries:
        metadata = _file_metadata_document(binary, "installed gVisor binary")
        if (
            metadata["uid"] != 0
            or metadata["mode"] & 0o022
            or not metadata["mode"] & 0o111
            or metadata["path"] in observed_binaries
        ):
            raise GVisorRuntimeError("installed gVisor binary permissions are unsafe")
        observed_binaries[metadata["path"]] = metadata
    if {
        path: metadata["digest"] for path, metadata in observed_binaries.items()
    } != expected_binaries:
        raise GVisorRuntimeError("installed gVisor binary identities changed")

    daemon = _json_object(evidence["daemon_config"], "Docker daemon configuration")
    if _raw_digest(evidence["daemon_config"]) != daemon_config_digest:
        raise GVisorRuntimeError("Docker daemon configuration identity changed")
    registration = _json_object(
        evidence["runtime_registration"], "Docker runtime registration"
    )
    expected_registration = {
        "path": runtime["path"],
        "runtimeArgs": runtime["arguments"],
    }
    if (
        set(registration) != {"path", "runtimeArgs", "status"}
        or {field: registration[field] for field in expected_registration}
        != expected_registration
        or not isinstance(registration["status"], dict)
    ):
        raise GVisorRuntimeError("Docker runtime registration changed")
    daemon_runtime = daemon.get("runtimes", {}).get(runtime["name"])
    if daemon_runtime != expected_registration:
        raise GVisorRuntimeError("Docker daemon runtime configuration changed")

    docker = _file_metadata_document(
        _json_value(evidence["docker_executable"], "Docker executable"),
        "Docker executable",
    )
    if docker["uid"] != 0 or docker["mode"] & 0o022 or not docker["mode"] & 0o111:
        raise GVisorRuntimeError("Docker executable permissions are unsafe")
    helpers = _json_value(evidence["helper_implementations"], f"{label} helpers")
    if not isinstance(helpers, list) or len(helpers) != len(helper_modules):
        raise GVisorRuntimeError(f"{label} helper inventory changed")
    for expected_module, item in zip(helper_modules, helpers, strict=True):
        helper = _object(item, f"{label} helper")
        _exact_keys(helper, {"module", "file"}, f"{label} helper")
        metadata = _file_metadata_document(helper["file"], f"{label} helper")
        if (
            helper["module"] != expected_module
            or Path(metadata["path"]).name != expected_module
            or metadata["digest"] != implementation_files[expected_module]
            or metadata["uid"] != 0
            or metadata["mode"] & 0o022
        ):
            raise GVisorRuntimeError(f"{label} helper identity is unsafe")
    pre_runner = _runner_receipt(evidence["runner_pre"], "pre-run Docker identity")
    post_runner = _runner_receipt(evidence["runner_post"], "post-run Docker identity")
    if pre_runner.document_json != post_runner.document_json:
        raise GVisorRuntimeError("Docker runner identity changed during the capture")
    _verify_image(runtime_lock, evidence["image_inspect"])
    return observed_binaries


def _verify_detonation_evidence(
    cas: CAS,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    evidence: dict[str, bytes],
    *,
    run_id: str,
    implementation_files: dict[str, str],
    artifact: _AcquiredArtifact | None,
    artifact_normalization_profile: str | None,
) -> tuple[tuple[bytes, ...], str]:
    helper_modules = (
        _ARTIFACT_HELPER_MODULES if artifact is not None else _CANARY_HELPER_MODULES
    )
    label = (
        "gVisor acquired artifact"
        if artifact is not None
        else "gVisor detonation canary"
    )
    observed_binaries = _verify_runtime_identity_evidence(
        runtime_lock,
        evidence,
        implementation_files=implementation_files,
        runtime=canary_lock["runtime"],
        daemon_config_digest=canary_lock["daemon_config_digest"],
        helper_modules=helper_modules,
        label=label,
    )
    bind_mount: dict[str, str] | None = None
    if artifact is not None:
        source = _file_metadata_document(
            _json_value(evidence["artifact_source"], "artifact source"),
            "artifact source",
        )
        if (
            source["digest"] != artifact.entrypoint_digest
            or source["size"] != artifact.entrypoint_size
            or source["uid"] != 0
            or source["mode"] & 0o022
            or source["mode"] & 0o111
        ):
            raise GVisorRuntimeError("materialized acquired artifact identity changed")
        bind_mount = {
            "source": source["path"],
            "destination": _ARTIFACT_TARGET,
        }
    pre = _inspect(evidence["container_pre_inspect"], f"prestart {label} container")
    live = _inspect(evidence["container_live_inspect"], f"live {label} container")
    post = _inspect(evidence["container_post_inspect"], f"postrun {label} container")
    container_id = _verify_detonation_container(
        runtime_lock,
        canary_lock,
        pre,
        phase="prestart",
        run_id=run_id,
        artifact=artifact,
        bind_mount=bind_mount,
    )
    if (
        _verify_detonation_container(
            runtime_lock,
            canary_lock,
            live,
            phase="live",
            run_id=run_id,
            artifact=artifact,
            bind_mount=bind_mount,
        )
        != container_id
        or _verify_detonation_container(
            runtime_lock,
            canary_lock,
            post,
            phase="postrun",
            run_id=run_id,
            artifact=artifact,
            bind_mount=bind_mount,
        )
        != container_id
    ):
        raise GVisorRuntimeError(f"{label} container identity changed")
    for field in ("Created", "Image", "Path", "Args"):
        if pre.get(field) != live.get(field) or pre.get(field) != post.get(field):
            raise GVisorRuntimeError(f"{label} container {field} changed")
    _verify_processes(
        runtime_lock,
        evidence["container_processes"],
        container_id=container_id,
        sandbox_pid=live["State"]["Pid"],
        installed_runsc=observed_binaries[canary_lock["runtime"]["path"]],
    )
    if evidence["container_stdout"] or evidence["container_stderr"]:
        raise GVisorRuntimeError(f"{label} produced output")
    cleanup = _json_object(
        evidence["container_cleanup"], "gVisor canary cleanup", canonical=True
    )
    if cleanup != {
        "schema": CANARY_CLEANUP_SCHEMA,
        "container_id": container_id,
        "absent": True,
    }:
        raise GVisorRuntimeError(f"{label} cleanup evidence changed")
    logs = _read_canary_logs(
        cas, evidence["backend_log_manifest"], canary_lock, container_id
    )
    for command, raw in logs.items():
        if command != "boot":
            _verify_canary_log_envelope(raw, canary_lock, container_id, command)
    source_events = (
        _parse_artifact_trace(
            logs["boot"],
            runtime_lock,
            canary_lock,
            container_id,
            normalization_profile=artifact_normalization_profile,
        )
        if artifact is not None
        else _parse_canary_trace(logs["boot"], runtime_lock, canary_lock, container_id)
    )
    return source_events, container_id


def _verify_canary_log_envelope(
    raw: bytes,
    canary_lock: dict[str, Any],
    container_id: str,
    command: str,
) -> None:
    records = _canary_log_records(raw, canary_lock, command)
    if not any(container_id in record["msg"] for record in records):
        raise GVisorRuntimeError(f"gVisor canary {command} log is not run-bound")


def _canary_log_records(
    raw: bytes,
    canary_lock: dict[str, Any],
    command: str,
) -> tuple[dict[str, Any], ...]:
    trace = canary_lock["trace"]
    if (
        not raw
        or len(raw) > trace["max_log_bytes"]
        or not raw.endswith(b"\n")
        or b"\x00" in raw
        or b"\r" in raw
    ):
        raise GVisorRuntimeError(f"gVisor canary {command} log framing is invalid")
    lines = raw.splitlines()
    if not lines or len(lines) > trace["max_log_lines"]:
        raise GVisorRuntimeError(f"gVisor canary {command} log line count is invalid")
    records = []
    for line in lines:
        if not line or len(line) > trace["max_line_bytes"]:
            raise GVisorRuntimeError(f"gVisor canary {command} log line is invalid")
        record = _json_object(line, f"gVisor canary {command} log record")
        _exact_keys(
            record,
            {"msg", "level", "time"},
            f"gVisor canary {command} log record",
        )
        if (
            record["level"] not in {"debug", "info", "warning"}
            or not isinstance(record["msg"], str)
            or not record["msg"]
            or "\x00" in record["msg"]
            or not isinstance(record["time"], str)
            or _TRACE_TIME.fullmatch(record["time"]) is None
        ):
            raise GVisorRuntimeError(f"gVisor canary {command} log record is invalid")
        records.append(record)
    return tuple(records)


def _runtime_lock(raw: object) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_LOCK_BYTES:
        raise GVisorRuntimeError("gVisor runtime lock is empty or oversized")
    lock = _json_object(raw, "gVisor runtime lock")
    _exact_keys(
        lock,
        {
            "schema",
            "authority",
            "release",
            "runtime",
            "binaries",
            "daemon_config_digest",
            "image",
            "smoke",
        },
        "gVisor runtime lock",
    )
    if lock["schema"] != LOCK_SCHEMA or lock["authority"] != LOCK_AUTHORITY:
        raise GVisorRuntimeError("gVisor runtime lock authority is invalid")

    release = _object(lock["release"], "gVisor release")
    _exact_keys(
        release,
        {
            "version",
            "tag",
            "tag_object",
            "source_commit",
            "archive_url",
            "archive_size",
            "archive_sha512",
            "archive_sha256",
        },
        "gVisor release",
    )
    version = _text(release["version"], "gVisor release version")
    if release["tag"] != f"release-{version}":
        raise GVisorRuntimeError("gVisor release tag does not match its version")
    for field in ("tag_object", "source_commit"):
        if (
            not isinstance(release[field], str)
            or _GIT.fullmatch(release[field]) is None
        ):
            raise GVisorRuntimeError(f"gVisor release {field} is invalid")
    expected_url = (
        f"https://storage.googleapis.com/gvisor/releases/release/{version}/"
        "aarch64/gvisor.tar.bz2"
    )
    if release["archive_url"] != expected_url:
        raise GVisorRuntimeError("gVisor release archive URL is invalid")
    if (
        isinstance(release["archive_size"], bool)
        or not isinstance(release["archive_size"], int)
        or not 1 <= release["archive_size"] <= 256 * 1024 * 1024
    ):
        raise GVisorRuntimeError("gVisor release archive size is invalid")
    if (
        not isinstance(release["archive_sha512"], str)
        or _SHA512.fullmatch(release["archive_sha512"]) is None
    ):
        raise GVisorRuntimeError("gVisor release SHA-512 is invalid")
    _digest(release["archive_sha256"], "gVisor release archive")

    runtime = _object(lock["runtime"], "gVisor runtime")
    _exact_keys(
        runtime,
        {"name", "path", "arguments", "version_output"},
        "gVisor runtime",
    )
    if runtime != {
        "name": "runsc-systrap",
        "path": "/usr/local/bin/runsc",
        "arguments": ["--platform=systrap", "--directfs=false"],
        "version_output": f"runsc version release-{version}\nspec: 1.2.1\n",
    }:
        raise GVisorRuntimeError("gVisor runtime profile is not the hardened pin")

    binaries = lock["binaries"]
    expected_paths = {
        "/usr/local/bin/runsc",
        "/usr/local/bin/containerd-shim-runsc-v1",
        "/usr/local/bin/gvisor-bin/checkpointgofer",
        "/usr/local/bin/gvisor-bin/runsc-metric-server",
    }
    if not isinstance(binaries, list) or len(binaries) != len(expected_paths):
        raise GVisorRuntimeError("gVisor binary inventory is invalid")
    paths: list[str] = []
    for item in binaries:
        binary = _object(item, "gVisor binary")
        _exact_keys(binary, {"path", "digest"}, "gVisor binary")
        paths.append(_text(binary["path"], "gVisor binary path"))
        _digest(binary["digest"], "gVisor binary")
    if paths != sorted(expected_paths):
        raise GVisorRuntimeError("gVisor binary inventory paths are invalid")
    _digest(lock["daemon_config_digest"], "Docker daemon configuration")

    image = _object(lock["image"], "gVisor smoke image")
    _exact_keys(
        image,
        {"reference", "repo_digest", "digest", "os", "architecture", "variant"},
        "gVisor smoke image",
    )
    image_digest = _digest(image["digest"], "gVisor smoke image")
    if (
        image["reference"] != f"docker.io/library/busybox@{image_digest}"
        or image["repo_digest"] != f"busybox@{image_digest}"
        or image["os"] != "linux"
        or image["architecture"] != "arm64"
        or image["variant"] != "v8"
    ):
        raise GVisorRuntimeError("gVisor smoke image pin is invalid")

    smoke = _object(lock["smoke"], "gVisor smoke profile")
    _exact_keys(
        smoke,
        {
            "command",
            "environment",
            "user",
            "network_mode",
            "read_only",
            "cap_drop",
            "security_opt",
            "pids_limit",
            "memory_bytes",
            "memory_swap_bytes",
            "nano_cpus",
            "nofile_soft",
            "nofile_hard",
        },
        "gVisor smoke profile",
    )
    if smoke != {
        "command": ["sleep", "10"],
        "environment": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "user": "65534:65534",
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges=true"],
        "pids_limit": 256,
        "memory_bytes": 64 * 1024 * 1024,
        "memory_swap_bytes": 64 * 1024 * 1024,
        "nano_cpus": 250_000_000,
        "nofile_soft": 1024,
        "nofile_hard": 1024,
    }:
        raise GVisorRuntimeError("gVisor smoke profile is not the bounded pin")
    return lock


def _canary_lock(raw: object) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_LOCK_BYTES:
        raise GVisorRuntimeError("gVisor detonation canary lock is empty or oversized")
    lock = _json_object(raw, "gVisor detonation canary lock")
    _exact_keys(
        lock,
        {
            "schema",
            "authority",
            "runtime_lock_digest",
            "daemon_config_digest",
            "runtime",
            "trace",
            "canary",
        },
        "gVisor detonation canary lock",
    )
    if (
        lock["schema"] != CANARY_LOCK_SCHEMA
        or lock["authority"] != CANARY_LOCK_AUTHORITY
    ):
        raise GVisorRuntimeError("gVisor detonation canary lock authority is invalid")
    _digest(lock["runtime_lock_digest"], "gVisor runtime lock")
    _digest(lock["daemon_config_digest"], "Docker daemon configuration")

    runtime = _object(lock["runtime"], "gVisor detonation canary runtime")
    _exact_keys(
        runtime,
        {"name", "path", "arguments"},
        "gVisor detonation canary runtime",
    )
    expected_log = "/var/log/aragorn-p2-docker-canary/%ID%.%CID%.%COMMAND%.jsonl"
    if runtime != {
        "name": "runsc-systrap-canary",
        "path": "/usr/local/bin/runsc",
        "arguments": [
            "--platform=systrap",
            "--directfs=false",
            "--network=none",
            "--strace=true",
            "--strace-syscalls=openat,execve",
            "--strace-log-size=256",
            "--debug=true",
            f"--debug-log={expected_log}",
            "--debug-log-format=json",
        ],
    }:
        raise GVisorRuntimeError("gVisor detonation canary runtime pin changed")

    trace = _object(lock["trace"], "gVisor detonation canary trace")
    _exact_keys(
        trace,
        {
            "directory",
            "format",
            "syscalls",
            "commands",
            "max_log_bytes",
            "max_log_lines",
            "max_line_bytes",
        },
        "gVisor detonation canary trace",
    )
    if trace != {
        "directory": "/var/log/aragorn-p2-docker-canary",
        "format": "json-lines",
        "syscalls": ["execve", "openat"],
        "commands": ["boot", "create", "gofer", "start"],
        "max_log_bytes": 1024 * 1024,
        "max_log_lines": 4096,
        "max_line_bytes": 32768,
    }:
        raise GVisorRuntimeError("gVisor detonation canary trace pin changed")

    canary = _object(lock["canary"], "gVisor detonation canary profile")
    _exact_keys(
        canary,
        {
            "command",
            "environment",
            "user",
            "network_mode",
            "read_only",
            "cap_drop",
            "security_opt",
            "pids_limit",
            "memory_bytes",
            "memory_swap_bytes",
            "nano_cpus",
            "nofile_soft",
            "nofile_hard",
            "tmpfs",
            "token",
            "token_path",
            "token_digest",
            "declared_capabilities",
            "source_events",
        },
        "gVisor detonation canary profile",
    )
    expected_token = "Aragorn-P2-canary-v1"
    expected_path = "/tmp/aragorn-canary"
    expected_events = [
        {
            "schema": "aragorn/detonation-source-event/v1",
            "operation": "file-open-read",
            "detail": f"gvisor-json-strace:openat:O_RDONLY:{expected_path}",
        },
        {
            "schema": "aragorn/detonation-source-event/v1",
            "operation": "process-exec",
            "detail": "gvisor-json-strace:execve:/bin/sha256sum",
        },
    ]
    if canary != {
        "command": [
            "/bin/sh",
            "-c",
            (
                "umask 077; printf Aragorn-P2-canary-v1 > /tmp/aragorn-canary; "
                "/bin/sha256sum /tmp/aragorn-canary >/dev/null; /bin/sleep 5; "
                "/bin/true"
            ),
        ],
        "environment": ["PATH=/bin"],
        "user": "65534:65534",
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges=true"],
        "pids_limit": 64,
        "memory_bytes": 64 * 1024 * 1024,
        "memory_swap_bytes": 64 * 1024 * 1024,
        "nano_cpus": 250_000_000,
        "nofile_soft": 1024,
        "nofile_hard": 1024,
        "tmpfs": {
            "destination": "/tmp",
            "options": "rw,noexec,nosuid,nodev,size=1048576",
        },
        "token": expected_token,
        "token_path": expected_path,
        "token_digest": _raw_digest(expected_token.encode("ascii")),
        "declared_capabilities": [],
        "source_events": expected_events,
    }:
        raise GVisorRuntimeError("gVisor detonation canary profile pin changed")
    return lock


def _verify_image(lock: dict[str, Any], raw: bytes) -> None:
    document = _json_value(raw, "Docker image inspect")
    if not isinstance(document, list) or len(document) != 1:
        raise GVisorRuntimeError("Docker image inspect must contain one image")
    image = _object(document[0], "Docker image inspect entry")
    expected = lock["image"]
    if (
        image.get("Id") != expected["digest"]
        or image.get("RepoDigests") != [expected["repo_digest"]]
        or image.get("Os") != expected["os"]
        or image.get("Architecture") != expected["architecture"]
    ):
        raise GVisorRuntimeError("Docker smoke image identity changed")


def _verify_container(
    lock: dict[str, Any], container: dict[str, Any], *, phase: str, run_id: str
) -> str:
    return _verify_container_profile(
        image=lock["image"],
        profile=lock["smoke"],
        runtime=lock["runtime"],
        container=container,
        phase=phase,
        labels={"aragorn.runtime-smoke.run_id": run_id},
        tmpfs=None,
    )


def _verify_detonation_container(
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    container: dict[str, Any],
    *,
    phase: str,
    run_id: str,
    artifact: _AcquiredArtifact | None,
    bind_mount: dict[str, str] | None,
) -> str:
    if (artifact is None) != (bind_mount is None):
        raise GVisorRuntimeError("acquired artifact mount identity changed")
    profile = (
        _artifact_profile(canary_lock)
        if artifact is not None
        else canary_lock["canary"]
    )
    label = (
        "aragorn.acquired-artifact.run_id"
        if artifact is not None
        else "aragorn.detonation-canary.run_id"
    )
    return _verify_container_profile(
        image=runtime_lock["image"],
        profile=profile,
        runtime=canary_lock["runtime"],
        container=container,
        phase=phase,
        labels={label: run_id},
        tmpfs={profile["tmpfs"]["destination"]: profile["tmpfs"]["options"]},
        bind_mount=bind_mount,
    )


def _verify_container_profile(
    *,
    image: dict[str, Any],
    profile: dict[str, Any],
    runtime: dict[str, Any],
    container: dict[str, Any],
    phase: str,
    labels: dict[str, str],
    tmpfs: dict[str, str] | None,
    bind_mount: dict[str, str] | None = None,
) -> str:
    container_id = container.get("Id")
    if not isinstance(container_id, str) or _CONTAINER.fullmatch(container_id) is None:
        raise GVisorRuntimeError("Docker container identity is invalid")
    if (
        container.get("Image") != image["digest"]
        or container.get("Path") != profile["command"][0]
        or container.get("Args") != profile["command"][1:]
        or container.get("Platform") != "linux"
    ):
        raise GVisorRuntimeError("Docker container execution identity changed")
    manifest = _object(
        container.get("ImageManifestDescriptor"), "container image descriptor"
    )
    if (
        manifest.get("digest") != image["digest"]
        or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        or manifest.get("platform")
        != {
            "architecture": image["architecture"],
            "os": image["os"],
            "variant": image["variant"],
        }
    ):
        raise GVisorRuntimeError("Docker container image descriptor changed")

    config = _object(container.get("Config"), "container configuration")
    if (
        config.get("Image") != image["reference"]
        or config.get("Cmd") != profile["command"]
        or config.get("User") != profile["user"]
        or config.get("Env") != profile["environment"]
        or config.get("Volumes") is not None
        or config.get("Entrypoint") is not None
        or config.get("Labels") != labels
    ):
        raise GVisorRuntimeError("Docker container configuration changed")

    expected_host = {
        "Runtime": runtime["name"],
        "NetworkMode": profile["network_mode"],
        "ReadonlyRootfs": profile["read_only"],
        "CapDrop": profile["cap_drop"],
        "SecurityOpt": profile["security_opt"],
        "PidsLimit": profile["pids_limit"],
        "Memory": profile["memory_bytes"],
        "MemorySwap": profile["memory_swap_bytes"],
        "NanoCpus": profile["nano_cpus"],
        "Ulimits": [
            {
                "Name": "nofile",
                "Hard": profile["nofile_hard"],
                "Soft": profile["nofile_soft"],
            }
        ],
    }
    if tmpfs is not None:
        expected_host["Tmpfs"] = tmpfs
    try:
        host, mounts = _verify_container_security_profile(
            container,
            expected_host=expected_host,
            expected_networks={"none"},
        )
    except VerificationError as exc:
        raise GVisorRuntimeError(str(exc)) from exc
    if (
        host.get("Binds") not in (None, [])
        or host.get("VolumesFrom") not in (None, [])
        or host.get("Links") not in (None, [])
        or host.get("ExtraHosts") not in (None, [])
        or host.get("Dns") not in (None, [])
        or host.get("DnsOptions") not in (None, [])
        or host.get("DnsSearch") not in (None, [])
        or host.get("GroupAdd") not in (None, [])
        or host.get("IpcMode") != "private"
        or host.get("CgroupnsMode") != "private"
        or host.get("PidMode") != ""
        or host.get("UTSMode") != ""
        or host.get("UsernsMode") != ""
    ):
        raise GVisorRuntimeError("Docker container has an unexpected host capability")
    host_mounts = host.get("Mounts")
    if bind_mount is None:
        if host_mounts not in (None, []) or mounts != []:
            raise GVisorRuntimeError("Docker container has an unexpected mount")
    else:
        if not isinstance(host_mounts, list) or len(host_mounts) != 1:
            raise GVisorRuntimeError("Docker container artifact mount is missing")
        host_mount = _object(host_mounts[0], "container artifact HostConfig mount")
        if (
            host_mount.get("Type") != "bind"
            or host_mount.get("Source") != bind_mount["source"]
            or host_mount.get("Target") != bind_mount["destination"]
            or host_mount.get("ReadOnly") is not True
            or len(mounts) != 1
        ):
            raise GVisorRuntimeError("Docker container artifact mount changed")
        mount = _object(mounts[0], "container artifact mount")
        if (
            mount.get("Type") != "bind"
            or mount.get("Source") != bind_mount["source"]
            or mount.get("Destination") != bind_mount["destination"]
            or mount.get("RW") is not False
            or mount.get("Mode") not in ("", "ro")
            or mount.get("Propagation") not in (None, "", "rprivate")
        ):
            raise GVisorRuntimeError("Docker resolved artifact mount changed")
    network = _object(container.get("NetworkSettings"), "container network settings")
    if network.get("Ports") not in (None, {}) or set(
        _object(network.get("Networks"), "container networks")
    ) != {"none"}:
        raise GVisorRuntimeError("Docker container network isolation changed")

    state = _object(container.get("State"), "container state")
    if phase == "prestart":
        expected_state = {
            "Status": "created",
            "Running": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
        }
    elif phase == "live":
        expected_state = {
            "Status": "running",
            "Running": True,
            "OOMKilled": False,
            "Dead": False,
            "ExitCode": 0,
            "Error": "",
        }
        if (
            isinstance(state.get("Pid"), bool)
            or not isinstance(state.get("Pid"), int)
            or state["Pid"] <= 0
        ):
            raise GVisorRuntimeError("live gVisor sandbox PID is invalid")
    elif phase == "postrun":
        expected_state = {
            "Status": "exited",
            "Running": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
        }
    else:
        raise GVisorRuntimeError("container verification phase is invalid")
    if any(state.get(field) != value for field, value in expected_state.items()):
        raise GVisorRuntimeError(f"Docker {phase} container state changed")
    return container_id


def _verify_processes(
    lock: dict[str, Any],
    raw: bytes,
    *,
    container_id: str,
    sandbox_pid: int,
    installed_runsc: dict[str, Any],
) -> None:
    pinned_runsc = _file_metadata_document(installed_runsc, "installed runsc")
    if pinned_runsc["path"] != lock["runtime"]["path"]:
        raise GVisorRuntimeError("installed runsc path changed")
    document = _json_object(raw, "gVisor process snapshot", canonical=True)
    _exact_keys(document, {"boot_id", "processes"}, "gVisor process snapshot")
    if (
        not isinstance(document["boot_id"], str)
        or _BOOT_ID.fullmatch(document["boot_id"]) is None
    ):
        raise GVisorRuntimeError("gVisor process boot identity is invalid")
    processes = document["processes"]
    if not isinstance(processes, list) or len(processes) != 3:
        raise GVisorRuntimeError("gVisor process snapshot must contain three processes")
    observed: dict[str, dict[str, Any]] = {}
    for item in processes:
        process = _object(item, "gVisor process")
        _exact_keys(
            process,
            {"role", "pid", "ppid", "starttime", "uids", "gids", "argv", "exe"},
            "gVisor process",
        )
        role = process["role"]
        if role not in {"gofer", "sandbox", "shim"} or role in observed:
            raise GVisorRuntimeError("gVisor process role is invalid")
        for field in ("pid", "starttime"):
            if (
                isinstance(process[field], bool)
                or not isinstance(process[field], int)
                or process[field] <= 0
            ):
                raise GVisorRuntimeError(f"gVisor process {field} is invalid")
        if (
            isinstance(process["ppid"], bool)
            or not isinstance(process["ppid"], int)
            or process["ppid"] < 0
            or not isinstance(process["uids"], list)
            or len(process["uids"]) != 4
            or not all(type(value) is int and value >= 0 for value in process["uids"])
            or not isinstance(process["gids"], list)
            or len(process["gids"]) != 4
            or not all(type(value) is int and value >= 0 for value in process["gids"])
            or not isinstance(process["argv"], list)
            or not process["argv"]
            or any(not isinstance(value, str) or not value for value in process["argv"])
        ):
            raise GVisorRuntimeError("gVisor process identity is invalid")
        _file_metadata_document(process["exe"], "gVisor process executable")
        observed[role] = process
    if list(observed) != ["gofer", "sandbox", "shim"]:
        raise GVisorRuntimeError("gVisor process snapshot order is not canonical")

    gofer = observed["gofer"]
    sandbox = observed["sandbox"]
    shim = observed["shim"]
    runsc_digest = next(
        item["digest"]
        for item in lock["binaries"]
        if item["path"] == lock["runtime"]["path"]
    )
    for process, name, subcommand, expected_ids in (
        (gofer, "runsc-gofer", "gofer", [0, 0]),
        (sandbox, "runsc-sandbox", "boot", [65534, 65534]),
    ):
        argv = process["argv"]
        executable = process["exe"]
        if (
            argv[0] != name
            or subcommand not in argv
            or container_id not in argv
            or "--platform=systrap" not in argv
            or "--directfs=false" not in argv
            or process["uids"][:2] != expected_ids
            or executable["path"] != lock["runtime"]["path"]
            or executable["digest"] != runsc_digest
        ):
            raise GVisorRuntimeError("gVisor runtime process identity changed")
    if (
        sandbox["pid"] != sandbox_pid
        or gofer["ppid"] != sandbox["ppid"]
        or gofer["ppid"] != shim["pid"]
        or shim["ppid"] != 1
        or shim["uids"][:2] != [0, 0]
        or shim["exe"]["path"] != "/usr/bin/containerd-shim-runc-v2"
        or shim["argv"][:3]
        != [
            "/usr/bin/containerd-shim-runc-v2",
            "-namespace",
            "moby",
        ]
        or "-id" not in shim["argv"]
        or container_id not in shim["argv"]
    ):
        raise GVisorRuntimeError("gVisor shim process relationship changed")
    for process in (gofer, sandbox):
        if any(
            process["exe"][field] != pinned_runsc[field]
            for field in (
                "path",
                "digest",
                "device",
                "inode",
                "mode",
                "uid",
                "gid",
                "size",
                "mtime_ns",
                "ctime_ns",
            )
        ):
            raise GVisorRuntimeError(
                "gVisor process did not execute the installed runsc inode"
            )


def _evidence_snapshot(
    value: object, *, expected: dict[str, int] = _EVIDENCE_LIMITS
) -> dict[str, bytes]:
    if type(value) is not dict:
        raise GVisorRuntimeError("gVisor runtime evidence must be a plain mapping")
    try:
        items = tuple(value.items())
    except RuntimeError as exc:
        raise GVisorRuntimeError(
            "gVisor runtime evidence changed during snapshot"
        ) from exc
    if {name for name, _raw in items} != set(expected):
        raise GVisorRuntimeError("gVisor runtime evidence inventory is incomplete")
    captured = dict(items)
    for name, raw in captured.items():
        if type(raw) is not bytes or len(raw) > expected[name]:
            raise GVisorRuntimeError(f"{name} evidence is invalid or oversized")
    return captured


def _inspect(raw: bytes, label: str) -> dict[str, Any]:
    value = _json_value(raw, label)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise GVisorRuntimeError(f"{label} must contain exactly one object")
    return value[0]


def _json_object(raw: bytes, label: str, *, canonical: bool = False) -> dict[str, Any]:
    value = _json_value(raw, label)
    if not isinstance(value, dict):
        raise GVisorRuntimeError(f"{label} must be a JSON object")
    if canonical:
        try:
            if canonical_json(value) != raw:
                raise GVisorRuntimeError(f"{label} must be canonical JSON")
        except WorkerProtocolError as exc:
            raise GVisorRuntimeError(f"{label} is not canonical JSON: {exc}") from exc
    return value


def _json_value(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise GVisorRuntimeError(f"{label} is invalid JSON: {exc}") from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GVisorRuntimeError(f"{label} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GVisorRuntimeError(f"{label} fields are invalid")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise GVisorRuntimeError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise GVisorRuntimeError(f"{label} digest is invalid")
    return value


def _raw_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"
