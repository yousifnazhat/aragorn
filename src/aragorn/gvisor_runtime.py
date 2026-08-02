"""Retain and replay one pinned gVisor runtime-path smoke."""

from __future__ import annotations

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
SCHEMA = "aragorn/gvisor-runtime-smoke-receipt/v1"
LOCK_SCHEMA = "aragorn/gvisor-runtime-lock/v1"
IMPLEMENTATION_SCHEMA = "aragorn/gvisor-runtime-implementation/v1"
AUTHORITY = (
    "RUNTIME_PATH_SMOKE_ONLY_NOT_RUNTIME_ATTESTATION_ISOLATION_OR_DETONATION_AUTHORITY"
)
LOCK_AUTHORITY = "PIN_ONLY_NOT_RUNTIME_ATTESTATION"

_MAX_LOCK_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_JSON_EVIDENCE_BYTES = 1024 * 1024
_MAX_PROCESS_BYTES = 64 * 1024
_MAX_STREAM_BYTES = 64 * 1024
_MAX_IMPLEMENTATION_MANIFEST_BYTES = 64 * 1024
_MAX_IMPLEMENTATION_SOURCE_BYTES = 1024 * 1024
_MAX_RUNTIME_BINARY_BYTES = 128 * 1024 * 1024
_MAX_DOCKER_BINARY_BYTES = 512 * 1024 * 1024
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


@dataclass(frozen=True, slots=True)
class _FileCapability:
    path: Path
    descriptor: int
    digest: str
    identity: tuple[int, int, int, int, int, int, int, int]
    metadata: dict[str, int | str]


class GVisorRuntimeError(ValueError):
    """A gVisor pin or runtime-path smoke failed closed."""


def load_gvisor_runtime_lock(
    path: str | Path = LOCK,
) -> tuple[bytes, dict[str, Any]]:
    """Load and validate the signed-repository trust pin."""

    try:
        candidate = Path(path).expanduser().resolve(strict=True)
        with candidate.open("rb") as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= _MAX_LOCK_BYTES
            ):
                raise GVisorRuntimeError(
                    "gVisor runtime lock is not a bounded regular file"
                )
            raw = source.read(_MAX_LOCK_BYTES + 1)
            if len(raw) != metadata.st_size or os.fstat(source.fileno()) != metadata:
                raise GVisorRuntimeError("gVisor runtime lock changed while read")
    except (OSError, RuntimeError) as exc:
        raise GVisorRuntimeError(f"cannot read gVisor runtime lock: {exc}") from exc
    return raw, _runtime_lock(raw)


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
        source_root = Path(__file__).resolve(strict=True).parent
        implementation_capabilities: dict[str, _FileCapability] = {}
        for module_name in _IMPLEMENTATION_MODULES:
            capability = _open_file_capability(
                source_root / module_name,
                expected_digest=None,
                maximum=_MAX_IMPLEMENTATION_SOURCE_BYTES,
                executable=False,
                label=f"gVisor runtime implementation {module_name}",
            )
            opened.append(capability)
            implementation_capabilities[module_name] = capability
        implementation_files = {
            module: capability.digest
            for module, capability in implementation_capabilities.items()
        }
        implementation_raw = canonical_json(
            {
                "schema": IMPLEMENTATION_SCHEMA,
                "files": implementation_files,
            }
        )
        if _raw_digest(implementation_raw) != expected_implementation:
            raise GVisorRuntimeError("gVisor runtime implementation identity changed")
        cas.put_expected(
            BytesIO(implementation_raw),
            expected_digest=expected_implementation,
            max_bytes=_MAX_IMPLEMENTATION_MANIFEST_BYTES,
        )
        for capability in implementation_capabilities.values():
            cas.put_expected(
                BytesIO(
                    _read_open_file(capability, _MAX_IMPLEMENTATION_SOURCE_BYTES)
                ),
                expected_digest=capability.digest,
                max_bytes=_MAX_IMPLEMENTATION_SOURCE_BYTES,
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
                _create_arguments(lock, container_name, run_id),
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

            cleanup_error = _cleanup_container(
                docker.path, container_name, docker_environment
            )
            container_name = None
            if cleanup_error is not None:
                raise GVisorRuntimeError(f"Docker cleanup failed: {cleanup_error}")
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
        if container_name is not None and docker_environment is not None:
            try:
                _cleanup_container(docker.path, container_name, docker_environment)
            except (OSError, UnboundLocalError):
                pass
        for capability in reversed(opened):
            os.close(capability.descriptor)


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
    lock: dict[str, Any], container_name: str, run_id: str
) -> tuple[str, ...]:
    smoke = lock["smoke"]
    return (
        "create",
        "--pull",
        "never",
        "--platform",
        "linux/arm64",
        "--name",
        container_name,
        "--label",
        f"aragorn.runtime-smoke.run_id={run_id}",
        "--runtime",
        lock["runtime"]["name"],
        "--network",
        smoke["network_mode"],
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        smoke["user"],
        "--pids-limit",
        str(smoke["pids_limit"]),
        "--memory",
        str(smoke["memory_bytes"]),
        "--memory-swap",
        str(smoke["memory_swap_bytes"]),
        "--cpus",
        f"{smoke['nano_cpus'] / 1_000_000_000:g}",
        "--ulimit",
        f"nofile={smoke['nofile_soft']}:{smoke['nofile_hard']}",
        "--env",
        smoke["environment"][0],
        lock["image"]["reference"],
        *smoke["command"],
    )


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


def _implementation_manifest(raw: bytes) -> dict[str, str]:
    document = _json_object(
        raw, "gVisor runtime implementation manifest", canonical=True
    )
    _exact_keys(
        document,
        {"schema", "files"},
        "gVisor runtime implementation manifest",
    )
    if document["schema"] != IMPLEMENTATION_SCHEMA:
        raise GVisorRuntimeError("gVisor runtime implementation schema changed")
    files = _object(document["files"], "gVisor runtime implementation files")
    if set(files) != set(_IMPLEMENTATION_MODULES):
        raise GVisorRuntimeError("gVisor runtime implementation inventory changed")
    return {
        module: _digest(files[module], f"gVisor runtime implementation {module}")
        for module in _IMPLEMENTATION_MODULES
    }


def _read_implementation(cas: CAS, digest: str) -> dict[str, str]:
    try:
        files = _implementation_manifest(
            cas.read(digest, max_bytes=_MAX_IMPLEMENTATION_MANIFEST_BYTES)
        )
        for source_digest in files.values():
            cas.verify(source_digest, max_bytes=_MAX_IMPLEMENTATION_SOURCE_BYTES)
        return files
    except CASError as exc:
        raise GVisorRuntimeError(
            f"cannot verify gVisor runtime implementation: {exc}"
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
    implementation_files = _read_implementation(
        cas, receipt["implementation_digest"]
    )
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


def _verify_evidence(
    lock: dict[str, Any],
    evidence: dict[str, bytes],
    *,
    run_id: str,
    implementation_files: dict[str, str],
) -> None:
    if set(implementation_files) != set(_IMPLEMENTATION_MODULES):
        raise GVisorRuntimeError("gVisor runtime implementation inventory changed")
    if evidence["runtime_version"] != lock["runtime"]["version_output"].encode():
        raise GVisorRuntimeError("gVisor runtime version changed")
    binaries = _json_value(evidence["installed_binaries"], "installed binaries")
    if not isinstance(binaries, list) or len(binaries) != len(lock["binaries"]):
        raise GVisorRuntimeError("installed gVisor binary inventory changed")
    expected_binaries = {item["path"]: item["digest"] for item in lock["binaries"]}
    observed_binaries: dict[str, dict[str, Any]] = {}
    for binary in binaries:
        metadata = _file_metadata_document(binary, "installed gVisor binary")
        if (
            metadata["uid"] != 0
            or metadata["mode"] & 0o022
            or not metadata["mode"] & 0o111
        ):
            raise GVisorRuntimeError("installed gVisor binary permissions are unsafe")
        observed_binaries[metadata["path"]] = metadata
    if {
        path: metadata["digest"] for path, metadata in observed_binaries.items()
    } != expected_binaries:
        raise GVisorRuntimeError("installed gVisor binary identities changed")

    daemon = _json_object(evidence["daemon_config"], "Docker daemon configuration")
    if _raw_digest(evidence["daemon_config"]) != lock["daemon_config_digest"]:
        raise GVisorRuntimeError("Docker daemon configuration identity changed")
    registration = _json_object(
        evidence["runtime_registration"], "Docker runtime registration"
    )
    expected_registration = {
        "path": lock["runtime"]["path"],
        "runtimeArgs": lock["runtime"]["arguments"],
    }
    if (
        set(registration) != {"path", "runtimeArgs", "status"}
        or {field: registration[field] for field in expected_registration}
        != expected_registration
        or not isinstance(registration["status"], dict)
    ):
        raise GVisorRuntimeError("Docker runtime registration changed")
    daemon_runtime = daemon.get("runtimes", {}).get(lock["runtime"]["name"])
    if daemon_runtime != expected_registration:
        raise GVisorRuntimeError("Docker daemon runtime configuration changed")

    docker = _file_metadata_document(
        _json_value(evidence["docker_executable"], "Docker executable"),
        "Docker executable",
    )
    if docker["uid"] != 0 or docker["mode"] & 0o022 or not docker["mode"] & 0o111:
        raise GVisorRuntimeError("Docker executable permissions are unsafe")
    helpers = _json_value(evidence["helper_implementations"], "gVisor runtime helpers")
    if not isinstance(helpers, list) or len(helpers) != len(_HELPER_MODULES):
        raise GVisorRuntimeError("gVisor runtime helper inventory changed")
    for expected_module, item in zip(_HELPER_MODULES, helpers, strict=True):
        helper = _object(item, "gVisor runtime helper")
        _exact_keys(helper, {"module", "file"}, "gVisor runtime helper")
        metadata = _file_metadata_document(helper["file"], "gVisor runtime helper")
        if (
            helper["module"] != expected_module
            or Path(metadata["path"]).name != expected_module
            or metadata["digest"] != implementation_files[expected_module]
            or metadata["uid"] != 0
            or metadata["mode"] & 0o022
        ):
            raise GVisorRuntimeError("gVisor runtime helper identity is unsafe")
    pre_runner = _runner_receipt(evidence["runner_pre"], "pre-run Docker identity")
    post_runner = _runner_receipt(evidence["runner_post"], "post-run Docker identity")
    if pre_runner.document_json != post_runner.document_json:
        raise GVisorRuntimeError("Docker runner identity changed during the smoke")

    _verify_image(lock, evidence["image_inspect"])
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
    container_id = container.get("Id")
    if not isinstance(container_id, str) or _CONTAINER.fullmatch(container_id) is None:
        raise GVisorRuntimeError("Docker container identity is invalid")
    image = lock["image"]
    smoke = lock["smoke"]
    runtime = lock["runtime"]
    if (
        container.get("Image") != image["digest"]
        or container.get("Path") != smoke["command"][0]
        or container.get("Args") != smoke["command"][1:]
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
        or config.get("Cmd") != smoke["command"]
        or config.get("User") != smoke["user"]
        or config.get("Env") != smoke["environment"]
        or config.get("Volumes") is not None
        or config.get("Entrypoint") is not None
        or config.get("Labels") != {"aragorn.runtime-smoke.run_id": run_id}
    ):
        raise GVisorRuntimeError("Docker container configuration changed")

    try:
        host, mounts = _verify_container_security_profile(
            container,
            expected_host={
                "Runtime": runtime["name"],
                "NetworkMode": smoke["network_mode"],
                "ReadonlyRootfs": smoke["read_only"],
                "CapDrop": smoke["cap_drop"],
                "SecurityOpt": smoke["security_opt"],
                "PidsLimit": smoke["pids_limit"],
                "Memory": smoke["memory_bytes"],
                "MemorySwap": smoke["memory_swap_bytes"],
                "NanoCpus": smoke["nano_cpus"],
                "Ulimits": [
                    {
                        "Name": "nofile",
                        "Hard": smoke["nofile_hard"],
                        "Soft": smoke["nofile_soft"],
                    }
                ],
            },
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
        or mounts != []
    ):
        raise GVisorRuntimeError("Docker container has an unexpected host capability")
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


def _evidence_snapshot(value: object) -> dict[str, bytes]:
    if type(value) is not dict:
        raise GVisorRuntimeError("gVisor runtime evidence must be a plain mapping")
    try:
        items = tuple(value.items())
    except RuntimeError as exc:
        raise GVisorRuntimeError(
            "gVisor runtime evidence changed during snapshot"
        ) from exc
    if {name for name, _raw in items} != set(_EVIDENCE_LIMITS):
        raise GVisorRuntimeError("gVisor runtime evidence inventory is incomplete")
    captured = dict(items)
    for name, raw in captured.items():
        if type(raw) is not bytes or len(raw) > _EVIDENCE_LIMITS[name]:
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
