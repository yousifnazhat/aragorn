"""Collect one exact three-run gVisor backend qualification batch."""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from .cas import CAS, CASError
from .docker_identity import DockerIdentityError
from .gvisor_backend_probe import (
    HOST_SNAPSHOT_SCHEMA,
    GVisorBackendProbeError,
    derive_gvisor_backend_controls,
)
from .gvisor_backend_qualification import (
    _ARTIFACT_FIELDS,
    _CONTROL_EXPECTATIONS,
    _MOUNT_DESTINATION,
    _RUN_LABEL,
    CLEANUP_EVIDENCE_SCHEMA,
    CONTROL_EVIDENCE_SCHEMA,
    HELPER_MODULES,
    IMPLEMENTATION_MODULES,
    IMPLEMENTATION_SCHEMA,
    PROFILE,
    RECEIPT_AUTHORITY,
    RECEIPT_SCHEMA,
    RUN_REQUEST_SCHEMA,
    GVisorBackendQualificationError,
    _qualification_lock,
    _qualification_profile,
    verify_gvisor_backend_qualification,
)
from .gvisor_runtime import (
    CANARY_LOCK,
    GVisorRuntimeError,
    _canary_lock,
    _canary_log_directory,
    _capture_cleanup_absence,
    _capture_processes,
    _cleanup_canary_logs_strict,
    _cleanup_container_strict,
    _command_environment,
    _create_arguments,
    _docker_output,
    _docker_result,
    _open_file_capability,
    _path_metadata,
    _raw_digest,
    _read_open_file,
    _require_canary_logs_new,
    _require_host_mount_namespace,
    _require_success,
    _retain_implementation,
    _runner_bundle,
    _runtime_lock,
    _stat_identity,
    _verify_container_profile,
    _verify_docker_unchanged,
    _verify_file_capability,
    _verify_image,
    _verify_protected_path,
    _verify_runtime_identity_evidence,
    _wait_for_live_container,
)
from .gvisor_runtime import LOCK as RUNTIME_LOCK
from .oci_runtime import (
    VerificationError,
    _capture_docker_document,
    _capture_post_runner_identity,
    _capture_pre_runner_identity,
    _inspect_container,
    _run_bounded,
    _RunnerReceiptBuffer,
    resolve_docker,
)
from .oci_worker_protocol import WorkerProtocolError, canonical_json

ROOT = Path(__file__).parents[2]
LOCK = ROOT / "benchmark" / "gvisor-backend-qualification-v1.lock.json"
PROBE = ROOT / "benchmark" / "fixtures" / "gvisor-backend-qualification" / "probe-v1.sh"
_RUNS = 3
_MAX_LOCK_BYTES = 64 * 1024
_MAX_PROBE_BYTES = 16 * 1024 * 1024
_MAX_RUNTIME_BINARY_BYTES = 128 * 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_STREAM_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_DOCKER_TIMEOUT_SECONDS = 30.0
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


class GVisorBackendQualificationCollectionError(ValueError):
    """The fixed backend qualification could not be collected safely."""


@dataclass(frozen=True, slots=True)
class _RunCapture:
    run_id: str
    container_id: str
    controls: list[dict[str, Any]]
    artifacts: dict[str, bytes]


def collect_gvisor_backend_qualification(
    cas: CAS,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
    lock_path: str | Path = LOCK,
    runtime_lock_path: str | Path = RUNTIME_LOCK,
    canary_lock_path: str | Path = CANARY_LOCK,
    probe_path: str | Path = PROBE,
    docker_executable: str | os.PathLike[str] = "docker",
) -> str:
    """Execute, retain, and replay the exact three-run qualification."""

    _require_collector_host()
    expected_lock = _digest(expected_lock_digest, "qualification lock")
    expected_runtime_lock = _digest(
        expected_runtime_lock_digest, "qualification runtime lock"
    )
    expected_implementation = _digest(
        expected_implementation_digest, "qualification implementation"
    )
    opened: list[Any] = []
    coordination = -1
    try:
        _require_host_mount_namespace()
        coordination = _open_coordination_lock(
            Path("/run/lock/aragorn-gvisor-canary.lock")
        )

        implementation_files, implementation_capabilities = _retain_implementation(
            cas,
            expected_digest=expected_implementation,
            schema=IMPLEMENTATION_SCHEMA,
            modules=IMPLEMENTATION_MODULES,
            opened=opened,
            label="gVisor backend qualification",
        )
        qualification_file = _open_file_capability(
            Path(lock_path).expanduser().resolve(strict=True),
            expected_digest=expected_lock,
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor backend qualification lock",
            retain=cas,
        )
        opened.append(qualification_file)
        qualification_lock = _qualification_lock(
            _read_open_file(qualification_file, _MAX_LOCK_BYTES)
        )
        if qualification_lock["runtime_lock_digest"] != expected_runtime_lock:
            raise GVisorBackendQualificationCollectionError(
                "qualification lock runtime identity changed"
            )

        runtime_file = _open_file_capability(
            Path(runtime_lock_path).expanduser().resolve(strict=True),
            expected_digest=expected_runtime_lock,
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor runtime lock",
            retain=cas,
        )
        opened.append(runtime_file)
        runtime_lock = _runtime_lock(_read_open_file(runtime_file, _MAX_LOCK_BYTES))
        canary_file = _open_file_capability(
            Path(canary_lock_path).expanduser().resolve(strict=True),
            expected_digest=qualification_lock["canary_lock_digest"],
            maximum=_MAX_LOCK_BYTES,
            executable=False,
            label="gVisor canary runtime lock",
            retain=cas,
        )
        opened.append(canary_file)
        canary_lock = _canary_lock(_read_open_file(canary_file, _MAX_LOCK_BYTES))
        if canary_lock["runtime_lock_digest"] != expected_runtime_lock:
            raise GVisorBackendQualificationCollectionError(
                "qualification canary runtime identity changed"
            )

        probe_file = _open_file_capability(
            Path(probe_path).expanduser().resolve(strict=True),
            expected_digest=qualification_lock["probe_digest"],
            maximum=_MAX_PROBE_BYTES,
            executable=False,
            label="gVisor backend qualification probe",
            retain=cas,
        )
        opened.append(probe_file)
        probe_raw = _read_open_file(probe_file, _MAX_PROBE_BYTES)

        installed = []
        runsc = None
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
            raise GVisorBackendQualificationCollectionError(
                "qualification runsc binary is absent"
            )
        daemon = _open_file_capability(
            Path("/etc/docker/daemon.json"),
            expected_digest=qualification_lock["daemon_config_digest"],
            maximum=_MAX_JSON_BYTES,
            executable=False,
            label="Docker daemon configuration",
            retain=cas,
        )
        opened.append(daemon)

        docker = resolve_docker(docker_executable)
        _verify_protected_path(docker.path)
        pre_runner = _RunnerReceiptBuffer()
        post_runner = _RunnerReceiptBuffer()
        with tempfile.TemporaryDirectory(
            prefix="aragorn-gvisor-qualification-control-"
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
            discovery_environment, docker_environment, runner_identity = (
                _capture_pre_runner_identity(docker, control_path, pre_runner)
            )
            runtime_name = canary_lock["runtime"]["name"]
            runtime_registration = _capture_docker_document(
                docker,
                (
                    "info",
                    "--format",
                    f'{{{{json (index .Runtimes "{runtime_name}")}}}}',
                ),
                env=docker_environment,
                label="Docker qualification runtime registration",
            )
            image_inspect = _docker_output(
                docker.path,
                ("image", "inspect", runtime_lock["image"]["reference"]),
                env=docker_environment,
                label="Docker qualification image inspect",
            )
            _verify_image(runtime_lock, image_inspect)
            _canary_log_directory(canary_lock, require_headroom=True)

            captures = [
                _collect_run(
                    docker.path,
                    docker_environment,
                    runtime_lock=runtime_lock,
                    canary_lock=canary_lock,
                    runsc=runsc,
                    probe_raw=probe_raw,
                    run_id=run_id,
                )
                for run_id in _fresh_run_ids()
            ]
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=docker_environment,
                expected=runner_identity,
                evidence=post_runner,
            )

        _verify_docker_unchanged(docker)
        for capability in opened:
            _verify_file_capability(capability)
        runner_pre = _runner_bundle(pre_runner)
        runner_post = _runner_bundle(post_runner)
        helper_implementations = [
            {
                "module": module,
                "file": implementation_capabilities[module].metadata,
            }
            for module in HELPER_MODULES
        ]
        runtime_identity_artifacts = {
            "runtime_version": runtime_version.stdout,
            "installed_binaries": canonical_json(installed),
            "runtime_registration": runtime_registration,
            "docker_executable": canonical_json(
                _path_metadata(docker.path, docker.digest)
            ),
            "helper_implementations": canonical_json(helper_implementations),
            "runner_identity_pre": runner_pre,
            "runner_identity_post": runner_post,
            "image_inspect": image_inspect,
        }
        _verify_runtime_identity_evidence(
            runtime_lock,
            {
                "runtime_version": runtime_identity_artifacts["runtime_version"],
                "installed_binaries": runtime_identity_artifacts["installed_binaries"],
                "daemon_config": _read_open_file(daemon, _MAX_JSON_BYTES),
                "runtime_registration": runtime_identity_artifacts[
                    "runtime_registration"
                ],
                "docker_executable": runtime_identity_artifacts["docker_executable"],
                "helper_implementations": runtime_identity_artifacts[
                    "helper_implementations"
                ],
                "runner_pre": runtime_identity_artifacts["runner_identity_pre"],
                "runner_post": runtime_identity_artifacts["runner_identity_post"],
                "image_inspect": runtime_identity_artifacts["image_inspect"],
            },
            implementation_files=implementation_files,
            runtime=canary_lock["runtime"],
            daemon_config_digest=qualification_lock["daemon_config_digest"],
            helper_modules=HELPER_MODULES,
            label="gVisor backend qualification",
        )

        runs = [
            _retain_run(
                cas,
                capture,
                shared_artifacts=runtime_identity_artifacts,
                lock_digest=expected_lock,
                runtime_lock_digest=expected_runtime_lock,
                implementation_digest=expected_implementation,
                probe_digest=qualification_lock["probe_digest"],
            )
            for capture in captures
        ]
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "authority": RECEIPT_AUTHORITY,
            "profile": PROFILE,
            "status": "PASS",
            "lock_digest": expected_lock,
            "runtime_lock_digest": expected_runtime_lock,
            "probe_digest": qualification_lock["probe_digest"],
            "implementation_digest": expected_implementation,
            "runs": runs,
        }
        receipt_digest = cas.put(
            BytesIO(canonical_json(receipt)), max_bytes=_MAX_RECEIPT_BYTES
        )
        verify_gvisor_backend_qualification(
            cas,
            receipt_digest,
            expected_lock_digest=expected_lock,
            expected_runtime_lock_digest=expected_runtime_lock,
            expected_implementation_digest=expected_implementation,
        )
        return receipt_digest
    except GVisorBackendQualificationCollectionError:
        raise
    except (
        CASError,
        DockerIdentityError,
        GVisorBackendProbeError,
        GVisorBackendQualificationError,
        GVisorRuntimeError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        VerificationError,
        WorkerProtocolError,
    ) as exc:
        raise GVisorBackendQualificationCollectionError(
            f"gVisor backend qualification collection failed: {exc}"
        ) from exc
    finally:
        for capability in reversed(opened):
            os.close(capability.descriptor)
        if coordination >= 0:
            os.close(coordination)


def _collect_run(
    docker: Path,
    environment: dict[str, str],
    *,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    runsc: Any,
    probe_raw: bytes,
    run_id: str,
) -> _RunCapture:
    cleanup_container_id: str | None = None
    trace_container_id: str | None = None
    host_process: subprocess.Popen[bytes] | None = None
    host_path: Path | None = None
    host_descriptor = -1
    input_descriptor = -1
    probe_descriptor = -1
    cleanup_errors: list[str] = []
    stage_name = ""
    capture: _RunCapture | None = None
    with tempfile.TemporaryDirectory(
        prefix=f"aragorn-gvisor-qualification-{run_id}-", dir="/run"
    ) as temporary:
        stage_name = temporary
        stage = Path(temporary)
        try:
            probe_descriptor = _write_exclusive(
                stage / "probe-v1.sh", probe_raw, mode=0o444
            )
            input_raw = f"Aragorn-input-{run_id}".encode("ascii")
            input_descriptor = _write_exclusive(stage / "input", input_raw, mode=0o444)
            stage.chmod(0o555)
            _verify_protected_path(stage / "probe-v1.sh")

            host_path = Path(f"/aragorn-host-file-{run_id}")
            host_raw = f"Aragorn-host-file-{run_id}".encode("ascii")
            host_descriptor = _write_exclusive(host_path, host_raw, mode=0o400)
            marker = f"Aragorn-host-process-{run_id}"
            host_process = subprocess.Popen(
                [marker, "30"],
                executable="/bin/sleep",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            host_pre = _host_snapshot(
                run_id,
                host_process.pid,
                host_path=host_path,
                host_descriptor=host_descriptor,
                input_path=stage / "input",
                input_descriptor=input_descriptor,
                process_marker=marker,
            )
            profile = _qualification_profile(canary_lock, run_id, host_process.pid)
            bind_mount = {
                "source": os.fspath(stage),
                "destination": _MOUNT_DESTINATION,
            }
            prior_logs = frozenset(
                path.name for path in _canary_log_directory(canary_lock).iterdir()
            )
            container_name = f"aragorn-gvisor-qualification-{run_id}"
            create = _docker_result(
                docker,
                _create_arguments(
                    image=runtime_lock["image"]["reference"],
                    profile=profile,
                    runtime=canary_lock["runtime"]["name"],
                    container_name=container_name,
                    run_label=f"{_RUN_LABEL}={run_id}",
                    tmpfs=profile["tmpfs"],
                    bind_mount=bind_mount,
                ),
                env=environment,
                label="Docker qualification create",
            )
            container_id = create.stdout.decode("ascii").strip()
            if _CONTAINER_ID.fullmatch(container_id) is None:
                raise GVisorBackendQualificationCollectionError(
                    "Docker qualification create returned an invalid container ID"
                )
            # ponytail: ambiguous create may orphan; never delete an unowned name.
            cleanup_container_id = container_id
            trace_container_id = container_id
            pre, pre_raw = _inspect_container(docker, container_id, environment)
            _verify_qualification_container(
                runtime_lock,
                canary_lock,
                profile,
                bind_mount,
                pre,
                phase="prestart",
                run_id=run_id,
            )
            _require_canary_logs_new(canary_lock, container_id, prior_logs)
            started = _docker_result(
                docker,
                ("start", container_id),
                env=environment,
                label="Docker qualification start",
            )
            if started.stdout != f"{container_id}\n".encode("ascii"):
                raise GVisorBackendQualificationCollectionError(
                    "Docker qualification start returned a different container ID"
                )
            live, live_raw = _wait_for_live_container(docker, container_id, environment)
            _verify_qualification_container(
                runtime_lock,
                canary_lock,
                profile,
                bind_mount,
                live,
                phase="live",
                run_id=run_id,
            )
            processes = _capture_processes(
                runtime_lock,
                runtime=canary_lock["runtime"],
                container_id=container_id,
                sandbox_pid=live["State"]["Pid"],
                runsc=runsc,
            )
            waited = _docker_result(
                docker,
                ("wait", container_id),
                env=environment,
                label="Docker qualification wait",
                timeout=25.0,
            )
            if waited.stdout != b"0\n" or waited.stderr:
                raise GVisorBackendQualificationCollectionError(
                    "gVisor qualification probe did not exit cleanly"
                )
            logs = _docker_result(
                docker,
                ("logs", container_id),
                env=environment,
                label="Docker qualification logs",
            )
            post, post_raw = _inspect_container(docker, container_id, environment)
            _verify_qualification_container(
                runtime_lock,
                canary_lock,
                profile,
                bind_mount,
                post,
                phase="postrun",
                run_id=run_id,
            )
            for field in ("Created", "Image", "Path", "Args"):
                if pre.get(field) != live.get(field) or pre.get(field) != post.get(
                    field
                ):
                    raise GVisorBackendQualificationCollectionError(
                        f"qualification container {field} changed across the run"
                    )
            host_post = _host_snapshot(
                run_id,
                host_process.pid,
                host_path=host_path,
                host_descriptor=host_descriptor,
                input_path=stage / "input",
                input_descriptor=input_descriptor,
                process_marker=marker,
            )
            controls = derive_gvisor_backend_controls(
                logs.stdout,
                logs.stderr,
                host_pre,
                host_post,
                expected_run_id=run_id,
            )
            expected_controls = [
                {"control_id": control_id, "observed": expected}
                for control_id, expected in _CONTROL_EXPECTATIONS
            ]
            if canonical_json(controls) != canonical_json(expected_controls):
                raise GVisorBackendQualificationCollectionError(
                    "qualification probe did not satisfy every fixed control"
                )

            _cleanup_container_strict(
                docker,
                container_id,
                environment,
                label="Docker qualification",
            )
            cleanup_container_id = None
            container_cleanup = _capture_cleanup_absence(
                docker, container_id, environment
            )
            _cleanup_canary_logs_strict(canary_lock, container_id)
            trace_container_id = None
            _stop_process(host_process)
            host_process = None
            os.close(host_descriptor)
            host_descriptor = -1
            host_path.unlink()
            if host_path.exists():
                raise GVisorBackendQualificationCollectionError(
                    "qualification host sentinel cleanup was incomplete"
                )
            host_path = None
            os.close(input_descriptor)
            input_descriptor = -1
            os.close(probe_descriptor)
            probe_descriptor = -1
            capture = _RunCapture(
                run_id=run_id,
                container_id=container_id,
                controls=controls,
                artifacts={
                    "container_cleanup": container_cleanup,
                    "container_live_inspect": live_raw,
                    "container_post_inspect": post_raw,
                    "container_pre_inspect": pre_raw,
                    "container_processes": processes,
                    "host_sentinel_post": host_post,
                    "host_sentinel_pre": host_pre,
                    "probe_stderr": logs.stderr,
                    "probe_stdout": logs.stdout,
                },
            )
        finally:
            if cleanup_container_id is not None:
                try:
                    _cleanup_container_strict(
                        docker,
                        cleanup_container_id,
                        environment,
                        label="Docker qualification",
                    )
                except (GVisorRuntimeError, OSError) as exc:
                    cleanup_errors.append(str(exc))
            if trace_container_id is not None:
                try:
                    _cleanup_canary_logs_strict(canary_lock, trace_container_id)
                except (GVisorRuntimeError, OSError) as exc:
                    cleanup_errors.append(str(exc))
            if host_process is not None:
                try:
                    _stop_process(host_process)
                except (OSError, subprocess.SubprocessError) as exc:
                    cleanup_errors.append(str(exc))
            for descriptor in (
                host_descriptor,
                input_descriptor,
                probe_descriptor,
            ):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError as exc:
                        cleanup_errors.append(str(exc))
            if host_path is not None:
                try:
                    host_path.unlink(missing_ok=True)
                except OSError as exc:
                    cleanup_errors.append(str(exc))
            if cleanup_errors:
                raise GVisorBackendQualificationCollectionError(
                    "qualification run cleanup failed: " + "; ".join(cleanup_errors)
                )
    if Path(stage_name).exists():
        raise GVisorBackendQualificationCollectionError(
            "qualification staging cleanup was incomplete"
        )
    if capture is None:
        raise GVisorBackendQualificationCollectionError(
            "qualification run did not produce a capture"
        )
    return capture


def _verify_qualification_container(
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    profile: dict[str, Any],
    bind_mount: dict[str, str],
    container: dict[str, Any],
    *,
    phase: str,
    run_id: str,
) -> str:
    return _verify_container_profile(
        image=runtime_lock["image"],
        profile=profile,
        runtime=canary_lock["runtime"],
        container=container,
        phase=phase,
        labels={_RUN_LABEL: run_id},
        tmpfs={profile["tmpfs"]["destination"]: profile["tmpfs"]["options"]},
        bind_mount=bind_mount,
    )


def _retain_run(
    cas: CAS,
    capture: _RunCapture,
    *,
    shared_artifacts: dict[str, bytes],
    lock_digest: str,
    runtime_lock_digest: str,
    implementation_digest: str,
    probe_digest: str,
) -> dict[str, str]:
    raw_artifacts = capture.artifacts | shared_artifacts
    if set(raw_artifacts) != _ARTIFACT_FIELDS:
        raise GVisorBackendQualificationCollectionError(
            "qualification artifact inventory is incomplete"
        )
    artifacts = {
        name: cas.put(BytesIO(raw), max_bytes=_MAX_JSON_BYTES)
        for name, raw in sorted(raw_artifacts.items())
    }
    run_request = {
        "schema": RUN_REQUEST_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "implementation_digest": implementation_digest,
        "probe_digest": probe_digest,
        "run_id": capture.run_id,
    }
    control_evidence = {
        "schema": CONTROL_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "run_id": capture.run_id,
        "container_id": capture.container_id,
        "controls": capture.controls,
        "artifacts": artifacts,
    }
    cleanup_evidence = {
        "schema": CLEANUP_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "run_id": capture.run_id,
        "container_id": capture.container_id,
        "container_absent": True,
        "trace_files_absent": True,
        "host_sentinels_unchanged": True,
        "sinks_closed": True,
    }
    return {
        "run_id": capture.run_id,
        "container_id": capture.container_id,
        "run_request_digest": _put_document(cas, run_request),
        "control_evidence_digest": _put_document(cas, control_evidence),
        "cleanup_evidence_digest": _put_document(cas, cleanup_evidence),
    }


def _host_snapshot(
    run_id: str,
    process_id: int,
    *,
    host_path: Path,
    host_descriptor: int,
    input_path: Path,
    input_descriptor: int,
    process_marker: str,
) -> bytes:
    host_raw = _stable_file(host_path, host_descriptor)
    input_raw = _stable_file(input_path, input_descriptor)
    expected_host = f"Aragorn-host-file-{run_id}".encode("ascii")
    expected_input = f"Aragorn-input-{run_id}".encode("ascii")
    expected_marker = f"Aragorn-host-process-{run_id}"
    if (
        host_raw != expected_host
        or input_raw != expected_input
        or process_marker != expected_marker
    ):
        raise GVisorBackendQualificationCollectionError(
            "qualification host sentinel identity changed"
        )
    start_ticks = _process_identity(process_id, process_marker)
    return canonical_json(
        {
            "schema": HOST_SNAPSHOT_SCHEMA,
            "run_id": run_id,
            "host_file_digest": _raw_digest(host_raw),
            "input_digest": _raw_digest(input_raw),
            "process_id": process_id,
            "process_start_ticks": start_ticks,
            "process_marker_digest": _raw_digest(process_marker.encode("ascii")),
        }
    )


def _stable_file(path: Path, descriptor: int) -> bytes:
    before = os.fstat(descriptor)
    path_before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino)
        or not 0 < before.st_size <= _MAX_PROBE_BYTES
    ):
        raise GVisorBackendQualificationCollectionError(
            "qualification sentinel file identity changed"
        )
    raw = os.pread(descriptor, before.st_size, 0)
    after = os.fstat(descriptor)
    path_after = path.lstat()
    if (
        len(raw) != before.st_size
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(before) != _stat_identity(path_after)
    ):
        raise GVisorBackendQualificationCollectionError(
            "qualification sentinel file changed while read"
        )
    return raw


def _process_identity(process_id: int, marker: str) -> int:
    stat_path = Path(f"/proc/{process_id}/stat")
    cmdline_path = Path(f"/proc/{process_id}/cmdline")
    before = stat_path.read_bytes()
    cmdline = cmdline_path.read_bytes()
    after = stat_path.read_bytes()
    if before != after or cmdline != f"{marker}\0{30}\0".encode("ascii"):
        raise GVisorBackendQualificationCollectionError(
            "qualification host process identity changed"
        )
    closing = before.rfind(b") ")
    if closing < 0:
        raise GVisorBackendQualificationCollectionError(
            "qualification host process stat is malformed"
        )
    fields = before[closing + 2 :].split()
    try:
        start_ticks = int(fields[19])
    except (IndexError, ValueError) as exc:
        raise GVisorBackendQualificationCollectionError(
            "qualification host process start time is invalid"
        ) from exc
    if start_ticks <= 0:
        raise GVisorBackendQualificationCollectionError(
            "qualification host process start time is invalid"
        )
    return start_ticks


def _write_exclusive(path: Path, raw: bytes, *, mode: int) -> int:
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if os.write(descriptor, raw) != len(raw):
            raise GVisorBackendQualificationCollectionError(
                "qualification sentinel write was incomplete"
            )
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != len(raw):
            raise GVisorBackendQualificationCollectionError(
                "qualification sentinel size changed"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3.0)
    if process.poll() is None:
        raise GVisorBackendQualificationCollectionError(
            "qualification host process cleanup was incomplete"
        )


def _fresh_run_ids() -> tuple[str, str, str]:
    run_ids: set[str] = set()
    while len(run_ids) < _RUNS:
        run_ids.add(secrets.token_hex(16))
    ordered = sorted(run_ids)
    return ordered[0], ordered[1], ordered[2]


def _open_coordination_lock(path: Path) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(path, flags)
        try:
            value = os.fstat(descriptor)
            current = path.lstat()
            if (
                not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) != 0o600
                or value.st_nlink != 1
                or (value.st_dev, value.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise GVisorBackendQualificationCollectionError(
                    "gVisor coordination lock identity is unsafe"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise GVisorBackendQualificationCollectionError(
                    "another gVisor capture is active"
                ) from exc
            after = path.lstat()
            if (value.st_dev, value.st_ino) != (after.st_dev, after.st_ino):
                raise GVisorBackendQualificationCollectionError(
                    "gVisor coordination lock identity changed"
                )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    except GVisorBackendQualificationCollectionError:
        raise
    except OSError as exc:
        raise GVisorBackendQualificationCollectionError(
            f"cannot open gVisor coordination lock: {exc}"
        ) from exc


def _require_collector_host() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise GVisorBackendQualificationCollectionError(
            "gVisor backend qualification collection requires Linux root"
        )


def _put_document(cas: CAS, value: object) -> str:
    return cas.put(BytesIO(canonical_json(value)), max_bytes=_MAX_JSON_BYTES)


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
    ):
        raise GVisorBackendQualificationCollectionError(f"{label} is invalid")
    return value
