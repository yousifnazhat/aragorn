"""Verify one exact-profile gVisor backend qualification evidence batch."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .cas import CAS, CASError
from .gvisor_backend_probe import (
    GVisorBackendProbeError,
    derive_gvisor_backend_controls,
)
from .gvisor_runtime import (
    CANARY_CLEANUP_SCHEMA,
    _canary_lock,
    _inspect,
    _read_implementation,
    _read_lock,
    _runtime_lock,
    _verify_container_profile,
    _verify_processes,
    _verify_runtime_identity_evidence,
)
from .oci_worker_protocol import WorkerProtocolError, _digest, canonical_json

LOCK_SCHEMA = "aragorn/gvisor-backend-qualification-lock/v1"
LOCK_AUTHORITY = "PIN_ONLY_NOT_BACKEND_QUALIFICATION_OR_PHASE2_EXIT_AUTHORITY"
RECEIPT_SCHEMA = "aragorn/gvisor-backend-qualification-receipt/v1"
RECEIPT_AUTHORITY = (
    "EXACT_COLIMA_GVISOR_RUNSC_SYSTRAP_CANARY_THREE_RUN_FIXED_PROFILE_AND_"
    "NEGATIVE_CONTROL_QUALIFICATION_WITH_FAILED_SEND_AND_NO_NON_LOOPBACK_PATH_"
    "ONLY_NOT_INDEPENDENT_EGRESS_OBSERVATION_HOST_HYPERVISOR_HARDWARE_"
    "ATTESTATION_GENERAL_ESCAPE_ABSENCE_CAPTURE_COMPLETENESS_VARIED_SCENARIOS_"
    "ADMISSION_OR_PHASE2_EXIT_AUTHORITY"
)
PROFILE = "colima-gvisor-runsc-systrap-canary-negative-controls/v1"
RUN_REQUEST_SCHEMA = "aragorn/gvisor-backend-qualification-run-request/v1"
CONTROL_EVIDENCE_SCHEMA = "aragorn/gvisor-backend-qualification-controls/v1"
CLEANUP_EVIDENCE_SCHEMA = "aragorn/gvisor-backend-qualification-cleanup/v1"
IMPLEMENTATION_SCHEMA = "aragorn/gvisor-backend-qualification-implementation/v1"
IMPLEMENTATION_MODULES = (
    "gvisor_runtime.py",
    "__init__.py",
    "acquire.py",
    "analyze.py",
    "cas.py",
    "docker_identity.py",
    "gvisor_backend_probe.py",
    "gvisor_backend_qualification.py",
    "gvisor_backend_qualification_collect.py",
    "oci_runtime.py",
    "oci_worker_protocol.py",
)
HELPER_MODULES = tuple(
    module for module in IMPLEMENTATION_MODULES if module != "gvisor_runtime.py"
)

_RUNS = 3
_MAX_LOCK_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_MAX_EVIDENCE_DOCUMENT_BYTES = 256 * 1024
_MAX_EVIDENCE_BLOB_BYTES = 2 * 1024 * 1024
_MAX_IMPLEMENTATION_BYTES = 16 * 1024 * 1024
_MAX_PROBE_BYTES = 16 * 1024 * 1024
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")

_CONTROL_EXPECTATIONS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "identity-profile",
        {
            "capability_masks_zero": True,
            "gid": 65534,
            "no_new_privileges": True,
            "supplementary_groups": [],
            "uid": 65534,
        },
    ),
    (
        "tmpfs-write-positive",
        {"attempted": True, "cleaned": True, "succeeded": True},
    ),
    (
        "tcp-sink-positive-control",
        {"attempted": True, "control_token_received": True},
    ),
    (
        "udp-sink-positive-control",
        {"attempted": True, "control_token_received": True},
    ),
    (
        "host-file-isolation",
        {"attempted": True, "host_unchanged": True, "visible": False},
    ),
    (
        "host-process-isolation",
        {"attempted": True, "host_alive": True, "visible": False},
    ),
    (
        "tcp-egress-denied",
        {"attempted": True, "no_non_loopback_path": True, "send_failed": True},
    ),
    (
        "udp-egress-denied",
        {"attempted": True, "no_non_loopback_path": True, "send_failed": True},
    ),
    (
        "rootfs-write-denied",
        {"artifact_absent": True, "attempted": True, "succeeded": False},
    ),
    (
        "input-mutation-denied",
        {
            "host_unchanged": True,
            "read_control_succeeded": True,
            "rename_succeeded": False,
            "unlink_succeeded": False,
            "write_succeeded": False,
        },
    ),
    (
        "tmpfs-exec-denied",
        {"attempted": True, "succeeded": False, "write_control_succeeded": True},
    ),
    (
        "mount-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "namespace-create-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "device-create-denied",
        {"attempted": True, "succeeded": False},
    ),
    (
        "privilege-escalation-denied",
        {
            "setgid_attempted": True,
            "setgid_succeeded": False,
            "setuid_attempted": True,
            "setuid_succeeded": False,
        },
    ),
)
_CONTROL_IDS = [control_id for control_id, _expected in _CONTROL_EXPECTATIONS]
_ARTIFACT_FIELDS = {
    "container_cleanup",
    "container_live_inspect",
    "container_post_inspect",
    "container_pre_inspect",
    "container_processes",
    "docker_executable",
    "helper_implementations",
    "host_sentinel_post",
    "host_sentinel_pre",
    "image_inspect",
    "installed_binaries",
    "probe_stderr",
    "probe_stdout",
    "runner_identity_post",
    "runner_identity_pre",
    "runtime_registration",
    "runtime_version",
}
_SHARED_ARTIFACT_FIELDS = {
    "docker_executable",
    "helper_implementations",
    "image_inspect",
    "installed_binaries",
    "runner_identity_post",
    "runner_identity_pre",
    "runtime_registration",
    "runtime_version",
}
_PROFILE_FIELDS = (
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
)
_MOUNT_DESTINATION = "/aragorn-qualification"
_RUN_LABEL = "aragorn.backend-qualification.run_id"
_LOCK_FIELDS = {
    "schema",
    "authority",
    "profile",
    "runs",
    "runtime_lock_digest",
    "canary_lock_digest",
    "daemon_config_digest",
    "probe_digest",
    "controls",
}
_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "profile",
    "status",
    "lock_digest",
    "runtime_lock_digest",
    "probe_digest",
    "implementation_digest",
    "runs",
}
_RUN_FIELDS = {
    "run_id",
    "container_id",
    "run_request_digest",
    "control_evidence_digest",
    "cleanup_evidence_digest",
}


class GVisorBackendQualificationError(ValueError):
    """A backend qualification contract is malformed or unbound."""


def load_gvisor_backend_qualification_lock(
    path: str | Path,
) -> tuple[bytes, dict[str, Any]]:
    """Load one canonical exact-profile qualification lock from disk."""

    try:
        raw = _read_lock(path, "gVisor backend qualification")
        return raw, _qualification_lock(raw)
    except GVisorBackendQualificationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise GVisorBackendQualificationError(
            f"cannot load gVisor backend qualification lock: {exc}"
        ) from exc


def verify_gvisor_backend_qualification(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> dict[str, Any]:
    """Replay one caller-pinned three-run qualification receipt."""

    receipt, _limits = _verify_qualification(
        cas,
        receipt_digest,
        expected_lock_digest=expected_lock_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_implementation_digest=expected_implementation_digest,
    )
    return receipt


def derive_gvisor_backend_qualification_closure(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> dict[str, int]:
    """Return every verified blob required to replay the qualification."""

    _receipt, limits = _verify_qualification(
        cas,
        receipt_digest,
        expected_lock_digest=expected_lock_digest,
        expected_runtime_lock_digest=expected_runtime_lock_digest,
        expected_implementation_digest=expected_implementation_digest,
    )
    try:
        return {
            digest: len(cas.read(digest, max_bytes=maximum))
            for digest, maximum in sorted(limits.items())
        }
    except CASError as exc:
        raise GVisorBackendQualificationError(
            f"cannot derive gVisor backend qualification closure: {exc}"
        ) from exc


def _verify_qualification(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_lock_digest: str,
    expected_runtime_lock_digest: str,
    expected_implementation_digest: str,
) -> tuple[dict[str, Any], dict[str, int]]:
    try:
        receipt_id = _digest(receipt_digest, "backend qualification receipt")
        lock_id = _digest(expected_lock_digest, "backend qualification lock")
        runtime_lock_id = _digest(
            expected_runtime_lock_digest, "backend qualification runtime lock"
        )
        implementation_id = _digest(
            expected_implementation_digest,
            "backend qualification verifier implementation",
        )
        receipt = _canonical_object(
            cas.read(receipt_id, max_bytes=_MAX_RECEIPT_BYTES),
            "backend qualification receipt",
        )
        _exact_fields(receipt, _RECEIPT_FIELDS, "backend qualification receipt")
        if (
            receipt["schema"] != RECEIPT_SCHEMA
            or receipt["authority"] != RECEIPT_AUTHORITY
            or receipt["profile"] != PROFILE
            or receipt["status"] != "PASS"
        ):
            raise GVisorBackendQualificationError(
                "backend qualification receipt authority is unsupported"
            )
        if receipt["lock_digest"] != lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt lock digest drifted"
            )
        if receipt["runtime_lock_digest"] != runtime_lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt runtime lock digest drifted"
            )
        if receipt["implementation_digest"] != implementation_id:
            raise GVisorBackendQualificationError(
                "backend qualification verifier implementation drifted"
            )

        lock = _qualification_lock(cas.read(lock_id, max_bytes=_MAX_LOCK_BYTES))
        if lock["runtime_lock_digest"] != runtime_lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification lock runtime identity drifted"
            )
        probe_id = _digest(lock["probe_digest"], "backend qualification probe")
        canary_lock_id = _digest(
            lock["canary_lock_digest"], "backend qualification canary lock"
        )
        daemon_config_id = _digest(
            lock["daemon_config_digest"],
            "backend qualification daemon configuration",
        )
        if receipt["probe_digest"] != probe_id:
            raise GVisorBackendQualificationError(
                "backend qualification receipt probe digest drifted"
            )

        runtime_lock = _runtime_lock(
            cas.read(runtime_lock_id, max_bytes=_MAX_LOCK_BYTES)
        )
        canary_lock = _canary_lock(cas.read(canary_lock_id, max_bytes=_MAX_LOCK_BYTES))
        if canary_lock["runtime_lock_digest"] != runtime_lock_id:
            raise GVisorBackendQualificationError(
                "backend qualification canary runtime identity drifted"
            )
        daemon_config = cas.read(daemon_config_id, max_bytes=_MAX_EVIDENCE_BLOB_BYTES)
        implementation_files = _read_implementation(
            cas,
            implementation_id,
            schema=IMPLEMENTATION_SCHEMA,
            modules=IMPLEMENTATION_MODULES,
            label="gVisor backend qualification",
        )

        limits = {
            receipt_id: _MAX_RECEIPT_BYTES,
            lock_id: _MAX_LOCK_BYTES,
            runtime_lock_id: _MAX_LOCK_BYTES,
            canary_lock_id: _MAX_LOCK_BYTES,
            daemon_config_id: _MAX_EVIDENCE_BLOB_BYTES,
            implementation_id: _MAX_IMPLEMENTATION_BYTES,
            probe_id: _MAX_PROBE_BYTES,
            **{
                digest: _MAX_IMPLEMENTATION_BYTES
                for digest in implementation_files.values()
            },
        }
        for digest, maximum in limits.items():
            cas.verify(digest, max_bytes=maximum)
        _verify_runs(
            cas,
            receipt["runs"],
            lock_digest=lock_id,
            runtime_lock_digest=runtime_lock_id,
            implementation_digest=implementation_id,
            probe_digest=probe_id,
            runtime_lock=runtime_lock,
            canary_lock=canary_lock,
            daemon_config=daemon_config,
            daemon_config_digest=daemon_config_id,
            implementation_files=implementation_files,
            limits=limits,
        )
        return receipt, limits
    except GVisorBackendQualificationError:
        raise
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise GVisorBackendQualificationError(
            f"cannot verify gVisor backend qualification: {exc}"
        ) from exc


def _verify_runs(
    cas: CAS,
    value: object,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    implementation_digest: str,
    probe_digest: str,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    daemon_config: bytes,
    daemon_config_digest: str,
    implementation_files: dict[str, str],
    limits: dict[str, int],
) -> None:
    if not isinstance(value, list) or len(value) != _RUNS:
        raise GVisorBackendQualificationError(
            "backend qualification requires exactly three run records"
        )
    run_ids: list[str] = []
    container_ids: set[str] = set()
    primary_evidence: set[str] = set()
    captures: list[tuple[str, str, dict[str, str]]] = []
    shared_artifacts: dict[str, str] | None = None
    for index, raw_run in enumerate(value):
        label = f"backend qualification runs[{index}]"
        run = _object(raw_run, label)
        _exact_fields(run, _RUN_FIELDS, label)
        run_id = _hex(run["run_id"], _RUN_ID, f"{label}.run_id")
        container_id = _hex(run["container_id"], _CONTAINER_ID, f"{label}.container_id")
        if run_id in run_ids or container_id in container_ids:
            raise GVisorBackendQualificationError(
                "backend qualification repeats a run or container ID"
            )
        run_ids.append(run_id)
        container_ids.add(container_id)
        digests = {
            field: _digest(run[field], f"{label}.{field}")
            for field in (
                "run_request_digest",
                "control_evidence_digest",
                "cleanup_evidence_digest",
            )
        }
        if primary_evidence.intersection(digests.values()):
            raise GVisorBackendQualificationError(
                "backend qualification repeats run-bound evidence"
            )
        primary_evidence.update(digests.values())
        _verify_run_request(
            cas,
            digests["run_request_digest"],
            lock_digest=lock_digest,
            runtime_lock_digest=runtime_lock_digest,
            implementation_digest=implementation_digest,
            probe_digest=probe_digest,
            run_id=run_id,
        )
        artifacts = _verify_control_evidence(
            cas,
            digests["control_evidence_digest"],
            lock_digest=lock_digest,
            runtime_lock_digest=runtime_lock_digest,
            probe_digest=probe_digest,
            run_id=run_id,
            container_id=container_id,
        )
        observed_shared = {field: artifacts[field] for field in _SHARED_ARTIFACT_FIELDS}
        if shared_artifacts is None:
            shared_artifacts = observed_shared
        elif observed_shared != shared_artifacts:
            raise GVisorBackendQualificationError(
                "backend qualification shared runtime evidence drifted"
            )
        captures.append((run_id, container_id, artifacts))
        _verify_cleanup_evidence(
            cas,
            digests["cleanup_evidence_digest"],
            lock_digest=lock_digest,
            run_id=run_id,
            container_id=container_id,
        )
        for digest in digests.values():
            limits[digest] = _MAX_EVIDENCE_DOCUMENT_BYTES
        for digest in artifacts.values():
            limits[digest] = max(
                limits.get(digest, 0),
                _MAX_EVIDENCE_BLOB_BYTES,
            )
            cas.verify(digest, max_bytes=_MAX_EVIDENCE_BLOB_BYTES)
    if run_ids != sorted(run_ids):
        raise GVisorBackendQualificationError(
            "backend qualification run records must be sorted by run ID"
        )
    if shared_artifacts is None:
        raise GVisorBackendQualificationError(
            "backend qualification shared runtime evidence is absent"
        )
    observed_binaries = _verify_shared_runtime_evidence(
        cas,
        shared_artifacts,
        runtime_lock=runtime_lock,
        canary_lock=canary_lock,
        daemon_config=daemon_config,
        daemon_config_digest=daemon_config_digest,
        implementation_files=implementation_files,
    )
    for run_id, container_id, artifacts in captures:
        _verify_execution_evidence(
            cas,
            artifacts,
            runtime_lock=runtime_lock,
            canary_lock=canary_lock,
            observed_binaries=observed_binaries,
            run_id=run_id,
            container_id=container_id,
        )


def _verify_shared_runtime_evidence(
    cas: CAS,
    artifacts: dict[str, str],
    *,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    daemon_config: bytes,
    daemon_config_digest: str,
    implementation_files: dict[str, str],
) -> dict[str, dict[str, Any]]:
    return _verify_runtime_identity_evidence(
        runtime_lock,
        {
            "runtime_version": _artifact(cas, artifacts, "runtime_version"),
            "installed_binaries": _artifact(cas, artifacts, "installed_binaries"),
            "daemon_config": daemon_config,
            "runtime_registration": _artifact(cas, artifacts, "runtime_registration"),
            "docker_executable": _artifact(cas, artifacts, "docker_executable"),
            "helper_implementations": _artifact(
                cas, artifacts, "helper_implementations"
            ),
            "runner_pre": _artifact(cas, artifacts, "runner_identity_pre"),
            "runner_post": _artifact(cas, artifacts, "runner_identity_post"),
            "image_inspect": _artifact(cas, artifacts, "image_inspect"),
        },
        implementation_files=implementation_files,
        runtime=canary_lock["runtime"],
        daemon_config_digest=daemon_config_digest,
        helper_modules=HELPER_MODULES,
        label="gVisor backend qualification",
    )


def _verify_execution_evidence(
    cas: CAS,
    artifacts: dict[str, str],
    *,
    runtime_lock: dict[str, Any],
    canary_lock: dict[str, Any],
    observed_binaries: dict[str, dict[str, Any]],
    run_id: str,
    container_id: str,
) -> None:
    pre = _inspect(
        _artifact(cas, artifacts, "container_pre_inspect"),
        "backend qualification prestart container",
    )
    live = _inspect(
        _artifact(cas, artifacts, "container_live_inspect"),
        "backend qualification live container",
    )
    post = _inspect(
        _artifact(cas, artifacts, "container_post_inspect"),
        "backend qualification postrun container",
    )
    snapshot = _canonical_object(
        _artifact(cas, artifacts, "host_sentinel_pre"),
        "backend qualification host sentinel pre",
    )
    profile = _qualification_profile(canary_lock, run_id, snapshot.get("process_id"))
    bind_mount = _qualification_bind_mount(pre, run_id)
    for phase, container in (
        ("prestart", pre),
        ("live", live),
        ("postrun", post),
    ):
        if (
            _verify_container_profile(
                image=runtime_lock["image"],
                profile=profile,
                runtime=canary_lock["runtime"],
                container=container,
                phase=phase,
                labels={_RUN_LABEL: run_id},
                tmpfs={profile["tmpfs"]["destination"]: profile["tmpfs"]["options"]},
                bind_mount=bind_mount,
            )
            != container_id
        ):
            raise GVisorBackendQualificationError(
                "backend qualification container identity changed"
            )
    for field in ("Created", "Image", "Path", "Args"):
        if pre.get(field) != live.get(field) or pre.get(field) != post.get(field):
            raise GVisorBackendQualificationError(
                f"backend qualification container {field} changed"
            )
    runsc = observed_binaries.get(canary_lock["runtime"]["path"])
    if runsc is None:
        raise GVisorBackendQualificationError(
            "backend qualification installed runsc evidence is absent"
        )
    _verify_processes(
        runtime_lock,
        _artifact(cas, artifacts, "container_processes"),
        runtime=canary_lock["runtime"],
        container_id=container_id,
        sandbox_pid=live["State"]["Pid"],
        installed_runsc=runsc,
    )
    cleanup = _canonical_object(
        _artifact(cas, artifacts, "container_cleanup"),
        "backend qualification container cleanup",
    )
    if cleanup != {
        "schema": CANARY_CLEANUP_SCHEMA,
        "container_id": container_id,
        "absent": True,
    }:
        raise GVisorBackendQualificationError(
            "backend qualification container cleanup observation changed"
        )


def _qualification_profile(
    canary_lock: dict[str, Any], run_id: str, host_pid: object
) -> dict[str, Any]:
    if (
        not isinstance(run_id, str)
        or _RUN_ID.fullmatch(run_id) is None
        or isinstance(host_pid, bool)
        or not isinstance(host_pid, int)
        or host_pid <= 0
    ):
        raise GVisorBackendQualificationError(
            "backend qualification run identity is invalid"
        )
    canary_profile = canary_lock["canary"]
    return {
        "command": ["/bin/sh", f"{_MOUNT_DESTINATION}/probe-v1.sh"],
        "environment": [
            "PATH=/bin",
            f"ARAGORN_RUN_ID={run_id}",
            f"ARAGORN_HOST_PID={host_pid}",
        ],
        **{field: canary_profile[field] for field in _PROFILE_FIELDS},
    }


def _qualification_bind_mount(prestart: dict[str, Any], run_id: str) -> dict[str, str]:
    host = _object(prestart.get("HostConfig"), "backend qualification host config")
    mounts = host.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise GVisorBackendQualificationError(
            "backend qualification bind mount is absent"
        )
    mount = _object(mounts[0], "backend qualification bind mount")
    source = mount.get("Source")
    prefix = f"/run/aragorn-gvisor-qualification-{run_id}-"
    if (
        not isinstance(source, str)
        or not source.startswith(prefix)
        or not source.removeprefix(prefix)
        or "/" in source.removeprefix(prefix)
        or len(source) > len(prefix) + 64
    ):
        raise GVisorBackendQualificationError(
            "backend qualification bind source is invalid"
        )
    return {"source": source, "destination": _MOUNT_DESTINATION}


def _artifact(cas: CAS, artifacts: dict[str, str], field: str) -> bytes:
    return cas.read(artifacts[field], max_bytes=_MAX_EVIDENCE_BLOB_BYTES)


def _verify_run_request(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    implementation_digest: str,
    probe_digest: str,
    run_id: str,
) -> None:
    request = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification run request",
    )
    expected = {
        "schema": RUN_REQUEST_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "implementation_digest": implementation_digest,
        "probe_digest": probe_digest,
        "run_id": run_id,
    }
    if _canonical_bytes(request) != _canonical_bytes(expected):
        raise GVisorBackendQualificationError(
            "backend qualification run request is unbound"
        )


def _verify_control_evidence(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    runtime_lock_digest: str,
    probe_digest: str,
    run_id: str,
    container_id: str,
) -> dict[str, str]:
    evidence = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification control evidence",
    )
    _exact_fields(
        evidence,
        {
            "schema",
            "lock_digest",
            "runtime_lock_digest",
            "probe_digest",
            "run_id",
            "container_id",
            "controls",
            "artifacts",
        },
        "backend qualification control evidence",
    )
    if {
        "schema": evidence["schema"],
        "lock_digest": evidence["lock_digest"],
        "runtime_lock_digest": evidence["runtime_lock_digest"],
        "probe_digest": evidence["probe_digest"],
        "run_id": evidence["run_id"],
        "container_id": evidence["container_id"],
    } != {
        "schema": CONTROL_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "run_id": run_id,
        "container_id": container_id,
    }:
        raise GVisorBackendQualificationError(
            "backend qualification control evidence is unbound"
        )
    controls = evidence["controls"]
    if not isinstance(controls, list) or len(controls) != len(_CONTROL_EXPECTATIONS):
        raise GVisorBackendQualificationError(
            "backend qualification control evidence is incomplete"
        )
    artifacts = _object(evidence["artifacts"], "backend qualification artifacts")
    _exact_fields(artifacts, _ARTIFACT_FIELDS, "backend qualification artifacts")
    artifact_digests = {
        field: _digest(value, f"backend qualification artifacts.{field}")
        for field, value in artifacts.items()
    }
    try:
        derived_controls = derive_gvisor_backend_controls(
            cas.read(
                artifact_digests["probe_stdout"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["probe_stderr"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["host_sentinel_pre"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            cas.read(
                artifact_digests["host_sentinel_post"],
                max_bytes=_MAX_EVIDENCE_BLOB_BYTES,
            ),
            expected_run_id=run_id,
        )
    except GVisorBackendProbeError as exc:
        raise GVisorBackendQualificationError(str(exc)) from exc
    for index, ((control_id, expected), raw_control, derived) in enumerate(
        zip(_CONTROL_EXPECTATIONS, controls, derived_controls, strict=True)
    ):
        control = _object(raw_control, f"backend qualification controls[{index}]")
        _exact_fields(
            control,
            {"control_id", "observed"},
            f"backend qualification controls[{index}]",
        )
        if (
            derived["control_id"] != control_id
            or _canonical_bytes(derived["observed"]) != _canonical_bytes(expected)
            or control["control_id"] != control_id
            or _canonical_bytes(control["observed"])
            != _canonical_bytes(derived["observed"])
        ):
            raise GVisorBackendQualificationError(
                f"backend qualification control failed: {control_id}"
            )
    return artifact_digests


def _verify_cleanup_evidence(
    cas: CAS,
    digest: str,
    *,
    lock_digest: str,
    run_id: str,
    container_id: str,
) -> None:
    cleanup = _canonical_object(
        cas.read(digest, max_bytes=_MAX_EVIDENCE_DOCUMENT_BYTES),
        "backend qualification cleanup evidence",
    )
    expected = {
        "schema": CLEANUP_EVIDENCE_SCHEMA,
        "lock_digest": lock_digest,
        "run_id": run_id,
        "container_id": container_id,
        "container_absent": True,
        "trace_files_absent": True,
        "host_sentinels_unchanged": True,
        "sinks_closed": True,
    }
    if _canonical_bytes(cleanup) != _canonical_bytes(expected):
        raise GVisorBackendQualificationError(
            "backend qualification cleanup did not complete"
        )


def _qualification_lock(raw: bytes) -> dict[str, Any]:
    lock = _canonical_object(raw.removesuffix(b"\n"), "backend qualification lock")
    _exact_fields(lock, _LOCK_FIELDS, "backend qualification lock")
    if (
        lock["schema"] != LOCK_SCHEMA
        or lock["authority"] != LOCK_AUTHORITY
        or lock["profile"] != PROFILE
        or lock["runs"] != _RUNS
        or lock["controls"] != _CONTROL_IDS
    ):
        raise GVisorBackendQualificationError(
            "backend qualification lock profile is unsupported"
        )
    lock["runtime_lock_digest"] = _digest(
        lock["runtime_lock_digest"], "backend qualification runtime lock"
    )
    lock["canary_lock_digest"] = _digest(
        lock["canary_lock_digest"], "backend qualification canary lock"
    )
    lock["daemon_config_digest"] = _digest(
        lock["daemon_config_digest"],
        "backend qualification daemon configuration",
    )
    lock["probe_digest"] = _digest(lock["probe_digest"], "backend qualification probe")
    return lock


def _canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GVisorBackendQualificationError(
            f"{label} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict) or _canonical_bytes(document) != raw:
        raise GVisorBackendQualificationError(f"{label} is not canonical JSON")
    return document


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value)
    except WorkerProtocolError as exc:
        raise GVisorBackendQualificationError(str(exc)) from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GVisorBackendQualificationError(f"{label} must be an object")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GVisorBackendQualificationError(f"{label} has missing or unknown fields")


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GVisorBackendQualificationError(f"{label} is not canonical hex")
    return value
