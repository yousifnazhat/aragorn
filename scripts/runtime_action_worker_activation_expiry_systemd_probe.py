#!/usr/bin/env python3
"""Produce one bounded P3.7c activation, expiry, and rotation observation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_openclaw_systemd_probe as p37b

from aragorn import runtime_action_broker as broker_v1
from aragorn import runtime_action_broker_v4 as broker_v4
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    parse_runtime_capability_grant,
)

lineage = p37b.lineage
capability = p37b.capability
openclaw = p37b.openclaw

_HARNESS = Path("/run/aragorn-harness.json")
_ACTIVATOR = Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh")
_DRIVER = p37b._DRIVER
_DRIVER_ROOT = p37b._DRIVER_ROOT
_GATEWAY_UNIT = p37b._GATEWAY_UNIT
_WORKER_UNIT = p37b._WORKER_UNIT
_SENSOR_UNIT = p37b._SENSOR_UNIT
_BROKER_UNIT = p37b._BROKER_UNIT
_UNITS = (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT)
_WORKER_SOCKET = p37b._WORKER_SOCKET
_SENSOR_SOCKET = p37b._SENSOR_SOCKET
_BROKER_SOCKET = p37b._BROKER_SOCKET
_SOCKETS = (_WORKER_SOCKET, _SENSOR_SOCKET, _BROKER_SOCKET)
_GRANT_SOURCE = p37b._GRANT_SOURCE
_GRANT_STATE = lineage._GRANT_STATE
_TARGET_PATH = lineage._PROTECTED / p37b._TARGET
_MAX_COMMAND_BYTES = 128 * 1024
_MAX_SNAPSHOT_BYTES = 128 * 1024
_COMMAND_ENV = {
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "TZ": "UTC",
}
_SOURCE_SIGNATURE = (
    b'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
    b"SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk\n"
)
_PARENT_IMAGE = (
    "sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db"
)
_AUTHORITY = (
    "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "EXACT_OPENCLAW_2026_7_1_RUNTIME_VOLUME_AND_EVALUATOR_PROVIDER_ONLY",
    "ONE_AVAILABLE_TO_EXPIRED_TRANSITION_ONLY",
    "ONE_OPERATOR_UNMASK_AND_TERMINAL_ARCHIVE_ROTATION_ONLY",
    "ONE_FRESH_GRANT_AND_ONE_CREATE_ACTION_ONLY",
    "EXPIRY_USES_LOCAL_WALL_CLOCK_WITHOUT_EXTERNAL_TIME_ATTESTATION",
    "NO_CLOCK_STEP_SLEW_ROLLBACK_OR_EXPIRY_LATENCY_QUALIFICATION",
    "NO_REBOOT_SYSTEMD_REEXEC_BOOT_ACTIVATION_OR_CREDENTIAL_REPROJECTION",
    "NO_SIGKILL_POWER_LOSS_OR_FILESYSTEM_DURABILITY_FAULT_INJECTION",
    "NO_AUTOMATIC_CONTINUOUS_REPEATED_OR_OVERLAPPING_GRANT_RENEWAL",
    "NO_CONCURRENT_ACTIVATION_LOCK_CONTENTION_OR_PARTIAL_SYSTEMCTL_FAILURE",
    "NO_CLAIMED_CONNECTION_ACROSS_EXPIRY_QUALIFICATION",
    "NO_NATIVE_HOST_VM_HOSTILE_ROOT_OR_SAME_UID_DIRECTORY_ATTESTATION",
    "SOURCE_COMMIT_SIGNATURE_TRUSTS_LOCAL_GIT_CONFIGURATION_AND_KEYRING",
    "CONTAINER_BUILD_AND_CAPTURE_TOOLCHAIN_NOT_INDEPENDENTLY_ATTESTED",
    "PYTHON_NODE_SYSTEMD_KERNEL_AND_NATIVE_DEPENDENCY_CLOSURE_NOT_FULLY_PINNED",
    "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
    "P3_7B_PARENT_REMAINS_SEPARATE_IMMUTABLE_QUALIFICATION",
    "SYSCALL_CAUSATION_IS_PINNED_IMPLEMENTATION_BOUND_NOT_INDEPENDENT_ATTESTATION",
    "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
    "VERIFIER_NOT_IMPLEMENTED",
    "RETAINED_EVIDENCE_NOT_PRODUCED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_PARENT = {
    "observation": {
        "path": (
            "benchmark/evidence/runtime-action-worker-openclaw-systemd-"
            "composition-p3-7b-2026-08-09.json"
        ),
        "bytes": 124214,
        "raw_digest": (
            "sha256:a4a9bbf375537713e72b9b8dda848202eedbf6ea3fd3a5bf8d3001297b5f82e6"
        ),
        "canonical_digest": (
            "sha256:4b668b1eae1875c6e129afd8fd0a56c4dc2e912179644bba22cc3e5a285b969e"
        ),
    },
    "receipt": {
        "path": (
            "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-"
            "qualification-v1-2026-08-09.json"
        ),
        "bytes": 5147,
        "raw_digest": (
            "sha256:154edc574bf00bd590c77de67b32764c5ecaf8a5582092487c6aa01bd23e4eb3"
        ),
        "canonical_digest": (
            "sha256:a920f71e196db07b4c8aa6838e23473bd8dc5d245368c5e6285484a4d4e8fd02"
        ),
    },
    "verifier_digest": (
        "sha256:68b240d19ca5625d027f5ed21520bc8a10a02a16b6c0c96908c1741b6b943812"
    ),
    "schema_digest": (
        "sha256:753e18cb7fd0df2eae5cb12a1b29e6e9be798162ed108114f681077d7fd2968a"
    ),
    "decision_status": "P3_7B_BOUNDED_PASS",
}
_INSTALLED = {
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "__init__.py",
            "oci_worker_protocol.py",
            "runtime_action_broker.py",
            "runtime_action_broker_v2.py",
            "runtime_action_broker_v3.py",
            "runtime_action_broker_v4.py",
            "runtime_action_broker_v5.py",
            "runtime_action_decision.py",
            "runtime_action_observation_publisher.py",
            "runtime_action_observation_publisher_v2.py",
            "runtime_action_observation_publisher_v3.py",
            "runtime_action_observation_publisher_v4.py",
            "runtime_action_service.py",
            "runtime_action_service_v2.py",
            "runtime_action_service_v4.py",
            "runtime_action_service_v5.py",
            "runtime_action_worker.py",
            "runtime_active_skill_lineage.py",
            "runtime_capability_grant.py",
            "runtime_lineage_capability_issuer.py",
            "runtime_observation_service.py",
            "runtime_observation_service_v2.py",
            "runtime_observation_service_v3.py",
            "runtime_observation_service_v4.py",
            "runtime_process_profile.py",
            "runtime_revocation_service.py",
        )
    },
    "/src/packaging/activate-runtime-capability-host.sh": (
        "/usr/libexec/aragorn/activate-runtime-capability-host.sh"
    ),
    "/src/packaging/activate-runtime-action-worker-host.sh": (
        "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"
    ),
    **{
        f"/src/packaging/libexec/{name}": f"/usr/libexec/aragorn/{name}"
        for name in (
            "aragorn-runtime-action-service-v5.py",
            "aragorn-runtime-action-worker-service.py",
            "aragorn-runtime-observation-service-v4.py",
            "aragorn-runtime-revocation-service.py",
        )
    },
    **{
        f"/src/packaging/systemd/{name}": f"/usr/lib/systemd/system/{name}"
        for name in (
            "aragorn-agent-gateway.service",
            "aragorn-runtime-action-worker.service",
            "aragorn-runtime-lineage-capability-action-broker.service",
            "aragorn-runtime-lineage-capability-observation-publisher.service",
            "aragorn-runtime-revocation-publisher.service",
        )
    },
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-worker.sysusers": (
        "/usr/lib/sysusers.d/aragorn-runtime-action-worker.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
}
_OBSOLETE_SHIMS = tuple(
    Path("/usr/libexec/aragorn") / name
    for name in (
        "aragorn-runtime-action-service.py",
        "aragorn-runtime-action-service-v2.py",
        "aragorn-runtime-action-service-v3.py",
        "aragorn-runtime-action-service-v4.py",
        "aragorn-runtime-observation-service.py",
        "aragorn-runtime-observation-service-v2.py",
        "aragorn-runtime-observation-service-v3.py",
    )
)
_STAGE = "BOOTSTRAP"

_expect = p37b._expect
_file = p37b._file
_document = p37b._document
_metadata = p37b._metadata
_process = p37b._process
_unit = p37b._unit
_user = p37b._user
_group = p37b._group
_systemctl = p37b._systemctl


def _set_stage(stage: str) -> None:
    global _STAGE
    _STAGE = stage


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _raw_record(raw: bytes) -> dict[str, Any]:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": _digest(raw),
    }


def _raw_bytes(record: dict[str, Any]) -> bytes:
    raw = base64.b64decode(record["base64"], validate=True)
    _expect(
        len(raw) == record["bytes"] and _digest(raw) == record["digest"],
        "retained raw byte record changed",
    )
    return raw


def _stat_record(value: os.stat_result) -> dict[str, Any]:
    kind = (
        "file"
        if stat.S_ISREG(value.st_mode)
        else "directory"
        if stat.S_ISDIR(value.st_mode)
        else "socket"
        if stat.S_ISSOCK(value.st_mode)
        else "other"
    )
    return {
        "type": kind,
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_file_snapshot(path: Path) -> tuple[dict[str, Any], bytes]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        _expect(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= _MAX_SNAPSHOT_BYTES,
            f"snapshot file metadata is unsafe: {path}",
        )
        retained = bytearray()
        while chunk := os.read(
            descriptor,
            min(8192, _MAX_SNAPSHOT_BYTES + 1 - len(retained)),
        ):
            retained.extend(chunk)
            _expect(
                len(retained) <= _MAX_SNAPSHOT_BYTES,
                f"snapshot file exceeds its byte limit: {path}",
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    path_state = os.stat(path, follow_symlinks=False)
    _expect(
        _stat_identity(before) == _stat_identity(after) == _stat_identity(path_state)
        and len(retained) == after.st_size,
        f"snapshot file changed while read: {path}",
    )
    raw = bytes(retained)
    return {
        "path": str(path),
        **_raw_record(raw),
        "stat": _stat_record(after),
    }, raw


def _reject_json_number(value: str) -> Any:
    raise ValueError(value)


def _stable_document_snapshot(
    path: Path,
    *,
    grant_state: bool = False,
) -> dict[str, Any]:
    file_record, raw = _stable_file_snapshot(path)
    try:
        document = json.loads(
            raw,
            parse_constant=_reject_json_number,
            parse_float=_reject_json_number,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise openclaw.ProbeError(f"snapshot document is invalid: {path}") from exc
    _expect(
        canonical_json(document) == raw,
        f"snapshot document is not canonical: {path}",
    )
    if grant_state:
        _expect(
            isinstance(document, dict)
            and isinstance(document.get("grant_digest"), str),
            f"grant state identity is invalid: {path}",
        )
        document = broker_v4._state(document, document["grant_digest"])
    digest = canonical_digest(document)
    _expect(digest == file_record["digest"], f"document/file digest changed: {path}")
    return {"digest": digest, "document": document, "file": file_record}


def _stable_grant_snapshot(path: Path) -> dict[str, Any]:
    retained = _stable_document_snapshot(path)
    raw = _raw_bytes(retained["file"])
    _expect(
        parse_runtime_capability_grant(raw) == retained["document"],
        f"runtime grant snapshot changed: {path}",
    )
    return retained


def _stable_state_snapshot(
    path: Path,
    expected_grant_digest: str | None = None,
) -> dict[str, Any]:
    retained = _stable_document_snapshot(path, grant_state=True)
    if expected_grant_digest is not None:
        _expect(
            retained["document"]["grant_digest"] == expected_grant_digest,
            f"grant state digest changed: {path}",
        )
    return retained


def _command(argv: list[str], *, timeout: int = 90) -> dict[str, Any]:
    started_at = _iso_now()
    started_ns = time.monotonic_ns()
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        timeout=timeout,
        env=_COMMAND_ENV,
    )
    completed_ns = time.monotonic_ns()
    completed_at = _iso_now()
    _expect(
        len(result.stdout) <= _MAX_COMMAND_BYTES
        and len(result.stderr) <= _MAX_COMMAND_BYTES,
        f"bounded command output exceeded: {argv}",
    )
    return {
        "argv": argv,
        "caller": {"uid": os.getuid(), "gid": os.getgid()},
        "started_at": started_at,
        "completed_at": completed_at,
        "started_monotonic_ns": started_ns,
        "completed_monotonic_ns": completed_ns,
        "elapsed_ns": completed_ns - started_ns,
        "exit_code": result.returncode if result.returncode >= 0 else None,
        "signal": -result.returncode if result.returncode < 0 else None,
        "stdout": _raw_record(result.stdout),
        "stderr": _raw_record(result.stderr),
    }


def _sample_units(names: tuple[str, ...]) -> dict[str, dict[str, str]]:
    properties = (
        "Id",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "MainPID",
        "InvocationID",
        "UnitFileState",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
    )
    result = subprocess.run(
        [
            "systemctl",
            "show",
            *names,
            *[f"-p{property_name}" for property_name in properties],
        ],
        check=False,
        capture_output=True,
        timeout=3,
        env=_COMMAND_ENV,
    )
    _expect(result.returncode == 0 and not result.stderr, "unit monitor failed")
    units = {}
    for block in result.stdout.decode("utf-8").strip().split("\n\n"):
        values = dict(line.split("=", 1) for line in block.splitlines())
        _expect(set(values) == set(properties), "unit monitor shape changed")
        units[values["Id"]] = values
    _expect(set(units) == set(names), "unit monitor inventory changed")
    return units


def _monitored_command(
    argv: list[str],
    names: tuple[str, ...],
    *,
    timeout: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    started_at = _iso_now()
    started_ns = time.monotonic_ns()
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_COMMAND_ENV,
    )
    deadline = time.monotonic() + timeout
    samples = []
    last = None
    stdout = None
    stderr = None
    completed_at = None
    completed_ns = None
    while True:
        units = _sample_units(names)
        if units != last:
            samples.append(
                {"observed_monotonic_ns": time.monotonic_ns(), "units": units}
            )
            _expect(len(samples) <= 64, "unit monitor transition bound exceeded")
            last = units
        if completed_ns is None and process.poll() is not None:
            stdout, stderr = process.communicate()
            completed_ns = time.monotonic_ns()
            completed_at = _iso_now()
        if completed_ns is not None and all(
            unit["ActiveState"] == "inactive" and unit["MainPID"] == "0"
            for unit in units.values()
        ):
            break
        if time.monotonic() >= deadline:
            if completed_ns is None:
                process.kill()
                process.communicate()
            raise openclaw.ProbeError(f"bounded command timed out: {argv}")
        time.sleep(0.005)
    monitor_completed_ns = time.monotonic_ns()
    monitor_completed_at = _iso_now()
    _expect(
        stdout is not None
        and stderr is not None
        and completed_at is not None
        and completed_ns is not None,
        "bounded command completion was not retained",
    )
    _expect(
        len(stdout) <= _MAX_COMMAND_BYTES and len(stderr) <= _MAX_COMMAND_BYTES,
        f"bounded command output exceeded: {argv}",
    )
    command = {
        "argv": argv,
        "caller": {"uid": os.getuid(), "gid": os.getgid()},
        "started_at": started_at,
        "completed_at": completed_at,
        "started_monotonic_ns": started_ns,
        "completed_monotonic_ns": completed_ns,
        "monitor_completed_at": monitor_completed_at,
        "monitor_completed_monotonic_ns": monitor_completed_ns,
        "elapsed_ns": completed_ns - started_ns,
        "exit_code": process.returncode if process.returncode >= 0 else None,
        "signal": -process.returncode if process.returncode < 0 else None,
        "stdout": _raw_record(stdout),
        "stderr": _raw_record(stderr),
    }
    return command, samples


def _clock() -> dict[str, Any]:
    boottime = getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii")
    uptime = Path("/proc/uptime").read_bytes()
    clocksource = Path(
        "/sys/devices/system/clocksource/clocksource0/current_clocksource"
    ).read_bytes()
    timedatectl = _command(
        [
            "timedatectl",
            "show",
            "--property=NTPSynchronized",
            "--property=Timezone",
        ]
    )
    return {
        "recorded_at": _iso_now(),
        "realtime_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "boottime_ns": time.clock_gettime_ns(boottime),
        "boot_id": boot_id.strip(),
        "proc_uptime": _raw_record(uptime),
        "clocksource": _raw_record(clocksource),
        "timedatectl": timedatectl,
    }


def _harness() -> dict[str, Any]:
    retained = _stable_document_snapshot(_HARNESS)
    value = retained["document"]
    _expect(
        set(value)
        == {
            "schema",
            "capture_disposition",
            "source_commit",
            "source_commit_verification",
            "container_id",
            "image_id",
            "image_reference",
            "run_image_reference",
            "parent_image_id",
            "image_lineage",
            "platform",
            "profile_label",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "openclaw_runtime_mount",
            "host_config",
        },
        "outer P3.7c harness shape changed",
    )
    source_commit = value.get("source_commit", "")
    verification = value.get("source_commit_verification")
    _expect(
        isinstance(verification, dict)
        and set(verification)
        == {"command", "exit_code", "commit_object", "stdout", "stderr"},
        "outer P3.7c source verification changed",
    )
    commit_raw = _raw_bytes(verification["commit_object"])
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    verification_stdout = _raw_bytes(verification["stdout"])
    verification_stderr = _raw_bytes(verification["stderr"])
    lineage_record = value["image_lineage"]
    parent = lineage_record.get("parent", {})
    child = lineage_record.get("child", {})
    added_layers = lineage_record.get("added_layers")
    parent_layers = parent.get("layers")
    child_layers = child.get("layers")
    expected_host = {
        "binds": sorted(
            [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
            ]
        ),
        "cgroupns_mode": "host",
        "ipc_mode": "private",
        "network_mode": "none",
        "privileged": True,
        "readonly_rootfs": False,
        "runtime": "runc",
        "security_opt": ["label=disable"],
        "tmpfs": {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        },
        "userns_mode": "",
    }
    _expect(
        value.get("schema")
        == "aragorn/runtime-action-worker-activation-expiry-systemd-harness/v1"
        and value.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and value.get("parent_image_id") == _PARENT_IMAGE
        and value.get("profile_label") == "p3.7c"
        and value.get("platform") == "linux"
        and re.fullmatch(r"[0-9a-f]{64}", value.get("container_id", "")) is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("image_id", "")) is not None
        and value.get("image_reference")
        == "aragorn-p37c-runtime-action-worker-activation-expiry-systemd"
        and value.get("run_image_reference") == value.get("image_id")
        and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None
        and verification["command"] == ["git", "verify-commit", "--raw", source_commit]
        and verification["exit_code"] == 0
        and commit_identity == source_commit
        and commit_raw.startswith(b"tree ")
        and b"\ngpgsig " in commit_raw
        and verification_stdout == b""
        and verification_stderr == _SOURCE_SIGNATURE
        and set(lineage_record) == {"parent", "child", "added_layers"}
        and set(parent) == {"id", "rootfs_type", "layers"}
        and set(child) == {"id", "rootfs_type", "layers"}
        and parent.get("id") == _PARENT_IMAGE
        and child.get("id") == value.get("image_id")
        and parent.get("rootfs_type") == child.get("rootfs_type") == "layers"
        and isinstance(parent_layers, list)
        and isinstance(child_layers, list)
        and isinstance(added_layers, list)
        and child_layers[: len(parent_layers)] == parent_layers
        and added_layers == child_layers[len(parent_layers) :]
        and len(added_layers) == 5
        and all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", layer) is not None
            for layer in child_layers
        )
        and value.get("openclaw_runtime_volume") == "aragorn-openclaw-2026-7-1-runtime"
        and value.get("openclaw_runtime_volume_identity")
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        }
        and value.get("openclaw_runtime_mount")
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        }
        and value.get("host_config") == expected_host,
        "outer P3.7c harness identity changed",
    )
    return retained


def _artifacts() -> dict[str, Any]:
    installed = []
    for source_path, installed_path in sorted(_INSTALLED.items()):
        source = _file(Path(source_path))
        target = _file(Path(installed_path))
        expected_mode = "0755" if "/usr/libexec/" in installed_path else "0644"
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"])
            and target["stat"]["type"] == "file"
            and target["stat"]["uid"] == 0
            and target["stat"]["gid"] == 0
            and target["stat"]["mode"] == expected_mode
            and target["stat"]["nlink"] == 1,
            f"P3.7c source/install mismatch: {installed_path}",
        )
        installed.append({"source": source, "installed": target})
    plugin_files, plugin_digest = p37b._plugin_artifacts()
    obsolete_shims = [str(path) for path in _OBSOLETE_SHIMS]
    _expect(
        all(not os.path.lexists(path) for path in _OBSOLETE_SHIMS),
        "obsolete runtime service shim remained installed",
    )
    installed_closure_digest = canonical_digest(
        [
            {
                "bytes": item["installed"]["bytes"],
                "digest": item["installed"]["digest"],
                "mode": item["installed"]["stat"]["mode"],
                "path": item["installed"]["path"],
            }
            for item in [*installed, *plugin_files]
        ]
    )
    return {
        "installed": installed,
        "installed_closure_digest": installed_closure_digest,
        "obsolete_shims_absent": obsolete_shims,
        "worker_installer": _file(
            Path("/src/packaging/install-runtime-action-worker-host.sh")
        ),
        "plugin": {"digest": plugin_digest, "files": plugin_files},
        "collector": {
            "base_installer": _file(
                Path("/src/packaging/install-runtime-capability-host.sh")
            ),
            "capture_recipe": _file(
                Path(
                    "/src/scripts/"
                    "capture_runtime_action_worker_activation_expiry_systemd.sh"
                )
            ),
            "dockerfile": _file(
                Path(
                    "/src/benchmark/runtime-action-worker-activation-expiry-"
                    "systemd/Dockerfile"
                )
            ),
            "driver": _file(_DRIVER),
            "parent_probe": _file(
                Path("/src/scripts/runtime_action_worker_openclaw_systemd_probe.py")
            ),
            "probe": _file(Path(__file__).resolve()),
        },
    }


def _gateway_configuration(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
) -> dict[str, Any]:
    config = p37b._gateway_configuration(
        gateway_uid, gateway_gid, worker_uid, skill_name
    )
    provider = config["models"]["providers"]["aragorn-runtime-action-mock"]
    provider["apiKey"] = "${OPENCLAW_GATEWAY_TOKEN}"
    config["tools"] = {
        "profile": "minimal",
        "alsoAllow": ["aragorn_runtime_create"],
        "deny": ["session_status"],
    }
    return config


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path, str]:
    p37b._mkdir(p37b._GATEWAY_CONFIG.parent, 0, 0, 0o700)
    for path in (
        p37b._GATEWAY_ROOT,
        p37b._GATEWAY_HOME,
        p37b._GATEWAY_STATE,
        p37b._GATEWAY_WORKSPACE,
    ):
        p37b._mkdir(path, gateway_uid, gateway_gid, 0o700)
    skill_root = p37b._GATEWAY_STATE / "skills"
    projected_root = skill_root / skill_name
    p37b._mkdir(skill_root, 0, 0, 0o555)
    p37b._mkdir(projected_root, 0, 0, 0o555)
    projected_skill = projected_root / "SKILL.md"
    projected_skill.write_bytes(skill_raw)
    os.chown(projected_skill, 0, 0)
    os.chmod(projected_skill, 0o444)
    config = _gateway_configuration(gateway_uid, gateway_gid, worker_uid, skill_name)
    p37b._write_document(p37b._GATEWAY_CONFIG, config)
    token = secrets.token_hex(32)
    p37b._GATEWAY_ENVIRONMENT.write_text(
        f"OPENCLAW_GATEWAY_TOKEN={token}\n", encoding="ascii"
    )
    os.chown(p37b._GATEWAY_ENVIRONMENT, 0, 0)
    os.chmod(p37b._GATEWAY_ENVIRONMENT, 0o400)
    return (
        config,
        {
            "OPENCLAW_GATEWAY_TOKEN": token,
            "ARAGORN_MOCK_PROVIDER_TOKEN": token,
        },
        projected_skill,
        token,
    )


def _grant(
    *,
    profile_digest: str,
    policy: dict[str, Any],
    action: dict[str, str],
    producer: dict[str, Any],
    skill_digest: str,
    issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": secrets.token_hex(32),
        "source_manifest_digest": producer["transaction"]["manifest_digest"],
        "install_context_digest": producer["transaction"]["context_digest"],
        "runtime_profile_digest": profile_digest,
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "active_skill_digest": skill_digest,
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "policy_digest": canonical_digest(policy),
        "policy_version": policy["version"],
        "operation_digest": action["operation_digest"],
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "max_actions": 1,
    }
    _expect(
        parse_runtime_capability_grant(
            canonical_json(grant), max(issued_at, expires_at - 1)
        )
        == grant,
        "runtime grant validation changed",
    )
    return grant


def _replace_document(path: Path, document: dict[str, Any]) -> dict[str, Any]:
    raw = canonical_json(document)
    temporary = path.with_name(f".{path.name}.p37c-{secrets.token_hex(8)}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    started = _clock()
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, "grant replacement write made no progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o400)
        os.fchown(descriptor, 0, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    snapshot = _stable_grant_snapshot(path)
    _expect(snapshot["document"] == document, "grant replacement changed")
    return {
        "started": started,
        "completed": _clock(),
        "grant": snapshot,
        "file": snapshot["file"],
    }


def _wait_state(
    status: str,
    expected_grant_digest: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            retained = _stable_state_snapshot(_GRANT_STATE)
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if (
            retained["document"]["status"] == status
            and retained["document"]["grant_digest"] == expected_grant_digest
        ):
            return retained
        time.sleep(0.05)
    raise openclaw.ProbeError(f"grant state did not become {status}")


def _socket_record(path: Path) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"path": str(path), "present": False, "metadata": None, "unix": []}
    metadata = _metadata(path)
    lines = [
        line
        for line in Path("/proc/net/unix").read_text(encoding="ascii").splitlines()
        if line.split() and line.split()[-1] == str(path)
    ]
    return {
        "path": str(path),
        "present": True,
        "metadata": metadata,
        "unix": lines,
    }


def _service_snapshot() -> dict[str, Any]:
    properties = (
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "MainPID",
        "InvocationID",
        "UnitFileState",
        "ControlGroup",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
        "ActiveEnterTimestampMonotonic",
        "InactiveEnterTimestampMonotonic",
    )
    units = {}
    for name in _UNITS:
        command = _command(
            [
                "systemctl",
                "show",
                name,
                *[f"-p{property_name}" for property_name in properties],
            ]
        )
        _expect(command["exit_code"] == 0, f"systemd snapshot failed: {name}")
        raw = base64.b64decode(command["stdout"]["base64"]).decode("utf-8")
        values = dict(line.split("=", 1) for line in raw.splitlines())
        _expect(set(values) == set(properties), f"systemd snapshot changed: {name}")
        cgroup = values["ControlGroup"]
        cgroup_path = Path("/sys/fs/cgroup") / cgroup.removeprefix("/")
        members = (
            cgroup_path.joinpath("cgroup.procs").read_text(encoding="ascii")
            if cgroup and cgroup_path.joinpath("cgroup.procs").is_file()
            else ""
        )
        units[name] = {
            "command": command,
            "properties": values,
            "cgroup_members": members.split(),
        }
    return {
        "units": units,
        "sockets": {str(path): _socket_record(path) for path in _SOCKETS},
    }


def _journal(
    name: str,
    invocation_id: str,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    arguments = ["journalctl", "--no-pager", "--output=short-monotonic"]
    if invocation_id:
        arguments.append(f"_SYSTEMD_INVOCATION_ID={invocation_id}")
    else:
        arguments.extend(
            ["--unit", name, "--since", started_at, "--until", completed_at]
        )
    return _command(arguments)


def _filtered_journals(
    route: dict[str, Any],
    started_at: str,
    completed_at: str,
    invocations: dict[str, str] | None = None,
) -> dict[str, Any]:
    retained = {}
    for name in invocations if invocations is not None else _UNITS:
        invocation_id = (invocations or {}).get(
            name,
            route["units"][name]["properties"]["InvocationID"],
        )
        retained[name] = _journal(name, invocation_id, started_at, completed_at)
        _expect(retained[name]["exit_code"] == 0, f"unit journal failed: {name}")
    return retained


def _successful_accepts(trace: dict[str, Any]) -> list[str]:
    return [
        line
        for line in trace["raw"].splitlines()
        if p37b.systemd_probe._ACCEPT_TRACE.fullmatch(line) is not None
    ]


def _non_grant_effects(snapshot: dict[str, Any]) -> dict[str, Any]:
    retained = {key: value for key, value in snapshot.items() if key != "grant_state"}
    retained["controls"] = {
        key: value
        for key, value in retained["controls"].items()
        if key != "capability-grant-state.json"
    }
    return retained


def _cleared_terminal_properties(properties: dict[str, str]) -> bool:
    return (
        properties["ActiveState"] == "inactive"
        and properties["SubState"] == "dead"
        and properties["Result"] == "success"
        and properties["MainPID"] == "0"
        and properties["ExecMainCode"] == "0"
        and properties["ExecMainStatus"] == "0"
        and properties["ExecMainStartTimestampMonotonic"] == "0"
        and properties["ExecMainExitTimestampMonotonic"] == "0"
        and properties["InvocationID"] == ""
    )


def _clean_terminal_unit(unit: dict[str, Any]) -> bool:
    properties = unit["properties"]
    exited_success = (
        properties["ExecMainCode"] == "1" and properties["ExecMainStatus"] == "0"
    )
    return (
        properties["ActiveState"] == "inactive"
        and properties["SubState"] == "dead"
        and properties["Result"] == "success"
        and (exited_success or _cleared_terminal_properties(properties))
        and properties["MainPID"] == "0"
        and unit["cgroup_members"] == []
    )


def _monitored_invocation(
    samples: list[dict[str, Any]],
    name: str,
    previous_invocation: str,
    command: dict[str, Any],
) -> dict[str, Any]:
    candidates = {}
    for sample in samples:
        properties = sample["units"][name]
        invocation_id = properties["InvocationID"]
        if invocation_id and invocation_id != previous_invocation:
            candidates.setdefault(invocation_id, []).append(sample)
    _expect(len(candidates) == 1, f"unit invocation was not observed: {name}")
    invocation_id, retained = next(iter(candidates.items()))
    starts = {
        int(sample["units"][name]["ExecMainStartTimestampMonotonic"])
        for sample in retained
        if sample["units"][name]["ExecMainStartTimestampMonotonic"] not in {"", "0"}
    }
    exits = {
        int(sample["units"][name]["ExecMainExitTimestampMonotonic"])
        for sample in retained
        if sample["units"][name]["ExecMainExitTimestampMonotonic"] not in {"", "0"}
    }
    start = next(iter(starts)) if len(starts) == 1 else None
    exit_timestamp = next(iter(exits)) if len(exits) == 1 else None
    terminal_sample = retained[-1]
    same_invocation_exit = (
        start is not None
        and exit_timestamp is not None
        and start <= exit_timestamp
        and exit_timestamp * 1000 <= terminal_sample["observed_monotonic_ns"]
        and any(
            sample["units"][name]["ExecMainCode"] == "1"
            and sample["units"][name]["ExecMainStatus"] == "0"
            for sample in retained
        )
    )
    cleared_sample = next(
        (
            sample
            for sample in samples
            if sample["observed_monotonic_ns"]
            > terminal_sample["observed_monotonic_ns"]
            and _cleared_terminal_properties(sample["units"][name])
        ),
        None,
    )
    cleared_success = not exits and cleared_sample is not None
    terminal_observation = terminal_sample if same_invocation_exit else cleared_sample
    _expect(
        start is not None
        and command["started_monotonic_ns"]
        <= start * 1000
        <= command["completed_monotonic_ns"]
        and terminal_observation is not None
        and terminal_observation["observed_monotonic_ns"]
        <= command["monitor_completed_monotonic_ns"]
        and any(int(sample["units"][name]["MainPID"]) > 0 for sample in retained)
        and (same_invocation_exit or cleared_success),
        "unit invocation timing changed: "
        + repr(
            {
                "command_monotonic_ns": [
                    command["started_monotonic_ns"],
                    command["completed_monotonic_ns"],
                    command["monitor_completed_monotonic_ns"],
                ],
                "cleared_sample": cleared_sample,
                "cleared_success": cleared_success,
                "exits": sorted(exits),
                "name": name,
                "same_invocation_exit": same_invocation_exit,
                "samples": [
                    {
                        "observed_monotonic_ns": sample["observed_monotonic_ns"],
                        "properties": sample["units"][name],
                    }
                    for sample in retained
                ],
                "starts": sorted(starts),
            }
        ),
    )
    return {
        "invocation_id": invocation_id,
        "samples": retained,
        "terminal_observation": (
            "same_invocation_exit"
            if same_invocation_exit
            else "same_invocation_started_then_cleared"
        ),
    }


def _all_inactive(route: dict[str, Any]) -> bool:
    return all(
        unit["properties"]["ActiveState"] == "inactive"
        and unit["properties"]["MainPID"] == "0"
        and unit["cgroup_members"] == []
        for unit in route["units"].values()
    ) and all(not value["present"] for value in route["sockets"].values())


def _gateway_listener(pid: int) -> dict[str, Any]:
    raw = Path(f"/proc/{pid}/net/tcp").read_bytes()
    matches = []
    for line in raw.decode("ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10 and fields[1] == "0100007F:4965" and fields[3] == "0A":
            matches.append({"line": line, "inode": int(fields[9])})
    _expect(len(matches) == 1, "gateway loopback listener changed")
    inode = matches[0]["inode"]
    owners = []
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        if target == f"socket:[{inode}]":
            owners.append(str(descriptor))
    _expect(len(owners) == 1, "gateway listener owner changed")
    return {
        "pid": pid,
        "proc_net_tcp": _raw_record(raw),
        "listener": matches[0],
        "fd_owners": owners,
    }


def _active_stack() -> dict[str, Any]:
    units = {name: _unit(name) for name in _UNITS}
    _expect(
        all(value["ActiveState"] == "active" for value in units.values()),
        "activated route is not fully active",
    )
    pids = {name: int(value["MainPID"]) for name, value in units.items()}
    _expect(all(pid > 0 for pid in pids.values()), "activated service PID changed")
    service_state = _service_snapshot()
    return {
        "units": units,
        "pids": pids,
        "processes": {name: _process(pid) for name, pid in pids.items()},
        "sockets": {str(path): _socket_record(path) for path in _SOCKETS},
        "gateway_listener": _gateway_listener(pids[_GATEWAY_UNIT]),
        "service_state": service_state,
        "enablement": {
            name: service_state["units"][name]["properties"]["UnitFileState"]
            for name in _UNITS
        },
    }


def _coherent_case(
    *,
    stack: dict[str, Any],
    tokens: dict[str, str],
    grant_digest: str,
    worker_profile: Any,
    worker_cgroup: str,
    producer: dict[str, Any],
    identities: dict[str, dict[str, int]],
    policy: dict[str, Any],
    policy_digest: str,
    python_digest: str,
    skill_digest: str,
    action: dict[str, str],
) -> dict[str, Any]:
    case_started_at = _iso_now()
    before_state = _stable_state_snapshot(_GRANT_STATE, grant_digest)
    before = p37b._snapshot_effects()
    _expect(
        before["grant_state"]
        == {"digest": before_state["digest"], "document": before_state["document"]},
        "coherent pre-state snapshot changed",
    )
    driver, traces = p37b._trace_case(
        {
            "gateway": stack["pids"][_GATEWAY_UNIT],
            "worker": stack["pids"][_WORKER_UNIT],
            "sensor": stack["pids"][_SENSOR_UNIT],
            "broker": stack["pids"][_BROKER_UNIT],
        },
        "p37c-coherent",
        lambda: p37b._run_driver(
            "coherent",
            "COMPLETED",
            {"verdict": "ALLOW", "effect_status": "CREATED"},
            "aragorn/runtime-action-worker-result/v1",
            tokens,
        ),
    )
    outcome = p37b._assert_driver_outcome(
        driver,
        "COMPLETED",
        {"verdict": "ALLOW", "effect_status": "CREATED"},
    )
    after = p37b._snapshot_effects()
    state_record = _stable_state_snapshot(_GRANT_STATE, grant_digest)
    state = state_record["document"]
    _expect(
        after["grant_state"] == {"digest": state_record["digest"], "document": state},
        "coherent terminal-state snapshot changed",
    )
    receipt = _stable_document_snapshot(lineage._RECEIPT)
    receipt_document = receipt["document"]
    claim = state.get("claim") or {}
    lease = claim.get("lease") or {}
    result_record = state.get("result") or {}
    profile_result = result_record.get("profile_result") or {}
    broker_result = receipt_document.get("broker_result")
    _expect(isinstance(broker_result, dict), "coherent receipt lost broker result")
    broker_result_digest = canonical_digest(broker_result)
    broker_state_record = _stable_document_snapshot(lineage._CONTROL / "state.json")
    broker_state = broker_v1._state(broker_state_record["document"])
    _expect(
        broker_state == broker_state_record["document"],
        "coherent base broker state changed",
    )
    attribution = receipt_document.get("runtime_attribution") or {}
    correlation = (
        claim.get("profile_claim", {})
        .get("profile_pending", {})
        .get("measured_action", {})
    )
    target, _target_raw = _stable_file_snapshot(_TARGET_PATH)
    skill, _skill_raw = _stable_file_snapshot(Path(producer["paths"]["skill"]))
    gateway_pid = stack["pids"][_GATEWAY_UNIT]
    worker_pid = stack["pids"][_WORKER_UNIT]
    sensor_pid = stack["pids"][_SENSOR_UNIT]
    broker_pid = stack["pids"][_BROKER_UNIT]
    expected_peer_chain = {
        "gateway_to_worker": {
            "pid": gateway_pid,
            "uid": identities["gateway"]["uid"],
            "gid": identities["gateway"]["gid"],
        },
        "worker_to_sensor": {
            "pid": worker_pid,
            "uid": identities["worker"]["uid"],
            "gid": identities["worker"]["gid"],
        },
        "sensor_to_broker": {
            "pid": sensor_pid,
            "uid": identities["sensor"]["uid"],
            "gid": identities["sensor"]["gid"],
        },
    }
    gateway_channels = traces["gateway"]["channels"]
    worker_channels = traces["worker"]["channels"]
    sensor_channels = traces["sensor"]["channels"]
    broker_channels = traces["broker"]["channels"]
    driver_identifiers = driver["output"].get("turn", {}).get("identifiers", {})
    driver_checks = (
        driver["output"].get("scenario", {}).get("proof", {}).get("checks", {})
    )
    broker_summary = {
        "source_schema": broker_result.get("schema"),
        "source_authority": broker_result.get("authority"),
        "verdict": broker_result.get("verdict"),
        "effect_status": broker_result.get("effect_status"),
        "reason_codes": broker_result.get("reason_codes"),
        "target_name": broker_result.get("target_name"),
    }
    worker_process = stack["processes"][_WORKER_UNIT]
    worker_mount_stat = os.stat(f"/proc/{worker_pid}/ns/mnt")
    worker_mount_namespace = {
        "device": worker_mount_stat.st_dev,
        "inode": worker_mount_stat.st_ino,
    }
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        service_state_after = _service_snapshot()
        broker_after = service_state_after["units"][_BROKER_UNIT]
        if (
            broker_after["properties"]["ActiveState"] == "inactive"
            and broker_after["properties"]["MainPID"] == "0"
            and broker_after["cgroup_members"] == []
            and not service_state_after["sockets"][str(_BROKER_SOCKET)]["present"]
        ):
            break
        time.sleep(0.05)
    else:
        raise openclaw.ProbeError("consumed broker did not stop cleanly")
    case_completed_at = _iso_now()
    service_pids_after = {
        name: int(value["properties"]["MainPID"])
        for name, value in service_state_after["units"].items()
    }
    checks = {
        "driver_completed_allow_created": outcome["status"] == "COMPLETED"
        and outcome["broker_result"]["verdict"] == "ALLOW"
        and outcome["broker_result"]["effect_status"] == "CREATED",
        "exact_peer_chain": gateway_channels == []
        and worker_channels
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": expected_peer_chain["gateway_to_worker"],
            },
            {
                "kind": "connect",
                "path": str(_SENSOR_SOCKET),
                "peer": {
                    "pid": sensor_pid,
                    "uid": identities["sensor"]["uid"],
                    "gid": identities["sensor"]["gid"],
                },
            },
        ]
        and sensor_channels
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": expected_peer_chain["worker_to_sensor"],
            },
            {
                "kind": "connect",
                "path": str(_BROKER_SOCKET),
                "peer": {
                    "pid": broker_pid,
                    "uid": identities["broker"]["uid"],
                    "gid": identities["broker"]["gid"],
                },
            },
        ]
        and broker_channels
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": expected_peer_chain["sensor_to_broker"],
            }
        ],
        "one_connect_no_retry": p37b._connect_paths(traces["gateway"])
        == [str(_WORKER_SOCKET)]
        and p37b._connect_paths(traces["worker"]) == [str(_SENSOR_SOCKET)]
        and p37b._connect_paths(traces["sensor"]) == [str(_BROKER_SOCKET)]
        and traces["broker"]["successful_connects"] == []
        and len(_successful_accepts(traces["worker"])) == 1
        and len(_successful_accepts(traces["sensor"])) == 1
        and len(_successful_accepts(traces["broker"])) == 1,
        "grant_consumed_once": state.get("status") == "CONSUMED"
        and state.get("grant_digest") == grant_digest
        and claim.get("grant_digest") == grant_digest
        and claim.get("lease_digest") == canonical_digest(lease)
        and result_record.get("grant_digest") == grant_digest
        and result_record.get("lease_digest") == claim.get("lease_digest")
        and len(broker_state.get("consumed", [])) == 1
        and broker_state["consumed"][0].get("request_digest")
        == broker_result.get("request_digest")
        and broker_state["consumed"][0].get("observation_digest")
        == broker_result.get("observation_digest")
        and broker_state.get("effect_journal") is None,
        "lease_bound": lease.get("grant_digest") == grant_digest
        and lease.get("max_actions") == 1
        and lease.get("runtime_profile_digest") == worker_profile.digest
        and lease.get("runtime_digest") == openclaw._RUNTIME_DIGEST
        and lease.get("active_skill_digest") == skill_digest
        and lease.get("sensor_digest") == openclaw._SENSOR_DIGEST
        and lease.get("policy_digest") == policy_digest
        and lease.get("policy_version") == policy["version"]
        and lease.get("operation_digest") == action["operation_digest"]
        and lease.get("path_digest") == action["path_digest"]
        and lease.get("payload_digest") == action["payload_digest"]
        and claim.get("profile_claim", {}).get("submission_digest")
        == lease.get("submission_digest")
        and claim.get("profile_claim", {}).get("request_digest")
        == lease.get("request_digest"),
        "receipt_result_bound": receipt_document.get("submission_digest")
        == lease.get("submission_digest")
        and receipt_document.get("runtime_attribution_digest")
        == lease.get("runtime_attribution_digest")
        == canonical_digest(attribution)
        and receipt_document.get("broker_result_digest") == broker_result_digest
        and profile_result.get("lease_digest") == claim.get("lease_digest")
        and profile_result.get("submission_digest") == lease.get("submission_digest")
        and profile_result.get("profile_receipt_digest")
        == canonical_digest(receipt_document)
        and profile_result.get("broker_result_digest") == broker_result_digest
        and profile_result.get("verdict") == broker_result.get("verdict")
        and profile_result.get("effect_status") == broker_result.get("effect_status")
        and outcome["broker_result"] == broker_summary,
        "worker_attributed": attribution.get("pid") == worker_pid
        and attribution.get("pid") != gateway_pid
        and attribution.get("uid") == identities["worker"]["uid"]
        and attribution.get("gid") == identities["worker"]["gid"]
        and attribution.get("profile_digest") == worker_profile.digest
        and attribution.get("runtime_digest") == openclaw._RUNTIME_DIGEST
        and attribution.get("executable_digest") == python_digest
        and attribution.get("active_skill_digest") == skill_digest
        and attribution.get("skill_path") == str(producer["paths"]["skill"])
        and attribution.get("cgroup") == worker_cgroup
        and attribution.get("start_time_ticks")
        == int(worker_process["start_time_ticks"])
        and worker_process["mount_namespace"]
        == f"mnt:[{worker_mount_namespace['inode']}]"
        and attribution.get("mount_namespace") == worker_mount_namespace,
        "effect_bound": target["digest"] == action["payload_digest"]
        and target["stat"]["type"] == "file"
        and target["stat"]["uid"] == identities["broker"]["uid"]
        and target["stat"]["gid"] == identities["broker"]["gid"]
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1
        and receipt["file"]["digest"] == receipt["digest"]
        and receipt["file"]["stat"]["type"] == "file"
        and receipt["file"]["stat"]["uid"] == identities["broker"]["uid"]
        and receipt["file"]["stat"]["gid"] == identities["broker"]["gid"]
        and receipt["file"]["stat"]["mode"] == "0400"
        and receipt["file"]["stat"]["nlink"] == 1
        and skill["digest"] == skill_digest,
        "transcript_join": isinstance(correlation.get("session_id"), str)
        and isinstance(correlation.get("run_id"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", correlation.get("tool_call_id", ""))
        is not None
        and driver_identifiers.get("session_id") == correlation.get("session_id")
        and driver_identifiers.get("run_id") == correlation.get("run_id")
        and driver_identifiers.get("tool_call_digest")
        == correlation.get("tool_call_id")
        and all(
            driver_checks.get(name) is True
            for name in (
                "exact_gateway_session_key",
                "exact_tool_call_id_identity",
                "exact_wait_run_id",
                "exact_worker_request_digest",
                "exact_transcript_rpc_tool_result_join",
            )
        )
        and driver["output"]
        .get("gateway", {})
        .get("system_info", {})
        .get("response", {})
        .get("pid")
        == gateway_pid,
        "clean_before_after": before_state["document"]["status"] == "AVAILABLE"
        and before_state["document"]["claim"] is None
        and before_state["document"]["result"] is None
        and before["protected_entries"] == []
        and before["staging_entries"] == []
        and not before["pending_exists"]
        and not before["receipt_exists"]
        and after["protected_entries"] == [p37b._TARGET]
        and after["staging_entries"] == []
        and not after["pending_exists"]
        and after["receipt_exists"],
        "route_completion": _clean_terminal_unit(broker_after)
        and service_pids_after[_BROKER_UNIT] == 0
        and not service_state_after["sockets"][str(_BROKER_SOCKET)]["present"]
        and all(
            service_pids_after[name] == stack["pids"][name]
            for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT)
        )
        and all(
            service_state_after["units"][name]["properties"]["InvocationID"]
            == stack["service_state"]["units"][name]["properties"]["InvocationID"]
            for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT)
        )
        and all(
            service_state_after["units"][name]["properties"]["ActiveState"] == "active"
            for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT)
        ),
    }
    _expect(
        all(checks.values()),
        "P3.7c coherent action changed: " + repr(checks),
    )
    return {
        "status": "OBSERVED",
        "checks": checks,
        "effects": {"before": before, "after": after},
        "driver": driver,
        "traces": traces,
        "receipt": receipt,
        "receipt_file": receipt["file"],
        "broker_state": broker_state_record,
        "target": target,
        "correlation": correlation,
        "service_pids": {"before": stack["pids"], "after": service_pids_after},
        "service_state_after": service_state_after,
        "grant_state": state_record,
        "grant_state_file": state_record["file"],
        "broker_journal_after": _journal(
            _BROKER_UNIT,
            stack["service_state"]["units"][_BROKER_UNIT]["properties"]["InvocationID"],
            case_started_at,
            case_completed_at,
        ),
    }


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    _set_stage("IDENTITIES_AND_ARTIFACTS")
    broker = _user("aragorn-broker")
    worker = _user("aragorn-runtime")
    gateway = _user("aragorn-agent-gateway")
    sensor = _user("aragorn-sensor")
    worker_gid = _group("aragorn-runtime").gr_gid
    gateway_gid = _group("aragorn-agent-gateway").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    identities = {
        "broker": {"uid": broker.pw_uid, "gid": worker_gid},
        "gateway": {"uid": gateway.pw_uid, "gid": gateway_gid},
        "worker": {"uid": worker.pw_uid, "gid": worker_gid},
        "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
    }
    _expect(
        all(value > 0 for item in identities.values() for value in item.values())
        and len({item["uid"] for item in identities.values()}) == 4,
        "P3.7c service identities changed",
    )
    artifacts = _artifacts()
    runtime = openclaw._runtime_snapshot()
    node = _file(p37b._NODE)
    python = _file(p37b._PYTHON.resolve(strict=True))

    _set_stage("FIXTURE_SETUP")
    p37b.prior.lineage._reset()
    producer = p37b.prior._prepare_producer(worker_gid)
    p37b.prior._producer = producer
    skill_path = producer["paths"]["skill"]
    skill_raw = skill_path.read_bytes()
    skill_digest = _digest(skill_raw)
    p37b._reset_action_plane()
    config, tokens, projected_skill, token = _prepare_gateway(
        gateway.pw_uid,
        gateway_gid,
        worker.pw_uid,
        producer["skill_name"],
        skill_raw,
    )
    _DRIVER_ROOT.mkdir(mode=0o700)
    protected_fd = os.open(lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(protected_fd, p37b._TARGET, p37b._PAYLOAD)
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-7c-worker-activation-expiry",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "revocation_source_digest": openclaw._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": openclaw._RUNTIME_DIGEST,
                "active_skill_digest": skill_digest,
                **action,
            }
        ],
    }
    policy_digest = canonical_digest(policy)
    worker_binding = {
        "schema": "aragorn/runtime-action-worker-binding/v1",
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "active_skill_digest": skill_digest,
        "policy_digest": policy_digest,
        "policy_version": policy["version"],
    }
    worker_cgroup = p37b._predicted_service_cgroup(_WORKER_UNIT)
    worker_profile_document, worker_profile = p37b._profile(
        runtime_digest=openclaw._RUNTIME_DIGEST,
        executable_digest=python["digest"],
        cgroup=worker_cgroup,
        skill_path=skill_path,
    )

    _set_stage("AVAILABLE_TO_EXPIRED")
    _systemctl("unmask", _GATEWAY_UNIT, _WORKER_UNIT, check=False)
    _systemctl("disable", _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT, check=False)
    now = int(time.time())
    short_grant = _grant(
        profile_digest=worker_profile.digest,
        policy=policy,
        action=action,
        producer=producer,
        skill_digest=skill_digest,
        issued_at=now - 1,
        expires_at=now + 8,
    )
    short_grant_digest = canonical_digest(short_grant)
    expiry_controls = p37b._controls(policy, action, skill_digest, now, 1)
    p37b._write_stack_inputs(
        profile_document=worker_profile_document,
        profile_digest=worker_profile.digest,
        worker_binding=worker_binding,
        grant=short_grant,
        controls=expiry_controls,
        broker_uid=broker.pw_uid,
        worker_gid=worker_gid,
    )
    short_grant_source = _stable_grant_snapshot(_GRANT_SOURCE)
    _expect(
        short_grant_source["document"] == short_grant,
        "short grant source changed",
    )
    expiry_started_clock = _clock()
    broker_start = _command(["systemctl", "start", _BROKER_UNIT])
    _expect(broker_start["exit_code"] == 0, "expiry broker did not start")
    lineage._wait_path(_BROKER_SOCKET)
    available_state = _wait_state("AVAILABLE", short_grant_digest)
    available_state_file = available_state["file"]
    available_effects = p37b._snapshot_effects()
    expiry_unit = _unit(_BROKER_UNIT)
    expiry_pid = int(expiry_unit["MainPID"])
    expiry_process = _process(expiry_pid)
    expiry_socket = _socket_record(_BROKER_SOCKET)
    expiry_trace_path = _DRIVER_ROOT / "p37c-expiry-broker.trace"
    expiry_trace_process = p37b._start_trace(expiry_pid, expiry_trace_path)
    expired_state = _wait_state("EXPIRED", short_grant_digest)
    expired_state_file = expired_state["file"]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        expiry_after_route = _service_snapshot()
        if (
            expiry_after_route["units"][_BROKER_UNIT]["properties"]["ActiveState"]
            == "inactive"
            and expiry_after_route["units"][_BROKER_UNIT]["properties"]["MainPID"]
            == "0"
            and expiry_after_route["units"][_BROKER_UNIT]["cgroup_members"] == []
            and not expiry_after_route["sockets"][str(_BROKER_SOCKET)]["present"]
        ):
            break
        time.sleep(0.05)
    else:
        raise openclaw.ProbeError("expired broker did not stop cleanly")
    try:
        expiry_trace_status = expiry_trace_process.wait(timeout=3)
    except subprocess.TimeoutExpired as exc:
        raise openclaw.ProbeError("expiry tracer outlived the broker") from exc
    expiry_trace_stderr = (
        expiry_trace_process.stderr.read() if expiry_trace_process.stderr else b""
    )
    _expect(
        expiry_trace_status == 0 and len(expiry_trace_stderr) <= _MAX_COMMAND_BYTES,
        "expiry tracer did not cover clean broker teardown",
    )
    expiry_trace = p37b._finish_trace(
        expiry_trace_process, expiry_trace_path, expiry_pid
    )
    expiry_trace["successful_accepts"] = _successful_accepts(expiry_trace)
    expiry_trace["tracer"] = {
        "exit_code": expiry_trace_status,
        "stderr": _raw_record(expiry_trace_stderr),
        "covered_terminal_state": True,
    }
    expired_effects = p37b._snapshot_effects()
    expiry_completed_clock = _clock()
    expiry_checks = {
        "available_state_bound": available_state["document"]["status"] == "AVAILABLE"
        and available_state["document"]["grant_digest"] == short_grant_digest,
        "expired_state_bound": expired_state["document"]["status"] == "EXPIRED"
        and expired_state["document"]["grant_digest"] == short_grant_digest
        and expired_state["document"]["claim"] is None
        and expired_state["document"]["result"]["grant_digest"] == short_grant_digest
        and expired_state["document"]["result"]["expires_at_unix"]
        == short_grant["expires_at_unix"]
        and expired_state["document"]["result"]["observed_at_unix"]
        >= short_grant["expires_at_unix"],
        "idle_no_peer_or_effect": expiry_trace["channels"] == []
        and expiry_trace["successful_connects"] == []
        and expiry_trace["successful_accepts"] == []
        and _non_grant_effects(available_effects) == _non_grant_effects(expired_effects)
        and not expired_effects["pending_exists"]
        and not expired_effects["receipt_exists"]
        and not expired_effects["target_exists"],
        "expired_broker_stopped": _clean_terminal_unit(
            expiry_after_route["units"][_BROKER_UNIT]
        )
        and not expiry_after_route["sockets"][str(_BROKER_SOCKET)]["present"],
    }
    _expect(
        all(expiry_checks.values()),
        "AVAILABLE to EXPIRED transition changed: "
        + repr(
            {
                "checks": expiry_checks,
                "broker": expiry_after_route["units"][_BROKER_UNIT]["properties"],
                "cgroup_members": expiry_after_route["units"][_BROKER_UNIT][
                    "cgroup_members"
                ],
            }
        ),
    )

    _set_stage("EXPIRED_ACTIVATION_FAIL_STOP")
    failed_before_state = _stable_state_snapshot(_GRANT_STATE, short_grant_digest)
    failed_before_state_file = failed_before_state["file"]
    failed_before_grant = _stable_grant_snapshot(_GRANT_SOURCE)
    failed_before_effects = p37b._snapshot_effects()
    failed_before_route = _service_snapshot()
    failed_started_clock = _clock()
    failed_activation, failed_unit_samples = _monitored_command(
        [str(_ACTIVATOR)],
        (_BROKER_UNIT, _SENSOR_UNIT),
        timeout=75,
    )
    failed_completed_clock = _clock()
    failed_after_state = _stable_state_snapshot(_GRANT_STATE, short_grant_digest)
    failed_after_state_file = failed_after_state["file"]
    failed_after_grant = _stable_grant_snapshot(_GRANT_SOURCE)
    failed_after_effects = p37b._snapshot_effects()
    failed_after_route = _service_snapshot()
    failed_invocations = {
        name: _monitored_invocation(
            failed_unit_samples,
            name,
            failed_before_route["units"][name]["properties"]["InvocationID"],
            failed_activation,
        )
        for name in (_BROKER_UNIT, _SENSOR_UNIT)
    }
    failed_journals = _filtered_journals(
        failed_after_route,
        failed_activation["started_at"],
        failed_activation["completed_at"],
        {name: value["invocation_id"] for name, value in failed_invocations.items()},
    )
    failed_stderr_lines = _raw_bytes(failed_activation["stderr"]).splitlines()
    expected_failure_line = (
        b"runtime worker endpoint did not become ready: " + os.fsencode(_BROKER_SOCKET)
    )
    failed_broker = failed_after_route["units"][_BROKER_UNIT]
    failed_sensor = failed_after_route["units"][_SENSOR_UNIT]
    failed_checks = {
        "activation_failed_at_expired_endpoint": failed_activation["exit_code"] == 1
        and failed_activation["signal"] is None
        and _raw_bytes(failed_activation["stdout"]) == b""
        and bool(failed_stderr_lines)
        and failed_stderr_lines[-1] == expected_failure_line,
        "expired_state_unchanged": failed_after_state == failed_before_state,
        "expired_grant_unchanged": failed_after_grant == failed_before_grant,
        "effects_unchanged": failed_after_effects == failed_before_effects,
        "route_fail_stopped": _all_inactive(failed_after_route),
        "expired_services_exited_cleanly": _clean_terminal_unit(failed_broker)
        and _clean_terminal_unit(failed_sensor)
        and not failed_after_route["sockets"][str(_BROKER_SOCKET)]["present"]
        and not failed_after_route["sockets"][str(_SENSOR_SOCKET)]["present"],
        "invocations_and_timestamps_bound": all(
            failed_invocations[name]["invocation_id"]
            != failed_before_route["units"][name]["properties"]["InvocationID"]
            and failed_journals[name]["exit_code"] == 0
            for name in (_BROKER_UNIT, _SENSOR_UNIT)
        ),
        "gateway_worker_masked": failed_after_route["units"][_GATEWAY_UNIT][
            "properties"
        ]["UnitFileState"]
        == "masked"
        and failed_after_route["units"][_WORKER_UNIT]["properties"]["UnitFileState"]
        == "masked",
        "sensor_broker_disabled": failed_after_route["units"][_SENSOR_UNIT][
            "properties"
        ]["UnitFileState"]
        == "disabled"
        and failed_after_route["units"][_BROKER_UNIT]["properties"]["UnitFileState"]
        == "disabled",
    }
    _expect(all(failed_checks.values()), "expired activation fail-stop changed")

    _set_stage("EXPIRED_ARCHIVE_FRESH_ROTATION")
    archive_path = lineage._CONTROL / broker_v4._archive_name(
        "state", short_grant_digest
    )
    expired_receipt_archive = lineage._CONTROL / broker_v4._archive_name(
        "profile-receipt", short_grant_digest
    )
    rotation_pre_entries = sorted(path.name for path in lineage._CONTROL.iterdir())
    expected_rotation_pre_entries = sorted(
        [
            "broker.instance.lock",
            "broker.lock",
            "capability-grant-state.json",
            "health.json",
            "observation.json",
            "policy.json",
            "revocations.json",
            "state.json",
        ]
    )
    _expect(
        not os.path.lexists(archive_path)
        and not os.path.lexists(expired_receipt_archive)
        and rotation_pre_entries == expected_rotation_pre_entries,
        "terminal archive path or control inventory was not fresh",
    )
    unmask = _command(["systemctl", "unmask", _GATEWAY_UNIT, _WORKER_UNIT])
    _expect(unmask["exit_code"] == 0, "explicit worker route unmask failed")
    refresh_now = int(time.time())
    activation_controls = p37b._refresh_controls(
        policy,
        action,
        skill_digest,
        broker.pw_uid,
        worker_gid,
        2,
    )
    fresh_grant = _grant(
        profile_digest=worker_profile.digest,
        policy=policy,
        action=action,
        producer=producer,
        skill_digest=skill_digest,
        issued_at=refresh_now - 1,
        expires_at=refresh_now + 290,
    )
    fresh_grant_digest = canonical_digest(fresh_grant)
    _expect(
        fresh_grant_digest != short_grant_digest,
        "fresh rotation grant did not change",
    )
    grant_replacement = _replace_document(_GRANT_SOURCE, fresh_grant)
    rotation_before_state = _stable_state_snapshot(_GRANT_STATE, short_grant_digest)
    rotation_before_effects = p37b._snapshot_effects()
    rotation_before = {
        "expired_state": rotation_before_state,
        "expired_state_file": rotation_before_state["file"],
        "grant_source": _stable_grant_snapshot(_GRANT_SOURCE),
        "route": _service_snapshot(),
        "clock": _clock(),
        "archive_paths": {
            "state": {"path": str(archive_path), "present": False},
            "profile_receipt": {
                "path": str(expired_receipt_archive),
                "present": False,
            },
        },
        "control_entries": rotation_pre_entries,
        "effects": rotation_before_effects,
    }
    successful_activation = _command([str(_ACTIVATOR)], timeout=90)
    _expect(successful_activation["exit_code"] == 0, "fresh activation failed")
    fresh_state = _wait_state("AVAILABLE", fresh_grant_digest)
    archive = _stable_state_snapshot(archive_path, short_grant_digest)
    full_stack = _active_stack()
    rotation_after_effects = p37b._snapshot_effects()
    rotation_post_entries = sorted(path.name for path in lineage._CONTROL.iterdir())
    expected_rotation_post_entries = sorted(
        [*expected_rotation_pre_entries, archive_path.name, _BROKER_SOCKET.name]
    )
    rotation_after = {
        "archive": archive,
        "archive_file": archive["file"],
        "current_state": fresh_state,
        "current_state_file": fresh_state["file"],
        "grant_source": _stable_grant_snapshot(_GRANT_SOURCE),
        "route": _service_snapshot(),
        "clock": _clock(),
        "expired_profile_receipt_archive_present": os.path.lexists(
            expired_receipt_archive
        ),
        "control_entries": rotation_post_entries,
        "effects": rotation_after_effects,
    }
    rotation_checks = {
        "fresh_grant_distinct_and_available": fresh_state["document"]["status"]
        == "AVAILABLE"
        and fresh_state["document"]["grant_digest"] == fresh_grant_digest
        and fresh_state["document"]["claim"] is None
        and fresh_state["document"]["result"] is None,
        "expired_state_archived_exactly": archive["document"]
        == expired_state["document"]
        and archive["digest"] == expired_state["digest"]
        and archive["file"]["base64"] == expired_state["file"]["base64"]
        and archive["document"]["status"] == "EXPIRED",
        "archive_metadata": rotation_after["archive_file"]["stat"]["uid"]
        == broker.pw_uid
        and rotation_after["archive_file"]["stat"]["gid"] == worker_gid
        and rotation_after["archive_file"]["stat"]["mode"] == "0400"
        and rotation_after["archive_file"]["stat"]["nlink"] == 1,
        "exact_control_inventory_no_stage_or_receipt": rotation_post_entries
        == expected_rotation_post_entries
        and not any(name.startswith(".") for name in rotation_post_entries)
        and not os.path.lexists(expired_receipt_archive),
        "rotation_changed_only_grant_state": _non_grant_effects(rotation_before_effects)
        == _non_grant_effects(rotation_after_effects)
        and not rotation_after_effects["pending_exists"]
        and not rotation_after_effects["receipt_exists"]
        and not rotation_after_effects["target_exists"],
        "four_units_active_no_boot_authority": all(
            value == "active"
            for value in (unit["ActiveState"] for unit in full_stack["units"].values())
        )
        and full_stack["enablement"][_GATEWAY_UNIT] == "static"
        and all(
            full_stack["enablement"][name] == "disabled"
            for name in (_WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT)
        ),
    }
    _expect(all(rotation_checks.values()), "terminal grant rotation changed")
    activation_checks = {
        "four_units_active": all(
            value["ActiveState"] == "active" for value in full_stack["units"].values()
        ),
        "three_sockets_present": all(
            value["present"] for value in full_stack["sockets"].values()
        ),
        "gateway_listener_bound_to_main_pid": full_stack["gateway_listener"]["pid"]
        == full_stack["pids"][_GATEWAY_UNIT],
        "no_boot_authority": full_stack["enablement"][_GATEWAY_UNIT] == "static"
        and all(
            full_stack["enablement"][name] == "disabled"
            for name in (_WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT)
        ),
    }
    _expect(all(activation_checks.values()), "full activation boundary changed")

    _set_stage("COHERENT_CONSUMED_ACTION")
    coherent_controls = p37b._refresh_controls(
        policy,
        action,
        skill_digest,
        broker.pw_uid,
        worker_gid,
        3,
    )
    coherent = _coherent_case(
        stack=full_stack,
        tokens=tokens,
        grant_digest=fresh_grant_digest,
        worker_profile=worker_profile,
        worker_cgroup=worker_cgroup,
        producer=producer,
        identities=identities,
        policy=policy,
        policy_digest=policy_digest,
        python_digest=python["digest"],
        skill_digest=skill_digest,
        action=action,
    )
    archive_after_action = _stable_state_snapshot(archive_path, short_grant_digest)
    _expect(archive_after_action == archive, "expired archive changed after action")

    _set_stage("OBSERVATION_ASSEMBLY")
    result = {
        "schema": (
            "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        ),
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "parent": _PARENT,
        "harness": harness,
        "artifacts": artifacts,
        "runtime": runtime,
        "identities": identities,
        "profiles": {
            "worker": {
                "digest": worker_profile.digest,
                "document": worker_profile_document,
            },
            "executables": {"node": node, "worker_python": python},
        },
        "inputs": {
            "action": action,
            "policy": policy,
            "policy_digest": policy_digest,
            "worker_binding": worker_binding,
            "worker_binding_file": _file(p37b._WORKER_BINDING),
            "short_grant": {
                "digest": short_grant_digest,
                "document": short_grant,
                "source": short_grant_source,
            },
            "fresh_grant": {
                "digest": fresh_grant_digest,
                "document": fresh_grant,
            },
            "grant_source": _stable_grant_snapshot(_GRANT_SOURCE),
            "control_sets": {
                "expiry": expiry_controls,
                "activation": activation_controls,
                "coherent_refresh": coherent_controls,
            },
            "producer": {
                "transaction": producer["transaction"],
                "record": producer["record"],
                "skill": _file(skill_path),
                "projected_skill": _file(projected_skill),
            },
            "gateway_config": config,
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
        },
        "cases": {
            "expired_fail_stop": {
                "status": "OBSERVED",
                "checks": {**expiry_checks, **failed_checks},
                "expiry": {
                    "started_clock": expiry_started_clock,
                    "completed_clock": expiry_completed_clock,
                    "broker_start": broker_start,
                    "available_state": available_state,
                    "available_state_file": available_state_file,
                    "expired_state": expired_state,
                    "expired_state_file": expired_state_file,
                    "effects": {
                        "available": available_effects,
                        "expired": expired_effects,
                    },
                    "unit": expiry_unit,
                    "process": expiry_process,
                    "socket": expiry_socket,
                    "trace": expiry_trace,
                    "after_route": expiry_after_route,
                },
                "activation": {
                    "started_clock": failed_started_clock,
                    "completed_clock": failed_completed_clock,
                    "command": failed_activation,
                    "state": {
                        "before": failed_before_state,
                        "after": failed_after_state,
                        "before_file": failed_before_state_file,
                        "after_file": failed_after_state_file,
                    },
                    "grant": {
                        "before": failed_before_grant,
                        "after": failed_after_grant,
                    },
                    "effects": {
                        "before": failed_before_effects,
                        "after": failed_after_effects,
                    },
                    "route": {
                        "before": failed_before_route,
                        "after": failed_after_route,
                        "monitor": failed_unit_samples,
                        "invocations": failed_invocations,
                    },
                    "journals": failed_journals,
                },
            },
            "terminal_archive_rotation": {
                "status": "OBSERVED",
                "checks": rotation_checks,
                "unmask_command": unmask,
                "grant_replacement": grant_replacement,
                "activation_command": successful_activation,
                "before": rotation_before,
                "after": rotation_after,
            },
            "full_activation": {
                "status": "OBSERVED",
                "checks": activation_checks,
                "activation_command": successful_activation,
                "stack": full_stack,
            },
            "coherent_consumed": {
                **coherent,
                "expired_archive_after": archive_after_action,
            },
        },
        "boundaries": {
            "activation_lock": "/run/lock/aragorn-runtime-capability-activation.lock",
            "units": full_stack["units"],
            "processes": full_stack["processes"],
            "sockets": full_stack["sockets"],
            "gateway_listener": full_stack["gateway_listener"],
            "service_state": full_stack["service_state"],
            "enablement": full_stack["enablement"],
        },
        "secret_checks": {
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
            "forbidden_driver_fields": p37b._forbidden_driver_fields(
                coherent["driver"]
            ),
        },
        "decision": {
            "status": "P3_7C_ACTIVATION_EXPIRY_OBSERVED",
            "verifier_status": "NOT_TESTED",
            "retained_evidence_eligible": False,
            "available_to_expired_observed": True,
            "expired_activation_fail_stop_observed": True,
            "terminal_archive_rotation_observed": True,
            "full_activation_no_boot_authority_observed": True,
            "coherent_allow_created_consumed_observed": True,
            "parent_p3_7b_unchanged": True,
            "aggregate_gate_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "limitations": _LIMITATIONS,
    }
    encoded = canonical_json(result)
    _expect(token.encode() not in encoded, "observation retained a gateway token")
    _expect(
        result["secret_checks"]["forbidden_driver_fields"] == [],
        "driver retained a forbidden authority field",
    )
    return result


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text(encoding="ascii").strip() != "systemd"
    ):
        raise openclaw.ProbeError(
            "collector requires root in the fixed systemd container"
        )
    harness = _harness()
    try:
        return _collect_live(harness)
    finally:
        p37b._stop_stack()
        _systemctl("disable", _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT, check=False)


def _failure(exc: Exception) -> dict[str, Any]:
    error = str(exc).encode("utf-8", errors="replace")
    return {
        "schema": (
            "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        ),
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_7C_ACTIVATION_EXPIRY_NOT_OBSERVED",
            "verifier_status": "NOT_TESTED",
            "retained_evidence_eligible": False,
            "aggregate_gate_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": _STAGE,
            "type": type(exc).__name__,
            "diagnostic": _raw_record(error),
        },
    }


def _publish(path: Path | None, document: dict[str, Any]) -> None:
    raw = canonical_json(document) + b"\n"
    if path is None:
        sys.stdout.buffer.write(raw)
        return
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise openclaw.ProbeError("output must be one absent absolute path")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("observation publication made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) == 2 and arguments[0] == "--output":
        output = Path(arguments[1])
    elif not arguments:
        output = None
    else:
        print(
            "usage: runtime_action_worker_activation_expiry_systemd_probe.py "
            "[--output ABSENT_ABSOLUTE_PATH]",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    _publish(output, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
