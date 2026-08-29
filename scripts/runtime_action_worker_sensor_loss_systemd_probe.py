#!/usr/bin/env python3
"""Capture one bounded gateway fail-stop after lineage-sensor process loss."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/src/scripts")

import runtime_action_worker_activation_expiry_systemd_probe as p37c
import runtime_action_worker_final_combined_v2_systemd_probe as final


class _SensorLossObserved(Exception):
    pass


_HARNESS_PATH = Path("/run/aragorn-harness.json")
_COLLECTOR_ROOT = Path("/opt/aragorn-sensor-loss-collector")
_PARENT_IMAGE = (
    "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
)
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ACTIVATOR_DIGEST = (
    "sha256:47d03e4600813cb32b536a267608f8d7eb97219c2421ba944426444693fee009"
)
_GATEWAY_UNIT_DIGEST = (
    "sha256:70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067"
)
_AUTHORITY = (
    "BOUNDED_LOCAL_SYSTEMD_SENSOR_PROCESS_LOSS_OBSERVATION_ONLY_"
    "NOT_RUN_02_PHASE3_EDR_OR_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "ONE_LOCAL_PRIVATE_CGROUP_SYSTEMD_CONTAINER_ONLY",
    "PRIVILEGED_DOCKER_ROOT_CONTROLLED_FIXTURE_ONLY",
    "CONTAINER_BUILD_AND_CAPTURE_TOOLCHAIN_NOT_INDEPENDENTLY_ATTESTED",
    "SOURCE_COMMIT_SIGNATURE_TRUSTS_LOCAL_GIT_CONFIGURATION_AND_KEYRING",
    "ONE_SIGKILL_SENSOR_PROCESS_LOSS_WITH_SYSTEMD_RESTART_ONLY",
    "NO_HUNG_SENSOR_STALE_SOCKET_OR_HEALTH_EPOCH_COVERAGE",
    "NO_IN_FLIGHT_EFFECT_REVOCATION_QUARANTINE_OR_EGRESS_ISOLATION_COVERAGE",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_ARTIFACT_PATHS = {
    "activator": Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"),
    "capture_recipe": _COLLECTOR_ROOT
    / "capture_runtime_action_worker_sensor_loss_systemd.sh",
    "dockerfile": _COLLECTOR_ROOT / "Dockerfile",
    "gateway_unit": Path("/usr/lib/systemd/system/aragorn-agent-gateway.service"),
    "probe": _COLLECTOR_ROOT / "runtime_action_worker_sensor_loss_systemd_probe.py",
}
_EXPECTED_MODES = {
    "activator": "0755",
    "capture_recipe": "0755",
    "dockerfile": "0644",
    "gateway_unit": "0644",
    "probe": "0755",
}

_CAPTURE: dict[str, Any] | None = None
_HARNESS: dict[str, Any] | None = None
_ARTIFACTS: dict[str, Any] | None = None
_TOKEN: bytes | None = None
_ORIGINAL_ACTIVE_STACK = p37c._active_stack
_ORIGINAL_ARTIFACTS = p37c._artifacts
_ORIGINAL_SERVICE_SNAPSHOT = p37c._service_snapshot


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _metadata(value: os.stat_result) -> dict[str, Any]:
    kind = (
        "directory"
        if stat.S_ISDIR(value.st_mode)
        else "file"
        if stat.S_ISREG(value.st_mode)
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
    }


def _file_snapshot(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        p37c._expect(
            stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
            f"artifact is not one regular file: {path}",
        )
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        raw = b"".join(chunks)
        retained = os.fstat(descriptor)
        p37c._expect(
            (retained.st_dev, retained.st_ino, retained.st_size)
            == (opened.st_dev, opened.st_ino, len(raw)),
            f"artifact changed while reading: {path}",
        )
    finally:
        os.close(descriptor)
    return {
        "path": str(path),
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": _digest(raw),
        "stat": _metadata(retained),
    }


def _decode_record(record: object, name: str) -> bytes:
    p37c._expect(
        isinstance(record, dict)
        and set(record) == {"base64", "bytes", "digest"}
        and isinstance(record.get("base64"), str)
        and isinstance(record.get("bytes"), int)
        and isinstance(record.get("digest"), str),
        f"invalid raw record: {name}",
    )
    try:
        raw = base64.b64decode(record["base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise p37c.openclaw.ProbeError(f"invalid raw record encoding: {name}") from exc
    p37c._expect(
        len(raw) == record["bytes"] and _digest(raw) == record["digest"],
        f"raw record identity changed: {name}",
    )
    return raw


def _harness() -> dict[str, Any]:
    global _HARNESS

    raw = _HARNESS_PATH.read_bytes()
    value = json.loads(raw)
    p37c._expect(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        == raw,
        "sensor-loss harness is not canonical JSON",
    )
    expected_fields = {
        "bindings",
        "capture_disposition",
        "container_id",
        "host_config",
        "image_id",
        "image_lineage",
        "image_reference",
        "openclaw_runtime_mount",
        "openclaw_runtime_volume",
        "openclaw_runtime_volume_identity",
        "parent_image_id",
        "platform",
        "profile_label",
        "raw_records",
        "run_image_reference",
        "schema",
        "source_artifacts",
        "source_commit_verification",
    }
    p37c._expect(
        isinstance(value, dict)
        and set(value) == expected_fields
        and value["schema"]
        == "aragorn/runtime-action-worker-sensor-loss-systemd-harness/v1"
        and value["capture_disposition"] == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and value["parent_image_id"] == _PARENT_IMAGE
        and value["image_id"] == value["run_image_reference"]
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"] or "") is not None
        and re.fullmatch(r"[0-9a-f]{64}", value["container_id"] or "") is not None
        and value["image_reference"]
        == "aragorn-phase3-runtime-action-worker-sensor-loss-systemd"
        and value["platform"] == "linux"
        and value["profile_label"] == "phase3-runtime-action-worker-sensor-loss"
        and value["openclaw_runtime_volume"] == _RUNTIME_VOLUME,
        "sensor-loss harness identity changed",
    )
    bindings = value["bindings"]
    p37c._expect(
        isinstance(bindings, dict)
        and set(bindings)
        == {"artifacts", "child_image_id", "parent_image_id", "source_commit"}
        and bindings["parent_image_id"] == _PARENT_IMAGE
        and bindings["child_image_id"] == value["image_id"]
        and re.fullmatch(r"[0-9a-f]{40}", bindings["source_commit"] or "") is not None
        and isinstance(bindings["artifacts"], dict)
        and set(bindings["artifacts"]) == set(_ARTIFACT_PATHS)
        and all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", digest or "") is not None
            for digest in bindings["artifacts"].values()
        ),
        "sensor-loss harness bindings changed",
    )
    expected_volume = {
        "driver": "local",
        "labels": {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
        },
        "name": _RUNTIME_VOLUME,
        "options": None,
        "scope": "local",
    }
    p37c._expect(
        value["openclaw_runtime_volume_identity"] == expected_volume
        and value["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _RUNTIME_VOLUME,
            "type": "volume",
        }
        and value["host_config"]
        == {
            "binds": [f"{_RUNTIME_VOLUME}:/runtime:ro"],
            "cgroupns_mode": "private",
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
        },
        "sensor-loss runtime volume or private cgroup profile changed",
    )
    raw_records = value["raw_records"]
    p37c._expect(
        isinstance(raw_records, dict)
        and set(raw_records)
        == {
            "child_image_inspect",
            "container_inspect",
            "parent_image_inspect",
            "runtime_volume_inspect",
        },
        "sensor-loss inspect records changed",
    )
    for name, record in raw_records.items():
        decoded = json.loads(_decode_record(record, name))
        p37c._expect(
            isinstance(decoded, list)
            and len(decoded) == 1
            and isinstance(decoded[0], dict),
            f"sensor-loss inspect record changed: {name}",
        )
    verification = value["source_commit_verification"]
    p37c._expect(
        isinstance(verification, dict)
        and set(verification)
        == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and verification["command"]
        == ["git", "verify-commit", "--raw", bindings["source_commit"]]
        and verification["exit_code"] == 0,
        "sensor-loss commit verification command changed",
    )
    commit_raw = _decode_record(verification["commit_object"], "commit_object")
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    stdout = _decode_record(verification["stdout"], "verify_stdout")
    stderr = _decode_record(verification["stderr"], "verify_stderr")
    p37c._expect(
        commit_identity == bindings["source_commit"]
        and commit_raw.startswith(b"tree ")
        and b"\ngpgsig " in commit_raw
        and stdout == b""
        and stderr == p37c._SOURCE_SIGNATURE,
        "sensor-loss signed source receipt changed",
    )
    source_artifacts = value["source_artifacts"]
    p37c._expect(
        isinstance(source_artifacts, dict)
        and set(source_artifacts) == set(_ARTIFACT_PATHS),
        "sensor-loss source artifact set changed",
    )
    for name, record in source_artifacts.items():
        source_raw = _decode_record(record, f"source_artifacts.{name}")
        p37c._expect(
            _digest(source_raw) == bindings["artifacts"][name],
            f"sensor-loss source artifact binding changed: {name}",
        )
    _HARNESS = value
    return value


def _artifacts() -> dict[str, Any]:
    global _ARTIFACTS

    p37c._expect(_HARNESS is not None, "sensor-loss harness was not loaded")
    _ORIGINAL_ARTIFACTS()
    retained = {name: _file_snapshot(path) for name, path in _ARTIFACT_PATHS.items()}
    source_artifacts = _HARNESS["source_artifacts"]
    bindings = _HARNESS["bindings"]["artifacts"]
    for name, item in retained.items():
        source_raw = _decode_record(source_artifacts[name], f"source_artifacts.{name}")
        p37c._expect(
            item["digest"] == bindings[name]
            and item["digest"] == _digest(source_raw)
            and item["bytes"] == len(source_raw)
            and item["stat"]["type"] == "file"
            and item["stat"]["uid"] == 0
            and item["stat"]["gid"] == 0
            and item["stat"]["mode"] == _EXPECTED_MODES[name]
            and item["stat"]["nlink"] == 1,
            f"sensor-loss artifact changed: {name}",
        )
    p37c._expect(
        retained["activator"]["digest"] == _ACTIVATOR_DIGEST
        and retained["activator"]["bytes"] == 31_295
        and retained["gateway_unit"]["digest"] == _GATEWAY_UNIT_DIGEST
        and retained["gateway_unit"]["bytes"] == 3_437,
        "sensor-loss enforcement artifact identity changed",
    )
    _ARTIFACTS = retained
    return retained


def _private_service_cgroup(unit: str) -> str:
    pid1 = p37c.p37b.profile_systemd._cgroup(1)
    p37c._expect(pid1 == "/init.scope", "PID1 is outside the private systemd cgroup")
    return f"/system.slice/{unit}"


def _service_snapshot() -> dict[str, Any]:
    snapshot = _ORIGINAL_SERVICE_SNAPSHOT()
    for name, unit in snapshot["units"].items():
        path = Path("/sys/fs/cgroup/system.slice") / name / "cgroup.procs"
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            raw = b""
            present = False
        else:
            try:
                chunks = []
                while chunk := os.read(descriptor, 1024 * 1024):
                    chunks.append(chunk)
                raw = b"".join(chunks)
            finally:
                os.close(descriptor)
            present = True
        try:
            members = raw.decode("ascii").split()
        except UnicodeDecodeError as exc:
            raise p37c.openclaw.ProbeError(
                f"non-ASCII cgroup membership: {name}"
            ) from exc
        p37c._expect(
            all(re.fullmatch(r"[1-9][0-9]*", member) for member in members),
            f"invalid cgroup membership: {name}",
        )
        unit["cgroup_members"] = members
        unit["cgroup_procs"] = {
            "path": str(path),
            "present": present,
            "raw": p37c._raw_record(raw),
        }
    return snapshot


def _prepare_gateway(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
    global _TOKEN

    result = final._prepare_gateway(*args, **kwargs)
    token = result[3]
    p37c._expect(isinstance(token, str) and token, "gateway token was not created")
    _TOKEN = token.encode("ascii")
    return result


def _protected_state() -> dict[str, Any]:
    root = p37c.p37b.lineage._PROTECTED
    return {
        "root": p37c._metadata(root),
        "entries": sorted(path.name for path in root.iterdir()),
        "target_exists": (root / p37c.p37b._TARGET).exists(),
    }


def _stopped(unit: dict[str, Any]) -> bool:
    properties = unit["properties"]
    return (
        properties["ActiveState"] == "inactive"
        and properties["SubState"] == "dead"
        and properties["MainPID"] == "0"
        and unit["cgroup_members"] == []
        and unit["cgroup_procs"]["present"] is False
        and p37c._raw_bytes(unit["cgroup_procs"]["raw"]) == b""
    )


def _restarted(before: dict[str, Any], after: dict[str, Any]) -> bool:
    before_properties = before["properties"]
    after_properties = after["properties"]
    pid = after_properties["MainPID"]
    return (
        after_properties["ActiveState"] == "active"
        and after_properties["SubState"] == "running"
        and re.fullmatch(r"[1-9][0-9]*", pid) is not None
        and pid != before_properties["MainPID"]
        and after_properties["InvocationID"] != before_properties["InvocationID"]
        and after_properties["InvocationID"] != ""
        and after["cgroup_members"] != []
        and pid in after["cgroup_members"]
        and after["cgroup_procs"]["present"] is True
    )


def _capture_sensor_loss() -> dict[str, Any]:
    global _CAPTURE

    p37c._expect(
        _HARNESS is not None and _ARTIFACTS is not None and _TOKEN is not None,
        "sensor-loss prerequisite validation was not reached",
    )
    stack = _ORIGINAL_ACTIVE_STACK()
    before = stack["service_state"]
    skill_before = final._skill_snapshot()
    protected_before = _protected_state()
    broker_before = before["units"][p37c._BROKER_UNIT]
    sensor_before = before["units"][p37c._SENSOR_UNIT]
    sensor_pid = sensor_before["properties"]["MainPID"]
    loss = p37c._command(["kill", "-KILL", sensor_pid])
    p37c._expect(loss["exit_code"] == 0, "lineage sensor SIGKILL failed")

    deadline = time.monotonic() + 10
    while True:
        after = p37c._service_snapshot()
        broker_after = after["units"][p37c._BROKER_UNIT]
        if (
            all(
                _stopped(after["units"][unit])
                for unit in (p37c._GATEWAY_UNIT, p37c._WORKER_UNIT)
            )
            and _restarted(sensor_before, after["units"][p37c._SENSOR_UNIT])
            and broker_after["properties"]["ActiveState"] == "active"
            and broker_after["properties"]["SubState"] == "running"
            and broker_after["properties"] == broker_before["properties"]
            and broker_after["cgroup_members"] == broker_before["cgroup_members"]
            and broker_after["cgroup_procs"] == broker_before["cgroup_procs"]
            and after["sockets"][str(p37c._BROKER_SOCKET)]
            == before["sockets"][str(p37c._BROKER_SOCKET)]
        ):
            break
        if time.monotonic() >= deadline:
            raise p37c.openclaw.ProbeError(
                "gateway and worker did not fail-stop after sensor process loss"
            )
        time.sleep(0.05)

    skill_after = final._skill_snapshot()
    protected_after = _protected_state()
    gateway_before = before["units"][p37c._GATEWAY_UNIT]
    gateway_after = after["units"][p37c._GATEWAY_UNIT]
    checks = {
        "gateway_started_with_process": (
            gateway_before["properties"]["ActiveState"] == "active"
            and gateway_before["properties"]["SubState"] == "running"
            and int(gateway_before["properties"]["MainPID"]) > 0
            and gateway_before["cgroup_members"] != []
        ),
        "gateway_stopped_with_empty_cgroup": _stopped(gateway_after),
        "worker_stopped_with_empty_cgroup": _stopped(after["units"][p37c._WORKER_UNIT]),
        "sensor_restarted_with_new_process": _restarted(
            sensor_before, after["units"][p37c._SENSOR_UNIT]
        ),
        "broker_process_and_socket_unchanged": (
            after["units"][p37c._BROKER_UNIT]["properties"]
            == broker_before["properties"]
            and after["units"][p37c._BROKER_UNIT]["cgroup_members"]
            == broker_before["cgroup_members"]
            and after["units"][p37c._BROKER_UNIT]["cgroup_procs"]
            == broker_before["cgroup_procs"]
            and after["sockets"][str(p37c._BROKER_SOCKET)]
            == before["sockets"][str(p37c._BROKER_SOCKET)]
        ),
        "singleton_skill_unchanged": skill_after == skill_before,
        "protected_state_unchanged": (
            protected_after == protected_before
            and protected_after["target_exists"] is False
        ),
    }
    p37c._expect(all(checks.values()), "sensor-loss fail-stop checks changed")
    _CAPTURE = {
        "schema": "aragorn/runtime-action-worker-sensor-loss-systemd-observation/v1",
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "bindings": _HARNESS["bindings"],
        "harness": _HARNESS,
        "artifacts": _ARTIFACTS,
        "before": {
            "services": before,
            "skill": skill_before,
            "protected": protected_before,
        },
        "loss": loss,
        "after": {
            "services": after,
            "skill": skill_after,
            "protected": protected_after,
        },
        "checks": checks,
        "secret_checks": {"gateway_token_retained": False},
        "decision": {
            "status": "SENSOR_PROCESS_LOSS_GATEWAY_FAIL_STOP_OBSERVED",
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
        "limitations": _LIMITATIONS,
    }
    encoded = p37c.canonical_json(_CAPTURE)
    p37c._expect(_TOKEN not in encoded, "observation retained a gateway token")
    raise _SensorLossObserved


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text(encoding="ascii").strip() != "systemd"
    ):
        raise p37c.openclaw.ProbeError(
            "collector requires root in the fixed systemd container"
        )
    harness = _harness()
    final._reset_transient_request_directory()
    try:
        with (
            mock.patch.object(p37c, "_artifacts", _artifacts),
            mock.patch.object(p37c, "_prepare_gateway", _prepare_gateway),
            mock.patch.object(p37c, "_service_snapshot", _service_snapshot),
            mock.patch.object(p37c, "_active_stack", _capture_sensor_loss),
            mock.patch.object(
                p37c.p37b,
                "_predicted_service_cgroup",
                _private_service_cgroup,
            ),
            mock.patch.object(final.openclaw, "_RUNTIME_DIGEST", final._RUNTIME_DIGEST),
            mock.patch.object(
                final.openclaw, "_ENTRYPOINT_DIGEST", final._ENTRYPOINT_DIGEST
            ),
            mock.patch.object(
                final.openclaw, "_runtime_snapshot", final._runtime_snapshot
            ),
        ):
            p37c._collect_live(harness)
    except _SensorLossObserved:
        pass
    finally:
        p37c.p37b._stop_stack()
        p37c._systemctl(
            "disable",
            p37c._WORKER_UNIT,
            p37c._SENSOR_UNIT,
            p37c._BROKER_UNIT,
            check=False,
        )
    if _CAPTURE is None:
        raise p37c.openclaw.ProbeError("sensor-loss boundary was not reached")
    return _CAPTURE


def _failure(exc: Exception) -> dict[str, Any]:
    raw = str(exc).encode("utf-8", errors="replace")
    return {
        "schema": "aragorn/runtime-action-worker-sensor-loss-systemd-observation/v1",
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "SENSOR_PROCESS_LOSS_GATEWAY_FAIL_STOP_NOT_OBSERVED",
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
            "type": type(exc).__name__,
            "diagnostic": {
                "base64": base64.b64encode(raw).decode("ascii"),
                "bytes": len(raw),
                "digest": _digest(raw),
            },
        },
    }


def _publish(path: Path | None, document: dict[str, Any]) -> None:
    raw = p37c.canonical_json(document) + b"\n"
    if path is None:
        sys.stdout.buffer.write(raw)
        return
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise p37c.openclaw.ProbeError("output must be one absent absolute path")
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
            "usage: runtime_action_worker_sensor_loss_systemd_probe.py "
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
