#!/usr/bin/env python3
"""Collect one bounded pinned-OpenClaw/systemd composition slice for P3.3c."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, "/usr/lib/aragorn")

from aragorn.oci_worker_protocol import canonical_digest, canonical_json  # noqa: E402
from aragorn.runtime_action_broker import (  # noqa: E402
    RuntimeActionBrokerConfig,
    RuntimeActionBrokerError,
    _action_digests,
    publish_runtime_control_document,
    write_all,
)

import runtime_action_systemd_probe as systemd_probe  # noqa: E402


_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL = _ROOT / "control"
_PROTECTED = _ROOT / "protected"
_STAGING = _ROOT / "staging"
_FRONTEND = Path("/run/aragorn-runtime-observation/sensor.sock")
_BACKEND = _CONTROL / "broker.sock"
_HARNESS = Path("/run/aragorn-harness.json")
_BROKER_UNIT = "aragorn-runtime-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-observation-publisher.service"
_OPENCLAW = Path("/runtime/lib/node_modules/openclaw/openclaw.mjs")
_PLUGIN = Path("/opt/aragorn/openclaw/aragorn-runtime-action")
_MJS_PROBE = Path(
    "/src/benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs"
)
_RUNTIME_DIGEST = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_SENSOR_IMPLEMENTATION_FILES = (
    (Path("/usr/lib/aragorn/aragorn/__init__.py"), "0644"),
    (Path("/usr/lib/aragorn/aragorn/oci_worker_protocol.py"), "0644"),
    (Path("/usr/lib/aragorn/aragorn/runtime_action_broker.py"), "0644"),
    (Path("/usr/lib/aragorn/aragorn/runtime_action_decision.py"), "0644"),
    (
        Path("/usr/lib/aragorn/aragorn/runtime_action_observation_publisher.py"),
        "0644",
    ),
    (Path("/usr/lib/aragorn/aragorn/runtime_action_service.py"), "0644"),
    (Path("/usr/lib/aragorn/aragorn/runtime_observation_service.py"), "0644"),
    (
        Path("/usr/libexec/aragorn/aragorn-runtime-observation-service.py"),
        "0755",
    ),
)
_REVOCATION_SOURCE = "sha256:" + hashlib.sha256(
    b"aragorn/p3.3c/revocation-source/v1"
).hexdigest()
_SKILL_NAME = "aragorn-runtime-composition"
_SKILL = (
    "---\n"
    f"name: {_SKILL_NAME}\n"
    "description: Bounded P3.3c native runtime-action composition fixture.\n"
    "---\n"
    "# Aragorn P3.3c fixture\n\n"
    "Call aragorn_runtime_create exactly once with the requested target and content.\n"
).encode()
_SKILL_DIGEST = "sha256:" + hashlib.sha256(_SKILL).hexdigest()
_SCENARIOS = {
    "allow": {
        "target_name": "openclaw-allowed.txt",
        "content": "Aragorn P3.3c OpenClaw allowed create\n",
        "expected_verdict": "ALLOW",
        "expected_effect_status": "CREATED",
    },
    "unhealthy": {
        "target_name": "openclaw-unhealthy.txt",
        "content": "Aragorn P3.3c OpenClaw unhealthy block\n",
        "expected_verdict": "BLOCK",
        "expected_effect_status": "NOT_PERFORMED",
    },
    "sensor_unavailable": {
        "target_name": "openclaw-sensor-down.txt",
        "content": "Aragorn P3.3c OpenClaw sensor-down block\n",
        "expected_verdict": "CLIENT_ERROR",
        "expected_effect_status": "NOT_SUBMITTED",
    },
}
_AUTHORITY = "BOUNDED_PINNED_OPENCLAW_SYSTEMD_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
_LIMITATIONS = [
    "SINGLE_PINNED_OPENCLAW_OPTIONAL_CREATE_TOOL_PROFILE_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "OPAQUE_SESSION_RUN_AND_TOOL_IDS_NOT_CAUSAL_ATTRIBUTION",
    "ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "SYSTEMD_PACKAGE_INSTALLED_FROM_NETWORKED_DEBIAN_REPOSITORY",
    "OPENCLAW_RUNTIME_LOCAL_VOLUME_REINVENTORIED_NOT_REACQUIRED",
    "OPENCLAW_RETURNED_TOOL_RESULT_ISERROR_FLAG_NOT_SECURITY_AUTHORITY",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_FORCED_RESET_FILESYSTEM_OR_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]


class ProbeError(RuntimeError):
    """The live P3.3c composition did not satisfy its bounded contract."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def _sensor_implementation() -> dict[str, Any]:
    files = []
    for path, expected_mode in _SENSOR_IMPLEMENTATION_FILES:
        observed = systemd_probe._file(path)  # noqa: SLF001
        metadata = observed["stat"]
        _expect(
            metadata["type"] == "file"
            and metadata["uid"] == 0
            and metadata["gid"] == 0
            and metadata["mode"] == expected_mode
            and metadata["nlink"] == 1
            and metadata["size"] == observed["bytes"],
            f"sensor implementation artifact changed: {path}",
        )
        files.append(
            {
                "path": str(path),
                "digest": observed["digest"],
                "bytes": observed["bytes"],
                "mode": metadata["mode"],
            }
        )
    closure = {
        "schema": "aragorn/runtime-observation-sensor-implementation/v1",
        "files": files,
    }
    return {**closure, "digest": canonical_digest(closure)}


def _broker_config() -> RuntimeActionBrokerConfig:
    broker = systemd_probe._user("aragorn-broker")  # noqa: SLF001
    runtime = systemd_probe._user("aragorn-runtime")  # noqa: SLF001
    sensor = systemd_probe._user("aragorn-sensor")  # noqa: SLF001
    runtime_gid = systemd_probe._group("aragorn-runtime").gr_gid  # noqa: SLF001
    sensor_gid = systemd_probe._group("aragorn-sensor").gr_gid  # noqa: SLF001
    return RuntimeActionBrokerConfig(
        socket_path=_BACKEND,
        instance_lock_path=_CONTROL / "broker.instance.lock",
        lock_path=_CONTROL / "broker.lock",
        control_root=_CONTROL,
        protected_root=_PROTECTED,
        staging_root=_STAGING,
        policy_path=_CONTROL / "policy.json",
        revocations_path=_CONTROL / "revocations.json",
        health_path=_CONTROL / "health.json",
        observation_path=_CONTROL / "observation.json",
        state_path=_CONTROL / "state.json",
        expected_broker_uid=broker.pw_uid,
        expected_peer_uid=sensor.pw_uid,
        expected_peer_gid=sensor_gid,
        expected_runtime_digest=_RUNTIME_DIGEST,
        expected_runtime_uid=runtime.pw_uid,
        expected_runtime_gid=runtime_gid,
    )


def _publish_status(status: str) -> dict[str, Any]:
    _expect(status in {"healthy", "unhealthy"}, "control status is invalid")
    config = _broker_config()
    for attempt in range(1, 4):
        current_health = json.loads(config.health_path.read_bytes())
        current_revocations = json.loads(config.revocations_path.read_bytes())
        now = int(time.time())
        revocations = {
            **current_revocations,
            "generation": current_revocations["generation"] + 1,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        }
        health = {
            **current_health,
            "epoch": current_health["epoch"] + 1,
            "status": status,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        }
        try:
            publish_runtime_control_document(
                config.revocations_path, revocations, config
            )
            publish_runtime_control_document(config.health_path, health, config)
        except RuntimeActionBrokerError:
            if attempt == 3:
                raise
            time.sleep(0.01)
            continue
        return {
            "attempt": attempt,
            "process": systemd_probe._identity(),  # noqa: SLF001
            "revocations": revocations,
            "health": health,
        }
    raise AssertionError("unreachable")


def _direct_write(path: Path) -> dict[str, Any]:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        result = {
            "blocked": True,
            "errno": exc.errno,
            "error": errno.errorcode.get(exc.errno, "UNKNOWN"),
        }
    else:
        os.close(descriptor)
        result = {"blocked": False, "errno": None, "error": None}
    return {  # noqa: SLF001
        "path": str(path),
        "process": systemd_probe._identity(),
        "result": result,
    }


def _run_python_as(
    uid: int,
    gid: int,
    groups: list[int],
    arguments: list[str],
) -> dict[str, Any]:
    group_option = (
        ["--clear-groups"]
        if not groups
        else [f"--groups={','.join(map(str, groups))}"]
    )
    result = subprocess.run(
        [
            "setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            *group_option,
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).resolve()),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise ProbeError(result.stderr.decode(errors="replace").strip())
    document = json.loads(result.stdout)
    _expect(canonical_json(document) + b"\n" == result.stdout, "subprocess output changed")
    return document


def _plugin_artifacts() -> tuple[list[dict[str, Any]], str]:
    records = []
    identity = []
    for name in ("index.js", "openclaw.plugin.json", "package.json"):
        source = Path("/src/packaging/openclaw/aragorn-runtime-action") / name
        installed = _PLUGIN / name
        source_file = systemd_probe._file(source)  # noqa: SLF001
        installed_file = systemd_probe._file(installed)  # noqa: SLF001
        _expect(
            source_file["digest"] == installed_file["digest"]
            and source_file["bytes"] == installed_file["bytes"]
            and installed_file["stat"]["uid"] == 0
            and installed_file["stat"]["gid"] == 0
            and not (int(installed_file["stat"]["mode"], 8) & 0o222),
            f"installed OpenClaw plugin changed: {name}",
        )
        records.append(
            {
                "source_path": str(source),
                "installed_path": str(installed),
                "source_digest": source_file["digest"],
                "installed_digest": installed_file["digest"],
                "bytes": source_file["bytes"],
                "installed_stat": installed_file["stat"],
            }
        )
        identity.append(
            {
                "digest": installed_file["digest"],
                "executable": bool(int(installed_file["stat"]["mode"], 8) & 0o111),
                "kind": "file",
                "links": installed_file["stat"]["nlink"],
                "path": name,
                "size": installed_file["bytes"],
            }
        )
    return records, canonical_digest(identity)


def _harness() -> dict[str, Any]:
    retained = systemd_probe._document(_HARNESS)  # noqa: SLF001
    document = retained["document"]
    _expect(
        document.get("schema")
        == "aragorn/runtime-action-openclaw-systemd-harness/v1"
        and isinstance(document.get("container_id"), str)
        and document["container_id"].startswith(platform.node())
        and document.get("image_reference") == "aragorn-p33c-openclaw-systemd"
        and document.get("platform") == "linux"
        and document.get("profile_label") == "p3.3c"
        and isinstance(document.get("image_id"), str)
        and document["image_id"].startswith("sha256:")
        and isinstance(document.get("systemd_base_image_id"), str)
        and document["systemd_base_image_id"].startswith("sha256:")
        and document.get("node_image")
        == {
            "architecture": "arm64",
            "id": "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf",
            "os": "linux",
            "reference": "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf",
            "variant": "v8",
        }
        and document.get("openclaw_runtime_volume")
        == "aragorn-openclaw-2026-7-1-runtime"
        and document.get("openclaw_runtime_mount")
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
        "outer P3.3c harness descriptor changed",
    )
    host = document.get("host_config")
    _expect(
        isinstance(host, dict)
        and host.get("binds")
        == [
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
        ]
        and host.get("cgroupns_mode") == "host"
        and host.get("ipc_mode") == "private"
        and host.get("network_mode") == "none"
        and host.get("privileged") is True
        and host.get("readonly_rootfs") is False
        and host.get("runtime") == "runc"
        and host.get("security_opt") == ["label=disable"]
        and host.get("tmpfs")
        == {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        }
        and host.get("userns_mode") == "",
        "outer P3.3c host profile changed",
    )
    return retained


def _write_config(path: Path, document: object, gid: int) -> None:
    raw = canonical_json(document) + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o440,
    )
    try:
        write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(path, 0, gid)


def _openclaw_config(
    scenario_id: str,
    policy: dict[str, Any],
    plugin_digest: str,
    identities: dict[str, int],
) -> tuple[Path, dict[str, Any]]:
    scenario = _SCENARIOS[scenario_id]
    root = Path("/run") / f"aragorn-openclaw-{scenario_id}"
    root.mkdir(mode=0o700)
    os.chown(root, identities["runtime_uid"], identities["runtime_gid"])
    config = {
        "schema": "aragorn/openclaw-runtime-action-systemd-probe-input/v1",
        "scenario": {"id": scenario_id, **scenario},
        "profile_root": str(root),
        "skill": {
            "name": _SKILL_NAME,
            "content": _SKILL.decode(),
            "digest": _SKILL_DIGEST,
        },
        "runtime": {
            "entrypoint": str(_OPENCLAW),
            "expected_tree_digest": _RUNTIME_DIGEST,
            "expected_version": "OpenClaw 2026.7.1 (2d2ddc4)",
        },
        "plugin": {
            "path": str(_PLUGIN),
            "digest": plugin_digest,
            "config": {
                "activeSkillDigest": _SKILL_DIGEST,
                "expectedBrokerUid": identities["broker_uid"],
                "expectedRuntimeGid": identities["runtime_gid"],
                "expectedRuntimeUid": identities["runtime_uid"],
                "expectedSensorUid": identities["sensor_uid"],
                "policyDigest": canonical_digest(policy),
                "policyVersion": policy["version"],
                "protectedRoot": str(_PROTECTED),
                "runtimeDigest": _RUNTIME_DIGEST,
                "sensorSocketPath": str(_FRONTEND),
            },
        },
    }
    path = Path("/run") / f"aragorn-openclaw-{scenario_id}.json"
    _write_config(path, config, identities["runtime_gid"])
    return path, config


def _run_openclaw(
    scenario_id: str,
    policy: dict[str, Any],
    plugin_digest: str,
    identities: dict[str, int],
    control_status: str | None,
) -> dict[str, Any]:
    path, config = _openclaw_config(
        scenario_id, policy, plugin_digest, identities
    )
    command = [
        "setpriv",
        f"--reuid={identities['runtime_uid']}",
        f"--regid={identities['runtime_gid']}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "/usr/local/bin/node",
        str(_MJS_PROBE),
        str(path),
    ]
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    refreshes = []
    if control_status is not None:
        refreshes.append(
            _run_python_as(
                identities["broker_uid"],
                identities["runtime_gid"],
                [identities["sensor_gid"]],
                ["publish-status", control_status],
            )
        )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "OPENCLAW_GATEWAY_TOKEN": "aragorn-p33c-gateway-token-v1",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
    )
    deadline = time.monotonic() + 90
    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=3)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    raise ProbeError(f"OpenClaw {scenario_id} probe timed out")
                if control_status is not None:
                    refreshes.append(
                        _run_python_as(
                            identities["broker_uid"],
                            identities["runtime_gid"],
                            [identities["sensor_gid"]],
                            ["publish-status", control_status],
                        )
                    )
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise
    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if process.returncode != 0:
        detail = stdout.decode(errors="replace")[-2000:]
        try:
            failed = json.loads(stdout)
            proof = failed["scenario"]["proof"]
            detail = canonical_json(
                {
                    "failed_checks": sorted(
                        name for name, passed in proof["checks"].items() if not passed
                    ),
                    "target_after": failed["turn"]["target_after"],
                    "tool_result": proof["tool_result"],
                }
            ).decode("ascii")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass
        raise ProbeError(
            f"OpenClaw {scenario_id} probe failed ({process.returncode}): "
            f"{stderr.decode(errors='replace').strip()} "
            f"{detail}"
        )
    document = json.loads(stdout)
    _expect(
        canonical_json(document) + b"\n" == stdout,
        f"OpenClaw {scenario_id} output was not canonical",
    )
    return {
        "config": config,
        "config_digest": canonical_digest(config),
        "command": command,
        "started_at": started_at,
        "completed_at": completed_at,
        "exit_code": process.returncode,
        "stdout_bytes": len(stdout),
        "stdout_digest": "sha256:" + hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_digest": "sha256:" + hashlib.sha256(stderr).hexdigest(),
        "control_refreshes": refreshes,
        "evidence": document,
    }


def _controls() -> dict[str, Any]:
    return {
        name: systemd_probe._document(_CONTROL / f"{name}.json")  # noqa: SLF001
        for name in ("health", "observation", "policy", "revocations", "state")
    }


def _collect() -> dict[str, Any]:
    _expect(
        sys.platform == "linux"
        and os.geteuid() == 0
        and Path("/proc/1/comm").read_text().strip() == "systemd",
        "the collector requires root in the fixed systemd container",
    )
    harness = _harness()
    broker = systemd_probe._user("aragorn-broker")  # noqa: SLF001
    runtime = systemd_probe._user("aragorn-runtime")  # noqa: SLF001
    sensor = systemd_probe._user("aragorn-sensor")  # noqa: SLF001
    runtime_gid = systemd_probe._group("aragorn-runtime").gr_gid  # noqa: SLF001
    sensor_gid = systemd_probe._group("aragorn-sensor").gr_gid  # noqa: SLF001
    identities = {
        "broker_uid": broker.pw_uid,
        "broker_gid": broker.pw_gid,
        "runtime_uid": runtime.pw_uid,
        "runtime_gid": runtime_gid,
        "sensor_uid": sensor.pw_uid,
        "sensor_gid": sensor_gid,
    }
    _expect(
        len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) == 3,
        "service UIDs overlap",
    )
    plugin_artifacts, plugin_digest = _plugin_artifacts()
    sensor_implementation = _sensor_implementation()
    sensor_digest = sensor_implementation["digest"]

    systemd_probe._systemctl("stop", _SENSOR_UNIT, _BROKER_UNIT, check=False)  # noqa: SLF001
    for directory in (_PROTECTED, _STAGING):
        for child in directory.iterdir():
            child.unlink()
    for name in ("health", "observation", "policy", "revocations", "state"):
        (_CONTROL / f"{name}.json").unlink(missing_ok=True)
    systemd_probe._run(  # noqa: SLF001
        ["systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"]
    )

    payloads = {
        name: (value["target_name"], value["content"].encode())
        for name, value in _SCENARIOS.items()
    }
    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        actions = {
            name: _action_digests(protected_fd, target, payload)
            for name, (target, payload) in payloads.items()
        }
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-3c-pinned-openclaw-composition",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": sensor_digest,
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": sorted(
            (
                {
                    "runtime_digest": _RUNTIME_DIGEST,
                    "active_skill_digest": _SKILL_DIGEST,
                    **actions[name],
                }
                for name in _SCENARIOS
            ),
            key=canonical_json,
        ),
    }
    seed = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "seed-p3-3c",
        "run_id": "seed-p3-3c",
        "tool_call_id": "seed-p3-3c",
        "active_skill_digest": _SKILL_DIGEST,
    }
    now = int(time.time())
    initial_controls = {
        "policy": policy,
        "revocations": {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 1,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        },
        "health": {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": sensor_digest,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        },
        "observation": {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": sensor_digest,
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": {"schema": "aragorn/runtime-active-context/v1", **seed},
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **seed,
                **actions["allow"],
            },
        },
        "state": {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
        },
    }
    for name, document in initial_controls.items():
        systemd_probe._write_control(  # noqa: SLF001
            _CONTROL / f"{name}.json", document, broker.pw_uid, runtime_gid
        )
    etc = Path("/etc/aragorn")
    etc.mkdir(mode=0o755, exist_ok=True)
    systemd_probe._write_control(  # noqa: SLF001
        etc / "runtime-action-runtime.json",
        {"schema": "aragorn/runtime-action-runtime-binding/v1", "runtime_digest": _RUNTIME_DIGEST},
        0,
        0,
    )
    systemd_probe._write_control(  # noqa: SLF001
        etc / "runtime-action-observation.json",
        {
            "schema": "aragorn/runtime-observation-binding/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "active_skill_digest": _SKILL_DIGEST,
            "sensor_digest": sensor_digest,
        },
        0,
        0,
    )

    verification = systemd_probe._run(  # noqa: SLF001
        [
            "systemd-analyze",
            "verify",
            "/usr/lib/systemd/system/aragorn-runtime-action-broker.service",
            "/usr/lib/systemd/system/aragorn-runtime-observation-publisher.service",
        ]
    )
    systemd_probe._systemctl("daemon-reload")  # noqa: SLF001
    systemd_probe._systemctl("start", _SENSOR_UNIT)  # noqa: SLF001
    systemd_probe._wait_path(_FRONTEND)  # noqa: SLF001
    systemd_probe._wait_path(_BACKEND)  # noqa: SLF001
    broker_unit = systemd_probe._unit(_BROKER_UNIT)  # noqa: SLF001
    sensor_unit = systemd_probe._unit(_SENSOR_UNIT)  # noqa: SLF001
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    deployment = {
        "units": {"broker": broker_unit, "sensor": sensor_unit},
        "processes": {
            "broker": systemd_probe._process(broker_pid),  # noqa: SLF001
            "sensor": systemd_probe._process(sensor_pid),  # noqa: SLF001
        },
        "directories": {
            "root": systemd_probe._metadata(_ROOT),  # noqa: SLF001
            "control": systemd_probe._metadata(_CONTROL),  # noqa: SLF001
            "protected": systemd_probe._metadata(_PROTECTED),  # noqa: SLF001
            "staging": systemd_probe._metadata(_STAGING),  # noqa: SLF001
            "runtime": systemd_probe._metadata(_FRONTEND.parent),  # noqa: SLF001
        },
        "sockets": {
            "backend": systemd_probe._metadata(_BACKEND),  # noqa: SLF001
            "frontend": systemd_probe._metadata(_FRONTEND),  # noqa: SLF001
        },
        "mounts": {
            "broker_root": systemd_probe._mount(broker_pid, "/"),  # noqa: SLF001
            "broker_action_root": systemd_probe._mount(broker_pid, str(_ROOT)),  # noqa: SLF001
            "broker_credentials": systemd_probe._mount(  # noqa: SLF001
                broker_pid, f"/run/credentials/{_BROKER_UNIT}"
            ),
            "sensor_root": systemd_probe._mount(sensor_pid, "/"),  # noqa: SLF001
            "sensor_runtime": systemd_probe._mount(  # noqa: SLF001
                sensor_pid, str(_FRONTEND.parent)
            ),
            "sensor_staging": systemd_probe._mount(  # noqa: SLF001
                sensor_pid, str(_STAGING)
            ),
            "sensor_credentials": systemd_probe._mount(  # noqa: SLF001
                sensor_pid, f"/run/credentials/{_SENSOR_UNIT}"
            ),
        },
        "targets_before": sorted(item.name for item in _PROTECTED.iterdir()),
    }
    controls_before = systemd_probe._control_snapshot()  # noqa: SLF001
    trace_root = Path("/tmp/aragorn-p3-3c-trace")
    trace_root.mkdir(mode=0o700, exist_ok=True)
    sensor_trace_path = trace_root / "sensor.trace"
    broker_trace_path = trace_root / "broker.trace"
    sensor_trace_path.unlink(missing_ok=True)
    broker_trace_path.unlink(missing_ok=True)
    sensor_tracer = systemd_probe._start_trace(sensor_pid, sensor_trace_path)  # noqa: SLF001
    broker_tracer = systemd_probe._start_trace(broker_pid, broker_trace_path)  # noqa: SLF001
    traces_finished = False
    try:
        attacker_uid = max(broker.pw_uid, runtime.pw_uid, sensor.pw_uid) + 1000
        sample = {
            "schema": "aragorn/runtime-action-broker-request/v1",
            "request": {
                "schema": "aragorn/runtime-action-request/v1",
                "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
                **seed,
                **actions["allow"],
                "policy_digest": canonical_digest(policy),
                "policy_version": 1,
                "issued_at_unix": now,
                "expires_at_unix": now + 5,
            },
            "effect": {
                "schema": "aragorn/runtime-create-file/v1",
                "operation": "create",
                "target_name": payloads["allow"][0],
                "payload_base64": "",
            },
        }
        raw_sample = canonical_json(sample)
        direct_backend = systemd_probe._run_as(  # noqa: SLF001
            runtime.pw_uid,
            runtime_gid,
            [],
            ["client", str(_BACKEND)],
            input_bytes=raw_sample,
        )
        wrong_backend = systemd_probe._run_as(  # noqa: SLF001
            attacker_uid,
            sensor_gid,
            [runtime_gid],
            ["client", str(_BACKEND)],
            input_bytes=raw_sample,
        )
        wrong_frontend = systemd_probe._run_as(  # noqa: SLF001
            attacker_uid,
            runtime_gid,
            [],
            ["client", str(_FRONTEND)],
            input_bytes=raw_sample,
        )
        direct_write = _run_python_as(
            runtime.pw_uid,
            runtime_gid,
            [],
            ["direct-write", str(_PROTECTED / "runtime-bypass.txt")],
        )
        controls_after_denials = systemd_probe._control_snapshot()  # noqa: SLF001

        allowed = _run_openclaw(
            "allow", policy, plugin_digest, identities, "healthy"
        )
        allowed_target = systemd_probe._file(  # noqa: SLF001
            _PROTECTED / payloads["allow"][0]
        )
        controls_after_allow = _controls()
        unhealthy = _run_openclaw(
            "unhealthy", policy, plugin_digest, identities, "unhealthy"
        )
        controls_after_unhealthy = _controls()
        sensor_trace = systemd_probe._trace(  # noqa: SLF001
            sensor_tracer,
            sensor_trace_path,
            sensor_pid,
            ["accept", "accept", "connect", "accept", "connect"],
        )
        broker_trace = systemd_probe._trace(  # noqa: SLF001
            broker_tracer,
            broker_trace_path,
            broker_pid,
            ["accept", "accept", "accept"],
        )
        traces_finished = True

        controls_before_sensor_stop = systemd_probe._control_snapshot()  # noqa: SLF001
        systemd_probe._systemctl("stop", _SENSOR_UNIT)  # noqa: SLF001
        _FRONTEND.parent.mkdir(mode=0o750, exist_ok=True)
        os.chown(_FRONTEND.parent, sensor.pw_uid, runtime_gid)
        os.chmod(_FRONTEND.parent, 0o750)
        sensor_down_runtime_directory = systemd_probe._metadata(  # noqa: SLF001
            _FRONTEND.parent
        )
        sensor_unavailable = _run_openclaw(
            "sensor_unavailable", policy, plugin_digest, identities, None
        )
        controls_after_sensor_stop = systemd_probe._control_snapshot()  # noqa: SLF001
        final_entries = sorted(item.name for item in _PROTECTED.iterdir())

        _expect(
            controls_before == controls_after_denials
            and direct_backend.get("outcome") == "CONNECT_ERROR"
            and direct_backend.get("errno") == errno.EACCES
            and wrong_backend.get("outcome") == "PEER_CLOSED"
            and wrong_frontend.get("outcome") == "PEER_CLOSED"
            and direct_write["result"]
            == {"blocked": True, "errno": errno.EACCES, "error": "EACCES"},
            "same-capture peer or direct-write isolation failed",
        )
        allow_state = controls_after_allow["state"]["document"]
        unhealthy_state = controls_after_unhealthy["state"]["document"]
        allow_result = allowed["evidence"]["scenario"]["proof"][
            "retained_tool_result"
        ]["result"]
        unhealthy_result = unhealthy["evidence"]["scenario"]["proof"][
            "retained_tool_result"
        ]["result"]
        allow_consumed = {
            (item["request_digest"], item["observation_digest"])
            for item in allow_state["consumed"]
        }
        unhealthy_consumed = {
            (item["request_digest"], item["observation_digest"])
            for item in unhealthy_state["consumed"]
        }
        allow_pair = (
            allow_result["request_digest"],
            allow_result["observation_digest"],
        )
        unhealthy_pair = (
            unhealthy_result["request_digest"],
            unhealthy_result["observation_digest"],
        )
        _expect(
            allowed["control_refreshes"]
            and allowed["control_refreshes"][-1]["health"]["status"] == "healthy"
            and allowed_target["digest"] == actions["allow"]["payload_digest"]
            and allowed_target["stat"]["uid"] == broker.pw_uid
            and allowed_target["stat"]["gid"] == runtime_gid
            and allowed_target["stat"]["mode"] == "0400"
            and allowed_target["stat"]["nlink"] == 1
            and allow_consumed == {allow_pair}
            and allow_state["effect_journal"] is None,
            "real OpenClaw allowed effect or state changed",
        )
        _expect(
            unhealthy["control_refreshes"]
            and unhealthy["control_refreshes"][-1]["health"]["status"]
            == "unhealthy"
            and unhealthy_pair in unhealthy_consumed
            and unhealthy_consumed <= {allow_pair, unhealthy_pair}
            and unhealthy_state["effect_journal"] is None
            and not (_PROTECTED / payloads["unhealthy"][0]).exists(),
            "real OpenClaw unhealthy case did not block",
        )
        _expect(
            controls_before_sensor_stop == controls_after_sensor_stop
            and not (_PROTECTED / payloads["sensor_unavailable"][0]).exists()
            and final_entries == [payloads["allow"][0]]
            and not _FRONTEND.exists(),
            "real OpenClaw sensor-unavailable case did not fail closed",
        )
        allow_gateway_pid = allowed["evidence"]["gateway"]["process_before"]["pid"]
        unhealthy_gateway_pid = unhealthy["evidence"]["gateway"]["process_before"]["pid"]
        _expect(
            broker_trace["peer_credentials"]
            == [
                {
                    "pid": wrong_backend["client"]["pid"],
                    "uid": attacker_uid,
                    "gid": sensor_gid,
                },
                {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid},
                {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid},
            ]
            and sensor_trace["peer_credentials"]
            == [
                {
                    "pid": wrong_frontend["client"]["pid"],
                    "uid": attacker_uid,
                    "gid": runtime_gid,
                },
                {
                    "pid": allow_gateway_pid,
                    "uid": runtime.pw_uid,
                    "gid": runtime_gid,
                },
                {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
                {
                    "pid": unhealthy_gateway_pid,
                    "uid": runtime.pw_uid,
                    "gid": runtime_gid,
                },
                {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
            ],
            "same-capture SO_PEERCRED chain changed",
        )

        artifacts = plugin_artifacts
        for source, installed in sorted(systemd_probe._ARTIFACTS.items()):  # noqa: SLF001
            source_file = systemd_probe._file(Path(source))  # noqa: SLF001
            installed_file = systemd_probe._file(Path(installed))  # noqa: SLF001
            _expect(
                source_file["digest"] == installed_file["digest"]
                and source_file["bytes"] == installed_file["bytes"],
                f"installed substrate artifact changed: {installed}",
            )
            artifacts.append(
                {
                    "source_path": source,
                    "installed_path": installed,
                    "source_digest": source_file["digest"],
                    "installed_digest": installed_file["digest"],
                    "bytes": source_file["bytes"],
                    "installed_stat": installed_file["stat"],
                }
            )

        return {
            "schema": "aragorn/runtime-action-openclaw-systemd-composition-evidence/v1",
            "authority": _AUTHORITY,
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "limitations": _LIMITATIONS,
            "decision": {
                "status": "P3_3C_OBSERVED",
                "bounded_systemd_profile_observed": True,
                "pinned_openclaw_composition_observed": True,
                "run_01_eligible": False,
                "run_02_eligible": False,
                "phase3_exit_eligible": False,
                "edr_claim_eligible": False,
                "public_release_eligible": False,
            },
            "environment": {
                "platform": sys.platform,
                "architecture": platform.machine(),
                "kernel_release": platform.release(),
                "python": platform.python_version(),
                "node": subprocess.run(
                    ["/usr/local/bin/node", "--version"],
                    stdout=subprocess.PIPE,
                    check=True,
                    timeout=5,
                ).stdout.decode().strip(),
                "node_binary": systemd_probe._file(  # noqa: SLF001
                    Path("/usr/local/bin/node")
                ),
                "systemd": systemd_probe._run(  # noqa: SLF001
                    ["systemd", "--version"]
                ).stdout.decode().splitlines()[0],
                "strace": systemd_probe._run(  # noqa: SLF001
                    ["strace", "--version"]
                ).stdout.decode().splitlines()[0],
                "container_id": platform.node(),
                "capture_identity": systemd_probe._identity(),  # noqa: SLF001
                "pid1_mount_namespace": os.readlink("/proc/1/ns/mnt"),
                "pid1_network_namespace": os.readlink("/proc/1/ns/net"),
                "systemd_verify": {
                    "exit_code": verification.returncode,
                    "stdout": verification.stdout.decode(),
                    "stderr": verification.stderr.decode(),
                },
            },
            "harness": harness,
            "artifacts": artifacts,
            "collector": {
                "probe": systemd_probe._file(Path(__file__).resolve()),  # noqa: SLF001
                "openclaw_probe": systemd_probe._file(_MJS_PROBE),  # noqa: SLF001
                "dockerfile": systemd_probe._file(  # noqa: SLF001
                    Path("/src/benchmark/runtime-action-openclaw-systemd/Dockerfile")
                ),
                "dockerignore": systemd_probe._file(Path("/src/.dockerignore")),  # noqa: SLF001
                "recipe": systemd_probe._file(  # noqa: SLF001
                    Path("/src/scripts/capture_runtime_action_openclaw_systemd.sh")
                ),
            },
            "identities": {**identities, "attacker_uid": attacker_uid},
            "deployment": deployment,
            "peer_trace": {"broker": broker_trace, "sensor": sensor_trace},
            "inputs": {
                "runtime_digest": _RUNTIME_DIGEST,
                "active_skill_digest": _SKILL_DIGEST,
                "sensor_digest": sensor_digest,
                "sensor_implementation": sensor_implementation,
                "plugin_digest": plugin_digest,
                "initial_controls": initial_controls,
                "policy": policy,
                "actions": actions,
            },
            "scenarios": {
                "runtime_direct_backend": {
                    "status": "PASS",
                    "client": direct_backend,
                    "control_before": controls_before,
                    "control_after": controls_after_denials,
                },
                "wrong_backend_uid": {
                    "status": "PASS",
                    "client": wrong_backend,
                    "control_before": controls_before,
                    "control_after": controls_after_denials,
                },
                "wrong_frontend_uid": {
                    "status": "PASS",
                    "client": wrong_frontend,
                    "control_before": controls_before,
                    "control_after": controls_after_denials,
                },
                "runtime_direct_write": {
                    "status": "PASS",
                    "control_before": controls_before,
                    "control_after": controls_after_denials,
                    **direct_write,
                },
                "openclaw_allowed_create": {
                    "status": "PASS",
                    "openclaw": allowed,
                    "target": allowed_target,
                    "control_after": controls_after_allow,
                },
                "openclaw_unhealthy_block": {
                    "status": "PASS",
                    "openclaw": unhealthy,
                    "target_exists": False,
                    "control_after": controls_after_unhealthy,
                },
                "openclaw_sensor_unavailable": {
                    "status": "PASS",
                    "openclaw": sensor_unavailable,
                    "target_exists": False,
                    "frontend_exists": False,
                    "runtime_directory": sensor_down_runtime_directory,
                    "control_before": controls_before_sensor_stop,
                    "control_after": controls_after_sensor_stop,
                    "units": {
                        "broker": systemd_probe._unit(_BROKER_UNIT),  # noqa: SLF001
                        "sensor": systemd_probe._unit(_SENSOR_UNIT),  # noqa: SLF001
                    },
                },
            },
        }
    finally:
        if not traces_finished:
            for tracer in (sensor_tracer, broker_tracer):
                if tracer.poll() is None:
                    tracer.send_signal(signal.SIGINT)
                    try:
                        tracer.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        tracer.kill()
        systemd_probe._systemctl("stop", _SENSOR_UNIT, _BROKER_UNIT, check=False)  # noqa: SLF001


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: Path | None = None
    if len(arguments) == 2 and arguments[0] == "publish-status":
        result = _publish_status(arguments[1])
    elif len(arguments) == 2 and arguments[0] == "direct-write":
        result = _direct_write(Path(arguments[1]))
    elif len(arguments) == 2 and arguments[0] == "--output":
        output_path = Path(arguments[1])
        result = _collect()
    elif not arguments:
        result = _collect()
    else:
        print("usage: runtime_action_openclaw_systemd_probe.py [--output PATH]", file=sys.stderr)
        return 64
    raw = canonical_json(result) + b"\n"
    if output_path is None:
        sys.stdout.buffer.write(raw)
    else:
        descriptor = os.open(
            output_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
