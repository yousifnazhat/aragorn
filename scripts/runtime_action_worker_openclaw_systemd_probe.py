#!/usr/bin/env python3
"""Produce one bounded distinct-gateway/runtime-worker systemd observation."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_producer_lineage_openclaw_systemd_probe as prior

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    parse_runtime_capability_grant,
)
from aragorn.runtime_process_profile import (
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    runtime_process_profile,
)

lineage = prior.lineage
capability = lineage.capability
openclaw = lineage.openclaw
profile_systemd = lineage.profile_systemd
systemd_probe = profile_systemd.prior

_HARNESS = Path("/run/aragorn-harness.json")
_DRIVER = Path(
    "/src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
)
_DRIVER_ROOT = Path("/run/aragorn-p37b-driver")
_GATEWAY_UNIT = "aragorn-agent-gateway.service"
_WORKER_UNIT = "aragorn-runtime-action-worker.service"
_BROKER_UNIT = lineage._BROKER_UNIT
_SENSOR_UNIT = lineage._SENSOR_UNIT
_UNIT_OBJECTS = {
    **systemd_probe._UNIT_OBJECTS,
    _GATEWAY_UNIT: (
        "/org/freedesktop/systemd1/unit/aragorn_2dagent_2dgateway_2eservice"
    ),
    _WORKER_UNIT: (
        "/org/freedesktop/systemd1/unit/aragorn_2druntime_2daction_2dworker_2eservice"
    ),
    _BROKER_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dlineage_2dcapability_2daction_2dbroker_2eservice"
    ),
    _SENSOR_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dlineage_2dcapability_2dobservation_2dpublisher_2eservice"
    ),
}
_WORKER_SOCKET = Path("/run/aragorn-runtime-action-worker/worker.sock")
_PARKED_WORKER_SOCKET = _WORKER_SOCKET.with_name(".worker.sock.p37b-parked")
_SENSOR_SOCKET = lineage._FRONTEND
_BROKER_SOCKET = lineage._BACKEND
_WORKER_BINDING = Path("/etc/aragorn/runtime-action-worker.json")
_RUNTIME_BINDING = lineage._RUNTIME_BINDING
_OBSERVATION_BINDING = lineage._OBSERVATION_BINDING
_GRANT_SOURCE = lineage._GRANT_SOURCE
_GATEWAY_CONFIG = Path("/etc/aragorn/agent-gateway/openclaw.json")
_GATEWAY_ENVIRONMENT = Path("/etc/aragorn/agent-gateway/environment")
_GATEWAY_ROOT = Path("/var/lib/aragorn-agent-gateway")
_GATEWAY_HOME = _GATEWAY_ROOT / "home"
_GATEWAY_STATE = _GATEWAY_ROOT / "state"
_GATEWAY_WORKSPACE = _GATEWAY_ROOT / "workspace"
_PLUGIN = Path("/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker")
_NODE = Path("/usr/local/bin/node")
_PYTHON = Path("/usr/bin/python3.12")
_TARGET = "runtime-worker-qualified.txt"
_PAYLOAD = b"Aragorn P3.7b distinct worker create\n"
_MAX_TRACE_BYTES = 64 * 1024
_PARENT_IMAGE = (
    "sha256:e0992ea8995a7ce1f537d6372cb78febab8761edbcbfc06e07b6c096c65ca16f"
)
_AUTHORITY = (
    "BOUNDED_DISTINCT_GATEWAY_RUNTIME_WORKER_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RETAINED_EVIDENCE_OR_RUN_EDR_RELEASE_AUTHORITY"
)
_STAGE = "BOOTSTRAP"
_LIMITATIONS = [
    "ONE_RETAINED_CAS_SINGLE_FILE_SKILL_AND_ONE_OPENCLAW_CREATE_ONLY",
    "LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_NOT_HOST_ATTESTATION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "GATEWAY_ENDPOINT_METADATA_IS_PRINCIPAL_NOT_EXACT_PROCESS_IDENTITY",
    "WORKER_PROFILE_IS_POINT_IN_TIME_KERNEL_MEASUREMENT_NOT_CONTINUOUS_ATTESTATION",
    "SKILL_PROMPT_PROJECTION_MATCHES_BYTES_BUT_NOT_SEMANTIC_CAUSATION",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_EXTERNAL_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "VERIFIER_NOT_IMPLEMENTED",
    "RETAINED_EVIDENCE_NOT_PRODUCED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_NEW_ARTIFACTS = {
    "/src/src/aragorn/runtime_action_worker.py": (
        "/usr/lib/aragorn/aragorn/runtime_action_worker.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-worker-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py"
    ),
    "/src/packaging/systemd/aragorn-agent-gateway.service": (
        "/usr/lib/systemd/system/aragorn-agent-gateway.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-worker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-action-worker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-worker.sysusers": (
        "/usr/lib/sysusers.d/aragorn-runtime-action-worker.conf"
    ),
    **{
        f"/src/packaging/openclaw/aragorn-runtime-action-worker/{name}": (
            f"/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/{name}"
        )
        for name in ("index.js", "openclaw.plugin.json", "package.json")
    },
}

_expect = lineage._expect
_run = lineage._run
_systemctl = lineage._systemctl
_user = lineage._user
_group = lineage._group
_metadata = lineage._metadata
_file = lineage._file
_document = lineage._document
_process = lineage._process
_security_status = lineage._security_status

_DRIVER_FORBIDDEN_FIELDS = frozenset(
    {
        "active_context_digest",
        "active_skill_digest",
        "decision",
        "grant",
        "grant_digest",
        "grant_id",
        "health",
        "install_context_digest",
        "lease",
        "measured_action_digest",
        "observation_digest",
        "operation_digest",
        "path_digest",
        "payload_digest",
        "policy",
        "policy_digest",
        "policy_version",
        "revocation_source_digest",
        "revocations",
        "runtime_attribution",
        "runtime_digest",
        "runtime_profile_digest",
        "sensor_digest",
        "skill_digest",
        "source_manifest_digest",
    }
)


def _byte_identity(raw: bytes) -> dict[str, Any]:
    return {
        "bytes": len(raw),
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def _set_stage(stage: str) -> None:
    global _STAGE
    _STAGE = stage


def _forbidden_driver_fields(value: object, path: str = "$") -> list[str]:
    matches = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in _DRIVER_FORBIDDEN_FIELDS:
                matches.append(child_path)
            matches.extend(_forbidden_driver_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(_forbidden_driver_fields(child, f"{path}[{index}]"))
    return matches


def _digest_values(value: object) -> set[str]:
    values = set()
    if isinstance(value, dict):
        for child in value.values():
            values.update(_digest_values(child))
    elif isinstance(value, list):
        for child in value:
            values.update(_digest_values(child))
    elif isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        values.add(value)
    return values


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    expected_fields = {
        "schema",
        "capture_disposition",
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
    }
    _expect(
        isinstance(document, dict)
        and set(document) == expected_fields
        and document["schema"]
        == "aragorn/runtime-action-worker-openclaw-systemd-harness/v1"
        and document["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"]
        == "aragorn-p37b-runtime-action-worker-openclaw-systemd"
        and document["run_image_reference"] == document["image_id"]
        and document["parent_image_id"] == _PARENT_IMAGE
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.7b",
        "outer P3.7b harness identity changed",
    )
    image_lineage = document["image_lineage"]
    _expect(
        isinstance(image_lineage, dict)
        and image_lineage["parent"]["id"] == _PARENT_IMAGE
        and image_lineage["child"]["id"] == document["image_id"]
        and image_lineage["child"]["layers"][: len(image_lineage["parent"]["layers"])]
        == image_lineage["parent"]["layers"]
        and image_lineage["added_layers"]
        == image_lineage["child"]["layers"][len(image_lineage["parent"]["layers"]) :]
        and bool(image_lineage["added_layers"]),
        "P3.7b image lineage changed",
    )
    return retained


def _stop_stack() -> None:
    _systemctl(
        "stop",
        _GATEWAY_UNIT,
        _WORKER_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        check=False,
    )


def _reset_action_plane() -> None:
    _stop_stack()
    _systemctl(
        "reset-failed",
        _GATEWAY_UNIT,
        _WORKER_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        check=False,
    )
    capability._reset()
    for path in (
        _WORKER_BINDING,
        _GATEWAY_CONFIG,
        _GATEWAY_ENVIRONMENT,
    ):
        path.unlink(missing_ok=True)
    if _GATEWAY_ROOT.exists():
        shutil.rmtree(_GATEWAY_ROOT)
    if _GATEWAY_CONFIG.parent.exists():
        shutil.rmtree(_GATEWAY_CONFIG.parent)
    if _DRIVER_ROOT.exists():
        shutil.rmtree(_DRIVER_ROOT)


def _clear_action_state() -> None:
    _stop_stack()
    lock_paths = sorted(lineage._CONTROL.glob("*.lock"))
    _expect(
        [path.name for path in lock_paths] == ["broker.instance.lock", "broker.lock"],
        "runtime action lock fixture changed",
    )
    lock_identity = {path.name: _file(path) for path in lock_paths}
    for directory in (lineage._PROTECTED, lineage._STAGING):
        for child in directory.iterdir():
            _expect(not child.is_dir(), f"unexpected action fixture directory: {child}")
            child.unlink()
    for path in lineage._CONTROL.iterdir():
        if path.name.endswith(".json"):
            path.unlink()
    _expect(
        {path.name: _file(path) for path in lock_paths} == lock_identity,
        "runtime action locks changed during state clear",
    )
    for path in (
        _WORKER_BINDING,
        _RUNTIME_BINDING,
        _OBSERVATION_BINDING,
        _GRANT_SOURCE,
    ):
        path.unlink(missing_ok=True)


def _write_document(
    path: Path,
    document: object,
    uid: int = 0,
    gid: int = 0,
    mode: int = 0o400,
) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    openclaw._write_document(path, document, uid, gid, mode)


def _mkdir(path: Path, uid: int, gid: int, mode: int) -> None:
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _gateway_configuration(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
) -> dict[str, Any]:
    provider = "aragorn-runtime-action-mock"
    model = "fixture-model"
    plugin_config = {
        "expectedGatewayGid": gateway_gid,
        "expectedGatewayUid": gateway_uid,
        "expectedWorkerUid": worker_uid,
        "workerSocketPath": str(_WORKER_SOCKET),
    }
    return {
        "agents": {
            "defaults": {
                "model": {"primary": f"{provider}/{model}"},
                "skills": [skill_name],
                "workspace": str(_GATEWAY_WORKSPACE),
            },
            "list": [
                {
                    "id": "main",
                    "skills": [skill_name],
                    "workspace": str(_GATEWAY_WORKSPACE),
                }
            ],
        },
        "gateway": {"mode": "local"},
        "models": {
            "mode": "replace",
            "providers": {
                provider: {
                    "api": "openai-completions",
                    "apiKey": "${ARAGORN_MOCK_PROVIDER_TOKEN}",
                    "baseUrl": "http://127.0.0.1:18080/v1",
                    "models": [
                        {
                            "compat": {
                                "maxTokensField": "max_tokens",
                                "supportsDeveloperRole": False,
                                "supportsStore": False,
                                "supportsStrictMode": False,
                                "supportsTools": True,
                                "supportsUsageInStreaming": False,
                            },
                            "contextWindow": 200000,
                            "cost": {
                                "cacheRead": 0,
                                "cacheWrite": 0,
                                "input": 0,
                                "output": 0,
                            },
                            "id": model,
                            "input": ["text"],
                            "maxTokens": 256,
                            "name": "Aragorn deterministic runtime-worker fixture",
                            "reasoning": False,
                        }
                    ],
                    "timeoutSeconds": 10,
                }
            },
        },
        "plugins": {
            "allow": ["aragorn-runtime-action-worker"],
            "enabled": True,
            "entries": {
                "aragorn-runtime-action-worker": {
                    "config": plugin_config,
                    "enabled": True,
                }
            },
            "load": {"paths": [str(_PLUGIN)]},
        },
        "skills": {
            "load": {"allowSymlinkTargets": [], "extraDirs": [], "watch": False}
        },
        "tools": {"alsoAllow": ["aragorn_runtime_create"]},
    }


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path]:
    for path in (_GATEWAY_ROOT, _GATEWAY_HOME, _GATEWAY_STATE, _GATEWAY_WORKSPACE):
        _mkdir(path, gateway_uid, gateway_gid, 0o700)
    skill_root = _GATEWAY_STATE / "skills"
    projected_root = skill_root / skill_name
    _mkdir(skill_root, 0, 0, 0o555)
    _mkdir(projected_root, 0, 0, 0o555)
    projected_skill = projected_root / "SKILL.md"
    projected_skill.write_bytes(skill_raw)
    os.chown(projected_skill, 0, 0)
    os.chmod(projected_skill, 0o444)

    config = _gateway_configuration(
        gateway_uid,
        gateway_gid,
        worker_uid,
        skill_name,
    )
    _write_document(_GATEWAY_CONFIG, config)
    tokens = {
        "OPENCLAW_GATEWAY_TOKEN": secrets.token_hex(32),
        "ARAGORN_MOCK_PROVIDER_TOKEN": secrets.token_hex(32),
    }
    _GATEWAY_ENVIRONMENT.write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(tokens.items())),
        encoding="ascii",
    )
    os.chown(_GATEWAY_ENVIRONMENT, 0, 0)
    os.chmod(_GATEWAY_ENVIRONMENT, 0o400)
    return config, tokens, projected_skill


def _predicted_service_cgroup(unit: str) -> str:
    pid1 = profile_systemd._cgroup(1)
    _expect(
        re.fullmatch(r"/docker/[0-9a-f]{64}/init\.scope", pid1) is not None,
        "PID1 cgroup is not the exact Docker systemd init scope",
    )
    root = pid1.removesuffix("/init.scope")
    return f"{root}/system.slice/{unit}"


def _profile(
    *, runtime_digest: str, executable_digest: str, cgroup: str, skill_path: Path
) -> tuple[dict[str, Any], Any]:
    document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": runtime_digest,
        "executable_digest": executable_digest,
        "cgroup": cgroup,
        "skill_path": str(skill_path),
    }
    return document, runtime_process_profile(document)


def _controls(
    policy: dict[str, Any],
    action: dict[str, str],
    skill_digest: str,
    now: int,
    counter: int,
) -> dict[str, Any]:
    with mock.patch.object(openclaw, "_SKILL_DIGEST", skill_digest):
        return capability._controls(policy, action, now, counter=counter)


def _grant(
    profile_digest: str,
    policy: dict[str, Any],
    action: dict[str, str],
    producer: dict[str, Any],
    skill_digest: str,
    now: int,
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
        "issued_at_unix": now - 1,
        "expires_at_unix": now + 290,
        "max_actions": 1,
    }
    _expect(
        parse_runtime_capability_grant(canonical_json(grant), now) == grant,
        "fresh worker grant validation changed",
    )
    return grant


def _write_stack_inputs(
    *,
    profile_document: dict[str, Any],
    profile_digest: str,
    worker_binding: dict[str, Any],
    grant: dict[str, Any],
    controls: dict[str, Any],
    broker_uid: int,
    worker_gid: int,
) -> None:
    for name, document in controls.items():
        capability._write_control(
            lineage._CONTROL / f"{name}.json",
            document,
            broker_uid,
            worker_gid,
        )
    _write_document(
        _RUNTIME_BINDING,
        {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": openclaw._RUNTIME_DIGEST,
            "runtime_profile_digest": profile_digest,
        },
    )
    _write_document(
        _OBSERVATION_BINDING,
        {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": openclaw._SENSOR_DIGEST,
            "runtime_profile": profile_document,
        },
    )
    _write_document(_WORKER_BINDING, worker_binding)
    _write_document(_GRANT_SOURCE, grant)


def _refresh_controls(
    policy: dict[str, Any],
    action: dict[str, str],
    skill_digest: str,
    broker_uid: int,
    worker_gid: int,
    counter: int,
) -> dict[str, Any]:
    refreshed = _controls(policy, action, skill_digest, int(time.time()), counter)
    for name in ("revocations", "health", "observation"):
        capability._write_control(
            lineage._CONTROL / f"{name}.json",
            refreshed[name],
            broker_uid,
            worker_gid,
        )
    return refreshed


def _unit(name: str) -> dict[str, str]:
    properties = (
        "ActiveState",
        "AmbientCapabilities",
        "CapabilityBoundingSet",
        "ControlGroup",
        "DropInPaths",
        "ExecMainStatus",
        "ExecStart",
        "FragmentPath",
        "Group",
        "InaccessiblePaths",
        "MainPID",
        "NoNewPrivileges",
        "PrivateMounts",
        "PrivateNetwork",
        "ProtectSystem",
        "ReadOnlyPaths",
        "ReadWritePaths",
        "RestrictAddressFamilies",
        "Result",
        "SubState",
        "SupplementaryGroups",
        "User",
    )
    raw = _run(
        [
            "systemctl",
            "show",
            name,
            *[f"-p{property_name}" for property_name in properties],
        ]
    ).stdout.decode()
    values = dict(line.split("=", 1) for line in raw.splitlines())
    _expect(set(values) == set(properties), f"systemd properties incomplete: {name}")
    values["LoadCredential"] = (
        _run(
            [
                "busctl",
                "get-property",
                "org.freedesktop.systemd1",
                _UNIT_OBJECTS[name],
                "org.freedesktop.systemd1.Service",
                "LoadCredential",
            ]
        )
        .stdout.decode()
        .strip()
    )
    fragment = Path(values["FragmentPath"])
    values["FragmentResolvedPath"] = str(fragment.resolve(strict=True))
    values["FragmentDigest"] = _file(fragment)["digest"]
    return values


def _start_stack(
    expected_worker_cgroup: str, expected_gateway_cgroup: str
) -> dict[str, Any]:
    _systemctl("daemon-reload")
    try:
        _systemctl("start", _GATEWAY_UNIT)
    except Exception as exc:
        journals = {}
        for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT):
            raw = _run(
                [
                    "journalctl",
                    "--no-pager",
                    "--output=cat",
                    "--unit",
                    name,
                    "--lines=60",
                ],
                check=False,
            ).stdout
            journals[name] = _byte_identity(raw)
        raise openclaw.ProbeError(
            "worker stack start failed closed: "
            f"cause={type(exc).__name__};journal_identities={journals}"
        ) from exc
    for path in (_BROKER_SOCKET, _SENSOR_SOCKET, _WORKER_SOCKET):
        lineage._wait_path(path)
    units = {
        name: _unit(name)
        for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT)
    }
    _expect(
        all(unit["ActiveState"] == "active" for unit in units.values()),
        "worker stack is not active",
    )
    pids = {name: int(unit["MainPID"]) for name, unit in units.items()}
    _expect(
        units[_WORKER_UNIT]["ControlGroup"] == expected_worker_cgroup
        and units[_GATEWAY_UNIT]["ControlGroup"] == expected_gateway_cgroup
        and profile_systemd._cgroup(pids[_WORKER_UNIT]) == expected_worker_cgroup
        and profile_systemd._cgroup(pids[_GATEWAY_UNIT]) == expected_gateway_cgroup,
        "predicted gateway or worker cgroup changed",
    )
    return {
        "units": units,
        "pids": pids,
        "processes": {name: _process(pid) for name, pid in pids.items()},
    }


def _start_trace(pid: int, path: Path) -> subprocess.Popen[bytes]:
    return systemd_probe._start_trace(pid, path)


def _finish_trace(
    process: subprocess.Popen[bytes], path: Path, service_pid: int
) -> dict[str, Any]:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    trace_state = os.lstat(path)
    _expect(
        stat.S_ISREG(trace_state.st_mode)
        and trace_state.st_nlink == 1
        and 0 <= trace_state.st_size <= _MAX_TRACE_BYTES,
        "socket trace file is invalid or oversized",
    )
    raw_bytes = path.read_bytes()
    _expect(
        len(raw_bytes) == trace_state.st_size <= _MAX_TRACE_BYTES,
        "socket trace bytes changed while reading",
    )
    raw = raw_bytes.decode("utf-8")
    lines = raw.splitlines()
    channels = []
    successful_connects = []
    for line in lines:
        connected = systemd_probe._CONNECT_TRACE.fullmatch(line)
        if connected is not None:
            successful_connects.append(
                {"fd": int(connected["fd"]), "path": connected["path"]}
            )
    for index, line in enumerate(lines):
        peer = systemd_probe._PEER_TRACE.fullmatch(line)
        if peer is None:
            continue
        previous = lines[index - 1] if index else ""
        accepted = systemd_probe._ACCEPT_TRACE.fullmatch(previous)
        connected = systemd_probe._CONNECT_TRACE.fullmatch(previous)
        precursor = accepted or connected
        _expect(
            precursor is not None
            and int(peer["service"]) == int(precursor["service"])
            and peer["fd"] == precursor["fd"],
            "SO_PEERCRED trace lost its successful channel precursor",
        )
        channels.append(
            {
                "kind": "accept" if accepted is not None else "connect",
                "path": None if connected is None else connected["path"],
                "peer": {key: int(peer[key]) for key in ("pid", "uid", "gid")},
            }
        )
    _expect(
        raw.count("SO_PEERCRED") == len(channels)
        and all(
            int(match.group("service")) > 0
            for match in systemd_probe._PEER_TRACE.finditer(raw)
        ),
        f"SO_PEERCRED trace changed for {service_pid}",
    )
    return {
        "service_pid": service_pid,
        "raw": raw,
        "raw_digest": "sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
        "raw_bytes": len(raw_bytes),
        "channels": channels,
        "successful_connects": successful_connects,
    }


def _trace_case(
    pids: dict[str, int],
    label: str,
    callback: Any,
) -> tuple[Any, dict[str, Any]]:
    traces = {}
    processes = {}
    for name, pid in pids.items():
        path = _DRIVER_ROOT / f"{label}-{name}.trace"
        processes[name] = (_start_trace(pid, path), path, pid)
    try:
        result = callback()
    finally:
        for name, (process, path, pid) in processes.items():
            traces[name] = _finish_trace(process, path, pid)
    return result, traces


def _connect_paths(trace: dict[str, Any]) -> list[str]:
    return [item["path"] for item in trace["successful_connects"]]


def _driver_gateway_pid(driver: dict[str, Any]) -> Any:
    return (
        driver["output"]
        .get("gateway", {})
        .get("system_info", {})
        .get("response", {})
        .get("pid")
    )


def _prebroker_channels(
    pids: dict[str, int], identities: dict[str, dict[str, int]]
) -> dict[str, list[dict[str, Any]]]:
    return {
        "worker": [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "pid": pids[_GATEWAY_UNIT],
                    **identities["gateway"],
                },
            },
            {
                "kind": "connect",
                "path": str(_SENSOR_SOCKET),
                "peer": {
                    "pid": pids[_SENSOR_UNIT],
                    **identities["sensor"],
                },
            },
        ],
        "sensor": [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "pid": pids[_WORKER_UNIT],
                    **identities["worker"],
                },
            }
        ],
    }


def _read_driver_output(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    document = json.loads(raw)
    _expect(
        raw in {canonical_json(document), canonical_json(document) + b"\n"},
        "worker driver output is not canonical JSON",
    )
    return document


def _run_driver(
    scenario_id: str,
    expected_status: str,
    expected_broker_result: dict[str, str] | None,
    expected_schema: str,
    tokens: dict[str, str],
) -> dict[str, Any]:
    input_path = _DRIVER_ROOT / f"{scenario_id}.input.json"
    output_path = _DRIVER_ROOT / f"{scenario_id}.output.json"
    driver_input = {
        "schema": "aragorn/openclaw-worker-driver-input/v1",
        "scenario": {
            "id": scenario_id,
            "target_name": _TARGET,
            "content": _PAYLOAD.decode("utf-8"),
            "expected_result": {
                "schema": expected_schema,
                "status": expected_status,
                "broker_result": expected_broker_result,
            },
        },
    }
    input_path.write_bytes(canonical_json(driver_input) + b"\n")
    os.chmod(input_path, 0o400)
    started = time.monotonic_ns()
    process = subprocess.run(
        [str(_NODE), str(_DRIVER), str(input_path), str(output_path)],
        check=False,
        capture_output=True,
        timeout=45,
        env={
            "HOME": str(_GATEWAY_HOME),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": str(_GATEWAY_CONFIG),
            "OPENCLAW_STATE_DIR": str(_GATEWAY_STATE),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
            **tokens,
        },
    )
    elapsed = time.monotonic_ns() - started
    output_identity = (
        _byte_identity(output_path.read_bytes()) if output_path.exists() else None
    )
    try:
        output = _read_driver_output(output_path) if output_path.exists() else {}
    except Exception as exc:
        raise openclaw.ProbeError(
            "OpenClaw worker driver output failed closed: "
            f"scenario={scenario_id};cause={type(exc).__name__};"
            f"output_identity={output_identity}"
        ) from exc
    passed = (
        process.returncode == 0
        and output.get("schema") == "aragorn/openclaw-worker-driver-output/v1"
        and output.get("scenario", {}).get("status") == "PASS"
    )
    _expect(
        passed,
        "OpenClaw worker driver failed closed: "
        f"scenario={scenario_id};returncode={process.returncode};"
        f"stdout={_byte_identity(process.stdout)};"
        f"stderr={_byte_identity(process.stderr)};"
        f"output={output_identity}",
    )
    return {
        "input": driver_input,
        "output": output,
        "exit_code": process.returncode,
        "stdout_digest": _byte_identity(process.stdout)["digest"],
        "stderr_digest": _byte_identity(process.stderr)["digest"],
        "elapsed_ns": elapsed,
    }


def _normalized_outcome(driver: dict[str, Any]) -> dict[str, Any]:
    outcome = driver["output"].get("scenario", {}).get("proof", {}).get("observed")
    expected_fields = {
        "schema",
        "source_schema",
        "source_authority",
        "status",
        "request_digest",
        "broker_result",
    }
    source_authorities = {
        "aragorn/runtime-action-worker-result/v1": (
            "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        ),
        "aragorn/runtime-action-worker-client-error/v1": (
            "GATEWAY_CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        ),
    }
    _expect(
        isinstance(outcome, dict)
        and set(outcome) == expected_fields
        and outcome.get("schema") == "aragorn/openclaw-worker-driver-relay-summary/v1"
        and outcome.get("source_schema") in source_authorities
        and outcome.get("source_authority")
        == source_authorities[outcome["source_schema"]]
        and outcome.get("status") in {"COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"},
        f"driver worker outcome changed: {outcome}",
    )
    if outcome["source_schema"] == "aragorn/runtime-action-worker-client-error/v1":
        _expect(
            outcome["status"] != "COMPLETED"
            and outcome["request_digest"] is None
            and outcome["broker_result"] is None,
            f"driver client-error summary changed: {outcome}",
        )
        return {"status": outcome["status"], "broker_result": None, "raw": outcome}
    _expect(
        re.fullmatch(r"sha256:[0-9a-f]{64}", outcome.get("request_digest", ""))
        is not None,
        f"driver worker request binding changed: {outcome}",
    )
    if outcome["status"] != "COMPLETED":
        _expect(
            outcome["broker_result"] is None,
            f"driver non-completed summary changed: {outcome}",
        )
        return {"status": outcome["status"], "broker_result": None, "raw": outcome}
    broker = outcome["broker_result"]
    _expect(
        isinstance(broker, dict)
        and set(broker)
        == {
            "source_schema",
            "source_authority",
            "verdict",
            "effect_status",
            "reason_codes",
            "target_name",
        }
        and broker["source_schema"] == "aragorn/runtime-action-broker-result/v1"
        and broker["source_authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and broker["verdict"] == "ALLOW"
        and broker["effect_status"] == "CREATED"
        and broker["reason_codes"] == []
        and broker["target_name"] == _TARGET,
        f"driver broker summary changed: {outcome}",
    )
    return {
        "status": outcome["status"],
        "broker_result": broker,
        "raw": outcome,
    }


def _assert_driver_outcome(
    driver: dict[str, Any],
    status: str,
    broker_result: dict[str, str] | None,
) -> dict[str, Any]:
    outcome = _normalized_outcome(driver)
    nested = outcome["broker_result"]
    _expect(outcome["status"] == status, f"worker status changed: {outcome}")
    if broker_result is None:
        _expect(nested is None, f"unexpected broker result: {outcome}")
    else:
        _expect(
            isinstance(nested, dict)
            and {key: nested.get(key) for key in broker_result} == broker_result,
            f"nested worker broker result changed: {outcome}",
        )
    return outcome


def _unauthorized_worker_client() -> dict[str, Any]:
    request = {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": _TARGET,
        "payload_base64": base64.b64encode(_PAYLOAD).decode("ascii"),
        "session_id": "unauthorized-root-session",
        "run_id": "unauthorized-root-run",
        "tool_call_digest": canonical_digest(
            {"schema": "aragorn/p37b-unauthorized-tool-call/v1"}
        ),
    }
    raw = canonical_json(request)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(1)
    record: dict[str, Any] = {
        "client": {"pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid()},
        "request_digest": canonical_digest(request),
    }
    try:
        connection.connect(os.fspath(_WORKER_SOCKET))
        peer = systemd_probe._PEER.unpack(
            connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                systemd_probe._PEER.size,
            )
        )
        record["server_peer"] = {"pid": peer[0], "uid": peer[1], "gid": peer[2]}
        try:
            connection.sendall(systemd_probe._FRAME.pack(len(raw)) + raw)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(1)
            record["outcome"] = "PEER_CLOSED" if not response else "UNEXPECTED_RESPONSE"
        except OSError as exc:
            _expect(
                exc.errno in {errno.ECONNRESET, errno.EPIPE},
                "unauthorized peer error changed",
            )
            record.update(
                outcome="PEER_CLOSED",
                errno=exc.errno,
                error=errno.errorcode.get(exc.errno, "UNKNOWN"),
            )
    finally:
        connection.close()
    return record


def _snapshot_effects() -> dict[str, Any]:
    return {
        "controls": capability._control_snapshot(),
        "grant_state": _document(lineage._GRANT_STATE),
        "target_exists": (lineage._PROTECTED / _TARGET).exists(),
        "protected_entries": sorted(path.name for path in lineage._PROTECTED.iterdir()),
        "staging_entries": sorted(path.name for path in lineage._STAGING.iterdir()),
        "pending_exists": lineage._PENDING.exists(),
        "receipt_exists": lineage._RECEIPT.exists(),
    }


def _available(snapshot: dict[str, Any], grant_digest: str) -> bool:
    document = snapshot["grant_state"]["document"]
    return (
        document.get("schema") == "aragorn/runtime-capability-grant-state/v1"
        and document.get("status") == "AVAILABLE"
        and document.get("grant_digest") == grant_digest
        and document.get("claim") is None
        and document.get("result") is None
    )


def _assert_no_broker(trace: dict[str, Any], label: str) -> None:
    _expect(
        trace["channels"] == [] and trace["successful_connects"] == [],
        f"{label} reached the broker",
    )


def _namespace_read_checks(
    pid: int,
    uid: int,
    gid: int,
    groups: list[int],
    paths: list[Path],
) -> dict[str, Any]:
    program = r"""
import errno
import json
import os
import sys

result = {}
for path in sys.argv[1:]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        result[path] = {"blocked": True, "errno": exc.errno, "error": errno.errorcode.get(exc.errno, "UNKNOWN")}
    else:
        os.close(descriptor)
        result[path] = {"blocked": False, "errno": None, "error": None}
sys.stdout.write(json.dumps(result, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
"""
    group_argument = (
        "--clear-groups" if not groups else f"--groups={','.join(map(str, groups))}"
    )
    result = _run(
        [
            "nsenter",
            "--target",
            str(pid),
            "--mount",
            "--",
            "setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            group_argument,
            str(_PYTHON),
            "-I",
            "-S",
            "-B",
            "-c",
            program,
            *map(str, paths),
        ]
    )
    document = json.loads(result.stdout)
    _expect(
        set(document) == {str(path) for path in paths}
        and all(
            item["blocked"]
            and item["errno"] in {errno.EACCES, errno.ENOENT, errno.ENOTDIR}
            for item in document.values()
        ),
        "service namespace retained a forbidden read",
    )
    return document


def _plugin_artifacts() -> tuple[list[dict[str, Any]], str]:
    records = []
    identity = []
    for name in ("index.js", "openclaw.plugin.json", "package.json"):
        source = Path("/src/packaging/openclaw/aragorn-runtime-action-worker") / name
        installed = _PLUGIN / name
        source_file = _file(source)
        installed_file = _file(installed)
        _expect(
            (source_file["digest"], source_file["bytes"])
            == (installed_file["digest"], installed_file["bytes"])
            and installed_file["stat"]["uid"] == 0
            and installed_file["stat"]["gid"] == 0
            and installed_file["stat"]["mode"] == "0644"
            and installed_file["stat"]["nlink"] == 1,
            f"installed worker plugin changed: {name}",
        )
        records.append({"source": source_file, "installed": installed_file})
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


def _artifacts() -> dict[str, Any]:
    installed = []
    for source_path, installed_path in sorted(_NEW_ARTIFACTS.items()):
        source = _file(Path(source_path))
        target = _file(Path(installed_path))
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"]),
            f"worker source/install mismatch: {installed_path}",
        )
        installed.append({"source": source, "installed": target})
    plugin, plugin_digest = _plugin_artifacts()
    return {
        "installed": installed,
        "plugin": {"digest": plugin_digest, "files": plugin},
        "collector": {
            "base_installer": _file(
                Path("/src/packaging/install-runtime-capability-host.sh")
            ),
            "probe": _file(Path(__file__).resolve()),
            "capture_recipe": _file(
                Path("/src/scripts/capture_runtime_action_worker_openclaw_systemd.sh")
            ),
            "dockerfile": _file(
                Path("/src/benchmark/runtime-action-worker-openclaw-systemd/Dockerfile")
            ),
            "driver": _file(_DRIVER),
            "installer": _file(
                Path("/src/packaging/install-runtime-action-worker-host.sh")
            ),
            "parent_probe": _file(
                Path("/src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py")
            ),
        },
    }


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    _set_stage("IDENTITY_CLOSURE")
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
        len({identity["uid"] for identity in identities.values()}) == 4,
        "gateway, worker, sensor, and broker UIDs are not distinct",
    )

    _set_stage("ARTIFACT_SOURCE_INSTALL_CLOSURE")
    artifacts = _artifacts()
    _set_stage("EXECUTABLE_RUNTIME_CLOSURE")
    node = _file(_NODE)
    python = _file(_PYTHON.resolve(strict=True))
    _expect(node["digest"] == openclaw._NODE_DIGEST, "pinned Node executable changed")
    runtime = openclaw._runtime_snapshot()

    _set_stage("PROTECTED_INSTALL_RESET")
    prior.lineage._reset()
    _set_stage("PROTECTED_INSTALL_PRODUCER")
    producer = prior._prepare_producer(worker_gid)
    prior._producer = producer
    skill_path = producer["paths"]["skill"]
    skill_raw = skill_path.read_bytes()
    skill_digest = "sha256:" + hashlib.sha256(skill_raw).hexdigest()
    _expect(
        skill_digest == producer["tree_entry"]["digest"],
        "fresh producer skill digest changed",
    )

    _set_stage("ACTION_PLANE_RESET")
    _reset_action_plane()
    _set_stage("GATEWAY_FIXTURE")
    config, tokens, projected_skill = _prepare_gateway(
        gateway.pw_uid,
        gateway_gid,
        worker.pw_uid,
        producer["skill_name"],
        skill_raw,
    )
    _expect(
        _file(projected_skill)["digest"] == skill_digest,
        "gateway skill projection differs from the fresh producer skill",
    )
    _DRIVER_ROOT.mkdir(mode=0o700)

    _set_stage("FRESH_AUTHORITY_INPUTS")
    protected_fd = os.open(lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(protected_fd, _TARGET, _PAYLOAD)
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-7b-distinct-gateway-runtime-worker",
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
    coherent_worker_binding = {
        "schema": "aragorn/runtime-action-worker-binding/v1",
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "active_skill_digest": skill_digest,
        "policy_digest": policy_digest,
        "policy_version": policy["version"],
    }
    mismatched_worker_binding = {
        **coherent_worker_binding,
        "active_skill_digest": canonical_digest(
            {
                "schema": "aragorn/p37b-worker-binding-mismatch/v1",
                "active_skill_digest": skill_digest,
            }
        ),
    }
    worker_cgroup = _predicted_service_cgroup(_WORKER_UNIT)
    gateway_cgroup = _predicted_service_cgroup(_GATEWAY_UNIT)
    worker_profile_document, worker_profile = _profile(
        runtime_digest=openclaw._RUNTIME_DIGEST,
        executable_digest=python["digest"],
        cgroup=worker_cgroup,
        skill_path=skill_path,
    )
    legacy_profile_document, legacy_profile = _profile(
        runtime_digest=openclaw._RUNTIME_DIGEST,
        executable_digest=node["digest"],
        cgroup=gateway_cgroup,
        skill_path=projected_skill,
    )

    _set_stage("LEGACY_PROFILE_CASE")
    now = int(time.time())
    _set_stage("LEGACY_PROFILE_INPUTS")
    legacy_grant = _grant(
        legacy_profile.digest,
        policy,
        action,
        producer,
        skill_digest,
        now,
    )
    legacy_grant_digest = canonical_digest(legacy_grant)
    legacy_controls = _controls(policy, action, skill_digest, now, 1)
    _set_stage("LEGACY_PROFILE_MATERIALIZATION")
    _write_stack_inputs(
        profile_document=legacy_profile_document,
        profile_digest=legacy_profile.digest,
        worker_binding=coherent_worker_binding,
        grant=legacy_grant,
        controls=legacy_controls,
        broker_uid=broker.pw_uid,
        worker_gid=worker_gid,
    )
    _set_stage("LEGACY_PROFILE_STACK_START")
    legacy_stack = _start_stack(worker_cgroup, gateway_cgroup)
    legacy_before = _snapshot_effects()
    _set_stage("LEGACY_PROFILE_DRIVER")
    legacy_driver, legacy_traces = _trace_case(
        {
            "worker": legacy_stack["pids"][_WORKER_UNIT],
            "sensor": legacy_stack["pids"][_SENSOR_UNIT],
            "broker": legacy_stack["pids"][_BROKER_UNIT],
        },
        "legacy-profile",
        lambda: _run_driver(
            "legacy-openclaw-profile",
            "INDETERMINATE",
            None,
            "aragorn/runtime-action-worker-result/v1",
            tokens,
        ),
    )
    _set_stage("LEGACY_PROFILE_OUTCOME")
    legacy_outcome = _assert_driver_outcome(legacy_driver, "INDETERMINATE", None)
    legacy_after = _snapshot_effects()
    _assert_no_broker(legacy_traces["broker"], "legacy OpenClaw profile")
    legacy_expected = _prebroker_channels(legacy_stack["pids"], identities)
    _set_stage("LEGACY_PROFILE_CAUSAL_CHECKS")
    legacy_checks = {
        "driver": legacy_outcome["status"] == "INDETERMINATE",
        "gateway_pid": _driver_gateway_pid(legacy_driver)
        == legacy_stack["pids"][_GATEWAY_UNIT],
        "worker_received_gateway": legacy_traces["worker"]["channels"]
        == legacy_expected["worker"],
        "sensor_received_worker": legacy_traces["sensor"]["channels"]
        == legacy_expected["sensor"],
        "exact_connects": _connect_paths(legacy_traces["worker"])
        == [str(_SENSOR_SOCKET)]
        and _connect_paths(legacy_traces["sensor"]) == [],
        "broker_not_reached": not legacy_traces["broker"]["channels"],
        "grant_available": _available(legacy_before, legacy_grant_digest),
        "effects_unchanged": legacy_before == legacy_after,
    }
    _expect(all(legacy_checks.values()), "legacy OpenClaw profile case changed")

    _set_stage("WORKER_BINDING_MISMATCH_CASE")
    _clear_action_state()
    now = int(time.time())
    grant = _grant(
        worker_profile.digest,
        policy,
        action,
        producer,
        skill_digest,
        now,
    )
    grant_digest = canonical_digest(grant)
    controls = _controls(policy, action, skill_digest, now, 2)
    _write_stack_inputs(
        profile_document=worker_profile_document,
        profile_digest=worker_profile.digest,
        worker_binding=mismatched_worker_binding,
        grant=grant,
        controls=controls,
        broker_uid=broker.pw_uid,
        worker_gid=worker_gid,
    )
    mismatch_stack = _start_stack(worker_cgroup, gateway_cgroup)
    mismatch_before = _snapshot_effects()
    mismatch_driver, mismatch_traces = _trace_case(
        {
            "worker": mismatch_stack["pids"][_WORKER_UNIT],
            "sensor": mismatch_stack["pids"][_SENSOR_UNIT],
            "broker": mismatch_stack["pids"][_BROKER_UNIT],
        },
        "worker-binding-mismatch",
        lambda: _run_driver(
            "worker-binding-mismatch",
            "INDETERMINATE",
            None,
            "aragorn/runtime-action-worker-result/v1",
            tokens,
        ),
    )
    mismatch_outcome = _assert_driver_outcome(mismatch_driver, "INDETERMINATE", None)
    mismatch_after = _snapshot_effects()
    _assert_no_broker(mismatch_traces["broker"], "worker-binding mismatch")
    mismatch_expected = _prebroker_channels(mismatch_stack["pids"], identities)
    mismatch_checks = {
        "driver": mismatch_outcome["status"] == "INDETERMINATE",
        "gateway_pid": _driver_gateway_pid(mismatch_driver)
        == mismatch_stack["pids"][_GATEWAY_UNIT],
        "worker_received_gateway": mismatch_traces["worker"]["channels"]
        == mismatch_expected["worker"],
        "sensor_received_worker": mismatch_traces["sensor"]["channels"]
        == mismatch_expected["sensor"],
        "exact_connects": _connect_paths(mismatch_traces["worker"])
        == [str(_SENSOR_SOCKET)]
        and _connect_paths(mismatch_traces["sensor"]) == [],
        "broker_not_reached": not mismatch_traces["broker"]["channels"],
        "grant_available": _available(mismatch_before, grant_digest),
        "effects_unchanged": mismatch_before == mismatch_after,
    }
    _expect(all(mismatch_checks.values()), "worker-binding mismatch case changed")

    _set_stage("WORKER_ENDPOINT_UNAVAILABLE_CASE")
    _stop_stack()
    _write_document(_WORKER_BINDING, coherent_worker_binding)
    coherent_stack = _start_stack(worker_cgroup, gateway_cgroup)
    stable_pids = coherent_stack["pids"]

    unavailable_before = _snapshot_effects()
    socket_before = _metadata(_WORKER_SOCKET)
    _expect(
        not os.path.lexists(_PARKED_WORKER_SOCKET),
        "worker endpoint parked path was preoccupied",
    )
    os.rename(_WORKER_SOCKET, _PARKED_WORKER_SOCKET)
    parked = _metadata(_PARKED_WORKER_SOCKET)
    _expect(
        not _WORKER_SOCKET.exists()
        and (socket_before["device"], socket_before["inode"])
        == (parked["device"], parked["inode"]),
        "worker endpoint parking changed listener identity",
    )
    try:
        unavailable_driver, unavailable_traces = _trace_case(
            {
                "worker": stable_pids[_WORKER_UNIT],
                "sensor": stable_pids[_SENSOR_UNIT],
                "broker": stable_pids[_BROKER_UNIT],
            },
            "worker-endpoint-unavailable",
            lambda: _run_driver(
                "worker-endpoint-unavailable",
                "NOT_SUBMITTED",
                None,
                "aragorn/runtime-action-worker-client-error/v1",
                tokens,
            ),
        )
    finally:
        _expect(
            not os.path.lexists(_WORKER_SOCKET),
            "worker endpoint path reappeared while parked",
        )
        os.rename(_PARKED_WORKER_SOCKET, _WORKER_SOCKET)
        _expect(
            not os.path.lexists(_PARKED_WORKER_SOCKET),
            "worker endpoint parked path remained after restore",
        )
    restored = _metadata(_WORKER_SOCKET)
    unavailable_outcome = _assert_driver_outcome(
        unavailable_driver, "NOT_SUBMITTED", None
    )
    unavailable_after = _snapshot_effects()
    stable_pids_after = {name: int(_unit(name)["MainPID"]) for name in stable_pids}
    endpoint_identity = {
        "before": {
            "device": socket_before["device"],
            "inode": socket_before["inode"],
        },
        "parked": {"device": parked["device"], "inode": parked["inode"]},
        "restored": {
            "device": restored["device"],
            "inode": restored["inode"],
        },
    }
    unavailable_checks = {
        "driver": unavailable_outcome["status"] == "NOT_SUBMITTED",
        "gateway_pid": _driver_gateway_pid(unavailable_driver)
        == stable_pids[_GATEWAY_UNIT],
        "listener_identity_restored": endpoint_identity["restored"]
        == endpoint_identity["before"]
        == endpoint_identity["parked"],
        "worker_not_reached": not unavailable_traces["worker"]["channels"]
        and not unavailable_traces["worker"]["successful_connects"],
        "sensor_not_reached": not unavailable_traces["sensor"]["channels"]
        and not unavailable_traces["sensor"]["successful_connects"],
        "broker_not_reached": not unavailable_traces["broker"]["channels"]
        and not unavailable_traces["broker"]["successful_connects"],
        "pids_stable": stable_pids_after == stable_pids,
        "grant_available": _available(unavailable_before, grant_digest),
        "effects_unchanged": unavailable_before == unavailable_after,
    }
    _expect(
        all(unavailable_checks.values()), "worker endpoint unavailable case changed"
    )

    _set_stage("UNAUTHORIZED_WORKER_PEER_CASE")
    unauthorized_before = _snapshot_effects()
    unauthorized_result, unauthorized_traces = _trace_case(
        {
            "worker": stable_pids[_WORKER_UNIT],
            "sensor": stable_pids[_SENSOR_UNIT],
            "broker": stable_pids[_BROKER_UNIT],
        },
        "unauthorized-worker-peer",
        _unauthorized_worker_client,
    )
    unauthorized_after = _snapshot_effects()
    unauthorized_checks = {
        "peer_closed": unauthorized_result["outcome"] == "PEER_CLOSED",
        "worker_authenticated_root": unauthorized_traces["worker"]["channels"]
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": {"pid": os.getpid(), "uid": 0, "gid": 0},
            }
        ],
        "worker_no_connect": not unauthorized_traces["worker"]["successful_connects"],
        "sensor_not_reached": not unauthorized_traces["sensor"]["channels"]
        and not unauthorized_traces["sensor"]["successful_connects"],
        "broker_not_reached": not unauthorized_traces["broker"]["channels"]
        and not unauthorized_traces["broker"]["successful_connects"],
        "grant_available": _available(unauthorized_before, grant_digest),
        "effects_unchanged": unauthorized_before == unauthorized_after,
    }
    _expect(all(unauthorized_checks.values()), "unauthorized worker peer case changed")

    _set_stage("STALE_ACTIVE_RECORD_CASE")
    _stop_stack()
    stale_tree_digest = canonical_digest(
        {
            "schema": "aragorn/p37b-stale-active-tree/v1",
            "tree_digest": producer["transaction"]["tree_digest"],
        }
    )
    fixture = prior._assemble_producer_fixture(
        worker_gid,
        {},
        {"destination": producer["transaction"]["destination"]},
        stale_tree_digest=stale_tree_digest,
    )
    stale_record = lineage._record_snapshot(fixture["paths"]["record"])
    stale_stack = _start_stack(worker_cgroup, gateway_cgroup)
    stale_controls = _refresh_controls(
        policy, action, skill_digest, broker.pw_uid, worker_gid, 3
    )
    stale_before = _snapshot_effects()
    stale_driver, stale_traces = _trace_case(
        {
            "worker": stale_stack["pids"][_WORKER_UNIT],
            "sensor": stale_stack["pids"][_SENSOR_UNIT],
            "broker": stale_stack["pids"][_BROKER_UNIT],
        },
        "stale-active-record",
        lambda: _run_driver(
            "stale-active-record",
            "INDETERMINATE",
            None,
            "aragorn/runtime-action-worker-result/v1",
            tokens,
        ),
    )
    stale_outcome = _assert_driver_outcome(stale_driver, "INDETERMINATE", None)
    stale_after = _snapshot_effects()
    _assert_no_broker(stale_traces["broker"], "stale active record")
    stale_expected = _prebroker_channels(stale_stack["pids"], identities)
    stale_checks = {
        "driver": stale_outcome["status"] == "INDETERMINATE",
        "gateway_pid": _driver_gateway_pid(stale_driver)
        == stale_stack["pids"][_GATEWAY_UNIT],
        "worker_received_gateway": stale_traces["worker"]["channels"]
        == stale_expected["worker"],
        "sensor_received_worker": stale_traces["sensor"]["channels"]
        == stale_expected["sensor"],
        "exact_connects": _connect_paths(stale_traces["worker"])
        == [str(_SENSOR_SOCKET)]
        and _connect_paths(stale_traces["sensor"]) == [],
        "broker_not_reached": not stale_traces["broker"]["channels"],
        "grant_available": _available(stale_before, grant_digest),
        "effects_unchanged": stale_before == stale_after,
    }
    _expect(all(stale_checks.values()), "stale active-record case changed")

    _set_stage("COHERENT_WORKER_CASE")
    _stop_stack()
    prior._restore_producer_record(fixture)
    coherent_record = lineage._record_snapshot(fixture["paths"]["record"])
    coherent_stack = _start_stack(worker_cgroup, gateway_cgroup)
    coherent_controls = _refresh_controls(
        policy, action, skill_digest, broker.pw_uid, worker_gid, 4
    )
    coherent_before = _snapshot_effects()
    coherent_driver, coherent_traces = _trace_case(
        {
            "gateway": coherent_stack["pids"][_GATEWAY_UNIT],
            "worker": coherent_stack["pids"][_WORKER_UNIT],
            "sensor": coherent_stack["pids"][_SENSOR_UNIT],
            "broker": coherent_stack["pids"][_BROKER_UNIT],
        },
        "coherent",
        lambda: _run_driver(
            "coherent",
            "COMPLETED",
            {"verdict": "ALLOW", "effect_status": "CREATED"},
            "aragorn/runtime-action-worker-result/v1",
            tokens,
        ),
    )
    coherent_outcome = _assert_driver_outcome(
        coherent_driver,
        "COMPLETED",
        {"verdict": "ALLOW", "effect_status": "CREATED"},
    )
    coherent_after = _snapshot_effects()
    state = coherent_after["grant_state"]["document"]
    claim = state.get("claim") or {}
    lease = claim.get("lease") or {}
    result_record = state.get("result") or {}
    profile_result = result_record.get("profile_result") or {}
    receipt = _document(lineage._RECEIPT)
    receipt_document = receipt["document"]
    receipt_file = _file(lineage._RECEIPT)
    broker_result = receipt_document.get("broker_result")
    _expect(isinstance(broker_result, dict), "coherent receipt lost broker result")
    broker_result_digest = canonical_digest(broker_result)
    broker_state_record = _document(lineage._CONTROL / "state.json")
    broker_state = broker_state_record["document"]
    attribution = receipt_document.get("runtime_attribution") or {}
    target = _file(lineage._PROTECTED / _TARGET)
    worker_pid = coherent_stack["pids"][_WORKER_UNIT]
    gateway_pid = coherent_stack["pids"][_GATEWAY_UNIT]
    sensor_pid = coherent_stack["pids"][_SENSOR_UNIT]
    broker_pid = coherent_stack["pids"][_BROKER_UNIT]
    expected_peer_chain = {
        "gateway_to_worker": {
            "pid": gateway_pid,
            "uid": gateway.pw_uid,
            "gid": gateway_gid,
        },
        "worker_to_sensor": {
            "pid": worker_pid,
            "uid": worker.pw_uid,
            "gid": worker_gid,
        },
        "sensor_to_broker": {
            "pid": sensor_pid,
            "uid": sensor.pw_uid,
            "gid": sensor_gid,
        },
    }
    worker_channels = coherent_traces["worker"]["channels"]
    sensor_channels = coherent_traces["sensor"]["channels"]
    broker_channels = coherent_traces["broker"]["channels"]
    gateway_channels = coherent_traces["gateway"]["channels"]
    correlation = (
        claim.get("profile_claim", {})
        .get("profile_pending", {})
        .get("measured_action", {})
    )
    driver_identifiers = (
        coherent_driver["output"].get("turn", {}).get("identifiers", {})
    )
    driver_checks = (
        coherent_driver["output"].get("scenario", {}).get("proof", {}).get("checks", {})
    )
    broker_summary = {
        "source_schema": broker_result.get("schema"),
        "source_authority": broker_result.get("authority"),
        "verdict": broker_result.get("verdict"),
        "effect_status": broker_result.get("effect_status"),
        "reason_codes": broker_result.get("reason_codes"),
        "target_name": broker_result.get("target_name"),
    }
    worker_process = coherent_stack["processes"][_WORKER_UNIT]
    worker_mount_stat = os.stat(f"/proc/{worker_pid}/ns/mnt")
    worker_mount_namespace = {
        "device": worker_mount_stat.st_dev,
        "inode": worker_mount_stat.st_ino,
    }
    coherent_checks = {
        "driver": coherent_outcome["status"] == "COMPLETED",
        "nested_allow_created": coherent_outcome["broker_result"]["verdict"] == "ALLOW"
        and coherent_outcome["broker_result"]["effect_status"] == "CREATED",
        "four_distinct_uids": len({item["uid"] for item in identities.values()}) == 4,
        "gateway_to_worker": gateway_channels == []
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
                    "uid": sensor.pw_uid,
                    "gid": sensor_gid,
                },
            },
        ],
        "worker_to_sensor_to_broker": sensor_channels
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
                    "uid": broker.pw_uid,
                    "gid": worker_gid,
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
        "one_send_no_retry": [
            connect["path"]
            for connect in coherent_traces["gateway"]["successful_connects"]
        ]
        == [str(_WORKER_SOCKET)]
        and [
            connect["path"]
            for connect in coherent_traces["worker"]["successful_connects"]
        ]
        == [str(_SENSOR_SOCKET)]
        and [
            connect["path"]
            for connect in coherent_traces["sensor"]["successful_connects"]
        ]
        == [str(_BROKER_SOCKET)]
        and coherent_traces["broker"]["successful_connects"] == [],
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
        and coherent_outcome["broker_result"] == broker_summary,
        "worker_attributed": attribution.get("pid") == worker_pid
        and attribution.get("pid") != gateway_pid
        and attribution.get("uid") == worker.pw_uid
        and attribution.get("gid") == worker_gid
        and attribution.get("profile_digest") == worker_profile.digest
        and attribution.get("runtime_digest") == openclaw._RUNTIME_DIGEST
        and attribution.get("executable_digest") == python["digest"]
        and attribution.get("active_skill_digest") == skill_digest
        and attribution.get("skill_path") == str(skill_path)
        and attribution.get("cgroup") == worker_cgroup
        and attribution.get("start_time_ticks")
        == int(worker_process["start_time_ticks"])
        and worker_process["mount_namespace"]
        == f"mnt:[{worker_mount_namespace['inode']}]"
        and attribution.get("mount_namespace") == worker_mount_namespace,
        "effect_bound": target["digest"] == action["payload_digest"]
        and target["stat"]["type"] == "file"
        and target["stat"]["uid"] == broker.pw_uid
        and target["stat"]["gid"] == worker_gid
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1
        and receipt_file["digest"] == receipt["digest"]
        and receipt_file["bytes"] == len(canonical_json(receipt_document))
        and receipt_file["stat"]["type"] == "file"
        and receipt_file["stat"]["uid"] == broker.pw_uid
        and receipt_file["stat"]["gid"] == worker_gid
        and receipt_file["stat"]["mode"] == "0400"
        and receipt_file["stat"]["nlink"] == 1,
        "correlation_fresh": isinstance(correlation.get("session_id"), str)
        and isinstance(correlation.get("run_id"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", correlation.get("tool_call_id", ""))
        is not None
        and driver_identifiers.get("session_id") == correlation.get("session_id")
        and driver_identifiers.get("run_id") == correlation.get("run_id")
        and driver_identifiers.get("tool_call_digest")
        == correlation.get("tool_call_id")
        and driver_checks.get("exact_gateway_session_key") is True
        and driver_checks.get("exact_tool_call_id_identity") is True
        and driver_checks.get("exact_wait_run_id") is True
        and driver_checks.get("exact_worker_request_digest") is True
        and driver_checks.get("exact_transcript_rpc_tool_result_join") is True
        and coherent_driver["output"]
        .get("gateway", {})
        .get("system_info", {})
        .get("response", {})
        .get("pid")
        == gateway_pid,
        "clean_before": _available(coherent_before, grant_digest)
        and coherent_before["protected_entries"] == []
        and coherent_before["staging_entries"] == []
        and not coherent_before["pending_exists"]
        and not coherent_before["receipt_exists"],
        "clean_after": not coherent_after["pending_exists"]
        and coherent_after["staging_entries"] == []
        and coherent_after["protected_entries"] == [_TARGET]
        and coherent_after["receipt_exists"],
    }
    _expect(
        all(coherent_checks.values()),
        "coherent worker route changed: " + repr(coherent_checks),
    )

    _set_stage("UNIT_NAMESPACE_BOUNDARIES")
    units = coherent_stack["units"]
    processes = {name: _process(pid) for name, pid in coherent_stack["pids"].items()}
    worker_socket = _metadata(_WORKER_SOCKET)
    worker_directory = _metadata(_WORKER_SOCKET.parent)
    sensor_socket = _metadata(_SENSOR_SOCKET)
    broker_socket = _metadata(_BROKER_SOCKET)
    # FragmentDigest binds source spelling; path equality binds the pinned
    # systemd representation, which retains optional "-" prefixes.
    worker_command = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
        f"/run/credentials/{_WORKER_UNIT}/worker-binding",
    ]
    new_unit_contracts = {
        _GATEWAY_UNIT: {
            "source": Path("/src/packaging/systemd/aragorn-agent-gateway.service"),
            "installed": "/usr/lib/systemd/system/aragorn-agent-gateway.service",
            "command": [
                "/usr/local/bin/node",
                "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "gateway",
                "run",
                "--auth",
                "token",
                "--bind",
                "loopback",
                "--port",
                "18789",
                "--tailscale",
                "off",
            ],
            "process_command": ["openclaw-gateway"],
            "credential": (
                'a(ss) 1 "openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"'
            ),
            "user": "aragorn-agent-gateway",
            "group": "aragorn-agent-gateway",
            "supplementary_groups": "",
            "private_network": "no",
            "read_only": {
                str(_PLUGIN),
                "/runtime",
                str(_WORKER_SOCKET.parent),
                "-/opt/aragorn/runtime-profile",
            },
            "read_write": {str(_GATEWAY_ROOT)},
            "inaccessible": {
                "/etc/aragorn/agent-gateway",
                str(_WORKER_BINDING),
                str(_RUNTIME_BINDING),
                str(_OBSERVATION_BINDING),
                str(_GRANT_SOURCE),
                "-/etc/aragorn/runtime-action-revocation-publication.json",
                str(lineage._CONTROL.parent),
                str(lineage._PROTECTED_INSTALL_ROOT.parent),
                str(_SENSOR_SOCKET.parent),
                "-/etc/aragorn/openclaw-profile",
                "-/var/lib/aragorn-openclaw-profile",
                "-/opt/aragorn/openclaw/aragorn-runtime-action",
            },
            "address_families": {"AF_UNIX", "AF_INET", "AF_INET6"},
        },
        _WORKER_UNIT: {
            "source": Path(
                "/src/packaging/systemd/aragorn-runtime-action-worker.service"
            ),
            "installed": (
                "/usr/lib/systemd/system/aragorn-runtime-action-worker.service"
            ),
            "command": worker_command,
            "process_command": worker_command,
            "credential": (
                'a(ss) 1 "worker-binding" "/etc/aragorn/runtime-action-worker.json"'
            ),
            "user": "aragorn-runtime",
            "group": "aragorn-runtime",
            "supplementary_groups": "aragorn-agent-gateway",
            "private_network": "yes",
            "read_only": {
                str(lineage._PROTECTED),
                str(lineage._PROTECTED_INSTALL_ROOT),
                "-/opt/aragorn/runtime-profile",
            },
            "read_write": set(),
            "inaccessible": {
                str(_WORKER_BINDING),
                str(_RUNTIME_BINDING),
                str(_OBSERVATION_BINDING),
                str(_GRANT_SOURCE),
                str(lineage._CONTROL),
                str(lineage._STAGING),
                "-/var/lib/aragorn-gateway",
                "-/etc/aragorn/agent-gateway",
                "-/etc/aragorn/openclaw-profile",
                "-/var/lib/aragorn-agent-gateway",
                "-/var/lib/aragorn-openclaw-profile",
                "-/profile/config",
                "-/profile/state",
                "-/profile/workspace",
            },
            "address_families": {"AF_UNIX"},
        },
    }
    loaded_unit_checks = {}
    for name, contract in new_unit_contracts.items():
        unit = units[name]
        process = processes[name]
        command = contract["command"]
        loaded_exec, separator, _metadata_suffix = unit["ExecStart"].partition(
            " ; ignore_errors="
        )
        loaded_unit_checks[name] = {
            "source_fragment": unit["FragmentPath"] == f"/lib/systemd/system/{name}"
            and unit["FragmentResolvedPath"] == contract["installed"]
            and unit["FragmentDigest"] == _file(contract["source"])["digest"]
            and unit["DropInPaths"] == "",
            "direct_process": bool(separator)
            and loaded_exec == f"{{ path={command[0]} ; argv[]={' '.join(command)}"
            and process["cmdline"] == contract["process_command"],
            "credential": unit["LoadCredential"] == contract["credential"],
            "principal": unit["User"] == contract["user"]
            and unit["Group"] == contract["group"]
            and unit["SupplementaryGroups"] == contract["supplementary_groups"],
            "hardening": unit["ActiveState"] == "active"
            and unit["SubState"] == "running"
            and unit["Result"] == "success"
            and unit["ExecMainStatus"] == "0"
            and unit["AmbientCapabilities"] == ""
            and unit["CapabilityBoundingSet"] == ""
            and unit["NoNewPrivileges"] == "yes"
            and unit["PrivateMounts"] == "yes"
            and unit["PrivateNetwork"] == contract["private_network"]
            and unit["ProtectSystem"] == "strict"
            and set(unit["RestrictAddressFamilies"].split())
            == contract["address_families"],
            "read_only_paths": set(unit["ReadOnlyPaths"].split())
            == contract["read_only"],
            "read_write_paths": set(unit["ReadWritePaths"].split())
            == contract["read_write"],
            "inaccessible_paths": set(unit["InaccessiblePaths"].split())
            == contract["inaccessible"],
        }
    boundaries = {
        "units": units,
        "processes": processes,
        "mounts": {
            "gateway_root": systemd_probe._mount(gateway_pid, "/"),
            "gateway_runtime": systemd_probe._mount(gateway_pid, "/runtime"),
            "gateway_worker_socket": systemd_probe._mount(
                gateway_pid, str(_WORKER_SOCKET.parent)
            ),
            "worker_root": systemd_probe._mount(worker_pid, "/"),
        },
        "covered_read_only_paths": {
            str(_PLUGIN): "gateway_root",
            str(lineage._PROTECTED): "worker_root",
            str(lineage._PROTECTED_INSTALL_ROOT): "worker_root",
        },
        "sockets": {
            "worker_directory": worker_directory,
            "worker": worker_socket,
            "sensor": sensor_socket,
            "broker": broker_socket,
        },
        "loaded_unit_checks": loaded_unit_checks,
        "forbidden_reads": {
            "gateway": _namespace_read_checks(
                gateway_pid,
                gateway.pw_uid,
                gateway_gid,
                [],
                [
                    _GATEWAY_CONFIG,
                    _GATEWAY_ENVIRONMENT,
                    _WORKER_BINDING,
                    _RUNTIME_BINDING,
                    _OBSERVATION_BINDING,
                    _GRANT_SOURCE,
                    lineage._CONTROL,
                    lineage._PROTECTED,
                    lineage._PROTECTED_INSTALL_ROOT,
                    _SENSOR_SOCKET,
                ],
            ),
            "worker": _namespace_read_checks(
                worker_pid,
                worker.pw_uid,
                worker_gid,
                [gateway_gid],
                [
                    _WORKER_BINDING,
                    _RUNTIME_BINDING,
                    _OBSERVATION_BINDING,
                    _GRANT_SOURCE,
                    lineage._CONTROL,
                    lineage._STAGING,
                    _GATEWAY_CONFIG,
                    _GATEWAY_ENVIRONMENT,
                    _GATEWAY_STATE,
                ],
            ),
        },
    }
    boundary_checks = {
        "socket_metadata": worker_directory["type"] == "directory"
        and worker_directory["uid"] == worker.pw_uid
        and worker_directory["gid"] == gateway_gid
        and worker_directory["mode"] == "0711"
        and worker_socket["type"] == "socket"
        and worker_socket["uid"] == worker.pw_uid
        and worker_socket["gid"] == gateway_gid
        and worker_socket["mode"] == "0660"
        and worker_socket["nlink"] == 1
        and sensor_socket["type"] == "socket"
        and sensor_socket["uid"] == sensor.pw_uid
        and sensor_socket["gid"] == worker_gid
        and sensor_socket["mode"] == "0660"
        and sensor_socket["nlink"] == 1
        and broker_socket["type"] == "socket"
        and broker_socket["uid"] == broker.pw_uid
        and broker_socket["gid"] == sensor_gid
        and broker_socket["mode"] == "0660"
        and broker_socket["nlink"] == 1,
        "gateway_identity": processes[_GATEWAY_UNIT]["uids"] == [gateway.pw_uid] * 4
        and processes[_GATEWAY_UNIT]["gids"] == [gateway_gid] * 4
        and processes[_GATEWAY_UNIT]["groups"] == [gateway_gid],
        "worker_identity": processes[_WORKER_UNIT]["uids"] == [worker.pw_uid] * 4
        and processes[_WORKER_UNIT]["gids"] == [worker_gid] * 4
        and processes[_WORKER_UNIT]["groups"] == sorted([worker_gid, gateway_gid]),
        "no_effective_capabilities": all(
            processes[name]["capabilities_effective"] == "0000000000000000"
            and processes[name]["no_new_privileges"] == 1
            for name in (_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT)
        ),
        "read_only_mounts": all(
            "ro" in mount["mount_options"] for mount in boundaries["mounts"].values()
        ),
        "covered_read_only_paths": boundaries["covered_read_only_paths"]
        == {
            str(_PLUGIN): "gateway_root",
            str(lineage._PROTECTED): "worker_root",
            str(lineage._PROTECTED_INSTALL_ROOT): "worker_root",
        }
        and all(
            Path(requested_path).is_absolute()
            and Path(requested_path).is_relative_to(
                boundaries["mounts"][mount_name]["mount_point"]
            )
            for requested_path, mount_name in boundaries[
                "covered_read_only_paths"
            ].items()
        ),
        "unit_dependency": units[_GATEWAY_UNIT]["User"] == "aragorn-agent-gateway"
        and units[_WORKER_UNIT]["User"] == "aragorn-runtime"
        and units[_GATEWAY_UNIT]["SupplementaryGroups"] == ""
        and "aragorn-agent-gateway" in units[_WORKER_UNIT]["SupplementaryGroups"],
        "loaded_new_units": all(
            all(checks.values()) for checks in loaded_unit_checks.values()
        ),
    }
    _expect(
        all(boundary_checks.values()),
        "unit, mount, socket, or process boundary changed: "
        + repr(
            {
                "boundaries": boundary_checks,
                "loaded_units": loaded_unit_checks,
            }
        ),
    )

    _set_stage("DRIVER_REDACTION_BOUNDARY")
    config_raw = canonical_json(config)
    authority_fields = (
        b"activeSkillDigest",
        b"expectedBrokerUid",
        b"expectedRuntimeDigest",
        b"expectedRuntimeGid",
        b"expectedRuntimeUid",
        b"expectedSensorUid",
        b"policyDigest",
        b"policyVersion",
        b"protectedRoot",
        b"runtimeDigest",
        b"sensorSocketPath",
    )
    gateway_authority_pins_absent = all(
        field not in config_raw for field in authority_fields
    )
    drivers = (
        legacy_driver,
        mismatch_driver,
        unavailable_driver,
        stale_driver,
        coherent_driver,
    )
    forbidden_driver_fields = {
        driver["input"]["scenario"]["id"]: _forbidden_driver_fields(driver)
        for driver in drivers
    }
    driver_authority_pins_absent = not any(forbidden_driver_fields.values())
    driver_raw = b"\n".join(canonical_json(driver) for driver in drivers)
    forbidden_driver_values = _digest_values(
        [
            action,
            policy,
            legacy_profile_document,
            worker_profile_document,
            coherent_worker_binding,
            mismatched_worker_binding,
            legacy_grant,
            grant,
            legacy_controls,
            controls,
        ]
    )
    forbidden_driver_values.update(coherent_after["controls"].values())
    forbidden_driver_values.update(
        {
            legacy_grant["grant_id"],
            legacy_grant_digest,
            grant["grant_id"],
            grant_digest,
            grant["schema"],
            grant["authority"],
            lease["lease_nonce"],
            lease["schema"],
            lease["authority"],
            policy_digest,
        }
    )
    driver_authority_values_absent = all(
        value.encode() not in driver_raw for value in forbidden_driver_values
    )
    secret_absent = capability._runtime_facing_secret_absence(
        tuple(driver["output"] for driver in drivers),
        grant,
        grant_digest,
        lease,
    ) and all(
        token.encode() not in config_raw
        and all(token.encode() not in canonical_json(driver) for driver in drivers)
        for token in tokens.values()
    )
    _expect(
        gateway_authority_pins_absent
        and driver_authority_pins_absent
        and driver_authority_values_absent
        and secret_absent,
        "gateway retained an authority pin or secret",
    )

    _set_stage("OBSERVATION_ASSEMBLY")
    result = {
        "schema": "aragorn/runtime-action-worker-openclaw-systemd-observation/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_7B_WORKER_TRUST_SPLIT_OBSERVED",
            "verifier_status": "NOT_TESTED",
            "retained_evidence_eligible": False,
            "legacy_openclaw_profile_rejected_observed": True,
            "unauthorized_worker_peer_rejected_observed": True,
            "worker_endpoint_unavailable_not_submitted_observed": True,
            "worker_binding_mismatch_indeterminate_observed": True,
            "stale_active_record_indeterminate_observed": True,
            "coherent_worker_allow_created_observed": True,
            "one_grant_consumption_observed": True,
            "worker_pid_attribution_observed": True,
            "aggregate_gate_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "harness": harness,
        "artifacts": artifacts,
        "identities": identities,
        "runtime": runtime,
        "profiles": {
            "legacy_openclaw": {
                "digest": legacy_profile.digest,
                "document": legacy_profile_document,
            },
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
            "control_sets": {
                "legacy": legacy_controls,
                "worker": controls,
                "stale_refresh": stale_controls,
                "coherent_refresh": coherent_controls,
            },
            "worker_binding": coherent_worker_binding,
            "worker_binding_mismatch": mismatched_worker_binding,
            "legacy_grant": {
                "digest": legacy_grant_digest,
                "document": legacy_grant,
            },
            "grant": {"digest": grant_digest, "document": grant},
            "active_record": coherent_record,
            "stale_active_record": stale_record,
            "producer": {
                "transaction": producer["transaction"],
                "record": producer["record"],
                "skill": _file(skill_path),
                "projected_skill": _file(projected_skill),
            },
            "gateway_config": config,
            "gateway_authority_pins_absent": gateway_authority_pins_absent,
            "driver_authority_pins_absent": driver_authority_pins_absent,
            "driver_authority_values_absent": driver_authority_values_absent,
            "gateway_secrets_retained": False,
        },
        "boundaries": {**boundaries, "checks": boundary_checks},
        "peer_chain": {
            "expected": expected_peer_chain,
            "observed": coherent_traces,
            "one_send_no_retry": coherent_checks["one_send_no_retry"],
        },
        "cases": {
            "legacy_openclaw_profile": {
                "status": "OBSERVED",
                "checks": legacy_checks,
                "effects": {"before": legacy_before, "after": legacy_after},
                "driver": legacy_driver,
                "traces": legacy_traces,
            },
            "unauthorized_worker_peer": {
                "status": "OBSERVED",
                "checks": unauthorized_checks,
                "effects": {
                    "before": unauthorized_before,
                    "after": unauthorized_after,
                },
                "client": unauthorized_result,
                "traces": unauthorized_traces,
            },
            "worker_endpoint_unavailable": {
                "status": "OBSERVED",
                "checks": unavailable_checks,
                "effects": {
                    "before": unavailable_before,
                    "after": unavailable_after,
                },
                "endpoint_identity": endpoint_identity,
                "service_pids": {
                    "before": stable_pids,
                    "after": stable_pids_after,
                },
                "driver": unavailable_driver,
                "traces": unavailable_traces,
            },
            "worker_binding_mismatch": {
                "status": "OBSERVED",
                "checks": mismatch_checks,
                "effects": {
                    "before": mismatch_before,
                    "after": mismatch_after,
                },
                "driver": mismatch_driver,
                "traces": mismatch_traces,
            },
            "stale_active_record": {
                "status": "OBSERVED",
                "checks": stale_checks,
                "effects": {"before": stale_before, "after": stale_after},
                "driver": stale_driver,
                "traces": stale_traces,
            },
            "coherent": {
                "status": "OBSERVED",
                "checks": coherent_checks,
                "effects": {"before": coherent_before, "after": coherent_after},
                "driver": coherent_driver,
                "traces": coherent_traces,
                "receipt": receipt,
                "receipt_file": receipt_file,
                "broker_state": broker_state_record,
                "target": target,
                "correlation": correlation,
            },
        },
        "secret_checks": {
            "runtime_facing_authority_secret_absent": secret_absent,
            "driver_authority_pins_absent": driver_authority_pins_absent,
            "driver_authority_values_absent": driver_authority_values_absent,
            "forbidden_driver_fields": forbidden_driver_fields,
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
        },
    }
    encoded = canonical_json(result)
    _expect(
        all(token.encode() not in encoded for token in tokens.values()),
        "observation retained a gateway or provider token",
    )
    return result


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise openclaw.ProbeError(
            "collector requires root in the fixed systemd container"
        )
    _set_stage("HARNESS_CLOSURE")
    harness = _harness()
    try:
        return _collect_live(harness)
    finally:
        _stop_stack()
        _systemctl("stop", prior._SERVICE, check=False)


def _failure(exc: Exception) -> dict[str, Any]:
    error = str(exc).encode("utf-8", errors="replace")
    return {
        "schema": "aragorn/runtime-action-worker-openclaw-systemd-observation/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_7B_WORKER_TRUST_SPLIT_NOT_OBSERVED",
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
            "diagnostic": _byte_identity(error),
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
            "usage: runtime_action_worker_openclaw_systemd_probe.py "
            "[--output ABSENT_ABSOLUTE_PATH]",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - self-describe failed live capture
        result = _failure(exc)
        status = 2
    _publish(output, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
