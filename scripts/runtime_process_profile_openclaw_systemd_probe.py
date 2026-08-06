#!/usr/bin/env python3
"""Collect one bounded pinned-OpenClaw process-profile slice for P3.4b."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_openclaw_systemd_probe as openclaw_prior  # noqa: E402
import runtime_process_profile_systemd_probe as profile_prior  # noqa: E402
from aragorn.oci_worker_protocol import canonical_digest, canonical_json  # noqa: E402
from aragorn.runtime_action_broker import _action_digests, write_all  # noqa: E402
from aragorn.runtime_process_profile import (  # noqa: E402
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    runtime_process_profile,
)

_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL = _ROOT / "control"
_PROTECTED = _ROOT / "protected"
_STAGING = _ROOT / "staging"
_FRONTEND = Path("/run/aragorn-runtime-observation/sensor.sock")
_BACKEND = _CONTROL / "broker.sock"
_PENDING = _CONTROL / "profile-pending.json"
_RECEIPT = _CONTROL / "profile-receipt.json"
_HARNESS = Path("/run/aragorn-harness.json")
_SKILL = Path(
    "/opt/aragorn/runtime-profile/aragorn-runtime-composition/SKILL.md"
)
_OPENCLAW = Path("/runtime/lib/node_modules/openclaw/openclaw.mjs")
_NODE = Path("/usr/local/bin/node")
_PLUGIN = Path("/opt/aragorn/openclaw/aragorn-runtime-action")
_CONFIG = Path("/etc/aragorn/openclaw-profile/openclaw.json")
_STATE = Path("/var/lib/aragorn-openclaw-profile/state")
_WORKSPACE = Path("/var/lib/aragorn-openclaw-profile/workspace")
_HOME = Path("/var/lib/aragorn-openclaw-profile/home")
_DRIVER = Path(
    "/src/benchmark/runtime-process-profile-openclaw-systemd/"
    "openclaw-profile-driver.mjs"
)
_DRIVER_ROOT = Path("/run/aragorn-openclaw-profile-driver")
_DRIVER_INPUT = _DRIVER_ROOT / "input.json"
_DRIVER_OUTPUT = _DRIVER_ROOT / "output.json"
_BROKER_UNIT = "aragorn-runtime-profile-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-profile-observation-publisher.service"
_GATEWAY_UNIT = "aragorn-openclaw-profile.service"
_V1_UNITS = (
    "aragorn-runtime-observation-publisher.service",
    "aragorn-runtime-action-broker.service",
)
_RUNTIME_DIGEST = openclaw_prior._RUNTIME_DIGEST  # noqa: SLF001
_ENTRYPOINT_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_NODE_DIGEST = (
    "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
)
_PLUGIN_DIGEST = (
    "sha256:f4d85f02353d792589bfad11c9f01769f29c5c693f65bc5ed941564b4b034e5f"
)
_SKILL_NAME = openclaw_prior._SKILL_NAME  # noqa: SLF001
_SKILL_BYTES = (
    b"---\n"
    b"name: aragorn-runtime-composition\n"
    b"description: Exercise one bounded profiled OpenClaw create in the P3.4b fixture.\n"
    b"---\n\n"
    b"Call aragorn_runtime_create exactly once with the requested target and content.\n"
)
_SKILL_DIGEST = "sha256:" + hashlib.sha256(_SKILL_BYTES).hexdigest()
_SENSOR_DIGEST = profile_prior._SENSOR_DIGEST  # noqa: SLF001
_REVOCATION_SOURCE = profile_prior._REVOCATION_SOURCE  # noqa: SLF001
_SYSTEMD_BASE_IMAGE = profile_prior._SYSTEMD_BASE_IMAGE  # noqa: SLF001
_P34A_IMAGE = (
    "sha256:1b982fd3b9164ac10af300775ea0aa3fe382a134db93745f33f060d803a9aedc"
)
_NODE_IMAGE = {
    "architecture": "arm64",
    "id": "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf",
    "os": "linux",
    "reference": (
        "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
    ),
    "variant": "v8",
}
_TARGET = "openclaw-profile-allowed.txt"
_PAYLOAD = b"Aragorn P3.4b profiled OpenClaw create\n"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_SYSTEMD_PROCESS_PROFILE_ONLY_"
    "NOT_SEMANTIC_CAUSATION_AUTHORITY"
)
_LIMITATIONS = [
    "SINGLE_PINNED_OPENCLAW_CREATE_PROFILE_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_IS_CONSUMPTION_EVIDENCE_NOT_SEMANTIC_CAUSATION",
    "RUNTIME_DIGEST_IS_POLICY_IDENTITY_NOT_EXECUTABLE_IDENTITY",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "BEFORE_AFTER_PROCESS_SNAPSHOTS_NOT_CONTINUOUS_EXEC_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_GATEWAY_UNIT_SOURCE = Path(
    "/src/benchmark/runtime-process-profile-openclaw-systemd/"
    "aragorn-openclaw-profile.service"
)
_GATEWAY_UNIT_INSTALLED = Path(
    "/usr/lib/systemd/system/aragorn-openclaw-profile.service"
)
_GATEWAY_EXEC_START = (
    "/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs "
    "gateway run --allow-unconfigured --auth token --bind loopback --port 18789 "
    "--tailscale off --ws-log full"
)
_ARTIFACTS = {
    **profile_prior._ARTIFACTS,  # noqa: SLF001
    (
        "/src/benchmark/runtime-process-profile-openclaw-systemd/SKILL.md"
    ): "/opt/aragorn/runtime-profile/aragorn-runtime-composition/SKILL.md",
    str(_GATEWAY_UNIT_SOURCE): str(_GATEWAY_UNIT_INSTALLED),
    **{
        f"/src/packaging/openclaw/aragorn-runtime-action/{name}": (
            f"/opt/aragorn/openclaw/aragorn-runtime-action/{name}"
        )
        for name in ("index.js", "openclaw.plugin.json", "package.json")
    },
}

ProbeError = profile_prior.ProbeError
_expect = profile_prior._expect
_run = profile_prior._run
_systemctl = profile_prior._systemctl
_user = profile_prior._user
_group = profile_prior._group
_metadata = profile_prior._metadata
_file = profile_prior._file
_document = profile_prior._document
_process = profile_prior._process
_wait_path = profile_prior._wait_path
_write_control = profile_prior._write_control
_unit = profile_prior._unit
_wait_active = profile_prior._wait_active
_security_status = profile_prior._security_status
_cgroup = profile_prior._cgroup


def _sha256(path: Path) -> str:
    return profile_prior._sha256(path)  # noqa: SLF001


def _write_document(path: Path, document: object, uid: int, gid: int, mode: int) -> None:
    profile_prior._write_document(path, document, uid, gid, mode)  # noqa: SLF001


def _runtime_snapshot() -> dict[str, Any]:
    root = Path(str(_OPENCLAW)[: -len("/lib/node_modules/openclaw/openclaw.mjs")])
    _expect(_OPENCLAW.resolve(strict=True) == _OPENCLAW, "runtime entrypoint moved")
    entries: list[dict[str, Any]] = []
    file_count = 0
    symlink_count = 0
    total_bytes = 0

    def walk(directory: Path, parts: tuple[str, ...] = ()) -> None:
        nonlocal file_count, symlink_count, total_bytes
        for item in sorted(os.scandir(directory), key=lambda candidate: candidate.name):
            _expect(item.name.isascii(), "runtime tree has a non-ASCII path")
            relative_parts = (*parts, item.name)
            relative = "/".join(relative_parts)
            metadata = item.stat(follow_symlinks=False)
            _expect(len(entries) < 100_000, "runtime tree entry limit exceeded")
            if item.is_dir(follow_symlinks=False):
                walk(Path(item.path), relative_parts)
            elif item.is_symlink():
                target = os.readlink(item.path)
                _expect(target.isascii(), "runtime tree has a non-ASCII symlink")
                entries.append({"kind": "symlink", "path": relative, "target": target})
                symlink_count += 1
            elif item.is_file(follow_symlinks=False) and metadata.st_size <= 128 * 1024 * 1024:
                digest = _sha256(Path(item.path))
                total_bytes += metadata.st_size
                _expect(total_bytes <= 1024 * 1024 * 1024, "runtime tree byte limit exceeded")
                entries.append(
                    {
                        "digest": digest,
                        "executable": bool(metadata.st_mode & 0o111),
                        "kind": "file",
                        "links": metadata.st_nlink,
                        "path": relative,
                        "size": metadata.st_size,
                    }
                )
                file_count += 1
            else:
                raise ProbeError(f"unsupported runtime tree entry: {relative}")

    walk(root)
    tree = {
        "algorithm": "aragorn/runtime-tree/v1",
        "entry_count": len(entries),
        "file_count": file_count,
        "symlink_count": symlink_count,
        "total_bytes": total_bytes,
        "tree_digest": canonical_digest(entries),
    }
    version = _run([str(_NODE), str(_OPENCLAW), "--version"]).stdout.decode().strip()
    snapshot = {
        "entrypoint": str(_OPENCLAW),
        "entrypoint_digest": _sha256(_OPENCLAW),
        "expected_version": "OpenClaw 2026.7.1 (2d2ddc4)",
        "root": str(root),
        "tree": tree,
        "version_output": version,
    }
    _expect(
        snapshot["entrypoint_digest"] == _ENTRYPOINT_DIGEST
        and tree
        == {
            "algorithm": "aragorn/runtime-tree/v1",
            "entry_count": 45856,
            "file_count": 45837,
            "symlink_count": 19,
            "total_bytes": 369317461,
            "tree_digest": _RUNTIME_DIGEST,
        }
        and version == snapshot["expected_version"],
        "pinned OpenClaw runtime inventory changed",
    )
    return snapshot


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    expected_keys = {
        "schema",
        "container_id",
        "image_id",
        "image_reference",
        "run_image_reference",
        "parent_image_id",
        "systemd_base_image_id",
        "node_image",
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
        and set(document) == expected_keys
        and document["schema"]
        == "aragorn/runtime-process-profile-openclaw-systemd-harness/v1"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and isinstance(document["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"]
        == "aragorn-p34b-runtime-profile-openclaw-systemd"
        and document["run_image_reference"] == document["image_id"]
        and document["parent_image_id"] == _P34A_IMAGE
        and document["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and document["node_image"] == _NODE_IMAGE
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.4b"
        and document["openclaw_runtime_volume"]
        == "aragorn-openclaw-2026-7-1-runtime"
        and document["openclaw_runtime_volume_identity"]
        == {
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "driver": "local",
            "labels": None,
            "options": None,
            "scope": "local",
        },
        "outer P3.4b harness identity changed",
    )
    _expect(
        document["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        }
        and document["host_config"]
        == {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
            ],
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
        },
        "outer P3.4b host profile changed",
    )
    lineage = document["image_lineage"]
    _expect(
        isinstance(lineage, dict)
        and set(lineage) == {"parent", "child", "added_layers"}
        and all(
            isinstance(lineage[name], dict)
            and set(lineage[name]) == {"id", "rootfs_type", "layers"}
            and lineage[name]["rootfs_type"] == "layers"
            and isinstance(lineage[name]["layers"], list)
            and all(
                isinstance(layer, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", layer)
                for layer in lineage[name]["layers"]
            )
            for name in ("parent", "child")
        )
        and lineage["parent"]["id"] == _P34A_IMAGE
        and lineage["child"]["id"] == document["image_id"]
        and lineage["child"]["layers"][: len(lineage["parent"]["layers"])]
        == lineage["parent"]["layers"]
        and lineage["added_layers"]
        == lineage["child"]["layers"][len(lineage["parent"]["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.4b image lineage changed",
    )
    return retained


def _gateway_config(
    policy: dict[str, Any], plugin_digest: str, identities: dict[str, int]
) -> dict[str, Any]:
    return {
        "agents": {
            "defaults": {
                "model": {"primary": "aragorn-runtime-action-mock/fixture-model"},
                "skills": [_SKILL_NAME],
                "workspace": str(_WORKSPACE),
            },
            "list": [
                {
                    "id": "main",
                    "skills": [_SKILL_NAME],
                    "workspace": str(_WORKSPACE),
                }
            ],
        },
        "models": {
            "mode": "replace",
            "providers": {
                "aragorn-runtime-action-mock": {
                    "api": "openai-completions",
                    "apiKey": "aragorn-runtime-action-mock-local",
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
                            "id": "fixture-model",
                            "input": ["text"],
                            "maxTokens": 256,
                            "name": "Aragorn deterministic runtime-action fixture",
                            "reasoning": False,
                        }
                    ],
                    "timeoutSeconds": 10,
                }
            },
        },
        "plugins": {
            "allow": ["aragorn-runtime-action"],
            "enabled": True,
            "entries": {
                "aragorn-runtime-action": {
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
                    "enabled": True,
                }
            },
            "load": {"paths": [str(_PLUGIN)]},
        },
        "skills": {
            "load": {
                "allowSymlinkTargets": [],
                "extraDirs": [str(_SKILL.parent)],
                "watch": False,
            }
        },
        "tools": {"alsoAllow": ["aragorn_runtime_create"]},
    }


def _cgroup_processes(cgroup: str) -> list[int]:
    root = Path("/sys/fs/cgroup").joinpath(*cgroup.lstrip("/").split("/"))
    _expect(
        not any(item.is_dir() for item in root.iterdir()),
        "gateway cgroup has delegated descendants",
    )
    return sorted(int(line) for line in (root / "cgroup.procs").read_text().splitlines())


def _mount_namespace(pid: int) -> dict[str, int]:
    value = os.stat(f"/proc/{pid}/ns/mnt")
    return {"device": value.st_dev, "inode": value.st_ino}


def _stop_units() -> None:
    _systemctl(
        "stop",
        _GATEWAY_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        *_V1_UNITS,
        check=False,
    )


def _reset() -> None:
    _stop_units()
    _systemctl(
        "reset-failed",
        _GATEWAY_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        check=False,
    )
    _run(
        [
            "systemd-tmpfiles",
            "--create",
            "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf",
        ]
    )
    for directory in (_PROTECTED, _STAGING):
        for child in directory.iterdir():
            _expect(not child.is_dir(), f"unexpected fixture directory: {child}")
            child.unlink()
    for name in (
        "health.json",
        "observation.json",
        "policy.json",
        "profile-pending.json",
        "profile-receipt.json",
        "revocations.json",
        "state.json",
    ):
        (_CONTROL / name).unlink(missing_ok=True)
    for path in (
        Path("/etc/aragorn/runtime-action-runtime.json"),
        Path("/etc/aragorn/runtime-action-observation.json"),
        _CONFIG,
        _DRIVER_INPUT,
        _DRIVER_OUTPUT,
    ):
        path.unlink(missing_ok=True)


def _system_prompt(driver: dict[str, Any]) -> str:
    records = driver.get("provider", {}).get("records", [])
    _expect(len(records) == 2, "deterministic provider request count changed")
    messages = records[0].get("body", {}).get("messages", [])
    _expect(isinstance(messages, list), "provider messages are invalid")
    return "\n".join(
        message.get("content", "")
        for message in messages
        if isinstance(message, dict)
        and message.get("role") == "system"
        and isinstance(message.get("content"), str)
    )


def _driver_result(driver: dict[str, Any]) -> dict[str, Any] | None:
    result = (
        driver.get("scenario", {})
        .get("proof", {})
        .get("retained_tool_result", {})
        .get("result")
    )
    return result if isinstance(result, dict) else None


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    identities = {
        "broker_uid": broker.pw_uid,
        "runtime_uid": runtime.pw_uid,
        "runtime_gid": runtime_gid,
        "sensor_uid": sensor.pw_uid,
        "sensor_gid": sensor_gid,
    }
    _expect(
        len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) == 3,
        "service UIDs overlap",
    )
    artifacts = []
    for source, installed in sorted(_ARTIFACTS.items()):
        source_file = _file(Path(source))
        installed_file = _file(Path(installed))
        _expect(
            source_file["digest"] == installed_file["digest"]
            and source_file["bytes"] == installed_file["bytes"],
            f"installed artifact differs from source: {installed}",
        )
        artifacts.append(
            {
                "source_path": source,
                "installed_path": installed,
                "source_digest": source_file["digest"],
                "installed_digest": installed_file["digest"],
                "source_bytes": source_file["bytes"],
                "installed_bytes": installed_file["bytes"],
                "installed_stat": installed_file["stat"],
            }
        )
    skill = _file(_SKILL)
    _expect(
        _SKILL.read_bytes() == _SKILL_BYTES
        and skill["digest"] == _SKILL_DIGEST
        and skill["stat"]["uid"] == 0
        and skill["stat"]["gid"] == 0
        and skill["stat"]["mode"] == "0444"
        and skill["stat"]["nlink"] == 1,
        "root-owned OpenClaw skill pin changed",
    )
    _, plugin_digest = openclaw_prior._plugin_artifacts()  # noqa: SLF001
    _expect(plugin_digest == _PLUGIN_DIGEST, "frozen P3.3c plugin changed")
    node = _file(_NODE)
    _expect(node["digest"] == _NODE_DIGEST, "pinned Node executable changed")
    executable_digest = node["digest"]
    runtime_snapshot = _runtime_snapshot()

    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(protected_fd, _TARGET, _PAYLOAD)
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-4b-pinned-openclaw-process-profile",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": _SENSOR_DIGEST,
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": _RUNTIME_DIGEST,
                "active_skill_digest": _SKILL_DIGEST,
                **action,
            }
        ],
    }
    config = _gateway_config(policy, plugin_digest, identities)
    _CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_document(_CONFIG, config, 0, 0, 0o444)

    verification = _run(
        [
            "systemd-analyze",
            "verify",
            f"/usr/lib/systemd/system/{_BROKER_UNIT}",
            f"/usr/lib/systemd/system/{_SENSOR_UNIT}",
            f"/usr/lib/systemd/system/{_GATEWAY_UNIT}",
        ]
    )
    _systemctl("daemon-reload")
    _systemctl("start", _GATEWAY_UNIT)
    gateway_unit = _wait_active(_GATEWAY_UNIT)
    time.sleep(0.25)
    gateway_unit = _unit(_GATEWAY_UNIT)
    if gateway_unit["ActiveState"] != "active" or gateway_unit["MainPID"] == "0":
        journal = _run(
            [
                "journalctl",
                "--no-pager",
                "--output=cat",
                "--unit",
                _GATEWAY_UNIT,
                "--lines=40",
            ],
            check=False,
        ).stdout.decode(errors="replace")
        raise ProbeError(f"systemd gateway exited during startup: {journal[-4000:]}")
    gateway_pid = int(gateway_unit["MainPID"])
    gateway_cgroup = _cgroup(gateway_pid)
    gateway_before = _process(gateway_pid)
    gateway_namespace = _mount_namespace(gateway_pid)
    gateway_security = _security_status(gateway_pid)
    gateway_exec_start = (
        "{ path=/usr/local/bin/node ; argv[]=" + _GATEWAY_EXEC_START
    )
    loaded_gateway_exec, exec_separator, _exec_metadata = gateway_unit[
        "ExecStart"
    ].partition(" ; ignore_errors=")
    gateway_profile_checks = {
        "unit_active": (
            gateway_unit["ActiveState"] == "active"
            and gateway_unit["SubState"] == "running"
            and gateway_unit["Result"] == "success"
            and gateway_unit["ExecMainStatus"] == "0"
        ),
        "loaded_fragment_matches_source": (
            gateway_unit["FragmentResolvedPath"] == str(_GATEWAY_UNIT_INSTALLED)
            and gateway_unit["FragmentDigest"]
            == _file(_GATEWAY_UNIT_SOURCE)["digest"]
            and gateway_unit["DropInPaths"] == ""
        ),
        "direct_exec_start": bool(exec_separator)
        and loaded_gateway_exec == gateway_exec_start,
        "unit_principal": (
            gateway_unit["User"] == "aragorn-runtime"
            and gateway_unit["Group"] == "aragorn-runtime"
            and gateway_unit["SupplementaryGroups"] == ""
        ),
        "unit_privilege_floor": (
            gateway_unit["AmbientCapabilities"] == ""
            and gateway_unit["CapabilityBoundingSet"] == ""
            and gateway_unit["NoNewPrivileges"] == "yes"
        ),
        "main_pid_matches": gateway_before["pid"] == gateway_pid,
        "cgroup_matches_unit": gateway_unit["ControlGroup"] == gateway_cgroup,
        "cgroup_is_singleton": _cgroup_processes(gateway_cgroup) == [gateway_pid],
        "uids_match": gateway_before["uids"] == [runtime.pw_uid] * 4,
        "gids_match": gateway_before["gids"] == [runtime_gid] * 4,
        "groups_match": gateway_before["groups"] == [runtime_gid],
        "effective_capabilities_empty": (
            gateway_before["capabilities_effective"] == "0000000000000000"
        ),
        "all_capabilities_empty": all(
            value["value"] == 0
            for value in gateway_security["capabilities"].values()
        ),
        "no_new_privileges": gateway_before["no_new_privileges"] == 1,
        "security_status_no_new_privileges": (
            gateway_security["no_new_privileges"] == 1
        ),
        "executable_matches": (
            os.path.realpath(f"/proc/{gateway_pid}/exe") == str(_NODE)
        ),
    }
    _expect(
        all(gateway_profile_checks.values()),
        "systemd gateway process profile changed: "
        + ",".join(
            name for name, matched in gateway_profile_checks.items() if not matched
        )
        + f";pid={gateway_pid};process={gateway_before};"
        + f"exe={os.path.realpath(f'/proc/{gateway_pid}/exe')}",
    )
    profile_document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": _RUNTIME_DIGEST,
        "executable_digest": executable_digest,
        "cgroup": gateway_cgroup,
        "skill_path": str(_SKILL),
    }
    profile = runtime_process_profile(profile_document)

    seed = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "seed-p3-4b",
        "run_id": "seed-p3-4b",
        "tool_call_id": "seed-p3-4b",
        "active_skill_digest": _SKILL_DIGEST,
    }
    now = int(time.time())
    controls = {
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
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        },
        "observation": {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": _SENSOR_DIGEST,
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": {"schema": "aragorn/runtime-active-context/v1", **seed},
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **seed,
                **action,
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
    for name, document in controls.items():
        _write_control(_CONTROL / f"{name}.json", document, broker.pw_uid, runtime_gid)
    etc = Path("/etc/aragorn")
    _write_document(
        etc / "runtime-action-runtime.json",
        {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": _RUNTIME_DIGEST,
            "runtime_profile_digest": profile.digest,
        },
        0,
        0,
        0o400,
    )
    _write_document(
        etc / "runtime-action-observation.json",
        {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": _SENSOR_DIGEST,
            "runtime_profile": profile_document,
        },
        0,
        0,
        0o400,
    )
    _systemctl("start", _BROKER_UNIT)
    _systemctl("start", _SENSOR_UNIT)
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    broker_unit = _wait_active(_BROKER_UNIT)
    sensor_unit = _wait_active(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])

    _DRIVER_ROOT.mkdir(mode=0o700)
    os.chown(_DRIVER_ROOT, runtime.pw_uid, runtime_gid)
    driver_input = {
        "schema": "aragorn/openclaw-profile-driver-input/v1",
        "scenario": {
            "id": "allow",
            "target_name": _TARGET,
            "content": _PAYLOAD.decode(),
            "expected_verdict": "ALLOW",
            "expected_effect_status": "CREATED",
        },
    }
    profile_prior._write_file(  # noqa: SLF001
        _DRIVER_INPUT, canonical_json(driver_input) + b"\n", 0, runtime_gid, 0o440
    )
    sensor_trace_path = _DRIVER_ROOT / "sensor.trace"
    broker_trace_path = _DRIVER_ROOT / "broker.trace"
    sensor_trace = profile_prior.prior._start_trace(  # noqa: SLF001
        sensor_pid, sensor_trace_path
    )
    broker_trace = profile_prior.prior._start_trace(  # noqa: SLF001
        broker_pid, broker_trace_path
    )
    driver_started = time.monotonic_ns()
    driver_process = subprocess.run(
        [
            "setpriv",
            f"--reuid={runtime.pw_uid}",
            f"--regid={runtime_gid}",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            str(_NODE),
            str(_DRIVER),
            str(_DRIVER_INPUT),
            str(_DRIVER_OUTPUT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "HOME": str(_HOME),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": str(_CONFIG),
            "OPENCLAW_GATEWAY_TOKEN": "aragorn-p34b-gateway-token-v1",
            "OPENCLAW_STATE_DIR": str(_STATE),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
        timeout=45,
        check=False,
    )
    driver_elapsed_ns = time.monotonic_ns() - driver_started
    driver = _document(_DRIVER_OUTPUT)["document"] if _DRIVER_OUTPUT.exists() else {}
    result = _driver_result(driver)
    passed = (
        driver_process.returncode == 0
        and driver.get("gateway", {})
        .get("system_info", {})
        .get("response", {})
        .get("pid")
        == gateway_pid
        and result is not None
        and result.get("verdict") == "ALLOW"
        and result.get("effect_status") == "CREATED"
        and _RECEIPT.exists()
        and (_PROTECTED / _TARGET).exists()
    )
    if passed:
        sensor_peer_trace = profile_prior.prior._trace(  # noqa: SLF001
            sensor_trace, sensor_trace_path, sensor_pid, ["accept", "connect"]
        )
        broker_peer_trace = profile_prior.prior._trace(  # noqa: SLF001
            broker_trace, broker_trace_path, broker_pid, ["accept"]
        )
    else:
        for tracer in (sensor_trace, broker_trace):
            tracer.send_signal(signal.SIGINT)
            try:
                tracer.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tracer.kill()
                tracer.wait(timeout=3)
        sensor_peer_trace = {
            "raw": sensor_trace_path.read_text(),
            "raw_digest": _sha256(sensor_trace_path),
            "peer_credentials": [],
        }
        broker_peer_trace = {
            "raw": broker_trace_path.read_text(),
            "raw_digest": _sha256(broker_trace_path),
            "peer_credentials": [],
        }

    gateway_after = _process(gateway_pid)
    prompt = _system_prompt(driver) if driver else ""
    receipt = _document(_RECEIPT) if _RECEIPT.exists() else None
    receipt_file = _file(_RECEIPT) if _RECEIPT.exists() else None
    target = _file(_PROTECTED / _TARGET) if (_PROTECTED / _TARGET).exists() else None
    state = _document(_CONTROL / "state.json")
    control_after = {
        path.name: _sha256(path)
        for path in (
            *(
                _CONTROL / f"{name}.json"
                for name in ("policy", "revocations", "health", "observation", "state")
            ),
            _RECEIPT,
        )
        if path.exists()
    }
    credentials = {
        "broker": _document(etc / "runtime-action-runtime.json"),
        "sensor": _document(etc / "runtime-action-observation.json"),
    }
    if passed:
        attribution = receipt["document"]["runtime_attribution"]
        _expect(
            sensor_peer_trace["peer_credentials"]
            == [
                {"pid": gateway_pid, "uid": runtime.pw_uid, "gid": runtime_gid},
                {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
            ]
            and broker_peer_trace["peer_credentials"]
            == [{"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid}],
            "SO_PEERCRED chain did not bind the gateway MainPID",
        )
        version = _SKILL_DIGEST[:23]
        description = (
            "Exercise one bounded profiled OpenClaw create in the P3.4b fixture."
        )
        _expect(
            prompt.count(f"<name>{_SKILL_NAME}</name>") == 1
            and prompt.count(f"<description>{description}</description>") == 1
            and prompt.count(f"<location>{_SKILL}</location>") == 1
            and prompt.count(f"<version>{version}</version>") == 1,
            "provider prompt did not project the exact root-owned skill pin",
        )
        receipt_document = receipt["document"]
        _expect(
            receipt_document.get("schema")
            == "aragorn/runtime-process-profile-receipt/v1"
            and receipt_document.get("broker_result") == result
            and receipt_document.get("broker_result_digest")
            == canonical_digest(result)
            and receipt_document.get("runtime_attribution_digest")
            == canonical_digest(attribution)
            and attribution.get("profile_digest") == profile.digest
            and attribution.get("runtime_digest") == _RUNTIME_DIGEST
            and attribution.get("executable_digest") == executable_digest
            and attribution.get("active_skill_digest") == _SKILL_DIGEST
            and attribution.get("skill_path") == str(_SKILL)
            and attribution.get("cgroup") == gateway_cgroup
            and attribution.get("pid") == gateway_pid
            and attribution.get("uid") == runtime.pw_uid
            and attribution.get("gid") == runtime_gid
            and attribution.get("start_time_ticks")
            == int(gateway_before["start_time_ticks"])
            and attribution.get("mount_namespace") == gateway_namespace
            and result.get("target_name") == _TARGET
            and target["digest"] == action["payload_digest"]
            and target["stat"]["uid"] == broker.pw_uid
            and target["stat"]["gid"] == runtime_gid
            and target["stat"]["mode"] == "0400"
            and target["stat"]["nlink"] == 1
            and receipt_file["stat"]["uid"] == broker.pw_uid
            and receipt_file["stat"]["gid"] == runtime_gid
            and receipt_file["stat"]["mode"] == "0400"
            and receipt_file["stat"]["nlink"] == 1
            and not _PENDING.exists()
            and len(state["document"]["consumed"]) == 1
            and state["document"]["effect_journal"] is None
            and _cgroup_processes(gateway_cgroup) == [gateway_pid]
            and gateway_after["start_time_ticks"] == gateway_before["start_time_ticks"]
            and gateway_after["mount_namespace"] == gateway_before["mount_namespace"],
            "durable receipt, target, or live gateway binding changed",
        )

    return {
        "schema": "aragorn/runtime-process-profile-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_4B_OPENCLAW_PROFILE_OBSERVED" if passed else "P3_4B_BUDGET_OR_GATE_FAILURE",
            "profiled_openclaw_allow_created_observed": passed,
            "gateway_main_pid_peer_bound": passed,
            "root_owned_skill_prompt_projection_observed": passed,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "public_release_eligible": False,
        },
        "harness": harness,
        "environment": {
            "platform": sys.platform,
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
            "python": platform.python_version(),
            "node": node,
            "capture_identity": profile_prior._identity(),  # noqa: SLF001
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
        },
        "artifacts": artifacts,
        "collector": {
            "probe": _file(Path(__file__).resolve()),
            "openclaw_helper": _file(
                Path("/src/scripts/runtime_action_openclaw_systemd_probe.py")
            ),
            "profile_probe": _file(
                Path("/src/scripts/runtime_process_profile_systemd_probe.py")
            ),
            "systemd_probe": _file(
                Path("/src/scripts/runtime_action_systemd_probe.py")
            ),
            "dockerfile": _file(
                Path(
                    "/src/benchmark/runtime-process-profile-openclaw-systemd/"
                    "Dockerfile"
                )
            ),
            "driver": _file(_DRIVER),
            "recipe": _file(
                Path(
                    "/src/scripts/"
                    "capture_runtime_process_profile_openclaw_systemd.sh"
                )
            ),
        },
        "profile": {
            "digest": profile.digest,
            "document": profile_document,
            "skill": skill,
            "executable": node,
        },
        "runtime": runtime_snapshot,
        "credentials": credentials,
        "identities": {
            "broker": {"uid": broker.pw_uid, "gid": runtime_gid},
            "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
            "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
        },
        "inputs": {
            "gateway_config": config,
            "gateway_config_digest": canonical_digest(config),
            "driver": driver_input,
            "policy": policy,
            "action": action,
            "initial_controls": controls,
        },
        "deployment": {
            "directories": {
                "root": _metadata(_ROOT),
                "control": _metadata(_CONTROL),
                "protected": _metadata(_PROTECTED),
                "staging": _metadata(_STAGING),
                "runtime": _metadata(_FRONTEND.parent),
            },
            "units": {
                "gateway": gateway_unit,
                "broker": broker_unit,
                "sensor": sensor_unit,
            },
            "processes": {
                "gateway_before": gateway_before,
                "gateway_after": gateway_after,
                "broker": _process(broker_pid),
                "sensor": _process(sensor_pid),
            },
            "security": {
                "gateway": gateway_security,
                "broker": _security_status(broker_pid),
                "sensor": _security_status(sensor_pid),
            },
            "gateway_cgroup_processes": _cgroup_processes(gateway_cgroup),
            "sockets": {
                "backend": _metadata(_BACKEND),
                "frontend": _metadata(_FRONTEND),
            },
        },
        "peer_trace": {"sensor": sensor_peer_trace, "broker": broker_peer_trace},
        "timing": {
            "sensor_deadline_ms": 500,
            "client_deadline_ms": 750,
            "driver_elapsed_ns": driver_elapsed_ns,
            "driver_elapsed_ms": driver_elapsed_ns // 1_000_000,
            "deadline_outcome": (
                "COMPLETED_WITHIN_ENFORCED_NESTED_DEADLINES"
                if passed
                else "FAILED_OR_EXCEEDED_ENFORCED_NESTED_DEADLINES"
            ),
            "note": "driver elapsed includes provider and gateway RPC overhead",
        },
        "scenario": {
            "status": "PASS" if passed else "FAIL",
            "driver_exit_code": driver_process.returncode,
            "driver_stdout": driver_process.stdout.decode(errors="replace"),
            "driver_stderr": driver_process.stderr.decode(errors="replace"),
            "driver": driver,
            "provider_system_prompt": prompt,
            "receipt": receipt,
            "receipt_file": receipt_file,
            "control_after": control_after,
            "target": target,
            "profile_pending_exists": _PENDING.exists(),
            "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
            "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
            "state": state,
        },
    }


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise ProbeError("collector requires root in the fixed systemd container")
    harness = _harness()
    _reset()
    try:
        return _collect_live(harness)
    finally:
        _stop_units()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: Path | None = None
    if len(arguments) == 2 and arguments[0] == "--output":
        output_path = Path(arguments[1])
        result = _collect()
    elif not arguments:
        result = _collect()
    else:
        print(
            "usage: runtime_process_profile_openclaw_systemd_probe.py "
            "[--output ABSENT_PATH]",
            file=sys.stderr,
        )
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
    return 0 if result["scenario"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
