#!/usr/bin/env python3
"""Run P3.7c once under the exact final combined v2 profile without promoting routes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_activation_expiry_systemd_probe as p37c

openclaw = p37c.openclaw

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path("/evidence/runtime-action-worker-final-combined-v2-systemd.json")
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_CONFIG = _ADMISSION / "protected-final-combined-config-v2.json"
_PROFILE = _ADMISSION / "protected-final-combined-profile-v2.json"
_LOCK = _ADMISSION / "protected-final-combined-runtime-v2.lock.json"
_SKILL = Path("/opt/aragorn/runtime-profile/template-skill/SKILL.md")
_ACTIVATOR = Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh")
_PREFLIGHT = Path("/usr/lib/aragorn/aragorn/runtime_action_worker.py")
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_RUNTIME_DIGEST = (
    "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
)
_ENTRYPOINT_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_SKILL_DIGEST = (
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
)
_ACTIVATOR_DIGEST = (
    "sha256:e89b5c456d276e6c14b403a976db4a1fa9f7e4fa7ce4a35e6d1431a7a1b9de18"
)
_PREFLIGHT_DIGEST = (
    "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873"
)
_CONFIG_DIGEST = (
    "sha256:2772bca6629607247e2a5c056282b4748ab5bb6d024fd742c9755fb915281ddb"
)
_PROFILE_DIGEST = (
    "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc"
)
_LOCK_DIGEST = "sha256:c5773a0b8829d1dbdd9fa89d7dc93e995ee54ea723208daa59b0951d50e76fd5"
_PLUGIN_DIGESTS = {
    "index.js": "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
    "openclaw.plugin.json": (
        "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
    ),
    "package.json": "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
}
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_"
    "PROFILE_ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "ONE_PINNED_P3_7C_ACTIVATION_ACTION_FLOW_ONLY",
    "TWENTY_ONE_ADMISSION_ROUTES_REMAIN_NOT_TESTED",
    "ACTION_OBSERVATION_DOES_NOT_PROMOTE_ANY_ADMISSION_ROUTE",
    "FRESH_RUNTIME_PROFILE_AND_FRESH_SESSIONS_REQUIRED",
    "OPENCLAW_TEST_FAST_ABSENT",
    "PUBLIC_NETWORK_DENIED",
    "EXACT_SINGLETON_EXTERNAL_SKILL_SOURCE_ONLY",
    (
        "EXACT_PINNED_ARAGORN_TOOL_PLUGIN_READ_TOOL_WORKSPACE_AND_RESOLVED_SKILL_"
        "ROOTS_AND_LOOPBACK_PROVIDER_ONLY"
    ),
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_ELIGIBILITY_KEYS = {
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
}
_ROUTE_IDS = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_STAGE = "BOOTSTRAP"
_PARENT_ARTIFACTS = p37c._artifacts


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    p37c._expect(condition, message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_source(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = path.read_bytes()
    document = json.loads(
        raw,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    canonical = p37c.canonical_json(document)
    _expect(raw == canonical + b"\n", f"source is not canonical JSON plus LF: {path}")
    return document, {
        "source": p37c._file(path),
        "canonical_bytes": len(canonical),
        "canonical_digest": _digest(canonical),
    }


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    fields = {"route_input_mount", "route_input_volume_identity"}
    present = fields & set(document)
    _expect(present in (set(), fields), "partial route input harness changed")
    if not present:
        return None
    identity = document["route_input_volume_identity"]
    mount = document["route_input_mount"]
    _expect(
        isinstance(identity, dict)
        and set(identity) == {"driver", "labels", "name", "options", "scope"}
        and isinstance(identity.get("name"), str),
        "route input volume shape changed",
    )
    name = identity["name"]
    matched = re.fullmatch(
        r"aragorn-phase3-final-combined-v2-route-input-([1-9][0-9]*)", name
    )
    owner = f"{source_commit}:{matched.group(1)}" if matched else None
    _expect(
        identity
        == {
            "driver": "local",
            "labels": {
                "dev.aragorn.capture-owner": owner,
                "dev.aragorn.role": "final-combined-v2-route-input",
                "dev.aragorn.source-commit": source_commit,
            },
            "name": name,
            "options": None,
            "scope": "local",
        }
        and mount
        == {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": name,
            "type": "volume",
        },
        "route input volume identity changed",
    )
    return name


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    fields = {
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
    }
    _expect(
        set(document)
        in (fields, fields | {"route_input_mount", "route_input_volume_identity"}),
        "outer final combined v2 harness shape changed",
    )
    lineage = document.get("image_lineage", {})
    parent = lineage.get("parent", {})
    child = lineage.get("child", {})
    parent_layers = parent.get("layers")
    child_layers = child.get("layers")
    source_commit = document.get("source_commit", "")
    route_input_volume = _route_input_volume_name(document, source_commit)
    verification = document.get("source_commit_verification", {})
    commit_raw = p37c._raw_bytes(verification.get("commit_object", {}))
    verification_stdout = p37c._raw_bytes(verification.get("stdout", {}))
    verification_stderr = p37c._raw_bytes(verification.get("stderr", {}))
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    expected_volume = {
        "driver": "local",
        "labels": {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": ("7fa98d8e21b6d5937f25a7f19445ff683bb980bf"),
            "io.aragorn.source-tree": ("dd5ac3991f6dbce8b6e630e3e43644f64bc71d44"),
        },
        "name": _RUNTIME_VOLUME,
        "options": None,
        "scope": "local",
    }
    expected_binds = [
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        f"{_RUNTIME_VOLUME}:/runtime:ro",
    ]
    if route_input_volume is not None:
        expected_binds.append(f"{route_input_volume}:/route-input:ro")
    expected_host = {
        "binds": sorted(expected_binds),
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
        document.get("schema")
        == "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        and document.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and document.get("parent_image_id") == _PARENT_IMAGE
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v2-systemd"
        and document.get("run_image_reference") == document.get("image_id")
        and document.get("profile_label") == "phase3-final-combined-v2"
        and document.get("platform") == "linux"
        and document.get("openclaw_runtime_volume") == _RUNTIME_VOLUME
        and document.get("openclaw_runtime_volume_identity") == expected_volume
        and document.get("openclaw_runtime_mount")
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _RUNTIME_VOLUME,
            "type": "volume",
        }
        and document.get("host_config") == expected_host
        and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None
        and set(verification)
        == {"command", "exit_code", "commit_object", "stdout", "stderr"}
        and verification.get("command")
        == ["git", "verify-commit", "--raw", source_commit]
        and verification.get("exit_code") == 0
        and commit_identity == source_commit
        and commit_raw.startswith(b"tree ")
        and b"\ngpgsig " in commit_raw
        and verification_stdout == b""
        and verification_stderr == p37c._SOURCE_SIGNATURE
        and re.fullmatch(r"[0-9a-f]{64}", document.get("container_id", "")) is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document.get("image_id", ""))
        is not None
        and parent.get("id") == _PARENT_IMAGE
        and child.get("id") == document.get("image_id")
        and parent.get("rootfs_type") == child.get("rootfs_type") == "layers"
        and isinstance(parent_layers, list)
        and isinstance(child_layers, list)
        and child_layers[: len(parent_layers)] == parent_layers
        and lineage.get("added_layers") == child_layers[len(parent_layers) :]
        and bool(lineage.get("added_layers")),
        "outer final combined v2 harness identity changed",
    )
    return retained


def _runtime_snapshot() -> dict[str, Any]:
    _, runtime_lock = _canonical_source(_LOCK)
    lock = json.loads(_LOCK.read_bytes())
    expected = lock["installed_runtime"]
    root = Path(expected["root"])
    entrypoint = Path(expected["openclaw_path"])
    entries: list[dict[str, Any]] = []
    file_count = 0
    symlink_count = 0
    total_bytes = 0

    def walk(directory: Path, parts: tuple[str, ...] = ()) -> None:
        nonlocal file_count, symlink_count, total_bytes
        for item in sorted(os.scandir(directory), key=lambda value: value.name):
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
            elif item.is_file(follow_symlinks=False):
                _expect(
                    metadata.st_size <= 128 * 1024 * 1024, "runtime file limit exceeded"
                )
                total_bytes += metadata.st_size
                _expect(
                    total_bytes <= 1024 * 1024 * 1024, "runtime byte limit exceeded"
                )
                entries.append(
                    {
                        "digest": openclaw._sha256(Path(item.path)),
                        "executable": bool(metadata.st_mode & 0o111),
                        "kind": "file",
                        "links": metadata.st_nlink,
                        "path": relative,
                        "size": metadata.st_size,
                    }
                )
                file_count += 1
            else:
                raise openclaw.ProbeError(f"unsupported runtime tree entry: {relative}")

    _expect(entrypoint.resolve(strict=True) == entrypoint, "runtime entrypoint moved")
    walk(root)
    tree = {
        "algorithm": "aragorn/runtime-tree/v1",
        "entry_count": len(entries),
        "file_count": file_count,
        "symlink_count": symlink_count,
        "total_bytes": total_bytes,
        "tree_digest": p37c.canonical_digest(entries),
    }
    version = (
        openclaw._run([str(openclaw._NODE), str(entrypoint), "--version"])
        .stdout.decode()
        .strip()
    )
    _expect(
        tree == expected["runtime_tree"]
        and openclaw._sha256(entrypoint) == expected["openclaw_digest"]
        and version == expected["version_output"]
        and runtime_lock["source"]["digest"] == _LOCK_DIGEST,
        "final combined v2 OpenClaw runtime inventory changed",
    )
    return {
        "entrypoint": str(entrypoint),
        "entrypoint_digest": expected["openclaw_digest"],
        "expected_version": expected["version_output"],
        "root": str(root),
        "tree": tree,
        "version_output": version,
    }


def _profile_snapshot() -> dict[str, Any]:
    profile, source = _canonical_source(_PROFILE)
    routes = profile.get("routes", [])
    outcomes = {name: 0 for name in ("PASS", "FAIL", "NOT_TESTED")}
    for route in routes:
        _expect(route.get("outcome") in outcomes, "final route outcome is invalid")
        outcomes[route["outcome"]] += 1
    decision = profile.get("decision", {})
    eligible = {key for key in decision if key.endswith("_eligible")}
    _expect(
        profile.get("name") == "openclaw-2026.7.1-protected-final-combined-v2"
        and len(routes) == 21
        and tuple(route.get("id") for route in routes) == _ROUTE_IDS
        and outcomes == {"PASS": 0, "FAIL": 0, "NOT_TESTED": 21}
        and set(decision) == {*_ELIGIBILITY_KEYS, "status"}
        and decision.get("status") == "NOT_TESTED"
        and eligible == _ELIGIBILITY_KEYS
        and all(decision[key] is False for key in eligible),
        "final profile is not the fresh 0 PASS / 0 FAIL / 21 NOT_TESTED ledger",
    )
    return {"document": profile, "file": source, "outcomes": outcomes}


def _skill_snapshot() -> dict[str, Any]:
    skill = p37c._file(_SKILL)
    _expect(
        skill["digest"] == _SKILL_DIGEST
        and skill["bytes"] == 140
        and skill["stat"]["uid"] == 0
        and skill["stat"]["gid"] == 0
        and skill["stat"]["mode"] == "0444"
        and skill["stat"]["nlink"] == 1,
        "final combined v2 singleton skill changed",
    )
    parents = []
    for path, expected_mode in (
        (Path("/"), 0o755),
        (Path("/opt"), 0o555),
        (Path("/opt/aragorn"), 0o555),
        (Path("/opt/aragorn/runtime-profile"), 0o555),
        (_SKILL.parent, 0o555),
    ):
        metadata = path.stat(follow_symlinks=False)
        _expect(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == expected_mode,
            f"final combined v2 skill parent changed: {path}",
        )
        parents.append(
            {
                "path": str(path),
                "mode": f"{expected_mode:04o}",
                "uid": 0,
                "gid": 0,
            }
        )
    return {"file": skill, "parents": parents}


def _artifacts() -> dict[str, Any]:
    parent = _PARENT_ARTIFACTS()
    config, config_file = _canonical_source(_CONFIG)
    profile = _profile_snapshot()
    lock, lock_file = _canonical_source(_LOCK)
    skill = _skill_snapshot()
    activator = p37c._file(_ACTIVATOR)
    preflight = p37c._file(_PREFLIGHT)
    _expect(
        activator["digest"] == _ACTIVATOR_DIGEST,
        "final combined v2 activator changed",
    )
    _expect(
        preflight["digest"] == _PREFLIGHT_DIGEST,
        "final combined v2 preflight changed",
    )
    plugin = {}
    for name, digest in _PLUGIN_DIGESTS.items():
        item = p37c._file(p37c.p37b._PLUGIN / name)
        _expect(
            item["digest"] == digest,
            f"final combined v2 plugin changed: {name}",
        )
        plugin[name] = item
    config_binding = lock["deployment_bindings"]["configuration"]
    activation_contract = lock["deployment_bindings"]["activation_contract"]
    installed_runtime = lock["installed_runtime"]
    _expect(
        config_file["source"]["digest"] == _CONFIG_DIGEST
        and profile["file"]["source"]["digest"] == _PROFILE_DIGEST
        and lock_file["source"]["digest"] == _LOCK_DIGEST
        and config["skills"]["activation"]["authority"] == "external"
        and config["skills"]["activation"]["sources"]
        == [
            {
                "filePath": str(_SKILL),
                "name": "template-skill",
                "sha256": _SKILL_DIGEST.removeprefix("sha256:"),
            }
        ]
        and config["agents"]["defaults"]["sandbox"]["mode"] == "off"
        and config["skills"]["load"]["watch"] is False
        and config["tools"]
        == {
            "alsoAllow": ["aragorn_runtime_create", "read"],
            "deny": ["session_status"],
            "fs": {"workspaceOnly": True},
            "profile": "minimal",
        }
        and activation_contract
        == {
            "activator": {"digest": _ACTIVATOR_DIGEST, "path": str(_ACTIVATOR)},
            "preflight": {"digest": _PREFLIGHT_DIGEST, "path": str(_PREFLIGHT)},
            "tool_policy": {
                "also_allow": ["aragorn_runtime_create", "read"],
                "deny": ["session_status"],
                "filesystem_workspace_only": True,
                "profile": "minimal",
            },
        }
        and config_binding
        == {
            "bytes": config_file["source"]["bytes"],
            "canonical_bytes": config_file["canonical_bytes"],
            "canonical_digest": config_file["canonical_digest"],
            "deployment_materialization": "canonical_json(config)_without_trailing_lf",
            "digest": config_file["source"]["digest"],
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-config-v2.json"
            ),
        }
        and installed_runtime["volume"] == _RUNTIME_VOLUME
        and installed_runtime["runtime_tree"]["tree_digest"] == _RUNTIME_DIGEST
        and installed_runtime["openclaw_digest"] == _ENTRYPOINT_DIGEST
        and installed_runtime["version_output"] == "OpenClaw 2026.7.1 (7fa98d8)",
        "final combined v2 binding changed",
    )
    return {
        **parent,
        "final_combined_v2": {
            "activator": activator,
            "preflight": preflight,
            "config": {"document": config, "file": config_file},
            "profile": profile,
            "runtime_lock": {"document": lock, "file": lock_file},
            "skill": skill,
            "plugin": plugin,
            "collector": {
                "capture_recipe": p37c._file(
                    Path(
                        "/src/scripts/"
                        "capture_runtime_action_worker_final_combined_v2_systemd.sh"
                    )
                ),
                "dockerfile": p37c._file(
                    Path(
                        "/src/benchmark/runtime-action-worker-final-combined-v2-"
                        "systemd/Dockerfile"
                    )
                ),
                "probe": p37c._file(Path(__file__).resolve()),
            },
        },
    }


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path, str]:
    _expect(
        (gateway_uid, gateway_gid, worker_uid, skill_name)
        == (992, 992, 997, "template-skill")
        and _digest(skill_raw) == _SKILL_DIGEST
        and _SKILL.read_bytes() == skill_raw
        and not p37c.p37b._GATEWAY_ROOT.exists(),
        "fresh final combined v2 gateway identity or singleton skill changed",
    )
    for path in (
        p37c.p37b._GATEWAY_ROOT,
        p37c.p37b._GATEWAY_HOME,
        p37c.p37b._GATEWAY_STATE,
        p37c.p37b._GATEWAY_WORKSPACE,
    ):
        p37c.p37b._mkdir(path, gateway_uid, gateway_gid, 0o700)
    p37c.p37b._mkdir(p37c.p37b._GATEWAY_CONFIG.parent, 0, 0, 0o700)
    config, _ = _canonical_source(_CONFIG)
    p37c.p37b._write_document(p37c.p37b._GATEWAY_CONFIG, config)
    _expect(
        p37c.p37b._GATEWAY_CONFIG.read_bytes() == p37c.canonical_json(config),
        "deployed final combined v2 config is not canonical JSON without LF",
    )
    token = secrets.token_hex(32)
    environment_raw = f"OPENCLAW_GATEWAY_TOKEN={token}\n".encode("ascii")
    p37c.p37b._GATEWAY_ENVIRONMENT.write_bytes(environment_raw)
    os.chown(p37c.p37b._GATEWAY_ENVIRONMENT, 0, 0)
    os.chmod(p37c.p37b._GATEWAY_ENVIRONMENT, 0o400)
    environment_stat = p37c.p37b._GATEWAY_ENVIRONMENT.stat(follow_symlinks=False)
    _expect(
        p37c.p37b._GATEWAY_ENVIRONMENT.read_bytes() == environment_raw
        and stat.S_ISREG(environment_stat.st_mode)
        and environment_stat.st_uid == 0
        and environment_stat.st_gid == 0
        and stat.S_IMODE(environment_stat.st_mode) == 0o400
        and environment_stat.st_nlink == 1,
        "final combined v2 gateway environment file changed",
    )
    return (
        config,
        {
            "OPENCLAW_GATEWAY_TOKEN": token,
            "ARAGORN_MOCK_PROVIDER_TOKEN": token,
        },
        _SKILL,
        token,
    )


def _reset_transient_request_directory() -> None:
    path = p37c.p37b.prior._REQUEST.parent
    metadata = path.stat(follow_symlinks=False)
    _expect(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and not any(path.iterdir()),
        "inherited protected-install request directory is not empty and exact",
    )
    path.rmdir()


def _observation_decision(observed: bool) -> dict[str, Any]:
    return {
        "status": (
            "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED"
            if observed
            else "FINAL_COMBINED_V2_ACTION_NOT_OBSERVED_PROFILE_NOT_TESTED"
        ),
        "p3_7c_activation_action_observed": observed,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_PROFILE")
    profile_before = _profile_snapshot()
    _reset_transient_request_directory()
    _set_stage("P3_7C_ACTION")
    with (
        mock.patch.object(p37c, "_harness", _harness),
        mock.patch.object(p37c, "_artifacts", _artifacts),
        mock.patch.object(p37c, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(openclaw, "_RUNTIME_DIGEST", _RUNTIME_DIGEST),
        mock.patch.object(openclaw, "_ENTRYPOINT_DIGEST", _ENTRYPOINT_DIGEST),
        mock.patch.object(openclaw, "_runtime_snapshot", _runtime_snapshot),
    ):
        action = p37c._collect()
    profile_after = _profile_snapshot()
    _expect(
        action["decision"]["status"] == "P3_7C_ACTIVATION_EXPIRY_OBSERVED"
        and action["cases"]["coherent_consumed"]["status"] == "OBSERVED"
        and all(action["cases"]["coherent_consumed"]["checks"].values())
        and action["inputs"]["gateway_config"] == json.loads(_CONFIG.read_bytes())
        and action["inputs"]["producer"]["projected_skill"]["path"] == str(_SKILL)
        and profile_after == profile_before,
        "reused P3.7c action did not remain exact under the final combined v2 profile",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "profile": {"before": profile_before, "after": profile_after},
        "action": action,
        "bindings": {
            "config_materialization": "canonical_json_without_trailing_lf",
            "runtime_volume": _RUNTIME_VOLUME,
            "runtime_digest": _RUNTIME_DIGEST,
            "skill_digest": _SKILL_DIGEST,
            "sessions": "fresh-only",
            "network": "none",
            "sandbox": "off",
            "openclaw_test_fast": "absent",
        },
        "decision": _observation_decision(True),
        "limitations": _LIMITATIONS,
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "decision": _observation_decision(False),
        "limitations": _LIMITATIONS,
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": _STAGE,
            "type": type(exc).__name__,
            "message": str(exc),
        },
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_action_worker_final_combined_v2_systemd_probe.py",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
