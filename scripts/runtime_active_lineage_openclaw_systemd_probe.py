#!/usr/bin/env python3
"""Collect one bounded live protected-lineage OpenClaw/systemd slice."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_capability_openclaw_systemd_probe as capability
import runtime_revocation_openclaw_systemd_probe as prior

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests, write_all
from aragorn.runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_AUTHORITY,
    ACTIVE_RUNTIME_RECORD,
    ACTIVE_RUNTIME_SCHEMA,
    verify_runtime_active_skill_lineage,
)
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

openclaw = capability.prior
profile_systemd = capability.profile_prior

_ROOT = capability._ROOT
_CONTROL = capability._CONTROL
_PROTECTED = capability._PROTECTED
_STAGING = capability._STAGING
_FRONTEND = capability._FRONTEND
_BACKEND = capability._BACKEND
_PENDING = capability._PENDING
_RECEIPT = capability._RECEIPT
_GRANT_STATE = capability._GRANT_STATE
_GRANT_SOURCE = capability._GRANT_SOURCE
_RUNTIME_BINDING = capability._RUNTIME_BINDING
_OBSERVATION_BINDING = capability._OBSERVATION_BINDING
_HARNESS = capability._HARNESS
_DRIVER_ROOT = capability._DRIVER_ROOT
_GATEWAY_UNIT = capability._GATEWAY_UNIT
_BROKER_UNIT = "aragorn-runtime-lineage-capability-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-lineage-capability-observation-publisher.service"
_PROTECTED_INSTALL_PARENT = Path("/var/lib/aragorn-protected")
_PROTECTED_INSTALL_ROOT = _PROTECTED_INSTALL_PARENT / "skills"
_PARENT_EVIDENCE = Path(
    "/src/benchmark/evidence/"
    "runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json"
)
_PARENT_EVIDENCE_DIGEST = (
    "sha256:e60d5cc364f9cf378ee832eaa955119733d92a7dafb0fb83365e85eb4f9225c4"
)
_PARENT_IMAGE = (
    "sha256:730b451086b74a4de9a0e5a335a7ded8ff5f1071dea8f1302afd56a38d06be9d"
)
_TARGET_NAME = "aragorn-runtime-composition"
_FIXTURE_AUTHORITY = (
    "ROOT_ASSEMBLED_PROTECTED_LINEAGE_FIXTURE_ONLY_NOT_FULL_PROTECTED_INSTALL_PRODUCER"
)
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_LIVE_PROTECTED_LINEAGE_SYSTEMD_COMPOSITION_ONLY_"
    "NOT_INSTALLER_RUN_OR_EDR_AUTHORITY"
)
_LIMITATIONS = [
    "ONE_ROOT_ASSEMBLED_SINGLE_FILE_ACTIVE_RECORD_AND_ONE_OPENCLAW_CREATE_ONLY",
    _FIXTURE_AUTHORITY,
    "ACTIVE_RECORD_AUTHORITY_IS_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
    "CLIENT_REPORTS_INDETERMINATE_AFTER_FRONTEND_WRITE_WHILE_BACKEND_TRACE_PROVES_NO_SUBMISSION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_IS_CONSUMPTION_EVIDENCE_NOT_SEMANTIC_CAUSATION",
    "PROCESS_PROFILE_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_MULTI_FILE_SKILL_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_LEGACY_UNITS = (
    "aragorn-runtime-action-broker.service",
    "aragorn-runtime-profile-action-broker.service",
    "aragorn-runtime-observation-publisher.service",
    "aragorn-runtime-profile-observation-publisher.service",
    "aragorn-runtime-capability-action-broker.service",
    "aragorn-runtime-capability-observation-publisher.service",
)
_UNIT_OBJECTS = {
    _BROKER_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dlineage_2dcapability_2daction_2dbroker_2eservice"
    ),
    _SENSOR_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dlineage_2dcapability_2dobservation_2dpublisher_2eservice"
    ),
}
_ARTIFACTS = {
    "/src/packaging/activate-runtime-capability-host.sh": (
        "/usr/libexec/aragorn/activate-runtime-capability-host.sh"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-service-v5.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service-v4.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py"
    ),
    (
        "/src/packaging/systemd/"
        "aragorn-runtime-lineage-capability-action-broker.service"
    ): (
        "/usr/lib/systemd/system/"
        "aragorn-runtime-lineage-capability-action-broker.service"
    ),
    (
        "/src/packaging/systemd/"
        "aragorn-runtime-lineage-capability-observation-publisher.service"
    ): (
        "/usr/lib/systemd/system/"
        "aragorn-runtime-lineage-capability-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "runtime_active_skill_lineage.py",
            "runtime_lineage_capability_issuer.py",
            "runtime_action_observation_publisher_v4.py",
            "runtime_action_broker_v5.py",
            "runtime_action_service_v5.py",
            "runtime_observation_service_v4.py",
        )
    },
}

_expect = capability._expect
_run = capability._run
_systemctl = capability._systemctl
_user = capability._user
_group = capability._group
_metadata = capability._metadata
_file = capability._file
_document = capability._document
_process = capability._process
_wait_path = capability._wait_path
_unit = capability._unit
_wait_active = capability._wait_active
_security_status = capability._security_status


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    expected = {
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
        and set(document) == expected
        and document["schema"]
        == "aragorn/runtime-active-lineage-openclaw-systemd-harness/v1"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and isinstance(document["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"]
        == "aragorn-p36a-runtime-active-lineage-openclaw-systemd"
        and document["run_image_reference"] == document["image_id"]
        and document["parent_image_id"] == _PARENT_IMAGE
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.6a",
        "outer P3.6a harness identity changed",
    )
    lineage = document["image_lineage"]
    _expect(
        isinstance(lineage, dict)
        and lineage["parent"]["id"] == _PARENT_IMAGE
        and lineage["child"]["id"] == document["image_id"]
        and lineage["child"]["layers"][: len(lineage["parent"]["layers"])]
        == lineage["parent"]["layers"]
        and lineage["added_layers"]
        == lineage["child"]["layers"][len(lineage["parent"]["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.6a image lineage changed",
    )
    return retained


def _parent_evidence() -> dict[str, Any]:
    raw = _PARENT_EVIDENCE.read_bytes()
    document = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    _expect(
        canonical_json(document) + b"\n" == raw
        and digest == _PARENT_EVIDENCE_DIGEST
        and document.get("schema")
        == "aragorn/runtime-revocation-openclaw-systemd-evidence/v1"
        and document.get("authority")
        == "BOUNDED_PINNED_OPENCLAW_LOCAL_SYSTEMD_REVOCATION_PUBLICATION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
        and document.get("decision", {}).get("status")
        == "P3_5B_LOCAL_SYSTEMD_REVOCATION_OBSERVED",
        "retained P3.5b evidence changed",
    )
    return {
        "repository_path": (
            "benchmark/evidence/"
            "runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json"
        ),
        "captured_path": str(_PARENT_EVIDENCE),
        "file_digest": digest,
        "bytes": len(raw),
        "schema": document["schema"],
        "authority": document["authority"],
        "decision_status": document["decision"]["status"],
    }


def _stop_units() -> None:
    _systemctl(
        "stop",
        _SENSOR_UNIT,
        _BROKER_UNIT,
        _GATEWAY_UNIT,
        *_LEGACY_UNITS,
        check=False,
    )


def _reset() -> None:
    _stop_units()
    _systemctl("reset-failed", _SENSOR_UNIT, _BROKER_UNIT, check=False)
    prior._reset()
    if _PROTECTED_INSTALL_PARENT.exists():
        shutil.rmtree(_PROTECTED_INSTALL_PARENT)


def _lineage_unit(name: str) -> dict[str, Any]:
    unit = _unit(name)
    unit["LoadCredential"] = (
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
    return unit


def _path_identity(path: Path) -> dict[str, Any]:
    metadata = os.lstat(path)
    kind = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "symlink"
        if stat.S_ISLNK(metadata.st_mode)
        else "other"
    )
    result = {
        "path": str(path),
        "type": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "nlink": metadata.st_nlink,
        "size": metadata.st_size,
    }
    if kind == "symlink":
        result["target"] = os.readlink(path)
    return result


def _fixture_snapshot(paths: dict[str, Path]) -> dict[str, dict[str, Any]]:
    return {name: _path_identity(path) for name, path in paths.items()}


def _record_snapshot(path: Path) -> dict[str, Any]:
    return {**_document(path), "file": _file(path)}


def _write_active_record(root_fd: int, document: dict[str, Any]) -> None:
    raw = canonical_json(document)
    temporary = _PROTECTED_INSTALL_ROOT / ".aragorn-active-runtime-fixture.tmp"
    temporary.unlink(missing_ok=True)
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        write_all(descriptor, raw)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, _PROTECTED_INSTALL_ROOT / ACTIVE_RUNTIME_RECORD)
    os.fsync(root_fd)


def _assemble_fixture(
    runtime_gid: int,
    source_manifest: dict[str, Any],
    install_context: dict[str, Any],
    *,
    stale_tree_digest: str,
) -> dict[str, Any]:
    context_digest = canonical_digest(install_context)
    manifest_digest = canonical_digest(source_manifest)
    context_id = canonical_digest(
        {
            "schema": "aragorn/evaluator-root-context-id/v1",
            "install_context_digest": context_digest,
        }
    )
    version_name = f"{context_id[7:]}-{manifest_digest[7:]}"
    version_path = f".aragorn-versions/{_TARGET_NAME}/{version_name}"
    versions = _PROTECTED_INSTALL_ROOT / ".aragorn-versions"
    target_versions = versions / _TARGET_NAME
    version = target_versions / version_name
    installed_skill = version / "SKILL.md"

    _expect(
        _path_identity(_PROTECTED_INSTALL_PARENT)["gid"] == runtime_gid
        and _path_identity(_PROTECTED_INSTALL_ROOT)["gid"] == runtime_gid,
        "protected fixture root was not prepared",
    )
    versions.mkdir(mode=0o755)
    target_versions.mkdir(mode=0o755)
    version.mkdir(mode=0o755)
    installed_skill.write_bytes(openclaw._SKILL.read_bytes())
    os.chown(installed_skill, 0, 0)
    os.chmod(installed_skill, 0o444)
    os.chmod(version, 0o555)
    (_PROTECTED_INSTALL_ROOT / _TARGET_NAME).symlink_to(version_path)

    root_state = os.lstat(_PROTECTED_INSTALL_ROOT)
    tree_entry = {
        "path": "SKILL.md",
        "size": installed_skill.stat().st_size,
        "digest": openclaw._SKILL_DIGEST,
        "executable": False,
    }
    tree_digest = canonical_digest([tree_entry])
    transaction = {
        "schema": "aragorn/protected-install-transaction/v1",
        "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_digest": context_digest,
        "context_id": context_id,
        "operation": "install",
        "expected_active": None,
        "manifest_digest": manifest_digest,
        "tree_digest": tree_digest,
        "destination": {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "target_name": _TARGET_NAME,
        },
        "version_path": version_path,
    }
    stale_transaction = {**transaction, "tree_digest": stale_tree_digest}
    stale_record = {
        "schema": ACTIVE_RUNTIME_SCHEMA,
        "authority": ACTIVE_RUNTIME_AUTHORITY,
        "transaction": stale_transaction,
    }
    record = {
        "schema": ACTIVE_RUNTIME_SCHEMA,
        "authority": ACTIVE_RUNTIME_AUTHORITY,
        "transaction": transaction,
    }
    root_fd = os.open(_PROTECTED_INSTALL_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        _write_active_record(root_fd, stale_record)
        fcntl.flock(root_fd, fcntl.LOCK_UN)
    finally:
        os.close(root_fd)
    paths = {
        "root": _PROTECTED_INSTALL_ROOT,
        "record": _PROTECTED_INSTALL_ROOT / ACTIVE_RUNTIME_RECORD,
        "active_link": _PROTECTED_INSTALL_ROOT / _TARGET_NAME,
        "versions": versions,
        "target_versions": target_versions,
        "version": version,
        "skill": installed_skill,
    }
    return {
        "record_document": record,
        "stale_record_document": stale_record,
        "transaction": transaction,
        "tree_entry": tree_entry,
        "paths": paths,
    }


def _publish_coherent_record(fixture: dict[str, Any]) -> None:
    root_fd = os.open(_PROTECTED_INSTALL_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        _write_active_record(root_fd, fixture["record_document"])
        fcntl.flock(root_fd, fcntl.LOCK_UN)
    finally:
        os.close(root_fd)


def _effect_snapshot() -> dict[str, Any]:
    target = _PROTECTED / capability._TARGET
    return {
        "target_lexists": os.path.lexists(target),
        "target": _file(target) if target.exists() else None,
        "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
        "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
        "profile_pending_exists": _PENDING.exists(),
        "profile_receipt_exists": _RECEIPT.exists(),
        "control_digests": capability._control_snapshot(),
    }


def _available(state: dict[str, Any], grant_digest: str) -> bool:
    document = state["document"]
    return (
        document.get("schema") == "aragorn/runtime-capability-grant-state/v1"
        and document.get("authority")
        == "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and document.get("status") == "AVAILABLE"
        and document.get("grant_digest") == grant_digest
        and document.get("claim") is None
        and document.get("result") is None
    )


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    parent_evidence = _parent_evidence()
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    _expect(
        len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) == 3,
        "service UIDs overlap",
    )

    installed_artifacts = []
    for source, installed in sorted(_ARTIFACTS.items()):
        source_file = _file(Path(source))
        installed_file = _file(Path(installed))
        _expect(
            source_file["digest"] == installed_file["digest"]
            and source_file["bytes"] == installed_file["bytes"],
            f"installed artifact differs from source: {installed}",
        )
        installed_artifacts.append(
            {
                "source": source_file,
                "installed": installed_file,
            }
        )

    node = _file(openclaw._NODE)
    skill = _file(openclaw._SKILL)
    _expect(
        node["digest"] == openclaw._NODE_DIGEST
        and skill["digest"] == openclaw._SKILL_DIGEST,
        "pinned executable or skill changed",
    )
    runtime_snapshot = openclaw._runtime_snapshot()
    _, plugin_digest = openclaw.openclaw_prior._plugin_artifacts()
    _expect(plugin_digest == openclaw._PLUGIN_DIGEST, "pinned plugin changed")

    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(
            protected_fd,
            capability._TARGET,
            capability._PAYLOAD,
        )
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-6a-pinned-openclaw-live-protected-lineage",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "revocation_source_digest": openclaw._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": openclaw._RUNTIME_DIGEST,
                "active_skill_digest": openclaw._SKILL_DIGEST,
                **action,
            }
        ],
    }
    identities = {
        "broker": {"uid": broker.pw_uid, "gid": runtime_gid},
        "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
        "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
    }
    config = openclaw._gateway_config(
        policy,
        plugin_digest,
        {
            "broker_uid": broker.pw_uid,
            "runtime_uid": runtime.pw_uid,
            "runtime_gid": runtime_gid,
            "sensor_uid": sensor.pw_uid,
            "sensor_gid": sensor_gid,
        },
    )
    openclaw._CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    openclaw._write_document(openclaw._CONFIG, config, 0, 0, 0o444)

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
    gateway = capability._gateway_state(runtime.pw_uid, runtime_gid)
    gateway_pid = gateway["pid"]
    profile_document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "executable_digest": node["digest"],
        "cgroup": gateway["cgroup"],
        "skill_path": str(openclaw._SKILL),
    }
    profile = runtime_process_profile(profile_document)

    _PROTECTED_INSTALL_PARENT.mkdir(mode=0o750)
    os.chown(_PROTECTED_INSTALL_PARENT, 0, runtime_gid)
    os.chmod(_PROTECTED_INSTALL_PARENT, 0o750)
    _PROTECTED_INSTALL_ROOT.mkdir(mode=0o750)
    os.chown(_PROTECTED_INSTALL_ROOT, 0, runtime_gid)
    os.chmod(_PROTECTED_INSTALL_ROOT, 0o750)
    root_state = os.lstat(_PROTECTED_INSTALL_ROOT)
    tree_entry = {
        "path": "SKILL.md",
        "size": skill["bytes"],
        "digest": skill["digest"],
        "executable": False,
    }
    tree_digest = canonical_digest([tree_entry])
    source_manifest = {
        "schema": "aragorn/evaluator-root-source-binding/v1",
        "authority": _FIXTURE_AUTHORITY,
        "fixture": "p3.6a-single-file-openclaw-source",
        "tree_digest": tree_digest,
        "files": [tree_entry],
    }
    install_context = {
        "schema": "aragorn/evaluator-root-install-binding/v1",
        "authority": _FIXTURE_AUTHORITY,
        "fixture": "p3.6a-single-file-openclaw-install",
        "runtime_profile_digest": profile.digest,
        "destination": {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "target_name": _TARGET_NAME,
        },
    }
    stale_tree_digest = canonical_digest(
        {"schema": "aragorn/stale-tree-fixture/v1", "tree_digest": tree_digest}
    )
    fixture = _assemble_fixture(
        runtime_gid,
        source_manifest,
        install_context,
        stale_tree_digest=stale_tree_digest,
    )
    _expect(
        fixture["tree_entry"] == tree_entry
        and fixture["transaction"]["tree_digest"] == tree_digest
        and fixture["transaction"]["destination"] == install_context["destination"],
        "root fixture identity changed while assembled",
    )
    stale_record = _record_snapshot(fixture["paths"]["record"])

    now = int(time.time())
    controls = capability._controls(policy, action, now, counter=1)
    for name, document in controls.items():
        capability._write_control(
            _CONTROL / f"{name}.json",
            document,
            broker.pw_uid,
            runtime_gid,
        )
    runtime_binding = {
        "schema": "aragorn/runtime-action-runtime-binding/v2",
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "runtime_profile_digest": profile.digest,
    }
    observation_binding = {
        "schema": "aragorn/runtime-observation-binding/v2",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "runtime_profile": profile_document,
    }
    openclaw._write_document(_RUNTIME_BINDING, runtime_binding, 0, 0, 0o400)
    openclaw._write_document(
        _OBSERVATION_BINDING,
        observation_binding,
        0,
        0,
        0o400,
    )
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": canonical_digest(
            {
                "schema": "aragorn/evaluator-root-grant-id/v1",
                "context_digest": fixture["transaction"]["context_digest"],
                "profile_digest": profile.digest,
            }
        )[7:],
        "source_manifest_digest": fixture["transaction"]["manifest_digest"],
        "install_context_digest": fixture["transaction"]["context_digest"],
        "runtime_profile_digest": profile.digest,
        "runtime_digest": openclaw._RUNTIME_DIGEST,
        "active_skill_digest": openclaw._SKILL_DIGEST,
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "policy_digest": canonical_digest(policy),
        "policy_version": policy["version"],
        "operation_digest": action["operation_digest"],
        "issued_at_unix": now - 1,
        "expires_at_unix": now + 240,
        "max_actions": 1,
    }
    grant_raw = canonical_json(grant)
    _expect(
        parse_runtime_capability_grant(grant_raw, now) == grant,
        "root grant validation changed",
    )
    openclaw._write_document(_GRANT_SOURCE, grant, 0, 0, 0o400)
    grant_digest = canonical_digest(grant)

    _DRIVER_ROOT.mkdir(mode=0o700)
    os.chown(_DRIVER_ROOT, runtime.pw_uid, runtime_gid)
    stale_activation = _run(
        ["/usr/libexec/aragorn/activate-runtime-capability-host.sh"]
    )
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    stale_broker_unit = _lineage_unit(_BROKER_UNIT)
    stale_sensor_unit = _lineage_unit(_SENSOR_UNIT)
    stale_broker_pid = int(stale_broker_unit["MainPID"])
    stale_state_before = _document(_GRANT_STATE)
    stale_effects_before = _effect_snapshot()
    _expect(
        _available(stale_state_before, grant_digest),
        "stale case did not start from AVAILABLE",
    )
    try:
        verify_runtime_active_skill_lineage(
            gateway_pid,
            {
                "pid": gateway_pid,
                "skill_path": str(openclaw._SKILL),
                "active_skill_digest": openclaw._SKILL_DIGEST,
            },
            grant,
            protected_root=_PROTECTED_INSTALL_ROOT,
            deadline=time.monotonic() + 0.5,
        )
    except Exception as exc:  # noqa: BLE001 - bounded negative evidence
        stale_verification = {"type": type(exc).__name__, "message": str(exc)}
    else:
        raise openclaw.ProbeError("stale active record unexpectedly verified")

    stale_broker_trace_process = profile_systemd.prior._start_trace(
        stale_broker_pid,
        _DRIVER_ROOT / "stale-broker.trace",
    )
    try:
        negative_input, negative = capability._run_driver(
            "stale-active-record",
            "CLIENT_ERROR",
            "NOT_SUBMITTED",
            runtime.pw_uid,
            runtime_gid,
        )
        stale_broker_trace = capability._trace(
            stale_broker_trace_process,
            _DRIVER_ROOT / "stale-broker.trace",
            stale_broker_pid,
            [],
        )
    finally:
        capability._stop_trace(stale_broker_trace_process)
    negative_result = openclaw._driver_result(negative["driver"])
    stale_state_after = _document(_GRANT_STATE)
    stale_effects_after = _effect_snapshot()
    stale_checks = {
        "driver": negative["status"] == "PASS",
        "client_error": negative_result is not None
        and negative_result.get("schema") == "aragorn/runtime-action-client-error/v1"
        and negative_result.get("authority")
        == "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        "client_conservative_indeterminate": negative_result is not None
        and negative_result.get("effect_status") == "INDETERMINATE",
        "frontend_write_preceded_reset": negative_result is not None
        and negative_result.get("message") == "broker transport failed: ECONNRESET",
        "broker_not_submitted": not stale_broker_trace["peer_credentials"],
        "grant_available": stale_state_before == stale_state_after
        and _available(stale_state_after, grant_digest),
        "broker_state_unchanged": stale_effects_before["control_digests"]
        == stale_effects_after["control_digests"],
        "no_target": not stale_effects_after["target_lexists"],
        "no_pending_or_receipt": not stale_effects_after["profile_pending_exists"]
        and not stale_effects_after["profile_receipt_exists"],
        "no_effect_files": not stale_effects_after["protected_entries"]
        and not stale_effects_after["staging_entries"],
        "live_verifier_rejected": stale_verification["type"]
        == "RuntimeActionObservationPublisherError",
    }
    _expect(
        all(stale_checks.values()),
        "stale active-record case changed: "
        + ",".join(name for name, passed in stale_checks.items() if not passed)
        + f";result={negative_result};driver={negative};verification={stale_verification}",
    )

    _systemctl("stop", _SENSOR_UNIT, _BROKER_UNIT, _GATEWAY_UNIT)
    _publish_coherent_record(fixture)
    coherent_record = _record_snapshot(fixture["paths"]["record"])
    coherent_before = _fixture_snapshot(fixture["paths"])
    _systemctl("start", _GATEWAY_UNIT)
    coherent_gateway = capability._gateway_state(
        runtime.pw_uid,
        runtime_gid,
        expected_cgroup=profile_document["cgroup"],
    )
    gateway_pid = coherent_gateway["pid"]
    refreshed = capability._controls(policy, action, int(time.time()), counter=2)
    for name in ("revocations", "health", "observation"):
        capability._write_control(
            _CONTROL / f"{name}.json",
            refreshed[name],
            broker.pw_uid,
            runtime_gid,
        )
    coherent_activation = _run(
        ["/usr/libexec/aragorn/activate-runtime-capability-host.sh"]
    )
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    broker_unit = _lineage_unit(_BROKER_UNIT)
    sensor_unit = _lineage_unit(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    coherent_state_before = _document(_GRANT_STATE)
    coherent_effects_before = _effect_snapshot()
    _expect(
        _available(coherent_state_before, grant_digest),
        "coherent case did not start from the same AVAILABLE grant",
    )

    positive_input, positive = capability._run_driver(
        "coherent-active-record",
        "ALLOW",
        "CREATED",
        runtime.pw_uid,
        runtime_gid,
    )
    positive_result = openclaw._driver_result(positive["driver"])
    coherent_state_after = _document(_GRANT_STATE)
    coherent_effects_after = _effect_snapshot()
    receipt = _document(_RECEIPT) if _RECEIPT.exists() else None
    target = (
        _file(_PROTECTED / capability._TARGET)
        if (_PROTECTED / capability._TARGET).exists()
        else None
    )
    state_document = coherent_state_after["document"]
    claim = state_document.get("claim") or {}
    lease = claim.get("lease") or {}
    receipt_document = receipt["document"] if receipt else {}
    attribution = receipt_document.get("runtime_attribution") or {}
    _expect(
        receipt is not None and attribution.get("pid") == gateway_pid,
        "coherent driver did not produce a bound receipt: "
        + repr(
            {
                "positive": positive,
                "result": positive_result,
                "state": state_document,
                "broker_journal": _run(
                    [
                        "journalctl",
                        "--no-pager",
                        "--output=cat",
                        "--unit",
                        _BROKER_UNIT,
                        "--lines=40",
                    ],
                    check=False,
                ).stdout.decode(errors="replace"),
                "sensor_journal": _run(
                    [
                        "journalctl",
                        "--no-pager",
                        "--output=cat",
                        "--unit",
                        _SENSOR_UNIT,
                        "--lines=40",
                    ],
                    check=False,
                ).stdout.decode(errors="replace"),
            }
        ),
    )
    verified_lineage = verify_runtime_active_skill_lineage(
        gateway_pid,
        attribution,
        grant,
        protected_root=_PROTECTED_INSTALL_ROOT,
        deadline=time.monotonic() + 0.5,
    )
    coherent_after = _fixture_snapshot(fixture["paths"])
    coherent_stable = coherent_before == coherent_after
    secret_absent = capability._runtime_facing_secret_absence(
        (negative["driver"], positive["driver"]),
        grant,
        grant_digest,
        lease,
    )
    coherent_checks = {
        "driver": positive["status"] == "PASS",
        "allow_created": positive_result is not None
        and positive_result.get("schema") == "aragorn/runtime-action-broker-result/v1"
        and positive_result.get("verdict") == "ALLOW"
        and positive_result.get("effect_status") == "CREATED",
        "grant_consumed": state_document.get("status") == "CONSUMED"
        and state_document.get("grant_digest") == grant_digest
        and claim.get("grant_digest") == grant_digest,
        "lease_bound": lease.get("grant_digest") == grant_digest
        and lease.get("runtime_profile_digest") == profile.digest
        and lease.get("runtime_digest") == openclaw._RUNTIME_DIGEST
        and lease.get("active_skill_digest") == openclaw._SKILL_DIGEST
        and lease.get("policy_digest") == canonical_digest(policy)
        and lease.get("operation_digest") == action["operation_digest"],
        "receipt_bound": receipt is not None
        and receipt_document.get("runtime_attribution_digest")
        == lease.get("runtime_attribution_digest")
        and receipt_document.get("broker_result") == positive_result
        and receipt_document.get("broker_result_digest")
        == canonical_digest(positive_result),
        "runtime_bound": attribution.get("pid") == gateway_pid
        and attribution.get("profile_digest") == profile.digest
        and attribution.get("active_skill_digest") == openclaw._SKILL_DIGEST,
        "target_created": target is not None
        and target["digest"] == action["payload_digest"]
        and target["stat"]["uid"] == broker.pw_uid
        and target["stat"]["gid"] == runtime_gid
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1,
        "no_pending_or_staging": not coherent_effects_after["profile_pending_exists"]
        and not coherent_effects_after["staging_entries"],
        "lineage_record_bound": verified_lineage["context_digest"]
        == grant["install_context_digest"]
        and verified_lineage["manifest_digest"] == grant["source_manifest_digest"]
        and verified_lineage["tree_digest"] == tree_digest
        and verified_lineage["active_skill_digest"] == grant["active_skill_digest"],
        "lineage_identities_stable": coherent_stable,
        "runtime_secret_absent": secret_absent,
    }
    _expect(
        all(coherent_checks.values()),
        "coherent active-record case changed: "
        + ",".join(name for name, passed in coherent_checks.items() if not passed)
        + f";result={positive_result};state={state_document}",
    )

    bindings = {
        "source_manifest_digest": {
            "grant": grant["source_manifest_digest"],
            "transaction": fixture["transaction"]["manifest_digest"],
            "matches": grant["source_manifest_digest"]
            == fixture["transaction"]["manifest_digest"],
        },
        "install_context_digest": {
            "grant": grant["install_context_digest"],
            "transaction": fixture["transaction"]["context_digest"],
            "matches": grant["install_context_digest"]
            == fixture["transaction"]["context_digest"],
        },
        "active_skill_digest": {
            "grant": grant["active_skill_digest"],
            "runtime_profile": skill["digest"],
            "installed": _file(fixture["paths"]["skill"])["digest"],
            "matches": grant["active_skill_digest"]
            == skill["digest"]
            == _file(fixture["paths"]["skill"])["digest"],
        },
        "tree_digest": {
            "transaction": fixture["transaction"]["tree_digest"],
            "reconstructed": canonical_digest([fixture["tree_entry"]]),
            "matches": fixture["transaction"]["tree_digest"]
            == canonical_digest([fixture["tree_entry"]]),
        },
        "runtime_profile_digest": {
            "grant": grant["runtime_profile_digest"],
            "profile": profile.digest,
            "matches": grant["runtime_profile_digest"] == profile.digest,
        },
    }
    _expect(
        all(item["matches"] for item in bindings.values()),
        "grant bindings changed",
    )

    return {
        "schema": "aragorn/runtime-active-lineage-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_6A_LIVE_PROTECTED_LINEAGE_OBSERVED",
            "stale_active_record_client_indeterminate_observed": True,
            "stale_active_record_broker_not_submitted_observed": True,
            "stale_grant_remained_available": True,
            "coherent_active_record_allow_created_observed": True,
            "grant_available_to_consumed_observed": True,
            "root_assembled_fixture_is_full_protected_install_producer": False,
            "semantic_causation_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "parent_evidence": parent_evidence,
        "harness": harness,
        "artifacts": {
            "installed": installed_artifacts,
            "collector": {
                "probe": _file(Path(__file__).resolve()),
                "dockerfile": _file(
                    Path(
                        "/src/benchmark/runtime-active-lineage-openclaw-systemd/"
                        "Dockerfile"
                    )
                ),
                "recipe": _file(
                    Path(
                        "/src/scripts/"
                        "capture_runtime_active_lineage_openclaw_systemd.sh"
                    )
                ),
            },
        },
        "runtime": runtime_snapshot,
        "profile": {
            "digest": profile.digest,
            "document": profile_document,
            "skill": skill,
            "executable": node,
        },
        "identities": identities,
        "grant": {
            "digest": grant_digest,
            "document": grant,
            "bindings": bindings,
            "initial_state": stale_state_before,
            "final_state": coherent_state_after,
        },
        "active_install": {
            "authority": _FIXTURE_AUTHORITY,
            "construction": _FIXTURE_AUTHORITY,
            "record": coherent_record,
            "stale_record": stale_record,
            "transaction": fixture["transaction"],
            "tree_entry": fixture["tree_entry"],
            "paths": {name: str(path) for name, path in fixture["paths"].items()},
            "coherent_snapshot": {
                "before": coherent_before,
                "after": coherent_after,
                "stable": coherent_stable,
            },
            "verified_lineage": verified_lineage,
        },
        "deployment": {
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
            "activation": {
                "stale": {
                    "exit_code": stale_activation.returncode,
                    "stdout": stale_activation.stdout.decode(),
                    "stderr": stale_activation.stderr.decode(),
                },
                "coherent": {
                    "exit_code": coherent_activation.returncode,
                    "stdout": coherent_activation.stdout.decode(),
                    "stderr": coherent_activation.stderr.decode(),
                },
            },
            "directories": {
                "runtime_action": _metadata(_ROOT),
                "control": _metadata(_CONTROL),
                "protected_effects": _metadata(_PROTECTED),
                "staging": _metadata(_STAGING),
                "protected_install_parent": _metadata(_PROTECTED_INSTALL_PARENT),
                "protected_install_root": _metadata(_PROTECTED_INSTALL_ROOT),
            },
            "gateway": {"stale": gateway, "coherent": coherent_gateway},
            "units": {
                "stale_broker": stale_broker_unit,
                "stale_sensor": stale_sensor_unit,
                "coherent_broker": broker_unit,
                "coherent_sensor": sensor_unit,
            },
            "processes": {
                "gateway": _process(gateway_pid),
                "broker": _process(broker_pid),
                "sensor": _process(sensor_pid),
            },
            "security": {
                "broker": _security_status(broker_pid),
                "sensor": _security_status(sensor_pid),
            },
            "sockets": {
                "backend": _metadata(_BACKEND),
                "frontend": _metadata(_FRONTEND),
            },
            "legacy_routes": capability._legacy_routes(),
        },
        "cases": {
            "stale_active_record": {
                "status": "PASS",
                "driver": {"input": negative_input, **negative},
                "checks": stale_checks,
                "grant_state_before": stale_state_before,
                "grant_state_after": stale_state_after,
                "effects": {
                    "before": stale_effects_before,
                    "after": stale_effects_after,
                    "verification_error": stale_verification,
                    "peer_trace": {
                        "broker": stale_broker_trace,
                    },
                },
            },
            "coherent_active_record": {
                "status": "PASS",
                "driver": {"input": positive_input, **positive},
                "checks": coherent_checks,
                "grant_state_before": coherent_state_before,
                "grant_state_after": coherent_state_after,
                "effects": {
                    "before": coherent_effects_before,
                    "after": coherent_effects_after,
                },
                "result": positive_result,
                "receipt": receipt,
                "target": target,
            },
        },
        "timing": {
            "grant_lifetime_seconds": grant["expires_at_unix"]
            - grant["issued_at_unix"],
            "sensor_deadline_ms": 500,
            "client_deadline_ms": 750,
            "stale_driver_elapsed_ns": negative["driver_elapsed_ns"],
            "coherent_driver_elapsed_ns": positive["driver_elapsed_ns"],
        },
    }


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise openclaw.ProbeError(
            "collector requires root in the fixed systemd container"
        )
    harness = _harness()
    _reset()
    try:
        return _collect_live(harness)
    finally:
        _stop_units()


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-active-lineage-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_6A_LIVE_PROTECTED_LINEAGE_NOT_OBSERVED",
            "stale_active_record_client_indeterminate_observed": False,
            "stale_active_record_broker_not_submitted_observed": False,
            "stale_grant_remained_available": False,
            "coherent_active_record_allow_created_observed": False,
            "grant_available_to_consumed_observed": False,
            "root_assembled_fixture_is_full_protected_install_producer": False,
            "semantic_causation_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "failure": {"type": type(exc).__name__, "message": str(exc)},
    }


def _publish(path: Path | None, document: dict[str, Any]) -> None:
    raw = canonical_json(document) + b"\n"
    if path is None:
        sys.stdout.buffer.write(raw)
        return
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
        write_all(descriptor, raw)
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
            "usage: runtime_active_lineage_openclaw_systemd_probe.py "
            "[--output ABSENT_PATH]",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - retained failure evidence is required
        result = _failure(exc)
        status = 2
    _publish(output, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
