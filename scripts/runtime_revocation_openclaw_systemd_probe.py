#!/usr/bin/env python3
"""Collect one bounded local-systemd runtime revocation slice for P3.5b."""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_capability_openclaw_systemd_probe as base

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests, write_all
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    LEASE_AUTHORITY,
    LEASE_SCHEMA,
    parse_runtime_capability_grant,
)
from aragorn.runtime_process_profile import (
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    runtime_process_profile,
)

_ROOT = base._ROOT
_CONTROL = base._CONTROL
_PROTECTED = base._PROTECTED
_STAGING = base._STAGING
_FRONTEND = base._FRONTEND
_BACKEND = base._BACKEND
_PENDING = base._PENDING
_RECEIPT = base._RECEIPT
_GRANT_STATE = base._GRANT_STATE
_GRANT_SOURCE = base._GRANT_SOURCE
_RUNTIME_BINDING = base._RUNTIME_BINDING
_OBSERVATION_BINDING = base._OBSERVATION_BINDING
_HARNESS = base._HARNESS
_DRIVER_ROOT = base._DRIVER_ROOT
_GATEWAY_UNIT = base._GATEWAY_UNIT
_BROKER_UNIT = base._BROKER_UNIT
_SENSOR_UNIT = base._SENSOR_UNIT
_LEGACY_UNITS = base._LEGACY_UNITS

_PUBLISHER_UNIT = "aragorn-runtime-revocation-publisher.service"
_PUBLISHER_OBJECT = (
    "/org/freedesktop/systemd1/unit/"
    "aragorn_2druntime_2drevocation_2dpublisher_2eservice"
)
_PUBLICATION_SOURCE = Path("/etc/aragorn/runtime-action-revocation-publication.json")
_P35A_IMAGE = "sha256:12ac568f41c61f714a15f0648b99b0781cedc816a1d591c59de6ef015bcccb4e"
_TARGET = base._TARGET
_PAYLOAD = base._PAYLOAD
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_LOCAL_SYSTEMD_REVOCATION_PUBLICATION_ONLY_"
    "NOT_RUN_OR_EDR_AUTHORITY"
)
_LIMITATIONS = [
    "ONE_ROOT_LOCAL_SYSTEMD_CREDENTIAL_PUBLICATION_AND_ONE_OPENCLAW_CREATE_ONLY",
    "LOCAL_CREDENTIAL_METADATA_NOT_CRYPTOGRAPHIC_AUTHORSHIP_OR_DURABLE_INGRESS_RECEIPT",
    "JOURNAL_STDOUT_IS_LOCAL_PROCESS_RESULT_NOT_DURABLE_PROVENANCE",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_IS_CONSUMPTION_EVIDENCE_NOT_SEMANTIC_CAUSATION",
    "ROOT_SUPPLIED_SOURCE_AND_INSTALL_DIGESTS_NOT_INDEPENDENT_PROVENANCE",
    "CAPTURED_WORKTREE_BYTES_NOT_COMMIT_OR_SIGNED_RELEASE_IDENTITY",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "PROCESS_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]

_expect = base._expect
_run = base._run
_systemctl = base._systemctl
_user = base._user
_group = base._group
_metadata = base._metadata
_file = base._file
_document = base._document
_process = base._process
_wait_path = base._wait_path
_write_control = base._write_control
_unit = base._unit
_wait_active = base._wait_active
_security_status = base._security_status

_ARTIFACTS = {
    **base._ARTIFACTS,
    "/src/src/aragorn/runtime_revocation_service.py": (
        "/usr/lib/aragorn/aragorn/runtime_revocation_service.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-revocation-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-revocation-service.py"
    ),
    "/src/packaging/systemd/aragorn-runtime-revocation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-revocation-publisher.service"
    ),
}


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
        == "aragorn/runtime-revocation-openclaw-systemd-harness/v1"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and isinstance(document["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"]
        == "aragorn-p35b-runtime-revocation-openclaw-systemd"
        and document["run_image_reference"] == document["image_id"]
        and document["parent_image_id"] == _P35A_IMAGE
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.5b",
        "outer P3.5b harness identity changed",
    )
    lineage = document["image_lineage"]
    _expect(
        isinstance(lineage, dict)
        and lineage["parent"]["id"] == _P35A_IMAGE
        and lineage["child"]["id"] == document["image_id"]
        and lineage["child"]["layers"][: len(lineage["parent"]["layers"])]
        == lineage["parent"]["layers"]
        and lineage["added_layers"]
        == lineage["child"]["layers"][len(lineage["parent"]["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.5b image lineage changed",
    )
    return retained


def _stop_units() -> None:
    _systemctl("stop", _PUBLISHER_UNIT, check=False)
    base._stop_units()


def _reset() -> None:
    _systemctl("stop", _PUBLISHER_UNIT, check=False)
    _systemctl("reset-failed", _PUBLISHER_UNIT, check=False)
    _systemctl("unmask", _PUBLISHER_UNIT, check=False)
    base._reset()
    _PUBLICATION_SOURCE.unlink(missing_ok=True)


def _control_snapshot() -> dict[str, dict[str, Any]]:
    return {
        name: _document(_CONTROL / f"{name}.json")
        for name in ("policy", "revocations", "health", "observation", "state")
    }


def _effect_snapshot() -> dict[str, Any]:
    target = _PROTECTED / _TARGET
    return {
        "target": {"path": str(target), "lexists": os.path.lexists(target)},
        "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
        "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
        "profile_pending_exists": _PENDING.exists(),
        "profile_receipt_exists": _RECEIPT.exists(),
    }


def _socket_snapshot() -> dict[str, dict[str, Any]]:
    return {"backend": _metadata(_BACKEND), "frontend": _metadata(_FRONTEND)}


def _process_snapshot(
    gateway_pid: int,
    broker_pid: int,
    sensor_pid: int,
) -> dict[str, dict[str, Any]]:
    return {
        "gateway": _process(gateway_pid),
        "broker": _process(broker_pid),
        "sensor": _process(sensor_pid),
    }


def _publisher_unit() -> dict[str, Any]:
    unit = _unit(_PUBLISHER_UNIT)
    unit["LoadCredential"] = (
        _run(
            [
                "busctl",
                "get-property",
                "org.freedesktop.systemd1",
                _PUBLISHER_OBJECT,
                "org.freedesktop.systemd1.Service",
                "LoadCredential",
            ]
        )
        .stdout.decode()
        .strip()
    )
    return unit


def _journal_cursor() -> str:
    raw = _run(
        [
            "journalctl",
            "-n",
            "0",
            "--show-cursor",
            "--no-pager",
        ]
    ).stdout.decode()
    cursors = [
        line.removeprefix("-- cursor: ")
        for line in raw.splitlines()
        if line.startswith("-- cursor: ")
    ]
    _expect(
        len(cursors) == 1 and 0 < len(cursors[0]) <= 1024 and cursors[0].isascii(),
        "revocation publisher journal cursor is invalid",
    )
    return cursors[0]


def _publication_journal(
    after_cursor: str,
    unit: dict[str, Any],
    result: dict[str, Any],
    broker_uid: int,
    runtime_gid: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    matches: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        raw = _run(
            [
                "journalctl",
                "-u",
                _PUBLISHER_UNIT,
                f"--after-cursor={after_cursor}",
                "--output=json",
                "--no-pager",
            ]
        ).stdout
        rows = [json.loads(line) for line in raw.splitlines() if line]
        matches = []
        for row in rows:
            message = row.get("MESSAGE")
            if not isinstance(message, str):
                continue
            try:
                document = json.loads(message)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if (
                canonical_json(document).decode("ascii") == message
                and document == result
            ):
                matches.append(row)
        if matches:
            break
        time.sleep(0.02)
    _expect(len(matches) == 1, "revocation publisher journal result is ambiguous")
    row = matches[0]
    invocation = row.get("_SYSTEMD_INVOCATION_ID")
    _expect(
        isinstance(invocation, str)
        and re.fullmatch(r"[0-9a-f]{32}", invocation)
        and invocation != "0" * 32
        and row.get("_SYSTEMD_UNIT") == _PUBLISHER_UNIT
        and row.get("_UID") == str(broker_uid)
        and row.get("_GID") == str(runtime_gid)
        and row.get("SYSLOG_IDENTIFIER") == "aragorn-runtime-revocation-publisher"
        and isinstance(row.get("_PID"), str)
        and row["_PID"].isdigit()
        and int(row["_PID"]) > 0,
        "revocation publisher journal identity is unbound",
    )
    retained_fields = (
        "MESSAGE",
        "SYSLOG_IDENTIFIER",
        "_BOOT_ID",
        "_GID",
        "_PID",
        "_SYSTEMD_INVOCATION_ID",
        "_SYSTEMD_UNIT",
        "_UID",
        "__CURSOR",
        "__MONOTONIC_TIMESTAMP",
        "__REALTIME_TIMESTAMP",
    )
    return {
        "after_cursor": after_cursor,
        "record": {field: row[field] for field in retained_fields},
        "result": result,
        "result_digest": canonical_digest(result),
    }


def _stable_processes(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> bool:
    fields = (
        "pid",
        "start_time_ticks",
        "mount_namespace",
        "network_namespace",
        "uids",
        "gids",
        "groups",
        "capabilities_effective",
        "no_new_privileges",
    )
    return all(
        all(before[name][field] == after[name][field] for field in fields)
        for name in before
    ) and all(
        before[name]["cmdline"] == after[name]["cmdline"]
        for name in ("broker", "sensor")
    )


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

    node = _file(base.prior._NODE)
    _expect(node["digest"] == base.prior._NODE_DIGEST, "pinned Node changed")
    runtime_snapshot = base.prior._runtime_snapshot()
    skill = _file(base.prior._SKILL)
    _expect(skill["digest"] == base.prior._SKILL_DIGEST, "pinned skill changed")
    _, plugin_digest = base.prior.openclaw_prior._plugin_artifacts()
    _expect(plugin_digest == base.prior._PLUGIN_DIGEST, "pinned plugin changed")

    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(protected_fd, _TARGET, _PAYLOAD)
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-5b-pinned-openclaw-local-systemd-revocation",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": base.prior._SENSOR_DIGEST,
        "revocation_source_digest": base.prior._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": base.prior._RUNTIME_DIGEST,
                "active_skill_digest": base.prior._SKILL_DIGEST,
                **action,
            }
        ],
    }
    config = base.prior._gateway_config(policy, plugin_digest, identities)
    base.prior._CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    base.prior._write_document(base.prior._CONFIG, config, 0, 0, 0o444)

    verification = _run(
        [
            "systemd-analyze",
            "verify",
            f"/usr/lib/systemd/system/{_BROKER_UNIT}",
            f"/usr/lib/systemd/system/{_SENSOR_UNIT}",
            f"/usr/lib/systemd/system/{_PUBLISHER_UNIT}",
            f"/usr/lib/systemd/system/{_GATEWAY_UNIT}",
        ]
    )
    _systemctl("daemon-reload")
    _systemctl("start", _GATEWAY_UNIT)
    gateway_initial = base._gateway_state(runtime.pw_uid, runtime_gid)
    gateway_pid = gateway_initial["pid"]
    gateway_cgroup = gateway_initial["cgroup"]
    gateway_process = gateway_initial["process"]
    profile_document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": base.prior._RUNTIME_DIGEST,
        "executable_digest": node["digest"],
        "cgroup": gateway_cgroup,
        "skill_path": str(base.prior._SKILL),
    }
    profile = runtime_process_profile(profile_document)

    now = int(time.time())
    initial_controls = base._controls(policy, action, now, counter=1)
    for name, document in initial_controls.items():
        _write_control(_CONTROL / f"{name}.json", document, broker.pw_uid, runtime_gid)
    runtime_binding = {
        "schema": "aragorn/runtime-action-runtime-binding/v2",
        "runtime_digest": base.prior._RUNTIME_DIGEST,
        "runtime_profile_digest": profile.digest,
    }
    observation_binding = {
        "schema": "aragorn/runtime-observation-binding/v2",
        "sensor_digest": base.prior._SENSOR_DIGEST,
        "runtime_profile": profile_document,
    }
    base.prior._write_document(_RUNTIME_BINDING, runtime_binding, 0, 0, 0o400)
    base.prior._write_document(
        _OBSERVATION_BINDING,
        observation_binding,
        0,
        0,
        0o400,
    )
    provenance_bindings = {
        "source_manifest": {
            "schema": "aragorn/evaluator-root-source-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5b-pinned-openclaw-revocation-source",
        },
        "install_context": {
            "schema": "aragorn/evaluator-root-install-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5b-pinned-openclaw-revocation-install",
        },
    }
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": secrets.token_hex(32),
        "source_manifest_digest": canonical_digest(
            provenance_bindings["source_manifest"]
        ),
        "install_context_digest": canonical_digest(
            provenance_bindings["install_context"]
        ),
        "runtime_profile_digest": profile.digest,
        "runtime_digest": base.prior._RUNTIME_DIGEST,
        "active_skill_digest": base.prior._SKILL_DIGEST,
        "sensor_digest": base.prior._SENSOR_DIGEST,
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
    base.prior._write_document(_GRANT_SOURCE, grant, 0, 0, 0o400)
    grant_digest = canonical_digest(grant)
    grant_source_file = _file(_GRANT_SOURCE)
    _expect(
        grant_source_file["stat"]["uid"] == 0
        and grant_source_file["stat"]["gid"] == 0
        and grant_source_file["stat"]["mode"] == "0400"
        and grant_source_file["stat"]["nlink"] == 1,
        "root grant source metadata changed",
    )

    activation_publication_now = int(time.time())
    activation_publication = {
        **initial_controls["revocations"],
        "generation": initial_controls["revocations"]["generation"] + 1,
        "observed_at_unix": activation_publication_now,
        "expires_at_unix": activation_publication_now + 15,
        "skill_digests": [base.prior._SKILL_DIGEST],
    }
    base.prior._write_document(
        _PUBLICATION_SOURCE,
        activation_publication,
        0,
        0,
        0o400,
    )
    activation_publication_source = _file(_PUBLICATION_SOURCE)
    _expect(
        activation_publication_source["digest"]
        == canonical_digest(activation_publication)
        and activation_publication_source["stat"]["uid"] == 0
        and activation_publication_source["stat"]["gid"] == 0
        and activation_publication_source["stat"]["mode"] == "0400"
        and activation_publication_source["stat"]["nlink"] == 1,
        "activation revocation source metadata changed",
    )

    _DRIVER_ROOT.mkdir(mode=0o700)
    os.chown(_DRIVER_ROOT, runtime.pw_uid, runtime_gid)
    activation = _run(["/usr/libexec/aragorn/activate-runtime-capability-host.sh"])
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    _wait_path(_GRANT_STATE)
    broker_unit = base._capability_unit(_BROKER_UNIT)
    sensor_unit = base._capability_unit(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    _expect(
        broker_unit["ActiveState"] == sensor_unit["ActiveState"] == "active"
        and broker_unit["DropInPaths"] == sensor_unit["DropInPaths"] == "",
        "dynamic capability units are not exact and active",
    )
    legacy_routes = base._legacy_routes()
    _expect(
        all(
            route["enabled"] == "masked" and route["active"] != "active"
            for route in legacy_routes.values()
        ),
        "legacy runtime route remained usable",
    )
    publisher_enabled = _systemctl("is-enabled", _PUBLISHER_UNIT, check=False)
    publisher_before = _publisher_unit()
    _expect(
        publisher_enabled.stdout.decode().strip() != "enabled"
        and publisher_before["ActiveState"] != "active",
        "revocation publisher is not manual-only and inactive",
    )

    gateway_after_activation = base._gateway_state(
        runtime.pw_uid,
        runtime_gid,
        expected_cgroup=gateway_cgroup,
    )
    _expect(
        gateway_after_activation["pid"] == gateway_pid
        and gateway_after_activation["process"]["start_time_ticks"]
        == gateway_process["start_time_ticks"],
        "activation replaced the pinned gateway",
    )
    available = _document(_GRANT_STATE)
    _expect(
        available["document"]["schema"] == "aragorn/runtime-capability-grant-state/v1"
        and available["document"]["authority"]
        == "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and available["document"]["status"] == "AVAILABLE"
        and available["document"]["grant_digest"] == grant_digest
        and available["document"]["claim"] is None
        and available["document"]["result"] is None,
        "grant did not initialize as AVAILABLE",
    )

    publication_now = int(time.time())
    publication = {
        **activation_publication,
        "observed_at_unix": publication_now,
        "expires_at_unix": publication_now + 15,
    }
    base.prior._write_document(_PUBLICATION_SOURCE, publication, 0, 0, 0o400)
    publication_source = _file(_PUBLICATION_SOURCE)
    publication_source_document = _document(_PUBLICATION_SOURCE)
    publication_digest = canonical_digest(publication)
    _expect(
        publication_source["digest"] == publication_digest
        and publication_source["bytes"] == len(canonical_json(publication))
        and publication_source_document["document"] == publication
        and publication_source_document["digest"] == publication_digest
        and publication["source_digest"] == policy["revocation_source_digest"]
        and publication["generation"]
        == initial_controls["revocations"]["generation"] + 1
        and publication["skill_digests"] == [base.prior._SKILL_DIGEST]
        and publication_source["stat"]["uid"] == 0
        and publication_source["stat"]["gid"] == 0
        and publication_source["stat"]["mode"] == "0400"
        and publication_source["stat"]["nlink"] == 1,
        "revocation publication source metadata changed",
    )

    before_publication_monotonic_ns = time.monotonic_ns()
    before_publication = {
        "controls": _control_snapshot(),
        "effects": _effect_snapshot(),
        "grant_state": _document(_GRANT_STATE),
        "processes": _process_snapshot(gateway_pid, broker_pid, sensor_pid),
        "sockets": _socket_snapshot(),
        "publication_source": _file(_PUBLICATION_SOURCE),
        "publication_source_document": _document(_PUBLICATION_SOURCE),
    }
    _expect(
        before_publication["grant_state"] == available
        and not before_publication["effects"]["target"]["lexists"]
        and not before_publication["effects"]["protected_entries"]
        and not before_publication["effects"]["staging_entries"]
        and not before_publication["effects"]["profile_pending_exists"]
        and not before_publication["effects"]["profile_receipt_exists"],
        "publication did not start from AVAILABLE with no effect",
    )
    publication_journal_cursor = _journal_cursor()
    publisher_start_monotonic_ns = time.monotonic_ns()
    _systemctl("start", _PUBLISHER_UNIT)
    base.profile_prior._wait_complete(_PUBLISHER_UNIT)
    publisher_after = _publisher_unit()
    publication_result = {
        "schema": "aragorn/runtime-revocation-publication-result/v1",
        "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_AUTHORITY",
        "revocations_digest": publication_digest,
        "generation": publication["generation"],
    }
    publication_journal = _publication_journal(
        publication_journal_cursor,
        publisher_after,
        publication_result,
        broker.pw_uid,
        runtime_gid,
    )
    after_publication = {
        "controls": _control_snapshot(),
        "effects": _effect_snapshot(),
        "grant_state": _document(_GRANT_STATE),
        "processes": _process_snapshot(gateway_pid, broker_pid, sensor_pid),
        "sockets": _socket_snapshot(),
        "publication_source": _file(_PUBLICATION_SOURCE),
        "publication_source_document": _document(_PUBLICATION_SOURCE),
    }
    after_publication_monotonic_ns = time.monotonic_ns()
    expected_state = {
        **before_publication["controls"]["state"]["document"],
        "minimum_revocation_generation": publication["generation"],
    }
    expected_load_credentials = {
        (
            'a(ss) 2 "runtime-binding" "/etc/aragorn/runtime-action-runtime.json" '
            '"revocations" "/etc/aragorn/runtime-action-revocation-publication.json"'
        ),
        (
            'a(ss) 2 "revocations" '
            '"/etc/aragorn/runtime-action-revocation-publication.json" '
            '"runtime-binding" "/etc/aragorn/runtime-action-runtime.json"'
        ),
    }
    publication_checks = {
        "unit_success": publisher_after["ActiveState"] == "inactive"
        and publisher_after["MainPID"] == "0"
        and publisher_after["Result"] == "success"
        and publisher_after["ExecMainStatus"] == "0",
        "unit_identity": publisher_after["User"] == "aragorn-broker"
        and publisher_after["Group"] == "aragorn-runtime"
        and publisher_after["SupplementaryGroups"] == "aragorn-sensor"
        and publisher_after["DropInPaths"] == ""
        and publisher_after["NoNewPrivileges"] == "yes"
        and publisher_after["AmbientCapabilities"] == ""
        and publisher_after["CapabilityBoundingSet"] == "",
        "unit_exec": (
            "/usr/libexec/aragorn/aragorn-runtime-revocation-service.py "
            f"/run/credentials/{_PUBLISHER_UNIT}/runtime-binding "
            f"/run/credentials/{_PUBLISHER_UNIT}/revocations"
        )
        in publisher_after["ExecStart"],
        "unit_credentials": publisher_after["LoadCredential"]
        in expected_load_credentials,
        "unit_fragment": publisher_after["FragmentResolvedPath"]
        == f"/usr/lib/systemd/system/{_PUBLISHER_UNIT}"
        and publisher_after["FragmentDigest"]
        == _file(Path(f"/usr/lib/systemd/system/{_PUBLISHER_UNIT}"))["digest"],
        "journal_result": publication_journal["result"] == publication_result,
        "revocations": after_publication["controls"]["revocations"]["document"]
        == publication
        and before_publication["controls"]["revocations"]["digest"]
        != after_publication["controls"]["revocations"]["digest"],
        "state_floor": after_publication["controls"]["state"]["document"]
        == expected_state
        and before_publication["controls"]["state"]["digest"]
        != after_publication["controls"]["state"]["digest"],
        "unrelated_controls": all(
            before_publication["controls"][name] == after_publication["controls"][name]
            for name in ("policy", "health", "observation")
        ),
        "effects": before_publication["effects"] == after_publication["effects"],
        "grant": before_publication["grant_state"] == after_publication["grant_state"],
        "processes": _stable_processes(
            before_publication["processes"],
            after_publication["processes"],
        ),
        "sockets": before_publication["sockets"] == after_publication["sockets"],
        "source": before_publication["publication_source"]
        == after_publication["publication_source"]
        and before_publication["publication_source_document"]
        == after_publication["publication_source_document"],
    }
    _expect(
        all(publication_checks.values()),
        "local systemd revocation publication changed: "
        + ",".join(name for name, passed in publication_checks.items() if not passed),
    )

    sensor_trace_path = _DRIVER_ROOT / "revoked-sensor.trace"
    broker_trace_path = _DRIVER_ROOT / "revoked-broker.trace"
    sensor_trace_process = base.profile_prior.prior._start_trace(
        sensor_pid,
        sensor_trace_path,
    )
    broker_trace_process = base.profile_prior.prior._start_trace(
        broker_pid,
        broker_trace_path,
    )
    driver_start_monotonic_ns = time.monotonic_ns()
    try:
        driver_input, blocked = base._run_driver(
            "local-systemd-revoked",
            "BLOCK",
            "NOT_PERFORMED",
            runtime.pw_uid,
            runtime_gid,
        )
        sensor_trace = base._trace(
            sensor_trace_process,
            sensor_trace_path,
            sensor_pid,
            ["accept", "connect"],
        )
        broker_trace = base._trace(
            broker_trace_process,
            broker_trace_path,
            broker_pid,
            ["accept"],
        )
    finally:
        base._stop_trace(sensor_trace_process)
        base._stop_trace(broker_trace_process)
    driver_complete_monotonic_ns = time.monotonic_ns()

    blocked_result = base.prior._driver_result(blocked["driver"])
    grant_state = _document(_GRANT_STATE)
    grant_state_file = _file(_GRANT_STATE)
    receipt = _document(_RECEIPT) if _RECEIPT.exists() else None
    receipt_file = _file(_RECEIPT) if _RECEIPT.exists() else None
    broker_state = _document(_CONTROL / "state.json")
    controls_after_action = _control_snapshot()
    effects_after_action = _effect_snapshot()
    processes_after_action = _process_snapshot(gateway_pid, broker_pid, sensor_pid)
    gateway_after_action = base._gateway_state(
        runtime.pw_uid,
        runtime_gid,
        expected_cgroup=gateway_cgroup,
    )
    claim = grant_state["document"].get("claim") or {}
    lease = claim.get("lease") or {}
    result_record = grant_state["document"].get("result") or {}
    profile_result = result_record.get("profile_result") or {}
    receipt_document = receipt["document"] if receipt else {}
    attribution = receipt_document.get("runtime_attribution") or {}
    proof = blocked["driver"].get("scenario", {}).get("proof", {})
    proof_checks = proof.get("checks", {})
    consumed = broker_state["document"].get("consumed", [])
    action_checks = {
        "driver": blocked["status"] == "PASS",
        "provider_tool_call": proof.get("passed") is True
        and proof_checks.get("one_provider_driven_tool_call") is True
        and proof_checks.get("action_result_bound") is True,
        "result": blocked_result is not None
        and blocked_result.get("schema") == "aragorn/runtime-action-broker-result/v1"
        and blocked_result.get("verdict") == "BLOCK"
        and blocked_result.get("effect_status") == "NOT_PERFORMED",
        "sole_reason": blocked_result is not None
        and blocked_result.get("reason_codes") == ["ACTIVE_SKILL_REVOKED"]
        and blocked_result.get("decision", {}).get("reason_codes")
        == ["ACTIVE_SKILL_REVOKED"],
        "decision_revocation": blocked_result is not None
        and blocked_result.get("decision", {}).get("revocation_generation")
        == publication["generation"]
        and blocked_result.get("decision", {}).get("minimum_revocation_generation")
        == publication["generation"]
        and blocked_result.get("decision", {}).get("revocation_snapshot_digest")
        == publication_digest,
        "decision_live_window": blocked_result is not None
        and publication["observed_at_unix"]
        <= blocked_result.get("decision", {}).get("evaluated_at_unix", -1)
        < publication["expires_at_unix"],
        "grant_consumed": grant_state["document"].get("status") == "CONSUMED"
        and grant_state["document"].get("schema")
        == "aragorn/runtime-capability-grant-state/v1"
        and grant_state["document"].get("authority")
        == "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and grant_state["document"].get("grant_digest") == grant_digest
        and claim.get("grant_digest") == grant_digest
        and result_record.get("schema") == "aragorn/runtime-capability-grant-result/v1"
        and result_record.get("authority")
        == "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and result_record.get("grant_digest") == grant_digest
        and result_record.get("lease_digest") == claim.get("lease_digest"),
        "lease": lease.get("schema") == LEASE_SCHEMA
        and lease.get("authority") == LEASE_AUTHORITY
        and claim.get("lease_digest") == canonical_digest(lease)
        and lease.get("grant_digest") == grant_digest
        and lease.get("max_actions") == 1
        and lease.get("runtime_profile_digest") == profile.digest
        and lease.get("runtime_digest") == base.prior._RUNTIME_DIGEST
        and lease.get("active_skill_digest") == base.prior._SKILL_DIGEST
        and lease.get("sensor_digest") == base.prior._SENSOR_DIGEST
        and lease.get("policy_digest") == canonical_digest(policy)
        and lease.get("operation_digest") == action["operation_digest"]
        and lease.get("path_digest") == action["path_digest"]
        and lease.get("payload_digest") == action["payload_digest"],
        "profile_claim": claim.get("profile_claim", {}).get("submission_digest")
        == lease.get("submission_digest")
        and claim.get("profile_claim", {}).get("request_digest")
        == lease.get("request_digest"),
        "receipt": receipt_document.get("schema")
        == "aragorn/runtime-process-profile-receipt/v1"
        and receipt_document.get("authority")
        == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and receipt_document.get("submission_digest") == lease.get("submission_digest")
        and receipt_document.get("runtime_attribution_digest")
        == lease.get("runtime_attribution_digest")
        and receipt_document.get("broker_result") == blocked_result
        and receipt_document.get("broker_result_digest")
        == canonical_digest(blocked_result),
        "profile_result": profile_result.get("schema")
        == "aragorn/runtime-capability-lease-result/v1"
        and profile_result.get("verdict") == "BLOCK"
        and profile_result.get("effect_status") == "NOT_PERFORMED"
        and profile_result.get("lease_digest") == claim.get("lease_digest")
        and profile_result.get("submission_digest") == lease.get("submission_digest")
        and profile_result.get("profile_receipt_digest")
        == canonical_digest(receipt_document)
        and profile_result.get("broker_result_digest")
        == canonical_digest(blocked_result),
        "attribution": attribution.get("profile_digest") == profile.digest
        and attribution.get("runtime_digest") == base.prior._RUNTIME_DIGEST
        and attribution.get("active_skill_digest") == base.prior._SKILL_DIGEST
        and attribution.get("pid") == gateway_pid
        and attribution.get("uid") == runtime.pw_uid
        and attribution.get("gid") == runtime_gid
        and attribution.get("start_time_ticks")
        == int(gateway_process["start_time_ticks"])
        and attribution.get("mount_namespace") == gateway_initial["mount_namespace"],
        "no_effect": not effects_after_action["target"]["lexists"]
        and not effects_after_action["protected_entries"]
        and not effects_after_action["staging_entries"]
        and not effects_after_action["profile_pending_exists"]
        and effects_after_action["profile_receipt_exists"],
        "state": broker_state["document"]["minimum_revocation_generation"]
        == publication["generation"]
        and broker_state["document"]["effect_journal"] is None
        and len(consumed) == 1
        and consumed[0].get("request_digest") == blocked_result.get("request_digest")
        and consumed[0].get("observation_digest")
        == blocked_result.get("observation_digest"),
        "peer_chain": sensor_trace["peer_credentials"]
        == [
            {"pid": gateway_pid, "uid": runtime.pw_uid, "gid": runtime_gid},
            {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
        ]
        and broker_trace["peer_credentials"]
        == [{"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid}],
        "gateway_stable": gateway_after_action["pid"] == gateway_pid
        and gateway_after_action["cgroup"] == gateway_cgroup
        and gateway_after_action["process"]["start_time_ticks"]
        == gateway_process["start_time_ticks"]
        and base.prior._cgroup_processes(gateway_cgroup) == [gateway_pid],
        "services_stable": _stable_processes(
            after_publication["processes"],
            processes_after_action,
        ),
        "sockets_stable": before_publication["sockets"] == _socket_snapshot(),
        "revocation_retained": controls_after_action["revocations"]["document"]
        == publication,
    }
    _expect(
        all(action_checks.values()),
        "revoked OpenClaw action changed: "
        + ",".join(name for name, passed in action_checks.items() if not passed),
    )
    _expect(
        before_publication_monotonic_ns
        <= publisher_start_monotonic_ns
        <= after_publication_monotonic_ns
        <= driver_start_monotonic_ns
        <= driver_complete_monotonic_ns,
        "revocation evidence sequence is not monotonic",
    )
    secret_absent = base._runtime_facing_secret_absence(
        (blocked["driver"],),
        grant,
        grant_digest,
        lease,
    )
    _expect(secret_absent, "runtime-facing output exposed grant or lease authority")

    credentials = {
        "root_runtime_binding": _file(_RUNTIME_BINDING),
        "root_observation_binding": _file(_OBSERVATION_BINDING),
        "root_grant": grant_source_file,
        "root_revocation_publication": publication_source,
        "broker": {
            "runtime_binding": base._credential_file(
                _BROKER_UNIT,
                "runtime-binding",
            ),
            "capability_grant": base._credential_file(
                _BROKER_UNIT,
                "capability-grant",
            ),
        },
        "sensor": {
            "observation_binding": base._credential_file(
                _SENSOR_UNIT,
                "observation-binding",
            ),
            "capability_grant": base._credential_file(
                _SENSOR_UNIT,
                "capability-grant",
            ),
        },
    }
    for copy in (
        credentials["broker"]["capability_grant"],
        credentials["sensor"]["capability_grant"],
    ):
        _expect(
            copy["digest"] == grant_digest and copy["bytes"] == len(grant_raw),
            "systemd grant credential changed",
        )

    return {
        "schema": "aragorn/runtime-revocation-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_5B_LOCAL_SYSTEMD_REVOCATION_OBSERVED",
            "local_systemd_revocation_publication_observed": True,
            "same_gateway_active_skill_block_observed": True,
            "grant_available_to_consumed_observed": True,
            "exact_profile_receipt_bound": True,
            "journal_result_is_durable_provenance": False,
            "cryptographic_authorship_established": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "harness": harness,
        "environment": {
            "platform": sys.platform,
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
            "python": platform.python_version(),
            "node": node,
            "capture_identity": base.profile_prior._identity(),
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
            "activation": {
                "exit_code": activation.returncode,
                "stdout": activation.stdout.decode(),
                "stderr": activation.stderr.decode(),
            },
        },
        "artifacts": artifacts,
        "collector": {
            "probe": _file(Path(__file__).resolve()),
            "dockerfile": _file(
                Path("/src/benchmark/runtime-revocation-openclaw-systemd/Dockerfile")
            ),
            "capture_recipe": _file(
                Path("/src/scripts/capture_runtime_revocation_openclaw_systemd.sh")
            ),
            "base_probe": _file(
                Path("/src/scripts/runtime_capability_openclaw_systemd_probe.py")
            ),
            "driver": _file(base._DRIVER),
            "profile_helper": _file(
                Path("/src/scripts/runtime_process_profile_openclaw_systemd_probe.py")
            ),
            "systemd_helper": _file(
                Path("/src/scripts/runtime_process_profile_systemd_probe.py")
            ),
        },
        "runtime": runtime_snapshot,
        "profile": {
            "digest": profile.digest,
            "document": profile_document,
            "skill": skill,
            "executable": node,
        },
        "identities": {
            "broker": {"uid": broker.pw_uid, "gid": runtime_gid},
            "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
            "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
        },
        "credentials": credentials,
        "inputs": {
            "action": action,
            "policy": policy,
            "gateway_config": config,
            "gateway_config_digest": canonical_digest(config),
            "initial_controls": initial_controls,
            "runtime_binding": runtime_binding,
            "observation_binding": observation_binding,
            "provenance_bindings": provenance_bindings,
            "grant": {"digest": grant_digest, "document": grant},
            "revocation_publication": {
                "digest": publication_digest,
                "document": publication,
            },
            "driver": driver_input,
        },
        "deployment": {
            "directories": {
                "root": _metadata(_ROOT),
                "control": _metadata(_CONTROL),
                "protected": _metadata(_PROTECTED),
                "staging": _metadata(_STAGING),
                "runtime": _metadata(_FRONTEND.parent),
            },
            "gateway": {
                "initial": gateway_initial,
                "after_activation": gateway_after_activation,
                "after_action": gateway_after_action,
            },
            "units": {
                "broker": broker_unit,
                "sensor": sensor_unit,
                "publisher_before": publisher_before,
                "publisher_after": publisher_after,
                "publisher_is_enabled": {
                    "exit_code": publisher_enabled.returncode,
                    "stdout": publisher_enabled.stdout.decode(),
                    "stderr": publisher_enabled.stderr.decode(),
                },
            },
            "legacy_routes": legacy_routes,
            "sockets": {
                "backend": _metadata(_BACKEND),
                "frontend": _metadata(_FRONTEND),
            },
        },
        "publication": {
            "checks": publication_checks,
            "activation_source": {
                "document": activation_publication,
                "file": activation_publication_source,
            },
            "sequence": {
                "before_publication_monotonic_ns": before_publication_monotonic_ns,
                "publisher_start_monotonic_ns": publisher_start_monotonic_ns,
                "after_publication_monotonic_ns": after_publication_monotonic_ns,
            },
            "before": before_publication,
            "unit": publisher_after,
            "journal": publication_journal,
            "after": after_publication,
        },
        "scenario": {
            **blocked,
            "checks": action_checks,
            "sequence": {
                "driver_start_monotonic_ns": driver_start_monotonic_ns,
                "driver_complete_monotonic_ns": driver_complete_monotonic_ns,
            },
            "grant_state_before": available,
            "grant_state_after": grant_state,
            "grant_state_file": grant_state_file,
            "profile_receipt": receipt,
            "profile_receipt_file": receipt_file,
            "broker_state": broker_state,
            "controls_after": controls_after_action,
            "effects_after": effects_after_action,
            "processes_after": processes_after_action,
            "runtime_facing_grant_or_lease_absent": secret_absent,
        },
        "peer_trace": {"sensor": sensor_trace, "broker": broker_trace},
        "timing": {
            "grant_lifetime_seconds": grant["expires_at_unix"]
            - grant["issued_at_unix"],
            "revocation_lifetime_seconds": publication["expires_at_unix"]
            - publication["observed_at_unix"],
            "sensor_deadline_ms": 500,
            "client_deadline_ms": 750,
            "driver_elapsed_ns": blocked["driver_elapsed_ns"],
        },
    }


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise base.prior.ProbeError(
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
        "schema": "aragorn/runtime-revocation-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_5B_LOCAL_SYSTEMD_REVOCATION_NOT_OBSERVED",
            "local_systemd_revocation_publication_observed": False,
            "same_gateway_active_skill_block_observed": False,
            "grant_available_to_consumed_observed": False,
            "exact_profile_receipt_bound": False,
            "journal_result_is_durable_provenance": False,
            "cryptographic_authorship_established": False,
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
            "usage: runtime_revocation_openclaw_systemd_probe.py "
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
