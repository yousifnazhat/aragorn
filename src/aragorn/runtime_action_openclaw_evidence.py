"""Verify the bounded P3.3c pinned-OpenClaw/systemd composition artifact."""

from __future__ import annotations

import errno
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import evaluate_runtime_action
from .runtime_action_systemd_evidence import (
    _client_identity_matches,
    _contains_float,
    _loaded_command_start,
    _nonnegative,
    _positive,
    _positive_text,
    _same_json,
    _systemd_time,
    _trace_peers,
    _verify_mount,
)

_SCHEMA = "aragorn/runtime-action-openclaw-systemd-composition-evidence/v1"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_SYSTEMD_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
)
# Set only after the retained artifact exists. Callers may provide the expected pin
# explicitly while the capture is being qualified.
_EVIDENCE_DIGEST: str | None = (
    "sha256:5ac0a675ac9e123eca28069693a9de118cff13745cc46e16f18d4c6980deb78f"
)
_RUNTIME_DIGEST = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_RUNTIME_ENTRYPOINT_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_NODE_IMAGE = (
    "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
)
_SKILL_NAME = "aragorn-runtime-composition"
_SKILL = (
    "---\n"
    f"name: {_SKILL_NAME}\n"
    "description: Bounded P3.3c native runtime-action composition fixture.\n"
    "---\n"
    "# Aragorn P3.3c fixture\n\n"
    "Call aragorn_runtime_create exactly once with the requested target and content.\n"
)
_SKILL_DIGEST = "sha256:" + hashlib.sha256(_SKILL.encode()).hexdigest()
_REVOCATION_SOURCE = "sha256:" + hashlib.sha256(
    b"aragorn/p3.3c/revocation-source/v1"
).hexdigest()
_BROKER_UNIT = "aragorn-runtime-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-observation-publisher.service"
_PROTECTED = "/var/lib/aragorn-runtime-action/protected"
_FRONTEND = "/run/aragorn-runtime-observation/sensor.sock"
_BACKEND = "/var/lib/aragorn-runtime-action/control/broker.sock"
_PLUGIN = "/opt/aragorn/openclaw/aragorn-runtime-action"
_MJS_PROBE = "/src/benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_TOOL = "aragorn_runtime_create"
_PROVIDER = "aragorn-runtime-action-mock"
_MODEL = "fixture-model"
_MOCK_KEY = "aragorn-runtime-action-mock-local"
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
_PROBE_LIMITATIONS = [
    "SINGLE_DETERMINISTIC_PROVIDER_DRIVEN_CREATE_TOOL_CALL_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
    "OPAQUE_SESSION_RUN_AND_TOOL_IDS_NOT_CAUSAL_ATTRIBUTION",
    "ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "OUTER_SYSTEMD_CONTAINER_AND_CONTROL_PLANE_NOT_ATTESTED_BY_THIS_PROBE",
    "OPENCLAW_ADMISSION_CONFORMANCE_NOT_ESTABLISHED",
    "OPENCLAW_RETURNED_TOOL_RESULT_ISERROR_FLAG_NOT_SECURITY_AUTHORITY",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_SCENARIOS = {
    "allow": (
        "openclaw-allowed.txt",
        "Aragorn P3.3c OpenClaw allowed create\n",
        "ALLOW",
        "CREATED",
    ),
    "unhealthy": (
        "openclaw-unhealthy.txt",
        "Aragorn P3.3c OpenClaw unhealthy block\n",
        "BLOCK",
        "NOT_PERFORMED",
    ),
    "sensor_unavailable": (
        "openclaw-sensor-down.txt",
        "Aragorn P3.3c OpenClaw sensor-down block\n",
        "CLIENT_ERROR",
        "NOT_SUBMITTED",
    ),
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAMESPACE = re.compile(r"(?:mnt|net):\[[1-9][0-9]*\]\Z")
_TARGET = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_SOURCES = {
    "/src/packaging/libexec/aragorn-runtime-action-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service.py"
    ),
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "__init__.py",
            "oci_worker_protocol.py",
            "runtime_action_broker.py",
            "runtime_action_decision.py",
            "runtime_action_observation_publisher.py",
            "runtime_action_service.py",
            "runtime_observation_service.py",
        )
    },
    **{
        f"/src/packaging/openclaw/aragorn-runtime-action/{name}": (
            f"{_PLUGIN}/{name}"
        )
        for name in ("index.js", "openclaw.plugin.json", "package.json")
    },
}
_UNITS = {
    "broker": {
        "name": _BROKER_UNIT,
        "installed": "/usr/lib/systemd/system/aragorn-runtime-action-broker.service",
        "credential": (
            'a(ss) 1 "runtime-binding" '
            '"/etc/aragorn/runtime-action-runtime.json"'
        ),
        "command": (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-service.py",
            f"/run/credentials/{_BROKER_UNIT}/runtime-binding",
        ),
    },
    "sensor": {
        "name": _SENSOR_UNIT,
        "installed": (
            "/usr/lib/systemd/system/"
            "aragorn-runtime-observation-publisher.service"
        ),
        "credential": (
            'a(ss) 1 "observation-binding" '
            '"/etc/aragorn/runtime-action-observation.json"'
        ),
        "command": (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-observation-service.py",
            f"/run/credentials/{_SENSOR_UNIT}/observation-binding",
        ),
    },
}


def verify_runtime_action_openclaw_composition_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.3c without granting RUN, EDR, or release authority."""

    try:
        pin = _EVIDENCE_DIGEST if expected_digest is None else expected_digest
        _expect(_digest(pin), "an explicit retained evidence digest is required")
        _expect(canonical_digest(document) == pin, "evidence changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(
            set(document)
            == {
                "artifacts",
                "authority",
                "collector",
                "decision",
                "deployment",
                "environment",
                "harness",
                "identities",
                "inputs",
                "limitations",
                "peer_trace",
                "recorded_at",
                "scenarios",
                "schema",
            },
            "top-level fields changed",
        )
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(
            _same_json(
                document["decision"],
                {
                    "status": "P3_3C_OBSERVED",
                    "bounded_systemd_profile_observed": True,
                    "pinned_openclaw_composition_observed": True,
                    "run_01_eligible": False,
                    "run_02_eligible": False,
                    "phase3_exit_eligible": False,
                    "edr_claim_eligible": False,
                    "public_release_eligible": False,
                },
            ),
            "authority ceiling changed",
        )
        _time(document["recorded_at"])
        identities = _verify_environment_artifacts(document)
        _verify_deployment(document, identities)
        _verify_inputs(document)
        _verify_negative_cases(document, identities)
        _verify_openclaw_cases(document, identities)
        _verify_process_and_filesystem_separation(document)
        _verify_recording_time(document)
    except (IndexError, KeyError, RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionEvidenceError):
            raise
        raise AdmissionEvidenceError(
            f"invalid runtime OpenClaw composition evidence: {exc}"
        ) from exc


def _verify_environment_artifacts(
    document: Mapping[str, Any],
) -> dict[str, int]:
    environment = document["environment"]
    _expect(
        set(environment)
        == {
            "architecture",
            "capture_identity",
            "container_id",
            "kernel_release",
            "node",
            "node_binary",
            "pid1_mount_namespace",
            "pid1_network_namespace",
            "platform",
            "python",
            "strace",
            "systemd",
            "systemd_verify",
        }
        and environment["platform"] == "linux"
        and environment["architecture"] == "aarch64"
        and environment["python"] == "3.12.13"
        and environment["node"] == "v24.16.0"
        and environment["systemd"] == "systemd 252 (252.39-1~deb12u2)"
        and environment["strace"] == "strace -- version 6.1"
        and re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[-+._0-9A-Za-z]*",
            environment["kernel_release"],
        )
        and re.fullmatch(r"[0-9a-f]{12}", environment["container_id"])
        and _same_json(
            environment["systemd_verify"],
            {"exit_code": 0, "stdout": "", "stderr": ""},
        )
        and all(
            _NAMESPACE.fullmatch(environment[name]) is not None
            for name in ("pid1_mount_namespace", "pid1_network_namespace")
        ),
        "qualification environment changed",
    )
    capture = environment["capture_identity"]
    _expect(
        _client_identity_matches(capture, 0, 0, [0]),
        "collector was not the exact root principal",
    )
    _verify_file(
        environment["node_binary"],
        "/usr/local/bin/node",
        uid=0,
        gid=0,
        mode="0755",
    )

    harness = document["harness"]
    retained = harness["document"]
    _expect(
        set(harness) == {"digest", "document"}
        and harness["digest"] == canonical_digest(retained)
        and set(retained)
        == {
            "container_id",
            "host_config",
            "image_id",
            "image_reference",
            "node_image",
            "openclaw_runtime_mount",
            "openclaw_runtime_volume",
            "platform",
            "profile_label",
            "schema",
            "systemd_base_image_id",
        }
        and retained["schema"]
        == "aragorn/runtime-action-openclaw-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", retained["container_id"])
        and retained["container_id"].startswith(environment["container_id"])
        and _digest(retained["image_id"])
        and _digest(retained["systemd_base_image_id"])
        and retained["image_id"] != retained["systemd_base_image_id"]
        and retained["image_reference"] == "aragorn-p33c-openclaw-systemd"
        and retained["platform"] == "linux"
        and retained["profile_label"] == "p3.3c"
        and retained["openclaw_runtime_volume"]
        == "aragorn-openclaw-2026-7-1-runtime"
        and _same_json(
            retained["node_image"],
            {
                "architecture": "arm64",
                "id": _NODE_IMAGE.removeprefix("node@"),
                "os": "linux",
                "reference": _NODE_IMAGE,
                "variant": "v8",
            },
        )
        and _same_json(
            retained["openclaw_runtime_mount"],
            {
                "destination": "/runtime",
                "driver": "local",
                "mode": "ro",
                "rw": False,
                "source": "aragorn-openclaw-2026-7-1-runtime",
                "type": "volume",
            },
        )
        and _same_json(
            retained["host_config"],
            {
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
        ),
        "outer harness changed",
    )

    identities = document["identities"]
    _expect(
        set(identities)
        == {
            "attacker_uid",
            "broker_gid",
            "broker_uid",
            "runtime_gid",
            "runtime_uid",
            "sensor_gid",
            "sensor_uid",
        }
        and all(_positive(value) for value in identities.values())
        and len(
            {
                identities["attacker_uid"],
                identities["broker_uid"],
                identities["runtime_uid"],
                identities["sensor_uid"],
            }
        )
        == 4
        and identities["runtime_gid"] != identities["sensor_gid"],
        "principal identities overlap",
    )

    artifacts = document["artifacts"]
    _expect(
        isinstance(artifacts, list) and len(artifacts) == len(_SOURCES),
        "artifact closure changed",
    )
    mapped = {item["source_path"]: item for item in artifacts}
    _expect(set(mapped) == set(_SOURCES), "artifact sources changed")
    for source, installed in _SOURCES.items():
        item = mapped[source]
        mode = (
            "0444"
            if installed.startswith(_PLUGIN)
            else "0755"
            if installed.startswith("/usr/libexec/")
            else "0644"
        )
        _expect(
            set(item)
            == {
                "bytes",
                "installed_digest",
                "installed_path",
                "installed_stat",
                "source_digest",
                "source_path",
            }
            and item["installed_path"] == installed
            and item["source_digest"] == item["installed_digest"]
            and _digest(item["source_digest"])
            and _positive(item["bytes"]),
            f"artifact binding changed: {installed}",
        )
        _verify_metadata(
            item["installed_stat"],
            kind="file",
            uid=0,
            gid=0,
            mode=mode,
            size=item["bytes"],
            nlink=1,
        )

    collector = document["collector"]
    expected_collectors = {
        "dockerfile": (
            "/src/benchmark/runtime-action-openclaw-systemd/Dockerfile",
            "0644",
        ),
        "dockerignore": ("/src/.dockerignore", "0644"),
        "openclaw_probe": (_MJS_PROBE, "0644"),
        "probe": ("/src/scripts/runtime_action_openclaw_systemd_probe.py", "0755"),
        "recipe": ("/src/scripts/capture_runtime_action_openclaw_systemd.sh", "0755"),
    }
    _expect(set(collector) == set(expected_collectors), "collector closure changed")
    for name, (path, mode) in expected_collectors.items():
        _verify_file(collector[name], path, uid=0, gid=0, mode=mode)
    return dict(identities)


def _verify_file(
    value: Mapping[str, Any], path: str, *, uid: int, gid: int, mode: str
) -> None:
    _expect(
        set(value) == {"bytes", "digest", "path", "stat"}
        and value["path"] == path
        and _digest(value["digest"])
        and _positive(value["bytes"]),
        f"file record changed: {path}",
    )
    _verify_metadata(
        value["stat"],
        kind="file",
        uid=uid,
        gid=gid,
        mode=mode,
        size=value["bytes"],
        nlink=1,
    )


def _verify_metadata(
    value: Mapping[str, Any],
    *,
    kind: str,
    uid: int,
    gid: int,
    mode: str,
    size: int | None = None,
    nlink: int | None = None,
) -> None:
    _expect(
        set(value)
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and value["type"] == kind
        and value["uid"] == uid
        and value["gid"] == gid
        and value["mode"] == mode
        and _positive(value["device"])
        and _positive(value["inode"])
        and _positive(value["nlink"])
        and _nonnegative(value["size"])
        and (size is None or value["size"] == size)
        and (nlink is None or value["nlink"] == nlink),
        f"{kind} metadata changed",
    )


def _verify_deployment(
    document: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    deployment = document["deployment"]
    _expect(
        set(deployment)
        == {"directories", "mounts", "processes", "sockets", "targets_before", "units"}
        and deployment["targets_before"] == [],
        "deployment fields changed or protected root was not empty",
    )
    directories = deployment["directories"]
    expected_directories = {
        "root": (0, 0, "0755"),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "protected": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "staging": (ids["broker_uid"], ids["broker_gid"], "0700"),
        "runtime": (ids["sensor_uid"], ids["runtime_gid"], "0750"),
    }
    _expect(set(directories) == set(expected_directories), "directory set changed")
    for name, (uid, gid, mode) in expected_directories.items():
        _verify_metadata(
            directories[name], kind="directory", uid=uid, gid=gid, mode=mode
        )
    sockets = deployment["sockets"]
    _expect(set(sockets) == {"backend", "frontend"}, "socket set changed")
    for name, (uid, gid) in {
        "backend": (ids["broker_uid"], ids["sensor_gid"]),
        "frontend": (ids["sensor_uid"], ids["runtime_gid"]),
    }.items():
        _verify_metadata(
            sockets[name],
            kind="socket",
            uid=uid,
            gid=gid,
            mode="0660",
            size=0,
            nlink=1,
        )
    _expect(
        sockets["backend"]["device"] == directories["control"]["device"]
        and sockets["frontend"]["device"] == directories["runtime"]["device"]
        and len(
            {
                directories[name]["device"]
                for name in ("root", "control", "protected", "staging")
            }
        )
        == 1
        and directories["runtime"]["device"] != directories["root"]["device"],
        "socket parent device changed",
    )

    units = deployment["units"]
    processes = deployment["processes"]
    _expect(
        set(units) == set(processes) == {"broker", "sensor"},
        "service set changed",
    )
    expected_units = {
        "broker": {
            "User": "aragorn-broker",
            "Group": "aragorn-runtime",
            "SupplementaryGroups": "aragorn-sensor",
            "ReadWritePaths": "/var/lib/aragorn-runtime-action",
            "ReadOnlyPaths": "",
            "InaccessiblePaths": "/etc/aragorn/runtime-action-runtime.json",
        },
        "sensor": {
            "User": "aragorn-sensor",
            "Group": "aragorn-sensor",
            "SupplementaryGroups": "aragorn-runtime",
            "ReadWritePaths": "",
            "ReadOnlyPaths": (
                "/var/lib/aragorn-runtime-action/control "
                "/var/lib/aragorn-runtime-action/protected"
            ),
            "InaccessiblePaths": (
                "/etc/aragorn/runtime-action-observation.json "
                "/var/lib/aragorn-runtime-action/staging"
            ),
        },
    }
    installed = {item["installed_path"]: item for item in document["artifacts"]}
    first_event = min(
        _time(
            document["scenarios"][name]["openclaw"]["started_at"]
        ).timestamp()
        for name in (
            "openclaw_allowed_create",
            "openclaw_unhealthy_block",
            "openclaw_sensor_unavailable",
        )
    )
    for name, expected in expected_units.items():
        unit = units[name]
        process = processes[name]
        contract = _UNITS[name]
        start = _loaded_command_start(
            unit["ExecStart"], contract["command"], process["pid"], "ignore_errors=no"
        )
        start_ex = _loaded_command_start(
            unit["ExecStartEx"], contract["command"], process["pid"], "flags="
        )
        _expect(
            set(unit)
            == set(expected)
            | {
                "ActiveState",
                "DropInPaths",
                "ExecStart",
                "ExecStartEx",
                "FragmentDigest",
                "FragmentPath",
                "FragmentResolvedPath",
                "LoadCredential",
                "MainPID",
                "NoNewPrivileges",
                "PrivateMounts",
                "PrivateNetwork",
                "ProtectSystem",
                "RestrictAddressFamilies",
                "SubState",
            }
            and all(unit[key] == value for key, value in expected.items())
            and unit["ActiveState"] == "active"
            and unit["SubState"] == "running"
            and unit["NoNewPrivileges"] == "yes"
            and unit["PrivateMounts"] == "yes"
            and unit["PrivateNetwork"] == "yes"
            and unit["ProtectSystem"] == "strict"
            and unit["RestrictAddressFamilies"] == "AF_UNIX"
            and unit["DropInPaths"] == ""
            and int(unit["MainPID"]) == process["pid"]
            and unit["FragmentPath"]
            == f"/lib/systemd/system/{contract['name']}"
            and unit["FragmentResolvedPath"] == contract["installed"]
            and unit["FragmentDigest"]
            == installed[contract["installed"]]["installed_digest"]
            and unit["LoadCredential"] == contract["credential"]
            and start is not None
            and start == start_ex
            and _systemd_time(start).timestamp() <= first_event,
            f"{name} unit changed",
        )
        uid = ids[f"{name}_uid"]
        gid = ids["runtime_gid"] if name == "broker" else ids["sensor_gid"]
        _verify_process(
            process,
            uid=uid,
            gid=gid,
            groups=sorted([ids["runtime_gid"], ids["sensor_gid"]]),
            command=list(contract["command"]),
        )
    _expect(
        len(
            {
                processes["broker"]["mount_namespace"],
                processes["sensor"]["mount_namespace"],
                document["environment"]["pid1_mount_namespace"],
            }
        )
        == 3
        and len(
            {
                processes["broker"]["network_namespace"],
                processes["sensor"]["network_namespace"],
                document["environment"]["pid1_network_namespace"],
            }
        )
        == 3,
        "service namespaces overlap",
    )

    mounts = deployment["mounts"]
    expected_mounts = {
        "broker_root": (
            "/",
            "/",
            "overlay",
            "overlay",
            {"ro", "nosuid"},
            {"rw"},
            directories["root"]["device"],
        ),
        "broker_action_root": (
            "/var/lib/aragorn-runtime-action",
            "/var/lib/aragorn-runtime-action",
            "overlay",
            "overlay",
            {"rw", "nosuid"},
            {"rw"},
            directories["root"]["device"],
        ),
        "broker_credentials": (
            f"/run/credentials/{_BROKER_UNIT}",
            "/",
            "ramfs",
            "ramfs",
            {"ro", "nodev", "noexec", "nosuid"},
            {"rw", "mode=700"},
        ),
        "sensor_root": (
            "/",
            "/",
            "overlay",
            "overlay",
            {"ro", "nosuid"},
            {"rw"},
            directories["root"]["device"],
        ),
        "sensor_runtime": (
            "/run/aragorn-runtime-observation",
            "/aragorn-runtime-observation",
            "tmpfs",
            "tmpfs",
            {"rw", "nodev", "noexec", "nosuid"},
            {"rw", "mode=755"},
            directories["runtime"]["device"],
        ),
        "sensor_staging": (
            "/var/lib/aragorn-runtime-action/staging",
            "/systemd/inaccessible/dir",
            "tmpfs",
            "tmpfs",
            {"ro", "nodev", "noexec", "nosuid"},
            {"rw", "mode=755"},
        ),
        "sensor_credentials": (
            f"/run/credentials/{_SENSOR_UNIT}",
            "/",
            "ramfs",
            "ramfs",
            {"ro", "nodev", "noexec", "nosuid"},
            {"rw", "mode=700"},
        ),
    }
    _expect(set(mounts) == set(expected_mounts), "systemd mount set changed")
    records = [
        _verify_mount(mounts[name], *expected)
        for name, expected in expected_mounts.items()
    ]
    mount_ids = [record[0] for record in records]
    devices = [record[2] for record in records]
    _expect(
        len(mount_ids) == len(set(mount_ids))
        and all(mount_id != parent for mount_id, parent, _device in records)
        and records[1][1] == records[0][0]
        and records[5][1] == records[3][0]
        and devices[0] == devices[1] == devices[3]
        and devices[4] == devices[5]
        and _same_json(
            mounts["broker_root"]["super_options"],
            mounts["broker_action_root"]["super_options"],
        )
        and _same_json(
            mounts["broker_root"]["super_options"],
            mounts["sensor_root"]["super_options"],
        )
        and _same_json(
            mounts["sensor_runtime"]["super_options"],
            mounts["sensor_staging"]["super_options"],
        )
        and len({devices[0], devices[2], devices[4], devices[6]}) == 4
        and mounts["broker_root"]["raw"] != mounts["sensor_root"]["raw"],
        "systemd mount relationships changed",
    )


def _verify_process(
    value: Mapping[str, Any],
    *,
    uid: int,
    gid: int,
    groups: list[int],
    command: list[str],
) -> None:
    _expect(
        set(value)
        == {
            "capabilities_effective",
            "cmdline",
            "gids",
            "groups",
            "mount_namespace",
            "network_namespace",
            "no_new_privileges",
            "pid",
            "start_time_ticks",
            "uids",
        }
        and value["cmdline"] == command
        and value["uids"] == [uid] * 4
        and value["gids"] == [gid] * 4
        and value["groups"] == groups
        and value["capabilities_effective"] == "0000000000000000"
        and value["no_new_privileges"] == 1
        and _positive(value["pid"])
        and _positive_text(value["start_time_ticks"])
        and _NAMESPACE.fullmatch(value["mount_namespace"]) is not None
        and _NAMESPACE.fullmatch(value["network_namespace"]) is not None,
        "process identity changed",
    )


def _verify_inputs(document: Mapping[str, Any]) -> None:
    inputs = document["inputs"]
    _expect(
        set(inputs)
        == {
            "actions",
            "active_skill_digest",
            "initial_controls",
            "plugin_digest",
            "policy",
            "runtime_digest",
            "sensor_digest",
            "sensor_implementation",
        }
        and inputs["runtime_digest"] == _RUNTIME_DIGEST
        and inputs["active_skill_digest"] == _SKILL_DIGEST
        and _digest(inputs["sensor_digest"])
        and _digest(inputs["plugin_digest"]),
        "input closure changed",
    )
    implementation = inputs["sensor_implementation"]
    _expect(
        set(implementation) == {"digest", "files", "schema"}
        and implementation["schema"]
        == "aragorn/runtime-observation-sensor-implementation/v1"
        and implementation["digest"] == inputs["sensor_digest"]
        and implementation["digest"]
        == canonical_digest(
            {"schema": implementation["schema"], "files": implementation["files"]}
        ),
        "sensor implementation closure changed",
    )
    installed = {item["installed_path"]: item for item in document["artifacts"]}
    expected_sensor_files = [
        ("/usr/lib/aragorn/aragorn/__init__.py", "0644"),
        ("/usr/lib/aragorn/aragorn/oci_worker_protocol.py", "0644"),
        ("/usr/lib/aragorn/aragorn/runtime_action_broker.py", "0644"),
        ("/usr/lib/aragorn/aragorn/runtime_action_decision.py", "0644"),
        (
            "/usr/lib/aragorn/aragorn/runtime_action_observation_publisher.py",
            "0644",
        ),
        ("/usr/lib/aragorn/aragorn/runtime_action_service.py", "0644"),
        ("/usr/lib/aragorn/aragorn/runtime_observation_service.py", "0644"),
        ("/usr/libexec/aragorn/aragorn-runtime-observation-service.py", "0755"),
    ]
    _expect(
        len(implementation["files"]) == len(expected_sensor_files),
        "sensor implementation files changed",
    )
    for observed, (path, mode) in zip(
        implementation["files"], expected_sensor_files, strict=True
    ):
        artifact = installed[path]
        _expect(
            _same_json(
                observed,
                {
                    "path": path,
                    "digest": artifact["installed_digest"],
                    "bytes": artifact["bytes"],
                    "mode": mode,
                },
            ),
            f"sensor implementation file changed: {path}",
        )
    protected = document["deployment"]["directories"]["protected"]
    expected_actions = {}
    for name, (target, content, _verdict, _effect) in _SCENARIOS.items():
        _expect(_TARGET.fullmatch(target) is not None, "scenario target changed")
        expected_actions[name] = {
            "operation_digest": canonical_digest(
                {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
            ),
            "path_digest": canonical_digest(
                {
                    "schema": "aragorn/runtime-protected-path/v1",
                    "root_device": protected["device"],
                    "root_inode": protected["inode"],
                    "target_name": target,
                }
            ),
            "payload_digest": "sha256:"
            + hashlib.sha256(content.encode()).hexdigest(),
        }
    _expect(
        _same_json(inputs["actions"], expected_actions),
        "measured action inputs changed",
    )
    expected_policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-3c-pinned-openclaw-composition",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": inputs["sensor_digest"],
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": sorted(
            [
                {
                    "runtime_digest": _RUNTIME_DIGEST,
                    "active_skill_digest": _SKILL_DIGEST,
                    **action,
                }
                for action in expected_actions.values()
            ],
            key=canonical_json,
        ),
    }
    _expect(
        _same_json(inputs["policy"], expected_policy),
        "policy scope changed",
    )
    _verify_initial_controls(inputs)


def _verify_initial_controls(inputs: Mapping[str, Any]) -> None:
    controls = inputs["initial_controls"]
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"}
        and controls["policy"] == inputs["policy"],
        "initial control closure changed",
    )
    revocations = controls["revocations"]
    health = controls["health"]
    observation = controls["observation"]
    state = controls["state"]
    seed = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "seed-p3-3c",
        "run_id": "seed-p3-3c",
        "tool_call_id": "seed-p3-3c",
        "active_skill_digest": _SKILL_DIGEST,
    }
    _expect(
        _same_json(
            revocations,
            {
                "schema": "aragorn/runtime-action-revocations/v1",
                "source_digest": _REVOCATION_SOURCE,
                "generation": 1,
                "observed_at_unix": revocations["observed_at_unix"],
                "expires_at_unix": revocations["observed_at_unix"] + 15,
                "skill_digests": [],
            },
        )
        and _same_json(
            health,
            {
                "schema": "aragorn/runtime-mediator-health/v1",
                "runtime_digest": _RUNTIME_DIGEST,
                "sensor_digest": inputs["sensor_digest"],
                "epoch": 1,
                "status": "healthy",
                "observed_at_unix": health["observed_at_unix"],
                "expires_at_unix": health["observed_at_unix"] + 15,
            },
        )
        and _same_json(
            observation,
            {
                "schema": "aragorn/runtime-action-observation/v1",
                "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
                "sequence": 1,
                "sensor_digest": inputs["sensor_digest"],
                "observed_at_unix": observation["observed_at_unix"],
                "expires_at_unix": observation["observed_at_unix"] + 5,
                "active": {"schema": "aragorn/runtime-active-context/v1", **seed},
                "measured_action": {
                    "schema": "aragorn/measured-runtime-action/v1",
                    **seed,
                    **inputs["actions"]["allow"],
                },
            },
        )
        and revocations["observed_at_unix"]
        == health["observed_at_unix"]
        == observation["observed_at_unix"]
        and _positive(revocations["observed_at_unix"])
        and _same_json(
            state,
            {
                "schema": "aragorn/runtime-action-broker-state/v2",
                "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "minimum_revocation_generation": 1,
                "minimum_mediator_health_epoch": 1,
                "consumed": [],
                "effect_journal": None,
            },
        ),
        "initial controls changed",
    )


def _verify_negative_cases(
    document: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    scenarios = document["scenarios"]
    expected_fields = {
        "runtime_direct_backend": {"client", "control_after", "control_before", "status"},
        "wrong_backend_uid": {"client", "control_after", "control_before", "status"},
        "wrong_frontend_uid": {"client", "control_after", "control_before", "status"},
        "runtime_direct_write": {
            "control_after",
            "control_before",
            "path",
            "process",
            "result",
            "status",
        },
        "openclaw_allowed_create": {"control_after", "openclaw", "status", "target"},
        "openclaw_unhealthy_block": {
            "control_after",
            "openclaw",
            "status",
            "target_exists",
        },
        "openclaw_sensor_unavailable": {
            "control_after",
            "control_before",
            "frontend_exists",
            "openclaw",
            "runtime_directory",
            "status",
            "target_exists",
            "units",
        },
    }
    _expect(
        set(scenarios) == set(expected_fields)
        and all(
            set(scenarios[name]) == fields and scenarios[name]["status"] == "PASS"
            for name, fields in expected_fields.items()
        ),
        "scenario closure changed",
    )
    inputs = document["inputs"]
    initial = inputs["initial_controls"]
    now = initial["health"]["observed_at_unix"]
    seed = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "seed-p3-3c",
        "run_id": "seed-p3-3c",
        "tool_call_id": "seed-p3-3c",
        "active_skill_digest": _SKILL_DIGEST,
    }
    sample = {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            **seed,
            **inputs["actions"]["allow"],
            "policy_digest": canonical_digest(inputs["policy"]),
            "policy_version": 1,
            "issued_at_unix": now,
            "expires_at_unix": now + 5,
        },
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": _SCENARIOS["allow"][0],
            "payload_base64": "",
        },
    }
    sample_raw = canonical_json(sample)
    sample_digest = "sha256:" + hashlib.sha256(sample_raw).hexdigest()
    before = {name: canonical_digest(value) for name, value in initial.items()}
    direct = scenarios["runtime_direct_backend"]
    wrong_backend = scenarios["wrong_backend_uid"]
    wrong_frontend = scenarios["wrong_frontend_uid"]
    direct_write = scenarios["runtime_direct_write"]
    for item in (direct, wrong_backend, wrong_frontend, direct_write):
        _expect(
            item["control_before"] == item["control_after"] == before,
            "denied action changed controls",
        )
    for item in (direct, wrong_backend, wrong_frontend):
        _expect(
            item["client"]["request_bytes"] == len(sample_raw)
            and item["client"]["request_file_digest"] == sample_digest,
            "negative request binding changed",
        )
    client = direct["client"]
    _expect(
        set(client)
        == {
            "client",
            "elapsed_ns",
            "errno",
            "error",
            "outcome",
            "request_bytes",
            "request_file_digest",
        }
        and client["outcome"] == "CONNECT_ERROR"
        and client["errno"] == errno.EACCES
        and client["error"] == "EACCES"
        and _bounded_elapsed(client["elapsed_ns"])
        and _client_identity_matches(
            client["client"], ids["runtime_uid"], ids["runtime_gid"], []
        ),
        "runtime direct-backend denial changed",
    )
    broker_pid = document["deployment"]["processes"]["broker"]["pid"]
    sensor_pid = document["deployment"]["processes"]["sensor"]["pid"]
    peer_fields = {
        "client",
        "elapsed_ns",
        "errno",
        "error",
        "outcome",
        "request_bytes",
        "request_file_digest",
        "server_peer",
    }
    _expect(
        set(wrong_backend["client"]) == set(wrong_frontend["client"]) == peer_fields
        and wrong_backend["client"]["outcome"] == "PEER_CLOSED"
        and wrong_frontend["client"]["outcome"] == "PEER_CLOSED"
        and all(
            item["client"]["errno"] == 104
            and item["client"]["error"] == "ECONNRESET"
            and _bounded_elapsed(item["client"]["elapsed_ns"])
            for item in (wrong_backend, wrong_frontend)
        )
        and _client_identity_matches(
            wrong_backend["client"]["client"],
            ids["attacker_uid"],
            ids["sensor_gid"],
            [ids["runtime_gid"]],
        )
        and _same_json(
            wrong_backend["client"]["server_peer"],
            {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
        )
        and _client_identity_matches(
            wrong_frontend["client"]["client"],
            ids["attacker_uid"],
            ids["runtime_gid"],
            [],
        )
        and _same_json(
            wrong_frontend["client"]["server_peer"],
            {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
        ),
        "wrong-UID denial changed",
    )
    _expect(
        direct_write["path"] == f"{_PROTECTED}/runtime-bypass.txt"
        and _client_identity_matches(
            direct_write["process"], ids["runtime_uid"], ids["runtime_gid"], []
        )
        and _same_json(
            direct_write["result"],
            {"blocked": True, "errno": errno.EACCES, "error": "EACCES"},
        ),
        "runtime direct-write denial changed",
    )
    _verify_peer_traces(document, ids)


def _verify_peer_traces(
    document: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    traces = document["peer_trace"]
    broker_pid = document["deployment"]["processes"]["broker"]["pid"]
    sensor_pid = document["deployment"]["processes"]["sensor"]["pid"]
    _expect(set(traces) == {"broker", "sensor"}, "peer trace set changed")
    for name, service_pid, kinds in (
        ("broker", broker_pid, ["accept", "accept", "accept"]),
        ("sensor", sensor_pid, ["accept", "accept", "connect", "accept", "connect"]),
    ):
        trace = traces[name]
        peers = _trace_peers(trace["raw"], service_pid, kinds)
        _expect(
            set(trace) == {"peer_credentials", "raw", "raw_digest"}
            and trace["raw_digest"]
            == "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
            and _same_json(trace["peer_credentials"], peers)
            and all(line.startswith(f"{service_pid} ") for line in trace["raw"].splitlines()),
            f"{name} peer trace changed",
        )
    scenarios = document["scenarios"]
    allow_pid = scenarios["openclaw_allowed_create"]["openclaw"]["evidence"]["gateway"][
        "process_before"
    ]["pid"]
    unhealthy_pid = scenarios["openclaw_unhealthy_block"]["openclaw"]["evidence"][
        "gateway"
    ]["process_before"]["pid"]
    _expect(
        _same_json(
            traces["broker"]["peer_credentials"],
            [
                {
                    "pid": scenarios["wrong_backend_uid"]["client"]["client"]["pid"],
                    "uid": ids["attacker_uid"],
                    "gid": ids["sensor_gid"],
                },
                {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
                {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
            ],
        )
        and _same_json(
            traces["sensor"]["peer_credentials"],
            [
                {
                    "pid": scenarios["wrong_frontend_uid"]["client"]["client"]["pid"],
                    "uid": ids["attacker_uid"],
                    "gid": ids["runtime_gid"],
                },
                {"pid": allow_pid, "uid": ids["runtime_uid"], "gid": ids["runtime_gid"]},
                {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
                {
                    "pid": unhealthy_pid,
                    "uid": ids["runtime_uid"],
                    "gid": ids["runtime_gid"],
                },
                {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
            ],
        ),
        "peer relationships changed",
    )


def _bounded_elapsed(value: object) -> bool:
    return _positive(value) and value < 500_000_000


def _verify_openclaw_cases(
    document: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    scenarios = document["scenarios"]
    inputs = document["inputs"]
    cases = {
        "openclaw_allowed_create": "allow",
        "openclaw_unhealthy_block": "unhealthy",
        "openclaw_sensor_unavailable": "sensor_unavailable",
    }
    retained_results = {}
    for case, scenario_id in cases.items():
        wrapper = scenarios[case]["openclaw"]
        profile_root = f"/run/aragorn-openclaw-{scenario_id}"
        config = _expected_probe_input(scenario_id, profile_root, inputs, ids)
        config_path = f"/run/aragorn-openclaw-{scenario_id}.json"
        command = [
            "setpriv",
            f"--reuid={ids['runtime_uid']}",
            f"--regid={ids['runtime_gid']}",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/local/bin/node",
            _MJS_PROBE,
            config_path,
        ]
        evidence = wrapper["evidence"]
        stdout = canonical_json(evidence) + b"\n"
        _expect(
            set(wrapper)
            == {
                "command",
                "completed_at",
                "config",
                "config_digest",
                "control_refreshes",
                "evidence",
                "exit_code",
                "started_at",
                "stderr_bytes",
                "stderr_digest",
                "stdout_bytes",
                "stdout_digest",
            }
            and _same_json(wrapper["config"], config)
            and wrapper["config_digest"] == canonical_digest(config)
            and wrapper["command"] == command
            and wrapper["exit_code"] == 0
            and wrapper["stdout_bytes"] == len(stdout)
            and wrapper["stdout_digest"]
            == "sha256:" + hashlib.sha256(stdout).hexdigest()
            and wrapper["stderr_bytes"] == 0
            and wrapper["stderr_digest"]
            == "sha256:" + hashlib.sha256(b"").hexdigest()
            and _time(wrapper["started_at"])
            <= _time(evidence["recorded_at"])
            <= _time(wrapper["completed_at"]),
            f"{scenario_id} OpenClaw wrapper changed",
        )
        _verify_refreshes(wrapper["control_refreshes"], scenario_id, ids, inputs)
        retained_results[scenario_id] = _verify_probe_evidence(
            evidence, config, config_path, document, ids
        )

    allow = scenarios["openclaw_allowed_create"]
    target = allow["target"]
    allow_action = inputs["actions"]["allow"]
    _expect(
        set(target) == {"bytes", "digest", "path", "stat"}
        and target["path"] == f"{_PROTECTED}/{_SCENARIOS['allow'][0]}"
        and target["digest"] == allow_action["payload_digest"]
        and target["bytes"] == len(_SCENARIOS["allow"][1].encode())
        and target["stat"]["device"]
        == document["deployment"]["directories"]["protected"]["device"],
        "allowed target binding changed",
    )
    _verify_metadata(
        target["stat"],
        kind="file",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
        size=target["bytes"],
        nlink=1,
    )
    _expect(
        scenarios["openclaw_unhealthy_block"]["target_exists"] is False
        and scenarios["openclaw_sensor_unavailable"]["target_exists"] is False
        and scenarios["openclaw_sensor_unavailable"]["frontend_exists"] is False,
        "fail-closed target outcome changed",
    )
    runtime_directory = scenarios["openclaw_sensor_unavailable"]["runtime_directory"]
    _verify_metadata(
        runtime_directory,
        kind="directory",
        uid=ids["sensor_uid"],
        gid=ids["runtime_gid"],
        mode="0750",
    )
    _verify_controls_and_replay(document, ids, retained_results)
    _verify_sensor_stop(document)


def _expected_probe_input(
    scenario_id: str,
    profile_root: str,
    inputs: Mapping[str, Any],
    ids: Mapping[str, int],
) -> dict[str, Any]:
    target, content, verdict, effect = _SCENARIOS[scenario_id]
    return {
        "schema": "aragorn/openclaw-runtime-action-systemd-probe-input/v1",
        "scenario": {
            "id": scenario_id,
            "target_name": target,
            "content": content,
            "expected_verdict": verdict,
            "expected_effect_status": effect,
        },
        "profile_root": profile_root,
        "skill": {"name": _SKILL_NAME, "content": _SKILL, "digest": _SKILL_DIGEST},
        "runtime": {
            "entrypoint": _OPENCLAW,
            "expected_tree_digest": _RUNTIME_DIGEST,
            "expected_version": "OpenClaw 2026.7.1 (2d2ddc4)",
        },
        "plugin": {
            "path": _PLUGIN,
            "digest": inputs["plugin_digest"],
            "config": {
                "activeSkillDigest": _SKILL_DIGEST,
                "expectedBrokerUid": ids["broker_uid"],
                "expectedRuntimeGid": ids["runtime_gid"],
                "expectedRuntimeUid": ids["runtime_uid"],
                "expectedSensorUid": ids["sensor_uid"],
                "policyDigest": canonical_digest(inputs["policy"]),
                "policyVersion": 1,
                "protectedRoot": _PROTECTED,
                "runtimeDigest": _RUNTIME_DIGEST,
                "sensorSocketPath": _FRONTEND,
            },
        },
    }


def _verify_refreshes(
    refreshes: object,
    scenario_id: str,
    ids: Mapping[str, int],
    inputs: Mapping[str, Any],
) -> None:
    _expect(isinstance(refreshes, list), "control refresh list changed")
    if scenario_id == "sensor_unavailable":
        _expect(refreshes == [], "sensor-down case published controls")
        return
    _expect(bool(refreshes), f"{scenario_id} control refreshes are absent")
    status = "healthy" if scenario_id == "allow" else "unhealthy"
    epochs = []
    generations = []
    observed_times = []
    processes = []
    for refresh in refreshes:
        _expect(
            set(refresh) == {"attempt", "health", "process", "revocations"}
            and _positive(refresh["attempt"])
            and refresh["attempt"] <= 3
            and _client_identity_matches(
                refresh["process"],
                ids["broker_uid"],
                ids["runtime_gid"],
                [ids["sensor_gid"]],
            ),
            "control refresh publisher changed",
        )
        health = refresh["health"]
        revocations = refresh["revocations"]
        _expect(
            _same_json(
                health,
                {
                    "schema": "aragorn/runtime-mediator-health/v1",
                    "runtime_digest": _RUNTIME_DIGEST,
                    "sensor_digest": inputs["sensor_digest"],
                    "epoch": health["epoch"],
                    "status": status,
                    "observed_at_unix": health["observed_at_unix"],
                    "expires_at_unix": health["observed_at_unix"] + 15,
                },
            )
            and _positive(health["epoch"])
            and _positive(health["observed_at_unix"])
            and _same_json(
                revocations,
                {
                    "schema": "aragorn/runtime-action-revocations/v1",
                    "source_digest": _REVOCATION_SOURCE,
                    "generation": revocations["generation"],
                    "observed_at_unix": revocations["observed_at_unix"],
                    "expires_at_unix": revocations["observed_at_unix"] + 15,
                    "skill_digests": [],
                },
            )
            and _positive(revocations["generation"])
            and health["observed_at_unix"] == revocations["observed_at_unix"],
            "published control document changed",
        )
        epochs.append(health["epoch"])
        generations.append(revocations["generation"])
        observed_times.append(health["observed_at_unix"])
        processes.append(
            (refresh["process"]["pid"], int(refresh["process"]["start_time_ticks"]))
        )
    _expect(
        epochs == sorted(set(epochs))
        and generations == sorted(set(generations))
        and observed_times == sorted(observed_times)
        and processes == sorted(set(processes), key=lambda value: value[1]),
        "control refresh chronology changed",
    )


def _expected_openclaw_configuration(
    config: Mapping[str, Any], paths: Mapping[str, str]
) -> dict[str, Any]:
    plugin_config = config["plugin"]["config"]
    return {
        "agents": {
            "defaults": {
                "model": {"primary": f"{_PROVIDER}/{_MODEL}"},
                "skills": [_SKILL_NAME],
                "workspace": paths["workspace"],
            },
            "list": [
                {
                    "id": "main",
                    "skills": [_SKILL_NAME],
                    "workspace": paths["workspace"],
                }
            ],
        },
        "models": {
            "mode": "replace",
            "providers": {
                _PROVIDER: {
                    "api": "openai-completions",
                    "apiKey": _MOCK_KEY,
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
                            "id": _MODEL,
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
                    "config": plugin_config,
                    "enabled": True,
                }
            },
            "load": {"paths": [_PLUGIN]},
        },
        "skills": {"load": {"allowSymlinkTargets": [], "extraDirs": [], "watch": False}},
        "tools": {"alsoAllow": [_TOOL]},
    }


def _verify_probe_evidence(
    evidence: Mapping[str, Any],
    config: Mapping[str, Any],
    config_path: str,
    document: Mapping[str, Any],
    ids: Mapping[str, int],
) -> Mapping[str, Any]:
    _expect(
        set(evidence)
        == {
            "authority",
            "configuration",
            "decision",
            "gateway",
            "input",
            "limitations",
            "plugin",
            "probe",
            "profile",
            "provider",
            "recorded_at",
            "runtime",
            "scenario",
            "schema",
            "skill",
            "turn",
        }
        and evidence["schema"]
        == "aragorn/openclaw-runtime-action-systemd-probe-evidence/v1"
        and evidence["authority"]
        == "BOUNDED_PINNED_OPENCLAW_CREATE_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
        and evidence["limitations"] == _PROBE_LIMITATIONS
        and _same_json(
            evidence["decision"],
            {
                "status": "P3_3C_OBSERVED",
                "pinned_openclaw_composition_observed": True,
                "run_01_eligible": False,
                "run_02_eligible": False,
                "phase3_exit_eligible": False,
                "edr_claim_eligible": False,
                "public_release_eligible": False,
            },
        ),
        "nested probe authority changed",
    )
    _time(evidence["recorded_at"])
    paths = {
        "config": f"{config['profile_root']}/config/openclaw.json",
        "home": f"{config['profile_root']}/home",
        "skill": f"{config['profile_root']}/state/skills/{_SKILL_NAME}/SKILL.md",
        "state": f"{config['profile_root']}/state",
        "workspace": f"{config['profile_root']}/workspace",
    }
    input_record = evidence["input"]
    config_raw = canonical_json(config) + b"\n"
    _expect(
        set(input_record) == {"digest", "path", "stat"}
        and input_record["path"] == config_path
        and input_record["digest"]
        == "sha256:" + hashlib.sha256(config_raw).hexdigest(),
        "probe input record changed",
    )
    _verify_metadata(
        input_record["stat"],
        kind="file",
        uid=0,
        gid=ids["runtime_gid"],
        mode="0440",
        size=len(config_raw),
        nlink=1,
    )
    expected_configuration = _expected_openclaw_configuration(config, paths)
    configuration = evidence["configuration"]
    configuration_raw = canonical_json(expected_configuration) + b"\n"
    _expect(
        set(configuration) == {"digest", "document", "file_digest", "path", "stat"}
        and _same_json(configuration["document"], expected_configuration)
        and configuration["digest"] == canonical_digest(expected_configuration)
        and configuration["file_digest"]
        == "sha256:" + hashlib.sha256(configuration_raw).hexdigest()
        and configuration["path"] == paths["config"],
        "OpenClaw configuration changed",
    )
    _verify_metadata(
        configuration["stat"],
        kind="file",
        uid=ids["runtime_uid"],
        gid=ids["runtime_gid"],
        mode="0600",
        size=len(configuration_raw),
        nlink=1,
    )
    profile = evidence["profile"]
    _expect(
        set(profile) == {"created_paths", "profile_root"}
        and profile["created_paths"] == paths,
        "profile closure changed",
    )
    _verify_metadata(
        profile["profile_root"],
        kind="directory",
        uid=ids["runtime_uid"],
        gid=ids["runtime_gid"],
        mode="0700",
    )
    skill = evidence["skill"]
    _expect(
        set(skill) == {"bytes", "digest", "path", "stat"}
        and skill["bytes"] == len(_SKILL.encode())
        and skill["digest"] == _SKILL_DIGEST
        and skill["path"] == paths["skill"],
        "deployed skill changed",
    )
    _verify_metadata(
        skill["stat"],
        kind="file",
        uid=ids["runtime_uid"],
        gid=ids["runtime_gid"],
        mode="0444",
        size=skill["bytes"],
        nlink=1,
    )
    _verify_runtime_and_plugin(evidence, config, document, ids)
    _verify_probe_processes(evidence, config, ids)
    _verify_turn_and_provider(evidence, config, document, ids)
    checks, retained = _derive_probe_checks(evidence, config)
    proof = evidence["scenario"]["proof"]
    _expect(
        set(proof)
        == {
            "checks",
            "exposed_tool_contract",
            "passed",
            "retained_tool_result",
            "retained_tool_result_digest",
            "tool_result",
        }
        and proof["checks"] == checks
        and all(checks.values())
        and proof["passed"] is True
        and proof["exposed_tool_contract"] == _tool_contract()
        and _same_json(proof["tool_result"], retained["message"])
        and _same_json(proof["retained_tool_result"], retained["document"])
        and proof["retained_tool_result_digest"] == retained["digest"],
        "nested proof was not independently reproduced",
    )
    return retained["document"]["result"]


def _verify_turn_and_provider(
    evidence: Mapping[str, Any],
    config: Mapping[str, Any],
    document: Mapping[str, Any],
    ids: Mapping[str, int],
) -> None:
    scenario = evidence["scenario"]
    expected = config["scenario"]
    _expect(
        set(scenario)
        == {
            "content_bytes",
            "content_digest",
            "expected_effect_status",
            "expected_verdict",
            "id",
            "proof",
            "status",
            "target_name",
        }
        and scenario["id"] == expected["id"]
        and scenario["target_name"] == expected["target_name"]
        and scenario["expected_verdict"] == expected["expected_verdict"]
        and scenario["expected_effect_status"] == expected["expected_effect_status"]
        and scenario["content_bytes"] == len(expected["content"].encode())
        and scenario["content_digest"]
        == "sha256:" + hashlib.sha256(expected["content"].encode()).hexdigest()
        and scenario["status"] == "PASS",
        "nested scenario binding changed",
    )
    provider = evidence["provider"]
    _expect(
        set(provider)
        == {"errors", "health_request_count", "records", "request_count", "transport"}
        and provider["errors"] == []
        and provider["health_request_count"] == 0
        and provider["request_count"] == len(provider["records"]) == 2
        and provider["transport"] == "openai-completions"
        and _time(provider["records"][0]["received_at"])
        <= _time(provider["records"][1]["received_at"]),
        "provider boundary changed",
    )
    turn = evidence["turn"]
    _expect(
        set(turn)
        == {"history", "identifiers", "send", "target_after", "target_before", "wait"},
        "turn closure changed",
    )
    scenario_id = expected["id"]
    run_id = f"aragorn-p33c-{scenario_id}"
    session_key = f"agent:main:{run_id}"
    tool_call_id = f"call_aragorn_{re.sub('[^a-z0-9]', '', scenario_id)}_1"
    identifiers = turn["identifiers"]
    _expect(
        set(identifiers) == {"run_id", "session_id", "session_key", "tool_call_id"}
        and identifiers["run_id"] == run_id
        and identifiers["session_key"] == session_key
        and identifiers["tool_call_id"] == tool_call_id
        and isinstance(identifiers["session_id"], str)
        and bool(identifiers["session_id"]),
        "OpenClaw turn identifiers changed",
    )
    user_text = f"Invoke {_TOOL} exactly once for bounded scenario {scenario_id}."
    send_params = canonical_json(
        {
            "deliver": False,
            "idempotencyKey": run_id,
            "message": user_text,
            "sessionKey": session_key,
            "timeoutMs": 10000,
        }
    ).decode("ascii")
    wait_params = canonical_json({"runId": run_id, "timeoutMs": 15000}).decode(
        "ascii"
    )
    history_params = canonical_json({"limit": 20, "sessionKey": session_key}).decode(
        "ascii"
    )
    for name, method, timeout, params in (
        ("send", "chat.send", "5000", send_params),
        ("wait", "agent.wait", "17000", wait_params),
        ("history", "chat.history", "5000", history_params),
    ):
        wrapper = turn[name]
        _expect(set(wrapper) == {"command", "response"}, f"{name} wrapper changed")
        _verify_command_summary(
            wrapper["command"],
            [
                "/usr/local/bin/node",
                _OPENCLAW,
                "gateway",
                "call",
                method,
                "--json",
                "--timeout",
                timeout,
                "--params",
                params,
            ],
        )
    history = turn["history"]["response"]
    _expect(
        set(history)
        == {"defaults", "messages", "sessionId", "sessionInfo", "sessionKey", "thinkingLevel"}
        and history["sessionId"] == identifiers["session_id"]
        and history["sessionKey"] == session_key
        and history["thinkingLevel"] == "off"
        and len(history["messages"]) == 4
        and [message["__openclaw"]["seq"] for message in history["messages"]]
        == [1, 2, 3, 4]
        and [message["timestamp"] for message in history["messages"]]
        == sorted(message["timestamp"] for message in history["messages"]),
        "persisted turn lineage changed",
    )
    protected = document["deployment"]["directories"]["protected"]
    for when in ("target_before", "target_after"):
        target = turn[when]
        _expect(
            set(target) == {"exists", "path", "root", "target"}
            and target["path"] == f"{_PROTECTED}/{expected['target_name']}"
            and target["root"]["device"] == protected["device"]
            and target["root"]["inode"] == protected["inode"]
            and target["root"]["uid"] == ids["broker_uid"]
            and target["root"]["gid"] == ids["runtime_gid"]
            and target["root"]["mode"] == "0710"
            and target["root"]["type"] == "directory",
            "turn target root changed",
        )
    _expect(
        turn["target_before"]["exists"] is False
        and turn["target_before"]["target"] is None
        and (
            turn["target_after"]["exists"] is True
            if expected["expected_verdict"] == "ALLOW"
            else turn["target_after"]["exists"] is False
            and turn["target_after"]["target"] is None
        ),
        "turn target outcome changed",
    )


def _verify_runtime_and_plugin(
    evidence: Mapping[str, Any],
    config: Mapping[str, Any],
    document: Mapping[str, Any],
    ids: Mapping[str, int],
) -> None:
    runtime = evidence["runtime"]
    _expect(
        set(runtime)
        == {
            "entrypoint",
            "entrypoint_digest",
            "expected_version",
            "root",
            "tree",
            "version_command",
            "version_output",
        }
        and runtime["entrypoint"] == _OPENCLAW
        and runtime["entrypoint_digest"] == _RUNTIME_ENTRYPOINT_DIGEST
        and runtime["root"] == "/runtime"
        and runtime["expected_version"]
        == runtime["version_output"]
        == "OpenClaw 2026.7.1 (2d2ddc4)"
        and _same_json(
            runtime["tree"],
            {
                "algorithm": "aragorn/runtime-tree/v1",
                "entry_count": 45856,
                "file_count": 45837,
                "symlink_count": 19,
                "total_bytes": 369317461,
                "tree_digest": _RUNTIME_DIGEST,
            },
        ),
        "pinned OpenClaw runtime changed",
    )
    _verify_command_summary(
        runtime["version_command"],
        ["/usr/local/bin/node", _OPENCLAW, "--version"],
    )
    plugin = evidence["plugin"]
    _expect(
        set(plugin) == {"configured_path", "expected_tree_digest", "inspect", "snapshot"}
        and plugin["configured_path"] == _PLUGIN
        and plugin["expected_tree_digest"] == config["plugin"]["digest"],
        "plugin pin changed",
    )
    snapshot = plugin["snapshot"]
    _expect(
        set(snapshot) == {"files", "root", "tree"}
        and _same_json(
            snapshot["tree"],
            {
                "algorithm": "aragorn/plugin-tree/v1",
                "entry_count": 3,
                "file_count": 3,
                "symlink_count": 0,
                "total_bytes": sum(item["bytes"] for item in snapshot["files"]),
                "tree_digest": config["plugin"]["digest"],
            },
        ),
        "plugin tree changed",
    )
    _verify_metadata(
        snapshot["root"], kind="directory", uid=0, gid=0, mode="0555"
    )
    artifacts = {
        item["installed_path"]: item
        for item in document["artifacts"]
        if item["installed_path"].startswith(_PLUGIN)
    }
    _expect(len(snapshot["files"]) == 3, "plugin file closure changed")
    for item in snapshot["files"]:
        _verify_file(item, item["path"], uid=0, gid=0, mode="0444")
        retained = artifacts[item["path"]]
        _expect(
            item["digest"] == retained["installed_digest"]
            and item["bytes"] == retained["bytes"]
            and item["stat"] == retained["installed_stat"],
            "plugin source/install/snapshot binding changed",
        )
    inspect = plugin["inspect"]
    _expect(
        set(inspect) == {"command", "response"}
        and isinstance(inspect["response"], Mapping)
        and isinstance(inspect["response"].get("plugin"), Mapping),
        "plugin inspection changed",
    )
    _verify_command_summary(
        inspect["command"],
        [
            "/usr/local/bin/node",
            _OPENCLAW,
            "plugins",
            "inspect",
            "aragorn-runtime-action",
            "--json",
        ],
    )
    probe = evidence["probe"]
    _expect(
        set(probe) == {"implementation_digest", "process"}
        and probe["implementation_digest"]
        == document["collector"]["openclaw_probe"]["digest"],
        "probe implementation changed",
    )


def _verify_probe_processes(
    evidence: Mapping[str, Any], config: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    probe = evidence["probe"]["process"]
    config_path = evidence["input"]["path"]
    _verify_process(
        probe,
        uid=ids["runtime_uid"],
        gid=ids["runtime_gid"],
        groups=[],
        command=["/usr/local/bin/node", _MJS_PROBE, config_path],
    )
    gateway = evidence["gateway"]
    _expect(
        set(gateway)
        == {
            "process_after",
            "process_before",
            "readiness_command",
            "shutdown",
            "spawned_pid",
            "system_info",
        }
        and gateway["process_before"] == gateway["process_after"],
        "Gateway process record changed",
    )
    _verify_process(
        gateway["process_before"],
        uid=ids["runtime_uid"],
        gid=ids["runtime_gid"],
        groups=[],
        command=["openclaw-gateway"],
    )
    gateway_pid = gateway["process_before"]["pid"]
    _expect(
        gateway["spawned_pid"] == gateway["system_info"]["pid"] == gateway_pid
        and gateway_pid != probe["pid"]
        and gateway["process_before"]["mount_namespace"] == probe["mount_namespace"]
        and gateway["process_before"]["network_namespace"] == probe["network_namespace"],
        "Gateway identity changed",
    )
    _verify_command_summary(
        gateway["readiness_command"],
        [
            "/usr/local/bin/node",
            _OPENCLAW,
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ],
    )
    shutdown = gateway["shutdown"]
    _expect(
        set(shutdown)
        == {"exit_code", "pid", "signal", "spawn_error", "stderr", "stdout"}
        and shutdown["pid"] == gateway_pid
        and shutdown["spawn_error"] is None
        and (shutdown["exit_code"] is not None or shutdown["signal"] is not None),
        "Gateway was not exactly stopped and reaped",
    )
    for stream in (shutdown["stderr"], shutdown["stdout"]):
        _expect(
            set(stream) == {"bytes", "digest", "excerpt", "retained_bytes", "truncated"}
            and _nonnegative(stream["bytes"])
            and _digest(stream["digest"])
            and isinstance(stream["excerpt"], str)
            and _nonnegative(stream["retained_bytes"])
            and stream["retained_bytes"] <= stream["bytes"] <= 1024 * 1024
            and stream["truncated"] is (stream["bytes"] > stream["retained_bytes"]),
            "Gateway bounded log record changed",
        )


def _verify_command_summary(value: Mapping[str, Any], argv: list[str]) -> None:
    _expect(
        set(value)
        == {
            "argv",
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stderr_digest",
            "stdout_bytes",
            "stdout_digest",
        }
        and value["argv"] == argv
        and value["exit_code"] == 0
        and value["error"] is None
        and value["signal"] is None
        and _positive(value["pid"])
        and _nonnegative(value["stdout_bytes"])
        and _nonnegative(value["stderr_bytes"])
        and _digest(value["stdout_digest"])
        and _digest(value["stderr_digest"])
        and _time(value["started_at"]) <= _time(value["completed_at"]),
        "OpenClaw command summary changed",
    )


def _tool_contract() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": _TOOL,
            "description": (
                "Create one policy-authorized file through the Aragorn runtime broker."
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["content", "target_name"],
                "properties": {
                    "content": {"maxLength": 32768, "type": "string"},
                    "target_name": {
                        "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$",
                        "type": "string",
                    },
                },
            },
        },
    }


def _derive_probe_checks(
    evidence: Mapping[str, Any], config: Mapping[str, Any]
) -> tuple[dict[str, bool], dict[str, Any]]:
    provider = evidence["provider"]
    records = provider["records"]
    first, second = records
    body = first["body"]
    contracts = [
        tool
        for tool in body.get("tools", [])
        if tool.get("function", {}).get("name") == _TOOL
    ]
    contract = contracts[0] if contracts else None
    scenario = config["scenario"]
    expected_arguments = {
        "content": scenario["content"],
        "target_name": scenario["target_name"],
    }
    run_id = f"aragorn-p33c-{scenario['id']}"
    session_key = f"agent:main:{run_id}"
    tool_call_id = evidence["turn"]["identifiers"]["tool_call_id"]
    transport_id = tool_call_id.replace("_", "")
    final_text = (
        f"ARAGORN_RUNTIME_ACTION_{scenario['expected_verdict']}_"
        f"{scenario['expected_effect_status']}"
    )
    history = evidence["turn"]["history"]["response"]
    messages = history["messages"]
    user, assistant, tool_result, final = messages
    retained = _retained_tool_result(tool_result)
    details = retained["document"]["result"]
    client_error = scenario["expected_verdict"] == "CLIENT_ERROR"
    reasons = (
        []
        if scenario["expected_verdict"] == "ALLOW"
        else ["MEDIATOR_UNHEALTHY"]
        if scenario["expected_verdict"] == "BLOCK"
        else None
    )
    expected_text = (
        f"Aragorn runtime action failed closed: {scenario['expected_effect_status']}"
        if client_error
        else f"Aragorn {scenario['expected_verdict']}: {scenario['expected_effect_status']}"
    )
    result_bound = (
        _same_json(
            details,
            {
                "schema": "aragorn/runtime-action-client-error/v1",
                "authority": "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
                "effect_status": "NOT_SUBMITTED",
                "message": "sensor socket is unavailable: ENOENT",
            },
        )
        if client_error
        else set(details)
        == {
            "authority",
            "decision",
            "effect_status",
            "observation_digest",
            "reason_codes",
            "request_digest",
            "schema",
            "target_name",
            "verdict",
        }
        and details["schema"] == "aragorn/runtime-action-broker-result/v1"
        and details["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and details["verdict"]
        == details["decision"]["verdict"]
        == scenario["expected_verdict"]
        and details["effect_status"] == scenario["expected_effect_status"]
        and details["target_name"] == scenario["target_name"]
        and details["reason_codes"] == details["decision"]["reason_codes"] == reasons
        and _digest(details["request_digest"])
        and _digest(details["observation_digest"])
    )
    first_count = len(first["body"]["messages"])
    transport_assistant = second["body"]["messages"][first_count]
    transport_tool = second["body"]["messages"][first_count + 1]
    provider_call = first["response"][0]["choices"][0]["delta"]["tool_calls"][0]
    target_before = evidence["turn"]["target_before"]
    target_after = evidence["turn"]["target_after"]
    stable_root_fields = ("device", "gid", "inode", "mode", "type", "uid")
    target_outcome = (
        target_after["exists"] is True
        and target_after["target"]["type"] == "file"
        and target_after["target"]["uid"]
        == config["plugin"]["config"]["expectedBrokerUid"]
        and target_after["target"]["gid"]
        == config["plugin"]["config"]["expectedRuntimeGid"]
        and target_after["target"]["mode"] == "0400"
        and target_after["target"]["nlink"] == 1
        and target_after["target"]["size"] == len(scenario["content"].encode())
        if scenario["expected_verdict"] == "ALLOW"
        else target_after["exists"] is False
    )
    inspect_plugin = evidence["plugin"]["inspect"]["response"]["plugin"]
    send = evidence["turn"]["send"]["response"]
    wait = evidence["turn"]["wait"]["response"]
    system_prompt = "\n".join(
        message["content"]
        for message in first["body"].get("messages", [])
        if message.get("role") == "system"
    )
    auth_digest = "sha256:" + hashlib.sha256(
        f"Bearer {_MOCK_KEY}".encode()
    ).hexdigest()
    checks = {
        "action_result_bound": bool(result_bound),
        "exact_exposed_tool_contract": len(contracts) == 1
        and _same_json(contract, _tool_contract()),
        "gateway_process_stable": evidence["gateway"]["process_before"]
        == evidence["gateway"]["process_after"]
        and evidence["gateway"]["process_before"]["cmdline"]
        == ["openclaw-gateway"]
        and evidence["gateway"]["process_before"]["mount_namespace"]
        == evidence["probe"]["process"]["mount_namespace"]
        and evidence["gateway"]["process_before"]["network_namespace"]
        == evidence["probe"]["process"]["network_namespace"],
        "history_lineage": [message.get("role") for message in messages]
        == ["user", "assistant", "toolResult", "assistant"]
        and user["content"]
        == f"Invoke {_TOOL} exactly once for bounded scenario {scenario['id']}."
        and user["idempotencyKey"] == f"{send['runId']}:user"
        and len(assistant["content"]) == 1
        and assistant["content"][0]["id"] == tool_call_id
        and assistant["content"][0]["name"] == _TOOL
        and assistant["content"][0]["arguments"] == expected_arguments
        and assistant["content"][0]["partialArgs"]
        == canonical_json(expected_arguments).decode("ascii")
        and assistant["stopReason"] == "toolUse"
        and tool_result["toolCallId"] == tool_call_id
        and tool_result["toolName"] == _TOOL
        and tool_result["isError"] is False
        and retained["document"]["message"] == expected_text
        and "details" not in tool_result
        and _text_content(tool_result) == retained["raw"]
        and final["provider"] == _PROVIDER
        and final["model"] == _MODEL
        and final["stopReason"] == "stop"
        and _text_content(final) == final_text,
        "one_provider_driven_tool_call": len(records) == 2
        and [record["sequence"] for record in records] == [1, 2]
        and all(record["body"]["model"] == _MODEL for record in records)
        and all(record["authorization_digest"] == auth_digest for record in records)
        and all(_valid_provider_record(record) for record in records)
        and all(
            message.get("role") not in {"assistant", "tool"}
            for message in first["body"]["messages"]
        )
        and len(first["response"]) == 1
        and len(first["response"][0]["choices"]) == 1
        and first["response"][0]["choices"][0]["finish_reason"] == "tool_calls"
        and len(first["response"][0]["choices"][0]["delta"]["tool_calls"]) == 1
        and provider_call["id"] == tool_call_id
        and provider_call["function"]["name"] == _TOOL
        and provider_call["function"]["arguments"]
        == canonical_json(expected_arguments).decode("ascii")
        and transport_assistant["role"] == "assistant"
        and len(transport_assistant["tool_calls"]) == 1
        and transport_assistant["tool_calls"][0]["id"] == transport_id
        and transport_assistant["tool_calls"][0]["function"]["name"] == _TOOL
        and transport_assistant["tool_calls"][0]["function"]["arguments"]
        == canonical_json(expected_arguments).decode("ascii")
        and transport_tool["role"] == "tool"
        and transport_tool["tool_call_id"] == transport_id
        and transport_tool["content"] == retained["raw"]
        and len(second["body"]["messages"]) == first_count + 2
        and _same_json(
            second["body"]["messages"][:first_count], first["body"]["messages"]
        )
        and len(second["response"]) == 2
        and len(second["response"][0]["choices"]) == 1
        and second["response"][0]["choices"][0]["delta"]["content"]
        == final_text
        and len(second["response"][1]["choices"]) == 1
        and second["response"][1]["choices"][0]["finish_reason"] == "stop",
        "plugin_loaded_from_pinned_path": inspect_plugin["id"]
        == "aragorn-runtime-action"
        and inspect_plugin["source"] == f"{_PLUGIN}/index.js"
        and inspect_plugin["status"] == "loaded"
        and inspect_plugin["version"] == "0.1.0",
        "provider_completed_without_error": provider["errors"] == [],
        "session_bound": send == {"status": "started", "runId": run_id}
        and wait["runId"] == run_id
        and wait["status"] == "ok"
        and _nonnegative(wait["endedAt"])
        and history["sessionKey"] == session_key
        and isinstance(history["sessionId"], str)
        and bool(history["sessionId"])
        and history["sessionInfo"]["key"] == session_key
        and history["sessionInfo"]["status"] == "done"
        and history["sessionInfo"]["activeRunIds"] == [],
        "skill_deployment_pin_visible": f"<name>{_SKILL_NAME}</name>"
        in system_prompt
        and f"<version>{_SKILL_DIGEST[:23]}</version>" in system_prompt,
        "target_effect_matches_result": target_before["exists"] is False
        and target_outcome
        and all(
            target_after["root"][field] == target_before["root"][field]
            for field in stable_root_fields
        ),
    }
    return checks, retained


def _retained_tool_result(message: Mapping[str, Any]) -> dict[str, Any]:
    _expect(
        isinstance(message.get("content"), list)
        and len(message["content"]) == 1
        and set(message["content"][0]) == {"text", "type"}
        and message["content"][0]["type"] == "text"
        and isinstance(message["content"][0]["text"], str),
        "retained tool result content changed",
    )
    raw = message["content"][0]["text"]
    retained = json.loads(raw)
    _expect(
        set(retained) == {"message", "result", "schema"}
        and retained["schema"] == "aragorn/runtime-action-tool-result-text/v1"
        and isinstance(retained["message"], str)
        and isinstance(retained["result"], Mapping)
        and canonical_json(retained) == raw.encode("ascii"),
        "retained tool result is not exact canonical JSON",
    )
    return {
        "digest": "sha256:" + hashlib.sha256(raw.encode("ascii")).hexdigest(),
        "document": retained,
        "message": message,
        "raw": raw,
    }


def _text_content(message: Mapping[str, Any]) -> str:
    return "".join(
        part["text"]
        for part in message.get("content", [])
        if isinstance(part, Mapping) and part.get("type") == "text"
    )


def _valid_provider_record(record: Mapping[str, Any]) -> bool:
    try:
        raw = record["body_raw"].encode()
        return (
            set(record)
            == {
                "authorization_digest",
                "body",
                "body_bytes",
                "body_digest",
                "body_raw",
                "content_type",
                "method",
                "path",
                "received_at",
                "response",
                "response_digest",
                "sequence",
            }
            and record["method"] == "POST"
            and record["path"] == "/v1/chat/completions"
            and record["content_type"] == "application/json"
            and record["body_bytes"] == len(raw)
            and record["body_digest"]
            == "sha256:" + hashlib.sha256(raw).hexdigest()
            and _same_json(json.loads(raw), record["body"])
            and record["response_digest"]
            == "sha256:" + hashlib.sha256(canonical_json(record["response"])).hexdigest()
            and _time(record["received_at"])
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _verify_controls_and_replay(
    document: Mapping[str, Any],
    ids: Mapping[str, int],
    results: Mapping[str, Mapping[str, Any]],
) -> None:
    scenarios = document["scenarios"]
    inputs = document["inputs"]
    controls_by_scenario = {
        "allow": scenarios["openclaw_allowed_create"]["control_after"],
        "unhealthy": scenarios["openclaw_unhealthy_block"]["control_after"],
    }
    reconstructed = {}
    for scenario_id, controls in controls_by_scenario.items():
        _expect(
            set(controls) == {"health", "observation", "policy", "revocations", "state"}
            and all(
                set(wrapper) == {"digest", "document"}
                and wrapper["digest"] == canonical_digest(wrapper["document"])
                for wrapper in controls.values()
            )
            and controls["policy"]["document"] == inputs["policy"],
            f"{scenario_id} retained controls changed",
        )
        wrapper = scenarios[
            "openclaw_allowed_create"
            if scenario_id == "allow"
            else "openclaw_unhealthy_block"
        ]["openclaw"]
        result = results[scenario_id]
        verdict = _SCENARIOS[scenario_id][2]
        effect_status = _SCENARIOS[scenario_id][3]
        reasons = [] if scenario_id == "allow" else ["MEDIATOR_UNHEALTHY"]
        _expect(
            result["schema"] == "aragorn/runtime-action-broker-result/v1"
            and result["authority"]
            == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
            and result["target_name"] == _SCENARIOS[scenario_id][0]
            and result["verdict"] == verdict
            and result["effect_status"] == effect_status
            and result["reason_codes"] == reasons
            and result["decision"]["verdict"] == verdict
            and result["decision"]["reason_codes"] == reasons
            and result["request_digest"] == result["decision"]["request_digest"]
            and result["observation_digest"] == controls["observation"]["digest"],
            f"{scenario_id} authoritative result changed",
        )
        request = _reconstruct_request(
            scenario_id, wrapper, result["request_digest"], inputs
        )
        decision = result["decision"]
        observation = controls["observation"]["document"]
        expected_attribution = {
            "runtime_digest": _RUNTIME_DIGEST,
            "session_id": wrapper["evidence"]["turn"]["identifiers"]["session_id"],
            "run_id": f"aragorn-p33c-{scenario_id}",
            "tool_call_id": "sha256:"
            + hashlib.sha256(
                wrapper["evidence"]["turn"]["identifiers"]["tool_call_id"].encode()
            ).hexdigest(),
            "active_skill_digest": _SKILL_DIGEST,
        }
        _expect(
            _same_json(
                observation,
                {
                    "schema": "aragorn/runtime-action-observation/v1",
                    "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
                    "sequence": 2 if scenario_id == "allow" else 3,
                    "sensor_digest": inputs["sensor_digest"],
                    "observed_at_unix": decision["evaluated_at_unix"],
                    "expires_at_unix": decision["evaluated_at_unix"] + 5,
                    "active": {
                        "schema": "aragorn/runtime-active-context/v1",
                        **expected_attribution,
                    },
                    "measured_action": {
                        "schema": "aragorn/measured-runtime-action/v1",
                        **expected_attribution,
                        **inputs["actions"][scenario_id],
                    },
                },
            )
            and all(
                request[field] == value for field, value in expected_attribution.items()
            ),
            f"{scenario_id} out-of-process observation changed",
        )
        health = _reconstruct_health(decision, verdict, inputs["sensor_digest"])
        revocations = _reconstruct_revocations(decision)
        state = controls["state"]["document"]
        _verify_state(state)
        replay = evaluate_runtime_action(
            request,
            inputs["policy"],
            now_unix=decision["evaluated_at_unix"],
            active=observation["active"],
            measured_action=observation["measured_action"],
            revocations=revocations,
            minimum_revocation_generation=decision["minimum_revocation_generation"],
            mediator_health=health,
            minimum_mediator_health_epoch=decision["minimum_mediator_health_epoch"],
        )
        _expect(
            _same_json(replay, decision),
            f"{scenario_id} deterministic decision replay changed",
        )
        refreshes = wrapper["control_refreshes"]
        _expect(
            controls["health"]["document"] == refreshes[-1]["health"]
            and controls["revocations"]["document"] == refreshes[-1]["revocations"]
            and state["minimum_mediator_health_epoch"]
            == controls["health"]["document"]["epoch"]
            and state["minimum_revocation_generation"]
            == controls["revocations"]["document"]["generation"]
            and controls["health"]["document"]["status"]
            == ("healthy" if scenario_id == "allow" else "unhealthy"),
            f"{scenario_id} post-decision control transition changed",
        )
        reconstructed[scenario_id] = {
            "request": request,
            "result": result,
            "state": state,
        }

    expected_consumed = {
        scenario_id: {
            "request_digest": item["result"]["request_digest"],
            "observation_digest": item["result"]["observation_digest"],
            "expires_at_unix": item["result"]["decision"]["evaluated_at_unix"] + 5,
        }
        for scenario_id, item in reconstructed.items()
    }
    allow_consumed = reconstructed["allow"]["state"]["consumed"]
    unhealthy_consumed = reconstructed["unhealthy"]["state"]["consumed"]
    _expect(
        allow_consumed == [expected_consumed["allow"]]
        and bool(unhealthy_consumed)
        and expected_consumed["unhealthy"] in unhealthy_consumed
        and all(item in expected_consumed.values() for item in unhealthy_consumed)
        and len(unhealthy_consumed) == len({item["request_digest"] for item in unhealthy_consumed})
        and reconstructed["allow"]["result"]["decision"]["evaluated_at_unix"]
        < reconstructed["unhealthy"]["result"]["decision"]["evaluated_at_unix"],
        "consumed request transition changed",
    )

    sensor_down = scenarios["openclaw_sensor_unavailable"]
    prior = {
        name: wrapper["digest"]
        for name, wrapper in controls_by_scenario["unhealthy"].items()
    }
    _expect(
        sensor_down["control_before"]
        == sensor_down["control_after"]
        == prior
        and results["sensor_unavailable"]
        == {
            "schema": "aragorn/runtime-action-client-error/v1",
            "authority": "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "effect_status": "NOT_SUBMITTED",
            "message": "sensor socket is unavailable: ENOENT",
        },
        "sensor-unavailable fail-closed transition changed",
    )


def _reconstruct_request(
    scenario_id: str,
    wrapper: Mapping[str, Any],
    expected_digest: str,
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    identifiers = wrapper["evidence"]["turn"]["identifiers"]
    base = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": identifiers["session_id"],
        "run_id": identifiers["run_id"],
        "tool_call_id": "sha256:"
        + hashlib.sha256(identifiers["tool_call_id"].encode()).hexdigest(),
        "active_skill_digest": _SKILL_DIGEST,
        **inputs["actions"][scenario_id],
        "policy_digest": canonical_digest(inputs["policy"]),
        "policy_version": 1,
    }
    start = int(_time(wrapper["started_at"]).timestamp()) - 1
    end = int(_time(wrapper["completed_at"]).timestamp()) + 1
    matches = []
    for issued in range(start, end + 1):
        request = {**base, "issued_at_unix": issued, "expires_at_unix": issued + 5}
        if canonical_digest(request) == expected_digest:
            matches.append(request)
    _expect(len(matches) == 1, f"{scenario_id} request was not uniquely reconstructed")
    return matches[0]


def _reconstruct_health(
    decision: Mapping[str, Any], verdict: str, sensor_digest: str
) -> dict[str, Any]:
    expected = decision["mediator_health_digest"]
    status = "healthy" if verdict == "ALLOW" else "unhealthy"
    matches = []
    now = decision["evaluated_at_unix"]
    for observed in range(now - 15, now + 1):
        health = {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": sensor_digest,
            "epoch": decision["mediator_health_epoch"],
            "status": status,
            "observed_at_unix": observed,
            "expires_at_unix": observed + 5,
        }
        if canonical_digest(health) == expected:
            matches.append(health)
    _expect(len(matches) == 1, "decision health snapshot was not uniquely reconstructed")
    return matches[0]


def _reconstruct_revocations(decision: Mapping[str, Any]) -> dict[str, Any]:
    expected = decision["revocation_snapshot_digest"]
    matches = []
    now = decision["evaluated_at_unix"]
    for observed in range(now - 15, now + 1):
        revocations = {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": decision["revocation_generation"],
            "observed_at_unix": observed,
            "expires_at_unix": observed + 15,
            "skill_digests": [],
        }
        if canonical_digest(revocations) == expected:
            matches.append(revocations)
    _expect(
        len(matches) == 1,
        "decision revocation snapshot was not uniquely reconstructed",
    )
    return matches[0]


def _verify_state(state: Mapping[str, Any]) -> None:
    consumed = state["consumed"]
    _expect(
        set(state)
        == {
            "authority",
            "consumed",
            "effect_journal",
            "minimum_mediator_health_epoch",
            "minimum_revocation_generation",
            "schema",
        }
        and state["schema"] == "aragorn/runtime-action-broker-state/v2"
        and state["authority"]
        == "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and _positive(state["minimum_mediator_health_epoch"])
        and _positive(state["minimum_revocation_generation"])
        and state["effect_journal"] is None
        and isinstance(consumed, list)
        and consumed == sorted(consumed, key=canonical_json)
        and all(
            set(item) == {"expires_at_unix", "observation_digest", "request_digest"}
            and _positive(item["expires_at_unix"])
            and _digest(item["observation_digest"])
            and _digest(item["request_digest"])
            for item in consumed
        ),
        "broker state changed",
    )


def _verify_sensor_stop(document: Mapping[str, Any]) -> None:
    deployment_units = document["deployment"]["units"]
    stopped = document["scenarios"]["openclaw_sensor_unavailable"]["units"]
    sensor = deployment_units["sensor"]
    command = " ".join(_UNITS["sensor"]["command"])
    expected_sensor = {
        **sensor,
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ExecStart": (
            "{ path=/usr/bin/python3.12 ; argv[]="
            f"{command} ; ignore_errors=no ; start_time=[n/a] ; "
            "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        ),
        "ExecStartEx": (
            "{ path=/usr/bin/python3.12 ; argv[]="
            f"{command} ; flags= ; start_time=[n/a] ; "
            "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        ),
    }
    _expect(
        set(stopped) == {"broker", "sensor"}
        and stopped["broker"] == deployment_units["broker"]
        and stopped["sensor"] == expected_sensor,
        "sensor stop boundary changed",
    )


def _verify_process_and_filesystem_separation(document: Mapping[str, Any]) -> None:
    scenarios = document["scenarios"]
    identities = [
        document["environment"]["capture_identity"],
        *document["deployment"]["processes"].values(),
        scenarios["runtime_direct_backend"]["client"]["client"],
        scenarios["wrong_backend_uid"]["client"]["client"],
        scenarios["wrong_frontend_uid"]["client"]["client"],
        scenarios["runtime_direct_write"]["process"],
    ]
    for case in (
        "openclaw_allowed_create",
        "openclaw_unhealthy_block",
        "openclaw_sensor_unavailable",
    ):
        wrapper = scenarios[case]["openclaw"]
        evidence = wrapper["evidence"]
        refreshes = [refresh["process"] for refresh in wrapper["control_refreshes"]]
        identities.extend(refreshes[:1])
        identities.extend([evidence["probe"]["process"], evidence["gateway"]["process_before"]])
        identities.extend(refreshes[1:])
    pids = [identity["pid"] for identity in identities]
    ticks = [int(identity["start_time_ticks"]) for identity in identities]
    _expect(
        len(pids) == len(set(pids))
        and ticks == sorted(ticks),
        "process role identity or chronology changed",
    )

    filesystem = []
    directories = document["deployment"]["directories"]
    sockets = document["deployment"]["sockets"]
    filesystem.extend(directories.values())
    filesystem.extend(sockets.values())
    filesystem.extend(item["installed_stat"] for item in document["artifacts"])
    filesystem.extend(item["stat"] for item in document["collector"].values())
    filesystem.append(document["environment"]["node_binary"]["stat"])
    filesystem.append(scenarios["openclaw_allowed_create"]["target"]["stat"])
    filesystem.append(
        scenarios["openclaw_sensor_unavailable"]["runtime_directory"]
    )
    for case in (
        "openclaw_allowed_create",
        "openclaw_unhealthy_block",
        "openclaw_sensor_unavailable",
    ):
        evidence = scenarios[case]["openclaw"]["evidence"]
        filesystem.extend(
            [
                evidence["input"]["stat"],
                evidence["configuration"]["stat"],
                evidence["skill"]["stat"],
                evidence["profile"]["profile_root"],
            ]
        )
    object_ids = [(item["device"], item["inode"]) for item in filesystem]
    _expect(
        all(_positive(part) for identity in object_ids for part in identity)
        and len(object_ids) == len(set(object_ids)),
        "distinct retained filesystem objects alias",
    )


def _verify_recording_time(document: Mapping[str, Any]) -> None:
    scenarios = document["scenarios"]
    wrappers = [
        scenarios[name]["openclaw"]
        for name in (
            "openclaw_allowed_create",
            "openclaw_unhealthy_block",
            "openclaw_sensor_unavailable",
        )
    ]
    _expect(
        all(
            _time(wrapper["started_at"]) <= _time(wrapper["completed_at"])
            for wrapper in wrappers
        )
        and all(
            _time(wrappers[index]["completed_at"])
            <= _time(wrappers[index + 1]["started_at"])
            for index in range(len(wrappers) - 1)
        ),
        "OpenClaw scenario chronology changed",
    )
    recorded = _time(document["recorded_at"])
    last = _time(wrappers[-1]["completed_at"])
    _expect(
        last <= recorded and (recorded - last).total_seconds() < 2,
        "recording time is inconsistent with capture events",
    )


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _expect(condition: object, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(
            f"invalid runtime OpenClaw composition evidence: {message}"
        )
