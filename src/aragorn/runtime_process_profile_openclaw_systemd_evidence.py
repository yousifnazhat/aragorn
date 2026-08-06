"""Verify the bounded P3.4b profiled OpenClaw/systemd artifact."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import evaluate_runtime_action
from .runtime_action_openclaw_evidence import (
    _expected_openclaw_configuration,
    _retained_tool_result,
    _tool_contract,
    _valid_provider_record,
    _verify_command_summary,
)
from .runtime_action_observation_publisher import RuntimeActionObservationPublisherError
from .runtime_action_systemd_evidence import _contains_float, _same_json
from .runtime_process_profile import runtime_process_profile
from .runtime_process_profile_systemd_evidence import (
    _ARTIFACTS as _P34A_ARTIFACTS,
)
from .runtime_process_profile_systemd_evidence import (
    _PROCESS_FIELDS,
    _UNIT_FIELDS,
    _digest,
    _file,
    _metadata,
    _mount_namespace,
    _positive,
    _positive_text,
    _process,
)

_SCHEMA = "aragorn/runtime-process-profile-openclaw-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_SYSTEMD_PROCESS_PROFILE_ONLY_"
    "NOT_SEMANTIC_CAUSATION_AUTHORITY"
)
_EVIDENCE_DIGEST: str | None = (
    "sha256:2cf59377917cea1461179c3a364cdfe07cdc69181eb1538abebea908954dda9c"
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
_DECISION = {
    "status": "P3_4B_OPENCLAW_PROFILE_OBSERVED",
    "profiled_openclaw_allow_created_observed": True,
    "gateway_main_pid_peer_bound": True,
    "root_owned_skill_prompt_projection_observed": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "phase3_exit_eligible": False,
    "edr_claim_eligible": False,
    "public_release_eligible": False,
}
_RUNTIME_DIGEST = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_ENTRYPOINT_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_NODE_DIGEST = (
    "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
)
_SENSOR_DIGEST = "sha256:" + "3" * 64
_REVOCATION_SOURCE = "sha256:" + "4" * 64
_SKILL = (
    "---\n"
    "name: aragorn-runtime-composition\n"
    "description: Exercise one bounded profiled OpenClaw create in the P3.4b fixture.\n"
    "---\n\n"
    "Call aragorn_runtime_create exactly once with the requested target and content.\n"
)
_SKILL_DIGEST = "sha256:" + hashlib.sha256(_SKILL.encode()).hexdigest()
_SKILL_NAME = "aragorn-runtime-composition"
_SKILL_PATH = "/opt/aragorn/runtime-profile/aragorn-runtime-composition/SKILL.md"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_NODE = "/usr/local/bin/node"
_PLUGIN = "/opt/aragorn/openclaw/aragorn-runtime-action"
_PROTECTED = "/var/lib/aragorn-runtime-action/protected"
_TARGET = "openclaw-profile-allowed.txt"
_PAYLOAD = b"Aragorn P3.4b profiled OpenClaw create\n"
_CREATE_OPERATION_DIGEST = canonical_digest(
    {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
)
_P34A_IMAGE = (
    "sha256:1b982fd3b9164ac10af300775ea0aa3fe382a134db93745f33f060d803a9aedc"
)
_P34B_IMAGE = (
    "sha256:9a3fad8e3b336799fda105d4dc598ae65445058539934a756b8d65e8f5a125ce"
)
_SYSTEMD_BASE_IMAGE = (
    "sha256:1a4fe98562882fca13e0349f84d9eb4c38b5361a1289da2a0bfa8852ccfdbc56"
)
_NODE_IMAGE = (
    "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
)
_ARTIFACTS = {
    **_P34A_ARTIFACTS,
    "/src/benchmark/runtime-process-profile-openclaw-systemd/SKILL.md": _SKILL_PATH,
    (
        "/src/benchmark/runtime-process-profile-openclaw-systemd/"
        "aragorn-openclaw-profile.service"
    ): "/usr/lib/systemd/system/aragorn-openclaw-profile.service",
    **{
        f"/src/packaging/openclaw/aragorn-runtime-action/{name}": (
            f"{_PLUGIN}/{name}"
        )
        for name in ("index.js", "openclaw.plugin.json", "package.json")
    },
}
_COLLECTORS = {
    "dockerfile": (
        "/src/benchmark/runtime-process-profile-openclaw-systemd/Dockerfile",
        "0444",
    ),
    "driver": (
        "/src/benchmark/runtime-process-profile-openclaw-systemd/"
        "openclaw-profile-driver.mjs",
        "0555",
    ),
    "openclaw_helper": ("/src/scripts/runtime_action_openclaw_systemd_probe.py", "0555"),
    "probe": (
        "/src/scripts/runtime_process_profile_openclaw_systemd_probe.py",
        "0555",
    ),
    "profile_probe": ("/src/scripts/runtime_process_profile_systemd_probe.py", "0555"),
    "recipe": (
        "/src/scripts/capture_runtime_process_profile_openclaw_systemd.sh",
        "0555",
    ),
    "systemd_probe": ("/src/scripts/runtime_action_systemd_probe.py", "0644"),
}


def verify_runtime_process_profile_openclaw_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.4b without granting semantic, RUN, EDR, or release authority."""

    try:
        pin = _EVIDENCE_DIGEST if expected_digest is None else expected_digest
        _expect(_digest(pin), "an explicit retained evidence digest is required")
        _expect(
            set(document)
            == {
                "artifacts",
                "authority",
                "collector",
                "credentials",
                "decision",
                "deployment",
                "environment",
                "harness",
                "identities",
                "inputs",
                "limitations",
                "peer_trace",
                "profile",
                "recorded_at",
                "runtime",
                "scenario",
                "schema",
                "timing",
            },
            "top-level fields changed",
        )
        _expect(canonical_digest(document) == pin, "retained evidence changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(_same_json(document["decision"], _DECISION), "claim ceiling changed")
        recorded_at = _time(document["recorded_at"])
        installed = _verify_artifacts(document)
        ids = _verify_environment_and_harness(document)
        profile = _verify_profile(document, installed)
        _verify_credentials(document, profile)
        deployment = _verify_deployment(document, ids, installed, profile)
        inputs = _verify_inputs(document, ids, profile, deployment, recorded_at)
        result = _verify_driver(document, deployment, inputs)
        _verify_receipt_and_replay(document, ids, profile, deployment, inputs, result)
        _verify_timing(document)
    except AdmissionEvidenceError:
        raise
    except (
        IndexError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RuntimeActionObservationPublisherError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime process-profile OpenClaw evidence: {exc}"
        ) from exc


def _verify_artifacts(
    document: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    artifacts = document["artifacts"]
    _expect(
        isinstance(artifacts, list) and len(artifacts) == len(_ARTIFACTS),
        "source/install closure changed",
    )
    by_source = {item["source_path"]: item for item in artifacts}
    installed = {item["installed_path"]: item for item in artifacts}
    _expect(
        set(by_source) == set(_ARTIFACTS) and len(installed) == len(_ARTIFACTS),
        "source/install paths changed or overlap",
    )
    identities = set()
    for source, installed_path in _ARTIFACTS.items():
        item = by_source[source]
        mode = item["installed_stat"]["mode"]
        expected_mode = (
            "0755"
            if installed_path.startswith("/usr/libexec/")
            else "0444"
            if installed_path.endswith("/SKILL.md")
            or installed_path.startswith(_PLUGIN)
            or installed_path.endswith("aragorn-openclaw-profile.service")
            or installed_path.endswith("aragorn-runtime-profile-client.service")
            else "0644"
        )
        _expect(
            set(item)
            == {
                "installed_bytes",
                "installed_digest",
                "installed_path",
                "installed_stat",
                "source_bytes",
                "source_digest",
                "source_path",
            }
            and item["source_path"] == source
            and item["installed_path"] == installed_path
            and _positive(item["source_bytes"])
            and item["source_bytes"] == item["installed_bytes"]
            and item["source_digest"] == item["installed_digest"]
            and _digest(item["source_digest"])
            and mode == expected_mode,
            f"source/install binding changed: {installed_path}",
        )
        _metadata(
            item["installed_stat"],
            kind="file",
            uid=0,
            gid=0,
            mode=expected_mode,
            size=item["installed_bytes"],
        )
        identity = (item["installed_stat"]["device"], item["installed_stat"]["inode"])
        _expect(identity not in identities, "installed artifacts alias")
        identities.add(identity)

    collector = document["collector"]
    _expect(set(collector) == set(_COLLECTORS), "collector closure changed")
    for name, (path, mode) in _COLLECTORS.items():
        _file(collector[name], path=path, uid=0, gid=0, mode=mode)
    return installed


def _verify_environment_and_harness(document: Mapping[str, Any]) -> dict[str, Any]:
    environment = document["environment"]
    _expect(
        set(environment)
        == {
            "architecture",
            "capture_identity",
            "kernel_release",
            "node",
            "platform",
            "python",
            "systemd_verify",
        }
        and environment["platform"] == "linux"
        and environment["architecture"] == "aarch64"
        and environment["python"] == "3.12.13"
        and re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[-+._0-9A-Za-z]*",
            environment["kernel_release"],
        )
        and environment["systemd_verify"]
        == {"exit_code": 0, "stdout": "", "stderr": ""},
        "qualification environment changed",
    )
    _file(environment["node"], path=_NODE, uid=0, gid=0, mode="0755")
    _expect(environment["node"]["digest"] == _NODE_DIGEST, "Node pin changed")
    capture = environment["capture_identity"]
    _expect(
        set(capture)
        == {
            "cgroup",
            "egid",
            "euid",
            "gid",
            "groups",
            "mount_namespace",
            "pid",
            "start_time_ticks",
            "uid",
        }
        and all(capture[field] == 0 for field in ("uid", "euid", "gid", "egid"))
        and capture["groups"] == [0]
        and _positive(capture["pid"])
        and _positive(capture["start_time_ticks"])
        and capture["cgroup"].endswith("/init.scope"),
        "capture principal changed",
    )
    _mount_namespace(capture["mount_namespace"])

    harness = document["harness"]
    _expect(
        set(harness) == {"digest", "document"}
        and harness["digest"] == canonical_digest(harness["document"]),
        "harness digest changed",
    )
    value = harness["document"]
    _expect(
        set(value)
        == {
            "container_id",
            "host_config",
            "image_id",
            "image_lineage",
            "image_reference",
            "node_image",
            "openclaw_runtime_mount",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "parent_image_id",
            "platform",
            "profile_label",
            "run_image_reference",
            "schema",
            "systemd_base_image_id",
        }
        and value["schema"]
        == "aragorn/runtime-process-profile-openclaw-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", value["container_id"])
        and value["image_id"] == value["run_image_reference"] == _P34B_IMAGE
        and value["image_reference"]
        == "aragorn-p34b-runtime-profile-openclaw-systemd"
        and value["parent_image_id"] == _P34A_IMAGE
        and value["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and value["platform"] == "linux"
        and value["profile_label"] == "p3.4b",
        "outer harness identity changed",
    )
    _expect(
        value["node_image"]
        == {
            "architecture": "arm64",
            "id": _NODE_IMAGE,
            "os": "linux",
            "reference": f"node@{_NODE_IMAGE}",
            "variant": "v8",
        }
        and value["openclaw_runtime_volume"]
        == "aragorn-openclaw-2026-7-1-runtime"
        and value["openclaw_runtime_volume_identity"]
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        }
        and value["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
        "pinned runtime mount identity changed",
    )
    _expect(
        value["host_config"]
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
        "outer host profile changed",
    )
    lineage = value["image_lineage"]
    parent = lineage["parent"]
    child = lineage["child"]
    _expect(
        set(lineage) == {"added_layers", "child", "parent"}
        and set(parent) == set(child) == {"id", "layers", "rootfs_type"}
        and parent["id"] == _P34A_IMAGE
        and child["id"] == _P34B_IMAGE
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and all(_digest(layer) for layer in parent["layers"] + child["layers"])
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and bool(lineage["added_layers"]),
        "image lineage changed",
    )
    container = value["container_id"]
    _expect(
        capture["cgroup"].startswith(f"/docker/{container}/"),
        "capture/container identity changed",
    )

    identities = document["identities"]
    _expect(set(identities) == {"broker", "runtime", "sensor"}, "identity set changed")
    result: dict[str, Any] = {}
    for name, identity in identities.items():
        _expect(
            set(identity) == {"uid", "gid"}
            and _positive(identity["uid"])
            and _positive(identity["gid"]),
            f"identity changed: {name}",
        )
        result[f"{name}_uid"] = identity["uid"]
        result[f"{name}_gid"] = identity["gid"]
    _expect(
        len({result[f"{name}_uid"] for name in identities}) == 3
        and result["broker_gid"] == result["runtime_gid"]
        and result["sensor_gid"] != result["runtime_gid"],
        "principal identities overlap",
    )
    result["container_id"] = container
    return result


def _verify_profile(
    document: Mapping[str, Any], installed: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    runtime = document["runtime"]
    _expect(
        runtime
        == {
            "entrypoint": _OPENCLAW,
            "entrypoint_digest": _ENTRYPOINT_DIGEST,
            "expected_version": "OpenClaw 2026.7.1 (2d2ddc4)",
            "root": "/runtime",
            "tree": {
                "algorithm": "aragorn/runtime-tree/v1",
                "entry_count": 45856,
                "file_count": 45837,
                "symlink_count": 19,
                "total_bytes": 369317461,
                "tree_digest": _RUNTIME_DIGEST,
            },
            "version_output": "OpenClaw 2026.7.1 (2d2ddc4)",
        },
        "pinned OpenClaw runtime changed",
    )
    profile = document["profile"]
    _expect(
        set(profile) == {"digest", "document", "executable", "skill"},
        "profile fields changed",
    )
    parsed = runtime_process_profile(profile["document"])
    _expect(
        profile["digest"] == parsed.digest
        and parsed.runtime_digest == _RUNTIME_DIGEST
        and parsed.executable_digest == _NODE_DIGEST
        and str(parsed.skill_path) == _SKILL_PATH,
        "runtime profile changed",
    )
    _file(profile["skill"], path=_SKILL_PATH, uid=0, gid=0, mode="0444")
    _file(profile["executable"], path=_NODE, uid=0, gid=0, mode="0755")
    retained_skill = installed[_SKILL_PATH]
    _expect(
        profile["skill"]
        == {
            "bytes": len(_SKILL.encode()),
            "digest": _SKILL_DIGEST,
            "path": _SKILL_PATH,
            "stat": retained_skill["installed_stat"],
        }
        and retained_skill["installed_bytes"] == len(_SKILL.encode())
        and retained_skill["installed_digest"] == _SKILL_DIGEST
        and profile["executable"] == document["environment"]["node"],
        "profile files are not bound to retained bytes",
    )
    return {
        "digest": parsed.digest,
        "document": profile["document"],
        "runtime_digest": parsed.runtime_digest,
        "executable_digest": parsed.executable_digest,
        "skill_digest": _SKILL_DIGEST,
        "skill_path": _SKILL_PATH,
        "cgroup": parsed.cgroup,
    }


def _verify_credentials(document: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    credentials = document["credentials"]
    _expect(set(credentials) == {"broker", "sensor"}, "credential set changed")
    for value in credentials.values():
        _expect(
            set(value) == {"digest", "document"}
            and value["digest"] == canonical_digest(value["document"]),
            "credential digest changed",
        )
    _expect(
        credentials["broker"]["document"]
        == {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": _RUNTIME_DIGEST,
            "runtime_profile_digest": profile["digest"],
        }
        and credentials["sensor"]["document"]
        == {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": _SENSOR_DIGEST,
            "runtime_profile": profile["document"],
        },
        "credential/profile binding changed",
    )


def _verify_deployment(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    installed: Mapping[str, Mapping[str, Any]],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    deployment = document["deployment"]
    _expect(
        set(deployment)
        == {
            "directories",
            "gateway_cgroup_processes",
            "processes",
            "security",
            "sockets",
            "units",
        },
        "deployment fields changed",
    )
    directories = deployment["directories"]
    _expect(
        set(directories) == {"control", "protected", "root", "runtime", "staging"},
        "directory set changed",
    )
    contracts = {
        "root": (0, 0, "0755", 1),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710", 1),
        "protected": (ids["broker_uid"], ids["runtime_gid"], "0710", 1),
        "staging": (ids["broker_uid"], ids["broker_uid"], "0700", 1),
        "runtime": (ids["sensor_uid"], ids["runtime_gid"], "0750", 2),
    }
    for name, (uid, gid, mode, nlink) in contracts.items():
        _metadata(
            directories[name],
            kind="directory",
            uid=uid,
            gid=gid,
            mode=mode,
            size=None,
            nlink=nlink,
        )
    _expect(
        len({(value["device"], value["inode"]) for value in directories.values()})
        == len(directories)
        and len(
            {
                directories[name]["device"]
                for name in ("root", "control", "protected", "staging")
            }
        )
        == 1
        and directories["runtime"]["device"] != directories["root"]["device"],
        "directory identities changed or overlap",
    )
    sockets = deployment["sockets"]
    _expect(set(sockets) == {"backend", "frontend"}, "socket set changed")
    _metadata(
        sockets["backend"],
        kind="socket",
        uid=ids["broker_uid"],
        gid=ids["sensor_gid"],
        mode="0660",
        size=0,
    )
    _metadata(
        sockets["frontend"],
        kind="socket",
        uid=ids["sensor_uid"],
        gid=ids["runtime_gid"],
        mode="0660",
        size=0,
    )
    _expect(
        sockets["backend"]["device"] == directories["control"]["device"]
        and sockets["frontend"]["device"] == directories["runtime"]["device"],
        "socket parent identity changed",
    )

    broker_command = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v2.py",
        "/run/credentials/aragorn-runtime-profile-action-broker.service/runtime-binding",
    ]
    sensor_command = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v2.py",
        (
            "/run/credentials/aragorn-runtime-profile-observation-publisher.service/"
            "observation-binding"
        ),
    ]
    gateway_command = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "run",
        "--allow-unconfigured",
        "--auth",
        "token",
        "--bind",
        "loopback",
        "--port",
        "18789",
        "--tailscale",
        "off",
        "--ws-log",
        "full",
    ]
    units = deployment["units"]
    _expect(set(units) == {"broker", "gateway", "sensor"}, "unit set changed")
    unit_contracts = {
        "broker": (
            "aragorn-runtime-profile-action-broker.service",
            "aragorn-broker",
            "aragorn-runtime",
            "aragorn-sensor",
            "",
            broker_command,
        ),
        "sensor": (
            "aragorn-runtime-profile-observation-publisher.service",
            "aragorn-sensor",
            "aragorn-sensor",
            "aragorn-runtime",
            "cap_setgid cap_setuid cap_setpcap",
            sensor_command,
        ),
        "gateway": (
            "aragorn-openclaw-profile.service",
            "aragorn-runtime",
            "aragorn-runtime",
            "",
            "",
            gateway_command,
        ),
    }
    for name, (service, user, group, supplementary, capabilities, command) in (
        unit_contracts.items()
    ):
        unit = units[name]
        path = f"/usr/lib/systemd/system/{service}"
        _expect(
            set(unit) == _UNIT_FIELDS
            and unit["FragmentPath"] == f"/lib/systemd/system/{service}"
            and unit["FragmentResolvedPath"] == path
            and unit["FragmentDigest"] == installed[path]["installed_digest"]
            and unit["DropInPaths"] == ""
            and unit["User"] == user
            and unit["Group"] == group
            and unit["SupplementaryGroups"] == supplementary
            and unit["AmbientCapabilities"] == capabilities
            and unit["CapabilityBoundingSet"] == capabilities
            and unit["NoNewPrivileges"] == "yes"
            and unit["ActiveState"] == "active"
            and unit["SubState"] == "running"
            and unit["Result"] == "success"
            and unit["ExecMainStatus"] == "0"
            and _loaded_command(unit["ExecStart"], command, unit["MainPID"]),
            f"loaded unit contract changed: {name}",
        )
    _expect(
        units["gateway"]["ControlGroup"] == profile["cgroup"]
        and all(
            unit["ControlGroup"].startswith(f"/docker/{ids['container_id']}/")
            for unit in units.values()
        ),
        "unit cgroup identity changed",
    )

    processes = deployment["processes"]
    _expect(
        set(processes) == {"broker", "gateway_after", "gateway_before", "sensor"},
        "process set changed",
    )
    _process(
        processes["broker"],
        unit=units["broker"],
        command=broker_command,
        uids=[ids["broker_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _process(
        processes["sensor"],
        unit=units["sensor"],
        command=sensor_command,
        uids=[ids["sensor_uid"], ids["sensor_uid"], ids["sensor_uid"], ids["runtime_uid"]],
        gids=[ids["sensor_gid"], ids["sensor_gid"], ids["sensor_gid"], ids["runtime_gid"]],
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    for name, command in (
        ("gateway_before", ["openclaw"]),
        ("gateway_after", ["openclaw-gateway"]),
    ):
        _process(
            processes[name],
            unit=units["gateway"],
            command=command,
            uids=[ids["runtime_uid"]] * 4,
            gids=[ids["runtime_gid"]] * 4,
            groups=[ids["runtime_gid"]],
        )
    before = processes["gateway_before"]
    after = processes["gateway_after"]
    _expect(
        all(
            before[field] == after[field]
            for field in _PROCESS_FIELDS - {"cmdline"}
        )
        and deployment["gateway_cgroup_processes"] == [before["pid"]]
        and before["pid"] == int(units["gateway"]["MainPID"]),
        "gateway MainPID was not stable and singleton",
    )
    _expect(
        len(
            {
                processes[name][namespace]
                for name in ("broker", "gateway_before", "sensor")
                for namespace in ("mount_namespace", "network_namespace")
            }
        )
        == 6,
        "service namespaces overlap",
    )
    security = deployment["security"]
    _expect(set(security) == {"broker", "gateway", "sensor"}, "security set changed")
    for name, value in security.items():
        capabilities = value["capabilities"]
        _expect(
            set(value) == {"capabilities", "no_new_privileges"}
            and value["no_new_privileges"] == 1
            and set(capabilities) == {"CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"}
            and all(
                item == {"hex": "0000000000000000", "value": 0}
                for item in capabilities.values()
            ),
            f"live capability state changed: {name}",
        )
    return {
        "broker_pid": processes["broker"]["pid"],
        "gateway": before,
        "gateway_pid": before["pid"],
        "sensor_pid": processes["sensor"]["pid"],
        "protected": directories["protected"],
    }


def _verify_inputs(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    deployment: Mapping[str, Any],
    recorded_at: Any,
) -> dict[str, Any]:
    inputs = document["inputs"]
    _expect(
        set(inputs)
        == {
            "action",
            "driver",
            "gateway_config",
            "gateway_config_digest",
            "initial_controls",
            "policy",
        },
        "input fields changed",
    )
    action = inputs["action"]
    expected_action = {
        "operation_digest": _CREATE_OPERATION_DIGEST,
        "path_digest": canonical_digest(
            {
                "schema": "aragorn/runtime-protected-path/v1",
                "root_device": deployment["protected"]["device"],
                "root_inode": deployment["protected"]["inode"],
                "target_name": _TARGET,
            }
        ),
        "payload_digest": "sha256:" + hashlib.sha256(_PAYLOAD).hexdigest(),
    }
    _expect(action == expected_action, "derived create action changed")
    policy = inputs["policy"]
    expected_rule = {
        "runtime_digest": _RUNTIME_DIGEST,
        "active_skill_digest": _SKILL_DIGEST,
        **expected_action,
    }
    _expect(
        policy
        == {
            "schema": "aragorn/runtime-action-policy/v1",
            "id": "p3-4b-pinned-openclaw-process-profile",
            "version": 1,
            "default": "BLOCK",
            "sensor_digest": _SENSOR_DIGEST,
            "revocation_source_digest": _REVOCATION_SOURCE,
            "allow": [expected_rule],
        },
        "runtime policy changed",
    )
    plugin_config = {
        "activeSkillDigest": _SKILL_DIGEST,
        "expectedBrokerUid": ids["broker_uid"],
        "expectedRuntimeGid": ids["runtime_gid"],
        "expectedRuntimeUid": ids["runtime_uid"],
        "expectedSensorUid": ids["sensor_uid"],
        "policyDigest": canonical_digest(policy),
        "policyVersion": 1,
        "protectedRoot": _PROTECTED,
        "runtimeDigest": _RUNTIME_DIGEST,
        "sensorSocketPath": "/run/aragorn-runtime-observation/sensor.sock",
    }
    expected_config = _expected_openclaw_configuration(
        {"plugin": {"config": plugin_config}},
        {"workspace": "/var/lib/aragorn-openclaw-profile/workspace"},
    )
    expected_config["skills"]["load"]["extraDirs"] = [
        "/opt/aragorn/runtime-profile/aragorn-runtime-composition"
    ]
    config = inputs["gateway_config"]
    _expect(
        _same_json(config, expected_config)
        and inputs["gateway_config_digest"] == canonical_digest(config),
        "OpenClaw gateway configuration changed",
    )
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
    _expect(inputs["driver"] == driver_input, "driver input changed")

    controls = inputs["initial_controls"]
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"}
        and controls["policy"] == policy,
        "initial control set changed",
    )
    now = controls["health"]["observed_at_unix"]
    active = {
        "schema": "aragorn/runtime-active-context/v1",
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "seed-p3-4b",
        "run_id": "seed-p3-4b",
        "tool_call_id": "seed-p3-4b",
        "active_skill_digest": _SKILL_DIGEST,
    }
    _expect(
        isinstance(now, int)
        and not isinstance(now, bool)
        and now > 0
        and now <= recorded_at.timestamp()
        and controls["revocations"]
        == {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 1,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        }
        and controls["health"]
        == {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        }
        and controls["observation"]
        == {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": _SENSOR_DIGEST,
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": active,
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **{key: value for key, value in active.items() if key != "schema"},
                **expected_action,
            },
        }
        and controls["state"]
        == {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
        },
        "initial control semantics changed",
    )
    return {
        "action": expected_action,
        "config": config,
        "controls": controls,
        "driver": driver_input,
        "policy": policy,
        "profile": profile,
    }


def _provider_responses(tool_call_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    common = {"created": 0, "model": "fixture-model", "object": "chat.completion.chunk"}
    arguments = canonical_json(
        {"content": _PAYLOAD.decode(), "target_name": _TARGET}
    ).decode("ascii")
    tool = [
        {
            **common,
            "choices": [
                {
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "arguments": arguments,
                                    "name": "aragorn_runtime_create",
                                },
                                "id": tool_call_id,
                                "index": 0,
                                "type": "function",
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                    "index": 0,
                }
            ],
            "id": "chatcmpl-allow-tool",
        }
    ]
    final = [
        {
            **common,
            "choices": [
                {
                    "delta": {
                        "content": "ARAGORN_RUNTIME_ACTION_ALLOW_CREATED",
                        "role": "assistant",
                    },
                    "finish_reason": None,
                    "index": 0,
                }
            ],
            "id": "chatcmpl-allow-final",
        },
        {
            **common,
            "choices": [{"delta": {}, "finish_reason": "stop", "index": 0}],
            "id": "chatcmpl-allow-final",
            "usage": {"completion_tokens": 1, "prompt_tokens": 1, "total_tokens": 2},
        },
    ]
    return tool, final


def _verify_driver(
    document: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> Mapping[str, Any]:
    outer = document["scenario"]
    _expect(
        set(outer)
        == {
            "control_after",
            "driver",
            "driver_exit_code",
            "driver_stderr",
            "driver_stdout",
            "profile_pending_exists",
            "protected_entries",
            "provider_system_prompt",
            "receipt",
            "receipt_file",
            "staging_entries",
            "state",
            "status",
            "target",
        }
        and outer["status"] == "PASS"
        and outer["driver_exit_code"] == 0
        and outer["driver_stdout"] == outer["driver_stderr"] == ""
        and outer["profile_pending_exists"] is False
        and outer["protected_entries"] == [_TARGET]
        and outer["staging_entries"] == [],
        "outer scenario changed",
    )
    driver = outer["driver"]
    _expect(
        set(driver) == {"gateway", "provider", "scenario", "schema", "timing", "turn"}
        and driver["schema"] == "aragorn/openclaw-profile-driver-output/v1",
        "driver output changed",
    )
    gateway = driver["gateway"]
    _expect(set(gateway) == {"system_info"}, "driver gateway fields changed")
    system_info = gateway["system_info"]
    _expect(
        set(system_info) == {"command", "response"}
        and system_info["response"] == {"pid": deployment["gateway_pid"]},
        "driver gateway PID changed",
    )
    _verify_command_summary(
        system_info["command"],
        [_NODE, _OPENCLAW, "gateway", "call", "system.info", "--json", "--timeout", "5000"],
    )

    identifiers = driver["turn"]["identifiers"]
    run_id = "aragorn-p34b-allow"
    session_key = f"agent:main:{run_id}"
    tool_call_id = "call_aragorn_p34b_allow_1"
    user_text = "Invoke aragorn_runtime_create exactly once for bounded scenario allow."
    _expect(
        set(identifiers) == {"run_id", "session_id", "session_key", "tool_call_id"}
        and identifiers["run_id"] == run_id
        and identifiers["session_key"] == session_key
        and identifiers["tool_call_id"] == tool_call_id
        and isinstance(identifiers["session_id"], str)
        and bool(identifiers["session_id"]),
        "driver turn identifiers changed",
    )
    provider = driver["provider"]
    records = provider["records"]
    expected_tool, expected_final = _provider_responses(tool_call_id)
    authorization = "sha256:" + hashlib.sha256(
        b"Bearer aragorn-runtime-action-mock-local"
    ).hexdigest()
    _expect(
        set(provider) == {"errors", "records", "request_count"}
        and provider["errors"] == []
        and provider["request_count"] == len(records) == 2
        and all(_valid_provider_record(record) for record in records)
        and [record["sequence"] for record in records] == [1, 2]
        and all(record["authorization_digest"] == authorization for record in records)
        and records[0]["response"] == expected_tool
        and records[1]["response"] == expected_final
        and _time(records[0]["received_at"]) <= _time(records[1]["received_at"]),
        "deterministic provider boundary changed",
    )
    first_body = records[0]["body"]
    second_body = records[1]["body"]
    body_fields = {"max_tokens", "messages", "model", "stream", "tool_choice", "tools"}
    _expect(
        set(first_body) == set(second_body) == body_fields
        and all(body["model"] == "fixture-model" for body in (first_body, second_body))
        and all(body["max_tokens"] == 256 for body in (first_body, second_body))
        and all(body["stream"] is True for body in (first_body, second_body))
        and all(body["tool_choice"] == "auto" for body in (first_body, second_body))
        and second_body["tools"] == first_body["tools"],
        "provider request contract changed",
    )
    tools = [
        tool
        for tool in first_body.get("tools", [])
        if isinstance(tool, Mapping)
        and tool.get("function", {}).get("name") == "aragorn_runtime_create"
    ]
    _expect(tools == [_tool_contract()], "exposed Aragorn tool contract changed")
    prompt = "\n".join(
        message["content"]
        for message in first_body.get("messages", [])
        if isinstance(message, Mapping)
        and message.get("role") == "system"
        and isinstance(message.get("content"), str)
    )
    description = "Exercise one bounded profiled OpenClaw create in the P3.4b fixture."
    _expect(
        outer["provider_system_prompt"] == prompt
        and prompt.count(f"<name>{_SKILL_NAME}</name>") == 1
        and prompt.count(f"<description>{description}</description>") == 1
        and prompt.count(f"<location>{_SKILL_PATH}</location>") == 1
        and prompt.count(f"<version>{_SKILL_DIGEST[:23]}</version>") == 1,
        "root-owned skill prompt projection changed",
    )

    turn = driver["turn"]
    _expect(set(turn) == {"history", "identifiers", "send", "wait"}, "turn fields changed")
    send_params = canonical_json(
        {
            "deliver": False,
            "idempotencyKey": run_id,
            "message": user_text,
            "sessionKey": session_key,
            "timeoutMs": 10000,
        }
    ).decode("ascii")
    wait_params = canonical_json({"runId": run_id, "timeoutMs": 15000}).decode("ascii")
    history_params = canonical_json({"limit": 20, "sessionKey": session_key}).decode("ascii")
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
                _NODE,
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
    _expect(
        turn["send"]["response"] == {"runId": run_id, "status": "started"}
        and set(turn["wait"]["response"]) == {"endedAt", "runId", "status"}
        and turn["wait"]["response"]["runId"] == run_id
        and turn["wait"]["response"]["status"] == "ok"
        and _positive(turn["wait"]["response"]["endedAt"]),
        "turn lifecycle changed",
    )
    history = turn["history"]["response"]
    messages = history["messages"]
    _expect(
        set(history)
        == {"defaults", "messages", "sessionId", "sessionInfo", "sessionKey", "thinkingLevel"}
        and history["sessionId"] == identifiers["session_id"]
        and history["sessionKey"] == session_key
        and history["thinkingLevel"] == "off"
        and len(messages) == 4
        and [message["__openclaw"]["seq"] for message in messages] == [1, 2, 3, 4]
        and [message["timestamp"] for message in messages]
        == sorted(message["timestamp"] for message in messages)
        and history["sessionInfo"]["key"] == session_key
        and history["sessionInfo"]["sessionId"] == identifiers["session_id"]
        and history["sessionInfo"]["status"] == "done"
        and history["sessionInfo"]["activeRunIds"] == [],
        "retained turn lineage changed",
    )
    tool_messages = [
        message
        for message in messages
        if message.get("role") == "toolResult"
        and message.get("toolName") == "aragorn_runtime_create"
    ]
    _expect(
        len(tool_messages) == 1
        and tool_messages[0]["toolCallId"] == tool_call_id
        and tool_messages[0]["isError"] is False,
        "retained tool result lineage changed",
    )
    retained_tool = _retained_tool_result(tool_messages[0])
    retained = retained_tool["document"]
    result = retained["result"]
    provider_call = expected_tool[0]["choices"][0]["delta"]["tool_calls"][0]
    expected_arguments = canonical_json(
        {"content": _PAYLOAD.decode(), "target_name": _TARGET}
    ).decode("ascii")
    user, assistant, tool_result, final = messages
    _expect(
        [message.get("role") for message in messages]
        == ["user", "assistant", "toolResult", "assistant"]
        and user["content"] == user_text
        and user["idempotencyKey"] == f"{run_id}:user"
        and len(assistant["content"]) == 1
        and assistant["content"][0]
        == {
            "arguments": {"content": _PAYLOAD.decode(), "target_name": _TARGET},
            "id": tool_call_id,
            "name": "aragorn_runtime_create",
            "partialArgs": expected_arguments,
            "type": "toolCall",
        }
        and assistant["api"] == "openai-completions"
        and assistant["provider"] == "aragorn-runtime-action-mock"
        and assistant["model"] == "fixture-model"
        and assistant["responseId"] == "chatcmpl-allow-tool"
        and assistant["stopReason"] == "toolUse"
        and tool_result["toolCallId"] == tool_call_id
        and tool_result["toolName"] == "aragorn_runtime_create"
        and tool_result["isError"] is False
        and tool_result["content"] == [{"text": retained_tool["raw"], "type": "text"}]
        and "details" not in tool_result
        and final["api"] == "openai-completions"
        and final["provider"] == "aragorn-runtime-action-mock"
        and final["model"] == "fixture-model"
        and final["responseId"] == "chatcmpl-allow-final"
        and final["stopReason"] == "stop"
        and final["content"]
        == [{"text": "ARAGORN_RUNTIME_ACTION_ALLOW_CREATED", "type": "text"}],
        "retained history lineage changed",
    )
    first_messages = first_body["messages"]
    second_messages = second_body["messages"]
    transport_id = tool_call_id.replace("_", "")
    _expect(
        [message.get("role") for message in first_messages] == ["system", "user"]
        and set(first_messages[1]) == {"content", "role"}
        and re.fullmatch(
            r"\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
            r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC\] "
            + re.escape(user_text),
            first_messages[1]["content"],
        )
        is not None
        and len(second_messages) == len(first_messages) + 2
        and _same_json(second_messages[: len(first_messages)], first_messages)
        and second_messages[-2]
        == {
            "content": None,
            "role": "assistant",
            "tool_calls": [
                {
                    "function": {
                        "arguments": expected_arguments,
                        "name": "aragorn_runtime_create",
                    },
                    "id": transport_id,
                    "type": "function",
                }
            ],
        }
        and second_messages[-1]
        == {
            "content": retained_tool["raw"],
            "role": "tool",
            "tool_call_id": transport_id,
        },
        "provider message transport lineage changed",
    )
    checks = {
        "action_result_bound": result.get("verdict") == "ALLOW"
        and result.get("effect_status") == "CREATED"
        and result.get("target_name") == _TARGET,
        "gateway_pid_present": _positive(system_info["response"]["pid"]),
        "history_lineage": tool_messages[0]["toolCallId"] == tool_call_id
        and history["sessionKey"] == session_key
        and turn["wait"]["response"]["runId"] == turn["send"]["response"]["runId"],
        "one_provider_driven_tool_call": len(records) == 2
        and provider_call["id"] == tool_call_id
        and provider_call["function"]["name"] == "aragorn_runtime_create"
        and provider_call["function"]["arguments"] == expected_arguments,
        "provider_completed_without_error": provider["errors"] == [],
    }
    proof = driver["scenario"]["proof"]
    _expect(
        driver["scenario"]["status"] == "PASS"
        and set(proof) == {"checks", "passed", "retained_tool_result"}
        and proof["checks"] == checks
        and all(checks.values())
        and proof["passed"] is True
        and _same_json(proof["retained_tool_result"], retained),
        "driver proof was not independently reproduced",
    )
    timing = driver["timing"]
    started = _time(timing["started_at"])
    completed = _time(timing["completed_at"])
    _expect(
        set(timing) == {"completed_at", "elapsed_ms", "started_at"}
        and _positive(timing["elapsed_ms"])
        and int((completed - started).total_seconds() * 1000) == timing["elapsed_ms"],
        "driver timing changed",
    )
    return result


def _verify_receipt_and_replay(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
    retained_result: Mapping[str, Any],
) -> None:
    scenario = document["scenario"]
    receipt = scenario["receipt"]
    receipt_document = receipt["document"]
    result = receipt_document["broker_result"]
    decision = result["decision"]
    now = decision["evaluated_at_unix"]
    identifiers = scenario["driver"]["turn"]["identifiers"]
    hashed_tool_call = "sha256:" + hashlib.sha256(
        identifiers["tool_call_id"].encode()
    ).hexdigest()

    request_base = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": identifiers["session_id"],
        "run_id": identifiers["run_id"],
        "tool_call_id": hashed_tool_call,
        "active_skill_digest": _SKILL_DIGEST,
        **inputs["action"],
        "policy_digest": canonical_digest(inputs["policy"]),
        "policy_version": 1,
    }
    requests = [
        {
            **request_base,
            "issued_at_unix": issued,
            "expires_at_unix": issued + 5,
        }
        for issued in range(now - 5, now + 1)
    ]
    requests = [
        request
        for request in requests
        if canonical_digest(request) == result["request_digest"]
    ]
    _expect(len(requests) == 1, "signed request could not be independently derived")
    request = requests[0]
    envelope = {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": request,
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": _TARGET,
            "payload_base64": base64.b64encode(_PAYLOAD).decode("ascii"),
        },
    }
    active = {
        "schema": "aragorn/runtime-active-context/v1",
        **{
            key: request[key]
            for key in (
                "runtime_digest",
                "session_id",
                "run_id",
                "tool_call_id",
                "active_skill_digest",
            )
        },
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{key: value for key, value in active.items() if key != "schema"},
        **inputs["action"],
    }
    health = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": _RUNTIME_DIGEST,
        "sensor_digest": _SENSOR_DIGEST,
        "epoch": 2,
        "status": "healthy",
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
    }
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": 2,
        "sensor_digest": _SENSOR_DIGEST,
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
        "active": active,
        "measured_action": measured,
    }
    state = {
        "schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 1,
        "minimum_mediator_health_epoch": 2,
        "consumed": [
            {
                "request_digest": canonical_digest(request),
                "observation_digest": canonical_digest(observation),
                "expires_at_unix": now + 5,
            }
        ],
        "effect_journal": None,
    }
    replay = evaluate_runtime_action(
        request,
        inputs["policy"],
        now_unix=now,
        active=active,
        measured_action=measured,
        revocations=inputs["controls"]["revocations"],
        minimum_revocation_generation=1,
        mediator_health=health,
        minimum_mediator_health_epoch=2,
    )
    controls = {
        "health.json": canonical_digest(health),
        "observation.json": canonical_digest(observation),
        "policy.json": canonical_digest(inputs["policy"]),
        "revocations.json": canonical_digest(inputs["controls"]["revocations"]),
        "state.json": canonical_digest(state),
    }
    _expect(
        set(result)
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
        and result["schema"] == "aragorn/runtime-action-broker-result/v1"
        and result["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and result["verdict"] == "ALLOW"
        and result["reason_codes"] == []
        and result["effect_status"] == "CREATED"
        and result["target_name"] == _TARGET
        and result["request_digest"] == canonical_digest(request)
        and result["observation_digest"] == canonical_digest(observation)
        and decision == replay
        and _same_json(result, retained_result)
        and request["issued_at_unix"] <= now < request["expires_at_unix"],
        "request, decision, or result replay changed",
    )
    initial = inputs["controls"]
    _expect(
        initial["health"]["observed_at_unix"] <= now
        < initial["health"]["expires_at_unix"]
        and initial["revocations"]["observed_at_unix"] <= now
        < initial["revocations"]["expires_at_unix"],
        "initial health or revocation snapshot was stale",
    )

    gateway = deployment["gateway"]
    namespace = re.fullmatch(r"mnt:\[([1-9][0-9]*)\]", gateway["mount_namespace"])
    _expect(namespace is not None, "gateway mount namespace changed")
    attribution = receipt_document["runtime_attribution"]
    expected_attribution = {
        "schema": "aragorn/runtime-process-profile-attribution/v1",
        "authority": "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "profile_digest": profile["digest"],
        "runtime_digest": _RUNTIME_DIGEST,
        "executable_digest": profile["executable_digest"],
        "active_skill_digest": _SKILL_DIGEST,
        "skill_path": _SKILL_PATH,
        "cgroup": profile["cgroup"],
        "pid": deployment["gateway_pid"],
        "uid": ids["runtime_uid"],
        "gid": ids["runtime_gid"],
        "start_time_ticks": int(gateway["start_time_ticks"]),
        "mount_namespace": {
            "device": document["environment"]["capture_identity"]["mount_namespace"][
                "device"
            ],
            "inode": int(namespace.group(1)),
        },
    }
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": _SENSOR_DIGEST,
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {
            "pid": deployment["gateway_pid"],
            "uid": ids["runtime_uid"],
            "gid": ids["runtime_gid"],
        },
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": attribution,
    }
    _expect(
        set(receipt) == {"digest", "document"}
        and receipt["digest"] == canonical_digest(receipt_document)
        and set(receipt_document)
        == {
            "authority",
            "broker_result",
            "broker_result_digest",
            "runtime_attribution",
            "runtime_attribution_digest",
            "schema",
            "submission_digest",
        }
        and receipt_document["schema"]
        == "aragorn/runtime-process-profile-receipt/v1"
        and receipt_document["authority"]
        == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and receipt_document["broker_result_digest"] == canonical_digest(result)
        and receipt_document["runtime_attribution_digest"]
        == canonical_digest(attribution)
        and attribution == expected_attribution
        and receipt_document["submission_digest"] == canonical_digest(submission),
        "profile receipt or submission binding changed",
    )
    controls["profile-receipt.json"] = receipt["digest"]
    _expect(
        scenario["state"] == {"digest": canonical_digest(state), "document": state}
        and scenario["control_after"] == controls,
        "durable control state changed",
    )
    target = scenario["target"]
    receipt_file = scenario["receipt_file"]
    _file(
        target,
        path=f"{_PROTECTED}/{_TARGET}",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _file(
        receipt_file,
        path="/var/lib/aragorn-runtime-action/control/profile-receipt.json",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _expect(
        target["digest"] == inputs["action"]["payload_digest"]
        and target["bytes"] == len(_PAYLOAD)
        and target["stat"]["device"] == deployment["protected"]["device"]
        and receipt_file["digest"] == receipt["digest"]
        and receipt_file["bytes"] == len(canonical_json(receipt_document))
        and receipt_file["stat"]["device"]
        == document["deployment"]["directories"]["control"]["device"],
        "created target or durable receipt file changed",
    )
    _verify_peer_trace(document, ids, deployment)
    recorded_at = _time(document["recorded_at"]).timestamp()
    _expect(0 <= recorded_at - now < 10, "recording time changed")


def _verify_peer_trace(
    document: Mapping[str, Any], ids: Mapping[str, Any], deployment: Mapping[str, Any]
) -> None:
    traces = document["peer_trace"]
    _expect(set(traces) == {"broker", "sensor"}, "peer trace set changed")
    expected = {
        "broker": [
            {
                "pid": deployment["sensor_pid"],
                "uid": ids["sensor_uid"],
                "gid": ids["sensor_gid"],
            }
        ],
        "sensor": [
            {
                "pid": deployment["gateway_pid"],
                "uid": ids["runtime_uid"],
                "gid": ids["runtime_gid"],
            },
            {
                "pid": deployment["broker_pid"],
                "uid": ids["broker_uid"],
                "gid": ids["runtime_gid"],
            },
        ],
    }
    peer_pattern = re.compile(
        r"(?P<service>\d+)\s+getsockopt\((?P<fd>\d+), SOL_SOCKET, "
        r"SO_PEERCRED, \{pid=(?P<pid>\d+), uid=(?P<uid>\d+), "
        r"gid=(?P<gid>\d+)\}, \[12\]\) = 0"
    )
    accept_pattern = re.compile(
        r"(?P<service>\d+)\s+accept4\(\d+, \{sa_family=AF_UNIX\}, "
        r"\[\d+ => \d+\], SOCK_CLOEXEC\) = (?P<fd>\d+)"
    )
    connect_pattern = re.compile(
        r'(?P<service>\d+)\s+connect\((?P<fd>\d+), '
        r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
    )
    detached_pattern = re.compile(
        r"(?P<service>\d+)\s+accept4\(\d+,\s+<detached \.\.\.>"
    )
    for name, service_pid, kinds in (
        ("broker", deployment["broker_pid"], ["accept"]),
        ("sensor", deployment["sensor_pid"], ["accept", "connect"]),
    ):
        trace = traces[name]
        raw = trace["raw"]
        lines = raw.splitlines()
        peers: list[dict[str, int]] = []
        actual_kinds: list[str] = []
        completed_channels = sum(
            accept_pattern.fullmatch(line) is not None
            or connect_pattern.fullmatch(line) is not None
            for line in lines
        )
        for index, line in enumerate(lines):
            match = peer_pattern.fullmatch(line)
            if match is None:
                continue
            precursor = lines[index - 1] if index else ""
            accept = accept_pattern.fullmatch(precursor)
            connect = connect_pattern.fullmatch(precursor)
            channel = accept or connect
            _expect(
                channel is not None
                and int(match["service"]) == int(channel["service"]) == service_pid
                and match["fd"] == channel["fd"]
                and (
                    connect is None
                    or connect["path"]
                    == "/var/lib/aragorn-runtime-action/control/broker.sock"
                ),
                "SO_PEERCRED was not paired with its channel syscall",
            )
            peers.append({key: int(match[key]) for key in ("pid", "uid", "gid")})
            actual_kinds.append("accept" if accept is not None else "connect")
        detached = detached_pattern.fullmatch(lines[-1]) if lines else None
        _expect(
            set(trace) == {"peer_credentials", "raw", "raw_digest"}
            and trace["raw_digest"]
            == "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
            and all(line.startswith(f"{service_pid} ") for line in lines)
            and raw.count("SO_PEERCRED") == len(peers)
            and completed_channels == len(peers)
            and actual_kinds == kinds
            and peers == trace["peer_credentials"] == expected[name]
            and detached is not None
            and int(detached["service"]) == service_pid,
            f"{name} kernel peer chain changed",
        )


def _verify_timing(document: Mapping[str, Any]) -> None:
    timing = document["timing"]
    driver_elapsed = document["scenario"]["driver"]["timing"]["elapsed_ms"]
    _expect(
        set(timing)
        == {
            "client_deadline_ms",
            "deadline_outcome",
            "driver_elapsed_ms",
            "driver_elapsed_ns",
            "note",
            "sensor_deadline_ms",
        }
        and timing["client_deadline_ms"] == 750
        and timing["sensor_deadline_ms"] == 500
        and _positive(timing["driver_elapsed_ns"])
        and timing["driver_elapsed_ms"] == timing["driver_elapsed_ns"] // 1_000_000
        and driver_elapsed <= timing["driver_elapsed_ms"]
        and timing["deadline_outcome"]
        == "COMPLETED_WITHIN_ENFORCED_NESTED_DEADLINES"
        and timing["note"] == "driver elapsed includes provider and gateway RPC overhead",
        "bounded timing record changed",
    )


def _loaded_command(raw: object, command: tuple[str, ...], pid: object) -> bool:
    if (
        not isinstance(raw, str)
        or not isinstance(pid, str)
        or not pid.isascii()
        or not pid.isdigit()
        or int(pid) <= 0
        or "\n" in raw
    ):
        return False
    prefix = f"{{ path={command[0]} ; argv[]={' '.join(command)} ; ignore_errors=no ; start_time=["
    suffix = f"] ; stop_time=[n/a] ; pid={pid} ; code=(null) ; status=0/0 }}"
    return (
        raw.startswith(prefix)
        and raw.endswith(suffix)
        and re.fullmatch(
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
            r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC",
            raw[len(prefix) : -len(suffix)],
        )
        is not None
    )


def _expect(condition: object, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
