"""Verify one bounded systemd sensor-process-loss fail-stop observation."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest

_SCHEMA = "aragorn/runtime-action-worker-sensor-loss-systemd-observation/v1"
_QUALIFICATION_SCHEMA = (
    "aragorn/runtime-action-worker-sensor-loss-systemd-qualification/v1"
)
_AUTHORITY = (
    "BOUNDED_LOCAL_SYSTEMD_SENSOR_PROCESS_LOSS_OBSERVATION_ONLY_"
    "NOT_RUN_02_PHASE3_EDR_OR_RELEASE_AUTHORITY"
)
_QUALIFICATION_ASSURANCE = (
    "SEMANTICALLY_REPLAY_VERIFIED_PINNED_SENSOR_PROCESS_LOSS_FAIL_STOP_OBSERVATION"
)
_UNITS = (
    "aragorn-agent-gateway.service",
    "aragorn-runtime-action-worker.service",
    "aragorn-runtime-lineage-capability-observation-publisher.service",
    "aragorn-runtime-lineage-capability-action-broker.service",
)
_GATEWAY_UNIT, _WORKER_UNIT, _SENSOR_UNIT, _BROKER_UNIT = _UNITS
_STOPPED_UNITS = (_GATEWAY_UNIT, _WORKER_UNIT)
_SOCKETS = (
    "/run/aragorn-runtime-action-worker/worker.sock",
    "/run/aragorn-runtime-observation/sensor.sock",
    "/var/lib/aragorn-runtime-action/control/broker.sock",
)
_PROPERTIES = (
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
_ARTIFACT_PATHS = {
    "activator": "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
    "capture_recipe": (
        "/opt/aragorn-sensor-loss-collector/"
        "capture_runtime_action_worker_sensor_loss_systemd.sh"
    ),
    "dockerfile": "/opt/aragorn-sensor-loss-collector/Dockerfile",
    "gateway_unit": "/usr/lib/systemd/system/aragorn-agent-gateway.service",
    "probe": (
        "/opt/aragorn-sensor-loss-collector/"
        "runtime_action_worker_sensor_loss_systemd_probe.py"
    ),
}
_ARTIFACT_MODES = {
    "activator": "0755",
    "capture_recipe": "0755",
    "dockerfile": "0644",
    "gateway_unit": "0644",
    "probe": "0755",
}
_TOP_LEVEL = {
    "after",
    "artifacts",
    "authority",
    "before",
    "bindings",
    "checks",
    "decision",
    "harness",
    "limitations",
    "recorded_at",
    "schema",
    "secret_checks",
    "loss",
}
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
_SOURCE_DECISION = {
    "aggregate_gate_eligible": False,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "retained_evidence_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "status": "SENSOR_PROCESS_LOSS_GATEWAY_FAIL_STOP_OBSERVED",
    "verifier_status": "NOT_TESTED",
}
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "bounded_sensor_process_loss_evidence_eligible": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "source_observation_verified": True,
    "status": "SENSOR_PROCESS_LOSS_GATEWAY_FAIL_STOP_OBSERVED",
}
_CHECKS = {
    "broker_process_and_socket_unchanged": True,
    "gateway_started_with_process": True,
    "gateway_stopped_with_empty_cgroup": True,
    "protected_state_unchanged": True,
    "sensor_restarted_with_new_process": True,
    "singleton_skill_unchanged": True,
    "worker_stopped_with_empty_cgroup": True,
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_INVOCATION = re.compile(r"[0-9a-f]{32}\Z")
_CGROUP_MEMBER = re.compile(r"[1-9][0-9]*\Z")
_MAX_RAW_BYTES = 2 * 1024 * 1024
_SOURCE_SIGNATURE = (
    b'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
    b"SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk\n"
)
_RETAINED_EVIDENCE_DIGEST: str | None = None
_RETAINED_BINDINGS: Mapping[str, Any] | None = None


def verify_runtime_action_worker_sensor_loss_systemd_evidence(
    document: Mapping[str, Any],
    *,
    expected_digest: str | None,
    expected_bindings: Mapping[str, Any] | None,
) -> None:
    """Replay raw state and bytes without trusting reported checks or decision."""

    try:
        _expect(
            _is_digest(expected_digest), "source observation digest pin is required"
        )
        _expect(
            canonical_digest(document) == expected_digest,
            "source observation digest changed",
        )
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(document["schema"] == _SCHEMA, "source schema changed")
        _expect(document["authority"] == _AUTHORITY, "source authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(document["decision"] == _SOURCE_DECISION, "source decision changed")
        _expect(document["checks"] == _CHECKS, "reported checks changed")
        _expect(
            document["secret_checks"] == {"gateway_token_retained": False},
            "secret-retention ceiling changed",
        )
        _time(document["recorded_at"])

        _verify_bindings(
            document["bindings"],
            document["artifacts"],
            document["harness"],
            expected_bindings,
        )
        before = _verify_snapshot(document["before"], active=True)
        sensor_pid = before["services"]["units"][_SENSOR_UNIT]["properties"]["MainPID"]
        loss = _verify_command(
            document["loss"],
            ["kill", "-KILL", sensor_pid],
            stdout_empty=True,
        )
        after = _verify_snapshot(document["after"], active=False)
        _verify_transition(before, loss, after, document["recorded_at"])
    except AdmissionEvidenceError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime worker sensor-loss systemd evidence: {exc}"
        ) from exc


def runtime_action_worker_sensor_loss_systemd_qualification(
    document: Mapping[str, Any],
    *,
    expected_digest: str | None,
    expected_bindings: Mapping[str, Any] | None,
    implementation_digest: str | None,
) -> dict[str, Any]:
    """Return the narrow qualification after an independent semantic replay."""

    _expect(
        _is_digest(_RETAINED_EVIDENCE_DIGEST)
        and expected_digest == _RETAINED_EVIDENCE_DIGEST,
        "retained source observation digest pin is not frozen",
    )
    _expect(
        _RETAINED_BINDINGS is not None and expected_bindings == _RETAINED_BINDINGS,
        "retained outer binding pin is not frozen",
    )
    verify_runtime_action_worker_sensor_loss_systemd_evidence(
        document,
        expected_digest=expected_digest,
        expected_bindings=expected_bindings,
    )
    verifier_digest = (
        "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    _expect(
        implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    return {
        "schema": _QUALIFICATION_SCHEMA,
        "assurance": _QUALIFICATION_ASSURANCE,
        "bindings": {
            "implementation": verifier_digest,
            "outer_harness": document["bindings"],
            "source_observation": expected_digest,
        },
        "decision": dict(_QUALIFICATION_DECISION),
        "limitations": list(_LIMITATIONS),
        "source_recorded_at": document["recorded_at"],
    }


def _verify_bindings(
    bindings: Any,
    artifacts: Any,
    harness: Any,
    expected: Mapping[str, Any] | None,
) -> None:
    _expect(expected is not None and bindings == expected, "outer binding changed")
    _expect(
        isinstance(bindings, Mapping)
        and set(bindings)
        == {"artifacts", "child_image_id", "parent_image_id", "source_commit"},
        "binding fields changed",
    )
    _expect(_HEX40.fullmatch(bindings["source_commit"]) is not None, "source changed")
    _expect(
        _is_digest(bindings["parent_image_id"])
        and _is_digest(bindings["child_image_id"])
        and bindings["parent_image_id"] != bindings["child_image_id"],
        "image binding changed",
    )
    artifact_bindings = bindings["artifacts"]
    _expect(
        isinstance(artifact_bindings, Mapping)
        and set(artifact_bindings) == set(_ARTIFACT_PATHS)
        and all(_is_digest(value) for value in artifact_bindings.values()),
        "artifact binding changed",
    )
    _expect(
        isinstance(artifacts, Mapping) and set(artifacts) == set(_ARTIFACT_PATHS),
        "artifact inventory changed",
    )
    for name, path in _ARTIFACT_PATHS.items():
        _verify_file_record(artifacts[name], expected_path=path, require_raw=True)
        _expect(
            artifacts[name]["digest"] == artifact_bindings[name]
            and artifacts[name]["stat"]["uid"] == 0
            and artifacts[name]["stat"]["gid"] == 0
            and artifacts[name]["stat"]["mode"] == _ARTIFACT_MODES[name],
            f"artifact digest changed: {name}",
        )
    _verify_harness(harness, bindings)


def _verify_harness(harness: Any, bindings: Mapping[str, Any]) -> None:
    _expect(isinstance(harness, Mapping), "harness is invalid")
    required = {
        "capture_disposition",
        "bindings",
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
    _expect(set(harness) == required, "harness fields changed")
    _expect(
        harness["schema"]
        == "aragorn/runtime-action-worker-sensor-loss-systemd-harness/v1"
        and harness["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and harness["platform"] == "linux"
        and harness["profile_label"] == "phase3-runtime-action-worker-sensor-loss"
        and harness["image_reference"]
        == "aragorn-phase3-runtime-action-worker-sensor-loss-systemd"
        and harness["bindings"] == bindings
        and harness["parent_image_id"] == bindings["parent_image_id"]
        and harness["image_id"] == bindings["child_image_id"]
        and harness["run_image_reference"] == bindings["child_image_id"]
        and _HEX64.fullmatch(harness["container_id"]) is not None,
        "harness identity changed",
    )
    _verify_source_commit(harness["source_commit_verification"], bindings)
    _verify_image_lineage(harness["image_lineage"], bindings)
    _verify_runtime_mount(harness)
    _verify_host_config(harness["host_config"], harness["openclaw_runtime_volume"])
    _verify_source_artifacts(harness["source_artifacts"], bindings)
    _verify_harness_raw_records(harness["raw_records"], harness)


def _verify_source_commit(value: Any, bindings: Mapping[str, Any]) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value) == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and value["command"]
        == ["git", "verify-commit", "--raw", bindings["source_commit"]]
        and _exact_int(value["exit_code"], 0),
        "source verification changed",
    )
    commit = _raw_bytes(value["commit_object"])
    stdout = _raw_bytes(value["stdout"])
    stderr = _raw_bytes(value["stderr"])
    identity = hashlib.sha1(
        f"commit {len(commit)}\0".encode("ascii") + commit
    ).hexdigest()
    _expect(
        identity == bindings["source_commit"]
        and commit.startswith(b"tree ")
        and b"\ngpgsig " in commit
        and stdout == b""
        and stderr == _SOURCE_SIGNATURE,
        "signed source identity changed",
    )


def _verify_image_lineage(value: Any, bindings: Mapping[str, Any]) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value) == {"added_layers", "child", "parent"},
        "image lineage fields changed",
    )
    parent = value["parent"]
    child = value["child"]
    for item, expected_id in (
        (parent, bindings["parent_image_id"]),
        (child, bindings["child_image_id"]),
    ):
        _expect(
            isinstance(item, Mapping)
            and set(item) == {"id", "layers", "rootfs_type"}
            and item["id"] == expected_id
            and item["rootfs_type"] == "layers"
            and _digest_list(item["layers"]),
            "image lineage identity changed",
        )
    added = value["added_layers"]
    _expect(
        _digest_list(added)
        and len(added) > 0
        and child["layers"] == [*parent["layers"], *added],
        "child image is not an additive parent layer",
    )


def _verify_runtime_mount(harness: Mapping[str, Any]) -> None:
    name = harness["openclaw_runtime_volume"]
    identity = harness["openclaw_runtime_volume_identity"]
    mount = harness["openclaw_runtime_mount"]
    _expect(isinstance(name, str) and name != "", "runtime volume changed")
    _expect(
        isinstance(identity, Mapping)
        and set(identity) == {"driver", "labels", "name", "options", "scope"}
        and identity["driver"] == "local"
        and identity["name"] == name
        and identity["options"] is None
        and identity["scope"] == "local"
        and identity["labels"]
        == {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": ("7fa98d8e21b6d5937f25a7f19445ff683bb980bf"),
            "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
        },
        "runtime volume identity changed",
    )
    _expect(
        mount
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": name,
            "type": "volume",
        },
        "runtime mount changed",
    )


def _verify_host_config(value: Any, runtime_volume: str) -> None:
    _expect(
        value
        == {
            "binds": [f"{runtime_volume}:/runtime:ro"],
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
        "outer host profile changed",
    )


def _verify_source_artifacts(value: Any, bindings: Mapping[str, Any]) -> None:
    _expect(
        isinstance(value, Mapping) and set(value) == set(_ARTIFACT_PATHS),
        "source artifact inventory changed",
    )
    for name, record in value.items():
        raw = _raw_bytes(record)
        _expect(
            "sha256:" + hashlib.sha256(raw).hexdigest() == bindings["artifacts"][name],
            f"source artifact binding changed: {name}",
        )


def _verify_harness_raw_records(value: Any, harness: Mapping[str, Any]) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value)
        == {
            "child_image_inspect",
            "container_inspect",
            "parent_image_inspect",
            "runtime_volume_inspect",
        },
        "harness raw-record inventory changed",
    )
    parsed = {}
    for name, record in value.items():
        decoded = json.loads(_raw_bytes(record))
        _expect(
            isinstance(decoded, list)
            and len(decoded) == 1
            and isinstance(decoded[0], dict),
            f"harness raw record changed: {name}",
        )
        parsed[name] = decoded[0]

    lineage = harness["image_lineage"]
    for name, normalized in (
        ("parent_image_inspect", lineage["parent"]),
        ("child_image_inspect", lineage["child"]),
    ):
        image = parsed[name]
        _expect(
            image.get("Id") == normalized["id"]
            and image.get("RootFS", {}).get("Type") == normalized["rootfs_type"]
            and image.get("RootFS", {}).get("Layers") == normalized["layers"],
            f"raw image lineage changed: {name}",
        )

    container = parsed["container_inspect"]
    config = container.get("Config", {})
    _expect(
        container.get("Id") == harness["container_id"]
        and container.get("Image") == harness["image_id"]
        and config.get("Image") == harness["run_image_reference"]
        and container.get("Platform") == harness["platform"]
        and config.get("Labels", {}).get("dev.aragorn.profile")
        == harness["profile_label"],
        "raw container identity changed",
    )
    all_mounts = container.get("Mounts")
    _expect(isinstance(all_mounts, list), "raw mount inventory changed")
    mounts = [
        item
        for item in all_mounts
        if isinstance(item, Mapping) and item.get("Destination") == "/runtime"
    ]
    _expect(
        len(all_mounts) == 1 and len(mounts) == 1,
        "raw runtime mount inventory changed",
    )
    mount = mounts[0]
    _expect(
        {
            "destination": mount.get("Destination"),
            "driver": mount.get("Driver"),
            "mode": mount.get("Mode"),
            "rw": mount.get("RW"),
            "source": mount.get("Name"),
            "type": mount.get("Type"),
        }
        == harness["openclaw_runtime_mount"],
        "raw runtime mount changed",
    )
    host = container.get("HostConfig", {})
    _expect(
        {
            "binds": sorted(host.get("Binds") or []),
            "cgroupns_mode": host.get("CgroupnsMode"),
            "ipc_mode": host.get("IpcMode"),
            "network_mode": host.get("NetworkMode"),
            "privileged": host.get("Privileged"),
            "readonly_rootfs": host.get("ReadonlyRootfs"),
            "runtime": host.get("Runtime"),
            "security_opt": host.get("SecurityOpt"),
            "tmpfs": host.get("Tmpfs"),
            "userns_mode": host.get("UsernsMode"),
        }
        == harness["host_config"],
        "raw host profile changed",
    )
    volume = parsed["runtime_volume_inspect"]
    _expect(
        {
            "driver": volume.get("Driver"),
            "labels": volume.get("Labels"),
            "name": volume.get("Name"),
            "options": volume.get("Options"),
            "scope": volume.get("Scope"),
        }
        == harness["openclaw_runtime_volume_identity"],
        "raw runtime volume identity changed",
    )


def _verify_snapshot(value: Any, *, active: bool) -> dict[str, Any]:
    _expect(
        isinstance(value, Mapping) and set(value) == {"protected", "services", "skill"},
        "snapshot fields changed",
    )
    services = value["services"]
    _expect(
        isinstance(services, Mapping) and set(services) == {"sockets", "units"},
        "service snapshot fields changed",
    )
    units = services["units"]
    _expect(
        isinstance(units, Mapping) and set(units) == set(_UNITS),
        "service inventory changed",
    )
    for name in _UNITS:
        _verify_unit(name, units[name])
    _verify_sockets(services["sockets"], active=active)
    _verify_skill(value["skill"])
    _verify_protected(value["protected"])
    return dict(value)


def _verify_unit(name: str, value: Any) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value) == {"cgroup_members", "cgroup_procs", "command", "properties"},
        f"service fields changed: {name}",
    )
    properties = value["properties"]
    _expect(
        isinstance(properties, Mapping)
        and set(properties) == set(_PROPERTIES)
        and all(isinstance(item, str) for item in properties.values()),
        f"service properties changed: {name}",
    )
    raw = _verify_command(
        value["command"],
        ["systemctl", "show", name, *[f"-p{key}" for key in _PROPERTIES]],
        stdout_empty=False,
    )["stdout"]
    lines = raw.decode("utf-8").splitlines()
    pairs = [line.split("=", 1) for line in lines]
    _expect(
        len(pairs) == len(_PROPERTIES)
        and all(len(pair) == 2 for pair in pairs)
        and len({pair[0] for pair in pairs}) == len(_PROPERTIES)
        and dict(pairs) == properties,
        f"raw systemd properties changed: {name}",
    )
    members = value["cgroup_members"]
    _expect(
        isinstance(members, list)
        and len(members) == len(set(members))
        and all(_CGROUP_MEMBER.fullmatch(member) is not None for member in members),
        f"cgroup membership changed: {name}",
    )
    cgroup_procs = value["cgroup_procs"]
    _expect(
        isinstance(cgroup_procs, Mapping)
        and set(cgroup_procs) == {"path", "present", "raw"}
        and cgroup_procs["path"] == f"/sys/fs/cgroup/system.slice/{name}/cgroup.procs"
        and type(cgroup_procs["present"]) is bool,
        f"cgroup.procs record changed: {name}",
    )
    retained = _raw_bytes(cgroup_procs["raw"])
    if retained:
        decoded = retained.decode("ascii")
        derived_members = decoded.splitlines()
        _expect(
            retained == ("\n".join(derived_members) + "\n").encode("ascii")
            and len(derived_members) == len(set(derived_members))
            and all(
                _CGROUP_MEMBER.fullmatch(member) is not None
                for member in derived_members
            ),
            f"raw cgroup membership changed: {name}",
        )
    else:
        derived_members = []
    _expect(
        members == derived_members,
        f"normalized cgroup membership diverged from raw bytes: {name}",
    )


def _verify_transition(
    before: Mapping[str, Any],
    loss: Mapping[str, Any],
    after: Mapping[str, Any],
    recorded_at: str,
) -> None:
    before_units = before["services"]["units"]
    after_units = after["services"]["units"]
    for name in _UNITS:
        unit = before_units[name]
        properties = unit["properties"]
        pid = properties["MainPID"]
        _expect(
            properties["ActiveState"] == "active"
            and properties["SubState"] == "running"
            and properties["Result"] == "success"
            and _CGROUP_MEMBER.fullmatch(pid) is not None
            and _INVOCATION.fullmatch(properties["InvocationID"]) is not None
            and properties["ControlGroup"] == f"/system.slice/{name}"
            and pid in unit["cgroup_members"]
            and unit["cgroup_members"],
            f"service was not active before sensor loss: {name}",
        )
        _expect(
            unit["cgroup_procs"]["present"] is True
            and unit["cgroup_procs"]["raw"]["bytes"] > 0,
            f"active cgroup.procs was not retained: {name}",
        )
        _expect(
            properties["ExecMainCode"] == "0"
            and properties["ExecMainStatus"] == "0"
            and properties["ExecMainExitTimestampMonotonic"] == "0"
            and properties["InactiveEnterTimestampMonotonic"] == "0"
            and _positive_decimal(properties["ExecMainStartTimestampMonotonic"])
            and _positive_decimal(properties["ActiveEnterTimestampMonotonic"])
            and int(properties["ExecMainStartTimestampMonotonic"])
            <= int(properties["ActiveEnterTimestampMonotonic"])
            and int(properties["ActiveEnterTimestampMonotonic"]) * 1_000
            <= unit["command"]["started_monotonic_ns"],
            f"active service execution state changed: {name}",
        )
    _expect(
        len({before_units[name]["properties"]["MainPID"] for name in _UNITS})
        == len(_UNITS)
        and len({before_units[name]["properties"]["InvocationID"] for name in _UNITS})
        == len(_UNITS),
        "active service identities were not distinct",
    )
    for name in _STOPPED_UNITS:
        unit = after_units[name]
        properties = unit["properties"]
        _expect(
            properties["ActiveState"] == "inactive"
            and properties["SubState"] == "dead"
            and properties["MainPID"] == "0"
            and properties["InvocationID"] == ""
            and properties["ControlGroup"] == ""
            and properties["Result"] == "success"
            and properties["ExecMainCode"] == "0"
            and properties["ExecMainStatus"] == "0"
            and properties["ExecMainStartTimestampMonotonic"] == "0"
            and properties["ExecMainExitTimestampMonotonic"] == "0"
            and properties["ActiveEnterTimestampMonotonic"] == "0"
            and properties["InactiveEnterTimestampMonotonic"] == "0"
            and properties["UnitFileState"]
            == before_units[name]["properties"]["UnitFileState"]
            and unit["cgroup_members"] == []
            and unit["cgroup_procs"]["present"] is False
            and unit["cgroup_procs"]["raw"]["bytes"] == 0,
            f"service did not fail-stop after sensor loss: {name}",
        )
    before_sensor = before_units[_SENSOR_UNIT]
    before_sensor_start = int(
        before_sensor["properties"]["ExecMainStartTimestampMonotonic"]
    )
    before_sensor_active = int(
        before_sensor["properties"]["ActiveEnterTimestampMonotonic"]
    )
    after_sensor = after_units[_SENSOR_UNIT]
    sensor_properties = after_sensor["properties"]
    sensor_pid = sensor_properties["MainPID"]
    _expect(
        sensor_properties["ActiveState"] == "active"
        and sensor_properties["SubState"] == "running"
        and sensor_properties["Result"] == "success"
        and sensor_properties["ExecMainCode"] == "0"
        and sensor_properties["ExecMainStatus"] == "0"
        and sensor_properties["ExecMainExitTimestampMonotonic"] == "0"
        and sensor_properties["InactiveEnterTimestampMonotonic"] == "0"
        and _positive_decimal(sensor_properties["ExecMainStartTimestampMonotonic"])
        and _positive_decimal(sensor_properties["ActiveEnterTimestampMonotonic"])
        and sensor_properties["UnitFileState"]
        == before_sensor["properties"]["UnitFileState"]
        and _CGROUP_MEMBER.fullmatch(sensor_pid) is not None
        and sensor_pid != before_sensor["properties"]["MainPID"]
        and _INVOCATION.fullmatch(sensor_properties["InvocationID"]) is not None
        and sensor_properties["InvocationID"]
        != before_sensor["properties"]["InvocationID"]
        and sensor_properties["ControlGroup"] == f"/system.slice/{_SENSOR_UNIT}"
        and sensor_pid in after_sensor["cgroup_members"]
        and after_sensor["cgroup_procs"]["present"] is True
        and after_sensor["cgroup_procs"]["raw"]["bytes"] > 0,
        "sensor process loss and restart were not observed",
    )
    after_sensor_start = int(sensor_properties["ExecMainStartTimestampMonotonic"])
    after_sensor_active = int(sensor_properties["ActiveEnterTimestampMonotonic"])
    _expect(
        before_sensor_start < after_sensor_start
        and before_sensor_active < after_sensor_active
        and loss["completed_monotonic_ns"] <= after_sensor_start * 1_000
        and after_sensor_start <= after_sensor_active
        and after_sensor_active * 1_000
        <= after_sensor["command"]["started_monotonic_ns"],
        "sensor restart chronology changed",
    )
    before_broker = before_units[_BROKER_UNIT]
    after_broker = after_units[_BROKER_UNIT]
    _expect(
        after_broker["properties"] == before_broker["properties"]
        and after_broker["cgroup_members"] == before_broker["cgroup_members"]
        and after_broker["cgroup_procs"] == before_broker["cgroup_procs"],
        "broker continuity changed",
    )
    _expect(
        sensor_pid != after_broker["properties"]["MainPID"]
        and sensor_properties["InvocationID"]
        != after_broker["properties"]["InvocationID"]
        and set(after_sensor["cgroup_members"]).isdisjoint(
            after_broker["cgroup_members"]
        ),
        "sensor and broker process identities overlapped",
    )
    _expect(
        before["services"]["sockets"][_SOCKETS[2]]
        == after["services"]["sockets"][_SOCKETS[2]],
        "broker socket continuity changed",
    )
    _expect(before["skill"] == after["skill"], "singleton skill changed")
    _expect(
        before["protected"] == after["protected"]
        and before["protected"]["target_exists"] is False,
        "protected target or entries changed",
    )
    before_completed = max(
        _time(unit["command"]["completed_at"]) for unit in before_units.values()
    )
    after_started = min(
        _time(unit["command"]["started_at"]) for unit in after_units.values()
    )
    after_completed = max(
        _time(unit["command"]["completed_at"]) for unit in after_units.values()
    )
    before_completed_monotonic = max(
        unit["command"]["completed_monotonic_ns"] for unit in before_units.values()
    )
    after_started_monotonic = min(
        unit["command"]["started_monotonic_ns"] for unit in after_units.values()
    )
    _expect(
        before_completed
        <= _time(loss["started_at"])
        <= _time(loss["completed_at"])
        <= after_started
        <= after_completed
        <= _time(recorded_at)
        and before_completed_monotonic
        <= loss["started_monotonic_ns"]
        <= loss["completed_monotonic_ns"]
        <= after_started_monotonic,
        "sensor-loss chronology changed",
    )


def _verify_sockets(value: Any, *, active: bool) -> None:
    _expect(
        isinstance(value, Mapping) and set(value) == set(_SOCKETS),
        "socket inventory changed",
    )
    for index, path in enumerate(_SOCKETS):
        record = value[path]
        _expect(
            isinstance(record, Mapping)
            and set(record) == {"metadata", "path", "present", "unix"}
            and record["path"] == path
            and isinstance(record["unix"], list)
            and all(isinstance(line, str) for line in record["unix"]),
            f"socket record changed: {path}",
        )
        expected_present = active or index in {1, 2}
        _expect(record["present"] is expected_present, f"socket state changed: {path}")
        if expected_present:
            _verify_socket_metadata(record["metadata"])
        else:
            _expect(
                record["metadata"] is None and record["unix"] == [],
                f"stopped socket remained: {path}",
            )


def _verify_socket_metadata(value: Any) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value)
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and value["type"] == "socket"
        and value["mode"] == "0660"
        and _positive_int(value["device"])
        and _positive_int(value["inode"])
        and _nonnegative_int(value["uid"])
        and _nonnegative_int(value["gid"])
        and _exact_int(value["nlink"], 1)
        and _exact_int(value["size"], 0),
        "socket metadata changed",
    )


def _verify_skill(value: Any) -> None:
    _expect(
        isinstance(value, Mapping) and set(value) == {"file", "parents"},
        "skill snapshot fields changed",
    )
    file = value["file"]
    _verify_file_record(
        file,
        expected_path="/opt/aragorn/runtime-profile/template-skill/SKILL.md",
        require_raw=False,
    )
    stat = file["stat"]
    _expect(
        stat["uid"] == stat["gid"] == 0
        and stat["mode"] == "0444"
        and stat["nlink"] == 1
        and file["bytes"] > 0,
        "singleton skill custody changed",
    )
    expected_parents = (
        ("/", "0755"),
        ("/opt", "0555"),
        ("/opt/aragorn", "0555"),
        ("/opt/aragorn/runtime-profile", "0555"),
        ("/opt/aragorn/runtime-profile/template-skill", "0555"),
    )
    parents = value["parents"]
    _expect(
        isinstance(parents, list) and len(parents) == len(expected_parents),
        "skill parent inventory changed",
    )
    for record, (path, mode) in zip(parents, expected_parents, strict=True):
        _expect(
            record == {"gid": 0, "mode": mode, "path": path, "uid": 0},
            f"skill parent custody changed: {path}",
        )


def _verify_protected(value: Any) -> None:
    _expect(
        isinstance(value, Mapping)
        and set(value) == {"entries", "root", "target_exists"}
        and value["target_exists"] is False
        and isinstance(value["entries"], list)
        and value["entries"] == sorted(set(value["entries"]))
        and all(
            isinstance(name, str) and name not in {"", ".", ".."} and "/" not in name
            for name in value["entries"]
        ),
        "protected state changed",
    )
    root = value["root"]
    _expect(
        isinstance(root, Mapping)
        and set(root)
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and root["type"] == "directory"
        and _positive_int(root["device"])
        and _positive_int(root["inode"])
        and _nonnegative_int(root["uid"])
        and _nonnegative_int(root["gid"])
        and re.fullmatch(r"[0-7]{4}", root["mode"]) is not None
        and _positive_int(root["nlink"])
        and _nonnegative_int(root["size"]),
        "protected root metadata changed",
    )


def _verify_command(
    value: Any,
    argv: list[str],
    *,
    stdout_empty: bool,
) -> dict[str, Any]:
    _expect(
        isinstance(value, Mapping)
        and set(value)
        == {
            "argv",
            "caller",
            "completed_at",
            "completed_monotonic_ns",
            "elapsed_ns",
            "exit_code",
            "signal",
            "started_at",
            "started_monotonic_ns",
            "stderr",
            "stdout",
        }
        and value["argv"] == argv
        and value["caller"] == {"gid": 0, "uid": 0}
        and _exact_int(value["exit_code"], 0)
        and value["signal"] is None
        and _nonnegative_int(value["started_monotonic_ns"])
        and _nonnegative_int(value["completed_monotonic_ns"])
        and _nonnegative_int(value["elapsed_ns"])
        and value["completed_monotonic_ns"] >= value["started_monotonic_ns"]
        and value["elapsed_ns"]
        == value["completed_monotonic_ns"] - value["started_monotonic_ns"]
        and _time(value["started_at"]) <= _time(value["completed_at"]),
        "command receipt changed",
    )
    stdout = _raw_bytes(value["stdout"])
    stderr = _raw_bytes(value["stderr"])
    _expect(stderr == b"", "command stderr changed")
    _expect(not stdout_empty or stdout == b"", "command stdout changed")
    return {**value, "stdout": stdout, "stderr": stderr}


def _verify_file_record(value: Any, *, expected_path: str, require_raw: bool) -> None:
    fields = {"bytes", "digest", "path", "stat"}
    if require_raw:
        fields.add("base64")
    _expect(
        isinstance(value, Mapping)
        and set(value) == fields
        and value["path"] == expected_path
        and _nonnegative_int(value["bytes"])
        and _is_digest(value["digest"]),
        f"file record changed: {expected_path}",
    )
    if require_raw:
        _raw_bytes(value)
    stat = value["stat"]
    _expect(
        isinstance(stat, Mapping)
        and set(stat)
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and stat["type"] == "file"
        and _positive_int(stat["device"])
        and _positive_int(stat["inode"])
        and _nonnegative_int(stat["uid"])
        and _nonnegative_int(stat["gid"])
        and re.fullmatch(r"[0-7]{4}", stat["mode"]) is not None
        and _exact_int(stat["nlink"], 1)
        and stat["size"] == value["bytes"],
        f"file metadata changed: {expected_path}",
    )


def _raw_bytes(value: Any) -> bytes:
    fields = set(value) if isinstance(value, Mapping) else set()
    _expect(
        isinstance(value, Mapping)
        and fields
        in (
            {"base64", "bytes", "digest"},
            {"base64", "bytes", "digest", "path", "stat"},
        )
        and isinstance(value["base64"], str)
        and _nonnegative_int(value["bytes"])
        and value["bytes"] <= _MAX_RAW_BYTES
        and _is_digest(value["digest"]),
        "raw byte record fields changed",
    )
    raw = base64.b64decode(value["base64"], validate=True)
    _expect(
        len(raw) == value["bytes"]
        and "sha256:" + hashlib.sha256(raw).hexdigest() == value["digest"],
        "raw byte record changed",
    )
    return raw


def _digest_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == len(set(value))
        and all(_is_digest(item) for item in value)
    )


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _exact_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _positive_decimal(value: Any) -> bool:
    return isinstance(value, str) and _CGROUP_MEMBER.fullmatch(value) is not None


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_float(key) or _contains_float(item) for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_float(item) for item in value)
    return False


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
