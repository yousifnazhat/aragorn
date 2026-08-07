"""Verify the bounded P3.5a dynamic-capability OpenClaw/systemd artifact."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_action_broker_v4 import _state as _validated_grant_state
from .runtime_action_decision import evaluate_runtime_action
from .runtime_action_openclaw_evidence import (
    _expected_openclaw_configuration,
    _retained_tool_result,
    _tool_contract,
    _valid_provider_record,
    _verify_command_summary,
)
from .runtime_action_systemd_evidence import _contains_float, _same_json
from .runtime_capability_grant import parse_runtime_capability_grant
from .runtime_process_profile import runtime_process_profile
from .runtime_process_profile_openclaw_systemd_evidence import (
    _ENTRYPOINT_DIGEST,
    _NODE,
    _NODE_DIGEST,
    _NODE_IMAGE,
    _OPENCLAW,
    _P34B_IMAGE,
    _REVOCATION_SOURCE,
    _RUNTIME_DIGEST,
    _SENSOR_DIGEST,
    _SKILL,
    _SKILL_DIGEST,
    _SKILL_NAME,
    _SKILL_PATH,
    _SYSTEMD_BASE_IMAGE,
)
from .runtime_process_profile_systemd_evidence import (
    _PROCESS_FIELDS,
    _UNIT_FIELDS,
    _digest,
    _file,
    _metadata,
    _mount_namespace,
    _positive,
    _process,
)

_SCHEMA = "aragorn/runtime-capability-openclaw-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_DYNAMIC_CAPABILITY_SYSTEMD_COMPOSITION_ONLY_"
    "NOT_RUN_OR_EDR_AUTHORITY"
)
_EVIDENCE_DIGEST: str | None = (
    "sha256:7fee778bbf16dd80c726c5007e290f948c1f3ae8212fe462e1a5c2345a32ab45"
)
_P35A_IMAGE = "sha256:12ac568f41c61f714a15f0648b99b0781cedc816a1d591c59de6ef015bcccb4e"
_LIMITATIONS = [
    "ONE_PINNED_OPENCLAW_CREATE_AND_ONE_ROOT_GRANT_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_IS_CONSUMPTION_EVIDENCE_NOT_SEMANTIC_CAUSATION",
    "ROOT_SUPPLIED_SOURCE_AND_INSTALL_DIGESTS_NOT_INDEPENDENT_PROVENANCE",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "PROCESS_PROFILE_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
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
_DECISION = {
    "status": "P3_5A_DYNAMIC_CAPABILITY_OBSERVED",
    "issuer_unavailable_not_submitted_no_effect_observed": True,
    "one_grant_available_to_consumed_observed": True,
    "exact_profile_receipt_bound": True,
    "gateway_main_pid_peer_bound": True,
    "semantic_causation_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "phase3_exit_eligible": False,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "public_release_eligible": False,
}
_TOP_LEVEL = {
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
    "scenarios",
    "schema",
    "timing",
}
_TARGET = "openclaw-capability-allowed.txt"
_PAYLOAD = b"Aragorn P3.5a dynamic one-shot OpenClaw create\n"
_PROTECTED = "/var/lib/aragorn-runtime-action/protected"
_CONTROL = "/var/lib/aragorn-runtime-action/control"
_OPERATION_DIGEST = canonical_digest(
    {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
)
_GATEWAY_FRAGMENT_DIGEST = (
    "sha256:8822cd374f9ebf93b7851fdedf536b240ad9d6e26c3bf3fcd5e5421f666035e8"
)
_PYTHON_MODULES = (
    "__init__.py",
    "oci_worker_protocol.py",
    "runtime_action_decision.py",
    "runtime_action_broker.py",
    "runtime_action_observation_publisher.py",
    "runtime_action_service.py",
    "runtime_observation_service.py",
    "runtime_process_profile.py",
    "runtime_action_broker_v2.py",
    "runtime_action_observation_publisher_v2.py",
    "runtime_action_service_v2.py",
    "runtime_observation_service_v2.py",
    "runtime_action_broker_v3.py",
    "runtime_capability_grant.py",
    "runtime_action_observation_publisher_v3.py",
    "runtime_action_broker_v4.py",
    "runtime_action_service_v4.py",
    "runtime_observation_service_v3.py",
)
_ARTIFACTS = {
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in _PYTHON_MODULES
    },
    "/src/packaging/activate-runtime-capability-host.sh": (
        "/usr/libexec/aragorn/activate-runtime-capability-host.sh"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-service-v4.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v4.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service-v3.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v3.py"
    ),
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-capability-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-capability-action-broker.service"
    ),
    (
        "/src/packaging/systemd/"
        "aragorn-runtime-capability-observation-publisher.service"
    ): (
        "/usr/lib/systemd/system/"
        "aragorn-runtime-capability-observation-publisher.service"
    ),
}
_COLLECTORS = {
    "dockerfile": (
        "/src/benchmark/runtime-capability-openclaw-systemd/Dockerfile",
        "0444",
    ),
    "driver": (
        (
            "/src/benchmark/runtime-process-profile-openclaw-systemd/"
            "openclaw-profile-driver.mjs"
        ),
        "0555",
    ),
    "probe": ("/src/scripts/runtime_capability_openclaw_systemd_probe.py", "0555"),
    "profile_helper": (
        "/src/scripts/runtime_process_profile_openclaw_systemd_probe.py",
        "0555",
    ),
    "recipe": (
        "/src/scripts/capture_runtime_capability_openclaw_systemd.sh",
        "0555",
    ),
}
_BROKER_SERVICE = "aragorn-runtime-capability-action-broker.service"
_SENSOR_SERVICE = "aragorn-runtime-capability-observation-publisher.service"
_LEGACY_SERVICES = {
    "aragorn-runtime-action-broker.service",
    "aragorn-runtime-profile-action-broker.service",
    "aragorn-runtime-observation-publisher.service",
    "aragorn-runtime-profile-observation-publisher.service",
}
_BROKER_COMMAND = [
    "/usr/bin/python3.12",
    "-I",
    "-S",
    "-B",
    "/usr/libexec/aragorn/aragorn-runtime-action-service-v4.py",
    f"/run/credentials/{_BROKER_SERVICE}/runtime-binding",
    f"/run/credentials/{_BROKER_SERVICE}/capability-grant",
]
_SENSOR_COMMAND = [
    "/usr/bin/python3.12",
    "-I",
    "-S",
    "-B",
    "/usr/libexec/aragorn/aragorn-runtime-observation-service-v3.py",
    f"/run/credentials/{_SENSOR_SERVICE}/observation-binding",
    f"/run/credentials/{_SENSOR_SERVICE}/capability-grant",
]
_GATEWAY_COMMAND = [
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


def verify_runtime_capability_openclaw_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.5a without granting semantic, RUN, EDR, or release authority."""

    try:
        pin = _EVIDENCE_DIGEST if expected_digest is None else expected_digest
        _expect(_digest(pin), "an explicit retained evidence digest is required")
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(canonical_digest(document) == pin, "retained evidence changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(_same_json(document["decision"], _DECISION), "claim ceiling changed")
        recorded_at = _time(document["recorded_at"])
        installed = _verify_artifacts(document)
        ids = _verify_environment_harness_and_identities(document)
        profile = _verify_runtime_and_profile(document, ids)
        inputs = _verify_inputs(document, ids, profile)
        _verify_credentials(document, ids, profile, inputs)
        deployment = _verify_deployment(document, ids, profile, installed)
        negative_result = _verify_negative(document, deployment, inputs)
        positive_result = _verify_positive_driver(document, deployment, inputs)
        _verify_positive_state(
            document,
            ids,
            profile,
            deployment,
            inputs,
            positive_result,
            recorded_at.timestamp(),
        )
        _verify_peer_traces(document, ids, deployment)
        _verify_timing(document, inputs)
        _expect(
            negative_result["effect_status"] == "NOT_SUBMITTED",
            "issuer-unavailable result changed",
        )
    except AdmissionEvidenceError:
        raise
    except (
        IndexError,
        KeyError,
        RecursionError,
        RuntimeActionBrokerError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime capability OpenClaw evidence: {exc}"
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
    identities: set[tuple[int, int]] = set()
    for source, installed_path in _ARTIFACTS.items():
        item = by_source[source]
        mode = "0755" if installed_path.startswith("/usr/libexec/") else "0644"
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
            and _digest(item["source_digest"]),
            f"source/install binding changed: {installed_path}",
        )
        _metadata(
            item["installed_stat"],
            kind="file",
            uid=0,
            gid=0,
            mode=mode,
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


def _verify_environment_harness_and_identities(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    environment = document["environment"]
    _expect(
        set(environment)
        == {
            "activation",
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
        == {"exit_code": 0, "stdout": "", "stderr": ""}
        and environment["activation"]["exit_code"] == 0
        and environment["activation"]["stdout"] == ""
        and set(environment["activation"]) == {"exit_code", "stdout", "stderr"},
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
        and all(capture[name] == 0 for name in ("uid", "euid", "gid", "egid"))
        and capture["groups"] == [0]
        and _positive(capture["pid"])
        and _positive(capture["start_time_ticks"])
        and capture["cgroup"].endswith("/init.scope"),
        "capture identity changed",
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
        and value["schema"] == "aragorn/runtime-capability-openclaw-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", value["container_id"])
        and value["image_id"] == value["run_image_reference"] == _P35A_IMAGE
        and value["image_reference"]
        == "aragorn-p35a-runtime-capability-openclaw-systemd"
        and value["parent_image_id"] == _P34B_IMAGE
        and value["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and value["platform"] == "linux"
        and value["profile_label"] == "p3.5a",
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
        and value["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
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
        and parent["id"] == _P34B_IMAGE
        and child["id"] == _P35A_IMAGE
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and all(_digest(layer) for layer in parent["layers"] + child["layers"])
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.4b parent/P3.5a child lineage changed",
    )
    container = value["container_id"]
    _expect(
        capture["cgroup"].startswith(f"/docker/{container}/"),
        "capture/container identity changed",
    )

    identities = document["identities"]
    _expect(set(identities) == {"broker", "runtime", "sensor"}, "identity set changed")
    result: dict[str, Any] = {"container_id": container}
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
    return result


def _verify_runtime_and_profile(
    document: Mapping[str, Any], ids: Mapping[str, Any]
) -> dict[str, Any]:
    _expect(
        document["runtime"]
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
    expected_cgroup = (
        f"/docker/{ids['container_id']}/system.slice/aragorn-openclaw-profile.service"
    )
    _expect(
        profile["digest"] == parsed.digest
        and parsed.runtime_digest == _RUNTIME_DIGEST
        and parsed.executable_digest == _NODE_DIGEST
        and str(parsed.skill_path) == _SKILL_PATH
        and parsed.cgroup == expected_cgroup,
        "runtime profile changed",
    )
    _file(profile["skill"], path=_SKILL_PATH, uid=0, gid=0, mode="0444")
    _file(profile["executable"], path=_NODE, uid=0, gid=0, mode="0755")
    _expect(
        profile["skill"]["bytes"] == len(_SKILL.encode())
        and profile["skill"]["digest"] == _SKILL_DIGEST
        and profile["executable"] == document["environment"]["node"],
        "profile files changed",
    )
    return {
        "digest": parsed.digest,
        "document": profile["document"],
        "cgroup": parsed.cgroup,
        "skill_digest": _SKILL_DIGEST,
        "executable_digest": _NODE_DIGEST,
    }


def _verify_inputs(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    inputs = document["inputs"]
    _expect(
        set(inputs)
        == {
            "action",
            "gateway_config",
            "gateway_config_digest",
            "grant",
            "initial_controls",
            "negative_driver",
            "policy",
            "positive_driver",
            "provenance_bindings",
            "refreshed_controls",
        },
        "input fields changed",
    )
    protected = document["deployment"]["directories"]["protected"]
    action = {
        "operation_digest": _OPERATION_DIGEST,
        "path_digest": canonical_digest(
            {
                "schema": "aragorn/runtime-protected-path/v1",
                "root_device": protected["device"],
                "root_inode": protected["inode"],
                "target_name": _TARGET,
            }
        ),
        "payload_digest": "sha256:" + hashlib.sha256(_PAYLOAD).hexdigest(),
    }
    _expect(inputs["action"] == action, "derived create action changed")
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-5a-pinned-openclaw-dynamic-capability",
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
    _expect(inputs["policy"] == policy, "runtime policy changed")
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
    _expect(
        _same_json(inputs["gateway_config"], expected_config)
        and inputs["gateway_config_digest"] == canonical_digest(expected_config),
        "OpenClaw gateway configuration changed",
    )
    negative_input = _driver_input(
        "issuer-unavailable", "CLIENT_ERROR", "NOT_SUBMITTED"
    )
    positive_input = _driver_input("one-shot-allow", "ALLOW", "CREATED")
    _expect(
        inputs["negative_driver"] == negative_input
        and inputs["positive_driver"] == positive_input,
        "driver inputs changed",
    )
    _verify_controls(inputs["initial_controls"], policy, action, counter=1, full=True)
    _verify_controls(
        inputs["refreshed_controls"], policy, action, counter=2, full=False
    )
    initial_at = inputs["initial_controls"]["health"]["observed_at_unix"]
    refreshed_at = inputs["refreshed_controls"]["health"]["observed_at_unix"]
    _expect(initial_at < refreshed_at, "control refresh did not advance")
    provenance = inputs["provenance_bindings"]
    expected_provenance = {
        "source_manifest": {
            "schema": "aragorn/evaluator-root-source-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5a-pinned-openclaw-source",
        },
        "install_context": {
            "schema": "aragorn/evaluator-root-install-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5a-pinned-openclaw-install",
        },
    }
    _expect(provenance == expected_provenance, "root provenance claim ceiling changed")
    retained_grant = inputs["grant"]
    grant = retained_grant["document"]
    _expect(
        set(retained_grant) == {"digest", "document"}
        and retained_grant["digest"] == canonical_digest(grant)
        and parse_runtime_capability_grant(
            canonical_json(grant), grant["issued_at_unix"]
        )
        == grant
        and grant["source_manifest_digest"]
        == canonical_digest(provenance["source_manifest"])
        and grant["install_context_digest"]
        == canonical_digest(provenance["install_context"])
        and grant["runtime_profile_digest"] == profile["digest"]
        and grant["runtime_digest"] == _RUNTIME_DIGEST
        and grant["active_skill_digest"] == _SKILL_DIGEST
        and grant["sensor_digest"] == _SENSOR_DIGEST
        and grant["policy_digest"] == canonical_digest(policy)
        and grant["policy_version"] == 1
        and grant["operation_digest"] == action["operation_digest"]
        and grant["expires_at_unix"] - grant["issued_at_unix"] == 241
        and grant["issued_at_unix"] <= initial_at < grant["expires_at_unix"]
        and grant["issued_at_unix"] <= refreshed_at < grant["expires_at_unix"],
        "root capability grant changed",
    )
    return {
        "action": action,
        "policy": policy,
        "grant": grant,
        "grant_digest": retained_grant["digest"],
        "initial": inputs["initial_controls"],
        "refreshed": inputs["refreshed_controls"],
    }


def _verify_controls(
    controls: Mapping[str, Any],
    policy: Mapping[str, Any],
    action: Mapping[str, Any],
    *,
    counter: int,
    full: bool,
) -> None:
    expected_fields = (
        {"policy", "revocations", "health", "observation", "state"}
        if full
        else {"revocations", "health", "observation"}
    )
    _expect(set(controls) == expected_fields, "control closure changed")
    now = controls["health"]["observed_at_unix"]
    _expect(_positive(now), "control time changed")
    seed = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": f"seed-p3-5a-{counter}",
        "run_id": f"seed-p3-5a-{counter}",
        "tool_call_id": f"seed-p3-5a-{counter}",
        "active_skill_digest": _SKILL_DIGEST,
    }
    _expect(
        controls["revocations"]
        == {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": counter,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        }
        and controls["health"]
        == {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": counter,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        }
        and controls["observation"]
        == {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": counter,
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
        "control semantics changed",
    )
    if full:
        _expect(
            controls["policy"] == policy
            and controls["state"]
            == {
                "schema": "aragorn/runtime-action-broker-state/v2",
                "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "minimum_revocation_generation": 1,
                "minimum_mediator_health_epoch": 1,
                "consumed": [],
                "effect_journal": None,
            },
            "initial broker state changed",
        )


def _verify_credentials(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> None:
    credentials = document["credentials"]
    _expect(
        set(credentials) == {"broker", "root_grant", "sensor"}
        and set(credentials["broker"]) == {"capability_grant", "runtime_binding"}
        and set(credentials["sensor"]) == {"capability_grant", "observation_binding"},
        "credential closure changed",
    )
    grant_raw = canonical_json(inputs["grant"])
    root = credentials["root_grant"]
    _file(
        root,
        path="/etc/aragorn/runtime-capability-grant.json",
        uid=0,
        gid=0,
        mode="0400",
    )
    _expect(
        root["digest"] == inputs["grant_digest"] and root["bytes"] == len(grant_raw),
        "root grant credential changed",
    )
    for service, principal in (
        ("broker", ids["broker_uid"]),
        ("sensor", ids["sensor_uid"]),
    ):
        copy = credentials[service]["capability_grant"]
        unit = _BROKER_SERVICE if service == "broker" else _SENSOR_SERVICE
        _file(
            copy,
            path=f"/run/credentials/{unit}/capability-grant",
            uid=principal,
            gid=0,
            mode="0400",
        )
        _expect(
            copy["digest"] == root["digest"] and copy["bytes"] == root["bytes"],
            "systemd grant credential changed",
        )
    runtime_binding = {
        "schema": "aragorn/runtime-action-runtime-binding/v2",
        "runtime_digest": _RUNTIME_DIGEST,
        "runtime_profile_digest": profile["digest"],
    }
    observation_binding = {
        "schema": "aragorn/runtime-observation-binding/v2",
        "sensor_digest": _SENSOR_DIGEST,
        "runtime_profile": profile["document"],
    }
    for record, path, principal, value in (
        (
            credentials["broker"]["runtime_binding"],
            f"/run/credentials/{_BROKER_SERVICE}/runtime-binding",
            ids["broker_uid"],
            runtime_binding,
        ),
        (
            credentials["sensor"]["observation_binding"],
            f"/run/credentials/{_SENSOR_SERVICE}/observation-binding",
            ids["sensor_uid"],
            observation_binding,
        ),
    ):
        _file(record, path=path, uid=principal, gid=0, mode="0400")
        _expect(
            record["digest"] == canonical_digest(value)
            and record["bytes"] == len(canonical_json(value)),
            "systemd binding credential changed",
        )


def _verify_deployment(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    installed: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    deployment = document["deployment"]
    _expect(
        set(deployment) == {"directories", "gateway", "negative", "positive"},
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
        len({(item["device"], item["inode"]) for item in directories.values()})
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
    gateways = deployment["gateway"]
    _expect(set(gateways) == {"negative", "positive"}, "gateway epochs changed")
    negative_gateway = _verify_gateway(
        gateways["negative"], ids, profile, positive=False
    )
    positive_gateway = _verify_gateway(
        gateways["positive"], ids, profile, positive=True
    )
    _expect(
        negative_gateway["pid"] != positive_gateway["pid"]
        and negative_gateway["mount_namespace"] == positive_gateway["mount_namespace"],
        "gateway restart/profile relationship changed",
    )

    negative = deployment["negative"]
    _expect(
        set(negative) == {"broker_process", "broker_unit", "effects", "sensor_unit"},
        "negative deployment changed",
    )
    broker_unit = negative["broker_unit"]
    sensor_unit = negative["sensor_unit"]
    _verify_unit(
        broker_unit,
        service=_BROKER_SERVICE,
        fragment_digest=installed[f"/usr/lib/systemd/system/{_BROKER_SERVICE}"][
            "installed_digest"
        ],
        user="aragorn-broker",
        group="aragorn-runtime",
        supplementary="aragorn-sensor",
        capabilities="",
        command=_BROKER_COMMAND,
        active=True,
        load_credential=None,
    )
    _verify_unit(
        sensor_unit,
        service=_SENSOR_SERVICE,
        fragment_digest=installed[f"/usr/lib/systemd/system/{_SENSOR_SERVICE}"][
            "installed_digest"
        ],
        user="aragorn-sensor",
        group="aragorn-sensor",
        supplementary="aragorn-runtime",
        capabilities="cap_setgid cap_setuid cap_setpcap",
        command=_SENSOR_COMMAND,
        active=False,
        load_credential=(
            'a(ss) 2 "observation-binding" '
            '"/etc/aragorn/runtime-action-observation.json" '
            '"capability-grant" "/etc/aragorn/runtime-capability-grant.json"'
        ),
    )
    _process(
        negative["broker_process"],
        unit=broker_unit,
        command=_BROKER_COMMAND,
        uids=[ids["broker_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _expect(negative["effects"] == _no_effects(), "negative effects changed")

    positive = deployment["positive"]
    _expect(
        set(positive) == {"legacy_routes", "processes", "security", "sockets", "units"},
        "positive deployment changed",
    )
    units = positive["units"]
    _expect(set(units) == {"broker", "sensor"}, "dynamic unit closure changed")
    unit_specs = {
        "broker": (
            _BROKER_SERVICE,
            "aragorn-broker",
            "aragorn-runtime",
            "aragorn-sensor",
            "",
            _BROKER_COMMAND,
            (
                'a(ss) 2 "runtime-binding" '
                '"/etc/aragorn/runtime-action-runtime.json" '
                '"capability-grant" "/etc/aragorn/runtime-capability-grant.json"'
            ),
        ),
        "sensor": (
            _SENSOR_SERVICE,
            "aragorn-sensor",
            "aragorn-sensor",
            "aragorn-runtime",
            "cap_setgid cap_setuid cap_setpcap",
            _SENSOR_COMMAND,
            (
                'a(ss) 2 "observation-binding" '
                '"/etc/aragorn/runtime-action-observation.json" '
                '"capability-grant" "/etc/aragorn/runtime-capability-grant.json"'
            ),
        ),
    }
    for name, (
        service,
        user,
        group,
        supplementary,
        capabilities,
        command,
        load,
    ) in unit_specs.items():
        _verify_unit(
            units[name],
            service=service,
            fragment_digest=installed[f"/usr/lib/systemd/system/{service}"][
                "installed_digest"
            ],
            user=user,
            group=group,
            supplementary=supplementary,
            capabilities=capabilities,
            command=command,
            active=True,
            load_credential=load,
        )
    processes = positive["processes"]
    _expect(set(processes) == {"broker", "sensor"}, "dynamic process closure changed")
    _process(
        processes["broker"],
        unit=units["broker"],
        command=_BROKER_COMMAND,
        uids=[ids["broker_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _process(
        processes["sensor"],
        unit=units["sensor"],
        command=_SENSOR_COMMAND,
        uids=[ids["sensor_uid"]] * 3 + [ids["runtime_uid"]],
        gids=[ids["sensor_gid"]] * 3 + [ids["runtime_gid"]],
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _expect(
        set(positive["security"]) == {"broker", "sensor"}
        and all(_zero_security(value) for value in positive["security"].values()),
        "dynamic process security changed",
    )
    sockets = positive["sockets"]
    _expect(set(sockets) == {"backend", "frontend"}, "socket closure changed")
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
    _expect(
        set(positive["legacy_routes"]) == _LEGACY_SERVICES
        and all(
            route
            == {
                "enabled_exit_code": 1,
                "enabled": "masked",
                "active_exit_code": 3,
                "active": "inactive",
            }
            for route in positive["legacy_routes"].values()
        ),
        "legacy runtime route remained usable",
    )
    namespaces = {
        processes[name][field]
        for name in ("broker", "sensor")
        for field in ("mount_namespace", "network_namespace")
    }
    namespaces.update(
        positive_gateway[field] for field in ("mount_namespace", "network_namespace")
    )
    _expect(len(namespaces) == 6, "service namespaces overlap")
    return {
        "negative_broker_pid": negative["broker_process"]["pid"],
        "negative_gateway_pid": negative_gateway["pid"],
        "positive_broker_pid": processes["broker"]["pid"],
        "positive_sensor_pid": processes["sensor"]["pid"],
        "positive_gateway": positive_gateway,
        "positive_gateway_pid": positive_gateway["pid"],
        "protected": directories["protected"],
        "control": directories["control"],
    }


def _verify_gateway(
    value: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    positive: bool,
) -> dict[str, Any]:
    before_name = "process_before" if positive else "process"
    expected_fields = (
        {"cgroup_processes", "process_after", before_name, "security", "unit"}
        if positive
        else {
            "cgroup",
            "mount_namespace",
            "pid",
            "process",
            "process_after",
            "security",
            "unit",
        }
    )
    _expect(set(value) == expected_fields, "gateway snapshot changed")
    unit = value["unit"]
    _verify_unit(
        unit,
        service="aragorn-openclaw-profile.service",
        fragment_digest=_GATEWAY_FRAGMENT_DIGEST,
        user="aragorn-runtime",
        group="aragorn-runtime",
        supplementary="",
        capabilities="",
        command=_GATEWAY_COMMAND,
        active=True,
        load_credential=None,
    )
    before = value[before_name]
    after = value["process_after"]
    _process(
        before,
        unit=unit,
        command=["openclaw"],
        uids=[ids["runtime_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=[ids["runtime_gid"]],
    )
    _process(
        after,
        unit=unit,
        command=["openclaw-gateway"],
        uids=[ids["runtime_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=[ids["runtime_gid"]],
    )
    _expect(
        all(before[field] == after[field] for field in _PROCESS_FIELDS - {"cmdline"})
        and unit["ControlGroup"] == profile["cgroup"]
        and _zero_security(value["security"]),
        "gateway process profile changed",
    )
    if positive:
        _expect(
            value["cgroup_processes"] == [before["pid"]], "gateway is not singleton"
        )
    else:
        _expect(
            value["pid"] == before["pid"]
            and value["cgroup"] == profile["cgroup"]
            and value["mount_namespace"]["inode"]
            == int(before["mount_namespace"][5:-1]),
            "negative gateway identity changed",
        )
        _mount_namespace(value["mount_namespace"])
    return {
        "pid": before["pid"],
        "start_time_ticks": int(before["start_time_ticks"]),
        "mount_namespace": before["mount_namespace"],
        "network_namespace": before["network_namespace"],
        "cgroup": unit["ControlGroup"],
    }


def _verify_unit(
    unit: Mapping[str, Any],
    *,
    service: str,
    fragment_digest: str,
    user: str,
    group: str,
    supplementary: str,
    capabilities: str,
    command: list[str],
    active: bool,
    load_credential: str | None,
) -> None:
    fields = _UNIT_FIELDS | (
        {"LoadCredential"} if load_credential is not None else set()
    )
    state = ("active", "running") if active else ("inactive", "dead")
    _expect(
        set(unit) == fields
        and unit["FragmentPath"] == f"/lib/systemd/system/{service}"
        and unit["FragmentResolvedPath"] == f"/usr/lib/systemd/system/{service}"
        and unit["FragmentDigest"] == fragment_digest
        and unit["DropInPaths"] == ""
        and unit["User"] == user
        and unit["Group"] == group
        and unit["SupplementaryGroups"] == supplementary
        and unit["AmbientCapabilities"] == capabilities
        and unit["CapabilityBoundingSet"] == capabilities
        and unit["NoNewPrivileges"] == "yes"
        and (unit["ActiveState"], unit["SubState"]) == state
        and unit["Result"] == "success"
        and unit["ExecMainStatus"] == "0"
        and _loaded_command(unit["ExecStart"], command)
        and (load_credential is None or unit["LoadCredential"] == load_credential)
        and ((unit["MainPID"] != "0") if active else unit["MainPID"] == "0"),
        f"loaded unit contract changed: {service}",
    )


def _verify_negative(
    document: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> Mapping[str, Any]:
    scenario = document["scenarios"]["issuer_unavailable"]
    _expect(
        set(scenario)
        == {
            "control_after",
            "control_before",
            "driver",
            "driver_elapsed_ns",
            "driver_exit_code",
            "driver_stderr",
            "driver_stdout",
            "effects",
            "grant_state_after",
            "grant_state_before",
            "status",
        }
        and scenario["status"] == "PASS"
        and scenario["driver_exit_code"] == 1
        and scenario["driver_stdout"] == scenario["driver_stderr"] == ""
        and _positive(scenario["driver_elapsed_ns"])
        and scenario["effects"] == _no_effects()
        and scenario["effects"] == document["deployment"]["negative"]["effects"],
        "issuer-unavailable scenario changed",
    )
    available = {
        "schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": inputs["grant_digest"],
        "status": "AVAILABLE",
        "claim": None,
        "result": None,
    }
    retained_available = {"digest": canonical_digest(available), "document": available}
    initial = inputs["initial"]
    controls = {
        "policy.json": canonical_digest(inputs["policy"]),
        "revocations.json": canonical_digest(initial["revocations"]),
        "health.json": canonical_digest(initial["health"]),
        "observation.json": canonical_digest(initial["observation"]),
        "state.json": canonical_digest(initial["state"]),
        "capability-grant-state.json": canonical_digest(available),
    }
    _expect(
        scenario["grant_state_before"]
        == scenario["grant_state_after"]
        == retained_available
        and _validated_grant_state(available, inputs["grant_digest"]) == available
        and scenario["control_before"] == scenario["control_after"] == controls,
        "issuer-unavailable path changed durable state",
    )
    result = _verify_driver(
        scenario["driver"],
        scenario_id="issuer-unavailable",
        gateway_pid=deployment["negative_gateway_pid"],
        expected_result={
            "schema": "aragorn/runtime-action-client-error/v1",
            "authority": "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "effect_status": "NOT_SUBMITTED",
            "message": "sensor runtime directory is unavailable: ENOENT",
        },
        expected_outer_pass=False,
    )
    return result


def _verify_positive_driver(
    document: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> Mapping[str, Any]:
    scenario = document["scenarios"]["one_shot_allow"]
    _expect(
        set(scenario)
        == {
            "before",
            "broker_state",
            "control_after",
            "driver",
            "driver_elapsed_ns",
            "driver_exit_code",
            "driver_stderr",
            "driver_stdout",
            "grant_state",
            "grant_state_file",
            "profile_pending_exists",
            "profile_receipt",
            "profile_receipt_file",
            "protected_entries",
            "runtime_facing_grant_or_lease_absent",
            "staging_entries",
            "status",
            "target",
        }
        and scenario["status"] == "PASS"
        and scenario["driver_exit_code"] == 0
        and scenario["driver_stdout"] == scenario["driver_stderr"] == ""
        and _positive(scenario["driver_elapsed_ns"])
        and scenario["profile_pending_exists"] is False
        and scenario["protected_entries"] == [_TARGET]
        and scenario["staging_entries"] == [],
        "one-shot positive scenario changed",
    )
    result = _verify_driver(
        scenario["driver"],
        scenario_id="one-shot-allow",
        gateway_pid=deployment["positive_gateway_pid"],
        expected_result=None,
        expected_outer_pass=True,
    )
    _expect(
        result.get("schema") == "aragorn/runtime-action-broker-result/v1"
        and result.get("authority")
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and result.get("verdict") == "ALLOW"
        and result.get("reason_codes") == []
        and result.get("effect_status") == "CREATED"
        and result.get("target_name") == _TARGET,
        "positive retained result changed",
    )
    return result


def _verify_driver(
    driver: Mapping[str, Any],
    *,
    scenario_id: str,
    gateway_pid: int,
    expected_result: Mapping[str, Any] | None,
    expected_outer_pass: bool,
) -> Mapping[str, Any]:
    _expect(
        set(driver) == {"gateway", "provider", "scenario", "schema", "timing", "turn"}
        and driver["schema"] == "aragorn/openclaw-profile-driver-output/v1",
        "driver output changed",
    )
    system_info = driver["gateway"]["system_info"]
    _expect(
        set(driver["gateway"]) == {"system_info"}
        and set(system_info) == {"command", "response"}
        and system_info["response"] == {"pid": gateway_pid},
        "driver gateway PID changed",
    )
    _verify_command_summary(
        system_info["command"],
        [
            _NODE,
            _OPENCLAW,
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ],
    )
    turn = driver["turn"]
    _expect(
        set(turn) == {"history", "identifiers", "send", "wait"}, "turn fields changed"
    )
    identifiers = turn["identifiers"]
    normalized = scenario_id.replace("-", "_")
    run_id = f"aragorn-p34b-{scenario_id}"
    session_key = f"agent:main:{run_id}"
    tool_call_id = f"call_aragorn_p34b_{normalized}_1"
    user_text = (
        "Invoke aragorn_runtime_create exactly once for bounded scenario "
        f"{scenario_id}."
    )
    _expect(
        set(identifiers) == {"run_id", "session_id", "session_key", "tool_call_id"}
        and identifiers["run_id"] == run_id
        and identifiers["session_key"] == session_key
        and identifiers["tool_call_id"] == tool_call_id
        and isinstance(identifiers["session_id"], str)
        and bool(identifiers["session_id"]),
        "driver identifiers changed",
    )
    provider = driver["provider"]
    records = provider["records"]
    _expect(
        set(provider) == {"errors", "records", "request_count"}
        and provider["errors"] == []
        and provider["request_count"] == len(records) == 2
        and all(_valid_provider_record(record) for record in records)
        and [record["sequence"] for record in records] == [1, 2]
        and _time(records[0]["received_at"]) <= _time(records[1]["received_at"]),
        "deterministic provider boundary changed",
    )
    bodies = [record["body"] for record in records]
    body_fields = {"max_tokens", "messages", "model", "stream", "tool_choice", "tools"}
    _expect(
        all(set(body) == body_fields for body in bodies)
        and all(body["model"] == "fixture-model" for body in bodies)
        and all(body["max_tokens"] == 256 for body in bodies)
        and all(body["stream"] is True for body in bodies)
        and all(body["tool_choice"] == "auto" for body in bodies)
        and bodies[1]["tools"] == bodies[0]["tools"],
        "provider request contract changed",
    )
    exposed = [
        tool
        for tool in bodies[0]["tools"]
        if isinstance(tool, Mapping)
        and tool.get("function", {}).get("name") == "aragorn_runtime_create"
    ]
    _expect(exposed == [_tool_contract()], "exposed Aragorn tool contract changed")
    prompt = "\n".join(
        message["content"]
        for message in bodies[0]["messages"]
        if isinstance(message, Mapping)
        and message.get("role") == "system"
        and isinstance(message.get("content"), str)
    )
    description = "Exercise one bounded profiled OpenClaw create in the P3.4b fixture."
    _expect(
        prompt.count(f"<name>{_SKILL_NAME}</name>") == 1
        and prompt.count(f"<description>{description}</description>") == 1
        and prompt.count(f"<location>{_SKILL_PATH}</location>") == 1
        and prompt.count(f"<version>{_SKILL_DIGEST[:23]}</version>") == 1,
        "root-owned skill prompt projection changed",
    )
    arguments = canonical_json(
        {"content": _PAYLOAD.decode(), "target_name": _TARGET}
    ).decode("ascii")
    first_response, second_response = _provider_responses(
        scenario_id, tool_call_id, expected_outer_pass
    )
    authorization = (
        "sha256:"
        + hashlib.sha256(b"Bearer aragorn-runtime-action-mock-local").hexdigest()
    )
    _expect(
        records[0]["response"] == first_response
        and records[1]["response"] == second_response
        and all(record["authorization_digest"] == authorization for record in records),
        "provider response lineage changed",
    )
    messages = turn["history"]["response"]["messages"]
    history = turn["history"]["response"]
    _expect(
        set(history)
        == {
            "defaults",
            "messages",
            "sessionId",
            "sessionInfo",
            "sessionKey",
            "thinkingLevel",
        }
        and history["sessionId"] == identifiers["session_id"]
        and history["sessionKey"] == session_key
        and history["thinkingLevel"] == "off"
        and len(messages) == 4
        and [item["__openclaw"]["seq"] for item in messages] == [1, 2, 3, 4]
        and [item["role"] for item in messages]
        == ["user", "assistant", "toolResult", "assistant"]
        and history["sessionInfo"]["key"] == session_key
        and history["sessionInfo"]["sessionId"] == identifiers["session_id"]
        and history["sessionInfo"]["status"] == "done"
        and history["sessionInfo"]["activeRunIds"] == [],
        "retained history lineage changed",
    )
    user, assistant, tool_message, final = messages
    retained_tool = _retained_tool_result(tool_message)
    retained = retained_tool["document"]
    result = retained["result"]
    final_code = (
        "ARAGORN_RUNTIME_ACTION_ALLOW_CREATED"
        if expected_outer_pass
        else "ARAGORN_RUNTIME_ACTION_CLIENT_ERROR_NOT_SUBMITTED"
    )
    _expect(
        user["content"] == user_text
        and user["idempotencyKey"] == f"{run_id}:user"
        and len(assistant["content"]) == 1
        and assistant["content"][0]
        == {
            "arguments": {"content": _PAYLOAD.decode(), "target_name": _TARGET},
            "id": tool_call_id,
            "name": "aragorn_runtime_create",
            "partialArgs": arguments,
            "type": "toolCall",
        }
        and assistant["provider"] == "aragorn-runtime-action-mock"
        and assistant["model"] == "fixture-model"
        and assistant["responseId"] == f"chatcmpl-{scenario_id}-tool"
        and assistant["stopReason"] == "toolUse"
        and tool_message["toolCallId"] == tool_call_id
        and tool_message["toolName"] == "aragorn_runtime_create"
        and tool_message["isError"] is False
        and tool_message["content"] == [{"text": retained_tool["raw"], "type": "text"}]
        and "details" not in tool_message
        and final["provider"] == "aragorn-runtime-action-mock"
        and final["model"] == "fixture-model"
        and final["responseId"] == f"chatcmpl-{scenario_id}-final"
        and final["stopReason"] == "stop"
        and final["content"] == [{"text": final_code, "type": "text"}],
        "retained tool result lineage changed",
    )
    if expected_result is not None:
        _expect(result == expected_result, "client fail-closed result changed")
    first_messages, second_messages = bodies[0]["messages"], bodies[1]["messages"]
    transport_id = tool_call_id.replace("_", "")
    _expect(
        [message.get("role") for message in first_messages] == ["system", "user"]
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
                        "arguments": arguments,
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
    _verify_turn_commands(turn, run_id, session_key, user_text)
    checks = {
        "action_result_bound": expected_outer_pass,
        "gateway_pid_present": True,
        "history_lineage": True,
        "one_provider_driven_tool_call": True,
        "provider_completed_without_error": True,
    }
    proof = driver["scenario"]["proof"]
    _expect(
        driver["scenario"]["status"] == ("PASS" if expected_outer_pass else "FAIL")
        and set(proof) == {"checks", "passed", "retained_tool_result"}
        and proof["checks"] == checks
        and proof["passed"] is expected_outer_pass
        and _same_json(proof["retained_tool_result"], retained),
        "driver proof changed",
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


def _verify_turn_commands(
    turn: Mapping[str, Any], run_id: str, session_key: str, user_text: str
) -> None:
    send_params = canonical_json(
        {
            "deliver": False,
            "idempotencyKey": run_id,
            "message": user_text,
            "sessionKey": session_key,
            "timeoutMs": 10000,
        }
    ).decode("ascii")
    contracts = (
        ("send", "chat.send", "5000", send_params),
        (
            "wait",
            "agent.wait",
            "17000",
            canonical_json({"runId": run_id, "timeoutMs": 15000}).decode("ascii"),
        ),
        (
            "history",
            "chat.history",
            "5000",
            canonical_json({"limit": 20, "sessionKey": session_key}).decode("ascii"),
        ),
    )
    for name, method, timeout, params in contracts:
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
        and turn["wait"]["response"]["runId"] == run_id
        and turn["wait"]["response"]["status"] == "ok"
        and _positive(turn["wait"]["response"]["endedAt"]),
        "turn lifecycle changed",
    )


def _verify_positive_state(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
    retained_result: Mapping[str, Any],
    recorded_at: float,
) -> None:
    scenario = document["scenarios"]["one_shot_allow"]
    state = scenario["grant_state"]
    state_document = state["document"]
    _expect(
        set(state) == {"digest", "document"}
        and state["digest"] == canonical_digest(state_document)
        and _validated_grant_state(state_document, inputs["grant_digest"])
        == state_document
        and state_document["status"] == "CONSUMED",
        "terminal grant state changed",
    )
    claim = state_document["claim"]
    lease = claim["lease"]
    lease_digest = canonical_digest(lease)
    profile_claim = claim["profile_claim"]
    pending = profile_claim["profile_pending"]
    attribution = pending["runtime_attribution"]
    measured = pending["measured_action"]
    identifiers = scenario["driver"]["turn"]["identifiers"]
    hashed_tool_call = (
        "sha256:" + hashlib.sha256(identifiers["tool_call_id"].encode()).hexdigest()
    )
    result = scenario["profile_receipt"]["document"]["broker_result"]
    decision = result["decision"]
    now = decision["evaluated_at_unix"]
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
    candidates = [
        {
            **request_base,
            "issued_at_unix": issued,
            "expires_at_unix": issued + 5,
        }
        for issued in range(now - 5, now + 1)
    ]
    candidates = [
        item
        for item in candidates
        if canonical_digest(item) == result["request_digest"]
    ]
    _expect(len(candidates) == 1, "signed request could not be independently derived")
    request = candidates[0]
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
    expected_measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{key: value for key, value in active.items() if key != "schema"},
        **inputs["action"],
    }
    expected_attribution = {
        "schema": "aragorn/runtime-process-profile-attribution/v1",
        "authority": "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "profile_digest": profile["digest"],
        "runtime_digest": _RUNTIME_DIGEST,
        "executable_digest": _NODE_DIGEST,
        "active_skill_digest": _SKILL_DIGEST,
        "skill_path": _SKILL_PATH,
        "cgroup": profile["cgroup"],
        "pid": deployment["positive_gateway_pid"],
        "uid": ids["runtime_uid"],
        "gid": ids["runtime_gid"],
        "start_time_ticks": deployment["positive_gateway"]["start_time_ticks"],
        "mount_namespace": {
            "device": document["environment"]["capture_identity"]["mount_namespace"][
                "device"
            ],
            "inode": int(deployment["positive_gateway"]["mount_namespace"][5:-1]),
        },
    }
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": _SENSOR_DIGEST,
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {
            "pid": deployment["positive_gateway_pid"],
            "uid": ids["runtime_uid"],
            "gid": ids["runtime_gid"],
        },
        "measured_action": expected_measured,
        "envelope": envelope,
        "runtime_attribution": expected_attribution,
    }
    _expect(
        measured == expected_measured
        and attribution == expected_attribution
        and pending
        == {
            "schema": "aragorn/runtime-process-profile-pending/v1",
            "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
            "submission_digest": canonical_digest(submission),
            "envelope_digest": canonical_digest(envelope),
            "request_digest": canonical_digest(request),
            "measured_action": expected_measured,
            "runtime_attribution_digest": canonical_digest(expected_attribution),
            "runtime_attribution": expected_attribution,
        }
        and profile_claim
        == {
            "schema": "aragorn/runtime-capability-lease-claim/v1",
            "authority": "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "lease_digest": lease_digest,
            "submission_digest": canonical_digest(submission),
            "runtime_attribution_digest": canonical_digest(expected_attribution),
            "envelope_digest": canonical_digest(envelope),
            "request_digest": canonical_digest(request),
            "measured_action_digest": canonical_digest(expected_measured),
            "claimed_at_unix": lease["issued_at_unix"],
            "session_id": identifiers["session_id"],
            "run_id": identifiers["run_id"],
            "tool_call_id": hashed_tool_call,
            "target_name": _TARGET,
            "profile_pending": pending,
        },
        "profile claim or submission binding changed",
    )
    grant = inputs["grant"]
    _expect(
        claim["grant_digest"] == inputs["grant_digest"]
        and claim["lease_digest"] == lease_digest
        and lease["grant_digest"] == inputs["grant_digest"]
        and lease["submission_digest"] == canonical_digest(submission)
        and lease["runtime_attribution_digest"] == canonical_digest(attribution)
        and lease["request_digest"] == canonical_digest(request)
        and lease["runtime_profile_digest"] == profile["digest"]
        and lease["runtime_digest"] == _RUNTIME_DIGEST
        and lease["active_skill_digest"] == _SKILL_DIGEST
        and lease["sensor_digest"] == _SENSOR_DIGEST
        and lease["policy_digest"] == canonical_digest(inputs["policy"])
        and lease["policy_version"] == 1
        and lease["operation_digest"] == inputs["action"]["operation_digest"]
        and lease["path_digest"] == inputs["action"]["path_digest"]
        and lease["payload_digest"] == inputs["action"]["payload_digest"]
        and lease["max_actions"] == 1
        and re.fullmatch(r"[0-9a-f]{64}", lease["lease_nonce"])
        and grant["issued_at_unix"]
        <= request["issued_at_unix"]
        <= lease["issued_at_unix"]
        == profile_claim["claimed_at_unix"]
        < lease["expires_at_unix"]
        == request["expires_at_unix"]
        <= grant["expires_at_unix"],
        "lease is not exactly bound to the root grant and measured action",
    )
    health = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": _RUNTIME_DIGEST,
        "sensor_digest": _SENSOR_DIGEST,
        "epoch": 3,
        "status": "healthy",
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
    }
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": 3,
        "sensor_digest": _SENSOR_DIGEST,
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
        "active": active,
        "measured_action": expected_measured,
    }
    broker_state = {
        "schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 2,
        "minimum_mediator_health_epoch": 3,
        "consumed": [
            {
                "request_digest": canonical_digest(request),
                "observation_digest": canonical_digest(observation),
                "expires_at_unix": request["expires_at_unix"],
            }
        ],
        "effect_journal": None,
    }
    replay = evaluate_runtime_action(
        request,
        inputs["policy"],
        now_unix=now,
        active=active,
        measured_action=expected_measured,
        revocations=inputs["refreshed"]["revocations"],
        minimum_revocation_generation=2,
        mediator_health=health,
        minimum_mediator_health_epoch=3,
    )
    _expect(
        result == retained_result
        and result["request_digest"] == canonical_digest(request)
        and result["observation_digest"] == canonical_digest(observation)
        and result["decision"] == replay
        and scenario["broker_state"]
        == {"digest": canonical_digest(broker_state), "document": broker_state},
        "request, policy decision, or broker state replay changed",
    )
    receipt = scenario["profile_receipt"]
    expected_receipt = {
        "schema": "aragorn/runtime-process-profile-receipt/v1",
        "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "submission_digest": canonical_digest(submission),
        "runtime_attribution_digest": canonical_digest(attribution),
        "runtime_attribution": attribution,
        "broker_result_digest": canonical_digest(result),
        "broker_result": result,
    }
    _expect(
        receipt
        == {"digest": canonical_digest(expected_receipt), "document": expected_receipt},
        "profile receipt changed",
    )
    expected_profile_result = {
        "schema": "aragorn/runtime-capability-lease-result/v1",
        "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": lease_digest,
        "submission_digest": canonical_digest(submission),
        "profile_receipt_digest": receipt["digest"],
        "broker_result_digest": canonical_digest(result),
        "verdict": "ALLOW",
        "effect_status": "CREATED",
    }
    _expect(
        state_document["result"]
        == {
            "schema": "aragorn/runtime-capability-grant-result/v1",
            "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": inputs["grant_digest"],
            "lease_digest": lease_digest,
            "profile_result": expected_profile_result,
        },
        "terminal grant result changed",
    )
    available = {
        "schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": inputs["grant_digest"],
        "status": "AVAILABLE",
        "claim": None,
        "result": None,
    }
    before_controls = {
        "policy.json": canonical_digest(inputs["policy"]),
        "revocations.json": canonical_digest(inputs["refreshed"]["revocations"]),
        "health.json": canonical_digest(inputs["refreshed"]["health"]),
        "observation.json": canonical_digest(inputs["refreshed"]["observation"]),
        "state.json": canonical_digest(inputs["initial"]["state"]),
        "capability-grant-state.json": canonical_digest(available),
    }
    _expect(
        scenario["before"]
        == {
            "controls": before_controls,
            "grant_state": {
                "digest": canonical_digest(available),
                "document": available,
            },
            "protected_entries": [],
            "staging_entries": [],
            "profile_pending_exists": False,
            "profile_receipt_exists": False,
        },
        "positive scenario did not reuse the clean AVAILABLE grant",
    )
    after_controls = {
        "policy.json": canonical_digest(inputs["policy"]),
        "revocations.json": canonical_digest(inputs["refreshed"]["revocations"]),
        "health.json": canonical_digest(health),
        "observation.json": canonical_digest(observation),
        "state.json": canonical_digest(broker_state),
        "capability-grant-state.json": state["digest"],
    }
    _expect(
        scenario["control_after"] == after_controls, "positive control state changed"
    )
    _verify_terminal_files(scenario, ids, deployment, inputs, state, receipt)
    raw_drivers = b"\n".join(
        canonical_json(document["scenarios"][name]["driver"])
        for name in ("issuer_unavailable", "one_shot_allow")
    )
    forbidden = (
        grant["grant_id"],
        inputs["grant_digest"],
        lease["lease_nonce"],
        lease["authority"],
        lease["schema"],
    )
    _expect(
        scenario["runtime_facing_grant_or_lease_absent"] is True
        and all(value.encode() not in raw_drivers for value in forbidden),
        "runtime-facing output exposed grant or lease authority",
    )
    _expect(0 <= recorded_at - now < 10, "recording time changed")


def _verify_terminal_files(
    scenario: Mapping[str, Any],
    ids: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
    state: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    target = scenario["target"]
    grant_file = scenario["grant_state_file"]
    receipt_file = scenario["profile_receipt_file"]
    _file(
        target,
        path=f"{_PROTECTED}/{_TARGET}",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _file(
        grant_file,
        path=f"{_CONTROL}/capability-grant-state.json",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _file(
        receipt_file,
        path=f"{_CONTROL}/profile-receipt.json",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _expect(
        target["digest"] == inputs["action"]["payload_digest"]
        and target["bytes"] == len(_PAYLOAD)
        and target["stat"]["device"] == deployment["protected"]["device"]
        and grant_file["digest"] == state["digest"]
        and grant_file["bytes"] == len(canonical_json(state["document"]))
        and grant_file["stat"]["device"] == deployment["control"]["device"]
        and receipt_file["digest"] == receipt["digest"]
        and receipt_file["bytes"] == len(canonical_json(receipt["document"]))
        and receipt_file["stat"]["device"] == deployment["control"]["device"],
        "terminal target, grant state, or receipt file changed",
    )


def _verify_peer_traces(
    document: Mapping[str, Any], ids: Mapping[str, Any], deployment: Mapping[str, Any]
) -> None:
    traces = document["peer_trace"]
    _expect(
        set(traces)
        == {"issuer_unavailable_broker", "one_shot_broker", "one_shot_sensor"},
        "peer trace closure changed",
    )
    contracts = {
        "issuer_unavailable_broker": (
            deployment["negative_broker_pid"],
            [],
            [],
        ),
        "one_shot_broker": (
            deployment["positive_broker_pid"],
            ["accept"],
            [
                {
                    "pid": deployment["positive_sensor_pid"],
                    "uid": ids["sensor_uid"],
                    "gid": ids["sensor_gid"],
                }
            ],
        ),
        "one_shot_sensor": (
            deployment["positive_sensor_pid"],
            ["accept", "connect"],
            [
                {
                    "pid": deployment["positive_gateway_pid"],
                    "uid": ids["runtime_uid"],
                    "gid": ids["runtime_gid"],
                },
                {
                    "pid": deployment["positive_broker_pid"],
                    "uid": ids["broker_uid"],
                    "gid": ids["runtime_gid"],
                },
            ],
        ),
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
        r"(?P<service>\d+)\s+connect\((?P<fd>\d+), "
        r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
    )
    detached_pattern = re.compile(
        r"(?P<service>\d+)\s+accept4\(\d+,\s+<detached \.\.\.>"
    )
    for name, (service_pid, expected_kinds, expected_peers) in contracts.items():
        trace = traces[name]
        raw = trace["raw"]
        lines = raw.splitlines()
        peers: list[dict[str, int]] = []
        kinds: list[str] = []
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
            kinds.append("accept" if accept is not None else "connect")
        detached = detached_pattern.fullmatch(lines[-1]) if lines else None
        _expect(
            set(trace) == {"peer_credentials", "raw", "raw_digest"}
            and trace["raw_digest"]
            == "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
            and all(line.startswith(f"{service_pid} ") for line in lines)
            and raw.count("SO_PEERCRED") == len(peers)
            and completed_channels == len(peers)
            and kinds == expected_kinds
            and peers == trace["peer_credentials"] == expected_peers
            and detached is not None
            and int(detached["service"]) == service_pid,
            f"kernel peer chain changed: {name}",
        )


def _verify_timing(document: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
    timing = document["timing"]
    scenarios = document["scenarios"]
    _expect(
        set(timing)
        == {
            "client_deadline_ms",
            "grant_lifetime_seconds",
            "negative_driver_elapsed_ns",
            "positive_driver_elapsed_ns",
            "sensor_deadline_ms",
        }
        and timing["client_deadline_ms"] == 750
        and timing["sensor_deadline_ms"] == 500
        and timing["grant_lifetime_seconds"]
        == inputs["grant"]["expires_at_unix"] - inputs["grant"]["issued_at_unix"]
        == 241
        and timing["negative_driver_elapsed_ns"]
        == scenarios["issuer_unavailable"]["driver_elapsed_ns"]
        and timing["positive_driver_elapsed_ns"]
        == scenarios["one_shot_allow"]["driver_elapsed_ns"]
        and _positive(timing["negative_driver_elapsed_ns"])
        and _positive(timing["positive_driver_elapsed_ns"]),
        "bounded timing record changed",
    )


def _provider_responses(
    scenario_id: str, tool_call_id: str, allowed: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
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
            "id": f"chatcmpl-{scenario_id}-tool",
        }
    ]
    code = (
        "ARAGORN_RUNTIME_ACTION_ALLOW_CREATED"
        if allowed
        else "ARAGORN_RUNTIME_ACTION_CLIENT_ERROR_NOT_SUBMITTED"
    )
    final = [
        {
            **common,
            "choices": [
                {
                    "delta": {"content": code, "role": "assistant"},
                    "finish_reason": None,
                    "index": 0,
                }
            ],
            "id": f"chatcmpl-{scenario_id}-final",
        },
        {
            **common,
            "choices": [{"delta": {}, "finish_reason": "stop", "index": 0}],
            "id": f"chatcmpl-{scenario_id}-final",
            "usage": {"completion_tokens": 1, "prompt_tokens": 1, "total_tokens": 2},
        },
    ]
    return tool, final


def _driver_input(scenario_id: str, verdict: str, effect: str) -> dict[str, Any]:
    return {
        "schema": "aragorn/openclaw-profile-driver-input/v1",
        "scenario": {
            "id": scenario_id,
            "target_name": _TARGET,
            "content": _PAYLOAD.decode(),
            "expected_verdict": verdict,
            "expected_effect_status": effect,
        },
    }


def _loaded_command(raw: object, command: list[str]) -> bool:
    if not isinstance(raw, str) or "\n" in raw:
        return False
    prefix = f"{{ path={command[0]} ; argv[]={' '.join(command)} ; ignore_errors=no ; "
    return (
        raw.startswith(prefix)
        and re.fullmatch(
            re.escape(prefix)
            + r"start_time=\[[^\]\n]+\] ; stop_time=\[[^\]\n]+\] ; "
            + r"pid=[0-9]+ ; code=\(null\) ; status=0/0 \}",
            raw,
        )
        is not None
    )


def _zero_security(value: Mapping[str, Any]) -> bool:
    capabilities = value.get("capabilities")
    return (
        set(value) == {"capabilities", "no_new_privileges"}
        and value["no_new_privileges"] == 1
        and isinstance(capabilities, Mapping)
        and set(capabilities) == {"CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"}
        and all(
            item == {"hex": "0000000000000000", "value": 0}
            for item in capabilities.values()
        )
    )


def _no_effects() -> dict[str, Any]:
    return {
        "frontend_exists": False,
        "target_exists": False,
        "profile_pending_exists": False,
        "profile_receipt_exists": False,
        "protected_entries": [],
        "staging_entries": [],
    }


def _expect(condition: object, message: str) -> None:
    if condition is not True:
        raise AdmissionEvidenceError(message)
