"""Verify the retained bounded P3.4a Linux process-profile artifact."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import evaluate_runtime_action
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from .runtime_action_systemd_evidence import _SOURCES as _V1_SOURCES
from .runtime_action_systemd_evidence import (
    _contains_float,
    _positive,
    _positive_text,
    _same_json,
)
from .runtime_process_profile import (
    ATTRIBUTION_AUTHORITY,
    ATTRIBUTION_SCHEMA,
    runtime_process_profile,
)

_SCHEMA = "aragorn/runtime-process-profile-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_SYNTHETIC_LINUX_SYSTEMD_PROCESS_PROFILE_ONLY_"
    "NOT_SEMANTIC_CAUSATION_AUTHORITY"
)
_EVIDENCE_DIGEST: str | None = (
    "sha256:5b389782e6dcafb65ed08279f1cbe87b3e8987d3d4a5ddf200f39d5db9128788"
)
_SYSTEMD_BASE_IMAGE_ID = (
    "sha256:1a4fe98562882fca13e0349f84d9eb4c38b5361a1289da2a0bfa8852ccfdbc56"
)
_LIMITATIONS = [
    "SINGLE_SYNTHETIC_CREATE_PROFILE_ONLY",
    "ROOT_PROVISIONED_SKILL_PATH_NOT_OPENCLAW_CONSUMPTION_PROOF",
    "RUNTIME_DIGEST_IS_POLICY_IDENTITY_NOT_EXECUTABLE_IDENTITY",
    "SENSOR_ADOPTS_RUNTIME_FS_CREDENTIALS_FOR_CROSS_UID_PROC_MEASUREMENT",
    "SENSOR_BOOTSTRAP_IDENTITY_CAPABILITIES_ARE_DROPPED_BEFORE_ACCEPT",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "BEFORE_AFTER_PROCESS_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_PER_MESSAGE_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_PINNED_OPENCLAW_RUNTIME_COMPOSITION",
    "NO_SEMANTIC_OR_CAUSAL_SKILL_ATTRIBUTION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DECISION = {
    "status": "P3_4A_SYNTHETIC_SYSTEMD_OBSERVED",
    "profiled_allow_created_observed": True,
    "broker_profile_receipt_observed": True,
    "wrong_cgroup_no_effect_observed": True,
    "openclaw_consumption_observed": False,
    "semantic_causation_observed": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "phase3_exit_eligible": False,
    "edr_claim_eligible": False,
    "public_release_eligible": False,
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAMESPACE = re.compile(r"(?:mnt|net):\[[1-9][0-9]*\]\Z")
_ARTIFACTS = {
    **_V1_SOURCES,
    "/src/benchmark/runtime-process-profile-systemd/SKILL.md": (
        "/opt/aragorn/runtime-profile/SKILL.md"
    ),
    "/src/benchmark/runtime-process-profile-systemd/aragorn-runtime-profile-client.service": (
        "/usr/lib/systemd/system/aragorn-runtime-profile-client.service"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-service-v2.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v2.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service-v2.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v2.py"
    ),
    "/src/packaging/systemd/aragorn-runtime-profile-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-profile-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-profile-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-profile-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "runtime_action_broker_v2.py",
            "runtime_action_observation_publisher_v2.py",
            "runtime_action_service_v2.py",
            "runtime_observation_service_v2.py",
            "runtime_process_profile.py",
        )
    },
}
_COLLECTORS = {
    "base_installer": ("/src/packaging/install-runtime-action-host.sh", "0755"),
    "base_probe": ("/src/scripts/runtime_action_systemd_probe.py", "0644"),
    "dockerfile": (
        "/src/benchmark/runtime-process-profile-systemd/Dockerfile",
        "0444",
    ),
    "installer": ("/src/packaging/install-runtime-profile-host.sh", "0755"),
    "probe": ("/src/scripts/runtime_process_profile_systemd_probe.py", "0555"),
    "recipe": ("/src/scripts/capture_runtime_process_profile_systemd.sh", "0555"),
}
_UNIT_FIELDS = {
    "ActiveState",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
    "ControlGroup",
    "DropInPaths",
    "ExecMainStatus",
    "ExecStart",
    "FragmentDigest",
    "FragmentPath",
    "FragmentResolvedPath",
    "Group",
    "InvocationID",
    "MainPID",
    "NoNewPrivileges",
    "Result",
    "SubState",
    "SupplementaryGroups",
    "User",
}
_PROCESS_FIELDS = {
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
_CONTROL_FILES = {
    "health.json",
    "observation.json",
    "policy.json",
    "profile-receipt.json",
    "revocations.json",
    "state.json",
}
_EFFECTS = {
    "allow": (
        "profile-allowed.txt",
        b"Aragorn P3.4a profiled create\n",
    ),
    "wrong_cgroup": (
        "profile-wrong-cgroup.txt",
        b"Aragorn P3.4a wrong-cgroup block\n",
    ),
}
_CREATE_OPERATION_DIGEST = canonical_digest(
    {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
)


def verify_runtime_process_profile_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.4a without granting semantic, RUN, EDR, or release authority."""

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
                "profile",
                "recorded_at",
                "scenarios",
                "schema",
            },
            "top-level fields changed",
        )
        _expect(canonical_digest(document) == pin, "retained evidence changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(_same_json(document["decision"], _DECISION), "claim ceiling changed")
        recorded_at = _time(document["recorded_at"]).timestamp()
        installed = _verify_artifacts_and_collectors(document)
        identities = _verify_environment(document)
        profile = _verify_profile_and_credentials(document, installed)
        _verify_deployment(document, identities, installed, profile)
        inputs = _verify_inputs(document, profile, recorded_at)
        allow = _verify_allow(document, identities, profile, inputs)
        _verify_wrong_cgroup(document, identities, profile, inputs, allow)
    except AdmissionEvidenceError:
        raise
    except (
        IndexError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
        RuntimeActionObservationPublisherError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime process-profile systemd evidence: {exc}"
        ) from exc


def _verify_artifacts_and_collectors(
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
        mode = (
            "0444"
            if installed_path.endswith(
                ("/SKILL.md", "aragorn-runtime-profile-client.service")
            )
            else "0755"
            if installed_path.startswith("/usr/libexec/")
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
            and item["installed_path"] == installed_path
            and item["source_bytes"] == item["installed_bytes"]
            and _positive(item["source_bytes"])
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
        identity = (
            item["installed_stat"]["device"],
            item["installed_stat"]["inode"],
        )
        _expect(identity not in identities, "installed artifacts alias")
        identities.add(identity)

    collector = document["collector"]
    _expect(set(collector) == set(_COLLECTORS), "collector closure changed")
    for name, (path, mode) in _COLLECTORS.items():
        _file(collector[name], path=path, uid=0, gid=0, mode=mode)
    return installed


def _verify_environment(document: Mapping[str, Any]) -> dict[str, int]:
    environment = document["environment"]
    _expect(
        set(environment)
        == {
            "architecture",
            "capture_identity",
            "container_id",
            "kernel_release",
            "platform",
            "python",
            "systemd",
            "systemd_verify",
        }
        and environment["platform"] == "linux"
        and environment["architecture"] == "aarch64"
        and environment["python"] == "3.12.13"
        and re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[-+._0-9A-Za-z]*", environment["kernel_release"]
        )
        and environment["systemd"] == "systemd 252 (252.39-1~deb12u2)"
        and re.fullmatch(r"[0-9a-f]{12}", environment["container_id"])
        and environment["systemd_verify"]
        == {"exit_code": 0, "stdout": "", "stderr": ""},
        "qualification environment changed",
    )
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
        and _positive(capture["start_time_ticks"]),
        "collector identity changed",
    )
    _mount_namespace(capture["mount_namespace"])

    harness = document["harness"]
    outer = harness["document"]
    _expect(
        set(harness) == {"digest", "document"}
        and harness["digest"] == canonical_digest(outer)
        and set(outer)
        == {
            "container_id",
            "host_config",
            "image_id",
            "image_reference",
            "platform",
            "profile_label",
            "schema",
            "systemd_base_image_id",
        }
        and outer["schema"] == "aragorn/runtime-process-profile-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", outer["container_id"])
        and outer["container_id"].startswith(environment["container_id"])
        and _digest(outer["image_id"])
        and outer["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE_ID
        and outer["image_reference"] == "aragorn-p34a-runtime-profile-systemd"
        and outer["platform"] == "linux"
        and outer["profile_label"] == "p3.4a"
        and outer["host_config"]
        == {
            "binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
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
        and capture["cgroup"] == f"/docker/{outer['container_id']}/init.scope",
        "outer harness changed",
    )

    values: dict[str, int] = {}
    identities = document["identities"]
    _expect(set(identities) == {"broker", "runtime", "sensor"}, "identity set changed")
    for name in identities:
        value = identities[name]
        _expect(
            set(value) == {"uid", "gid"}
            and _positive(value["uid"])
            and _positive(value["gid"]),
            f"identity changed: {name}",
        )
        values[f"{name}_uid"] = value["uid"]
        values[f"{name}_gid"] = value["gid"]
    _expect(
        len({values[f"{name}_uid"] for name in identities}) == 3
        and values["broker_gid"] == values["runtime_gid"]
        and values["sensor_gid"] != values["runtime_gid"],
        "principal identities overlap",
    )
    return values


def _verify_profile_and_credentials(
    document: Mapping[str, Any], installed: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    profile = document["profile"]
    _expect(
        set(profile) == {"digest", "document", "executable", "skill"},
        "profile fields changed",
    )
    parsed = runtime_process_profile(profile["document"])
    _expect(profile["digest"] == parsed.digest, "profile digest changed")
    skill = profile["skill"]
    executable = profile["executable"]
    _file(
        skill,
        path=str(parsed.skill_path),
        uid=0,
        gid=0,
        mode="0444",
    )
    _file(
        executable,
        path="/usr/local/bin/python3.12",
        uid=0,
        gid=0,
        mode="0755",
    )
    retained_skill = installed[str(parsed.skill_path)]
    _expect(
        skill
        == {
            "bytes": retained_skill["installed_bytes"],
            "digest": retained_skill["installed_digest"],
            "path": retained_skill["installed_path"],
            "stat": retained_skill["installed_stat"],
        }
        and executable["digest"] == parsed.executable_digest,
        "profile files are not bound to the installed closure",
    )

    credentials = document["credentials"]
    _expect(set(credentials) == {"broker", "sensor"}, "credential set changed")
    for value in credentials.values():
        _expect(
            set(value) == {"digest", "document"}
            and value["digest"] == canonical_digest(value["document"]),
            "credential digest changed",
        )
    broker = credentials["broker"]["document"]
    sensor = credentials["sensor"]["document"]
    _expect(
        broker
        == {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": parsed.runtime_digest,
            "runtime_profile_digest": parsed.digest,
        }
        and set(sensor) == {"schema", "sensor_digest", "runtime_profile"}
        and sensor["schema"] == "aragorn/runtime-observation-binding/v2"
        and _digest(sensor["sensor_digest"])
        and sensor["runtime_profile"] == profile["document"],
        "credential/profile binding changed",
    )
    return {
        "digest": parsed.digest,
        "runtime_digest": parsed.runtime_digest,
        "cgroup": parsed.cgroup,
        "skill_path": str(parsed.skill_path),
        "skill_digest": skill["digest"],
        "executable_digest": parsed.executable_digest,
        "sensor_digest": sensor["sensor_digest"],
    }


def _verify_inputs(
    document: Mapping[str, Any], profile: Mapping[str, Any], recorded_at: float
) -> dict[str, Any]:
    inputs = document["inputs"]
    _expect(
        set(inputs)
        == {"actions", "control_baseline", "envelopes", "initial_controls", "policy"},
        "input fields changed",
    )
    controls = inputs["initial_controls"]
    baseline = inputs["control_baseline"]
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"}
        and set(baseline)
        == {
            "health.json",
            "observation.json",
            "policy.json",
            "revocations.json",
            "state.json",
        }
        and all(
            baseline[f"{name}.json"] == canonical_digest(value)
            for name, value in controls.items()
        )
        and inputs["policy"] == controls["policy"],
        "initial control binding changed",
    )
    policy = inputs["policy"]
    _expect(
        set(policy)
        == {
            "allow",
            "default",
            "id",
            "revocation_source_digest",
            "schema",
            "sensor_digest",
            "version",
        }
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and policy["id"] == "p3-4a-systemd-process-profile"
        and policy["default"] == "BLOCK"
        and policy["version"] == 1
        and policy["sensor_digest"] == profile["sensor_digest"]
        and _digest(policy["revocation_source_digest"])
        and isinstance(policy["allow"], list)
        and len(policy["allow"]) == 2,
        "policy changed",
    )
    health = controls["health"]
    revocations = controls["revocations"]
    observation = controls["observation"]
    state = controls["state"]
    _expect(
        health["schema"] == "aragorn/runtime-mediator-health/v1"
        and health["runtime_digest"] == profile["runtime_digest"]
        and health["sensor_digest"] == profile["sensor_digest"]
        and health["status"] == "healthy"
        and observation["schema"] == "aragorn/runtime-action-observation/v1"
        and observation["sensor_digest"] == profile["sensor_digest"]
        and revocations["schema"] == "aragorn/runtime-action-revocations/v1"
        and revocations["skill_digests"] == []
        and state
        == {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
        },
        "initial controls changed",
    )

    actions = inputs["actions"]
    envelopes = inputs["envelopes"]
    protected = document["deployment"]["directories"]["protected"]
    _expect(
        set(actions) == set(envelopes) == {"allow", "wrong_cgroup"},
        "scenario inputs changed",
    )
    policy_rules = []
    payloads: dict[str, bytes] = {}
    for name, (target, expected_payload) in _EFFECTS.items():
        action = actions[name]
        envelope = envelopes[name]
        _expect(
            set(action) == {"operation_digest", "path_digest", "payload_digest"}
            and all(_digest(value) for value in action.values())
            and set(envelope) == {"schema", "effect", "request"}
            and envelope["schema"] == "aragorn/runtime-action-broker-request/v1",
            f"action input changed: {name}",
        )
        effect = envelope["effect"]
        request = envelope["request"]
        _expect(
            set(effect) == {"operation", "payload_base64", "schema", "target_name"}
            and effect["schema"] == "aragorn/runtime-create-file/v1"
            and effect["operation"] == "create"
            and effect["target_name"] == target
            and set(request)
            == {
                "active_skill_digest",
                "authority",
                "expires_at_unix",
                "issued_at_unix",
                "operation_digest",
                "path_digest",
                "payload_digest",
                "policy_digest",
                "policy_version",
                "run_id",
                "runtime_digest",
                "schema",
                "session_id",
                "tool_call_id",
            }
            and request["schema"] == "aragorn/runtime-action-request/v1"
            and request["authority"]
            == "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
            and request["runtime_digest"] == profile["runtime_digest"]
            and request["active_skill_digest"] == profile["skill_digest"]
            and request["session_id"] == "session-p3-4a"
            and request["run_id"] == "run-p3-4a"
            and request["tool_call_id"]
            == ("call-allow" if name == "allow" else "call-wrong-cgroup")
            and request["policy_digest"] == canonical_digest(policy)
            and request["policy_version"] == policy["version"]
            and all(request[key] == action[key] for key in action)
            and request["issued_at_unix"] <= recorded_at <= request["expires_at_unix"]
            and request["expires_at_unix"] - request["issued_at_unix"] == 5,
            f"request input changed: {name}",
        )
        try:
            payload = base64.b64decode(effect["payload_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AdmissionEvidenceError(f"payload is invalid: {name}") from exc
        _expect(
            payload == expected_payload
            and action
            == {
                "operation_digest": _CREATE_OPERATION_DIGEST,
                "path_digest": canonical_digest(
                    {
                        "schema": "aragorn/runtime-protected-path/v1",
                        "root_device": protected["device"],
                        "root_inode": protected["inode"],
                        "target_name": target,
                    }
                ),
                "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            },
            f"derived action digest changed: {name}",
        )
        payloads[name] = payload
        policy_rules.append(
            {
                "runtime_digest": profile["runtime_digest"],
                "active_skill_digest": profile["skill_digest"],
                **action,
            }
        )
    _expect(policy["allow"] == policy_rules, "policy/action binding changed")
    _verify_initial_controls(
        controls,
        policy,
        profile,
        actions["allow"],
        recorded_at,
        envelopes,
    )
    return {
        "actions": actions,
        "controls": controls,
        "envelopes": envelopes,
        "payloads": payloads,
        "policy": policy,
        "recorded_at": recorded_at,
    }


def _verify_initial_controls(
    controls: Mapping[str, Any],
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    allow_action: Mapping[str, str],
    recorded_at: float,
    envelopes: Mapping[str, Any],
) -> None:
    now = controls["health"]["observed_at_unix"]
    active = {
        "schema": "aragorn/runtime-active-context/v1",
        "runtime_digest": profile["runtime_digest"],
        "session_id": "session-p3-4a",
        "run_id": "run-p3-4a",
        "tool_call_id": "call-initial",
        "active_skill_digest": profile["skill_digest"],
    }
    _expect(
        isinstance(now, int)
        and not isinstance(now, bool)
        and 0 < now <= recorded_at
        and all(
            envelope["request"]["issued_at_unix"] == now
            for envelope in envelopes.values()
        )
        and controls["revocations"]
        == {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": policy["revocation_source_digest"],
            "generation": 1,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        }
        and controls["health"]
        == {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": profile["runtime_digest"],
            "sensor_digest": profile["sensor_digest"],
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
            "sensor_digest": profile["sensor_digest"],
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": active,
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **{key: value for key, value in active.items() if key != "schema"},
                **allow_action,
            },
        },
        "initial control semantics changed",
    )


def _verify_deployment(
    document: Mapping[str, Any],
    ids: Mapping[str, int],
    installed: Mapping[str, Mapping[str, Any]],
    profile: Mapping[str, Any],
) -> None:
    deployment = document["deployment"]
    _expect(
        set(deployment) == {"directories", "processes", "security", "sockets", "units"},
        "deployment fields changed",
    )
    directories = deployment["directories"]
    _expect(
        set(directories) == {"control", "protected", "root", "runtime", "staging"},
        "directory set changed",
    )
    directory_contracts = {
        "root": (0, 0, "0755", 1),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710", 1),
        "protected": (ids["broker_uid"], ids["runtime_gid"], "0710", 1),
        "staging": (ids["broker_uid"], ids["broker_uid"], "0700", 1),
        "runtime": (ids["sensor_uid"], ids["runtime_gid"], "0750", 2),
    }
    for name, (uid, gid, mode, nlink) in directory_contracts.items():
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
    _expect(
        sockets["backend"]["device"] == directories["control"]["device"]
        and sockets["frontend"]["device"] == directories["runtime"]["device"],
        "socket parent device changed",
    )
    _metadata(
        sockets["frontend"],
        kind="socket",
        uid=ids["sensor_uid"],
        gid=ids["runtime_gid"],
        mode="0660",
        size=0,
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
        "/run/credentials/aragorn-runtime-profile-observation-publisher.service/observation-binding",
    ]
    client_command = [
        "/bin/sh",
        "-c",
        "while [ ! -e /run/aragorn-runtime-profile-go ]; do sleep 0.05; done; exec /usr/bin/python3.12 -I -S -B /src/scripts/runtime_process_profile_systemd_probe.py client /run/aragorn-runtime-profile-request.json",
    ]
    units = deployment["units"]
    _expect(
        set(units) == {"broker", "sensor", "client_started", "client_completed"},
        "unit set changed",
    )
    contracts = {
        "broker": (
            "aragorn-runtime-profile-action-broker.service",
            "aragorn-broker",
            "aragorn-runtime",
            "aragorn-sensor",
            "",
            broker_command,
            "active",
            "running",
        ),
        "sensor": (
            "aragorn-runtime-profile-observation-publisher.service",
            "aragorn-sensor",
            "aragorn-sensor",
            "aragorn-runtime",
            "cap_setgid cap_setuid cap_setpcap",
            sensor_command,
            "active",
            "running",
        ),
        "client_started": (
            "aragorn-runtime-profile-client.service",
            "aragorn-runtime",
            "aragorn-runtime",
            "",
            "",
            client_command,
            "active",
            "running",
        ),
        "client_completed": (
            "aragorn-runtime-profile-client.service",
            "aragorn-runtime",
            "aragorn-runtime",
            "",
            "",
            client_command,
            "inactive",
            "dead",
        ),
    }
    for name, contract in contracts.items():
        service, user, group, supplementary, capabilities, command, active, sub = (
            contract
        )
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
            and unit["ActiveState"] == active
            and unit["SubState"] == sub
            and unit["Result"] == "success"
            and unit["ExecMainStatus"] == "0"
            and f"path={command[0]} ; argv[]={' '.join(command)} ;"
            in unit["ExecStart"],
            f"loaded unit contract changed: {name}",
        )
    _expect(
        units["client_started"]["ControlGroup"] == profile["cgroup"]
        and units["client_completed"]["MainPID"] == "0"
        and units["client_completed"]["ControlGroup"] == "",
        "client unit lifecycle changed",
    )

    processes = deployment["processes"]
    _expect(set(processes) == {"broker", "sensor"}, "service process set changed")
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
        uids=[
            ids["sensor_uid"],
            ids["sensor_uid"],
            ids["sensor_uid"],
            ids["runtime_uid"],
        ],
        gids=[
            ids["sensor_gid"],
            ids["sensor_gid"],
            ids["sensor_gid"],
            ids["runtime_gid"],
        ],
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _expect(
        len(
            {
                processes[name][namespace]
                for name in processes
                for namespace in ("mount_namespace", "network_namespace")
            }
        )
        == 4,
        "service namespaces overlap",
    )

    security = deployment["security"]
    _expect(
        set(security)
        == {
            "broker",
            "sensor",
            "sensor_bootstrap_capabilities",
            "sensor_filesystem_identity",
        },
        "security fields changed",
    )
    for name in ("broker", "sensor"):
        value = security[name]
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
    sensor_process = processes["sensor"]
    _expect(
        security["sensor_filesystem_identity"]
        == {
            "real_uid": ids["sensor_uid"],
            "effective_uid": ids["sensor_uid"],
            "saved_uid": ids["sensor_uid"],
            "filesystem_uid": ids["runtime_uid"],
            "real_gid": ids["sensor_gid"],
            "effective_gid": ids["sensor_gid"],
            "saved_gid": ids["sensor_gid"],
            "filesystem_gid": ids["runtime_gid"],
        }
        and security["sensor_filesystem_identity"]["filesystem_uid"]
        == sensor_process["uids"][3]
        and security["sensor_filesystem_identity"]["filesystem_gid"]
        == sensor_process["gids"][3]
        and security["sensor_bootstrap_capabilities"]
        == {
            "names": ["CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP"],
            "purpose": "adopt runtime FS credentials then irreversibly drop all caps",
            "live_after_start": [],
        },
        "runtime measurement security contract changed",
    )


def _verify_allow(
    document: Mapping[str, Any],
    ids: Mapping[str, int],
    profile: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    scenario = document["scenarios"]["profiled_allow"]
    _expect(
        set(scenario)
        == {
            "client",
            "control_after",
            "profile_pending_exists",
            "receipt",
            "receipt_file",
            "status",
            "target",
        }
        and scenario["status"] == "PASS"
        and scenario["profile_pending_exists"] is False,
        "profiled allow fields or pending state changed",
    )
    envelope = inputs["envelopes"]["allow"]
    client_record = scenario["client"]
    client = _client(
        client_record,
        ids,
        envelope,
        expected_sensor_pid=document["deployment"]["processes"]["sensor"]["pid"],
        request_path="/run/aragorn-runtime-profile-request.json",
        expected_outcome="RESPONSE",
    )
    _expect(
        client["cgroup"] == profile["cgroup"]
        and client["pid"]
        == int(document["deployment"]["units"]["client_started"]["MainPID"]),
        "allowed client process identity changed",
    )
    controls = scenario["control_after"]
    _expect(set(controls) == _CONTROL_FILES, "allow control snapshot changed")

    response = client_record["response"]
    request = envelope["request"]
    decision = response["decision"]
    _expect(
        set(response)
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
        and response["schema"] == "aragorn/runtime-action-broker-result/v1"
        and response["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and response["verdict"] == "ALLOW"
        and response["reason_codes"] == []
        and response["effect_status"] == "CREATED"
        and response["target_name"] == envelope["effect"]["target_name"]
        and response["request_digest"] == canonical_digest(request)
        and response["observation_digest"] == controls["observation.json"]
        and set(decision)
        == {
            "active_context_digest",
            "authority",
            "evaluated_at_unix",
            "measured_action_digest",
            "mediator_health_digest",
            "mediator_health_epoch",
            "minimum_mediator_health_epoch",
            "minimum_revocation_generation",
            "policy_digest",
            "policy_version",
            "reason_codes",
            "request_digest",
            "revocation_generation",
            "revocation_snapshot_digest",
            "schema",
            "verdict",
        }
        and decision["schema"] == "aragorn/runtime-action-decision/v1"
        and decision["authority"]
        == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and decision["verdict"] == "ALLOW"
        and decision["reason_codes"] == []
        and decision["request_digest"] == response["request_digest"]
        and decision["policy_digest"] == canonical_digest(inputs["policy"])
        and decision["policy_digest"] == controls["policy.json"]
        and decision["revocation_snapshot_digest"] == controls["revocations.json"]
        and decision["mediator_health_digest"] == controls["health.json"],
        "allow result binding changed",
    )

    now = decision["evaluated_at_unix"]
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
        **inputs["actions"]["allow"],
    }
    initial = inputs["controls"]
    health = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": profile["runtime_digest"],
        "sensor_digest": profile["sensor_digest"],
        "epoch": 2,
        "status": "healthy",
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
    }
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": 2,
        "sensor_digest": profile["sensor_digest"],
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
    expected_controls = {
        "policy.json": canonical_digest(inputs["policy"]),
        "revocations.json": canonical_digest(initial["revocations"]),
        "health.json": canonical_digest(health),
        "observation.json": canonical_digest(observation),
        "state.json": canonical_digest(state),
    }
    replay = evaluate_runtime_action(
        request,
        inputs["policy"],
        now_unix=now,
        active=active,
        measured_action=measured,
        revocations=initial["revocations"],
        minimum_revocation_generation=state["minimum_revocation_generation"],
        mediator_health=health,
        minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"],
    )
    _expect(
        isinstance(now, int)
        and not isinstance(now, bool)
        and request["issued_at_unix"] <= now < request["expires_at_unix"]
        and now <= inputs["recorded_at"]
        and decision == replay
        and all(controls[name] == digest for name, digest in expected_controls.items()),
        "deterministic allow transition replay changed",
    )

    receipt = scenario["receipt"]
    receipt_document = receipt["document"]
    attribution = receipt_document["runtime_attribution"]
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
        and receipt_document["schema"] == "aragorn/runtime-process-profile-receipt/v1"
        and receipt_document["authority"]
        == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and receipt_document["broker_result"] == response
        and receipt_document["broker_result_digest"] == canonical_digest(response)
        and receipt_document["runtime_attribution_digest"]
        == canonical_digest(attribution)
        and set(attribution)
        == {
            "active_skill_digest",
            "authority",
            "cgroup",
            "executable_digest",
            "gid",
            "mount_namespace",
            "pid",
            "profile_digest",
            "runtime_digest",
            "schema",
            "skill_path",
            "start_time_ticks",
            "uid",
        }
        and attribution["schema"] == ATTRIBUTION_SCHEMA
        and attribution["authority"] == ATTRIBUTION_AUTHORITY
        and attribution["profile_digest"] == profile["digest"]
        and attribution["runtime_digest"] == profile["runtime_digest"]
        and attribution["executable_digest"] == profile["executable_digest"]
        and attribution["active_skill_digest"] == profile["skill_digest"]
        and attribution["skill_path"] == profile["skill_path"]
        and attribution["cgroup"] == profile["cgroup"]
        and (attribution["pid"], attribution["uid"], attribution["gid"])
        == (client["pid"], ids["runtime_uid"], ids["runtime_gid"])
        and attribution["start_time_ticks"] == client["start_time_ticks"]
        and attribution["mount_namespace"] == client["mount_namespace"],
        "profile receipt attribution binding changed",
    )
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": profile["sensor_digest"],
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {key: client[key] for key in ("pid", "uid", "gid")},
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": attribution,
    }
    _expect(
        receipt_document["submission_digest"] == canonical_digest(submission),
        "receipt submission binding changed",
    )

    target = scenario["target"]
    receipt_file = scenario["receipt_file"]
    _file(
        target,
        path="/var/lib/aragorn-runtime-action/protected/profile-allowed.txt",
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
        target["digest"] == inputs["actions"]["allow"]["payload_digest"]
        and target["bytes"] == len(inputs["payloads"]["allow"])
        and target["stat"]["device"]
        == document["deployment"]["directories"]["protected"]["device"]
        and receipt_file["digest"] == receipt["digest"]
        and receipt_file["bytes"] == len(canonical_json(receipt_document))
        and receipt_file["stat"]["device"]
        == document["deployment"]["directories"]["control"]["device"]
        and controls["profile-receipt.json"] == receipt["digest"],
        "allow effect or receipt file changed",
    )
    return {"control_after": controls, "target_name": envelope["effect"]["target_name"]}


def _verify_wrong_cgroup(
    document: Mapping[str, Any],
    ids: Mapping[str, int],
    profile: Mapping[str, Any],
    inputs: Mapping[str, Any],
    allow: Mapping[str, Any],
) -> None:
    scenarios = document["scenarios"]
    _expect(
        set(scenarios) == {"profiled_allow", "wrong_cgroup"}, "scenario set changed"
    )
    wrong = scenarios["wrong_cgroup"]
    _expect(
        set(wrong)
        == {
            "actual_cgroup",
            "client",
            "control_after",
            "control_before",
            "expected_cgroup",
            "protected_entries",
            "staging_entries",
            "status",
            "target_exists",
        }
        and wrong["status"] == "PASS"
        and wrong["expected_cgroup"] == profile["cgroup"]
        and wrong["actual_cgroup"] != profile["cgroup"]
        and wrong["target_exists"] is False
        and wrong["protected_entries"] == [allow["target_name"]]
        and wrong["staging_entries"] == []
        and wrong["control_before"] == wrong["control_after"] == allow["control_after"]
        and set(wrong["control_before"]) == _CONTROL_FILES,
        "wrong-cgroup fail-closed state changed",
    )
    client_record = wrong["client"]
    client = _client(
        client_record,
        ids,
        inputs["envelopes"]["wrong_cgroup"],
        expected_sensor_pid=document["deployment"]["processes"]["sensor"]["pid"],
        request_path="/run/aragorn-runtime-profile-wrong-request.json",
        expected_outcome="PEER_CLOSED",
    )
    _expect(
        set(client_record)
        == {
            "client",
            "elapsed_ns",
            "errno",
            "error",
            "outcome",
            "request_bytes",
            "request_digest",
            "request_file_digest",
            "request_path",
            "server_peer",
        }
        and client_record["errno"] == 104
        and client_record["error"] == "ECONNRESET"
        and client["cgroup"] == wrong["actual_cgroup"]
        and "profile-pending.json" not in wrong["control_after"],
        "wrong-cgroup request did not fail before broker state or effect",
    )
    pids = {
        document["environment"]["capture_identity"]["pid"],
        document["deployment"]["processes"]["broker"]["pid"],
        document["deployment"]["processes"]["sensor"]["pid"],
        document["scenarios"]["profiled_allow"]["client"]["client"]["pid"],
        client["pid"],
    }
    _expect(len(pids) == 5, "process roles overlap")


def _client(
    record: Mapping[str, Any],
    ids: Mapping[str, int],
    envelope: Mapping[str, Any],
    *,
    expected_sensor_pid: int,
    request_path: str,
    expected_outcome: str,
) -> Mapping[str, Any]:
    client = record["client"]
    fields = {
        "client",
        "elapsed_ns",
        "outcome",
        "request_bytes",
        "request_digest",
        "request_file_digest",
        "request_path",
        "server_peer",
    }
    fields.add("response" if expected_outcome == "RESPONSE" else "errno")
    if expected_outcome != "RESPONSE":
        fields.add("error")
    _expect(
        set(record) == fields
        and set(client)
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
        and all(client[name] == ids["runtime_uid"] for name in ("uid", "euid"))
        and all(client[name] == ids["runtime_gid"] for name in ("gid", "egid"))
        and set(client["groups"]).issubset({ids["runtime_gid"]})
        and _positive(client["pid"])
        and _positive(client["start_time_ticks"])
        and _positive(record["elapsed_ns"])
        and record["outcome"] == expected_outcome
        and record["request_path"] == request_path
        and record["request_digest"] == canonical_digest(envelope)
        and record["request_file_digest"] == record["request_digest"]
        and record["request_bytes"] == len(canonical_json(envelope))
        and record["server_peer"]
        == {
            "pid": expected_sensor_pid,
            "uid": ids["sensor_uid"],
            "gid": ids["sensor_gid"],
        },
        "runtime client identity or request binding changed",
    )
    _mount_namespace(client["mount_namespace"])
    return client


def _process(
    value: Mapping[str, Any],
    *,
    unit: Mapping[str, Any],
    command: list[str],
    uids: list[int],
    gids: list[int],
    groups: list[int],
) -> None:
    _expect(
        set(value) == _PROCESS_FIELDS
        and value["cmdline"] == command
        and value["uids"] == uids
        and value["gids"] == gids
        and value["groups"] == groups
        and value["capabilities_effective"] == "0000000000000000"
        and value["no_new_privileges"] == 1
        and _positive(value["pid"])
        and str(value["pid"]) == unit["MainPID"]
        and _positive_text(value["start_time_ticks"])
        and _NAMESPACE.fullmatch(value["mount_namespace"]) is not None
        and _NAMESPACE.fullmatch(value["network_namespace"]) is not None,
        "service process changed",
    )


def _file(
    value: Mapping[str, Any], *, path: str, uid: int, gid: int, mode: str
) -> None:
    _expect(
        set(value) == {"bytes", "digest", "path", "stat"}
        and value["path"] == path
        and _positive(value["bytes"])
        and _digest(value["digest"]),
        f"file record changed: {path}",
    )
    _metadata(
        value["stat"], kind="file", uid=uid, gid=gid, mode=mode, size=value["bytes"]
    )


def _metadata(
    value: Mapping[str, Any],
    *,
    kind: str,
    uid: int,
    gid: int,
    mode: str,
    size: int | None,
    nlink: int | None = 1,
) -> None:
    _expect(
        set(value) == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and value["type"] == kind
        and value["uid"] == uid
        and value["gid"] == gid
        and value["mode"] == mode
        and (nlink is None or value["nlink"] == nlink)
        and (size is None or value["size"] == size)
        and _positive(value["nlink"])
        and isinstance(value["size"], int)
        and value["size"] >= 0
        and _positive(value["device"])
        and _positive(value["inode"]),
        f"{kind} metadata changed",
    )


def _mount_namespace(value: Mapping[str, Any]) -> None:
    _expect(
        set(value) == {"device", "inode"}
        and isinstance(value["device"], int)
        and value["device"] >= 0
        and _positive(value["inode"]),
        "mount namespace changed",
    )


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _expect(condition: object, message: str) -> None:
    if condition is not True:
        raise AdmissionEvidenceError(message)
