"""Verify the bounded P3.5b local-systemd revocation artifact."""

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
from .runtime_capability_openclaw_systemd_evidence import (
    _ARTIFACTS as _P35A_ARTIFACTS,
)
from .runtime_capability_openclaw_systemd_evidence import (
    _BROKER_COMMAND,
    _BROKER_SERVICE,
    _GATEWAY_COMMAND,
    _GATEWAY_FRAGMENT_DIGEST,
    _LEGACY_SERVICES,
    _OPERATION_DIGEST,
    _PAYLOAD,
    _PROTECTED,
    _SENSOR_COMMAND,
    _SENSOR_SERVICE,
    _TARGET,
    _verify_controls,
    _verify_runtime_and_profile,
    _verify_unit,
    _zero_security,
)
from .runtime_process_profile_openclaw_systemd_evidence import (
    _NODE,
    _NODE_DIGEST,
    _NODE_IMAGE,
    _OPENCLAW,
    _REVOCATION_SOURCE,
    _RUNTIME_DIGEST,
    _SENSOR_DIGEST,
    _SKILL_DIGEST,
    _SKILL_NAME,
    _SKILL_PATH,
    _SYSTEMD_BASE_IMAGE,
)
from .runtime_process_profile_systemd_evidence import (
    _PROCESS_FIELDS,
    _digest,
    _file,
    _metadata,
    _mount_namespace,
    _positive,
    _process,
)

_SCHEMA = "aragorn/runtime-revocation-openclaw-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_LOCAL_SYSTEMD_REVOCATION_PUBLICATION_ONLY_"
    "NOT_RUN_OR_EDR_AUTHORITY"
)
_RAW_DIGEST = "e60d5cc364f9cf378ee832eaa955119733d92a7dafb0fb83365e85eb4f9225c4"
_EVIDENCE_DIGEST = (
    "sha256:3751a1650b0f5caa49fa56ef412047f7965ecd06c659e46ca223715de5868e94"
)
_P35A_IMAGE = "sha256:12ac568f41c61f714a15f0648b99b0781cedc816a1d591c59de6ef015bcccb4e"
_P35B_IMAGE = "sha256:730b451086b74a4de9a0e5a335a7ded8ff5f1071dea8f1302afd56a38d06be9d"
_PUBLISHER_SERVICE = "aragorn-runtime-revocation-publisher.service"
_CONTROL = "/var/lib/aragorn-runtime-action/control"
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
_DECISION = {
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
    "publication",
    "recorded_at",
    "runtime",
    "scenario",
    "schema",
    "timing",
}
_ARTIFACTS = {
    **_P35A_ARTIFACTS,
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
_COLLECTORS = {
    "base_probe": (
        "/src/scripts/runtime_capability_openclaw_systemd_probe.py",
        "0555",
        "sha256:12b4b8169c7a84cf92197a6ea7756916e775902a29c5a4b65258e8d853780770",
    ),
    "capture_recipe": (
        "/src/scripts/capture_runtime_revocation_openclaw_systemd.sh",
        "0555",
        "sha256:29f37c81c73e05c5ede34075bc61f338642b23def24052acc9990bd9e2418799",
    ),
    "dockerfile": (
        "/src/benchmark/runtime-revocation-openclaw-systemd/Dockerfile",
        "0444",
        "sha256:4270b41b41060c87e88dd7d8718ee4dd863c006ad4ca2bbbfbae16f0ee277fd1",
    ),
    "driver": (
        "/src/benchmark/runtime-process-profile-openclaw-systemd/openclaw-profile-driver.mjs",
        "0555",
        "sha256:207e74377cf014ca07944b9a5f57d48baa6e41b6dbeba66873d793b2782946a6",
    ),
    "probe": (
        "/src/scripts/runtime_revocation_openclaw_systemd_probe.py",
        "0555",
        "sha256:7b008e3e3a19c44406809035bb9723d2ad6a4dbd8281682a0342d7bf67131186",
    ),
    "profile_helper": (
        "/src/scripts/runtime_process_profile_openclaw_systemd_probe.py",
        "0555",
        "sha256:48a1a901de3cfc09490d81effc41034c29ba06953b2bd296c8be1d2945c9bd69",
    ),
    "systemd_helper": (
        "/src/scripts/runtime_process_profile_systemd_probe.py",
        "0555",
        "sha256:ffe732f8f28d3636bd153722283a1d29c6ad57804816a8c920fc39be835051f4",
    ),
}
_PUBLISHER_COMMAND = [
    "/usr/bin/python3.12",
    "-I",
    "-S",
    "-B",
    "/usr/libexec/aragorn/aragorn-runtime-revocation-service.py",
    f"/run/credentials/{_PUBLISHER_SERVICE}/runtime-binding",
    f"/run/credentials/{_PUBLISHER_SERVICE}/revocations",
]
_ACTIVATION_STDERR = "".join(
    f"Created symlink {path} → {target}.\n"
    for path, target in (
        ("/etc/systemd/system/aragorn-runtime-action-broker.service", "/dev/null"),
        (
            "/etc/systemd/system/aragorn-runtime-profile-action-broker.service",
            "/dev/null",
        ),
        (
            "/etc/systemd/system/aragorn-runtime-observation-publisher.service",
            "/dev/null",
        ),
        (
            "/etc/systemd/system/aragorn-runtime-profile-observation-publisher.service",
            "/dev/null",
        ),
        (
            (
                "/etc/systemd/system/multi-user.target.wants/"
                "aragorn-runtime-capability-action-broker.service"
            ),
            "/lib/systemd/system/aragorn-runtime-capability-action-broker.service",
        ),
        (
            (
                "/etc/systemd/system/multi-user.target.wants/"
                "aragorn-runtime-capability-observation-publisher.service"
            ),
            (
                "/lib/systemd/system/"
                "aragorn-runtime-capability-observation-publisher.service"
            ),
        ),
    )
)


def verify_runtime_revocation_openclaw_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.5b without promoting journal, RUN, EDR, or release authority."""

    try:
        _expect(
            _digest(expected_digest), "an explicit retained evidence digest is required"
        )
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(
            canonical_digest(document) == expected_digest, "retained evidence changed"
        )
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(_same_json(document["decision"], _DECISION), "claim ceiling changed")
        recorded_at = _time(document["recorded_at"])
        installed = _verify_artifacts_and_collectors(document)
        ids = _verify_environment_harness_identities(document)
        profile = _verify_runtime_and_profile(document, ids)
        inputs = _verify_inputs(document, ids, profile)
        _verify_credentials(document, ids, inputs)
        deployment = _verify_deployment(document, ids, profile, installed)
        publication = _verify_publication(document, ids, inputs, deployment)
        _verify_scenario(
            document,
            ids,
            profile,
            inputs,
            deployment,
            publication,
            recorded_at.timestamp(),
        )
        _verify_peer_trace_and_timing(document, ids, deployment, inputs)
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
            f"invalid runtime revocation OpenClaw evidence: {exc}"
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
    for source, path in _ARTIFACTS.items():
        item = by_source[source]
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
            and item["installed_path"] == path
            and _positive(item["source_bytes"])
            and item["source_bytes"] == item["installed_bytes"]
            and item["source_digest"] == item["installed_digest"]
            and _digest(item["source_digest"]),
            f"source/install binding changed: {path}",
        )
        _metadata(
            item["installed_stat"],
            kind="file",
            uid=0,
            gid=0,
            mode="0755" if path.startswith("/usr/libexec/") else "0644",
            size=item["installed_bytes"],
        )
        identity = (item["installed_stat"]["device"], item["installed_stat"]["inode"])
        _expect(identity not in identities, "installed artifacts alias")
        identities.add(identity)

    collector = document["collector"]
    _expect(set(collector) == set(_COLLECTORS), "collector closure changed")
    for name, (path, mode, digest) in _COLLECTORS.items():
        _file(collector[name], path=path, uid=0, gid=0, mode=mode)
        _expect(collector[name]["digest"] == digest, f"collector changed: {name}")
    return installed


def _verify_environment_harness_identities(
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
        and environment["activation"]
        == {"exit_code": 0, "stdout": "", "stderr": _ACTIVATION_STDERR},
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
        and value["schema"] == "aragorn/runtime-revocation-openclaw-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", value["container_id"])
        and value["image_id"] == value["run_image_reference"] == _P35B_IMAGE
        and value["image_reference"]
        == "aragorn-p35b-runtime-revocation-openclaw-systemd"
        and value["parent_image_id"] == _P35A_IMAGE
        and value["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and value["platform"] == "linux"
        and value["profile_label"] == "p3.5b",
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
    parent, child = lineage["parent"], lineage["child"]
    _expect(
        set(lineage) == {"added_layers", "child", "parent"}
        and set(parent) == set(child) == {"id", "layers", "rootfs_type"}
        and parent["id"] == _P35A_IMAGE
        and child["id"] == _P35B_IMAGE
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and all(_digest(layer) for layer in parent["layers"] + child["layers"])
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.5a parent/P3.5b child lineage changed",
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
            "driver",
            "gateway_config",
            "gateway_config_digest",
            "grant",
            "initial_controls",
            "observation_binding",
            "policy",
            "provenance_bindings",
            "revocation_publication",
            "runtime_binding",
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
        "id": "p3-5b-pinned-openclaw-local-systemd-revocation",
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
    _verify_controls(inputs["initial_controls"], policy, action, counter=1, full=True)
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
    _expect(
        inputs["runtime_binding"] == runtime_binding
        and inputs["observation_binding"] == observation_binding,
        "runtime or observation binding changed",
    )
    provenance = {
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
    _expect(inputs["provenance_bindings"] == provenance, "provenance ceiling changed")
    retained_grant = inputs["grant"]
    grant = retained_grant["document"]
    initial_at = inputs["initial_controls"]["health"]["observed_at_unix"]
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
        and grant["issued_at_unix"] <= initial_at < grant["expires_at_unix"],
        "root capability grant changed",
    )
    publication = inputs["revocation_publication"]
    publication_document = publication["document"]
    _expect(
        set(publication) == {"digest", "document"}
        and publication["digest"] == canonical_digest(publication_document)
        and publication_document
        == {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 2,
            "observed_at_unix": publication_document["observed_at_unix"],
            "expires_at_unix": publication_document["observed_at_unix"] + 15,
            "skill_digests": [_SKILL_DIGEST],
        }
        and publication_document["observed_at_unix"] >= initial_at,
        "revocation publication changed",
    )
    _expect(
        inputs["driver"]
        == {
            "schema": "aragorn/openclaw-profile-driver-input/v1",
            "scenario": {
                "id": "local-systemd-revoked",
                "target_name": _TARGET,
                "content": _PAYLOAD.decode(),
                "expected_verdict": "BLOCK",
                "expected_effect_status": "NOT_PERFORMED",
            },
        },
        "driver input changed",
    )
    return {
        "action": action,
        "policy": policy,
        "grant": grant,
        "grant_digest": retained_grant["digest"],
        "initial": inputs["initial_controls"],
        "runtime_binding": runtime_binding,
        "observation_binding": observation_binding,
        "publication": publication_document,
        "publication_digest": publication["digest"],
    }


def _verify_credentials(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> None:
    credentials = document["credentials"]
    _expect(
        set(credentials)
        == {
            "broker",
            "root_grant",
            "root_observation_binding",
            "root_revocation_publication",
            "root_runtime_binding",
            "sensor",
        }
        and set(credentials["broker"]) == {"capability_grant", "runtime_binding"}
        and set(credentials["sensor"]) == {"capability_grant", "observation_binding"},
        "credential closure changed",
    )
    roots = (
        (
            "root_grant",
            "/etc/aragorn/runtime-capability-grant.json",
            inputs["grant"],
        ),
        (
            "root_runtime_binding",
            "/etc/aragorn/runtime-action-runtime.json",
            inputs["runtime_binding"],
        ),
        (
            "root_observation_binding",
            "/etc/aragorn/runtime-action-observation.json",
            inputs["observation_binding"],
        ),
        (
            "root_revocation_publication",
            "/etc/aragorn/runtime-action-revocation-publication.json",
            inputs["publication"],
        ),
    )
    for name, path, value in roots:
        record = credentials[name]
        _file(record, path=path, uid=0, gid=0, mode="0400")
        _expect(
            record["digest"] == canonical_digest(value)
            and record["bytes"] == len(canonical_json(value)),
            f"root credential changed: {name}",
        )
    copies = (
        (
            credentials["broker"]["capability_grant"],
            f"/run/credentials/{_BROKER_SERVICE}/capability-grant",
            ids["broker_uid"],
            inputs["grant"],
        ),
        (
            credentials["broker"]["runtime_binding"],
            f"/run/credentials/{_BROKER_SERVICE}/runtime-binding",
            ids["broker_uid"],
            inputs["runtime_binding"],
        ),
        (
            credentials["sensor"]["capability_grant"],
            f"/run/credentials/{_SENSOR_SERVICE}/capability-grant",
            ids["sensor_uid"],
            inputs["grant"],
        ),
        (
            credentials["sensor"]["observation_binding"],
            f"/run/credentials/{_SENSOR_SERVICE}/observation-binding",
            ids["sensor_uid"],
            inputs["observation_binding"],
        ),
    )
    for record, path, uid, value in copies:
        _file(record, path=path, uid=uid, gid=0, mode="0400")
        _expect(
            record["digest"] == canonical_digest(value)
            and record["bytes"] == len(canonical_json(value)),
            "systemd credential copy changed",
        )


def _verify_deployment(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    installed: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    deployment = document["deployment"]
    _expect(
        set(deployment)
        == {"directories", "gateway", "legacy_routes", "sockets", "units"},
        "deployment fields changed",
    )
    directories = deployment["directories"]
    contracts = {
        "root": (0, 0, "0755", 1),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710", 1),
        "protected": (ids["broker_uid"], ids["runtime_gid"], "0710", 2),
        "staging": (ids["broker_uid"], ids["broker_uid"], "0700", 2),
        "runtime": (ids["sensor_uid"], ids["runtime_gid"], "0750", 2),
    }
    _expect(set(directories) == set(contracts), "directory set changed")
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
    sockets = deployment["sockets"]
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
        set(deployment["legacy_routes"]) == _LEGACY_SERVICES
        and all(
            route
            == {
                "enabled_exit_code": 1,
                "enabled": "masked",
                "active_exit_code": 3,
                "active": "inactive",
            }
            for route in deployment["legacy_routes"].values()
        ),
        "legacy runtime route remained usable",
    )

    units = deployment["units"]
    _expect(
        set(units)
        == {
            "broker",
            "publisher_after",
            "publisher_before",
            "publisher_is_enabled",
            "sensor",
        },
        "unit closure changed",
    )
    _verify_unit(
        units["broker"],
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
        load_credential=(
            'a(ss) 2 "runtime-binding" "/etc/aragorn/runtime-action-runtime.json" '
            '"capability-grant" "/etc/aragorn/runtime-capability-grant.json"'
        ),
    )
    _verify_unit(
        units["sensor"],
        service=_SENSOR_SERVICE,
        fragment_digest=installed[f"/usr/lib/systemd/system/{_SENSOR_SERVICE}"][
            "installed_digest"
        ],
        user="aragorn-sensor",
        group="aragorn-sensor",
        supplementary="aragorn-runtime",
        capabilities="cap_setgid cap_setuid cap_setpcap",
        command=_SENSOR_COMMAND,
        active=True,
        load_credential=(
            'a(ss) 2 "capability-grant" "/etc/aragorn/runtime-capability-grant.json" '
            '"observation-binding" "/etc/aragorn/runtime-action-observation.json"'
        ),
    )
    publisher_load = (
        'a(ss) 2 "runtime-binding" "/etc/aragorn/runtime-action-runtime.json" '
        '"revocations" "/etc/aragorn/runtime-action-revocation-publication.json"'
    )
    publisher_digest = installed[f"/usr/lib/systemd/system/{_PUBLISHER_SERVICE}"][
        "installed_digest"
    ]
    for name in ("publisher_before", "publisher_after"):
        _verify_unit(
            units[name],
            service=_PUBLISHER_SERVICE,
            fragment_digest=publisher_digest,
            user="aragorn-broker",
            group="aragorn-runtime",
            supplementary="aragorn-sensor",
            capabilities="",
            command=_PUBLISHER_COMMAND,
            active=False,
            load_credential=publisher_load,
        )
    _expect(
        units["publisher_before"] == units["publisher_after"]
        and units["publisher_is_enabled"]
        == {"exit_code": 0, "stdout": "static\n", "stderr": ""},
        "publisher is not exact, static, and manual-only",
    )
    gateway = _verify_gateway_epochs(deployment["gateway"], ids, profile)
    return {
        "broker_pid": int(units["broker"]["MainPID"]),
        "sensor_pid": int(units["sensor"]["MainPID"]),
        "gateway": gateway,
        "directories": directories,
        "sockets": sockets,
        "units": units,
    }


def _verify_gateway_epochs(
    gateways: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    _expect(
        set(gateways) == {"after_action", "after_activation", "initial"},
        "gateway epochs changed",
    )
    processes = []
    for name, command in (
        ("initial", ["openclaw"]),
        ("after_activation", ["openclaw"]),
        ("after_action", ["openclaw-gateway"]),
    ):
        value = gateways[name]
        _expect(
            set(value)
            == {"cgroup", "mount_namespace", "pid", "process", "security", "unit"}
            and value["cgroup"] == profile["cgroup"]
            and value["pid"] == value["process"]["pid"]
            and value["mount_namespace"]["inode"]
            == int(value["process"]["mount_namespace"][5:-1])
            and _zero_security(value["security"]),
            f"gateway snapshot changed: {name}",
        )
        _mount_namespace(value["mount_namespace"])
        _verify_unit(
            value["unit"],
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
        _process(
            value["process"],
            unit=value["unit"],
            command=command,
            uids=[ids["runtime_uid"]] * 4,
            gids=[ids["runtime_gid"]] * 4,
            groups=[ids["runtime_gid"]],
        )
        processes.append(value["process"])
    _expect(
        all(
            processes[0][field] == process[field]
            for process in processes[1:]
            for field in _PROCESS_FIELDS - {"cmdline"}
        ),
        "gateway process was replaced",
    )
    initial = gateways["initial"]
    return {
        "pid": initial["pid"],
        "start_time_ticks": int(initial["process"]["start_time_ticks"]),
        "mount_namespace": initial["mount_namespace"],
        "process_mount_namespace": initial["process"]["mount_namespace"],
        "network_namespace": initial["process"]["network_namespace"],
        "unit": initial["unit"],
    }


def _verify_publication(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    inputs: Mapping[str, Any],
    deployment: Mapping[str, Any],
) -> dict[str, Any]:
    publication = document["publication"]
    _expect(
        set(publication)
        == {
            "activation_source",
            "after",
            "before",
            "checks",
            "journal",
            "sequence",
            "unit",
        }
        and set(publication["checks"])
        == {
            "effects",
            "grant",
            "journal_result",
            "processes",
            "revocations",
            "sockets",
            "source",
            "state_floor",
            "unit_credentials",
            "unit_exec",
            "unit_fragment",
            "unit_identity",
            "unit_success",
            "unrelated_controls",
        }
        and all(value is True for value in publication["checks"].values())
        and publication["unit"] == deployment["units"]["publisher_after"],
        "publication proof closure changed",
    )
    initial = inputs["initial"]
    activation_document = {
        **initial["revocations"],
        "generation": 2,
        "skill_digests": [_SKILL_DIGEST],
    }
    activation = publication["activation_source"]
    _expect(
        set(activation) == {"document", "file"}
        and activation["document"] == activation_document,
        "activation publication changed",
    )
    _verify_bound_file(
        activation["file"],
        path="/etc/aragorn/runtime-action-revocation-publication.json",
        uid=0,
        gid=0,
        value=activation_document,
    )
    before, after = publication["before"], publication["after"]
    fields = {
        "controls",
        "effects",
        "grant_state",
        "processes",
        "publication_source",
        "publication_source_document",
        "sockets",
    }
    _expect(set(before) == set(after) == fields, "publication snapshots changed")
    for phase in (before, after):
        _expect(
            set(phase["controls"])
            == {"health", "observation", "policy", "revocations", "state"},
            "control snapshot changed",
        )
        for retained in phase["controls"].values():
            _retained(retained)
        _retained(phase["grant_state"])
        _retained(phase["publication_source_document"])
        _verify_bound_file(
            phase["publication_source"],
            path="/etc/aragorn/runtime-action-revocation-publication.json",
            uid=0,
            gid=0,
            value=inputs["publication"],
        )
        _expect(
            phase["publication_source_document"]
            == {
                "digest": inputs["publication_digest"],
                "document": inputs["publication"],
            },
            "publication source document changed",
        )
        _verify_processes(
            phase["processes"], ids, deployment, gateway_command=["openclaw"]
        )
    available = {
        "schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": inputs["grant_digest"],
        "status": "AVAILABLE",
        "claim": None,
        "result": None,
    }
    before_controls = before["controls"]
    _expect(
        all(
            before_controls[name]
            == {"digest": canonical_digest(initial[name]), "document": initial[name]}
            for name in ("policy", "revocations", "health", "observation", "state")
        )
        and before["grant_state"]
        == {"digest": canonical_digest(available), "document": available},
        "publication did not start from initial AVAILABLE state",
    )
    expected_state = {**initial["state"], "minimum_revocation_generation": 2}
    after_controls = after["controls"]
    _expect(
        after_controls["revocations"]
        == {"digest": inputs["publication_digest"], "document": inputs["publication"]}
        and after_controls["state"]
        == {"digest": canonical_digest(expected_state), "document": expected_state}
        and before_controls["revocations"]["digest"]
        != after_controls["revocations"]["digest"]
        and before_controls["state"]["digest"] != after_controls["state"]["digest"]
        and all(
            before_controls[name] == after_controls[name]
            for name in ("policy", "health", "observation")
        )
        and before["effects"] == after["effects"] == _effects(receipt=False)
        and before["grant_state"] == after["grant_state"]
        and before["processes"] == after["processes"]
        and before["sockets"] == after["sockets"] == deployment["sockets"]
        and before["publication_source"]
        == after["publication_source"]
        == document["credentials"]["root_revocation_publication"]
        and before["publication_source_document"]
        == after["publication_source_document"],
        "publication transition changed or was a no-op",
    )
    sequence = publication["sequence"]
    _expect(
        set(sequence)
        == {
            "after_publication_monotonic_ns",
            "before_publication_monotonic_ns",
            "publisher_start_monotonic_ns",
        }
        and all(_positive(value) for value in sequence.values())
        and sequence["before_publication_monotonic_ns"]
        <= sequence["publisher_start_monotonic_ns"]
        <= sequence["after_publication_monotonic_ns"],
        "publication sequence changed",
    )
    journal = publication["journal"]
    result = {
        "schema": "aragorn/runtime-revocation-publication-result/v1",
        "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_AUTHORITY",
        "revocations_digest": inputs["publication_digest"],
        "generation": 2,
    }
    record = journal["record"]
    journal_monotonic_ns = int(record["__MONOTONIC_TIMESTAMP"]) * 1000
    journal_realtime_us = int(record["__REALTIME_TIMESTAMP"])
    recorded_at_us = int(_time(document["recorded_at"]).timestamp() * 1_000_000)
    _expect(
        set(journal) == {"after_cursor", "record", "result", "result_digest"}
        and isinstance(journal["after_cursor"], str)
        and 0 < len(journal["after_cursor"]) <= 1024
        and journal["after_cursor"].isascii()
        and journal["result"] == result
        and journal["result_digest"] == canonical_digest(result)
        and set(record)
        == {
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
        }
        and record["MESSAGE"] == canonical_json(result).decode("ascii")
        and record["SYSLOG_IDENTIFIER"] == "aragorn-runtime-revocation-publisher"
        and record["_SYSTEMD_UNIT"] == _PUBLISHER_SERVICE
        and record["_UID"] == str(ids["broker_uid"])
        and record["_GID"] == str(ids["runtime_gid"])
        and re.fullmatch(r"[0-9a-f]{32}", record["_SYSTEMD_INVOCATION_ID"])
        and record["_SYSTEMD_INVOCATION_ID"] != "0" * 32
        and all(
            isinstance(record[name], str)
            and record[name].isdigit()
            and int(record[name]) > 0
            for name in ("_PID", "__MONOTONIC_TIMESTAMP", "__REALTIME_TIMESTAMP")
        )
        and sequence["publisher_start_monotonic_ns"]
        <= journal_monotonic_ns
        <= sequence["after_publication_monotonic_ns"]
        and inputs["publication"]["observed_at_unix"] * 1_000_000
        <= journal_realtime_us
        < inputs["publication"]["expires_at_unix"] * 1_000_000
        and journal_realtime_us <= recorded_at_us
        and all(
            isinstance(record[name], str)
            and bool(record[name])
            and record[name].isascii()
            for name in ("_BOOT_ID", "__CURSOR")
        ),
        "journal process result changed or gained durable authority",
    )
    return {"sequence": sequence, "available": available}


def _verify_scenario(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    inputs: Mapping[str, Any],
    deployment: Mapping[str, Any],
    publication: Mapping[str, Any],
    recorded_at: float,
) -> None:
    scenario = document["scenario"]
    _expect(
        set(scenario)
        == {
            "broker_state",
            "checks",
            "controls_after",
            "driver",
            "driver_elapsed_ns",
            "driver_exit_code",
            "driver_stderr",
            "driver_stdout",
            "effects_after",
            "grant_state_after",
            "grant_state_before",
            "grant_state_file",
            "processes_after",
            "profile_receipt",
            "profile_receipt_file",
            "runtime_facing_grant_or_lease_absent",
            "sequence",
            "status",
        }
        and set(scenario["checks"])
        == {
            "attribution",
            "decision_live_window",
            "decision_revocation",
            "driver",
            "gateway_stable",
            "grant_consumed",
            "lease",
            "no_effect",
            "peer_chain",
            "profile_claim",
            "profile_result",
            "provider_tool_call",
            "receipt",
            "result",
            "revocation_retained",
            "services_stable",
            "sockets_stable",
            "sole_reason",
            "state",
        }
        and all(value is True for value in scenario["checks"].values())
        and scenario["status"] == "PASS"
        and scenario["driver_exit_code"] == 0
        and scenario["driver_stdout"] == scenario["driver_stderr"] == ""
        and _positive(scenario["driver_elapsed_ns"])
        and scenario["runtime_facing_grant_or_lease_absent"] is True,
        "revoked scenario closure changed",
    )
    _expect(
        scenario["grant_state_before"]
        == {
            "digest": canonical_digest(publication["available"]),
            "document": publication["available"],
        },
        "scenario did not begin with the clean AVAILABLE grant",
    )
    state = scenario["grant_state_after"]
    _retained(state)
    _expect(
        _validated_grant_state(state["document"], inputs["grant_digest"])
        == state["document"]
        and state["document"]["status"] == "CONSUMED",
        "terminal grant state changed",
    )
    result = _verify_driver(scenario["driver"], deployment["gateway"]["pid"])
    _verify_state_and_replay(
        document,
        scenario,
        ids,
        profile,
        inputs,
        deployment,
        state,
        result,
        recorded_at,
    )
    _verify_processes(
        scenario["processes_after"],
        ids,
        deployment,
        gateway_command=["openclaw-gateway"],
    )
    after_publication_processes = document["publication"]["after"]["processes"]
    _expect(
        all(
            after_publication_processes[name][field]
            == scenario["processes_after"][name][field]
            for name in ("broker", "gateway", "sensor")
            for field in _PROCESS_FIELDS - {"cmdline"}
        ),
        "protected processes were replaced after publication",
    )
    _expect(
        scenario["effects_after"] == _effects(receipt=True),
        "blocked action produced an effect",
    )
    sequence = scenario["sequence"]
    _expect(
        set(sequence) == {"driver_complete_monotonic_ns", "driver_start_monotonic_ns"}
        and _positive(sequence["driver_start_monotonic_ns"])
        and sequence["driver_start_monotonic_ns"]
        <= sequence["driver_complete_monotonic_ns"]
        and publication["sequence"]["after_publication_monotonic_ns"]
        <= sequence["driver_start_monotonic_ns"],
        "action/publication sequence changed",
    )


def _verify_driver(driver: Mapping[str, Any], gateway_pid: int) -> Mapping[str, Any]:
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
    identifiers = turn["identifiers"]
    run_id = "aragorn-p34b-local-systemd-revoked"
    session_key = f"agent:main:{run_id}"
    tool_call_id = "call_aragorn_p34b_local_systemd_revoked_1"
    user_text = (
        "Invoke aragorn_runtime_create exactly once for bounded scenario "
        "local-systemd-revoked."
    )
    _expect(
        set(turn) == {"history", "identifiers", "send", "wait"}
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
    _expect(
        all(
            set(body)
            == {"max_tokens", "messages", "model", "stream", "tool_choice", "tools"}
            for body in bodies
        )
        and all(body["model"] == "fixture-model" for body in bodies)
        and all(
            body["max_tokens"] == 256
            and body["stream"] is True
            and body["tool_choice"] == "auto"
            for body in bodies
        )
        and bodies[1]["tools"] == bodies[0]["tools"]
        and [
            tool
            for tool in bodies[0]["tools"]
            if tool.get("function", {}).get("name") == "aragorn_runtime_create"
        ]
        == [_tool_contract()],
        "provider request contract changed",
    )
    description = "Exercise one bounded profiled OpenClaw create in the P3.4b fixture."
    for body in bodies:
        prompt = "\n".join(
            message["content"]
            for message in body["messages"]
            if isinstance(message, Mapping)
            and message.get("role") == "system"
            and isinstance(message.get("content"), str)
        )
        _expect(
            prompt.count(f"<name>{_SKILL_NAME}</name>") == 1
            and prompt.count(f"<description>{description}</description>") == 1
            and prompt.count(f"<location>{_SKILL_PATH}</location>") == 1
            and prompt.count(f"<version>{_SKILL_DIGEST[:23]}</version>") == 1,
            "root-owned skill prompt projection changed",
        )
    expected_arguments = {"content": _PAYLOAD.decode(), "target_name": _TARGET}
    arguments = canonical_json(expected_arguments).decode("ascii")
    call = records[0]["response"][0]["choices"][0]["delta"]["tool_calls"]
    _expect(
        len(call) == 1
        and call[0]["id"] == tool_call_id
        and call[0]["function"]
        == {"arguments": arguments, "name": "aragorn_runtime_create"}
        and records[1]["response"][0]["choices"][0]["delta"]["content"]
        == "ARAGORN_RUNTIME_ACTION_BLOCK_NOT_PERFORMED",
        "provider tool call changed",
    )
    history = turn["history"]["response"]
    messages = history["messages"]
    _expect(
        len(messages) == 4
        and [item["__openclaw"]["seq"] for item in messages] == [1, 2, 3, 4]
        and [item["role"] for item in messages]
        == ["user", "assistant", "toolResult", "assistant"]
        and history["sessionId"] == identifiers["session_id"]
        and history["sessionKey"] == session_key
        and history["sessionInfo"]["key"] == session_key
        and history["sessionInfo"]["sessionId"] == identifiers["session_id"]
        and history["sessionInfo"]["status"] == "done"
        and history["sessionInfo"]["activeRunIds"] == [],
        "retained history lineage changed",
    )
    user, assistant, tool_message, final = messages
    retained = _retained_tool_result(tool_message)
    result = retained["document"]["result"]
    _expect(
        user["content"] == user_text
        and user["idempotencyKey"] == f"{run_id}:user"
        and assistant["content"]
        == [
            {
                "arguments": expected_arguments,
                "id": tool_call_id,
                "name": "aragorn_runtime_create",
                "partialArgs": arguments,
                "type": "toolCall",
            }
        ]
        and assistant["provider"] == "aragorn-runtime-action-mock"
        and assistant["model"] == "fixture-model"
        and assistant["stopReason"] == "toolUse"
        and tool_message["toolCallId"] == tool_call_id
        and tool_message["toolName"] == "aragorn_runtime_create"
        and tool_message["isError"] is False
        and tool_message["content"] == [{"text": retained["raw"], "type": "text"}]
        and "details" not in tool_message
        and final["content"]
        == [{"text": "ARAGORN_RUNTIME_ACTION_BLOCK_NOT_PERFORMED", "type": "text"}]
        and final["provider"] == "aragorn-runtime-action-mock"
        and final["model"] == "fixture-model"
        and final["stopReason"] == "stop",
        "persisted tool result lineage changed",
    )
    proof = driver["scenario"]["proof"]
    _expect(
        driver["scenario"]["status"] == "PASS"
        and set(proof) == {"checks", "passed", "retained_tool_result"}
        and proof["checks"]
        == {
            "action_result_bound": True,
            "gateway_pid_present": True,
            "history_lineage": True,
            "one_provider_driven_tool_call": True,
            "provider_completed_without_error": True,
        }
        and proof["passed"] is True
        and _same_json(proof["retained_tool_result"], retained["document"]),
        "driver proof changed",
    )
    _verify_turn_commands(turn, run_id, session_key, user_text)
    timing = driver["timing"]
    _expect(
        set(timing) == {"completed_at", "elapsed_ms", "started_at"}
        and _positive(timing["elapsed_ms"])
        and int(
            (
                _time(timing["completed_at"]) - _time(timing["started_at"])
            ).total_seconds()
            * 1000
        )
        == timing["elapsed_ms"],
        "driver timing changed",
    )
    return result


def _verify_turn_commands(
    turn: Mapping[str, Any], run_id: str, session_key: str, user_text: str
) -> None:
    contracts = (
        (
            "send",
            "chat.send",
            "5000",
            {
                "deliver": False,
                "idempotencyKey": run_id,
                "message": user_text,
                "sessionKey": session_key,
                "timeoutMs": 10000,
            },
        ),
        ("wait", "agent.wait", "17000", {"runId": run_id, "timeoutMs": 15000}),
        ("history", "chat.history", "5000", {"limit": 20, "sessionKey": session_key}),
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
                canonical_json(params).decode("ascii"),
            ],
        )
    _expect(
        turn["send"]["response"] == {"runId": run_id, "status": "started"}
        and turn["wait"]["response"]["runId"] == run_id
        and turn["wait"]["response"]["status"] == "ok"
        and _positive(turn["wait"]["response"]["endedAt"]),
        "turn lifecycle changed",
    )


def _verify_state_and_replay(
    document: Mapping[str, Any],
    scenario: Mapping[str, Any],
    ids: Mapping[str, Any],
    profile: Mapping[str, Any],
    inputs: Mapping[str, Any],
    deployment: Mapping[str, Any],
    state: Mapping[str, Any],
    retained_result: Mapping[str, Any],
    recorded_at: float,
) -> None:
    claim = state["document"]["claim"]
    lease = claim["lease"]
    lease_digest = canonical_digest(lease)
    profile_claim = claim["profile_claim"]
    pending = profile_claim["profile_pending"]
    identifiers = scenario["driver"]["turn"]["identifiers"]
    hashed_tool_call = (
        "sha256:" + hashlib.sha256(identifiers["tool_call_id"].encode()).hexdigest()
    )
    receipt = scenario["profile_receipt"]
    _retained(receipt)
    result = receipt["document"]["broker_result"]
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
        {**request_base, "issued_at_unix": issued, "expires_at_unix": issued + 5}
        for issued in range(now - 5, now + 1)
    ]
    candidates = [
        item
        for item in candidates
        if canonical_digest(item) == result["request_digest"]
    ]
    _expect(len(candidates) == 1, "request could not be independently derived")
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
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{key: value for key, value in active.items() if key != "schema"},
        **inputs["action"],
    }
    attribution = {
        "schema": "aragorn/runtime-process-profile-attribution/v1",
        "authority": "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "profile_digest": profile["digest"],
        "runtime_digest": _RUNTIME_DIGEST,
        "executable_digest": _NODE_DIGEST,
        "active_skill_digest": _SKILL_DIGEST,
        "skill_path": _SKILL_PATH,
        "cgroup": profile["cgroup"],
        "pid": deployment["gateway"]["pid"],
        "uid": ids["runtime_uid"],
        "gid": ids["runtime_gid"],
        "start_time_ticks": deployment["gateway"]["start_time_ticks"],
        "mount_namespace": deployment["gateway"]["mount_namespace"],
    }
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": _SENSOR_DIGEST,
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {
            "pid": deployment["gateway"]["pid"],
            "uid": ids["runtime_uid"],
            "gid": ids["runtime_gid"],
        },
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": attribution,
    }
    expected_pending = {
        "schema": "aragorn/runtime-process-profile-pending/v1",
        "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
        "submission_digest": canonical_digest(submission),
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "measured_action": measured,
        "runtime_attribution_digest": canonical_digest(attribution),
        "runtime_attribution": attribution,
    }
    expected_claim = {
        "schema": "aragorn/runtime-capability-lease-claim/v1",
        "authority": "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": lease_digest,
        "submission_digest": canonical_digest(submission),
        "runtime_attribution_digest": canonical_digest(attribution),
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "measured_action_digest": canonical_digest(measured),
        "claimed_at_unix": lease["issued_at_unix"],
        "session_id": identifiers["session_id"],
        "run_id": identifiers["run_id"],
        "tool_call_id": hashed_tool_call,
        "target_name": _TARGET,
        "profile_pending": expected_pending,
    }
    _expect(
        pending == expected_pending
        and profile_claim == expected_claim
        and claim["grant_digest"] == inputs["grant_digest"]
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
        and inputs["grant"]["issued_at_unix"]
        <= request["issued_at_unix"]
        <= lease["issued_at_unix"]
        == profile_claim["claimed_at_unix"]
        < lease["expires_at_unix"]
        == request["expires_at_unix"]
        <= inputs["grant"]["expires_at_unix"],
        "lease, profile claim, or submission binding changed",
    )
    controls = scenario["controls_after"]
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"},
        "terminal controls changed",
    )
    for retained in controls.values():
        _retained(retained)
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
    broker_state = {
        "schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 2,
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
        revocations=inputs["publication"],
        minimum_revocation_generation=2,
        mediator_health=health,
        minimum_mediator_health_epoch=2,
    )
    counterfactual = evaluate_runtime_action(
        request,
        inputs["policy"],
        now_unix=now,
        active=active,
        measured_action=measured,
        revocations=inputs["initial"]["revocations"],
        minimum_revocation_generation=1,
        mediator_health=health,
        minimum_mediator_health_epoch=2,
    )
    expected_result = {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(request),
        "observation_digest": canonical_digest(observation),
        "target_name": _TARGET,
        "verdict": "BLOCK",
        "reason_codes": ["ACTIVE_SKILL_REVOKED"],
        "effect_status": "NOT_PERFORMED",
        "decision": replay,
    }
    _expect(
        replay["verdict"] == "BLOCK"
        and replay["reason_codes"] == ["ACTIVE_SKILL_REVOKED"]
        and counterfactual["verdict"] == "ALLOW"
        and counterfactual["reason_codes"] == []
        and inputs["publication"]["observed_at_unix"]
        <= now
        < inputs["publication"]["expires_at_unix"]
        and result == retained_result == expected_result
        and controls["policy"]
        == {"digest": canonical_digest(inputs["policy"]), "document": inputs["policy"]}
        and controls["revocations"]
        == {"digest": inputs["publication_digest"], "document": inputs["publication"]}
        and controls["health"]
        == {"digest": canonical_digest(health), "document": health}
        and controls["observation"]
        == {"digest": canonical_digest(observation), "document": observation}
        and controls["state"]
        == {"digest": canonical_digest(broker_state), "document": broker_state}
        and scenario["broker_state"] == controls["state"],
        "revocation was not the sole independently replayed block cause",
    )
    expected_receipt = {
        "schema": "aragorn/runtime-process-profile-receipt/v1",
        "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "submission_digest": canonical_digest(submission),
        "runtime_attribution_digest": canonical_digest(attribution),
        "runtime_attribution": attribution,
        "broker_result_digest": canonical_digest(result),
        "broker_result": result,
    }
    profile_result = {
        "schema": "aragorn/runtime-capability-lease-result/v1",
        "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": lease_digest,
        "submission_digest": canonical_digest(submission),
        "profile_receipt_digest": canonical_digest(expected_receipt),
        "broker_result_digest": canonical_digest(result),
        "verdict": "BLOCK",
        "effect_status": "NOT_PERFORMED",
    }
    _expect(
        receipt
        == {"digest": canonical_digest(expected_receipt), "document": expected_receipt}
        and state["document"]["result"]
        == {
            "schema": "aragorn/runtime-capability-grant-result/v1",
            "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": inputs["grant_digest"],
            "lease_digest": lease_digest,
            "profile_result": profile_result,
        },
        "terminal receipt or grant result was reused or changed",
    )
    _verify_bound_file(
        scenario["grant_state_file"],
        path=f"{_CONTROL}/capability-grant-state.json",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        value=state["document"],
    )
    _verify_bound_file(
        scenario["profile_receipt_file"],
        path=f"{_CONTROL}/profile-receipt.json",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        value=receipt["document"],
    )
    _expect(
        scenario["grant_state_file"]["digest"] == state["digest"]
        and scenario["profile_receipt_file"]["digest"] == receipt["digest"]
        and scenario["grant_state_file"]["stat"]["device"]
        == deployment["directories"]["control"]["device"]
        and scenario["profile_receipt_file"]["stat"]["device"]
        == deployment["directories"]["control"]["device"]
        and 0 <= recorded_at - now < 10,
        "terminal files or recording time changed",
    )
    raw_driver = canonical_json(scenario["driver"])
    _expect(
        all(
            value.encode() not in raw_driver
            for value in (
                inputs["grant"]["grant_id"],
                inputs["grant_digest"],
                lease["lease_nonce"],
                lease["authority"],
                lease["schema"],
            )
        ),
        "runtime-facing output exposed grant or lease authority",
    )


def _verify_processes(
    value: Mapping[str, Any],
    ids: Mapping[str, Any],
    deployment: Mapping[str, Any],
    *,
    gateway_command: list[str],
) -> None:
    _expect(set(value) == {"broker", "gateway", "sensor"}, "process closure changed")
    _process(
        value["broker"],
        unit=deployment["units"]["broker"],
        command=_BROKER_COMMAND,
        uids=[ids["broker_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _process(
        value["sensor"],
        unit=deployment["units"]["sensor"],
        command=_SENSOR_COMMAND,
        uids=[ids["sensor_uid"]] * 3 + [ids["runtime_uid"]],
        gids=[ids["sensor_gid"]] * 3 + [ids["runtime_gid"]],
        groups=sorted([ids["sensor_gid"], ids["runtime_gid"]]),
    )
    _process(
        value["gateway"],
        unit=deployment["gateway"]["unit"],
        command=gateway_command,
        uids=[ids["runtime_uid"]] * 4,
        gids=[ids["runtime_gid"]] * 4,
        groups=[ids["runtime_gid"]],
    )
    _expect(
        value["broker"]["pid"] == deployment["broker_pid"]
        and value["sensor"]["pid"] == deployment["sensor_pid"]
        and value["gateway"]["pid"] == deployment["gateway"]["pid"],
        "service process identity changed",
    )


def _verify_peer_trace_and_timing(
    document: Mapping[str, Any],
    ids: Mapping[str, Any],
    deployment: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> None:
    traces = document["peer_trace"]
    _expect(set(traces) == {"broker", "sensor"}, "peer trace closure changed")
    contracts = {
        "broker": (
            deployment["broker_pid"],
            ["accept"],
            [
                {
                    "pid": deployment["sensor_pid"],
                    "uid": ids["sensor_uid"],
                    "gid": ids["sensor_gid"],
                }
            ],
        ),
        "sensor": (
            deployment["sensor_pid"],
            ["accept", "connect"],
            [
                {
                    "pid": deployment["gateway"]["pid"],
                    "uid": ids["runtime_uid"],
                    "gid": ids["runtime_gid"],
                },
                {
                    "pid": deployment["broker_pid"],
                    "uid": ids["broker_uid"],
                    "gid": ids["runtime_gid"],
                },
            ],
        ),
    }
    peer_pattern = re.compile(
        r"(?P<service>\d+)\s+getsockopt\((?P<fd>\d+), SOL_SOCKET, SO_PEERCRED, "
        r"\{pid=(?P<pid>\d+), uid=(?P<uid>\d+), gid=(?P<gid>\d+)\}, \[12\]\) = 0"
    )
    accept_pattern = re.compile(
        r"(?P<service>\d+)\s+accept4\(\d+, \{sa_family=AF_UNIX\}, \[\d+ => \d+\], SOCK_CLOEXEC\) = (?P<fd>\d+)"
    )
    connect_pattern = re.compile(
        r'(?P<service>\d+)\s+connect\((?P<fd>\d+), \{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
    )
    detached_pattern = re.compile(
        r"(?P<service>\d+)\s+accept4\(\d+,\s+<detached \.\.\.>"
    )
    for name, (service_pid, expected_kinds, expected_peers) in contracts.items():
        trace = traces[name]
        raw = trace["raw"]
        lines = raw.splitlines()
        peers, kinds = [], []
        completed = sum(
            accept_pattern.fullmatch(line) is not None
            or connect_pattern.fullmatch(line) is not None
            for line in lines
        )
        for index, line in enumerate(lines):
            match = peer_pattern.fullmatch(line)
            if match is None:
                continue
            accept = accept_pattern.fullmatch(lines[index - 1] if index else "")
            connect = connect_pattern.fullmatch(lines[index - 1] if index else "")
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
            and completed == len(peers)
            and kinds == expected_kinds
            and peers == trace["peer_credentials"] == expected_peers
            and detached is not None
            and int(detached["service"]) == service_pid,
            f"kernel peer chain changed: {name}",
        )
    timing = document["timing"]
    _expect(
        timing
        == {
            "grant_lifetime_seconds": inputs["grant"]["expires_at_unix"]
            - inputs["grant"]["issued_at_unix"],
            "revocation_lifetime_seconds": inputs["publication"]["expires_at_unix"]
            - inputs["publication"]["observed_at_unix"],
            "sensor_deadline_ms": 500,
            "client_deadline_ms": 750,
            "driver_elapsed_ns": document["scenario"]["driver_elapsed_ns"],
        }
        and timing["grant_lifetime_seconds"] == 241
        and timing["revocation_lifetime_seconds"] == 15
        and _positive(timing["driver_elapsed_ns"]),
        "timing contract changed",
    )


def _verify_bound_file(
    record: Mapping[str, Any],
    *,
    path: str,
    uid: int,
    gid: int,
    value: Mapping[str, Any],
) -> None:
    _file(record, path=path, uid=uid, gid=gid, mode="0400")
    _expect(
        record["digest"] == canonical_digest(value)
        and record["bytes"] == len(canonical_json(value)),
        f"bound file changed: {path}",
    )


def _retained(value: Mapping[str, Any]) -> None:
    _expect(
        set(value) == {"digest", "document"}
        and value["digest"] == canonical_digest(value["document"]),
        "retained document digest changed",
    )


def _effects(*, receipt: bool) -> dict[str, Any]:
    return {
        "target": {"path": f"{_PROTECTED}/{_TARGET}", "lexists": False},
        "protected_entries": [],
        "staging_entries": [],
        "profile_pending_exists": False,
        "profile_receipt_exists": receipt,
    }


def _expect(condition: object, message: str) -> None:
    if condition is not True:
        raise AdmissionEvidenceError(message)
