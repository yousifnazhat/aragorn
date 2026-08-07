"""Verify the bounded P3.6a live protected-lineage artifact."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_action_broker_v4 import _state as _validated_grant_state
from .runtime_action_systemd_evidence import _contains_float
from .runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_AUTHORITY,
    ACTIVE_RUNTIME_SCHEMA,
    VERIFIED_LINEAGE_AUTHORITY,
    VERIFIED_LINEAGE_SCHEMA,
    parse_active_runtime_record,
)
from .runtime_capability_grant import parse_runtime_capability_grant
from .runtime_capability_openclaw_systemd_evidence import (
    _ENTRYPOINT_DIGEST,
    _PAYLOAD,
    _TARGET,
)
from .runtime_process_profile import runtime_process_profile
from .runtime_process_profile_openclaw_systemd_evidence import (
    _NODE,
    _NODE_DIGEST,
    _NODE_IMAGE,
    _OPENCLAW,
    _RUNTIME_DIGEST,
    _SENSOR_DIGEST,
    _SKILL_DIGEST,
    _SKILL_PATH,
    _SYSTEMD_BASE_IMAGE,
)
from .runtime_process_profile_systemd_evidence import (
    _digest,
    _file,
    _metadata,
    _positive,
)
from .runtime_revocation_openclaw_systemd_evidence import _expect, _retained

_SCHEMA = "aragorn/runtime-active-lineage-openclaw-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_LIVE_PROTECTED_LINEAGE_SYSTEMD_COMPOSITION_ONLY_"
    "NOT_INSTALLER_RUN_OR_EDR_AUTHORITY"
)
_RAW_DIGEST = "b70ca54d1efdb4b9e93ed2d3895819a2f248c132cf29d811b24635fe79517362"
_EVIDENCE_DIGEST = (
    "sha256:5c48201f3273dc4597e0e387f2873d6cf93940a645d6a528344c4aa9e2f7e1bd"
)
_P35B_IMAGE = "sha256:730b451086b74a4de9a0e5a335a7ded8ff5f1071dea8f1302afd56a38d06be9d"
_P36A_IMAGE = "sha256:5059135af5a9b0799be878814abe293f921fd55ea680bc2298330aff56198972"
_P35B_RAW_DIGEST = (
    "sha256:e60d5cc364f9cf378ee832eaa955119733d92a7dafb0fb83365e85eb4f9225c4"
)
_FIXTURE_AUTHORITY = (
    "ROOT_ASSEMBLED_PROTECTED_LINEAGE_FIXTURE_ONLY_NOT_FULL_PROTECTED_INSTALL_PRODUCER"
)
_TARGET_NAME = "aragorn-runtime-composition"
_INSTALL_ROOT = "/var/lib/aragorn-protected/skills"
_EFFECT_ROOT = "/var/lib/aragorn-runtime-action/protected"
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
_DECISION = {
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
}
_TOP_LEVEL = {
    "schema",
    "authority",
    "recorded_at",
    "limitations",
    "decision",
    "parent_evidence",
    "harness",
    "artifacts",
    "runtime",
    "profile",
    "identities",
    "grant",
    "active_install",
    "deployment",
    "cases",
    "timing",
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
    "/src/packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service"
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


def verify_runtime_active_lineage_openclaw_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.6a without promoting fixture, RUN, EDR, or release authority."""

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
        _expect(document["decision"] == _DECISION, "claim ceiling changed")
        _time(document["recorded_at"])
        _verify_parent(document["parent_evidence"])
        harness = _verify_harness(document["harness"])
        _verify_artifacts(document["artifacts"])
        _verify_composition(document, harness)
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
            f"invalid runtime active-lineage OpenClaw evidence: {exc}"
        ) from exc


def _verify_composition(
    document: Mapping[str, Any],
    harness: Mapping[str, Any],
    *,
    fixture_authority: str = _FIXTURE_AUTHORITY,
    target_name: str = _TARGET_NAME,
    skill_path: str = _SKILL_PATH,
    skill_digest: str = _SKILL_DIGEST,
) -> None:
    """Verify the shared protected-lineage runtime composition."""

    ids = _verify_identities(document["identities"])
    profile = _verify_runtime_profile(
        document,
        harness,
        skill_path=skill_path,
        skill_digest=skill_digest,
    )
    grant = _grant_document(
        document["grant"], profile, skill_digest=skill_digest
    )
    active = _verify_active_install(
        document["active_install"],
        grant,
        profile,
        ids,
        fixture_authority=fixture_authority,
        target_name=target_name,
        skill_digest=skill_digest,
    )
    states = _verify_grant(document["grant"], grant, profile, active)
    deployment = _verify_deployment(document["deployment"], ids, harness, active)
    _verify_cases(
        document["cases"],
        grant,
        profile,
        active,
        states,
        ids,
        deployment,
        skill_digest=skill_digest,
    )
    _verify_timing(document["timing"], document["cases"], grant)


def _verify_parent(value: Mapping[str, Any]) -> None:
    _expect(
        value
        == {
            "repository_path": (
                "benchmark/evidence/"
                "runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json"
            ),
            "captured_path": (
                "/src/benchmark/evidence/"
                "runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json"
            ),
            "file_digest": _P35B_RAW_DIGEST,
            "bytes": 303241,
            "schema": "aragorn/runtime-revocation-openclaw-systemd-evidence/v1",
            "authority": (
                "BOUNDED_PINNED_OPENCLAW_LOCAL_SYSTEMD_REVOCATION_PUBLICATION_ONLY_"
                "NOT_RUN_OR_EDR_AUTHORITY"
            ),
            "decision_status": "P3_5B_LOCAL_SYSTEMD_REVOCATION_OBSERVED",
        },
        "P3.5b parent evidence pin changed",
    )


def _verify_harness(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _retained(value)
    harness = value["document"]
    fields = {
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
        set(harness) == fields
        and harness["schema"]
        == "aragorn/runtime-active-lineage-openclaw-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", harness["container_id"])
        and bool(_P36A_IMAGE)
        and harness["image_id"] == harness["run_image_reference"] == _P36A_IMAGE
        and harness["image_reference"]
        == "aragorn-p36a-runtime-active-lineage-openclaw-systemd"
        and harness["parent_image_id"] == _P35B_IMAGE
        and harness["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and harness["platform"] == "linux"
        and harness["profile_label"] == "p3.6a",
        "P3.6a harness identity changed",
    )
    _expect(
        harness["node_image"]
        == {
            "architecture": "arm64",
            "id": _NODE_IMAGE,
            "os": "linux",
            "reference": f"node@{_NODE_IMAGE}",
            "variant": "v8",
        }
        and harness["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
        and harness["openclaw_runtime_volume_identity"]
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        }
        and harness["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
        "pinned runtime mount changed",
    )
    _expect(
        harness["host_config"]
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
        "outer harness profile changed",
    )
    lineage = harness["image_lineage"]
    parent, child = lineage["parent"], lineage["child"]
    _expect(
        set(lineage) == {"parent", "child", "added_layers"}
        and set(parent) == set(child) == {"id", "rootfs_type", "layers"}
        and parent["id"] == _P35B_IMAGE
        and child["id"] == _P36A_IMAGE
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and all(_digest(layer) for layer in parent["layers"] + child["layers"])
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.5b parent/P3.6a child lineage changed",
    )
    return harness


def _verify_artifacts(value: Mapping[str, Any]) -> None:
    _expect(set(value) == {"installed", "collector"}, "artifact closure changed")
    installed = value["installed"]
    _expect(
        isinstance(installed, list) and len(installed) == len(_ARTIFACTS),
        "installed artifact count changed",
    )
    by_source = {item["source"]["path"]: item for item in installed}
    _expect(set(by_source) == set(_ARTIFACTS), "source artifact paths changed")
    for source_path, installed_path in _ARTIFACTS.items():
        item = by_source[source_path]
        _expect(set(item) == {"source", "installed"}, "artifact fields changed")
        source, target = item["source"], item["installed"]
        source_mode = "0555" if source_path.endswith(".sh") else "0444"
        target_mode = "0755" if "/libexec/" in installed_path else "0644"
        _file(source, path=source_path, uid=0, gid=0, mode=source_mode)
        _file(target, path=installed_path, uid=0, gid=0, mode=target_mode)
        _expect(
            source["digest"] == target["digest"] and source["bytes"] == target["bytes"],
            f"source/install binding changed: {installed_path}",
        )
    collector = value["collector"]
    expected = {
        "probe": (
            "/src/scripts/runtime_active_lineage_openclaw_systemd_probe.py",
            "0555",
        ),
        "dockerfile": (
            "/src/benchmark/runtime-active-lineage-openclaw-systemd/Dockerfile",
            "0444",
        ),
        "recipe": (
            "/src/scripts/capture_runtime_active_lineage_openclaw_systemd.sh",
            "0555",
        ),
    }
    _expect(set(collector) == set(expected), "collector closure changed")
    for name, (path, mode) in expected.items():
        _file(collector[name], path=path, uid=0, gid=0, mode=mode)


def _verify_identities(value: Mapping[str, Any]) -> dict[str, int]:
    _expect(set(value) == {"broker", "runtime", "sensor"}, "identity set changed")
    result: dict[str, int] = {}
    for name, identity in value.items():
        _expect(
            set(identity) == {"uid", "gid"}
            and _positive(identity["uid"])
            and _positive(identity["gid"]),
            f"identity changed: {name}",
        )
        result[f"{name}_uid"] = identity["uid"]
        result[f"{name}_gid"] = identity["gid"]
    _expect(
        len({result[f"{name}_uid"] for name in value}) == 3
        and result["broker_gid"] == result["runtime_gid"]
        and result["sensor_gid"] != result["runtime_gid"],
        "service principals overlap",
    )
    return result


def _verify_runtime_profile(
    document: Mapping[str, Any],
    harness: Mapping[str, Any],
    *,
    skill_path: str = _SKILL_PATH,
    skill_digest: str = _SKILL_DIGEST,
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
        set(profile) == {"digest", "document", "skill", "executable"},
        "profile fields changed",
    )
    parsed = runtime_process_profile(profile["document"])
    expected_cgroup = (
        f"/docker/{harness['container_id']}/system.slice/"
        "aragorn-openclaw-profile.service"
    )
    _expect(
        profile["digest"] == parsed.digest
        and parsed.runtime_digest == _RUNTIME_DIGEST
        and parsed.executable_digest == _NODE_DIGEST
        and str(parsed.skill_path) == skill_path
        and parsed.cgroup == expected_cgroup,
        "runtime profile changed",
    )
    _file(profile["skill"], path=skill_path, uid=0, gid=0, mode="0444")
    _file(profile["executable"], path=_NODE, uid=0, gid=0, mode="0755")
    _expect(
        profile["skill"]["digest"] == skill_digest
        and profile["executable"]["digest"] == _NODE_DIGEST,
        "profile files changed",
    )
    return {"digest": parsed.digest, "document": profile["document"], **profile}


def _grant_document(
    value: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    skill_digest: str = _SKILL_DIGEST,
) -> dict[str, Any]:
    _expect(
        set(value)
        == {"digest", "document", "bindings", "initial_state", "final_state"},
        "grant fields changed",
    )
    grant = value["document"]
    _expect(
        value["digest"] == canonical_digest(grant)
        and parse_runtime_capability_grant(
            canonical_json(grant), grant["issued_at_unix"]
        )
        == grant
        and grant["runtime_profile_digest"] == profile["digest"]
        and grant["runtime_digest"] == _RUNTIME_DIGEST
        and grant["active_skill_digest"] == skill_digest
        and grant["sensor_digest"] == _SENSOR_DIGEST
        and grant["expires_at_unix"] - grant["issued_at_unix"] == 241,
        "root capability grant changed",
    )
    return grant


def _record(value: Mapping[str, Any], *, stale: bool) -> dict[str, Any]:
    _expect(
        set(value) == {"digest", "document", "file"}, "active record fields changed"
    )
    document = value["document"]
    parsed = parse_active_runtime_record(canonical_json(document))
    _expect(
        value["digest"] == canonical_digest(document) and parsed == document,
        "active record digest changed",
    )
    _file(
        value["file"],
        path=f"{_INSTALL_ROOT}/.aragorn-active-runtime.json",
        uid=0,
        gid=0,
        mode="0444",
    )
    _expect(
        value["file"]["digest"] == value["digest"]
        and value["file"]["bytes"] == len(canonical_json(document)),
        "active record file changed",
    )
    if stale:
        _expect(
            document["schema"] == ACTIVE_RUNTIME_SCHEMA, "stale record schema changed"
        )
    return document


def _verify_active_install(
    value: Mapping[str, Any],
    grant: Mapping[str, Any],
    profile: Mapping[str, Any],
    ids: Mapping[str, int],
    *,
    fixture_authority: str = _FIXTURE_AUTHORITY,
    target_name: str = _TARGET_NAME,
    skill_digest: str = _SKILL_DIGEST,
) -> dict[str, Any]:
    fields = {
        "authority",
        "construction",
        "record",
        "stale_record",
        "transaction",
        "tree_entry",
        "paths",
        "coherent_snapshot",
        "verified_lineage",
    }
    _expect(
        set(value) == fields
        and value["authority"] == value["construction"] == fixture_authority,
        "root-assembled fixture authority changed",
    )
    record = _record(value["record"], stale=False)
    stale_record = _record(value["stale_record"], stale=True)
    transaction = value["transaction"]
    tree_entry = value["tree_entry"]
    _expect(
        record["authority"] == stale_record["authority"] == ACTIVE_RUNTIME_AUTHORITY
        and record["transaction"] == transaction
        and {
            **stale_record["transaction"],
            "tree_digest": transaction["tree_digest"],
        }
        == transaction
        and stale_record["transaction"]["tree_digest"] != transaction["tree_digest"],
        "stale/coherent active transaction relation changed",
    )
    expected_tree = {
        "path": "SKILL.md",
        "size": profile["skill"]["bytes"],
        "digest": skill_digest,
        "executable": False,
    }
    _expect(
        tree_entry == expected_tree
        and transaction["tree_digest"] == canonical_digest([tree_entry])
        and transaction["context_digest"] == grant["install_context_digest"]
        and transaction["manifest_digest"] == grant["source_manifest_digest"]
        and transaction["operation"] == "install"
        and transaction["expected_active"] is None
        and transaction["destination"]["target_name"] == target_name,
        "protected transaction or tree binding changed",
    )
    version_name = (
        f"{transaction['context_id'][7:]}-{transaction['manifest_digest'][7:]}"
    )
    expected_version = f".aragorn-versions/{target_name}/{version_name}"
    paths = {
        "root": _INSTALL_ROOT,
        "record": f"{_INSTALL_ROOT}/.aragorn-active-runtime.json",
        "active_link": f"{_INSTALL_ROOT}/{target_name}",
        "versions": f"{_INSTALL_ROOT}/.aragorn-versions",
        "target_versions": f"{_INSTALL_ROOT}/.aragorn-versions/{target_name}",
        "version": f"{_INSTALL_ROOT}/{expected_version}",
        "skill": f"{_INSTALL_ROOT}/{expected_version}/SKILL.md",
    }
    _expect(
        transaction["version_path"] == expected_version and value["paths"] == paths,
        "protected install paths changed",
    )
    snapshot = value["coherent_snapshot"]
    _expect(
        set(snapshot) == {"before", "after", "stable"}
        and snapshot["stable"] is True
        and snapshot["before"] == snapshot["after"]
        and set(snapshot["before"]) == set(paths),
        "coherent path identities changed",
    )
    states = snapshot["before"]
    contracts = {
        "root": ("directory", 0, ids["runtime_gid"], "0750", None),
        "record": ("file", 0, 0, "0444", None),
        "active_link": ("symlink", 0, 0, "0777", expected_version),
        "versions": ("directory", 0, 0, "0755", None),
        "target_versions": ("directory", 0, 0, "0755", None),
        "version": ("directory", 0, 0, "0555", None),
        "skill": ("file", 0, 0, "0444", None),
    }
    for name, (kind, uid, gid, mode, target) in contracts.items():
        _path_identity(states[name], paths[name], kind, uid, gid, mode, target=target)
    _expect(
        states["root"]["device"] == transaction["destination"]["root_device"]
        and states["root"]["inode"] == transaction["destination"]["root_inode"]
        and states["skill"]["size"] == tree_entry["size"],
        "protected root or skill metadata changed",
    )
    lineage = value["verified_lineage"]
    expected_lineage_fields = {
        "schema",
        "authority",
        "active_record_digest",
        "context_digest",
        "manifest_digest",
        "tree_digest",
        "version_path",
        "target_name",
        "root_device",
        "root_inode",
        "active_link_device",
        "active_link_inode",
        "version_device",
        "version_inode",
        "skill_device",
        "skill_inode",
        "runtime_skill_path",
        "active_skill_digest",
    }
    _expect(
        set(lineage) == expected_lineage_fields
        and lineage["schema"] == VERIFIED_LINEAGE_SCHEMA
        and lineage["authority"] == VERIFIED_LINEAGE_AUTHORITY
        and lineage["active_record_digest"] == canonical_digest(record)
        and lineage["context_digest"] == transaction["context_digest"]
        and lineage["manifest_digest"] == transaction["manifest_digest"]
        and lineage["tree_digest"] == transaction["tree_digest"]
        and lineage["version_path"] == transaction["version_path"]
        and lineage["target_name"] == target_name
        and lineage["runtime_skill_path"] == profile["document"]["skill_path"]
        and lineage["active_skill_digest"] == skill_digest
        and lineage["root_device"] == states["root"]["device"]
        and lineage["root_inode"] == states["root"]["inode"]
        and lineage["active_link_device"] == states["active_link"]["device"]
        and lineage["active_link_inode"] == states["active_link"]["inode"]
        and lineage["version_device"] == states["version"]["device"]
        and lineage["version_inode"] == states["version"]["inode"]
        and lineage["skill_device"] == states["skill"]["device"]
        and lineage["skill_inode"] == states["skill"]["inode"],
        "verified active lineage changed",
    )
    return {
        "transaction": transaction,
        "tree_entry": tree_entry,
        "paths": paths,
        "states": states,
        "lineage": lineage,
    }


def _path_identity(
    value: Mapping[str, Any],
    path: str,
    kind: str,
    uid: int,
    gid: int,
    mode: str,
    *,
    target: str | None,
) -> None:
    fields = {"path", "type", "device", "inode", "uid", "gid", "mode", "nlink", "size"}
    if target is not None:
        fields.add("target")
    _expect(
        set(value) == fields and value["path"] == path, f"path identity changed: {path}"
    )
    metadata = {name: value[name] for name in fields - {"path", "target"}}
    _metadata(
        metadata,
        kind=kind,
        uid=uid,
        gid=gid,
        mode=mode,
        size=None,
        nlink=1 if kind in {"file", "symlink"} else None,
    )
    _expect(target is None or value["target"] == target, f"link target changed: {path}")


def _verify_grant(
    value: Mapping[str, Any],
    grant: Mapping[str, Any],
    profile: Mapping[str, Any],
    active: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    bindings = value["bindings"]
    transaction = active["transaction"]
    expected = {
        "source_manifest_digest": {
            "grant": grant["source_manifest_digest"],
            "transaction": transaction["manifest_digest"],
            "matches": True,
        },
        "install_context_digest": {
            "grant": grant["install_context_digest"],
            "transaction": transaction["context_digest"],
            "matches": True,
        },
        "active_skill_digest": {
            "grant": grant["active_skill_digest"],
            "runtime_profile": profile["skill"]["digest"],
            "installed": active["tree_entry"]["digest"],
            "matches": True,
        },
        "tree_digest": {
            "transaction": transaction["tree_digest"],
            "reconstructed": canonical_digest([active["tree_entry"]]),
            "matches": True,
        },
        "runtime_profile_digest": {
            "grant": grant["runtime_profile_digest"],
            "profile": profile["digest"],
            "matches": True,
        },
    }
    _expect(bindings == expected, "grant binding summary changed")
    initial, final = value["initial_state"], value["final_state"]
    _retained(initial)
    _retained(final)
    grant_digest = canonical_digest(grant)
    _expect(
        _validated_grant_state(initial["document"], grant_digest) == initial["document"]
        and initial["document"]["status"] == "AVAILABLE"
        and _validated_grant_state(final["document"], grant_digest) == final["document"]
        and final["document"]["status"] == "CONSUMED",
        "grant state transition changed",
    )
    return {"initial": initial, "final": final}


def _verify_deployment(
    value: Mapping[str, Any],
    ids: Mapping[str, int],
    harness: Mapping[str, Any],
    active: Mapping[str, Any],
) -> dict[str, int]:
    fields = {
        "systemd_verify",
        "activation",
        "directories",
        "gateway",
        "units",
        "processes",
        "security",
        "sockets",
        "legacy_routes",
    }
    _expect(
        set(value) == fields
        and value["systemd_verify"] == {"exit_code": 0, "stdout": "", "stderr": ""},
        "deployment closure changed",
    )
    _expect(
        set(value["activation"]) == {"stale", "coherent"}
        and all(
            set(item) == {"exit_code", "stdout", "stderr"}
            and item["exit_code"] == 0
            and item["stdout"] == ""
            for item in value["activation"].values()
        ),
        "activation failed",
    )
    directories = value["directories"]
    contracts = {
        "runtime_action": (0, 0, "0755"),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "protected_effects": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "staging": (ids["broker_uid"], ids["broker_uid"], "0700"),
        "protected_install_parent": (0, ids["runtime_gid"], "0750"),
        "protected_install_root": (0, ids["runtime_gid"], "0750"),
    }
    _expect(set(directories) == set(contracts), "directory closure changed")
    for name, (uid, gid, mode) in contracts.items():
        _metadata(
            directories[name],
            kind="directory",
            uid=uid,
            gid=gid,
            mode=mode,
            size=None,
            nlink=None,
        )
    _expect(
        directories["protected_install_root"]["device"]
        == active["states"]["root"]["device"]
        and directories["protected_install_root"]["inode"]
        == active["states"]["root"]["inode"],
        "live protected root identity changed",
    )
    gateways = value["gateway"]
    _expect(set(gateways) == {"stale", "coherent"}, "gateway epochs changed")
    gateway = gateways["coherent"]
    _expect(
        gateway["cgroup"]
        == f"/docker/{harness['container_id']}/system.slice/aragorn-openclaw-profile.service",
        "gateway cgroup changed",
    )
    units, processes = value["units"], value["processes"]
    _expect(
        set(units)
        == {"stale_broker", "stale_sensor", "coherent_broker", "coherent_sensor"}
        and set(processes) == {"gateway", "broker", "sensor"},
        "service closure changed",
    )
    broker_pid = int(units["coherent_broker"]["MainPID"])
    sensor_pid = int(units["coherent_sensor"]["MainPID"])
    _expect(
        broker_pid == processes["broker"]["pid"]
        and sensor_pid == processes["sensor"]["pid"]
        and gateway["pid"] == processes["gateway"]["pid"],
        "service process identity changed",
    )
    return {
        "gateway_pid": gateway["pid"],
        "broker_pid": broker_pid,
        "sensor_pid": sensor_pid,
    }


def _verify_cases(
    value: Mapping[str, Any],
    grant: Mapping[str, Any],
    profile: Mapping[str, Any],
    active: Mapping[str, Any],
    states: Mapping[str, Mapping[str, Any]],
    ids: Mapping[str, int],
    deployment: Mapping[str, int],
    *,
    skill_digest: str = _SKILL_DIGEST,
) -> None:
    _expect(
        set(value) == {"stale_active_record", "coherent_active_record"},
        "case closure changed",
    )
    stale = value["stale_active_record"]
    stale_checks = {
        "driver",
        "client_error",
        "client_conservative_indeterminate",
        "frontend_write_preceded_reset",
        "broker_not_submitted",
        "grant_available",
        "broker_state_unchanged",
        "no_target",
        "no_pending_or_receipt",
        "no_effect_files",
        "live_verifier_rejected",
    }
    _expect(
        set(stale)
        == {
            "status",
            "driver",
            "checks",
            "grant_state_before",
            "grant_state_after",
            "effects",
        }
        and stale["status"] == "PASS"
        and set(stale["checks"]) == stale_checks
        and all(item is True for item in stale["checks"].values()),
        "stale case checks changed",
    )
    stale_result = _driver_result(
        stale["driver"], "stale-active-record", "CLIENT_ERROR", "NOT_SUBMITTED", 1
    )
    _expect(
        stale_result["schema"] == "aragorn/runtime-action-client-error/v1"
        and stale_result["authority"]
        == "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and stale_result["effect_status"] == "INDETERMINATE"
        and stale_result["message"] == "broker transport failed: ECONNRESET",
        "stale client result changed",
    )
    _expect(
        stale["grant_state_before"] == stale["grant_state_after"] == states["initial"],
        "stale request changed the AVAILABLE grant",
    )
    stale_effects = stale["effects"]
    _expect(
        set(stale_effects) == {"before", "after", "verification_error", "peer_trace"}
        and stale_effects["before"] == stale_effects["after"]
        and stale_effects["after"]["target_lexists"] is False
        and stale_effects["after"]["target"] is None
        and stale_effects["after"]["protected_entries"] == []
        and stale_effects["after"]["staging_entries"] == []
        and stale_effects["after"]["profile_pending_exists"] is False
        and stale_effects["after"]["profile_receipt_exists"] is False
        and stale_effects["verification_error"]["type"]
        == "RuntimeActionObservationPublisherError",
        "stale request produced an effect",
    )
    trace = stale_effects["peer_trace"]
    _expect(set(trace) == {"broker"}, "stale peer trace closure changed")
    broker_trace = trace["broker"]
    _expect(
        set(broker_trace) == {"raw", "raw_digest", "peer_credentials"}
        and broker_trace["peer_credentials"] == []
        and broker_trace["raw_digest"]
        == "sha256:" + hashlib.sha256(broker_trace["raw"].encode()).hexdigest(),
        "stale request reached the broker",
    )

    coherent = value["coherent_active_record"]
    coherent_checks = {
        "driver",
        "allow_created",
        "grant_consumed",
        "lease_bound",
        "receipt_bound",
        "runtime_bound",
        "target_created",
        "no_pending_or_staging",
        "lineage_record_bound",
        "lineage_identities_stable",
        "runtime_secret_absent",
    }
    _expect(
        set(coherent)
        == {
            "status",
            "driver",
            "checks",
            "grant_state_before",
            "grant_state_after",
            "effects",
            "result",
            "receipt",
            "target",
        }
        and coherent["status"] == "PASS"
        and set(coherent["checks"]) == coherent_checks
        and all(item is True for item in coherent["checks"].values())
        and coherent["grant_state_before"] == states["initial"]
        and coherent["grant_state_after"] == states["final"],
        "coherent case state changed",
    )
    result = _driver_result(
        coherent["driver"], "coherent-active-record", "ALLOW", "CREATED", 0
    )
    _expect(
        result == coherent["result"]
        and result["schema"] == "aragorn/runtime-action-broker-result/v1"
        and result["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and result["verdict"] == "ALLOW"
        and result["effect_status"] == "CREATED"
        and result["reason_codes"] == []
        and result["target_name"] == _TARGET,
        "coherent broker result changed",
    )
    final = states["final"]["document"]
    claim = final["claim"]
    lease = claim["lease"]
    receipt = coherent["receipt"]
    _retained(receipt)
    receipt_document = receipt["document"]
    profile_result = final["result"]["profile_result"]
    _expect(
        lease["grant_digest"] == canonical_digest(grant)
        and lease["runtime_profile_digest"] == profile["digest"]
        and lease["runtime_digest"] == _RUNTIME_DIGEST
        and lease["active_skill_digest"] == skill_digest
        and lease["sensor_digest"] == _SENSOR_DIGEST
        and lease["operation_digest"] == grant["operation_digest"]
        and lease["payload_digest"] == "sha256:" + hashlib.sha256(_PAYLOAD).hexdigest()
        and receipt["digest"] == profile_result["profile_receipt_digest"]
        and receipt_document["submission_digest"] == lease["submission_digest"]
        and receipt_document["runtime_attribution_digest"]
        == lease["runtime_attribution_digest"]
        and receipt_document["broker_result"] == result
        and receipt_document["broker_result_digest"] == canonical_digest(result)
        and receipt_document["runtime_attribution"]["pid"] == deployment["gateway_pid"]
        and receipt_document["runtime_attribution"]["profile_digest"]
        == profile["digest"]
        and receipt_document["runtime_attribution"]["active_skill_digest"]
        == skill_digest,
        "lease or receipt binding changed",
    )
    target = coherent["target"]
    _file(
        target,
        path=f"{_EFFECT_ROOT}/{_TARGET}",
        uid=ids["broker_uid"],
        gid=ids["runtime_gid"],
        mode="0400",
    )
    _expect(
        target["digest"] == lease["payload_digest"]
        and target["bytes"] == len(_PAYLOAD),
        "created target changed",
    )
    effects = coherent["effects"]
    _expect(
        set(effects) == {"before", "after"}
        and effects["before"]["target_lexists"] is False
        and effects["after"]["target_lexists"] is True
        and effects["after"]["target"] == target
        and effects["after"]["protected_entries"] == [_TARGET]
        and effects["after"]["staging_entries"] == []
        and effects["after"]["profile_pending_exists"] is False
        and effects["after"]["profile_receipt_exists"] is True
        and active["lineage"]["active_skill_digest"] == lease["active_skill_digest"],
        "coherent effect changed",
    )


def _driver_result(
    value: Mapping[str, Any],
    scenario_id: str,
    verdict: str,
    effect_status: str,
    exit_code: int,
) -> Mapping[str, Any]:
    fields = {
        "input",
        "status",
        "driver_exit_code",
        "driver_stdout",
        "driver_stderr",
        "driver_elapsed_ns",
        "driver",
    }
    _expect(
        set(value) == fields
        and value["status"] == "PASS"
        and value["driver_exit_code"] == exit_code
        and value["driver_stdout"] == value["driver_stderr"] == ""
        and _positive(value["driver_elapsed_ns"])
        and value["input"]
        == {
            "schema": "aragorn/openclaw-profile-driver-input/v1",
            "scenario": {
                "id": scenario_id,
                "target_name": _TARGET,
                "content": _PAYLOAD.decode(),
                "expected_verdict": verdict,
                "expected_effect_status": effect_status,
            },
        },
        f"driver input changed: {scenario_id}",
    )
    driver = value["driver"]
    _expect(
        driver["schema"] == "aragorn/openclaw-profile-driver-output/v1",
        f"driver output changed: {scenario_id}",
    )
    retained = driver["scenario"]["proof"]["retained_tool_result"]
    _expect(
        set(retained) == {"schema", "message", "result"}
        and retained["schema"] == "aragorn/runtime-action-tool-result-text/v1"
        and isinstance(retained["message"], str)
        and isinstance(retained["result"], Mapping),
        f"retained tool result changed: {scenario_id}",
    )
    return retained["result"]


def _verify_timing(
    value: Mapping[str, Any], cases: Mapping[str, Any], grant: Mapping[str, Any]
) -> None:
    _expect(
        set(value)
        == {
            "grant_lifetime_seconds",
            "sensor_deadline_ms",
            "client_deadline_ms",
            "stale_driver_elapsed_ns",
            "coherent_driver_elapsed_ns",
        }
        and value["grant_lifetime_seconds"]
        == grant["expires_at_unix"] - grant["issued_at_unix"]
        == 241
        and value["sensor_deadline_ms"] == 500
        and value["client_deadline_ms"] == 750
        and value["stale_driver_elapsed_ns"]
        == cases["stale_active_record"]["driver"]["driver_elapsed_ns"]
        and value["coherent_driver_elapsed_ns"]
        == cases["coherent_active_record"]["driver"]["driver_elapsed_ns"]
        and _positive(value["stale_driver_elapsed_ns"])
        and _positive(value["coherent_driver_elapsed_ns"]),
        "timing contract changed",
    )
