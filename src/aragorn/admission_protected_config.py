"""Exact-profile qualification for protected OpenClaw config activation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_runtime_profile as shared
from .admission_evidence import AdmissionEvidenceError, _read_exact, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_PROFILE = "openclaw-2026.7.1-protected-consumer"
_ROUTE = "ADM-02/update/config-entry-activation"
_EVIDENCE_SCHEMA = "aragorn/openclaw-protected-config-activation-observation/v1"
_EVIDENCE_DIGEST = (
    "sha256:5989b46e66a1e057ca778b303b6083da5d12f12bcdaa88eb07c47fa9cc316575"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:32aa7037c32b20b36a97094a1479456465bdfa6136da056008e70c01e2868db7"
)
_PROBE_DIGEST = (
    "sha256:49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234"
)
_CONFIG_DIGEST = archive._CONFIG_DIGEST
_CONFIG_CANONICAL_DIGEST = archive._CONFIG_CANONICAL_DIGEST
_PROFILE_DIGEST = archive._PROFILE_DIGEST
_TARGET_DIGEST = archive._TARGET_DIGEST
_TARGET_TREE_DIGEST = archive._TARGET_TREE_DIGEST
_RUNTIME_TREE = archive._RUNTIME_TREE
_OPENCLAW_DIGEST = archive._OPENCLAW_DIGEST
_ARCHIVE_IMPLEMENTATION_DIGEST = (
    "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f"
)
_SHARED_IMPLEMENTATION_DIGEST = (
    "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b"
)
_CONFIG = "/profile/config/openclaw.json"
_TARGET = "/profile/workspace/skills/requesting-code-review"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_LIMITATIONS = [
    "EXACT_PINNED_PROFILE_AND_SINGLE_CAPTURE_ONLY",
    "VALID_NATIVE_CONFIG_UPDATE_DENIED_AT_READ_ONLY_LOCK_PATH",
    "CONFIGURATION_ACTIVE_SKILL_DISCOVERY_AND_GATEWAY_PRESERVED",
    "NATIVE_ROUTE_DENIAL_NOT_BROKER_MEDIATED",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "OTHER_ADMISSION_ROUTES_NOT_QUALIFIED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "PHASE3_RUN_AND_EDR_AUTHORITY_NOT_ESTABLISHED",
]


def verify_openclaw_protected_config_activation(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one exact pre-effect config denial without aggregate authority."""

    try:
        archive_digest = _implementation_digest(archive)
        shared_digest = _implementation_digest(shared)
        if archive_digest != _ARCHIVE_IMPLEMENTATION_DIGEST:
            raise AdmissionEvidenceError("protected helper implementation changed")
        if shared_digest != _SHARED_IMPLEMENTATION_DIGEST:
            raise AdmissionEvidenceError("shared route verifier changed")
        shared.validate_openclaw_protected_consumer_profile(
            route_profile,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        if canonical_digest(source_receipt) != _RECEIPT_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("config activation retention receipt changed")

        evidence = _read_exact(evidence_cas, _EVIDENCE_DIGEST, _EVIDENCE_SCHEMA)
        profile_raw = canonical_json(dict(route_profile)) + b"\n"
        if _digest(profile_raw) != _PROFILE_DIGEST:
            raise AdmissionEvidenceError("protected-consumer profile changed")
        archive._read_source_bytes(
            evidence_cas, _PROFILE_DIGEST, profile_raw, "protected-consumer profile"
        )
        probe_raw = archive._read_source_bytes(
            evidence_cas, _PROBE_DIGEST, None, "config activation probe"
        )
        config_raw = archive._read_source_bytes(
            evidence_cas, _CONFIG_DIGEST, None, "protected configuration"
        )
        target_raw = archive._read_source_bytes(
            evidence_cas,
            _TARGET_DIGEST,
            archive._TARGET_BYTES,
            "protected active skill",
        )
        _verify_source_closure(
            source_receipt,
            evidence,
            probe_raw=probe_raw,
            config_raw=config_raw,
            target_raw=target_raw,
        )
        _verify_action(evidence, source_receipt)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid protected config activation evidence: {exc}"
        ) from exc

    return {
        "assurance": "SEMANTICALLY_VERIFIED_EXACT_PROFILE_CONFIG_WRITE_DENIAL",
        "bindings": {
            "configuration_digest": _CONFIG_DIGEST,
            "existing_target_digest": _TARGET_DIGEST,
            "profile_digest": _PROFILE_DIGEST,
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "protected_helper_implementation_digest": archive_digest,
            "shared_verifier_implementation_digest": shared_digest,
            "source_evidence_digest": _EVIDENCE_DIGEST,
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_LIMITATIONS),
        "profile": _PROFILE,
        "route": {
            "id": _ROUTE,
            "observed_outcome": "DENIED_PRE_EFFECT_CONFIGURATION_PRESERVED",
            "status": "PASS",
        },
        "runtime": dict(route_profile["runtime"]),
        "schema": "aragorn/admission-protected-config-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _implementation_digest(module: Any) -> str:
    return _digest(Path(module.__file__).read_bytes())


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_source_closure(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    probe_raw: bytes,
    config_raw: bytes,
    target_raw: bytes,
) -> None:
    inputs = receipt["inputs"]
    containment = receipt["containment"]
    expected_mounts = [
        {
            "destination": "/probe",
            "read_only": True,
            "volume": "aragorn-openclaw-p38-config-probe-v2",
        },
        {
            "destination": "/profile/config",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-config-v1",
        },
        {
            "destination": "/profile/home/.agents/skills",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-guard-v1",
        },
        {
            "destination": "/profile/state/extensions",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-guard-v1",
        },
        {
            "destination": "/profile/state/plugin-skills",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-guard-v1",
        },
        {
            "destination": "/profile/state/skills",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-guard-v1",
        },
        {
            "destination": "/profile/workspace/.agents/skills",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-guard-v1",
        },
        {
            "destination": "/profile/workspace/skills",
            "read_only": True,
            "volume": "aragorn-openclaw-p3-archive-target-v1",
        },
        {
            "destination": "/runtime",
            "read_only": True,
            "volume": "aragorn-openclaw-2026-7-1-runtime",
        },
    ]
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-config-activation-retention/v1"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_RAW_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
        or receipt["status"] != "RAW_OBSERVATION_ONLY"
        or receipt["admission_profile_eligible"] is not False
        or receipt["installer_work_eligible"] is not False
        or receipt["phase3_exit_eligible"] is not False
        or receipt["results"]
        != {"fail": [], "not_tested": [], "observed": [_ROUTE], "pass": []}
        or receipt["evidence"]
        != {
            "bytes": 32_656,
            "digest": _EVIDENCE_DIGEST,
            "path": "benchmark/evidence/openclaw-v2026.7.1-protected-config-activation-2026-08-07.json",
            "recorded_at": evidence["recorded_at"],
            "run_nonce": evidence["run_nonce"],
        }
        or inputs["probe"]["digest"] != _PROBE_DIGEST
        or inputs["probe"]["bytes"] != len(probe_raw)
        or inputs["configuration"]["digest"] != _CONFIG_DIGEST
        or inputs["configuration"]["bytes"] != len(config_raw)
        or inputs["configuration"]["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or inputs["existing_target"]["digest"] != _TARGET_DIGEST
        or inputs["existing_target"]["bytes"] != len(target_raw)
        or receipt["runtime"]["runtime_tree"] != _RUNTIME_TREE
        or containment["capabilities_dropped"] != ["ALL"]
        or containment["cgroup_namespace_mode"] != "private"
        or containment["cpu_limit"] != 1_000_000_000
        or containment["effective_user"] != "1000:1000"
        or containment["gateway_pid"] != 1
        or containment["hostname"] != "aragorn-p38-config-activation-v5"
        or containment["image_digest"]
        != "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        or containment["ipc_mode"] != "private"
        or containment["memory_limit"] != 1_073_741_824
        or containment["memory_swap_limit"] != 1_073_741_824
        or containment["mounts"] != expected_mounts
        or containment["network_mode"] != "none"
        or containment["no_new_privileges"] is not True
        or containment["pids_limit"] != 128
        or containment["privileged"] is not False
        or containment["read_only_root_filesystem"] is not True
        or containment["restart_count"] != 0
        or containment["supplementary_groups"] != ["982"]
    ):
        raise AdmissionEvidenceError("config activation source closure changed")

    config = shared.load_runtime_profile(config_raw)
    if (
        canonical_json(config) + b"\n" != config_raw
        or canonical_digest(config) != _CONFIG_CANONICAL_DIGEST
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digest"] != _PROBE_DIGEST
        or evidence["runtime_binding"]
        != {
            "commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": _OPENCLAW_DIGEST,
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("config activation source identity changed")


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(archive._ROOT_MOUNTS)
    ):
        raise AdmissionEvidenceError("config activation protected boundary changed")
    for name, (target, source, entries) in archive._ROOT_MOUNTS.items():
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=target,
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=entries,
        )
    archive._verify_ro_mount(
        boundary["probe"],
        target="/probe",
        source="/docker/volumes/aragorn-openclaw-p38-config-probe-v2/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["protected-config-activation-probe.mjs"],
    )
    archive._verify_ro_mount(
        boundary["configuration"]["mount"],
        target="/profile/config",
        source="/docker/volumes/aragorn-openclaw-p3-archive-config-v1/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["openclaw.json"],
    )
    archive._verify_ro_mount(
        boundary["runtime"],
        target="/runtime",
        source="/docker/volumes/aragorn-openclaw-2026-7-1-runtime/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    config = boundary["configuration"]
    if (
        config["ready"] is not True
        or config["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or config["file"]["path"] != _CONFIG
        or config["file"]["type"] != "file"
        or config["file"]["uid"] != 0
        or config["file"]["gid"] != 982
        or config["file"]["mode"] != "440"
        or config["file"]["nlink"] != 1
        or config["file"]["size"] != 316
        or config["file"]["digest"] != _CONFIG_DIGEST
        or config["file"]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("protected configuration changed")


def _verify_action(evidence: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    if evidence["route"] != {
        "action_id": "config-entry-activation",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }:
        raise AdmissionEvidenceError("config activation route selection changed")
    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "config-entry-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["config_lock_before"] != {"exists": False, "path": f"{_CONFIG}.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != after["boundary_after"]["configuration"]
        or after["config_after"] != before["config_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
    ):
        raise AdmissionEvidenceError("config activation pre-effect state changed")

    _verify_boundary(before["boundary_before"])
    archive._verify_fixture_tree(
        before["target_before"],
        root_path=_TARGET,
        digest=_TARGET_DIGEST,
        size=len(archive._TARGET_BYTES),
        tree_digest=_TARGET_TREE_DIGEST,
    )
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("config activation runtime tree changed")

    gateway = before["gateway_process_before"]
    if (
        after["gateway_process_after"] != gateway
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["hostname"] != receipt["containment"]["hostname"]
        or gateway["no_new_privileges"] != "1"
        or gateway["pid"] != receipt["containment"]["gateway_pid"] == 1
        or gateway["seccomp"] != "2"
        or gateway["start_time_ticks"]
        != receipt["containment"]["gateway_start_time_ticks"]
    ):
        raise AdmissionEvidenceError("config activation gateway identity changed")

    _verify_openclaw(before["openclaw_before"])
    _verify_discovery(before["discovery_before"])
    _verify_discovery(after["discovery_after"])
    if (
        before["discovery_before"]["response"] != after["discovery_after"]["response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("config activation discovery changed")

    _verify_system(before["system_info_before"], gateway)
    _verify_system(after["system_info_after"], gateway)
    version = before["version"]
    if (
        version["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not shared._command_succeeded_clean(version)
        or not shared._command_output_is_exact(version)
        or version["stdout_excerpt"] != "OpenClaw 2026.7.1 (2d2ddc4)\n"
    ):
        raise AdmissionEvidenceError("config activation version changed")

    update = after["update"]
    command = update["command"]
    response = {
        "error": {
            "code": "UNAVAILABLE",
            "message": (
                "Error: EROFS: read-only file system, open "
                "'/profile/config/openclaw.json.lock': code=EROFS"
            ),
            "retryable": False,
            "type": "gateway_request_error",
        },
        "ok": False,
    }
    update_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.update",
        "--json",
        "--timeout",
        "5000",
        "--params",
        '{"enabled":true,"skillKey":"requesting-code-review"}',
    ]
    if (
        update["params"] != {"enabled": True, "skillKey": "requesting-code-review"}
        or update["response"] != {"parsed": True, "value": response}
        or command["argv"] != update_argv
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
        or command["stderr_excerpt"] != ""
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != response
    ):
        raise AdmissionEvidenceError("protected config write denial changed")

    commands = action["commands"]
    expected_commands = [
        version,
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        command,
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected_commands
        or any(
            _time(current["completed_at"]) > _time(next_["started_at"])
            for current, next_ in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("config activation command causality changed")


def _verify_openclaw(value: Mapping[str, Any]) -> None:
    if (
        value["path"] != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or value["exists"] is not True
        or value["type"] != "file"
        or value["uid"] != 0
        or value["gid"] != 0
        or value["mode"] != "755"
        or value["nlink"] != 1
        or value["size"] != 23_463
        or value["digest"] != _OPENCLAW_DIGEST
        or value["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("config activation launcher changed")


def _verify_discovery(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        value["response"] != {"parsed": True, "value": archive._EXPECTED_DISCOVERY}
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != archive._EXPECTED_DISCOVERY
    ):
        raise AdmissionEvidenceError("config activation discovery changed")


def _verify_system(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    command = value["command"]
    response = value["response"]
    system = response["value"]
    if (
        command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ]
        or response["parsed"] is not True
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != system
        or system["pid"] != gateway["pid"]
        or system["hostname"] != gateway["hostname"]
        or system["platform"] != "linux"
        or system["arch"] != "arm64"
        or system["nodeVersion"] != "v24.16.0"
        or system["port"] != 18_789
        or system["diskPath"] != "/profile/state"
        or system["diskTotalBytes"] != 33_554_432
    ):
        raise AdmissionEvidenceError("config activation system identity changed")
