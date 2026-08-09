"""Exact-profile qualification for protected OpenClaw prompt reconstruction."""

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
_ROUTE = "ADM-02/reload/missing-prompt-blob-rebuild"
_EVIDENCE_SCHEMA = "aragorn/openclaw-protected-prompt-rebuild-observation/v1"
_EVIDENCE_DIGEST = (
    "sha256:0dd80dbf1f4e3c6526c8ec1694cda1ba3cdfa8db4822503b9e4877d960498afb"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:d67707b0292c0171b472be818d39ec7411cb40269e630e16d602a78cef835762"
)
_HELPER_DIGEST = (
    "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b"
)
_PROBE_DIGEST = (
    "sha256:f8fcfe8af1243c558ad071f7a001f84dca5cd219cdb069e64af6d48aac32d7eb"
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
_SESSION_STORE = "/profile/state/agents/main/sessions/sessions.json"
_PROMPT = (
    b"\n\nThe following skills provide specialized instructions for specific tasks.\n"
    b"Use the read tool to load a skill's file when the task matches its description.\n"
    b"If a skill's <version> differs from a previous turn, re-read its SKILL.md before using it.\n"
    b"When a skill file references a relative path, resolve it against the skill directory "
    b"(parent of SKILL.md / dirname of the path) and use that absolute path in tool commands.\n\n"
    b"<available_skills>\n"
    b"  <skill>\n"
    b"    <name>requesting-code-review</name>\n"
    b"    <description>Inert protected archive replacement target v1.</description>\n"
    b"    <location>/profile/workspace/skills/requesting-code-review/SKILL.md</location>\n"
    b"    <version>sha256:1a13f195721f8fa7</version>\n"
    b"  </skill>\n"
    b"</available_skills>"
)
_PROMPT_DIGEST = "sha256:" + hashlib.sha256(_PROMPT).hexdigest()
_PROMPT_PATH = (
    "/profile/state/agents/main/sessions/skills-prompts/sha256/bb/"
    "bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c.txt"
)
_LIMITATIONS = [
    "EXACT_PINNED_PROFILE_AND_SINGLE_CAPTURE_ONLY",
    "ONE_MISSING_PROMPT_BLOB_CACHE_MISS_RECONSTRUCTED",
    "SESSION_STORE_MTIME_CHANGED_WITH_IDENTICAL_BYTES_TO_FORCE_CACHE_MISS",
    "NORMAL_TURNS_FAIL_AFTER_PROMPT_BUILD_WITHOUT_PROVIDER_CREDENTIALS",
    "PROTECTED_SOURCE_CONFIGURATION_RUNTIME_AND_GATEWAY_PRESERVED",
    "NATIVE_ROUTE_OBSERVATION_NOT_BROKER_MEDIATED",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "OTHER_ADMISSION_ROUTES_NOT_QUALIFIED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "PHASE3_RUN_AND_EDR_AUTHORITY_NOT_ESTABLISHED",
]


def verify_openclaw_protected_prompt_rebuild(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one exact prompt cache reconstruction without aggregate authority."""

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
            raise AdmissionEvidenceError("prompt rebuild retention receipt changed")

        evidence = _read_exact(evidence_cas, _EVIDENCE_DIGEST, _EVIDENCE_SCHEMA)
        profile_raw = canonical_json(dict(route_profile)) + b"\n"
        if _digest(profile_raw) != _PROFILE_DIGEST:
            raise AdmissionEvidenceError("protected-consumer profile changed")
        archive._read_source_bytes(
            evidence_cas, _PROFILE_DIGEST, profile_raw, "protected-consumer profile"
        )
        helper_raw = archive._read_source_bytes(
            evidence_cas, _HELPER_DIGEST, None, "protected observation helper"
        )
        probe_raw = archive._read_source_bytes(
            evidence_cas, _PROBE_DIGEST, None, "protected prompt rebuild probe"
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
            helper_raw=helper_raw,
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
            f"invalid protected prompt rebuild evidence: {exc}"
        ) from exc

    return {
        "assurance": "SEMANTICALLY_VERIFIED_EXACT_PROFILE_PROMPT_BLOB_REBUILD",
        "bindings": {
            "configuration_digest": _CONFIG_DIGEST,
            "existing_target_digest": _TARGET_DIGEST,
            "helper_implementation_digest": _HELPER_DIGEST,
            "probe_implementation_digest": _PROBE_DIGEST,
            "profile_digest": _PROFILE_DIGEST,
            "protected_helper_implementation_digest": archive_digest,
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
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
            "observed_outcome": "EXACT_PROTECTED_PROMPT_BLOB_REBUILT",
            "status": "PASS",
        },
        "runtime": dict(route_profile["runtime"]),
        "schema": "aragorn/admission-protected-prompt-rebuild-route-qualification/v1",
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
    helper_raw: bytes,
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
            "volume": "aragorn-openclaw-p40-prompt-probe-v1",
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
    expected_containment = {
        "capabilities_dropped": ["ALL"],
        "cgroup_namespace_mode": "private",
        "command": [
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
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
        ],
        "container_id": (
            "5e67876fc1ade5c31b47079b830fc6b5d7dc3a3ee1382aab57a862a44611d5f9"
        ),
        "container_name": "aragorn-openclaw-p40-prompt-rebuild-v1",
        "container_started_at": "2026-08-09T05:54:44.1366199Z",
        "cpu_limit": 1_000_000_000,
        "effective_user": "1000:1000",
        "environment": [
            "HOME=/profile/home",
            "OPENCLAW_CONFIG_PATH=/profile/config/openclaw.json",
            "OPENCLAW_DISABLE_BUNDLED_PLUGINS=1",
            "OPENCLAW_NO_RESPAWN=1",
            "OPENCLAW_SKIP_CHANNELS=1",
            "OPENCLAW_SKIP_PROVIDERS=1",
            "OPENCLAW_STATE_DIR=/profile/state",
        ],
        "gateway_pid": 1,
        "gateway_start_time_ticks": "25190131",
        "gateway_token_present": True,
        "hostname": "aragorn-p40-prompt-rebuild-v1",
        "image_digest": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "ipc_mode": "private",
        "memory_limit": 1_073_741_824,
        "memory_swap_limit": 1_073_741_824,
        "mounts": expected_mounts,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_root_filesystem": True,
        "restart_count": 0,
        "supplementary_groups": ["982"],
        "tmpfs": {
            "/profile/home": (
                "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000"
            ),
            "/profile/state": (
                "rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=1000,gid=1000"
            ),
            "/profile/workspace": (
                "rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=1000,gid=1000"
            ),
            "/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777",
        },
        "ulimits": [{"Hard": 256, "Name": "nofile", "Soft": 256}],
    }
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-prompt-rebuild-retention/v1"
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
            "bytes": 51_313,
            "digest": _EVIDENCE_DIGEST,
            "path": (
                "benchmark/evidence/"
                "openclaw-v2026.7.1-protected-prompt-rebuild-2026-08-09.json"
            ),
            "recorded_at": evidence["recorded_at"],
            "run_nonce": evidence["run_nonce"],
        }
        or inputs["helper"]["digest"] != _HELPER_DIGEST
        or inputs["helper"]["bytes"] != len(helper_raw)
        or inputs["probe"]["digest"] != _PROBE_DIGEST
        or inputs["probe"]["bytes"] != len(probe_raw)
        or inputs["configuration"]["digest"] != _CONFIG_DIGEST
        or inputs["configuration"]["bytes"] != len(config_raw)
        or inputs["configuration"]["canonical_digest"]
        != _CONFIG_CANONICAL_DIGEST
        or inputs["existing_target"]["digest"] != _TARGET_DIGEST
        or inputs["existing_target"]["bytes"] != len(target_raw)
        or receipt["runtime"]["runtime_tree"] != _RUNTIME_TREE
        or containment != expected_containment
    ):
        raise AdmissionEvidenceError("prompt rebuild source closure changed")

    config = shared.load_runtime_profile(config_raw)
    if (
        canonical_json(config) + b"\n" != config_raw
        or canonical_digest(config) != _CONFIG_CANONICAL_DIGEST
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digests"]
        != {"helper": _HELPER_DIGEST, "probe": _PROBE_DIGEST}
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
        raise AdmissionEvidenceError("prompt rebuild source identity changed")


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(archive._ROOT_MOUNTS)
    ):
        raise AdmissionEvidenceError("prompt rebuild protected boundary changed")
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
        source="/docker/volumes/aragorn-openclaw-p40-prompt-probe-v1/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=[
            "protected-observation-v1.mjs",
            "protected-prompt-rebuild-probe.mjs",
        ],
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
        or canonical_digest(config["document"]) != _CONFIG_CANONICAL_DIGEST
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
        raise AdmissionEvidenceError("prompt rebuild protected configuration changed")


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
        raise AdmissionEvidenceError("prompt rebuild launcher changed")


def _verify_discovery(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        value["response"] != {"parsed": True, "value": archive._EXPECTED_DISCOVERY}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "info",
            "requesting-code-review",
            "--agent",
            "main",
            "--json",
        ]
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != archive._EXPECTED_DISCOVERY
    ):
        raise AdmissionEvidenceError("prompt rebuild discovery changed")


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
        or system["machineName"] != gateway["hostname"]
        or system["platform"] != "linux"
        or system["arch"] != "arm64"
        or system["nodeVersion"] != "v24.16.0"
        or system["port"] != 18_789
        or system["diskPath"] != "/profile/state"
        or system["diskTotalBytes"] != 33_554_432
    ):
        raise AdmissionEvidenceError("prompt rebuild system identity changed")


def _verify_snapshot(value: Mapping[str, Any]) -> None:
    blob = value["blob"]
    entry = value["entry"]
    prompt = value["prompt"]
    expected_ref = {
        "algorithm": "sha256",
        "bytes": len(_PROMPT),
        "hash": _PROMPT_DIGEST.removeprefix("sha256:"),
        "version": 1,
    }
    if (
        set(value) != {"blob", "entry", "prompt"}
        or entry["run_status"] != "failed"
        or entry["runtime_ms"] != 0
        or entry["started_at"] != entry["ended_at"]
        or not isinstance(entry["started_at"], int)
        or not isinstance(entry["snapshot_version"], int)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            entry["session_id"],
        )
        is None
        or entry["skill_filter"] != ["requesting-code-review"]
        or entry["skill_names"] != ["requesting-code-review"]
        or prompt
        != {
            "bytes": len(_PROMPT),
            "digest": _PROMPT_DIGEST,
            "exact_text": _PROMPT.decode(),
            "storage": "promptRef",
        }
        or blob["bytes"] != len(_PROMPT)
        or blob["digest"] != _PROMPT_DIGEST
        or blob["mode"] != "600"
        or re.fullmatch(r"[1-9][0-9]*", blob["mtime_ns"]) is None
        or blob["nlink"] != 1
        or blob["path"] != _PROMPT_PATH
        or blob["prompt_ref"] != expected_ref
    ):
        raise AdmissionEvidenceError("protected prompt snapshot changed")


def _verify_turn(
    turn: Mapping[str, Any], *, label: str, nonce: str, session_key: str
) -> None:
    run_id = f"aragorn-protected-prompt-rebuild-{label}-{nonce}"
    params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": f"Inert protected prompt rebuild {label}.",
        "sessionKey": session_key,
        "timeoutMs": 5000,
    }
    send = turn["send"]
    wait = turn["wait"]
    if (
        turn["confirmed"] is not True
        or turn["commands"] != [send["command"], wait["command"]]
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait["response"]["parsed"] is not True
        or wait["response"]["value"]["runId"] != run_id
        or wait["response"]["value"]["status"] != "ok"
        or not isinstance(wait["response"]["value"]["endedAt"], int)
        or send["command"]["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "chat.send",
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(params, sort_keys=True, separators=(",", ":")),
        ]
        or wait["command"]["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "agent.wait",
            "--json",
            "--timeout",
            "12000",
            "--params",
            json.dumps(
                {"runId": run_id, "timeoutMs": 10_000},
                sort_keys=True,
                separators=(",", ":"),
            ),
        ]
        or any(
            not shared._command_succeeded_clean(command)
            or not shared._command_output_is_exact(command)
            for command in turn["commands"]
        )
        or json.loads(send["command"]["stdout_excerpt"])
        != send["response"]["value"]
        or json.loads(wait["command"]["stdout_excerpt"])
        != wait["response"]["value"]
    ):
        raise AdmissionEvidenceError(f"protected prompt {label} turn changed")


def _verify_action(evidence: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    if evidence["route"] != {
        "action_id": "missing-prompt-blob-rebuild",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }:
        raise AdmissionEvidenceError("prompt rebuild route selection changed")
    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "missing-prompt-blob-rebuild"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or before["config_lock_before"]
        != {"exists": False, "path": f"{_CONFIG}.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["protected_root_trees_after"]
        != before["protected_root_trees_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
    ):
        raise AdmissionEvidenceError("prompt rebuild protected state changed")

    _verify_boundary(before["boundary_before"])
    archive._verify_fixture_tree(
        before["target_before"],
        root_path=_TARGET,
        digest=_TARGET_DIGEST,
        size=len(archive._TARGET_BYTES),
        tree_digest=_TARGET_TREE_DIGEST,
    )
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("prompt rebuild runtime tree changed")
    if (
        before["config_tree_before"]["ready"] is not True
        or len(before["config_tree_before"]["entries"]) != 1
        or before["config_tree_before"]["entries"][0]["path"] != "openclaw.json"
    ):
        raise AdmissionEvidenceError("prompt rebuild config residue changed")

    gateway = before["gateway_process_before"]
    if (
        gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["hostname"] != receipt["containment"]["hostname"]
        or gateway["no_new_privileges"] != "1"
        or gateway["pid"] != receipt["containment"]["gateway_pid"] == 1
        or gateway["seccomp"] != "2"
        or gateway["start_time_ticks"]
        != receipt["containment"]["gateway_start_time_ticks"]
    ):
        raise AdmissionEvidenceError("prompt rebuild gateway identity changed")

    _verify_openclaw(before["openclaw_before"])
    _verify_discovery(before["discovery_before"])
    _verify_discovery(after["discovery_after"])
    if (
        before["discovery_before"]["response"]
        != after["discovery_after"]["response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("prompt rebuild discovery changed")
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
        raise AdmissionEvidenceError("prompt rebuild version changed")

    initial = after["initial_snapshot"]
    rebuilt = after["rebuilt_snapshot"]
    _verify_snapshot(initial)
    _verify_snapshot(rebuilt)
    nonce = evidence["run_nonce"]
    session_key = f"agent:main:aragorn-protected-prompt-rebuild-{nonce}"
    _verify_turn(after["initial_turn"], label="initial", nonce=nonce, session_key=session_key)
    _verify_turn(after["rebuild_turn"], label="rebuild", nonce=nonce, session_key=session_key)
    initial_blob_ms = int(initial["blob"]["mtime_ns"]) // 1_000_000
    rebuilt_blob_ms = int(rebuilt["blob"]["mtime_ns"]) // 1_000_000
    initial_wait_ms = after["initial_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_wait_ms = after["rebuild_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_send_ms = int(
        _time(after["rebuild_turn"]["send"]["command"]["started_at"]).timestamp()
        * 1_000
    )
    if (
        rebuilt["entry"]["session_id"] != initial["entry"]["session_id"]
        or rebuilt["entry"]["snapshot_version"]
        != initial["entry"]["snapshot_version"]
        or rebuilt["entry"]["started_at"] <= initial["entry"]["ended_at"]
        or rebuilt["blob"]["prompt_ref"] != initial["blob"]["prompt_ref"]
        or rebuilt["blob"]["path"] != initial["blob"]["path"]
        or rebuilt["prompt"] != initial["prompt"]
        or not initial["entry"]["ended_at"] <= initial_blob_ms <= initial_wait_ms
        or not rebuild_send_ms <= rebuilt["entry"]["ended_at"]
        or not rebuilt["entry"]["ended_at"] <= rebuilt_blob_ms <= rebuild_wait_ms
    ):
        raise AdmissionEvidenceError("prompt reconstruction identity changed")

    invalidation = after["invalidation"]
    store_before = invalidation["store_before"]
    store_after = invalidation["store_after_rewrite"]
    invalidation_started_ms = int(_time(invalidation["started_at"]).timestamp() * 1_000)
    invalidation_completed_ms = int(
        _time(invalidation["completed_at"]).timestamp() * 1_000
    )
    store_after_ms = int(store_after["mtime_ns"]) // 1_000_000
    if (
        invalidation["blob_exists_after_unlink"] is not False
        or invalidation["blob_path"] != _PROMPT_PATH
        or store_before["path"] != _SESSION_STORE
        or store_before["mode"] != "600"
        or store_before["nlink"] != 1
        or store_after["path"] != _SESSION_STORE
        or store_after["mode"] != "600"
        or store_after["nlink"] != 1
        or store_after["bytes"] != store_before["bytes"]
        or store_after["digest"] != store_before["digest"]
        or int(store_after["mtime_ns"]) <= int(store_before["mtime_ns"])
        or not invalidation_started_ms <= store_after_ms <= invalidation_completed_ms
        or int(rebuilt["blob"]["mtime_ns"]) <= int(store_after["mtime_ns"])
        or int(rebuilt["blob"]["mtime_ns"]) <= int(initial["blob"]["mtime_ns"])
        or _time(invalidation["started_at"])
        >= _time(invalidation["completed_at"])
    ):
        raise AdmissionEvidenceError("prompt cache invalidation changed")

    commands = action["commands"]
    expected_commands = [
        version,
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        *after["initial_turn"]["commands"],
        *after["rebuild_turn"]["commands"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected_commands
        or any(
            _time(current["completed_at"]) > _time(next_["started_at"])
            for current, next_ in pairwise(commands)
        )
        or _time(after["initial_turn"]["commands"][-1]["completed_at"])
        > _time(invalidation["started_at"])
        or _time(invalidation["completed_at"])
        > _time(after["rebuild_turn"]["commands"][0]["started_at"])
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("prompt rebuild command causality changed")
