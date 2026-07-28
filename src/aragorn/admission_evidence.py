"""Semantic verification for one retained OpenClaw runtime-restart claim."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .admission_conformance import (
    AdmissionConformanceError,
    validate_admission_conformance,
)
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest

_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_PROBE_SCHEMA = "aragorn/openclaw-contained-restart-probe-evidence/v1"
_ENV_SCHEMA = "aragorn/openclaw-contained-restart-environment-evidence/v1"
_PROBE_DIGEST = (
    "sha256:f9b08c63b414b0f91b5cc14deeb91a86a8a0b4aa3151e52702395004dde7dcb3"
)
_ENV_DIGEST = "sha256:e67b2522a705d9f9efbd447da68aae61af6964f51dd9275d2d956688389ebbfa"
_EVIDENCE_PAIR = sorted((_ENV_DIGEST, _PROBE_DIGEST))
_ADMITTED_DIGEST = (
    "sha256:5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d"
)
_TEST_TOKEN = "aragorn-contained-restart-token-v1"
_INVALID_TEST_TOKEN = "aragorn-invalid-test-token-v1"
_ARAGORN_BINDING = {
    "implementation_digest": "sha256:979f1a06b87e26459faba52ce7bb94ceb89e3a39e212c7d2e4f6a418e41d9a71",
    "policy_digest": "sha256:f23061d06e0f2d28357f74989b9ea21f7270882d60963d60341a3494a98ec764",
}
_STATUSES = {
    "DET-01/identical-canonical-input-replay": "NOT_TESTED",
    "ADM-01/exact-admitted-bytes": "NOT_TESTED",
    "ADM-02/install": "PASS",
    "ADM-02/update": "NOT_TESTED",
    "ADM-02/direct-write": "PASS",
    "ADM-02/rename": "PASS",
    "ADM-02/symlink": "PASS",
    "ADM-02/auto-discovery": "PASS",
    "ADM-02/reload": "NOT_TESTED",
    "ADM-02/restart": "PASS",
    "ADM-03/policy-failure": "PASS",
    "ADM-03/policy-tampering": "PASS",
}
_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/update": ["UPDATE_PATH_NOT_TESTED"],
    "ADM-02/reload": ["LIVE_RELOAD_NOT_TESTED"],
}


class AdmissionEvidenceError(AdmissionConformanceError):
    """The retained OpenClaw restart evidence is invalid."""


def verify_openclaw_restart_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify only ADM-02/restart; carried claims and installer authority stay out of scope."""
    try:
        status = validate_admission_conformance(document)
        if status != "NOT_TESTED" or document["decision"] != {
            "status": "NOT_TESTED",
            "installer_work_eligible": False,
        }:
            raise AdmissionEvidenceError(
                "partial semantic closure cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if {key: value["status"] for key, value in formal.items()} != _STATUSES:
            raise AdmissionEvidenceError("partial profile claim set changed")
        reasons = {
            key: value["reason_codes"]
            for key, value in formal.items()
            if value["status"] == "NOT_TESTED"
        }
        if reasons != _REASONS:
            raise AdmissionEvidenceError("partial profile reason set changed")
        for key, scenario in formal.items():
            expected = _EVIDENCE_PAIR if _STATUSES[key] == "PASS" else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact retained proof pair"
                )
        probe = _read_exact(evidence_cas, _PROBE_DIGEST, _PROBE_SCHEMA)
        environment = _read_exact(evidence_cas, _ENV_DIGEST, _ENV_SCHEMA)
        _verify_bindings(document, probe, environment)
        _verify_carried_context(probe)
        _verify_restart(probe)
        _verify_environment(probe, environment)
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid partial admission semantic closure: {exc}"
        ) from exc


def _read_exact(cas: CAS, digest: str, schema: str) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_EVIDENCE_BYTES)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"evidence is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != schema:
        raise AdmissionEvidenceError("evidence schema pair is unsupported")
    if _canonical_bytes(document) + b"\n" != raw:
        raise AdmissionEvidenceError("evidence is not canonical JSON plus LF")
    return document


def _verify_bindings(
    receipt: Mapping[str, Any], probe: Mapping[str, Any], environment: Mapping[str, Any]
) -> None:
    if receipt["recorded_at"] != probe["recorded_at"]:
        raise AdmissionEvidenceError("receipt and probe timestamps differ")
    runtime = probe["runtime"]
    expected_runtime = {
        "name": "openclaw-contained",
        "version": "2026.7.1",
        "repository_url": "https://github.com/openclaw/openclaw",
        "commit": runtime["commit"],
        "source_tree_digest": runtime["runtime_tree"]["tree_digest"],
    }
    if receipt["bindings"]["runtime"] != expected_runtime:
        raise AdmissionEvidenceError("runtime binding changed")
    adapter = probe["adapter"]
    if (
        adapter["configuration_digest"] != canonical_digest(adapter["configuration"])
        or adapter["implementation_digest"]
        != canonical_digest(adapter["implementation"])
        or receipt["bindings"]["adapter"]
        != {
            "name": "openclaw-contained-profile-restart",
            "implementation_digest": adapter["implementation_digest"],
            "configuration_digest": adapter["configuration_digest"],
        }
    ):
        raise AdmissionEvidenceError("adapter binding changed")
    image_digest = environment["container"]["image"]["platform_manifest_digest"]
    if (
        environment["os_profile_digest"] != canonical_digest(environment["isolation"])
        or receipt["bindings"]["environment"]
        != {
            "worker_digest": image_digest,
            "os_profile_digest": environment["os_profile_digest"],
        }
        or receipt["bindings"]["aragorn"] != _ARAGORN_BINDING
    ):
        raise AdmissionEvidenceError("environment or Aragorn binding changed")


def _verify_carried_context(probe: Mapping[str, Any]) -> None:
    adm03_profile = probe["adm03_profile"]
    adm03 = adm03_profile["evidence"]
    if (
        adm03_profile["digest"] != _line_digest(adm03)
        or adm03["schema"] != "aragorn/openclaw-contained-adm03-probe-evidence/v1"
        or adm03["runtime"] != probe["runtime"]
        or adm03["adapter"]["configuration"] != probe["adapter"]["configuration"]
    ):
        raise AdmissionEvidenceError("carried ADM-03 context binding changed")
    if [(item["id"], item["status"]) for item in adm03["scenarios"]] != [
        ("ADM-03/policy-failure", "PASS"),
        ("ADM-03/policy-tampering", "PASS"),
    ]:
        raise AdmissionEvidenceError("carried ADM-03 context changed")
    contained_profile = adm03["contained_profile"]
    contained = contained_profile["evidence"]
    if (
        contained_profile["digest"] != _line_digest(contained)
        or contained["schema"] != "aragorn/openclaw-contained-profile-probe-evidence/v1"
        or contained["runtime"] != probe["runtime"]
        or contained["adapter"]["configuration"] != probe["adapter"]["configuration"]
    ):
        raise AdmissionEvidenceError("carried contained context binding changed")
    if [(item["id"], item["status"]) for item in contained["scenarios"]] != [
        ("ADM-01/exact-admitted-bytes", "PASS"),
        ("ADM-02/install", "PASS"),
        ("ADM-02/direct-write", "PASS"),
        ("ADM-02/rename", "PASS"),
        ("ADM-02/symlink", "PASS"),
        ("ADM-02/auto-discovery", "PASS"),
        ("ADM-02/restart", "PASS"),
    ]:
        raise AdmissionEvidenceError("carried contained context changed")


def _verify_restart(probe: Mapping[str, Any]) -> None:
    if [(item["id"], item["status"]) for item in probe["scenarios"]] != [
        ("ADM-02/restart", "PASS")
    ]:
        raise AdmissionEvidenceError("outer restart claim changed")
    scenario = probe["scenarios"][0]
    commands, evidence = scenario["commands"], scenario["evidence"]
    response = evidence["restart_response"]
    restart_command = commands["restart"]
    if (
        restart_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "restart",
            "--safe",
            "--json",
        ]
        or restart_command["exit_code"] != 0
        or restart_command["stdout_bytes"] != 0
        or json.loads(restart_command["stderr"]) != response
        or response["ok"] is not True
        or response["result"] != "scheduled"
        or response["preflight"]
        != {
            "blockers": [],
            "counts": {
                "activeTasks": 0,
                "cronRuns": 0,
                "embeddedRuns": 0,
                "pendingReplies": 0,
                "queueSize": 0,
                "totalActive": 0,
            },
            "safe": True,
            "summary": "safe to restart now",
        }
        or {
            key: response["restart"][key]
            for key in ("coalesced", "mode", "ok", "pid", "reason", "signal")
        }
        != {
            "coalesced": False,
            "mode": "emit",
            "ok": True,
            "pid": 1,
            "reason": "gateway.restart.safe",
            "signal": "SIGUSR1",
        }
    ):
        raise AdmissionEvidenceError("safe restart was not proven")
    expected_auth_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "system.info",
        "--token",
        _INVALID_TEST_TOKEN,
        "--json",
        "--timeout",
        "5000",
    ]
    for key in ("authentication_before", "authentication_after"):
        auth = commands[key]
        if (
            auth["status"] != "PASS"
            or auth["command"]["argv"] != expected_auth_argv
            or auth["command"]["exit_code"] != 1
            or "unauthorized" not in auth["command"]["stderr"]
            or auth["response"]["ok"] is not False
            or auth["response"]["error"]["code"] != 1008
        ):
            raise AdmissionEvidenceError("authentication denial changed")
    lifecycle = evidence["lifecycle"]
    order = (
        "first_ready",
        "signal",
        "restarting",
        "shutdown",
        "restart_mode",
        "second_ready",
    )
    offsets = [lifecycle[key]["offset"] for key in order]
    if offsets != sorted(set(offsets)):
        raise AdmissionEvidenceError("restart lifecycle is not strictly ordered")
    times = [_time(lifecycle[key]["time"]) for key in order]
    restart_started = _time(commands["restart"]["started_at"])
    restart_completed = _time(commands["restart"]["completed_at"])
    if (
        times != sorted(times)
        or restart_started > times[1]
        or times[2] > restart_completed
        or restart_completed > times[3]
    ):
        raise AdmissionEvidenceError("restart lifecycle timing is not causal")
    messages = [lifecycle[key]["message"] for key in order]
    if (
        messages[:3]
        != [
            "gateway ready",
            "signal SIGUSR1 received",
            "received SIGUSR1; restarting",
        ]
        or not messages[3].startswith("shutdown completed cleanly ")
        or not messages[4].startswith("restart mode: in-process restart ")
        or messages[5] != "gateway ready"
    ):
        raise AdmissionEvidenceError("restart lifecycle markers changed")
    if (
        lifecycle["process_before"] != lifecycle["process_after"]
        or lifecycle["process_before"]
        != {
            "cmdline": ["openclaw-gateway"],
            "pid": 1,
            "start_time_ticks": lifecycle["process_before"]["start_time_ticks"],
        }
        or evidence["protected_state_before"] != evidence["protected_state_after"]
        or evidence["skills"]["raw_bytes_equal"] is not True
        or evidence["skills"]["projection_before"]
        != evidence["skills"]["projection_after"]
    ):
        raise AdmissionEvidenceError("post-restart protected state changed")
    clients = evidence["rpc_clients"]
    skills_before = commands["skills_before"]
    skills_after = commands["skills_after"]
    expected_skills_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
        "--params",
        '{"agentId":"main"}',
    ]
    for key in ("skills_before", "skills_after"):
        if clients[key] != {
            field: commands[key][field]
            for field in ("completed_at", "pid", "started_at")
        }:
            raise AdmissionEvidenceError("RPC client binding changed")
    if (
        clients["skills_before"]["pid"] <= 1
        or clients["skills_after"]["pid"] <= 1
        or clients["skills_before"]["pid"] == clients["skills_after"]["pid"]
        or _time(clients["skills_before"]["completed_at"])
        > _time(commands["restart"]["started_at"])
        or _time(clients["skills_after"]["started_at"])
        < _time(lifecycle["second_ready"]["time"])
        or skills_before["argv"] != expected_skills_argv
        or skills_after["argv"] != expected_skills_argv
        or skills_before["exit_code"] != 0
        or skills_after["exit_code"] != 0
        or skills_before["stdout_bytes"] <= 0
        or skills_before["stdout_bytes"] != skills_after["stdout_bytes"]
        or skills_before["stdout_digest"] != skills_after["stdout_digest"]
    ):
        raise AdmissionEvidenceError("fresh post-restart RPC was not proven")
    system_info = evidence["system_info"]
    expected_system_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "system.info",
        "--json",
        "--timeout",
        "5000",
    ]
    if any(
        commands[key]["argv"] != expected_system_argv
        or commands[key]["exit_code"] != 0
        or commands[key]["stdout_bytes"] <= 0
        for key in ("system_before", "system_after")
    ):
        raise AdmissionEvidenceError("system identity RPC changed")
    if set(system_info) != {"before", "after"} or any(
        item["pid"] != 1
        or item["port"] != 18789
        or item["platform"] != "linux"
        or item["nodeVersion"] != "v24.16.0"
        for item in system_info.values()
    ):
        raise AdmissionEvidenceError("gateway system identity changed")
    _verify_skill_projection(evidence["skills"]["projection_after"])
    protected = evidence["protected_state_before"]
    if (
        protected["admitted_digest"] != _ADMITTED_DIGEST
        or protected["implementation"] != probe["adapter"]["implementation"]
        or protected["policy_digest"]
        != probe["adapter"]["implementation"]["contained_probe_digest"]
    ):
        raise AdmissionEvidenceError("protected restart identity changed")
    _verify_gateway_log(evidence["gateway_log"], lifecycle, order)


def _verify_skill_projection(projection: Mapping[str, Any]) -> None:
    if (
        projection["agent_id"] != "main"
        or projection["agent_skill_filter"] != ["aragorn-admitted"]
        or projection["managed_skills_dir"] != "/profile/state/skills"
        or projection["workspace_dir"] != "/profile/workspace"
    ):
        raise AdmissionEvidenceError("skill projection context changed")
    admitted_entries = [
        item for item in projection["skills"] if item["name"] == "aragorn-admitted"
    ]
    expected_admitted = {
        "base_dir": "/profile/state/skills/aragorn-admitted",
        "blocked_by_agent_filter": False,
        "blocked_by_allowlist": False,
        "command_visible": True,
        "disabled": False,
        "eligible": True,
        "file_path": "/profile/state/skills/aragorn-admitted/SKILL.md",
        "model_visible": True,
        "name": "aragorn-admitted",
        "source": "openclaw-managed",
        "user_invocable": True,
    }
    if admitted_entries != [expected_admitted]:
        raise AdmissionEvidenceError("admitted skill projection changed")
    effective = [
        item
        for item in projection["skills"]
        if not item["disabled"]
        and not item["blocked_by_allowlist"]
        and not item["blocked_by_agent_filter"]
        and (item["eligible"] or item["model_visible"] or item["command_visible"])
    ]
    if effective != [expected_admitted]:
        raise AdmissionEvidenceError("effective admitted skill changed")
    if any(
        not item["blocked_by_agent_filter"]
        or item["model_visible"]
        or item["command_visible"]
        for item in projection["skills"]
        if item["name"] != "aragorn-admitted"
    ):
        raise AdmissionEvidenceError("unadmitted skill became visible")


def _verify_gateway_log(
    log: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    order: tuple[str, ...],
) -> None:
    raw = ("\n".join(log["lines"]) + "\n").encode("utf-8")
    if (
        len(raw) != log["bytes"]
        or "sha256:" + hashlib.sha256(raw).hexdigest() != log["digest"]
        or _TEST_TOKEN.encode() in raw
        or _INVALID_TEST_TOKEN.encode() in raw
    ):
        raise AdmissionEvidenceError("gateway log closure changed")
    records = {}
    offset = 0
    for line in log["lines"]:
        records[offset] = json.loads(line, object_pairs_hook=_reject_duplicates)
        offset += len(line.encode("utf-8")) + 1
    if offset != log["bytes"] or any(
        records[lifecycle[key]["offset"]].get("message") != lifecycle[key]["message"]
        or records[lifecycle[key]["offset"]].get("time") != lifecycle[key]["time"]
        or records[lifecycle[key]["offset"]].get("traceId")
        != lifecycle[key]["trace_id"]
        or lifecycle[key]["connection_id"] is not None
        or lifecycle[key]["request_id"] is not None
        for key in order
    ):
        raise AdmissionEvidenceError("lifecycle markers are not bound to the log")


def _verify_environment(
    probe: Mapping[str, Any], environment: Mapping[str, Any]
) -> None:
    container = environment["container"]
    execution = environment["container"]["probe_exec"]
    isolation = environment["isolation"]
    state = container["state"]
    expected_command = [
        "/bin/sh",
        "-c",
        "/usr/local/bin/node /probe/contained-probe.mjs > "
        "/tmp/contained-profile.json && /usr/local/bin/node "
        "/probe/adm03-probe.mjs > /tmp/contained-adm03.json && exec "
        "/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs "
        "gateway run --allow-unconfigured --auth token --bind loopback "
        "--port 18789 --tailscale off --ws-log full",
    ]
    if (
        execution["command"] != ["/usr/local/bin/node", "/probe/restart-probe.mjs"]
        or execution["exit_code"] != 0
        or execution["recorded_at"] != probe["recorded_at"]
        or execution["stdout"] != {"bytes": 125_866, "digest": _PROBE_DIGEST}
        or execution["user"] != "1000:1000"
        or container["command"] != expected_command
        or container["working_dir"] != "/profile/workspace"
        or (state["status"], state["exit_code"], state["oom_killed"])
        != ("exited", 0, False)
    ):
        raise AdmissionEvidenceError("probe execution environment changed")
    controls = {
        "cap_drop": ["ALL"],
        "cgroupns_mode": "private",
        "devices": [],
        "ipc_mode": "private",
        "memory_bytes": 1_073_741_824,
        "memory_swap_bytes": 1_073_741_824,
        "nano_cpus": 1_000_000_000,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_rootfs": True,
        "runtime": "runc",
        "user": "1000:1000",
    }
    expected_environment = {
        "HOME": "/profile/home",
        "NODE_VERSION": "24.16.0",
        "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
        "OPENCLAW_GATEWAY_TOKEN": _TEST_TOKEN,
        "OPENCLAW_STATE_DIR": "/profile/state",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "YARN_VERSION": "1.22.22",
    }
    expected_tmpfs = {
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
    }
    expected_mounts = {
        "/acquisition": "aragorn-openclaw-2026-7-1-acquisition",
        "/probe": "aragorn-openclaw-2026-7-1-contained-probe-v7",
        "/profile/config": "aragorn-openclaw-2026-7-1-contained-profile-config-v1",
        "/profile/home/.agents": "aragorn-openclaw-2026-7-1-contained-guard-v1",
        "/profile/state/plugin-skills": (
            "aragorn-openclaw-2026-7-1-contained-guard-v1"
        ),
        "/profile/state/skills": "aragorn-openclaw-2026-7-1-contained-admitted-v1",
        "/profile/workspace/.agents": ("aragorn-openclaw-2026-7-1-contained-guard-v1"),
        "/profile/workspace/skills": ("aragorn-openclaw-2026-7-1-contained-guard-v1"),
        "/runtime": "aragorn-openclaw-2026-7-1-runtime",
    }
    mounts = {
        item["destination"]: {
            "read_only": item["read_only"],
            "source": item["source"],
            "type": item["type"],
        }
        for item in isolation["mounts"]
    }
    if (
        any(isolation[key] != value for key, value in controls.items())
        or isolation["environment"] != expected_environment
        or isolation["tmpfs"] != expected_tmpfs
        or isolation["ulimits"] != [{"hard": 256, "name": "nofile", "soft": 256}]
        or len(isolation["mounts"]) != 9
        or len(mounts) != 9
        or mounts
        != {
            destination: {
                "read_only": True,
                "source": source,
                "type": "volume",
            }
            for destination, source in expected_mounts.items()
        }
        or container["image"]
        != {
            "index_digest": (
                "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
            "platform_manifest_digest": (
                "sha256:1df790a7d590f617d0d3c2cd84cbe18b5400ff972dd9701670f7e5a4f1634e52"
            ),
            "reference": (
                "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
        }
        or environment["docker"]["platform_manifest_resolution"]["digest"]
        != container["image"]["platform_manifest_digest"]
        or environment["docker"]["assurance"]
        != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
    ):
        raise AdmissionEvidenceError("contained isolation proof changed")


def _line_digest(document: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(document) + b"\n").hexdigest()


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise AdmissionEvidenceError("timestamp is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AdmissionEvidenceError("timestamp lacks timezone")
    return parsed


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"non-finite JSON value: {value}")
