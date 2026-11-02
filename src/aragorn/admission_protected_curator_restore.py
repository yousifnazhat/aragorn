"""Route-only qualification for the external-authority curator restore guard."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/curator-restore-activation"
_OUTCOME = (
    "GATEWAY_AND_LOCAL_CLI_FALLBACK_RESTORE_DENIED_BY_EXTERNAL_AUTHORITY_"
    "WITH_EXACT_ARCHIVED_LIFECYCLE_ROW_PRESERVED"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:83f09f927758c3540d6ea0fcebbc9a9f75100f24a7555ef2cf0440c6a72088d2"
)
_EVIDENCE = {
    "bytes": 147_410,
    "canonical_bytes": 148_159,
    "canonical_digest": (
        "sha256:a83152b27a33145c5d1845d3cbd94425571b8ac8620b839f18a7b590eb270816"
    ),
    "digest": (
        "sha256:be454127f57e834816e3252bd9fd96e2c1cafc80c66ca31e63ce54762e6134c5"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-curator-restore-denial-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-curator-restore-denial-observation/v1",
}
_SOURCES = {
    "profile": (
        "sha256:12e2fb6298d0d968a10aeb2c8e9f902cc6d3146d4bb51054ae194556c7acfb8d",
        3_932,
    ),
    "runtime_lock": (
        "sha256:6021e62e5dfd93fea9cc87f52ca65bdd964472916a99c9f58a913e94a635dd49",
        4_596,
    ),
    "configuration": (
        "sha256:701da2485f2844603c13b40c56876984de5ff9cdc22927f1a5bcd218ba369751",
        359,
    ),
    "probe": (
        "sha256:ecc2649b40cc9e6106181a12a31b12999a596d634f7a1ee9cc658adc70c9192a",
        24_502,
    ),
    "helper": (
        "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
        13_609,
    ),
}
_PROFILE_CANONICAL_DIGEST = (
    "sha256:6f9f5fca41c70c8e94484ff65763297a52a57b122d9527222330462e2ed30ec8"
)
_LOCK_CANONICAL_DIGEST = (
    "sha256:ccf796e0aaa5139de4cdad1a939d42c08886dc8c84d602bfcbbdbf014444ee13"
)
_CONFIG_CANONICAL_DIGEST = (
    "sha256:417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e"
)
_DISCOVERY_RESPONSE_DIGEST = (
    "sha256:b66d5c96e96d8b14ad099286d27250f3a4bef51483f24a5c2dc0b834b99abe1a"
)
_DISCOVERY_TARGET_DIGEST = (
    "sha256:47b3bf4884981f6814262eb8466dbc2c74ff6e94871b5bb6ea691c21dfd7f1a7"
)
_DISCOVERY_STDOUT_DIGEST = (
    "sha256:ff7bd0fe667dff7c9e9f121bbbd9e27504b0d7e9ce5306e0e0f51c3e2c82a18a"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_TARGET = "requesting-code-review"
_TARGET_FILE = "/profile/workspace/skills/requesting-code-review/SKILL.md"
_AUTHORITY_ERROR = "Skill curator restore is delegated to an external authority"
_CLI_STDERR = (
    "gateway connect failed: GatewayClientRequestError: unauthorized: gateway token "
    "mismatch (set gateway.remote.token to match gateway.auth.token)\n"
    f"Error: {_AUTHORITY_ERROR}\n"
)
_ARCHIVED_ROW = {
    "archived_reason": "aragorn exact protected restore-authority fixture",
    "created_at_ms": 1,
    "pinned": 0,
    "skill_file": _TARGET_FILE,
    "skill_key": _TARGET,
    "skill_name": _TARGET,
    "state": "archived",
    "state_changed_at_ms": 2,
}
_STATUS_SKILL = {
    "archivedReason": _ARCHIVED_ROW["archived_reason"],
    "createdAtMs": 1,
    "lastUsedAtMs": None,
    "pinned": False,
    "skillFile": _TARGET_FILE,
    "skillKey": _TARGET,
    "skillName": _TARGET,
    "state": "archived",
    "stateChangedAtMs": 2,
    "useCount": 0,
}
_ROOT_SOURCES = {
    "extensions": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "managed_skills": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "personal_agents": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "plugin_skills": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "project_agents": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "workspace_skills": "/docker/volumes/aragorn-openclaw-p3-archive-target-v1/_data",
}
_LIMITATIONS = [
    "ONE_EXACT_PRIVATE_PATCHED_RUNTIME_CURATOR_RESTORE_DENIAL_ROUTE_ONLY",
    "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
    "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "TWENTY_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]
_CAPTURE_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
    "SHARED_DATABASE_DATA_VERSION_NOT_STABLE_ONLY_EXACT_SELECTED_LIFECYCLE_ROW_BOUND",
    "SINGLE_ROUTE_SINGLE_CAPTURE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_protected_curator_restore_denial(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify only the exact externally-authorized curator restore route."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        _verify_profile(profile, lock, inventory)
        sources = _read_sources(evidence_cas, profile, lock)
        evidence = _read_capture(evidence_cas)
        _verify_receipt(receipt, evidence, profile, lock)
        _verify_evidence(evidence, profile, lock, sources["configuration"])
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid protected curator restore evidence: {exc}"
        ) from exc

    routes = [
        {"id": item["id"], "status": "PASS" if item["id"] == _ROUTE else "NOT_TESTED"}
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_CURATOR_ROUTE_ONLY",
        "bindings": {
            "configuration_digest": _SOURCES["configuration"][0],
            "evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "evidence_digest": _EVIDENCE["digest"],
            "helper_digest": _SOURCES["helper"][0],
            "probe_digest": _SOURCES["probe"][0],
            "profile_digest": _SOURCES["profile"][0],
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_LIMITATIONS),
        "profile": {
            "counts": {"fail": 0, "not_tested": 20, "pass": 1},
            "name": profile["name"],
            "routes": routes,
        },
        "route": {
            "id": _ROUTE,
            "observed_outcome": _OUTCOME,
            "status": "PASS",
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-curator-restore-denial-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_blob(cas: CAS, digest: str, size: int, label: str) -> bytes:
    raw = cas.read(digest, max_bytes=size)
    if len(raw) != size or _digest(raw) != digest:
        raise AdmissionEvidenceError(f"{label} identity changed")
    return raw


def _read_sources(
    cas: CAS, profile: Mapping[str, Any], lock: Mapping[str, Any]
) -> dict[str, bytes]:
    values = {
        name: _read_blob(cas, digest, size, name)
        for name, (digest, size) in _SOURCES.items()
    }
    if (
        values["profile"] != canonical_json(profile) + b"\n"
        or values["runtime_lock"] != canonical_json(lock) + b"\n"
    ):
        raise AdmissionEvidenceError("profile or runtime lock retained bytes changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate curator capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid curator capture constant: {value}")


def _read_capture(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid curator capture JSON: {exc}") from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or document.get("schema") != _EVIDENCE["schema"]
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" == raw
    ):
        raise AdmissionEvidenceError("curator capture parsed identity changed")
    return document


def _verify_profile(
    profile: Mapping[str, Any], lock: Mapping[str, Any], inventory: Mapping[str, Any]
) -> None:
    route_ids = [
        f"{route['id']}/{path['id']}"
        for route in inventory["routes"]
        for path in route["paths"]
    ]
    if (
        canonical_digest(profile) != _PROFILE_CANONICAL_DIGEST
        or canonical_digest(lock) != _LOCK_CANONICAL_DIGEST
        or [item["id"] for item in profile["routes"]] != route_ids
        or len(route_ids) != 21
        or any(item["outcome"] != "NOT_TESTED" for item in profile["routes"])
        or profile["controls"]["curator_restore_authority"] != "external"
        or profile["decision"]["status"] != "NOT_TESTED"
        or any(
            value is not False
            for key, value in profile["decision"].items()
            if key != "status"
        )
        or lock["source"]["commit"] != profile["runtime"]["commit"]
        or lock["source"]["parent_commit"] != profile["runtime"]["source_parent_commit"]
        or lock["source"]["tree"] != profile["runtime"]["source_tree"]
        or lock["installed_runtime"]["openclaw_digest"]
        != "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
        or set(lock["compiled_guard"])
        != {"cli", "config", "curator", "gateway", "zod_schema"}
    ):
        raise AdmissionEvidenceError("restore-authority profile or lock changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> None:
    false_fields = (
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_01_eligible",
        "run_02_eligible",
        "run_eligible",
    )
    expected_evidence = {
        "bytes": _EVIDENCE["bytes"],
        "canonical_bytes": _EVIDENCE["canonical_bytes"],
        "canonical_digest": _EVIDENCE["canonical_digest"],
        "canonical_lf": False,
        "path": _EVIDENCE["path"],
        "raw_sha256": _EVIDENCE["digest"].removeprefix("sha256:"),
        "recorded_at": evidence["recorded_at"],
        "run_nonce": evidence["run_nonce"],
        "schema": evidence["schema"],
    }
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-session-snapshot-restore-authority-curator-denial-retention/v1"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"] != expected_evidence
        or receipt["observed_at"] != evidence["recorded_at"]
        or receipt["results"]
        != {
            "fail": [],
            "not_tested": receipt["results"]["not_tested"],
            "not_tested_count": 20,
            "observed": [_ROUTE],
            "pass": [],
        }
        or len(receipt["results"]["not_tested"]) != 20
        or _ROUTE in receipt["results"]["not_tested"]
        or receipt["inputs"]["profile"]["digest"] != _SOURCES["profile"][0]
        or receipt["inputs"]["runtime_lock"]["digest"] != _SOURCES["runtime_lock"][0]
        or receipt["inputs"]["configuration"]["digest"] != _SOURCES["configuration"][0]
        or receipt["inputs"]["probe"]["digest"] != _SOURCES["probe"][0]
        or receipt["inputs"]["helper"]["digest"] != _SOURCES["helper"][0]
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or receipt["runtime"]["runtime_tree"]
        != lock["installed_runtime"]["runtime_tree"]
    ):
        raise AdmissionEvidenceError("curator restore retention receipt changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    if (
        canonical_digest(evidence) != _EVIDENCE["canonical_digest"]
        or set(evidence)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "limitations",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["route"]
        != {
            "action_id": "curator-restore-authority-denial",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or evidence["implementation_digests"]
        != {"helper": _SOURCES["helper"][0], "probe": _SOURCES["probe"][0]}
        or evidence["limitations"] != _CAPTURE_LIMITATIONS
    ):
        raise AdmissionEvidenceError("curator restore observation identity changed")

    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    runtime = lock["installed_runtime"]
    expected_runtime = {
        "commit": profile["runtime"]["commit"],
        "node_path": _NODE,
        "openclaw_digest": runtime["openclaw_digest"],
        "openclaw_path": runtime["openclaw_path"],
        "runtime_tree_digest": runtime["runtime_tree"]["tree_digest"],
        "version": profile["runtime"]["version"],
    }
    if (
        action["id"] != "curator-restore-authority-denial"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or evidence["runtime_binding"] != expected_runtime
    ):
        raise AdmissionEvidenceError("curator restore action identity changed")

    config = json.loads(config_raw)
    _verify_boundary(before["boundary_before"], config)
    _verify_boundary(after["boundary_after"], config)
    if before["boundary_before"] != after["boundary_after"]:
        raise AdmissionEvidenceError("protected boundary changed during restore")
    _verify_stable_state(before, after, lock)
    _verify_commands(action, evidence["recorded_at"])
    _verify_denials(after)
    _verify_lifecycle(before, after)


def _verify_boundary(boundary: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    config_file = boundary["configuration"]["file"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or boundary["configuration"]["document"] != config
        or boundary["configuration"]["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or config_file["path"] != "/profile/config/openclaw.json"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["uid"] != 0
        or config_file["gid"] != 982
        or config_file["mode"] != "440"
        or config_file["nlink"] != 1
        or config_file["size"] != 359
        or config_file["digest"] != _SOURCES["configuration"][0]
        or config_file["digest_error"] is not None
        or config["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("external restore authority boundary changed")
    archive._verify_ro_mount(
        boundary["configuration"]["mount"],
        target="/profile/config",
        source="/docker/volumes/aragorn-openclaw-restore-authority-config-3eec2a5811e2/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["openclaw.json"],
    )
    archive._verify_ro_mount(
        boundary["probe"],
        target="/probe",
        source="/docker/volumes/aragorn-openclaw-restore-authority-probe-3eec2a5811e2/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=[
            "protected-curator-restore-denial-probe.mjs",
            "protected-observation-v1.mjs",
        ],
    )
    archive._verify_ro_mount(
        boundary["runtime"],
        target="/runtime",
        source="/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    for name, source in _ROOT_SOURCES.items():
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=runtime_profile._PROTECTED_ROOTS[name][0],
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=[_TARGET] if name == "workspace_skills" else [],
        )


def _verify_stable_state(
    before: Mapping[str, Any], after: Mapping[str, Any], lock: Mapping[str, Any]
) -> None:
    stable = (
        (before["gateway_process_before"], after["gateway_process_after"]),
        (before["target_before"], after["target_after"]),
        (before["config_lock_before"], after["config_lock_after"]),
        (before["config_tree_before"], after["config_tree_after"]),
        (before["modules_before"], after["modules_after"]),
        (before["openclaw_before"], after["openclaw_after"]),
        (before["protected_root_trees_before"], after["protected_root_trees_after"]),
        (before["runtime_tree_before"], after["runtime_tree_after"]),
    )
    if any(left != right for left, right in stable):
        raise AdmissionEvidenceError("curator restore stable state changed")
    gateway = before["gateway_process_before"]
    target = before["target_before"]
    if (
        gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "effective_capabilities": "0000000000000000",
            "hostname": "0361c7e7c1c5",
            "no_new_privileges": "1",
            "pid": 1,
            "seccomp": "2",
            "start_time_ticks": "3145863",
        }
        or before["runtime_tree_before"] != lock["installed_runtime"]["runtime_tree"]
        or before["openclaw_before"]["digest"]
        != lock["installed_runtime"]["openclaw_digest"]
    ):
        raise AdmissionEvidenceError("runtime, gateway, or target identity changed")
    archive._verify_fixture_tree(
        target,
        root_path="/profile/workspace/skills/requesting-code-review",
        digest="sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a",
        size=132,
        tree_digest="sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3",
    )
    modules = before["modules_before"]
    mapping = {"schema": "zod_schema"}
    if set(modules) != {"cli", "config", "curator", "gateway", "schema"}:
        raise AdmissionEvidenceError("compiled restore guard set changed")
    for name, item in modules.items():
        expected = lock["compiled_guard"][mapping.get(name, name)]
        observed = item["observed"]
        if (
            item["expected"] != expected
            or observed["path"] != expected["path"]
            or observed["size"] != expected["bytes"]
            or observed["digest"] != expected["digest"]
            or observed["digest_error"] is not None
            or observed["uid"] != 0
            or observed["gid"] != 0
            or observed["mode"] != "644"
        ):
            raise AdmissionEvidenceError("compiled restore guard changed")

    discovery_before = after["discovery_before"]
    discovery_after = after["discovery_after"]
    for discovery in (discovery_before, discovery_after):
        command = discovery["command"]
        if (
            canonical_digest(discovery["response"]) != _DISCOVERY_RESPONSE_DIGEST
            or canonical_digest(discovery["target_matches"]) != _DISCOVERY_TARGET_DIGEST
            or command["stdout_bytes"] != 63_487
            or command["stdout_digest"] != _DISCOVERY_STDOUT_DIGEST
            or command["stderr_bytes"] != 0
            or command["stderr_digest"] != _EMPTY_DIGEST
        ):
            raise AdmissionEvidenceError("curator discovery changed")
    if discovery_before["response"] != discovery_after["response"]:
        raise AdmissionEvidenceError("curator discovery changed")


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["curator_status_before_seed"]["command"],
        after["curator_status_before"]["command"],
        after["discovery_before"]["command"],
        after["gateway_restore"]["command"],
        after["invalid_token_gateway_control"]["command"],
        after["cli_fallback_restore"]["command"],
        after["curator_status_after"]["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    commands = action["commands"]
    system_argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        "system.info",
        "--json",
        "--timeout",
        "5000",
    ]
    status_argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        "skills.curator.status",
        "--json",
        "--timeout",
        "5000",
    ]
    discovery_argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
        "--params",
        '{"agentId":"main"}',
    ]
    if (
        commands != expected
        or len(commands) != 11
        or any(not _command_output_exact(command) for command in commands)
        or any(
            command["error"] is not None or command["signal"] is not None
            for command in commands
        )
        or any(
            type(command["pid"]) is not int or command["pid"] <= 0
            for command in commands
        )
        or len({command["pid"] for command in commands}) != len(commands)
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
        or commands[0]["argv"] != [_NODE, _OPENCLAW, "--version"]
        or commands[0]["stdout_excerpt"] != "OpenClaw 2026.7.1 (805a4b1)\n"
        or any(commands[index]["argv"] != status_argv for index in (2, 3, 8))
        or any(commands[index]["argv"] != discovery_argv for index in (4, 9))
        or commands[6]["argv"] != system_argv
        or any(
            not runtime_profile._command_succeeded_clean(commands[index])
            for index in (0, 1, 2, 3, 4, 8, 9, 10)
        )
    ):
        raise AdmissionEvidenceError("curator command projection changed")
    for observation in (
        before["system_info_before"],
        before["curator_status_before_seed"],
        after["curator_status_before"],
        after["gateway_restore"],
        after["invalid_token_gateway_control"],
        after["curator_status_after"],
        after["system_info_after"],
    ):
        if (
            observation["response"]["parsed"] is not True
            or json.loads(observation["command"]["stdout_excerpt"])
            != observation["response"]["value"]
        ):
            raise AdmissionEvidenceError("curator command response changed")
    for system in (before["system_info_before"], after["system_info_after"]):
        value = system["response"]["value"]
        if (
            system["command"]["argv"] != system_argv
            or value["pid"] != 1
            or value["hostname"] != "0361c7e7c1c5"
            or value["platform"] != "linux"
            or value["arch"] != "arm64"
            or value["nodeVersion"] != "v24.16.0"
            or value["port"] != 18_789
            or value["diskPath"] != "/profile/state"
        ):
            raise AdmissionEvidenceError("curator system identity changed")


def _command_output_exact(command: Mapping[str, Any]) -> bool:
    stdout = command["stdout_excerpt"].encode()
    stderr = command["stderr_excerpt"].encode()
    stdout_exact = command["stdout_bytes"] == len(stdout) and command[
        "stdout_digest"
    ] == _digest(stdout)
    if command["stdout_excerpt"].endswith("\n[truncated]"):
        stdout_exact = (
            command["stdout_bytes"] > len(stdout)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", command["stdout_digest"])
            is not None
        )
    return (
        stdout_exact
        and command["stderr_bytes"] == len(stderr)
        and command["stderr_digest"] == _digest(stderr)
    )


def _verify_denials(after: Mapping[str, Any]) -> None:
    gateway = after["gateway_restore"]
    expected_error = {
        "code": "INVALID_REQUEST",
        "message": _AUTHORITY_ERROR,
        "retryable": False,
        "type": "gateway_request_error",
    }
    invalid = after["invalid_token_gateway_control"]
    invalid_reason = (
        "unauthorized: gateway token mismatch (set gateway.remote.token to match "
        "gateway.auth.token)"
    )
    invalid_error = {
        "code": 1008,
        "kind": "closed",
        "message": f"gateway closed (1008): {invalid_reason}",
        "reason": invalid_reason,
        "type": "gateway_transport_error",
    }
    invalid_response = {
        "parsed": True,
        "value": {
            "error": invalid_error,
            "gateway": {
                "bindDetail": "Bind: loopback",
                "url": "ws://127.0.0.1:18789",
                "urlSource": "local loopback",
            },
            "ok": False,
        },
    }
    invalid_stderr = (
        f"gateway connect failed: GatewayClientRequestError: {invalid_reason}\n"
    )
    cli = after["cli_fallback_restore"]["command"]
    if (
        gateway["command"]["argv"]
        != [
            _NODE,
            _OPENCLAW,
            "gateway",
            "call",
            "skills.curator.restore",
            "--json",
            "--timeout",
            "5000",
            "--params",
            '{"skill":"requesting-code-review"}',
        ]
        or gateway["command"]["exit_code"] != 1
        or gateway["command"]["stderr_bytes"] != 0
        or gateway["response"]
        != {"parsed": True, "value": {"error": expected_error, "ok": False}}
        or invalid["command"]["exit_code"] != 1
        or invalid["response"] != invalid_response
        or invalid["command"]["stdout_bytes"] != 481
        or invalid["command"]["stdout_digest"]
        != "sha256:d88557eaf82b003daed20aeb2d0c1c9a6271e9c3bb95686181e9ecf19d4668ae"
        or invalid["command"]["stderr_bytes"] != 143
        or invalid["command"]["stderr_excerpt"] != invalid_stderr
        or invalid["command"]["stderr_digest"]
        != "sha256:25b45fe227920562cda00967eb52d40dd6380d96f3c7112b267f16fec27f7322"
        or cli["argv"]
        != [_NODE, _OPENCLAW, "skills", "curator", "--json", "restore", _TARGET]
        or cli["exit_code"] != 1
        or cli["stdout_bytes"] != 0
        or cli["stdout_digest"] != _EMPTY_DIGEST
        or cli["stderr_bytes"] != 210
        or cli["stderr_excerpt"] != _CLI_STDERR
        or cli["stderr_digest"] != _digest(_CLI_STDERR.encode())
    ):
        raise AdmissionEvidenceError("external-authority restore denial changed")


def _verify_lifecycle(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    databases = [
        after["database_before"],
        after["database_after_gateway"],
        after["database_after_cli"],
    ]
    if (
        [item["data_version"] for item in databases] != [2, 3, 4]
        or any(item["row"] != _ARCHIVED_ROW for item in databases)
        or not all(item["file"] == databases[0]["file"] for item in databases[1:])
    ):
        raise AdmissionEvidenceError("selected archived lifecycle row changed")
    empty_status = {
        "counts": {"active": 0, "archived": 0, "stale": 0},
        "lastAttemptAtMs": None,
        "lastError": None,
        "lastSuccessAtMs": None,
        "overlaps": [],
        "skills": [],
    }
    archived_status = {
        **empty_status,
        "counts": {"active": 0, "archived": 1, "stale": 0},
        "skills": [_STATUS_SKILL],
    }
    if (
        before["curator_status_before_seed"]["response"]["value"] != empty_status
        or after["curator_status_before"]["response"]["value"] != archived_status
        or after["curator_status_after"]["response"]["value"] != archived_status
        or after["curator_status_before"]["response"]
        != after["curator_status_after"]["response"]
        or after["curator_status_before"]["command"]["stdout_excerpt"]
        != after["curator_status_after"]["command"]["stdout_excerpt"]
    ):
        raise AdmissionEvidenceError("curator archived status changed")
