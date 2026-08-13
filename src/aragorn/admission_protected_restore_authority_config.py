"""Compose two exact restore-authority route qualifications."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_protected_curator_restore as curator
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_CONFIG_ROUTE = "ADM-02/update/config-entry-activation"
_PASS_ROUTES = {_CONFIG_ROUTE, curator._ROUTE}
_EVIDENCE = {
    "bytes": 32_237,
    "canonical_bytes": 32_236,
    "canonical_digest": (
        "sha256:65b0df2c024cb799cfb4373b89d1bea5d2da64053645a3a851a667ba6b5e0447"
    ),
    "digest": (
        "sha256:b4f2eb03aeaf229c85f294bd7e5eedbf48c7eb96775b0cd2382941ae9a0bc7a4"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-config-activation-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-config-activation-observation/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:ddb1508e592e227c7ea3afaea9731b66557c4c5079dafc3b4215115c4be2ea8d"
)
_CURATOR_QUALIFICATION_DIGEST = (
    "sha256:5a81b53f28753c972ca8451115cad847f79f05cc65b8cb3c5d9dedbda4ab0f67"
)
_CURATOR_IMPLEMENTATION_DIGEST = (
    "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a"
)
_SOURCES = {
    "profile": (curator._SOURCES["profile"][0], 3_932),
    "runtime_lock": (curator._SOURCES["runtime_lock"][0], 4_596),
    "configuration": (curator._SOURCES["configuration"][0], 359),
    "probe": (
        "sha256:bf0cea804669e71bc3fa13df449635e8b703385d139c5845a65c9f054f1a2a07",
        20_622,
    ),
}
_MATERIALIZER = {
    "bytes": 17_240,
    "digest": (
        "sha256:71e37237f951104f90db5d2a7e363b8408b0597a4931ef4dc76804dff072586a"
    ),
    "path": "scripts/materialize_fixed_admission_probes.py",
}
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_VERSION_STDOUT = "OpenClaw 2026.7.1 (805a4b1)\n"
_CONFIG_CANONICAL_DIGEST = curator._CONFIG_CANONICAL_DIGEST
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_RUNTIME_SOURCE = (
    "/docker/volumes/aragorn-openclaw-2026-7-1-"
    "session-snapshot-restore-authority-v1/_data"
)
_LIMITATIONS = [
    "TWO_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "NINETEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_config_activation(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    curator_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose exact curator and config route PASSes without broader authority."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(curator_qualification)
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        if (
            _digest(Path(curator.__file__).read_bytes())
            != _CURATOR_IMPLEMENTATION_DIGEST
        ):
            raise AdmissionEvidenceError("curator verifier implementation changed")
        curator._verify_profile(profile, lock, inventory)
        sources = _read_sources(evidence_cas, profile, lock)
        evidence = _read_evidence(evidence_cas)
        _verify_parent(parent, profile)
        _verify_receipt(receipt, evidence, profile, lock, sources)
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
            f"invalid restore-authority config evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_TWO_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "configuration_digest": _SOURCES["configuration"][0],
            "config_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "config_evidence_digest": _EVIDENCE["digest"],
            "config_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "curator_qualification_canonical_digest": _CURATOR_QUALIFICATION_DIGEST,
            "curator_verifier_implementation_digest": _CURATOR_IMPLEMENTATION_DIGEST,
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER["digest"],
            "profile_digest": _SOURCES["profile"][0],
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
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
            "status": "PARTIAL_ROUTE_COVERAGE",
        },
        "limitations": list(_LIMITATIONS),
        "profile": {
            "counts": {"fail": 0, "not_tested": 19, "pass": 2},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-config-route-coverage/v1",
        "source_recorded_at": max(
            parent["source_recorded_at"], evidence["recorded_at"]
        ),
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
    config = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_digest(config) != _CONFIG_CANONICAL_DIGEST
        or canonical_json(config) + b"\n" != values["configuration"]
        or config["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("restore-authority configuration changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate config capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid config capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid config capture JSON: {exc}") from exc
    if (
        not isinstance(document, dict)
        or canonical_json(document) + b"\n" != raw
        or len(canonical_json(document)) != _EVIDENCE["canonical_bytes"]
    ):
        raise AdmissionEvidenceError("config capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] == curator._ROUTE else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    if (
        canonical_digest(parent) != _CURATOR_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-curator-restore-denial-route-qualification/v1"
        or parent["route"]["id"] != curator._ROUTE
        or parent["route"]["status"] != "PASS"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 20, "pass": 1},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _CURATOR_IMPLEMENTATION_DIGEST
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("curator parent qualification changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    sources: Mapping[str, bytes],
) -> None:
    not_tested = [
        item["id"] for item in profile["routes"] if item["id"] != _CONFIG_ROUTE
    ]
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
        "canonical_lf": True,
        "path": _EVIDENCE["path"],
        "raw_sha256": _EVIDENCE["digest"].removeprefix("sha256:"),
        "recorded_at": evidence["recorded_at"],
        "run_nonce": evidence["run_nonce"],
        "schema": _EVIDENCE["schema"],
    }
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-restore-authority-config-activation-retention/v1"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"] != expected_evidence
        or receipt["observed_at"] != evidence["recorded_at"]
        or receipt["results"]
        != {
            "fail": [],
            "not_tested": not_tested,
            "not_tested_count": 20,
            "observed": [_CONFIG_ROUTE],
            "pass": [],
        }
        or receipt["implementation"]["materializer"] != _MATERIALIZER
        or receipt["inputs"]["probe"]["digest"] != _SOURCES["probe"][0]
        or receipt["inputs"]["probe"]["bytes"] != len(sources["probe"])
        or receipt["inputs"]["profile"]["digest"] != _SOURCES["profile"][0]
        or receipt["inputs"]["runtime_lock"]["digest"] != _SOURCES["runtime_lock"][0]
        or receipt["inputs"]["configuration"]["digest"] != _SOURCES["configuration"][0]
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or receipt["runtime"]["runtime_tree"]
        != lock["installed_runtime"]["runtime_tree"]
    ):
        raise AdmissionEvidenceError("config retention receipt changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    # Exact envelope first: semantic checks below remain readable, not normalizing.
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("config observation envelope changed")
    expected_runtime = {
        "commit": profile["runtime"]["commit"],
        "node_path": _NODE,
        "openclaw_digest": lock["installed_runtime"]["openclaw_digest"],
        "openclaw_path": _OPENCLAW,
        "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"]["tree_digest"],
        "version": profile["runtime"]["version"],
    }
    if (
        set(evidence)
        != {
            "action",
            "assurance",
            "implementation_digest",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digest"] != _SOURCES["probe"][0]
        or evidence["runtime_binding"] != expected_runtime
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["route"]
        != {
            "action_id": "config-entry-activation",
            "id": _CONFIG_ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
    ):
        raise AdmissionEvidenceError("config observation identity changed")

    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "config-entry-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["config_lock_before"]
        != {"exists": False, "path": "/profile/config/openclaw.json.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != after["boundary_after"]["configuration"]
        or after["config_after"] != before["config_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["discovery_after"]["response"]
        != before["discovery_before"]["response"]
        or after["discovery_after"]["command"]["stdout_digest"]
        != before["discovery_before"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("config activation state changed")

    config = runtime_profile.load_runtime_profile(config_raw)
    _verify_boundary(before["boundary_before"], config)
    archive._verify_fixture_tree(
        before["target_before"],
        root_path="/profile/workspace/skills/requesting-code-review",
        digest="sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a",
        size=132,
        tree_digest="sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3",
    )
    if before["runtime_tree_before"] != lock["installed_runtime"]["runtime_tree"]:
        raise AdmissionEvidenceError("config runtime tree changed")
    _verify_runtime(before["openclaw_before"], before["gateway_process_before"], lock)
    _verify_commands(action, evidence["recorded_at"])


def _verify_boundary(boundary: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(curator._ROOT_SOURCES)
    ):
        raise AdmissionEvidenceError("config protected boundary changed")
    for name, source in curator._ROOT_SOURCES.items():
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=runtime_profile._PROTECTED_ROOTS[name][0],
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=[curator._TARGET] if name == "workspace_skills" else [],
        )
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
        source="/docker/volumes/aragorn-openclaw-restore-authority-config-probe-3eeddbd/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["protected-config-activation-probe.mjs"],
    )
    archive._verify_ro_mount(
        boundary["runtime"],
        target="/runtime",
        source=_RUNTIME_SOURCE,
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    file = boundary["configuration"]["file"]
    if (
        boundary["configuration"]["ready"] is not True
        or boundary["configuration"]["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or file["path"] != "/profile/config/openclaw.json"
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 0
        or file["gid"] != 982
        or file["mode"] != "440"
        or file["nlink"] != 1
        or file["size"] != _SOURCES["configuration"][1]
        or file["digest"] != _SOURCES["configuration"][0]
        or file["digest_error"] is not None
        or config["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("config boundary document changed")


def _verify_runtime(
    openclaw: Mapping[str, Any], gateway: Mapping[str, Any], lock: Mapping[str, Any]
) -> None:
    if (
        openclaw["path"] != _OPENCLAW
        or openclaw["exists"] is not True
        or openclaw["type"] != "file"
        or openclaw["uid"] != 0
        or openclaw["gid"] != 0
        or openclaw["mode"] != "755"
        or openclaw["nlink"] != 1
        or openclaw["size"] != 23_463
        or openclaw["digest"] != lock["installed_runtime"]["openclaw_digest"]
        or openclaw["digest_error"] is not None
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "effective_capabilities": "0000000000000000",
            "hostname": "8cc0741b65e1",
            "no_new_privileges": "1",
            "pid": 1,
            "seccomp": "2",
            "start_time_ticks": "3297798",
        }
    ):
        raise AdmissionEvidenceError("config runtime identity changed")


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    update = after["update"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        update["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    commands = action["commands"]
    if (
        commands != expected
        or len(commands) != 6
        or any(not curator._command_output_exact(command) for command in commands)
        or any(
            command["error"] is not None or command["signal"] is not None
            for command in commands
        )
        or any(
            type(command["pid"]) is not int or command["pid"] <= 0
            for command in commands
        )
        or len({command["pid"] for command in commands}) != 6
        or any(
            _time(command["started_at"]) >= _time(command["completed_at"])
            for command in commands
        )
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
        or commands[0]["argv"] != [_NODE, _OPENCLAW, "--version"]
        or commands[0]["stdout_excerpt"] != _VERSION_STDOUT
        or any(
            not runtime_profile._command_succeeded_clean(commands[index])
            for index in (0, 1, 2, 4, 5)
        )
    ):
        raise AdmissionEvidenceError("config command projection changed")

    gateway = before["gateway_process_before"]
    for observation in (
        before["system_info_before"],
        before["discovery_before"],
        update,
        after["discovery_after"],
        after["system_info_after"],
    ):
        if (
            observation["response"]["parsed"] is not True
            or json.loads(observation["command"]["stdout_excerpt"])
            != observation["response"]["value"]
        ):
            raise AdmissionEvidenceError("config command response changed")
    for system in (before["system_info_before"], after["system_info_after"]):
        value = system["response"]["value"]
        if (
            system["command"]["argv"]
            != [
                _NODE,
                _OPENCLAW,
                "gateway",
                "call",
                "system.info",
                "--json",
                "--timeout",
                "5000",
            ]
            or value["pid"] != gateway["pid"]
            or value["hostname"] != gateway["hostname"]
            or value["platform"] != "linux"
            or value["arch"] != "arm64"
            or value["nodeVersion"] != "v24.16.0"
            or value["port"] != 18_789
            or value["diskPath"] != "/profile/state"
            or value["diskTotalBytes"] != 33_554_432
        ):
            raise AdmissionEvidenceError("config system identity changed")
    for discovery in (before["discovery_before"], after["discovery_after"]):
        if (
            discovery["command"]["argv"]
            != [
                _NODE,
                _OPENCLAW,
                "skills",
                "info",
                curator._TARGET,
                "--agent",
                "main",
                "--json",
            ]
            or discovery["response"]["value"] != archive._EXPECTED_DISCOVERY
        ):
            raise AdmissionEvidenceError("config discovery changed")

    expected_error = {
        "code": "UNAVAILABLE",
        "message": (
            "Error: EROFS: read-only file system, open "
            "'/profile/config/openclaw.json.lock': code=EROFS"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    command = update["command"]
    if (
        update["params"] != {"enabled": True, "skillKey": curator._TARGET}
        or update["response"]
        != {"parsed": True, "value": {"error": expected_error, "ok": False}}
        or command["argv"]
        != [
            _NODE,
            _OPENCLAW,
            "gateway",
            "call",
            "skills.update",
            "--json",
            "--timeout",
            "5000",
            "--params",
            '{"enabled":true,"skillKey":"requesting-code-review"}',
        ]
        or command["exit_code"] != 1
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
    ):
        raise AdmissionEvidenceError("config EROFS denial changed")
