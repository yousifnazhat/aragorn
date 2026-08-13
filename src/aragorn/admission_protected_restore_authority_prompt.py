"""Compose the exact restore-authority prompt-rebuild qualification."""

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
from . import admission_protected_prompt as prompt
from . import admission_protected_restore_authority_archive as parent_archive
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/missing-prompt-blob-rebuild"
_PASS_ROUTES = parent_archive._PASS_ROUTES | {_ROUTE}
_EVIDENCE = {
    "bytes": 51_906,
    "canonical_bytes": 51_905,
    "canonical_digest": (
        "sha256:3fcec01472ba7ea554a8bc609e1adb84f398dea6a0503da10e72afe9869c7c66"
    ),
    "digest": (
        "sha256:31bd12321e137979313dd22e9ab8319e81cbec895d1bed8a557287eb12ba45e3"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-prompt-rebuild-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-prompt-rebuild-observation/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:30e1431f6b67c99aa55726b55395a0ed912045a8aa858311b2f4bbe140945163"
)
_PARENT_QUALIFICATION_DIGEST = (
    "sha256:866d40476abb395d1e0630a89e068b0b1033a50e9de6c1c2a7bf063b2cad93c2"
)
_RUNTIME_CANDIDATES_DIGEST = parent_archive._RUNTIME_CANDIDATES_DIGEST
_IMPLEMENTATIONS = {
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "parent": "sha256:688b11eeefca19d804e01eca0b52e362021d7b8a486a2764c5461c29095e69cf",
    "prompt": "sha256:99e50bd0b18723a0bb37ca8afea04ef8b40c6fd3e159c6e17f26320f4f7c586c",
    "runtime_profile": "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b",
}
_SOURCES = {
    "profile": (curator._SOURCES["profile"][0], 3_932),
    "runtime_lock": (curator._SOURCES["runtime_lock"][0], 4_596),
    "configuration": (curator._SOURCES["configuration"][0], 359),
    "helper": (
        "sha256:81db497cbde9c07e211a406699896da37c137358d0b7534d8580eab43c47c216",
        13_609,
    ),
    "probe": (
        "sha256:cc342cd6ec87164397f842a6c921917bcd25d3ac239d978f722d4fc59c5c5af4",
        15_501,
    ),
    "target": (archive._TARGET_DIGEST, len(archive._TARGET_BYTES)),
}
_SOURCE_HELPER = (
    "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
    13_609,
)
_SOURCE_PROBE = (
    "sha256:f8fcfe8af1243c558ad071f7a001f84dca5cd219cdb069e64af6d48aac32d7eb",
    15_501,
)
_MATERIALIZER = (
    "sha256:cd89e6796550e9fff53b223a2a21280f40dbe1887732a25ccc50091e3a4c97ed",
    18_472,
)
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_TARGET = "/profile/workspace/skills/requesting-code-review"
_CONFIG = "/profile/config/openclaw.json"
_CONFIG_TREE_DIGEST = (
    "sha256:5ec654ec62bdd53105dac6061f7b0ad50f252a724458743bd832a4872c450d21"
)
_LIMITATIONS = [
    "FOUR_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "ONE_EXACT_MISSING_PROMPT_BLOB_REBUILD_ONLY",
    "NORMAL_TURNS_FAILED_AFTER_PROMPT_BUILD_WITHOUT_PROVIDER_EXECUTION",
    "APPLEDOUBLE_STAGING_SIDECARS_REMOVED_BEFORE_CAPTURE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "SEVENTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_prompt_rebuild(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    archive_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact prompt-rebuild PASS to frozen 3-route coverage."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(archive_qualification)
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        modules = {
            "archive": archive,
            "curator": curator,
            "parent": parent_archive,
            "prompt": prompt,
            "runtime_profile": runtime_profile,
        }
        if any(
            _digest(Path(module.__file__).read_bytes()) != _IMPLEMENTATIONS[name]
            for name, module in modules.items()
        ):
            raise AdmissionEvidenceError("prompt dependency implementation changed")
        curator._verify_profile(profile, lock, inventory)
        sources = _read_sources(evidence_cas, profile, lock)
        evidence = _read_evidence(evidence_cas)
        _verify_parent(parent, profile)
        _verify_receipt(receipt, evidence, profile, lock, sources)
        _verify_evidence(evidence, receipt, profile, lock, sources["configuration"])
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
            f"invalid restore-authority prompt evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_FOUR_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "archive_qualification_canonical_digest": _PARENT_QUALIFICATION_DIGEST,
            "configuration_digest": _SOURCES["configuration"][0],
            "helper_digest": _SOURCES["helper"][0],
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER[0],
            "profile_digest": _SOURCES["profile"][0],
            "prompt_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "prompt_evidence_digest": _EVIDENCE["digest"],
            "prompt_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "target_digest": _SOURCES["target"][0],
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
            "counts": {"fail": 0, "not_tested": 17, "pass": 4},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-prompt-route-coverage/v1",
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
        or values["target"] != archive._TARGET_BYTES
    ):
        raise AdmissionEvidenceError("prompt retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("prompt restore-authority config changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate prompt capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid prompt capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid prompt capture JSON: {exc}") from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" != raw
    ):
        raise AdmissionEvidenceError("prompt capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": (
                "PASS" if item["id"] in parent_archive._PASS_ROUTES else "NOT_TESTED"
            ),
        }
        for item in profile["routes"]
    ]
    if (
        canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-archive-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 18, "pass": 3},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _IMPLEMENTATIONS["parent"]
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("archive parent qualification changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    sources: Mapping[str, bytes],
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
    not_tested = [item["id"] for item in profile["routes"] if item["id"] != _ROUTE]
    inputs = receipt["inputs"]
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-restore-authority-prompt-rebuild-retention/v1"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"]
        != {
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
        or receipt["observed_at"] != evidence["recorded_at"]
        or receipt["results"]
        != {
            "fail": [],
            "not_tested": not_tested,
            "not_tested_count": 20,
            "observed": [_ROUTE],
            "pass": [],
        }
        or inputs["profile"]["digest"] != _SOURCES["profile"][0]
        or inputs["profile"]["bytes"] != len(sources["profile"])
        or inputs["runtime_lock"]["digest"] != _SOURCES["runtime_lock"][0]
        or inputs["runtime_lock"]["bytes"] != len(sources["runtime_lock"])
        or inputs["configuration"]["digest"] != _SOURCES["configuration"][0]
        or inputs["configuration"]["bytes"] != len(sources["configuration"])
        or inputs["helper"]["digest"] != _SOURCES["helper"][0]
        or inputs["helper"]["bytes"] != len(sources["helper"])
        or inputs["helper"]["source"]["digest"] != _SOURCE_HELPER[0]
        or inputs["probe"]["digest"] != _SOURCES["probe"][0]
        or inputs["probe"]["bytes"] != len(sources["probe"])
        or inputs["probe"]["source"]["digest"] != _SOURCE_PROBE[0]
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
        or receipt["implementation"]["materializer"]
        != {
            "bytes": _MATERIALIZER[1],
            "digest": _MATERIALIZER[0],
            "path": "scripts/materialize_fixed_admission_probes.py",
            "source": "git archive 8a91c569f001cc115629f1bc0959f43cfd9087bb",
        }
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or receipt["runtime"]["runtime_tree"]
        != lock["installed_runtime"]["runtime_tree"]
        or "APPLEDOUBLE_STAGING_SIDECARS_REMOVED_BEFORE_CAPTURE_AND_ABSENT_FROM_CAPTURE_BOUNDARY"
        not in receipt["limitations"]
    ):
        raise AdmissionEvidenceError("prompt retention receipt changed")
    _verify_containment(receipt, evidence)


def _verify_containment(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    containment = receipt["containment"]
    container = containment["container"]
    controls = containment["controls"]
    mounts = [
        {"destination": destination, "read_only": True, "volume": volume}
        for destination, volume in (
            (
                "/profile/config",
                "aragorn-openclaw-restore-authority-config-3eec2a5811e2",
            ),
            ("/profile/home/.agents/skills", "aragorn-openclaw-p3-archive-guard-v1"),
            ("/profile/state/extensions", "aragorn-openclaw-p3-archive-guard-v1"),
            ("/profile/state/plugin-skills", "aragorn-openclaw-p3-archive-guard-v1"),
            ("/profile/state/skills", "aragorn-openclaw-p3-archive-guard-v1"),
            (
                "/profile/workspace/.agents/skills",
                "aragorn-openclaw-p3-archive-guard-v1",
            ),
            ("/profile/workspace/skills", "aragorn-openclaw-p3-archive-target-v1"),
            ("/probe", "aragorn-openclaw-restore-authority-prompt-probe-8a91c56"),
            (
                "/runtime",
                "aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1",
            ),
        )
    ]
    if (
        containment["command"]
        != [
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
        or containment["mounts"] != mounts
        or controls["cap_add"] != []
        or controls["cap_drop"] != ["ALL"]
        or controls["network"] != "none"
        or controls["no_new_privileges"] is not True
        or controls["privileged"] is not False
        or controls["read_only_rootfs"] is not True
        or controls["runtime_user"] != "1000:1000"
        or controls["group_add"] != [982]
        or controls["pids_limit"] != 128
        or controls["memory_bytes"] != 1_073_741_824
        or controls["memory_swap_bytes"] != 1_073_741_824
        or controls["cpu_limit"] != 1_000_000_000
        or controls["restart_policy"] != "no"
        or controls["gateway_token_present"] is not True
        or container["id"]
        != "0084af2ba3f83dc06eb8ec55b0a8b5718b82011a8dde00272b46056c239acb93"
        or container["name"]
        != "aragorn-openclaw-restore-authority-prompt-final-8a91c56"
        or container["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
        or container["labels"]["io.aragorn.helper-sha256"]
        != _SOURCES["helper"][0].removeprefix("sha256:")
        or container["labels"]["io.aragorn.probe-sha256"]
        != _SOURCES["probe"][0].removeprefix("sha256:")
        or container["labels"]["io.aragorn.source-commit"]
        != "8a91c569f001cc115629f1bc0959f43cfd9087bb"
        or receipt["inputs"]["probe_volume"]["exact_capture_files"]
        != ["protected-observation-v1.mjs", "protected-prompt-rebuild-probe.mjs"]
        or _time(container["started_at"])
        > _time(evidence["action"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("prompt containment changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    # Exact envelope first; legacy prompt helpers are used only after this gate.
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("prompt observation envelope changed")
    if (
        set(evidence)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digests"]
        != {"helper": _SOURCES["helper"][0], "probe": _SOURCES["probe"][0]}
        or evidence["runtime_binding"]
        != {
            "commit": profile["runtime"]["commit"],
            "node_path": _NODE,
            "openclaw_digest": lock["installed_runtime"]["openclaw_digest"],
            "openclaw_path": _OPENCLAW,
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "version": profile["runtime"]["version"],
        }
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["route"]
        != {
            "action_id": "missing-prompt-blob-rebuild",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
    ):
        raise AdmissionEvidenceError("prompt observation identity changed")

    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or action["id"] != "missing-prompt-blob-rebuild"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or before["config_lock_before"] != {"exists": False, "path": f"{_CONFIG}.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["protected_root_trees_after"] != before["protected_root_trees_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
    ):
        raise AdmissionEvidenceError("prompt observed state changed")

    configuration = runtime_profile.load_runtime_profile(config_raw)
    _verify_boundary(before["boundary_before"], configuration)
    _verify_static_state(before, receipt, lock)
    _verify_commands(action, evidence["run_nonce"], evidence["recorded_at"])
    _verify_rebuild(after, evidence["run_nonce"])


def _verify_boundary(
    boundary: Mapping[str, Any], configuration: Mapping[str, Any]
) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(curator._ROOT_SOURCES)
    ):
        raise AdmissionEvidenceError("prompt protected boundary changed")
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
    for value, target, source, gid, mode, entries in (
        (
            boundary["probe"],
            "/probe",
            "/docker/volumes/aragorn-openclaw-restore-authority-prompt-probe-8a91c56/_data",
            0,
            "755",
            ["protected-observation-v1.mjs", "protected-prompt-rebuild-probe.mjs"],
        ),
        (
            boundary["configuration"]["mount"],
            "/profile/config",
            "/docker/volumes/aragorn-openclaw-restore-authority-config-3eec2a5811e2/_data",
            982,
            "750",
            ["openclaw.json"],
        ),
        (
            boundary["runtime"],
            "/runtime",
            "/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1/_data",
            0,
            "755",
            ["bin", "lib"],
        ),
    ):
        archive._verify_ro_mount(
            value,
            target=target,
            source=source,
            uid=0,
            gid=gid,
            mode=mode,
            entries=entries,
        )
    config = boundary["configuration"]
    file = config["file"]
    if (
        config["ready"] is not True
        or config["canonical_digest"] != curator._CONFIG_CANONICAL_DIGEST
        or config["document"] != configuration
        or file["path"] != _CONFIG
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 0
        or file["gid"] != 982
        or file["mode"] != "440"
        or file["nlink"] != 1
        or file["size"] != _SOURCES["configuration"][1]
        or file["digest"] != _SOURCES["configuration"][0]
        or file["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("prompt boundary config changed")


def _verify_static_state(
    before: Mapping[str, Any], receipt: Mapping[str, Any], lock: Mapping[str, Any]
) -> None:
    archive._verify_fixture_tree(
        before["target_before"],
        root_path=_TARGET,
        digest=_SOURCES["target"][0],
        size=_SOURCES["target"][1],
        tree_digest=archive._TARGET_TREE_DIGEST,
    )
    config_tree = before["config_tree_before"]
    gateway = before["gateway_process_before"]
    openclaw = before["openclaw_before"]
    if (
        before["runtime_tree_before"] != lock["installed_runtime"]["runtime_tree"]
        or config_tree["ready"] is not True
        or config_tree["tree_digest"] != _CONFIG_TREE_DIGEST
        or len(config_tree["entries"]) != 1
        or config_tree["entries"][0]["path"] != "openclaw.json"
        or config_tree["entries"][0]["digest"] != _SOURCES["configuration"][0]
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "effective_capabilities": "0000000000000000",
            "hostname": receipt["containment"]["container"]["name"],
            "no_new_privileges": "1",
            "pid": 1,
            "seccomp": "2",
            "start_time_ticks": "3670007",
        }
        or openclaw["path"] != _OPENCLAW
        or openclaw["exists"] is not True
        or openclaw["type"] != "file"
        or openclaw["uid"] != 0
        or openclaw["gid"] != 0
        or openclaw["mode"] != "755"
        or openclaw["nlink"] != 1
        or openclaw["size"] != 23_463
        or openclaw["digest"] != lock["installed_runtime"]["openclaw_digest"]
        or openclaw["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("prompt static runtime state changed")


def _verify_commands(action: Mapping[str, Any], nonce: str, recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        *after["initial_turn"]["commands"],
        *after["rebuild_turn"]["commands"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected
        or len(commands) != 9
        or any(
            command["error"] is not None
            or command["signal"] is not None
            or command["exit_code"] != 0
            or not curator._command_output_exact(command)
            for command in commands
        )
        or any(
            type(command["pid"]) is not int or command["pid"] <= 0
            for command in commands
        )
        or len({command["pid"] for command in commands}) != 9
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
        or commands[0]["stdout_excerpt"] != "OpenClaw 2026.7.1 (805a4b1)\n"
    ):
        raise AdmissionEvidenceError("prompt command projection changed")
    gateway = before["gateway_process_before"]
    prompt._verify_system(before["system_info_before"], gateway)
    prompt._verify_discovery(before["discovery_before"])
    prompt._verify_turn(
        after["initial_turn"],
        label="initial",
        nonce=nonce,
        session_key=f"agent:main:aragorn-protected-prompt-rebuild-{nonce}",
    )
    prompt._verify_turn(
        after["rebuild_turn"],
        label="rebuild",
        nonce=nonce,
        session_key=f"agent:main:aragorn-protected-prompt-rebuild-{nonce}",
    )
    prompt._verify_discovery(after["discovery_after"])
    prompt._verify_system(after["system_info_after"], gateway)


def _verify_rebuild(after: Mapping[str, Any], nonce: str) -> None:
    initial = after["initial_snapshot"]
    rebuilt = after["rebuilt_snapshot"]
    prompt._verify_snapshot(initial)
    prompt._verify_snapshot(rebuilt)
    initial_blob_ms = int(initial["blob"]["mtime_ns"]) // 1_000_000
    rebuilt_blob_ms = int(rebuilt["blob"]["mtime_ns"]) // 1_000_000
    initial_wait_ms = after["initial_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_wait_ms = after["rebuild_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_send_ms = int(
        _time(after["rebuild_turn"]["send"]["command"]["started_at"]).timestamp()
        * 1_000
    )
    invalidation = after["invalidation"]
    store_before = invalidation["store_before"]
    store_after = invalidation["store_after_rewrite"]
    invalidation_started_ms = int(_time(invalidation["started_at"]).timestamp() * 1_000)
    invalidation_completed_ms = int(
        _time(invalidation["completed_at"]).timestamp() * 1_000
    )
    store_after_ms = int(store_after["mtime_ns"]) // 1_000_000
    if (
        rebuilt["entry"]["session_id"] != initial["entry"]["session_id"]
        or rebuilt["entry"]["snapshot_version"] != initial["entry"]["snapshot_version"]
        or rebuilt["entry"]["started_at"] <= initial["entry"]["ended_at"]
        or rebuilt["blob"]["prompt_ref"] != initial["blob"]["prompt_ref"]
        or rebuilt["blob"]["path"] != initial["blob"]["path"]
        or rebuilt["prompt"] != initial["prompt"]
        or not initial["entry"]["ended_at"] <= initial_blob_ms <= initial_wait_ms
        or not rebuild_send_ms <= rebuilt["entry"]["ended_at"]
        or not rebuilt["entry"]["ended_at"] <= rebuilt_blob_ms <= rebuild_wait_ms
        or invalidation["blob_exists_after_unlink"] is not False
        or invalidation["blob_path"] != initial["blob"]["path"]
        or store_before["path"] != prompt._SESSION_STORE
        or store_after["path"] != store_before["path"]
        or store_before["mode"] != "600"
        or store_after["mode"] != "600"
        or store_before["nlink"] != 1
        or store_after["nlink"] != 1
        or store_after["bytes"] != store_before["bytes"]
        or store_after["digest"] != store_before["digest"]
        or int(store_after["mtime_ns"]) <= int(store_before["mtime_ns"])
        or not invalidation_started_ms <= store_after_ms <= invalidation_completed_ms
        or int(rebuilt["blob"]["mtime_ns"]) <= int(store_after["mtime_ns"])
        or int(store_after["mtime_ns"]) <= int(initial["blob"]["mtime_ns"])
        or _time(after["initial_turn"]["wait"]["command"]["completed_at"])
        > _time(invalidation["started_at"])
        or _time(invalidation["started_at"]) >= _time(invalidation["completed_at"])
        or _time(invalidation["completed_at"])
        > _time(after["rebuild_turn"]["send"]["command"]["started_at"])
        or nonce not in after["initial_turn"]["send"]["command"]["argv"][-1]
        or nonce not in after["rebuild_turn"]["send"]["command"]["argv"][-1]
    ):
        raise AdmissionEvidenceError("prompt reconstruction causality changed")
