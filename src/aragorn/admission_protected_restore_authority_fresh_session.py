"""Compose the exact restore-authority fresh-session reset qualification."""

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
from . import admission_protected_restore_authority_prompt as parent_prompt
from . import admission_protected_session_snapshot_fixed_fresh_session as legacy
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PASS_ROUTES = parent_prompt._PASS_ROUTES | {_ROUTE}
_EVIDENCE = {
    "bytes": 25_670,
    "canonical_bytes": 25_669,
    "canonical_digest": (
        "sha256:c959c54ddac1c4feb714e993ce113ce1cc2833538d2ff92ba259f4e7b4b7f216"
    ),
    "digest": (
        "sha256:c99f3791bd9dc491e4772da17ff4e1a9a6f2c144fc24d3322f4d8634d8caa163"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-fresh-session-reset-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-route-action-observations/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:7eb2fc3cdf90fcd7a054f9362eb752a2d1ad5043cc1c98993911ccb5eb3fe1cb"
)
_PARENT_QUALIFICATION_DIGEST = (
    "sha256:b1b2ed26b8ac00956bd64688e3ab25c4772ec342682034400008965b21b3deb4"
)
_RUNTIME_CANDIDATES_DIGEST = parent_prompt._RUNTIME_CANDIDATES_DIGEST
_IMPLEMENTATIONS = {
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "legacy": "sha256:9cc66405473f3db712f379cdb786256ad2fa6beda1351de33a2a0f8952aa42e1",
    "parent": "sha256:86d9ca8113f73b29e324f117caa5ca36d872557de7e302960b4e68f96facaf29",
    "runtime_profile": "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b",
}
_SOURCES = {
    "profile": (curator._SOURCES["profile"][0], 3_932),
    "runtime_lock": (curator._SOURCES["runtime_lock"][0], 4_596),
    "configuration": (curator._SOURCES["configuration"][0], 359),
    "source_probe": (
        "sha256:3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
        34_185,
    ),
    "probe": (
        "sha256:094f4879f2ddb3dea3a15c73bfef09ff309a1847ec178e12fa23648da02617c2",
        40_223,
    ),
    "target": (archive._TARGET_DIGEST, len(archive._TARGET_BYTES)),
}
_MATERIALIZER = (
    "sha256:d3ac8dd12b73c363ce9538720a72344875573934b6e6cec0ac1e603423bd5e77",
    18_581,
)
_BOUNDARY_DIGEST = (
    "sha256:be5ad17b752c585c8d8b47f1c1cc1c7553767c9650d8941794c87de4c6a67597"
)
_ACTION_DIGEST = (
    "sha256:99a909d6a4dfa091b54255220f72edf98d18c21a6310d0ba63cff35c30592ab9"
)
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_CONFIG = "/profile/config/openclaw.json"
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_RECORDED_AT = "2026-08-13T10:18:50.203Z"
_LIMITATIONS = [
    "FIVE_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "ONE_EXACT_FRESH_SESSION_RESET_INVALIDATION_AND_PROTECTED_SNAPSHOT_REBUILD_ONLY",
    "RESET_REPLY_COMPLETION_NOT_RETAINED_OR_CLAIMED",
    "RESET_REPLY_DISPATCH_ERRORED_OUTSIDE_RETAINED_ROUTE_CLAIM",
    "MODEL_TURNS_FAILED_NO_SUCCESSFUL_MODEL_OR_REPLY_DELIVERY_CLAIM",
    "AFTER_REBUILD_MODEL_TIMESTAMPS_NON_MONOTONIC_NOT_USED_FOR_ROUTE_CLAIM",
    "FULL_RUNTIME_TREE_NOT_REHASHED_BY_THIS_CAPTURE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "SIXTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_fresh_session_reset(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    prompt_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact fresh-session reset PASS to frozen four-route coverage."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(prompt_qualification)
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        modules = {
            "archive": archive,
            "curator": curator,
            "legacy": legacy,
            "parent": parent_prompt,
            "runtime_profile": runtime_profile,
        }
        if any(
            _digest(Path(module.__file__).read_bytes()) != _IMPLEMENTATIONS[name]
            for name, module in modules.items()
        ):
            raise AdmissionEvidenceError("fresh-session dependency changed")
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
            f"invalid restore-authority fresh-session evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_FIVE_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "configuration_digest": _SOURCES["configuration"][0],
            "fresh_session_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "fresh_session_evidence_digest": _EVIDENCE["digest"],
            "fresh_session_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER[0],
            "profile_digest": _SOURCES["profile"][0],
            "prompt_qualification_canonical_digest": _PARENT_QUALIFICATION_DIGEST,
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "source_probe_digest": _SOURCES["source_probe"][0],
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
            "counts": {"fail": 0, "not_tested": 16, "pass": 5},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-fresh-session-route-coverage/v1",
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
        raise AdmissionEvidenceError("fresh-session retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("fresh-session restore-authority config changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate fresh-session capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid fresh-session capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(
            f"invalid fresh-session capture JSON: {exc}"
        ) from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" != raw
    ):
        raise AdmissionEvidenceError("fresh-session capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": (
                "PASS" if item["id"] in parent_prompt._PASS_ROUTES else "NOT_TESTED"
            ),
        }
        for item in profile["routes"]
    ]
    statuses = {item["id"]: item["status"] for item in parent["profile"]["routes"]}
    if (
        canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-prompt-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 17, "pass": 4},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _IMPLEMENTATIONS["parent"]
        or statuses.get(_ROUTE) != "NOT_TESTED"
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("prompt parent qualification changed")


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
        != "aragorn/phase3-openclaw-protected-restore-authority-fresh-session-reset-retention/v1"
        or receipt["status"] != "OBSERVED"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_PRIVATE_RESTORE_AUTHORITY_RAW_FRESH_SESSION_RESET_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
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
        or inputs["probe"]["digest"] != _SOURCES["probe"][0]
        or inputs["probe"]["bytes"] != len(sources["probe"])
        or inputs["probe"]["source"]["digest"] != _SOURCES["source_probe"][0]
        or inputs["probe"]["source"]["bytes"] != len(sources["source_probe"])
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
        or receipt["implementation"]["materializer"]
        != {
            "bytes": _MATERIALIZER[1],
            "digest": _MATERIALIZER[0],
            "path": "scripts/materialize_fixed_admission_probes.py",
            "source": "git archive 5f02a8aec46d087b771250168a30f8968421f10a",
        }
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or {
            key: receipt["runtime"]["runtime_tree"][key]
            for key in lock["installed_runtime"]["runtime_tree"]
        }
        != lock["installed_runtime"]["runtime_tree"]
        or receipt["runtime"]["runtime_tree"]["capture_rehashed"] is not False
        or receipt["runtime"]["runtime_tree"]["identity_source"]
        != "protected-restore-authority-runtime-v1.lock.json and prior retained runtime capture"
        or receipt["limitations"]
        != [
            "OBSERVED_IS_NOT_ROUTE_PASS_OR_CONFORMANCE_AUTHORITY",
            "ONE_EXACT_PRIVATE_PATCHED_RUNTIME_FRESH_SESSION_RESET_ROUTE_ONLY",
            "FRESH_SESSION_RESET_INVALIDATION_AND_EXACT_PROTECTED_SNAPSHOT_REBUILD_ONLY",
            "RESET_REPLY_COMPLETION_NOT_RETAINED_OR_CLAIMED",
            "RESET_REPLY_DISPATCH_ERRORED_OUTSIDE_RETAINED_ROUTE_CLAIM",
            "MODEL_TURNS_FAILED_NO_SUCCESSFUL_MODEL_OR_REPLY_DELIVERY_CLAIM",
            "NO_PROVIDER_NETWORK_OR_PROVIDER_REQUEST_MODEL_SUCCESS_OBSERVED",
            "FULL_RUNTIME_TREE_IDENTITY_INHERITED_FROM_LOCK_AND_PRIOR_CAPTURE_NOT_REHASHED_BY_THIS_CAPTURE",
            "SESSION_STORE_MUTATION_CONFINED_TO_EPHEMERAL_STATE_TMPFS",
            "RAW_EVIDENCE_IS_OCI_CANONICAL_JSON_PLUS_LF",
            "DOCKER_CONTROL_PLANE_SELF_REPORTED",
            "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "INSTALL_PREP_CONTAINER_EXITED_137_AFTER_OPERATOR_STOP_NOT_CLEAN_STOP",
            "TEMPORARY_INSPECT_GATEWAY_LOG_AND_SYNTHETIC_GATEWAY_TOKEN_BYTES_NOT_RETAINED",
            "TWENTY_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
            "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
            "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
        ]
    ):
        raise AdmissionEvidenceError("fresh-session retention receipt changed")
    _verify_containment(receipt, evidence)


def _verify_containment(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    containment = receipt["containment"]
    container = containment["container"]
    controls = containment["controls"]
    expected_mounts = [
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
            (
                "/probe",
                "aragorn-openclaw-restore-authority-fresh-session-probe-5f02a8a",
            ),
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
        or containment["mounts"] != expected_mounts
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
        != "8d28141927e4c9d0b3f25ed97517b27bda9b8b31e2edabe5b59c9afebf0d9118"
        or container["name"]
        != "aragorn-openclaw-restore-authority-fresh-session-final-5f02a8a"
        or container["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
        or container["labels"]["io.aragorn.probe-sha256"]
        != _SOURCES["probe"][0].removeprefix("sha256:")
        or container["labels"]["io.aragorn.source-commit"]
        != "5f02a8aec46d087b771250168a30f8968421f10a"
        or _time(container["started_at"])
        > _time(evidence["actions"][0]["prerequisites"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("fresh-session containment changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    # The legacy leaf helpers below are safe only behind this exact new envelope.
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("fresh-session observation envelope changed")
    if (
        set(evidence)
        != {
            "actions",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "routes",
            "run_nonce",
            "runtime_binding",
            "schema",
            "selected_route_ids",
        }
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["recorded_at"] != _RECORDED_AT
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["selected_route_ids"] != [_ROUTE]
        or evidence["implementation_digest"] != _SOURCES["probe"][0]
        or evidence["runtime_binding"]
        != {
            "commit": profile["runtime"]["commit"],
            "node_path": _NODE,
            "openclaw_digest": lock["installed_runtime"]["openclaw_digest"],
            "openclaw_path": _OPENCLAW,
            "version": profile["runtime"]["version"],
        }
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(evidence["actions"]) != 1
    ):
        raise AdmissionEvidenceError("fresh-session observation identity changed")

    configuration = runtime_profile.load_runtime_profile(config_raw)
    _verify_boundary(evidence["protected_boundary"], configuration)
    action = evidence["actions"][0]
    if (
        canonical_digest(action) != _ACTION_DIGEST
        or set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or action["id"] != "fresh-session-reset"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("fresh-session action identity changed")
    _verify_prerequisites(action["prerequisites"], receipt, lock)
    _verify_commands(action, evidence["run_nonce"], evidence["recorded_at"])
    _verify_transition(
        action["observations"], evidence["run_nonce"], evidence["recorded_at"]
    )


def _verify_boundary(
    boundary: Mapping[str, Any], configuration: Mapping[str, Any]
) -> None:
    if (
        canonical_digest(boundary) != _BOUNDARY_DIGEST
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 1000, "uid": 1000}
        or set(boundary["roots"]) != set(curator._ROOT_SOURCES)
    ):
        raise AdmissionEvidenceError("fresh-session protected boundary changed")
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
        boundary["runtime"],
        target="/runtime",
        source="/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    config = boundary["configuration"]
    config_file = config["file"]
    if (
        config["ready"] is not True
        or config["parse_error"] is not None
        or config["json_object"] is not True
        or config["canonical_digest"] != curator._CONFIG_CANONICAL_DIGEST
        or config["expected_canonical_digest"] != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
        or config_file["path"] != _CONFIG
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["uid"] != 0
        or config_file["gid"] != 982
        or config_file["mode"] != "440"
        or config_file["nlink"] != 1
        or config_file["size"] != _SOURCES["configuration"][1]
        or config_file["digest"] != _SOURCES["configuration"][0]
        or config_file["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("fresh-session configuration changed")


def _verify_prerequisites(
    before: Mapping[str, Any], receipt: Mapping[str, Any], lock: Mapping[str, Any]
) -> None:
    gateway = before["gateway_process"]
    runtime_files = before["runtime_files"]
    node = runtime_files["node"]
    openclaw = runtime_files["openclaw"]
    if (
        set(before)
        != {
            "commands",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
        }
        or before["ready"] is not True
        or before["reason_codes"] != []
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": receipt["containment"]["container"]["name"],
            "pid": 1,
            "start_time_ticks": "3835723",
        }
        or node["executable"] is not True
        or node["file"]["path"] != _NODE
        or node["file"]["exists"] is not True
        or node["file"]["type"] != "file"
        or node["file"]["mode"] != "755"
        or node["file"]["uid"] != 0
        or node["file"]["gid"] != 0
        or node["file"]["digest"] is not None
        or node["file"]["digest_error"] != "FILE_EXCEEDS_CONTROL_LIMIT"
        or openclaw["executable"] is not True
        or openclaw["file"]["path"] != _OPENCLAW
        or openclaw["file"]["exists"] is not True
        or openclaw["file"]["type"] != "file"
        or openclaw["file"]["mode"] != "755"
        or openclaw["file"]["uid"] != 0
        or openclaw["file"]["gid"] != 0
        or openclaw["file"]["nlink"] != 1
        or openclaw["file"]["size"] != 23_463
        or openclaw["file"]["digest"] != lock["installed_runtime"]["openclaw_digest"]
        or openclaw["file"]["digest_error"] is not None
        or len(before["commands"]) != 2
        or before["system_info"]["command"] != before["commands"][1]
        or before["system_info"]["response"]["parsed"] is not True
        or before["system_info"]["response"]["value"]["pid"] != gateway["pid"]
        or before["system_info"]["response"]["value"]["hostname"] != gateway["hostname"]
        or before["system_info"]["response"]["value"]["machineName"]
        != gateway["hostname"]
        or before["system_info"]["response"]["value"]["diskPath"] != "/profile/state"
    ):
        raise AdmissionEvidenceError("fresh-session prerequisites changed")


def _gateway_argv(
    method: str, timeout: str, params: Mapping[str, Any] | None = None
) -> list[str]:
    argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        timeout,
    ]
    if params is not None:
        argv.extend(
            ["--params", json.dumps(params, sort_keys=True, separators=(",", ":"))]
        )
    return argv


def _verify_command(
    command: Mapping[str, Any],
    argv: list[str],
    *,
    stdout_value: Mapping[str, Any] | None = None,
    stdout_exact: str | None = None,
) -> None:
    stdout = command["stdout_excerpt"]
    stderr = command["stderr_excerpt"]
    if (
        set(command)
        != {
            "argv",
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stderr_digest",
            "stderr_excerpt",
            "stdout_bytes",
            "stdout_digest",
            "stdout_excerpt",
        }
        or command["argv"] != argv
        or type(command["pid"]) is not int
        or command["pid"] <= 0
        or command["exit_code"] != 0
        or command["signal"] is not None
        or command["error"] is not None
        or _time(command["started_at"]) >= _time(command["completed_at"])
        or stderr != ""
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _digest(b"")
        or command["stdout_bytes"] != len(stdout.encode())
        or command["stdout_digest"] != _digest(stdout.encode())
        or (stdout_exact is not None and stdout != stdout_exact)
    ):
        raise AdmissionEvidenceError("fresh-session command changed")
    if stdout_value is not None:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AdmissionEvidenceError(
                "fresh-session command output changed"
            ) from exc
        if parsed != stdout_value:
            raise AdmissionEvidenceError("fresh-session command output changed")


def _verify_commands(action: Mapping[str, Any], nonce: str, recorded_at: str) -> None:
    before = action["prerequisites"]
    observations = action["observations"]
    initial = observations["initialization_turn"]
    rebuild = observations["rebuild_turn"]
    commands = [*before["commands"], *action["commands"]]
    if (
        action["commands"] != [*initial["commands"], *rebuild["commands"]]
        or initial["commands"]
        != [initial["send"]["command"], initial["wait"]["command"]]
        or rebuild["commands"]
        != [rebuild["send"]["command"], rebuild["wait"]["command"]]
        or [item["pid"] for item in commands] != [34, 41, 53, 65, 77, 89]
        or len({item["pid"] for item in commands}) != len(commands)
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
    ):
        raise AdmissionEvidenceError("fresh-session command projection changed")
    _verify_command(
        commands[0],
        [_NODE, _OPENCLAW, "--version"],
        stdout_exact="OpenClaw 2026.7.1 (805a4b1)\n",
    )
    _verify_command(
        commands[1],
        _gateway_argv("system.info", "5000"),
        stdout_value=before["system_info"]["response"]["value"],
    )
    _verify_turn(initial, "fresh-session-initialize", nonce)
    _verify_turn(rebuild, "fresh-session-rebuild", nonce)


def _verify_turn(turn: Mapping[str, Any], label: str, nonce: str) -> None:
    legacy._verify_turn(turn, label, nonce)
    run_id = f"aragorn-protected-route-{label}-{nonce}"
    message = {
        "fresh-session-initialize": "Inert protected-route session initialization.",
        "fresh-session-rebuild": "Inert protected-route post-reset snapshot rebuild.",
    }[label]
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 5000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10_000}
    if (
        set(turn) != {"commands", "confirmed", "send", "wait"}
        or turn["confirmed"] is not True
        or turn["send"]["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or turn["wait"]["response"]["parsed"] is not True
        or turn["wait"]["response"]["value"]["runId"] != run_id
        or turn["wait"]["response"]["value"]["status"] != "ok"
        or type(turn["wait"]["response"]["value"]["endedAt"]) is not int
    ):
        raise AdmissionEvidenceError("fresh-session turn changed")
    _verify_command(
        turn["send"]["command"],
        _gateway_argv("chat.send", "5000", send_params),
        stdout_value=turn["send"]["response"]["value"],
    )
    _verify_command(
        turn["wait"]["command"],
        _gateway_argv("agent.wait", "12000", wait_params),
        stdout_value=turn["wait"]["response"]["value"],
    )


def _verify_transition(
    observations: Mapping[str, Any], nonce: str, recorded_at: str
) -> None:
    # These legacy semantics are composed only after the exact-envelope gate.
    legacy._verify_transition(observations, nonce, recorded_at)
    if set(observations) != {
        "initialization_turn",
        "rebuild_turn",
        "rebuilt_snapshot_matches_baseline",
        "reset_snapshot_cleared",
        "reset_turn",
        "rotation_observed_at",
        "session_after_reset",
        "session_after_reset_check",
        "session_after_rotation",
        "session_before_reset",
        "session_before_reset_check",
        "session_id_rotated",
    }:
        raise AdmissionEvidenceError("fresh-session observation shape changed")
    before = observations["session_before_reset"]
    rotated = observations["session_after_rotation"]
    after = observations["session_after_reset"]
    reset = observations["reset_turn"]
    reset_id = f"aragorn-protected-route-fresh-session-reset-{nonce}"
    if (
        observations["session_id_rotated"] is not True
        or observations["reset_snapshot_cleared"] is not True
        or observations["rebuilt_snapshot_matches_baseline"] is not True
        or observations["session_before_reset_check"] != legacy._READY_CHECK
        or observations["session_after_reset_check"] != legacy._READY_CHECK
        or reset
        != {
            "accepted": True,
            "completed_at": "2026-08-13T10:18:48.076Z",
            "error": None,
            "method": "chat.send",
            "params": {
                "deliver": False,
                "idempotencyKey": reset_id,
                "message": "/new",
                "sessionKey": _SESSION_KEY,
                "timeoutMs": 5000,
            },
            "response": {"runId": reset_id, "status": "started"},
            "scopes": ["operator.admin", "operator.write"],
            "started_at": "2026-08-13T10:18:47.984Z",
            "transport": "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli",
        }
        or not (
            _time(
                observations["initialization_turn"]["wait"]["command"]["completed_at"]
            )
            < _time(reset["started_at"])
            < _time(reset["completed_at"])
            < _time(observations["rotation_observed_at"])
            <= _time(observations["rebuild_turn"]["send"]["command"]["started_at"])
            < _time(recorded_at)
        )
    ):
        raise AdmissionEvidenceError("fresh-session reset transition changed")
    _verify_snapshot(
        before,
        session_id="2641d59b-595b-4a06-a58e-fe0762ef7f81",
        snapshot_digest="sha256:83a842584c026cd765ef388b03f52f6f707d832c53921bedcb23bcda8399e957",
        store_digest="sha256:d1a309f50bd4ae2c682b4200300075cca0483fb70889565082ef48d23e4b408f",
        store_inode=29,
        store_size=1266,
    )
    _verify_rotated_snapshot(rotated)
    _verify_snapshot(
        after,
        session_id="04052e36-e2f2-4df4-829c-10ba06167cd5",
        snapshot_digest="sha256:4a6b0ab56a051e91909541d6157ea8d422239b43cbf991b0c94be89c02728fcb",
        store_digest="sha256:a16e8a51428a7aa199addbca0966f71e2fbb7cbba10cac9efa1865050cf4ff49",
        store_inode=40,
        store_size=1459,
    )
    if (
        before["entry"]["session_id"] == after["entry"]["session_id"]
        or rotated["entry"]["session_id"] != after["entry"]["session_id"]
        or before["entry"]["snapshot_version"] != after["entry"]["snapshot_version"]
        or before["entry"]["prompt"] != after["entry"]["prompt"]
        or before["entry"]["skill_names"] != after["entry"]["skill_names"]
        or len(
            {
                before["file"]["inode"],
                rotated["file"]["inode"],
                after["file"]["inode"],
            }
        )
        != 3
        # Retained anomaly is exact and is deliberately excluded from success/timing claims.
        or after["entry"]["ended_at"] + 2 != after["entry"]["started_at"]
    ):
        raise AdmissionEvidenceError("fresh-session snapshot custody changed")


def _verify_snapshot(
    snapshot: Mapping[str, Any],
    *,
    session_id: str,
    snapshot_digest: str,
    store_digest: str,
    store_inode: int,
    store_size: int,
) -> None:
    if canonical_digest(snapshot) != snapshot_digest:
        raise AdmissionEvidenceError("fresh-session snapshot envelope changed")
    legacy._verify_snapshot(snapshot, session_id)
    entry = snapshot["entry"]
    prompt = entry["prompt"]
    file = prompt["file"]
    store = snapshot["file"]
    if (
        entry["session_id"] != session_id
        or entry["skill_names"] != ["requesting-code-review"]
        or entry["snapshot_version"] != 1_786_616_290_628
        or entry["status"] != "failed"
        or entry["runtime_ms"] != 0
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 728
        or prompt["digest"] != legacy._PROMPT_DIGEST
        or prompt["expected_digest"] != legacy._PROMPT_DIGEST
        or file
        != {
            "device": 62,
            "digest": legacy._PROMPT_DIGEST,
            "digest_error": None,
            "exists": True,
            "gid": 1000,
            "inode": 22,
            "mode": "600",
            "nlink": 1,
            "path": legacy._PROMPT_PATH,
            "size": 728,
            "type": "file",
            "uid": 1000,
        }
        or store
        != {
            "device": 62,
            "digest": store_digest,
            "digest_error": None,
            "exists": True,
            "gid": 1000,
            "inode": store_inode,
            "mode": "600",
            "nlink": 1,
            "path": "/profile/state/agents/main/sessions/sessions.json",
            "size": store_size,
            "type": "file",
            "uid": 1000,
        }
    ):
        raise AdmissionEvidenceError("fresh-session protected snapshot changed")


def _verify_rotated_snapshot(snapshot: Mapping[str, Any]) -> None:
    if (
        canonical_digest(snapshot)
        != "sha256:6b7b90827a2d54e7dbf5dc21c1065b12f2b83f1e7e170c8efdc179b9593eab18"
        or snapshot
        != {
            "entry": {
                "ended_at": None,
                "prompt": {
                    "bytes": None,
                    "digest": None,
                    "storage": "absent-or-invalid",
                },
                "runtime_ms": None,
                "session_id": "04052e36-e2f2-4df4-829c-10ba06167cd5",
                "skill_names": [],
                "snapshot_present": False,
                "snapshot_version": None,
                "started_at": None,
                "status": None,
                "updated_at": 1_786_616_328_078,
            },
            "file": {
                "device": 62,
                "digest": "sha256:4ed2a2690f1f49a6928072e70135af422cc06e6a2c6556e56b40688241486ce8",
                "digest_error": None,
                "exists": True,
                "gid": 1000,
                "inode": 30,
                "mode": "600",
                "nlink": 1,
                "path": "/profile/state/agents/main/sessions/sessions.json",
                "size": 917,
                "type": "file",
                "uid": 1000,
            },
            "present": True,
        }
    ):
        raise AdmissionEvidenceError("fresh-session cleared snapshot changed")
