"""Compose the exact restore-authority session-snapshot consumer qualification."""

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
from . import admission_protected_restore_authority_fresh_session as parent_fresh
from . import admission_protected_restore_authority_workshop as parent_workshop
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_PASS_ROUTES = parent_workshop._PASS_ROUTES | {_ROUTE}
_EVIDENCE = {
    "bytes": 16_889,
    "canonical_bytes": 16_888,
    "canonical_digest": (
        "sha256:bfc71041284319d0c2f54224dae56cb4110c7a8bf2801682fcd5df2c28c427fb"
    ),
    "digest": (
        "sha256:ee8f059e9f41bcaaf79271c9d3c6418f5edbb1468e714ca3560123a8f7c7092f"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-session-snapshot-consumer-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-route-action-observations/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:5b64f7b29a19159c6e0c235e95e26df221fe04596bcf298daaff9ccf5f0e3034"
)
_PARENT_QUALIFICATION_DIGEST = (
    "sha256:f4a275a28560f7b34de7ee388495891f1be45398d013e24956df9d4c09a181fc"
)
_RUNTIME_CANDIDATES_DIGEST = parent_workshop._RUNTIME_CANDIDATES_DIGEST
_IMPLEMENTATIONS = {
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "parent_fresh": "sha256:edb554c9518210ecff4cf63845256d4175168328a0308ebe0ffcdf47f9cde3f6",
    "parent_workshop": "sha256:7f804dab6ed791ad83cf0b2370c39ba51e8bcb89318f8c35dd3edc8be30c8183",
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
_BOUNDARY_DIGEST = parent_fresh._BOUNDARY_DIGEST
_ACTION_DIGEST = (
    "sha256:5dd91589442a80196cee8e7cc660076f9f1dd06e313773736b753c0ce112214c"
)
_SNAPSHOT_DIGEST = (
    "sha256:8d1409c2a2f12ff48cd5007de163912cdbdf0fed248ea6cfc1617f012260d73d"
)
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_RECORDED_AT = "2026-08-13T11:13:53.376Z"
_LIMITATIONS = [
    "SEVEN_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "ONE_EXACT_SESSION_SNAPSHOT_CONSUMER_POPULATION_ONLY",
    "BLACK_BOX_NATIVE_CHAT_TURN_OBSERVATION_NOT_DIRECT_MODULE_EXECUTION_TRACE",
    "SESSION_STORE_ABSENT_BEFORE_TURN_SO_NO_EXISTING_SNAPSHOT_REUSE_OR_TAMPER_REPAIR_CLAIM",
    "EXACT_PROTECTED_SNAPSHOT_CREATION_OBSERVED_AFTER_CONFIRMED_NATIVE_TURN",
    "NO_SNAPSHOT_INVALIDATION_OR_MUTATION_POSITIVE_CONTROL_IN_THIS_CAPTURE",
    "MODEL_TURN_FAILED_NO_SUCCESSFUL_MODEL_OR_REPLY_DELIVERY_CLAIM",
    "FULL_RUNTIME_TREE_NOT_REHASHED_BY_THIS_CAPTURE",
    "ROUTE_MODULE_DIGESTS_REHASHED_WITHOUT_DIRECT_EXECUTION_TRACE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "FOURTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_session_snapshot_consumer(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    workshop_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact snapshot-consumer population PASS to six routes."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(workshop_qualification)
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        modules = {
            "archive": archive,
            "curator": curator,
            "parent_fresh": parent_fresh,
            "parent_workshop": parent_workshop,
            "runtime_profile": runtime_profile,
        }
        if any(
            _digest(Path(module.__file__).read_bytes()) != _IMPLEMENTATIONS[name]
            for name, module in modules.items()
        ):
            raise AdmissionEvidenceError("session-consumer dependency changed")
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
            f"invalid restore-authority session-consumer evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_SEVEN_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "configuration_digest": _SOURCES["configuration"][0],
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER[0],
            "profile_digest": _SOURCES["profile"][0],
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "session_consumer_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "session_consumer_evidence_digest": _EVIDENCE["digest"],
            "session_consumer_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "source_probe_digest": _SOURCES["source_probe"][0],
            "target_digest": _SOURCES["target"][0],
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_qualification_canonical_digest": _PARENT_QUALIFICATION_DIGEST,
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
            "counts": {"fail": 0, "not_tested": 14, "pass": 7},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-session-consumer-route-coverage/v1",
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
        raise AdmissionEvidenceError("session-consumer retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError(
            "session-consumer restore-authority config changed"
        )
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(
                f"duplicate session-consumer capture key: {key}"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid session-consumer capture constant: {value}")


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
            f"invalid session-consumer capture JSON: {exc}"
        ) from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" != raw
    ):
        raise AdmissionEvidenceError("session-consumer capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": (
                "PASS" if item["id"] in parent_workshop._PASS_ROUTES else "NOT_TESTED"
            ),
        }
        for item in profile["routes"]
    ]
    statuses = {item["id"]: item["status"] for item in parent["profile"]["routes"]}
    if (
        canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-workshop-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 15, "pass": 6},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _IMPLEMENTATIONS["parent_workshop"]
        or statuses.get(_ROUTE) != "NOT_TESTED"
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("workshop parent qualification changed")


_RECEIPT_LIMITATIONS = [
    "OBSERVED_IS_NOT_ROUTE_PASS_OR_CONFORMANCE_AUTHORITY",
    "ONE_EXACT_PRIVATE_PATCHED_RUNTIME_SESSION_SNAPSHOT_CONSUMER_ROUTE_ONLY",
    "BLACK_BOX_NATIVE_CHAT_TURN_OBSERVATION_NOT_DIRECT_MODULE_EXECUTION_TRACE",
    "SESSION_STORE_ABSENT_BEFORE_TURN_SO_NO_EXISTING_SNAPSHOT_REUSE_OR_TAMPER_REPAIR_CLAIM",
    "EXACT_PROTECTED_SNAPSHOT_CREATION_OBSERVED_AFTER_CONFIRMED_NATIVE_TURN",
    "NO_SNAPSHOT_INVALIDATION_OR_MUTATION_POSITIVE_CONTROL_IN_THIS_CAPTURE",
    "MODEL_TURN_FAILED_NO_SUCCESSFUL_MODEL_OR_REPLY_DELIVERY_CLAIM",
    "NO_PROVIDER_NETWORK_OR_PROVIDER_REQUEST_MODEL_SUCCESS_OBSERVED",
    "SESSION_STORE_AND_PROMPT_BLOB_MUTATION_CONFINED_TO_EPHEMERAL_STATE_TMPFS",
    "RAW_EVIDENCE_IS_OCI_CANONICAL_JSON_PLUS_LF",
    "FULL_RUNTIME_TREE_IDENTITY_INHERITED_FROM_LOCK_AND_PRIOR_CAPTURE_NOT_REHASHED_BY_THIS_CAPTURE",
    "ROUTE_MODULE_DIGESTS_REHASHED_FROM_LIVE_VOLUME_WITHOUT_DIRECT_EXECUTION_TRACE",
    "DOCKER_CONTROL_PLANE_SELF_REPORTED",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
    "INSTALL_PREP_CONTAINER_EXITED_137_AFTER_OPERATOR_STOP_NOT_CLEAN_STOP",
    "TEMPORARY_INSPECT_GATEWAY_LOG_AND_SYNTHETIC_GATEWAY_TOKEN_BYTES_NOT_RETAINED",
    "TWENTY_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


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
        != "aragorn/phase3-openclaw-protected-restore-authority-session-snapshot-consumer-retention/v1"
        or receipt["status"] != "OBSERVED"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_PRIVATE_RESTORE_AUTHORITY_RAW_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
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
        or inputs["probe"]["retained_volume_bytes_reverified_before_capture"]
        is not True
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
        or receipt["implementation"]["materializer"]["digest"] != _MATERIALIZER[0]
        or receipt["implementation"]["materializer"]["bytes"] != _MATERIALIZER[1]
        or receipt["implementation"]["harness_commit"]
        != "759cf5596a14aa7b83ed40cae29505242f14d541"
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or {
            key: receipt["runtime"]["runtime_tree"][key]
            for key in lock["installed_runtime"]["runtime_tree"]
        }
        != lock["installed_runtime"]["runtime_tree"]
        or receipt["runtime"]["runtime_tree"]["capture_rehashed"] is not False
        or receipt["runtime"]["route_modules_rehashed_during_retention_audit"]
        is not True
        or receipt["runtime"]["route_modules"]
        != [
            {
                "bytes": 97_476,
                "digest": "sha256:737ca1356675d3777855925b96f9c636b6615f9c9e1c46ea45dd40105b40c499",
                "path": "/runtime/lib/node_modules/openclaw/dist/agent-command-DiNsR_X4.js",
            },
            {
                "bytes": 3_661,
                "digest": "sha256:d8a1bd6c3ee26b981e5cfe6e7756a91263fd40c4727e1bdb0e69171b8458cb28",
                "path": "/runtime/lib/node_modules/openclaw/dist/session-snapshot-8MgHKMdq.js",
            },
        ]
        or receipt["limitations"] != _RECEIPT_LIMITATIONS
    ):
        raise AdmissionEvidenceError("session-consumer retention receipt changed")
    _verify_containment(receipt, evidence)
    _verify_receipt_execution(receipt, evidence)


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
            (
                "/profile/state/plugin-skills",
                "aragorn-openclaw-p3-archive-guard-v1",
            ),
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
        != "5c9d0a9fac16f7029e2c528bf4e8104559779b93fac61b35889ad989054ad63a"
        or container["name"]
        != "aragorn-openclaw-restore-authority-session-consumer-final-759cf55-0234e448"
        or container["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
        or container["labels"]
        != {
            "io.aragorn.phase3-route": "ADM-02-reload-session-snapshot-consumer",
            "io.aragorn.probe-sha256": _SOURCES["probe"][0].removeprefix("sha256:"),
            "io.aragorn.source-commit": "759cf5596a14aa7b83ed40cae29505242f14d541",
        }
        or _time(container["started_at"])
        > _time(evidence["actions"][0]["prerequisites"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("session-consumer containment changed")


def _verify_receipt_execution(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    action = evidence["actions"][0]
    commands = [*action["prerequisites"]["commands"], *action["commands"]]
    execution = receipt["execution"]
    summary = execution["action"]
    observation = execution["observation"]
    projection_keys = (
        "argv",
        "completed_at",
        "error",
        "exit_code",
        "pid",
        "signal",
        "started_at",
        "stderr_bytes",
        "stderr_digest",
        "stdout_bytes",
        "stdout_digest",
    )
    projections = [
        {key: command[key] for key in projection_keys} for command in commands
    ]
    before = action["prerequisites"]
    after = action["observations"]
    snapshot = after["session_after"]
    transition = observation["session_transition"]
    if (
        summary["status"] != action["status"]
        or summary["reason_codes"] != action["reason_codes"]
        or summary["execution_error"] != action["execution_error"]
        or summary["command_count"] != 4
        or summary["prerequisite_command_count"] != 2
        or summary["action_spawned_command_count"] != 2
        or summary["command_pids"] != [item["pid"] for item in commands]
        or summary["command_projections"] != projections
        or summary["command_sequence"]
        != [
            "version",
            "system.info",
            "chat.send.snapshot-consumer",
            "agent.wait.snapshot-consumer",
        ]
        or summary["command_window"]
        != {
            "completed_at": commands[-1]["completed_at"],
            "started_at": commands[0]["started_at"],
        }
        or observation["boundary_ready"] != evidence["protected_boundary"]["ready"]
        or observation["effective_identity"]
        != evidence["protected_boundary"]["effective_identity"]
        or observation["gateway_process"]["pid"] != before["gateway_process"]["pid"]
        or observation["gateway_process"]["hostname"]
        != before["gateway_process"]["hostname"]
        or observation["gateway_process"]["start_time_ticks"]
        != before["gateway_process"]["start_time_ticks"]
        or observation["gateway_process"]["hostname_matches_container_id_prefix"]
        is not True
        or transition["before"]
        != {
            "entry_absent": True,
            "present": False,
            "session_store_exists": False,
            "session_store_path": "/profile/state/agents/main/sessions/sessions.json",
        }
        or transition["existing_snapshot_present_before"] is not False
        or transition["exact_protected_snapshot_created"] is not True
        or transition["after"]["session_id"] != snapshot["entry"]["session_id"]
        or transition["after"]["prompt_digest"] != snapshot["entry"]["prompt"]["digest"]
        or transition["after"]["session_store_digest"] != snapshot["file"]["digest"]
        or execution["outer_capture"]
        != {"exit_code": 0, "stderr_bytes": 0, "stderr_digest": _digest(b"")}
        or execution["container_stop"]
        != {
            **receipt["containment"]["container"]["state"],
            "finished_at": receipt["containment"]["container"]["finished_at"],
            "stopped_cleanly": True,
        }
    ):
        raise AdmissionEvidenceError("session-consumer receipt execution join changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("session-consumer observation envelope changed")
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
                "action_id": "session-snapshot-consumer",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(evidence["actions"]) != 1
    ):
        raise AdmissionEvidenceError("session-consumer observation identity changed")

    configuration = runtime_profile.load_runtime_profile(config_raw)
    parent_fresh._verify_boundary(evidence["protected_boundary"], configuration)
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
        or action["id"] != "session-snapshot-consumer"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("session-consumer action identity changed")
    _verify_prerequisites(action["prerequisites"], receipt, lock)
    _verify_commands(action, evidence["run_nonce"], evidence["recorded_at"])
    _verify_transition(action["observations"], evidence["run_nonce"])


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
            "hostname": receipt["containment"]["container"]["id"][:12],
            "pid": 1,
            "start_time_ticks": "4169760",
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
        raise AdmissionEvidenceError("session-consumer prerequisites changed")


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
        or command["stderr_excerpt"] != ""
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _digest(b"")
        or command["stdout_bytes"] != len(stdout.encode())
        or command["stdout_digest"] != _digest(stdout.encode())
        or (stdout_exact is not None and stdout != stdout_exact)
    ):
        raise AdmissionEvidenceError("session-consumer command changed")
    if stdout_value is not None:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AdmissionEvidenceError(
                "session-consumer command output changed"
            ) from exc
        if parsed != stdout_value:
            raise AdmissionEvidenceError("session-consumer command output changed")


def _verify_commands(action: Mapping[str, Any], nonce: str, recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    turn = after["turn"]
    commands = [*before["commands"], *action["commands"]]
    if (
        action["commands"] != turn["commands"]
        or turn["commands"] != [turn["send"]["command"], turn["wait"]["command"]]
        or [item["pid"] for item in commands] != [67, 74, 86, 98]
        or len({item["pid"] for item in commands}) != 4
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
    ):
        raise AdmissionEvidenceError("session-consumer command projection changed")
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
    _verify_turn(turn, nonce)


def _verify_turn(turn: Mapping[str, Any], nonce: str) -> None:
    run_id = f"aragorn-protected-route-snapshot-consumer-{nonce}"
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": "Inert protected-route snapshot consumer observation.",
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 5_000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10_000}
    send = turn["send"]
    wait = turn["wait"]
    if (
        set(turn) != {"commands", "confirmed", "send", "wait"}
        or turn["confirmed"] is not True
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait["response"]["parsed"] is not True
        or wait["response"]["value"]["runId"] != run_id
        or wait["response"]["value"]["status"] != "ok"
        or type(wait["response"]["value"]["endedAt"]) is not int
    ):
        raise AdmissionEvidenceError("session-consumer native turn changed")
    _verify_command(
        send["command"],
        _gateway_argv("chat.send", "5000", send_params),
        stdout_value=send["response"]["value"],
    )
    _verify_command(
        wait["command"],
        _gateway_argv("agent.wait", "12000", wait_params),
        stdout_value=wait["response"]["value"],
    )


def _verify_transition(observations: Mapping[str, Any], nonce: str) -> None:
    if set(observations) != {"session_after", "session_before", "turn"}:
        raise AdmissionEvidenceError("session-consumer observation shape changed")
    before = observations["session_before"]
    after = observations["session_after"]
    turn = observations["turn"]
    run_id = f"aragorn-protected-route-snapshot-consumer-{nonce}"
    if (
        before
        != {
            "entry": None,
            "file": {
                "exists": False,
                "path": "/profile/state/agents/main/sessions/sessions.json",
            },
            "present": False,
        }
        or canonical_digest(after) != _SNAPSHOT_DIGEST
        or turn["send"]["response"]["value"]["runId"] != run_id
        or turn["wait"]["response"]["value"]["runId"] != run_id
    ):
        raise AdmissionEvidenceError("session-consumer population transition changed")
    _verify_snapshot(after)
    entry = after["entry"]
    wait_ended_at = turn["wait"]["response"]["value"]["endedAt"]
    if (
        entry["started_at"] != entry["ended_at"]
        or entry["updated_at"] < entry["ended_at"]
        or entry["updated_at"] > wait_ended_at
        or _time(turn["send"]["command"]["completed_at"])
        > _time(turn["wait"]["command"]["started_at"])
    ):
        raise AdmissionEvidenceError("session-consumer snapshot timing changed")


def _verify_snapshot(snapshot: Mapping[str, Any]) -> None:
    entry = snapshot["entry"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    store = snapshot["file"]
    prompt_digest = (
        "sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c"
    )
    prompt_path = (
        "/profile/state/agents/main/sessions/skills-prompts/sha256/bb/"
        "bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c.txt"
    )
    if (
        set(snapshot) != {"entry", "file", "present"}
        or snapshot["present"] is not True
        or set(entry)
        != {
            "ended_at",
            "prompt",
            "runtime_ms",
            "session_id",
            "skill_names",
            "snapshot_present",
            "snapshot_version",
            "started_at",
            "status",
            "updated_at",
        }
        or entry["session_id"] != "63db0059-4e6e-4b10-b35b-f9ef25afd713"
        or entry["skill_names"] != ["requesting-code-review"]
        or entry["snapshot_present"] is not True
        or entry["snapshot_version"] != 1_786_619_628_454
        or entry["status"] != "failed"
        or entry["runtime_ms"] != 0
        or entry["started_at"] != 1_786_619_632_622
        or entry["ended_at"] != 1_786_619_632_622
        or entry["updated_at"] != 1_786_619_632_649
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 728
        or prompt["digest"] != prompt_digest
        or prompt["expected_digest"] != prompt_digest
        or prompt_file
        != {
            "device": 63,
            "digest": prompt_digest,
            "digest_error": None,
            "exists": True,
            "gid": 1000,
            "inode": 22,
            "mode": "600",
            "nlink": 1,
            "path": prompt_path,
            "size": 728,
            "type": "file",
            "uid": 1000,
        }
        or store
        != {
            "device": 63,
            "digest": "sha256:27078114b74e1e1510c489e0bd95d5efc7a47b34f8afb185e3216beddf835291",
            "digest_error": None,
            "exists": True,
            "gid": 1000,
            "inode": 29,
            "mode": "600",
            "nlink": 1,
            "path": "/profile/state/agents/main/sessions/sessions.json",
            "size": 1_266,
            "type": "file",
            "uid": 1000,
        }
    ):
        raise AdmissionEvidenceError("session-consumer protected snapshot changed")
