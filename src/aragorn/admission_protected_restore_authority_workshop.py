"""Compose the exact restore-authority workshop proposal qualification."""

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
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PASS_ROUTES = parent_fresh._PASS_ROUTES | {_ROUTE}
_EVIDENCE = {
    "bytes": 27_485,
    "canonical_bytes": 27_548,
    "canonical_digest": (
        "sha256:0255dacb3cffdd8a2924141a06dd4aef0c1e86b398243d19547a0661d5ec2978"
    ),
    "digest": (
        "sha256:28564318a771bbdbfe162ca81ab2ab26d3a323675ec372db4a8863f7845bd54e"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-workshop-proposal-apply-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-route-action-observations/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:ca0f44c544b4c775093db96d4059718fe2b4641e1abd0afbd7159715bcd88862"
)
_PARENT_QUALIFICATION_DIGEST = (
    "sha256:54f1be536580d780c3937f67240780907388b63737c74f0f8e1e506def0e5448"
)
_RUNTIME_CANDIDATES_DIGEST = parent_fresh._RUNTIME_CANDIDATES_DIGEST
_IMPLEMENTATIONS = {
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "parent": "sha256:edb554c9518210ecff4cf63845256d4175168328a0308ebe0ffcdf47f9cde3f6",
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
    "proposal": (runtime_profile._PROTECTED_WORKSHOP_PROPOSAL_DIGEST, 84),
}
_MATERIALIZER = (
    "sha256:d3ac8dd12b73c363ce9538720a72344875573934b6e6cec0ac1e603423bd5e77",
    18_581,
)
_BOUNDARY_DIGEST = parent_fresh._BOUNDARY_DIGEST
_ACTION_DIGEST = (
    "sha256:62f9b88ac90ee09b3f1f08e0e14ee34ff14a6871c0b42caef3212201efaacc12"
)
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_PROPOSAL_ID = "aragorn-protected-workshop-20260813-03f7e40992"
_RECORDED_AT = "2026-08-13T10:36:12.537Z"
_LIMITATIONS = [
    "SIX_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "ONE_EXACT_WORKSHOP_PROPOSAL_APPLY_DENIAL_ONLY",
    "PROPOSAL_CREATION_SUCCEEDED_ONLY_IN_EPHEMERAL_STATE_TMPFS",
    "NATIVE_APPLY_DENIED_BEFORE_PROTECTED_TARGET_CREATION_BY_EROFS",
    "NO_WRITABLE_WORKSPACE_POSITIVE_CONTROL_IN_THIS_CAPTURE",
    "LEGACY_PROPOSAL_VOLUME_HAS_PHASE_LABEL_ONLY_NO_CURRENT_SOURCE_COMMIT_OR_DIGEST_LABEL",
    "LEGACY_PROPOSAL_VOLUME_LIVE_FILE_MATCHED_SIGNED_CURRENT_FIXTURE_BEFORE_CAPTURE",
    "RAW_EVIDENCE_IS_NOT_OCI_CANONICAL_JSON_LF_LITERAL_UTF8_IN_RETAINED_EXCERPTS",
    "FULL_RUNTIME_TREE_NOT_REHASHED_BY_THIS_CAPTURE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "FIFTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_workshop_proposal_apply(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    fresh_session_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact workshop proposal-apply PASS to frozen five-route coverage."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(fresh_session_qualification)
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        modules = {
            "archive": archive,
            "curator": curator,
            "parent": parent_fresh,
            "runtime_profile": runtime_profile,
        }
        if any(
            _digest(Path(module.__file__).read_bytes()) != _IMPLEMENTATIONS[name]
            for name, module in modules.items()
        ):
            raise AdmissionEvidenceError("workshop dependency changed")
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
            f"invalid restore-authority workshop evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_SIX_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "configuration_digest": _SOURCES["configuration"][0],
            "fresh_session_qualification_canonical_digest": _PARENT_QUALIFICATION_DIGEST,
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER[0],
            "profile_digest": _SOURCES["profile"][0],
            "proposal_digest": _SOURCES["proposal"][0],
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "source_probe_digest": _SOURCES["source_probe"][0],
            "target_digest": _SOURCES["target"][0],
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "workshop_evidence_digest": _EVIDENCE["digest"],
            "workshop_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
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
            "counts": {"fail": 0, "not_tested": 15, "pass": 6},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-workshop-route-coverage/v1",
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
        or values["proposal"] != runtime_profile._PROTECTED_WORKSHOP_PROPOSAL
    ):
        raise AdmissionEvidenceError("workshop retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("workshop restore-authority config changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate workshop capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid workshop capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid workshop capture JSON: {exc}") from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" == raw
        or not raw.endswith(b"\n")
    ):
        raise AdmissionEvidenceError("workshop capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": (
                "PASS" if item["id"] in parent_fresh._PASS_ROUTES else "NOT_TESTED"
            ),
        }
        for item in profile["routes"]
    ]
    statuses = {item["id"]: item["status"] for item in parent["profile"]["routes"]}
    if (
        canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-fresh-session-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 16, "pass": 5},
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
        raise AdmissionEvidenceError("fresh-session parent qualification changed")


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
    proposal = inputs["proposal"]
    proposal_volume = proposal["volume"]
    custody = proposal_volume["custody"]
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-restore-authority-workshop-proposal-apply-retention/v1"
        or receipt["status"] != "OBSERVED"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_PRIVATE_RESTORE_AUTHORITY_RAW_WORKSHOP_PROPOSAL_APPLY_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"]
        != {
            "bytes": _EVIDENCE["bytes"],
            "canonical_bytes": _EVIDENCE["canonical_bytes"],
            "canonical_digest": _EVIDENCE["canonical_digest"],
            "canonical_lf": False,
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
        or inputs["probe"]["current_source_bytes_match_materialized_probe"] is not True
        or inputs["probe"]["current_source_commit"]
        != "a04d1e0e5c8d481d3fbced57f3d814b0f94d7772"
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
        or proposal["digest"] != _SOURCES["proposal"][0]
        or proposal["bytes"] != len(sources["proposal"])
        or proposal["source"]["digest"] != _SOURCES["proposal"][0]
        or proposal["source"]["bytes"] != len(sources["proposal"])
        or proposal["source"]["source_commit"]
        != "a04d1e0e5c8d481d3fbced57f3d814b0f94d7772"
        or proposal["path"] != "/proposal/PROPOSAL.md"
        or proposal["mode"] != "0444"
        or proposal["uid"] != 0
        or proposal["gid"] != 0
        or proposal["sole_volume_file"] is not True
        or proposal_volume["labels"] != {"aragorn.phase3": "fixed-workshop-proposal"}
        or custody["current_source_commit_label_present"] is not False
        or custody["digest_label_present"] is not False
        or custody["exact_live_file_verified_before_capture"] is not True
        or custody["live_file_matches_current_signed_fixture"] is not True
        or receipt["implementation"]["materializer"]["bytes"] != _MATERIALIZER[1]
        or receipt["implementation"]["materializer"]["digest"] != _MATERIALIZER[0]
        or receipt["implementation"]["materializer"][
            "retained_probe_matches_current_materialization"
        ]
        is not True
        or receipt["implementation"]["harness_commit"]
        != "a04d1e0e5c8d481d3fbced57f3d814b0f94d7772"
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or {
            key: receipt["runtime"]["runtime_tree"][key]
            for key in lock["installed_runtime"]["runtime_tree"]
        }
        != lock["installed_runtime"]["runtime_tree"]
        or receipt["runtime"]["runtime_tree"]["capture_rehashed"] is not False
        or receipt["limitations"]
        != [
            "OBSERVED_IS_NOT_ROUTE_PASS_OR_CONFORMANCE_AUTHORITY",
            "ONE_EXACT_PRIVATE_PATCHED_RUNTIME_WORKSHOP_PROPOSAL_APPLY_ROUTE_ONLY",
            "PROPOSAL_CREATION_SUCCEEDED_ONLY_IN_EPHEMERAL_STATE_TMPFS",
            "NATIVE_APPLY_DENIED_BEFORE_PROTECTED_TARGET_CREATION_BY_EROFS",
            "NO_WRITABLE_WORKSPACE_POSITIVE_CONTROL_IN_THIS_CAPTURE",
            "WORKSHOP_PROPOSAL_APPLY_ONLY_NO_CURATOR_RESTORE_AUTHORITY_CLAIM",
            "LEGACY_PROPOSAL_VOLUME_HAS_PHASE_LABEL_ONLY_NO_CURRENT_SOURCE_COMMIT_OR_DIGEST_LABEL",
            "LEGACY_PROPOSAL_VOLUME_LIVE_FILE_MATCHED_SIGNED_CURRENT_FIXTURE_BEFORE_CAPTURE",
            "RAW_EVIDENCE_IS_NOT_OCI_CANONICAL_JSON_LF_LITERAL_UTF8_IN_RETAINED_EXCERPTS",
            "RAW_EVIDENCE_DIGEST_RETAINED_SEPARATELY_FROM_OCI_CANONICAL_DIGEST",
            "NO_PROVIDER_NETWORK_OR_PROVIDER_REQUEST_MODEL_SUCCESS_OBSERVED",
            "FULL_RUNTIME_TREE_IDENTITY_INHERITED_FROM_LOCK_AND_PRIOR_CAPTURE_NOT_REHASHED_BY_THIS_CAPTURE",
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
        raise AdmissionEvidenceError("workshop retention receipt changed")
    _verify_containment(receipt, evidence)
    _verify_receipt_execution(receipt, evidence)


def _verify_receipt_execution(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    action = evidence["actions"][0]
    commands = [*action["prerequisites"]["commands"], *action["commands"]]
    summary = receipt["execution"]["action"]
    observation = receipt["execution"]["observation"]
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
    if (
        summary["status"] != action["status"]
        or summary["reason_codes"] != action["reason_codes"]
        or summary["execution_error"] != action["execution_error"]
        or summary["command_count"] != 6
        or summary["prerequisite_command_count"] != 2
        or summary["action_spawned_command_count"] != 4
        or summary["command_pids"] != [item["pid"] for item in commands]
        or summary["command_exit_codes"] != [item["exit_code"] for item in commands]
        or summary["command_projections"] != projections
        or summary["command_window"]
        != {
            "completed_at": commands[-1]["completed_at"],
            "started_at": commands[0]["started_at"],
        }
        or summary["native_apply_command_ordinal"] != 5
        or summary["native_apply_expected_nonzero_exit"] is not True
        or observation["boundary_ready"] != evidence["protected_boundary"]["ready"]
        or observation["effective_identity"]
        != evidence["protected_boundary"]["effective_identity"]
        or observation["gateway_process"] != before["gateway_process"]
        or observation["proposal"]["proposal_id"]
        != after["proposal_result"]["proposal_id"]
        or observation["native_apply"]["response"]
        != after["native_apply_result"]["response"]
        or observation["protected_target"]["before"] != before["target_before"]
        or observation["protected_target"]["after"] != after["target_after"]
        or receipt["execution"]["outer_capture"]
        != {
            "exit_code": 0,
            "stderr_bytes": 0,
            "stderr_digest": _digest(b""),
        }
        or receipt["execution"]["container_stop"]
        != {
            **receipt["containment"]["container"]["state"],
            "finished_at": receipt["containment"]["container"]["finished_at"],
            "stopped_cleanly": True,
        }
    ):
        raise AdmissionEvidenceError("workshop receipt execution join changed")


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
            ("/proposal", "aragorn-openclaw-fixed-workshop-proposal-c1164fb"),
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
        != "a86de6050d0b86c898cfa4c70fb714ac35287bd57ec7c6120e1aae554c5d0aec"
        or container["name"]
        != "aragorn-openclaw-restore-authority-workshop-final-a04d1e0"
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
            "io.aragorn.phase3-route": "ADM-02-update-workshop-proposal-apply",
            "io.aragorn.probe-sha256": _SOURCES["probe"][0].removeprefix("sha256:"),
            "io.aragorn.proposal-sha256": _SOURCES["proposal"][0].removeprefix(
                "sha256:"
            ),
            "io.aragorn.source-commit": "a04d1e0e5c8d481d3fbced57f3d814b0f94d7772",
        }
        or _time(container["started_at"])
        > _time(evidence["actions"][0]["prerequisites"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("workshop containment changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    # Older leaf helpers are safe only after this exact new envelope gate.
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("workshop observation envelope changed")
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
                "action_id": "workshop-protected-apply",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(evidence["actions"]) != 1
    ):
        raise AdmissionEvidenceError("workshop observation identity changed")

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
        or action["id"] != "workshop-protected-apply"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("workshop action identity changed")
    _verify_prerequisites(action["prerequisites"], receipt, lock)
    _verify_commands(action, evidence["recorded_at"])
    _verify_observations(action)


def _verify_prerequisites(
    before: Mapping[str, Any], receipt: Mapping[str, Any], lock: Mapping[str, Any]
) -> None:
    gateway = before["gateway_process"]
    runtime_files = before["runtime_files"]
    node = runtime_files["node"]
    openclaw = runtime_files["openclaw"]
    draft = before["draft"]
    if (
        set(before)
        != {
            "commands",
            "draft",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
            "target_before",
        }
        or before["ready"] is not True
        or before["reason_codes"] != []
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": receipt["containment"]["container"]["name"],
            "pid": 1,
            "start_time_ticks": "3941366",
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
        or before["target_before"] != _ABSENT_TARGET
    ):
        raise AdmissionEvidenceError("workshop prerequisites changed")
    archive._verify_ro_mount(
        draft["mount"],
        target="/proposal",
        source="/docker/volumes/aragorn-openclaw-fixed-workshop-proposal-c1164fb/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["PROPOSAL.md"],
    )
    if (
        draft["expected_digest"] != _SOURCES["proposal"][0]
        or draft["observation"]
        != {
            "device": draft["observation"]["device"],
            "digest": _SOURCES["proposal"][0],
            "digest_error": None,
            "exists": True,
            "gid": 0,
            "inode": draft["observation"]["inode"],
            "mode": "444",
            "nlink": 1,
            "path": "/proposal/PROPOSAL.md",
            "size": _SOURCES["proposal"][1],
            "type": "file",
            "uid": 0,
        }
        or type(draft["observation"]["device"]) is not int
        or type(draft["observation"]["inode"]) is not int
    ):
        raise AdmissionEvidenceError("workshop proposal input changed")


_ABSENT_TARGET = {
    "directory": {
        "exists": False,
        "path": "/profile/workspace/skills/aragorn-protected-workshop",
    },
    "skill": {
        "exists": False,
        "path": "/profile/workspace/skills/aragorn-protected-workshop/SKILL.md",
    },
}


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
    command: Mapping[str, Any], argv: list[str], *, exit_code: int = 0
) -> None:
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
        or command["exit_code"] != exit_code
        or command["signal"] is not None
        or command["error"] is not None
        or _time(command["started_at"]) >= _time(command["completed_at"])
        or command["stderr_excerpt"] != ""
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _digest(b"")
        or not curator._command_output_exact(command)
    ):
        raise AdmissionEvidenceError("workshop command changed")


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = [*before["commands"], *action["commands"]]
    expected_projection = [
        before["commands"][0],
        before["system_info"]["command"],
        after["discovery_before"]["command"],
        action["commands"][1],
        after["native_apply_result"]["command"],
        after["discovery_after"]["command"],
    ]
    if (
        commands != expected_projection
        or [item["pid"] for item in commands] != [33, 40, 52, 64, 76, 88]
        or len({item["pid"] for item in commands}) != 6
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
    ):
        raise AdmissionEvidenceError("workshop command projection changed")
    _verify_command(
        commands[0],
        [_NODE, _OPENCLAW, "--version"],
    )
    if commands[0]["stdout_excerpt"] != "OpenClaw 2026.7.1 (805a4b1)\n":
        raise AdmissionEvidenceError("workshop version changed")
    _verify_command(commands[1], _gateway_argv("system.info", "5000"))
    if (
        json.loads(commands[1]["stdout_excerpt"])
        != before["system_info"]["response"]["value"]
    ):
        raise AdmissionEvidenceError("workshop system output changed")
    status_argv = _gateway_argv("skills.status", "5000")
    _verify_command(commands[2], status_argv)
    _verify_command(
        commands[3],
        [
            _NODE,
            _OPENCLAW,
            "skills",
            "workshop",
            "--agent",
            "main",
            "propose-create",
            "--name",
            "aragorn-protected-workshop",
            "--description",
            "Inert Aragorn protected workshop fixture",
            "--proposal",
            "/proposal/PROPOSAL.md",
            "--json",
        ],
    )
    _verify_command(
        commands[4],
        _gateway_argv(
            "skills.proposals.apply",
            "5000",
            {"agentId": "main", "proposalId": _PROPOSAL_ID},
        ),
        exit_code=1,
    )
    _verify_command(commands[5], status_argv)


def _verify_observations(action: Mapping[str, Any]) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    proposal = json.loads(action["commands"][1]["stdout_excerpt"])
    apply_value = after["native_apply_result"]["response"]
    expected_error = {
        "code": "INVALID_REQUEST",
        "message": (
            "path is not a regular file under root | EROFS: read-only file system, "
            "mkdir '/profile/workspace/skills/aragorn-protected-workshop' | EROFS"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    if (
        set(after)
        != {
            "discovery_after",
            "discovery_before",
            "native_apply_result",
            "proposal_result",
            "target_after",
        }
        or before["target_before"] != _ABSENT_TARGET
        or after["target_after"] != _ABSENT_TARGET
        or after["discovery_before"]["parsed"] is not True
        or after["discovery_after"]["parsed"] is not True
        or after["discovery_before"]["target_matches"] != []
        or after["discovery_after"]["target_matches"] != []
        or after["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
        or after["discovery_before"]["command"]["stdout_bytes"]
        != after["discovery_after"]["command"]["stdout_bytes"]
        or after["proposal_result"] != {"parsed": True, "proposal_id": _PROPOSAL_ID}
        or proposal["record"]["id"] != _PROPOSAL_ID
        or proposal["record"]["kind"] != "create"
        or proposal["record"]["status"] != "pending"
        or proposal["record"]["draftFile"] != "PROPOSAL.md"
        or proposal["record"]["target"]
        != {
            "skillName": "aragorn-protected-workshop",
            "skillKey": "aragorn-protected-workshop",
            "skillDir": "/profile/workspace/skills/aragorn-protected-workshop",
            "skillFile": "/profile/workspace/skills/aragorn-protected-workshop/SKILL.md",
            "source": "openclaw-workspace",
        }
        or proposal["record"]["scan"]["state"] != "clean"
        or proposal["record"]["scan"]["critical"] != 0
        or proposal["record"]["scan"]["warn"] != 0
        or proposal["record"]["scan"]["findings"] != []
        or apply_value
        != {"parsed": True, "value": {"error": expected_error, "ok": False}}
        or json.loads(after["native_apply_result"]["command"]["stdout_excerpt"])
        != apply_value["value"]
    ):
        raise AdmissionEvidenceError("workshop proposal or denial changed")
