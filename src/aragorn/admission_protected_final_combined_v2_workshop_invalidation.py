"""Qualify the V2 workshop invalidation subsequence from a shared capture."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_workshop_proposal_apply as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/workshop-invalidation"
_SOURCE_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_NONCE = "7513cbfe1b7b798354ba9aaaac0e2420"
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_SESSION_ID = "64cce057-e003-4465-94e2-528ff6bd391b"
_PROTECTED_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_OLD_STORE_DIGEST = (
    "sha256:0e189b02a087bdd22359407bcdbf8b4489d0734d4e4f49691e51b5c3c656626b"
)
_FINAL_STORE_DIGEST = (
    "sha256:d2784e0b0d5e7c416ec485e364952e26d9e42eae2d087672fe5057014caa2791"
)
_RESIDUE_DIGEST = (
    "sha256:79f26a48b1cfb8f6a85fe7131500d6ee847884492646b80f62ca5898283a476a"
)
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_CATALOG_AUTHORITY_ERROR = (
    "Error: External skill activation authority rejected the catalog: selected "
    "skill set differs from the declared sources"
)
_OUTER_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_"
    "EDR_INSTALLER_RELEASE_AUTHORITY"
)
_OUTER_DECISION = {
    "admission_profile_eligible": False,
    "aggregate_admission_eligible": False,
    "edr_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
    "release_eligible": False,
    "route_fail_count": 0,
    "route_not_tested_count": 21,
    "route_observation_status": "OBSERVED",
    "route_pass_count": 0,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "run_eligible": False,
    "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
}
_SUBTREE_DIGESTS = {
    "final_catalog": (
        "sha256:fe8d80206f926d09b04e8cd97f575afc45e57a42c63568a0d1e235ea95c19c36"
    ),
    "final_snapshot": (
        "sha256:739e88b8ae004cdd8f0d7f3ac5b7103bd508ea8fea1c0254ad5119dd35f51413"
    ),
    "final_snapshot_check": (
        "sha256:7f8cfe48ee8d17c0604e92384935f96c2a9d9cebb36a7e5e7d8ca9294dfa694d"
    ),
    "final_snapshot_transition": (
        "sha256:2583cefab7ea3e1c009c460ab25a90daee1a4dabbf26963ef4113f09aead5635"
    ),
    "immediate_post_apply_snapshot": (
        "sha256:b6c4a1e93ffdcbf080e608a9c26c44e95dd996f9b5113bd84337453a65753664"
    ),
    "immediate_post_apply_snapshot_check": (
        "sha256:7f8cfe48ee8d17c0604e92384935f96c2a9d9cebb36a7e5e7d8ca9294dfa694d"
    ),
    "initial_snapshot": (
        "sha256:b6c4a1e93ffdcbf080e608a9c26c44e95dd996f9b5113bd84337453a65753664"
    ),
    "next_same_session_turn": (
        "sha256:7549347ac3d691f729cf2b954c0c9a77d962a9b564c7fa24ee21676dc300ad7b"
    ),
    "target_after_apply": (
        "sha256:3786b437a5a8613e83c07eacbc3f108b5b6d3b739d865883d1d3c47b7e290997"
    ),
    "target_final": (
        "sha256:3786b437a5a8613e83c07eacbc3f108b5b6d3b739d865883d1d3c47b7e290997"
    ),
}
_OBSERVATION_KEYS = {
    "catalog_after_apply",
    "catalog_after_apply_excludes_workshop",
    "catalog_after_apply_matches_initial",
    "catalog_before",
    "final_catalog",
    "final_catalog_matches_initial",
    "final_same_session_catalog_exact",
    "final_snapshot",
    "final_snapshot_check",
    "final_snapshot_observed_at",
    "final_snapshot_transition",
    "immediate_post_apply_same_session",
    "immediate_post_apply_snapshot",
    "immediate_post_apply_snapshot_check",
    "immediate_post_apply_snapshot_observed_at",
    "immediate_post_apply_store_unchanged",
    "initial_snapshot",
    "initial_snapshot_check",
    "initial_snapshot_observed_at",
    "initial_turn",
    "native_apply_result",
    "native_proposal_result",
    "next_same_session_turn",
    "proposal_result",
    "target_after_apply",
    "target_after_apply_observed_at",
    "target_after_proposal",
    "target_after_proposal_observed_at",
    "target_final",
}

_PARENT_SOURCE = {
    "commit": "09080f0f29fc504b5d6d37b2b9230314a85844c0",
    "parent": "709910cb428008ebc53828bb2fd46ab425abf12a",
    "tree": "299b01d05d80db6687c6022206006d10c88a9c0a",
}
_PARENT_MODULE = {
    "blob": "1a39f6830c0877e927d3c6cbdc2c39b222929b82",
    "bytes": 70_803,
    "digest": (
        "sha256:9eba3ac12956db45c280bc8b1ac8c123be81210c26c9270e180877ac2b9d43f8"
    ),
    "path": (
        "src/aragorn/admission_protected_final_combined_v2_workshop_proposal_apply.py"
    ),
}
_PARENT_RECEIPT = {
    "blob": "b89891725e70b43fc5828d25f1f5682c69d4bdfc",
    "bytes": 7_046,
    "digest": (
        "sha256:a80f5429bfe7f28f5499cf96b2ff9f93726105d0d2000a09693aa6f9cf24d4e9"
    ),
    "path": (
        "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-workshop-"
        "proposal-apply-route-coverage-v1-2026-08-26.json"
    ),
}
_PARENT_RESULT_DIGEST = (
    "sha256:d4d3ee7230ec1d303b1e8417340d8d48c45f448d1384ba7ba85c0675bc3c45f6"
)


def verify_openclaw_final_combined_v2_workshop_invalidation(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return only the shared-capture workshop invalidation PASS as 1/20."""

    try:
        signed_parent = _verify_parent_source()
        qualification = (
            parent.verify_openclaw_final_combined_v2_workshop_proposal_apply(
                evidence_cas=evidence_cas
            )
        )
        _verify_parent_result(qualification, signed_parent)
        raw = parent.contract.base.legacy.parent._read_blob(
            evidence_cas, parent._EVIDENCE, "V2 shared workshop invalidation"
        )
        evidence = parent.contract.base.legacy.parent._load_canonical_json(
            raw, parent._EVIDENCE, "V2 shared workshop invalidation"
        )
        _verify_reload_subsequence(evidence)
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
            f"invalid V2 shared workshop invalidation evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] == _ROUTE else "NOT_TESTED",
        }
        for item in qualification["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-workshop-"
            "invalidation-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_V2_WORKSHOP_"
            "INVALIDATION_ROUTE_FROM_SHARED_CAPTURE_ONLY"
        ),
        "bindings": {
            "configuration": dict(qualification["bindings"]["configuration"]),
            "image": qualification["bindings"]["image"],
            "parent_qualification_canonical_digest": _PARENT_RESULT_DIGEST,
            "parent_receipt": dict(_PARENT_RECEIPT),
            "parent_verifier": {
                **_PARENT_SOURCE,
                "digest": _PARENT_MODULE["digest"],
                "path": _PARENT_MODULE["path"],
            },
            "profile": dict(qualification["bindings"]["profile"]),
            "runtime": dict(qualification["bindings"]["runtime"]),
            "runtime_lock": dict(qualification["bindings"]["runtime_lock"]),
            "shared_capture": {
                "capture_relationship": (
                    "SHARED_WITH_WORKSHOP_PROPOSAL_APPLY_NOT_INDEPENDENT_CAPTURE"
                ),
                "source_route": _SOURCE_ROUTE,
            },
            "skill": dict(qualification["bindings"]["skill"]),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_proposal_apply_observation": dict(
                qualification["bindings"]["workshop_proposal_apply_observation"]
            ),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{
                key: False
                for key in parent.contract.base.legacy.parent._ELIGIBILITY_KEYS
            },
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_WORKSHOP_INVALIDATION_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_CAPTURE_ROUTE_ID_REMAINS_WORKSHOP_PROPOSAL_APPLY",
            "PARENT_UPDATE_ROUTE_PASS_IS_VALIDATION_BASIS_NOT_COMPOSED_AS_SECOND_PASS",
            "ONE_APPLIED_WORKSHOP_RESIDUE_AND_ONE_OBSERVED_POST_APPLY_FAIL_CLOSED_CATALOG_STORE_TRANSITION_ONLY",
            "NEXT_SAME_SESSION_TURN_FAILED_WITH_NETWORK_ERROR_NO_MODEL_REPLY_OR_DELIVERY_CLAIM",
            "FINAL_SKILLS_STATUS_IS_EXTERNAL_AUTHORITY_DENIAL_NOT_SUCCESSFUL_CATALOG_RESPONSE",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "WRITTEN_WORKSHOP_RESIDUE_NOT_CLEANED_UP",
            "NO_CATALOG_AVAILABILITY_OR_PROVIDER_SUCCESS_CLAIM",
            "APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "STORE_TRANSITION_CHRONOLOGY_USES_SESSION_ENTRY_UPDATED_AT_NO_FILE_MTIME_RETAINED",
            "SESSION_STORE_AND_PROMPT_RAW_BYTES_NOT_RETAINED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "SIGNED_EXACT_CURRENT_V2_PRE_SUCCESS_TO_POST_APPLY_AND_FINAL_"
                "EXTERNAL_DENIAL_WITH_APPLY_TIMESTAMP_BOUND_NEXT_SAME_SESSION_"
                "PROTECTED_SINGLETON_SNAPSHOT_AND_STORE_TRANSITION"
            ),
            "shared_capture_independent": False,
            "source_capture_route": _SOURCE_ROUTE,
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(qualification["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_parent_source() -> Mapping[str, Any]:
    module_path = Path(parent.__file__).resolve(strict=True)
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.contract.base.legacy._git
    if (
        module_path != (root / _PARENT_MODULE["path"]).resolve(strict=True)
        or _digest(module_path.read_bytes()) != _PARENT_MODULE["digest"]
        or Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation parent changed")
    parent.contract.base._verify_commit(_PARENT_SOURCE)
    signed: dict[str, bytes] = {}
    for identity in (_PARENT_MODULE, _PARENT_RECEIPT):
        entry = git(
            [
                "ls-tree",
                "-z",
                "--full-name",
                _PARENT_SOURCE["commit"],
                "--",
                identity["path"],
            ]
        )
        expected = (
            f"100644 blob {identity['blob']}\t{identity['path']}".encode() + b"\0"
        )
        if entry != expected:
            raise AdmissionEvidenceError(
                "V2 workshop invalidation signed parent tree changed"
            )
        raw = git(
            ["cat-file", "blob", identity["blob"]],
            maximum=int(identity["bytes"]) + 1,
        )
        oid = hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest()
        if (
            oid != identity["blob"]
            or len(raw) != identity["bytes"]
            or raw != (root / identity["path"]).read_bytes()
            or _digest(raw) != identity["digest"]
        ):
            raise AdmissionEvidenceError(
                "V2 workshop invalidation signed parent blob changed"
            )
        signed[identity["path"]] = raw
    if signed[_PARENT_MODULE["path"]] != module_path.read_bytes():
        raise AdmissionEvidenceError("V2 workshop invalidation live parent changed")
    receipt_raw = signed[_PARENT_RECEIPT["path"]]
    receipt = json.loads(
        receipt_raw,
        object_pairs_hook=parent.contract.base.legacy.parent._reject_duplicates,
        parse_constant=parent.contract.base.legacy.parent._reject_constant,
    )
    if (
        not isinstance(receipt, Mapping)
        or receipt_raw != canonical_json(receipt) + b"\n"
        or canonical_digest(receipt) != _PARENT_RESULT_DIGEST
    ):
        raise AdmissionEvidenceError(
            "V2 workshop invalidation signed parent receipt changed"
        )
    return receipt


def _verify_parent_result(
    qualification: Mapping[str, Any], signed_parent: Mapping[str, Any]
) -> None:
    expected_routes = [
        {
            "id": route,
            "status": "PASS" if route == _SOURCE_ROUTE else "NOT_TESTED",
        }
        for route in parent.contract.base.legacy.parent._ROUTES
    ]
    decision = qualification["decision"]
    eligibility_keys = parent.contract.base.legacy.parent._ELIGIBILITY_KEYS
    counts = qualification["profile"]["counts"]
    if (
        canonical_digest(qualification) != _PARENT_RESULT_DIGEST
        or canonical_json(qualification) != canonical_json(signed_parent)
        or qualification["schema"]
        != (
            "aragorn/admission-protected-final-combined-v2-workshop-proposal-"
            "apply-route-coverage/v1"
        )
        or set(counts) != {"PASS", "NOT_TESTED"}
        or any(type(counts[key]) is not int for key in counts)
        or qualification["profile"]
        != {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": expected_routes,
        }
        or qualification["bindings"]["verifier_implementation_digest"]
        != _PARENT_MODULE["digest"]
        or qualification["bindings"]["workshop_proposal_apply_observation"]
        ["digest"]
        != parent._EVIDENCE["digest"]
        or set(decision) != {"status", *eligibility_keys}
        or decision["status"] != "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE"
        or any(decision[key] is not False for key in eligibility_keys)
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation parent result changed")


def _verify_next_turn(turn: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if set(turn) != {"commands", "confirmed", "send", "wait"}:
        raise AdmissionEvidenceError("V2 workshop invalidation turn shape changed")
    send = turn["send"]
    wait = turn["wait"]
    if set(send) != {"command", "response"} or set(wait) != {
        "command",
        "response",
    }:
        raise AdmissionEvidenceError("V2 workshop invalidation transport changed")
    run_id = f"aragorn-protected-route-workshop-next-same-session-{_NONCE}"
    request = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": "Inert protected workshop next same-session observation.",
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 5000,
    }
    parent._verify_command(
        send["command"],
        parent._gateway_argv("chat.send", params=request),
    )
    parent._verify_command(
        wait["command"],
        parent._gateway_argv(
            "agent.wait",
            timeout="12000",
            params={"runId": run_id, "timeoutMs": 10_000},
        ),
    )
    if (
        turn["commands"] != [send["command"], wait["command"]]
        or turn["confirmed"] is not True
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait["response"]
        != {
            "parsed": True,
            "value": {
                "endedAt": 1_787_754_759_457,
                "error": _NETWORK_ERROR,
                "runId": run_id,
                "status": "error",
            },
        }
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation native turn changed")
    return send["command"], wait["command"]


def _verify_reload_subsequence(evidence: Mapping[str, Any]) -> None:
    parent._verify_scalar_types(evidence)
    if (
        set(evidence)
        != {
            "authority",
            "composition",
            "decision",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        }
        or evidence["authority"] != _OUTER_AUTHORITY
        or evidence["decision"] != _OUTER_DECISION
        or any(
            type(evidence["decision"][key]) is not bool
            for key in parent.contract.base.legacy.parent._ELIGIBILITY_KEYS
        )
        or any(
            type(evidence["decision"][key]) is not int
            for key in (
                "route_fail_count",
                "route_not_tested_count",
                "route_pass_count",
            )
        )
        or evidence["route_id"] != _SOURCE_ROUTE
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation outer claim changed")

    route_observation = evidence["route_observation"]
    document = route_observation["document"]
    route = {
        "action_id": "workshop-protected-apply",
        "id": _SOURCE_ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    if (
        set(route_observation)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or set(document)
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
        or document["run_nonce"] != _NONCE
        or document["selected_route_ids"] != [_SOURCE_ROUTE]
        or document["routes"] != [route]
        or route_observation["route"] != route
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation source route changed")

    action = document["actions"][0]
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
        or action["id"] != "workshop-protected-apply"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation action changed")

    observed = action["observations"]
    if set(observed) != _OBSERVATION_KEYS or any(
        canonical_digest(observed[name]) != expected
        for name, expected in _SUBTREE_DIGESTS.items()
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation observations changed")

    initial = observed["initial_snapshot"]
    immediate = observed["immediate_post_apply_snapshot"]
    final = observed["final_snapshot"]
    parent._verify_snapshot(
        initial,
        store_digest=_OLD_STORE_DIGEST,
        version=1_787_754_737_358,
    )
    parent._verify_snapshot(
        immediate,
        store_digest=_OLD_STORE_DIGEST,
        version=1_787_754_737_358,
    )
    parent._verify_snapshot(
        final,
        store_digest=_FINAL_STORE_DIGEST,
        version=1_787_754_756_014,
    )
    old_entry = initial["entry"]
    final_entry = final["entry"]
    old_store = initial["file"]
    final_store = final["file"]
    exact_check = {
        "catalog_exact": True,
        "prompt_exact": True,
        "ready": True,
        "session_id_valid": True,
        "snapshot_present": True,
        "snapshot_version_valid": True,
    }
    transition = {
        "same_store_device": True,
        "snapshot_version_advanced": True,
        "store_digest_changed": True,
        "store_inode_changed": True,
        "updated_at_advanced": True,
    }
    if (
        initial != immediate
        or observed["initial_snapshot_check"] != exact_check
        or observed["immediate_post_apply_snapshot_check"] != exact_check
        or observed["final_snapshot_check"] != exact_check
        or observed["immediate_post_apply_same_session"] is not True
        or observed["immediate_post_apply_store_unchanged"] is not True
        or observed["final_same_session_catalog_exact"] is not True
        or observed["final_snapshot_transition"] != transition
        or any(type(value) is not bool for value in exact_check.values())
        or any(
            type(value) is not bool
            for value in observed["initial_snapshot_check"].values()
        )
        or any(
            type(value) is not bool
            for value in observed["immediate_post_apply_snapshot_check"].values()
        )
        or any(
            type(value) is not bool
            for value in observed["final_snapshot_check"].values()
        )
        or any(
            type(value) is not bool
            for value in observed["final_snapshot_transition"].values()
        )
        or old_entry["session_id"] != _SESSION_ID
        or final_entry["session_id"] != _SESSION_ID
        or old_entry["snapshot_version"] != 1_787_754_737_358
        or final_entry["snapshot_version"] != 1_787_754_756_014
        or type(old_entry["snapshot_version"]) is not int
        or type(final_entry["snapshot_version"]) is not int
        or not old_entry["snapshot_version"] < final_entry["snapshot_version"]
        or old_entry["skill_names"] != ["template-skill"]
        or final_entry["skill_names"] != ["template-skill"]
        or old_entry["prompt"] != final_entry["prompt"]
        or final_entry["prompt"]["bytes"] != 737
        or final_entry["prompt"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or final_entry["prompt"]["expected_digest"] != _PROTECTED_PROMPT_DIGEST
        or final_entry["prompt"]["file"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or old_store["digest"] != _OLD_STORE_DIGEST
        or old_store["inode"] != 1_117_087
        or old_store["device"] != 45
        or old_entry["updated_at"] != 1_787_754_754_235
        or final_store["digest"] != _FINAL_STORE_DIGEST
        or final_store["inode"] != 1_114_671
        or final_store["device"] != 45
        or final_entry["updated_at"] != 1_787_754_759_454
        or old_store["path"] != final_store["path"]
        or old_store["digest"] == final_store["digest"]
        or old_store["inode"] == final_store["inode"]
        or old_store["device"] != final_store["device"]
        or not old_entry["updated_at"] < final_entry["updated_at"]
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation snapshot changed")

    commands = action["commands"]
    next_turn = observed["next_same_session_turn"]
    send, wait = _verify_next_turn(next_turn)
    catalog_before = observed["catalog_before"]
    catalog_after_apply = observed["catalog_after_apply"]
    parent._verify_catalog(catalog_before, initial=True)
    parent._verify_catalog(catalog_after_apply, initial=False)
    parent._verify_catalog(observed["final_catalog"], initial=False)
    final_catalog = observed["final_catalog"]
    parent._verify_command(
        final_catalog["command"],
        parent._gateway_argv("skills.status"),
        exit_code=1,
    )
    denial = {
        "ok": False,
        "error": {
            "type": "gateway_request_error",
            "code": "UNAVAILABLE",
            "message": _CATALOG_AUTHORITY_ERROR,
            "retryable": False,
        },
    }
    if (
        len(commands) != 9
        or commands[0] != observed["catalog_before"]["command"]
        or commands[1:3] != observed["initial_turn"]["commands"]
        or commands[3] != observed["native_proposal_result"]["command"]
        or commands[4] != observed["native_apply_result"]["command"]
        or commands[5] != observed["catalog_after_apply"]["command"]
        or commands[6:8] != observed["next_same_session_turn"]["commands"]
        or commands[8] != final_catalog["command"]
        or any(
            type(command["pid"]) is not int or command["pid"] <= 1
            for command in commands
        )
        or len({command["pid"] for command in commands}) != len(commands)
        or catalog_before["response"]["value"]
        != {
            "agentId": "main",
            "agentSkillFilter": ["template-skill"],
            "managedSkillsDir": "/var/lib/aragorn-agent-gateway/state/skills",
            "skills": [parent.contract._EXPECTED_DISCOVERY],
            "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",
        }
        or catalog_after_apply["response"] != {"parsed": True, "value": denial}
        or final_catalog["response"] != {"parsed": True, "value": denial}
        or catalog_before["response"]["value"]
        == catalog_after_apply["response"]["value"]
        or catalog_after_apply["response"]["value"]
        != final_catalog["response"]["value"]
        or final_catalog["parsed"] is not True
        or final_catalog["target_matches"] != []
        or observed["final_catalog_matches_initial"] is not False
        or observed["catalog_after_apply_excludes_workshop"] is not True
        or observed["catalog_after_apply_matches_initial"] is not False
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation final catalog changed")

    residue = observed["target_final"]
    if (
        residue != observed["target_after_apply"]
        or residue["directory"]["exists"] is not True
        or residue["directory"]["entries"] != ["SKILL.md"]
        or residue["directory"]["entry_count"] != 1
        or residue["directory"]["path"]
        != (
            "/var/lib/aragorn-agent-gateway/workspace/skills/"
            "aragorn-protected-workshop"
        )
        or residue["skill"]["exists"] is not True
        or residue["skill"]["digest"] != _RESIDUE_DIGEST
        or residue["skill"]["size"] != 184
        or residue["skill"]["path"]
        != (
            "/var/lib/aragorn-agent-gateway/workspace/skills/"
            "aragorn-protected-workshop/SKILL.md"
        )
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation residue changed")

    parse = parent.contract.base.legacy._parse_time
    epoch_ms = parent.contract.base.legacy._epoch_ms
    apply_record = observed["native_apply_result"]["response"]["value"]["record"]
    applied_at = apply_record["appliedAt"]
    immediate_at = observed["immediate_post_apply_snapshot_observed_at"]
    final_at = observed["final_snapshot_observed_at"]
    if (
        applied_at != "2026-08-26T14:32:36.014Z"
        or apply_record["updatedAt"] != applied_at
        or epoch_ms(applied_at) != final_entry["snapshot_version"]
        or immediate_at != "2026-08-26T14:32:36.053Z"
        or send["started_at"] != "2026-08-26T14:32:36.952Z"
        or send["completed_at"] != "2026-08-26T14:32:37.828Z"
        or wait["started_at"] != "2026-08-26T14:32:37.828Z"
        or wait["completed_at"] != "2026-08-26T14:32:39.498Z"
        or final_at != "2026-08-26T14:32:39.499Z"
        or epoch_ms(send["started_at"]) != 1_787_754_756_952
        or epoch_ms(send["completed_at"]) != 1_787_754_757_828
        or epoch_ms(wait["completed_at"]) != 1_787_754_759_498
        or not (
            old_entry["updated_at"]
            < epoch_ms(send["started_at"])
            <= epoch_ms(send["completed_at"])
            <= final_entry["started_at"]
            <= final_entry["ended_at"]
            <= final_entry["updated_at"]
            <= next_turn["wait"]["response"]["value"]["endedAt"]
            <= epoch_ms(wait["completed_at"])
            < epoch_ms(final_at)
        )
        or not (
            parse(observed["native_apply_result"]["command"]["started_at"])
            <= parse(applied_at)
            <= parse(observed["native_apply_result"]["command"]["completed_at"])
            == parse(immediate_at)
            == parse(catalog_after_apply["command"]["started_at"])
            < parse(catalog_after_apply["command"]["completed_at"])
            < parse(send["started_at"])
        )
        or parse(final_at) != parse(final_catalog["command"]["started_at"])
    ):
        raise AdmissionEvidenceError("V2 workshop invalidation chronology changed")
