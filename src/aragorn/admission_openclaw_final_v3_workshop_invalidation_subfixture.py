"""Verify workshop-invalidation semantic compatibility without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import admission_protected_final_combined_v3_workshop_invalidation as oracle
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = "ADM-02/reload/workshop-invalidation"
_ACTION = "workshop-invalidation"
_SCHEMA = "aragorn/openclaw-protected-workshop-invalidation-observation/v1"
_PROBE_DIGEST = (
    "sha256:d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334"
)
_PROPOSAL_DIGEST = (
    "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a"
)
_ELIGIBILITY_KEYS = oracle.parent.v3_contract.contract._ELIGIBILITY_KEYS
_DOCUMENT_KEYS = {
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
_ACTION_KEYS = {
    "commands",
    "execution_error",
    "id",
    "observations",
    "prerequisites",
    "reason_codes",
    "status",
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


def verify_openclaw_final_v3_workshop_invalidation_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify exact document predicates without claiming route execution."""

    try:
        _verify_document(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 workshop-invalidation subfixture: {exc}"
        ) from exc
    return {
        "schema": (
            "aragorn/openclaw-final-v3-workshop-invalidation-"
            "semantic-compatibility/v1"
        ),
        "assurance": (
            "WORKSHOP_INVALIDATION_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_"
            "CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY"
        ),
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": _PROBE_DIGEST,
            "input_document_canonical_digest": canonical_digest(document),
        },
        "decision": {
            "status": (
                "WORKSHOP_INVALIDATION_SEMANTIC_COMPATIBILITY_VERIFIED_"
                "NOT_OBSERVED_OR_QUALIFIED"
            ),
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "NO_DEDICATED_CAPTURE_OBSERVATION_BOUND",
            "CAPTURE_FRESHNESS_NOT_VERIFIED",
            "CAPTURE_DESTRUCTION_NOT_VERIFIED",
            "CAPTURE_INDEPENDENCE_NOT_VERIFIED",
            "PROPOSAL_APPLY_IS_PREREQUISITE_TO_INVALIDATION_OBSERVATION",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NO_MODEL_PROVIDER_REQUEST_SUCCESS_OR_DELIVERY_CLAIM",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
            "NOT_COMPOSED_WITH_OTHER_FRESH_CAMPAIGN_SUBFIXTURES",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "route_semantics": {
            "expected_action_id": _ACTION,
            "semantic_target_route": _ROUTE,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "shared_capture_independence_verified": False,
            "transition_predicates_verified": True,
        },
    }


def _verify_document(document: Mapping[str, Any]) -> None:
    if type(document) is not dict:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation document must be an object"
        )
    oracle.parent._verify_scalar_types(document)
    route = {
        "action_id": _ACTION,
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    runtime = oracle.parent.v3_contract.contract
    if (
        set(document) != _DOCUMENT_KEYS
        or document["schema"] != _SCHEMA
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE_DIGEST
        or document["selected_route_ids"] != [_ROUTE]
        or document["routes"] != [route]
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": runtime._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": runtime._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }
        or document["protected_boundary"].get("ready") is not True
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation document identity changed"
        )
    action = document["actions"][0]
    prerequisites = action["prerequisites"]
    draft = prerequisites["draft"]
    draft_file = draft["observation"]
    if (
        set(action) != _ACTION_KEYS
        or action["id"] != _ACTION
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or prerequisites["ready"] is not True
        or prerequisites["reason_codes"] != []
        or draft["expected_digest"] != _PROPOSAL_DIGEST
        or draft_file.get("path")
        != "/route-input/workshop-invalidation/PROPOSAL.md"
        or draft_file.get("exists") is not True
        or draft_file.get("type") != "file"
        or draft_file.get("uid") != 0
        or draft_file.get("gid") != 0
        or draft_file.get("mode") != "444"
        or draft_file.get("nlink") != 1
        or draft_file.get("size") != 84
        or draft_file.get("digest") != _PROPOSAL_DIGEST
        or set(action["observations"]) != _OBSERVATION_KEYS
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation action prerequisites changed"
        )
    _verify_transition(action, document["run_nonce"], document["recorded_at"])


def _verify_transition(
    action: Mapping[str, Any], nonce: str, recorded_at: str
) -> None:
    after = action["observations"]
    initial = after["initial_snapshot"]
    immediate = after["immediate_post_apply_snapshot"]
    final = after["final_snapshot"]
    initial_entry = initial["entry"]
    final_entry = final["entry"]
    initial_store = initial["file"]
    final_store = final["file"]
    next_turn = after["next_same_session_turn"]
    commands = action["commands"]
    proposed = after["native_proposal_result"]
    applied = after["native_apply_result"]
    pending_record = proposed["response"]["value"]["record"]
    applied_record = applied["response"]["value"]["record"]
    applied_at = applied_record["appliedAt"]
    parse = oracle.parent.contract.base.legacy._parse_time
    applied_ms = oracle.parent.contract.base.legacy._epoch_ms(applied_at)
    proposal_argv = proposed["command"]["argv"]
    if (
        proposed["response"].get("parsed") is not True
        or applied["response"].get("parsed") is not True
        or pending_record.get("status") != "pending"
        or applied_record.get("status") != "applied"
        or pending_record.get("id") != applied_record.get("id")
        or after["proposal_result"]
        != {"parsed": True, "proposal_id": applied_record.get("id")}
        or applied_record.get("appliedAt") != applied_record.get("updatedAt")
        or proposal_argv[-2:]
        != ["/route-input/workshop-invalidation/PROPOSAL.md", "--json"]
        or initial != immediate
        or after["target_final"] != after["target_after_apply"]
        or initial_entry["session_id"] != final_entry["session_id"]
        or initial_entry["skill_names"] != final_entry["skill_names"]
        or initial_entry["prompt"] != final_entry["prompt"]
        or type(initial_entry["snapshot_version"]) is not int
        or type(final_entry["snapshot_version"]) is not int
        or initial_entry["snapshot_version"] >= final_entry["snapshot_version"]
        or final_entry["snapshot_version"] != applied_ms
        or type(initial_entry["updated_at"]) is not int
        or type(final_entry["updated_at"]) is not int
        or initial_entry["updated_at"] >= final_entry["updated_at"]
        or initial_store["path"] != final_store["path"]
        or initial_store["device"] != final_store["device"]
        or initial_store["digest"] == final_store["digest"]
        or initial_store["inode"] == final_store["inode"]
        or after["catalog_before"]["response"]["value"]
        == after["catalog_after_apply"]["response"]["value"]
        or after["catalog_after_apply"]["response"]["value"]
        != after["final_catalog"]["response"]["value"]
        or commands
        != [
            after["catalog_before"]["command"],
            *after["initial_turn"]["commands"],
            proposed["command"],
            applied["command"],
            after["catalog_after_apply"]["command"],
            *next_turn["commands"],
            after["final_catalog"]["command"],
        ]
        or not (
            parse(applied["command"]["started_at"])
            <= parse(applied_at)
            <= parse(applied["command"]["completed_at"])
            <= parse(after["target_after_apply_observed_at"])
            <= parse(after["catalog_after_apply"]["command"]["started_at"])
            < parse(next_turn["send"]["command"]["started_at"])
            <= parse(next_turn["wait"]["command"]["completed_at"])
            <= parse(after["final_snapshot_observed_at"])
            <= parse(after["final_catalog"]["command"]["started_at"])
            <= parse(recorded_at)
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation post-apply transition changed"
        )
    proposal_id = applied_record["id"]
    expected_proposal_argv = [
        oracle.parent._NODE,
        oracle.parent._OPENCLAW,
        "skills",
        "workshop",
        "--agent",
        "main",
        "propose-create",
        "--name",
        oracle.parent._WORKSHOP,
        "--description",
        "Inert Aragorn protected workshop fixture",
        "--proposal",
        "/route-input/workshop-invalidation/PROPOSAL.md",
        "--json",
    ]
    oracle.parent._verify_command(proposed["command"], expected_proposal_argv)
    oracle.parent._verify_command(
        applied["command"],
        oracle.parent._gateway_argv(
            "skills.proposals.apply",
            params={"agentId": "main", "proposalId": proposal_id},
        ),
    )
    if (
        oracle.parent._load_strict_json_stdout(proposed["command"])
        != proposed["response"]["value"]
        or oracle.parent._load_strict_json_stdout(applied["command"])
        != applied["response"]["value"]
        or set(proposed["response"]["value"]) != {"content", "record"}
        or set(applied["response"]["value"]) != {"record", "targetSkillFile"}
        or applied["response"]["value"]["targetSkillFile"]
        != oracle.parent._WORKSHOP_FILE
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal response changed"
        )
    _verify_proposal_join(
        proposed["response"]["value"], applied["response"]["value"]
    )
    if (
        after["target_after_proposal"] != oracle.parent._absent_target()
        or after["target_final"] != after["target_after_apply"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation target transition changed"
        )
    oracle.parent._verify_residue(after["target_after_apply"])
    # Reuse the existing exact catalog and same-session-turn validators. Their
    # raw records are authority; the probe's summary booleans are intentionally
    # excluded from the qualification predicate.
    oracle.parent._verify_catalog(after["catalog_before"], initial=True)
    oracle.parent._verify_catalog(after["catalog_after_apply"], initial=False)
    oracle.parent._verify_catalog(after["final_catalog"], initial=False)
    oracle.parent._verify_turn(
        after["initial_turn"],
        nonce=nonce,
        label="initial-snapshot",
        message="Inert protected workshop initial snapshot observation.",
        snapshot=initial,
    )
    oracle.parent._verify_turn(
        next_turn,
        nonce=nonce,
        label="next-same-session",
        message="Inert protected workshop next same-session observation.",
        snapshot=final,
    )


def _verify_proposal_join(
    proposed: Mapping[str, Any], applied: Mapping[str, Any]
) -> None:
    pending = proposed["record"]
    final = applied["record"]
    immutable = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "schema",
        "target",
        "title",
    }
    _verify_proposal_record(pending, applied=False)
    _verify_proposal_record(final, applied=True)
    content = proposed["content"]
    if (
        type(content) is not str
        or oracle.parent._digest(content.encode())
        != f"sha256:{pending['draftHash']}"
        or {key: pending[key] for key in immutable}
        != {key: final[key] for key in immutable}
        or pending["status"] != "pending"
        or final["status"] != "applied"
        or final["appliedAt"] != final["updatedAt"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal/apply join changed"
        )


def _verify_proposal_record(value: Mapping[str, Any], *, applied: bool) -> None:
    keys = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "scan",
        "schema",
        "status",
        "target",
        "title",
        "updatedAt",
    }
    if applied:
        keys.add("appliedAt")
    scan = value["scan"]
    if (
        set(value) != keys
        or value["schema"] != "openclaw.skill-workshop.proposal.v1"
        or type(value["id"]) is not str
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", value["id"]) is None
        or value["kind"] != "create"
        or value["title"] != f"Create {oracle.parent._WORKSHOP}"
        or value["description"] != "Inert Aragorn protected workshop fixture"
        or value["createdBy"] != "cli"
        or value["proposedVersion"] != "v1"
        or value["draftFile"] != "PROPOSAL.md"
        or re.fullmatch(r"[0-9a-f]{64}", value["draftHash"]) is None
        or value["target"]
        != {
            "skillName": oracle.parent._WORKSHOP,
            "skillKey": oracle.parent._WORKSHOP,
            "skillDir": oracle.parent._WORKSHOP_ROOT,
            "skillFile": oracle.parent._WORKSHOP_FILE,
            "source": "openclaw-workspace",
        }
        or set(scan) != {"critical", "findings", "info", "scannedAt", "state", "warn"}
        or scan["state"] != "clean"
        or scan["critical"] != 0
        or scan["warn"] != 0
        or scan["info"] != 0
        or scan["findings"] != []
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal record changed"
        )
