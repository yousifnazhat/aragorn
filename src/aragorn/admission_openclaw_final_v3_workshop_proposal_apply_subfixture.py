"""Check fresh workshop proposal/apply semantics without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_workshop_invalidation_subfixture as shared
from . import admission_protected_final_combined_v3_workshop_proposal_apply as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "workshop-protected-apply"
_PROBE_DIGEST = old._PROBES[1]["digest"]
_PARSE = old.contract.base.legacy._parse_time


def verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Check actual document joins; never substitute retained run identities."""
    try:
        _verify_document(document)
        document_digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 workshop proposal/apply semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-workshop-proposal-apply-semantic-compatibility/v1",
        "assurance": (
            "WORKSHOP_PROPOSAL_APPLY_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_"
            "CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY"
        ),
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": _PROBE_DIGEST,
            "input_document_canonical_digest": document_digest,
        },
        "decision": {
            "status": "WORKSHOP_PROPOSAL_APPLY_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in shared._ELIGIBILITY_KEYS},
        },
        "route_semantics": {
            "expected_action_id": _ACTION,
            "semantic_target_route": _ROUTE,
            "transition_predicates_verified": True,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "shared_capture_independence_verified": False,
        },
        "limitations": [
            "NO_CAPTURE_EXECUTION_FRESHNESS_DESTRUCTION_OR_INDEPENDENCE_VERIFIED",
            "FRESH_INPUT_VOLUME_IDENTITY_REQUIRES_OUTER_CAPTURE_JOIN",
            "SNAPSHOT_STORE_BYTES_NOT_PRESENT_FOR_INDEPENDENT_REDERIVATION",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NO_MODEL_PROVIDER_REQUEST_SUCCESS_OR_DELIVERY_CLAIM",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _verify_document(document: Mapping[str, Any]) -> None:
    if type(document) is not dict:
        raise AdmissionEvidenceError("V3 workshop proposal document must be an object")
    old._verify_scalar_types(document)
    runtime = old.v3_contract.contract
    if (
        set(document) != shared._DOCUMENT_KEYS
        or document["schema"]
        != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE_DIGEST
        or document["selected_route_ids"] != [_ROUTE]
        or document["routes"]
        != [
            {
                "action_id": _ACTION,
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": runtime._OPENCLAW["commit"],
            "node_path": old._NODE,
            "openclaw_digest": runtime._RUNTIME["entrypoint_digest"],
            "openclaw_path": old._OPENCLAW,
            "version": "2026.7.1",
        }
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError("V3 workshop proposal document identity changed")
    old._verify_boundary(
        document["protected_boundary"],
        {
            "security": {"installPolicy": old.v3_contract.parent._POLICY},
            "skills": {
                "activation": {"authority": "external"},
                "workshop": {"restoreAuthority": "external"},
            },
        },
    )
    action = document["actions"][0]
    if (
        set(action) != shared._ACTION_KEYS
        or action["id"] != _ACTION
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or set(action["observations"]) != shared._OBSERVATION_KEYS
    ):
        raise AdmissionEvidenceError("V3 workshop proposal action changed")
    _verify_prerequisites(action["prerequisites"])
    _verify_transition(action, document["run_nonce"], document["recorded_at"])


def _verify_prerequisites(before: Mapping[str, Any]) -> None:
    gateway = before["gateway_process"]
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
        or len(before["commands"]) != 2
        or before["commands"][1] != before["system_info"]["command"]
        or set(gateway) != {"cmdline", "hostname", "pid", "start_time_ticks"}
        or gateway["cmdline"] != ["openclaw-gateway"]
        or re.fullmatch(r"[0-9a-f]{12}", gateway["hostname"]) is None
        or type(gateway["pid"]) is not int
        or gateway["pid"] <= 0
        or re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is None
        or before["target_before"] != old._absent_target()
    ):
        raise AdmissionEvidenceError("V3 workshop proposal prerequisites changed")
    old.contract._verify_version(before["commands"][0])
    system_info = before["system_info"]
    system = system_info["response"]["value"]
    if (
        set(system_info) != {"command", "response"}
        or set(system_info["response"]) != {"parsed", "value"}
        or system_info["response"]["parsed"] is not True
        or old._load_strict_json_stdout(system_info["command"]) != system
        or system["pid"] != gateway["pid"]
        or system["hostname"] != gateway["hostname"]
        or system["machineName"] != gateway["hostname"]
        or system["platform"] != "linux"
    ):
        raise AdmissionEvidenceError("V3 workshop proposal gateway identity changed")
    old._verify_command(before["commands"][0], [old._NODE, old._OPENCLAW, "--version"])
    old._verify_command(before["commands"][1], old._gateway_argv("system.info"))
    old._verify_runtime_files(before["runtime_files"])
    draft = before["draft"]
    file = draft["observation"]
    mount = draft["mount"]
    source = mount["records"][0]["root"]
    if (
        set(draft) != {"expected_digest", "mount", "observation"}
        or draft["expected_digest"] != old._FIXTURE["digest"]
        or file["path"] != "/route-input/workshop-proposal-apply/PROPOSAL.md"
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 0
        or file["gid"] != 0
        or file["mode"] != "444"
        or file["nlink"] != 1
        or file["size"] != old._FIXTURE["bytes"]
        or file["digest"] != old._FIXTURE["digest"]
        or file["digest_error"] is not None
        or mount["entry"]["entries"] != ["workshop-proposal-apply"]
        or mount["entry"]["entry_count"] != 1
        or mount["entry"]["entries_truncated"] is not False
        or mount["entry"]["exists"] is not True
        or mount["entry"]["type"] != "directory"
        or mount["entry"]["path"] != "/route-input"
        or mount["entry"]["uid"] != 0
        or mount["entry"]["gid"] != 0
        or mount["entry"]["mode"] != "555"
        or "rw" in mount["records"][0]["mount_options"]
        or re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", source)
        is None
    ):
        raise AdmissionEvidenceError("V3 workshop proposal draft changed")
    old.v3_contract._verify_read_only_mount(mount, path="/route-input", source=source)


def _verify_snapshot(snapshot: Mapping[str, Any]) -> None:
    entry, file = snapshot["entry"], snapshot["file"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    digest = old._PROTECTED_PROMPT_DIGEST
    prompt_path = (
        "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/"
        f"sha256/{digest[7:9]}/{digest[7:]}.txt"
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
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            entry["session_id"],
        )
        is None
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or entry["status"] != "timeout"
        or any(
            type(entry[key]) is not int or not 0 < entry[key] <= 2**53 - 1
            for key in (
                "ended_at",
                "runtime_ms",
                "snapshot_version",
                "started_at",
                "updated_at",
            )
        )
        or not entry["snapshot_version"]
        <= entry["started_at"]
        <= entry["ended_at"]
        <= entry["updated_at"]
        or set(prompt) != {"bytes", "digest", "expected_digest", "file", "storage"}
        or prompt["bytes"] != 737
        or prompt["digest"] != digest
        or prompt["expected_digest"] != digest
        or prompt["storage"] != "promptRef"
        or prompt_file["path"] != prompt_path
        or prompt_file["size"] != 737
        or prompt_file["digest"] != digest
        or file["path"]
        != "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
        or type(file["size"]) is not int
        or not 0 < file["size"] <= 4 * 1_048_576
        or re.fullmatch(r"sha256:[0-9a-f]{64}", file["digest"]) is None
    ):
        raise AdmissionEvidenceError("V3 workshop proposal protected snapshot changed")
    for value in (file, prompt_file):
        if (
            value["exists"] is not True
            or value["type"] != "file"
            or value["uid"] != 992
            or value["gid"] != 992
            or value["mode"] != "600"
            or value["nlink"] != 1
            or value["digest_error"] is not None
            or any(
                type(value[key]) is not int or value[key] <= 0
                for key in ("device", "inode")
            )
        ):
            raise AdmissionEvidenceError("V3 workshop proposal snapshot file changed")


def _verify_proposal(after: Mapping[str, Any]) -> None:
    proposed, applied = after["native_proposal_result"], after["native_apply_result"]
    for value, keys in (
        (proposed, {"content", "record"}),
        (applied, {"record", "targetSkillFile"}),
    ):
        if (
            set(value) != {"command", "response"}
            or set(value["response"]) != {"parsed", "value"}
            or value["response"]["parsed"] is not True
            or set(value["response"]["value"]) != keys
            or old._load_strict_json_stdout(value["command"])
            != value["response"]["value"]
        ):
            raise AdmissionEvidenceError("V3 workshop proposal response changed")
    pending = proposed["response"]["value"]["record"]
    final = applied["response"]["value"]["record"]
    shared._verify_proposal_join(
        proposed["response"]["value"], applied["response"]["value"]
    )
    expected_content = (
        f'---\nname: "{old._WORKSHOP}"\n'
        'description: "Inert Aragorn protected workshop fixture"\n'
        'status: proposal\nversion: "v1"\n'
        f'date: "{pending["createdAt"]}"\n---\n\n'
        "# Aragorn protected workshop route fixture\n\n"
        "This inert fixture performs no actions.\n"
    )
    if (
        proposed["response"]["value"]["content"] != expected_content
        or applied["response"]["value"]["targetSkillFile"] != old._WORKSHOP_FILE
        or after["proposal_result"] != {"parsed": True, "proposal_id": final["id"]}
        or not (
            _PARSE(proposed["command"]["started_at"])
            <= _PARSE(pending["createdAt"])
            == _PARSE(pending["updatedAt"])
            == _PARSE(pending["scan"]["scannedAt"])
            <= _PARSE(proposed["command"]["completed_at"])
            <= _PARSE(applied["command"]["started_at"])
            < _PARSE(final["scan"]["scannedAt"])
            <= _PARSE(final["appliedAt"])
            == _PARSE(final["updatedAt"])
            <= _PARSE(applied["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal identity or timeline changed"
        )
    old._verify_command(
        proposed["command"],
        [
            old._NODE,
            old._OPENCLAW,
            "skills",
            "workshop",
            "--agent",
            "main",
            "propose-create",
            "--name",
            old._WORKSHOP,
            "--description",
            "Inert Aragorn protected workshop fixture",
            "--proposal",
            "/route-input/workshop-proposal-apply/PROPOSAL.md",
            "--json",
        ],
    )
    old._verify_command(
        applied["command"],
        old._gateway_argv(
            "skills.proposals.apply",
            params={"agentId": "main", "proposalId": final["id"]},
        ),
    )


def _verify_transition(action: Mapping[str, Any], nonce: str, recorded_at: str) -> None:
    after = action["observations"]
    initial, final = after["initial_snapshot"], after["final_snapshot"]
    _verify_snapshot(initial)
    _verify_snapshot(final)
    _verify_proposal(after)
    for name, is_initial in (
        ("catalog_before", True),
        ("catalog_after_apply", False),
        ("final_catalog", False),
    ):
        old._verify_catalog(after[name], initial=is_initial)
    for name, label, message, snapshot in (
        (
            "initial_turn",
            "initial-snapshot",
            "Inert protected workshop initial snapshot observation.",
            initial,
        ),
        (
            "next_same_session_turn",
            "next-same-session",
            "Inert protected workshop next same-session observation.",
            final,
        ),
    ):
        old._verify_turn(
            after[name], nonce=nonce, label=label, message=message, snapshot=snapshot
        )
    # Probe summary values do not confer authority: validate their shape, then
    # derive the predicate from actual snapshots and command responses below.
    for name in (
        "initial_snapshot_check",
        "immediate_post_apply_snapshot_check",
        "final_snapshot_check",
    ):
        old._verify_snapshot_check(after[name])
    old._verify_residue(after["target_after_apply"])
    applied = after["native_apply_result"]
    proposed = after["native_proposal_result"]
    commands = action["commands"]
    all_commands = [*action["prerequisites"]["commands"], *commands]
    if (
        after["target_after_proposal"] != old._absent_target()
        or after["target_final"] != after["target_after_apply"]
        or after["immediate_post_apply_snapshot"] != initial
        or initial["entry"]["session_id"] != final["entry"]["session_id"]
        or initial["entry"]["prompt"] != final["entry"]["prompt"]
        or initial["entry"]["snapshot_version"] >= final["entry"]["snapshot_version"]
        or final["entry"]["snapshot_version"]
        != old.contract.base.legacy._epoch_ms(
            applied["response"]["value"]["record"]["appliedAt"]
        )
        or initial["entry"]["updated_at"] >= final["entry"]["updated_at"]
        or initial["file"]["device"] != final["file"]["device"]
        or initial["file"]["digest"] == final["file"]["digest"]
        or initial["file"]["inode"] == final["file"]["inode"]
        or set(after["final_snapshot_transition"])
        != {
            "same_store_device",
            "snapshot_version_advanced",
            "store_digest_changed",
            "store_inode_changed",
            "updated_at_advanced",
        }
        or commands
        != [
            after["catalog_before"]["command"],
            *after["initial_turn"]["commands"],
            proposed["command"],
            applied["command"],
            after["catalog_after_apply"]["command"],
            *after["next_same_session_turn"]["commands"],
            after["final_catalog"]["command"],
        ]
        or len({command["pid"] for command in all_commands}) != 11
        or any(
            _PARSE(left["completed_at"]) > _PARSE(right["started_at"])
            for left, right in pairwise(all_commands)
        )
        or _PARSE(all_commands[-1]["completed_at"]) > _PARSE(recorded_at)
        or not (
            _PARSE(after["initial_turn"]["wait"]["command"]["completed_at"])
            <= _PARSE(after["initial_snapshot_observed_at"])
            <= _PARSE(proposed["command"]["started_at"])
            < _PARSE(proposed["command"]["completed_at"])
            <= _PARSE(after["target_after_proposal_observed_at"])
            <= _PARSE(applied["command"]["started_at"])
            < _PARSE(applied["command"]["completed_at"])
            <= _PARSE(after["target_after_apply_observed_at"])
            <= _PARSE(after["immediate_post_apply_snapshot_observed_at"])
            <= _PARSE(after["catalog_after_apply"]["command"]["started_at"])
            < _PARSE(after["next_same_session_turn"]["send"]["command"]["started_at"])
            < _PARSE(after["next_same_session_turn"]["wait"]["command"]["completed_at"])
            <= _PARSE(after["final_snapshot_observed_at"])
            <= _PARSE(after["final_catalog"]["command"]["started_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal transition or command join changed"
        )
