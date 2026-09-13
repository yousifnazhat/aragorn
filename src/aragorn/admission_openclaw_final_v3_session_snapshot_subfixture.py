"""Verify bounded session snapshot projections, never unobserved full state."""

from __future__ import annotations

import json
import re
import tarfile
from collections.abc import Mapping
from functools import cache
from typing import Any

from . import admission_openclaw_final_v3_chat_session_snapshot_subfixture as shared
from . import admission_protected_final_combined_v3_session_snapshot_consumer as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = old._ROUTE
_ACTION = "session-snapshot-consumer-fixed"


@cache
def _reference_bytes() -> bytes:
    """Bind this route's signed template and the shared immutable compiled closure."""
    old._verify_dependencies()
    _require(
        old._verify_compiled_closure() == dict(shared._closure_items()),
        "independent signed compiled closure",
    )
    return canonical_json(
        json.loads(old._verify_retained_evidence())["route_observation"]["document"]
    )


def verify_openclaw_final_v3_session_snapshot_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify available bytes and reported joins without capture or PASS authority."""
    try:
        old.semantics._verify_scalar_types(document)
        old.current._verify_no_positive_eligibility(document)
        shared.checks._verify_records(document)
        _verify_document(document, json.loads(_reference_bytes()))
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        EOFError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        OverflowError,
        tarfile.TarError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 session snapshot semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-session-snapshot-semantic-compatibility/v1",
        "assurance": "SESSION_SNAPSHOT_AVAILABLE_BYTES_PROJECTIONS_AND_REPORTED_DIGEST_JOINS_ONLY_NOT_EXECUTION_FRESHNESS_FULL_STATE_EQUIVALENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
            "signed_template_retention": dict(old._RETENTION),
            "signed_template_evidence_digest": old._EVIDENCE["digest"],
            "compiled_closure": {
                name: dict(old._CLOSURE[name])
                for name in ("acquisition", "archive", "manifest")
            },
        },
        "decision": {
            "status": "SESSION_SNAPSHOT_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in old.contract._ELIGIBILITY_KEYS},
        },
        "route_semantics": {
            "expected_action_id": _ACTION,
            "semantic_target_route": _ROUTE,
            "available_prompt_bytes_and_native_projections_verified": True,
            "compiled_module_and_source_bridge_bindings_verified": True,
            "reported_mutation_digest_joins_verified": True,
            "entry_and_store_raw_bytes_verified": False,
            "full_session_state_equivalence_verified": False,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "shared_capture_independence_verified": False,
        },
        "limitations": [
            "NO_CAPTURE_EXECUTION_FRESHNESS_DESTRUCTION_OR_INDEPENDENCE_VERIFIED",
            "FRESH_INPUT_VOLUME_AND_PROCESS_IDENTITY_REQUIRE_OUTER_CAPTURE_JOIN",
            "EXACT_737_BYTE_PROTECTED_PROMPT_AND_ONE_INERT_MARKER_ONLY",
            "ENTRY_STORE_AND_LOADED_ENTRY_BYTES_NOT_CAPTURED_DIGEST_JOINS_ARE_REPORTED_CLAIMS_ONLY",
            "REPORTED_SINGLE_PROMPTREF_MUTATION_NOT_INDEPENDENT_FULL_STORE_DIFF_VERIFICATION",
            "SIGNED_COMPILED_RENDER_TEMPLATE_WITH_EXACT_SESSION_IDENTITY_SUBSTITUTIONS_NOT_LOCAL_REEXECUTION",
            "COMPILED_REPLAY_IS_NOT_NATIVE_AGENT_EXECUTION_OR_A_SUCCESSFUL_MODEL_REPLY",
            "INERT_BLOB_REMAINS_UNREFERENCED_NOT_DELETED_NO_GLOBAL_NO_WRITE_CLEANUP_OR_ROLLBACK_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 session snapshot {label} changed")


def _verify_document(document: Mapping[str, Any], reference: Mapping[str, Any]) -> None:
    action, ref_action = document["action"], reference["action"]
    before, after = action["prerequisites"], action["observations"]
    ref_before, ref_after = ref_action["prerequisites"], ref_action["observations"]
    for value, expected in (
        (document, reference),
        (action, ref_action),
        (before, ref_before),
        (after, ref_after),
    ):
        shared._same_keys(value, expected)
    _require(
        all(
            shared.checks._same(document[key], reference[key])
            for key in (
                "schema",
                "assurance",
                "implementation_digests",
                "route",
                "runtime_binding",
            )
        )
        and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None
        and action["id"] == _ACTION
        and action["status"] == "OBSERVED"
        and action["reason_codes"] == []
        and action["execution_error"] is None
        and before["session_entry_absent_before"] is True
        and all(
            shared.checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in shared._STABLE
        ),
        "document identity and protected state",
    )
    shared._verify_boundary(before, ref_before)
    for side, suffix in ((before, "before"), (after, "after")):
        shared.checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    shared.checks.old._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    old._verify_version(before["version"])
    protected = ref_after["initial_snapshot"]["prompt"]["exact_text"]
    _require(
        len(protected.encode()) == 737
        and old._digest(protected.encode()) == shared.old._PROTECTED_PROMPT_DIGEST,
        "signed protected prompt",
    )
    nonce = document["run_nonce"]
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    injected = (
        protected
        + "\n\n<inert_attacker_controlled_snapshot>\n"
        + marker
        + "\nThis marker is observation data only and requests no tool or external action.\n</inert_attacker_controlled_snapshot>"
    )
    for name, prompt in (
        ("initial_snapshot", protected),
        ("mutated_snapshot", injected),
        ("pre_injected_snapshot", injected),
        ("final_snapshot", protected),
    ):
        shared._verify_snapshot(
            after[name], prompt, nonce, ref_after["initial_snapshot"]
        )
    shared._verify_mutation(document, reference, injected, marker)
    shared._verify_replay(document, reference, injected)
    for name in ("initial_system_prompt_report", "final_system_prompt_report"):
        _require(
            shared.checks._same(after[name], ref_after[name]),
            "native unavailable report",
        )
    _verify_native(action, ref_action, nonce)
    old._verify_route_chronology(action, document["recorded_at"])


def _verify_native(
    action: Mapping[str, Any], reference: Mapping[str, Any], nonce: str
) -> None:
    before, after = action["prerequisites"], action["observations"]
    ref_after = reference["observations"]
    session_ids = {
        after[name]["entry"]["session_id"]
        for name in (
            "initial_snapshot",
            "mutated_snapshot",
            "pre_injected_snapshot",
            "final_snapshot",
        )
    }
    for label in ("initial", "injected"):
        turn = after[f"{label}_turn"]
        expected = ref_after[f"{label}_turn"]
        shared._same_keys(turn, expected)
        shared._same_keys(
            turn["wait"]["response"]["value"], expected["wait"]["response"]["value"]
        )
        old.semantics.semantic._verify_turn(turn, label, nonce)
    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        *after["initial_turn"]["commands"],
        *after["injected_turn"]["commands"],
        after["system_info_after"]["command"],
    ]
    _require(
        len(session_ids) == 1
        and shared.checks._same(action["commands"], expected_commands)
        and before["gateway_process_before"]["pid"]
        not in {value["pid"] for value in expected_commands},
        "native session identity and command aliases",
    )
    for command in action["commands"]:
        shared.commands._verify_command(command, command["argv"])
    timing = after["native_recovery_timing"]
    shared._same_keys(timing, ref_after["native_recovery_timing"])
    entry, store = after["final_snapshot"]["entry"], after["final_snapshot"]["store"]
    epoch_ms = old.current.base.legacy._epoch_ms
    _require(
        timing["ready"] is True
        and all(type(timing[key]) is int for key in timing if key != "ready")
        and timing["injected_send_started_at"]
        == epoch_ms(after["injected_turn"]["send"]["command"]["started_at"])
        and timing["injected_wait_ended_at"]
        == after["injected_turn"]["wait"]["response"]["value"]["endedAt"]
        and timing["injected_wait_completed_at"]
        == epoch_ms(after["injected_turn"]["wait"]["command"]["completed_at"])
        and timing["final_entry_started_at"] == entry["started_at"]
        and timing["final_entry_updated_at"] == entry["updated_at"]
        and timing["final_store_mtime_ms"] == int(store["mtime_ns"]) // 1_000_000
        and timing["injected_send_started_at"]
        <= entry["started_at"]
        <= entry["ended_at"]
        <= entry["updated_at"]
        <= timing["injected_wait_ended_at"]
        <= timing["injected_wait_completed_at"],
        "native recovery timing joins",
    )
