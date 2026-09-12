"""Verify bounded chat snapshot semantics, never full unobserved session state."""

from __future__ import annotations

import json
import re
import tarfile
from collections.abc import Mapping
from functools import cache
from typing import Any

from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import (
    admission_protected_final_combined_v3_chat_session_snapshot_consumer as old,
)
from . import admission_protected_final_combined_v3_fresh_session_reset as commands
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = old._ROUTE
_ACTION = "session-snapshot-consumer-fixed"
_STABLE = (
    "boundary",
    "config",
    "config_lock",
    "config_tree",
    "gateway_process",
    "openclaw",
    "protected_root_trees",
    "runtime_tree",
    "target",
)
_PROOF_KEYS = {
    "bytes",
    "digest",
    "gid",
    "inode",
    "mode",
    "mtime_ns",
    "nlink",
    "path",
    "uid",
}


@cache
def _reference_bytes() -> bytes:
    """Cache immutable bytes only, after exact signed source/retention checks."""
    old._verify_dependencies()
    return canonical_json(
        json.loads(old._verify_retained_evidence())["route_observation"]["document"]
    )


@cache
def _closure_items() -> tuple[tuple[str, bytes], ...]:
    return tuple(old._verify_compiled_closure().items())


def verify_openclaw_final_v3_chat_session_snapshot_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify available bytes/projections and label opaque digest claims explicitly."""
    try:
        old.session.semantics._verify_scalar_types(document)
        old.current._verify_no_positive_eligibility(document)
        checks._verify_records(document)
        reference = json.loads(_reference_bytes())
        _verify_document(document, reference)
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
            f"invalid V3 chat snapshot semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-chat-session-snapshot-semantic-compatibility/v1",
        "assurance": "CHAT_SESSION_SNAPSHOT_AVAILABLE_BYTES_PROJECTIONS_AND_REPORTED_DIGEST_JOINS_ONLY_NOT_EXECUTION_FRESHNESS_FULL_STATE_EQUIVALENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
            "signed_template_retention": dict(old._RETENTION),
            "signed_template_evidence_digest": old._EVIDENCE["digest"],
            "compiled_closure": {
                name: dict(old.session._CLOSURE[name])
                for name in ("acquisition", "archive", "manifest")
            },
        },
        "decision": {
            "status": "CHAT_SESSION_SNAPSHOT_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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
        raise AdmissionEvidenceError(f"V3 chat snapshot {label} changed")


def _digest(value: Any) -> None:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "reported digest shape",
    )


def _same_keys(value: Any, reference: Mapping[str, Any]) -> None:
    _require(type(value) is dict and set(value) == set(reference), "object keys")


def _static_record(value: Mapping[str, Any], reference: Mapping[str, Any]) -> None:
    excluded = {"device", "inode"} | (
        {"size"} if reference["type"] == "directory" else set()
    )
    _require(
        checks._same(
            {k: v for k, v in value.items() if k not in excluded},
            {k: v for k, v in reference.items() if k not in excluded},
        ),
        "signed file contents and custody",
    )


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
        _same_keys(value, expected)
    _require(
        all(
            checks._same(document[key], reference[key])
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
            checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in _STABLE
        ),
        "document identity and protected state",
    )
    _verify_boundary(before, ref_before)
    for side, suffix in ((before, "before"), (after, "after")):
        checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    checks.old._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    old.session._verify_version(before["version"])
    for name in ("initial_turn", "injected_turn"):
        _same_keys(after[name], ref_after[name])
    _same_keys(after["native_recovery_timing"], ref_after["native_recovery_timing"])
    protected = ref_after["initial_snapshot"]["prompt"]["exact_text"]
    _require(
        len(protected.encode()) == 737
        and old._digest(protected.encode()) == old._PROTECTED_PROMPT_DIGEST,
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
        _verify_snapshot(after[name], prompt, nonce, ref_after["initial_snapshot"])
    _verify_mutation(document, reference, injected, marker)
    _verify_replay(document, reference, injected)
    for name in ("initial_system_prompt_report", "final_system_prompt_report"):
        _require(
            checks._same(after[name], ref_after[name]), "native unavailable report"
        )
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        *after["initial_turn"]["commands"],
        *after["injected_turn"]["commands"],
        after["system_info_after"]["command"],
    ]
    _require(
        checks._same(action["commands"], expected)
        and before["gateway_process_before"]["pid"]
        not in {value["pid"] for value in expected},
        "native command aliases and PID separation",
    )
    for command in action["commands"]:
        commands._verify_command(command, command["argv"])
    old._verify_chat_persistence(document)
    old._verify_route_chronology(action, document["recorded_at"])


def _verify_boundary(before: Mapping[str, Any], reference: Mapping[str, Any]) -> None:
    boundary, ref_boundary = before["boundary_before"], reference["boundary_before"]
    config, gateway = boundary["configuration"], before["gateway_process_before"]
    for value, expected in (
        (boundary, ref_boundary),
        (config, ref_boundary["configuration"]),
        (gateway, reference["gateway_process_before"]),
    ):
        _same_keys(value, expected)
    _require(
        boundary["ready"] is True
        and checks._same(
            boundary["effective_identity"], {"gid": 992, "groups": [992], "uid": 992}
        )
        and checks._same(before["config_before"], config)
        and config["canonical_digest"] == canonical_digest(config["document"])
        and before["config_lock_before"] == reference["config_lock_before"]
        and before["runtime_tree_before"] == old.current._RUNTIME_TREE
        and re.fullmatch(r"[0-9a-f]{12}", gateway["hostname"]) is not None
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None
        and type(gateway["pid"]) is int
        and gateway["pid"] > 1,
        "protected boundary",
    )
    old.v3_contract._verify_config(config)
    old.current._verify_gateway(gateway, gateway["hostname"])
    old.current._verify_openclaw(before["openclaw_before"])
    source = boundary["probe"]["records"][0]["root"]
    _require(
        re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", source)
        is not None,
        "probe volume",
    )
    for mount, expected, path, root in (
        (
            config["mount"],
            ref_boundary["configuration"]["mount"],
            "/run/credentials/aragorn-agent-gateway.service",
            "/",
        ),
        (
            boundary["runtime"],
            ref_boundary["runtime"],
            "/runtime",
            f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
        ),
        (boundary["probe"], ref_boundary["probe"], "/route-input", source),
    ):
        checks._verify_mount(mount, path=path, source=root)
        _static_record(mount["entry"], expected["entry"])
    _require(
        before["openclaw_before"]["device"] == boundary["runtime"]["entry"]["device"],
        "runtime executable mount join",
    )
    tree = before["config_tree_before"]
    _require(
        checks._same(tree["root"], config["mount"]["entry"])
        and checks._same(
            tree["entries"], [{**config["file"], "path": "openclaw-config"}]
        )
        and config["file"]["device"] == tree["root"]["device"],
        "configuration tree join",
    )
    target, expected_target = before["target_before"], reference["target_before"]
    _require(
        len(target["entries"]) == 1
        and target["root"]["device"] == target["entries"][0]["device"],
        "target tree join",
    )
    _static_record(target["root"], expected_target["root"])
    _static_record(target["entries"][0], expected_target["entries"][0])
    _require(
        set(boundary["roots"])
        == set(before["protected_root_trees_before"])
        == set(checks._ROOTS),
        "protected roots inventory",
    )
    for name in checks._ROOTS:
        value, tree = (
            boundary["roots"][name],
            before["protected_root_trees_before"][name],
        )
        _require(
            set(value) == {"observation", "ready", "writable"}
            and value["ready"] is True
            and value["writable"] is True
            and checks._same(tree["root"], value["observation"])
            and tree["entries"] == [],
            "protected root tree join",
        )
        _static_record(value["observation"], ref_boundary["roots"][name]["observation"])


def _file_proof(
    value: Mapping[str, Any], *, extras: set[str] | frozenset[str] = frozenset()
) -> None:
    _require(
        set(value) == _PROOF_KEYS | extras
        and all(
            type(value[key]) is int for key in ("bytes", "gid", "inode", "nlink", "uid")
        )
        and 0 < value["bytes"] <= 512 * 1024
        and value["inode"] > 1
        and (value["uid"], value["gid"], value["mode"], value["nlink"])
        == (992, 992, "600", 1)
        and type(value["path"]) is str
        and re.fullmatch(r"[1-9][0-9]*", value["mtime_ns"]) is not None,
        "reported state file custody",
    )
    _digest(value["digest"])


def _verify_snapshot(
    value: Mapping[str, Any], prompt: str, nonce: str, reference: Mapping[str, Any]
) -> None:
    for key in ("entry", "prompt", "snapshot"):
        _same_keys(value[key], reference[key])
    _same_keys(value, reference)
    entry, metadata = value["entry"], value["snapshot"]["metadata"]
    _same_keys(metadata, reference["snapshot"]["metadata"])
    _digest(value["entry_digest"])
    _file_proof(value["store"], extras={"top_level_keys"})
    _file_proof(value["blob"], extras={"prompt_ref"})
    raw, digest = prompt.encode(), old._digest(prompt.encode())
    ref = {
        "algorithm": "sha256",
        "bytes": len(raw),
        "hash": digest.removeprefix("sha256:"),
        "version": 1,
    }
    _require(
        value["present"] is True
        and value["prompt"]
        == {
            "bytes": len(raw),
            "characters": len(prompt.encode("utf-16-le")) // 2,
            "digest": digest,
            "exact_text": prompt,
            "storage": "promptRef",
        }
        and value["blob"]["digest"] == digest
        and value["blob"]["bytes"] == len(raw)
        and checks._same(value["blob"]["prompt_ref"], ref)
        and value["blob"]["path"]
        == f"/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/sha256/{ref['hash'][:2]}/{ref['hash']}.txt"
        and value["store"]["path"]
        == "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
        and value["store"]["top_level_keys"]
        == [
            f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}",
            "agent:main:aragorn-worker-coherent",
        ]
        and value["store"]["inode"] != value["blob"]["inode"]
        and entry["run_status"] == "timeout"
        and entry["system_prompt_report"] is None
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            entry["session_id"],
        )
        is not None
        and all(
            type(entry[key]) is int and entry[key] >= 0
            for key in ("ended_at", "runtime_ms", "started_at", "updated_at")
        )
        and 0 < entry["started_at"] <= entry["ended_at"] <= entry["updated_at"]
        and entry["runtime_ms"] == entry["ended_at"] - entry["started_at"]
        and metadata
        == {**reference["snapshot"]["metadata"], "version": metadata["version"]}
        and type(metadata["version"]) is int
        and 0 < metadata["version"] <= entry["started_at"]
        and value["snapshot"]["metadata_digest"] == canonical_digest(metadata)
        and value["snapshot"]["prompt_field_present"] is False
        and value["snapshot"]["prompt_ref_present"] is True,
        "available prompt bytes and native snapshot projection",
    )


def _verify_mutation(
    document: Mapping[str, Any],
    reference: Mapping[str, Any],
    injected: str,
    marker: str,
) -> None:
    after, ref_after = (
        document["action"]["observations"],
        reference["action"]["observations"],
    )
    initial, mutated, final, mutation = (
        after[name]
        for name in (
            "initial_snapshot",
            "mutated_snapshot",
            "final_snapshot",
            "mutation",
        )
    )
    _same_keys(mutation, ref_after["mutation"])
    preserved = mutation["preserved_entry_without_prompt_ref"]
    _same_keys(preserved, ref_after["mutation"]["preserved_entry_without_prompt_ref"])
    _digest(preserved["before_digest"])
    _file_proof(after["attacker_blob_after"])
    nonce = document["run_nonce"]
    _require(
        after["compiled_protected_prompt_boundary_observed"] is True
        and preserved["exact_equal"] is True
        and preserved["before_digest"] == preserved["after_digest"]
        and checks._same(after["pre_injected_snapshot"], mutated)
        and checks._same(initial["snapshot"], mutated["snapshot"])
        and checks._same(initial["snapshot"], final["snapshot"])
        and checks._same(initial["entry"], mutated["entry"])
        and mutation["changed_json_paths"]
        == [
            f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}.skillsSnapshot.promptRef"
        ]
        and mutation["injected_marker"] == marker
        and mutation["entry_before_digest"] == initial["entry_digest"]
        and mutation["entry_after_digest"] == mutated["entry_digest"]
        and initial["entry_digest"] != mutated["entry_digest"]
        and checks._same(mutation["store_before"], initial["store"])
        and checks._same(
            mutation["store_after_rewrite"],
            {k: v for k, v in mutated["store"].items() if k != "top_level_keys"},
        )
        and initial["store"]["digest"] != mutated["store"]["digest"]
        and initial["store"]["inode"] != mutated["store"]["inode"]
        and final["store"]["inode"] != mutated["store"]["inode"]
        and checks._same(mutation["blob"], {**mutated["blob"], "exact_text": injected})
        and checks._same(
            {k: v for k, v in after["attacker_blob_after"].items() if k != "mtime_ns"},
            {
                k: v
                for k, v in mutated["blob"].items()
                if k not in {"mtime_ns", "prompt_ref"}
            },
        )
        and after["attacker_blob_unreferenced_after"] is True
        and mutation["atomic_store_replacement"]
        == {
            "directory_fsync": True,
            "rename_completed": True,
            "same_directory": True,
            "temporary_path": f"/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json.aragorn-{nonce}.tmp",
            "temporary_path_absent_after": True,
        },
        "reported mutation digest joins",
    )


def _verify_replay(
    document: Mapping[str, Any], reference: Mapping[str, Any], injected: str
) -> None:
    after, ref_after = (
        document["action"]["observations"],
        reference["action"]["observations"],
    )
    replay, expected = (
        after["compiled_route_replay"],
        ref_after["compiled_route_replay"],
    )
    _same_keys(replay, expected)
    initial = after["initial_snapshot"]
    session_id, nonce = initial["entry"]["session_id"], document["run_nonce"]
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    closure = dict(_closure_items())
    old.session.semantics.semantic._verify_module_files(replay["module_files"], closure)
    old.session.semantics.semantic._verify_source_bridges(
        replay["handoff_statements"], closure
    )
    runtime_device = document["action"]["prerequisites"]["boundary_before"]["runtime"][
        "entry"
    ]["device"]
    for name, value in replay["module_files"].items():
        _require(
            value["path"] == expected["module_files"][name]["path"]
            and value["device"] == runtime_device,
            "compiled module role and mount join",
        )
    for key in ("baseline_loaded_entry_digest", "mutated_loaded_entry_digest"):
        _digest(replay[key])
    _require(
        replay["baseline_loaded_entry_digest"] != replay["mutated_loaded_entry_digest"],
        "reported hydrated entry digests",
    )
    inputs = json.loads(canonical_json(expected["non_skill_render_inputs"]))
    inputs["runtimeInfo"].update(sessionId=session_id, sessionKey=session_key)
    _require(
        checks._same(replay["non_skill_render_inputs"], inputs)
        and replay["non_skill_render_inputs_digest"] == canonical_digest(inputs),
        "signed render inputs and identity joins",
    )
    resolver = replay["resolver"]
    _same_keys(resolver, expected["resolver"])
    resolved = json.loads(canonical_json(expected["resolver"]["baseline_snapshot"]))
    resolved["version"] = initial["snapshot"]["metadata"]["version"]
    expected_resolver = {
        **expected["resolver"],
        "baseline_snapshot": resolved,
        "injected_snapshot": resolved,
        "baseline_snapshot_digest": canonical_digest(resolved),
        "injected_snapshot_digest": canonical_digest(resolved),
        **{
            key: resolved["version"]
            for key in (
                "persisted_snapshot_version",
                "baseline_snapshot_version",
                "injected_snapshot_version",
            )
        },
    }
    _require(
        checks._same(resolver, expected_resolver), "signed reusable snapshot resolver"
    )
    system_prompt = (
        expected["baseline_render"]["system_prompt"]
        .replace(reference["run_nonce"], nonce)
        .replace(ref_after["initial_snapshot"]["entry"]["session_id"], session_id)
    )
    rendered = {**expected["baseline_render"], "system_prompt": system_prompt}
    report = json.loads(canonical_json(expected["baseline_report"]))
    report.update(sessionId=session_id, sessionKey=session_key)
    chars = len(system_prompt.encode("utf-16-le")) // 2
    report["systemPrompt"].update(
        chars=chars,
        nonProjectContextChars=chars,
        hash=old._digest(system_prompt.encode()).removeprefix("sha256:"),
    )
    _require(
        replay["assurance"] == expected["assurance"]
        and replay["ready"] is True
        and replay["native_agent_execution"] is False
        and replay["consumer_chain"] == expected["consumer_chain"]
        and checks._same(replay["baseline_render"], rendered)
        and checks._same(replay["injected_render"], rendered)
        and checks._same(replay["baseline_report"], report)
        and checks._same(replay["injected_report"], report)
        and replay["hydrated_inputs"]
        == {
            "baseline_prompt_digest": old._PROTECTED_PROMPT_DIGEST,
            "injected_marker_count": 1,
            "injected_prompt_digest": old._digest(injected.encode()),
        },
        "signed compiled prompt and reports",
    )
    baseline = replay["baseline_store_copy"]
    _file_proof(baseline, extras={"absent_after_replay"})
    store = initial["store"]
    _require(
        baseline
        == {
            **{
                k: v
                for k, v in store.items()
                if k not in {"top_level_keys", "inode", "mtime_ns", "path"}
            },
            "absent_after_replay": True,
            "inode": baseline["inode"],
            "mtime_ns": baseline["mtime_ns"],
            "path": f"{store['path']}.aragorn-{nonce}.baseline.json",
        }
        and baseline["inode"]
        not in {
            after["mutated_snapshot"]["store"]["inode"],
            initial["blob"]["inode"],
            after["mutated_snapshot"]["blob"]["inode"],
        }
        and old.current.base.legacy._epoch_ms(after["mutation"]["completed_at"])
        <= int(baseline["mtime_ns"]) // 1_000_000
        <= old.current.base.legacy._epoch_ms(
            after["injected_turn"]["send"]["command"]["started_at"]
        ),
        "reported baseline copy and chronology",
    )
