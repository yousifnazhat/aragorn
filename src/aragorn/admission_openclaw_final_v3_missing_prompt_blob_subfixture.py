"""Verify exact missing-blob reconstruction semantics without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_fresh_session_reset as commands
from . import admission_protected_final_combined_v3_prompt_rebuild as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "missing-prompt-blob-rebuild"
_STABLE = (
    "boundary",
    "config_lock",
    "config_tree",
    "gateway_process",
    "openclaw",
    "protected_root_trees",
    "runtime_tree",
    "target",
)
_FILE_PROOF_KEYS = {"bytes", "digest", "mode", "mtime_ns", "nlink", "path"}


def verify_openclaw_final_v3_missing_prompt_blob_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute fixed-route predicates using this document's actual identities."""
    try:
        old.semantics._verify_scalar_types(document)
        old.current._verify_no_positive_eligibility(document)
        checks._verify_records(document)
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 missing-prompt semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-missing-prompt-blob-semantic-compatibility/v1",
        "assurance": "MISSING_PROMPT_BLOB_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "MISSING_PROMPT_BLOB_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in old.contract._ELIGIBILITY_KEYS},
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
            "FRESH_INPUT_VOLUME_AND_PROCESS_IDENTITY_REQUIRE_OUTER_CAPTURE_JOIN",
            "FIXED_TEMPLATE_SKILL_PROMPT_BLOB_UNLINK_AND_REBUILD_ONLY",
            "STORE_REWRITE_BYTES_AND_DIGEST_MATCH_NOT_FULL_SESSION_STATE_EQUIVALENCE",
            "MODEL_NETWORK_ERROR_IS_NOT_A_SUCCESSFUL_MODEL_REPLY",
            "NO_GLOBAL_NO_WRITE_CLEANUP_ROLLBACK_OR_GENERAL_RECONSTRUCTION_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 missing-prompt {label} changed")


def _verify_document(document: Mapping[str, Any]) -> None:
    _require(
        type(document) is dict
        and set(document)
        == {
            "action",
            "assurance",
            "implementation_digests",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        and document["schema"]
        == "aragorn/openclaw-protected-prompt-rebuild-observation/v1"
        and document["assurance"]
        == "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["implementation_digests"]
        == {
            "helper": old._PROBE_BUNDLE[1]["digest"],
            "probe": old._PROBE_BUNDLE[0]["digest"],
        }
        and document["route"]
        == {
            "action_id": _ACTION,
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None
        and document["runtime_binding"]
        == {
            "commit": old.contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": old.contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": old.current._RUNTIME_TREE["tree_digest"],
            "version": old.contract._OPENCLAW["version"],
        },
        "document identity",
    )
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    _require(
        set(action)
        == {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        and action["id"] == _ACTION
        and action["status"] == "OBSERVED"
        and action["reason_codes"] == []
        and action["execution_error"] is None
        and set(before)
        == {
            *(f"{name}_before" for name in _STABLE),
            "session_entry_absent_before",
            "system_info_before",
            "version",
        }
        and set(after)
        == {
            *(f"{name}_after" for name in _STABLE),
            "initial_snapshot",
            "initial_turn",
            "invalidation",
            "rebuild_turn",
            "rebuilt_snapshot",
            "system_info_after",
        }
        and before["session_entry_absent_before"] is True
        and all(
            checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in _STABLE
        ),
        "protected state stability",
    )
    _verify_boundary(before)
    for side, suffix in ((before, "before"), (after, "after")):
        checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    for name in ("initial_turn", "rebuild_turn"):
        _require(
            set(after[name]) == {"commands", "confirmed", "send", "wait"}, "turn shape"
        )
    for name in ("initial_snapshot", "rebuilt_snapshot"):
        _verify_snapshot_shape(after[name])
    invalidation = after["invalidation"]
    _require(
        set(invalidation)
        == {
            "blob_exists_after_unlink",
            "blob_path",
            "completed_at",
            "started_at",
            "store_after_rewrite",
            "store_before",
        },
        "invalidation shape",
    )
    for name in ("store_before", "store_after_rewrite"):
        _verify_file_proof(invalidation[name])
    old.semantics._verify_commands(
        action, document["run_nonce"], document["recorded_at"]
    )
    old.semantics.semantic._verify_rebuild(after)
    old.semantics._verify_rebuild_chronology(after, document["recorded_at"])
    _require(
        before["gateway_process_before"]["pid"]
        not in {value["pid"] for value in action["commands"]},
        "command and gateway PID disjointness",
    )
    for command in action["commands"]:
        # Exact argv and response meanings are checked by the frozen route helpers.
        commands._verify_command(command, command["argv"])


def _verify_boundary(before: Mapping[str, Any]) -> None:
    boundary = before["boundary_before"]
    config, gateway = boundary["configuration"], before["gateway_process_before"]
    _require(
        set(boundary)
        == {"configuration", "effective_identity", "probe", "ready", "roots", "runtime"}
        and boundary["ready"] is True
        and checks._same(
            boundary["effective_identity"], {"gid": 992, "groups": [992], "uid": 992}
        )
        and set(config) == {"canonical_digest", "document", "file", "mount", "ready"}
        and config["canonical_digest"] == canonical_digest(config["document"])
        and before["runtime_tree_before"] == old.current._RUNTIME_TREE
        and before["config_lock_before"]
        == {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
        and set(gateway)
        == {
            "cmdline",
            "effective_capabilities",
            "hostname",
            "no_new_privileges",
            "pid",
            "seccomp",
            "start_time_ticks",
        }
        and re.fullmatch(r"[0-9a-f]{12}", gateway["hostname"]) is not None
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None
        and type(gateway["pid"]) is int
        and gateway["pid"] > 1,
        "boundary shape",
    )
    old.v3_contract._verify_config(config)
    old.current._verify_gateway(gateway, gateway["hostname"])
    old.current._verify_openclaw(before["openclaw_before"])
    checks._verify_mount(
        config["mount"],
        path="/run/credentials/aragorn-agent-gateway.service",
        source="/",
    )
    checks._verify_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
    )
    source = boundary["probe"]["records"][0]["root"]
    _require(
        re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", source)
        is not None,
        "probe volume",
    )
    checks._verify_mount(boundary["probe"], path="/route-input", source=source)
    for mount, uid, gid, mode, entries in (
        (config["mount"], 992, 0, "500", ["openclaw-config"]),
        (boundary["runtime"], 0, 0, "755", ["bin", "lib"]),
        (boundary["probe"], 0, 0, "555", [_ACTION]),
    ):
        entry = mount["entry"]
        _require(
            entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (uid, gid, mode, entries),
            "mount root custody",
        )
    config_tree = before["config_tree_before"]
    _require(
        checks._same(config_tree["root"], config["mount"]["entry"])
        and checks._same(
            config_tree["entries"], [{**config["file"], "path": "openclaw-config"}]
        ),
        "config tree join",
    )
    _require(
        set(boundary["roots"]) == set(checks._ROOTS)
        and set(before["protected_root_trees_before"]) == set(checks._ROOTS),
        "protected root inventory",
    )
    for name, path in checks._ROOTS.items():
        root = boundary["roots"][name]
        entry = root["observation"]
        tree = before["protected_root_trees_before"][name]
        _require(
            set(root) == {"observation", "ready", "writable"}
            and root["ready"] is True
            and root["writable"] is True
            and entry["path"] == path
            and entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (992, 992, "700", [])
            and checks._same(tree["root"], entry)
            and tree["entries"] == [],
            "protected root tree join",
        )
    target = before["target_before"]
    root, entries = target["root"], target["entries"]
    _require(
        root["path"] == old.current._TARGET_ROOT
        and root["type"] == "directory"
        and (root["uid"], root["gid"], root["mode"], root["entries"])
        == (0, 0, "555", ["SKILL.md"])
        and len(entries) == 1,
        "target root",
    )
    file = entries[0]
    _require(
        file["path"] == "SKILL.md"
        and file["type"] == "file"
        and (file["uid"], file["gid"], file["mode"], file["nlink"]) == (0, 0, "444", 1)
        and file["size"] == old.current._SOURCES["skill"]["bytes"]
        and file["digest"] == old.current._SOURCES["skill"]["digest"],
        "target content",
    )


def _verify_file_proof(value: Mapping[str, Any], *, blob: bool = False) -> None:
    _require(
        set(value) == _FILE_PROOF_KEYS | ({"prompt_ref"} if blob else set())
        and type(value["bytes"]) is int
        and value["bytes"] > 0
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]) is not None
        and re.fullmatch(r"[1-9][0-9]*", value["mtime_ns"]) is not None
        and value["mode"] == "600"
        and type(value["nlink"]) is int
        and value["nlink"] == 1,
        "prompt/store file proof",
    )


def _verify_snapshot_shape(value: Mapping[str, Any]) -> None:
    entry = value["entry"]
    _require(
        set(value) == {"blob", "entry", "prompt"}
        and set(entry)
        == {
            "ended_at",
            "run_status",
            "runtime_ms",
            "session_id",
            "skill_filter",
            "skill_names",
            "snapshot_version",
            "started_at",
            "updated_at",
        }
        and all(
            type(entry[key]) is int and entry[key] > 0
            for key in ("ended_at", "snapshot_version", "started_at", "updated_at")
        )
        and type(entry["runtime_ms"]) is int
        and entry["runtime_ms"] >= 0,
        "snapshot shape and scalar types",
    )
    _verify_file_proof(value["blob"], blob=True)
