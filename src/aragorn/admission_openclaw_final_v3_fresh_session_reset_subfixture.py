"""Verify fresh-compatible reset/rebuild semantics without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_fresh_session_reset as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "fresh-session-reset"
_PARSE = old.contract.base.legacy._parse_time
_MILLIS = old.old.legacy._epoch_ms


def verify_openclaw_final_v3_fresh_session_reset_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute transition predicates with current-run identities and times."""
    try:
        old._verify_scalar_types(document)
        old.contract._verify_no_positive_eligibility(document)
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 fresh-session semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-fresh-session-reset-semantic-compatibility/v1",
        "assurance": "FRESH_SESSION_RESET_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "FRESH_SESSION_RESET_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in old.v3_contract.contract._ELIGIBILITY_KEYS},
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
            "FIXED_INERT_SESSION_RESET_AND_TEMPLATE_SKILL_PROMPT_REBUILD_ONLY",
            "MODEL_NETWORK_ERROR_IS_NOT_A_SUCCESSFUL_MODEL_REPLY",
            "SESSION_STORE_SELECTED_ENTRY_NOT_FULL_DATABASE_STATE_EQUIVALENCE",
            "OVERSIZE_NODE_BINARY_NOT_HASHED_REQUIRES_OUTER_IMAGE_BINDING",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 fresh-session {label} changed")


def _verify_document(document: Mapping[str, Any]) -> None:
    _require(
        type(document) is dict
        and set(document)
        == {
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
        and document["schema"]
        == "aragorn/openclaw-protected-route-action-observations/v1"
        and document["assurance"]
        == "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["implementation_digest"] == old._PROBE["digest"]
        and document["selected_route_ids"] == [_ROUTE]
        and document["routes"]
        == [
            {
                "action_id": _ACTION,
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        and type(document["actions"]) is list
        and len(document["actions"]) == 1
        and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None
        and document["runtime_binding"]
        == {
            "commit": old.v3_contract.contract._OPENCLAW["commit"],
            "node_path": old._NODE,
            "openclaw_path": old._OPENCLAW,
            "openclaw_digest": old.v3_contract.contract._RUNTIME["entrypoint_digest"],
            "version": old.v3_contract.contract._OPENCLAW["version"],
        },
        "document identity",
    )
    action = document["actions"][0]
    observed = action["observations"]
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
        and action["execution_error"] is None
        and action["reason_codes"] == []
        and set(observed)
        == {
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
        },
        "action shape",
    )
    checks._verify_records(
        [document["protected_boundary"], observed, action["commands"]]
    )
    _verify_boundary(document["protected_boundary"])
    _verify_prerequisites(action["prerequisites"])
    _verify_transition(document)


def _verify_boundary(value: Mapping[str, Any]) -> None:
    config = value["configuration"]
    _require(
        set(value)
        == {"configuration", "effective_identity", "ready", "roots", "runtime"}
        and value["ready"] is True
        and checks._same(value["effective_identity"], {"gid": 992, "uid": 992})
        and set(value["roots"]) == set(checks._ROOTS)
        and set(config)
        == {
            "canonical_digest",
            "expected_canonical_digest",
            "file",
            "json_object",
            "mount",
            "parse_error",
            "ready",
        }
        and config["json_object"] is True
        and config["parse_error"] is None
        and config["expected_canonical_digest"] == config["canonical_digest"],
        "protected boundary",
    )
    old.v3_contract._verify_config(config)
    checks._verify_mount(
        config["mount"],
        path="/run/credentials/aragorn-agent-gateway.service",
        source="/",
    )
    checks._verify_mount(
        value["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
    )
    for mount, uid, gid, mode, entries in (
        (config["mount"], 992, 0, "500", ["openclaw-config"]),
        (value["runtime"], 0, 0, "755", ["bin", "lib"]),
    ):
        entry = mount["entry"]
        _require(
            entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (uid, gid, mode, entries),
            "mount custody",
        )
    for name, path in checks._ROOTS.items():
        root = value["roots"][name]
        entry = root["observation"]
        _require(
            set(root) == {"observation", "ready", "writable"}
            and root["ready"] is True
            and root["writable"] is True
            and entry["path"] == path
            and entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (992, 992, "700", []),
            "protected root custody",
        )


def _verify_prerequisites(value: Mapping[str, Any]) -> None:
    gateway, runtime, commands = (
        value["gateway_process"],
        value["runtime_files"],
        value["commands"],
    )
    _require(
        set(value)
        == {
            "commands",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
        }
        and value["ready"] is True
        and value["reason_codes"] == []
        and set(gateway) == {"cmdline", "hostname", "pid", "start_time_ticks"}
        and gateway["cmdline"] == ["openclaw-gateway"]
        and type(gateway["pid"]) is int
        and gateway["pid"] > 1
        and re.fullmatch(r"[0-9a-f]{12}", gateway["hostname"]) is not None
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None
        and len(commands) == 2
        and checks._same(value["system_info"]["command"], commands[1]),
        "runtime prerequisites",
    )
    old._verify_runtime_files(runtime)
    node = runtime["node"]["file"]
    _require(
        set(node) == checks._FILE_KEYS
        and node["size"] == 121333752
        and node["nlink"] == 1
        and all(
            type(node[key]) is int and node[key] > 0 for key in ("device", "inode")
        ),
        "oversize node custody",
    )
    checks._verify_records(
        [
            commands,
            value["system_info"],
            gateway,
            runtime["openclaw"],
            list(node.values()),
        ]
    )
    checks._verify_system(value["system_info"], gateway)
    old._verify_command(
        commands[0],
        [old._NODE, old._OPENCLAW, "--version"],
        stdout_exact=old.v3_contract.contract._RUNTIME["version_output"] + "\n",
    )
    old._verify_command(
        commands[1],
        old._gateway_argv("system.info"),
        stdout_value=value["system_info"]["response"]["value"],
    )


def _verify_transition(document: Mapping[str, Any]) -> None:
    action = document["actions"][0]
    observed = action["observations"]
    before, rotated, after = (
        observed[name]
        for name in (
            "session_before_reset",
            "session_after_rotation",
            "session_after_reset",
        )
    )
    before_id, after_id = before["entry"]["session_id"], after["entry"]["session_id"]
    reset = observed["reset_turn"]
    nonce = document["run_nonce"]
    _require(
        old._UUID4.fullmatch(before_id) is not None
        and old._UUID4.fullmatch(after_id) is not None
        and before_id != after_id
        and set(rotated) == {"entry", "file", "present"}
        and rotated["present"] is True
        and checks._same(
            rotated["entry"],
            {
                "ended_at": None,
                "prompt": {
                    "bytes": None,
                    "digest": None,
                    "storage": "absent-or-invalid",
                },
                "runtime_ms": None,
                "session_id": after_id,
                "skill_names": [],
                "snapshot_present": False,
                "snapshot_version": None,
                "started_at": None,
                "status": None,
                "updated_at": rotated["entry"]["updated_at"],
            },
        )
        and type(rotated["entry"]["updated_at"]) is int
        and rotated["entry"]["updated_at"] > 0
        and set(reset)
        == {
            "accepted",
            "completed_at",
            "error",
            "method",
            "params",
            "response",
            "scopes",
            "started_at",
            "transport",
        }
        and reset["accepted"] is True
        and reset["error"] is None
        and reset["method"] == "chat.send"
        and checks._same(
            reset["params"],
            {
                "deliver": False,
                "idempotencyKey": f"aragorn-protected-route-fresh-session-reset-{nonce}",
                "message": "/new",
                "sessionKey": old._SESSION_KEY,
                "timeoutMs": 5000,
            },
        )
        and reset["response"]
        == {
            "runId": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "status": "started",
        }
        and reset["scopes"] == ["operator.admin", "operator.write"]
        and reset["transport"]
        == "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli",
        "rotation and reset request",
    )
    initial, rebuild = observed["initialization_turn"], observed["rebuild_turn"]
    for turn, label, snapshot, session_id in (
        (initial, "fresh-session-initialize", before, before_id),
        (rebuild, "fresh-session-rebuild", after, after_id),
    ):
        old._verify_turn(turn, label=label, nonce=nonce, snapshot=snapshot)
        old._verify_snapshot(snapshot, session_id=session_id)
    old._verify_store_file(rotated["file"])
    commands = [
        *action["prerequisites"]["commands"],
        *initial["commands"],
        *rebuild["commands"],
    ]
    _require(
        checks._same(action["commands"], initial["commands"] + rebuild["commands"])
        and all(
            type(command["pid"]) is int and command["pid"] > 1 for command in commands
        )
        and len({command["pid"] for command in commands}) == 6
        and action["prerequisites"]["gateway_process"]["pid"]
        not in {command["pid"] for command in commands}
        and all(
            _PARSE(left["completed_at"]) <= _PARSE(right["started_at"])
            for left, right in pairwise(commands)
        )
        and before["entry"]["snapshot_version"] == after["entry"]["snapshot_version"]
        and checks._same(before["entry"]["prompt"], after["entry"]["prompt"])
        and len({value["file"]["inode"] for value in (before, rotated, after)}) == 3
        and len({value["file"]["digest"] for value in (before, rotated, after)}) == 3
        and len({value["file"]["device"] for value in (before, rotated, after)}) == 1
        and _PARSE(initial["wait"]["command"]["completed_at"])
        <= _PARSE(reset["started_at"])
        <= _PARSE(reset["completed_at"])
        <= _PARSE(observed["rotation_observed_at"])
        <= _PARSE(rebuild["send"]["command"]["started_at"])
        < _PARSE(rebuild["wait"]["command"]["completed_at"])
        <= _PARSE(document["recorded_at"])
        and _MILLIS(reset["completed_at"])
        <= rotated["entry"]["updated_at"]
        <= _MILLIS(observed["rotation_observed_at"]),
        "snapshot identity and causality",
    )
    # Summary booleans must agree with the transition predicates recomputed above.
    _require(
        all(
            observed[name] is True
            for name in (
                "session_id_rotated",
                "reset_snapshot_cleared",
                "rebuilt_snapshot_matches_baseline",
            )
        )
        and all(
            checks._same(observed[name], {key: True for key in old._READY})
            for name in ("session_before_reset_check", "session_after_reset_check")
        ),
        "snapshot summary consistency",
    )
