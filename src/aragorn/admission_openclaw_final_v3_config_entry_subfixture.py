"""Check one current-run config-entry denial without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_config_entry_activation as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "config-entry-activation"
_STABLE = (
    "boundary",
    "config",
    "config_lock",
    "gateway_process",
    "openclaw",
    "runtime_tree",
    "target",
)
_COMMAND_KEYS = {
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


def verify_openclaw_final_v3_config_entry_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify predicates and actual identity joins, never qualify a capture."""
    try:
        old.config._verify_scalar_types(document)
        old.config._verify_no_positive_eligibility(document)
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 config-entry semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-config-entry-semantic-compatibility/v1",
        "assurance": "CONFIG_ENTRY_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "CONFIG_ENTRY_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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
            "TEMPLATE_SKILL_ALREADY_AVAILABLE_AND_ELIGIBLE_BEFORE_ACTION",
            "ONLY_ENABLED_TRUE_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_OBSERVED",
            "NO_DISABLED_TO_ENABLED_ACTIVATION_TRANSITION_OR_INSTALL_POLICY_CAUSALITY_CLAIM",
            "NO_GLOBAL_NO_WRITE_CONFIG_LOGICAL_EQUIVALENCE_ROLLBACK_OR_CAUSALITY_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 config-entry {label} changed")


def _verify_document(document: Mapping[str, Any]) -> None:
    _require(
        type(document) is dict
        and set(document)
        == {
            "action",
            "assurance",
            "implementation_digest",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        and document["schema"]
        == "aragorn/openclaw-protected-config-activation-observation/v1"
        and document["assurance"]
        == "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["implementation_digest"] == old._PROBE["digest"]
        and document["route"] == old.value_route()
        and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None
        and document["runtime_binding"]
        == {
            "commit": old.contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": old.contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": old.config._RUNTIME_TREE["tree_digest"],
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
            "discovery_before",
            "system_info_before",
            "version",
        }
        and set(after)
        == {
            *(f"{name}_after" for name in _STABLE),
            "discovery_after",
            "system_info_after",
            "update",
        }
        and all(
            checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in _STABLE
        ),
        "protected state stability",
    )
    update = after["update"]
    _require(set(update) == {"command", "params", "response"}, "update shape")
    # The shared record checker has no params-bearing command wrapper.
    checks._verify_records(
        [
            before,
            action["commands"],
            *[value for key, value in after.items() if key != "update"],
            {"command": update["command"], "response": update["response"]},
        ]
    )
    _verify_boundary(before)
    old.config._verify_openclaw(before["openclaw_before"])
    old.config._verify_version(before["version"])
    old.config._verify_update(update)
    for suffix, side in (("before", before), ("after", after)):
        old.config._verify_discovery(side[f"discovery_{suffix}"])
        checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    old.config._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    _require(
        checks._same(
            before["discovery_before"]["response"], after["discovery_after"]["response"]
        )
        and before["discovery_before"]["command"]["stdout_digest"]
        == after["discovery_after"]["command"]["stdout_digest"],
        "discovery stability",
    )
    commands = action["commands"]
    _require(
        checks._same(
            commands,
            [
                before["version"],
                before["system_info_before"]["command"],
                before["discovery_before"]["command"],
                update["command"],
                after["discovery_after"]["command"],
                after["system_info_after"]["command"],
            ],
        )
        and len({command["pid"] for command in commands}) == 6
        and before["gateway_process_before"]["pid"]
        not in {command["pid"] for command in commands}
        and all(
            set(command) == _COMMAND_KEYS
            and type(command["pid"]) is int
            and command["pid"] > 0
            and all(
                type(command[key]) is int
                for key in ("exit_code", "stdout_bytes", "stderr_bytes")
            )
            and command["error"] is None
            and command["signal"] is None
            and old.config._command_output_is_exact(command)
            and old.parent._time(command["started_at"])
            <= old.parent._time(command["completed_at"])
            for command in commands
        )
        and all(
            old.parent._time(left["completed_at"])
            <= old.parent._time(right["started_at"])
            for left, right in pairwise(commands)
        )
        and old.parent._time(commands[-1]["completed_at"])
        <= old.parent._time(document["recorded_at"]),
        "command causality",
    )


def _verify_boundary(before: Mapping[str, Any]) -> None:
    boundary = before["boundary_before"]
    config = boundary["configuration"]
    gateway = before["gateway_process_before"]
    _require(
        set(boundary)
        == {"configuration", "effective_identity", "probe", "ready", "roots", "runtime"}
        and boundary["ready"] is True
        and boundary["effective_identity"] == {"gid": 992, "groups": [992], "uid": 992}
        and set(config) == {"canonical_digest", "file", "mount", "ready"}
        and config == before["config_before"]
        and before["config_lock_before"]
        == {"exists": False, "path": f"{old._CONFIG_PATH}.lock"}
        and before["runtime_tree_before"] == old.config._RUNTIME_TREE
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
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None,
        "boundary shape",
    )
    old._verify_config(config)
    old.config._verify_gateway(gateway, gateway["hostname"])
    checks._verify_mount(
        config["mount"],
        path="/run/credentials/aragorn-agent-gateway.service",
        source="/",
    )
    checks._verify_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{old.config._RUNTIME_VOLUME}/_data",
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
            "mount custody",
        )
    _require(set(boundary["roots"]) == set(checks._ROOTS), "root inventory")
    for name, path in checks._ROOTS.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        _require(
            set(value) == {"observation", "ready", "writable"}
            and value["ready"] is True
            and value["writable"] is True
            and entry["path"] == path
            and entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (992, 992, "700", []),
            "protected root custody",
        )
    target = before["target_before"]
    root, entries = target["root"], target["entries"]
    _require(
        root["path"] == old._TARGET_ROOT
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
        and file["size"] == old.config._SOURCES["skill"]["bytes"]
        and file["digest"] == old.config._SOURCES["skill"]["digest"],
        "target contents",
    )
