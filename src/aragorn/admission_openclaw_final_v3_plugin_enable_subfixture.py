"""Check one fresh-compatible plugin-enable denial without capture authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_config_entry_subfixture as config_checks
from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_plugin_enable as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "plugin-enable-activation"
_STABLE = (
    "boundary",
    "config",
    "config_lock",
    "gateway_process",
    "openclaw",
    "plugin_tree",
    "runtime_tree",
)
# Immutable content projections omit only current-run inode/device metadata.
_PLUGIN_CONTENT_DIGEST = (
    "sha256:49a137d6324d18f87ce977ce8bb3c2aeaedad6c29efe92bfd3c6c03d31218c5f"
)
_PLUGIN_EXCERPT_DIGEST = (
    "sha256:71524bb6c04bfd711f47d46d231cec170067f4765bc5a3a36da4dae9e6752a0d"
)
_WORKSPACE_ENTRIES = [
    ".agents",
    "AGENTS.md",
    "BOOTSTRAP.md",
    "HEARTBEAT.md",
    "IDENTITY.md",
    "SOUL.md",
    "TOOLS.md",
    "USER.md",
    "openclaw-workspace-state.json",
    "skills",
]


def verify_openclaw_final_v3_plugin_enable_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify exact denial predicates and joins, never qualify a capture."""
    try:
        old.enable._verify_scalar_types(document)
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 plugin-enable semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-plugin-enable-semantic-compatibility/v1",
        "assurance": "PLUGIN_ENABLE_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "PLUGIN_ENABLE_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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
            "EXACT_BUNDLED_TTS_LOCAL_CLI_ENABLE_ATTEMPT_ONLY",
            "CREDENTIAL_LOCK_EROFS_DENIAL_NOT_INSTALL_POLICY_CAUSALITY",
            "PLUGIN_REMAINS_DISABLED_NOT_IMPORTED_OR_ACTIVATED",
            "PLUGIN_INSPECTION_OUTPUT_TRUNCATED_EXACT_EXCERPT_DIGEST_AND_PARSED_RESPONSE_BOUND",
            "NO_SQLITE_LOGICAL_EQUIVALENCE_GLOBAL_NO_WRITE_ROLLBACK_OR_CAUSALITY_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 plugin-enable {label} changed")


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
        == "aragorn/openclaw-protected-plugin-enable-observation/v1"
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
            "plugin_before",
            "system_info_before",
            "version",
        }
        and set(after)
        == {
            *(f"{name}_after" for name in _STABLE),
            "plugin_after",
            "system_info_after",
            "native_enable",
        }
        and all(
            checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in _STABLE
        ),
        "protected state stability",
    )
    # Plugin inspection retains truncated output: verify its exact bounded record below.
    checks._verify_records(
        [
            *[value for key, value in before.items() if key != "plugin_before"],
            *[value for key, value in after.items() if key != "plugin_after"],
            action["commands"],
        ]
    )
    _verify_boundary(before)
    _verify_plugin_tree(before["plugin_tree_before"])
    old.config._verify_openclaw(before["openclaw_before"])
    old.config._verify_version(before["version"])
    _verify_native_enable(after["native_enable"])
    for side, suffix in ((before, "before"), (after, "after")):
        _verify_plugin_observation(side[f"plugin_{suffix}"])
        checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    old.config._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    _require(
        checks._same(
            before["plugin_before"]["response"], after["plugin_after"]["response"]
        ),
        "plugin state stability",
    )
    commands = action["commands"]
    _require(
        checks._same(
            commands,
            [
                before["version"],
                before["system_info_before"]["command"],
                before["plugin_before"]["command"],
                after["native_enable"]["command"],
                after["plugin_after"]["command"],
                after["system_info_after"]["command"],
            ],
        )
        and len({command["pid"] for command in commands}) == 6
        and before["gateway_process_before"]["pid"]
        not in {command["pid"] for command in commands}
        and all(
            set(command) == config_checks._COMMAND_KEYS
            and type(command["pid"]) is int
            and command["pid"] > 0
            and all(
                type(command[key]) is int
                for key in ("exit_code", "stdout_bytes", "stderr_bytes")
            )
            and command["error"] is None
            and command["signal"] is None
            and (index in (2, 4) or old.config._command_output_is_exact(command))
            and old.parent._time(command["started_at"])
            <= old.parent._time(command["completed_at"])
            for index, command in enumerate(commands)
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
        == {
            "configuration",
            "effective_identity",
            "ready",
            "route_input",
            "runtime",
            "workspace",
        }
        and boundary["ready"] is True
        and checks._same(
            boundary["effective_identity"], {"gid": 992, "groups": [992], "uid": 992}
        )
        and set(config)
        == {"canonical_digest", "file", "mount", "plugin_policy", "ready"}
        and checks._same(config, before["config_before"])
        and checks._same(
            config["plugin_policy"],
            {
                "allow": ["aragorn-runtime-action-worker"],
                "enabled": True,
                "target_allowlisted": False,
                "target_entry": None,
                "target_entry_present": False,
            },
        )
        and checks._same(
            before["config_lock_before"],
            {"exists": False, "path": f"{old._CONFIG_PATH}.lock"},
        )
        and checks._same(before["runtime_tree_before"], old.config._RUNTIME_TREE)
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
        "boundary identity",
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
    source = boundary["route_input"]["records"][0]["root"]
    _require(
        re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", source)
        is not None,
        "route volume",
    )
    checks._verify_mount(boundary["route_input"], path="/route-input", source=source)
    for mount, uid, gid, mode, entries in (
        (config["mount"], 992, 0, "500", ["openclaw-config"]),
        (boundary["runtime"], 0, 0, "755", ["bin", "lib"]),
        (boundary["route_input"], 0, 0, "555", [_ACTION]),
    ):
        entry = mount["entry"]
        _require(
            entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (uid, gid, mode, entries),
            "mount custody",
        )
    workspace = boundary["workspace"]
    entry = workspace["observation"]
    _require(
        set(workspace) == {"observation", "ready", "writable"}
        and workspace["ready"] is True
        and workspace["writable"] is True
        and entry["path"] == "/var/lib/aragorn-agent-gateway/workspace"
        and entry["type"] == "directory"
        and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
        == (992, 992, "700", _WORKSPACE_ENTRIES),
        "workspace custody",
    )


def _verify_plugin_tree(tree: Mapping[str, Any]) -> None:
    root, entries = tree["root"], tree["entries"]
    _require(
        root["path"] == old._PLUGIN_ROOT
        and root["type"] == "directory"
        and (root["uid"], root["gid"], root["mode"]) == (0, 0, "755")
        and root["entries"] == [entry["path"] for entry in entries]
        and canonical_digest(
            [
                {key: entry[key] for key in ("path", "size", "digest")}
                for entry in entries
            ]
        )
        == _PLUGIN_CONTENT_DIGEST
        and all(
            entry["type"] == "file"
            and (entry["uid"], entry["gid"], entry["mode"], entry["nlink"])
            == (0, 0, "644", 1)
            for entry in entries
        ),
        "plugin content custody",
    )


def _verify_native_enable(value: Mapping[str, Any]) -> None:
    command = value["command"]
    _require(
        set(value) == {"command", "process_started", "target_plugin_id"}
        and value["process_started"] is True
        and value["target_plugin_id"] == old._PLUGIN_ID
        and command["argv"]
        == [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "enable",
            old._PLUGIN_ID,
        ]
        and command["exit_code"] == 1
        and command["stdout_excerpt"] == ""
        and command["stderr_excerpt"] == old._STDERR,
        "credential lock denial",
    )


def _verify_plugin_observation(value: Mapping[str, Any]) -> None:
    _require(
        set(value) == {"command", "response"}
        and canonical_digest(value["response"])
        == old._SEMANTIC_DIGESTS["plugin_response"]
        and old._digest(value["command"]["stdout_excerpt"].encode())
        == _PLUGIN_EXCERPT_DIGEST,
        "plugin inspection identity",
    )
    old._verify_plugin_observation(value)
