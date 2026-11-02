"""Check current-run curator restore denial semantics without capture authority."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from . import admission_protected_final_combined_v3_curator_restore as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = old._ROUTE
_ACTION = "curator-restore-authority-denial"
_PARSE = old.current.base.legacy._parse_time
_FILE_KEYS = {
    "device",
    "digest",
    "digest_error",
    "exists",
    "gid",
    "inode",
    "mode",
    "nlink",
    "path",
    "size",
    "type",
    "uid",
}
_DIRECTORY_KEYS = (_FILE_KEYS - {"digest", "digest_error"}) | {
    "entries",
    "entries_truncated",
    "entry_count",
}
_ROOTS = {
    "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
    "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
    "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
    "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
    "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
    "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
}
_STABLE = (
    "boundary",
    "config_lock",
    "config_tree",
    "gateway_process",
    "modules",
    "openclaw",
    "protected_root_trees",
    "runtime_tree",
    "target",
)


def verify_openclaw_final_v3_curator_restore_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate actual identities and predicates; do not qualify a capture."""
    try:
        old.semantics._verify_scalar_types(document)
        _verify_records(document)
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 curator restore semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-curator-restore-semantic-compatibility/v1",
        "assurance": "CURATOR_RESTORE_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "CURATOR_RESTORE_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
            "DATABASE_DATA_VERSION_NOT_A_STATE_EQUIVALENCE_OR_CAUSALITY_PROOF",
            "SKILLS_STATUS_ARCHIVED_DIAGNOSTIC_NOT_ACTIVE_CONSUMER_PROOF",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 curator restore {label} changed")


def _same(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def _verify_records(value: Any) -> None:
    """Reject malformed scalar, file, tree and parsed-command trust boundaries."""
    if type(value) is float:
        _require(math.isfinite(value) and value >= 0, "numeric telemetry")
    elif type(value) is int:
        _require(0 <= value <= 2**53 - 1, "safe integer")
    elif type(value) is dict:
        _require(all(type(key) is str for key in value), "object keys")
        if value.get("type") in {"file", "directory"}:
            is_file = value["type"] == "file"
            _require(
                set(value) == (_FILE_KEYS if is_file else _DIRECTORY_KEYS), "file shape"
            )
            _require(
                value["exists"] is True
                and all(
                    type(value[key]) is int and value[key] > 0
                    for key in ("device", "inode", "nlink")
                )
                and all(
                    type(value[key]) is int and value[key] >= 0
                    for key in ("uid", "gid", "size")
                )
                and type(value["path"]) is str
                and bool(value["path"])
                and re.fullmatch(r"[0-7]{3,4}", value["mode"]) is not None,
                "file custody",
            )
            if is_file:
                _require(
                    value["digest_error"] is None
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
                    is not None,
                    "file digest",
                )
            else:
                _require(
                    type(value["entries"]) is list
                    and all(type(item) is str for item in value["entries"])
                    and value["entries"] == sorted(set(value["entries"]))
                    and value["entries_truncated"] is False
                    and type(value["entry_count"]) is int
                    and value["entry_count"] == len(value["entries"]),
                    "directory entries",
                )
        if "root" in value and "tree_digest" in value:
            _require(
                set(value) == {"entries", "ready", "root", "tree_digest"}
                and value["ready"] is True
                and type(value["entries"]) is list
                and value["tree_digest"] == canonical_digest(value["entries"]),
                "tree digest",
            )
        if "command" in value and "response" in value:
            response = value["response"]
            _require(
                set(value)
                in ({"command", "response"}, {"command", "response", "target_matches"})
                and set(response) == {"parsed", "value"}
                and response["parsed"] is True
                and _same(
                    json.loads(
                        value["command"]["stdout_excerpt"],
                        object_pairs_hook=old.contract._reject_duplicates,
                        parse_constant=old.contract._reject_constant,
                    ),
                    response["value"],
                ),
                "parsed command output",
            )
        for item in value.values():
            _verify_records(item)
    elif type(value) is list:
        for item in value:
            _verify_records(item)
    else:
        _require(value is None or type(value) in (str, bool), "JSON scalar")


def _verify_document(document: Mapping[str, Any]) -> None:
    _require(
        type(document) is dict
        and set(document)
        == {
            "action",
            "assurance",
            "implementation_digests",
            "limitations",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        },
        "document shape",
    )
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    _require(
        document["schema"]
        == "aragorn/openclaw-protected-curator-restore-denial-observation/v1"
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
        }
        and document["limitations"]
        == [
            "OBSERVED_IS_NOT_PASS",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "SHARED_DATABASE_DATA_VERSION_NOT_STABLE_ONLY_EXACT_SELECTED_LIFECYCLE_ROW_BOUND",
            "SINGLE_ROUTE_SINGLE_CAPTURE",
            "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        and set(action)
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
            "curator_status_before_seed",
            "system_info_before",
            "version",
        }
        and set(after)
        == {
            *(f"{name}_after" for name in _STABLE),
            "cli_fallback_restore",
            "curator_status_after",
            "curator_status_before",
            "database_after_cli",
            "database_after_gateway",
            "database_before",
            "discovery_after",
            "discovery_before",
            "gateway_restore",
            "invalid_token_gateway_control",
            "system_info_after",
        },
        "document identity",
    )
    _require(
        all(
            _same(before[f"{name}_before"], after[f"{name}_after"]) for name in _STABLE
        ),
        "protected state stability",
    )
    _verify_boundary(before)
    _verify_system(before["system_info_before"], before["gateway_process_before"])
    _verify_system(after["system_info_after"], after["gateway_process_after"])
    old._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    old._verify_version(before["version"])
    _verify_semantics(action)
    commands = action["commands"]
    _require(
        len(commands) == 11
        and len({command["pid"] for command in commands}) == 11
        and all(
            set(command)
            == {
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
            and type(command["pid"]) is int
            and command["pid"] > 0
            and all(
                type(command[key]) is int
                for key in ("exit_code", "stdout_bytes", "stderr_bytes")
            )
            and command["error"] is None
            and command["signal"] is None
            and old._command_output_is_exact(command)
            and _PARSE(command["started_at"]) <= _PARSE(command["completed_at"])
            for command in commands
        )
        and all(
            _PARSE(left["completed_at"]) <= _PARSE(right["started_at"])
            for left, right in pairwise(commands)
        )
        and _PARSE(commands[-1]["completed_at"]) <= _PARSE(document["recorded_at"]),
        "command chronology",
    )


def _verify_mount(value: Mapping[str, Any], *, path: str, source: str) -> None:
    _require(
        set(value)
        == {"entry", "error", "explicit", "path", "read_only", "ready", "records"}
        and value["error"] is None
        and value["ready"] is True
        and value["read_only"] is True
        and value["explicit"] is True
        and value["path"] == path
        and value["entry"]["path"] == path
        and type(value["records"]) is list
        and len(value["records"]) == 1,
        "mount",
    )
    record = value["records"][0]
    _require(
        set(record)
        == {
            "filesystem",
            "mount_options",
            "mount_point",
            "root",
            "source",
            "super_options",
        }
        and record["mount_point"] == path
        and record["root"] == source
        and all(
            type(record[key]) is list and all(type(item) is str for item in record[key])
            for key in ("mount_options", "super_options")
        )
        and "ro" in record["mount_options"]
        and "rw" not in record["mount_options"]
        and type(record["filesystem"]) is str
        and bool(record["filesystem"])
        and type(record["source"]) is str
        and bool(record["source"]),
        "read-only mount record",
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
        and set(config)
        == {"canonical_digest", "document", "file", "mount", "parse_error", "ready"}
        and config["parse_error"] is None
        and config["canonical_digest"] == canonical_digest(config["document"])
        and before["runtime_tree_before"] == old.current._RUNTIME_TREE
        and before["config_lock_before"]
        == {"exists": False, "path": f"{old.semantics._CONFIG_PATH}.lock"}
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
        "protected boundary",
    )
    old.v3_contract._verify_config(config)
    old.current._verify_gateway(gateway, gateway["hostname"])
    old.current._verify_openclaw(before["openclaw_before"])
    old.semantics._verify_modules(before["modules_before"])
    for item in before["modules_before"].values():
        _require(set(item) == {"expected", "observed"}, "module shape")
    _verify_mount(
        config["mount"],
        path="/run/credentials/aragorn-agent-gateway.service",
        source="/",
    )
    _verify_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
    )
    probe_source = boundary["probe"]["records"][0]["root"]
    _require(
        re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", probe_source)
        is not None,
        "probe volume",
    )
    _verify_mount(boundary["probe"], path="/route-input", source=probe_source)
    for mount, uid, gid, mode, entries in (
        (config["mount"], 992, 0, "500", ["openclaw-config"]),
        (boundary["runtime"], 0, 0, "755", ["bin", "lib"]),
        (boundary["probe"], 0, 0, "555", ["curator-restore-activation"]),
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
        config_tree["root"] == config["mount"]["entry"]
        and config_tree["entries"] == [{**config["file"], "path": "openclaw-config"}],
        "configuration tree join",
    )
    target = before["target_before"]
    root, entries = target["root"], target["entries"]
    _require(
        root["path"] == old.semantics._TARGET_ROOT
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
        "target contents",
    )
    _require(
        set(boundary["roots"]) == set(_ROOTS)
        and set(before["protected_root_trees_before"]) == set(_ROOTS),
        "protected root inventory",
    )
    for name, path in _ROOTS.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        tree = before["protected_root_trees_before"][name]
        _require(
            set(value) == {"observation", "ready", "writable"}
            and value["ready"] is True
            and value["writable"] is True
            and entry["path"] == path
            and entry["type"] == "directory"
            and (entry["uid"], entry["gid"], entry["mode"], entry["entries"])
            == (992, 992, "700", [])
            and tree["root"] == entry
            and tree["entries"] == [],
            "protected root tree",
        )


def _verify_system(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    command = value["command"]
    system = value["response"]["value"]
    _require(
        set(system)
        == {
            "arch",
            "cpuCount",
            "diskAvailableBytes",
            "diskPath",
            "diskTotalBytes",
            "hostname",
            "loadAverage",
            "machineName",
            "memoryFreeBytes",
            "memoryTotalBytes",
            "nodeVersion",
            "osLabel",
            "pid",
            "platform",
            "port",
            "release",
            "uptimeMs",
        }
        and command["argv"]
        == [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ]
        and old._command_succeeded_clean(command)
        and system["pid"] == gateway["pid"]
        and system["hostname"] == gateway["hostname"]
        and system["machineName"] == gateway["hostname"]
        and system["platform"] == "linux"
        and system["arch"] == "arm64"
        and system["nodeVersion"] == "v24.16.0"
        and system["osLabel"] == f"Linux {system['release']}"
        and system["port"] == 18789
        and system["diskPath"] == "/var/lib/aragorn-agent-gateway/state"
        and all(
            type(system[key]) is str and bool(system[key])
            for key in ("arch", "nodeVersion", "osLabel", "release")
        )
        and all(
            type(system[key]) is int and system[key] > 0
            for key in ("diskTotalBytes", "memoryTotalBytes", "uptimeMs", "pid", "port")
        )
        and all(
            type(system[key]) is int and system[key] >= 0
            for key in ("diskAvailableBytes", "memoryFreeBytes", "cpuCount")
        )
        and system["diskAvailableBytes"] <= system["diskTotalBytes"]
        and system["memoryFreeBytes"] <= system["memoryTotalBytes"]
        and type(system["loadAverage"]) is list
        and len(system["loadAverage"]) == 3
        and all(
            type(item) in (int, float) and math.isfinite(item) and item >= 0
            for item in system["loadAverage"]
        ),
        "system identity",
    )


def _verify_semantics(action: Mapping[str, Any]) -> None:
    before, after = action["prerequisites"], action["observations"]
    semantics = old.semantics
    for status, expected in (
        (before["curator_status_before_seed"], semantics._EMPTY_STATUS),
        (after["curator_status_before"], semantics._ARCHIVED_STATUS),
        (after["curator_status_after"], semantics._ARCHIVED_STATUS),
    ):
        semantics._verify_curator_status(status, expected)
        _require(
            _same(status["response"]["value"], expected), "curator status scalar types"
        )
    semantics._verify_discovery(after["discovery_before"])
    semantics._verify_discovery(after["discovery_after"])
    semantics._verify_denials(after)
    databases = [
        after[name]
        for name in ("database_before", "database_after_gateway", "database_after_cli")
    ]
    for value in databases:
        file = value["file"]
        _require(
            set(value) == {"data_version", "file", "row"}
            and type(value["data_version"]) is int
            and value["data_version"] > 0
            and _same(value["row"], semantics._ARCHIVED_ROW)
            and file == databases[0]["file"]
            and file["path"]
            == "/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite"
            and file["type"] == "file"
            and file["size"] > 0
            and (file["uid"], file["gid"], file["mode"], file["nlink"])
            == (992, 992, "600", 1),
            "selected lifecycle row",
        )
    _require(
        _same(
            action["commands"],
            [
                before["version"],
                before["system_info_before"]["command"],
                before["curator_status_before_seed"]["command"],
                after["curator_status_before"]["command"],
                after["discovery_before"]["command"],
                after["gateway_restore"]["command"],
                after["invalid_token_gateway_control"]["command"],
                after["cli_fallback_restore"]["command"],
                after["curator_status_after"]["command"],
                after["discovery_after"]["command"],
                after["system_info_after"]["command"],
            ],
        ),
        "command order",
    )
