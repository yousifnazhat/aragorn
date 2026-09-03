"""Verify the semantic shape of one V3 core-updater replacement capture."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = "ADM-02/update/core-updater-plugin-replacement"
_ACTION = "core-updater-plugin-replacement"
_PLUGIN_ID = "aragorn-runtime-action-worker"
_SCHEMA = (
    "aragorn/openclaw-protected-core-updater-plugin-replacement-observation/v1"
)
_DELEGATED_SCHEMA = "aragorn/openclaw-protected-route-action-observations/v1"
_IMPLEMENTATION_DIGEST = (
    "sha256:7ade7b9f12010dc1a4f7cc06a8410bc01436efebc6a184bc9d0b748f010bce38"
)
_DELEGATED_DIGEST = (
    "sha256:2e655f7039cf6f2c06f815b281bb7a5ca7a84ed48ef44cf4d2ce8dfdc7df6902"
)
_CANDIDATE_COMMIT = "222d0c39429841044b95549407422873ec106a54"
_CANDIDATE_TREE = "fc3f1336c488b32d3b668f637ec4bdc6ccf56213"
_CANDIDATE_REPOSITORY = (
    "/var/lib/aragorn-agent-gateway/workspace/"
    "aragorn-core-updater-plugin-replacement-source"
)
_SPEC = f"git:file://{_CANDIDATE_REPOSITORY}@{_CANDIDATE_COMMIT}"
_MANAGED_REPOSITORY = (
    "/var/lib/aragorn-agent-gateway/state/git/git-79bb9b8ab164a123/repo"
)
_POLICY_REASON = "plugin installs disabled by Aragorn protected profile"
_RAW_FAILURE = (
    f'Disabled "{_PLUGIN_ID}" after plugin update failure; '
    "OpenClaw will continue without it. "
    f"Failed to update {_PLUGIN_ID}: blocked by install policy: "
    f"{_POLICY_REASON} (git {_SPEC})."
)
_GUIDANCE = [
    "Run openclaw update repair to retry post-update plugin repair.",
    f"Run openclaw plugins inspect {_PLUGIN_ID} --runtime --json for details.",
]
_GUIDED_MESSAGE = (
    f'Plugin "{_PLUGIN_ID}" could not be processed after the core update: '
    f"{_RAW_FAILURE} {' '.join(_GUIDANCE)}"
)
_EXPECTED_OUTCOME = {
    "message": _GUIDED_MESSAGE,
    "pluginId": _PLUGIN_ID,
    "status": "skipped",
}
_TARGET = "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"
_WORKING_CONFIG = (
    "/var/lib/aragorn-agent-gateway/state/core-updater-openclaw.json"
)
_CONFIG_BYTES = 2_159
_CONFIG_DIGEST = (
    "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
)
_CONFIG_CANONICAL_DIGEST = (
    "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
)
_TARGET_DIGESTS = {
    "index.js": (23_860,
        "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"
    ),
    "openclaw.plugin.json": (723,
        "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
    ),
    "package.json": (134,
        "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"
    ),
}
_CANDIDATE_FILES = {
    "index.js": (
        154,
        "sha256:67ecfc8f10e39dcc60ec880a587fadeacdb0040b1911ef93a995575f2aa5bbf2",
    ),
    "openclaw.plugin.json": (
        698,
        "sha256:a9d62834481462f8f474fe16bab4fb3d466942d9fc2602c618592897bf427d82",
    ),
    "package.json": (
        134,
        "sha256:86f83ebce70efcb741663859444a059de21eb8906fbe45dc220aed6c94eb5803",
    ),
}
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)


def verify_openclaw_final_v3_core_updater_plugin_replacement_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify route semantics without granting observation or PASS authority."""

    try:
        _verify_scalar_types(document)
        _verify_no_positive_eligibility(document)
        if type(document) is not dict:
            raise AdmissionEvidenceError("core-updater document must be an object")
        required = {
            "actions",
            "assurance",
            "core_updater_preflight",
            "delegated_implementation_digest",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "routes",
            "run_nonce",
            "runtime_binding",
            "schema",
            "selected_route_ids",
        }
        if (
            set(document) != required
            or document["schema"] != _SCHEMA
            or document["assurance"]
            != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
            or document["implementation_digest"] != _IMPLEMENTATION_DIGEST
            or document["delegated_implementation_digest"] != _DELEGATED_DIGEST
            or document["selected_route_ids"] != [_ROUTE]
            or not re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"])
            or document["protected_boundary"].get("ready") is not True
        ):
            raise AdmissionEvidenceError("core-updater document identity changed")
        runtime = document["runtime_binding"]
        if runtime != {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": (
                "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
            ),
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }:
            raise AdmissionEvidenceError("core-updater runtime binding changed")
        action = _one(document["actions"], "core-updater action")
        route = _one(document["routes"], "core-updater route")
        if (
            type(action) is not dict
            or set(action)
            != {
                "commands",
                "execution_error",
                "id",
                "observations",
                "prerequisites",
                "reason_codes",
                "status",
            }
            or action.get("id") != _ACTION
            or action.get("status") != "OBSERVED"
            or action.get("reason_codes") != []
            or action.get("execution_error") is not None
            or action.get("prerequisites", {}).get("ready") is not True
            or type(route) is not dict
            or route
            != {
                "action_id": _ACTION,
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ):
            raise AdmissionEvidenceError("core-updater route was not exactly observed")
        repair, outcome = _verify_action(action)
        preflight = _verify_preflight(document["core_updater_preflight"], outcome)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid core-updater semantic compatibility document: {exc}"
        ) from exc

    return {
        "schema": (
            "aragorn/openclaw-final-v3-core-updater-plugin-replacement-"
            "semantic-compatibility/v1"
        ),
        "assurance": (
            "PINNED_CORE_UPDATER_POLICY_BLOCK_SEMANTICS_ONLY_"
            "NOT_OBSERVED_QUALIFIED_OR_PASS_AUTHORITY"
        ),
        "bindings": {
            "candidate_git_commit": _CANDIDATE_COMMIT,
            "candidate_git_tree": _CANDIDATE_TREE,
            "delegated_probe_digest": _DELEGATED_DIGEST,
            "diagnostic_module": dict(
                preflight["trusted_policy_audit"]["diagnostic_module"]
            ),
            "implementation_digest": _IMPLEMENTATION_DIGEST,
            "plugin_id": _PLUGIN_ID,
            "policy_reason": _POLICY_REASON,
            "runtime": dict(document["runtime_binding"]),
            "working_config_canonical_digest": _CONFIG_CANONICAL_DIGEST,
            "writer_module": dict(preflight["installed_index"]["writer_module"]),
        },
        "decision": {
            "status": (
                "CORE_UPDATER_POLICY_BLOCK_SEMANTIC_COMPATIBILITY_VERIFIED_"
                "NOT_OBSERVED_OR_QUALIFIED"
            ),
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "NO_DEDICATED_CAPTURE_OBSERVATION_BOUND",
            "CAPTURE_FRESHNESS_NOT_VERIFIED",
            "CAPTURE_DESTRUCTION_NOT_VERIFIED",
            "CAPTURE_INDEPENDENCE_NOT_VERIFIED",
            "WRITER_MODULE_DIGEST_NOT_FORMALLY_PINNED_TO_SIGNED_CAPTURE_SOURCE",
            "DIAGNOSTIC_MODULE_DIGEST_NOT_FORMALLY_PINNED_TO_SIGNED_CAPTURE_SOURCE",
            "EPHEMERAL_WRITABLE_CONFIG_COPY_USED_FOR_FAILURE_BOOKKEEPING",
            "NO_ROUTE_PASS_OR_CAMPAIGN_AUTHORITY",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "route_semantics": {
            "candidate_git_source_exact": True,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "policy_blocked_target_specific_outcome_shape_verified": True,
            "replacement_target_unchanged": True,
            "shared_capture_independence_verified": False,
            "update_repair_argv": list(repair["command"]["argv"]),
        },
    }


def _verify_action(action: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    commands = action.get("commands")
    observations = action.get("observations")
    if (
        type(commands) is not list
        or len(commands) != 3
        or type(observations) is not dict
        or set(observations)
        != {
            "configuration_after",
            "inventory_after",
            "inventory_before",
            "roots_after",
            "roots_before",
            "update_repair",
        }
    ):
        raise AdmissionEvidenceError("core-updater action shape changed")
    repair = observations["update_repair"]
    inventory_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "plugins",
        "list",
        "--json",
    ]
    expected_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "update",
        "repair",
        "--timeout",
        "10",
        "--yes",
        "--json",
        "--no-restart",
    ]
    if (
        type(repair) is not dict
        or repair.get("command") != commands[1]
        or commands
        != [
            observations["inventory_before"].get("command"),
            repair["command"],
            observations["inventory_after"].get("command"),
        ]
        or repair.get("response", {}).get("parsed") is not True
        or observations["inventory_before"].get("response", {}).get("parsed")
        is not True
        or observations["inventory_after"].get("response", {}).get("parsed")
        is not True
        or observations["roots_before"] != observations["roots_after"]
    ):
        raise AdmissionEvidenceError("exact update repair attempt absent")
    _verify_command(commands[0], inventory_argv)
    _verify_command(commands[1], expected_argv)
    _verify_command(commands[2], inventory_argv)
    response = repair["response"].get("value")
    expected_warning = {
        "guidance": list(_GUIDANCE),
        "message": _GUIDED_MESSAGE,
        "pluginId": _PLUGIN_ID,
        "reason": _RAW_FAILURE,
    }
    expected_response = {
        "channel": "stable",
        "mode": "finalize",
        "postUpdate": {
            "doctor": {"status": "ok"},
            "plugins": {
                "changed": True,
                "integrityDrifts": [],
                "npm": {"changed": True, "outcomes": [dict(_EXPECTED_OUTCOME)]},
                "status": "warning",
                "sync": {
                    "changed": False,
                    "errors": [],
                    "switchedToBundled": [],
                    "switchedToNpm": [],
                    "warnings": [],
                },
                "warnings": [expected_warning],
            },
        },
        "restart": False,
        "root": "/runtime/lib/node_modules/openclaw",
        "status": "warning",
    }
    if type(response) is not dict or response != expected_response:
        raise AdmissionEvidenceError("update repair response shape changed")
    outcome = response["postUpdate"]["plugins"]["npm"]["outcomes"][0]
    return repair, outcome


def _verify_command(value: Any, argv: list[str]) -> None:
    keys = {
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
    if (
        type(value) is not dict
        or set(value) != keys
        or value["argv"] != argv
        or value["error"] is not None
        or type(value["exit_code"]) is not int
        or value["exit_code"] != 0
        or type(value["pid"]) is not int
        or value["pid"] <= 0
        or value["signal"] is not None
        or type(value["started_at"]) is not str
        or type(value["completed_at"]) is not str
        or type(value["stderr_bytes"]) is not int
        or value["stderr_bytes"] < 0
        or type(value["stdout_bytes"]) is not int
        or value["stdout_bytes"] < 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["stderr_digest"])
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["stdout_digest"])
        or type(value["stderr_excerpt"]) is not str
        or type(value["stdout_excerpt"]) is not str
    ):
        raise AdmissionEvidenceError("core-updater command record changed")


def _verify_preflight(
    value: Mapping[str, Any], outcome: Mapping[str, Any]
) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != {
        "candidate_repository",
        "delegated_probe",
        "installed_index",
        "policy_outcome",
        "policy_reason",
        "ready",
        "target_after",
        "target_before",
        "trusted_policy_audit",
        "working_config_after",
        "working_config_before",
    }:
        raise AdmissionEvidenceError("core-updater preflight shape changed")
    repository = value["candidate_repository"]
    if (
        value["ready"] is not True
        or value["policy_reason"] != _POLICY_REASON
        or value["policy_outcome"] != outcome
        or repository.get("commit") != _CANDIDATE_COMMIT
        or repository.get("tree") != _CANDIDATE_TREE
        or repository.get("object_format") != "sha1"
        or repository.get("path") != _CANDIDATE_REPOSITORY
    ):
        raise AdmissionEvidenceError("core-updater preflight identity changed")
    _verify_candidate_files(repository.get("candidates"))
    _verify_git_commands(repository.get("commands"))
    delegated = value["delegated_probe"]
    if delegated != {
        "bytes": 45_137,
        "digest": _DELEGATED_DIGEST,
        "path": (
            "/route-input/core-updater-plugin-replacement/"
            "protected-route-action-probe.mjs"
        ),
    }:
        raise AdmissionEvidenceError("delegated core-updater probe changed")
    installed = value["installed_index"]
    record = installed.get("record")
    writer = installed.get("writer_module")
    store = installed.get("store")
    if (
        type(installed) is not dict
        or set(installed)
        != {
            "managed_repository_after",
            "managed_repository_before",
            "record",
            "store",
            "writer_module",
        }
        or record
        != {
            "gitCommit": _CANDIDATE_COMMIT,
            "gitRef": _CANDIDATE_COMMIT,
            "gitUrl": f"file://{_CANDIDATE_REPOSITORY}",
            "installPath": _TARGET,
            "installedAt": "2026-01-01T00:00:00.000Z",
            "plugin_id": _PLUGIN_ID,
            "resolvedAt": "2026-01-01T00:00:00.000Z",
            "source": "git",
            "spec": _SPEC,
            "version": "0.1.0",
        }
        or type(writer) is not dict
        or set(writer) != {"alias", "bytes", "digest", "path"}
        or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", writer["alias"])
        or type(writer["bytes"]) is not int
        or not 1 <= writer["bytes"] <= 1024 * 1024
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", writer["digest"])
        or not re.fullmatch(
            r"/runtime/lib/node_modules/openclaw/dist/"
            r"installed-plugin-index-records-[A-Za-z0-9_-]+\.js",
            writer["path"],
        )
        or type(store) is not dict
        or set(store)
        != {"bytes", "gid", "mode", "nlink", "path", "type", "uid"}
        or store.get("path")
        != "/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite"
        or store.get("type") != "file"
        or store.get("uid") != 992
        or store.get("gid") != 992
        or store.get("mode") != "600"
        or store.get("nlink") != 1
        or type(store.get("bytes")) is not int
        or store["bytes"] <= 0
    ):
        raise AdmissionEvidenceError("pinned installed-index writer binding changed")
    managed = {
        "entries": [],
        "gid": 992,
        "mode": "700",
        "path": _MANAGED_REPOSITORY,
        "type": "directory",
        "uid": 992,
    }
    if (
        installed["managed_repository_before"] != managed
        or installed["managed_repository_after"] != managed
    ):
        raise AdmissionEvidenceError("managed Git update repository changed")
    before = _verify_target(value["target_before"])
    after = _verify_target(value["target_after"])
    if before != after:
        raise AdmissionEvidenceError("denied replacement changed installed target")
    _verify_working_config_transition(
        value["working_config_before"], value["working_config_after"]
    )
    _verify_trusted_policy_audit(value["trusted_policy_audit"])
    return value


def _verify_trusted_policy_audit(value: Any) -> None:
    if type(value) is not dict or set(value) != {
        "diagnostic_module",
        "event",
        "journal",
        "metadata",
    }:
        raise AdmissionEvidenceError("trusted plugin audit shape changed")
    if value["metadata"] != {"internal": True, "trusted": True}:
        raise AdmissionEvidenceError("plugin audit is not trusted internal evidence")
    module = value["diagnostic_module"]
    if (
        type(module) is not dict
        or set(module) != {"alias", "bytes", "digest", "path"}
        or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", module["alias"])
        or type(module["bytes"]) is not int
        or not 1 <= module["bytes"] <= 2 * 1024 * 1024
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", module["digest"])
        or not re.fullmatch(
            r"/runtime/lib/node_modules/openclaw/dist/"
            r"diagnostic-events-[A-Za-z0-9_-]+\.js",
            module["path"],
        )
    ):
        raise AdmissionEvidenceError("trusted diagnostic module binding changed")
    event = value["event"]
    event_keys = {
        "action",
        "actor",
        "attributes",
        "category",
        "control",
        "eventId",
        "outcome",
        "policy",
        "reason",
        "seq",
        "severity",
        "target",
        "ts",
        "type",
    }
    if (
        type(event) is not dict
        or set(event) not in (event_keys, event_keys | {"trace"})
        or event.get("type") != "security.event"
        or event.get("category") != "plugin"
        or event.get("action") != "plugin.audit.failed"
        or event.get("outcome") != "denied"
        or event.get("severity") != "medium"
        or event.get("actor") != {"kind": "operator"}
        or event.get("target") != {"kind": "plugin", "name": _PLUGIN_ID}
        or event.get("policy")
        != {
            "decision": "deny",
            "id": "plugin.install",
            "reason": "security_scan_blocked",
        }
        or event.get("control")
        != {"family": "supply_chain", "id": "plugin.install.audit"}
        or event.get("reason") != "security_scan_blocked"
        or event.get("attributes") != {"mode": "update", "source_family": "git"}
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            event.get("eventId", ""),
        )
        or type(event.get("seq")) is not int
        or event["seq"] <= 0
        or type(event.get("ts")) is not int
        or event["ts"] <= 0
    ):
        raise AdmissionEvidenceError("trusted denied plugin audit projection changed")
    journal = value["journal"]
    if (
        type(journal) is not dict
        or set(journal)
        != {"bytes", "digest", "gid", "mode", "nlink", "path", "type", "uid"}
        or journal.get("path")
        != "/var/lib/aragorn-agent-gateway/state/core-updater-policy-audit.jsonl"
        or journal.get("type") != "file"
        or journal.get("uid") != 992
        or journal.get("gid") != 992
        or journal.get("mode") != "600"
        or journal.get("nlink") != 1
        or type(journal.get("bytes")) is not int
        or journal["bytes"] <= 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", journal.get("digest", ""))
    ):
        raise AdmissionEvidenceError("trusted plugin audit journal custody changed")


def _verify_working_config_transition(before: Any, after: Any) -> None:
    keys = {
        "bytes",
        "canonical_digest",
        "digest",
        "document",
        "gid",
        "mode",
        "nlink",
        "path",
        "type",
        "uid",
    }
    if (
        type(before) is not dict
        or type(after) is not dict
        or set(before) != keys
        or set(after) != keys
        or before["bytes"] != _CONFIG_BYTES
        or before["digest"] != _CONFIG_DIGEST
        or before["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or canonical_digest(before["document"]) != _CONFIG_CANONICAL_DIGEST
        or type(after["bytes"]) is not int
        or after["bytes"] <= 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", after["digest"])
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", after["canonical_digest"]
        )
        or canonical_digest(after["document"]) != after["canonical_digest"]
    ):
        raise AdmissionEvidenceError("working core-updater config binding changed")
    custody = {
        "gid": 992,
        "mode": "600",
        "nlink": 1,
        "path": _WORKING_CONFIG,
        "type": "file",
        "uid": 992,
    }
    if (
        {key: before[key] for key in custody} != custody
        or {key: after[key] for key in custody} != custody
    ):
        raise AdmissionEvidenceError("working core-updater config custody changed")
    expected = deepcopy(before["document"])
    observed = deepcopy(after["document"])
    try:
        expected["plugins"]["entries"][_PLUGIN_ID]["enabled"] = False
        expected["plugins"].pop("allow")
        expected["plugins"]["bundledDiscovery"] = "compat"
        observed_meta = observed.pop("meta")
        observed_wizard = observed.pop("wizard")
        expected.pop("meta", None)
    except (AttributeError, KeyError, TypeError) as exc:
        raise AdmissionEvidenceError(
            "working core-updater config transition changed"
        ) from exc
    if (
        observed != expected
        or type(observed_meta) is not dict
        or set(observed_meta) != {"lastTouchedAt", "lastTouchedVersion"}
        or observed_meta["lastTouchedVersion"] != "2026.7.1"
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            observed_meta["lastTouchedAt"],
        )
        or type(observed_wizard) is not dict
        or set(observed_wizard)
        != {"lastRunAt", "lastRunCommand", "lastRunMode", "lastRunVersion"}
        or observed_wizard["lastRunVersion"] != "2026.7.1"
        or observed_wizard["lastRunCommand"] != "doctor"
        or observed_wizard["lastRunMode"] != "local"
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            observed_wizard["lastRunAt"],
        )
    ):
        raise AdmissionEvidenceError("working core-updater config transition changed")


def _verify_candidate_files(value: Any) -> None:
    if type(value) is not list or len(value) != len(_CANDIDATE_FILES):
        raise AdmissionEvidenceError("candidate bundle cardinality changed")
    by_name = {item["path"].rsplit("/", 1)[-1]: item for item in value}
    if set(by_name) != set(_CANDIDATE_FILES):
        raise AdmissionEvidenceError("candidate bundle names changed")
    for name, (bytes_, digest) in _CANDIDATE_FILES.items():
        item = by_name[name]
        if item != {
            "bytes": bytes_,
            "digest": digest,
            "gid": 0,
            "mode": "444",
            "nlink": 1,
            "path": f"/route-input/core-updater-plugin-replacement/candidate-source/{name}",
            "type": "file",
            "uid": 0,
        }:
            raise AdmissionEvidenceError(f"candidate fixture changed: {name}")


def _verify_git_commands(value: Any) -> None:
    expected = [
        ["/usr/bin/git", "init", "--quiet", "--object-format=sha1", "."],
        [
            "/usr/bin/git",
            "add",
            "--",
            "index.js",
            "openclaw.plugin.json",
            "package.json",
        ],
        [
            "/usr/bin/git",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "Pinned core updater replacement fixture",
        ],
        ["/usr/bin/git", "rev-parse", "--show-object-format"],
        ["/usr/bin/git", "rev-parse", "HEAD"],
        ["/usr/bin/git", "rev-parse", "HEAD^{tree}"],
    ]
    if type(value) is not list or [item.get("argv") for item in value] != expected:
        raise AdmissionEvidenceError("candidate Git command sequence changed")
    for item in value:
        if (
            set(item)
            != {
                "argv",
                "error",
                "exit_code",
                "signal",
                "stderr_bytes",
                "stderr_digest",
                "stdout_bytes",
                "stdout_digest",
            }
            or item["error"] is not None
            or type(item["exit_code"]) is not int
            or item["exit_code"] != 0
            or item["signal"] is not None
        ):
            raise AdmissionEvidenceError("candidate Git command failed")


def _verify_target(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(_TARGET_DIGESTS):
        raise AdmissionEvidenceError("installed target inventory changed")
    for name, (bytes_, digest) in _TARGET_DIGESTS.items():
        item = value[name]
        if (
            type(item) is not dict
            or item.get("digest") != digest
            or item.get("path") != f"{_TARGET}/{name}"
            or item.get("type") != "file"
            or item.get("uid") != 0
            or item.get("gid") != 0
            or item.get("mode") != "644"
            or item.get("nlink") != 1
            or item.get("bytes") != bytes_
        ):
            raise AdmissionEvidenceError(f"installed target changed: {name}")
    return dict(value)


def _one(value: Any, label: str) -> Any:
    if type(value) is not list or len(value) != 1:
        raise AdmissionEvidenceError(f"{label} is not an exact singleton")
    return value[0]


def _verify_scalar_types(value: Any) -> None:
    if value is None or type(value) in {str, int, float, bool}:
        return
    if type(value) is list:
        for item in value:
            _verify_scalar_types(item)
        return
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise AdmissionEvidenceError("core-updater object key must be a string")
        for item in value.values():
            _verify_scalar_types(item)
        return
    raise AdmissionEvidenceError("core-updater document contains unsupported type")


def _verify_no_positive_eligibility(value: Any) -> None:
    if type(value) is dict:
        for key, item in value.items():
            if key.endswith("_eligible") and item is not False:
                raise AdmissionEvidenceError(
                    "core-updater input asserts positive eligibility"
                )
            _verify_no_positive_eligibility(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            _verify_no_positive_eligibility(item)
