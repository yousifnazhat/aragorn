"""Verify current-run cron rescan semantics without execution authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import admission_openclaw_final_v3_archive_replacement_subfixture as records
from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_cron_rescan as old
from . import admission_protected_final_combined_v3_fresh_session_reset as commands
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "cron-rescan"
_STABLE = (
    "boundary",
    "config",
    "config_lock",
    "config_tree",
    "gateway_process",
    "module_files",
    "openclaw",
    "protected_root_trees",
    "runtime_tree",
    "target",
)


def verify_openclaw_final_v3_cron_rescan_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind exact cron predicates to this document, not retained run identities."""
    try:
        old.semantics._verify_route_scalar_types(document)
        old.semantics._verify_no_positive_eligibility(document)
        checks._verify_records(_record_view(document))
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 cron rescan semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-cron-rescan-semantic-compatibility/v1",
        "assurance": "CRON_RESCAN_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "CRON_RESCAN_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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
            "FIXED_INERT_CRON_JOB_AND_737_BYTE_TEMPLATE_SKILL_PROMPT_ONLY",
            "SESSION_STORE_RAW_BYTES_AND_EXACT_NEW_ENTRY_JOIN_NOT_RETAINED_STORE_FINGERPRINT",
            "SQLITE_METADATA_AND_WAL_TRANSITIONS_NOT_FULL_DATABASE_CONTENT_EQUIVALENCE",
            "MODEL_NOT_FOUND_IS_NOT_A_SUCCESSFUL_MODEL_REPLY",
            "NO_GLOBAL_NO_WRITE_ROLLBACK_OR_GENERAL_CRON_ACTIVATION_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 cron rescan {label} changed")


def _record_view(value: Any) -> Any:
    """Adapt native-call params wrappers to the existing parsed-record checker."""
    if type(value) is dict:
        if set(value) == {"command", "params", "response"}:
            return [
                {key: _record_view(value[key]) for key in ("command", "response")},
                _record_view(value["params"]),
            ]
        return {key: _record_view(item) for key, item in value.items()}
    if type(value) is list:
        return [_record_view(item) for item in value]
    return value


def _verify_document(document: Mapping[str, Any]) -> None:
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
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
        == "aragorn/openclaw-protected-cron-rescan-observation/v1"
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
        and action["execution_error"] is None
        and action["reason_codes"] == []
        and set(before)
        == {
            *(f"{name}_before" for name in _STABLE),
            "cron_inventory_before",
            "session_store_before",
            "system_info_before",
            "version",
        }
        and set(after)
        == {
            *(f"{name}_after" for name in _STABLE),
            "cleanup",
            "cron_inventory_after_add",
            "cron_inventory_after_remove",
            "job",
            "run",
            "session_state_before_forced_run",
            "session_store_after",
            "snapshot",
            "system_info_after",
            "terminal_result",
        }
        and all(
            checks._same(before[f"{name}_before"], after[f"{name}_after"])
            for name in _STABLE
        )
        and set(after["run"]) == {"poll_count", "polls", "request", "terminal_poll"},
        "document identity and stable state",
    )
    _verify_boundary(before)
    for side, suffix in ((before, "before"), (after, "after")):
        checks._verify_system(
            side[f"system_info_{suffix}"], side[f"gateway_process_{suffix}"]
        )
    checks.old._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    for command in action["commands"]:
        commands._verify_command(command, command["argv"])
    _require(
        all(command["pid"] > 1 for command in action["commands"])
        and before["gateway_process_before"]["pid"]
        not in {command["pid"] for command in action["commands"]},
        "command and gateway PID separation",
    )
    _verify_route(action, document["recorded_at"])


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
        and checks._same(config, before["config_before"])
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
    for mount, path, root, uid, gid, mode, entries, nlink in (
        (
            config["mount"],
            "/run/credentials/aragorn-agent-gateway.service",
            "/",
            992,
            0,
            "500",
            ["openclaw-config"],
            2,
        ),
        (
            boundary["runtime"],
            "/runtime",
            f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
            0,
            0,
            "755",
            ["bin", "lib"],
            4,
        ),
        (boundary["probe"], "/route-input", source, 0, 0, "555", [_ACTION], 3),
    ):
        checks._verify_mount(mount, path=path, source=root)
        records._directory(mount["entry"], path, uid, gid, mode, entries, nlink)
    config_tree = before["config_tree_before"]
    _require(
        checks._same(config_tree["root"], config["mount"]["entry"])
        and checks._same(
            config_tree["entries"], [{**config["file"], "path": "openclaw-config"}]
        ),
        "configuration tree join",
    )
    records._tree_devices(config_tree)
    records._verify_fixture(before["target_before"], source=False)
    _require(
        set(boundary["roots"])
        == set(before["protected_root_trees_before"])
        == set(checks._ROOTS),
        "protected root inventory",
    )
    for name, path in checks._ROOTS.items():
        value, tree = (
            boundary["roots"][name],
            before["protected_root_trees_before"][name],
        )
        _require(
            set(value) == {"observation", "ready", "writable"}
            and value["ready"] is True
            and value["writable"] is True
            and checks._same(value["observation"], tree["root"])
            and tree["entries"] == [],
            "protected root tree join",
        )
        records._directory(value["observation"], path, 992, 992, "700", [], 2)
    modules = before["module_files_before"]
    _require(set(modules) == set(old.semantics._MODULES), "module inventory")
    for name, identity in old.semantics._MODULES.items():
        module = modules[name]
        _require(
            set(module) == {"expected", "observed"} and module["expected"] == identity,
            "module source",
        )
        records._file(
            module["observed"],
            identity["path"],
            0,
            0,
            "644",
            identity["bytes"],
            identity["digest"],
        )
    _require(
        all(
            value["device"] == boundary["runtime"]["entry"]["device"]
            for value in [
                before["openclaw_before"],
                *(module["observed"] for module in modules.values()),
            ]
        ),
        "runtime file device joins",
    )
    store = before["session_store_before"]
    records._file(
        store,
        old.semantics._SESSION_STORE,
        992,
        992,
        "600",
        store["size"],
        store["digest"],
    )
    _require(0 < store["size"] <= 512 * 1024, "bounded session store")


def _verify_route(action: Mapping[str, Any], recorded_at: str) -> None:
    """Reuse frozen route transitions, excluding retained system/store pins."""
    semantics = old.semantics
    before, after = action["prerequisites"], action["observations"]
    semantics._verify_version(before["version"])
    inventory_before = semantics._verify_cron_inventory(
        before["cron_inventory_before"],
        mtime_not_after=after["job"]["command"]["started_at"],
    )
    job_id = semantics._verify_job(after["job"])
    inventory_added = semantics._verify_cron_inventory(
        after["cron_inventory_after_add"],
        job=after["job"]["response"]["value"],
        mtime_not_before=after["job"]["command"]["started_at"],
        mtime_not_after=after["session_state_before_forced_run"]["started_at"],
    )
    pre_store = semantics._verify_pre_run(
        after["session_state_before_forced_run"], before["session_store_before"], job_id
    )
    checks._verify_records(pre_store)
    request = after["run"]["request"]
    semantics._verify_native_call(
        request, method="cron.run", params={"id": job_id, "mode": "force"}
    )
    run_id = request["response"]["value"].get("runId")
    _require(
        request["response"]["value"] == {"enqueued": True, "ok": True, "runId": run_id}
        and type(run_id) is str
        and semantics.cron._RUN_ID.fullmatch(run_id) is not None
        and type(after["run"]["poll_count"]) is int
        and after["run"]["poll_count"] == 1
        and checks._same(after["run"]["polls"], [after["run"]["terminal_poll"]]),
        "single forced run and terminal poll",
    )
    poll, terminal = after["run"]["terminal_poll"], after["terminal_result"]
    semantics._verify_native_call(
        poll, method="cron.runs", params={"id": job_id, "limit": 10}
    )
    _require(
        checks._same(
            poll["response"]["value"],
            {
                "entries": [terminal],
                "hasMore": False,
                "limit": 10,
                "nextOffset": None,
                "offset": 0,
                "total": 1,
            },
        ),
        "terminal history join",
    )
    semantics._verify_snapshot(after["snapshot"], job_id, pre_store)
    checks._verify_records(
        semantics._decode_store_raw(after["snapshot"]["store_raw"])[1]
    )
    old._verify_terminal(
        terminal,
        job=after["job"],
        request=request,
        poll=poll,
        snapshot=after["snapshot"],
        job_id=job_id,
        run_id=run_id,
    )
    semantics._verify_store(
        after["session_store_after"],
        after["snapshot"]["store"],
        before["session_store_before"],
    )
    semantics._verify_native_call(
        after["cleanup"], method="cron.remove", params={"id": job_id}
    )
    _require(
        after["cleanup"]["response"]["value"] == {"ok": True, "removed": True},
        "job cleanup",
    )
    inventory_removed = semantics._verify_cron_inventory(
        after["cron_inventory_after_remove"],
        mtime_not_before=after["cleanup"]["command"]["started_at"],
        mtime_not_after=after["system_info_after"]["command"]["started_at"],
    )
    semantics._verify_cron_store_transition(
        inventory_before, inventory_added, inventory_removed
    )
    _require(
        not {
            snapshot[name]["inode"]
            for snapshot in (inventory_before, inventory_added, inventory_removed)
            for name in ("database", "shared_memory", "write_ahead_log")
        }
        & {after["snapshot"]["blob"]["inode"], after["snapshot"]["store"]["inode"]},
        "SQLite and session file inode separation",
    )
    semantics._verify_commands(action, recorded_at)
