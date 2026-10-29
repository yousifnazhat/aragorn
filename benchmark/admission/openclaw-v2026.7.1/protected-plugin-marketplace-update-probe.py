"""Observe one ordinary tracked local-marketplace update denied before replacement."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path("/route-input/plugin-package-skill-replacement")
PLUGIN_ID = "aragorn-plugin-skill-replacement-fixture"
ROUTE = "ADM-02/update/plugin-package-skill-replacement"
BRANCH = "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
PRIOR_NAME = "protected-plugin-package-skill-replacement-probe.py"
PRIOR_PIN = (
    26494,
    "sha256:d4e7c4bc2408045aab6702a8e2877916241ad372d917aaf8d5e62a289caf5a4e",
)
SEED_NAME = "seed-plugin-marketplace-update-record.mjs"
SCHEMA = "aragorn/native-plugin-marketplace-update-denial/v1"
AUTHORITY = "FIXED_OWNED_UPDATE_BRANCH_OBSERVATION_NOT_ROUTE_OR_PHASE3_QUALIFICATION"
DIAGNOSTIC_SCHEMA = "aragorn/native-plugin-update-diagnostic/v1"
CHECKS = (
    "identity",
    "sources",
    "prerequisites",
    "tracked_record",
    "update_command",
    "policy_denial",
    "protected_boundary",
    "sqlite_custody",
)
REASONS = {
    "IDENTITY",
    "SOURCES",
    "PREREQUISITES",
    "TRACKED_RECORD",
    "UPDATE_COMMAND",
    "POLICY_DENIAL",
    "PROTECTED_BOUNDARY",
    "SQLITE_CUSTODY",
    "INTERNAL",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _prior():
    path = Path(__file__).with_name(PRIOR_NAME)
    raw = path.read_bytes()
    if path.is_symlink() or (len(raw), digest(raw)) != PRIOR_PIN:
        raise ValueError("pinned helper changed")
    spec = importlib.util.spec_from_file_location(
        "aragorn_update_observation_primitives", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_record():
    return {
        "source": "marketplace",
        "marketplaceSource": str(ROOT / "marketplace.json"),
        "marketplacePlugin": PLUGIN_ID,
        "installPath": "/var/lib/aragorn-agent-gateway/state/extensions/" + PLUGIN_ID,
        "version": "1.0.0",
    }


def marketplace():
    return {
        "name": "aragorn-owned-local-marketplace",
        "plugins": [
            {"name": PLUGIN_ID, "version": "2.0.0", "source": "./candidate-source"}
        ],
    }


def fixture_files(version):
    files = _prior().fixture_files(version)
    package = json.loads(files["package.json"])
    # Matching names avoid an unrelated package-ID migration/logging branch.
    package["name"] = PLUGIN_ID
    files["package.json"] = canonical(package) + b"\n"
    return files


def _base(prior):
    base = prior._base()
    base.EXPECTED_FIXTURES = {
        key: {
            "version": version,
            "digests": {
                name: digest(raw) for name, raw in fixture_files(version).items()
            },
        }
        for key, version in (("baseline", "1.0.0"), ("candidate", "2.0.0"))
    }
    base.exact_disabled_target = lambda inspection, version: _disabled(
        base, inspection, version
    )
    return base


def diagnostic(reason, checks=None, exits=None):
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "reason": reason,
        "checks": dict.fromkeys(CHECKS, False) | (checks or {}),
        "exit_codes": exits if exits is not None else [None] * 8,
    }


class Refusal(ValueError):
    def __init__(self, reason, checks, exits=None):
        self.diagnostic = diagnostic(reason, checks, exits)
        super().__init__(reason)


def _record_snapshot():
    path = Path("/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite")
    if path.resolve(strict=True) != path:
        raise ValueError("state path changed")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute(
            "SELECT install_records_json FROM installed_plugin_index WHERE index_key = ?",
            ("installed-plugin-index",),
        ).fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not str or len(rows[0][0]) > 16384:
        raise ValueError("record inventory changed")
    value = json.loads(rows[0][0])
    if value != {PLUGIN_ID: install_record()}:
        raise ValueError("tracked record changed")
    return value


def _disabled(base, inspection, version):
    value = base.parsed_object(inspection)
    plugin = value.get("plugin", {}) if value is not None else {}
    return (
        inspection.get("command", {}).get("exit_code") == 0
        and inspection.get("command", {}).get("error") is None
        and plugin.get("id") == PLUGIN_ID
        and plugin.get("source") == str(base.TARGET_ROOT / "index.js")
        and plugin.get("status") == "disabled"
        and plugin.get("version") == version
        and value.get("install") == install_record()
    )


def _sqlite_custody(prior, before, after):
    # Seed bootstrap may have checkpointed a larger main database. Verify that
    # exact observed main file stays identical; never claim logical DB equality.
    db_before, db_after = before["entries"][0], after["entries"][0]
    if (
        db_before != db_after
        or type(db_before["size"]) is not int
        or db_before["size"] < 4096
        or db_before["size"] % 4096
    ):
        raise ValueError("main database changed")
    import copy

    left, right = copy.deepcopy(before), copy.deepcopy(after)
    for item in (left, right):
        item["entries"][0]["size"] = 4096
        item["tree_digest"] = digest(canonical(item["entries"]))
    validated = prior._sqlite_delta(left, right)
    return {
        **validated,
        "before": before,
        "after": after,
        "main_database_bytes": db_before["size"],
        "validation_binding": "EXACT_OBSERVED_PAGE_ALIGNED_MAIN_FILE_NOT_PREDECESSOR_SIZE",
        "logical_database_unchanged_verified": False,
    }


def validate(action, base, prior, records_before, records_after, checks):
    commands = action["commands"]
    exits = [
        item.get("exit_code")
        if type(item.get("exit_code")) is int and -255 <= item["exit_code"] <= 255
        else None
        for item in commands
    ]

    def require(ok, key, reason):
        checks[key] = bool(ok)
        if not ok:
            raise Refusal(reason, checks, exits)

    require(
        records_before == records_after == {PLUGIN_ID: install_record()},
        "tracked_record",
        "TRACKED_RECORD",
    )
    require(
        len(commands) == 8
        and all(
            item.get("error") is None
            and item.get("exit_code") == (1 if index == 4 else 0)
            for index, item in enumerate(commands)
        ),
        "update_command",
        "UPDATE_COMMAND",
    )
    update = commands[4]
    # The native policy logger writes its context before the update summary.
    # Both logger.warn and the outcome logger use defaultRuntime.log (stdout).
    expected = (
        f"Install policy target=plugin:{PLUGIN_ID} request=plugin-dir/update "
        "origin=plugin-package pathKind=directory source=local-path/user: "
        f"blocked by install policy: {base.EXPECTED_BLOCK_REASON}\n"
        f"Failed to update {PLUGIN_ID}: blocked by install policy: {base.EXPECTED_BLOCK_REASON} "
        f"(marketplace plugin {PLUGIN_ID} from {ROOT / 'marketplace.json'}).\n"
    ).encode("ascii")
    require(
        update.get("argv") == [base.NODE, base.OPENCLAW, "plugins", "update", PLUGIN_ID]
        and type(update.get("pid")) is int
        and update["pid"] > 0
        and update.get("signal") is None
        and update.get("stdout_excerpt") == expected.decode("ascii")
        and update.get("stdout_bytes") == len(expected)
        and update.get("stdout_digest") == digest(expected)
        and update.get("stderr_excerpt") == ""
        and update.get("stderr_bytes") == 0
        and update.get("stderr_digest") == digest(b""),
        "policy_denial",
        "POLICY_DENIAL",
    )
    before, after = action["before"], action["after"]
    invariants = {
        key: before["boundary"][key] == after["boundary"][key]
        for key in prior._INVARIANTS
        if key not in {"plugin_inspection", "skills_status"}
    }
    invariants.update(
        plugin_inspection=before["plugin"]["response"] == after["plugin"]["response"],
        skills_status=before["skills"]["response"] == after["skills"]["response"],
    )
    action["state_invariants"] = invariants
    info = base.parsed_object(after["info"])
    require(
        all(value for key, value in invariants.items() if key != "state_store")
        and _disabled(base, before["plugin"], "1.0.0")
        and _disabled(base, after["plugin"], "1.0.0")
        and info is not None
        and info.get("pid") == before["boundary"]["gateway_process"]["pid"]
        and all(
            boundary["target_plugin"]["baseline"]["ready"] is True
            and boundary["target_plugin"]["candidate"]["ready"] is False
            and all(
                boundary[key]["manifest"].get("skills") == ["."]
                for key in ("baseline_source", "candidate_source")
            )
            for boundary in (before["boundary"], after["boundary"])
        ),
        "protected_boundary",
        "PROTECTED_BOUNDARY",
    )
    try:
        sqlite = _sqlite_custody(
            prior, before["boundary"]["state_store"], after["boundary"]["state_store"]
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise Refusal("SQLITE_CUSTODY", checks, exits) from exc
    checks["sqlite_custody"] = True
    return {
        "explicit_policy_denial": True,
        "tracked_record_unchanged": True,
        "tracked_records_before": records_before,
        "tracked_records_after": records_after,
        "non_sqlite_protected_boundary_unchanged": True,
        "sqlite_file_delta": sqlite,
        "logical_database_unchanged_verified": False,
        "qualification_eligible": False,
    }


def observe():
    checks = dict.fromkeys(CHECKS, False)
    checks["identity"] = (
        sys.platform == "linux"
        and os.geteuid() == 992
        and os.getegid() == 992
        and os.getgroups() == [992]
        and bool(os.environ.get("OPENCLAW_GATEWAY_TOKEN"))
    )
    if not checks["identity"]:
        raise Refusal("IDENTITY", checks)
    prior = _prior()
    base = _base(prior)
    if (ROOT / "marketplace.json").read_bytes() != canonical(marketplace()) + b"\n":
        raise Refusal("SOURCES", checks)
    checks["sources"] = True
    version = base.command(["--version"])
    before = {
        "info": base.gateway_call("system.info"),
        "skills": base.gateway_call("skills.status"),
        "plugin": base.plugin_inspection(),
        "boundary": base.boundary(),
    }
    preliminary = {
        "prerequisites": {
            "version": base.public_command(version),
            "system_info_before": before["info"],
            "skills_status_before": before["skills"],
            "plugin_before": before["plugin"],
            "boundary_before": before["boundary"],
        }
    }
    readiness = prior.diagnostic(
        "PREREQUISITES", "PREREQUISITE_MISSING", preliminary, base
    )["checks"]
    checks["prerequisites"] = before["boundary"]["config"]["ready"] and all(
        value
        for key, value in readiness.items()
        if key not in {"policy_denial", "state_unchanged", "commands_clean"}
    )
    if not checks["prerequisites"]:
        raise Refusal("PREREQUISITES", checks)
    try:
        records_before = _record_snapshot()
    except (ValueError, sqlite3.Error) as exc:
        raise Refusal("TRACKED_RECORD", checks) from exc
    update = base.command(["plugins", "update", PLUGIN_ID])
    after = {
        "plugin": base.plugin_inspection(),
        "skills": base.gateway_call("skills.status"),
        "info": base.gateway_call("system.info"),
        "boundary": base.boundary(),
    }
    action = {
        "operation": "plugins update",
        "before": before,
        "after": after,
        "commands": [
            base.public_command(version),
            before["info"]["command"],
            before["skills"]["command"],
            before["plugin"]["command"],
            base.public_command(update),
            after["plugin"]["command"],
            after["skills"]["command"],
            after["info"]["command"],
        ],
    }
    try:
        records_after = _record_snapshot()
    except (ValueError, sqlite3.Error) as exc:
        raise Refusal(
            "TRACKED_RECORD",
            checks,
            [item.get("exit_code") for item in action["commands"]],
        ) from exc
    denial = validate(action, base, prior, records_before, records_after, checks)
    return {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "route_id": ROUTE,
        "branch": BRANCH,
        "status": "OBSERVED",
        "plugin_update_lifecycle_executed": True,
        "inventory_route_coverage": False,
        "route_qualified": False,
        "action": action,
        "explicit_policy_denial_observation": denial,
        "readiness_checks": readiness,
        "implementation_digest": digest(Path(__file__).read_bytes()),
        "helper_binding": {
            "name": PRIOR_NAME,
            "bytes": PRIOR_PIN[0],
            "digest": PRIOR_PIN[1],
            "legacy_run_observation_executed": False,
            "legacy_main_executed": False,
        },
        "native_version_binding": prior._VERSION_BINDING,
        "native_update_source_binding": {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "upstream_archive_digest": "sha256:ce65a9dcb876c0c507be4cc89a5c45566ac2d1b1abe1dc6813d52a359ba11623",
            "anchors": [
                "src/cli/plugins-update-command.ts:264-297,326-329",
                "src/plugins/update.ts:192-202,2110-2120",
                "src/plugins/marketplace.ts:672-678,1294-1318",
                "src/plugins/install-security-scan.runtime.ts:997-1043",
                "src/security/install-policy.ts:721-726,827-846",
            ],
            "policy_failure_channel": "stdout",
        },
        "decision": dict.fromkeys(prior._ELIGIBILITY, False),
        "limitations": [
            "LOCAL_MARKETPLACE_BRANCH_ONLY_NOT_NPM_GIT_OR_CLAWHUB",
            "PRE_EFFECT_DENIAL_NOT_REPLACEMENT_OR_RELOAD",
            "NO_LOGICAL_WHOLE_DATABASE_EQUALITY",
            "NOT_PHASE3_OR_FROZEN_V3_QUALIFICATION",
        ],
    }


def main():
    if sys.argv[1:]:
        return 64
    try:
        print(canonical(observe()).decode("ascii"))
        return 0
    except Refusal as exc:
        print(canonical(exc.diagnostic).decode("ascii"))
        return 126
    except Exception:  # noqa: BLE001 - emit only the bounded diagnostic at this process boundary
        print(canonical(diagnostic("INTERNAL")).decode("ascii"))
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
