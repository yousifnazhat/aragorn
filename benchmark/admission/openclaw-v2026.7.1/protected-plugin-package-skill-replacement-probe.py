"""Observe policy denial of one inert plugin package carrying replacement skills."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import types
from pathlib import Path

ROUTE = "VARIANT/plugin-package-skill-forced-install-denial"
INVENTORY_ROUTE = "ADM-02/update/plugin-package-skill-replacement"
PLUGIN_ID = "aragorn-plugin-skill-replacement-fixture"
ROOT = Path("/route-input/plugin-package-skill-replacement")
BASE_NAME = "protected-plugin-force-reinstall-v3-probe.py"
BASE_PIN = (
    30362,
    "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
)
_MAIN = b"\n\ntry:\n    output = main(sys.argv[1:])"
NATIVE_VERSION_STDOUT = "OpenClaw 2026.7.1\n"
_VERSION_ANCHOR = (
    b'and version.get("stdout_excerpt", "").strip() == "OpenClaw 2026.7.1 (7fa98d8)"'
)
_VERSION_BINDING = {
    "expected_stdout": NATIVE_VERSION_STDOUT,
    "retained_build_record": "benchmark/evidence/phase3-native-tool-runtime-build-development-v2-2026-09-13.json",
    "retained_build_bytes": 40591,
    "retained_build_digest": "sha256:a1d302431804f760299e1bcbd16aa269214ce0f35e2b8996c9f0cd3d03658877",
    "retained_field": "runtime_measurement.cli.stdout",
    "authority": "EXACT_NATIVE_DISPLAY_REBINDING_NOT_PREDECESSOR_EXECUTION_OR_RUNTIME_IDENTITY",
}
_DIAGNOSTIC_SCHEMA = "aragorn/native-plugin-package-denial-diagnostic/v1"
_CHECKS = (
    "version_match",
    "config_match",
    "config_custody",
    "config_mount",
    "config_lock_absent",
    "install_policy_match",
    "plugin_policy",
    "discovery_roots",
    "state_store",
    "baseline_source",
    "candidate_source",
    "target_baseline",
    "target_not_candidate",
    "target_metadata",
    "target_writable",
    "input_mount",
    "policy_command",
    "entrypoint_match",
    "gateway_identity",
    "system_info_pid",
    "skills_status",
    "plugin_disabled",
    "policy_denial",
    "state_unchanged",
    "commands_clean",
)
_EXITS = (
    "version",
    "system_info_before",
    "skills_before",
    "plugin_before",
    "force",
    "plugin_after",
    "skills_after",
    "system_info_after",
)
_INVARIANTS = (
    "baseline_source",
    "candidate_source",
    "config",
    "config_lock",
    "discovery_roots",
    "gateway_process",
    "install_policy_command",
    "openclaw",
    "plugin_inspection",
    "route_input_mount",
    "skills_status",
    "state_store",
    "target_plugin",
)
_ELIGIBILITY = (
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


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class ProbeRefusal(ValueError):
    """Only a bounded projection, never native diagnostics or exception text."""

    def __init__(self, phase, reason, action=None, base=None):
        super().__init__(reason)
        self.diagnostic = diagnostic(phase, reason, action, base)


def diagnostic(phase, reason, action=None, base=None):
    checks = dict.fromkeys(_CHECKS, False)
    exits = dict.fromkeys(_EXITS)
    invariants = dict.fromkeys(_INVARIANTS, False)
    if action is not None and base is not None:
        prerequisites = action.get("prerequisites", {})
        boundary = prerequisites.get("boundary_before", {})
        config = boundary.get("config", {})
        policy = config.get("plugin_policy", {})
        gateway = boundary.get("gateway_process", {})
        target = boundary.get("target_plugin", {})
        command = boundary.get("install_policy_command", {})
        version = prerequisites.get("version", {})
        info = base.parsed_object(prerequisites.get("system_info_before", {}))
        skills = prerequisites.get("skills_status_before", {})
        observations = action.get("observations", {})
        invariants.update(
            {
                key: observations.get("state_invariants", {}).get(key) is True
                for key in _INVARIANTS
            }
        )
        checks.update(
            {
                "version_match": version.get("exit_code") == 0
                and version.get("stdout_excerpt") == NATIVE_VERSION_STDOUT,
                "config_match": config.get("canonical_digest")
                == base.EXPECTED_CONFIG_DIGEST
                and config.get("file", {}).get("digest") == base.EXPECTED_CONFIG_DIGEST,
                "config_custody": all(
                    config.get("file", {}).get(key) == value
                    for key, value in (("mode", "400"), ("uid", 992), ("gid", 0))
                ),
                "config_mount": config.get("mount", {}).get("ready") is True,
                "config_lock_absent": boundary.get("config_lock", {}).get("exists")
                is False,
                "install_policy_match": config.get("install_policy")
                == base.EXPECTED_INSTALL_POLICY,
                "plugin_policy": policy.get("enabled") is True
                and policy.get("target_allowlisted") is False
                and policy.get("target_entry_present") is False,
                "discovery_roots": bool(boundary.get("discovery_roots"))
                and all(
                    item.get("ready") is True
                    for item in boundary.get("discovery_roots", {}).values()
                ),
                "state_store": boundary.get("state_store", {}).get("ready") is True,
                "baseline_source": boundary.get("baseline_source", {}).get("ready")
                is True,
                "candidate_source": boundary.get("candidate_source", {}).get("ready")
                is True,
                "target_baseline": target.get("baseline", {}).get("ready") is True,
                "target_not_candidate": target.get("candidate", {}).get("ready")
                is False,
                "target_metadata": target.get("exact_gateway_owned_metadata") is True,
                "target_writable": target.get("parent_writable") is True
                and target.get("target_writable") is True,
                "input_mount": boundary.get("route_input_mount", {}).get("ready")
                is True,
                "policy_command": all(
                    command.get(key) == value
                    for key, value in (
                        ("type", "file"),
                        ("uid", 0),
                        ("gid", 0),
                        ("mode", "755"),
                        ("nlink", 1),
                        ("size", 68480),
                        ("digest", base.EXPECTED_POLICY_COMMAND_DIGEST),
                        ("digest_error", None),
                    )
                ),
                "entrypoint_match": boundary.get("openclaw", {}).get("digest")
                == base.EXPECTED_OPENCLAW_DIGEST,
                "gateway_identity": gateway.get("cmdline") == ["openclaw-gateway"]
                and gateway.get("effective_capabilities") == "0000000000000000"
                and gateway.get("no_new_privileges") == "1",
                "system_info_pid": info is not None
                and info.get("pid") == gateway.get("pid"),
                "skills_status": skills.get("command", {}).get("exit_code") == 0
                and base.parsed_object(skills) is not None,
                "plugin_disabled": base.exact_disabled_target(
                    prerequisites.get("plugin_before", {}), "1.0.0"
                ),
                "policy_denial": observations.get("native_force_reinstall", {}).get(
                    "explicit_policy_block_observed"
                )
                is True,
                "state_unchanged": bool(observations.get("state_invariants"))
                and all(
                    value is True
                    for value in observations.get("state_invariants", {}).values()
                ),
                "commands_clean": bool(action.get("commands"))
                and all(
                    item.get("error") is None for item in action.get("commands", [])
                ),
            }
        )
        commands = [
            version,
            prerequisites.get("system_info_before", {}).get("command", {}),
            skills.get("command", {}),
            prerequisites.get("plugin_before", {}).get("command", {}),
        ]
        if len(action.get("commands", [])) == 8:
            commands = action["commands"]
        for name, item in zip(_EXITS, commands, strict=False):
            value = item.get("exit_code")
            exits[name] = value if type(value) is int and -255 <= value <= 255 else None
    return {
        "schema": _DIAGNOSTIC_SCHEMA,
        "phase": phase,
        "reason": reason,
        "checks": checks,
        "exit_codes": exits,
        "invariant_checks": invariants,
    }


def _sqlite_delta(before, after):
    """Bound physical custody/WAL shape only, never infer logical database equality."""
    file_keys = {
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
    directory_keys = file_keys - {"digest", "digest_error"}
    names = ["openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"]
    for state in (before, after):
        if (
            type(state) is not dict
            or set(state) != {"entries", "ready", "root", "tree_digest"}
            or state["ready"] is not True
            or type(state["entries"]) is not list
            or len(state["entries"]) != 3
            or [item.get("path") for item in state["entries"]] != names
            or state["tree_digest"] != digest(canonical(state["entries"]))
        ):
            raise ValueError("SQLite inventory changed")
        root = state["root"]
        if (
            type(root) is not dict
            or set(root) != directory_keys
            or any(
                root.get(key) != value
                for key, value in (
                    ("exists", True),
                    ("type", "directory"),
                    ("mode", "700"),
                    ("uid", 992),
                    ("gid", 992),
                    ("path", "/var/lib/aragorn-agent-gateway/state/state"),
                )
            )
        ):
            raise ValueError("SQLite root custody changed")
        for item in [root, *state["entries"]]:
            if (
                any(
                    type(item.get(key)) is not int or item[key] <= 0
                    for key in ("device", "inode", "nlink")
                )
                or type(item.get("size")) is not int
                or item["size"] < 0
            ):
                raise ValueError("SQLite identity changed")
        for item in state["entries"]:
            if (
                set(item) != file_keys
                or any(
                    item.get(key) != value
                    for key, value in (
                        ("exists", True),
                        ("type", "file"),
                        ("mode", "600"),
                        ("uid", 992),
                        ("gid", 992),
                        ("nlink", 1),
                        ("digest_error", None),
                    )
                )
                or type(item["digest"]) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is None
            ):
                raise ValueError("SQLite file custody changed")
        if (
            len({(item["device"], item["inode"]) for item in [root, *state["entries"]]})
            != 4
        ):
            raise ValueError("SQLite identities alias")
    if before["root"] != after["root"]:
        raise ValueError("SQLite root changed")
    for prior, later in zip(before["entries"], after["entries"], strict=True):
        if {k: v for k, v in prior.items() if k not in {"digest", "size"}} != {
            k: v for k, v in later.items() if k not in {"digest", "size"}
        }:
            raise ValueError("SQLite file identity changed")
    db, shm, wal = before["entries"]
    db_after, shm_after, wal_after = after["entries"]
    if db != db_after or db["size"] != 4096:
        raise ValueError("SQLite main database or shared memory shape changed")
    if (
        shm["size"] != 32768
        or shm_after["size"] != 32768
        or any(
            item["size"] <= 32 or (item["size"] - 32) % 4120
            for item in (wal, wal_after)
        )
    ):
        raise ValueError("SQLite WAL frame shape changed")
    changed = before != after
    if changed and not (
        shm["digest"] != shm_after["digest"]
        and wal["digest"] != wal_after["digest"]
        and wal["size"] < wal_after["size"]
    ):
        raise ValueError("SQLite delta is not the established WAL growth shape")
    return {
        "schema": "aragorn/plugin-denial-sqlite-file-delta/v1",
        "authority": "PHYSICAL_CUSTODY_AND_WAL_SHAPE_ONLY_NOT_LOGICAL_STATE_OR_CAUSATION_PROOF",
        "status": "OBSERVED",
        "delta_kind": "ESTABLISHED_WAL_GROWTH_SHAPE" if changed else "BYTE_IDENTICAL",
        "custody_unchanged": True,
        "main_database_file_bytes_unchanged": True,
        "wal_frame_bytes": 4120,
        "wal_size_increase_bytes": wal_after["size"] - wal["size"],
        "before": before,
        "after": after,
        "entire_state_store_byte_identical": not changed,
        "logical_database_unchanged_verified": False,
        "housekeeping_causation_verified": False,
        "qualification_eligible": False,
    }


def _successor_denial(action, base):
    """A separate narrow observation; preserve every raw predecessor claim."""

    def require(condition, reason):
        if not condition:
            raise ProbeRefusal("DENIAL", reason, action, base)

    before = action["prerequisites"]
    after = action["observations"]
    prior, later = before["boundary_before"], after["boundary_after"]
    invariants = after["state_invariants"]
    require(
        set(invariants) == set(_INVARIANTS)
        and all(type(value) is bool for value in invariants.values()),
        "PROTECTED_BOUNDARY_CHANGED",
    )
    computed = {
        key: prior[key] == later[key]
        for key in _INVARIANTS
        if key not in {"plugin_inspection", "skills_status"}
    }
    computed["plugin_inspection"] = (
        before["plugin_before"]["response"] == after["plugin_after"]["response"]
    )
    computed["skills_status"] = (
        before["skills_status_before"]["response"]
        == after["skills_status_after"]["response"]
    )
    require(
        invariants == computed
        and all(value for key, value in computed.items() if key != "state_store"),
        "PROTECTED_BOUNDARY_CHANGED",
    )
    commands = action["commands"]
    require(
        action["status"] == "OBSERVED"
        and action["execution_error"] is None
        and len(commands) == 8
        and all(
            item.get("error") is None
            and item.get("exit_code") == (1 if index == 4 else 0)
            for index, item in enumerate(commands)
        ),
        "POLICY_DENIAL_NOT_ESTABLISHED",
    )
    force = after["native_force_reinstall"]
    command = force["command"]
    expected_stderr = (
        "blocked by install policy: " + base.EXPECTED_BLOCK_REASON + "\n"
    ).encode("ascii")
    require(
        force["process_started"] is True
        and command == commands[4]
        and command.get("argv") == [base.NODE, base.OPENCLAW, *base.FORCE_ARGS]
        and type(command.get("pid")) is int
        and command["pid"] > 0
        and command.get("signal") is None
        and command.get("stderr_excerpt") == expected_stderr.decode("ascii")
        and command.get("stderr_bytes") == len(expected_stderr)
        and command.get("stderr_digest") == digest(expected_stderr),
        "POLICY_DENIAL_NOT_ESTABLISHED",
    )
    info = base.parsed_object(after["system_info_after"])
    require(
        base.exact_disabled_target(before["plugin_before"], "1.0.0")
        and base.exact_disabled_target(after["plugin_after"], "1.0.0")
        and base.install_record_absent(before["plugin_before"])
        and base.install_record_absent(after["plugin_after"])
        and prior["target_plugin"]["baseline"]["ready"] is True
        and later["target_plugin"]["baseline"]["ready"] is True
        and prior["target_plugin"]["candidate"]["ready"] is False
        and later["target_plugin"]["candidate"]["ready"] is False
        and info is not None
        and info.get("pid") == prior["gateway_process"]["pid"],
        "PROTECTED_BOUNDARY_CHANGED",
    )
    try:
        sqlite = _sqlite_delta(prior["state_store"], later["state_store"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ProbeRefusal("SQLITE", "SQLITE_DELTA_UNRECOGNIZED", action, base) from exc
    return {
        "schema": "aragorn/plugin-package-force-install-policy-denial-observation/v1",
        "authority": "EXACT_POLICY_DENIAL_AND_NON_SQLITE_BOUNDARY_ONLY_NOT_WHOLE_STATE_OR_ROUTE_QUALIFICATION",
        "status": "OBSERVED",
        "explicit_policy_denial": True,
        "non_sqlite_protected_boundary_unchanged": True,
        "disabled_baseline_and_cli_install_record_absence_unchanged": True,
        "raw_base_explicit_policy_block_observed": force[
            "explicit_policy_block_observed"
        ],
        "sqlite_file_delta": sqlite,
        "logical_database_unchanged_verified": False,
        "qualification_eligible": False,
    }


def fixture_files(version: str) -> dict[str, bytes]:
    if version not in {"1.0.0", "2.0.0"}:
        raise ValueError("only the two fixed inert package versions are supported")
    label = "baseline" if version == "1.0.0" else "candidate"
    return {
        "index.js": (
            'export default { id: "' + PLUGIN_ID + '", '
            'name: "Aragorn inert plugin skills fixture", register() {} };\n'
        ).encode("ascii"),
        "openclaw.plugin.json": canonical(
            {
                "id": PLUGIN_ID,
                "name": "Aragorn inert plugin skills fixture",
                "version": version,
                "skills": ["."],
                "configSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        )
        + b"\n",
        "package.json": canonical(
            {
                "name": "@aragorn/plugin-skill-replacement-fixture",
                "private": True,
                "type": "module",
                "version": version,
                "openclaw": {"extensions": ["./index.js"]},
            }
        )
        + b"\n",
        "SKILL.md": (
            "---\nname: aragorn-inert-plugin-skill\n"
            "description: Inert plugin package admission fixture.\n---\n"
            f"# Aragorn {label} skill\n\nThis fixture performs no actions.\n"
        ).encode("ascii"),
    }


def _read_base(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        raw = b""
        while len(raw) <= BASE_PIN[0]:
            part = os.read(fd, BASE_PIN[0] + 1 - len(raw))
            if not part:
                break
            raw += part
        after, named = os.fstat(fd), path.lstat()
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            (len(raw), digest(raw)) != BASE_PIN
            or before.st_nlink != 1
            or any(
                getattr(before, key) != getattr(after, key)
                or getattr(after, key) != getattr(named, key)
                for key in fields
            )
        ):
            raise ValueError("pinned denial helper changed")
        return raw
    finally:
        os.close(fd)


def _base():
    source = Path(__file__).with_name(BASE_NAME)
    raw = _read_base(source)
    if raw.count(_MAIN) != 1:
        raise ValueError("pinned denial helper entrypoint changed")
    definitions = raw.split(_MAIN)[0]
    if definitions.count(_VERSION_ANCHOR) != 1:
        raise ValueError("pinned version predicate changed")
    definitions = definitions.replace(
        _VERSION_ANCHOR,
        b'and version.get("stdout_excerpt", "") == '
        + repr(NATIVE_VERSION_STDOUT).encode("ascii"),
    )
    module = types.ModuleType("aragorn_plugin_package_denial_base")
    module.__file__ = str(source)
    # Exact-pinned definitions with one disclosed native display predicate rebound.
    # The predecessor CLI main never runs, and captured CLI bytes are not rewritten.
    exec(compile(definitions, str(source), "exec"), module.__dict__)  # noqa: S102 - exact pinned definitions plus one fixed predicate, no legacy main
    module.rendered_definitions_digest = digest(definitions)
    module.PLUGIN_ID = PLUGIN_ID
    module.ROUTE_ID = ROUTE
    module.ACTION_ID = "plugin-package-skill-replacement"
    module.ROUTE_ROOT = ROOT
    module.BASELINE_SOURCE = ROOT / "baseline-source"
    module.CANDIDATE_SOURCE = ROOT / "candidate-source"
    module.TARGET_ROOT = module.STATE / "extensions" / PLUGIN_ID
    module.FORCE_ARGS = ("plugins", "install", str(module.CANDIDATE_SOURCE), "--force")
    module.EXPECTED_FIXTURES = {
        key: {
            "version": version,
            "digests": {
                name: digest(content)
                for name, content in fixture_files(version).items()
            },
        }
        for key, version in (("baseline", "1.0.0"), ("candidate", "2.0.0"))
    }

    def target_metadata(observation):
        tree = observation.get("tree", {})
        root, entries = tree.get("root", {}), tree.get("entries", [])
        return (
            root.get("type") == "directory"
            and root.get("uid") == 992
            and root.get("gid") == 992
            and root.get("mode") == "700"
            and len(entries) == 4
            and all(
                item.get("type") == "file"
                and item.get("uid") == 992
                and item.get("gid") == 992
                and item.get("mode") == "600"
                and item.get("nlink") == 1
                for item in entries
            )
        )

    module.exact_target_metadata = target_metadata
    return module


def observe() -> dict:
    if (
        sys.platform != "linux"
        or os.geteuid() != 992
        or os.getegid() != 992
        or os.getgroups() != [992]
        or not os.environ.get("OPENCLAW_GATEWAY_TOKEN")
    ):
        raise ProbeRefusal("IDENTITY", "GATEWAY_IDENTITY_REFUSED")
    try:
        base = _base()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise ProbeRefusal("HELPER", "HELPER_REFUSED") from exc
    try:
        action = base.run_observation()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise ProbeRefusal("PREREQUISITES", "OBSERVATION_FAILED") from exc
    if action["status"] == "NOT_TESTED" and not action.get("observations"):
        raise ProbeRefusal("PREREQUISITES", "PREREQUISITE_MISSING", action, base)
    denial = _successor_denial(action, base)
    before = action["prerequisites"]["boundary_before"]
    after = action["observations"]["boundary_after"]
    for boundary in (before, after):
        for item in (
            boundary["baseline_source"],
            boundary["candidate_source"],
            boundary["target_plugin"]["baseline"],
        ):
            if item["manifest"].get("skills") != ["."] or not item["ready"]:
                raise ProbeRefusal("BOUNDARY", "DECLARED_SKILL_CHANGED", action, base)
    if fixture_files("1.0.0")["SKILL.md"] == fixture_files("2.0.0")["SKILL.md"]:
        raise ProbeRefusal("INVARIANTS", "PROTECTED_STATE_CHANGED", action, base)
    return {
        "schema": "aragorn/native-plugin-package-skill-replacement-denial/v1",
        "authority": "FIXED_INERT_PACKAGE_POLICY_DENIAL_NOT_ADMISSION_OR_CAMPAIGN_QUALIFICATION",
        "route_id": ROUTE,
        "intended_inventory_route_id": INVENTORY_ROUTE,
        "operation_variant": "FIXED_LOCAL_FORCE_INSTALL_WITH_DECLARED_SKILLS_NOT_PLUGIN_UPDATE",
        "inventory_route_executed": False,
        "inventory_route_coverage": False,
        "plugin_update_lifecycle_executed": False,
        "status": "OBSERVED",
        "action": action,
        "explicit_policy_denial_observation": denial,
        "base_helper": {"bytes": BASE_PIN[0], "digest": BASE_PIN[1]},
        "rendered_definitions_digest": base.rendered_definitions_digest,
        "native_version_binding": _VERSION_BINDING,
        "implementation_digest": digest(Path(__file__).read_bytes()),
        "declared_skill_root": ".",
        "baseline_skill_digest": digest(fixture_files("1.0.0")["SKILL.md"]),
        "candidate_skill_digest": digest(fixture_files("2.0.0")["SKILL.md"]),
        "decision": {key: False for key in _ELIGIBILITY},
        "limitations": [
            "DORMANT_NON_ALLOWLISTED_PLUGIN_PACKAGE_ONLY_NO_PLUGIN_CODE_LOADED",
            "ORDINARY_FORCE_INSTALL_DENIED_NOT_SUCCESSFUL_PACKAGE_OR_SKILL_ACTIVATION",
            "GATEWAY_SKILLS_STATUS_CHECKED_NOT_INTERNAL_CACHE_OR_MODEL_PROMPT",
            "REQUIRES_CALLER_BOUND_RUNTIME_TREE_NAMESPACE_PARENT_AND_CLEANUP",
            "NO_FINAL_CAMPAIGN_PASS_OR_PHASE3_AUTHORITY",
            "PLUGIN_UPDATE_INVENTORY_LIFECYCLE_NOT_EXECUTED",
            "SQLITE_WAL_SHAPE_OBSERVED_NOT_LOGICAL_DATABASE_EQUALITY_OR_HOUSEKEEPING_CAUSATION",
        ],
    }


def main() -> int:
    if sys.argv[1:]:
        return 64
    try:
        print(canonical(observe()).decode("ascii"))
        return 0
    except KeyboardInterrupt:
        return 130
    except ProbeRefusal as exc:
        print(canonical(exc.diagnostic).decode("ascii"))
        return 126
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        print(canonical(diagnostic("INTERNAL", "INTERNAL_ERROR")).decode("ascii"))
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
