#!/usr/bin/env python3
"""Observe one exact native plugin force-reinstall attempt without authority claims."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ASSURANCE = "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
NODE = "/usr/local/bin/node"
OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
CONFIG = Path("/run/credentials/aragorn-agent-gateway.service/openclaw-config")
STATE = Path("/var/lib/aragorn-agent-gateway/state")
STATE_STORE = STATE / "state"
HOME = Path("/var/lib/aragorn-agent-gateway/home")
WORKSPACE = Path("/var/lib/aragorn-agent-gateway/workspace")
ROUTE_INPUT = Path("/route-input")
ROUTE_ROOT = ROUTE_INPUT / "plugin-force-reinstall"
BASELINE_SOURCE = ROUTE_ROOT / "baseline-source"
CANDIDATE_SOURCE = ROUTE_ROOT / "candidate-source"
PLUGIN_ID = "aragorn-force-reinstall-fixture"
TARGET_ROOT = STATE / "extensions" / PLUGIN_ID
ROUTE_ID = "ADM-02/update/plugin-force-reinstall"
ACTION_ID = "plugin-force-reinstall"
EXPECTED_CONFIG_DIGEST = (
    "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
)
EXPECTED_OPENCLAW_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
FORCE_ARGS = ("plugins", "install", str(CANDIDATE_SOURCE), "--force")
EXPECTED_FIXTURES = {
    "baseline": {
        "version": "1.0.0",
        "digests": {
            "index.js": "sha256:631cc6f036f3cdf2f8fa6c814a27da075bf8c37fd2fe3681a55f7f5e593dd4ea",
            "openclaw.plugin.json": "sha256:9b93a70d606ec63c32d15dd9021dc603df9bdf680b74789c675f5227c1c6b077",
            "package.json": "sha256:cf817f208ceb1f4bb211d5cc97b190f6ba54cb27f34d7864b9fea5adc74a679e",
        },
    },
    "candidate": {
        "version": "2.0.0",
        "digests": {
            "index.js": "sha256:0d4abd050921ecb1c29c8c97457654184137c65644ca9b3e21a920284ce5178b",
            "openclaw.plugin.json": "sha256:5579b471618e53e8fd72df36ad0128bb6310c0fc8111be6db31a18c672b5053c",
            "package.json": "sha256:7e73514c5369d1d90524663baff896f41f71e21540d1b0a311a73aaf456ee8de",
        },
    },
}
DISCOVERY_ROOTS = (
    STATE / "extensions",
    STATE / "plugin-skills",
    STATE / "skills",
    HOME / ".agents" / "skills",
    WORKSPACE / ".agents" / "skills",
    WORKSPACE / "skills",
)
OUTPUT_LIMIT = 2 * 1024 * 1024
EXCERPT_LIMIT = 2048
TREE_LIMIT = 512


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def error_record(error: BaseException) -> dict[str, Any]:
    return {
        "message": str(error),
        "name": type(error).__name__,
    }


def runtime_environment() -> dict[str, str]:
    return {
        "HOME": str(HOME),
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "NO_COLOR": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "OPENCLAW_CONFIG_PATH": str(CONFIG),
        "OPENCLAW_GATEWAY_TOKEN": os.environ.get("OPENCLAW_GATEWAY_TOKEN", ""),
        "OPENCLAW_NO_RESPAWN": "1",
        "OPENCLAW_SKIP_CHANNELS": "1",
        "OPENCLAW_SKIP_PROVIDERS": "1",
        "OPENCLAW_STATE_DIR": str(STATE),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_offline": "true",
    }


def command(arguments: list[str], timeout: float = 30.0) -> dict[str, Any]:
    argv = [NODE, OPENCLAW, *arguments]
    started_at = now()
    process: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    error: dict[str, Any] | None = None
    try:
        process = subprocess.Popen(
            argv,
            cwd=WORKSPACE,
            env=runtime_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        error = error_record(exc)
        if process is not None:
            process.send_signal(signal.SIGKILL)
            stdout, stderr = process.communicate()
    except OSError as exc:
        error = error_record(exc)
    if len(stdout) > OUTPUT_LIMIT or len(stderr) > OUTPUT_LIMIT:
        error = error_record(ValueError("native command output exceeded bound"))
    return {
        "argv": argv,
        "completed_at": now(),
        "error": error,
        "exit_code": process.returncode if process is not None else None,
        "pid": process.pid if process is not None else None,
        "signal": (
            signal.Signals(-process.returncode).name
            if process is not None and process.returncode is not None and process.returncode < 0
            else None
        ),
        "started_at": started_at,
        "stderr_bytes": len(stderr),
        "stderr_digest": digest(stderr),
        "stderr_excerpt": stderr[:EXCERPT_LIMIT].decode("utf-8", errors="replace"),
        "stdout_bytes": len(stdout),
        "stdout_digest": digest(stdout),
        "stdout_excerpt": stdout[:EXCERPT_LIMIT].decode("utf-8", errors="replace"),
        "_stderr": stderr.decode("utf-8", errors="replace"),
        "_stdout": stdout.decode("utf-8", errors="replace"),
    }


def public_command(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def parsed_command(value: dict[str, Any]) -> dict[str, Any]:
    for raw in (value.get("_stdout", ""), value.get("_stderr", "")):
        try:
            return {"parsed": True, "value": json.loads(raw)}
        except (TypeError, ValueError):
            pass
    return {"parsed": False, "value": None}


def path_observation(path: Path, *, hash_file: bool = False) -> dict[str, Any]:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "path": str(path)}
    kind = (
        "directory"
        if stat.S_ISDIR(value.st_mode)
        else "file"
        if stat.S_ISREG(value.st_mode)
        else "symlink"
        if stat.S_ISLNK(value.st_mode)
        else "other"
    )
    record: dict[str, Any] = {
        "device": value.st_dev,
        "exists": True,
        "gid": value.st_gid,
        "inode": value.st_ino,
        "mode": format(stat.S_IMODE(value.st_mode), "o"),
        "nlink": value.st_nlink,
        "path": str(path),
        "size": value.st_size,
        "type": kind,
        "uid": value.st_uid,
    }
    if kind == "file" and hash_file:
        try:
            record["digest"] = digest(path.read_bytes())
            record["digest_error"] = None
        except OSError as exc:
            record["digest"] = None
            record["digest_error"] = error_record(exc)
    elif kind == "symlink":
        record["target"] = os.readlink(path)
    return record


def tree_observation(root: Path) -> dict[str, Any]:
    root_record = path_observation(root)
    if root_record.get("type") != "directory":
        return {"entries": [], "ready": False, "root": root_record, "tree_digest": None}
    entries: list[dict[str, Any]] = []
    pending = [root]
    try:
        while pending:
            directory = pending.pop(0)
            for path in sorted(directory.iterdir(), key=lambda item: item.name):
                record = path_observation(path, hash_file=True)
                record["path"] = str(path.relative_to(root))
                entries.append(record)
                if len(entries) > TREE_LIMIT:
                    return {
                        "entries": entries[:TREE_LIMIT],
                        "ready": False,
                        "root": root_record,
                        "tree_digest": None,
                    }
                if record["type"] == "directory":
                    pending.append(path)
    except OSError as exc:
        return {
            "entries": entries,
            "error": error_record(exc),
            "ready": False,
            "root": root_record,
            "tree_digest": None,
        }
    return {
        "entries": entries,
        "ready": all(item.get("digest_error") is None for item in entries),
        "root": root_record,
        "tree_digest": digest(canonical_json(entries)),
    }


def fixture_observation(root: Path, fixture: str) -> dict[str, Any]:
    tree = tree_observation(root)
    expected = EXPECTED_FIXTURES[fixture]
    actual = {
        item["path"]: item.get("digest")
        for item in tree.get("entries", [])
        if item.get("type") == "file"
    }
    manifest = None
    package = None
    try:
        manifest = json.loads((root / "openclaw.plugin.json").read_bytes())
        package = json.loads((root / "package.json").read_bytes())
    except (OSError, ValueError):
        pass
    openclaw = package.get("openclaw") if isinstance(package, dict) else None
    ready = (
        tree.get("ready") is True
        and len(tree.get("entries", [])) == len(expected["digests"])
        and all(
            item.get("type") == "file" for item in tree.get("entries", [])
        )
        and actual == expected["digests"]
        and isinstance(manifest, dict)
        and manifest.get("id") == PLUGIN_ID
        and manifest.get("version") == expected["version"]
        and isinstance(package, dict)
        and package.get("version") == expected["version"]
        and isinstance(openclaw, dict)
        and openclaw.get("extensions") == ["./index.js"]
        and not any(key in package for key in ("dependencies", "scripts"))
    )
    return {
        "expected_fixture": fixture,
        "manifest": manifest,
        "package": package,
        "ready": ready,
        "tree": tree,
    }


def exact_target_metadata(observation: dict[str, Any]) -> bool:
    tree = observation.get("tree", {})
    root = tree.get("root", {})
    entries = tree.get("entries", [])
    return (
        root.get("type") == "directory"
        and root.get("uid") == 992
        and root.get("gid") == 992
        and root.get("mode") == "700"
        and len(entries) == 3
        and all(
            item.get("type") == "file"
            and item.get("uid") == 992
            and item.get("gid") == 992
            and item.get("mode") == "600"
            and item.get("nlink") == 1
            for item in entries
        )
    )


def decode_mount_path(value: str) -> str:
    for code in ("040", "011", "012", "134"):
        value = value.replace("\\" + code, chr(int(code, 8)))
    return value


def mount_observation(path: Path) -> dict[str, Any]:
    records = []
    try:
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            fields = line.split(" ")
            separator = fields.index("-") if "-" in fields else -1
            if separator < 6 or len(fields) < separator + 4:
                continue
            if Path(decode_mount_path(fields[4])).resolve() != path.resolve():
                continue
            records.append(
                {
                    "filesystem": fields[separator + 1],
                    "mount_options": sorted(fields[5].split(",")),
                    "mount_point": decode_mount_path(fields[4]),
                    "root": decode_mount_path(fields[3]),
                    "source": decode_mount_path(fields[separator + 2]),
                    "super_options": sorted(fields[separator + 3].split(",")),
                }
            )
    except OSError as exc:
        return {"error": error_record(exc), "path": str(path), "records": [], "ready": False}
    read_only = (
        len(records) == 1
        and "ro" in records[0]["mount_options"]
        and "rw" not in records[0]["mount_options"]
    )
    return {"path": str(path), "read_only": read_only, "records": records, "ready": read_only}


def config_observation() -> dict[str, Any]:
    file_record = path_observation(CONFIG, hash_file=True)
    document = None
    canonical_digest = None
    try:
        document = json.loads(CONFIG.read_bytes())
        canonical_digest = digest(canonical_json(document))
    except (OSError, ValueError):
        pass
    plugins = document.get("plugins", {}) if isinstance(document, dict) else {}
    allow = plugins.get("allow", []) if isinstance(plugins, dict) else []
    entries = plugins.get("entries", {}) if isinstance(plugins, dict) else {}
    allow = allow if isinstance(allow, list) else []
    entries = entries if isinstance(entries, dict) else {}
    return {
        "canonical_digest": canonical_digest,
        "file": file_record,
        "mount": mount_observation(CONFIG.parent),
        "plugin_policy": {
            "allow": plugins.get("allow"),
            "enabled": plugins.get("enabled"),
            "target_allowlisted": PLUGIN_ID in allow,
            "target_entry": entries.get(PLUGIN_ID),
            "target_entry_present": PLUGIN_ID in entries,
        },
        "ready": (
            file_record.get("digest") == EXPECTED_CONFIG_DIGEST
            and canonical_digest == EXPECTED_CONFIG_DIGEST
            and file_record.get("mode") == "400"
            and file_record.get("uid") == 992
            and file_record.get("gid") == 0
            and mount_observation(CONFIG.parent)["ready"]
        ),
    }


def gateway_process() -> dict[str, Any]:
    raw_pid = os.environ.get("ARAGORN_GATEWAY_PID", "")
    if not raw_pid.isdecimal() or raw_pid.startswith("0"):
        return {"error": error_record(ValueError("invalid gateway PID")), "pid": None}
    pid = int(raw_pid)
    try:
        status_rows = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
        status = dict(row.split(":", 1) for row in status_rows if ":" in row)
        raw_stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").strip()
        close = raw_stat.rfind(")")
        fields = raw_stat[close + 2 :].split(" ") if close >= 0 else []
        return {
            "cmdline": [
                item
                for item in Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .decode("utf-8")
                .split("\0")
                if item
            ],
            "effective_capabilities": status.get("CapEff", "").strip(),
            "no_new_privileges": status.get("NoNewPrivs", "").strip(),
            "pid": pid,
            "seccomp": status.get("Seccomp", "").strip(),
            "start_time_ticks": fields[19] if len(fields) > 19 else None,
        }
    except OSError as exc:
        return {"error": error_record(exc), "pid": pid}


def plugin_inspection() -> dict[str, Any]:
    native = command(["plugins", "inspect", PLUGIN_ID, "--json"])
    return {"command": public_command(native), "response": parsed_command(native)}


def gateway_call(method: str) -> dict[str, Any]:
    native = command(["gateway", "call", method, "--json", "--timeout", "5000"], 10.0)
    return {"command": public_command(native), "response": parsed_command(native)}


def boundary() -> dict[str, Any]:
    target_baseline = fixture_observation(TARGET_ROOT, "baseline")
    target_candidate = fixture_observation(TARGET_ROOT, "candidate")
    return {
        "baseline_source": fixture_observation(BASELINE_SOURCE, "baseline"),
        "candidate_source": fixture_observation(CANDIDATE_SOURCE, "candidate"),
        "config": config_observation(),
        "config_lock": path_observation(Path(str(CONFIG) + ".lock"), hash_file=True),
        "discovery_roots": {str(path): tree_observation(path) for path in DISCOVERY_ROOTS},
        "gateway_process": gateway_process(),
        "openclaw": path_observation(Path(OPENCLAW), hash_file=True),
        "route_input_mount": mount_observation(ROUTE_INPUT),
        "state_store": tree_observation(STATE_STORE),
        "target_plugin": {
            "baseline": target_baseline,
            "candidate": target_candidate,
            "exact_gateway_owned_metadata": exact_target_metadata(target_baseline),
            "parent_writable": os.access(TARGET_ROOT.parent, os.W_OK),
            "target_writable": os.access(TARGET_ROOT, os.W_OK),
        },
    }


def parsed_object(observation: dict[str, Any]) -> dict[str, Any] | None:
    response = observation.get("response")
    if not isinstance(response, dict) or response.get("parsed") is not True:
        return None
    value = response.get("value")
    return value if isinstance(value, dict) else None


def exact_disabled_target(inspection: dict[str, Any], version: str) -> bool:
    value = parsed_object(inspection)
    plugin = value.get("plugin") if value is not None else None
    return (
        inspection.get("command", {}).get("exit_code") == 0
        and inspection.get("command", {}).get("error") is None
        and isinstance(plugin, dict)
        and plugin.get("id") == PLUGIN_ID
        and plugin.get("source") == str(TARGET_ROOT / "index.js")
        and plugin.get("status") == "disabled"
        and plugin.get("version") == version
        and "install" not in value
    )


def install_record_absent(inspection: dict[str, Any]) -> bool:
    value = parsed_object(inspection)
    return value is not None and "install" not in value


def run_observation() -> dict[str, Any]:
    version = command(["--version"])
    info_before = gateway_call("system.info")
    skills_before = gateway_call("skills.status")
    plugin_before = plugin_inspection()
    before = boundary()
    gateway = before["gateway_process"]
    policy = before["config"]["plugin_policy"]
    info_value = parsed_object(info_before)
    skills_value = parsed_object(skills_before)
    ready = (
        before["config"]["ready"]
        and policy["enabled"] is True
        and policy["target_allowlisted"] is False
        and policy["target_entry_present"] is False
        and before["config_lock"].get("exists") is False
        and all(item.get("ready") is True for item in before["discovery_roots"].values())
        and before["route_input_mount"].get("ready") is True
        and before["state_store"].get("ready") is True
        and before["baseline_source"].get("ready") is True
        and before["candidate_source"].get("ready") is True
        and before["target_plugin"]["baseline"].get("ready") is True
        and before["target_plugin"]["candidate"].get("ready") is False
        and before["target_plugin"]["exact_gateway_owned_metadata"] is True
        and before["target_plugin"]["parent_writable"] is True
        and before["target_plugin"]["target_writable"] is True
        and before["openclaw"].get("digest") == EXPECTED_OPENCLAW_DIGEST
        and gateway.get("cmdline") == ["openclaw-gateway"]
        and gateway.get("effective_capabilities") == "0000000000000000"
        and gateway.get("no_new_privileges") == "1"
        and version.get("exit_code") == 0
        and version.get("stdout_excerpt", "").strip() == "OpenClaw 2026.7.1 (7fa98d8)"
        and info_value is not None
        and info_value.get("pid") == gateway.get("pid")
        and skills_before["command"].get("exit_code") == 0
        and skills_value is not None
        and exact_disabled_target(plugin_before, "1.0.0")
    )
    prerequisites = {
        "boundary_before": before,
        "plugin_before": plugin_before,
        "skills_status_before": skills_before,
        "system_info_before": info_before,
        "version": public_command(version),
    }
    if not ready:
        return {
            "commands": [],
            "execution_error": None,
            "id": ACTION_ID,
            "observations": {},
            "prerequisites": prerequisites,
            "reason_codes": ["EXACT_PLUGIN_FORCE_REINSTALL_PREREQUISITE_MISSING"],
            "status": "NOT_TESTED",
        }

    force = command(list(FORCE_ARGS))
    plugin_after = plugin_inspection()
    skills_after = gateway_call("skills.status")
    info_after = gateway_call("system.info")
    after = boundary()
    started = isinstance(force.get("pid"), int) and force["pid"] > 0 and force["error"] is None
    invariants = {
        "baseline_source": before["baseline_source"] == after["baseline_source"],
        "candidate_source": before["candidate_source"] == after["candidate_source"],
        "config": before["config"] == after["config"],
        "config_lock": before["config_lock"] == after["config_lock"],
        "discovery_roots": before["discovery_roots"] == after["discovery_roots"],
        "gateway_process": before["gateway_process"] == after["gateway_process"],
        "openclaw": before["openclaw"] == after["openclaw"],
        "plugin_inspection": plugin_before["response"] == plugin_after["response"],
        "route_input_mount": before["route_input_mount"] == after["route_input_mount"],
        "skills_status": skills_before["response"] == skills_after["response"],
        "state_store": before["state_store"] == after["state_store"],
        "target_plugin": before["target_plugin"] == after["target_plugin"],
    }
    target_transition = {
        "after_is_baseline": after["target_plugin"]["baseline"].get("ready") is True,
        "after_is_candidate": after["target_plugin"]["candidate"].get("ready") is True,
        "before_is_baseline": before["target_plugin"]["baseline"].get("ready") is True,
        "candidate_differs_from_baseline": (
            EXPECTED_FIXTURES["candidate"]["digests"]
            != EXPECTED_FIXTURES["baseline"]["digests"]
        ),
    }
    return {
        "commands": [
            public_command(version),
            info_before["command"],
            skills_before["command"],
            plugin_before["command"],
            public_command(force),
            plugin_after["command"],
            skills_after["command"],
            info_after["command"],
        ],
        "execution_error": force["error"],
        "id": ACTION_ID,
        "observations": {
            "boundary_after": after,
            "native_force_reinstall": {
                "command": public_command(force),
                "effective_update_basis": {
                    "candidate_manifest_id": PLUGIN_ID,
                    "existing_target_manifest_id": PLUGIN_ID,
                    "force_requested": True,
                    "target_existed_before": True,
                },
                "process_started": started,
                "same_id_existing_target": (
                    before["target_plugin"]["baseline"].get("ready") is True
                    and before["candidate_source"].get("ready") is True
                ),
                "source_path": str(CANDIDATE_SOURCE),
                "target_plugin_id": PLUGIN_ID,
                "target_path": str(TARGET_ROOT),
            },
            "plugin_after": plugin_after,
            "post_write_containment": {
                "configuration_unchanged": invariants["config"],
                "external_skill_catalog_unchanged": invariants["skills_status"],
                "gateway_process_unchanged": invariants["gateway_process"],
                "installed_record_absent": install_record_absent(plugin_after),
                "replacement_disabled": exact_disabled_target(plugin_after, "2.0.0"),
                "state_store_unchanged": invariants["state_store"],
                "target_transition": target_transition,
            },
            "skills_status_after": skills_after,
            "state_invariants": invariants,
            "system_info_after": info_after,
        },
        "prerequisites": prerequisites,
        "reason_codes": [] if started else ["NATIVE_PLUGIN_FORCE_REINSTALL_PROCESS_NOT_STARTED"],
        "status": "OBSERVED" if started else "NOT_TESTED",
    }


def self_check() -> dict[str, Any]:
    checks = {
        "action_id_exact": ACTION_ID == "plugin-force-reinstall",
        "fixtures_are_distinct": (
            EXPECTED_FIXTURES["baseline"]["digests"]
            != EXPECTED_FIXTURES["candidate"]["digests"]
        ),
        "native_action_exact": list(FORCE_ARGS)
        == ["plugins", "install", str(CANDIDATE_SOURCE), "--force"],
        "raw_observation_only": ASSURANCE
        == "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
        "route_id_exact": ROUTE_ID == "ADM-02/update/plugin-force-reinstall",
        "same_id_target_exact": TARGET_ROOT.name == PLUGIN_ID,
        "target_is_state_extension": TARGET_ROOT
        == STATE / "extensions" / "aragorn-force-reinstall-fixture",
    }
    return {
        "assurance": ASSURANCE,
        "checks": checks,
        "native_action": {"argv": [NODE, OPENCLAW, *FORCE_ARGS]},
        "route_id": ROUTE_ID,
        "schema": "aragorn/openclaw-protected-plugin-force-reinstall-self-check/v1",
        "status": "SELF_CHECK_OK" if all(checks.values()) else "SELF_CHECK_ERROR",
    }


def main(arguments: list[str]) -> dict[str, Any]:
    if arguments == ["self-check"]:
        return self_check()
    if arguments:
        raise ValueError("the plugin force-reinstall probe accepts no arguments or self-check")
    if not os.environ.get("OPENCLAW_GATEWAY_TOKEN"):
        raise ValueError("OPENCLAW_GATEWAY_TOKEN is required")
    action = run_observation()
    return {
        "action": action,
        "assurance": ASSURANCE,
        "implementation_digest": digest(Path(__file__).read_bytes()),
        "recorded_at": now(),
        "route": {
            "action_id": action["id"],
            "id": ROUTE_ID,
            "reason_codes": action["reason_codes"],
            "status": action["status"],
        },
        "run_nonce": secrets.token_hex(16),
        "runtime_binding": {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": NODE,
            "openclaw_digest": EXPECTED_OPENCLAW_DIGEST,
            "openclaw_path": OPENCLAW,
            "version": "2026.7.1",
        },
        "schema": "aragorn/openclaw-protected-plugin-force-reinstall-observation/v1",
    }


try:
    output = main(sys.argv[1:])
    sys.stdout.buffer.write(canonical_json(output) + b"\n")
    if output.get("status") == "SELF_CHECK_ERROR":
        raise SystemExit(1)
except SystemExit:
    raise
except BaseException as exc:  # noqa: BLE001 - failed probes self-describe
    sys.stdout.buffer.write(
        canonical_json(
            {
                "assurance": ASSURANCE,
                "fatal_error": error_record(exc),
                "schema": "aragorn/openclaw-protected-plugin-force-reinstall-error/v1",
            }
        )
        + b"\n"
    )
    raise SystemExit(2)
