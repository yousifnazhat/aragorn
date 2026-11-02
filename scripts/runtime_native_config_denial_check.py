"""One denied skill-disable request in the owned native fixture, not admission."""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_SCHEMA = "aragorn/native-config-denial-observation/v1"
_AUTHORITY = (
    "OWNED_CONFIG_PERSISTENCE_DENIAL_ONLY_NOT_RELOAD_OR_ADMISSION_QUALIFICATION"
)
_PARAMS = {"enabled": False, "skillKey": "template-skill"}
_CLI = ["/usr/local/bin/node", "/runtime/lib/node_modules/openclaw/openclaw.mjs"]
_INFO = ["gateway", "call", "system.info", "--json", "--timeout", "5000"]
_DISCOVERY = ["skills", "info", "template-skill", "--agent", "main", "--json"]
_EXPECTED_DISCOVERY = {
    "skillKey": "template-skill",
    "name": "template-skill",
    "filePath": "/opt/aragorn/runtime-profile/template-skill/SKILL.md",
    "source": "openclaw-extra",
    "disabled": False,
    "eligible": True,
    "blockedByAgentFilter": False,
    "blockedByAllowlist": False,
    "modelVisible": True,
    "commandVisible": True,
}
_UPDATE = [
    "gateway",
    "call",
    "skills.update",
    "--json",
    "--timeout",
    "5000",
    "--params",
    canonical_json(_PARAMS).decode("ascii"),
]
_DENIAL = {
    "error": {
        "code": "UNAVAILABLE",
        "message": "Error: EROFS: read-only file system, open "
        "'/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock': code=EROFS",
        "retryable": False,
        "type": "gateway_request_error",
    },
    "ok": False,
}
_LIMITS = {
    "phase3_eligible": False,
    "run_conformance_eligible": False,
    "production_activation_eligible": False,
    "successful_reload_observed": False,
    "gateway_skill_cache_observed": False,
}


class ConfigDenialError(RuntimeError):
    """Fixed assertions only; never wraps native diagnostics or parse errors."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigDenialError(message)


def validate(value: dict, predecessor: dict) -> None:
    """Replay only bounded joins; this does not authenticate supplied evidence."""
    _expect(
        value["schema"] == _SCHEMA
        and value["authority"] == _AUTHORITY
        and value["status"] == predecessor["status"] == "OBSERVED"
        and value["fixture_container"] == predecessor["fixture_container"]
        and predecessor["phase3_eligible"] is False
        and predecessor["run_conformance_eligible"] is False
        and all(value[key] is False for key in _LIMITS),
        "config denial proof ceiling changed",
    )
    _validate_state(value["before"], value["after"], predecessor)
    commands = value["commands"]
    _expect(
        type(commands) is list and len(commands) == 5, "config command count changed"
    )
    prior_end = 0
    for index, (command, arguments) in enumerate(
        zip(commands, (_INFO, _DISCOVERY, _UPDATE, _DISCOVERY, _INFO), strict=True)
    ):
        start, end = command["started_boottime_ns"], command["completed_boottime_ns"]
        _expect(
            command["argv"] == _CLI + arguments
            and type(command["exit_code"]) is int
            and command["exit_code"] == (1 if index == 2 else 0)
            and type(command["stderr_bytes"]) is int
            and command["stderr_bytes"] == 0
            and type(command["stdout_bytes"]) is int
            and 0 < command["stdout_bytes"] <= 65536
            and type(start) is type(end) is int
            and prior_end < start <= end,
            "config command identity or chronology changed",
        )
        prior_end = end
        expected = (
            _DENIAL
            if index == 2
            else _EXPECTED_DISCOVERY
            if index in (1, 3)
            else {"pid": value["before"]["processes"]["gateway"]["process"]["pid"]}
        )
        _expect(
            canonical_json(command["response"]) == canonical_json(expected),
            "config command response changed",
        )


def _validate_state(before: dict, after: dict, predecessor: dict) -> None:
    _expect(
        canonical_json(before) == canonical_json(after)
        and before["configuration"]["digest"]
        == predecessor["setup"]["configuration_digest"]
        and canonical_json(before["processes"])
        == canonical_json(predecessor["processes"])
        and before["boot_id"] == predecessor["boot_id"]
        and canonical_json(before["receipts"])
        == canonical_json(predecessor["receipt_store_after_create"])
        and before["installed"]["skill_digest"] == predecessor["setup"]["skill_digest"]
        and before["installed"]["denial"] is None
        and before["effects"]["target_digest"]
        == predecessor["effect_proof"]["target_digest"]
        and before["effects"]["receipt_digest"]
        == predecessor["effect_proof"]["receipt_digest"]
        and canonical_digest(before["effects"]["grant_state"]["document"])
        == predecessor["effect_proof"]["grant_state_digest"],
        "config denial changed the native fixture",
    )


def run_after_native(container: str, observation: dict, native: Any) -> dict:
    native.setup_prior._require_fixture(container)
    import runtime_action_worker_openclaw_systemd_probe as p37b

    _expect(observation["fixture_container"] == container, "config predecessor changed")
    response = native.response

    def snapshot() -> dict:
        held = []
        try:
            parent = native.provision._root_directory(p37b._GATEWAY_CONFIG.parent, held)
            source = native.provision._hold_file(
                parent, p37b._GATEWAY_CONFIG.name, 0, 0, 0o400, 65536, held
            )
            config = response.broker._parse_canonical_document(
                source.raw, "config denial"
            )
            configuration = {
                "digest": canonical_digest(config),
                "identity": list(source.identity),
            }
            _expect(
                not os.path.lexists(str(p37b._GATEWAY_CONFIG) + ".lock"),
                "root configuration lock unexpectedly exists",
            )
            native.provision._recheck(held)
        finally:
            native.provision._close(held)
        broker_uid = response._identities()[0]
        effects = p37b._snapshot_effects()
        for name, path in (
            ("target", p37b.lineage._PROTECTED / p37b._TARGET),
            ("receipt", p37b.lineage._RECEIPT),
        ):
            effects[name + "_digest"] = native.prior._digest(
                response._read_regular(path, broker_uid, {0o400})
            )
        return {
            "configuration": configuration,
            "installed": native.setup_prior._installed(
                observation["setup"]["skill_digest"]
            ),
            "processes": native.prior._processes(container),
            "boot_id": native.prior._boot(),
            "receipts": native._snapshot(
                observation["setup"]["provisioning"]["genesis_digest"], 4
            ),
            "effects": effects,
        }

    token = native._fixture_token(p37b)
    environment = {
        "HOME": str(p37b._GATEWAY_HOME),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "OPENCLAW_CONFIG_PATH": str(p37b._GATEWAY_CONFIG),
        "OPENCLAW_STATE_DIR": str(p37b._GATEWAY_STATE),
        "OPENCLAW_GATEWAY_TOKEN": token,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TZ": "UTC",
    }
    before, commands = snapshot(), []
    _validate_state(before, before, observation)
    for index, arguments in enumerate((_INFO, _DISCOVERY, _UPDATE, _DISCOVERY, _INFO)):
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        result = subprocess.run(
            _CLI + arguments,
            cwd=p37b._GATEWAY_WORKSPACE,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=15,
        )
        completed = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _expect(
            result.returncode == (1 if index == 2 else 0)
            and not result.stderr
            and 0 < len(result.stdout) <= 65536,
            "config native command refused",
        )
        # Parse strictly and retain only fixed, validated responses. Never output
        # arbitrary CLI diagnostics, configuration bytes, or fixture credentials.
        parsed = json.loads(
            result.stdout.decode("utf-8"),
            object_pairs_hook=response.broker._reject_duplicate_pairs,
            parse_constant=response.broker._reject_constant,
        )
        projected = (
            {"pid": parsed["pid"]}
            if index in (0, 4)
            else {key: parsed[key] for key in _EXPECTED_DISCOVERY}
            if index in (1, 3)
            else parsed
        )
        expected = (
            _DENIAL
            if index == 2
            else _EXPECTED_DISCOVERY
            if index in (1, 3)
            else {"pid": before["processes"]["gateway"]["process"]["pid"]}
        )
        _expect(
            canonical_json(projected) == canonical_json(expected),
            "config native response changed",
        )
        commands.append(
            {
                "argv": _CLI + arguments,
                "exit_code": result.returncode,
                "stdout_bytes": len(result.stdout),
                "stderr_bytes": 0,
                "started_boottime_ns": started,
                "completed_boottime_ns": completed,
                "response": projected,
            }
        )
    value = {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "status": "OBSERVED",
        "fixture_container": container,
        "before": before,
        "after": snapshot(),
        "commands": commands,
        **_LIMITS,
    }
    validate(value, observation)
    return value
