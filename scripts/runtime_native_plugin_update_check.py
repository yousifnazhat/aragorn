"""Owned native fixture for the tracked, offline marketplace update branch only."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

if __package__:
    from scripts import runtime_native_plugin_package_check as prior
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import runtime_native_plugin_package_check as prior

_SCHEMA = "aragorn/runtime-native-plugin-update-observation/v1"
_AUTHORITY = "OWNED_LOCAL_MARKETPLACE_UPDATE_DENIAL_NOT_ROUTE_OR_RUN_QUALIFICATION"
_ROUTE = "ADM-02/update/plugin-package-skill-replacement"
_STAGED = Path("/opt/aragorn/native-plugin-update-input")
_PROBE = "protected-plugin-marketplace-update-probe.py"
_BUNDLE = {
    "adapter/protected-plugin-force-reinstall-v3-probe.py": (
        30362,
        "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
    ),
    "adapter/protected-plugin-marketplace-update-probe.py": (
        14622,
        "sha256:4396ab676084c72ea54c010f063104d9b12b37c78d72a1eaafd1a9130eb1a6f4",
    ),
    "adapter/protected-plugin-package-skill-replacement-probe.py": (
        26494,
        "sha256:d4e7c4bc2408045aab6702a8e2877916241ad372d917aaf8d5e62a289caf5a4e",
    ),
    "adapter/seed-plugin-marketplace-update-record.mjs": (
        2260,
        "sha256:8c7fc9c1dae8be9ad7688252408905ed223a8200f0a9373994afaa0906db2840",
    ),
    "baseline-source/SKILL.md": (
        154,
        "sha256:6ff97ef11eb3fc88c13c6b341d565d374acc69f189b259e6e2711a25ccaf66aa",
    ),
    "baseline-source/index.js": (
        127,
        "sha256:39b9c5a247cbca515a569ca05443659ecf81ca6e65966a56d16813af59d8cc98",
    ),
    "baseline-source/openclaw.plugin.json": (
        206,
        "sha256:684957a5344e298c60d3cad7738decfdb3f2f113d8baa43a64bcb183c68fd298",
    ),
    "baseline-source/package.json": (
        142,
        "sha256:af969eb26e6dc284438a23d9df01fbc1b72343beea4ce4cd69f0db308499f95e",
    ),
    "candidate-source/SKILL.md": (
        155,
        "sha256:1406a1294ff93c5bf35134236976446d3ee0585f19453274f84ec661292d2b6c",
    ),
    "candidate-source/index.js": (
        127,
        "sha256:39b9c5a247cbca515a569ca05443659ecf81ca6e65966a56d16813af59d8cc98",
    ),
    "candidate-source/openclaw.plugin.json": (
        206,
        "sha256:cb0a827d40f125ab2e8ba53f16318d011e3498db216999db89d4cbdf23aee8a6",
    ),
    "candidate-source/package.json": (
        142,
        "sha256:89bb2b1604d947de725c29e738dd5a9bd392ca7479dedce27da1d5fb6a16e652",
    ),
    "marketplace.json": (
        155,
        "sha256:0f054e4ebdb8bd2b732df21c426c817afbcd804ead9ad4c96b08d7f13da00ec1",
    ),
}
_CHECKS = {
    "identity",
    "sources",
    "prerequisites",
    "tracked_record",
    "update_command",
    "policy_denial",
    "protected_boundary",
    "sqlite_custody",
}
_REASONS = {
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
_HELPER_PIN = "sha256:d7b2cc380f25844ded16d471cf0044016623709aa9085e4232d01f46b7bb9df9"


def _decode_diagnostic(raw: bytes, token: str | None):
    prior._expect(
        len(raw) <= 4096
        and (
            token is None or (type(token) is str and token.encode("ascii") not in raw)
        ),
        "update diagnostic unsafe",
    )
    value = json.loads(
        raw, object_pairs_hook=prior._unique_pairs, parse_constant=prior._deny_constant
    )
    prior._expect(
        type(value) is dict
        and set(value) == {"schema", "reason", "checks", "exit_codes"}
        and value["schema"] == "aragorn/native-plugin-update-diagnostic/v1"
        and type(value["reason"]) is str
        and value["reason"] in _REASONS
        and type(value["checks"]) is dict
        and set(value["checks"]) == _CHECKS
        and all(type(item) is bool for item in value["checks"].values())
        and type(value["exit_codes"]) is list
        and len(value["exit_codes"]) == 8
        and all(
            item is None or (type(item) is int and -255 <= item <= 255)
            for item in value["exit_codes"]
        )
        and raw
        == json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n",
        "update diagnostic schema refused",
    )
    return value


def _seed(p37b):
    baseline = _seed_baseline(p37b)
    raw = p37b._GATEWAY_CONFIG.read_bytes()
    document = json.loads(raw)
    canonical = json.dumps(
        document, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    prior._expect(
        prior._digest(canonical)
        == "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
        "seed config identity changed",
    )
    argv = [
        "/usr/bin/setpriv",
        "--reuid=992",
        "--regid=992",
        "--groups=992",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "/usr/local/bin/node",
        str(prior._INPUT / "adapter/seed-plugin-marketplace-update-record.mjs"),
    ]
    environment = {
        "HOME": str(p37b._GATEWAY_HOME),
        "OPENCLAW_STATE_DIR": str(p37b._GATEWAY_STATE),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
    }
    result = subprocess.run(
        argv,
        input=canonical,
        capture_output=True,
        check=False,
        timeout=45,
        cwd=str(p37b._GATEWAY_WORKSPACE),
        env=environment,
    )
    prior._expect(
        result.returncode == 0
        and result.stdout == b"ARAGORN_OWNED_MARKETPLACE_RECORD_SEEDED\n"
        and not result.stderr,
        "fixed tracked-record bootstrap refused",
    )
    return {
        **baseline,
        "tracked_record_seed": {
            "api": "writePersistedInstalledPluginIndexInstallRecords",
            "module_digest": "sha256:5500445dcd66876952758eec91019a3c4dcc4a852498f956022828f0f867d21f",
            "exit_code": 0,
            "before_activation": True,
            "configuration_changed": False,
        },
    }


_seed_baseline = prior._seed_baseline


def _invoke(p37b, gateway_pid, token):
    prior._expect(
        type(gateway_pid) is int
        and gateway_pid > 0
        and re.fullmatch(r"[0-9a-f]{64}", token) is not None,
        "update invocation identity changed",
    )
    argv = [
        "/usr/bin/nsenter",
        "--target",
        str(gateway_pid),
        "--mount",
        "--",
        "/usr/bin/setpriv",
        "--reuid=992",
        "--regid=992",
        "--groups=992",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        str(prior._INPUT / "adapter" / _PROBE),
    ]
    environment = {
        "HOME": str(p37b._GATEWAY_HOME),
        "ARAGORN_GATEWAY_PID": str(gateway_pid),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "OPENCLAW_CONFIG_PATH": "/run/credentials/aragorn-agent-gateway.service/openclaw-config",
        "OPENCLAW_STATE_DIR": str(p37b._GATEWAY_STATE),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TZ": "UTC",
        "OPENCLAW_GATEWAY_TOKEN": token,
    }
    result = subprocess.run(
        argv,
        cwd=str(p37b._GATEWAY_WORKSPACE),
        env=environment,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if result.returncode == 126 and not result.stderr:
        diagnostic = _decode_diagnostic(result.stdout, token)
        failure = prior.PluginFixtureError("adapter " + diagnostic["reason"])
        failure.add_note(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")))
        raise failure
    prior._expect(
        result.returncode == 0
        and len(result.stdout) <= 2 * 1024 * 1024
        and not result.stderr
        and token.encode("ascii") not in result.stdout,
        "fixed update adapter refused or output unsafe",
    )
    value = json.loads(
        result.stdout,
        object_pairs_hook=prior._unique_pairs,
        parse_constant=prior._deny_constant,
    )
    prior._expect(
        result.stdout
        == json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
        and value["schema"] == "aragorn/native-plugin-marketplace-update-denial/v1"
        and value["authority"]
        == "FIXED_OWNED_UPDATE_BRANCH_OBSERVATION_NOT_ROUTE_OR_PHASE3_QUALIFICATION"
        and value["route_id"] == _ROUTE
        and value["branch"] == "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
        and value["status"] == "OBSERVED"
        and value["plugin_update_lifecycle_executed"] is True
        and value["inventory_route_coverage"] is False
        and value["route_qualified"] is False
        and value["implementation_digest"] == _BUNDLE["adapter/" + _PROBE][1]
        and value["decision"]
        and all(item is False for item in value["decision"].values()),
        "update observation or proof ceiling changed",
    )
    return {
        "document": value,
        "execution": {
            "argv": argv,
            "exit_code": 0,
            "effective_identity": {"uid": 992, "gid": 992, "groups": [992]},
            "environment_names": sorted(environment),
            "stdout_bytes": len(result.stdout),
            "stdout_digest": prior._digest(result.stdout),
            "stderr_bytes": 0,
        },
    }


def _run(container, copied_owner):
    prior._expect(
        prior._digest(Path(prior.__file__).read_bytes()) == _HELPER_PIN
        and len(_BUNDLE) == 13,
        "fixture helper or bundle inventory changed",
    )
    with patch.multiple(
        prior,
        _BUNDLE=_BUNDLE,
        _STAGED=_STAGED,
        _PROBE=_PROBE,
        _ROUTE=_ROUTE,
        _SCHEMA=_SCHEMA,
        _AUTHORITY=_AUTHORITY,
        _seed_baseline=_seed,
        _invoke=_invoke,
    ):
        value = prior._run(container, copied_owner)
    value["plugin_update"] = value.pop("plugin_package")
    value["branch"] = "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
    value["route_qualified"] = False
    return value


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if (
        len(args) != 3
        or re.fullmatch(r"[0-9a-f]{64}", args[0]) is None
        or any(re.fullmatch(r"[0-9]{1,10}", value) is None for value in args[1:])
    ):
        return 64
    try:
        print(
            json.dumps(
                _run(args[0], tuple(map(int, args[1:]))),
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - never forward unbounded native diagnostics
        detail = (
            str(exc) if type(exc) is prior.PluginFixtureError else type(exc).__name__
        )
        print(
            "native plugin update fixture refused: " + prior._PHASE + ": " + detail,
            file=sys.stderr,
        )
        if type(exc) is prior.PluginFixtureError:
            for note in getattr(exc, "__notes__", ())[:1]:
                print(note, file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
