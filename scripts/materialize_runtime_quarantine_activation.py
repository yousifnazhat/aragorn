"""Render pinned worker startup-unit and activator sources; never install them."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay
from scripts import materialize_runtime_quarantine_services as services

_SCHEMA = "aragorn/runtime-quarantine-activation-overlay/v1"
_AUTHORITY = "PINNED_ACTIVATION_SOURCE_ONLY_NOT_DEPLOYMENT_OR_PHASE3_QUALIFICATION"
_UNIT = "packaging/systemd/aragorn-runtime-action-worker.service"
_ACTIVATOR = "packaging/activate-runtime-action-worker-host.sh"
_SOURCES = {
    _UNIT: (
        2_573,
        "sha256:e4ef9e3f2229d92ed9dd9ee4896646e646d7171ee585ecba5aecdd87dba5e790",
    ),
    _ACTIVATOR: (
        32_271,
        "sha256:dd615a00aacd5f76f52ac60400ea095f9014c2ef29d7793fd3ba35b26ffe3186",
    ),
}
_OUTPUTS = {
    _UNIT: (
        2_750,
        "sha256:4572460c7d54e29f8608fa16c9d97e645c2b32ea233377b5ae38e130461817d7",
    ),
    _ACTIVATOR: (
        34_705,
        "sha256:c01ae51517f7d51428dbbf336eee1cb5213d2e5991ea7b3e7ac9cbc2dec8af8d",
    ),
}
_DEPENDENCIES = {
    **services._DEPENDENCIES,
    "src/aragorn/runtime_skill_startup.py": (
        19_135,
        "sha256:f8cbe88b27d18b676a21cac3101c3ba3eb2b1e04ae7ec75845a5720f0f5197ec",
    ),
    "src/aragorn/runtime_skill_startup_service.py": (
        8_385,
        "sha256:a1a8ebb31cd934cfa62a74622a8861eae0a999e97bf1babf4c3824443abcb033",
    ),
    "packaging/libexec/aragorn-runtime-skill-startup-service.py": (
        346,
        "sha256:6cb66e92136e34e9c478499e0ab1bebc25d4b8341db65c41aead82fbe3d1dffd",
    ),
    "src/aragorn/runtime_response_service.py": (
        40_085,
        "sha256:18289bdb705ab62b3b3568d7eded7d030ba38cf7a07b0450183495599c68e780",
    ),
    "src/aragorn/runtime_quarantine_response.py": (
        12_423,
        "sha256:438733d5b17c135d7991810e6a20833e19008024ea134d937b3c70f5096d6d62",
    ),
    "src/aragorn/runtime_quarantine_service.py": (
        2_877,
        "sha256:205aef5538105b8c1b421959d8811fe818b8792c0f705524faf70b784518fdd8",
    ),
    "packaging/libexec/aragorn-runtime-quarantine-service.py": (
        358,
        "sha256:6f6fb64237518da42aec1def0c9a5d5f41ee666f90844c220ed0de8e7f1a74e7",
    ),
}
_STARTUP_COMMAND = (
    "/usr/bin/python3.12 -I -S -B "
    "/usr/libexec/aragorn/aragorn-runtime-skill-startup-service.py"
)
_CONFIG_DIGEST = "dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
_CREDENTIAL_CHECK = r"""    if [ "$verified_unit" = "$worker_unit" ]; then
        verified_expected="a(ss) 2 \"$verified_name\" \"$verified_source\" \"openclaw-config\" \"$gateway_config\""
        verified_reverse="a(ss) 2 \"openclaw-config\" \"$gateway_config\" \"$verified_name\" \"$verified_source\""
        case "$verified_credentials" in
            "$verified_expected"|"$verified_reverse") ;;
            *) fail_activation "effective LoadCredential is unsafe for $verified_unit" ;;
        esac
    elif [ "$verified_credentials" != "a(ss) 1 \"$verified_name\" \"$verified_source\"" ]; then
        fail_activation "effective LoadCredential is unsafe for $verified_unit"
    fi"""
_STARTUP_CHECK = r"""verify_worker_startup()
{
    startup_command="STARTUP_COMMAND"
    startup_exec=$(unit_property "$worker_unit" ExecStartPre)
    startup_prefix="{ path=/usr/bin/python3.12 ; argv[]=$startup_command ; ignore_errors=no ; "
    case "$startup_exec" in
        "$startup_prefix"*) ;;
        *) fail_activation "effective ExecStartPre is unsafe for $worker_unit" ;;
    esac
    startup_tail=${startup_exec#"$startup_prefix"}
    case "$startup_tail" in
        *"argv[]="*|*"ignore_errors="*)
            fail_activation "multiple effective ExecStartPre commands exist for $worker_unit"
            ;;
    esac
    require_unit_value "$worker_unit" LimitNOFILE 128
    require_unit_value "$worker_unit" LimitNOFILESoft 128
}

""".replace("STARTUP_COMMAND", _STARTUP_COMMAND)


class RuntimeQuarantineActivationError(ValueError):
    """Pinned activation inputs, replacements, or publication failed."""


def _replace(raw: bytes, old: str, new: str) -> bytes:
    before = old.encode("ascii")
    if raw.count(before) != 1:
        raise RuntimeQuarantineActivationError("activation replacement shape changed")
    return raw.replace(before, new.encode("ascii"))


def _render(unit: bytes, activator: bytes) -> dict[str, bytes]:
    unit = _replace(
        unit,
        "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\n",
        "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\n"
        "LoadCredential=openclaw-config:/etc/aragorn/agent-gateway/openclaw.json\n"
        f"ExecStartPre={_STARTUP_COMMAND}\n",
    )
    # ponytail: the bounded 64-entry snapshot holds FDs until its final recheck.
    unit = _replace(unit, "LimitNOFILE=64\n", "LimitNOFILE=128\n")
    activator = _replace(activator, _SOURCES[_UNIT][1][7:], overlay._digest(unit)[7:])
    activator = _replace(
        activator,
        "b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
        _CONFIG_DIGEST,
    )
    for _, source_digest, _, rendered_digest in services._SERVICES.values():
        activator = _replace(activator, source_digest[7:], rendered_digest[7:])
    dependency_pins = []
    for name, (_, digest) in _DEPENDENCIES.items():
        if name.startswith("src/aragorn/"):
            path, mode = "/usr/lib/aragorn/aragorn/" + Path(name).name, "644"
        else:
            path, mode = "/usr/libexec/aragorn/" + Path(name).name, "755"
        dependency_pins.append(f"{mode} {digest[7:]} {path}\n")
    activator = _replace(
        activator, "\nEOF\n", "\n" + "".join(dependency_pins) + "EOF\n"
    )
    activator = _replace(
        activator,
        r"""    if [ "$verified_credentials" != "a(ss) 1 \"$verified_name\" \"$verified_source\"" ]; then
        fail_activation "effective LoadCredential is unsafe for $verified_unit"
    fi""",
        _CREDENTIAL_CHECK,
    )
    activator = _replace(
        activator, "verify_process()\n", _STARTUP_CHECK + "verify_process()\n"
    )
    activator = _replace(
        activator,
        'require_unit_value "$worker_unit" PrivateNetwork yes\n',
        'verify_worker_startup\nrequire_unit_value "$worker_unit" PrivateNetwork yes\n',
    )
    return {_UNIT: unit, _ACTIVATOR: activator}


def materialize_runtime_quarantine_activation(output: Path) -> dict[str, Any]:
    """Write two flat, read-only sources with explicit installed destinations.

    This successor starts from tracked worker packaging, not the distinct
    retained V3 installed profile. The base installers must run before overrides.
    No installer, systemctl, build, activation, or source pin is executed/updated.
    A partial write may leave output; it never returns a success manifest.
    """
    try:
        if not isinstance(output, Path) or output.exists() or output.is_symlink():
            raise RuntimeQuarantineActivationError("output must be a new Path")
        inputs = {
            name: overlay._read_pinned(name, size, digest, root=_ROOT)
            for name, (size, digest) in _SOURCES.items()
        }
        for name, (size, digest) in _DEPENDENCIES.items():
            overlay._read_pinned(name, size, digest, root=_ROOT)
        for name, (
            size,
            digest,
            output_size,
            output_digest,
        ) in services._SERVICES.items():
            raw = services._transform(
                overlay._read_pinned(name, size, digest, root=_ROOT)
            )
            if (len(raw), overlay._digest(raw)) != (output_size, output_digest):
                raise RuntimeQuarantineActivationError("runtime service output changed")
        rendered = _render(inputs[_UNIT], inputs[_ACTIVATOR])
        for name, raw in rendered.items():
            if (len(raw), overlay._digest(raw)) != _OUTPUTS[name]:
                raise RuntimeQuarantineActivationError(
                    f"activation output changed: {name}"
                )
        overlay._write_overlay(
            output, {Path(name).name: raw for name, raw in rendered.items()}, ()
        )
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {
                    "name": Path(name).name,
                    "source_name": name,
                    "source_bytes": _SOURCES[name][0],
                    "source_digest": _SOURCES[name][1],
                    "bytes": len(raw),
                    "digest": _OUTPUTS[name][1],
                    "installed_path": (
                        "/usr/lib/systemd/system/"
                        if name == _UNIT
                        else "/usr/libexec/aragorn/"
                    )
                    + Path(name).name,
                    "installed_mode": "0644" if name == _UNIT else "0755",
                }
                for name, raw in rendered.items()
            ],
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _DEPENDENCIES.items()
            ],
            "required_runtime_overrides_not_included": [
                {"name": name, "bytes": values[2], "digest": values[3]}
                for name, values in services._SERVICES.items()
            ],
            "gateway_config_digest": "sha256:" + _CONFIG_DIGEST,
            "standalone_executable": False,
            "production_activation_eligible": False,
            "runtime_startup_enforcement": False,
            "missing_release_inputs": [
                "complete package, frozen base installation, then source overrides and dependencies",
                "fresh successor deployment identity and real systemd credential/startup validation",
                "quarantine response deployment, isolated campaign, and independent qualification",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeQuarantineActivationError(
            f"cannot materialize activation: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_quarantine_activation(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
