"""Stage fixed gateway discovery seals without activating any service."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_native_startup_profile as startup

base = startup.base
_SCHEMA = "aragorn/runtime-native-admission-staged-profile/v1"
_AUTHORITY = "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_OR_ADMISSION_AUTHORITY"
_PREDECESSOR = "scripts/stage_runtime_native_startup_profile.py"
_PREDECESSOR_PIN = (
    8299,
    "sha256:5da4968e024cdff144d445dfd694ea8b7697f6af871b34fc1e13e71391364d16",
)
_SOURCE_PINS = {**startup._SOURCE_PINS, _PREDECESSOR: _PREDECESSOR_PIN}
_RUNTIME_TREE = startup._RUNTIME_TREE
_GATEWAY = "packaging/systemd/aragorn-agent-gateway.service"
_ACTIVATOR = startup._ACTIVATOR
_DISCOVERY_READ_ONLY_PATHS = (
    "/var/lib/aragorn-agent-gateway/state/skills",
    "/var/lib/aragorn-agent-gateway/state/plugin-skills",
    "/var/lib/aragorn-agent-gateway/workspace/skills",
    "/var/lib/aragorn-agent-gateway/workspace/.agents",
    "/var/lib/aragorn-agent-gateway/home/.agents",
)
_UNIT_ANCHOR = b"ReadWritePaths=/var/lib/aragorn-agent-gateway\n"
_UNIT_SEALS = b"".join(
    f"ReadOnlyPaths={path}\n".encode("ascii") for path in _DISCOVERY_READ_ONLY_PATHS
)
_DIRECTORY_ANCHOR = b"\nunit_property()\n"
# The predecessor has already stopped all four services and validated gateway_root
# and its home/state/workspace children. Validate each parent before its child;
# never chmod/chown existing state or follow a substituted .agents symlink.
_DIRECTORIES = b"""
# Fixed native admission discovery roots; absent-only provisioning while stopped.
for directory in state/skills state/plugin-skills workspace/skills workspace/.agents workspace/.agents/skills home/.agents home/.agents/skills
do
    path=$gateway_root/$directory
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        install -d -o "$gateway_uid" -g "$gateway_gid" -m 0700 "$path"
    fi
    require_exact_directory "$path" "$gateway_uid" "$gateway_gid" 700
done
"""
_CHECK_ANCHOR = b'require_unit_value "$gateway_unit" PrivateNetwork no\n'
_CHECKS = b"".join(
    f'require_unit_member "$gateway_unit" ReadOnlyPaths "{path}"\n'.encode("ascii")
    for path in _DISCOVERY_READ_ONLY_PATHS
)


class RuntimeNativeAdmissionStageError(ValueError):
    """The successor cannot preserve the predecessor and fixed discovery seals."""


def _destination(name: str) -> tuple[str, int]:
    return startup._destination(name)


def _verified_payloads():
    base.overlay._read_pinned(_PREDECESSOR, *_PREDECESSOR_PIN, root=_ROOT)
    inherited, replacements = startup._verified_payloads()
    original = inherited | replacements
    gateway, gateway_mode = _destination(_GATEWAY)
    before = original[gateway][2]
    if before.count(_UNIT_ANCHOR) != 1 or any(
        line in before for line in _UNIT_SEALS.splitlines()
    ):
        raise RuntimeNativeAdmissionStageError("gateway discovery seal anchor changed")
    after = before.replace(_UNIT_ANCHOR, _UNIT_ANCHOR + _UNIT_SEALS)
    activator, activator_mode = _destination(_ACTIVATOR)
    script = original[activator][2]
    old_digest = base.overlay._digest(before)[7:].encode("ascii")
    new_digest = base.overlay._digest(after)[7:].encode("ascii")
    if (
        script.count(old_digest) != 1
        or script.count(_DIRECTORY_ANCHOR) != 1
        or script.count(_CHECK_ANCHOR) != 1
        or _DIRECTORIES in script
        or _CHECKS in script
    ):
        raise RuntimeNativeAdmissionStageError(
            "activator discovery seal anchors changed"
        )
    rendered = (
        script.replace(old_digest, new_digest)
        .replace(_DIRECTORY_ANCHOR, _DIRECTORIES + _DIRECTORY_ANCHOR)
        .replace(_CHECK_ANCHOR, _CHECKS + _CHECK_ANCHOR)
    )
    if len(original) != 70 or len(base._directories(original)) != 16:
        raise RuntimeNativeAdmissionStageError("native admission inventory changed")
    return original, {
        gateway: (_GATEWAY, gateway_mode, after),
        activator: (_ACTIVATOR, activator_mode, rendered),
    }


def stage_runtime_native_admission_profile(output: Path) -> dict:
    """Render only two successor files; retain all frozen sources and proof limits."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeNativeAdmissionStageError(
                "DESTDIR must be absolute and absent"
            )
        parent = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = startup.stage_runtime_native_startup_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != parent
        ):
            raise RuntimeNativeAdmissionStageError("admission staging inputs changed")
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "discovery_read_only_paths": list(_DISCOVERY_READ_ONLY_PATHS),
            "admission_qualified": False,
            "files": [
                {
                    "path": "/" + name,
                    "source_name": source,
                    "bytes": len(raw),
                    "digest": base.overlay._digest(raw),
                    "mode": f"{mode:04o}",
                }
                for name, (source, mode, raw) in sorted(final.items())
            ],
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in sorted(_SOURCE_PINS.items())
            ],
            "new_dependencies": [
                {
                    "name": name,
                    "bytes": len(final[_destination(name)[0]][2]),
                    "digest": base.overlay._digest(final[_destination(name)[0]][2]),
                }
                for name in sorted(
                    {row["name"] for row in report["new_dependencies"]} | {_GATEWAY}
                )
            ],
            "missing_inputs": report["missing_inputs"]
            + [
                "new gateway/activator identities require common provisioning and dispatcher integration",
                "no observed gateway mount seals, direct-write outcome or admission qualification",
                "read-only namespace seals do not protect against privileged host mount replacement",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise RuntimeNativeAdmissionStageError(
            "cannot stage native admission profile"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_native_admission_profile(parser.parse_args().output)
    except RuntimeNativeAdmissionStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
