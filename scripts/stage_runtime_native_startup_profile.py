"""Stage finite startup capacity and an opt-in accepted-health expiry watchdog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_native_health_profile as health

base = health.base
_SCHEMA = "aragorn/runtime-native-startup-staged-profile/v1"
_AUTHORITY = health._AUTHORITY
_RUNTIME_TREE = health._RUNTIME_TREE
_PREDECESSOR = "scripts/stage_runtime_native_health_profile.py"
_PREDECESSOR_PIN = (
    11717,
    "sha256:df162d2717fab8a5abcf33faf6c0d16e640777024df29d24dbf601e55558f4bf",
)
_ADDED_PINS = {
    "src/aragorn/runtime_health_watchdog.py": (
        11136,
        "sha256:cfa9c0a9f8cc52224f3b84fe4b8d1f4f8b8577d0317e8392778d02f271ea55e5",
    ),
    "packaging/libexec/aragorn-runtime-health-watchdog.py": (
        347,
        "sha256:632056e88d3b8ed3f09462a3c1fac5e97165bb36acadd1804731ef7bd382ecea",
    ),
    "packaging/systemd/aragorn-runtime-health-watchdog.service": (
        1756,
        "sha256:4a17aa69014b5ab14b4f2213bdef2f278f0a7acbc28878dec1e4df4a3bf1a852",
    ),
    "packaging/systemd/aragorn-runtime-health-watchdog.timer": (
        245,
        "sha256:aa70491ff496a1ab1788d47097f7a8d57a51704bcb29e2e09c3c478356ba23f0",
    ),
}
_SOURCE_PINS = {**health._SOURCE_PINS, _PREDECESSOR: _PREDECESSOR_PIN, **_ADDED_PINS}
_WORKER = "packaging/systemd/aragorn-runtime-action-worker.service"
_ACTIVATOR = health._ACTIVATOR
_TASKS_MAX = 8
_ANCHOR = b'require_unit_value "$worker_unit" PrivateNetwork yes\n'
_CHECK = b'require_unit_value "$worker_unit" TasksMax 8\n'
_POST_ANCHOR = b'require_unit_value "$worker_unit" ActiveState active\n'
_POST_CHECK = b'require_unit_value "$worker_unit" EffectiveTasksMax 8\n'


class RuntimeNativeStartupStageError(ValueError):
    """The successor cannot preserve its frozen predecessor and finite limit."""


def _destination(name: str) -> tuple[str, int]:
    if name == "packaging/systemd/aragorn-runtime-health-watchdog.timer":
        return "usr/lib/systemd/system/aragorn-runtime-health-watchdog.timer", 0o644
    return health._destination(name)


def _verified_payloads():
    base.overlay._read_pinned(_PREDECESSOR, *_PREDECESSOR_PIN, root=_ROOT)
    inherited, replacements = health._verified_payloads()
    original = inherited | replacements
    added = {
        _destination(name)[0]: (
            name,
            _destination(name)[1],
            base.overlay._read_pinned(name, *pin, root=_ROOT),
        )
        for name, pin in _ADDED_PINS.items()
    }
    if set(added) & set(original) or len(added) != 4:
        raise RuntimeNativeStartupStageError("watchdog payload inventory changed")
    worker, mode = health._destination(_WORKER)
    source, _, before = original[worker]
    if before.count(b"\nTasksMax=2\n") != 1:
        raise RuntimeNativeStartupStageError("worker task budget anchor changed")
    after = before.replace(b"\nTasksMax=2\n", b"\nTasksMax=8\n")
    activator, activator_mode = health._destination(_ACTIVATOR)
    script = original[activator][2]
    old_digest = base.overlay._digest(before)[7:].encode()
    new_digest = base.overlay._digest(after)[7:].encode()
    if (
        script.count(old_digest) != 1
        or script.count(_ANCHOR) != 1
        or script.count(_POST_ANCHOR) != 1
    ):
        raise RuntimeNativeStartupStageError("activator task budget anchors changed")
    rendered = script.replace(old_digest, new_digest).replace(_ANCHOR, _CHECK + _ANCHOR)
    # EffectiveTasksMax reads the realized cgroup; it is not valid before start.
    rendered = rendered.replace(_POST_ANCHOR, _POST_ANCHOR + _POST_CHECK)
    lines = "".join(
        f"{_destination(name)[1]:o} {pin[1][7:]} /{_destination(name)[0]}\n"
        for name, pin in sorted(_ADDED_PINS.items())
    ).encode("ascii")
    if rendered.count(b"\nEOF\n") != 1:
        raise RuntimeNativeStartupStageError("watchdog pin inventory anchor changed")
    rendered = rendered.replace(b"\nEOF\n", b"\n" + lines + b"EOF\n")
    return original, {
        **added,
        worker: (source, mode, after),
        activator: (_ACTIVATOR, activator_mode, rendered),
    }


def stage_runtime_native_startup_profile(output: Path) -> dict:
    """Keep credential and pre-start checks; allow bounded setup helper tasks."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeNativeStartupStageError("DESTDIR must be absolute and absent")
        parent = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = health.stage_runtime_native_health_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != parent
        ):
            raise RuntimeNativeStartupStageError("startup staging inputs changed")
        return {
            **report,
            "schema": _SCHEMA,
            "worker_tasks_max": _TASKS_MAX,
            "watchdog_timer_enabled": False,
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
                    {row["name"] for row in report["new_dependencies"]}
                    | set(_ADDED_PINS)
                )
            ],
            "missing_inputs": [
                item
                for item in report["missing_inputs"]
                if item
                != "no health detector, expiry timer, durable queue or response delivery guarantee"
            ]
            + [
                "watchdog timer requires explicit opt-in; accepted-health wall-clock expiry only",
                "no sensor heartbeat detector, durable response queue or latency guarantee",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise RuntimeNativeStartupStageError(
            "cannot stage native startup profile"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_native_startup_profile(parser.parse_args().output)
    except RuntimeNativeStartupStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
