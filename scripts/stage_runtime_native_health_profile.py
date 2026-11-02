"""Stage accepted-health response sources after the fixed native receipt profile."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_native_receipt_profile as native

base = native.base
_SCHEMA = "aragorn/runtime-native-health-staged-profile/v1"
_AUTHORITY = (
    "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_HEALTH_DISPATCH_DEPLOYMENT_OR_RUN_AUTHORITY"
)
_RUNTIME_TREE = dict(native._RUNTIME_TREE)
_ACTIVATOR = native._ACTIVATOR
_PREDECESSOR = "scripts/stage_runtime_native_receipt_profile.py"
_PREDECESSOR_PIN = (
    18870,
    "sha256:ee01af6bbc9a3693e94e512b8615422093bcdca5bf21cf1291d1f616e7f3cf33",
)
_HOOK = "packaging/systemd/50-runtime-health-response.conf"
_ADDED_PINS = {
    "src/aragorn/runtime_health_service.py": (
        3381,
        "sha256:1518e5afa3450d88b878f27baa79e670e0fd48decc5719ecf249e7a351343817",
    ),
    "packaging/libexec/aragorn-runtime-health-service.py": (
        350,
        "sha256:d9801ec5532735c20ff5ff46e320a9192e847f64cb70a2bec2db4292467c7ae7",
    ),
    "packaging/libexec/aragorn-runtime-response-service.py": (
        349,
        "sha256:69e7eb1b13901e6d700799e473ae5bbfef1a17b2f7cc257559a66d2b0064c35c",
    ),
    "packaging/systemd/aragorn-runtime-health-publisher.service": (
        1822,
        "sha256:c52a88c5c95b39b51e017d8fc76f177a9f99f433aa33365164e6220acab11893",
    ),
    "packaging/systemd/aragorn-runtime-health-response.service": (
        2049,
        "sha256:b165c021537b14be356ec67396fc359844474f65b1406239e5863029e6ed730f",
    ),
    _HOOK: (
        79,
        "sha256:0de3ae4657861631e8479d1cab194de46d84a18283b1a2c1eb2272bb1d3d505a",
    ),
}
_SOURCE_PINS = {
    **native._SOURCE_PINS,
    **_ADDED_PINS,
    _PREDECESSOR: _PREDECESSOR_PIN,
}
_ACTIVATOR_PIN = (
    39602,
    "sha256:d22a9fbce56a5fa13ea5f2605b5ff89c16ba12e83402f6b97367b57a3099edce",
)
_NEW_DIRECTORIES = (
    "usr/share",
    "usr/share/aragorn",
    "usr/share/aragorn/systemd",
)
_ANCHOR = b"\nEOF\n"


class RuntimeNativeHealthStageError(ValueError):
    """The bounded successor did not produce an exact, verified staging tree."""


def _destination(name: str) -> tuple[str, int]:
    if name == _HOOK:
        return "usr/share/aragorn/systemd/50-runtime-health-response.conf", 0o644
    return native._destination(name)


def _added_lines() -> bytes:
    return "".join(
        f"{_destination(name)[1]:o} {pin[1][7:]} /{_destination(name)[0]}\n"
        for name, pin in sorted(_ADDED_PINS.items())
    ).encode("ascii")


def _render_activator(raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != native._ACTIVATOR_PIN:
        raise RuntimeNativeHealthStageError("native activator input changed")
    if raw.count(_ANCHOR) != 1:
        raise RuntimeNativeHealthStageError("native pin inventory anchor changed")
    lines = _added_lines()
    if len(lines.splitlines()) != 6 or any(
        line in raw for line in lines.splitlines(keepends=True)
    ):
        raise RuntimeNativeHealthStageError("health pin inventory already exists")
    after = b"\n" + lines + b"EOF\n"
    rendered = raw.replace(_ANCHOR, after)
    if (
        rendered.count(after) != 1
        or rendered.replace(after, _ANCHOR) != raw
        or (len(rendered), base.overlay._digest(rendered)) != _ACTIVATOR_PIN
    ):
        raise RuntimeNativeHealthStageError("health activator changed other bytes")
    return rendered


def _verified_payloads() -> tuple[dict[str, base._Payload], dict[str, base._Payload]]:
    if (
        native._ROOT != _ROOT
        or base._ROOT != _ROOT
        or len(native._SOURCE_PINS) != 72
        or len(_ADDED_PINS) != 6
        or set(_ADDED_PINS) & set(native._SOURCE_PINS)
        or _PREDECESSOR in native._SOURCE_PINS
        or len(_SOURCE_PINS) != len(native._SOURCE_PINS) + len(_ADDED_PINS) + 1
        or len(_SOURCE_PINS) != 79
        or _RUNTIME_TREE != native._RUNTIME_TREE
    ):
        raise RuntimeNativeHealthStageError("health source inventory changed")
    inputs = {
        name: base.overlay._read_pinned(name, *pin, root=_ROOT)
        for name, pin in _SOURCE_PINS.items()
    }
    inherited, replacements = native._verified_payloads()
    original = inherited | replacements
    added = {
        _destination(name)[0]: (name, _destination(name)[1], inputs[name])
        for name in _ADDED_PINS
    }
    if set(added) & set(original):
        raise RuntimeNativeHealthStageError("health payload overlaps native files")
    destination, mode = _destination(_ACTIVATOR)
    added[destination] = (
        _ACTIVATOR,
        mode,
        _render_activator(original[destination][2]),
    )
    final = original | added
    if (
        len(original) != 60
        or len(added) != 7
        or len(final) != 66
        or len(base._directories(final)) != 16
        or base._directories(final) - base._directories(original)
        != set(_NEW_DIRECTORIES)
    ):
        raise RuntimeNativeHealthStageError("health staged inventory changed")
    return original, added


def _add_directories(output: Path) -> None:
    # Three fixed additions only. Keep every ancestor descriptor until all new
    # directories are synced and their named identities have been rechecked.
    parent = output / "usr"
    before = base._parent_custody(parent)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(parent, flags)
    held = [(None, parent, fd, before)]
    try:
        for relative in _NEW_DIRECTORIES:
            current = base._parent_custody(parent)
            if base.overlay._identity(os.fstat(fd))[:5] != current or current != before:
                raise RuntimeNativeHealthStageError("health directory parent changed")
            name = Path(relative).name
            os.mkdir(name, mode=0o755, dir_fd=fd)
            child = os.open(name, flags, dir_fd=fd)
            held.append((fd, name, child, None))
            os.fchmod(child, 0o755)
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o755
                or os.listdir(child)
                or base.overlay._identity(metadata)
                != base.overlay._identity(
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                )
                or base._parent_custody(parent) != before
            ):
                raise RuntimeNativeHealthStageError("health directory custody changed")
            before = base.overlay._identity(metadata)[:5]
            held[-1] = (fd, name, child, before)
            fd, parent = child, output / relative
        for parent_fd, name, descriptor, identity in reversed(held):
            metadata = os.fstat(descriptor)
            if base.overlay._identity(metadata)[
                :5
            ] != identity or base.overlay._identity(metadata) != base.overlay._identity(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            ):
                raise RuntimeNativeHealthStageError(
                    "health directory changed after creation"
                )
            os.fsync(descriptor)
    finally:
        failure = None
        for _, _, descriptor, _ in reversed(held):
            try:
                os.close(descriptor)
            except OSError as exc:
                failure = failure or exc
        if failure is not None:
            raise RuntimeNativeHealthStageError(
                "health directory cleanup failed"
            ) from failure


def stage_runtime_native_health_profile(output: Path) -> dict[str, Any]:
    """Stage pinned sources only; failure may leave an unusable partial DESTDIR."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeNativeHealthStageError(
                "DESTDIR must be an absolute absent Path"
            )
        parent = base._parent_custody(output.parent)
        original, additions = _verified_payloads()
        report = native.stage_runtime_native_receipt_profile(output)
        if (
            base._parent_custody(output.parent) != parent
            or report["schema"] != native._SCHEMA
            or len(report["files"]) != 60
            or len(report["source_inputs"]) != 72
            or len(report["new_dependencies"]) != 15
        ):
            raise RuntimeNativeHealthStageError("native predecessor staging changed")
        base._audit_tree(output, original)
        _add_directories(output)
        base._apply_overrides(output, additions)
        final = original | additions
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, additions)
            or base._parent_custody(output.parent) != parent
        ):
            raise RuntimeNativeHealthStageError("health staging inputs changed")
        names = {item["name"] for item in report["new_dependencies"]} | set(_ADDED_PINS)
        if len(names) != 21:
            raise RuntimeNativeHealthStageError("health dependency inventory changed")
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
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
            "directories": ["/" + name for name in sorted(base._directories(final))],
            "new_dependencies": [
                {
                    "name": name,
                    "bytes": len(final[_destination(name)[0]][2]),
                    "digest": base.overlay._digest(final[_destination(name)[0]][2]),
                }
                for name in sorted(names)
            ],
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in sorted(_SOURCE_PINS.items())
            ],
            "health_publication_performed": False,
            "health_dispatch_enabled": False,
            "accepted_unhealthy_response_verified": False,
            "sensor_loss_detection": False,
            "missing_inputs": [
                *report["missing_inputs"],
                "separate root-owned health credential provisioning and explicit hook opt-in",
                "effective health unit/credential custody and accepted-unhealthy dispatch verification",
                "no health detector, expiry timer, durable queue or response delivery guarantee",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise RuntimeNativeHealthStageError(
            "cannot stage native health profile"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_native_health_profile(parser.parse_args().output)
    except RuntimeNativeHealthStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
