"""Stage the fixed 74-file worker-ingress successor, never activate it.

The rendered activator alone owns absent-only ingress-directory provisioning.
Staging neither touches that live path nor establishes runtime measurement.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_phase3_common_profile as predecessor
from scripts import materialize_runtime_worker_ingress_measurement as renderer

base = predecessor.base
_PARENT = "scripts/stage_runtime_phase3_common_profile.py"
_RENDERER = "scripts/materialize_runtime_worker_ingress_measurement.py"
_SOURCE_PINS = {
    _PARENT: (
        7248,
        "sha256:576d2572dfc8a4fb8bd6fab8e14929b2de18150db8e19eb16a7d2b4d8695bebf",
    ),
    _RENDERER: (
        14363,
        "sha256:91d65053a6590fe773eaac21db65b0ccbb3a26aff5a35259e8559556b8afe5cc",
    ),
    **renderer._DEPENDENCIES,
}
_WORKER = renderer._WORKER
_HELPER = renderer._HELPER
_UNIT = "packaging/systemd/aragorn-runtime-action-worker.service"
_ACTIVATOR = predecessor.admission._ACTIVATOR
_MEASUREMENT_ROOT = "/var/lib/aragorn-runtime-worker-measurement"
_SCHEMA = "aragorn/runtime-phase3-ingress-staged-profile/v1"
_AUTHORITY = "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_OR_PHASE3_AUTHORITY"
_OUTPUTS = {
    _WORKER: renderer._OUTPUT,
    _HELPER: renderer._DEPENDENCIES[_HELPER],
    _UNIT: (
        3084,
        "sha256:eddb82f4fa51e5211a6c19ae52f1e29cd7eb9e9b791adffc94f23ff01f0f7053",
    ),
    _ACTIVATOR: (
        46670,
        "sha256:167de84ec8cce52cd185e3f947d6a69983b6fb923be5c8bc92f167b219c5dabf",
    ),
}
_UNIT_ANCHOR = b"StateDirectoryMode=0700\n"
_UNIT_WRITE_PATH = (
    b"# Ingress custody is provisioned absent-only, never managed by StateDirectory.\n"
    b"ReadWritePaths=/var/lib/aragorn-runtime-worker-measurement\n"
)
_ACTIVATION_ANCHOR = b'ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"\n'
_LOADED_CHECKS = b"""# Ingress must not become a systemd-managed/chowned state directory.
require_unit_value "$worker_unit" StateDirectory aragorn-runtime-tool-receipts
require_unit_value "$worker_unit" StateDirectoryMode 0700
require_unit_value "$worker_unit" ReadWritePaths /var/lib/aragorn-runtime-worker-measurement
require_unit_value "$worker_unit" DynamicUser no
require_unit_value "$worker_unit" ProtectSystem strict
require_unit_value "$worker_unit" Restart no
"""

# Fixed root/leaf paths, no caller-selected path, helper import, repair or erase.
# The directory itself is an absent-only claim: even an empty previous directory
# refuses activation. A failed creation/chown/sync never rolls that claim back.
_PROVISION_PY = """import os
import stat
import sys

def require(value):
    if not value:
        raise SystemExit("worker ingress directory custody refused")

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

def root_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) & 0o022 == 0)

def empty(descriptor):
    with os.scandir(descriptor) as entries:
        return next(entries, None) is None

require(os.geteuid() == os.getegid() == 0 and len(sys.argv) == 3)
uid, gid = int(sys.argv[1]), int(sys.argv[2])
require(0 < uid < 2**32 and 0 < gid < 2**32)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
held = []
ancestry = []
failure = None
try:
    parent = os.open("/", flags)
    held.append(parent)
    root = os.fstat(parent)
    root_directory(root)
    require(identity(root) == identity(os.lstat("/")))
    for name in ("var", "lib"):
        child = os.open(name, flags, dir_fd=parent)
        held.append(child)
        info = os.fstat(child)
        root_directory(info)
        require(identity(info) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        ancestry.append((parent, name, child, identity(info)))
        parent = child
    leaf = "aragorn-runtime-worker-measurement"
    os.umask(0o077)
    # No exist_ok, parent creation, pre-existing empty directory, or retry.
    os.mkdir(leaf, 0o700, dir_fd=parent)
    os.fsync(parent)
    descriptor = os.open(leaf, flags, dir_fd=parent)
    held.append(descriptor)
    created = os.fstat(descriptor)
    require(stat.S_ISDIR(created.st_mode) and created.st_uid == created.st_gid == 0
            and stat.S_IMODE(created.st_mode) == 0o700
            and identity(created) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
            and empty(descriptor))
    os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, 0o700)
    os.fsync(descriptor)
    os.fsync(parent)
    retained = os.fstat(descriptor)
    require(retained.st_dev == created.st_dev and retained.st_ino == created.st_ino
            and stat.S_ISDIR(retained.st_mode) and stat.S_IMODE(retained.st_mode) == 0o700
            and retained.st_uid == uid and retained.st_gid == gid
            and identity(retained) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
            and empty(descriptor))
    require(identity(root) == identity(os.fstat(held[0]))
            and identity(root) == identity(os.lstat("/")))
    for parent_fd, name, descriptor, expected in ancestry:
        require(expected == identity(os.fstat(descriptor))
                and expected == identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)))
except BaseException as error:
    failure = error
    raise
finally:
    cleanup_error = None
    for descriptor in reversed(held):
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_error = cleanup_error or error
    if failure is None and cleanup_error is not None:
        raise cleanup_error
"""
_PROVISION = (
    b"""# All route services must still be stopped before the absent-only claim.
for ingress_unit in "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"
do
    require_unit_value "$ingress_unit" ActiveState inactive
    require_unit_value "$ingress_unit" MainPID 0
done
if ! /usr/bin/python3.12 -I -S -B - "$worker_uid" "$worker_gid" <<'PY_WORKER_INGRESS'
"""
    + _PROVISION_PY.encode("ascii")
    + b"""PY_WORKER_INGRESS
then
    fail_activation "worker ingress absent-only provisioning failed"
fi
require_exact_directory /var/lib/aragorn-runtime-worker-measurement "$worker_uid" "$worker_gid" 700
"""
)


class Phase3IngressStageError(ValueError):
    """The fixed ingress successor cannot preserve its source/custody contract."""


def _destination(name: str) -> tuple[str, int]:
    return predecessor.admission._destination(name)


def _replace(raw: bytes, before: bytes, after: bytes) -> bytes:
    if raw.count(before) != 1 or before == after or after in raw:
        raise Phase3IngressStageError("ingress source anchor changed")
    result = raw.replace(before, after)
    if result.replace(after, before) != raw:
        raise Phase3IngressStageError("ingress transformation is not reversible")
    return result


def _render_unit(raw: bytes) -> bytes:
    if (
        raw.count(b"StateDirectory=aragorn-runtime-tool-receipts\n") != 1
        or b"ReadWritePaths=" in raw
        or _MEASUREMENT_ROOT.encode("ascii") in raw
    ):
        raise Phase3IngressStageError("worker state-directory contract changed")
    return _replace(raw, _UNIT_ANCHOR, _UNIT_ANCHOR + _UNIT_WRITE_PATH)


def _pin_line(name: str, raw: bytes) -> bytes:
    destination, mode = _destination(name)
    return f"{mode:o} {base.overlay._digest(raw)[7:]} /{destination}\n".encode("ascii")


def _activator_changes(original: dict, worker: bytes, unit: bytes, helper: bytes):
    old_worker = original[_destination(_WORKER)[0]][2]
    old_unit = original[_destination(_UNIT)[0]][2]
    return (
        (_pin_line(_WORKER, old_worker), _pin_line(_WORKER, worker)),
        (
            base.overlay._digest(old_unit)[7:].encode("ascii"),
            base.overlay._digest(unit)[7:].encode("ascii"),
        ),
        (b"\nEOF\n", b"\n" + _pin_line(_HELPER, helper) + b"EOF\n"),
        (_ACTIVATION_ANCHOR, _LOADED_CHECKS + _PROVISION + _ACTIVATION_ANCHOR),
    )


def _render_activator(
    raw: bytes, original: dict, worker: bytes, unit: bytes, helper: bytes
) -> bytes:
    if _MEASUREMENT_ROOT.encode("ascii") in raw:
        raise Phase3IngressStageError("ingress provisioning already present")
    changes = _activator_changes(original, worker, unit, helper)
    result = raw
    for before, after in changes:
        result = _replace(result, before, after)
    restored = result
    for before, after in reversed(changes):
        if restored.count(after) != 1:
            raise Phase3IngressStageError("ingress inverse anchor changed")
        restored = restored.replace(after, before)
    if restored != raw:
        raise Phase3IngressStageError("ingress activator changed unrelated bytes")
    return result


def _verified_payloads():
    if predecessor._ROOT != _ROOT or renderer._ROOT != _ROOT:
        raise Phase3IngressStageError("ingress source roots disagree")
    for name, pin in _SOURCE_PINS.items():
        base.overlay._read_pinned(name, *pin, root=_ROOT)
    inherited, previous = predecessor._verified_payloads()
    original = inherited | previous
    for source in (_WORKER, _UNIT, _ACTIVATOR):
        path, mode = _destination(source)
        if original.get(path, ())[:2] != (source, mode):
            raise Phase3IngressStageError("ingress predecessor source identity changed")
    worker_path = _destination(_WORKER)[0]
    if (
        len(original) != 73
        or len(base._directories(original)) != 16
        or _destination(_HELPER)[0] in original
        or (
            len(original[worker_path][2]),
            base.overlay._digest(original[worker_path][2]),
        )
        != renderer._INPUT
    ):
        raise Phase3IngressStageError("ingress predecessor inventory changed")
    worker = renderer._verified_inputs()
    helper = base.overlay._read_pinned(_HELPER, *_SOURCE_PINS[_HELPER], root=_ROOT)
    unit = _render_unit(original[_destination(_UNIT)[0]][2])
    activator = _render_activator(
        original[_destination(_ACTIVATOR)[0]][2], original, worker, unit, helper
    )
    replacements = {
        _destination(name)[0]: (name, _destination(name)[1], raw)
        for name, raw in (
            (_WORKER, worker),
            (_HELPER, helper),
            (_UNIT, unit),
            (_ACTIVATOR, activator),
        )
    }
    actual = {
        name: (len(raw), base.overlay._digest(raw))
        for name, _, raw in replacements.values()
    }
    if (
        actual != _OUTPUTS
        or len(original | replacements) != 74
        or len(base._directories(original | replacements)) != 16
    ):
        raise Phase3IngressStageError("ingress output pins or inventory changed")
    return original, replacements


def stage_runtime_phase3_ingress_profile(output: Path) -> dict:
    """Stage exact bytes only; leave all live/provisioning/measurement flags false."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise Phase3IngressStageError("DESTDIR must be absolute and absent")
        custody = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = predecessor.stage_runtime_phase3_common_profile(output)
        if base._parent_custody(output.parent) != custody:
            raise Phase3IngressStageError("ingress staging parent changed")
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != custody
        ):
            raise Phase3IngressStageError("ingress staging custody changed")
        sources = {}
        for row in report["source_inputs"]:
            name, pin = row["name"], (row["bytes"], row["digest"])
            if name in sources:
                raise Phase3IngressStageError("duplicate predecessor source input")
            sources[name] = pin
        for name, pin in _SOURCE_PINS.items():
            if name in sources and sources[name] != pin:
                raise Phase3IngressStageError("conflicting ingress source pin")
            sources[name] = pin
        dependencies = {row["name"] for row in report["new_dependencies"]} | {_HELPER}
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "worker_ingress_deployed": False,
            "worker_ingress_directory_provisioned": False,
            "worker_ingress_collected": False,
            "clock_domain_verified": False,
            "elapsed_time_derived": False,
            "metrics_eligible": False,
            "worker_ingress_state_directory": _MEASUREMENT_ROOT,
            "worker_ingress_provisioning": "ABSENT_ONLY_WHILE_FOUR_UNITS_STOPPED_NO_REPAIR_RESET_OR_RETRY",
            "files": [
                {
                    "path": "/" + path,
                    "source_name": source,
                    "bytes": len(raw),
                    "digest": base.overlay._digest(raw),
                    "mode": f"{mode:04o}",
                }
                for path, (source, mode, raw) in sorted(final.items())
            ],
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in sorted(sources.items())
            ],
            "new_dependencies": [
                {
                    "name": name,
                    "bytes": len(final[_destination(name)[0]][2]),
                    "digest": base.overlay._digest(final[_destination(name)[0]][2]),
                }
                for name in sorted(dependencies)
            ],
            "missing_inputs": report["missing_inputs"]
            + [
                "this 74-file profile requires exact successor preparation, provisioning and independent installed/process identity joins; old 73-file reports must not be relabeled",
                "ingress startup retention must be observed in one owned fixture; staging does not create the private live directory or run the activator",
                "worker timestamps require independent same-boot/clock-domain evidence and final broker decision/sink joins; no elapsed latency, effect, RUN or Phase 3 qualification",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        raise Phase3IngressStageError("cannot stage Phase 3 ingress profile") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_phase3_ingress_profile(parser.parse_args().output)
    except Phase3IngressStageError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
