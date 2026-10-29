"""Compose admission seals and effective receipt retention in one inert profile.

This does not activate a service, provision measurement credentials, change the
existing capture deployment, or establish admission/RUN/measurement eligibility.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import stage_runtime_native_admission_profile as admission
from scripts import stage_runtime_broker_effective_receipt_profile as effective

base = admission.base
_SCHEMA = "aragorn/runtime-phase3-common-staged-profile/v1"
_AUTHORITY = "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_OR_PHASE3_AUTHORITY"
_ADMISSION = "scripts/stage_runtime_native_admission_profile.py"
_ADMISSION_PIN = (
    7462,
    "sha256:793a3de2765c0cc3f9592f777fe2cc93de714a9d95a1a392130d29958d124591",
)
_EFFECTIVE = "scripts/stage_runtime_broker_effective_receipt_profile.py"
_EFFECTIVE_PIN = (
    12700,
    "sha256:4862d2bf0d812396f88546437e394416e142d548cb65a7a0431bedf609be2125",
)


class Phase3CommonStageError(ValueError):
    """The two reviewed boundaries could not be preserved together."""


def _replace(raw: bytes, before: bytes, after: bytes) -> bytes:
    if raw.count(before) != 1 or after == before or after in raw:
        raise Phase3CommonStageError("common profile anchor changed")
    rendered = raw.replace(before, after)
    if rendered.replace(after, before) != raw:
        raise Phase3CommonStageError("common profile replacement is not reversible")
    return rendered


def _verified_payloads():
    base.overlay._read_pinned(_ADMISSION, *_ADMISSION_PIN, root=_ROOT)
    base.overlay._read_pinned(_EFFECTIVE, *_EFFECTIVE_PIN, root=_ROOT)
    inherited, replacements = effective._verified_payloads()
    original = inherited | replacements
    old_admission, sealed = admission._verified_payloads()
    gateway, _ = admission._destination(admission._GATEWAY)
    activator, mode = admission._destination(admission._ACTIVATOR)
    if (
        len(original) != 73
        or len(base._directories(original)) != 16
        or original[gateway] != old_admission[gateway]
        or original[activator][:2] != (admission._ACTIVATOR, mode)
    ):
        raise Phase3CommonStageError("common predecessor inventory changed")
    before = original[activator][2]
    old_pin = base.overlay._digest(original[gateway][2])[7:].encode("ascii")
    new_pin = base.overlay._digest(sealed[gateway][2])[7:].encode("ascii")
    transformations = (
        (old_pin, new_pin),
        (
            admission._DIRECTORY_ANCHOR,
            admission._DIRECTORIES + admission._DIRECTORY_ANCHOR,
        ),
        (admission._CHECK_ANCHOR, admission._CHECKS + admission._CHECK_ANCHOR),
    )
    after = before
    for source, target in transformations:
        after = _replace(after, source, target)
    restored = after
    for source, target in reversed(transformations):
        if restored.count(target) != 1:
            raise Phase3CommonStageError("common activator inverse changed")
        restored = restored.replace(target, source)
    if restored != before:
        raise Phase3CommonStageError("common activator changed unrelated behavior")
    return original, {
        gateway: sealed[gateway],
        activator: (admission._ACTIVATOR, mode, after),
    }


def stage_runtime_phase3_common_profile(output: Path) -> dict:
    """Stage one 73-file successor; all execution/provisioning claims stay false."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise Phase3CommonStageError("DESTDIR must be absolute and absent")
        custody = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = effective.stage_runtime_broker_effective_receipt_profile(output)
        base._audit_tree(output, original)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != custody
        ):
            raise Phase3CommonStageError("common staging custody changed")
        sources = {
            row["name"]: (row["bytes"], row["digest"])
            for row in report["source_inputs"]
        }
        for name, pin in ((_ADMISSION, _ADMISSION_PIN), (_EFFECTIVE, _EFFECTIVE_PIN)):
            if name in sources and sources[name] != pin:
                raise Phase3CommonStageError("conflicting predecessor source pin")
            sources[name] = pin
        dependencies = {row["name"] for row in report["new_dependencies"]} | {
            admission._GATEWAY
        }
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "discovery_read_only_paths": list(admission._DISCOVERY_READ_ONLY_PATHS),
            "admission_qualified": False,
            "common_deployment_activated": False,
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
                    "bytes": len(final[admission._destination(name)[0]][2]),
                    "digest": base.overlay._digest(
                        final[admission._destination(name)[0]][2]
                    ),
                }
                for name in sorted(dependencies)
            ],
            "missing_inputs": report["missing_inputs"]
            + [
                "common measurement credential/input-CAS provisioning, request handoff and installed identity integration are not implemented by staging",
                "existing 70-file admission capture intent must not be relabelled as this 73-file deployment",
                "new common deployment requires reviewed native activation and independent semantic verification before final freeze",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        raise Phase3CommonStageError("cannot stage common Phase 3 profile") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        value = stage_runtime_phase3_common_profile(parser.parse_args().output)
    except Phase3CommonStageError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
