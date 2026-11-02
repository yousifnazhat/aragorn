"""Stage the protected-credential HTTP94 successor in one absent inert DESTDIR.

The frozen HTTP93/94 sources are inputs, never modified. This stage has no
provisioning, activation, network, cleanup or qualification operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import stage_runtime_phase3_http_ready_profile as predecessor
from scripts import materialize_runtime_http_credentials as renderer

base = predecessor.base
_PARENT = "scripts/stage_runtime_phase3_http_ready_profile.py"
_RENDERER = "scripts/materialize_runtime_http_credentials.py"
_SCHEMA = "aragorn/runtime-phase3-http-credential-staged-profile/v1"
_SOURCE_PINS = {
    _PARENT: (13146, "sha256:535893d521ec08472cb56d13f19e3e4f1ebf47df1f85f88666bf0054e69b88d0"),
    _RENDERER: (15541, "sha256:e7921c3488614fe6bfc338812703013d9bf849747dc4efe8419f442d5e4f67cc"),
}
MEASUREMENT_SOURCE_NAMES = predecessor.MEASUREMENT_SOURCE_NAMES


class Phase3HttpCredentialStageError(ValueError):
    """The pinned predecessor, finite joins or fresh staging custody changed."""


def _require(condition, reason):
    if not condition:
        raise Phase3HttpCredentialStageError(reason)


def _destination(source):
    return predecessor._destination(source)


def _verified_payloads():
    """Read pinned originals; render only nine payloads plus two activators."""
    _require(predecessor._ROOT == _ROOT, "HTTP credential predecessor root changed")
    inputs = {
        name: base.overlay._read_pinned(name, *pin, root=_ROOT)
        for name, pin in _SOURCE_PINS.items()
    }
    inherited, ready_changes, _ = predecessor._verified_payloads()
    original = inherited | ready_changes
    _require(len(original) == 94 and len(base._directories(original)) == 21,
             "HTTP94 predecessor inventory changed")
    old = {source: raw for source, _, raw in original.values()}
    _require(len(old) == 94 and set(renderer.SOURCES) <= set(old),
             "HTTP credential predecessor ownership changed")
    changed = renderer.render(old)
    _require(set(changed) == set(renderer.SOURCES),
             "HTTP credential renderer ownership changed")
    replacements = {}
    for name, raw in changed.items():
        path, mode = _destination(name)
        _require(original[path][:2] == (name, mode) and type(raw) is bytes
                 and raw != original[path][2], "HTTP credential output changed")
        replacements[path] = (name, mode, raw)
    # Preserve every old pre-import guard, adding all newly changed dependencies.
    # Activators are excluded to avoid a self-hash cycle. The worker subsequently
    # pins the completed subordinate capability activator in its full manifest.
    activators = {predecessor._ACTIVATOR, predecessor._CAP_ACTIVATOR}
    prior_early = {path: row for path, row in ready_changes.items()
                   if row[0] not in activators}
    old_early = predecessor._early_pins(prior_early)
    new_early = predecessor._early_pins(prior_early | replacements)
    rendered = old | changed
    replace_pins = predecessor.predecessor._replace_pins
    cap = replace_pins(old[predecessor._CAP_ACTIVATOR], old, rendered)
    cap = predecessor._replace(cap, replace_pins(old_early, old, rendered), new_early)
    rendered[predecessor._CAP_ACTIVATOR] = cap
    path, mode = _destination(predecessor._CAP_ACTIVATOR)
    replacements[path] = (predecessor._CAP_ACTIVATOR, mode, cap)
    worker = replace_pins(old[predecessor._ACTIVATOR], old, rendered)
    worker = predecessor._replace(worker, replace_pins(old_early, old, rendered), new_early)
    path, mode = _destination(predecessor._ACTIVATOR)
    replacements[path] = (predecessor._ACTIVATOR, mode, worker)
    final = original | replacements
    _require(len(final) == 94 and set(final) == set(original)
             and len(base._directories(final)) == 21 and len(replacements) == 11,
             "HTTP credential output inventory changed")
    _require(all(predecessor._inventory(final[_destination(name)[0]][2])
                 == set(MEASUREMENT_SOURCE_NAMES)
                 for name in (predecessor._MEASUREMENT, predecessor._PLAN, predecessor._PRIOR)),
             "HTTP credential measurement closure changed")
    return original, replacements, inputs


def stage_runtime_phase3_http_credential_profile(output):
    """One fresh inert tree and public byte report; no retained private fixture."""
    _require(isinstance(output, Path) and output.is_absolute()
             and not output.exists() and not output.is_symlink(),
             "HTTP credential DESTDIR must be absolute and absent")
    custody = base._parent_custody(output.parent)
    original, replacements, inputs = _verified_payloads()
    report = predecessor.stage_runtime_phase3_http_ready_profile(output)
    base._audit_tree(output, original)
    base._apply_overrides(output, replacements)
    final = original | replacements
    base._audit_tree(output, final)
    _require(_verified_payloads() == (original, replacements, inputs)
             and base._parent_custody(output.parent) == custody,
             "HTTP credential staging custody changed")
    sources = {row["name"]: (row["bytes"], row["digest"])
               for row in report["source_inputs"]}
    for name, pin in _SOURCE_PINS.items():
        _require(name not in sources or sources[name] == pin,
                 "HTTP credential conflicting source pin")
        sources[name] = pin
    dependencies = {row["name"] for row in report["new_dependencies"]}
    return {
        **report,
        "schema": _SCHEMA,
        "http_service_credentials_staged": True,
        "http_service_credentials_observed": False,
        "gateway_native_restart_environment_staged": True,
        "gateway_lifecycle_logging_staged": True,
        "gateway_lifecycle_log_observed": False,
        "gateway_config_digest_required_not_included": base.overlay._digest(
            final[_destination(renderer.GATEWAY_CONFIG)[0]][2]
        ),
        "http_service_credential_units": {
            Path(source).name: [renderer.FIXTURE_NAME] +
                ([renderer.READINESS_NAME] if source == renderer.BROKER_UNIT else [])
            for source in (renderer.WORKER_UNIT, renderer.SENSOR_UNIT, renderer.BROKER_UNIT)
        },
        "binding_source_pins": {
            name: base.overlay._digest(final[_destination("src/aragorn/" + name)[0]][2])
            for name in MEASUREMENT_SOURCE_NAMES
        },
        "files": [
            {"path": "/" + path, "source_name": source, "mode": f"{mode:04o}",
             "bytes": len(raw), "digest": base.overlay._digest(raw)}
            for path, (source, mode, raw) in sorted(final.items())
        ],
        "source_inputs": [
            {"name": name, "bytes": pin[0], "digest": pin[1]}
            for name, pin in sorted(sources.items())
        ],
        "new_dependencies": [
            {"name": name, "bytes": len(raw), "digest": base.overlay._digest(raw)}
            for name, _, raw in sorted(final.values()) if name in dependencies
        ],
        "missing_inputs": report["missing_inputs"] + [
            "fresh generated helper/capture assembly pinned to this exact public inert report",
            "service credential mount/UID/cgroup/boot and held-sensor descriptor observation",
            "fresh gateway configuration and independent native restart environment joins",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(stage_runtime_phase3_http_credential_profile(parser.parse_args().output),
                     sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
