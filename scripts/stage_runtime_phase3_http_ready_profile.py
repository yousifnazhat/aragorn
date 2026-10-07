"""Stage one readiness-capable HTTP94 successor in an absent caller DESTDIR.

HTTP93 sources and reports remain frozen. This operation only renders, writes
and audits inert staging bytes; it never provisions a credential, starts a
listener/service, probes readiness or establishes deployment qualification.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import stage_runtime_phase3_http_profile as predecessor
from scripts import materialize_runtime_http_readiness as renderer

base = predecessor.base
_PARENT = "scripts/stage_runtime_phase3_http_profile.py"
_RENDERER = "scripts/materialize_runtime_http_readiness.py"
_HELPER = renderer.RUNTIME_SOURCE
_ACTIVATOR = predecessor._ACTIVATOR
_CAP_ACTIVATOR = predecessor._CAP_ACTIVATOR
_MEASUREMENT = predecessor._MEASUREMENT
_PLAN = predecessor.collection.PLAN
_PRIOR = predecessor.collection.PRIOR
_EFFECTIVE = predecessor.collection.EFFECTIVE
_SCHEMA = "aragorn/runtime-phase3-http-ready-staged-profile/v1"
_SOURCE_PINS = {
    _PARENT: (
        20715,
        "sha256:214c4dfbf7ab2f89873b4602bd359f948a3cf6e61cb6a62c02941f8f82e3d7c6",
    ),
    _RENDERER: (
        2633,
        "sha256:d012b334a5e8154d40c4c9cc4b4bda6ec4ae63d048eda8bb6fe403634595c27d",
    ),
    _HELPER: (
        18520,
        "sha256:acd11f1583ba3ca1df7b9f68251336e2b45b9f991ef631bade5415d6aa8ba7cc",
    ),
}
READINESS_SOURCE_NAME = "runtime_http_readiness.py"
MEASUREMENT_SOURCE_NAMES = tuple(
    sorted(
        {
            "runtime_action_broker.py",
            "runtime_action_broker_v4.py",
            "runtime_action_broker_v5.py",
            "runtime_action_service_v5.py",
            "runtime_broker_decision_measurement.py",
            "phase3_deployment.py",
            "phase3_quantitative_metrics.py",
            *predecessor.HTTP_MEASUREMENT_SOURCES,
            READINESS_SOURCE_NAME,
        }
    )
)


class Phase3HttpReadyStageError(ValueError):
    """A finite predecessor, source closure or staging custody check failed."""


def _require(value, reason):
    if not value:
        raise Phase3HttpReadyStageError(reason)


def _destination(name):
    return predecessor._destination(name)


def _replace(raw, before, after):
    _require(
        type(raw) is bytes
        and before != after
        and raw.count(before) == 1
        and after not in raw,
        "HTTP readiness anchor changed",
    )
    changed = raw.replace(before, after)
    _require(
        changed.replace(after, before) == raw,
        "HTTP readiness replacement not reversible",
    )
    return changed


_VALIDATE = b'''def validate_activation_readiness():
    """Read-only guard before any activation mutation; never creates or probes."""
    binding = http.load_fixture_binding()
    with owned_http_fixture(binding["fixture"]) as held:
        _require(binding == provision._new_binding(binding["fixture"]),
                 "HTTP_READINESS_FIXTURE_BINDING_CHANGED")
        provision._stopped()
        raw, metadata = _read_owned(
            CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440
        )
        request = _input(raw, binding)
        _require(not os.path.lexists(CLAIM) and not os.path.lexists(RESULT),
                 "HTTP_READINESS_ALREADY_USED")
        held.guard()
        _require(http.load_fixture_binding() == binding
                 and _read_owned(CREDENTIAL, uid=0,
                                 gid=binding["expected_broker_gid"], mode=0o440)
                 == (raw, metadata), "HTTP_READINESS_PREACTIVATION_CUSTODY_CHANGED")
        held.guard()
    return canonical_digest(request)


'''

_READY_GUARD = b"""# Fixed readiness input, stopped units and exact owned namespace; no writes.
if ! /usr/bin/python3.12 -I -S -B -c 'import sys; sys.path.insert(0,"/usr/lib/aragorn"); from aragorn.runtime_http_readiness import validate_activation_readiness; validate_activation_readiness()'
then
    echo "HTTP readiness prerequisite refused before activation" >&2
    exit 1
fi
"""


def _early_pins(payloads):
    """Finite read-only checks, before importing the new root-side guard."""
    lines = []
    for path, (_name, mode, raw) in sorted(payloads.items()):
        lines.append(f"{mode:o} {base.overlay._digest(raw)[7:]} /{path}\n".encode())
    return (
        b"""# Exact changed HTTP readiness dependencies; read-only, before lock/trap writes.
while read -r ready_mode ready_digest ready_path
do
    if [ -L "$ready_path" ] || [ ! -f "$ready_path" ]; then
        echo "HTTP readiness source custody refused" >&2
        exit 1
    fi
    ready_before=$(stat -c '%u:%g:%a:%h:%d:%i:%s:%Y:%Z' -- "$ready_path") || exit 1
    case "$ready_before" in
        "0:0:$ready_mode:1:"*) ;;
        *) echo "HTTP readiness source mode/owner refused" >&2; exit 1 ;;
    esac
    ready_actual=$(/usr/bin/sha256sum -- "$ready_path") || exit 1
    if [ "${ready_actual%% *}" != "$ready_digest" ] || [ "$ready_before" != "$(stat -c '%u:%g:%a:%h:%d:%i:%s:%Y:%Z' -- "$ready_path")" ]; then
        echo "HTTP readiness source pin changed" >&2
        exit 1
    fi
done <<'ARAGORN_READY_SOURCE_PINS'
"""
        + b"".join(lines)
        + b"ARAGORN_READY_SOURCE_PINS\n"
        + _READY_GUARD
    )


def _inventory(raw):
    values = [
        node.value
        for node in ast.parse(raw).body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_SOURCES"
            for target in node.targets
        )
    ]
    _require(len(values) == 1, "HTTP readiness measurement inventory ambiguous")
    value = ast.literal_eval(values[0])
    _require(
        type(value) is set and all(type(name) is str for name in value),
        "HTTP readiness measurement inventory invalid",
    )
    return value


def _verified_payloads():
    """Return HTTP93 originals, finite destination-keyed changes and input bytes."""
    _require(predecessor._ROOT == _ROOT, "HTTP readiness predecessor root changed")
    inputs = {
        name: base.overlay._read_pinned(name, *pin, root=_ROOT)
        for name, pin in _SOURCE_PINS.items()
    }
    inherited, prior_changes, _ = predecessor._verified_payloads()
    original = inherited | prior_changes
    _require(
        len(original) == 93 and len(base._directories(original)) == 21,
        "HTTP93 predecessor inventory changed",
    )
    old = {source: raw for source, _, raw in original.values()}
    _require(
        len(old) == 93 and _destination(_HELPER)[0] not in original,
        "HTTP readiness source ownership changed",
    )
    changed = renderer.render({path: row[2] for path, row in original.items()})
    _require(
        set(changed) == {renderer.SERVICE, renderer.UNIT},
        "HTTP readiness renderer ownership changed",
    )
    replacements = {path: (*original[path][:2], raw) for path, raw in changed.items()}
    helper = _replace(
        inputs[_HELPER],
        b"def run_startup_readiness():\n",
        _VALIDATE + b"def run_startup_readiness():\n",
    )
    destination, mode = _destination(_HELPER)
    _require(
        (destination, mode) == (renderer.RUNTIME_DESTINATION, 0o644),
        "HTTP readiness helper destination changed",
    )
    replacements[destination] = (_HELPER, mode, helper)
    _require(len(MEASUREMENT_SOURCE_NAMES) == 22, "HTTP readiness source count changed")
    for name in (_MEASUREMENT, _PLAN, _PRIOR):
        before = old[name]
        _require(
            _inventory(before)
            == set(MEASUREMENT_SOURCE_NAMES) - {READINESS_SOURCE_NAME},
            "HTTP93 measurement source closure changed",
        )
        after = _replace(
            before,
            b"_SOURCES = {\n",
            b'_SOURCES = {\n    "runtime_http_readiness.py",\n',
        )
        _require(
            _inventory(after) == set(MEASUREMENT_SOURCE_NAMES),
            "HTTP readiness measurement closure changed",
        )
        path, mode = _destination(name)
        replacements[path] = (name, mode, after)
    # Complete the subordinate activator first; the worker manifest then binds it.
    early = _early_pins(replacements)
    rendered = {**old, **{name: raw for name, _, raw in replacements.values()}}
    capability = predecessor._replace_pins(old[_CAP_ACTIVATOR], old, rendered)
    capability = _replace(capability, b"export PATH\n", b"export PATH\n\n" + early)
    rendered[_CAP_ACTIVATOR] = capability
    path, mode = _destination(_CAP_ACTIVATOR)
    replacements[path] = (_CAP_ACTIVATOR, mode, capability)
    worker = predecessor._replace_pins(old[_ACTIVATOR], old, rendered)
    worker = _replace(
        worker,
        b"export PATH LANG LC_ALL TZ\n",
        b"export PATH LANG LC_ALL TZ\n\n" + early,
    )
    helper_row = f"644 {base.overlay._digest(helper)[7:]} /{renderer.RUNTIME_DESTINATION}\n".encode()
    worker = _replace(worker, b"\nEOF\n", b"\n" + helper_row + b"EOF\n")
    worker = _replace(
        worker,
        predecessor._ACTIVATION_GUARD,
        _READY_GUARD + predecessor._ACTIVATION_GUARD,
    )
    path, mode = _destination(_ACTIVATOR)
    replacements[path] = (_ACTIVATOR, mode, worker)
    final = original | replacements
    _require(
        len(final) == 94
        and len(base._directories(final)) == 21
        and set(final) - set(original) == {renderer.RUNTIME_DESTINATION},
        "HTTP94 output inventory changed",
    )
    return original, replacements, inputs


def stage_runtime_phase3_http_ready_profile(output):
    """One fresh inert DESTDIR; no existing output reuse or live activation."""
    _require(
        isinstance(output, Path)
        and output.is_absolute()
        and not output.exists()
        and not output.is_symlink(),
        "HTTP readiness DESTDIR must be absolute and absent",
    )
    custody = base._parent_custody(output.parent)
    original, replacements, inputs = _verified_payloads()
    report = predecessor.stage_runtime_phase3_http_profile(output)
    base._audit_tree(output, original)
    base._apply_overrides(output, replacements)
    final = original | replacements
    base._audit_tree(output, final)
    _require(
        _verified_payloads() == (original, replacements, inputs)
        and base._parent_custody(output.parent) == custody,
        "HTTP readiness staging custody changed",
    )
    sources = {
        row["name"]: (row["bytes"], row["digest"]) for row in report["source_inputs"]
    }
    for name, pin in _SOURCE_PINS.items():
        _require(
            name not in sources or sources[name] == pin,
            "HTTP readiness conflicting source pin",
        )
        sources[name] = pin
    dependencies = {row["name"] for row in report["new_dependencies"]} | {_HELPER}
    _require(
        set(report["binding_source_pins"])
        == set(MEASUREMENT_SOURCE_NAMES) - {READINESS_SOURCE_NAME},
        "HTTP93 measurement report source inventory changed",
    )
    return {
        **report,
        "schema": _SCHEMA,
        "http_readiness_paths_staged": True,
        "http_readiness_provisioned": False,
        "broker_readiness_observed": False,
        "broker_restricted_readiness_verified": False,
        "http_readiness_input_required_not_included": renderer.CREDENTIAL,
        "measurement_source_names": list(MEASUREMENT_SOURCE_NAMES),
        "binding_source_pins": {
            name: base.overlay._digest(final[_destination("src/aragorn/" + name)[0]][2])
            for name in MEASUREMENT_SOURCE_NAMES
        },
        "files": [
            {
                "path": "/" + path,
                "source_name": source,
                "mode": f"{mode:04o}",
                "bytes": len(raw),
                "digest": base.overlay._digest(raw),
            }
            for path, (source, mode, raw) in sorted(final.items())
        ],
        "source_inputs": [
            {"name": name, "bytes": pin[0], "digest": pin[1]}
            for name, pin in sorted(sources.items())
        ],
        "directories": sorted(base._directories(final)),
        "new_dependencies": [
            {"name": name, "bytes": len(raw), "digest": base.overlay._digest(raw)}
            for name, _, raw in sorted(final.values())
            if name in dependencies
        ],
        "missing_inputs": report["missing_inputs"]
        + [
            "absent-only readiness input provisioning after fresh fixture and measurement inputs",
            "listener open before activation and same-current-broker listener witness after readiness result publication",
            "fresh installed profile/measurement/identity joins; staging is not a readiness observation",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(
        json.dumps(
            stage_runtime_phase3_http_ready_profile(parser.parse_args().output),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
