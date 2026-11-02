"""Checked-source CLI for one HTTP94 capture; no VM startup or effect retries.

Use prepare-setup first, then the common prepare/capture/verify commands. Each
generated module is private to this launcher; package globals stay unchanged.
"""

from __future__ import annotations

import builtins
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts import materialize_native_phase3_http_attempt_capture as renderer


def _load(raw, source, modules):
    if source not in (*renderer.generated_paths(), *renderer.PRIVATE_STAGED_SOURCES):
        raise ValueError("HTTP attempt loader source is not fixed")
    package = "aragorn" if source.startswith("src/aragorn/") else "scripts"
    leaf = Path(source).stem
    module = ModuleType(package + "._http_attempt_" + leaf + "_" + uuid4().hex)
    module.__package__, module.__file__ = package, str(ROOT / source)

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        prefix = package if level == 1 else name
        key = package + "." + name if level == 1 else name
        if fromlist and key in modules:
            return modules[key]
        if fromlist and (
            (level == 1 and not name) or (level == 0 and name in {"aragorn", "scripts"})
        ):
            selected = {}
            for item in fromlist:
                key = prefix + "." + item
                if key in modules:
                    selected[item] = modules[key]
                else:
                    original = builtins.__import__(prefix, globals, locals, (item,), 0)
                    selected[item] = getattr(original, item)
            return SimpleNamespace(**selected)
        return builtins.__import__(name, globals, locals, fromlist, level)

    module.__dict__["__builtins__"] = vars(builtins) | {"__import__": local_import}
    # Dataclasses resolve postponed annotations through sys.modules during class
    # creation. Register only this unique private name, never a package alias.
    if module.__name__ in sys.modules:
        raise ValueError("HTTP attempt private module name is already bound")
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, module.__file__, "exec"), module.__dict__)  # noqa: S102
    finally:
        if sys.modules.get(module.__name__) is not module:
            raise ValueError("HTTP attempt private module binding changed")
        del sys.modules[module.__name__]
    modules[package + "." + leaf] = module
    return module


def _staged_private_sources(original):
    """Use only the finite stager's locally pinned payloads, never evidence code."""
    from scripts import stage_runtime_phase3_http_ready_profile as stage

    if stage._ROOT != ROOT:
        raise ValueError("HTTP attempt private stage root differs")
    inherited, replacements, _ = stage._verified_payloads()
    payloads = inherited | replacements
    # Capability INPUTS pins include generated intermediate V4 bytes. Source
    # custody must compare the signed original, using the root stage inventory.
    pins = stage.base._BASE_INPUTS | stage.predecessor._SOURCE_PINS
    result = {}
    for source in renderer.PRIVATE_STAGED_SOURCES:
        expected = stage.base.overlay._read_pinned(source, *pins[source], root=ROOT)
        if original[source] != expected:
            raise ValueError("HTTP attempt private source differs from pinned stage")
        rows = [
            (path, mode, raw)
            for path, (name, mode, raw) in payloads.items()
            if name == source
        ]
        destination = "usr/lib/aragorn/aragorn/" + Path(source).name
        if (
            len(rows) != 1
            or rows[0][:2] != (destination, 0o644)
            or type(rows[0][2]) is not bytes
            or not rows[0][2]
        ):
            raise ValueError("HTTP attempt private stage payload differs")
        result[source] = rows[0][2]
    return result


def build_controller(original):
    if type(original) is not dict or set(original) != set(renderer.source_paths()):
        raise ValueError("HTTP attempt launcher source closure differs")
    generated = renderer.compose(original)
    staged = _staged_private_sources(original)
    modules = {}
    order = (
        *renderer.PRIVATE_STAGED_SOURCES,
        "src/aragorn/runtime_broker_decision_measurement_verify.py",
        "src/aragorn/runtime_broker_measurement_plan.py",
        "src/aragorn/runtime_broker_effective_receipt_verify.py",
        "src/aragorn/native_phase3_common_identity.py",
        "src/aragorn/native_phase3_common_process_verifier.py",
        "src/aragorn/runtime_native_measurement_inputs.py",
        "src/aragorn/runtime_native_measurement_provisioning.py",
        "src/aragorn/native_phase3_common_preparation.py",
        "scripts/runtime_native_common_case_setup.py",
        "src/aragorn/native_phase3_common_setup_capture.py",
        "scripts/runtime_native_common_setup_capture.py",
        "scripts/capture_native_phase3_common_setup.py",
        "scripts/runtime_native_common_measurement_handoff.py",
        "scripts/runtime_native_common_attempt_plan.py",
        "scripts/runtime_native_measurement_evidence_snapshot.py",
        "scripts/runtime_native_common_attempt.py",
        renderer.INPUT,
        "scripts/runtime_native_common_attempt_capture.py",
        "src/aragorn/native_phase3_common_attempt_capture.py",
        "src/aragorn/native_phase3_common_measurement_capture.py",
        "scripts/retain_native_common_measurement_inputs.py",
        renderer.HOST,
    )
    for source in order:
        _load(
            staged[source] if source in staged else generated[source],
            source,
            modules,
        )
    controller = modules["scripts.capture_native_phase3_common_attempt"]
    if set(controller._SOURCE_PATHS) != set(original):
        raise ValueError("HTTP attempt loaded closure differs")
    return controller


def _verified_sources():
    from scripts import capture_native_phase3_plugin_update_case as legacy
    from scripts import capture_runtime_native_receipt_systemd_check as native
    from scripts import prepare_native_plugin_update_identity_pins as pins

    paths = renderer.source_paths()
    source = legacy._current_source()
    original = {}
    for path in paths:
        row = native.acquisition._tree_file(source["commit"], Path(path))
        original[path] = pins._read_fixed(ROOT / path, (row["bytes"], row["digest"]))
    if legacy._current_source() != source:
        raise ValueError("HTTP attempt signed source changed while loading")
    return original


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        controller = build_controller(_verified_sources())
        if argv and argv[0] == "prepare-setup":
            return controller.base.main(["prepare", *argv[1:]])
        return controller.main(argv)
    except Exception:
        print(
            '{"status":"REFUSED","reason":"HTTP_ATTEMPT_SOURCE_OR_CONTROLLER_REFUSED"}'
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
