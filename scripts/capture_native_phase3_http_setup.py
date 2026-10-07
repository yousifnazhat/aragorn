"""Checked-source HTTP93 setup-only CLI; never activate or capture an attempt.

Commands match the common setup controller, with a required --http-attempt-id
on prepare. Generated modules have private local import bindings: no sys.modules
or package-global replacement. Source bytes must belong to the clean signed tree
before any generated controller is evaluated. Capture requires the existing VM.
"""

from __future__ import annotations

import builtins
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts import materialize_native_phase3_http_setup_capture as renderer


def source_paths():
    """The finite source inventory can be inspected without evaluating output."""
    from aragorn import native_phase3_common_setup_capture as predecessor

    helpers = set(predecessor.FIXTURE_HELPERS) - set(renderer.STAGE_OWNED)
    return tuple(
        sorted(
            helpers
            | set(renderer.GENERATED_SOURCES)
            | set(renderer.RENDERER_SOURCES)
            | {
                renderer.HOST,
                renderer.LAUNCHER,
                "scripts/stage_runtime_phase3_http_profile.py",
            }
        )
    )


def _load_fixed(raw, source, modules):
    """Evaluate one reviewed finite output with only local dependency wiring."""
    if source not in renderer.GENERATED_SOURCES:
        raise ValueError("HTTP launcher refuses arbitrary source names")
    package = "aragorn" if source.startswith("src/aragorn/") else "scripts"
    leaf = Path(source).stem
    module = ModuleType(package + "._http_setup_" + leaf)
    module.__package__ = package
    module.__file__ = str(ROOT / source)

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        prefix = package if level == 1 else name
        if level == 1 and name:
            key = package + "." + name
            if key in modules:
                return modules[key]
        if fromlist and (
            level == 1 and not name or level == 0 and name in {"aragorn", "scripts"}
        ):
            selected = {}
            for item in fromlist:
                key = prefix + "." + item
                if key in modules:
                    selected[item] = modules[key]
                else:
                    base = builtins.__import__(prefix, globals, locals, (item,), 0)
                    selected[item] = getattr(base, item)
            return SimpleNamespace(**selected)
        return builtins.__import__(name, globals, locals, fromlist, level)

    module.__dict__["__builtins__"] = vars(builtins) | {"__import__": local_import}
    exec(compile(raw, module.__file__, "exec"), module.__dict__)  # noqa: S102
    modules[package + "." + leaf] = module
    return module


def build_controller(original):
    """Compose caller-verified source bytes; no command is dispatched here.

    This internal seam is used by inert checks. The public CLI always obtains
    its bytes through _verified_sources before calling it. No arbitrary source
    path or generated payload is accepted from a bundle for execution.
    """
    if type(original) is not dict or set(original) != set(source_paths()):
        raise ValueError("HTTP launcher source closure changed")
    generated = renderer.compose(original)
    modules = {}
    order = (
        "src/aragorn/runtime_broker_decision_measurement_verify.py",
        "src/aragorn/runtime_broker_measurement_plan.py",
        "src/aragorn/runtime_broker_effective_receipt_verify.py",
        "src/aragorn/native_phase3_common_identity.py",
        "src/aragorn/native_phase3_common_process_verifier.py",
        "src/aragorn/runtime_native_measurement_inputs.py",
        "src/aragorn/native_phase3_common_preparation.py",
        "scripts/runtime_native_common_case_setup.py",
        renderer.CONSUMER,
        renderer.GUEST,
        renderer.HOST,
    )
    for source in order:
        _load_fixed(generated[source], source, modules)
    # The writer executes only in the already-owned guest after copied-byte
    # verification; importing its fixture bootstrap here is unnecessary.
    controller = modules["scripts.capture_native_phase3_common_setup"]
    if set(controller._SOURCE_PATHS) != set(original):
        raise ValueError("HTTP loaded controller source inventory changed")
    return controller


def _verified_sources():
    from scripts import capture_native_phase3_plugin_update_case as legacy
    from scripts import prepare_native_plugin_update_identity_pins as pins

    source = legacy._current_source()
    api = legacy.native.acquisition if hasattr(legacy, "native") else None
    if api is None:
        from scripts import capture_runtime_native_receipt_systemd_check as native

        api = native.acquisition
    original = {}
    for path in source_paths():
        row = api._tree_file(source["commit"], Path(path))
        original[path] = pins._read_fixed(ROOT / path, (row["bytes"], row["digest"]))
    # Recheck source identity after the complete read, before generated exec.
    if legacy._current_source() != source:
        raise ValueError("HTTP signed source changed while loading")
    return original


def main(argv=None):
    try:
        controller = build_controller(_verified_sources())
        return controller.main(argv)
    except Exception:
        print('{"status":"REFUSED","reason":"HTTP_SETUP_SOURCE_OR_CONTROLLER_REFUSED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
