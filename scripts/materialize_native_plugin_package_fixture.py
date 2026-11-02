"""Prepare exact inert package inputs and the policy-denial adapter; never execute."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from scripts import materialize_protected_install_quarantine_producers as writer

_PROBE = "protected-plugin-package-skill-replacement-probe.py"
_DIRECTORY = _ROOT / "benchmark/admission/openclaw-v2026.7.1"


def _adapter():
    spec = importlib.util.spec_from_file_location(
        "aragorn_plugin_package_fixture", _DIRECTORY / _PROBE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def materialize(output: Path) -> dict:
    if not isinstance(output, Path) or not output.is_absolute() or output.exists():
        raise ValueError("fixture output must be a new absolute path")
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("fixture output ancestry must not contain symlinks")
    adapter = _adapter()
    base = adapter._read_base(_DIRECTORY / adapter.BASE_NAME)
    source = (_DIRECTORY / _PROBE).read_bytes()
    output.mkdir(mode=0o755)
    files = {}
    for name, version in (("baseline-source", "1.0.0"), ("candidate-source", "2.0.0")):
        package = adapter.fixture_files(version)
        writer._write_overlay(output / name, package, ())
        files.update({name + "/" + key: value for key, value in package.items()})
    probes = {_PROBE: source, adapter.BASE_NAME: base}
    writer._write_overlay(output / "adapter", probes, ())
    files.update({"adapter/" + key: value for key, value in probes.items()})
    output.chmod(0o555)
    return {
        "schema": "aragorn/native-plugin-package-fixture-bundle/v1",
        "authority": "INERT_INPUT_PREPARATION_ONLY_NOT_EXECUTION_OR_QUALIFICATION",
        "route_id": adapter.ROUTE,
        "files": [
            {"name": name, "bytes": len(raw), "digest": adapter.digest(raw)}
            for name, raw in sorted(files.items())
        ],
        "installation": {
            "read_only_input_root": str(adapter.ROOT),
            "adapter": "adapter/" + _PROBE,
            "baseline_target": "/var/lib/aragorn-agent-gateway/state/extensions/"
            + adapter.PLUGIN_ID,
            "baseline_directory_mode": "0700",
            "baseline_file_mode": "0600",
            "baseline_uid": 992,
            "baseline_gid": 992,
            "gateway_namespace_required": True,
        },
        "decision": {key: False for key in adapter._ELIGIBILITY},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    result = materialize(parser.parse_args().output)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
