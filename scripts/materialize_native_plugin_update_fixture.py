"""Materialize one fixed inert tracked-marketplace update bundle; no execution."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import materialize_native_plugin_package_fixture as prior

_ROOT, _DIRECTORY = prior._ROOT, prior._DIRECTORY
_PROBE = "protected-plugin-marketplace-update-probe.py"
_SCHEMA = "aragorn/native-plugin-update-fixture-bundle/v1"


def _adapter():
    spec = importlib.util.spec_from_file_location(
        "aragorn_marketplace_update_fixture", _DIRECTORY / _PROBE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payloads():
    adapter = _adapter()
    primitives = adapter._prior()
    files = {
        f"{name}/{key}": raw
        for name, version in (
            ("baseline-source", "1.0.0"),
            ("candidate-source", "2.0.0"),
        )
        for key, raw in adapter.fixture_files(version).items()
    }
    files["marketplace.json"] = adapter.canonical(adapter.marketplace()) + b"\n"
    files["adapter/" + primitives.BASE_NAME] = primitives._read_base(
        _DIRECTORY / primitives.BASE_NAME
    )
    for name in (_PROBE, adapter.PRIOR_NAME, adapter.SEED_NAME):
        files["adapter/" + name] = (_DIRECTORY / name).read_bytes()
    return files


def materialize(output: Path):
    if not isinstance(output, Path) or not output.is_absolute() or output.exists():
        raise ValueError("fixture output must be new and absolute")
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("fixture ancestry contains a symlink")
    adapter = _adapter()
    files = payloads()
    output.mkdir(mode=0o755)
    for group in ("adapter", "baseline-source", "candidate-source"):
        prior.writer._write_overlay(
            output / group,
            {
                name.split("/", 1)[1]: raw
                for name, raw in files.items()
                if name.startswith(group + "/")
            },
            (),
        )
    fd = os.open(
        output / "marketplace.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o444,
    )
    try:
        raw = files["marketplace.json"]
        if os.write(fd, raw) != len(raw):
            raise ValueError("manifest write incomplete")
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    output.chmod(0o555)
    return {
        "schema": _SCHEMA,
        "authority": "INERT_INPUT_PREPARATION_ONLY_NOT_EXECUTION_OR_QUALIFICATION",
        "route_id": adapter.ROUTE,
        "branch": adapter.BRANCH,
        "files": [
            {"name": name, "bytes": len(raw), "digest": adapter.digest(raw)}
            for name, raw in sorted(files.items())
        ],
        "decision": dict.fromkeys(adapter._prior()._ELIGIBILITY, False),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(
        json.dumps(
            materialize(parser.parse_args().output),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
