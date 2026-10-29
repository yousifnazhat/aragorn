"""Render pinned runtime source overrides, not an activated runtime release."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay

_SCHEMA = "aragorn/runtime-quarantine-service-overlay/v1"
_AUTHORITY = "PINNED_RUNTIME_SOURCE_OVERLAY_ONLY_NOT_DEPLOYMENT_OR_STARTUP_AUTHORITY"
_SERVICES = {
    "src/aragorn/runtime_action_broker_v5.py": (
        10_907,
        "sha256:35c17f92cca01ba064058f6d76223a03072138aa61d060538600f6799af7eca5",
        10_938,
        "sha256:724e6114775450788fcce4ebb1b5d96a5ba35a7ae9ea6d70073114386969c072",
    ),
    "src/aragorn/runtime_action_observation_publisher_v4.py": (
        12_107,
        "sha256:2f021264b43d4602842134b9d7422105243fbbf594b474a58a6a5ae8290442ae",
        12_138,
        "sha256:12f8ee9ab6f91503cd1186bf814c640196ab489e1adbe0d26172d2dedb1baeac",
    ),
    "src/aragorn/runtime_lineage_capability_issuer.py": (
        2_149,
        "sha256:85c4ec36c163648e3d706e5c7c650642caee8b1f6799fd820bc12fb1486ad0ca",
        2_180,
        "sha256:371b0e8f54796d11aef40a0f27f72e841987f8e1a4fdd039c6a7c3ad17c16cfd",
    ),
}
_DEPENDENCIES = {
    "src/aragorn/runtime_active_skill_lineage_v2.py": (
        3_256,
        "sha256:f1c2c3091a092bc8b0a117c1a8f3853645df3b9d8fb24ecf96b65122b97c27cc",
    ),
    "src/aragorn/protected_skill_quarantine.py": (
        6_920,
        "sha256:fa1297bc05345c85e518be8ac397e35d289c8b1dc30dc4aa4002154af8aeddd0",
    ),
}


class RuntimeQuarantineOverlayError(ValueError):
    """The exact source transformation or read-only publication failed."""


def _transform(raw: bytes) -> bytes:
    matches = []
    for verb in (b"hold", b"verify"):
        function = verb + b"_runtime_active_skill_lineage"
        old = (
            b"from .runtime_active_skill_lineage import (\n"
            b"    DEFAULT_PROTECTED_INSTALL_ROOT,\n    " + function + b",\n)"
        )
        matches.extend([(old, function)] * raw.count(old))
    if len(matches) != 1:
        raise RuntimeQuarantineOverlayError("runtime lineage import shape changed")
    old, function = matches[0]
    return raw.replace(
        old,
        b"from .runtime_active_skill_lineage import DEFAULT_PROTECTED_INSTALL_ROOT\n"
        b"from .runtime_active_skill_lineage_v2 import " + function,
    )


def _verified_inputs() -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    dependencies = []
    for name, (size, digest) in _DEPENDENCIES.items():
        overlay._read_pinned(name, size, digest, root=_ROOT)
        dependencies.append({"name": name, "bytes": size, "digest": digest})
    rendered = {}
    for name, (size, digest, output_size, output_digest) in _SERVICES.items():
        raw = _transform(overlay._read_pinned(name, size, digest, root=_ROOT))
        if len(raw) != output_size or overlay._digest(raw) != output_digest:
            raise RuntimeQuarantineOverlayError(
                f"rendered runtime bytes changed: {name}"
            )
        rendered[name] = raw
    return rendered, dependencies


def materialize_runtime_quarantine_services(output: Path) -> dict[str, Any]:
    """Write three pinned module overrides; never launch or install them.

    These relative-path overrides require a complete, separately bound package.
    Same-named modules keep the existing sensor-to-issuer import intact. The only
    source change selects the digest-denial lineage wrappers. A partial write
    may leave output behind but never returns a success manifest.
    """
    try:
        if not isinstance(output, Path) or output.exists() or output.is_symlink():
            raise RuntimeQuarantineOverlayError("output must be a new Path")
        rendered, dependencies = _verified_inputs()
        overlay._write_overlay(output, rendered, ("src", "aragorn"))
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {
                    "name": name,
                    "bytes": len(raw),
                    "digest": _SERVICES[name][3],
                    "source_bytes": _SERVICES[name][0],
                    "source_digest": _SERVICES[name][1],
                }
                for name, raw in rendered.items()
            ],
            "required_checkout_dependencies_not_included": dependencies,
            "standalone_executable": False,
            "production_activation_eligible": False,
            "runtime_startup_enforcement": False,
            "missing_release_inputs": [
                "complete src/aragorn package and its whole-package analyzer identity",
                "requirements-worker.lock",
                "runtime service source pins, systemd units, and activation bindings",
                "mandatory installed/external/worker-binding startup byte gate",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeQuarantineOverlayError(
            f"cannot materialize runtime overlay: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_quarantine_services(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
