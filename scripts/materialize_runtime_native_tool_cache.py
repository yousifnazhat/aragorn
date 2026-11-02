"""Preserve the fixed worker tool lifecycle on warm descriptor-cache paths."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import materialize_runtime_native_tool_hooks as hooks

_INPUT = "src/plugins/tools.ts"
_INPUT_PIN = (
    47585,
    "sha256:1a0dee76a2cfc040dc2787fbccfcba3cc6df258aa2f38d6d27b26dfecc5757e5",
)
_OUTPUT_PIN = (
    47899,
    "sha256:d9bb350dfae70081e86b219e285bfc55470afc8d6775b999146859710b96e156",
)
_BEFORE = b"""  const onlyPluginIdSet = new Set(params.onlyPluginIds);
  for (const plugin of params.snapshot.plugins) {
"""
_AFTER = (
    _BEFORE
    + b"""    // ponytail: descriptor-only cache omits this tool's private lifecycle.
    // Use the existing current-context factory path; general callback forwarding
    // belongs in the cache only when other lifecycle-bearing tools need it.
    if (plugin.id === "aragorn-runtime-action-worker") {
      continue;
    }
"""
)


def _upstream_bytes() -> bytes:
    result = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-C",
            str(hooks._UPSTREAM),
            "show",
            f"{hooks._SOURCE}:{_INPUT}",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    raw = result.stdout
    if (
        result.returncode
        or result.stderr
        or (len(raw), hooks.overlay._digest(raw)) != _INPUT_PIN
    ):
        raise ValueError("cached tool source identity changed")
    return raw


def _verified_inputs() -> dict[str, bytes]:
    original = _upstream_bytes()
    if original.count(_BEFORE) != 1:
        raise ValueError("cached tool selection boundary changed")
    raw = original.replace(_BEFORE, _AFTER)
    if raw.count(_AFTER) != 1 or raw.replace(_AFTER, _BEFORE) != original:
        raise ValueError("unrelated cached tool behavior changed")
    if (len(raw), hooks.overlay._digest(raw)) != _OUTPUT_PIN:
        raise ValueError("cached tool output identity changed")
    return {"tools.ts": raw}


def materialize_runtime_native_tool_cache(output: Path) -> dict:
    if (
        not isinstance(output, Path)
        or not output.is_absolute()
        or output.exists()
        or output.is_symlink()
    ):
        raise ValueError("output must be an absent absolute Path")
    rendered = _verified_inputs()
    hooks.overlay._write_overlay(output, rendered, ())
    if _verified_inputs() != rendered:
        raise ValueError("cached tool source changed during publication")
    return {
        "schema": "aragorn/runtime-native-tool-cache-source-overlay/v1",
        "authority": "UNBUILT_FIXED_PLUGIN_CACHE_COMPATIBILITY_ONLY",
        "upstream_commit": hooks._SOURCE,
        "upstream_input": {
            "name": _INPUT,
            "bytes": _INPUT_PIN[0],
            "digest": _INPUT_PIN[1],
        },
        "files": [
            {"name": "tools.ts", "bytes": _OUTPUT_PIN[0], "digest": _OUTPUT_PIN[1]}
        ],
        "runtime_build_identity": None,
        "production_activation_eligible": False,
        "run_eligible": False,
        "phase3_eligible": False,
        "limitations": [
            "FIXED_WORKER_PLUGIN_ONLY_OTHER_PLUGIN_CACHE_BEHAVIOR_UNCHANGED",
            "CURRENT_CONTEXT_FACTORY_RESOLUTION_COST_NOT_PERFORMANCE_QUALIFIED",
            "REQUIRES_NATIVE_HOOK_COMPANIONS_NEW_BUILD_AND_COMMON_PROFILE_REQUALIFICATION",
            "NO_LIVE_WARM_CACHE_RECEIPT_OR_EFFECT_PROOF",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_native_tool_cache(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
