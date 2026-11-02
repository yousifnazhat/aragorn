"""Render one pinned additive native client source; no hooks or activation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay

_PLUGIN = "packaging/openclaw/aragorn-runtime-action-worker/index.js"
_CLIENT = "packaging/openclaw/aragorn-runtime-native-tool-client/client.cjs"
_INPUTS = {
    _PLUGIN: (
        23860,
        "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
    ),
    _CLIENT: (
        11546,
        "sha256:59fb37e46ab6635217569ac26698b4d57ed2c44459bcc538691e7ee07e5f1fb7",
    ),
}
_DEPENDENCIES = {
    "scripts/materialize_protected_install_quarantine_producers.py": (
        8703,
        "sha256:91cae167762c4aca7527fcd14952990059ebe8e4d37d3e2e64b102843f27e164",
    ),
    "src/aragorn/runtime_native_tool_receipts.py": (
        22210,
        "sha256:b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
    ),
}
_OUTPUT = (
    35434,
    "sha256:193415bea885023664ac44931d9faa096e02b3bc64aafc47113c17aca664566c",
)
_REPLACEMENTS = (
    (
        b"function requestWorker(config, request, signal) {",
        b"function requestWorker(config, request, signal, parseResult = parseWorkerResult) {",
    ),
    (
        b"finish(null, parseWorkerResult(response.subarray(4), request));",
        b"finish(null, parseResult(response.subarray(4), request));",
    ),
)


class NativeToolClientOverlayError(ValueError):
    """A frozen input, exact transform, or read-only publication changed."""


def _transform(plugin: bytes, client: bytes) -> bytes:
    for raw, name in ((plugin, _PLUGIN), (client, _CLIENT)):
        if type(raw) is not bytes or len(raw) != _INPUTS[name][0]:
            raise NativeToolClientOverlayError("native client input size changed")
        if overlay._digest(raw) != _INPUTS[name][1]:
            raise NativeToolClientOverlayError("native client input digest changed")
    for before, after in _REPLACEMENTS:
        if plugin.count(before) != 1:
            raise NativeToolClientOverlayError("native client transform changed")
        plugin = plugin.replace(before, after)
    return plugin + b"\n" + client


def _verified_inputs() -> bytes:
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    raw = _transform(
        *(overlay._read_pinned(name, *pin, root=_ROOT) for name, pin in _INPUTS.items())
    )
    if (len(raw), overlay._digest(raw)) != _OUTPUT:
        raise NativeToolClientOverlayError("native client output changed")
    return raw


def materialize_runtime_native_tool_client(output: Path) -> dict[str, Any]:
    """Publish one flat source, not a standalone plugin or deployed profile.

    The original effect parser remains the default. Only the fixed native client
    passes its receipt parser. No arbitrary protocol router or retries are added.
    Partial publication may leave output, but cannot return a success manifest.
    """
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeToolClientOverlayError("output must be an absent absolute Path")
        raw = _verified_inputs()
        overlay._write_overlay(output, {"index.js": raw}, ())
        if _verified_inputs() != raw:
            raise NativeToolClientOverlayError("source inputs changed")
        return {
            "schema": "aragorn/runtime-native-tool-client-source-overlay/v1",
            "authority": "PINNED_NATIVE_CLIENT_SOURCE_ONLY_NOT_DEPLOYMENT_OR_RUN_AUTHORITY",
            "files": [{"name": "index.js", "bytes": len(raw), "digest": _OUTPUT[1]}],
            "source_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _INPUTS.items()
            ],
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _DEPENDENCIES.items()
            ],
            "standalone_executable": False,
            "production_activation_eligible": False,
            "native_hook_reachability": False,
            "create_to_attempt_enforcement": False,
            "mandatory_capture": False,
            "run_eligible": False,
            "limitations": [
                "REQUIRES_ROOT_BOUND_GATEWAY_CONFIG_AND_GENESIS_CREDENTIAL_LOADER",
                "REQUIRES_EXACT_FINAL_PARAMS_NATIVE_HOOKS_IN_WRAPPER_AND_UNWRAPPED_ADAPTER",
                "FROZEN_DETACHED_PARAMS_REQUIRE_READ_CREATE_SEMANTIC_COMPATIBILITY_TESTS",
                "REQUIRES_RECEIPT_WORKER_TRANSPORT_AND_CREATE_TO_OPEN_ATTEMPT_GATE",
                "REQUIRES_NEW_RUNTIME_BUILD_IDENTITY_AND_ACTIVATOR_STAGER_UNIT_PINS",
                "ONE_CLIENT_ONE_INFLIGHT_CALL_NO_RETRY_OR_RESET_AFTER_UNCERTAINTY",
                "FINITE_JSON_CONTENT_IS_AN_OPAQUE_PROJECTION_NOT_EFFECT_CAUSATION",
                "NO_HARD_HEAP_CPU_LATENCY_OR_COMPLETE_CAPTURE_QUALIFICATION",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise NativeToolClientOverlayError("cannot materialize native client") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_native_tool_client(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
