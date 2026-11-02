"""Render mandatory private read/create hooks over exact OpenClaw sources."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_native_gateway_credentials as credentials
from scripts import materialize_runtime_native_tool_client as client

overlay = client.overlay
_UPSTREAM = _ROOT.parent / "openclaw-session-snapshot-fix"
_SOURCE = "7fa98d8e21b6d5937f25a7f19445ff683bb980bf"
_WRAPPER = "src/agents/agent-tools.before-tool-call.ts"
_ADAPTER = "src/agents/agent-tool-definition-adapter.ts"
_INTEGRATION = "packaging/openclaw/aragorn-runtime-native-tool-client/integration.cjs"
_UPSTREAM_INPUTS = {
    _WRAPPER: (
        71947,
        "sha256:4aed265d569aafcb4146bccd12c1e79670385d10428ef07595a31e8176511426",
    ),
    _ADAPTER: (
        19034,
        "sha256:79cd78f240443ebbf7215499139f92711992f3b4b2b700575a043043a793a2ee",
    ),
}
_INTEGRATION_PIN = (
    5149,
    "sha256:a542165168c1d5655cad4fdde1e69609cfd87bfea2b9909a9343bcde00e1bbad",
)
_DEPENDENCIES = {
    "scripts/materialize_runtime_native_tool_client.py": (
        5782,
        "sha256:a3e136bac65092c7bb51e539d10ee34a30c0bbe47dad0f3abd5c9f3d543069e7",
    ),
    "scripts/materialize_runtime_native_gateway_credentials.py": (
        13690,
        "sha256:f25a6dee913f1b9c73ec26effe6a39669e3fc800d20d6789e24c5fc5e1c6ac18",
    ),
}
_CLIENT_PIN = (
    35434,
    "sha256:193415bea885023664ac44931d9faa096e02b3bc64aafc47113c17aca664566c",
)
_CREDENTIAL_PINS = {
    "runtime_native_gateway_credentials.py": (
        10362,
        "sha256:7cfdcf2a6ac8ee49af900b486f0e67ec9a44a5e86c0f752fd891dc1225adcaae",
    ),
    "aragorn-runtime-native-gateway-credentials.py": (
        353,
        "sha256:30fea987fff036b206852e008b67f0eea4e9d805a43449e3f73ed3c8327b2865",
    ),
    "aragorn-agent-gateway.service": (
        3564,
        "sha256:7c9993591363e382ceed407f055a48fe2b5fc539387342487f43ce3575d27317",
    ),
}
_OUTPUTS = {
    "agent-tools.before-tool-call.ts": (
        72258,
        "sha256:5171c9d332d132ead4e86916108cbe10aec8d37d21a753ce7e14a887e90173ff",
    ),
    "agent-tool-definition-adapter.ts": (
        19600,
        "sha256:6e4f45ded2f835c2ae366c4282a1db04bdffa2aae13691b902f79140ee63687c",
    ),
    "aragorn-native-tool-execution.ts": (
        913,
        "sha256:b0e4316eea304a40e7a31b7c26a0dfc33f85a17152e32632a0ad344e17d0f0a4",
    ),
    "integration.cjs": _INTEGRATION_PIN,
}
_BRIDGE = b"""// Private fixed-profile bridge. No optional hooks or caller-selected loader.
import { createRequire } from "node:module";

type NativeContext = {
  runId: unknown;
  sessionId: unknown;
  sessionKey: unknown;
  toolCallId: unknown;
};
type Bridge = {
  execute<T>(
    name: string,
    params: unknown,
    context: NativeContext,
    invoke: (detached: unknown) => T | Promise<T>,
    signal?: AbortSignal,
  ): Promise<T>;
};
// Absolute CJS resolution gives every compiled caller the same cached client.
const bridge = createRequire(import.meta.url)(
  "/usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client/integration.cjs",
) as Bridge;

export function executeAragornNativeTool<T>(
  name: string,
  params: unknown,
  context: NativeContext,
  invoke: (detached: unknown) => T | Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  return bridge.execute(name, params, context, invoke, signal);
}
"""
_IMPORT = (
    'import { executeAragornNativeTool } from "./aragorn-native-tool-execution.js";\n'
)
_REPLACEMENTS = {
    _WRAPPER: (
        (
            'import { normalizeFileToolPathParam } from "./agent-tools.params.js";\n',
            'import { normalizeFileToolPathParam } from "./agent-tools.params.js";\n'
            + _IMPORT,
        ),
        (
            "        const result = await execute(toolCallId, executeParams, signal, onUpdate);\n",
            """        const result = await executeAragornNativeTool(
          toolName,
          executeParams,
          { runId: ctx?.runId, sessionId: ctx?.sessionId, sessionKey: ctx?.sessionKey, toolCallId },
          (detachedParams) => execute(toolCallId, detachedParams, signal, onUpdate),
          signal,
        );
""",
        ),
    ),
    _ADAPTER: (
        (
            '  runBeforeToolCallHook,\n} from "./agent-tools.before-tool-call.js";\n',
            '  runBeforeToolCallHook,\n} from "./agent-tools.before-tool-call.js";\n'
            + _IMPORT,
        ),
        (
            "          const rawResult = await tool.execute(toolCallId, executeParams, signal, onUpdate);\n",
            """          const rawResult = beforeHookWrapped
            ? await tool.execute(toolCallId, executeParams, signal, onUpdate)
            : await executeAragornNativeTool(
                name,
                executeParams,
                {
                  runId: hookContext?.runId,
                  sessionId: hookContext?.sessionId,
                  sessionKey: hookContext?.sessionKey,
                  toolCallId,
                },
                (detachedParams) => tool.execute(toolCallId, detachedParams, signal, onUpdate),
                signal,
              );
""",
        ),
    ),
}


class NativeToolHookOverlayError(ValueError):
    """A fixed source, exact wrapper boundary, or publication was refused."""


def _upstream_bytes(name: str) -> bytes:
    if name not in _UPSTREAM_INPUTS:
        raise NativeToolHookOverlayError("unsupported upstream source")
    result = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-C",
            str(_UPSTREAM),
            "show",
            f"{_SOURCE}:{name}",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    raw = result.stdout
    if (
        result.returncode != 0
        or result.stderr
        or (len(raw), overlay._digest(raw)) != _UPSTREAM_INPUTS[name]
    ):
        raise NativeToolHookOverlayError("upstream source identity changed")
    return raw


def _transform(name: str, raw: bytes) -> bytes:
    if (
        name not in _UPSTREAM_INPUTS
        or type(raw) is not bytes
        or len(raw) != _UPSTREAM_INPUTS[name][0]
        or overlay._digest(raw) != _UPSTREAM_INPUTS[name][1]
    ):
        raise NativeToolHookOverlayError("native hook input changed")
    original = raw
    for before, after in _REPLACEMENTS[name]:
        raw = credentials._replace(raw, before, after)
    restored = raw
    for before, after in reversed(_REPLACEMENTS[name]):
        restored = credentials._replace(restored, after, before)
    if restored != original:
        raise NativeToolHookOverlayError("unrelated native behavior changed")
    return raw


def _verified_inputs() -> dict[str, bytes]:
    if client._ROOT != _ROOT or credentials._ROOT != _ROOT:
        raise NativeToolHookOverlayError("native hook source roots disagree")
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    native_client = client._verified_inputs()
    if (len(native_client), overlay._digest(native_client)) != _CLIENT_PIN:
        raise NativeToolHookOverlayError("native client identity changed")
    projected = credentials._verified_inputs()
    if {
        name: (len(raw), overlay._digest(raw)) for name, raw in projected.items()
    } != _CREDENTIAL_PINS:
        raise NativeToolHookOverlayError("gateway credential sources changed")
    integration = overlay._read_pinned(_INTEGRATION, *_INTEGRATION_PIN, root=_ROOT)
    rendered = {
        Path(name).name: _transform(name, _upstream_bytes(name))
        for name in _UPSTREAM_INPUTS
    }
    rendered["aragorn-native-tool-execution.ts"] = _BRIDGE
    rendered["integration.cjs"] = integration
    if {
        name: (len(raw), overlay._digest(raw)) for name, raw in rendered.items()
    } != _OUTPUTS:
        raise NativeToolHookOverlayError("native hook output identity changed")
    return rendered


def materialize_runtime_native_tool_hooks(output: Path) -> dict[str, Any]:
    """Publish four unbuilt sources; preserve all deployment/coverage ceilings."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeToolHookOverlayError("output must be an absent absolute Path")
        rendered = _verified_inputs()
        overlay._write_overlay(output, rendered, ())
        if _verified_inputs() != rendered:
            raise NativeToolHookOverlayError("native hook sources changed")
        return {
            "schema": "aragorn/runtime-native-tool-hook-source-overlay/v1",
            "authority": "UNBUILT_PRIVATE_READ_CREATE_SOURCE_ONLY_NOT_DEPLOYMENT_CAUSATION_OR_RUN_AUTHORITY",
            "upstream_commit": _SOURCE,
            "upstream_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _UPSTREAM_INPUTS.items()
            ],
            "source_input": {
                "name": _INTEGRATION,
                "bytes": _INTEGRATION_PIN[0],
                "digest": _INTEGRATION_PIN[1],
            },
            "files": [
                {"name": name, "bytes": len(raw), "digest": overlay._digest(raw)}
                for name, raw in rendered.items()
            ],
            "required_companion_client_not_included": {
                "name": client._PLUGIN,
                "bytes": _CLIENT_PIN[0],
                "digest": _CLIENT_PIN[1],
            },
            "required_companion_credentials_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _CREDENTIAL_PINS.items()
            ],
            "source_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _DEPENDENCIES.items()
            ],
            "runtime_build_identity": None,
            "standalone_executable": False,
            "production_activation_eligible": False,
            "native_hook_reachability": False,
            "native_causation_verified": False,
            "mandatory_capture": False,
            "run_eligible": False,
            "limitations": [
                "ONLY_READ_AND_ARAGORN_RUNTIME_CREATE_OTHER_TOOL_NAMES_REFUSE",
                "RAW_CALLBACK_RETURN_OR_THROW_ONLY_NOT_PROGRESS_TRANSCRIPT_OR_DIAGNOSTIC_OUTPUT",
                "EXISTING_ADAPTER_MAY_PRESENT_TOOL_ERRORS_CLIENT_UNCERTAINTY_REMAINS_STICKY",
                "REQUIRES_FULL_PINNED_OPENCLAW_BUILD_TYPECHECK_AND_COMPILED_IMPORT_CLOSURE",
                "REQUIRES_RENDERED_NATIVE_CLIENT_CREATE_GATE_AND_CREDENTIAL_COMPANIONS",
                "REQUIRES_ACTIVATOR_STAGER_PINS_ROOT_PROVISIONING_AND_AUTHORIZED_LINUX_VALIDATION",
                "NO_HOSTILE_SAME_PROCESS_JAVASCRIPT_BOUNDARY_OR_COMPLETE_CAPTURE_QUALIFICATION",
            ],
        }
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        raise NativeToolHookOverlayError(
            "cannot materialize native tool hooks"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_native_tool_hooks(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
