"""Render a fixed read-only gateway credential helper; never install or run it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay

_HELPER = "src/aragorn/runtime_skill_startup_service.py"
_SHIM = "packaging/libexec/aragorn-runtime-skill-startup-service.py"
_UNIT = "packaging/systemd/aragorn-agent-gateway.service"
_INPUTS = {
    _HELPER: (
        8385,
        "sha256:a1a8ebb31cd934cfa62a74622a8861eae0a999e97bf1babf4c3824443abcb033",
    ),
    _SHIM: (
        346,
        "sha256:6cb66e92136e34e9c478499e0ab1bebc25d4b8341db65c41aead82fbe3d1dffd",
    ),
    _UNIT: (
        3437,
        "sha256:70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067",
    ),
}
_DEPENDENCIES = {
    "src/aragorn/runtime_action_worker.py": (
        37878,
        "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
    ),
    "scripts/materialize_protected_install_quarantine_producers.py": (
        8703,
        "sha256:91cae167762c4aca7527fcd14952990059ebe8e4d37d3e2e64b102843f27e164",
    ),
    "src/aragorn/runtime_native_tool_receipts.py": (
        22210,
        "sha256:b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
    ),
    "src/aragorn/runtime_action_broker.py": (
        79641,
        "sha256:94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21",
    ),
    "src/aragorn/oci_worker_protocol.py": (
        22775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
    ),
}
_OUTPUTS = {
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


class NativeGatewayCredentialOverlayError(ValueError):
    """A fixed input, transformation, or read-only publication changed."""


_APPLICATION = '''def _identities() -> tuple[int, int, int, int]:
    if sys.platform != "linux":
        raise RuntimeSkillStartupServiceError("Linux execution is required")
    gateway = pwd.getpwnam("aragorn-agent-gateway")
    worker = pwd.getpwnam("aragorn-runtime")
    gateway_group = grp.getgrnam("aragorn-agent-gateway")
    worker_group = grp.getgrnam("aragorn-runtime")
    identities = (
        gateway.pw_uid, gateway_group.gr_gid, worker.pw_uid, worker_group.gr_gid
    )
    for identity in identities:
        receipts._uint(identity, 2**32 - 1, 1)
    uid, gid, worker_uid, worker_gid = identities
    if (
        uid == worker_uid or gid == worker_gid
        or gateway.pw_gid != gid or worker.pw_gid != worker_gid
        or os.getuid() != uid or os.geteuid() != uid
        or os.getgid() != gid or os.getegid() != gid
        or any(group != gid for group in os.getgroups())
    ):
        raise RuntimeSkillStartupServiceError("gateway process identity is invalid")
    return identities


def _configuration(config: dict[str, Any], identities: tuple[int, int, int, int]) -> dict[str, Any]:
    uid, gid, worker_uid, _worker_gid = identities
    worker_config = {
        "expectedGatewayGid": gid,
        "expectedGatewayUid": uid,
        "expectedWorkerUid": worker_uid,
        "workerSocketPath": "/run/aragorn-runtime-action-worker/worker.sock",
    }
    expected_plugins = {
        "allow": ["aragorn-runtime-action-worker"],
        "enabled": True,
        "entries": {
            "aragorn-runtime-action-worker": {"config": worker_config, "enabled": True}
        },
        "load": {"paths": ["/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"]},
    }
    if canonical_json(config.get("plugins")) != canonical_json(expected_plugins):
        raise RuntimeSkillStartupServiceError("gateway plugin configuration is invalid")
    return worker_config


def _genesis(value: dict[str, Any], identities: tuple[int, int, int, int]) -> str:
    receipts._exact(value, receipts._GENESIS_FIELDS)
    if (
        value["schema"] != "aragorn/native-tool-receipt-genesis/v1"
        or value["authority"] != "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY"
    ):
        raise RuntimeSkillStartupServiceError("gateway genesis schema is invalid")
    for name in ("stream_id", "runtime_digest", "policy_digest"):
        receipts._digest(value[name])
    receipts._uint(value["policy_version"], 2**53 - 1, 1)
    for name, expected in zip(("worker_uid", "worker_gid"), identities[2:], strict=True):
        receipts._uint(value[name], 2**32 - 1, 1)
        if value[name] != expected:
            raise RuntimeSkillStartupServiceError("gateway genesis identity is unbound")
    return canonical_digest(value)


def _run() -> dict[str, Any]:
    # Only projected root credentials supply trust. No ACK, worker state, mutable
    # OpenClaw context or application config is consulted for genesis identity.
    identities = _identities()
    entries: list[_Held] = []
    try:
        directory_fd = _open_directory(identities[0], entries)
        config = _parse_canonical_document(
            _read_credential(directory_fd, "openclaw-config", identities[0], entries, 64 * 1024),
            "gateway configuration",
        )
        genesis = _parse_canonical_document(
            _read_credential(directory_fd, "native-tool-genesis", identities[0], entries, 4096),
            "gateway native genesis",
        )
        result = {
            "worker_config": _configuration(config, identities),
            "genesis_digest": _genesis(genesis, identities),
        }
        _recheck(entries, directory_fd)
        if len(canonical_json(result)) > 1024:
            raise RuntimeSkillStartupServiceError("gateway credential result exceeds its bound")
        return result
    finally:
        failure = None
        for entry in reversed(entries):
            try:
                os.close(entry.fd)
            except BaseException as exc:  # noqa: BLE001 - close every held FD and refuse uncertainty
                failure = failure or exc
        if failure is not None:
            raise RuntimeSkillStartupServiceError("gateway credential cleanup failed") from failure


def main(argv: Sequence[str] | None = None) -> int:
    """No arguments, no credential content in errors, bounded canonical output."""
    if list(sys.argv[1:] if argv is None else argv):
        print("usage: aragorn-runtime-native-gateway-credentials", file=sys.stderr)
        return 64
    try:
        raw = canonical_json(_run())
        if len(raw) > 1024 or sys.stdout.write(raw.decode("ascii")) != len(raw):
            raise RuntimeSkillStartupServiceError("gateway credential output failed")
        sys.stdout.flush()
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - fixed fail-closed boundary
        print("aragorn native gateway credentials: verification failed", file=sys.stderr)
        return 126
    return 0
'''


def _replace(raw: bytes, before: str, after: str) -> bytes:
    expected = before.encode("ascii")
    if raw.count(expected) != 1:
        raise NativeGatewayCredentialOverlayError("credential source shape changed")
    return raw.replace(expected, after.encode("ascii"))


def _render_helper(raw: bytes) -> bytes:
    boundary = b"\ndef _binding("
    if raw.count(boundary) != 1:
        raise NativeGatewayCredentialOverlayError(
            "credential application boundary changed"
        )
    prefix = raw.split(boundary)[0]
    doc, separator, body = prefix.partition(b"\n\nfrom __future__ import annotations\n")
    if not doc.startswith(b'"""Fixed-credential') or not separator:
        raise NativeGatewayCredentialOverlayError("credential module header changed")
    prefix = (
        b'"""Fixed projected gateway credentials; no acquisition, execution or RUN authority."""'
        + separator
        + body
    )
    for before, after in (
        ("import os\n", "import grp\nimport os\nimport pwd\n"),
        (
            "from . import runtime_action_worker as worker\nfrom . import runtime_skill_startup as startup\n",
            "from . import runtime_native_tool_receipts as receipts\nfrom .oci_worker_protocol import canonical_digest, canonical_json\n",
        ),
        (
            'Path("/run/credentials/aragorn-runtime-action-worker.service")',
            'Path("/run/credentials/aragorn-agent-gateway.service")',
        ),
        (
            'frozenset({"worker-binding", "openclaw-config"})',
            'frozenset({"native-tool-genesis", "openclaw-config"})',
        ),
    ):
        prefix = _replace(prefix, before, after)
    return prefix + b"\n" + _APPLICATION.encode("ascii")


def _render(inputs: dict[str, bytes]) -> dict[str, bytes]:
    if set(inputs) != set(_INPUTS):
        raise NativeGatewayCredentialOverlayError("credential input inventory changed")
    for name, raw in inputs.items():
        size, digest = _INPUTS[name]
        if type(raw) is not bytes or len(raw) != size or overlay._digest(raw) != digest:
            raise NativeGatewayCredentialOverlayError(
                "credential input identity changed"
            )
    shim = _replace(
        inputs[_SHIM],
        "runtime skill pre-start check",
        "native gateway credential check",
    )
    shim = _replace(
        shim,
        "aragorn.runtime_skill_startup_service",
        "aragorn.runtime_native_gateway_credentials",
    )
    unit = _replace(
        inputs[_UNIT],
        "LoadCredential=openclaw-config:/etc/aragorn/agent-gateway/openclaw.json\n",
        "LoadCredential=openclaw-config:/etc/aragorn/agent-gateway/openclaw.json\n"
        "LoadCredential=native-tool-genesis:/etc/aragorn/runtime-native-tool-genesis.json\n",
    )
    unit = _replace(
        unit,
        "InaccessiblePaths=/etc/aragorn/agent-gateway\n",
        "InaccessiblePaths=/etc/aragorn/agent-gateway /etc/aragorn/runtime-native-tool-genesis.json\n",
    )
    return dict(
        zip(_OUTPUTS, (_render_helper(inputs[_HELPER]), shim, unit), strict=True)
    )


def _verified_inputs() -> dict[str, bytes]:
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    rendered = _render(
        {
            name: overlay._read_pinned(name, *pin, root=_ROOT)
            for name, pin in _INPUTS.items()
        }
    )
    for name, raw in rendered.items():
        if (len(raw), overlay._digest(raw)) != _OUTPUTS[name]:
            raise NativeGatewayCredentialOverlayError(
                "credential output identity changed"
            )
    return rendered


def materialize_runtime_native_gateway_credentials(output: Path) -> dict[str, Any]:
    """Publish three sources only; no deployed credential or native-hook claim."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeGatewayCredentialOverlayError(
                "output must be an absent absolute Path"
            )
        rendered = _verified_inputs()
        overlay._write_overlay(output, rendered, ())
        if _verified_inputs() != rendered:
            raise NativeGatewayCredentialOverlayError("credential source changed")
        return {
            "schema": "aragorn/runtime-native-gateway-credential-source-overlay/v1",
            "authority": "PINNED_PROJECTED_CREDENTIAL_SOURCE_ONLY_NOT_DEPLOYMENT_OR_RUN_AUTHORITY",
            "files": [
                {"name": name, "bytes": len(raw), "digest": overlay._digest(raw)}
                for name, raw in rendered.items()
            ],
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
            "gateway_credential_projection_verified": False,
            "native_hook_reachability": False,
            "run_eligible": False,
            "limitations": [
                "REQUIRES_ROOT_PROVISIONED_SAME_SOURCE_GENESIS_IN_GATEWAY_AND_WORKER",
                "REQUIRES_FIXED_NATIVE_CLIENT_BOOTSTRAP_AND_MANDATORY_READ_CREATE_WRAPPERS",
                "REQUIRES_COMPLETE_IMPORT_CLOSURE_AND_ACTIVATOR_STAGER_UNIT_SOURCE_PINS",
                "CREDENTIAL_SNAPSHOT_IS_NOT_PROCESS_CONSUMPTION_OR_NATIVE_CAUSATION",
                "NO_RECEIPT_STORE_ACCESS_REPAIR_EFFECT_OR_COMPLETE_CAPTURE_AUTHORITY",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NativeGatewayCredentialOverlayError(
            "cannot materialize gateway credentials"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_native_gateway_credentials(
        parser.parse_args().output
    )
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
