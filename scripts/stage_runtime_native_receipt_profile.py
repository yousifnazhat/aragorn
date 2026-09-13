"""Stage the fixed native read/create receipt profile in a new DESTDIR only."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_native_create_gate as gate
from scripts import materialize_runtime_native_gateway_credentials as credentials
from scripts import materialize_runtime_native_tool_client as client
from scripts import materialize_runtime_native_tool_receipts as receipts
from scripts import stage_runtime_broker_response_drain_profile as drain

base = drain.base
_ACTIVATOR = drain._ACTIVATOR
_CORE = receipts._CORE
_PROVISIONER = "src/aragorn/runtime_native_tool_provisioning.py"
_GATEWAY_HELPER = "src/aragorn/runtime_native_gateway_credentials.py"
_GATEWAY_SHIM = "packaging/libexec/aragorn-runtime-native-gateway-credentials.py"
_INTEGRATION = "packaging/openclaw/aragorn-runtime-native-tool-client/integration.cjs"
_NEW_DIRECTORY = "usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client"
_SCHEMA = "aragorn/runtime-native-receipt-staged-profile/v1"
_AUTHORITY = (
    "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_PROVISIONING_DEPLOYMENT_OR_RUN_AUTHORITY"
)
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 31988,
    "file_count": 31970,
    "symlink_count": 18,
    "total_bytes": 289776316,
    "tree_digest": "sha256:4e6e94cf4fb8a2527ec1cd789b20a7ddf6c84f03973b3579ded64ef8e2ef96c3",
}
_ENTRYPOINT = (
    23463,
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
)
_DIRECT_PINS = {
    "scripts/stage_runtime_broker_response_drain_profile.py": (
        13562,
        "sha256:f492ff2433fe9bf1d680c4c4e0d3133e9f0a319c5d7fb3560e13e8a3df6b528a",
    ),
    "scripts/materialize_runtime_native_tool_receipts.py": (
        23173,
        "sha256:f5e166d5334204ffeb44a30ac0e4835abdda6481c7d733d07307e03c0643ca32",
    ),
    "scripts/materialize_runtime_native_create_gate.py": (
        8686,
        "sha256:91b377340c5bffaf4cca0af676501c3d674663d4ede21afa43d215385269243b",
    ),
    "scripts/materialize_runtime_native_tool_client.py": (
        5782,
        "sha256:a3e136bac65092c7bb51e539d10ee34a30c0bbe47dad0f3abd5c9f3d543069e7",
    ),
    "scripts/materialize_runtime_native_gateway_credentials.py": (
        13690,
        "sha256:f25a6dee913f1b9c73ec26effe6a39669e3fc800d20d6789e24c5fc5e1c6ac18",
    ),
    _PROVISIONER: (
        15105,
        "sha256:d5944c938677dc4e5c693627629194e3869a76abbf695b710d8f9965833aaee0",
    ),
    _INTEGRATION: (
        5149,
        "sha256:a542165168c1d5655cad4fdde1e69609cfd87bfea2b9909a9343bcde00e1bbad",
    ),
}
_SOURCE_PINS = {
    **drain._SOURCE_PINS,
    **receipts._DEPENDENCIES,
    **gate._DEPENDENCIES,
    **client._INPUTS,
    **client._DEPENDENCIES,
    **credentials._INPUTS,
    **credentials._DEPENDENCIES,
    **_DIRECT_PINS,
}
_ACTIVATOR_PIN = (
    38837,
    "sha256:dad9cf54d27b50abea74af6159319c2b5d05a12c9cdf74d931b4b105a1b01285",
)
_OUTPUT_PINS = {
    **receipts._OUTPUTS,
    receipts._WORKER: gate._OUTPUT,
    client._PLUGIN: client._OUTPUT,
    credentials._UNIT: credentials._OUTPUTS["aragorn-agent-gateway.service"],
    _GATEWAY_HELPER: credentials._OUTPUTS["runtime_native_gateway_credentials.py"],
    _GATEWAY_SHIM: credentials._OUTPUTS[
        "aragorn-runtime-native-gateway-credentials.py"
    ],
    _CORE: receipts._DEPENDENCIES[_CORE],
    _PROVISIONER: _DIRECT_PINS[_PROVISIONER],
    _INTEGRATION: _DIRECT_PINS[_INTEGRATION],
}
_OLD_RUNTIME = (
    "45860:45841:19:369443243:"
    "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154:"
    + _ENTRYPOINT[1]
)
_NEW_RUNTIME = (
    "31988:31970:18:289776316:" + _RUNTIME_TREE["tree_digest"] + ":" + _ENTRYPOINT[1]
)
_BINDING_CHECK = """def verify_native_sources(worker_uid, worker_gid):
    # Read the fixed root sources, not projected credentials or mutable state.
    # These custody helpers acquire no activation lock and perform no writes.
    provisioning._require_root()
    held = []
    try:
        parent = provisioning._root_directory(Path("/etc/aragorn"), held)
        binding_file = provisioning._hold_file(
            parent, "runtime-action-worker.json", 0, 0, 0o400, 4096, held
        )
        binding = provisioning.startup._binding(binding_file.raw)
        genesis_file = provisioning._hold_file(
            parent, "runtime-native-tool-genesis.json", 0, 0, 0o400, 4096, held
        )
        genesis = provisioning.broker._parse_canonical_document(
            genesis_file.raw, "native genesis source"
        )
        gateway_credentials._genesis(genesis, (0, 0, worker_uid, worker_gid))
        if binding.runtime_digest != "RUNTIME_DIGEST" or any(
            type(genesis[name]) is not type(expected) or genesis[name] != expected
            for name, expected in (
                ("runtime_digest", binding.runtime_digest),
                ("policy_digest", binding.policy_digest),
                ("policy_version", binding.policy_version),
            )
        ):
            raise SystemExit("native runtime binding changed")
        provisioning._recheck(held)
    finally:
        provisioning._close(held)


verify_native_sources(int(sys.argv[1]), int(sys.argv[2]))
""".replace("RUNTIME_DIGEST", _RUNTIME_TREE["tree_digest"])


class RuntimeNativeReceiptStageError(ValueError):
    """A pinned input, transformation, custody check or staging operation failed."""


def _destination(name: str) -> tuple[str, int]:
    if name == _INTEGRATION:
        return _NEW_DIRECTORY + "/integration.cjs", 0o644
    return base._destination(name)


def _pin_line(name: str, digest: str) -> str:
    destination, mode = _destination(name)
    return f"{mode:o} {digest[7:]} /{destination}\n"


def _credential_check() -> str:
    # busctl may return either unit directive order; accept every exact
    # permutation, never duplicate, missing, extra or caller-selected sources.
    common = (
        '\\"native-tool-genesis\\" \\"/etc/aragorn/runtime-native-tool-genesis.json\\"'
    )
    worker = (
        '\\"worker-binding\\" \\"$worker_binding\\"',
        '\\"openclaw-config\\" \\"$gateway_config\\"',
        common,
    )
    gateway = (worker[1], common)
    lines = []
    for branch, values in (("worker", worker), ("gateway", gateway)):
        lines.append(
            f'    {"if" if branch == "worker" else "elif"} [ "$verified_unit" = "${branch}_unit" ]; then\n'
        )
        lines.append('        case "$verified_credentials" in\n')
        alternatives = [
            '"a(ss) ' + str(len(values)) + " " + " ".join(order) + '"'
            for order in itertools.permutations(values)
        ]
        lines.append("            " + "|".join(alternatives) + ") ;;\n")
        lines.append(
            '            *) fail_activation "effective LoadCredential is unsafe for $verified_unit" ;;\n'
        )
        lines.append("        esac\n")
    lines.append(
        '    else\n        fail_activation "unexpected credential unit"\n    fi'
    )
    return "".join(lines)


def _render_activator(raw: bytes, original: dict[str, base._Payload]) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != drain._OUTPUTS[_ACTIVATOR]:
        raise RuntimeNativeReceiptStageError("drain activator identity changed")
    replacements = []
    for name, pin in _OUTPUT_PINS.items():
        destination, _mode = _destination(name)
        if destination not in original:
            continue
        before = base.overlay._digest(original[destination][2])
        if name in {receipts._UNIT, credentials._UNIT}:
            replacements.append((before[7:], pin[1][7:]))
        else:
            replacements.append((_pin_line(name, before), _pin_line(name, pin[1])))
    added = "".join(
        _pin_line(name, pin[1])
        for name, pin in sorted(_OUTPUT_PINS.items())
        if _destination(name)[0] not in original
    )
    replacements.extend(
        (
            ("\nEOF\n", "\n" + added + "EOF\n"),
            (_OLD_RUNTIME, _NEW_RUNTIME),
            (base.activation._CREDENTIAL_CHECK, _credential_check()),
            (
                'require_root_secret "$worker_binding" 4096\n',
                (
                    'require_root_secret "$worker_binding" 4096\n'
                    "require_root_secret /etc/aragorn/runtime-native-tool-genesis.json 4096\n"
                ),
            ),
            (
                "runtime_identity=$(/usr/bin/python3.12 -I -S -B - <<'PY'\n",
                'runtime_identity=$(/usr/bin/python3.12 -I -S -B - "$worker_uid" "$worker_gid" <<\'PY\'\n',
            ),
            (
                'import os\nfrom pathlib import Path\n\nroot = Path("/runtime")\n',
                "import os\nimport sys\nfrom pathlib import Path\n\n"
                'sys.path.insert(0, "/usr/lib/aragorn")\n'
                "from aragorn import runtime_native_tool_provisioning as provisioning\n"
                "from aragorn import runtime_native_gateway_credentials as gateway_credentials\n\n"
                + _BINDING_CHECK
                + '\nroot = Path("/runtime")\n',
            ),
            (
                '    require_unit_value "$worker_unit" LimitNOFILESoft 128\n',
                (
                    '    require_unit_value "$worker_unit" LimitNOFILESoft 128\n'
                    '    require_unit_value "$worker_unit" StateDirectory aragorn-runtime-tool-receipts\n'
                    '    require_unit_value "$worker_unit" StateDirectoryMode 0700\n'
                    '    require_unit_value "$worker_unit" RuntimeDirectory aragorn-runtime-action-worker\n'
                    '    require_unit_value "$worker_unit" RuntimeDirectoryMode 0711\n'
                ),
            ),
            (
                'ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"\n',
                (
                    "# StateDirectory is not a substitute for absent-only root provisioning.\n"
                    'require_exact_directory /var/lib/aragorn-runtime-tool-receipts "$worker_uid" "$worker_gid" 700\n'
                    'ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"\n'
                ),
            ),
        )
    )
    original_raw = raw
    for before, after in replacements:
        raw = base.activation._replace(raw, before, after)
    restored = raw
    for before, after in reversed(replacements):
        restored = base.activation._replace(restored, after, before)
    if restored != original_raw:
        raise RuntimeNativeReceiptStageError("native activator changed other behavior")
    return raw


def _verified_payloads() -> tuple[dict[str, base._Payload], dict[str, base._Payload]]:
    if any(
        module._ROOT != _ROOT
        for module in (drain, base, gate, receipts, credentials, client)
    ):
        raise RuntimeNativeReceiptStageError("native source roots disagree")
    inputs = {
        name: base.overlay._read_pinned(name, *pin, root=_ROOT)
        for name, pin in _SOURCE_PINS.items()
    }
    inherited, drained = drain._verified_payloads()
    original = inherited | drained
    rendered = receipts._verified_inputs()
    rendered[receipts._WORKER] = gate._verified_inputs()
    rendered[client._PLUGIN] = client._verified_inputs()
    gateway = credentials._verified_inputs()
    rendered.update(
        {
            credentials._UNIT: gateway["aragorn-agent-gateway.service"],
            _GATEWAY_HELPER: gateway["runtime_native_gateway_credentials.py"],
            _GATEWAY_SHIM: gateway["aragorn-runtime-native-gateway-credentials.py"],
            _CORE: inputs[_CORE],
            _PROVISIONER: inputs[_PROVISIONER],
            _INTEGRATION: inputs[_INTEGRATION],
        }
    )
    if set(rendered) != set(_OUTPUT_PINS):
        raise RuntimeNativeReceiptStageError("native render inventory changed")
    for name, raw in rendered.items():
        if (len(raw), base.overlay._digest(raw)) != _OUTPUT_PINS[name]:
            raise RuntimeNativeReceiptStageError("native output identity changed")
    activator = _render_activator(original[_destination(_ACTIVATOR)[0]][2], original)
    if (len(activator), base.overlay._digest(activator)) != _ACTIVATOR_PIN:
        raise RuntimeNativeReceiptStageError("native activator output identity changed")
    rendered[_ACTIVATOR] = activator
    replacements = {
        _destination(name)[0]: (name, _destination(name)[1], raw)
        for name, raw in rendered.items()
    }
    if (
        len(original) != 55
        or len(replacements) != 12
        or len(original | replacements) != 60
    ):
        raise RuntimeNativeReceiptStageError("native staged inventory changed")
    if base._directories(original | replacements) - base._directories(original) != {
        _NEW_DIRECTORY
    }:
        raise RuntimeNativeReceiptStageError("native directory inventory changed")
    return original, replacements


def _add_directory(output: Path) -> None:
    parent = output / Path(_NEW_DIRECTORY).parent
    before = base._parent_custody(parent)
    fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    child_fd = None
    try:
        if (
            base.overlay._identity(os.fstat(fd))[:5] != before
            or base.overlay._identity(parent.stat())[:5] != before
        ):
            raise RuntimeNativeReceiptStageError("native directory parent changed")
        name = Path(_NEW_DIRECTORY).name
        os.mkdir(name, mode=0o755, dir_fd=fd)
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=fd,
        )
        os.fchmod(child_fd, 0o755)
        metadata = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or os.listdir(child_fd)
            or base.overlay._identity(metadata)
            != base.overlay._identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
            or base._parent_custody(parent) != before
        ):
            raise RuntimeNativeReceiptStageError("native directory custody changed")
        os.fsync(child_fd)
        os.fsync(fd)
    finally:
        try:
            if child_fd is not None:
                os.close(child_fd)
        finally:
            os.close(fd)


def stage_runtime_native_receipt_profile(output: Path) -> dict[str, Any]:
    """Stage only pinned bytes. Failure can leave an unusable partial DESTDIR."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeNativeReceiptStageError(
                "DESTDIR must be an absolute absent Path"
            )
        parent = base._parent_custody(output.parent)
        original, replacements = _verified_payloads()
        report = drain.stage_runtime_broker_response_drain_profile(output)
        if base._parent_custody(output.parent) != parent:
            raise RuntimeNativeReceiptStageError("DESTDIR parent changed")
        base._audit_tree(output, original)
        _add_directory(output)
        base._apply_overrides(output, replacements)
        final = original | replacements
        base._audit_tree(output, final)
        if (
            _verified_payloads() != (original, replacements)
            or base._parent_custody(output.parent) != parent
        ):
            raise RuntimeNativeReceiptStageError("native staging inputs changed")
        dependency_names = {item["name"] for item in report["new_dependencies"]} | {
            source
            for name, (source, _mode, _raw) in replacements.items()
            if name not in original
        }
        dependencies = {
            name: final[_destination(name)[0]][2] for name in sorted(dependency_names)
        }
        return {
            **report,
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {
                    "path": "/" + name,
                    "source_name": source,
                    "bytes": len(raw),
                    "digest": base.overlay._digest(raw),
                    "mode": f"{mode:04o}",
                }
                for name, (source, mode, raw) in sorted(final.items())
            ],
            "directories": ["/" + name for name in sorted(base._directories(final))],
            "new_dependencies": [
                {"name": name, "bytes": len(raw), "digest": base.overlay._digest(raw)}
                for name, raw in dependencies.items()
            ],
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in sorted(_SOURCE_PINS.items())
            ],
            "required_runtime_not_included": {
                "root": "/runtime",
                "tree": dict(_RUNTIME_TREE),
                "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "entrypoint_bytes": _ENTRYPOINT[0],
                "entrypoint_digest": _ENTRYPOINT[1],
            },
            "native_receipt_profile_deployed": False,
            "receipt_state_provisioned": False,
            "gateway_credential_projection_verified": False,
            "native_hook_reachability": False,
            "native_causation_verified": False,
            "mandatory_capture": False,
            "missing_inputs": [
                "separate root-owned Linux deployment, complete measured runtime and coherent control bindings",
                "separate absent-only receipt provisioning before any StateDirectory service start",
                "same-source worker/gateway credentials and real mandatory native read/create validation",
                "no hostile-owner rollback, complete capture, latency or RUN qualification",
                "producer release and full analyzer identity remain separate",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeNativeReceiptStageError(
            "cannot stage native receipt profile"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    try:
        report = stage_runtime_native_receipt_profile(parser.parse_args().output)
    except RuntimeNativeReceiptStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
