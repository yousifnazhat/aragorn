"""Render a worker-lifetime create/attempt gate; never stage or activate it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_runtime_native_tool_receipts as base

overlay = base.base.base.overlay
_WORKER = base._WORKER
_INPUT = (
    44163,
    "sha256:0ccf4c808e006ff9464582014dda22497b2607512543392d4a83c9878e57b50c",
)
_OUTPUT = (
    46629,
    "sha256:df55f788ed29d188c71ca201d5778e7bff734b9a2f09445d8247c4ab6f40cd32",
)
_DEPENDENCIES = {
    "scripts/materialize_runtime_native_tool_receipts.py": (
        23173,
        "sha256:f5e166d5334204ffeb44a30ac0e4835abdda6481c7d733d07307e03c0643ca32",
    ),
    "src/aragorn/runtime_native_tool_receipts.py": (
        22210,
        "sha256:b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
    ),
}


class NativeCreateGateOverlayError(ValueError):
    """The fixed predecessor, transform or read-only publication changed."""


_GATE = '''def _relay_native_attempt_once(
    request: dict[str, Any],
    config: RuntimeActionWorkerConfig,
    *,
    deadline: float,
    native_receipts: _receipts.NativeToolReceiptStore,
    relayed_native_attempts: set[str],
) -> dict[str, Any]:
    """Bind one relay to a held open create report, not to true native causation."""
    validated, _payload = _worker_request(request)
    request_digest = canonical_digest(validated)
    with native_receipts._locked() as fd:
        state, receipts = native_receipts._load(fd)
        _receipts._trust(
            type(relayed_native_attempts) is set
            and len(relayed_native_attempts) <= _receipts._MAX_CALLS
            and not native_receipts._halted
        )
        _receipts._require(len(receipts) % 2 == 1)
        attempt = receipts[-1]
        event = attempt["event"]
        attempt_digest = canonical_digest(attempt)
        _receipts._require(
            event["tool_name"] == "aragorn_runtime_create"
            and event["worker_request_digest"] == request_digest
            and all(
                event[name] == validated[name]
                for name in ("run_id", "session_id", "tool_call_digest")
            )
            and attempt_digest not in relayed_native_attempts
            and len(relayed_native_attempts) < _receipts._MAX_CALLS
        )
        before = canonical_digest(state)
        # Consumption precedes every possible sensor connection. Neither a
        # NOT_SUBMITTED nor an INDETERMINATE reply permits automatic retry.
        # Restart with this unmatched attempt is already refused by the core.
        relayed_native_attempts.add(attempt_digest)
        try:
            return _relay_request(validated, config, deadline=deadline)
        finally:
            # Keep the core lock through relay and recheck the same full chain;
            # cooperating terminal writers cannot close/replace the attempt.
            native_receipts._load(fd, expected_state_digest=before)
            _receipts._trust(not native_receipts._halted)


'''

_REPLACEMENTS = (
    (
        "    receipt_failure: _receipts.NativeToolReceiptFatal | None = None\n",
        (
            "    receipt_failure: _receipts.NativeToolReceiptFatal | None = None\n"
            "    relayed_native_attempts: set[str] = set()\n"
        ),
    ),
    (
        "                        native_receipts=native_receipts,\n",
        (
            "                        native_receipts=native_receipts,\n"
            "                        relayed_native_attempts=relayed_native_attempts,\n"
        ),
    ),
    (
        "    native_receipts: _receipts.NativeToolReceiptStore,\n) -> None:\n",
        (
            "    native_receipts: _receipts.NativeToolReceiptStore,\n"
            "    relayed_native_attempts: set[str],\n) -> None:\n"
        ),
    ),
    (
        (
            "        # Receipt-only requests never enter this existing effect relay. This\n"
            "        # transport slice does not yet require a matching attempt for creates.\n"
            "        result = _relay_request(request, config, deadline=deadline)\n"
        ),
        (
            "        # Receipt-only requests return before the held open-attempt gate.\n"
            "        try:\n"
            "            result = _relay_native_attempt_once(\n"
            "                request, config, deadline=deadline,\n"
            "                native_receipts=native_receipts,\n"
            "                relayed_native_attempts=relayed_native_attempts,\n"
            "            )\n"
            "        except _receipts.NativeToolReceiptRejected as exc:\n"
            "            raise RuntimeActionWorkerError(\n"
            '                "native create attempt refused"\n'
            "            ) from exc\n"
        ),
    ),
    ("def _relay_request(\n", _GATE + "def _relay_request(\n"),
)


def _transform(raw: bytes) -> bytes:
    if type(raw) is not bytes or len(raw) != _INPUT[0]:
        raise NativeCreateGateOverlayError("native gate input size changed")
    if overlay._digest(raw) != _INPUT[1]:
        raise NativeCreateGateOverlayError("native gate input digest changed")
    for before, after in _REPLACEMENTS:
        raw = base._replace(raw, before, after)
    return raw


def _verified_inputs() -> bytes:
    if base._ROOT != _ROOT:
        raise NativeCreateGateOverlayError("native gate source roots disagree")
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    rendered = base._verified_inputs()
    if set(rendered) != set(base._OUTPUTS):
        raise NativeCreateGateOverlayError("native gate predecessor inventory changed")
    raw = _transform(rendered[_WORKER])
    if (len(raw), overlay._digest(raw)) != _OUTPUT:
        raise NativeCreateGateOverlayError("native gate output changed")
    return raw


def materialize_runtime_native_create_gate(output: Path) -> dict[str, Any]:
    """Publish a source override; unchanged broker gates still own effects."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeCreateGateOverlayError("output must be an absent absolute Path")
        raw = _verified_inputs()
        overlay._write_overlay(output, {Path(_WORKER).name: raw}, ())
        if _verified_inputs() != raw:
            raise NativeCreateGateOverlayError("native gate source changed")
        return {
            "schema": "aragorn/runtime-native-create-gate-source-overlay/v1",
            "authority": "PINNED_CREATE_ATTEMPT_GATE_SOURCE_ONLY_NOT_DEPLOYMENT_OR_RUN_AUTHORITY",
            "files": [
                {"name": Path(_WORKER).name, "bytes": len(raw), "digest": _OUTPUT[1]}
            ],
            "predecessor_worker": {
                "name": _WORKER,
                "bytes": _INPUT[0],
                "digest": _INPUT[1],
            },
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _DEPENDENCIES.items()
            ],
            "standalone_executable": False,
            "production_activation_eligible": False,
            "native_hook_reachability": False,
            "native_causation_verified": False,
            "mandatory_capture": False,
            "run_eligible": False,
            "limitations": [
                "REQUIRES_COMPLETE_PINNED_RECEIPT_TRANSPORT_AND_QUARANTINE_PROFILE",
                "REQUIRES_ROOT_PROVISIONED_GENESIS_STATE_CREDENTIALS_AND_ACTIVATOR_PINS",
                "AUTHENTICATED_GATEWAY_REPORTS_DO_NOT_PROVE_NATIVE_TOOL_CAUSATION",
                "PARAMS_AND_SESSION_KEY_ARE_NOT_RECONSTRUCTED_FROM_WORKER_REQUEST",
                "ONE_WORKER_LIFETIME_NO_RESET_REPAIR_OR_RETRY_AFTER_CONSUMPTION",
                "NO_HOSTILE_OWNER_ROLLBACK_RESISTANCE_OR_LATENCY_QUALIFICATION",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NativeCreateGateOverlayError(
            "cannot materialize native create gate"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_native_create_gate(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
