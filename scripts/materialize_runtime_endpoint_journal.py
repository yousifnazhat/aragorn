"""Render pinned endpoint journal producers; never install or run services."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay
from scripts import materialize_runtime_quarantine_services as quarantine

_SCHEMA = "aragorn/runtime-endpoint-journal-source-overlay/v1"
_AUTHORITY = "PINNED_JOURNAL_PRODUCER_SOURCE_ONLY_NOT_DEPLOYMENT_OR_RUN_AUTHORITY"
_WORKER = "src/aragorn/runtime_action_worker.py"
_SENSOR = "src/aragorn/runtime_action_observation_publisher_v4.py"
_BROKER = "src/aragorn/runtime_action_broker_v5.py"
_ISSUER = "src/aragorn/runtime_lineage_capability_issuer.py"
_HELPER = "src/aragorn/runtime_endpoint_journal.py"
_WORKER_PIN = (
    37_878,
    "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
)
_HELPER_PIN = (
    13_110,
    "sha256:19221eb7c3ed6ce74122e544b776447ccd72e7f966671f922dffd6c4e344b569",
)
_SUPPORT_PINS = {
    "scripts/materialize_protected_install_quarantine_producers.py": (
        8703,
        "sha256:91cae167762c4aca7527fcd14952990059ebe8e4d37d3e2e64b102843f27e164",
    ),
    "scripts/materialize_runtime_quarantine_services.py": (
        5541,
        "sha256:77f1ffa2a9b4969768853cc6a3b06f6bd1aeed5dd26c563397bafbdb6e89e3d4",
    ),
    "src/aragorn/oci_worker_protocol.py": (
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
    ),
}
_OUTPUTS = {
    _WORKER: (
        38_599,
        "sha256:1a03136a202e5e9f758175b0de9905f1aa1cee3e8e540fc063f8136f7f3b3bf4",
    ),
    _SENSOR: (
        12_882,
        "sha256:becb54691aba35e902c6c65c7a459ccd2e1aeef6018f679c918826e84c18a34b",
    ),
    _BROKER: (
        11_716,
        "sha256:fe0861eec5a3439b142d81e59d50f02516b8ca346408e18465f5276bc60ec496",
    ),
}


class RuntimeEndpointJournalOverlayError(ValueError):
    """A fixed input, boundary replacement, or output identity changed."""


def _replace(raw: bytes, before: str, after: str) -> bytes:
    expected = before.encode("ascii")
    if raw.count(expected) != 1:
        raise RuntimeEndpointJournalOverlayError("endpoint boundary shape changed")
    return raw.replace(expected, after.encode("ascii"))


def _render(name: str, raw: bytes) -> bytes:
    role = {_WORKER: "worker", _SENSOR: "sensor", _BROKER: "broker"}.get(name)
    if role is None:
        raise RuntimeEndpointJournalOverlayError("unsupported endpoint source")
    raw = _replace(
        raw,
        "from .oci_worker_protocol import",
        "from . import runtime_endpoint_journal as _journal\n\nfrom .oci_worker_protocol import",
    )
    arguments = (
        '"broker", RuntimeActionBrokerError, RuntimeActionEffectIndeterminate'
        if role == "broker"
        else f'"{role}"'
    )
    raw = _replace(
        raw,
        "def _handle_connection(\n",
        f"@_journal.endpoint({arguments})\ndef _handle_connection(\n",
    )
    if role == "worker":
        replacements = (
            (
                '    pid, uid, gid = _valid_peer(_peer_credentials(connection), "gateway")\n',
                '    pid, uid, gid = _valid_peer(_peer_credentials(connection), "gateway")\n    _journal.note("peer", (pid, uid, gid))\n',
            ),
            (
                "    deadline = time.monotonic() + timeout_seconds\n    try:\n        request = _read_frame(connection, deadline)\n",
                '    _journal.note("peer_expected")\n    deadline = time.monotonic() + timeout_seconds\n    try:\n        _journal.note("stage", "FRAME")\n        request = _read_frame(connection, deadline)\n        _journal.note("frame")\n        _journal.note("stage", "REQUEST")\n',
            ),
            (
                "        result = _relay_request(request, config, deadline=deadline)\n        _send_frame(connection, canonical_json(result), deadline)\n",
                '        result = _relay_request(request, config, deadline=deadline)\n        _journal.note("worker_result", result)\n        _journal.note("delivery_attempt")\n        _send_frame(connection, canonical_json(result), deadline)\n        _journal.note("delivery_sent")\n',
            ),
            (
                "        validated, payload = _worker_request(request)\n",
                '        validated, payload = _worker_request(request)\n        _journal.note("worker_request", validated)\n',
            ),
            (
                "        sensor = _connect_sensor(config, deadline)\n        submitted = True\n",
                '        _journal.note("action_document", envelope)\n        _journal.note("stage", "BACKEND_CONNECT")\n        sensor = _connect_sensor(config, deadline)\n        submitted = True\n        _journal.note("stage", "FORWARD")\n        _journal.note("submit")\n',
            ),
            (
                "        candidate = _read_frame(sensor, deadline)\n        broker_result = _broker_result(candidate, envelope, config.binding)\n",
                '        candidate = _read_frame(sensor, deadline)\n        _journal.note("stage", "RESULT")\n        broker_result = _broker_result(candidate, envelope, config.binding)\n        _journal.note("broker_result", broker_result)\n',
            ),
        )
    elif role == "sensor":
        replacements = (
            (
                "        pid, uid, gid = runtime_peer\n",
                '        pid, uid, gid = runtime_peer\n        _journal.note("peer", runtime_peer)\n',
            ),
            (
                "        pidfd = open_peer_pidfd(connection, pid)\n",
                '        _journal.note("peer_expected")\n        _journal.note("stage", "PROFILE")\n        pidfd = open_peer_pidfd(connection, pid)\n',
            ),
            (
                "        envelope = _read_frame(connection, deadline)\n",
                '        _journal.note("stage", "FRAME")\n        envelope = _read_frame(connection, deadline)\n        _journal.note("frame")\n        _journal.note("stage", "PROFILE")\n',
            ),
            (
                "                publisher,\n                after,\n            )\n",
                '                publisher,\n                after,\n            )\n            _journal.note("validated_submission", submission)\n            _journal.note("profile", after)\n',
            ),
            (
                "        with _connect_backend(base, deadline) as backend:\n",
                '        _journal.note("stage", "BACKEND_CONNECT")\n        with _connect_backend(base, deadline) as backend:\n',
            ),
            (
                "                _send_frame(backend, canonical_json(issuance), deadline)\n",
                '                _journal.note("stage", "FORWARD")\n                _journal.note("submit")\n                _send_frame(backend, canonical_json(issuance), deadline)\n',
            ),
            (
                "                response = _read_frame(backend, deadline)\n",
                '                response = _read_frame(backend, deadline)\n                _journal.note("stage", "RESULT")\n                _journal.note("reply", response)\n',
            ),
            (
                "        _send_frame(connection, canonical_json(response), deadline)\n",
                '        _journal.note("delivery_attempt")\n        _send_frame(connection, canonical_json(response), deadline)\n        _journal.note("delivery_sent")\n',
            ),
        )
    else:
        replacements = (
            (
                "    pid, uid, gid = _peer_credentials(connection)\n",
                '    pid, uid, gid = _peer_credentials(connection)\n    _journal.note("peer", (pid, uid, gid))\n',
            ),
            (
                "    deadline = time.monotonic() + timeout_seconds\n    result = mediate_lineage_granted_profiled_runtime_create(\n        _read_frame(connection, deadline),\n",
                '    _journal.note("peer_expected")\n    deadline = time.monotonic() + timeout_seconds\n    _journal.note("stage", "FRAME")\n    submission = _read_frame(connection, deadline)\n    _journal.note("frame")\n    _journal.note("stage", "REQUEST")\n    result = mediate_lineage_granted_profiled_runtime_create(\n        submission,\n',
            ),
            (
                "    try:\n        _send_frame(connection, canonical_json(result), deadline)\n",
                '    _journal.note("broker_result", result)\n    try:\n        _journal.note("delivery_attempt")\n        _send_frame(connection, canonical_json(result), deadline)\n        _journal.note("delivery_sent")\n',
            ),
            (
                "    result: dict[str, Any] = {}\n",
                '    _journal.note("validated_submission", _legacy)\n    _journal.note("profile", attribution)\n    _journal.note("stage", "PROFILE")\n    result: dict[str, Any] = {}\n',
            ),
            (
                "            result = mediate_granted_profiled_runtime_create(\n",
                '            _journal.note("stage", "CORE")\n            _journal.note("submit")\n            result = mediate_granted_profiled_runtime_create(\n',
            ),
            (
                "                deadline_monotonic=deadline_monotonic,\n            )\n    except RuntimeActionObservationPublisherError as exc:\n",
                '                deadline_monotonic=deadline_monotonic,\n            )\n            _journal.note("stage", "RESULT")\n            _journal.note("broker_result", result)\n    except RuntimeActionObservationPublisherError as exc:\n',
            ),
        )
    for before, after in replacements:
        raw = _replace(raw, before, after)
    return raw


def _verified_inputs() -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    dependencies = []
    for name, (size, digest) in {**_SUPPORT_PINS, **quarantine._DEPENDENCIES}.items():
        overlay._read_pinned(name, size, digest, root=_ROOT)
        dependencies.append({"name": name, "bytes": size, "digest": digest})
    # Verify the required issuer override too, but do not silently omit its
    # separate staging requirement or emit a conflicting second copy.
    quarantined = {}
    for name, (
        size,
        digest,
        output_size,
        output_digest,
    ) in quarantine._SERVICES.items():
        raw = quarantine._transform(
            overlay._read_pinned(name, size, digest, root=_ROOT)
        )
        if (len(raw), overlay._digest(raw)) != (output_size, output_digest):
            raise RuntimeEndpointJournalOverlayError("quarantine input overlay changed")
        quarantined[name] = raw
    sources = {
        _WORKER: overlay._read_pinned(_WORKER, *_WORKER_PIN, root=_ROOT),
        _SENSOR: quarantined[_SENSOR],
        _BROKER: quarantined[_BROKER],
    }
    rendered = {}
    for name, raw in sources.items():
        result = _render(name, raw)
        if (len(result), overlay._digest(result)) != _OUTPUTS[name]:
            raise RuntimeEndpointJournalOverlayError("journal producer output changed")
        rendered[name] = result
    rendered[_HELPER] = overlay._read_pinned(_HELPER, *_HELPER_PIN, root=_ROOT)
    return rendered, dependencies


def materialize_runtime_endpoint_journal(output: Path) -> dict[str, Any]:
    """Write four pinned read-only modules, not a complete deployable package."""
    try:
        if not isinstance(output, Path) or output.exists() or output.is_symlink():
            raise RuntimeEndpointJournalOverlayError("output must be a new Path")
        rendered, dependencies = _verified_inputs()
        overlay._write_overlay(output, rendered, ("src", "aragorn"))
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {"name": name, "bytes": len(raw), "digest": overlay._digest(raw)}
                for name, raw in rendered.items()
            ],
            "required_checkout_dependencies_not_included": dependencies,
            "required_companion_overrides_not_included": [
                {
                    "name": _ISSUER,
                    "bytes": quarantine._SERVICES[_ISSUER][2],
                    "digest": quarantine._SERVICES[_ISSUER][3],
                }
            ],
            "standalone_executable": False,
            "production_activation_eligible": False,
            "run_eligible": False,
            "limitations": [
                "FIXED_ENDPOINT_BEST_EFFORT_JOURNAL_VISIBILITY_ONLY",
                "NO_MANDATORY_EVENT_LOSS_FAIL_CLOSED_OR_DURABLE_RETENTION",
                "NO_SEMANTIC_CAUSATION_OR_DECISION_LATENCY_MEASUREMENT",
                "NO_COMPLETE_EVENT_CLASS_OR_RUN_QUALIFICATION",
                "REQUIRES_FULL_STAGED_IMPORT_CLOSURE_AND_NEW_ACTIVATOR_SOURCE_PINS",
                "REQUIRES_QUARANTINE_ISSUER_OVERRIDE_AND_SEPARATELY_BOUND_DEPLOYMENT",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeEndpointJournalOverlayError(
            "cannot materialize journal producers"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_runtime_endpoint_journal(parser.parse_args().output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
