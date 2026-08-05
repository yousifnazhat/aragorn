"""Linux service entrypoint for the profile-attributing runtime broker."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .oci_worker_protocol import _digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerConfig, RuntimeActionBrokerError
from .runtime_action_broker_v2 import (
    RuntimeActionBrokerV2Config,
    serve_runtime_action_broker_v2,
)
from .runtime_action_service import (
    _CONTROL_ROOT,
    _PROTECTED_ROOT,
    _STAGING_ROOT,
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
    _service_identities,
)

_BINDING_SCHEMA = "aragorn/runtime-action-runtime-binding/v2"
_BINDING_FIELDS = {"schema", "runtime_digest", "runtime_profile_digest"}


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: aragorn-runtime-action-service-v2 RUNTIME_BINDING_CREDENTIAL",
            file=sys.stderr,
        )
        return 64
    try:
        _run(Path(arguments[0]))
        return 0
    except KeyboardInterrupt:
        return 0
    except (
        KeyError,
        OSError,
        RuntimeActionBrokerError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"aragorn runtime action service v2: {exc}", file=sys.stderr)
        return 126


def _run(credential_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeActionServiceError("Linux execution is required")
    broker_uid, runtime_uid, runtime_gid, sensor_uid, sensor_gid = _service_identities()
    credential_path = _credential_path(credential_path, broker_uid)
    runtime_digest, runtime_profile_digest = _read_runtime_binding(
        credential_path,
        broker_uid,
    )
    broker = RuntimeActionBrokerConfig(
        socket_path=_CONTROL_ROOT / "broker.sock",
        instance_lock_path=_CONTROL_ROOT / "broker.instance.lock",
        lock_path=_CONTROL_ROOT / "broker.lock",
        control_root=_CONTROL_ROOT,
        protected_root=_PROTECTED_ROOT,
        staging_root=_STAGING_ROOT,
        policy_path=_CONTROL_ROOT / "policy.json",
        revocations_path=_CONTROL_ROOT / "revocations.json",
        health_path=_CONTROL_ROOT / "health.json",
        observation_path=_CONTROL_ROOT / "observation.json",
        state_path=_CONTROL_ROOT / "state.json",
        expected_broker_uid=broker_uid,
        expected_peer_uid=sensor_uid,
        expected_peer_gid=sensor_gid,
        expected_runtime_digest=runtime_digest,
        expected_runtime_uid=runtime_uid,
        expected_runtime_gid=runtime_gid,
    )
    serve_runtime_action_broker_v2(
        RuntimeActionBrokerV2Config(
            broker=broker,
            expected_runtime_profile_digest=runtime_profile_digest,
            profile_pending_path=_CONTROL_ROOT / "profile-pending.json",
            profile_receipt_path=_CONTROL_ROOT / "profile-receipt.json",
        )
    )


def _read_runtime_binding(path: Path, expected_uid: int) -> tuple[str, str]:
    raw = _read_credential_bytes(
        path,
        expected_uid,
        label="runtime profile binding",
    )
    try:
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or set(document) != _BINDING_FIELDS
            or document["schema"] != _BINDING_SCHEMA
            or canonical_json(document) != raw
        ):
            raise RuntimeActionServiceError(
                "runtime profile binding credential is invalid"
            )
        return (
            _digest(document["runtime_digest"], "runtime binding digest"),
            _digest(
                document["runtime_profile_digest"],
                "runtime profile binding digest",
            ),
        )
    except RuntimeActionServiceError:
        raise
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        raise RuntimeActionServiceError(
            "runtime profile binding credential is invalid"
        ) from exc


if __name__ == "__main__":
    raise SystemExit(main())
