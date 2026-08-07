"""Linux service entrypoint for dynamically issued runtime capabilities."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from .runtime_action_broker import RuntimeActionBrokerConfig, RuntimeActionBrokerError
from .runtime_action_broker_v2 import RuntimeActionBrokerV2Config
from .runtime_action_broker_v4 import (
    RuntimeActionBrokerV4Config,
    initialize_runtime_capability_grant,
    serve_runtime_action_broker_v4,
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
from .runtime_action_service_v2 import _read_runtime_binding


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(
            "usage: aragorn-runtime-action-service-v4 "
            "RUNTIME_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL",
            file=sys.stderr,
        )
        return 64
    try:
        _run(Path(arguments[0]), Path(arguments[1]))
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
        print(f"aragorn runtime action service v4: {exc}", file=sys.stderr)
        return 126


def _run(runtime_binding_path: Path, capability_grant_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeActionServiceError("Linux execution is required")
    broker_uid, runtime_uid, runtime_gid, sensor_uid, sensor_gid = _service_identities()
    runtime_binding_path = _credential_path(runtime_binding_path, broker_uid)
    capability_grant_path = _credential_path(
        capability_grant_path,
        broker_uid,
        credential_name="capability-grant",
    )
    runtime_digest, runtime_profile_digest = _read_runtime_binding(
        runtime_binding_path,
        broker_uid,
    )
    capability_grant = _read_credential_bytes(
        capability_grant_path,
        broker_uid,
        label="runtime capability grant",
    )
    config = RuntimeActionBrokerV4Config(
        broker=RuntimeActionBrokerV2Config(
            broker=RuntimeActionBrokerConfig(
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
            ),
            expected_runtime_profile_digest=runtime_profile_digest,
            profile_pending_path=_CONTROL_ROOT / "profile-pending.json",
            profile_receipt_path=_CONTROL_ROOT / "profile-receipt.json",
        ),
        capability_grant=capability_grant,
        grant_state_path=_CONTROL_ROOT / "capability-grant-state.json",
    )
    initialize_runtime_capability_grant(config)
    serve_runtime_action_broker_v4(config)


if __name__ == "__main__":
    raise SystemExit(main())
