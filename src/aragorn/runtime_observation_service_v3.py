"""Linux service entrypoint for sensor-issued runtime capabilities."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from .runtime_action_observation_publisher_v2 import (
    RuntimeActionObservationPublisherV2Config,
)
from .runtime_action_observation_publisher_v3 import (
    RuntimeActionObservationPublisherV3Config,
    serve_runtime_action_observation_publisher_v3,
)
from .runtime_action_service import (
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
)
from .runtime_observation_service import _service_identities
from .runtime_observation_service_v2 import (
    _ROOT,
    _RUNTIME_DIRECTORY,
    RuntimeObservationServiceV2Error,
    _read_binding,
)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(
            "usage: aragorn-runtime-observation-service-v3 "
            "OBSERVATION_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL",
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
        RuntimeActionObservationPublisherError,
        RuntimeActionServiceError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"aragorn runtime observation service v3: {exc}", file=sys.stderr)
        return 126


def _run(observation_binding_path: Path, capability_grant_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeObservationServiceV2Error("Linux execution is required")
    observer_uid, observer_gid, runtime_uid, runtime_gid, broker_uid = (
        _service_identities()
    )
    observation_binding_path = _credential_path(
        observation_binding_path,
        observer_uid,
        credential_name="observation-binding",
    )
    capability_grant_path = _credential_path(
        capability_grant_path,
        observer_uid,
        credential_name="capability-grant",
    )
    profile, sensor_digest = _read_binding(
        observation_binding_path,
        observer_uid,
    )
    capability_grant = _read_credential_bytes(
        capability_grant_path,
        observer_uid,
        label="runtime capability grant",
    )
    serve_runtime_action_observation_publisher_v3(
        RuntimeActionObservationPublisherV3Config(
            publisher=RuntimeActionObservationPublisherV2Config(
                frontend_socket_path=_RUNTIME_DIRECTORY / "sensor.sock",
                runtime_directory=_RUNTIME_DIRECTORY,
                instance_lock_path=_RUNTIME_DIRECTORY / "sensor.instance.lock",
                backend_socket_path=_ROOT / "control" / "broker.sock",
                protected_root=_ROOT / "protected",
                expected_observer_uid=observer_uid,
                expected_observer_gid=observer_gid,
                expected_runtime_uid=runtime_uid,
                expected_runtime_gid=runtime_gid,
                expected_broker_uid=broker_uid,
                expected_broker_gid=runtime_gid,
                expected_runtime_digest=profile.runtime_digest,
                expected_sensor_digest=sensor_digest,
                runtime_profile=profile,
            ),
            capability_grant=capability_grant,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
