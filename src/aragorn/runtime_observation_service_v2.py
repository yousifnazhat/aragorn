"""Linux service entrypoint for profile-attributed runtime observation."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .oci_worker_protocol import _digest, canonical_json
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from .runtime_action_observation_publisher_v2 import (
    RuntimeActionObservationPublisherV2Config,
    serve_runtime_action_observation_publisher_v2,
)
from .runtime_action_service import (
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
)
from .runtime_observation_service import _service_identities
from .runtime_process_profile import (
    RuntimeProcessProfile,
    runtime_process_profile,
)

_BINDING_SCHEMA = "aragorn/runtime-observation-binding/v2"
_BINDING_FIELDS = {"schema", "sensor_digest", "runtime_profile"}
_ROOT = Path("/var/lib/aragorn-runtime-action")
_RUNTIME_DIRECTORY = Path("/run/aragorn-runtime-observation")


class RuntimeObservationServiceV2Error(ValueError):
    """The profile-attributing service configuration is unsafe."""


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: aragorn-runtime-observation-service-v2 "
            "OBSERVATION_BINDING_CREDENTIAL",
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
        RuntimeActionObservationPublisherError,
        RuntimeActionServiceError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"aragorn runtime observation service v2: {exc}", file=sys.stderr)
        return 126


def _run(credential_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeObservationServiceV2Error("Linux execution is required")
    observer_uid, observer_gid, runtime_uid, runtime_gid, broker_uid = (
        _service_identities()
    )
    credential_path = _credential_path(
        credential_path,
        observer_uid,
        credential_name="observation-binding",
    )
    profile, sensor_digest = _read_binding(credential_path, observer_uid)
    serve_runtime_action_observation_publisher_v2(
        RuntimeActionObservationPublisherV2Config(
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
        )
    )


def _read_binding(
    path: Path,
    expected_uid: int,
) -> tuple[RuntimeProcessProfile, str]:
    raw = _read_credential_bytes(
        path,
        expected_uid,
        label="runtime observation v2 binding",
    )
    try:
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or set(document) != _BINDING_FIELDS
            or document["schema"] != _BINDING_SCHEMA
            or canonical_json(document) != raw
        ):
            raise RuntimeObservationServiceV2Error(
                "runtime observation v2 binding credential is invalid"
            )
        return (
            runtime_process_profile(document["runtime_profile"]),
            _digest(document["sensor_digest"], "runtime observation sensor digest"),
        )
    except RuntimeObservationServiceV2Error:
        raise
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        raise RuntimeObservationServiceV2Error(
            "runtime observation v2 binding credential is invalid"
        ) from exc


if __name__ == "__main__":
    raise SystemExit(main())
