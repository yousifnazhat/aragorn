"""Linux service entrypoint for the runtime observation gateway."""

from __future__ import annotations

import grp
import json
import os
import pwd
import sys
from collections.abc import Sequence
from pathlib import Path

from .oci_worker_protocol import _digest, canonical_json
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherConfig,
    RuntimeActionObservationPublisherError,
    serve_runtime_action_observation_publisher,
)
from .runtime_action_service import (
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
)

_BROKER_USER = "aragorn-broker"
_RUNTIME_PRINCIPAL = "aragorn-runtime"
_SENSOR_PRINCIPAL = "aragorn-sensor"
_BINDING_SCHEMA = "aragorn/runtime-observation-binding/v1"
_BINDING_FIELDS = {
    "schema",
    "runtime_digest",
    "active_skill_digest",
    "sensor_digest",
}
_ROOT = Path("/var/lib/aragorn-runtime-action")
_RUNTIME_DIRECTORY = Path("/run/aragorn-runtime-observation")


class RuntimeObservationServiceError(ValueError):
    """The fixed observation-gateway service configuration is unsafe."""


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: aragorn-runtime-observation-service OBSERVATION_BINDING_CREDENTIAL",
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
        print(f"aragorn runtime observation service: {exc}", file=sys.stderr)
        return 126


def _run(credential_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeObservationServiceError("Linux execution is required")
    observer_uid, observer_gid, runtime_uid, runtime_gid, broker_uid = (
        _service_identities()
    )
    credential_path = _credential_path(
        credential_path,
        observer_uid,
        credential_name="observation-binding",
    )
    runtime_digest, active_skill_digest, sensor_digest = _read_binding(
        credential_path,
        observer_uid,
    )
    serve_runtime_action_observation_publisher(
        RuntimeActionObservationPublisherConfig(
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
            expected_runtime_digest=runtime_digest,
            expected_active_skill_digest=active_skill_digest,
            expected_sensor_digest=sensor_digest,
        )
    )


def _service_identities() -> tuple[int, int, int, int, int]:
    try:
        observer = pwd.getpwnam(_SENSOR_PRINCIPAL)
        runtime = pwd.getpwnam(_RUNTIME_PRINCIPAL)
        broker = pwd.getpwnam(_BROKER_USER)
        observer_group = grp.getgrnam(_SENSOR_PRINCIPAL)
        runtime_group = grp.getgrnam(_RUNTIME_PRINCIPAL)
    except KeyError as exc:
        raise RuntimeObservationServiceError(
            "required service identity is absent"
        ) from exc
    if (
        os.geteuid() != observer.pw_uid
        or os.getegid() != observer_group.gr_gid
        or observer.pw_gid != observer_group.gr_gid
    ):
        raise RuntimeObservationServiceError("sensor process identity is invalid")
    if runtime.pw_gid != runtime_group.gr_gid:
        raise RuntimeObservationServiceError(
            "runtime user and group identities disagree"
        )
    if len({observer.pw_uid, runtime.pw_uid, broker.pw_uid}) != 3 or (
        observer_group.gr_gid == runtime_group.gr_gid
    ):
        raise RuntimeObservationServiceError(
            "runtime, sensor, and broker identities overlap"
        )
    groups = set(os.getgroups())
    if runtime_group.gr_gid not in groups or not groups.issubset(
        {observer_group.gr_gid, runtime_group.gr_gid}
    ):
        raise RuntimeObservationServiceError(
            "sensor supplementary groups are invalid"
        )
    return (
        observer.pw_uid,
        observer_group.gr_gid,
        runtime.pw_uid,
        runtime_group.gr_gid,
        broker.pw_uid,
    )


def _read_binding(path: Path, expected_uid: int) -> tuple[str, str, str]:
    raw = _read_credential_bytes(
        path,
        expected_uid,
        label="runtime observation binding",
    )
    try:
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or set(document) != _BINDING_FIELDS
            or document["schema"] != _BINDING_SCHEMA
            or canonical_json(document) != raw
        ):
            raise RuntimeObservationServiceError(
                "runtime observation binding credential is invalid"
            )
        return tuple(
            _digest(document[field], f"runtime observation {field}")
            for field in (
                "runtime_digest",
                "active_skill_digest",
                "sensor_digest",
            )
        )
    except RuntimeObservationServiceError:
        raise
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        raise RuntimeObservationServiceError(
            "runtime observation binding credential is invalid"
        ) from exc


if __name__ == "__main__":
    raise SystemExit(main())
