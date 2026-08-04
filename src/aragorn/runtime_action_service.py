"""Linux service entrypoint for the private runtime action broker."""

from __future__ import annotations

import grp
import json
import os
import pwd
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from .oci_worker_protocol import _digest, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerConfig,
    RuntimeActionBrokerError,
    serve_runtime_action_broker,
)

_BROKER_USER = "aragorn-broker"
_RUNTIME_PRINCIPAL = "aragorn-runtime"
_SENSOR_PRINCIPAL = "aragorn-sensor"
_BINDING_SCHEMA = "aragorn/runtime-action-runtime-binding/v1"
_BINDING_FIELDS = {"schema", "runtime_digest"}
_MAX_CREDENTIAL_BYTES = 4 * 1024
_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL_ROOT = _ROOT / "control"
_PROTECTED_ROOT = _ROOT / "protected"
_STAGING_ROOT = _ROOT / "staging"


class RuntimeActionServiceError(ValueError):
    """The fixed runtime action service configuration is unsafe."""


def main(argv: Sequence[str] | None = None) -> int:
    """Resolve fixed service identities and run the broker until interrupted."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: aragorn-runtime-action-service RUNTIME_BINDING_CREDENTIAL",
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
        print(f"aragorn runtime action service: {exc}", file=sys.stderr)
        return 126


def _run(credential_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeActionServiceError("Linux execution is required")

    broker_uid, runtime_uid, runtime_gid, sensor_uid, sensor_gid = (
        _service_identities()
    )
    credential_path = _credential_path(credential_path, broker_uid)
    runtime_digest = _read_runtime_binding(credential_path, broker_uid)
    serve_runtime_action_broker(
        RuntimeActionBrokerConfig(
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
    )


def _service_identities() -> tuple[int, int, int, int, int]:
    try:
        broker = pwd.getpwnam(_BROKER_USER)
        runtime = pwd.getpwnam(_RUNTIME_PRINCIPAL)
        sensor = pwd.getpwnam(_SENSOR_PRINCIPAL)
        runtime_group = grp.getgrnam(_RUNTIME_PRINCIPAL)
        sensor_group = grp.getgrnam(_SENSOR_PRINCIPAL)
    except KeyError as exc:
        raise RuntimeActionServiceError("required service identity is absent") from exc
    if os.geteuid() != broker.pw_uid:
        raise RuntimeActionServiceError("broker process identity is invalid")
    if runtime.pw_uid == broker.pw_uid:
        raise RuntimeActionServiceError("runtime and broker identities overlap")
    if runtime.pw_gid != runtime_group.gr_gid:
        raise RuntimeActionServiceError("runtime user and group identities disagree")
    if sensor.pw_gid != sensor_group.gr_gid:
        raise RuntimeActionServiceError("sensor user and group identities disagree")
    if len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) != 3 or (
        runtime_group.gr_gid == sensor_group.gr_gid
    ):
        raise RuntimeActionServiceError(
            "runtime, sensor, and broker identities overlap"
        )
    groups = set(os.getgroups())
    if (
        os.getegid() != runtime_group.gr_gid
        or sensor_group.gr_gid not in groups
        or not groups.issubset({runtime_group.gr_gid, sensor_group.gr_gid})
    ):
        raise RuntimeActionServiceError("broker process groups are invalid")
    return (
        broker.pw_uid,
        runtime.pw_uid,
        runtime_group.gr_gid,
        sensor.pw_uid,
        sensor_group.gr_gid,
    )


def _credential_path(
    path: Path,
    expected_uid: int,
    *,
    credential_name: str = "runtime-binding",
) -> Path:
    directory_value = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory_value:
        raise RuntimeActionServiceError("systemd credential directory is absent")
    directory = Path(directory_value)
    expected = directory / credential_name
    try:
        metadata = os.lstat(directory)
        resolved = directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeActionServiceError(
            "systemd credential directory is unsafe"
        ) from exc
    if (
        not directory.is_absolute()
        or path != expected
        or resolved != directory
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, expected_uid}
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeActionServiceError("systemd credential path is invalid")
    return path


def _read_runtime_binding(path: Path, expected_uid: int) -> str:
    return _runtime_digest(
        _read_credential_bytes(path, expected_uid, label="runtime binding")
    )


def _read_credential_bytes(
    path: Path,
    expected_uid: int,
    *,
    label: str,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        owner_is_safe = (
            before.st_uid == expected_uid and mode == 0o400
        ) or (
            before.st_uid == 0
            and before.st_gid == 0
            and mode in {0o400, 0o440}
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or not owner_is_safe
            or before.st_nlink != 1
            or before.st_size > _MAX_CREDENTIAL_BYTES
        ):
            raise RuntimeActionServiceError(f"{label} credential is unsafe")
        raw = os.read(descriptor, _MAX_CREDENTIAL_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) > _MAX_CREDENTIAL_BYTES
        or len(raw) != after.st_size
        or _file_identity(before) != _file_identity(after)
    ):
        raise RuntimeActionServiceError(f"{label} credential changed while read")
    return raw


def _runtime_digest(raw: bytes) -> str:
    try:
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or set(document) != _BINDING_FIELDS
            or document["schema"] != _BINDING_SCHEMA
            or canonical_json(document) != raw
        ):
            raise RuntimeActionServiceError("runtime binding credential is invalid")
        return _digest(document["runtime_digest"], "runtime binding digest")
    except RuntimeActionServiceError:
        raise
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        raise RuntimeActionServiceError("runtime binding credential is invalid") from exc


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


if __name__ == "__main__":
    raise SystemExit(main())
