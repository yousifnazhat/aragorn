"""Broker-enforced active-skill lineage around the frozen v4 redeemer."""

from __future__ import annotations

import logging
import os
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
    _acquire_lock,
    _directory_identity,
    _exact,
    _open_lock_file,
    _open_protected_directory,
    _peer_credentials,
    _prepare_socket_path,
    _ProtectedFileError,
    _read_frame,
    _recover_before_listen,
    _release_lock_and_close,
    _send_frame,
)
from .runtime_action_broker_v2 import _require_no_profile_pending
from .runtime_action_broker_v4 import (
    RuntimeActionBrokerV4Config,
    _issued_submission,
    mediate_granted_profiled_runtime_create,
    recover_runtime_capability_grant,
)
from .runtime_action_broker_v4 import (
    _validate_config as _validate_v4_config,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from .runtime_active_skill_lineage import (
    DEFAULT_PROTECTED_INSTALL_ROOT,
    hold_runtime_active_skill_lineage,
)
from .runtime_lineage_capability_issuer import (
    LINEAGE_ISSUANCE_AUTHORITY,
    LINEAGE_ISSUANCE_SCHEMA,
)

_LOG = logging.getLogger(__name__)

_LINEAGE_ISSUANCE_FIELDS = {"schema", "authority", "lineage", "issuance"}


@dataclass(frozen=True, slots=True)
class RuntimeActionBrokerV5Config:
    """Frozen v4 grant broker plus its protected-install authority root."""

    broker: RuntimeActionBrokerV4Config
    protected_install_root: Path = DEFAULT_PROTECTED_INSTALL_ROOT


def mediate_lineage_granted_profiled_runtime_create(
    value: object,
    config: RuntimeActionBrokerV5Config,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Require live protected lineage before the v4 grant can be claimed."""

    wrapped = _exact(
        value,
        _LINEAGE_ISSUANCE_FIELDS,
        "lineage-profiled runtime capability issuance",
    )
    if (
        wrapped["schema"] != LINEAGE_ISSUANCE_SCHEMA
        or wrapped["authority"] != LINEAGE_ISSUANCE_AUTHORITY
    ):
        raise RuntimeActionBrokerError(
            "lineage-profiled runtime capability issuance is invalid"
        )
    try:
        supplied_lineage = canonical_json(wrapped["lineage"])
    except (RecursionError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(
            "lineage-profiled runtime capability issuance is invalid"
        ) from exc

    grant = _validate_config(config)
    issuance = wrapped["issuance"]
    _submission, _legacy, attribution, _digest, _lease = _issued_submission(
        issuance,
        config.broker,
        grant,
        int(time.time()),
    )
    result: dict[str, Any] = {}
    try:
        with hold_runtime_active_skill_lineage(
            attribution["pid"],
            attribution,
            grant,
            protected_root=config.protected_install_root,
            deadline=deadline_monotonic,
        ) as live_lineage:
            if canonical_json(live_lineage) != supplied_lineage:
                raise RuntimeActionBrokerError(
                    "runtime active-skill lineage changed before grant redemption"
                )
            result = mediate_granted_profiled_runtime_create(
                issuance,
                config.broker,
                deadline_monotonic=deadline_monotonic,
            )
    except RuntimeActionObservationPublisherError as exc:
        if result.get("effect_status") == "CREATED":
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but active-skill lineage cleanup failed"
            ) from exc
        raise RuntimeActionBrokerError(
            "runtime active-skill lineage cannot be verified"
        ) from exc
    return result


def serve_runtime_action_broker_v5(
    config: RuntimeActionBrokerV5Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve only lineage-wrapped sensor capabilities through frozen v4."""

    _validate_config(config)
    broker = config.broker.broker.broker
    if not 0 < request_timeout_seconds <= 0.5:
        raise RuntimeActionBrokerError("broker request timeout is invalid")
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeActionBrokerError("Linux SO_PEERCRED is required")

    control_fd = _open_protected_directory(
        broker.control_root,
        broker.expected_broker_uid,
        "runtime broker control root",
    )
    listener: socket.socket | None = None
    instance_lock_fd = -1
    instance_locked = False
    bound = False
    socket_identity: tuple[int, int] | None = None
    try:
        if _directory_identity(os.lstat(broker.control_root)) != _directory_identity(
            os.fstat(control_fd)
        ):
            raise RuntimeActionBrokerError("runtime broker control root changed")
        instance_lock_fd = _open_lock_file(
            control_fd,
            broker,
            path=broker.instance_lock_path,
        )
        _acquire_lock(instance_lock_fd, time.monotonic())
        instance_locked = True
        _recover_before_listen(broker, request_timeout_seconds)
        recover_runtime_capability_grant(
            config.broker,
            timeout_seconds=request_timeout_seconds,
        )
        _require_no_profile_pending(
            config.broker.broker,
            request_timeout_seconds,
        )
        _prepare_socket_path(control_fd, broker)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(broker.socket_path))
        bound = True
        metadata = os.stat(
            broker.socket_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
        socket_identity = metadata.st_dev, metadata.st_ino
        os.chown(
            broker.socket_path,
            broker.expected_broker_uid,
            broker.expected_peer_gid,
        )
        os.chmod(broker.socket_path, 0o660, follow_symlinks=False)
        metadata = os.stat(
            broker.socket_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != broker.expected_broker_uid
            or metadata.st_gid != broker.expected_peer_gid
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeActionBrokerError("runtime broker socket metadata is unsafe")
        listener.listen(16)
        while True:
            connection, _address = listener.accept()
            with connection:
                try:
                    _handle_connection(
                        connection,
                        config,
                        timeout_seconds=request_timeout_seconds,
                    )
                except RuntimeActionEffectIndeterminate as exc:
                    _LOG.error("runtime action effect is indeterminate: %s", exc)
                except RuntimeActionBrokerError as exc:
                    _LOG.warning("runtime action failed before effect: %s", exc)
    except RuntimeActionBrokerError:
        raise
    except (OSError, _ProtectedFileError) as exc:
        raise RuntimeActionBrokerError(
            f"runtime broker transport failed: {exc}"
        ) from exc
    finally:
        cleanup_failure: OSError | None = None
        if listener is not None:
            try:
                listener.close()
            except OSError as exc:
                cleanup_failure = exc
        if bound:
            try:
                current = os.stat(
                    broker.socket_path.name,
                    dir_fd=control_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino) or (
                    socket_identity is None
                    and stat.S_ISSOCK(current.st_mode)
                    and current.st_uid == broker.expected_broker_uid
                ):
                    os.unlink(broker.socket_path.name, dir_fd=control_fd)
                    os.fsync(control_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_failure = cleanup_failure or exc
        cleanup_failure = cleanup_failure or _release_lock_and_close(
            instance_lock_fd,
            instance_locked,
            control_fd,
        )
        if cleanup_failure is not None:
            raise RuntimeActionBrokerError(
                "runtime broker transport cleanup failed"
            ) from cleanup_failure


def _handle_connection(
    connection: socket.socket,
    config: RuntimeActionBrokerV5Config,
    *,
    timeout_seconds: float,
) -> None:
    broker = config.broker.broker.broker
    pid, uid, gid = _peer_credentials(connection)
    if uid != broker.expected_peer_uid or gid != broker.expected_peer_gid:
        raise RuntimeActionBrokerError(
            f"runtime broker peer {pid} has an unauthorized identity"
        )
    deadline = time.monotonic() + timeout_seconds
    result = mediate_lineage_granted_profiled_runtime_create(
        _read_frame(connection, deadline),
        config,
        deadline_monotonic=deadline,
    )
    try:
        _send_frame(connection, canonical_json(result), deadline)
    except RuntimeActionBrokerError as exc:
        if result["effect_status"] == "CREATED":
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but its response failed"
            ) from exc
        raise


def _validate_config(config: RuntimeActionBrokerV5Config) -> dict[str, Any]:
    if (
        not isinstance(config, RuntimeActionBrokerV5Config)
        or not isinstance(config.protected_install_root, Path)
        or not config.protected_install_root.is_absolute()
        or config.protected_install_root == Path(config.protected_install_root.anchor)
    ):
        raise RuntimeActionBrokerError(
            "runtime lineage capability broker configuration is invalid"
        )
    return _validate_v4_config(config.broker)
