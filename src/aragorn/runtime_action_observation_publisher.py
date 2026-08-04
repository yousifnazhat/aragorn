"""Out-of-process measurement gateway for runtime action submissions."""

from __future__ import annotations

import fcntl
import math
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_digest, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _action_digests,
    _peer_credentials,
    _read_frame,
    _require_protected_ancestry,
    _request_effect,
    _send_frame,
)
from .runtime_action_decision import (
    _InvalidRequest,
    _request as _validate_runtime_action_request,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTRIBUTION_FIELDS = (
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
)
_ACTION_FIELDS = ("operation_digest", "path_digest", "payload_digest")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class RuntimeActionObservationPublisherError(RuntimeError):
    """The observation gateway could not safely relay a runtime action."""


@dataclass(frozen=True, slots=True)
class RuntimeActionObservationPublisherConfig:
    """Launcher-owned paths, identities, and measurement pins."""

    frontend_socket_path: Path
    runtime_directory: Path
    instance_lock_path: Path
    backend_socket_path: Path
    protected_root: Path
    expected_observer_uid: int
    expected_observer_gid: int
    expected_runtime_uid: int
    expected_runtime_gid: int
    expected_broker_uid: int
    expected_broker_gid: int
    expected_runtime_digest: str
    expected_active_skill_digest: str
    expected_sensor_digest: str


def build_observed_submission(
    envelope: object,
    runtime_peer: tuple[int, int, int],
    protected_fd: int,
    config: RuntimeActionObservationPublisherConfig,
) -> dict[str, Any]:
    """Independently measure an effect and bind it to its authenticated caller."""

    _validate_config(config)
    pid, uid, gid = _runtime_peer(runtime_peer)
    if uid != config.expected_runtime_uid or gid != config.expected_runtime_gid:
        raise RuntimeActionObservationPublisherError(
            f"runtime observation peer {pid} has an unauthorized identity"
        )
    try:
        request, target_name, payload = _request_effect(envelope)
        request = _validate_runtime_action_request(request)
        action = _action_digests(protected_fd, target_name, payload)
        envelope_digest = canonical_digest(envelope)
        request_digest = canonical_digest(request)
    except (
        _InvalidRequest,
        RuntimeActionBrokerError,
        WorkerProtocolError,
        OSError,
        RecursionError,
    ) as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime observation submission is invalid"
        ) from exc
    if request["runtime_digest"] != config.expected_runtime_digest:
        raise RuntimeActionObservationPublisherError(
            "runtime observation runtime pin does not match"
        )
    if request["active_skill_digest"] != config.expected_active_skill_digest:
        raise RuntimeActionObservationPublisherError(
            "runtime observation active-skill pin does not match"
        )
    if any(request[field] != action[field] for field in _ACTION_FIELDS):
        raise RuntimeActionObservationPublisherError(
            "runtime observation action measurement does not match"
        )
    measured_action = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{field: request[field] for field in _ATTRIBUTION_FIELDS},
        **action,
    }
    return {
        "schema": "aragorn/runtime-observed-create-submission/v1",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": config.expected_sensor_digest,
        "envelope_digest": envelope_digest,
        "request_digest": request_digest,
        "runtime_peer": {"pid": pid, "uid": uid, "gid": gid},
        "measured_action": measured_action,
        "envelope": envelope,
    }


def serve_runtime_action_observation_publisher(
    config: RuntimeActionObservationPublisherConfig,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve measured runtime submissions until interrupted by the service manager."""

    _validate_config(config)
    if not _valid_timeout(request_timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "O_PATH"):
        raise RuntimeActionObservationPublisherError(
            "Linux SO_PEERCRED and O_PATH are required"
        )

    runtime_fd = _open_runtime_directory(config)
    lock_fd = -1
    locked = False
    listener: socket.socket | None = None
    bound = False
    socket_identity: tuple[int, int] | None = None
    try:
        lock_fd = _open_instance_lock(runtime_fd, config)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeActionObservationPublisherError(
                "runtime observation publisher is already running"
            ) from exc
        locked = True
        _prepare_frontend_socket(runtime_fd, config)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(config.frontend_socket_path))
        bound = True
        metadata = os.stat(
            config.frontend_socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        socket_identity = metadata.st_dev, metadata.st_ino
        os.chown(
            config.frontend_socket_path,
            config.expected_observer_uid,
            config.expected_runtime_gid,
        )
        os.chmod(config.frontend_socket_path, 0o660, follow_symlinks=False)
        metadata = os.stat(
            config.frontend_socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != config.expected_observer_uid
            or metadata.st_gid != config.expected_runtime_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime observation socket metadata is unsafe"
            )
        os.fsync(runtime_fd)
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
                except RuntimeActionObservationPublisherError:
                    # A closed connection is the only fail-closed frontend response.
                    continue
    except RuntimeActionObservationPublisherError:
        raise
    except OSError as exc:
        raise RuntimeActionObservationPublisherError(
            f"runtime observation transport failed: {exc}"
        ) from exc
    finally:
        cleanup_error: OSError | None = None
        if listener is not None:
            try:
                listener.close()
            except OSError as exc:
                cleanup_error = exc
        if bound:
            try:
                current = os.stat(
                    config.frontend_socket_path.name,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino):
                    os.unlink(config.frontend_socket_path.name, dir_fd=runtime_fd)
                    os.fsync(runtime_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if locked:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        for descriptor in (lock_fd, runtime_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise RuntimeActionObservationPublisherError(
                "runtime observation transport cleanup failed"
            ) from cleanup_error


def _handle_connection(
    connection: socket.socket,
    config: RuntimeActionObservationPublisherConfig,
    *,
    timeout_seconds: float,
) -> None:
    if not _valid_timeout(timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    try:
        runtime_peer = _runtime_peer(_peer_credentials(connection))
        pid, uid, gid = runtime_peer
        if uid != config.expected_runtime_uid or gid != config.expected_runtime_gid:
            raise RuntimeActionObservationPublisherError(
                f"runtime observation peer {pid} has an unauthorized identity"
            )
        deadline = time.monotonic() + timeout_seconds
        envelope = _read_frame(connection, deadline)
        protected_fd = _open_protected_root(config)
        try:
            submission = build_observed_submission(
                envelope,
                runtime_peer,
                protected_fd,
                config,
            )
        finally:
            os.close(protected_fd)

        with _connect_backend(config, deadline) as backend:
            pid, uid, gid = _runtime_peer(_peer_credentials(backend))
            if uid != config.expected_broker_uid or gid != config.expected_broker_gid:
                raise RuntimeActionObservationPublisherError(
                    f"runtime broker peer {pid} has an unauthorized identity"
                )
            _send_frame(backend, canonical_json(submission), deadline)
            backend.shutdown(socket.SHUT_WR)
            response = _read_frame(backend, deadline)
        _send_frame(connection, canonical_json(response), deadline)
    except RuntimeActionObservationPublisherError:
        raise
    except (RuntimeActionBrokerError, WorkerProtocolError, OSError) as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime observation relay failed"
        ) from exc


def _connect_backend(
    config: RuntimeActionObservationPublisherConfig,
    deadline: float,
) -> socket.socket:
    backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeActionObservationPublisherError(
                "runtime observation request timed out"
            )
        backend.settimeout(remaining)
        backend.connect(os.fspath(config.backend_socket_path))
        return backend
    except BaseException:
        backend.close()
        raise


def _open_protected_root(config: RuntimeActionObservationPublisherConfig) -> int:
    descriptor = -1
    try:
        if not hasattr(os, "O_PATH"):
            raise RuntimeActionObservationPublisherError("Linux O_PATH is required")
        if config.protected_root.resolve(strict=True) != config.protected_root:
            raise RuntimeActionObservationPublisherError(
                "runtime protected root path is not canonical"
            )
        _require_protected_ancestry(
            config.protected_root.parent,
            config.expected_broker_uid,
        )
        before = os.lstat(config.protected_root)
        descriptor = os.open(
            config.protected_root,
            os.O_PATH
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        after = os.fstat(descriptor)
        if (
            _directory_identity(before) != _directory_identity(after)
            or after.st_uid != config.expected_broker_uid
            or after.st_gid != config.expected_broker_gid
            or stat.S_IMODE(after.st_mode) != 0o710
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime protected root metadata is unsafe"
            )
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, RuntimeActionObservationPublisherError):
            raise
        if isinstance(exc, (OSError, RuntimeError, ValueError)):
            raise RuntimeActionObservationPublisherError(
                "cannot open runtime protected root"
            ) from exc
        raise


def _open_runtime_directory(config: RuntimeActionObservationPublisherConfig) -> int:
    descriptor = -1
    try:
        if config.runtime_directory.resolve(strict=True) != config.runtime_directory:
            raise RuntimeActionObservationPublisherError(
                "runtime observation directory path is not canonical"
            )
        _require_protected_ancestry(
            config.runtime_directory.parent,
            config.expected_observer_uid,
        )
        before = os.lstat(config.runtime_directory)
        descriptor = os.open(config.runtime_directory, _DIRECTORY_FLAGS)
        after = os.fstat(descriptor)
        if (
            _directory_identity(before) != _directory_identity(after)
            or after.st_uid != config.expected_observer_uid
            or after.st_gid
            not in {
                config.expected_observer_gid,
                config.expected_runtime_gid,
            }
            or stat.S_IMODE(after.st_mode) != 0o750
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime observation directory metadata is unsafe"
            )
        os.fchown(
            descriptor,
            config.expected_observer_uid,
            config.expected_runtime_gid,
        )
        os.fchmod(descriptor, 0o750)
        after = os.fstat(descriptor)
        if (
            after.st_gid != config.expected_runtime_gid
            or stat.S_IMODE(after.st_mode) != 0o750
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime observation directory metadata is unsafe"
            )
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, RuntimeActionObservationPublisherError):
            raise
        if isinstance(exc, (OSError, RuntimeError, ValueError)):
            raise RuntimeActionObservationPublisherError(
                "cannot open runtime observation directory"
            ) from exc
        raise


def _open_instance_lock(
    runtime_fd: int,
    config: RuntimeActionObservationPublisherConfig,
) -> int:
    descriptor = os.open(
        config.instance_lock_path.name,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=runtime_fd,
    )
    try:
        os.fchown(
            descriptor,
            config.expected_observer_uid,
            config.expected_observer_gid,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        named = os.stat(
            config.instance_lock_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != config.expected_observer_uid
            or metadata.st_gid != config.expected_observer_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime observation lock metadata is unsafe"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_frontend_socket(
    runtime_fd: int,
    config: RuntimeActionObservationPublisherConfig,
) -> None:
    try:
        metadata = os.stat(
            config.frontend_socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(metadata.st_mode) or (
        metadata.st_nlink != 1
        or metadata.st_uid != config.expected_observer_uid
    ):
        raise RuntimeActionObservationPublisherError(
            "existing runtime observation socket is unsafe"
        )
    current = os.stat(
        config.frontend_socket_path.name,
        dir_fd=runtime_fd,
        follow_symlinks=False,
    )
    if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
        raise RuntimeActionObservationPublisherError(
            "existing runtime observation socket changed"
        )
    os.unlink(config.frontend_socket_path.name, dir_fd=runtime_fd)
    os.fsync(runtime_fd)


def _runtime_peer(value: object) -> tuple[int, int, int]:
    if (
        not isinstance(value, tuple)
        or len(value) != 3
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime observation peer credentials are invalid"
        )
    pid, uid, gid = value
    if pid <= 0 or uid < 0 or gid < 0:
        raise RuntimeActionObservationPublisherError(
            "runtime observation peer credentials are invalid"
        )
    return pid, uid, gid


def _validate_config(config: RuntimeActionObservationPublisherConfig) -> None:
    if not isinstance(config, RuntimeActionObservationPublisherConfig):
        raise RuntimeActionObservationPublisherError(
            "runtime observation configuration is invalid"
        )
    for value in (
        config.expected_observer_uid,
        config.expected_observer_gid,
        config.expected_runtime_uid,
        config.expected_runtime_gid,
        config.expected_broker_uid,
        config.expected_broker_gid,
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeActionObservationPublisherError(
                "runtime observation identity is invalid"
            )
    if (
        os.name != "posix"
        or os.geteuid() != config.expected_observer_uid
        or os.getegid() != config.expected_observer_gid
        or len(
            {
                config.expected_observer_uid,
                config.expected_runtime_uid,
                config.expected_broker_uid,
            }
        )
        != 3
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime observation identity is invalid"
        )
    for digest in (
        config.expected_runtime_digest,
        config.expected_active_skill_digest,
        config.expected_sensor_digest,
    ):
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise RuntimeActionObservationPublisherError(
                "runtime observation digest pin is invalid"
            )
    paths = (
        config.frontend_socket_path,
        config.runtime_directory,
        config.instance_lock_path,
        config.backend_socket_path,
        config.protected_root,
    )
    if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
        raise RuntimeActionObservationPublisherError(
            "runtime observation paths must be absolute Path values"
        )
    if (
        config.frontend_socket_path.parent != config.runtime_directory
        or config.instance_lock_path.parent != config.runtime_directory
        or config.frontend_socket_path.name == config.instance_lock_path.name
        or len(
            {
                config.frontend_socket_path,
                config.instance_lock_path,
                config.backend_socket_path,
                config.protected_root,
                config.runtime_directory,
            }
        )
        != 5
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime observation paths are invalid"
        )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
        raise RuntimeActionObservationPublisherError(
            "runtime observation directory identity is invalid"
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _valid_timeout(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 < value <= 0.5
    )
