"""Lineage-bound capability gateway around the source-frozen v3 publisher."""

from __future__ import annotations

import fcntl
import os
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .oci_worker_protocol import WorkerProtocolError, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _peer_credentials,
    _read_frame,
    _send_frame,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
    _connect_backend,
    _open_instance_lock,
    _open_protected_root,
    _open_runtime_directory,
    _prepare_frontend_socket,
    _runtime_peer,
    _valid_timeout,
)
from .runtime_action_observation_publisher_v2 import (
    _EMPTY_DIGEST,
    RuntimeActionObservationPublisherV2Config,
    _adopt_runtime_fs_identity,
    _restore_observer_fs_identity,
    _v1_config,
    build_profiled_submission,
)
from .runtime_action_observation_publisher_v2 import (
    _validate_config as _validate_v2_config,
)
from .runtime_active_skill_lineage import (
    DEFAULT_PROTECTED_INSTALL_ROOT,
    verify_runtime_active_skill_lineage,
)
from .runtime_capability_grant import (
    RuntimeCapabilityGrantError,
    parse_runtime_capability_grant,
)
from .runtime_lineage_capability_issuer import (
    hold_profiled_runtime_capability_issuance,
)
from .runtime_process_profile import (
    measure_runtime_process_profile,
    open_peer_pidfd,
    require_live_pidfd,
)


@dataclass(frozen=True, slots=True)
class RuntimeActionObservationPublisherV4Config:
    """Profiled publisher configuration plus one protected-install grant."""

    publisher: RuntimeActionObservationPublisherV2Config
    capability_grant: bytes
    protected_install_root: Path = DEFAULT_PROTECTED_INSTALL_ROOT


def serve_runtime_action_observation_publisher_v4(
    config: RuntimeActionObservationPublisherV4Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve sensor-issued, profile-attributed requests until interrupted."""

    _validate_config(config)
    if not _valid_timeout(request_timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "O_PATH"):
        raise RuntimeActionObservationPublisherError(
            "Linux SO_PEERCRED and O_PATH are required"
        )

    publisher = config.publisher
    base = _v1_config(publisher, _EMPTY_DIGEST)
    runtime_fd = _open_runtime_directory(base)
    lock_fd = -1
    locked = False
    listener: socket.socket | None = None
    bound = False
    socket_identity: tuple[int, int] | None = None
    runtime_fs_identity = False
    try:
        lock_fd = _open_instance_lock(runtime_fd, base)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeActionObservationPublisherError(
                "runtime observation publisher is already running"
            ) from exc
        locked = True
        _prepare_frontend_socket(runtime_fd, base)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(publisher.frontend_socket_path))
        bound = True
        metadata = os.stat(
            publisher.frontend_socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        socket_identity = metadata.st_dev, metadata.st_ino
        os.chown(
            publisher.frontend_socket_path,
            publisher.expected_observer_uid,
            publisher.expected_runtime_gid,
        )
        os.chmod(publisher.frontend_socket_path, 0o660, follow_symlinks=False)
        metadata = os.stat(
            publisher.frontend_socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != publisher.expected_observer_uid
            or metadata.st_gid != publisher.expected_runtime_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime observation socket metadata is unsafe"
            )
        os.fsync(runtime_fd)
        listener.listen(16)
        _adopt_runtime_fs_identity(
            publisher.expected_runtime_uid,
            publisher.expected_runtime_gid,
            publisher.expected_observer_uid,
            publisher.expected_observer_gid,
        )
        runtime_fs_identity = True
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
                    continue
    except RuntimeActionObservationPublisherError:
        raise
    except OSError as exc:
        raise RuntimeActionObservationPublisherError(
            f"runtime observation transport failed: {exc}"
        ) from exc
    finally:
        cleanup_error: OSError | None = None
        if runtime_fs_identity:
            try:
                _restore_observer_fs_identity(
                    publisher.expected_observer_uid,
                    publisher.expected_observer_gid,
                )
            except RuntimeActionObservationPublisherError as exc:
                cleanup_error = OSError(str(exc))
        if listener is not None:
            try:
                listener.close()
            except OSError as exc:
                cleanup_error = exc
        if bound:
            try:
                current = os.stat(
                    publisher.frontend_socket_path.name,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino):
                    os.unlink(publisher.frontend_socket_path.name, dir_fd=runtime_fd)
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
    config: RuntimeActionObservationPublisherV4Config,
    *,
    timeout_seconds: float,
) -> None:
    if not _valid_timeout(timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    publisher = config.publisher
    pidfd = -1
    try:
        runtime_peer = _runtime_peer(_peer_credentials(connection))
        pid, uid, gid = runtime_peer
        if (
            uid != publisher.expected_runtime_uid
            or gid != publisher.expected_runtime_gid
        ):
            raise RuntimeActionObservationPublisherError(
                f"runtime observation peer {pid} has an unauthorized identity"
            )
        pidfd = open_peer_pidfd(connection, pid)
        before = measure_runtime_process_profile(
            pid,
            pidfd,
            publisher.runtime_profile,
            expected_uid=uid,
            expected_gid=gid,
        )
        deadline = time.monotonic() + timeout_seconds
        grant = parse_runtime_capability_grant(config.capability_grant)
        initial_lineage = verify_runtime_active_skill_lineage(
            pid,
            before,
            grant,
            protected_root=config.protected_install_root,
            deadline=deadline,
        )
        envelope = _read_frame(connection, deadline)
        after = measure_runtime_process_profile(
            pid,
            pidfd,
            publisher.runtime_profile,
            expected_uid=uid,
            expected_gid=gid,
        )
        if after != before:
            raise RuntimeActionObservationPublisherError(
                "runtime process profile changed while observed"
            )
        base = _v1_config(publisher, after["active_skill_digest"])
        protected_fd = _open_protected_root(base)
        try:
            submission = build_profiled_submission(
                envelope,
                runtime_peer,
                protected_fd,
                publisher,
                after,
            )
        finally:
            os.close(protected_fd)

        require_live_pidfd(pidfd)
        with _connect_backend(base, deadline) as backend:
            broker_pid, broker_uid, broker_gid = _runtime_peer(
                _peer_credentials(backend)
            )
            if (
                broker_uid != publisher.expected_broker_uid
                or broker_gid != publisher.expected_broker_gid
            ):
                raise RuntimeActionObservationPublisherError(
                    f"runtime broker peer {broker_pid} has an unauthorized identity"
                )
            require_live_pidfd(pidfd)
            final = measure_runtime_process_profile(
                pid,
                pidfd,
                publisher.runtime_profile,
                expected_uid=uid,
                expected_gid=gid,
            )
            if final != after:
                raise RuntimeActionObservationPublisherError(
                    "runtime process profile changed before capability issuance"
                )
            with hold_profiled_runtime_capability_issuance(
                submission,
                config.capability_grant,
                int(time.time()),
                pidfd=pidfd,
                lineage_snapshot=initial_lineage,
                protected_install_root=config.protected_install_root,
                deadline=deadline,
            ) as issuance:
                _send_frame(backend, canonical_json(issuance), deadline)
                backend.shutdown(socket.SHUT_WR)
                response = _read_frame(backend, deadline)
        _send_frame(connection, canonical_json(response), deadline)
    except RuntimeActionObservationPublisherError:
        raise
    except (
        RuntimeActionBrokerError,
        RuntimeCapabilityGrantError,
        WorkerProtocolError,
        OSError,
    ) as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime observation relay failed"
        ) from exc
    finally:
        if pidfd >= 0:
            os.close(pidfd)


def _validate_config(config: RuntimeActionObservationPublisherV4Config) -> None:
    if not isinstance(config, RuntimeActionObservationPublisherV4Config):
        raise RuntimeActionObservationPublisherError(
            "runtime capability publisher configuration is invalid"
        )
    _validate_v2_config(config.publisher)
    if (
        not isinstance(config.protected_install_root, Path)
        or not config.protected_install_root.is_absolute()
        or config.protected_install_root == Path(config.protected_install_root.anchor)
    ):
        raise RuntimeActionObservationPublisherError(
            "protected install root configuration is invalid"
        )
    try:
        parse_runtime_capability_grant(config.capability_grant)
    except RuntimeCapabilityGrantError as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime capability grant configuration is invalid"
        ) from exc
