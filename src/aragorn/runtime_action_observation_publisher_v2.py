"""Profile-attributing runtime observation gateway."""

from __future__ import annotations

import ctypes
import fcntl
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
    _peer_credentials,
    _read_frame,
    _send_frame,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherConfig,
    RuntimeActionObservationPublisherError,
    _connect_backend,
    _open_instance_lock,
    _open_protected_root,
    _open_runtime_directory,
    _prepare_frontend_socket,
    _runtime_peer,
    _valid_timeout,
    build_observed_submission,
)
from .runtime_action_observation_publisher import (
    _validate_config as _validate_v1_config,
)
from .runtime_process_profile import (
    ATTRIBUTION_AUTHORITY,
    ATTRIBUTION_SCHEMA,
    RuntimeProcessProfile,
    measure_runtime_process_profile,
    open_peer_pidfd,
)

_EMPTY_DIGEST = "sha256:" + "0" * 64
_CAP_SETGID = 6
_CAP_SETUID = 7
_CAP_SETPCAP = 8
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_PR_CAPBSET_DROP = 24
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_ATTRIBUTION_FIELDS = {
    "schema",
    "authority",
    "profile_digest",
    "runtime_digest",
    "executable_digest",
    "active_skill_digest",
    "skill_path",
    "cgroup",
    "pid",
    "uid",
    "gid",
    "start_time_ticks",
    "mount_namespace",
}


class _CapabilityHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class _CapabilityData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


@dataclass(frozen=True, slots=True)
class RuntimeActionObservationPublisherV2Config:
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
    expected_sensor_digest: str
    runtime_profile: RuntimeProcessProfile


def build_profiled_submission(
    envelope: object,
    runtime_peer: tuple[int, int, int],
    protected_fd: int,
    config: RuntimeActionObservationPublisherV2Config,
    attribution: object,
) -> dict[str, Any]:
    """Build a broker-visible v2 submission from derived attribution."""

    _validate_config(config)
    pid, uid, gid = _runtime_peer(runtime_peer)
    if not isinstance(attribution, dict) or set(attribution) != _ATTRIBUTION_FIELDS:
        raise RuntimeActionObservationPublisherError(
            "runtime process profile attribution is invalid"
        )
    if (
        attribution["schema"] != ATTRIBUTION_SCHEMA
        or attribution["authority"] != ATTRIBUTION_AUTHORITY
        or attribution["profile_digest"] != config.runtime_profile.digest
        or attribution["runtime_digest"] != config.expected_runtime_digest
        or attribution["executable_digest"] != config.runtime_profile.executable_digest
        or attribution["skill_path"] != str(config.runtime_profile.skill_path)
        or attribution["cgroup"] != config.runtime_profile.cgroup
        or (attribution["pid"], attribution["uid"], attribution["gid"])
        != (pid, uid, gid)
        or isinstance(attribution["start_time_ticks"], bool)
        or not isinstance(attribution["start_time_ticks"], int)
        or attribution["start_time_ticks"] <= 0
        or not isinstance(attribution["mount_namespace"], dict)
        or set(attribution["mount_namespace"]) != {"device", "inode"}
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in attribution["mount_namespace"].values()
        )
        or attribution["mount_namespace"]["inode"] <= 0
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime process profile attribution is invalid"
        )
    observed = build_observed_submission(
        envelope,
        runtime_peer,
        protected_fd,
        _v1_config(config, attribution["active_skill_digest"]),
    )
    return {
        **observed,
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "runtime_attribution": attribution,
    }


def serve_runtime_action_observation_publisher_v2(
    config: RuntimeActionObservationPublisherV2Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve profile-attributed requests until interrupted by systemd."""

    _validate_config(config)
    if not _valid_timeout(request_timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "O_PATH"):
        raise RuntimeActionObservationPublisherError(
            "Linux SO_PEERCRED and O_PATH are required"
        )

    # The v1 transport is retained evidence and therefore source-frozen.
    runtime_fd = _open_runtime_directory(_v1_config(config, _EMPTY_DIGEST))
    lock_fd = -1
    locked = False
    listener: socket.socket | None = None
    bound = False
    socket_identity: tuple[int, int] | None = None
    runtime_fs_identity = False
    try:
        lock_fd = _open_instance_lock(runtime_fd, _v1_config(config, _EMPTY_DIGEST))
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeActionObservationPublisherError(
                "runtime observation publisher is already running"
            ) from exc
        locked = True
        base = _v1_config(config, _EMPTY_DIGEST)
        _prepare_frontend_socket(runtime_fd, base)
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
        _adopt_runtime_fs_identity(
            config.expected_runtime_uid,
            config.expected_runtime_gid,
            config.expected_observer_uid,
            config.expected_observer_gid,
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
                    config.expected_observer_uid,
                    config.expected_observer_gid,
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
    config: RuntimeActionObservationPublisherV2Config,
    *,
    timeout_seconds: float,
) -> None:
    if not _valid_timeout(timeout_seconds):
        raise RuntimeActionObservationPublisherError(
            "runtime observation timeout is invalid"
        )
    pidfd = -1
    try:
        runtime_peer = _runtime_peer(_peer_credentials(connection))
        pid, uid, gid = runtime_peer
        if uid != config.expected_runtime_uid or gid != config.expected_runtime_gid:
            raise RuntimeActionObservationPublisherError(
                f"runtime observation peer {pid} has an unauthorized identity"
            )
        pidfd = open_peer_pidfd(connection, pid)
        before = measure_runtime_process_profile(
            pid,
            pidfd,
            config.runtime_profile,
            expected_uid=uid,
            expected_gid=gid,
        )
        deadline = time.monotonic() + timeout_seconds
        envelope = _read_frame(connection, deadline)
        after = measure_runtime_process_profile(
            pid,
            pidfd,
            config.runtime_profile,
            expected_uid=uid,
            expected_gid=gid,
        )
        if after != before:
            raise RuntimeActionObservationPublisherError(
                "runtime process profile changed while observed"
            )
        base = _v1_config(config, after["active_skill_digest"])
        protected_fd = _open_protected_root(base)
        try:
            submission = build_profiled_submission(
                envelope,
                runtime_peer,
                protected_fd,
                config,
                after,
            )
        finally:
            os.close(protected_fd)

        with _connect_backend(base, deadline) as backend:
            broker_pid, broker_uid, broker_gid = _runtime_peer(
                _peer_credentials(backend)
            )
            if (
                broker_uid != config.expected_broker_uid
                or broker_gid != config.expected_broker_gid
            ):
                raise RuntimeActionObservationPublisherError(
                    f"runtime broker peer {broker_pid} has an unauthorized identity"
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
    finally:
        if pidfd >= 0:
            os.close(pidfd)


def _v1_config(
    config: RuntimeActionObservationPublisherV2Config,
    active_skill_digest: str,
) -> RuntimeActionObservationPublisherConfig:
    return RuntimeActionObservationPublisherConfig(
        frontend_socket_path=config.frontend_socket_path,
        runtime_directory=config.runtime_directory,
        instance_lock_path=config.instance_lock_path,
        backend_socket_path=config.backend_socket_path,
        protected_root=config.protected_root,
        expected_observer_uid=config.expected_observer_uid,
        expected_observer_gid=config.expected_observer_gid,
        expected_runtime_uid=config.expected_runtime_uid,
        expected_runtime_gid=config.expected_runtime_gid,
        expected_broker_uid=config.expected_broker_uid,
        expected_broker_gid=config.expected_broker_gid,
        expected_runtime_digest=config.expected_runtime_digest,
        expected_active_skill_digest=active_skill_digest,
        expected_sensor_digest=config.expected_sensor_digest,
    )


def _adopt_runtime_fs_identity(
    runtime_uid: int,
    runtime_gid: int,
    observer_uid: int,
    observer_gid: int,
) -> None:
    """Adopt peer FS credentials, then irreversibly drop capabilities."""

    library = ctypes.CDLL(None, use_errno=True)
    library.setfsuid.argtypes = (ctypes.c_uint,)
    library.setfsuid.restype = ctypes.c_int
    library.setfsgid.argtypes = (ctypes.c_uint,)
    library.setfsgid.restype = ctypes.c_int
    library.prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    library.prctl.restype = ctypes.c_int
    library.capset.argtypes = (
        ctypes.POINTER(_CapabilityHeader),
        ctypes.POINTER(_CapabilityData),
    )
    library.capset.restype = ctypes.c_int
    try:
        library.setfsgid(runtime_gid)
        library.setfsuid(runtime_uid)
        status = _process_security_status()
        if status["fsuid"] != runtime_uid or status["fsgid"] != runtime_gid:
            raise OSError("runtime filesystem identity change failed")
        for capability in (_CAP_SETGID, _CAP_SETUID, _CAP_SETPCAP):
            if library.prctl(_PR_CAPBSET_DROP, capability, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "capability bounding drop failed")
        if library.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "ambient capability drop failed")
        header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
        data = (_CapabilityData * 2)()
        if library.capset(ctypes.byref(header), data) != 0:
            raise OSError(ctypes.get_errno(), "process capability drop failed")
        status = _process_security_status()
        if (
            status["fsuid"] != runtime_uid
            or status["fsgid"] != runtime_gid
            or any(
                status[field] != 0
                for field in (
                    "cap_eff",
                    "cap_prm",
                    "cap_inh",
                    "cap_amb",
                    "cap_bnd",
                )
            )
        ):
            raise OSError("runtime filesystem identity is not capability-free")
    except (OSError, ValueError) as exc:
        library.setfsuid(observer_uid)
        library.setfsgid(observer_gid)
        raise RuntimeActionObservationPublisherError(
            "runtime filesystem identity cannot be isolated"
        ) from exc


def _restore_observer_fs_identity(observer_uid: int, observer_gid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    library.setfsuid.argtypes = (ctypes.c_uint,)
    library.setfsuid.restype = ctypes.c_int
    library.setfsgid.argtypes = (ctypes.c_uint,)
    library.setfsgid.restype = ctypes.c_int
    library.setfsuid(observer_uid)
    library.setfsgid(observer_gid)
    status = _process_security_status()
    if status["fsuid"] != observer_uid or status["fsgid"] != observer_gid:
        raise RuntimeActionObservationPublisherError(
            "runtime observation filesystem identity cannot be restored"
        )


def _process_security_status() -> dict[str, int]:
    values = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        name, separator, remainder = line.partition(":")
        if not separator:
            continue
        if name == "Uid":
            identifiers = remainder.split()
            if len(identifiers) == 4 and all(value.isdigit() for value in identifiers):
                values["fsuid"] = int(identifiers[3])
        elif name == "Gid":
            identifiers = remainder.split()
            if len(identifiers) == 4 and all(value.isdigit() for value in identifiers):
                values["fsgid"] = int(identifiers[3])
        elif name in {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}:
            values[name.lower().replace("cap", "cap_")] = int(remainder, 16)
    expected = {
        "fsuid",
        "fsgid",
        "cap_eff",
        "cap_prm",
        "cap_inh",
        "cap_amb",
        "cap_bnd",
    }
    if set(values) != expected:
        raise ValueError("process security status is invalid")
    return values


def _validate_config(config: RuntimeActionObservationPublisherV2Config) -> None:
    if (
        not isinstance(config, RuntimeActionObservationPublisherV2Config)
        or not isinstance(config.runtime_profile, RuntimeProcessProfile)
        or config.runtime_profile.runtime_digest != config.expected_runtime_digest
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime process profile configuration is invalid"
        )
    _validate_v1_config(_v1_config(config, _EMPTY_DIGEST))
