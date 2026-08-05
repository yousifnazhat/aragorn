"""Profile-attributing wrapper around the source-frozen runtime broker."""

from __future__ import annotations

import logging
import os
import socket
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import (
    _OBSERVED_SUBMISSION_FIELDS,
    RuntimeActionBrokerConfig,
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
    _acquire_lock,
    _atomic_publish_at,
    _directory_identity,
    _exact,
    _observed_submission,
    _open_lock_file,
    _open_protected_directory,
    _peer_credentials,
    _positive_uint,
    _prepare_socket_path,
    _read_frame,
    _read_owned_bytes_at,
    _recover_before_listen,
    _release_lock_and_close,
    _require_digest,
    _send_frame,
    _uint,
    mediate_observed_runtime_create,
)
from .runtime_action_broker import (
    _validate_config as _validate_v1_config,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from .runtime_process_profile import (
    ATTRIBUTION_AUTHORITY,
    ATTRIBUTION_SCHEMA,
    _cgroup_path,
)

_LOG = logging.getLogger(__name__)
_PROFILED_SUBMISSION_FIELDS = _OBSERVED_SUBMISSION_FIELDS | {"runtime_attribution"}
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


@dataclass(frozen=True, slots=True)
class RuntimeActionBrokerV2Config:
    broker: RuntimeActionBrokerConfig
    expected_runtime_profile_digest: str
    profile_pending_path: Path
    profile_receipt_path: Path


def mediate_profiled_runtime_create(
    submission: object,
    config: RuntimeActionBrokerV2Config,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Mediate one v2 submission and durably bind its attribution to the result."""

    _validate_config(config)
    legacy, attribution, submission_digest = _profiled_submission(submission, config)
    pending = {
        "schema": "aragorn/runtime-process-profile-pending/v1",
        "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
        "submission_digest": submission_digest,
        "envelope_digest": legacy["envelope_digest"],
        "request_digest": legacy["request_digest"],
        "measured_action": legacy["measured_action"],
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
    }
    _create_profile_pending(config, pending, deadline_monotonic)
    try:
        result = mediate_observed_runtime_create(
            legacy,
            config.broker,
            deadline_monotonic=deadline_monotonic,
        )
    except RuntimeActionEffectIndeterminate:
        raise
    except RuntimeActionBrokerError:
        _discard_profile_pending(config, pending, deadline_monotonic)
        raise
    receipt = {
        "schema": "aragorn/runtime-process-profile-receipt/v1",
        "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "submission_digest": submission_digest,
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
        "broker_result": result,
        "broker_result_digest": canonical_digest(result),
    }
    try:
        _persist_profile_receipt(config, receipt, deadline_monotonic)
        _discard_profile_pending(config, pending, deadline_monotonic)
    except RuntimeActionBrokerError as exc:
        if result["effect_status"] == "CREATED":
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but its profile receipt failed"
            ) from exc
        raise
    return result


def serve_runtime_action_broker_v2(
    config: RuntimeActionBrokerV2Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve v2 sensor submissions until interrupted by systemd."""

    _validate_config(config)
    broker = config.broker
    if not 0 < request_timeout_seconds <= 0.5:
        raise RuntimeActionBrokerError("broker request timeout is invalid")
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeActionBrokerError("Linux SO_PEERCRED is required")

    # The v1 transport is retained evidence and therefore source-frozen.
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
        _require_no_profile_pending(config, request_timeout_seconds)
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
    except OSError as exc:
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
    config: RuntimeActionBrokerV2Config,
    *,
    timeout_seconds: float,
) -> None:
    broker = config.broker
    pid, uid, gid = _peer_credentials(connection)
    if uid != broker.expected_peer_uid or gid != broker.expected_peer_gid:
        raise RuntimeActionBrokerError(
            f"runtime broker peer {pid} has an unauthorized identity"
        )
    deadline = time.monotonic() + timeout_seconds
    result = mediate_profiled_runtime_create(
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


def _profiled_submission(
    value: object,
    config: RuntimeActionBrokerV2Config,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    submission = _exact(
        value,
        _PROFILED_SUBMISSION_FIELDS,
        "profiled runtime submission",
    )
    if submission["schema"] != "aragorn/runtime-observed-create-submission/v2":
        raise RuntimeActionBrokerError("profiled runtime submission is required")
    attribution = _exact(
        submission["runtime_attribution"],
        _ATTRIBUTION_FIELDS,
        "runtime process profile attribution",
    )
    if (
        attribution["schema"] != ATTRIBUTION_SCHEMA
        or attribution["authority"] != ATTRIBUTION_AUTHORITY
    ):
        raise RuntimeActionBrokerError("runtime process profile attribution is invalid")
    for field in (
        "profile_digest",
        "runtime_digest",
        "executable_digest",
        "active_skill_digest",
    ):
        _require_digest(attribution[field], f"runtime attribution {field}")
    try:
        _cgroup_path(attribution["cgroup"])
    except RuntimeActionObservationPublisherError as exc:
        raise RuntimeActionBrokerError("runtime attribution cgroup is invalid") from exc
    skill_path = attribution["skill_path"]
    if (
        not isinstance(skill_path, str)
        or not Path(skill_path).is_absolute()
        or Path(skill_path).name != "SKILL.md"
    ):
        raise RuntimeActionBrokerError("runtime attribution skill path is invalid")
    _positive_uint(attribution["pid"], "runtime attribution pid")
    _uint(attribution["uid"], "runtime attribution uid")
    _uint(attribution["gid"], "runtime attribution gid")
    _positive_uint(
        attribution["start_time_ticks"],
        "runtime attribution start time",
    )
    namespace = _exact(
        attribution["mount_namespace"],
        {"device", "inode"},
        "runtime attribution mount namespace",
    )
    _uint(namespace["device"], "runtime attribution mount device")
    _positive_uint(namespace["inode"], "runtime attribution mount inode")

    legacy = {**submission, "schema": "aragorn/runtime-observed-create-submission/v1"}
    legacy.pop("runtime_attribution")
    legacy = _observed_submission(legacy)
    peer = legacy["runtime_peer"]
    measured = legacy["measured_action"]
    request = legacy["envelope"]["request"]
    if (
        attribution["profile_digest"] != config.expected_runtime_profile_digest
        or (attribution["pid"], attribution["uid"], attribution["gid"])
        != (peer.get("pid"), peer.get("uid"), peer.get("gid"))
        or any(
            attribution[field] != measured.get(field)
            or attribution[field] != request.get(field)
            for field in ("runtime_digest", "active_skill_digest")
        )
    ):
        raise RuntimeActionBrokerError("runtime process profile attribution is unbound")
    return legacy, attribution, canonical_digest(submission)


def _persist_profile_receipt(
    config: RuntimeActionBrokerV2Config,
    receipt: dict[str, Any],
    deadline: float | None,
) -> None:
    broker = config.broker

    def publish(control_fd: int) -> None:
        # ponytail: latest-only for the bounded slice; use an append-only CAS
        # when multi-action forensic retention becomes a qualified requirement.
        _atomic_publish_at(
            control_fd,
            config.profile_receipt_path.name,
            canonical_json(receipt),
            expected_uid=broker.expected_broker_uid,
        )

    _with_profile_lock(config, deadline, publish)


def _create_profile_pending(
    config: RuntimeActionBrokerV2Config,
    pending: dict[str, Any],
    deadline: float | None,
) -> None:
    broker = config.broker

    def publish(control_fd: int) -> None:
        try:
            os.stat(
                config.profile_pending_path.name,
                dir_fd=control_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise RuntimeActionBrokerError(
                "an unresolved runtime process profile action exists"
            )
        _atomic_publish_at(
            control_fd,
            config.profile_pending_path.name,
            canonical_json(pending),
            expected_uid=broker.expected_broker_uid,
        )

    _with_profile_lock(config, deadline, publish)


def _discard_profile_pending(
    config: RuntimeActionBrokerV2Config,
    pending: dict[str, Any],
    deadline: float | None,
) -> None:
    broker = config.broker
    expected = canonical_json(pending)

    def discard(control_fd: int) -> None:
        current = _read_owned_bytes_at(
            control_fd,
            config.profile_pending_path.name,
            max_bytes=len(expected),
            expected_uid=broker.expected_broker_uid,
            exact_mode=0o400,
            label="runtime process profile pending record",
        )
        if current != expected:
            raise RuntimeActionBrokerError(
                "runtime process profile pending record changed"
            )
        os.unlink(config.profile_pending_path.name, dir_fd=control_fd)
        os.fsync(control_fd)

    _with_profile_lock(config, deadline, discard)


def _require_no_profile_pending(
    config: RuntimeActionBrokerV2Config,
    timeout_seconds: float,
) -> None:
    def check(control_fd: int) -> None:
        try:
            os.stat(
                config.profile_pending_path.name,
                dir_fd=control_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        raise RuntimeActionBrokerError(
            "an unresolved runtime process profile action exists"
        )

    _with_profile_lock(config, time.monotonic() + timeout_seconds, check)


def _with_profile_lock(
    config: RuntimeActionBrokerV2Config,
    deadline: float | None,
    operation: Callable[[int], None],
) -> None:
    broker = config.broker
    control_fd = lock_fd = -1
    locked = False
    try:
        control_fd = _open_protected_directory(
            broker.control_root,
            broker.expected_broker_uid,
            "runtime broker control root",
        )
        lock_fd = _open_lock_file(control_fd, broker)
        _acquire_lock(
            lock_fd,
            time.monotonic() + 0.5 if deadline is None else deadline,
        )
        locked = True
        operation(control_fd)
    except RuntimeActionBrokerError:
        raise
    except (OSError, ValueError) as exc:
        raise RuntimeActionBrokerError(
            "runtime process profile state update failed"
        ) from exc
    finally:
        failure = _release_lock_and_close(lock_fd, locked, control_fd)
        if failure is not None:
            raise RuntimeActionBrokerError(
                "runtime process profile state cleanup failed"
            ) from failure


def _validate_config(config: RuntimeActionBrokerV2Config) -> None:
    if not isinstance(config, RuntimeActionBrokerV2Config):
        raise RuntimeActionBrokerError(
            "runtime profile broker configuration is invalid"
        )
    _validate_v1_config(config.broker)
    _require_digest(
        config.expected_runtime_profile_digest,
        "expected runtime profile digest",
    )
    if (
        config.broker.expected_runtime_uid is None
        or config.profile_pending_path.parent != config.broker.control_root
        or config.profile_pending_path.name != "profile-pending.json"
        or config.profile_receipt_path.parent != config.broker.control_root
        or config.profile_receipt_path.name != "profile-receipt.json"
        or config.profile_pending_path == config.profile_receipt_path
        or config.profile_receipt_path
        in {
            config.broker.socket_path,
            config.broker.instance_lock_path,
            config.broker.lock_path,
            config.broker.policy_path,
            config.broker.revocations_path,
            config.broker.health_path,
            config.broker.observation_path,
            config.broker.state_path,
        }
        or config.profile_pending_path
        in {
            config.broker.socket_path,
            config.broker.instance_lock_path,
            config.broker.lock_path,
            config.broker.policy_path,
            config.broker.revocations_path,
            config.broker.health_path,
            config.broker.observation_path,
            config.broker.state_path,
        }
    ):
        raise RuntimeActionBrokerError(
            "runtime profile broker configuration is invalid"
        )
