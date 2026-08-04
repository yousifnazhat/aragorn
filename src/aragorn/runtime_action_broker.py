"""Fail-closed mediation for one digest-bound runtime file creation."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import secrets
import socket
import stat
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_digest, canonical_json
from .runtime_action_decision import (
    _InvalidRequest,
    _request as _validate_runtime_action_request,
    RuntimeActionStateError,
    evaluate_runtime_action,
    qualify_runtime_health_epoch,
    qualify_runtime_revocation_generation,
)

_LOG = logging.getLogger(__name__)
_FRAME_HEADER = struct.Struct(">I")
_PEER_CREDENTIALS = struct.Struct("3i")
_MAX_FRAME_BYTES = 64 * 1024
_MAX_PAYLOAD_BYTES = 32 * 1024
_MAX_OBSERVATION_LIFETIME_SECONDS = 5
_MAX_CONSUMED = 128
_MAX_CONTROL_BYTES = 128 * 1024
_TARGET_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_ENVELOPE_FIELDS = {"schema", "request", "effect"}
_EFFECT_FIELDS = {"schema", "operation", "target_name", "payload_base64"}
_OBSERVATION_FIELDS = {
    "schema",
    "authority",
    "sequence",
    "sensor_digest",
    "observed_at_unix",
    "expires_at_unix",
    "active",
    "measured_action",
}
_OBSERVED_SUBMISSION_FIELDS = {
    "schema",
    "authority",
    "sensor_digest",
    "envelope_digest",
    "request_digest",
    "runtime_peer",
    "measured_action",
    "envelope",
}
_RUNTIME_PEER_FIELDS = {"pid", "uid", "gid"}
_STATE_FIELDS = {
    "schema",
    "authority",
    "minimum_revocation_generation",
    "minimum_mediator_health_epoch",
    "consumed",
    "effect_journal",
}
_STATE_V1_FIELDS = _STATE_FIELDS - {"effect_journal"}
_CONSUMED_FIELDS = {"request_digest", "observation_digest", "expires_at_unix"}
_ACTION_DIGEST_FIELDS = ("operation_digest", "path_digest", "payload_digest")
_MEASURED_ACTION_FIELDS = {
    "schema",
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
    *_ACTION_DIGEST_FIELDS,
}
_TRANSACTION_FIELDS = {
    "schema",
    "authority",
    "status",
    "request_digest",
    "observation_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
    "payload_size",
    "target_name",
    "protected_root_device",
    "protected_root_inode",
    "staging_name",
    "staging_device",
    "staging_inode",
}
_STAGING_NAME = re.compile(r"\.aragorn-runtime-[0-9a-f]{24}\Z")


class RuntimeActionBrokerError(RuntimeError):
    """The broker could not safely complete a request."""


class RuntimeActionEffectIndeterminate(RuntimeActionBrokerError):
    """The effect may exist, but its completion could not be confirmed."""


class _ProtectedFileError(ValueError):
    pass


def require_owned_directory(
    descriptor: int,
    *,
    expected_uid: int,
    require_owner_write: bool,
    label: str,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_nlink < 1
        or metadata.st_uid != expected_uid
        or mode & 0o022
        or not mode & 0o100
        or (require_owner_write and not mode & 0o200)
    ):
        raise _ProtectedFileError(f"{label} must be broker-owned and protected")
    return metadata


def create_exclusive_file_at(
    parent_fd: int,
    *,
    prefix: str,
    mode: int,
) -> tuple[str, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _ in range(100):
        name = f"{prefix}{secrets.token_hex(12)}"
        try:
            descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, mode)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_size != 0
                or stat.S_IMODE(metadata.st_mode) != mode
            ):
                raise _ProtectedFileError("exclusive protected file metadata is unsafe")
            return name, descriptor
        except BaseException:
            os.close(descriptor)
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise _ProtectedFileError("cannot allocate an exclusive protected file")


def write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise _ProtectedFileError("protected file write made no progress")
        remaining = remaining[written:]


@dataclass(frozen=True, slots=True)
class RuntimeActionBrokerConfig:
    """Fixed paths and identities owned by the broker launcher."""

    socket_path: Path
    instance_lock_path: Path
    lock_path: Path
    control_root: Path
    protected_root: Path
    staging_root: Path
    policy_path: Path
    revocations_path: Path
    health_path: Path
    observation_path: Path
    state_path: Path
    expected_broker_uid: int
    expected_peer_uid: int
    expected_peer_gid: int
    expected_runtime_digest: str
    expected_runtime_uid: int | None = None
    expected_runtime_gid: int | None = None


def serve_runtime_action_broker(
    config: RuntimeActionBrokerConfig,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve create-only requests until interrupted by the service manager."""

    _validate_config(config)
    if not 0 < request_timeout_seconds <= 0.5:
        raise RuntimeActionBrokerError("broker request timeout is invalid")
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeActionBrokerError("Linux SO_PEERCRED is required")

    control_fd = _open_protected_directory(
        config.control_root,
        config.expected_broker_uid,
        "runtime broker control root",
    )
    listener: socket.socket | None = None
    instance_lock_fd = -1
    instance_locked = False
    bound = False
    socket_identity: tuple[int, int] | None = None
    try:
        if _directory_identity(os.lstat(config.control_root)) != _directory_identity(
            os.fstat(control_fd)
        ):
            raise RuntimeActionBrokerError("runtime broker control root changed")
        instance_lock_fd = _open_lock_file(
            control_fd,
            config,
            path=config.instance_lock_path,
        )
        _acquire_lock(instance_lock_fd, time.monotonic())
        instance_locked = True
        _recover_before_listen(config, request_timeout_seconds)
        _prepare_socket_path(control_fd, config)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(config.socket_path))
        bound = True
        metadata = os.stat(
            config.socket_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
        socket_identity = metadata.st_dev, metadata.st_ino
        os.chown(
            config.socket_path, config.expected_broker_uid, config.expected_peer_gid
        )
        os.chmod(config.socket_path, 0o660, follow_symlinks=False)
        metadata = os.stat(
            config.socket_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != config.expected_broker_uid
            or metadata.st_gid != config.expected_peer_gid
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
                    config.socket_path.name,
                    dir_fd=control_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino) or (
                    socket_identity is None
                    and stat.S_ISSOCK(current.st_mode)
                    and current.st_uid == config.expected_broker_uid
                ):
                    os.unlink(config.socket_path.name, dir_fd=control_fd)
                    os.fsync(control_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_failure = cleanup_failure or exc
        lock_cleanup_failure = _release_lock_and_close(
            instance_lock_fd,
            instance_locked,
            control_fd,
        )
        cleanup_failure = cleanup_failure or lock_cleanup_failure
        if cleanup_failure is not None:
            raise RuntimeActionBrokerError(
                "runtime broker transport cleanup failed"
            ) from cleanup_failure


def mediate_runtime_create(
    envelope: object,
    config: RuntimeActionBrokerConfig,
    *,
    clock: Callable[[], int] | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Consume one authorized request before atomically creating its target."""

    return _mediate_runtime_create(
        envelope,
        config,
        clock=clock,
        deadline_monotonic=deadline_monotonic,
        observed_submission=None,
    )


def mediate_observed_runtime_create(
    submission: object,
    config: RuntimeActionBrokerConfig,
    *,
    clock: Callable[[], int] | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Mediate one request measured by the authenticated observation gateway."""

    observed = _observed_submission(submission)
    return _mediate_runtime_create(
        observed["envelope"],
        config,
        clock=clock,
        deadline_monotonic=deadline_monotonic,
        observed_submission=observed,
    )


def _mediate_runtime_create(
    envelope: object,
    config: RuntimeActionBrokerConfig,
    *,
    clock: Callable[[], int] | None,
    deadline_monotonic: float | None,
    observed_submission: dict[str, Any] | None,
) -> dict[str, Any]:

    _validate_config(config)
    request, target_name, payload = _request_effect(envelope)
    trusted_clock = (lambda: int(time.time())) if clock is None else clock
    deadline = (
        time.monotonic() + 0.5 if deadline_monotonic is None else deadline_monotonic
    )
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or (isinstance(deadline, float) and not math.isfinite(deadline))
    ):
        raise RuntimeActionBrokerError("runtime broker deadline is invalid")

    control_fd = -1
    protected_fd = -1
    staging_fd = -1
    lock_fd = -1
    locked = False
    effect_committed = False
    try:
        control_fd, protected_fd, staging_fd = _open_broker_roots(config)
        lock_fd = _open_lock_file(control_fd, config)
        _acquire_lock(lock_fd, deadline)
        locked = True
        _recover_effect_journal(
            control_fd,
            protected_fd,
            staging_fd,
            config,
        )

        action_digests = _action_digests(protected_fd, target_name, payload)
        now = _clock_value(trusted_clock)
        if observed_submission is not None:
            _publish_observed_state_locked(
                control_fd,
                config,
                request,
                action_digests,
                observed_submission,
                now,
            )
        state, observation_digest, decision, broker_reasons = _evaluate_snapshot(
            control_fd,
            config,
            request,
            action_digests,
            now,
        )
        request_digest = canonical_digest(request)
        consumed = state["consumed"]
        if any(
            item["request_digest"] == request_digest
            or item["observation_digest"] == observation_digest
            for item in consumed
        ):
            return _result(
                request_digest=request_digest,
                observation_digest=observation_digest,
                target_name=target_name,
                verdict="BLOCK",
                reason_codes=["BROKER_REPLAY_BLOCKED"],
                effect_status="NOT_PERFORMED",
                decision=None,
            )
        if len(consumed) >= _MAX_CONSUMED:
            raise RuntimeActionBrokerError("runtime broker replay state is full")

        consumed.append(
            {
                "request_digest": request_digest,
                "observation_digest": observation_digest,
                "expires_at_unix": now + _MAX_OBSERVATION_LIFETIME_SECONDS,
            }
        )
        state["consumed"] = sorted(consumed, key=canonical_json)
        _commit_state(control_fd, config, state)

        if decision["verdict"] != "ALLOW" or broker_reasons:
            return _result(
                request_digest=request_digest,
                observation_digest=observation_digest,
                target_name=target_name,
                verdict="BLOCK",
                reason_codes=broker_reasons or decision["reason_codes"],
                effect_status="NOT_PERFORMED",
                decision=decision,
            )

        final_observation_digest = observation_digest
        final_decision = decision
        final_reasons: list[str] = []
        journal_state: dict[str, Any] | None = None

        def authorize_link() -> bool:
            nonlocal final_observation_digest, final_decision
            nonlocal final_reasons, journal_state
            previous_now = now
            for _attempt in range(2):
                effect_now = _clock_value(trusted_clock)
                if effect_now < previous_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    return False
                final_state, final_observation_digest, final_decision, reasons = (
                    _evaluate_snapshot(
                        control_fd,
                        config,
                        request,
                        action_digests,
                        effect_now,
                        minimum_state=state,
                    )
                )
                after_evaluation = _clock_value(trusted_clock)
                if after_evaluation == effect_now:
                    final_reasons = reasons
                    break
                if after_evaluation < effect_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    return False
                previous_now = after_evaluation
            else:
                final_reasons = ["BROKER_CLOCK_UNSTABLE"]
                return False
            if (
                final_observation_digest != observation_digest
                or not any(
                    item["request_digest"] == request_digest
                    and item["observation_digest"] == observation_digest
                    for item in final_state["consumed"]
                )
                or final_decision["verdict"] != "ALLOW"
            ):
                final_reasons = (
                    final_reasons
                    or final_decision["reason_codes"]
                    or ["BROKER_CLAIM_STATE_CHANGED"]
                )
                return False
            if time.monotonic() >= deadline:
                final_reasons = ["BROKER_DEADLINE_EXPIRED"]
                return False
            if final_reasons:
                return False
            try:
                os.stat(
                    target_name,
                    dir_fd=protected_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise RuntimeActionBrokerError("runtime create target already exists")
            journal_state = final_state
            return True

        def record_pending(
            staging_name: str,
            staged: os.stat_result,
        ) -> None:
            nonlocal journal_state
            if (
                journal_state is None
                or journal_state["effect_journal"] is not None
                or _STAGING_NAME.fullmatch(staging_name) is None
                or staged.st_gid != _effect_gid(config)
            ):
                raise RuntimeActionBrokerError(
                    "runtime effect journal preparation is invalid"
                )
            root = os.fstat(protected_fd)
            journal_state = {
                **journal_state,
                "effect_journal": {
                    "schema": "aragorn/runtime-effect-journal/v1",
                    "authority": "BROKER_RECOVERY_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
                    "status": "PENDING",
                    "request_digest": request_digest,
                    "observation_digest": observation_digest,
                    **action_digests,
                    "payload_size": len(payload),
                    "target_name": target_name,
                    "protected_root_device": root.st_dev,
                    "protected_root_inode": root.st_ino,
                    "staging_name": staging_name,
                    "staging_device": staged.st_dev,
                    "staging_inode": staged.st_ino,
                },
            }
            _commit_state(control_fd, config, journal_state)

        def record_applied(
            staging_name: str,
            staged: os.stat_result,
        ) -> None:
            nonlocal journal_state
            if journal_state is None:
                raise RuntimeActionBrokerError("runtime effect journal is absent")
            transaction = journal_state["effect_journal"]
            if (
                not isinstance(transaction, dict)
                or transaction.get("status") != "PENDING"
                or transaction.get("staging_name") != staging_name
                or (
                    transaction.get("staging_device"),
                    transaction.get("staging_inode"),
                )
                != (staged.st_dev, staged.st_ino)
            ):
                raise RuntimeActionBrokerError("runtime effect journal changed")
            journal_state = {
                **journal_state,
                "effect_journal": {**transaction, "status": "APPLIED"},
            }
            _commit_state(control_fd, config, journal_state)

        if not _atomic_create(
            staging_fd,
            protected_fd,
            target_name,
            payload,
            authorize_link=authorize_link,
            record_pending=record_pending,
            record_applied=record_applied,
        ):
            return _result(
                request_digest=request_digest,
                observation_digest=final_observation_digest,
                target_name=target_name,
                verdict="BLOCK",
                reason_codes=final_reasons,
                effect_status="NOT_PERFORMED",
                decision=final_decision,
            )
        effect_committed = True
        if (
            journal_state is None
            or not isinstance(journal_state["effect_journal"], dict)
            or journal_state["effect_journal"].get("status") != "APPLIED"
        ):
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed without an applied journal"
            )
        try:
            _recover_effect_journal(
                control_fd,
                protected_fd,
                staging_fd,
                config,
            )
        except (
            OSError,
            RuntimeActionBrokerError,
            WorkerProtocolError,
            _ProtectedFileError,
        ) as exc:
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but could not be finalized"
            ) from exc
        return _result(
            request_digest=request_digest,
            observation_digest=observation_digest,
            target_name=target_name,
            verdict="ALLOW",
            reason_codes=[],
            effect_status="CREATED",
            decision=final_decision,
        )
    except RuntimeActionEffectIndeterminate:
        effect_committed = True
        raise
    except RuntimeActionBrokerError:
        raise
    except (OSError, _ProtectedFileError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(
            f"runtime action mediation failed: {exc}"
        ) from exc
    finally:
        cleanup_failure = _release_lock_and_close(
            lock_fd,
            locked,
            staging_fd,
            protected_fd,
            control_fd,
        )
        if effect_committed and cleanup_failure is not None:
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but broker cleanup failed"
            ) from cleanup_failure
        if cleanup_failure is not None:
            raise RuntimeActionBrokerError(
                "runtime broker cleanup failed"
            ) from cleanup_failure


def publish_runtime_control_document(
    path: Path,
    document: object,
    config: RuntimeActionBrokerConfig,
    *,
    timeout_seconds: float = 0.5,
    clock: Callable[[], int] | None = None,
) -> None:
    """Atomically publish trusted state under the broker's private lock."""

    _validate_config(config)
    allowed = {
        config.revocations_path,
        config.health_path,
        config.observation_path,
    }
    if path not in allowed or not 0 < timeout_seconds <= 0.5:
        raise RuntimeActionBrokerError("runtime control publication is invalid")
    trusted_clock = (lambda: int(time.time())) if clock is None else clock
    control_fd = -1
    lock_fd = -1
    locked = False
    try:
        raw = canonical_json(document)
        publication = _parse_canonical_document(raw, "runtime control publication")
        control_fd = _open_protected_directory(
            config.control_root,
            config.expected_broker_uid,
            "runtime broker control root",
        )
        lock_fd = _open_lock_file(control_fd, config)
        _acquire_lock(lock_fd, time.monotonic() + timeout_seconds)
        locked = True
        _publish_control_locked(
            control_fd,
            path,
            publication,
            raw,
            config,
            _clock_value(trusted_clock),
        )
    except RuntimeActionBrokerError:
        raise
    except (OSError, _ProtectedFileError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(
            f"runtime control publication failed: {exc}"
        ) from exc
    finally:
        cleanup_failure = _release_lock_and_close(lock_fd, locked, control_fd)
        if cleanup_failure is not None:
            raise RuntimeActionBrokerError(
                "runtime control publication cleanup failed"
            ) from cleanup_failure


def _publish_control_locked(
    control_fd: int,
    path: Path,
    document: dict[str, Any],
    raw: bytes,
    config: RuntimeActionBrokerConfig,
    now_unix: int,
) -> None:
    if path == config.observation_path:
        current = _load_control(
            control_fd,
            path,
            config,
            "current runtime observation",
        )
        current_observation = _observation(
            current,
            _uint(
                current.get("observed_at_unix"),
                "current runtime observation time",
            ),
        )
        candidate = _observation(document, now_unix)
        policy = _load_control(
            control_fd,
            config.policy_path,
            config,
            "runtime action policy",
        )
        if candidate["sensor_digest"] != policy.get("sensor_digest"):
            raise RuntimeActionBrokerError("runtime observation publication is unbound")
        if candidate["sequence"] < current_observation["sequence"] or (
            candidate["sequence"] == current_observation["sequence"]
            and candidate != current_observation
        ):
            raise RuntimeActionBrokerError(
                "runtime observation publication rolled back"
            )
        if candidate["sequence"] > current_observation["sequence"]:
            _atomic_publish_at(
                control_fd,
                path.name,
                raw,
                expected_uid=config.expected_broker_uid,
            )
        return
    policy = _load_control(
        control_fd,
        config.policy_path,
        config,
        "runtime action policy",
    )
    state = _load_state(control_fd, config)
    current = _load_control(control_fd, path, config, "current runtime control")
    field, current_counter = _publication_counter(
        path,
        current,
        policy,
        config,
        minimum=1,
        now_unix=current.get("observed_at_unix"),
    )
    _field, candidate_counter = _publication_counter(
        path,
        document,
        policy,
        config,
        minimum=state[field],
        now_unix=now_unix,
    )
    if candidate_counter is None:
        raise RuntimeActionBrokerError(
            "runtime control publication is stale, unbound, or rolled back"
        )
    if current_counter is None:
        raise RuntimeActionBrokerError("current runtime control is unbound")
    if current_counter < state[field] and candidate_counter <= state[field]:
        raise RuntimeActionBrokerError(
            "runtime control recovery must advance beyond the persisted floor"
        )
    if candidate_counter < current_counter or (
        candidate_counter == current_counter and current != document
    ):
        raise RuntimeActionBrokerError("runtime control publication rolled back")
    if candidate_counter > current_counter:
        _atomic_publish_at(
            control_fd,
            path.name,
            raw,
            expected_uid=config.expected_broker_uid,
        )
    if candidate_counter > state[field]:
        _commit_state(control_fd, config, {**state, field: candidate_counter})


def _publication_counter(
    path: Path,
    document: dict[str, Any],
    policy: dict[str, Any],
    config: RuntimeActionBrokerConfig,
    *,
    minimum: int,
    now_unix: object,
) -> tuple[str, int | None]:
    try:
        if path == config.revocations_path:
            return "minimum_revocation_generation", (
                qualify_runtime_revocation_generation(
                    policy,
                    document,
                    now_unix=now_unix,
                    minimum_revocation_generation=minimum,
                )
            )
        return "minimum_mediator_health_epoch", qualify_runtime_health_epoch(
            policy,
            document,
            expected_runtime_digest=config.expected_runtime_digest,
            now_unix=now_unix,
            minimum_mediator_health_epoch=minimum,
        )
    except RuntimeActionStateError as exc:
        raise RuntimeActionBrokerError(
            f"runtime control publication is invalid: {exc}"
        ) from exc


def _evaluate_snapshot(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
    request: dict[str, Any],
    action_digests: dict[str, str],
    now_unix: int,
    *,
    minimum_state: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str, dict[str, Any], list[str]]:
    policy = _load_control(
        control_fd,
        config.policy_path,
        config,
        "runtime action policy",
    )
    state = _load_state(control_fd, config)
    stream_errors = []
    try:
        revocations = _load_control(
            control_fd,
            config.revocations_path,
            config,
            "runtime action revocations",
        )
    except RuntimeActionBrokerError as exc:
        revocations = None
        stream_errors.append(f"revocations: {exc}")
    try:
        health = _load_control(
            control_fd,
            config.health_path,
            config,
            "runtime mediator health",
        )
    except RuntimeActionBrokerError as exc:
        health = None
        stream_errors.append(f"health: {exc}")
    if minimum_state is not None and (
        state["minimum_revocation_generation"]
        < minimum_state["minimum_revocation_generation"]
        or state["minimum_mediator_health_epoch"]
        < minimum_state["minimum_mediator_health_epoch"]
    ):
        raise RuntimeActionBrokerError("runtime broker state rolled back")
    state = _advance_floors(
        control_fd,
        config,
        state,
        policy,
        revocations,
        health,
        now_unix,
        stream_errors=stream_errors,
    )
    observation = _observation(
        _load_control(
            control_fd,
            config.observation_path,
            config,
            "runtime action observation",
        ),
        now_unix,
    )
    measured = observation["measured_action"]
    try:
        decision = evaluate_runtime_action(
            request,
            policy,
            now_unix=now_unix,
            active=observation["active"],
            measured_action=measured,
            revocations=revocations,
            minimum_revocation_generation=state["minimum_revocation_generation"],
            mediator_health=health,
            minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"],
        )
    except RuntimeActionStateError as exc:
        raise RuntimeActionBrokerError(
            f"runtime action trusted state is invalid: {exc}"
        ) from exc

    reasons = []
    if request.get("runtime_digest") != config.expected_runtime_digest:
        reasons.append("BROKER_RUNTIME_PIN_MISMATCH")
    if observation["sensor_digest"] != policy.get("sensor_digest"):
        reasons.append("BROKER_SENSOR_PIN_MISMATCH")
    if not isinstance(measured, dict) or any(
        measured.get(field) != action_digests[field] for field in _ACTION_DIGEST_FIELDS
    ):
        reasons.append("BROKER_EFFECT_MEASUREMENT_MISMATCH")
    if any(request.get(field) != value for field, value in action_digests.items()):
        reasons.append("BROKER_EFFECT_BINDING_MISMATCH")
    return state, canonical_digest(observation), decision, sorted(reasons)


def _advance_floors(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
    state: dict[str, Any],
    policy: dict[str, Any],
    revocations: dict[str, Any] | None,
    health: dict[str, Any] | None,
    now_unix: int,
    *,
    stream_errors: list[str],
) -> dict[str, Any]:
    next_state = {**state, "consumed": _live_consumed(state["consumed"], now_unix)}
    errors = list(stream_errors)
    if revocations is not None:
        try:
            generation = qualify_runtime_revocation_generation(
                policy,
                revocations,
                now_unix=now_unix,
                minimum_revocation_generation=state["minimum_revocation_generation"],
            )
            if generation is not None:
                next_state["minimum_revocation_generation"] = generation
        except RuntimeActionStateError as exc:
            errors.append(f"revocations: {exc}")
    if health is not None:
        try:
            epoch = qualify_runtime_health_epoch(
                policy,
                health,
                expected_runtime_digest=config.expected_runtime_digest,
                now_unix=now_unix,
                minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"],
            )
            if epoch is not None:
                next_state["minimum_mediator_health_epoch"] = epoch
        except RuntimeActionStateError as exc:
            errors.append(f"health: {exc}")
    if next_state != state:
        _commit_state(control_fd, config, next_state)
    if errors:
        raise RuntimeActionBrokerError(
            "runtime trusted control stream is invalid: " + "; ".join(errors)
        )
    return next_state


def _clock_value(clock: Callable[[], int]) -> int:
    try:
        return _uint(clock(), "trusted broker time")
    except RuntimeActionBrokerError:
        raise
    except Exception as exc:
        raise RuntimeActionBrokerError("trusted broker clock failed") from exc


def _handle_connection(
    connection: socket.socket,
    config: RuntimeActionBrokerConfig,
    *,
    timeout_seconds: float,
) -> None:
    pid, uid, gid = _peer_credentials(connection)
    if uid != config.expected_peer_uid or gid != config.expected_peer_gid:
        raise RuntimeActionBrokerError(
            f"runtime broker peer {pid} has an unauthorized identity"
        )
    deadline = time.monotonic() + timeout_seconds
    submission = _read_frame(connection, deadline)
    if config.expected_runtime_uid is None:
        result = mediate_runtime_create(
            submission,
            config,
            deadline_monotonic=deadline,
        )
    else:
        result = mediate_observed_runtime_create(
            submission,
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


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeActionBrokerError("Linux SO_PEERCRED is required")
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            _PEER_CREDENTIALS.size,
        )
    except OSError as exc:
        raise RuntimeActionBrokerError(
            "cannot authenticate runtime broker peer"
        ) from exc
    if len(raw) != _PEER_CREDENTIALS.size:
        raise RuntimeActionBrokerError("runtime broker peer credentials are truncated")
    return _PEER_CREDENTIALS.unpack(raw)


def _read_frame(connection: socket.socket, deadline: float) -> dict[str, Any]:
    header = _receive_exact(connection, _FRAME_HEADER.size, deadline)
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > _MAX_FRAME_BYTES:
        raise RuntimeActionBrokerError("runtime broker request frame length is invalid")
    raw = _receive_exact(connection, length, deadline)
    _require_eof(connection, deadline)
    return _parse_canonical_document(raw, "runtime broker request frame")


def _send_frame(connection: socket.socket, raw: bytes, deadline: float) -> None:
    if not raw or len(raw) > _MAX_FRAME_BYTES:
        raise RuntimeActionBrokerError(
            "runtime broker response frame length is invalid"
        )
    remaining = memoryview(_FRAME_HEADER.pack(len(raw)) + raw)
    while remaining:
        _set_deadline(connection, deadline)
        try:
            written = connection.send(remaining)
        except (OSError, TimeoutError) as exc:
            raise RuntimeActionBrokerError("runtime broker response failed") from exc
        if written <= 0:
            raise RuntimeActionBrokerError("runtime broker response made no progress")
        remaining = remaining[written:]


def _receive_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    received = bytearray()
    while len(received) < size:
        _set_deadline(connection, deadline)
        try:
            chunk = connection.recv(size - len(received))
        except (OSError, TimeoutError) as exc:
            raise RuntimeActionBrokerError("runtime broker request failed") from exc
        if not chunk:
            raise RuntimeActionBrokerError("runtime broker request ended early")
        received.extend(chunk)
    return bytes(received)


def _require_eof(connection: socket.socket, deadline: float) -> None:
    _set_deadline(connection, deadline)
    try:
        trailing = connection.recv(1)
    except (OSError, TimeoutError) as exc:
        raise RuntimeActionBrokerError(
            "runtime broker request did not terminate"
        ) from exc
    if trailing:
        raise RuntimeActionBrokerError("runtime broker request has trailing bytes")


def _set_deadline(connection: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeActionBrokerError("runtime broker request timed out")
    connection.settimeout(remaining)


def _request_effect(envelope: object) -> tuple[dict[str, Any], str, bytes]:
    document = _exact(envelope, _ENVELOPE_FIELDS, "runtime broker request")
    if document["schema"] != "aragorn/runtime-action-broker-request/v1":
        raise RuntimeActionBrokerError("runtime broker request schema is unsupported")
    request = document["request"]
    if not isinstance(request, dict):
        raise RuntimeActionBrokerError("runtime action request must be an object")
    effect = _exact(document["effect"], _EFFECT_FIELDS, "runtime create effect")
    if (
        effect["schema"] != "aragorn/runtime-create-file/v1"
        or effect["operation"] != "create"
    ):
        raise RuntimeActionBrokerError("runtime create effect is unsupported")
    target_name = effect["target_name"]
    if not isinstance(target_name, str) or _TARGET_NAME.fullmatch(target_name) is None:
        raise RuntimeActionBrokerError("runtime create target name is invalid")
    encoded = effect["payload_base64"]
    if (
        not isinstance(encoded, str)
        or len(encoded) > ((_MAX_PAYLOAD_BYTES + 2) // 3) * 4
    ):
        raise RuntimeActionBrokerError("runtime create payload is invalid")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeActionBrokerError("runtime create payload is invalid") from exc
    if (
        len(payload) > _MAX_PAYLOAD_BYTES
        or base64.b64encode(payload).decode("ascii") != encoded
    ):
        raise RuntimeActionBrokerError("runtime create payload is not canonical")
    return request, target_name, payload


def _observed_submission(value: object) -> dict[str, Any]:
    submission = _exact(
        value,
        _OBSERVED_SUBMISSION_FIELDS,
        "observed runtime submission",
    )
    if (
        submission["schema"]
        != "aragorn/runtime-observed-create-submission/v1"
        or submission["authority"]
        != "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY"
    ):
        raise RuntimeActionBrokerError("observed runtime submission identity is invalid")
    _require_digest(submission["sensor_digest"], "observed sensor digest")
    _require_digest(submission["envelope_digest"], "observed envelope digest")
    _require_digest(submission["request_digest"], "observed request digest")
    peer = _exact(
        submission["runtime_peer"],
        _RUNTIME_PEER_FIELDS,
        "observed runtime peer",
    )
    _positive_uint(peer["pid"], "observed runtime pid")
    _uint(peer["uid"], "observed runtime uid")
    _uint(peer["gid"], "observed runtime gid")
    measured = _exact(
        submission["measured_action"],
        _MEASURED_ACTION_FIELDS,
        "observed measured action",
    )
    if measured["schema"] != "aragorn/measured-runtime-action/v1":
        raise RuntimeActionBrokerError("observed measured action identity is invalid")
    request, _target_name, _payload = _request_effect(submission["envelope"])
    try:
        _validate_runtime_action_request(request)
    except _InvalidRequest as exc:
        raise RuntimeActionBrokerError("observed runtime request is invalid") from exc
    if (
        submission["envelope_digest"] != canonical_digest(submission["envelope"])
        or submission["request_digest"] != canonical_digest(request)
    ):
        raise RuntimeActionBrokerError("observed runtime submission digest changed")
    return submission


def _publish_observed_state_locked(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
    request: dict[str, Any],
    action_digests: dict[str, str],
    submission: dict[str, Any],
    now_unix: int,
) -> None:
    if config.expected_runtime_uid is None or config.expected_runtime_gid is None:
        raise RuntimeActionBrokerError("observed runtime identity is not configured")
    peer = submission["runtime_peer"]
    if (
        peer["uid"] != config.expected_runtime_uid
        or peer["gid"] != config.expected_runtime_gid
        or request["runtime_digest"] != config.expected_runtime_digest
    ):
        raise RuntimeActionBrokerError("observed runtime identity is unbound")
    attribution = {
        field: request[field]
        for field in (
            "runtime_digest",
            "session_id",
            "run_id",
            "tool_call_id",
            "active_skill_digest",
        )
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **attribution,
        **action_digests,
    }
    if submission["measured_action"] != measured or any(
        request.get(field) != digest for field, digest in action_digests.items()
    ):
        raise RuntimeActionBrokerError("observed runtime action measurement changed")

    policy = _load_control(
        control_fd,
        config.policy_path,
        config,
        "runtime action policy",
    )
    sensor_digest = _require_digest(
        policy.get("sensor_digest"),
        "runtime action policy sensor",
    )
    if submission["sensor_digest"] != sensor_digest:
        raise RuntimeActionBrokerError("observed runtime sensor is unbound")
    state = _load_state(control_fd, config)
    current_health = _load_control(
        control_fd,
        config.health_path,
        config,
        "current runtime mediator health",
    )
    health_field, current_epoch = _publication_counter(
        config.health_path,
        current_health,
        policy,
        config,
        minimum=1,
        now_unix=current_health.get("observed_at_unix"),
    )
    if current_epoch is None:
        raise RuntimeActionBrokerError("current runtime mediator health is unbound")
    health = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": config.expected_runtime_digest,
        "sensor_digest": sensor_digest,
        "epoch": max(current_epoch, state[health_field]) + 1,
        "status": current_health["status"],
        "observed_at_unix": now_unix,
        "expires_at_unix": now_unix + _MAX_OBSERVATION_LIFETIME_SECONDS,
    }
    _publish_control_locked(
        control_fd,
        config.health_path,
        health,
        canonical_json(health),
        config,
        now_unix,
    )

    current_observation = _load_control(
        control_fd,
        config.observation_path,
        config,
        "current runtime observation",
    )
    current_observation = _observation(
        current_observation,
        _uint(
            current_observation.get("observed_at_unix"),
            "current runtime observation time",
        ),
    )
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": current_observation["sequence"] + 1,
        "sensor_digest": sensor_digest,
        "observed_at_unix": now_unix,
        "expires_at_unix": now_unix + _MAX_OBSERVATION_LIFETIME_SECONDS,
        "active": {
            "schema": "aragorn/runtime-active-context/v1",
            **attribution,
        },
        "measured_action": measured,
    }
    _publish_control_locked(
        control_fd,
        config.observation_path,
        observation,
        canonical_json(observation),
        config,
        now_unix,
    )


def _observation(document: dict[str, Any], now_unix: int) -> dict[str, Any]:
    value = _exact(document, _OBSERVATION_FIELDS, "runtime action observation")
    if value["schema"] != "aragorn/runtime-action-observation/v1":
        raise RuntimeActionBrokerError(
            "runtime action observation schema is unsupported"
        )
    if value["authority"] != "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY":
        raise RuntimeActionBrokerError(
            "runtime action observation authority is invalid"
        )
    _positive_uint(value["sequence"], "runtime observation sequence")
    _require_digest(value["sensor_digest"], "runtime observation sensor")
    observed = _uint(value["observed_at_unix"], "runtime observation time")
    expires = _uint(value["expires_at_unix"], "runtime observation expiry")
    if (
        observed > now_unix
        or now_unix >= expires
        or expires <= observed
        or expires - observed > _MAX_OBSERVATION_LIFETIME_SECONDS
    ):
        raise RuntimeActionBrokerError("runtime action observation is stale")
    return value


def _state(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema") == "aragorn/runtime-action-broker-state/v1":
        legacy = _exact(document, _STATE_V1_FIELDS, "runtime broker state")
        value = {
            **legacy,
            "schema": "aragorn/runtime-action-broker-state/v2",
            "effect_journal": None,
        }
    else:
        value = _exact(document, _STATE_FIELDS, "runtime broker state")
    if value["schema"] != "aragorn/runtime-action-broker-state/v2":
        raise RuntimeActionBrokerError("runtime broker state schema is unsupported")
    if value["authority"] != "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY":
        raise RuntimeActionBrokerError("runtime broker state authority is invalid")
    _positive_uint(
        value["minimum_revocation_generation"],
        "minimum revocation generation",
    )
    _positive_uint(
        value["minimum_mediator_health_epoch"],
        "minimum mediator health epoch",
    )
    consumed = value["consumed"]
    if not isinstance(consumed, list) or len(consumed) > _MAX_CONSUMED:
        raise RuntimeActionBrokerError("runtime broker consumed state is invalid")
    normalized = []
    for item in consumed:
        entry = _exact(item, _CONSUMED_FIELDS, "runtime broker replay entry")
        _require_digest(entry["request_digest"], "consumed request digest")
        _require_digest(
            entry["observation_digest"],
            "consumed observation digest",
        )
        _uint(entry["expires_at_unix"], "consumed replay expiry")
        normalized.append(entry)
    if (
        normalized != sorted(normalized, key=canonical_json)
        or len({item["request_digest"] for item in normalized}) != len(normalized)
        or len({item["observation_digest"] for item in normalized}) != len(normalized)
    ):
        raise RuntimeActionBrokerError(
            "runtime broker replay entries must be sorted and unique"
        )
    journal = value["effect_journal"]
    if journal is not None:
        transaction = _effect_journal(journal)
        if not any(
            item["request_digest"] == transaction["request_digest"]
            and item["observation_digest"] == transaction["observation_digest"]
            for item in normalized
        ):
            raise RuntimeActionBrokerError(
                "runtime effect journal has no durable replay claim"
            )
    return value


def _effect_journal(value: object) -> dict[str, Any]:
    transaction = _exact(value, _TRANSACTION_FIELDS, "runtime effect journal")
    if (
        transaction["schema"] != "aragorn/runtime-effect-journal/v1"
        or transaction["authority"]
        != "BROKER_RECOVERY_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
        or transaction["status"] not in {"PENDING", "APPLIED"}
    ):
        raise RuntimeActionBrokerError("runtime effect journal identity is invalid")
    for field in (
        "request_digest",
        "observation_digest",
        *_ACTION_DIGEST_FIELDS,
    ):
        _require_digest(transaction[field], f"journal {field}")
    for field in (
        "payload_size",
        "protected_root_device",
        "protected_root_inode",
        "staging_device",
        "staging_inode",
    ):
        _uint(transaction[field], f"journal {field}")
    if (
        transaction["payload_size"] > _MAX_PAYLOAD_BYTES
        or not isinstance(transaction["target_name"], str)
        or _TARGET_NAME.fullmatch(transaction["target_name"]) is None
        or not isinstance(transaction["staging_name"], str)
        or _STAGING_NAME.fullmatch(transaction["staging_name"]) is None
    ):
        raise RuntimeActionBrokerError("runtime effect journal path is invalid")
    return transaction


def _load_control(
    control_fd: int,
    path: Path,
    config: RuntimeActionBrokerConfig,
    label: str,
) -> dict[str, Any]:
    if path.parent != config.control_root:
        raise RuntimeActionBrokerError(f"{label} is outside the locked control root")
    try:
        raw = _read_owned_bytes_at(
            control_fd,
            path.name,
            max_bytes=_MAX_CONTROL_BYTES,
            expected_uid=config.expected_broker_uid,
            exact_mode=0o400,
            label=label,
        )
        return _parse_canonical_document(raw, label)
    except (OSError, _ProtectedFileError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(f"cannot load {label}: {exc}") from exc


def _load_state(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
) -> dict[str, Any]:
    stored = _load_control(
        control_fd,
        config.state_path,
        config,
        "runtime broker state",
    )
    state = _state(stored)
    if state != stored:
        _commit_state(control_fd, config, state)
    return state


def _commit_state(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
    state: dict[str, Any],
) -> None:
    state = _state(state)
    try:
        _atomic_publish_at(
            control_fd,
            config.state_path.name,
            canonical_json(state),
            expected_uid=config.expected_broker_uid,
        )
    except (OSError, _ProtectedFileError, WorkerProtocolError) as exc:
        raise RuntimeActionBrokerError(
            f"cannot persist runtime broker state: {exc}"
        ) from exc


def _read_owned_bytes_at(
    parent_fd: int,
    name: str,
    *,
    max_bytes: int,
    expected_uid: int,
    exact_mode: int,
    label: str,
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != exact_mode
            or before.st_size > max_bytes
        ):
            raise _ProtectedFileError(f"{label} metadata is unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, min(8192, max_bytes + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise _ProtectedFileError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _file_identity(before) != _file_identity(after) or len(raw) != after.st_size:
        raise _ProtectedFileError(f"{label} changed while read")
    return bytes(raw)


def _atomic_publish_at(
    parent_fd: int,
    name: str,
    raw: bytes,
    *,
    expected_uid: int,
) -> None:
    if len(raw) > _MAX_CONTROL_BYTES:
        raise _ProtectedFileError("runtime broker state exceeds its byte limit")
    temporary_name: str | None = None
    descriptor = -1
    try:
        temporary_name, descriptor = create_exclusive_file_at(
            parent_fd,
            prefix=f".{name}.",
            mode=0o600,
        )
        write_all(descriptor, raw)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            raise _ProtectedFileError("runtime broker state staging is unsafe")
        os.rename(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
        os.fsync(parent_fd)
        if (
            _read_owned_bytes_at(
                parent_fd,
                name,
                max_bytes=_MAX_CONTROL_BYTES,
                expected_uid=expected_uid,
                exact_mode=0o400,
                label="runtime broker retained state",
            )
            != raw
        ):
            raise _ProtectedFileError("runtime broker retained state changed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def _parse_canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        encoded = canonical_json(document)
    except RuntimeActionBrokerError:
        raise
    except (
        UnicodeDecodeError,
        ValueError,
        RecursionError,
        WorkerProtocolError,
    ) as exc:
        raise RuntimeActionBrokerError(f"{label} is invalid: {exc}") from exc
    if not isinstance(document, dict) or encoded != raw:
        raise RuntimeActionBrokerError(f"{label} must be canonical JSON")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document = {}
    for key, value in pairs:
        if key in document:
            raise RuntimeActionBrokerError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise RuntimeActionBrokerError(f"non-finite JSON number: {value}")


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


def _action_digests(
    protected_fd: int,
    target_name: str,
    payload: bytes,
) -> dict[str, str]:
    return {
        **_operation_path_digests(protected_fd, target_name),
        "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def _operation_path_digests(
    protected_fd: int,
    target_name: str,
) -> dict[str, str]:
    root = os.fstat(protected_fd)
    return {
        "operation_digest": canonical_digest(
            {
                "schema": "aragorn/runtime-file-operation/v1",
                "operation": "create",
            }
        ),
        "path_digest": canonical_digest(
            {
                "schema": "aragorn/runtime-protected-path/v1",
                "root_device": root.st_dev,
                "root_inode": root.st_ino,
                "target_name": target_name,
            }
        ),
    }


def _effect_file_at(
    parent_fd: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_size: int,
    expected_digest: str,
    allowed_links: frozenset[int],
    label: str,
) -> os.stat_result | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeActionBrokerError(f"cannot inspect {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or before.st_nlink not in allowed_links
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size != expected_size
        ):
            raise RuntimeActionBrokerError(f"{label} metadata is unsafe")
        raw = bytearray()
        while len(raw) <= expected_size:
            chunk = os.read(descriptor, min(8192, expected_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _file_identity(before) != _file_identity(after)
        or len(raw) != expected_size
        or "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest
    ):
        raise RuntimeActionBrokerError(f"{label} content is unsafe")
    return after


def _unlink_effect_file_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    label: str,
) -> None:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if _file_identity(current) != _file_identity(expected):
        raise RuntimeActionBrokerError(f"{label} changed before cleanup")
    os.unlink(name, dir_fd=parent_fd)


def _clean_staging_orphans(
    staging_fd: int,
    config: RuntimeActionBrokerConfig,
    *,
    force_sync: bool = False,
) -> None:
    removed = False
    for name in os.listdir(staging_fd):
        try:
            before = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeActionBrokerError(
                f"cannot inspect runtime staging orphan: {exc}"
            ) from exc
        if (
            _STAGING_NAME.fullmatch(name) is None
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != config.expected_broker_uid
            or before.st_gid != _effect_gid(config)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or before.st_size > _MAX_PAYLOAD_BYTES
        ):
            raise RuntimeActionBrokerError("runtime staging orphan is unsafe")
        _unlink_effect_file_at(
            staging_fd,
            name,
            before,
            "runtime staging orphan",
        )
        removed = True
    if removed or force_sync:
        os.fsync(staging_fd)


def _recover_effect_journal(
    control_fd: int,
    protected_fd: int,
    staging_fd: int,
    config: RuntimeActionBrokerConfig,
) -> None:
    state = _load_state(control_fd, config)
    journal = state["effect_journal"]
    if journal is None:
        _clean_staging_orphans(staging_fd, config)
        return
    transaction = _effect_journal(journal)
    root = os.fstat(protected_fd)
    expected_action = _operation_path_digests(
        protected_fd,
        transaction["target_name"],
    )
    if (
        transaction["protected_root_device"] != root.st_dev
        or transaction["protected_root_inode"] != root.st_ino
        or any(
            transaction[field] != expected_action[field]
            for field in ("operation_digest", "path_digest")
        )
    ):
        raise RuntimeActionBrokerError("runtime effect journal root binding changed")
    file_options = {
        "expected_uid": config.expected_broker_uid,
        "expected_gid": _effect_gid(config),
        "expected_size": transaction["payload_size"],
        "expected_digest": transaction["payload_digest"],
    }
    staged = _effect_file_at(
        staging_fd,
        transaction["staging_name"],
        allowed_links=frozenset({1, 2}),
        label="runtime staged effect",
        **file_options,
    )
    target = _effect_file_at(
        protected_fd,
        transaction["target_name"],
        allowed_links=frozenset({1, 2}),
        label="runtime protected effect",
        **file_options,
    )

    if transaction["status"] == "PENDING" and target is None:
        if (
            staged is None
            or staged.st_nlink != 1
            or (staged.st_dev, staged.st_ino)
            != (transaction["staging_device"], transaction["staging_inode"])
        ):
            raise RuntimeActionBrokerError(
                "pending runtime effect lost its staged payload"
            )
        _commit_state(control_fd, config, {**state, "effect_journal": None})
        _unlink_effect_file_at(
            staging_fd,
            transaction["staging_name"],
            staged,
            "runtime staged effect",
        )
        _clean_staging_orphans(staging_fd, config, force_sync=True)
        return

    if target is None:
        raise RuntimeActionBrokerError("applied runtime effect target is absent")
    target_identity = target.st_dev, target.st_ino
    expected_identity = (
        transaction["staging_device"],
        transaction["staging_inode"],
    )
    if target_identity != expected_identity:
        raise RuntimeActionBrokerError("runtime effect target identity changed")
    if transaction["status"] == "PENDING":
        if (
            staged is None
            or staged.st_nlink != 2
            or target.st_nlink != 2
            or (staged.st_dev, staged.st_ino) != target_identity
        ):
            raise RuntimeActionBrokerError(
                "pending runtime effect links are inconsistent"
            )
        os.fsync(protected_fd)
        state = {
            **state,
            "effect_journal": {**transaction, "status": "APPLIED"},
        }
        _commit_state(control_fd, config, state)
    elif staged is not None and (
        staged.st_nlink != 2
        or target.st_nlink != 2
        or (staged.st_dev, staged.st_ino) != target_identity
    ):
        raise RuntimeActionBrokerError("applied runtime effect links are inconsistent")

    if staged is not None:
        _unlink_effect_file_at(
            staging_fd,
            transaction["staging_name"],
            staged,
            "runtime staged effect",
        )
    _clean_staging_orphans(staging_fd, config, force_sync=True)
    confirmed = _effect_file_at(
        protected_fd,
        transaction["target_name"],
        allowed_links=frozenset({1}),
        label="runtime protected effect",
        **file_options,
    )
    if confirmed is None or (confirmed.st_dev, confirmed.st_ino) != expected_identity:
        raise RuntimeActionBrokerError("runtime effect target could not be confirmed")
    _commit_state(control_fd, config, {**state, "effect_journal": None})


def _recover_before_listen(
    config: RuntimeActionBrokerConfig,
    timeout_seconds: float,
) -> None:
    control_fd = protected_fd = staging_fd = lock_fd = -1
    locked = False
    try:
        control_fd, protected_fd, staging_fd = _open_broker_roots(config)
        lock_fd = _open_lock_file(control_fd, config)
        _acquire_lock(lock_fd, time.monotonic() + timeout_seconds)
        locked = True
        _recover_effect_journal(control_fd, protected_fd, staging_fd, config)
    finally:
        cleanup_failure = _release_lock_and_close(
            lock_fd,
            locked,
            staging_fd,
            protected_fd,
            control_fd,
        )
        if cleanup_failure is not None:
            raise RuntimeActionBrokerError(
                "runtime broker startup recovery cleanup failed"
            ) from cleanup_failure


def _atomic_create(
    staging_fd: int,
    protected_fd: int,
    target_name: str,
    payload: bytes,
    *,
    authorize_link: Callable[[], bool] = lambda: True,
    record_pending: Callable[[str, os.stat_result], None] | None = None,
    record_applied: Callable[[str, os.stat_result], None] | None = None,
) -> bool:
    if (record_pending is None) != (record_applied is None):
        raise RuntimeActionBrokerError("runtime create journal callbacks are invalid")
    temporary_name: str | None = None
    descriptor = -1
    linked = False
    link_attempted = False
    preserve_stage = False
    failure: BaseException | None = None
    try:
        temporary_name, descriptor = create_exclusive_file_at(
            staging_fd,
            prefix=".aragorn-runtime-",
            mode=0o600,
        )
        write_all(descriptor, payload)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        named = os.stat(temporary_name, dir_fd=staging_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_uid != os.geteuid()
            or stat.S_IMODE(staged.st_mode) != 0o400
            or staged.st_size != len(payload)
            or staged.st_nlink != 1
            or (staged.st_dev, staged.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise RuntimeActionBrokerError("runtime create staging metadata is unsafe")
        os.fsync(staging_fd)
        authorized = authorize_link()
        if not isinstance(authorized, bool):
            raise RuntimeActionBrokerError("runtime create authorization is invalid")
        if authorized:
            if record_pending is not None:
                preserve_stage = True
                record_pending(temporary_name, staged)
            link_attempted = True
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=staging_fd,
                dst_dir_fd=protected_fd,
                follow_symlinks=False,
            )
            linked = True
            os.fsync(protected_fd)
            target = os.stat(target_name, dir_fd=protected_fd, follow_symlinks=False)
            if (
                (target.st_dev, target.st_ino) != (staged.st_dev, staged.st_ino)
                or target.st_nlink != 2
            ):
                raise RuntimeActionBrokerError(
                    "runtime create target identity is indeterminate"
                )
            if record_applied is not None:
                record_applied(temporary_name, staged)
    except BaseException as exc:  # noqa: BLE001 - clean up before process exit
        failure = exc
    cleanup_failure: BaseException | None = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError as exc:
            cleanup_failure = exc
    if temporary_name is not None and not preserve_stage:
        try:
            os.unlink(temporary_name, dir_fd=staging_fd)
            os.fsync(staging_fd)
        except OSError as exc:
            cleanup_failure = cleanup_failure or exc
    if failure is not None and not isinstance(failure, Exception):
        raise failure
    if (linked or link_attempted) and (
        failure is not None or cleanup_failure is not None
    ):
        raise RuntimeActionEffectIndeterminate(
            "runtime create was linked but completion is indeterminate"
        ) from (failure or cleanup_failure)
    if failure is not None:
        raise failure
    if cleanup_failure is not None:
        raise cleanup_failure
    return linked


def _result(
    *,
    request_digest: str,
    observation_digest: str,
    target_name: str,
    verdict: str,
    reason_codes: list[str],
    effect_status: str,
    decision: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": request_digest,
        "observation_digest": observation_digest,
        "target_name": target_name,
        "verdict": verdict,
        "reason_codes": reason_codes,
        "effect_status": effect_status,
        "decision": decision,
    }


def _effect_gid(config: RuntimeActionBrokerConfig) -> int:
    return (
        config.expected_peer_gid
        if config.expected_runtime_gid is None
        else config.expected_runtime_gid
    )


def _validate_config(config: RuntimeActionBrokerConfig) -> None:
    if not isinstance(config, RuntimeActionBrokerConfig):
        raise RuntimeActionBrokerError("runtime broker configuration is invalid")
    if os.name != "posix" or os.geteuid() != config.expected_broker_uid:
        raise RuntimeActionBrokerError("runtime broker identity is invalid")
    for value, label in (
        (config.expected_broker_uid, "broker uid"),
        (config.expected_peer_uid, "peer uid"),
        (config.expected_peer_gid, "peer gid"),
    ):
        _uint(value, label)
    if config.expected_peer_uid == config.expected_broker_uid:
        raise RuntimeActionBrokerError("runtime and broker UIDs must be distinct")
    if (config.expected_runtime_uid is None) != (
        config.expected_runtime_gid is None
    ):
        raise RuntimeActionBrokerError("observed runtime identity is incomplete")
    if config.expected_runtime_uid is not None:
        _uint(config.expected_runtime_uid, "runtime uid")
        _uint(config.expected_runtime_gid, "runtime gid")
        if (
            config.expected_runtime_uid
            in {config.expected_broker_uid, config.expected_peer_uid}
            or config.expected_runtime_gid == config.expected_peer_gid
        ):
            raise RuntimeActionBrokerError(
                "runtime, sensor, and broker identities must be distinct"
            )
    _require_digest(config.expected_runtime_digest, "expected runtime digest")
    paths = (
        config.socket_path,
        config.instance_lock_path,
        config.lock_path,
        config.control_root,
        config.protected_root,
        config.staging_root,
        config.policy_path,
        config.revocations_path,
        config.health_path,
        config.observation_path,
        config.state_path,
    )
    if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
        raise RuntimeActionBrokerError(
            "runtime broker paths must be absolute Path values"
        )
    control_files = (
        config.socket_path,
        config.instance_lock_path,
        config.lock_path,
        config.policy_path,
        config.revocations_path,
        config.health_path,
        config.observation_path,
        config.state_path,
    )
    if any(path.parent != config.control_root for path in control_files) or len(
        {path.name for path in control_files}
    ) != len(control_files):
        raise RuntimeActionBrokerError("runtime broker control paths are invalid")
    if len({config.control_root, config.protected_root, config.staging_root}) != 3:
        raise RuntimeActionBrokerError("runtime broker roots must be distinct")
    required = {os.link, os.open, os.stat, os.unlink}
    if (
        not required.issubset(os.supports_dir_fd)
        or os.link not in os.supports_follow_symlinks
    ):
        raise RuntimeActionBrokerError(
            "descriptor-relative runtime creation is unsupported"
        )


def _open_protected_directory(path: Path, expected_uid: int, label: str) -> int:
    descriptor = -1
    try:
        resolved = path.resolve(strict=True)
        if path != resolved:
            raise _ProtectedFileError(f"{label} path is not canonical")
        _require_protected_ancestry(path.parent, expected_uid)
        before = os.lstat(path)
        descriptor = os.open(path, _DIRECTORY_FLAGS)
        after = require_owned_directory(
            descriptor,
            expected_uid=expected_uid,
            require_owner_write=True,
            label=label,
        )
    except (OSError, RuntimeError, _ProtectedFileError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise RuntimeActionBrokerError(f"cannot open {label}: {exc}") from exc
    if _directory_identity(before) != _directory_identity(after):
        os.close(descriptor)
        raise RuntimeActionBrokerError(f"{label} identity changed")
    return descriptor


def _open_broker_roots(config: RuntimeActionBrokerConfig) -> tuple[int, int, int]:
    descriptors: list[int] = []
    try:
        for path, label in (
            (config.control_root, "runtime broker control root"),
            (config.protected_root, "runtime broker protected root"),
            (config.staging_root, "runtime broker staging root"),
        ):
            descriptors.append(
                _open_protected_directory(
                    path,
                    config.expected_broker_uid,
                    label,
                )
            )
        control_fd, protected_fd, staging_fd = descriptors
        if stat.S_IMODE(os.fstat(staging_fd).st_mode) & 0o077:
            raise RuntimeActionBrokerError(
                "runtime broker staging root must be owner-only"
            )
        roots = {
            (metadata.st_dev, metadata.st_ino)
            for metadata in map(os.fstat, descriptors)
        }
        if len(roots) != 3:
            raise RuntimeActionBrokerError("runtime broker root identities overlap")
        if os.fstat(protected_fd).st_dev != os.fstat(staging_fd).st_dev:
            raise RuntimeActionBrokerError(
                "runtime broker staging and protected roots differ by filesystem"
            )
        return control_fd, protected_fd, staging_fd
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _require_protected_ancestry(path: Path, expected_uid: int) -> None:
    current = path
    while True:
        metadata = os.lstat(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise _ProtectedFileError("runtime broker protected ancestry is unsafe")
        if current == Path(current.anchor):
            return
        current = current.parent


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_lock_file(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
    *,
    path: Path | None = None,
) -> int:
    lock_path = config.lock_path if path is None else path
    descriptor = os.open(
        lock_path.name,
        os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=control_fd,
    )
    try:
        opened = os.fstat(descriptor)
        named = os.stat(
            lock_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != config.expected_broker_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or _file_identity(opened) != _file_identity(named)
        ):
            raise RuntimeActionBrokerError("runtime broker lock file is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _acquire_lock(descriptor: int, deadline: float) -> None:
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeActionBrokerError("runtime broker lock timed out")
            time.sleep(min(0.01, remaining))


def _release_lock_and_close(
    lock_fd: int,
    locked: bool,
    *descriptors: int,
) -> OSError | None:
    failure = None
    if locked:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError as exc:
            failure = exc
    for descriptor in (lock_fd, *descriptors):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                failure = failure or exc
    return failure


def _prepare_socket_path(
    control_fd: int,
    config: RuntimeActionBrokerConfig,
) -> None:
    try:
        stale = os.stat(
            config.socket_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(stale.st_mode)
        or stale.st_uid != config.expected_broker_uid
        or stale.st_nlink != 1
    ):
        raise RuntimeActionBrokerError("runtime broker socket path is occupied")
    current = os.stat(
        config.socket_path.name,
        dir_fd=control_fd,
        follow_symlinks=False,
    )
    if (stale.st_dev, stale.st_ino) != (current.st_dev, current.st_ino):
        raise RuntimeActionBrokerError("runtime broker socket path changed")
    os.unlink(config.socket_path.name, dir_fd=control_fd)
    os.fsync(control_fd)


def _live_consumed(
    consumed: list[dict[str, Any]], now_unix: int
) -> list[dict[str, Any]]:
    return [dict(item) for item in consumed if now_unix < item["expires_at_unix"]]


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeActionBrokerError(f"{label} fields are invalid")
    return value


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise RuntimeActionBrokerError(f"{label} is not a canonical SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise RuntimeActionBrokerError(
            f"{label} is not a canonical SHA-256 digest"
        ) from exc
    if value[7:] != value[7:].lower():
        raise RuntimeActionBrokerError(f"{label} is not a canonical SHA-256 digest")
    return value


def _uint(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeActionBrokerError(f"{label} is invalid")
    return value


def _positive_uint(value: object, label: str) -> int:
    integer = _uint(value, label)
    if integer == 0:
        raise RuntimeActionBrokerError(f"{label} is invalid")
    return integer
