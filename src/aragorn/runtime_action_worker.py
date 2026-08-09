"""Authenticated gateway-to-worker relay for one bounded runtime action."""

from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import re
import socket
import stat
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_digest, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _action_digests,
    _peer_credentials,
    _read_frame,
    _require_digest,
    _require_protected_ancestry,
    _send_frame,
    _uint,
)
from .runtime_action_service import (
    RuntimeActionServiceError,
    _credential_path,
    _read_credential_bytes,
)

_WORKER_PRINCIPAL = "aragorn-runtime"
_GATEWAY_PRINCIPAL = "aragorn-agent-gateway"
_SENSOR_PRINCIPAL = "aragorn-sensor"
_BROKER_PRINCIPAL = "aragorn-broker"
_BINDING_SCHEMA = "aragorn/runtime-action-worker-binding/v1"
_REQUEST_SCHEMA = "aragorn/runtime-action-worker-request/v1"
_REQUEST_AUTHORITY = "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
_RESULT_SCHEMA = "aragorn/runtime-action-worker-result/v1"
_RESULT_AUTHORITY = "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
_BROKER_RESULT_SCHEMA = "aragorn/runtime-action-broker-result/v1"
_BROKER_RESULT_AUTHORITY = "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
_DECISION_SCHEMA = "aragorn/runtime-action-decision/v1"
_DECISION_AUTHORITY = (
    "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
)
_MAX_PAYLOAD_BYTES = 32 * 1024
_MAX_REQUEST_LIFETIME_SECONDS = 5
_TARGET_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_BINDING_FIELDS = {
    "schema",
    "runtime_digest",
    "active_skill_digest",
    "policy_digest",
    "policy_version",
}
_REQUEST_FIELDS = {
    "schema",
    "authority",
    "target_name",
    "payload_base64",
    "session_id",
    "run_id",
    "tool_call_digest",
}
_BROKER_RESULT_FIELDS = {
    "schema",
    "authority",
    "request_digest",
    "observation_digest",
    "target_name",
    "verdict",
    "reason_codes",
    "effect_status",
    "decision",
}
_DECISION_FIELDS = {
    "schema",
    "authority",
    "request_digest",
    "active_context_digest",
    "measured_action_digest",
    "policy_digest",
    "policy_version",
    "evaluated_at_unix",
    "revocation_snapshot_digest",
    "revocation_generation",
    "minimum_revocation_generation",
    "mediator_health_digest",
    "mediator_health_epoch",
    "minimum_mediator_health_epoch",
    "verdict",
    "reason_codes",
}
_ROOT = Path("/var/lib/aragorn-runtime-action")
_WORKER_RUNTIME_DIRECTORY = Path("/run/aragorn-runtime-action-worker")
_SENSOR_RUNTIME_DIRECTORY = Path("/run/aragorn-runtime-observation")


class RuntimeActionWorkerError(RuntimeError):
    """The worker could not safely relay or classify a runtime action."""


@dataclass(frozen=True, slots=True)
class RuntimeActionWorkerBinding:
    """Digest pins provisioned to the worker by the trusted operator."""

    runtime_digest: str
    active_skill_digest: str
    policy_digest: str
    policy_version: int


@dataclass(frozen=True, slots=True)
class RuntimeActionWorkerConfig:
    """Fixed paths, identities, and pins for the action worker."""

    socket_path: Path
    runtime_directory: Path
    sensor_socket_path: Path
    protected_root: Path
    expected_worker_uid: int
    expected_worker_gid: int
    expected_gateway_uid: int
    expected_gateway_gid: int
    expected_sensor_uid: int
    expected_sensor_gid: int
    expected_broker_uid: int
    binding: RuntimeActionWorkerBinding


def serve_runtime_action_worker(
    config: RuntimeActionWorkerConfig,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve authenticated gateway requests until interrupted by systemd."""

    _validate_config(config)
    if not _valid_timeout(request_timeout_seconds):
        raise RuntimeActionWorkerError("worker request timeout is invalid")
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "O_PATH"):
        raise RuntimeActionWorkerError("Linux SO_PEERCRED and O_PATH are required")

    runtime_fd = _open_runtime_directory(config)
    listener: socket.socket | None = None
    bound = False
    socket_identity: tuple[int, int] | None = None
    try:
        _prepare_socket_path(runtime_fd, config)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(config.socket_path))
        bound = True
        metadata = os.stat(
            config.socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        socket_identity = metadata.st_dev, metadata.st_ino
        os.chown(
            config.socket_path,
            config.expected_worker_uid,
            config.expected_gateway_gid,
        )
        os.chmod(config.socket_path, 0o660, follow_symlinks=False)
        metadata = os.stat(
            config.socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != config.expected_worker_uid
            or metadata.st_gid != config.expected_gateway_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o660
        ):
            raise RuntimeActionWorkerError("worker socket metadata is unsafe")
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
                except RuntimeActionWorkerError:
                    continue
    except RuntimeActionWorkerError:
        raise
    except OSError as exc:
        raise RuntimeActionWorkerError(f"worker transport failed: {exc}") from exc
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
                    config.socket_path.name,
                    dir_fd=runtime_fd,
                    follow_symlinks=False,
                )
                if socket_identity == (current.st_dev, current.st_ino):
                    os.unlink(config.socket_path.name, dir_fd=runtime_fd)
                    os.fsync(runtime_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        try:
            os.close(runtime_fd)
        except OSError as exc:
            cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise RuntimeActionWorkerError("worker transport cleanup failed") from (
                cleanup_error
            )


def main(argv: Sequence[str] | None = None) -> int:
    """Resolve service identities and serve one fixed worker endpoint."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: aragorn-runtime-action-worker WORKER_BINDING_CREDENTIAL",
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
        RuntimeActionServiceError,
        RuntimeActionWorkerError,
        TypeError,
        ValueError,
        WorkerProtocolError,
    ) as exc:
        print(f"aragorn runtime action worker: {exc}", file=sys.stderr)
        return 126


def _run(credential_path: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeActionWorkerError("Linux execution is required")
    identities = _service_identities()
    credential_path = _credential_path(
        credential_path,
        identities[0],
        credential_name="worker-binding",
    )
    binding = _read_worker_binding(credential_path, identities[0])
    serve_runtime_action_worker(
        RuntimeActionWorkerConfig(
            socket_path=_WORKER_RUNTIME_DIRECTORY / "worker.sock",
            runtime_directory=_WORKER_RUNTIME_DIRECTORY,
            sensor_socket_path=_SENSOR_RUNTIME_DIRECTORY / "sensor.sock",
            protected_root=_ROOT / "protected",
            expected_worker_uid=identities[0],
            expected_worker_gid=identities[1],
            expected_gateway_uid=identities[2],
            expected_gateway_gid=identities[3],
            expected_sensor_uid=identities[4],
            expected_sensor_gid=identities[5],
            expected_broker_uid=identities[6],
            binding=binding,
        )
    )


def _service_identities() -> tuple[int, int, int, int, int, int, int]:
    try:
        worker = pwd.getpwnam(_WORKER_PRINCIPAL)
        gateway = pwd.getpwnam(_GATEWAY_PRINCIPAL)
        sensor = pwd.getpwnam(_SENSOR_PRINCIPAL)
        broker = pwd.getpwnam(_BROKER_PRINCIPAL)
        worker_group = grp.getgrnam(_WORKER_PRINCIPAL)
        gateway_group = grp.getgrnam(_GATEWAY_PRINCIPAL)
        sensor_group = grp.getgrnam(_SENSOR_PRINCIPAL)
    except KeyError as exc:
        raise RuntimeActionWorkerError("required service identity is absent") from exc
    if (
        os.geteuid() != worker.pw_uid
        or os.getegid() != worker_group.gr_gid
        or worker.pw_gid != worker_group.gr_gid
        or gateway.pw_gid != gateway_group.gr_gid
        or sensor.pw_gid != sensor_group.gr_gid
    ):
        raise RuntimeActionWorkerError("worker process identity is invalid")
    if len({worker.pw_uid, gateway.pw_uid, sensor.pw_uid, broker.pw_uid}) != 4:
        raise RuntimeActionWorkerError("worker service identities overlap")
    if len({worker_group.gr_gid, gateway_group.gr_gid, sensor_group.gr_gid}) != 3:
        raise RuntimeActionWorkerError("worker service groups overlap")
    groups = set(os.getgroups())
    if gateway_group.gr_gid not in groups or not groups.issubset(
        {worker_group.gr_gid, gateway_group.gr_gid}
    ):
        raise RuntimeActionWorkerError("worker process groups are invalid")
    return (
        worker.pw_uid,
        worker_group.gr_gid,
        gateway.pw_uid,
        gateway_group.gr_gid,
        sensor.pw_uid,
        sensor_group.gr_gid,
        broker.pw_uid,
    )


def _read_worker_binding(path: Path, expected_uid: int) -> RuntimeActionWorkerBinding:
    raw = _read_credential_bytes(path, expected_uid, label="worker binding")
    try:
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or set(document) != _BINDING_FIELDS
            or document["schema"] != _BINDING_SCHEMA
            or canonical_json(document) != raw
        ):
            raise RuntimeActionWorkerError("worker binding credential is invalid")
        return RuntimeActionWorkerBinding(
            runtime_digest=_worker_digest(
                document["runtime_digest"], "worker runtime digest"
            ),
            active_skill_digest=_worker_digest(
                document["active_skill_digest"], "worker active skill digest"
            ),
            policy_digest=_worker_digest(
                document["policy_digest"], "worker policy digest"
            ),
            policy_version=_positive_uint(
                document["policy_version"], "worker policy version"
            ),
        )
    except RuntimeActionWorkerError:
        raise
    except (
        KeyError,
        RecursionError,
        RuntimeActionBrokerError,
        TypeError,
        ValueError,
        WorkerProtocolError,
    ) as exc:
        raise RuntimeActionWorkerError("worker binding credential is invalid") from exc


def _handle_connection(
    connection: socket.socket,
    config: RuntimeActionWorkerConfig,
    *,
    timeout_seconds: float,
) -> None:
    if not _valid_timeout(timeout_seconds):
        raise RuntimeActionWorkerError("worker request timeout is invalid")
    pid, uid, gid = _valid_peer(_peer_credentials(connection), "gateway")
    if uid != config.expected_gateway_uid or gid != config.expected_gateway_gid:
        raise RuntimeActionWorkerError(
            f"worker gateway peer {pid} has an unauthorized identity"
        )
    deadline = time.monotonic() + timeout_seconds
    try:
        request = _read_frame(connection, deadline)
        result = _relay_request(request, config, deadline=deadline)
        _send_frame(connection, canonical_json(result), deadline)
    except RuntimeActionWorkerError:
        raise
    except (OSError, RuntimeActionBrokerError, WorkerProtocolError) as exc:
        raise RuntimeActionWorkerError("worker gateway relay failed") from exc


def _relay_request(
    request: dict[str, Any],
    config: RuntimeActionWorkerConfig,
    *,
    deadline: float,
    clock: Callable[[], int] | None = None,
) -> dict[str, Any]:
    """Relay once, preserving whether bytes may have reached the sensor."""

    request_digest = canonical_digest(request)
    submitted = False
    broker_result: dict[str, Any] | None = None
    protected_fd = -1
    sensor: socket.socket | None = None
    failure: Exception | None = None
    try:
        validated, payload = _worker_request(request)
        protected_fd = _open_protected_root(config)
        trusted_clock = (lambda: int(time.time())) if clock is None else clock
        now_unix = _clock_value(trusted_clock)
        envelope = _broker_envelope(
            validated,
            payload,
            protected_fd,
            config.binding,
            now_unix,
        )
        sensor = _connect_sensor(config, deadline)
        submitted = True
        _send_frame(sensor, canonical_json(envelope), deadline)
        sensor.shutdown(socket.SHUT_WR)
        candidate = _read_frame(sensor, deadline)
        broker_result = _broker_result(candidate, envelope, config.binding)
    except (
        OSError,
        RuntimeActionBrokerError,
        RuntimeActionWorkerError,
        TypeError,
        ValueError,
        WorkerProtocolError,
    ) as exc:
        failure = exc
    finally:
        if sensor is not None:
            try:
                sensor.close()
            except OSError as exc:
                failure = failure or exc
        if protected_fd >= 0:
            try:
                os.close(protected_fd)
            except OSError as exc:
                failure = failure or exc
    if failure is not None or broker_result is None:
        return _worker_result(
            request_digest,
            "INDETERMINATE" if submitted else "NOT_SUBMITTED",
            None,
        )
    return _worker_result(request_digest, "COMPLETED", broker_result)


def _worker_request(value: object) -> tuple[dict[str, Any], bytes]:
    document = _exact(value, _REQUEST_FIELDS, "worker request")
    if document["schema"] != _REQUEST_SCHEMA:
        raise RuntimeActionWorkerError("worker request schema is unsupported")
    if document["authority"] != _REQUEST_AUTHORITY:
        raise RuntimeActionWorkerError("worker request authority is invalid")
    target_name = document["target_name"]
    if not isinstance(target_name, str) or _TARGET_NAME.fullmatch(target_name) is None:
        raise RuntimeActionWorkerError("worker target name is invalid")
    for field in ("session_id", "run_id"):
        value = document[field]
        if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
            raise RuntimeActionWorkerError(f"worker {field} is invalid")
    _worker_digest(document["tool_call_digest"], "worker tool call digest")
    encoded = document["payload_base64"]
    if (
        not isinstance(encoded, str)
        or len(encoded) > ((_MAX_PAYLOAD_BYTES + 2) // 3) * 4
    ):
        raise RuntimeActionWorkerError("worker payload is invalid")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeActionWorkerError("worker payload is invalid") from exc
    if (
        len(payload) > _MAX_PAYLOAD_BYTES
        or base64.b64encode(payload).decode("ascii") != encoded
    ):
        raise RuntimeActionWorkerError("worker payload is not canonical")
    return dict(document), payload


def _broker_envelope(
    request: dict[str, Any],
    payload: bytes,
    protected_fd: int,
    binding: RuntimeActionWorkerBinding,
    now_unix: int,
) -> dict[str, Any]:
    action = _action_digests(protected_fd, request["target_name"], payload)
    return {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "runtime_digest": binding.runtime_digest,
            "session_id": request["session_id"],
            "run_id": request["run_id"],
            "tool_call_id": request["tool_call_digest"],
            "active_skill_digest": binding.active_skill_digest,
            **action,
            "policy_digest": binding.policy_digest,
            "policy_version": binding.policy_version,
            "issued_at_unix": now_unix,
            "expires_at_unix": now_unix + _MAX_REQUEST_LIFETIME_SECONDS,
        },
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": request["target_name"],
            "payload_base64": request["payload_base64"],
        },
    }


def _worker_result(
    request_digest: str,
    status: str,
    broker_result: dict[str, Any] | None,
) -> dict[str, Any]:
    _worker_digest(request_digest, "worker result request digest")
    if status not in {"COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"}:
        raise RuntimeActionWorkerError("worker result status is invalid")
    if (status == "COMPLETED") != isinstance(broker_result, dict):
        raise RuntimeActionWorkerError("worker result outcome is inconsistent")
    return {
        "schema": _RESULT_SCHEMA,
        "authority": _RESULT_AUTHORITY,
        "request_digest": request_digest,
        "status": status,
        "broker_result": broker_result,
    }


def _broker_result(
    value: object,
    envelope: dict[str, Any],
    binding: RuntimeActionWorkerBinding,
) -> dict[str, Any]:
    result = _exact(value, _BROKER_RESULT_FIELDS, "broker result")
    expected_request_digest = canonical_digest(envelope["request"])
    if (
        result["schema"] != _BROKER_RESULT_SCHEMA
        or result["authority"] != _BROKER_RESULT_AUTHORITY
        or _worker_digest(result["request_digest"], "broker request digest")
        != expected_request_digest
        or _worker_digest(result["observation_digest"], "observation digest")
        != result["observation_digest"]
        or result["target_name"] != envelope["effect"]["target_name"]
    ):
        raise RuntimeActionWorkerError("broker result binding is invalid")
    reasons = _reason_codes(result["reason_codes"], "broker result")
    decision = result["decision"]
    if decision is not None:
        decision = _decision(
            decision,
            expected_request_digest=expected_request_digest,
            binding=binding,
        )
    allowed = (
        result["verdict"] == "ALLOW"
        and result["effect_status"] == "CREATED"
        and reasons == []
        and decision is not None
        and decision["verdict"] == "ALLOW"
        and decision["reason_codes"] == []
    )
    blocked = (
        result["verdict"] == "BLOCK"
        and result["effect_status"] == "NOT_PERFORMED"
        and len(reasons) > 0
    )
    if not allowed and not blocked:
        raise RuntimeActionWorkerError("broker result outcome is inconsistent")
    return dict(result)


def _decision(
    value: object,
    *,
    expected_request_digest: str,
    binding: RuntimeActionWorkerBinding,
) -> dict[str, Any]:
    decision = _exact(value, _DECISION_FIELDS, "runtime action decision")
    if (
        decision["schema"] != _DECISION_SCHEMA
        or decision["authority"] != _DECISION_AUTHORITY
        or _worker_digest(decision["request_digest"], "decision request digest")
        != expected_request_digest
        or _worker_digest(decision["policy_digest"], "decision policy digest")
        != binding.policy_digest
        or _positive_uint(decision["policy_version"], "decision policy version")
        != binding.policy_version
        or decision["verdict"] not in {"ALLOW", "BLOCK"}
    ):
        raise RuntimeActionWorkerError("runtime action decision binding is invalid")
    reasons = _reason_codes(decision["reason_codes"], "runtime action decision")
    for field, absent_reason in (
        ("active_context_digest", "ACTION_UNATTRIBUTED"),
        ("measured_action_digest", "ACTION_UNMEASURED"),
    ):
        absent = decision[field] is None
        if absent and not (
            absent_reason in reasons or "ACTION_REQUEST_INVALID" in reasons
        ):
            raise RuntimeActionWorkerError(
                "runtime action decision attribution is inconsistent"
            )
        if not absent and absent_reason in reasons:
            raise RuntimeActionWorkerError(
                "runtime action decision attribution is inconsistent"
            )
        if not absent:
            _worker_digest(decision[field], f"decision {field}")
    for field in ("revocation_snapshot_digest", "mediator_health_digest"):
        _worker_digest(decision[field], f"decision {field}")
    for field in (
        "evaluated_at_unix",
        "revocation_generation",
        "minimum_revocation_generation",
        "mediator_health_epoch",
        "minimum_mediator_health_epoch",
    ):
        _worker_uint(decision[field], f"decision {field}")
    if (decision["verdict"] == "ALLOW") != (reasons == []):
        raise RuntimeActionWorkerError(
            "runtime action decision outcome is inconsistent"
        )
    return dict(decision)


def _connect_sensor(
    config: RuntimeActionWorkerConfig,
    deadline: float,
) -> socket.socket:
    before = _sensor_socket_identity(config)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeActionWorkerError("worker request timed out")
        connection.settimeout(remaining)
        connection.connect(os.fspath(config.sensor_socket_path))
        pid, uid, gid = _valid_peer(_peer_credentials(connection), "sensor")
        if uid != config.expected_sensor_uid or gid != config.expected_sensor_gid:
            raise RuntimeActionWorkerError(
                f"worker sensor peer {pid} has an unauthorized identity"
            )
        if _sensor_socket_identity(config) != before:
            raise RuntimeActionWorkerError("sensor socket changed while connected")
        return connection
    except BaseException:
        connection.close()
        raise


def _sensor_socket_identity(config: RuntimeActionWorkerConfig) -> tuple[int, ...]:
    try:
        parent = os.lstat(config.sensor_socket_path.parent)
        metadata = os.lstat(config.sensor_socket_path)
    except OSError as exc:
        raise RuntimeActionWorkerError("sensor socket is unavailable") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != config.expected_sensor_uid
        or parent.st_gid != config.expected_worker_gid
        or stat.S_IMODE(parent.st_mode) != 0o750
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != config.expected_sensor_uid
        or metadata.st_gid != config.expected_worker_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o660
    ):
        raise RuntimeActionWorkerError("sensor socket metadata is unsafe")
    return (*_file_identity(parent), *_file_identity(metadata))


def _open_protected_root(config: RuntimeActionWorkerConfig) -> int:
    descriptor = -1
    try:
        if config.protected_root.resolve(strict=True) != config.protected_root:
            raise RuntimeActionWorkerError("protected root path is not canonical")
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
            _file_identity(before) != _file_identity(after)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != config.expected_broker_uid
            or after.st_gid != config.expected_worker_gid
            or stat.S_IMODE(after.st_mode) != 0o710
        ):
            raise RuntimeActionWorkerError("protected root metadata is unsafe")
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, RuntimeActionWorkerError):
            raise
        if isinstance(exc, (OSError, RuntimeError, ValueError)):
            raise RuntimeActionWorkerError("cannot open protected root") from exc
        raise


def _open_runtime_directory(config: RuntimeActionWorkerConfig) -> int:
    descriptor = -1
    try:
        if config.runtime_directory.resolve(strict=True) != config.runtime_directory:
            raise RuntimeActionWorkerError("worker runtime path is not canonical")
        _require_protected_ancestry(
            config.runtime_directory.parent,
            config.expected_worker_uid,
        )
        before = os.lstat(config.runtime_directory)
        descriptor = os.open(
            config.runtime_directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        after = os.fstat(descriptor)
        if (
            _file_identity(before) != _file_identity(after)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != config.expected_worker_uid
            or after.st_gid
            not in {config.expected_worker_gid, config.expected_gateway_gid}
            or stat.S_IMODE(after.st_mode) != 0o711
        ):
            raise RuntimeActionWorkerError("worker runtime metadata is unsafe")
        os.fchown(
            descriptor,
            config.expected_worker_uid,
            config.expected_gateway_gid,
        )
        os.fchmod(descriptor, 0o711)
        after = os.fstat(descriptor)
        named = os.lstat(config.runtime_directory)
        if (
            _file_identity(named) != _file_identity(after)
            or after.st_uid != config.expected_worker_uid
            or after.st_gid != config.expected_gateway_gid
            or stat.S_IMODE(after.st_mode) != 0o711
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeActionWorkerError("worker runtime metadata is unsafe")
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, RuntimeActionWorkerError):
            raise
        if isinstance(exc, (OSError, RuntimeError, ValueError)):
            raise RuntimeActionWorkerError(
                "cannot open worker runtime directory"
            ) from exc
        raise


def _prepare_socket_path(
    runtime_fd: int,
    config: RuntimeActionWorkerConfig,
) -> None:
    try:
        metadata = os.stat(
            config.socket_path.name,
            dir_fd=runtime_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != config.expected_worker_uid
        or metadata.st_gid != config.expected_gateway_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o660
    ):
        raise RuntimeActionWorkerError("existing worker socket is unsafe")
    current = os.stat(
        config.socket_path.name,
        dir_fd=runtime_fd,
        follow_symlinks=False,
    )
    if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
        raise RuntimeActionWorkerError("existing worker socket changed")
    os.unlink(config.socket_path.name, dir_fd=runtime_fd)
    os.fsync(runtime_fd)


def _validate_config(config: RuntimeActionWorkerConfig) -> None:
    if not isinstance(config, RuntimeActionWorkerConfig):
        raise RuntimeActionWorkerError("worker configuration is invalid")
    identities = (
        config.expected_worker_uid,
        config.expected_worker_gid,
        config.expected_gateway_uid,
        config.expected_gateway_gid,
        config.expected_sensor_uid,
        config.expected_sensor_gid,
        config.expected_broker_uid,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in identities
    ):
        raise RuntimeActionWorkerError("worker identity is invalid")
    if (
        len(
            {
                config.expected_worker_uid,
                config.expected_gateway_uid,
                config.expected_sensor_uid,
                config.expected_broker_uid,
            }
        )
        != 4
        or len(
            {
                config.expected_worker_gid,
                config.expected_gateway_gid,
                config.expected_sensor_gid,
            }
        )
        != 3
    ):
        raise RuntimeActionWorkerError("worker identities overlap")
    if (
        os.name != "posix"
        or os.geteuid() != config.expected_worker_uid
        or os.getegid() != config.expected_worker_gid
    ):
        raise RuntimeActionWorkerError("worker process identity is invalid")
    groups = set(os.getgroups())
    if config.expected_gateway_gid not in groups or not groups.issubset(
        {config.expected_worker_gid, config.expected_gateway_gid}
    ):
        raise RuntimeActionWorkerError("worker process groups are invalid")
    paths = (
        config.socket_path,
        config.runtime_directory,
        config.sensor_socket_path,
        config.protected_root,
    )
    if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
        raise RuntimeActionWorkerError("worker paths must be absolute Path values")
    if (
        config.socket_path.parent != config.runtime_directory
        or config.socket_path == config.sensor_socket_path
        or config.runtime_directory == Path(config.runtime_directory.anchor)
        or config.sensor_socket_path.parent == Path(config.sensor_socket_path.anchor)
        or config.protected_root == Path(config.protected_root.anchor)
    ):
        raise RuntimeActionWorkerError("worker path topology is invalid")
    if not isinstance(config.binding, RuntimeActionWorkerBinding):
        raise RuntimeActionWorkerError("worker binding is invalid")
    for value, label in (
        (config.binding.runtime_digest, "worker runtime digest"),
        (config.binding.active_skill_digest, "worker active skill digest"),
        (config.binding.policy_digest, "worker policy digest"),
    ):
        _worker_digest(value, label)
    _positive_uint(config.binding.policy_version, "worker policy version")


def _reason_codes(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 128
        or any(
            not isinstance(reason, str) or _REASON_CODE.fullmatch(reason) is None
            for reason in value
        )
        or value != sorted(set(value))
    ):
        raise RuntimeActionWorkerError(f"{label} reason codes are invalid")
    return value


def _valid_peer(value: object, label: str) -> tuple[int, int, int]:
    if (
        not isinstance(value, tuple)
        or len(value) != 3
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise RuntimeActionWorkerError(f"{label} peer credentials are invalid")
    pid, uid, gid = value
    if pid <= 0 or uid < 0 or gid < 0:
        raise RuntimeActionWorkerError(f"{label} peer credentials are invalid")
    return pid, uid, gid


def _clock_value(clock: Callable[[], int]) -> int:
    try:
        return _worker_uint(clock(), "worker request time")
    except Exception as exc:
        raise RuntimeActionWorkerError("worker clock failed") from exc


def _valid_timeout(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and 0 < value <= 0.5
    )


def _positive_uint(value: object, label: str) -> int:
    integer = _worker_uint(value, label)
    if integer == 0:
        raise RuntimeActionWorkerError(f"{label} is invalid")
    return integer


def _worker_digest(value: object, label: str) -> str:
    try:
        return _require_digest(value, label)
    except RuntimeActionBrokerError as exc:
        raise RuntimeActionWorkerError(f"{label} is invalid") from exc


def _worker_uint(value: object, label: str) -> int:
    try:
        return _uint(value, label)
    except RuntimeActionBrokerError as exc:
        raise RuntimeActionWorkerError(f"{label} is invalid") from exc


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeActionWorkerError(f"{label} fields are invalid")
    return value


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
