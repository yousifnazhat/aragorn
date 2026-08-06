"""One-shot capability attribution around the source-frozen v2 broker."""

from __future__ import annotations

import logging
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
    _acquire_lock,
    _atomic_publish_at,
    _directory_identity,
    _exact,
    _open_lock_file,
    _open_protected_directory,
    _parse_canonical_document,
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
)
from .runtime_action_broker_v2 import (
    RuntimeActionBrokerV2Config,
    _profiled_submission,
    _require_no_profile_pending,
    _with_profile_lock,
    mediate_profiled_runtime_create,
)
from .runtime_action_broker_v2 import (
    _validate_config as _validate_v2_config,
)

_LOG = logging.getLogger(__name__)
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_LEASE_BYTES = 64 * 1024
_MAX_LEASE_LIFETIME_SECONDS = 300
_LEASE_FIELDS = {
    "schema",
    "authority",
    "lease_nonce",
    "runtime_profile_digest",
    "runtime_digest",
    "active_skill_digest",
    "sensor_digest",
    "request_digest",
    "policy_digest",
    "policy_version",
    "operation_digest",
    "path_digest",
    "payload_digest",
    "issued_at_unix",
    "expires_at_unix",
    "max_actions",
}
_STATE_FIELDS = {
    "schema",
    "authority",
    "lease_digest",
    "status",
    "claim",
    "result",
}
_CLAIM_FIELDS = {
    "schema",
    "authority",
    "lease_digest",
    "claimed_at_unix",
    "submission_digest",
    "runtime_attribution_digest",
    "envelope_digest",
    "request_digest",
    "measured_action_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "target_name",
    "profile_pending",
}
_RESULT_FIELDS = {
    "schema",
    "authority",
    "lease_digest",
    "submission_digest",
    "profile_receipt_digest",
    "broker_result_digest",
    "verdict",
    "effect_status",
}
_PROFILE_PENDING_FIELDS = {
    "schema",
    "authority",
    "submission_digest",
    "envelope_digest",
    "request_digest",
    "measured_action",
    "runtime_attribution",
    "runtime_attribution_digest",
}
_PROFILE_RECEIPT_FIELDS = {
    "schema",
    "authority",
    "submission_digest",
    "runtime_attribution",
    "runtime_attribution_digest",
    "broker_result",
    "broker_result_digest",
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


@dataclass(frozen=True, slots=True)
class RuntimeActionBrokerV3Config:
    """Exact v2 broker plus one immutable lease and its durable state."""

    broker: RuntimeActionBrokerV2Config
    capability_lease: bytes
    lease_state_path: Path


def initialize_runtime_capability_lease(
    config: RuntimeActionBrokerV3Config,
    *,
    now_unix: int | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Durably issue the configured lease once, without resetting existing state."""

    lease = _validate_config(config)
    now = int(time.time()) if now_unix is None else _uint(now_unix, "lease issue time")
    issued = {
        "schema": "aragorn/runtime-capability-lease-state/v1",
        "authority": ("BROKER_DURABLE_LEASE_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"),
        "lease_digest": canonical_digest(lease),
        "status": "ISSUED",
        "claim": None,
        "result": None,
    }

    current_state = issued

    def initialize(control_fd: int) -> None:
        nonlocal current_state
        try:
            current = _load_state(control_fd, config, issued["lease_digest"])
        except FileNotFoundError:
            _require_live_lease(lease, now)
            _publish_state(control_fd, config, issued)
            return
        if current["lease_digest"] != issued["lease_digest"]:
            raise RuntimeActionBrokerError("runtime capability lease changed")
        if current["status"] == "ISSUED":
            _require_live_lease(lease, now)
        current_state = current

    _with_profile_lock(config.broker, deadline_monotonic, initialize)
    return current_state


def mediate_leased_profiled_runtime_create(
    submission: object,
    config: RuntimeActionBrokerV3Config,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Consume one exact lease before invoking the unchanged v2 effect route."""

    lease = _validate_config(config)
    legacy, attribution, submission_digest = _profiled_submission(
        submission,
        config.broker,
    )
    now = int(time.time())
    claim = _build_claim(
        lease,
        legacy,
        attribution,
        submission_digest,
        now,
    )
    _claim_lease(config, claim, deadline_monotonic)
    # Any failure leaves the lease CLAIMED. A known pre-effect failure is still
    # one consumed authority attempt and must never restore authorization.
    result = mediate_profiled_runtime_create(
        submission,
        config.broker,
        deadline_monotonic=deadline_monotonic,
    )
    _consume_lease(config, claim, result, deadline_monotonic)
    return result


def recover_runtime_capability_lease(
    config: RuntimeActionBrokerV3Config,
    *,
    timeout_seconds: float = 0.5,
) -> dict[str, Any]:
    """Recover only from an exact durable v2 receipt; never retry an effect."""

    lease = _validate_config(config)
    recovered: dict[str, Any] = {}

    def recover(control_fd: int) -> None:
        nonlocal recovered
        state = _load_state(control_fd, config, canonical_digest(lease))
        if state["status"] == "ISSUED":
            _require_no_pending_at(control_fd, config)
            recovered = state
            return
        if state["status"] == "CLAIMED":
            receipt = _load_profile_receipt(control_fd, config)
            result_record = _result_record(state["claim"], receipt)
            state = {**state, "status": "CONSUMED", "result": result_record}
            _publish_state(control_fd, config, state)
        else:
            receipt = _load_profile_receipt(control_fd, config)
            if state["result"] != _result_record(state["claim"], receipt):
                raise RuntimeActionBrokerError(
                    "runtime capability lease result changed"
                )
        _discard_exact_profile_pending(control_fd, config, state["claim"])
        recovered = state

    _with_profile_lock(
        config.broker,
        time.monotonic() + timeout_seconds,
        recover,
    )
    return recovered


def serve_runtime_action_broker_v3(
    config: RuntimeActionBrokerV3Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve exact v2 submissions through the one-shot v3 authority state."""

    _validate_config(config)
    broker = config.broker.broker
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
        recover_runtime_capability_lease(
            config,
            timeout_seconds=request_timeout_seconds,
        )
        _require_no_profile_pending(config.broker, request_timeout_seconds)
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
    config: RuntimeActionBrokerV3Config,
    *,
    timeout_seconds: float,
) -> None:
    broker = config.broker.broker
    pid, uid, gid = _peer_credentials(connection)
    if uid != broker.expected_peer_uid or gid != broker.expected_peer_gid:
        raise RuntimeActionBrokerError(
            f"runtime broker peer {pid} has an unauthorized identity"
        )
    deadline = time.monotonic() + timeout_seconds
    result = mediate_leased_profiled_runtime_create(
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


def _build_claim(
    lease: dict[str, Any],
    legacy: dict[str, Any],
    attribution: dict[str, Any],
    submission_digest: str,
    now_unix: int,
) -> dict[str, Any]:
    _require_live_lease(lease, now_unix)
    request = legacy["envelope"]["request"]
    measured = legacy["measured_action"]
    effect = legacy["envelope"]["effect"]
    bindings = {
        "runtime_profile_digest": attribution["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": legacy["sensor_digest"],
        "request_digest": legacy["request_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
        "path_digest": request["path_digest"],
        "payload_digest": request["payload_digest"],
    }
    if any(lease[field] != value for field, value in bindings.items()) or (
        request["issued_at_unix"] < lease["issued_at_unix"]
        or request["expires_at_unix"] > lease["expires_at_unix"]
    ):
        raise RuntimeActionBrokerError("runtime capability lease is unbound")
    profile_pending = {
        "schema": "aragorn/runtime-process-profile-pending/v1",
        "authority": "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY",
        "submission_digest": submission_digest,
        "envelope_digest": legacy["envelope_digest"],
        "request_digest": legacy["request_digest"],
        "measured_action": measured,
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
    }
    return {
        "schema": "aragorn/runtime-capability-lease-claim/v1",
        "authority": "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": canonical_digest(lease),
        "claimed_at_unix": now_unix,
        "submission_digest": submission_digest,
        "runtime_attribution_digest": canonical_digest(attribution),
        "envelope_digest": legacy["envelope_digest"],
        "request_digest": legacy["request_digest"],
        "measured_action_digest": canonical_digest(measured),
        "session_id": request["session_id"],
        "run_id": request["run_id"],
        "tool_call_id": request["tool_call_id"],
        "target_name": effect["target_name"],
        "profile_pending": profile_pending,
    }


def _claim_lease(
    config: RuntimeActionBrokerV3Config,
    claim: dict[str, Any],
    deadline: float | None,
) -> None:
    def claim_once(control_fd: int) -> None:
        state = _load_state(control_fd, config, claim["lease_digest"])
        if state["status"] != "ISSUED":
            raise RuntimeActionBrokerError("runtime capability lease is consumed")
        _require_no_pending_at(control_fd, config)
        _discard_stale_profile_receipt(control_fd, config)
        _publish_state(
            control_fd,
            config,
            {**state, "status": "CLAIMED", "claim": claim},
        )

    _with_profile_lock(config.broker, deadline, claim_once)


def _consume_lease(
    config: RuntimeActionBrokerV3Config,
    claim: dict[str, Any],
    result: dict[str, Any],
    deadline: float | None,
) -> None:
    def consume(control_fd: int) -> None:
        state = _load_state(control_fd, config, claim["lease_digest"])
        if state["status"] != "CLAIMED" or state["claim"] != claim:
            raise RuntimeActionEffectIndeterminate(
                "runtime capability lease claim changed after mediation"
            )
        _require_no_pending_at(control_fd, config)
        receipt = _load_profile_receipt(control_fd, config)
        result_record = _result_record(claim, receipt)
        if result_record["broker_result_digest"] != canonical_digest(result):
            raise RuntimeActionEffectIndeterminate(
                "runtime capability lease result is unbound"
            )
        _publish_state(
            control_fd,
            config,
            {**state, "status": "CONSUMED", "result": result_record},
        )

    try:
        _with_profile_lock(config.broker, deadline, consume)
    except RuntimeActionEffectIndeterminate:
        raise
    except RuntimeActionBrokerError as exc:
        if result["effect_status"] == "CREATED":
            raise RuntimeActionEffectIndeterminate(
                "runtime create committed but its lease receipt failed"
            ) from exc
        raise


def _result_record(
    claim: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    document = _exact(receipt, _PROFILE_RECEIPT_FIELDS, "runtime profile receipt")
    if (
        document["schema"] != "aragorn/runtime-process-profile-receipt/v1"
        or document["authority"]
        != "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        or document["submission_digest"] != claim["submission_digest"]
        or document["runtime_attribution_digest"] != claim["runtime_attribution_digest"]
        or document["runtime_attribution"]
        != claim["profile_pending"]["runtime_attribution"]
    ):
        raise RuntimeActionBrokerError("runtime profile receipt is unbound")
    result = _exact(
        document["broker_result"],
        _BROKER_RESULT_FIELDS,
        "runtime broker result",
    )
    _require_digest(result["observation_digest"], "runtime observation digest")
    decision = result["decision"]
    valid_decision = (
        isinstance(decision, dict)
        and decision.get("schema") == "aragorn/runtime-action-decision/v1"
        and decision.get("authority")
        == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and decision.get("request_digest") == claim["request_digest"]
        and decision.get("verdict") == result["verdict"]
        and decision.get("reason_codes") == result["reason_codes"]
    )
    if (
        document["broker_result_digest"] != canonical_digest(result)
        or result["schema"] != "aragorn/runtime-action-broker-result/v1"
        or result["authority"]
        != "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or result["request_digest"] != claim["request_digest"]
        or result["target_name"] != claim["target_name"]
        or not isinstance(result["reason_codes"], list)
        or any(not isinstance(reason, str) for reason in result["reason_codes"])
        or not valid_decision
        or (result["verdict"] == "ALLOW" and result["reason_codes"] != [])
        or (result["verdict"] == "BLOCK" and not result["reason_codes"])
        or (
            result["verdict"],
            result["effect_status"],
        )
        not in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}
    ):
        raise RuntimeActionBrokerError("runtime broker result is unbound")
    return {
        "schema": "aragorn/runtime-capability-lease-result/v1",
        "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": claim["lease_digest"],
        "submission_digest": claim["submission_digest"],
        "profile_receipt_digest": canonical_digest(document),
        "broker_result_digest": canonical_digest(result),
        "verdict": result["verdict"],
        "effect_status": result["effect_status"],
    }


def _lease(value: bytes) -> dict[str, Any]:
    if not isinstance(value, bytes) or not value or len(value) > _MAX_LEASE_BYTES:
        raise RuntimeActionBrokerError("runtime capability lease is invalid")
    document = _exact(
        _parse_canonical_document(value, "runtime capability lease"),
        _LEASE_FIELDS,
        "runtime capability lease",
    )
    if (
        document["schema"] != "aragorn/runtime-capability-lease/v1"
        or document["authority"]
        != "BROKER_ENFORCED_SINGLE_CAPABILITY_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or not isinstance(document["lease_nonce"], str)
        or _NONCE.fullmatch(document["lease_nonce"]) is None
    ):
        raise RuntimeActionBrokerError("runtime capability lease is invalid")
    for field in (
        "runtime_profile_digest",
        "runtime_digest",
        "active_skill_digest",
        "sensor_digest",
        "request_digest",
        "policy_digest",
        "operation_digest",
        "path_digest",
        "payload_digest",
    ):
        _require_digest(document[field], f"runtime capability lease {field}")
    if _positive_uint(document["max_actions"], "runtime capability max actions") != 1:
        raise RuntimeActionBrokerError("runtime capability lease is invalid")
    _positive_uint(document["policy_version"], "runtime capability policy version")
    issued = _uint(document["issued_at_unix"], "runtime capability issue time")
    expires = _uint(document["expires_at_unix"], "runtime capability expiry")
    if expires <= issued or expires - issued > _MAX_LEASE_LIFETIME_SECONDS:
        raise RuntimeActionBrokerError("runtime capability lease lifetime is invalid")
    return document


def _require_live_lease(lease: dict[str, Any], now_unix: int) -> None:
    if lease["issued_at_unix"] > now_unix or now_unix >= lease["expires_at_unix"]:
        raise RuntimeActionBrokerError("runtime capability lease is stale")


def _state(value: object, expected_lease_digest: str) -> dict[str, Any]:
    document = _exact(value, _STATE_FIELDS, "runtime capability lease state")
    if (
        document["schema"] != "aragorn/runtime-capability-lease-state/v1"
        or document["authority"]
        != "BROKER_DURABLE_LEASE_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["lease_digest"] != expected_lease_digest
        or document["status"] not in {"ISSUED", "CLAIMED", "CONSUMED"}
    ):
        raise RuntimeActionBrokerError("runtime capability lease state is invalid")
    _require_digest(document["lease_digest"], "runtime capability lease digest")
    status = document["status"]
    if status == "ISSUED":
        if document["claim"] is not None or document["result"] is not None:
            raise RuntimeActionBrokerError("runtime capability lease state is invalid")
    else:
        claim = _claim(document["claim"], expected_lease_digest)
        if status == "CLAIMED" and document["result"] is not None:
            raise RuntimeActionBrokerError("runtime capability lease state is invalid")
        if status == "CONSUMED":
            _lease_result(document["result"], claim)
    return document


def _claim(value: object, expected_lease_digest: str) -> dict[str, Any]:
    document = _exact(value, _CLAIM_FIELDS, "runtime capability lease claim")
    if (
        document["schema"] != "aragorn/runtime-capability-lease-claim/v1"
        or document["authority"]
        != "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["lease_digest"] != expected_lease_digest
    ):
        raise RuntimeActionBrokerError("runtime capability lease claim is invalid")
    for field in (
        "lease_digest",
        "submission_digest",
        "runtime_attribution_digest",
        "envelope_digest",
        "request_digest",
        "measured_action_digest",
    ):
        _require_digest(document[field], f"runtime capability claim {field}")
    _uint(document["claimed_at_unix"], "runtime capability claim time")
    for field in ("session_id", "run_id", "tool_call_id", "target_name"):
        if not isinstance(document[field], str) or not document[field]:
            raise RuntimeActionBrokerError("runtime capability lease claim is invalid")
    pending = _exact(
        document["profile_pending"],
        _PROFILE_PENDING_FIELDS,
        "runtime profile pending claim",
    )
    if (
        pending["schema"] != "aragorn/runtime-process-profile-pending/v1"
        or pending["authority"] != "BROKER_PENDING_PROFILE_ONLY_NOT_EFFECT_AUTHORITY"
        or pending["submission_digest"] != document["submission_digest"]
        or pending["envelope_digest"] != document["envelope_digest"]
        or pending["request_digest"] != document["request_digest"]
        or pending["runtime_attribution_digest"]
        != document["runtime_attribution_digest"]
        or canonical_digest(pending["measured_action"])
        != document["measured_action_digest"]
        or canonical_digest(pending["runtime_attribution"])
        != document["runtime_attribution_digest"]
        or any(
            pending["measured_action"].get(field) != document[field]
            for field in ("session_id", "run_id", "tool_call_id")
        )
    ):
        raise RuntimeActionBrokerError("runtime capability lease claim is unbound")
    return document


def _lease_result(value: object, claim: dict[str, Any]) -> dict[str, Any]:
    document = _exact(value, _RESULT_FIELDS, "runtime capability lease result")
    if (
        document["schema"] != "aragorn/runtime-capability-lease-result/v1"
        or document["authority"]
        != "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["lease_digest"] != claim["lease_digest"]
        or document["submission_digest"] != claim["submission_digest"]
        or (
            document["verdict"],
            document["effect_status"],
        )
        not in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}
    ):
        raise RuntimeActionBrokerError("runtime capability lease result is invalid")
    for field in (
        "lease_digest",
        "submission_digest",
        "profile_receipt_digest",
        "broker_result_digest",
    ):
        _require_digest(document[field], f"runtime capability result {field}")
    return document


def _load_state(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
    expected_lease_digest: str,
) -> dict[str, Any]:
    raw = _read_owned_bytes_at(
        control_fd,
        config.lease_state_path.name,
        max_bytes=_MAX_LEASE_BYTES,
        expected_uid=config.broker.broker.expected_broker_uid,
        exact_mode=0o400,
        label="runtime capability lease state",
    )
    return _state(
        _parse_canonical_document(raw, "runtime capability lease state"),
        expected_lease_digest,
    )


def _publish_state(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
    state: dict[str, Any],
) -> None:
    lease_digest = canonical_digest(_lease(config.capability_lease))
    document = _state(state, lease_digest)
    _atomic_publish_at(
        control_fd,
        config.lease_state_path.name,
        canonical_json(document),
        expected_uid=config.broker.broker.expected_broker_uid,
    )


def _load_profile_receipt(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
) -> dict[str, Any]:
    try:
        raw = _read_owned_bytes_at(
            control_fd,
            config.broker.profile_receipt_path.name,
            max_bytes=_MAX_LEASE_BYTES,
            expected_uid=config.broker.broker.expected_broker_uid,
            exact_mode=0o400,
            label="runtime process profile receipt",
        )
    except FileNotFoundError as exc:
        raise RuntimeActionBrokerError(
            "claimed runtime capability has no durable profile receipt"
        ) from exc
    return _parse_canonical_document(raw, "runtime process profile receipt")


def _discard_stale_profile_receipt(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
) -> None:
    try:
        _read_owned_bytes_at(
            control_fd,
            config.broker.profile_receipt_path.name,
            max_bytes=_MAX_LEASE_BYTES,
            expected_uid=config.broker.broker.expected_broker_uid,
            exact_mode=0o400,
            label="stale runtime process profile receipt",
        )
    except FileNotFoundError:
        return
    os.unlink(config.broker.profile_receipt_path.name, dir_fd=control_fd)
    os.fsync(control_fd)


def _require_no_pending_at(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
) -> None:
    try:
        os.stat(
            config.broker.profile_pending_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise RuntimeActionBrokerError(
        "an unresolved runtime process profile action exists"
    )


def _discard_exact_profile_pending(
    control_fd: int,
    config: RuntimeActionBrokerV3Config,
    claim: dict[str, Any],
) -> None:
    expected = canonical_json(claim["profile_pending"])
    try:
        current = _read_owned_bytes_at(
            control_fd,
            config.broker.profile_pending_path.name,
            max_bytes=len(expected),
            expected_uid=config.broker.broker.expected_broker_uid,
            exact_mode=0o400,
            label="runtime process profile pending record",
        )
    except FileNotFoundError:
        return
    if current != expected:
        raise RuntimeActionBrokerError("runtime process profile pending record changed")
    os.unlink(config.broker.profile_pending_path.name, dir_fd=control_fd)
    os.fsync(control_fd)


def _validate_config(config: RuntimeActionBrokerV3Config) -> dict[str, Any]:
    if not isinstance(config, RuntimeActionBrokerV3Config):
        raise RuntimeActionBrokerError(
            "runtime capability broker configuration is invalid"
        )
    _validate_v2_config(config.broker)
    lease = _lease(config.capability_lease)
    broker = config.broker.broker
    if (
        config.lease_state_path.parent != broker.control_root
        or config.lease_state_path.name != "capability-lease-state.json"
        or config.lease_state_path
        in {
            broker.socket_path,
            broker.instance_lock_path,
            broker.lock_path,
            broker.policy_path,
            broker.revocations_path,
            broker.health_path,
            broker.observation_path,
            broker.state_path,
            config.broker.profile_pending_path,
            config.broker.profile_receipt_path,
        }
        or lease["runtime_profile_digest"]
        != config.broker.expected_runtime_profile_digest
        or lease["runtime_digest"] != broker.expected_runtime_digest
    ):
        raise RuntimeActionBrokerError(
            "runtime capability broker configuration is invalid"
        )
    return lease
