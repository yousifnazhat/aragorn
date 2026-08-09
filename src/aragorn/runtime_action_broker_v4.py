"""Root-grant redemption for sensor-issued runtime capabilities."""

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
    _file_identity,
    _open_lock_file,
    _open_protected_directory,
    _parse_canonical_document,
    _peer_credentials,
    _positive_uint,
    _prepare_socket_path,
    _ProtectedFileError,
    _read_frame,
    _read_owned_bytes_at,
    _recover_before_listen,
    _release_lock_and_close,
    _require_digest,
    _send_frame,
    _uint,
    create_exclusive_file_at,
    write_all,
)
from .runtime_action_broker_v2 import (
    RuntimeActionBrokerV2Config,
    _profiled_submission,
    _require_no_profile_pending,
    _with_profile_lock,
    mediate_profiled_runtime_create,
)
from .runtime_action_broker_v2 import _validate_config as _validate_v2_config
from .runtime_action_broker_v3 import _claim as _validate_profile_claim
from .runtime_action_broker_v3 import (
    _discard_exact_profile_pending,
    _discard_stale_profile_receipt,
    _load_profile_receipt,
    _require_no_pending_at,
)
from .runtime_action_broker_v3 import (
    _lease_result as _validate_profile_result,
)
from .runtime_action_broker_v3 import (
    _result_record as _profile_result_record,
)
from .runtime_capability_grant import (
    ISSUANCE_AUTHORITY,
    ISSUANCE_SCHEMA,
    LEASE_AUTHORITY,
    LEASE_SCHEMA,
    parse_runtime_capability_grant,
)

_LOG = logging.getLogger(__name__)
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_STATE_BYTES = 64 * 1024
_MAX_LEASE_LIFETIME_SECONDS = 300
_ISSUED_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "lease",
    "profiled_submission",
}
_LEASE_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "lease_nonce",
    "submission_digest",
    "runtime_attribution_digest",
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
    "grant_digest",
    "status",
    "claim",
    "result",
}
_CLAIM_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "lease_digest",
    "lease",
    "profile_claim",
}
_RESULT_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "lease_digest",
    "profile_result",
}
_ABANDONMENT_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "lease_digest",
    "failure_code",
}
_EXPIRATION_FIELDS = {
    "schema",
    "authority",
    "grant_digest",
    "expires_at_unix",
    "observed_at_unix",
}
_TERMINAL_STATES = {"CONSUMED", "ABANDONED", "EXPIRED"}


@dataclass(frozen=True, slots=True)
class RuntimeActionBrokerV4Config:
    """Exact v2 effect broker plus one root-provisioned capability grant."""

    broker: RuntimeActionBrokerV2Config
    capability_grant: bytes
    grant_state_path: Path


def initialize_runtime_capability_grant(
    config: RuntimeActionBrokerV4Config,
    *,
    now_unix: int | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Create AVAILABLE state once without resetting an accepted attempt."""

    grant = _validate_config(config)
    fixed_now = None if now_unix is None else _uint(now_unix, "grant time")
    grant_digest = canonical_digest(grant)
    available = {
        "schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": grant_digest,
        "status": "AVAILABLE",
        "claim": None,
        "result": None,
    }
    current_state = available

    def initialize(control_fd: int) -> None:
        nonlocal current_state
        now = int(time.time()) if fixed_now is None else fixed_now
        try:
            current = _load_any_state(control_fd, config)
        except FileNotFoundError:
            _require_fresh_grant(control_fd, config, grant_digest)
            if grant["issued_at_unix"] > now:
                raise RuntimeActionBrokerError("runtime capability grant is stale")
            current_state = _refresh_available_grant(
                control_fd,
                config,
                grant,
                available,
                now,
            )
            if current_state["status"] == "AVAILABLE":
                _publish_state(control_fd, config, current_state)
            return
        if current["grant_digest"] != grant_digest:
            if current["status"] not in _TERMINAL_STATES:
                raise RuntimeActionBrokerError(
                    "runtime capability grant changed while active"
                )
            _require_live_grant(grant, now)
            _require_fresh_grant(control_fd, config, grant_digest)
            _archive_terminal_state(control_fd, config, current)
            _publish_state(control_fd, config, available)
            return
        if current["status"] == "AVAILABLE":
            _require_fresh_grant(control_fd, config, grant_digest)
            current = _refresh_available_grant(
                control_fd,
                config,
                grant,
                current,
                now,
            )
        elif current["status"] == "EXPIRED":
            _require_expiration_matches_grant(current, grant)
            _require_no_pending_at(control_fd, config)
            _require_no_profile_receipt_at(control_fd, config)
        current_state = current

    _with_profile_lock(config.broker, deadline_monotonic, initialize)
    return current_state


def mediate_granted_profiled_runtime_create(
    issued_submission: object,
    config: RuntimeActionBrokerV4Config,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Claim one root grant before invoking the unchanged v2 effect route."""

    grant = _validate_config(config)
    now = int(time.time())
    submission, legacy, attribution, submission_digest, lease = _issued_submission(
        issued_submission,
        config,
        grant,
        now,
    )
    claim = _build_claim(
        grant,
        lease,
        legacy,
        attribution,
        submission_digest,
        now,
    )
    claim = _claim_grant(config, claim, grant, deadline_monotonic)
    # Indeterminate effects stay CLAIMED; known pre-effect failures become terminal.
    try:
        result = mediate_profiled_runtime_create(
            submission,
            config.broker,
            deadline_monotonic=deadline_monotonic,
        )
    except RuntimeActionEffectIndeterminate:
        raise
    except RuntimeActionBrokerError:
        _abandon_grant(config, claim, deadline_monotonic)
        raise
    _consume_grant(config, claim, result, deadline_monotonic)
    return result


def recover_runtime_capability_grant(
    config: RuntimeActionBrokerV4Config,
    *,
    timeout_seconds: float = 0.5,
) -> dict[str, Any]:
    """Recover only an exact claimed v2 receipt; never retry an effect."""

    grant = _validate_config(config)
    grant_digest = canonical_digest(grant)
    recovered: dict[str, Any] = {}

    def recover(control_fd: int) -> None:
        nonlocal recovered
        state = _load_state(control_fd, config, grant_digest)
        if state["status"] == "AVAILABLE":
            now = int(time.time())
            state = _refresh_available_grant(
                control_fd,
                config,
                grant,
                state,
                now,
            )
            if state["status"] == "AVAILABLE":
                _require_no_pending_at(control_fd, config)
            recovered = state
            return
        if state["status"] == "ABANDONED":
            _require_no_pending_at(control_fd, config)
            _require_no_profile_receipt_at(control_fd, config)
            recovered = state
            return
        if state["status"] == "EXPIRED":
            _require_expiration_matches_grant(state, grant)
            _require_no_pending_at(control_fd, config)
            _require_no_profile_receipt_at(control_fd, config)
            recovered = state
            return
        claim = state["claim"]
        if state["status"] == "CLAIMED":
            receipt = _load_profile_receipt(control_fd, config)
            state = {
                **state,
                "status": "CONSUMED",
                "result": _result_record(claim, receipt),
            }
            _publish_state(control_fd, config, state)
        else:
            receipt = _load_profile_receipt(control_fd, config)
            if state["result"] != _result_record(claim, receipt):
                raise RuntimeActionBrokerError(
                    "runtime capability grant result changed"
                )
        _discard_exact_profile_pending(
            control_fd,
            config,
            state["claim"]["profile_claim"],
        )
        recovered = state

    _with_profile_lock(
        config.broker,
        time.monotonic() + timeout_seconds,
        recover,
    )
    return recovered


def serve_runtime_action_broker_v4(
    config: RuntimeActionBrokerV4Config,
    *,
    request_timeout_seconds: float = 0.5,
) -> None:
    """Serve sensor-issued capabilities through one root grant."""

    grant = _validate_config(config)
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
        state = recover_runtime_capability_grant(
            config,
            timeout_seconds=request_timeout_seconds,
        )
        if state["status"] != "AVAILABLE":
            return
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
            state = initialize_runtime_capability_grant(
                config,
                deadline_monotonic=time.monotonic() + request_timeout_seconds,
            )
            if state["status"] != "AVAILABLE":
                return
            remaining = grant["expires_at_unix"] - time.time()
            if remaining <= 0:
                continue
            listener.settimeout(remaining)
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
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
    config: RuntimeActionBrokerV4Config,
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
    result = mediate_granted_profiled_runtime_create(
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


def _issued_submission(
    value: object,
    config: RuntimeActionBrokerV4Config,
    grant: dict[str, Any],
    now_unix: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    issued = _exact(value, _ISSUED_FIELDS, "issued runtime capability submission")
    if issued["schema"] != ISSUANCE_SCHEMA or issued["authority"] != ISSUANCE_AUTHORITY:
        raise RuntimeActionBrokerError("issued runtime capability is invalid")
    grant_digest = canonical_digest(grant)
    if issued["grant_digest"] != grant_digest:
        raise RuntimeActionBrokerError("runtime capability grant is unbound")
    _require_digest(issued["grant_digest"], "runtime capability grant digest")

    submission = issued["profiled_submission"]
    legacy, attribution, submission_digest = _profiled_submission(
        submission,
        config.broker,
    )
    lease = _exact(issued["lease"], _LEASE_FIELDS, "runtime capability lease")
    request = legacy["envelope"]["request"]
    expected_lease = {
        "grant_digest": grant_digest,
        "submission_digest": submission_digest,
        "runtime_attribution_digest": canonical_digest(attribution),
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
    grant_bindings = {
        "runtime_profile_digest": attribution["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": legacy["sensor_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
    }
    if (
        lease["schema"] != LEASE_SCHEMA
        or lease["authority"] != LEASE_AUTHORITY
        or any(lease[field] != expected for field, expected in expected_lease.items())
        or any(grant[field] != expected for field, expected in grant_bindings.items())
        or not isinstance(lease["lease_nonce"], str)
        or _NONCE.fullmatch(lease["lease_nonce"]) is None
    ):
        raise RuntimeActionBrokerError("runtime capability lease is unbound")
    for field in (
        "grant_digest",
        "submission_digest",
        "runtime_attribution_digest",
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
        _require_digest(lease[field], f"runtime capability lease {field}")
    if _positive_uint(lease["max_actions"], "runtime capability max actions") != 1:
        raise RuntimeActionBrokerError("runtime capability lease is invalid")
    _positive_uint(lease["policy_version"], "runtime capability policy version")
    issued_at = _uint(lease["issued_at_unix"], "runtime capability issue time")
    expires_at = _uint(lease["expires_at_unix"], "runtime capability expiry")
    request_issued = _uint(request["issued_at_unix"], "runtime request issue time")
    request_expires = _uint(request["expires_at_unix"], "runtime request expiry")
    if (
        grant["issued_at_unix"] > request_issued
        or request_issued > issued_at
        or issued_at > now_unix
        or now_unix >= expires_at
        or expires_at != request_expires
        or expires_at > grant["expires_at_unix"]
        or expires_at <= issued_at
        or expires_at - issued_at > _MAX_LEASE_LIFETIME_SECONDS
    ):
        raise RuntimeActionBrokerError("runtime capability lease lifetime is invalid")
    return submission, legacy, attribution, submission_digest, lease


def _build_claim(
    grant: dict[str, Any],
    lease: dict[str, Any],
    legacy: dict[str, Any],
    attribution: dict[str, Any],
    submission_digest: str,
    now_unix: int,
) -> dict[str, Any]:
    request = legacy["envelope"]["request"]
    measured = legacy["measured_action"]
    effect = legacy["envelope"]["effect"]
    lease_digest = canonical_digest(lease)
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
    profile_claim = {
        "schema": "aragorn/runtime-capability-lease-claim/v1",
        "authority": "BROKER_LEASE_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": lease_digest,
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
    return {
        "schema": "aragorn/runtime-capability-grant-claim/v1",
        "authority": "BROKER_GRANT_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": canonical_digest(grant),
        "lease_digest": lease_digest,
        "lease": lease,
        "profile_claim": profile_claim,
    }


def _claim_grant(
    config: RuntimeActionBrokerV4Config,
    claim: dict[str, Any],
    grant: dict[str, Any],
    deadline: float | None,
) -> dict[str, Any]:
    accepted: dict[str, Any] = {}

    def claim_once(control_fd: int) -> None:
        nonlocal accepted
        claimed_at = int(time.time())
        _require_live_grant(grant, claimed_at)
        lease = claim["lease"]
        if not lease["issued_at_unix"] <= claimed_at < lease["expires_at_unix"]:
            raise RuntimeActionBrokerError("runtime capability lease is stale")
        accepted = {
            **claim,
            "profile_claim": {
                **claim["profile_claim"],
                "claimed_at_unix": claimed_at,
            },
        }
        _grant_claim(accepted, claim["grant_digest"])
        state = _load_state(control_fd, config, accepted["grant_digest"])
        if state["status"] != "AVAILABLE":
            raise RuntimeActionBrokerError("runtime capability grant is consumed")
        _require_no_pending_at(control_fd, config)
        _discard_stale_profile_receipt(control_fd, config)
        _publish_state(
            control_fd,
            config,
            {**state, "status": "CLAIMED", "claim": accepted},
        )

    _with_profile_lock(config.broker, deadline, claim_once)
    return accepted


def _consume_grant(
    config: RuntimeActionBrokerV4Config,
    claim: dict[str, Any],
    result: dict[str, Any],
    deadline: float | None,
) -> None:
    def consume(control_fd: int) -> None:
        state = _load_state(control_fd, config, claim["grant_digest"])
        if state["status"] != "CLAIMED" or state["claim"] != claim:
            raise RuntimeActionEffectIndeterminate(
                "runtime capability grant claim changed after mediation"
            )
        _require_no_pending_at(control_fd, config)
        receipt = _load_profile_receipt(control_fd, config)
        result_record = _result_record(claim, receipt)
        if result_record["profile_result"]["broker_result_digest"] != canonical_digest(
            result
        ):
            raise RuntimeActionEffectIndeterminate(
                "runtime capability grant result is unbound"
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
                "runtime create committed but its grant receipt failed"
            ) from exc
        raise


def _abandon_grant(
    config: RuntimeActionBrokerV4Config,
    claim: dict[str, Any],
    deadline: float | None,
) -> None:
    """Make a known pre-effect failure terminal without restoring authority."""

    def abandon(control_fd: int) -> None:
        state = _load_state(control_fd, config, claim["grant_digest"])
        if state["status"] != "CLAIMED" or state["claim"] != claim:
            raise RuntimeActionBrokerError(
                "runtime capability grant claim changed before abandonment"
            )
        _require_no_pending_at(control_fd, config)
        _require_no_profile_receipt_at(control_fd, config)
        _publish_state(
            control_fd,
            config,
            {
                **state,
                "status": "ABANDONED",
                "result": {
                    "schema": "aragorn/runtime-capability-grant-abandonment/v1",
                    "authority": (
                        "BROKER_GRANT_ABANDONMENT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
                    ),
                    "grant_digest": claim["grant_digest"],
                    "lease_digest": claim["lease_digest"],
                    "failure_code": "KNOWN_NO_EFFECT_RUNTIME_BROKER_ERROR",
                },
            },
        )

    _with_profile_lock(config.broker, deadline, abandon)


def _result_record(
    claim: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    profile_result = _profile_result_record(claim["profile_claim"], receipt)
    return {
        "schema": "aragorn/runtime-capability-grant-result/v1",
        "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": claim["grant_digest"],
        "lease_digest": claim["lease_digest"],
        "profile_result": profile_result,
    }


def _expiration_record(grant: dict[str, Any], observed_at_unix: int) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-capability-grant-expiration/v1",
        "authority": "BROKER_GRANT_EXPIRATION_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": canonical_digest(grant),
        "expires_at_unix": grant["expires_at_unix"],
        "observed_at_unix": observed_at_unix,
    }


def _refresh_available_grant(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
    grant: dict[str, Any],
    state: dict[str, Any],
    now_unix: int,
) -> dict[str, Any]:
    if now_unix < grant["expires_at_unix"]:
        _require_live_grant(grant, now_unix)
        return state
    _require_no_pending_at(control_fd, config)
    _require_no_profile_receipt_at(control_fd, config)
    expired = {
        **state,
        "status": "EXPIRED",
        "result": _expiration_record(grant, now_unix),
    }
    _publish_state(control_fd, config, expired)
    return expired


def _require_expiration_matches_grant(
    state: dict[str, Any], grant: dict[str, Any]
) -> None:
    if state["result"]["expires_at_unix"] != grant["expires_at_unix"]:
        raise RuntimeActionBrokerError("runtime capability grant expiration changed")


def _require_live_grant(grant: dict[str, Any], now_unix: int) -> None:
    if grant["issued_at_unix"] > now_unix or now_unix >= grant["expires_at_unix"]:
        raise RuntimeActionBrokerError("runtime capability grant is stale")


def _state(value: object, expected_grant_digest: str) -> dict[str, Any]:
    document = _exact(value, _STATE_FIELDS, "runtime capability grant state")
    if (
        document["schema"] != "aragorn/runtime-capability-grant-state/v1"
        or document["authority"]
        != "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["grant_digest"] != expected_grant_digest
        or document["status"]
        not in {"AVAILABLE", "CLAIMED", "CONSUMED", "ABANDONED", "EXPIRED"}
    ):
        raise RuntimeActionBrokerError("runtime capability grant state is invalid")
    _require_digest(document["grant_digest"], "runtime capability grant digest")
    if document["status"] == "AVAILABLE":
        if document["claim"] is not None or document["result"] is not None:
            raise RuntimeActionBrokerError("runtime capability grant state is invalid")
    elif document["status"] == "EXPIRED":
        if document["claim"] is not None:
            raise RuntimeActionBrokerError("runtime capability grant state is invalid")
        _grant_expiration(document["result"], expected_grant_digest)
    else:
        claim = _grant_claim(document["claim"], expected_grant_digest)
        if document["status"] == "CLAIMED" and document["result"] is not None:
            raise RuntimeActionBrokerError("runtime capability grant state is invalid")
        if document["status"] == "CONSUMED":
            _grant_result(document["result"], claim)
        if document["status"] == "ABANDONED":
            _grant_abandonment(document["result"], claim)
    return document


def _grant_expiration(value: object, expected_grant_digest: str) -> dict[str, Any]:
    document = _exact(
        value,
        _EXPIRATION_FIELDS,
        "runtime capability grant expiration",
    )
    if (
        document["schema"] != "aragorn/runtime-capability-grant-expiration/v1"
        or document["authority"]
        != "BROKER_GRANT_EXPIRATION_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["grant_digest"] != expected_grant_digest
    ):
        raise RuntimeActionBrokerError("runtime capability grant expiration is invalid")
    _require_digest(document["grant_digest"], "runtime capability grant digest")
    expires_at = _uint(
        document["expires_at_unix"],
        "runtime capability grant expiration time",
    )
    observed_at = _uint(
        document["observed_at_unix"],
        "runtime capability grant expiration observation time",
    )
    if observed_at < expires_at:
        raise RuntimeActionBrokerError("runtime capability grant expiration is invalid")
    return document


def _grant_claim(value: object, expected_grant_digest: str) -> dict[str, Any]:
    document = _exact(value, _CLAIM_FIELDS, "runtime capability grant claim")
    if (
        document["schema"] != "aragorn/runtime-capability-grant-claim/v1"
        or document["authority"]
        != "BROKER_GRANT_CLAIM_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["grant_digest"] != expected_grant_digest
    ):
        raise RuntimeActionBrokerError("runtime capability grant claim is invalid")
    _require_digest(document["grant_digest"], "runtime capability grant digest")
    _require_digest(document["lease_digest"], "runtime capability lease digest")
    lease = _exact(document["lease"], _LEASE_FIELDS, "runtime capability lease")
    if (
        lease["schema"] != LEASE_SCHEMA
        or lease["authority"] != LEASE_AUTHORITY
        or canonical_digest(lease) != document["lease_digest"]
        or lease["grant_digest"] != document["grant_digest"]
        or not isinstance(lease["lease_nonce"], str)
        or _NONCE.fullmatch(lease["lease_nonce"]) is None
    ):
        raise RuntimeActionBrokerError("runtime capability grant claim is invalid")
    for field in (
        "grant_digest",
        "submission_digest",
        "runtime_attribution_digest",
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
        _require_digest(lease[field], f"runtime capability lease {field}")
    if _positive_uint(lease["max_actions"], "runtime capability max actions") != 1:
        raise RuntimeActionBrokerError("runtime capability grant claim is invalid")
    _positive_uint(lease["policy_version"], "runtime capability policy version")
    issued = _uint(lease["issued_at_unix"], "runtime capability issue time")
    expires = _uint(lease["expires_at_unix"], "runtime capability expiry")
    profile_claim = _validate_profile_claim(
        document["profile_claim"],
        document["lease_digest"],
    )
    pending = profile_claim["profile_pending"]
    attribution = pending["runtime_attribution"]
    measured = pending["measured_action"]
    if (
        not issued <= profile_claim["claimed_at_unix"] < expires
        or lease["submission_digest"] != profile_claim["submission_digest"]
        or lease["runtime_attribution_digest"]
        != profile_claim["runtime_attribution_digest"]
        or lease["request_digest"] != profile_claim["request_digest"]
        or lease["runtime_profile_digest"] != attribution["profile_digest"]
        or lease["runtime_digest"] != attribution["runtime_digest"]
        or lease["active_skill_digest"] != attribution["active_skill_digest"]
        or any(
            lease[field] != measured[field]
            for field in (
                "runtime_digest",
                "active_skill_digest",
                "operation_digest",
                "path_digest",
                "payload_digest",
            )
        )
    ):
        raise RuntimeActionBrokerError("runtime capability grant claim is unbound")
    return document


def _grant_result(value: object, claim: dict[str, Any]) -> dict[str, Any]:
    document = _exact(value, _RESULT_FIELDS, "runtime capability grant result")
    if (
        document["schema"] != "aragorn/runtime-capability-grant-result/v1"
        or document["authority"]
        != "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["grant_digest"] != claim["grant_digest"]
        or document["lease_digest"] != claim["lease_digest"]
    ):
        raise RuntimeActionBrokerError("runtime capability grant result is invalid")
    _validate_profile_result(document["profile_result"], claim["profile_claim"])
    return document


def _grant_abandonment(value: object, claim: dict[str, Any]) -> dict[str, Any]:
    document = _exact(
        value,
        _ABANDONMENT_FIELDS,
        "runtime capability grant abandonment",
    )
    if (
        document["schema"] != "aragorn/runtime-capability-grant-abandonment/v1"
        or document["authority"]
        != "BROKER_GRANT_ABANDONMENT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        or document["grant_digest"] != claim["grant_digest"]
        or document["lease_digest"] != claim["lease_digest"]
        or document["failure_code"] != "KNOWN_NO_EFFECT_RUNTIME_BROKER_ERROR"
    ):
        raise RuntimeActionBrokerError(
            "runtime capability grant abandonment is invalid"
        )
    return document


def _load_any_state(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
) -> dict[str, Any]:
    raw = _read_owned_bytes_at(
        control_fd,
        config.grant_state_path.name,
        max_bytes=_MAX_STATE_BYTES,
        expected_uid=config.broker.broker.expected_broker_uid,
        exact_mode=0o400,
        label="runtime capability grant state",
    )
    document = _parse_canonical_document(raw, "runtime capability grant state")
    grant_digest = document.get("grant_digest")
    _require_digest(grant_digest, "runtime capability grant digest")
    return _state(document, grant_digest)


def _load_state(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
    expected_grant_digest: str,
) -> dict[str, Any]:
    raw = _read_owned_bytes_at(
        control_fd,
        config.grant_state_path.name,
        max_bytes=_MAX_STATE_BYTES,
        expected_uid=config.broker.broker.expected_broker_uid,
        exact_mode=0o400,
        label="runtime capability grant state",
    )
    return _state(
        _parse_canonical_document(raw, "runtime capability grant state"),
        expected_grant_digest,
    )


def _publish_state(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
    state: dict[str, Any],
) -> None:
    grant_digest = canonical_digest(
        parse_runtime_capability_grant(config.capability_grant)
    )
    document = _state(state, grant_digest)
    _atomic_publish_at(
        control_fd,
        config.grant_state_path.name,
        canonical_json(document),
        expected_uid=config.broker.broker.expected_broker_uid,
    )


def _archive_terminal_state(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
    state: dict[str, Any],
) -> None:
    grant_digest = state["grant_digest"]
    state = _state(state, grant_digest)
    if state["status"] not in _TERMINAL_STATES:
        raise RuntimeActionBrokerError("runtime capability grant is not terminal")
    _require_no_pending_at(control_fd, config)
    if state["status"] == "CONSUMED":
        receipt = _load_profile_receipt(control_fd, config)
        if state["result"] != _result_record(state["claim"], receipt):
            raise RuntimeActionBrokerError(
                "runtime capability grant result changed before archive"
            )
        _publish_immutable_at(
            control_fd,
            _archive_name("profile-receipt", grant_digest),
            canonical_json(receipt),
            config,
            "runtime capability profile receipt archive",
        )
    else:
        _require_no_profile_receipt_at(control_fd, config)
    _publish_immutable_at(
        control_fd,
        _archive_name("state", grant_digest),
        canonical_json(state),
        config,
        "runtime capability grant state archive",
    )


def _archive_name(kind: str, grant_digest: str) -> str:
    _require_digest(grant_digest, "runtime capability grant digest")
    return f"capability-grant-{kind}-{grant_digest.removeprefix('sha256:')}.json"


def _publish_immutable_at(
    control_fd: int,
    name: str,
    raw: bytes,
    config: RuntimeActionBrokerV4Config,
    label: str,
) -> None:
    if not raw or len(raw) > _MAX_STATE_BYTES:
        raise RuntimeActionBrokerError(f"{label} exceeds its byte limit")
    expected_uid = config.broker.broker.expected_broker_uid
    temporary_name: str | None = None
    descriptor = -1
    try:
        temporary_name, descriptor = create_exclusive_file_at(
            control_fd,
            prefix=f".{name}.",
            mode=0o600,
        )
        write_all(descriptor, raw)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != len(raw)
        ):
            raise RuntimeActionBrokerError(f"{label} metadata is unsafe")
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=control_fd,
                dst_dir_fd=control_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            current = _read_immutable_archive_at(
                control_fd,
                name,
                max_bytes=_MAX_STATE_BYTES,
                expected_uid=expected_uid,
                label=label,
            )
            if current != raw:
                raise RuntimeActionBrokerError(f"{label} changed")
        else:
            os.fsync(control_fd)
        os.unlink(temporary_name, dir_fd=control_fd)
        temporary_name = None
        os.fsync(control_fd)
        if (
            _read_owned_bytes_at(
                control_fd,
                name,
                max_bytes=_MAX_STATE_BYTES,
                expected_uid=expected_uid,
                exact_mode=0o400,
                label=label,
            )
            != raw
        ):
            raise RuntimeActionBrokerError(f"{label} changed")
    except OSError as exc:
        raise RuntimeActionBrokerError(f"cannot persist {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=control_fd)
            except FileNotFoundError:
                pass


def _require_fresh_grant(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
    grant_digest: str,
) -> None:
    name = _archive_name("state", grant_digest)
    try:
        raw = _read_immutable_archive_at(
            control_fd,
            name,
            max_bytes=_MAX_STATE_BYTES,
            expected_uid=config.broker.broker.expected_broker_uid,
            label="runtime capability grant state archive",
        )
    except FileNotFoundError:
        return
    archived = _state(
        _parse_canonical_document(raw, "runtime capability grant state archive"),
        grant_digest,
    )
    if archived["status"] not in _TERMINAL_STATES:
        raise RuntimeActionBrokerError(
            "runtime capability grant state archive is not terminal"
        )
    raise RuntimeActionBrokerError("runtime capability grant is already terminal")


def _read_immutable_archive_at(
    control_fd: int,
    name: str,
    *,
    max_bytes: int,
    expected_uid: int,
    label: str,
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=control_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > max_bytes
        ):
            raise RuntimeActionBrokerError(f"{label} metadata is unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, min(8192, max_bytes + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise RuntimeActionBrokerError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _file_identity(before) != _file_identity(after) or len(raw) != after.st_size:
        raise RuntimeActionBrokerError(f"{label} changed while read")
    content = bytes(raw)
    if after.st_nlink == 2:
        _remove_abandoned_archive_stage(control_fd, name, after, label)
        if (
            _read_owned_bytes_at(
                control_fd,
                name,
                max_bytes=max_bytes,
                expected_uid=expected_uid,
                exact_mode=0o400,
                label=label,
            )
            != content
        ):
            raise RuntimeActionBrokerError(f"{label} changed after recovery")
    return content


def _remove_abandoned_archive_stage(
    control_fd: int,
    name: str,
    archive: os.stat_result,
    label: str,
) -> None:
    prefix = f".{name}."
    matches = []
    with os.scandir(control_fd) as entries:
        for entry in entries:
            suffix = entry.name.removeprefix(prefix)
            if (
                entry.name.startswith(prefix)
                and len(suffix) == 24
                and all(character in "0123456789abcdef" for character in suffix)
            ):
                metadata = entry.stat(follow_symlinks=False)
                if (metadata.st_dev, metadata.st_ino) == (
                    archive.st_dev,
                    archive.st_ino,
                ):
                    matches.append(entry.name)
    if len(matches) != 1:
        raise RuntimeActionBrokerError(f"{label} staging recovery is ambiguous")
    os.unlink(matches[0], dir_fd=control_fd)
    os.fsync(control_fd)


def _require_no_profile_receipt_at(
    control_fd: int,
    config: RuntimeActionBrokerV4Config,
) -> None:
    try:
        os.stat(
            config.broker.profile_receipt_path.name,
            dir_fd=control_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise RuntimeActionBrokerError("an unexpected runtime profile receipt exists")


def _validate_config(config: RuntimeActionBrokerV4Config) -> dict[str, Any]:
    if not isinstance(config, RuntimeActionBrokerV4Config):
        raise RuntimeActionBrokerError(
            "runtime capability grant broker configuration is invalid"
        )
    _validate_v2_config(config.broker)
    grant = parse_runtime_capability_grant(config.capability_grant)
    broker = config.broker.broker
    if (
        config.grant_state_path.parent != broker.control_root
        or config.grant_state_path.name != "capability-grant-state.json"
        or config.grant_state_path
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
        or grant["runtime_profile_digest"]
        != config.broker.expected_runtime_profile_digest
        or grant["runtime_digest"] != broker.expected_runtime_digest
    ):
        raise RuntimeActionBrokerError(
            "runtime capability grant broker configuration is invalid"
        )
    return grant
