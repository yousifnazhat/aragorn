"""Best-effort journal observations for three fixed runtime Unix endpoints.

These records describe transport and locally verified results, not semantic
causation, decision latency, durable retention, or RUN qualification. No request
bytes, credential values, exception text, or caller-selected paths are emitted.
"""

from __future__ import annotations

import contextvars
import functools
import os
import re
import secrets
import socket
import sys
from collections.abc import Callable
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json

_SCHEMA = "aragorn/runtime-endpoint-journal-event/v1"
_AUTHORITY = (
    "LOCAL_ENDPOINT_OBSERVATION_NOT_CAUSATION_DURABLE_RETENTION_OR_RUN_AUTHORITY"
)
_MAX_BYTES = 4096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ROLES = {"worker", "sensor", "broker"}
_STAGES = {
    "PEER",
    "FRAME",
    "REQUEST",
    "PROFILE",
    "BACKEND_CONNECT",
    "FORWARD",
    "CORE",
    "RESULT",
    "CLIENT_DELIVERY",
}
_ENUMS = {
    "role": _ROLES,
    "phase": {"START", "TERMINAL"},
    "stage": _STAGES,
    "request_state": {"UNAVAILABLE", "CANONICAL_FRAME_ONLY", "VALIDATED"},
    "submission": {"NOT_STARTED", "SEND_ATTEMPTED", "CORE_ENTERED"},
    "result_kind": {"NONE", "CANONICAL_REPLY_ONLY", "VALIDATED_BROKER_RESULT"},
    "worker_status": {None, "COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"},
    "client_delivery": {"NOT_STARTED", "SEND_ATTEMPTED", "FRAME_SENT_NOT_ACKNOWLEDGED"},
    "handler_status": {"RUNNING", "RETURNED", "RAISED"},
    "outcome": {
        "CONNECTION_OBSERVED",
        "REJECTED_BEFORE_SUBMISSION",
        "REJECTED_BEFORE_EFFECT",
        "BROKER_RESULT_OBSERVED",
        "REPLY_RELAYED_EFFECT_UNVERIFIED",
        "INDETERMINATE",
    },
}
_DIGEST_FIELDS = {
    "worker_request_digest",
    "action_request_digest",
    "profile_attribution_digest",
    "result_digest",
}
_FIELDS = {
    "schema",
    "authority",
    "attempt_id",
    "peer",
    "peer_expected",
    "verdict",
    "effect_status",
    *_ENUMS,
    *_DIGEST_FIELDS,
}
_CURRENT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "runtime_endpoint_journal_attempt", default=None
)


def _valid_event(document: object) -> bool:
    if (
        type(document) is not dict
        or set(document) != _FIELDS
        or document["schema"] != _SCHEMA
        or document["authority"] != _AUTHORITY
        or type(document["attempt_id"]) is not str
        or re.fullmatch(r"[0-9a-f]{32}", document["attempt_id"]) is None
        or type(document["peer_expected"]) is not bool
    ):
        return False
    if any(document[key] not in values for key, values in _ENUMS.items()):
        return False
    if any(
        document[key] is not None
        and (type(document[key]) is not str or _DIGEST.fullmatch(document[key]) is None)
        for key in _DIGEST_FIELDS
    ):
        return False
    peer = document["peer"]
    if peer is None:
        if document["peer_expected"]:
            return False
    elif (
        type(peer) is not dict
        or set(peer) != {"pid", "uid", "gid"}
        or any(
            type(value) is not int or value < 0 or value >= 2**63
            for value in peer.values()
        )
        or peer["pid"] == 0
    ):
        return False
    action = document["action_request_digest"]
    worker = document["worker_request_digest"]
    if (document["request_state"] == "VALIDATED") != (
        action is not None or worker is not None
    ):
        return False
    if (worker is not None or document["worker_status"] is not None) and document[
        "role"
    ] != "worker":
        return False
    if document["profile_attribution_digest"] is not None and action is None:
        return False
    if document["result_kind"] == "VALIDATED_BROKER_RESULT":
        if (
            action is None
            or document["result_digest"] is None
            or document["role"] == "sensor"
            or (document["verdict"], document["effect_status"])
            not in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}
        ):
            return False
    elif document["verdict"] is not None or document["effect_status"] is not None:
        return False
    elif document["result_kind"] == "CANONICAL_REPLY_ONLY":
        if document["role"] != "sensor" or document["result_digest"] is None:
            return False
    elif document["result_digest"] is not None:
        return False
    return True


def emit_journal_event(document: dict[str, Any], *, descriptor: int = 1) -> bool:
    """Try one nonblocking send on a duplicate of an existing Unix stream.

    No connect, retry, buffering, descriptor-flag change, or durability claim.
    Unsupported descriptors and partial/full/broken output are telemetry loss.
    Even a diagnostic interruption must not replace an in-flight core exception.
    """
    duplicate = -1
    stream: socket.socket | None = None
    try:
        if sys.platform != "linux":
            return False
        if not _valid_event(document):
            return False
        if type(descriptor) is not int or descriptor < 0:
            return False
        if not hasattr(socket, "MSG_DONTWAIT") or not hasattr(socket, "MSG_NOSIGNAL"):
            return False
        # socket(fileno=...) adopts the process-wide default timeout and can
        # otherwise set O_NONBLOCK on the shared open-file description.
        if socket.getdefaulttimeout() is not None:
            return False
        raw = canonical_json(document) + b"\n"
        if len(raw) > _MAX_BYTES:
            return False
        duplicate = os.dup(descriptor)
        stream = socket.socket(fileno=duplicate)
        duplicate = -1  # The socket now owns only the duplicate.
        if stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM:
            return False
        stream.getpeername()  # Refuse unconnected sockets; never open a connection.
        return stream.send(raw, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(raw)
    except BaseException:  # noqa: BLE001 - diagnostics cannot change mediation
        return False
    finally:
        try:
            if stream is not None:
                stream.close()
            elif duplicate >= 0:
                os.close(duplicate)
        except BaseException:  # noqa: BLE001, S110 - preserve the original outcome
            pass


def _new(role: str) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "role": role,
        "attempt_id": secrets.token_hex(16),
        "phase": "START",
        "stage": "PEER",
        "peer": None,
        "peer_expected": False,
        "request_state": "UNAVAILABLE",
        "worker_request_digest": None,
        "action_request_digest": None,
        "profile_attribution_digest": None,
        "submission": "NOT_STARTED",
        "result_kind": "NONE",
        "result_digest": None,
        "verdict": None,
        "effect_status": None,
        "worker_status": None,
        "client_delivery": "NOT_STARTED",
        "handler_status": "RUNNING",
        "outcome": "CONNECTION_OBSERVED",
    }


def _emit(document: dict[str, Any]) -> None:
    try:
        emit_journal_event(document)
    except BaseException:  # noqa: BLE001, S110 - isolate diagnostic sinks
        pass


def endpoint(
    role: str,
    pre_effect_error: type[Exception] | None = None,
    indeterminate_error: type[Exception] | None = None,
) -> Callable:
    """Observe one existing handler without changing its arguments or errors."""
    if role not in _ROLES:
        raise ValueError("unsupported fixed endpoint role")

    def decorate(function: Callable) -> Callable:
        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                document = _new(role)
                token = _CURRENT.set(document)
            except BaseException:  # noqa: BLE001 - unavailable telemetry is inert
                return function(*args, **kwargs)
            _emit(document)
            failure: BaseException | None = None
            try:
                return function(*args, **kwargs)
            except BaseException as exc:
                failure = exc
                raise
            finally:
                try:
                    document["phase"] = "TERMINAL"
                    document["handler_status"] = "RAISED" if failure else "RETURNED"
                    if document["result_kind"] == "VALIDATED_BROKER_RESULT":
                        outcome = "BROKER_RESULT_OBSERVED"
                    elif document["submission"] == "NOT_STARTED":
                        outcome = "REJECTED_BEFORE_SUBMISSION"
                    elif (
                        role == "broker"
                        and pre_effect_error is not None
                        and isinstance(failure, pre_effect_error)
                        and not (
                            indeterminate_error is not None
                            and isinstance(failure, indeterminate_error)
                        )
                    ):
                        outcome = "REJECTED_BEFORE_EFFECT"
                    elif (
                        document["result_kind"] == "CANONICAL_REPLY_ONLY"
                        and failure is None
                    ):
                        outcome = "REPLY_RELAYED_EFFECT_UNVERIFIED"
                    else:
                        outcome = "INDETERMINATE"
                    document["outcome"] = outcome
                    _emit(document)
                except BaseException:  # noqa: BLE001, S110 - preserve return/exception
                    pass
                finally:
                    try:
                        _CURRENT.reset(token)
                    except BaseException:  # noqa: BLE001, S110 - diagnostics only
                        pass

        return wrapped

    return decorate


def note(kind: str, value: Any = None) -> None:
    """Record only fixed projections at source-pinned validation boundaries."""
    try:
        document = _CURRENT.get()
        if document is None:
            return
        if kind == "stage" and value in _STAGES:
            document["stage"] = value
        elif kind == "peer":
            if (
                type(value) is tuple
                and len(value) == 3
                and all(type(item) is int and item >= 0 for item in value)
                and value[0] > 0
            ):
                document["peer"] = dict(zip(("pid", "uid", "gid"), value, strict=True))
        elif kind == "peer_expected":
            if document["peer"] is not None:
                document["peer_expected"] = True
        elif kind == "frame":
            document["request_state"] = "CANONICAL_FRAME_ONLY"
        elif kind == "worker_request":
            document["worker_request_digest"] = canonical_digest(value)
            document["request_state"] = "VALIDATED"
        elif kind == "action_document":
            note("action_request", canonical_digest(value["request"]))
        elif kind == "validated_submission":
            note("action_request", value["request_digest"])
        elif kind == "action_request":
            if type(value) is str and _DIGEST.fullmatch(value):
                document["action_request_digest"] = value
                document["request_state"] = "VALIDATED"
        elif kind == "profile":
            if document["action_request_digest"] is not None:
                document["profile_attribution_digest"] = canonical_digest(value)
        elif kind == "submit":
            document["submission"] = (
                "CORE_ENTERED" if document["role"] == "broker" else "SEND_ATTEMPTED"
            )
        elif kind == "reply":
            document["result_digest"] = canonical_digest(value)
            document["result_kind"] = "CANONICAL_REPLY_ONLY"
        elif kind == "broker_result":
            if (
                type(value) is dict
                and value.get("request_digest") == document["action_request_digest"]
                and document["action_request_digest"] is not None
                and (value.get("verdict"), value.get("effect_status"))
                in {("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED")}
            ):
                document["result_digest"] = canonical_digest(value)
                document["result_kind"] = "VALIDATED_BROKER_RESULT"
                document["verdict"] = value["verdict"]
                document["effect_status"] = value["effect_status"]
        elif kind == "worker_result":
            status = value["status"]
            if status in {"COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"}:
                document["worker_status"] = status
        elif kind == "delivery_attempt":
            document["stage"] = "CLIENT_DELIVERY"
            document["client_delivery"] = "SEND_ATTEMPTED"
        elif kind == "delivery_sent":
            document["client_delivery"] = "FRAME_SENT_NOT_ACKNOWLEDGED"
    except BaseException:  # noqa: BLE001, S110 - telemetry cannot authorize
        pass
