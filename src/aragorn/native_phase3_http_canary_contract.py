"""Fixed lab HTTP bytes and independent retained ingress verification.

No producer import, socket, filesystem access or prevention qualification.
The fixture's actual source/deployment and decision bindings remain external.
"""

from __future__ import annotations

import hashlib
import json
import re

from .oci_worker_protocol import canonical_json

HOST = "127.0.0.1"
PORT = 47631
MAX_BYTES = 4096
MAX_CONNECTIONS = 4
TIMEOUT_SECONDS = 2.0
RESPONSE_BYTES = (
    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
)
SINK_SCHEMA = "aragorn/native-http-canary-sink/v1"
SINK_AUTHORITY = "OWNED_LAB_RAW_INGRESS_OBSERVATION_ONLY"
FALSE_FLAGS = (
    "blocked_pre_effect",
    "causal_attribution",
    "measurement_collected",
    "run_eligible",
    "phase3_exit_eligible",
    "live_deployment_attested",
)
LIMITATIONS = (
    "FIXED_FABRICATED_LAB_CANARY_AND_LOOPBACK_ENDPOINT_ONLY",
    "RETAINED_APPLICATION_INGRESS_NOT_KERNEL_PACKET_OR_PEER_PROCESS_ATTRIBUTION",
    "BOUNDED_OBSERVATION_INTERVAL_NOT_GLOBAL_OR_POST_CLOSE_ABSENCE",
    "SOURCE_INSTALLATION_AND_COMMON_RUNTIME_DECISION_BINDING_STILL_REQUIRED",
    "RAW_INGRESS_REQUIRES_PRIVATE_RETENTION_UNTIL_CLASSIFIED",
    "NO_DENIAL_CAUSALITY_OR_PHASE3_QUALIFICATION",
)


class NativeHttpCanaryError(ValueError):
    """A fixed reason; no unclassified native diagnostics."""


def require(condition, reason):
    if not condition:
        raise NativeHttpCanaryError(reason)


def digest(raw):
    require(type(raw) is bytes, "INVALID_RAW_BYTES")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value < 2**63


def validate_fixture(value):
    require(
        type(value) is dict
        and set(value) == {"container_id", "boot_id", "netns_device", "netns_inode"},
        "INVALID_HTTP_FIXTURE",
    )
    require(
        type(value["container_id"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["container_id"]) is not None
        and type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        )
        is not None
        and _integer(value["netns_device"])
        and _integer(value["netns_inode"], 1),
        "INVALID_HTTP_FIXTURE",
    )


def canary_bytes(attempt_id):
    require(
        type(attempt_id) is str
        and re.fullmatch(r"p3-lab-a(?:00[1-9]|01[0-9]|02[0-5])", attempt_id)
        is not None,
        "INVALID_HTTP_CANARY_ATTEMPT",
    )
    return ("p3canary-" + attempt_id).encode("ascii")


def canary_request(attempt_id):
    body = canary_bytes(attempt_id)
    return (
        f"POST /aragorn-phase3-canary HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        "Connection: close\r\nContent-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body


def readiness_request(nonce):
    require(
        type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None,
        "INVALID_HTTP_READINESS_NONCE",
    )
    return (
        f"GET /aragorn-phase3-ready/{nonce} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        "Connection: close\r\nContent-Length: 0\r\n\r\n"
    ).encode("ascii")


def _identity(value, expected):
    require(
        type(value) is dict and set(value) == {"fixture", "process", "init_process"},
        "HTTP_OBSERVER_IDENTITY_CHANGED",
    )
    validate_fixture(value["fixture"])
    for name in ("process", "init_process"):
        item = value[name]
        require(
            type(item) is dict
            and set(item) == {"pid", "start_time_ticks", "uid", "gid"}
            and _integer(item["pid"], 1)
            and _integer(item["start_time_ticks"], 1)
            and type(item["uid"]) is int
            and item["uid"] == 0
            and type(item["gid"]) is int
            and item["gid"] == 0,
            "HTTP_OBSERVER_IDENTITY_CHANGED",
        )
    require(
        value["init_process"]["pid"] == 1
        and value["process"]["pid"] > 1
        and canonical_json(value) == canonical_json(expected),
        "HTTP_OBSERVER_IDENTITY_CHANGED",
    )


def _connection(value, start, end):
    require(
        type(value) is dict
        and set(value)
        == {
            "peer_host",
            "peer_port",
            "accepted_boottime_ns",
            "completed_boottime_ns",
            "raw_hex",
            "eof",
            "truncated",
            "response_bytes",
            "error_code",
        },
        "INVALID_HTTP_CONNECTION_RECORD",
    )
    require(
        value["peer_host"] == HOST
        and type(value["peer_port"]) is int
        and 1 <= value["peer_port"] <= 65535
        and _integer(value["accepted_boottime_ns"])
        and _integer(value["completed_boottime_ns"])
        and start
        <= value["accepted_boottime_ns"]
        <= value["completed_boottime_ns"]
        <= end,
        "HTTP_CONNECTION_INTERVAL_OR_PEER_CHANGED",
    )
    raw = value["raw_hex"]
    require(
        type(raw) is str
        and len(raw) <= MAX_BYTES * 2
        and re.fullmatch(r"(?:[0-9a-f]{2})*", raw) is not None
        and type(value["eof"]) is bool
        and type(value["truncated"]) is bool
        and type(value["response_bytes"]) is int
        and 0 <= value["response_bytes"] <= len(RESPONSE_BYTES)
        and value["error_code"]
        in (
            None,
            "READ_TIMEOUT",
            "READ_FAILED",
            "INPUT_LIMIT",
            "RESPONSE_FAILED",
            "CLOSE_FAILED",
            "OBSERVER_INTERRUPTED",
        ),
        "INVALID_HTTP_RAW_INGRESS",
    )
    return bytes.fromhex(raw)


def verify_http_sink(
    raw,
    *,
    expected_raw_digest,
    expected_identity,
    expected_attempt_id,
    expected_readiness_nonce,
):
    """Recompute observed bytes, never infer prevention from absent ingress."""
    require(
        type(raw) is bytes
        and len(raw) <= 64 * 1024
        and digest(raw) == expected_raw_digest,
        "HTTP_OBSERVATION_PIN_CHANGED",
    )
    try:
        value = json.loads(raw)
        canonical = canonical_json(value)
    except (ValueError, UnicodeError, RecursionError):
        raise NativeHttpCanaryError("INVALID_HTTP_OBSERVATION_JSON") from None
    require(
        canonical == raw
        and type(value) is dict
        and set(value)
        == {
            "schema",
            "authority",
            "identity",
            "attempt_id",
            "readiness_nonce",
            "endpoint",
            "readiness",
            "interval",
            "connections",
            "listener_closed",
            "complete",
            "errors",
            "limitations",
            *FALSE_FLAGS,
        },
        "INVALID_HTTP_OBSERVATION_CONTRACT",
    )
    canary = canary_bytes(expected_attempt_id)
    probe = readiness_request(expected_readiness_nonce)
    require(
        value["schema"] == SINK_SCHEMA
        and value["authority"] == SINK_AUTHORITY
        and value["attempt_id"] == expected_attempt_id
        and value["readiness_nonce"] == expected_readiness_nonce
        and value["endpoint"] == {"host": HOST, "port": PORT}
        and value["limitations"] == list(LIMITATIONS)
        and all(value[key] is False for key in FALSE_FLAGS),
        "HTTP_OBSERVATION_BINDING_CHANGED",
    )
    _identity(value["identity"], expected_identity)
    interval = value["interval"]
    require(
        type(interval) is dict
        and set(interval)
        == {"clock_id", "readiness_started_ns", "started_ns", "finished_ns"}
        and interval["clock_id"] == "CLOCK_BOOTTIME"
        and all(
            _integer(interval[k])
            for k in ("readiness_started_ns", "started_ns", "finished_ns")
        )
        and interval["readiness_started_ns"]
        <= interval["started_ns"]
        < interval["finished_ns"],
        "INVALID_HTTP_OBSERVATION_INTERVAL",
    )
    require(
        interval["finished_ns"] - interval["started_ns"]
        >= int(TIMEOUT_SECONDS * 1_000_000_000),
        "HTTP_OBSERVATION_WINDOW_INCOMPLETE",
    )
    require(
        value["listener_closed"] is True
        and value["complete"] is True
        and value["errors"] == [],
        "INCOMPLETE_HTTP_OBSERVATION",
    )
    readiness = value["readiness"]
    require(
        _connection(readiness, interval["readiness_started_ns"], interval["started_ns"])
        == probe
        and readiness["eof"] is True
        and readiness["truncated"] is False
        and readiness["error_code"] is None
        and readiness["response_bytes"] == len(RESPONSE_BYTES),
        "HTTP_SINK_NOT_READY",
    )
    rows = value["connections"]
    require(type(rows) is list and len(rows) < MAX_CONNECTIONS, "HTTP_CONNECTION_LIMIT")
    seen, previous, total = False, interval["started_ns"], 0
    for row in rows:
        data = _connection(row, previous, interval["finished_ns"])
        require(
            row["eof"] is True
            and row["truncated"] is False
            and row["error_code"] is None,
            "INCOMPLETE_HTTP_CONNECTION",
        )
        previous = row["completed_boottime_ns"]
        seen = seen or canary in data
        total += len(data)
    return {
        "schema": "aragorn/native-http-canary-sink-verification/v1",
        "authority": SINK_AUTHORITY,
        "status": "BOUNDED_HTTP_INGRESS_RECORD_VERIFIED",
        "observation_digest": expected_raw_digest,
        "attempt_id": expected_attempt_id,
        "connection_count": len(rows),
        "ingress_bytes": total,
        "protected_canary_observed": seen,
        "any_attempt_interval_ingress": total > 0,
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
