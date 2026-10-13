"""Bounded structural broker/reader packets; never an acquisition or health gate."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid


REQUEST_LIMIT = 4096
RESPONSE_LIMIT = 262144
ERROR_CODES = frozenset({
    "INPUT_REFUSED", "IDENTITY_CHANGED", "CLOCK_REFUSED", "DEADLINE_EXPIRED",
    "READER_UNAVAILABLE", "READER_REFUSED", "LOSS_UNAVAILABLE",
    "CHECKPOINT_UNAVAILABLE", "RETENTION_FAILED", "CLEANUP_FAILED",
    "PROTOCOL_REFUSED", "INTERNAL_REFUSAL",
})
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_ECHO = ("exchange_id", "phase", "context_digest", "epoch_digest",
         "request_digest", "effect_digest")
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
          "effect_authorized", "run_qualified", "phase3_qualified")
_BINDINGS = ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("nonfinite JSON value")


def _decode(raw: bytes, maximum: int) -> object:
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "JSON byte bound")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
        _require(_canonical(value) == raw, "noncanonical JSON")
        return value
    except (UnicodeError, RecursionError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError("invalid bounded canonical JSON") from exc


def _keys(value: object, keys) -> None:
    _require(type(value) is dict and set(value) == set(keys), "unexpected record fields")


def _uint(value: object, minimum: int = 0, maximum: int = 2**63 - 1) -> None:
    _require(type(value) is int and minimum <= value <= maximum, "invalid uint")


def _pin(value: object) -> None:
    _require(type(value) is str and _PIN.fullmatch(value) is not None, "invalid pin")


def _nonce(value: object) -> None:
    _require(type(value) is str and _NONCE.fullmatch(value) is not None, "invalid nonce")


def _process(value: object) -> None:
    _keys(value, ("pid", "start_time_ticks", "uid", "gid"))
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    for key in ("uid", "gid"):
        _uint(value[key], 0, 4294967295)


def _clock(value: object) -> None:
    _keys(value, ("boot_id", "clock_id", "time_namespace"))
    _require(type(value["boot_id"]) is str and len(value["boot_id"]) == 36,
             "invalid boot identity")
    try:
        _require(str(uuid.UUID(value["boot_id"])) == value["boot_id"], "invalid boot identity")
    except (ValueError, AttributeError) as exc:
        raise ValueError("invalid boot identity") from exc
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "invalid clock identifier")
    _keys(value["time_namespace"], ("device", "inode"))
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


def _artifact(value: object, maximum: int) -> bytes | None:
    if value is None:
        return None
    _keys(value, ("base64", "bytes", "digest"))
    _uint(value["bytes"], 1, maximum)
    _pin(value["digest"])
    encoded = value["base64"]
    _require(type(encoded) is str and len(encoded) <= 4 * ((maximum + 2) // 3),
             "base64 byte bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid artifact base64") from exc
    _require(0 < len(raw) <= maximum and len(raw) == value["bytes"]
             and base64.b64encode(raw).decode("ascii") == encoded
             and _digest(raw) == value["digest"], "artifact bytes differ")
    return raw


def _loss(raw: bytes, bindings: dict | None) -> dict:
    value = _decode(raw, 8192)
    _keys(value, ("epoch_digest", "challenge_digest", "request_digest", "scope_digest",
                  "before", "after"))
    _require(bindings is not None, "loss bindings unavailable")
    for key, bound in (("epoch_digest", "epoch"), ("challenge_digest", "challenge"),
                       ("request_digest", "request"), ("scope_digest", "loss_scope")):
        _pin(value[key])
        _require(value[key] == bindings[bound], "loss binding differs")
    for name in ("before", "after"):
        sample = value[name]
        if sample is None:
            continue
        _keys(sample, ("start_ns", "end_ns", "counters"))
        _uint(sample["start_ns"])
        _uint(sample["end_ns"])
        _require(sample["start_ns"] <= sample["end_ns"], "reversed loss sample")
        counters = sample["counters"]
        _require(type(counters) is list and 1 <= len(counters) <= 32, "loss counter bound")
        for counter in counters:
            if counter is not None:
                _uint(counter)
    if value["before"] is not None and value["after"] is not None:
        _require(len(value["before"]["counters"]) == len(value["after"]["counters"]),
                 "loss counter lengths differ")
    return value


def validate_guard_request(raw: bytes) -> dict:
    """Return a detached packet after structural validation, without authority."""
    value = _decode(raw, REQUEST_LIMIT)
    _keys(value, ("schema", *_ECHO, "deadline_boottime_ns", "previous_response_digest"))
    _require(value["schema"] == "aragorn/native-phase3-broker-reader-request/v1",
             "request schema differs")
    _nonce(value["exchange_id"])
    for name in ("context_digest", "epoch_digest", "request_digest", "effect_digest"):
        _pin(value[name])
    _uint(value["deadline_boottime_ns"], 1)
    phase = value["phase"]
    _require(phase in ("BEFORE_CONNECT", "BEFORE_PAYLOAD_SEND"), "invalid request phase")
    if phase == "BEFORE_CONNECT":
        _require(value["previous_response_digest"] is None, "unexpected previous response")
    else:
        _pin(value["previous_response_digest"])
    return value


def validate_guard_response(raw: bytes, *, request_raw: bytes) -> dict:
    """Validate bounded original bytes and joins; acquired facts remain unverified."""
    request = validate_guard_request(request_raw)
    value = _decode(raw, RESPONSE_LIMIT)
    _keys(value, ("schema", "request_packet_digest", *_ECHO, "received_ns", "finished_ns",
                  "status", "error_codes", "reader_connection_epoch", "bindings",
                  "reader_evidence", "reader_summary", "reader_retention", "loss_record",
                  "checkpoint_record", *_FLAGS))
    _require(value["schema"] == "aragorn/native-phase3-broker-reader-response/v1",
             "response schema differs")
    _require(value["request_packet_digest"] == _digest(request_raw)
             and all(value[key] == request[key] for key in _ECHO), "response request differs")
    _require(all(value[key] is False for key in _FLAGS), "unsupported authority claim")
    _uint(value["received_ns"])
    _uint(value["finished_ns"])
    _require(value["received_ns"] <= value["finished_ns"], "reversed response time")
    codes = value["error_codes"]
    _require(type(codes) is list and len(codes) <= 8
             and all(type(code) is str and code in ERROR_CODES for code in codes),
             "invalid response errors")
    _require(codes == sorted(set(codes)), "noncanonical response errors")
    _require(value["status"] in ("EVIDENCE", "REFUSED"), "invalid response status")
    _require((value["status"] == "EVIDENCE") == (len(codes) == 0), "status errors differ")
    if value["reader_connection_epoch"] is not None:
        _nonce(value["reader_connection_epoch"])
    bindings = value["bindings"]
    if bindings is not None:
        _keys(bindings, _BINDINGS)
        for pin in bindings.values():
            _pin(pin)
        _require(bindings["epoch"] == request["epoch_digest"]
                 and bindings["request"] == request["request_digest"], "reader binding differs")
    evidence = _artifact(value["reader_evidence"], 131072)
    _artifact(value["reader_summary"], 32768)
    loss = _artifact(value["loss_record"], 8192)
    _artifact(value["checkpoint_record"], 16384)
    if loss is not None:
        _loss(loss, bindings)
    retention = value["reader_retention"]
    if retention is not None:
        _keys(retention, ("digest", "bytes"))
        _pin(retention["digest"])
        _uint(retention["bytes"], 1, 131072)
        _require(evidence is not None and retention["digest"] == _digest(evidence)
                 and retention["bytes"] == len(evidence), "reader retention differs")
    if value["status"] == "EVIDENCE":
        _require(all(value[key] is not None for key in (
            "reader_evidence", "reader_summary", "reader_retention", "loss_record",
            "checkpoint_record", "bindings", "reader_connection_epoch")), "missing evidence item")
    return value
