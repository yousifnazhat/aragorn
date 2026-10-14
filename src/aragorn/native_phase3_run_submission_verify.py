"""Independent bounded submission replay; retained bytes cannot attest OS custody."""
from __future__ import annotations

import base64
import hashlib
import json
import re

_PREFIX = "aragorn/native-phase3-"
_MAX_TOTAL = 786432
_MAX_AGE = 200000000
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
          "effect_authorized", "run_qualified", "phase3_qualified")
_ERRORS = frozenset(("INPUT_REFUSED", "IDENTITY_CHANGED", "CLOCK_REFUSED",
                    "DEADLINE_EXPIRED", "READER_UNAVAILABLE", "READER_REFUSED",
                    "LOSS_UNAVAILABLE", "CHECKPOINT_UNAVAILABLE", "RETENTION_FAILED",
                    "CLEANUP_FAILED", "PROTOCOL_REFUSED", "INTERNAL_REFUSAL"))
_TERMINAL_ERRORS = _ERRORS | {"POLICY_REFUSED", "TRANSPORT_REFUSED",
                             "TRANSPORT_INDETERMINATE", "JOURNAL_REFUSED"}
_ARROWS = {
    "BOUND": ("CONNECT_CHECKED", "TERMINAL"),
    "CONNECT_CHECKED": ("CONNECT_INTENT", "TERMINAL"),
    "CONNECT_INTENT": ("PAYLOAD_CHECKED", "TERMINAL"),
    "PAYLOAD_CHECKED": ("PAYLOAD_INTENT", "TERMINAL"),
    "PAYLOAD_INTENT": ("TERMINAL",), "TERMINAL": (),
}
_ECHOES = ("exchange_id", "phase", "context_digest", "epoch_digest",
           "request_digest", "effect_digest")
_IMMUTABLE_READER = ("reader_connection_epoch", "bindings", "reader_evidence",
                     "reader_summary", "reader_retention")


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names), "FIELD_INVENTORY")


def _uint(value, minimum=0, maximum=2**63 - 1):
    _require(type(value) is int and minimum <= value <= maximum, "UINT")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "PIN")


def _nonce(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "NONCE")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _parse(raw, limit):
    _require(type(raw) is bytes and 0 < len(raw) <= limit and raw.isascii(), "RAW_BOUND")

    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result, "DUPLICATE_KEY")
            result[name] = value
        return result

    def constant(_):
        raise ValueError("NONFINITE")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        _require(_canonical(value) == raw, "NONCANONICAL_JSON")
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError("JSON_REFUSED") from error
    _require(type(value) is dict, "RECORD_OBJECT")
    return value


def _process(value):
    _fields(value, ("pid", "start_time_ticks", "uid", "gid"))
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    _uint(value["uid"], 0, 4294967295)
    _uint(value["gid"], 0, 4294967295)


def _clock(value):
    _fields(value, ("boot_id", "clock_id", "time_namespace"))
    _require(type(value["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "BOOT_ID")
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "CLOCK_ID")
    namespace = value["time_namespace"]
    _fields(namespace, ("device", "inode"))
    _uint(namespace["device"])
    _uint(namespace["inode"], 1)


def _context(raw, expected_digest, expected_request, broker, provider, clock):
    _pin(expected_digest)
    _pin(expected_request)
    _process(broker)
    _process(provider)
    _clock(clock)
    value = _parse(raw, 8192)
    _require(_digest(raw) == expected_digest, "CONTEXT_PIN")
    _fields(value, ("schema", "request_digest", "effect_digest", "grant_digest",
                    "deployment_digest", "epoch_digest", "broker", "provider", "clock",
                    "exchange_id", "accepted_boottime_ns", "deadline_boottime_ns", "clock_bracket"))
    _require(value["schema"] == _PREFIX + "broker-reader-context/v1", "CONTEXT_SCHEMA")
    for key in ("request_digest", "effect_digest", "grant_digest", "deployment_digest", "epoch_digest"):
        _pin(value[key])
    _nonce(value["exchange_id"])
    _process(value["broker"])
    _process(value["provider"])
    _clock(value["clock"])
    _require(value["request_digest"] == expected_request and value["broker"] == broker
             and value["provider"] == provider and value["clock"] == clock, "HELD_IDENTITY_JOIN")
    _require(broker["uid"] > 0 and broker["gid"] > 0
             and provider["uid"] == provider["gid"] == 0
             and broker["pid"] != provider["pid"], "ACCOUNT_JOIN")
    accepted = _uint(value["accepted_boottime_ns"])
    deadline = _uint(value["deadline_boottime_ns"], 1)
    bracket = value["clock_bracket"]
    _fields(bracket, ("boottime_before_ns", "monotonic_ns", "boottime_after_ns",
                      "original_monotonic_deadline_ns"))
    for number in bracket.values():
        _uint(number)
    before, after = bracket["boottime_before_ns"], bracket["boottime_after_ns"]
    remaining = bracket["original_monotonic_deadline_ns"] - bracket["monotonic_ns"]
    _require(0 < remaining <= 500000000 and accepted <= before <= after < deadline
             and deadline == before + remaining, "CLOCK_BUDGET")
    return value


def _artifact(value, limit):
    if value is None:
        return None
    _fields(value, ("base64", "bytes", "digest"))
    _uint(value["bytes"], 1, limit)
    _pin(value["digest"])
    encoded = value["base64"]
    _require(type(encoded) is str and len(encoded) <= ((limit + 2) // 3) * 4, "BASE64_BOUND")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as error:
        raise ValueError("BASE64_REFUSED") from error
    _require(0 < len(decoded) <= limit and len(decoded) == value["bytes"]
             and base64.b64encode(decoded).decode("ascii") == encoded
             and _digest(decoded) == value["digest"], "ARTIFACT_JOIN")
    return decoded


def _loss(raw, bindings):
    if raw is None:
        return None
    _require(bindings is not None, "LOSS_WITHOUT_BINDINGS")
    value = _parse(raw, 8192)
    _fields(value, ("epoch_digest", "challenge_digest", "request_digest", "scope_digest", "before", "after"))
    for name, key in (("epoch_digest", "epoch"), ("challenge_digest", "challenge"),
                      ("request_digest", "request"), ("scope_digest", "loss_scope")):
        _pin(value[name])
        _require(value[name] == bindings[key], "LOSS_BINDING")
    for sample in (value["before"], value["after"]):
        if sample is None:
            continue
        _fields(sample, ("start_ns", "end_ns", "counters"))
        _require(_uint(sample["start_ns"]) <= _uint(sample["end_ns"]), "LOSS_TIME")
        counters = sample["counters"]
        _require(type(counters) is list and 1 <= len(counters) <= 32, "COUNTER_BOUND")
        for count in counters:
            if count is not None:
                _uint(count)
    if value["before"] is not None and value["after"] is not None:
        _require(len(value["before"]["counters"]) == len(value["after"]["counters"]), "COUNTER_LENGTH")
    return value


def _packet_pair(request_raw, response_raw, context, context_digest, phase, previous):
    request = _parse(request_raw, 4096)
    _fields(request, ("schema", *_ECHOES, "deadline_boottime_ns", "previous_response_digest"))
    _require(request["schema"] == _PREFIX + "broker-reader-request/v1"
             and request["phase"] == phase, "REQUEST_SCHEMA_PHASE")
    _nonce(request["exchange_id"])
    for name in ("context_digest", "epoch_digest", "request_digest", "effect_digest"):
        _pin(request[name])
    _uint(request["deadline_boottime_ns"], 1)
    if request["previous_response_digest"] is not None:
        _pin(request["previous_response_digest"])
    _require(request["previous_response_digest"] == previous, "PREVIOUS_RESPONSE")
    for name in ("exchange_id", "epoch_digest", "request_digest", "effect_digest", "deadline_boottime_ns"):
        _require(request[name] == context[name], "REQUEST_CONTEXT")
    _require(request["context_digest"] == context_digest, "REQUEST_CONTEXT_PIN")
    response = _parse(response_raw, 262144)
    _fields(response, ("schema", "request_packet_digest", *_ECHOES, "received_ns", "finished_ns",
                       "status", "error_codes", "reader_connection_epoch", "bindings", "reader_evidence",
                       "reader_summary", "reader_retention", "loss_record", "checkpoint_record", *_FLAGS))
    _require(response["schema"] == _PREFIX + "broker-reader-response/v1"
             and response["request_packet_digest"] == _digest(request_raw), "RESPONSE_REQUEST_PIN")
    for name in _ECHOES:
        _require(response[name] == request[name], "RESPONSE_ECHO")
    _require(all(response[name] is False for name in _FLAGS), "CLAIM_PROMOTION")
    _require(_uint(response["received_ns"]) <= _uint(response["finished_ns"]), "RESPONSE_TIME")
    codes = response["error_codes"]
    _require(type(codes) is list and len(codes) <= 8
             and all(type(code) is str and code in _ERRORS for code in codes), "ERROR_CODES")
    _require(codes == sorted(set(codes)), "ERROR_ORDER")
    _require((response["status"] == "EVIDENCE" and not codes)
             or (response["status"] == "REFUSED" and bool(codes)), "RESPONSE_STATUS")
    bindings = response["bindings"]
    if bindings is not None:
        _fields(bindings, ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy"))
        for value in bindings.values():
            _pin(value)
        _require(bindings["epoch"] == request["epoch_digest"]
                 and bindings["request"] == request["request_digest"], "READER_BINDINGS")
    if response["reader_connection_epoch"] is not None:
        _nonce(response["reader_connection_epoch"])
    artifacts = {name: _artifact(response[name], limit) for name, limit in (
        ("reader_evidence", 131072), ("reader_summary", 32768),
        ("loss_record", 8192), ("checkpoint_record", 16384))}
    retention = response["reader_retention"]
    if retention is not None:
        _fields(retention, ("digest", "bytes"))
        _pin(retention["digest"])
        _uint(retention["bytes"], 1, 131072)
        evidence = response["reader_evidence"]
        _require(evidence is not None and retention == {k: evidence[k] for k in ("digest", "bytes")},
                 "RETENTION_JOIN")
    if response["status"] == "EVIDENCE":
        _require(all(value is not None for value in artifacts.values()) and bindings is not None
                 and response["reader_connection_epoch"] is not None and retention is not None,
                 "EVIDENCE_INCOMPLETE")
    return response, _loss(artifacts["loss_record"], bindings)


def _checked(response, loss, checked_ns, context, phase, connect_time):
    received, finished = response["received_ns"], response["finished_ns"]
    cap = 250000000 if phase == "BEFORE_CONNECT" else 100000000
    _require(context["clock_bracket"]["boottime_after_ns"] <= received <= finished <= checked_ns
             < context["deadline_boottime_ns"] and finished - received <= cap
             and checked_ns - finished < _MAX_AGE, "CHECK_TIMING")
    if phase == "BEFORE_PAYLOAD_SEND":
        _require(connect_time is not None and received >= connect_time, "PRE_CONNECT_RESPONSE")
    if loss is not None and loss["after"] is not None:
        _require(received <= loss["after"]["start_ns"] <= loss["after"]["end_ns"] <= finished,
                 "LOSS_AFTER_BRACKET")


def _intent(response, loss, checked_ns):
    _require(response is not None and response["status"] == "EVIDENCE"
             and checked_ns - response["finished_ns"] < _MAX_AGE, "INTENT_WITHOUT_FRESH_EVIDENCE")
    _require(loss is not None and loss["before"] is not None and loss["after"] is not None,
             "INTENT_WITHOUT_LOSS")
    before, after = loss["before"]["counters"], loss["after"]["counters"]
    _require(all(count is not None for count in before + after) and before == after, "INTENT_LOSS")


def verify_submission_transcript(
    context_raw: bytes, events_raw: list[bytes], packets: dict[str, bytes], *,
    expected_context_digest: str, expected_request_digest: str,
    expected_broker: dict, expected_provider: dict, expected_clock: dict,
    expected_terminal_digest: str | None,
) -> dict:
    """Replay byte consistency only. Unknown publication/cleanup facts stay unknown."""
    _require(type(context_raw) is bytes and 0 < len(context_raw) <= 8192, "CONTEXT_BOUND")
    _require(type(events_raw) is list and 1 <= len(events_raw) <= 6, "EVENT_COUNT")
    _require(type(packets) is dict and len(packets) <= 5, "PACKET_COUNT")
    total = len(context_raw)
    for raw in events_raw:
        _require(type(raw) is bytes and 0 < len(raw) <= 8192, "EVENT_BOUND")
        total += len(raw)
    for raw in packets.values():
        _require(type(raw) is bytes and 0 < len(raw) <= 262144, "PACKET_BOUND")
        total += len(raw)
    _require(total <= _MAX_TOTAL, "TRANSCRIPT_BOUND")
    context = _context(context_raw, expected_context_digest, expected_request_digest,
                       expected_broker, expected_provider, expected_clock)
    if expected_terminal_digest is not None:
        _pin(expected_terminal_digest)
    for key, raw in packets.items():
        _pin(key)
        _require(_digest(raw) == key, "PACKET_PIN")
    used = set()

    def packet(key):
        _pin(key)
        _require(key in packets, "MISSING_PACKET")
        used.add(key)
        return packets[key]

    previous_phase = previous_digest = None
    last_time = context["clock_bracket"]["boottime_after_ns"]
    known_intent = False
    response = loss = first_response = first_loss = first_response_pin = connect_time = None
    for sequence, raw in enumerate(events_raw):
        event = _parse(raw, 8192)
        _fields(event, ("schema", "context_digest", "sequence", "previous_digest", "phase", "checked_ns",
                        "request_packet_digest", "response_packet_digest", "transport_digest",
                        "failure_code", "intent", "effect_possible"))
        _require(event["schema"] == _PREFIX + "broker-submission-event/v1"
                 and event["context_digest"] == expected_context_digest, "EVENT_CONTEXT")
        _require(_uint(event["sequence"], 0, 5) == sequence
                 and event["previous_digest"] == previous_digest, "EVENT_CHAIN")
        phase = event["phase"]
        _require(type(phase) is str and phase in _ARROWS, "EVENT_PHASE")
        _require((sequence == 0 and phase == "BOUND")
                 or (sequence > 0 and phase in _ARROWS[previous_phase]), "PHASE_ORDER")
        checked = _uint(event["checked_ns"])
        _require(checked >= last_time and (phase == "TERMINAL"
                 or checked < context["deadline_boottime_ns"]), "EVENT_TIME")
        if phase in ("CONNECT_CHECKED", "PAYLOAD_CHECKED"):
            which = "BEFORE_CONNECT" if phase == "CONNECT_CHECKED" else "BEFORE_PAYLOAD_SEND"
            request_raw = packet(event["request_packet_digest"])
            response_raw = packet(event["response_packet_digest"])
            response, loss = _packet_pair(request_raw, response_raw, context, expected_context_digest,
                                          which, first_response_pin)
            _checked(response, loss, checked, context, which, connect_time)
            if phase == "CONNECT_CHECKED":
                first_response, first_loss = response, loss
                first_response_pin = event["response_packet_digest"]
            else:
                _require(all(response[key] == first_response[key] for key in _IMMUTABLE_READER),
                         "READER_REPLACEMENT")
                if loss is not None:
                    _require(first_loss is not None and loss["before"] == first_loss["before"],
                             "LOSS_BASELINE_REPLACEMENT")
        else:
            _require(event["request_packet_digest"] is None and event["response_packet_digest"] is None,
                     "UNEXPECTED_PACKET_PINS")
        if phase in ("CONNECT_INTENT", "PAYLOAD_INTENT"):
            _intent(response, loss, checked)
            known_intent = True
            if phase == "CONNECT_INTENT":
                connect_time = checked
        if phase == "TERMINAL":
            code = event["failure_code"]
            _require(code is None or (type(code) is str and code in _TERMINAL_ERRORS), "FAILURE_CODE")
            if event["transport_digest"] is not None:
                _parse(packet(event["transport_digest"]), 32768)
            _require(code is not None or (previous_phase == "PAYLOAD_INTENT"
                     and event["transport_digest"] is not None), "TERMINAL_EVIDENCE")
            _require(event["intent"] is known_intent and event["effect_possible"] is
                     (True if known_intent else None), "TERMINAL_INTENT_DOWNGRADE")
        else:
            _require(event["failure_code"] is None and event["transport_digest"] is None,
                     "NONTERMINAL_FIELDS")
            _require(event["intent"] is known_intent and event["effect_possible"] is known_intent,
                     "INTENT_DOWNGRADE")
        previous_phase, previous_digest, last_time = phase, _digest(raw), checked
    _require(used == set(packets), "UNREFERENCED_PACKETS")
    if expected_terminal_digest is not None:
        _require(previous_phase == "TERMINAL" and previous_digest == expected_terminal_digest,
                 "TERMINAL_PIN")
    return {
        "status": ("CONSISTENT_TERMINAL_TRANSCRIPT" if expected_terminal_digest is not None
                   else "CONSISTENT_OPEN_PREFIX"),
        "context_digest": expected_context_digest, "last_event_digest": previous_digest,
        "submission_state": "SUBMITTED" if known_intent else "UNKNOWN",
        **{name: False for name in _FLAGS},
    }
