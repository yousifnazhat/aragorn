"""Independent raw-record joins, then existing progress-decision verification.

No acquisition producer imports. Caller pins are custody assumptions, not proof
of authentic acquisition, live reader execution, replay exclusion or enforcement.
"""

import hashlib
import json
import re

from .native_phase3_run_progress_verify import verify_progress


def _encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError("raw record shape")
    return value


def _number(value, positive=False):
    if type(value) is not int or value < int(positive) or value >= 2**63:
        raise ValueError("raw integer")
    return value


def _matches(value, pattern):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ValueError("raw identifier")


def verify_acquisition(raw: bytes, window: bytes, decision: dict, *, bindings: dict,
                       expected_raw_digest: str) -> dict:
    """Validate pinned raw evidence without trusting a projected summary."""
    _object(bindings, "epoch challenge request process clock loss_scope policy")
    for value in (*bindings.values(), expected_raw_digest):
        _matches(value, r"sha256:[0-9a-f]{64}")
    if type(raw) is not bytes or not 0 < len(raw) <= 32768 or _hash(raw) != expected_raw_digest:
        raise ValueError("raw bytes or digest")
    try:
        records = json.loads(raw)
        if _encode(records) != raw:
            raise ValueError("raw encoding is not canonical")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("raw decoding") from exc
    _object(records, "schema epoch challenge reader loss submission")
    if records["schema"] != "aragorn/native-phase3-run-acquisition/v1":
        raise ValueError("raw schema")
    e = _object(records["epoch"], "process clock loss_scope policy deployment_digest")
    c = _object(records["challenge"], "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
    r = _object(records["reader"], "epoch_digest challenge_digest request_digest process_before process_after "
                "clock_before clock_after peer status sequence_after ack_ns received_ns")
    loss = _object(records["loss"], "epoch_digest challenge_digest request_digest scope_digest before after")
    state = _object(records["submission"], "epoch_digest challenge_digest request_digest checked_ns custody intent effect_possible")
    for name, value in (("epoch", e), ("challenge", c), ("process", e["process"]),
                         ("clock", e["clock"]), ("loss_scope", e["loss_scope"]), ("policy", e["policy"])):
        if _hash(_encode(value)) != bindings[name]:
            raise ValueError("caller record pin mismatch")
    for record in (c, r, loss, state):
        for field in ("epoch_digest", "challenge_digest", "request_digest", "scope_digest"):
            if field in record:
                role = "loss_scope" if field == "scope_digest" else field.removesuffix("_digest")
                if record[field] != bindings[role]:
                    raise ValueError("nested pin mismatch")
    p = _object(e["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks reader_uid "
                "reader_gid sensor_uid sensor_gid reader_source_digest sensor_source_digest stream_digest program_map_digest")
    _matches(p["boot_id"], r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    for name, value in p.items():
        if name.endswith("_digest"):
            _matches(value, r"sha256:[0-9a-f]{64}")
        elif name != "boot_id":
            _number(value, name.endswith(("_pid", "_ticks")))
    _matches(e["deployment_digest"], r"sha256:[0-9a-f]{64}")
    clock = _object(e["clock"], "boot_id clock_id time_namespace_inode")
    _number(clock["time_namespace_inode"], True)
    if clock["boot_id"] != p["boot_id"] or clock["clock_id"] != "CLOCK_BOOTTIME":
        raise ValueError("clock binding")
    for name in ("process_before", "process_after", "clock_before", "clock_after"):
        role = name.split("_")[0]
        if _encode(r[name]) != _encode(e[role]):
            raise ValueError("raw identity discontinuity")
    policy = _object(e["policy"], "timeout_ns max_age_ns")
    duration = _number(policy["timeout_ns"], True)
    age = _number(policy["max_age_ns"], True)
    _matches(c["nonce"], r"[0-9a-f]{64}")
    issue, deadline, baseline = (_number(c[key]) for key in ("issued_ns", "deadline_ns", "sequence_before"))
    now, sequence = _number(state["checked_ns"]), _number(r["sequence_after"])
    if c["boundary"] != "BEFORE_FIRST_EFFECT" or deadline - issue != duration or now < deadline:
        raise ValueError("boundary or chronology")
    if r["peer"] is not None:
        peer = _object(r["peer"], "pid uid gid")
        for field in ("pid", "uid", "gid"):
            if _number(peer[field], field == "pid") != p["reader_" + field]:
                raise ValueError("sender mismatch")
    if r["status"] == "TIMEOUT":
        if r["ack_ns"] is not None or r["received_ns"] is not None or sequence != baseline:
            raise ValueError("timeout fabricated progress")
    elif r["status"] == "ACK":
        ack, receive = _number(r["ack_ns"]), _number(r["received_ns"])
        if r["peer"] is None or sequence <= baseline or not issue <= ack <= receive <= now:
            raise ValueError("acknowledgement chronology")
    else:
        raise ValueError("acknowledgement status")
    scope = e["loss_scope"]
    if type(scope) is not list or not 1 <= len(scope) <= 32:
        raise ValueError("loss scope bound")
    for name in scope:
        _matches(name, r"sha256:[0-9a-f]{64}")
    if scope != sorted(set(scope)):
        raise ValueError("loss series order")
    sums = {}
    for edge, sample in (("before", loss["before"]), ("after", loss["after"])):
        sums[edge] = None
        if sample is None:
            continue
        _object(sample, "start_ns end_ns counters")
        start, end = _number(sample["start_ns"]), _number(sample["end_ns"])
        if not start <= end <= now or (edge == "before" and end > issue) or (edge == "after" and start < deadline):
            raise ValueError("loss sample chronology")
        values = sample["counters"]
        if type(values) is not list or len(values) != len(scope):
            raise ValueError("loss series inventory")
        for value in values:
            if value is not None:
                _number(value)
        if all(value is not None for value in values):
            sums[edge] = _number(sum(values))
    if all(loss[edge] is not None for edge in ("before", "after")):
        for index in range(len(scope)):
            a, b = loss["before"]["counters"][index], loss["after"]["counters"][index]
            if a is not None and b is not None and a > b:
                sums = {"before": None, "after": None}
                break
    if state["custody"] not in ("EXCLUSIVE", "PARTIAL"):
        raise ValueError("submission custody")
    flags = (state["intent"], state["effect_possible"])
    if any(flag is not None and type(flag) is not bool for flag in flags):
        raise ValueError("submission scalar")
    effect = "UNKNOWN"
    if any(flag is True for flag in flags):
        effect = "SUBMITTED"
    elif state["custody"] == "EXCLUSIVE" and all(flag is False for flag in flags):
        effect = "NOT_SUBMITTED"
    reconstructed = _encode({
        "schema": "aragorn/native-phase3-run-progress-window/v1",
        "epoch": bindings["epoch"], "challenge": bindings["challenge"], "clock_id": "CLOCK_BOOTTIME",
        "issued_ns": issue, "deadline_ns": deadline, "checked_ns": now,
        "max_age_ns": age, "ack_ns": r["ack_ns"], "sequence_before": baseline,
        "sequence_after": sequence, "loss_before": sums["before"], "loss_after": sums["after"],
        "effect_state": effect,
    })
    if type(window) is not bytes or window != reconstructed:
        raise ValueError("projection does not match raw records")
    verdict = verify_progress(window, decision, expected_digest=_hash(window),
                              expected_epoch=bindings["epoch"], expected_challenge=bindings["challenge"])
    return {
        "status": "CONSISTENT_RETAINED_PROJECTION", "raw_digest": expected_raw_digest,
        "window_digest": verdict["window_digest"], "acquisition_authenticity_verified": False,
        "sensor_health_verified": False, "effect_authorized": False, "run_qualified": False,
    }
