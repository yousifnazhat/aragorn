"""Finite reader-challenge decision; no acquisition, publication or effect authority.

The caller must bind epoch/challenge to protected observations of the real reader
loop (including idle polling), not a timer thread or the number of traffic events.
"""

import hashlib
import json
import re


def evaluate_progress(raw: bytes, *, expected_epoch: str, expected_challenge: str) -> dict:
    """Evaluate one closed CLOCK_BOOTTIME window; never authorize an effect."""
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError("progress input size")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("progress input encoding") from exc
    fields = {
        "schema", "epoch", "challenge", "clock_id", "issued_ns", "deadline_ns",
        "checked_ns", "max_age_ns", "ack_ns", "sequence_before", "sequence_after",
        "loss_before", "loss_after", "effect_state",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("progress input fields")
    if json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() != raw:
        raise ValueError("progress input is not canonical")
    for pin in (expected_epoch, expected_challenge):
        if type(pin) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None:
            raise ValueError("progress caller pin")
    if (value["schema"] != "aragorn/native-phase3-run-progress-window/v1"
            or value["clock_id"] != "CLOCK_BOOTTIME"
            or value["epoch"] != expected_epoch
            or value["challenge"] != expected_challenge):
        raise ValueError("progress identity or clock")
    for field in ("issued_ns", "deadline_ns", "checked_ns", "max_age_ns",
                  "sequence_before", "sequence_after", "ack_ns", "loss_before", "loss_after"):
        item = value[field]
        if item is None and field in {"ack_ns", "loss_before", "loss_after"}:
            continue
        if type(item) is not int or not 0 <= item < 2**63:
            raise ValueError("progress integer")
    if not (value["issued_ns"] < value["deadline_ns"] <= value["checked_ns"]
            and value["max_age_ns"] > 0):
        raise ValueError("progress window is not closed")
    if value["ack_ns"] is not None and not value["issued_ns"] <= value["ack_ns"] <= value["checked_ns"]:
        raise ValueError("progress acknowledgement outside window")
    if value["effect_state"] not in ("NOT_SUBMITTED", "SUBMITTED", "UNKNOWN"):
        raise ValueError("progress effect state")

    reasons = []
    if value["sequence_after"] < value["sequence_before"]:
        reasons.append("PROGRESS_RESET")
    if value["sequence_after"] == value["sequence_before"] or value["ack_ns"] is None:
        reasons.append("NO_READER_PROGRESS")
    if value["ack_ns"] is not None:
        if value["ack_ns"] >= value["deadline_ns"]:
            reasons.append("CHALLENGE_DEADLINE_MISSED")
        if value["checked_ns"] - value["ack_ns"] >= value["max_age_ns"]:
            reasons.append("STALE_READER_PROGRESS")
    if value["loss_before"] is None or value["loss_after"] is None:
        reasons.append("LOSS_UNKNOWN")
    elif value["loss_after"] < value["loss_before"]:
        reasons.append("LOSS_COUNTER_RESET")
    elif value["loss_after"] > value["loss_before"]:
        reasons.append("LOSS_OBSERVED")
    return {
        "schema": "aragorn/native-phase3-run-progress-decision/v1",
        "window_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "reasons": reasons,
        "disposition": "INDETERMINATE" if value["effect_state"] != "NOT_SUBMITTED"
        else "HOLD_UNSUBMITTED" if reasons else "CONTINUE_OTHER_GATES",
        "effect_authorized": False,
        "sensor_health_verified": False,
        "run_qualified": False,
    }
