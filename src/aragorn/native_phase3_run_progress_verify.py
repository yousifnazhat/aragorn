"""Independent retained-window consumer; does not import the decision producer.

Caller pins are trust anchors, not authentication or evidence of acquisition.
No healthy verdict or claim of an actual stop is established here.
"""

import hashlib
import json
import re


def verify_progress(raw: bytes, decision: dict, *, expected_digest: str,
                    expected_epoch: str, expected_challenge: str) -> dict:
    """Reconstruct the finite decision from exact externally pinned input bytes."""
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError("window size")
    for pin in (expected_digest, expected_epoch, expected_challenge):
        if type(pin) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None:
            raise ValueError("caller pin")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("window digest")
    try:
        w = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("window encoding") from exc
    if type(w) is not dict or set(w) != {
        "schema", "epoch", "challenge", "clock_id", "issued_ns", "deadline_ns",
        "checked_ns", "max_age_ns", "ack_ns", "sequence_before", "sequence_after",
        "loss_before", "loss_after", "effect_state",
    }:
        raise ValueError("window fields")
    if raw != json.dumps(w, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode():
        raise ValueError("window canonical encoding")
    if (w["schema"], w["clock_id"], w["epoch"], w["challenge"]) != (
        "aragorn/native-phase3-run-progress-window/v1", "CLOCK_BOOTTIME",
        expected_epoch, expected_challenge,
    ):
        raise ValueError("window binding")
    required = ("issued_ns", "deadline_ns", "checked_ns", "max_age_ns",
                "sequence_before", "sequence_after")
    optional = ("ack_ns", "loss_before", "loss_after")
    for key in required + optional:
        n = w[key]
        if key in optional and n is None:
            continue
        if type(n) is not int or n < 0 or n >= 2**63:
            raise ValueError("window scalar")
    issue, deadline, now, ack = (w[k] for k in ("issued_ns", "deadline_ns", "checked_ns", "ack_ns"))
    if issue >= deadline or now < deadline or w["max_age_ns"] == 0:
        raise ValueError("window ordering")
    if ack is not None and (ack < issue or ack > now):
        raise ValueError("ack ordering")
    if w["effect_state"] not in ("NOT_SUBMITTED", "SUBMITTED", "UNKNOWN"):
        raise ValueError("effect state")

    checks = (
        ("PROGRESS_RESET", w["sequence_after"] < w["sequence_before"]),
        ("NO_READER_PROGRESS", ack is None or w["sequence_after"] == w["sequence_before"]),
        ("CHALLENGE_DEADLINE_MISSED", ack is not None and ack >= deadline),
        ("STALE_READER_PROGRESS", ack is not None and now - ack >= w["max_age_ns"]),
        ("LOSS_UNKNOWN", w["loss_before"] is None or w["loss_after"] is None),
    )
    reasons = [name for name, failed in checks if failed]
    if all(w[k] is not None for k in ("loss_before", "loss_after")):
        if w["loss_before"] > w["loss_after"]:
            reasons.append("LOSS_COUNTER_RESET")
        if w["loss_before"] < w["loss_after"]:
            reasons.append("LOSS_OBSERVED")
    disposition = "INDETERMINATE"
    if w["effect_state"] == "NOT_SUBMITTED":
        disposition = "HOLD_UNSUBMITTED" if reasons else "CONTINUE_OTHER_GATES"
    expected = {
        "schema": "aragorn/native-phase3-run-progress-decision/v1",
        "window_digest": expected_digest, "reasons": reasons, "disposition": disposition,
        "effect_authorized": False, "sensor_health_verified": False, "run_qualified": False,
    }
    if type(decision) is not dict or decision != expected or any(
        decision[key] is not False
        for key in ("effect_authorized", "sensor_health_verified", "run_qualified")
    ):
        raise ValueError("decision differs from independent reconstruction")
    return {"status": "CONSISTENT_FINITE_DECISION", "window_digest": expected_digest,
            "run_qualified": False, "sensor_health_verified": False}
