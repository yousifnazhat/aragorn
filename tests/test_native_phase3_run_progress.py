"""Inert checks only; registration and scheduling belong to the coordinator."""

import hashlib
import json
import unittest

from aragorn.native_phase3_run_progress import evaluate_progress
from aragorn.native_phase3_run_progress_verify import verify_progress


EPOCH = "sha256:" + "a" * 64
CHALLENGE = "sha256:" + "b" * 64


def window(**changes):
    value = {
        "schema": "aragorn/native-phase3-run-progress-window/v1",
        "epoch": EPOCH, "challenge": CHALLENGE, "clock_id": "CLOCK_BOOTTIME",
        "issued_ns": 10, "deadline_ns": 20, "checked_ns": 20, "max_age_ns": 10,
        "ack_ns": 19, "sequence_before": 4, "sequence_after": 5,
        "loss_before": 7, "loss_after": 7, "effect_state": "NOT_SUBMITTED",
    }
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def expected(raw, reasons=(), disposition="CONTINUE_OTHER_GATES"):
    # Independent fixture expectations are never obtained from the producer.
    return {
        "schema": "aragorn/native-phase3-run-progress-decision/v1",
        "window_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "reasons": list(reasons), "disposition": disposition,
        "effect_authorized": False, "sensor_health_verified": False, "run_qualified": False,
    }


def consume(raw, result, **pins):
    return verify_progress(raw, result, **{
        "expected_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "expected_epoch": EPOCH, "expected_challenge": CHALLENGE, **pins,
    })


class RunProgressTests(unittest.TestCase):
    def test_finite_outcomes_and_submitted_ambiguity(self):
        cases = (
            ({}, ()),
            ({"sequence_after": 4}, ("NO_READER_PROGRESS",)),
            ({"ack_ns": None}, ("NO_READER_PROGRESS",)),
            ({"ack_ns": 20}, ("CHALLENGE_DEADLINE_MISSED",)),
            ({"checked_ns": 29}, ("STALE_READER_PROGRESS",)),
            ({"checked_ns": 28}, ()),
            ({"sequence_after": 3}, ("PROGRESS_RESET",)),
            ({"loss_after": 8}, ("LOSS_OBSERVED",)),
            ({"loss_after": 6}, ("LOSS_COUNTER_RESET",)),
            ({"loss_after": None}, ("LOSS_UNKNOWN",)),
            ({"loss_before": None}, ("LOSS_UNKNOWN",)),
            ({"ack_ns": None, "loss_after": 8}, ("NO_READER_PROGRESS", "LOSS_OBSERVED")),
        )
        for changes, reasons in cases:
            for state in ("NOT_SUBMITTED", "SUBMITTED", "UNKNOWN"):
                with self.subTest(changes=changes, state=state):
                    raw = window(**changes, effect_state=state)
                    disposition = "INDETERMINATE" if state != "NOT_SUBMITTED" else (
                        "HOLD_UNSUBMITTED" if reasons else "CONTINUE_OTHER_GATES")
                    result = expected(raw, reasons, disposition)
                    self.assertEqual(evaluate_progress(raw, expected_epoch=EPOCH,
                                                      expected_challenge=CHALLENGE), result)
                    self.assertEqual(consume(raw, result)["status"], "CONSISTENT_FINITE_DECISION")

    def test_malformed_or_unbound_windows_refuse_in_both_paths(self):
        changes = (
            {"epoch": CHALLENGE}, {"challenge": EPOCH}, {"clock_id": "CLOCK_REALTIME"},
            {"issued_ns": 20}, {"checked_ns": 19}, {"max_age_ns": 0},
            {"ack_ns": 9}, {"ack_ns": 21}, {"sequence_after": True},
            {"loss_after": -1}, {"sequence_before": 2**63}, {"ack_ns": 19.0},
            {"loss_before": "7"}, {"effect_state": "BLOCKED"}, {"extra": 0},
        )
        raws = [window(**change) for change in changes]
        raws.extend((b"{}", b"[]", b"\xff", b"[" * 1500 + b"]" * 1500,
                     window() + b"\n", b" " * 4097,
                     window().replace(b'"ack_ns":19', b'"ack_ns":18,"ack_ns":19')))
        for raw in raws:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    evaluate_progress(raw, expected_epoch=EPOCH, expected_challenge=CHALLENGE)
                with self.assertRaises(ValueError):
                    consume(raw, expected(raw))

    def test_consumer_rejects_forged_claims_and_caller_pins(self):
        raw = window(effect_state="SUBMITTED", ack_ns=None)
        result = expected(raw, ("NO_READER_PROGRESS",), "INDETERMINATE")
        for change in (
            {"reasons": []}, {"disposition": "HOLD_UNSUBMITTED"},
            {"disposition": "BLOCKED_PRE_EFFECT"}, {"effect_authorized": True},
            {"sensor_health_verified": True}, {"run_qualified": True},
            {"run_qualified": 0}, {"window_digest": EPOCH}, {"extra": False},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                consume(raw, {**result, **change})
        for key in ("expected_digest", "expected_epoch", "expected_challenge"):
            with self.subTest(pin=key), self.assertRaises(ValueError):
                consume(raw, result, **{key: "sha256:" + "c" * 64})
        for invalid in (None, "", "sha256:" + "g" * 64):
            with self.subTest(pin=invalid), self.assertRaises(ValueError):
                evaluate_progress(raw, expected_epoch=invalid, expected_challenge=CHALLENGE)
