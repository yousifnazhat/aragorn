"""Focused inert acquisition joins; expected windows never come from the producer."""

import ast
from copy import deepcopy
import hashlib
import inspect
import json
import unittest

from aragorn.native_phase3_run_acquisition import project_acquisition
from aragorn import native_phase3_run_acquisition_verify as consumer
from aragorn.native_phase3_run_progress import evaluate_progress


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if type(value) is bytes else encode(value)).hexdigest()


PIN = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def seal(records):
    """Fixture-only custody pins; mutation checks also hold these pins unchanged."""
    epoch = records["epoch"]
    pins = {role: digest(epoch[role]) for role in ("process", "clock", "loss_scope", "policy")}
    pins.update(epoch=digest(epoch), request=PIN)
    records["challenge"]["epoch_digest"] = pins["epoch"]
    pins["challenge"] = digest(records["challenge"])
    for role in ("reader", "loss", "submission"):
        if records[role] is not None:
            records[role].update(epoch_digest=pins["epoch"], challenge_digest=pins["challenge"])
    records["loss"]["scope_digest"] = pins["loss_scope"]
    return pins


def fixture():
    process = {
        "boot_id": "11111111-2222-3333-4444-555555555555", "reader_pid": 101,
        "reader_start_ticks": 12, "sensor_pid": 102, "sensor_start_ticks": 13,
        "reader_uid": 997, "reader_gid": 997, "sensor_uid": 0, "sensor_gid": 0,
        "reader_source_digest": PIN, "sensor_source_digest": PIN,
        "stream_digest": PIN, "program_map_digest": PIN,
    }
    clock = {"boot_id": process["boot_id"], "clock_id": "CLOCK_BOOTTIME", "time_namespace_inode": 99}
    records = {
        "schema": "aragorn/native-phase3-run-acquisition/v1",
        "epoch": {"process": process, "clock": clock, "loss_scope": [PIN, OTHER],
                  "policy": {"timeout_ns": 100, "max_age_ns": 50}, "deployment_digest": PIN},
        "challenge": {"epoch_digest": PIN, "request_digest": PIN, "boundary": "BEFORE_FIRST_EFFECT",
                      "nonce": "c" * 64, "issued_ns": 100, "deadline_ns": 200, "sequence_before": 4},
        "reader": {"epoch_digest": PIN, "challenge_digest": PIN, "request_digest": PIN,
                   "process_before": deepcopy(process), "process_after": deepcopy(process),
                   "clock_before": deepcopy(clock), "clock_after": deepcopy(clock),
                   "peer": {"pid": 101, "uid": 997, "gid": 997},
                   "status": "ACK", "sequence_after": 5, "ack_ns": 190, "received_ns": 195},
        "loss": {"epoch_digest": PIN, "challenge_digest": PIN, "request_digest": PIN, "scope_digest": PIN,
                 "before": {"start_ns": 90, "end_ns": 95, "counters": [7, 3]},
                 "after": {"start_ns": 200, "end_ns": 205, "counters": [7, 3]}},
        "submission": {"epoch_digest": PIN, "challenge_digest": PIN, "request_digest": PIN,
                       "checked_ns": 210, "custody": "EXCLUSIVE", "intent": False, "effect_possible": False},
    }
    return records, seal(records)


def expected(pins, **changes):
    return encode({
        "schema": "aragorn/native-phase3-run-progress-window/v1", "epoch": pins["epoch"],
        "challenge": pins["challenge"], "clock_id": "CLOCK_BOOTTIME", "issued_ns": 100,
        "deadline_ns": 200, "checked_ns": 210, "max_age_ns": 50, "ack_ns": 190,
        "sequence_before": 4, "sequence_after": 5, "loss_before": 10, "loss_after": 10,
        "effect_state": "NOT_SUBMITTED", **changes,
    })


def consume(raw, window, pins, decision=None, raw_pin=None):
    if decision is None:
        decision = evaluate_progress(window, expected_epoch=pins["epoch"], expected_challenge=pins["challenge"])
    return consumer.verify_acquisition(raw, window, decision, bindings=pins,
                                       expected_raw_digest=digest(raw) if raw_pin is None else raw_pin)


def change(record, path, value):
    fields = path.split(".")
    for field in fields[:-1]:
        record = record[field]
    record[fields[-1]] = value


class AcquisitionTests(unittest.TestCase):
    def assert_refuses(self, records, pins):
        raw = encode(records)
        with self.assertRaises(ValueError):
            project_acquisition(raw, bindings=pins)
        with self.assertRaises(ValueError):
            consume(raw, expected(pins), pins)

    def assert_projection(self, records, pins, **fields):
        raw, window = encode(records), expected(pins, **fields)
        self.assertEqual(project_acquisition(raw, bindings=pins), window)
        result = consume(raw, window, pins)
        self.assertEqual(result["status"], "CONSISTENT_RETAINED_PROJECTION")
        for flag in ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized", "run_qualified"):
            self.assertIs(result[flag], False)

    def test_expected_projection_and_closed_freshness_boundaries(self):
        records, pins = fixture()
        self.assert_projection(records, pins)
        for now, ack, receive, reasons in (
            (239, 190, 195, []), (240, 190, 195, ["STALE_READER_PROGRESS"]),
            (210, 200, 200, ["CHALLENGE_DEADLINE_MISSED"]),
        ):
            with self.subTest(now=now, ack=ack):
                r = deepcopy(records)
                r["submission"]["checked_ns"] = now
                r["reader"].update(ack_ns=ack, received_ns=receive)
                self.assert_projection(r, pins, checked_ns=now, ack_ns=ack)
                window = expected(pins, checked_ns=now, ack_ns=ack)
                decision = evaluate_progress(window, expected_epoch=pins["epoch"], expected_challenge=pins["challenge"])
                self.assertEqual(decision["reasons"], reasons)

    def test_timeout_never_invents_progress_and_missing_identity_refuses(self):
        records, pins = fixture()
        records["reader"].update(status="TIMEOUT", peer=None, sequence_after=4, ack_ns=None, received_ns=None)
        self.assert_projection(records, pins, sequence_after=4, ack_ns=None)
        for path, value in (("reader.sequence_after", 5), ("reader.ack_ns", 190),
                            ("reader.received_ns", 195), ("reader.process_after", None)):
            changed = deepcopy(records)
            change(changed, path, value)
            with self.subTest(path=path):
                self.assert_refuses(changed, pins)

    def test_scoped_loss_partial_reset_and_positive_counts(self):
        for before, after, totals in (
            ([7, 3], [8, 3], (10, 11)), ([7, 3], [6, 5], (None, None)),
            ([None, 3], [7, 3], (None, 10)), ([7, 3], [None, 3], (10, None)),
            ([7, 3], None, (10, None)), (None, [7, 3], (None, 10)), (None, None, (None, None)),
            ([7, None], [6, 4], (None, None)),
        ):
            records, pins = fixture()
            for edge, counters in (("before", before), ("after", after)):
                if counters is None:
                    records["loss"][edge] = None
                else:
                    records["loss"][edge]["counters"] = counters
            with self.subTest(before=before, after=after):
                self.assert_projection(records, pins, loss_before=totals[0], loss_after=totals[1])

    def test_submission_truth_table_and_absent_state(self):
        for custody in ("EXCLUSIVE", "PARTIAL"):
            for intent in (False, True, None):
                for possible in (False, True, None):
                    records, pins = fixture()
                    records["submission"].update(custody=custody, intent=intent, effect_possible=possible)
                    state = "SUBMITTED" if intent is True or possible is True else (
                        "NOT_SUBMITTED" if custody == "EXCLUSIVE" and intent is False and possible is False else "UNKNOWN")
                    with self.subTest(custody=custody, intent=intent, possible=possible):
                        self.assert_projection(records, pins, effect_state=state)
                        window = expected(pins, effect_state=state)
                        decision = evaluate_progress(window, expected_epoch=pins["epoch"], expected_challenge=pins["challenge"])
                        self.assertEqual(decision["disposition"], "CONTINUE_OTHER_GATES" if state == "NOT_SUBMITTED" else "INDETERMINATE")
        records, pins = fixture()
        records["submission"] = None
        self.assert_refuses(records, pins)

    def test_all_caller_pins_and_nested_bindings(self):
        records, pins = fixture()
        for role in pins:
            with self.subTest(caller=role):
                self.assert_refuses(records, {**pins, role: OTHER})
        for role in ("challenge", "reader", "loss", "submission"):
            for field in ("epoch_digest", "challenge_digest", "request_digest", "scope_digest"):
                if field not in records[role]:
                    continue
                altered = deepcopy(records)
                altered[role][field] = OTHER
                updated = dict(pins)
                if role == "challenge":
                    updated["challenge"] = digest(altered[role])
                    for dependent in ("reader", "loss", "submission"):
                        altered[dependent]["challenge_digest"] = updated["challenge"]
                with self.subTest(role=role, field=field):
                    self.assert_refuses(altered, updated)
        for role in ("reader", "loss", "submission"):
            altered = deepcopy(records)
            altered["reader"].update(status="TIMEOUT", sequence_after=4, ack_ns=None, received_ns=None)
            altered["loss"]["after"] = None
            altered["submission"]["custody"] = "PARTIAL"
            altered[role]["request_digest"] = OTHER
            with self.subTest(partial_role=role):
                self.assert_refuses(altered, pins)

    def test_identity_peer_clock_and_chronology_refusals(self):
        mutations = (
            ("reader.process_before.reader_pid", 999), ("reader.process_after.reader_start_ticks", 99),
            ("reader.process_after.sensor_pid", 999), ("reader.clock_after.time_namespace_inode", 100),
            ("reader.peer.pid", 999), ("reader.peer.uid", True), ("reader.peer", None),
            ("reader.ack_ns", 99), ("reader.received_ns", 189), ("reader.received_ns", 211),
            ("reader.sequence_after", 4), ("reader.status", "PARTIAL"),
            ("submission.checked_ns", 199), ("submission.checked_ns", True),
            ("loss.before.end_ns", 101), ("loss.after.start_ns", 199),
            ("loss.after.end_ns", 211), ("loss.after.start_ns", 206),
            ("loss.after.counters", [7]), ("loss.after.counters", [True, 3]),
            ("loss.after.counters", [2**63 - 1, 1]), ("loss.after.counters", [-1, 3]),
            ("submission.intent", 0), ("submission.effect_possible", "false"),
            ("submission.custody", "UNLOCKED"),
        )
        for path, value in mutations:
            records, pins = fixture()
            change(records, path, value)
            with self.subTest(path=path, value=value):
                self.assert_refuses(records, pins)

    def test_pinned_but_invalid_epoch_policy_or_boundary_refuses(self):
        for path, value in (
            ("epoch.process.reader_pid", True), ("epoch.clock.clock_id", "CLOCK_REALTIME"),
            ("epoch.clock.boot_id", "22222222-2222-3333-4444-555555555555"),
            ("epoch.process.boot_id", "bad"), ("epoch.policy.max_age_ns", 0),
            ("epoch.policy.timeout_ns", 0), ("epoch.loss_scope", [OTHER, PIN]),
            ("epoch.loss_scope", [PIN, PIN]), ("epoch.loss_scope", []),
            ("epoch.loss_scope", [PIN] * 33), ("epoch.deployment_digest", "bad"),
            ("challenge.boundary", "BEFORE_PAYLOAD_SEND"), ("challenge.nonce", "x" * 64),
            ("challenge.deadline_ns", 201), ("challenge.issued_ns", 2**63),
        ):
            records, _ = fixture()
            change(records, path, value)
            pins = seal(records)
            # Keep readbacks consistent so scalar checks cannot hide behind identity mismatch.
            for role in ("process", "clock"):
                for edge in ("before", "after"):
                    records["reader"][f"{role}_{edge}"] = deepcopy(records["epoch"][role])
            with self.subTest(path=path, value=value):
                self.assert_refuses(records, pins)

    def test_noncanonical_bounded_and_malformed_records_refuse(self):
        records, pins = fixture()
        raw = encode(records)
        raws = (raw + b"\n", b" " * 32769, b"\xff", b"[]", b"[" * 1500 + b"]" * 1500,
                raw.replace(b'"checked_ns":210', b'"checked_ns":209,"checked_ns":210'))
        for bad in raws:
            with self.subTest(raw=bad[:40]):
                with self.assertRaises(ValueError):
                    project_acquisition(bad, bindings=pins)
                with self.assertRaises(ValueError):
                    consume(bad, expected(pins), pins)
        for role in (None, "epoch", "challenge", "reader", "loss", "submission"):
            altered = deepcopy(records)
            target = altered if role is None else altered[role]
            target["extra"] = False
            with self.subTest(role=role):
                self.assert_refuses(altered, pins)
        altered = deepcopy(records)
        del altered["submission"]["intent"]
        self.assert_refuses(altered, pins)

    def test_consumer_rejects_raw_window_decision_tampering(self):
        records, pins = fixture()
        raw, window = encode(records), expected(pins)
        decision = evaluate_progress(window, expected_epoch=pins["epoch"], expected_challenge=pins["challenge"])
        with self.assertRaises(ValueError):
            consume(raw, window, pins, raw_pin=OTHER)
        for field, value in (("effect_state", "SUBMITTED"), ("loss_after", 0),
                             ("ack_ns", 195), ("checked_ns", 211), ("epoch", OTHER)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                consume(raw, expected(pins, **{field: value}), pins, decision)
        for changes in ({"effect_authorized": True}, {"sensor_health_verified": True},
                        {"run_qualified": True}, {"disposition": "BLOCKED_PRE_EFFECT"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                consume(raw, window, pins, {**decision, **changes})

    def test_consumer_import_boundary(self):
        tree = ast.parse(inspect.getsource(consumer))
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"hashlib", "json", "re", "native_phase3_run_progress_verify"})
