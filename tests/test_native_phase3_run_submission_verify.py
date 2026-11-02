"""Hand-authored transcript bytes; no producer codec, journal or fixture imports."""
import base64
import copy
import hashlib
import json
import unittest

from aragorn.native_phase3_run_submission_verify import verify_submission_transcript


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def artifact(raw):
    return {"base64": base64.b64encode(raw).decode("ascii"), "bytes": len(raw), "digest": digest(raw)}


FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
         "effect_authorized", "run_qualified", "phase3_qualified")
PHASES = ("BOUND", "CONNECT_CHECKED", "CONNECT_INTENT", "PAYLOAD_CHECKED", "PAYLOAD_INTENT", "TERMINAL")
BASE = 1000000000


class Transcript:
    def __init__(self):
        self.broker = {"pid": 501, "start_time_ticks": 101, "uid": 990, "gid": 990}
        self.provider = {"pid": 601, "start_time_ticks": 201, "uid": 0, "gid": 0}
        self.clock = {"boot_id": "12345678-1234-1234-1234-123456789abc", "clock_id": "CLOCK_BOOTTIME",
                      "time_namespace": {"device": 4, "inode": 100}}
        self.context = {
            "schema": "aragorn/native-phase3-broker-reader-context/v1",
            **{key + "_digest": digest(key.encode()) for key in ("request", "effect", "grant", "deployment", "epoch")},
            "broker": copy.deepcopy(self.broker), "provider": copy.deepcopy(self.provider),
            "clock": copy.deepcopy(self.clock), "exchange_id": "e" * 64,
            "accepted_boottime_ns": BASE - 10, "deadline_boottime_ns": BASE + 500000000,
            "clock_bracket": {"boottime_before_ns": BASE, "monotonic_ns": 700000000,
                              "boottime_after_ns": BASE + 10, "original_monotonic_deadline_ns": 1200000000},
        }
        bindings = {key: digest(key.encode()) for key in ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy")}
        loss = {"epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"],
                "request_digest": bindings["request"], "scope_digest": bindings["loss_scope"],
                "before": {"start_ns": BASE + 100, "end_ns": BASE + 200, "counters": [0, 7]},
                "after": {"start_ns": BASE + 120000000, "end_ns": BASE + 125000000, "counters": [0, 7]}}
        evidence = artifact(canonical({"status": "ACK", "opaque": "not independently authenticated"}))
        response = {
            "received_ns": BASE + 30000000, "finished_ns": BASE + 130000000,
            "status": "EVIDENCE", "error_codes": [], "reader_connection_epoch": "d" * 64,
            "bindings": bindings, "reader_evidence": evidence,
            "reader_summary": artifact(canonical({"status": "ACK", "sensor_progress": "unproved"})),
            "reader_retention": {k: evidence[k] for k in ("bytes", "digest")},
            "loss_record": artifact(canonical(loss)),
            "checkpoint_record": artifact(b"opaque checkpoint stand-in"), **{flag: False for flag in FLAGS},
        }
        self.responses = [response, copy.deepcopy(response)]
        second = self.responses[1]
        second.update(received_ns=BASE + 160000000, finished_ns=BASE + 190000000)
        loss["after"].update(start_ns=BASE + 180000000, end_ns=BASE + 185000000)
        second["loss_record"] = artifact(canonical(loss))
        second["checkpoint_record"] = artifact(b"fresh opaque checkpoint stand-in")
        self.request_changes = [{}, {}]
        self.event_changes = {}
        self.times = {"BOUND": BASE + 20, "CONNECT_CHECKED": BASE + 140000000,
                      "CONNECT_INTENT": BASE + 150000000, "PAYLOAD_CHECKED": BASE + 195000000,
                      "PAYLOAD_INTENT": BASE + 200000000, "TERMINAL": BASE + 210000000}
        self.transport = canonical({"status": "NOT_PERFORMED", "connect_attempted": False})

    def edit_loss(self, phase, change):
        value = json.loads(base64.b64decode(self.responses[phase]["loss_record"]["base64"]))
        change(value)
        self.responses[phase]["loss_record"] = artifact(canonical(value))

    def build(self, phases=PHASES, terminal_code=None):
        context_raw = canonical(self.context)
        context_pin = digest(context_raw)
        packets = {}
        pair_pins = []
        previous_response = None
        for i, phase in enumerate(("BEFORE_CONNECT", "BEFORE_PAYLOAD_SEND")):
            request = {"schema": "aragorn/native-phase3-broker-reader-request/v1", "phase": phase,
                       "context_digest": context_pin,
                       **{key: self.context[key] for key in ("exchange_id", "epoch_digest", "request_digest", "effect_digest", "deadline_boottime_ns")},
                       "previous_response_digest": previous_response, **self.request_changes[i]}
            request_raw = canonical(request)
            response = {"schema": "aragorn/native-phase3-broker-reader-response/v1",
                        **{key: request[key] for key in ("exchange_id", "phase", "context_digest", "epoch_digest", "request_digest", "effect_digest")},
                        "request_packet_digest": digest(request_raw), **self.responses[i]}
            response_raw = canonical(response)
            pair_pins.append((digest(request_raw), digest(response_raw)))
            packets[digest(request_raw)], packets[digest(response_raw)] = request_raw, response_raw
            previous_response = digest(response_raw)
        if self.transport is not None:
            packets[digest(self.transport)] = self.transport
        events = []
        referenced = set()
        previous = None
        intent = False
        for sequence, phase in enumerate(phases):
            request_pin = response_pin = transport_pin = code = None
            if phase in ("CONNECT_CHECKED", "PAYLOAD_CHECKED"):
                request_pin, response_pin = pair_pins[0 if phase == "CONNECT_CHECKED" else 1]
                referenced.update((request_pin, response_pin))
            if phase in ("CONNECT_INTENT", "PAYLOAD_INTENT"):
                intent = True
            if phase == "TERMINAL":
                code = terminal_code
                if self.transport is not None:
                    transport_pin = digest(self.transport); referenced.add(transport_pin)
            event = {"schema": "aragorn/native-phase3-broker-submission-event/v1", "context_digest": context_pin,
                     "sequence": sequence, "previous_digest": previous, "phase": phase,
                     "checked_ns": self.times[phase], "request_packet_digest": request_pin,
                     "response_packet_digest": response_pin, "transport_digest": transport_pin,
                     "failure_code": code, "intent": intent,
                     "effect_possible": (True if intent else None) if phase == "TERMINAL" else intent,
                     **self.event_changes.get(sequence, {})}
            event_raw = canonical(event); events.append(event_raw); previous = digest(event_raw)
        return context_raw, events, {k: packets[k] for k in referenced}


class SubmissionReplayTests(unittest.TestCase):
    def setUp(self):
        self.t = Transcript()

    def verify(self, transcript=None, terminal=True, **changes):
        context, events, packets = transcript if transcript is not None else self.t.build()
        arguments = {"expected_context_digest": digest(context), "expected_request_digest": self.t.context["request_digest"],
                     "expected_broker": self.t.broker, "expected_provider": self.t.provider,
                     "expected_clock": self.t.clock,
                     "expected_terminal_digest": digest(events[-1]) if terminal and events else None}
        arguments.update(changes)
        return verify_submission_transcript(context, events, packets, **arguments)

    def test_complete_independently_authored_transcript(self):
        result = self.verify()
        self.assertEqual(set(result), {"status", "context_digest", "last_event_digest", "submission_state", *FLAGS})
        self.assertEqual(result["status"], "CONSISTENT_TERMINAL_TRANSCRIPT")
        self.assertEqual(result["submission_state"], "SUBMITTED")
        self.assertTrue(all(result[flag] is False for flag in FLAGS))

    def test_each_open_prefix_and_no_unsubmitted_inference(self):
        for count in range(1, 6):
            with self.subTest(count=count):
                result = self.verify(self.t.build(PHASES[:count]), terminal=False)
                self.assertEqual(result["status"], "CONSISTENT_OPEN_PREFIX")
                self.assertEqual(result["submission_state"], "SUBMITTED" if count >= 3 else "UNKNOWN")

    def test_terminal_after_each_phase_is_conservative(self):
        for count in range(1, 6):
            with self.subTest(count=count):
                result = self.verify(self.t.build((*PHASES[:count], "TERMINAL"), "TRANSPORT_INDETERMINATE"))
                self.assertEqual(result["submission_state"], "SUBMITTED" if count >= 3 else "UNKNOWN")

    def test_unpinned_terminal_is_only_prefix_analysis(self):
        result = self.verify(terminal=False)
        self.assertEqual(result["status"], "CONSISTENT_OPEN_PREFIX")
        self.assertEqual(result["submission_state"], "SUBMITTED")

    def test_missing_or_substituted_expected_terminal_refuses(self):
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:3]))
        with self.assertRaises(ValueError):
            self.verify(expected_terminal_digest=digest(b"other terminal"))

    def test_external_context_request_process_and_clock_pins(self):
        variants = {"expected_context_digest": digest(b"other context"),
                    "expected_request_digest": digest(b"other request"),
                    "expected_broker": {**self.t.broker, "start_time_ticks": 102},
                    "expected_provider": {**self.t.provider, "pid": 602},
                    "expected_clock": {**self.t.clock, "time_namespace": {"device": 5, "inode": 100}}}
        for name, value in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify(**{name: value})

    def test_context_exact_fields_accounts_process_bounds_and_clock(self):
        changes = [lambda c: c.update(extra=1), lambda c: c.update(exchange_id="A" * 64),
                   lambda c: c["broker"].update(pid=True), lambda c: c["broker"].update(pid=2147483648),
                   lambda c: c["broker"].update(uid=4294967296), lambda c: c["broker"].update(start_time_ticks=0),
                   lambda c: c["clock"].update(clock_id="CLOCK_MONOTONIC"),
                   lambda c: c["clock"]["time_namespace"].update(inode=0)]
        for change in changes:
            self.t = Transcript(); change(self.t.context)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        self.t = Transcript(); self.t.broker["uid"] = self.t.context["broker"]["uid"] = 0
        with self.assertRaises(ValueError):
            self.verify()
        self.t = Transcript(); self.t.provider["gid"] = self.t.context["provider"]["gid"] = 1
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_clock_budget_and_accepted_bracket_bound_chronology(self):
        changes = [lambda c: c.update(accepted_boottime_ns=BASE + 1),
                   lambda c: c["clock_bracket"].update(boottime_after_ns=BASE - 1),
                   lambda c: c["clock_bracket"].update(original_monotonic_deadline_ns=700000000),
                   lambda c: c["clock_bracket"].update(original_monotonic_deadline_ns=1200000001),
                   lambda c: c.update(deadline_boottime_ns=BASE + 500000001),
                   lambda c: c["clock_bracket"].update(monotonic_ns=700000001)]
        for change in changes:
            self.t = Transcript(); change(self.t.context)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        self.t = Transcript(); self.t.times["BOUND"] = BASE + 9
        with self.assertRaises(ValueError):
            self.verify()

    def test_event_chain_sequence_order_and_extra_fields(self):
        for change in ({"sequence": True}, {"sequence": 3}, {"previous_digest": None},
                       {"context_digest": digest(b"other")}, {"schema": "other"}, {"extra": 1}):
            self.t.event_changes = {1: change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        self.t.event_changes = {}
        for phases in (("CONNECT_CHECKED",), ("BOUND", "CONNECT_INTENT"),
                       ("BOUND", "CONNECT_CHECKED", "CONNECT_CHECKED"),
                       ("BOUND", "TERMINAL", "CONNECT_CHECKED")):
            with self.subTest(phases=phases), self.assertRaises(ValueError):
                self.verify(self.t.build(phases, "JOURNAL_REFUSED"), terminal=False)

    def test_monotonic_event_time_and_nonterminal_deadline(self):
        for phase, timestamp in (("CONNECT_INTENT", BASE + 139999999),
                                 ("PAYLOAD_INTENT", BASE + 500000000), ("BOUND", True),
                                 ("BOUND", 2**63), ("BOUND", 1.0)):
            self.t = Transcript(); self.t.times[phase] = timestamp
            with self.subTest(phase=phase, timestamp=timestamp), self.assertRaises(ValueError):
                self.verify()

    def test_late_terminal_retains_submitted_ambiguity(self):
        self.t.times["TERMINAL"] = BASE + 900000000
        self.assertEqual(self.verify()["submission_state"], "SUBMITTED")

    def test_packet_echo_and_previous_response_substitution(self):
        variants = ({"exchange_id": "a" * 64}, {"effect_digest": digest(b"other")},
                    {"epoch_digest": digest(b"other")}, {"context_digest": digest(b"other")},
                    {"request_digest": digest(b"other")}, {"deadline_boottime_ns": BASE + 600000000},
                    {"previous_response_digest": digest(b"other")}, {"phase": "BEFORE_CONNECT"})
        for change in variants:
            self.t = Transcript(); self.t.request_changes[1] = change
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        for change in ({"request_packet_digest": digest(b"other")}, {"exchange_id": "c" * 64},
                       {"schema": "other"}, {"healthy": True}):
            self.t = Transcript(); self.t.responses[0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()

    def test_packet_pins_missing_and_unreferenced_extras(self):
        context, events, packets = self.t.build()
        altered = dict(packets); altered.pop(next(iter(altered)))
        with self.assertRaises(ValueError):
            self.verify((context, events, altered))
        altered = dict(packets); first = next(iter(altered)); altered[first] += b"\n"
        with self.assertRaises(ValueError):
            self.verify((context, events, altered))
        context, events, packets = self.t.build(PHASES[:2])
        packets[digest(b"{}")] = b"{}"
        with self.assertRaises(ValueError):
            self.verify((context, events, packets), terminal=False)

    def test_response_status_errors_and_false_flags(self):
        changes = [{"status": "ACK"}, {"status": "REFUSED"}, {"error_codes": ["INTERNAL_REFUSAL"]},
                   {"status": "REFUSED", "error_codes": ["UNKNOWN"]},
                   {"status": "REFUSED", "error_codes": ["READER_REFUSED", "READER_REFUSED"]},
                   {"status": "REFUSED", "error_codes": ["RETENTION_FAILED", "CLEANUP_FAILED"]}]
        changes += [{flag: value} for flag in FLAGS for value in (True, 0, None)]
        for change in changes:
            self.t = Transcript(); self.t.responses[0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(self.t.build(PHASES[:2]), terminal=False)

    def test_refused_ack_looking_partial_evidence_does_not_imply_health(self):
        self.t.responses[0].update(status="REFUSED", error_codes=["RETENTION_FAILED"],
                                   reader_retention=None, loss_record=None, checkpoint_record=None)
        transcript = self.t.build(("BOUND", "CONNECT_CHECKED", "TERMINAL"), "RETENTION_FAILED")
        result = self.verify(transcript)
        self.assertEqual(result["submission_state"], "UNKNOWN")
        self.assertTrue(all(result[key] is False for key in FLAGS))
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:3]), terminal=False)

    def test_refused_without_any_artifacts_is_consistent_but_unknown(self):
        self.t.responses[0].update(status="REFUSED", error_codes=["READER_UNAVAILABLE"],
                                   reader_connection_epoch=None, bindings=None, reader_evidence=None,
                                   reader_summary=None, reader_retention=None, loss_record=None, checkpoint_record=None)
        self.assertEqual(self.verify(self.t.build(PHASES[:2]), terminal=False)["submission_state"], "UNKNOWN")

    def test_evidence_requires_all_artifacts_and_retention_join(self):
        for field in ("reader_connection_epoch", "bindings", "reader_evidence", "reader_summary",
                      "reader_retention", "loss_record", "checkpoint_record"):
            self.t = Transcript(); self.t.responses[0][field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
        for key, value in (("bytes", True), ("bytes", 1), ("digest", digest(b"wrong"))):
            self.t = Transcript(); self.t.responses[0]["reader_retention"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_artifact_base64_size_digest_and_decoded_bounds(self):
        changes = [lambda a: a.update(base64="%%%"), lambda a: a.update(bytes=True),
                   lambda a: a.update(bytes=0), lambda a: a.update(digest=digest(b"other")),
                   lambda a: a.update(base64="Zh==", bytes=1, digest=digest(b"f")),
                   lambda a: a.update(extra=1)]
        for change in changes:
            self.t = Transcript(); change(self.t.responses[0]["checkpoint_record"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        for name, limit in (("reader_evidence", 131072), ("reader_summary", 32768),
                            ("loss_record", 8192), ("checkpoint_record", 16384)):
            self.t = Transcript(); self.t.responses[0][name] = artifact(b"x" * (limit + 1))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()

    def test_loss_pin_shape_counter_types_and_lengths(self):
        changes = [lambda v: v.update(scope_digest=digest(b"other")),
                   lambda v: v.update(challenge_digest=digest(b"other")),
                   lambda v: v.update(extra=1), lambda v: v["before"].update(start_ns=True),
                   lambda v: v["before"].update(start_ns=BASE + 201),
                   lambda v: v["before"].update(counters=[]),
                   lambda v: v["after"].update(counters=[0]),
                   lambda v: v["after"].update(counters=[True, 7]),
                   lambda v: v["after"].update(counters=[0, 2**63])]
        for change in changes:
            self.t = Transcript(); self.t.edit_loss(0, change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(self.t.build(PHASES[:2]), terminal=False)

    def test_unknown_reset_or_lost_counts_cannot_justify_intent(self):
        changes = [lambda v: v.update(before=None), lambda v: v.update(after=None),
                   lambda v: v["before"].update(counters=[None, 7]),
                   lambda v: v["after"].update(counters=[0, None]),
                   lambda v: v["after"].update(counters=[0, 6]),
                   lambda v: v["after"].update(counters=[1, 7])]
        for change in changes:
            self.t = Transcript(); self.t.edit_loss(0, change)
            self.assertEqual(self.verify(self.t.build(PHASES[:2]), terminal=False)["submission_state"], "UNKNOWN")
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(self.t.build(PHASES[:3]), terminal=False)

    def test_phase_two_preserves_reader_connection_evidence_receipt_and_loss_baseline(self):
        changes = [lambda r: r.update(reader_connection_epoch="f" * 64),
                   lambda r: r.update(reader_summary=artifact(b"replacement summary")),
                   lambda r: r["bindings"].update(process=digest(b"replacement process")),
                   lambda r: r["bindings"].update(challenge=digest(b"replacement challenge")),
                   lambda r: r.update(reader_evidence=artifact(b"replacement ACK"))]
        for change in changes:
            self.t = Transcript(); change(self.t.responses[1])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        self.t = Transcript(); self.t.edit_loss(1, lambda v: v["before"].update(start_ns=BASE + 101))
        with self.assertRaises(ValueError):
            self.verify()

    def test_payload_refusal_preserves_submitted_and_accepts_unavailable_loss(self):
        self.t.responses[1].update(status="REFUSED", error_codes=["LOSS_UNAVAILABLE"], loss_record=None)
        result = self.verify(self.t.build((*PHASES[:4], "TERMINAL"), "LOSS_UNAVAILABLE"))
        self.assertEqual(result["submission_state"], "SUBMITTED")
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:5]), terminal=False)

    def test_payload_loss_reset_is_evidenced_but_blocks_payload_intent(self):
        self.t.edit_loss(1, lambda v: v["after"].update(counters=[0, 6]))
        self.assertEqual(self.verify(self.t.build(PHASES[:4]), terminal=False)["submission_state"], "SUBMITTED")
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:5]), terminal=False)

    def test_response_receipt_before_connect_intent_refuses(self):
        self.t.responses[1]["received_ns"] = BASE + 149999999
        with self.assertRaises(ValueError):
            self.verify()

    def test_loss_after_must_be_fresh_inside_each_response_bracket(self):
        for phase, start, end in ((0, BASE + 29999999, BASE + 125000000),
                                  (0, BASE + 120000000, BASE + 130000001),
                                  (1, BASE + 120000000, BASE + 125000000),
                                  (1, BASE + 180000000, BASE + 190000001)):
            self.t = Transcript(); self.t.edit_loss(phase, lambda v: v["after"].update(start_ns=start, end_ns=end))
            with self.subTest(phase=phase, start=start), self.assertRaises(ValueError):
                self.verify()

    def test_response_phase_budget_deadline_and_staleness(self):
        cases = [(0, "received_ns", BASE + 9), (0, "received_ns", BASE + 130000001),
                 (0, "finished_ns", BASE + 280000001), (1, "finished_ns", BASE + 260000001),
                 (1, "finished_ns", BASE + 500000000)]
        for phase, field, value in cases:
            self.t = Transcript(); self.t.responses[phase][field] = value
            with self.subTest(phase=phase, field=field), self.assertRaises(ValueError):
                self.verify()
        self.t = Transcript(); self.t.times["CONNECT_CHECKED"] = BASE + 330000000
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:2]), terminal=False)
        self.t = Transcript(); self.t.times["CONNECT_INTENT"] = BASE + 330000000
        with self.assertRaises(ValueError):
            self.verify(self.t.build(PHASES[:3]), terminal=False)
        # Hold other brackets valid so only the per-phase acquisition cap changes.
        for phase, finished, checked in ((0, 280000000, 290000000), (1, 260000000, 270000000)):
            self.t = Transcript()
            self.t.responses[phase]["finished_ns"] = BASE + finished
            self.t.times["CONNECT_CHECKED" if phase == 0 else "PAYLOAD_CHECKED"] = BASE + checked
            phases = PHASES[:2 if phase == 0 else 4]
            self.assertEqual(self.verify(self.t.build(phases), terminal=False)["status"], "CONSISTENT_OPEN_PREFIX")
            self.t.responses[phase]["finished_ns"] += 1
            with self.subTest(cap_phase=phase), self.assertRaises(ValueError):
                self.verify(self.t.build(phases), terminal=False)

    def test_intent_flags_cannot_downgrade_or_use_integers(self):
        for index in range(6):
            for name in ("intent", "effect_possible"):
                for value in (0, 1, None):
                    self.t.event_changes = {index: {name: value}}
                    with self.subTest(index=index, name=name, value=value), self.assertRaises(ValueError):
                        self.verify()
        self.t.event_changes = {5: {"intent": False, "effect_possible": False}}
        with self.assertRaises(ValueError):
            self.verify()

    def test_terminal_failure_enum_null_success_and_opaque_transport(self):
        for code in ("CLEANUP_FAILED", "RETENTION_FAILED", "TRANSPORT_REFUSED", "POLICY_REFUSED", "JOURNAL_REFUSED"):
            with self.subTest(code=code):
                self.assertEqual(self.verify(self.t.build(terminal_code=code))["submission_state"], "SUBMITTED")
        with self.assertRaises(ValueError):
            self.verify(self.t.build(terminal_code="UNKNOWN"))
        with self.assertRaises(ValueError):
            self.verify(self.t.build(("BOUND", "TERMINAL")))
        self.t.transport = None
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.verify(self.t.build(terminal_code="JOURNAL_REFUSED"))["submission_state"], "SUBMITTED")

    def test_unexpected_packet_and_terminal_fields_refuse(self):
        for index, change in ((0, {"request_packet_digest": digest(b"other")}),
                              (0, {"transport_digest": digest(b"other")}),
                              (1, {"failure_code": "CLEANUP_FAILED"})):
            self.t.event_changes = {index: change}
            with self.subTest(index=index, change=change), self.assertRaises(ValueError):
                self.verify()

    def test_opaque_transport_claims_never_attest_health_lock_or_nonsubmission(self):
        self.t.transport = canonical({"status": "NOT_SUBMITTED", "healthy": True, "lock_custody": "EXCLUSIVE"})
        result = self.verify()
        self.assertEqual(result["submission_state"], "SUBMITTED")
        self.assertTrue(all(result[key] is False for key in FLAGS))
        self.t.responses[0]["credentials_abi"] = "linux-le-ucred32-v1"
        with self.assertRaises(ValueError):
            self.verify()

    def test_canonical_json_duplicates_nonfinite_nonascii_and_trailing_bytes(self):
        context, events, packets = self.t.build()
        for value in (context + b"\n", b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b'{"x":1e999}'):
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                self.verify((value, events, packets))
        malformed_events = list(events); malformed_events[0] += b" "
        with self.assertRaises(ValueError):
            self.verify((context, malformed_events, packets))
        self.t.transport += b"\n"
        with self.assertRaises(ValueError):
            self.verify()

    def test_all_raw_bounds_counts_and_aggregate_before_parsing(self):
        context, events, packets = self.t.build()
        for transcript in ((b"x" * 8193, events, packets), (context, [], {}),
                           (context, events * 2, packets), (context, [b"x" * 8193], {}),
                           (context, events, {digest(b"x" * 262145): b"x" * 262145})):
            with self.assertRaises(ValueError):
                self.verify(transcript, terminal=False)
        extra = {digest(str(i).encode()): str(i).encode() for i in range(6)}
        with self.assertRaises(ValueError):
            self.verify((context, events, extra), terminal=False)
        large = {digest(bytes([i]) * 160000): bytes([i]) * 160000 for i in range(5)}
        with self.assertRaises(ValueError):
            self.verify((context, events, large), terminal=False)
        self.t.transport = canonical({"opaque": "x" * 32769})
        with self.assertRaises(ValueError):
            self.verify()

    def test_replay_leaves_inputs_unchanged(self):
        transcript = self.t.build()
        before = copy.deepcopy(transcript)
        self.verify(transcript)
        self.assertEqual(transcript, before)


if __name__ == "__main__":
    unittest.main()
