"""Inert B77 replay using the existing complete Node trace fixture and a real local CAS."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import pi_core_action_boundary_verify as verify
from aragorn import pi_core_action_evidence as producer
from tests import test_pi_core_node_source_replay as node_fixtures
from tests import test_pi_core_request_handoff as packet_fixtures


class ActionBoundaryReplayTests(unittest.TestCase):
    def setUp(self):
        self.f = node_fixtures.NodeReplayTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.put = lambda obj: self.f.put(canonical_json(obj))
        args = self.f.arguments
        worker, bindings, clock = (args[k] for k in ("expected_worker", "expected_bindings", "expected_clock"))
        a = packet_fixtures.activation() | {k: worker[k] for k in ("pid", "uid", "gid", "cgroup")}
        a.update(start_time_ticks=worker["start_ticks"], boot_id=clock["boot_id"], executable_digest=bindings["node_digest"],
                 runtime_digest=bindings["runtime_digest"], deployment_digest=bindings["deployment_digest"])
        self.args = dict(expected_activation=a, expected_request=packet_fixtures.request(), expected_broker_nonce="b"*32,
                         expected_deadline_ns=a["expires_at_monotonic_ns"], evidence_cas=CAS(self.f.cas.root, read_only=True),
                         source_expectations={k: deepcopy(args[k]) for k in verify._SOURCE_ARGS})
        self.entries, self.rows, self.selections = [], [], []
        self.append()

    def append(self):
        n = len(self.entries) + 1
        record, challenge = deepcopy(self.f.record), dict(self.f.challenge)
        if n > 1:
            self.f.challenge["nonce"] = "d"*64
            self.f.finish(deepcopy(self.f.record["events"]))
            # A second challenge starts after the first recorded local send.
            self.f.challenge["issued_ns"] += 5
            self.f.challenge["deadline_ns"] += 5
            self.f.record["events"][-1].update(self.f.challenge)
            record, challenge = deepcopy(self.f.record), dict(self.f.challenge)
        a = canonical_digest(self.args["expected_activation"])
        check = verify._packet("CHECK", terminal_ack=True, sequence=n, nonce=self.args["expected_broker_nonce"],
            activation_digest=a, request_digest=canonical_digest(self.args["expected_request"]),
            deadline_ns=self.args["expected_deadline_ns"])
        tick = record["events"][-1]["boottime_ns"]
        attempt = dict(schema="aragorn/pi-core-action-current-attempt/v2", activation_digest=a, check_digest=self.put(check),
            sequence=n, current=check | {"kind": "CURRENT"}, source_capture=record,
            boundary=dict(clock=deepcopy(self.args["source_expectations"]["expected_clock"]), challenge=challenge,
                          boundary_boottime_ns=tick + 1))
        self.entries.append(attempt)
        self.selections.append(dict(check_digest=attempt["check_digest"], attempt_digest=self.put(attempt),
                                    observation_digest=self.put(record), challenge=dict(challenge)))
        self.rows.append(dict(sequence=n, attempt_digest=self.selections[-1]["attempt_digest"],
                              before_send_boottime_ns=tick + 2, send_returned_boottime_ns=tick + 3))

    def replay(self, **overrides):
        summary = dict(schema="aragorn/pi-core-action-current-sends/v1",
                       activation_digest=canonical_digest(self.args["expected_activation"]), rows=self.rows)
        return verify.verify_action_current_boundaries(**(self.args | dict(expected_summary_digest=self.put(summary),
             selections=self.selections) | overrides))

    def repin_attempt(self, index):
        pin = self.put(self.entries[index])
        self.selections[index]["attempt_digest"] = self.rows[index]["attempt_digest"] = pin

    def test_two_challenges_replay_only_records_of_local_returns(self):
        self.append()
        report = self.replay()
        self.assertEqual(report["completed_sequences"], 2)
        self.assertTrue(all(report[k] is False for k in ("acquisition_authenticity_verified", "broker_receipt_verified",
                            "effect_verified", "sensor_health_verified", "phase3_qualified")))

    def test_actual_producer_envelopes_are_accepted_by_independent_reader(self):
        owner = producer.PiNativeActionEvidence(producer._SEAL, None)
        a, request = self.args["expected_activation"], self.args["expected_request"]
        current = self.entries[0]["current"]
        check = current | {"kind": "CHECK"}
        fields = {k: current[k] for k in ("nonce", "activation_digest", "request_digest", "deadline_ns")}
        owner._deadline, owner._activation, owner._active = 120.0, a, True
        owner._record["activation_digest"] = canonical_digest(a)
        owner._context = dict(activation=a, request=request, offer_intent=verify._packet("OFFER", terminal_ack=True,
            **fields, activation=a, worker_request=request), challenge=verify._packet("CHALLENGE", terminal_ack=True,
                                                                                    nonce=fields["nonce"]))
        saved = {}
        def retain(kind, value):
            saved[kind] = self.put(value)
            return dict(kind=kind, digest=saved[kind], bytes=len(canonical_json(value)))
        owner._store = SimpleNamespace(retain=retain)
        tick = self.f.record["events"][-1]["boottime_ns"]
        with patch.object(owner, "_guard"), patch.object(producer, "_time_namespace_inode", return_value=22), \
                patch.object(producer, "_boottime_ns", side_effect=[tick+i for i in (1, 2, 3, 4)]), \
                patch.object(producer.channel, "validate_deadline"), patch.object(producer.time, "monotonic_ns", return_value=1):
            owner.retain("CHECK", check)
            owner.prepare_current(check, current, lambda: self.f.record)
            owner.before_current_send(current)
            owner.current_send_returned(current)  # Inert simulation of normal local return, no socket.
            owner._finish_current_sends()
        selection = dict(self.selections[0], check_digest=saved["CHECK"], attempt_digest=saved["CURRENT_ATTEMPT"])
        result = verify.verify_action_current_boundaries(**self.args, selections=[selection],
                                                         expected_summary_digest=saved["CURRENT_SEND_SUMMARY"])
        self.assertEqual(result["completed_sequences"], 1)
        self.assertFalse(result["effect_verified"])

    def test_pin_and_activation_request_broker_and_source_expectations_cannot_be_self_selected_from_attempt(self):
        for changes in (dict(expected_request=self.args["expected_request"] | {"target_name": "other.txt"}),
                        dict(expected_activation=self.args["expected_activation"] | {"pid": 102}),
                        dict(expected_broker_nonce="d"*32), dict(expected_deadline_ns=1),
                        dict(expected_summary_digest=self.selections[0]["attempt_digest"]),
                        dict(source_expectations=self.args["source_expectations"] | {
                            "expected_gate_identity": self.f.identity(99, 1, 0o100555)})):
            with self.subTest(keys=list(changes)), self.assertRaises(ValueError):
                self.replay(**changes)

    def test_zero_short_out_of_order_and_stale_send_rows_do_not_prove_local_return(self):
        first = self.rows[0].copy()
        stale = self.f.record["events"][-1]["boottime_ns"] + 200_000_001
        for rows in ([], [first | {"sequence": True}], [first | {"send_returned_boottime_ns": None}],
                     [first | {"before_send_boottime_ns": first["send_returned_boottime_ns"]+1}],
                     [first | {"before_send_boottime_ns": stale, "send_returned_boottime_ns": stale+1}],
                     [first | {"attempt_digest": self.selections[0]["observation_digest"]}]):
            self.rows = rows
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.replay()

    def test_acquisition_deadline_is_not_a_send_lease(self):
        self.rows[0].update(before_send_boottime_ns=130_000_000, send_returned_boottime_ns=400_000_000)
        self.assertEqual(self.replay()["completed_sequences"], 1)

    def test_rehashed_attempt_with_wrong_check_or_altered_clock_still_refuses(self):
        item = self.entries[0]
        original = deepcopy(item)
        for mutate in (lambda r: r.update(check_digest=self.selections[0]["observation_digest"]),
                       lambda r: r["current"].update(sequence=2),
                       lambda r: r["boundary"]["clock"].update(time_namespace_inode=33),
                       lambda r: r["boundary"].update(boundary_boottime_ns=1)):
            item.clear()
            item.update(deepcopy(original))
            mutate(item)
            self.repin_attempt(0)
            with self.assertRaises(ValueError):
                self.replay()

    def test_embedded_object_is_not_automatically_supplied_as_a_cas_blob(self):
        item = self.entries[0]
        item["source_capture"]["accounting"]["bytes_read"] += 1
        # Pin a changed envelope AND its claimed trace digest, but do not
        # export that trace. The independently invoked Node reader must refuse.
        self.selections[0]["observation_digest"] = canonical_digest(item["source_capture"])
        self.repin_attempt(0)
        with self.assertRaises(CASError):
            self.replay()
        with self.assertRaises(ValueError):
            self.replay(evidence_cas=self.f.cas)

    def test_individually_replayable_but_forked_challenge_history_is_rejected(self):
        self.append()
        trace = self.entries[1]["source_capture"]
        trace["events"][len(self.entries[0]["source_capture"]["events"])-1]["nonce"] = "e"*64
        self.selections[1]["observation_digest"] = self.put(trace)
        self.repin_attempt(1)
        with self.assertRaisesRegex(ValueError, "CAPTURE_FORK"):
            self.replay()
