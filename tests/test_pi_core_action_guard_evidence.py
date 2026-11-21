"""Real guarded action transport/receipt transitions; source, clocks, store and socket edges are inert."""
import copy
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_action_evidence as evidence
from aragorn import pi_core_request_handoff as handoff
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_action_evidence as terminal_owner
from tests import test_pi_core_action_evidence_composition as composition
from tests import test_pi_core_action_evidence_store as store_fixture
from tests import test_pi_core_node_source_observer as node
from tests import test_pi_core_provider_observation as provider
from tests import test_pi_core_request_handoff as wire
from tests import test_pi_core_request_terminal as terminal


class GuardBoundary(terminal.RootTests):
    @classmethod
    def setUpClass(cls):
        cls.source = provider.provider_inputs()

    def setUp(self):
        super().setUp()  # forbids OS/process/socket access; keeps real protocol validation
        self.trace = copy.deepcopy(self.source["source_capture"])
        self.activation = wire.activation()
        for field in ("pid", "start_time_ticks", "uid", "gid", "cgroup", "boot_id", "runtime_digest",
                      "deployment_digest", "executable_digest"):
            self.activation[field] = self.source["activation"][field]
        self.read_activation.return_value = self.activation
        handoff.broker._peer_credentials.return_value = tuple(self.activation[k] for k in ("pid", "uid", "gid"))
        self.binding = handoff.worker.RuntimeActionWorkerBinding(
            self.activation["runtime_digest"], self.activation["active_skill_digest"], self.activation["policy_digest"], 1)
        self.custody._channels = SimpleNamespace(binding=self.binding)
        self.owner = evidence.PiNativeActionEvidence(evidence._SEAL, self.custody)
        self.owner._active, self.owner._activation, self.owner._grant, self.owner._deadline = True, self.activation, {}, 120.
        self.owner._record["activation_digest"] = canonical_digest(self.activation)
        self.store = self.owner._store = terminal_owner.InertStore(self.events, self.activation)
        # Focus on CHECK/CURRENT: real caller, guard proof, storage input, terminal joining and actual return hook.
        # Source acquire, root FD/generation checks, broker control reread and sockets have separate fixture owners.
        self.owner._guard = mock.Mock()
        self.owner._readback = mock.Mock()
        self.fields = wire.fields() | dict(activation_digest=canonical_digest(self.activation))
        self.check = handoff._packet("CHECK", **self.fields, sequence=1, terminal_ack=True)
        self.packet_list[1] = (self.check, ())
        done = self.packet_list[-1][0]
        done.update(self.fields)
        done["envelope"]["request"]["runtime_digest"] = self.activation["runtime_digest"]
        done["result"]["broker_result"]["request_digest"] = canonical_digest(done["envelope"]["request"])
        self.ticket.terminal_receipt = handoff.sensor_transport._packet("DONE", nonce="d" * 32,
            request_digest=self.fields["request_digest"], deadline_ns=self.fields["deadline_ns"],
            broker_result_digest=canonical_digest(done["result"]["broker_result"]), terminal_ack=True)
        body = canonical_json(wire.request())
        self.stack.enter_context(mock.patch.object(handoff.broker, "_receive_exact",
            side_effect=(handoff.broker._FRAME_HEADER.pack(len(body)), body)))
        self.stack.enter_context(mock.patch.object(handoff.broker, "_require_eof"))
        self.tick_value = self.trace["events"][-1]["boottime_ns"] + 1
        def tick():
            result = self.tick_value
            self.tick_value += 1
            self.events.append(("clock", result))
            return result
        self.tick = self.stack.enter_context(mock.patch.object(evidence, "_boottime_ns", side_effect=tick))
        self.time_ns = self.stack.enter_context(mock.patch.object(evidence, "_time_namespace_inode",
                                                                 return_value=self.trace["clock"]["time_namespace_inode"]))
        self.final_reads = 0
        self.acquire = lambda: self.trace
        def guard():
            # Only the final guard used in preparation supplies evidence. A subsequent guard cannot
            # silently replace it; returning None anywhere else exposes accidental re-acquisition.
            if self.owner._send_phase == "PREPARING":
                self.final_reads += 1
                return self.acquire()
            return None
        self.guard.side_effect = guard

    def run_action(self):
        return self.handle(action_evidence=self.owner, binding=self.binding)

    def records(self, kind):
        return [raw for label, raw in self.store.values if label == kind]

    def test_real_current_send_bracket_uses_same_raw_guard_after_original_source_changes(self):
        start, original, store = self.tick_value, copy.deepcopy(self.trace), self.store.retain
        def retain(kind, value):
            result = store(kind, value)
            if kind == "CURRENT_ATTEMPT":
                # Mutate acquisition-side copy after durable write; owner must retain the actual prefix.
                self.trace["state"] = "withdrawn-input-copy"
            return result
        self.store.retain = retain
        self.assertEqual(self.run_action()["status"], "COMPLETED")
        check, = self.records("CHECK")
        attempt, = self.records("CURRENT_ATTEMPT")
        summary, = self.records("CURRENT_SEND_SUMMARY")
        self.assertEqual(check, self.check)
        self.assertEqual(attempt["source_capture"], original)
        self.assertEqual((attempt["check_digest"], attempt["sequence"], attempt["current"]),
                         (canonical_digest(check), 1, check | dict(kind="CURRENT")))
        self.assertEqual(attempt["boundary"]["boundary_boottime_ns"], start)
        self.assertEqual(summary["rows"], [dict(sequence=1, attempt_digest=canonical_digest(attempt),
            before_send_boottime_ns=start+2, send_returned_boottime_ns=start+3)])
        index = self.events.index("CURRENT")
        self.assertEqual(self.events[index-1:index+2], [("clock", start+2), "CURRENT", ("clock", start+3)])
        self.assertEqual(self.final_reads, 1)
        self.assertIs(self.owner.observation["health_verified"], False)
        self.assertIs(self.owner.observation["effect_verified"], False)
        self.assertIs(self.owner.observation["timing_verified"], False)

    def test_mismatched_check_is_retained_but_not_challenged_or_sent(self):
        self.check["nonce"] = "e" * 32
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertEqual(self.records("CHECK"), [self.check])
        self.assertEqual((self.final_reads, self.records("CURRENT_ATTEMPT"), self.events.count("CURRENT")), (0, [], 0))

    def test_missing_capture_does_not_substitute_a_mutable_snapshot_or_repeat_guard(self):
        self.acquire = lambda: None
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertEqual(self.final_reads, 1)
        self.assertEqual(self.records("CURRENT_ATTEMPT"), [])
        self.assertNotIn("CURRENT", self.events)
        self.assertEqual(self.records("FAILURE")[0]["stage"], "CURRENT_PREPARATION")

    def test_stale_during_storage_no_send_no_substitute_and_no_new_challenge(self):
        start = self.tick_value
        self.tick.side_effect = [start, start+10, self.trace["events"][-1]["boottime_ns"]+200_000_001]
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertEqual(self.final_reads, 1)
        self.assertEqual(len(self.records("CURRENT_ATTEMPT")), 1)
        row, = self.records("FAILURE")[0]["current_send_summary"]["rows"]
        self.assertIsNone(row["before_send_boottime_ns"])
        self.assertIsNone(row["send_returned_boottime_ns"])
        self.assertNotIn("CURRENT", self.events)

    def test_changed_namespace_before_send_refuses_same_boot_ticks(self):
        ns = self.trace["clock"]["time_namespace_inode"]
        self.time_ns.side_effect = [ns, ns+1]
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertNotIn("CURRENT", self.events)
        self.assertEqual(self.records("FAILURE")[0]["stage"], "CURRENT_FINAL_CHECK")
        self.assertEqual(self.final_reads, 1)

    def test_original_operation_deadline_cannot_be_extended_by_fresh_health(self):
        store = self.store.retain
        def retain(kind, value):
            ref = store(kind, value)
            if kind == "CURRENT_ATTEMPT":
                handoff.time.monotonic_ns.return_value = self.fields["deadline_ns"]
            return ref
        self.store.retain = retain
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertNotIn("CURRENT", self.events)
        self.assertEqual(self.records("FAILURE")[0]["stage"], "CURRENT_FINAL_CHECK")
        self.assertEqual(self.final_reads, 1)

    def test_wrong_generation_incomplete_acquisition_and_oversize_never_reach_attempt_store(self):
        # Isolate each attempt: failed owners and authenticated sequences are never reused.
        for transform in (lambda c: c["worker"].update(start_ticks=c["worker"]["start_ticks"]+1),
                          lambda c: c["accounting"].update(pending_reads=1),
                          lambda c: c.update(extra="x" * evidence.storage._MAX_RECORD)):
            with self.subTest(transform=transform):
                owner = self.local_owner()
                capture = copy.deepcopy(self.trace)
                transform(capture)
                guard = mock.Mock(return_value=capture)
                with self.assertRaises((RuntimeError, ValueError)):
                    owner.prepare_current(self.check, self.check | dict(kind="CURRENT"), guard)
                guard.assert_called_once()
                self.assertFalse(any(k == "CURRENT_ATTEMPT" for k, _ in owner._store.values))

    def local_owner(self):
        owner = evidence.PiNativeActionEvidence(evidence._SEAL, self.custody)
        owner._active, owner._deadline, owner._activation = True, 120., self.activation
        owner._record["activation_digest"] = canonical_digest(self.activation)
        owner._guard = mock.Mock()
        owner._store = terminal_owner.InertStore([], self.activation)
        owner.retain("REQUEST_CONTEXT", dict(activation=self.activation, request=wire.request(),
            challenge=self.packet_list[0][0], offer_intent=handoff._packet("OFFER", **self.fields,
                                            activation=self.activation, worker_request=wire.request(), terminal_ack=True)))
        owner.retain("CHECK", self.check)
        return owner

    def test_mutated_check_or_different_sequence_refuses_before_final_challenge(self):
        for check, current in ((self.check | dict(sequence=2), self.check | dict(kind="CURRENT", sequence=2)),
                               (self.check, self.check | dict(kind="CURRENT", sequence=2))):
            owner, guard = self.local_owner(), mock.Mock()
            with self.assertRaises(RuntimeError):
                owner.prepare_current(check, current, guard)
            guard.assert_not_called()

    def test_socket_exception_has_no_return_mark_no_retry_and_no_terminal_ack(self):
        original = self.send.side_effect
        def send(*args, **kwargs):
            original(*args, **kwargs)
            if args[1]["kind"] == "CURRENT":
                raise OSError("unknown handoff")
        self.send.side_effect = send
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertEqual(self.events.count("CURRENT"), 1)
        failure, = self.records("FAILURE")
        self.assertEqual(failure["stage"], "CURRENT_SEND")
        row, = failure["current_send_summary"]["rows"]
        self.assertIsInstance(row["before_send_boottime_ns"], int)
        self.assertIsNone(row["send_returned_boottime_ns"])
        self.assertEqual(self.records("CURRENT_SEND_SUMMARY"), [])
        self.retire.assert_not_called()

    def test_attempt_storage_failure_does_not_send_or_recover_an_effect(self):
        self.store.failure_kind = "CURRENT_ATTEMPT"
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertNotIn("CURRENT", self.events)
        self.owner._readback.assert_not_called()
        self.retire.assert_not_called()
        self.assertEqual((self.final_reads, self.events.count(("retain", "CURRENT_ATTEMPT"))), (1, 1))
        self.assertTrue(self.owner._cleanup_hold)

    def test_summary_retention_failure_after_send_keeps_attempt_but_withholds_ack(self):
        self.store.failure_kind = "CURRENT_SEND_SUMMARY"
        self.assertEqual(self.run_action()["status"], "INDETERMINATE")
        self.assertEqual(self.events.count("CURRENT"), 1)
        self.assertEqual(len(self.records("CURRENT_ATTEMPT")), 1)
        self.assertEqual(self.events.count(("retain", "CURRENT_SEND_SUMMARY")), 1)
        self.assertEqual(self.records("CURRENT_SEND_SUMMARY"), [])
        # An uncertain summary write closes the store to every later append.
        self.assertNotIn(("retain", "FAILURE"), self.events)
        self.assertTrue(self.owner._cleanup_hold)
        self.assertIn({"stage": "RETAIN", "reason": "STORAGE_RETENTION_UNCONFIRMED"},
                      self.owner.observation["cleanup_uncertainty"])
        self.retire.assert_not_called()

    def test_sixteen_cumulative_real_producer_prefixes_fit_original_capacity_and_no_seventeenth_guard(self):
        # Make exactly the maximum useful number of inert kernel challenges once. No execution or VM.
        prefixes = node.build_inert_node_source_capture(challenges=16)["prefixes"]
        def acquire():
            capture = prefixes[self.final_reads-1]
            self.tick_value = capture["events"][-1]["boottime_ns"]+1
            return capture
        self.acquire = acquire
        self.packet_list[1:2] = [(self.check | dict(sequence=i), ()) for i in range(1, 17)]
        receive = self.receive.side_effect
        def packet(*args, **kwargs):
            data = receive(*args, **kwargs)
            if data[0]["kind"] == "DONE":
                # Before terminal completion, the prior valid 16 have exhausted the existing limit.
                with self.assertRaisesRegex(RuntimeError, "CHECK_ALREADY_BOUND"):
                    self.owner.retain("CHECK", self.check | dict(sequence=17))
            return data
        self.receive.side_effect = packet
        self.assertEqual(self.run_action()["status"], "COMPLETED")
        self.assertEqual((len(self.records("CURRENT_ATTEMPT")), self.final_reads, self.events.count("CURRENT")), (16,16,16))
        rows = self.records("CURRENT_SEND_SUMMARY")[0]["rows"]
        self.assertEqual([r["sequence"] for r in rows], list(range(1,17)))
        self.assertLess(len(self.store.values), evidence.storage._MAX_RECORDS)
        self.assertEqual(self.final_reads, 16)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(GuardBoundary(name) for name in GuardBoundary.__dict__ if name.startswith("test_"))
    for cls, names in (
        (terminal_owner.NativeActionEvidenceTests, ("test_completed_allow_retains_original_records_and_closes_only_owned_handles",
            "test_terminal_records_precede_locked_readback_and_store_closes_before_control")),
        (composition.HandoffTests, ("test_context_check_current_attempt_precede_actual_sends",
            "test_invalid_check_retained_without_current_attempt",
            "test_uncertain_current_send_keeps_attempt_without_retry")),
        (store_fixture.ActionEvidenceStoreTests, ("test_exact_action_schema_kinds_and_ordered_private_references",)),
    ):
        suite.addTests(cls(name) for name in names)
    return suite
