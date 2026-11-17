"""Focused inert action evidence/caller joins, not deployment or effect proof.

Existing fixtures trap process/socket/filesystem activation. Only actual new
caller boundaries are selected; imported historical suites are not discovered.
"""

import base64
import copy
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest import mock

from aragorn import pi_core_action_evidence as evidence
from aragorn import pi_core_native_request as native
from aragorn import pi_core_request_handoff as handoff
from aragorn import pi_core_sensor_channel as sensor
from aragorn import pi_core_service_channels as channels
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_native_request as native_fixtures
from tests import test_pi_core_request_handoff as handoff_fixtures
from tests import test_pi_core_request_terminal as terminal_fixtures
from tests import test_pi_core_sensor_channel as sensor_fixtures
from tests import test_pi_core_sensor_terminal as sensor_terminal_fixtures


def closed_observation():
    return {"schema": evidence.SCHEMA, "authority": evidence.AUTHORITY,
        "status": "CLOSED", "owned_handles_closed": True,
        "receipt_join_verified": True, "phase3_exit_eligible": False,
        "retained_evidence": {"records": [{"kind": "ACTION_DONE"}]}}


class HandoffTests(terminal_fixtures.RootTests):
    def setUp(self):
        super().setUp()
        self.evidence = object.__new__(evidence.PiNativeActionEvidence)
        self.evidence._custody = self.custody
        self.records = []
        self.body = canonical_json(handoff_fixtures.request())
        self.header = handoff.broker._FRAME_HEADER.pack(len(self.body))
        self.ticket.terminal_receipt = {"fixture": "actual-sensor-DONE"}

        def receive_exact(connection, size, deadline):
            self.assertIs(connection, self.worker)
            self.assertEqual(deadline, 120.0)
            if size == handoff.broker._FRAME_HEADER.size:
                self.events.append("header")
                return self.header
            self.assertEqual(size, len(self.body))
            self.events.append("body")
            return self.body

        def retain(owner, kind, value):
            self.assertIs(owner, self.evidence)
            self.records.append((kind, copy.deepcopy(value)))
            self.events.append("retain:" + kind)

        def complete(owner, **values):
            self.assertIs(owner, self.evidence)
            self.assertEqual(values, {"done": self.done,
                "sensor_done": self.ticket.terminal_receipt,
                "result": handoff_fixtures.result()})
            self.events.append("readback_complete")

        self.done = copy.deepcopy(self.packet_list[-1][0])
        self.exact = self.stack.enter_context(mock.patch.object(handoff.broker,
            "_receive_exact", side_effect=receive_exact))
        self.eof = self.stack.enter_context(mock.patch.object(handoff.broker,
            "_require_eof", side_effect=lambda *args: self.events.append("EOF")))
        parse = handoff.broker._parse_canonical_document
        self.parse = self.stack.enter_context(mock.patch.object(handoff.broker,
            "_parse_canonical_document", side_effect=lambda *args: (self.events.append("parse"), parse(*args))[1]))
        self.retain = self.stack.enter_context(mock.patch.object(evidence.PiNativeActionEvidence,
            "retain", autospec=True, side_effect=retain))
        self.complete = self.stack.enter_context(mock.patch.object(evidence.PiNativeActionEvidence,
            "complete", autospec=True, side_effect=complete))

    def handle(self, **changes):
        return super().handle(**{"action_evidence": self.evidence, **changes})

    def retained(self, kind):
        return [value for name, value in self.records if name == kind]

    def assert_no_release(self):
        self.retire.assert_not_called()
        self.ticket.acknowledge.assert_not_called()
        self.assertNotIn("ACK", self.events)
        self.deliver.assert_not_called()

    def test_header_and_body_are_retained_before_eof_or_parse(self):
        self.assertEqual(self.handle(), handoff_fixtures.result())
        prefix = [name for name in self.events if name in
            ("header", "body", "retain:REQUEST_FRAME", "EOF", "parse")]
        self.assertEqual(prefix, ["header", "retain:REQUEST_FRAME", "body",
            "retain:REQUEST_FRAME", "EOF", "parse"])
        first, full = self.retained("REQUEST_FRAME")
        self.assertEqual(base64.b64decode(first["header_base64"]), self.header)
        self.assertIsNone(first["body_base64"])
        self.assertIs(first["body_complete"], False)
        self.assertEqual(base64.b64decode(full["body_base64"]), self.body)
        self.assertIs(full["body_complete"], True)
        for row in (first, full):
            self.assertIs(row["parsed"], False)
            self.assertIs(row["eof_verified"], False)
        self.read.assert_not_called()
        self.deliver.assert_not_called()

    def test_invalid_length_retains_only_received_header(self):
        self.header = handoff.broker._FRAME_HEADER.pack(0)
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.exact.assert_called_once()
        self.assertEqual(len(self.retained("REQUEST_FRAME")), 1)
        self.assertIsNone(self.retained("REQUEST_FRAME")[0]["body_base64"])
        self.assertEqual(self.retained("FAILURE")[0]["stage"], "REQUEST_FRAME")
        self.eof.assert_not_called()
        self.parse.assert_not_called()
        self.assert_no_release()

    def test_short_body_keeps_header_without_inventing_partial_bytes(self):
        self.exact.side_effect = [self.header, TimeoutError("short body")]
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.assertEqual(self.exact.call_count, 2)
        self.assertEqual(len(self.retained("REQUEST_FRAME")), 1)
        self.assertIsNone(self.retained("REQUEST_FRAME")[0]["body_base64"])
        self.eof.assert_not_called()
        self.parse.assert_not_called()
        self.assert_no_release()

    def test_short_header_has_no_fabricated_frame(self):
        self.exact.side_effect = TimeoutError("short header")
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.assertEqual(self.retained("REQUEST_FRAME"), [])
        self.assertEqual(len(self.retained("FAILURE")), 1)
        self.assert_no_release()

    def test_eof_refusal_preserves_full_bytes_without_parsing(self):
        self.eof.side_effect = RuntimeError("extra frame bytes")
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.assertEqual(base64.b64decode(self.retained("REQUEST_FRAME")[-1]["body_base64"]), self.body)
        self.parse.assert_not_called()
        self.assert_no_release()

    def test_malformed_json_remains_raw_evidence_without_offer(self):
        self.body = b"{broken"
        self.header = handoff.broker._FRAME_HEADER.pack(len(self.body))
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.assertEqual(base64.b64decode(self.retained("REQUEST_FRAME")[-1]["body_base64"]), self.body)
        self.parse.assert_called_once()
        self.send.assert_not_called()
        self.assert_no_release()

    def test_header_storage_failure_prevents_body_read(self):
        self.retain.side_effect = OSError("storage unavailable")
        with self.assertRaises(handoff.PiRequestHandoffError): self.handle()
        self.exact.assert_called_once()
        self.eof.assert_not_called()
        self.assert_no_release()

    def test_exact_owner_and_native_custody_are_required_before_read(self):
        for owner in ({"authorized": True}, object()):
            with self.subTest(owner=type(owner)), self.assertRaises(RuntimeError):
                self.handle(action_evidence=owner)
        self.evidence._custody = object()
        with self.assertRaises(RuntimeError): self.handle()
        self.exact.assert_not_called()
        self.retain.assert_not_called()

    def test_action_evidence_cannot_select_legacy_mode(self):
        with self.assertRaises(RuntimeError): self.handle(terminal_ack=False)
        self.exact.assert_not_called()

    def test_context_check_current_attempt_precede_actual_sends(self):
        self.handle()
        for left, right in (("retain:REQUEST_CONTEXT", "OFFER"),
                            ("retain:CHECK", "retain:CURRENT_ATTEMPT"),
                            ("retain:CURRENT_ATTEMPT", "CURRENT")):
            self.assertLess(self.events.index(left), self.events.index(right))
        context = self.retained("REQUEST_CONTEXT")[0]
        self.assertEqual(context["request"], handoff_fixtures.request())
        self.assertEqual(context["activation"], handoff_fixtures.activation())
        self.assertEqual(context["measurement"], {"fixture": "measured"})
        self.assertEqual(context["lineage"], {"fixture": "lineage"})
        self.assertEqual(context["grant"], {})
        self.assertEqual(context["offer_intent"], self.send.call_args_list[0].args[1])
        self.assertEqual(self.retained("CURRENT_ATTEMPT")[0], self.send.call_args_list[1].args[1])

    def test_context_storage_failure_prevents_offer_and_ack(self):
        original = self.retain.side_effect
        def retain(owner, kind, value):
            if kind == "REQUEST_CONTEXT": raise OSError("context not retained")
            original(owner, kind, value)
        self.retain.side_effect = retain
        self.assertEqual(self.handle()["status"], "NOT_SUBMITTED")
        self.send.assert_not_called()
        self.assert_no_release()

    def test_invalid_check_retained_without_current_attempt(self):
        self.packet_list[1][0]["sequence"] = 2
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.retained("CHECK")[0]["sequence"], 2)
        self.assertEqual(self.retained("CURRENT_ATTEMPT"), [])
        self.assert_no_release()

    def test_uncertain_current_send_keeps_attempt_without_retry(self):
        original = self.send.side_effect
        def send(connection, document, deadline, **options):
            original(connection, document, deadline, **options)
            if document["kind"] == "CURRENT": raise OSError("uncertain send")
        self.send.side_effect = send
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(len(self.retained("CURRENT_ATTEMPT")), 1)
        self.assertEqual(self.events.count("CURRENT"), 1)
        self.assert_no_release()

    def test_actual_done_retained_before_binding_validation(self):
        self.packet_list[-1][0]["nonce"] = "c" * 32
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.retained("ACTION_DONE")[0]["nonce"], "c" * 32)
        self.ticket.finish.assert_not_called()
        self.complete.assert_not_called()
        self.assert_no_release()

    def test_done_with_invalid_effect_keeps_original_before_projection(self):
        self.packet_list[-1][0]["envelope"]["effect"]["target_name"] = "other.txt"
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.retained("ACTION_DONE")[0]["envelope"]["effect"]["target_name"], "other.txt")
        self.complete.assert_not_called()
        self.assert_no_release()

    def test_readback_completes_before_retirement_and_both_acks(self):
        self.assertEqual(self.handle(), handoff_fixtures.result())
        ordered = ["retain:ACTION_DONE", "sensor_DONE", "readback_complete", "retire", "sensor_ACK", "ACK"]
        self.assertEqual([value for value in self.events if value in ordered], ordered)
        self.complete.assert_called_once()
        self.deliver.assert_not_called()

    def test_readback_failure_blocks_retirement_and_both_acks(self):
        self.complete.side_effect = RuntimeError("receipt differs")
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.complete.assert_called_once()
        self.assertEqual(self.retained("FAILURE")[-1]["stage"], "EFFECT_EVIDENCE")
        self.assert_no_release()

    def test_cancelled_readback_preserves_original_even_if_failure_store_fails(self):
        failure = KeyboardInterrupt("cancelled readback")
        self.complete.side_effect = failure
        original = self.retain.side_effect
        def retain(owner, kind, value):
            if kind == "FAILURE": raise OSError("failure prefix uncertain")
            original(owner, kind, value)
        self.retain.side_effect = retain
        with self.assertRaises(KeyboardInterrupt) as caught: self.handle()
        self.assertIs(caught.exception, failure)
        self.complete.assert_called_once()
        self.assert_no_release()


class SensorReceiptTests(sensor_terminal_fixtures.TicketTests):
    def test_receipt_available_only_after_actual_finish_and_before_ack(self):
        with self.held(terminal_ack=True) as ticket:
            with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt
            ticket.finish(sensor_fixtures.broker_result())
            self.assertEqual(ticket.terminal_receipt, sensor_terminal_fixtures.done())
            ticket.acknowledge()
            with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt
        self.assertEqual(self.receive.call_count, 3)

    def test_receipt_detaches_without_receiving_or_closing_again(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(sensor_fixtures.broker_result())
            ticket.terminal_receipt["nonce"] = "c" * 32
            self.assertEqual(ticket.terminal_receipt, sensor_terminal_fixtures.done())
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)

    def test_receipt_after_scope_exit_refuses(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(sensor_fixtures.broker_result())
        with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt
        self.assertEqual(self.receive.call_count, 3)

    def test_failed_done_or_close_never_exposes_receipt(self):
        with self.held(terminal_ack=True) as ticket:
            self.close.side_effect = OSError("uncertain close")
            with self.assertRaises(OSError): ticket.finish(sensor_fixtures.broker_result())
            with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt
        self.close.assert_called_once_with(70)

    def test_receipt_rechecks_connected_peer(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(sensor_fixtures.broker_result())
            with mock.patch.object(sensor.broker, "_peer_credentials", return_value=(401, 1301, 1302)):
                with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt
        self.assertEqual(self.receive.call_count, 3)

    def test_receipt_rechecks_original_nanosecond_expiry(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(sensor_fixtures.broker_result())
            with mock.patch.object(sensor.time, "monotonic_ns", return_value=120_000_000_000):
                with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt


class LegacyReceiptTests(sensor_fixtures.TicketTests):
    def test_legacy_finish_does_not_gain_terminal_receipt(self):
        with self.held() as ticket:
            ticket.finish(sensor_fixtures.broker_result())
            with self.assertRaises(RuntimeError): _ = ticket.terminal_receipt


class NativeTests(native_fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.lease = object.__new__(channels.PiServiceChannels)
        self.lease._deadline = 115.0
        self.lease._requests_retired = False
        self.channels = replace(self.channels, service_custody=self.lease)
        self.lease._request_channels = self.channels
        self.dispatch.channels = self.channels
        self.stack.enter_context(mock.patch.object(channels.PiServiceChannels, "guard"))
        self.events, self.owner = [], None
        self.record = closed_observation()
        self.close_failure = None

        @contextmanager
        def held(custody):
            self.assertIs(type(custody), native.PiNativeRequestCustody)
            self.assertIs(custody._channels, self.channels)
            self.owner = evidence.PiNativeActionEvidence(evidence._SEAL, custody)
            self.events.append("evidence_open")
            try:
                yield self.owner
            finally:
                self.events.append("evidence_close")
                self.owner._record = copy.deepcopy(self.record)
                if self.close_failure is not None: raise self.close_failure

        def forward(*args, **options):
            self.assertIs(options["action_evidence"], self.owner)
            self.assertIs(options["native_custody"], self.owner.custody)
            self.assertIs(options["terminal_ack"], True)
            self.events.append("handoff")
            return handoff_fixtures.result()

        self.hold = self.stack.enter_context(mock.patch.object(evidence,
            "hold_native_action_evidence", side_effect=held))
        self.forward.side_effect = forward
        self.deliver = self.stack.enter_context(mock.patch.object(native.broker,
            "_send_frame", side_effect=lambda *args: self.events.append("deliver")))

    def assert_held_failure(self):
        self.deliver.assert_not_called()
        self.assertIs(self.dispatch._remote_custody_hold, True)
        self.assertEqual(self.dispatch.observation["status"], "REQUEST_INDETERMINATE")
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")

    def test_owner_closes_and_validates_before_exact_single_delivery(self):
        self.assertEqual(self.handle(), handoff_fixtures.result())
        self.assertEqual(self.events, ["evidence_open", "handoff", "evidence_close", "deliver"])
        self.deliver.assert_called_once_with(self.worker, canonical_json(handoff_fixtures.result()), 115)
        self.assertEqual(self.dispatch.observation["action_evidence"], self.record)
        self.assertIs(self.owned.request_attempted, True)
        with self.assertRaises(RuntimeError): self.owner.custody.guard()

    def test_observation_is_detached_from_owner_after_close(self):
        self.handle()
        self.owner._record["retained_evidence"]["records"].clear()
        self.assertEqual(len(self.dispatch.observation["action_evidence"]["retained_evidence"]["records"]), 1)

    def test_success_observation_is_read_once_before_delivery(self):
        with mock.patch.object(evidence.PiNativeActionEvidence, "observation",
                new_callable=mock.PropertyMock, side_effect=[self.record, RuntimeError("second getter forbidden")]) as observation:
            self.assertEqual(self.handle(), handoff_fixtures.result())
        self.assertEqual(observation.call_count, 1)
        self.deliver.assert_called_once()

    def test_close_failure_prevents_worker_success_and_preserves_original(self):
        self.close_failure = OSError("owned close uncertain")
        self.record.update(status="CLEANUP_HOLD", owned_handles_closed=False)
        with self.assertRaises(OSError) as caught: self.handle()
        self.assertIs(caught.exception, self.close_failure)
        self.assertEqual(self.events.count("evidence_close"), 1)
        self.assertEqual(self.dispatch.observation["action_evidence"], self.record)
        self.assert_held_failure()

    def test_nonclosed_observation_blocks_delivery(self):
        self.record["status"] = "HELD"
        with self.assertRaises(RuntimeError): self.handle()
        self.assert_held_failure()

    def test_missing_receipt_join_blocks_delivery(self):
        self.record["receipt_join_verified"] = False
        with self.assertRaises(RuntimeError): self.handle()
        self.assert_held_failure()

    def test_unknown_owned_cleanup_blocks_delivery(self):
        self.record["owned_handles_closed"] = None
        with self.assertRaises(RuntimeError): self.handle()
        self.assert_held_failure()

    def test_forged_authority_is_not_retained_as_valid_owner_evidence(self):
        self.record["authority"] = "EFFECT_VERIFIED"
        with self.assertRaises(RuntimeError): self.handle()
        self.assertIsNone(self.dispatch.observation["action_evidence"])
        self.assertEqual(self.dispatch.observation["action_evidence_uncertainty"], "OWNER_RECORD_UNAVAILABLE_OR_INVALID")
        self.assert_held_failure()

    def test_oversized_owner_record_blocks_success(self):
        self.record["oversized"] = "x" * (4 * 1024 * 1024)
        with self.assertRaises(RuntimeError): self.handle()
        self.assert_held_failure()

    def test_original_cancellation_survives_failed_observation_getter(self):
        failure = KeyboardInterrupt("native cancellation")
        self.forward.side_effect = failure
        with mock.patch.object(evidence.PiNativeActionEvidence, "observation",
                new_callable=mock.PropertyMock, side_effect=RuntimeError("record unavailable")):
            with self.assertRaises(KeyboardInterrupt) as caught: self.handle()
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.events.count("evidence_close"), 1)
        self.assert_held_failure()

    def test_factory_failure_retains_its_actual_partial_observation(self):
        failure = OSError("store acquisition failed")
        failure.pi_native_action_evidence_observation = {**self.record,
            "status": "CLEANUP_HOLD", "owned_handles_closed": False,
            "receipt_join_verified": False}
        self.hold.side_effect = failure
        with self.assertRaises(OSError) as caught: self.handle()
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.dispatch.observation["action_evidence"], failure.pi_native_action_evidence_observation)
        self.forward.assert_not_called()
        self.assert_held_failure()

    def test_delivery_failure_is_not_retried_after_owner_closed(self):
        failure = OSError("worker delivery uncertain")
        self.deliver.side_effect = failure
        with self.assertRaises(OSError) as caught: self.handle()
        self.assertIs(caught.exception, failure)
        self.deliver.assert_called_once()
        self.assertEqual(self.dispatch.observation["action_evidence"], self.record)
        self.assertIs(self.dispatch._remote_custody_hold, True)

    def test_bare_channels_keep_old_handoff_and_no_evidence_store(self):
        self.channels = replace(self.channels, service_custody=None)
        self.dispatch.channels = self.channels
        self.forward.side_effect = None
        self.forward.return_value = {"status": "COMPLETED", "fixture": "bare"}
        self.assertEqual(self.handle(), self.forward.return_value)
        self.hold.assert_not_called()
        self.deliver.assert_not_called()
        self.assertNotIn("action_evidence", self.forward.call_args.kwargs)
        self.assertNotIn("terminal_ack", self.forward.call_args.kwargs)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in (HandoffTests, SensorReceiptTests, LegacyReceiptTests, NativeTests):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    for cls, name in (
        (handoff_fixtures.RootReaderTests, "test_actual_frame_bound_to_offer_and_cleanup_precedes_success"),
        (handoff_fixtures.RootReaderTests, "test_unreadable_request_never_offers_or_fabricates_digest"),
        (terminal_fixtures.RootTests, "test_both_done_then_live_guard_then_retirement_then_acks"),
        (sensor_terminal_fixtures.TicketTests, "test_finish_records_done_and_closes_owned_pidfd_without_sending_ack"),
        (native_fixtures.NativeCustodyTests, "test_exact_held_native_custody_wraps_existing_reader_and_sensor_channel"),
        (native_fixtures.SelectionTests, "test_unavailable_bootstrap_returns_no_request_without_fabricating_work"),
    ):
        suite.addTest(cls(name))
    return suite
