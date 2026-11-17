"""Only additive sensor-terminal tests and explicitly affected legacy cases.

All packet, process and service boundaries are inert. Caller fixtures reuse
their existing owned temporary files; no live sensor or deployment is started.
"""

import copy
import unittest
from unittest import mock

from aragorn import pi_core_sensor_channel as subject
from aragorn import pi_core_request_sensor as sensor
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_sensor_channel as fixtures
from tests import test_pi_core_request_sensor as sensor_fixtures


def packet(kind, **fields):
    return subject._packet(kind, terminal_ack=True, **fields)


def offer():
    return packet("OFFER", **fixtures.bound(), request=fixtures.request())


def done():
    return packet("DONE", **fixtures.bound(), broker_result_digest=canonical_digest(fixtures.broker_result()))


def ack():
    return packet("ACK", **fixtures.bound(), done_digest=canonical_digest(done()))


class PacketTests(fixtures.InertTests):
    def test_fixed_v2_packet_set_and_entire_done_digest(self):
        values = [packet("CHALLENGE", nonce="b" * 32), offer(), packet("READY", **fixtures.bound()), done(), ack()]
        for value in values:
            with self.subTest(kind=value["kind"]):
                self.assertEqual(subject._validate_packet(value, terminal_ack=True), value)
                self.assertEqual(value["schema"], "aragorn/pi-core-sensor-custody/v2")
                self.assertEqual(value["authority"], subject.AUTHORITY)
        self.assertEqual(ack()["done_digest"], canonical_digest(done()))
        self.assertNotEqual(ack()["done_digest"], canonical_digest(fixtures.broker_result()))

    def test_default_is_v1_and_neither_version_downgrades(self):
        self.assertEqual(subject._packet("READY", **fixtures.bound())["schema"], subject.SCHEMA)
        for value, mode in ((offer(), False), (fixtures.offer(), True), (ack(), False)):
            with self.subTest(mode=mode, kind=value["kind"]), self.assertRaises(RuntimeError):
                subject._validate_packet(value, terminal_ack=mode)

    def test_mode_is_strict_boolean_before_transport(self):
        with mock.patch.object(subject.transport, "send_authenticated_packet") as send, \
             mock.patch.object(subject.transport, "receive_authenticated_packet") as receive:
            for mode in (0, 1, None, "true", [], {}):
                with self.subTest(mode=mode):
                    for operation in (
                        lambda: subject._packet("READY", terminal_ack=mode, **fixtures.bound()),
                        lambda: subject._validate_packet(offer(), terminal_ack=mode),
                        lambda: subject._send(mock.Mock(), offer(), 120, terminal_ack=mode),
                        lambda: subject._receive(mock.Mock(), (200, 0, 0), 120, terminal_ack=mode),
                    ):
                        with self.assertRaisesRegex(RuntimeError, "local boolean"):
                            operation()
            send.assert_not_called()
            receive.assert_not_called()

    def test_ack_fields_nonce_deadline_and_done_digest_are_closed(self):
        for change in ({"extra": True}, {"done_digest": "bad"}, {"done_digest": True},
                       {"nonce": "B" * 32}, {"deadline_ns": True}, {"deadline_ns": 0},
                       {"request_digest": "bad"}, {"authority": "EFFECT_AUTHORITY"}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                subject._validate_packet({**ack(), **change}, terminal_ack=True)

    def test_ack_cannot_send_or_receive_descriptor_rights(self):
        with mock.patch.object(subject.transport, "send_authenticated_packet") as send:
            with self.assertRaises(RuntimeError):
                subject._send(mock.Mock(), ack(), 120, rights=(81,), terminal_ack=True)
            send.assert_not_called()
        with mock.patch.object(subject.transport, "receive_authenticated_packet", return_value=(ack(), (81,))):
            with self.assertRaises(RuntimeError):
                subject._receive(mock.Mock(), (200, 0, 0), 120, rights=1, terminal_ack=True)
        self.close.assert_called_once_with(81)

    def test_mixed_offer_closes_received_right_without_fallback(self):
        with mock.patch.object(subject.transport, "receive_authenticated_packet", return_value=(fixtures.offer(), (81,))) as read:
            with self.assertRaises(RuntimeError):
                subject._receive(mock.Mock(), (200, 0, 0), 120, rights=1, terminal_ack=True)
        read.assert_called_once()
        self.close.assert_called_once_with(81)

    def test_ack_uses_existing_authenticated_transport_once(self):
        connection = mock.Mock()
        with mock.patch.object(subject.transport, "send_authenticated_packet", side_effect=OSError("uncertain")) as send:
            with self.assertRaises(OSError):
                subject._send(connection, ack(), 120, terminal_ack=True)
        send.assert_called_once_with(connection, ack(), 120, rights=(), max_bytes=subject.MAX_PACKET_BYTES)
        with mock.patch.object(subject.transport, "receive_authenticated_packet", return_value=(ack(), ())) as receive:
            self.assertEqual(subject._receive(connection, (200, 0, 0), 120, terminal_ack=True), (ack(), ()))
        receive.assert_called_once_with(connection, (200, 0, 0), 120, expected_rights=0,
                                        max_bytes=subject.MAX_PACKET_BYTES)


class CandidateTests(fixtures.CandidateTests):
    def setUp(self):
        super().setUp()
        self.offered, self.acknowledgment, self.sent = offer(), ack(), []
        self.peer.side_effect = lambda connection: (200, 0, 0) if connection is self.connection else (300, 1201, 1202)
        self.send.side_effect = self.send_packet
        self.receive.side_effect = self.receive_packet

    def send_packet(self, connection, value, deadline, **options):
        self.assertIs(connection, self.connection)
        self.assertEqual((deadline, options), (120.0, {"terminal_ack": True}))
        subject._validate_packet(value, terminal_ack=True)
        self.sent.append(copy.deepcopy(value))
        self.events.append(value["kind"])

    def receive_packet(self, connection, peer, deadline, **options):
        self.assertEqual((connection, peer, deadline), (self.connection, (200, 0, 0), 120.0))
        if options.get("rights") == 1:
            self.assertEqual(options, {"rights": 1, "terminal_ack": True})
            subject._validate_packet(self.offered, terminal_ack=True)
            return self.offered, (81,)
        self.assertEqual(options, {"terminal_ack": True})
        self.assertEqual(self.sent[-1], done())
        self.assertIn("close_pi_duplicate", self.events)
        self.assertIn(("close", 80), self.events)
        self.events.append("ACK_RECEIVE")
        if isinstance(self.acknowledgment, BaseException):
            raise self.acknowledgment
        subject._validate_packet(self.acknowledgment, terminal_ack=True)
        return self.acknowledgment, ()

    def test_v2_candidate_closes_owned_handles_before_done_and_ack_wait(self):
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            candidate.finish(fixtures.broker_result())
            self.assertEqual(self.receive.call_count, 2)
        self.assertEqual(self.events, ["CHALLENGE", "READY", "close_pi_duplicate", ("close", 80), "DONE", "ACK_RECEIVE"])
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)
        self.assert_no_pi_io()

    def test_v2_mode_is_chosen_before_the_first_challenge(self):
        for mode in (1, None, "v2"):
            with self.subTest(mode=mode), self.assertRaises(RuntimeError), self.held(terminal_ack=mode):
                pass
        self.guard.assert_not_called()
        self.send.assert_not_called()
        self.receive.assert_not_called()

    def test_missing_ack_is_terminal_and_never_retries_done_or_cleanup(self):
        self.acknowledgment = TimeoutError("missing ACK")
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaises(TimeoutError) as caught:
                candidate.finish(fixtures.broker_result())
            self.assertIs(caught.exception, self.acknowledgment)
            with self.assertRaises(RuntimeError):
                candidate.finish(fixtures.broker_result())
        self.assertEqual([value["kind"] for value in self.sent], ["CHALLENGE", "READY", "DONE"])
        self.assertEqual(self.receive.call_count, 2)
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)

    def test_wrong_ack_nonce_request_deadline_or_entire_done_digest_refuses(self):
        # Separate local scopes model separate attempts, not an effect retry.
        for changes in ({"nonce": "c" * 32}, {"request_digest": "sha256:" + "f" * 64},
                        {"deadline_ns": 119_000_000_000},
                        {"done_digest": canonical_digest(fixtures.broker_result())}):
            self.acknowledgment = {**ack(), **changes}
            with self.subTest(changes=changes), self.held(terminal_ack=True) as candidate:
                candidate.ready()
                with self.assertRaisesRegex(RuntimeError, "ACK differs"):
                    candidate.finish(fixtures.broker_result())

    def test_v1_ack_cannot_be_adopted_as_v2(self):
        self.acknowledgment = {**ack(), "schema": subject.SCHEMA}
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaises(RuntimeError):
                candidate.finish(fixtures.broker_result())
        self.assertEqual(self.receive.call_count, 2)

    def test_ack_packet_authentication_failure_is_not_retried(self):
        self.acknowledgment = subject.transport.PiIdentityHandoffError("foreign packet credentials")
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaises(subject.transport.PiIdentityHandoffError):
                candidate.finish(fixtures.broker_result())
        self.assertEqual(self.receive.call_count, 2)
        self.close.assert_called_once_with(80)

    def test_changed_connected_root_peer_refuses_ack_after_cleanup(self):
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            self.peer.side_effect = None
            self.peer.return_value = (201, 0, 0)
            with self.assertRaisesRegex(RuntimeError, "terminal sensor peer"):
                candidate.finish(fixtures.broker_result())
        self.assertEqual(self.receive.call_count, 1)
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)

    def test_ack_arriving_after_original_deadline_is_refused(self):
        receive = self.receive.side_effect

        def late(*args, **kwargs):
            value = receive(*args, **kwargs)
            if kwargs.get("rights") != 1:
                self.stack.enter_context(mock.patch.object(subject.time, "monotonic_ns", return_value=120_000_000_000))
            return value

        self.receive.side_effect = late
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaisesRegex(RuntimeError, "original deadline"):
                candidate.finish(fixtures.broker_result())
        self.close.assert_called_once_with(80)

    def test_done_send_failure_has_no_ack_read_and_no_second_close(self):
        send = self.send.side_effect

        def fail(connection, value, deadline, **options):
            send(connection, value, deadline, **options)
            if value["kind"] == "DONE":
                raise OSError("uncertain DONE")

        self.send.side_effect = fail
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaises(OSError):
                candidate.finish(fixtures.broker_result())
            with self.assertRaises(RuntimeError):
                candidate.finish(fixtures.broker_result())
        self.assertEqual(self.receive.call_count, 1)
        self.close.assert_called_once_with(80)
        self.stream.close.assert_called_once_with()

    def test_owned_cleanup_failure_prevents_done_and_ack_wait(self):
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            self.stream.close.side_effect = OSError("uncertain duplicate close")
            with self.assertRaisesRegex(RuntimeError, "cleanup is uncertain"):
                candidate.finish(fixtures.broker_result())
        self.assertEqual([value["kind"] for value in self.sent], ["CHALLENGE", "READY"])
        self.assertEqual(self.receive.call_count, 1)
        self.close.assert_called_once_with(80)
        self.stream.close.assert_called_once_with()

    def test_cancellation_while_waiting_for_ack_preserves_original_and_no_retry(self):
        self.acknowledgment = KeyboardInterrupt("inert cancellation")
        with self.held(terminal_ack=True) as candidate:
            candidate.ready()
            with self.assertRaises(KeyboardInterrupt) as caught:
                candidate.finish(fixtures.broker_result())
            self.assertIs(caught.exception, self.acknowledgment)
            with self.assertRaises(RuntimeError):
                candidate.finish(fixtures.broker_result())
        self.close.assert_called_once_with(80)
        self.stream.close.assert_called_once_with()


class TicketTests(fixtures.TicketTests):
    def setUp(self):
        super().setUp()
        self.messages = [packet("CHALLENGE", nonce="b" * 32), packet("READY", **fixtures.bound()), done()]
        self.send.side_effect = self.send_packet
        self.receive.side_effect = self.receive_packet
        self.close.side_effect = lambda fd: self.events.append(("CLOSE", fd))

    def send_packet(self, connection, value, deadline, **options):
        self.assertEqual((connection, deadline), (self.connection, 120.0))
        self.assertEqual(options.get("terminal_ack"), True)
        subject._validate_packet(value, terminal_ack=True)
        self.events.append((copy.deepcopy(value), options))

    def receive_packet(self, connection, peer, deadline, **options):
        self.assertEqual((connection, peer, deadline, options),
                         (self.connection, (400, 1301, 1302), 120.0, {"terminal_ack": True}))
        value = self.messages.pop(0)
        subject._validate_packet(value, terminal_ack=True)
        return value, ()

    def test_finish_records_done_and_closes_owned_pidfd_without_sending_ack(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            self.assertEqual(ticket._done, done())
            self.assertEqual(self.send.call_count, 1)
            self.assertEqual(self.events[-1], ("CLOSE", 70))
        self.close.assert_called_once_with(70)
        self.assert_borrowed_connections_untouched()

    def test_explicit_ack_is_one_shot_and_binds_complete_done(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            ticket.acknowledge()
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.events[-1], (ack(), {"terminal_ack": True}))
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)

    def test_ack_before_done_and_after_scope_exit_is_unavailable(self):
        with self.held(terminal_ack=True) as ticket:
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
            ticket.finish(fixtures.broker_result())
        with self.assertRaises(RuntimeError):
            ticket.acknowledge()
        self.assertEqual(self.send.call_count, 1)

    def test_bad_done_never_enables_ack_or_second_finish(self):
        self.messages[-1]["broker_result_digest"] = "sha256:" + "f" * 64
        with self.held(terminal_ack=True) as ticket:
            with self.assertRaises(RuntimeError):
                ticket.finish(fixtures.broker_result())
            self.assertIsNone(ticket._done)
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
            with self.assertRaises(RuntimeError):
                ticket.finish(fixtures.broker_result())
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.receive.call_count, 3)

    def test_pidfd_close_failure_retains_done_but_disables_ack_and_retry(self):
        with self.held(terminal_ack=True) as ticket:
            self.close.side_effect = OSError("uncertain close")
            with self.assertRaises(OSError):
                ticket.finish(fixtures.broker_result())
            self.assertEqual(ticket._done, done())
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.close.assert_called_once_with(70)
        self.assertEqual(self.send.call_count, 1)

    def test_ack_send_failure_consumes_attempt_without_restoring_authority(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            self.send.side_effect = OSError("uncertain ACK")
            with self.assertRaises(OSError):
                ticket.acknowledge()
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.send.call_count, 2)
        self.close.assert_called_once_with(70)

    def test_expired_or_changed_peer_ack_cannot_be_retried(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            with mock.patch.object(subject.time, "monotonic_ns", return_value=120_000_000_000):
                with self.assertRaises(RuntimeError):
                    ticket.acknowledge()
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.send.call_count, 1)

    def test_changed_connected_sensor_peer_prevents_ack(self):
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            self.peer.return_value = (401, 1301, 1302)
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.send.call_count, 1)

    def test_cancellation_during_ack_is_one_shot(self):
        cancelled = KeyboardInterrupt("inert cancellation")
        with self.held(terminal_ack=True) as ticket:
            ticket.finish(fixtures.broker_result())
            self.send.side_effect = cancelled
            with self.assertRaises(KeyboardInterrupt) as caught:
                ticket.acknowledge()
            self.assertIs(caught.exception, cancelled)
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.send.call_count, 2)
        self.close.assert_called_once_with(70)

    def test_mixed_v1_challenge_does_not_start_transfer(self):
        self.messages[0]["schema"] = subject.SCHEMA
        with self.assertRaises(RuntimeError), self.held(terminal_ack=True):
            pass
        self.send.assert_not_called()
        self.close.assert_called_once_with(70)

    def test_invalid_local_mode_refuses_before_any_channel_custody(self):
        for mode in (1, None, "v2"):
            with self.subTest(mode=mode), self.assertRaises(RuntimeError), self.held(terminal_ack=mode):
                pass
        self.guard.assert_not_called()
        self.receive.assert_not_called()
        self.send.assert_not_called()


class LegacyDefaultTests(fixtures.TicketTests):
    def test_v1_ticket_cannot_emit_an_ack_even_after_successful_finish(self):
        with self.held() as ticket:
            ticket.finish(fixtures.broker_result())
            with self.assertRaises(RuntimeError):
                ticket.acknowledge()
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)


class SensorCallerTests(sensor_fixtures.PiRequestSensorTests):
    def setUp(self):
        super().setUp()
        self.modes, self.ack_failure = [], None
        held = self.hold.side_effect

        def selected(connection, **options):
            self.modes.append(options.pop("terminal_ack", False))
            return held(connection, **options)

        self.hold.side_effect = selected

    def finish(self, result):
        super().finish(result)
        if self.modes[-1]:
            self.events.append("ACK_WAIT")
            if self.ack_failure is not None:
                raise self.ack_failure
            self.events.append("ACK_RECEIVED")

    def test_prepared_sensor_caller_threads_explicit_terminal_mode_only(self):
        result = self.run_request(terminal_ack=True)
        self.assertEqual(self.modes, [True])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertLess(self.events.index("DONE"), self.events.index("ACK_RECEIVED"))
        self.adopt.assert_not_called()
        self.restore.assert_not_called()

    def test_dedicated_sensor_restores_and_closes_measurements_before_terminal_wait(self):
        result = self.run_request(dedicated=True, terminal_ack=True)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.modes, [True])
        for event in ("lineage_exit", ("close", 701), ("close", 702), "restore"):
            self.assertLess(self.events.index(event), self.events.index("DONE"))
        self.assertLess(self.events.index("DONE"), self.events.index("ACK_RECEIVED"))
        self.adopt.assert_called_once()
        self.restore.assert_called_once()
        self.candidate.finish.assert_called_once()

    def test_bad_mode_cannot_adopt_identity_or_open_custody(self):
        for dedicated in (False, True):
            for mode in (1, None, "true"):
                with self.subTest(dedicated=dedicated, mode=mode), self.assertRaises(RuntimeError):
                    self.run_request(dedicated=dedicated, terminal_ack=mode)
        self.adopt.assert_not_called()
        self.restore.assert_not_called()
        self.hold.assert_not_called()
        self.pidfd.assert_not_called()
        self.send.assert_not_called()

    def test_missing_ack_after_submission_is_indeterminate_with_no_resubmission(self):
        self.ack_failure = TimeoutError("missing ACK")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate) as caught:
            self.run_request(dedicated=True, terminal_ack=True)
        self.assertIs(caught.exception.__cause__, self.ack_failure)
        self.send.assert_called_once()
        self.candidate.finish.assert_called_once()
        self.restore.assert_called_once()
        self.source.close.assert_called_once()
        self.assertNotIn("ACK_RECEIVED", self.events)
        for descriptor in (701, 702):
            self.assertEqual(self.events.count(("close", descriptor)), 1)

    def test_cancelled_terminal_wait_does_not_restore_or_close_twice(self):
        self.ack_failure = KeyboardInterrupt("cancelled ACK wait")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_request(dedicated=True, terminal_ack=True)
        self.assertIs(caught.exception, self.ack_failure)
        self.send.assert_called_once()
        self.candidate.finish.assert_called_once()
        self.restore.assert_called_once()
        self.source.close.assert_called_once()
        for descriptor in (701, 702):
            self.assertEqual(self.events.count(("close", descriptor)), 1)

    def test_default_mode_keeps_old_nonwaiting_caller_behavior(self):
        result = self.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.modes, [False])
        self.assertNotIn("ACK_WAIT", self.events)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for case in (PacketTests, CandidateTests, TicketTests, LegacyDefaultTests, SensorCallerTests):
        suite.addTests(case(name) for name in sorted(case.__dict__) if name.startswith("test_"))
    affected = {
        fixtures.PacketTests: ("test_four_packet_shapes_have_exact_non_authorizing_schema",
                              "test_receive_bad_shape_or_kind_rights_closes_installed_duplicate"),
        fixtures.CandidateTests: ("test_authenticated_candidate_closes_owned_handles_before_done",
                                 "test_done_send_failure_follows_cleanup_and_never_retries"),
        fixtures.TicketTests: ("test_root_publishes_exact_original_fd_and_receives_matching_done",
                              "test_authenticated_terminal_done_remains_valid_after_sensor_exit"),
        sensor_fixtures.PiRequestSensorTests: ("test_dedicated_process_adopts_once_and_restores_before_done",),
    }
    for case, names in affected.items():
        suite.addTests(case(name) for name in names)
    return suite
