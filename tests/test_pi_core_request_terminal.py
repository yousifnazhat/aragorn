"""Inert v2 terminal ordering; no process, socket, provider or effect executes."""

import unittest
from contextlib import contextmanager
from unittest import mock

from tests import test_pi_core_request_handoff as fixtures
from aragorn import pi_core_native_request as native
from aragorn import pi_core_request_handoff as subject
from aragorn.oci_worker_protocol import canonical_digest


class PacketTests(fixtures.InertTests):
    def ack(self):
        return subject._packet("ACK", terminal_ack=True, **fixtures.fields(),
            done_digest="sha256:" + "c" * 64)

    def test_mode_is_strict_local_boolean(self):
        for value in (None, 0, 1, "v2", {}, []):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                subject._packet("CHALLENGE", nonce="b" * 32, terminal_ack=value)

    def test_v2_ack_exact_closed_fields(self):
        packet = self.ack()
        self.assertEqual(subject._validate_packet(packet, terminal_ack=True), packet)
        for changes in ({"extra": True}, {"done_digest": "wrong"}, {"nonce": "x"},
                        {"deadline_ns": True}, {"authority": "ALLOW"}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                subject._validate_packet({**packet, **changes}, terminal_ack=True)

    def test_v1_rejects_ack_even_with_v1_schema(self):
        with self.assertRaises(RuntimeError):
            subject._validate_packet({**self.ack(), "schema": subject.SCHEMA})

    def test_no_schema_negotiation_or_downgrade(self):
        for selected in (False, True):
            packet = subject._packet("CHALLENGE", nonce="b" * 32, terminal_ack=not selected)
            with self.subTest(selected=selected), self.assertRaises(RuntimeError):
                subject._validate_packet(packet, terminal_ack=selected)

    def test_receive_closes_unexpected_rights_on_schema_refusal(self):
        with mock.patch.object(subject.transport, "receive_authenticated_packet",
                return_value=(fixtures.offer(), (81,))):
            with self.assertRaises(RuntimeError):
                subject._receive(mock.Mock(), (200, 0, 0), 120.0, rights=1, terminal_ack=True)
        self.close.assert_called_once_with(81)

    def test_ack_cannot_transfer_descriptors(self):
        with mock.patch.object(subject.transport, "send_authenticated_packet") as send:
            with self.assertRaises(RuntimeError):
                subject._send(mock.Mock(), self.ack(), 120.0, rights=(81,), terminal_ack=True)
            send.assert_not_called()


class AuthorityTests(fixtures.AuthorityTests):
    def setUp(self):
        super().setUp()
        self.offered["schema"] = subject.TERMINAL_SCHEMA
        self.peer = self.stack.enter_context(mock.patch.object(subject.broker, "_peer_credentials", return_value=(200, 0, 0)))
        original = self.receive.side_effect

        def receive(*args, **kwargs):
            if self.latest is not None and self.latest["kind"] == "DONE":
                self.events.append("ACK_RECEIVE")
                return subject._packet("ACK", terminal_ack=True, **fixtures.fields(),
                    done_digest=canonical_digest(self.latest)), ()
            return original(*args, **kwargs)

        self.receive.side_effect = receive

    def held(self, **changes):
        return super().held(**{"terminal_ack": True, **changes})

    def test_v2_closes_before_done_and_waits_bound_ack(self):
        with self.held() as authority:
            authority.begin()
            authority.finish(fixtures.envelope(), fixtures.result())
            with self.assertRaises(RuntimeError):
                authority.finish(fixtures.envelope(), fixtures.result())
        self.assertEqual(self.events, ["CHALLENGE", "CHECK", "CHECK", ("close", 81),
            ("close", 80), "DONE", "ACK_RECEIVE"])
        self.assertTrue(all(call.kwargs["terminal_ack"] for call in self.receive.call_args_list))
        self.connection.close.assert_not_called()

    def test_ack_binds_every_terminal_field(self):
        original = self.receive.side_effect
        for field, value in (("nonce", "c" * 32), ("activation_digest", "sha256:" + "f" * 64),
                ("request_digest", "sha256:" + "f" * 64), ("deadline_ns", 119_000_000_000),
                ("done_digest", "sha256:" + "f" * 64)):
            self.receive_count, self.latest = 0, None

            def receive(*args, **kwargs):
                packet, rights = original(*args, **kwargs)
                if packet["kind"] == "ACK": packet[field] = value
                return packet, rights

            self.receive.side_effect = receive
            with self.subTest(field=field), self.held() as authority:
                authority.begin()
                with self.assertRaisesRegex(RuntimeError, "acknowledgment"):
                    authority.finish(fixtures.envelope(), fixtures.result())
                with self.assertRaises(RuntimeError): authority.guard()

    def test_missing_ack_never_reopens_authority_or_recloses_handles(self):
        original = self.receive.side_effect

        def receive(*args, **kwargs):
            if self.latest["kind"] == "DONE": raise TimeoutError("original deadline")
            return original(*args, **kwargs)

        self.receive.side_effect = receive
        with self.held() as authority:
            authority.begin()
            with self.assertRaises(TimeoutError): authority.finish(fixtures.envelope(), fixtures.result())
            with self.assertRaises(RuntimeError): authority.finish(fixtures.envelope(), fixtures.result())
        self.assertEqual(self.events.count("DONE"), 1)
        self.assertEqual(self.close.call_count, 2)

    def test_expired_ack_cannot_complete(self):
        original = self.receive.side_effect

        def receive(*args, **kwargs):
            value = original(*args, **kwargs)
            if value[0]["kind"] == "ACK": subject.time.monotonic.return_value = 120.0
            return value

        self.receive.side_effect = receive
        with self.held() as authority:
            authority.begin()
            with self.assertRaises(RuntimeError): authority.finish(fixtures.envelope(), fixtures.result())
        self.assertEqual(self.events.count("DONE"), 1)

    def test_close_failure_prevents_done_and_ack_wait(self):
        self.close.side_effect = OSError("uncertain close")
        with self.held() as authority:
            authority.begin()
            with self.assertRaises(RuntimeError): authority.finish(fixtures.envelope(), fixtures.result())
        self.assertNotIn("DONE", self.events)
        self.assertEqual(self.close.call_count, 2)

    def test_changed_root_peer_after_done_refuses(self):
        self.peer.return_value = (201, 0, 0)
        with self.held() as authority:
            authority.begin()
            with self.assertRaisesRegex(RuntimeError, "terminal request peer"):
                authority.finish(fixtures.envelope(), fixtures.result())
        self.assertNotIn("ACK_RECEIVE", self.events)

    def test_ack_exact_nanosecond_expiry_refuses(self):
        original = self.receive.side_effect
        def receive(*args, **kwargs):
            value = original(*args, **kwargs)
            if value[0]["kind"] == "ACK": subject.time.monotonic_ns.return_value = 120_000_000_000
            return value
        self.receive.side_effect = receive
        with self.held() as authority:
            authority.begin()
            with self.assertRaisesRegex(RuntimeError, "original deadline"):
                authority.finish(fixtures.envelope(), fixtures.result())


class RootTests(fixtures.RootReaderTests):
    def setUp(self):
        super().setUp()
        self.packet_list = [({**packet, "schema": subject.TERMINAL_SCHEMA}, rights)
            for packet, rights in self.packet_list]
        self.custody = object.__new__(native.PiNativeRequestCustody)
        self.custody._deadline = 120.0
        self.guard = self.stack.enter_context(mock.patch.object(native.PiNativeRequestCustody,
            "guard", side_effect=lambda: self.events.append("guard")))
        self.retire = self.stack.enter_context(mock.patch.object(native.PiNativeRequestCustody,
            "retire_requests", side_effect=lambda: self.events.append("retire")))
        sensor = mock.Mock()
        sensor.fileno.return_value = 3
        self.sensor_channel = subject.sensor_transport.PiSensorChannel(sensor, (500, 1401, 1402))
        self.ticket = mock.Mock()
        self.ticket.finish.side_effect = lambda value: self.events.append("sensor_DONE")
        self.ticket.acknowledge.side_effect = lambda: self.events.append("sensor_ACK")

        @contextmanager
        def held(*args, **kwargs):
            self.assertTrue(kwargs["terminal_ack"])
            yield self.ticket

        self.stack.enter_context(mock.patch.object(subject.sensor_transport, "hold_pi_sensor_channel", side_effect=held))

    def handle(self, **changes):
        return super().handle(**{"terminal_ack": True, "native_custody": self.custody,
            "sensor_channel": self.sensor_channel, **changes})

    def test_both_done_then_live_guard_then_retirement_then_acks(self):
        self.assertEqual(self.handle(), fixtures.result())
        terminal = self.events[self.events.index("sensor_DONE"):]
        self.assertEqual(terminal[:6], ["sensor_DONE", "guard", "retire", "sensor_ACK", "ACK", "guard"])
        self.ticket.finish.assert_called_once_with(fixtures.result()["broker_result"])
        self.retire.assert_called_once()
        done = subject._packet("DONE", terminal_ack=True, **fixtures.fields(),
            envelope=fixtures.envelope(), result=fixtures.result())
        ack = self.send.call_args_list[-1].args[1]
        self.assertEqual(ack["done_digest"], canonical_digest(done))

    def test_sensor_done_refusal_never_retires_or_acknowledges(self):
        self.ticket.finish.side_effect = RuntimeError("different result")
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.retire.assert_not_called()
        self.ticket.acknowledge.assert_not_called()
        self.assertNotIn("ACK", self.events)

    def test_preterminal_service_death_is_not_a_retirement_waiver(self):
        def guard():
            if "sensor_DONE" in self.events: raise RuntimeError("sensor exited before ACK")
        self.guard.side_effect = guard
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.retire.assert_not_called()
        self.ticket.acknowledge.assert_not_called()

    def test_retirement_failure_releases_neither_ack(self):
        self.retire.side_effect = RuntimeError("generation changed")
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.ticket.acknowledge.assert_not_called()
        self.assertNotIn("ACK", self.events)

    def test_sensor_ack_failure_never_attempts_action_ack(self):
        self.ticket.acknowledge.side_effect = OSError("partial send")
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.retire.assert_called_once()
        self.ticket.acknowledge.assert_called_once()
        self.assertNotIn("ACK", self.events)

    def test_action_ack_failure_never_retries_either_ack(self):
        original = self.send.side_effect
        def send(*args, **kwargs):
            original(*args, **kwargs)
            if args[1]["kind"] == "ACK": raise OSError("partial send")
        self.send.side_effect = send
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.events.count("ACK"), 1)
        self.ticket.acknowledge.assert_called_once()

    def test_postterminal_guard_failure_cannot_deliver_success(self):
        def guard():
            if "ACK" in self.events: raise RuntimeError("worker changed")
        self.guard.side_effect = guard
        self.assertEqual(self.handle()["status"], "INDETERMINATE")

    def test_terminal_mode_requires_both_native_and_sensor_custody(self):
        for changes in ({"native_custody": None}, {"sensor_channel": None}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError): self.handle(**changes)
        self.read.assert_not_called()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in (PacketTests, AuthorityTests, RootTests):
        for name in cls.__dict__:
            if name.startswith("test_"): suite.addTest(cls(name))
    for cls, names in ((fixtures.AuthorityTests, (
            "test_scoped_authority_consumes_once_and_closes_before_done",
            "test_context_exit_revokes_without_fabricated_done")),
            (fixtures.RootReaderTests, ("test_actual_frame_bound_to_offer_and_cleanup_precedes_success",))):
        suite.addTests(cls(name) for name in names)
    return suite
