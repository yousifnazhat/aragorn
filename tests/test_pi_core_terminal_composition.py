"""Inert fixed managed caller selection and retirement joins, not live proof."""

import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest import mock

from tests import test_pi_core_native_request as native_fixtures
from tests import test_pi_core_request_service as service_fixtures
from tests import test_pi_core_service_entry as entry_fixtures
from aragorn import pi_core_native_request as native
from aragorn import pi_core_service_channels as channels
from aragorn import pi_core_service_entry as entry
from aragorn import pi_core_request_service as service


class NativeTests(native_fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.lease = object.__new__(channels.PiServiceChannels)
        self.lease._deadline = 115.0
        self.lease._requests_retired = False
        self.channels = replace(self.channels, service_custody=self.lease)
        self.lease._request_channels = self.channels
        self.dispatch.channels = self.channels
        self.service_guard = self.stack.enter_context(mock.patch.object(channels.PiServiceChannels, "guard"))
        self.retire = self.stack.enter_context(mock.patch.object(channels.PiServiceChannels, "retire_requests"))

    def test_exact_native_service_lease_selects_v2(self):
        self.handle()
        self.assertIs(self.forward.call_args.kwargs["terminal_ack"], True)
        self.service_guard.assert_called()

    def test_bare_legacy_channels_do_not_select_v2(self):
        self.channels = replace(self.channels, service_custody=None)
        self.dispatch.channels = self.channels
        self.handle()
        self.assertNotIn("terminal_ack", self.forward.call_args.kwargs)

    def test_native_terminal_transition_guards_before_same_lease_retirement(self):
        def forward(*args, **kwargs):
            kwargs["native_custody"].retire_requests()
            return {"status": "COMPLETED"}
        self.forward.side_effect = forward
        self.handle()
        self.retire.assert_called_once_with(deadline=115)
        self.assertEqual(self.source_health.call_count, 2)

    def test_retired_pair_refuses_new_request_before_consumption(self):
        self.lease._requests_retired = True
        with self.assertRaisesRegex(RuntimeError, "terminal"): self.handle()
        self.assertFalse(self.owned.request_attempted)
        self.forward.assert_not_called()

    def test_retired_pair_refuses_new_dispatch_before_filesystem_mutation(self):
        self.lease._requests_retired = True
        with self.assertRaisesRegex(RuntimeError, "terminal"): self.dispatch._open()

    def test_replaced_service_binding_cannot_select_v2(self):
        self.lease._request_channels = replace(self.channels)
        with self.assertRaisesRegex(RuntimeError, "binding"): self.handle()
        self.forward.assert_not_called()

    def test_source_guard_failure_prevents_retirement(self):
        def forward(*args, **kwargs):
            self.source_health.side_effect = RuntimeError("source health lost")
            kwargs["native_custody"].retire_requests()
        self.forward.side_effect = forward
        with self.assertRaisesRegex(RuntimeError, "source health"): self.handle()
        self.retire.assert_not_called()


class EntryTests(entry_fixtures.PiServiceEntryTests):
    def test_source_verified_action_selects_v2_after_handshake(self):
        loader = object()
        with mock.patch.object(entry, "_source_handshake",
                side_effect=lambda *_: self.events.append(("source",))) as handshake:
            entry.run("action", ["9000", "105000000000"], source_loader=loader)
        handshake.assert_called_once()
        self.assertIs(self.action.call_args.kwargs["terminal_ack"], True)
        self.assertLess(self.events.index(("source",)), self.events.index(("handler",)))

    def test_source_verified_sensor_selects_v2(self):
        self.configure("sensor")
        with mock.patch.object(entry, "_source_handshake") as handshake:
            entry.run("sensor", ["9000", "105000000000"], source_loader=object())
        handshake.assert_called_once()
        self.assertIs(self.sensor.call_args.kwargs["terminal_ack"], True)

    def test_failed_source_handshake_does_not_dispatch(self):
        with mock.patch.object(entry, "_source_handshake", side_effect=RuntimeError("changed source")):
            with self.assertRaises(RuntimeError):
                entry.run("action", ["9000", "105000000000"], source_loader=object())
        self.action.assert_not_called()

    def test_legacy_entry_keeps_v1_default(self):
        self.run_role()
        self.assertNotIn("terminal_ack", self.action.call_args.kwargs)


class ServiceTests(service_fixtures.PiRequestServiceTests):
    def test_action_service_threads_local_v2_mode(self):
        @contextmanager
        def held(connection, **options):
            self.assertIs(connection, self.root_channel)
            self.assertEqual(options, {"expected_supervisor_peer": (200, 0, 0),
                "deadline": 120.0, "terminal_ack": True})
            yield self.authority
        self.hold.side_effect = held
        self.run_request(terminal_ack=True)
        self.authority.finish.assert_called_once()

    def test_invalid_mode_refuses_before_recovery_or_effect(self):
        for value in (None, 1, "v2"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.run_request(terminal_ack=value)
        self.recover.assert_not_called()
        self.mediate.assert_not_called()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in (NativeTests, EntryTests, ServiceTests):
        for name in cls.__dict__:
            if name.startswith("test_"): suite.addTest(cls(name))
    for cls, name in ((native_fixtures.NativeCustodyTests,
            "test_exact_held_native_custody_wraps_existing_reader_and_sensor_channel"),
            (entry_fixtures.PiServiceEntryTests, "test_sensor_dispatches_real_adoption_wrapper_with_direct_stream"),
            (service_fixtures.PiRequestServiceTests, "test_authenticated_inputs_route_once_and_cleanup_before_success")):
        suite.addTest(cls(name))
    return suite
