"""Only new held-service wiring and four selected affected inert callers.

The lease factory has its own focused checks. Here a local stand-in isolates
caller wiring; no protected files, processes, sockets or services are opened.
"""

import linecache
import unittest
from dataclasses import replace
from unittest import mock

from aragorn import pi_core_service_channels as services
from aragorn import pi_core_native_request as native
from aragorn import pi_core_provider_mediation as provider
from tests import test_pi_core_native_request as native_fixtures
from tests import test_pi_core_provider_egress as provider_fixtures


class InertLease:
    def __init__(self):
        self.deadline = 120.0
        self.provider_retired = False
        self.guard = mock.Mock()
        self.retire_provider = mock.Mock(side_effect=self._retire)

    def _retire(self, **options):
        if self.provider_retired:
            raise RuntimeError("already retired")
        self.provider_retired = True


class NativeServiceWiringTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(linecache, "getlines", return_value=[]))
        self.enterContext(mock.patch.object(linecache, "checkcache", return_value=None))
        self.f = native_fixtures.InertTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.enterContext(mock.patch.object(services, "PiServiceChannels", InertLease))
        self.lease = InertLease()
        self.f.channels = replace(self.f.channels, service_custody=self.lease)
        self.f.dispatch.channels = self.f.channels
        self.lease.request_channels = self.f.channels

    def test_held_service_guard_precedes_request_dispatch(self):
        def guard(**options):
            self.f.forward.assert_not_called()
            self.assertEqual(options, {"deadline": 115})
        self.lease.guard.side_effect = guard
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.assertEqual(self.lease.guard.call_count, 2)

    def test_nested_native_guard_rechecks_service_lease(self):
        def forwarded(*args, **kwargs):
            kwargs["native_custody"].guard()
            return {"status": "COMPLETED"}
        self.f.forward.side_effect = forwarded
        self.f.handle()
        self.assertEqual(self.lease.guard.call_count, 3)

    def test_withdrawn_service_lease_blocks_before_request_consumption(self):
        self.lease.guard.side_effect = RuntimeError("withdrawn")
        with self.assertRaisesRegex(RuntimeError, "withdrawn"):
            self.f.handle()
        self.assertFalse(self.f.owned.request_attempted)
        self.f.forward.assert_not_called()

    def test_plain_receipt_or_callback_is_not_a_service_lease(self):
        for value in ({"active": True}, lambda: None):
            self.f.channels = replace(self.lease.request_channels, service_custody=value)
            self.f.dispatch.channels = self.f.channels
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.f.handle()
        self.f.forward.assert_not_called()

    def test_lease_cannot_be_rebound_to_copied_channel_configuration(self):
        self.f.channels = replace(self.f.channels)
        self.f.dispatch.channels = self.f.channels
        with self.assertRaisesRegex(RuntimeError, "custody binding"):
            self.f.handle()
        self.lease.guard.assert_not_called()

    def test_request_cannot_extend_service_lease_deadline(self):
        self.lease.deadline = 114
        with self.assertRaisesRegex(RuntimeError, "custody binding"):
            self.f.handle()
        self.lease.guard.assert_not_called()

    def test_retired_provider_does_not_remove_broker_sensor_guard(self):
        self.lease.provider_retired = True
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.assertEqual(self.lease.guard.call_count, 2)
        self.lease.retire_provider.assert_not_called()


class ProviderServiceWiringTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(linecache, "getlines", return_value=[]))
        self.enterContext(mock.patch.object(linecache, "checkcache", return_value=None))
        self.e = provider_fixtures.ProviderEgressTests(methodName="runTest")
        self.e.setUp()
        self.addCleanup(self.e.doCleanups)
        self.f = self.e.f
        self.enterContext(mock.patch.object(services, "PiServiceChannels", InertLease))
        self.lease = InertLease()
        self.lease.provider_connection = self.f.provider
        self.lease.provider_peer = self.f.peer

    def run_request(self, **options):
        return self.f.run_request(provider_service=True, service_custody=self.lease, **options)

    def test_custody_rechecks_cover_handoff_connect_send_and_terminal(self):
        observed = []
        self.lease.guard.side_effect = lambda **options: observed.append((len(self.e.sent), self.lease.provider_retired))
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        self.assertIn((0, False), observed)
        self.assertIn((1, False), observed)
        self.assertIn((2, False), observed)
        self.assertEqual(observed[-1], (3, True))
        self.lease.retire_provider.assert_called_once()

    def test_tightened_action_deadline_reaches_guard_and_retirement(self):
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        self.assertEqual(self.lease.guard.call_args_list[0], mock.call(deadline=120.0))
        self.assertEqual(self.lease.guard.call_args_list[-1], mock.call(deadline=103.0))
        self.lease.retire_provider.assert_called_once_with(deadline=103.0)

    def test_custody_change_between_connect_and_send_refuses_second_permit(self):
        def changed(index):
            if index == 1:
                self.lease.guard.side_effect = RuntimeError("changed service bytes")
        self.e.before_receive = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.assertEqual(len(self.e.sent), 2)
        self.lease.retire_provider.assert_not_called()

    def test_terminal_retirement_failure_cannot_deliver_success(self):
        self.lease.retire_provider.side_effect = RuntimeError("terminal custody hold")
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.lease.retire_provider.assert_called_once()

    def test_invalid_terminal_never_retires_provider(self):
        def changed(index, packet):
            if index == 2:
                packet["cleanup"] = "CLEANUP_HOLD"
            return packet
        self.e.mutate_reply = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.lease.retire_provider.assert_not_called()

    def test_validated_terminal_allows_provider_exit_and_retires_once(self):
        def exited(index):
            if index == 2:
                self.f.peer_live.side_effect = RuntimeError("provider exited")
        self.e.before_receive = exited
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        self.assertTrue(self.lease.provider_retired)
        self.lease.retire_provider.assert_called_once()

    def test_retired_provider_cannot_start_a_second_exchange(self):
        self.lease.provider_retired = True
        with self.assertRaisesRegex(RuntimeError, "ALREADY_RETIRED"):
            self.run_request()
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()

    def test_wrong_provider_connection_peer_or_lease_deadline_refuses_before_read(self):
        mutations = (
            ("provider_connection", object()),
            ("provider_peer", (999, *self.f.peer[1:])),
            ("deadline", 119.0),
        )
        for name, value in mutations:
            old = getattr(self.lease, name)
            setattr(self.lease, name, value)
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "CUSTODY_REFUSED"):
                self.run_request()
            setattr(self.lease, name, old)
        self.f.read.assert_not_called()

    def test_lease_refuses_legacy_v1_mode_before_identity_or_claim(self):
        with self.assertRaisesRegex(RuntimeError, "REQUIRES_V2"):
            self.f.run_request(service_custody=self.lease)
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()

    def test_plain_document_is_not_provider_custody(self):
        with self.assertRaisesRegex(RuntimeError, "CUSTODY_REFUSED"):
            self.f.run_request(provider_service=True, service_custody={"active": True})
        self.f.read.assert_not_called()


def load_tests(loader, tests, pattern):
    for name in ("test_exact_held_native_custody_wraps_existing_reader_and_sensor_channel",
                 "test_each_nested_guard_rechecks_real_native_and_request_identity"):
        tests.addTest(native_fixtures.NativeCustodyTests(name))
    for name in ("test_root_binds_exact_wire_and_checks_twice_under_one_claim",
                 "test_authenticated_terminal_may_precede_service_exit_without_fabricated_liveness"):
        tests.addTest(provider_fixtures.ProviderEgressTests(name))
    return tests
