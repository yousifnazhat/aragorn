"""New mandatory source-health joins over existing inert caller fixtures only.

The observer method is mocked to isolate these enforcement boundaries. These
checks neither trace a task nor establish source consumption, sensor health,
Node compatibility or qualification. No old test class is inherited or selected.
"""

import copy
import linecache
from dataclasses import replace
import unittest
from unittest import mock

from aragorn import pi_core_native_request as native
from aragorn import pi_core_provider_mediation as provider
from aragorn import pi_core_source_observer as source
from tests import test_pi_core_native_request as native_fixture
from tests import test_pi_core_provider_egress as provider_fixture
from tests import test_pi_core_provider_mediation as mediation_fixture
from tests import test_pi_core_service_channels as channel_fixture


class Lookalike:
    def __init__(self, owned=None):
        self._owned = owned
        self.guard_source_health = mock.Mock()


class NativeSourceHealthTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(linecache, "getlines", return_value=[]))
        self.enterContext(mock.patch.object(linecache, "checkcache", return_value=None))
        self.f = native_fixture.InertTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        # Reuse the fixture's sole autospec patch, never autospec an existing mock.
        self.observer, self.health = self.f.source_observer, self.f.source_health

    def attach(self, observer):
        self.f.channels = replace(self.f.channels, source_observer=observer)
        self.f.dispatch.channels = self.f.channels

    def test_existing_native_channels_without_observer_deny_protected_handoff(self):
        default_channels = native.PiNativeRequestChannels(self.f.broker, self.f.sensor,
            self.f.channels.broker_peer, self.f.channels.sensor_peer, self.f.binding)
        self.assertIsNone(default_channels.source_observer)
        with self.assertRaisesRegex(native.PiNativeRequestError, "source observer"):
            self.f.handle(source_observer=default_channels.source_observer)
        self.assertIsNone(self.f.channels.source_observer)
        self.health.assert_not_called()
        self.f.forward.assert_not_called()

    def test_serialized_healthy_receipt_cannot_replace_held_observer(self):
        self.attach({"state": "HELD", "source_complete": True, "loss": 0})
        with self.assertRaisesRegex(native.PiNativeRequestError, "source observer"):
            self.f.handle()
        self.health.assert_not_called()
        self.f.forward.assert_not_called()

    def test_lookalike_guard_is_never_called(self):
        value = Lookalike(self.f.owned)
        self.attach(value)
        with self.assertRaisesRegex(native.PiNativeRequestError, "source observer"):
            self.f.handle()
        value.guard_source_health.assert_not_called()

    def test_observer_subclass_is_not_the_protected_factory_type(self):
        class Derived(source.PiSourceObserver):
            pass
        value = object.__new__(Derived)
        value._owned = self.f.owned
        self.attach(value)
        with self.assertRaisesRegex(native.PiNativeRequestError, "source observer"):
            self.f.handle()
        self.health.assert_not_called()

    def test_exact_observer_for_another_owned_worker_is_refused(self):
        self.observer._owned = object()
        self.attach(self.observer)
        with self.assertRaisesRegex(native.PiNativeRequestError, "source observer"):
            self.f.handle()
        self.health.assert_not_called()

    def test_same_activation_and_original_deadline_precede_broker_sensor_handoff(self):
        self.attach(self.observer)
        def checked(held, *, activation, deadline):
            self.assertIs(held, self.observer)
            self.assertEqual(activation, native_fixture.activation())
            self.assertEqual(deadline, 115)
            self.f.forward.assert_not_called()
        self.health.side_effect = checked
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.health.assert_called_once()
        self.assertEqual(self.f.forward.call_args.kwargs["deadline"], 115)
        self.assertIs(self.f.forward.call_args.kwargs["sensor_channel"].connection, self.f.sensor)

    def test_every_nested_current_guard_rechecks_observer(self):
        self.attach(self.observer)
        def forwarded(*args, **options):
            options["native_custody"].guard()
            options["native_custody"].guard()
            return {"status": "COMPLETED"}
        self.f.forward.side_effect = forwarded
        self.f.handle()
        self.assertEqual(self.health.call_count, 3)
        self.assertTrue(all(call.kwargs == {"activation": native_fixture.activation(), "deadline": 115}
                            for call in self.health.call_args_list))

    def test_stale_or_incomplete_source_health_blocks_without_effect_retry(self):
        self.attach(self.observer)
        self.health.side_effect = RuntimeError("SOURCE_COVERAGE_OR_ACTIVATION")
        with self.assertRaisesRegex(RuntimeError, "SOURCE_COVERAGE"):
            self.f.handle()
        with self.assertRaisesRegex(RuntimeError, "already attempted"):
            self.f.handle()
        self.health.assert_called_once()
        self.f.forward.assert_not_called()

    def test_loss_after_handoff_prevents_next_current_guard(self):
        self.attach(self.observer)
        self.health.side_effect = [None, RuntimeError("OBSERVER_LOSS")]
        def forwarded(*args, **options):
            options["native_custody"].guard()
        self.f.forward.side_effect = forwarded
        with self.assertRaisesRegex(RuntimeError, "OBSERVER_LOSS"):
            self.f.handle()
        self.assertEqual(self.health.call_count, 2)
        self.assertFalse(self.f.forward.call_args.kwargs["native_custody"]._active)

    def test_changed_activation_is_not_hidden_by_health_success(self):
        self.attach(self.observer)
        self.f.read_activation.return_value = {**native_fixture.activation(), "pid": 301}
        with self.assertRaisesRegex(RuntimeError, "activation changed"):
            self.f.handle()
        self.health.assert_not_called()

    def test_cancelled_health_check_preserves_one_shot_and_borrowed_handles(self):
        self.attach(self.observer)
        self.health.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.f.handle()
        self.assertTrue(self.f.owned.request_attempted)
        self.f.forward.assert_not_called()
        for connection in (self.f.bootstrap, self.f.worker, self.f.broker, self.f.sensor):
            connection.close.assert_not_called()


class ProviderSourceHealthTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(linecache, "getlines", return_value=[]))
        self.enterContext(mock.patch.object(linecache, "checkcache", return_value=None))
        self.e = provider_fixture.ProviderEgressTests(methodName="runTest")
        self.e.setUp()
        self.addCleanup(self.e.doCleanups)
        self.f = self.e.f
        self.observer, self.health = self.f.source_observer, self.f.source_health

    def run_request(self, **options):
        arguments = dict(provider_service=True, source_observer=self.observer)
        arguments.update(options)
        return self.f.run_request(**arguments)

    def test_missing_observer_refuses_before_request_read_or_claim(self):
        with self.assertRaisesRegex(provider.PiProviderMediationError, "SOURCE_OBSERVER_REQUIRED"):
            self.f.run_request(provider_service=True, source_observer=None)
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()
        self.assertEqual(self.e.sent, [])

    def test_legacy_provider_handoff_cannot_bypass_observer_requirement(self):
        with self.assertRaisesRegex(provider.PiProviderMediationError, "SOURCE_OBSERVER_REQUIRED"):
            self.f.run_request(source_observer=None)
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()

    def test_serialized_source_coverage_cannot_authorize_provider_payload(self):
        with self.assertRaisesRegex(provider.PiProviderMediationError, "SOURCE_OBSERVER_REQUIRED"):
            self.f.run_request(provider_service=True, source_observer={"state": "HELD", "source_complete": True})
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()

    def test_lookalike_provider_guard_is_never_called(self):
        value = Lookalike()
        with self.assertRaisesRegex(provider.PiProviderMediationError, "SOURCE_OBSERVER_REQUIRED"):
            self.f.run_request(provider_service=True, source_observer=value)
        value.guard_source_health.assert_not_called()
        self.f.read.assert_not_called()

    def test_initial_missing_health_retains_not_submitted_without_reading_payload(self):
        self.health.side_effect = RuntimeError("OBSERVER_CUSTODY")
        result = self.run_request()
        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.assertEqual(result["failure_stage"], "SOURCE_HEALTH")
        self.assertIsNone(result["request_digest"])
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()
        self.assertEqual(self.e.sent, [])

    def test_same_activation_and_tightened_budget_are_used_for_each_check(self):
        observed = []
        def checked(held, *, activation, deadline):
            self.assertIs(held, self.observer)
            self.assertEqual(activation, self.f.activation)
            observed.append((len(self.e.sent), deadline, copy.deepcopy(activation)))
        self.health.side_effect = checked
        result = self.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(observed[0][1], 120.0)
        self.assertEqual(observed[-1][1], 103.0)
        self.assertEqual({item[0] for item in observed}, {0, 1, 2})
        self.assertTrue(all(item[1] <= 120.0 for item in observed))

    def test_lost_health_before_service_submission_does_not_send_payload(self):
        def committed(*args):
            self.f.storage["state.json"] = copy.deepcopy(args[-1])
            self.health.side_effect = RuntimeError("OBSERVER_LOSS")
        self.f.commit.side_effect = committed
        result = self.run_request()
        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.assertEqual(result["activation_claim"], "RETAINED_OR_UNCERTAIN")
        self.assertTrue(self.f.claims)
        self.assertEqual(self.e.sent, [])

    def test_lost_health_before_connect_keeps_spent_claim_and_blocks_permit(self):
        self.e.before_receive = lambda index: setattr(self.health, "side_effect", RuntimeError("OBSERVER_LOSS"))
        result = self.run_request()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertEqual(result["egress_checks"], 0)
        self.assertEqual([packet["kind"] for packet in self.e.sent], ["REQUEST"])
        self.assertTrue(self.f.claims)

    def test_lost_health_between_connect_and_send_blocks_second_permit(self):
        def before(index):
            if index == 1:
                self.health.side_effect = RuntimeError("OBSERVER_LOSS")
        self.e.before_receive = before
        result = self.run_request()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertEqual(result["egress_checks"], 1)
        self.assertEqual([packet["kind"] for packet in self.e.sent], ["REQUEST", "CURRENT"])
        self.assertTrue(self.f.claims)

    def test_terminal_cleanup_does_not_renew_source_or_egress_authority(self):
        def before(index):
            if index == 2:
                self.health.side_effect = RuntimeError("terminal source scope ended")
        self.e.before_receive = before
        result = self.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["egress_checks"], 2)
        self.assertEqual([packet["kind"] for packet in self.e.sent], ["REQUEST", "CURRENT", "CURRENT"])

    def test_original_short_permit_is_not_widened_for_source_challenge(self):
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        for packet in self.e.sent[1:]:
            self.assertEqual(packet["permit_expires_monotonic_ns"], 100_100_000_000)
            self.assertEqual(packet["deadline_ns"], 103_000_000_000)

    def test_existing_unhealthy_policy_still_blocks_despite_observer_success(self):
        self.f.storage["health.json"]["status"] = "unhealthy"
        result = self.run_request()
        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.f.claim.assert_not_called()
        self.assertEqual(self.e.sent, [])

    def test_changed_activation_cannot_be_approved_by_a_healthy_observer(self):
        provider.broker._peer_credentials.return_value = (9999, 1201, 1202)
        with self.assertRaisesRegex(provider.PiProviderMediationError, "WORKER_PEER_REFUSED"):
            self.run_request()
        self.health.assert_not_called()

    def test_cancelled_source_check_runs_cleanup_without_submission_or_retry(self):
        self.health.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_request()
        self.f.release.assert_called_once()
        self.f.read.assert_not_called()
        self.f.claim.assert_not_called()
        self.assertEqual(self.e.sent, [])

    def test_selected_existing_authenticated_terminal_with_explicit_inert_observer(self):
        # Select one affected case with the explicit inert dependency; no source
        # acquisition or readiness is implied by the fixture's mocked guard.
        self.e.run_request = self.run_request
        provider_fixture.ProviderEgressTests.test_authenticated_terminal_may_precede_service_exit_without_fabricated_liveness(self.e)


def load_tests(loader, tests, pattern):
    """Four selected old cases plus the terminal wrapper, not whole suites."""
    tests.addTest(native_fixture.SelectionTests(
        "test_unavailable_bootstrap_returns_no_request_without_fabricating_work"))
    tests.addTest(native_fixture.SelectionTests(
        "test_one_actual_request_is_dispatched_then_owned_stream_closed_before_result"))
    tests.addTest(mediation_fixture.ProviderMediationTests(
        "test_real_policy_allow_consumes_before_handoff_and_closes_before_worker_completion"))
    tests.addTest(channel_fixture.PiServiceChannelTests(
        "test_real_peer_authentication_builds_existing_request_channels_without_readiness_io"))
    return tests


if __name__ == "__main__":
    unittest.main()
