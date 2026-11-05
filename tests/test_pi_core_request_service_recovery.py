"""New lifecycle/recovery connection and selected affected inert caller checks."""

import unittest
from unittest import mock

from aragorn import pi_core_request_service as service
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_request_service as fixtures


class PiServiceRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PiRequestServiceTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.initialize = self.f.stack.enter_context(mock.patch.object(service.recovery,
            "initialize_pi_runtime_capability_grant", return_value={"status": "AVAILABLE"}))

    def test_recovery_precedes_request_custody_without_initialization(self):
        def recover(*args, **kwargs):
            self.f.hold.assert_not_called()
            self.f.pidfd.assert_not_called()
            self.f.mediate.assert_not_called()
            return {"status": "AVAILABLE"}
        self.f.recover.side_effect = recover
        self.assertEqual(self.f.run_request()["status"], "COMPLETED")
        self.f.recover.assert_called_once_with(self.f.config.broker, deadline_monotonic=120.0)
        self.initialize.assert_not_called()

    def test_terminal_states_block_before_channels_or_effects(self):
        for status in ("CONSUMED", "EXPIRED", "ABANDONED", "CLAIMED"):
            self.f.recover.return_value = {"status": status}
            with self.subTest(status=status), self.assertRaises(service.broker.RuntimeActionBrokerError):
                self.f.run_request()
        self.f.hold.assert_not_called()
        self.f.pidfd.assert_not_called()
        self.f.mediate.assert_not_called()
        self.initialize.assert_not_called()

    def test_recovery_uncertainty_is_preserved_and_never_retried(self):
        self.f.recover.side_effect = service.broker.RuntimeActionEffectIndeterminate("retained hold")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.f.run_request()
        self.f.recover.assert_called_once()
        self.f.hold.assert_not_called()
        self.f.mediate.assert_not_called()
        self.initialize.assert_not_called()

    def test_config_or_deadline_refusal_never_recovers_state(self):
        self.f.validate.side_effect = service.broker.RuntimeActionBrokerError("config refused")
        with self.assertRaises(service.broker.RuntimeActionBrokerError):
            self.f.run_request()
        with self.assertRaises(RuntimeError):
            self.f.run_request(deadline=99.0)
        self.f.recover.assert_not_called()

    def test_explicit_preparation_passes_original_budget_and_returns_only_metadata(self):
        grant = {"fixture": "explicit protected grant"}
        state = {"status": "AVAILABLE", "fixture": "protected durable state"}
        self.f.validate.return_value = grant
        self.initialize.return_value = state
        result = service.initialize_pi_broker_request_service(self.f.config, deadline=120.0, now_unix=1000)
        self.initialize.assert_called_once_with(self.f.config.broker, now_unix=1000, deadline_monotonic=120.0)
        self.assertEqual(result["grant_digest"], canonical_digest(grant))
        self.assertEqual(result["state_digest"], canonical_digest(state))
        self.assertFalse(result["activation_performed"] or result["service_ready"] or result["phase3_exit_eligible"])
        self.assertNotIn("state", result)
        self.f.hold.assert_not_called()
        self.f.mediate.assert_not_called()
        self.f.recover.assert_not_called()

    def test_explicit_preparation_does_not_convert_terminal_state_into_readiness(self):
        self.f.validate.return_value = {"fixture": "grant"}
        self.initialize.return_value = {"status": "CONSUMED"}
        result = service.initialize_pi_broker_request_service(self.f.config, deadline=120.0)
        self.assertEqual(result["status"], "CONSUMED")
        self.assertFalse(result["service_ready"])
        self.f.mediate.assert_not_called()

    def test_preparation_failure_is_not_retried_or_followed_by_activation(self):
        self.initialize.side_effect = service.broker.RuntimeActionEffectIndeterminate("archive hold")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            service.initialize_pi_broker_request_service(self.f.config, deadline=120.0)
        self.initialize.assert_called_once()
        self.f.hold.assert_not_called()
        self.f.mediate.assert_not_called()

    def test_preparation_rejects_expired_original_deadline_before_config(self):
        with self.assertRaises(RuntimeError):
            service.initialize_pi_broker_request_service(self.f.config, deadline=99.0)
        self.f.validate.assert_not_called()
        self.initialize.assert_not_called()


def load_tests(loader, tests, pattern):
    for name in (
        "test_authenticated_inputs_route_once_and_cleanup_before_success",
        "test_config_refusal_does_not_accept_either_channel",
        "test_indeterminate_mediator_never_retries_or_reports_success",
        "test_sensor_close_failure_prevents_done_without_close_retry",
    ):
        tests.addTest(fixtures.PiRequestServiceTests(name))
    return tests
