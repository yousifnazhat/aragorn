"""Native failure evidence through existing managed/root callers; inert only."""

import copy
import unittest

from aragorn import pi_core_managed_bootstrap as subject
from tests import test_pi_core_managed_bootstrap as fixtures
import test_pi_core_coordinator_failure_evidence as root_fixtures


def native_record():
    return {"schema": "aragorn/pi-core-native-supervisor-result/v1",
        "authority": "BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION",
        "status": "CLEANUP_HOLD", "bootstrap": {"status": "WORKER_COMPLETED"},
        "identity_registration": {"status": "NOT_REQUESTED"},
        "request_channel": {"status": "REQUEST_RETURNED"},
        "provider_channel": {"status": "PROVIDER_RETURNED", "private": "fabricated response"},
        "source_observation": {"capture": {"inert": True}},
        "cleanup": {"status": "VERIFIED_OWNED_CLEANUP"},
        "failure_evidence": {"stage": "LAUNCH_SCOPE_EXIT", "launch_scope_cleanup": "UNVERIFIED_ON_EXCEPTION"}}


class NativeFailureCompositionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ManagedBootstrapTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def fail(self, value, error=None):
        self.error = OSError("native cleanup uncertainty") if error is None else error
        self.error.pi_native_supervisor_observation = value
        self.f.worker.side_effect = self.error
        with self.assertRaises(type(self.f.cleanup_error or self.error)) as caught:
            self.f.run_bootstrap()
        self.f.worker.assert_called_once()
        self.f.hold.assert_called_once()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)
        return caught.exception

    def test_native_terminal_record_survives_as_private_managed_evidence(self):
        value = native_record()
        error = self.fail(value)
        self.assertIs(error, self.error)
        result = error.pi_managed_bootstrap_observation
        self.assertEqual(result["worker"], value)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertEqual(result["worker"]["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")

    def test_service_cleanup_replacement_retains_native_snapshot(self):
        self.f.cleanup_error = RuntimeError("service cleanup failure")
        value = native_record()
        error = self.fail(value)
        self.assertIs(error, self.f.cleanup_error)
        self.assertEqual(error.pi_managed_bootstrap_observation["worker"], value)

    def test_native_snapshot_is_detached_before_outer_cleanup(self):
        value = native_record()
        expected = copy.deepcopy(value)
        error = self.fail(value)
        value["provider_channel"].clear()
        self.assertEqual(error.pi_managed_bootstrap_observation["worker"], expected)

    def test_partial_native_owners_remain_null_and_unknown(self):
        value = native_record() | {"bootstrap": None, "source_observation": None, "cleanup": None}
        result = self.fail(value).pi_managed_bootstrap_observation
        self.assertEqual(result["worker"], value)
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_cancelled_native_call_retains_same_exception(self):
        cancellation = KeyboardInterrupt()
        error = self.fail(native_record(), cancellation)
        self.assertIs(error, cancellation)
        self.assertEqual(error.pi_managed_bootstrap_observation["worker"]["status"], "CLEANUP_HOLD")

    def test_foreign_or_success_claiming_exception_record_is_not_adopted(self):
        for value in ({}, [], native_record() | {"schema": "foreign"},
                      native_record() | {"authority": "qualified"},
                      native_record() | {"status": "BOOTSTRAP_COMPLETE"},
                      native_record() | {"cleanup": "closed"}):
            with self.subTest(value=value):
                self.f.worker.reset_mock(); self.f.hold.reset_mock(); self.f.events.clear()
                result = self.fail(value).pi_managed_bootstrap_observation
                self.assertIsNone(result["worker"])
                self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_nonserializable_or_oversized_record_does_not_mask_original(self):
        for value in (native_record() | {"invalid": object()},
                      native_record() | {"large": "x" * (4 * 1024 * 1024)}):
            self.f.worker.reset_mock(); self.f.hold.reset_mock(); self.f.events.clear()
            error = self.fail(value)
            self.assertIs(error, self.error)
            self.assertIsNone(error.pi_managed_bootstrap_observation["worker"])

    def test_clean_services_do_not_erase_held_launch_scope_cleanup_uncertainty(self):
        result = self.fail(native_record()).pi_managed_bootstrap_observation
        self.assertEqual(result["services"]["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["status"], "CLEANUP_HOLD")


class RootNativeFailureEvidenceTests(root_fixtures.CoordinatorFailureEvidenceTests):
    def test_native_record_survives_managed_root_boundary_and_holder_replacement(self):
        value = root_fixtures.partial_result() | {"worker": native_record()}
        self.fail_close = "public"
        error = self.failed_call(value)
        self.assertEqual(error.observation["managed_result"]["worker"], value["worker"])
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(NativeFailureCompositionTests)
    suite.addTest(RootNativeFailureEvidenceTests(
        "test_native_record_survives_managed_root_boundary_and_holder_replacement"))
    suite.addTests(fixtures.ManagedBootstrapTests(name) for name in (
        "test_existing_worker_receives_exact_owned_channels_inside_service_lifetime",
        "test_worker_exception_never_retries_and_cleans_services"))
    return suite
