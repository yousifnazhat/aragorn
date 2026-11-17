"""Failure propagation only; native services and provider calls remain inert."""

from contextlib import contextmanager
import copy
import unittest
from unittest import mock

from aragorn import pi_core_managed_bootstrap as subject
from aragorn.oci_worker_protocol import WorkerProtocolError
from tests import test_pi_core_managed_bootstrap as managed_fixtures
from tests import test_pi_core_provider_managed as provider_fixtures


class ManagedFailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = managed_fixtures.ManagedBootstrapTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.worker_result.update(
            schema="aragorn/pi-core-native-supervisor-result/v1",
            authority="BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION",
            provider_channel={"status": "COMPLETED", "response": {"sum": 6}},
            source_observation={"capture": {"inert": True}})
        self.f.services.observation.update(
            schema="aragorn/pi-core-service-lifecycle/v1", status="CLOSED",
            loaded_code_verified=False, phase3_exit_eligible=False)

    def escaped(self, error):
        with self.assertRaises(type(error)) as caught:
            self.f.run_bootstrap()
        self.assertIs(caught.exception, error)
        result = caught.exception.pi_managed_bootstrap_observation
        self.assertEqual(result["schema"], "aragorn/pi-core-managed-bootstrap-result/v1")
        self.assertEqual(result["authority"], "SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3")
        for field in ("provider_available", "useful_task_verified", "loaded_code_verified", "phase3_exit_eligible"):
            self.assertIs(result[field], False)
        self.assertIn(result["status"], ("REFUSED", "CLEANUP_HOLD"))
        return result

    def acquisition_error(self, error, observation):
        if observation is not None:
            error.pi_service_lifecycle_observation = observation
        self.f.hold.side_effect = error
        return self.escaped(error)

    def test_returned_worker_survives_service_teardown_failure(self):
        error = self.f.cleanup_error = RuntimeError("inert teardown refusal")
        result = self.escaped(error)
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertEqual(result["services"], self.f.services.observation)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["failure_evidence"], {
            "service_scope_acquired": True, "worker_call_attempted": True, "uncertainty": []})
        self.f.hold.assert_called_once()
        self.f.worker.assert_called_once()
        self.f.services.close.assert_not_called()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_returned_worker_snapshot_precedes_teardown_mutation(self):
        original = copy.deepcopy(self.f.worker_result)
        error = RuntimeError("inert post-return failure")
        self.f.worker.side_effect = None
        self.f.worker.return_value = self.f.worker_result
        @contextmanager
        def hold(**kwargs):
            yield self.f.services
            self.f.worker_result["provider_channel"]["response"]["sum"] = 999
            raise error
        self.f.hold.side_effect = hold
        self.assertEqual(self.escaped(error)["worker"], original)

    def test_service_snapshot_is_detached_from_later_mutation(self):
        error = self.f.cleanup_error = RuntimeError("inert cleanup failure")
        result = self.escaped(error)
        self.f.services.observation["cleanup"]["status"] = "changed after capture"
        self.assertEqual(result["services"]["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")

    def test_lifecycle_acquisition_failure_retains_its_closed_record(self):
        error = subject.lifecycle.PiServiceLifecycleError("inert startup refusal")
        result = self.acquisition_error(error, copy.deepcopy(self.f.services.observation))
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["services"]["status"], "CLOSED")
        self.assertFalse(result["failure_evidence"]["service_scope_acquired"])
        self.assertFalse(result["failure_evidence"]["worker_call_attempted"])
        self.f.worker.assert_not_called()

    def test_oserror_acquisition_retains_factory_attached_lifecycle_record(self):
        result = self.acquisition_error(OSError("inert open refusal"),
                                        copy.deepcopy(self.f.services.observation))
        self.assertEqual(result["services"], self.f.services.observation)
        self.assertEqual(result["status"], "REFUSED")
        self.f.worker.assert_not_called()

    def test_acquisition_without_record_keeps_unknown_cleanup(self):
        result = self.acquisition_error(OSError("inert unavailable owner"), None)
        self.assertIsNone(result["worker"])
        self.assertIsNone(result["services"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertIn({"owner": "services", "reason": "NO_OWNED_OBSERVATION"},
                      result["failure_evidence"]["uncertainty"])

    def test_acquisition_cleanup_hold_cannot_become_refusal_with_clean_owners(self):
        value = copy.deepcopy(self.f.services.observation)
        value.update(status="CLEANUP_HOLD", cleanup={"status": "CLEANUP_HOLD"})
        result = self.acquisition_error(OSError("inert hold"), value)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["services"], value)

    def test_invalid_exception_records_are_not_adopted(self):
        initial = copy.deepcopy(self.f.services.observation)
        for value in ([], {}, initial | {"schema": "foreign"},
                      initial | {"status": "QUALIFIED"},
                      initial | {"loaded_code_verified": True},
                      initial | {"phase3_exit_eligible": True},
                      initial | {"cleanup": "verified"}):
            with self.subTest(value=value):
                result = self.acquisition_error(OSError("inert invalid record"), value)
                self.assertIsNone(result["services"])
                self.assertEqual(result["status"], "CLEANUP_HOLD")
                self.assertIn({"owner": "services", "reason": "INVALID_EXCEPTION_OBSERVATION"},
                              result["failure_evidence"]["uncertainty"])

    def test_service_guard_failure_has_no_worker_attempt_and_retains_cleanup(self):
        error = RuntimeError("inert guard refusal")
        self.f.services.guard.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertFalse(result["failure_evidence"]["worker_call_attempted"])
        self.assertEqual(result["status"], "REFUSED")
        self.f.worker.assert_not_called()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_worker_exception_keeps_unknown_worker_cleanup(self):
        error = RuntimeError("inert worker failure")
        self.f.worker.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertTrue(result["failure_evidence"]["worker_call_attempted"])
        self.assertIn({"owner": "worker", "reason": "NO_RETURNED_OBSERVATION"},
                      result["failure_evidence"]["uncertainty"])
        self.f.worker.assert_called_once()

    def test_arbitrary_native_exception_attributes_do_not_supply_worker_evidence(self):
        error = subject.native.PiNativeSupervisorError("no native retention contract")
        error.pi_native_supervisor_observation = copy.deepcopy(self.f.worker_result)
        error.pi_managed_bootstrap_observation = {"status": "BOOTSTRAP_COMPLETE"}
        self.f.worker.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_cleanup_replacement_keeps_unknown_worker_and_same_escaped_error(self):
        worker_error = RuntimeError("inert body failure")
        self.f.worker.side_effect = worker_error
        escaped = self.f.cleanup_error = OSError("inert teardown failure")
        result = self.escaped(escaped)
        self.assertIs(escaped.__context__, worker_error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.f.worker.assert_called_once()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_keyboard_interrupt_is_preserved_and_does_not_infer_worker_cleanup(self):
        error = KeyboardInterrupt()
        self.f.worker.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_teardown_system_exit_preserves_already_returned_worker(self):
        error = self.f.cleanup_error = SystemExit(7)
        result = self.escaped(error)
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertEqual(error.code, 7)

    def test_service_snapshot_failure_never_masks_existing_exception(self):
        error = self.f.cleanup_error = RuntimeError("keep this error")
        with mock.patch.object(type(self.f.services), "observation", create=True,
                               new_callable=mock.PropertyMock,
                               side_effect=KeyboardInterrupt("inert snapshot refusal")) as read:
            result = self.escaped(error)
        self.assertIsNone(result["services"])
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        read.assert_called_once_with()

    def test_lifecycle_exception_snapshot_can_survive_failed_held_snapshot(self):
        error = self.f.cleanup_error = OSError("inert cleanup error")
        error.pi_service_lifecycle_observation = copy.deepcopy(self.f.services.observation)
        with mock.patch.object(type(self.f.services), "observation", create=True,
                               new_callable=mock.PropertyMock, side_effect=ValueError("inert unreadable")):
            result = self.escaped(error)
        self.assertEqual(result["services"], error.pi_service_lifecycle_observation)
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_noncanonical_service_record_keeps_original_error_and_fixed_uncertainty(self):
        error = self.f.cleanup_error = RuntimeError("private exception text")
        self.f.services.observation["noncanonical"] = float("nan")
        result = self.escaped(error)
        self.assertIsNone(result["services"])
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertNotIn("private exception text", repr(result["failure_evidence"]))
        self.assertIn({"owner": "services", "reason": "SNAPSHOT_UNAVAILABLE"},
                      result["failure_evidence"]["uncertainty"])

    def test_post_cleanup_observation_read_failure_keeps_returned_worker_without_reread(self):
        error = OSError("inert final read failure")
        with mock.patch.object(type(self.f.services), "observation", create=True,
                               new_callable=mock.PropertyMock, side_effect=error) as read:
            result = self.escaped(error)
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertIsNone(result["services"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        read.assert_called_once_with()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_post_cleanup_result_classification_failure_retains_both_records(self):
        self.f.services.observation["cleanup"] = None
        with self.assertRaises(AttributeError) as caught:
            self.f.run_bootstrap()
        result = caught.exception.pi_managed_bootstrap_observation
        self.assertEqual(result["worker"], self.f.worker_result)
        self.assertEqual(result["services"], self.f.services.observation)
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_worker_snapshot_failure_precedes_cleanup_without_retry(self):
        self.f.worker_result["noncanonical"] = float("nan")
        with self.assertRaises(WorkerProtocolError) as caught:
            self.f.run_bootstrap()
        result = caught.exception.pi_managed_bootstrap_observation
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.f.worker.assert_called_once()
        self.assertEqual(self.f.events.count("services-cleanup"), 1)

    def test_worker_snapshot_failure_cannot_replace_later_cleanup_error(self):
        self.f.worker_result["noncanonical"] = float("nan")
        error = self.f.cleanup_error = OSError("inert later cleanup failure")
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertIn({"owner": "worker", "reason": "SNAPSHOT_UNAVAILABLE"},
                      result["failure_evidence"]["uncertainty"])

    def test_oversized_worker_snapshot_is_not_attached_as_usable_evidence(self):
        self.f.worker_result["oversized"] = "x" * (4 * 1024 * 1024)
        error = self.f.cleanup_error = OSError("inert cleanup failure")
        result = self.escaped(error)
        self.assertIsNone(result["worker"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertLess(len(subject.canonical_json(result)), 4096)

    def test_oversized_service_exception_record_is_not_adopted(self):
        value = copy.deepcopy(self.f.services.observation)
        value["oversized"] = "x" * (4 * 1024 * 1024)
        result = self.acquisition_error(OSError("inert startup failure"), value)
        self.assertIsNone(result["services"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_exception_attachment_refusal_never_replaces_original_error(self):
        class SealedError(RuntimeError):
            def __setattr__(self, key, value):
                if key == "pi_managed_bootstrap_observation":
                    raise TypeError("inert attachment refusal")
                super().__setattr__(key, value)
        error = self.f.cleanup_error = SealedError("original error")
        with self.assertRaises(SealedError) as caught:
            self.f.run_bootstrap()
        self.assertIs(caught.exception, error)
        self.assertFalse(hasattr(error, "pi_managed_bootstrap_observation"))
        self.f.worker.assert_called_once()

    def test_normal_result_does_not_gain_failure_metadata(self):
        result = self.f.run_bootstrap()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertNotIn("failure_evidence", result)
        self.assertEqual(result["worker"], self.f.worker_result)


class ProviderFailureEvidenceTests(unittest.TestCase):
    def test_enabled_failure_preserves_configuration_without_releasing_borrowed_authority(self):
        fixture = provider_fixtures.ManagedProviderTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        error = fixture.f.cleanup_error = OSError("inert provider lifetime refusal")
        with self.assertRaises(OSError) as caught:
            fixture.run_enabled()
        self.assertIs(caught.exception, error)
        result = error.pi_managed_bootstrap_observation
        self.assertTrue(result["provider_configured"])
        self.assertFalse(result["provider_available"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertEqual(result["worker"], fixture.f.worker_result)
        fixture.f.worker.assert_called_once()
        fixture.credential.guard.assert_called_once_with(deadline=125)
        fixture.approval.guard.assert_called_once_with(deadline=125)
        self.assertFalse(hasattr(fixture.credential, "close"))
        self.assertFalse(hasattr(fixture.approval, "close"))


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(ManagedFailureEvidenceTests)
    suite.addTests(loader.loadTestsFromTestCase(ProviderFailureEvidenceTests))
    for name in (
        "test_existing_worker_receives_exact_owned_channels_inside_service_lifetime",
        "test_deadlines_reserve_worker_cleanup_inside_service_cleanup_budget",
        "test_failed_service_guard_prevents_worker_and_still_cleans_services",
        "test_worker_exception_never_retries_and_cleans_services",
        "test_worker_cleanup_hold_is_not_promoted_by_clean_services",
        "test_service_cleanup_hold_is_not_promoted_by_clean_worker",
        "test_service_cleanup_exception_is_propagated_without_retry",
        "test_refused_worker_cannot_become_success",
    ):
        suite.addTest(managed_fixtures.ManagedBootstrapTests(name))
    for name in (
        "test_enabled_caller_joins_same_credential_approval_and_service_channels",
        "test_worker_failure_does_not_retry_or_release_borrowed_authority",
    ):
        suite.addTest(provider_fixtures.ManagedProviderTests(name))
    return suite
