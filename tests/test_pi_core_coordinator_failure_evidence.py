"""Focused failure propagation; inert owners, no VM or effect execution."""

import unittest

import test_pi_core_coordinator_entry as legacy
import test_pi_core_coordinator_wrapper as wrapper_fixture


def partial_result():
    return {"schema": "aragorn/pi-core-managed-bootstrap-result/v1",
        "authority": "SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3",
        "status": "CLEANUP_HOLD", "worker": {"status": "BOOTSTRAP_COMPLETE",
            "cleanup": {"status": "VERIFIED_OWNED_CLEANUP"},
            "request_channel": {"private_task": "must-not-appear-on-stdout"}},
        "services": {"cleanup": {"status": "CLEANUP_HOLD"}},
        "provider_configured": False, "provider_available": False,
        "useful_task_verified": False, "loaded_code_verified": False,
        "phase3_exit_eligible": False}


class CoordinatorFailureEvidenceTests(legacy.CoordinatorEntryTests):
    def failed_call(self, result=None, error=None):
        self.error = RuntimeError("private failure detail") if error is None else error
        if result is not None:
            self.error.pi_managed_bootstrap_observation = result
        self.call.side_effect = self.error
        with self.assertRaises(legacy.subject.PiCoordinatorEntryError) as raised:
            self.invoke()
        self.call.assert_called_once()
        self.input_holder.close.assert_called_once()
        return raised.exception

    def test_child_cleanup_hold_retains_worker_evidence_and_original_cause(self):
        value = partial_result()
        error = self.failed_call(value)
        self.assertIs(error.__cause__, self.error)
        self.assertEqual(error.observation["managed_result"], value)
        self.assertEqual(error.observation["managed_failure_evidence"], "RETAINED")
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertTrue(error.observation["owned_inputs_closed"])

    def test_retained_failure_is_detached_from_owner_mutation(self):
        value = partial_result()
        error = self.failed_call(value)
        value["worker"]["request_channel"].clear()
        self.assertIn("private_task", error.observation["managed_result"]["worker"]["request_channel"])

    def test_holder_cleanup_replacement_cannot_erase_child_observation(self):
        self.fail_close = "public"
        value = partial_result()
        error = self.failed_call(value)
        self.assertIsNot(error.__cause__, self.error)
        self.assertEqual(error.observation["managed_result"], value)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")

    def test_holder_cleanup_replacement_marks_hold_even_after_child_refusal(self):
        self.fail_close = "public"
        value = partial_result() | {"status": "REFUSED", "worker": None, "services": None}
        error = self.failed_call(value)
        self.assertEqual(error.observation["managed_result"], value)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["failure_stage"], "HOLDER_CLEANUP")

    def test_input_cleanup_failure_retains_child_and_exact_uncertainty(self):
        self.input_holder.close.side_effect = OSError("uncertain input close")
        self.input_holder.cleanup_uncertainty = [{"scope": "DESCRIPTOR_CLOSE", "descriptors": [17]}]
        error = self.failed_call(partial_result())
        self.assertFalse(error.observation["owned_inputs_closed"])
        self.assertEqual(error.observation["managed_result"]["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["input_cleanup_uncertainty"], self.input_holder.cleanup_uncertainty)

    def test_missing_child_evidence_stays_unknown_not_fabricated(self):
        error = self.failed_call()
        self.assertIsNone(error.observation["managed_result"])
        self.assertEqual(error.observation["managed_failure_evidence"], "UNAVAILABLE_OR_INVALID")
        self.assertEqual(error.observation["status"], "REFUSED_OR_INDETERMINATE")

    def test_partial_refusal_preserves_null_owners_without_promoting_cleanup(self):
        value = partial_result() | {"status": "REFUSED", "worker": None, "services": None}
        error = self.failed_call(value)
        self.assertEqual(error.observation["managed_result"], value)
        self.assertEqual(error.observation["status"], "REFUSED_OR_INDETERMINATE")

    def test_malformed_or_qualifying_child_result_is_not_adopted(self):
        cases = [{}, [], partial_result() | {"schema": "different"},
            partial_result() | {"authority": "different"},
            partial_result() | {"status": "BOOTSTRAP_COMPLETE"},
            partial_result() | {"worker": []}, partial_result() | {"services": "closed"},
            partial_result() | {"provider_configured": 0}]
        cases += [partial_result() | {name: True} for name in
            ("provider_available", "useful_task_verified", "loaded_code_verified", "phase3_exit_eligible")]
        for value in cases:
            with self.subTest(value=value):
                self.call.reset_mock()
                self.input_holder.close.reset_mock()
                error = self.failed_call(value)
                self.assertIsNone(error.observation["managed_result"])
                self.assertIs(error.__cause__, self.error)

    def test_nonserializable_and_oversized_child_evidence_do_not_mask_failure(self):
        cyclic = partial_result()
        cyclic["worker"]["cycle"] = cyclic
        for value in (cyclic, partial_result() | {"unknown": object()},
                      partial_result() | {"large": "x" * (4 * 1024 * 1024)}):
            self.call.reset_mock()
            self.input_holder.close.reset_mock()
            error = self.failed_call(value)
            self.assertIsNone(error.observation["managed_result"])
            self.assertIs(error.__cause__, self.error)

    def test_raising_evidence_property_does_not_replace_original_exception(self):
        class FailedEvidence(RuntimeError):
            @property
            def pi_managed_bootstrap_observation(self):
                raise ValueError("private snapshot failure")
        error = self.failed_call(error=FailedEvidence("original failure"))
        self.assertIs(error.__cause__, self.error)
        self.assertIsNone(error.observation["managed_result"])

    def test_cancellation_keeps_child_evidence_and_no_second_invocation(self):
        error = self.failed_call(partial_result(), error=KeyboardInterrupt())
        self.assertIs(error.__cause__, self.error)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")


class PublicFailureProjectionTests(wrapper_fixture.CoordinatorWrapperTests):
    def test_partial_managed_evidence_is_digest_only_in_public_report(self):
        value = self.observation()
        value.update(status="CLEANUP_HOLD", managed_result=partial_result(), failure_stage="MANAGED_CALL")
        report = self.s._public_observation(value)
        self.assertEqual(report["managed_status"], "CLEANUP_HOLD")
        self.assertEqual(report["managed_result_digest"], self.s._digest(self.s._canonical(value["managed_result"])))
        self.assertFalse(report["managed_cleanup_complete"])
        self.assertNotIn(b"must-not-appear-on-stdout", self.s._canonical(report))
        self.assertNotIn("managed_result", report)

    def test_missing_owner_is_not_reported_as_complete_cleanup(self):
        value = self.observation()
        value.update(status="REFUSED_OR_INDETERMINATE",
            managed_result=partial_result() | {"status": "REFUSED", "worker": None, "services": None})
        report = self.s._public_observation(value)
        self.assertFalse(report["managed_cleanup_complete"])
        self.assertFalse(report["phase3_exit_eligible"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in (CoordinatorFailureEvidenceTests, PublicFailureProjectionTests):
        suite.addTests(cls(name) for name in sorted(cls.__dict__) if name.startswith("test_"))
    suite.addTests(legacy.CoordinatorEntryTests(name) for name in (
        "test_unavailable_calls_once_with_derived_inputs_and_readonly_cas",
        "test_protected_uses_only_existing_metadata_credential_and_approval_holders",
        "test_managed_failure_is_not_retried_and_input_custody_closes",
        "test_holder_cleanup_failure_retains_result_and_marks_hold",
        "test_returned_managed_refusal_and_cleanup_hold_are_not_success"))
    return suite
