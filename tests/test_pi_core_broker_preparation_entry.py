"""Inert pinned root preparation composition; no unit, effect or provider runs."""

import copy
from contextlib import contextmanager
from pathlib import Path
import unittest
from unittest import mock

from aragorn import pi_core_broker_preparation_entry as subject
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_coordinator_entry as fixtures


def lifecycle_result():
    return {"schema": "aragorn/pi-core-service-lifecycle/v1", "status": "CLOSED",
        "phase3_exit_eligible": False, "loaded_code_verified": False,
        "cleanup": {"status": "VERIFIED_OWNED_CLEANUP"},
        "broker_preparation": {"schema": "aragorn/pi-core-broker-preparation/v1",
            "authority": "EXPLICIT_GRANT_PREPARATION_NOT_ACTIVATION_OR_PHASE3",
            "status": "PREPARED", "phase": "COMPLETE", "command_attempted": True,
            "ack_attempted": True, "ack_sent": True, "phase3_exit_eligible": False,
            "command": {"fixture": "private-command"}, "result_packet": {"fixture": "private-result"},
            "readback": {"fixture": "private-readback"}}}


class PreparationEntryTests(fixtures.CoordinatorEntryTests):
    def setUp(self):
        super().setUp()
        self.source.source_digests[subject._SOURCE] = fixtures.pin("b")
        values = self.custody.return_value
        values[1].append({"module": subject.__name__, "path": subject._SOURCE, "digest": fixtures.pin("b")})
        self.bundle_fail_enter = self.bundle_fail_close = False

        @contextmanager
        def bundle(*args, **kwargs):
            self.events.append("enter:bundle")
            if self.bundle_fail_enter: raise RuntimeError("admission refused")
            try: yield object()
            finally:
                self.events.append("close:bundle")
                if self.bundle_fail_close: raise RuntimeError("bundle cleanup uncertain")

        self.bundle = self.enterContext(mock.patch.object(subject, "hold_prepared_pi_bundle", side_effect=bundle))
        self.prepared_result = lifecycle_result()
        self.prepare = self.enterContext(mock.patch.object(subject.lifecycle, "prepare_native_pi_broker_control",
            return_value=self.prepared_result))

    def invoke(self, **changes):
        args = dict(deadline_ns=125_000_000_000, source_loader=self.source, host_custody=self.host)
        args.update(changes)
        return subject.run(Path("/var/lib/pi/plan.json"), canonical_digest(self.plan), **args)

    def refused(self):
        with self.assertRaises(subject.PiBrokerPreparationEntryError) as error:
            self.invoke()
        return error.exception

    def test_held_admitted_bundle_precedes_one_preparation_and_cleanup(self):
        result = self.invoke()
        self.prepare.assert_called_once()
        self.bundle.assert_called_once()
        options = self.prepare.call_args.kwargs
        self.assertIs(options["deployment"], self.held["runtime"])
        self.assertIs(options["configuration"], self.held["config"])
        self.assertIs(options["provider_inputs"], self.held["public"])
        self.assertEqual(options["binding"].policy_digest, self.grant["policy_digest"])
        self.assertLess(options["deadline"], 125.0)
        self.assertEqual(options["cleanup_timeout_seconds"], 5.0)
        bundle = self.bundle.call_args.kwargs
        self.assertEqual(bundle["grant"], self.grant)
        self.assertEqual(bundle["protected_root"], Path("/var/lib/aragorn/admitted"))
        self.assertEqual(bundle["now_unix"], 1000)
        self.assertEqual(bundle["revoked_context_ids"], ())
        self.cas.assert_called_once_with(Path("/var/lib/pi/cas"), read_only=True)
        self.assertEqual([e for e in self.events if e.startswith("close:")],
                         ["close:bundle", "close:public", "close:config", "close:runtime"])
        self.assertEqual(result["status"], "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED")
        self.assertTrue(result["owned_inputs_closed"] and result["owned_holders_closed"])
        self.assertFalse(result["managed_call_attempted"] or result["phase3_exit_eligible"])
        self.assertIsNot(result["preparation_result"], self.prepared_result)
        self.call.assert_not_called()
        self.credential_hold.assert_not_called()
        self.approval_hold.assert_not_called()

    def test_protected_provider_plan_refuses_before_holders(self):
        self.plan, self.documents = fixtures.prepared(True)
        self.refused()
        self.runtime_hold.assert_not_called()
        self.prepare.assert_not_called()
        self.credential_hold.assert_not_called()

    def test_missing_source_pin_refuses_before_input_acquisition(self):
        self.source.source_digests.pop(subject._SOURCE)
        self.refused()
        self.input_holder.read.assert_not_called()

    def test_missing_duplicate_or_foreign_consumed_source_refuses(self):
        original = copy.deepcopy(self.custody.return_value)
        for mode in ("missing", "duplicate", "foreign"):
            values = copy.deepcopy(original)
            if mode == "missing": values[1].pop()
            elif mode == "duplicate": values[1].append(copy.deepcopy(values[1][-1]))
            else: values[1][-1]["digest"] = fixtures.pin("f")
            self.custody.return_value = values
            with self.subTest(mode=mode): self.refused()
        self.prepare.assert_not_called()

    def test_changed_reference_pin_refuses_before_prepare(self):
        self.plan["service_runtime"]["manifest"]["digest"] = fixtures.pin("f")
        self.refused()
        self.prepare.assert_not_called()

    def test_grant_mismatch_cannot_initialize_authority(self):
        self.configs["sensor"]["capability_grant"]["policy_digest"] = fixtures.pin("f")
        self.refused()
        self.bundle.assert_not_called()
        self.prepare.assert_not_called()

    def test_admission_refusal_prevents_action_preparation(self):
        self.bundle_fail_enter = True
        error = self.refused()
        self.prepare.assert_not_called()
        self.assertFalse(error.observation["preparation_attempted"])
        self.assertTrue(error.observation["owned_inputs_closed"])

    def test_holder_failure_prevents_preparation(self):
        self.fail_enter = "config"
        self.refused()
        self.prepare.assert_not_called()
        self.assertIn("close:runtime", self.events)

    def test_preparation_failure_retains_actual_evidence_and_original_cause(self):
        failure = KeyboardInterrupt("cancelled preparation")
        retained = lifecycle_result()
        retained["status"] = "CLEANUP_HOLD"
        failure.pi_service_lifecycle_observation = retained
        self.prepare.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["preparation_result"], retained)
        self.assertEqual(error.observation["preparation_failure_evidence"], "RETAINED")
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.prepare.assert_called_once()

    def test_outer_holder_failure_does_not_replace_original_preparation_evidence(self):
        failure = RuntimeError("original preparation failure")
        failure.pi_service_lifecycle_observation = lifecycle_result()
        self.prepare.side_effect = failure
        self.fail_close = "public"
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["preparation_result"], failure.pi_service_lifecycle_observation)
        self.assertEqual(error.observation["failure_stage"], "HOLDER_CLEANUP")
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")

    def test_unknown_failure_evidence_stays_unknown(self):
        failure = RuntimeError("no owner record")
        failure.pi_service_lifecycle_observation = {"schema": "foreign", "status": "CLOSED"}
        self.prepare.side_effect = failure
        error = self.refused()
        self.assertIsNone(error.observation["preparation_result"])
        self.assertEqual(error.observation["preparation_failure_evidence"], "UNAVAILABLE_OR_INVALID")

    def test_oversized_owner_evidence_is_not_trimmed_into_success(self):
        self.prepared_result["raw"] = "x" * (4 * 1024 * 1024)
        error = self.refused()
        self.assertIsNone(error.observation["preparation_result"])
        self.assertNotEqual(error.observation["status"], "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_available_without_cleanup_or_ack_cannot_complete(self):
        original = lifecycle_result()
        variants = [copy.deepcopy(original) for _ in range(3)]
        variants[0]["cleanup"]["status"] = "PENDING"
        variants[1]["broker_preparation"]["ack_sent"] = False
        variants[2]["broker_preparation"]["readback"] = None
        for value in variants:
            self.prepare.return_value = value
            with self.subTest(value=value): self.refused()

    def test_bundle_cleanup_failure_keeps_result_but_withholds_success(self):
        self.bundle_fail_close = True
        error = self.refused()
        self.assertEqual(error.observation["preparation_result"], self.prepared_result)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertFalse(error.observation["owned_holders_closed"])

    def test_input_cleanup_failure_keeps_result_and_exact_uncertainty(self):
        self.input_holder.close.side_effect = OSError("uncertain close")
        self.input_holder.cleanup_uncertainty = [{"scope": "DESCRIPTOR_CLOSE", "descriptors": [19]}]
        error = self.refused()
        self.assertEqual(error.observation["preparation_result"], self.prepared_result)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertFalse(error.observation["owned_inputs_closed"])
        self.input_holder.close.assert_called_once()

    def test_postcall_host_change_preserves_completed_child_but_refuses(self):
        values = self.custody.return_value
        self.custody.side_effect = [values, values, values, (fixtures.pin("f"), values[1], values[2])]
        error = self.refused()
        self.assertEqual(error.observation["preparation_result"], self.prepared_result)
        self.assertEqual(error.observation["failure_stage"], "POST_CALL_CUSTODY")

    def test_postcall_error_plus_holder_failure_keeps_original_and_cleanup_hold(self):
        failure = RuntimeError("original postcall custody")
        values = self.custody.return_value
        self.custody.side_effect = [values, values, values, failure]
        self.fail_close = "config"
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["failure_stage"], "HOLDER_CLEANUP")
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["preparation_result"], self.prepared_result)

    def test_partial_holder_acquisition_and_cleanup_failure_stay_hold(self):
        self.fail_enter, self.fail_close = "config", "runtime"
        error = self.refused()
        self.assertEqual(str(error.__cause__), "held prerequisite refused")
        self.assertEqual(error.observation["failure_stage"], "HOLDER_CLEANUP")
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.prepare.assert_not_called()

    def test_deadline_and_root_identity_refuse_before_preparation(self):
        with mock.patch.object(subject.os, "geteuid", return_value=1001): self.refused()
        with self.assertRaises(subject.PiBrokerPreparationEntryError): self.invoke(deadline_ns=100_000_000_000)
        self.prepare.assert_not_called()


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(PreparationEntryTests(name) for name in PreparationEntryTests.__dict__
                             if name.startswith("test_"))
