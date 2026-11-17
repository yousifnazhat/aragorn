"""Only the new fixed base-installation branch and named affected default cases.

Installed inputs, admission, custody and the installer are inert seams. These
checks do not install controls, initialize a grant or start any process/service.
"""

import copy
from pathlib import Path
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as installer
from aragorn import pi_core_broker_preparation_entry as subject
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_broker_preparation_entry as preparation
from tests import test_pi_core_coordinator_entry as fixtures


def state():
    return {"schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 3, "minimum_mediator_health_epoch": 7,
        "consumed": [], "effect_journal": None}


class BaseEntryTests(preparation.PreparationEntryTests):
    def setUp(self):
        super().setUp()
        path = "/var/lib/pi/prepared/broker-base-state.json"
        self.documents[path] = state()
        self.plan["broker_base_state"] = {"path": path, "digest": canonical_digest(state())}
        self.source.source_digests[subject._BASE_SOURCE] = fixtures.pin("9")
        self.custody.return_value[1].append({"module": installer.__name__,
            "path": subject._BASE_SOURCE, "digest": fixtures.pin("9")})
        self.installed = {
            "schema": "aragorn/pi-core-broker-base-installation/v1",
            "authority": "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3",
            "status": "INSTALLED", "configuration_digest": canonical_digest(self.configs),
            "base_state_digest": canonical_digest(state()), "destination": "/var/lib/aragorn-runtime-action",
            "mutation_attempted": True, "owned_handles_closed": True, "cleanup_uncertainty": [],
            "readback": {"state": state(), "directories": {"control": {"inode": 41}}},
            "activation_performed": False, "service_ready": False,
            "current_grant_authority": False, "phase3_exit_eligible": False}
        self.install = self.enterContext(mock.patch.object(installer, "provision_pi_broker_base",
                                                         side_effect=self.install_base))

    def install_base(self, **options):
        self.events.append("install:base")
        self.assertIn("enter:bundle", self.events)
        entered = max(index for index, event in enumerate(self.events) if event == "enter:bundle")
        self.assertFalse(any(event.startswith("close:") for event in self.events[entered:]))
        return self.installed

    def invoke(self, **changes):
        return super().invoke(**({"install_base": True} | changes))

    def test_fixed_installation_uses_admission_holders_and_original_pinned_state_once(self):
        result = self.invoke()
        self.install.assert_called_once()
        options = self.install.call_args.kwargs
        self.assertEqual(set(options), {"configuration", "base_state", "base_state_digest", "deadline"})
        self.assertIs(options["configuration"], self.held["config"])
        self.assertEqual(options["base_state"], state())
        self.assertEqual(options["base_state_digest"], self.plan["broker_base_state"]["digest"])
        self.assertLess(options["deadline"], 125.0)
        self.assertGreater(options["deadline"], 124.99)
        self.bundle.assert_called_once()
        self.cas.assert_called_once_with(Path("/var/lib/pi/cas"), read_only=True)
        self.assertEqual([event for event in self.events if event.startswith("close:")],
                         ["close:bundle", "close:public", "close:config", "close:runtime"])
        self.assertEqual((result["schema"], result["authority"], result["status"]),
            (subject.BASE_SCHEMA, subject.BASE_AUTHORITY, "BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED"))
        self.assertTrue(result["base_installation_attempted"])
        self.assertTrue(result["owned_holders_closed"] and result["owned_inputs_closed"])

    def test_base_installation_cannot_start_services_grant_preparation_or_provider(self):
        result = self.invoke()
        self.prepare.assert_not_called()
        self.call.assert_not_called()
        self.credential_hold.assert_not_called()
        self.approval_hold.assert_not_called()
        self.assertFalse(result["preparation_attempted"] or result["managed_call_attempted"])
        self.assertIsNone(result["preparation_result"])
        self.assertFalse(result["phase3_exit_eligible"])

    def test_non_boolean_local_selector_refuses_before_custody_or_inputs(self):
        for selector in (1, 0, None, "INSTALL", [], {}):
            with self.subTest(selector=selector), self.assertRaises(subject.PiBrokerPreparationEntryError):
                self.invoke(install_base=selector)
        self.custody.assert_not_called()
        self.input_holder.read.assert_not_called()
        self.install.assert_not_called()

    def test_default_preparation_rejects_installation_reference(self):
        with self.assertRaises(subject.PiBrokerPreparationEntryError) as raised:
            self.invoke(install_base=False)
        self.assertEqual(raised.exception.observation["schema"], subject.SCHEMA)
        self.input_holder.ref.assert_not_called()
        self.prepare.assert_not_called()
        self.install.assert_not_called()

    def test_true_mode_requires_exact_base_reference_without_generated_default(self):
        del self.plan["broker_base_state"]
        error = self.refused()
        self.assertFalse(error.observation["base_installation_attempted"])
        self.input_holder.ref.assert_not_called()
        self.install.assert_not_called()

    def test_base_reference_rejects_extra_fields_and_invalid_paths_or_pins(self):
        original = copy.deepcopy(self.plan["broker_base_state"])
        for change in ({"command": "not allowed"}, {"path": "relative.json"}, {"digest": "unbound"}):
            self.plan["broker_base_state"] = {**original, **change}
            with self.subTest(change=change): self.refused()
        self.input_holder.ref.assert_not_called()
        self.install.assert_not_called()

    def test_other_plan_extras_are_not_stripped_with_the_known_reference(self):
        self.plan["destination"] = "/tmp/foreign"
        self.refused()
        self.input_holder.ref.assert_not_called()
        self.install.assert_not_called()

    def test_provider_authority_is_rejected_before_state_and_holders(self):
        self.plan["provider"] = {"credential_source": "/var/lib/pi/key"}
        self.refused()
        self.input_holder.ref.assert_not_called()
        self.runtime_hold.assert_not_called()
        self.install.assert_not_called()

    def test_changed_referenced_base_bytes_refuse_before_holders(self):
        self.documents[self.plan["broker_base_state"]["path"]]["minimum_mediator_health_epoch"] = 8
        self.refused()
        self.runtime_hold.assert_not_called()
        self.install.assert_not_called()

    def test_missing_installer_pin_is_not_self_adopted(self):
        del self.source.source_digests[subject._BASE_SOURCE]
        error = self.refused()
        self.assertFalse(error.observation["base_installation_attempted"])
        self.install.assert_not_called()
        self.prepare.assert_not_called()

    def test_missing_duplicate_and_foreign_consumed_installer_refuse_call(self):
        original = copy.deepcopy(self.custody.return_value)
        for mode in ("missing", "duplicate", "foreign", "module"):
            value = copy.deepcopy(original)
            if mode == "missing": value[1].pop()
            elif mode == "duplicate": value[1].append(copy.deepcopy(value[1][-1]))
            elif mode == "foreign": value[1][-1]["digest"] = fixtures.pin("8")
            else: value[1][-1]["module"] = "aragorn.foreign"
            self.custody.return_value = value
            with self.subTest(mode=mode): self.refused()
        self.install.assert_not_called()

    def test_admission_refusal_and_grant_mismatch_cannot_install(self):
        self.bundle_fail_enter = True
        self.refused()
        self.bundle_fail_enter = False
        self.configs["sensor"]["capability_grant"]["policy_digest"] = fixtures.pin("8")
        self.refused()
        self.install.assert_not_called()

    def test_runtime_holder_refusal_cannot_install(self):
        self.fail_enter = "runtime"
        self.refused()
        self.bundle.assert_not_called()
        self.install.assert_not_called()

    def test_actual_installer_record_is_detached_and_bound_to_plan_and_configuration(self):
        result = self.invoke()
        self.assertEqual(result["base_installation_result"], self.installed)
        self.installed["readback"]["state"]["minimum_mediator_health_epoch"] = 55
        self.assertEqual(result["base_installation_result"]["readback"]["state"], state())
        self.assertEqual(result["plan_digest"], canonical_digest(self.plan))
        self.assertEqual(result["context_digest"], self.plan["context"]["digest"])

    def test_installer_result_substitution_or_missing_readback_cannot_complete(self):
        original = copy.deepcopy(self.installed)
        variants = ({"configuration_digest": fixtures.pin("8")}, {"base_state_digest": fixtures.pin("8")},
                    {"destination": "/tmp/foreign"}, {"readback": None}, {"mutation_attempted": False},
                    {"cleanup_uncertainty": [{"scope": "unknown"}]}, {"owned_handles_closed": False})
        for change in variants:
            self.installed = {**original, **change}
            with self.subTest(change=change):
                error = self.refused()
                self.assertEqual(error.observation["failure_stage"], "BASE_INSTALLATION")
                self.assertNotEqual(error.observation["status"], "BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED")

    def test_forged_qualification_or_foreign_schema_record_is_not_retained(self):
        original = copy.deepcopy(self.installed)
        for change in ({"phase3_exit_eligible": True}, {"current_grant_authority": True},
                       {"service_ready": True}, {"activation_performed": True}, {"schema": "foreign"}):
            self.installed = {**original, **change}
            with self.subTest(change=change):
                error = self.refused()
                self.assertIsNone(error.observation["base_installation_result"])

    def test_partial_installation_retains_original_owner_evidence_without_retry(self):
        failure = OSError("partial private installation")
        failure.pi_broker_base_observation = {**self.installed, "status": "PARTIAL_OR_INDETERMINATE", "readback": None}
        self.install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["base_installation_result"], failure.pi_broker_base_observation)
        self.assertEqual(error.observation["base_installation_failure_evidence"], "RETAINED")
        self.assertTrue(error.observation["base_installation_attempted"])
        self.assertEqual(sum(row.get("module") == installer.__name__ for row in error.observation["source_before"]), 1)
        self.install.assert_called_once()

    def test_installer_cleanup_hold_survives_successful_outer_cleanup(self):
        failure = RuntimeError("private handles uncertain")
        failure.pi_broker_base_observation = {**self.installed, "status": "CLEANUP_HOLD", "owned_handles_closed": False}
        self.install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertTrue(error.observation["owned_inputs_closed"])

    def test_cancellation_retains_owner_record_and_is_not_retried(self):
        failure = KeyboardInterrupt("cancelled installation")
        failure.pi_broker_base_observation = {**self.installed, "status": "PARTIAL_OR_INDETERMINATE"}
        self.install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["base_installation_failure_evidence"], "RETAINED")
        self.install.assert_called_once()

    def test_unknown_or_unreadable_exception_evidence_preserves_original_error(self):
        class Failure(RuntimeError):
            @property
            def pi_broker_base_observation(self):
                raise RuntimeError("private metadata unavailable")
        failure = Failure("original owner failure")
        self.install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertIsNone(error.observation["base_installation_result"])
        self.assertEqual(error.observation["base_installation_failure_evidence"], "UNAVAILABLE_OR_INVALID")

    def test_oversized_owner_evidence_is_not_trimmed_or_promoted(self):
        self.installed["raw"] = "x" * (4 * 1024 * 1024)
        error = self.refused()
        self.assertIsNone(error.observation["base_installation_result"])
        self.assertNotEqual(error.observation["status"], "BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED")

    def test_outer_holder_failure_retains_original_installation_failure_and_record(self):
        failure = RuntimeError("original installer failure")
        failure.pi_broker_base_observation = {**self.installed, "status": "PARTIAL_OR_INDETERMINATE"}
        self.install.side_effect = failure
        self.fail_close = "config"
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["base_installation_result"], failure.pi_broker_base_observation)
        self.assertEqual((error.observation["status"], error.observation["failure_stage"]),
                         ("CLEANUP_HOLD", "HOLDER_CLEANUP"))

    def test_successful_installer_cannot_hide_bundle_cleanup_failure(self):
        self.bundle_fail_close = True
        error = self.refused()
        self.assertEqual(error.observation["base_installation_result"], self.installed)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertFalse(error.observation["owned_holders_closed"])

    def test_input_cleanup_uncertainty_retains_installed_controls_without_retry(self):
        self.input_holder.close.side_effect = OSError("owned input close failed")
        self.input_holder.cleanup_uncertainty = [{"scope": "DESCRIPTOR_CLOSE", "descriptors": [19]}]
        error = self.refused()
        self.assertEqual(error.observation["base_installation_result"], self.installed)
        self.assertEqual(error.observation["input_cleanup_uncertainty"], self.input_holder.cleanup_uncertainty)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.install.assert_called_once()
        self.input_holder.close.assert_called_once()

    def test_postcall_installer_source_change_retains_result_but_refuses(self):
        original = self.install.side_effect
        def install(**options):
            result = original(**options)
            self.custody.return_value[1][-1]["digest"] = fixtures.pin("8")
            return result
        self.install.side_effect = install
        error = self.refused()
        self.assertEqual(error.observation["base_installation_result"], self.installed)
        self.assertEqual(error.observation["failure_stage"], "POST_CALL_CUSTODY")

    def test_root_identity_and_original_expired_deadline_refuse_before_custody(self):
        with mock.patch.object(subject.os, "getegid", return_value=1001): self.refused()
        with self.assertRaises(subject.PiBrokerPreparationEntryError):
            self.invoke(deadline_ns=100_000_000_000)
        self.custody.assert_not_called()
        self.install.assert_not_called()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(BaseEntryTests(name) for name in BaseEntryTests.__dict__ if name.startswith("test_"))
    for name in (
        "test_held_admitted_bundle_precedes_one_preparation_and_cleanup",
        "test_preparation_failure_retains_actual_evidence_and_original_cause",
        "test_outer_holder_failure_does_not_replace_original_preparation_evidence",
        "test_input_cleanup_failure_keeps_result_and_exact_uncertainty",
        "test_postcall_host_change_preserves_completed_child_but_refuses",
    ):
        suite.addTest(preparation.PreparationEntryTests(name))
    return suite


if __name__ == "__main__":
    unittest.main()
