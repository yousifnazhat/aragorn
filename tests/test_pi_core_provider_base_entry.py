"""Offline coordinator selection, custody and receipt joins. No provider operations."""

import copy
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as installer
from aragorn import pi_core_broker_preparation_entry as entry
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_broker_base_entry as action
from tests import test_pi_core_broker_preparation_entry as prep


class ProviderBaseEntryTests(action.BaseEntryTests):
    def setUp(self):
        super().setUp()
        self.plan["provider_base_state"] = self.plan.pop("broker_base_state")
        path, document = "/var/lib/pi/prepared/provider-base-config.json", {"fixture": "root config"}
        self.plan["provider_root_broker_config"] = {"path": path, "digest": canonical_digest(document)}
        self.documents[path] = document
        self.installed.update(schema="aragorn/pi-core-provider-base-installation/v1",
            destination="/var/lib/aragorn-runtime-provider", provider_config_digest=canonical_digest(document))
        self.provider_install = self.enterContext(mock.patch.object(installer, "provision_pi_provider_base",
            side_effect=self.install_base))

    def invoke(self, **changes):
        return prep.PreparationEntryTests.invoke(self, **({"install_provider_base": True} | changes))

    def test_fixed_root_route_joins_held_inputs_and_only_calls_provider_installer(self):
        result = self.invoke()
        args = self.provider_install.call_args.kwargs
        self.provider_install.assert_called_once()
        self.assertIs(args["provider_config"], self.root_config)
        self.assertIs(args["configuration"], self.held["config"])
        self.assertEqual((args["base_state"], args["base_state_digest"]),
                         (action.state(), self.plan["provider_base_state"]["digest"]))
        entry.coordinator._broker_config.assert_called_once_with(self.documents[self.plan["provider_root_broker_config"]["path"]])
        self.install.assert_not_called()
        self.prepare.assert_not_called()
        self.approval_hold.assert_not_called()
        self.credential_hold.assert_not_called()
        self.call.assert_not_called()
        self.bundle.assert_called_once()
        self.assertEqual((result["schema"], result["authority"], result["status"]),
            (entry.PROVIDER_BASE_SCHEMA, entry.PROVIDER_BASE_AUTHORITY, "PROVIDER_BASE_INSTALLED_NOT_READY_OR_QUALIFIED"))
        self.assertEqual(result["base_installation_result"], self.installed)
        self.assertFalse(result["phase3_exit_eligible"] or result["preparation_attempted"] or result["managed_call_attempted"])
        self.assertTrue(result["owned_holders_closed"] and result["owned_inputs_closed"])

    def test_conflicting_or_non_boolean_mode_refuses_before_input_custody(self):
        for selectors in ({"install_base": True}, {"install_provider_base": 1},
                          {"install_provider_base": "provider"}, {"install_base": 0}):
            with self.subTest(selectors=selectors), self.assertRaises(entry.PiBrokerPreparationEntryError):
                self.invoke(**selectors)
        self.custody.assert_not_called()
        self.install.assert_not_called()
        self.provider_install.assert_not_called()

    def test_both_references_required_without_fetching_or_inventing_defaults(self):
        for name in ("provider_root_broker_config", "provider_base_state"):
            with self.subTest(name=name), mock.patch.dict(self.plan):
                del self.plan[name]
                self.refused()
        self.input_holder.ref.assert_not_called()
        self.provider_install.assert_not_called()

    def test_action_base_and_provider_authority_are_not_valid_additions(self):
        for changes in ({"broker_base_state": self.plan["provider_base_state"]},
                        {"provider": {"credential_source": "/not-read"}}, {"mode": "PROTECTED"},
                        {"health": {"status": "healthy"}}):
            with self.subTest(changes=changes), mock.patch.dict(self.plan, changes):
                self.refused()
        self.input_holder.ref.assert_not_called()
        self.provider_install.assert_not_called()

    def test_other_selectors_do_not_accept_provider_base_plan(self):
        for action_mode in (False, True):
            with self.subTest(action=action_mode), self.assertRaises(entry.PiBrokerPreparationEntryError):
                self.invoke(install_base=action_mode, install_provider_base=False)
        self.provider_install.assert_not_called()
        self.prepare.assert_not_called()
        self.install.assert_not_called()

    def test_changed_config_or_state_bytes_refuse_before_holders(self):
        for name in ("provider_root_broker_config", "provider_base_state"):
            path = self.plan[name]["path"]
            with self.subTest(name=name), mock.patch.dict(self.documents, {path: {"changed": True}}):
                self.refused()
        self.runtime_hold.assert_not_called()
        self.provider_install.assert_not_called()

    def test_root_config_parser_refusal_cannot_reach_installation(self):
        failure = ValueError("config does not describe root")
        entry.coordinator._broker_config.side_effect = failure
        self.assertIs(self.refused().__cause__, failure)
        self.provider_install.assert_not_called()

    def test_admission_or_consumed_installer_mismatch_does_not_mutate(self):
        self.bundle_fail_enter = True
        self.refused()
        self.bundle_fail_enter = False
        self.custody.return_value[1][-1]["digest"] = "sha256:" + "1" * 64
        self.refused()
        self.provider_install.assert_not_called()

    def test_foreign_schema_plan_pins_and_crossed_destinations_cannot_complete(self):
        for changes in ({"schema": "aragorn/pi-core-broker-base-installation/v1"},
                        {"provider_config_digest": "sha256:" + "7" * 64}, {"provider_config_digest": None},
                        {"base_state_digest": "sha256:" + "8" * 64},
                        {"destination": "/var/lib/aragorn-runtime-action"},
                        {"phase3_exit_eligible": True}, {"service_ready": True}):
            with self.subTest(changes=changes), mock.patch.dict(self.installed, changes):
                self.assertEqual(self.refused().observation["failure_stage"], "BASE_INSTALLATION")

    def test_provider_exception_retains_own_partial_record_and_original_failure(self):
        failure = KeyboardInterrupt("stop once")
        failure.pi_provider_base_observation = {**self.installed, "status": "CLEANUP_HOLD",
            "owned_handles_closed": False, "cleanup_uncertainty": ["uncertain"]}
        self.provider_install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["base_installation_failure_evidence"], "RETAINED")
        self.assertEqual(error.observation["base_installation_result"], failure.pi_provider_base_observation)
        self.provider_install.assert_called_once()

    def test_action_exception_attribute_cannot_replace_missing_provider_evidence(self):
        failure = OSError("incomplete provider evidence")
        failure.pi_broker_base_observation = copy.deepcopy(self.installed)
        self.provider_install.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertIsNone(error.observation["base_installation_result"])
        self.assertEqual(error.observation["base_installation_failure_evidence"], "UNAVAILABLE_OR_INVALID")

    def test_late_holder_failure_withholds_success_after_provider_install(self):
        self.bundle_fail_close = True
        error = self.refused()
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["base_installation_result"], self.installed)
        self.assertFalse(error.observation["owned_holders_closed"])
        self.provider_install.assert_called_once()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(ProviderBaseEntryTests(n) for n in ProviderBaseEntryTests.__dict__ if n.startswith("test_"))
    for name in ("test_fixed_installation_uses_admission_holders_and_original_pinned_state_once",
                 "test_installer_result_substitution_or_missing_readback_cannot_complete",
                 "test_partial_installation_retains_original_owner_evidence_without_retry"):
        suite.addTest(action.BaseEntryTests(name))
    suite.addTest(prep.PreparationEntryTests("test_held_admitted_bundle_precedes_one_preparation_and_cleanup"))
    return suite
