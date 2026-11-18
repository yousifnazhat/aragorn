"""Only initial-policy dispatch and its directly affected legacy siblings."""

import copy
import hashlib
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as installer
from aragorn import pi_core_broker_preparation_entry as entry
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_base_entry as base


class InitialPolicyEntryTests(base.ProviderBaseEntryTests):
    def setUp(self):
        super().setUp()
        for key in ("provider_initial_policy", "provider_initial_revocations"):
            path = "/var/lib/pi/prepared/" + key + ".json"
            self.documents[path] = {"fixture": key, "issued_at_unix": 1000}
            self.plan[key] = {"path": path, "digest": canonical_digest(self.documents[path])}
        digests = {"broker.lock": "sha256:" + hashlib.sha256(b"").hexdigest(),
            "policy.json": self.plan["provider_initial_policy"]["digest"],
            "revocations.json": self.plan["provider_initial_revocations"]["digest"],
            "state.json": self.plan["provider_base_state"]["digest"]}
        sizes = {name: len(canonical_json(self.documents[self.plan[key]["path"]])) for name, key in (
            ("policy.json", "provider_initial_policy"), ("revocations.json", "provider_initial_revocations"),
            ("state.json", "provider_base_state"))}
        rows = {key: {"identity": [1, i + 1, 0o100600 if key == "broker.lock" else 0o100400,
                                   1, 0, 0, sizes.get(key, 0), 0, 0], "digest": pin}
                for i, (key, pin) in enumerate(digests.items())}
        dirs = {key: [1, i + 20, 0o40700, 1, 0, 0, 128, 0, 0] for i, key in enumerate(
            ("aragorn-runtime-provider", "control", "protected", "staging", "provider-evidence", "blobs", "sha256"))}
        self.installed.update(schema="aragorn/pi-core-provider-initial-policy/v1",
            authority="PINNED_INITIAL_POLICY_AND_REVOCATIONS_ONLY_NOT_HEALTH_OR_EXECUTION",
            uncertain_creation=None,
            policy_digest=digests["policy.json"], revocations_digest=digests["revocations.json"],
            readback={"base_state": base.action.state(), "files": rows, "directories": dirs},
            created_members={"control/" + name: rows[name]["identity"] for name in ("policy.json", "revocations.json")})
        self.initial = self.enterContext(mock.patch.object(installer, "initialize_pi_provider_policy",
            side_effect=self.install_base))

    def invoke(self, **changes):
        return base.prep.PreparationEntryTests.invoke(self, **({"initialize_provider_policy": True} | changes))

    def test_passes_unchanged_held_documents_and_independent_pins_without_other_authority(self):
        result = self.invoke()
        self.initial.assert_called_once()
        options = self.initial.call_args.kwargs
        for name, key in (("policy", "provider_initial_policy"), ("revocations", "provider_initial_revocations"),
                          ("base_state", "provider_base_state")):
            self.assertEqual(options[name], self.documents[self.plan[key]["path"]])
            self.assertEqual(options[name + "_digest"], self.plan[key]["digest"])
        self.assertIs(options["configuration"], self.held["config"])
        self.assertIs(options["provider_config"], self.root_config)
        self.bundle.assert_called_once()
        for other in (self.install, self.provider_install, self.approval_hold, self.credential_hold, self.prepare, self.call):
            other.assert_not_called()
        self.assertEqual((result["schema"], result["authority"], result["status"]),
            (entry.POLICY_SCHEMA, entry.POLICY_AUTHORITY, "INITIAL_PROVIDER_POLICY_RECORDED_NOT_READY_OR_QUALIFIED"))
        self.assertTrue(result["base_installation_attempted"] and result["owned_holders_closed"] and result["owned_inputs_closed"])
        self.assertFalse(result["managed_call_attempted"] or result["phase3_exit_eligible"] or result["preparation_attempted"])

    def test_requires_exclusive_local_boolean_before_inputs(self):
        for change in ({"install_base": True}, {"install_provider_base": True},
                       {"initialize_provider_policy": 1}, {"initialize_provider_policy": "initialize"}):
            with self.subTest(change=change), self.assertRaises(entry.PiBrokerPreparationEntryError):
                self.invoke(**change)
        self.input_holder.read.assert_not_called()
        self.initial.assert_not_called()

    def test_partial_refs_or_unapproved_extras_fail_before_dereference(self):
        for key in ("provider_base_state", "provider_root_broker_config", "provider_initial_policy", "provider_initial_revocations"):
            with self.subTest(key=key), mock.patch.dict(self.plan):
                del self.plan[key]
                self.refused()
        for change in ({"provider_initial_health": {"healthy": True}}, {"provider": {"approval_intent": {}}}):
            with mock.patch.dict(self.plan, change):
                self.refused()
        self.input_holder.ref.assert_not_called()
        self.initial.assert_not_called()

    def test_existing_provider_base_route_refuses_initial_documents(self):
        with self.assertRaises(entry.PiBrokerPreparationEntryError):
            self.invoke(initialize_provider_policy=False, install_provider_base=True)
        self.initial.assert_not_called()
        self.provider_install.assert_not_called()

    def test_policy_or_revocations_pin_changed_before_acquisition_refuses(self):
        for key in ("provider_initial_policy", "provider_initial_revocations"):
            with mock.patch.dict(self.documents, {self.plan[key]["path"]: {"different": key}}):
                self.refused()
        self.bundle.assert_not_called()
        self.initial.assert_not_called()

    def test_installer_must_be_admitted_and_its_source_consumed(self):
        self.bundle_fail_enter = True
        self.refused()
        self.bundle_fail_enter = False
        self.custody.return_value[1][-1]["digest"] = "sha256:" + "9" * 63 + "1"
        self.refused()
        self.initial.assert_not_called()

    def test_foreign_schema_authority_and_changed_top_level_pins_refuse_success(self):
        for change in ({"schema": "aragorn/pi-core-provider-base-installation/v1"},
                       {"authority": "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3"},
                       {"policy_digest": None}, {"revocations_digest": self.installed["policy_digest"]},
                       {"provider_config_digest": None}, {"base_state_digest": None}, {"configuration_digest": None},
                       {"destination": "/var/lib/aragorn-runtime-action"}, {"service_ready": True},
                       {"uncertain_creation": "policy.json"}):
            with self.subTest(change=change), mock.patch.dict(self.installed, change):
                self.assertEqual(self.refused().observation["failure_stage"], "BASE_INSTALLATION")
        with mock.patch.dict(self.installed):
            del self.installed["uncertain_creation"]
            self.assertEqual(self.refused().observation["failure_stage"], "BASE_INSTALLATION")

    def test_incomplete_or_substituted_named_readback_blocks_completion(self):
        for key in ("missing_dir", "extra_file", "missing_identity", "swapped_bytes", "other_state", "other_created"):
            with self.subTest(key=key), mock.patch.dict(self.installed, copy.deepcopy(self.installed)):
                read = self.installed["readback"]
                if key == "missing_dir": del read["directories"]["sha256"]
                elif key == "extra_file": read["files"]["health.json"] = {}
                elif key == "missing_identity": del read["files"]["policy.json"]["identity"]
                elif key == "swapped_bytes": read["files"]["revocations.json"]["digest"] = self.installed["policy_digest"]
                elif key == "other_state": read["base_state"]["consumed"].append("foreign")
                else: self.installed["created_members"]["control/health.json"] = []
                self.assertEqual(self.refused().observation["failure_stage"], "BASE_INSTALLATION")

    def test_owner_mode_links_length_aliases_and_created_boolean_are_not_clean_readback(self):
        for name, index, value in (("broker.lock", 2, 0o100400), ("broker.lock", 6, 1),
                ("policy.json", 2, 0o100600), ("policy.json", 3, 2), ("policy.json", 4, 1000),
                ("revocations.json", 5, 1), ("state.json", 6, 0), ("state.json", 1, 20),
                ("control", 2, 0o100700), ("sha256", 3, 0), ("staging", 0, 2),
                ("created", 3, True)):
            with self.subTest(name=name, index=index), mock.patch.dict(self.installed, copy.deepcopy(self.installed)):
                read = self.installed["readback"]
                if name == "created":
                    row = list(self.installed["created_members"]["control/policy.json"])
                    self.installed["created_members"]["control/policy.json"] = row
                else:
                    row = read["directories"][name] if name in read["directories"] else read["files"][name]["identity"]
                row[index] = value
                self.assertEqual(self.refused().observation["failure_stage"], "BASE_INSTALLATION")

    def test_partial_failure_retains_only_original_policy_record_and_never_retries(self):
        failure = KeyboardInterrupt("cancel policy publication")
        failure.pi_provider_initial_policy_observation = {**self.installed, "status": "PARTIAL_OR_INDETERMINATE",
            "readback": {"directories": {}, "files": {}}}
        self.initial.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["base_installation_result"], failure.pi_provider_initial_policy_observation)
        self.assertEqual(error.observation["base_installation_failure_evidence"], "RETAINED")
        self.initial.assert_called_once()

    def test_other_installer_exception_attribute_cannot_supply_policy_evidence(self):
        failure = OSError("policy failure")
        failure.pi_provider_base_observation = self.installed
        self.initial.side_effect = failure
        error = self.refused()
        self.assertIs(error.__cause__, failure)
        self.assertEqual(error.observation["base_installation_failure_evidence"], "UNAVAILABLE_OR_INVALID")
        self.assertIsNone(error.observation["base_installation_result"])

    def test_input_cleanup_failure_does_not_erase_successful_inner_policy_record(self):
        self.input_holder.close.side_effect = OSError("cleanup failed")
        error = self.refused()
        self.assertEqual(error.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(error.observation["base_installation_result"], self.installed)
        self.initial.assert_called_once()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(InitialPolicyEntryTests(name) for name in InitialPolicyEntryTests.__dict__ if name.startswith("test_"))
    suite.addTest(base.ProviderBaseEntryTests("test_fixed_root_route_joins_held_inputs_and_only_calls_provider_installer"))
    suite.addTest(base.ProviderBaseEntryTests("test_provider_exception_retains_own_partial_record_and_original_failure"))
    suite.addTest(base.action.BaseEntryTests("test_fixed_installation_uses_admission_holders_and_original_pinned_state_once"))
    suite.addTest(base.prep.PreparationEntryTests("test_held_admitted_bundle_precedes_one_preparation_and_cleanup"))
    return suite
