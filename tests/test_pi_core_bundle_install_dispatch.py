"""Fixed materialization route and public metadata; no installation or launch."""

import json
import sys
import types
import unittest
from unittest import mock

import test_pi_core_coordinator_wrapper as legacy
import test_pi_core_inventory_dispatch as preparation_fixture


class BundleInstallDispatchTests(legacy.CoordinatorWrapperTests):
    def install_observation(self):
        value = self.observation()
        tree = "sha256:" + "1" * 64
        for edge in ("source_before", "source_after"):
            value[edge] += [{"module": "aragorn." + name, "path": "opt/aragorn/src/aragorn/" + name + ".py",
                             "digest": "sha256:" + digit * 64}
                            for name, digit in (("pi_core_coordinator_entry", "7"), ("pi_core_bundle_install_entry", "8"))]
        value.update(schema="aragorn/pi-core-bundle-install-result/v1",
            authority="PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="INSTALLED_NOT_ACTIVATED_OR_QUALIFIED", managed_call_attempted=False,
            managed_result=None, context_digest="sha256:" + "f" * 64,
            installation_attempted=True, owned_destination_closed=True,
            publication_state="PUBLISHER_RETURNED", input_cleanup_uncertainty=[], observed_tree_digest=tree,
            transaction={"schema": "aragorn/protected-install-transaction/v1",
                         "tree_digest": tree,
                         "private": "never-public-transaction-content"}, recovery=None)
        return value

    def invoke_install(self, value, *, entry_error=False, cleanup_error=False, host_close=None,
                       after_guard=None, prefix="--install-bundle"):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=after_guard), close=mock.Mock(side_effect=host_close))
        loader = types.SimpleNamespace(close=mock.Mock(
            side_effect=OSError("private cleanup text") if cleanup_error else None))
        entry = types.ModuleType("aragorn.pi_core_bundle_install_entry")
        failure = RuntimeError("private install error")
        failure.observation = value
        entry.run = mock.Mock(side_effect=failure if entry_error else None, return_value=value)
        forbidden = types.ModuleType("aragorn.pi_core_coordinator_entry")
        forbidden.run = mock.Mock(side_effect=AssertionError("install route must not launch"))
        package = types.ModuleType("aragorn")
        package.__path__ = []
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.object(sys, "argv", [str(self.wrapper), prefix, str(self.profile_path),
                    self.s._digest(self.s._canonical(self.profile)), str(self.root / "plan.json"), "sha256:" + "a" * 64,
                    str(int(self.deadline * 1_000_000_000))]), \
                mock.patch.dict(sys.modules, {"aragorn": package, entry.__name__: entry,
                                             forbidden.__name__: forbidden}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            result = self.s.main()
        forbidden.run.assert_not_called()
        if prefix == "--install-bundle":
            entry.run.assert_called_once()
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        printed.assert_called_once()
        return result, json.loads(printed.call_args.args[0])

    def test_fixed_route_returns_only_metadata_and_existing_transaction_digest(self):
        value = self.install_observation()
        # The protected loader may consume an additional module without losing its earlier history.
        value["source_after"].append({"module": "aragorn.cas", "path": "opt/aragorn/src/aragorn/cas.py",
                                      "digest": "sha256:" + "3" * 64})
        code, report = self.invoke_install(value)
        self.assertEqual(code, 0)
        self.assertEqual(report["schema"], "aragorn/pi-core-bundle-install-report/v2")
        self.assertEqual(report["observed_tree_digest"], value["observed_tree_digest"])
        self.assertEqual(report["status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")
        self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
        self.assertNotIn("never-public", json.dumps(report))
        self.assertNotIn("transaction", report)
        self.assertFalse(report["managed_call_attempted"])
        self.assertFalse(report["phase3_exit_eligible"])

    def test_arbitrary_selector_is_not_an_install_route(self):
        for prefix in ("--install", "--install-bundle=force", "--module=aragorn.install"):
            code, report = self.invoke_install(None, prefix=prefix)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])

    def test_installation_does_not_accept_execution_authority_or_foreign_schema(self):
        for changes in ({"schema": "foreign"}, {"authority": "qualified"},
                        {"managed_call_attempted": True}, {"managed_result": {"private": "secret"}},
                        {"phase3_exit_eligible": True}):
            with self.subTest(changes=changes):
                code, report = self.invoke_install(self.install_observation() | changes)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")
                self.assertNotIn("secret", json.dumps(report))

    def test_success_requires_owned_input_and_destination_cleanup(self):
        for field in ("owned_inputs_closed", "owned_destination_closed"):
            code, report = self.invoke_install(self.install_observation() | {field: False})
            self.assertEqual(code, 126)
            self.assertIsNone(report["observed_tree_digest"])
            self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_success_requires_attempt_transaction_context_and_no_recovery(self):
        for changes in ({"installation_attempted": False}, {"transaction": None},
                        {"context_digest": None}, {"publication_state": "UNKNOWN"},
                        {"recovery": {"private": "held claim"}},
                        {"input_cleanup_uncertainty": [{"scope": "held"}]}):
            with self.subTest(changes=changes):
                code, report = self.invoke_install(self.install_observation() | changes)
                self.assertEqual(code, 126)
                self.assertIsNone(report["observed_tree_digest"])
                self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_publisher_failure_retains_recovery_digest_without_raw_record(self):
        value = self.install_observation() | {"status": "CLEANUP_HOLD",
            "failure_stage": "INSTALLATION", "publication_state": "RECOVERY_RECORD_RETAINED",
            "transaction": None, "observed_tree_digest": None, "recovery": {"private": "never-public-recovery-content"}}
        code, report = self.invoke_install(value, entry_error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["recovery_digest"], self.s._digest(self.s._canonical(value["recovery"])))
        self.assertTrue(report["installation_attempted"])
        self.assertEqual(report["entry_status"], "CLEANUP_HOLD")
        self.assertIsNone(report["observed_tree_digest"])
        self.assertNotIn("never-public", json.dumps(report))

    def test_post_install_host_custody_failure_does_not_erase_publication_digest(self):
        value = self.install_observation()
        code, report = self.invoke_install(value, after_guard=[None, RuntimeError("changed host")])
        self.assertEqual(code, 126)
        self.assertEqual(report["status"], "REFUSED_OR_CLEANUP_HOLD")
        self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
        self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")
        self.assertIsNone(report["observed_tree_digest"])

    def test_wrapper_close_failure_cannot_become_success(self):
        for owner, opts in (("source_loader", {"cleanup_error": True}),
                            ("host", {"host_close": OSError("private close error")})):
            with self.subTest(owner=owner):
                value = self.install_observation()
                code, report = self.invoke_install(value, **opts)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_cleanup"][owner], "CLEANUP_HOLD")
                self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
                self.assertTrue(report["installation_attempted"])
                self.assertIsNone(report["observed_tree_digest"])
                self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_successful_looking_exception_cannot_publish_the_tree(self):
        value = self.install_observation()
        code, report = self.invoke_install(value, entry_error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
        self.assertEqual(report["publication_state"], "PUBLISHER_RETURNED")
        self.assertIsNone(report["observed_tree_digest"])
        self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_old_or_invalid_measurement_preserves_publication_but_cannot_be_certified(self):
        # No fallback from observed bytes to the publisher's tree claim, even for an old result.
        missing = object()
        for pin in (missing, None, "sha256:" + "2" * 64, "sha256:bad", True):
            with self.subTest(pin=pin):
                value = self.install_observation()
                if pin is missing:
                    del value["observed_tree_digest"]
                else:
                    value["observed_tree_digest"] = pin
                code, report = self.invoke_install(value)
                self.assertEqual(code, 126)
                self.assertTrue(report["installation_attempted"])
                self.assertEqual(report["publication_state"], "PUBLISHER_RETURNED")
                self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
                self.assertIsNone(report["observed_tree_digest"])
                self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_matching_noncanonical_or_zero_pins_are_not_observed_trees(self):
        for pin in ("sha256:" + "A" * 64, "sha256:" + "0" * 64):
            with self.subTest(pin=pin):
                value = self.install_observation()
                value["observed_tree_digest"] = value["transaction"]["tree_digest"] = pin
                code, report = self.invoke_install(value)
                self.assertEqual(code, 126)
                self.assertIsNone(report["observed_tree_digest"])

    def test_changed_matching_observation_and_transaction_after_guard_cannot_be_emitted(self):
        value = self.install_observation()
        original = self.s._digest(self.s._canonical(value["transaction"]))
        def substitute():
            value["observed_tree_digest"] = value["transaction"]["tree_digest"] = "sha256:" + "9" * 64
        code, report = self.invoke_install(value, host_close=substitute)
        self.assertEqual(code, 126)
        self.assertEqual(set(report["wrapper_cleanup"].values()), {"CLOSED"})
        self.assertEqual(report["transaction_digest"], original)
        self.assertIsNone(report["observed_tree_digest"])
        self.assertNotEqual(report["entry_status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")

    def test_original_deadline_reached_during_final_close_withholds_measurement(self):
        value = self.install_observation()
        def at_deadline():
            self.enterContext(mock.patch.object(self.s.time, "monotonic_ns",
                                                return_value=int(self.deadline * 1_000_000_000)))
        code, report = self.invoke_install(value, host_close=at_deadline)
        self.assertEqual(code, 126)
        self.assertEqual(set(report["wrapper_cleanup"].values()), {"CLOSED"})
        self.assertEqual(report["transaction_digest"], self.s._digest(self.s._canonical(value["transaction"])))
        self.assertIsNone(report["observed_tree_digest"])

    def test_measured_digest_requires_custody_and_the_invoked_plan_and_host(self):
        for field in ("plan_digest", "host_before", "host_after", "source_before", "source_after", "both_host_pins",
                      "source_history_changed", "failure_stage", "deployment_digest"):
            with self.subTest(field=field):
                value = self.install_observation()
                if field == "plan_digest":
                    value[field] = "sha256:" + "9" * 64
                elif field == "failure_stage":
                    value[field] = "POST_CALL_CUSTODY"
                elif field == "deployment_digest":
                    value[field] = "sha256:" + "0" * 64
                elif field == "source_history_changed":
                    value["source_after"] = list(reversed(value["source_before"]))
                elif field == "both_host_pins":
                    for k in ("host_before", "host_after"):
                        value[k] = value[k] | {"host_profile_digest": "sha256:" + "9" * 64}
                else:
                    value[field] = [] if field.startswith("source_") else None
                code, report = self.invoke_install(value)
                self.assertEqual(code, 126)
                self.assertIsNone(report["observed_tree_digest"])

    def test_missing_entry_record_preserves_unknown_attempt(self):
        code, report = self.invoke_install(None, entry_error=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["installation_attempted"])
        self.assertTrue(report["entry_call_attempted"])
        self.assertEqual(report["publication_state"], "UNKNOWN")
        self.assertIsNone(report["observed_tree_digest"])

    def test_uncertain_descriptor_metadata_remains_private_and_bound(self):
        value = self.install_observation() | {"status": "CLEANUP_HOLD",
            "failure_stage": "DESTINATION_CLEANUP", "owned_destination_closed": False,
            "input_cleanup_uncertainty": [{"scope": "DESTINATION_CLOSE", "descriptors": [19]}]}
        report = self.s._public_install(value)
        self.assertEqual(report["input_cleanup_uncertainty_digest"],
            self.s._digest(self.s._canonical(value["input_cleanup_uncertainty"])))
        self.assertNotIn("descriptors", json.dumps(report))
        self.assertIsNone(report["observed_tree_digest"])

    def test_private_records_are_bounded_and_transaction_schema_is_fixed(self):
        for changes in ({"transaction": {"schema": "foreign"}}, {"recovery": []},
                        {"transaction": {"schema": "aragorn/protected-install-transaction/v1",
                                         "large": "x" * (256 * 1024)}},
                        {"input_cleanup_uncertainty": [None] * 513}):
            with self.subTest(field=list(changes)):
                code, report = self.invoke_install(self.install_observation() | changes)
                self.assertEqual(code, 126)
                self.assertTrue(report["installation_attempted"])

    def test_prepublication_refusal_does_not_claim_installation(self):
        value = self.install_observation() | {"status": "REFUSED_OR_INDETERMINATE",
            "failure_stage": "PREPARED_INPUTS", "installation_attempted": False,
            "publication_state": "NOT_ATTEMPTED", "observed_tree_digest": None, "transaction": None}
        code, report = self.invoke_install(value, entry_error=True)
        self.assertEqual(code, 126)
        self.assertFalse(report["installation_attempted"])
        self.assertIsNone(report["transaction_digest"])
        self.assertIsNone(report["observed_tree_digest"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(BundleInstallDispatchTests(name)
        for name in sorted(BundleInstallDispatchTests.__dict__) if name.startswith("test_"))
    suite.addTests(legacy.CoordinatorWrapperTests(name) for name in (
        "test_main_calls_fixed_entry_once_and_reports_only_completed_bootstrap",
        "test_main_keeps_entry_exception_observation_and_stage"))
    suite.addTests(preparation_fixture.InventoryDispatchTests(name) for name in (
        "test_literal_preparation_route_retains_exact_existing_artifacts_without_launch",
        "test_post_call_host_failure_withholds_artifacts_without_retry"))
    return suite
