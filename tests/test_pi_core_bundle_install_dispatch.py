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
        value.update(schema="aragorn/pi-core-bundle-install-result/v1",
            authority="PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="INSTALLED_NOT_ACTIVATED_OR_QUALIFIED", managed_call_attempted=False,
            managed_result=None, context_digest="sha256:" + "f" * 64,
            installation_attempted=True, owned_destination_closed=True,
            publication_state="PUBLISHER_RETURNED", input_cleanup_uncertainty=[],
            transaction={"schema": "aragorn/protected-install-transaction/v1",
                         "private": "never-public-transaction-content"}, recovery=None)
        return value

    def invoke_install(self, value, *, entry_error=False, cleanup_error=False,
                       after_guard=None, prefix="--install-bundle"):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=after_guard), close=mock.Mock())
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
                    "sha256:" + "d" * 64, str(self.root / "plan.json"), "sha256:" + "e" * 64,
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
        return result, json.loads(printed.call_args.args[0])

    def test_fixed_route_returns_only_metadata_and_existing_transaction_digest(self):
        value = self.install_observation()
        code, report = self.invoke_install(value)
        self.assertEqual(code, 0)
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
            self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_success_requires_attempt_transaction_context_and_no_recovery(self):
        for changes in ({"installation_attempted": False}, {"transaction": None},
                        {"context_digest": None}, {"publication_state": "UNKNOWN"},
                        {"recovery": {"private": "held claim"}},
                        {"input_cleanup_uncertainty": [{"scope": "held"}]}):
            with self.subTest(changes=changes):
                code, report = self.invoke_install(self.install_observation() | changes)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_publisher_failure_retains_recovery_digest_without_raw_record(self):
        value = self.install_observation() | {"status": "CLEANUP_HOLD",
            "failure_stage": "INSTALLATION", "publication_state": "RECOVERY_RECORD_RETAINED",
            "transaction": None, "recovery": {"private": "never-public-recovery-content"}}
        code, report = self.invoke_install(value, entry_error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["recovery_digest"], self.s._digest(self.s._canonical(value["recovery"])))
        self.assertTrue(report["installation_attempted"])
        self.assertEqual(report["entry_status"], "CLEANUP_HOLD")
        self.assertNotIn("never-public", json.dumps(report))

    def test_post_install_host_custody_failure_does_not_erase_publication_digest(self):
        code, report = self.invoke_install(self.install_observation(),
            after_guard=[None, RuntimeError("changed host")])
        self.assertEqual(code, 126)
        self.assertEqual(report["status"], "REFUSED_OR_CLEANUP_HOLD")
        self.assertIsNotNone(report["transaction_digest"])

    def test_wrapper_close_failure_cannot_become_success(self):
        code, report = self.invoke_install(self.install_observation(), cleanup_error=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_cleanup"]["source_loader"], "CLEANUP_HOLD")
        self.assertTrue(report["installation_attempted"])

    def test_missing_entry_record_preserves_unknown_attempt(self):
        code, report = self.invoke_install(None, entry_error=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["installation_attempted"])
        self.assertTrue(report["entry_call_attempted"])

    def test_uncertain_descriptor_metadata_remains_private_and_bound(self):
        value = self.install_observation() | {"status": "CLEANUP_HOLD",
            "failure_stage": "DESTINATION_CLEANUP", "owned_destination_closed": False,
            "input_cleanup_uncertainty": [{"scope": "DESTINATION_CLOSE", "descriptors": [19]}]}
        report = self.s._public_install(value)
        self.assertEqual(report["input_cleanup_uncertainty_digest"],
            self.s._digest(self.s._canonical(value["input_cleanup_uncertainty"])))
        self.assertNotIn("descriptors", json.dumps(report))

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
            "publication_state": "NOT_ATTEMPTED", "transaction": None}
        code, report = self.invoke_install(value, entry_error=True)
        self.assertEqual(code, 126)
        self.assertFalse(report["installation_attempted"])
        self.assertIsNone(report["transaction_digest"])


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
