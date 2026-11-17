"""Fixed fresh-base route with inert root custody and no installation or activation."""

import json
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_coordinator_wrapper as fixtures
from tests import test_pi_core_broker_preparation_wrapper as preparation


def installed():
    return {"schema": "aragorn/pi-core-broker-base-installation/v1",
        "authority": "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3",
        "status": "INSTALLED", "mutation_attempted": True, "owned_handles_closed": True,
        "configuration_digest": "sha256:" + "b" * 64, "base_state_digest": "sha256:" + "c" * 64,
        "destination": "/var/lib/aragorn-runtime-action", "readback": {"fixture": "private-base-readback"},
        "activation_performed": False, "service_ready": False, "current_grant_authority": False,
        "phase3_exit_eligible": False, "cleanup_uncertainty": []}


class BaseWrapperTests(fixtures.CoordinatorWrapperTests):
    def result(self):
        value = self.observation()
        value.update(schema="aragorn/pi-core-broker-base-result/v1",
            authority="PROTECTED_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED", managed_call_attempted=False,
            managed_result=None, preparation_attempted=False, preparation_result=None,
            base_installation_attempted=True, base_installation_result=installed(),
            owned_holders_closed=True, context_digest="sha256:" + "f" * 64,
            input_cleanup_uncertainty=[])
        return value

    def invoke(self, value, *, failure=False, cleanup=False, guard=None, prefix="--install-broker-base"):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=guard), close=mock.Mock())
        loader = types.SimpleNamespace(close=mock.Mock(side_effect=OSError("private base cleanup") if cleanup else None))
        entry = types.ModuleType("aragorn.pi_core_broker_preparation_entry")
        error = RuntimeError("private base failure")
        error.observation = value
        entry.run = mock.Mock(return_value=value, side_effect=error if failure else None)
        forbidden = types.ModuleType("aragorn.pi_core_coordinator_entry")
        forbidden.run = mock.Mock(side_effect=AssertionError("base install must not activate"))
        package = types.ModuleType("aragorn")
        package.__path__ = []
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.object(sys, "argv", [str(self.wrapper), prefix, str(self.profile_path),
                    "sha256:" + "d" * 64, str(self.root / "plan.json"), "sha256:" + "e" * 64,
                    str(int(self.deadline * 1_000_000_000))]), \
                mock.patch.dict(sys.modules, {"aragorn": package, entry.__name__: entry, forbidden.__name__: forbidden}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            code = self.s.main()
        forbidden.run.assert_not_called()
        if prefix == "--install-broker-base":
            entry.run.assert_called_once()
            self.assertIs(entry.run.call_args.kwargs["install_base"], True)
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        return code, json.loads(printed.call_args.args[0])

    def test_fixed_route_sets_only_local_base_mode_and_reports_digest(self):
        value = self.result()
        code, report = self.invoke(value)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED")
        self.assertEqual(report["base_installation_result_digest"], self.s._digest(self.s._canonical(installed())))
        self.assertTrue(report["base_cleanup_complete"])
        self.assertNotIn("private-base-readback", json.dumps(report))
        self.assertNotIn("base_installation_result", report)
        self.assertFalse(report["managed_call_attempted"] or report["phase3_exit_eligible"])

    def test_unknown_or_force_selectors_cannot_call_entry(self):
        for prefix in ("--install-base", "--install-broker-base=force", "--install-broker-base=/tmp"):
            code, report = self.invoke(None, prefix=prefix)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])

    def test_unavailable_owner_record_keeps_attempt_unknown(self):
        code, report = self.invoke(None, failure=True)
        self.assertEqual(code, 126)
        self.assertTrue(report["entry_call_attempted"])
        self.assertIsNone(report["base_installation_attempted"])

    def test_execution_or_preparation_authority_is_not_base_installation(self):
        for change in ({"schema": "foreign"}, {"authority": "ALLOW"}, {"managed_call_attempted": True},
                {"managed_result": {}}, {"preparation_attempted": True}, {"preparation_result": {}},
                {"phase3_exit_eligible": True}):
            with self.subTest(change=change):
                code, report = self.invoke(self.result() | change)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_root_success_needs_complete_custody_context_and_attempt(self):
        for change in ({"base_installation_attempted": False}, {"owned_holders_closed": False},
                {"owned_inputs_closed": False}, {"context_digest": None},
                {"input_cleanup_uncertainty": [{"scope": "UNKNOWN"}]}):
            code, report = self.invoke(self.result() | change)
            self.assertEqual(code, 126)
            self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_installer_success_requires_real_readback_mutation_and_closed_handles(self):
        for change in ({"status": "PARTIAL_OR_INDETERMINATE"}, {"owned_handles_closed": False},
                {"mutation_attempted": False}, {"readback": None}, {"readback": []},
                {"cleanup_uncertainty": ["UNKNOWN"]}):
            value = self.result()
            value["base_installation_result"].update(change)
            code, report = self.invoke(value)
            self.assertEqual(code, 126)
            self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_installer_cannot_claim_activation_health_grant_or_qualification(self):
        for key in ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible"):
            for replacement in (True, 0, None):
                value = self.result()
                value["base_installation_result"][key] = replacement
                code, report = self.invoke(value)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_foreign_installer_result_is_not_reported_as_installed(self):
        for change in ({"schema": "foreign"}, {"authority": "AVAILABLE"}, {"status": "PASS"}):
            value = self.result()
            value["base_installation_result"].update(change)
            code, report = self.invoke(value)
            self.assertEqual(code, 126)
            self.assertIsNone(report["base_installation_result_digest"])

    def test_partial_failure_retains_digest_not_raw_state_or_error(self):
        value = self.result() | {"status": "REFUSED_OR_INDETERMINATE", "failure_stage": "BASE_INSTALLATION"}
        value["base_installation_result"].update(status="PARTIAL_OR_INDETERMINATE", readback=None)
        code, report = self.invoke(value, failure=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["base_installation_status"], "PARTIAL_OR_INDETERMINATE")
        self.assertIsNotNone(report["base_installation_result_digest"])
        self.assertNotIn("private base failure", json.dumps(report))
        self.assertNotIn("base_installation_result", report)

    def test_installer_cleanup_hold_survives_wrapper_cleanup_success(self):
        value = self.result() | {"status": "CLEANUP_HOLD", "failure_stage": "BASE_INSTALLATION"}
        value["base_installation_result"].update(status="CLEANUP_HOLD", owned_handles_closed=False)
        code, report = self.invoke(value, failure=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["entry_status"], "CLEANUP_HOLD")
        self.assertFalse(report["base_cleanup_complete"])

    def test_post_call_host_change_withholds_success_and_retains_digest(self):
        code, report = self.invoke(self.result(), guard=[None, RuntimeError("host replaced")])
        self.assertEqual(code, 126)
        self.assertIsNotNone(report["base_installation_result_digest"])

    def test_wrapper_close_uncertainty_cannot_promote_installed_result(self):
        code, report = self.invoke(self.result(), cleanup=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_cleanup"]["source_loader"], "CLEANUP_HOLD")

    def test_evidence_and_cleanup_size_bounds_preserve_attempt_without_raw_data(self):
        value = self.result()
        value["base_installation_result"]["raw"] = "z" * (4 * 1024 * 1024)
        for record in (value, self.result() | {"input_cleanup_uncertainty": [{}] * 513}):
            code, report = self.invoke(record)
            self.assertEqual(code, 126)
            self.assertTrue(report["base_installation_attempted"])
            self.assertIsNone(report["base_installation_result_digest"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(BaseWrapperTests(name) for name in BaseWrapperTests.__dict__
                             if name.startswith("test_"))
    for cls, name in ((fixtures.CoordinatorWrapperTests, "test_main_calls_fixed_entry_once_and_reports_only_completed_bootstrap"),
            (preparation.PreparationWrapperTests, "test_fixed_route_reports_digest_only_after_cleanup"),
            (preparation.PreparationWrapperTests, "test_failure_retains_digest_without_raw_command_state_or_error")):
        suite.addTest(cls(name))
    return suite
