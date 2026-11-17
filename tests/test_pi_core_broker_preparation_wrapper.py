"""Fixed root route and digest-only output; owned inert wrapper fixture only."""

import copy
import json
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_coordinator_wrapper as legacy
from tests import test_pi_core_bundle_install_dispatch as installation
from tests import test_pi_core_terminal_composition as terminal
from tests.test_pi_core_broker_preparation_entry import lifecycle_result


class PreparationWrapperTests(legacy.CoordinatorWrapperTests):
    def prepared(self):
        value = self.observation()
        value.update(schema="aragorn/pi-core-broker-preparation-result/v1",
            authority="PROTECTED_GRANT_PREPARATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED", managed_call_attempted=False,
            managed_result=None, context_digest="sha256:" + "f" * 64,
            preparation_attempted=True, owned_holders_closed=True,
            preparation_result=lifecycle_result(), input_cleanup_uncertainty=[])
        return value

    def invoke(self, value, *, failure=False, cleanup=False, guard=None, prefix="--prepare-broker-control"):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=guard), close=mock.Mock())
        loader = types.SimpleNamespace(close=mock.Mock(side_effect=OSError("private cleanup") if cleanup else None))
        entry = types.ModuleType("aragorn.pi_core_broker_preparation_entry")
        error = RuntimeError("private failure")
        error.observation = value
        entry.run = mock.Mock(return_value=value, side_effect=error if failure else None)
        forbidden = types.ModuleType("aragorn.pi_core_coordinator_entry")
        forbidden.run = mock.Mock(side_effect=AssertionError("preparation must not launch worker/provider"))
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
        if prefix == "--prepare-broker-control":
            entry.run.assert_called_once()
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        return code, json.loads(printed.call_args.args[0])

    def test_fixed_route_reports_digest_only_after_cleanup(self):
        value = self.prepared()
        code, report = self.invoke(value)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED")
        self.assertEqual(report["preparation_result_digest"], self.s._digest(self.s._canonical(value["preparation_result"])))
        self.assertTrue(report["preparation_cleanup_complete"])
        self.assertNotIn("private-", json.dumps(report))
        self.assertFalse(report["managed_call_attempted"] or report["phase3_exit_eligible"])

    def test_no_arbitrary_preparation_or_module_selector(self):
        for prefix in ("--prepare", "--prepare-broker-control=force", "--module=aragorn.prepare"):
            code, report = self.invoke(None, prefix=prefix)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])

    def test_missing_owner_result_keeps_attempt_unknown(self):
        code, report = self.invoke(None, failure=True)
        self.assertEqual(code, 126)
        self.assertTrue(report["entry_call_attempted"])
        self.assertIsNone(report["preparation_attempted"])

    def test_malformed_or_execution_authority_cannot_be_preparation(self):
        for changes in ({"schema": "foreign"}, {"authority": "ALLOW"}, {"managed_call_attempted": True},
                        {"managed_result": {"private": "secret"}}, {"phase3_exit_eligible": True}):
            with self.subTest(changes=changes):
                code, report = self.invoke(self.prepared() | changes)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")
                self.assertNotIn("secret", json.dumps(report))

    def test_success_needs_attempt_context_and_all_owned_cleanup(self):
        for changes in ({"preparation_attempted": False}, {"owned_holders_closed": False},
                        {"owned_inputs_closed": False}, {"context_digest": None},
                        {"input_cleanup_uncertainty": [{"scope": "uncertain"}]}):
            code, report = self.invoke(self.prepared() | changes)
            self.assertEqual(code, 126)
            self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_success_needs_real_readback_ack_and_lifecycle_cleanup(self):
        original = self.prepared()
        for scope, field, replacement in (("broker_preparation", "ack_sent", False),
                ("broker_preparation", "readback", None), ("broker_preparation", "status", "INDETERMINATE"),
                ("cleanup", "status", "PENDING")):
            value = copy.deepcopy(original)
            value["preparation_result"][scope][field] = replacement
            with self.subTest(field=field):
                code, report = self.invoke(value)
                self.assertEqual(code, 126)
                self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")

    def test_failure_retains_digest_without_raw_command_state_or_error(self):
        value = self.prepared() | {"status": "CLEANUP_HOLD", "failure_stage": "PREPARATION_CALL"}
        value["preparation_result"]["status"] = "CLEANUP_HOLD"
        value["preparation_result"]["broker_preparation"]["status"] = "INDETERMINATE"
        code, report = self.invoke(value, failure=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["entry_status"], "CLEANUP_HOLD")
        self.assertIsNotNone(report["preparation_result_digest"])
        for raw in ("private-command", "private-result", "private-readback", "private failure"):
            self.assertNotIn(raw, json.dumps(report))
        self.assertNotIn("preparation_result", report)

    def test_post_call_host_failure_keeps_result_but_never_succeeds(self):
        code, report = self.invoke(self.prepared(), guard=[None, RuntimeError("changed host")])
        self.assertEqual(code, 126)
        self.assertIsNotNone(report["preparation_result_digest"])

    def test_wrapper_cleanup_failure_cannot_promote_success(self):
        code, report = self.invoke(self.prepared(), cleanup=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["wrapper_cleanup"]["source_loader"], "CLEANUP_HOLD")
        self.assertTrue(report["preparation_attempted"])

    def test_report_size_bound_preserves_attempt_without_raw_record(self):
        value = self.prepared()
        value["preparation_result"]["raw"] = "z" * (4 * 1024 * 1024)
        code, report = self.invoke(value)
        self.assertEqual(code, 126)
        self.assertTrue(report["preparation_attempted"])
        self.assertIsNone(report["preparation_result_digest"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(PreparationWrapperTests(name) for name in PreparationWrapperTests.__dict__
        if name.startswith("test_"))
    for cls, name in ((legacy.CoordinatorWrapperTests, "test_main_calls_fixed_entry_once_and_reports_only_completed_bootstrap"),
            (legacy.CoordinatorWrapperTests, "test_main_report_refusal_preserves_attempted_or_unknown"),
            (installation.BundleInstallDispatchTests, "test_fixed_route_returns_only_metadata_and_existing_transaction_digest"),
            (terminal.EntryTests, "test_source_verified_action_selects_v2_after_handshake")):
        suite.addTest(cls(name))
    return suite
