"""Inert fixed-host wrapper checks; no provider controls are installed."""

import json
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_provider_base_wrapper as provider_base


class InitialPolicyWrapperTests(provider_base.ProviderBaseWrapperTests):
    def policy_result(self):
        value = self.provider_result()
        value.update(schema="aragorn/pi-core-provider-initial-policy-result/v1",
            authority="PROTECTED_INITIAL_PROVIDER_POLICY_ONLY_NOT_HEALTH_OR_EXECUTION",
            status="INITIAL_PROVIDER_POLICY_RECORDED_NOT_READY_OR_QUALIFIED")
        value["base_installation_result"].update(schema="aragorn/pi-core-provider-initial-policy/v1",
            authority="PINNED_INITIAL_POLICY_AND_REVOCATIONS_ONLY_NOT_HEALTH_OR_EXECUTION",
            policy_digest="sha256:" + "7" * 64, revocations_digest="sha256:" + "8" * 64,
            readback={"fixture": "private policy and revocations"})
        return value

    def invoke_policy(self, value, *, prefix="--initialize-provider-policy", extra=(), fail=False,
                      close_error=False):
        host, loader = mock.Mock(), mock.Mock()
        if close_error:
            host.close.side_effect = OSError("private host failure")
        package = types.ModuleType("aragorn")
        package.__path__ = []
        entry = types.ModuleType("aragorn.pi_core_broker_preparation_entry")
        error = RuntimeError("private entry failure")
        error.observation = value
        entry.run = mock.Mock(return_value=value, side_effect=error if fail else None)
        argv = [str(self.wrapper), prefix, str(self.profile_path), "sha256:" + "d" * 64,
            str(self.root / "plan.json"), "sha256:" + "e" * 64, str(int(self.deadline * 1e9)), *extra]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.dict(sys.modules, {"aragorn": package, entry.__name__: entry}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            code = self.s.main()
        if prefix == "--initialize-provider-policy" and not extra:
            entry.run.assert_called_once_with(self.root / "plan.json", argv[5], deadline_ns=int(argv[6]),
                source_loader=loader, host_custody=host, initialize_provider_policy=True)
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        return code, json.loads(printed.call_args.args[0])

    def test_policy_selector_only_and_digest_not_raw_controls(self):
        value = self.policy_result()
        code, report = self.invoke_policy(value)
        self.assertEqual((code, report["schema"], report["authority"], report["status"]),
            (0, "aragorn/pi-core-provider-initial-policy-report/v1", value["authority"], value["status"]))
        self.assertEqual(report["base_installation_result_digest"],
                         self.s._digest(self.s._canonical(value["base_installation_result"])))
        self.assertNotIn("private policy and revocations", json.dumps(report))
        self.assertNotIn("base_installation_result", report)
        self.assertFalse(report["managed_call_attempted"] or report["phase3_exit_eligible"])

    def test_policy_cross_route_outer_and_inner_bindings(self):
        for foreign in (self.provider_result(), self.result()):
            for field in ("schema", "authority", "status"):
                with self.subTest(outer=field):
                    with self.assertRaises(ValueError):
                        self.s._public_broker_base_install(self.policy_result() | {field: foreign[field]},
                                                          initial_policy=True)
            for field, replacement in (("schema", foreign["base_installation_result"]["schema"]),
                    ("authority", foreign["base_installation_result"]["authority"]), ("status", "PASS")):
                with self.subTest(inner=field):
                    value = self.policy_result()
                    value["base_installation_result"][field] = replacement
                    with self.assertRaises(ValueError):
                        self.s._public_broker_base_install(value, initial_policy=True)
        for route in ({}, {"provider": True}):
            with self.assertRaises(ValueError):
                self.s._public_broker_base_install(self.policy_result(), **route)

    def test_policy_partial_evidence_digest_and_unknown_attempt(self):
        value = self.policy_result() | {"status": "REFUSED_OR_INDETERMINATE", "failure_stage": "BASE_INSTALLATION"}
        value["base_installation_result"].update(status="PARTIAL_OR_INDETERMINATE", readback=None)
        code, report = self.invoke_policy(value, fail=True)
        self.assertEqual((code, report["base_installation_status"]), (126, "PARTIAL_OR_INDETERMINATE"))
        self.assertEqual(report["base_installation_result_digest"],
                         self.s._digest(self.s._canonical(value["base_installation_result"])))
        self.assertNotIn("private entry failure", json.dumps(report))
        code, report = self.invoke_policy(None, fail=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["base_installation_attempted"])

    def test_policy_requires_complete_installation_and_custody(self):
        for change in ({"status": "PARTIAL_OR_INDETERMINATE"}, {"readback": None},
                {"cleanup_uncertainty": ["UNKNOWN"]}, {"owned_handles_closed": False},
                {"service_ready": True}, {"activation_performed": True}):
            value = self.policy_result()
            value["base_installation_result"].update(change)
            with self.subTest(inner=change), self.assertRaises(ValueError):
                self.s._public_broker_base_install(value, initial_policy=True)
        for change in ({"preparation_attempted": True}, {"managed_call_attempted": True},
                {"owned_holders_closed": False}, {"input_cleanup_uncertainty": ["UNKNOWN"]}):
            with self.subTest(outer=change), self.assertRaises(ValueError):
                self.s._public_broker_base_install(self.policy_result() | change, initial_policy=True)
        code, report = self.invoke_policy(self.policy_result(), close_error=True)
        self.assertEqual((code, report["status"], report["wrapper_cleanup"]["host"]),
                         (126, "REFUSED_OR_CLEANUP_HOLD", "CLEANUP_HOLD"))
        self.assertNotIn("private host failure", json.dumps(report))

    def test_policy_selector_cannot_be_combined_or_parameterized(self):
        for prefix, extra in (("--initialize-provider-policy=/tmp", ()),
                ("--initialize-provider-policy", ("--install-provider-base",))):
            code, report = self.invoke_policy(None, prefix=prefix, extra=extra)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(InitialPolicyWrapperTests(name) for name in InitialPolicyWrapperTests.__dict__
                               if name.startswith("test_"))
    suite.addTest(provider_base.ProviderBaseWrapperTests("test_fixed_selector_and_private_digest_result"))
    suite.addTest(provider_base.base.BaseWrapperTests("test_fixed_route_sets_only_local_base_mode_and_reports_digest"))
    return suite
