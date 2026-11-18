"""Owned inert host fixture for the fixed provider-storage preparation route."""

import json
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_broker_base_wrapper as base


class ProviderBaseWrapperTests(base.BaseWrapperTests):
    def provider_result(self):
        value = self.result()
        value.update(schema="aragorn/pi-core-provider-base-result/v1",
            authority="PROTECTED_PROVIDER_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="PROVIDER_BASE_INSTALLED_NOT_READY_OR_QUALIFIED")
        value["base_installation_result"].update(schema="aragorn/pi-core-provider-base-installation/v1",
            destination="/var/lib/aragorn-runtime-provider", provider_config_digest="sha256:" + "a" * 64)
        return value

    def provider(self, value, *, prefix="--install-provider-base", extra=(), cleanup=False, fail=False):
        host, loader = mock.Mock(), mock.Mock()
        if cleanup:
            loader.close.side_effect = OSError("private close error")
        entry = types.ModuleType("aragorn.pi_core_broker_preparation_entry")
        error = RuntimeError("private install error")
        error.observation = value
        entry.run = mock.Mock(return_value=value, side_effect=error if fail else None)
        package = types.ModuleType("aragorn")
        package.__path__ = []
        argv = [str(self.wrapper), prefix, str(self.profile_path), "sha256:" + "d" * 64,
            str(self.root / "plan.json"), "sha256:" + "e" * 64, str(int(self.deadline * 1e9)), *extra]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.dict(sys.modules, {"aragorn": package, entry.__name__: entry}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            code = self.s.main()
        if prefix == "--install-provider-base" and not extra:
            entry.run.assert_called_once_with(self.root / "plan.json", argv[5], deadline_ns=int(argv[6]),
                source_loader=loader, host_custody=host, install_provider_base=True)
            host.close.assert_called_once()
            loader.close.assert_called_once()
        else:
            entry.run.assert_not_called()
        return code, json.loads(printed.call_args.args[0])

    def test_fixed_selector_and_private_digest_result(self):
        value = self.provider_result()
        code, report = self.provider(value)
        self.assertEqual(code, 0)
        self.assertEqual(report["schema"], "aragorn/pi-core-provider-base-report/v1")
        self.assertEqual((report["authority"], report["status"]), (value["authority"], value["status"]))
        self.assertEqual(report["base_installation_result_digest"],
                         self.s._digest(self.s._canonical(value["base_installation_result"])))
        self.assertNotIn("private-base-readback", json.dumps(report))
        self.assertFalse(report["phase3_exit_eligible"] or report["managed_call_attempted"])

    def test_cross_route_substitutions_are_refused(self):
        action = self.result()
        for key in ("schema", "authority", "status", "base_installation_result"):
            with self.subTest(key=key):
                code, report = self.provider(self.provider_result() | {key: action[key]})
                self.assertEqual((code, report["wrapper_stage"]), (126, "REPORT_REFUSED"))
                self.assertIsNone(report["base_installation_result_digest"])
        with self.assertRaises(ValueError):
            self.s._public_broker_base_install(self.provider_result())

    def test_partial_refusal_retains_only_digest(self):
        value = self.provider_result() | {"status": "REFUSED_OR_INDETERMINATE", "failure_stage": "BASE_INSTALLATION"}
        value["base_installation_result"].update(status="PARTIAL_OR_INDETERMINATE", readback=None)
        code, report = self.provider(value, fail=True)
        self.assertEqual(code, 126)
        self.assertEqual(report["base_installation_status"], "PARTIAL_OR_INDETERMINATE")
        self.assertEqual(report["base_installation_result_digest"],
                         self.s._digest(self.s._canonical(value["base_installation_result"])))
        self.assertNotIn("private install error", json.dumps(report))

    def test_cleanup_hold_cannot_become_success(self):
        code, report = self.provider(self.provider_result(), cleanup=True)
        self.assertEqual((code, report["status"], report["wrapper_cleanup"]["source_loader"]),
                         (126, "REFUSED_OR_CLEANUP_HOLD", "CLEANUP_HOLD"))
        self.assertNotIn("private close error", json.dumps(report))

    def test_missing_observation_preserves_unknown_attempt(self):
        code, report = self.provider(None, fail=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["base_installation_attempted"])

    def test_no_combined_or_parameterized_selector(self):
        for prefix, extra in (("--install-provider-base=/tmp", ()), ("--install-provider-base", ("--install-broker-base",))):
            code, report = self.provider(None, prefix=prefix, extra=extra)
            self.assertEqual(code, 126)
            self.assertFalse(report["entry_call_attempted"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(ProviderBaseWrapperTests(name) for name in ProviderBaseWrapperTests.__dict__
                               if name.startswith("test_"))
    for name in ("test_fixed_route_sets_only_local_base_mode_and_reports_digest",
                 "test_foreign_installer_result_is_not_reported_as_installed"):
        suite.addTest(base.BaseWrapperTests(name))
    return suite
