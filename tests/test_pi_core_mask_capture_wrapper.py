"""Fixed mask-capture route under the inert wrapper fixture; no real entry is invoked."""
import json
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_coordinator_wrapper as legacy


def pin(n):
    return "sha256:" + n * 64


def retained(consistent=True):
    return dict(schema="aragorn/pi-core-mask-capture-entry/v1",
                status="CAPTURE_RETAINED_ONLY" if consistent else "CAPTURE_RETAINED_INCONSISTENT",
                capture_attempted=True, claim_confirmed=True, owned_inputs_closed=True,
                cleanup_verified=True, mask_consistent=consistent, capture_digest=pin("8"),
                receipt_digest=pin("9"), activation_authorized=False, phase3_exit_eligible=False)


class MaskCaptureWrapper(legacy.CoordinatorWrapperTests):
    def invoke(self, value, *, release=None, flag="--capture-stopped-masks", error=False, cleanup=None, guard=None):
        release = [pin("c")] if release is None else release
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=guard), close=mock.Mock())
        loader = types.SimpleNamespace(close=mock.Mock())
        if cleanup is not None:
            (host if cleanup == "host" else loader).close.side_effect = OSError("PRIVATE_CLOSE")
        package = types.ModuleType("aragorn")
        package.__path__ = []
        entry = types.ModuleType("aragorn.pi_core_mask_capture_entry")
        managed = types.ModuleType("aragorn.pi_core_coordinator_entry")
        exc = RuntimeError("PRIVATE_ERROR")
        exc.observation = value
        entry.run = mock.Mock(return_value=value, side_effect=exc if error else None)
        managed.run = mock.Mock(side_effect=AssertionError("capture cannot run managed bootstrap"))
        cmd = [str(self.wrapper), flag, str(self.profile_path), pin("a"), str(self.root / "plan"), pin("b"),
               *release, str(int(self.deadline * 1_000_000_000))]
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host) as held, \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.object(sys, "argv", cmd), mock.patch.dict(sys.modules, {
                    "aragorn": package, entry.__name__: entry, managed.__name__: managed}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            code = self.s.main()
        managed.run.assert_not_called()
        if entry.run.called:
            entry.run.assert_called_once_with(self.root / "plan", pin("b"), release_digest=pin("c"),
                deadline_ns=int(cmd[-1]), source_loader=loader, host_custody=host)
            host.close.assert_called_once_with()
            loader.close.assert_called_once_with()
        else:
            held.assert_not_called()
        raw = printed.call_args.args[0]
        self.assertNotIn("PRIVATE", raw)
        self.assertNotIn(str(self.root), raw)
        return code, json.loads(raw)

    def test_only_exact_capture_route_with_separate_pins_can_report_verified_retention(self):
        code, report = self.invoke(retained())
        self.assertEqual((code, report["status"], report["capture_digest"], report["receipt_digest"]),
                         (0, "CAPTURE_RETAINED_ONLY", pin("8"), pin("9")))
        self.assertEqual(report["wrapper_cleanup"], {"host": "CLOSED", "source_loader": "CLOSED"})
        self.assertFalse(report["activation_authorized"] or report["phase3_exit_eligible"])

    def test_missing_repeated_null_extra_or_malformed_approval_refuses_before_custody(self):
        for release in ([], [pin("a")], [pin("b")], [pin("0")], ["null"], [pin("c"), pin("d")]):
            with self.subTest(release=release):
                code, report = self.invoke(None, release=release)
                self.assertEqual(code, 126)
                self.assertFalse(report["entry_call_attempted"])
        code, report = self.invoke(None, flag="--capture-stopped-masks=force")
        self.assertEqual((code, report["entry_call_attempted"]), (126, False))

    def test_verified_negative_emits_two_pins_but_never_success(self):
        code, report = self.invoke(retained(False))
        self.assertEqual((code, report["status"], report["mask_consistent"], report["receipt_digest"]),
                         (126, "CAPTURE_RETAINED_INCONSISTENT", False, pin("9")))

    def test_custody_loss_close_failure_or_entry_exception_withholds_both_pins(self):
        for change in (dict(error=True), dict(guard=[None, ValueError("PRIVATE_GUARD")]),
                       dict(cleanup="source_loader"), dict(cleanup="host")):
            with self.subTest(change=change):
                code, report = self.invoke(retained(), **change)
                self.assertEqual((code, report["entry_status"], report["capture_attempted"]),
                                 (126, "CLEANUP_HOLD", True))
                self.assertIsNone(report["capture_digest"])
                self.assertIsNone(report["receipt_digest"])
                self.assertIsNone(report["mask_consistent"])
                self.assertFalse(report["cleanup_verified"])

    def test_forged_claim_denial_or_privileged_result_is_not_serialized(self):
        for changes in (dict(claim_confirmed=False), dict(cleanup_verified=False), dict(owned_inputs_closed=False),
                        dict(mask_consistent=False), dict(mask_consistent=1), dict(receipt_digest=pin("8")),
                        dict(activation_authorized=True), dict(phase3_exit_eligible=True), dict(raw="PRIVATE")):
            with self.subTest(changes=changes):
                code, report = self.invoke(retained() | changes)
                self.assertEqual((code, report["wrapper_stage"], report["capture_attempted"]), (126, "REPORT_REFUSED", True))
                self.assertIsNone(report["receipt_digest"])

    def test_entry_cleanup_hold_keeps_known_attempt_without_publishing_provisional_pins(self):
        code, report = self.invoke(retained() | dict(status="CLEANUP_HOLD", owned_inputs_closed=False), error=True)
        self.assertEqual((code, report["entry_status"], report["claim_confirmed"]), (126, "CLEANUP_HOLD", True))
        self.assertIsNone(report["receipt_digest"])
        code, report = self.invoke(None, error=True)
        self.assertEqual(code, 126)
        self.assertIsNone(report["capture_attempted"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(MaskCaptureWrapper(n) for n in MaskCaptureWrapper.__dict__ if n.startswith("test_"))
    suite.addTest(legacy.CoordinatorWrapperTests("test_main_calls_fixed_entry_once_and_reports_only_completed_bootstrap"))
    return suite
