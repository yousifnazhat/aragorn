"""Inert start boundary only; reuse the stopped supervisor's native substitutes."""
from pathlib import Path
from unittest import TestCase, mock

from aragorn import pi_core_native_supervisor as native
from tests import test_pi_core_stopped_mask_hook as fixture


class CaptureStartGuard(TestCase):
    setUp = fixture.CaptureSupervisor.setUp
    stub_observer = fixture.CaptureSupervisor.stub_observer
    was_cleanup_only = fixture.CaptureSupervisor.was_cleanup_only

    def run_capture(self, *, _before_start):
        return native.run_native_pi_stopped_mask_capture(None, {}, profile=None, grant={}, protected_root=Path("/fixture/admitted"),
            runtime_conformance_digest="", deployment={}, revoked_context_ids=(), now_unix=0, deadline=20.0,
            config=self.config, capture=self.custody, _before_start=_before_start)

    def test_protected_guard_can_withdraw_after_preparation_before_any_start(self):
        def withdrawn():
            self.resources.assert_called_once()
            self.assertEqual(native._unit_state.call_count, 2)
            self.start.assert_not_called()
            raise PermissionError("release withdrawn")
        result = self.run_capture(_before_start=withdrawn)
        self.assertEqual((result["status"], result["retention"]), ("REFUSED", None))
        self.assertFalse(self.cleanup.call_args.args[0].start_attempted)
        self.arm.assert_not_called()
        self.start.assert_not_called()
        self.close.assert_called_once()

    def test_protected_guard_cannot_consume_the_reserved_cleanup_time(self):
        def late():
            native.time.monotonic.return_value = 15.0
        self.assertEqual(self.run_capture(_before_start=late)["status"], "REFUSED")
        self.start.assert_not_called()
        self.assertFalse(self.cleanup.call_args.args[0].start_attempted)

    def test_confirmed_protected_guard_allows_one_original_bounded_start(self):
        def guard():
            self.resources.assert_called_once()
            self.start.assert_not_called()
        confirm = mock.Mock(side_effect=guard)
        self.arm.side_effect = self.stub_observer
        self.assertEqual(self.run_capture(_before_start=confirm)["status"], "CAPTURE_RETAINED_ONLY")
        confirm.assert_called_once_with()
        self.was_cleanup_only()
