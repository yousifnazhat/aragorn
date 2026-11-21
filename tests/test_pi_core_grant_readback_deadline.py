"""B29's locked readback must still be valid after its own cleanup returns."""

import unittest
from unittest import mock

from aragorn import pi_core_service_lifecycle as lifecycle
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_broker_preparation_lifecycle as b29


class GrantReadbackDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.f = b29.ControlSnapshotTests(methodName="runTest")
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def after_close(self, *, wall, monotonic):
        def close(_handles):
            lifecycle.time.time.return_value = wall
            lifecycle.time.monotonic.return_value = monotonic

        self.f.close_handles.side_effect = close

    def closed_once(self):
        self.assertEqual(self.f.lock.call_args_list, [
            mock.call(104, lifecycle.fcntl.LOCK_EX | lifecycle.fcntl.LOCK_NB),
            mock.call(104, lifecycle.fcntl.LOCK_UN),
        ])
        self.f.close_handles.assert_called_once_with([104, 103, 102, 101])

    def assert_incomplete_at_return(self, *, wall, monotonic):
        self.after_close(wall=wall, monotonic=monotonic)
        with self.assertRaises(RuntimeError) as raised:
            self.f.snapshot(require_available=True)
        record = raised.exception.pi_broker_control_snapshot
        self.assertEqual(record["status"], "INCOMPLETE")
        self.assertIs(record["owned_handles_closed"], True)
        self.assertEqual(record["base_state"], b29.base_state())
        self.assertEqual(record["base_state_digest"], canonical_digest(b29.base_state()))
        self.assertEqual(record["grant_state"], b29.available(self.f.grant))
        self.assertEqual(record["state_digest"], canonical_digest(b29.available(self.f.grant)))
        self.closed_once()

    def test_grant_expires_during_handle_close(self):
        self.assert_incomplete_at_return(wall=self.f.grant["expires_at_unix"], monotonic=119.0)

    def test_original_deadline_reached_during_handle_close(self):
        self.assert_incomplete_at_return(wall=self.f.grant["expires_at_unix"] - 1, monotonic=120.0)

    def test_post_close_clock_interrupt_keeps_original_and_readback(self):
        interrupted = KeyboardInterrupt("inert clock interruption")

        def closed(_handles):
            lifecycle.time.time.side_effect = interrupted

        self.f.close_handles.side_effect = closed
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.f.snapshot(require_available=True)
        self.assertIs(raised.exception, interrupted)
        record = interrupted.pi_broker_control_snapshot
        self.assertEqual(record["status"], "INCOMPLETE")
        self.assertIs(record["owned_handles_closed"], True)
        self.assertEqual(record["base_state"], b29.base_state())
        self.assertEqual(record["grant_state"], b29.available(self.f.grant))
        self.closed_once()

    def test_readback_returns_available_just_before_both_boundaries(self):
        self.after_close(wall=self.f.grant["expires_at_unix"] - 0.001, monotonic=119.999)
        result = self.f.snapshot(require_available=True)
        self.assertEqual(result["status"], "AVAILABLE_READBACK")
        self.assertIs(result["owned_handles_closed"], True)
        self.closed_once()

    def test_base_only_preflight_never_claims_fresh_grant_at_return(self):
        self.after_close(wall=self.f.grant["expires_at_unix"], monotonic=119.999)
        result = self.f.snapshot(require_available=False)
        self.assertEqual(result["status"], "PREINSTALLED_CONTROLS_ONLY")
        self.assertIsNone(result["grant_state"])
        self.assertIsNone(result["state_digest"])
        self.f.read.assert_called_once_with(101, "state.json", 1201, 120.0)
        self.f.missing.assert_not_called()
        self.closed_once()
