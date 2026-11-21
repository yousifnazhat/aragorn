"""Return-boundary checks using only the existing recovery fixture's in-memory state."""

import json
import unittest

from aragorn import pi_core_request_recovery as recovery
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_request_recovery as fixture


class GrantReturnDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.PiRequestRecoveryTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def _after_release(self, **clock_values):
        original = self.f.lock.side_effect

        def release(*args, **kwargs):
            original(*args, **kwargs)
            self.assertFalse(self.f.held)
            self.assertEqual(self.f.events[-1], "close")
            for clock, value in clock_values.items():
                getattr(self.f, clock).return_value = value

        self.f.lock.side_effect = release

    def _expire_on_publication(self):
        original = self.f.publish.side_effect

        def publish(*args, **kwargs):
            original(*args, **kwargs)
            self.f.wall.return_value = self.f.grant["expires_at_unix"]

        self.f.publish.side_effect = publish

    def _refuses_without_mutation(self, operation):
        before = self.f.files.copy()
        with self.assertRaises(recovery.broker.RuntimeActionBrokerError) as refusal:
            operation()
        self.assertNotIsInstance(refusal.exception, recovery.broker.RuntimeActionEffectIndeterminate)
        self.assertEqual(self.f.files, before)
        self.assertEqual(self.f.events, ["lock", "close"])
        self.f.publish.assert_not_called()
        self.f.archive.assert_not_called()
        self.f.lock.assert_called_once()

    def test_fresh_publication_at_expiry_is_preserved_without_retry(self):
        self._expire_on_publication()
        with self.assertRaises(recovery.broker.RuntimeActionEffectIndeterminate):
            self.f.initialize(now=102)
        self.assertEqual(self.f.state()["status"], "AVAILABLE")
        self.assertEqual(self.f.state()["grant_digest"], canonical_digest(self.f.grant))
        self.assertEqual(self.f.events, ["lock", ("publish", self.f.config.grant_state_path.name), "close"])
        self.f.publish.assert_called_once()

    def test_rotated_publication_at_expiry_preserves_both_archives_without_retry(self):
        receipt = self.f.receipt(consumed=True)
        old = self.f.state()
        successor = self.f.replacement()
        self._expire_on_publication()
        with self.assertRaises(recovery.broker.RuntimeActionEffectIndeterminate):
            self.f.initialize(successor, now=102)
        for kind, value in (("profile-receipt", receipt), ("state", old)):
            name = recovery.grants._archive_name(kind, old["grant_digest"])
            self.assertEqual(json.loads(self.f.files[name]), value)
        self.assertNotIn("profile-receipt.json", self.f.files)
        self.assertEqual(self.f.state()["status"], "AVAILABLE")
        self.assertEqual(self.f.state()["grant_digest"], canonical_digest(json.loads(successor.capability_grant)))
        self.assertEqual(self.f.archive.call_count, 2)
        self.f.publish.assert_called_once()
        self.f.lock.assert_called_once()

    def test_same_grant_initializer_refuses_expiry_on_release_despite_fixed_now(self):
        self.f.put_state("AVAILABLE", claim=False)
        self._after_release(wall=self.f.grant["expires_at_unix"])
        self._refuses_without_mutation(lambda: self.f.initialize(now=102))

    def test_same_grant_initializer_refuses_clock_rollback_before_issue_despite_fixed_now(self):
        self.f.put_state("AVAILABLE", claim=False)
        self._after_release(wall=self.f.grant["issued_at_unix"] - 1)
        self._refuses_without_mutation(lambda: self.f.initialize(now=102))

    def test_recovery_refuses_newly_expired_available_on_release(self):
        self.f.put_state("AVAILABLE", claim=False)
        self._after_release(wall=self.f.grant["expires_at_unix"])
        self._refuses_without_mutation(self.f.recover)

    def test_recovery_refuses_monotonic_deadline_on_release_without_retry(self):
        self.f.put_state("AVAILABLE", claim=False)
        self._after_release(mono=100.5)
        self._refuses_without_mutation(self.f.recover)

    def test_still_live_available_can_return_after_unlock(self):
        original = self.f.put_state("AVAILABLE", claim=False)
        self._after_release(wall=self.f.grant["expires_at_unix"] - 1, mono=100.49)
        self.assertEqual(self.f.recover(), original)
        self.assertEqual(self.f.events, ["lock", "close"])
        self.f.publish.assert_not_called()
