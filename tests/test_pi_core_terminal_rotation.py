"""Fixed-receipt retirement and fault boundaries; no filesystem or effect I/O."""

import os
import unittest
from unittest import mock

from tests import test_pi_core_request_recovery as recovery

subject = recovery.subject
RECEIPT = "profile-receipt.json"
STATE = "capability-grant-state.json"


class TerminalRotationTests(recovery.PiRequestRecoveryTests):
    def originals(self):
        self.receipt(consumed=True)
        self.state_raw, self.receipt_raw = self.files[STATE], self.files[RECEIPT]
        digest = self.state()["grant_digest"]
        self.saved_state = subject.grants._archive_name("state", digest)
        self.saved_receipt = subject.grants._archive_name("profile-receipt", digest)

    def assert_archived(self):
        self.assertEqual(self.files[self.saved_state], self.state_raw)
        self.assertEqual(self.files[self.saved_receipt], self.receipt_raw)

    def test_retire_exact_alias_only_after_both_archives_before_available(self):
        self.originals()
        self.files["untouched"] = b"not ours"
        result = self.initialize(self.replacement())
        self.assert_archived()
        self.assertNotIn(RECEIPT, self.files)
        self.assertEqual(self.files["untouched"], b"not ours")
        self.assertEqual(result["status"], "AVAILABLE")
        expected = [("archive", self.saved_receipt), ("archive", self.saved_state), ("unlink", RECEIPT),
                    "fsync", ("publish", STATE)]
        self.assertEqual([e for e in self.events if e in expected], expected)
        self.assertIsNone(self.receipt_fd)

    def test_fixed_orphan_blocks_both_available_entrypoints_without_mutation(self):
        self.receipt(consumed=True)
        self.put_state("AVAILABLE", claim=False)
        before = dict(self.files)
        for operation in (self.initialize, self.recover):
            with self.subTest(operation=operation.__name__), self.assertRaises(subject.broker.RuntimeActionBrokerError):
                operation()
        self.assertEqual(self.files, before)
        self.archive.assert_not_called()
        self.publish.assert_not_called()
        os.unlink.assert_not_called()

    def test_foreign_claim_bytes_refuse_before_any_archive(self):
        self.originals()
        row = recovery.json.loads(self.receipt_raw)
        row["submission_digest"] = "sha256:" + "1" * 64
        self.files[RECEIPT] = recovery.canonical_json(row)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError):
            self.initialize(self.replacement())
        self.archive.assert_not_called()
        self.publish.assert_not_called()
        os.unlink.assert_not_called()
        self.assertEqual(self.files[STATE], self.state_raw)

    def test_original_must_be_single_link_role_owned_read_only_regular_file(self):
        self.originals()
        fstat = os.fstat.side_effect
        for field, invalid in (("st_uid", 0), ("st_gid", 0), ("st_nlink", 2),
                               ("st_mode", 0o100600), ("st_mode", 0o120400)):
            def wrong(fd):
                row = fstat(fd)
                if fd == 84:
                    setattr(row, field, invalid)
                return row
            with self.subTest(field=field, value=invalid), mock.patch.object(os, "fstat", side_effect=wrong):
                with self.assertRaises(subject.broker.RuntimeActionBrokerError):
                    self.initialize(self.replacement())
        self.archive.assert_not_called()
        self.publish.assert_not_called()
        os.unlink.assert_not_called()

    def test_replaced_fixed_name_after_archival_is_not_unlinked_even_when_bytes_match(self):
        self.originals()
        def substitute(name):
            if name == self.saved_state:
                self.named_ino += 1
        self.after_archive = substitute
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.initialize(self.replacement())
        self.assert_archived()
        self.publish.assert_not_called()
        os.unlink.assert_not_called()
        self.assertEqual((self.files[STATE], self.files[RECEIPT]), (self.state_raw, self.receipt_raw))
        self.assertIsNone(self.receipt_fd)

    def test_wrong_archived_bytes_cannot_retire_active_alias(self):
        self.originals()
        def corrupt(name):
            if name == self.saved_state:
                self.files[self.saved_receipt] = b"substituted"
        self.after_archive = corrupt
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.initialize(self.replacement())
        self.assertEqual((self.files[STATE], self.files[RECEIPT]), (self.state_raw, self.receipt_raw))
        self.assertEqual(self.files[self.saved_receipt], b"substituted")
        os.unlink.assert_not_called()
        self.publish.assert_not_called()

    def test_existing_exact_predecessor_archive_is_a_hold_not_resume_permission(self):
        self.originals()
        for archive, content in ((self.saved_receipt, self.receipt_raw), (self.saved_state, self.state_raw)):
            with self.subTest(archive=archive), mock.patch.dict(self.files, {archive: content}):
                before = dict(self.files)
                with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
                    self.initialize(self.replacement())
                self.assertEqual(self.files, before)
        self.archive.assert_not_called()
        os.unlink.assert_not_called()
        self.publish.assert_not_called()

    def test_incoming_receipt_only_archive_cannot_issue_or_resume_available_authority(self):
        incoming = self.replacement()
        incoming_digest = recovery.canonical_digest(recovery.json.loads(incoming.capability_grant))
        name = subject.grants._archive_name("profile-receipt", incoming_digest)
        self.originals()
        with mock.patch.dict(self.files, {name: self.receipt_raw}):
            before = dict(self.files)
            with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
                self.initialize(incoming)
            self.assertEqual(self.files, before)
        self.files.pop(RECEIPT)
        self.put_state("AVAILABLE", claim=False)
        self.files[self.saved_receipt] = self.receipt_raw
        for operation in (self.initialize, self.recover):
            before = dict(self.files)
            with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
                operation()
            self.assertEqual(self.files, before)
        del self.files[STATE]
        before = dict(self.files)
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.initialize()
        self.assertEqual(self.files, before)
        self.archive.assert_not_called()
        os.unlink.assert_not_called()
        self.publish.assert_not_called()

    def test_unlink_with_unknown_outcome_is_not_reissued_or_published(self):
        self.originals()
        unlink = os.unlink.side_effect
        marker = OSError("retirement acknowledgment unavailable")
        def uncertain(name, *, dir_fd):
            unlink(name, dir_fd=dir_fd)
            raise marker
        os.unlink.side_effect = uncertain
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate) as caught:
            self.initialize(self.replacement())
        self.assertIs(caught.exception.__cause__, marker)
        os.unlink.assert_called_once_with(RECEIPT, dir_fd=77)
        self.publish.assert_not_called()
        self.assert_archived()
        self.assertNotIn(RECEIPT, self.files)
        self.assertEqual(self.files[STATE], self.state_raw)

    def test_uncertain_directory_sync_retains_archives_and_withholds_authority(self):
        self.originals()
        self.fail_sync = True
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.initialize(self.replacement())
        self.assert_archived()
        self.assertNotIn(RECEIPT, self.files)
        self.assertEqual(self.files[STATE], self.state_raw)
        os.unlink.assert_called_once_with(RECEIPT, dir_fd=77)
        os.fsync.assert_called_once_with(77)
        self.publish.assert_not_called()

    def test_new_grant_expiring_during_retirement_never_becomes_available(self):
        self.originals()
        sync = os.fsync.side_effect
        def expire(fd):
            sync(fd)
            self.wall.return_value = self.grant["expires_at_unix"]
        os.fsync.side_effect = expire
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.initialize(self.replacement(), now=None)
        self.assert_archived()
        self.assertEqual(self.files[STATE], self.state_raw)
        self.assertNotIn(RECEIPT, self.files)
        self.publish.assert_not_called()

    def test_close_failure_does_not_replace_retirement_error_or_retry_close(self):
        self.originals()
        marker = OSError("retirement uncertain")
        os.unlink.side_effect = marker
        os.close.side_effect = OSError("held descriptor cleanup uncertain")
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate) as caught:
            self.initialize(self.replacement())
        errors = []
        error = caught.exception
        while error is not None:
            errors.append(error)
            error = error.__cause__
        self.assertIn(marker, errors)
        self.assertTrue(any("close" in str(e).lower() for e in errors))
        os.close.assert_called_once_with(84)
        os.unlink.assert_called_once_with(RECEIPT, dir_fd=77)
        self.assert_archived()
        self.publish.assert_not_called()

    def assert_role_lock_failure(self, error, marker):
        while error is not None and not hasattr(error, "pi_role_lock_cleanup_error"):
            error = error.__cause__
        self.assertIsNotNone(error, "secondary lock cleanup failure must remain identifiable")
        self.assertIs(error.__cause__, marker)
        cleanup = error.pi_role_lock_cleanup_error
        self.assertIsInstance(cleanup, subject.broker.RuntimeActionBrokerError)
        self.assertEqual(str(cleanup), "mock cleanup uncertainty")
        self.lock.assert_called_once()

    def test_uncertain_retirement_and_lock_cleanup_keep_both_failures(self):
        self.originals()
        self.fail_cleanup = True
        marker = OSError("retirement outcome unknown")
        os.unlink.side_effect = marker
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate) as caught:
            self.initialize(self.replacement())
        self.assert_role_lock_failure(caught.exception, marker)
        os.unlink.assert_called_once_with(RECEIPT, dir_fd=77)
        self.assert_archived()
        self.assertEqual((self.files[STATE], self.files[RECEIPT]), (self.state_raw, self.receipt_raw))
        self.publish.assert_not_called()

    def test_uncertain_consumption_and_lock_cleanup_keep_both_failures(self):
        self.receipt()
        before = dict(self.files)
        self.fail_cleanup = True
        marker = OSError("consumption publication outcome unknown")
        self.publish.side_effect = marker
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate) as caught:
            self.recover()
        self.assert_role_lock_failure(caught.exception, marker)
        self.publish.assert_called_once()
        self.assertEqual(self.files, before)
        self.archive.assert_not_called()
        os.unlink.assert_not_called()

    def test_crash_after_retirement_requires_reconciliation_not_implicit_reconstruction(self):
        self.originals()
        self.files[self.saved_state] = self.state_raw
        self.files[self.saved_receipt] = self.files.pop(RECEIPT)
        before = dict(self.files)
        for operation in (self.recover, lambda: self.initialize(self.replacement())):
            with self.assertRaises((FileNotFoundError, subject.broker.RuntimeActionBrokerError)):
                operation()
        self.assertEqual(self.files, before)
        self.archive.assert_not_called()
        self.publish.assert_not_called()
        os.unlink.assert_not_called()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(TerminalRotationTests(name) for name in TerminalRotationTests.__dict__
                               if name.startswith("test_"))
    for name in ("test_fresh_grant_rotation_archives_receipt_then_state_before_available",
                 "test_terminal_with_pending_requires_explicit_recovery_before_rotation",
                 "test_old_archived_grant_cannot_be_reissued", "test_restored_available_state_cannot_revive_archived_terminal_grant",
                 "test_changed_immutable_archive_never_overwritten", "test_archive_failure_retains_old_state_and_partial_evidence",
                 "test_post_archive_publication_uncertainty_never_rolls_back", "test_deadline_expiring_after_archive_never_publishes_new_authority",
                 "test_expired_available_grant_terminalizes_without_effect", "test_abandoned_terminal_can_rotate_but_never_become_available_again"):
        suite.addTest(TerminalRotationTests(name))
    return suite
