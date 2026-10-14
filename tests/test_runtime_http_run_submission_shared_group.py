"""New actual-account delta and journal/replay composition; fabricated OS only."""

from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

from aragorn.native_phase3_run_submission_verify import verify_submission_transcript
from test_runtime_http_run_submission import (
    CONTROL, LOCK, CONTROL_FD, LOCK_FD, UID, GID, FALSE_FLAGS,
    MemoryJournal, canonical, context_record, digest, subject,
)


class SharedRuntimeGroupTests(unittest.TestCase):
    def begin(self, *, runtime_uid=903, runtime_gid=GID):
        raw = canonical(context_record())
        config = SimpleNamespace(control_root=Path(CONTROL), lock_path=Path(LOCK),
                                 expected_broker_uid=UID,
                                 expected_runtime_uid=runtime_uid,
                                 expected_runtime_gid=runtime_gid)
        return subject.begin_http_submission_locked(
            CONTROL_FD, LOCK_FD, config, context_raw=raw,
            expected_context_digest=digest(raw))

    def borrowed_only(self, fs):
        self.assertEqual(set(fs.handles), {CONTROL_FD, LOCK_FD})
        self.assertNotIn(("close", CONTROL_FD), fs.calls)
        self.assertNotIn(("close", LOCK_FD), fs.calls)

    def test_shared_group_actual_journal_bound_replays_without_authority(self):
        for runtime_gid in (GID, GID + 1):
            with self.subTest(runtime_gid=runtime_gid):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(runtime_gid=runtime_gid)
                    files = fs.journal_files()
                    context_raw = next(raw for path, raw in files.items()
                                       if path.endswith("-context.json"))
                    bound_raw = next(raw for path, raw in files.items()
                                     if path.endswith("-event-0.json"))
                    context = context_record()
                    replay = verify_submission_transcript(
                        context_raw, [bound_raw], {},
                        expected_context_digest=digest(context_raw),
                        expected_request_digest=context["request_digest"],
                        expected_broker=context["broker"],
                        expected_provider=context["provider"],
                        expected_clock=context["clock"],
                        expected_terminal_digest=None)
                    self.assertEqual(replay["status"], "CONSISTENT_OPEN_PREFIX")
                    self.assertEqual(replay["submission_state"], "UNKNOWN")
                    self.assertTrue(all(replay[key] is False for key in FALSE_FLAGS))
                    self.assertEqual(len(files), 2)
                    self.assertTrue(all(stat.S_IMODE(fs.nodes[path].st_mode) == 0o400
                                        for path in files))
                    journal.close()
                    self.borrowed_only(fs)

    def test_runtime_uid_overlap_and_malformed_or_partial_accounts_refuse(self):
        accounts = [(UID, GID), (True, GID), (903, True), (-1, GID),
                    (903, -1), ("903", GID), (903, "902"), (903.0, GID),
                    (903, 902.0), (None, GID), (903, None)]
        for runtime_uid, runtime_gid in accounts:
            with self.subTest(runtime_uid=runtime_uid, runtime_gid=runtime_gid):
                fs = MemoryJournal()
                with fs.patches():
                    with self.assertRaises(subject.SubmissionJournalError):
                        self.begin(runtime_uid=runtime_uid, runtime_gid=runtime_gid)
                    self.assertEqual(fs.journal_files(), {})
                    self.borrowed_only(fs)

    def test_shared_group_never_relaxes_control_lock_or_root_permissions(self):
        for path, mode in ((CONTROL, stat.S_IFDIR | 0o710),
                           (CONTROL, stat.S_IFDIR | 0o770),
                           (LOCK, stat.S_IFREG | 0o640),
                           (LOCK, stat.S_IFREG | 0o660),
                           ("/var", stat.S_IFDIR | 0o775)):
            with self.subTest(path=path, mode=mode):
                fs = MemoryJournal()
                fs.nodes[path].st_mode = mode
                with fs.patches():
                    with self.assertRaises(subject.SubmissionJournalError):
                        self.begin()
                    self.assertEqual(fs.journal_files(), {})
                    self.borrowed_only(fs)

    def test_shared_group_record_permission_and_saved_identity_changes_refuse(self):
        for changed in ("record_group_read", "record_group_write", "saved_uid", "saved_gid"):
            with self.subTest(changed=changed):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin()
                    refused_fd = None
                    if changed.startswith("record_"):
                        path = next(iter(fs.journal_files()))
                        refused_fd = next(fd for fd, handle in fs.handles.items()
                                          if handle.node.path == path)
                        fs.nodes[path].st_mode = stat.S_IFREG | (
                            0o440 if changed == "record_group_read" else 0o420)
                    elif changed == "saved_uid":
                        fs.uids = (UID, UID, UID + 1)
                    else:
                        fs.gids = (GID, GID, GID + 1)
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        journal.submission_snapshot()
                    self.assertFalse(caught.exception.intent_attempted)
                    self.assertFalse(caught.exception.known_intent)
                    self.assertIsNone(caught.exception.effect_possible)
                    with self.assertRaises(subject.SubmissionJournalError) as closing:
                        journal.close()
                    if refused_fd is None:
                        self.borrowed_only(fs)
                    else:
                        self.assertEqual(set(fs.handles), {CONTROL_FD, LOCK_FD, refused_fd})
                        self.assertNotIn(("close", refused_fd), fs.calls)
                        self.assertEqual(len(closing.exception.cleanup_failures), 1)


if __name__ == "__main__":
    unittest.main()
