"""Prepared inert checks only: scratch FDs and mocked native fixture/clock guards."""

import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_workload_copy_readback as producer
from aragorn import native_phase3_workload_copy_readback_verify as consumer
from aragorn import phase3_reference_tasks as tasks
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


INPUT = b"Aragorn Phase 3 benign copy/readback data.\n"
FIXTURE = {
    "container_id": "a" * 64, "boot_id": "12345678-1234-1234-1234-123456789abc",
    "netns_device": 1, "netns_inode": 2,
}


class CopyReadbackTests(unittest.TestCase):
    def setUp(self):
        descriptor = tasks.describe_tasks(Path(tasks.__file__).read_bytes())["BENIGN_COPY_READBACK"]
        self.request = {
            "kind": "task", "mode": "baseline", "pair_id": "p3-lab-p076",
            "task_digest": canonical_digest(descriptor),
            "input_digest": descriptor["input"]["digest"],
            "host_profile_digest": "sha256:" + "1" * 64,
            "collection_digest": "sha256:" + "2" * 64,
            "deployment_digest": "sha256:" + "3" * 64,
        }
        self.boundaries = {"TASK_ACCEPTED": 10, "TASK_COMPLETED": 20}

    @contextmanager
    def scratch(self):
        held = MagicMock()

        @contextmanager
        def owned(fixture):
            self.assertEqual(fixture, FIXTURE)
            try:
                yield held
            finally:
                held.guard()

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            # macOS scratch parents may inherit a different group.
            os.chown(directory, -1, os.getegid())
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            meta = os.fstat(fd)
            context = {
                "copy_directory_fd": fd,
                "expected_copy_directory_identity": {
                    "device": meta.st_dev, "inode": meta.st_ino,
                    "mode": stat.S_IMODE(meta.st_mode), "uid": meta.st_uid, "gid": meta.st_gid,
                },
                "expected_fixture": dict(FIXTURE),
            }
            try:
                with patch.object(producer, "owned_http_fixture", owned), \
                     patch.object(consumer, "owned_http_fixture", owned), \
                     patch.object(tasks, "owned_http_fixture", owned), \
                     patch.object(producer.sys, "platform", "linux"), \
                     patch.object(producer.time, "CLOCK_BOOTTIME", 7, create=True):
                    yield directory, context, held
            finally:
                os.close(fd)

    def execute(self, context, request=None, mark=None):
        return producer.execute(self.request if request is None else request,
                                self.boundaries.__getitem__ if mark is None else mark, **context)

    def verify(self, raw, context, request=None, boundaries=None):
        return consumer.verify(raw, self.request if request is None else request,
                               self.boundaries if boundaries is None else boundaries, **context)

    def test_both_modes_delegate_once_between_marks_and_preserve_caller_fd(self):
        identities = []
        # Keep both directories alive while checking they are distinct.
        with self.scratch() as baseline, self.scratch() as instrumented:
            for mode, (directory, context, _) in zip(("baseline", "instrumented"), (baseline, instrumented)):
                request = {**self.request, "mode": mode}
                before = copy.deepcopy(context)
                events = []
                original = tasks.execute_reference_task

                def task(*args, **kwargs):
                    events.append("TASK")
                    return original(*args, **kwargs)

                def mark(name):
                    events.append(name)
                    return self.boundaries[name]

                with patch.object(tasks, "execute_reference_task", side_effect=task) as called:
                    raw = self.execute(context, request, mark)
                called.assert_called_once()
                self.assertEqual(called.call_args.args, ("BENIGN_COPY_READBACK", INPUT))
                self.assertEqual(events, ["TASK_ACCEPTED", "TASK", "TASK_COMPLETED"])
                self.assertEqual(self.verify(raw, context, request)["semantics"], {"completed": True})
                self.assertEqual(context, before)
                self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT)
                self.assertEqual(os.fstat(context["copy_directory_fd"]).st_ino,
                                 context["expected_copy_directory_identity"]["inode"])
                identities.append(context["expected_copy_directory_identity"])
            self.assertNotEqual(identities[0], identities[1])

    def test_malformed_request_context_and_wrong_task_refuse_before_marks(self):
        with self.scratch() as (directory, context, _):
            variants = [
                ({**self.request, "input_digest": "sha256:" + "4" * 64}, context),
                ({**self.request, "task_digest": "sha256:" + "4" * 64}, context),
                (self.request, {**context, "copy_directory_fd": True}),
                (self.request, {**context, "expected_fixture": {}}),
                (self.request, {**context, "expected_copy_directory_identity": {
                    **context["expected_copy_directory_identity"], "inode": True}}),
                (self.request, {**context, "expected_copy_directory_identity": {
                    **context["expected_copy_directory_identity"],
                    "inode": context["expected_copy_directory_identity"]["inode"] + 1}}),
            ]
            for request, altered in variants:
                with self.subTest(request=request, context=altered), self.assertRaises(ValueError):
                    self.execute(altered, request, lambda _: self.fail("unexpected mark"))
            self.assertFalse((directory / "allowed-copy.txt").exists())

    def test_task_failure_retains_partial_output_without_completion_or_retry(self):
        with self.scratch() as (directory, context, _):
            events = []
            original_write = os.write

            def fail_after_partial(fd, raw):
                original_write(fd, raw[:3])
                raise OSError("injected partial write")

            with patch.object(tasks.os, "write", side_effect=fail_after_partial) as called:
                with self.assertRaisesRegex(OSError, "partial write"):
                    self.execute(context, mark=lambda name: events.append(name) or 10)
            self.assertEqual(called.call_count, 1)
            self.assertEqual(events, ["TASK_ACCEPTED"])
            self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT[:3])
            os.fstat(context["copy_directory_fd"])
        with self.scratch() as (directory, context, _):
            events = []
            with patch.object(producer, "_retained_identity", side_effect=OSError("retention failed")):
                with self.assertRaisesRegex(OSError, "retention failed"):
                    self.execute(context, mark=lambda name: events.append(name) or self.boundaries[name])
            self.assertEqual(events, ["TASK_ACCEPTED", "TASK_COMPLETED"])
            self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT)

    def test_reused_directory_refuses_without_changing_retained_file(self):
        with self.scratch() as (directory, context, _):
            raw = self.execute(context)
            before = (directory / "allowed-copy.txt").stat()
            with self.assertRaises(FileExistsError):
                self.execute(context, {**self.request, "mode": "instrumented"})
            after = (directory / "allowed-copy.txt").stat()
            self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                             (after.st_ino, after.st_mtime_ns, after.st_ctime_ns))
            self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT)
            self.verify(raw, context)

    def test_consumer_is_independent_and_rejects_forged_output(self):
        with self.scratch() as (_, context, _):
            raw = self.execute(context)
            with patch.object(producer, "_retained_identity", side_effect=AssertionError), \
                 patch.object(tasks, "execute_reference_task", side_effect=AssertionError), \
                 patch.object(tasks, "_guard_file", side_effect=AssertionError), \
                 patch.object(tasks, "_guard_directory", side_effect=AssertionError):
                self.assertTrue(self.verify(raw, context)["semantics"]["completed"])
            receipt = json.loads(raw)
            receipt["observation"]["result"]["output"]["readback_equal"] = False
            with self.assertRaisesRegex(ValueError, "BINDING_OR_OUTPUT"):
                self.verify(canonical_json(receipt), context)

    def test_symlink_hardlink_and_nonregular_retention_refuse(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), self.scratch() as (directory, context, _):
                raw = self.execute(context)
                target = directory / "allowed-copy.txt"
                # Test-only adversarial mutation of its disposable scratch fixture.
                if kind == "hardlink":
                    os.link(target, directory / "alias")
                else:
                    target.rename(directory / "original")
                    if kind == "symlink":
                        target.symlink_to(directory / "original")
                    else:
                        os.mkfifo(target, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    self.verify(raw, context)
                self.assertTrue(target.exists())

    def test_same_bytes_inode_replacement_refuses(self):
        with self.scratch() as (directory, context, _):
            raw = self.execute(context)
            target = directory / "allowed-copy.txt"
            target.rename(directory / "original")
            target.write_bytes(INPUT)
            target.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "FILE_CHANGED"):
                self.verify(raw, context)
            self.assertEqual(target.read_bytes(), INPUT)

    def test_directory_and_fixture_final_guard_changes_refuse(self):
        with self.scratch() as (directory, context, held):
            raw = self.execute(context)
            directory.chmod(0o750)
            with self.assertRaisesRegex(ValueError, "DIRECTORY_CHANGED"):
                self.verify(raw, context)
            directory.chmod(0o700)  # Restore only test-owned scratch permissions.
            held.guard.side_effect = ValueError("fixture changed")
            with self.assertRaisesRegex(ValueError, "fixture changed"):
                self.verify(raw, context)
            os.fstat(context["copy_directory_fd"])
        with self.scratch() as (directory, context, held):
            raw = self.execute(context)
            original_read = os.read
            for primary_failure in (False, True):
                held.guard.side_effect = None

                def read_then_arm_final_guard(fd, size):
                    copied = original_read(fd, size)
                    self.assertEqual(copied, INPUT)
                    # Fail the consumer's final guard only; fixture exit succeeds.
                    held.guard.side_effect = [ValueError("final fixture changed"), None]
                    if primary_failure:
                        raise OSError("primary after read")
                    return copied

                with patch.object(consumer.os, "read", side_effect=read_then_arm_final_guard) as read:
                    if primary_failure:
                        with self.assertRaisesRegex(OSError, "primary after read") as caught:
                            self.verify(raw, context)
                        self.assertIn("COPY_VERIFY_FINAL_CUSTODY_OR_CLOSE_FAILED", caught.exception.__notes__)
                    else:
                        with self.assertRaisesRegex(ValueError, "COPY_VERIFY_FINAL_CUSTODY_OR_CLOSE_FAILED"):
                            self.verify(raw, context)
                    read.assert_called_once()
                os.fstat(context["copy_directory_fd"])
                self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT)

    def test_content_short_extra_and_post_read_metadata_changes_refuse(self):
        with self.scratch() as (directory, context, _):
            raw = self.execute(context)
            for readback in (INPUT[:-1], INPUT + b"x", b"X" + INPUT[1:]):
                with patch.object(consumer.os, "read", return_value=readback):
                    with self.assertRaisesRegex(ValueError, "CONTENT_CHANGED"):
                        self.verify(raw, context)
            original_read = os.read

            def changed(fd, size):
                data = original_read(fd, size)
                (directory / "allowed-copy.txt").chmod(0o640)
                return data

            with patch.object(consumer.os, "read", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "FILE_CHANGED"):
                    self.verify(raw, context)

    def test_close_failure_refuses_and_preserves_primary_error_and_caller_fd(self):
        with self.scratch() as (_, context, _):
            raw = self.execute(context)
            original_close = os.close

            def close_then_report_failure(fd):
                self.assertNotEqual(fd, context["copy_directory_fd"])
                original_close(fd)
                raise OSError("injected close report")

            with patch.object(consumer.os, "close", side_effect=close_then_report_failure):
                with self.assertRaisesRegex(ValueError, "FINAL_CUSTODY_OR_CLOSE_FAILED"):
                    self.verify(raw, context)
            with patch.object(consumer.os, "close", side_effect=close_then_report_failure), \
                 patch.object(consumer.os, "read", side_effect=OSError("primary read")):
                with self.assertRaisesRegex(OSError, "primary read") as caught:
                    self.verify(raw, context)
            self.assertIn("COPY_VERIFY_FINAL_CUSTODY_OR_CLOSE_FAILED", caught.exception.__notes__)
            os.fstat(context["copy_directory_fd"])
        with self.scratch() as (directory, context, _):
            original_dup, original_close = os.dup, os.close
            duplicates, failed_closes, events = [], [], []

            def record_duplicate(fd):
                duplicate = original_dup(fd)
                duplicates.append(duplicate)
                return duplicate

            def fail_producer_close_only(fd):
                self.assertNotEqual(fd, context["copy_directory_fd"])
                original_close(fd)
                if fd == duplicates[0]:
                    self.assertEqual(events, ["TASK_ACCEPTED", "TASK_COMPLETED"])
                    failed_closes.append(fd)
                    raise OSError("producer duplicate close report")

            with patch.object(producer.os, "dup", side_effect=record_duplicate), \
                 patch.object(producer.os, "close", side_effect=fail_producer_close_only), \
                 patch.object(tasks, "execute_reference_task", wraps=tasks.execute_reference_task) as task:
                with self.assertRaisesRegex(ValueError, "^COPY_FINAL_CUSTODY_OR_CLOSE_FAILED$"):
                    self.execute(context, mark=lambda name: events.append(name) or self.boundaries[name])
                task.assert_called_once()
            self.assertEqual(len(duplicates), 2)
            self.assertEqual(failed_closes, [duplicates[0]])
            self.assertEqual(events, ["TASK_ACCEPTED", "TASK_COMPLETED"])
            self.assertEqual((directory / "allowed-copy.txt").read_bytes(), INPUT)
            os.fstat(context["copy_directory_fd"])

    def test_invalid_marks_canonical_bytes_and_boolean_metadata_refuse(self):
        with self.scratch() as (_, context, _):
            raw = self.execute(context)
            for boundaries in ({"TASK_ACCEPTED": True, "TASK_COMPLETED": 20},
                               {"TASK_ACCEPTED": 20, "TASK_COMPLETED": 10}):
                with self.assertRaises(ValueError):
                    self.verify(raw, context, boundaries=boundaries)
            for malformed in (b"null", b"{}", b"\xff", raw + b"\n", b"x" * 65537):
                with self.assertRaises(ValueError):
                    self.verify(malformed, context)
            receipt = json.loads(raw)
            receipt["observation"]["retained_file"]["identity"]["nlink"] = True
            with self.assertRaisesRegex(ValueError, "FILE_IDENTITY_REQUIRED"):
                self.verify(canonical_json(receipt), context)

    def test_pair_mode_and_independent_directory_context_cannot_be_swapped(self):
        with self.scratch() as (_, first, _), self.scratch() as (_, second, _):
            raw = self.execute(first)
            self.execute(second, {**self.request, "mode": "instrumented"})
            for request, context in ((self.request, second),
                                     ({**self.request, "mode": "instrumented"}, first),
                                     ({**self.request, "pair_id": "p3-lab-p077"}, first)):
                with self.assertRaisesRegex(ValueError, "BINDING_OR_OUTPUT"):
                    self.verify(raw, context, request)
