"""Inert filesystem fixtures only; no host runner, VM, firmware or clock simulation."""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from scripts.build_pi_core_linux import BuildError, canonical, sha256
from scripts.pi_core_host_evidence_export import WATCH, cleanup_attempt, export_attempt, read_export


class EvidenceExport(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.parent, self.dest = self.root / "fixture", self.root / "export"
        self.parent.mkdir(0o700)
        self.dest.mkdir(0o700)
        self.name = str(uuid4())
        self.attempt = self.parent / self.name
        self.attempt.mkdir(0o700)
        s = self.parent.stat()
        self.binding = canonical({"schema": "aragorn/b44-host-binding/v1", "mode": "preview",
                                  "fixture_identity": {"dev": s.st_dev, "ino": s.st_ino},
                                  "capture": {"attempt_start_ns": 3, "record_end_ns": 9, "clock": "CLOCK_MONOTONIC_RAW"},
                                  "runner_sha256": "a" * 64, "attempt_uuid": self.name, "boot_observed": False,
                                  "phase3_exit_eligible": False, "vm_created": False})
        self.seal(self.attempt / "binding.json", self.binding)
        self.seal(self.attempt / "serial.raw", b"")
        self.replay = {"status": "matched_no_boot_binding", "attempt_uuid": self.name,
                       "binding_sha256": sha256(self.binding), "runner_sha256": "a" * 64,
                       "boot_observed": False, "phase3_exit_eligible": False}
        self.watch = {"schema": WATCH, "attempt_uuid": self.name, "outcome": "child-exited", "child_reaped": True,
                      "child_returncode": 0, "interrupted": False, "host_kill_requested": False, "graceful": None,
                      "force": None, "vm_stopped_verified": False, "start_raw_ns": 1, "child_pid": 123,
                      "clock": "CLOCK_MONOTONIC_RAW", "interrupt_signal": None, "host_kill_raw_ns": None,
                      "exit_observed_raw_ns": 10, "run_deadline_raw_ns": 180_000_000_001,
                      "graceful_deadline_raw_ns": 195_000_000_001, "force_deadline_raw_ns": 210_000_000_001,
                      "effective_deadlines_raw_ns": [180_000_000_001, 195_000_000_001, 210_000_000_001]}

    @staticmethod
    def seal(path, data):
        path.write_bytes(data)
        path.chmod(0o400)

    def export(self):
        return export_attempt(self.attempt, self.dest, self.watch, replay_result=self.replay)

    def test_receipt_ack_and_scoped_cleanup(self):
        firmware = self.parent / "efi-vars.fd"
        self.seal(firmware, b"unrelated")
        digest = self.export()
        out = self.dest / self.name
        self.assertEqual((out / "binding.json").read_bytes(), self.binding)
        self.assertEqual((out / "watchdog.json").read_bytes(), canonical(self.watch))
        doc = read_export(self.dest, self.name, digest)
        self.assertIs(doc["eligible_for_local_evidence_cleanup"], True)
        self.assertTrue(self.attempt.is_dir())
        for ack in (None, "", "0" * 64):
            with self.subTest(ack=ack), self.assertRaises(BuildError):
                cleanup_attempt(self.attempt, self.dest, ack)
        result = cleanup_attempt(self.attempt, self.dest, digest)
        self.assertFalse(self.attempt.exists())
        self.assertEqual(result["removed_evidence"], ["binding.json", "serial.raw"])
        self.assertEqual(firmware.read_bytes(), b"unrelated")
        self.assertEqual(read_export(self.dest, self.name, digest), doc)
        self.assertIs(result["vm_stopped_verified"], False)

    def test_failure_or_partial_captures_archived_only(self):
        (self.attempt / "binding.json").unlink()
        (self.attempt / "serial.raw").unlink()
        serial = b"\0\xffpartial\r\n"
        (self.attempt / "serial.raw").write_bytes(serial)
        (self.attempt / "serial.raw").chmod(0o600)
        self.seal(self.attempt / "binding-failure.json", b'{"retained":true}')
        digest = export_attempt(self.attempt, self.dest, self.watch)
        self.assertIs(read_export(self.dest, self.name, digest)["eligible_for_local_evidence_cleanup"], False)
        with self.assertRaises(BuildError):
            cleanup_attempt(self.attempt, self.dest, digest)
        self.assertEqual((self.dest / self.name / "serial.raw").read_bytes(), serial)
        self.assertEqual((self.attempt / "serial.raw").read_bytes(), serial)
        self.assertTrue((self.attempt / "binding-failure.json").exists())

    def test_wrong_replay_reaped_late_or_forced_child_not_cleanable(self):
        for i, (watch_delta, replay_delta) in enumerate((
            ({"force": {"sent": True}}, {}), ({"child_reaped": False}, {}), ({"host_kill_requested": True}, {}),
            ({"exit_observed_raw_ns": 180_000_000_001}, {}), ({"exit_observed_raw_ns": 8}, {}),
            ({"error_type": "RuntimeError"}, {}), ({"run_deadline_raw_ns": 180_000_000_002}, {}),
            ({}, {"binding_sha256": "0" * 64}), ({}, {"attempt_uuid": str(uuid4())}),
        )):
            with self.subTest(i=i):
                dest = self.root / f"hold{i}"
                dest.mkdir(0o700)
                digest = export_attempt(self.attempt, dest, dict(self.watch, **watch_delta),
                                        replay_result=dict(self.replay, **replay_delta))
                self.assertIs(read_export(dest, self.name, digest)["eligible_for_local_evidence_cleanup"], False)
                with self.assertRaises(BuildError):
                    cleanup_attempt(self.attempt, dest, digest)
        self.assertEqual(set(os.listdir(self.attempt)), {"binding.json", "serial.raw"})
        # Even a separately replayed target-store binding is outside local-preview cleanup authority.
        target = self.binding.replace(b'"mode":"preview"', b'"mode":"bind-existing"')
        (self.attempt / "binding.json").unlink()
        self.seal(self.attempt / "binding.json", target)
        digest = export_attempt(self.attempt, self.dest, self.watch,
                                replay_result=dict(self.replay, binding_sha256=sha256(target)))
        with self.assertRaises(BuildError):
            cleanup_attempt(self.attempt, self.dest, digest)
        self.assertEqual((self.attempt / "binding.json").read_bytes(), target)

    def test_conflicting_destination_or_unknown_entry_never_removed(self):
        (self.attempt / "notes").write_bytes(b"operator owned")
        with self.assertRaises(BuildError):
            self.export()
        self.assertFalse((self.dest / self.name).exists())
        (self.attempt / "notes").unlink()
        digest = self.export()
        with self.assertRaises(FileExistsError):
            self.export()
        (self.attempt / "unknown-directory").mkdir()
        with self.assertRaises(BuildError):
            cleanup_attempt(self.attempt, self.dest, digest)
        self.assertTrue((self.attempt / "binding.json").exists())
        self.assertTrue((self.attempt / "serial.raw").exists())
        self.assertTrue((self.attempt / "unknown-directory").exists())

    def test_mutated_source_and_substituted_inode_leave_other_entries(self):
        digest = self.export()
        raw = self.attempt / "serial.raw"
        replacement = self.root / "replacement"
        self.seal(replacement, b"")
        os.replace(replacement, raw)
        for data in (b"", b"changed"):
            if data:
                raw.chmod(0o600)
                self.seal(raw, data)
            with self.subTest(data=data), self.assertRaises(BuildError):
                cleanup_attempt(self.attempt, self.dest, digest)
            self.assertEqual((self.attempt / "binding.json").read_bytes(), self.binding)
            self.assertEqual(raw.read_bytes(), data)

    def test_changed_export_refuses_cleanup(self):
        digest = self.export()
        raw = self.dest / self.name / "serial.raw"
        raw.chmod(0o600)
        self.seal(raw, b"changed")
        with self.assertRaises(BuildError):
            read_export(self.dest, self.name, digest)
        with self.assertRaises(BuildError):
            cleanup_attempt(self.attempt, self.dest, digest)
        self.assertEqual(set(os.listdir(self.attempt)), {"binding.json", "serial.raw"})

    def test_aliased_roots_links_or_foreign_watchdog_refused(self):
        unsafe = self.parent / "export"
        unsafe.mkdir(0o700)
        link = self.root / "alias"
        link.symlink_to(self.dest)
        for dest in (self.parent, unsafe, self.root, link):
            with self.subTest(dest=dest), self.assertRaises((OSError, BuildError)):
                export_attempt(self.attempt, dest, self.watch)
        with self.assertRaises(BuildError):
            export_attempt(self.attempt, self.dest, dict(self.watch, attempt_uuid=str(uuid4())))
        with self.assertRaises(BuildError):
            read_export(self.dest, "00000000-0000-0000-0000-000000000000", "0" * 64)
        raw = self.attempt / "serial.raw"
        raw.unlink()
        raw.symlink_to(self.attempt / "binding.json")
        with self.assertRaises((OSError, BuildError)):
            self.export()
        raw.unlink()
        os.link(self.attempt / "binding.json", raw)
        with self.assertRaises(BuildError):
            self.export()
        self.assertEqual(os.listdir(self.dest), [])
