"""Archive custody only: inert private files, no process launch, guest or firmware."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from scripts import pi_core_owner_archive as archive
from scripts.build_pi_core_linux import BuildError, sha256


class OwnerArchive(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.uid = str(uuid4())
        self.fixture, self.ledger, self.dest = (self.base / n for n in ("fixture", "ledger", "archive"))
        for p in (self.fixture, self.ledger, self.dest):
            p.mkdir(0o700)
        self.attempt = self.fixture / self.uid
        self.watch = self.ledger / self.uid
        self.exported = self.dest / self.uid

    @staticmethod
    def file(path, raw, mode=0o400):
        with path.open("xb") as out:
            out.write(raw)
        path.chmod(mode)

    def export(self):
        return archive.export_owner_archive(self.fixture, self.ledger, self.dest, self.uid)

    def read(self, digest, portable=False):
        return archive.read_owner_archive(self.dest, self.uid, digest, portable=portable)

    def test_exact_original_bytes_private_seals_and_inert_raw(self):
        self.attempt.mkdir(0o700)
        self.watch.mkdir(0o700)
        src = {"owner-events.jsonl": b'{"unit":"inert"}\r\n', "owner-terminal.json": b'{ "a" : 2 }',
               "serial.raw": b"\0\xff\r\n", "watchdog.json.owner-arm": b"raw arm", "watchdog.json": b"raw terminal"}
        for n, raw in src.items():
            self.file((self.attempt if n in archive.OWNER else self.watch) / n, raw)
        digest = self.export()
        doc, payload = self.read(digest)
        self.assertEqual(src, payload)
        for name, data in src.items():
            record = doc["files"][name]
            self.assertEqual(record["sha256"], sha256(data))
            self.assertEqual(record["source"]["mode"], 0o400)
            self.assertEqual(record["export"]["ino"], (self.exported / name).stat().st_ino)
        self.assertEqual(doc["attempt_identity"]["ino"], self.attempt.stat().st_ino)
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertEqual(src, self.read(digest)[1])
        self.assertFalse(doc["cleanup_authorized"] or doc["phase3_exit_eligible"])

    def test_absence_is_distinct_from_unsealed_partial_and_unsupplied_fixture(self):
        self.watch.mkdir(0o700)
        self.file(self.watch / "watchdog.json.started", b"partial\x00", 0o600)
        digest = archive.export_owner_archive(None, self.ledger, self.dest, self.uid)
        doc, payload = self.read(digest)
        self.assertIsNone(doc["fixture_identity"])
        self.assertIsNone(doc["attempt_identity"])
        self.assertEqual(payload, {"watchdog.json.started": b"partial\x00"})
        self.assertEqual(doc["files"]["watchdog.json.started"]["source"]["mode"], 0o600)
        other = str(uuid4())
        d = archive.export_owner_archive(self.fixture, self.ledger, self.dest, other)
        empty, no_bytes = archive.read_owner_archive(self.dest, other, d)
        self.assertEqual(no_bytes, {})
        self.assertEqual(empty["fixture_identity"]["ino"], self.fixture.stat().st_ino)
        self.assertIsNone(empty["attempt_identity"])
        self.assertIsNone(empty["ledger_attempt_identity"])

    def test_unknown_oversize_and_linked_inputs_are_not_copied(self):
        self.attempt.mkdir(0o700)
        self.watch.mkdir(0o700)
        self.file(self.fixture / "efi-vars.fd", b"unrelated")
        (self.watch / "no-target").mkdir()
        with self.assertRaises(BuildError):
            archive.export_owner_archive(None, self.ledger, self.dest, self.uid)
        (self.watch / "no-target").rmdir()
        p = self.attempt / "owner-terminal.json"
        for kind in ("symlink", "hardlink", "oversize", "public"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    p.symlink_to(self.fixture / "efi-vars.fd")
                elif kind == "hardlink":
                    os.link(self.fixture / "efi-vars.fd", p)
                else:
                    self.file(p, bytes(32769) if kind == "oversize" else b"x", 0o644 if kind == "public" else 0o400)
                with self.assertRaises((OSError, BuildError)):
                    self.export()
                self.assertFalse(self.exported.exists())
                p.unlink()
        self.assertEqual((self.fixture / "efi-vars.fd").read_bytes(), b"unrelated")

    def test_overlap_symlinked_root_and_dangling_source_leaf_refused(self):
        nested = self.ledger / "other"
        nested.mkdir(0o700)
        linked = self.base / "linked"
        linked.symlink_to(self.fixture)
        for fixture, destination in ((self.fixture, nested), (self.ledger, self.dest), (linked, self.dest)):
            with self.subTest(fixture=fixture, destination=destination), self.assertRaises((OSError, BuildError)):
                archive.export_owner_archive(fixture, self.ledger, destination, self.uid)
        self.attempt.symlink_to(self.base / "missing")
        with self.assertRaises((BuildError, OSError)):
            self.export()
        self.assertFalse(self.exported.exists())

    def test_source_substitution_retains_partial_export_and_refuses_retry(self):
        self.attempt.mkdir(0o700)
        path = self.attempt / "serial.raw"
        self.file(path, b"same bytes")
        original = archive.custody._write
        def replacing(fd, name, raw):
            row = original(fd, name, raw)
            if name == "serial.raw":
                replacement = self.fixture / "incoming"
                self.file(replacement, raw)
                os.replace(replacement, path)
            return row
        with patch.object(archive.custody, "_write", replacing), self.assertRaises(BuildError):
            self.export()
        self.assertFalse((self.exported / archive.MANIFEST).exists())
        self.assertEqual((self.exported / "serial.raw").read_bytes(), path.read_bytes())
        with self.assertRaises(FileExistsError):
            self.export()

    def test_external_digest_required_and_relocated_copy_reverified_without_inodes(self):
        self.watch.mkdir(0o700)
        self.file(self.watch / "refusal.stderr", b"exact stderr\n")
        digest = self.export()
        expected = self.read(digest)
        backup = self.base / "backup"
        shutil.copytree(self.dest, backup)
        for root, auth, portable in ((self.dest, "", False), (self.dest, "f"*64, True), (backup, digest, False)):
            with self.subTest(root=root, auth=auth, portable=portable), self.assertRaises(BuildError):
                archive.read_owner_archive(root, self.uid, auth, portable=portable)
        self.assertEqual(archive.read_owner_archive(backup, self.uid, digest, portable=True), expected)
        for root, portable in ((self.dest, False), (backup, True)):
            p = root / self.uid / "refusal.stderr"
            p.chmod(0o600)
            p.write_bytes(b"wrong stderr\n")
            p.chmod(0o400)
            with self.assertRaises(BuildError):
                archive.read_owner_archive(root, self.uid, digest, portable=portable)
