from __future__ import annotations

import fcntl
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from aragorn import protected_install_namespace_v2 as subject
from aragorn.protected_skill_quarantine import publish_quarantine_at

_SKILL = "sha256:" + "a" * 64
_OTHER = "sha256:" + "b" * 64
_SNAPSHOT = "sha256:" + "c" * 64


@contextmanager
def _fixture():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve() / "protected"
        root.mkdir(mode=0o700)
        yield root


def _publish(root, skill=_SKILL):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return publish_quarantine_at(fd, skill, _SNAPSHOT, expected_uid=os.geteuid())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _entries(root):
    return subject.protected_root_entries(root, os.geteuid())


class ProtectedInstallNamespaceV2Tests(unittest.TestCase):
    def test_only_fully_verified_records_are_removed_from_inventory(self):
        with _fixture() as root:
            self.assertEqual(_entries(root), [])
            for name in ("unknown", ".aragorn-versions", ".aragorn-quarantined-skill"):
                (root / name).mkdir(mode=0o700)
            expected = sorted(child.name for child in root.iterdir())
            self.assertEqual(_entries(root), expected)
            _publish(root)
            _publish(root, _OTHER)
            records = {
                path.name: path.read_bytes()
                for path in root.iterdir()
                if path.name.endswith(".json")
            }
            self.assertEqual(_entries(root), expected)
            self.assertEqual(
                {name: (root / name).read_bytes() for name in records}, records
            )

    def test_malformed_names_and_present_unsafe_records_fail_closed(self):
        for suffix in ("A" * 64 + ".json", "a" * 63 + ".json", "a" * 64, "../x"):
            with self.subTest(suffix=suffix), _fixture() as root:
                name = subject._PREFIX + suffix.replace("/", "_")
                (root / name).write_bytes(b"{}")
                with self.assertRaisesRegex(
                    subject.ProtectedInstallNamespaceError, "filename is invalid"
                ):
                    _entries(root)
        for mutation in ("malformed", "mode", "symlink", "fifo", "hardlink"):
            with self.subTest(mutation=mutation), _fixture() as root:
                _publish(root)
                record = root / (subject._PREFIX + _SKILL[7:] + ".json")
                if mutation == "malformed":
                    record.chmod(0o600)
                    record.write_bytes(b"{")
                    record.chmod(0o444)
                elif mutation == "mode":
                    record.chmod(0o644)
                elif mutation == "hardlink":
                    os.link(record, root / "other-link")
                else:
                    record.unlink()
                    if mutation == "symlink":
                        record.symlink_to(root / "missing")
                    else:
                        os.mkfifo(record, 0o444)
                with self.assertRaises(subject.ProtectedInstallNamespaceError):
                    _entries(root)

    def test_owner_canonical_path_and_root_custody_are_required(self):
        with _fixture() as root:
            link = root.parent / "alias"
            link.symlink_to(root)
            for path, uid in (
                (link, os.geteuid()),
                (Path("relative"), os.geteuid()),
                (root, True),
                (root, os.geteuid() + 1),
                (root, -1),
            ):
                with (
                    self.subTest(path=path, uid=uid),
                    self.assertRaises(subject.ProtectedInstallNamespaceError),
                ):
                    subject.protected_root_entries(path, uid)
            for mode in (0o777, 0o500):
                root.chmod(mode)
                with self.assertRaises(subject.ProtectedInstallNamespaceError):
                    _entries(root)
            root.chmod(0o700)

    def test_inventory_and_record_reads_hold_shared_lock_then_release_it(self):
        with _fixture() as root:
            _publish(root)
            listdir = os.listdir
            read = subject.read_quarantine_at
            observations = []

            def require_locked():
                other = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(other)

            def list_locked(fd):
                self.assertIs(type(fd), int)
                observations.append("list")
                require_locked()
                return listdir(fd)

            def read_locked(*args, **kwargs):
                observations.append("read")
                require_locked()
                return read(*args, **kwargs)

            with (
                mock.patch.object(subject.os, "listdir", side_effect=list_locked),
                mock.patch.object(
                    subject, "read_quarantine_at", side_effect=read_locked
                ),
            ):
                self.assertEqual(_entries(root), [])
            self.assertEqual(observations, ["list", "read", "list"])
            other = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(
                    subject.ProtectedInstallNamespaceError, "cannot verify"
                ):
                    _entries(root)
                fcntl.flock(other, fcntl.LOCK_UN)
            finally:
                os.close(other)

    def test_disappearing_or_rebound_namespace_never_returns_filtered_success(self):
        for mutation in ("disappear", "add", "root-rebind", "read-error"):
            with self.subTest(mutation=mutation), _fixture() as root:
                _publish(root)
                record = root / (subject._PREFIX + _SKILL[7:] + ".json")
                read = subject.read_quarantine_at

                def race(
                    *args,
                    mutation=mutation,
                    read=read,
                    record=record,
                    root=root,
                    **kwargs,
                ):
                    if mutation == "disappear":
                        record.unlink()
                        return read(*args, **kwargs)
                    if mutation == "read-error":
                        raise OSError("injected read failure")
                    result = read(*args, **kwargs)
                    if mutation == "add":
                        (root / "new-entry").write_bytes(b"new")
                    else:
                        root.rename(root.parent / "old-protected")
                        root.mkdir(mode=0o700)
                    return result

                with (
                    mock.patch.object(subject, "read_quarantine_at", side_effect=race),
                    self.assertRaises(subject.ProtectedInstallNamespaceError),
                ):
                    _entries(root)
                actual = (
                    root.parent / "old-protected" if mutation == "root-rebind" else root
                )
                fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
