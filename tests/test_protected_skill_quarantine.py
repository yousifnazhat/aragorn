from __future__ import annotations

import fcntl
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from aragorn import protected_skill_quarantine as subject
from aragorn.oci_worker_protocol import canonical_json

_SKILL = "sha256:" + "a" * 64
_SNAPSHOT = "sha256:" + "b" * 64
_OTHER = "sha256:" + "c" * 64


@contextmanager
def _fixture():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield root, fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _publish(fd, skill=_SKILL, snapshot=_SNAPSHOT):
    return subject.publish_quarantine_at(fd, skill, snapshot, expected_uid=os.geteuid())


def _read(fd, skill=_SKILL):
    return subject.read_quarantine_at(fd, skill, expected_uid=os.geteuid())


class ProtectedSkillQuarantineTests(unittest.TestCase):
    def test_absence_publication_readback_and_permanent_first_record(self):
        with _fixture() as (root, fd):
            self.assertIsNone(_read(fd))
            subject.require_not_quarantined_at(fd, _SKILL, expected_uid=os.geteuid())
            self.assertEqual(list(root.iterdir()), [])
            record = _publish(fd)
            path = root / subject._name(_SKILL)
            self.assertEqual(path.read_bytes(), canonical_json(record))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(_read(fd), record)
            with self.assertRaisesRegex(
                subject.ProtectedSkillQuarantineError, "quarantined"
            ):
                subject.require_not_quarantined_at(
                    fd, _SKILL, expected_uid=os.geteuid()
                )
            self.assertIsNone(_read(fd, _OTHER))
            original = path.stat()
            self.assertEqual(_publish(fd, snapshot=_OTHER), record)
            self.assertEqual(path.stat().st_ino, original.st_ino)
            self.assertEqual(path.stat().st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(list(root.iterdir()), [path])

    def test_invalid_record_content_and_custody_fail_closed_without_replacement(self):
        mutations = (
            "malformed",
            "noncanonical",
            "duplicate",
            "array",
            "mode",
            "empty",
            "oversize",
            "symlink",
            "hardlink",
            "fifo",
            "directory",
            {"schema": "wrong"},
            {"authority": "PASS"},
            {"skill_digest": _OTHER},
            {"revocation_snapshot_digest": True},
            {"revocation_snapshot_digest": "sha256:+" + "b" * 63},
            {"extra": None},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), _fixture() as (root, fd):
                record = _publish(fd)
                path = root / subject._name(_SKILL)
                path.chmod(0o600)
                if isinstance(mutation, dict):
                    path.write_bytes(canonical_json({**record, **mutation}))
                elif mutation in {"symlink", "hardlink", "fifo", "directory"}:
                    if mutation == "hardlink":
                        os.link(path, root / "second-name")
                    else:
                        path.unlink()
                        if mutation == "symlink":
                            path.symlink_to(root / "missing")
                        elif mutation == "fifo":
                            os.mkfifo(path, 0o444)
                        else:
                            path.mkdir(mode=0o444)
                else:
                    path.write_bytes(
                        {
                            "malformed": b"{",
                            "noncanonical": canonical_json(record) + b"\n",
                            "duplicate": b'{"schema":0,"schema":1}',
                            "array": b"[]",
                            "mode": canonical_json(record),
                            "empty": b"",
                            "oversize": b"x" * (subject._MAX_BYTES + 1),
                        }[mutation]
                    )
                if not isinstance(mutation, str) or mutation not in {
                    "mode",
                    "symlink",
                    "fifo",
                    "directory",
                }:
                    path.chmod(0o444)
                original = path.lstat()
                for operation in (lambda: _read(fd), lambda: _publish(fd)):
                    with self.assertRaises(subject.ProtectedSkillQuarantineError):
                        operation()
                self.assertEqual(
                    subject._file_identity(path.lstat()),
                    subject._file_identity(original),
                )

    def test_invalid_identity_and_owner_never_create_records(self):
        with _fixture() as (root, fd):
            for skill in (
                True,
                "../escape",
                "sha256:" + "A" * 64,
                "",
                "sha256:+" + "b" * 63,
                "sha256: " + "b" * 63,
                "sha256:" + "b" * 31 + "_" + "b" * 32,
            ):
                with (
                    self.subTest(skill=skill),
                    self.assertRaises(subject.ProtectedSkillQuarantineError),
                ):
                    _publish(fd, skill)
                with self.assertRaises(subject.ProtectedSkillQuarantineError):
                    _publish(fd, snapshot=skill)
            for invalid_fd, uid in (
                (True, os.geteuid()),
                (fd, True),
                (fd, os.geteuid() + 1),
            ):
                with (
                    self.subTest(fd=invalid_fd, uid=uid),
                    self.assertRaises(subject.ProtectedSkillQuarantineError),
                ):
                    subject.read_quarantine_at(invalid_fd, _SKILL, expected_uid=uid)
            with self.assertRaises(subject.ProtectedSkillQuarantineError):
                _publish(fd, snapshot="invalid")
            self.assertEqual(list(root.iterdir()), [])

    def test_read_replacement_and_partial_publication_never_report_success(self):
        with _fixture() as (root, fd):
            _publish(fd)
            path = root / subject._name(_SKILL)
            read = os.read

            def replace_after_read(descriptor, count):
                raw = read(descriptor, count)
                path.unlink()
                path.write_bytes(raw)
                path.chmod(0o444)
                return raw

            with (
                patch.object(subject.os, "read", side_effect=replace_after_read),
                self.assertRaises(subject.ProtectedSkillQuarantineError),
            ):
                _read(fd)
        for phase in ("before_link", "after_link", "directory_sync", "idempotent_sync"):
            with self.subTest(phase=phase), _fixture() as (root, fd):
                link, fsync = os.link, os.fsync
                if phase == "idempotent_sync":
                    _publish(fd)

                def fail_link(*args, phase=phase, link=link, **kwargs):
                    if phase == "after_link":
                        link(*args, **kwargs)
                    raise OSError("interrupted link")

                def fail_directory_sync(descriptor, fd=fd, fsync=fsync):
                    if descriptor == fd:
                        raise OSError("directory sync failed")
                    fsync(descriptor)

                failure = (
                    patch.object(subject.os, "link", side_effect=fail_link)
                    if phase.endswith("link")
                    else patch.object(
                        subject.os, "fsync", side_effect=fail_directory_sync
                    )
                )
                with failure, self.assertRaises(subject.ProtectedSkillQuarantineError):
                    _publish(fd)
                self.assertFalse(
                    any(
                        p.name.startswith(".aragorn-skill-denial-staging-")
                        for p in root.iterdir()
                    )
                )
                if phase == "before_link":
                    self.assertIsNone(_read(fd))
                else:
                    self.assertIsNotNone(_read(fd))
                    with self.assertRaises(subject.ProtectedSkillQuarantineError):
                        subject.require_not_quarantined_at(
                            fd, _SKILL, expected_uid=os.geteuid()
                        )

    def test_staging_and_post_publication_close_failures_are_not_success(self):
        for phase in ("write", "file_sync", "close"):
            with self.subTest(phase=phase), _fixture() as (root, fd):
                create, close = subject.create_exclusive_file_at, os.close
                staged = []

                def remember(*args, create=create, staged=staged, **kwargs):
                    result = create(*args, **kwargs)
                    staged.append(result[1])
                    return result

                def fail_close(descriptor, close=close, staged=staged):
                    close(descriptor)
                    if descriptor in staged:
                        raise OSError("closed staging descriptor with error")

                failure = (
                    patch.object(
                        subject, "write_all", side_effect=OSError("write failed")
                    )
                    if phase == "write"
                    else patch.object(
                        subject.os, "fsync", side_effect=OSError("sync failed")
                    )
                    if phase == "file_sync"
                    else patch.object(subject.os, "close", side_effect=fail_close)
                )
                with (
                    patch.object(
                        subject, "create_exclusive_file_at", side_effect=remember
                    ),
                    failure,
                    self.assertRaises((subject.ProtectedSkillQuarantineError, OSError)),
                ):
                    _publish(fd)
                if phase == "close":
                    self.assertIsNotNone(_read(fd))
                    self.assertEqual(
                        [p.name for p in root.iterdir()], [subject._name(_SKILL)]
                    )
                else:
                    self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
