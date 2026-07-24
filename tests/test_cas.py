from __future__ import annotations

from io import BytesIO
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from aragorn.cas import CAS, CASError


class CASTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "cas"
        self.cas = CAS(self.root)

    def test_root_is_private_and_rejects_unsafe_state(self) -> None:
        private_root = Path(self.temporary_directory.name) / "private"
        CAS(private_root)
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(private_root).st_mode))

        shared_root = Path(self.temporary_directory.name) / "shared"
        shared_root.mkdir(mode=0o700)
        shared_root.chmod(0o750)
        with self.assertRaisesRegex(CASError, "group or other"):
            CAS(shared_root)

        file_root = Path(self.temporary_directory.name) / "file"
        file_root.write_bytes(b"not a directory")
        with self.assertRaisesRegex(CASError, "not a directory"):
            CAS(file_root)

        linked_root = Path(self.temporary_directory.name) / "linked-root"
        linked_root.symlink_to(private_root, target_is_directory=True)
        with self.assertRaisesRegex(CASError, "must not be a symlink"):
            CAS(linked_root)

        poisoned_root = Path(self.temporary_directory.name) / "poisoned"
        poisoned_root.mkdir(mode=0o700)
        outside = Path(self.temporary_directory.name) / "outside"
        outside.mkdir()
        (poisoned_root / "blobs").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(CASError, "must be a real directory"):
            CAS(poisoned_root)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership check")
    def test_root_requires_current_user_ownership(self) -> None:
        owned_root = Path(self.temporary_directory.name) / "owned"
        owned_root.mkdir(mode=0o700)
        with mock.patch("aragorn.cas.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(CASError, "not owned"):
                CAS(owned_root)

    def test_put_is_idempotent_and_honors_read_only_mode(self) -> None:
        payload = b"the exact reviewed bytes"
        first = self.cas.put(BytesIO(payload), max_bytes=len(payload))
        second = self.cas.put(BytesIO(payload), max_bytes=len(payload))

        self.assertEqual(first, second)
        self.assertEqual(payload, self.cas.read(first))
        self.cas.verify(first, max_bytes=len(payload))
        with self.assertRaisesRegex(CASError, "exceeds max_bytes"):
            self.cas.read(first, max_bytes=1)
        with self.assertRaisesRegex(CASError, "exceeds max_bytes"):
            self.cas.verify(first, max_bytes=1)
        self.assertEqual(
            1,
            len(list((self.root / "blobs" / "sha256").glob("??/*"))),
        )
        with self.assertRaisesRegex(CASError, "read-only"):
            CAS(self.root, read_only=True).put(BytesIO(payload), max_bytes=len(payload))
        with self.assertRaisesRegex(CASError, "exceeds max_bytes"):
            self.cas.put(BytesIO(b"oversized"), max_bytes=1)

    def test_put_expected_never_publishes_mismatched_content(self) -> None:
        expected_content = b"expected"
        substituted_content = b"attacker"
        expected_digest = "sha256:" + hashlib.sha256(expected_content).hexdigest()
        substituted_digest = "sha256:" + hashlib.sha256(substituted_content).hexdigest()

        with self.assertRaisesRegex(CASError, "does not match expected"):
            self.cas.put_expected(
                BytesIO(substituted_content),
                expected_digest=expected_digest,
                max_bytes=len(substituted_content),
            )

        for digest in (expected_digest, substituted_digest):
            with self.assertRaises(CASError):
                self.cas.verify(digest)
        self.assertEqual(
            list((self.root / "blobs" / "sha256").glob("??/*")),
            [],
        )

    def test_digest_prefix_symlink_is_rejected(self) -> None:
        payload = b"x"
        prefix = hashlib.sha256(payload).hexdigest()[:2]
        outside = Path(self.temporary_directory.name) / "outside-prefix"
        outside.mkdir()
        prefix_path = self.root / "blobs" / "sha256" / prefix
        prefix_path.symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(CASError, "must be a real directory"):
            self.cas.put(BytesIO(payload), max_bytes=len(payload))

        self.assertEqual(list(outside.iterdir()), [])

    def test_read_and_materialize_reject_corruption(self) -> None:
        digest = self.cas.put(BytesIO(b"approved"), max_bytes=8)
        hex_digest = digest.removeprefix("sha256:")
        blob = self.root / "blobs" / "sha256" / hex_digest[:2] / hex_digest[2:]
        blob.chmod(0o600)
        blob.write_bytes(b"tampered")

        with self.assertRaisesRegex(CASError, "digest verification"):
            self.cas.read(digest)
        destination = Path(self.temporary_directory.name) / "rejected"
        with self.assertRaisesRegex(CASError, "digest verification"):
            self.cas.materialize(
                digest, destination, root=Path(self.temporary_directory.name)
            )
        self.assertFalse(os.path.lexists(destination))

    def test_streaming_read_bound_rejects_blob_growth_after_open(self) -> None:
        payload = b"bounded"
        digest = self.cas.put(BytesIO(payload), max_bytes=len(payload))
        hex_digest = digest.removeprefix("sha256:")
        blob = self.root / "blobs" / "sha256" / hex_digest[:2] / hex_digest[2:]
        mutated = False

        def mutate_after_first_chunk(_chunk: bytes) -> None:
            nonlocal mutated
            if mutated:
                return
            mutated = True
            blob.chmod(0o600)
            with blob.open("ab") as stream:
                stream.write(b"x")

        with mock.patch("aragorn.cas._CHUNK_SIZE", 2):
            with self.assertRaisesRegex(CASError, "exceeds max_bytes"):
                self.cas._stream_verified(
                    digest,
                    mutate_after_first_chunk,
                    max_bytes=len(payload),
                )

        self.assertTrue(mutated)

    def test_materialize_creates_verified_file_without_overwriting(self) -> None:
        payload = b"verified content"
        digest = self.cas.put(BytesIO(payload), max_bytes=len(payload))
        destination = Path(self.temporary_directory.name) / "installed"

        materialization_root = Path(self.temporary_directory.name)
        self.assertEqual(
            destination,
            self.cas.materialize(digest, destination, root=materialization_root),
        )
        self.assertEqual(payload, destination.read_bytes())
        with self.assertRaisesRegex(CASError, "already exists"):
            self.cas.materialize(digest, destination, root=materialization_root)

        symlink = Path(self.temporary_directory.name) / "symlink"
        symlink.symlink_to(Path(self.temporary_directory.name) / "missing")
        with self.assertRaisesRegex(CASError, "already exists"):
            self.cas.materialize(digest, symlink, root=materialization_root)

        real_parent = Path(self.temporary_directory.name) / "real-parent"
        real_parent.mkdir()
        linked_parent = Path(self.temporary_directory.name) / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(CASError, "symlink"):
            self.cas.materialize(
                digest, linked_parent / "installed", root=materialization_root
            )
        self.assertFalse(os.path.lexists(real_parent / "installed"))

        nested = real_parent / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(CASError, "symlink"):
            self.cas.materialize(
                digest,
                linked_parent / "nested" / "installed",
                root=materialization_root,
            )
        self.assertFalse(os.path.lexists(nested / "installed"))


if __name__ == "__main__":
    unittest.main()
