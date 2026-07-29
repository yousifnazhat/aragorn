from __future__ import annotations

import stat
import tempfile
import unittest
import warnings
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.zip_inventory import (
    ZipInventoryError,
    retain_zip_inventory,
    verify_zip_inventory,
)


def _zip(
    entries: list[tuple[str | zipfile.ZipInfo, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    shebang: bool = False,
) -> bytes:
    output = BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, mode="w", compression=compression) as archive:
            for name, content in entries:
                archive.writestr(name, content)
    raw = output.getvalue()
    return b"#!/usr/bin/env python3\n" + raw if shebang else raw


class ZipInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "cas")

    def _retain_archive(self, raw: bytes) -> str:
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def test_zip_whl_pyz_and_renamed_zip_are_magic_verified_and_replayable(
        self,
    ) -> None:
        for name, shebang, kind in (
            ("bundle.zip", False, "zip"),
            ("bundle.whl", False, "wheel"),
            ("bundle.pyz", True, "zipapp"),
            ("bundle.bin", False, "zip"),
        ):
            with self.subTest(name=name):
                raw = _zip(
                    [
                        ("package/", b""),
                        ("package/main.py", b"print('retained')\n"),
                        ("README.md", b"bounded archive\n"),
                    ],
                    shebang=shebang,
                )
                archive_digest = self._retain_archive(raw)
                inventory_digest = retain_zip_inventory(
                    self.cas,
                    archive_digest,
                    archive_name=name,
                )
                replay = verify_zip_inventory(
                    self.cas,
                    inventory_digest,
                    expected_archive_digest=archive_digest,
                    expected_archive_name=name,
                )

                self.assertEqual(replay["archive"]["kind"], kind)
                self.assertEqual(
                    replay["archive"]["prefix"],
                    "python_shebang" if shebang else "none",
                )
                self.assertEqual(replay["totals"]["files"], 2)
                self.assertEqual(replay["directories"], ["package"])
                self.assertEqual(
                    [entry["path"] for entry in replay["files"]],
                    ["README.md", "package/main.py"],
                )
                for entry in replay["files"]:
                    self.assertEqual(
                        len(self.cas.read(entry["digest"], max_bytes=entry["size"])),
                        entry["size"],
                    )
                self.assertEqual(
                    retain_zip_inventory(
                        self.cas,
                        archive_digest,
                        archive_name=name,
                    ),
                    inventory_digest,
                )

    def test_suffix_does_not_override_missing_zip_magic(self) -> None:
        digest = self._retain_archive(b"not a ZIP archive")
        with self.assertRaisesRegex(ZipInventoryError, "magic is missing"):
            retain_zip_inventory(self.cas, digest, archive_name="misleading.zip")

    def test_rejects_unsafe_paths_collisions_links_and_special_members(self) -> None:
        unsafe_archives: list[tuple[str, bytes, str]] = [
            ("traversal", _zip([("../escape", b"x")]), "path"),
            ("absolute", _zip([("/escape", b"x")]), "path"),
            ("backslash", _zip([("dir\\escape", b"x")]), "path"),
            ("drive", _zip([("C:/escape", b"x")]), "path"),
            ("leading-space", _zip([("dir/ file", b"x")]), "canonical"),
            ("trailing-space", _zip([("dir /file", b"x")]), "canonical"),
            (
                "deep",
                _zip([("/".join(["d"] * 33) + "/file", b"x")]),
                "bounds",
            ),
            ("duplicate", _zip([("a", b"1"), ("a", b"2")]), "duplicate"),
            ("casefold", _zip([("A", b"1"), ("a", b"2")]), "collision"),
            ("prefix", _zip([("a", b"1"), ("a/b", b"2")]), "directory prefix"),
        ]
        for label, raw, message in unsafe_archives:
            with self.subTest(label=label):
                digest = self._retain_archive(raw)
                with self.assertRaisesRegex(ZipInventoryError, message):
                    retain_zip_inventory(
                        self.cas,
                        digest,
                        archive_name=f"{label}.zip",
                    )

        for label, member_type in (
            ("symlink", stat.S_IFLNK),
            ("fifo", stat.S_IFIFO),
        ):
            with self.subTest(label=label):
                info = zipfile.ZipInfo(label)
                info.create_system = 3
                info.external_attr = (member_type | 0o777) << 16
                digest = self._retain_archive(_zip([(info, b"target")]))
                with self.assertRaisesRegex(
                    ZipInventoryError,
                    "links and special",
                ):
                    retain_zip_inventory(
                        self.cas,
                        digest,
                        archive_name=f"{label}.zip",
                    )

    def test_rejects_encryption_unsupported_method_and_nested_archives(self) -> None:
        encrypted = bytearray(_zip([("file.txt", b"content")]))
        local = encrypted.index(b"PK\x03\x04")
        central = encrypted.index(b"PK\x01\x02")
        encrypted[local + 6] |= 1
        encrypted[central + 8] |= 1
        digest = self._retain_archive(bytes(encrypted))
        with self.assertRaisesRegex(ZipInventoryError, "encrypted"):
            retain_zip_inventory(self.cas, digest, archive_name="encrypted.zip")

        digest = self._retain_archive(
            _zip([("file.txt", b"content")], compression=zipfile.ZIP_BZIP2)
        )
        with self.assertRaisesRegex(ZipInventoryError, "compression method"):
            retain_zip_inventory(self.cas, digest, archive_name="bzip2.zip")

        inner = _zip([("payload.py", b"print('nested')")])
        for path, content in (
            ("nested.bin", inner),
            ("nested.zip", b"not even ZIP bytes"),
        ):
            with self.subTest(path=path):
                digest = self._retain_archive(_zip([(path, content)]))
                with self.assertRaisesRegex(ZipInventoryError, "nested ZIP"):
                    retain_zip_inventory(
                        self.cas,
                        digest,
                        archive_name="outer.zip",
                    )

    def test_enforces_archive_member_expansion_ratio_and_path_bounds(self) -> None:
        cases = (
            (
                "archive",
                {"MAX_ARCHIVE_BYTES": 20},
                _zip([("file", b"x" * 30)]),
                "blob exceeds max_bytes",
            ),
            (
                "entries",
                {"MAX_ENTRIES": 1},
                _zip([("one", b"1"), ("two", b"2")]),
                "entry count",
            ),
            (
                "member",
                {"MAX_MEMBER_BYTES": 3},
                _zip([("file", b"1234")]),
                "metadata is invalid",
            ),
            (
                "expanded",
                {"MAX_EXPANDED_BYTES": 3},
                _zip([("file", b"1234")]),
                "expanded bytes",
            ),
            (
                "ratio",
                {"MAX_COMPRESSION_RATIO": 2},
                _zip([("file", b"A" * 1000)]),
                "compression ratio",
            ),
            (
                "path",
                {"MAX_PATH_BYTES": 3},
                _zip([("long", b"x")]),
                "bounds",
            ),
        )
        for label, changes, raw, message in cases:
            with self.subTest(label=label):
                digest = self._retain_archive(raw)
                patches = [
                    mock.patch(f"aragorn.zip_inventory.{key}", value)
                    for key, value in changes.items()
                ]
                for patcher in patches:
                    patcher.start()
                    self.addCleanup(patcher.stop)
                try:
                    with self.assertRaisesRegex(ZipInventoryError, message):
                        retain_zip_inventory(
                            self.cas,
                            digest,
                            archive_name=f"{label}.zip",
                        )
                finally:
                    for patcher in reversed(patches):
                        patcher.stop()

    def test_remaining_limits_reject_before_member_retention(self) -> None:
        raw = _zip([("one", b"12"), ("two", b"34")])
        digest = self._retain_archive(raw)
        with mock.patch.object(
            self.cas,
            "put_expected",
            wraps=self.cas.put_expected,
        ) as retain_member:
            for limits, message in (
                ({"max_expanded_bytes": 3}, "expanded bytes"),
                ({"max_entries": 1}, "entry count"),
                ({"max_entries": True}, "max_entries"),
            ):
                with (
                    self.subTest(limits=limits),
                    self.assertRaisesRegex(ZipInventoryError, message),
                ):
                    retain_zip_inventory(
                        self.cas,
                        digest,
                        archive_name="remaining.zip",
                        **limits,
                    )
            retain_member.assert_not_called()

    def test_crc_mismatch_and_missing_retained_member_fail_closed(self) -> None:
        corrupt = bytearray(_zip([("file.txt", b"content")]))
        local = corrupt.index(b"PK\x03\x04")
        central = corrupt.index(b"PK\x01\x02")
        corrupt[local + 14 : local + 18] = b"\0" * 4
        corrupt[central + 16 : central + 20] = b"\0" * 4
        digest = self._retain_archive(bytes(corrupt))
        with self.assertRaises(ZipInventoryError):
            retain_zip_inventory(self.cas, digest, archive_name="corrupt.zip")

        raw = _zip([("file.txt", b"content")])
        archive_digest = self._retain_archive(raw)
        inventory_digest = retain_zip_inventory(
            self.cas,
            archive_digest,
            archive_name="valid.zip",
        )
        inventory_raw = self.cas.read(inventory_digest)
        with tempfile.TemporaryDirectory() as temporary:
            incomplete = CAS(Path(temporary) / "cas")
            incomplete.put_expected(
                BytesIO(raw),
                expected_digest=archive_digest,
                max_bytes=len(raw),
            )
            incomplete.put_expected(
                BytesIO(inventory_raw),
                expected_digest=inventory_digest,
                max_bytes=len(inventory_raw),
            )
            with self.assertRaisesRegex(ZipInventoryError, "cannot verify"):
                verify_zip_inventory(
                    incomplete,
                    inventory_digest,
                    expected_archive_digest=archive_digest,
                    expected_archive_name="valid.zip",
                )

        changed = dict(self.cas.read(inventory_digest) and verify_zip_inventory(
            self.cas,
            inventory_digest,
            expected_archive_digest=archive_digest,
            expected_archive_name="valid.zip",
        ))
        changed["archive"] = {**changed["archive"], "name": "other.zip"}
        changed_raw = canonical_json(changed)
        changed_digest = self.cas.put(BytesIO(changed_raw), max_bytes=len(changed_raw))
        with self.assertRaisesRegex(ZipInventoryError, "does not match"):
            verify_zip_inventory(
                self.cas,
                changed_digest,
                expected_archive_digest=archive_digest,
                expected_archive_name="valid.zip",
            )


if __name__ == "__main__":
    unittest.main()
