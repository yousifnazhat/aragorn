from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.acquire import (
    InventoryError,
    ingest_local,
    ingest_open_directory,
    inventory_local,
)
from aragorn.cas import CAS


class InventoryLocalTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "z.txt").write_bytes(b"z")
            (root / "nested").mkdir()
            (root / "nested" / "a.txt").write_bytes(b"a")

            first = inventory_local(root)
            second = inventory_local(root)

            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "aragorn/manifest/v1")
            self.assertEqual(first["source"]["kind"], "local")
            self.assertEqual(first["closure"], {"scope": "source_tree", "status": "complete"})
            self.assertEqual(
                [entry["path"] for entry in first["files"]],
                ["nested/a.txt", "z.txt"],
            )
            self.assertRegex(first["tree_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertFalse(any(entry["executable"] for entry in first["files"]))

    def test_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "one").write_bytes(b"12")
            (root / "two").write_bytes(b"34")
            (root / "deep").mkdir()
            (root / "deep" / "three").write_bytes(b"5")

            cases = (
                ({"max_files": 2}, "file count"),
                ({"max_file_size": 1}, "file size"),
                ({"max_total_bytes": 3}, "total byte"),
                ({"max_depth": 0}, "depth"),
            )
            for limits, message in cases:
                with self.subTest(limits=limits):
                    with self.assertRaisesRegex(InventoryError, message):
                        inventory_local(root, **limits)

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            outside = root.parent / f"{root.name}-outside"
            outside.write_bytes(b"outside")
            try:
                os.symlink(outside, root / "escape")
                with self.assertRaisesRegex(InventoryError, "symlink rejected"):
                    inventory_local(root)
            finally:
                outside.unlink(missing_ok=True)

    def test_hardlink_to_outside_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "skill"
            root.mkdir()
            outside = temporary / "host-secret"
            outside.write_bytes(b"secret")
            os.link(outside, root / "escape")

            with self.assertRaisesRegex(InventoryError, "hardlink rejected"):
                inventory_local(root)

    def test_ingest_stores_every_manifest_file_in_cas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "skill"
            root.mkdir()
            expected = {"a.txt": b"alpha", "nested/b.bin": b"\x00beta"}
            for relative_path, content in expected.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            cas = CAS(temporary / "cas")

            manifest = ingest_local(root, cas)

            self.assertEqual(
                expected,
                {entry["path"]: cas.read(entry["digest"]) for entry in manifest["files"]},
            )

    def test_open_directory_capability_survives_parent_symlink_retarget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            first = temporary / "first"
            second = temporary / "second"
            first.mkdir()
            second.mkdir()
            (first / "identity").write_bytes(b"first")
            (second / "identity").write_bytes(b"second")
            selected = temporary / "selected"
            selected.symlink_to(first, target_is_directory=True)
            resolved = selected.resolve(strict=True)
            descriptor = os.open(
                resolved,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                selected.unlink()
                selected.symlink_to(second, target_is_directory=True)
                cas = CAS(temporary / "cas")
                manifest = ingest_open_directory(resolved, descriptor, cas)
            finally:
                os.close(descriptor)

            self.assertEqual(
                cas.read(manifest["files"][0]["digest"]),
                b"first",
            )


if __name__ == "__main__":
    unittest.main()
