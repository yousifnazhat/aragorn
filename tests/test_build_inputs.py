from __future__ import annotations

from pathlib import Path
import stat
import tempfile
import unittest

from scripts.verify_build_inputs import VerificationError, tree_digest


class BuildInputVerifierTests(unittest.TestCase):
    def test_digest_binds_paths_and_bytes_but_not_creation_order(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            (first_root / "nested").mkdir()
            (first_root / "nested" / "b.txt").write_bytes(b"two")
            (first_root / "a.txt").write_bytes(b"one")
            (second_root / "a.txt").write_bytes(b"one")
            (second_root / "nested").mkdir()
            (second_root / "nested" / "b.txt").write_bytes(b"two")

            expected = tree_digest(first_root)
            self.assertEqual(expected, tree_digest(second_root))

            (second_root / "nested" / "b.txt").write_bytes(b"changed")
            self.assertNotEqual(expected, tree_digest(second_root))

            (second_root / "nested" / "b.txt").write_bytes(b"two")
            (second_root / "a.txt").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            self.assertNotEqual(expected, tree_digest(second_root))

    def test_includes_bind_only_the_declared_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_bytes(b"project")
            (root / "src").mkdir()
            (root / "src" / "module.py").write_bytes(b"source")
            expected = tree_digest(root, ("pyproject.toml", "src"))

            (root / "ignored.txt").write_bytes(b"not copied by the Dockerfile")
            self.assertEqual(
                expected, tree_digest(root, ("pyproject.toml", "src"))
            )
            self.assertNotEqual(expected, tree_digest(root))

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").write_bytes(b"target")
            (root / "link").symlink_to("target")

            with self.assertRaisesRegex(VerificationError, "unsupported build input"):
                tree_digest(root)


if __name__ == "__main__":
    unittest.main()
