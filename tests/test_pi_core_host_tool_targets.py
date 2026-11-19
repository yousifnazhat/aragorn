"""New source-input and ownership boundaries. Never configure or compile tools."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import prepare_pi_core_host_tool_targets as tools
from scripts.build_pi_core_linux import BuildError


class HostToolInputs(unittest.TestCase):
    def test_writable_output_parent_refused_before_extraction(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            writable = root / "shared"
            writable.mkdir()
            writable.chmod(0o772)
            with self.assertRaisesRegex(BuildError, "writable preparation parent"):
                tools.prepare(root, writable / "out")
            self.assertFalse((writable / "out").exists())

    def test_wrong_source_descriptor_cannot_create_output(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / tools.DSC[0]).write_bytes(b"unapproved")
            with self.assertRaisesRegex(BuildError, "unapproved Ubuntu source input"):
                tools.prepare(root, root / "work")
            self.assertFalse((root / "work").exists())

    def test_occupied_or_dangling_destination_is_not_adopted(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            occupied = root / "occupied"
            occupied.mkdir()
            marker = occupied / "marker"
            marker.write_bytes(b"keep")
            dangling = root / "dangling"
            dangling.symlink_to(root / "absent")
            for dest in (occupied, dangling):
                with self.subTest(dest=dest.name), self.assertRaisesRegex(BuildError, "existing source preparation"):
                    tools.prepare(root, dest)
            self.assertEqual(marker.read_bytes(), b"keep")
            self.assertTrue(dangling.is_symlink())
