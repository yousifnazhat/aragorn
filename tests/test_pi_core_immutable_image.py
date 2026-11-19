"""Affected image controls only. Never rebuild an image or run a guest here."""
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts import prepare_pi_core_immutable_image as image
from scripts.build_pi_core_linux import BuildError, sha256


class ImmutableRootImage(unittest.TestCase):
    def test_retained_readback_matches_root_inventory_pins(self):
        pin = json.loads(image.PINS.with_name("image-output.json").read_bytes())
        transaction = image.WORK / pin["fingerprint"]
        raw = (transaction / "receipt.json").read_bytes()
        self.assertEqual(sha256(raw), pin["receipt_sha256"])
        receipt = json.loads(raw)
        self.assertEqual((receipt["sha256"], receipt["bytes"], receipt["entries"], receipt["xattr_records"]),
                         (pin["root_sha256"], pin["root_bytes"], pin["inventory_entries"], pin["xattr_records"]))
        self.assertEqual(len(receipt["library_aliases_retargeted"]), pin["alias_targets_relocated"])
        self.assertEqual(image.digest(transaction / "inventory.jsonl"), pin["inventory_sha256"])
        self.assertEqual(receipt["inventory_sha256"], pin["inventory_sha256"])
        self.assertIs(receipt["boot_verified"], False)
        self.assertIs(receipt["phase3_exit_eligible"], False)

    def test_pseudo_rejects_host_command_traversal_duplicate_and_orphan_xattr(self):
        for rows in (b"bad F 10 755 0 0 touch host\n", b"../bad D 0 755 0 0\n",
                     b"same D 0 755 0 0\nsame D 0 755 0 0\n", b"orphan x security.capability=bad\n"):
            with self.subTest(rows=rows), self.assertRaises(BuildError):
                image.read_pseudo(io.BytesIO(rows + image.MARKER))

    def test_inventory_binds_binary_data_and_linux_metadata(self):
        def inventory(header, raw):
            pseudo = header + image.MARKER + raw
            rows, attrs, start = image.read_pseudo(io.BytesIO(pseudo))
            return image.inventory(rows, attrs, pseudo, start, None)
        original = b"escaped\\ file R 17 555 11 22 3 0 0\nescaped\\ file x user.label=v\n"
        base = inventory(original, b"abc")
        for altered, data in ((original, b"abd"), (original.replace(b"555", b"755"), b"abc"),
                              (original.replace(b"11 22", b"12 22"), b"abc"),
                              (original.replace(b"label=v", b"label=w"), b"abc")):
            with self.subTest(altered=altered, data=data):
                self.assertNotEqual(base, inventory(altered, data))
        with self.assertRaisesRegex(BuildError, "extent"):
            inventory(original, b"x")

    def test_projection_rejects_unsafe_alias_without_following_host_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            d = root / "usr/lib"
            d.mkdir(parents=True)
            (d / "libfixture.so.1").write_bytes(b"new")
            entries = [{"path": "/lib", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
                       {"path": "/usr/lib/libfixture.so.1", "type": "file", "uid": 0, "gid": 0,
                        "mode": 0o555, "size": 3, "sha256": sha256(b"new")}]
            base = (b"lib S 1776674791 777 0 0 usr/lib\nusr D 0 755 0 0\nusr/lib D 0 755 0 0\n"
                    b"usr/lib/libfixture.so.1 S 0 777 0 0 ../../etc/not-a-library\n")
            rows, attrs, offset = image.read_pseudo(io.BytesIO(base + image.MARKER))
            with self.assertRaisesRegex(BuildError, "escaping guest library alias"):
                image.project(rows, attrs, b"", offset, root, entries)
