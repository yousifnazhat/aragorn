"""Cross-build input checks; no rebuilding, target execution, network or activation."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_host_sysroot as target
from scripts.build_pi_core_linux import BuildError, canonical, sha256


class HostSysroot(unittest.TestCase):
    def test_package_lock_matches_both_retained_signed_release_indexes(self):
        packages = target.profile()["packages"]
        self.assertEqual(len(packages), 196)
        self.assertEqual(packages["libc6"]["Version"], "2.43-2ubuntu2")
        self.assertEqual(packages["linux-bpf-dev"]["Architecture"], "arm64")
        self.assertEqual(packages["libmicrohttpd-dev"]["component"], "universe")

    def test_target_absolute_link_rebases_and_traversal_is_refused(self):
        name = "usr/lib/ld-linux-aarch64.so.1"
        self.assertEqual(target.target_link(name, "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
                         "aarch64-linux-gnu/ld-linux-aarch64.so.1")
        with self.assertRaisesRegex(BuildError, "escapes"):
            target.target_link(name, "../../../outside")
        for item in ("./../outside", "/usr/include/input.h", "./usr//lib/x"):
            with self.subTest(item=item), self.assertRaises(BuildError):
                target.clean_name(item)

    def test_both_case_aliases_and_non_compiler_surfaces_are_excluded(self):
        for name in target.OMITTED_CASE_FOLDS:
            self.assertFalse(target.selected(name))
            prefix, leaf = name.rsplit("_", 1)
            self.assertFalse(target.selected(prefix + "_" + leaf[:-2].upper() + ".h"))
        for name in ("usr/bin/systemctl", "DEBIAN/preinst", "etc/ld.so.preload"):
            self.assertFalse(target.selected(name))
        self.assertTrue(target.selected("usr/include/aarch64-linux-gnu/linux/bpf/vmlinux.h"))

    def test_existing_packages_in_external_tree_cannot_supply_linked_input(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "root"
            root.mkdir()
            sentinel = root.parent / "unrelated"
            sentinel.write_bytes(b"keep")
            (root / "dep").symlink_to("../unrelated")
            with self.assertRaisesRegex(BuildError, "escaping"):
                target.inventory(root)
            self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_verified_tree_binds_bytes_modes_targets_and_file_set(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "root"
            root.mkdir()
            data = root / "libc.so.6"
            data.write_bytes(b"abi")
            data.chmod(0o644)
            (root / "other").write_bytes(b"abi")
            link = root / "libc.so"
            link.symlink_to(data.name)
            rows, counts = target.inventory(root)
            (base / "sysroot-packages.json").write_bytes(b"lock")
            (base / "sysroot-tree.json").write_text(json.dumps(dict(
                counts, inventory_sha256=sha256(canonical(rows)), package_lock_sha256=sha256(b"lock"))))
            with patch.object(target, "PINS", base):
                self.assertEqual(target.verify(root)["files"], 2)
                for mutate, undo in (
                        (lambda: data.write_bytes(b"bad"), lambda: data.write_bytes(b"abi")),
                        (lambda: data.chmod(0o444), lambda: data.chmod(0o644)),
                        (lambda: os.rename(link, root / "renamed"), lambda: os.rename(root / "renamed", link)),
                        (lambda: (link.unlink(), link.symlink_to("other")),
                         lambda: (link.unlink(), link.symlink_to(data.name)))):
                    mutate()
                    with self.assertRaisesRegex(BuildError, "unexpected sysroot"):
                        target.verify(root)
                    undo()
