"""One offline physical layout fragment; no mount, boot, or installed custody."""
import hashlib
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest

from scripts import prepare_pi_core_immutable_host_layout as layout


PREFLIGHT = Path(__file__).resolve().parents[1] / ".aragorn/host-preflight"
# Independent payload pins from the B38 release-authenticated Ubuntu libc6 package.
FILES = {
    "/usr/lib/ld-linux-aarch64.so.1": "sha256:058b11f959fd1006abfc289a7fa9e2df86892e8a05f2d8b79a137e6a29c11a78",
    "/usr/lib/aarch64-linux-gnu/libc.so.6": "sha256:4306bea54c5862911d6ed2ee19adc0cdcb092cd1948ceb14a9c1e3592e8487d7",
}


class ImmutableHostLayout(unittest.TestCase):
    def test_retain_actual_unmounted_fragment(self):
        dest = PREFLIGHT / "immutable-layout-b39"
        retained = dest.with_suffix(".receipt.json")
        self.assertFalse(os.path.lexists(dest), "preserve earlier or partial fragment")
        self.assertFalse(os.path.lexists(retained), "preserve earlier or partial receipt")
        receipt = layout.prepare(PREFLIGHT / "build-b38", dest)
        self.assertEqual(receipt["status"], "PREPARED_IMMUTABLE_HOST_LAYOUT_FRAGMENT_NOT_MOUNTED")
        self.assertEqual(receipt["physical_files"], FILES)
        self.assertEqual(receipt["required_early_boot_bind"],
                         {"source": "/usr/lib", "target": "/lib", "readonly": True})
        for key in ("mount_performed", "installed_identity_verified", "bootable_host", "phase3_exit_eligible"):
            self.assertIs(receipt[key], False)

        dirs = {"/lib", "/usr", "/usr/lib", "/usr/lib/aarch64-linux-gnu"}
        entries = {"/" + p.relative_to(dest).as_posix(): p for p in dest.rglob("*")}
        self.assertEqual(set(entries), dirs | set(FILES))
        self.assertEqual(stat.S_IMODE(dest.lstat().st_mode), 0o700)
        for name in dirs:
            self.assertTrue(stat.S_ISDIR(entries[name].lstat().st_mode), name)
        self.assertEqual(list(entries["/lib"].iterdir()), [])
        for name, pin in FILES.items():
            info = entries[name].lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode), name)
            self.assertEqual((info.st_nlink, stat.S_IMODE(info.st_mode)), (1, 0o555))
            self.assertEqual("sha256:" + hashlib.sha256(entries[name].read_bytes()).hexdigest(), pin)
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        with retained.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o400)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.assertEqual(retained.read_bytes(), raw)
        print(raw.decode("ascii").strip(), flush=True)

    def test_occupied_or_dangling_destination_is_never_adopted(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            occupied = root / "owned"
            occupied.mkdir()
            marker = occupied / "marker"
            marker.write_bytes(b"keep")
            dangling = root / "dangling"
            dangling.symlink_to(root / "absent")
            for dest in (occupied, dangling):
                with self.subTest(dest=dest.name), self.assertRaisesRegex(ValueError, "existing host layout destination"):
                    layout.prepare(root, dest)
            self.assertEqual(marker.read_bytes(), b"keep")
            self.assertTrue(dangling.is_symlink())
            self.assertFalse((root / "absent").exists())

    def test_substituted_inputs_do_not_create_fragment(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name, size in (("ubuntu-loader.elf", 201872), ("ubuntu-libc.elf", 1788240)):
                (root / name).write_bytes(bytes(size))
            with self.assertRaisesRegex(ValueError, "unapproved host layout input"):
                layout.prepare(root, root / "out")
            self.assertFalse(os.path.lexists(root / "out"))

    def test_linked_parent_or_payload_refused_before_output(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            for inputs, dest in ((alias, real / "out"), (real, alias / "out")):
                with self.subTest(inputs=inputs, dest=dest), self.assertRaises(ValueError):
                    layout.prepare(inputs, dest)
                self.assertFalse((real / "out").exists())
            (real / "bytes").write_bytes(b"x")
            (real / "ubuntu-loader.elf").symlink_to("bytes")
            with self.assertRaisesRegex(ValueError, "linked or nonregular"):
                layout.prepare(real, real / "out")
            self.assertFalse((real / "out").exists())
