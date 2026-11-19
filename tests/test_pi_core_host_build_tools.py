"""B40 build-only input/dispatch guards; no target or translated executable is run."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_host_build_tools as h


class HostTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.bpf = self.work / "firewall_rules.bpf.unstripped.o"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[16:18] = (1).to_bytes(2, "little")
        header[18:20] = (247).to_bytes(2, "little")
        self.bpf.write_bytes(header)

    def test_exact_archive_size_and_digest(self):
        row = {"size": 64, "sha256": hashlib.sha256(self.bpf.read_bytes()).hexdigest()}
        h.checked_archive(self.bpf, row)
        for key, value in (("size", 63), ("sha256", "0" * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                h.checked_archive(self.bpf, {**row, key: value})

    def test_archive_paths_reject_traversal_and_links(self):
        (self.work / "linked").symlink_to(self.work)
        for path in ("../a", "x/../a", "/absolute", ".", "linked/out"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                h.direct(self.work, path)

    def test_tampered_dispatched_bytes_and_mode_are_distinct(self):
        before = h.tree(self.work)
        self.bpf.chmod(0o555)
        after = h.tree(self.work)
        self.assertNotEqual(before, after)
        self.bpf.chmod(0o644)
        self.bpf.write_bytes(b"replacement")
        self.assertNotEqual(before, h.tree(self.work))

    def test_nonempty_bytecode_tree_is_rejected(self):
        (self.work / "__pycache__").mkdir()
        with self.assertRaisesRegex(ValueError, "bytecode"):
            h.tree(self.work)

    def test_version_and_object_names_are_exact(self):
        self.assertEqual(h.bpf_args(["--version"], self.work), (["--version"], None, None))
        out = self.work / "firewall_rules.bpf.o"
        args, data, dest = h.bpf_args(["gen", "object", str(out), str(self.bpf)], self.work)
        self.assertEqual((args, data, dest),
                         (["gen", "object", "/output/" + out.name, "/input/" + self.bpf.name],
                          self.bpf.read_bytes(), out))
        self.assertEqual(h.bpf_args(["gen", "skeleton", str(self.bpf)], self.work)[0],
                         ["gen", "skeleton", "/input/" + self.bpf.name])

    def test_refuses_privileged_or_renamed_dispatch(self):
        for args in (["map", "show"], ["prog", "load", "x", "y"], ["batch", "file", "x"],
                     ["--version", "anything"], ["gen", "skeleton", str(self.bpf), "name", "x"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                h.bpf_args(args, self.work)

    def test_rejects_non_bpf_or_nonfresh_destination(self):
        with self.assertRaisesRegex(ValueError, "overwrite"):
            h.bpf_args(["gen", "object", str(self.bpf), str(self.bpf)], self.work)
        raw = bytearray(self.bpf.read_bytes())
        raw[18:20] = (183).to_bytes(2, "little")
        self.bpf.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "not a relocatable BPF"):
            h.bpf_args(["gen", "skeleton", str(self.bpf)], self.work)

    def test_refuses_symlink_hardlink_and_outside_aliases(self):
        sym = self.work / "symlink.o"
        sym.symlink_to(self.bpf)
        with self.assertRaises(ValueError):
            h.bpf_args(["gen", "skeleton", str(sym)], self.work)
        os.link(self.bpf, self.work / "hardlink.o")
        with self.assertRaises(ValueError):
            h.bpf_args(["gen", "skeleton", str(self.bpf)], self.work)
        with self.assertRaises(ValueError):
            h.bpf_args(["gen", "skeleton", str(self.work.parent / "outside.o")], self.work)

    def test_scratch_is_owned_private_and_exact(self):
        with patch.object(h, "CLIENT", self.work):
            wrong = self.work / "not-a-fingerprint" / "tmp"
            wrong.mkdir(parents=True)
            with self.assertRaises(ValueError):
                h.scratch_owner(wrong)
            good = self.work / ("a" * 64) / "tmp"
            good.mkdir(parents=True)
            good.parent.chmod(0o700)
            good.chmod(0o700)
            self.assertEqual(h.scratch_owner(good), good.parent)
            good.chmod(0o755)
            with self.assertRaises(ValueError):
                h.scratch_owner(good)


if __name__ == "__main__":
    unittest.main()
