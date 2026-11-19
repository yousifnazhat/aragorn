"""B41 offline boot artifact inspection. No kernel, guest init or module is run."""
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_immutable_boot as boot
from scripts.build_pi_core_linux import BuildError, regular_bytes, sha256


class ImmutableBoot(unittest.TestCase):
    def test_signed_release_kernel_and_static_init_lineage(self):
        pin = json.loads(regular_bytes(boot.PACK / "boot-artifacts.json"))
        receipt = json.loads(regular_bytes(boot.WORK / "receipt.json"))
        self.assertEqual(receipt, pin)
        lock = boot.indexed()
        self.assertFalse(receipt["booted"])
        kernel = regular_bytes(boot.WORK / "vmlinuz", 32 << 20)
        self.assertEqual(sha256(kernel), lock["kernel_sha256"])
        self.assertEqual(pin["kernel_sha256"], lock["kernel_sha256"])
        boot.kernel_pe(kernel)
        directory = boot.WORK / pin["build"]
        inputs = regular_bytes(directory / "inputs.json")
        self.assertEqual(directory.name, "build-" + sha256(inputs))
        binding = json.loads(inputs)
        self.assertEqual(binding["source"], sha256(regular_bytes(boot.SOURCE)))
        self.assertEqual(binding["release_lock"], sha256(regular_bytes(boot.LOCK)))
        self.assertEqual(binding["recipe"], sha256(regular_bytes(Path(boot.__file__).resolve())))
        self.assertEqual(binding["tool_manifest"], sha256(regular_bytes(boot.tools.LOCK)))
        self.assertEqual(binding["tool_tree"], json.loads(regular_bytes(boot.tools.LOCK))["sealed_sha256"])
        self.assertEqual(binding["sysroot_tree"],
                         json.loads(regular_bytes(boot.sysroot.PINS / "sysroot-tree.json"))["inventory_sha256"])

    def test_independent_libarchive_replay_of_exact_cpio_metadata_and_policy(self):
        pin = json.loads(regular_bytes(boot.PACK / "boot-artifacts.json"))
        lock = json.loads(regular_bytes(boot.LOCK))
        archive = boot.WORK / "initramfs.cpio"
        self.assertEqual(sha256(regular_bytes(archive, 8 << 20)), pin["initramfs_sha256"])
        tool = Path("/usr/bin/bsdtar")
        self.assertEqual(sha256(regular_bytes(tool, 2 << 20)),
                         "f96200d5be4a3f99cdbc88892a2e26f14d501d354c72b224472462cc67fa271d")
        # Format translation in memory only; no extraction and no creation of device nodes.
        result = subprocess.run([str(tool), "-cf", "-", "--format=ustar", "@" + str(archive)], check=True,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        self.assertEqual(result.stderr, b"")
        expected = {"dev", "proc", "newroot", "modules", "dev/console", "policy", "init"}
        modules = {"modules/" + Path(n).name + ".ko": sha for n, _, sha in lock["modules"]}
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
            entries = tar.getmembers()
            self.assertCountEqual([entry.name for entry in entries], expected | set(modules))
            for entry in entries:
                self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0), entry.name)
                if entry.name == "dev/console":
                    self.assertTrue(entry.ischr())
                    self.assertEqual((entry.devmajor, entry.devminor, entry.mode), (5, 1, 0o600))
                elif entry.name in ("dev", "proc", "newroot", "modules"):
                    self.assertTrue(entry.isdir() and entry.mode == 0o755)
                else:
                    self.assertTrue(entry.isfile())
                    raw = tar.extractfile(entry).read()
                    self.assertEqual(entry.mode, 0o555 if entry.name == "init" else 0o400)
                    if entry.name == "init":
                        self.assertEqual(sha256(raw), pin["init_sha256"])
                        boot.require_static_arm64_elf(raw)
                    elif entry.name == "policy":
                        magic, length, root, manager, loader = struct.unpack("<8sQ32s32s32s", raw)
                        self.assertEqual((magic, length, root.hex(), manager.hex(), loader.hex()),
                                         (b"ARGBOOT1", pin["root_bytes"], pin["root_sha256"],
                                          lock["manager_sha256"], boot.LOADER_SHA))
                    else:
                        self.assertEqual(sha256(raw), modules[entry.name])

    def test_substituted_root_cannot_publish_a_boot_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d).resolve(); dst = work / "build-test"; dst.mkdir(mode=0o700)
            image = work / "image"; image.write_bytes(b"hsqs" + bytes(4092))
            with patch.object(boot, "WORK", work), patch.object(boot, "indexed", return_value={}):
                with self.assertRaisesRegex(BuildError, "not the pinned bytes"):
                    boot.finish(dst, image, "0"*64, "0"*64)
            self.assertFalse((work/"vmlinuz").exists())
            self.assertFalse((work/"initramfs.cpio").exists())

    def test_policy_refuses_unbounded_lengths_and_partial_digests(self):
        for n in (True, 4095, (8 << 30) + 1):
            with self.subTest(n=n), self.assertRaisesRegex(BuildError, "root length"):
                boot.policy(n, "0"*64, "0"*64)
        with self.assertRaisesRegex(BuildError, "bad boot digest"):
            boot.policy(8192, "00", "0"*64)
