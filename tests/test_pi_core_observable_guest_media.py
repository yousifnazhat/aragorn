"""Read B44 as ordinary sealed files. Nothing in the guest is executed."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from scripts import inspect_pi_core_guest_disk as disk
from scripts import prepare_pi_core_guest_disk as b41
from scripts import prepare_pi_core_guest_firmware_trust as b42
from scripts.build_pi_core_linux import regular_bytes, require_static_arm64_elf, sha256


PACK = b41.PACK.parent / "immutable-host-b44"
CMDLINE = b41.CMDLINE + " console=hvc0"


def read_json(path):
    return json.loads(regular_bytes(path))


class ObservableGuestMedia(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = read_json(PACK / "media-output.json")
        name = cls.pin["directory"]
        if not re.fullmatch("build-[0-9a-f]{64}", name):
            raise ValueError("unexpected B44 build name")
        cls.out = b41.WORK.parent / "build-b44" / name
        cls.prev = read_json(b41.PACK / "media-output.json")

    def test_successor_replaces_only_the_candidate_in_the_boot_request(self):
        p = self.pin
        self.assertEqual(p, read_json(self.out / "receipt.json"))
        old = read_json(b41.PACK.parent / "immutable-host-b43/boot-request.json")
        for k in ("disk_sha256", "uki_sha256", "initramfs_sha256", "esp_sha256"):
            self.assertNotEqual(p[k], self.prev[k], k)
        old_fw = read_json(b42.PIN)
        for k in ("authenticode_sha256", "esl_sha256"):
            self.assertNotEqual(p[k], old_fw[k], k)
        for k in ("root_size", "root_sha256", "kernel_sha256", "disk_bytes", "sector_size"):
            self.assertEqual(p[k], self.prev[k], k)
        old["guest"]["disk_sha256"] = p["disk_sha256"]
        old["firmware"].update(raw_uki_sha256=p["uki_sha256"], proposed_esl_sha256=p["esl_sha256"],
                               allow_image_authenticode_sha256=p["authenticode_sha256"])
        self.assertEqual(read_json(PACK / "boot-request.json"), old)
        for k in ("secure_boot_enrollment", "boot_observed", "phase3_exit_eligible"):
            self.assertIs(p[k], False, k)

    def test_build_identity_binds_compiled_source_recipes_and_tool_pins(self):
        raw = regular_bytes(self.out / "inputs.json")
        self.assertEqual(self.out.name, "build-" + sha256(raw))
        inputs = json.loads(raw)
        source = regular_bytes(PACK / "boot-init.c")
        self.assertEqual(source, regular_bytes(self.out / "boot-init.c"))
        self.assertEqual((sha256(source), inputs["source_sha256"]), (self.pin["source_sha256"],) * 2)
        self.assertEqual(inputs["cmdline"], CMDLINE)
        paths = [*(b41.PACK / name for name in ("boot-artifacts.json", "boot-inputs.json",
                                                "media-output.json", "image-output.json", "boot-init.c")),
                 b42.PIN, *(b41.ROOT / "scripts" / name for name in ("prepare_pi_core_observable_guest.py",
                     "prepare_pi_core_immutable_boot.py", "prepare_pi_core_guest_disk.py",
                     "inspect_pi_core_guest_disk.py", "prepare_pi_core_guest_firmware_trust.py"))]
        self.assertEqual(inputs["predecessors_and_recipes"],
                         {p.relative_to(b41.ROOT).as_posix(): sha256(regular_bytes(p)) for p in paths})
        tools = b41.PACK.parent / "host-tools-b40"
        self.assertEqual(inputs["tool_manifest"], sha256(regular_bytes(tools / "tools.json")))
        self.assertEqual(inputs["tool_tree"], read_json(tools / "tools.json")["sealed_sha256"])
        self.assertEqual(inputs["sysroot_tree"], read_json(tools / "sysroot-tree.json")["inventory_sha256"])
        self.assertEqual((self.pin["cmdline"], self.pin["osrel"]), (CMDLINE, b41.OSREL.replace("b41", "b44")))

    def test_finished_raw_disk_gpt_efi_boot_payload_and_sealed_root(self):
        p = self.pin
        with b41.opened(self.out / "aragorn-arm64.raw") as f:
            st = os.fstat(f.fileno())
            self.assertEqual((st.st_mode & 0o7777, st.st_uid, st.st_size),
                             (0o400, os.getuid(), p["disk_bytes"]))
            whole = hashlib.sha256()

            def take(n):
                chunk = f.read(n)
                self.assertEqual(len(chunk), n)
                whole.update(chunk)
                return chunk

            last = st.st_size // 512 - 1
            mbr, header, table = take(512), take(512), take(32 * 512)
            self.assertEqual((mbr[446 + 4], struct.unpack_from("<II", mbr, 454), mbr[510:]),
                             (0xee, (1, last), b"\x55\xaa"))
            self.assertFalse(any(mbr[462:510]))
            extents = disk.gpt(header, table, 1, last, 2)
            (es, ee), (rs, re_) = extents
            self.assertEqual((es, ee + 1, rs), (b41.ESP_START, b41.ROOT_START, b41.ROOT_START))
            self.assertFalse(any(take((es - 34) * 512)))
            esp = take((ee + 1 - es) * 512)
            self.assertEqual(sha256(esp), p["esp_sha256"])
            uki = disk.fat_uki(memoryview(esp), es)
            self.assertEqual((sha256(uki), len(uki)), (p["uki_sha256"], p["uki_bytes"]))
            sections = disk.sections(uki)
            self.assertEqual(sections[b".cmdline"], CMDLINE.encode())
            self.assertEqual(sections[b".uname"], b41.LINUX_VERSION.encode())
            self.assertEqual(sections[b".osrel"], b41.OSREL.replace("b41", "b44").encode())
            self.assertNotIn(b".profile", sections)
            self.assertEqual(sha256(sections[b".initrd"]), p["initramfs_sha256"])
            self.assertEqual(sha256(sections[b".linux"]), self.prev["kernel_sha256"])
            root = hashlib.sha256()
            left = self.prev["root_size"]
            self.assertEqual((left + 511) // 512, re_ + 1 - rs)
            while left:
                data = take(min(left, 4 << 20))
                root.update(data)
                left -= len(data)
            self.assertEqual(root.hexdigest(), self.prev["root_sha256"])
            self.assertFalse(any(take((-self.prev["root_size"]) % 512)))
            self.assertEqual(take(32 * 512), table)
            self.assertEqual(disk.gpt(take(512), table, last, 1, last - 32), extents)
            self.assertEqual(f.read(1), b"")
            self.assertEqual(whole.hexdigest(), p["disk_sha256"])

    def test_initramfs_contains_changed_static_observer_and_unchanged_policy_and_modules(self):
        p = self.pin
        lock = read_json(b41.PACK / "boot-inputs.json")
        prev_boot = read_json(b41.PACK / "boot-artifacts.json")
        kernel_cfg = regular_bytes(self.out / "kernel.config", 2 << 20)
        self.assertEqual(sha256(kernel_cfg), lock["config_sha256"])
        for flag in ("HVC_DRIVER", "VIRTIO_CONSOLE", "VIRTIO_PCI", "PCI_HOST_GENERIC", "PROC_FS"):
            self.assertIn(("CONFIG_" + flag + "=y").encode(), kernel_cfg.splitlines())
        bsdtar = Path("/usr/bin/bsdtar")
        self.assertEqual(sha256(regular_bytes(bsdtar, 2 << 20)),
                         "f96200d5be4a3f99cdbc88892a2e26f14d501d354c72b224472462cc67fa271d")
        cpio = regular_bytes(self.out / "initramfs.cpio", 8 << 20)
        self.assertEqual(sha256(cpio), p["initramfs_sha256"])
        decoded = subprocess.run([bsdtar, "-cf", "-", "--format=ustar", "@-"], input=cpio,
                                 check=True, capture_output=True, timeout=15)
        self.assertEqual(decoded.stderr, b"")
        modules = {"modules/" + Path(n).name + ".ko": h for n, _, h in lock["modules"]}
        with tarfile.open(fileobj=io.BytesIO(decoded.stdout)) as ar:
            self.assertCountEqual(ar.getnames(), ["dev", "proc", "newroot", "modules", "dev/console", "init",
                                                  "policy", *modules])
            for member in ar:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                if member.name in ("dev", "proc", "newroot", "modules"):
                    self.assertTrue(member.isdir() and member.mode == 0o755)
                elif member.name == "dev/console":
                    self.assertTrue(member.ischr())
                    self.assertEqual((member.devmajor, member.devminor, member.mode), (5, 1, 0o600))
                else:
                    self.assertTrue(member.isfile())
                    self.assertEqual(member.mode, 0o555 if member.name == "init" else 0o400)
                    raw = ar.extractfile(member).read()
                    if member.name == "init":
                        require_static_arm64_elf(raw)
                        self.assertEqual(sha256(raw), p["init_sha256"])
                        self.assertNotEqual(p["init_sha256"], prev_boot["init_sha256"])
                        self.assertIn(CMDLINE.encode(), raw)
                        self.assertIn(b"ARAGORN_B44_V1 ", raw)
                    elif member.name == "policy":
                        magic, size, root, manager, loader = struct.unpack("<8sQ32s32s32s", raw)
                        self.assertEqual((magic, size, root.hex(), manager.hex(), loader.hex()), (b"ARGBOOT1",
                            self.prev["root_size"], self.prev["root_sha256"], prev_boot["manager_sha256"],
                            prev_boot["loader_sha256"]))
                    else:
                        self.assertEqual(sha256(raw), modules[member.name])

    def test_independent_pe_hash_and_exact_single_entry_firmware_proposal(self):
        p = self.pin
        pe = regular_bytes(self.out / "BOOTAA64.EFI", 32 << 20)
        self.assertEqual(sha256(pe), p["uki_sha256"])
        wheel = regular_bytes(b42.OUT.parent / "reference/lief-1.0.0-cp312-abi3-macosx_11_0_arm64.whl", 4 << 20)
        self.assertEqual(sha256(wheel), "92bf3b06c19a1ebd9e7978de47cc61040752ec452f7906bc3aac8d57abb23a8b")
        with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(io.BytesIO(wheel)) as z:
            dest = Path(tmp).resolve()
            (dest / "lief").mkdir(mode=0o700)
            for name in ("lief/__init__.py", "lief/_lief.so"):
                b41.put(dest / name, z.read(name))
            cmd = "import sys;sys.path.insert(0,sys.argv[1]);import lief;print(bytes(lief.PE.parse(sys.stdin.buffer.read()).authentihash_sha256).hex())"
            digest = subprocess.run(["/usr/bin/sandbox-exec", "-p",
                '(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read* (subpath "/Users"))',
                sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=/dev/null/pyc", "-c", cmd, dest],
                input=pe, capture_output=True, cwd=dest, env={"HOME": str(dest), "PATH": "/usr/bin:/bin"},
                check=True, timeout=30).stdout.decode("ascii").strip()
        self.assertEqual(digest, p["authenticode_sha256"])
        esl = regular_bytes(self.out / "b44-uki-sha256.esl")
        self.assertEqual((len(esl), sha256(esl)), (76, p["esl_sha256"]))
        self.assertEqual(struct.unpack("<16sIII16s32s", esl),
                         (b42.EFI_CERT_SHA256.bytes_le, 76, 0, 48, b42.OWNER.bytes_le, bytes.fromhex(digest)))
