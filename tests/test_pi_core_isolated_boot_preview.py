"""B43 request and inert host-side configuration only. Never open a variable store or a VM."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import prepare_pi_core_guest_disk as media


PROFILE = media.PACK.parent / "immutable-host-b43"


class BootRequest(unittest.TestCase):
    def test_request_joins_signed_media_and_firmware_pins_without_authority(self):
        request = json.loads((PROFILE / "boot-request.json").read_bytes())
        pins = json.loads((media.PACK / "media-output.json").read_bytes())
        trust = json.loads((media.PACK.parent / "immutable-host-b42/firmware-trust.json").read_bytes())
        disk, fw = request["guest"], request["firmware"]
        self.assertEqual((disk["disk_sha256"], disk["disk_bytes"], disk["expected_logical_sector_bytes"]),
                         (pins["disk_sha256"], pins["disk_bytes"], pins["sector_size"]))
        self.assertEqual(fw["raw_uki_sha256"], pins["uki_sha256"])
        self.assertEqual((fw["raw_uki_sha256"], fw["allow_image_authenticode_sha256"], fw["proposed_esl_sha256"]),
                         (trust["uki_sha256"], trust["authenticode_sha256"], trust["esl_sha256"]))
        self.assertTrue(fw["new_private_store_only"] and fw["preserve_approved_revocations"])
        self.assertIs(fw["broad_default_allow_signatures"], False)
        self.assertEqual(request["status"], "draft-not-authority")
        self.assertEqual(request["authority_now"], dict.fromkeys(
            ("allocate_host", "transfer_media", "create_variable_store", "enroll", "boot", "pilot", "qualify"), False))
        self.assertTrue(request["private_bindings_required"])
        self.assertTrue(all(v is None for v in request["private_bindings_required"].values()))
        limits = request["proposed_limits_after_separate_approvals"]
        self.assertEqual((limits["boot_attempts"], limits["automatic_retries"]), (1, 0))


class NativePreview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Path("/Library/Developer/CommandLineTools/usr/bin/clang").open("rb") as f:
            cls.clang = Path(f.name)
            if hashlib.file_digest(f, "sha256").hexdigest() != "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba":
                raise RuntimeError("unexpected local Apple compiler")
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.tmp = Path(tmp.name).resolve()
        cls.env = {"HOME": str(cls.tmp), "TMPDIR": str(cls.tmp), "PATH": "/usr/bin:/bin"}
        cls.binary = cls.tmp / "preview"
        subprocess.run([cls.clang, "-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
                        "-arch", "arm64", "-mmacosx-version-min=14", "-fobjc-arc", "-fno-modules", "-Werror",
                        "-framework", "Foundation", "-framework", "Virtualization", PROFILE / "boot-config-preview.m",
                        "-o", cls.binary], cwd=cls.tmp, env=cls.env, check=True, stdin=subprocess.DEVNULL, timeout=45)
        cls.disk = media.WORK / "media-v1/aragorn-arm64.raw"

    def preview(self, path):
        return subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)(deny file-write*)",
                               self.binary, path], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              cwd=self.tmp, env=self.env, timeout=15)

    def test_configuration_readback_matches_isolated_request(self):
        guest = json.loads((PROFILE / "boot-request.json").read_bytes())["guest"]
        with media.opened(self.disk) as original:
            self.assertEqual(os.fstat(original.fileno()).st_size, guest["disk_bytes"])
            proc = self.preview(self.disk)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["schema"], "aragorn/pi-core-boot-config-preview/v1")
        for key in ("cpu_count", "memory_bytes"):
            self.assertEqual(result[key], guest[key])
        self.assertEqual((guest["nvme_controllers"], guest["raw_disks"], result["storage_devices"]), (1, 1, 1))
        self.assertIs(result["nvme_read_only"], guest["attachment_read_only"])
        self.assertEqual((result["serial_ports"], result["serial_input"], result["serial_output_pipe"]),
                         (guest["serial_output_only"], guest["guest_serial_input"], True))
        self.assertEqual(result["empty_devices"], dict.fromkeys(
            ("audio", "console", "shares", "entropy", "graphics", "keyboards", "balloon", "network",
             "pointing", "sockets", "usb", "custom_virtio"), 0))
        self.assertEqual(set(result["trust_selectors"]), {"get_enabled", "get_databases", "enroll", "enable_default_pk"})
        self.assertIs(result["efi_without_store"], True)
        for key in ("variable_store_opened", "vm_created", "boot_observed", "trust_proven", "guest_nvme_observed"):
            self.assertIs(result[key], False, key)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))

    def test_wrong_file_and_symlink_refused_before_configuration(self):
        for name in ("symlink", "wrong-size"):
            with self.subTest(name=name):
                folder = self.tmp
                for part in (name, ".aragorn", "host-preflight", "build-b41", "media-v1"):
                    folder = folder / part
                    folder.mkdir(mode=0o700)
                path = folder / "aragorn-arm64.raw"
                if name == "symlink":
                    path.symlink_to(self.disk)
                else:
                    path.touch(mode=0o400)
                result = self.preview(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
