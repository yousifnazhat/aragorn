"""Inspect Darwin storage descriptors only; no VZVirtualMachine, EFI, guest, or disk writes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import prepare_pi_core_guest_disk as media


class HostAttachment(unittest.TestCase):
    def test_retained_raw_path_accepted_as_readonly_nvme_descriptor(self):
        pin = json.loads((media.PACK / "media-output.json").read_bytes())
        path = media.WORK / pin["directory"] / "aragorn-arm64.raw"
        sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk")
        clang = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        headers = sdk / "System/Library/Frameworks/Virtualization.framework/Headers"
        for file, digest in (
            (clang, "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba"),
            (headers / "VZNVMExpressControllerDeviceConfiguration.h", "91021e578f51d4c35f358c62c6c7cc052cb7f9432650af7829c208a65c7ddc17"),
            (headers / "VZDiskImageStorageDeviceAttachment.h", "70d1d99ce2f698b04dc4a65f865f0e44d1f65cf501b2f9ae698215c8a478cbb2"),
        ):
            with file.open("rb") as f:
                self.assertEqual(hashlib.file_digest(f, "sha256").hexdigest(), digest)
        with tempfile.TemporaryDirectory() as tmp, media.opened(path) as original:
            st = os.fstat(original.fileno())
            self.assertEqual((st.st_mode & 0o777, st.st_size), (0o400, pin["disk_bytes"]))
            self.assertEqual(st.st_size % 512, 0)
            dest = Path(tmp).resolve()
            src = media.PACK.parent / "immutable-host-b42/vz-attachment.m"
            binary = dest / "probe"
            env = {"PATH": "/usr/bin:/bin", "TMPDIR": str(dest), "HOME": str(dest)}
            subprocess.run([clang, "-isysroot", sdk, "-arch", "arm64", "-mmacosx-version-min=14",
                            "-fobjc-arc", "-fno-modules", "-Werror", "-framework", "Foundation",
                            "-framework", "Virtualization", src, "-o", binary], cwd=dest, env=env,
                           stdin=subprocess.DEVNULL, timeout=45, check=True)
            proc = subprocess.run(["/usr/bin/sandbox-exec", "-p",
                    "(version 1)(allow default)(deny network*)(deny file-write*)", binary, path],
                    cwd=dest, env=env, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(),
                             "host: raw read-only attachment accepted by NVMe descriptor; guest: not observed")
            print(proc.stdout.strip())
