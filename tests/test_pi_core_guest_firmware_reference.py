"""Independent host-only Authenticode reader, not part of the guest or its trust base."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from scripts import prepare_pi_core_guest_firmware_trust as trust
from scripts.build_pi_core_linux import regular_bytes, sha256


class IndependentFirmwareDigest(unittest.TestCase):
    def test_pinned_lief_reads_same_firmware_digest_from_exact_b41_bytes(self):
        pin = json.loads(regular_bytes(trust.PIN))
        image = regular_bytes(trust.UKI, 32 << 20)
        self.assertEqual(sha256(image), json.loads(regular_bytes(trust.B41))["uki_sha256"])
        wheel = trust.OUT.parent / "reference/lief-1.0.0-cp312-abi3-macosx_11_0_arm64.whl"
        raw = regular_bytes(wheel, 4 << 20)
        self.assertEqual(sha256(raw), "92bf3b06c19a1ebd9e7978de47cc61040752ec452f7906bc3aac8d57abb23a8b")
        with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(io.BytesIO(raw)) as z:
            dest = Path(tmp).resolve()
            (dest / "lief").mkdir(mode=0o700)
            for name in ("lief/__init__.py", "lief/_lief.so"):
                with (dest / name).open("xb") as f:
                    f.write(z.read(name))
            # Parse stdin as data. Neither EFI code nor wheel installation scripts are run.
            code = ("import sys; sys.path.insert(0,sys.argv[1]); import lief; "
                    "print(bytes(lief.PE.parse(sys.stdin.buffer.read()).authentihash_sha256).hex())")
            proc = subprocess.run(["/usr/bin/sandbox-exec", "-p",
                    '(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read* (subpath "/Users"))',
                    sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=/dev/null/pyc", "-c", code, dest],
                    cwd=dest, env={"PATH": "/usr/bin:/bin", "HOME": str(dest)}, input=image,
                    capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
            digest = proc.stdout.decode("ascii").strip()
            self.assertEqual(digest, pin["authenticode_sha256"])
            print("LIEF 1.0.0 Authenticode SHA-256:", digest)
