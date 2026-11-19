"""Verify the retained build; run only its explicitly held route. No VZ object, store or VM."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from scripts import prepare_pi_core_vm_owner as prep
from scripts.build_pi_core_linux import BuildError, sha256
from scripts.check_pi_core_held_vm_owner import check_hold


class OwnerArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads(prep.PIN.read_bytes())
        cls.dst = prep.WORK / cls.pin["directory"]

    def test_production_code_and_snapshot_match_retained_release(self):
        binary = prep.verified_binary(self.pin)
        inputs = json.loads((self.dst / "inputs.json").read_bytes())
        self.assertEqual(json.loads((self.dst / "receipt.json").read_bytes()), self.pin)
        for p in prep.SOURCES:
            self.assertEqual(sha256(p.read_bytes()), inputs["files"][p.name])
            self.assertEqual(sha256((self.dst / p.name).read_bytes()), inputs["files"][p.name])
        self.assertEqual(inputs["recipe_sha256"], sha256(Path(prep.__file__).read_bytes()))
        self.assertEqual(inputs["b45_recipe_sha256"], sha256(Path(prep.b45.__file__).read_bytes()))
        self.assertEqual(json.loads((self.dst / "owner-release.json").read_bytes()), prep.HOLD)
        self.assertEqual(self.pin["release_sha256"], inputs["files"]["owner-release.json"])
        self.assertEqual(inputs["disk_sha256"], self.pin["disk_sha256"])
        self.assertEqual(inputs["media_pins_sha256"], sha256(prep.binding.MEDIA.read_bytes()))
        self.assertEqual(inputs["request_sha256"], sha256((prep.b45.B44 / "boot-request.json").read_bytes()))
        symbols = subprocess.run(["/usr/bin/nm", "-j", binary], capture_output=True, check=True, timeout=15).stdout.splitlines()
        for s in (b"_B47OwnMachine", b"_B45RecordSerialArmed", b"_OBJC_CLASS_$_B46VMStopBridge", b"_OBJC_CLASS_$_VZVirtualMachine"):
            self.assertIn(s, symbols)
        self.assertNotIn(b"_B47InertMachine", symbols)

    def test_digest_and_active_pin_refused_before_process_creation(self):
        for patch in ({"runner_sha256":"0"*64}, {"boot_authorized":True}, {"directory":"../other"}):
            with self.subTest(patch=patch), self.assertRaises(BuildError):
                prep.verified_binary(dict(self.pin, **patch))

    def test_signed_binary_on_real_watchdog_declines_before_vm_or_target_access(self):
        # Retain the tiny journal on stable local storage, including failed attempts.
        root = Path(tempfile.mkdtemp(dir=prep.WORK, prefix="hold-"))
        uid = str(uuid.uuid4())
        row = check_hold(self.pin, root, uid)
        self.assertIs(row["vm_stopped_verified"], False)
        self.assertIsNone(row["owner_arm"]["ready_raw_ns"])
        print("Retained B47 no-grant refusal:", root / uid, flush=True)
