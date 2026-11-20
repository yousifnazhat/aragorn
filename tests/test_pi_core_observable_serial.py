"""Inert wire-format fixtures only; no captured boot, device, firmware store or guest execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.build_pi_core_linux import BuildError
from scripts import inspect_pi_core_observable_serial as serial


class SerialReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent fixture expectations from the retained predecessor root/manager, not reader output.
        pins = json.loads((serial.PINS.parent.parent / "immutable-host-b41/boot-artifacts.json").read_bytes())
        cls.boot = "c011ec7e-1000-4abc-a987-123400005678"
        cls.part = (pins["root_bytes"] + 511) // 512 * 512
        cls.line = (f"ARAGORN_B44_V1 boot={cls.boot} disk_ro=1 part_ro=1 sector=512 part_bytes={cls.part} "
                    f"root_ro=1 lib_ro=1 lib_same=1 pid=1 manager_sha256={pins['manager_sha256']} "
                    f"root_sha256={pins['root_sha256']}\n").encode("ascii")

    def test_lf_crlf_preserve_raw_offsets_hash_and_evidence_ceiling(self):
        for row in (self.line, self.line.replace(b"\n", b"\r\n")):
            prefix = b"\xff kernel text\r\n"
            raw = prefix + row + b"other guest output\n"
            got = serial.inspect_serial(raw, expected_boot_id=self.boot)
            start = got["record_offset"]
            self.assertEqual((start, raw[start:start + got["record_bytes"]]), (len(prefix), row))
            self.assertEqual((got["capture_sha256"], got["capture_bytes"]),
                             (hashlib.sha256(raw).hexdigest(), len(raw)))
            self.assertEqual((got["boot_id"], got["external_boot_id_compared"]), (self.boot, True))
            self.assertEqual(got["status"], "matching_guest_record_only")
            self.assertIs(got["host_custody_verified"], False)
            self.assertIs(got["phase3_exit_eligible"], False)
        self.assertIs(serial.inspect_serial(self.line)["external_boot_id_compared"], False)

    def test_even_exact_record_cannot_override_refusal_or_panic(self):
        for bad in (b"aragorn early boot refused: disk\r\n", b"Kernel panic - not syncing: init\n"):
            for raw in (self.line + bad, bad + self.line):
                with self.assertRaisesRegex(BuildError, "refusal or panic"):
                    serial.inspect_serial(raw)

    def test_matching_line_cannot_override_invalid_supplied_media_pins(self):
        pins = json.loads(serial.PINS.read_bytes())
        for field, value in (("schema", "unrelated"), ("boot_observed", 0), ("secure_boot_enrollment", True),
                             ("phase3_exit_eligible", True), ("disk_sha256", ""), ("uki_sha256", None),
                             ("root_size", True), ("sector_size", 4096), ("disk_bytes", pins["disk_bytes"] + 1)):
            with self.subTest(field=field), self.assertRaises(BuildError):
                serial.inspect_serial_with_pins(self.line, pins | {field: value})

    def test_no_inference_from_partial_duplicate_mixed_or_embedded_record(self):
        for raw in (b"", b"started\n", self.line[:-1], self.line + b"incomplete console", self.line + self.line,
                    b"ARAGORN_B43_V1\n" + self.line, b"noise " + self.line,
                    self.line.replace(b"pid=1 ", b"pid=1 pid=1 ")):
            with self.subTest(raw=raw[:30]), self.assertRaises(BuildError):
                serial.inspect_serial(raw)

    def test_wrong_geometry_read_only_mount_identity_and_manager_are_refused(self):
        for old, new in ((b"disk_ro=1", b"disk_ro=0"), (b"part_ro=1", b"part_ro=0"),
                         (b"sector=512", b"sector=4096"), (str(self.part).encode(), b"512"),
                         (b"root_ro=1", b"root_ro=0"), (b"lib_ro=1", b"lib_ro=0"),
                         (b"lib_same=1", b"lib_same=0"), (b"pid=1", b"pid=2"),
                         (b"manager_sha256=6", b"manager_sha256=0"), (b"root_sha256=4", b"root_sha256=0")):
            with self.subTest(field=old), self.assertRaises(BuildError):
                serial.inspect_serial(self.line.replace(old, new))

    def test_uuid_scope_and_capture_limits(self):
        for raw, boot in ((self.line, self.boot[:-1] + "9"),
                          (self.line.replace(b"4abc-a987", b"1abc-0987"), None),
                          (self.line + b"x" * (serial.LIMIT - len(self.line) - 1) + b"\n", None)):
            with self.assertRaises(BuildError):
                serial.inspect_serial(raw, expected_boot_id=boot)

    def test_read_only_file_consumer_joins_external_digest_without_modifying_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "raw"
            path.write_bytes(self.line)
            expected = hashlib.sha256(self.line).hexdigest()
            self.assertEqual(serial.inspect_capture(path, expected)["capture_sha256"], expected)
            with self.assertRaisesRegex(BuildError, "external digest mismatch"):
                serial.inspect_capture(path, "0" * 64)
            self.assertEqual(path.read_bytes(), self.line)
