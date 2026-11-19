"""Only B42's proposed image-hash record. No firmware access or EFI execution."""
import json
import struct
import unittest
import uuid

from scripts import prepare_pi_core_guest_firmware_trust as trust
from scripts import prepare_pi_core_guest_disk as media
from scripts.build_pi_core_linux import BuildError, regular_bytes, sha256


class FirmwareHashProposal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads(regular_bytes(trust.PIN))
        cls.b41 = json.loads(regular_bytes(trust.B41))
        with media.opened(trust.UKI) as f:
            cls.image = f.read(128 << 20)

    def test_exact_retained_esl_independently_decodes(self):
        with media.opened(trust.OUT / trust.FILE) as f:
            record = f.read(77)
        self.assertEqual((len(record), sha256(record)), (76, self.pin["esl_sha256"]))
        self.assertEqual(record, trust.proposal(self.image, self.pin, self.b41))
        self.assertEqual(uuid.UUID(bytes_le=record[:16]), uuid.UUID("c1c41626-504c-4092-aca9-41f936934328"))
        self.assertEqual(struct.unpack_from("<III", record, 16), (76, 0, 48))
        self.assertEqual(str(uuid.UUID(bytes_le=record[28:44])), self.pin["signature_owner"])
        self.assertEqual(record[44:].hex(), self.pin["authenticode_sha256"])
        self.assertNotEqual(record[44:].hex(), self.b41["uki_sha256"])

    def test_same_authenticode_after_checksum_change_is_not_the_pinned_raw_candidate(self):
        data = bytearray(self.image)
        opt = struct.unpack_from("<I", data, 60)[0] + 24
        data[opt + 64] ^= 1
        self.assertEqual(trust.image_hash(data).hex(), self.pin["authenticode_sha256"])
        with self.assertRaisesRegex(BuildError, "whole UKI differs"):
            trust.proposal(data, self.pin, self.b41)

    def test_reject_foreign_certificate_table_or_ambiguous_raw_layout(self):
        data = bytearray(self.image)
        opt = struct.unpack_from("<I", data, 60)[0] + 24
        data[opt + 144] = 1
        with self.assertRaisesRegex(BuildError, "certificate directory"):
            trust.image_hash(data)
        data[opt + 144] = 0
        with self.assertRaisesRegex(BuildError, "overlay"):
            trust.image_hash(data + b"trailing data")
        # Shorten the .rodata raw extent by a sector; the hole must not be ignored.
        start = opt + struct.unpack_from("<H", data, opt - 4)[0]
        table = {bytes(data[p:p+8]).rstrip(b"\0"): p for p in range(
            start, start + 40 * struct.unpack_from("<H", data, opt-18)[0], 40)}
        field = table[b".rodata"] + 16
        struct.pack_into("<I", data, field, struct.unpack_from("<I", data, field)[0] - 512)
        with self.assertRaisesRegex(BuildError, "section gap"):
            trust.image_hash(data)

    def test_proposal_cannot_claim_grant_enrollment_or_phase_completion(self):
        for name in ("firmware_grant", "enrolled", "boot_observed", "phase3_exit_eligible", "firmware_dbx"):
            with self.subTest(field=name), self.assertRaisesRegex(BuildError, "not an inert firmware proposal"):
                trust.proposal(self.image, {**self.pin, name: True}, self.b41)
