"""Only the new ambiguity and firmware-entry checks. No mounts or image rebuild."""
import json
import struct
import unittest

from scripts import inspect_pi_core_guest_disk as reader
from scripts import prepare_pi_core_guest_disk as media
from scripts.build_pi_core_linux import BuildError, regular_bytes


class FirmwareReadback(unittest.TestCase):
    def test_reject_contradictory_fat32_or_mirroring_fields(self):
        for pos, value in ((17, 512), (19, 128), (22, 16), (40, 0x81), (42, 1)):
            with self.subTest(pos=pos), self.assertRaisesRegex(BuildError, "conflicting FAT32"):
                boot = bytearray(512)
                struct.pack_into("<H", boot, pos, value)
                reader.fat_uki(boot, 2048)

    def test_reject_changed_efi_entry_code_mapping_and_execute_flags(self):
        pin = json.loads(regular_bytes(media.PACK / "media-output.json"))
        with media.opened(media.WORK / pin["directory"] / "BOOTAA64.EFI") as f:
            # All mutations are in the headers or entry code; keep the actual UKI unchanged.
            pe = bytearray(f.read())
        p = struct.unpack_from("<I", pe, 60)[0]
        optional = p + 24
        first = optional + struct.unpack_from("<H", pe, p+20)[0]
        table = {bytes(pe[s:s+8]).rstrip(b"\0"): s for s in range(
            first, first+40*struct.unpack_from("<H", pe, p+6)[0], 40)}
        text, ro = table[b".text"], table[b".rodata"]
        rva, _, raw = struct.unpack_from("<III", pe, text+12)
        entry = struct.unpack_from("<I", pe, optional+16)[0]
        for pos, change, error in (
                (optional+16, struct.pack("<I", entry+4), "unexpected firmware entrypoint"),
                (raw+entry-rva, bytes([pe[raw+entry-rva] ^ 1]), "unapproved firmware entry code"),
                (text+36, struct.pack("<I", 0x40000020), "unapproved firmware entry code"),
                (ro+36, struct.pack("<I", 0x60000040), "unexpected executable firmware section"),
                (ro+12, struct.pack("<I", rva), "invalid mapped PE sections")):
            orig = pe[pos:pos+len(change)]
            pe[pos:pos+len(change)] = change
            with self.subTest(pos=pos), self.assertRaisesRegex(BuildError, error):
                reader.sections(memoryview(pe))
            pe[pos:pos+len(change)] = orig
