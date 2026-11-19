"""Final media readback and narrow refusal cases; no mounts, rebuilds or guest execution."""
import json
import lzma
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from scripts import inspect_pi_core_guest_disk as read
from scripts import prepare_pi_core_guest_disk as media
from scripts import prepare_pi_core_host_sysroot as ubuntu
from scripts.build_pi_core_linux import BuildError, regular_bytes


class ImmutableDisk(unittest.TestCase):
    def setUp(self):
        self.pin = json.loads(regular_bytes(media.PACK / "media-output.json"))
        self.disk = media.WORK / self.pin["directory"] / "aragorn-arm64.raw"

    def test_three_new_efi_inputs_match_authenticated_release_package_rows(self):
        found = {}
        names = {n.partition("_")[0] for n in media.DEBS}
        for index, digest in ((ubuntu.B38 / "Packages-arm64.xz", ubuntu.MAIN),
                              (ubuntu.WORK / "Packages-universe-arm64.xz", ubuntu.UNIVERSE)):
            raw = regular_bytes(index, 32 << 20)
            self.assertEqual(media.sha256(raw), digest)
            for paragraph in lzma.decompress(raw).decode().split("\n\n"):
                if paragraph.partition("\n")[0].removeprefix("Package: ") not in names:
                    continue
                row = dict(line.split(": ", 1) for line in paragraph.splitlines()
                           if ": " in line and not line.startswith(" "))
                name = Path(row["Filename"]).name
                self.assertNotIn(name, found)
                self.assertIn(name, media.DEBS)
                self.assertIn(row["Architecture"], {"all", "arm64"})
                package = regular_bytes(media.MEDIA_INPUTS / name, 1 << 20)
                self.assertEqual((media.sha256(package), len(package)), (row["SHA256"], int(row["Size"])))
                found[name] = row["SHA256"]
        self.assertEqual(found, {n: spec[0] for n, spec in media.DEBS.items()})

    def test_final_disk_cross_links_to_independent_root_inventory_and_boot_pins(self):
        root = json.loads(regular_bytes(media.PACK / "image-output.json"))
        boot = json.loads(regular_bytes(media.PACK / "boot-artifacts.json"))
        payload = json.loads(regular_bytes(media.PACK / "payload-pins.json"))
        inventory_receipt = regular_bytes(media.WORK / "image" / root["fingerprint"] / "receipt.json")
        self.assertEqual(media.sha256(inventory_receipt), root["receipt_sha256"])
        self.assertEqual(json.loads(inventory_receipt)["payload_sha256"], payload["manifest_sha256"])
        self.assertEqual((root["root_sha256"], root["root_bytes"]),
                         (self.pin["root_sha256"], self.pin["root_size"]))
        self.assertEqual((boot["root_sha256"], boot["root_bytes"]), (root["root_sha256"], root["root_bytes"]))
        for key in ("initramfs_sha256", "kernel_sha256", "cmdline"):
            self.assertEqual(boot[key], self.pin[key], key)
        self.assertEqual(self.pin["cmdline"], media.CMDLINE)
        inspected = read.inspect(self.disk, self.pin)
        self.assertEqual(inspected["disk_sha256"], self.pin["disk_sha256"])
        self.assertFalse(inspected["boot_observed"] or inspected["phase3_exit_eligible"])

    def test_writable_root_is_refused_even_with_valid_table_and_header_crcs(self):
        with media.opened(self.disk) as f:
            f.seek(512)
            h, table = bytearray(f.read(512)), bytearray(f.read(16384))
        struct.pack_into("<Q", table, 128+48, 0)
        struct.pack_into("<I", h, 88, zlib.crc32(table))
        struct.pack_into("<I", h, 16, 0)
        struct.pack_into("<I", h, 16, zlib.crc32(h[:92]))
        with self.assertRaisesRegex(BuildError, "invalid partition"):
            read.gpt(bytes(h), bytes(table), 1, self.pin["disk_bytes"]//512-1, 2)

    def test_pe_machine_substitution_rejected(self):
        pe = bytearray(regular_bytes(self.disk.parent / "BOOTAA64.EFI", 64 << 20))
        offset = int.from_bytes(pe[60:64], "little")
        pe[offset+4:offset+6] = b"\x64\x86"
        with self.assertRaisesRegex(BuildError, "not ARM64 PE"):
            read.sections(pe)

    def test_fat_with_no_boot_sector_is_refused(self):
        with self.assertRaisesRegex(BuildError, "missing FAT32"):
            read.fat_uki(b"", 2048)

    def test_alternate_long_name_or_checksum_cannot_shadow_the_efi_short_name(self):
        slot = bytes.fromhex("4142004f004f00540041000f00544100360034002e0045004600000049000000")
        read.redundant_name(slot, b"BOOTAA64EFI", "BOOTAA64.EFI")
        for pos in (0, 1, 13, 26):
            bad = bytearray(slot)
            bad[pos] ^= 1
            with self.subTest(pos=pos), self.assertRaisesRegex(BuildError, "ambiguous VFAT"):
                read.redundant_name(bad, b"BOOTAA64EFI", "BOOTAA64.EFI")

    def test_reader_refuses_linked_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp).resolve() / "disk"
            link.symlink_to(self.disk)
            with self.assertRaisesRegex(BuildError, "linked or relative"), media.opened(link):
                self.fail("followed symlink")
