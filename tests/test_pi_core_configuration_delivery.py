"""Data-only configuration delivery: never mounts the test disk or invokes guest code."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import pi_core_configuration_carrier as guest
from scripts import prepare_pi_core_configuration_delivery as delivery
from scripts.pi_core_configuration_delivery_layout import layout
from tests.test_pi_core_configuration_delivery_layout import fixture_configurations


class ConfigurationDeliveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="aragorn-b66-inert-", dir=Path.home() / "Library")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.config = self.base / "config.json"
        configs = fixture_configurations()
        self.raw = canonical_json(configs)
        self.pin = canonical_digest(configs)
        self.config.write_bytes(self.raw)
        self.config.chmod(0o400)
        self.out = self.base / "new"

    def test_pinned_tools_build_and_reopen_only_a_data_image(self):
        _, section = layout(self.raw, self.pin, 100)
        with patch.object(delivery.time, "time", return_value=100):
            reported = delivery.prepare(self.config, self.pin, self.out)
        image = self.out / "config.squashfs"
        disk = self.out / "config.raw"
        outcome = self.out / "outcome.json"
        self.assertEqual(json.loads(outcome.read_bytes()), reported)
        self.assertEqual(reported["schema"], "aragorn/pi-core-private-configuration-carrier/v2")
        self.assertEqual(reported["service_configuration"], section)
        logical, raw = image.read_bytes(), disk.read_bytes()
        self.assertEqual((reported["image_sha256"], reported["image_bytes"]),
                         (hashlib.sha256(logical).hexdigest(), len(logical)))
        self.assertEqual(logical[:4], b"hsqs")
        self.assertEqual(int.from_bytes(logical[40:48], "little"), len(logical))
        self.assertEqual(raw, logical + b"\x00" * (-len(logical) % 1024))
        self.assertEqual((reported["disk_sha256"], reported["disk_bytes"], reported["sector_bytes"]),
                         (hashlib.sha256(raw).hexdigest(), len(raw), 512))
        self.assertEqual({p.name for p in self.out.iterdir()}, {image.name, disk.name, outcome.name})
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in (image, disk, outcome)))
        self.assertTrue(all(reported[key] is False for key in ("mount_authorized", "current_grant_authority",
                                                              "installed_identity_verified", "phase3_exit_eligible")))
        # The actual writer's one decoded file is also consumed by the guest byte
        # verifier. Only its block ioctls are modeled; pread reads the real output.
        with disk.open("rb") as data:
            def geometry(fd, request, buf):
                self.assertEqual(fd, data.fileno())
                return {0x125e: struct.pack("=i", 1), 0x1268: struct.pack("=i", 512),
                        0x80081272: struct.pack("=Q", os.fstat(fd).st_size)}[request]
            with patch.object(guest.fcntl, "ioctl", side_effect=geometry):
                guest._verify_bytes(data.fileno(), {k: reported[k] for k in ("image_sha256", "image_bytes")},
                                    time.monotonic() + 10)

    def test_aligned_and_unaligned_images_produce_only_complete_filesystem_device_blocks(self):
        for length, padded in ((512, 1024), (1024, 1024), (1025, 2048)):
            logical = b"x" * length
            dest = self.base / str(length)
            with self.subTest(length=length), patch.object(delivery, "_make_image", return_value=logical), \
                    patch.object(delivery.image, "decoder", return_value={}), \
                    patch.object(delivery.time, "time", return_value=100):
                reported = delivery.prepare(self.config, self.pin, dest)
                self.assertEqual((dest / "config.raw").read_bytes(), logical + bytes(padded - length))
                self.assertEqual((reported["image_bytes"], reported["disk_bytes"]), (length, padded))

    def test_changed_disk_bytes_or_padding_withhold_publication(self):
        logical = b"x" * 1025
        write = delivery._write
        for name, damaged in (("content", b"y" + logical[1:] + bytes(1023)),
                              ("tail", logical + bytes(1022) + b"\x01"),
                              ("only-sector-rounded", logical + bytes(511)), ("extra-sector", logical + bytes(1535))):
            def damage(parent, filename, raw):
                write(parent, filename, damaged if filename == "config.raw" else raw)
            dest = self.base / name
            with self.subTest(kind=name), patch.object(delivery, "_make_image", return_value=logical), \
                    patch.object(delivery, "_write", side_effect=damage), \
                    patch.object(delivery.image, "decoder", return_value={}), \
                    patch.object(delivery.time, "time", return_value=100), self.assertRaisesRegex(RuntimeError, "disk"):
                delivery.prepare(self.config, self.pin, dest)
            self.assertFalse((dest / "outcome.json").exists())

    def test_grant_expiring_before_publication_withholds_the_outcome(self):
        # Isolate the publication boundary. The verified media path is exercised above.
        with patch.object(delivery, "_make_image", return_value=b"inert-publication-fixture"), \
                patch.object(delivery.time, "time", side_effect=[100, 100, 110]), self.assertRaises(ValueError):
            delivery.prepare(self.config, self.pin, self.out)
        self.assertFalse((self.out / "outcome.json").exists())
        self.assertTrue(self.out.is_dir())

    def test_changed_linux_metadata_or_content_cannot_pass_readback(self):
        members = {"/": (0o700, None), "test": (0o400, b"DATA")}
        original = delivery._pseudo(members)
        for raw in (original.replace(b"400 0 0", b"444 0 0"),
                    original.replace(b"400 0 0", b"400 1 0"), original.replace(b"DATA", b"DATO")):
            self.assertNotEqual(raw, original)
            with self.subTest(raw=raw), self.assertRaises((ValueError, RuntimeError)):
                delivery.verify_pseudo(raw, members)

    def test_ambiguous_input_or_existing_output_never_begins_build(self):
        alias = self.base / "alias"
        alias.symlink_to(self.config)
        self.out.mkdir(mode=0o700)
        marker = self.out / "unrelated"
        marker.write_bytes(b"retain")
        with patch.object(delivery, "_make_image", side_effect=AssertionError("unexpected build")), \
                patch.object(delivery.time, "time", return_value=100):
            for source, dest in ((self.config, self.out), (alias, self.base / "other")):
                with self.subTest(source=source), self.assertRaises((ValueError, OSError, RuntimeError)):
                    delivery.prepare(source, self.pin, dest)
        self.assertEqual(marker.read_bytes(), b"retain")
        self.assertFalse((self.base / "other").exists())
