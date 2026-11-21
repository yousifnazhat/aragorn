"""Data-only B66 delivery: never mounts the test image or invokes guest code."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
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
        outcome = self.out / "outcome.json"
        self.assertEqual(json.loads(outcome.read_bytes()), reported)
        self.assertEqual(reported["service_configuration"], section)
        self.assertEqual(reported["image_sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
        self.assertEqual(image.read_bytes()[:4], b"hsqs")
        self.assertEqual({p.name for p in self.out.iterdir()}, {image.name, outcome.name})
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in (image, outcome)))
        self.assertTrue(all(reported[key] is False for key in ("mount_authorized", "current_grant_authority",
                                                              "installed_identity_verified", "phase3_exit_eligible")))

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
