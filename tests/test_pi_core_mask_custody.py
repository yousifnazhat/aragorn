"""Private temporary files only. No guest, kernel observer, mount or external recipient."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from aragorn import pi_core_mask_custody as custody
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class MaskCustodyTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.store, self.receipts = self.root / "independent", self.root / "external"
        self.store.mkdir(0o700)
        self.receipts.mkdir(0o700)
        CAS(self.store)
        uid, gid = self.root.stat().st_uid, self.root.stat().st_gid
        self.enterContext(patch.object(custody.held.provision, "_ROOT_UID", uid))
        self.enterContext(patch.object(custody.held.provision, "_ROOT_GID", gid))
        # Only outer machine-owned ancestors are exempted in this fixture.
        # All owned directories, links, files, modes and CAS IO remain checked.
        outer = {(p.stat().st_dev, p.stat().st_ino) for p in self.root.parents}
        original = custody.held._ancestor
        def ancestor(fd):
            value = os.fstat(fd)
            if (value.st_dev, value.st_ino) not in outer:
                original(fd)
        self.enterContext(patch.object(custody.held, "_ancestor", side_effect=ancestor))
        self.raw = dict(bindings=canonical_json({"boot": "inert", "attempt": "one"}), proof=b'{"fixture":"proof"}',
                        vantage=b'{"fixture":"probe"}', manager=b"1 9 8:1 / / ro - ext4 /dev/sda1 ro\n",
                        worker=b"1 9 8:2 / / ro - ext4 /dev/sda2 ro\n")
        self.paths = dict(store=self.store, receipt_directory=self.receipts, capture_digest=digest(self.raw["bindings"]))
        self.receipt = self.receipts / ("mask-" + self.paths["capture_digest"][7:] + ".json")
        self.roots = custody.check_mask_destinations(store=self.store, receipt_directory=self.receipts,
                                                    deadline=time.monotonic() + 30)

    def retain(self, **updates):
        args = self.paths | {k + "_raw": v for k, v in self.raw.items()} | {
            "deadline": time.monotonic() + 30, "expected_roots": self.roots}
        return custody.retain_mask_observation(**(args | updates))

    def replay(self, pin, **updates):
        return custody.replay_mask_observation(**(self.paths | {"receipt_digest": pin} | updates))

    def test_exact_original_bytes_survive_fresh_read_only_replay(self):
        pin = self.retain()
        self.assertEqual(digest(self.receipt.read_bytes()), pin)
        with patch.object(CAS, "put_expected", side_effect=AssertionError("read-only replay wrote data")), \
             patch.object(CAS, "materialize", side_effect=AssertionError("read-only replay rewrote receipt")):
            self.assertEqual(self.replay(pin), self.raw)
        self.assertEqual(set(self.receipts.iterdir()), {self.receipt})
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o444)

    def test_second_publication_never_replaces_a_receipt_or_fills_an_ambiguous_slot(self):
        pin = self.retain()
        obj = self.receipt.stat()
        with self.assertRaises(FileExistsError):
            self.retain(proof_raw=b'{"other":true}')
        self.assertEqual(self.replay(pin), self.raw)
        self.assertEqual(obj.st_ino, self.receipt.stat().st_ino)
        self.receipt.unlink()
        self.receipt.write_bytes(b"unfinished original")
        with self.assertRaises(FileExistsError):
            self.retain()
        self.assertEqual(self.receipt.read_bytes(), b"unfinished original")

    def test_external_pin_capture_and_all_blob_bytes_are_required(self):
        pin = self.retain()
        with self.assertRaises(ValueError):
            self.replay(digest(b"wrong"))
        with self.assertRaises(FileNotFoundError):
            self.replay(pin, capture_digest=digest(b"another capture"))
        row = json.loads(self.receipt.read_bytes())["members"]["worker"]["sha256"][7:]
        blob = self.store / "blobs" / "sha256" / row[:2] / row[2:]
        blob.chmod(0o600)
        blob.write_bytes(self.raw["manager"])
        with self.assertRaises(CASError):
            self.replay(pin)

    def test_missing_replaced_or_aliased_out_of_store_receipt_never_falls_back_to_the_cas(self):
        pin = self.retain()
        original = self.receipt.read_bytes()
        self.receipt.unlink()
        with self.assertRaises(FileNotFoundError):
            self.replay(pin)
        saved = self.root / "saved"
        saved.write_bytes(original)
        saved.chmod(0o444)
        self.receipt.symlink_to(saved)
        with self.assertRaises(ValueError):
            self.replay(pin)
        self.receipt.unlink()
        os.link(saved, self.receipt)
        with self.assertRaises(ValueError):
            self.replay(pin)

    def test_unsafe_ancestry_missing_uninitialized_or_overlapping_roots_fail_closed(self):
        alias = self.root / "alias"
        alias.symlink_to(self.store, target_is_directory=True)
        absent, empty = self.root / "absent", self.root / "empty"
        empty.mkdir(0o700)
        for update in (dict(receipt_directory=self.store), dict(receipt_directory=self.store / "blobs"),
                       dict(store=self.receipts / "missing"), dict(store=alias), dict(store=absent), dict(store=empty),
                       dict(store=Path("relative"))):
            with self.subTest(update=update), self.assertRaises((ValueError, OSError, RuntimeError, CASError)):
                self.retain(**update)
        self.assertFalse(absent.exists())
        self.assertFalse((empty / "blobs").exists())
        self.store.chmod(0o750)
        with self.assertRaises(RuntimeError):
            self.retain()
        self.store.chmod(0o700)
        self.root.chmod(0o777)
        with self.assertRaises(RuntimeError):
            self.retain()
        self.assertEqual(list(self.receipts.iterdir()), [])

    def test_mixed_noncanonical_truncated_or_oversized_inputs_do_not_publish(self):
        for update in (dict(bindings_raw=b'{"other":true}'), dict(proof_raw=b'{"x":false,"x":true}'),
                       dict(vantage_raw=b'{"probe":1.5}'), dict(bindings_raw=self.raw["bindings"] + b"\n"),
                       dict(worker_raw=self.raw["worker"][:-1]), dict(manager_raw=b"\x00\n"),
                       dict(worker_raw=b"x" * (1 << 20) + b"\n")):
            with self.subTest(member=next(iter(update))), self.assertRaises(ValueError):
                self.retain(**update)
        self.assertFalse(self.receipt.exists())

    def test_replacement_of_nominated_directory_after_preflight_never_receives_a_receipt(self):
        self.receipts.rename(self.root / "original")
        self.receipts.mkdir(0o700)
        with self.assertRaisesRegex(ValueError, "changed after preflight"):
            self.retain()
        self.assertFalse(self.receipt.exists())
        self.assertFalse(list((self.root / "original").iterdir()))

    def test_expiry_before_publication_refuses_and_post_publication_failure_preserves_receipt(self):
        real_put, now = CAS.put_expected, [100.0]
        def expire_after_index(store, stream, **kwargs):
            pin = real_put(store, stream, **kwargs)
            if b"aragorn/pi-core-mask-local-custody/v1" in stream.getvalue():
                now[0] = 140.0
            return pin
        with patch.object(time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(CAS, "put_expected", new=expire_after_index), self.assertRaises(RuntimeError):
            self.retain(deadline=130.0)
        self.assertFalse(self.receipt.exists())
        with patch.object(custody, "_replay", side_effect=OSError("simulated final readback failure")), \
             self.assertRaises(OSError):
            self.retain()
        pin = digest(self.receipt.read_bytes())
        with self.assertRaises(FileExistsError):
            self.retain()
        self.assertEqual(self.replay(pin), self.raw)
