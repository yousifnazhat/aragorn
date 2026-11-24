"""B110 private attempt and receipt refusal cases. Files are disposable, never a guest."""
import time
import unittest
from unittest.mock import patch

from aragorn import pi_core_pilot_output_custody as subject
from aragorn.oci_worker_protocol import canonical_json
from tests import test_pi_core_mask_custody as fixture


class PilotOutputCustodyTests(unittest.TestCase):
    def setUp(self):
        private = fixture.MaskCustodyTests()
        self.addCleanup(private.doCleanups)
        private.setUp()
        self.src = dict(schema="aragorn/runtime-protected-path/v1", target_name="result.json",
                        root_device=23, root_inode=101)
        self.attempt, self.activation = "b" * 32, "a" * 32
        self.dst = dict(store=private.store, receipt_directory=private.receipts, attempt_id=self.attempt,
                        expected_path_digest=fixture.digest(canonical_json(self.src)),
                        deployment_digest="sha256:" + "d" * 64, plan_digest="sha256:" + "e" * 64,
                        release_digest="sha256:" + "c" * 64)
        self.live = dict(expected_roots=private.roots, deadline=time.monotonic() + 15)
        raw = b'{"total":3}'
        self.doc = dict(schema="aragorn/pi-core-pilot-output-observation/v1", activation_id=self.activation,
                        path_descriptor=self.src, before="ABSENT", after="PRESENT", file_device=23,
                        file_inode=107, payload_digest=fixture.digest(raw), payload_bytes=len(raw),
                        payload_hex=raw.hex())
        self.names = [private.receipts / n for n in subject._names(self.attempt)]

    def write(self, raw=None, **overrides):
        return subject.retain(**(self.dst | self.live | dict(expected_activation_id=self.activation,
            observation_raw=canonical_json(self.doc) if raw is None else raw) | overrides))

    def test_one_claim_before_start_cannot_be_readopted_by_a_different_plan(self):
        with self.assertRaises(FileNotFoundError):
            self.write()
        with self.assertRaisesRegex(ValueError, "SEPARATE_RELEASE"):
            subject.preflight(**(self.dst | {"release_digest": self.dst["plan_digest"]}), **self.live)
        subject.preflight(**self.dst, **self.live)
        pin = fixture.digest(self.names[0].read_bytes())
        with self.assertRaises(FileExistsError):
            subject.preflight(**self.dst, **self.live)
        with self.assertRaises(ValueError):
            self.write(plan_digest="sha256:" + "3" * 64)
        with self.assertRaises(ValueError):
            self.write(release_digest="sha256:" + "f" * 64)
        with self.assertRaises(ValueError):
            self.write(expected_roots=self.live["expected_roots"][::-1])
        self.assertEqual(fixture.digest(self.names[0].read_bytes()), pin)
        self.assertEqual(list(self.dst["receipt_directory"].iterdir()), self.names[:1])

    def test_bad_raw_or_context_is_refused_before_receipt_or_data_write(self):
        subject.preflight(**self.dst, **self.live)
        with patch.object(subject.CAS, "put_expected", side_effect=AssertionError("private bytes written")):
            for raw in (canonical_json(self.doc | {"extra": "private"}),
                        canonical_json(self.doc | {"payload_hex": "0" * 22}),
                        canonical_json(self.doc | {"activation_id": "8" * 32}),
                        canonical_json(self.doc | {"path_descriptor": self.src | {"root_inode": 100}}),
                        canonical_json(self.doc | {"file_inode": self.src["root_inode"]}),
                        canonical_json(self.doc) + b"\n", b"x" * 2049):
                with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                    self.write(raw)
        self.assertFalse(self.names[1].exists())
        self.assertFalse(self.names[2].exists())

    def test_interrupted_raw_publication_keeps_spent_slot_and_never_retries(self):
        subject.preflight(**self.dst, **self.live)
        original = subject.CAS.put_expected
        raw_pin = fixture.digest(canonical_json(self.doc))

        def interrupt(archive, stream, *, expected_digest, max_bytes):
            if expected_digest == raw_pin:
                raise OSError("inert interruption writing observation")
            return original(archive, stream, expected_digest=expected_digest, max_bytes=max_bytes)

        with patch.object(subject.CAS, "put_expected", interrupt), self.assertRaises(OSError):
            self.write()
        self.assertTrue(self.names[1].is_file())
        self.assertFalse(self.names[2].exists())
        with patch.object(subject.CAS, "put_expected", side_effect=AssertionError("retried")):
            with self.assertRaises(FileExistsError):
                self.write()
            with self.assertRaises(FileExistsError):
                subject.preflight(**self.dst, **self.live)

    def test_complete_receipt_cannot_replace_the_separate_claim_or_publication(self):
        subject.preflight(**self.dst, **self.live)
        pins = self.write()
        with self.assertRaises(FileExistsError):
            self.write()
        with self.assertRaisesRegex(ValueError, "CLAIM"):
            subject.read_retained(**(self.dst | {"release_digest": "sha256:" + "f" * 64}),
                                  **pins, expected_activation_id=self.activation)
        self.names[1].unlink()
        with patch.object(subject.CAS, "put_expected", side_effect=AssertionError("replay mutates archive")):
            with self.assertRaises(FileNotFoundError):
                subject.read_retained(**self.dst, **pins, expected_activation_id=self.activation)
        self.assertTrue(self.names[2].is_file())

    def test_mount_bound_attempt_cannot_omit_or_outlast_its_topology_guard(self):
        for invalid in ({"mount_id": 67}, {"topology_guard": lambda: None}, {"mount_id": True,
                                                                              "topology_guard": lambda: None}):
            with self.subTest(fields=tuple(invalid)), self.assertRaisesRegex(ValueError, "MOUNT|TOPOLOGY"):
                subject.preflight(**self.dst, **self.live, **invalid)
        self.assertFalse(self.names[0].exists())
        with patch.object(subject.custody, "_mount_id", return_value=67):
            subject.preflight(**self.dst, **self.live, mount_id=67, topology_guard=lambda: None)
            with self.assertRaises(ValueError):
                self.write()  # An unguarded publisher cannot consume the guarded claim.

            def lost():
                if self.names[1].exists():
                    raise ValueError("held topology changed")

            with self.assertRaisesRegex(ValueError, "held topology changed"):
                self.write(mount_id=67, topology_guard=lost)
            self.assertTrue(self.names[1].is_file())
            self.assertFalse(self.names[2].exists())
