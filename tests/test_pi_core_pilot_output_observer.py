"""Offline tests with disposable local files, not evidence of a pilot attempt."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts.pi_core_pilot_output_observer import hold_pilot_output


class PilotOutputObserverTests(TestCase):
    payload = b'{"total":3}'  # B95 oracle: the trailing newline would be a different output.
    payload_pin = "sha256:9f827af5202050f264dfa05aeec4603d0fcec968de43ed7b039ce6a2d6231b08"
    activation_id = "1" * 32

    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.out = self.root / "protected"
        self.out.mkdir(mode=0o700)
        self.fd = os.open(self.out, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        st = os.fstat(self.fd)
        self.descriptor = dict(schema="aragorn/runtime-protected-path/v1", root_device=st.st_dev,
                               root_inode=st.st_ino, target_name="result.json")
        self.target = self.out / "result.json"

    def hold(self, descriptor=None):
        return hold_pilot_output(self.fd, self.descriptor if descriptor is None else descriptor,
                                 expected_activation_id=self.activation_id)

    @staticmethod
    def write(path, payload, *, mode=0o400):
        with path.open("xb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(payload)

    def test_reads_exact_public_bytes_from_original_directory_once(self):
        with self.hold() as after:
            held = self.root / "still-held"
            self.out.rename(held)
            self.out.mkdir(mode=0o700)
            self.write(self.target, b'{"total":9}')  # decoy at the former path
            real = held / self.descriptor["target_name"]
            self.write(real, self.payload)
            st = real.stat()
            got = after()
            self.assertEqual(got["schema"], "aragorn/pi-core-pilot-output-observation/v1")
            self.assertEqual((got["path_descriptor"], got["activation_id"]), (self.descriptor, self.activation_id))
            self.assertEqual((got["before"], got["after"]), ("ABSENT", "PRESENT"))
            self.assertEqual((got["payload_bytes"], got["payload_digest"]), (11, self.payload_pin))
            self.assertEqual((got["file_device"], got["file_inode"]), (st.st_dev, st.st_ino))
            with self.assertRaises((ValueError, OSError)):
                after()
        self.assertEqual(os.fstat(self.fd).st_ino, self.descriptor["root_inode"])

    def test_refuses_wrong_directory_name_or_preexisting_target_before_yield(self):
        for field, value in (("root_inode", self.root.stat().st_ino), ("target_name", "other.json")):
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                with self.hold({**self.descriptor, field: value}):
                    self.fail("observer accepted the wrong nomination")
        self.write(self.target, self.payload)
        with self.assertRaises((ValueError, OSError)):
            with self.hold():
                self.fail("observer treated a preexisting result as absent")

    def test_absent_wrong_bytes_or_link_cannot_be_repaired_and_retried(self):
        original = self.root / "original"
        self.write(original, self.payload)
        for case in ("absent", "same-size-wrong", "trailing-lf", "wrong-mode", "symlink", "hardlink"):
            with self.subTest(case=case), self.hold() as after:
                if case == "same-size-wrong":
                    self.write(self.target, b'{"total":4}')
                elif case == "trailing-lf":
                    self.write(self.target, self.payload + b"\n")
                elif case == "wrong-mode":
                    self.write(self.target, self.payload, mode=0o600)
                elif case == "symlink":
                    self.target.symlink_to(original)
                elif case == "hardlink":
                    os.link(original, self.target)
                with self.assertRaises((ValueError, OSError)):
                    after()
                self.target.unlink(missing_ok=True)
                self.write(self.target, self.payload)
                with self.assertRaises((ValueError, OSError)):
                    after()
                self.target.unlink()
