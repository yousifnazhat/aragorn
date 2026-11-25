"""Trust the original operands and the observed file, not worker output."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from aragorn.local_quickstart_sum_observer import hold_sum_output


class SumObservation(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.result = Path(root.name) / "result.json"
        self.dirfd = os.open(root.name, os.O_DIRECTORY | os.O_RDONLY)
        self.addCleanup(os.close, self.dirfd)

    def place(self, data):
        self.result.write_bytes(data)
        self.result.chmod(0o400)

    def test_extreme_sums_are_exact_observed_bytes(self):
        for operands, result in (
            ((2**31 - 1, 2**31 - 1), b'{"total":4294967294}'),
            ((-2**31, -2**31), b'{"total":-4294967296}'),
        ):
            with self.subTest(operands=operands), hold_sum_output(self.dirfd, operands) as after:
                self.place(result)
                self.assertEqual(after(), result)
                self.result.unlink()

    def test_wrong_or_noncanonical_bytes_never_pass(self):
        for raw in (b'{"total":12}', b'{"total":21}\n'):
            with self.subTest(raw=raw), hold_sum_output(self.dirfd, (8, 13)) as after:
                self.place(raw)
                with self.assertRaises(ValueError):
                    after()
                self.result.unlink()

    def test_rejects_preexisting_name_and_changed_entry_during_read(self):
        self.result.symlink_to("missing")
        with self.assertRaises(ValueError), hold_sum_output(self.dirfd, (8, 13)):
            self.fail("accepted a preexisting dangling link")
        self.result.unlink()
        with hold_sum_output(self.dirfd, (8, 13)) as after:
            self.place(b'{"total":21}')
            real_read = os.read

            def swap_after_read(fd, n):
                data = real_read(fd, n)
                self.result.unlink()
                self.place(data)
                return data

            with patch("aragorn.local_quickstart_sum_observer.os.read", side_effect=swap_after_read):
                with self.assertRaises(ValueError):
                    after()

    def test_rejects_invalid_original_operands(self):
        for pair in ((True, 1), ("8", 13), (2**31, 0), (-2**31 - 1, 1), (1,), (1, 2, 3)):
            with self.subTest(pair=pair), self.assertRaises(ValueError), hold_sum_output(self.dirfd, pair):
                self.fail("accepted an invalid original operand")
