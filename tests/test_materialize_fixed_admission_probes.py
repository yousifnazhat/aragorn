from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.materialize_fixed_admission_probes import (
    SOURCE_DIGESTS,
    materialize,
    transformed_probe,
)


class FixedAdmissionProbeMaterializerTests(unittest.TestCase):
    def test_materializes_every_pinned_probe_without_parent_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixed"
            materialize(output, list(SOURCE_DIGESTS))
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                sorted(SOURCE_DIGESTS),
            )
            for path in output.iterdir():
                raw = path.read_bytes()
                self.assertEqual(raw, transformed_probe(path.name))
                self.assertNotIn(b"2d2ddc43", raw)
                self.assertNotIn(b"475772bbb9", raw)
                self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                self.assertEqual(len(hashlib.sha256(raw).digest()), 32)
            cron = (output / "protected-cron-rescan-probe.mjs").read_bytes()
            self.assertIn(b"cron-snapshot.runtime-DzbSus3I.js", cron)
            self.assertIn(b"session-snapshot-CMKRWMg1.js", cron)


if __name__ == "__main__":
    unittest.main()
