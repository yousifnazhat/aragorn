from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.protected_coordinator_archive_replay import (
    AUTHORITY,
    ProtectedCoordinatorArchiveReplayError,
    verify_protected_coordinator_archive,
)

_ARCHIVE = (
    Path(__file__).parents[1]
    / "benchmark"
    / "evidence"
    / "phase1-protected-coordinator-live-2d29a19-2026-07-29.tar.gz"
)


class ProtectedCoordinatorArchiveReplayTests(unittest.TestCase):
    def test_exact_archive_replays_without_regranting_live_authority(self) -> None:
        replay = verify_protected_coordinator_archive(_ARCHIVE)

        self.assertEqual(replay["authority"], AUTHORITY)
        self.assertEqual(replay["archive"]["members"], 89)
        self.assertEqual(replay["install"]["cas_blob_count"], 16)
        self.assertEqual(replay["update"]["cas_blob_count"], 17)
        self.assertEqual(replay["install"]["verdict"], "ALLOW")
        self.assertEqual(replay["update"]["verdict"], "ALLOW")
        self.assertEqual(replay["protected_state"]["skill_bytes"], 140)
        self.assertFalse(replay["phase1_exit_eligible"])

        with TemporaryDirectory() as temporary:
            forged = Path(temporary) / "capture.tar.gz"
            raw = bytearray(_ARCHIVE.read_bytes())
            raw[-1] ^= 1
            forged.write_bytes(raw)
            with self.assertRaisesRegex(
                ProtectedCoordinatorArchiveReplayError,
                "archive digest is not the retained identity",
            ):
                verify_protected_coordinator_archive(forged)


if __name__ == "__main__":
    unittest.main()
