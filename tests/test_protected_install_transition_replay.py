from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.protected_install_transition_replay import (
    AUTHORITY,
    ProtectedInstallTransitionReplayError,
    verify_protected_install_transition_replay,
)

_ROOT = Path(__file__).parents[1]
_EVIDENCE = _ROOT / "benchmark" / "evidence"
_ARCHIVE = (
    _EVIDENCE / "phase1-protected-install-transition-8924988-2026-07-29.tar.gz"
)
_INSTALL = (
    _EVIDENCE
    / "openclaw-v2026.7.1-agent-skill-protected-service-live-972f368f-2026-07-29.json"
)
_UPDATE = (
    _EVIDENCE
    / "openclaw-v2026.7.1-protected-install-update-live-8924988-2026-07-29.json"
)
_STALE = (
    _EVIDENCE
    / "openclaw-v2026.7.1-protected-install-update-stale-8924988-2026-07-29.json"
)
_CONSUMED = (
    _EVIDENCE
    / "openclaw-v2026.7.1-protected-install-update-consumed-8924988-2026-07-29.json"
)
_CAPTURE = (
    _EVIDENCE
    / "phase1-protected-install-update-live-8924988-2026-07-29.json"
)
_RETENTION = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-protected-install-update-live-retention-8924988-2026-07-29.json"
)


class ProtectedInstallTransitionReplayTests(unittest.TestCase):
    def test_exact_capture_replays_without_regranting_live_custody(self) -> None:
        replay = verify_protected_install_transition_replay(
            _ARCHIVE,
            _INSTALL,
            _UPDATE,
            _CONSUMED,
            _STALE,
            _CAPTURE,
        )

        self.assertEqual(replay["authority"], AUTHORITY)
        self.assertEqual(replay["install"]["blob_count"], 16)
        self.assertEqual(replay["install"]["closure"], "exact")
        self.assertEqual(replay["update"]["blob_count"], 23)
        self.assertEqual(replay["update"]["positive_closure_blob_count"], 17)
        self.assertEqual(replay["negative_extra_chains"]["blob_count"], 6)
        self.assertEqual(replay["negative_extra_chains"]["chain_count"], 2)
        self.assertEqual(replay["installed"]["install"]["skill_bytes"], 140)
        self.assertEqual(replay["installed"]["update"]["skill_bytes"], 309)
        self.assertEqual(
            replay["custody_replay"],
            "HISTORICAL_VALUES_BOUND_BUT_DEVICE_INODE_CUSTODY_NOT_REATTESTED",
        )
        self.assertFalse(replay["phase1_exit_eligible"])

        retention = json.loads(_RETENTION.read_bytes())
        self.assertEqual(retention["replay"]["status"], "PASS")
        self.assertFalse(retention["phase1_exit_eligible"])
        for item in retention["evidence"].values():
            retained = _ROOT / item["path"]
            raw = retained.read_bytes()
            self.assertEqual(len(raw), item["file_bytes"])
            self.assertEqual(
                "sha256:" + hashlib.sha256(raw).hexdigest(),
                item["file_digest"],
            )

        with TemporaryDirectory() as temporary:
            forged = Path(temporary) / "update.json"
            forged.write_bytes(_UPDATE.read_bytes().replace(b'"PASS"', b'"FAIL"', 1))
            with self.assertRaisesRegex(
                ProtectedInstallTransitionReplayError,
                "update evidence digest is not the retained identity",
            ):
                verify_protected_install_transition_replay(
                    _ARCHIVE,
                    _INSTALL,
                    forged,
                    _CONSUMED,
                    _STALE,
                    _CAPTURE,
                )


if __name__ == "__main__":
    unittest.main()
