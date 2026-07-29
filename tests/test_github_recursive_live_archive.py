from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.github_recursive_live_archive import (
    GitHubRecursiveLiveArchiveError,
    verify_github_recursive_live_archive,
)

_EVIDENCE = Path(__file__).parents[1] / "benchmark" / "evidence"
_DECISION_ARCHIVE = _EVIDENCE / (
    "phase1-github-recursive-anthropics-claude-plugins-"
    "hook-development-6b708ace-2026-07-29.tar.gz"
)
_DECISION_INVENTORY = _EVIDENCE / (
    "phase1-github-recursive-anthropics-claude-plugins-"
    "hook-development-6b708ace-2026-07-29.inventory.json"
)
_DECISION_ARCHIVE_DIGEST = (
    "sha256:5c1465dde68a3e40c6d97790809ae24bed9c0320efb3b934fe853a46b0abc292"
)
_DECISION_INVENTORY_DIGEST = (
    "sha256:5ba46a3f1278e7573158022b385b1a233cdd5e451e41c8f6d3e4932eb7effb2c"
)
_DECISION_REQUEST = {
    "schema": "aragorn/github-gateway-request/v1",
    "owner": "anthropics",
    "repository": "claude-plugins-official",
    "commit": "6b708ace50a2a9869c3d21ca7df2b04defc82f2b",
    "skill_path": "plugins/plugin-dev/skills/hook-development",
}


class GitHubRecursiveLiveArchiveTests(unittest.TestCase):
    def test_replays_graph_decision_and_rejects_tampering(self) -> None:
        replay = verify_github_recursive_live_archive(
            _DECISION_ARCHIVE,
            expected_archive_digest=_DECISION_ARCHIVE_DIGEST,
            inventory_path=_DECISION_INVENTORY,
            expected_inventory_digest=_DECISION_INVENTORY_DIGEST,
            expected_request=_DECISION_REQUEST,
        )

        self.assertEqual(replay["archive"]["cas_blob_count"], 35)
        self.assertEqual(replay["static_captured"], 13)
        self.assertEqual(replay["static_total"], 13)
        self.assertEqual(len(replay["unresolved"]), 18)
        self.assertFalse(replay["allow_possible"])
        self.assertEqual(replay["outcome"], "ERROR")
        self.assertEqual(
            replay["decision_digest"],
            ("sha256:be2076bcf7d49127b998befef25b1b26e2a76ef72c5f0ff0d3e30631a5ee6704"),
        )

        with TemporaryDirectory() as temporary:
            forged = Path(temporary) / "forged.tar.gz"
            raw = bytearray(_DECISION_ARCHIVE.read_bytes())
            raw[-1] ^= 1
            forged.write_bytes(raw)
            with self.assertRaisesRegex(
                GitHubRecursiveLiveArchiveError,
                "archive digest changed",
            ):
                verify_github_recursive_live_archive(
                    forged,
                    expected_archive_digest=_DECISION_ARCHIVE_DIGEST,
                    inventory_path=_DECISION_INVENTORY,
                    expected_inventory_digest=_DECISION_INVENTORY_DIGEST,
                )


if __name__ == "__main__":
    unittest.main()
