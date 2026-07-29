from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.github_gateway_live_evidence import (
    AUTHORITY,
    GitHubGatewayLiveEvidenceError,
    verify_github_gateway_live_evidence,
)

_EVIDENCE = (
    Path(__file__).parents[1]
    / "benchmark"
    / "evidence"
    / "github-gateway-anthropics-template-live-2026-07-29.json"
)


class GitHubGatewayLiveEvidenceTests(unittest.TestCase):
    def test_exact_live_capture_replays_without_granting_authority(self) -> None:
        evidence = json.loads(_EVIDENCE.read_bytes())

        verified = verify_github_gateway_live_evidence(evidence)

        self.assertEqual(verified["authority"], AUTHORITY)
        self.assertEqual(
            verified["assurance"]["custody_replay"],
            "LIVE_LINUX_DEVICE_INODE_AND_ROOT_CUSTODY_NOT_REPLAYABLE_ON_MACOS",
        )

        forged = deepcopy(evidence)
        forged["negative"]["cleanup"]["uid_999_processes"] = 1
        with self.assertRaisesRegex(
            GitHubGatewayLiveEvidenceError,
            "digest is not the retained identity",
        ):
            verify_github_gateway_live_evidence(forged)


if __name__ == "__main__":
    unittest.main()
