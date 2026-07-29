from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_PRODUCER = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-install-broker.py"
)


@unittest.skipUnless(os.name == "posix", "protected install requires POSIX")
class ProtectedInstallBrokerProducerTests(unittest.TestCase):
    def test_real_chain_and_negative_attempts_are_local_and_fail_closed(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir(mode=0o700)
            runtime_digest = "sha256:" + "1" * 64
            conformance_digest = "sha256:" + "2" * 64
            completed = subprocess.run(
                [
                    sys.executable,
                    str(_PRODUCER),
                    "--cas-root",
                    str(root / "cas"),
                    "--protected-root",
                    str(protected),
                    "--expected-broker-uid",
                    str(os.geteuid()),
                    "--now-unix",
                    "100",
                    "--expires-at-unix",
                    "200",
                    "--target-runtime-digest",
                    runtime_digest,
                    "--runtime-conformance-digest",
                    conformance_digest,
                ],
                capture_output=True,
                check=False,
                cwd=_ROOT,
                timeout=20,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stderr, b"")
            receipt = json.loads(completed.stdout)
            self.assertEqual(
                completed.stdout,
                canonical_json(receipt) + b"\n",
            )
            self.assertEqual(receipt["slice_status"], "PASS")
            self.assertEqual(
                receipt["assurance"],
                "LOCAL_BROKER_CONFORMANCE_ONLY_NOT_INSTALLER_AUTHORITY",
            )
            self.assertFalse(receipt["decision"]["installer_work_eligible"])
            self.assertEqual(
                [item["operation"] for item in receipt["transactions"]],
                ["install", "update", "rollback"],
            )
            self.assertNotEqual(
                receipt["transactions"][0]["version_path"],
                receipt["transactions"][2]["version_path"],
            )
            self.assertEqual(
                [item["attempt"] for item in receipt["negative_attempts"]],
                ["replay", "stale", "revoked"],
            )
            self.assertTrue(
                all(
                    item["status"] == "BLOCKED"
                    and item["bounded_tree_snapshot_unchanged"]
                    and item["bounded_tree_snapshot_digest_before"]
                    == item["bounded_tree_snapshot_digest_after"]
                    for item in receipt["negative_attempts"]
                )
            )
            self.assertIn(
                "OPENCLAW_RUNTIME_COMPOSITION_MUST_PIN_AGENTS_DEFAULTS_SANDBOX_MODE_OFF",
                receipt["limitations"],
            )
            self.assertIn(
                "SELF_FED_CONTEXT_AND_RUNTIME_DIGESTS_NOT_INDEPENDENT_TRUST_ANCHORS",
                receipt["limitations"],
            )
            self.assertIn(
                "CLAIM_TIME_REUSES_PRE_STAGING_CLOCK_NOT_EXPIRY_OR_REVOCATION_FRESHNESS",
                receipt["limitations"],
            )

            active = protected / "aragorn-admitted"
            self.assertTrue(active.is_symlink())
            self.assertIn(
                b"aragorn-broker-v1",
                (active / "SKILL.md").read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE((active / "SKILL.md").stat().st_mode),
                0o444,
            )
            claims = list((protected / ".aragorn-install-claims").glob("*.json"))
            versions = list(
                (protected / ".aragorn-versions" / "aragorn-admitted").iterdir()
            )
            self.assertEqual(len(claims), 3)
            self.assertEqual(len(versions), 3)
            self.assertEqual(
                sorted(path.name for path in protected.iterdir()),
                [
                    ".aragorn-install-claims",
                    ".aragorn-versions",
                    "aragorn-admitted",
                ],
            )
            self.assertLess(len(completed.stdout), 64 * 1024)

            overlapping = root / "overlapping"
            overlapping.mkdir(mode=0o700)
            rejected = subprocess.run(
                [
                    sys.executable,
                    str(_PRODUCER),
                    "--cas-root",
                    str(overlapping / "cas"),
                    "--protected-root",
                    str(overlapping),
                    "--expected-broker-uid",
                    str(os.geteuid()),
                    "--now-unix",
                    "100",
                    "--expires-at-unix",
                    "200",
                    "--target-runtime-digest",
                    runtime_digest,
                    "--runtime-conformance-digest",
                    conformance_digest,
                ],
                capture_output=True,
                check=False,
                cwd=_ROOT,
                timeout=5,
            )
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(
                json.loads(rejected.stdout)["error"]["message"],
                "CAS and protected roots must be disjoint",
            )


if __name__ == "__main__":
    unittest.main()
