from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.materialize_fixed_admission_probes import (
    SOURCE_DIGESTS,
    materialize,
    transformed_probe,
    transformed_restore_authority_probe,
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
            workshop = (output / "protected-route-probe.mjs").read_bytes()
            self.assertIn(b'const CONFIG = "/profile/config/openclaw.json";', workshop)
            self.assertIn(b'const WORKSHOP_DRAFT = "/proposal/PROPOSAL.md";', workshop)
            self.assertIn(b'mountObservation(dirname(CONFIG), "directory")', workshop)
            self.assertIn(
                b'mountObservation(dirname(WORKSHOP_DRAFT), "directory")', workshop
            )
            self.assertIn(
                b'from "/runtime/lib/node_modules/openclaw/dist/plugin-sdk/gateway-runtime.js"',
                workshop,
            )
            self.assertIn(b'scopes: ["operator.admin", "operator.write"]', workshop)
            self.assertIn(
                b'trace.not_tested_reason = "PROTECTED_SNAPSHOT_NOT_REBUILT"',
                workshop,
            )
            self.assertIn(
                b"trace.observations.reset_snapshot_cleared = resetSnapshotCleared",
                workshop,
            )
            self.assertIn(
                b"prompt.file.size === EXPECTED_SESSION_PROMPT_BYTES", workshop
            )
            self.assertIn(b"prompt.file.digest_error === null", workshop)
            self.assertIn(
                b"prompt.file.path === EXPECTED_SESSION_PROMPT_PATH", workshop
            )
            self.assertIn(b"trace.observations.rotation_observed_at", workshop)
            self.assertIn(b"rebuild.confirmed &&", workshop)
            self.assertIn(
                b"trace.observations.rebuilt_snapshot_matches_baseline = baselineMatched",
                workshop,
            )
            self.assertIn(b'OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1"', workshop)
            self.assertNotIn(
                b'const reset = normalTurn("fresh-session-reset", "/new");',
                workshop,
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "config-activation-probe.mjs").read_bytes(),
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "live-reload-probe.mjs").read_bytes(),
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "plug01-probe.mjs").read_bytes(),
            )

    def test_materializes_restore_authority_config_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "restore-authority"
            name = "protected-config-activation-probe.mjs"
            materialize(output, [name], restore_authority=True)
            raw = (output / name).read_bytes()
            self.assertEqual(raw, transformed_restore_authority_probe(name))
            self.assertEqual(len(raw), 20_622)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                "bf0cea804669e71bc3fa13df449635e8b703385d139c5845a65c9f054f1a2a07",
            )
            self.assertIn(b"OpenClaw 2026.7.1 (805a4b1)", raw)
            self.assertNotIn(b"4b198daf", raw)
            rejected = Path(temporary) / "unsupported"
            with self.assertRaises(ValueError):
                materialize(rejected, ["probe.mjs"], restore_authority=True)
            self.assertFalse(rejected.exists())


if __name__ == "__main__":
    unittest.main()
