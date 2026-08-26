from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import openclaw_final_admission_v2_systemd_probe as probe


class FinalAdmissionV2SystemdProbeTests(unittest.TestCase):
    def test_capture_materializes_the_v2_base_route_input(self) -> None:
        capture = (
            ROOT / "scripts" / "capture_openclaw_final_admission_v2_systemd.sh"
        ).read_text(encoding="utf-8")
        for support in (
            "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
            "scripts/materialize_fixed_admission_probes.py",
            "scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
            "scripts/runtime_action_worker_final_route_systemd_probe.py",
        ):
            self.assertIn(support, capture)
        for route in (
            "archive-source-force-replacement",
            "config-entry-activation",
            "cron-rescan",
            "curator-restore-activation",
            "workshop-proposal-apply",
            "fresh-session-reset",
            "missing-prompt-blob-rebuild",
            "session-snapshot-consumer",
        ):
            self.assertIn(
                f'--final-combined-v2 "$context/route-input/{route}"', capture
            )
        self.assertLess(capture.index("--final-combined-v2"), capture.index("docker build"))

    def test_empty_scaffold_stays_bound_and_not_tested(self) -> None:
        required = (
            "ARAGORN_CONFIG_PATH",
            "ARAGORN_PROBE_ROOT",
            "ARAGORN_PROFILE_PATH",
            "ARAGORN_RUNTIME_LOCK_PATH",
            "ARAGORN_RUNTIME_ROOT",
            "ARAGORN_RUN_NONCE",
            "ARAGORN_SKILL_PATH",
        )
        self.assertEqual(probe._REQUIRED_ENV, required)
        self.assertEqual(
            tuple(probe._suite_environment("a" * 64, Path("/runtime"), Path("/probe"))),
            required,
        )

        helper = (
            ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "protected-observation-v1.mjs"
        ).read_bytes()
        helper_digest = "sha256:" + hashlib.sha256(helper).hexdigest()
        self.assertEqual(helper_digest, probe._EXPECTED_OBSERVATION_HELPER_DIGEST)
        self.assertEqual(
            probe._decision_document("NOT_TESTED"),
            {
                "status": "NOT_TESTED",
                "semantic_pass_verified": False,
                "property_not_tested_count": 2,
                "formal_category_not_tested_count": 8,
                "route_observed_count": 0,
                "route_fail_count": 0,
                "route_not_tested_count": 21,
                "adm03_not_tested_count": 2,
                **{key: False for key in sorted(probe._ELIGIBILITY_KEYS)},
            },
        )
        bindings = {
            "suite": {
                "digest": "sha256:" + "1" * 64,
                "observation_helper_digest": helper_digest,
            }
        }
        main = probe._main_input("a" * 64, bindings)
        adm03 = probe._adm03_input("a" * 64, bindings)
        rows = [
            *main["properties"],
            *main["formal_categories"],
            *main["routes"],
            *adm03["scenarios"],
        ]
        self.assertEqual(len(main["routes"]), 21)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))
        self.assertTrue(
            all(
                row
                == {
                    "evidence_refs": [],
                    "id": row["id"],
                    "reason_codes": ["SEMANTIC_EVIDENCE_NOT_PRODUCED"],
                    "status": "NOT_TESTED",
                }
                for row in rows
            )
        )
        with self.assertRaisesRegex(probe.CaptureError, "duplicate JSON key"):
            probe._json(b'{"schema":"one","schema":"two"}\n', "duplicate")


if __name__ == "__main__":
    unittest.main()
