from __future__ import annotations

import hashlib
import json
import sys
import unittest
from unittest import mock
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
        self.assertIn(
            'cp "$context/benchmark/admission/openclaw-v2026.7.1/'
            'protected-plugin-enable-probe.mjs"',
            capture,
        )
        self.assertIn(
            '"$context/route-input/plugin-enable-activation/'
            'protected-plugin-enable-probe.mjs"',
            capture,
        )
        self.assertIn(
            "COPY route-input/fresh-session-reset/protected-route-probe.mjs "
            "/src/benchmark/admission/openclaw-v2026.7.1/"
            "protected-route-probe.mjs",
            capture,
        )
        self.assertIn("--privileged --cgroupns=host --network=none", capture)
        self.assertIn("-v /sys/fs/cgroup:/sys/fs/cgroup:rw", capture)
        self.assertIn("/run/systemd/private", capture)
        self.assertNotIn("while :; do sleep 3600; done", capture)

    def test_one_route_slice_stays_bound_observed_and_non_promoting(self) -> None:
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
            probe._decision_document("NOT_TESTED", route_observed_count=1),
            {
                "status": "NOT_TESTED",
                "semantic_pass_verified": False,
                "property_not_tested_count": 2,
                "formal_category_not_tested_count": 8,
                "route_observed_count": 1,
                "route_fail_count": 0,
                "route_not_tested_count": 20,
                "adm03_not_tested_count": 2,
                **{key: False for key in sorted(probe._ELIGIBILITY_KEYS)},
            },
        )
        with self.assertRaisesRegex(probe.CaptureError, "observation count"):
            probe._decision_document("NOT_TESTED", route_observed_count=2)
        bindings = {
            "suite": {
                "digest": "sha256:" + "1" * 64,
                "observation_helper_digest": helper_digest,
            }
        }
        artifact = {
            "digest": "sha256:" + "2" * 64,
            "path": probe._ROUTE_SLICE_ARTIFACT,
            "schema": probe._BOUND_EVIDENCE_SCHEMA,
        }
        main = probe._main_input("a" * 64, bindings, artifact)
        adm03 = probe._adm03_input("a" * 64, bindings)
        rows = [
            *main["properties"],
            *main["formal_categories"],
            *main["routes"],
            *adm03["scenarios"],
        ]
        self.assertEqual(len(main["routes"]), 21)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))
        self.assertEqual(main["artifacts"], [artifact])
        observed = [row for row in main["routes"] if row["status"] == "OBSERVED"]
        self.assertEqual(
            observed,
            [
                {
                    "evidence_refs": [artifact["digest"]],
                    "id": probe._ROUTE_SLICE_ID,
                    "reason_codes": [probe._ROUTE_SLICE_REASON],
                    "status": "OBSERVED",
                }
            ],
        )
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
                if row["id"] != probe._ROUTE_SLICE_ID
            )
        )
        bound = probe._bound_route_artifact_document(
            "a" * 64,
            bindings,
            {"decision": {"aggregate_admission_eligible": False}},
            "sha256:" + "3" * 64,
        )
        self.assertEqual(
            set(bound),
            {
                "bindings",
                "mode",
                "observation",
                "probe_digest",
                "probe_module",
                "run_nonce",
                "schema",
            },
        )
        probe._reject_promoted_eligibility(bound["observation"])
        with self.assertRaisesRegex(probe.CaptureError, "promoted eligibility"):
            probe._reject_promoted_eligibility(
                {"nested": {"aggregate_admission_eligible": True}}
            )
        with self.assertRaisesRegex(probe.CaptureError, "duplicate JSON key"):
            probe._json(b'{"schema":"one","schema":"two"}\n', "duplicate")

    def test_route_slice_validator_recomputes_retained_raw_shape(self) -> None:
        retained = json.loads(
            (
                ROOT
                / "benchmark"
                / "evidence"
                / (
                    "runtime-action-worker-final-combined-v2-route-fresh-session-"
                    "reset-systemd-p3-final-catalog-fixed-2026-08-22.json"
                )
            ).read_bytes()
        )
        with mock.patch.object(probe.route_probe, "_collect", return_value=retained):
            observed = probe._route_slice_observation()
        self.assertEqual(observed["route_id"], probe._ROUTE_SLICE_ID)
        self.assertEqual(observed["decision"]["route_observation_status"], "OBSERVED")
        opaque = probe._retained_route_slice_observation(observed)
        self.assertEqual(
            json.loads(probe._raw_record(opaque["route_capture"], "route capture")),
            retained,
        )

        hostile = {**retained, "decision": {**retained["decision"]}}
        hostile["decision"]["aggregate_admission_eligible"] = True
        with (
            mock.patch.object(probe.route_probe, "_collect", return_value=hostile),
            self.assertRaisesRegex(probe.CaptureError, "promoted eligibility"),
        ):
            probe._route_slice_observation()


if __name__ == "__main__":
    unittest.main()
