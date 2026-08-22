from __future__ import annotations

import stat
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_SCRIPTS))

import runtime_action_worker_final_combined_v2_systemd_probe as probe


class RuntimeActionWorkerFinalCombinedV2BootstrapTests(unittest.TestCase):
    def test_sources_are_runnable(self) -> None:
        capture = (
            _SCRIPTS / "capture_runtime_action_worker_final_combined_v2_systemd.sh"
        )
        probe_path = (
            _SCRIPTS / "runtime_action_worker_final_combined_v2_systemd_probe.py"
        )
        self.assertEqual(stat.S_IMODE(capture.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(probe_path.stat().st_mode), 0o755)
        subprocess.run(["sh", "-n", str(capture)], check=True, capture_output=True)
        compile(probe_path.read_bytes(), str(probe_path), "exec")
        capture_source = capture.read_text(encoding="utf-8")
        self.assertIn(
            'stat -c "%u:%g:%a" /run/aragorn-protected-install', capture_source
        )
        self.assertIn(
            "systemd and protected-install tmpfiles did not become ready",
            capture_source,
        )

    def test_decisions_cannot_promote_the_fresh_profile(self) -> None:
        for observed in (False, True):
            with self.subTest(observed=observed):
                decision = probe._observation_decision(observed)
                self.assertEqual(decision["route_pass_count"], 0)
                self.assertEqual(decision["route_fail_count"], 0)
                self.assertEqual(decision["route_not_tested_count"], 21)
                self.assertEqual(
                    {key for key in decision if key.endswith("_eligible")},
                    probe._ELIGIBILITY_KEYS,
                )
                self.assertTrue(
                    all(decision[key] is False for key in probe._ELIGIBILITY_KEYS)
                )
                self.assertIs(decision["p3_7c_activation_action_observed"], observed)
                self.assertIn("PROFILE_NOT_TESTED", decision["status"])

    def test_route_input_harness_requires_one_exact_read_only_volume(self) -> None:
        source_commit = "a" * 40
        name = "aragorn-phase3-final-combined-v2-route-input-123"
        document = {
            "route_input_mount": {
                "destination": "/route-input",
                "driver": "local",
                "mode": "ro",
                "rw": False,
                "source": name,
                "type": "volume",
            },
            "route_input_volume_identity": {
                "driver": "local",
                "labels": {
                    "dev.aragorn.capture-owner": f"{source_commit}:123",
                    "dev.aragorn.role": "final-combined-v2-route-input",
                    "dev.aragorn.source-commit": source_commit,
                },
                "name": name,
                "options": None,
                "scope": "local",
            },
        }
        self.assertEqual(probe._route_input_volume_name(document, source_commit), name)
        changed = {
            **document,
            "route_input_mount": {**document["route_input_mount"], "rw": True},
        }
        with self.assertRaises(probe.openclaw.ProbeError):
            probe._route_input_volume_name(changed, source_commit)


if __name__ == "__main__":
    unittest.main()
