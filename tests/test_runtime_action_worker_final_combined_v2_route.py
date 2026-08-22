from __future__ import annotations

import hashlib
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(SCRIPTS))

import runtime_action_worker_final_combined_v2_route_systemd_probe as route
from materialize_fixed_admission_probes import transformed_final_combined_v2_probe


class RuntimeActionWorkerFinalCombinedV2RouteTests(unittest.TestCase):
    def test_single_route_reuses_injector_without_promoting_claims(self) -> None:
        capture = SCRIPTS / "capture_runtime_action_worker_final_combined_v2_systemd.sh"
        collector = (
            SCRIPTS / "runtime_action_worker_final_combined_v2_route_systemd_probe.py"
        )
        self.assertEqual(stat.S_IMODE(capture.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(collector.stat().st_mode), 0o755)
        subprocess.run(["sh", "-n", str(capture)], check=True, capture_output=True)
        compile(collector.read_bytes(), str(collector), "exec")

        source = capture.read_text(encoding="utf-8")
        self.assertIn(
            '--final-combined-v2 "$context/route-probe"',
            source,
        )
        self.assertIn("--fresh-session-reset", source)
        self.assertNotIn("route_image=", source)
        self.assertNotIn("Dockerfile.route-v2", source)
        self.assertNotIn("parse_float=", source)
        self.assertIn("parse_constant=", source)

        dockerfile = (
            ROOT
            / "benchmark"
            / "runtime-action-worker-final-combined-v2-systemd"
            / "Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn("COPY route-probe/ /route-input/probe/", dockerfile)
        self.assertIn(
            "ac23d68064c1a904649c6c1064f8c7729768fe516eef1e6d7c2bdc6b4e12d299",
            dockerfile,
        )
        materialized = transformed_final_combined_v2_probe("protected-route-probe.mjs")
        self.assertEqual(
            route._EXPECTED_PROBE,
            {
                "bytes": len(materialized),
                "digest": "sha256:" + hashlib.sha256(materialized).hexdigest(),
            },
        )

        probe = {
            "bytes": 1,
            "digest": "sha256:" + "0" * 64,
            "name": "protected-route-probe.mjs",
        }
        observed = {"route": {"id": route._ROUTE, "status": "OBSERVED"}}
        with (
            mock.patch.object(route, "_probe_record", return_value=probe),
            mock.patch.object(
                route.v1_route, "_run_route", return_value=observed
            ) as delegated,
        ):
            self.assertIs(route._run_route({"TOKEN": "value"}, 123), observed)
        delegated.assert_called_once_with(
            {"TOKEN": "value"},
            {"document": {"probe_bundle": [probe]}},
            123,
        )

        for status in ("OBSERVED", "NOT_TESTED"):
            decision = route._decision(status)
            self.assertEqual(decision["route_observation_status"], status)
            self.assertEqual(decision["route_pass_count"], 0)
            self.assertEqual(decision["route_fail_count"], 0)
            self.assertEqual(decision["route_not_tested_count"], 21)
            self.assertTrue(
                all(decision[key] is False for key in route.combined._ELIGIBILITY_KEYS)
            )


if __name__ == "__main__":
    unittest.main()
