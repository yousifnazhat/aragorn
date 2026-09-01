from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aragorn.admission_openclaw_final_v3_det01 import (
    Det01ObservationError,
    verify_openclaw_final_v3_det01_observation,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.materialize_openclaw_final_v3_det01 import (
    materialize_openclaw_final_v3_det01,
)


class OpenClawFinalV3Det01Tests(unittest.TestCase):
    def test_materialized_bundle_executes_and_semantics_stay_non_authoritative(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "det01"
            repeated = Path(temporary) / "det01-repeated"
            manifest = materialize_openclaw_final_v3_det01(bundle)
            self.assertEqual(
                manifest,
                materialize_openclaw_final_v3_det01(repeated),
            )
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o555)
            self.assertEqual((bundle / "aragorn").stat().st_mode & 0o777, 0o555)
            for item in manifest["files"]:
                path = bundle / item["name"]
                self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                self.assertEqual(path.read_bytes(), (repeated / item["name"]).read_bytes())
            completed = subprocess.run(
                [sys.executable, str(bundle / "run_admission_authority_replay.py")],
                cwd=temporary,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stderr, b"")

            verification = verify_openclaw_final_v3_det01_observation(
                completed.stdout, bundle_root=bundle
            )
            self.assertEqual(verification["case_id"], "DET-01")
            self.assertEqual(
                verification["decision"]["status"],
                "SEMANTIC_OBSERVATION_VERIFIED_NOT_QUALIFIED",
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in verification["decision"].items()
                    if key.endswith("_eligible")
                )
            )
            self.assertNotIn("PASS", json.dumps(verification, sort_keys=True))
            self.assertNotIn("isolation", verification)
            self.assertIn(
                "NO_FRESH_V3_ISOLATED_SUBFIXTURE_CAPTURE_BOUND",
                verification["limitations"],
            )

            tampered = json.loads(completed.stdout)
            tampered["cases"][0]["replays"][0]["exit_code"] = False
            with self.assertRaisesRegex(
                Det01ObservationError, "process exit-code type changed"
            ):
                verify_openclaw_final_v3_det01_observation(
                    canonical_json(tampered) + b"\n", bundle_root=bundle
                )

            for field, value, message in (
                ("schema", "aragorn/hostile/v1", "observation identity changed"),
                ("recorded_at", "2026-02-31T00:00:00.000Z", "recorded_at is invalid"),
            ):
                hostile = json.loads(completed.stdout)
                hostile[field] = value
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(Det01ObservationError, message),
                ):
                    verify_openclaw_final_v3_det01_observation(
                        canonical_json(hostile) + b"\n", bundle_root=bundle
                    )

            hostile = json.loads(completed.stdout)
            hostile["environment"]["profile"]["unexpected"] = "attacker"
            hostile["environment"]["profile_digest"] = canonical_digest(
                hostile["environment"]["profile"]
            )
            with self.assertRaisesRegex(
                Det01ObservationError, "environment profile shape changed"
            ):
                verify_openclaw_final_v3_det01_observation(
                    canonical_json(hostile) + b"\n", bundle_root=bundle
                )

            nested = b'{"a":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}\n"
            with self.assertRaises(Det01ObservationError):
                verify_openclaw_final_v3_det01_observation(nested, bundle_root=bundle)
            with (
                mock.patch(
                    "aragorn.admission_openclaw_final_v3_det01.json.loads",
                    side_effect=RecursionError("hostile nesting"),
                ),
                self.assertRaisesRegex(Det01ObservationError, "not strict JSON"),
            ):
                verify_openclaw_final_v3_det01_observation(
                    completed.stdout, bundle_root=bundle
                )

    def test_rejects_bundle_dependency_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "det01"
            materialize_openclaw_final_v3_det01(bundle)
            runner = bundle / "run_admission_authority_replay.py"
            completed = subprocess.run(
                [sys.executable, str(runner)],
                capture_output=True,
                check=True,
                timeout=30,
            )
            dependency = bundle / "aragorn" / "policy.py"
            dependency.chmod(0o644)
            dependency.write_bytes(dependency.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                Det01ObservationError, "bundle identity changed"
            ):
                verify_openclaw_final_v3_det01_observation(
                    completed.stdout, bundle_root=bundle
                )

if __name__ == "__main__":
    unittest.main()
