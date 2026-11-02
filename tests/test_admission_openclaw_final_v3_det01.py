from __future__ import annotations

import base64
import hashlib
import json
import os
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
from scripts import (
    runtime_action_worker_final_combined_v3_det01_systemd_probe as capture,
)
from scripts.materialize_openclaw_final_v3_det01 import (
    materialize_openclaw_final_v3_det01,
)

_ROOT = Path(__file__).resolve().parents[1]


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

    def test_fresh_capture_subfixture_executes_and_is_destroyed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign_root = Path(temporary) / "campaign"
            campaign_root.mkdir(mode=0o755)
            result = capture._run_subfixture(
                campaign_root=campaign_root,
                materializer=(
                    _ROOT / "scripts/materialize_openclaw_final_v3_det01.py"
                ),
                python=Path(sys.executable),
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )
            self.assertEqual(list(campaign_root.iterdir()), [])
            self.assertEqual(
                result["lifecycle"]["before_materialization"]["entries"], []
            )
            self.assertTrue(result["lifecycle"]["fresh_path_observed"])
            self.assertTrue(
                result["lifecycle"]["destroyed_before_capture_return"]
            )
            self.assertEqual(
                result["lifecycle"]["after_destruction"]["entries"], []
            )
            self.assertEqual(
                result["materializer"]["manifest"]["case_id"], "DET-01"
            )
            self.assertEqual(
                [item["role"] for item in result["bundle"]],
                [
                    "probe",
                    "vector",
                    "probe-dependency",
                    "probe-dependency",
                    "probe-dependency",
                    "probe-dependency",
                    "probe-dependency",
                ],
            )
            self.assertEqual(
                [case["case_id"] for case in result["replay"]["document"]["cases"]],
                ["allow", "deny", "error", "review"],
            )

            replay_raw = base64.b64decode(
                result["replay"]["command"]["stdout"]["base64"], validate=True
            )
            hostile_replay = json.loads(replay_raw)
            hostile_replay["cases"][0]["replays"][0]["exit_code"] = False
            with self.assertRaisesRegex(
                capture.Det01CaptureError, "replay determinism changed"
            ):
                capture._verify_replay_shape(
                    canonical_json(hostile_replay) + b"\n",
                    python=Path(sys.executable),
                    root=Path(result["lifecycle"]["root"]),
                )
            for field, value, message in (
                ("adapter", {}, "replay adapter changed"),
                ("environment", {}, "replay environment changed"),
                ("limitations", [], "replay limitations changed"),
                ("unexpected", True, "replay identity changed"),
            ):
                hostile_replay = json.loads(replay_raw)
                hostile_replay[field] = value
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(capture.Det01CaptureError, message),
                ):
                    capture._verify_replay_shape(
                        canonical_json(hostile_replay) + b"\n",
                        python=Path(sys.executable),
                        root=Path(result["lifecycle"]["root"]),
                    )
            qualification_bundle = Path(temporary) / "qualification-bundle"
            materialize_openclaw_final_v3_det01(qualification_bundle)
            verification = verify_openclaw_final_v3_det01_observation(
                replay_raw, bundle_root=qualification_bundle
            )
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

    def test_capture_failure_destroys_partial_subfixture_and_grants_nothing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign_root = Path(temporary) / "campaign"
            campaign_root.mkdir(mode=0o755)
            failed = subprocess.CompletedProcess(
                args=[], returncode=9, stdout=b"", stderr=b"failed"
            )
            with (
                mock.patch.object(capture.subprocess, "run", return_value=failed),
                self.assertRaisesRegex(
                    capture.Det01CaptureError,
                    "materializer did not exit cleanly",
                ),
            ):
                capture._run_subfixture(
                    campaign_root=campaign_root,
                    materializer=(
                        _ROOT / "scripts/materialize_openclaw_final_v3_det01.py"
                    ),
                    python=Path(sys.executable),
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )
            self.assertEqual(list(campaign_root.iterdir()), [])
            failure = capture._failure(capture.Det01CaptureError("bounded"))
            self.assertEqual(
                failure["decision"]["det01_observation_status"], "NOT_TESTED"
            )
            self.assertEqual(failure["decision"]["det01_pass_count"], 0)
            self.assertTrue(
                all(
                    value is False
                    for key, value in failure["decision"].items()
                    if key.endswith("_eligible")
                )
            )

    def test_capture_wrapper_and_child_are_exact_observation_only_plumbing(
        self,
    ) -> None:
        recipe = _ROOT / (
            "scripts/capture_runtime_action_worker_final_combined_v3_"
            "det01_systemd.sh"
        )
        temporary_root = Path(tempfile.gettempdir())
        before = set(temporary_root.glob("aragorn-v3-det01-capture.*"))
        completed = subprocess.run(
            ["sh", str(recipe)],
            cwd=_ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        after = set(temporary_root.glob("aragorn-v3-det01-capture.*"))
        self.assertEqual(completed.returncode, 64)
        self.assertEqual(
            completed.stderr,
            "usage: capture_runtime_action_worker_final_combined_v3_"
            "det01_systemd.sh ABSENT_OUTPUT_PATH\n",
        )
        self.assertEqual(before, after)
        wrapper = recipe.read_text(encoding="utf-8")
        for binding in (
            "a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96",
            "materialize_openclaw_final_v3_det01.py",
            "run_admission_authority_replay.py",
            "subfixture_volume",
            'document.get("case_id")',
            "det01_observation_status",
            "det01_not_tested_count",
            "DET-01 subfixture path remained after collector return",
            "NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ):
            self.assertIn(binding, wrapper)

        generated_source = _ROOT / (
            "scripts/capture_runtime_action_worker_final_combined_v3_"
            "workshop_proposal_apply_systemd.sh"
        )
        transformer = wrapper.partition("<<'PY'\n")[2].partition("\nPY\nchmod")[0]
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "capture.sh"
            generated.touch()
            transformed = subprocess.run(
                [sys.executable, "-", str(generated_source), str(generated)],
                input=transformer,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(transformed.returncode, 0, transformed.stderr)
            generated_text = generated.read_text(encoding="utf-8")
            self.assertIn(
                "removal_id=$(docker container inspect --format "
                "'{{.Id}}' \"$container\" 2>/dev/null || :)",
                generated_text,
            )
            self.assertIn(
                "current_image=$(docker container inspect --format "
                "'{{.Image}}' \"$removal_id\" 2>/dev/null || :)",
                generated_text,
            )
            self.assertIn(
                '"$removal_id" 2>/dev/null || :)',
                generated_text,
            )
            create = "created_volume=$(docker volume create"
            self.assertLess(
                generated_text.index("subfixture_volume_created=1\n" + create),
                generated_text.index(create),
            )
            self.assertNotIn(
                '"$subfixture_volume")\nsubfixture_volume_created=1',
                generated_text,
            )
            for cleanup_binding in (
                "dev.aragorn.source-commit",
                "dev.aragorn.role",
                "final-combined-v3-det01-subfixture",
            ):
                self.assertIn(cleanup_binding, generated_text)
            syntax = subprocess.run(
                ["sh", "-n", str(generated)],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

        dockerfile = _ROOT / (
            "benchmark/runtime-action-worker-final-combined-v3-det01-"
            "systemd/Dockerfile"
        )
        docker = dockerfile.read_text(encoding="utf-8")
        collector = _ROOT / (
            "scripts/runtime_action_worker_final_combined_v3_"
            "det01_systemd_probe.py"
        )
        for binding in (
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f",
            "42af9e1c895a2e63de4c5803b5fb0dfc9aedcef2b164e4d8bd53b4cbf1660081",
            "1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
            "rm -rf -- /campaign",
            "test -z \"$(find /campaign",
        ):
            self.assertIn(binding, docker)
        for path in (recipe, collector):
            raw = path.read_bytes()
            self.assertIn(hashlib.sha256(raw).hexdigest(), docker)
            self.assertIn(str(len(raw)), docker)
        self.assertNotIn("workshop", docker.lower())

        decision = capture._decision("OBSERVED")
        self.assertEqual(
            decision["status"],
            "FINAL_COMBINED_V3_DET01_OBSERVED_PROFILE_NOT_TESTED",
        )
        self.assertEqual(decision["det01_pass_count"], 0)
        self.assertTrue(
            all(
                value is False
                for key, value in decision.items()
                if key.endswith("_eligible")
            )
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
