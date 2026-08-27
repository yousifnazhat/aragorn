from __future__ import annotations

import hashlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PLUGIN_ENABLE_PROBE = (
    ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-plugin-enable-probe.mjs"
)
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(SCRIPTS))

import capture_openclaw_final_combined_v2_session_snapshot_closure as closure
import runtime_action_worker_final_combined_v2_route_systemd_probe as route
from materialize_fixed_admission_probes import (
    materialize,
    transformed_final_combined_v2_probe,
)


class RuntimeActionWorkerFinalCombinedV2RouteTests(unittest.TestCase):
    def test_closure_git_checks_disable_replace_refs(self) -> None:
        signature = (
            b'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
            + closure._SIGNING_KEY.encode()
        )
        with mock.patch.object(
            closure.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout=b"", stderr=signature),
        ) as run:
            self.assertEqual(closure._git(["status", "--porcelain"]), b"")
            closure._verify_signature("a" * 40)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_session_snapshot_compiled_closure_is_deterministic(self) -> None:
        manifest, archive, files = closure._verify_bundle()
        self.assertEqual(manifest["runtime_tree"], closure._RUNTIME_TREE)
        self.assertEqual(tuple(files), closure._PATHS)
        self.assertEqual(len(files), 14)
        self.assertEqual(
            "sha256:" + hashlib.sha256(archive).hexdigest(),
            closure._ARCHIVE_IDENTITY["digest"],
        )
        self.assertEqual(closure.main(["--self-check"]), 0)

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
            '--final-combined-v2 "$context/route-input/fresh-session-reset"',
            source,
        )
        for flag in (
            "--archive-source-force-replacement",
            "--config-entry-activation",
            "--curator-restore-activation",
            "--plugin-enable-activation",
            "--workshop-proposal-apply",
            "--cron-rescan",
            "--fresh-session-reset",
            "--missing-prompt-blob-rebuild",
            "--session-snapshot-consumer",
        ):
            self.assertIn(flag, source)
        self.assertNotIn("route_image=", source)
        self.assertNotIn("Dockerfile.route-v2", source)
        self.assertIn('-v "$route_input_volume:/route-input:ro"', source)
        self.assertIn(
            "benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md",
            source,
        )
        self.assertIn(
            "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
            source,
        )
        self.assertIn(
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-plugin-enable-probe.mjs",
            source,
        )
        self.assertIn(
            'cp "$context/benchmark/admission/openclaw-v2026.7.1/'
            'protected-plugin-enable-probe.mjs"',
            source,
        )
        self.assertNotIn(
            '--final-combined-v2 "$context/route-input/plugin-enable-activation"',
            source,
        )
        for control in (
            "docker run --rm -i --pull=never",
            "--network=none --cap-drop=ALL",
            "--security-opt no-new-privileges:true --read-only --user 0:992",
            "cat > /sources/replacement/SKILL.md",
            '-v "$archive_source_volume:/sources:ro"',
        ):
            self.assertIn(control, source)
        self.assertIn('"route_input_volume_identity": route_volume_identity', source)
        self.assertNotIn("parse_float=", source)
        self.assertIn("parse_constant=", source)
        self.assertNotIn(
            "ADM-02/update/config-entry-activation", route.v1_route._ROUTES
        )

        dockerfile = (
            ROOT
            / "benchmark"
            / "runtime-action-worker-final-combined-v2-systemd"
            / "Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn("COPY route-input/ /route-input/", dockerfile)
        for route_id, specification in route._ROUTES.items():
            workshop = route_id == "ADM-02/update/workshop-proposal-apply"
            for name in specification["files"]:
                materialized = (
                    PLUGIN_ENABLE_PROBE.read_bytes()
                    if route_id == "ADM-02/update/plugin-enable-activation"
                    else transformed_final_combined_v2_probe(
                        name, workshop=workshop
                    )
                )
                expected = {
                    "bytes": len(materialized),
                    "digest": "sha256:" + hashlib.sha256(materialized).hexdigest(),
                }
                actual = (
                    route._EXPECTED_WORKSHOP_PROBE
                    if workshop and name == "protected-route-probe.mjs"
                    else route._EXPECTED_PROBES[name]
                )
                self.assertEqual(actual, expected)
                self.assertIn(expected["digest"][7:], dockerfile)
        self.assertEqual(
            route._ROUTES["ADM-02/update/workshop-proposal-apply"]["fixtures"],
            ("PROPOSAL.md",),
        )
        self.assertEqual(
            route._ROUTES["ADM-02/update/workshop-proposal-apply"]["probe"],
            "protected-route-probe.mjs",
        )
        self.assertEqual(
            route._ROUTES["ADM-02/update/plugin-enable-activation"],
            {
                "files": ("protected-plugin-enable-probe.mjs",),
                "probe": "protected-plugin-enable-probe.mjs",
                "schema": (
                    "aragorn/openclaw-protected-plugin-enable-observation/v1"
                ),
            },
        )

        for route_id in route._ROUTES:
            with self.subTest(route_id=route_id):
                probe_bundle = [
                    {"bytes": 1, "digest": "sha256:" + "0" * 64, "name": name}
                    for name in route._ROUTES[route_id]["files"]
                ]
                observed = {"route": {"id": route_id, "status": "OBSERVED"}}
                with (
                    mock.patch.object(
                        route, "_probe_bundle", return_value=probe_bundle
                    ),
                    mock.patch.object(
                        route.v1_route, "_run_route", return_value=observed
                    ) as delegated,
                ):
                    self.assertIs(
                        route._run_route(route_id, {"TOKEN": "value"}, 123),
                        observed,
                    )
                delegated.assert_called_once_with(
                    {"TOKEN": "value"},
                    {"document": {"probe_bundle": probe_bundle}},
                    123,
                )

        workshop_id = "ADM-02/update/workshop-proposal-apply"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workshop"
            materialize(
                root,
                ["PROPOSAL.md", "protected-route-probe.mjs"],
                final_combined_v2=True,
            )

            def exact_file(path: Path) -> dict[str, object]:
                raw = path.read_bytes()
                return {
                    "bytes": len(raw),
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "stat": {
                        "uid": 0,
                        "gid": 0,
                        "mode": "0444",
                        "nlink": 1,
                    },
                }

            roots = {**route._ROUTE_ROOTS, workshop_id: root}
            with (
                mock.patch.object(route, "_ROUTE_ROOTS", roots),
                mock.patch.object(route.combined.p37c, "_file", side_effect=exact_file),
            ):
                bundle = route._probe_bundle(workshop_id)
                self.assertEqual(
                    [item["role"] for item in bundle], ["fixture", "probe"]
                )
                with (
                    mock.patch.object(route.v1_route, "_ROUTES", route._ROUTES),
                    mock.patch.object(route.v1_route, "_PROBE_ROOT", root),
                    mock.patch.object(route.v1_route, "_SELECTED_ROUTE", workshop_id),
                ):
                    self.assertEqual(
                        route.v1_route._probe_bundle(
                            {"document": {"probe_bundle": bundle}}
                        ),
                        bundle,
                    )

        with mock.patch("sys.stderr"):
            self.assertEqual(route.main([]), 64)
            self.assertEqual(route.main(["unsupported"]), 64)

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
