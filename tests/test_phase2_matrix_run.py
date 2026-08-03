from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

from aragorn.acquire import inventory_local
from aragorn.behavior_capability_diff import derive_behavior_capability_diff
from aragorn.benchmark import _digest_json, load_suite_for_run
from aragorn.cas import CAS
from aragorn.gvisor_runtime import ARTIFACT_SCHEMA_V4, ARTIFACT_SCHEMA_V5
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase2_matrix_run import (
    Phase2MatrixRunError,
    run_phase2_matrix,
)

_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_FAMILIES = (
    "agent-propagation",
    "credential-exfiltration",
    "destructive-action",
    "persistence",
    "prompt-obfuscation",
    "remote-code-bootstrap",
    "tool-poisoning",
)


class Phase2MatrixRunTests(unittest.TestCase):
    def test_runs_exact_serial_matrix_and_publishes_canonical_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, lock_digest, classes = self._prepared(Path(temporary))
            calls, collector, verifier = self._runtime_stubs(classes)

            def evaluator(
                suite_path: Path, outcome_path: Path, **options: object
            ) -> dict:
                self.assertEqual(suite_path, root / "suite" / "phase2-suite.json")
                self.assertEqual(options["evidence_state"], root / "evidence")
                self.assertTrue(options["phase2_metrics_checkpoint"])
                self.assertEqual(
                    options["phase2_coverage_lock"], root / "coverage-lock.json"
                )
                self.assertEqual(
                    options["expected_phase2_coverage_lock_digest"], lock_digest
                )
                lines = outcome_path.read_bytes().splitlines()
                self.assertEqual(len(lines), 100)
                outcomes = [json.loads(line) for line in lines]
                self.assertTrue(
                    all(
                        line == canonical_json(item)
                        for line, item in zip(lines, outcomes)
                    )
                )
                evidence = CAS(root / "evidence", read_only=True)
                for outcome in outcomes:
                    expected = (
                        "REVIEW"
                        if classes[outcome["case_id"]] == "adversarial"
                        else "ALLOW"
                    )
                    self.assertEqual(outcome["verdict"], expected)
                    self.assertEqual(
                        outcome["reason_codes"],
                        ["UNDECLARED_OBSERVED_CAPABILITY"]
                        if expected == "REVIEW"
                        else [],
                    )
                    envelope_raw = evidence.read(outcome["evidence_digest"])
                    envelope = json.loads(envelope_raw)
                    self.assertEqual(envelope_raw, canonical_json(envelope))
                    self.assertEqual(
                        envelope["schema"],
                        "aragorn/benchmark-phase2-gvisor-v4-evidence/v1",
                    )
                    self.assertEqual(envelope["case_id"], outcome["case_id"])
                    self.assertEqual(envelope["run_id"], outcome["run_id"])
                    self.assertEqual(envelope["verdict"], outcome["verdict"])
                return {
                    "schema": "aragorn/benchmark-phase2-metrics-checkpoint/v2",
                    "coverage_lock_digest": lock_digest,
                    "phase2_exit_eligible": False,
                }

            with (
                patch(
                    "aragorn.phase2_matrix_run.verify_gvisor_acquired_artifact",
                    side_effect=verifier,
                ),
                patch(
                    "aragorn.phase2_matrix_run.evaluate_files",
                    side_effect=evaluator,
                ) as evaluate_mock,
            ):
                report = run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=collector,
                )

            case_ids = sorted(classes)
            self.assertEqual(calls, [case for case in case_ids for _run in range(5)])
            self.assertEqual(len(calls), 100)
            evaluate_mock.assert_called_once()
            results = root / "results"
            self.assertEqual(
                len((results / "outcomes.jsonl").read_bytes().splitlines()), 100
            )
            self.assertEqual(
                (results / "report.json").read_bytes(), canonical_json(report) + b"\n"
            )
            self.assertEqual(os.stat(results).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(results / "outcomes.jsonl").st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(results / "report.json").st_mode & 0o777, 0o600)

    def test_evaluator_failure_leaves_no_results_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, lock_digest, classes = self._prepared(Path(temporary))
            calls, collector, verifier = self._runtime_stubs(classes)

            with (
                patch(
                    "aragorn.phase2_matrix_run.verify_gvisor_acquired_artifact",
                    side_effect=verifier,
                ),
                patch(
                    "aragorn.phase2_matrix_run.evaluate_files",
                    side_effect=RuntimeError("forced evaluator failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "forced evaluator failure"),
            ):
                run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=collector,
                )

            self.assertEqual(len(calls), 100)
            self.assertFalse((root / "results").exists())
            self.assertEqual(list(root.glob(".results.*")), [])

    def test_v2_runs_the_locked_scenario_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _old_digest, classes = self._prepared(Path(temporary))
            lock_path = root / "coverage-lock.json"
            lock = json.loads(lock_path.read_bytes())
            lock.update(
                {
                    "schema": "aragorn/benchmark-phase2-coverage-lock/v2",
                    "assurance": (
                        "operator_asserted_pre_outcome_scenario_binding_not_"
                        "independent_or_timestamped"
                    ),
                    "scenario_matrix": {
                        "profile": "two-scenario-path-surface/v1",
                        "environment_variable": "ARAGORN_SCENARIO",
                        "run_schedule": [
                            "primary",
                            "alternate",
                            "primary",
                            "alternate",
                            "primary",
                        ],
                    },
                }
            )
            lock["gvisor"].update(
                {
                    "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v5",
                    "execution_profile": "bounded-single-script/v2",
                }
            )
            lock_raw = canonical_json(lock)
            lock_digest = "sha256:" + hashlib.sha256(lock_raw).hexdigest()
            lock_path.write_bytes(lock_raw)
            index_path = root / "operator-index.json"
            index = json.loads(index_path.read_bytes())
            index["coverage_lock_digest"] = lock_digest
            index_path.write_bytes(canonical_json(index))
            calls, collector, verifier = self._runtime_stubs(classes)
            scenarios: list[str] = []

            def scenario_collector(cas: CAS, source_cas: CAS, **pins: object) -> str:
                scenarios.append(str(pins["expected_scenario_id"]))
                return collector(cas, source_cas, **pins)

            def evaluator(
                _suite_path: Path, outcome_path: Path, **_options: object
            ) -> dict:
                evidence = CAS(root / "evidence", read_only=True)
                for line in outcome_path.read_bytes().splitlines():
                    outcome = json.loads(line)
                    envelope = json.loads(evidence.read(outcome["evidence_digest"]))
                    self.assertEqual(
                        envelope["scenario_id"],
                        ("primary" if outcome["run_id"] in {1, 3, 5} else "alternate"),
                    )
                    self.assertEqual(
                        envelope["schema"],
                        "aragorn/benchmark-phase2-gvisor-v5-evidence/v2",
                    )
                return {
                    "schema": "aragorn/benchmark-phase2-metrics-checkpoint/v3",
                    "coverage_lock_digest": lock_digest,
                    "phase2_exit_eligible": False,
                }

            with (
                patch(
                    "aragorn.phase2_matrix_run.verify_gvisor_acquired_artifact",
                    side_effect=verifier,
                ),
                patch(
                    "aragorn.phase2_matrix_run.evaluate_files",
                    side_effect=evaluator,
                ),
            ):
                report = run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=scenario_collector,
                )

            self.assertEqual(len(calls), 100)
            self.assertEqual(scenarios.count("primary"), 60)
            self.assertEqual(scenarios.count("alternate"), 40)
            self.assertEqual(
                report["schema"], "aragorn/benchmark-phase2-metrics-checkpoint/v3"
            )

    def test_unknown_attribution_scope_stops_after_first_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, lock_digest, classes = self._prepared(Path(temporary))
            first_case = min(classes)
            calls, collector, verifier = self._runtime_stubs(
                classes,
                unknown_attribution_case=first_case,
            )

            with (
                patch(
                    "aragorn.phase2_matrix_run.verify_gvisor_acquired_artifact",
                    side_effect=verifier,
                ),
                self.assertRaisesRegex(
                    Phase2MatrixRunError, "unknown attribution scope"
                ),
            ):
                run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=collector,
                )

            self.assertEqual(calls, [first_case])
            self.assertFalse((root / "results").exists())

    def test_rejects_index_digest_substitution_before_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, lock_digest, _classes = self._prepared(Path(temporary))
            index_path = root / "operator-index.json"
            index = json.loads(index_path.read_bytes())
            index["coverage_lock_digest"] = "sha256:" + "f" * 64
            index_path.write_bytes(canonical_json(index))
            collector = Mock()

            with self.assertRaisesRegex(
                Phase2MatrixRunError, "does not match the caller-held digest"
            ):
                run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=collector,
                )

            collector.assert_not_called()
            self.assertFalse((root / "results").exists())

    def test_rejects_path_escape_before_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, lock_digest, _classes = self._prepared(Path(temporary))
            index_path = root / "operator-index.json"
            index = json.loads(index_path.read_bytes())
            index["suite_path"] = "../phase2-suite.json"
            index_path.write_bytes(canonical_json(index))
            collector = Mock()

            with self.assertRaises(Phase2MatrixRunError):
                run_phase2_matrix(
                    root,
                    expected_coverage_lock_digest=lock_digest,
                    _collector=collector,
                )

            collector.assert_not_called()

    @staticmethod
    def _runtime_stubs(
        classes: dict[str, str],
        *,
        unknown_attribution_case: str | None = None,
    ):
        calls: list[str] = []

        def collector(cas: CAS, source_cas: CAS, **pins: object) -> str:
            case_id = source_cas.root.name
            calls.append(case_id)
            declared = list(pins["expected_declared_capabilities"])
            observed = [*declared]
            if classes[case_id] == "adversarial":
                observed.append("file-write")
            capability_diff = derive_behavior_capability_diff(
                subject_digest=str(pins["expected_tree_digest"]),
                declared_capabilities=declared,
                observed_capabilities=observed,
            )
            capability_diff_digest = cas.put(
                _bytes(capability_diff), max_bytes=16 * 1024
            )
            diff_receipt_digest = cas.put(
                _bytes({"capability_diff_digest": capability_diff_digest}),
                max_bytes=16 * 1024,
            )
            attribution_manifest_digest = cas.put(
                _bytes(
                    {
                        "events": [
                            {
                                "scope": (
                                    "unknown"
                                    if case_id == unknown_attribution_case
                                    else "subject"
                                )
                            }
                        ]
                    }
                ),
                max_bytes=16 * 1024,
            )
            scenario_id = pins.get("expected_scenario_id")
            receipt = {
                "schema": (
                    ARTIFACT_SCHEMA_V5
                    if scenario_id is not None
                    else ARTIFACT_SCHEMA_V4
                ),
                "attribution_manifest_digest": attribution_manifest_digest,
                "capability_diff_receipt_digest": diff_receipt_digest,
                "test_sequence": len(calls),
            }
            if scenario_id is not None:
                receipt["scenario_id"] = scenario_id
            return cas.put(
                _bytes(receipt),
                max_bytes=16 * 1024,
            )

        def verifier(cas: CAS, digest: str, **_pins: object) -> dict:
            return json.loads(cas.read(digest))

        return calls, collector, verifier

    @classmethod
    def _prepared(cls, root: Path) -> tuple[Path, str, dict[str, str]]:
        root = root.resolve()
        suite_root = root / "suite"
        fixture_root = suite_root / "fixtures"
        fixture_root.mkdir(parents=True)
        system = {
            "name": "aragorn",
            "version": "phase2-test",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        specifications = [(f"benign-{index}", "benign", "benign") for index in range(4)]
        for family_index, family in enumerate(_FAMILIES):
            count = 3 if family_index < 2 else 2
            specifications.extend(
                (f"attack-{family}-{index}", "adversarial", family)
                for index in range(count)
            )
        cases = []
        classes = {}
        for case_id, case_class, family in specifications:
            fixture = fixture_root / case_id
            fixture.mkdir()
            (fixture / "SKILL.md").write_text(case_id + "\n", encoding="utf-8")
            (fixture / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            classes[case_id] = case_class
            cases.append(
                {
                    "schema": "aragorn/benchmark-case/v1",
                    "id": case_id,
                    "class": case_class,
                    "family": family,
                    "lineage": "lineage-" + case_id,
                    "split": "held_out",
                    "path": f"fixtures/{case_id}",
                    "tree_digest": inventory_local(fixture)["tree_digest"],
                    "inert": True,
                    "source": {
                        "kind": "synthetic",
                        "reference": "phase2-test/" + case_id,
                        "license": "CC0-1.0",
                    },
                }
            )
        suite = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "phase2-matrix-test",
            "purpose": "evidence_smoke",
            "runs_per_case": 5,
            "systems": [system],
            "cases": cases,
        }
        suite_path = suite_root / "phase2-suite.json"
        suite_path.write_bytes(canonical_json(suite))
        loaded = load_suite_for_run(suite_path, CAS(root / "suite-validation"))
        lock = cls._coverage_lock(loaded, system)
        lock_raw = canonical_json(lock)
        lock_digest = "sha256:" + hashlib.sha256(lock_raw).hexdigest()
        (root / "coverage-lock.json").write_bytes(lock_raw)

        index_cases = []
        for case_id in sorted(classes):
            CAS(root / "sources" / case_id)
            index_cases.append(
                {
                    "case_id": case_id,
                    "source_state_path": f"sources/{case_id}",
                }
            )
        index = {
            "schema": "aragorn/phase2-matrix-operator-index/v1",
            "authority": "RELATIVE_PATH_HINTS_ONLY_NOT_EVIDENCE_OR_PHASE2_AUTHORITY",
            "coverage_lock_digest": lock_digest,
            "suite_path": "suite/phase2-suite.json",
            "coverage_lock_path": "coverage-lock.json",
            "evidence_state_path": "evidence",
            "results_path": "results",
            "cases": index_cases,
        }
        (root / "operator-index.json").write_bytes(canonical_json(index))
        return root, lock_digest, classes

    @staticmethod
    def _coverage_lock(loaded: dict, system: dict) -> dict:
        locked_cases = []
        for case_id in sorted(loaded["cases"]):
            case = loaded["cases"][case_id]
            manifest = loaded["manifests"][case_id]
            entrypoint = next(
                item for item in manifest["files"] if item["path"] == "run.sh"
            )
            locked_cases.append(
                {
                    "case_id": case_id,
                    "class": case["class"],
                    "family": case["family"],
                    "lineage": case["lineage"],
                    "tree_digest": case["tree_digest"],
                    "suite_manifest_digest": _digest_json(manifest),
                    "source_manifest_digest": _digest_json(
                        {"source-manifest": case_id}
                    ),
                    "quarantine_receipt_digest": _digest_json({"quarantine": case_id}),
                    "gateway_profile_digest": _digest_json({"gateway": case_id}),
                    "entrypoint_path": "run.sh",
                    "entrypoint_digest": entrypoint["digest"],
                    "declared_capabilities": ["file-read", "process-exec"],
                }
            )
        return {
            "schema": "aragorn/benchmark-phase2-coverage-lock/v1",
            "assurance": (
                "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
            ),
            "suite_digest": loaded["digest"],
            "evaluation_split": "held_out",
            "runs_per_case": 5,
            "candidate_system": system,
            "verdict_profile": "undeclared-observed-review/v1",
            "gvisor": {
                "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v4",
                "normalization_profile": "successful-openat-execve-attributed/v1",
                "execution_profile": "bounded-single-script/v1",
                "lock_digest": "sha256:" + "a" * 64,
                "verifier_implementation_digest": "sha256:" + "b" * 64,
            },
            "cases": locked_cases,
        }


def _bytes(document: object) -> BytesIO:
    return BytesIO(canonical_json(document))


if __name__ == "__main__":
    unittest.main()
